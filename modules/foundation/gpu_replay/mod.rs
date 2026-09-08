//! Replay GPU provider — the GPU contract with no GPU.
//!
//! A thin pump. Everything that decides anything lives in the shared cores:
//! [`gpu_wire`](../../sdk/wire/gpu_wire.rs) is the contract,
//! [`gpu_device`](../../sdk/cores/gpu_device.rs) is admission, handles,
//! fences and output commit, [`gpu_pack`](../../sdk/cores/gpu_pack.rs)
//! validates program identity, and [`gpu_replay`](../../sdk/cores/gpu_replay.rs)
//! is the deterministic backend. This file owns only the channel loop and the
//! buffers those cores borrow — which is the same division a browser or native
//! provider makes, with a different backend on the far side.
//!
//! ## The step
//!
//! Read commands, admit one record at a time, execute the work it produced,
//! push outcomes back. Three properties make the step bounded:
//!
//!   * one record per iteration, each at most `MAX_PAYLOAD + 16` bytes;
//!   * admission stops the moment the outcome ring cannot hold a request's
//!     answers, so a slow consumer becomes backpressure rather than loss;
//!   * at most one readback is in flight, and while its bytes are still owed
//!     no new command is admitted. That is what lets a synchronous backend
//!     honour fence dependencies without a deferred-work queue: by the time a
//!     record is admitted, every earlier fence is already terminal, so
//!     `advance` always makes a submission runnable before it runs.

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    dead_code,
    unused_imports,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so this \
              module's compile sees the full ABI and GPU-contract surface; a \
              provider uses a subset of a contract shared with producers"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/crypto/sha256.rs");
include!("../../sdk/wire/gpu_wire.rs");
include!("../../sdk/cores/gpu_pack.rs");
include!("../../sdk/cores/gpu_device.rs");
include!("../../sdk/cores/gpu_pump.rs");
include!("../../sdk/cores/gpu_replay.rs");

// ── Sizing ──────────────────────────────────────────────────────────────
//
// The table widths and the arena size are the replay profile in
// `cores/gpu_replay.rs`, named locally for readability. They are shared with
// the offline packer, which validates a pack against the device a graph would
// actually get — so a pack `fluxor gpu validate` accepts is a pack this
// provider accepts.

const MAX_RESOURCES: usize = REPLAY_MAX_RESOURCES;
const MAX_VIEWS: usize = REPLAY_MAX_VIEWS;
const MAX_PROGRAMS: usize = REPLAY_MAX_PROGRAMS;
const MAX_PIPELINES: usize = REPLAY_MAX_PIPELINES;
const MAX_FENCES: usize = REPLAY_MAX_FENCES;
const MAX_SURFACES: usize = REPLAY_MAX_SURFACES;

/// Command bytes buffered from the input channel. One whole record must fit,
/// so this is the contract's record ceiling plus room to keep reading while a
/// partial record is buffered.
const CMD_BUF: usize = MAX_RECORD + 8 * 1024;
/// Outcome ring. Sized to hold a capability record, a maximal readback chunk
/// and several requests' answers, so a consumer that drains once per step
/// never stalls the provider on a single large result.
const RING_BYTES: usize = 96 * 1024;
const ARENA_BLOCKS: usize = REPLAY_ARENA_BLOCKS;
const ARENA_BYTES: usize = REPLAY_ARENA_BYTES;
/// Assembly buffer for one chunked program pack at a time. A pack larger than
/// this is refused at `finish_program` rather than truncated.
const PACK_BUF: usize = 128 * 1024;

/// Heap the module asks the loader for: the four big buffers plus slack for
/// the allocator's own bookkeeping.
const HEAP_BYTES: u32 = (CMD_BUF + RING_BYTES + ARENA_BYTES + PACK_BUF + 4096) as u32;

// The widths `GpuDevice::new` would check at runtime. This module builds its
// device with `restore`, which checks nothing, so the same invariants are
// asserted here — where they are compile-time constants and a violation is a
// build failure rather than a `None` at boot.
const _: () = assert!(MAX_RESOURCES < NO_SLOT as usize);
const _: () = assert!(MAX_VIEWS < NO_SLOT as usize);
const _: () = assert!(MAX_PROGRAMS < NO_SLOT as usize);
const _: () = assert!(MAX_PIPELINES < NO_SLOT as usize);
const _: () = assert!(MAX_FENCES < NO_SLOT as usize);
const _: () = assert!(MAX_SURFACES < NO_SLOT as usize);
// A ring too small to hold a capability record could not answer the first
// question a consumer asks.
const _: () = assert!(RING_BYTES >= MIN_RING_BYTES);
// One whole record must fit, or a maximal upload chunk could never be admitted.
const _: () = assert!(CMD_BUF >= MAX_RECORD);
// The replay store carves the arena into fixed blocks and tracks them in a
// bitmap, so a partial trailing block would be memory it could never hand out.
const _: () = assert!(ARENA_BYTES.is_multiple_of(BLOCK_BYTES));

/// A readback whose bytes are still owed. While one is armed no new command
/// is admitted, so the synchronous backend never has to defer a submission
/// whose dependency is still open.
#[derive(Clone, Copy)]
struct Readback {
    active: bool,
    fence: u16,
    resource: u16,
    offset: u64,
    len: u32,
}

#[repr(C)]
pub struct GpuNullState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,

    // Heap-held buffers the cores borrow each step.
    cmd_buf: *mut u8,
    cmd_len: u32,
    ring: *mut u8,
    arena: *mut u8,
    pack_buf: *mut u8,
    /// Progress through a chunked pack, if one is being assembled.
    pack: PackCursor,

    /// A readback whose bytes have not all reached the output channel.
    rb: Readback,
    /// How far a drained run of outcome records has got towards the channel,
    /// and the staging buffer that run lives in. The bytes are already out of
    /// the device's ring, so losing this cursor would lose them.
    out: OutCursor,
    out_buf: [u8; MAX_RECORD],

    // Device tables.
    resources: [ResourceSlot; MAX_RESOURCES],
    views: [ViewSlot; MAX_VIEWS],
    programs: [ProgramSlot; MAX_PROGRAMS],
    pipelines: [PipelineSlot; MAX_PIPELINES],
    fences: [FenceSlot; MAX_FENCES],
    surfaces: [SurfaceSlot; MAX_SURFACES],
    /// Preserved across steps: the device's own state lives in the tables
    /// above, but its scalars (epoch, budgets, ring cursors, statistics) live
    /// in the `GpuDevice` value, which is rebuilt each step. Keeping them here
    /// is what makes that rebuild lossless.
    saved: DeviceScalars,

    // Replay store bookkeeping.
    first_block: [u32; MAX_RESOURCES],
    block_count: [u32; MAX_RESOURCES],
    used_block: [bool; ARENA_BLOCKS],

    /// Set once the graph is wired and the tables are initialised.
    ready: bool,
    /// The command stream desynchronised and was abandoned.
    ///
    /// Latched, because a byte FIFO cannot be resynchronised: without this the
    /// module reports one framing fault per read chunk, which reads to a
    /// producer as a storm rather than as the single "this stream is over"
    /// that it is. Cleared only by rebuilding the module.
    faulted: bool,
}

const STATE_SIZE: usize = core::mem::size_of::<GpuNullState>();

// ── Entry points ────────────────────────────────────────────────────────

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_state_size")]
pub extern "C" fn module_state_size() -> u32 {
    STATE_SIZE as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_arena_size")]
pub extern "C" fn module_arena_size() -> u32 {
    HEAP_BYTES
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_init")]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_new")]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    _state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    // SAFETY: the loader hands a state block of at least `module_state_size()`
    // bytes, aligned for this type, and calls `module_new` exactly once for it.
    let s = unsafe { &mut *(state as *mut GpuNullState) };
    let syscalls = syscalls as *const SyscallTable;
    s.syscalls = syscalls;
    s.in_chan = in_chan;
    s.out_chan = out_chan;
    s.cmd_len = 0;
    s.pack = PackCursor::idle();
    s.rb = Readback {
        active: false,
        fence: NO_SLOT,
        resource: NO_SLOT,
        offset: 0,
        len: 0,
    };
    s.out = OutCursor::default();
    s.ready = false;
    s.faulted = false;

    // SAFETY: `syscalls` is the loader's live table for this module, and the
    // heap it draws from was sized by `module_arena_size` above.
    let sys = unsafe { &*syscalls };
    s.cmd_buf = unsafe { (sys.heap_alloc)(CMD_BUF as u32) };
    s.ring = unsafe { (sys.heap_alloc)(RING_BYTES as u32) };
    s.arena = unsafe { (sys.heap_alloc)(ARENA_BYTES as u32) };
    s.pack_buf = unsafe { (sys.heap_alloc)(PACK_BUF as u32) };
    if s.cmd_buf.is_null() || s.ring.is_null() || s.arena.is_null() || s.pack_buf.is_null() {
        return -1;
    }

    s.resources = [ResourceSlot::EMPTY; MAX_RESOURCES];
    s.views = [ViewSlot::EMPTY; MAX_VIEWS];
    s.programs = [ProgramSlot::EMPTY; MAX_PROGRAMS];
    s.pipelines = [PipelineSlot::EMPTY; MAX_PIPELINES];
    s.fences = [FenceSlot::EMPTY; MAX_FENCES];
    s.surfaces = [SurfaceSlot::EMPTY; MAX_SURFACES];
    s.first_block = [NO_BLOCK; MAX_RESOURCES];
    s.block_count = [0; MAX_RESOURCES];
    s.used_block = [false; ARENA_BLOCKS];
    s.saved = DeviceScalars::initial();
    s.ready = true;
    0
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_step")]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    // SAFETY: the scheduler passes the pointer `module_new` initialised, once
    // per step, single-threaded within this module's domain.
    let s = unsafe { &mut *(state as *mut GpuNullState) };
    if !s.ready {
        return -1;
    }
    step(s);
    0
}

/// One cooperative step. Split out of the `extern "C"` shell so the borrow
/// checker sees ordinary references rather than a raw pointer.
///
/// The state is destructured once, up front. The device borrows the tables for
/// the whole step, so every other field it needs — the command buffer, the
/// pack assembly, the readback, the output staging — has to be a disjoint
/// borrow taken at the same moment rather than reached through `s` later.
fn step(s: &mut GpuNullState) {
    let GpuNullState {
        syscalls,
        in_chan,
        out_chan,
        cmd_buf,
        cmd_len,
        ring,
        arena,
        pack_buf,
        pack,
        rb,
        out,
        out_buf,
        resources,
        views,
        programs,
        pipelines,
        fences,
        surfaces,
        saved,
        first_block,
        block_count,
        used_block,
        ready: _,
        faulted,
    } = s;

    // SAFETY: every pointer below was allocated in `module_new` from this
    // module's own heap at exactly the length it is reconstituted with, and
    // nothing else holds a reference to any of them during a step.
    let sys = unsafe { &**syscalls };
    let cmd = unsafe { core::slice::from_raw_parts_mut(*cmd_buf, CMD_BUF) };
    let ring = unsafe { core::slice::from_raw_parts_mut(*ring, RING_BYTES) };
    let arena = unsafe { core::slice::from_raw_parts_mut(*arena, ARENA_BYTES) };
    let pack_bytes = unsafe { core::slice::from_raw_parts_mut(*pack_buf, PACK_BUF) };
    let out_chan = *out_chan;

    let mut dev = GpuDevice::restore(
        GpuTables {
            resources,
            views,
            programs,
            pipelines,
            fences,
            surfaces,
            outcomes: ring,
        },
        replay_limits(ARENA_BYTES as u64),
        BACKEND_REPLAY,
        PROVIDER_EPOCH,
        *saved,
    );
    let Some(mut store) = ReplayStore::restore(arena, first_block, block_count, used_block) else {
        return;
    };
    let write = |bytes: &[u8]| -> i32 {
        if out_chan < 0 {
            return -1;
        }
        // SAFETY: `bytes` is a live slice of the staging buffer for the
        // duration of the call.
        unsafe { (sys.channel_write)(out_chan, bytes.as_ptr(), bytes.len()) }
    };

    // Finish what is already owed before taking on more.
    flush_outcomes(&mut dev, out_buf, out, write);
    if rb.active {
        if push_readback(&mut dev, &store, rb.fence, rb.resource, rb.offset, rb.len)
            == Executed::Pending
        {
            // Bytes still owed. Publish what we have and try again next step;
            // admitting more work now could accept a submission whose
            // dependency has not settled.
            //
            // Advance even though no new work was admitted: it is what
            // re-attempts a terminal record the ring could not take, and a
            // readback owing bytes is exactly when the ring is fullest.
            // Returning without it would leave that fence undeliverable for
            // as long as the readback lasts.
            dev.advance();
            // Flush BEFORE saving: draining moves the ring's cursor, and
            // saving the pre-drain value would roll it back and re-emit every
            // record on the next step.
            flush_outcomes(&mut dev, out_buf, out, write);
            *saved = dev.save();
            return;
        }
        rb.active = false;
    }

    // Refill the command buffer. A faulted stream is read no further: its
    // rejection already went out, and every later byte is the tail of a frame
    // nobody can place.
    while !*faulted && (*cmd_len as usize) < CMD_BUF {
        let room = CMD_BUF - *cmd_len as usize;
        // SAFETY: `cmd` is `CMD_BUF` bytes and `cmd_len + room == CMD_BUF`.
        let n =
            unsafe { (sys.channel_read)(*in_chan, cmd.as_mut_ptr().add(*cmd_len as usize), room) };
        if n <= 0 {
            break;
        }
        *cmd_len += n as u32;
    }

    pump_admit(
        &mut dev,
        OWNER,
        cmd,
        cmd_len,
        faulted,
        |dev, record, work| run_work(dev, &mut store, pack, pack_bytes, rb, record, work),
    );

    dev.advance();
    flush_outcomes(&mut dev, out_buf, out, write);
    // Saved last, for the same reason: the flush is what advances the ring.
    *saved = dev.save();
}

/// The graph owner this provider serves. One channel, one owner: authority
/// comes from the granted port, and the contract carries no owner field
/// precisely so a record cannot claim a different one.
const OWNER: u16 = 0;

/// Provider epoch reported in the capability record. Fixed, because this
/// provider has no adapter to be re-created against — a number that changed
/// would imply a re-initialisation that never happens.
const PROVIDER_EPOCH: u32 = 0;

/// Carry out one admitted request. Answers whether the pump may keep going.
///
/// Program loading and readback are the two the shared backend deliberately
/// leaves to its caller: assembling a chunked pack needs a buffer this module
/// owns, and a readback's progress depends on how much room the outcome ring
/// has right now.
fn run_work(
    dev: &mut GpuDevice<'_>,
    store: &mut ReplayStore<'_>,
    pack: &mut PackCursor,
    pack_buf: &mut [u8],
    rb: &mut Readback,
    record: &[u8],
    work: Work,
) -> bool {
    match work {
        Work::LoadProgram {
            fence,
            slot,
            chunk_offset,
            payload_offset,
            chunk_len,
        } => {
            let Some(bytes) = record.get(payload_offset..payload_offset + chunk_len) else {
                dev.fail(fence, REASON_MALFORMED, 0);
                return true;
            };
            absorb_pack_chunk(dev, pack, pack_buf, fence, slot, chunk_offset, bytes);
            true
        }

        Work::Readback {
            fence,
            resource,
            offset,
            len,
        } => {
            if push_readback(dev, store, fence, resource, offset, len) == Executed::Pending {
                *rb = Readback {
                    active: true,
                    fence,
                    resource,
                    offset,
                    len,
                };
                // Stop admitting: a submission accepted now could name a
                // dependency this readback has not settled.
                return false;
            }
            true
        }

        Work::Submit { fence, .. } => {
            // Every earlier fence is terminal by construction — this backend is
            // synchronous and admits nothing while a readback is open — so one
            // `advance` is enough to make a satisfied submission runnable.
            dev.advance();
            if dev.fence(fence).is_some_and(|f| f.state == FENCE_READY) {
                dev.mark_running(fence);
                execute(dev, store, OWNER, record, work);
            }
            // A submission whose waits are not met stays in the table; a later
            // `advance` settles it against its dependency's outcome.
            true
        }

        other => {
            execute(dev, store, OWNER, record, other);
            true
        }
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/runtime/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/runtime/wasm_entry.rs");
