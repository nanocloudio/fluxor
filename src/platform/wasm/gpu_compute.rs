//! `wasm_browser_compute` built-in — the generic GPU contract on WebGPU.
//!
//! Same contract, same shared cores and same lifetime corpus as the
//! null/replay provider and the native Linux one; the only thing that differs
//! is which device objects sit behind the slot numbers.
//!
//! ## The split
//!
//! Validation, handles, views, sealing, residency, fences, dependency order,
//! candidate-output commit and epochs are
//! [`gpu_wire`](../../../modules/sdk/wire/gpu_wire.rs) and the cores beside it.
//! This file translates admitted work into the `host_gpu_service_*` imports and
//! polls their answers. The JavaScript on the other side validates nothing,
//! because everything it receives has already been proved — a backend that
//! re-checked the contract would be a second implementation of it, and the two
//! would disagree.
//!
//! ## Why the device is shared
//!
//! `host_gpu_service_*` draws from the page's one adapter and device — the same
//! one the raster shim uses. WebGPU resources belong to the device that made
//! them, so a second device would be a disjoint resource world and every
//! hand-off between compute and raster a CPU round trip. One device is what
//! makes the hand-off expressible; it does not merge the surfaces'
//! capabilities or oblige either to own a swapchain.
//!
//! ## Asynchrony
//!
//! Nothing here blocks. Adapter acquisition, pipeline compilation, submission
//! completion and buffer mapping are all polled across steps, because a
//! cooperative step has no room to wait for a driver — and because a
//! synchronous pipeline create would stall the shared device's whole timeline
//! behind one compile.

use crate::kernel::exec::scheduler;
use crate::kernel::ipc::channel;
use crate::kernel::module::syscalls;

use crate::abi::contracts::gpu as gw;

#[path = "../../../modules/sdk/wire/gpu_exec_wire.rs"]
mod exec;

// ── Sizing ──────────────────────────────────────────────────────────────
//
// R2 table widths for a browser provider: wide enough for a real consumer
// pipeline, narrow enough that the state block stays inside a wasm heap that
// also holds a page's worth of everything else.

const MAX_RESOURCES: usize = 64;
const MAX_VIEWS: usize = 128;
const MAX_PROGRAMS: usize = 16;
const MAX_PIPELINES: usize = 16;
const MAX_FENCES: usize = 64;
const MAX_SURFACES: usize = 2;

const CMD_BUF: usize = gw::MAX_RECORD + 32 * 1024;
const RING_BYTES: usize = 256 * 1024;
const PACK_BUF: usize = 256 * 1024;
/// Bytes of one hand-off item list. A submission larger than this is refused
/// at admission by the queue-depth and reference ceilings long before it gets
/// here, but the buffer is bounded regardless.
const EXEC_BUF: usize = 16 * 1024;
/// Readback bytes staged from the backend per step.
const RB_BUF: usize = 64 * 1024;

const OWNER: u16 = 0;

// Backend poll answers, mirroring `SVC_PENDING` / `SVC_DONE` in host_shims.js.
const BACKEND_PENDING: i32 = 0;
const BACKEND_DONE: i32 = 1;

extern "C" {
    fn host_gpu_service_init() -> i32;
    fn host_gpu_service_poll_init() -> i32;
    /// Write [`exec::FACT_LEN`] bytes of adapter facts. 0, or <0 with no device.
    fn host_gpu_service_facts(out_ptr: *mut u8) -> i32;
    fn host_gpu_service_create_buffer(slot: u32, size: u32, usage: u32) -> i32;
    fn host_gpu_service_destroy(slot: u32) -> i32;
    fn host_gpu_service_upload(slot: u32, offset: u32, ptr: *const u8, len: u32) -> i32;
    fn host_gpu_service_program(
        slot: u32,
        src_ptr: *const u8,
        src_len: u32,
        entry_ptr: *const u8,
        entry_len: u32,
    ) -> i32;
    fn host_gpu_service_pipeline(slot: u32, program_slot: u32) -> i32;
    fn host_gpu_service_poll_pipeline(slot: u32) -> i32;
    fn host_gpu_service_release_pipeline(slot: u32) -> i32;
    fn host_gpu_service_release_program(slot: u32) -> i32;
    fn host_gpu_service_submit(ticket: u32, list_ptr: *const u8, list_len: u32) -> i32;
    fn host_gpu_service_poll_submit(ticket: u32) -> i32;
    fn host_gpu_service_release_ticket(ticket: u32) -> i32;
    fn host_gpu_service_readback(
        ticket: u32,
        slot: u32,
        offset: u32,
        out_ptr: *mut u8,
        len: u32,
    ) -> i32;
    fn host_gpu_service_drain(ticket: u32) -> i32;
    fn host_gpu_service_epoch() -> u32;
}

/// What a fence is waiting on in the backend.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Await {
    /// Nothing; the slot is free.
    Idle,
    /// A pipeline compile, identified by its pipeline slot.
    Pipeline(u16),
    /// A submission or drain ticket.
    Ticket,
    /// A readback: the resource, its offset and the byte count still owed.
    Readback(u16, u64, u32),
}

#[repr(C)]
pub(crate) struct GpuComputeState {
    in_chan: i32,
    out_chan: i32,
    live: bool,
    unavailable: bool,
    /// The backend's device epoch when this provider last looked. A change
    /// means every object behind every slot is gone.
    backend_epoch: u32,

    cmd: *mut u8,
    cmd_len: u32,
    ring: *mut u8,
    pack_buf: *mut u8,
    out_buf: *mut u8,
    exec_buf: *mut u8,
    rb_buf: *mut u8,

    resources: *mut gw::ResourceSlot,
    views: *mut gw::ViewSlot,
    programs: *mut gw::ProgramSlot,
    pipelines: *mut gw::PipelineSlot,
    fences: *mut gw::FenceSlot,
    surfaces: *mut gw::SurfaceSlot,
    saved: gw::DeviceScalars,
    limits: gw::DeviceLimits,

    pack: gw::PackCursor,
    out: gw::OutCursor,
    faulted: bool,
    /// What each fence slot is waiting on in the backend. Parallel to the
    /// fence table because a fence's device-side state is the backend's, and
    /// the contract core has no place to keep it.
    awaiting: *mut Await,
}

/// Heap the module asks the runtime for.
pub(crate) fn heap_size_for() -> usize {
    core::mem::size_of::<GpuComputeState>()
        + CMD_BUF
        + RING_BYTES
        + PACK_BUF
        + gw::MAX_RECORD
        + EXEC_BUF
        + RB_BUF
        + MAX_RESOURCES * core::mem::size_of::<gw::ResourceSlot>()
        + MAX_VIEWS * core::mem::size_of::<gw::ViewSlot>()
        + MAX_PROGRAMS * core::mem::size_of::<gw::ProgramSlot>()
        + MAX_PIPELINES * core::mem::size_of::<gw::PipelineSlot>()
        + MAX_FENCES * core::mem::size_of::<gw::FenceSlot>()
        + MAX_SURFACES * core::mem::size_of::<gw::SurfaceSlot>()
        + MAX_FENCES * core::mem::size_of::<Await>()
        + 4096
}

// The widths `GpuDevice::new` checks at runtime, asserted here instead: this
// provider builds its device with `restore`, and a compile-time constant is a
// better place to fail than a boot.
const _: () = assert!(MAX_RESOURCES < gw::NO_SLOT as usize);
const _: () = assert!(MAX_VIEWS < gw::NO_SLOT as usize);
const _: () = assert!(MAX_FENCES < gw::NO_SLOT as usize);
const _: () = assert!(RING_BYTES >= gw::MIN_RING_BYTES);
const _: () = assert!(CMD_BUF >= gw::MAX_RECORD);

/// Allocate every buffer and table this provider borrows each step.
///
/// # Safety
/// Runs once, from `build`, before any step.
unsafe fn alloc_state(in_chan: i32, out_chan: i32) -> *mut GpuComputeState {
    let table = syscalls::get_syscall_table();
    let raw =
        (table.heap_alloc)(core::mem::size_of::<GpuComputeState>() as u32) as *mut GpuComputeState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    let alloc = |n: usize| (table.heap_alloc)(n as u32);
    let cmd = alloc(CMD_BUF);
    let ring = alloc(RING_BYTES);
    let pack_buf = alloc(PACK_BUF);
    let out_buf = alloc(gw::MAX_RECORD);
    let exec_buf = alloc(EXEC_BUF);
    let rb_buf = alloc(RB_BUF);
    let resources =
        alloc(MAX_RESOURCES * core::mem::size_of::<gw::ResourceSlot>()) as *mut gw::ResourceSlot;
    let views = alloc(MAX_VIEWS * core::mem::size_of::<gw::ViewSlot>()) as *mut gw::ViewSlot;
    let programs =
        alloc(MAX_PROGRAMS * core::mem::size_of::<gw::ProgramSlot>()) as *mut gw::ProgramSlot;
    let pipelines =
        alloc(MAX_PIPELINES * core::mem::size_of::<gw::PipelineSlot>()) as *mut gw::PipelineSlot;
    let fences = alloc(MAX_FENCES * core::mem::size_of::<gw::FenceSlot>()) as *mut gw::FenceSlot;
    let surfaces =
        alloc(MAX_SURFACES * core::mem::size_of::<gw::SurfaceSlot>()) as *mut gw::SurfaceSlot;
    let awaiting = alloc(MAX_FENCES * core::mem::size_of::<Await>()) as *mut Await;
    if cmd.is_null()
        || ring.is_null()
        || pack_buf.is_null()
        || out_buf.is_null()
        || exec_buf.is_null()
        || rb_buf.is_null()
        || resources.is_null()
        || views.is_null()
        || programs.is_null()
        || pipelines.is_null()
        || fences.is_null()
        || surfaces.is_null()
        || awaiting.is_null()
    {
        return core::ptr::null_mut();
    }

    for i in 0..MAX_RESOURCES {
        core::ptr::write(resources.add(i), gw::ResourceSlot::EMPTY);
    }
    for i in 0..MAX_VIEWS {
        core::ptr::write(views.add(i), gw::ViewSlot::EMPTY);
    }
    for i in 0..MAX_PROGRAMS {
        core::ptr::write(programs.add(i), gw::ProgramSlot::EMPTY);
    }
    for i in 0..MAX_PIPELINES {
        core::ptr::write(pipelines.add(i), gw::PipelineSlot::EMPTY);
    }
    for i in 0..MAX_FENCES {
        core::ptr::write(fences.add(i), gw::FenceSlot::EMPTY);
        core::ptr::write(awaiting.add(i), Await::Idle);
    }
    for i in 0..MAX_SURFACES {
        core::ptr::write(surfaces.add(i), gw::SurfaceSlot::EMPTY);
    }

    core::ptr::write(
        raw,
        GpuComputeState {
            in_chan,
            out_chan,
            live: false,
            unavailable: false,
            backend_epoch: 0,
            cmd,
            cmd_len: 0,
            ring,
            pack_buf,
            out_buf,
            exec_buf,
            rb_buf,
            resources,
            views,
            programs,
            pipelines,
            fences,
            surfaces,
            saved: gw::DeviceScalars::initial(),
            // Replaced by the adapter's own facts the moment it opens.
            // Nothing is admitted before then.
            limits: gw::DeviceLimits::baseline(),
            pack: gw::PackCursor::idle(),
            out: gw::OutCursor::default(),
            faulted: false,
            awaiting,
        },
    );
    raw
}

fn gpu_compute_step(state: *mut u8) -> i32 {
    // SAFETY: single-threaded module step; `state` holds the live pointer
    // `build` wrote, and every buffer below was allocated in `alloc_state` at
    // exactly the length it is reconstituted with.
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut GpuComputeState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;
        if st.in_chan < 0 {
            return 0;
        }
        if st.unavailable {
            refuse(st);
            return 0;
        }
        if !st.live && !acquire(st) {
            return 0;
        }
        step(st);
        0
    }
}

/// Answer every request with a rejection, because no device will open here.
///
/// # Safety
/// Called only from the step, with `st` valid.
unsafe fn refuse(st: &mut GpuComputeState) {
    let cmd = core::slice::from_raw_parts_mut(st.cmd, CMD_BUF);
    while !st.faulted && (st.cmd_len as usize) < CMD_BUF {
        let room = CMD_BUF - st.cmd_len as usize;
        let n = channel::channel_read(st.in_chan, cmd.as_mut_ptr().add(st.cmd_len as usize), room);
        if n <= 0 {
            break;
        }
        st.cmd_len += n as u32;
    }
    let out_chan = st.out_chan;
    gw::refuse_records(
        cmd,
        &mut st.cmd_len,
        &mut st.faulted,
        gw::REASON_DEVICE_LOST,
        |bytes| {
            if out_chan < 0 {
                return -1;
            }
            channel::channel_write(out_chan, bytes.as_ptr(), bytes.len())
        },
    );
}

/// Open the shared device and read its facts. Answers whether work can start.
///
/// # Safety
/// Called only from the step, with `st` valid.
unsafe fn acquire(st: &mut GpuComputeState) -> bool {
    let status = if st.backend_epoch == 0 {
        host_gpu_service_init()
    } else {
        host_gpu_service_poll_init()
    };
    if status < 0 {
        st.unavailable = true;
        return false;
    }
    if status != 0 {
        // Still acquiring. `0` is the backend's READY; anything positive is
        // pending, matching the other browser shims' three-state init.
        st.backend_epoch = 1;
        return false;
    }
    let mut facts = [0u8; exec::FACT_LEN];
    if host_gpu_service_facts(facts.as_mut_ptr()) < 0 {
        st.backend_epoch = 1;
        return false;
    }
    st.limits = limits_from(&facts);
    st.backend_epoch = host_gpu_service_epoch();
    st.live = true;
    true
}

/// Build the contract's device facts from the adapter's reported limits.
///
/// Only what the adapter says. f16 in particular is advertised only where the
/// device reports it: there is no emulation path here, so the honest answer
/// where it is missing is "unsupported", not "supported, slowly".
fn limits_from(facts: &[u8; exec::FACT_LEN]) -> gw::DeviceLimits {
    let u32_at = |off: usize| -> u32 {
        u32::from_le_bytes([facts[off], facts[off + 1], facts[off + 2], facts[off + 3]])
    };
    let mut l = gw::DeviceLimits::baseline();
    let native = gw::ARITH_STORAGE | gw::ARITH_COMPUTE | gw::ARITH_ACCUM | gw::ARITH_NATIVE;
    let mut arith = [0u8; gw::ARITH_TYPE_COUNT];
    arith[gw::ARITH_I32] = native;
    arith[gw::ARITH_U32] = native;
    arith[gw::ARITH_F32] = native;
    // Storable, not computable: a packed byte tensor is bytes.
    arith[gw::ARITH_I8] = gw::ARITH_STORAGE;
    arith[gw::ARITH_U8] = gw::ARITH_STORAGE;
    arith[gw::ARITH_I16] = gw::ARITH_STORAGE;
    arith[gw::ARITH_U16] = gw::ARITH_STORAGE;
    let flags = u32_at(exec::FACT_FLAGS);
    if flags & exec::FACT_HAS_F16 != 0 {
        arith[gw::ARITH_F16] = native;
    }
    l.arith_types = arith;
    l.arith_ops = gw::AOP_FMA_F32 | gw::AOP_ATOMIC_I32;

    let mut features = gw::FEATURE_COMPUTE | gw::FEATURE_READBACK;
    if flags & exec::FACT_HAS_TIMESTAMP != 0 {
        features |= gw::FEATURE_TIMESTAMP;
    }
    // Raster, shared surfaces, indirect dispatch, subgroups, preemption and
    // device reset are not implemented in this provider, so none is claimed.
    l.features = features;
    l.targets = [
        gw::TARGET_WGSL,
        gw::TARGET_NONE,
        gw::TARGET_NONE,
        gw::TARGET_NONE,
    ];

    l.min_align = u32_at(exec::FACT_MIN_ALIGN).max(1);
    l.max_bindings = (gw::MAX_PROGRAM_BINDINGS as u32).min(u32_at(exec::FACT_MAX_BINDINGS));
    l.max_workgroup = [
        u32_at(exec::FACT_MAX_WORKGROUP_X),
        u32_at(exec::FACT_MAX_WORKGROUP_Y),
        u32_at(exec::FACT_MAX_WORKGROUP_Z),
    ];
    l.max_workgroup_invocations = u32_at(exec::FACT_MAX_INVOCATIONS);
    let grid = u32_at(exec::FACT_MAX_GRID);
    l.max_grid = [grid, grid, grid];
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&facts[exec::FACT_MAX_BUFFER_BYTES..exec::FACT_MAX_BUFFER_BYTES + 8]);
    l.max_alloc_bytes = u64::from_le_bytes(buf);
    // A browser tab's memory is not the page's to spend without limit. These
    // are the provider's declared ceilings, not the adapter's.
    l.max_resident_bytes = 128 * 1024 * 1024;
    l.max_staging_bytes = 8 * 1024 * 1024;
    l.max_scratch_bytes = l.max_resident_bytes;
    l.max_queue_depth = 32;
    l
}

/// One cooperative step.
///
/// # Safety
/// `st` is the live state; every pointer it holds was allocated in
/// `alloc_state` at the length reconstituted here, and nothing else borrows
/// them during a step.
unsafe fn step(st: &mut GpuComputeState) {
    let cmd = core::slice::from_raw_parts_mut(st.cmd, CMD_BUF);
    let ring = core::slice::from_raw_parts_mut(st.ring, RING_BYTES);
    let pack_buf = core::slice::from_raw_parts_mut(st.pack_buf, PACK_BUF);
    let out_buf = core::slice::from_raw_parts_mut(st.out_buf, gw::MAX_RECORD);
    let exec_buf = core::slice::from_raw_parts_mut(st.exec_buf, EXEC_BUF);
    let rb_buf = core::slice::from_raw_parts_mut(st.rb_buf, RB_BUF);
    let awaiting = core::slice::from_raw_parts_mut(st.awaiting, MAX_FENCES);

    let mut dev = gw::GpuDevice::restore(
        gw::GpuTables {
            resources: core::slice::from_raw_parts_mut(st.resources, MAX_RESOURCES),
            views: core::slice::from_raw_parts_mut(st.views, MAX_VIEWS),
            programs: core::slice::from_raw_parts_mut(st.programs, MAX_PROGRAMS),
            pipelines: core::slice::from_raw_parts_mut(st.pipelines, MAX_PIPELINES),
            fences: core::slice::from_raw_parts_mut(st.fences, MAX_FENCES),
            surfaces: core::slice::from_raw_parts_mut(st.surfaces, MAX_SURFACES),
            outcomes: ring,
        },
        st.limits,
        gw::BACKEND_WEBGPU,
        1,
        st.saved,
    );

    // A device loss ends the epoch. Everything minted before it is gone, and
    // saying so is the whole recovery contract — a consumer rebuilds its
    // derived state rather than working against objects that no longer exist.
    let epoch = host_gpu_service_epoch();
    if epoch != st.backend_epoch {
        st.backend_epoch = epoch;
        dev.bump_epoch(gw::NO_SLOT);
        for a in awaiting.iter_mut() {
            *a = Await::Idle;
        }
    }

    let out_chan = st.out_chan;
    let mut write = |bytes: &[u8]| -> i32 {
        if out_chan < 0 {
            return -1;
        }
        channel::channel_write(out_chan, bytes.as_ptr(), bytes.len())
    };

    poll_backend(&mut dev, awaiting, rb_buf);
    gw::flush_outcomes(&mut dev, out_buf, &mut st.out, &mut write);

    while !st.faulted && (st.cmd_len as usize) < CMD_BUF {
        let room = CMD_BUF - st.cmd_len as usize;
        let n = channel::channel_read(st.in_chan, cmd.as_mut_ptr().add(st.cmd_len as usize), room);
        if n <= 0 {
            break;
        }
        st.cmd_len += n as u32;
    }

    let pack = &mut st.pack;
    let faulted = &mut st.faulted;
    gw::pump_admit(
        &mut dev,
        OWNER,
        cmd,
        &mut st.cmd_len,
        faulted,
        |dev, record, work| translate(dev, awaiting, pack, pack_buf, exec_buf, record, work),
    );

    dev.advance();
    while let Some(fence) = dev.next_ready() {
        dev.mark_running(fence);
        if dev.fence(fence).map_or(0, |f| f.op) == gw::OP_DRAIN {
            awaiting[fence as usize] = Await::Ticket;
            host_gpu_service_drain(fence as u32);
        } else {
            // Everything else was handed to the backend at admission; a fence
            // that reaches here with nothing pending has already done its work.
            dev.complete(fence, 0);
        }
    }

    poll_backend(&mut dev, awaiting, rb_buf);
    gw::flush_outcomes(&mut dev, out_buf, &mut st.out, &mut write);
    // Saved last: draining is what advances the ring's cursor, and a save
    // taken before it would roll that cursor back and re-emit every record.
    st.saved = dev.save();
}

/// Ask the backend about everything outstanding and settle what has finished.
///
/// # Safety
/// Called from the step with a live device and the backend acquired.
unsafe fn poll_backend(dev: &mut gw::GpuDevice<'_>, awaiting: &mut [Await], rb: &mut [u8]) {
    for (slot, entry) in awaiting.iter_mut().enumerate() {
        match *entry {
            Await::Idle => {}

            Await::Pipeline(pipe) => {
                let s = host_gpu_service_poll_pipeline(pipe as u32);
                if s == BACKEND_PENDING {
                    continue;
                }
                *entry = Await::Idle;
                if s == BACKEND_DONE {
                    dev.mark_pipeline_ready(pipe, true);
                    dev.complete(slot as u16, 0);
                } else {
                    // A shader that will not compile is a graph-visible
                    // outcome. Never a dispatch quietly skipped and reported
                    // as successful compute.
                    dev.mark_pipeline_ready(pipe, false);
                    dev.fail(slot as u16, gw::REASON_BAD_PROGRAM, (-s) as u32);
                }
            }

            Await::Ticket => {
                let s = host_gpu_service_poll_submit(slot as u32);
                if s == BACKEND_PENDING {
                    continue;
                }
                *entry = Await::Idle;
                host_gpu_service_release_ticket(slot as u32);
                if s == BACKEND_DONE {
                    // Conservative queue completion, not a per-submit GPU
                    // timestamp: `gpu_nanos` stays zero and the outcome flags
                    // itself queue-timed rather than passing off a CPU reading.
                    dev.complete(slot as u16, 0);
                } else {
                    dev.fail(slot as u16, gw::REASON_DEVICE_LOST, (-s) as u32);
                }
            }

            Await::Readback(resource, offset, remaining) => {
                let owed = dev.result_outstanding(slot as u16);
                if owed == 0 {
                    *entry = Await::Idle;
                    dev.complete(slot as u16, 0);
                    continue;
                }
                let want = (remaining as usize)
                    .min(rb.len())
                    .min(gw::MAX_PAYLOAD as usize - 24);
                let sent = offset;
                let got = host_gpu_service_readback(
                    slot as u32,
                    resource as u32,
                    sent as u32,
                    rb.as_mut_ptr(),
                    want as u32,
                );
                if got == -1 {
                    // Still mapping. Nothing is lost by waiting a step.
                    continue;
                }
                if got < 0 {
                    *entry = Await::Idle;
                    dev.fail(slot as u16, gw::REASON_TIMEOUT, 0);
                    continue;
                }
                let n = got as usize;
                if !dev.push_result(slot as u16, sent, &rb[..n]) {
                    // The outcome ring is full. The bytes stay owed and the
                    // same window is re-read next step; dropping them would be
                    // indistinguishable from work that never ran.
                    continue;
                }
                let left = remaining - n as u32;
                if left == 0 {
                    *entry = Await::Idle;
                    dev.complete(slot as u16, 0);
                } else {
                    *entry = Await::Readback(resource, sent + n as u64, left);
                }
            }
        }
    }
}

/// Hand one admitted request to the backend.
///
/// # Safety
/// Called from the step; every slice borrows a live buffer.
unsafe fn translate(
    dev: &mut gw::GpuDevice<'_>,
    awaiting: &mut [Await],
    pack: &mut gw::PackCursor,
    pack_buf: &mut [u8],
    exec_buf: &mut [u8],
    record: &[u8],
    work: gw::Work,
) -> bool {
    match work {
        gw::Work::None => true,

        gw::Work::CreateBuffer { fence, slot } | gw::Work::CreateTexture { fence, slot } => {
            let (size, usage) = dev.resource(slot).map_or((0, 0), |r| (r.size, r.usage));
            dev.mark_running(fence);
            if host_gpu_service_create_buffer(slot as u32, size as u32, usage) < 0 {
                dev.fail(fence, gw::REASON_RESOURCE_EXHAUSTED, size as u32);
            } else {
                dev.complete(fence, 0);
            }
            true
        }

        gw::Work::DestroyResource { fence, slot } => {
            dev.mark_running(fence);
            if dev.resource_free_pending(slot) || dev.resource(slot).is_none_or(|r| !r.live) {
                host_gpu_service_destroy(slot as u32);
            }
            dev.complete(fence, 0);
            true
        }

        gw::Work::LoadProgram {
            fence,
            slot,
            chunk_offset,
            payload_offset,
            chunk_len,
        } => {
            let Some(bytes) = record.get(payload_offset..payload_offset + chunk_len) else {
                dev.fail(fence, gw::REASON_MALFORMED, 0);
                return true;
            };
            let declared = dev.program(slot).map_or(0, |p| p.declared) as usize;
            // Validated by the shared core before a byte of it reaches a
            // shader compiler.
            if gw::absorb_pack_chunk(dev, pack, pack_buf, fence, slot, chunk_offset, bytes)
                != gw::PackChunk::Loaded
            {
                return true;
            }
            let Ok(p) = gw::decode(&pack_buf[..declared.min(pack_buf.len())]) else {
                dev.fail(fence, gw::REASON_BAD_PROGRAM, 0);
                return true;
            };
            let art = p.artifact();
            let entry = p.entry();
            dev.mark_running(fence);
            if host_gpu_service_program(
                slot as u32,
                art.as_ptr(),
                art.len() as u32,
                entry.as_ptr(),
                entry.len() as u32,
            ) < 0
            {
                dev.fail(fence, gw::REASON_BAD_PROGRAM, 0);
            } else {
                dev.complete(fence, 0);
            }
            true
        }

        gw::Work::CreatePipeline {
            fence,
            slot,
            program,
        } => {
            dev.mark_running(fence);
            if host_gpu_service_pipeline(slot as u32, program as u32) < 0 {
                dev.mark_pipeline_ready(slot, false);
                dev.fail(fence, gw::REASON_BAD_HANDLE, program as u32);
            } else {
                // Compilation is asynchronous; the fence stays open until the
                // backend says which way it went.
                awaiting[fence as usize] = Await::Pipeline(slot);
            }
            true
        }

        gw::Work::ReleaseProgram { fence, slot } => {
            dev.mark_running(fence);
            host_gpu_service_release_program(slot as u32);
            dev.complete(fence, 0);
            true
        }

        gw::Work::ReleasePipeline { fence, slot } => {
            dev.mark_running(fence);
            host_gpu_service_release_pipeline(slot as u32);
            dev.complete(fence, 0);
            true
        }

        gw::Work::Upload {
            fence,
            resource,
            offset,
            payload_offset,
            len,
        } => {
            let Some(bytes) = record.get(payload_offset..payload_offset + len as usize) else {
                dev.fail(fence, gw::REASON_MALFORMED, 0);
                return true;
            };
            dev.mark_running(fence);
            if host_gpu_service_upload(resource as u32, offset as u32, bytes.as_ptr(), len) < 0 {
                dev.fail(fence, gw::REASON_BAD_HANDLE, resource as u32);
            } else {
                dev.complete(fence, 0);
            }
            true
        }

        gw::Work::Readback {
            fence,
            resource,
            offset,
            len,
        } => {
            dev.mark_running(fence);
            awaiting[fence as usize] = Await::Readback(resource, offset, len);
            true
        }

        gw::Work::Submit {
            fence,
            items_offset,
            items_len,
            ..
        } => {
            match encode_exec(dev, exec_buf, record, items_offset, items_len) {
                Some(n) => {
                    dev.mark_running(fence);
                    if host_gpu_service_submit(fence as u32, exec_buf.as_ptr(), n as u32) < 0 {
                        dev.fail(fence, gw::REASON_DEVICE_LOST, 0);
                    } else {
                        awaiting[fence as usize] = Await::Ticket;
                    }
                }
                None => dev.fail(fence, gw::REASON_OVERSIZE, items_len as u32),
            }
            true
        }

        gw::Work::Drain { .. } => true,

        gw::Work::Cancel { fence, .. } => {
            // No preemption is advertised, so there is nothing to ask WebGPU
            // for. The disposition the core already reported is the truth.
            dev.mark_running(fence);
            dev.complete(fence, 0);
            true
        }

        gw::Work::Reset { fence, .. } => {
            dev.fail(
                fence,
                gw::REASON_UNSUPPORTED_FEATURE,
                gw::FEATURE_DEVICE_RESET,
            );
            true
        }

        gw::Work::ExportSurface { fence, .. } => {
            dev.fail(
                fence,
                gw::REASON_UNSUPPORTED_FEATURE,
                gw::FEATURE_SHARED_SURFACE,
            );
            true
        }
    }
}

/// Encode a validated submission for the backend, in table slots.
///
/// Admission already proved every handle, range, alignment, usage and right;
/// this only translates. `None` means the item list would not fit the bounded
/// hand-off buffer, which is a refusal rather than a truncation.
fn encode_exec(
    dev: &gw::GpuDevice<'_>,
    out: &mut [u8],
    record: &[u8],
    items_offset: usize,
    items_len: usize,
) -> Option<usize> {
    let walk = dev.items(record, items_offset, items_len);
    let bytes = walk.bytes();
    let mut at = 0usize;
    for item in dev.items(record, items_offset, items_len) {
        match item {
            gw::SubmitItem::Dispatch {
                pipeline,
                binds_offset,
                bind_count,
                groups,
            } => {
                let pslot = dev.slot_of(pipeline, gw::KIND_PIPELINE, OWNER)?;
                let mut off = at + exec::exec_put_dispatch(&mut out[at..], pslot, bind_count)?;
                for i in 0..bind_count {
                    let e = binds_offset + i * gw::BIND_ENTRY_LEN;
                    let slot = gw::get_u16(bytes, e)?;
                    let view = gw::get_u64(bytes, e + 4)?;
                    let vslot = dev.slot_of(view, gw::KIND_VIEW, OWNER)?;
                    let (res, offset, len) = dev.view_range(vslot)?;
                    // The pack's binding slot IS the shader's `@binding`
                    // index: one number, declared once and used unchanged.
                    exec::exec_put_bind(out, off, u32::from(slot), res, offset, len);
                    off += exec::EXEC_BIND_LEN;
                }
                exec::exec_put_groups(out, off, groups);
                at = off + exec::EXEC_DISPATCH_GROUPS;
            }
            gw::SubmitItem::Copy { src, dst, len } => {
                let s = dev.slot_of(src, gw::KIND_VIEW, OWNER)?;
                let d = dev.slot_of(dst, gw::KIND_VIEW, OWNER)?;
                let (src_slot, src_off, _) = dev.view_range(s)?;
                let (dst_slot, dst_off, _) = dev.view_range(d)?;
                at +=
                    exec::exec_put_copy(&mut out[at..], src_slot, dst_slot, src_off, dst_off, len)?;
            }
            // Raster items cannot be admitted: this provider does not
            // advertise `FEATURE_RASTER`, so the queue check refuses them.
            _ => return None,
        }
    }
    Some(at)
}

/// Build the module. Returns a built-in whose state is null when the heap
/// could not satisfy it — the step then does nothing rather than fault.
///
/// # Safety
/// Called once per instance from the platform's graph construction.
pub(crate) unsafe fn build(in_chan: i32, out_chan: i32) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_compute", gpu_compute_step);
    let raw = alloc_state(in_chan, out_chan);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut GpuComputeState, raw);
    m
}
