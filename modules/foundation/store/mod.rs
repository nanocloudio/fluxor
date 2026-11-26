//! store — the versioned watchable key store.
//!
//! One keyspace served as the standard storage surfaces: `storage.object`
//! (conditional and streamed writes, `GET`/`RANGE_GET`/`HEAD`, `LIST`,
//! capability grants) and `storage.namespace` (`LIST`, `SUBSCRIBE`,
//! `CHANGES`). A monotone revision clock stamps every write; a key's
//! revision is its CAS token and its etag; a bounded key-only history
//! answers `CHANGES` from a revision.
//!
//! # Tables
//!
//! Every table comes from the instance's heap, sized from its params:
//! `objects` entries (live keys and the tombstones of deletes the history
//! still holds), a sorted index over them, `history` change entries, `reads`
//! `GET` slots, `writes` streamed-write slots and `grants` grants. Keys and
//! values are heap blocks charged against `value_bytes`, a streamed write's
//! staged bytes too; a write past it is `ENOSPC`, a new key past `objects`
//! `ENOMEM` (the oldest tombstone is retired first, and the history base
//! moves past it). Subscriptions are taken from the heap as they are asked
//! for, in pages: the composer grows the heap by the graph's declared
//! `store_subs` demand, and a subscription the heap cannot hold is refused
//! and counted against that pool (`LEDGER_DENY`).
//!
//! # Durability
//!
//! `durable = on`: the store is an append log, `<dir>/store.log`, written
//! through the `fs` contract beneath. Record:
//!
//! ```text
//!   [rev u64 LE][op u8][key_len u16 LE][val_len u32 LE][key][value]
//! ```
//!
//! `op` 1 is a put, 2 a delete. A partial record at the end — a crash
//! mid-append — is cut off at open. A write appends its record and fences
//! it (`FSYNC`) before it applies; until then it answers `EINPROGRESS` and
//! is asked again byte-identical, and the answer that decides it carries
//! `LocalDurable` on the filesystem's device. One write is in flight at a
//! time: another is refused `EBUSY` meanwhile. The store's step carries an
//! undecided write on when its caller stops asking, and keeps the decision
//! for the ask that collects it. A write the filesystem refuses lands
//! nothing and answers `ERROR`; the log, which may then end in part of its
//! record, is rewritten from its fenced records as an open rewrites it, and
//! the store answers `EAGAIN` meanwhile.
//!
//! A filesystem may truncate a file it opens for writing (FAT32 does), so
//! the log is never reopened for appending. Open replays the log, copies its
//! valid records to `store.cpy` and publishes that as `store.bak`, then
//! rewrites `store.log` from it and removes `store.bak`: a crash at any
//! point leaves either the old log or a whole `store.bak`, which the next
//! open replays from. The store answers `EAGAIN` and reports not ready until
//! the open is done; the contract-readiness gate holds its consumers
//! meanwhile.
//!
//! `durable = off`: RAM only. Every write decides inside the call and
//! reports `RevisionMonotone`: the order holds, nothing survives a restart.
//!
//! # Scoping
//!
//! Every handle (`GET` read, streamed write, subscription) is stamped with
//! its opener's owner (`CALLER_OWNER`) and answers that owner alone; an
//! owner's release (`OWNER_RELEASED`) closes what it held. Which callers
//! reach this store is the kernel's to decide: the store of a workload is a
//! module of that workload, over that workload's rooted `fs`.
//!
//! # Grants
//!
//! `roots` set (one or two hex Ed25519 keys): every `storage.object` op runs
//! under a grant `PRESENT` verified against those roots and the trusted
//! clock, scoped to a key prefix; the namespace surface, which cannot carry
//! a grant, answers `EACCES`. No `roots`: `PRESENT` is `ENOSYS`.

#![cfg_attr(not(feature = "host-test"), no_std)]

use core::ffi::c_void;

use abi::contracts::mesh::capability as cap;
use abi::contracts::storage::handle::STORAGE_KEY_MAX;
use abi::contracts::storage::{fs, namespace as ns_op, object as obj_op};
use abi::fence::{trailer, Fence};
use abi::kernel_abi::{doorbell, query_key};
use abi::registry::errno::{
    EACCES, EAGAIN, EBADF, EBUSY, EEXIST, EINPROGRESS, EINVAL, EIO, ENOENT, ENOMEM, ENOSPC, ENOSYS,
    ENXIO, EOVERFLOW, ERROR,
};
use abi::SyscallTable;
use fluxor_abi as abi;
use fluxor_rt::*;
use fluxor_sdk::crypto::ed25519::ed25519_verify;
use fluxor_sdk::crypto::sha256::{sha256, Sha256};

include!("engine.rs");
include!("log.rs");
include!("object.rs");
include!("namespace.rs");

/// The fence source a revision fence names: the same bytes on every node,
/// so a consumer matching on it need not know which store answered.
const STORE_SOURCE: [u8; 16] = *b"fluxor-cp-store\0";

/// Longest `dir`.
const DIR_MAX: usize = 96;
/// The longest path the store names: `dir` and `/store.log`.
const PATH_MAX: usize = DIR_MAX + 16;
/// Most mesh roots a guarded store verifies against.
const MAX_ROOTS: usize = cap::MAX_ROOTS;

/// The heap the instance starts from before its tables: the replay and
/// copy buffer and allocator slack. The manifest's `heap_per_param` base.
const HEAP_BASE: u32 = 8192;

/// `durable` values.
const DURABLE_OFF: u8 = 0;
const DURABLE_ON: u8 = 1;
/// Most objects a store indexes: its index doubles past this.
const OBJECTS_MAX: u32 = u32::MAX / 2;

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,

    // ── params ──
    dir: [u8; DIR_MAX],
    dir_len: usize,
    durable: u8,
    n_objects: u32,
    value_bytes: u32,
    n_history: u32,
    stage_max: u32,
    n_reads: u16,
    n_writes: u16,
    n_grants: u16,
    /// History entries (or relisted keys) one `CHANGES` call walks at most.
    changes_budget: u32,
    roots: [[u8; 32]; MAX_ROOTS],
    n_roots: u8,
    /// The `roots` param did not parse: the store refuses to construct.
    roots_bad: u8,

    // ── keyspace ──
    entries: *mut Entry,
    /// Entry slots in key order: the live keys and the tombstones.
    index: *mut u32,
    n_index: u32,
    /// Value-arena bytes in use (blocks and staged chunks, each with its
    /// allocator overhead).
    value_used: u64,
    revision: u64,
    hist: *mut Hist,
    hist_head: u32,
    hist_len: u32,
    /// Every revision after this one is in the history.
    history_base: u64,
    /// A `CHANGES` call's mark on the entries it passed over.
    call_mark: u32,

    // ── handles ──
    reads: *mut ReadSlot,
    writes: *mut WriteSlot,
    grants: *mut Grant,
    sub_pages: [*mut Sub; MAX_SUB_PAGES],
    n_sub_pages: u16,

    // ── the log ──
    open: Open,
    log_fd: i32,
    log_len: u64,
    /// The device the filesystem's `LocalDurable` fences name.
    device: u64,
    device_known: u8,
    io_buf: *mut u8,
    inflight: InFlight,
    settled: Settled,
}

mod params_def {
    use super::*;
    fluxor_rt::define_params! {
        State;

        1, dir, str, 0, max DIR_MAX => |s, d, len| {
            if len > DIR_MAX {
                s.dir_len = DIR_MAX + 1;
            } else {
                core::ptr::copy_nonoverlapping(d, s.dir.as_mut_ptr(), len);
                s.dir_len = len;
            }
        };

        2, durable, u8, 1, enum { off=0, on=1 }
            => |s, d, len| { s.durable = p_u8(d, len, 0, DURABLE_ON); };

        3, objects, u32, 512, range 1..=OBJECTS_MAX
            => |s, d, len| { s.n_objects = p_u32(d, len, 0, 512); };

        4, value_bytes, u32, 262144
            => |s, d, len| { s.value_bytes = p_u32(d, len, 0, 262144); };

        5, history, u32, 4096, range 1..=u32::MAX
            => |s, d, len| { s.n_history = p_u32(d, len, 0, 4096); };

        6, stage_max, u32, 65536
            => |s, d, len| { s.stage_max = p_u32(d, len, 0, 65536); };

        7, reads, u16, 8
            => |s, d, len| { s.n_reads = p_u16(d, len, 0, 8); };

        8, writes, u16, 2
            => |s, d, len| { s.n_writes = p_u16(d, len, 0, 2); };

        9, grants, u16, 16
            => |s, d, len| { s.n_grants = p_u16(d, len, 0, 16); };

        11, roots, str, 0 => |s, d, len| {
            parse_roots(s, core::slice::from_raw_parts(d, len));
        };

        12, changes_budget, u32, 1024, range 1..=u32::MAX
            => |s, d, len| { s.changes_budget = p_u32(d, len, 0, 1024); };
    }
}

/// `roots`: one or two 64-hex-digit Ed25519 keys, comma-separated.
fn parse_roots(s: &mut State, v: &[u8]) {
    s.n_roots = 0;
    s.roots_bad = 0;
    for item in v.split(|&b| b == b',') {
        let item = trim(item);
        if item.is_empty() && v.iter().all(|b| b.is_ascii_whitespace() || *b == b',') {
            continue;
        }
        if item.len() != 64 || usize::from(s.n_roots) == MAX_ROOTS {
            s.roots_bad = 1;
            return;
        }
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            match (hex(item[2 * i]), hex(item[2 * i + 1])) {
                (Some(h), Some(l)) => *b = h << 4 | l,
                _ => {
                    s.roots_bad = 1;
                    return;
                }
            }
        }
        s.roots[usize::from(s.n_roots)] = k;
        s.n_roots += 1;
    }
}

fn trim(b: &[u8]) -> &[u8] {
    let start = b
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map_or(start, |e| e + 1);
    &b[start..end]
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl State {
    fn sys(&self) -> &SyscallTable {
        // SAFETY: set by `module_new` from the loader's table, which lives
        // for the module's lifetime.
        unsafe { &*self.syscalls }
    }

    fn dir(&self) -> &[u8] {
        &self.dir[..self.dir_len.min(DIR_MAX)]
    }

    fn guarded(&self) -> bool {
        self.n_roots > 0
    }
}

// ── kernel services ───────────────────────────────────────────────────

fn log(s: &State, level: u8, msg: &[u8]) {
    // SAFETY: `msg` is live for the call.
    unsafe { dev_log(s.sys(), level, msg.as_ptr(), msg.len()) };
}

/// A kernel call with `arg` and no `data`.
fn kcall(s: &State, op: u32, arg: &mut [u8]) -> i32 {
    // SAFETY: `arg` is live for the call.
    unsafe {
        (s.sys().provider_call)(
            -1,
            op,
            arg.as_mut_ptr(),
            arg.len(),
            core::ptr::null_mut(),
            0,
        )
    }
}

/// An 8-byte record a `handle = -1` query answers (`CALLER_OWNER`,
/// `CALLER_MODULE`'s first 8 bytes), or zeros when there is no caller.
fn query8(s: &State, key: u32) -> [u8; 8] {
    let mut r = [0u8; 12];
    // SAFETY: `r` is writable for its length.
    let rc = unsafe { (s.sys().provider_query)(-1, key, r.as_mut_ptr(), r.len()) };
    let mut out = [0u8; 8];
    if rc >= 8 {
        out.copy_from_slice(&r[..8]);
    }
    out
}

/// The calling module's owner record.
fn caller_owner(s: &State) -> [u8; 8] {
    query8(s, query_key::CALLER_OWNER)
}

/// The calling module's occupancy `[idx u16][0 u16][gen u32]`.
fn caller_module(s: &State) -> [u8; 8] {
    query8(s, query_key::CALLER_MODULE)
}

/// Whether the module occupancy `rec` names is still live.
fn module_live(s: &State, rec: &[u8; 8]) -> bool {
    let mut r = *rec;
    // SAFETY: `r` is writable for its length.
    let rc = unsafe { (s.sys().provider_query)(-1, query_key::MODULE_LIVE, r.as_mut_ptr(), 8) };
    rc > 0
}

fn heap_take(s: &State, bytes: usize) -> *mut u8 {
    let Ok(b) = u32::try_from(bytes) else {
        return core::ptr::null_mut();
    };
    if b == 0 {
        return core::ptr::null_mut();
    }
    // SAFETY: this instance's heap.
    let p = unsafe { heap_alloc(s.sys(), b) };
    if !p.is_null() {
        // SAFETY: `p` names `bytes` fresh bytes.
        unsafe { core::ptr::write_bytes(p, 0, bytes) };
    }
    p
}

fn heap_give(s: &State, p: *mut u8) {
    if !p.is_null() {
        // SAFETY: `p` came from this instance's heap.
        unsafe { heap_free(s.sys(), p) };
    }
}

/// One table of `n` `T`s from the heap, zeroed: null when it does not fit
/// (or `n` is 0).
fn take_table<T>(s: &State, n: usize) -> *mut T {
    heap_take(s, n.saturating_mul(core::mem::size_of::<T>())).cast()
}

/// Write `fence` into the trailer of `arg`.
fn write_fence(fence: Fence, arg: &mut [u8]) {
    trailer::put(arg, &fence);
}

/// The fence a write that landed at `rev` achieved.
fn write_fence_of(s: &State, rev: u64) -> Fence {
    if s.durable == DURABLE_OFF {
        Fence::RevisionMonotone {
            source: STORE_SOURCE,
            revision: rev,
        }
    } else if s.device_known != 0 {
        Fence::LocalDurable {
            device_id: s.device,
        }
    } else {
        Fence::Volatile
    }
}

/// The fence a read at the current state achieved.
fn view_fence(s: &State) -> Fence {
    Fence::ViewConsistent {
        source: STORE_SOURCE,
        revision: s.revision,
    }
}

// ── construction ──────────────────────────────────────────────────────

fn refuse(s: &State, why: &[u8]) -> i32 {
    log(s, 1, why);
    -1
}

fn construct(s: &mut State) -> i32 {
    if s.dir_len > DIR_MAX {
        return refuse(
            s,
            b"[store] refusing to construct: `dir` is longer than 96 bytes",
        );
    }
    if s.durable > DURABLE_ON {
        return refuse(s, b"[store] refusing to construct: `durable` out of range");
    }
    if s.roots_bad != 0 {
        return refuse(
            s,
            b"[store] refusing to construct: `roots` is not one or two 64-hex-digit keys",
        );
    }
    if s.n_objects == 0 || s.n_history == 0 || s.changes_budget == 0 || s.n_objects > OBJECTS_MAX {
        return refuse(
            s,
            b"[store] refusing to construct: `objects`, `history` and `changes_budget` must be at least 1",
        );
    }
    if s.durable == DURABLE_ON && (s.dir_len == 0 || s.dir[0] != b'/') {
        return refuse(
            s,
            b"[store] refusing to construct: a durable store needs an absolute `dir`",
        );
    }
    s.entries = take_table(s, s.n_objects as usize);
    s.index = take_table(s, s.n_objects as usize);
    s.hist = take_table(s, s.n_history as usize);
    s.reads = take_table(s, usize::from(s.n_reads));
    s.writes = take_table(s, usize::from(s.n_writes));
    s.grants = take_table(s, usize::from(s.n_grants));
    if s.durable == DURABLE_ON {
        s.io_buf = heap_take(s, IO_BUF);
    }
    if s.entries.is_null()
        || s.index.is_null()
        || s.hist.is_null()
        || (s.n_reads > 0 && s.reads.is_null())
        || (s.n_writes > 0 && s.writes.is_null())
        || (s.n_grants > 0 && s.grants.is_null())
        || (s.durable == DURABLE_ON && s.io_buf.is_null())
    {
        return refuse(
            s,
            b"[store] refusing to construct: the heap does not hold the tables its params size",
        );
    }
    for w in writes_mut(s).iter_mut() {
        w.grant = -1;
    }
    s.log_fd = -1;
    s.open = Open::new();
    s.inflight = InFlight::EMPTY;
    s.open.phase = if s.durable == DURABLE_ON {
        OPEN_CAPS
    } else {
        OPEN_READY
    };
    0
}

fluxor_rt::module_facts! { state: State, arena: HEAP_BASE }

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_init")]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_new")]
pub unsafe extern "C" fn module_new(
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if syscalls.is_null() || state.is_null() {
        return -1;
    }
    if state_size < core::mem::size_of::<State>() {
        return -2;
    }
    // SAFETY: the loader hands a block of at least `State`'s size, zeroed
    // here before it is read as one; every field is valid at all-zero bytes.
    let s = unsafe {
        core::ptr::write_bytes(state, 0, core::mem::size_of::<State>());
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        params_def::set_defaults(s);
        let default_dir = b"/store";
        s.dir[..default_dir.len()].copy_from_slice(default_dir);
        s.dir_len = default_dir.len();
        if !params.is_null() && params_len > 0 {
            params_def::parse_tlv(s, params, params_len);
        }
        s
    };
    construct(s)
}

/// Opens the log, then carries an undecided write on. `Ready` once the
/// store serves; an open that cannot finish faults the module, naming why.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_step")]
pub extern "C" fn module_step(state: *mut u8) -> StepReturn {
    if state.is_null() {
        return StepReturn::error(EINVAL);
    }
    // SAFETY: the kernel passes the block `module_new` initialised.
    let s = unsafe { &mut *(state as *mut State) };
    if s.open.phase != OPEN_READY {
        return match open_step(s) {
            OpenStep::Pending => StepReturn::Continue,
            OpenStep::Ready => StepReturn::Ready,
            OpenStep::Failed(e) => StepReturn::error(e),
        };
    }
    if s.open.announced == 0 {
        s.open.announced = 1;
        return StepReturn::Ready;
    }
    carry_inflight(s);
    StepReturn::Continue
}

/// # Safety
/// Kernel provider-dispatch entry point: `state` is the instance block this
/// module's `module_new` initialised, `arg` points to `arg_len` bytes and
/// `data` to `data_len` bytes (either may be null when its length is 0),
/// disjoint and valid for the call.
#[cfg_attr(
    not(feature = "host-test"),
    link_section = ".text.module_provider_dispatch"
)]
#[cfg_attr(not(feature = "host-test"), export_name = "module_provider_dispatch")]
pub unsafe extern "C" fn store_dispatch(
    state: *mut u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
    data: *mut u8,
    data_len: usize,
) -> i32 {
    if state.is_null() {
        return EINVAL;
    }
    // SAFETY: the kernel passes the state block `module_new` initialised.
    let s = unsafe { &mut *(state as *mut State) };
    let a: &mut [u8] = if arg.is_null() || arg_len == 0 {
        &mut []
    } else {
        // SAFETY: the caller named `arg_len` bytes at `arg` for the call.
        unsafe { core::slice::from_raw_parts_mut(arg, arg_len) }
    };
    let d: &mut [u8] = if data.is_null() || data_len == 0 {
        &mut []
    } else {
        // SAFETY: the caller named `data_len` bytes at `data`, disjoint
        // from `arg`, for the call.
        unsafe { core::slice::from_raw_parts_mut(data, data_len) }
    };
    dispatch(s, handle, opcode, a, d)
}

fn dispatch(s: &mut State, handle: i32, opcode: u32, a: &mut [u8], d: &mut [u8]) -> i32 {
    match opcode {
        abi::internal::reconfigure::OWNER_RELEASED => {
            owner_released(s, a);
            0
        }
        abi::contracts::resource::POOL_SAMPLE => pool_sample(s, a),
        doorbell::BIND_DOORBELL => ns_bind_doorbell(s, handle, a),
        abi::fence::QUERY_OP => read_fence(s, handle, a),
        obj_op::CAPS => object_caps(s, a),
        ns_op::CAPS => {
            if s.guarded() {
                return EACCES;
            }
            abi::kernel_abi::caps_word::answer(a, ns_op::caps::SUBSCRIBE | ns_op::caps::CHANGES)
        }
        // A handle closes whether or not the store is up.
        ns_op::CLOSE => ns_close(s, handle),
        _ if s.open.phase != OPEN_READY => {
            if s.open.failed != 0 {
                EIO
            } else {
                EAGAIN
            }
        }
        op if op >> 8 == u32::from(abi::registry::storage_object::ID) => {
            object_call(s, handle, op, a, d)
        }
        op if op >> 8 == u32::from(abi::registry::storage_namespace::ID) => {
            namespace_call(s, handle, op, a, d)
        }
        _ => ENOSYS,
    }
}

/// `OWNER_RELEASED`: every handle the released owner held goes. A write it
/// left in flight is decided in the log and lands; only its answer is
/// uncollected.
fn owner_released(s: &mut State, a: &[u8]) {
    let Some(rec) = a.get(..8) else { return };
    let mut owner = [0u8; 8];
    owner.copy_from_slice(rec);
    for i in 0..usize::from(s.n_reads) {
        if reads(s)[i].in_use != 0 && reads(s)[i].owner == owner {
            close_read(s, i);
        }
    }
    for i in 0..usize::from(s.n_writes) {
        if writes(s)[i].in_use != 0 && writes(s)[i].owner == owner {
            drop_write(s, i);
        }
    }
    release_subs_of(s, &owner);
}

/// `POOL_SAMPLE` for `store_subs`: the subscriptions held now.
fn pool_sample(s: &State, a: &[u8]) -> i32 {
    match a {
        [lo, hi, ..]
            if u16::from_le_bytes([*lo, *hi]) == abi::contracts::resource::POOL_STORE_SUBS =>
        {
            live_subs(s) as i32
        }
        _ => EINVAL,
    }
}

fluxor_rt::wasm_entry!();
