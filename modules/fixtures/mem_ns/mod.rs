//! mem_ns — RAM-backed `storage.namespace` fixture provider.
//!
//! The contract-proving provider for the namespace surface
//! (`modules/sdk/contracts/storage/namespace.rs`), and the implementor of
//! `BIND` (0x1308) that proves it. Exists so the surface — and the
//! `mount` routing tier above it — is testable with **no on-disk
//! format in the loop**: a repo that owns a contract holds an in-repo
//! provider that proves it.
//!
//! Every binding lives in the module's state arena: a fixed table of
//! `path → {kind, target}` entries plus a LOOKUP handle table. All
//! fences are honestly `Volatile` — nothing here survives a power
//! cut, and a fixture that claimed otherwise would defeat the fence
//! axis it exists to exercise.
//!
//! Implements: BIND, LOOKUP, STAT, LIST, RENAME, DELETE, CLOSE,
//! SUBSCRIBE, TAKE_RUNG, CHANGES, CAPS
//! (BIND|RENAME|DELETE|SUBSCRIBE|CHANGES).
//!
//! # Subscriptions
//!
//! Small and fixed, but the whole doorbell contract: a subscription names
//! the caller's own kernel event (refused unless `EVENT_OWNER` says the
//! caller's module owns it) and is stamped with the caller's owner record
//! and module occupancy. A change under its prefix sets its *rung* bit and
//! signals the event when the bit was clear — after checking, every time,
//! that the occupancy still stands (`MODULE_LIVE`) and still owns the
//! event; a subscription that fails either is dropped, never signalled.
//! `TAKE_RUNG` returns and clears the caller's rung bits on an event,
//! signalling again when they do not all fit.
//!
//! `CHANGES` is served from a key-only change log of the last
//! [`LOG_CAP`] entries `{rev, path, hint}`, one per key a write touched
//! (a `RENAME` touches two under one revision), paged within
//! [`SCAN_BUDGET`] entries and the caller's buffer. Records are read at
//! the current table: present → `Added`/`Modified` with the target as its
//! value, absent → `Deleted`, never omitted; a key is reported at its
//! last entry only, so no record carries a revision past the page's cut.
//! A `since` older than the log reaches is `LOST`, and the empty token
//! relists the prefix by path, pinned at the revision its first page saw.
//! Nothing here waits, so no answer is `EAGAIN` and a read's `sub` is
//! never re-rung.
//!
//! # Parameters
//!
//! None. The `ctl` input port is declared for symmetry with `mount`
//! and stays inert when unwired.

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    dead_code,
    reason = "the PIC build mounts the whole of modules/sdk/* via include!, so every \
              module's compile sees the entire ABI surface while using a subset. This \
              allow is the SDK's textual mounting showing through"
)]
#![allow(
    unused_imports,
    reason = "same cause: the mounted SDK brings names this module does not reach for"
)]
#![allow(
    unreachable_patterns,
    reason = "defensive `_ => Error` arms in enum state-machine matches. The match is \
              exhaustive, which is why the lint fires; the arm exists so that adding a \
              variant cannot silently bypass the error path. #[expect] is not the \
              alternative — it fails the build in the configurations where the lint \
              does not fire"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

// Namespace contract opcodes (modules/sdk/contracts/storage/namespace.rs).
const NS_LOOKUP: u32 = 0x1300;
const NS_STAT: u32 = 0x1301;
const NS_LIST: u32 = 0x1302;
const NS_RENAME: u32 = 0x1303;
const NS_DELETE: u32 = 0x1304;
const NS_SUBSCRIBE: u32 = 0x1305;
const NS_CLOSE: u32 = 0x1306;
const NS_CHANGES: u32 = 0x1307;
const NS_BIND: u32 = 0x1308;
const NS_TAKE_RUNG: u32 = 0x1309;
const NS_CAPS: u32 = 0x13FF;

// namespace.rs::caps bits.
const NS_CAP_BIND: u32 = 1 << 0;
const NS_CAP_RENAME: u32 = 1 << 1;
const NS_CAP_DELETE: u32 = 1 << 2;
const NS_CAP_SUBSCRIBE: u32 = 1 << 3;
const NS_CAP_CHANGES: u32 = 1 << 4;

use abi::contracts::storage::namespace::{changes, subscribe, take};
use abi::kernel_abi::{event as kevent, fd, query_key};

// Entry kind tags.
const KIND_MAX: u8 = 2; // 0=object, 1=namespace, 2=stream

// Errnos beyond the SDK's consts.rs set (E_INVAL/E_NOSYS come from the
// runtime include).
const E_NOENT: i32 = -2;
const E_EXIST: i32 = -17;
const E_NOSPC: i32 = -28;
const E_NOMEM: i32 = -12;

const MAX_BINDINGS: usize = 64;
const MAX_PATH: usize = 96;
const MAX_TARGET: usize = 64;
const MAX_OPEN: usize = 8;

/// Subscriptions held at once, across every owner.
const MAX_SUBS: usize = 8;
/// Subscriptions one owner may hold: one owner cannot take the pool.
const SUB_QUOTA: usize = 4;
/// Raw slot band of subscription handles, beside the LOOKUP slots below
/// it, so `CLOSE` tells the two apart from the slot alone.
const SUB_BAND: i32 = 0x100;
/// Change-log entries kept; older ones are gone, and a `since` before
/// them is `LOST`.
const LOG_CAP: usize = 32;
/// Log entries (or relisted bindings) one `CHANGES` call walks at most.
const SCAN_BUDGET: usize = 16;

// Change-log hints: advisory, they only label a present key Added or
// Modified.
const HINT_CREATED: u8 = 0;
const HINT_MODIFIED: u8 = 1;
const HINT_DELETED: u8 = 2;

// Continuation tokens this provider issues. Never 8 bytes long — 8 bytes
// is a bare revision.
/// `[b'L'][rev u64][ordinal u16]`: the next log entry to read.
const TOKEN_LOG: u8 = b'L';
const TOKEN_LOG_LEN: usize = 11;
/// `[b'R'][pinned rev u64][last path]`: a relist resumed after a path.
const TOKEN_RELIST: u8 = b'R';
const TOKEN_RELIST_MAX: usize = 9 + MAX_PATH;

#[repr(C)]
#[derive(Clone, Copy)]
struct Binding {
    /// Revision of the write that last set this binding.
    mod_rev: u64,
    in_use: u8,
    kind: u8,
    path_len: u8,
    target_len: u8,
    path: [u8; MAX_PATH],
    target: [u8; MAX_TARGET],
}

const BINDING_EMPTY: Binding = Binding {
    mod_rev: 0,
    in_use: 0,
    kind: 0,
    path_len: 0,
    target_len: 0,
    path: [0; MAX_PATH],
    target: [0; MAX_TARGET],
};

#[repr(C)]
#[derive(Clone, Copy)]
struct OpenSlot {
    in_use: u8,
    binding: u8, // index into bindings
}

/// A subscription: whose it is, where it rings, what it watches.
#[repr(C)]
#[derive(Clone, Copy)]
struct Sub {
    in_use: u8,
    /// Set by a change, cleared by `TAKE_RUNG`; while set, further
    /// changes do nothing.
    rung: u8,
    prefix_len: u8,
    _pad: u8,
    /// The subscriber's tagged event fd.
    event: i32,
    /// `CALLER_OWNER` record of the opener.
    owner: [u8; 8],
    /// `CALLER_MODULE` record of the opener: the occupancy that must
    /// still stand, and still own `event`, for a signal to be sent.
    occ: [u8; 8],
    prefix: [u8; MAX_PATH],
}

const SUB_EMPTY: Sub = Sub {
    in_use: 0,
    rung: 0,
    prefix_len: 0,
    _pad: 0,
    event: -1,
    owner: [0; 8],
    occ: [0; 8],
    prefix: [0; MAX_PATH],
};

/// One change-log entry: a key a write touched, at the write's revision.
#[repr(C)]
#[derive(Clone, Copy)]
struct LogEntry {
    rev: u64,
    hint: u8,
    path_len: u8,
    path: [u8; MAX_PATH],
}

const LOG_EMPTY: LogEntry = LogEntry {
    rev: 0,
    hint: 0,
    path_len: 0,
    path: [0; MAX_PATH],
};

#[repr(C)]
struct MemNsState {
    syscalls: *const SyscallTable,
    revision: u64,
    /// Highest revision any of whose log entries has been overwritten:
    /// a `since` below it cannot be answered.
    lost_upto: u64,
    bindings: [Binding; MAX_BINDINGS],
    open: [OpenSlot; MAX_OPEN],
    subs: [Sub; MAX_SUBS],
    /// Ring of the newest `log_len` entries, oldest at `log_head`, in
    /// `(rev, apply order)` order.
    log: [LogEntry; LOG_CAP],
    log_head: u16,
    log_len: u16,
}

declare_module_state_bytes!(MemNsState);

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_state_size")]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<MemNsState>() as u32
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_init")]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_new")]
pub extern "C" fn module_new(
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<MemNsState>() {
            return -2;
        }
        let s = &mut *(state as *mut MemNsState);
        s.syscalls = syscalls as *const SyscallTable;
        s.revision = 0;
        s.lost_upto = 0;
        let mut k = 0;
        while k < MAX_SUBS {
            s.subs[k] = SUB_EMPTY;
            k += 1;
        }
        let mut k = 0;
        while k < LOG_CAP {
            s.log[k] = LOG_EMPTY;
            k += 1;
        }
        s.log_head = 0;
        s.log_len = 0;
        let mut i = 0;
        while i < MAX_BINDINGS {
            s.bindings[i] = BINDING_EMPTY;
            i += 1;
        }
        let mut j = 0;
        while j < MAX_OPEN {
            s.open[j] = OpenSlot {
                in_use: 0,
                binding: 0,
            };
            j += 1;
        }
        0
    }
}

/// Providers are called through `provider_call`, never stepped for work;
/// this exists to satisfy the module ABI.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_step")]
pub extern "C" fn module_step(_state: *mut u8) -> i32 {
    0 // Continue
}

// ── arg-parse helpers (bounds-checked, LE) ─────────────────────────

#[inline]
fn get_u16(a: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*a.get(off)?, *a.get(off + 1)?]))
}

#[inline]
fn get_u64(a: &[u8], off: usize) -> Option<u64> {
    let mut b = [0u8; 8];
    let mut i = 0;
    while i < 8 {
        b[i] = *a.get(off + i)?;
        i += 1;
    }
    Some(u64::from_le_bytes(b))
}

/// Write the achieved fence — always `Volatile` here — into the caller's
/// `[fence_out_ptr, fence_out_cap]` pair. A null/short buffer is EINVAL,
/// mirroring the platform providers.
unsafe fn write_volatile_fence(a: &[u8], off: usize) -> i32 {
    let Some(fptr) = get_u64(a, off) else {
        return E_INVAL;
    };
    let Some(fcap) = get_u16(a, off + 8) else {
        return E_INVAL;
    };
    write_volatile_fence_at(fptr, fcap)
}

/// Write a `Volatile` fence into the caller's `[fptr, fptr + fcap)`.
unsafe fn write_volatile_fence_at(fptr: u64, fcap: u16) -> i32 {
    let fcap = fcap as usize;
    if fptr == 0 || fcap < abi::fence::WIRE_MAX_LEN {
        return E_INVAL;
    }
    let buf = core::slice::from_raw_parts_mut(fptr as *mut u8, fcap);
    match abi::fence::Fence::Volatile.encode(buf) {
        Some(_) => 0,
        None => E_INVAL,
    }
}

fn find_binding(s: &MemNsState, path: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < MAX_BINDINGS {
        let b = &s.bindings[i];
        if b.in_use != 0 && &b.path[..b.path_len as usize] == path {
            return Some(i);
        }
        i += 1;
    }
    None
}

// ── ops ────────────────────────────────────────────────────────────

/// BIND — `[path_len:u16][path][kind:u8][flags:u8][target_len:u16][target]
/// [fence_out_ptr:u64][fence_out_cap:u16]`.
unsafe fn ns_bind(s: &mut MemNsState, a: &[u8]) -> i32 {
    let Some(pl) = get_u16(a, 0).map(|v| v as usize) else {
        return E_INVAL;
    };
    if pl == 0 || pl > MAX_PATH || a.len() < 2 + pl + 2 {
        return E_INVAL;
    }
    let path = &a[2..2 + pl];
    // A path is what LIST names, and a listed name is UTF-8.
    if !utf8_valid(path) {
        return E_INVAL;
    }
    let kind = a[2 + pl];
    let flags = a[2 + pl + 1];
    if kind > KIND_MAX {
        return E_INVAL;
    }
    let Some(tl) = get_u16(a, 2 + pl + 2).map(|v| v as usize) else {
        return E_INVAL;
    };
    if tl > MAX_TARGET || a.len() < 2 + pl + 4 + tl + 10 {
        return E_INVAL;
    }
    let target_off = 2 + pl + 4;
    let fence_off = target_off + tl;

    let existing = find_binding(s, path);
    let slot = match existing {
        Some(idx) if flags & 0x01 == 0 => {
            let _ = idx;
            return E_EXIST;
        }
        Some(idx) => idx,
        None => {
            let mut free = None;
            let mut i = 0;
            while i < MAX_BINDINGS {
                if s.bindings[i].in_use == 0 {
                    free = Some(i);
                    break;
                }
                i += 1;
            }
            match free {
                Some(i) => i,
                None => return E_NOSPC,
            }
        }
    };

    // Fence write can still fail on a malformed buffer; do it BEFORE
    // mutating so a failed call leaves the table untouched.
    let frc = write_volatile_fence(a, fence_off);
    if frc != 0 {
        return frc;
    }

    s.revision += 1;
    let b = &mut s.bindings[slot];
    b.mod_rev = s.revision;
    b.in_use = 1;
    b.kind = kind;
    b.path_len = pl as u8;
    b.path[..pl].copy_from_slice(path);
    b.target_len = tl as u8;
    b.target[..tl].copy_from_slice(&a[target_off..target_off + tl]);
    let hint = if existing.is_some() {
        HINT_MODIFIED
    } else {
        HINT_CREATED
    };
    changed(s, path, hint);
    0
}

/// LOOKUP — arg is the raw UTF-8 path; returns an open handle.
fn ns_lookup(s: &mut MemNsState, a: &[u8]) -> i32 {
    if a.is_empty() || a.len() > MAX_PATH {
        return E_INVAL;
    }
    let Some(bidx) = find_binding(s, a) else {
        return E_NOENT;
    };
    let mut i = 0;
    while i < MAX_OPEN {
        if s.open[i].in_use == 0 {
            s.open[i] = OpenSlot {
                in_use: 1,
                binding: bidx as u8,
            };
            return i as i32;
        }
        i += 1;
    }
    E_NOSPC
}

/// STAT — handle-bound; output per namespace.rs (size/mtime/kind/etag).
unsafe fn ns_stat(s: &MemNsState, handle: i32, arg: *mut u8, arg_len: usize) -> i32 {
    let idx = handle as usize;
    if handle < 0 || idx >= MAX_OPEN || s.open[idx].in_use == 0 {
        return E_INVAL;
    }
    let b = &s.bindings[s.open[idx].binding as usize];
    if b.in_use == 0 {
        return E_NOENT; // deleted behind the handle
    }
    const OUT: usize = 8 + 8 + 1 + 1;
    if arg.is_null() || arg_len < OUT {
        return E_INVAL;
    }
    let out = core::slice::from_raw_parts_mut(arg, OUT);
    out[..8].copy_from_slice(&(b.target_len as u64).to_le_bytes());
    out[8..16].copy_from_slice(&0u64.to_le_bytes()); // no clock in the fixture
    out[16] = b.kind;
    out[17] = 0; // no etag
    OUT as i32
}

/// LIST — the `namespace::LIST` request; the page is written by
/// `namespace::list::PageWriter`. Entries are in ascending path order and the
/// cursor is the last path a page returned, so the table's slot order and any
/// write between pages are invisible to the listing.
unsafe fn ns_list(s: &MemNsState, a: &[u8]) -> i32 {
    let Some(req) = abi::contracts::storage::namespace::list::parse_request(a) else {
        return E_INVAL;
    };
    // Key-shaped: the cursor is the last path a page returned, so one that is
    // not UTF-8 or not under the prefix was not issued here.
    let mut after: Option<&[u8]> = if req.cursor.is_empty() {
        None
    } else if req.cursor.starts_with(req.prefix) && utf8_valid(req.cursor) {
        Some(req.cursor)
    } else {
        return E_INVAL;
    };
    let out = core::slice::from_raw_parts_mut(req.out_ptr as *mut u8, req.out_cap as usize);
    let mut page = abi::contracts::storage::namespace::list::PageWriter::new(out);
    let mut more = false;
    let mut last_binding = MAX_BINDINGS;
    loop {
        // The smallest path under the prefix that sorts after `after`.
        let mut pick = MAX_BINDINGS;
        let mut i = 0;
        while i < MAX_BINDINGS {
            let b = &s.bindings[i];
            let path = &b.path[..b.path_len as usize];
            if b.in_use != 0
                && path.starts_with(req.prefix)
                && after.is_none_or(|c| path > c)
                && (pick == MAX_BINDINGS
                    || path < &s.bindings[pick].path[..s.bindings[pick].path_len as usize])
            {
                pick = i;
            }
            i += 1;
        }
        if pick == MAX_BINDINGS {
            break;
        }
        let b = &s.bindings[pick];
        let path = &b.path[..b.path_len as usize];
        if !page.push(path, b.kind) {
            more = true;
            break;
        }
        after = Some(path);
        last_binding = pick;
    }
    let cursor: &[u8] = if !more {
        &[]
    } else if last_binding == MAX_BINDINGS {
        // A page that cannot hold the next entry made no progress.
        return E_NOMEM;
    } else {
        let b = &s.bindings[last_binding];
        &b.path[..b.path_len as usize]
    };
    let Some(n) = page.finish(cursor) else {
        return E_NOMEM;
    };
    let frc = write_volatile_fence_at(req.fence_out_ptr, req.fence_out_cap);
    if frc != 0 {
        return frc;
    }
    n as i32
}

/// RENAME — `[src_len:u16][src][dst_len:u16][dst][flags:u8]
/// [fence_out_ptr:u64][fence_out_cap:u16]`.
unsafe fn ns_rename(s: &mut MemNsState, a: &[u8]) -> i32 {
    let Some(sl) = get_u16(a, 0).map(|v| v as usize) else {
        return E_INVAL;
    };
    if sl == 0 || a.len() < 2 + sl + 2 {
        return E_INVAL;
    }
    let Some(dl) = get_u16(a, 2 + sl).map(|v| v as usize) else {
        return E_INVAL;
    };
    if dl == 0 || dl > MAX_PATH || a.len() < 2 + sl + 2 + dl + 1 + 10 {
        return E_INVAL;
    }
    if !utf8_valid(&a[2 + sl + 2..2 + sl + 2 + dl]) {
        return E_INVAL;
    }
    let flags_off = 2 + sl + 2 + dl;
    let flags = a[flags_off];
    let frc = write_volatile_fence(a, flags_off + 1);
    if frc != 0 {
        return frc;
    }
    // Borrow-split: locate indices first, then mutate.
    let src_idx = {
        let src = &a[2..2 + sl];
        match find_binding(s, src) {
            Some(i) => i,
            None => return E_NOENT,
        }
    };
    let dst = &a[2 + sl + 2..2 + sl + 2 + dl];
    let mut dst_hint = HINT_CREATED;
    if let Some(d) = find_binding(s, dst) {
        if flags & 0x01 == 0 {
            return E_EXIST;
        }
        if d != src_idx {
            s.bindings[d] = BINDING_EMPTY;
        }
        dst_hint = HINT_MODIFIED;
    }
    let mut src = [0u8; MAX_PATH];
    let src_len = s.bindings[src_idx].path_len as usize;
    src[..src_len].copy_from_slice(&s.bindings[src_idx].path[..src_len]);
    s.revision += 1;
    let b = &mut s.bindings[src_idx];
    b.mod_rev = s.revision;
    b.path_len = dl as u8;
    b.path[..dl].copy_from_slice(dst);
    // Two keys under one revision: the source goes, the destination
    // comes (a rename onto itself is one key, modified).
    if &src[..src_len] != dst {
        changed(s, &src[..src_len], HINT_DELETED);
    }
    changed(s, dst, dst_hint);
    0
}

/// DELETE — `[path_len:u16][path][flags:u8][fence_out_ptr:u64]
/// [fence_out_cap:u16]`. Flat table: nothing nests, so the recursive
/// flag is accepted and means nothing extra.
unsafe fn ns_delete(s: &mut MemNsState, a: &[u8]) -> i32 {
    let Some(pl) = get_u16(a, 0).map(|v| v as usize) else {
        return E_INVAL;
    };
    if pl == 0 || a.len() < 2 + pl + 1 + 10 {
        return E_INVAL;
    }
    let frc = write_volatile_fence(a, 2 + pl + 1);
    if frc != 0 {
        return frc;
    }
    let path = &a[2..2 + pl];
    let Some(idx) = find_binding(s, path) else {
        return E_NOENT;
    };
    s.bindings[idx] = BINDING_EMPTY;
    s.revision += 1;
    changed(s, path, HINT_DELETED);
    0
}

unsafe fn ns_close(s: &mut MemNsState, handle: i32) -> i32 {
    if handle >= 0 && fd::slot_of(handle) & SUB_BAND != 0 {
        return sub_close(s, fd::slot_of(handle));
    }
    let idx = handle as usize;
    if handle < 0 || idx >= MAX_OPEN || s.open[idx].in_use == 0 {
        return E_INVAL;
    }
    s.open[idx] = OpenSlot {
        in_use: 0,
        binding: 0,
    };
    0
}

// ── subscriptions ──────────────────────────────────────────────────

/// An 8-byte record from a `handle = -1`-style query (`CALLER_OWNER`,
/// `CALLER_MODULE`) or `EVENT_OWNER` on `handle`, or the errno.
unsafe fn query_record(sys: &SyscallTable, handle: i32, key: u32) -> Result<[u8; 8], i32> {
    let mut r = [0u8; 8];
    let rc = (sys.provider_query)(handle, key, r.as_mut_ptr(), r.len());
    match rc {
        8 => Ok(r),
        rc if rc < 0 => Err(rc),
        _ => Err(E_INVAL),
    }
}

/// Whether `sub` may still be signalled: its module occupancy stands and
/// still owns its event. Checked before every signal, so an occupancy that
/// ended, or an event slot another module now holds, never wakes anybody.
unsafe fn sub_alive(sys: &SyscallTable, sub: &Sub) -> bool {
    let mut occ = sub.occ;
    let live = (sys.provider_query)(-1, query_key::MODULE_LIVE, occ.as_mut_ptr(), occ.len());
    live == 1 && query_record(sys, sub.event, query_key::EVENT_OWNER) == Ok(sub.occ)
}

/// Ring subscription `i`: set its bit and signal its event when the bit
/// was clear. A subscription that may no longer be signalled, or whose
/// event the kernel no longer holds, is dropped instead.
unsafe fn ring(s: &mut MemNsState, i: usize) {
    if s.subs[i].in_use == 0 || s.subs[i].rung != 0 {
        return;
    }
    let sys = &*s.syscalls;
    if !sub_alive(sys, &s.subs[i]) {
        s.subs[i] = SUB_EMPTY;
        return;
    }
    s.subs[i].rung = 1;
    let rc = (sys.provider_call)(s.subs[i].event, kevent::SIGNAL, core::ptr::null_mut(), 0);
    if rc == E_INVAL {
        s.subs[i] = SUB_EMPTY;
    }
}

/// Append one key a write touched to the change log, then ring every
/// subscription whose prefix covers it. The oldest entry makes room, and
/// its revision can no longer be read from.
unsafe fn changed(s: &mut MemNsState, path: &[u8], hint: u8) {
    if s.log_len as usize == LOG_CAP {
        let dropped = s.log[s.log_head as usize].rev;
        if dropped > s.lost_upto {
            s.lost_upto = dropped;
        }
        s.log_head = ((s.log_head as usize + 1) % LOG_CAP) as u16;
        s.log_len -= 1;
    }
    let at = (s.log_head as usize + s.log_len as usize) % LOG_CAP;
    let e = &mut s.log[at];
    e.rev = s.revision;
    e.hint = hint;
    e.path_len = path.len() as u8;
    e.path[..path.len()].copy_from_slice(path);
    s.log_len += 1;
    let mut i = 0;
    while i < MAX_SUBS {
        let sub = &s.subs[i];
        if sub.in_use != 0 && path.starts_with(&sub.prefix[..sub.prefix_len as usize]) {
            ring(s, i);
        }
        i += 1;
    }
}

fn sub_handle(i: usize) -> i32 {
    fd::tag_fd(fd::FD_TAG_STORAGE_NAMESPACE, SUB_BAND | i as i32)
}

/// SUBSCRIBE — `namespace::subscribe`.
unsafe fn ns_subscribe(s: &mut MemNsState, a: &[u8]) -> i32 {
    let Some(req) = subscribe::parse(a) else {
        return E_INVAL;
    };
    if req.prefix.len() > MAX_PATH {
        return E_INVAL;
    }
    let sys = &*s.syscalls;
    // A call from outside any module has no occupancy to stamp.
    let (Ok(occ), Ok(owner)) = (
        query_record(sys, -1, query_key::CALLER_MODULE),
        query_record(sys, -1, query_key::CALLER_OWNER),
    ) else {
        return E_INVAL;
    };
    // The event must be the caller's own: a subscription never wakes a
    // module that did not ask for it.
    if query_record(sys, req.event, query_key::EVENT_OWNER) != Ok(occ) {
        return E_INVAL;
    }
    let ring_now = req.flags & subscribe::FLAG_RING_NOW != 0;
    // Idempotent: a module re-running its subscribe path gets the same
    // handle back.
    let mut i = 0;
    while i < MAX_SUBS {
        let sub = &s.subs[i];
        if sub.in_use != 0
            && sub.owner == owner
            && sub.occ == occ
            && sub.event == req.event
            && &sub.prefix[..sub.prefix_len as usize] == req.prefix
        {
            if ring_now {
                ring(s, i);
            }
            return sub_handle(i);
        }
        i += 1;
    }
    let mut slot = admit(s, &owner);
    if slot.is_none() {
        // Dead subscriptions are swept before a refusal.
        let mut j = 0;
        while j < MAX_SUBS {
            if s.subs[j].in_use != 0 && !sub_alive(sys, &s.subs[j]) {
                s.subs[j] = SUB_EMPTY;
            }
            j += 1;
        }
        slot = admit(s, &owner);
    }
    let Some(i) = slot else {
        return E_NOMEM;
    };
    let sub = &mut s.subs[i];
    *sub = SUB_EMPTY;
    sub.in_use = 1;
    sub.event = req.event;
    sub.owner = owner;
    sub.occ = occ;
    sub.prefix_len = req.prefix.len() as u8;
    sub.prefix[..req.prefix.len()].copy_from_slice(req.prefix);
    if ring_now {
        ring(s, i);
    }
    sub_handle(i)
}

/// A free subscription slot, unless the pool or `owner`'s quota is spent.
fn admit(s: &MemNsState, owner: &[u8; 8]) -> Option<usize> {
    let mut held = 0;
    let mut free = None;
    let mut i = 0;
    while i < MAX_SUBS {
        if s.subs[i].in_use == 0 {
            free = free.or(Some(i));
        } else if &s.subs[i].owner == owner {
            held += 1;
        }
        i += 1;
    }
    if held >= SUB_QUOTA {
        return None;
    }
    free
}

/// TAKE_RUNG — `namespace::take`. Names and clears the rung bits of the
/// caller's subscriptions on the event, and signals the event again when
/// they did not all fit.
unsafe fn ns_take_rung(s: &mut MemNsState, a: &[u8]) -> i32 {
    let Some(req) = take::parse(a) else {
        return E_INVAL;
    };
    let out = core::slice::from_raw_parts_mut(req.out_ptr as *mut u8, req.out_cap as usize);
    let sys = &*s.syscalls;
    let Ok(occ) = query_record(sys, -1, query_key::CALLER_MODULE) else {
        return E_INVAL;
    };
    let Some(mut w) = take::Writer::new(out) else {
        return E_NOMEM;
    };
    let mut more = false;
    let mut i = 0;
    while i < MAX_SUBS {
        let sub = &mut s.subs[i];
        if sub.in_use != 0 && sub.rung != 0 && sub.occ == occ && sub.event == req.event {
            if !w.push(sub_handle(i)) {
                more = true;
                break;
            }
            sub.rung = 0;
        }
        i += 1;
    }
    let n = w.finish(more);
    if more {
        (sys.provider_call)(req.event, kevent::SIGNAL, core::ptr::null_mut(), 0);
    }
    n as i32
}

/// CLOSE of a subscription. One the caller did not open is as if not open:
/// a no-op.
unsafe fn sub_close(s: &mut MemNsState, raw: i32) -> i32 {
    let i = (raw & !SUB_BAND) as usize;
    if i >= MAX_SUBS || s.subs[i].in_use == 0 {
        return 0;
    }
    let sys = &*s.syscalls;
    if query_record(sys, -1, query_key::CALLER_OWNER) == Ok(s.subs[i].owner)
        && query_record(sys, -1, query_key::CALLER_MODULE) == Ok(s.subs[i].occ)
    {
        s.subs[i] = SUB_EMPTY;
    }
    0
}

// ── CHANGES ────────────────────────────────────────────────────────

fn log_at(s: &MemNsState, i: usize) -> &LogEntry {
    &s.log[(s.log_head as usize + i) % LOG_CAP]
}

fn entry_path(e: &LogEntry) -> &[u8] {
    &e.path[..e.path_len as usize]
}

/// The position of log entry `i` among the entries of its revision.
fn ordinal(s: &MemNsState, i: usize) -> u16 {
    let rev = log_at(s, i).rev;
    let mut n = 0u16;
    let mut j = i;
    while j > 0 && log_at(s, j - 1).rev == rev {
        n += 1;
        j -= 1;
    }
    n
}

/// Whether log entry `i` is the last one for its key: a key is reported
/// at its last entry only, so its record never carries a revision past
/// the cut of the page that reports it.
fn last_for_key(s: &MemNsState, i: usize) -> bool {
    let path = entry_path(log_at(s, i));
    let mut j = i + 1;
    while j < s.log_len as usize {
        if entry_path(log_at(s, j)) == path {
            return false;
        }
        j += 1;
    }
    true
}

/// CHANGES — `namespace::changes`. One page from the log (a bare revision
/// or an `L` continuation), or of a relist (the empty token or an `R`
/// continuation).
unsafe fn ns_changes(s: &MemNsState, a: &[u8]) -> i32 {
    let Some(req) = changes::parse_request(a) else {
        return E_INVAL;
    };
    let out = core::slice::from_raw_parts_mut(req.out_ptr as *mut u8, req.out_cap as usize);
    let tok = req.token;
    let n = if tok.is_empty() || tok[0] == TOKEN_RELIST && tok.len() > 9 {
        changes_relist(s, req.prefix, tok, out)
    } else {
        changes_log(s, req.prefix, tok, out)
    };
    if n < 0 {
        return n;
    }
    let frc = write_volatile_fence_at(req.fence_out_ptr, req.fence_out_cap);
    if frc != 0 {
        return frc;
    }
    n
}

/// A page of the log from a bare revision or an `L` continuation.
fn changes_log(s: &MemNsState, prefix: &[u8], tok: &[u8], out: &mut [u8]) -> i32 {
    let len = s.log_len as usize;
    let start = if let Some(since) = changes::token_revision(tok) {
        // Older than the log reaches, or a revision this store never
        // reached (it restarted): relist.
        if since < s.lost_upto || since > s.revision {
            return changes::write_lost(out).map_or(E_NOMEM, |n| n as i32);
        }
        let mut i = 0;
        while i < len && log_at(s, i).rev <= since {
            i += 1;
        }
        i
    } else if tok.len() == TOKEN_LOG_LEN && tok[0] == TOKEN_LOG {
        let mut r = [0u8; 8];
        r.copy_from_slice(&tok[1..9]);
        let rev = u64::from_le_bytes(r);
        let ord = u16::from_le_bytes([tok[9], tok[10]]) as usize;
        // Entries of that revision were overwritten: the ordinal no
        // longer names the same entry.
        if rev <= s.lost_upto {
            return changes::write_lost(out).map_or(E_NOMEM, |n| n as i32);
        }
        let mut i = 0;
        while i < len && log_at(s, i).rev < rev {
            i += 1;
        }
        if i + ord >= len || log_at(s, i + ord).rev != rev {
            return E_INVAL; // not a continuation issued here
        }
        i + ord
    } else {
        return E_INVAL;
    };
    let Some(mut page) = changes::PageWriter::new(out, TOKEN_LOG_LEN) else {
        return E_NOMEM;
    };
    let mut i = start;
    while i < len && i - start < SCAN_BUDGET {
        let e = log_at(s, i);
        let path = entry_path(e);
        if path.starts_with(prefix) && last_for_key(s, i) {
            let pushed = match find_binding(s, path) {
                Some(b) => {
                    let kind = if e.hint == HINT_CREATED {
                        changes::KIND_ADDED
                    } else {
                        changes::KIND_MODIFIED
                    };
                    let b = &s.bindings[b];
                    page.push(b.mod_rev, kind, path, &b.target[..b.target_len as usize])
                }
                // Absent now: its last entry is the delete, at that entry's
                // revision.
                None => page.push(e.rev, changes::KIND_DELETED, path, &[]),
            };
            if !pushed {
                if i == start {
                    return E_NOMEM; // not even one record fits
                }
                break;
            }
        }
        i += 1;
    }
    let n = if i >= len {
        page.finish(false, s.revision, &changes::revision_token(s.revision))
    } else {
        // Everything before the next entry's revision has been read.
        let next = log_at(s, i).rev;
        let mut t = [0u8; TOKEN_LOG_LEN];
        t[0] = TOKEN_LOG;
        t[1..9].copy_from_slice(&next.to_le_bytes());
        t[9..11].copy_from_slice(&ordinal(s, i).to_le_bytes());
        page.finish(true, next - 1, &t)
    };
    n.map_or(E_NOMEM, |n| n as i32)
}

/// A relist page: the bindings under the prefix in path order, with their
/// targets. The first page pins the current revision; a binding written
/// after it is left to the `CHANGES` that follows, from the pinned
/// revision the last page hands back.
fn changes_relist(s: &MemNsState, prefix: &[u8], tok: &[u8], out: &mut [u8]) -> i32 {
    let (pin, mut after) = if tok.is_empty() {
        (s.revision, None)
    } else {
        let mut r = [0u8; 8];
        r.copy_from_slice(&tok[1..9]);
        let cursor = &tok[9..];
        if !cursor.starts_with(prefix) || cursor.len() > MAX_PATH {
            return E_INVAL;
        }
        (u64::from_le_bytes(r), Some(cursor))
    };
    let Some(mut page) = changes::PageWriter::new(out, TOKEN_RELIST_MAX) else {
        return E_NOMEM;
    };
    let mut more = false;
    let mut walked = 0;
    let mut progressed = false;
    loop {
        // The smallest path under the prefix that sorts after `after`.
        let mut pick = MAX_BINDINGS;
        let mut i = 0;
        while i < MAX_BINDINGS {
            let b = &s.bindings[i];
            let path = &b.path[..b.path_len as usize];
            if b.in_use != 0
                && path.starts_with(prefix)
                && after.is_none_or(|c| path > c)
                && (pick == MAX_BINDINGS
                    || path < &s.bindings[pick].path[..s.bindings[pick].path_len as usize])
            {
                pick = i;
            }
            i += 1;
        }
        if pick == MAX_BINDINGS {
            break;
        }
        if walked == SCAN_BUDGET {
            more = true;
            break;
        }
        let b = &s.bindings[pick];
        let path = &b.path[..b.path_len as usize];
        if b.mod_rev <= pin
            && !page.push(
                b.mod_rev,
                changes::KIND_ADDED,
                path,
                &b.target[..b.target_len as usize],
            )
        {
            if !progressed {
                return E_NOMEM;
            }
            more = true;
            break;
        }
        progressed = true;
        walked += 1;
        after = Some(path);
    }
    let n = if more {
        let cursor = after.unwrap_or(&[]);
        let mut t = [0u8; TOKEN_RELIST_MAX];
        t[0] = TOKEN_RELIST;
        t[1..9].copy_from_slice(&pin.to_le_bytes());
        t[9..9 + cursor.len()].copy_from_slice(cursor);
        // Nothing is delivered whole until the walk ends.
        page.finish(true, 0, &t[..9 + cursor.len()])
    } else {
        page.finish(false, pin, &changes::revision_token(pin))
    };
    n.map_or(E_NOMEM, |n| n as i32)
}

// ── provider exports ───────────────────────────────────────────────

#[cfg_attr(
    not(feature = "host-test"),
    link_section = ".text.module_provides_contract"
)]
#[cfg_attr(not(feature = "host-test"), no_mangle)]
pub extern "C" fn module_provides_contract() -> u32 {
    0x0013 // STORAGE_NAMESPACE
}

/// # Safety
/// Kernel provider-dispatch entry point: `state` is the instance block this
/// module's `module_new` initialised, and `arg` points to `arg_len` bytes
/// (may be null when `arg_len` is 0) valid for the call.
#[cfg_attr(
    not(feature = "host-test"),
    link_section = ".text.module_provider_dispatch"
)]
#[cfg_attr(not(feature = "host-test"), export_name = "module_provider_dispatch")]
pub unsafe extern "C" fn mem_ns_dispatch(
    state: *mut u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    if state.is_null() {
        return E_INVAL;
    }
    let s = &mut *(state as *mut MemNsState);

    // Per-handle fence introspection: everything here is RAM.
    if opcode == abi::fence::QUERY_OP {
        if arg.is_null() || arg_len < abi::fence::WIRE_MAX_LEN {
            return E_INVAL;
        }
        let idx = handle as usize;
        if handle < 0 || idx >= MAX_OPEN || s.open[idx].in_use == 0 {
            return E_NOSYS;
        }
        let buf = core::slice::from_raw_parts_mut(arg, arg_len);
        return match abi::fence::Fence::Volatile.encode(buf) {
            Some(n) => n as i32,
            None => E_INVAL,
        };
    }

    let a = if arg.is_null() {
        &[][..]
    } else {
        core::slice::from_raw_parts(arg as *const u8, arg_len)
    };

    match opcode {
        NS_CAPS => {
            (NS_CAP_BIND | NS_CAP_RENAME | NS_CAP_DELETE | NS_CAP_SUBSCRIBE | NS_CAP_CHANGES) as i32
        }
        NS_BIND => ns_bind(s, a),
        NS_LOOKUP => ns_lookup(s, a),
        NS_STAT => ns_stat(s, handle, arg, arg_len),
        NS_LIST => ns_list(s, a),
        NS_RENAME => ns_rename(s, a),
        NS_DELETE => ns_delete(s, a),
        NS_CLOSE => ns_close(s, handle),
        NS_SUBSCRIBE => ns_subscribe(s, a),
        NS_TAKE_RUNG => ns_take_rung(s, a),
        NS_CHANGES => ns_changes(s, a),
        _ => E_NOSYS,
    }
}

include!("../../sdk/runtime/wasm_entry.rs");
