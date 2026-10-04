//! mem_ns — RAM-backed `storage.namespace` fixture provider.
//!
//! The contract-proving provider for the namespace surface
//! (`modules/sdk/contracts/storage/namespace.rs`), and the first
//! implementor of `BIND` (0x1308). Exists so the surface — and the
//! `mount` routing tier above it — is testable with **no on-disk
//! format in the loop** (a repo
//! that owns a contract holds an in-repo provider that proves it).
//!
//! Every binding lives in the module's state arena: a fixed table of
//! `path → {kind, target}` entries plus a LOOKUP handle table. All
//! fences are honestly `Volatile` — nothing here survives a power
//! cut, and a fixture that claimed otherwise would defeat the fence
//! axis it exists to exercise.
//!
//! Implements: BIND, LOOKUP, STAT, LIST, RENAME, DELETE, CLOSE, CAPS
//! (BIND|RENAME|DELETE). SUBSCRIBE/CHANGES return ENOSYS with their
//! cap bits clear — the canonical read-mostly-provider posture a
//! consumer must handle anyway.
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
const NS_CAPS: u32 = 0x13FF;

// namespace.rs::caps bits.
const NS_CAP_BIND: u32 = 1 << 0;
const NS_CAP_RENAME: u32 = 1 << 1;
const NS_CAP_DELETE: u32 = 1 << 2;

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

#[repr(C)]
#[derive(Clone, Copy)]
struct Binding {
    in_use: u8,
    kind: u8,
    path_len: u8,
    target_len: u8,
    path: [u8; MAX_PATH],
    target: [u8; MAX_TARGET],
}

const BINDING_EMPTY: Binding = Binding {
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

#[repr(C)]
struct MemNsState {
    syscalls: *const SyscallTable,
    revision: u64,
    bindings: [Binding; MAX_BINDINGS],
    open: [OpenSlot; MAX_OPEN],
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

    let b = &mut s.bindings[slot];
    b.in_use = 1;
    b.kind = kind;
    b.path_len = pl as u8;
    b.path[..pl].copy_from_slice(path);
    b.target_len = tl as u8;
    b.target[..tl].copy_from_slice(&a[target_off..target_off + tl]);
    s.revision += 1;
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
    if let Some(d) = find_binding(s, dst) {
        if flags & 0x01 == 0 {
            return E_EXIST;
        }
        if d != src_idx {
            s.bindings[d] = BINDING_EMPTY;
        }
    }
    let b = &mut s.bindings[src_idx];
    b.path_len = dl as u8;
    b.path[..dl].copy_from_slice(dst);
    s.revision += 1;
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
    let idx = {
        let path = &a[2..2 + pl];
        match find_binding(s, path) {
            Some(i) => i,
            None => return E_NOENT,
        }
    };
    s.bindings[idx] = BINDING_EMPTY;
    s.revision += 1;
    0
}

fn ns_close(s: &mut MemNsState, handle: i32) -> i32 {
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

// ── provider exports ───────────────────────────────────────────────

#[cfg_attr(
    not(feature = "host-test"),
    link_section = ".text.module_provides_contract"
)]
#[cfg_attr(not(feature = "host-test"), no_mangle)]
pub extern "C" fn module_provides_contract() -> u32 {
    0x0013 // STORAGE_NAMESPACE
}

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
        NS_CAPS => (NS_CAP_BIND | NS_CAP_RENAME | NS_CAP_DELETE) as i32,
        NS_BIND => ns_bind(s, a),
        NS_LOOKUP => ns_lookup(s, a),
        NS_STAT => ns_stat(s, handle, arg, arg_len),
        NS_LIST => ns_list(s, a),
        NS_RENAME => ns_rename(s, a),
        NS_DELETE => ns_delete(s, a),
        NS_CLOSE => ns_close(s, handle),
        // SUBSCRIBE/CHANGES: cap bits clear, canonical read-mostly posture.
        NS_SUBSCRIBE | NS_CHANGES => E_NOSYS,
        _ => E_NOSYS,
    }
}

include!("../../sdk/runtime/wasm_entry.rs");
