//! WASM `storage.object` provider — browser `fetch()` with byte
//! ranges behind the STORAGE_OBJECT contract.
//!
//! This is the object-surface sibling of [`super::fs`]. Where the FS
//! provider fronts whole-file streaming `GET`s and intentionally has
//! no seek (`FS_SEEK` → `ENOSYS`), the object provider adds the
//! bounded-range reads the Playload RFC (§12.3) needs so a wasm host
//! can demand-page immutable assets instead of fetching whole files.
//!
//! It is backed by four host bindings, the browser shims named by the
//! RFC:
//!
//!   - `host_object_head`       — issue a `HEAD`, surface size + mtime
//!   - `host_object_range_open` — issue a ranged `GET`, return a stream
//!   - `host_object_recv`       — drain bytes / metadata from a stream
//!   - `host_object_close`      — cancel + release a stream handle
//!
//! All windowing math (clamping a request to the object tail, encoding
//! the `HEAD` record) lives in the host-neutral, unit-tested
//! `abi::contracts::storage::object::range` module; this file is the
//! thin async transport wrapper. `host_object_recv` uses the same
//! four-state return shape as `host_fetch_recv`:
//!
//!   shim n  > 0  → bytes delivered
//!   shim n == 0  → pending; retry (EAGAIN)
//!   shim n == -1 → stream complete (EOF)
//!   shim n  < -1 → error
//!
//! The `host_object_head` / `host_object_range_open` shims MUST be
//! idempotent per `(key)` / `(key, offset, length)` so a provider call
//! that returns `EAGAIN` and is retried re-finds the same in-flight
//! request rather than issuing a duplicate fetch.

use crate::abi::contracts::fence as dev_fence;
use crate::abi::contracts::storage::object as dev_obj;
use crate::kernel::errno;
use crate::kernel::fd::{slot_of, tag_fd, FD_TAG_STORAGE_OBJECT};

const MAX_OPEN_OBJECTS: usize = 16;
/// Bounded copy of the object key so a slot can re-issue a ranged GET
/// across `EAGAIN` retries without the caller's buffer staying live.
const MAX_KEY_LEN: usize = 256;

struct ObjectSlot {
    in_use: bool,
    /// Object key (URL/path) this handle was opened against.
    key: [u8; MAX_KEY_LEN],
    key_len: usize,
    /// In-flight host stream handle for the current range window, or
    /// -1 when no range is open.
    host_handle: i32,
    /// Byte offset the open stream has delivered up to — the next
    /// sequential `RANGE_GET` offset that may reuse it.
    open_offset: u64,
    /// Exclusive end of the currently-open window (`open start + length`
    /// at the time the range was issued). `host_object_range_open`
    /// produces a *bounded* stream of exactly `length` bytes, so once
    /// `open_offset` reaches `open_end` the handle is exhausted and a
    /// sequential continuation must open a fresh range rather than reuse
    /// it — otherwise the next read sees a spurious EOF.
    open_end: u64,
}

const EMPTY_SLOT: ObjectSlot = ObjectSlot {
    in_use: false,
    key: [0u8; MAX_KEY_LEN],
    key_len: 0,
    host_handle: -1,
    open_offset: 0,
    open_end: 0,
};

static mut OBJECTS: [ObjectSlot; MAX_OPEN_OBJECTS] = [EMPTY_SLOT; MAX_OPEN_OBJECTS];

extern "C" {
    /// Issue an HTTP `HEAD` for `key_ptr[..key_len]`. Returns a
    /// non-negative handle whose first `host_object_recv` yields the
    /// 16-byte `[size:u64 LE][mtime:u64 LE]` metadata record, or a
    /// negative errno. Idempotent per key.
    fn host_object_head(key_ptr: *const u8, key_len: usize) -> i32;

    /// Issue a ranged `GET` (`Range: bytes=offset-…`) for
    /// `key_ptr[..key_len]`. Returns a non-negative stream handle for
    /// `host_object_recv`, or a negative errno. Idempotent per
    /// `(key, offset, length)`.
    fn host_object_range_open(key_ptr: *const u8, key_len: usize, offset: u64, length: u64) -> i32;

    /// Drain up to `len` bytes from a head/range stream into `buf`.
    /// Four-state return (see module docs).
    fn host_object_recv(handle: i32, buf: *mut u8, len: usize) -> i32;

    /// Cancel any in-flight reader and release the handle. Idempotent.
    fn host_object_close(handle: i32) -> i32;
}

/// Register the provider with the kernel so any module declaring
/// `requires_contract = "storage.object"` dispatches HEAD / GET /
/// RANGE_GET / CLOSE here. Called from `wasm_init_providers`.
pub fn register() {
    use crate::kernel::provider;
    use crate::kernel::provider::contract as dev_class;
    provider::register(dev_class::STORAGE_OBJECT, wasm_object_dispatch);
}

unsafe fn wasm_object_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    // `provider_call` passes tagged handles through `dispatch` unchanged
    // (see `kernel/provider.rs` + the `fs.rs` sibling): `alloc_slot`
    // returns `tag_fd(FD_TAG_STORAGE_OBJECT, slot)`, so every per-handle
    // op (QUERY/RANGE_GET/CLOSE) arrives tagged. Strip the tag here to
    // recover the raw OBJECTS slot — without it the tag bits push every
    // index past `MAX_OPEN_OBJECTS` and RANGE_GET/CLOSE after a GET fail
    // with EINVAL. GET/HEAD ignore `handle`; stripping a -1 is harmless.
    let handle = slot_of(handle);
    // Per-handle fence: the browser fetch model is volatile (no
    // durability tier), so every open handle advertises Volatile.
    if opcode == dev_fence::QUERY_OP {
        if arg.is_null() || arg_len < dev_fence::WIRE_MAX_LEN {
            return errno::EINVAL;
        }
        let slot_idx = handle as usize;
        let objs = &*core::ptr::addr_of!(OBJECTS);
        if slot_idx >= MAX_OPEN_OBJECTS || !objs[slot_idx].in_use {
            return errno::ENOSYS;
        }
        let buf = core::slice::from_raw_parts_mut(arg, arg_len);
        return match dev_fence::Fence::Volatile.encode(buf) {
            Some(n) => n as i32,
            None => errno::EINVAL,
        };
    }
    match opcode {
        dev_obj::GET => obj_get(arg, arg_len),
        dev_obj::HEAD => obj_head(arg, arg_len),
        dev_obj::RANGE_GET => obj_range_get(handle, arg, arg_len),
        dev_obj::CLOSE => obj_close(handle),
        _ => errno::ENOSYS,
    }
}

/// Read a little-endian `u64` from `ptr[off..off+8]`.
unsafe fn read_u64(ptr: *const u8, off: usize) -> u64 {
    let mut b = [0u8; 8];
    core::ptr::copy_nonoverlapping(ptr.add(off), b.as_mut_ptr(), 8);
    u64::from_le_bytes(b)
}

/// Allocate a slot bound to `key`, returning a tagged FD or errno.
unsafe fn alloc_slot(key: &[u8]) -> i32 {
    if key.is_empty() || key.len() > MAX_KEY_LEN {
        return errno::EINVAL;
    }
    let objs = &mut *core::ptr::addr_of_mut!(OBJECTS);
    let slot_idx = match objs.iter().position(|s| !s.in_use) {
        Some(i) => i,
        None => return errno::ENOMEM,
    };
    let slot = &mut objs[slot_idx];
    slot.key[..key.len()].copy_from_slice(key);
    slot.key_len = key.len();
    slot.host_handle = -1;
    slot.open_offset = 0;
    slot.open_end = 0;
    slot.in_use = true;
    tag_fd(FD_TAG_STORAGE_OBJECT, slot_idx as i32)
}

/// `GET` — `arg` is the UTF-8 key; reserve a handle bound to it. The
/// first `RANGE_GET` issues the actual ranged fetch.
unsafe fn obj_get(key_ptr: *mut u8, key_len: usize) -> i32 {
    if key_ptr.is_null() || key_len == 0 {
        return errno::EINVAL;
    }
    let key = core::slice::from_raw_parts(key_ptr, key_len);
    alloc_slot(key)
}

/// `RANGE_GET` — `arg` is `[offset:u64 LE][length:u32 LE][out_ptr:u64 LE]`.
/// Reads up to `length` bytes from `offset` into `out_ptr`, returning
/// the byte count (possibly less near the tail), `EAGAIN` while the
/// fetch is pending, or negative errno.
unsafe fn obj_range_get(handle: i32, arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 8 + 4 + 8 {
        return errno::EINVAL;
    }
    let slot_idx = handle as usize;
    let objs = &mut *core::ptr::addr_of_mut!(OBJECTS);
    if slot_idx >= MAX_OPEN_OBJECTS || !objs[slot_idx].in_use {
        return errno::EINVAL;
    }
    let offset = read_u64(arg, 0);
    let length = {
        let mut b = [0u8; 4];
        core::ptr::copy_nonoverlapping(arg.add(8), b.as_mut_ptr(), 4);
        u32::from_le_bytes(b) as u64
    };
    let out_ptr = read_u64(arg, 12) as usize as *mut u8;
    if length == 0 {
        return errno::OK; // empty window — nothing to read.
    }

    let slot = &mut objs[slot_idx];
    // Reuse the open stream only when this call continues sequentially
    // *within the same bounded window* — i.e. the next byte is exactly
    // where the last read left off AND that byte is still inside the
    // window the stream was opened for. Once `open_offset` reaches
    // `open_end` the host stream is exhausted (it yields only its
    // requested `length` bytes), so a continuation past the window must
    // open a fresh range; otherwise we'd drain a spent handle and report
    // a false EOF. Any other (offset, length) (re)opens at `offset`.
    let reusable = slot.host_handle >= 0 && slot.open_offset == offset && offset < slot.open_end;
    if !reusable {
        if slot.host_handle >= 0 {
            host_object_close(slot.host_handle);
            slot.host_handle = -1;
        }
        let key_ptr = slot.key.as_ptr();
        let h = host_object_range_open(key_ptr, slot.key_len, offset, length);
        if h < 0 {
            return errno::ENODEV;
        }
        slot.host_handle = h;
        slot.open_offset = offset;
        slot.open_end = offset + length;
    }

    let n = host_object_recv(slot.host_handle, out_ptr, length as usize);
    if n > 0 {
        // Advance the cursor so the next sequential call reuses the
        // stream. `range::Cursor` mirrors this accounting in tests.
        slot.open_offset = offset + n as u64;
        n
    } else if n == 0 {
        errno::EAGAIN
    } else if n == -1 {
        // Window exhausted at the object tail.
        host_object_close(slot.host_handle);
        slot.host_handle = -1;
        errno::OK
    } else {
        host_object_close(slot.host_handle);
        slot.host_handle = -1;
        errno::ERROR
    }
}

/// `HEAD` — read size + mtime without opening a stream. `arg` is the
/// `object::HEAD` layout; we fill the caller's out buffer with a
/// `range::encode_head` record and write a Volatile fence.
unsafe fn obj_head(arg: *mut u8, arg_len: usize) -> i32 {
    // [key_len:u16][key][out_ptr:u64][out_cap:u32][fence_out_ptr:u64][fence_out_cap:u16]
    if arg.is_null() || arg_len < 2 {
        return errno::EINVAL;
    }
    let key_len = {
        let mut b = [0u8; 2];
        core::ptr::copy_nonoverlapping(arg, b.as_mut_ptr(), 2);
        u16::from_le_bytes(b) as usize
    };
    let fixed = 2 + key_len + 8 + 4 + 8 + 2;
    if arg_len < fixed || key_len == 0 || key_len > MAX_KEY_LEN {
        return errno::EINVAL;
    }
    let key_ptr = arg.add(2);
    let mut p = 2 + key_len;
    let out_ptr = read_u64(arg, p) as usize as *mut u8;
    p += 8;
    let out_cap = {
        let mut b = [0u8; 4];
        core::ptr::copy_nonoverlapping(arg.add(p), b.as_mut_ptr(), 4);
        u32::from_le_bytes(b) as usize
    };
    p += 4;
    let fence_out_ptr = read_u64(arg, p) as usize as *mut u8;
    p += 8;
    let fence_out_cap = {
        let mut b = [0u8; 2];
        core::ptr::copy_nonoverlapping(arg.add(p), b.as_mut_ptr(), 2);
        u16::from_le_bytes(b) as usize
    };

    // Idempotent per key: a retry after EAGAIN re-finds the same
    // in-flight HEAD on the host side.
    let h = host_object_head(key_ptr, key_len);
    if h < 0 {
        return errno::ENODEV;
    }
    let mut meta = [0u8; 16];
    let got = host_object_recv(h, meta.as_mut_ptr(), meta.len());
    if got == 0 {
        return errno::EAGAIN; // metadata not ready — keep host cache, retry.
    }
    if got < 0 || (got as usize) < 16 {
        host_object_close(h);
        return errno::ENODEV;
    }
    host_object_close(h);

    let size = u64::from_le_bytes(meta[0..8].try_into().unwrap());
    let mtime = u64::from_le_bytes(meta[8..16].try_into().unwrap());

    if out_ptr.is_null() {
        return errno::EINVAL;
    }
    let out = core::slice::from_raw_parts_mut(out_ptr, out_cap);
    let written = match dev_obj::range::encode_head(out, size, mtime, &[], &[]) {
        Some(n) => n,
        None => return errno::EINVAL,
    };

    if !fence_out_ptr.is_null() && fence_out_cap >= dev_fence::WIRE_MAX_LEN {
        let fbuf = core::slice::from_raw_parts_mut(fence_out_ptr, fence_out_cap);
        let _ = dev_fence::Fence::Volatile.encode(fbuf);
    }
    written as i32
}

/// `CLOSE` — release any open stream and free the slot.
unsafe fn obj_close(handle: i32) -> i32 {
    let slot_idx = handle as usize;
    let objs = &mut *core::ptr::addr_of_mut!(OBJECTS);
    if slot_idx >= MAX_OPEN_OBJECTS || !objs[slot_idx].in_use {
        return errno::EINVAL;
    }
    let slot = &mut objs[slot_idx];
    if slot.host_handle >= 0 {
        host_object_close(slot.host_handle);
    }
    slot.host_handle = -1;
    slot.key_len = 0;
    slot.open_offset = 0;
    slot.open_end = 0;
    slot.in_use = false;
    errno::OK
}
