//! WASM `storage.object` provider — browser `fetch()` with byte
//! ranges behind the STORAGE_OBJECT contract.
//!
//! This is the object-surface sibling of [`super::fs`]. Where the FS
//! provider fronts whole-file streaming `GET`s and intentionally has
//! no seek (`FS_SEEK` → `ENOSYS`), the object provider adds the
//! bounded-range reads the Playload RFC (§12.3) needs so a wasm host
//! can demand-page immutable assets instead of fetching whole files.
//!
//! It is backed by five host bindings, the browser shims named by the
//! RFC:
//!
//!   - `host_object_head`       — issue a `HEAD`, surface size + mtime
//!   - `host_object_range_open` — issue a ranged `GET`, return a stream
//!   - `host_object_recv`       — drain bytes / metadata from a stream
//!   - `host_object_close`      — cancel + release a stream handle
//!   - `host_object_put`        — write a blob to the persistent tier
//!
//! ## Read tier vs. write tier (OPFS)
//!
//! The four read bindings front a *read-only* tier: `fetch()` over the
//! page origin (and the in-bundle `asset://` map), which serves shipped,
//! immutable content. There is no way to `PUT` to an HTTP origin from the
//! browser, so on its own this tier cannot persist user-generated data
//! (RFC 0009 save-state derivatives, imported ROMs, caches).
//!
//! `host_object_put` adds the missing write tier, backed by **OPFS**
//! (Origin Private File System) on the host side — see
//! `docs/architecture/wasm_browser_host.md` §5.6. Writes are
//! synchronously *accepted* into an in-memory store (so an immediately
//! following `GET`/`HEAD`/`RANGE_GET` of the same key sees the bytes)
//! and persisted to OPFS in the background; the shim also hydrates that
//! store from OPFS at boot, so a key written in a prior session reads
//! back. Reads consult the written store before falling through to
//! `fetch()`, which is why GET/HEAD/RANGE_GET need no wasm-side change to
//! see PUT data. Durability is therefore *best-effort* — the per-handle
//! fence stays `Volatile`, matching the browser quota model (origin
//! storage may be evicted) per `endpoint_capability_surface.md` §4.
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

    /// Write `body_ptr[..body_len]` to the persistent (OPFS) tier under
    /// `key_ptr[..key_len]`. Returns `0` once the write is *accepted*
    /// (staged in the host's in-memory store and queued for OPFS
    /// persistence), or a negative errno. The acceptance is synchronous —
    /// a subsequent `host_object_head`/`host_object_range_open` for the
    /// same key reads the staged bytes immediately — but OPFS durability
    /// is best-effort (background commit), so the contract fence is
    /// `Volatile`, not `Durable`.
    fn host_object_put(
        key_ptr: *const u8,
        key_len: usize,
        body_ptr: *const u8,
        body_len: usize,
    ) -> i32;

    /// Range-fetch `url[..url_len]` (`Range: bytes=offset-…`) and decode
    /// the result to a `width`×`height` RGB565 buffer in the browser.
    /// Returns a non-negative job handle for `host_image_decode_recv` /
    /// `host_image_decode_close`, or a negative errno.
    fn host_image_decode_url(
        url_ptr: *const u8,
        url_len: usize,
        offset: u64,
        length: u64,
        width: u32,
        height: u32,
    ) -> i32;

    /// Drain the decoded RGB565 buffer. Returns bytes copied, `-1` while
    /// the decode is still pending, `-2` on error, `0` once drained.
    fn host_image_decode_recv(handle: i32, buf: *mut u8, len: usize) -> i32;

    /// Release a decode job. Idempotent.
    fn host_image_decode_close(handle: i32) -> i32;
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
        dev_obj::PUT => obj_put(arg, arg_len),
        dev_obj::GET => obj_get(arg, arg_len),
        dev_obj::HEAD => obj_head(arg, arg_len),
        dev_obj::RANGE_GET => obj_range_get(handle, arg, arg_len),
        dev_obj::CLOSE => obj_close(handle),
        dev_obj::IMG_DECODE => img_decode(arg, arg_len),
        dev_obj::IMG_RECV => img_recv(handle, arg, arg_len),
        dev_obj::IMG_CLOSE => img_close(handle),
        _ => errno::ENOSYS,
    }
}

/// `IMG_DECODE` — range-fetch + decode an embedded image to RGB565.
/// `arg` = `[offset:u64][length:u64][width:u16][height:u16][url…]`.
/// Returns a tagged handle (for `IMG_RECV` / `IMG_CLOSE`) or errno.
unsafe fn img_decode(arg: *mut u8, arg_len: usize) -> i32 {
    const HDR: usize = 8 + 8 + 2 + 2;
    if arg.is_null() || arg_len <= HDR {
        return errno::EINVAL;
    }
    let offset = read_u64(arg, 0);
    let length = read_u64(arg, 8);
    let mut wb = [0u8; 2];
    core::ptr::copy_nonoverlapping(arg.add(16), wb.as_mut_ptr(), 2);
    let width = u16::from_le_bytes(wb) as u32;
    let mut hb = [0u8; 2];
    core::ptr::copy_nonoverlapping(arg.add(18), hb.as_mut_ptr(), 2);
    let height = u16::from_le_bytes(hb) as u32;
    let url = core::slice::from_raw_parts(arg.add(HDR), arg_len - HDR);

    // Reuse the OBJECTS slot table for the handle mapping (url as key).
    let fd = alloc_slot(url);
    if fd < 0 {
        return fd;
    }
    let idx = slot_of(fd) as usize;
    let objs = &mut *core::ptr::addr_of_mut!(OBJECTS);
    let h = host_image_decode_url(url.as_ptr(), url.len(), offset, length, width, height);
    if h < 0 {
        objs[idx].in_use = false;
        return errno::ENODEV;
    }
    objs[idx].host_handle = h;
    fd
}

/// `IMG_RECV` — drain the decoded RGB565 into `arg[..arg_len]`. Returns
/// bytes copied, `EAGAIN` while decoding, `OK` (0) once drained, or errno.
unsafe fn img_recv(handle: i32, arg: *mut u8, arg_len: usize) -> i32 {
    let idx = handle as usize;
    let objs = &mut *core::ptr::addr_of_mut!(OBJECTS);
    if idx >= MAX_OPEN_OBJECTS || !objs[idx].in_use || arg.is_null() {
        return errno::EINVAL;
    }
    let h = objs[idx].host_handle;
    let n = host_image_decode_recv(h, arg, arg_len);
    if n > 0 {
        n
    } else if n == -1 {
        errno::EAGAIN // decode still pending
    } else if n == 0 {
        errno::OK // fully drained
    } else {
        errno::ERROR // decode failed
    }
}

/// `IMG_CLOSE` — release a decode handle.
unsafe fn img_close(handle: i32) -> i32 {
    let idx = handle as usize;
    let objs = &mut *core::ptr::addr_of_mut!(OBJECTS);
    if idx < MAX_OPEN_OBJECTS && objs[idx].in_use {
        if objs[idx].host_handle >= 0 {
            host_image_decode_close(objs[idx].host_handle);
        }
        objs[idx].in_use = false;
    }
    errno::OK
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

/// `PUT` — single-shot write to the persistent (OPFS) tier. `arg` is:
///
/// ```text
///   [key_len:u16 LE][key]
///   [content_type_len:u8][content_type]
///   [body_ptr:u64 LE][body_len:u64 LE]
///   [if_match_len:u8][if_match]
///   [fence_out_ptr:u64 LE][fence_out_cap:u16 LE]
/// ```
///
/// We forward `key` and `body` to `host_object_put` (which stages then
/// background-persists to OPFS) and write a `Volatile` fence into the
/// caller's fence buffer on success. `content_type` is parsed for layout
/// but not enforced (no etag store). A nonzero `if_match` requests a
/// conditional overwrite the wasm tier cannot honor yet, so it is
/// REJECTED with `ENOSYS` rather than silently performing an
/// unconditional PUT and reporting the guard as satisfied — matching the
/// linux provider, which also rejects conditional PUT until etag
/// enforcement lands.
unsafe fn obj_put(arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 2 {
        return errno::EINVAL;
    }
    let key_len = {
        let mut b = [0u8; 2];
        core::ptr::copy_nonoverlapping(arg, b.as_mut_ptr(), 2);
        u16::from_le_bytes(b) as usize
    };
    if key_len == 0 || key_len > MAX_KEY_LEN {
        return errno::EINVAL;
    }
    // Walk the variable-width prefix, bounds-checking each field before
    // advancing so a short/truncated arg can never read past the buffer.
    let mut p = 2 + key_len;
    if arg_len < p + 1 {
        return errno::EINVAL;
    }
    let ct_len = *arg.add(p) as usize;
    p += 1 + ct_len;
    if arg_len < p + 8 + 8 + 1 {
        return errno::EINVAL;
    }
    let body_ptr = read_u64(arg, p) as usize as *const u8;
    p += 8;
    let body_len = read_u64(arg, p) as usize;
    p += 8;
    let if_match_len = *arg.add(p) as usize;
    p += 1 + if_match_len;
    if arg_len < p + 8 + 2 {
        return errno::EINVAL;
    }
    // Conditional PUT (nonzero if_match) can't be enforced without an
    // etag store. Fail loudly rather than do an unconditional overwrite
    // and falsely report the precondition as met.
    if if_match_len != 0 {
        return errno::ENOSYS;
    }
    let fence_out_ptr = read_u64(arg, p) as usize as *mut u8;
    p += 8;
    let fence_out_cap = {
        let mut b = [0u8; 2];
        core::ptr::copy_nonoverlapping(arg.add(p), b.as_mut_ptr(), 2);
        u16::from_le_bytes(b) as usize
    };

    let key_ptr = arg.add(2);
    let rc = host_object_put(key_ptr, key_len, body_ptr, body_len);
    if rc < 0 {
        return errno::ENODEV;
    }

    // PUT acceptance carries the strongest fence the commit achieved;
    // the browser write tier is best-effort, so that is Volatile.
    if !fence_out_ptr.is_null() && fence_out_cap >= dev_fence::WIRE_MAX_LEN {
        let fbuf = core::slice::from_raw_parts_mut(fence_out_ptr, fence_out_cap);
        let _ = dev_fence::Fence::Volatile.encode(fbuf);
    }
    errno::OK
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
