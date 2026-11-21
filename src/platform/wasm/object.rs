//! WASM `storage.object` provider — browser `fetch()` with byte
//! ranges behind the STORAGE_OBJECT contract.
//!
//! This is the object-surface sibling of [`super::fs`]. Where the FS
//! provider fronts whole-file streaming `GET`s and intentionally has
//! no seek (`FS_SEEK` → `ENOSYS`), the object provider adds the
//! bounded-range reads a wasm host needs to demand-page immutable
//! assets instead of fetching whole files.
//!
//! It is backed by these host bindings, the browser shims:
//!
//!   - `host_object_head`       — issue a `HEAD`, surface size + mtime
//!   - `host_object_range_open` — issue a ranged `GET`, return a stream
//!   - `host_object_recv`       — drain bytes / metadata from a stream
//!   - `host_object_close`      — cancel + release a stream handle
//!   - `host_object_put`        — write a blob to the persistent layer
//!   - `host_object_delete`     — remove a blob from the persistent layer
//!
//! ## Read layer vs. write layer (OPFS)
//!
//! The four read bindings front a *read-only* layer: `fetch()` over the
//! page origin (and the in-bundle `asset://` map), which serves shipped,
//! immutable content. There is no way to `PUT` to an HTTP origin from the
//! browser, so on its own this layer cannot persist user-generated data
//! (save-state derivatives, imported ROMs, caches).
//!
//! `host_object_put` is the write layer, backed by **OPFS** (Origin
//! Private File System) on the host side — see
//! `docs/architecture/wasm_browser_host.md` §5. Writes are
//! synchronously *accepted* into an in-memory store (so an immediately
//! following `GET`/`HEAD`/`RANGE_GET` of the same key sees the bytes)
//! and persisted to OPFS in the background; the shim also hydrates that
//! store from OPFS at boot, so a key written in a prior session reads
//! back. Reads consult the written store before falling through to
//! `fetch()`, which is why GET/HEAD/RANGE_GET need no wasm-side change to
//! see PUT data. Durability is therefore *best-effort* — the per-handle
//! fence stays `Volatile`, matching the browser quota model (origin
//! storage may be evicted).
//!
//! `LIST` answers `ENOSYS`: reads fall through to `fetch()` against the
//! page origin, which cannot be enumerated, and a listing of the written
//! layer alone would omit objects `GET` serves.
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

use crate::abi::contracts::storage::handle as dev_obj_handle;
use crate::abi::contracts::storage::object as dev_obj;
use crate::abi::contracts::storage::object::precondition as obj_precondition;
use crate::abi::fence as dev_fence;
use crate::kernel::module::user_span::UserSpan;
use crate::kernel::sys::errno;

pub(super) const MAX_OPEN_OBJECTS: usize = 16;
/// Longest object key: the contract's one bound, so a key `PUT` writes is
/// one `storage.namespace` can list. A slot keeps a bounded copy of its key
/// to re-issue a ranged GET across `EAGAIN` retries without the caller's
/// buffer staying live.
const MAX_KEY_LEN: usize = dev_obj_handle::STORAGE_KEY_MAX;

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

    /// Write `body_ptr[..body_len]` to the persistent (OPFS) layer under
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

    /// Remove `key_ptr[..key_len]` from the persistent (OPFS/IDB) write
    /// layer. Returns `0` when the key is gone, `-2 ENOENT` when this
    /// layer never held it — a key served only by the read layer
    /// (shipped content behind `fetch`) is not this provider's to
    /// delete. Acceptance is synchronous; the backing removal is
    /// queued behind the same chain as `host_object_put`, so a delete
    /// cannot race a write of the same key.
    fn host_object_delete(key_ptr: *const u8, key_len: usize) -> i32;
}

/// Register the provider with the kernel so any module declaring
/// `requires_contract = "storage.object"` dispatches HEAD / GET /
/// RANGE_GET / CLOSE here. Called from `wasm_init_providers`.
pub fn register() {
    use crate::kernel::module::provider;
    use crate::kernel::module::provider::contract as dev_class;
    provider::register(dev_class::STORAGE_OBJECT, wasm_object_dispatch);
}

fn wasm_object_dispatch(handle: i32, opcode: u32, arg: &mut [u8], mut data: UserSpan<'_>) -> i32 {
    // Every per-handle op arrives with the OBJECTS slot's index
    // `alloc_slot` returned; ops that take `handle = -1` ignore it.
    // SAFETY: provider dispatch runs on the one wasm thread, which alone
    // touches the slot table; the host bindings take only slices of `arg`,
    // `data` and the slot table, each valid for the call.
    unsafe {
        // Per-handle fence: the browser fetch model is volatile (no
        // durability layer), so every open handle advertises Volatile.
        if opcode == dev_fence::QUERY_OP {
            let objs = &*core::ptr::addr_of!(OBJECTS);
            if !objs.get(handle as usize).is_some_and(|s| s.in_use) {
                return errno::ENOSYS;
            }
            return match dev_fence::Fence::Volatile.encode(arg) {
                Some(n) => n as i32,
                None => errno::EINVAL,
            };
        }
        match opcode {
            dev_obj::PUT => obj_put(arg, data.as_slice()),
            dev_obj::GET => obj_get(arg),
            dev_obj::HEAD => obj_head(arg),
            dev_obj::RANGE_GET => obj_range_get(handle, arg, data.as_mut()),
            dev_obj::DELETE => obj_delete(arg),
            dev_obj::CLOSE => obj_close(handle),
            // Unconditional writes to the persistent layer; no listing, no
            // condition, no kept field, no streamed put, no grants.
            dev_obj::CAPS => crate::abi::kernel_abi::caps_word::answer(arg, dev_obj::caps::WRITE),
            // See the module docs: the origin cannot be enumerated.
            dev_obj::LIST => errno::ENOSYS,
            _ => errno::ENOSYS,
        }
    }
}

/// Read a little-endian `u64` from `b[off..off+8]`; the caller has checked
/// the length.
fn read_u64(b: &[u8], off: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(v)
}

/// Allocate a slot bound to `key`, returning its index or errno.
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
    slot_idx as i32
}

/// `PUT` — single-shot write to the persistent (OPFS) layer: `arg` is the
/// `object::PUT` record and its fence trailer, `data` the body.
///
/// We forward `key` and `body` to `host_object_put` (which stages then
/// background-persists to OPFS) and write a `Volatile` fence into the
/// trailer on success. `content_type` is parsed for layout but not kept
/// (no etag store). A precondition other than `ANY`, or any field for the
/// store to keep, asks for a guarantee this layer cannot make, so it is
/// REFUSED with `ENOSYS` rather than silently downgraded — the contract
/// requires that, because downgrading a conditional write to an
/// unconditional one turns a refusal into a lost update, and a retained
/// write to a deletable one.
unsafe fn obj_put(arg: &mut [u8], body: &[u8]) -> i32 {
    let Some(req) = dev_obj::put::parse(arg) else {
        return errno::EINVAL;
    };
    if req.key.is_empty() || req.key.len() > MAX_KEY_LEN {
        return errno::EINVAL;
    }
    if req.precondition != obj_precondition::ANY || !req.kept.is_none() {
        return errno::ENOSYS;
    }
    // A key that is not UTF-8 is not one a listing can name.
    if core::str::from_utf8(req.key).is_err() {
        return errno::EINVAL;
    }
    let rc = host_object_put(req.key.as_ptr(), req.key.len(), body.as_ptr(), body.len());
    if rc < 0 {
        return errno::ENODEV;
    }
    // PUT acceptance carries the strongest fence the commit achieved;
    // the browser write layer is best-effort, so that is Volatile.
    let _ = dev_fence::trailer::put(arg, &dev_fence::Fence::Volatile);
    errno::OK
}

/// `GET` — `arg` is the `[key_len:u16][key]` record; reserve a handle bound
/// to the key. The first `RANGE_GET` issues the actual ranged fetch.
unsafe fn obj_get(arg: &[u8]) -> i32 {
    match dev_obj::key::parse(arg) {
        Some(key) => alloc_slot(key),
        None => errno::EINVAL,
    }
}

/// `RANGE_GET` — `arg` is `[offset:u64 LE]`, `out` the caller's `data`.
/// Reads up to `out.len()` bytes from `offset` into `out`, returning the
/// byte count (possibly less near the tail), `EAGAIN` while the fetch is
/// pending, or negative errno.
unsafe fn obj_range_get(handle: i32, arg: &[u8], out: &mut [u8]) -> i32 {
    let Some(offset) = dev_obj::range_get::parse(arg) else {
        return errno::EINVAL;
    };
    let slot_idx = handle as usize;
    let objs = &mut *core::ptr::addr_of_mut!(OBJECTS);
    if slot_idx >= MAX_OPEN_OBJECTS || !objs[slot_idx].in_use {
        return errno::EINVAL;
    }
    let length = out.len() as u64;
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
        let h = host_object_range_open(slot.key.as_ptr(), slot.key_len, offset, length);
        if h < 0 {
            return errno::ENODEV;
        }
        slot.host_handle = h;
        slot.open_offset = offset;
        slot.open_end = offset + length;
    }

    let n = host_object_recv(slot.host_handle, out.as_mut_ptr(), out.len());
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
/// `object::HEAD` request; the key is taken first, then the
/// `range::encode_head` record is written over `arg` and a Volatile fence
/// into its trailer.
unsafe fn obj_head(arg: &mut [u8]) -> i32 {
    let mut key = [0u8; MAX_KEY_LEN];
    let key_len = match dev_obj::head::parse_request(arg) {
        Some(k) if k.len() <= MAX_KEY_LEN => {
            key[..k.len()].copy_from_slice(k);
            k.len()
        }
        _ => return errno::EINVAL,
    };

    // Idempotent per key: a retry after EAGAIN re-finds the same
    // in-flight HEAD on the host side.
    let h = host_object_head(key.as_ptr(), key_len);
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

    let size = read_u64(&meta, 0);
    let mtime = read_u64(&meta, 8);

    let Some(out) = dev_obj::head::answer_area(arg) else {
        return errno::EINVAL;
    };
    let written =
        match dev_obj::range::encode_head(out, size, mtime, &[], &[], dev_obj::Kept::none()) {
            Some(n) => n,
            None => return errno::ENOMEM,
        };
    let _ = dev_fence::trailer::put(arg, &dev_fence::Fence::Volatile);
    written as i32
}

/// `DELETE` — remove a key from the write layer. `arg` is the
/// `object::DELETE` request and its fence trailer.
///
/// Preconditions are REFUSED rather than ignored. This layer keys bytes
/// and holds no etag to compare, and the contract is explicit that a
/// provider which cannot offer a condition must refuse it with `ENOSYS`
/// — silently downgrading a conditional delete to an unconditional one
/// turns a refusal into a lost update.
unsafe fn obj_delete(arg: &mut [u8]) -> i32 {
    let Some(req) = dev_obj::delete::parse_request(arg) else {
        return errno::EINVAL;
    };
    if req.key.is_empty() || req.key.len() > MAX_KEY_LEN {
        return errno::EINVAL;
    }
    if req.precondition != dev_obj::precondition::ANY {
        return errno::ENOSYS;
    }
    let rc = host_object_delete(req.key.as_ptr(), req.key.len());
    if rc < 0 {
        return rc;
    }
    // Volatile for the same reason PUT is: acceptance is synchronous and
    // the backing removal commits behind the call.
    let _ = dev_fence::trailer::put(arg, &dev_fence::Fence::Volatile);
    0
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
