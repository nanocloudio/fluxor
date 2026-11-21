//! WASM FS provider — browser `fetch()` behind FS_CONTRACT.
//!
//! The wasm-target equivalent of `fat32` over NVMe (bare metal) and
//! `linux_fs_dispatch` (Linux host). Any module that already speaks
//! the FS contract — `media_loader` opening ROM/snapshot, `foundation/http`
//! serving routes via HANDLER_FS_FILE — works on wasm without channel
//! plumbing for asset ingest, because the kernel routes
//! `provider_call(-1, FS_OPEN, …)` to the FS provider registered here.
//!
//! `host_fetch_open` returns a handle synchronously; the response
//! body streams in via `host_fetch_recv` over many calls. FS_OPEN
//! therefore returns a slot index immediately — the fetch is in
//! flight but no bytes are guaranteed yet. FS_READ translates the
//! shim's four-state return into FS-contract semantics:
//!
//!   shim n  > 0  → return n               (bytes delivered)
//!   shim n == 0  → return EAGAIN          (response pending; retry)
//!   shim n == -1 → return 0               (response complete; EOF)
//!   shim n  < -1 → return ERROR           (404, network error, …)
//!
//! The `arg` byte slice is forwarded to the host shim verbatim and
//! resolved as a URL relative to the page origin, so `/assets/foo.bin`
//! lands at `<origin>/assets/foo.bin`.
//!
//! FS_STAT looks up the response's `Content-Length` via
//! `host_fetch_size` and maps its four-state return:
//!
//!   shim size >= 0 → OK; write the 32-byte `fs::Stat` record with
//!                   `size` and every other field 0
//!   shim size == -1 → ENOSYS  (headers in, no Content-Length —
//!                    chunked / identity-of-unknown-length; consumer
//!                    can safely commit a streaming response)
//!   shim size == -2 → ENODEV  (hard fetch failure)
//!   shim size == -3 → EAGAIN  (headers not yet received; consumer
//!                    should keep polling before committing)
//!
//! mtime = 0 because `fetch()` doesn't reliably surface modification
//! time.
//!
//! FS_SEEK and FS_FSYNC return ENOSYS — the streaming fetch model has no
//! equivalent.
//!
//! FS_WRITE is served, and not by fetch: writes stage against the handle
//! and publish as one file at FS_CLOSE into the same persistent layer
//! `storage.object` uses (OPFS, or IndexedDB where OPFS is absent — it
//! needs a secure context). FS_OPEN consults that layer before reaching
//! for the network, so a path written here reads back as itself, this
//! session and the next. Until this existed the contract was half served
//! on this target: a graph could be granted `fs` and then not write
//! through it.
//!
//! FS_CLOSE calls `host_fetch_close`, cancelling any in-flight body
//! reader and dropping the host-side handle entry.

use crate::abi::contracts::storage::fs as dev_fs;
use crate::abi::fence as dev_fence;
use crate::kernel::sys::errno;

pub(super) const MAX_OPEN_FILES: usize = 16;

struct FetchSlot {
    /// Host fetch handle from `host_fetch_open`. -1 when the slot is free.
    host_handle: i32,
    in_use: bool,
}

static mut FETCH_FILES: [FetchSlot; MAX_OPEN_FILES] = [const {
    FetchSlot {
        host_handle: -1,
        in_use: false,
    }
}; MAX_OPEN_FILES];

extern "C" {
    /// Issue an HTTP GET to `url_ptr[..url_len]` (UTF-8 path or absolute
    /// URL, resolved against the page origin by the host shim). Returns
    /// a non-negative handle for `host_fetch_recv`, or negative errno.
    /// The shim opens the request asynchronously; recvs return 0 until
    /// the first chunk arrives.
    fn host_fetch_open(url_ptr: *const u8, url_len: usize) -> i32;

    /// Drain bytes from the response body into `buf`. Return shape:
    ///   `> 0`  bytes written
    ///   `= 0`  no chunk yet, more may come
    ///   `= -1` EOF (response complete)
    ///   `< -1` error
    fn host_fetch_recv(handle: i32, buf: *mut u8, len: usize) -> i32;

    /// Cancel any in-flight body reader and release the host-side
    /// handle. Idempotent — closing an already-closed or unknown
    /// handle returns 0. Returns negative errno only on a hard host
    /// failure (no expected callers act on the value).
    fn host_fetch_close(handle: i32) -> i32;

    /// Append `len` bytes at `buf` to the handle's staged content.
    /// Returns bytes taken, or a negative errno. The bytes are joined
    /// and published as one file when the handle is closed, so a reader
    /// never observes a partially-written file — and so a sequence of
    /// writes is one file rather than a race between them.
    fn host_fetch_write(handle: i32, buf: *const u8, len: usize) -> i32;

    /// Look up the response status / content length for a fetch
    /// handle. Four-state return — distinguishing "received but no
    /// length" from "headers haven't arrived yet" lets length-aware
    /// consumers wait for an outcome before committing a response:
    ///   `>= 0`  Content-Length received in bytes
    ///   `= -1`  headers received, no Content-Length (chunked,
    ///          identity-of-unknown-length); fetch is committed-OK
    ///   `= -2`  hard failure (rejected fetch, non-OK status, or
    ///          exception before body)
    ///   `= -3`  headers not yet received; outcome unknown
    /// Idempotent: reads cached state, does not drive the fetch.
    fn host_fetch_size(handle: i32) -> i32;
}

/// Register the FS provider with the kernel. Called from
/// `wasm_init_providers` (HAL bring-up) so that any module declaring
/// `requires_contract = "fs"` can dispatch FS_OPEN/READ/CLOSE through
/// `provider_call` without further wiring.
pub fn register() {
    use crate::kernel::module::provider;
    use crate::kernel::module::provider::contract as dev_class;
    provider::register(dev_class::FS, wasm_fs_dispatch);
}

fn wasm_fs_dispatch(
    handle: i32,
    opcode: u32,
    arg: &mut [u8],
    mut data: crate::kernel::module::user_span::UserSpan<'_>,
) -> i32 {
    // SAFETY: provider dispatch runs on the scheduler thread, the only one
    // touching FETCH_FILES; the host imports take spans of `arg` and `data`
    // it holds.
    unsafe { fs_dispatch_on_thread(handle, opcode, arg, data.as_mut()) }
}

/// # Safety
/// Scheduler thread only (FETCH_FILES).
unsafe fn fs_dispatch_on_thread(handle: i32, opcode: u32, arg: &mut [u8], data: &mut [u8]) -> i32 {
    // `fs_open` answers the FETCH_FILES slot's index, and every per-FD op
    // (QUERY/READ/STAT/CLOSE) below is handed it back.
    // The wasm fetch model has no fsync path and no replication, so
    // every successful op is `Fence::Volatile`. Contract errno rule
    // (see `fence.rs::QUERY_OP`): `EINVAL` for malformed buffer,
    // `ENOSYS` for handles this provider does not own — closed,
    // stale, or out-of-range slots fall in the ENOSYS bucket.
    if opcode == dev_fence::QUERY_OP {
        if arg.len() < dev_fence::WIRE_MAX_LEN {
            return errno::EINVAL;
        }
        let slot_idx = handle as usize;
        let files = &*core::ptr::addr_of!(FETCH_FILES);
        if slot_idx >= MAX_OPEN_FILES || !files[slot_idx].in_use {
            return errno::ENOSYS;
        }
        return match dev_fence::Fence::Volatile.encode(arg) {
            Some(n) => n as i32,
            None => errno::EINVAL,
        };
    }
    // FS capability bitmap (crates/fluxor-abi/src/contracts/storage/fs.rs::CAPS).
    // Reports handle-acquisition / write-layer capability only;
    // per-FD ops (READ, STAT, CLOSE) are always supported on any
    // FD this provider hands back and aren't represented in the
    // bitmap. The wasm backend offers OPEN against asset URLs and
    // WRITE against the persistent layer. OPENDIR is not advertised
    // (browsers expose no generic list-files primitive for arbitrary
    // URL roots); the browser's storage primitives are key-value, so a
    // path is the key, which is why `fs` paths and `storage.object`
    // keys deliberately share one namespace on this platform — two
    // names for one byte range would let a program write under one and
    // fail to find it under the other.
    if opcode == dev_fs::CAPS {
        // Writes go to the same persistent layer `storage.object` uses
        // (OPFS, IndexedDB where OPFS is absent), which is also what reads
        // consult first, so a path written here reads back as itself.
        let caps: u32 = dev_fs::caps::OPEN | dev_fs::caps::WRITE;
        return crate::abi::kernel_abi::caps_word::answer(arg, caps);
    }
    match opcode {
        dev_fs::OPEN => fs_open(arg),
        dev_fs::READ => fs_read(handle, data),
        dev_fs::CLOSE => fs_close(handle),
        dev_fs::STAT => fs_stat(handle, arg),
        dev_fs::WRITE => fs_write(handle, data),
        _ => errno::ENOSYS,
    }
}

unsafe fn fs_open(path: &[u8]) -> i32 {
    if path.is_empty() {
        return errno::EINVAL;
    }
    let files = &mut *core::ptr::addr_of_mut!(FETCH_FILES);
    let slot_idx = match files.iter().position(|s| !s.in_use) {
        Some(i) => i,
        None => return errno::ENOMEM,
    };
    let host_handle = host_fetch_open(path.as_ptr(), path.len());
    if host_handle < 0 {
        return errno::ENODEV;
    }
    files[slot_idx].host_handle = host_handle;
    files[slot_idx].in_use = true;
    // FS handles carry their contract in the tag; the vtable wrapper
    // strips it on re-entry so inbound ops see the raw slot.
    slot_idx as i32
}

unsafe fn fs_read(handle: i32, buf: &mut [u8]) -> i32 {
    if buf.is_empty() {
        return errno::EINVAL;
    }
    let slot_idx = handle as usize;
    let files = &*core::ptr::addr_of!(FETCH_FILES);
    if slot_idx >= MAX_OPEN_FILES || !files[slot_idx].in_use {
        return errno::EINVAL;
    }
    let n = host_fetch_recv(files[slot_idx].host_handle, buf.as_mut_ptr(), buf.len());
    if n > 0 {
        n
    } else if n == 0 {
        errno::EAGAIN
    } else if n == -1 {
        errno::OK
    } else {
        errno::ERROR
    }
}

unsafe fn fs_stat(handle: i32, arg: &mut [u8]) -> i32 {
    if arg.len() != dev_fs::stat::LEN {
        return errno::EINVAL;
    }
    let slot_idx = handle as usize;
    let files = &*core::ptr::addr_of!(FETCH_FILES);
    if slot_idx >= MAX_OPEN_FILES || !files[slot_idx].in_use {
        return errno::EINVAL;
    }
    let size = host_fetch_size(files[slot_idx].host_handle);
    if size == -3 {
        return errno::EAGAIN;
    }
    if size == -2 {
        return errno::ENODEV;
    }
    if size == -1 {
        return errno::ENOSYS;
    }
    if size < 0 {
        return errno::ENODEV;
    }
    // This backing has no mtime (a fetched resource carries none it can
    // vouch for), no file identity and no name count, so each is reported
    // as zero: not a value that could be mistaken for a real one.
    dev_fs::Stat {
        size: size as u64,
        ..dev_fs::Stat::default()
    }
    .answer(arg)
}

/// `WRITE` — append `data` to the open handle.
///
/// Returns bytes written. The bytes are staged against the handle and
/// published as one file at `CLOSE`, which is what makes several writes
/// one file instead of a sequence a reader can catch halfway.
unsafe fn fs_write(handle: i32, data: &[u8]) -> i32 {
    if data.is_empty() {
        return 0;
    }
    let slot_idx = handle as usize;
    let files = &*core::ptr::addr_of!(FETCH_FILES);
    if slot_idx >= MAX_OPEN_FILES || !files[slot_idx].in_use {
        return errno::EINVAL;
    }
    let n = host_fetch_write(files[slot_idx].host_handle, data.as_ptr(), data.len());
    if n < 0 {
        return errno::ENODEV;
    }
    n
}

unsafe fn fs_close(handle: i32) -> i32 {
    let slot_idx = handle as usize;
    let files = &mut *core::ptr::addr_of_mut!(FETCH_FILES);
    if slot_idx >= MAX_OPEN_FILES || !files[slot_idx].in_use {
        return errno::EINVAL;
    }
    let host_handle = files[slot_idx].host_handle;
    files[slot_idx].host_handle = -1;
    files[slot_idx].in_use = false;
    if host_handle >= 0 {
        host_fetch_close(host_handle);
    }
    errno::OK
}
