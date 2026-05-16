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
//!   shim size >= 0 → OK; write `[size:u32, mtime:u32=0]` into the
//!                   8-byte stat buffer
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
//! FS_SEEK, FS_FSYNC, FS_WRITE return ENOSYS — the streaming fetch
//! model has no equivalent.
//!
//! FS_CLOSE calls `host_fetch_close`, cancelling any in-flight body
//! reader and dropping the host-side handle entry.

use crate::abi::contracts::fence as dev_fence;
use crate::abi::contracts::storage::fs as dev_fs;
use crate::kernel::errno;
use crate::kernel::fd::{tag_fd, FD_TAG_FS};

const MAX_OPEN_FILES: usize = 16;

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
    use crate::kernel::provider;
    use crate::kernel::provider::contract as dev_class;
    provider::register(dev_class::FS, wasm_fs_dispatch);
}

unsafe fn wasm_fs_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    // The wasm fetch model has no fsync path and no replication, so
    // every successful op is `Fence::Volatile`. Contract errno rule
    // (see `fence.rs::QUERY_OP`): `EINVAL` for malformed buffer,
    // `ENOSYS` for handles this provider does not own — closed,
    // stale, or out-of-range slots fall in the ENOSYS bucket.
    if opcode == dev_fence::QUERY_OP {
        if arg.is_null() || arg_len < dev_fence::WIRE_MAX_LEN {
            return errno::EINVAL;
        }
        let slot_idx = handle as usize;
        let files = &*core::ptr::addr_of!(FETCH_FILES);
        if slot_idx >= MAX_OPEN_FILES || !files[slot_idx].in_use {
            return errno::ENOSYS;
        }
        let buf = core::slice::from_raw_parts_mut(arg, arg_len);
        return match dev_fence::Fence::Volatile.encode(buf) {
            Some(n) => n as i32,
            None => errno::EINVAL,
        };
    }
    match opcode {
        dev_fs::OPEN => fs_open(arg, arg_len),
        dev_fs::READ => fs_read(handle, arg, arg_len),
        dev_fs::CLOSE => fs_close(handle),
        dev_fs::STAT => fs_stat(handle, arg, arg_len),
        _ => errno::ENOSYS,
    }
}

unsafe fn fs_open(path_ptr: *mut u8, path_len: usize) -> i32 {
    if path_ptr.is_null() || path_len == 0 {
        return errno::EINVAL;
    }
    let files = &mut *core::ptr::addr_of_mut!(FETCH_FILES);
    let slot_idx = match files.iter().position(|s| !s.in_use) {
        Some(i) => i,
        None => return errno::ENOMEM,
    };
    let host_handle = host_fetch_open(path_ptr as *const u8, path_len);
    if host_handle < 0 {
        return errno::ENODEV;
    }
    files[slot_idx].host_handle = host_handle;
    files[slot_idx].in_use = true;
    // FS handles carry their contract in the tag; the vtable wrapper
    // strips it on re-entry so inbound ops see the raw slot.
    tag_fd(FD_TAG_FS, slot_idx as i32)
}

unsafe fn fs_read(handle: i32, buf: *mut u8, len: usize) -> i32 {
    if buf.is_null() || len == 0 {
        return errno::EINVAL;
    }
    let slot_idx = handle as usize;
    let files = &*core::ptr::addr_of!(FETCH_FILES);
    if slot_idx >= MAX_OPEN_FILES || !files[slot_idx].in_use {
        return errno::EINVAL;
    }
    let n = host_fetch_recv(files[slot_idx].host_handle, buf, len);
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

unsafe fn fs_stat(handle: i32, arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 8 {
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
    let size_u = size as u32;
    let size_b = size_u.to_le_bytes();
    *arg = size_b[0];
    *arg.add(1) = size_b[1];
    *arg.add(2) = size_b[2];
    *arg.add(3) = size_b[3];
    *arg.add(4) = 0;
    *arg.add(5) = 0;
    *arg.add(6) = 0;
    *arg.add(7) = 0;
    errno::OK
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
