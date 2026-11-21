//! WASM `image_decode` provider: the browser reads the named byte range of
//! an object through the same object store `storage.object` serves (the
//! written layer first, then a ranged `fetch()` of the page origin) and
//! decodes it with `createImageBitmap` + `OffscreenCanvas`, scaled to the
//! requested size and packed as RGB565.
//!
//! The encoded bytes stay in the browser; the kernel holds only a job table
//! mapping each job handle to the shim's job. Host bindings:
//!
//!   - `host_image_decode_object` — start a decode of `key[offset..+length]`
//!   - `host_image_decode_recv`   — drain decoded pixels
//!   - `host_image_decode_close`  — release a job
//!
//! `host_image_decode_recv` answers `> 0` bytes copied, `0` drained, `-1`
//! still decoding, `-2` failed, `-3` no such job.

use crate::abi::contracts::image_decode as img;
use crate::kernel::module::user_span::UserSpan;
use crate::kernel::sys::errno;

/// Decode jobs open at once, across every caller.
pub(super) const JOBS: usize = 8;

/// The shim's job handle for each open job, `-1` for a free entry.
static mut JOB_HOST: [i32; JOBS] = [-1; JOBS];

extern "C" {
    /// Start decoding `key[..key_len]`'s bytes `[offset, offset + length)`
    /// to a `width` x `height` RGB565 image. Returns a non-negative job
    /// handle, or a negative value when the decode could not start.
    fn host_image_decode_object(
        key_ptr: *const u8,
        key_len: usize,
        offset: u64,
        length: u32,
        width: u32,
        height: u32,
    ) -> i32;

    /// Drain up to `len` decoded bytes into `buf` (see the module docs).
    fn host_image_decode_recv(handle: i32, buf: *mut u8, len: usize) -> i32;

    /// Release a job. Idempotent.
    fn host_image_decode_close(handle: i32) -> i32;
}

/// Register the provider. Called from `wasm_init_providers`.
pub fn register() {
    crate::kernel::module::provider::register(img::CLASS, dispatch);
}

fn dispatch(handle: i32, op: u32, arg: &mut [u8], mut data: UserSpan<'_>) -> i32 {
    match op {
        img::DECODE => decode(arg),
        img::RECV => recv(handle, data.as_mut()),
        img::CLOSE => close(handle),
        _ => errno::ENOSYS,
    }
}

/// The job table: one wasm thread runs every provider call.
fn jobs() -> &'static mut [i32; JOBS] {
    // SAFETY: the wasm kernel is single-threaded and no caller holds the
    // returned reference across another call into this module.
    unsafe { &mut *core::ptr::addr_of_mut!(JOB_HOST) }
}

/// The job entry a handle names, if it is one of this provider's open jobs.
fn job_of(handle: i32) -> Option<usize> {
    let slot = usize::try_from(handle).ok()?;
    (slot < JOBS && jobs()[slot] >= 0).then_some(slot)
}

/// `DECODE`: start a job and mint its handle.
fn decode(arg: &[u8]) -> i32 {
    let Some(req) = img::decode::parse(arg) else {
        return errno::EINVAL;
    };
    if req.format != img::format::RGB565 {
        return errno::ENOTSUP;
    }
    let table = jobs();
    let Some(slot) = table.iter().position(|h| *h < 0) else {
        return errno::ENOMEM;
    };
    // SAFETY: the key is a live slice for the call; the shim copies it
    // before returning.
    let h = unsafe {
        host_image_decode_object(
            req.key.as_ptr(),
            req.key.len(),
            req.offset,
            req.length,
            u32::from(req.width),
            u32::from(req.height),
        )
    };
    if h < 0 {
        return errno::ENODEV;
    }
    table[slot] = h;
    slot as i32
}

/// `RECV`: drain the job's pixels into `out`.
fn recv(handle: i32, out: &mut [u8]) -> i32 {
    let Some(slot) = job_of(handle) else {
        return errno::EINVAL;
    };
    if out.is_empty() {
        return errno::EINVAL;
    }
    // SAFETY: `out` is the caller's data span, valid and writable for the
    // call; the shim writes at most `out.len()` bytes into it.
    let n = unsafe { host_image_decode_recv(jobs()[slot], out.as_mut_ptr(), out.len()) };
    match n {
        n if n >= 0 => n,
        -1 => errno::EAGAIN,
        _ => errno::EIO,
    }
}

/// `CLOSE`: release the job.
fn close(handle: i32) -> i32 {
    let Some(slot) = job_of(handle) else {
        return errno::EINVAL;
    };
    let table = jobs();
    // SAFETY: a plain host call on the shim's own job handle.
    unsafe { host_image_decode_close(table[slot]) };
    table[slot] = -1;
    errno::OK
}
