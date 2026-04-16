//! Platform-agnostic USB CDC writer bridge.
//!
//! Mirror of `uart_write` for USB CDC-ACM. The RP platform installs a
//! function that enqueues bytes into an embassy pipe which an async task
//! drains into the CDC endpoint. Platforms without USB simply don't
//! install anything; the `USB_WRITE_RAW` syscall returns ENOSYS and
//! callers (like the log_usb overlay module) fall back.
//!
//! Unlike UART writes, USB writes are non-blocking: the enqueue may
//! accept fewer bytes than requested if the internal pipe is full, and
//! the installed function returns the count actually enqueued. Callers
//! should treat a short write as back-pressure and retry the remaining
//! bytes on the next step.

use portable_atomic::{AtomicPtr, Ordering};
use core::ptr;

type UsbWriteFn = unsafe fn(*const u8, usize) -> usize;

static WRITER: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());

/// Install the platform's USB writer. Safe to call once at boot.
pub fn install(f: UsbWriteFn) {
    WRITER.store(f as *mut (), Ordering::Release);
}

/// Enqueue bytes for USB CDC transmission if a writer is installed.
/// Returns bytes enqueued, or `None` if no writer is installed.
pub fn write(bytes: &[u8]) -> Option<usize> {
    let ptr_val = WRITER.load(Ordering::Acquire);
    if ptr_val.is_null() {
        return None;
    }
    let f: UsbWriteFn = unsafe { core::mem::transmute(ptr_val) };
    let n = unsafe { f(bytes.as_ptr(), bytes.len()) };
    Some(n)
}
