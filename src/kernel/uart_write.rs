//! Platform-agnostic UART writer bridge.
//!
//! A platform with a primary UART (currently only bcm2712) calls
//! `install()` during boot with a function that writes raw bytes to that
//! UART synchronously. The `UART_WRITE_RAW` syscall (dev_system 0x0C65)
//! forwards `write()` calls to that function.
//!
//! Platforms without a UART (e.g. pico/picow boards where the RP UART
//! pins are usually repurposed) simply don't install anything; the
//! syscall returns ENOSYS and callers fall back.
//!
//! # Why a bridge instead of a cfg
//!
//! Keeping this out of `syscalls.rs` means the syscall dispatcher stays
//! platform-agnostic — no `#[cfg(feature = "chip-bcm2712")]` cluttering
//! the opcode match. Platforms register at boot; the rest of the kernel
//! just sees an optional function pointer.
//!
//! # Not the panic path
//!
//! Emergency output (panic / exception handlers) must work even when the
//! scheduler is dead and the overlay module isn't running. Platforms
//! write to the UART hardware directly from those paths (bcm2712 uses
//! `uart_raw_puts` / `uart_raw_putc`), bypassing this indirection.

use portable_atomic::{AtomicPtr, Ordering};
use core::ptr;

type UartWriteFn = unsafe fn(*const u8, usize) -> usize;

static WRITER: AtomicPtr<()> = AtomicPtr::new(ptr::null_mut());

/// Install the platform's UART writer. Safe to call once at boot.
/// Calling again overwrites the previous installation.
pub fn install(f: UartWriteFn) {
    WRITER.store(f as *mut (), Ordering::Release);
}

/// Write bytes to the UART if a writer is installed. Returns the number
/// of bytes written, or `None` if no writer is installed (i.e. the
/// platform has no UART).
pub fn write(bytes: &[u8]) -> Option<usize> {
    let ptr_val = WRITER.load(Ordering::Acquire);
    if ptr_val.is_null() {
        return None;
    }
    // SAFETY: caller of `install` is responsible for providing a valid fn.
    // Transmute via the known fn-pointer signature.
    let f: UartWriteFn = unsafe { core::mem::transmute(ptr_val) };
    let n = unsafe { f(bytes.as_ptr(), bytes.len()) };
    Some(n)
}
