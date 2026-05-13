//! PL011 UART driver for BCM2712 (Pi 5 / CM5) and QEMU virt.
//!
//! Two write paths, both writing to the same MMIO:
//!   * **Normal**: `uart_putc` / `uart_puts` push bytes into the kernel
//!     log ring; the platform debug drain ([`Bcm2712UartSink`]) drains
//!     to the wire from core 0 once per scheduler tick.
//!   * **Raw** (`uart_raw_*`): synchronous direct MMIO writes used only
//!     by the exception / panic handler, which cannot rely on the
//!     scheduler still being alive. Gated on [`UART_READY`] so panics
//!     before `uart_init` don't poke an unmapped peripheral.
//!
//! Register layout (PL011, board-cm5 only; QEMU's PL011 ignores FR for
//! TX-readiness so the `#[cfg]` branches collapse to "always-write"):
//!   * `+0x00 DR`    — data register (TX/RX FIFO)
//!   * `+0x18 FR`    — flags (TXFF bit 5 = TX FIFO full)
//!   * `+0x24 IBRD`  — integer baud rate divisor
//!   * `+0x28 FBRD`  — fractional baud rate divisor
//!   * `+0x2c LCRH`  — line control
//!   * `+0x30 CR`    — control (UARTEN | TXE | RXE)
//!   * `+0x38 IMSC`  — interrupt mask
//!   * `+0x44 ICR`   — interrupt clear

#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, Ordering};

// UART (PL011)
#[cfg(not(feature = "board-cm5"))]
pub const UART_BASE: usize = 0x0900_0000; // QEMU virt PL011
#[cfg(feature = "board-cm5")]
pub const UART_BASE: usize = 0x1c_0003_0000; // Pi 5 RP1 UART0 on GPIO14/15
// RP1 is mapped at 0x1c_0000_0000 by VPU firmware (PCIe outbound window).
// Requires enable_uart=1, enable_rp1_uart=1, and pciex4_reset=0 in config.txt.

pub const UART_DR: *mut u32 = UART_BASE as *mut u32;
#[cfg(feature = "board-cm5")]
pub const UART_FR: *const u32 = (UART_BASE + 0x18) as *const u32;
#[cfg(feature = "board-cm5")]
pub const UART_FR_TXFF: u32 = 1 << 5;

/// Set to 1 after `uart_init` completes — exception_dump / panic_handler
/// won't touch the wire before this. Gating keeps an early-boot fault
/// from re-faulting on an unmapped PCIe address.
pub static UART_READY: AtomicU32 = AtomicU32::new(0);

/// Initialise PL011 UART for Pi 5 (RP1 UART0 at 0x1c_0003_0000).
///
/// Depends on `rp1_clocks_init()` having run first to ungate the PL011
/// reference clock. Values are the ones a running Linux kernel programs
/// (captured via devmem) for 115200 baud at RP1's 50 MHz UART ref clock.
///
///   +0x24 IBRD = 0x1B  (27)     -> 50 MHz ref / (16 * (27 + 8/64)) = 115200 baud
///   +0x28 FBRD = 0x08  (8)
///   +0x2c LCRH = 0x70           -> 8N1, FIFO enabled
///   +0x30 CR   = 0x301          -> UARTEN | TXE | RXE (no hardware flow control)
#[cfg(feature = "board-cm5")]
pub unsafe fn uart_init() {
    // VPU firmware (with enable_rp1_uart=1) fully configures PL011 at
    // 115200 8N1 before kernel handoff. We just reprogram to be sure.
    let fr = (UART_BASE + 0x18) as *const u32;
    let ibrd = (UART_BASE + 0x24) as *mut u32;
    let fbrd = (UART_BASE + 0x28) as *mut u32;
    let lcrh = (UART_BASE + 0x2c) as *mut u32;
    let cr = (UART_BASE + 0x30) as *mut u32;
    let imsc = (UART_BASE + 0x38) as *mut u32;
    let icr = (UART_BASE + 0x44) as *mut u32;

    core::ptr::write_volatile(cr, 0);
    let mut retries = 0u32;
    while retries < 10_000 {
        if core::ptr::read_volatile(fr) & (1 << 3) == 0 {
            break;
        }
        retries += 1;
    }
    core::ptr::write_volatile(imsc, 0);
    core::ptr::write_volatile(icr, 0x7FF);
    core::ptr::write_volatile(ibrd, 27);
    core::ptr::write_volatile(fbrd, 8);
    core::ptr::write_volatile(lcrh, 0x70);
    core::ptr::write_volatile(cr, 0x301);
}

#[cfg(not(feature = "board-cm5"))]
pub unsafe fn uart_init() {
    // QEMU virt: UART is already configured, nothing to do
}

// Normal kernel log path: push to the log ring only. The wire is driven
// by the platform-runtime debug drain (`platform::debug::DebugDrain`)
// via the `Bcm2712UartSink` below. Keeps logs opt-in and orthogonal to
// the application.
pub fn uart_putc(c: u8) {
    fluxor::kernel::log_ring::push_byte(c);
}

pub fn uart_puts(s: &[u8]) {
    fluxor::kernel::log_ring::push_bytes(s);
}

// Direct synchronous MMIO path — used only by the exception / panic
// handler, which cannot rely on the scheduler (or therefore the debug
// drain) still being alive. Normal-runtime writes go through the non-
// blocking FIFO-fill path (`uart_nonblocking_write`).
pub fn uart_raw_putc(c: u8) {
    unsafe {
        #[cfg(feature = "board-cm5")]
        {
            while core::ptr::read_volatile(UART_FR) & UART_FR_TXFF != 0 {}
        }
        core::ptr::write_volatile(UART_DR, c as u32);
    }
}

pub fn uart_raw_puts(s: &[u8]) {
    let mut i = 0;
    while i < s.len() {
        uart_raw_putc(s[i]);
        i += 1;
    }
}

/// Non-blocking UART FIFO fill. Writes as many bytes as the TX FIFO
/// will accept right now, then returns the count. Used as the
/// `DebugTx` backend for the platform debug drain — the drain owns
/// retry/backpressure state so we never spin here. On QEMU virt
/// (non-board-cm5) the FR bit isn't meaningful; fall back to writing
/// all bytes.
pub fn uart_nonblocking_write(bytes: &[u8]) -> usize {
    if UART_READY.load(Ordering::Relaxed) == 0 {
        return 0;
    }
    let mut i = 0;
    while i < bytes.len() {
        #[cfg(feature = "board-cm5")]
        unsafe {
            if core::ptr::read_volatile(UART_FR) & UART_FR_TXFF != 0 {
                break;
            }
        }
        unsafe { core::ptr::write_volatile(UART_DR, bytes[i] as u32) };
        i += 1;
    }
    i
}

/// Raw u32 decimal printer for panic / exception paths (mirrors
/// `uart_put_u32` but goes straight to the wire).
pub fn uart_raw_put_u32(mut n: u32) {
    let mut buf = [0u8; 10];
    let mut i = 0usize;
    if n == 0 {
        uart_raw_putc(b'0');
        return;
    }
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        uart_raw_putc(buf[i]);
    }
}

// --- Platform debug drain (local UART) ---
//
// Normal-runtime path for kernel log output. Drains `log_ring` into
// the UART via `DebugTx`, called from the core-0 main loop once per
// scheduler tick (tier 0 / tier 1a). SPSC against the kernel log
// path — single consumer. Panic / exception handlers do not use this
// path; they hit the wire directly via `uart_raw_puts`.
pub struct Bcm2712UartSink;

impl fluxor::platform::debug::DebugTx for Bcm2712UartSink {
    fn write(&mut self, bytes: &[u8]) -> usize {
        uart_nonblocking_write(bytes)
    }
}

pub static mut DEBUG_DRAIN: fluxor::platform::debug::DebugDrain<1024> =
    fluxor::platform::debug::DebugDrain::new();
pub static mut DEBUG_SINK: Bcm2712UartSink = Bcm2712UartSink;

/// Drain queued log bytes to the UART. MUST only be called from core 0.
#[inline]
pub fn debug_drain_poll_core0() {
    // SAFETY: SPSC consumer on log_ring; only called from core 0 in
    // the main loop or during boot before secondary cores wake.
    unsafe {
        let drain_p = &raw mut DEBUG_DRAIN;
        let sink_p = &raw mut DEBUG_SINK;
        (*drain_p).poll(&mut *sink_p);
    }
}

pub fn uart_put_u32(mut n: u32) {
    let mut buf = [0u8; 10];
    let mut i = 0usize;
    if n == 0 {
        uart_putc(b'0');
        return;
    }
    while n > 0 {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        uart_putc(buf[i]);
    }
}

pub fn uart_put_hex32(val: u32) {
    let hex = b"0123456789abcdef";
    uart_puts(b"0x");
    let mut i = 28i32;
    while i >= 0 {
        uart_putc(hex[((val >> i as u32) & 0xf) as usize]);
        i -= 4;
    }
}
