//! Exception vectors + IRQ handler — BCM2712 (Pi 5 / QEMU virt).
//!
//! The `global_asm!` block defines `exception_vectors:` (aligned to 2 KB)
//! with 16 × 128 B entries per VBAR_EL1 layout. Synchronous / FIQ /
//! SError → `unhandled_exception` (dumps state and spins). IRQ entries
//! save caller-saved registers, branch into [`irq_handler`], and
//! `eret`.
//!
//! `irq_handler` reads `GICC_IAR`, EOIs, then either reloads the timer
//! tick (PPI 30 on cm5 / PPI 27 on QEMU) or walks `IRQ_BINDINGS` to
//! either fan out via `pcie::pcie1_msi_dispatch` or signal a single
//! kernel event via `event_signal_from_isr`.
//!
//! `exception_dump` is `#[no_mangle]` — called from the `unhandled_*`
//! assembly entry — and is gated on [`UART_READY`] (defined in
//! `bcm2712/uart.rs`) so it never pokes an unmapped peripheral on an
//! early-boot fault. State is also stashed at the fixed address
//! 0x4007_0000 for offline QEMU monitor inspection.

#![allow(dead_code, reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it")]

use core::arch::global_asm;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::gic::{
    EVENT_HANDLE_PCIE1_MSI, GICC_EOIR, GICC_IAR, IRQ_BINDINGS, IRQ_BINDING_COUNT, TIMER_PPI,
};
use super::uart::{uart_raw_putc, uart_raw_put_u32, uart_raw_puts, UART_READY};
use super::timer;

global_asm!(
    ".section .text",
    ".balign 2048",
    ".global exception_vectors",
    "exception_vectors:",
    // Current EL with SP_EL0 (4 entries). Tagged catch (`fluxor_el1_catch` in
    // kernel::mmu): a kernel-side or async fault taken while servicing an
    // isolated module FAILS STOP — it latches ESR/FAR/SPSR/ELR (surfaced over
    // UDP by a sibling core) and spins, rather than longjmp-recovering out of a
    // possibly-held kernel lock. (Genuine EL0 module faults arrive at the
    // lower-EL synchronous vector instead, which does recover.)
    ".balign 128", "mov w17, #5", "b fluxor_el1_catch",  // Synchronous
    ".balign 128", "mov w17, #6", "b fluxor_el1_catch",  // IRQ
    ".balign 128", "mov w17, #7", "b fluxor_el1_catch",  // FIQ
    ".balign 128", "mov w17, #8", "b fluxor_el1_catch",  // SError
    // Current EL with SP_ELx (4 entries)
    // Synchronous (EL1h): a fault in the kernel's own EL1 code — including
    // while servicing an isolated module's svc1/abort path — FAILS STOP via
    // `fluxor_el1_sync_vec` (kernel::mmu): latch syndrome + dump + spin. It is
    // NOT recovered, because a fault inside kernel servicing may hold a lock
    // whose abandonment would deadlock the kernel.
    ".balign 128", "b fluxor_el1_sync_vec",  // Synchronous
    // IRQ handler — save all caller-saved registers
    ".balign 128",
    "sub sp, sp, #256",
    "stp x0,  x1,  [sp, #0]",
    "stp x2,  x3,  [sp, #16]",
    "stp x4,  x5,  [sp, #32]",
    "stp x6,  x7,  [sp, #48]",
    "stp x8,  x9,  [sp, #64]",
    "stp x10, x11, [sp, #80]",
    "stp x12, x13, [sp, #96]",
    "stp x14, x15, [sp, #112]",
    "stp x16, x17, [sp, #128]",
    "stp x18, x19, [sp, #144]",
    "stp x29, x30, [sp, #160]",
    "bl irq_handler",
    "ldp x0,  x1,  [sp, #0]",
    "ldp x2,  x3,  [sp, #16]",
    "ldp x4,  x5,  [sp, #32]",
    "ldp x6,  x7,  [sp, #48]",
    "ldp x8,  x9,  [sp, #64]",
    "ldp x10, x11, [sp, #80]",
    "ldp x12, x13, [sp, #96]",
    "ldp x14, x15, [sp, #112]",
    "ldp x16, x17, [sp, #128]",
    "ldp x18, x19, [sp, #144]",
    "ldp x29, x30, [sp, #160]",
    "add sp, sp, #256",
    "eret",
    ".balign 128", "mov w17, #9", "b fluxor_el1_catch",  // FIQ (EL1h)
    ".balign 128", "mov w17, #4", "b fluxor_el1_catch",  // SError (EL1h)
    // Lower EL using AArch64 (4 entries)
    // Synchronous from a lower EL (EL0) — SVC return from an isolated
    // module_step, or a data/instruction abort while it runs. Routed to
    // the EL0-isolation dispatcher in `kernel::mmu` (fluxor_el0_lower_sync_vec)
    // which longjmps back to the EL1 scheduler. The other three lower-EL
    // entries (IRQ/FIQ/SError) stay on the dump path: IRQs are masked for
    // the duration of an EL0 step, so they should not fire here.
    ".balign 128", "b fluxor_el0_lower_sync_vec",  // Synchronous
    ".balign 128", "mov w17, #10", "b fluxor_el1_catch",  // IRQ (lower EL)
    ".balign 128", "mov w17, #11", "b fluxor_el1_catch",  // FIQ (lower EL)
    ".balign 128", "mov w17, #12", "b fluxor_el1_catch",  // SError (lower EL)
    // Lower EL using AArch32 (4 entries)
    ".balign 128", "b unhandled_exception",
    ".balign 128", "b unhandled_exception",
    ".balign 128", "b unhandled_exception",
    ".balign 128", "b unhandled_exception",
    // `.global` so the EL0-isolation dispatcher in `kernel::mmu`
    // (a separate global_asm! block) can branch here when a lower-EL
    // synchronous exception arrives with no active EL0 step.
    ".global unhandled_exception",
    "unhandled_exception:",
    "stp x29, x30, [sp, #-16]!",
    "stp x0, x1, [sp, #-16]!",
    "mrs x0, elr_el1",
    "mrs x1, esr_el1",
    "mrs x2, far_el1",
    "bl exception_dump",
    "ldp x0, x1, [sp], #16",
    "ldp x29, x30, [sp], #16",
    // Spin on exception — no recovery, keep CPU in diagnosable state.
    "1: b 1b",
);

/// Guard against recursive exceptions in exception_dump.
pub static EXCEPTION_DEPTH: AtomicU32 = AtomicU32::new(0);

/// Per-core fault latch. `exception_dump` records the faulting core's ESR/FAR
/// and a count here so a sibling core (core 0, which owns the UDP debug drain)
/// can surface secondary-core faults over network telemetry — the UART dump is
/// invisible on benches without a wired debug UART. Indexed by core id (0..3).
pub static CORE_FAULT_ESR: [AtomicU64; 4] =
    [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
pub static CORE_FAULT_FAR: [AtomicU64; 4] =
    [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
pub static CORE_FAULT_COUNT: [AtomicU32; 4] =
    [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)];
/// SPSR_EL1 at the fault — M[3:0] gives the EL the fault was taken FROM
/// (0=EL0t, 4=EL1t, 5=EL1h), which disambiguates an `svc` taken at EL0 vs EL1.
pub static CORE_FAULT_SPSR: [AtomicU64; 4] =
    [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
/// ELR_EL1 at the fault — the faulting instruction's address.
pub static CORE_FAULT_ELR: [AtomicU64; 4] =
    [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

#[no_mangle]
pub unsafe extern "C" fn exception_dump(elr: u64, esr: u64, far: u64) {
    // Latch the fault per-core BEFORE the recursion guard so a sibling core
    // (core 0) can surface it over UDP telemetry even when this core's UART
    // dump is invisible (no wired debug UART) or the core then hangs.
    let c = (current_core_id() as usize) & 3;
    let spsr: u64;
    // SAFETY: reading SPSR_EL1 in the exception handler is side-effect free.
    core::arch::asm!("mrs {}, spsr_el1", out(reg) spsr, options(nomem, nostack));
    CORE_FAULT_SPSR[c].store(spsr, Ordering::Relaxed);
    CORE_FAULT_ELR[c].store(elr, Ordering::Relaxed);
    CORE_FAULT_ESR[c].store(esr, Ordering::Relaxed);
    CORE_FAULT_FAR[c].store(far, Ordering::Relaxed);
    CORE_FAULT_COUNT[c].fetch_add(1, Ordering::Relaxed);

    // Prevent recursive exception storms — if we fault inside the handler,
    // just spin silently rather than faulting again.
    if EXCEPTION_DEPTH.fetch_add(1, Ordering::Relaxed) > 0 {
        return;
    }
    // Always store exception state at a fixed address for QEMU monitor inspection.
    // Read with: (qemu) xp /4gx 0x40070000
    // Useful when UART is not yet initialized (early boot / KVM).
    core::ptr::write_volatile(0x4007_0000 as *mut u64, elr);
    core::ptr::write_volatile(0x4007_0008 as *mut u64, esr);
    core::ptr::write_volatile(0x4007_0010 as *mut u64, far);
    core::ptr::write_volatile(0x4007_0018 as *mut u64, 0xDEAD_BEEF_CAFE_BABE);

    // Don't touch UART if it hasn't been initialised yet (early boot / KVM)
    if UART_READY.load(Ordering::Relaxed) == 0 {
        return;
    }
    // Exception path writes directly to the UART hardware. The ring
    // is unusable here — the scheduler may be dead, the log_uart
    // overlay won't drain, and even the heap allocator might be
    // poisoned. Raw MMIO is the only thing we can trust.
    uart_raw_puts(b"\r\n!!! EXCEPTION\r\n");
    uart_raw_puts(b"  ELR=0x");
    exception_dump_hex64(elr);
    uart_raw_puts(b"\r\n  ESR=0x");
    exception_dump_hex64(esr);
    uart_raw_puts(b"\r\n  FAR=0x");
    exception_dump_hex64(far);
    uart_raw_puts(b"\r\n");
    // Recent log tail — helps correlate the fault with whatever the
    // system logged right before it. `read_tail` does not advance
    // the SPSC tail pointer, so a concurrent drain (if any remains)
    // still sees the same bytes.
    let mut buf = [0u8; 1024];
    let n = fluxor::kernel::log_ring::read_tail(&mut buf);
    if n > 0 {
        uart_raw_puts(b"--- log tail (");
        uart_raw_put_u32(n as u32);
        uart_raw_puts(b" bytes) ---\r\n");
        uart_raw_puts(&buf[..n]);
        uart_raw_puts(b"\r\n--- end ---\r\n");
    }
}

/// Hex dump for exception handler. Duplicates uart_put_hex64 but routes
/// through uart_raw_putc — see exception_dump rationale.
pub fn exception_dump_hex64(val: u64) {
    let hex = b"0123456789abcdef";
    let mut i = 60i32;
    while i >= 0 {
        uart_raw_putc(hex[((val >> i as u64) & 0xf) as usize]);
        i -= 4;
    }
}

/// Timer ticks per scheduler tick (set from tick_us config or default 1ms)
pub static mut TICKS_PER_TICK: u32 = 0;

/// Per-core tick counters. Core 0 also reads `DBG_TICK` (legacy
/// alias kept for the single-core diagnostic path); cores 1-3
/// read only this array.
pub static CORE_TICKS: [AtomicU32; 4] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];

/// Per-core last interrupted PC (ELR_EL1), latched by the timer IRQ. When a
/// core's scheduler loop hangs but timer IRQs still fire, this is the PC of
/// the spinning code — map it with `rust-objdump -d` on the firmware ELF.
pub static CORE_LAST_ELR: [AtomicU64; 4] =
    [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

/// Current core number (0-3). Pi 5 encodes it in MPIDR Aff1[15:8].
#[inline(always)]
pub fn current_core_id() -> u8 {
    let mpidr: u64;
    // SAFETY: `mrs mpidr_el1` reads a per-CPU system register; no operands.
    unsafe {
        core::arch::asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nomem, nostack));
    }
    ((mpidr >> 8) & 0xFF) as u8
}

#[no_mangle]
pub unsafe extern "C" fn irq_handler() {
    let iar = core::ptr::read_volatile(GICC_IAR);
    let irq_id = iar & 0x3FF;
    core::ptr::write_volatile(GICC_EOIR, iar);

    if irq_id == TIMER_PPI {
        // Timer tick — reload and count
        timer::timer_set(TICKS_PER_TICK);
        let core_id = {
            let mpidr: u64;
            core::arch::asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nomem, nostack));
            ((mpidr >> 8) & 0xFF) as usize
        };
        CORE_TICKS[core_id].fetch_add(1, Ordering::Relaxed);
        // Latch the interrupted PC per core. If a core's scheduler loop has
        // frozen (domain tick_count stuck) while CORE_TICKS keeps climbing,
        // every timer IRQ interrupts the spinning code at the same PC — so
        // CORE_LAST_ELR names exactly where it's stuck (map via objdump).
        if core_id < 4 {
            let elr: u64;
            core::arch::asm!("mrs {}, elr_el1", out(reg) elr, options(nomem, nostack));
            CORE_LAST_ELR[core_id].store(elr, Ordering::Relaxed);
        }
    } else {
        // Check IRQ bindings (virtio, etc.)
        let n = IRQ_BINDING_COUNT;
        let mut i = 0;
        while i < n {
            let binding = &IRQ_BINDINGS[i];
            if binding.irq == irq_id {
                if binding.event_handle == EVENT_HANDLE_PCIE1_MSI {
                    // brcmstb MSI mux: read + clear MSI_INT_STATUS,
                    // fan out per-vector events. Keeps total ISR
                    // cost proportional to the number of pending
                    // MSIs (typically 1).
                    let _ = fluxor::kernel::pcie::pcie1_msi_dispatch();
                } else if binding.event_handle >= 0 {
                    // ACK device if mmio_base is set (virtio-mmio)
                    if binding.mmio_base != 0 {
                        let isr = core::ptr::read_volatile(
                            (binding.mmio_base + 0x60) as *const u32,
                        );
                        if isr != 0 {
                            core::ptr::write_volatile(
                                (binding.mmio_base + 0x64) as *mut u32,
                                isr,
                            );
                        }
                    }
                    fluxor::kernel::event::event_signal_from_isr(binding.event_handle);
                }
            }
            i += 1;
        }
    }
}
