//! Cortex-M architecture primitives — instructions, barriers, PRIMASK and NVIC.
//!
//! These are the ARM architecture's own facilities, not a chip's peripherals:
//! every Cortex-M part has them at the same addresses with the same encodings,
//! so they belong to the architecture layer rather than to `platform/rp`.
//! Keeping them here is what lets an RP register file talk about IO_BANK0
//! without also owning what a memory barrier is.
//!
//! # ARMv6-M versus ARMv8-M
//!
//! Fluxor targets both: RP2040 is Cortex-M0+ (ARMv6-M) and RP2350 is
//! Cortex-M33 (ARMv8-M Mainline). The differences that reach this module are
//! called out at each site rather than hidden, because the ones that are
//! silent are the dangerous ones:
//!
//! - **NVIC width.** ARMv6-M defines exactly one 32-bit ISER/ICER pair and so
//!   supports at most 32 external interrupts; ARMv8-M defines up to 16 of
//!   each. [`nvic_unmask`] and [`nvic_mask`] index by register, and the
//!   ARMv6-M build asserts the index is zero rather than writing past the
//!   architected window.
//! - **Interrupt masking.** Both have PRIMASK and `cpsid i`/`cpsie i`.
//!   ARMv8-M Mainline also has BASEPRI, which would allow priority-selective
//!   masking; it is deliberately unused, so that one masking discipline holds
//!   on both parts.
//! - **Barriers.** `dsb`, `isb` and `dmb` exist in both, with the same
//!   semantics for the uses here.
//!
//! Everything is `#[inline(always)]` over `core::arch::asm!`, so this carries
//! no dependency of its own — the point being that the architecture layer is
//! the one place that may not defer to an external HAL.

use core::arch::asm;

/// Data Synchronisation Barrier. Completes every memory access before any
/// instruction after it executes.
#[inline(always)]
pub fn dsb() {
    // SAFETY: a barrier has no operands and no memory effects of its own.
    unsafe { asm!("dsb", options(nostack, preserves_flags)) }
}

/// Instruction Synchronisation Barrier. Flushes the pipeline so that
/// instructions fetched after it see the effects of everything before it —
/// required after changing MPU or vector-table state.
#[inline(always)]
pub fn isb() {
    // SAFETY: as `dsb`.
    unsafe { asm!("isb", options(nostack, preserves_flags)) }
}

/// Data Memory Barrier. Orders memory accesses without waiting for them to
/// complete, which is the weaker and cheaper of the two orderings.
#[inline(always)]
pub fn dmb() {
    // SAFETY: as `dsb`.
    unsafe { asm!("dmb", options(nostack, preserves_flags)) }
}

/// No-operation. Used where a deliberate, non-elidable delay slot is wanted.
#[inline(always)]
pub fn nop() {
    // SAFETY: no operands, no effects.
    unsafe { asm!("nop", options(nomem, nostack, preserves_flags)) }
}

/// Wait For Event. Sleeps the core until an event arrives (an interrupt, an
/// `sev` from the other core, or a spurious wake). The caller must always
/// re-check its condition on waking: a spurious wake is architecturally
/// permitted and the event register may already have been set.
#[inline(always)]
pub fn wfe() {
    // SAFETY: `wfe` may return immediately; correctness rests on the
    // caller's re-check loop, not on this instruction.
    unsafe { asm!("wfe", options(nomem, nostack, preserves_flags)) }
}

/// Send Event, waking any core parked in [`wfe`].
#[inline(always)]
pub fn sev() {
    // SAFETY: no operands; the effect is on other cores' event registers.
    unsafe { asm!("sev", options(nomem, nostack, preserves_flags)) }
}

/// Busy-wait for approximately `cycles` core cycles.
///
/// A 2-cycle `subs`/`bne` loop, so the argument is halved. Deliberately
/// approximate: this exists for the short hardware settling delays a
/// peripheral datasheet specifies, never for timekeeping — real deadlines
/// belong to the monotonic timer.
#[inline(always)]
pub fn delay(cycles: u32) {
    let loops = cycles / 2;
    if loops == 0 {
        return;
    }
    // SAFETY: a self-contained countdown over a local register.
    unsafe {
        asm!(
            "1:",
            "subs {n}, #1",
            "bne 1b",
            n = inout(reg) loops => _,
            options(nostack),
        )
    }
}

/// Read PRIMASK. `true` means interrupts are currently masked.
#[inline(always)]
pub fn primask_is_active() -> bool {
    let primask: u32;
    // SAFETY: reads an architected special register into a local.
    unsafe { asm!("mrs {}, PRIMASK", out(reg) primask, options(nomem, nostack, preserves_flags)) }
    primask & 1 == 1
}

/// Enable interrupts (`cpsie i`).
///
/// # Safety
///
/// Unmasking inside a critical section breaks whatever invariant that section
/// was protecting. Callers must own the masking state they are changing.
#[inline(always)]
pub unsafe fn enable_interrupts() {
    // SAFETY: the caller asserts it owns the masking state.
    unsafe { asm!("cpsie i", options(nomem, nostack, preserves_flags)) }
}

/// Disable interrupts (`cpsid i`).
///
/// # Safety
///
/// Masking without a matching restore stalls every interrupt-driven path on
/// the core. Prefer [`interrupt_free`], which cannot leak the mask.
#[inline(always)]
pub unsafe fn disable_interrupts() {
    // SAFETY: the caller asserts it will restore the mask.
    unsafe { asm!("cpsid i", options(nomem, nostack, preserves_flags)) }
}

/// Run `f` with interrupts masked, restoring the **previous** PRIMASK rather
/// than unconditionally enabling.
///
/// Restoring rather than enabling is what makes this safe to nest: an inner
/// call inside an outer critical section leaves the mask set on the way out,
/// where an unconditional `cpsie i` would silently open the outer section.
#[inline]
pub fn interrupt_free<R>(f: impl FnOnce() -> R) -> R {
    let was_active = primask_is_active();
    // SAFETY: the matching restore below is unconditional — `f` cannot
    // return early without passing through it, and a panic in a no_std
    // kernel does not unwind.
    unsafe { disable_interrupts() };
    let r = f();
    if !was_active {
        // SAFETY: interrupts were enabled on entry, so restoring that is
        // exactly the state the caller had.
        unsafe { enable_interrupts() };
    }
    r
}

use super::nvic;

/// Number of architected 32-bit ISER/ICER registers.
///
/// ARMv6-M defines exactly one; ARMv8-M defines up to 16. The `armv6m` cfg
/// is emitted by `build.rs` from the resolved target, because Rust has no
/// built-in cfg for the M-profile variant.
#[cfg(armv6m)]
const NVIC_REGISTERS: u16 = 1;
#[cfg(not(armv6m))]
const NVIC_REGISTERS: u16 = 16;

/// Unmask one external interrupt. Returns `false` if `irq` is outside the
/// NVIC window, having written nothing.
#[inline]
pub fn nvic_unmask(irq: u16) -> bool {
    let Some((reg, bit)) = nvic::slot(irq, NVIC_REGISTERS) else {
        return false;
    };
    // SAFETY: `reg` is bounded by NVIC_REGISTERS, so the address is inside
    // the architected NVIC block. ISER is write-1-to-set: writing a single
    // bit cannot disturb the others.
    unsafe { core::ptr::write_volatile((nvic::NVIC_ISER + reg * 4) as *mut u32, bit) };
    true
}

/// Mask one external interrupt. Returns `false` if `irq` is outside the
/// NVIC window, having written nothing.
///
/// The `dsb`/`isb` pair after the write is architecturally required: without
/// it the mask is not guaranteed to be in force for instructions already in
/// the pipeline, so an interrupt can still arrive after the call returns.
#[inline]
pub fn nvic_mask(irq: u16) -> bool {
    let Some((reg, bit)) = nvic::slot(irq, NVIC_REGISTERS) else {
        return false;
    };
    // SAFETY: as `nvic_unmask`; ICER is write-1-to-clear.
    unsafe { core::ptr::write_volatile((nvic::NVIC_ICER + reg * 4) as *mut u32, bit) };
    dsb();
    isb();
    true
}

// ============================================================================
// Fault status registers
// ============================================================================

/// Configurable/Hard Fault status, where the architecture has them.
///
/// **ARMv6-M has neither.** `CFSR` (0xE000_ED28) and `BFAR` (0xE000_ED38) are
/// reserved SCB space on Cortex-M0+, and ARMv6-M leaves accesses to reserved
/// SCB space UNPREDICTABLE. Reading them from inside a HardFault handler is
/// the worst place to find out: a fault taken during HardFault on ARMv6-M has
/// nowhere to escalate, so the part locks up instead of recording the crash it
/// was invoked to record.
pub mod fault {
    /// Configurable Fault Status Register — which fault, and why.
    #[cfg(not(armv6m))]
    const CFSR: usize = 0xE000_ED28;
    /// Bus Fault Address Register — the address that faulted.
    #[cfg(not(armv6m))]
    const BFAR: usize = 0xE000_ED38;

    /// Read `CFSR`, or 0 where the architecture has no such register.
    ///
    /// Zero rather than an `Option`: the crash record is a fixed array of
    /// words read by a post-boot reporter, and "no fault detail available on
    /// this architecture" is exactly what an all-zero field means there.
    #[inline]
    pub fn status() -> u32 {
        #[cfg(armv6m)]
        {
            0
        }
        #[cfg(not(armv6m))]
        {
            // SAFETY: a defined SCB register on this architecture.
            unsafe { core::ptr::read_volatile(CFSR as *const u32) }
        }
    }

    /// Read `BFAR`, or 0 where the architecture has no such register.
    #[inline]
    pub fn address() -> u32 {
        #[cfg(armv6m)]
        {
            0
        }
        #[cfg(not(armv6m))]
        {
            // SAFETY: a defined SCB register on this architecture.
            unsafe { core::ptr::read_volatile(BFAR as *const u32) }
        }
    }
}

/// Whether a debugger is attached and has enabled halting debug.
///
/// `DHCSR.C_DEBUGEN`, which exists on every Cortex-M including ARMv6-M.
///
/// The distinction matters in a fault handler: resetting is right in the
/// field, because a board that resets keeps working, but it is exactly wrong
/// under a debugger — the crash that was being investigated is gone before it
/// can be examined.
#[inline]
pub fn debugger_attached() -> bool {
    const DHCSR: usize = 0xE000_EDF0;
    const C_DEBUGEN: u32 = 1 << 0;
    // SAFETY: DHCSR is defined on every Cortex-M profile; a read has no
    // side effects (the write side is what needs the debug key).
    unsafe { core::ptr::read_volatile(DHCSR as *const u32) & C_DEBUGEN != 0 }
}

/// Request a system reset via `AIRCR.SYSRESETREQ`.
///
/// Does not return: the reset is asynchronous, so the caller must park.
#[inline]
pub fn system_reset() -> ! {
    const AIRCR: usize = 0xE000_ED0C;
    /// `VECTKEY` (0x05FA) in the top half; a write without it is ignored,
    /// which would leave the caller spinning in the loop below forever.
    const VECTKEY_SYSRESETREQ: u32 = 0x05FA_0004;
    // SAFETY: AIRCR is defined on every Cortex-M profile and the key is
    // included, so the write takes effect.
    unsafe {
        dsb();
        core::ptr::write_volatile(AIRCR as *mut u32, VECTKEY_SYSRESETREQ);
        dsb();
    }
    loop {
        nop();
    }
}
