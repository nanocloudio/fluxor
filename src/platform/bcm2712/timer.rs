//! ARM Generic Timer — Pi 5 (physical) and QEMU virt (virtual).
//!
//! Three primitives:
//!   * [`timer_freq`]  — `CNTFRQ_EL0` clock frequency (Hz).
//!   * [`read_timer_count`] — low 32 bits of `CNTPCT_EL0` (cm5) or
//!     `CNTVCT_EL0` (QEMU); the wraparound is handled by callers
//!     using `wrapping_sub`.
//!   * [`timer_set`] — programme the next timer interrupt for
//!     `ticks` counter ticks from now and enable the counter.
//!
//! Pi 5: physical counter (CNTPCT_EL0) — direct hardware access.
//! QEMU: virtual counter (CNTVCT_EL0) — no KVM trap overhead.

#[inline(always)]
pub fn timer_freq() -> u64 {
    let freq: u64;
    // SAFETY: `mrs cntfrq_el0` reads a system register; no operands.
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq) };
    freq
}

/// Read the timer counter for cycle-accurate timing.
/// Pi 5: physical counter (CNTPCT_EL0) — direct hardware access.
/// QEMU: virtual counter (CNTVCT_EL0) — no KVM trap overhead.
#[inline(always)]
pub fn read_timer_count() -> u32 {
    let val: u64;
    #[cfg(feature = "board-cm5")]
    // SAFETY: `mrs cntpct_el0` reads the physical-counter system register.
    unsafe {
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) val)
    };
    #[cfg(not(feature = "board-cm5"))]
    // SAFETY: `mrs cntvct_el0` reads the virtual-counter system register.
    unsafe {
        core::arch::asm!("mrs {}, cntvct_el0", out(reg) val)
    };
    val as u32
}

#[inline(always)]
pub unsafe fn timer_set(ticks: u32) {
    #[cfg(feature = "board-cm5")]
    core::arch::asm!(
        "msr cntp_tval_el0, {val}",
        "mov {ctl}, #1",
        "msr cntp_ctl_el0, {ctl}",
        val = in(reg) ticks as u64,
        ctl = out(reg) _,
    );
    #[cfg(not(feature = "board-cm5"))]
    core::arch::asm!(
        "msr cntv_tval_el0, {val}",
        "mov {ctl}, #1",
        "msr cntv_ctl_el0, {ctl}",
        val = in(reg) ticks as u64,
        ctl = out(reg) _,
    );
}
