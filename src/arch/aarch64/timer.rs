//! ARM Generic Timer.
//!
//! Three primitives:
//!   * [`timer_freq`]  — `CNTFRQ_EL0` clock frequency (Hz).
//!   * [`read_timer_count`] — low 32 bits of the counter; the wraparound is
//!     handled by callers using `wrapping_sub`.
//!   * [`timer_set`] — programme the next timer interrupt for `ticks`
//!     counter ticks from now and enable the timer.
//!
//! plus [`timer_set_cval`], which arms an absolute compare value instead.
//!
//! Which counter is the platform's choice ([`configure`]): the physical
//! counter (`CNTPCT_EL0`) on bare metal with no hypervisor, the virtual
//! counter (`CNTVCT_EL0`) under one, where the physical timer traps. The
//! choice is a value set at boot, not a build: `bcm2712.rs` passes the
//! physical counter on the Pi 5 and the virtual one on QEMU `virt`.

use core::sync::atomic::{AtomicBool, Ordering};

/// Which generic-timer counter the machine runs on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Counter {
    /// `CNTPCT_EL0` / `CNTP_*`: direct hardware access, no hypervisor.
    Physical,
    /// `CNTVCT_EL0` / `CNTV_*`: under a hypervisor, where the physical
    /// timer would trap on every access.
    Virtual,
}

static VIRTUAL: AtomicBool = AtomicBool::new(false);

/// Choose the counter. Called once by the platform at boot, before the
/// first timer read.
pub fn configure(counter: Counter) {
    VIRTUAL.store(counter == Counter::Virtual, Ordering::Relaxed);
}

#[inline(always)]
fn virtual_counter() -> bool {
    VIRTUAL.load(Ordering::Relaxed)
}

#[inline(always)]
pub fn timer_freq() -> u64 {
    let freq: u64;
    // SAFETY: `mrs cntfrq_el0` reads a system register; no operands.
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq) };
    freq
}

/// Read the timer counter for cycle-accurate timing (low 32 bits).
#[inline(always)]
pub fn read_timer_count() -> u32 {
    read_timer_count_64() as u32
}

/// Full 64-bit counter read. Needed for the absolute-deadline (`cval`)
/// re-arm path, which compares and programs full counter values rather than
/// the low-32 down-counter.
#[inline(always)]
pub fn read_timer_count_64() -> u64 {
    let val: u64;
    if virtual_counter() {
        // SAFETY: `mrs cntvct_el0` reads the virtual-counter system register.
        unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) val) };
    } else {
        // SAFETY: `mrs cntpct_el0` reads the physical-counter system register.
        unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) val) };
    }
    val
}

/// Programme the next timer interrupt at an ABSOLUTE counter value
/// (`cntp_cval_el0` or `cntv_cval_el0`) and enable the timer.
///
/// Unlike [`timer_set`] (a relative `tval` down-counter re-armed from the
/// moment of the write, so each period also carries the IRQ-entry latency),
/// arming an absolute compare relative to the *previous* programmed deadline
/// keeps the tick grid drift-free. The caller MUST guard against a `cval` already in the past
/// (e.g. after a long ISR) by resyncing to `now + period`, else the timer
/// fires a catch-up burst of immediate IRQs.
///
/// # Safety
/// Writes the timer's compare and control registers; the caller owns the
/// timer on this core.
#[inline(always)]
pub unsafe fn timer_set_cval(cval: u64) {
    if virtual_counter() {
        core::arch::asm!(
            "msr cntv_cval_el0, {val}",
            "mov {ctl}, #1",
            "msr cntv_ctl_el0, {ctl}",
            val = in(reg) cval,
            ctl = out(reg) _,
        );
    } else {
        core::arch::asm!(
            "msr cntp_cval_el0, {val}",
            "mov {ctl}, #1",
            "msr cntp_ctl_el0, {ctl}",
            val = in(reg) cval,
            ctl = out(reg) _,
        );
    }
}

/// Programme the next timer interrupt `ticks` counter ticks from now and
/// enable the timer.
///
/// # Safety
/// As [`timer_set_cval`].
#[inline(always)]
pub unsafe fn timer_set(ticks: u32) {
    if virtual_counter() {
        core::arch::asm!(
            "msr cntv_tval_el0, {val}",
            "mov {ctl}, #1",
            "msr cntv_ctl_el0, {ctl}",
            val = in(reg) ticks as u64,
            ctl = out(reg) _,
        );
    } else {
        core::arch::asm!(
            "msr cntp_tval_el0, {val}",
            "mov {ctl}, #1",
            "msr cntp_ctl_el0, {ctl}",
            val = in(reg) ticks as u64,
            ctl = out(reg) _,
        );
    }
}
