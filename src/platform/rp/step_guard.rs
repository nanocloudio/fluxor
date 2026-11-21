//! RP-family step guard + `timer` ISR hardware backends.
//!
//! Which timer instance, alarm index and IRQ each owner gets is declared in
//! the silicon TOML's `[kernel.timers]` ledger and generated into
//! `chip::TIMER_ALARM_*` / `chip::TIMER_IRQ_*`; `build.rs` rejects any
//! overlap between owners and the timer provider.

use crate::kernel::exec::step_guard;
use portable_atomic::{AtomicU32, Ordering};

/// Alarm fires the step guard dropped because their target was still ahead.
static STRAY: AtomicU32 = AtomicU32::new(0);

/// How many step-guard alarm fires were dropped as not due.
pub fn stray_count() -> u32 {
    STRAY.load(Ordering::Relaxed)
}

// ── Step-guard backend (one implementation, both chips) ───────────────
//
// The chips differ only in timer instance and alarm index, and both are
// generated facts (`chip::MONOTONIC_BASE`, `chip::TIMER_ALARM_STEP_GUARD`).
// One copy and no `cfg`, so the two cannot drift apart while appearing to
// agree.

mod guard {
    use super::*;
    use crate::platform::chip::TIMER_ALARM_STEP_GUARD as IDX;
    use crate::platform::rp_timer::alarm;

    pub fn init() {
        alarm::set_enabled(IDX, false);
        alarm::ack(IDX);
        crate::arch::cortex_m::nvic_unmask(crate::platform::chip::TIMER_IRQ_STEP_GUARD);
    }

    pub fn arm(deadline_us: u32) {
        // Quiesce first: an alarm still live from the previous step could
        // otherwise fire between the flag being cleared and the new target
        // being written, and be read as this step's timeout.
        alarm::set_enabled(IDX, false);
        alarm::ack(IDX);
        step_guard::clear_timed_out();
        step_guard::set_armed(true);
        alarm::set_target_from_now(IDX, deadline_us);
        alarm::set_enabled(IDX, true);
    }

    pub fn disarm() {
        if !step_guard::is_armed() {
            return;
        }
        alarm::set_enabled(IDX, false);
        alarm::ack(IDX);
        step_guard::set_armed(false);
    }

    /// Move a live deadline `us` later. For time the kernel spent with
    /// interrupts off on the stepping module's behalf -- a flash erase holds
    /// XIP detached for tens of milliseconds -- which is not the module's
    /// code running away. An alarm that came due meanwhile is withdrawn,
    /// both at the timer and at the NVIC, so it is not taken as a timeout
    /// once interrupts are back. Called with interrupts disabled.
    pub fn defer(us: u32) {
        if !step_guard::is_armed() {
            return;
        }
        alarm::set_enabled(IDX, false);
        alarm::ack(IDX);
        crate::arch::cortex_m::nvic_unpend(crate::platform::chip::TIMER_IRQ_STEP_GUARD);
        let target = alarm::target(IDX).wrapping_add(us);
        // A target the counter has already passed would never fire: the
        // remaining budget is at least a microsecond.
        let now = alarm::now_raw_lo();
        let target = if target.wrapping_sub(now) > i32::MAX as u32 {
            now.wrapping_add(1)
        } else {
            target
        };
        alarm::set_target(IDX, target);
        alarm::set_enabled(IDX, true);
    }

    pub fn on_timer_irq() {
        alarm::ack(IDX);
        alarm::set_enabled(IDX, false);
        // The deadline has passed only if the counter has reached the
        // target this arm wrote. A fire that reports a target still ahead
        // belongs to no step; it is counted and dropped.
        if alarm::now_raw_lo().wrapping_sub(alarm::target(IDX)) > i32::MAX as u32 {
            STRAY.fetch_add(1, Ordering::Relaxed);
            step_guard::set_armed(false);
            return;
        }
        step_guard::set_timed_out();
        step_guard::set_armed(false);
        // A gated module can be forced out: unprivileged, it holds no kernel
        // lock the kernel could need back.
        #[cfg(feature = "kernel-mpu")]
        if crate::platform::rp_protection::gated_active() {
            crate::platform::rp_protection::force_out();
        }
    }
}

pub fn rp_step_guard_init() {
    guard::init();
}

pub fn rp_step_guard_arm(deadline_us: u32) {
    guard::arm(deadline_us);
}

pub fn rp_step_guard_disarm() {
    guard::disarm();
}

/// Move the live step deadline `us` later; see `guard::defer`.
pub fn rp_step_guard_defer(us: u32) {
    guard::defer(us);
}

// ── ISR vector entry points ───────────────────────────────────────────

/// # Safety
/// ISR vector entry — invoked by the NVIC, never directly. Runs in
/// interrupt context with interrupts disabled at this priority; must
/// not block, allocate, or touch non-`#[no_mangle]` cross-module
/// state. Acks the timer interrupt and dispatches the step-guard
/// fault path.
#[cfg(not(feature = "chip-rp2040"))]
#[no_mangle]
pub unsafe extern "C" fn TIMER1_IRQ_0() {
    guard::on_timer_irq();
}

/// # Safety
/// ISR vector entry — invoked by the NVIC, never directly. Same
/// constraints as the RP2350 variant: runs in interrupt context,
/// must not block.
#[cfg(feature = "chip-rp2040")]
#[no_mangle]
pub unsafe extern "C" fn TIMER_IRQ_3() {
    guard::on_timer_irq();
}

use crate::kernel::exec::timer;

// ── RP2350 backend ────────────────────────────────────────────────────

// ── `timer` cadence backend (one implementation, both chips) ─────────

mod module_timer {
    use super::*;
    use crate::platform::chip::TIMER_ALARM_MODULE_TIMER as IDX;
    use crate::platform::rp_timer::alarm;

    pub fn start(period_us: u32) {
        timer::set_period_us(period_us);
        alarm::set_enabled(IDX, false);
        alarm::ack(IDX);
        alarm::set_target_from_now(IDX, period_us);
        alarm::set_enabled(IDX, true);
        crate::arch::cortex_m::nvic_unmask(crate::platform::chip::TIMER_IRQ_MODULE_TIMER);
        timer::TIMER_ACTIVE.store(true, portable_atomic::Ordering::Release);
    }

    pub fn stop() {
        alarm::set_enabled(IDX, false);
        alarm::ack(IDX);
        timer::TIMER_ACTIVE.store(false, portable_atomic::Ordering::Release);
    }

    pub fn on_timer_irq() {
        // Acknowledge first: the cadence re-arms below, and a late ack would
        // clear the flag the re-armed alarm has just set.
        alarm::ack(IDX);
        let period = timer::period_us();
        if period > 0 && timer::TIMER_ACTIVE.load(portable_atomic::Ordering::Acquire) {
            alarm::set_target_from_now(IDX, period);
        } else {
            alarm::set_enabled(IDX, false);
            return;
        }
        // SAFETY: invoked from the `timer` alarm ISR; `timer::handler`
        // documents itself as ISR-callable.
        unsafe {
            timer::handler();
        }
    }
}

pub fn rp_isr_backend_start(period_us: u32) {
    module_timer::start(period_us);
}

pub fn rp_isr_backend_stop() {
    module_timer::stop();
}

// ── ISR vector entry points ───────────────────────────────────────────

/// # Safety
/// ISR vector entry — invoked by the NVIC, never directly. Drives
/// the `timer` periodic ISR backend; must not block or touch
/// non-ISR-safe state.
#[cfg(not(feature = "chip-rp2040"))]
#[no_mangle]
pub unsafe extern "C" fn TIMER1_IRQ_1() {
    module_timer::on_timer_irq();
}

/// # Safety
/// ISR vector entry — invoked by the NVIC, never directly. RP2040
/// counterpart of `TIMER1_IRQ_1`; same ISR-context constraints.
#[cfg(feature = "chip-rp2040")]
#[no_mangle]
pub unsafe extern "C" fn TIMER_IRQ_2() {
    module_timer::on_timer_irq();
}
