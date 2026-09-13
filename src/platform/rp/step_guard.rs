//! RP-family step guard + Tier-1b ISR hardware backends.
//!
//! Which timer instance, alarm index and IRQ each owner gets is declared in
//! the silicon TOML's `[kernel.timers]` ledger and generated into
//! `chip::TIMER_ALARM_*` / `chip::TIMER_IRQ_*`; `build.rs` rejects any
//! overlap between owners and the timer provider.

use crate::kernel::exec::step_guard;

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
        step_guard::clear_timed_out();
        step_guard::set_armed(true);
        alarm::ack(IDX);
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

    pub fn on_timer_irq() {
        alarm::ack(IDX);
        alarm::set_enabled(IDX, false);
        step_guard::set_timed_out();
        step_guard::set_armed(false);
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

use crate::kernel::exec::isr_tier;

// ── RP2350 backend ────────────────────────────────────────────────────

// ── Tier-1b cadence backend (one implementation, both chips) ─────────

mod tier1b {
    use super::*;
    use crate::platform::chip::TIMER_ALARM_TIER1B as IDX;
    use crate::platform::rp_timer::alarm;

    pub fn start(period_us: u32) {
        isr_tier::set_tier1b_period_us(period_us);
        alarm::set_enabled(IDX, false);
        alarm::ack(IDX);
        alarm::set_target_from_now(IDX, period_us);
        alarm::set_enabled(IDX, true);
        crate::arch::cortex_m::nvic_unmask(crate::platform::chip::TIMER_IRQ_TIER1B);
        isr_tier::TIER1B_ACTIVE.store(true, portable_atomic::Ordering::Release);
    }

    pub fn stop() {
        alarm::set_enabled(IDX, false);
        alarm::ack(IDX);
        isr_tier::TIER1B_ACTIVE.store(false, portable_atomic::Ordering::Release);
    }

    pub fn on_timer_irq() {
        // Acknowledge first: the cadence re-arms below, and a late ack would
        // clear the flag the re-armed alarm has just set.
        alarm::ack(IDX);
        let period = isr_tier::tier1b_period_us();
        if period > 0 && isr_tier::TIER1B_ACTIVE.load(portable_atomic::Ordering::Acquire) {
            alarm::set_target_from_now(IDX, period);
        } else {
            alarm::set_enabled(IDX, false);
            return;
        }
        // SAFETY: invoked from the Tier-1b alarm ISR; `isr_tier1b_handler`
        // documents itself as ISR-callable.
        unsafe {
            isr_tier::isr_tier1b_handler();
        }
    }
}

pub fn rp_isr_backend_start(period_us: u32) {
    tier1b::start(period_us);
}

pub fn rp_isr_backend_stop() {
    tier1b::stop();
}

// ── ISR vector entry points ───────────────────────────────────────────

/// # Safety
/// ISR vector entry — invoked by the NVIC, never directly. Drives
/// the Tier-1B periodic ISR backend; must not block or touch
/// non-ISR-safe state.
#[cfg(not(feature = "chip-rp2040"))]
#[no_mangle]
pub unsafe extern "C" fn TIMER1_IRQ_1() {
    tier1b::on_timer_irq();
}

/// # Safety
/// ISR vector entry — invoked by the NVIC, never directly. RP2040
/// counterpart of `TIMER1_IRQ_1`; same ISR-context constraints.
#[cfg(feature = "chip-rp2040")]
#[no_mangle]
pub unsafe extern "C" fn TIMER_IRQ_2() {
    tier1b::on_timer_irq();
}
