//! RP-family step guard + `timer` ISR hardware backends.
//!
//! Which timer instance, alarm index and IRQ each owner gets is declared in
//! the silicon TOML's `[kernel.timers]` ledger and generated into
//! `chip::TIMER_ALARM_*` / `chip::TIMER_IRQ_*`; `build.rs` rejects any
//! overlap between owners and the timer provider.

use crate::kernel::exec::step_guard;
use crate::platform::rp_step_charge::{self as charge, RefillCredit};
use crate::platform::rp_timer::alarm::Alarms;
use portable_atomic::{AtomicU32, Ordering};

/// Cores with a step guard of their own.
const CORES: usize = 2;

/// Alarm fires each core's step guard dropped because their target was still
/// ahead.
static STRAY: [AtomicU32; CORES] = [const { AtomicU32::new(0) }; CORES];

/// The deadline each core's guard is armed with, in microseconds; 0 while it
/// is not armed.
static ARMED_US: [AtomicU32; CORES] = [const { AtomicU32::new(0) }; CORES];

/// Each core's counter reading when its guard was armed, and the time the
/// kernel has held the core for since: what the armed step is charged is
/// the time between, less the time held.
static ARMED_AT: [AtomicU32; CORES] = [const { AtomicU32::new(0) }; CORES];
static HELD_US: [AtomicU32; CORES] = [const { AtomicU32::new(0) }; CORES];

/// Each core's allowance for refilling the execute-in-place cache after a
/// flash write.
static REFILL: [RefillCredit; CORES] = [const { RefillCredit::new() }; CORES];

/// The execute-in-place cache was emptied (a sector erase, a page program):
/// each core may run over its step deadlines by one refill of the cache.
/// Called on core 0, with the other core parked, before interrupts return;
/// the calling core's armed step takes its share up at once.
pub fn xip_cache_flushed() {
    for credit in REFILL.iter() {
        credit.grant(charge::XIP_REFILL_US);
    }
    guard::take_up_credit();
}

/// The calling core reached a pass boundary: an unspent refill allowance
/// that has seen its passes lapses.
pub fn pass_ended() {
    REFILL[this_core()].pass_ended();
}

/// The calling core left a park: its armed step takes up any refill
/// allowance granted while it was parked. Called with interrupts masked.
pub fn park_ended() {
    guard::take_up_credit();
}

/// Times each core's module-timer handler has run.
static TIMER_RUNS: [AtomicU32; CORES] = [const { AtomicU32::new(0) }; CORES];

/// Times `core`'s module-timer handler has run since boot.
pub fn module_timer_runs(core: usize) -> u32 {
    TIMER_RUNS
        .get(core)
        .map_or(0, |r| r.load(Ordering::Relaxed))
}

/// How many of core 0's step-guard alarm fires were dropped as not due.
pub fn stray_count() -> u32 {
    STRAY[0].load(Ordering::Relaxed)
}

/// How many of `core`'s step-guard alarm fires were dropped as not due.
pub fn stray_count_on(core: usize) -> u32 {
    STRAY.get(core).map_or(0, |s| s.load(Ordering::Relaxed))
}

/// The deadline `core`'s guard is armed with, in microseconds; `None` while
/// no step of that core is under its guard.
pub fn armed_deadline_us(core: usize) -> Option<u32> {
    match ARMED_US.get(core).map(|a| a.load(Ordering::Acquire)) {
        Some(0) | None => None,
        Some(us) => Some(us),
    }
}

/// One core's alarm: the instance it is on, its index there, and the NVIC
/// line it raises.
#[derive(Clone, Copy)]
struct Alarm {
    timer: Alarms,
    idx: u8,
    irq: u16,
}

impl Alarm {
    fn disable(self) {
        self.timer.set_enabled(self.idx, false);
        self.timer.ack(self.idx);
    }
}

/// The calling core's number: 0, or 1 where core 1 runs a domain.
#[inline]
fn this_core() -> usize {
    #[cfg(feature = "smp")]
    return crate::platform::chip::core_id();
    #[cfg(not(feature = "smp"))]
    0
}

// ── Step-guard backend (one implementation, both chips, both cores) ───
//
// The chips and the cores differ only in timer instance, alarm index and
// line, and all are generated facts. One copy and no `cfg` in the logic, so
// the copies cannot drift apart while appearing to agree. Each core arms,
// disarms and defers its own guard, against its own instance's counter.

mod guard {
    use super::*;

    /// The calling core's step-guard alarm.
    #[inline]
    fn mine() -> Alarm {
        #[cfg(feature = "smp")]
        if this_core() != 0 {
            return Alarm {
                timer: crate::platform::rp_timer::alarm::SECONDARY,
                idx: crate::platform::chip::SECONDARY_TIMER_ALARM_STEP_GUARD,
                irq: crate::platform::chip::SECONDARY_TIMER_IRQ_STEP_GUARD,
            };
        }
        Alarm {
            timer: crate::platform::rp_timer::alarm::MONOTONIC,
            idx: crate::platform::chip::TIMER_ALARM_STEP_GUARD,
            irq: crate::platform::chip::TIMER_IRQ_STEP_GUARD,
        }
    }

    /// Quiet the calling core's alarm and enable its line in the calling
    /// core's NVIC.
    pub fn init() {
        let a = mine();
        a.disable();
        crate::arch::cortex_m::nvic_unmask(a.irq);
    }

    pub fn arm(deadline_us: u32) {
        let a = mine();
        // Quiesce first: an alarm still live from the previous step could
        // otherwise fire between the flag being cleared and the new target
        // being written, and be read as this step's timeout.
        a.disable();
        step_guard::clear_timed_out();
        step_guard::set_armed(true);
        let core = this_core();
        ARMED_US[core].store(deadline_us.max(1), Ordering::Release);
        ARMED_AT[core].store(a.timer.now_raw_lo(), Ordering::Relaxed);
        HELD_US[core].store(0, Ordering::Relaxed);
        // A cache emptied by a flash write is refilled on the time of the
        // steps that follow: the deadline carries what is left of that.
        let allowed = deadline_us.saturating_add(REFILL[core].at_arm());
        a.timer.set_target_from_now(a.idx, allowed);
        a.timer.set_enabled(a.idx, true);
    }

    pub fn disarm() {
        if !step_guard::is_armed() {
            return;
        }
        let a = mine();
        a.disable();
        let core = this_core();
        let deadline_us = ARMED_US[core].load(Ordering::Acquire);
        if deadline_us != 0 {
            // What the step ran over its own deadline is spent from the
            // refill allowance.
            REFILL[core].step_ended(
                deadline_us,
                charge::charged_us(
                    ARMED_AT[core].load(Ordering::Relaxed),
                    a.timer.now_raw_lo(),
                    HELD_US[core].load(Ordering::Relaxed),
                ),
            );
        }
        ARMED_US[core].store(0, Ordering::Release);
        step_guard::set_armed(false);
    }

    /// Move the live deadline `us` later without taking the time out of the
    /// step: the alarm withdrawn at the timer and at the NVIC, then set
    /// again. Called with interrupts disabled, the guard armed.
    fn move_target(us: u32) {
        let a = mine();
        a.disable();
        crate::arch::cortex_m::nvic_unpend(a.irq);
        let target = charge::deferred_target(a.timer.target(a.idx), us, a.timer.now_raw_lo());
        a.timer.set_target(a.idx, target);
        a.timer.set_enabled(a.idx, true);
    }

    /// Give the armed step the refill allowance granted since it was armed
    /// or last took one up. Called with interrupts disabled.
    pub fn take_up_credit() {
        if !step_guard::is_armed() {
            return;
        }
        let granted = REFILL[this_core()].newly_granted();
        if granted != 0 {
            move_target(granted);
        }
    }

    /// Move a live deadline `us` later, for time the kernel held the core:
    /// a flash erase with XIP detached for tens of milliseconds, a park for
    /// the other core's. That time is not the module's code running away:
    /// an alarm that came due meanwhile is withdrawn, so it is not taken as
    /// a timeout once interrupts are back, and the scheduler leaves the
    /// time out of what it records for the step. Called with interrupts
    /// disabled.
    pub fn defer(us: u32) {
        if !step_guard::is_armed() {
            return;
        }
        let held = &HELD_US[this_core()];
        held.store(
            held.load(Ordering::Relaxed).saturating_add(us),
            Ordering::Relaxed,
        );
        step_guard::exclude(us);
        move_target(us);
    }

    pub fn on_timer_irq() {
        let a = mine();
        a.timer.ack(a.idx);
        a.timer.set_enabled(a.idx, false);
        ARMED_US[this_core()].store(0, Ordering::Release);
        // The deadline has passed only if the counter has reached the
        // target this arm wrote. A fire that reports a target still ahead
        // belongs to no step; it is counted and dropped.
        if a.timer.now_raw_lo().wrapping_sub(a.timer.target(a.idx)) > i32::MAX as u32 {
            STRAY[this_core()].fetch_add(1, Ordering::Relaxed);
            step_guard::set_armed(false);
            return;
        }
        // A step that reached its alarm has used the whole of any refill
        // allowance its deadline carried.
        REFILL[this_core()].step_ended(0, u32::MAX);
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

/// # Safety
/// ISR vector entry — invoked by the NVIC, never directly. Core 1's step
/// guard: the line is enabled in core 1's NVIC alone.
#[cfg(feature = "smp")]
#[no_mangle]
pub unsafe extern "C" fn TIMER0_IRQ_1() {
    crate::platform::rp_core1::count_interrupt();
    guard::on_timer_irq();
}

use crate::kernel::exec::timer;

// ── `timer` cadence backend (one implementation, both chips) ─────────

mod module_timer {
    use super::*;

    /// The calling core's module-timer alarm.
    #[inline]
    fn mine() -> Alarm {
        #[cfg(feature = "smp")]
        if this_core() != 0 {
            return Alarm {
                timer: crate::platform::rp_timer::alarm::SECONDARY,
                idx: crate::platform::chip::SECONDARY_TIMER_ALARM_MODULE_TIMER,
                irq: crate::platform::chip::SECONDARY_TIMER_IRQ_MODULE_TIMER,
            };
        }
        Alarm {
            timer: crate::platform::rp_timer::alarm::MONOTONIC,
            idx: crate::platform::chip::TIMER_ALARM_MODULE_TIMER,
            irq: crate::platform::chip::TIMER_IRQ_MODULE_TIMER,
        }
    }

    /// Start the module timer. Core 0 arms its own alarm at its own period;
    /// a core that runs a `timer` domain of its own arms its alarm itself
    /// ([`arm_this_core`]), since only it can enable the line.
    pub fn start(period_us: u32) {
        timer::set_period_us(period_us);
        timer::TIMER_ACTIVE.store(true, portable_atomic::Ordering::Release);
        arm_this_core();
    }

    /// Arm the calling core's alarm at its own period, when the module timer
    /// runs and the core has a period. Idempotent.
    pub fn arm_this_core() {
        let a = mine();
        let period = timer::core_period_us(this_core());
        if period == 0 || !timer::TIMER_ACTIVE.load(portable_atomic::Ordering::Acquire) {
            a.disable();
            return;
        }
        if a.timer.is_enabled(a.idx) {
            return;
        }
        a.timer.ack(a.idx);
        a.timer.set_target_from_now(a.idx, period);
        a.timer.set_enabled(a.idx, true);
        crate::arch::cortex_m::nvic_unmask(a.irq);
    }

    /// Stop the module timer on every core: the alarm enables are plain
    /// registers either core may clear.
    pub fn stop() {
        timer::TIMER_ACTIVE.store(false, portable_atomic::Ordering::Release);
        let a = Alarm {
            timer: crate::platform::rp_timer::alarm::MONOTONIC,
            idx: crate::platform::chip::TIMER_ALARM_MODULE_TIMER,
            irq: crate::platform::chip::TIMER_IRQ_MODULE_TIMER,
        };
        a.disable();
        #[cfg(feature = "smp")]
        Alarm {
            timer: crate::platform::rp_timer::alarm::SECONDARY,
            idx: crate::platform::chip::SECONDARY_TIMER_ALARM_MODULE_TIMER,
            irq: crate::platform::chip::SECONDARY_TIMER_IRQ_MODULE_TIMER,
        }
        .disable();
    }

    pub fn on_timer_irq() {
        let a = mine();
        // Acknowledge first: the cadence re-arms below, and a late ack would
        // clear the flag the re-armed alarm has just set.
        a.timer.ack(a.idx);
        let core = this_core();
        let period = timer::core_period_us(core);
        if period > 0 && timer::TIMER_ACTIVE.load(portable_atomic::Ordering::Acquire) {
            a.timer.set_target_from_now(a.idx, period);
        } else {
            a.timer.set_enabled(a.idx, false);
            return;
        }
        TIMER_RUNS[core].fetch_add(1, Ordering::Relaxed);
        // SAFETY: invoked from the `timer` alarm ISR on `core`;
        // `timer::handler_on` documents itself as ISR-callable.
        unsafe {
            timer::handler_on(core as u8);
        }
    }
}

/// Arm the calling core's module-timer alarm if the module timer runs and
/// the core has a period (see `module_timer::arm_this_core`).
pub fn rp_module_timer_arm_this_core() {
    module_timer::arm_this_core();
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

/// # Safety
/// ISR vector entry — invoked by the NVIC, never directly. Core 1's module
/// timer: the line is enabled in core 1's NVIC alone.
#[cfg(feature = "smp")]
#[no_mangle]
pub unsafe extern "C" fn TIMER0_IRQ_3() {
    crate::platform::rp_core1::count_interrupt();
    module_timer::on_timer_irq();
}
