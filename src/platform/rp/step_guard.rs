//! RP-family step guard + Tier-1b ISR hardware backends.
//!
//! step_guard: RP2350 uses TIMER1 alarm 0, RP2040 uses TIMER alarm 3
//!             (Embassy reserves TIMER0 / alarms 0-2 respectively).
//! isr_tier:   RP2350 uses TIMER1 alarm 1, RP2040 uses TIMER alarm 2.

use crate::kernel::step_guard;

// ── RP2350 backend ────────────────────────────────────────────────────

#[cfg(not(feature = "chip-rp2040"))]
mod rp2350_guard {
    use super::*;
    use embassy_rp::pac;

    fn timer1() -> pac::timer::Timer {
        pac::TIMER1
    }

    pub fn init() {
        let t = timer1();
        t.inte().modify(|w| w.set_alarm(0, false));
        t.intr().write(|w| w.set_alarm(0, true));
        unsafe {
            let nvic = &*cortex_m::peripheral::NVIC::PTR;
            const TIMER1_IRQ_0: u16 = 4;
            nvic.iser[0].write(1 << TIMER1_IRQ_0);
        }
    }

    pub fn arm(deadline_us: u32) {
        step_guard::clear_timed_out();
        step_guard::set_armed(true);
        let t = timer1();
        let now_lo = t.timelr().read();
        let target = now_lo.wrapping_add(deadline_us);
        t.intr().write(|w| w.set_alarm(0, true));
        t.alarm(0).write_value(target);
        t.inte().modify(|w| w.set_alarm(0, true));
    }

    pub fn disarm() {
        if !step_guard::is_armed() {
            return;
        }
        let t = timer1();
        t.inte().modify(|w| w.set_alarm(0, false));
        t.intr().write(|w| w.set_alarm(0, true));
        step_guard::set_armed(false);
    }

    pub fn on_timer_irq() {
        let t = timer1();
        t.intr().write(|w| w.set_alarm(0, true));
        t.inte().modify(|w| w.set_alarm(0, false));
        step_guard::set_timed_out();
        step_guard::set_armed(false);
    }
}

// ── RP2040 backend ────────────────────────────────────────────────────

#[cfg(feature = "chip-rp2040")]
mod rp2040_guard {
    use super::*;
    use embassy_rp::pac;

    fn timer() -> pac::timer::Timer {
        pac::TIMER
    }

    pub fn init() {
        let t = timer();
        t.inte().modify(|w| w.set_alarm(3, false));
        t.intr().write(|w| w.set_alarm(3, true));
        unsafe {
            let nvic = &*cortex_m::peripheral::NVIC::PTR;
            const TIMER_IRQ_3: u16 = 3;
            nvic.iser[0].write(1 << TIMER_IRQ_3);
        }
    }

    pub fn arm(deadline_us: u32) {
        step_guard::clear_timed_out();
        step_guard::set_armed(true);
        let t = timer();
        let now_lo = t.timelr().read();
        let target = now_lo.wrapping_add(deadline_us);
        t.intr().write(|w| w.set_alarm(3, true));
        t.alarm(3).write_value(target);
        t.inte().modify(|w| w.set_alarm(3, true));
    }

    pub fn disarm() {
        if !step_guard::is_armed() {
            return;
        }
        let t = timer();
        t.inte().modify(|w| w.set_alarm(3, false));
        t.intr().write(|w| w.set_alarm(3, true));
        step_guard::set_armed(false);
    }

    pub fn on_timer_irq() {
        let t = timer();
        t.intr().write(|w| w.set_alarm(3, true));
        t.inte().modify(|w| w.set_alarm(3, false));
        step_guard::set_timed_out();
        step_guard::set_armed(false);
    }
}

// ── Public wrappers ───────────────────────────────────────────────────

pub fn rp_step_guard_init() {
    #[cfg(not(feature = "chip-rp2040"))]
    rp2350_guard::init();
    #[cfg(feature = "chip-rp2040")]
    rp2040_guard::init();
}

pub fn rp_step_guard_arm(deadline_us: u32) {
    #[cfg(not(feature = "chip-rp2040"))]
    rp2350_guard::arm(deadline_us);
    #[cfg(feature = "chip-rp2040")]
    rp2040_guard::arm(deadline_us);
}

pub fn rp_step_guard_disarm() {
    #[cfg(not(feature = "chip-rp2040"))]
    rp2350_guard::disarm();
    #[cfg(feature = "chip-rp2040")]
    rp2040_guard::disarm();
}

// ── ISR vector entry points ───────────────────────────────────────────

#[cfg(not(feature = "chip-rp2040"))]
#[no_mangle]
pub unsafe extern "C" fn TIMER1_IRQ_0() {
    rp2350_guard::on_timer_irq();
}

#[cfg(feature = "chip-rp2040")]
#[no_mangle]
pub unsafe extern "C" fn TIMER_IRQ_3() {
    rp2040_guard::on_timer_irq();
}

use crate::kernel::isr_tier;

// ── RP2350 backend ────────────────────────────────────────────────────

#[cfg(not(feature = "chip-rp2040"))]
mod rp2350_isr {
    use super::*;
    use embassy_rp::pac;

    fn timer1() -> pac::timer::Timer {
        pac::TIMER1
    }

    pub fn start(period_us: u32) {
        isr_tier::set_tier1b_period_us(period_us);
        let t = timer1();
        t.inte().modify(|w| w.set_alarm(1, false));
        t.intr().write(|w| w.set_alarm(1, true));
        let now_lo = t.timelr().read();
        let target = now_lo.wrapping_add(period_us);
        t.alarm(1).write_value(target);
        t.inte().modify(|w| w.set_alarm(1, true));
        unsafe {
            let nvic = &*cortex_m::peripheral::NVIC::PTR;
            const TIMER1_IRQ_1: u16 = 5;
            nvic.iser[0].write(1 << TIMER1_IRQ_1);
        }
        isr_tier::TIER1B_ACTIVE.store(true, portable_atomic::Ordering::Release);
    }

    pub fn stop() {
        let t = timer1();
        t.inte().modify(|w| w.set_alarm(1, false));
        t.intr().write(|w| w.set_alarm(1, true));
        isr_tier::TIER1B_ACTIVE.store(false, portable_atomic::Ordering::Release);
    }

    pub fn on_timer_irq() {
        let t = timer1();
        t.intr().write(|w| w.set_alarm(1, true));
        let period = isr_tier::tier1b_period_us();
        if period > 0 && isr_tier::TIER1B_ACTIVE.load(portable_atomic::Ordering::Acquire) {
            let now_lo = t.timelr().read();
            let target = now_lo.wrapping_add(period);
            t.alarm(1).write_value(target);
        } else {
            t.inte().modify(|w| w.set_alarm(1, false));
            return;
        }
        unsafe {
            isr_tier::isr_tier1b_handler();
        }
    }
}

// ── RP2040 backend ────────────────────────────────────────────────────

#[cfg(feature = "chip-rp2040")]
mod rp2040_isr {
    use super::*;
    use embassy_rp::pac;

    fn timer() -> pac::timer::Timer {
        pac::TIMER
    }

    pub fn start(period_us: u32) {
        isr_tier::set_tier1b_period_us(period_us);
        let t = timer();
        t.inte().modify(|w| w.set_alarm(2, false));
        t.intr().write(|w| w.set_alarm(2, true));
        let now_lo = t.timelr().read();
        let target = now_lo.wrapping_add(period_us);
        t.alarm(2).write_value(target);
        t.inte().modify(|w| w.set_alarm(2, true));
        unsafe {
            let nvic = &*cortex_m::peripheral::NVIC::PTR;
            const TIMER_IRQ_2: u16 = 2;
            nvic.iser[0].write(1 << TIMER_IRQ_2);
        }
        isr_tier::TIER1B_ACTIVE.store(true, portable_atomic::Ordering::Release);
    }

    pub fn stop() {
        let t = timer();
        t.inte().modify(|w| w.set_alarm(2, false));
        t.intr().write(|w| w.set_alarm(2, true));
        isr_tier::TIER1B_ACTIVE.store(false, portable_atomic::Ordering::Release);
    }

    pub fn on_timer_irq() {
        let t = timer();
        t.intr().write(|w| w.set_alarm(2, true));
        let period = isr_tier::tier1b_period_us();
        if period > 0 && isr_tier::TIER1B_ACTIVE.load(portable_atomic::Ordering::Acquire) {
            let now_lo = t.timelr().read();
            let target = now_lo.wrapping_add(period);
            t.alarm(2).write_value(target);
        } else {
            t.inte().modify(|w| w.set_alarm(2, false));
            return;
        }
        unsafe {
            isr_tier::isr_tier1b_handler();
        }
    }
}

// ── Public wrappers ───────────────────────────────────────────────────

pub fn rp_isr_backend_start(period_us: u32) {
    #[cfg(not(feature = "chip-rp2040"))]
    rp2350_isr::start(period_us);
    #[cfg(feature = "chip-rp2040")]
    rp2040_isr::start(period_us);
}

pub fn rp_isr_backend_stop() {
    #[cfg(not(feature = "chip-rp2040"))]
    rp2350_isr::stop();
    #[cfg(feature = "chip-rp2040")]
    rp2040_isr::stop();
}

// ── ISR vector entry points ───────────────────────────────────────────

#[cfg(not(feature = "chip-rp2040"))]
#[no_mangle]
pub unsafe extern "C" fn TIMER1_IRQ_1() {
    rp2350_isr::on_timer_irq();
}

#[cfg(feature = "chip-rp2040")]
#[no_mangle]
pub unsafe extern "C" fn TIMER_IRQ_2() {
    rp2040_isr::on_timer_irq();
}
