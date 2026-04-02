// RP-family step guard backends — included from rp.rs
//
// RP2350: TIMER1 alarm 0 (Embassy uses TIMER0).
// RP2040: TIMER alarm 3 (Embassy uses alarms 0-2).

use fluxor::kernel::step_guard;

// ── RP2350 backend ────────────────────────────────────────────────────

#[cfg(not(feature = "chip-rp2040"))]
mod rp2350_guard {
    use super::*;
    use embassy_rp::pac;

    fn timer1() -> pac::timer::Timer { pac::TIMER1 }

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
        if !step_guard::is_armed() { return; }
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

    fn timer() -> pac::timer::Timer { pac::TIMER }

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
        if !step_guard::is_armed() { return; }
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
