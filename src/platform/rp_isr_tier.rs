// RP-family ISR tier backends — included from rp.rs
//
// RP2350: TIMER1 alarm 1 (periodic Tier 1b).
// RP2040: TIMER alarm 2 (periodic Tier 1b).

use fluxor::kernel::isr_tier;

// ── RP2350 backend ────────────────────────────────────────────────────

#[cfg(not(feature = "chip-rp2040"))]
mod rp2350_isr {
    use super::*;
    use embassy_rp::pac;

    fn timer1() -> pac::timer::Timer { pac::TIMER1 }

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
        unsafe { isr_tier::isr_tier1b_handler(); }
    }
}

// ── RP2040 backend ────────────────────────────────────────────────────

#[cfg(feature = "chip-rp2040")]
mod rp2040_isr {
    use super::*;
    use embassy_rp::pac;

    fn timer() -> pac::timer::Timer { pac::TIMER }

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
        unsafe { isr_tier::isr_tier1b_handler(); }
    }
}

// ── Public wrappers ───────────────────────────────────────────────────

fn rp_isr_backend_start(period_us: u32) {
    #[cfg(not(feature = "chip-rp2040"))]
    rp2350_isr::start(period_us);
    #[cfg(feature = "chip-rp2040")]
    rp2040_isr::start(period_us);
}

fn rp_isr_backend_stop() {
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
