//! RP 64-bit monotonic time.
//!
//! The RP timer peripheral counts microseconds in a 64-bit counter exposed as
//! two 32-bit registers. Reading them is not atomic, so a naive `hi, lo` pair
//! can straddle a low-word rollover and produce a timestamp that jumps
//! backwards by about 71 minutes — or forwards by the same, depending which
//! half is stale. At 1 MHz the low word wraps every 2^32 µs ≈ 71.6 minutes,
//! so this is not a theoretical concern on a device that stays up.
//!
//! [`assemble`] is the wrap-safe read, kept free of register access so the
//! arithmetic is exercised on a host build — the arithmetic is where the
//! backwards jump lives, and it cannot be tested on the silicon that has it.
//! The arithmetic therefore compiles on every target; only the register
//! reads below are `rp`-gated, so `tests/harness/tests/rp_timer_wrap.rs`
//! can reach them from a host build.
//!
//! # One clock
//!
//! Every `HalOps` time entry and `step_guard`'s alarms read this same
//! counter. Two sources that merely derive from the same peripheral share a
//! rate but agree at no particular instant, which lets a deadline and the
//! guard measuring it disagree about whether it was met.

/// Assemble a 64-bit microsecond count from a high/low/high register triple.
///
/// The caller reads `hi1`, then `lo`, then `hi2`. If the high word did not
/// change across the low read, the pair is coherent and `lo` belongs with
/// `hi1`. If it did change, the low word wrapped during the read, and the
/// coherent pair is `hi2` with a low word re-read after it — signalled here
/// by returning `None` so the caller retries rather than guessing.
///
/// Returning `None` rather than picking a half is deliberate: every
/// "reasonable" reconstruction of a torn read is wrong some of the time, and
/// a monotonic clock that is wrong rarely is worse than one that retries.
#[inline]
pub const fn assemble(hi1: u32, lo: u32, hi2: u32) -> Option<u64> {
    if hi1 == hi2 {
        Some(((hi1 as u64) << 32) | lo as u64)
    } else {
        None
    }
}

/// Microseconds until `deadline_us`, saturating at zero for a deadline that
/// has already passed.
///
/// Saturating rather than wrapping: a missed deadline must arm an alarm for
/// "now", never for 2^64 µs in the future, which is how a single late step
/// turns into a hang that outlives the observer.
#[inline]
pub const fn until(now_us: u64, deadline_us: u64) -> u64 {
    deadline_us.saturating_sub(now_us)
}

/// The 32-bit alarm value for an absolute 64-bit deadline.
///
/// RP alarms compare against the low 32 bits of the counter only, so an
/// alarm can be armed for at most one low-word period (~71.6 minutes) ahead.
/// A deadline further out than that is clamped to the furthest representable
/// point, and the caller must re-arm when it fires early — which is the
/// wrap-safe re-arm. Returns the alarm value and whether
/// the deadline was truncated.
#[inline]
pub const fn alarm_value(now_us: u64, deadline_us: u64) -> (u32, bool) {
    let delta = until(now_us, deadline_us);
    if delta > u32::MAX as u64 {
        // Furthest representable: now + u32::MAX, truncated.
        ((now_us as u32).wrapping_add(u32::MAX), true)
    } else {
        ((now_us as u32).wrapping_add(delta as u32), false)
    }
}

/// Read the 64-bit monotonic microsecond counter.
///
/// Retries a high/low/high triple until the high word is stable across the
/// low read. The loop is bounded in practice by the low word's 71.6-minute
/// period: at most one retry can be needed, because a second wrap cannot
/// occur within the few cycles of a re-read.
///
/// # Which timer, and why it matters
///
/// RP2350 reads TIMER1 and RP2040 reads TIMER — the same instances
/// `step_guard` drives its alarms from. Reading the counter the step guard
/// uses is what makes "the same source" true in practice rather than only in
/// the same units: TIMER0 and TIMER1 are independent counters started at
/// slightly different moments, so a `HalOps` clock on one and a step guard on
/// the other agree on rate and on nothing else.
///
/// Which instance that is comes from `MONOTONIC_BASE`, generated from the
/// silicon TOML. The two chips put their timers at different addresses *and*
/// put INTR/INTE at different offsets inside them (0x3c/0x40 against
/// 0x34/0x38), so reaching them through generated facts is what keeps this
/// from being two copies of the same file.
///
/// `TIMERAWH`/`TIMERAWL` are read-only raw views with no latching side
/// effect, so reading them is sound regardless of which alarms are owned
/// elsewhere.
#[cfg(feature = "rp")]
#[inline]
pub fn now_us() -> u64 {
    use crate::platform::chip::MONOTONIC_BASE;
    use crate::platform::rp_regs::read32;
    let base = MONOTONIC_BASE as usize;
    loop {
        // SAFETY: the generated monotonic-timer base for this silicon; the
        // RAW views are read-only and have no latching side effect.
        let (hi1, lo, hi2) = unsafe {
            (
                read32(base + addr::TIMERAWH),
                read32(base + addr::TIMERAWL),
                read32(base + addr::TIMERAWH),
            )
        };
        if let Some(t) = assemble(hi1, lo, hi2) {
            return t;
        }
    }
}

/// Monotonic milliseconds.
#[cfg(feature = "rp")]
#[inline]
pub fn now_ms() -> u64 {
    now_us() / 1_000
}

// ── Scheduler deadline alarm ─────────────────────────────────────────
//
// The alarm's only job is to make `WFE` return at the deadline; the wake
// reason is decided by re-reading the clock, never by trusting which
// interrupt fired. That keeps the ISR to an acknowledgement and nothing
// more.

/// Arm the scheduler's alarm for an absolute deadline.
///
/// RP alarms compare the low 32 bits only, so a deadline more than one
/// low-word period (~71.6 min) out is clamped by [`alarm_value`] and the
/// alarm fires early. That is harmless and intended: the waiter re-checks
/// the 64-bit clock, finds the deadline unreached, and re-arms. Returns
/// whether the deadline was truncated, for callers that want to know they
/// will be woken early.
#[cfg(feature = "rp")]
pub fn arm_scheduler_alarm(deadline_us: u64) -> bool {
    let idx = crate::platform::chip::TIMER_ALARM_SCHEDULER as usize;
    let (value, truncated) = alarm_value(now_us(), deadline_us);
    // Clear any stale latched interrupt before arming, or the alarm fires
    // immediately on a flag left by the previous deadline.
    alarm::ack(idx as u8);
    alarm::set_target(idx as u8, value);
    alarm::set_enabled(idx as u8, true);
    truncated
}

/// Disarm the scheduler's alarm and clear any pending flag.
///
/// Called on every wake, including an event wake: an alarm left armed from
/// an abandoned deadline fires later against a deadline nobody is waiting
/// for, and each such stray costs a needless exit from idle.
#[cfg(feature = "rp")]
pub fn disarm_scheduler_alarm() {
    let idx = crate::platform::chip::TIMER_ALARM_SCHEDULER;
    alarm::set_enabled(idx, false);
    alarm::ack(idx);
}

/// Acknowledge the scheduler alarm from its ISR.
///
/// Writing `intr` clears the latched flag. Without it the line re-asserts
/// the instant the handler returns and the core spins in the vector rather
/// than making progress.
///
/// # Safety
///
/// Call only from the scheduler alarm's interrupt handler.
#[cfg(feature = "rp")]
pub unsafe fn ack_scheduler_alarm() {
    alarm::ack(crate::platform::chip::TIMER_ALARM_SCHEDULER);
}

// ── Scheduler alarm ISR vector entries ───────────────────────────────
//
// The alarm has to reach the NVIC for `WFE` to wake on it: a pending
// interrupt that is masked at the NVIC does not generate a wake-up event
// unless `SEVONPEND` is set, and relying on that would make the idle path
// depend on a system-control bit nobody else touches. So the line is
// unmasked and handled, and the handler does the least a handler can do —
// acknowledge, and return. The wake reason is decided by the waiter
// re-reading the clock, so nothing here needs to record anything.

/// # Safety
/// ISR vector entry — invoked by the NVIC, never directly. Runs in
/// interrupt context; acknowledges the scheduler alarm and returns.
#[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
#[no_mangle]
pub unsafe extern "C" fn TIMER1_IRQ_2() {
    // SAFETY: this is the scheduler alarm's own handler.
    unsafe { ack_scheduler_alarm() };
}

/// # Safety
/// ISR vector entry — invoked by the NVIC, never directly. Same
/// constraints as the RP2350 variant.
#[cfg(all(feature = "rp", feature = "chip-rp2040"))]
#[no_mangle]
pub unsafe extern "C" fn TIMER_IRQ_1() {
    // SAFETY: this is the scheduler alarm's own handler.
    unsafe { ack_scheduler_alarm() };
}

/// Start TIMER1's tick generator (RP2350 only).
///
/// **On RP2350 every timer instance is fed by its own tick from the TICKS
/// block, and a timer whose tick is not enabled does not count at all.**
/// TIMER1 — the instance this kernel reads for monotonic time and arms its
/// alarms from — must therefore have its tick started explicitly.
///
/// A stopped counter fails quietly in both directions: `now_us()` returns 0
/// forever, and an alarm compared against a counter that never advances never
/// fires. The second is the dangerous one, because an alarm that never fires
/// is indistinguishable from a guard that never trips.
///
/// The tick is one microsecond: `clk_ref / 1 MHz` cycles. RP2040 has no TICKS
/// block — its single TIMER is fed by the watchdog tick — so this is
/// rp235x-only.
#[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
fn start_monotonic_tick() {
    use crate::platform::chip::TICKS_BASE;
    use crate::platform::rp_regs::write32;

    // TICKS register offsets for the TIMER1 tick generator. Per-instance
    // blocks are 0x0c apart: {ctrl, cycles, count}. TIMER1 is instance 1.
    const TIMER1_CTRL: usize = 0x24;
    const TIMER1_CYCLES: usize = 0x28;
    /// `ctrl.enable` is bit 0; bit 1 is a read-only `running` status.
    const TICK_ENABLE: u32 = 1 << 0;

    // clk_ref runs from the crystal undivided after clock init, and the
    // crystal is a board fact. Declared rather than measured: this divider
    // sets the monotonic tick, so a measurement that came back wrong would
    // corrupt every timestamp in the system. `rp_clocks::verify` checks the
    // crystal against this constant at boot and says so if they disagree.
    let cycles = crate::platform::chip::XOSC_HZ / 1_000_000;
    let base = TICKS_BASE as usize;
    // SAFETY: TICKS_BASE is generated from the silicon TOML and the offsets
    // are this block's own; single boot-thread writer, before any consumer.
    // Cycles before enable: the divider is latched when the tick starts.
    unsafe {
        write32(base + TIMER1_CYCLES, cycles);
        write32(base + TIMER1_CTRL, TICK_ENABLE);
    }
}

/// RP2040 feeds its single TIMER from the watchdog tick, which the clock
/// bring-up already enables.
#[cfg(all(feature = "rp", feature = "chip-rp2040"))]
fn start_monotonic_tick() {}

/// Start the monotonic timer and enable the scheduler alarm's NVIC line.
/// Call once at boot, before anything reads the clock or sleeps.
#[cfg(feature = "rp")]
pub fn init_scheduler_alarm() {
    start_monotonic_tick();
    disarm_scheduler_alarm();
    crate::arch::cortex_m::nvic_unmask(crate::platform::chip::TIMER_IRQ_SCHEDULER);
}

/// Address arithmetic for the TIMER block, separated from the register
/// access so it can be checked on a host.
///
/// A wrong alarm or interrupt-register address does not fail — it writes
/// somewhere else in the same peripheral. On this block the neighbour of
/// `INTE` is `INTF`, the force-interrupt register, so an off-by-one there
/// fires the interrupt it was meant to enable. That is not a failure mode
/// worth discovering on hardware when it is four lines of arithmetic.
pub mod addr {
    /// `ALARM0`; the four alarm compare registers are consecutive words.
    pub const ALARM0: usize = 0x10;
    /// Low half of the latched counter.
    pub const TIMELR: usize = 0x0c;
    /// High half of the **raw** counter — no latching side effect, so it is
    /// sound to read regardless of which alarms are owned elsewhere.
    pub const TIMERAWH: usize = 0x24;
    /// Low half of the raw counter.
    pub const TIMERAWL: usize = 0x28;

    /// Address of alarm `idx`'s compare register.
    #[inline]
    pub const fn alarm(base: usize, idx: u8) -> usize {
        base + ALARM0 + (idx as usize) * 4
    }

    /// Bit for alarm `idx` in the INTR/INTE/INTF/INTS registers, which all
    /// share the layout `alarm n => bit n`.
    #[inline]
    pub const fn alarm_bit(idx: u8) -> u32 {
        1u32 << idx
    }
}

/// Alarm control over the typed register layer, shared by every RP alarm
/// owner.
///
/// One implementation for both chips. The instance base, the alarm index and
/// the interrupt-register offsets are all generated facts, so the RP2040 and
/// RP2350 difference lives in target data rather than in a `cfg` around every
/// caller — and the callers stop being two near-identical copies that have to
/// be edited in step.
///
/// The write semantics are the point of using the typed layer here:
///
/// - `INTE` is a plain read/modify/write — one alarm's enable bit changes and
///   the other three keep their state;
/// - `INTR` is **write-one-to-clear** — acknowledging alarm *n* means writing
///   only bit *n*. A read-modify-write would clear whichever of the other
///   three happened to be pending at that instant, losing an interrupt that
///   nothing would ever report.
#[cfg(feature = "rp")]
pub mod alarm {
    use crate::platform::chip::{MONOTONIC_BASE, TIMER_INTE_OFFSET, TIMER_INTR_OFFSET};
    use crate::platform::rp_regs::{clear_w1c, modify32, read32, write32};

    use super::addr;

    #[inline]
    fn base() -> usize {
        MONOTONIC_BASE as usize
    }

    /// Current low word of the counter.
    #[inline]
    pub fn now_lo() -> u32 {
        // SAFETY: generated base plus this block's own offset.
        unsafe { read32(addr::TIMELR + base()) }
    }

    /// Enable or disable one alarm's interrupt, leaving the others alone.
    #[inline]
    pub fn set_enabled(idx: u8, on: bool) {
        let bit = addr::alarm_bit(idx);
        // SAFETY: INTE is a plain RW register; RMW is correct here and only
        // here.
        unsafe {
            modify32(base() + TIMER_INTE_OFFSET as usize, |v| {
                if on {
                    v | bit
                } else {
                    v & !bit
                }
            })
        };
    }

    /// Acknowledge one alarm's pending interrupt.
    #[inline]
    pub fn ack(idx: u8) {
        // SAFETY: INTR is write-one-to-clear — write only this alarm's bit.
        unsafe { clear_w1c(base() + TIMER_INTR_OFFSET as usize, addr::alarm_bit(idx)) };
    }

    /// Arm an alarm at an absolute counter value, without enabling it.
    ///
    /// Separate from [`set_target_from_now`] because the scheduler computes
    /// its deadline against the 64-bit clock and then truncates: adding a
    /// delta here would re-read the counter and drift by however long that
    /// computation took.
    #[inline]
    pub fn set_target(idx: u8, value: u32) {
        // SAFETY: plain RW alarm compare register.
        unsafe { write32(addr::alarm(base(), idx), value) };
    }

    /// Arm an alarm for `delta_us` from now, without enabling it.
    #[inline]
    pub fn set_target_from_now(idx: u8, delta_us: u32) -> u32 {
        let target = now_lo().wrapping_add(delta_us);
        // SAFETY: plain RW alarm compare register.
        unsafe { write32(addr::alarm(base(), idx), target) };
        target
    }
}
