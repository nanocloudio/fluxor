//! What a step on an RP core is and is not charged.
//!
//! A step's deadline measures the module's own code. Two things the kernel
//! does on RP stretch a step without being the module's:
//!
//! - **Time with the core held.** Core 0 runs a flash erase, a page program
//!   or the BOOTSEL read with its interrupts masked, and the other core
//!   waits that out parked in RAM. The held time is known exactly, so the
//!   live deadline moves later by it ([`deferred_target`]) and the scheduler
//!   leaves it out of the step's time.
//! - **The cold cache after a flash write.** An erase or a program ends by
//!   emptying the execute-in-place cache both cores fetch through. Code
//!   that was resident is fetched from flash again the first time each core
//!   runs it: the rest of the interrupted step, and the steps of the pass
//!   after it. That cost cannot be measured per step, but it is bounded: a
//!   cache refilled once, line by line ([`XIP_REFILL_US`]). Each flush
//!   grants each core that much [`RefillCredit`]; a step may run over its
//!   deadline by the credit left, what it runs over is spent from it, and
//!   what is not spent lapses when the core has made a whole pass with the
//!   cache warm again.
//!
//! Pure arithmetic and atomics, so a host test drives it.

use core::sync::atomic::{AtomicU32, Ordering};

/// Lines in the execute-in-place cache: 16 kB of 8-byte lines, on both
/// chips.
pub const XIP_CACHE_LINES: u32 = 16 * 1024 / 8;

/// The time one cache line takes to come from flash, in microseconds: an
/// estimate, on the slow side, of a serial read of eight bytes at the clock
/// divider the bootrom leaves the flash interface with.
pub const XIP_LINE_FETCH_US: u32 = 4;

/// The longest the cache takes to refill once: every line fetched again.
pub const XIP_REFILL_US: u32 = XIP_CACHE_LINES * XIP_LINE_FETCH_US;

/// Passes of a core's loop a credit outlives: the one it was granted in,
/// which may be nearly over, and one whole pass after it.
pub const REFILL_PASSES: u32 = 2;

/// The alarm target of a deadline moved `us` later, on a counter that reads
/// `now`. A target the counter has already passed would not fire until the
/// counter wrapped, so the least a moved deadline leaves is one tick.
pub const fn deferred_target(target: u32, us: u32, now: u32) -> u32 {
    let moved = target.wrapping_add(us);
    if moved.wrapping_sub(now) > i32::MAX as u32 {
        now.wrapping_add(1)
    } else {
        moved
    }
}

/// The time a step has been charged: from `armed_at` to `now` on its core's
/// counter, less what the kernel held the core for meanwhile.
pub const fn charged_us(armed_at: u32, now: u32, held_us: u32) -> u32 {
    now.wrapping_sub(armed_at).saturating_sub(held_us)
}

/// One core's allowance for refilling the cache after a flash write.
///
/// The core that flushes grants it (to itself, and to the other core while
/// that one is parked); everything else is the owning core's.
pub struct RefillCredit {
    /// Microseconds of overrun still allowed.
    credit_us: AtomicU32,
    /// How much of the credit the armed step's deadline already includes.
    applied_us: AtomicU32,
    /// Pass boundaries left before the credit lapses.
    passes_left: AtomicU32,
}

impl Default for RefillCredit {
    fn default() -> Self {
        Self::new()
    }
}

impl RefillCredit {
    pub const fn new() -> Self {
        Self {
            credit_us: AtomicU32::new(0),
            applied_us: AtomicU32::new(0),
            passes_left: AtomicU32::new(0),
        }
    }

    /// The cache was emptied: the core may overrun by `us` in all, until it
    /// has made [`REFILL_PASSES`] pass boundaries. A second flush does not
    /// add to what the first left: the cache is no emptier.
    pub fn grant(&self, us: u32) {
        self.credit_us.store(us, Ordering::Release);
        self.passes_left.store(REFILL_PASSES, Ordering::Release);
    }

    /// The credit left.
    pub fn credit_us(&self) -> u32 {
        self.credit_us.load(Ordering::Acquire)
    }

    /// A step is being armed: the credit to add to its deadline.
    pub fn at_arm(&self) -> u32 {
        let credit = self.credit_us();
        self.applied_us.store(credit, Ordering::Relaxed);
        credit
    }

    /// The credit granted since the armed step's deadline last took it up:
    /// what to move the live deadline later by after a flush inside the
    /// step.
    pub fn newly_granted(&self) -> u32 {
        let credit = self.credit_us();
        // Only the owning core arms and takes up: a load and a store.
        let applied = self.applied_us.load(Ordering::Relaxed);
        self.applied_us.store(credit, Ordering::Relaxed);
        credit.saturating_sub(applied)
    }

    /// The armed step ended having been charged `charged_us` against a
    /// deadline of `deadline_us`: what it ran over is spent.
    pub fn step_ended(&self, deadline_us: u32, charged_us: u32) {
        self.applied_us.store(0, Ordering::Relaxed);
        let over = charged_us.saturating_sub(deadline_us);
        if over != 0 {
            let left = self.credit_us().saturating_sub(over);
            self.credit_us.store(left, Ordering::Release);
        }
    }

    /// The core reached a pass boundary: a credit that has seen its passes
    /// lapses.
    pub fn pass_ended(&self) {
        match self.passes_left.load(Ordering::Acquire) {
            0 => {}
            1 => {
                self.passes_left.store(0, Ordering::Release);
                self.credit_us.store(0, Ordering::Release);
            }
            n => self.passes_left.store(n - 1, Ordering::Release),
        }
    }
}
