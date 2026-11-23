//! A lock between cores, held with interrupts masked.
//!
//! One word in RAM, taken with the processor's exclusive accesses
//! (`compare_exchange`, which the cores' shared exclusive monitor
//! arbitrates). The word names the core that holds it, so a core that takes
//! the lock again while holding it, a nested critical section, is told so
//! and does not wait for itself. The holder keeps its own interrupts masked
//! for as long as it holds the lock: a handler on the holding core can then
//! never find the lock taken by the code it interrupted.
//!
//! Pure atomics with no architecture in it, so a host test contends for it
//! from two threads.

use core::sync::atomic::{AtomicU32, Ordering};

/// The word of an unheld lock.
const FREE: u32 = 0;

/// A lock between cores.
pub struct CoreLock {
    /// [`FREE`], or the holding core's number plus one.
    holder: AtomicU32,
    /// Times the lock was taken, written only by the holder.
    taken: AtomicU32,
}

impl Default for CoreLock {
    fn default() -> Self {
        Self::new()
    }
}

impl CoreLock {
    pub const fn new() -> Self {
        Self {
            holder: AtomicU32::new(FREE),
            taken: AtomicU32::new(0),
        }
    }

    /// Take the lock for `core`, spinning while another core holds it.
    /// Returns `false`, having taken nothing, when `core` already holds it:
    /// the caller is nested and its outer section releases. The caller has
    /// its interrupts masked.
    #[inline]
    pub fn acquire(&self, core: u32) -> bool {
        let me = core + 1;
        if self.holder.load(Ordering::Relaxed) == me {
            return false;
        }
        while self
            .holder
            .compare_exchange_weak(FREE, me, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // Only the holder writes the count, so a plain load and store keeps
        // it exact.
        self.taken.store(
            self.taken.load(Ordering::Relaxed).wrapping_add(1),
            Ordering::Relaxed,
        );
        true
    }

    /// Release the lock. Called by the core whose [`Self::acquire`] returned
    /// `true`, once, with its interrupts still masked.
    #[inline]
    pub fn release(&self) {
        self.holder.store(FREE, Ordering::Release);
    }

    /// Release the lock if `core` holds it, for a core that has stopped for
    /// good inside a section it will never leave. Returns whether it did.
    pub fn abandon(&self, core: u32) -> bool {
        self.holder
            .compare_exchange(core + 1, FREE, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }

    /// Times the lock has been taken: one per outermost critical section.
    pub fn taken(&self) -> u32 {
        self.taken.load(Ordering::Relaxed)
    }

    /// Whether `core` holds the lock.
    pub fn held_by(&self, core: u32) -> bool {
        self.holder.load(Ordering::Relaxed) == core + 1
    }
}
