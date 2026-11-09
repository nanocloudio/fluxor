//! The kernel's multi-consumer record ring: the core under
//! [`super::log_ring`] and [`super::telemetry_ring`].
//!
//! A power-of-two byte buffer with one head and `N` consumer slots, each with
//! its own tail, dropped counter and active flag. Any context on any core may
//! push; each consumer drains at its own pace.
//!
//! # Record-atomic push
//!
//! [`Ring::push`] publishes one record whole or not at all. It masks this
//! core's interrupts and takes a spinlock, checks every active consumer's lag,
//! copies the record and publishes the new head (Release), then releases the
//! lock and restores the interrupt mask. So a drain, which reads up to the
//! head (Acquire), never observes a torn record or two records interleaved,
//! whichever cores or interrupt handlers push. Masking first is what makes the
//! lock safe to take from an interrupt handler: a handler cannot preempt a
//! holder on its own core, and a holder on another core releases within one
//! record copy.
//!
//! # Overflow
//!
//! Drop-new: a record that would overrun any active consumer is dropped whole,
//! and each overrun consumer's dropped counter bumps by the record's
//! [`DropUnit`] (its length in bytes, or one record). An inactive consumer is
//! never overrun: the producer is not held back by a reader that is not there.
//! With no consumer active, [`WhenIdle`] decides whether the record still
//! enters the ring's history.

use portable_atomic::{AtomicBool, AtomicU32, Ordering};

/// What a push does when no consumer is active.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WhenIdle {
    /// Write it anyway: the ring keeps the last `CAP` bytes as history a
    /// consumer activated later can replay.
    Retain,
    /// Drop it: nothing would read it.
    Discard,
}

/// What a dropped record adds to an overrun consumer's dropped counter.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DropUnit {
    /// Its length in bytes.
    Bytes,
    /// One.
    Records,
}

/// What [`Ring::push`] did with a record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pushed {
    /// Published.
    Written,
    /// Dropped whole: it would have overrun an active consumer, or it is
    /// longer than the ring.
    Dropped,
    /// Dropped because no consumer is active and the ring discards then.
    NoConsumer,
}

/// A ring of `CAP` bytes (a power of two) with `N` consumer slots.
pub struct Ring<const CAP: usize, const N: usize> {
    buf: core::cell::UnsafeCell<[u8; CAP]>,
    head: AtomicU32,
    tails: [AtomicU32; N],
    dropped: [AtomicU32; N],
    active: [AtomicBool; N],
    lock: AtomicBool,
    when_idle: WhenIdle,
    drop_unit: DropUnit,
}

// SAFETY: the buffer is written only under `lock` with this core's interrupts
// masked, and read at positions below a head published with Release after the
// write; every other field is atomic.
unsafe impl<const CAP: usize, const N: usize> Sync for Ring<CAP, N> {}

/// The lock, held with this core's interrupts masked. Dropping it releases the
/// lock and then restores the mask.
pub struct Guard<'a> {
    lock: &'a AtomicBool,
    masked: Option<u32>,
}

impl Drop for Guard<'_> {
    #[inline]
    fn drop(&mut self) {
        self.lock.store(false, Ordering::Release);
        if let Some(state) = self.masked {
            core::sync::atomic::compiler_fence(Ordering::SeqCst);
            crate::kernel::sys::hal::restore_interrupts(state);
        }
    }
}

impl<const CAP: usize, const N: usize> Ring<CAP, N> {
    const MASK: usize = CAP - 1;
    const POWER_OF_TWO: () = assert!(CAP.is_power_of_two() && CAP <= 1 << 31);

    /// An empty ring with every consumer inactive.
    pub const fn new(when_idle: WhenIdle, drop_unit: DropUnit) -> Self {
        let () = Self::POWER_OF_TWO;
        Self {
            buf: core::cell::UnsafeCell::new([0; CAP]),
            head: AtomicU32::new(0),
            tails: [const { AtomicU32::new(0) }; N],
            dropped: [const { AtomicU32::new(0) }; N],
            active: [const { AtomicBool::new(false) }; N],
            lock: AtomicBool::new(false),
            when_idle,
            drop_unit,
        }
    }

    /// The ring's size in bytes.
    pub const fn capacity(&self) -> usize {
        CAP
    }

    /// Mask this core's interrupts, then take the lock. Before the platform
    /// has installed its HAL no handler is bound, so there is nothing to mask.
    #[inline]
    pub fn lock(&self) -> Guard<'_> {
        let masked = if crate::kernel::sys::hal::is_initialised() {
            let state = crate::kernel::sys::hal::disable_interrupts();
            core::sync::atomic::compiler_fence(Ordering::SeqCst);
            Some(state)
        } else {
            None
        };
        while self
            .lock
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Guard {
            lock: &self.lock,
            masked,
        }
    }

    /// Publish a record of `len` bytes whose byte `i` is `byte(i)`, whole or
    /// not at all.
    pub fn push(&self, len: usize, mut byte: impl FnMut(usize) -> u8) -> Pushed {
        if len == 0 {
            return Pushed::Written;
        }
        if len > CAP {
            self.count_drop_all(len);
            return Pushed::Dropped;
        }
        let _g = self.lock();
        let head = self.head.load(Ordering::Relaxed);
        let mut any_active = false;
        let mut overrun = false;
        for slot in 0..N {
            if self.active[slot].load(Ordering::Acquire) {
                any_active = true;
                if self.lag(slot, head) + len > CAP {
                    overrun = true;
                }
            }
        }
        if !any_active && self.when_idle == WhenIdle::Discard {
            return Pushed::NoConsumer;
        }
        if overrun {
            let unit = self.unit(len);
            for slot in 0..N {
                if self.active[slot].load(Ordering::Acquire) && self.lag(slot, head) + len > CAP {
                    self.dropped[slot].fetch_add(unit, Ordering::Relaxed);
                }
            }
            return Pushed::Dropped;
        }
        let base = self.buf.get().cast::<u8>();
        for i in 0..len {
            let idx = (head.wrapping_add(i as u32) as usize) & Self::MASK;
            // SAFETY: `idx` is below CAP; the lock makes this the only writer,
            // and no consumer reads at or past `head` until the store below.
            unsafe { core::ptr::write_volatile(base.add(idx), byte(i)) };
        }
        self.head
            .store(head.wrapping_add(len as u32), Ordering::Release);
        Pushed::Written
    }

    /// [`push`](Self::push) a byte slice.
    #[inline]
    pub fn push_bytes(&self, bytes: &[u8]) -> Pushed {
        self.push(bytes.len(), |i| bytes[i])
    }

    /// Every active consumer counts a record that cannot fit at all.
    fn count_drop_all(&self, len: usize) {
        let unit = self.unit(len);
        for slot in 0..N {
            if self.active[slot].load(Ordering::Acquire) {
                self.dropped[slot].fetch_add(unit, Ordering::Relaxed);
            }
        }
    }

    #[inline]
    fn unit(&self, len: usize) -> u32 {
        match self.drop_unit {
            DropUnit::Bytes => len as u32,
            DropUnit::Records => 1,
        }
    }

    #[inline]
    fn lag(&self, slot: usize, head: u32) -> usize {
        head.wrapping_sub(self.tails[slot].load(Ordering::Acquire)) as usize
    }

    /// The published head: bytes ever pushed, modulo 2^32.
    #[inline]
    pub fn head(&self) -> u32 {
        self.head.load(Ordering::Acquire)
    }

    /// The byte at ring position `pos` (any position; it is masked).
    #[inline]
    pub fn byte_at(&self, pos: u32) -> u8 {
        // SAFETY: the masked index is below CAP. A read below the published
        // head sees the bytes published with it; any other read is a racy
        // read of plain bytes, which cannot fault.
        unsafe {
            core::ptr::read_volatile(self.buf.get().cast::<u8>().add((pos as usize) & Self::MASK))
        }
    }

    /// Copy from `slot`'s tail up to the head into `out` and advance the tail
    /// past what was copied. Returns the bytes copied.
    pub fn drain_bytes(&self, slot: usize, out: &mut [u8]) -> usize {
        let tail = self.tails[slot].load(Ordering::Relaxed);
        let head = self.head();
        let n = core::cmp::min(head.wrapping_sub(tail) as usize, out.len());
        for (i, o) in out[..n].iter_mut().enumerate() {
            *o = self.byte_at(tail.wrapping_add(i as u32));
        }
        if n > 0 {
            self.tails[slot].store(tail.wrapping_add(n as u32), Ordering::Release);
        }
        n
    }

    /// `slot`'s tail.
    #[inline]
    pub fn tail(&self, slot: usize) -> u32 {
        self.tails[slot].load(Ordering::Acquire)
    }

    /// Move `slot`'s tail.
    #[inline]
    pub fn set_tail(&self, slot: usize, tail: u32) {
        self.tails[slot].store(tail, Ordering::Release);
    }

    /// Whether `slot` is active.
    #[inline]
    pub fn is_active(&self, slot: usize) -> bool {
        self.active[slot].load(Ordering::Acquire)
    }

    /// Activate `slot` with its tail at `tail(head)` and its dropped counter
    /// at zero, unless it is active already. Returns whether it was activated
    /// now. Under the caller's hold of the lock, so a concurrent push sees the
    /// slot whole or not at all.
    pub fn activate(&self, _held: &Guard<'_>, slot: usize, tail: impl FnOnce(u32) -> u32) -> bool {
        if self.active[slot].load(Ordering::Acquire) {
            return false;
        }
        let head = self.head.load(Ordering::Relaxed);
        self.tails[slot].store(tail(head), Ordering::Release);
        self.dropped[slot].store(0, Ordering::Release);
        self.active[slot].store(true, Ordering::Release);
        true
    }

    /// Deactivate `slot`, under the caller's hold of the lock.
    pub fn deactivate(&self, _held: &Guard<'_>, slot: usize) {
        self.active[slot].store(false, Ordering::Release);
    }

    /// Read and clear `slot`'s dropped counter.
    #[inline]
    pub fn take_dropped(&self, slot: usize) -> u32 {
        self.dropped[slot].swap(0, Ordering::Relaxed)
    }

    /// `slot`'s dropped counter, left as it is.
    #[inline]
    pub fn dropped(&self, slot: usize) -> u32 {
        self.dropped[slot].load(Ordering::Relaxed)
    }

    /// Back to the state [`new`](Self::new) builds: no history, every
    /// consumer inactive. For a harness that reuses the ring across cases.
    pub fn reset(&self) {
        let _g = self.lock();
        self.head.store(0, Ordering::Release);
        for slot in 0..N {
            self.tails[slot].store(0, Ordering::Release);
            self.dropped[slot].store(0, Ordering::Release);
            self.active[slot].store(false, Ordering::Release);
        }
    }
}
