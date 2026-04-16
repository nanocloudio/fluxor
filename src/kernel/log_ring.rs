//! Kernel log ring — SPSC byte buffer for opt-in log forwarding.
//!
//! The kernel's `log::Log` backend pushes formatted records here. A PIC
//! overlay module (`log_net`, `log_uart`, `log_usb`) drains it via the
//! `LOG_RING_DRAIN` syscall and forwards the bytes on its transport.
//!
//! # Semantics
//!
//! - Single-producer single-consumer ring, lock-free.
//! - On overflow, **new** bytes are dropped and a saturating counter is
//!   bumped. The consumer reads the counter via `take_dropped` and can
//!   surface a gap marker in its output. Old bytes already queued are
//!   preserved.
//! - The producer is the kernel log path. The consumer is whichever log
//!   overlay is active (at most one at a time).
//!
//! # Why drop-new rather than overwrite
//!
//! Overwrite-on-full would require the producer to mutate the consumer's
//! tail pointer, which is unsafe under any real concurrency. Drop-new is
//! a pure SPSC pattern and survives being called from tighter contexts
//! (ISRs, cross-core) later.

use portable_atomic::{AtomicU32, Ordering};

/// Ring capacity. Must be a power of two; sized to cover early boot until the
/// log_net module is up (~a few seconds of chatty logging).
const CAPACITY: usize = 8192;
const MASK: usize = CAPACITY - 1;

static mut BUF: [u8; CAPACITY] = [0; CAPACITY];
static HEAD: AtomicU32 = AtomicU32::new(0);
static TAIL: AtomicU32 = AtomicU32::new(0);
static DROPPED: AtomicU32 = AtomicU32::new(0);

/// Push one byte into the ring. Non-blocking: drops on full and increments
/// the dropped-byte counter.
#[inline]
pub fn push_byte(b: u8) {
    let head = HEAD.load(Ordering::Relaxed);
    let tail = TAIL.load(Ordering::Acquire);
    if head.wrapping_sub(tail) as usize >= CAPACITY {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    unsafe {
        let ptr = (&raw mut BUF[0]).add((head as usize) & MASK);
        core::ptr::write_volatile(ptr, b);
    }
    HEAD.store(head.wrapping_add(1), Ordering::Release);
}

/// Push a slice. Bytes that would overflow are dropped and counted.
pub fn push_bytes(s: &[u8]) {
    for &b in s {
        push_byte(b);
    }
}

/// Drain up to `out.len()` bytes into `out`. Returns the number of bytes copied.
///
/// Caller is the single consumer. Must not be invoked from multiple threads
/// concurrently.
pub fn drain(out: &mut [u8]) -> usize {
    let tail = TAIL.load(Ordering::Relaxed);
    let head = HEAD.load(Ordering::Acquire);
    let available = head.wrapping_sub(tail) as usize;
    let n = core::cmp::min(available, out.len());
    let mut i = 0;
    while i < n {
        let idx = (tail.wrapping_add(i as u32) as usize) & MASK;
        out[i] = unsafe { core::ptr::read_volatile((&raw const BUF[0]).add(idx)) };
        i += 1;
    }
    if n > 0 {
        TAIL.store(tail.wrapping_add(n as u32), Ordering::Release);
    }
    n
}

/// Atomically read and clear the dropped-byte counter.
pub fn take_dropped() -> u32 {
    DROPPED.swap(0, Ordering::Relaxed)
}
