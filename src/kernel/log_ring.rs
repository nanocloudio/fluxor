//! Kernel log ring — multi-consumer byte buffer for opt-in log forwarding.
//!
//! The kernel's `log::Log` backend pushes formatted records here. Two
//! consumers drain the ring with independent tails, so neither steals
//! bytes from the other:
//!
//! - **Local drain**: `platform::debug::DebugDrain` calls [`drain_local`]
//!   and writes to a board-owned sink (UART on bcm2712, USB CDC on rp).
//! - **Net drain**: `log_net` consumes via the `LOG_RING_DRAIN` syscall,
//!   which calls [`drain_net`].
//!
//! # Semantics
//!
//! - Single producer, two consumers. Both observe the same byte stream
//!   in the same order; advancing one tail does not affect the other.
//! - On overflow the **new** byte is dropped and the affected consumers'
//!   dropped counters bump. Each consumer reads its own counter via
//!   `take_dropped_local` / `take_dropped_net` and can surface a gap
//!   marker. Bytes already queued are preserved.
//! - Both consumers are opt-in. The net consumer activates on its first
//!   `drain_net` call; the local consumer activates when the platform
//!   runtime calls [`activate_local`] (typically at boot for a sink
//!   whose FIFO is always drained by hardware, or on connect for a
//!   sink that stalls until a host is attached). An inactive consumer
//!   does not participate in the overflow check — the producer is
//!   never back-pressured by a sink that is not yet ready.
//!
//! # Why drop-new rather than overwrite
//!
//! Overwrite-on-full would require the producer to mutate consumer tail
//! pointers, which is unsafe under any real concurrency. Drop-new is a
//! pure SPMC pattern and survives being called from tighter contexts
//! (ISRs, cross-core) later.
use portable_atomic::{AtomicBool, AtomicU32, Ordering};
/// Ring capacity. Must be a power of two; sized to cover early boot until the
/// log_net module is up (~a few seconds of chatty logging). Smaller on RP2040
/// (264 KB total SRAM — a 64 KB ring is 25% of DRAM and pushes .bss past
/// the region when combined with STATE_ARENA / BUFFER_ARENA).
#[cfg(feature = "chip-rp2040")]
const CAPACITY: usize = 4096;
#[cfg(not(feature = "chip-rp2040"))]
const CAPACITY: usize = 65536;
const MASK: usize = CAPACITY - 1;
static mut BUF: [u8; CAPACITY] = [0; CAPACITY];
static HEAD: AtomicU32 = AtomicU32::new(0);
static TAIL_LOCAL: AtomicU32 = AtomicU32::new(0);
static TAIL_NET: AtomicU32 = AtomicU32::new(0);
static DROPPED_LOCAL: AtomicU32 = AtomicU32::new(0);
static DROPPED_NET: AtomicU32 = AtomicU32::new(0);
/// True once `drain_net` has been called at least once. While false, the
/// net tail does not participate in the overflow check.
static NET_ACTIVE: AtomicBool = AtomicBool::new(false);
/// Starts false. Platform runtime calls [`activate_local`] when its
/// local-transport sink is ready to accept bytes without stalling.
static LOCAL_ACTIVE: AtomicBool = AtomicBool::new(false);
/// Activate the local consumer. Called by the platform runtime once the
/// local-transport sink can accept bytes without stalling — at boot for
/// transports whose FIFO is always drained by hardware (a UART line
/// with no listener still clocks bits out), and on host-attach for
/// transports that stall without a reader (USB CDC).
///
/// On the false→true transition the local tail is seeded to the current
/// HEAD, so the consumer starts from "now" and any backlog that built
/// up while it was inactive is skipped (the producer cannot have
/// back-pressured on it while the flag was false). Idempotent on
/// subsequent calls.
pub fn activate_local() {
    if !LOCAL_ACTIVE.load(Ordering::Acquire) {
        let head = HEAD.load(Ordering::Acquire);
        TAIL_LOCAL.store(head, Ordering::Release);
        LOCAL_ACTIVE.store(true, Ordering::Release);
    }
}
/// Deactivate the local consumer.
pub fn disable_local() {
    LOCAL_ACTIVE.store(false, Ordering::Release);
}
/// Push one byte into the ring. Non-blocking: drops on full and bumps
/// the affected consumer's dropped-byte counter(s).
#[inline]
pub fn push_byte(b: u8) {
    let head = HEAD.load(Ordering::Relaxed);
    let (lag_local, local_active) = if LOCAL_ACTIVE.load(Ordering::Acquire) {
        let tail_local = TAIL_LOCAL.load(Ordering::Acquire);
        (head.wrapping_sub(tail_local) as usize, true)
    } else {
        (0, false)
    };
    let (lag_net, net_active) = if NET_ACTIVE.load(Ordering::Acquire) {
        let tail_net = TAIL_NET.load(Ordering::Acquire);
        (head.wrapping_sub(tail_net) as usize, true)
    } else {
        (0, false)
    };
    // With no active consumer the head still advances so `read_tail` can
    // dump history in panic handlers, but the producer never drops.
    if !local_active && !net_active {
        // SAFETY: `head as usize & MASK` is in-bounds for `BUF[0..CAPACITY]`
        // since MASK = CAPACITY - 1; volatile write is single-byte and
        // ordered against the subsequent `HEAD.store(Release)`.
        unsafe {
            let ptr = (&raw mut BUF[0]).add((head as usize) & MASK);
            core::ptr::write_volatile(ptr, b);
        }
        HEAD.store(head.wrapping_add(1), Ordering::Release);
        return;
    }
    let lag = if lag_local > lag_net {
        lag_local
    } else {
        lag_net
    };
    if lag >= CAPACITY {
        if local_active {
            DROPPED_LOCAL.fetch_add(1, Ordering::Relaxed);
        }
        if net_active {
            DROPPED_NET.fetch_add(1, Ordering::Relaxed);
        }
        return;
    }
    // SAFETY: `head as usize & MASK` is in-bounds for `BUF`; volatile
    // write happens-before `HEAD.store(Release)` below.
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
#[inline]
fn drain_from(tail_reg: &AtomicU32, out: &mut [u8]) -> usize {
    let tail = tail_reg.load(Ordering::Relaxed);
    let head = HEAD.load(Ordering::Acquire);
    let available = head.wrapping_sub(tail) as usize;
    let n = core::cmp::min(available, out.len());
    let mut i = 0;
    while i < n {
        let idx = (tail.wrapping_add(i as u32) as usize) & MASK;
        // SAFETY: `idx & MASK` is in-bounds for `BUF`; volatile read
        // paired with the `HEAD.load(Acquire)` above.
        out[i] = unsafe { core::ptr::read_volatile((&raw const BUF[0]).add(idx)) };
        i += 1;
    }
    if n > 0 {
        tail_reg.store(tail.wrapping_add(n as u32), Ordering::Release);
    }
    n
}
/// Drain for the local (platform-owned) debug transport. Advances the
/// local tail only.
pub fn drain_local(out: &mut [u8]) -> usize {
    if !LOCAL_ACTIVE.load(Ordering::Acquire) {
        return 0;
    }
    drain_from(&TAIL_LOCAL, out)
}
/// Drain for the net-side consumer (`LOG_RING_DRAIN` syscall). Advances
/// the net tail only. The first call activates the net consumer, seeding
/// `TAIL_NET` to `HEAD` so the consumer starts from "now" and returning
/// 0; subsequent calls copy bytes normally.
pub fn drain_net(out: &mut [u8]) -> usize {
    if !NET_ACTIVE.load(Ordering::Acquire) {
        let head = HEAD.load(Ordering::Acquire);
        TAIL_NET.store(head, Ordering::Release);
        NET_ACTIVE.store(true, Ordering::Release);
        return 0;
    }
    drain_from(&TAIL_NET, out)
}
/// Atomically read and clear the local-tail dropped-byte counter.
pub fn take_dropped_local() -> u32 {
    DROPPED_LOCAL.swap(0, Ordering::Relaxed)
}
/// Atomically read and clear the net-tail dropped-byte counter.
pub fn take_dropped_net() -> u32 {
    DROPPED_NET.swap(0, Ordering::Relaxed)
}
/// Non-destructive snapshot of the drop counters and consumer state,
/// for diagnostic surfaces that must not disturb the main accounting.
/// Returns `(dropped_local, dropped_net, local_active, net_active)`.
pub fn peek_stats() -> (u32, u32, bool, bool) {
    (
        DROPPED_LOCAL.load(Ordering::Relaxed),
        DROPPED_NET.load(Ordering::Relaxed),
        LOCAL_ACTIVE.load(Ordering::Relaxed),
        NET_ACTIVE.load(Ordering::Relaxed),
    )
}
/// Snapshot the most recent `out.len()` bytes of ring history into `out`
/// without advancing the tail. Returns the number of bytes copied.
///
/// Intended for panic / exception handlers that want to dump the tail of
/// the log alongside fault state. Unlike `drain`, this does not consume
/// bytes and does not cooperate with the SPSC consumer — it reads the
/// underlying buffer directly. Safe to call from any context: no locks,
/// no allocation, no scheduler dependency.
///
/// If the producer has emitted fewer bytes than `out.len()` since boot,
/// only that many bytes are copied. If more than `CAPACITY` bytes have
/// been written, at most `CAPACITY` bytes are available (the oldest are
/// overwritten by normal ring rotation). A concurrent producer racing
/// with this call may yield slightly truncated or partially-updated
/// bytes; the call will not corrupt memory.
pub fn read_tail(out: &mut [u8]) -> usize {
    let head = HEAD.load(Ordering::Relaxed);
    if head == 0 {
        return 0;
    }
    let history = if (head as usize) < CAPACITY {
        head as usize
    } else {
        CAPACITY
    };
    let n = core::cmp::min(out.len(), history);
    let start = head.wrapping_sub(n as u32);
    let mut i = 0;
    while i < n {
        let idx = (start.wrapping_add(i as u32) as usize) & MASK;
        // SAFETY: `idx & MASK` is in-bounds for `BUF`; volatile read
        // for panic-handler history dump.
        out[i] = unsafe { core::ptr::read_volatile((&raw const BUF[0]).add(idx)) };
        i += 1;
    }
    n
}
/// Test-only serialisation lock. Every test that touches the
/// module-level statics (`HEAD`, `TAIL_LOCAL`, `TAIL_NET`,
/// `LOCAL_ACTIVE`, `NET_ACTIVE`, dropped counters) — including
/// integration tests under `tests/` and `platform::debug` —
/// must hold this lock for the duration of the test body. Cargo
/// runs tests in parallel by default and the statics aren't safe
/// to mutate concurrently.
///
/// Exposed as `pub` (gated on `host-linux`) so integration tests
/// in `tests/` can serialise on the same lock.
#[cfg(feature = "host-linux")]
pub static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// Acquire the test serialisation lock. Recovers from poisoning —
/// a previous test that panicked still left global state behind,
/// but every caller resets the ring before relying on it.
#[cfg(feature = "host-linux")]
pub fn lock_tests() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}
/// Test-only reset. Brings the ring back to its post-boot state
/// so tests don't see bytes pushed by earlier cases. Exposed as
/// `pub` (gated on `host-linux`) so integration tests can call it.
#[cfg(feature = "host-linux")]
pub fn _test_reset() {
    HEAD.store(0, Ordering::Release);
    TAIL_LOCAL.store(0, Ordering::Release);
    TAIL_NET.store(0, Ordering::Release);
    DROPPED_LOCAL.store(0, Ordering::Release);
    DROPPED_NET.store(0, Ordering::Release);
    LOCAL_ACTIVE.store(false, Ordering::Release);
    NET_ACTIVE.store(false, Ordering::Release);
}
/// Capacity of the log ring on the host build. Exposed for
/// integration tests under `tests/` that need to push past the
/// wrap point.
#[cfg(feature = "host-linux")]
pub const TEST_CAPACITY: usize = CAPACITY;
