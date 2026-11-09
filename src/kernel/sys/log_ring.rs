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
//! - Any context on any core produces, through [`push_record`] alone, and a
//!   record is published whole or not at all (`super::ring`): a drain never
//!   sees a torn record or two records interleaved. Both consumers observe the
//!   same byte stream in the same order; advancing one tail does not affect
//!   the other.
//! - On overflow the **new** record is dropped whole and each consumer it
//!   would overrun counts its bytes. Each consumer reads its own counter via
//!   `take_dropped_local` / `take_dropped_net` and can surface a gap marker.
//!   Bytes already queued are preserved.
//! - Both consumers are opt-in. The net consumer activates on its first
//!   `drain_net` call; the local consumer activates when the platform
//!   runtime calls [`activate_local`] (typically at boot for a sink
//!   whose FIFO is always drained by hardware, or on connect for a
//!   sink that stalls until a host is attached). An inactive consumer
//!   does not participate in the overflow check — the producer is
//!   never back-pressured by a sink that is not yet ready. With neither
//!   active the ring still records, so a consumer that arrives later, and
//!   `read_tail` in a panic handler, have history to read.
//!
//! # Why drop-new rather than overwrite
//!
//! Overwrite-on-full would require the producer to mutate consumer tail
//! pointers, which a consumer on another core reads without the lock.
//! Drop-new leaves every tail to its consumer.

use super::ring::{DropUnit, Ring, WhenIdle};

/// Ring capacity, from the kernel's capacity profile
/// (`config::LOG_RING_CAPACITY`): a power of two, sized to cover early boot
/// until a consumer can reach its transport. On RP it is the silicon TOML's
/// `log_ring_kb`, since a host-class ring does not fit beside the state and
/// buffer arenas.
///
/// The ring is also the size of the replay burst a consumer gets when it
/// attaches, since the whole retained span is sent at once. A network
/// collector's socket buffer drops the oldest datagrams of a burst first, and
/// those are the records the replay exists to deliver. So a larger ring
/// delivers fewer early records, not more, until the replay is paced.
const CAPACITY: usize = crate::kernel::config::LOG_RING_CAPACITY;

/// Consumer slot of the local (platform-owned) drain.
const LOCAL: usize = 0;

/// Consumer slot of the net drain.
const NET: usize = 1;

static RING: Ring<CAPACITY, 2> = Ring::new(WhenIdle::Retain, DropUnit::Bytes);

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
    if !RING.is_active(LOCAL) {
        RING.activate(&RING.lock(), LOCAL, |head| head);
    }
}

/// Activate the local consumer **with** its backlog.
///
/// As [`activate_local`], but the tail is seeded to the oldest byte the ring
/// still holds rather than to `HEAD`, so whatever accumulated before a
/// reader arrived is delivered first. For a console that is opened after
/// the board booted, that is the boot log — which is the part a person
/// opening the console is usually looking for. Idempotent once active.
///
/// The ring only ever holds the last `CAPACITY` bytes: with no consumer
/// active the producer overwrites freely, so the backlog is bounded by the
/// ring, not by how long the board has been up.
pub fn activate_local_from_backlog() {
    if !RING.is_active(LOCAL) {
        RING.activate(&RING.lock(), LOCAL, backlog_tail);
    }
}

/// Deactivate the local consumer.
pub fn disable_local() {
    RING.deactivate(&RING.lock(), LOCAL);
}

/// Publish one record: a whole log line, or the whole of what one caller
/// writes at once. Non-blocking. A record that would overrun an active
/// consumer is dropped whole and counted in that consumer's dropped bytes.
#[inline]
pub fn push_record(bytes: &[u8]) {
    let _ = RING.push_bytes(bytes);
}

/// Drain for the local (platform-owned) debug transport. Advances the
/// local tail only.
pub fn drain_local(out: &mut [u8]) -> usize {
    if !RING.is_active(LOCAL) {
        return 0;
    }
    RING.drain_bytes(LOCAL, out)
}

/// Drain for the net-side consumer (`LOG_RING_DRAIN` syscall). Advances
/// the net tail only.
///
/// The first call activates the net consumer and seeds its tail to the
/// OLDEST byte the ring still holds, not to `HEAD`, so the backlog that
/// accumulated before the consumer could reach its transport is
/// delivered first. This is [`activate_local_from_backlog`]'s rule on
/// the net tail, for the same reason.
///
/// It matters more here than for a console, because the net consumer
/// cannot start early even in principle: `log_net` forwards nothing
/// until its endpoint is bound, and binding waits on DHCP. Seeding to
/// `HEAD` would discard exactly the window nothing else can see —
/// instantiation, and any refusal during it — on a board whose only
/// other transport is a serial line that may not be attached.
///
/// The ring holds at most `CAPACITY` bytes, so the replay is bounded by
/// the ring rather than by how long the board took to get an address.
pub fn drain_net(out: &mut [u8]) -> usize {
    if !RING.is_active(NET) {
        RING.activate(&RING.lock(), NET, backlog_tail);
    }
    RING.drain_bytes(NET, out)
}

/// The oldest byte a backlog replay should start at, given `head`.
///
/// The ring retains its last `CAPACITY` bytes, and that boundary falls
/// wherever the producer happened to be — almost always inside a record.
/// Starting exactly there emits a fragment as if it were a line: the
/// first thing a reader sees is a truncated record with its tag missing,
/// which reads as corruption and, worse, can partially match a pattern
/// someone is grepping for.
///
/// So the tail advances past the first newline in the retained span, and
/// the replay begins at the first WHOLE record. If the span holds no
/// newline at all there is no record boundary to find and the raw tail
/// stands, which is the best available answer rather than dropping the
/// backlog entirely.
fn backlog_tail(head: u32) -> u32 {
    let retained = core::cmp::min(head as usize, CAPACITY);
    let start = head.wrapping_sub(retained as u32);
    // Only a WRAPPED ring can open mid-record. Before the first wrap the
    // span starts at the very first byte ever logged, which is a record
    // start by construction — skipping there would throw away a whole
    // valid record, and if the log so far is one line it would throw
    // away all of it.
    if (head as usize) <= CAPACITY {
        return start;
    }
    for i in 0..retained {
        if RING.byte_at(start.wrapping_add(i as u32)) == b'\n' {
            return start.wrapping_add(i as u32 + 1);
        }
    }
    start
}

/// Atomically read and clear the local-tail dropped-byte counter.
pub fn take_dropped_local() -> u32 {
    RING.take_dropped(LOCAL)
}

/// Atomically read and clear the net-tail dropped-byte counter.
pub fn take_dropped_net() -> u32 {
    RING.take_dropped(NET)
}

/// Non-destructive snapshot of the drop counters and consumer state,
/// for diagnostic surfaces that must not disturb the main accounting.
/// Returns `(dropped_local, dropped_net, local_active, net_active)`.
pub fn peek_stats() -> (u32, u32, bool, bool) {
    (
        RING.dropped(LOCAL),
        RING.dropped(NET),
        RING.is_active(LOCAL),
        RING.is_active(NET),
    )
}

/// Snapshot the most recent `out.len()` bytes of ring history into `out`
/// without advancing the tail. Returns the number of bytes copied.
///
/// Intended for panic / exception handlers that want to dump the tail of
/// the log alongside fault state. Unlike `drain`, this does not consume
/// bytes and does not cooperate with the consumers — it reads the
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
    let head = RING.head();
    let history = core::cmp::min(head as usize, CAPACITY);
    let n = core::cmp::min(out.len(), history);
    let start = head.wrapping_sub(n as u32);
    for (i, o) in out[..n].iter_mut().enumerate() {
        *o = RING.byte_at(start.wrapping_add(i as u32));
    }
    n
}

/// Test-only serialisation lock. Every test that depends on the ring's
/// state (its head, tails, active consumers and dropped counters) —
/// including integration tests under `tests/` and `platform::debug` —
/// must hold this lock for the duration of the test body. Cargo
/// runs tests in parallel by default and the ring is one static.
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
    RING.reset();
}

/// Capacity of the log ring on the host build. Exposed for
/// integration tests under `tests/` that need to push past the
/// wrap point.
#[cfg(feature = "host-linux")]
pub const TEST_CAPACITY: usize = CAPACITY;
