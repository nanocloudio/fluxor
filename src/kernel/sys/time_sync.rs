//! Network-disciplined wall clock, for platforms with no RTC and no operating
//! system to run a time protocol for them.
//!
//! A bare-metal board knows only how long it has been up. A time client in the
//! graph (the `sntp` foundation module) measures the offset to network time and
//! hands the kernel one anchor through `timer::DISCIPLINE`: "at monotonic
//! instant M it was Unix time U, within E". From then on the wall clock is
//! `U + (now − M)`, and the platform can answer `clock_sync_status` honestly:
//! synchronised, with an error bound that is the anchor's own uncertainty plus
//! the oscillator drift admitted since it was taken.
//!
//! An anchor goes stale: past [`STALE_AFTER_US`] without a fresh one the clock
//! keeps counting but reports itself unsynchronised, so a credential decision
//! that needs a trusted clock fails closed rather than trusting a free-running
//! counter. The client re-anchors well inside that window.
//!
//! Readers and writers run on any core. The anchor is published under a
//! sequence lock: a writer claims it by moving the sequence from even to odd,
//! so two anchors never interleave, and a reader retries until it sees the
//! same even sequence on both sides of its read, so it never pairs one
//! anchor's Unix time with another's monotonic instant.

use portable_atomic::{AtomicU64, Ordering};

/// Oscillator drift admitted, in parts per million of the time elapsed since
/// the anchor. A crystal that keeps a schedule is an order of magnitude better.
pub const MAX_DRIFT_PPM: u64 = 100;

/// An anchor older than this no longer counts as synchronised (1 hour: the
/// drift allowance alone has reached 360 ms by then).
pub const STALE_AFTER_US: u64 = 3_600_000_000;

/// The earliest Unix time an anchor may claim (2024-01-01T00:00:00Z). A
/// reading before it is a broken source, not a clock.
pub const MIN_UNIX_US: u64 = 1_704_067_200_000_000;

static SEQ: AtomicU64 = AtomicU64::new(0);
/// Unix microseconds at the anchor; 0 = never disciplined.
static ANCHOR_UNIX_US: AtomicU64 = AtomicU64::new(0);
static ANCHOR_MONO_US: AtomicU64 = AtomicU64::new(0);
static ANCHOR_ERR_US: AtomicU64 = AtomicU64::new(0);

/// A consistent snapshot of the anchor, or `None` if never disciplined.
fn anchor() -> Option<(u64, u64, u64)> {
    loop {
        let s0 = SEQ.load(Ordering::Acquire);
        if s0 & 1 != 0 {
            core::hint::spin_loop();
            continue;
        }
        let unix = ANCHOR_UNIX_US.load(Ordering::Acquire);
        let mono = ANCHOR_MONO_US.load(Ordering::Acquire);
        let err = ANCHOR_ERR_US.load(Ordering::Acquire);
        if SEQ.load(Ordering::Acquire) == s0 {
            return if unix == 0 {
                None
            } else {
                Some((unix, mono, err))
            };
        }
    }
}

/// Install an anchor: at monotonic `mono_us` it was `unix_us`, within
/// `err_us`. Returns 0, or a negative errno for an anchor that cannot be
/// true (before [`MIN_UNIX_US`], or a monotonic instant in the future).
pub fn discipline(unix_us: u64, mono_us: u64, err_us: u64, now_mono_us: u64) -> i32 {
    if unix_us < MIN_UNIX_US || mono_us > now_mono_us {
        return super::errno::EINVAL;
    }
    let seq = write_begin();
    ANCHOR_MONO_US.store(mono_us, Ordering::Release);
    ANCHOR_ERR_US.store(err_us, Ordering::Release);
    ANCHOR_UNIX_US.store(unix_us, Ordering::Release);
    SEQ.store(seq + 2, Ordering::Release);
    0
}

/// Claim the anchor for writing: move the sequence from an even value `s` to
/// `s + 1` and return `s`. Spins while another writer holds it.
fn write_begin() -> u64 {
    loop {
        let s = SEQ.load(Ordering::Acquire);
        if s & 1 == 0
            && SEQ
                .compare_exchange_weak(s, s + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            return s;
        }
        core::hint::spin_loop();
    }
}

/// Wall-clock milliseconds since the Unix epoch at monotonic `now_mono_us`,
/// or 0 if the clock was never disciplined.
pub fn unix_millis(now_mono_us: u64) -> u64 {
    match anchor() {
        Some((unix, mono, _)) => (unix + now_mono_us.saturating_sub(mono)) / 1_000,
        None => 0,
    }
}

/// `(synchronised, max_error_us)` at monotonic `now_mono_us`, for
/// `HalOps::clock_sync_status`. `None` until the first anchor: until then
/// the platform has nothing to say about a clock it does not have.
pub fn status(now_mono_us: u64) -> Option<(bool, u64)> {
    let (_, mono, err) = anchor()?;
    let age = now_mono_us.saturating_sub(mono);
    let max_error = err.saturating_add(age.saturating_mul(MAX_DRIFT_PPM) / 1_000_000);
    Some((age < STALE_AFTER_US, max_error))
}

/// Forget the anchor (test isolation only).
#[cfg(feature = "host-linux")]
pub fn reset() {
    let seq = write_begin();
    ANCHOR_UNIX_US.store(0, Ordering::Release);
    SEQ.store(seq + 2, Ordering::Release);
}
