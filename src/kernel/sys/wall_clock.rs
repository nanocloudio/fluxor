//! Wall-clock observation ledger: the `source_epoch` and rollback flag a
//! `timer::TRUSTED_UNIX` reading carries.
//!
//! A calendar clock is only useful for a security decision if a consumer can
//! tell when the clock it decided under stops being the clock it is reading
//! now. The reading itself cannot say that: a clock stepped back an hour and
//! forward again looks, at every instant, like an honest clock. What makes
//! the step visible is comparing each reading against the previous one
//! through the monotonic counter read at the same instant — the monotonic
//! delta says how much time really passed, and a wall-clock delta that
//! disagrees by more than the reported uncertainty is a step.
//!
//! The epoch is a per-boot counter that advances on every such event:
//!
//! - the synchronisation state changes (a source came up, or went away);
//! - the wall clock moved backwards relative to the monotonic counter;
//! - the wall clock jumped forwards by more than the uncertainty admits.
//!
//! A consumer stamps a cached decision with the epoch it was made under and
//! discards it when the epoch moves. The backward case additionally raises
//! `ROLLBACK_SUSPECT` for the rest of that epoch, so a consumer that only
//! polls occasionally still sees it.
//!
//! Cross-core: readings are recorded with relaxed atomics and no lock. Two
//! cores observing one step at the same instant may each advance the epoch,
//! and that is the fail-safe direction — an extra advance only discards a
//! cache, never keeps a stale one.

use portable_atomic::{AtomicU64, AtomicU8, Ordering};

/// Slack, in milliseconds, before a disagreement between the wall clock and
/// the monotonic counter counts as a step. Covers the read granularity of
/// both clocks plus a synchronisation daemon's slew, which adjusts by at
/// most a few hundred parts per million and never approaches this within
/// one observation interval.
pub const STEP_TOLERANCE_MS: u64 = 500;

/// Drift allowance per elapsed second, expressed as a divisor: elapsed
/// milliseconds divided by this is added to the tolerance, so a long gap
/// between readings does not report ordinary oscillator drift as a step.
/// 1000 admits 0.1% — an order of magnitude above any crystal that keeps
/// a schedule.
const DRIFT_DIVISOR: u64 = 1_000;

/// Synchronisation state as last observed.
const SYNC_UNKNOWN: u8 = 0;
const SYNC_NO: u8 = 1;
const SYNC_YES: u8 = 2;

static EPOCH: AtomicU64 = AtomicU64::new(0);
static ROLLBACK_EPOCH: AtomicU64 = AtomicU64::new(u64::MAX);
static LAST_UNIX_MS: AtomicU64 = AtomicU64::new(0);
static LAST_MONO_US: AtomicU64 = AtomicU64::new(0);
static LAST_SYNC: AtomicU8 = AtomicU8::new(SYNC_UNKNOWN);
static PRIMED: AtomicU8 = AtomicU8::new(0);

/// What one observation concluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    /// The epoch this reading belongs to.
    pub epoch: u64,
    /// The clock moved backwards during this epoch.
    pub rollback_suspect: bool,
}

/// Record a reading and return the epoch it belongs to.
///
/// `unix_ms` is the wall clock (0 = none), `mono_us` the monotonic counter
/// read at the same instant, `synced` the platform's synchronisation
/// answer (`None` = cannot tell), `uncertainty_ms` the half-width the
/// reading is honest within.
pub fn observe(
    unix_ms: u64,
    mono_us: u64,
    synced: Option<bool>,
    uncertainty_ms: u32,
) -> Observation {
    let sync_now = match synced {
        Some(true) => SYNC_YES,
        Some(false) => SYNC_NO,
        None => SYNC_UNKNOWN,
    };

    if PRIMED.swap(1, Ordering::Relaxed) == 0 {
        LAST_UNIX_MS.store(unix_ms, Ordering::Relaxed);
        LAST_MONO_US.store(mono_us, Ordering::Relaxed);
        LAST_SYNC.store(sync_now, Ordering::Relaxed);
        return Observation {
            epoch: EPOCH.load(Ordering::Relaxed),
            rollback_suspect: false,
        };
    }

    let last_unix = LAST_UNIX_MS.swap(unix_ms, Ordering::Relaxed);
    let last_mono = LAST_MONO_US.swap(mono_us, Ordering::Relaxed);
    let last_sync = LAST_SYNC.swap(sync_now, Ordering::Relaxed);

    let mut advance = false;
    let mut rollback = false;

    // A source that came up or went away is a different clock, whatever
    // the reading says. "Cannot tell" is not a state change from "no".
    let was_synced = last_sync == SYNC_YES;
    let is_synced = sync_now == SYNC_YES;
    if was_synced != is_synced {
        advance = true;
    }

    // Both readings carry a clock: compare the wall-clock delta against the
    // monotonic delta. A clock that appeared or vanished is covered by the
    // sync transition above, not here.
    if unix_ms != 0 && last_unix != 0 {
        let elapsed_ms = mono_us.saturating_sub(last_mono) / 1_000;
        let tolerance = STEP_TOLERANCE_MS
            .saturating_add(u64::from(uncertainty_ms))
            .saturating_add(elapsed_ms / DRIFT_DIVISOR);
        let expected = last_unix.saturating_add(elapsed_ms);
        if unix_ms.saturating_add(tolerance) < expected {
            advance = true;
            rollback = true;
        } else if unix_ms > expected.saturating_add(tolerance) {
            advance = true;
        }
    }

    let epoch = if advance {
        EPOCH.fetch_add(1, Ordering::Relaxed) + 1
    } else {
        EPOCH.load(Ordering::Relaxed)
    };
    if rollback {
        ROLLBACK_EPOCH.store(epoch, Ordering::Relaxed);
    }
    Observation {
        epoch,
        rollback_suspect: ROLLBACK_EPOCH.load(Ordering::Relaxed) == epoch,
    }
}

/// Forget every recorded reading, so the next `observe` primes afresh at
/// epoch 0. For a harness that runs several clock scenarios in one process.
pub fn reset() {
    PRIMED.store(0, Ordering::Relaxed);
    EPOCH.store(0, Ordering::Relaxed);
    ROLLBACK_EPOCH.store(u64::MAX, Ordering::Relaxed);
    LAST_UNIX_MS.store(0, Ordering::Relaxed);
    LAST_MONO_US.store(0, Ordering::Relaxed);
    LAST_SYNC.store(SYNC_UNKNOWN, Ordering::Relaxed);
}
