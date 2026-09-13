//! Common bare-metal graph lifecycle — the steps every bare-metal platform
//! must perform identically, extracted so that "identically" is enforced by
//! there being one copy rather than asserted in a comment.
//!
//! Two steps live here, both of which every bare-metal platform must do the
//! same way:
//!
//! - owner-plan application, before any provider handle is opened;
//! - bounded pending-module completion, under one budget.
//!
//! The rest of the boot sequence is still platform-owned. It is expressed as
//! shared functions rather than a platform trait because the steps that
//! genuinely differ have not settled, and a trait spanning them would fix one
//! platform's shape as the contract for both.

use crate::kernel::workload::owner_plan;

/// Apply the staged owner plan, or re-apply the retained one.
///
/// **Ordering is the whole point.** `prepare_graph` resets every module to
/// the system owner, and `module_new` records provider handles under the
/// module's owner *at open time*. So ownership must be live before the
/// instantiation loop runs, or those handles are permanently system-owned
/// and silently bypass tenant isolation. On a rebuild this also re-applies
/// the retained plan, so an ordinary rebuild cannot drop isolation.
///
/// Fails closed: a staged-but-invalid plan must reject the graph rather than
/// run it unowned. A caller that cannot panic should still refuse to
/// activate — running a graph with isolation disabled is the one outcome
/// this function exists to prevent.
///
/// With no plan ever staged, this is `Ok(0)` and costs nothing, which is why
/// a platform with no owner-plan path of its own should still call it: it
/// gains the step for free and cannot later acquire plans without it.
pub fn apply_owner_plan() -> Result<usize, owner_plan::PlanError> {
    owner_plan::apply_staged()
}

/// Poll budget for a module whose instantiation returned `Pending`.
///
/// One budget for every bare-metal platform. A module that never completes
/// must fail visibly rather than wedge boot: an unbounded poll loop hangs
/// the graph with no diagnostic at all, and a budget that differs per
/// platform gives the same situation two outcomes.
///
/// # The error policy
///
/// See [`instantiation_is_fail_closed`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingBudget {
    /// Polls before the module is declared timed out.
    pub max_polls: u32,
}

impl PendingBudget {
    /// The shared default: 100 polls.
    ///
    /// The wait *between* polls is the platform's — RP sleeps a
    /// millisecond, BCM spins — so this is a poll count and not a duration
    /// until `sleep_until` is the primitive on both.
    pub const DEFAULT: Self = Self { max_polls: 100 };

    /// Whether a poll count has exhausted the budget.
    #[inline]
    pub fn exhausted(&self, polls: u32) -> bool {
        polls >= self.max_polls
    }
}

impl Default for PendingBudget {
    fn default() -> Self {
        Self::DEFAULT
    }
}

// `portable_atomic`, not `core::sync::atomic`: ARMv6-M (Cortex-M0+, RP2040)
// has no LDREX/STREX, so `core`'s `AtomicBool` offers no read-modify-write
// there and `swap` does not exist. `portable_atomic` provides it over a
// critical section on those parts and compiles to the native instruction on
// ARMv8-M and AArch64 — the same source, honestly implemented per target.
use portable_atomic::{AtomicBool, Ordering};

/// A producer-set, consumer-cleared wake flag.
///
/// The smallest primitive that cannot lose a wake. The protocol is
/// two-sided and both sides matter:
///
/// - **Producer**: [`signal`](Self::signal), then the architecture's event
///   instruction (`SEV` on Cortex-M). Latch first, event second — the reverse
///   order loses a wake whenever the consumer's `WFE` returns between them.
/// - **Consumer**: [`take`](Self::take) *before* sleeping, and again after
///   every wake. Never sleep without re-checking.
///
/// The lost-wake hazard this exists for: the consumer checks for work, finds
/// none, and is about to sleep when a producer signals. If the consumer then
/// slept unconditionally, the wake is gone and the system hangs until the
/// next unrelated interrupt. It is safe here because the architecture's event
/// register is *sticky* — a `SEV` that lands after the check but before the
/// `WFE` leaves the event register set, so the `WFE` returns immediately and
/// the caller's re-check sees the latch.
pub struct WakeLatch {
    flagged: AtomicBool,
}

impl WakeLatch {
    /// A latch with no pending wake.
    pub const fn new() -> Self {
        Self {
            flagged: AtomicBool::new(false),
        }
    }

    /// Record a wake. Idempotent: several signals before one `take` are one
    /// wake, which is correct — the consumer re-examines all its work.
    ///
    /// `Release` pairs with `take`'s `Acquire`, so whatever the producer
    /// wrote before signalling is visible to the woken consumer. On ARMv6-M
    /// the pairing is provided by `portable_atomic`'s critical section
    /// rather than by the barrier, which is stronger, not weaker.
    #[inline]
    pub fn signal(&self) {
        self.flagged.store(true, Ordering::Release);
    }

    /// Consume a pending wake, reporting whether there was one.
    #[inline]
    pub fn take(&self) -> bool {
        self.flagged.swap(false, Ordering::Acquire)
    }

    /// Whether a wake is pending, without consuming it. For assertions and
    /// diagnostics — a consumer deciding whether to sleep must use `take`,
    /// or it will sleep on a wake it just observed.
    #[inline]
    pub fn peek(&self) -> bool {
        self.flagged.load(Ordering::Acquire)
    }
}

impl Default for WakeLatch {
    fn default() -> Self {
        Self::new()
    }
}

/// Wait until `deadline_us` or a wake, whichever comes first.
///
/// Returns the `hal::WOKEN_*` flags: `WOKEN_EVENT` when the latch was set,
/// `WOKEN_DEADLINE` when the deadline passed, and both when they coincide.
///
/// `now` reads the monotonic clock and `wait` parks the core until *any*
/// event (`WFE`). Both are injected so the ordering hazards this function
/// exists to survive can be driven deterministically from a host test —
/// a lost wake reproduced only on hardware is a lost wake nobody debugs.
///
/// `wait` may return spuriously and is expected to: `WFE` wakes on any
/// event, including ones meant for something else. That is why the loop
/// re-checks rather than trusting the return.
pub fn wait_for_wake(
    latch: &WakeLatch,
    deadline_us: u64,
    mut now: impl FnMut() -> u64,
    mut wait: impl FnMut(),
) -> u32 {
    use crate::kernel::sys::hal::{WOKEN_DEADLINE, WOKEN_EVENT};
    loop {
        // Latch first: a wake that arrived while we were getting here must
        // be reported even if the deadline has also passed, or a busy
        // producer's signal is silently swallowed by a late tick.
        let event = latch.take();
        let expired = now() >= deadline_us;
        if event || expired {
            let mut reason = 0;
            if event {
                reason |= WOKEN_EVENT;
            }
            if expired {
                reason |= WOKEN_DEADLINE;
            }
            return reason;
        }
        wait();
    }
}

/// Whether a module that fails to instantiate refuses the whole graph.
///
/// **True, on every bare-metal platform.** A module that did not instantiate
/// has unwired ports: its consumers block forever and its producers write
/// into nothing. A graph running in that state is not a degraded version of
/// the requested graph, it is a different one that nobody asked for — and it
/// fails at the point of use, far from the cause.
///
/// This matches the rest of the kernel: the owner plan refuses rather than
/// running a graph unowned, for the same reason.
///
/// The cost is worth stating. A deployment carrying a module that fails to
/// instantiate does not boot, where it might otherwise have run degraded.
/// That is the intent — it turns a silent, permanent misconfiguration into a
/// loud one at the point where it can still be diagnosed.
pub const fn instantiation_is_fail_closed() -> bool {
    true
}
