//! Graph instantiation as a caller-driven walk.
//!
//! Instantiating a graph means loading each module and, for the ones whose
//! providers are not ready yet, polling until they are. That polling needs a
//! wait between attempts — and the *right* wait differs between runtimes,
//! which is exactly why this is a walk the caller steps rather than a loop
//! that sleeps.
//!
//! On RP nothing else runs during graph build,
//! so a bounded spin on the monotonic clock is correct and simpler. A single
//! function containing one of those choices is wrong under the other: a
//! synchronous park on a runtime with concurrent tasks starves them — it can
//! take a board off the USB bus entirely while every host gate stays green.
//!
//! So the sequencing lives here, once, and how to wait belongs to the caller.

/// What the walk needs before it can make more progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// A module was instantiated. Call again for the next one.
    Progressed,
    /// A module's providers are not ready. Wait briefly, then call again.
    ///
    /// The caller chooses how to wait, which is the point of this type.
    NeedsPoll,
    /// Every module is instantiated; the count is the walk's result.
    Finished(i32),
    /// Instantiation failed and the graph must be refused.
    Failed(i32),
}

/// Polls a pending module may take before it is declared stuck.
///
/// Inherited from [`crate::kernel::exec::bare_metal::PendingBudget`], which
/// is where the shared default lives; repeated here only so the walk can
/// bound itself without the caller passing it in.
pub const DEFAULT_PENDING_POLLS: u32 = 100;

/// Cursor through a graph's module list.
///
/// Holds only indices and counters — the module table, edges and ports stay
/// with the scheduler, because a builder owning them would be a second place
/// they could be mutated from.
#[derive(Clone, Copy, Debug)]
pub struct GraphWalk {
    /// Next entry in the configured module list.
    next_entry: usize,
    /// How many modules have been instantiated so far.
    instantiated: usize,
    /// Entries the list holds.
    total: usize,
    /// Polls spent on the module currently pending, if any.
    polls: u32,
    /// Budget for those polls.
    budget: u32,
}

impl GraphWalk {
    /// A walk over `total` configured entries.
    pub const fn new(total: usize) -> Self {
        Self {
            next_entry: 0,
            instantiated: 0,
            total,
            polls: 0,
            budget: DEFAULT_PENDING_POLLS,
        }
    }

    /// Modules instantiated so far.
    pub const fn instantiated(&self) -> usize {
        self.instantiated
    }

    /// The entry the walk will look at next.
    pub const fn next_entry(&self) -> usize {
        self.next_entry
    }

    /// Whether every entry has been visited.
    pub const fn is_finished(&self) -> bool {
        self.next_entry >= self.total
    }

    /// Polls spent on the module currently pending.
    pub const fn polls(&self) -> u32 {
        self.polls
    }

    /// Record that the current entry needs another poll.
    ///
    /// Returns `false` once the budget is exhausted — a module that never
    /// completes must fail visibly rather than wedge boot, which is the whole
    /// reason the budget exists.
    pub fn record_poll(&mut self) -> bool {
        self.polls = self.polls.saturating_add(1);
        self.polls < self.budget
    }

    /// Record that the current entry produced a module.
    pub fn advance_instantiated(&mut self) {
        self.next_entry += 1;
        self.instantiated += 1;
        self.polls = 0;
    }

    /// Record that the current entry held no module and was skipped.
    ///
    /// Distinct from [`advance_instantiated`](Self::advance_instantiated):
    /// an empty slot moves the cursor but must not claim a module index, or
    /// every module after it is wired to the wrong ports.
    pub fn advance_skipped(&mut self) {
        self.next_entry += 1;
        self.polls = 0;
    }

    /// The result to report when the walk finishes.
    pub const fn finish(&self) -> Step {
        Step::Finished(self.instantiated as i32)
    }
}
