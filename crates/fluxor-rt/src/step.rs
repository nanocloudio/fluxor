//! What a module's `module_step` answers.

use fluxor_abi::kernel_abi::step_return;

/// A `module_step` answer: one of the named outcomes, or an error.
///
/// It is the `i32` the kernel reads (`fluxor_abi::kernel_abi::step_return`,
/// anything else an error), so `module_step` returns it straight across the
/// ABI.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StepReturn(i32);

#[allow(
    non_upper_case_globals,
    reason = "the outcomes read as the variants they are: `StepReturn::Ready`"
)]
impl StepReturn {
    /// More work is possible on later ticks.
    pub const Continue: Self = Self(step_return::CONTINUE);
    /// Finished: the module is never stepped again.
    pub const Done: Self = Self(step_return::DONE);
    /// More work now: step again this tick, up to the scheduler's burst limit.
    pub const Burst: Self = Self(step_return::BURST);
    /// Initialisation complete, outputs now meaningful: downstream may start.
    pub const Ready: Self = Self(step_return::READY);

    /// A failed step, reporting `errno` (negative); the kernel faults the
    /// module.
    pub const fn error(errno: i32) -> Self {
        Self(errno)
    }

    /// Whether this answer is an error rather than an outcome.
    pub const fn is_error(self) -> bool {
        self.0 < 0
    }

    /// The wire value.
    pub const fn raw(self) -> i32 {
        self.0
    }
}
