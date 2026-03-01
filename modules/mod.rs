//! Module trait for the poll-based runtime.
//!
//! All modules (PIC and built-in) implement [`Module`] for a uniform
//! step-based execution interface. See `docs/specs/module_spec.md` for details.

/// Outcome of a single `step()` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepOutcome {
    /// Continue running (more work possible on future ticks).
    Continue,
    /// Module completed its task (done, will not be stepped again).
    Done,
    /// Module has more immediate work — requests re-step this tick.
    /// The scheduler will call step() again up to MAX_BURST_STEPS times,
    /// stopping early if the module returns Continue, Done, or Error.
    /// Use this for compute-heavy modules that can productively do
    /// multiple chunks of work per tick (e.g. emulators catching up).
    Burst,
    /// Module initialization complete — outputs are now meaningful.
    /// One-shot signal: after returning Ready, module should return
    /// Continue/Burst as normal. The scheduler uses this to gate
    /// downstream modules until infrastructure (cyw43, ip) is ready.
    /// PIC modules return 3 for this variant.
    Ready,
}

/// Common trait for modules in the poll-based runtime.
///
/// Modules expose a `step()` function that advances state by one logical
/// step without blocking, enabling cooperative multitasking.
pub trait Module {
    /// Advance the module by one step.
    ///
    /// Returns:
    /// - `Ok(StepOutcome::Continue)` - Continue running (more work to do)
    /// - `Ok(StepOutcome::Done)` - Module completed its task (done)
    /// - `Ok(StepOutcome::Burst)` - Re-step immediately (has more work this tick)
    /// - `Ok(StepOutcome::Ready)` - Initialization complete, outputs meaningful
    /// - `Err(rc)` - Error occurred (rc is the negative return code from module_step)
    fn step(&mut self) -> Result<StepOutcome, i32>;

    /// Return the module's name for debugging/logging.
    fn name(&self) -> &'static str {
        "unknown"
    }
}
