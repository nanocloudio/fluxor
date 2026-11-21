//! What a module's step answers, and the trait the scheduler steps.
//!
//! Every instance the scheduler runs (a loaded module or a native one)
//! implements [`Module`]. A loaded module answers through the
//! `module_step` wire value, whose codes are
//! `fluxor_abi::kernel_abi::step_return`; [`StepOutcome::from_wire`] is the
//! one place they are read.

use crate::abi::kernel_abi::step_return;

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
    Ready,
}

impl StepOutcome {
    /// Decode a `module_step` wire value: one of the `step_return` codes, or
    /// anything else as the error it reports.
    pub fn from_wire(rc: i32) -> Result<Self, i32> {
        match rc {
            step_return::CONTINUE => Ok(StepOutcome::Continue),
            step_return::DONE => Ok(StepOutcome::Done),
            step_return::BURST => Ok(StepOutcome::Burst),
            step_return::READY => Ok(StepOutcome::Ready),
            _ => Err(rc),
        }
    }
}

/// A slot the scheduler steps.
///
/// Each step advances the slot by one logical step without blocking, which
/// is what lets every slot share one cooperative loop.
pub trait Module {
    /// Advance the module by one step: the outcome, or `Err(rc)` with the
    /// negative code the module's step returned.
    fn step(&mut self) -> Result<StepOutcome, i32>;

    /// Refill a pipeline input between bounded graph passes. Returns true only
    /// when new work was admitted and another pass can make progress.
    fn pipeline_refill(&mut self) -> Result<bool, i32>;

    /// Ship output produced by the completed graph pass without re-running
    /// the module's input/RX path; `Ok` with nothing done for a module that
    /// has no flush hook.
    fn post_tick_flush(&mut self) -> Result<(), i32>;

    /// The slot's name, for logging.
    fn name(&self) -> &'static str;

    /// The worst-case stack depth the slot's step needs, in bytes, which the
    /// scheduler fences each step at; 0 runs it unfenced.
    fn stack_bytes(&self) -> usize;
}
