//! Execution — the scheduler and its pass engine, the execution domains,
//! the interrupt execution modes, per-step deadline guard.

/// Common bare-metal graph lifecycle shared by every bare-metal platform.
pub mod bare_metal;
/// Execution domains on their cores: which core runs each domain, the
/// quiesce that parks the other cores, and, on a bare-metal platform with
/// more than one core, the per-core run loop and the bridges between cores.
pub mod domains;
pub mod graph_build;
pub mod interrupt;
pub mod irq;
pub mod scheduler;
pub mod step;
pub mod step_guard;
pub mod timer;
