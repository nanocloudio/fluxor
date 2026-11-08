//! Execution domain — scheduler run loop, ISR tiers, per-step deadline guard.

/// Common bare-metal graph lifecycle shared by every bare-metal platform.
pub mod bare_metal;
/// Execution domains on cores of their own: the per-core run loop, the
/// bridges between domains, the quiesce. Every bare-metal platform with more
/// than one core.
#[cfg(all(
    feature = "smp",
    target_arch = "aarch64",
    target_os = "none",
    feature = "aarch64-metal"
))]
pub mod domains;
pub mod graph_build;
pub mod isr_tier;
pub mod scheduler;
pub mod step_guard;
