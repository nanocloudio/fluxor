//! Execution domain — scheduler run loop, ISR tiers, per-step deadline guard.

/// Common bare-metal graph lifecycle shared by RP and BCM2712.
pub mod bare_metal;
pub mod graph_build;
pub mod isr_tier;
pub mod scheduler;
pub mod step_guard;
