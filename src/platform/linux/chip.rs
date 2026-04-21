//! Chip abstraction layer — Linux hosted target.
//!
//! Provides equivalent constants to the RP generated chip_generated.rs
//! and the BCM2712 chip module. No real hardware — generous arena sizes.

// Linux host: generous arenas for application graphs. Quantum's
// session_processor + topic_engine + consumer_group_coordinator alone
// consume ~1.5 MB of state.
pub const STATE_ARENA_SIZE: usize = 4 * 1024 * 1024;
pub const BUFFER_ARENA_SIZE: usize = 1024 * 1024;
pub const MAX_MODULE_CONFIG_SIZE: usize = 16 * 1024;
