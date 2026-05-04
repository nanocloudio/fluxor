//! Chip abstraction layer — Linux hosted target.
//!
//! Provides equivalent constants to the RP generated chip_generated.rs
//! and the BCM2712 chip module. No real hardware — generous arena sizes.

// Linux host: generous arenas for application graphs. Quantum's
// session_processor + topic_engine + consumer_group_coordinator alone
// consume ~1.5 MB of state.
pub const STATE_ARENA_SIZE: usize = 16 * 1024 * 1024;
// 8 MiB lets high-throughput graphs size individual channels at
// 16-64 KiB without exhausting the arena; smaller rings flap
// back-pressure under sustained gigabit-class loads.
pub const BUFFER_ARENA_SIZE: usize = 8 * 1024 * 1024;
pub const MAX_MODULE_CONFIG_SIZE: usize = 32 * 1024;
pub const CONFIG_ARENA_SIZE: usize = 64 * 1024;
