//! Chip abstraction layer — Linux hosted target.
//!
//! Provides equivalent constants to the RP generated chip_generated.rs
//! and the BCM2712 chip module. No real hardware — generous arena sizes.

pub const STATE_ARENA_SIZE: usize = 256 * 1024;
pub const BUFFER_ARENA_SIZE: usize = 128 * 1024;
pub const MAX_MODULE_CONFIG_SIZE: usize = 16 * 1024;
