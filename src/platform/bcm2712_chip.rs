//! Chip abstraction layer — BCM2712 (aarch64) target.
//!
//! Provides equivalent constants to the RP generated chip_generated.rs.

pub const STATE_ARENA_SIZE: usize = 256 * 1024;
pub const BUFFER_ARENA_SIZE: usize = 32 * 1024;
pub const MAX_MODULE_CONFIG_SIZE: usize = 16 * 1024;
