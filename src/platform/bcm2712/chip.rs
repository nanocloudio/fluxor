//! Chip abstraction layer — BCM2712 (aarch64) target.
//!
//! Provides equivalent constants to the RP generated chip_generated.rs.

// BCM2712 (CM5): generous arena to fit large application modules
// like Quantum's session_processor (~440KB) and topic_engine (~570KB).
pub const STATE_ARENA_SIZE: usize = 4 * 1024 * 1024;
pub const BUFFER_ARENA_SIZE: usize = 1024 * 1024;
pub const MAX_MODULE_CONFIG_SIZE: usize = 16 * 1024;
