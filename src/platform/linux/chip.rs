//! Chip abstraction layer — Linux hosted target.
//!
//! Capacity tunables are centralised in `abi::config::kernel`;
//! per-board profiles live there. This file is a thin re-export
//! shim so platform code can keep its existing import paths.

pub use crate::abi::config::kernel::{
    BUFFER_ARENA_SIZE, CONFIG_ARENA_SIZE, LOG_RING_CAPACITY, MAX_MODULE_CONFIG_SIZE,
    STATE_ARENA_SIZE,
};

/// Default step deadline: 2 ms.
pub const DEFAULT_STEP_DEADLINE_US: u32 = 2000;
