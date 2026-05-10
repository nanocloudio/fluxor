//! Chip abstraction layer — Linux hosted target.
//!
//! Capacity tunables are centralised in `abi::config::kernel`;
//! per-board profiles live there. This file is a thin re-export
//! shim so platform code can keep its existing import paths.

pub use crate::abi::config::kernel::{
    BUFFER_ARENA_SIZE, CONFIG_ARENA_SIZE, MAX_MODULE_CONFIG_SIZE, STATE_ARENA_SIZE,
};
