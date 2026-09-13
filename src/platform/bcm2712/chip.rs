//! Chip abstraction layer — BCM2712 (aarch64) target.
//!
//! Capacity tunables are centralised in `abi::config::kernel`;
//! per-board profiles live there, not here. This file only
//! re-exports them: a locally-defined copy of a size such as
//! `STATE_ARENA_SIZE` can drift below what a module's arena
//! demand needs and fail silently on the board, so there is one
//! source of truth and no shadowing.

pub use crate::abi::config::kernel::{
    BUFFER_ARENA_SIZE, CONFIG_ARENA_SIZE, LOG_RING_CAPACITY, MAX_MODULE_CONFIG_SIZE,
    STATE_ARENA_SIZE,
};
