//! Chip abstraction layer — BCM2712 (aarch64) target.
//!
//! Capacity tunables are centralised in `abi::config::kernel`;
//! per-board profiles live there, not here. This file used to
//! shadow them with locally-defined values; that pattern caused
//! the cm5 silent-fail in the multi-conn refactor when the http
//! module's arena demand outgrew an out-of-date local
//! `STATE_ARENA_SIZE` here. Re-exporting from one source of truth
//! prevents the recurrence.

pub use crate::abi::config::kernel::{
    BUFFER_ARENA_SIZE, CONFIG_ARENA_SIZE, MAX_MODULE_CONFIG_SIZE, STATE_ARENA_SIZE,
};
