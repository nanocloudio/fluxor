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

/// Default step deadline on the Cortex-A76: 2 ms.
#[cfg(feature = "board-pi5")]
pub const DEFAULT_STEP_DEADLINE_US: u32 = 2000;

/// QEMU virt (bcm2712 without `board-pi5`): ten times the hardware figure.
/// The guard measures the generic timer, which runs at host speed, while
/// QEMU executes guest code an order of magnitude slower than the
/// Cortex-A76 the 2 ms default is sized for, so a step the Pi 5 finishes
/// well inside 2 ms can take longer than that under emulation. A deadline is
/// a fault threshold, not a budget, and it is scaled to the machine the code
/// runs on so that it stays one.
#[cfg(not(feature = "board-pi5"))]
pub const DEFAULT_STEP_DEADLINE_US: u32 = 20000;
