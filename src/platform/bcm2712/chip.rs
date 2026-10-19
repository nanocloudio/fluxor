//! Chip abstraction layer — BCM2712 (aarch64) target.
//!
//! Kernel capacity (arenas, module slots, config and log-ring sizes) is
//! stated per kernel platform in `kernel::config` (`profile_bcm2712`), not
//! here: one source of truth, so a second copy of a size such as
//! `STATE_ARENA_SIZE` cannot drift below what a module's arena demand needs
//! and fail silently on the board.

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
