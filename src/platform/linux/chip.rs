//! Chip abstraction layer — Linux hosted target.
//!
//! Kernel capacity (arenas, module slots, heap segments, the log ring) is
//! stated per kernel platform in `kernel::config`, not here.

/// Default step deadline: 2 ms.
pub const DEFAULT_STEP_DEADLINE_US: u32 = 2000;
