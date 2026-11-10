//! Memory domain — allocation.

#[cfg(any(feature = "aarch64-metal", feature = "rp"))]
pub mod carve;
pub mod elastic;
pub mod heap;
pub mod pool_plan;
pub mod table;
