//! Memory domain — allocation and demand paging.

pub mod backing;
#[cfg(any(feature = "aarch64-metal", feature = "rp"))]
pub mod carve;
pub mod elastic;
pub mod heap;
pub mod page_pool;
pub mod pool_plan;
pub mod table;
