//! Sys domain — HAL seam, critical-section guard, errno, kernel log ring,
//! resource ledger.

pub mod errno;
pub mod guard;
pub mod hal;
pub mod log_ring;
pub mod resource_ledger;
pub mod telemetry_ring;
