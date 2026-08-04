//! Sys domain — HAL seam, critical-section guard, errno, kernel log ring.

pub mod errno;
pub mod guard;
pub mod hal;
pub mod log_ring;
pub mod telemetry_ring;
