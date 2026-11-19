//! Boot domain — configuration parsing + device tree.

pub mod config;
#[cfg(feature = "dtb")]
pub mod dtb;
pub mod graph_image;
