//! Boot — configuration parsing + device tree.

pub mod config;
#[cfg(feature = "dtb")]
pub mod dtb;
pub mod node_image;
