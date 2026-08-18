//! Module domain — PIC loader, provider dispatch, syscall surface, EL0 gateway.

pub mod el0_abi;
pub mod loader;
// OTA RAM staging surface (Pi 5 / hosted Linux). Not compiled on RP —
// its OTA path is the flash graph-slot A/B pair, and the staging
// buffers would dwarf SRAM.
#[cfg(any(feature = "chip-bcm2712", feature = "host-linux"))]
pub mod ota_stage;
pub mod provider;
pub mod syscalls;
