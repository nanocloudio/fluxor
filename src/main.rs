//! Fluxor — Config-driven pipeline runtime
//!
//! Platform-specific entry point selected at compile time.
//! Each platform entrypoint stays here; supporting code lives under
//! `src/platform/<name>/`.
//!
//! To add a new architecture:
//!   1. Create src/platform/<name>.rs with the entry point
//!   2. Put support modules under src/platform/<name>/
//!   3. Add a chip-<name> feature to Cargo.toml
//!   4. Add a cfg_attr / include below

#![no_std]
#![no_main]

// RP family (RP2040, RP2350A/B) — Cortex-M, embassy async runtime
#[cfg(feature = "rp")]
include!("platform/rp.rs");

// BCM2712 (Raspberry Pi 5 / CM5) — Cortex-A76, bare-metal
#[cfg(feature = "chip-bcm2712")]
include!("platform/bcm2712.rs");
