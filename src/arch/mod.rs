//! Architecture primitives — the instruction-set facilities a kernel needs
//! that belong to the processor architecture rather than to any chip.
//!
//! The split this enforces: `arch` knows what a barrier, an interrupt mask
//! and an NVIC are; `platform` knows what a UART is and where it lives.
//! A file that reaches for both is a file doing two jobs.
//!
//! AArch64's equivalents live in `platform/bcm2712`. This module is
//! Cortex-M-only rather than claiming a symmetry that does not yet exist.

/// Critical-section implementation for builds that do not link one.
#[cfg(feature = "rp-critical-section")]
mod critical_section_impl;
/// NVIC addressing arithmetic. Always compiled — it is pure arithmetic with
/// no asm, so a host `cargo test` exercises it on every architecture.
pub mod nvic;
/// The Cortex-M vector table and reset path.
pub mod vector;

/// Cortex-M instruction primitives. ARM-only: `core::arch::asm!` throughout.
#[cfg(target_arch = "arm")]
pub mod cortex_m;
