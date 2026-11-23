//! Architecture primitives — the instruction-set facilities a kernel needs
//! that belong to the processor architecture rather than to any chip.
//!
//! The split this enforces: `arch` knows what a barrier, an interrupt mask
//! and an NVIC are; `platform` knows what a UART is and where it lives.
//! A file that reaches for both is a file doing two jobs.
//!
//! AArch64's bare-metal primitives — vectors, the GIC, device register
//! access, generic timer, cores, PSCI, the boot identity map, EL0 isolation —
//! live in [`aarch64`], parameterised by the platform at boot; the Cortex-M
//! primitives are the modules below.

/// A lock between cores over the exclusive accesses. Compiled wherever the
/// processor has compare-and-swap, hosts included: it is plain atomics, so a
/// host test contends for it from two threads. A target without it
/// (ARMv6-M) has no second core to exclude.
#[cfg(target_has_atomic = "32")]
pub mod core_lock;
/// Critical-section implementation for builds that do not link one.
#[cfg(feature = "rp-critical-section")]
pub mod critical_section_impl;
/// The EL2 to EL1 drop of an AArch64 entry path, as assembly text, and the
/// entry level it records. Always compiled: text and arithmetic, so a host
/// test reads the drop the kernels assemble.
pub mod el2_drop;
/// NVIC addressing arithmetic. Always compiled — it is pure arithmetic with
/// no asm, so a host `cargo test` exercises it on every architecture.
pub mod nvic;
/// The Cortex-M vector table and reset path.
pub mod vector;

/// The FP/SIMD frame around a call into module code from an AArch64 IRQ.
/// Compiled for every AArch64 build, hosted ones included, so the harness
/// drives the frame the kernel uses.
#[cfg(target_arch = "aarch64")]
pub mod fp_frame;

/// Cortex-M instruction primitives. ARM-only: `core::arch::asm!` throughout.
#[cfg(target_arch = "arm")]
pub mod cortex_m;

/// AArch64 EL1 primitives: exception vectors, the GIC, device register
/// access, generic timer, cores, PSCI, the boot identity map, EL0 isolation. Bare metal only — the
/// vectors are `global_asm!` that a hosted binary must not carry — and
/// only for the platforms that configure them.
#[cfg(all(target_arch = "aarch64", target_os = "none", feature = "aarch64-metal"))]
pub mod aarch64;
