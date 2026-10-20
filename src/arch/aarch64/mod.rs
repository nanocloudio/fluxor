//! AArch64 primitives for a bare-metal kernel at EL1: the exception
//! vectors and IRQ dispatch, the GICv2 controller, the generic timer, the
//! cores (MPIDR numbering, the EL2 → EL1 drop), PSCI, the boot-time
//! identity map, and EL0 module isolation.
//!
//! Nothing here knows which machine it runs on. The facts that differ
//! between machines — a Pi 5 and a QEMU `virt` machine, the two boards
//! `platform/bcm2712.rs` configures it for — are where the GIC is, which
//! PPI the timer raises, physical or virtual counter, `smc` or `hvc` to
//! PSCI, which MPIDR field numbers the cores, what each gigabyte of the
//! identity map holds and where a fault dump may be written. The platform
//! supplies them at boot through each module's `configure` and `set_*`
//! functions, before the first interrupt can be taken; `bcm2712.rs` passes
//! per-board constants.

pub mod boot_mmu;
pub mod cpu;
pub mod exception;
pub mod gic;
pub mod isolation;
pub mod psci;
pub mod timer;
