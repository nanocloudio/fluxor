//! AArch64 primitives for a bare-metal kernel at EL1: the exception
//! vectors and IRQ dispatch, the GICv2 controller, the generic timer, the
//! cores (MPIDR numbering, the EL2 → EL1 drop), PSCI, the boot-time
//! identity map, and EL0 module isolation.
//!
//! Nothing here knows which machine it runs on. The facts that differ
//! between a Pi 5, a QEMU `virt` machine and a UEFI instance — where the
//! GIC is, which PPI the timer raises, physical or virtual counter, where
//! a fault dump may be written, which MPIDR field numbers the cores — are
//! values the platform supplies at boot through each module's `configure`
//! and `set_*` functions, before the first interrupt can be taken. A
//! platform that learns them from firmware tables passes what it read; one
//! that knows them at build time passes constants.

pub mod boot_mmu;
pub mod cpu;
pub mod exception;
pub mod gic;
pub mod isolation;
pub mod psci;
pub mod timer;
