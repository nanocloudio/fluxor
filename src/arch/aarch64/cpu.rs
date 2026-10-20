//! The processor as a set of cores: which one is running, how a core
//! number maps to an MPIDR, and the drop from EL2 to EL1 at entry.
//!
//! Some firmware hands a core over at EL2 (the Pi 5's Trusted Firmware),
//! some at EL1 (a hypervisor's guest). Each entry path — the boot core's
//! `_start`, a secondary core arriving from PSCI — runs the same drop, so
//! it is one piece of assembly, [`drop_to_el1`], not two copies.

use core::sync::atomic::{AtomicU32, Ordering};

/// The MPIDR shift, as a symbol so assembly can read it too. The platform
/// sets it before the MMU is on, so the store is in memory, not a cache,
/// and a secondary core's entry stub reads it with its own MMU still off.
pub static CORE_ID_SHIFT: AtomicU32 = AtomicU32::new(8);

/// Which MPIDR affinity level holds the core number on this machine: the
/// shift of that field (`8` for Aff1, as on the Pi 5; `0` for Aff0, as
/// QEMU's `virt` machine numbers its cores). Set by the platform at boot,
/// before the MMU is enabled.
pub fn configure_core_id(mpidr_shift: u32) {
    CORE_ID_SHIFT.store(mpidr_shift, Ordering::Relaxed);
}

/// The configured MPIDR shift.
#[inline(always)]
pub fn core_id_shift() -> u32 {
    CORE_ID_SHIFT.load(Ordering::Relaxed)
}

/// Current core number, from the configured MPIDR affinity level.
#[inline(always)]
pub fn current_core_id() -> u8 {
    let mpidr: u64;
    // SAFETY: `mrs mpidr_el1` reads a per-CPU system register; no operands.
    unsafe {
        core::arch::asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nomem, nostack));
    }
    ((mpidr >> core_id_shift()) & 0xFF) as u8
}

/// The MPIDR a PSCI call names core `core_id` by, on this machine.
#[inline(always)]
pub fn mpidr_for_core(core_id: u8) -> u64 {
    (core_id as u64) << core_id_shift()
}

/// The EL2 → EL1h drop as assembly text for an entry path: if the core is
/// at EL2, disable the EL2 MMU and caches (`SCTLR_EL2.{M,C,I}`), make EL1
/// AArch64 (`HCR_EL2.RW`), give EL1 the physical counter and timer
/// (`CNTHCTL_EL2.{EL1PCTEN,EL1PCEN}`, with `CNTVOFF_EL2` zero so the
/// virtual counter equals the physical one), and `eret` to the label with
/// DAIF masked on SP_EL1; if it is already at EL1, branch to the same label. The two scratch
/// registers and the label are the caller's, so the macro fits whatever
/// the surrounding code has free. `$label` is a local-label reference such
/// as `"2f"`; the caller places `"2:"` right after the expansion.
#[macro_export]
macro_rules! drop_to_el1 {
    ($t0:literal, $t1:literal, $label:literal) => {
        concat!(
            "mrs ",
            $t0,
            ", CurrentEL\n",
            "cmp ",
            $t0,
            ", #(2 << 2)\n",
            "b.ne ",
            $label,
            "\n",
            // At EL2: disable EL2 MMU/caches and prepare an eret to EL1h.
            "mrs ",
            $t0,
            ", sctlr_el2\n",
            "bic ",
            $t0,
            ", ",
            $t0,
            ", #(1 << 0)\n",
            "bic ",
            $t0,
            ", ",
            $t0,
            ", #(1 << 2)\n",
            "bic ",
            $t0,
            ", ",
            $t0,
            ", #(1 << 12)\n",
            "msr sctlr_el2, ",
            $t0,
            "\n",
            "isb\n",
            // HCR_EL2.RW = 1: EL1 is AArch64.
            "mrs ",
            $t0,
            ", hcr_el2\n",
            "mov ",
            $t1,
            ", #(1 << 31)\n",
            "orr ",
            $t0,
            ", ",
            $t0,
            ", ",
            $t1,
            "\n",
            "msr hcr_el2, ",
            $t0,
            "\n",
            // CNTHCTL_EL2: EL1 may use the physical timer and counter.
            "mrs ",
            $t0,
            ", cnthctl_el2\n",
            "orr ",
            $t0,
            ", ",
            $t0,
            ", #(1 << 0)\n",
            "orr ",
            $t0,
            ", ",
            $t0,
            ", #(1 << 1)\n",
            "msr cnthctl_el2, ",
            $t0,
            "\n",
            "msr cntvoff_el2, xzr\n",
            // Return state: DAIF masked, EL1h (SP_EL1).
            "mov ",
            $t0,
            ", #0x3c5\n",
            "msr spsr_el2, ",
            $t0,
            "\n",
            "adr ",
            $t0,
            ", ",
            $label,
            "\n",
            "msr elr_el2, ",
            $t0,
            "\n",
            "eret",
        )
    };
}
