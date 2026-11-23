//! The EL2 to EL1 drop of an AArch64 entry path, and what it leaves for the
//! kernel to read.
//!
//! Some firmware hands a core over at EL2 (the Pi 5's Trusted Firmware),
//! some at EL1 (a hypervisor's guest). Each entry path — the boot core's
//! `_start`, a secondary core arriving from PSCI — runs the same drop, so
//! it is one piece of assembly, [`drop_to_el1`](crate::drop_to_el1), not
//! two copies.
//!
//! Compiled on every build: the drop is assembly text and the rest is
//! arithmetic, so a host test reads both. Only an AArch64 entry path
//! assembles the text.

/// The exception level a core entered the kernel at, as
/// [`drop_to_el1`](crate::drop_to_el1) left it in `TPIDR_EL1`: a register
/// the architecture gives EL1 for its own use, which the kernel uses for
/// nothing else.
pub const ENTRY_EL1: u64 = 1;
pub const ENTRY_EL2: u64 = 2;

/// Whether `ID_AA64DFR0_EL1` names the architecture's performance monitors:
/// `PMUVer` neither 0 (none) nor 0xF (implementation defined).
pub const fn has_monitors(id_aa64dfr0: u64) -> bool {
    let pmuver = (id_aa64dfr0 >> 8) & 0xF;
    pmuver != 0 && pmuver != 0xF
}

/// The EL2 → EL1h drop as assembly text for an entry path.
///
/// At EL2: disable the EL2 MMU and caches (`SCTLR_EL2.{M,C,I}`), make EL1
/// AArch64 (`HCR_EL2.RW`), give EL1 the physical counter and timer
/// (`CNTHCTL_EL2.{EL1PCTEN,EL1PCEN}`, with `CNTVOFF_EL2` zero so the
/// virtual counter equals the physical one), give EL1 the performance
/// monitors untrapped, record the entry level ([`ENTRY_EL2`] in
/// `TPIDR_EL1`), and `eret` to the label with DAIF masked on SP_EL1.
///
/// `MDCR_EL2` is written whole: no trap of the monitors or of debug
/// registers (`TPM`, `TPMCR`, `TDA`, `TDE` and the rest clear) and every
/// event counter EL1's (`HPMN`, bits 4:0, = `PMCR_EL0.N`, bits 15:11). A
/// core without monitors ([`has_monitors`]) gets zero, and its `PMCR_EL0`
/// is never read.
///
/// At EL1 already: record [`ENTRY_EL1`] and branch to the same label. What
/// EL2 traps is then not the kernel's to set or to read.
///
/// The two scratch registers and the label are the caller's, so the macro
/// fits whatever the surrounding code has free. `$label` is a local-label
/// reference such as `"2f"`; the caller places `"2:"` right after the
/// expansion. The macro's own local labels are 7701 and 7702.
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
            "b.eq 7701f\n",
            "mov ",
            $t0,
            ", #1\n",
            "msr tpidr_el1, ",
            $t0,
            "\n",
            "b ",
            $label,
            "\n",
            "7701:\n",
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
            // MDCR_EL2: nothing trapped; HPMN = PMCR_EL0.N where the core
            // has performance monitors, else zero.
            "mrs ",
            $t0,
            ", id_aa64dfr0_el1\n",
            "ubfx ",
            $t0,
            ", ",
            $t0,
            ", #8, #4\n",
            "cmp ",
            $t0,
            ", #0xf\n",
            "csel ",
            $t0,
            ", xzr, ",
            $t0,
            ", eq\n",
            "cbz ",
            $t0,
            ", 7702f\n",
            "mrs ",
            $t0,
            ", pmcr_el0\n",
            "ubfx ",
            $t0,
            ", ",
            $t0,
            ", #11, #5\n",
            "7702:\n",
            "msr mdcr_el2, ",
            $t0,
            "\n",
            // The entry level, for `cpu::entered_at_el2`.
            "mov ",
            $t0,
            ", #2\n",
            "msr tpidr_el1, ",
            $t0,
            "\n",
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
