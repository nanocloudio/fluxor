//! The processor as a set of cores: which one is running, how a core
//! number maps to an MPIDR, and the exception level a core entered at (the
//! drop from EL2 to EL1 itself is `arch::el2_drop`).

use core::sync::atomic::{AtomicU32, Ordering};

/// The MPIDR shift, as a symbol so assembly can read it too. The platform
/// sets it before the MMU is on, so the store is in memory, not a cache,
/// and a secondary core's entry stub reads it with its own MMU still off.
pub static CORE_ID_SHIFT: AtomicU32 = AtomicU32::new(8);

/// Which MPIDR affinity level holds the core number on this machine: the
/// shift of that field (`8` for Aff1, as on the Pi 5; `0` for Aff0, as
/// QEMU's `virt` machine numbers its cores). Set by the platform at boot,
/// before any reader runs: bcm2712 before its MMU is on, uefi once ACPI has
/// listed the cores and before its timer or a secondary starts.
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

/// Make this core's earlier stores visible to the other cores, then wake
/// every core waiting in [`wait_for_event`].
#[inline(always)]
pub fn signal_cores() {
    // SAFETY: DMB + SEV are architectural hints; no memory effects.
    unsafe { core::arch::asm!("dmb ish", "sev", options(nostack)) };
}

/// Park this core until an event ([`signal_cores`]) or an interrupt.
#[inline(always)]
pub fn wait_for_event() {
    // SAFETY: WFE halts the core until an event; hint-only.
    unsafe { core::arch::asm!("wfe", options(nostack)) };
}

/// Park this core until an interrupt is pending.
#[inline(always)]
pub fn wait_for_interrupt() {
    // SAFETY: WFI halts the core until an interrupt; hint-only.
    unsafe { core::arch::asm!("wfi", options(nostack)) };
}

/// Whether this core entered the kernel at EL2 (the entry level the drop
/// recorded, `arch::el2_drop`), so the kernel itself set what EL2 traps
/// from EL1 on the way down. A core entered at EL1 runs under something the
/// kernel cannot ask: a hypervisor, or firmware that kept EL2.
#[inline(always)]
pub fn entered_at_el2() -> bool {
    let entry: u64;
    // SAFETY: an EL1 software register with no side effects.
    unsafe { core::arch::asm!("mrs {}, tpidr_el1", out(reg) entry, options(nomem, nostack)) };
    entry == crate::arch::el2_drop::ENTRY_EL2
}
