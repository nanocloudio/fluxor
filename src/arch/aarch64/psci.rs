//! PSCI: the firmware's power-state interface, reached through whichever
//! conduit the machine's firmware answers on.
//!
//! The Pi 5's Trusted Firmware at EL3 takes `smc`; a hypervisor's guest
//! (QEMU `virt`, a cloud instance) takes `hvc`. ACPI's FADT says which;
//! the platform tells this module ([`configure`]) before the first call.

use core::sync::atomic::{AtomicBool, Ordering};

/// How PSCI calls reach the firmware.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Conduit {
    /// `smc #0`: a secure monitor at EL3.
    Smc,
    /// `hvc #0`: a hypervisor at EL2.
    Hvc,
}

static HVC: AtomicBool = AtomicBool::new(false);

/// Choose the conduit. Called once by the platform at boot.
pub fn configure(conduit: Conduit) {
    HVC.store(conduit == Conduit::Hvc, Ordering::Relaxed);
}

/// PSCI `CPU_ON` (SMC64 function id).
const CPU_ON: u64 = 0xC400_0003;

/// A PSCI call: function id in x0, three arguments, the return value in x0.
///
/// # Safety
/// A secure-monitor or hypervisor call with whatever effect the function
/// has; the caller owns the state it changes.
unsafe fn call(fid: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let ret: u64;
    if HVC.load(Ordering::Relaxed) {
        core::arch::asm!(
            "hvc #0",
            inout("x0") fid => ret,
            in("x1") a1,
            in("x2") a2,
            in("x3") a3,
            options(nomem, nostack),
        );
    } else {
        core::arch::asm!(
            "smc #0",
            inout("x0") fid => ret,
            in("x1") a1,
            in("x2") a2,
            in("x3") a3,
            options(nomem, nostack),
        );
    }
    ret
}

/// Start the core `target_mpidr` names at `entry_point` with `context_id`
/// in x0, MMU off, at the EL the firmware hands cores over at. Returns
/// the PSCI status: 0 on success, negative on refusal.
///
/// # Safety
/// `entry_point` must be the physical address of code prepared to run on a
/// cold core (no MMU, no stack), and whatever it reads must be published
/// (`dsb sy`) before this call.
pub unsafe fn cpu_on(target_mpidr: u64, entry_point: u64, context_id: u64) -> i32 {
    call(CPU_ON, target_mpidr, entry_point, context_id) as i32
}
