//! PSCI: the firmware's power-state interface, reached through whichever
//! conduit the machine's firmware answers on.
//!
//! A secure monitor at EL3 (the Pi 5's Trusted Firmware) takes `smc`; a
//! hypervisor (QEMU `virt`) takes `hvc`. The platform tells this module
//! which ([`configure`]) before the first call; `bcm2712.rs` passes a
//! per-board constant.

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
/// The SMC Calling Convention lets the firmware return results in x0–x3
/// and, before SMCCC v1.1, leave x4–x17 unpredictable, so all of them are
/// clobbers. Not `nomem`: the firmware acts on memory the caller published
/// (a woken core runs code and reads data the caller wrote), so the
/// compiler must not move the caller's stores past the call.
///
/// # Safety
/// A secure-monitor or hypervisor call with whatever effect the function
/// has; the caller owns the state it changes.
unsafe fn call(fid: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let ret: u64;
    macro_rules! conduit {
        ($insn:literal) => {
            core::arch::asm!(
                $insn,
                inout("x0") fid => ret,
                inout("x1") a1 => _,
                inout("x2") a2 => _,
                inout("x3") a3 => _,
                out("x4") _, out("x5") _, out("x6") _, out("x7") _,
                out("x8") _, out("x9") _, out("x10") _, out("x11") _,
                out("x12") _, out("x13") _, out("x14") _, out("x15") _,
                out("x16") _, out("x17") _,
                options(nostack),
            )
        };
    }
    if HVC.load(Ordering::Relaxed) {
        conduit!("hvc #0");
    } else {
        conduit!("smc #0");
    }
    ret
}

/// Start the core `target_mpidr` names at `entry_point` with `context_id`
/// in x0, MMU off, at the EL the firmware hands cores over at. Returns
/// the PSCI status: 0 on success, negative on refusal (`-2`
/// `INVALID_PARAMETERS` for an MPIDR that names no core, `-4`
/// `ALREADY_ON`).
///
/// # Safety
/// `entry_point` must be the physical address of code prepared to run on a
/// cold core (no MMU, no stack), and whatever it reads with its MMU off
/// must be at the point of coherency before this call.
pub unsafe fn cpu_on(target_mpidr: u64, entry_point: u64, context_id: u64) -> i32 {
    call(CPU_ON, target_mpidr, entry_point, context_id) as i32
}
