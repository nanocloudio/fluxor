//! Chip abstraction layer — the `uefi` runtime.
//!
//! Kernel capacity is stated in `kernel::config` (`profile_uefi`).

/// Default step deadline on the server cores this runtime targets: 2 ms.
#[cfg(not(feature = "board-qemu-uefi"))]
pub const DEFAULT_STEP_DEADLINE_US: u32 = 2000;

/// On QEMU: ten times the hardware figure, as on bcm2712's QEMU build. The guard
/// reads the virtual counter, which runs on while the guest waits on its
/// emulator: every access to an emulated device, and the user network's own
/// work, holds the vCPU for as long as QEMU's main loop takes. A step that is
/// quick on silicon can measure milliseconds here. A deadline is a fault
/// threshold, not a budget, and it is scaled to the machine it runs on so that
/// it stays one.
#[cfg(feature = "board-qemu-uefi")]
pub const DEFAULT_STEP_DEADLINE_US: u32 = 20000;
