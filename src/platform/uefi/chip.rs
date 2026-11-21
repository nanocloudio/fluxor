//! Chip abstraction layer — the `uefi` runtime.
//!
//! Kernel capacity is stated in `kernel::config` (`profile_uefi`).

/// Default step deadline on the server cores this runtime targets: 2 ms.
#[cfg(not(feature = "board-qemu-uefi"))]
pub const DEFAULT_STEP_DEADLINE_US: u32 = 2000;

/// On QEMU: ten times the hardware figure, as on bcm2712's QEMU build. The guard
/// reads the virtual counter, which runs on while the guest waits on its
/// emulator: every access to an emulated device, and the user network's own
/// work, holds the vCPU for as long as QEMU's event loop takes. A step that is
/// quick on silicon can measure milliseconds here. A deadline is a fault
/// threshold, not a budget, and it is scaled to the machine it runs on so that
/// it stays one.
#[cfg(feature = "board-qemu-uefi")]
pub const DEFAULT_STEP_DEADLINE_US: u32 = 20000;

/// Default budget of one interrupt-mode step, in the generic timer's
/// counter (`hal::read_cycle_count`), whose frequency the machine sets.
pub const DEFAULT_ISR_BUDGET_CYCLES: u32 = 2000;

/// Size the kernel's tables from the boot plan (`size`): this platform keeps
/// no tables of its own and plans no memory around them.
///
/// # Safety
/// Graph preparation: no module runs and nothing holds a reference into
/// any of the tables.
pub unsafe fn plan_tables(
    size: impl FnOnce() -> Result<(), crate::kernel::sys::resource_ledger::Refused>,
) -> Result<(), crate::kernel::sys::resource_ledger::Refused> {
    size()
}
