// Platform: BCM2712 PCIe bus/config access.
//
// Layer: platform/bcm2712 (chip-specific, unstable).
//
// Pre-open PCIe bring-up: raw enumeration-table config access and bus rescan
// on the brcmstb root complex. These act on a *device-enumeration index*
// before any handle is bound, and PCIE_RESCAN re-trains/re-scans a controller
// whose link trains slowly (Pi 5 PCIe1) — semantics tied to this controller's
// bring-up sequence, so they stay platform (D-HW-TAXONOMY). The generic,
// controller-independent device-access capability (handle-scoped config/BAR/
// MSI/info) is a separate surface at `contracts/hal/pcie` and is what portable
// drivers (NVMe, rp1_gem) use for real config access — these ops are not it.

/// Re-run PCIe bus enumeration. Intended for cold-boot recovery on
/// platforms where the link trains slowly (Pi 5 NVMe HAT+ PCIe1).
/// handle=-1, arg=[] (unused). Returns new device count.
pub const PCIE_RESCAN: u32 = 0x0CF5;
/// Read 32-bit word from a discovered device's PCI configuration
/// space. handle=-1, arg=[dev_idx:u8, _pad:u8, offset:u16 LE] (4 bytes
/// input). On success, writes value:u32 LE to arg[4..8]. Returns 0
/// or negative errno.
pub const PCIE_CFG_READ32: u32 = 0x0CF6;
/// Write 32-bit word to a discovered device's PCI configuration
/// space. handle=-1, arg=[dev_idx:u8, _pad:u8, offset:u16 LE,
///                        value:u32 LE] (8 bytes).
/// Returns 0 or negative errno.
pub const PCIE_CFG_WRITE32: u32 = 0x0CF7;
