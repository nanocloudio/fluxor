//! PCIe enumeration and BAR mapping for BCM2712 (CM5).
//!
//! Provides:
//! - ECAM config space reads for PCIe device discovery
//! - BAR mapping / unmapping for device register access
//! - Device type identification (RP1, Intel E810, Mellanox ConnectX-5)
//!
//! On QEMU virt: returns a fake RP1 device for testing code paths.
//! On board-cm5: reads real ECAM at 0xFD500000 (PCIe2 controller).

#![allow(dead_code)]

// ============================================================================
// Constants
// ============================================================================

/// BCM2712 PCIe2 ECAM base (RP1 is on PCIe2).
#[cfg(feature = "board-cm5")]
const ECAM_BASE: usize = 0xFD50_0000;

/// QEMU: no real ECAM; stub returns fake devices.
#[cfg(not(feature = "board-cm5"))]
const ECAM_BASE: usize = 0;

/// BCM2712 PCIe2 MMIO window base (outbound BAR region).
#[cfg(feature = "board-cm5")]
const PCIE_MMIO_BASE: usize = 0x1F_0000_0000;

#[cfg(not(feature = "board-cm5"))]
const PCIE_MMIO_BASE: usize = 0x4000_0000;

/// Maximum devices to scan on bus 0.
const MAX_SCAN_DEVS: usize = 32;

/// Maximum BARs per device.
const MAX_BARS: usize = 6;

/// Maximum mapped BAR regions.
const MAX_BAR_MAPS: usize = 8;

// ============================================================================
// PCIe NIC type detection
// ============================================================================

/// Known NIC device types for kernel-bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PcieNicType {
    /// RP1 Cadence GEM (on Pi 5 / CM5)
    Rp1Gem = 0,
    /// Intel E810 100GbE
    IntelE810 = 1,
    /// Mellanox ConnectX-5
    MellanoxCx5 = 2,
    /// Unknown / not a known NIC
    Unknown = 0xFF,
}

// ============================================================================
// PcieDevice
// ============================================================================

/// Discovered PCIe device info.
#[derive(Debug, Clone, Copy)]
pub struct PcieDevice {
    /// Bus number.
    pub bus: u8,
    /// Device number.
    pub dev: u8,
    /// Function number.
    pub func: u8,
    /// Vendor ID.
    pub vendor_id: u16,
    /// Device ID.
    pub device_id: u16,
    /// Class code (24-bit: base class << 16 | sub << 8 | prog_if).
    pub class: u32,
    /// BAR base addresses (physical, from config space).
    pub bars: [u64; MAX_BARS],
    /// BAR sizes (bytes, 0 if unused).
    pub bar_sizes: [u64; MAX_BARS],
    /// Detected NIC type.
    pub nic_type: PcieNicType,
}

impl PcieDevice {
    const fn empty() -> Self {
        Self {
            bus: 0,
            dev: 0,
            func: 0,
            vendor_id: 0,
            device_id: 0,
            class: 0,
            bars: [0; MAX_BARS],
            bar_sizes: [0; MAX_BARS],
            nic_type: PcieNicType::Unknown,
        }
    }

    /// Identify the NIC type from vendor/device IDs.
    fn identify_nic(&mut self) {
        self.nic_type = match (self.vendor_id, self.device_id) {
            // RP1 on Pi 5: vendor 0x1de4, device 0x0001
            (0x1de4, 0x0001) => PcieNicType::Rp1Gem,
            // Intel E810 100GbE
            (0x8086, 0x1592) => PcieNicType::IntelE810,
            (0x8086, 0x1593) => PcieNicType::IntelE810,
            // Mellanox ConnectX-5
            (0x15B3, 0x1017) => PcieNicType::MellanoxCx5,
            (0x15B3, 0x1019) => PcieNicType::MellanoxCx5,
            _ => PcieNicType::Unknown,
        };
    }
}

// ============================================================================
// BAR map tracking
// ============================================================================

/// A mapped BAR region.
#[derive(Clone, Copy)]
struct BarMap {
    /// BDF (bus:dev:func packed).
    bdf: u16,
    /// BAR index.
    bar_idx: u8,
    /// Virtual address of the mapping.
    virt_addr: usize,
    /// Size of the mapping.
    size: usize,
    /// In use.
    active: bool,
}

impl BarMap {
    const fn empty() -> Self {
        Self {
            bdf: 0,
            bar_idx: 0,
            virt_addr: 0,
            size: 0,
            active: false,
        }
    }
}

// ============================================================================
// Static state
// ============================================================================

/// Discovered devices.
static mut DEVICES: [PcieDevice; MAX_SCAN_DEVS] = [const { PcieDevice::empty() }; MAX_SCAN_DEVS];
static mut DEVICE_COUNT: usize = 0;

/// BAR map slots.
static mut BAR_MAPS: [BarMap; MAX_BAR_MAPS] = [const { BarMap::empty() }; MAX_BAR_MAPS];

// ============================================================================
// ECAM config space access (board-cm5)
// ============================================================================

#[cfg(feature = "board-cm5")]
unsafe fn ecam_read32(bus: u8, dev: u8, func: u8, offset: u16) -> u32 {
    let addr = ECAM_BASE
        + ((bus as usize) << 20)
        + ((dev as usize) << 15)
        + ((func as usize) << 12)
        + (offset as usize & 0xFFC);
    core::ptr::read_volatile(addr as *const u32)
}

#[cfg(feature = "board-cm5")]
unsafe fn ecam_write32(bus: u8, dev: u8, func: u8, offset: u16, val: u32) {
    let addr = ECAM_BASE
        + ((bus as usize) << 20)
        + ((dev as usize) << 15)
        + ((func as usize) << 12)
        + (offset as usize & 0xFFC);
    core::ptr::write_volatile(addr as *mut u32, val);
}

// ============================================================================
// Enumerate (board-cm5)
// ============================================================================

/// Enumerate PCIe bus 0 and discover devices.
/// Returns number of devices found.
#[cfg(feature = "board-cm5")]
pub fn enumerate() -> usize {
    unsafe {
        DEVICE_COUNT = 0;
        for dev_num in 0..32u8 {
            let id = ecam_read32(0, dev_num, 0, 0x00);
            let vendor_id = (id & 0xFFFF) as u16;
            let device_id = ((id >> 16) & 0xFFFF) as u16;

            // 0xFFFF = no device present
            if vendor_id == 0xFFFF || vendor_id == 0 {
                continue;
            }

            let class_rev = ecam_read32(0, dev_num, 0, 0x08);
            let class_code = class_rev >> 8; // upper 24 bits

            let mut pdev = PcieDevice::empty();
            pdev.bus = 0;
            pdev.dev = dev_num;
            pdev.func = 0;
            pdev.vendor_id = vendor_id;
            pdev.device_id = device_id;
            pdev.class = class_code;

            // Read BARs
            let mut bar_idx = 0usize;
            while bar_idx < 6 {
                let bar_offset = (0x10 + bar_idx * 4) as u16;
                let bar_val = ecam_read32(0, dev_num, 0, bar_offset);

                if bar_val & 1 == 0 {
                    // Memory BAR
                    let is_64bit = (bar_val >> 1) & 3 == 2;

                    // Write all-ones to determine size
                    ecam_write32(0, dev_num, 0, bar_offset, 0xFFFF_FFFF);
                    let size_mask = ecam_read32(0, dev_num, 0, bar_offset);
                    ecam_write32(0, dev_num, 0, bar_offset, bar_val); // restore

                    let base = (bar_val & 0xFFFF_FFF0) as u64;
                    let size = if size_mask == 0 {
                        0u64
                    } else {
                        let mask = (size_mask & 0xFFFF_FFF0) as u64;
                        (!mask).wrapping_add(1)
                    };

                    if is_64bit && bar_idx < 5 {
                        let hi_offset = (0x10 + (bar_idx + 1) * 4) as u16;
                        let hi_val = ecam_read32(0, dev_num, 0, hi_offset);
                        pdev.bars[bar_idx] = base | ((hi_val as u64) << 32);
                        pdev.bar_sizes[bar_idx] = size;
                        bar_idx += 2; // skip the upper 32 bits
                        continue;
                    } else {
                        pdev.bars[bar_idx] = base;
                        pdev.bar_sizes[bar_idx] = size;
                    }
                }
                bar_idx += 1;
            }

            pdev.identify_nic();

            if DEVICE_COUNT < MAX_SCAN_DEVS {
                DEVICES[DEVICE_COUNT] = pdev;
                DEVICE_COUNT += 1;
            }
        }
        let count = DEVICE_COUNT;
        log::info!("[pcie] enumerated {} devices on bus 0", count);
        for i in 0..count {
            let d = &DEVICES[i];
            log::info!(
                "[pcie]   {:02x}:{:02x}.{} vendor={:04x} device={:04x} class={:06x}",
                d.bus, d.dev, d.func, d.vendor_id, d.device_id, d.class
            );
        }
        count
    }
}

// ============================================================================
// Enumerate (QEMU stub)
// ============================================================================

/// QEMU stub: return a fake RP1 device for testing code paths.
#[cfg(not(feature = "board-cm5"))]
pub fn enumerate() -> usize {
    unsafe {
        DEVICE_COUNT = 0;

        // Fake RP1 device
        let mut rp1 = PcieDevice::empty();
        rp1.bus = 0;
        rp1.dev = 0;
        rp1.func = 0;
        rp1.vendor_id = 0x1de4;
        rp1.device_id = 0x0001;
        rp1.class = 0x020000; // Ethernet controller
        // Fake BAR0: point to a safe MMIO area in QEMU virt address space
        rp1.bars[0] = PCIE_MMIO_BASE as u64;
        rp1.bar_sizes[0] = 0x0040_0000; // 4MB
        rp1.nic_type = PcieNicType::Rp1Gem;
        DEVICES[0] = rp1;
        DEVICE_COUNT = 1;

        log::info!("[pcie] QEMU stub: fake RP1 device at BAR0=0x{:x}", PCIE_MMIO_BASE);
        1
    }
}

// ============================================================================
// Device lookup
// ============================================================================

/// Find a device by NIC type. Returns index into DEVICES array, or None.
pub fn find_by_nic_type(nic_type: PcieNicType) -> Option<usize> {
    unsafe {
        for i in 0..DEVICE_COUNT {
            if DEVICES[i].nic_type == nic_type {
                return Some(i);
            }
        }
        None
    }
}

/// Get a device by index.
pub fn get_device(idx: usize) -> Option<&'static PcieDevice> {
    unsafe {
        if idx < DEVICE_COUNT {
            Some(&DEVICES[idx])
        } else {
            None
        }
    }
}

/// Return the number of discovered devices.
pub fn device_count() -> usize {
    unsafe { DEVICE_COUNT }
}

// ============================================================================
// BAR mapping
// ============================================================================

/// Map a device BAR into kernel virtual address space.
///
/// On CM5: The PCIe outbound window provides a direct physical mapping.
/// On QEMU: Returns the fake BAR address directly (identity-mapped).
///
/// Returns the kernel virtual address, or 0 on failure.
pub fn bar_map(dev_idx: usize, bar_idx: usize) -> usize {
    unsafe {
        if dev_idx >= DEVICE_COUNT || bar_idx >= MAX_BARS {
            return 0;
        }
        let dev = &DEVICES[dev_idx];
        let phys = dev.bars[bar_idx];
        let size = dev.bar_sizes[bar_idx];
        if phys == 0 || size == 0 {
            return 0;
        }

        // Find a free BAR map slot
        let mut slot = MAX_BAR_MAPS;
        for i in 0..MAX_BAR_MAPS {
            if !BAR_MAPS[i].active {
                slot = i;
                break;
            }
        }
        if slot >= MAX_BAR_MAPS {
            log::error!("[pcie] no free BAR map slots");
            return 0;
        }

        // On both CM5 and QEMU the physical address is identity-mapped
        // (CM5: outbound PCIe window; QEMU: flat memory model)
        let virt = phys as usize;

        let bdf = ((dev.bus as u16) << 8) | ((dev.dev as u16) << 3) | (dev.func as u16);
        BAR_MAPS[slot] = BarMap {
            bdf,
            bar_idx: bar_idx as u8,
            virt_addr: virt,
            size: size as usize,
            active: true,
        };

        log::info!(
            "[pcie] BAR{} mapped: phys=0x{:x} virt=0x{:x} size=0x{:x}",
            bar_idx, phys, virt, size
        );
        virt
    }
}

/// Unmap a previously mapped BAR region.
/// Returns 0 on success, negative errno on failure.
pub fn bar_unmap(virt_addr: usize) -> i32 {
    unsafe {
        for i in 0..MAX_BAR_MAPS {
            if BAR_MAPS[i].active && BAR_MAPS[i].virt_addr == virt_addr {
                BAR_MAPS[i].active = false;
                log::info!("[pcie] BAR unmapped: virt=0x{:x}", virt_addr);
                return 0;
            }
        }
        crate::kernel::errno::EINVAL
    }
}

// ============================================================================
// Syscall handlers (called from system_provider_dispatch)
// ============================================================================

/// NIC_BAR_MAP syscall: arg=[dev_idx:u8, bar_idx:u8] (2 bytes).
/// Returns mapped virtual address as i32 (truncated on aarch64, full on 32-bit).
/// On aarch64 with >4GB addresses, the full address is written to arg[2..10].
pub unsafe fn syscall_bar_map(arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 2 {
        return crate::kernel::errno::EINVAL;
    }
    let dev_idx = *arg as usize;
    let bar_idx = *arg.add(1) as usize;
    let virt = bar_map(dev_idx, bar_idx);
    if virt == 0 {
        return crate::kernel::errno::ENOMEM;
    }
    // Write full 64-bit address to arg buffer if space allows
    if arg_len >= 10 {
        let addr_bytes = (virt as u64).to_le_bytes();
        core::ptr::copy_nonoverlapping(addr_bytes.as_ptr(), arg.add(2), 8);
    }
    virt as i32
}

/// NIC_BAR_UNMAP syscall: arg=[virt_addr:u64 LE] (8 bytes).
pub unsafe fn syscall_bar_unmap(arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 8 {
        return crate::kernel::errno::EINVAL;
    }
    let mut addr_buf = [0u8; 8];
    core::ptr::copy_nonoverlapping(arg, addr_buf.as_mut_ptr(), 8);
    let virt = u64::from_le_bytes(addr_buf) as usize;
    bar_unmap(virt)
}
