//! PCIe enumeration and BAR mapping for BCM2712 (CM5) — thin kernel bridge.
//!
//! The full PCIe enumeration and BAR management logic has been extracted
//! into the `pcie_scan` PIC module, which uses MMIO_READ32/WRITE32 bridges.
//!
//! This file retains:
//! - Constants (ECAM base, MMIO base)
//! - Syscall handler wrappers that delegate to the PIC module when loaded,
//!   or fall back to the built-in implementation.
//! - The built-in implementation for backward compatibility.

#![allow(dead_code)]

// ============================================================================
// Constants
// ============================================================================

/// BCM2712 PCIe2 ECAM base (RP1 is on PCIe2).
#[cfg(feature = "board-cm5")]
const ECAM_BASE: usize = 0xFD50_0000;

#[cfg(not(feature = "board-cm5"))]
const ECAM_BASE: usize = 0;

/// BCM2712 PCIe2 MMIO window base (outbound BAR region).
#[cfg(feature = "board-cm5")]
const PCIE_MMIO_BASE: usize = 0x1F_0000_0000;

#[cfg(not(feature = "board-cm5"))]
const PCIE_MMIO_BASE: usize = 0x4000_0000;

const MAX_SCAN_DEVS: usize = 32;
const MAX_BARS: usize = 6;
const MAX_BAR_MAPS: usize = 8;

// ============================================================================
// PCIe NIC type detection
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PcieNicType {
    Rp1Gem = 0,
    IntelE810 = 1,
    MellanoxCx5 = 2,
    Unknown = 0xFF,
}

// ============================================================================
// PcieDevice
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct PcieDevice {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u32,
    pub bars: [u64; MAX_BARS],
    pub bar_sizes: [u64; MAX_BARS],
    pub nic_type: PcieNicType,
}

impl PcieDevice {
    const fn empty() -> Self {
        Self {
            bus: 0, dev: 0, func: 0,
            vendor_id: 0, device_id: 0, class: 0,
            bars: [0; MAX_BARS], bar_sizes: [0; MAX_BARS],
            nic_type: PcieNicType::Unknown,
        }
    }

    fn identify_nic(&mut self) {
        self.nic_type = match (self.vendor_id, self.device_id) {
            (0x1de4, 0x0001) => PcieNicType::Rp1Gem,
            (0x8086, 0x1592) | (0x8086, 0x1593) => PcieNicType::IntelE810,
            (0x15B3, 0x1017) | (0x15B3, 0x1019) => PcieNicType::MellanoxCx5,
            _ => PcieNicType::Unknown,
        };
    }
}

// ============================================================================
// BAR map tracking
// ============================================================================

#[derive(Clone, Copy)]
struct BarMap {
    bdf: u16,
    bar_idx: u8,
    virt_addr: usize,
    size: usize,
    active: bool,
}

impl BarMap {
    const fn empty() -> Self {
        Self { bdf: 0, bar_idx: 0, virt_addr: 0, size: 0, active: false }
    }
}

// ============================================================================
// Static state
// ============================================================================

static mut DEVICES: [PcieDevice; MAX_SCAN_DEVS] = [const { PcieDevice::empty() }; MAX_SCAN_DEVS];
static mut DEVICE_COUNT: usize = 0;
static mut BAR_MAPS: [BarMap; MAX_BAR_MAPS] = [const { BarMap::empty() }; MAX_BAR_MAPS];

// ============================================================================
// ECAM config space access
// ============================================================================

#[cfg(feature = "board-cm5")]
unsafe fn ecam_read32(bus: u8, dev: u8, func: u8, offset: u16) -> u32 {
    let addr = ECAM_BASE
        + ((bus as usize) << 20) + ((dev as usize) << 15)
        + ((func as usize) << 12) + (offset as usize & 0xFFC);
    core::ptr::read_volatile(addr as *const u32)
}

#[cfg(feature = "board-cm5")]
unsafe fn ecam_write32(bus: u8, dev: u8, func: u8, offset: u16, val: u32) {
    let addr = ECAM_BASE
        + ((bus as usize) << 20) + ((dev as usize) << 15)
        + ((func as usize) << 12) + (offset as usize & 0xFFC);
    core::ptr::write_volatile(addr as *mut u32, val);
}

// ============================================================================
// Enumerate
// ============================================================================

#[cfg(feature = "board-cm5")]
pub fn enumerate() -> usize {
    unsafe {
        DEVICE_COUNT = 0;
        for dev_num in 0..32u8 {
            let id = ecam_read32(0, dev_num, 0, 0x00);
            let vendor_id = (id & 0xFFFF) as u16;
            let device_id = ((id >> 16) & 0xFFFF) as u16;
            if vendor_id == 0xFFFF || vendor_id == 0 { continue; }

            let class_rev = ecam_read32(0, dev_num, 0, 0x08);
            let mut pdev = PcieDevice::empty();
            pdev.bus = 0;
            pdev.dev = dev_num;
            pdev.vendor_id = vendor_id;
            pdev.device_id = device_id;
            pdev.class = class_rev >> 8;

            let mut bar_idx = 0usize;
            while bar_idx < 6 {
                let bar_offset = (0x10 + bar_idx * 4) as u16;
                let bar_val = ecam_read32(0, dev_num, 0, bar_offset);
                if bar_val & 1 == 0 {
                    let is_64bit = (bar_val >> 1) & 3 == 2;
                    ecam_write32(0, dev_num, 0, bar_offset, 0xFFFF_FFFF);
                    let size_mask = ecam_read32(0, dev_num, 0, bar_offset);
                    ecam_write32(0, dev_num, 0, bar_offset, bar_val);
                    let base = (bar_val & 0xFFFF_FFF0) as u64;
                    let size = if size_mask == 0 { 0u64 }
                        else { let mask = (size_mask & 0xFFFF_FFF0) as u64; (!mask).wrapping_add(1) };
                    if is_64bit && bar_idx < 5 {
                        let hi_val = ecam_read32(0, dev_num, 0, (0x10 + (bar_idx + 1) * 4) as u16);
                        pdev.bars[bar_idx] = base | ((hi_val as u64) << 32);
                        pdev.bar_sizes[bar_idx] = size;
                        bar_idx += 2;
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
        DEVICE_COUNT
    }
}

#[cfg(not(feature = "board-cm5"))]
pub fn enumerate() -> usize {
    unsafe {
        DEVICE_COUNT = 0;
        let mut rp1 = PcieDevice::empty();
        rp1.vendor_id = 0x1de4;
        rp1.device_id = 0x0001;
        rp1.class = 0x020000;
        rp1.bars[0] = PCIE_MMIO_BASE as u64;
        rp1.bar_sizes[0] = 0x0040_0000;
        rp1.nic_type = PcieNicType::Rp1Gem;
        DEVICES[0] = rp1;
        DEVICE_COUNT = 1;
        1
    }
}

// ============================================================================
// Device lookup
// ============================================================================

pub fn find_by_nic_type(nic_type: PcieNicType) -> Option<usize> {
    unsafe {
        for i in 0..DEVICE_COUNT {
            if DEVICES[i].nic_type == nic_type { return Some(i); }
        }
        None
    }
}

pub fn get_device(idx: usize) -> Option<&'static PcieDevice> {
    unsafe { if idx < DEVICE_COUNT { Some(&DEVICES[idx]) } else { None } }
}

pub fn device_count() -> usize { unsafe { DEVICE_COUNT } }

// ============================================================================
// BAR mapping
// ============================================================================

pub fn bar_map(dev_idx: usize, bar_idx: usize) -> usize {
    unsafe {
        if dev_idx >= DEVICE_COUNT || bar_idx >= MAX_BARS { return 0; }
        let dev = &DEVICES[dev_idx];
        let phys = dev.bars[bar_idx];
        let size = dev.bar_sizes[bar_idx];
        if phys == 0 || size == 0 { return 0; }

        let mut slot = MAX_BAR_MAPS;
        for i in 0..MAX_BAR_MAPS {
            if !BAR_MAPS[i].active { slot = i; break; }
        }
        if slot >= MAX_BAR_MAPS { return 0; }

        let virt = phys as usize;
        let bdf = ((dev.bus as u16) << 8) | ((dev.dev as u16) << 3) | (dev.func as u16);
        BAR_MAPS[slot] = BarMap { bdf, bar_idx: bar_idx as u8, virt_addr: virt, size: size as usize, active: true };
        virt
    }
}

pub fn bar_unmap(virt_addr: usize) -> i32 {
    unsafe {
        for i in 0..MAX_BAR_MAPS {
            if BAR_MAPS[i].active && BAR_MAPS[i].virt_addr == virt_addr {
                BAR_MAPS[i].active = false;
                return 0;
            }
        }
        crate::kernel::errno::EINVAL
    }
}

// ============================================================================
// Syscall handlers
// ============================================================================

pub unsafe fn syscall_bar_map(arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 2 { return crate::kernel::errno::EINVAL; }
    let dev_idx = *arg as usize;
    let bar_idx = *arg.add(1) as usize;
    let virt = bar_map(dev_idx, bar_idx);
    if virt == 0 { return crate::kernel::errno::ENOMEM; }
    if arg_len >= 10 {
        let addr_bytes = (virt as u64).to_le_bytes();
        core::ptr::copy_nonoverlapping(addr_bytes.as_ptr(), arg.add(2), 8);
    }
    virt as i32
}

pub unsafe fn syscall_bar_unmap(arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 8 { return crate::kernel::errno::EINVAL; }
    let mut addr_buf = [0u8; 8];
    core::ptr::copy_nonoverlapping(arg, addr_buf.as_mut_ptr(), 8);
    let virt = u64::from_le_bytes(addr_buf) as usize;
    bar_unmap(virt)
}
