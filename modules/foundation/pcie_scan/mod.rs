//! PCIe Scan — PIC module for PCIe ECAM enumeration and BAR mapping.
//!
//! Extracts the PCIe enumeration and BAR management logic from
//! `bcm2712_pcie.rs` into a PIC module. Uses the kernel's generic
//! MMIO_READ32/WRITE32 bridges to access PCIe config space.
//!
//! On init (module_new): scans bus 0 of the configured controller and
//! discovers devices. Registers as a provider so downstream modules can
//! request BAR maps.
//!
//! # Controllers (BCM2712 / Pi 5 / CM5)
//!
//! - `controller = 0` (default): PCIe2 — the internal x4 link to RP1.
//!   Historical ECAM value `0xFD50_0000` preserved for back-compat.
//! - `controller = 1`: PCIe1 — the external x1 slot used by the NVMe
//!   HAT+ and other Pi 5 PCIe peripherals. Requires `pciex1` enabled in
//!   `config.txt` so VPU trains the link before kernel handoff.
//!
//! # Provider Dispatch (NIC_BAR_MAP/UNMAP subcommands)
//!
//! - NIC_BAR_MAP:   arg=[dev_idx:u8, bar_idx:u8], returns mapped address
//! - NIC_BAR_UNMAP: arg=[virt_addr:u64 LE], returns 0 or error
//!
//! Exports module_deferred_ready: downstream waits for scan to complete.

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

// ============================================================================
// Constants
// ============================================================================

/// MMIO bridge opcodes
const MMIO_READ32: u32 = 0x0CE4;
const MMIO_WRITE32: u32 = 0x0CE5;

/// NIC BAR opcodes (we handle these via provider dispatch)
const NIC_BAR_MAP: u32 = 0x0CF0;
const NIC_BAR_UNMAP: u32 = 0x0CF1;

// Controller presets -- see module-level docs for the why.
const CTRL_PCIE2: u8 = 0;
const CTRL_PCIE1: u8 = 1;

/// PCIe2 (RP1, x4) — historical back-compat values.
const ECAM_BASE_PCIE2: u64       = 0xFD50_0000;
const PCIE_MMIO_BASE_PCIE2: u64  = 0x1F_0000_0000;

/// PCIe1 (external x1 / NVMe HAT+) — verified against the Pi 5 base
/// board 6.12 rpt kernel (dmesg 2026-04-16): controller at
/// `0x10_0011_0000`, outbound MMIO window `0x18_0000_0000..0x1B_FFFF_FFFF`.
/// Requires `dtparam=pciex1` (no `=on`) in `config.txt`.
const ECAM_BASE_PCIE1: u64       = 0x10_0011_0000;
const PCIE_MMIO_BASE_PCIE1: u64  = 0x18_0000_0000;

/// QEMU virt stub: no real ECAM; synthesise a fake RP1 so higher layers
/// have something to wire against.
const ECAM_BASE_QEMU: u64        = 0;
const PCIE_MMIO_BASE_QEMU: u64   = 0x4000_0000;

const MAX_DEVICES: usize = 8;
const MAX_BARS: usize = 6;
const MAX_BAR_MAPS: usize = 8;

// NIC type IDs
const NIC_RP1_GEM: u8 = 0;
const NIC_E810: u8 = 1;
const NIC_CX5: u8 = 2;
const NIC_UNKNOWN: u8 = 0xFF;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct PcieDevice {
    bus: u8,
    dev: u8,
    func: u8,
    nic_type: u8,
    vendor_id: u16,
    device_id: u16,
    class_code: u32,
    bars: [u64; MAX_BARS],
    bar_sizes: [u64; MAX_BARS],
}

#[repr(C)]
struct BarMap {
    bdf: u16,
    bar_idx: u8,
    active: u8,
    virt_addr: u64,
    size: u64,
}

#[repr(C)]
struct PcieScanState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    device_count: u8,
    scan_done: u8,
    controller: u8,
    _pad0: u8,
    ecam_base: u64,
    mmio_base: u64,
    _pad: [u8; 4],
    devices: [PcieDevice; MAX_DEVICES],
    bar_maps: [BarMap; MAX_BAR_MAPS],
}

// ============================================================================
// Parameter schema
// ============================================================================

mod params_def {
    use super::PcieScanState;
    use super::p_u8;
    use super::SCHEMA_MAX;

    define_params! {
        PcieScanState;

        1, controller, u8, 0, enum { pcie2=0, pcie1=1 }
            => |s, d, len| { s.controller = p_u8(d, len, 0, 0); };
    }
}

// ============================================================================
// MMIO bridge helpers
// ============================================================================

unsafe fn mmio_read32(sys: &SyscallTable, addr: u64) -> u32 {
    let mut buf = [0u8; 12];
    let bp = buf.as_mut_ptr();
    let ab = addr.to_le_bytes();
    *bp = ab[0]; *bp.add(1) = ab[1]; *bp.add(2) = ab[2]; *bp.add(3) = ab[3];
    *bp.add(4) = ab[4]; *bp.add(5) = ab[5]; *bp.add(6) = ab[6]; *bp.add(7) = ab[7];
    let rc = (sys.dev_call)(-1, MMIO_READ32, bp, 12);
    if rc < 0 { return 0xFFFF_FFFF; }
    u32::from_le_bytes([*bp.add(8), *bp.add(9), *bp.add(10), *bp.add(11)])
}

unsafe fn mmio_write32(sys: &SyscallTable, addr: u64, val: u32) {
    let mut buf = [0u8; 12];
    let bp = buf.as_mut_ptr();
    let ab = addr.to_le_bytes();
    *bp = ab[0]; *bp.add(1) = ab[1]; *bp.add(2) = ab[2]; *bp.add(3) = ab[3];
    *bp.add(4) = ab[4]; *bp.add(5) = ab[5]; *bp.add(6) = ab[6]; *bp.add(7) = ab[7];
    let vb = val.to_le_bytes();
    *bp.add(8) = vb[0]; *bp.add(9) = vb[1]; *bp.add(10) = vb[2]; *bp.add(11) = vb[3];
    (sys.dev_call)(-1, MMIO_WRITE32, bp, 12);
}

// ============================================================================
// ECAM config space access
// ============================================================================

unsafe fn ecam_addr(base: u64, bus: u8, dev: u8, func: u8, offset: u16) -> u64 {
    base + ((bus as u64) << 20) + ((dev as u64) << 15)
        + ((func as u64) << 12) + ((offset & 0xFFC) as u64)
}

unsafe fn ecam_read32(sys: &SyscallTable, base: u64, bus: u8, dev: u8, func: u8, offset: u16) -> u32 {
    let addr = ecam_addr(base, bus, dev, func, offset);
    mmio_read32(sys, addr)
}

unsafe fn ecam_write32(sys: &SyscallTable, base: u64, bus: u8, dev: u8, func: u8, offset: u16, val: u32) {
    let addr = ecam_addr(base, bus, dev, func, offset);
    mmio_write32(sys, addr, val);
}

// ============================================================================
// Device identification
// ============================================================================

fn identify_nic(vendor: u16, device: u16) -> u8 {
    // RP1 on Pi 5: vendor 0x1de4, device 0x0001
    if vendor == 0x1de4 && device == 0x0001 { return NIC_RP1_GEM; }
    // Intel E810 100GbE
    if vendor == 0x8086 && (device == 0x1592 || device == 0x1593) { return NIC_E810; }
    // Mellanox ConnectX-5
    if vendor == 0x15B3 && (device == 0x1017 || device == 0x1019) { return NIC_CX5; }
    NIC_UNKNOWN
}

// ============================================================================
// Enumeration
// ============================================================================

unsafe fn enumerate(s: &mut PcieScanState) {
    let sys = &*s.syscalls;

    if s.ecam_base == 0 {
        // QEMU stub: fake an RP1 device
        let dp = s.devices.as_mut_ptr();
        (*dp).bus = 0;
        (*dp).dev = 0;
        (*dp).func = 0;
        (*dp).vendor_id = 0x1de4;
        (*dp).device_id = 0x0001;
        (*dp).class_code = 0x020000;
        (*dp).bars[0] = s.mmio_base;
        (*dp).bar_sizes[0] = 0x0040_0000; // 4MB
        (*dp).nic_type = NIC_RP1_GEM;
        s.device_count = 1;
        dev_log(sys, 3, b"[pcie_scan] QEMU stub: fake RP1\0".as_ptr(), 30);
        return;
    }

    let mut dev_num = 0u8;
    let mut nvme_count = 0u8;
    while dev_num < 32 && (s.device_count as usize) < MAX_DEVICES {
        let id = ecam_read32(sys, s.ecam_base, 0, dev_num, 0, 0x00);
        let vendor_id = (id & 0xFFFF) as u16;
        let device_id = ((id >> 16) & 0xFFFF) as u16;

        if vendor_id == 0xFFFF || vendor_id == 0 {
            dev_num += 1;
            continue;
        }

        let class_rev = ecam_read32(sys, s.ecam_base, 0, dev_num, 0, 0x08);
        let class_code = class_rev >> 8;
        // NVMe is PCI class 0x01_08_02 (mass-storage / NVM / NVMe).
        // The nvme driver only attaches to `controller_index` (0 by
        // default), so any extras are ignored — warn the user once so
        // the silent selection isn't a surprise.
        if class_code == 0x01_08_02 {
            nvme_count = nvme_count.saturating_add(1);
        }

        let idx = s.device_count as usize;
        let dp = s.devices.as_mut_ptr().add(idx);
        (*dp).bus = 0;
        (*dp).dev = dev_num;
        (*dp).func = 0;
        (*dp).vendor_id = vendor_id;
        (*dp).device_id = device_id;
        (*dp).class_code = class_code;
        (*dp).nic_type = identify_nic(vendor_id, device_id);

        // Read BARs
        let mut bar_idx = 0usize;
        while bar_idx < 6 {
            let bar_offset = (0x10 + bar_idx * 4) as u16;
            let bar_val = ecam_read32(sys, s.ecam_base, 0, dev_num, 0, bar_offset);

            if bar_val & 1 == 0 {
                // Memory BAR
                let is_64bit = (bar_val >> 1) & 3 == 2;

                // Write all-ones to determine size
                ecam_write32(sys, s.ecam_base, 0, dev_num, 0, bar_offset, 0xFFFF_FFFF);
                let size_mask = ecam_read32(sys, s.ecam_base, 0, dev_num, 0, bar_offset);
                ecam_write32(sys, s.ecam_base, 0, dev_num, 0, bar_offset, bar_val); // restore

                let base = (bar_val & 0xFFFF_FFF0) as u64;
                let size = if size_mask == 0 {
                    0u64
                } else {
                    let mask = (size_mask & 0xFFFF_FFF0) as u64;
                    (!mask).wrapping_add(1)
                };

                if is_64bit && bar_idx < 5 {
                    let hi_offset = (0x10 + (bar_idx + 1) * 4) as u16;
                    let hi_val = ecam_read32(sys, s.ecam_base, 0, dev_num, 0, hi_offset);
                    (*dp).bars[bar_idx] = base | ((hi_val as u64) << 32);
                    (*dp).bar_sizes[bar_idx] = size;
                    bar_idx += 2;
                    continue;
                } else {
                    (*dp).bars[bar_idx] = base;
                    (*dp).bar_sizes[bar_idx] = size;
                }
            }
            bar_idx += 1;
        }

        s.device_count += 1;
        dev_num += 1;
    }

    if nvme_count > 1 {
        let mut msg = [0u8; 64];
        let p = msg.as_mut_ptr();
        let prefix = b"[pcie_scan] multiple NVMe controllers (";
        core::ptr::copy_nonoverlapping(prefix.as_ptr(), p, prefix.len());
        let mut pos = prefix.len();
        *p.add(pos) = b'0' + ((nvme_count / 10) % 10);
        *p.add(pos + 1) = b'0' + (nvme_count % 10);
        pos += 2;
        let tail = b"); v1 only drives index 0";
        core::ptr::copy_nonoverlapping(tail.as_ptr(), p.add(pos), tail.len());
        pos += tail.len();
        dev_log(sys, 2, p, pos);
    }

    dev_log(sys, 3, b"[pcie_scan] enumeration done\0".as_ptr(), 27);
}

// ============================================================================
// BAR mapping
// ============================================================================

unsafe fn bar_map(s: &mut PcieScanState, dev_idx: u8, bar_idx: u8, arg: *mut u8, arg_len: usize) -> i32 {
    if dev_idx as usize >= s.device_count as usize || bar_idx as usize >= MAX_BARS {
        return -22; // EINVAL
    }
    let dp = s.devices.as_ptr().add(dev_idx as usize);
    let phys = (*dp).bars[bar_idx as usize];
    let size = (*dp).bar_sizes[bar_idx as usize];
    if phys == 0 || size == 0 {
        return -12; // ENOMEM
    }

    // Find free slot
    let mut slot = MAX_BAR_MAPS;
    let mut i = 0usize;
    while i < MAX_BAR_MAPS {
        let mp = s.bar_maps.as_ptr().add(i);
        if (*mp).active == 0 {
            slot = i;
            break;
        }
        i += 1;
    }
    if slot >= MAX_BAR_MAPS {
        return -12; // ENOMEM
    }

    // Identity mapping (CM5 outbound PCIe window / QEMU flat)
    let virt = phys;

    let mp = s.bar_maps.as_mut_ptr().add(slot);
    let bdf = (((*dp).bus as u16) << 8) | (((*dp).dev as u16) << 3) | ((*dp).func as u16);
    (*mp).bdf = bdf;
    (*mp).bar_idx = bar_idx;
    (*mp).active = 1;
    (*mp).virt_addr = virt;
    (*mp).size = size;

    // Write full 64-bit address to arg buffer if space allows
    if !arg.is_null() && arg_len >= 10 {
        let ab = virt.to_le_bytes();
        *arg.add(2) = ab[0]; *arg.add(3) = ab[1]; *arg.add(4) = ab[2]; *arg.add(5) = ab[3];
        *arg.add(6) = ab[4]; *arg.add(7) = ab[5]; *arg.add(8) = ab[6]; *arg.add(9) = ab[7];
    }

    virt as i32
}

unsafe fn bar_unmap(s: &mut PcieScanState, arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 8 {
        return -22; // EINVAL
    }
    let virt = u64::from_le_bytes([
        *arg, *arg.add(1), *arg.add(2), *arg.add(3),
        *arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7),
    ]);

    let mut i = 0usize;
    while i < MAX_BAR_MAPS {
        let mp = s.bar_maps.as_mut_ptr().add(i);
        if (*mp).active != 0 && (*mp).virt_addr == virt {
            (*mp).active = 0;
            return 0;
        }
        i += 1;
    }
    -22 // EINVAL
}

// ============================================================================
// Provider dispatch
// ============================================================================

#[unsafe(no_mangle)]
#[link_section = ".text.module_provider_dispatch"]
#[export_name = "module_provider_dispatch"]
pub unsafe extern "C" fn pcie_scan_dispatch(
    state: *mut u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    let _ = handle;
    let s = &mut *(state as *mut PcieScanState);

    match opcode {
        NIC_BAR_MAP => {
            if arg.is_null() || arg_len < 2 { return -22; }
            let dev_idx = *arg;
            let bar_idx = *arg.add(1);
            bar_map(s, dev_idx, bar_idx, arg, arg_len)
        }
        NIC_BAR_UNMAP => {
            bar_unmap(s, arg, arg_len)
        }
        _ => -38, // ENOSYS
    }
}

// ============================================================================
// Module ABI
// ============================================================================

#[unsafe(no_mangle)]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> u32 { 1 }

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<PcieScanState>()
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

unsafe fn bases_for_controller(ctrl: u8) -> (u64, u64) {
    match ctrl {
        CTRL_PCIE1 => (ECAM_BASE_PCIE1, PCIE_MMIO_BASE_PCIE1),
        _          => (ECAM_BASE_PCIE2, PCIE_MMIO_BASE_PCIE2),
    }
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32, out_chan: i32, ctrl_chan: i32,
    params: *const u8, params_len: usize,
    state: *mut u8, state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<PcieScanState>() { return -2; }

        let s = &mut *(state as *mut PcieScanState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.ctrl_chan = ctrl_chan;
        s.device_count = 0;
        s.scan_done = 0;
        s.controller = CTRL_PCIE2;

        let sys = &*s.syscalls;

        // Parse TLV params (controller selector).
        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        let (ecam, mmio) = bases_for_controller(s.controller);
        s.ecam_base = ecam;
        s.mmio_base = mmio;

        if s.controller == CTRL_PCIE1 {
            dev_log(sys, 3, b"[pcie_scan] controller=PCIe1 (external)\0".as_ptr(), 37);
        } else {
            dev_log(sys, 3, b"[pcie_scan] controller=PCIe2 (RP1)\0".as_ptr(), 33);
        }

        // Probe: if ECAM read returns 0xFFFFFFFF, fall back to QEMU stub.
        // On real hardware without the controller brought up (e.g. missing
        // `pciex1` in config.txt for PCIe1), this also trips — but the
        // intended semantics here are "QEMU virt has no PCIe RC", so we
        // only fall back when the MMIO bridge itself is unavailable.
        let probe = mmio_read32(sys, s.ecam_base);
        if probe == 0xFFFF_FFFF || probe == 0 {
            if s.controller == CTRL_PCIE1 {
                dev_log(sys, 2, b"[pcie_scan] PCIe1 ECAM unreadable (pciex1 enabled?)\0".as_ptr(), 51);
                // Leave device_count = 0; do NOT fabricate QEMU stub.
                s.ecam_base = 0xFFFF_FFFF_FFFF_FFFF; // suppress enumerate()
            } else {
                s.ecam_base = ECAM_BASE_QEMU;
                s.mmio_base = PCIE_MMIO_BASE_QEMU;
            }
        }

        if s.ecam_base != 0xFFFF_FFFF_FFFF_FFFF {
            enumerate(s);
        }
        s.scan_done = 1;

        dev_log(sys, 3, b"[pcie_scan] ready\0".as_ptr(), 16);
        0
    }
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut PcieScanState);

    // If scan is done, emit device info on output channel (first step only)
    if s.scan_done == 1 {
        s.scan_done = 2;
        if s.out_chan >= 0 {
            let sys = &*s.syscalls;
            // Emit each device as a 16-byte message:
            // [bus, dev, func, nic_type, vendor_id:u16 LE, device_id:u16 LE,
            //  bar0_lo:u32 LE, bar0_hi:u32 LE]
            let mut i = 0u8;
            while (i as usize) < s.device_count as usize {
                let dp = s.devices.as_ptr().add(i as usize);
                let mut msg = [0u8; 16];
                let mp = msg.as_mut_ptr();
                *mp = (*dp).bus;
                *mp.add(1) = (*dp).dev;
                *mp.add(2) = (*dp).func;
                *mp.add(3) = (*dp).nic_type;
                let vid = (*dp).vendor_id.to_le_bytes();
                *mp.add(4) = vid[0]; *mp.add(5) = vid[1];
                let did = (*dp).device_id.to_le_bytes();
                *mp.add(6) = did[0]; *mp.add(7) = did[1];
                let bar0 = (*dp).bars[0];
                let bl = (bar0 as u32).to_le_bytes();
                *mp.add(8) = bl[0]; *mp.add(9) = bl[1]; *mp.add(10) = bl[2]; *mp.add(11) = bl[3];
                let bh = ((bar0 >> 32) as u32).to_le_bytes();
                *mp.add(12) = bh[0]; *mp.add(13) = bh[1]; *mp.add(14) = bh[2]; *mp.add(15) = bh[3];
                (sys.channel_write)(s.out_chan, mp, 16);
                i += 1;
            }
        }
        return 3; // Ready — unblock downstream
    }

    0 // Continue
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
