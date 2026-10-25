//! PCIe Scan — diagnostic report of the PCIe devices the kernel enumerated
//! on BCM2712.
//!
//! This module is diagnostic-only: drivers bind devices through the
//! `PCIE_DEVICE` contract
//! (`provider_open(PCIE_DEVICE, BIND, <selector>)`), which consults
//! the board-local alias table in `src/platform/<chip>/pcie_aliases.rs`.
//! Include `pcie_scan` in a config when you want human-readable
//! enumeration output for bring-up.
//!
//! It reads the kernel's device table (`PCIE_CFG_READ32` by table index)
//! and touches no controller itself: config cycles go through each root
//! complex's index/data registers, which only the kernel drives, under its
//! own lock. It never sizes a BAR either — sizing writes a live device's
//! BAR — and reports BAR0 as the device decodes it. The kernel's table holds
//! the devices behind PCIe1 (the external connector) and nothing behind
//! PCIe2, whose RP1 the firmware brings up. When the table is empty it asks
//! the kernel to rescan (`PCIE_RESCAN`), once a second for up to five
//! seconds: PCIe1's link can train after boot's own scan, and with no device
//! in the table none can be bound, so a rescan disturbs no driver. On QEMU
//! virt the kernel serves no config read, so it reports no devices.
//!
//! Emits a 16-byte record per device on `devices`:
//!   `[bus:u8, index:u8, func:u8, nic_type:u8,
//!     vendor_id:u16 LE, device_id:u16 LE, bar0:u64 LE]`
//! `bus` is 1 (the bus behind the PCIe1 root port), `index` the kernel
//! table index (what `PCIE_CFG_READ32` takes), `func` 0, and `bar0` the
//! memory BAR0 register (both halves of a 64-bit one) with its flag bits
//! cleared: a PCI bus address, which the outbound window places in CPU
//! space; 0 for an I/O BAR.
//!
//! Exports module_deferred_ready: downstream diagnostic consumers wait
//! for the report before draining the `devices` channel.

#![no_std]
#![allow(
    dead_code,
    reason = "the PIC build mounts the whole of modules/sdk/* via include!, so every \
              module's compile sees the entire ABI surface while using a subset. This \
              allow is the SDK's textual mounting showing through"
)]
#![allow(
    unused_imports,
    reason = "same cause: the mounted SDK brings names this module does not reach for"
)]
#![allow(
    unreachable_patterns,
    reason = "defensive `_ => Error` arms in enum state-machine matches. The match is \
              exhaustive, which is why the lint fires; the arm exists so that adding a \
              variant cannot silently bypass the error path. #[expect] is not the \
              alternative — it fails the build in the configurations where the lint \
              does not fire"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

// ============================================================================
// Constants
// ============================================================================

/// Re-enumerate a controller (`pcie_config::PCIE_RESCAN`).
const PCIE_RESCAN: u32 = 0x0CF5;

/// Devices reported, at most.
const MAX_DEVICES: usize = 8;
/// Rescans asked for while the table is empty, one per interval.
const MAX_RESCANS: u8 = 5;
const RESCAN_INTERVAL_MS: u64 = 1000;

/// PCI class 0x01_08_02: mass storage / NVM / NVMe.
const CLASS_NVME: u32 = 0x01_08_02;

// NIC type IDs
const NIC_RP1_GEM: u8 = 0;
const NIC_E810: u8 = 1;
const NIC_CX5: u8 = 2;
const NIC_UNKNOWN: u8 = 0xFF;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct PcieScanState {
    syscalls: *const SyscallTable,
    out_chan: i32,
    rescans: u8,
    reported: u8,
    _pad: [u8; 2],
    last_rescan_ms: u64,
}

// ============================================================================
// Device identification
// ============================================================================

fn identify_nic(vendor: u16, device: u16) -> u8 {
    // RP1 on Pi 5: vendor 0x1de4, device 0x0001
    if vendor == 0x1de4 && device == 0x0001 {
        return NIC_RP1_GEM;
    }
    // Intel E810 100GbE
    if vendor == 0x8086 && (device == 0x1592 || device == 0x1593) {
        return NIC_E810;
    }
    // Mellanox ConnectX-5
    if vendor == 0x15B3 && (device == 0x1017 || device == 0x1019) {
        return NIC_CX5;
    }
    NIC_UNKNOWN
}

// ============================================================================
// Report
// ============================================================================

unsafe fn log_line(sys: &SyscallTable, level: u8, line: &[u8]) {
    dev_log(sys, level, line.as_ptr(), line.len());
}

/// Whether the kernel's table holds a device at index 0. An index past the
/// table reads all-ones, as a missing responder does.
unsafe fn table_populated(sys: &SyscallTable) -> bool {
    dev_pcie_cfg_read32(sys, 0, 0x00) != 0xFFFF_FFFF
}

/// Emit one record per device in the kernel's table, and warn when more
/// than one NVMe controller is present (the NVMe driver binds one, by alias).
unsafe fn report(s: &mut PcieScanState) {
    let sys = &*s.syscalls;
    let mut nvme_count = 0u8;
    let mut idx = 0u8;
    while (idx as usize) < MAX_DEVICES {
        let id = dev_pcie_cfg_read32(sys, idx, 0x00);
        if id == 0xFFFF_FFFF {
            break;
        }
        let vendor_id = (id & 0xFFFF) as u16;
        let device_id = (id >> 16) as u16;
        let class_code = dev_pcie_cfg_read32(sys, idx, 0x08) >> 8;
        if class_code == CLASS_NVME {
            nvme_count = nvme_count.saturating_add(1);
        }
        let bar_lo = dev_pcie_cfg_read32(sys, idx, 0x10);
        let mut bar0 = 0u64;
        if bar_lo & 1 == 0 {
            bar0 = (bar_lo & 0xFFFF_FFF0) as u64;
            if (bar_lo >> 1) & 3 == 2 {
                bar0 |= (dev_pcie_cfg_read32(sys, idx, 0x14) as u64) << 32;
            }
        }

        if s.out_chan >= 0 {
            let mut msg = [0u8; 16];
            let mp = msg.as_mut_ptr();
            *mp = 1;
            *mp.add(1) = idx;
            *mp.add(2) = 0;
            *mp.add(3) = identify_nic(vendor_id, device_id);
            let vid = vendor_id.to_le_bytes();
            *mp.add(4) = vid[0];
            *mp.add(5) = vid[1];
            let did = device_id.to_le_bytes();
            *mp.add(6) = did[0];
            *mp.add(7) = did[1];
            let bb = bar0.to_le_bytes();
            let mut k = 0usize;
            while k < 8 {
                *mp.add(8 + k) = bb[k];
                k += 1;
            }
            (sys.channel_write)(s.out_chan, mp, 16);
        }
        idx += 1;
    }

    if nvme_count > 1 {
        log_line(
            sys,
            2,
            b"[pcie_scan] multiple NVMe controllers: bind one by alias, @class=nvme is refused",
        );
    }
    if idx == 0 {
        log_line(sys, 2, b"[pcie_scan] no devices");
    } else {
        log_line(sys, 3, b"[pcie_scan] enumeration done");
    }
}

// ============================================================================
// Module ABI
// ============================================================================

#[unsafe(no_mangle)]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> u32 {
    1
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<PcieScanState>()
}

/// # Safety
/// Kernel module-ABI entry point: `syscalls` is the kernel's syscall table,
/// valid for the module's lifetime.
#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    _in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if syscalls.is_null() || state.is_null() {
        return -1;
    }
    if state_size < core::mem::size_of::<PcieScanState>() {
        return -2;
    }
    let s = &mut *(state as *mut PcieScanState);
    s.syscalls = syscalls as *const SyscallTable;
    s.out_chan = out_chan;
    s.rescans = 0;
    s.reported = 0;
    s.last_rescan_ms = 0;
    0
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut PcieScanState);
    if s.reported != 0 {
        return 0;
    }
    let sys = &*s.syscalls;
    if !table_populated(sys) && s.rescans < MAX_RESCANS {
        let now = dev_millis(sys);
        if s.rescans == 0 || now.wrapping_sub(s.last_rescan_ms) >= RESCAN_INTERVAL_MS {
            s.last_rescan_ms = now;
            s.rescans += 1;
            let _ = (sys.provider_call)(-1, PCIE_RESCAN, core::ptr::null_mut(), 0);
        }
        if !table_populated(sys) {
            return 0;
        }
    }
    report(s);
    s.reported = 1;
    3 // Ready — unblock downstream
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/runtime/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/runtime/wasm_entry.rs");
