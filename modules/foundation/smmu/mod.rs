//! SMMU Configuration — PIC module for IOMMU setup and DMA mapping.
//!
//! Extracts SMMU/IOMMU logic from `bcm2712_smmu.rs` into a PIC module.
//! Uses the kernel's MMIO_READ32/WRITE32 bridges for register access.
//!
//! On init: configures SMMU global registers via MMIO bridge.
//! Registers as a provider for IOMMU services (SMMU_MAP_DMA / SMMU_UNMAP_DMA).
//! Exports module_deferred_ready to gate downstream until SMMU is initialized.
//!
//! On QEMU (no real SMMU): stubs all operations (identity-mapped DMA).

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

// ============================================================================
// Constants
// ============================================================================

/// MMIO bridge opcodes
const MMIO_READ32: u32 = 0x0CE4;
const MMIO_WRITE32: u32 = 0x0CE5;

/// SMMU provider opcodes (0x0CFB..0x0CFD within the 0x0Cxx range).
/// Consumers call `provider_call(-1, SMMU_MAP_DMA, ...)` and the kernel
/// routes them here via `system_provider_dispatch`.
const SMMU_MAP_DMA: u32 = 0x0CFB;
const SMMU_UNMAP_DMA: u32 = 0x0CFC;
const SMMU_FAULT_CHECK: u32 = 0x0CFD;

/// BCM2712 SMMU base address (ARM MMU-500 compatible).
const SMMU_BASE: u64 = 0xFD5D_0000;

// SMMU Global Register Space 0 offsets
const SCR0: u64 = 0x000;
const GFSR: u64 = 0x048;
const GFAR_LO: u64 = 0x040;
const GFAR_HI: u64 = 0x044;
const GFSYNR0: u64 = 0x050;
const IDR0: u64 = 0x020;
const SMR_BASE: u64 = 0x800;
const S2CR_BASE: u64 = 0xC00;

// Context bank
const CB_BASE: u64 = 0x10000;
const CB_TTBR0_LO: u64 = 0x020;
const CB_TTBR0_HI: u64 = 0x024;
const CB_TCR: u64 = 0x030;
const CB_MAIR0: u64 = 0x038;
const CB_SCTLR: u64 = 0x000;

// SCR0 bits
const SCR0_CLIENTPD: u32 = 1 << 0;
const SCR0_GFRE: u32 = 1 << 1;
const SCR0_GFIE: u32 = 1 << 2;
const SCR0_GCFGFRE: u32 = 1 << 4;
const SCR0_GCFGFIE: u32 = 1 << 5;

// S2CR types
const S2CR_TYPE_TRANS: u32 = 0;
const S2CR_TYPE_FAULT: u32 = 2;

const MAX_DMA_MAPS: usize = 32;
const MAX_STREAM_IDS: usize = 8;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct DmaMapping {
    stream_id: u16,
    _pad: u16,
    iova: u64,
    phys: u64,
    size: u64,
    active: u8,
    _pad2: [u8; 7],
}

#[repr(C)]
struct SmmuCfgState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    initialized: u8,
    is_qemu: u8,
    num_smrg: u16,
    dma_maps: [DmaMapping; MAX_DMA_MAPS],
    map_count: u16,
    _pad: [u8; 6],
}

// ============================================================================
// MMIO helpers
// ============================================================================

unsafe fn mmio_read32(sys: &SyscallTable, addr: u64) -> u32 {
    let mut buf = [0u8; 12];
    let bp = buf.as_mut_ptr();
    let ab = addr.to_le_bytes();
    *bp = ab[0]; *bp.add(1) = ab[1]; *bp.add(2) = ab[2]; *bp.add(3) = ab[3];
    *bp.add(4) = ab[4]; *bp.add(5) = ab[5]; *bp.add(6) = ab[6]; *bp.add(7) = ab[7];
    let rc = (sys.provider_call)(-1, MMIO_READ32, bp, 12);
    if rc < 0 { return 0; }
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
    (sys.provider_call)(-1, MMIO_WRITE32, bp, 12);
}

// ============================================================================
// SMMU initialization
// ============================================================================

unsafe fn smmu_init(s: &mut SmmuCfgState) {
    let sys = &*s.syscalls;

    // Probe: try reading IDR0
    let idr0 = mmio_read32(sys, SMMU_BASE + IDR0);
    if idr0 == 0 {
        // MMIO_READ32 returned 0 — probably QEMU (no SMMU)
        s.is_qemu = 1;
        s.initialized = 1;
        dev_log(sys, 3, b"[smmu_cfg] QEMU stub: no-op\0".as_ptr(), 25);
        return;
    }

    s.num_smrg = (idr0 & 0xFF) as u16;

    // Disable client port while configuring
    let mut scr0 = mmio_read32(sys, SMMU_BASE + SCR0);
    scr0 |= SCR0_CLIENTPD;
    mmio_write32(sys, SMMU_BASE + SCR0, scr0);

    // Enable global fault reporting
    scr0 |= SCR0_GFRE | SCR0_GFIE | SCR0_GCFGFRE | SCR0_GCFGFIE;
    mmio_write32(sys, SMMU_BASE + SCR0, scr0);

    // Default all stream mapping entries to fault
    let max_entries = if (s.num_smrg as usize) < 128 { s.num_smrg as usize } else { 128 };
    let mut i = 0usize;
    while i < max_entries {
        mmio_write32(sys, SMMU_BASE + S2CR_BASE + (i as u64) * 4, S2CR_TYPE_FAULT);
        i += 1;
    }

    // Re-enable client port
    scr0 &= !SCR0_CLIENTPD;
    mmio_write32(sys, SMMU_BASE + SCR0, scr0);

    s.initialized = 1;
    dev_log(sys, 3, b"[smmu_cfg] initialized\0".as_ptr(), 21);
}

// ============================================================================
// DMA mapping
// ============================================================================

unsafe fn map_dma(s: &mut SmmuCfgState, stream_id: u16, iova: u64, phys: u64, size: u64) -> i32 {
    // Find free mapping slot
    let mut slot = MAX_DMA_MAPS;
    let mut i = 0usize;
    while i < MAX_DMA_MAPS {
        let mp = s.dma_maps.as_ptr().add(i);
        if (*mp).active == 0 {
            slot = i;
            break;
        }
        i += 1;
    }
    if slot >= MAX_DMA_MAPS {
        return -12; // ENOMEM
    }

    if s.is_qemu == 0 {
        let sys = &*s.syscalls;

        // Program stream mapping: SMR for this stream_id -> context bank 0
        let smr_val = (stream_id as u32) | (1 << 31); // valid bit
        mmio_write32(sys, SMMU_BASE + SMR_BASE + (stream_id as u64) * 4, smr_val);

        // S2CR: translate using context bank 0
        mmio_write32(sys, SMMU_BASE + S2CR_BASE + (stream_id as u64) * 4, S2CR_TYPE_TRANS);

        // Setup context bank 0 with identity mapping
        let cb_base = SMMU_BASE + CB_BASE;
        mmio_write32(sys, cb_base + CB_TTBR0_LO, phys as u32);
        mmio_write32(sys, cb_base + CB_TTBR0_HI, (phys >> 32) as u32);
        // MAIR0: Normal WB-WA + Device-nGnRnE
        mmio_write32(sys, cb_base + CB_MAIR0, 0x0000_00FF);
        // TCR: 4KB granule, 39-bit VA (T0SZ=25)
        mmio_write32(sys, cb_base + CB_TCR, 25 | (0b01 << 8) | (0b01 << 10) | (0b11 << 12));
        // SCTLR: enable
        mmio_write32(sys, cb_base + CB_SCTLR, 1);
    }

    let mp = s.dma_maps.as_mut_ptr().add(slot);
    (*mp).stream_id = stream_id;
    (*mp).iova = iova;
    (*mp).phys = phys;
    (*mp).size = size;
    (*mp).active = 1;
    s.map_count += 1;
    0
}

unsafe fn unmap_dma(s: &mut SmmuCfgState, stream_id: u16, iova: u64, size: u64) -> i32 {
    let mut i = 0usize;
    while i < MAX_DMA_MAPS {
        let mp = s.dma_maps.as_mut_ptr().add(i);
        if (*mp).active != 0
            && (*mp).stream_id == stream_id
            && (*mp).iova == iova
            && (*mp).size == size
        {
            (*mp).active = 0;
            s.map_count = s.map_count.saturating_sub(1);

            if s.is_qemu == 0 {
                let sys = &*s.syscalls;
                mmio_write32(
                    sys,
                    SMMU_BASE + S2CR_BASE + (stream_id as u64) * 4,
                    S2CR_TYPE_FAULT,
                );
            }
            return 0;
        }
        i += 1;
    }
    -22 // EINVAL
}

unsafe fn check_faults(s: &mut SmmuCfgState) {
    if s.is_qemu != 0 { return; }
    let sys = &*s.syscalls;

    let gfsr_val = mmio_read32(sys, SMMU_BASE + GFSR);
    if gfsr_val == 0 { return; }

    // Read fault address and syndrome for logging
    let _far_lo = mmio_read32(sys, SMMU_BASE + GFAR_LO);
    let _far_hi = mmio_read32(sys, SMMU_BASE + GFAR_HI);
    let _synr0 = mmio_read32(sys, SMMU_BASE + GFSYNR0);

    dev_log(sys, 1, b"[smmu_cfg] FAULT detected\0".as_ptr(), 25);

    // Clear fault
    mmio_write32(sys, SMMU_BASE + GFSR, gfsr_val);
}

// ============================================================================
// Provider dispatch
// ============================================================================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn smmu_cfg_dispatch(
    state: *mut u8,
    _handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    let s = &mut *(state as *mut SmmuCfgState);

    match opcode {
        SMMU_MAP_DMA => {
            // arg=[stream_id:u16 LE, iova:u64 LE, phys:u64 LE, size:u64 LE] (26 bytes)
            if arg.is_null() || arg_len < 26 { return -22; }
            let stream_id = u16::from_le_bytes([*arg, *arg.add(1)]);
            let iova = u64::from_le_bytes([
                *arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5),
                *arg.add(6), *arg.add(7), *arg.add(8), *arg.add(9),
            ]);
            let phys = u64::from_le_bytes([
                *arg.add(10), *arg.add(11), *arg.add(12), *arg.add(13),
                *arg.add(14), *arg.add(15), *arg.add(16), *arg.add(17),
            ]);
            let size = u64::from_le_bytes([
                *arg.add(18), *arg.add(19), *arg.add(20), *arg.add(21),
                *arg.add(22), *arg.add(23), *arg.add(24), *arg.add(25),
            ]);
            map_dma(s, stream_id, iova, phys, size)
        }
        SMMU_UNMAP_DMA => {
            // arg=[stream_id:u16 LE, iova:u64 LE, size:u64 LE] (18 bytes)
            if arg.is_null() || arg_len < 18 { return -22; }
            let stream_id = u16::from_le_bytes([*arg, *arg.add(1)]);
            let iova = u64::from_le_bytes([
                *arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5),
                *arg.add(6), *arg.add(7), *arg.add(8), *arg.add(9),
            ]);
            let size = u64::from_le_bytes([
                *arg.add(10), *arg.add(11), *arg.add(12), *arg.add(13),
                *arg.add(14), *arg.add(15), *arg.add(16), *arg.add(17),
            ]);
            unmap_dma(s, stream_id, iova, size)
        }
        SMMU_FAULT_CHECK => {
            check_faults(s);
            0
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
    core::mem::size_of::<SmmuCfgState>()
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32, out_chan: i32, ctrl_chan: i32,
    _params: *const u8, _params_len: usize,
    state: *mut u8, state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<SmmuCfgState>() { return -2; }

        let s = &mut *(state as *mut SmmuCfgState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.ctrl_chan = ctrl_chan;

        // Initialize SMMU
        smmu_init(s);

        dev_log(&*s.syscalls, 3, b"[smmu_cfg] ready\0".as_ptr(), 15);
        0
    }
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut SmmuCfgState);

    // Periodic fault check
    check_faults(s);

    // First step: return Ready to unblock downstream
    if s.initialized == 1 {
        s.initialized = 2;
        return 3; // Ready
    }

    0 // Continue
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
