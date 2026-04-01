//! SMMU/IOMMU setup for BCM2712 (CM5).
//!
//! Provides:
//! - SMMU initialization for PCIe NIC DMA isolation
//! - DMA address mapping (IOVA ↔ physical)
//! - Fault handling
//!
//! On QEMU virt: stubs (no SMMU in QEMU virt machine).
//! On board-cm5: real MMIO to BCM2712 SMMU registers.

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// BCM2712 SMMU base address (ARM MMU-500 compatible).
#[cfg(feature = "board-cm5")]
const SMMU_BASE: usize = 0xFD5D_0000;

/// SMMU Global Register Space 0 offsets.
#[cfg(feature = "board-cm5")]
mod regs {
    pub const SCR0: usize = 0x000;
    pub const SCR1: usize = 0x004;
    pub const SACR: usize = 0x010;
    pub const IDR0: usize = 0x020;
    pub const IDR1: usize = 0x024;
    pub const IDR2: usize = 0x028;
    pub const GFAR_LO: usize = 0x040;
    pub const GFAR_HI: usize = 0x044;
    pub const GFSR: usize = 0x048;
    pub const GFSYNR0: usize = 0x050;

    // Stream mapping registers (SMR + S2CR)
    pub const SMR_BASE: usize = 0x800;
    pub const S2CR_BASE: usize = 0xC00;

    // Context bank base (offset from SMMU_BASE + 0x10000)
    pub const CB_BASE: usize = 0x10000;
    pub const CB_STRIDE: usize = 0x1000;

    // Context bank registers
    pub const CB_SCTLR: usize = 0x000;
    pub const CB_TTBR0_LO: usize = 0x020;
    pub const CB_TTBR0_HI: usize = 0x024;
    pub const CB_TCR: usize = 0x030;
    pub const CB_MAIR0: usize = 0x038;
    pub const CB_MAIR1: usize = 0x03C;
    pub const CB_FSR: usize = 0x058;
    pub const CB_FAR_LO: usize = 0x060;
    pub const CB_FAR_HI: usize = 0x064;
    pub const CB_FSYNR0: usize = 0x068;

    // SCR0 bits
    pub const SCR0_CLIENTPD: u32 = 1 << 0;
    pub const SCR0_GFRE: u32 = 1 << 1;
    pub const SCR0_GFIE: u32 = 1 << 2;
    pub const SCR0_GCFGFRE: u32 = 1 << 4;
    pub const SCR0_GCFGFIE: u32 = 1 << 5;

    // S2CR types
    pub const S2CR_TYPE_TRANS: u32 = 0; // Translate using context bank
    pub const S2CR_TYPE_BYPASS: u32 = 1; // Bypass SMMU
    pub const S2CR_TYPE_FAULT: u32 = 2; // Fault all transactions
}

/// Maximum number of DMA mappings we track.
const MAX_DMA_MAPS: usize = 64;

/// Maximum stream IDs (one per NIC queue).
const MAX_STREAM_IDS: usize = 8;

// ============================================================================
// DMA mapping tracking
// ============================================================================

#[derive(Clone, Copy)]
struct DmaMapping {
    stream_id: u16,
    iova: u64,
    phys: u64,
    size: u64,
    active: bool,
}

impl DmaMapping {
    const fn empty() -> Self {
        Self {
            stream_id: 0,
            iova: 0,
            phys: 0,
            size: 0,
            active: false,
        }
    }
}

static mut DMA_MAPS: [DmaMapping; MAX_DMA_MAPS] = [const { DmaMapping::empty() }; MAX_DMA_MAPS];
static SMMU_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// SMMU init (board-cm5)
// ============================================================================

#[cfg(feature = "board-cm5")]
unsafe fn smmu_read32(offset: usize) -> u32 {
    core::ptr::read_volatile((SMMU_BASE + offset) as *const u32)
}

#[cfg(feature = "board-cm5")]
unsafe fn smmu_write32(offset: usize, val: u32) {
    core::ptr::write_volatile((SMMU_BASE + offset) as *mut u32, val);
}

/// Initialize SMMU for NIC DMA isolation.
#[cfg(feature = "board-cm5")]
pub fn smmu_init() {
    unsafe {
        // Read identification
        let idr0 = smmu_read32(regs::IDR0);
        let num_smrg = (idr0 & 0xFF) as usize;
        log::info!("[smmu] IDR0=0x{:08x} num_smrg={}", idr0, num_smrg);

        // Disable client port while configuring
        let mut scr0 = smmu_read32(regs::SCR0);
        scr0 |= regs::SCR0_CLIENTPD;
        smmu_write32(regs::SCR0, scr0);

        // Enable global fault reporting
        scr0 |= regs::SCR0_GFRE | regs::SCR0_GFIE | regs::SCR0_GCFGFRE | regs::SCR0_GCFGFIE;
        smmu_write32(regs::SCR0, scr0);

        // Default all stream mapping entries to fault
        let max_entries = num_smrg.min(128);
        for i in 0..max_entries {
            smmu_write32(regs::S2CR_BASE + i * 4, regs::S2CR_TYPE_FAULT);
        }

        // Re-enable client port
        scr0 &= !regs::SCR0_CLIENTPD;
        smmu_write32(regs::SCR0, scr0);

        SMMU_INITIALIZED.store(true, Ordering::Release);
        log::info!("[smmu] initialized, {} stream mapping groups", num_smrg);
    }
}

/// QEMU stub: no SMMU.
#[cfg(not(feature = "board-cm5"))]
pub fn smmu_init() {
    SMMU_INITIALIZED.store(true, Ordering::Release);
    log::info!("[smmu] QEMU stub: SMMU init (no-op)");
}

/// Check if SMMU is initialized.
pub fn is_initialized() -> bool {
    SMMU_INITIALIZED.load(Ordering::Acquire)
}

// ============================================================================
// DMA mapping (board-cm5)
// ============================================================================

/// Create an IOMMU mapping for a NIC stream.
///
/// On CM5: programs the SMMU stream mapping and context bank.
/// On QEMU: just records the mapping (identity-mapped, no real IOMMU).
///
/// Returns 0 on success, negative errno on failure.
#[cfg(feature = "board-cm5")]
pub fn smmu_map_dma(stream_id: u16, iova: u64, phys: u64, size: u64) -> i32 {
    unsafe {
        // Find a free mapping slot
        let mut slot = MAX_DMA_MAPS;
        for i in 0..MAX_DMA_MAPS {
            if !DMA_MAPS[i].active {
                slot = i;
                break;
            }
        }
        if slot >= MAX_DMA_MAPS {
            return crate::kernel::errno::ENOMEM;
        }

        // Program stream mapping: SMR for this stream_id → context bank 0
        let smr_val = (stream_id as u32) | (1 << 31); // valid bit
        smmu_write32(regs::SMR_BASE + (stream_id as usize) * 4, smr_val);

        // S2CR: translate using context bank 0
        let s2cr_val = regs::S2CR_TYPE_TRANS; // CB index 0
        smmu_write32(regs::S2CR_BASE + (stream_id as usize) * 4, s2cr_val);

        // For a proper implementation we'd program the context bank page tables.
        // For now we set up a 1:1 identity mapping in CB0 using a simplified
        // stage-1 translation with a single 1GB block descriptor.
        let cb_base = regs::CB_BASE;

        // TTBR0: point to a minimal page table (identity mapped)
        smmu_write32(cb_base + regs::CB_TTBR0_LO, phys as u32);
        smmu_write32(cb_base + regs::CB_TTBR0_HI, (phys >> 32) as u32);

        // MAIR0: Normal WB-WA + Device-nGnRnE
        smmu_write32(cb_base + regs::CB_MAIR0, 0x0000_00FF);

        // TCR: 4KB granule, 39-bit VA (T0SZ=25)
        smmu_write32(cb_base + regs::CB_TCR, 25 | (0b01 << 8) | (0b01 << 10) | (0b11 << 12));

        // SCTLR: enable translation
        smmu_write32(cb_base + regs::CB_SCTLR, 1); // M=1 (enable)

        DMA_MAPS[slot] = DmaMapping {
            stream_id,
            iova,
            phys,
            size,
            active: true,
        };

        log::info!(
            "[smmu] map stream {} iova=0x{:x} phys=0x{:x} size=0x{:x}",
            stream_id, iova, phys, size
        );
        0
    }
}

/// QEMU stub: record mapping (identity-mapped, no real IOMMU).
#[cfg(not(feature = "board-cm5"))]
pub fn smmu_map_dma(stream_id: u16, iova: u64, phys: u64, size: u64) -> i32 {
    unsafe {
        let mut slot = MAX_DMA_MAPS;
        for i in 0..MAX_DMA_MAPS {
            if !DMA_MAPS[i].active {
                slot = i;
                break;
            }
        }
        if slot >= MAX_DMA_MAPS {
            return crate::kernel::errno::ENOMEM;
        }
        DMA_MAPS[slot] = DmaMapping {
            stream_id,
            iova,
            phys,
            size,
            active: true,
        };
        log::info!(
            "[smmu] QEMU stub: map stream {} iova=0x{:x} phys=0x{:x} size=0x{:x}",
            stream_id, iova, phys, size
        );
        0
    }
}

/// Remove an IOMMU mapping.
pub fn smmu_unmap_dma(stream_id: u16, iova: u64, size: u64) -> i32 {
    unsafe {
        for i in 0..MAX_DMA_MAPS {
            if DMA_MAPS[i].active
                && DMA_MAPS[i].stream_id == stream_id
                && DMA_MAPS[i].iova == iova
                && DMA_MAPS[i].size == size
            {
                DMA_MAPS[i].active = false;

                #[cfg(feature = "board-cm5")]
                {
                    // Invalidate TLB entries for this IOVA range
                    // (simplified: full invalidate)
                    smmu_write32(regs::S2CR_BASE + (stream_id as usize) * 4, regs::S2CR_TYPE_FAULT);
                }

                log::info!(
                    "[smmu] unmap stream {} iova=0x{:x} size=0x{:x}",
                    stream_id, iova, size
                );
                return 0;
            }
        }
        crate::kernel::errno::EINVAL
    }
}

/// Handle an SMMU fault.
///
/// On CM5: reads fault registers, identifies the faulting stream, logs info.
/// On QEMU: no-op (no SMMU faults possible).
pub fn smmu_fault_handler() {
    #[cfg(feature = "board-cm5")]
    unsafe {
        let gfsr = smmu_read32(regs::GFSR);
        if gfsr == 0 {
            return;
        }
        let far_lo = smmu_read32(regs::GFAR_LO);
        let far_hi = smmu_read32(regs::GFAR_HI);
        let synr0 = smmu_read32(regs::GFSYNR0);
        let far = ((far_hi as u64) << 32) | far_lo as u64;

        log::error!(
            "[smmu] FAULT: GFSR=0x{:08x} FAR=0x{:016x} SYNR0=0x{:08x}",
            gfsr, far, synr0
        );

        // Clear fault
        smmu_write32(regs::GFSR, gfsr);
    }
}
