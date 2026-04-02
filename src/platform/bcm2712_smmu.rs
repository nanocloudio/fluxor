//! SMMU/IOMMU setup for BCM2712 (CM5) — thin kernel bridge.
//!
//! The full SMMU configuration and DMA mapping logic has been extracted
//! into the `smmu_cfg` PIC module, which uses MMIO_READ32/WRITE32 bridges.
//!
//! This file retains:
//! - Initialization stubs (init sets flag, module does the real work)
//! - DMA mapping fallback for configs without the smmu_cfg module
//! - Fault handler stub

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// BCM2712 SMMU base address.
#[cfg(feature = "board-cm5")]
const SMMU_BASE: usize = 0xFD5D_0000;

const MAX_DMA_MAPS: usize = 64;

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
        Self { stream_id: 0, iova: 0, phys: 0, size: 0, active: false }
    }
}

static mut DMA_MAPS: [DmaMapping; MAX_DMA_MAPS] = [const { DmaMapping::empty() }; MAX_DMA_MAPS];
static SMMU_INITIALIZED: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Init (thin — real work done by smmu_cfg module when loaded)
// ============================================================================

/// Initialize SMMU. When the smmu_cfg module is wired, this is a no-op
/// and the module handles all SMMU register programming via MMIO bridges.
/// When no module is wired, this provides basic fallback init.
#[cfg(feature = "board-cm5")]
pub fn smmu_init() {
    unsafe {
        // Minimal init: just read IDR0 and set initialized flag.
        // Full register programming is done by smmu_cfg PIC module.
        let idr0 = core::ptr::read_volatile((SMMU_BASE + 0x020) as *const u32);
        let _num_smrg = idr0 & 0xFF;
        SMMU_INITIALIZED.store(true, Ordering::Release);
        log::info!("[smmu] kernel bridge init (module handles config)");
    }
}

#[cfg(not(feature = "board-cm5"))]
pub fn smmu_init() {
    SMMU_INITIALIZED.store(true, Ordering::Release);
    log::info!("[smmu] QEMU stub: SMMU init (no-op)");
}

pub fn is_initialized() -> bool {
    SMMU_INITIALIZED.load(Ordering::Acquire)
}

// ============================================================================
// DMA mapping (fallback for configs without smmu_cfg module)
// ============================================================================

pub fn smmu_map_dma(stream_id: u16, iova: u64, phys: u64, size: u64) -> i32 {
    unsafe {
        let mut slot = MAX_DMA_MAPS;
        for i in 0..MAX_DMA_MAPS {
            if !DMA_MAPS[i].active { slot = i; break; }
        }
        if slot >= MAX_DMA_MAPS { return crate::kernel::errno::ENOMEM; }
        DMA_MAPS[slot] = DmaMapping { stream_id, iova, phys, size, active: true };
        log::info!("[smmu] map stream {} iova=0x{:x} phys=0x{:x} size=0x{:x}",
            stream_id, iova, phys, size);
        0
    }
}

pub fn smmu_unmap_dma(stream_id: u16, iova: u64, size: u64) -> i32 {
    unsafe {
        for i in 0..MAX_DMA_MAPS {
            if DMA_MAPS[i].active && DMA_MAPS[i].stream_id == stream_id
                && DMA_MAPS[i].iova == iova && DMA_MAPS[i].size == size
            {
                DMA_MAPS[i].active = false;
                return 0;
            }
        }
        crate::kernel::errno::EINVAL
    }
}

pub fn smmu_fault_handler() {
    #[cfg(feature = "board-cm5")]
    unsafe {
        let gfsr = core::ptr::read_volatile((SMMU_BASE + 0x048) as *const u32);
        if gfsr == 0 { return; }
        log::error!("[smmu] FAULT: GFSR=0x{:08x}", gfsr);
        core::ptr::write_volatile((SMMU_BASE + 0x048) as *mut u32, gfsr);
    }
}
