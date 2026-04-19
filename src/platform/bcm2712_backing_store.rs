//! Backing store for demand-paged arenas — thin kernel bridge.
//!
//! The full backing store logic (ramdisk, arena management) has been
//! extracted into the `paging_provider` PIC module.
//!
//! This file retains:
//! - The public API surface (backing_init, backing_register, etc.)
//! - A built-in ramdisk fallback for configs without the paging module
//! - Types shared with the pager (BackingType, WritebackPolicy, ArenaBackingInfo)

use crate::kernel::page_pool::PAGE_SIZE;

// ============================================================================
// Constants
// ============================================================================

pub const MAX_ARENAS: usize = 16;
pub const MAX_RAMDISK_PAGES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BackingType {
    None = 0,
    RamDisk = 1,
    Nvme = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WritebackPolicy {
    Deferred = 0,
    WriteThrough = 1,
}

// ============================================================================
// Per-arena backing info
// ============================================================================

#[derive(Clone, Copy)]
pub struct ArenaBackingInfo {
    pub backing_type: BackingType,
    pub writeback: WritebackPolicy,
    pub module_idx: u8,
    pub virtual_pages: u32,
    pub resident_max_pages: u32,
    pub backing_offset: u32,
    pub active: bool,
}

impl ArenaBackingInfo {
    pub const fn empty() -> Self {
        Self {
            backing_type: BackingType::None,
            writeback: WritebackPolicy::Deferred,
            module_idx: 0xFF,
            virtual_pages: 0,
            resident_max_pages: 0,
            backing_offset: 0,
            active: false,
        }
    }
}

// ============================================================================
// Static state (kernel fallback when paging_provider module not loaded)
// ============================================================================

#[cfg(feature = "chip-bcm2712")]
static mut RAMDISK: [[u8; PAGE_SIZE]; MAX_RAMDISK_PAGES] = [[0u8; PAGE_SIZE]; MAX_RAMDISK_PAGES];

static mut ARENAS: [ArenaBackingInfo; MAX_ARENAS] = [ArenaBackingInfo::empty(); MAX_ARENAS];

#[cfg(feature = "chip-bcm2712")]
static mut RAMDISK_NEXT_OFFSET: u32 = 0;

// ============================================================================
// Public API
// ============================================================================

pub fn backing_init() {
    let arenas = &raw mut ARENAS;
    unsafe {
        for i in 0..MAX_ARENAS {
            (*arenas)[i] = ArenaBackingInfo::empty();
        }
        #[cfg(feature = "chip-bcm2712")]
        { *(&raw mut RAMDISK_NEXT_OFFSET) = 0; }
    }
}

/// Per-arena LBA layout for NVMe-backed arenas.
///
/// Arenas are allocated back-to-back starting at LBA `NVME_ARENA_LBA_BASE`
/// on namespace 1. Each 4 KB virtual page occupies `PAGE_SIZE / 512 = 8`
/// LBAs (assuming 512 B LBAs, which is what fat32 also requires). The
/// low LBA range 0..NVME_ARENA_LBA_BASE is left free for a FAT32
/// partition header, which is the typical shared-media configuration
/// (fat32 at the front, paged arenas in the raw tail).
const NVME_ARENA_LBA_BASE: u64 = 0x0020_0000; // 1 GB in
const PAGE_SIZE_LBAS:      u64 = (PAGE_SIZE / 512) as u64;

static mut NVME_ARENA_NEXT_LBA: u64 = NVME_ARENA_LBA_BASE;

pub fn backing_register(
    module_idx: u8,
    virtual_pages: u32,
    resident_max_pages: u32,
    backing_type: BackingType,
    writeback: WritebackPolicy,
) -> i32 {
    let arenas = &raw mut ARENAS;
    unsafe {
        let mut slot = MAX_ARENAS;
        for i in 0..MAX_ARENAS {
            if !(*arenas)[i].active { slot = i; break; }
        }
        if slot >= MAX_ARENAS { return -1; }

        let backing_offset;
        match backing_type {
            BackingType::RamDisk => {
                #[cfg(feature = "chip-bcm2712")]
                {
                    let rd_next = &raw mut RAMDISK_NEXT_OFFSET;
                    let offset = *rd_next;
                    if (offset + virtual_pages) as usize > MAX_RAMDISK_PAGES { return -1; }
                    *rd_next = offset + virtual_pages;
                    backing_offset = offset;
                }
                #[cfg(not(feature = "chip-bcm2712"))]
                { backing_offset = 0; }
            }
            BackingType::Nvme => {
                // NVMe-backed arenas carve an LBA span from the tail of
                // namespace 1. The offset field stores the arena's
                // starting LBA divided by PAGE_SIZE_LBAS so it fits in
                // u32 (vpage granular).
                let next_lba = &raw mut NVME_ARENA_NEXT_LBA;
                let base_vpage = (*next_lba / PAGE_SIZE_LBAS) as u32;
                if (base_vpage as u64 + virtual_pages as u64) > (u32::MAX as u64) {
                    return -1;
                }
                *next_lba += (virtual_pages as u64) * PAGE_SIZE_LBAS;
                backing_offset = base_vpage;
            }
            BackingType::None => { backing_offset = 0; }
        }

        (*arenas)[slot] = ArenaBackingInfo {
            backing_type, writeback, module_idx,
            virtual_pages, resident_max_pages, backing_offset, active: true,
        };
        slot as i32
    }
}

/// Build the 24-byte arg buffer the nvme_backing dispatch expects:
///   [arena_lba_base: u64 LE][vpage_idx: u32 LE][buf_ptr: u64 LE][_pad: u32]
#[cfg(feature = "chip-bcm2712")]
fn build_nvme_arg(arena_lba_base: u64, vpage_idx: u32, buf: u64) -> [u8; 24] {
    let mut a = [0u8; 24];
    let b0 = arena_lba_base.to_le_bytes();
    a[0..8].copy_from_slice(&b0);
    let b1 = vpage_idx.to_le_bytes();
    a[8..12].copy_from_slice(&b1);
    let b2 = buf.to_le_bytes();
    a[12..20].copy_from_slice(&b2);
    a
}

pub fn backing_read(arena_id: usize, vpage_idx: u32, buf: *mut u8) -> i32 {
    if buf.is_null() { return -22; }
    let arenas = &raw const ARENAS;
    let info = unsafe {
        if arena_id >= MAX_ARENAS || !(*arenas)[arena_id].active { return -19; }
        (*arenas)[arena_id]
    };
    if vpage_idx >= info.virtual_pages { return -22; }

    match info.backing_type {
        BackingType::RamDisk => {
            #[cfg(feature = "chip-bcm2712")]
            unsafe {
                let disk_page = (info.backing_offset + vpage_idx) as usize;
                if disk_page >= MAX_RAMDISK_PAGES { return -22; }
                let src = RAMDISK[disk_page].as_ptr();
                core::ptr::copy_nonoverlapping(src, buf, PAGE_SIZE);
            }
            0
        }
        BackingType::Nvme => {
            #[cfg(feature = "chip-bcm2712")]
            {
                if !crate::kernel::nvme_backing::ready() {
                    return crate::kernel::errno::ENODEV;
                }
                let arena_lba_base =
                    (info.backing_offset as u64) * PAGE_SIZE_LBAS;
                let mut arg = build_nvme_arg(arena_lba_base, vpage_idx, buf as u64);
                crate::kernel::nvme_backing::dispatch(
                    crate::kernel::nvme_backing::op::READ_PAGE,
                    arg.as_mut_ptr(),
                    arg.len(),
                )
            }
            #[cfg(not(feature = "chip-bcm2712"))]
            { -38 } // ENOSYS
        }
        BackingType::None => {
            unsafe { core::ptr::write_bytes(buf, 0, PAGE_SIZE); }
            0
        }
    }
}

pub fn backing_write(arena_id: usize, vpage_idx: u32, buf: *const u8) -> i32 {
    if buf.is_null() { return -22; }
    let arenas = &raw const ARENAS;
    let info = unsafe {
        if arena_id >= MAX_ARENAS || !(*arenas)[arena_id].active { return -19; }
        (*arenas)[arena_id]
    };
    if vpage_idx >= info.virtual_pages { return -22; }

    match info.backing_type {
        BackingType::RamDisk => {
            #[cfg(feature = "chip-bcm2712")]
            unsafe {
                let disk_page = (info.backing_offset + vpage_idx) as usize;
                if disk_page >= MAX_RAMDISK_PAGES { return -22; }
                let dst = RAMDISK[disk_page].as_mut_ptr();
                core::ptr::copy_nonoverlapping(buf, dst, PAGE_SIZE);
            }
            0
        }
        BackingType::Nvme => {
            #[cfg(feature = "chip-bcm2712")]
            {
                if !crate::kernel::nvme_backing::ready() {
                    return crate::kernel::errno::ENODEV;
                }
                let arena_lba_base =
                    (info.backing_offset as u64) * PAGE_SIZE_LBAS;
                let mut arg = build_nvme_arg(arena_lba_base, vpage_idx, buf as u64);
                crate::kernel::nvme_backing::dispatch(
                    crate::kernel::nvme_backing::op::WRITE_PAGE,
                    arg.as_mut_ptr(),
                    arg.len(),
                )
            }
            #[cfg(not(feature = "chip-bcm2712"))]
            { -38 } // ENOSYS
        }
        BackingType::None => { 0 }
    }
}

pub fn backing_flush(_arena_id: usize) -> i32 {
    #[cfg(feature = "chip-bcm2712")]
    {
        if crate::kernel::nvme_backing::ready() {
            return crate::kernel::nvme_backing::dispatch(
                crate::kernel::nvme_backing::op::FLUSH,
                core::ptr::null_mut(),
                0,
            );
        }
    }
    0
}

pub fn backing_release(arena_id: usize) {
    let arenas = &raw mut ARENAS;
    unsafe {
        if arena_id < MAX_ARENAS { (*arenas)[arena_id] = ArenaBackingInfo::empty(); }
    }
}

pub fn backing_info(arena_id: usize) -> Option<ArenaBackingInfo> {
    let arenas = &raw const ARENAS;
    unsafe {
        if arena_id < MAX_ARENAS && (*arenas)[arena_id].active {
            Some((*arenas)[arena_id])
        } else { None }
    }
}

pub fn backing_is_clean(_arena_id: usize) -> bool { true }
