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
            BackingType::RamDisk | BackingType::Nvme => {
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
            BackingType::None => { backing_offset = 0; }
        }

        (*arenas)[slot] = ArenaBackingInfo {
            backing_type, writeback, module_idx,
            virtual_pages, resident_max_pages, backing_offset, active: true,
        };
        slot as i32
    }
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
        BackingType::RamDisk | BackingType::Nvme => {
            #[cfg(feature = "chip-bcm2712")]
            unsafe {
                let disk_page = (info.backing_offset + vpage_idx) as usize;
                if disk_page >= MAX_RAMDISK_PAGES { return -22; }
                let src = RAMDISK[disk_page].as_ptr();
                core::ptr::copy_nonoverlapping(src, buf, PAGE_SIZE);
            }
            0
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
        BackingType::RamDisk | BackingType::Nvme => {
            #[cfg(feature = "chip-bcm2712")]
            unsafe {
                let disk_page = (info.backing_offset + vpage_idx) as usize;
                if disk_page >= MAX_RAMDISK_PAGES { return -22; }
                let dst = RAMDISK[disk_page].as_mut_ptr();
                core::ptr::copy_nonoverlapping(buf, dst, PAGE_SIZE);
            }
            0
        }
        BackingType::None => { 0 }
    }
}

pub fn backing_flush(_arena_id: usize) -> i32 { 0 }

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
