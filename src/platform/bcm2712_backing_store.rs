//! Backing store for demand-paged arenas — thin kernel bridge.
//!
//! Storage for demand-paged virtual memory comes from one of:
//!   - `None`: zero-fill only (no persistence).
//!   - `RamDisk`: a built-in RAM-resident page array (bring-up default).
//!   - `External`: a driver module that has registered itself via the
//!     `BACKING_PROVIDER_ENABLE` syscall (NVMe, SD card, eMMC, raw
//!     flash, …). The kernel holds no device-specific knowledge — it
//!     assigns each arena an abstract page-granular `backing_offset`
//!     and the driver maps that to its own addressing (LBA, sector,
//!     offset, …) in its dispatch handler.

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
    /// Backed by a driver module registered via BACKING_PROVIDER_ENABLE.
    External = 2,
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
// Static state
// ============================================================================

#[cfg(feature = "chip-bcm2712")]
static mut RAMDISK: [[u8; PAGE_SIZE]; MAX_RAMDISK_PAGES] = [[0u8; PAGE_SIZE]; MAX_RAMDISK_PAGES];

static mut ARENAS: [ArenaBackingInfo; MAX_ARENAS] = [ArenaBackingInfo::empty(); MAX_ARENAS];

#[cfg(feature = "chip-bcm2712")]
static mut RAMDISK_NEXT_OFFSET: u32 = 0;

/// Running page counter for `External`-backed arenas. Each registration
/// carves `virtual_pages` from this counter and hands the starting
/// page index back as `backing_offset`. The driver interprets that
/// abstract page index in its own addressing (LBA, sector, …).
static mut EXTERNAL_ARENA_NEXT_PAGE: u32 = 0;

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
        *(&raw mut EXTERNAL_ARENA_NEXT_PAGE) = 0;
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
            BackingType::External => {
                // Abstract page-granular allocation — the driver
                // converts to device-specific addressing in its
                // dispatch handler.
                let next = &raw mut EXTERNAL_ARENA_NEXT_PAGE;
                let base_page = *next;
                if (base_page as u64 + virtual_pages as u64) > (u32::MAX as u64) {
                    return -1;
                }
                *next = base_page + virtual_pages;
                backing_offset = base_page;
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

/// Build the 16-byte arg buffer the backing_provider dispatch expects:
///   [arena_base_page: u32 LE][vpage_idx: u32 LE][buf_ptr: u64 LE]
#[cfg(feature = "chip-bcm2712")]
fn build_backing_arg(arena_base_page: u32, vpage_idx: u32, buf: u64) -> [u8; 16] {
    let mut a = [0u8; 16];
    let b0 = arena_base_page.to_le_bytes();
    a[0..4].copy_from_slice(&b0);
    let b1 = vpage_idx.to_le_bytes();
    a[4..8].copy_from_slice(&b1);
    let b2 = buf.to_le_bytes();
    a[8..16].copy_from_slice(&b2);
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
        BackingType::External => {
            #[cfg(feature = "chip-bcm2712")]
            {
                if !crate::kernel::backing_provider::ready() {
                    return crate::kernel::errno::ENODEV;
                }
                let mut arg = build_backing_arg(info.backing_offset, vpage_idx, buf as u64);
                crate::kernel::backing_provider::dispatch(
                    crate::kernel::backing_provider::op::READ_PAGE,
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
        BackingType::External => {
            #[cfg(feature = "chip-bcm2712")]
            {
                if !crate::kernel::backing_provider::ready() {
                    return crate::kernel::errno::ENODEV;
                }
                let mut arg = build_backing_arg(info.backing_offset, vpage_idx, buf as u64);
                crate::kernel::backing_provider::dispatch(
                    crate::kernel::backing_provider::op::WRITE_PAGE,
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
        if crate::kernel::backing_provider::ready() {
            return crate::kernel::backing_provider::dispatch(
                crate::kernel::backing_provider::op::FLUSH,
                core::ptr::null_mut(),
                0,
            );
        }
    }
    0
}

/// Mark an arena slot free. Called by the pager when a module tears
/// down its paged arena. The slot is reusable on the next register;
/// we do not reclaim the `backing_offset` span (it's bump-allocated
/// and the driver is free to over-write it on the next registration).
pub fn backing_release(arena_id: usize) {
    let arenas = &raw mut ARENAS;
    unsafe {
        if arena_id < MAX_ARENAS {
            (*arenas)[arena_id] = ArenaBackingInfo::empty();
        }
    }
}
