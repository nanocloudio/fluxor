//! Backing store for demand-paged arenas (E10-S4).
//!
//! Provides page-level read/write to persistent storage. Currently implements
//! a RAM-disk backing store for testing/QEMU. NVMe backing is stubbed for CM5.

use crate::kernel::page_pool::PAGE_SIZE;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of arenas across all modules.
pub const MAX_ARENAS: usize = 16;

/// Maximum pages in the RAM-disk backing (1MB = 256 pages, for testing).
pub const MAX_RAMDISK_PAGES: usize = 256;

/// Backing store types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BackingType {
    /// No backing (resident-only, faults are errors).
    None = 0,
    /// RAM-disk (for testing / QEMU).
    RamDisk = 1,
    /// NVMe block device (CM5 hardware).
    Nvme = 2,
}

/// Writeback policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WritebackPolicy {
    /// Write dirty pages lazily (on eviction or explicit sync).
    Deferred = 0,
    /// Write dirty pages immediately on every modify.
    WriteThrough = 1,
}

// ============================================================================
// Per-arena backing info
// ============================================================================

/// Per-arena backing store descriptor.
#[derive(Clone, Copy)]
pub struct ArenaBackingInfo {
    /// Backing type.
    pub backing_type: BackingType,
    /// Writeback policy.
    pub writeback: WritebackPolicy,
    /// Module index that owns this arena.
    pub module_idx: u8,
    /// Total virtual pages in the arena.
    pub virtual_pages: u32,
    /// Maximum resident pages allowed.
    pub resident_max_pages: u32,
    /// Offset into the backing store (in pages). For RAM-disk, this is the
    /// starting page index in the RAMDISK buffer.
    pub backing_offset: u32,
    /// Whether this arena slot is in use.
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
// RAM-disk storage
// ============================================================================

/// Static RAM-disk buffer. Each page is PAGE_SIZE bytes.
/// On QEMU/testing this serves as the "disk".
#[cfg(feature = "chip-bcm2712")]
static mut RAMDISK: [[u8; PAGE_SIZE]; MAX_RAMDISK_PAGES] = [[0u8; PAGE_SIZE]; MAX_RAMDISK_PAGES];

/// Per-arena backing descriptors.
static mut ARENAS: [ArenaBackingInfo; MAX_ARENAS] = [ArenaBackingInfo::empty(); MAX_ARENAS];

/// Next free ramdisk page offset for allocation.
#[cfg(feature = "chip-bcm2712")]
static mut RAMDISK_NEXT_OFFSET: u32 = 0;

// ============================================================================
// Public API
// ============================================================================

/// Initialize the backing store subsystem.
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

/// Register a paged arena's backing store.
///
/// Returns the arena_id (index) on success, or -1 on failure.
pub fn backing_register(
    module_idx: u8,
    virtual_pages: u32,
    resident_max_pages: u32,
    backing_type: BackingType,
    writeback: WritebackPolicy,
) -> i32 {
    let arenas = &raw mut ARENAS;
    unsafe {
        // Find a free slot
        let mut slot = MAX_ARENAS;
        for i in 0..MAX_ARENAS {
            if !(*arenas)[i].active {
                slot = i;
                break;
            }
        }
        if slot >= MAX_ARENAS {
            return -1;
        }

        let backing_offset;
        match backing_type {
            BackingType::RamDisk => {
                #[cfg(feature = "chip-bcm2712")]
                {
                    let rd_next = &raw mut RAMDISK_NEXT_OFFSET;
                    let offset = *rd_next;
                    if (offset + virtual_pages) as usize > MAX_RAMDISK_PAGES {
                        log::error!("[backing] ramdisk: not enough pages ({} + {} > {})",
                            offset, virtual_pages, MAX_RAMDISK_PAGES);
                        return -1;
                    }
                    *rd_next = offset + virtual_pages;
                    backing_offset = offset;
                }
                #[cfg(not(feature = "chip-bcm2712"))]
                { backing_offset = 0; }
            }
            BackingType::Nvme => {
                #[cfg(feature = "chip-bcm2712")]
                {
                    let rd_next = &raw mut RAMDISK_NEXT_OFFSET;
                    let offset = *rd_next;
                    if (offset + virtual_pages) as usize > MAX_RAMDISK_PAGES {
                        return -1;
                    }
                    *rd_next = offset + virtual_pages;
                    backing_offset = offset;
                }
                #[cfg(not(feature = "chip-bcm2712"))]
                { backing_offset = 0; }
            }
            BackingType::None => {
                backing_offset = 0;
            }
        }

        (*arenas)[slot] = ArenaBackingInfo {
            backing_type,
            writeback,
            module_idx,
            virtual_pages,
            resident_max_pages,
            backing_offset,
            active: true,
        };

        slot as i32
    }
}

/// Read a page from backing store into a buffer.
///
/// `arena_id`: arena slot index.
/// `vpage_idx`: virtual page index within the arena.
/// `buf`: destination buffer (must be at least PAGE_SIZE bytes).
///
/// Returns 0 on success, negative errno on error.
pub fn backing_read(arena_id: usize, vpage_idx: u32, buf: *mut u8) -> i32 {
    if buf.is_null() {
        return -22; // EINVAL
    }

    let arenas = &raw const ARENAS;
    let info = unsafe {
        if arena_id >= MAX_ARENAS || !(*arenas)[arena_id].active {
            return -19; // ENODEV
        }
        (*arenas)[arena_id]
    };

    if vpage_idx >= info.virtual_pages {
        return -22; // EINVAL
    }

    match info.backing_type {
        BackingType::RamDisk | BackingType::Nvme => {
            #[cfg(feature = "chip-bcm2712")]
            unsafe {
                let disk_page = (info.backing_offset + vpage_idx) as usize;
                if disk_page >= MAX_RAMDISK_PAGES {
                    return -22;
                }
                let src = RAMDISK[disk_page].as_ptr();
                core::ptr::copy_nonoverlapping(src, buf, PAGE_SIZE);
            }
            0
        }
        BackingType::None => {
            // No backing: zero-fill the page
            unsafe {
                core::ptr::write_bytes(buf, 0, PAGE_SIZE);
            }
            0
        }
    }
}

/// Write a page to backing store from a buffer.
///
/// `arena_id`: arena slot index.
/// `vpage_idx`: virtual page index within the arena.
/// `buf`: source buffer (must be at least PAGE_SIZE bytes).
///
/// Returns 0 on success, negative errno on error.
pub fn backing_write(arena_id: usize, vpage_idx: u32, buf: *const u8) -> i32 {
    if buf.is_null() {
        return -22; // EINVAL
    }

    let arenas = &raw const ARENAS;
    let info = unsafe {
        if arena_id >= MAX_ARENAS || !(*arenas)[arena_id].active {
            return -19; // ENODEV
        }
        (*arenas)[arena_id]
    };

    if vpage_idx >= info.virtual_pages {
        return -22; // EINVAL
    }

    match info.backing_type {
        BackingType::RamDisk | BackingType::Nvme => {
            #[cfg(feature = "chip-bcm2712")]
            unsafe {
                let disk_page = (info.backing_offset + vpage_idx) as usize;
                if disk_page >= MAX_RAMDISK_PAGES {
                    return -22;
                }
                let dst = RAMDISK[disk_page].as_mut_ptr();
                core::ptr::copy_nonoverlapping(buf, dst, PAGE_SIZE);
            }
            0
        }
        BackingType::None => {
            // No backing: data is lost on eviction
            0
        }
    }
}

/// Flush all dirty data for an arena. (Sync for RAM-disk is a no-op.)
pub fn backing_flush(arena_id: usize) -> i32 {
    if arena_id >= MAX_ARENAS {
        return -22;
    }
    // RAM-disk and NVMe-on-QEMU: writes are synchronous, nothing to flush
    0
}

/// Release a backing arena slot.
pub fn backing_release(arena_id: usize) {
    let arenas = &raw mut ARENAS;
    unsafe {
        if arena_id < MAX_ARENAS {
            (*arenas)[arena_id] = ArenaBackingInfo::empty();
        }
    }
}

/// Get arena backing info.
pub fn backing_info(arena_id: usize) -> Option<ArenaBackingInfo> {
    let arenas = &raw const ARENAS;
    unsafe {
        if arena_id < MAX_ARENAS && (*arenas)[arena_id].active {
            Some((*arenas)[arena_id])
        } else {
            None
        }
    }
}

/// Check if backing store for an arena is clean (no unflushed data).
/// For RAM-disk this is always true (synchronous writes).
pub fn backing_is_clean(arena_id: usize) -> bool {
    if arena_id >= MAX_ARENAS {
        return true;
    }
    // RAM-disk is always clean (synchronous)
    true
}
