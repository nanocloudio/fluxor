//! Per-module heap allocator.
//!
//! Provides bounded dynamic memory allocation within each module's arena.
//! The allocator runs in kernel space (not in the module) for safety and
//! observability. Each module gets an independent heap carved from the
//! STATE_ARENA — no module can allocate from or free to another module's heap.
//!
//! Design: simple freelist with first-fit and immediate coalescing on free.
//! 8-byte header per block, 16-byte minimum allocation granularity.
//!
//! See `.context/rfc-per-module-heap-allocation.md` for the full design.
//!
//! ## Concurrency
//!
//! Each `MODULE_HEAPS[i]` entry is owned by module `i`, which steps on
//! a single assigned core, so an individual heap is touched by one
//! core at a time and needs no cross-core synchronisation. See
//! `docs/architecture/concurrency.md`.

use crate::kernel::scheduler::MAX_MODULES;

// ============================================================================
// Constants
// ============================================================================

/// Minimum allocation size (excluding header). Prevents degenerate fragmentation.
const MIN_ALLOC: usize = 16;

/// Block header size in bytes.
const HEADER_SIZE: usize = 8;

/// Bit 31 of size_and_flags indicates allocated.
const ALLOC_FLAG: u32 = 0x8000_0000;

/// Magic value in next_or_magic when block is allocated (debug aid).
const ALLOC_MAGIC: u32 = 0xDEAD_BEEF;

// ============================================================================
// Block Header
// ============================================================================

/// 8-byte block header placed before each allocation.
///
/// When free: size_and_flags = data size (bit 31 clear), next_or_magic = offset
/// to next free block (0 = end of free list).
///
/// When allocated: size_and_flags = data size | ALLOC_FLAG, next_or_magic = ALLOC_MAGIC.
#[repr(C)]
#[derive(Clone, Copy)]
struct BlockHeader {
    /// Size of data region (excluding header). Bit 31 = allocated flag.
    size_and_flags: u32,
    /// When free: byte offset from arena base to next free block header (0 = end).
    /// When allocated: debug magic.
    next_or_magic: u32,
}

impl BlockHeader {
    #[inline(always)]
    fn data_size(&self) -> usize {
        (self.size_and_flags & !ALLOC_FLAG) as usize
    }

    #[inline(always)]
    fn is_allocated(&self) -> bool {
        (self.size_and_flags & ALLOC_FLAG) != 0
    }

    #[inline(always)]
    fn set_allocated(&mut self, size: usize) {
        self.size_and_flags = (size as u32) | ALLOC_FLAG;
        self.next_or_magic = ALLOC_MAGIC;
    }

    #[inline(always)]
    fn set_free(&mut self, size: usize, next_offset: u32) {
        self.size_and_flags = size as u32;
        self.next_or_magic = next_offset;
    }
}

// ============================================================================
// Per-module heap metadata
// ============================================================================

/// Per-module heap state, stored in kernel memory (not in module's arena).
#[derive(Clone, Copy)]
pub struct ModuleHeap {
    /// Base address of this module's heap arena.
    base: *mut u8,
    /// Total size of the heap arena in bytes.
    size: u32,
    /// Offset from base to the first free block header (0 = no free blocks / not init).
    /// We use u32 offsets rather than pointers to stay 32/64-bit portable.
    first_free_offset: u32,
    /// Current allocated bytes (excluding headers).
    pub allocated: u32,
    /// Number of active allocations.
    pub alloc_count: u16,
    /// Lifetime allocation count (for diagnostics).
    pub total_allocs: u16,
    /// High-water mark of allocated bytes.
    pub high_water: u32,
    /// Number of failed allocation attempts.
    pub fail_count: u16,
    /// Padding.
    _pad: u16,
}

/// Heap statistics queryable by modules.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct HeapStats {
    /// Total heap arena size in bytes.
    pub arena_size: u32,
    /// Currently allocated bytes (excluding headers).
    pub allocated: u32,
    /// Number of active allocations.
    pub alloc_count: u16,
    /// Lifetime total allocations.
    pub total_allocs: u16,
    /// High-water mark of allocated bytes.
    pub high_water: u32,
    /// Number of free blocks (fragmentation indicator).
    pub free_blocks: u16,
    /// Largest free block in bytes (allocation headroom).
    pub largest_free: u16,
}

impl ModuleHeap {
    /// Create an empty (uninitialized) heap — for modules with no arena.
    pub const fn empty() -> Self {
        Self {
            base: core::ptr::null_mut(),
            size: 0,
            first_free_offset: 0,
            allocated: 0,
            alloc_count: 0,
            total_allocs: 0,
            high_water: 0,
            fail_count: 0,
            _pad: 0,
        }
    }

    /// Initialize a heap from a raw arena pointer and size.
    ///
    /// Sets up the arena as a single large free block.
    /// The arena must be at least HEADER_SIZE + MIN_ALLOC bytes.
    pub fn init(base: *mut u8, size: usize) -> Self {
        if base.is_null() || size < HEADER_SIZE + MIN_ALLOC {
            return Self::empty();
        }

        // Initialize the arena as a single free block
        let hdr = base as *mut BlockHeader;
        let data_size = size - HEADER_SIZE;
        unsafe {
            (*hdr).set_free(data_size, 0); // 0 = no next free block
        }

        Self {
            base,
            size: size as u32,
            first_free_offset: 0, // first free block is at offset 0
            allocated: 0,
            alloc_count: 0,
            total_allocs: 0,
            high_water: 0,
            fail_count: 0,
            _pad: 0,
        }
    }

    /// Check if this heap is initialized (has a valid arena).
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        !self.base.is_null() && self.size > 0
    }

    /// Allocate `size` bytes from this module's heap.
    ///
    /// Returns a pointer to the allocated memory, or null on failure.
    /// Size is rounded up to MIN_ALLOC alignment.
    pub fn alloc(&mut self, size: usize) -> *mut u8 {
        if !self.is_active() || size == 0 {
            return core::ptr::null_mut();
        }

        // Round up to MIN_ALLOC granularity
        let aligned_size = (size + MIN_ALLOC - 1) & !(MIN_ALLOC - 1);

        // First-fit search through free list
        let mut prev_offset: u32 = u32::MAX; // sentinel: no previous
        let mut cur_offset = self.first_free_offset;

        loop {
            if cur_offset as usize + HEADER_SIZE > self.size as usize {
                // Reached end of free list or invalid offset
                break;
            }

            let hdr_ptr = unsafe { self.base.add(cur_offset as usize) as *mut BlockHeader };
            let hdr = unsafe { *hdr_ptr };

            if hdr.is_allocated() {
                // Corrupted free list — shouldn't happen
                break;
            }

            let block_data_size = hdr.data_size();
            let next_free = hdr.next_or_magic;

            if block_data_size >= aligned_size {
                // Found a fit. Check if we can split.
                let remainder = block_data_size - aligned_size;

                if remainder >= HEADER_SIZE + MIN_ALLOC {
                    // Split: create new free block after this allocation
                    let new_free_offset = cur_offset + HEADER_SIZE as u32 + aligned_size as u32;
                    let new_free_data = remainder - HEADER_SIZE;
                    let new_hdr_ptr =
                        unsafe { self.base.add(new_free_offset as usize) as *mut BlockHeader };
                    unsafe {
                        (*new_hdr_ptr).set_free(new_free_data, next_free);
                        (*hdr_ptr).set_allocated(aligned_size);
                    }

                    // Update free list linkage
                    if prev_offset == u32::MAX {
                        self.first_free_offset = new_free_offset;
                    } else {
                        let prev_hdr =
                            unsafe { self.base.add(prev_offset as usize) as *mut BlockHeader };
                        unsafe {
                            (*prev_hdr).next_or_magic = new_free_offset;
                        }
                    }
                } else {
                    // Use entire block (no split — remainder too small)
                    unsafe {
                        (*hdr_ptr).set_allocated(block_data_size);
                    }

                    // Remove from free list
                    if prev_offset == u32::MAX {
                        self.first_free_offset = next_free;
                    } else {
                        let prev_hdr =
                            unsafe { self.base.add(prev_offset as usize) as *mut BlockHeader };
                        unsafe {
                            (*prev_hdr).next_or_magic = next_free;
                        }
                    }
                }

                // Update stats
                let actual_size = unsafe { (*hdr_ptr).data_size() as u32 };
                self.allocated += actual_size;
                self.alloc_count += 1;
                self.total_allocs = self.total_allocs.saturating_add(1);
                if self.allocated > self.high_water {
                    self.high_water = self.allocated;
                }

                // Return pointer to data region (after header)
                return unsafe { self.base.add(cur_offset as usize + HEADER_SIZE) };
            }

            // Move to next free block
            prev_offset = cur_offset;
            if next_free == 0 {
                break; // end of free list
            }
            cur_offset = next_free;
        }

        // Allocation failed
        self.fail_count = self.fail_count.saturating_add(1);
        core::ptr::null_mut()
    }

    /// Free a previously allocated block.
    ///
    /// Validates that ptr is within this module's arena and is a valid allocation.
    /// Passing null is a no-op. Coalesces with adjacent free blocks.
    pub fn free(&mut self, ptr: *mut u8) {
        if ptr.is_null() || !self.is_active() {
            return;
        }

        let ptr_addr = ptr as usize;
        let base_addr = self.base as usize;

        // Validate: ptr must be within arena and properly aligned to a header
        if ptr_addr < base_addr + HEADER_SIZE || ptr_addr >= base_addr + self.size as usize {
            log::error!("[heap] free: ptr outside arena");
            return;
        }

        let hdr_addr = ptr_addr - HEADER_SIZE;
        let offset = (hdr_addr - base_addr) as u32;
        let hdr_ptr = hdr_addr as *mut BlockHeader;
        let hdr = unsafe { *hdr_ptr };

        if !hdr.is_allocated() {
            log::error!("[heap] free: double free at offset {}", offset);
            return;
        }

        if hdr.next_or_magic != ALLOC_MAGIC {
            log::error!("[heap] free: corrupted header at offset {}", offset);
            return;
        }

        let freed_size = hdr.data_size();

        // Update stats
        self.allocated = self.allocated.saturating_sub(freed_size as u32);
        self.alloc_count = self.alloc_count.saturating_sub(1);

        // Insert into free list in address order, then coalesce
        self.insert_free_and_coalesce(offset, freed_size);
    }

    /// Reallocate: grow or shrink an existing allocation.
    ///
    /// Returns new pointer or null on failure. On null return, the original
    /// allocation is unchanged.
    pub fn realloc(&mut self, ptr: *mut u8, new_size: usize) -> *mut u8 {
        if ptr.is_null() {
            return self.alloc(new_size);
        }
        if new_size == 0 {
            self.free(ptr);
            return core::ptr::null_mut();
        }

        let ptr_addr = ptr as usize;
        let base_addr = self.base as usize;

        if ptr_addr < base_addr + HEADER_SIZE || ptr_addr >= base_addr + self.size as usize {
            return core::ptr::null_mut();
        }

        let hdr_ptr = (ptr_addr - HEADER_SIZE) as *mut BlockHeader;
        let hdr = unsafe { *hdr_ptr };

        if !hdr.is_allocated() {
            return core::ptr::null_mut();
        }

        let old_size = hdr.data_size();
        let aligned_new = (new_size + MIN_ALLOC - 1) & !(MIN_ALLOC - 1);

        // Shrink in place?
        if aligned_new <= old_size {
            // Could split excess into free block, but for simplicity just keep it
            return ptr;
        }

        // Try to extend in place by checking if next block is free and adjacent
        let next_block_offset = (ptr_addr - base_addr + old_size) as u32;
        if (next_block_offset as usize) + HEADER_SIZE <= self.size as usize {
            let next_hdr =
                unsafe { *(self.base.add(next_block_offset as usize) as *const BlockHeader) };
            if !next_hdr.is_allocated() {
                let combined = old_size + HEADER_SIZE + next_hdr.data_size();
                if combined >= aligned_new {
                    // Can extend in place — remove next block from free list
                    self.remove_from_free_list(next_block_offset);

                    let remainder = combined - aligned_new;
                    if remainder >= HEADER_SIZE + MIN_ALLOC {
                        // Split: resize current, create new free block
                        unsafe {
                            (*hdr_ptr).set_allocated(aligned_new);
                        }
                        let new_free_off = (ptr_addr - base_addr + aligned_new) as u32;
                        let new_free_size = remainder - HEADER_SIZE;
                        let new_free_hdr =
                            unsafe { self.base.add(new_free_off as usize) as *mut BlockHeader };
                        unsafe {
                            (*new_free_hdr).set_free(new_free_size, 0);
                        }
                        self.insert_free_and_coalesce(new_free_off, new_free_size);
                        self.allocated += (aligned_new - old_size) as u32;
                    } else {
                        // Use all combined space
                        unsafe {
                            (*hdr_ptr).set_allocated(combined);
                        }
                        self.allocated += (combined - old_size) as u32;
                    }
                    if self.allocated > self.high_water {
                        self.high_water = self.allocated;
                    }
                    return ptr;
                }
            }
        }

        // Fall back to alloc + copy + free
        let new_ptr = self.alloc(new_size);
        if new_ptr.is_null() {
            return core::ptr::null_mut();
        }
        let copy_size = old_size.min(new_size);
        unsafe {
            core::ptr::copy_nonoverlapping(ptr, new_ptr, copy_size);
        }
        self.free(ptr);
        new_ptr
    }

    /// Get heap statistics.
    pub fn stats(&self) -> HeapStats {
        if !self.is_active() {
            return HeapStats::default();
        }

        let mut free_blocks: u16 = 0;
        let mut largest_free: usize = 0;

        // Walk free list
        let mut offset = self.first_free_offset;
        let mut iterations = 0u32;
        while (offset as usize) + HEADER_SIZE <= self.size as usize && iterations < 1000 {
            let hdr = unsafe { *(self.base.add(offset as usize) as *const BlockHeader) };
            if hdr.is_allocated() {
                break; // corrupted
            }
            free_blocks += 1;
            let ds = hdr.data_size();
            if ds > largest_free {
                largest_free = ds;
            }
            let next = hdr.next_or_magic;
            if next == 0 {
                break;
            }
            offset = next;
            iterations += 1;
        }

        HeapStats {
            arena_size: self.size,
            allocated: self.allocated,
            alloc_count: self.alloc_count,
            total_allocs: self.total_allocs,
            high_water: self.high_water,
            free_blocks,
            largest_free: largest_free.min(u16::MAX as usize) as u16,
        }
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    /// Remove a free block at `offset` from the free list.
    fn remove_from_free_list(&mut self, offset: u32) {
        let target_hdr = unsafe { *(self.base.add(offset as usize) as *const BlockHeader) };
        let target_next = target_hdr.next_or_magic;

        if self.first_free_offset == offset {
            self.first_free_offset = target_next;
            return;
        }

        let mut prev = self.first_free_offset;
        let mut iterations = 0u32;
        while (prev as usize) + HEADER_SIZE <= self.size as usize && iterations < 1000 {
            let hdr = unsafe { &mut *(self.base.add(prev as usize) as *mut BlockHeader) };
            if hdr.next_or_magic == offset {
                hdr.next_or_magic = target_next;
                return;
            }
            if hdr.next_or_magic == 0 {
                break;
            }
            prev = hdr.next_or_magic;
            iterations += 1;
        }
    }

    /// Insert a freed block at `offset` into the free list in address order,
    /// then coalesce with adjacent free blocks.
    fn insert_free_and_coalesce(&mut self, offset: u32, data_size: usize) {
        let hdr_ptr = unsafe { self.base.add(offset as usize) as *mut BlockHeader };

        // Find insertion point: the free block just before this offset
        if self.first_free_offset > offset || !self.has_free_blocks() {
            // Insert at head
            let old_first = if self.has_free_blocks() {
                self.first_free_offset
            } else {
                0
            };
            unsafe {
                (*hdr_ptr).set_free(data_size, old_first);
            }
            self.first_free_offset = offset;
        } else {
            // Find the free block that should precede this one
            let mut prev = self.first_free_offset;
            let mut iterations = 0u32;
            loop {
                if iterations >= 1000 {
                    break;
                }
                let prev_hdr = unsafe { &mut *(self.base.add(prev as usize) as *mut BlockHeader) };
                let next = prev_hdr.next_or_magic;
                if next == 0 || next > offset {
                    // Insert between prev and next
                    unsafe {
                        (*hdr_ptr).set_free(data_size, next);
                    }
                    prev_hdr.next_or_magic = offset;
                    break;
                }
                prev = next;
                iterations += 1;
            }
        }

        // Coalesce forward: merge with next block if adjacent
        let hdr = unsafe { &mut *hdr_ptr };
        let end_of_this = offset as usize + HEADER_SIZE + hdr.data_size();
        let next_off = hdr.next_or_magic;
        if next_off != 0 && end_of_this == next_off as usize {
            let next_hdr = unsafe { *(self.base.add(next_off as usize) as *const BlockHeader) };
            if !next_hdr.is_allocated() {
                let merged_size = hdr.data_size() + HEADER_SIZE + next_hdr.data_size();
                hdr.set_free(merged_size, next_hdr.next_or_magic);
            }
        }

        // Coalesce backward: if predecessor is adjacent, merge into it
        if self.first_free_offset != offset {
            let mut scan = self.first_free_offset;
            let mut iterations = 0u32;
            while (scan as usize) + HEADER_SIZE <= self.size as usize && iterations < 1000 {
                let scan_hdr = unsafe { &mut *(self.base.add(scan as usize) as *mut BlockHeader) };
                if scan_hdr.next_or_magic == offset {
                    let end_of_prev = scan as usize + HEADER_SIZE + scan_hdr.data_size();
                    if end_of_prev == offset as usize {
                        // Adjacent — merge
                        let cur_hdr =
                            unsafe { *(self.base.add(offset as usize) as *const BlockHeader) };
                        let merged_size = scan_hdr.data_size() + HEADER_SIZE + cur_hdr.data_size();
                        scan_hdr.set_free(merged_size, cur_hdr.next_or_magic);
                    }
                    break;
                }
                let next = scan_hdr.next_or_magic;
                if next == 0 {
                    break;
                }
                scan = next;
                iterations += 1;
            }
        }
    }

    /// Check if there are any free blocks in the list.
    fn has_free_blocks(&self) -> bool {
        let offset = self.first_free_offset;
        if (offset as usize) + HEADER_SIZE > self.size as usize {
            return false;
        }
        let hdr = unsafe { *(self.base.add(offset as usize) as *const BlockHeader) };
        !hdr.is_allocated()
    }
}

// ============================================================================
// Global heap state (indexed by module)
// ============================================================================

/// Per-module heap metadata, stored in kernel memory.
static mut MODULE_HEAPS: [ModuleHeap; MAX_MODULES] = [const { ModuleHeap::empty() }; MAX_MODULES];

/// Initialize a module's heap from its arena allocation.
/// Called by the scheduler during module instantiation when module_arena_size() > 0.
pub fn init_module_heap(module_idx: usize, arena_ptr: *mut u8, arena_size: usize) {
    if module_idx >= MAX_MODULES {
        return;
    }
    unsafe {
        MODULE_HEAPS[module_idx] = ModuleHeap::init(arena_ptr, arena_size);
    }
    if arena_size > 0 {
        log::debug!(
            "[heap] module {} heap init {} bytes",
            module_idx,
            arena_size
        );
    }
}

/// Reset a module's heap (called on graph reconfigure).
pub fn reset_module_heap(module_idx: usize) {
    if module_idx >= MAX_MODULES {
        return;
    }
    unsafe {
        MODULE_HEAPS[module_idx] = ModuleHeap::empty();
    }
}

/// Reset all module heaps.
pub fn reset_all() {
    unsafe {
        let heaps = &raw mut MODULE_HEAPS;
        for slot in (*heaps).iter_mut() {
            *slot = ModuleHeap::empty();
        }
    }
}

/// Allocate from the current module's heap.
/// Returns pointer to allocated memory, or null on failure.
pub fn heap_alloc(module_idx: usize, size: usize) -> *mut u8 {
    if module_idx >= MAX_MODULES {
        return core::ptr::null_mut();
    }
    unsafe { MODULE_HEAPS[module_idx].alloc(size) }
}

/// Free memory from the current module's heap.
pub fn heap_free(module_idx: usize, ptr: *mut u8) {
    if module_idx >= MAX_MODULES {
        return;
    }
    unsafe { MODULE_HEAPS[module_idx].free(ptr) }
}

/// Reallocate from the current module's heap.
pub fn heap_realloc(module_idx: usize, ptr: *mut u8, new_size: usize) -> *mut u8 {
    if module_idx >= MAX_MODULES {
        return core::ptr::null_mut();
    }
    unsafe { MODULE_HEAPS[module_idx].realloc(ptr, new_size) }
}

/// Get heap statistics for a module.
pub fn heap_stats(module_idx: usize) -> HeapStats {
    if module_idx >= MAX_MODULES {
        return HeapStats::default();
    }
    unsafe { MODULE_HEAPS[module_idx].stats() }
}

/// Check if a module has an active heap.
pub fn has_heap(module_idx: usize) -> bool {
    if module_idx >= MAX_MODULES {
        return false;
    }
    unsafe { MODULE_HEAPS[module_idx].is_active() }
}
