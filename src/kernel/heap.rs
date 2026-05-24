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

/// Trailing canary value written at the end of every allocated chunk
/// when `canary_enabled`. Distinct from `ALLOC_MAGIC` (chunk-header
/// sentinel) and `STATE_CANARY` (state-arena trailing canary) so a
/// single 4-byte dump at triage time identifies which arena overflowed.
const HEAP_CANARY: u32 = 0xCAFE_BABE;

/// Trailing-canary footprint in bytes. Included in the allocator's
/// `aligned_size` so user-visible space is unchanged.
const HEAP_CANARY_SIZE: usize = 4;

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
    /// When set, `free()` memsets the chunk's data region to zero
    /// before linking it back into the free list. Opt-in for modules
    /// that handle secrets (TLS key material, session tokens) via
    /// `heap.zero_on_free: true` in the manifest. Default `false`
    /// keeps the hot-path free minimal for general modules.
    zero_on_free: bool,
    /// When set, a null return from `alloc()` or `realloc()` (with
    /// `new_size > 0`) raises a module fault via
    /// `raise_module_fault(idx, STEP_ERROR)`. The current step still
    /// receives null, but the module enters `Faulted` and its
    /// declared `FaultPolicy` runs at the next tick. Default `false`
    /// preserves the C-style "caller checks null" pattern. Modules
    /// preferring kernel-managed recovery declare
    /// `heap.alloc_failure_policy = "fault"`.
    fault_on_alloc_failure: bool,
    /// When set, every allocation reserves a trailing canary word
    /// inside the chunk; `free()` validates and logs on mismatch.
    /// Opt-in because the +4 bytes per chunk are significant on
    /// RP2350's tight `STATE_ARENA`. Modules with many small chunks
    /// weigh the diagnostic value against the overhead.
    canary_enabled: bool,
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
    /// Padding to align the `largest_free` u32 on its natural boundary.
    pub _pad: u16,
    /// Largest contiguous free block in bytes — the allocation
    /// headroom for the next request. Under heavy fragmentation this
    /// is significantly smaller than `arena_size - allocated`, and
    /// surfacing it makes the fragmentation visible before a single
    /// over-large request returns null.
    pub largest_free: u32,
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
            zero_on_free: false,
            fault_on_alloc_failure: false,
            canary_enabled: false,
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
        // SAFETY: `base..base + size` is the caller-supplied arena (sized
        // and aligned during `Heap::new`); `hdr` writes the first 8 bytes.
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
            zero_on_free: false,
            fault_on_alloc_failure: false,
            canary_enabled: false,
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
    ///
    /// When `canary_enabled`, the allocator reserves
    /// `HEAP_CANARY_SIZE` extra bytes at the chunk tail and writes
    /// `HEAP_CANARY` there. User-visible space is unchanged — the
    /// canary sits in the alignment slack past `size`.
    pub fn alloc(&mut self, size: usize) -> *mut u8 {
        if !self.is_active() || size == 0 {
            return core::ptr::null_mut();
        }

        // Round up to MIN_ALLOC granularity. Canary overhead is part
        // of the rounding budget so the canary always lives within
        // the chunk. Every arithmetic step is checked: a wrapped
        // size would produce a tiny chunk that the caller's first
        // write would overrun by `size` bytes.
        let raw_need = if self.canary_enabled {
            match size.checked_add(HEAP_CANARY_SIZE) {
                Some(n) => n,
                None => {
                    self.fail_count = self.fail_count.saturating_add(1);
                    return core::ptr::null_mut();
                }
            }
        } else {
            size
        };
        let aligned_size = match raw_need.checked_add(MIN_ALLOC - 1) {
            Some(n) => n & !(MIN_ALLOC - 1),
            None => {
                self.fail_count = self.fail_count.saturating_add(1);
                return core::ptr::null_mut();
            }
        };

        // First-fit search through free list
        let mut prev_offset: u32 = u32::MAX; // sentinel: no previous
        let mut cur_offset = self.first_free_offset;

        loop {
            if cur_offset as usize + HEADER_SIZE > self.size as usize {
                // Reached end of free list or invalid offset
                break;
            }

            // SAFETY: `cur_offset + HEADER_SIZE <= self.size` checked above;
            // `hdr_ptr` lands at a chunk header inside the arena.
            let hdr_ptr = unsafe { self.base.add(cur_offset as usize) as *mut BlockHeader };
            // SAFETY: as above; reads the 8-byte header.
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
                    // SAFETY: `new_free_offset = cur_offset + HEADER_SIZE +
                    // aligned_size` and the if-guard ensured the remainder
                    // fits a header + MIN_ALLOC. Pointer is inside the arena.
                    let new_hdr_ptr =
                        unsafe { self.base.add(new_free_offset as usize) as *mut BlockHeader };
                    // SAFETY: `hdr_ptr` and `new_hdr_ptr` are distinct
                    // 8-byte headers in the arena, just established above.
                    unsafe {
                        (*new_hdr_ptr).set_free(new_free_data, next_free);
                        (*hdr_ptr).set_allocated(aligned_size);
                    }

                    // Update free list linkage
                    if prev_offset == u32::MAX {
                        self.first_free_offset = new_free_offset;
                    } else {
                        // SAFETY: `prev_offset < self.size` (it was a valid
                        // free-list cursor on a prior iteration).
                        let prev_hdr =
                            unsafe { self.base.add(prev_offset as usize) as *mut BlockHeader };
                        // SAFETY: writes the `next_or_magic` field of the
                        // previous header at a known location inside the arena.
                        unsafe {
                            (*prev_hdr).next_or_magic = new_free_offset;
                        }
                    }
                } else {
                    // Use entire block (no split — remainder too small)
                    // SAFETY: `hdr_ptr` is the chunk header we just selected.
                    unsafe {
                        (*hdr_ptr).set_allocated(block_data_size);
                    }

                    // Remove from free list
                    if prev_offset == u32::MAX {
                        self.first_free_offset = next_free;
                    } else {
                        // SAFETY: `prev_offset < self.size` (prior iteration cursor).
                        let prev_hdr =
                            unsafe { self.base.add(prev_offset as usize) as *mut BlockHeader };
                        // SAFETY: writes the `next_or_magic` field of the
                        // previous header at a known location inside the arena.
                        unsafe {
                            (*prev_hdr).next_or_magic = next_free;
                        }
                    }
                }

                // Update stats
                // SAFETY: `hdr_ptr` is the chunk header for the just-allocated
                // block; reads the size field set by `set_allocated`.
                let actual_size = unsafe { (*hdr_ptr).data_size() as u32 };
                self.allocated += actual_size;
                self.alloc_count += 1;
                self.total_allocs = self.total_allocs.saturating_add(1);
                if self.allocated > self.high_water {
                    self.high_water = self.allocated;
                }

                // SAFETY: `cur_offset + HEADER_SIZE + actual_size <= self.size`
                // because `aligned_size <= block_data_size` and the block
                // fully lives inside the arena.
                let data_ptr = unsafe { self.base.add(cur_offset as usize + HEADER_SIZE) };
                // Trailing canary at the last 4 bytes of the chunk's
                // data region. Detection is at the chunk boundary,
                // not the requested-size boundary: a user write
                // exactly `size` bytes is safe; a write past chunk
                // end clobbers the canary. Overruns into the
                // alignment slack between `size` and the canary pass
                // undetected — the chunk-header `ALLOC_MAGIC`
                // sentinel catches writes into the next chunk.
                if self.canary_enabled {
                    let canary_off = actual_size as usize - HEAP_CANARY_SIZE;
                    // SAFETY: `actual_size >= aligned_size >= HEAP_CANARY_SIZE`
                    // (canary cost is rolled into `aligned_size`); writes
                    // 4 bytes inside the just-allocated chunk.
                    unsafe {
                        core::ptr::write_unaligned(
                            data_ptr.add(canary_off) as *mut u32,
                            HEAP_CANARY,
                        );
                    }
                }

                // Return pointer to data region (after header)
                return data_ptr;
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
        // SAFETY: `ptr_addr - HEADER_SIZE >= base_addr` (caller passed an
        // arena-allocated pointer ≥ base + HEADER_SIZE). The 8-byte header
        // is inside the arena.
        let hdr = unsafe { *hdr_ptr };

        if !hdr.is_allocated() {
            log::error!("[heap] free: double free at offset {offset}");
            return;
        }

        if hdr.next_or_magic != ALLOC_MAGIC {
            log::error!("[heap] free: corrupted header at offset {offset}");
            return;
        }

        let freed_size = hdr.data_size();

        // Validate the trailing canary before releasing the chunk.
        // A clobbered canary indicates the module wrote past its
        // allocation; the chunk is still returned to the pool (the
        // data is already lost — this is a detection hook, not a
        // recovery one).
        if self.canary_enabled && freed_size >= HEAP_CANARY_SIZE {
            let canary_off = freed_size - HEAP_CANARY_SIZE;
            // SAFETY: `canary_off + 4 = freed_size`; canary lives in the
            // last 4 bytes of the chunk.
            let read = unsafe { core::ptr::read_unaligned(ptr.add(canary_off) as *const u32) };
            if read != HEAP_CANARY {
                log::error!(
                    "[heap] HEAP CANARY CLOBBERED at offset {offset} (chunk size {freed_size}) — \
                     module overran its allocation",
                );
            }
        }

        // Zero the data region before insertion into the free list
        // when the module opted in. Done BEFORE the insert so a
        // subsequent allocator walk (immediate coalesce, realloc
        // returning this chunk) can't observe the stale bytes.
        if self.zero_on_free && freed_size > 0 {
            // SAFETY: `ptr` is the just-freed chunk's data region;
            // `freed_size` is the chunk header's stored size.
            unsafe {
                core::ptr::write_bytes(ptr, 0, freed_size);
            }
        }

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
        // SAFETY: `ptr_addr - HEADER_SIZE >= base_addr` (checked above);
        // the 8-byte header lies inside the arena.
        let hdr = unsafe { *hdr_ptr };

        if !hdr.is_allocated() {
            return core::ptr::null_mut();
        }

        let old_size = hdr.data_size();
        // Include canary cost in the new alignment when enabled —
        // an in-place grow that omitted this would write the new
        // canary at `chunk_end - 4`, landing inside the caller's
        // resized region. Checked arithmetic guards against
        // `realloc(ptr, usize::MAX)` shrinking the chunk while the
        // caller treats it as huge.
        let raw_need = if self.canary_enabled {
            match new_size.checked_add(HEAP_CANARY_SIZE) {
                Some(n) => n,
                None => return core::ptr::null_mut(),
            }
        } else {
            new_size
        };
        let aligned_new = match raw_need.checked_add(MIN_ALLOC - 1) {
            Some(n) => n & !(MIN_ALLOC - 1),
            None => return core::ptr::null_mut(),
        };

        // Shrink in place. The chunk size header is unchanged, so
        // the existing trailing canary at `old_size - 4` stays valid
        // for `free()`. Detection inside the new (smaller) logical
        // size is correspondingly looser — tightening would require
        // splitting the chunk, which the allocator skips for
        // simplicity.
        if aligned_new <= old_size {
            return ptr;
        }

        // Try to extend in place by checking if next block is free and adjacent
        let next_block_offset = (ptr_addr - base_addr + old_size) as u32;
        if (next_block_offset as usize) + HEADER_SIZE <= self.size as usize {
            // SAFETY: `next_block_offset + HEADER_SIZE <= self.size`
            // checked above; reads the adjacent chunk's header.
            let next_hdr =
                unsafe { *(self.base.add(next_block_offset as usize) as *const BlockHeader) };
            if !next_hdr.is_allocated() {
                let combined = old_size + HEADER_SIZE + next_hdr.data_size();
                if combined >= aligned_new {
                    // Can extend in place — remove next block from free list
                    self.remove_from_free_list(next_block_offset);

                    let remainder = combined - aligned_new;
                    let final_size = if remainder >= HEADER_SIZE + MIN_ALLOC {
                        // Split: resize current, create new free block
                        // SAFETY: `hdr_ptr` is the chunk we're resizing.
                        unsafe {
                            (*hdr_ptr).set_allocated(aligned_new);
                        }
                        let new_free_off = (ptr_addr - base_addr + aligned_new) as u32;
                        let new_free_size = remainder - HEADER_SIZE;
                        // SAFETY: `new_free_off + HEADER_SIZE <=
                        // next_block_offset + HEADER_SIZE + next.data_size()
                        // <= self.size`.
                        let new_free_hdr =
                            unsafe { self.base.add(new_free_off as usize) as *mut BlockHeader };
                        // SAFETY: `new_free_hdr` is the just-placed header.
                        unsafe {
                            (*new_free_hdr).set_free(new_free_size, 0);
                        }
                        self.insert_free_and_coalesce(new_free_off, new_free_size);
                        self.allocated += (aligned_new - old_size) as u32;
                        aligned_new
                    } else {
                        // Use all combined space
                        // SAFETY: `hdr_ptr` is the chunk we're resizing.
                        unsafe {
                            (*hdr_ptr).set_allocated(combined);
                        }
                        self.allocated += (combined - old_size) as u32;
                        combined
                    };
                    if self.allocated > self.high_water {
                        self.high_water = self.allocated;
                    }
                    // Stamp a fresh canary at the new chunk tail —
                    // the grow moved `chunk_end`, so the canary
                    // must move with it.
                    if self.canary_enabled && final_size >= HEAP_CANARY_SIZE {
                        let canary_off = final_size - HEAP_CANARY_SIZE;
                        // SAFETY: `canary_off + 4 = final_size`; writes
                        // canary in the last 4 bytes of the resized chunk.
                        unsafe {
                            core::ptr::write_unaligned(
                                ptr.add(canary_off) as *mut u32,
                                HEAP_CANARY,
                            );
                        }
                    }
                    return ptr;
                }
            }
        }

        // Fall back to alloc + copy + free. With canary enabled,
        // `old_size` includes the trailing canary bytes — copying
        // those into the new chunk would land the canary value at
        // an internal user-readable offset and confuse the next
        // overrun-detection scan. Clamp the copy to the user
        // region (old chunk minus its canary tail).
        let new_ptr = self.alloc(new_size);
        if new_ptr.is_null() {
            return core::ptr::null_mut();
        }
        let user_old = if self.canary_enabled && old_size >= HEAP_CANARY_SIZE {
            old_size - HEAP_CANARY_SIZE
        } else {
            old_size
        };
        let copy_size = user_old.min(new_size);
        // SAFETY: `copy_size <= user_old <= old_size` (user region of old
        // chunk) and `copy_size <= new_size <= aligned_new` (data region
        // of new chunk); src/dst are disjoint allocations.
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
            // SAFETY: `offset + HEADER_SIZE <= self.size` (loop bound).
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
            _pad: 0,
            largest_free: largest_free.min(u32::MAX as usize) as u32,
        }
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    /// Remove a free block at `offset` from the free list.
    fn remove_from_free_list(&mut self, offset: u32) {
        // SAFETY: caller passes an offset that was previously inserted
        // into the free list (so `offset + HEADER_SIZE <= self.size`).
        let target_hdr = unsafe { *(self.base.add(offset as usize) as *const BlockHeader) };
        let target_next = target_hdr.next_or_magic;

        if self.first_free_offset == offset {
            self.first_free_offset = target_next;
            return;
        }

        let mut prev = self.first_free_offset;
        let mut iterations = 0u32;
        while (prev as usize) + HEADER_SIZE <= self.size as usize && iterations < 1000 {
            // SAFETY: `prev + HEADER_SIZE <= self.size` (loop bound).
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
        // SAFETY: caller passes a valid offset from `free()` so
        // `offset + HEADER_SIZE <= self.size`.
        let hdr_ptr = unsafe { self.base.add(offset as usize) as *mut BlockHeader };

        // Find insertion point: the free block just before this offset
        if self.first_free_offset > offset || !self.has_free_blocks() {
            // Insert at head
            let old_first = if self.has_free_blocks() {
                self.first_free_offset
            } else {
                0
            };
            // SAFETY: `hdr_ptr` is the newly-freed chunk's header.
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
                // SAFETY: free-list cursor; previously validated offset.
                let prev_hdr = unsafe { &mut *(self.base.add(prev as usize) as *mut BlockHeader) };
                let next = prev_hdr.next_or_magic;
                if next == 0 || next > offset {
                    // Insert between prev and next
                    // SAFETY: `hdr_ptr` is the newly-freed chunk's header.
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
        // SAFETY: `hdr_ptr` is the just-inserted free chunk's header.
        let hdr = unsafe { &mut *hdr_ptr };
        let end_of_this = offset as usize + HEADER_SIZE + hdr.data_size();
        let next_off = hdr.next_or_magic;
        if next_off != 0 && end_of_this == next_off as usize {
            // SAFETY: `next_off` is a free-list cursor; `next_off + HEADER_SIZE
            // <= self.size` (was inserted by the same allocator path).
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
                // SAFETY: `scan + HEADER_SIZE <= self.size` (loop bound).
                let scan_hdr = unsafe { &mut *(self.base.add(scan as usize) as *mut BlockHeader) };
                if scan_hdr.next_or_magic == offset {
                    let end_of_prev = scan as usize + HEADER_SIZE + scan_hdr.data_size();
                    if end_of_prev == offset as usize {
                        // Adjacent — merge
                        // SAFETY: `offset + HEADER_SIZE <= self.size` (caller).
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
        // SAFETY: `offset + HEADER_SIZE <= self.size` (checked above).
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
    // SAFETY: per-module heap; each module steps on a single core (see file
    // header), so concurrent access is precluded. `module_idx` bounded.
    unsafe {
        MODULE_HEAPS[module_idx] = ModuleHeap::init(arena_ptr, arena_size);
    }
    if arena_size > 0 {
        log::debug!("[heap] module {module_idx} heap init {arena_size} bytes");
    }
}

/// Reset a module's heap (called on graph reconfigure).
pub fn reset_module_heap(module_idx: usize) {
    if module_idx >= MAX_MODULES {
        return;
    }
    // SAFETY: as above; reconfigure runs between graph rebuilds.
    unsafe {
        MODULE_HEAPS[module_idx] = ModuleHeap::empty();
    }
}

/// Reset all module heaps.
pub fn reset_all() {
    // SAFETY: scheduler-side reset; no module is stepping when this runs.
    unsafe {
        let heaps = &raw mut MODULE_HEAPS;
        for slot in (*heaps).iter_mut() {
            *slot = ModuleHeap::empty();
        }
    }
}

/// Allocate from the current module's heap. Returns the allocated
/// pointer or null on failure. When `fault_on_alloc_failure` is set,
/// a null return also raises a `STEP_ERROR` fault so the module's
/// declared `FaultPolicy` runs at the next tick; the C-style
/// caller-checks-NULL pattern stays the default.
pub fn heap_alloc(module_idx: usize, size: usize) -> *mut u8 {
    if module_idx >= MAX_MODULES {
        return core::ptr::null_mut();
    }
    // SAFETY: per-module heap owned by the calling module's core.
    let ptr = unsafe { MODULE_HEAPS[module_idx].alloc(size) };
    if ptr.is_null() {
        // SAFETY: as above.
        let fault_policy_enabled = unsafe { MODULE_HEAPS[module_idx].fault_on_alloc_failure };
        if fault_policy_enabled {
            crate::kernel::scheduler::raise_module_fault(
                module_idx,
                crate::kernel::step_guard::fault_type::STEP_ERROR,
            );
        }
    }
    ptr
}

/// Free memory from the current module's heap.
pub fn heap_free(module_idx: usize, ptr: *mut u8) {
    if module_idx >= MAX_MODULES {
        return;
    }
    // SAFETY: per-module heap; `module_idx` bounded.
    unsafe { MODULE_HEAPS[module_idx].free(ptr) }
}

/// Reallocate from the current module's heap.
///
/// Honours `fault_on_alloc_failure` the same way as `heap_alloc`:
/// when the realloc returns null AND `new_size > 0` (the caller
/// wanted space, not a free), `raise_module_fault(idx, STEP_ERROR)`
/// flips the module into `Faulted` so its declared `FaultPolicy`
/// runs at the next tick. `new_size == 0` is the alloc-equivalent-
/// of-free path — a null return there is the expected no-op, not an
/// OOM, so it doesn't raise.
pub fn heap_realloc(module_idx: usize, ptr: *mut u8, new_size: usize) -> *mut u8 {
    if module_idx >= MAX_MODULES {
        return core::ptr::null_mut();
    }
    // SAFETY: per-module heap.
    let new_ptr = unsafe { MODULE_HEAPS[module_idx].realloc(ptr, new_size) };
    if new_ptr.is_null() && new_size > 0 {
        // SAFETY: as above.
        let fault_policy_enabled = unsafe { MODULE_HEAPS[module_idx].fault_on_alloc_failure };
        if fault_policy_enabled {
            crate::kernel::scheduler::raise_module_fault(
                module_idx,
                crate::kernel::step_guard::fault_type::STEP_ERROR,
            );
        }
    }
    new_ptr
}

/// Get heap statistics for a module.
pub fn heap_stats(module_idx: usize) -> HeapStats {
    if module_idx >= MAX_MODULES {
        return HeapStats::default();
    }
    // SAFETY: per-module heap.
    unsafe { MODULE_HEAPS[module_idx].stats() }
}

/// Check if a module has an active heap.
pub fn has_heap(module_idx: usize) -> bool {
    if module_idx >= MAX_MODULES {
        return false;
    }
    // SAFETY: per-module heap; read-only.
    unsafe { MODULE_HEAPS[module_idx].is_active() }
}

/// Opt the module's heap into zero-on-free. Must be called before
/// any allocation. When `true`, every `heap_free` memsets the chunk's
/// data region to 0 before re-linking it into the free list, closing
/// the cross-allocation residue channel for modules that handle
/// secrets. Sourced from the manifest's `heap.zero_on_free` flag.
pub fn set_zero_on_free(module_idx: usize, enabled: bool) {
    if module_idx >= MAX_MODULES {
        return;
    }
    // SAFETY: per-module heap; configured during instantiation.
    unsafe {
        MODULE_HEAPS[module_idx].zero_on_free = enabled;
    }
}

/// Query whether the module's heap zeroes on free.
pub fn zero_on_free_enabled(module_idx: usize) -> bool {
    if module_idx >= MAX_MODULES {
        return false;
    }
    // SAFETY: per-module heap; read-only.
    unsafe { MODULE_HEAPS[module_idx].zero_on_free }
}

/// Opt the module into kernel-managed fault on heap exhaustion.
/// When `true`, every `heap_alloc`/`heap_realloc` null return also
/// raises a `STEP_ERROR` fault — the declared `FaultPolicy` (Skip /
/// Restart) decides what happens at the next tick. Default `false`
/// keeps the caller-checks-NULL pattern. Sourced from the manifest's
/// `heap.alloc_failure_policy = "fault"` setting.
pub fn set_fault_on_alloc_failure(module_idx: usize, enabled: bool) {
    if module_idx >= MAX_MODULES {
        return;
    }
    // SAFETY: per-module heap; configured during instantiation.
    unsafe {
        MODULE_HEAPS[module_idx].fault_on_alloc_failure = enabled;
    }
}

/// Query whether the module's heap raises a fault on exhaustion.
pub fn fault_on_alloc_failure_enabled(module_idx: usize) -> bool {
    if module_idx >= MAX_MODULES {
        return false;
    }
    // SAFETY: per-module heap; read-only.
    unsafe { MODULE_HEAPS[module_idx].fault_on_alloc_failure }
}

/// Enable the trailing canary on this module's heap. Must be called
/// before any allocation — toggling mid-life would mismatch existing
/// chunks. When enabled, each `alloc()` reserves `HEAP_CANARY_SIZE`
/// extra bytes at the chunk tail; `free()` validates and logs on
/// mismatch. Sourced from the manifest's `heap.canary_enabled` flag.
pub fn set_canary_enabled(module_idx: usize, enabled: bool) {
    if module_idx >= MAX_MODULES {
        return;
    }
    // SAFETY: per-module heap; configured during instantiation.
    unsafe {
        MODULE_HEAPS[module_idx].canary_enabled = enabled;
    }
}

/// Query whether the trailing canary is enabled for this module's heap.
pub fn canary_enabled(module_idx: usize) -> bool {
    if module_idx >= MAX_MODULES {
        return false;
    }
    // SAFETY: per-module heap; read-only.
    unsafe { MODULE_HEAPS[module_idx].canary_enabled }
}
