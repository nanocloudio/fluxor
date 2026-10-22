//! Per-module heap allocator.
//!
//! Provides bounded dynamic memory allocation within each module's heap.
//! The allocator runs in kernel space (not in the module) for safety and
//! observability. Each module gets an independent heap carved from the
//! STATE_ARENA — no module can allocate from or free to another module's heap.
//!
//! Design: simple freelist with first-fit and immediate coalescing on free.
//! 8-byte header per block, 16-byte minimum allocation granularity.
//!
//! ## Committed and elastic heaps
//!
//! A heap has a CAP: the module type's declared arena (manifest
//! `arena_bytes` or its `module_arena_size` export), or the graph's
//! per-instance `heap.arena_bytes` override (params tag 0xEF). How the cap
//! is backed depends on the module and the platform:
//!
//! - **Committed**: one segment, the whole cap, carved at instantiation. Every
//!   gated module (its heap must sit where its protection regions cover it)
//!   and every module on a profile with one heap segment (`HEAP_SEGMENTS`
//!   == 1: RP and wasm, whose small static arenas are planned up front).
//! - **Elastic**: nothing is carved at instantiation. The first allocation
//!   carves a segment from the state arena, and a later allocation that no
//!   segment can serve carves the next, each at least as large as everything
//!   committed so far, until the committed total reaches the cap. Memory is
//!   committed only as the module uses it, so a reader type declared for the
//!   largest object it might touch costs each instance only what it touches.
//!
//! Elastic growth is bounded work: a carve is one state-arena allocation (a
//! first fit over that allocator's bounded free list, else a bump) plus
//! zeroing exactly the bytes carved, and the segment table is fixed. The
//! first segment is `cap >> (HEAP_SEGMENTS - 1)` (at least the platform
//! quantum) and each carve at least doubles what is committed, so
//! `HEAP_SEGMENTS` carves always reach the cap; the last slot takes all that
//! is left. Growth that cannot be satisfied — the cap reached, or the state
//! arena exhausted — fails LOUDLY: the allocation returns null, `fail_count`
//! and `grow_denied` count it, the kernel logs it (rate-limited to powers of
//! two), and a module declaring `heap.alloc_failure_policy = "fault"` faults.
//! Segments are returned to the state arena when the module is torn down or
//! removed (`detach_module_heap`), and wholesale at a rebuild.
//!
//! ## Concurrency
//!
//! Each `MODULE_HEAPS[i]` entry is owned by module `i`, which steps on
//! a single assigned core, so an individual heap is touched by one
//! core at a time and needs no cross-core synchronisation. Elastic growth
//! draws on the shared state arena, which serialises its own bookkeeping
//! (`loader::alloc_state`). See `docs/architecture/concurrency.md`.

use crate::kernel::exec::scheduler::MAX_MODULES;

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
// Segments
// ============================================================================

/// Segments one heap may hold: the platform profile's `HEAP_SEGMENTS`. 1 means
/// every heap is committed whole at instantiation.
pub const HEAP_SEGMENTS: usize = crate::kernel::config::HEAP_SEGMENTS;

/// Smallest segment an elastic heap carves: the platform quantum, so a
/// small heap is committed in one or two carves rather than in slivers.
const MIN_SEGMENT: usize = crate::kernel::config::ELASTIC_QUANTUM;

/// One contiguous region of a heap, with its own address-ordered free list.
/// Offsets are relative to `base`, as u32s, so the allocator is 32/64-bit
/// portable.
#[derive(Clone, Copy)]
struct Segment {
    /// Base address of the segment.
    base: *mut u8,
    /// Size of the segment in bytes.
    size: u32,
    /// Offset from base to the first free block header. A segment whose list
    /// is empty points at an allocated block, which `free_block` rejects.
    first_free_offset: u32,
}

impl Segment {
    const fn empty() -> Self {
        Self {
            base: core::ptr::null_mut(),
            size: 0,
            first_free_offset: 0,
        }
    }

    /// The segment over `base..base + size` as one free block, or `None`
    /// when it cannot hold a single minimum allocation.
    fn init(base: *mut u8, size: usize) -> Option<Self> {
        if base.is_null() || size < HEADER_SIZE + MIN_ALLOC || size > u32::MAX as usize {
            return None;
        }
        let hdr = base as *mut BlockHeader;
        // SAFETY: `base..base + size` is the caller-supplied region;
        // `hdr` writes its first 8 bytes.
        unsafe { (*hdr).set_free(size - HEADER_SIZE, 0) };
        Some(Self {
            base,
            size: size as u32,
            first_free_offset: 0,
        })
    }

    /// Whether `ptr` lies inside this segment.
    #[inline(always)]
    fn contains(&self, ptr: *const u8) -> bool {
        let b = self.base as usize;
        let p = ptr as usize;
        p >= b && p - b < self.size as usize
    }

    /// The header at `off`, if one can be there: 8-byte aligned and wholly
    /// inside the segment. Every header the allocator touches is reached
    /// through this, because the segment — headers included — is writable by
    /// the module: a gated module can put anything in it, and the kernel
    /// must never follow it outside the segment.
    #[inline(always)]
    fn header(&self, off: u32) -> Option<*mut BlockHeader> {
        let fits = (off as usize).checked_add(HEADER_SIZE)? <= self.size as usize;
        // SAFETY: `off + HEADER_SIZE <= self.size`, so the header lies inside
        // the segment.
        (fits && (off as usize).is_multiple_of(HEADER_SIZE))
            .then(|| unsafe { self.base.add(off as usize) as *mut BlockHeader })
    }

    /// Whether a block at `off` holding `data` bytes lies wholly inside the
    /// segment.
    #[inline(always)]
    fn fits(&self, off: u32, data: usize) -> bool {
        (off as usize)
            .checked_add(HEADER_SIZE)
            .and_then(|n| n.checked_add(data))
            .is_some_and(|end| end <= self.size as usize)
    }

    /// The free block at `off` (header pointer, header), if its header and
    /// its whole data region are inside the segment and it is marked free.
    /// The next link must lie strictly beyond it: the free list is kept in
    /// address order, which also bounds every walk and rules out cycles.
    #[inline(always)]
    fn free_block(&self, off: u32) -> Option<(*mut BlockHeader, BlockHeader)> {
        let p = self.header(off)?;
        // SAFETY: `header` checked the 8 bytes are inside the segment.
        let h = unsafe { *p };
        let linked = h.next_or_magic == 0 || h.next_or_magic > off;
        (!h.is_allocated() && self.fits(off, h.data_size()) && linked).then_some((p, h))
    }

    /// The allocated block whose data starts at `ptr` (offset, header
    /// pointer, header), if `ptr` is one this segment handed out.
    #[inline(always)]
    fn allocated_block(&self, ptr: *mut u8) -> Option<(u32, *mut BlockHeader, BlockHeader)> {
        let off = (ptr as usize)
            .checked_sub(self.base as usize)?
            .checked_sub(HEADER_SIZE)?;
        let off = u32::try_from(off).ok()?;
        let p = self.header(off)?;
        // SAFETY: `header` checked the 8 bytes are inside the segment.
        let h = unsafe { *p };
        (h.is_allocated() && h.next_or_magic == ALLOC_MAGIC && self.fits(off, h.data_size()))
            .then_some((off, p, h))
    }

    /// First fit for `aligned_size` data bytes: `(data pointer, chunk size)`.
    fn take(&mut self, aligned_size: usize) -> Option<(*mut u8, usize)> {
        let mut prev: Option<*mut BlockHeader> = None;
        let mut cur_offset = self.first_free_offset;
        while let Some((hdr_ptr, hdr)) = self.free_block(cur_offset) {
            let block_data_size = hdr.data_size();
            let next_free = hdr.next_or_magic;

            if block_data_size >= aligned_size {
                let remainder = block_data_size - aligned_size;
                // What replaces this block in the free list: the split-off
                // tail, or the block's successor.
                let replacement = if remainder >= HEADER_SIZE + MIN_ALLOC {
                    let new_free_offset = cur_offset + (HEADER_SIZE + aligned_size) as u32;
                    // SAFETY: the tail lies inside this block, which
                    // `free_block` found wholly inside the segment.
                    unsafe {
                        let new_hdr = self.base.add(new_free_offset as usize) as *mut BlockHeader;
                        (*new_hdr).set_free(remainder - HEADER_SIZE, next_free);
                        (*hdr_ptr).set_allocated(aligned_size);
                    }
                    new_free_offset
                } else {
                    // SAFETY: `hdr_ptr` is this block's validated header.
                    unsafe { (*hdr_ptr).set_allocated(block_data_size) };
                    next_free
                };
                match prev {
                    None => self.first_free_offset = replacement,
                    // SAFETY: the previous block's header, validated on the
                    // prior iteration.
                    Some(p) => unsafe { (*p).next_or_magic = replacement },
                }
                // SAFETY: reads the size `set_allocated` just wrote; the data
                // region lies inside the validated block.
                let (actual, data) = unsafe {
                    (
                        (*hdr_ptr).data_size(),
                        self.base.add(cur_offset as usize + HEADER_SIZE),
                    )
                };
                return Some((data, actual));
            }

            if next_free == 0 {
                break;
            }
            prev = Some(hdr_ptr);
            cur_offset = next_free;
        }
        None
    }

    /// `(free blocks, largest free block)`.
    fn free_stats(&self) -> (u16, usize) {
        let mut free_blocks: u16 = 0;
        let mut largest_free: usize = 0;
        let mut offset = self.first_free_offset;
        while let Some((_, hdr)) = self.free_block(offset) {
            free_blocks = free_blocks.saturating_add(1);
            largest_free = largest_free.max(hdr.data_size());
            if hdr.next_or_magic == 0 {
                break;
            }
            offset = hdr.next_or_magic;
        }
        (free_blocks, largest_free)
    }

    /// Unlink the free block at `offset`. Returns whether it was on the list.
    fn remove_from_free_list(&mut self, offset: u32) -> bool {
        let Some((_, target)) = self.free_block(offset) else {
            return false;
        };
        if self.first_free_offset == offset {
            self.first_free_offset = target.next_or_magic;
            return true;
        }
        let mut prev = self.first_free_offset;
        while let Some((p, h)) = self.free_block(prev) {
            if h.next_or_magic == offset {
                // SAFETY: a validated free header.
                unsafe { (*p).next_or_magic = target.next_or_magic };
                return true;
            }
            if h.next_or_magic == 0 || h.next_or_magic > offset {
                break;
            }
            prev = h.next_or_magic;
        }
        false
    }

    /// Insert a freed block at `offset` into the free list in address order,
    /// then coalesce with adjacent free blocks. The caller has validated the
    /// block (`allocated_block`, or a tail split from one).
    fn insert_free_and_coalesce(&mut self, offset: u32, data_size: usize) {
        // SAFETY: the caller validated the block, header included.
        let hdr_ptr = unsafe { self.base.add(offset as usize) as *mut BlockHeader };

        // The free block just before `offset`, if any. A walk that meets a
        // block it cannot trust stops there: the freed block is linked after
        // the last good one, and whatever lay beyond is left unreachable
        // rather than followed.
        let mut prev: Option<(u32, *mut BlockHeader)> = None;
        let mut next = self.first_free_offset;
        let head_valid = self.free_block(next).is_some();
        if head_valid && next < offset {
            let mut cur = next;
            next = 0;
            while let Some((p, h)) = self.free_block(cur) {
                prev = Some((cur, p));
                let n = h.next_or_magic;
                if n == 0 || n > offset || self.free_block(n).is_none() {
                    next = if n > offset && self.free_block(n).is_some() {
                        n
                    } else {
                        0
                    };
                    break;
                }
                cur = n;
            }
        } else if !head_valid {
            next = 0;
        }

        // Link: prev -> this -> next.
        // SAFETY: `hdr_ptr` is the validated block's header.
        unsafe { (*hdr_ptr).set_free(data_size, next) };
        match prev {
            // SAFETY: a validated free header.
            Some((_, p)) => unsafe { (*p).next_or_magic = offset },
            None => self.first_free_offset = offset,
        }

        // Coalesce forward: merge the next block if it is adjacent.
        let end_of_this = offset as usize + HEADER_SIZE + data_size;
        if next != 0 && end_of_this == next as usize {
            if let Some((_, nh)) = self.free_block(next) {
                // SAFETY: `hdr_ptr` as above; the merged block spans two
                // validated blocks.
                unsafe {
                    (*hdr_ptr).set_free(data_size + HEADER_SIZE + nh.data_size(), nh.next_or_magic)
                };
            }
        }

        // Coalesce backward: merge into the previous block if adjacent.
        if let Some((prev_off, p)) = prev {
            // SAFETY: both are validated headers.
            let (ph, ch) = unsafe { (*p, *hdr_ptr) };
            if prev_off as usize + HEADER_SIZE + ph.data_size() == offset as usize {
                // SAFETY: a validated free header.
                unsafe {
                    (*p).set_free(
                        ph.data_size() + HEADER_SIZE + ch.data_size(),
                        ch.next_or_magic,
                    )
                };
            }
        }
    }
}

/// The segments an elastic heap carved from the state arena, detached from
/// the module so its teardown can return them (`loader::ModuleMemory`).
#[derive(Clone, Copy)]
pub struct HeapSegments {
    segs: [(*mut u8, u32); HEAP_SEGMENTS],
    count: usize,
}

// SAFETY: plain state-arena ranges owned by nothing but this value until they
// are released; moving it between cores moves that ownership.
unsafe impl Send for HeapSegments {}

impl HeapSegments {
    /// No segments.
    pub const fn none() -> Self {
        Self {
            segs: [(core::ptr::null_mut(), 0); HEAP_SEGMENTS],
            count: 0,
        }
    }

    /// The `(base, size)` of each segment.
    pub fn iter(&self) -> impl Iterator<Item = (*mut u8, usize)> + '_ {
        self.segs
            .iter()
            .take(self.count)
            .map(|&(p, n)| (p, n as usize))
    }

    /// Bytes the segments hold.
    pub fn bytes(&self) -> usize {
        self.iter().map(|(_, n)| n).sum()
    }
}

// ============================================================================
// Per-module heap metadata
// ============================================================================

/// Per-module heap state, stored in kernel memory (not in module's arena).
#[derive(Clone, Copy)]
pub struct ModuleHeap {
    /// The heap's segments; `seg_count` of them are live.
    segs: [Segment; HEAP_SEGMENTS],
    seg_count: u8,
    /// The most the heap may commit, in bytes.
    cap: u32,
    /// Bytes its segments hold.
    committed: u32,
    /// Whether the heap carves its own segments on demand (and so owns them),
    /// or was handed one committed arena whose owner frees it.
    elastic: bool,
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
    /// Allocations refused because the heap could not grow: its cap was
    /// reached, or the state arena could not supply the carve.
    pub grow_denied: u16,
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
    /// Bytes the state arena zeroed for this module while its step was on
    /// the stack (`heap_zero_step_bytes`): a heap segment carved, or an arena
    /// committed, from memory the arena could not vouch was zero.
    zero_step_bytes: u64,
}

/// Bytes zeroed on any module's step, all modules together.
static ZERO_STEP_TOTAL: portable_atomic::AtomicU64 = portable_atomic::AtomicU64::new(0);

/// Account `bytes` the state arena just zeroed: against the stepping module
/// when a module's step is on the stack, and nowhere when the zeroing runs at
/// instantiation or teardown, where it belongs.
pub fn note_zeroed(bytes: usize) {
    if !crate::kernel::exec::scheduler::in_module_step() {
        return;
    }
    ZERO_STEP_TOTAL.fetch_add(bytes as u64, portable_atomic::Ordering::Relaxed);
    let idx = crate::kernel::exec::scheduler::current_module_index();
    if idx < crate::kernel::exec::scheduler::module_slots() {
        // SAFETY: the stepping module's own heap, on its core.
        unsafe {
            let h = &mut (*core::ptr::addr_of_mut!(MODULE_HEAPS))[idx];
            h.zero_step_bytes = h.zero_step_bytes.saturating_add(bytes as u64);
        }
    }
}

/// `heap_zero_step_bytes` for one module: bytes the state arena zeroed while
/// its step ran. Zero on Linux, where freed memory is returned to zero when it
/// is freed and nothing is zeroed on allocation.
pub fn heap_zero_step_bytes(module_idx: usize) -> u64 {
    if module_idx >= crate::kernel::exec::scheduler::module_slots() {
        return 0;
    }
    // SAFETY: a word read of the module's heap record.
    unsafe { (*core::ptr::addr_of!(MODULE_HEAPS))[module_idx].zero_step_bytes }
}

/// `heap_zero_step_bytes` summed over every module since boot.
pub fn heap_zero_step_bytes_total() -> u64 {
    ZERO_STEP_TOTAL.load(portable_atomic::Ordering::Relaxed)
}

/// Heap statistics queryable by modules.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct HeapStats {
    /// The heap's size in bytes: its cap, which an elastic heap commits only
    /// as it is used.
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
    /// The largest single allocation the heap can serve next: its largest
    /// free block, or what is still to commit when that is more. Under
    /// heavy fragmentation this is significantly smaller than
    /// `arena_size - allocated`, and surfacing it makes the fragmentation
    /// visible before a single over-large request returns null.
    pub largest_free: u32,
}

impl ModuleHeap {
    /// Create an empty (uninitialized) heap — for modules with no arena.
    pub const fn empty() -> Self {
        Self {
            segs: [Segment::empty(); HEAP_SEGMENTS],
            seg_count: 0,
            cap: 0,
            committed: 0,
            elastic: false,
            allocated: 0,
            alloc_count: 0,
            total_allocs: 0,
            high_water: 0,
            fail_count: 0,
            grow_denied: 0,
            zero_on_free: false,
            fault_on_alloc_failure: false,
            canary_enabled: false,
            zero_step_bytes: 0,
        }
    }

    /// A committed heap over the arena `base..base + size`: one segment,
    /// owned by whoever supplied it.
    ///
    /// The arena must be at least HEADER_SIZE + MIN_ALLOC bytes.
    pub fn init(base: *mut u8, size: usize) -> Self {
        let Some(seg) = Segment::init(base, size) else {
            return Self::empty();
        };
        let mut h = Self::empty();
        h.segs[0] = seg;
        h.seg_count = 1;
        h.cap = seg.size;
        h.committed = seg.size;
        h
    }

    /// An elastic heap that may commit up to `cap` bytes, carving segments
    /// from the state arena as allocations need them. Nothing is carved now.
    ///
    /// The cap is rounded down to the 8-byte block alignment, the granularity
    /// every segment is carved in, so a heap committed whole
    /// ([`commit_whole`](Self::commit_whole)) is exactly its cap and is
    /// recognised as such on every later `ARENA_GET`.
    pub fn init_elastic(cap: usize) -> Self {
        let cap = cap & !(HEADER_SIZE - 1);
        if cap < HEADER_SIZE + MIN_ALLOC || cap > u32::MAX as usize {
            return Self::empty();
        }
        let mut h = Self::empty();
        h.cap = cap as u32;
        h.elastic = true;
        h
    }

    /// Check if this heap is initialized (has a cap to allocate within).
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        self.cap > 0
    }

    /// Bytes committed so far, and the cap.
    pub fn footprint(&self) -> (usize, usize) {
        (self.committed as usize, self.cap as usize)
    }

    /// The size of the next segment an elastic heap carves to serve a
    /// request of `aligned_size` data bytes, or `None` when it cannot grow
    /// that far. At least what is already committed (so the committed total
    /// doubles), at least `cap >> (HEAP_SEGMENTS - 1)` and the platform
    /// quantum, at least the request, and never past the cap; the last slot
    /// takes everything that is left.
    fn next_segment(&self, aligned_size: usize) -> Option<usize> {
        if !self.elastic || self.seg_count as usize >= HEAP_SEGMENTS {
            return None;
        }
        let need = aligned_size.checked_add(HEADER_SIZE)?;
        let remaining = (self.cap - self.committed) as usize;
        if need > remaining {
            return None;
        }
        let first = (self.cap as usize >> (HEAP_SEGMENTS - 1)).max(MIN_SEGMENT);
        let last = self.seg_count as usize + 1 == HEAP_SEGMENTS;
        let want = if last {
            remaining
        } else {
            first.max(self.committed as usize).max(need).min(remaining)
        };
        // Segment headers are 8-byte aligned: keep every segment a multiple
        // of eight so its tail block's header stays aligned.
        let want = want & !(HEADER_SIZE - 1);
        (want >= need).then_some(want)
    }

    /// Carve the next segment for a request of `aligned_size` data bytes.
    /// Returns its index.
    fn grow(&mut self, aligned_size: usize) -> Option<usize> {
        let size = self.next_segment(aligned_size)?;
        // The state arena hands out zeroed memory; on Linux it zeroed it when
        // it was freed, so a step that grows its heap zeroes nothing.
        let base = crate::kernel::module::loader::alloc_state(size).ok()?;
        let Some(seg) = Segment::init(base, size) else {
            // SAFETY: the allocation just returned, referenced by nothing.
            unsafe { crate::kernel::module::loader::free_state_range(base, size) };
            return None;
        };
        let i = self.seg_count as usize;
        self.segs[i] = seg;
        self.seg_count += 1;
        self.committed += seg.size;
        Some(i)
    }

    /// A request for `size` user bytes, rounded to the allocator's
    /// granularity with the canary's room when enabled. `None` when it
    /// overflows or cannot fit the heap at all.
    fn aligned(&self, size: usize) -> Option<usize> {
        // Canary overhead is part of the rounding budget so the canary always
        // lives within the chunk. Every arithmetic step is checked: a wrapped
        // size would produce a tiny chunk that the caller's first write would
        // overrun by `size` bytes.
        let raw_need = if self.canary_enabled {
            size.checked_add(HEAP_CANARY_SIZE)
        } else {
            Some(size)
        };
        raw_need
            .and_then(|n| n.checked_add(MIN_ALLOC - 1))
            .map(|n| n & !(MIN_ALLOC - 1))
            .filter(|&n| n < self.cap as usize)
    }

    /// The segment holding `ptr`, if any.
    fn segment_of(&self, ptr: *const u8) -> Option<usize> {
        self.segs
            .iter()
            .take(self.seg_count as usize)
            .position(|s| s.contains(ptr))
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
        let Some(aligned_size) = self.aligned(size) else {
            self.fail_count = self.fail_count.saturating_add(1);
            return core::ptr::null_mut();
        };

        // First fit across the segments, then a new segment.
        let mut found = None;
        for i in 0..self.seg_count as usize {
            if let Some(hit) = self.segs[i].take(aligned_size) {
                found = Some(hit);
                break;
            }
        }
        if found.is_none() && self.elastic {
            match self.grow(aligned_size) {
                Some(i) => found = self.segs[i].take(aligned_size),
                None => {
                    self.grow_denied = self.grow_denied.saturating_add(1);
                    if self.grow_denied.is_power_of_two() {
                        log::error!(
                            "[heap] module {} heap cannot grow for {} B: {} of its {} B cap \
                             committed in {} segment(s) (denial #{}; raise the instance's \
                             `heap.arena_bytes` if this is its working set)",
                            crate::kernel::exec::scheduler::current_module_index(),
                            size,
                            self.committed,
                            self.cap,
                            self.seg_count,
                            self.grow_denied
                        );
                    }
                }
            }
        }
        let Some((data_ptr, actual_size)) = found else {
            self.fail_count = self.fail_count.saturating_add(1);
            return core::ptr::null_mut();
        };

        self.allocated += actual_size as u32;
        self.alloc_count += 1;
        self.total_allocs = self.total_allocs.saturating_add(1);
        if self.allocated > self.high_water {
            self.high_water = self.allocated;
        }
        // Trailing canary at the last 4 bytes of the chunk's data region.
        // Detection is at the chunk boundary, not the requested-size
        // boundary: a user write exactly `size` bytes is safe; a write past
        // chunk end clobbers the canary. Overruns into the alignment slack
        // between `size` and the canary pass undetected — the chunk-header
        // `ALLOC_MAGIC` sentinel catches writes into the next chunk.
        if self.canary_enabled {
            // SAFETY: `actual_size >= aligned_size >= HEAP_CANARY_SIZE`;
            // the 4 bytes are the chunk's last.
            unsafe {
                core::ptr::write_unaligned(
                    data_ptr.add(actual_size - HEAP_CANARY_SIZE) as *mut u32,
                    HEAP_CANARY,
                );
            }
        }
        data_ptr
    }

    /// Free a previously allocated block.
    ///
    /// Validates that ptr is within one of this module's segments and is a
    /// valid allocation. Passing null is a no-op. Coalesces with adjacent
    /// free blocks.
    pub fn free(&mut self, ptr: *mut u8) {
        if ptr.is_null() || !self.is_active() {
            return;
        }
        let found = self
            .segment_of(ptr)
            .and_then(|i| self.segs[i].allocated_block(ptr).map(|b| (i, b)));
        let Some((seg, (offset, _, hdr))) = found else {
            log::error!(
                "[heap] free: 0x{:x} is not a live allocation of this heap",
                ptr as usize
            );
            return;
        };
        let freed_size = hdr.data_size();

        // Validate the trailing canary before releasing the chunk.
        // A clobbered canary indicates the module wrote past its
        // allocation; the chunk is still returned to the pool (the
        // data is already lost — this is a detection hook, not a
        // recovery one).
        if self.canary_enabled && freed_size >= HEAP_CANARY_SIZE {
            // SAFETY: the chunk's last 4 bytes, inside the validated block.
            let read = unsafe {
                core::ptr::read_unaligned(ptr.add(freed_size - HEAP_CANARY_SIZE) as *const u32)
            };
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
            // SAFETY: the validated block's data region.
            unsafe { core::ptr::write_bytes(ptr, 0, freed_size) };
        }

        self.allocated = self.allocated.saturating_sub(freed_size as u32);
        self.alloc_count = self.alloc_count.saturating_sub(1);
        self.segs[seg].insert_free_and_coalesce(offset, freed_size);
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
        let found = self
            .segment_of(ptr)
            .and_then(|i| self.segs[i].allocated_block(ptr).map(|b| (i, b)));
        let Some((seg, (offset, hdr_ptr, hdr))) = found else {
            return core::ptr::null_mut();
        };
        let old_size = hdr.data_size();
        // Include canary cost in the new alignment when enabled —
        // an in-place grow that omitted this would write the new
        // canary at `chunk_end - 4`, landing inside the caller's
        // resized region. Checked arithmetic guards against
        // `realloc(ptr, usize::MAX)` shrinking the chunk while the
        // caller treats it as huge.
        let raw_need = if self.canary_enabled {
            new_size.checked_add(HEAP_CANARY_SIZE)
        } else {
            Some(new_size)
        };
        let Some(aligned_new) = raw_need
            .and_then(|n| n.checked_add(MIN_ALLOC - 1))
            .map(|n| n & !(MIN_ALLOC - 1))
        else {
            return core::ptr::null_mut();
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

        // Extend in place into the adjacent block when it is free and
        // together they are large enough.
        let s = &mut self.segs[seg];
        let next_block_offset = offset + (HEADER_SIZE + old_size) as u32;
        if let Some((_, next_hdr)) = s.free_block(next_block_offset) {
            let combined = old_size + HEADER_SIZE + next_hdr.data_size();
            if combined >= aligned_new && s.remove_from_free_list(next_block_offset) {
                let remainder = combined - aligned_new;
                let final_size = if remainder >= HEADER_SIZE + MIN_ALLOC {
                    let new_free_off = offset + (HEADER_SIZE + aligned_new) as u32;
                    let new_free_size = remainder - HEADER_SIZE;
                    // SAFETY: both headers lie inside this block and its
                    // validated neighbour.
                    unsafe {
                        (*hdr_ptr).set_allocated(aligned_new);
                        (*(s.base.add(new_free_off as usize) as *mut BlockHeader))
                            .set_free(new_free_size, 0);
                    }
                    s.insert_free_and_coalesce(new_free_off, new_free_size);
                    aligned_new
                } else {
                    // SAFETY: this block's validated header.
                    unsafe { (*hdr_ptr).set_allocated(combined) };
                    combined
                };
                self.allocated += (final_size - old_size) as u32;
                if self.allocated > self.high_water {
                    self.high_water = self.allocated;
                }
                // Stamp a fresh canary at the new chunk tail —
                // the grow moved `chunk_end`, so the canary
                // must move with it.
                if self.canary_enabled && final_size >= HEAP_CANARY_SIZE {
                    // SAFETY: the resized chunk's last 4 bytes.
                    unsafe {
                        core::ptr::write_unaligned(
                            ptr.add(final_size - HEAP_CANARY_SIZE) as *mut u32,
                            HEAP_CANARY,
                        );
                    }
                }
                return ptr;
            }
        }

        // Fall back to alloc + copy + free (the new chunk may be in another
        // segment, or a new one). With canary enabled, `old_size` includes
        // the trailing canary bytes — copying those into the new chunk would
        // land the canary value at an internal user-readable offset and
        // confuse the next overrun-detection scan. Clamp the copy to the user
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
        // SAFETY: `copy_size` is within both validated chunks; they are
        // disjoint allocations.
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
        for s in self.segs.iter().take(self.seg_count as usize) {
            let (n, l) = s.free_stats();
            free_blocks = free_blocks.saturating_add(n);
            largest_free = largest_free.max(l);
        }
        // What an elastic heap could still commit serves a request too.
        if self.elastic && (self.seg_count as usize) < HEAP_SEGMENTS {
            let remaining = ((self.cap - self.committed) as usize) & !(HEADER_SIZE - 1);
            largest_free = largest_free.max(remaining.saturating_sub(HEADER_SIZE));
        }
        HeapStats {
            arena_size: self.cap,
            allocated: self.allocated,
            alloc_count: self.alloc_count,
            total_allocs: self.total_allocs,
            high_water: self.high_water,
            free_blocks,
            _pad: 0,
            largest_free: largest_free.min(u32::MAX as usize) as u32,
        }
    }

    /// Commit an elastic heap's whole cap as one segment, for a module that
    /// asks for its arena as raw memory (`ARENA_GET`) rather than through
    /// `heap_alloc`. Only before the heap has grown (or when it already is
    /// one whole segment): a heap that grew in pieces has no contiguous
    /// arena to hand out. `(base, size)`.
    fn commit_whole(&mut self) -> Option<(*mut u8, usize)> {
        if !self.elastic {
            return None;
        }
        if self.seg_count == 1 && self.segs[0].size == self.cap {
            return Some((self.segs[0].base, self.cap as usize));
        }
        if self.seg_count != 0 {
            return None;
        }
        let size = self.cap as usize;
        let base = crate::kernel::module::loader::alloc_state(size).ok()?;
        let Some(seg) = Segment::init(base, size) else {
            // SAFETY: the allocation just returned, referenced by nothing.
            unsafe { crate::kernel::module::loader::free_state_range(base, size) };
            return None;
        };
        self.segs[0] = seg;
        self.seg_count = 1;
        self.committed = seg.size;
        Some((base, size))
    }

    /// The segments this heap owns (an elastic heap's carves; a committed
    /// heap's arena belongs to whoever supplied it).
    fn owned_segments(&self) -> HeapSegments {
        let mut out = HeapSegments::none();
        if self.elastic {
            for s in self.segs.iter().take(self.seg_count as usize) {
                out.segs[out.count] = (s.base, s.size);
                out.count += 1;
            }
        }
        out
    }
}

// ============================================================================
// Global heap state (indexed by module)
// ============================================================================

/// Per-module heap metadata, stored in kernel memory.
static mut MODULE_HEAPS: [ModuleHeap; MAX_MODULES] = [const { ModuleHeap::empty() }; MAX_MODULES];

/// Initialize a module's committed heap over an arena allocation.
/// Called by the loader during instantiation for a module whose heap is
/// committed whole (see the module header).
pub fn init_module_heap(module_idx: usize, arena_ptr: *mut u8, arena_size: usize) {
    if module_idx >= crate::kernel::exec::scheduler::module_slots() {
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

/// Initialize a module's elastic heap with a cap of `cap` bytes: nothing is
/// committed until it allocates.
pub fn init_module_heap_elastic(module_idx: usize, cap: usize) {
    if module_idx >= crate::kernel::exec::scheduler::module_slots() {
        return;
    }
    // SAFETY: as `init_module_heap`.
    unsafe {
        MODULE_HEAPS[module_idx] = ModuleHeap::init_elastic(cap);
    }
    log::debug!("[heap] module {module_idx} elastic heap cap {cap} bytes");
}

/// Whether heaps on this platform can be elastic at all.
pub const fn elastic_heaps() -> bool {
    HEAP_SEGMENTS > 1
}

/// Reset a module's heap (called on graph reconfigure).
pub fn reset_module_heap(module_idx: usize) {
    if module_idx >= crate::kernel::exec::scheduler::module_slots() {
        return;
    }
    // SAFETY: as above; reconfigure runs between graph rebuilds.
    unsafe {
        MODULE_HEAPS[module_idx] = ModuleHeap::empty();
    }
}

/// Detach a module's heap at teardown: the slot is emptied and the segments
/// an elastic heap carved are handed back for the caller to release with the
/// rest of the module's memory. A committed heap's arena is not among them;
/// its owner frees it.
pub fn detach_module_heap(module_idx: usize) -> HeapSegments {
    if module_idx >= crate::kernel::exec::scheduler::module_slots() {
        return HeapSegments::none();
    }
    // SAFETY: teardown context — the module is unspliced and never stepped
    // again, so nothing else touches its heap.
    unsafe {
        let owned = MODULE_HEAPS[module_idx].owned_segments();
        MODULE_HEAPS[module_idx] = ModuleHeap::empty();
        owned
    }
}

/// Reset all module heaps. Called when the state arena is reset wholesale,
/// so no heap keeps segments of the previous graph.
pub fn reset_all() {
    // SAFETY: scheduler-side reset; no module is stepping when this runs.
    unsafe {
        let heaps = &raw mut MODULE_HEAPS;
        for slot in (*heaps).iter_mut() {
            *slot = ModuleHeap::empty();
        }
    }
}

/// The heap's whole-cap arena when it was committed whole — what `ARENA_GET`
/// hands a module that declared raw arena use (committed at instantiation,
/// [`commit_whole`]). Never allocates: a step that asks for an arena it did
/// not declare gets none.
pub fn committed_whole(module_idx: usize) -> Option<(*mut u8, usize)> {
    if module_idx >= crate::kernel::exec::scheduler::module_slots() {
        return None;
    }
    // SAFETY: a read of the module's heap record on its core.
    let h = unsafe { &(*core::ptr::addr_of!(MODULE_HEAPS))[module_idx] };
    (h.elastic && h.seg_count == 1 && h.segs[0].size == h.cap)
        .then(|| (h.segs[0].base, h.cap as usize))
}

/// Commit the calling module's whole heap as one contiguous arena, for
/// `ARENA_GET`. `None` for a committed heap (its arena is the scheduler's
/// record) and for an elastic heap that already grew in pieces.
pub fn commit_whole(module_idx: usize) -> Option<(*mut u8, usize)> {
    if module_idx >= crate::kernel::exec::scheduler::module_slots() {
        return None;
    }
    // SAFETY: per-module heap owned by the calling module's core.
    let r = unsafe { MODULE_HEAPS[module_idx].commit_whole() };
    if r.is_none() && is_elastic(module_idx) {
        log::error!(
            "[heap] module {module_idx}: ARENA_GET after its heap grew in segments — there is \
             no contiguous arena to hand out"
        );
    }
    r
}

/// Whether module `module_idx` has an elastic heap.
pub fn is_elastic(module_idx: usize) -> bool {
    if module_idx >= crate::kernel::exec::scheduler::module_slots() {
        return false;
    }
    // SAFETY: per-module heap; read-only.
    unsafe { MODULE_HEAPS[module_idx].elastic }
}

/// `(committed, cap)` of module `module_idx`'s heap, in bytes.
pub fn heap_footprint(module_idx: usize) -> (usize, usize) {
    if module_idx >= crate::kernel::exec::scheduler::module_slots() {
        return (0, 0);
    }
    // SAFETY: per-module heap; a word-sized read of each field.
    unsafe { MODULE_HEAPS[module_idx].footprint() }
}

/// Across every module: `(heaps, committed bytes, cap bytes, grow denials)`.
/// What `[arena]` reports beside the state arena, so the bytes heaps hold and
/// the bytes they could ask for are both visible.
pub fn heaps_usage() -> (usize, usize, usize, usize) {
    let mut n = 0;
    let mut committed = 0;
    let mut cap = 0;
    let mut denied = 0;
    // SAFETY: scheduler-side read; each field is read whole.
    unsafe {
        let heaps = &raw const MODULE_HEAPS;
        for h in (*heaps).iter() {
            if h.is_active() {
                n += 1;
                committed += h.committed as usize;
                cap += h.cap as usize;
                denied += h.grow_denied as usize;
            }
        }
    }
    (n, committed, cap, denied)
}

/// Allocate from the current module's heap. Returns the allocated
/// pointer or null on failure. When `fault_on_alloc_failure` is set,
/// a null return also raises a `STEP_ERROR` fault so the module's
/// declared `FaultPolicy` runs at the next tick; the C-style
/// caller-checks-NULL pattern stays the default.
pub fn heap_alloc(module_idx: usize, size: usize) -> *mut u8 {
    if module_idx >= crate::kernel::exec::scheduler::module_slots() {
        return core::ptr::null_mut();
    }
    // SAFETY: per-module heap owned by the calling module's core.
    let ptr = unsafe { MODULE_HEAPS[module_idx].alloc(size) };
    if ptr.is_null() {
        // SAFETY: as above.
        let fault_policy_enabled = unsafe { MODULE_HEAPS[module_idx].fault_on_alloc_failure };
        if fault_policy_enabled {
            crate::kernel::exec::scheduler::raise_module_fault(
                module_idx,
                crate::kernel::exec::step_guard::fault_type::STEP_ERROR,
            );
        }
    }
    ptr
}

/// Free memory from the current module's heap.
pub fn heap_free(module_idx: usize, ptr: *mut u8) {
    if module_idx >= crate::kernel::exec::scheduler::module_slots() {
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
    if module_idx >= crate::kernel::exec::scheduler::module_slots() {
        return core::ptr::null_mut();
    }
    // SAFETY: per-module heap.
    let new_ptr = unsafe { MODULE_HEAPS[module_idx].realloc(ptr, new_size) };
    if new_ptr.is_null() && new_size > 0 {
        // SAFETY: as above.
        let fault_policy_enabled = unsafe { MODULE_HEAPS[module_idx].fault_on_alloc_failure };
        if fault_policy_enabled {
            crate::kernel::exec::scheduler::raise_module_fault(
                module_idx,
                crate::kernel::exec::step_guard::fault_type::STEP_ERROR,
            );
        }
    }
    new_ptr
}

/// Get heap statistics for a module.
pub fn heap_stats(module_idx: usize) -> HeapStats {
    if module_idx >= crate::kernel::exec::scheduler::module_slots() {
        return HeapStats::default();
    }
    // SAFETY: per-module heap.
    unsafe { MODULE_HEAPS[module_idx].stats() }
}

/// Check if a module has an active heap.
pub fn has_heap(module_idx: usize) -> bool {
    if module_idx >= crate::kernel::exec::scheduler::module_slots() {
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
    if module_idx >= crate::kernel::exec::scheduler::module_slots() {
        return;
    }
    // SAFETY: per-module heap; configured during instantiation.
    unsafe {
        MODULE_HEAPS[module_idx].zero_on_free = enabled;
    }
}

/// Query whether the module's heap zeroes on free.
pub fn zero_on_free_enabled(module_idx: usize) -> bool {
    if module_idx >= crate::kernel::exec::scheduler::module_slots() {
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
    if module_idx >= crate::kernel::exec::scheduler::module_slots() {
        return;
    }
    // SAFETY: per-module heap; configured during instantiation.
    unsafe {
        MODULE_HEAPS[module_idx].fault_on_alloc_failure = enabled;
    }
}

/// Query whether the module's heap raises a fault on exhaustion.
pub fn fault_on_alloc_failure_enabled(module_idx: usize) -> bool {
    if module_idx >= crate::kernel::exec::scheduler::module_slots() {
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
    if module_idx >= crate::kernel::exec::scheduler::module_slots() {
        return;
    }
    // SAFETY: per-module heap; configured during instantiation.
    unsafe {
        MODULE_HEAPS[module_idx].canary_enabled = enabled;
    }
}

/// Query whether the trailing canary is enabled for this module's heap.
pub fn canary_enabled(module_idx: usize) -> bool {
    if module_idx >= crate::kernel::exec::scheduler::module_slots() {
        return false;
    }
    // SAFETY: per-module heap; read-only.
    unsafe { MODULE_HEAPS[module_idx].canary_enabled }
}
