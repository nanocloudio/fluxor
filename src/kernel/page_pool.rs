//! Physical page pool for demand-paged arenas (E10-S1).
//!
//! Manages a fixed pool of 4KB physical pages. Each page has a descriptor
//! tracking its owner, state, virtual page index, and LRU counter.
//! Eviction uses the clock (second-chance) algorithm.

/// Page size in bytes (4KB, matching AArch64 granule).
pub const PAGE_SIZE: usize = 4096;

/// Maximum number of pages in the pool. 256 pages = 1MB.
/// Can be overridden at init time with a smaller count.
pub const MAX_POOL_PAGES: usize = 256;

/// Page states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PageState {
    /// Page is free (in free list).
    Free = 0,
    /// Page is mapped and in use.
    Mapped = 1,
    /// Page is being evicted (dirty writeback in progress).
    Evicting = 2,
    /// Page is being loaded from backing store.
    Loading = 3,
    /// Page is being written back (async flush).
    Writeback = 4,
}

/// Page descriptor flags.
pub mod page_flags {
    /// Page has been modified since load.
    pub const DIRTY: u8 = 0x01;
    /// Page is pinned (cannot be evicted).
    pub const PINNED: u8 = 0x02;
    /// Page is currently being loaded (DMA in progress).
    pub const LOADING: u8 = 0x04;
    /// Page has been accessed since last clock sweep (second-chance bit).
    pub const ACCESSED: u8 = 0x08;
}

/// 16-byte page descriptor.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct PageDescriptor {
    /// Module that owns this page (0xFF = free).
    pub owner_module: u8,
    /// Current page state.
    pub state: u8,
    /// Flags (DIRTY, PINNED, LOADING, ACCESSED).
    pub flags: u8,
    /// Arena ID within the owning module (for future multi-arena support).
    pub arena_id: u8,
    /// Virtual page index within the module's paged arena.
    pub vpage_idx: u32,
    /// LRU counter (incremented on each access).
    pub lru_counter: u32,
    /// Next free page index (only valid when state == Free). u32::MAX = end.
    pub next_free: u32,
}

impl PageDescriptor {
    pub const fn free() -> Self {
        Self {
            owner_module: 0xFF,
            state: PageState::Free as u8,
            flags: 0,
            arena_id: 0,
            vpage_idx: 0,
            lru_counter: 0,
            next_free: u32::MAX,
        }
    }

    #[inline]
    pub fn is_free(&self) -> bool {
        self.state == PageState::Free as u8
    }

    #[inline]
    pub fn is_mapped(&self) -> bool {
        self.state == PageState::Mapped as u8
    }

    #[inline]
    pub fn is_dirty(&self) -> bool {
        self.flags & page_flags::DIRTY != 0
    }

    #[inline]
    pub fn is_pinned(&self) -> bool {
        self.flags & page_flags::PINNED != 0
    }

    #[inline]
    pub fn is_accessed(&self) -> bool {
        self.flags & page_flags::ACCESSED != 0
    }
}

/// The physical page pool.
pub struct PagePool {
    /// Page descriptors, one per physical page.
    descriptors: [PageDescriptor; MAX_POOL_PAGES],
    /// Base physical address of the page pool memory.
    base_addr: usize,
    /// Number of active pages in the pool (<= MAX_POOL_PAGES).
    page_count: usize,
    /// Head of the free list (index into descriptors). u32::MAX = empty.
    free_head: u32,
    /// Number of free pages.
    free_count: usize,
    /// Global LRU counter (monotonically increasing).
    global_lru: u32,
    /// Clock hand for eviction (index into descriptors).
    clock_hand: usize,
    /// Whether the pool has been initialized.
    initialized: bool,
}

impl Default for PagePool {
    fn default() -> Self {
        Self::new()
    }
}

impl PagePool {
    pub const fn new() -> Self {
        Self {
            descriptors: [PageDescriptor::free(); MAX_POOL_PAGES],
            base_addr: 0,
            page_count: 0,
            free_head: u32::MAX,
            free_count: 0,
            global_lru: 0,
            clock_hand: 0,
            initialized: false,
        }
    }

    /// Initialize the pool with a contiguous physical memory region.
    ///
    /// `base_addr`: physical address of the first page.
    /// `count`: number of 4KB pages available.
    pub fn init(&mut self, base_addr: usize, count: usize) {
        let count = count.min(MAX_POOL_PAGES);
        self.base_addr = base_addr;
        self.page_count = count;
        self.global_lru = 0;
        self.clock_hand = 0;

        // Build free list: 0 -> 1 -> 2 -> ... -> (count-1) -> END
        if count > 0 {
            self.free_head = 0;
            let mut i = 0;
            while i < count {
                self.descriptors[i] = PageDescriptor::free();
                self.descriptors[i].next_free = if i + 1 < count {
                    (i + 1) as u32
                } else {
                    u32::MAX
                };
                i += 1;
            }
            self.free_count = count;
        } else {
            self.free_head = u32::MAX;
            self.free_count = 0;
        }

        self.initialized = true;
    }

    /// Check if the pool is initialized and has pages.
    #[inline]
    pub fn is_active(&self) -> bool {
        self.initialized && self.page_count > 0
    }

    /// Get the physical address of a page by index.
    #[inline]
    pub fn page_phys_addr(&self, page_idx: usize) -> usize {
        self.base_addr + page_idx * PAGE_SIZE
    }

    /// Get a mutable pointer to a page's memory.
    #[inline]
    pub fn page_ptr(&self, page_idx: usize) -> *mut u8 {
        self.page_phys_addr(page_idx) as *mut u8
    }

    /// Allocate a free page for a module.
    ///
    /// Returns Some(page_index) on success, None if pool is empty.
    pub fn alloc(&mut self, module_idx: u8) -> Option<usize> {
        if self.free_head == u32::MAX {
            return None;
        }

        let idx = self.free_head as usize;
        let desc = &mut self.descriptors[idx];
        self.free_head = desc.next_free;
        self.free_count -= 1;

        desc.owner_module = module_idx;
        desc.state = PageState::Loading as u8;
        desc.flags = page_flags::LOADING;
        desc.vpage_idx = 0;
        desc.lru_counter = self.global_lru;
        desc.next_free = u32::MAX;
        self.global_lru += 1;

        Some(idx)
    }

    /// Free a page back to the pool.
    pub fn free(&mut self, page_idx: usize) {
        if page_idx >= self.page_count {
            return;
        }

        let desc = &mut self.descriptors[page_idx];
        desc.owner_module = 0xFF;
        desc.state = PageState::Free as u8;
        desc.flags = 0;
        desc.vpage_idx = 0;
        desc.lru_counter = 0;
        desc.next_free = self.free_head;
        self.free_head = page_idx as u32;
        self.free_count += 1;
    }

    /// Mark a page as mapped (loading complete).
    pub fn mark_mapped(&mut self, page_idx: usize, vpage_idx: u32) {
        if page_idx >= self.page_count {
            return;
        }
        let desc = &mut self.descriptors[page_idx];
        desc.state = PageState::Mapped as u8;
        desc.flags = page_flags::ACCESSED; // clear LOADING, set ACCESSED
        desc.vpage_idx = vpage_idx;
        desc.lru_counter = self.global_lru;
        self.global_lru += 1;
    }

    /// Mark a page as dirty (written to).
    pub fn mark_dirty(&mut self, page_idx: usize) {
        if page_idx >= self.page_count {
            return;
        }
        self.descriptors[page_idx].flags |= page_flags::DIRTY;
    }

    /// Mark a page as accessed (for clock algorithm).
    pub fn mark_accessed(&mut self, page_idx: usize) {
        if page_idx >= self.page_count {
            return;
        }
        self.descriptors[page_idx].flags |= page_flags::ACCESSED;
        self.descriptors[page_idx].lru_counter = self.global_lru;
        self.global_lru += 1;
    }

    /// Pin a page (prevent eviction).
    pub fn pin(&mut self, page_idx: usize) {
        if page_idx >= self.page_count {
            return;
        }
        self.descriptors[page_idx].flags |= page_flags::PINNED;
    }

    /// Unpin a page.
    pub fn unpin(&mut self, page_idx: usize) {
        if page_idx >= self.page_count {
            return;
        }
        self.descriptors[page_idx].flags &= !page_flags::PINNED;
    }

    /// Evict a page using the clock (second-chance) algorithm.
    ///
    /// Scans mapped pages, skipping PINNED and LOADING pages.
    /// On first pass, clears ACCESSED bit. On second encounter with
    /// ACCESSED cleared, selects the page for eviction.
    ///
    /// If `prefer_module` is not 0xFF, prefer evicting from that module
    /// first (for per-module pressure). Falls back to global eviction.
    ///
    /// Returns Some(page_index) of the evicted page (now in Evicting state),
    /// or None if no evictable page found.
    pub fn evict_clock(&mut self, prefer_module: u8) -> Option<usize> {
        if self.page_count == 0 {
            return None;
        }

        // Two full rotations: enough for second-chance to clear all accessed bits
        let max_scan = self.page_count * 2;

        for _ in 0..max_scan {
            let idx = self.clock_hand;
            self.clock_hand = (self.clock_hand + 1) % self.page_count;

            let desc = &self.descriptors[idx];

            // Skip non-mapped pages
            if desc.state != PageState::Mapped as u8 {
                continue;
            }

            // Skip pinned or loading
            if desc.flags & (page_flags::PINNED | page_flags::LOADING) != 0 {
                continue;
            }

            // Prefer the specified module
            if prefer_module != 0xFF && desc.owner_module != prefer_module {
                continue;
            }

            // Second-chance: if accessed, clear and skip
            if desc.flags & page_flags::ACCESSED != 0 {
                self.descriptors[idx].flags &= !page_flags::ACCESSED;
                continue;
            }

            // Found a victim
            self.descriptors[idx].state = PageState::Evicting as u8;
            return Some(idx);
        }

        // If prefer_module was set and we found nothing, try global
        if prefer_module != 0xFF {
            return self.evict_clock(0xFF);
        }

        None
    }

    /// Free all pages owned by a module (called on module teardown).
    pub fn free_module_pages(&mut self, module_idx: u8) {
        let mut i = 0;
        while i < self.page_count {
            if self.descriptors[i].owner_module == module_idx
                && self.descriptors[i].state != PageState::Free as u8
            {
                self.free(i);
            }
            i += 1;
        }
    }

    /// Count resident (mapped) pages for a module.
    pub fn resident_count(&self, module_idx: u8) -> usize {
        let mut count = 0;
        let mut i = 0;
        while i < self.page_count {
            if self.descriptors[i].owner_module == module_idx && self.descriptors[i].is_mapped() {
                count += 1;
            }
            i += 1;
        }
        count
    }

    /// Count dirty pages for a module.
    pub fn dirty_count(&self, module_idx: u8) -> usize {
        let mut count = 0;
        let mut i = 0;
        while i < self.page_count {
            if self.descriptors[i].owner_module == module_idx && self.descriptors[i].is_dirty() {
                count += 1;
            }
            i += 1;
        }
        count
    }

    /// Number of free pages.
    #[inline]
    pub fn free_pages(&self) -> usize {
        self.free_count
    }

    /// Total pages in pool.
    #[inline]
    pub fn total_pages(&self) -> usize {
        self.page_count
    }

    /// Get a reference to a page descriptor.
    #[inline]
    pub fn descriptor(&self, page_idx: usize) -> &PageDescriptor {
        &self.descriptors[page_idx]
    }

    /// Get a mutable reference to a page descriptor.
    #[inline]
    pub fn descriptor_mut(&mut self, page_idx: usize) -> &mut PageDescriptor {
        &mut self.descriptors[page_idx]
    }

    /// Find a mapped page by (module, vpage_idx). Returns page index or None.
    pub fn find_page(&self, module_idx: u8, vpage_idx: u32) -> Option<usize> {
        let mut i = 0;
        while i < self.page_count {
            let d = &self.descriptors[i];
            if d.owner_module == module_idx
                && d.vpage_idx == vpage_idx
                && (d.state == PageState::Mapped as u8 || d.state == PageState::Loading as u8)
            {
                return Some(i);
            }
            i += 1;
        }
        None
    }
}

// ============================================================================
// Global pool instance
// ============================================================================

static mut POOL: PagePool = PagePool::new();

/// Get a mutable pointer to the global pool.
#[inline(always)]
fn pool() -> *mut PagePool {
    &raw mut POOL
}

/// Initialize the global page pool.
pub fn pool_init(base_addr: usize, page_count: usize) {
    unsafe {
        (*pool()).init(base_addr, page_count);
    }
}

/// Allocate a page for a module.
pub fn pool_alloc(module_idx: u8) -> Option<usize> {
    unsafe { (*pool()).alloc(module_idx) }
}

/// Free a page.
pub fn pool_free(page_idx: usize) {
    unsafe {
        (*pool()).free(page_idx);
    }
}

/// Evict using clock algorithm, preferring pages from the given module.
pub fn pool_evict_clock(module_idx: u8) -> Option<usize> {
    unsafe { (*pool()).evict_clock(module_idx) }
}

/// Mark a page as mapped after loading.
pub fn pool_mark_mapped(page_idx: usize, vpage_idx: u32) {
    unsafe {
        (*pool()).mark_mapped(page_idx, vpage_idx);
    }
}

/// Mark a page as dirty.
pub fn pool_mark_dirty(page_idx: usize) {
    unsafe {
        (*pool()).mark_dirty(page_idx);
    }
}

/// Mark a page as accessed.
pub fn pool_mark_accessed(page_idx: usize) {
    unsafe {
        (*pool()).mark_accessed(page_idx);
    }
}

/// Free all pages for a module.
pub fn pool_free_module(module_idx: u8) {
    unsafe {
        (*pool()).free_module_pages(module_idx);
    }
}

/// Count resident pages for a module.
pub fn pool_resident_count(module_idx: u8) -> usize {
    unsafe { (*pool()).resident_count(module_idx) }
}

/// Count dirty pages for a module.
pub fn pool_dirty_count(module_idx: u8) -> usize {
    unsafe { (*pool()).dirty_count(module_idx) }
}

/// Number of free pages in pool.
pub fn pool_free_pages() -> usize {
    unsafe { (*pool()).free_pages() }
}

/// Total pages in pool.
pub fn pool_total_pages() -> usize {
    unsafe { (*pool()).total_pages() }
}

/// Check if pool is active.
pub fn pool_is_active() -> bool {
    unsafe { (*pool()).is_active() }
}

/// Get physical address of a page.
pub fn pool_page_phys_addr(page_idx: usize) -> usize {
    unsafe { (*pool()).page_phys_addr(page_idx) }
}

/// Get pointer to page memory.
pub fn pool_page_ptr(page_idx: usize) -> *mut u8 {
    unsafe { (*pool()).page_ptr(page_idx) }
}

/// Find a mapped page.
pub fn pool_find_page(module_idx: u8, vpage_idx: u32) -> Option<usize> {
    unsafe { (*pool()).find_page(module_idx, vpage_idx) }
}

/// Get descriptor copy.
pub fn pool_descriptor(page_idx: usize) -> PageDescriptor {
    unsafe { (*pool()).descriptors[page_idx] }
}

/// Pin a page.
pub fn pool_pin(page_idx: usize) {
    unsafe {
        (*pool()).pin(page_idx);
    }
}

/// Unpin a page.
pub fn pool_unpin(page_idx: usize) {
    unsafe {
        (*pool()).unpin(page_idx);
    }
}

/// Get mutable reference to the global pool (for pager use).
///
/// # Safety
/// Returns an aliasing `&mut` to the static `POOL`. Caller must ensure
/// no other reference to `POOL` is live for the returned reference's
/// lifetime — in practice this is only sound from the pager / kernel
/// init path running on the boot core before any module is stepped.
pub unsafe fn pool_mut() -> &'static mut PagePool {
    let p = &raw mut POOL;
    &mut *p
}
