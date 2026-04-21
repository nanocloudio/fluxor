//! BCM2712 memory support.

pub mod backing_store {
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
    static mut RAMDISK: [[u8; PAGE_SIZE]; MAX_RAMDISK_PAGES] =
        [[0u8; PAGE_SIZE]; MAX_RAMDISK_PAGES];

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
            {
                *(&raw mut RAMDISK_NEXT_OFFSET) = 0;
            }
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
                            return -1;
                        }
                        *rd_next = offset + virtual_pages;
                        backing_offset = offset;
                    }
                    #[cfg(not(feature = "chip-bcm2712"))]
                    {
                        backing_offset = 0;
                    }
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
        if buf.is_null() {
            return -22;
        }
        let arenas = &raw const ARENAS;
        let info = unsafe {
            if arena_id >= MAX_ARENAS || !(*arenas)[arena_id].active {
                return -19;
            }
            (*arenas)[arena_id]
        };
        if vpage_idx >= info.virtual_pages {
            return -22;
        }

        match info.backing_type {
            BackingType::RamDisk => {
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
                {
                    -38
                } // ENOSYS
            }
            BackingType::None => {
                unsafe {
                    core::ptr::write_bytes(buf, 0, PAGE_SIZE);
                }
                0
            }
        }
    }

    pub fn backing_write(arena_id: usize, vpage_idx: u32, buf: *const u8) -> i32 {
        if buf.is_null() {
            return -22;
        }
        let arenas = &raw const ARENAS;
        let info = unsafe {
            if arena_id >= MAX_ARENAS || !(*arenas)[arena_id].active {
                return -19;
            }
            (*arenas)[arena_id]
        };
        if vpage_idx >= info.virtual_pages {
            return -22;
        }

        match info.backing_type {
            BackingType::RamDisk => {
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
                {
                    -38
                } // ENOSYS
            }
            BackingType::None => 0,
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
}

pub mod pager {
    //! Demand pager: page fault handler, dirty tracking, and writeback.
    //!
    //! When a module accesses an unmapped page in its paged arena, the data abort
    //! handler calls `handle_page_fault()`. This function:
    //! 1. Allocates a physical page (evicting if necessary)
    //! 2. Reads the page from backing store
    //! 3. Maps the page in the module's page table
    //! 4. Invalidates TLB
    //! 5. Returns control to the faulting instruction
    //!
    //! Dirty page writeback is performed on eviction or via explicit sync.

    use crate::kernel::backing_store;
    use crate::kernel::page_pool::{self, page_flags, PAGE_SIZE};
    use crate::kernel::scheduler::MAX_MODULES;

    // ============================================================================
    // Per-module pager state
    // ============================================================================

    /// Per-module paged arena configuration.
    #[derive(Clone, Copy)]
    pub struct PagedArenaConfig {
        /// Whether this module has a paged arena.
        pub active: bool,
        /// Base virtual address of the paged arena.
        pub base_vaddr: usize,
        /// Total virtual size in bytes.
        pub virtual_size: usize,
        /// Arena ID in the backing store.
        pub arena_id: u8,
        /// Maximum faults allowed per step (budget).
        pub max_faults_per_step: u16,
        /// Maximum resident pages.
        pub resident_max_pages: u32,
        /// Prefault page count (pages loaded at init).
        pub prefault_pages: u16,
        /// Writeback policy.
        pub writeback: backing_store::WritebackPolicy,
    }

    impl PagedArenaConfig {
        pub const fn empty() -> Self {
            Self {
                active: false,
                base_vaddr: 0,
                virtual_size: 0,
                arena_id: 0,
                max_faults_per_step: 4,
                resident_max_pages: 0,
                prefault_pages: 0,
                writeback: backing_store::WritebackPolicy::Deferred,
            }
        }

        /// Number of virtual pages in this arena.
        #[inline]
        pub fn virtual_pages(&self) -> u32 {
            (self.virtual_size / PAGE_SIZE) as u32
        }
    }

    /// Per-module pager runtime statistics.
    #[derive(Clone, Copy)]
    pub struct PagerStats {
        /// Faults during the current step.
        pub faults_this_step: u16,
        /// Total faults since arena was created.
        pub total_faults: u32,
        /// Total evictions since arena was created.
        pub evictions: u32,
        /// Total writebacks since arena was created.
        pub writebacks: u32,
    }

    impl PagerStats {
        pub const fn new() -> Self {
            Self {
                faults_this_step: 0,
                total_faults: 0,
                evictions: 0,
                writebacks: 0,
            }
        }
    }

    /// Combined per-module pager state.
    static mut PAGER_CONFIG: [PagedArenaConfig; MAX_MODULES] =
        [PagedArenaConfig::empty(); MAX_MODULES];
    static mut PAGER_STATS: [PagerStats; MAX_MODULES] = [PagerStats::new(); MAX_MODULES];

    // ============================================================================
    // Fault handling
    // ============================================================================

    /// Error codes from the page fault handler.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FaultError {
        /// Address is not within any paged arena.
        NotPagedArena,
        /// Per-step fault budget exceeded.
        BudgetExceeded,
        /// Could not allocate or evict a physical page.
        NoPages,
        /// Backing store read failed.
        BackingReadError(i32),
        /// Backing store write failed (during eviction writeback).
        BackingWriteError(i32),
        /// Module index out of range.
        InvalidModule,
    }

    /// Check if a fault address falls within a module's paged arena.
    pub fn is_paged_arena_fault(module_idx: usize, vaddr: usize) -> bool {
        if module_idx >= MAX_MODULES {
            return false;
        }
        let config = unsafe { (*(&raw const PAGER_CONFIG))[module_idx] };
        if !config.active {
            return false;
        }
        vaddr >= config.base_vaddr && vaddr < config.base_vaddr + config.virtual_size
    }

    /// Handle a page fault from a module's paged arena.
    ///
    /// This is called from the data abort handler (or from a synchronous
    /// fault path on cooperative systems). The function is synchronous:
    /// it blocks until the page is loaded and mapped.
    ///
    /// On success, the faulting instruction can be retried.
    pub fn handle_page_fault(module_idx: usize, fault_vaddr: usize) -> Result<(), FaultError> {
        if module_idx >= MAX_MODULES {
            return Err(FaultError::InvalidModule);
        }

        let config = unsafe { (*(&raw const PAGER_CONFIG))[module_idx] };
        if !config.active {
            return Err(FaultError::NotPagedArena);
        }

        // Compute virtual page index
        if fault_vaddr < config.base_vaddr || fault_vaddr >= config.base_vaddr + config.virtual_size
        {
            return Err(FaultError::NotPagedArena);
        }
        let vpage_idx = ((fault_vaddr - config.base_vaddr) / PAGE_SIZE) as u32;

        // Check fault budget
        let stats = unsafe { &mut (*(&raw mut PAGER_STATS))[module_idx] };
        if stats.faults_this_step >= config.max_faults_per_step {
            return Err(FaultError::BudgetExceeded);
        }

        // Check if page is already mapped (spurious fault / race)
        if page_pool::pool_find_page(module_idx as u8, vpage_idx).is_some() {
            // Already present — just needs TLB invalidation
            #[cfg(feature = "chip-bcm2712")]
            tlbi_page(fault_vaddr);
            stats.faults_this_step += 1;
            stats.total_faults += 1;
            return Ok(());
        }

        // Allocate a physical page
        let page_idx = match page_pool::pool_alloc(module_idx as u8) {
            Some(idx) => idx,
            None => {
                // Pool is full — evict
                match evict_one(module_idx as u8, config.arena_id) {
                    Some(idx) => idx,
                    None => return Err(FaultError::NoPages),
                }
            }
        };

        // Read page content from backing store
        let page_buf = page_pool::pool_page_ptr(page_idx);
        let rc = backing_store::backing_read(config.arena_id as usize, vpage_idx, page_buf);
        if rc < 0 {
            page_pool::pool_free(page_idx);
            return Err(FaultError::BackingReadError(rc));
        }

        // Mark page as mapped
        page_pool::pool_mark_mapped(page_idx, vpage_idx);

        // Map in page table
        #[cfg(feature = "chip-bcm2712")]
        {
            let phys = page_pool::pool_page_phys_addr(page_idx);
            let vaddr_page = config.base_vaddr + (vpage_idx as usize) * PAGE_SIZE;
            map_page_in_table(module_idx, vaddr_page, phys);
            tlbi_page(vaddr_page);
        }

        // Update stats
        stats.faults_this_step += 1;
        stats.total_faults += 1;

        Ok(())
    }

    /// Evict one page to make room, writing back if dirty.
    fn evict_one(module_idx: u8, arena_id: u8) -> Option<usize> {
        let page_idx = page_pool::pool_evict_clock(module_idx)?;

        let desc = page_pool::pool_descriptor(page_idx);

        // If dirty, write back to backing store
        if desc.is_dirty() {
            let buf = page_pool::pool_page_ptr(page_idx);
            let rc =
                backing_store::backing_write(arena_id as usize, desc.vpage_idx, buf as *const u8);
            if rc < 0 {
                log::error!(
                    "[pager] writeback failed for page {} vpage {}: {}",
                    page_idx,
                    desc.vpage_idx,
                    rc
                );
                // Continue anyway — data loss on this page
            }

            let stats = unsafe { &mut (*(&raw mut PAGER_STATS))[desc.owner_module as usize] };
            stats.writebacks += 1;
        }

        // Unmap from old owner's page table
        #[cfg(feature = "chip-bcm2712")]
        {
            let old_module = desc.owner_module as usize;
            let old_config = unsafe { &(*(&raw const PAGER_CONFIG))[old_module] };
            if old_config.active {
                let old_vaddr = old_config.base_vaddr + (desc.vpage_idx as usize) * PAGE_SIZE;
                unmap_page_in_table(old_module, old_vaddr);
                tlbi_page(old_vaddr);
            }
        }

        // Update eviction stats for the old owner
        {
            let owner_stats = unsafe { &mut (*(&raw mut PAGER_STATS))[desc.owner_module as usize] };
            owner_stats.evictions += 1;
        }

        // Free the page (puts it back in pool)
        page_pool::pool_free(page_idx);

        // Re-allocate for the new owner
        page_pool::pool_alloc(module_idx)
    }

    // ============================================================================
    // Page table manipulation (BCM2712)
    // ============================================================================

    /// Map a 4KB page in a module's L3 page table.
    ///
    /// This requires extending the MMU from 2MB blocks to 4KB pages for
    /// the paged arena region. We add L3 tables for the arena VA range.
    #[cfg(feature = "chip-bcm2712")]
    fn map_page_in_table(module_idx: usize, vaddr: usize, phys: usize) {
        // Delegate to mmu module's 4KB page mapping
        crate::kernel::mmu::map_4k_page(module_idx, vaddr as u64, phys as u64, true);
    }

    /// Unmap a 4KB page (set PTE to invalid).
    #[cfg(feature = "chip-bcm2712")]
    fn unmap_page_in_table(module_idx: usize, vaddr: usize) {
        crate::kernel::mmu::unmap_4k_page(module_idx, vaddr as u64);
    }

    /// Invalidate TLB entry for a specific virtual address.
    #[cfg(feature = "chip-bcm2712")]
    fn tlbi_page(vaddr: usize) {
        unsafe {
            let addr = (vaddr >> 12) as u64; // TLB invalidate by VA, page-aligned
            core::arch::asm!(
                "tlbi vale1, {}",
                "dsb ish",
                "isb",
                in(reg) addr,
            );
        }
    }

    // ============================================================================
    // Dirty tracking and writeback
    // ============================================================================

    /// Write back up to `max_pages` dirty pages for a module.
    ///
    /// Returns the number of pages actually written back.
    pub fn writeback_dirty(module_idx: usize, max_pages: usize) -> usize {
        if module_idx >= MAX_MODULES {
            return 0;
        }
        let config = unsafe { &(*(&raw const PAGER_CONFIG))[module_idx] };
        if !config.active {
            return 0;
        }

        let pool = unsafe { page_pool::pool_mut() };
        let total = pool.total_pages();
        let mut written = 0;

        let mut i = 0;
        while i < total && written < max_pages {
            let desc = pool.descriptor(i);
            if desc.owner_module == module_idx as u8
                && desc.is_mapped()
                && desc.is_dirty()
                && !desc.is_pinned()
            {
                let buf = pool.page_ptr(i);
                let rc = backing_store::backing_write(
                    config.arena_id as usize,
                    desc.vpage_idx,
                    buf as *const u8,
                );
                if rc == 0 {
                    // Clear dirty flag
                    let d = pool.descriptor_mut(i);
                    d.flags &= !page_flags::DIRTY;
                    written += 1;

                    let stats = unsafe { &mut (*(&raw mut PAGER_STATS))[module_idx] };
                    stats.writebacks += 1;
                }
            }
            i += 1;
        }

        written
    }

    /// Sync all dirty pages for a module (flush everything).
    pub fn sync_all(module_idx: usize) -> usize {
        writeback_dirty(module_idx, usize::MAX)
    }

    // ============================================================================
    // Pager lifecycle
    // ============================================================================

    /// Reset per-step fault counters. Called by scheduler before each step.
    pub fn reset_step_faults(module_idx: usize) {
        if module_idx < MAX_MODULES {
            unsafe {
                (*(&raw mut PAGER_STATS))[module_idx].faults_this_step = 0;
            }
        }
    }

    /// Configure a paged arena for a module.
    ///
    /// Called during module instantiation when the config includes paged_arena.
    /// Allocates backing store and sets up the arena virtual range.
    ///
    /// Returns 0 on success, negative on error.
    pub fn configure_arena(
        module_idx: usize,
        base_vaddr: usize,
        virtual_size_bytes: usize,
        resident_max_pages: u32,
        backing_type: backing_store::BackingType,
        writeback: backing_store::WritebackPolicy,
        max_faults_per_step: u16,
        prefault_pages: u16,
    ) -> i32 {
        if module_idx >= MAX_MODULES {
            return -22;
        }

        let virtual_pages = (virtual_size_bytes / PAGE_SIZE) as u32;

        // Register with backing store
        let arena_id = backing_store::backing_register(
            module_idx as u8,
            virtual_pages,
            resident_max_pages,
            backing_type,
            writeback,
        );
        if arena_id < 0 {
            return arena_id;
        }

        unsafe {
            (*(&raw mut PAGER_CONFIG))[module_idx] = PagedArenaConfig {
                active: true,
                base_vaddr,
                virtual_size: virtual_size_bytes,
                arena_id: arena_id as u8,
                max_faults_per_step,
                resident_max_pages,
                prefault_pages,
                writeback,
            };
            (*(&raw mut PAGER_STATS))[module_idx] = PagerStats::new();
        }

        log::info!(
            "[pager] module {} arena: vaddr=0x{:x} size={}KB vpages={} resident_max={} backing={}",
            module_idx,
            base_vaddr,
            virtual_size_bytes / 1024,
            virtual_pages,
            resident_max_pages,
            arena_id
        );

        arena_id
    }

    /// Prefault pages for a module (load them before first access).
    ///
    /// Returns number of pages successfully prefaulted.
    pub fn prefault(module_idx: usize, start_vpage: u32, count: u32) -> u32 {
        if module_idx >= MAX_MODULES {
            return 0;
        }
        let config = unsafe { (*(&raw const PAGER_CONFIG))[module_idx] };
        if !config.active {
            return 0;
        }

        let mut loaded = 0u32;
        let mut vpage = start_vpage;
        while vpage < start_vpage + count && vpage < config.virtual_pages() {
            // Check if already mapped
            if page_pool::pool_find_page(module_idx as u8, vpage).is_some() {
                vpage += 1;
                loaded += 1;
                continue;
            }

            // Allocate physical page
            let page_idx = match page_pool::pool_alloc(module_idx as u8) {
                Some(idx) => idx,
                None => break,
            };

            // Load from backing
            let buf = page_pool::pool_page_ptr(page_idx);
            let rc = backing_store::backing_read(config.arena_id as usize, vpage, buf);
            if rc < 0 {
                page_pool::pool_free(page_idx);
                break;
            }

            // Mark mapped
            page_pool::pool_mark_mapped(page_idx, vpage);

            // Map in page table
            #[cfg(feature = "chip-bcm2712")]
            {
                let phys = page_pool::pool_page_phys_addr(page_idx);
                let vaddr = config.base_vaddr + (vpage as usize) * PAGE_SIZE;
                map_page_in_table(module_idx, vaddr, phys);
            }

            loaded += 1;
            vpage += 1;
        }

        #[cfg(feature = "chip-bcm2712")]
        if loaded > 0 {
            // Bulk TLB invalidation
            unsafe {
                core::arch::asm!("tlbi vmalle1", "dsb ish", "isb");
            }
        }

        loaded
    }

    /// Tear down a module's paged arena (free all pages + backing).
    pub fn teardown_arena(module_idx: usize) {
        if module_idx >= MAX_MODULES {
            return;
        }

        let config = unsafe { &(*(&raw const PAGER_CONFIG))[module_idx] };
        if !config.active {
            return;
        }

        // Sync dirty pages before teardown
        sync_all(module_idx);

        // Free all physical pages
        page_pool::pool_free_module(module_idx as u8);

        // Release backing store
        backing_store::backing_release(config.arena_id as usize);

        // Clear config
        unsafe {
            (*(&raw mut PAGER_CONFIG))[module_idx] = PagedArenaConfig::empty();
            (*(&raw mut PAGER_STATS))[module_idx] = PagerStats::new();
        }
    }

    /// Get pager config for a module.
    pub fn get_config(module_idx: usize) -> PagedArenaConfig {
        if module_idx >= MAX_MODULES {
            return PagedArenaConfig::empty();
        }
        unsafe { (*(&raw const PAGER_CONFIG))[module_idx] }
    }

    /// Get pager stats for a module.
    pub fn get_stats(module_idx: usize) -> PagerStats {
        if module_idx >= MAX_MODULES {
            return PagerStats::new();
        }
        unsafe { (*(&raw const PAGER_STATS))[module_idx] }
    }

    /// Stats struct returned to modules via syscall.
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct PagedArenaStats {
        /// Number of resident (mapped) pages.
        pub resident: u32,
        /// Total page faults since arena creation.
        pub faults: u32,
        /// Total page evictions.
        pub evictions: u32,
        /// Number of dirty pages.
        pub dirty: u32,
        /// Total writebacks.
        pub writebacks: u32,
        /// Hit ratio (faults avoided / total accesses) as Q8.8 fixed point.
        /// 0 if no data yet.
        pub hit_ratio_q8: u16,
        /// Reserved.
        pub _reserved: u16,
    }

    /// Build stats struct for a module's paged arena.
    pub fn build_stats(module_idx: usize) -> PagedArenaStats {
        if module_idx >= MAX_MODULES {
            return PagedArenaStats::default();
        }
        let config = unsafe { &(*(&raw const PAGER_CONFIG))[module_idx] };
        if !config.active {
            return PagedArenaStats::default();
        }
        let stats = unsafe { &(*(&raw const PAGER_STATS))[module_idx] };

        let resident = page_pool::pool_resident_count(module_idx as u8) as u32;
        let dirty = page_pool::pool_dirty_count(module_idx as u8) as u32;

        PagedArenaStats {
            resident,
            faults: stats.total_faults,
            evictions: stats.evictions,
            dirty,
            writebacks: stats.writebacks,
            hit_ratio_q8: 0, // Would need access counter to compute
            _reserved: 0,
        }
    }
}
