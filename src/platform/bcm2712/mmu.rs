//! MMU-based hardware isolation for Cortex-A76 (BCM2712 / Pi 5).
//!
//! # Architecture
//!
//! Modules run at EL0 (unprivileged), kernel at EL1 (privileged).
//! Each module gets its own page table with a unique ASID, so TLB
//! entries survive context switches between modules.
//!
//! ## Page Table Layout (4KB granule, 2-level for 1GB VA space)
//!
//! - L1 table: 512 entries (each covers 1GB, but we only use first few)
//! - L2 table: 512 entries per L1 entry (each covers 2MB blocks)
//! - We use 2MB block descriptors (no L3 tables) for simplicity
//!
//! ## Memory Map
//!
//! | Region              | QEMU virt address      | Pi 5 address         |
//! |---------------------|------------------------|---------------------|
//! | Kernel code+data    | 0x4008_0000..          | 0x0008_0000..       |
//! | Module code (blob)  | After kernel           | After kernel        |
//! | Module state (heap) | SRAM arena             | SRAM arena          |
//! | MMIO                | 0x0800_0000..          | 0xFE00_0000..       |
//!
//! ## ASID Management
//!
//! ASID 0 = kernel (full access at EL1)
//! ASID 1..N = modules (restricted EL0 access)
//! TTBR0_EL1 is swapped per-module with the module's page table + ASID.

/// The stack an isolated module runs on at EL0, above one unmapped guard page.
/// The composer, and the loader behind it, refuse an isolated module whose
/// manifest declares a larger need (`declare_module_stack_bytes!`).
pub const ISOLATED_STACK_BYTES: usize = 64 * 1024;

#[cfg(feature = "chip-bcm2712")]
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
mod bcm2712_impl {
    use crate::kernel::exec::scheduler::MAX_MODULES;

    // ========================================================================
    // AArch64 translation table constants (4KB granule)
    // ========================================================================

    /// Page/block size (4KB granule)
    const PAGE_SIZE: usize = 4096;
    /// Number of entries per page table level
    const TABLE_ENTRIES: usize = 512;
    /// L2 block size: 2MB (512 * 4KB)
    const L2_BLOCK_SIZE: u64 = 2 * 1024 * 1024;
    /// L1 block size: 1GB (512 * 2MB)
    const L1_BLOCK_SIZE: u64 = 1024 * 1024 * 1024;

    // Descriptor bits
    const DESC_VALID: u64 = 1 << 0;
    const DESC_TABLE: u64 = 1 << 1; // L1: table descriptor (not block)
    const DESC_BLOCK: u64 = 0 << 1; // L1/L2: block descriptor (with VALID)

    // Lower attributes (block/page descriptors)
    const ATTR_IDX_SHIFT: u64 = 2; // AttrIndx[2:0] at bits [4:2]
    const ATTR_NS: u64 = 1 << 5; // Non-secure
    const AP_SHIFT: u64 = 6; // AP[2:1] at bits [7:6]
    const SH_SHIFT: u64 = 8; // SH[1:0] at bits [9:8]
    const AF: u64 = 1 << 10; // Access Flag
    const _NG: u64 = 1 << 11; // Not Global (use ASID)

    // AP values
    /// EL1 RW, EL0 no access
    const AP_EL1_RW: u64 = 0b00;
    /// EL1 RW, EL0 RW
    const AP_EL0_RW: u64 = 0b01;
    /// EL1 RO, EL0 no access
    const AP_EL1_RO: u64 = 0b10;
    /// EL1 RO, EL0 RO
    const AP_EL0_RO: u64 = 0b11;

    // Shareability
    const SH_ISH: u64 = 0b11; // Inner-shareable

    // Upper attributes
    const PXN: u64 = 1 << 53; // Privileged Execute-Never
    const UXN: u64 = 1 << 54; // Unprivileged Execute-Never (EL0 XN)

    // MAIR attribute indices (must match MAIR_EL1 setup)
    const ATTR_IDX_NORMAL: u64 = 0;
    const ATTR_IDX_DEVICE: u64 = 1;
    const ATTR_IDX_NORMAL_NC: u64 = 2;

    /// MAIR_EL1 encoding:
    /// Attr0: Normal, WB-WA inner+outer (0xFF)
    /// Attr1: Device-nGnRnE (0x00)
    /// Attr2: Normal non-cacheable (0x44)
    // Attr1 (Device-nGnRnE) encodes as 0x00, so its slot contributes nothing
    // to the bitmask; only Attr0 and Attr2 are spelled out below.
    const MAIR_VALUE: u64 = 0xFF |          // Attr0: Normal memory, WB-WA
        (0x44 << 16); // Attr2: Normal non-cacheable

    /// TCR_EL1 value for 4KB granule, 39-bit VA (512GB), ASID 8-bit.
    /// T0SZ = 25 (64-25=39 bit VA space)
    /// IRGN0 = 0b01 (inner WB-WA cacheable)
    /// ORGN0 = 0b01 (outer WB-WA cacheable)
    /// SH0 = 0b11 (inner shareable)
    /// TG0 = 0b00 (4KB granule)
    /// A1 = 0 (TTBR0 ASID)
    /// AS = 0 (8-bit ASID)
    // TG0 (4KB granule) encodes as 0b00, so its slot contributes nothing to
    // the bitmask; only the non-zero fields are spelled out below.
    const TCR_VALUE: u64 = 25 |             // T0SZ = 25 → 39-bit VA
        (0b01 << 8) |   // IRGN0 = WB-WA
        (0b01 << 10) |  // ORGN0 = WB-WA
        (0b11 << 12) |  // SH0 = Inner-shareable
        (0b1 << 23); // EPD1 = 1 (disable TTBR1 walks)

    // ========================================================================
    // Page table storage
    // ========================================================================

    /// Kernel L1 page table (covers entire VA space).
    #[repr(C, align(4096))]
    struct PageTable([u64; TABLE_ENTRIES]);

    /// L2 page table (covers 1GB).
    #[repr(C, align(4096))]
    struct L2PageTable([u64; TABLE_ENTRIES]);

    /// Kernel page tables (L1 + one L2 for the first 1GB).
    static mut KERNEL_L1: PageTable = PageTable([0; TABLE_ENTRIES]);
    static mut KERNEL_L2: L2PageTable = L2PageTable([0; TABLE_ENTRIES]);

    /// Per-module L2 page tables (one per module).
    /// Each module gets a custom L2 table that maps only its allowed regions.
    static mut MODULE_L2: [L2PageTable; MAX_MODULES] = {
        const EMPTY: L2PageTable = L2PageTable([0; TABLE_ENTRIES]);
        [EMPTY; MAX_MODULES]
    };

    /// Per-module L1 page tables (one per module, pointing to module's L2).
    static mut MODULE_L1: [PageTable; MAX_MODULES] = {
        const EMPTY: PageTable = PageTable([0; TABLE_ENTRIES]);
        [EMPTY; MAX_MODULES]
    };

    /// Whether MMU isolation is enabled.
    static mut ISOLATION_ENABLED: bool = false;

    /// Per-module region info.
    #[derive(Clone, Copy)]
    struct ModuleRegions {
        code_base: u64,
        code_size: u64,
        state_base: u64,
        state_size: u64,
        heap_base: u64,
        heap_size: u64,
    }

    impl ModuleRegions {
        const fn empty() -> Self {
            Self {
                code_base: 0,
                code_size: 0,
                state_base: 0,
                state_size: 0,
                heap_base: 0,
                heap_size: 0,
            }
        }
    }

    static mut MODULE_REGION_INFO: [ModuleRegions; MAX_MODULES] =
        [ModuleRegions::empty(); MAX_MODULES];

    // ========================================================================
    // Helper functions
    // ========================================================================

    /// Align down to 2MB block boundary.
    #[inline]
    const fn align_down_2mb(addr: u64) -> u64 {
        addr & !(L2_BLOCK_SIZE - 1)
    }

    /// Align up to 2MB block boundary.
    #[inline]
    const fn align_up_2mb(addr: u64) -> u64 {
        (addr + L2_BLOCK_SIZE - 1) & !(L2_BLOCK_SIZE - 1)
    }

    /// L2 index for a given address.
    #[inline]
    const fn l2_index(addr: u64) -> usize {
        ((addr >> 21) & 0x1FF) as usize // bits [29:21]
    }

    /// L1 index for a given address.
    #[inline]
    const fn l1_index(addr: u64) -> usize {
        ((addr >> 30) & 0x1FF) as usize // bits [38:30]
    }

    /// Make a 2MB block descriptor.
    fn make_block_desc(phys: u64, attr_idx: u64, ap: u64, xn_el0: bool, xn_el1: bool) -> u64 {
        let pxn = if xn_el1 { PXN } else { 0 };
        let uxn = if xn_el0 { UXN } else { 0 };
        (phys & !(L2_BLOCK_SIZE - 1))
            | DESC_VALID
            | DESC_BLOCK
            | (attr_idx << ATTR_IDX_SHIFT)
            | (ap << AP_SHIFT)
            | (SH_ISH << SH_SHIFT)
            | AF
            | _NG // Use ASID for TLB matching
            | pxn
            | uxn
    }

    /// Make an L1 table descriptor pointing to an L2 table.
    fn make_table_desc(l2_addr: u64) -> u64 {
        (l2_addr & !0xFFF) | DESC_VALID | DESC_TABLE
    }

    // ========================================================================
    // Public API
    // ========================================================================

    /// Initialize MMU for isolation mode.
    ///
    /// This sets up kernel page tables and configures MAIR/TCR.
    /// The actual EL1→EL0 transitions happen in `switch_to_module()`.
    ///
    /// Note: The existing bcm2712.rs already sets up basic page tables for
    /// the kernel. This function builds the per-module isolation tables
    /// on top of that foundation.
    pub fn mmu_init() {
        // SAFETY: MMU init runs once at boot before any module observes
        // virt addresses; touches KERNEL_L1/L2 statics + MAIR/TCR sysregs.
        unsafe {
            // Build kernel L2 page table (identity map first 1GB)
            // This covers RAM + MMIO for QEMU virt
            for i in 0..TABLE_ENTRIES {
                let phys = (i as u64) * L2_BLOCK_SIZE;
                // Default: kernel RW, EL0 no access, execute-never at EL0
                KERNEL_L2.0[i] = make_block_desc(
                    phys,
                    ATTR_IDX_NORMAL,
                    AP_EL1_RW,
                    true,  // UXN (EL0 can't execute)
                    false, // PXN=0 (EL1 can execute)
                );
            }

            // MMIO regions: device memory attribute
            // QEMU virt: GIC at 0x0800_0000 (L2 index 4)
            // UART at 0x0900_0000 (L2 index 4-5 in 2MB blocks)
            for i in 0..32 {
                // First 64MB as device memory (covers GIC + UART on QEMU virt)
                KERNEL_L2.0[i] = make_block_desc(
                    (i as u64) * L2_BLOCK_SIZE,
                    ATTR_IDX_DEVICE,
                    AP_EL1_RW,
                    true,
                    true, // No execute
                );
            }

            // Pi 5: peripherals at 0xFE00_0000+ are in higher L1 entries
            // This is handled by having additional L1→L2 mappings for those.

            // Kernel L1: point entry 0 to kernel L2 (covers 0..1GB)
            let l2_addr = &raw const KERNEL_L2 as u64;
            KERNEL_L1.0[0] = make_table_desc(l2_addr);
            // Higher L1 entries: identity map as 1GB blocks for QEMU virt
            // (RAM at 0x4000_0000 = L1 index 1)
            KERNEL_L1.0[1] =
                make_block_desc(L1_BLOCK_SIZE, ATTR_IDX_NORMAL, AP_EL1_RW, true, false);

            // Set MAIR_EL1
            core::arch::asm!("msr mair_el1, {}", in(reg) MAIR_VALUE);
            // Set TCR_EL1
            core::arch::asm!("msr tcr_el1, {}", in(reg) TCR_VALUE);

            core::arch::asm!("isb");

            ISOLATION_ENABLED = true;
            log::info!("[mmu] isolation page tables initialized");
        }
    }

    /// Build a module's page table.
    ///
    /// Creates an L2 table that maps:
    /// - Kernel code as RO+X at EL0 (for syscall stubs)
    /// - Module code as RO+X at EL0
    /// - Module state as RW at EL0
    /// - Module heap as RW at EL0
    /// - Channel buffers as RW at EL0
    /// - Kernel data: NOT mapped at EL0 (will fault)
    // Stack guard page is deferred: modules currently execute at EL1 on the
    // kernel stack, so there is no per-module stack region to protect. Once
    // modules run at EL0 with their own stacks, leave the lowest 4 KB of
    // the stack region as an invalid L3 entry — `handle_data_abort` already
    // routes translation faults into the fault state machine.
    pub fn build_module_page_table(module_idx: usize) {
        if module_idx >= MAX_MODULES {
            return;
        }
        // SAFETY: per-module page-table build runs during instantiation;
        // no other thread accesses this module's MODULE_REGION_INFO /
        // MODULE_L1 / MODULE_L2 entry yet. module_idx bounded above.
        unsafe {
            let r = &MODULE_REGION_INFO[module_idx];
            let l2 = &mut MODULE_L2[module_idx];
            let l1 = &mut MODULE_L1[module_idx];

            // Start with all entries invalid (EL0 will fault on access)
            for entry in l2.0.iter_mut() {
                *entry = 0;
            }
            for entry in l1.0.iter_mut() {
                *entry = 0;
            }

            // Map module code region (RO+X at EL0)
            if r.code_size > 0 {
                let start = align_down_2mb(r.code_base);
                let end = align_up_2mb(r.code_base + r.code_size);
                let mut addr = start;
                while addr < end {
                    let idx = l2_index(addr);
                    if idx < TABLE_ENTRIES {
                        l2.0[idx] = make_block_desc(
                            addr,
                            ATTR_IDX_NORMAL,
                            AP_EL0_RO, // EL0 RO
                            false,     // UXN=0 (EL0 can execute)
                            true,      // PXN=1 (EL1 shouldn't execute module code)
                        );
                    }
                    addr += L2_BLOCK_SIZE;
                }
            }

            // Map module state (RW at EL0, no execute)
            if r.state_size > 0 {
                let start = align_down_2mb(r.state_base);
                let end = align_up_2mb(r.state_base + r.state_size);
                let mut addr = start;
                while addr < end {
                    let idx = l2_index(addr);
                    if idx < TABLE_ENTRIES {
                        l2.0[idx] = make_block_desc(
                            addr,
                            ATTR_IDX_NORMAL,
                            AP_EL0_RW,
                            true,
                            true, // No execute
                        );
                    }
                    addr += L2_BLOCK_SIZE;
                }
            }

            // Map module heap (RW at EL0, no execute)
            if r.heap_size > 0 {
                let start = align_down_2mb(r.heap_base);
                let end = align_up_2mb(r.heap_base + r.heap_size);
                let mut addr = start;
                while addr < end {
                    let idx = l2_index(addr);
                    if idx < TABLE_ENTRIES {
                        l2.0[idx] = make_block_desc(addr, ATTR_IDX_NORMAL, AP_EL0_RW, true, true);
                    }
                    addr += L2_BLOCK_SIZE;
                }
            }

            // L1: point to module's L2
            let l2_addr = l2 as *const _ as u64;
            l1.0[0] = make_table_desc(l2_addr);
            // Also map the RAM region for QEMU (L1 index 1)
            l1.0[1] = make_table_desc(l2_addr);
        }
    }

    /// Register module regions (called during module instantiation).
    pub fn register_module_regions(
        module_idx: usize,
        code_base: u64,
        code_size: u64,
        state_ptr: *mut u8,
        state_size: usize,
        heap_ptr: *mut u8,
        heap_size: usize,
    ) {
        if module_idx >= MAX_MODULES {
            return;
        }
        // SAFETY: per-module write during instantiation; module_idx bounded.
        unsafe {
            MODULE_REGION_INFO[module_idx] = ModuleRegions {
                code_base,
                code_size,
                state_base: state_ptr as u64,
                state_size: state_size as u64,
                heap_base: if heap_ptr.is_null() {
                    0
                } else {
                    heap_ptr as u64
                },
                heap_size: if heap_ptr.is_null() {
                    0
                } else {
                    heap_size as u64
                },
            };
        }
    }

    // ========================================================================
    // ASID management
    // ========================================================================

    /// Switch TTBR0_EL1 to a module's page table with its ASID.
    ///
    /// ASID = module_idx + 1 (ASID 0 reserved for kernel).
    pub fn switch_to_module(module_idx: usize) {
        if !is_enabled() || module_idx >= MAX_MODULES {
            return;
        }
        // SAFETY: writes TTBR0_EL1 to the per-module L1 base — sysreg
        // is per-CPU and the scheduler thread is the sole writer.
        unsafe {
            let l1_addr = &MODULE_L1[module_idx] as *const _ as u64;
            let asid = (module_idx as u64 + 1) & 0xFF;
            let ttbr0 = l1_addr | (asid << 48);

            core::arch::asm!(
                "msr ttbr0_el1, {}",
                "isb",
                in(reg) ttbr0,
            );
        }
    }

    /// Switch TTBR0_EL1 back to kernel page table (ASID 0).
    pub fn switch_to_kernel() {
        if !is_enabled() {
            return;
        }
        // SAFETY: TTBR0_EL1 write to the kernel L1; ASID 0 reserved.
        unsafe {
            let l1_addr = &raw const KERNEL_L1 as u64;
            let ttbr0 = l1_addr; // ASID 0 (kernel)

            core::arch::asm!(
                "msr ttbr0_el1, {}",
                "isb",
                in(reg) ttbr0,
            );
        }
    }

    /// Check if MMU isolation is enabled.
    #[inline]
    pub fn is_enabled() -> bool {
        // SAFETY: ISOLATION_ENABLED is a bool static; aligned read.
        unsafe { ISOLATION_ENABLED }
    }

    /// Enable or disable MMU isolation.
    pub fn set_enabled(enabled: bool) {
        // SAFETY: ISOLATION_ENABLED is a bool static; sole writer is the
        // scheduler-thread `mmu_init` / `set_enabled` call.
        unsafe {
            ISOLATION_ENABLED = enabled;
        }
    }

    // ========================================================================
    // EL1/EL0 transitions
    // ========================================================================

    /// Enter EL0 to execute module_step, return to EL1 via SVC.
    ///
    /// Routes to the real EL0 walking-skeleton transition (`el0::enter`)
    /// when isolation is enabled AND the current module has a built
    /// isolated page table. Otherwise falls through to a direct EL1
    /// call so non-isolated modules keep the exact pre-existing path.
    ///
    /// The current module index is resolved from the scheduler — the
    /// caller (`DynamicModule::step`) runs inside `m.step()` where
    /// `set_current_module(idx)` has already been called.
    ///
    /// # Safety
    /// The result of a protected call that could not be made: a fault, so the
    /// scheduler applies the module's policy. The module never runs at EL1.
    const EL0_FAIL_CLOSED: i32 = -14;

    /// Data abort handler (called from exception vector).
    ///
    /// Reads FAR_EL1 to get the faulting address. If the address falls within
    /// a module's paged arena, delegates to the demand pager. Otherwise,
    /// records a protection fault.
    pub unsafe fn handle_data_abort() {
        let far: u64;
        let esr: u64;
        core::arch::asm!("mrs {}, far_el1", out(reg) far);
        core::arch::asm!("mrs {}, esr_el1", out(reg) esr);

        let module_idx = crate::kernel::exec::scheduler::current_module_index();
        let dfsc = esr & 0x3F; // Data Fault Status Code

        // Check if this is a translation fault in a paged arena (DFSC 0x04-0x07 = translation fault)
        let is_translation_fault = (dfsc & 0x3C) == 0x04;
        if is_translation_fault
            && crate::kernel::pager::is_paged_arena_fault(module_idx, far as usize)
        {
            match crate::kernel::pager::handle_page_fault(module_idx, far as usize) {
                Ok(()) => return, // Page loaded, retry faulting instruction
                Err(e) => {
                    log::error!(
                        "[mmu] pager fault failed for module {module_idx} at 0x{far:016x}: {e:?}"
                    );
                    // Fall through to record as MPU fault
                }
            }
        }

        log::error!(
            "[mmu] module {module_idx} data abort at 0x{far:016x} ESR=0x{esr:08x} DFSC=0x{dfsc:02x}"
        );

        // Record fault via step_guard
        crate::kernel::exec::step_guard::record_mpu_fault(module_idx);
    }

    // ========================================================================
    // L3 page table support for 4KB demand paging
    // ========================================================================

    /// L3 page table (512 entries, each maps a 4KB page).
    #[derive(Clone, Copy)]
    #[repr(C, align(4096))]
    struct L3PageTable([u64; TABLE_ENTRIES]);

    /// Maximum L3 tables per module (each covers 2MB = 512 x 4KB pages).
    /// 4 tables = 8MB paged arena range per module.
    const MAX_L3_PER_MODULE: usize = 4;

    /// Per-module L3 page tables for paged arena regions.
    static mut MODULE_L3: [[L3PageTable; MAX_L3_PER_MODULE]; MAX_MODULES] = {
        const EMPTY_L3: L3PageTable = L3PageTable([0; TABLE_ENTRIES]);
        const EMPTY_MODULE_L3: [L3PageTable; MAX_L3_PER_MODULE] = [EMPTY_L3; MAX_L3_PER_MODULE];
        [EMPTY_MODULE_L3; MAX_MODULES]
    };

    /// Per-module: base VA of paged arena (0 = no paged arena).
    static mut MODULE_PAGED_BASE: [u64; MAX_MODULES] = [0; MAX_MODULES];
    /// Per-module: size of paged arena in bytes.
    static mut MODULE_PAGED_SIZE: [u64; MAX_MODULES] = [0; MAX_MODULES];
    /// Per-module: number of L3 tables allocated.
    static mut MODULE_L3_COUNT: [u8; MAX_MODULES] = [0; MAX_MODULES];

    /// L3 index for a given address (bits [20:12]).
    #[inline]
    const fn l3_index(addr: u64) -> usize {
        ((addr >> 12) & 0x1FF) as usize
    }

    /// Make a 4KB page descriptor.
    fn make_page_desc(phys: u64, attr_idx: u64, ap: u64, xn_el0: bool, xn_el1: bool) -> u64 {
        let pxn = if xn_el1 { PXN } else { 0 };
        let uxn = if xn_el0 { UXN } else { 0 };
        (phys & !0xFFF)
            | DESC_VALID
            | (1 << 1) // bit 1 = page (not block) at L3
            | (attr_idx << ATTR_IDX_SHIFT)
            | (ap << AP_SHIFT)
            | (SH_ISH << SH_SHIFT)
            | AF
            | _NG
            | pxn
            | uxn
    }

    /// Set up the paged arena L3 tables for a module.
    ///
    /// Called once during module instantiation. Creates invalid L3 entries
    /// (fault-on-access) and wires L2 entries to point to L3 tables.
    ///
    /// `base_va`: base virtual address of the paged arena (must be 2MB-aligned).
    /// `size`: virtual size in bytes (rounded up to 2MB).
    pub fn setup_paged_arena(module_idx: usize, base_va: u64, size: u64) {
        if module_idx >= MAX_MODULES {
            return;
        }
        // SAFETY: paged-arena setup runs during instantiation; module_idx
        // bounded above; MODULE_PAGED_* and MODULE_L3 entries are per-module.
        unsafe {
            MODULE_PAGED_BASE[module_idx] = base_va;
            MODULE_PAGED_SIZE[module_idx] = size;

            // Compute number of L3 tables needed (each covers 2MB)
            let l3_count = size.div_ceil(L2_BLOCK_SIZE) as usize;
            let l3_count = l3_count.min(MAX_L3_PER_MODULE);
            MODULE_L3_COUNT[module_idx] = l3_count as u8;

            // Initialize all L3 entries as invalid (unmapped)
            let module_l3_p = &raw mut MODULE_L3;
            for table in (*module_l3_p)[module_idx].iter_mut().take(l3_count) {
                for e in table.0.iter_mut() {
                    *e = 0; // Invalid = fault
                }
            }

            // Wire L2 entries to point to L3 tables instead of 2MB blocks
            let l2 = &mut MODULE_L2[module_idx];
            for (t, table) in (*module_l3_p)[module_idx].iter().enumerate().take(l3_count) {
                let va = base_va + (t as u64) * L2_BLOCK_SIZE;
                let idx = l2_index(va);
                if idx < TABLE_ENTRIES {
                    let l3_addr = table as *const _ as u64;
                    // L2 table descriptor pointing to L3 table
                    l2.0[idx] = (l3_addr & !0xFFF) | DESC_VALID | DESC_TABLE;
                }
            }
        }
    }

    /// Map a single 4KB page in a module's paged arena.
    ///
    /// `vaddr`: virtual address (must be page-aligned and within the paged arena).
    /// `phys`: physical address of the page.
    /// `writable`: whether the page is writable by the module (EL0).
    pub fn map_4k_page_impl(module_idx: usize, vaddr: u64, phys: u64, writable: bool) {
        if module_idx >= MAX_MODULES {
            return;
        }
        // SAFETY: pager-thread per-module mutation; module_idx bounded.
        unsafe {
            let base = MODULE_PAGED_BASE[module_idx];
            let size = MODULE_PAGED_SIZE[module_idx];
            if base == 0 || vaddr < base || vaddr >= base + size {
                return;
            }

            // Which L3 table?
            let offset = vaddr - base;
            let l3_table_idx = (offset / L2_BLOCK_SIZE) as usize;
            if l3_table_idx >= MODULE_L3_COUNT[module_idx] as usize {
                return;
            }

            let l3_entry_idx = l3_index(vaddr);
            let ap = if writable { AP_EL0_RW } else { AP_EL0_RO };
            MODULE_L3[module_idx][l3_table_idx].0[l3_entry_idx] =
                make_page_desc(phys, ATTR_IDX_NORMAL, ap, true, true); // XN for both (data only)
        }
    }

    /// Unmap a single 4KB page (set PTE to invalid).
    pub fn unmap_4k_page_impl(module_idx: usize, vaddr: u64) {
        if module_idx >= MAX_MODULES {
            return;
        }
        // SAFETY: pager-thread per-module mutation; module_idx bounded.
        unsafe {
            let base = MODULE_PAGED_BASE[module_idx];
            let size = MODULE_PAGED_SIZE[module_idx];
            if base == 0 || vaddr < base || vaddr >= base + size {
                return;
            }

            let offset = vaddr - base;
            let l3_table_idx = (offset / L2_BLOCK_SIZE) as usize;
            if l3_table_idx >= MODULE_L3_COUNT[module_idx] as usize {
                return;
            }

            let l3_entry_idx = l3_index(vaddr);
            MODULE_L3[module_idx][l3_table_idx].0[l3_entry_idx] = 0; // Invalid
        }
    }

    // ========================================================================
    // EL0 module-isolation walking skeleton
    // ========================================================================
    //
    // This module turns the dormant page-table machinery above into a real
    // EL1→EL0→EL1 round-trip for modules declared `protection: isolated`.
    //
    // Mechanism (setjmp/longjmp-style coroutine across an exception):
    //   * `enter`   — save kernel callee-saved regs + SP + LR + live
    //                 TTBR0 + DAIF into the per-core control block, install
    //                 the module's TTBR0/ASID, set ELR_EL1=module_step,
    //                 SPSR_EL1=EL0t (DAIF masked), SP_EL0=bounded module
    //                 stack, x0=state, LR=svc trampoline, then `ERET`.
    //   * EL0       — `module_step(state)` runs unprivileged under the
    //                 module's page table. On return it branches to the
    //                 trampoline page which executes `SVC #0`.
    //   * vector    — the lower-EL AArch64 synchronous vector
    //                 (`exception.rs`) branches to `fluxor_el0_lower_sync_vec`
    //                 below, which decodes ESR_EL1.EC: `SVC #0` carries the
    //                 module's i32 StepOutcome in x0; a data/instruction
    //                 abort records ESR/FAR/ELR and yields EFAULT. Either
    //                 way it `b fluxor_el0_resume`.
    //   * `resume`  — restore the kernel TTBR0/DAIF/SP/regs and `RET` to the
    //                 saved kernel LR, so `enter` "returns" the outcome.
    //                 We do NOT `eret` back to EL0 on a fault, so an illegal
    //                 access becomes a one-shot module fault, never a
    //                 re-faulting core spin.
    //
    // Liveness: EL0 runs with IRQs unmasked. A lower-EL IRQ is served under
    // the kernel's own table and, if the module has run past its step
    // deadline, forces it out through `resume` — a runaway EL0 loop costs its
    // deadline, not its core.
    //
    // The kernel is reached only through the trampoline page's veneers: each
    // is `svc #op; ret`, and the gateway `SyscallTable` handed to the module
    // points at them, so an unmodified module runs here. The kernel serves a
    // veneer's trap through `kernel::module::gateway`, which authorises every
    // pointer, handle and opcode before anything is dereferenced.
    pub mod el0 {
        use super::{
            make_block_desc, make_page_desc, L3PageTable, PageTable, AP_EL0_RO, AP_EL0_RW,
            AP_EL1_RW, ATTR_IDX_DEVICE, ATTR_IDX_NORMAL, DESC_TABLE, DESC_VALID, L1_BLOCK_SIZE,
            L2_BLOCK_SIZE, MODULE_REGION_INFO, TABLE_ENTRIES,
        };
        use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        // `DEVICE_RANGES`: the blocks a device window may be granted in,
        // generated from `targets/silicon/bcm2712.toml` `[isolation]`.
        include!(concat!(env!("OUT_DIR"), "/isolation_generated.rs"));

        /// Max modules isolated at once: the static L1/L2/L3 + stack slabs.
        /// The composer admits against `[isolation] isolated_slots`, pinned to
        /// this; a module that finds no free slot is refused at load, never
        /// run privileged instead.
        pub const MAX_ISO: usize = 2;
        /// Cores supported (matches scheduler MAX_DOMAINS / Pi 5 quad-core).
        const MAX_CORES: usize = 4;
        /// L3 tables per isolated module. Each maps one 2 MB window at 4 KB
        /// granularity; one per distinct 2 MB-aligned window the module's
        /// regions (code, state, heap, stack, trampoline) and the kernel
        /// stack guards touch.
        const MAX_L3: usize = 16;
        /// GBs of low DRAM identity-mapped EL1-only into every module table
        /// as the kernel base (so vectors / handler / kernel data are
        /// reachable at EL1 while TTBR0 holds the module table). 3 GB
        /// comfortably covers the kernel image, BSS, arenas, stacks, and the
        /// modules blob on the Pi 5. Module EL0 regions are carved on top.
        const KERNEL_BASE_GB: usize = 3;

        /// 4 KB page size.
        const PAGE: u64 = 4096;
        /// EL0 stack usable size (grows down toward the guard page).
        const EL0_STACK_BYTES: u64 = super::super::ISOLATED_STACK_BYTES as u64;
        /// Per-isolated-module stack slab: one guard page + the EL0 stack,
        /// 4 KB-aligned. Page 0 is left unmapped as the guard page; the stack
        /// occupies the pages immediately above it. Mapped at 4 KB granularity
        /// (`map_4k` carves it out of the kernel base), so it needs only page
        /// alignment; a 2 MB-aligned 2 MB slab would bloat firmware BSS by ~6 MB
        /// (2 slabs × 2 MB + 2 MB-alignment padding) for no benefit.
        const STACK_SLAB_BYTES: usize = 4096 + super::super::ISOLATED_STACK_BYTES; // guard page + stack

        // ---- Per-core EL0 control block ------------------------------------
        //
        // Field byte offsets are pinned here AND used as literal immediates
        // in the assembly below. The `const _: () = assert!` block keeps the
        // two in sync — change a field, the build breaks until the asm and
        // the asserts agree.
        #[repr(C, align(64))]
        struct El0ControlBlock {
            kernel_sp: u64,     // 0
            kernel_lr: u64,     // 8
            kernel_ttbr0: u64,  // 16
            kernel_daif: u64,   // 24
            saved_x19: u64,     // 32
            saved_x20: u64,     // 40
            saved_x21: u64,     // 48
            saved_x22: u64,     // 56
            saved_x23: u64,     // 64
            saved_x24: u64,     // 72
            saved_x25: u64,     // 80
            saved_x26: u64,     // 88
            saved_x27: u64,     // 96
            saved_x28: u64,     // 104
            saved_x29: u64,     // 112
            fault_esr: u64,     // 120
            fault_far: u64,     // 128
            fault_elr: u64,     // 136
            active: u32,        // 144
            fault_pending: u32, // 148  (0=none, 1=abort, 2=bad-svc, 3=deadline)
            outcome: i32,       // 152
            module_idx: u32,    // 156  (the gateway's caller)
            // Callee-saved FP/SIMD (v8-v15), full 128-bit, preserved across the
            // EL0 round-trip for the kernel caller.
            saved_v8: [u64; 2],  // 160
            saved_v9: [u64; 2],  // 176
            saved_v10: [u64; 2], // 192
            saved_v11: [u64; 2], // 208
            saved_v12: [u64; 2], // 224
            saved_v13: [u64; 2], // 240
            saved_v14: [u64; 2], // 256
            saved_v15: [u64; 2], // 272
            module_ttbr0: u64,   // 288  (restored after a gateway op)
            gate_elr: u64,       // 296  (the module's ELR/SPSR across a gateway op,
            gate_spsr: u64,      // 304   which IRQs taken during it overwrite)
            gate_x18: u64,       // 312  (the module's x18/x30 across a gateway op)
            gate_x30: u64,       // 320
            deadline: u64,       // 328  (CNTPCT at which the entry is forced out; 0 = none)
            _pad: [u8; 48],      // 336 → 384
        }

        const CB_SIZE: usize = 384;

        const _: () = {
            assert!(core::mem::size_of::<El0ControlBlock>() == CB_SIZE);
            assert!(core::mem::offset_of!(El0ControlBlock, kernel_sp) == 0);
            assert!(core::mem::offset_of!(El0ControlBlock, kernel_lr) == 8);
            assert!(core::mem::offset_of!(El0ControlBlock, kernel_ttbr0) == 16);
            assert!(core::mem::offset_of!(El0ControlBlock, kernel_daif) == 24);
            assert!(core::mem::offset_of!(El0ControlBlock, saved_x19) == 32);
            assert!(core::mem::offset_of!(El0ControlBlock, saved_x29) == 112);
            assert!(core::mem::offset_of!(El0ControlBlock, fault_esr) == 120);
            assert!(core::mem::offset_of!(El0ControlBlock, fault_far) == 128);
            assert!(core::mem::offset_of!(El0ControlBlock, fault_elr) == 136);
            assert!(core::mem::offset_of!(El0ControlBlock, active) == 144);
            assert!(core::mem::offset_of!(El0ControlBlock, fault_pending) == 148);
            assert!(core::mem::offset_of!(El0ControlBlock, outcome) == 152);
            assert!(core::mem::offset_of!(El0ControlBlock, module_idx) == 156);
            assert!(core::mem::offset_of!(El0ControlBlock, saved_v8) == 160);
            assert!(core::mem::offset_of!(El0ControlBlock, saved_v15) == 272);
            assert!(core::mem::offset_of!(El0ControlBlock, module_ttbr0) == 288);
            assert!(core::mem::offset_of!(El0ControlBlock, gate_elr) == 296);
            assert!(core::mem::offset_of!(El0ControlBlock, gate_spsr) == 304);
            assert!(core::mem::offset_of!(El0ControlBlock, gate_x18) == 312);
            assert!(core::mem::offset_of!(El0ControlBlock, gate_x30) == 320);
            assert!(core::mem::offset_of!(El0ControlBlock, deadline) == 328);
        };

        /// Bytes of each core's fault stack; the fail-stop path's
        /// `lsl #13` in `fluxor_el1_catch` is this.
        const EL1_FAULT_STACK_BYTES: usize = 8192;

        /// The stack the fail-stop EL1 fault path dumps on, one per core, so a
        /// fault that is itself a kernel stack overflow can still be reported.
        #[repr(C, align(16))]
        struct FaultStacks([[u8; EL1_FAULT_STACK_BYTES]; MAX_CORES]);
        #[no_mangle]
        static mut EL1_FAULT_STACKS: FaultStacks =
            FaultStacks([[0; EL1_FAULT_STACK_BYTES]; MAX_CORES]);

        /// Per-core control blocks. `#[no_mangle]` so the assembly can
        /// `adrp`/`add` the array base. Indexed by core id (0..MAX_CORES).
        #[no_mangle]
        static mut EL0_CBS: [El0ControlBlock; MAX_CORES] = {
            const Z: El0ControlBlock = El0ControlBlock {
                kernel_sp: 0,
                kernel_lr: 0,
                kernel_ttbr0: 0,
                kernel_daif: 0,
                saved_x19: 0,
                saved_x20: 0,
                saved_x21: 0,
                saved_x22: 0,
                saved_x23: 0,
                saved_x24: 0,
                saved_x25: 0,
                saved_x26: 0,
                saved_x27: 0,
                saved_x28: 0,
                saved_x29: 0,
                fault_esr: 0,
                fault_far: 0,
                fault_elr: 0,
                active: 0,
                fault_pending: 0,
                outcome: 0,
                module_idx: 0,
                saved_v8: [0; 2],
                saved_v9: [0; 2],
                saved_v10: [0; 2],
                saved_v11: [0; 2],
                saved_v12: [0; 2],
                saved_v13: [0; 2],
                saved_v14: [0; 2],
                saved_v15: [0; 2],
                module_ttbr0: 0,
                gate_elr: 0,
                gate_spsr: 0,
                gate_x18: 0,
                gate_x30: 0,
                deadline: 0,
                _pad: [0; 48],
            };
            [Z; MAX_CORES]
        };

        // ---- Per-isolated-module page tables (separate from the
        //      demand-pager pools so the two never alias) -------------------
        #[repr(C, align(4096))]
        struct IsoL2([u64; TABLE_ENTRIES]);

        static mut ISO_L1: [PageTable; MAX_ISO] = {
            const E: PageTable = PageTable([0; TABLE_ENTRIES]);
            [E; MAX_ISO]
        };
        /// One L2 table per kernel-base GB (`KERNEL_BASE_GB`) per module. The
        /// module table is a full EL1 identity map of low DRAM (so exception
        /// vectors / handler code / `EL0_CBS` / kernel channel code+data are
        /// reachable at EL1 while TTBR0 holds the module table) with the
        /// module's own regions carved to EL0 access at 4 KB. Indexed by the
        /// 1 GB (L1) index.
        static mut ISO_L2: [[IsoL2; KERNEL_BASE_GB]; MAX_ISO] = {
            const E: IsoL2 = IsoL2([0; TABLE_ENTRIES]);
            const M: [IsoL2; KERNEL_BASE_GB] = [E, E, E];
            [M; MAX_ISO]
        };
        /// One L2 per module for the gigabyte its device window lies in, and
        /// that gigabyte's L1 index (`usize::MAX` for none). A window is one
        /// peripheral block, so it never spans two gigabytes.
        static mut ISO_DEV_L2: [IsoL2; MAX_ISO] = {
            const E: IsoL2 = IsoL2([0; TABLE_ENTRIES]);
            [E; MAX_ISO]
        };
        static mut ISO_DEV_GB: [usize; MAX_ISO] = [usize::MAX; MAX_ISO];
        static mut ISO_L3: [[L3PageTable; MAX_L3]; MAX_ISO] = {
            const E: L3PageTable = L3PageTable([0; TABLE_ENTRIES]);
            [[E; MAX_L3]; MAX_ISO]
        };
        /// How many L3 tables are committed for each module, and which 2 MB
        /// window (`l1<<9 | l2` index key) each maps.
        static mut ISO_L3_USED: [usize; MAX_ISO] = [0; MAX_ISO];
        static mut ISO_L3_KEY: [[u32; MAX_L3]; MAX_ISO] = [[0; MAX_L3]; MAX_ISO];

        /// EL0 stack slabs (2 MB-aligned). Page 0 = guard (unmapped).
        #[repr(C, align(4096))]
        struct StackSlab([u8; STACK_SLAB_BYTES]);
        static mut ISO_STACKS: [StackSlab; MAX_ISO] = {
            const Z: StackSlab = StackSlab([0; STACK_SLAB_BYTES]);
            [Z; MAX_ISO]
        };

        /// The trampoline page, mapped RO+X at EL0 in every isolated module's
        /// table. Words `2·op, 2·op+1` are op `op`'s veneer, `svc #op; ret`,
        /// for every gateway op; then the return veneer `svc #RETURN; b .`,
        /// which `module_*` entry points return into; then, at
        /// [`GATEWAY_TABLE_OFFSET`], the `SyscallTable` a gated module is
        /// handed, whose entries point at the veneers. Nothing else in the
        /// page — no kernel `.text` or data is reachable from EL0.
        #[repr(C, align(4096))]
        struct TrampPage([u32; 1024]);
        #[no_mangle]
        static mut FLUXOR_EL0_TRAMP: TrampPage = {
            let mut p = [0u32; 1024];
            let mut op = 0;
            while op < GATEWAY_OPS {
                p[2 * op] = 0xD400_0001 | ((op as u32) << 5); // svc #op
                p[2 * op + 1] = 0xD65F_03C0; // ret
                op += 1;
            }
            p[2 * RETURN_OP] = 0xD400_0001 | ((RETURN_OP as u32) << 5); // svc #RETURN
            p[2 * RETURN_OP + 1] = 0x1400_0000; // b . (never reached)
            TrampPage(p)
        };
        static TRAMP_READY: AtomicBool = AtomicBool::new(false);
        /// Gateway operations with a veneer; the op is the SVC immediate.
        const GATEWAY_OPS: usize = crate::kernel::module::gateway::op::COUNT as usize;
        /// The return veneer's op.
        const RETURN_OP: usize = crate::kernel::module::gateway::op::RETURN as usize;
        /// Byte offset of the gateway `SyscallTable` in the trampoline page.
        const GATEWAY_TABLE_OFFSET: usize = 256;
        const _: () = assert!(8 * (RETURN_OP + 1) <= GATEWAY_TABLE_OFFSET);

        /// Owner of each isolated slot, `usize::MAX` when free. A slot is
        /// claimed at registration and released at teardown.
        static ISO_SLOT_OWNER: [AtomicUsize; MAX_ISO] =
            [const { AtomicUsize::new(usize::MAX) }; MAX_ISO];

        /// Maps a scheduler module index → isolated-slot (0..MAX_ISO), or
        /// `usize::MAX` if not isolated. `ISO_BUILT[slot]` gates `enter`.
        static mut MOD_TO_SLOT: [usize; super::MAX_MODULES] = [usize::MAX; super::MAX_MODULES];
        static mut ISO_BUILT: [bool; MAX_ISO] = [false; MAX_ISO];
        /// SP_EL0 top for each isolated slot (computed in `build_table`).
        static mut ISO_SP_TOP: [u64; MAX_ISO] = [0; MAX_ISO];
        /// Per-slot clean-step counter. The first clean EL0 round-trip and then
        /// every `EL0_OK_LOG_EVERY` steps logs a confirmation line (observable
        /// proof of EL0 execution + clean SVC return). Recurring (not one-shot)
        /// so the line is observable in a telemetry stream that only starts once
        /// the module is networking, well after its first step.
        static mut ISO_OK_COUNT: [u32; MAX_ISO] = [0; MAX_ISO];
        /// Log the EL0 clean-step confirmation on step 0 and every N thereafter.
        /// Kept small so even an infrequently-scheduled isolated module (a
        /// pure-compute source with no I/O steps far less than once per tick)
        /// emits one within a reasonable window.
        const EL0_OK_LOG_EVERY: u32 = 256;

        #[inline]
        fn cur_core() -> usize {
            let id = crate::kernel::sys::hal::core_id();
            if id < MAX_CORES {
                id
            } else {
                0
            }
        }

        /// Has the current module index got a usable isolated page table?
        pub fn is_isolated(module_idx: usize) -> bool {
            if module_idx >= super::MAX_MODULES {
                return false;
            }
            // SAFETY: scheduler-thread reads; arrays are boot/instantiation
            // populated and only read on the step path.
            unsafe {
                let slot = MOD_TO_SLOT[module_idx];
                slot != usize::MAX && slot < MAX_ISO && ISO_BUILT[slot]
            }
        }

        /// Reset all isolated-module bookkeeping. Called from
        /// `prepare_graph` so a reconfigure starts from a clean slate.
        pub fn reset() {
            // SAFETY: scheduler-thread-only, called while secondary cores are
            // parked during reconfigure. Indexed writes through raw pointers
            // (no `&mut` to the statics) match the file's static-access idiom.
            unsafe {
                let m = core::ptr::addr_of_mut!(MOD_TO_SLOT);
                for i in 0..super::MAX_MODULES {
                    (*m)[i] = usize::MAX;
                }
                let b = core::ptr::addr_of_mut!(ISO_BUILT);
                let ok = core::ptr::addr_of_mut!(ISO_OK_COUNT);
                for i in 0..MAX_ISO {
                    (*b)[i] = false;
                    (*ok)[i] = 0;
                }
                // Clear all per-module region records; instantiation re-sets
                // them for the new graph.
                let ri = core::ptr::addr_of_mut!(MODULE_REGION_INFO);
                for i in 0..super::MAX_MODULES {
                    (*ri)[i] = super::ModuleRegions::empty();
                }
                for owner in ISO_SLOT_OWNER.iter() {
                    owner.store(usize::MAX, Ordering::Relaxed);
                }
                // Flush all stage-1 EL1&0 translations (inner-shareable) before
                // the graph rebuilds. ASIDs are derived deterministically from
                // the module index (`module_idx + 1`), so a reconfigure that
                // re-uses an index would otherwise inherit the PREVIOUS graph's
                // EL0 mappings for that ASID out of the TLB — stale, and a
                // cross-graph information leak. The module-page descriptors are
                // `nG` (ASID-tagged), so without this invalidate a `switch` to a
                // recycled ASID can hit a retained entry. Cores are parked during
                // reconfigure, so a one-shot broadcast invalidate is sufficient.
                core::arch::asm!(
                    "dsb ishst",
                    "tlbi vmalle1is",
                    "dsb ish",
                    "isb",
                    options(nostack, preserves_flags),
                );
            }
        }

        /// One-time publish of the trampoline page: fill in the gateway
        /// `SyscallTable` (the veneers' absolute addresses are known only at
        /// run time), then clean the D-cache and invalidate the I-cache over
        /// the veneers so EL0 fetches the instructions written as data.
        unsafe fn ensure_trampoline() {
            if TRAMP_READY.swap(true, Ordering::AcqRel) {
                return;
            }
            let base = core::ptr::addr_of!(FLUXOR_EL0_TRAMP) as usize;
            let veneer = |op: u32| base + 8 * op as usize;
            use crate::kernel::module::gateway::op;
            // SAFETY: each veneer is `svc #op; ret`, called with the slot's
            // own C signature; the kernel serves the trap with the same
            // arguments the slot declares.
            let table = unsafe {
                crate::abi::SyscallTable {
                    version: crate::abi::ABI_VERSION,
                    channel_read: core::mem::transmute::<
                        usize,
                        unsafe extern "C" fn(i32, *mut u8, usize) -> i32,
                    >(veneer(op::CHANNEL_READ)),
                    channel_write: core::mem::transmute::<
                        usize,
                        unsafe extern "C" fn(i32, *const u8, usize) -> i32,
                    >(veneer(op::CHANNEL_WRITE)),
                    channel_poll: core::mem::transmute::<
                        usize,
                        unsafe extern "C" fn(i32, u32) -> i32,
                    >(veneer(op::CHANNEL_POLL)),
                    heap_alloc: core::mem::transmute::<usize, unsafe extern "C" fn(u32) -> *mut u8>(
                        veneer(op::HEAP_ALLOC),
                    ),
                    heap_free: core::mem::transmute::<usize, unsafe extern "C" fn(*mut u8)>(
                        veneer(op::HEAP_FREE),
                    ),
                    heap_realloc: core::mem::transmute::<
                        usize,
                        unsafe extern "C" fn(*mut u8, u32) -> *mut u8,
                    >(veneer(op::HEAP_REALLOC)),
                    provider_open: core::mem::transmute::<
                        usize,
                        unsafe extern "C" fn(u32, u32, *const u8, usize) -> i32,
                    >(veneer(op::PROVIDER_OPEN)),
                    provider_call: core::mem::transmute::<
                        usize,
                        unsafe extern "C" fn(i32, u32, *mut u8, usize) -> i32,
                    >(veneer(op::PROVIDER_CALL)),
                    provider_query: core::mem::transmute::<
                        usize,
                        unsafe extern "C" fn(i32, u32, *mut u8, usize) -> i32,
                    >(veneer(op::PROVIDER_QUERY)),
                    provider_close: core::mem::transmute::<usize, unsafe extern "C" fn(i32) -> i32>(
                        veneer(op::PROVIDER_CLOSE),
                    ),
                    channel_peek: core::mem::transmute::<
                        usize,
                        unsafe extern "C" fn(i32, *mut u8, usize) -> i32,
                    >(veneer(op::CHANNEL_PEEK)),
                    provider_call_sel: core::mem::transmute::<
                        usize,
                        unsafe extern "C" fn(*const u8, usize, i32, u32, *mut u8, usize) -> i32,
                    >(veneer(op::PROVIDER_CALL_SEL)),
                    // A word the kernel writes cannot be both mapped read-only
                    // to EL0 and kept current; the SDK treats null as "ask".
                    telemetry_enabled: core::ptr::null(),
                }
            };
            core::ptr::write(
                (base + GATEWAY_TABLE_OFFSET) as *mut crate::abi::SyscallTable,
                table,
            );
            let mut line = base;
            while line < base + GATEWAY_TABLE_OFFSET {
                core::arch::asm!(
                    "dc cvau, {p}",
                    "dsb ish",
                    "ic ivau, {p}",
                    p = in(reg) line,
                    options(nostack, preserves_flags),
                );
                line += 64;
            }
            core::arch::asm!("dsb ish", "isb", options(nostack, preserves_flags));
        }

        /// The gateway `SyscallTable` in the trampoline page.
        pub fn gateway_table() -> *const crate::abi::SyscallTable {
            // SAFETY: publishes the page once; afterwards only its address.
            unsafe { ensure_trampoline() };
            (core::ptr::addr_of!(FLUXOR_EL0_TRAMP) as usize + GATEWAY_TABLE_OFFSET) as *const _
        }

        /// Claim an isolated slot for `module_idx` and build its page table
        /// from the regions registered in `MODULE_REGION_INFO` (code, state,
        /// heap), plus a guarded EL0 stack and the trampoline page. Called at
        /// registration, before any of the module's code runs; `false` fails
        /// the load closed.
        pub fn build_table(module_idx: usize) -> bool {
            if module_idx >= super::MAX_MODULES {
                return false;
            }
            // SAFETY: registration runs on the setup path; the claimed slot's
            // tables are this call's alone until it is published.
            unsafe {
                ensure_trampoline();
                let r = MODULE_REGION_INFO[module_idx];
                if r.code_size == 0 || r.state_size == 0 {
                    log::warn!(
                        "[el0] module {module_idx}: code/state region missing; cannot isolate"
                    );
                    return false;
                }
                // Page-isolation invariant: every mapping rounds out to whole
                // 4 KiB pages, so an EL0-RW region that is not itself
                // page-aligned and page-sized would drag a neighbour — kernel
                // data or another module's state — into the module's reach.
                // `loader::alloc_isolated` makes state and heap page-clean;
                // this refuses anything that is not, before claiming a slot.
                let page_clean = |base: u64, size: u64| -> bool {
                    size == 0 || (base & (PAGE - 1) == 0 && size & (PAGE - 1) == 0)
                };
                if !page_clean(r.state_base, r.state_size) || !page_clean(r.heap_base, r.heap_size)
                {
                    log::error!(
                        "[el0] module {module_idx}: REFUSING isolation — an EL0-RW region is not \
                         page-aligned/page-sized (state 0x{:x}+{} heap 0x{:x}+{})",
                        r.state_base,
                        r.state_size,
                        r.heap_base,
                        r.heap_size,
                    );
                    return false;
                }
                // Code is EL0-RO; a region that is not page-aligned exposes
                // neighbouring module code read-only, never writable.
                if !page_clean(r.code_base, r.code_size) {
                    log::warn!(
                        "[el0] module {module_idx}: code region 0x{:x}+{} not page-aligned — \
                         adjacent module code is EL0-readable (RO)",
                        r.code_base,
                        r.code_size,
                    );
                }
                let Some(slot) = ISO_SLOT_OWNER.iter().position(|o| {
                    o.compare_exchange(usize::MAX, module_idx, Ordering::AcqRel, Ordering::Relaxed)
                        .is_ok()
                }) else {
                    log::warn!("[el0] module {module_idx}: no isolated slot free (max {MAX_ISO})");
                    return false;
                };

                // Fresh tables for this slot.
                for e in ISO_L1[slot].0.iter_mut() {
                    *e = 0;
                }
                for t in ISO_L2[slot].iter_mut() {
                    for e in t.0.iter_mut() {
                        *e = 0;
                    }
                }
                for t in ISO_L3[slot].iter_mut() {
                    for e in t.0.iter_mut() {
                        *e = 0;
                    }
                }
                ISO_L3_USED[slot] = 0;
                for e in ISO_DEV_L2[slot].0.iter_mut() {
                    *e = 0;
                }
                ISO_DEV_GB[slot] = usize::MAX;
                // A slot's stack is the module's own memory: none of the
                // previous occupant's frames survive into it.
                core::ptr::write_bytes(
                    core::ptr::addr_of_mut!(ISO_STACKS[slot]).cast::<u8>(),
                    0,
                    STACK_SLAB_BYTES,
                );

                // Seed the kernel EL1-only identity base so the vectors and
                // the trap path are reachable at EL1 while this table is
                // live; EL0 has no access to any of it (AP_EL1_RW).
                seed_kernel_base(slot);

                // Carve the module's regions to EL0 access at 4 KB. Every
                // region must map completely, or the table is not published.
                let mut mapped = true;
                let tramp = core::ptr::addr_of!(FLUXOR_EL0_TRAMP) as u64;
                let slab = core::ptr::addr_of!(ISO_STACKS[slot]) as u64;
                let stack_lo = slab + PAGE; // first mapped page (guard = slab..slab+PAGE)
                mapped &= map_region(slot, r.code_base, r.code_size, AP_EL0_RO, false); // RO + X
                mapped &= map_region(slot, r.state_base, r.state_size, AP_EL0_RW, true); // RW + XN
                if r.heap_size > 0 {
                    mapped &= map_region(slot, r.heap_base, r.heap_size, AP_EL0_RW, true);
                }
                // Trampoline page: RO + X at EL0.
                mapped &= map_region(slot, tramp, PAGE, AP_EL0_RO, false);
                // The device window the graph granted: its peripheral's
                // registers, Device memory, EL0 RW and never executable.
                if let Some((wb, wz)) =
                    crate::kernel::exec::scheduler::module_device_window(module_idx)
                {
                    mapped &= map_device(slot, module_idx, wb, wz as u64);
                }
                // EL0 stack above an unmapped guard page.
                mapped &= map_region(slot, stack_lo, EL0_STACK_BYTES, AP_EL0_RW, true);
                ISO_SP_TOP[slot] = stack_lo + EL0_STACK_BYTES; // grows down
                                                               // The kernel stacks' guard pages stay unmapped under this
                                                               // table too: the kernel runs on them while serving this
                                                               // module's traps and interrupts.
                for guard in crate::platform::multicore::kernel_stack_guards() {
                    mapped &= unmap_4k(slot, guard);
                }

                if !mapped {
                    log::error!(
                        "[el0] module {module_idx}: page-table build INCOMPLETE (region out of \
                         window or L3 pool exhausted) — refusing to publish (fail closed)"
                    );
                    ISO_SLOT_OWNER[slot].store(usize::MAX, Ordering::Release);
                    return false;
                }

                // Publish: descriptors visible to the walker, then invalidate
                // the whole EL1&0 regime — a cached global entry for the 2 MB
                // window these tables live in would shadow the module's nG
                // carve in the same window.
                core::arch::asm!(
                    "dsb ishst",
                    "tlbi vmalle1is",
                    "dsb ish",
                    "isb",
                    options(nostack, preserves_flags),
                );
                MOD_TO_SLOT[module_idx] = slot;
                ISO_BUILT[slot] = true;
                ISO_OK_COUNT[slot] = 0;
                log::info!(
                    "[el0] module {module_idx} isolated slot={slot} \
                     code=0x{:x}+{} state=0x{:x}+{} sp_top=0x{:x}",
                    r.code_base,
                    r.code_size,
                    r.state_base,
                    r.state_size,
                    ISO_SP_TOP[slot]
                );
                crate::kernel::module::gateway::set_stack(
                    module_idx,
                    crate::kernel::module::gateway::Region {
                        base: stack_lo as usize,
                        len: EL0_STACK_BYTES as usize,
                    },
                );
                true
            }
        }

        /// Release `module_idx`'s slot at teardown, so a later module can be
        /// isolated in its place.
        pub fn release(module_idx: usize) {
            if module_idx >= super::MAX_MODULES {
                return;
            }
            // SAFETY: teardown runs with the module no longer stepping.
            unsafe {
                let slot = MOD_TO_SLOT[module_idx];
                if slot >= MAX_ISO {
                    return;
                }
                MOD_TO_SLOT[module_idx] = usize::MAX;
                ISO_BUILT[slot] = false;
                ISO_SLOT_OWNER[slot].store(usize::MAX, Ordering::Release);
                // The module's ASID must not resolve to its old pages.
                let asid = (module_idx as u64 + 1) & 0xFF;
                core::arch::asm!(
                    "dsb ishst",
                    "tlbi aside1is, {a}",
                    "dsb ish",
                    "isb",
                    a = in(reg) asid << 48,
                    options(nostack, preserves_flags),
                );
            }
        }

        /// Identity-map `[base, base+size)` into slot `slot`'s tables at
        /// 4 KB granularity with the given access perms. `phys == va`
        /// (the Pi 5 kernel runs an identity map). Returns `false` if ANY page
        /// failed to map — the caller must treat a partial region as a build
        /// failure (do not publish the table).
        #[must_use]
        unsafe fn map_region(slot: usize, base: u64, size: u64, ap: u64, xn_el0: bool) -> bool {
            if size == 0 {
                return true;
            }
            let start = base & !(PAGE - 1);
            let end = (base + size + PAGE - 1) & !(PAGE - 1);
            let mut va = start;
            let mut ok = true;
            while va < end {
                // Map every page even after a failure (so the warning log names
                // all unmappable pages), but remember that the region is partial.
                ok &= map_4k(slot, va, ap, xn_el0);
                va += PAGE;
            }
            ok
        }

        /// Seed the module table with a kernel EL1-only identity map of the
        /// first `KERNEL_BASE_GB` of DRAM: 1 GB blocks, EL1 RW + executable
        /// (PXN=0 so the exception vectors / handler run), EL0 no-access
        /// (AP_EL1_RW) + UXN. Module EL0 regions are carved on top by
        /// `map_4k`, which splits the enclosing block into a table while
        /// preserving these EL1 attrs for the surrounding (kernel) pages.
        unsafe fn seed_kernel_base(slot: usize) {
            for gb in 0..KERNEL_BASE_GB {
                let phys = (gb as u64) * L1_BLOCK_SIZE;
                // make_block_desc(phys, attr, ap, xn_el0, xn_el1):
                //   AP_EL1_RW → EL0 no access; xn_el0=true (UXN); xn_el1=false
                //   (PXN=0, EL1 may execute kernel code/vectors).
                ISO_L1[slot].0[gb] = make_block_desc(phys, ATTR_IDX_NORMAL, AP_EL1_RW, true, false);
            }
            seed_kernel_mmio(slot);
        }

        /// 1 GB L1 indices (GB = phys >> 30) for the MMIO apertures the kernel
        /// touches at EL1 while a module's TTBR0 is live: the GIC (timer
        /// IAR/EOIR on the IRQ path, idx 64+65 covering 0x10_7fff_a000) and the
        /// RP1 PL011 UART (fault/panic dump + debug drain, idx 112 covering
        /// 0x1c_0003_0000). Mirrors the boot table device blocks
        /// (`boot_mmu::init_page_tables`) but EL1-only (`AP_EL1_RW`, no EL0
        /// access) so an isolated module still cannot reach MMIO — only the
        /// kernel servicing its trap can. WITHOUT this, any EL1 fault taken
        /// while the module table is installed (or the IRQ handler / svc1
        /// dispatch) hits an unmapped UART/GIC and recurses into a silent
        /// translation-fault loop.
        const KERNEL_MMIO_GB: [usize; 3] = [64, 65, 112];

        /// Install the EL1-only Device blocks for [`KERNEL_MMIO_GB`] into a
        /// module table's L1 so EL1 trap/IRQ handlers can reach MMIO under the
        /// module regime.
        unsafe fn seed_kernel_mmio(slot: usize) {
            for &gb in KERNEL_MMIO_GB.iter() {
                let phys = (gb as u64) * L1_BLOCK_SIZE;
                // Device-nGnRnE, EL1 RW, EL0 no-access, XN at both ELs.
                ISO_L1[slot].0[gb] = make_block_desc(phys, ATTR_IDX_DEVICE, AP_EL1_RW, true, true);
            }
        }

        /// EL1-only 2 MB block descriptor used to back-fill an L2 when a 1 GB
        /// kernel block is split to carve an EL0 hole.
        #[inline]
        unsafe fn kernel_block_2m(phys: u64) -> u64 {
            make_block_desc(phys, ATTR_IDX_NORMAL, AP_EL1_RW, true, false)
        }

        /// EL1-only 4 KB page descriptor used to back-fill an L3 when a 2 MB
        /// block is split to carve an EL0 hole.
        #[inline]
        unsafe fn kernel_page_4k(phys: u64) -> u64 {
            make_page_desc(phys, ATTR_IDX_NORMAL, AP_EL1_RW, true, false)
        }

        /// Walk slot `slot`'s page table for `va` and return the raw descriptors
        /// `(l1, l2, l3)` the MMU would use (l2/l3 = 0 if the walk stops at a
        /// block). Diagnostic only — lets the EL0 abort handler show whether the
        /// faulting address's L2 was split to a table (L3 carve present) or is
        /// still a kernel EL1-only block (the carve never took effect).
        unsafe fn walk_descriptors(slot: usize, va: u64) -> (u64, u64, u64) {
            let l1i = (va / L1_BLOCK_SIZE) as usize;
            if l1i >= TABLE_ENTRIES {
                return (0, 0, 0);
            }
            let l1 = ISO_L1[slot].0[l1i];
            if l1 & DESC_TABLE == 0 {
                return (l1, 0, 0); // L1 block — no L2/L3
            }
            let l2i = ((va >> 21) & 0x1FF) as usize;
            let l2 = if l1i < KERNEL_BASE_GB {
                ISO_L2[slot][l1i].0[l2i]
            } else {
                ISO_DEV_L2[slot].0[l2i]
            };
            if l2 & DESC_TABLE == 0 {
                return (l1, l2, 0); // L2 block — no L3 (the bug signature)
            }
            // L2 is a table → follow ITS pointer to the real L3 the MMU uses
            // (not a key-search, which can disagree with the published L2). This
            // reads the actual leaf descriptor for `va`.
            let l3_base = (l2 & 0x0000_FFFF_FFFF_F000) as *const u64;
            let l3i = ((va >> 12) & 0x1FF) as usize;
            let l3 = core::ptr::read_volatile(l3_base.add(l3i));
            (l1, l2, l3)
        }

        /// Map one 4 KB identity page into slot `slot` with EL0 access perms,
        /// carving it out of the kernel EL1 base. Splits the enclosing 1 GB
        /// block → L2 (2 MB EL1 blocks) and the enclosing 2 MB block → L3
        /// (4 KB EL1 pages) on first touch, so every non-carved page in those
        /// windows keeps its kernel EL1 mapping and only this page becomes
        /// EL0-accessible.
        /// Returns `false` if the page could not be mapped (VA outside the
        /// supported window, or the per-slot L3-table pool is exhausted). The
        /// caller MUST propagate this — a silently-unmapped page would leave the
        /// isolated module with an incomplete table that faults at EL0 (or worse,
        /// an EL1-only block where it expected its own RW memory).
        #[must_use]
        unsafe fn map_4k(slot: usize, va: u64, ap: u64, xn_el0: bool) -> bool {
            let Some(entry) = l3_entry(slot, va, false) else {
                return false;
            };
            // XN at EL1 stays true for module memory (the kernel never
            // executes module pages); xn_el0 is per-region (false only for
            // the module's RO+X code/trampoline).
            *entry = make_page_desc(va, ATTR_IDX_NORMAL, ap, xn_el0, true);
            true
        }

        /// Map a module's device window into slot `slot`: Device memory, EL0
        /// RW, never executable at either level. Only whole pages inside one
        /// block the target lists as grantable, whatever the config says.
        #[must_use]
        unsafe fn map_device(slot: usize, module_idx: usize, base: u64, size: u64) -> bool {
            let grantable = DEVICE_RANGES
                .iter()
                .any(|&(rb, rz)| base >= rb && base + size <= rb + rz);
            if !grantable || base & (PAGE - 1) != 0 || size & (PAGE - 1) != 0 || size == 0 {
                log::error!(
                    "[el0] module {module_idx}: device window 0x{base:x}+{size} is not whole \
                     pages inside a grantable block — refusing"
                );
                return false;
            }
            let mut va = base;
            while va < base + size {
                let Some(entry) = l3_entry(slot, va, true) else {
                    return false;
                };
                *entry = make_page_desc(va, ATTR_IDX_DEVICE, AP_EL0_RW, true, true);
                va += PAGE;
            }
            log::info!("[el0] module {module_idx} device window 0x{base:x}+{size}");
            true
        }

        /// Leave the 4 KB page at `va` unmapped in slot `slot`'s table — at
        /// every EL — splitting the enclosing kernel blocks as `map_4k` does.
        /// Used for the kernel stack guard pages, which the seeded 1 GB kernel
        /// blocks would otherwise map while a module's table is live.
        #[must_use]
        unsafe fn unmap_4k(slot: usize, va: u64) -> bool {
            let Some(entry) = l3_entry(slot, va, false) else {
                return false;
            };
            *entry = 0;
            true
        }

        /// The L3 descriptor for `va` in slot `slot`'s table, splitting the
        /// seeded 1 GB kernel block and then the 2 MB block that enclose it
        /// (back-filled with the EL1-only descriptors they replace). `None` if
        /// `va` is outside the kernel window or the L3 pool is exhausted.
        unsafe fn l3_entry(slot: usize, va: u64, device: bool) -> Option<&'static mut u64> {
            let l1i = (va / L1_BLOCK_SIZE) as usize; // 1 GB index
            let l2i = ((va >> 21) & 0x1FF) as usize;
            let l3i = ((va >> 12) & 0x1FF) as usize;
            // Which L2 the gigabyte uses, and what its untouched pages hold:
            // the kernel's EL1-only memory in the kernel base, the kernel's
            // EL1-only Device mapping in an aperture it reaches under this
            // table, nothing in any other device gigabyte.
            let kernel_mmio = KERNEL_MMIO_GB.contains(&l1i);
            let l2: *mut IsoL2 = if l1i < KERNEL_BASE_GB {
                core::ptr::addr_of_mut!(ISO_L2[slot][l1i])
            } else if device && l1i < TABLE_ENTRIES {
                if ISO_DEV_GB[slot] == usize::MAX {
                    ISO_DEV_GB[slot] = l1i;
                }
                if ISO_DEV_GB[slot] != l1i {
                    log::warn!(
                        "[el0] slot {slot}: device va 0x{va:x} in a second gigabyte — skipped"
                    );
                    return None;
                }
                core::ptr::addr_of_mut!(ISO_DEV_L2[slot])
            } else {
                log::warn!(
                    "[el0] slot {slot}: va 0x{va:x} above {KERNEL_BASE_GB} GB base — skipped"
                );
                return None;
            };
            let fill_2m = |phys: u64| -> u64 {
                if l1i < KERNEL_BASE_GB {
                    kernel_block_2m(phys)
                } else if kernel_mmio {
                    make_block_desc(phys, ATTR_IDX_DEVICE, AP_EL1_RW, true, true)
                } else {
                    0
                }
            };

            // 1. Ensure L1[l1i] is a table → its L2. If it is still the seeded
            //    1 GB block (or empty), split it: fill the L2 with the 2 MB
            //    blocks covering the whole GB, then point L1 at it.
            if ISO_L1[slot].0[l1i] & DESC_TABLE == 0 {
                let gb_base = (l1i as u64) * L1_BLOCK_SIZE;
                for (j, e) in (*l2).0.iter_mut().enumerate() {
                    *e = fill_2m(gb_base + (j as u64) * L2_BLOCK_SIZE);
                }
                let l2_base = l2 as u64;
                ISO_L1[slot].0[l1i] = (l2_base & !0xFFF) | DESC_VALID | DESC_TABLE;
            }

            // 2. Ensure L2[l2i] is a table → an L3. If it is still a 2 MB
            //    kernel block, split it: fill the L3 with EL1 4 KB pages
            //    covering the 2 MB, then point L2 at it. The L3 table is
            //    found/allocated from the per-slot pool keyed by (l1i,l2i).
            let key = ((l1i as u32) << 9) | (l2i as u32);
            let used = ISO_L3_USED[slot];
            let mut l3slot = usize::MAX;
            let mut k = 0;
            while k < used {
                if ISO_L3_KEY[slot][k] == key {
                    l3slot = k;
                    break;
                }
                k += 1;
            }
            if l3slot == usize::MAX {
                if used >= MAX_L3 {
                    log::warn!("[el0] slot {slot}: out of L3 tables mapping va 0x{va:x}");
                    return None;
                }
                l3slot = used;
                ISO_L3_KEY[slot][l3slot] = key;
                ISO_L3_USED[slot] = used + 1;
                // Back-fill the new L3 with the EL1 pages it replaces.
                let win_base = (l1i as u64) * L1_BLOCK_SIZE + (l2i as u64) * L2_BLOCK_SIZE;
                for (j, e) in ISO_L3[slot][l3slot].0.iter_mut().enumerate() {
                    let phys = win_base + (j as u64) * PAGE;
                    *e = if l1i < KERNEL_BASE_GB {
                        kernel_page_4k(phys)
                    } else if kernel_mmio {
                        make_page_desc(phys, ATTR_IDX_DEVICE, AP_EL1_RW, true, true)
                    } else {
                        0
                    };
                }
                let l3_base = core::ptr::addr_of!(ISO_L3[slot][l3slot]) as u64;
                (*l2).0[l2i] = (l3_base & !0xFFF) | DESC_VALID | DESC_TABLE;
            }
            Some(&mut ISO_L3[slot][l3slot].0[l3i])
        }

        /// Call one entry point of isolated module `module_idx` at EL0 under
        /// its own page table: `args` in x0–x7, `params` copied to the top of
        /// its EL0 stack (their address replacing `args[3]`), the return
        /// veneer as its link register, forced out after `deadline_us`.
        ///
        /// # Safety
        /// `entry` is a validated export of `module_idx` taking these
        /// arguments; the caller runs on the module's owning core.
        pub unsafe fn call(
            module_idx: usize,
            entry: usize,
            args: &[usize; 8],
            params: &[u8],
            deadline_us: u32,
        ) -> i32 {
            let slot = MOD_TO_SLOT[module_idx];
            if slot == usize::MAX || slot >= MAX_ISO || !ISO_BUILT[slot] {
                return super::EL0_FAIL_CLOSED;
            }
            let core = cur_core();
            let cb = core::ptr::addr_of_mut!(EL0_CBS[core]);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*cb).module_idx), module_idx as u32);
            // Module TTBR0: ISO_L1 base | ASID (module_idx+1) in [63:48].
            let l1 = core::ptr::addr_of!(ISO_L1[slot]) as u64;
            let asid = (module_idx as u64 + 1) & 0xFF;
            let ttbr0 = (l1 & 0x0000_FFFF_FFFF_FFFF) | (asid << 48);

            // Params go to the top of the module's own stack, 16-aligned, so
            // what it reads is its own memory; the stack starts below them.
            let mut regs = [0u64; 8];
            for (r, a) in regs.iter_mut().zip(args.iter()) {
                *r = *a as u64;
            }
            let mut sp = ISO_SP_TOP[slot];
            if !params.is_empty() {
                let len = (params.len() as u64 + 15) & !15;
                if len > EL0_STACK_BYTES / 2 {
                    return super::EL0_FAIL_CLOSED;
                }
                sp -= len;
                core::ptr::copy_nonoverlapping(params.as_ptr(), sp as *mut u8, params.len());
                regs[3] = sp;
            }
            let ret = core::ptr::addr_of!(FLUXOR_EL0_TRAMP) as u64 + 8 * RETURN_OP as u64;
            let freq: u64;
            // SAFETY: reading the counter frequency is side-effect free.
            core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nomem, nostack));
            let deadline = if deadline_us == 0 || freq == 0 {
                0
            } else {
                read_cntpct() + u64::from(deadline_us) * freq / 1_000_000
            };
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*cb).deadline), deadline);

            // SAFETY: fluxor_el0_enter saves the kernel context into *cb and
            // returns through fluxor_el0_resume with the outcome.
            let outcome: i32;
            core::arch::asm!(
                "bl fluxor_el0_enter",
                in("x0") cb,
                in("x1") ttbr0,
                in("x2") sp,
                in("x3") entry,
                in("x4") regs.as_ptr(),
                in("x5") ret,
                lateout("x0") outcome,
                // callee-saved x19-x29 and v8-v15 are restored from *cb, so
                // this is a normal C call to the caller.
                clobber_abi("C"),
            );
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*cb).deadline), 0);

            let fp = core::ptr::read_volatile(core::ptr::addr_of!((*cb).fault_pending));
            if fp == 0 {
                let n = ISO_OK_COUNT[slot];
                ISO_OK_COUNT[slot] = n.wrapping_add(1);
                if n < 64 || n.is_multiple_of(EL0_OK_LOG_EVERY) {
                    log::info!(
                        "[el0] module {module_idx} el0 step ok outcome={outcome} step={n} \
                         (lower-EL SVC return confirms EL0 execution)"
                    );
                }
                return outcome;
            }
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*cb).fault_pending), 0);
            let esr = core::ptr::read_volatile(core::ptr::addr_of!((*cb).fault_esr));
            let far = core::ptr::read_volatile(core::ptr::addr_of!((*cb).fault_far));
            let elr = core::ptr::read_volatile(core::ptr::addr_of!((*cb).fault_elr));
            match fp {
                2 => log::error!(
                    "[el0] module {module_idx} illegal SVC (ESR=0x{esr:016x}) at \
                     ELR=0x{elr:016x} — protection fault"
                ),
                3 => log::error!(
                    "[el0] module {module_idx} forced out at ELR=0x{elr:016x}: ran past its \
                     {deadline_us} us deadline"
                ),
                _ => {
                    let ec = (esr >> 26) & 0x3F;
                    let r = MODULE_REGION_INFO[module_idx];
                    let sp_top = ISO_SP_TOP[slot];
                    let stack_lo = sp_top.saturating_sub(EL0_STACK_BYTES);
                    let (d1, d2, d3) = walk_descriptors(slot, far);
                    log::error!(
                        "[el0] module {module_idx} EL0 abort EC=0x{ec:02x} ESR=0x{esr:016x} \
                         FAR=0x{far:016x} ELR=0x{elr:016x} — protection fault \
                         [state=0x{state_base:x}+{state_size} heap=0x{heap_base:x}+{heap_size} \
                         stack=0x{stack_lo:x}..0x{sp_top:x} \
                         code=0x{code_base:x}+{code_size}] walk[l1=0x{d1:x} l2=0x{d2:x} l3=0x{d3:x}]",
                        state_base = r.state_base, state_size = r.state_size,
                        heap_base = r.heap_base, heap_size = r.heap_size,
                        code_base = r.code_base, code_size = r.code_size,
                    );
                }
            }
            // A deadline overrun is a step timeout, the rest protection
            // faults; either reaches the scheduler through the step guard, so
            // this returns Continue rather than an error the scheduler would
            // process a second time.
            if fp == 3 {
                crate::kernel::exec::step_guard::record_forced_timeout(module_idx);
            } else {
                crate::kernel::exec::step_guard::record_mpu_fault(module_idx);
            }
            0
        }

        #[inline]
        fn read_cntpct() -> u64 {
            let v: u64;
            // SAFETY: reading the virtual counter is side-effect free.
            unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) v, options(nomem, nostack)) };
            v
        }

        /// The gateway trap, called from `fluxor_el0_svc_gate` under the
        /// kernel's table with IRQs open: authorise and serve op `op` for the
        /// module the control block names.
        #[no_mangle]
        unsafe extern "C" fn fluxor_gateway_el0(
            module_idx: u32,
            op: u32,
            a0: u64,
            a1: u64,
            a2: u64,
            a3: u64,
            a4: u64,
            a5: u64,
        ) -> i64 {
            let args = [
                a0 as usize,
                a1 as usize,
                a2 as usize,
                a3 as usize,
                a4 as usize,
                a5 as usize,
            ];
            // SAFETY: the module is suspended at its veneer; the gateway
            // validates everything it was passed before use.
            unsafe {
                crate::kernel::module::gateway::dispatch(module_idx as usize, op, args) as i64
            }
        }

        /// Whether the entry running at EL0 on this core has passed its
        /// deadline, called from the lower-EL IRQ path after the interrupt
        /// has been served. `true` forces the module out.
        #[no_mangle]
        extern "C" fn fluxor_el0_irq_preempt() -> u32 {
            let core = cur_core();
            // SAFETY: this core's control block, read on this core.
            let deadline =
                unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EL0_CBS[core].deadline)) };
            u32::from(deadline != 0 && read_cntpct() >= deadline)
        }

        // ---- Assembly: EL0 entry, longjmp-resume, lower-EL sync dispatch ---
        //
        // Offsets below are the El0ControlBlock byte offsets pinned by the
        // assert block above.
        core::arch::global_asm!(
            ".section .text",
            ".global fluxor_el0_enter",
            ".global fluxor_el0_resume",
            ".global fluxor_el0_lower_sync_vec",
            ".global fluxor_el0_lower_irq_vec",
            // ---- fluxor_el0_enter(cb=x0, ttbr0=x1, sp_el0=x2,
            //                       entry=x3, args=x4 (8 × u64), ret=x5) -> i32 ----
            "fluxor_el0_enter:",
            "mov   x9, sp",
            "str   x9,  [x0, #0]", // kernel_sp
            "str   x30, [x0, #8]", // kernel_lr (return into call())
            "mrs   x9, ttbr0_el1",
            "str   x9,  [x0, #16]", // kernel_ttbr0 (live boot table)
            "mrs   x9, daif",
            "str   x9,  [x0, #24]", // kernel_daif
            "stp   x19, x20, [x0, #32]",
            "stp   x21, x22, [x0, #48]",
            "stp   x23, x24, [x0, #64]",
            "stp   x25, x26, [x0, #80]",
            "stp   x27, x28, [x0, #96]",
            "str   x29, [x0, #112]",
            "str   q8,  [x0, #160]",
            "str   q9,  [x0, #176]",
            "str   q10, [x0, #192]",
            "str   q11, [x0, #208]",
            "str   q12, [x0, #224]",
            "str   q13, [x0, #240]",
            "str   q14, [x0, #256]",
            "str   q15, [x0, #272]",
            "str   x1,  [x0, #288]", // module_ttbr0
            "mov   w9, #1",
            "str   w9,  [x0, #144]", // active = 1
            "str   wzr, [x0, #148]", // fault_pending = 0
            // Install the module translation regime.
            "msr   ttbr0_el1, x1",
            "isb",
            "msr   sp_el0, x2",
            "msr   elr_el1, x3", // EL0 entry point
            // SPSR_EL1: EL0t with IRQs unmasked (D, A, F masked). An IRQ at EL0
            // is served by `fluxor_el0_lower_irq_vec`, which is what bounds a
            // module that never returns.
            "movz  x9, #0x340",
            "msr   spsr_el1, x9",
            "mov   x30, x5", // LR = the return veneer
            "mov   x9, x4",
            "ldp   x0, x1, [x9, #0]",
            "ldp   x2, x3, [x9, #16]",
            "ldp   x4, x5, [x9, #32]",
            "ldp   x6, x7, [x9, #48]",
            // Scrub every other register so no kernel state is visible at EL0
            // (the kernel's callee-saved values are in the control block).
            "mov x8, xzr",
            "mov x9, xzr",
            "mov x10, xzr",
            "mov x11, xzr",
            "mov x12, xzr",
            "mov x13, xzr",
            "mov x14, xzr",
            "mov x15, xzr",
            "mov x16, xzr",
            "mov x17, xzr",
            "mov x18, xzr",
            "mov x19, xzr",
            "mov x20, xzr",
            "mov x21, xzr",
            "mov x22, xzr",
            "mov x23, xzr",
            "mov x24, xzr",
            "mov x25, xzr",
            "mov x26, xzr",
            "mov x27, xzr",
            "mov x28, xzr",
            "mov x29, xzr",
            "movi v0.2d, #0",
            "movi v1.2d, #0",
            "movi v2.2d, #0",
            "movi v3.2d, #0",
            "movi v4.2d, #0",
            "movi v5.2d, #0",
            "movi v6.2d, #0",
            "movi v7.2d, #0",
            "movi v8.2d, #0",
            "movi v9.2d, #0",
            "movi v10.2d, #0",
            "movi v11.2d, #0",
            "movi v12.2d, #0",
            "movi v13.2d, #0",
            "movi v14.2d, #0",
            "movi v15.2d, #0",
            "movi v16.2d, #0",
            "movi v17.2d, #0",
            "movi v18.2d, #0",
            "movi v19.2d, #0",
            "movi v20.2d, #0",
            "movi v21.2d, #0",
            "movi v22.2d, #0",
            "movi v23.2d, #0",
            "movi v24.2d, #0",
            "movi v25.2d, #0",
            "movi v26.2d, #0",
            "movi v27.2d, #0",
            "movi v28.2d, #0",
            "movi v29.2d, #0",
            "movi v30.2d, #0",
            "movi v31.2d, #0",
            "eret",
            // ---- fluxor_el0_resume(cb=x0, outcome=w1) ----
            // Restore the kernel regime + callee-saved and RET to call().
            "fluxor_el0_resume:",
            "str   wzr, [x0, #144]", // active = 0
            "str   w1,  [x0, #152]", // outcome (diagnostic)
            "ldr   x9,  [x0, #16]",  // kernel_ttbr0
            "msr   ttbr0_el1, x9",
            "isb",
            "ldr   x9,  [x0, #24]", // kernel_daif
            "msr   daif, x9",
            "ldp   x19, x20, [x0, #32]",
            "ldp   x21, x22, [x0, #48]",
            "ldp   x23, x24, [x0, #64]",
            "ldp   x25, x26, [x0, #80]",
            "ldp   x27, x28, [x0, #96]",
            "ldr   x29, [x0, #112]",
            "ldr   q8,  [x0, #160]",
            "ldr   q9,  [x0, #176]",
            "ldr   q10, [x0, #192]",
            "ldr   q11, [x0, #208]",
            "ldr   q12, [x0, #224]",
            "ldr   q13, [x0, #240]",
            "ldr   q14, [x0, #256]",
            "ldr   q15, [x0, #272]",
            "ldr   x30, [x0, #8]", // kernel_lr
            "ldr   x9,  [x0, #0]", // kernel_sp
            "mov   sp, x9",
            "mov   w0, w1", // return outcome
            "ret",
            // ---- fluxor_el0_lower_sync_vec ----
            // A synchronous exception from EL0: a veneer's SVC, or an abort.
            // x9-x16 are scratch here (caller-saved across any veneer call).
            "fluxor_el0_lower_sync_vec:",
            "mov   x9, x0", // the module's x0 (outcome, or a gateway arg)
            "mrs   x10, mpidr_el1",
            "lsr   x10, x10, #8",
            "and   x10, x10, #3", // core id (Pi 5: MPIDR Aff1)
            "adrp  x11, EL0_CBS",
            "add   x11, x11, #:lo12:EL0_CBS",
            "mov   x12, #384",          // CB_SIZE
            "madd  x11, x10, x12, x11", // x11 = &EL0_CBS[core]
            "ldr   w13, [x11, #144]",   // active
            "cbz   w13, fluxor_el0_inactive",
            "mrs   x14, esr_el1",
            "lsr   x15, x14, #26", // EC
            "cmp   x15, #0x15",    // SVC from AArch64
            "b.eq  fluxor_el0_svc",
            // ---- abort: record ESR/FAR/ELR, resume with EFAULT (-14) ----
            "str   x14, [x11, #120]", // fault_esr
            "mrs   x16, far_el1",
            "str   x16, [x11, #128]", // fault_far
            "mrs   x16, elr_el1",
            "str   x16, [x11, #136]", // fault_elr
            "mov   w16, #1",
            "str   w16, [x11, #148]", // fault_pending = 1 (abort)
            "mov   x0, x11",
            "movn  w1, #13", // outcome = -14 (EFAULT)
            "b     fluxor_el0_resume",
            // An SVC is honoured only from its own veneer: ELR must be the
            // instruction after `svc #imm` in the trampoline page, and imm a
            // gateway op or the return. Anything else is a protection fault.
            "fluxor_el0_svc:",
            "and   x16, x14, #0xffff", // imm16 (ESR ISS)
            "cmp   x16, #{ret_op}",
            "b.hi  fluxor_el0_badsvc",
            "adrp  x15, FLUXOR_EL0_TRAMP",
            "add   x15, x15, #:lo12:FLUXOR_EL0_TRAMP",
            "add   x15, x15, x16, lsl #3",
            "add   x15, x15, #4",
            "mrs   x13, elr_el1",
            "cmp   x13, x15",
            "b.ne  fluxor_el0_badsvc",
            "cmp   x16, #{ret_op}",
            "b.ne  fluxor_el0_svc_gate",
            // The return veneer: the entry point returned; x0 is its result.
            "mov   x0, x11",
            "mov   w1, w9",
            "b     fluxor_el0_resume",
            // A gateway op: serve it under the kernel's own table with IRQs
            // open, then return to the veneer's `ret`. The module's x19-x29
            // and d8-d15 survive the C call; x18 and x30 are saved here, and
            // ELR/SPSR in the control block because an IRQ taken while the
            // kernel works overwrites them.
            "fluxor_el0_svc_gate:",
            "str   x18, [x11, #312]",
            "str   x30, [x11, #320]",
            "str   x13, [x11, #296]", // ELR
            "mrs   x13, spsr_el1",
            "str   x13, [x11, #304]",
            "ldr   x13, [x11, #16]", // kernel_ttbr0
            "msr   ttbr0_el1, x13",
            "isb",
            // fluxor_gateway_el0(module_idx, op, a0..a5)
            "mov   x7, x5",
            "mov   x6, x4",
            "mov   x5, x3",
            "mov   x4, x2",
            "mov   x3, x1",
            "mov   x2, x9",
            "mov   x1, x16",
            "ldr   w0, [x11, #156]",
            "msr   daifclr, #2",
            "bl    fluxor_gateway_el0",
            "msr   daifset, #2",
            // The deadline may have passed while the kernel served the op:
            // an interrupt taken at EL1 could not force the module out, so
            // the check the EL0 IRQ path makes is made here before it can
            // resume.
            "str   x0, [sp, #-16]!",
            "bl    fluxor_el0_irq_preempt",
            "mov   x9, x0",
            "ldr   x0, [sp], #16",
            "mrs   x10, mpidr_el1",
            "lsr   x10, x10, #8",
            "and   x10, x10, #3", // core id (Pi 5: MPIDR Aff1)
            "adrp  x11, EL0_CBS",
            "add   x11, x11, #:lo12:EL0_CBS",
            "mov   x12, #384",          // CB_SIZE
            "madd  x11, x10, x12, x11", // x11 = &EL0_CBS[core]
            "cbnz  w9, fluxor_el0_gate_forced",
            "ldr   x13, [x11, #296]",
            "msr   elr_el1, x13",
            "ldr   x13, [x11, #304]",
            "msr   spsr_el1, x13",
            "ldr   x13, [x11, #288]", // module_ttbr0
            "msr   ttbr0_el1, x13",
            "isb",
            "ldr   x18, [x11, #312]",
            "ldr   x30, [x11, #320]",
            // Scrub what the kernel left in caller-saved registers; x0 is the
            // result. v8-v15 keep their low halves (the module's, preserved by
            // the C ABI) and lose their upper halves (not preserved).
            "mov x1, xzr",
            "mov x2, xzr",
            "mov x3, xzr",
            "mov x4, xzr",
            "mov x5, xzr",
            "mov x6, xzr",
            "mov x7, xzr",
            "mov x8, xzr",
            "mov x9, xzr",
            "mov x10, xzr",
            "mov x11, xzr",
            "mov x12, xzr",
            "mov x13, xzr",
            "mov x14, xzr",
            "mov x15, xzr",
            "mov x16, xzr",
            "mov x17, xzr",
            "mov v8.d[1], xzr",
            "mov v9.d[1], xzr",
            "mov v10.d[1], xzr",
            "mov v11.d[1], xzr",
            "mov v12.d[1], xzr",
            "mov v13.d[1], xzr",
            "mov v14.d[1], xzr",
            "mov v15.d[1], xzr",
            "movi v0.2d, #0",
            "movi v1.2d, #0",
            "movi v2.2d, #0",
            "movi v3.2d, #0",
            "movi v4.2d, #0",
            "movi v5.2d, #0",
            "movi v6.2d, #0",
            "movi v7.2d, #0",
            "movi v16.2d, #0",
            "movi v17.2d, #0",
            "movi v18.2d, #0",
            "movi v19.2d, #0",
            "movi v20.2d, #0",
            "movi v21.2d, #0",
            "movi v22.2d, #0",
            "movi v23.2d, #0",
            "movi v24.2d, #0",
            "movi v25.2d, #0",
            "movi v26.2d, #0",
            "movi v27.2d, #0",
            "movi v28.2d, #0",
            "movi v29.2d, #0",
            "movi v30.2d, #0",
            "movi v31.2d, #0",
            "eret",
            "fluxor_el0_badsvc:",
            "mov   w16, #2",
            "str   w16, [x11, #148]", // fault_pending = 2 (bad svc)
            "str   x14, [x11, #120]", // fault_esr
            "mrs   x16, elr_el1",
            "str   x16, [x11, #136]", // fault_elr
            "mov   x0, x11",
            "movn  w1, #21", // outcome = -22 (EINVAL)
            "b     fluxor_el0_resume",
            // Past its deadline during a gateway op: record where it was and
            // resume the kernel as if the entry had faulted; the kernel's
            // table is already live.
            "fluxor_el0_gate_forced:",
            "ldr   x16, [x11, #296]", // the module's ELR
            "str   x16, [x11, #136]", // fault_elr
            "mov   w16, #3",
            "str   w16, [x11, #148]", // fault_pending = 3 (deadline)
            "mov   x0, x11",
            "movn  w1, #109", // outcome = -110 (ETIMEDOUT)
            "b     fluxor_el0_resume",
            "fluxor_el0_inactive:",
            "b     unhandled_exception",
            // ---- fluxor_el0_lower_irq_vec ----
            // An IRQ taken at EL0. Save the module's whole register file on
            // the kernel stack, serve the interrupt under the kernel's table,
            // then either resume the module or — past its deadline — force it
            // out through `resume`, discarding its frame.
            "fluxor_el0_lower_irq_vec:",
            "sub   sp, sp, #720",
            "stp   x0, x1,   [sp, #0]",
            "stp   x2, x3,   [sp, #16]",
            "stp   x4, x5,   [sp, #32]",
            "stp   x6, x7,   [sp, #48]",
            "stp   x8, x9,   [sp, #64]",
            "stp   x10, x11, [sp, #80]",
            "stp   x12, x13, [sp, #96]",
            "stp   x14, x15, [sp, #112]",
            "stp   x16, x17, [sp, #128]",
            "stp   x18, x29, [sp, #144]",
            "str   x30,      [sp, #160]",
            "mrs   x0, elr_el1",
            "mrs   x1, spsr_el1",
            "stp   x0, x1,   [sp, #176]",
            "mrs   x0, ttbr0_el1",
            "str   x0,       [sp, #192]",
            "stp q0, q1, [sp, #208]",
            "stp q2, q3, [sp, #240]",
            "stp q4, q5, [sp, #272]",
            "stp q6, q7, [sp, #304]",
            "stp q8, q9, [sp, #336]",
            "stp q10, q11, [sp, #368]",
            "stp q12, q13, [sp, #400]",
            "stp q14, q15, [sp, #432]",
            "stp q16, q17, [sp, #464]",
            "stp q18, q19, [sp, #496]",
            "stp q20, q21, [sp, #528]",
            "stp q22, q23, [sp, #560]",
            "stp q24, q25, [sp, #592]",
            "stp q26, q27, [sp, #624]",
            "stp q28, q29, [sp, #656]",
            "stp q30, q31, [sp, #688]",
            "mrs   x10, mpidr_el1",
            "lsr   x10, x10, #8",
            "and   x10, x10, #3", // core id (Pi 5: MPIDR Aff1)
            "adrp  x11, EL0_CBS",
            "add   x11, x11, #:lo12:EL0_CBS",
            "mov   x12, #384",          // CB_SIZE
            "madd  x11, x10, x12, x11", // x11 = &EL0_CBS[core]
            "ldr   x0, [x11, #16]", // kernel_ttbr0
            "msr   ttbr0_el1, x0",
            "isb",
            "bl    irq_handler",
            "bl    fluxor_el0_irq_preempt",
            "cbnz  w0, 2f",
            "ldr   x0, [sp, #192]",
            "msr   ttbr0_el1, x0",
            "isb",
            "ldp   x0, x1, [sp, #176]",
            "msr   elr_el1, x0",
            "msr   spsr_el1, x1",
            "ldp q0, q1, [sp, #208]",
            "ldp q2, q3, [sp, #240]",
            "ldp q4, q5, [sp, #272]",
            "ldp q6, q7, [sp, #304]",
            "ldp q8, q9, [sp, #336]",
            "ldp q10, q11, [sp, #368]",
            "ldp q12, q13, [sp, #400]",
            "ldp q14, q15, [sp, #432]",
            "ldp q16, q17, [sp, #464]",
            "ldp q18, q19, [sp, #496]",
            "ldp q20, q21, [sp, #528]",
            "ldp q22, q23, [sp, #560]",
            "ldp q24, q25, [sp, #592]",
            "ldp q26, q27, [sp, #624]",
            "ldp q28, q29, [sp, #656]",
            "ldp q30, q31, [sp, #688]",
            "ldp   x0, x1,   [sp, #0]",
            "ldp   x2, x3,   [sp, #16]",
            "ldp   x4, x5,   [sp, #32]",
            "ldp   x6, x7,   [sp, #48]",
            "ldp   x8, x9,   [sp, #64]",
            "ldp   x10, x11, [sp, #80]",
            "ldp   x12, x13, [sp, #96]",
            "ldp   x14, x15, [sp, #112]",
            "ldp   x16, x17, [sp, #128]",
            "ldp   x18, x29, [sp, #144]",
            "ldr   x30,      [sp, #160]",
            "add   sp, sp, #720",
            "eret",
            // Past its deadline: record where it was, discard the frame, and
            // resume the kernel as if the entry had faulted.
            "2:",
            "ldr   x16, [sp, #176]", // the module's ELR
            "add   sp, sp, #720",
            "mrs   x10, mpidr_el1",
            "lsr   x10, x10, #8",
            "and   x10, x10, #3", // core id (Pi 5: MPIDR Aff1)
            "adrp  x11, EL0_CBS",
            "add   x11, x11, #:lo12:EL0_CBS",
            "mov   x12, #384",          // CB_SIZE
            "madd  x11, x10, x12, x11", // x11 = &EL0_CBS[core]
            "str   x16, [x11, #136]", // fault_elr
            "mov   w16, #3",
            "str   w16, [x11, #148]", // fault_pending = 3 (deadline)
            "mov   x0, x11",
            "movn  w1, #109", // outcome = -110 (ETIMEDOUT)
            "b     fluxor_el0_resume",
            // ---- fluxor_el1_catch (reason in w17) ----
            // Catch for the EL1 + lower-EL-async exception vectors. A genuine EL0
            // module fault arrives at the lower-EL SYNCHRONOUS vector
            // (`fluxor_el0_lower_sync_vec`) and is recovered by faulting the
            // module; anything reaching HERE is a kernel-side fault (e.g. inside
            // `el0_syscall_dispatch` while it holds the channel spinlock) or an
            // async exception (IRQs are masked across an EL0 step, so these
            // should not fire). Recovering from a kernel-side fault could abandon
            // a held lock and deadlock, so we FAIL STOP: hand to
            // `unhandled_exception`, which latches ESR/FAR/SPSR/ELR into the
            // per-core `CORE_FAULT_*` cells (surfaced over UDP by a sibling core)
            // and spins diagnosably.
            // Each vector slot does `mov w17,#reason; b fluxor_el1_catch`.
            //   reason: 3=EL1h sync, 4=EL1h SError, 5=EL1t sync, 6=EL1t IRQ,
            //   7=EL1t FIQ, 8=EL1t SError, 9=EL1h FIQ, 10=lowerEL IRQ,
            //   11=lowerEL FIQ, 12=lowerEL SError.
            ".global fluxor_el1_catch",
            ".global fluxor_el1_sync_vec",
            "fluxor_el1_sync_vec:", // named entry for the EL1h sync slot
            "mov   w17, #3",
            "fluxor_el1_catch:",
            // Regardless of whether an EL0 step is active, this is a kernel-side
            // or async fault that must not be silently recovered. Dump + spin
            // (latches CORE_FAULT_* for sibling-core UDP surfacing).
            //
            // The dump runs on this core's fault stack, not the interrupted
            // SP: the fault may BE a kernel stack overflow into its guard page,
            // and pushing a frame onto that stack would fault again, forever.
            // Nothing returns from here, so the switch is unconditional.
            // SP_top = EL1_FAULT_STACKS + (Aff1 + 1) * EL1_FAULT_STACK_BYTES.
            "adrp  x16, EL1_FAULT_STACKS",
            "add   x16, x16, :lo12:EL1_FAULT_STACKS",
            "mov   sp, x16",
            "mrs   x16, mpidr_el1",
            "ubfx  x16, x16, #8, #8",
            "and   x16, x16, #3",
            "add   x16, x16, #1",
            "lsl   x16, x16, #13",
            "add   sp, sp, x16",
            "b     unhandled_exception",
            ret_op = const RETURN_OP,
        );
    }
}

// ============================================================================
// Public API (platform-dispatched)
// ============================================================================

/// Initialize MMU isolation (BCM2712 only).
pub fn init() {
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_impl::mmu_init();
}

/// Register an isolated module's code/state/heap and build its EL0 page
/// table, before any of its code runs. `false` fails its load closed.
pub fn register_module(
    module_idx: usize,
    code_base: u64,
    code_size: u64,
    state_ptr: *mut u8,
    state_size: usize,
    heap_ptr: *mut u8,
    heap_size: usize,
) -> bool {
    #[cfg(feature = "chip-bcm2712")]
    {
        bcm2712_impl::register_module_regions(
            module_idx, code_base, code_size, state_ptr, state_size, heap_ptr, heap_size,
        );
        bcm2712_impl::el0::build_table(module_idx)
    }
    #[cfg(not(feature = "chip-bcm2712"))]
    {
        let _ = (
            module_idx, code_base, code_size, state_ptr, state_size, heap_ptr, heap_size,
        );
        false
    }
}

/// Release an isolated module's slot at teardown.
pub fn release_module(module_idx: usize) {
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_impl::el0::release(module_idx);
    let _ = module_idx;
}

/// The gateway `SyscallTable` an isolated module is handed.
pub fn gateway_table() -> *const crate::abi::SyscallTable {
    #[cfg(feature = "chip-bcm2712")]
    return bcm2712_impl::el0::gateway_table();
    #[cfg(not(feature = "chip-bcm2712"))]
    core::ptr::null()
}

/// Whether `module_idx` has a built EL0-isolation page table.
pub fn is_isolated(module_idx: usize) -> bool {
    #[cfg(feature = "chip-bcm2712")]
    return bcm2712_impl::el0::is_isolated(module_idx);
    #[cfg(not(feature = "chip-bcm2712"))]
    {
        let _ = module_idx;
        false
    }
}

/// Reset all EL0-isolation bookkeeping (called from `prepare_graph` so a
/// graph reconfigure rebuilds isolated tables from scratch).
pub fn reset_isolation() {
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_impl::el0::reset();
}

/// Call one entry point of an isolated module at EL0 (the HAL's
/// `protected_call`). A module with no built table fails closed; it is never
/// run at EL1.
///
/// # Safety
/// `entry` is a validated export of `module_idx` taking `args`; the caller
/// runs on the module's owning core.
pub unsafe fn protected_call(
    module_idx: usize,
    entry: usize,
    args: &[usize; 8],
    params: &[u8],
    deadline_us: u32,
) -> i32 {
    #[cfg(feature = "chip-bcm2712")]
    return bcm2712_impl::el0::call(module_idx, entry, args, params, deadline_us);
    #[cfg(not(feature = "chip-bcm2712"))]
    {
        let _ = (module_idx, entry, args, params, deadline_us);
        -14
    }
}

/// Check if MMU isolation is enabled.
pub fn is_enabled() -> bool {
    #[cfg(feature = "chip-bcm2712")]
    return bcm2712_impl::is_enabled();
    #[cfg(not(feature = "chip-bcm2712"))]
    false
}

/// Enable or disable MMU isolation.
pub fn set_enabled(enabled: bool) {
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_impl::set_enabled(enabled);
    let _ = enabled;
}

/// Handle a data abort from module context (called from exception vector).
///
/// # Safety
/// Must only be invoked from the EL1 synchronous-exception vector while the
/// faulting module's translation regime (TTBR0_EL1, ASID, MAIR) is still
/// installed. Reads `FAR_EL1`/`ESR_EL1` of the live exception frame and may
/// touch the current module's paged-arena L3 tables, so the scheduler's
/// `current_module_index()` must still identify the faulting module.
pub unsafe fn handle_data_abort() {
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_impl::handle_data_abort();
}

/// Set up paged arena L3 tables for a module (BCM2712 only).
pub fn setup_paged_arena(module_idx: usize, base_va: u64, size: u64) {
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_impl::setup_paged_arena(module_idx, base_va, size);
    let _ = (module_idx, base_va, size);
}

/// Map a 4KB page in a module's paged arena.
pub fn map_4k_page(module_idx: usize, vaddr: u64, phys: u64, writable: bool) {
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_impl::map_4k_page_impl(module_idx, vaddr, phys, writable);
    let _ = (module_idx, vaddr, phys, writable);
}

/// Unmap a 4KB page in a module's paged arena.
pub fn unmap_4k_page(module_idx: usize, vaddr: u64) {
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_impl::unmap_4k_page_impl(module_idx, vaddr);
    let _ = (module_idx, vaddr);
}
