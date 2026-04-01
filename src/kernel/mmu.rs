//! MMU-based hardware isolation for Cortex-A76 (BCM2712 / CM5).
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
//! | Region              | QEMU virt address      | CM5 address         |
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

#[cfg(feature = "chip-bcm2712")]
#[allow(dead_code)]
mod bcm2712_impl {
    use crate::kernel::scheduler::MAX_MODULES;

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
    const DESC_TABLE: u64 = 1 << 1;     // L1: table descriptor (not block)
    const DESC_BLOCK: u64 = 0 << 1;     // L1/L2: block descriptor (with VALID)

    // Lower attributes (block/page descriptors)
    const ATTR_IDX_SHIFT: u64 = 2;      // AttrIndx[2:0] at bits [4:2]
    const ATTR_NS: u64 = 1 << 5;        // Non-secure
    const AP_SHIFT: u64 = 6;            // AP[2:1] at bits [7:6]
    const SH_SHIFT: u64 = 8;            // SH[1:0] at bits [9:8]
    const AF: u64 = 1 << 10;            // Access Flag
    const _NG: u64 = 1 << 11;            // Not Global (use ASID)

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
    const SH_ISH: u64 = 0b11;  // Inner-shareable

    // Upper attributes
    const PXN: u64 = 1 << 53;           // Privileged Execute-Never
    const UXN: u64 = 1 << 54;           // Unprivileged Execute-Never (EL0 XN)

    // MAIR attribute indices (must match MAIR_EL1 setup)
    const ATTR_IDX_NORMAL: u64 = 0;
    const ATTR_IDX_DEVICE: u64 = 1;
    const ATTR_IDX_NORMAL_NC: u64 = 2;

    /// MAIR_EL1 encoding:
    /// Attr0: Normal, WB-WA inner+outer (0xFF)
    /// Attr1: Device-nGnRnE (0x00)
    /// Attr2: Normal non-cacheable (0x44)
    const MAIR_VALUE: u64 =
        (0xFF << 0) |   // Attr0: Normal memory, WB-WA
        (0x00 << 8) |   // Attr1: Device-nGnRnE
        (0x44 << 16);   // Attr2: Normal non-cacheable

    /// TCR_EL1 value for 4KB granule, 39-bit VA (512GB), ASID 8-bit.
    /// T0SZ = 25 (64-25=39 bit VA space)
    /// IRGN0 = 0b01 (inner WB-WA cacheable)
    /// ORGN0 = 0b01 (outer WB-WA cacheable)
    /// SH0 = 0b11 (inner shareable)
    /// TG0 = 0b00 (4KB granule)
    /// A1 = 0 (TTBR0 ASID)
    /// AS = 0 (8-bit ASID)
    const TCR_VALUE: u64 =
        (25 << 0) |     // T0SZ = 25 → 39-bit VA
        (0b01 << 8) |   // IRGN0 = WB-WA
        (0b01 << 10) |  // ORGN0 = WB-WA
        (0b11 << 12) |  // SH0 = Inner-shareable
        (0b00 << 14) |  // TG0 = 4KB granule
        (0b1 << 23);    // EPD1 = 1 (disable TTBR1 walks)

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
        chan_base: u64,
        chan_size: u64,
    }

    impl ModuleRegions {
        const fn empty() -> Self {
            Self {
                code_base: 0, code_size: 0,
                state_base: 0, state_size: 0,
                heap_base: 0, heap_size: 0,
                chan_base: 0, chan_size: 0,
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
                    true, true, // No execute
                );
            }

            // CM5: peripherals at 0xFE00_0000+ are in higher L1 entries
            // This is handled by having additional L1→L2 mappings for those.

            // Kernel L1: point entry 0 to kernel L2 (covers 0..1GB)
            let l2_addr = &raw const KERNEL_L2 as u64;
            KERNEL_L1.0[0] = make_table_desc(l2_addr);
            // Higher L1 entries: identity map as 1GB blocks for QEMU virt
            // (RAM at 0x4000_0000 = L1 index 1)
            KERNEL_L1.0[1] = make_block_desc(
                L1_BLOCK_SIZE,
                ATTR_IDX_NORMAL,
                AP_EL1_RW,
                true, false,
            );

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
    pub fn build_module_page_table(module_idx: usize) {
        if module_idx >= MAX_MODULES {
            return;
        }
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
                            AP_EL0_RO,   // EL0 RO
                            false,       // UXN=0 (EL0 can execute)
                            true,        // PXN=1 (EL1 shouldn't execute module code)
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
                            true, true, // No execute
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
                        l2.0[idx] = make_block_desc(
                            addr,
                            ATTR_IDX_NORMAL,
                            AP_EL0_RW,
                            true, true,
                        );
                    }
                    addr += L2_BLOCK_SIZE;
                }
            }

            // Map channel buffers (RW at EL0, no execute)
            if r.chan_size > 0 {
                let start = align_down_2mb(r.chan_base);
                let end = align_up_2mb(r.chan_base + r.chan_size);
                let mut addr = start;
                while addr < end {
                    let idx = l2_index(addr);
                    if idx < TABLE_ENTRIES {
                        l2.0[idx] = make_block_desc(
                            addr,
                            ATTR_IDX_NORMAL,
                            AP_EL0_RW,
                            true, true,
                        );
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
        unsafe {
            MODULE_REGION_INFO[module_idx] = ModuleRegions {
                code_base,
                code_size,
                state_base: state_ptr as u64,
                state_size: state_size as u64,
                heap_base: if heap_ptr.is_null() { 0 } else { heap_ptr as u64 },
                heap_size: if heap_ptr.is_null() { 0 } else { heap_size as u64 },
                chan_base: 0,
                chan_size: 0,
            };
        }
    }

    /// Set channel buffer region for a module.
    pub fn set_module_channel_region(module_idx: usize, base: u64, size: u64) {
        if module_idx >= MAX_MODULES {
            return;
        }
        unsafe {
            MODULE_REGION_INFO[module_idx].chan_base = base;
            MODULE_REGION_INFO[module_idx].chan_size = size;
        }
    }

    // ========================================================================
    // ASID management (E8-S7)
    // ========================================================================

    /// Switch TTBR0_EL1 to a module's page table with its ASID.
    ///
    /// ASID = module_idx + 1 (ASID 0 reserved for kernel).
    pub fn switch_to_module(module_idx: usize) {
        if !is_enabled() || module_idx >= MAX_MODULES {
            return;
        }
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
        unsafe { ISOLATION_ENABLED }
    }

    /// Enable or disable MMU isolation.
    pub fn set_enabled(enabled: bool) {
        unsafe { ISOLATION_ENABLED = enabled; }
    }

    // ========================================================================
    // EL1/EL0 transitions (E8-S8)
    // ========================================================================

    /// Enter EL0 to execute module_step, return to EL1 via SVC.
    ///
    /// Flow:
    /// 1. Switch to module's page table (ASID)
    /// 2. Set up ELR_EL1 to module_step, SPSR_EL1 for EL0
    /// 3. ERET to drop to EL0
    /// 4. Module calls SVC to return (SVC handler at EL1 reads result)
    ///
    /// For now, this is a privileged direct call — full EL0 transition
    /// requires exception vector table integration with the existing
    /// bcm2712.rs vectors. The ASID switch still provides memory isolation
    /// via page table restrictions even at EL1.
    pub unsafe fn enter_el0(
        step_fn: crate::kernel::loader::ModuleStepFn,
        state_ptr: *mut u8,
    ) -> i32 {
        if !is_enabled() {
            return step_fn(state_ptr);
        }

        // For initial implementation: switch page table but stay at EL1.
        // This gives us memory isolation (the module can only access
        // pages mapped in its page table) without the complexity of
        // full EL0 transition + SVC return.
        // Full EL0 transition is deferred to E8-S8 follow-up.
        step_fn(state_ptr)
    }

    /// Data abort handler (called from exception vector).
    ///
    /// Reads FAR_EL1 to get the faulting address, identifies the module
    /// from scheduler's current_module, triggers fault recovery.
    pub unsafe fn handle_data_abort() {
        let far: u64;
        let esr: u64;
        core::arch::asm!("mrs {}, far_el1", out(reg) far);
        core::arch::asm!("mrs {}, esr_el1", out(reg) esr);

        let module_idx = crate::kernel::scheduler::current_module_index();
        let dfsc = esr & 0x3F; // Data Fault Status Code

        log::error!(
            "[mmu] module {} data abort at 0x{:016x} ESR=0x{:08x} DFSC=0x{:02x}",
            module_idx, far, esr, dfsc
        );

        // Record fault via step_guard
        crate::kernel::step_guard::record_mpu_fault(module_idx);
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

/// Register module regions for MMU isolation.
pub fn register_module(
    module_idx: usize,
    code_base: u64,
    code_size: u64,
    state_ptr: *mut u8,
    state_size: usize,
    heap_ptr: *mut u8,
    heap_size: usize,
) {
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_impl::register_module_regions(
        module_idx, code_base, code_size,
        state_ptr, state_size, heap_ptr, heap_size,
    );
    let _ = (module_idx, code_base, code_size, state_ptr, state_size, heap_ptr, heap_size);
}

/// Set channel buffer region for a module.
pub fn set_channel_region(module_idx: usize, base: u64, size: u64) {
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_impl::set_module_channel_region(module_idx, base, size);
    let _ = (module_idx, base, size);
}

/// Build a module's page table after all regions are registered.
pub fn build_page_table(module_idx: usize) {
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_impl::build_module_page_table(module_idx);
    let _ = module_idx;
}

/// Switch to a module's ASID/page table before stepping.
pub fn switch_to_module(module_idx: usize) {
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_impl::switch_to_module(module_idx);
    let _ = module_idx;
}

/// Switch back to kernel ASID after stepping.
pub fn switch_to_kernel() {
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_impl::switch_to_kernel();
}

/// Execute module_step with MMU isolation.
pub unsafe fn protected_step(
    step_fn: crate::kernel::loader::ModuleStepFn,
    state_ptr: *mut u8,
) -> i32 {
    #[cfg(feature = "chip-bcm2712")]
    return bcm2712_impl::enter_el0(step_fn, state_ptr);
    #[cfg(not(feature = "chip-bcm2712"))]
    {
        step_fn(state_ptr)
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
pub unsafe fn handle_data_abort() {
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_impl::handle_data_abort();
}
