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
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
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
        chan_base: u64,
        chan_size: u64,
        /// The ONLY channel handles this module may name in an `SVC #1`
        /// channel syscall: `[in_chan, out_chan, ctrl_chan]` exactly as
        /// passed to `module_new`. Any other handle is rejected by the
        /// gateway (`el0_chan_ok`) so an isolated module can't enumerate
        /// and read/write unrelated graph edges. `-1` = unused slot
        /// (never matches, since a valid handle is `>= 0`).
        chans: [i32; 3],
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
                chan_base: 0,
                chan_size: 0,
                chans: [-1, -1, -1],
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

            // CM5: peripherals at 0xFE00_0000+ are in higher L1 entries
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

            // Map channel buffers (RW at EL0, no execute)
            if r.chan_size > 0 {
                let start = align_down_2mb(r.chan_base);
                let end = align_up_2mb(r.chan_base + r.chan_size);
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
            // PRESERVE the channel region (chan_base/chan_size/chans). The
            // channel-buffer range is computed and registered during graph
            // preparation (`scheduler::prepare_graph` → `set_channel_region`),
            // which runs BEFORE instantiation. Overwriting the whole record here
            // with chan_base=0 would erase it, leaving the lazily-built EL0 table
            // without the module's channel pages (so its mediated channel I/O
            // would EFAULT). `reset_module_regions` clears the chan fields per
            // graph, so nothing stale from a prior graph survives. (`chans` is
            // re-set right after by `set_module_channels`; preserving it here is
            // harmless.)
            let prev = MODULE_REGION_INFO[module_idx];
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
                chan_base: prev.chan_base,
                chan_size: prev.chan_size,
                chans: prev.chans,
            };
        }
    }

    /// Set channel buffer region for a module.
    pub fn set_module_channel_region(module_idx: usize, base: u64, size: u64) {
        if module_idx >= MAX_MODULES {
            return;
        }
        // SAFETY: per-module write; module_idx bounded.
        unsafe {
            MODULE_REGION_INFO[module_idx].chan_base = base;
            MODULE_REGION_INFO[module_idx].chan_size = size;
        }
    }

    /// Record the channel handles an isolated module is permitted to name in
    /// its `SVC #1` gateway calls — exactly the `[in, out, ctrl]` it received
    /// from `module_new`. The gateway rejects any other handle.
    pub fn set_module_channels(module_idx: usize, in_chan: i32, out_chan: i32, ctrl_chan: i32) {
        if module_idx >= MAX_MODULES {
            return;
        }
        // SAFETY: per-module write during instantiation; module_idx bounded.
        unsafe {
            MODULE_REGION_INFO[module_idx].chans = [in_chan, out_chan, ctrl_chan];
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
    /// See [`super::protected_step`]. `step_fn`/`state_ptr` must be the
    /// genuine export/state of the currently-stepping module.
    /// Fault code returned when a declared-isolated module has no usable EL0
    /// table. Mapped to `Err` by `DynamicModule::step`, driving the scheduler's
    /// fault path (skip/restart/restart-graph) — never an EL1 execution.
    const EL0_FAIL_CLOSED: i32 = -14; // EFAULT

    pub unsafe fn enter_el0(
        step_fn: crate::kernel::loader::ModuleStepFn,
        state_ptr: *mut u8,
    ) -> i32 {
        let idx = crate::kernel::scheduler::current_module_index();
        if is_enabled() {
            // The loader only routes here for a module that declared
            // `protection: isolated`. If its isolated page table isn't built
            // yet, build it now (lazily). The prepare-graph build pass can run
            // before a module's protection flag + regions are registered (graph
            // shape dependent), leaving `is_isolated` false at first step;
            // without this, the module would run at EL1 where its `svc #N`
            // gateway is illegal and traps. Regions are registered by the first
            // step, so the build succeeds here. One-shot per module: once built,
            // `is_isolated` is true and this is skipped.
            if !el0::is_isolated(idx) {
                let built = el0::build_table(idx);
                let (slot, _b, next, cs, ss, _ch) = el0::diag(idx);
                log::info!(
                    "[el0] lazy build_table idx={idx} ok={built} slot={slot} next={next} \
                     code_sz={cs} state_sz={ss}"
                );
            }
            if el0::is_isolated(idx) {
                // SAFETY: idx is the live current module; its isolated page
                // table is now built. step_fn is the module's real export.
                return unsafe { el0::enter(idx, step_fn, state_ptr) };
            }
        }
        // FAIL CLOSED. We only reach here for a module that DECLARED
        // `protection: isolated` (the loader routes only those through
        // `protected_step`), yet it has no usable EL0 page table — isolation
        // is globally disabled, no isolated slot was free, or its regions are
        // unusable. Running its `module_step` at EL1 would silently elevate a
        // module the author asked to sandbox (and its `svc #N` gateway calls
        // would trap there anyway). Refuse: return a fault so the scheduler
        // applies the module's fault policy (skip/restart/restart-graph)
        // instead of executing it privileged. The module's code NEVER runs at
        // EL1. Rate-limited diagnostic, visible over UDP.
        {
            use core::sync::atomic::{AtomicU32, Ordering as O};
            static FT: AtomicU32 = AtomicU32::new(0);
            let n = FT.fetch_add(1, O::Relaxed);
            // A fail-closed module is fault-gated (terminated, or restarted with
            // backoff) — never stepped every tick — so logging the first 1000
            // occurrences can't flood; then fall back to a coarse rate limit.
            if n < 1000 || n.is_multiple_of(50_000) {
                let (slot, built, next, cs, ss, chs) = el0::diag(idx);
                log::error!(
                    "[el0] FAIL-CLOSED idx={idx} enabled={} isolated={} slot={slot} \
                     built={built} next_slot={next} code_sz={cs} state_sz={ss} chan_sz={chs} \
                     — isolated module NOT stepped (would run at EL1)",
                    is_enabled(),
                    el0::is_isolated(idx),
                );
            }
        }
        // -1 → `DynamicModule::step` maps non-{0,1,2} to `Err(code)`, driving
        // the scheduler's fault path. The module is never executed here.
        EL0_FAIL_CLOSED
    }

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

        let module_idx = crate::kernel::scheduler::current_module_index();
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
        crate::kernel::step_guard::record_mpu_fault(module_idx);
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
    // Scope / known limits (see docs/architecture/cm5_el0_isolation.md):
    //   * IRQs are masked during the EL0 step (SPSR DAIF). A runaway EL0
    //     loop that never faults and never returns would hang the owning
    //     core — bounding that needs an EL0 preemption timer (follow-up).
    //   * The walking-skeleton module must be syscall-free: it may touch
    //     only its own mapped regions. `SyscallTable` entries are direct
    //     EL1 kernel pointers and are NOT mapped/usable at EL0. A minimal
    //     SVC syscall gateway is a bounded follow-up.
    pub mod el0 {
        use super::{
            make_block_desc, make_page_desc, L3PageTable, PageTable, AP_EL0_RO, AP_EL0_RW,
            AP_EL1_RW, ATTR_IDX_DEVICE, ATTR_IDX_NORMAL, DESC_TABLE, DESC_VALID, L1_BLOCK_SIZE,
            L2_BLOCK_SIZE, MODULE_REGION_INFO, TABLE_ENTRIES,
        };
        use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        /// Max modules that can be `protection: isolated` simultaneously.
        /// Bounds the per-module L1/L2/L3 + stack BSS footprint. A graph
        /// declaring more isolated modules than this logs and falls back
        /// to the EL1 direct path for the overflow (still functional, just
        /// not EL0-isolated).
        pub const MAX_ISO: usize = 2;
        /// Cores supported (matches scheduler MAX_DOMAINS / Pi 5 quad-core).
        const MAX_CORES: usize = 4;
        /// L3 tables per isolated module. Each maps one 2 MB window at 4 KB
        /// granularity; we need one per distinct 2 MB-aligned region window
        /// (code, state, heap, channel, stack, trampoline — each may span a
        /// couple of windows). 16 is comfortable headroom for a probe.
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
        const EL0_STACK_BYTES: u64 = 64 * 1024;
        /// Per-isolated-module stack slab: one guard page + the EL0 stack,
        /// 4 KB-aligned. Page 0 is left unmapped as the guard page; the stack
        /// occupies the pages immediately above it. Mapped at 4 KB granularity
        /// (`map_4k` carves it out of the kernel base), so it needs only page
        /// alignment; a 2 MB-aligned 2 MB slab would bloat firmware BSS by ~6 MB
        /// (2 slabs × 2 MB + 2 MB-alignment padding) for no benefit.
        const STACK_SLAB_BYTES: usize = 4096 + 64 * 1024; // guard page + EL0_STACK_BYTES

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
            fault_pending: u32, // 148  (0=none, 1=abort, 2=bad-svc)
            outcome: i32,       // 152
            module_idx: u32,    // 156  (for SVC #1 syscall pointer validation)
            // Callee-saved FP/SIMD (v8-v15) saved across the EL0 round-trip.
            // Per AAPCS64 v8-v15 are callee-saved, so `fluxor_el0_enter`/`resume`
            // — which the kernel calls like a function — must preserve them. The
            // round-trip clears v8-v15 at entry and the module clobbers them at
            // EL0, so without save+restore the kernel caller's live FP state is
            // corrupted. Full 128-bit lanes (str/ldr q) so upper halves are
            // preserved too. 16-byte-aligned offsets for `str q`/`ldr q`.
            saved_v8: [u64; 2],  // 160
            saved_v9: [u64; 2],  // 176
            saved_v10: [u64; 2], // 192
            saved_v11: [u64; 2], // 208
            saved_v12: [u64; 2], // 224
            saved_v13: [u64; 2], // 240
            saved_v14: [u64; 2], // 256
            saved_v15: [u64; 2], // 272
            _pad: [u8; 32],      // 288 → pad to 320 (multiple of 64)
        }

        const CB_SIZE: usize = 320;

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
        };

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
                _pad: [0; 32],
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

        /// Dedicated trampoline page: `SVC #0; b .` Mapped RO+X at EL0 in
        /// every isolated module table so a returning `module_step` traps
        /// back to EL1 without exposing any kernel `.text`.
        #[repr(C, align(4096))]
        struct TrampPage([u32; 1024]);
        static mut TRAMP: TrampPage = {
            let mut p = [0u32; 1024];
            p[0] = 0xD400_0001; // SVC #0
            p[1] = 0x1400_0000; // b . (self — never reached; module returns via SVC)
            TrampPage(p)
        };
        static TRAMP_READY: AtomicBool = AtomicBool::new(false);

        /// Maps a scheduler module index → isolated-slot (0..MAX_ISO), or
        /// `usize::MAX` if not isolated. `ISO_BUILT[slot]` gates `enter`.
        static mut MOD_TO_SLOT: [usize; super::MAX_MODULES] = [usize::MAX; super::MAX_MODULES];
        static mut ISO_BUILT: [bool; MAX_ISO] = [false; MAX_ISO];
        /// Next free isolated slot. Atomic so a lazy `build_table` racing on
        /// two cores (concurrent first-steps of two isolated modules) reserves
        /// distinct slots via `fetch_add` rather than both reading the same
        /// index. `reset()` (single-threaded, in `prepare_graph`) stores 0.
        static ISO_NEXT_SLOT: AtomicUsize = AtomicUsize::new(0);
        /// Per-slot build lock: claimed for the duration of a slot's table
        /// build so a second core can't observe a half-built table. Indexed by
        /// slot; `false` = free/done, `true` = build in progress.
        static ISO_BUILDING: [AtomicBool; MAX_ISO] = [const { AtomicBool::new(false) }; MAX_ISO];
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
            let id = crate::kernel::hal::core_id();
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

        /// Diagnostic snapshot of a module's isolation bookkeeping:
        /// (slot, built, next_slot, code_size, state_size, chan_size).
        pub fn diag(module_idx: usize) -> (usize, bool, usize, u64, u64, u64) {
            if module_idx >= super::MAX_MODULES {
                return (usize::MAX, false, 0, 0, 0, 0);
            }
            // SAFETY: diagnostic reads of boot-populated statics.
            unsafe {
                let slot = MOD_TO_SLOT[module_idx];
                let built = slot < MAX_ISO && ISO_BUILT[slot];
                let r = MODULE_REGION_INFO[module_idx];
                let next = ISO_NEXT_SLOT.load(Ordering::Relaxed);
                (slot, built, next, r.code_size, r.state_size, r.chan_size)
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
                // Clear all per-module region records. `register_module_regions`
                // now PRESERVES the channel region (set during graph prep) across
                // instantiation, so the per-graph baseline must be cleared here —
                // otherwise a module that had channels in a prior graph but none
                // in this one would inherit a stale chan range. Code/state/heap
                // are re-set at instantiation; clearing is the safe default.
                let ri = core::ptr::addr_of_mut!(MODULE_REGION_INFO);
                for i in 0..super::MAX_MODULES {
                    (*ri)[i] = super::ModuleRegions::empty();
                }
                for building in ISO_BUILDING.iter() {
                    building.store(false, Ordering::Relaxed);
                }
                ISO_NEXT_SLOT.store(0, Ordering::Relaxed);
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

        /// One-time encode + I-cache publish of the trampoline page so the
        /// `SVC #0` we wrote as data is executable at EL0.
        unsafe fn ensure_trampoline() {
            if TRAMP_READY.swap(true, Ordering::AcqRel) {
                return;
            }
            let p = core::ptr::addr_of!(TRAMP) as u64;
            // Clean D-cache to PoU, invalidate I-cache for the two words,
            // then barrier so EL0 fetches see the instructions.
            core::arch::asm!(
                "dc cvau, {p}",
                "dsb ish",
                "ic ivau, {p}",
                "dsb ish",
                "isb",
                p = in(reg) p,
                options(nostack, preserves_flags),
            );
        }

        /// Reserve an isolated slot for `module_idx` and build its page
        /// table from the regions registered in `MODULE_REGION_INFO`
        /// (code/state/heap/channel) plus a guarded EL0 stack and the
        /// trampoline page. Returns false (and leaves the module on the
        /// EL1 path) if no slot is free or the regions are unusable.
        pub fn build_table(module_idx: usize) -> bool {
            if module_idx >= super::MAX_MODULES {
                return false;
            }
            // SAFETY: builds this module's slot. Safe to call from either the
            // single-threaded `prepare_graph` pass or lazily on the stepping
            // core (see `enter_el0`). Slot reservation is atomic; per-module
            // bookkeeping is owned by the one core that steps `module_idx`.
            unsafe {
                // Idempotent: already built for this module → nothing to do.
                // (Prevents the prepare-graph pass and the lazy path from each
                // reserving a slot for the same module.)
                let existing = MOD_TO_SLOT[module_idx];
                if existing < MAX_ISO && ISO_BUILT[existing] {
                    return true;
                }
                ensure_trampoline();
                let r = MODULE_REGION_INFO[module_idx];
                if r.code_size == 0 || r.state_size == 0 {
                    log::warn!(
                        "[el0] module {module_idx}: code/state region missing; cannot isolate"
                    );
                    return false;
                }
                // SECURITY (page-isolation invariant). `map_region` rounds every
                // mapping out to whole 4 KiB pages, so a region that is not
                // itself page-aligned AND page-sized would drag its neighbours
                // into the module's EL0 address space. For the EL0-RW regions
                // (state / heap / channel) that neighbour could be a kernel
                // global (e.g. scheduler state in the same page) or a peer
                // module's buffer — a writable cross-domain breach. REFUSE to
                // build an unsafe table (the module then fails closed in
                // `enter_el0`; it is never run at EL1). The isolated allocators
                // (`loader::alloc_isolated`, page-aligned channel buffers) make
                // these regions page-clean; this is the backstop that turns any
                // gap into a loud refusal instead of a silent leak. Done BEFORE
                // reserving a slot so a refusal consumes nothing.
                let page_clean = |base: u64, size: u64| -> bool {
                    size == 0 || (base & (PAGE - 1) == 0 && size & (PAGE - 1) == 0)
                };
                if !page_clean(r.state_base, r.state_size)
                    || !page_clean(r.heap_base, r.heap_size)
                    || !page_clean(r.chan_base, r.chan_size)
                {
                    log::error!(
                        "[el0] module {module_idx}: REFUSING isolation — an EL0-RW region is not \
                         page-aligned/page-sized (state 0x{:x}+{} heap 0x{:x}+{} chan 0x{:x}+{}); \
                         mapping it would expose adjacent kernel/peer memory. Module fails closed.",
                        r.state_base,
                        r.state_size,
                        r.heap_base,
                        r.heap_size,
                        r.chan_base,
                        r.chan_size,
                    );
                    return false;
                }
                // Code is EL0-RO; a non-page-aligned code region only exposes
                // adjacent module code read-only (a lesser, confidentiality-only
                // issue). Warn rather than refuse so existing module image
                // layouts still isolate; per-module page alignment in the image
                // layout (combine tool) is the full fix (tracked separately).
                if !page_clean(r.code_base, r.code_size) {
                    log::warn!(
                        "[el0] module {module_idx}: code region 0x{:x}+{} not page-aligned — \
                         adjacent module code may be EL0-readable (RO). Isolating anyway.",
                        r.code_base,
                        r.code_size,
                    );
                }
                // Atomically reserve the next slot. A concurrent lazy build on
                // another core gets a distinct index; over-reservation past
                // MAX_ISO just fails (we don't roll back — a sibling may have
                // legitimately taken the last slot).
                let slot = ISO_NEXT_SLOT.fetch_add(1, Ordering::AcqRel);
                if slot >= MAX_ISO {
                    log::warn!(
                        "[el0] module {module_idx}: no isolated slot free (max {MAX_ISO}); \
                         falling back to EL1 direct step"
                    );
                    return false;
                }
                // Mark the slot under construction so `is_isolated` (which gates
                // entry) only reports ready after the publish barrier below.
                ISO_BUILDING[slot].store(true, Ordering::Release);

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

                // Seed the kernel EL1-only identity base FIRST so the
                // exception vectors, the lower-EL handler, `EL0_CBS`, and the
                // kernel channel code+data are reachable at EL1 while this
                // table is installed in TTBR0 — otherwise the first SVC/abort
                // from EL0 would fault fetching its own vector and hang the
                // core. EL0 still has no access to any of it (AP_EL1_RW).
                seed_kernel_base(slot);

                // Carve the module's regions to EL0 access at 4 KB. Only its
                // exact pages become EL0-reachable; neighbouring modules'
                // state and all other kernel memory stay EL1-only (→ EL0
                // fault on access). Every region must map COMPLETELY — a partial
                // map (VA out of window, or L3-table pool exhausted) must abort
                // the build, not publish a half-built table.
                let mut mapped = true;
                let tramp = core::ptr::addr_of!(TRAMP) as u64;
                let slab = core::ptr::addr_of!(ISO_STACKS[slot]) as u64;
                let stack_lo = slab + PAGE; // first mapped page (guard = slab..slab+PAGE)
                mapped &= map_region(slot, r.code_base, r.code_size, AP_EL0_RO, false); // RO + X
                mapped &= map_region(slot, r.state_base, r.state_size, AP_EL0_RW, true); // RW + XN
                if r.heap_size > 0 {
                    mapped &= map_region(slot, r.heap_base, r.heap_size, AP_EL0_RW, true);
                }
                if r.chan_size > 0 {
                    mapped &= map_region(slot, r.chan_base, r.chan_size, AP_EL0_RW, true);
                }
                // Trampoline page: RO + X at EL0.
                mapped &= map_region(slot, tramp, PAGE, AP_EL0_RO, false);
                // EL0 stack with a guard page. Page 0 of the slab is left
                // unmapped (a stack underflow/overflow-down into it faults);
                // the stack occupies the next EL0_STACK_BYTES.
                mapped &= map_region(slot, stack_lo, EL0_STACK_BYTES, AP_EL0_RW, true);
                ISO_SP_TOP[slot] = stack_lo + EL0_STACK_BYTES; // grows down

                if !mapped {
                    // A region could not be mapped completely. Do NOT publish a
                    // partial table — the module would run at EL0 with missing
                    // pages (fault, or worse, hit a kernel EL1-only block where it
                    // expected its own RW memory). Release the reserved slot and
                    // fail; `enter_el0` then fails the module closed (never runs
                    // it at EL1). The half-written descriptors stay in this slot's
                    // (unpublished) tables and are overwritten on the next build.
                    log::error!(
                        "[el0] module {module_idx}: page-table build INCOMPLETE (region out of \
                         window or L3 pool exhausted) — refusing to publish (fail closed)"
                    );
                    ISO_BUILDING[slot].store(false, Ordering::Release);
                    return false;
                }

                // Publish: ensure every page-table descriptor written above is
                // observable to the table walker BEFORE the slot is marked
                // usable, so the first `enter` (which loads this table into
                // TTBR0) can't walk stale entries. `dsb ishst` orders the
                // descriptor stores; `isb` is belt-and-braces before any
                // subsequent context-synchronising TTBR0 load.
                core::arch::asm!("dsb ishst", "isb", options(nostack, preserves_flags));
                // Invalidate the WHOLE stage-1 EL1&0 regime (broadcast), not just
                // this module's ASID. CRITICAL: the boot identity map
                // (`boot_mmu::dram_block`) maps DRAM as GLOBAL (non-nG) 2 MB
                // blocks. Writing this slot's page tables just above — which live
                // in DRAM — cached a GLOBAL TLB entry for their 2 MB window
                // (EL1-only). A GLOBAL entry matches ANY ASID, so it would shadow
                // this module's `nG` EL0 carve in the same window (e.g. the EL0
                // stack, which co-locates with the page-table BSS) → an EL0
                // permission fault at level 2 even though ISO_L1/L2 are correctly
                // carved. An ASID-only `tlbi aside1is` does NOT evict global
                // entries, so it must be `vmalle1is`. Build is rare (graph setup
                // or one lazy first-step per module), so the full flush is cheap;
                // nothing re-caches these windows at EL1 afterward (only the
                // module touches its EL0 stack, and table-walker reads don't
                // populate data TLB entries).
                core::arch::asm!(
                    "tlbi vmalle1is",
                    "dsb ish",
                    "isb",
                    options(nostack, preserves_flags),
                );
                MOD_TO_SLOT[module_idx] = slot;
                ISO_BUILT[slot] = true;
                ISO_BUILDING[slot].store(false, Ordering::Release);
                log::info!(
                    "[el0] module {module_idx} isolated slot={slot} \
                     code=0x{:x}+{} state=0x{:x}+{} sp_top=0x{:x}",
                    r.code_base,
                    r.code_size,
                    r.state_base,
                    r.state_size,
                    ISO_SP_TOP[slot]
                );
                true
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
            if l1i >= KERNEL_BASE_GB {
                return (0, 0, 0);
            }
            let l1 = ISO_L1[slot].0[l1i];
            if l1 & DESC_TABLE == 0 {
                return (l1, 0, 0); // L1 block — no L2/L3
            }
            let l2i = ((va >> 21) & 0x1FF) as usize;
            let l2 = ISO_L2[slot][l1i].0[l2i];
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
            let l1i = (va / L1_BLOCK_SIZE) as usize; // 1 GB index
            if l1i >= KERNEL_BASE_GB {
                log::warn!(
                    "[el0] slot {slot}: va 0x{va:x} above {KERNEL_BASE_GB} GB base — skipped"
                );
                return false;
            }
            let l2i = ((va >> 21) & 0x1FF) as usize;
            let l3i = ((va >> 12) & 0x1FF) as usize;

            // 1. Ensure L1[l1i] is a table → ISO_L2[slot][l1i]. If it is still
            //    the seeded 1 GB kernel block, split it: fill the L2 with EL1
            //    2 MB blocks covering the whole GB, then point L1 at it.
            if ISO_L1[slot].0[l1i] & DESC_TABLE == 0 {
                let gb_base = (l1i as u64) * L1_BLOCK_SIZE;
                for (j, e) in ISO_L2[slot][l1i].0.iter_mut().enumerate() {
                    *e = kernel_block_2m(gb_base + (j as u64) * L2_BLOCK_SIZE);
                }
                let l2_base = core::ptr::addr_of!(ISO_L2[slot][l1i]) as u64;
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
                    return false;
                }
                l3slot = used;
                ISO_L3_KEY[slot][l3slot] = key;
                ISO_L3_USED[slot] = used + 1;
                // Back-fill the new L3 with the kernel EL1 pages it replaces.
                let win_base = (l1i as u64) * L1_BLOCK_SIZE + (l2i as u64) * L2_BLOCK_SIZE;
                for (j, e) in ISO_L3[slot][l3slot].0.iter_mut().enumerate() {
                    *e = kernel_page_4k(win_base + (j as u64) * PAGE);
                }
                let l3_base = core::ptr::addr_of!(ISO_L3[slot][l3slot]) as u64;
                ISO_L2[slot][l1i].0[l2i] = (l3_base & !0xFFF) | DESC_VALID | DESC_TABLE;
            }

            // 3. Overlay the module's EL0 page. XN at EL1 stays true for module
            //    memory (the kernel never executes module pages); xn_el0 is
            //    per-region (false only for the module's RO+X code/trampoline).
            ISO_L3[slot][l3slot].0[l3i] = make_page_desc(va, ATTR_IDX_NORMAL, ap, xn_el0, true);
            true
        }

        /// Perform the EL1→EL0→EL1 round-trip for an isolated module step.
        ///
        /// # Safety
        /// `step_fn` must be the module's genuine `module_step` export and
        /// `state_ptr` its live state. Caller runs on the module's owning
        /// core (scheduler invariant).
        pub unsafe fn enter(
            module_idx: usize,
            step_fn: crate::kernel::loader::ModuleStepFn,
            state_ptr: *mut u8,
        ) -> i32 {
            let slot = MOD_TO_SLOT[module_idx];
            if slot == usize::MAX || slot >= MAX_ISO || !ISO_BUILT[slot] {
                return step_fn(state_ptr);
            }
            let core = cur_core();
            let cb = core::ptr::addr_of_mut!(EL0_CBS[core]);
            // Record the module index so the SVC #1 syscall handler can
            // validate EL0 buffer pointers against THIS module's regions.
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*cb).module_idx), module_idx as u32);
            // Module TTBR0: ISO_L1 base | ASID (module_idx+1) in [63:48].
            let l1 = core::ptr::addr_of!(ISO_L1[slot]) as u64;
            let asid = (module_idx as u64 + 1) & 0xFF;
            let ttbr0 = (l1 & 0x0000_FFFF_FFFF_FFFF) | (asid << 48);
            let sp_top = ISO_SP_TOP[slot];
            let tramp = core::ptr::addr_of!(TRAMP) as u64;

            // SAFETY: fluxor_el0_enter saves the kernel context into *cb and
            // either returns the SVC outcome or is longjmp-resumed by the
            // lower-EL vector with the same cb. All pointers are valid for
            // the call; the asm restores SP/regs/TTBR0 before returning.
            let outcome: i32;
            core::arch::asm!(
                "bl fluxor_el0_enter",
                in("x0") cb,
                in("x1") ttbr0,
                in("x2") sp_top,
                in("x3") step_fn as usize,
                in("x4") state_ptr,
                in("x5") tramp,
                lateout("x0") outcome,
                // fluxor_el0_enter saves+restores callee-saved (x19-x29) from
                // *cb across the EL0 excursion, so from the caller's view this
                // is a normal C call: clobber_abi covers the caller-saved set
                // (x1-x18, x30) and excludes our explicit operands.
                clobber_abi("C"),
            );

            // Surface abort diagnostics latched by the vector.
            let fp = core::ptr::read_volatile(core::ptr::addr_of!((*cb).fault_pending));
            if fp != 0 {
                let esr = core::ptr::read_volatile(core::ptr::addr_of!((*cb).fault_esr));
                let far = core::ptr::read_volatile(core::ptr::addr_of!((*cb).fault_far));
                let elr = core::ptr::read_volatile(core::ptr::addr_of!((*cb).fault_elr));
                if fp == 2 {
                    log::error!(
                        "[el0] module {module_idx} illegal SVC (ESR=0x{esr:016x}) at \
                         ELR=0x{elr:016x} — protection fault"
                    );
                } else {
                    // fp == 1: an EL0-origin abort caught by the lower-EL
                    // synchronous vector. (Kernel-side/async faults fail-stop in
                    // `fluxor_el1_catch` and never reach this resume path.)
                    let ec = (esr >> 26) & 0x3F;
                    // Log the module's regions (so the fault log shows which one
                    // the FAR lies in, or that it's out of region) plus a
                    // page-table walk of FAR — distinguishing a genuine carve gap
                    // (l3 leaf lacks EL0 perm) from a stale-TLB shadow (tables
                    // correct but the MMU faults anyway).
                    let r = MODULE_REGION_INFO[module_idx];
                    let sp_top = ISO_SP_TOP[slot];
                    let stack_lo = sp_top.saturating_sub(EL0_STACK_BYTES);
                    let (d1, d2, d3) = walk_descriptors(slot, far);
                    log::error!(
                        "[el0] module {module_idx} EL0 abort EC=0x{ec:02x} ESR=0x{esr:016x} \
                         FAR=0x{far:016x} ELR=0x{elr:016x} — protection fault \
                         [state=0x{state_base:x}+{state_size} heap=0x{heap_base:x}+{heap_size} \
                         chan=0x{chan_base:x}+{chan_size} stack=0x{stack_lo:x}..0x{sp_top:x} \
                         code=0x{code_base:x}+{code_size}] walk[l1=0x{d1:x} l2=0x{d2:x} l3=0x{d3:x}]",
                        state_base = r.state_base, state_size = r.state_size,
                        heap_base = r.heap_base, heap_size = r.heap_size,
                        chan_base = r.chan_base, chan_size = r.chan_size,
                        code_base = r.code_base, code_size = r.code_size,
                    );
                }
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*cb).fault_pending), 0);
                // Record against the fault state machine so the scheduler's
                // post-step check runs the configured Skip/Restart policy.
                crate::kernel::step_guard::record_mpu_fault(module_idx);
            } else {
                // Clean EL0 round-trip: `module_step` ran at EL0 and returned
                // via the `SVC #0` trampoline through the lower-EL vector —
                // observable proof of EL0 execution + a clean SVC return. Log the
                // first 64 (so even an infrequently-stepped module emits some
                // early lines) then periodically, to avoid spamming every tick.
                let n = ISO_OK_COUNT[slot];
                ISO_OK_COUNT[slot] = n.wrapping_add(1);
                if n < 64 || n.is_multiple_of(EL0_OK_LOG_EVERY) {
                    log::info!(
                        "[el0] module {module_idx} el0 step ok outcome={outcome} step={n} \
                         (lower-EL SVC return confirms EL0 execution)"
                    );
                }
            }
            // On a recorded fault (`fp != 0`), return a CONTINUE outcome (0),
            // NOT the abort/EINVAL code: the fault is already delivered to the
            // scheduler via `record_mpu_fault` above, which its post-step
            // `check_and_clear_mpu_fault` → `handle_mpu_fault` consumes. Returning
            // the negative code would ALSO drive the scheduler's
            // `Err → handle_step_error` arm, double-processing the SAME fault —
            // terminating the module and decrementing `active_count` twice (which
            // can stop a healthy sibling) and consuming the restart budget twice.
            if fp != 0 {
                0
            } else {
                outcome
            }
        }

        /// Validate that `[ptr, ptr+len)` lies within an isolated module's
        /// own EL0 read/write regions (state / heap / channel / stack).
        /// Code/trampoline are RO+X and excluded — a channel buffer must be
        /// in writable module memory. Returns false for any out-of-region,
        /// straddling, or wrapping range. Both directions use the same
        /// (RW) region set: the kernel writes the buffer for a read and
        /// reads it for a write, and the EL0 RW regions are valid for both.
        unsafe fn el0_buf_ok(module_idx: usize, ptr: u64, len: usize) -> bool {
            if module_idx >= super::MAX_MODULES {
                return false;
            }
            let slot = MOD_TO_SLOT[module_idx];
            if slot == usize::MAX || slot >= MAX_ISO {
                return false;
            }
            let r = MODULE_REGION_INFO[module_idx];
            let stack_top = ISO_SP_TOP[slot];
            let stack_lo = stack_top.saturating_sub(EL0_STACK_BYTES);
            let regions = [
                (r.state_base, r.state_size),
                (r.heap_base, r.heap_size),
                (r.chan_base, r.chan_size),
                (stack_lo, EL0_STACK_BYTES),
            ];
            crate::kernel::el0_abi::buf_within_regions(ptr, len, &regions)
        }

        /// Authorize a channel handle for `module_idx`'s `SVC #1` gateway.
        /// Only the module's own `[in, out, ctrl]` handles (recorded at
        /// instantiation via `set_module_channels`) are accepted; every other
        /// handle is rejected so an isolated module cannot enumerate handle
        /// numbers and read/write unrelated graph edges. A `-1` slot never
        /// matches because a valid handle is non-negative.
        unsafe fn el0_chan_ok(module_idx: usize, chan: i32) -> bool {
            if module_idx >= super::MAX_MODULES || chan < 0 {
                return false;
            }
            let allowed = MODULE_REGION_INFO[module_idx].chans;
            allowed[0] == chan || allowed[1] == chan || allowed[2] == chan
        }

        /// The calling module's registered EL0 heap mapping `(base, size)`.
        /// `size` is the page-padded footprint mapped EL0-RW (≥ the
        /// allocator's usable arena), so a pointer validated against it is
        /// guaranteed reachable by the module at EL0. `(0, 0)` when the module
        /// declared no arena.
        unsafe fn el0_heap_region(module_idx: usize) -> (u64, u64) {
            if module_idx >= super::MAX_MODULES {
                return (0, 0);
            }
            let r = MODULE_REGION_INFO[module_idx];
            (r.heap_base, r.heap_size)
        }

        /// EL1 service routine for an isolated module's `SVC #1` channel
        /// syscall. Called from the lower-EL vector with the module's EL0
        /// register values; runs at EL1 under the module's TTBR0 (kernel is
        /// mapped EL1-only there). Validates the EL0 buffer pointer against
        /// the calling module's own regions BEFORE the kernel dereferences
        /// it, then forwards to the channel primitive. The caller `ERET`s
        /// back to EL0 with the returned value in x0.
        ///
        /// `channel_read` / `channel_write` / `channel_poll` and the
        /// per-module heap ops `heap_alloc` / `heap_free` are exposed (this
        /// slice). Unknown ops, unauthorized handles, and out-of-region
        /// pointers return errno without touching kernel state.
        ///
        /// Returns a **signed 64-bit** value in `x0`: channel errno/byte
        /// counts keep their `i32` semantics (sign-extended), while
        /// `heap_alloc` returns a full pointer-sized value (or `0`/null) that
        /// must not be truncated — hence the `i64` return.
        ///
        /// `module_idx` is the explicit identity latched in the EL0 control
        /// block at entry; the gateway routes EVERY operation through it and
        /// never consults ambient scheduler state, so a module can only reach
        /// its own channels and its own heap.
        ///
        /// # Safety
        /// Invoked only from `fluxor_el0_svc1` with a live isolated-module
        /// context; `chan`/`ptr`/`len` are the untrusted EL0 args and are
        /// validated here before any dereference.
        #[no_mangle]
        unsafe extern "C" fn el0_syscall_dispatch(
            op: u64,
            chan: i32,
            ptr: u64,
            len: usize,
            module_idx: u32,
        ) -> i64 {
            use crate::kernel::channel;
            use crate::kernel::el0_abi::{
                classify_heap_free, HeapFreeAction, EL0_EFAULT, EL0_EINVAL, EL0_EPERM,
                SYS_CHANNEL_POLL, SYS_CHANNEL_READ, SYS_CHANNEL_WRITE, SYS_HEAP_ALLOC,
                SYS_HEAP_FREE,
            };
            let module_idx = module_idx as usize;
            match op {
                SYS_CHANNEL_READ | SYS_CHANNEL_WRITE | SYS_CHANNEL_POLL => {
                    // Every channel op names a handle; authorize it against the
                    // module's own [in, out, ctrl] before touching channel
                    // state, so a hostile module cannot reach edges it was
                    // never granted.
                    if !el0_chan_ok(module_idx, chan) {
                        // Log the first 64 denials then rate-limit, so a denial
                        // is observable without a tight loop flooding the log.
                        use core::sync::atomic::{AtomicU32, Ordering as O};
                        static DENY: AtomicU32 = AtomicU32::new(0);
                        let dn = DENY.fetch_add(1, O::Relaxed);
                        if dn < 64 || dn.is_multiple_of(256) {
                            log::warn!(
                                "[el0] module {module_idx} channel handle {chan} DENIED (op={op}) — \
                                 not in module's [in,out,ctrl] allowlist; returning EPERM"
                            );
                        }
                        return EL0_EPERM;
                    }
                    match op {
                        SYS_CHANNEL_READ => {
                            if !el0_buf_ok(module_idx, ptr, len) {
                                return EL0_EFAULT;
                            }
                            // SAFETY: range validated to lie in the module's EL0
                            // RW memory (also EL1-RW under the module table);
                            // the kernel writes up to `len` bytes there.
                            channel::syscall_channel_read(chan, ptr as *mut u8, len) as i64
                        }
                        SYS_CHANNEL_WRITE => {
                            if !el0_buf_ok(module_idx, ptr, len) {
                                return EL0_EFAULT;
                            }
                            // SAFETY: range validated as above; the kernel reads
                            // up to `len` bytes from it.
                            channel::syscall_channel_write(chan, ptr as *const u8, len) as i64
                        }
                        // Poll takes no buffer — report readable bytes (or 0 for
                        // an invalid handle, matching channel_readable_bytes).
                        _ => channel::channel_readable_bytes(chan) as i64,
                    }
                }
                // ---- Per-module heap (routed through THIS module's own heap) --
                //
                // Size travels in `len` (x3). The kernel allocator is keyed by
                // the explicit `module_idx`, so the allocation comes from this
                // module's own `ModuleHeap` — no other module's arena is
                // reachable. A null return (heap exhausted / no arena) is the
                // defined failure signal; the module checks for it.
                SYS_HEAP_ALLOC => {
                    let size = len;
                    if size == 0 {
                        return 0; // alloc(0) is null by contract
                    }
                    let p = crate::kernel::heap::heap_alloc(module_idx, size);
                    if p.is_null() {
                        return 0;
                    }
                    // DEFENSE IN DEPTH: confirm the allocation lies wholly
                    // within this module's EL0-mapped heap region. By
                    // construction it does (the allocator arena IS the mapped
                    // heap), but if a misconfiguration ever returned memory
                    // outside the EL0 mapping we must NOT hand EL0 a pointer it
                    // cannot reach (or that aliases foreign memory) — free it
                    // back and fail closed.
                    let pa = p as u64;
                    let (hb, hs) = el0_heap_region(module_idx);
                    if !crate::kernel::el0_abi::buf_within_regions(pa, size, &[(hb, hs)]) {
                        crate::kernel::heap::heap_free(module_idx, p);
                        log::error!(
                            "[el0] module {module_idx} heap_alloc({size}) returned 0x{pa:x} \
                             OUTSIDE heap mapping 0x{hb:x}+{hs} — freed + failing closed"
                        );
                        return 0;
                    }
                    // Observable proof of a serviced heap alloc: first few then
                    // periodic (rate-limited like the clean-step / deny logs).
                    use core::sync::atomic::{AtomicU32, Ordering as O};
                    static ALLOC_OK: AtomicU32 = AtomicU32::new(0);
                    let an = ALLOC_OK.fetch_add(1, O::Relaxed);
                    if an < 8 || an.is_multiple_of(1024) {
                        log::info!(
                            "[el0] module {module_idx} heap_alloc ok ptr=0x{pa:x} size={size} \
                             (within heap 0x{hb:x}+{hs})"
                        );
                    }
                    pa as i64
                }
                SYS_HEAP_FREE => {
                    let (hb, hs) = el0_heap_region(module_idx);
                    match classify_heap_free(ptr, hb, hs) {
                        HeapFreeAction::Noop => 0, // free(NULL) — defined no-op
                        HeapFreeAction::Forward => {
                            // Inside the module's own heap. The allocator does
                            // the remaining interior/stale/double-free/header
                            // checks against its block metadata (confined to
                            // this arena) — logging, never corrupting, on a bad
                            // pointer.
                            // SAFETY: `ptr` is non-null and validated to lie in
                            // this module's heap arena; the allocator only
                            // touches block metadata within that arena.
                            crate::kernel::heap::heap_free(module_idx, ptr as *mut u8);
                            0
                        }
                        HeapFreeAction::Reject => {
                            use core::sync::atomic::{AtomicU32, Ordering as O};
                            static REJ: AtomicU32 = AtomicU32::new(0);
                            let rn = REJ.fetch_add(1, O::Relaxed);
                            if rn < 64 || rn.is_multiple_of(256) {
                                log::warn!(
                                    "[el0] module {module_idx} heap_free ptr=0x{ptr:x} REJECTED — \
                                     outside heap 0x{hb:x}+{hs}; returning EFAULT (no kernel deref)"
                                );
                            }
                            EL0_EFAULT
                        }
                    }
                }
                _ => EL0_EINVAL,
            }
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
            // ---- fluxor_el0_enter(cb=x0, ttbr0=x1, sp_el0=x2,
            //                       step_fn=x3, state=x4, tramp=x5) -> i32 ----
            "fluxor_el0_enter:",
            "mov   x9, sp",
            "str   x9,  [x0, #0]", // kernel_sp
            "str   x30, [x0, #8]", // kernel_lr (return into enter())
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
            // Save callee-saved FP/SIMD v8-v15 (full 128-bit) — the round-trip
            // clears them at entry + the module clobbers them at EL0; restored in
            // fluxor_el0_resume so the kernel caller's FP state survives.
            "str   q8,  [x0, #160]",
            "str   q9,  [x0, #176]",
            "str   q10, [x0, #192]",
            "str   q11, [x0, #208]",
            "str   q12, [x0, #224]",
            "str   q13, [x0, #240]",
            "str   q14, [x0, #256]",
            "str   q15, [x0, #272]",
            "mov   w9, #1",
            "str   w9,  [x0, #144]", // active = 1
            "str   wzr, [x0, #148]", // fault_pending = 0
            // Install the module translation regime.
            "msr   ttbr0_el1, x1",
            "isb",
            "msr   sp_el0, x2",
            "msr   elr_el1, x3", // EL0 entry = module_step
            "movz  x9, #0x3c0",  // SPSR_EL1: EL0t, DAIF masked
            "msr   spsr_el1, x9",
            "mov   x0, x4",  // x0 = state_ptr (module_step arg)
            "mov   x30, x5", // LR = trampoline (SVC #0 on return)
            // Scrub EVERY GP reg except the two carrying legitimate EL0 values
            // (x0 = state_ptr, x30 = trampoline) so NO kernel state is visible
            // at EL0. The callee-saved x19-x29 were saved to the control block
            // above (and are reloaded from it on resume), so zeroing the live
            // registers here is safe and prevents disclosing the kernel's
            // callee-saved values across the privilege boundary.
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
            // Scrub ALL FP/SIMD registers too: CPACR enables FP at EL0, the
            // kernel uses NEON (TLS/SHA/ChaCha crypto) on this core between
            // steps, and module_step is a fresh call that expects no live FP
            // state — so leaving v0-v31 intact would disclose kernel crypto
            // material to EL0. v8-v15 (C-ABI callee-saved) are also kernel state
            // at entry, so the full bank is cleared here.
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
            // Restore kernel regime + callee-saved, RET to saved kernel LR.
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
            // Restore callee-saved FP/SIMD v8-v15 saved by fluxor_el0_enter, so
            // the kernel caller's live FP state survives the EL0 round-trip.
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
            // Reached from the lower-EL AArch64 synchronous vector while a
            // module runs at EL0. GPRs still hold EL0 values. Decide SVC vs
            // abort and longjmp into fluxor_el0_resume. If no EL0 step is
            // active on this core, fall back to the generic dump.
            "fluxor_el0_lower_sync_vec:",
            "mov   x9, x0", // save EL0 x0 (candidate SVC outcome)
            "mrs   x10, mpidr_el1",
            "lsr   x10, x10, #8",
            "and   x10, x10, #3", // core id (Pi 5: MPIDR Aff1)
            "adrp  x11, EL0_CBS",
            "add   x11, x11, #:lo12:EL0_CBS",
            "mov   x12, #320",          // CB_SIZE
            "madd  x11, x10, x12, x11", // x11 = &EL0_CBS[core]
            "ldr   w13, [x11, #144]",   // active
            "cbz   w13, fluxor_el0_inactive",
            "mrs   x14, esr_el1",
            "lsr   x15, x14, #26", // EC
            "cmp   x15, #0x15",    // SVC from AArch64
            "b.eq  fluxor_el0_svc",
            // ---- abort path: record ESR/FAR/ELR, return EFAULT (-14) ----
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
            "fluxor_el0_svc:",
            "and   x16, x14, #0xffff",    // SVC imm16 (ESR ISS)
            "cbz   x16, fluxor_el0_svc0", // imm == 0 -> end-of-step return
            "cmp   x16, #1",
            "b.eq  fluxor_el0_svc1",   // imm == 1 -> channel syscall
            "b     fluxor_el0_badsvc", // any other imm -> rejected
            // SVC #0: module_step returned. Longjmp back to the scheduler
            // with the StepOutcome the module left in x0 (saved in x9).
            "fluxor_el0_svc0:",
            "mov   x0, x11",
            "mov   w1, w9", // outcome = EL0 x0 (StepOutcome i32)
            "b     fluxor_el0_resume",
            // SVC #1: channel + heap syscall gateway. Service it at EL1 (still
            // under the module's TTBR0, where the kernel is mapped EL1-only)
            // and ERET back to EL0 so the module continues the same step. EL0
            // x0=op (saved in x9), x1=chan, x2=ptr, x3=len are the args;
            // x4=module_idx from the control block. el0_syscall_dispatch
            // validates the pointer/handle before any dereference and returns
            // an i64 result in x0 — a full pointer-sized value for heap_alloc,
            // which the scrub below preserves (it clears only x1-x18+lr). The
            // C ABI preserves x19-x30 and SP_EL1, and ELR_EL1/SPSR_EL1 still
            // point just past the SVC at EL0. The module's own `svc #1` asm
            // marks x0-x18+lr clobbered, so leaving x1-x18 dirty across the
            // syscall is within contract.
            "fluxor_el0_svc1:",
            "ldr   w4, [x11, #156]", // module_idx
            "mov   x0, x9",          // op
            "bl    el0_syscall_dispatch",
            // Scrub kernel state out of the caller-saved regs + LR before
            // returning to EL0. `el0_syscall_dispatch` (a C call) leaves kernel
            // pointers / intermediates in x1-x18 and a kernel return address in
            // x30; the module's `svc #1` wrapper marks x0-x18+lr clobbered, so it
            // won't USE them — but a hostile module could still READ them, which
            // is a cross-privilege disclosure. x0 holds the syscall result
            // (kept); x19-x29 are C-ABI callee-saved = the module's OWN values
            // (must be preserved, not scrubbed).
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
            "mov x18, xzr",
            "mov x30, xzr",
            // Scrub the caller-saved FP/SIMD regs the dispatch may have left
            // kernel data in. v0-v7, v16-v31 are fully caller-saved → clear all
            // 128 bits. v8-v15 are callee-saved but AAPCS64 only preserves their
            // LOW 64 bits across a call, so `el0_syscall_dispatch` may leave
            // kernel data in their UPPER 64 bits — clear just those (keep the low
            // halves, which are the module's own preserved values its `svc #1`
            // wrapper relies on).
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
            "fluxor_el0_inactive:",
            // No active EL0 step — genuinely unexpected. Hand to the generic
            // dumper (defined in exception.rs).
            "b     unhandled_exception",
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
            "fluxor_el1_sync_vec:", // back-compat alias: EL1h sync
            "mov   w17, #3",
            "fluxor_el1_catch:",
            // Regardless of whether an EL0 step is active, this is a kernel-side
            // or async fault that must not be silently recovered. Dump + spin
            // (latches CORE_FAULT_* for sibling-core UDP surfacing).
            "b     unhandled_exception",
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
        module_idx, code_base, code_size, state_ptr, state_size, heap_ptr, heap_size,
    );
    let _ = (
        module_idx, code_base, code_size, state_ptr, state_size, heap_ptr, heap_size,
    );
}

/// Set channel buffer region for a module.
pub fn set_channel_region(module_idx: usize, base: u64, size: u64) {
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_impl::set_module_channel_region(module_idx, base, size);
    let _ = (module_idx, base, size);
}

/// Record the channel handles an isolated module may name in its `SVC #1`
/// gateway calls (its own `[in, out, ctrl]` from `module_new`). The gateway
/// rejects any other handle with `EPERM`.
pub fn set_isolated_channels(module_idx: usize, in_chan: i32, out_chan: i32, ctrl_chan: i32) {
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_impl::set_module_channels(module_idx, in_chan, out_chan, ctrl_chan);
    let _ = (module_idx, in_chan, out_chan, ctrl_chan);
}

/// Build a module's page table after all regions are registered.
pub fn build_page_table(module_idx: usize) {
    #[cfg(feature = "chip-bcm2712")]
    bcm2712_impl::build_module_page_table(module_idx);
    let _ = module_idx;
}

/// Build the EL0-isolation page table for an isolated module from its
/// registered regions (code/state/heap/channel) plus a guarded EL0 stack
/// and the SVC trampoline page. Returns `true` if the module now has a
/// usable isolated table (so the scheduler routes it through the EL0
/// protected step); `false` if no isolated slot was available or the
/// regions were unusable (the module stays on the EL1 direct path).
pub fn build_isolated_table(module_idx: usize) -> bool {
    #[cfg(feature = "chip-bcm2712")]
    return bcm2712_impl::el0::build_table(module_idx);
    #[cfg(not(feature = "chip-bcm2712"))]
    {
        let _ = module_idx;
        false
    }
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
///
/// # Safety
/// `step_fn` must be the genuine `module_step` export of the module whose
/// state lives at `state_ptr`. `state_ptr` must remain valid for the duration
/// of the call (the EL0 trampoline keeps it pinned in x0 across the ERET).
/// Caller must run on the module's owning core so MMU isolation targets the
/// correct per-module L2/L3 page tables installed via `setup_paged_arena`.
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
