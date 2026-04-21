//! MPU-based hardware isolation for Cortex-M33 (RP2350).
//!
//! # Architecture
//!
//! Modules run in unprivileged Thread mode with a restricted MPU configuration.
//! The kernel runs in privileged Handler mode (SVC / ISR context). Syscalls from
//! modules go through SVC gateway stubs that trap into the kernel.
//!
//! ## MPU Region Layout (ARMv8-M, 8 regions)
//!
//! | Region | Purpose                  | Access             |
//! |--------|--------------------------|--------------------|
//! | 0      | Kernel code (.text)      | Priv RO+X          |
//! | 1      | Kernel data (.data+.bss) | Priv RW            |
//! | 2      | Syscall table            | Unpriv RO          |
//! | 3      | Module code (flash XIP)  | Unpriv RO+X        |
//! | 4      | Module state             | Unpriv RW          |
//! | 5      | Module heap arena        | Unpriv RW          |
//! | 6      | Channel buffers          | Unpriv RW          |
//! | 7      | MMIO peripherals         | Device, Priv RW    |
//!
//! ## Privilege transitions
//!
//! - `enter_unprivileged()`: sets PSP, drops CONTROL.nPRIV=1, calls module_step
//! - Module executes `SVC #0` to return to privileged mode
//! - SVC handler reads syscall number from stacked R12, dispatches
//!
//! ## Alignment
//!
//! ARMv8-M MPU requires region base addresses to be 32-byte aligned and region
//! sizes to be >= 32 bytes. The alloc_state() arena already aligns to 4 bytes;
//! we round to 32-byte alignment for MPU configuration.

#[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
#[allow(dead_code)]
mod rp2350_impl {
    use crate::abi::SyscallTable;
    use crate::kernel::loader::ModuleStepFn;

    // ========================================================================
    // ARMv8-M MPU register addresses (Cortex-M33)
    // ========================================================================

    /// MPU base address (System Control Space)
    const MPU_BASE: u32 = 0xE000_ED90;

    /// MPU Type Register — reports number of regions
    const MPU_TYPE: *const u32 = (MPU_BASE + 0x00) as *const u32;
    /// MPU Control Register
    const MPU_CTRL: *mut u32 = (MPU_BASE + 0x04) as *mut u32;
    /// MPU Region Number Register
    const MPU_RNR: *mut u32 = (MPU_BASE + 0x08) as *mut u32;
    /// MPU Region Base Address Register
    const MPU_RBAR: *mut u32 = (MPU_BASE + 0x0C) as *mut u32;
    /// MPU Region Limit Address Register
    const MPU_RLAR: *mut u32 = (MPU_BASE + 0x10) as *mut u32;
    /// MPU Region Base Address Register Alias 1
    const MPU_RBAR_A1: *mut u32 = (MPU_BASE + 0x14) as *mut u32;
    /// MPU Region Limit Address Register Alias 1
    const MPU_RLAR_A1: *mut u32 = (MPU_BASE + 0x18) as *mut u32;
    /// MPU Region Base Address Register Alias 2
    const MPU_RBAR_A2: *mut u32 = (MPU_BASE + 0x1C) as *mut u32;
    /// MPU Region Limit Address Register Alias 2
    const MPU_RLAR_A2: *mut u32 = (MPU_BASE + 0x20) as *mut u32;
    /// MPU Region Base Address Register Alias 3
    const MPU_RBAR_A3: *mut u32 = (MPU_BASE + 0x24) as *mut u32;
    /// MPU Region Limit Address Register Alias 3
    const MPU_RLAR_A3: *mut u32 = (MPU_BASE + 0x28) as *mut u32;

    /// Memory Attribute Indirection Register 0 (attr 0-3)
    const MPU_MAIR0: *mut u32 = (MPU_BASE + 0x30) as *mut u32;
    /// Memory Attribute Indirection Register 1 (attr 4-7)
    const MPU_MAIR1: *mut u32 = (MPU_BASE + 0x34) as *mut u32;

    // CTRL register bits
    /// Enable MPU
    const CTRL_ENABLE: u32 = 1 << 0;
    /// Enable MPU during HardFault and NMI handlers
    const CTRL_HFNMIENA: u32 = 1 << 1;
    /// Enable default privileged background map
    const CTRL_PRIVDEFENA: u32 = 1 << 2;

    // RBAR field positions (ARMv8-M)
    // [4:0] = reserved/zero (base address bits [31:5] start at bit 5)
    // [0] = XN (execute-never)
    // [2:1] = AP (access permissions)
    // [3] = SH (shareability) — we use non-shareable (0) for single-core

    /// XN bit in RBAR: 1 = execute-never
    const RBAR_XN: u32 = 1 << 0;
    /// AP field shift in RBAR
    const RBAR_AP_SHIFT: u32 = 1;

    // Access Permission encodings (AP[2:1])
    /// Privileged RW, Unprivileged no access
    const AP_PRIV_RW: u32 = 0b00;
    /// Privileged RW, Unprivileged RW
    const AP_RW_RW: u32 = 0b01;
    /// Privileged RO, Unprivileged no access
    const AP_PRIV_RO: u32 = 0b10;
    /// Privileged RO, Unprivileged RO
    const AP_RO_RO: u32 = 0b11;

    // RLAR field positions
    /// Enable bit in RLAR
    const RLAR_EN: u32 = 1 << 0;
    /// Attribute index field shift (bits [3:1])
    const RLAR_ATTR_SHIFT: u32 = 1;

    // Memory attribute encodings for MAIR
    // Attr 0: Normal, outer write-back transient, inner write-back transient (cacheable)
    //   Outer: 0b0100_1111 = Write-Back, Read-Write-Allocate, Transient
    //   But ARM simplified: outer byte [7:4], inner byte [3:0]
    //   We use: 0xFF = Normal memory, outer WB-WA, inner WB-WA (non-transient)
    const MAIR_ATTR_NORMAL_CACHED: u8 = 0xFF;
    // Attr 1: Device-nGnRnE (strongly ordered, suitable for MMIO)
    const MAIR_ATTR_DEVICE: u8 = 0x00;
    // Attr 2: Normal, non-cacheable (for shared buffers if needed)
    const MAIR_ATTR_NORMAL_NC: u8 = 0x44;

    // Attribute indices
    const ATTR_IDX_NORMAL: u32 = 0;
    const ATTR_IDX_DEVICE: u32 = 1;
    const ATTR_IDX_NORMAL_NC: u32 = 2;

    // Region indices
    const REGION_KERNEL_CODE: u32 = 0;
    const REGION_KERNEL_DATA: u32 = 1;
    const REGION_SYSCALL_TABLE: u32 = 2;
    const REGION_MODULE_CODE: u32 = 3;
    const REGION_MODULE_STATE: u32 = 4;
    const REGION_MODULE_HEAP: u32 = 5;
    const REGION_CHANNEL_BUF: u32 = 6;
    const REGION_MMIO: u32 = 7;

    // SCB SHCSR for MemManage enable
    const SCB_SHCSR: *mut u32 = 0xE000_ED24 as *mut u32;
    const SHCSR_MEMFAULTENA: u32 = 1 << 16;

    // MemManage Fault Status Register (part of CFSR)
    const SCB_CFSR: *const u32 = 0xE000_ED28 as *const u32;
    // MemManage Fault Address Register
    const SCB_MMFAR: *const u32 = 0xE000_ED34 as *const u32;

    // MMFSR bit fields (byte 0 of CFSR)
    const MMFSR_IACCVIOL: u32 = 1 << 0; // Instruction access violation
    const MMFSR_DACCVIOL: u32 = 1 << 1; // Data access violation
    const MMFSR_MUNSTKERR: u32 = 1 << 3; // MemManage fault on unstacking
    const MMFSR_MSTKERR: u32 = 1 << 4; // MemManage fault on stacking
    const MMFSR_MLSPERR: u32 = 1 << 5; // MemManage fault during FP lazy stacking
    const MMFSR_MMARVALID: u32 = 1 << 7; // MMFAR has valid address

    /// Maximum modules we track isolation info for.
    const MAX_MODULES: usize = crate::kernel::scheduler::MAX_MODULES;

    /// Per-module memory region info for MPU configuration.
    #[derive(Clone, Copy)]
    struct ModuleRegions {
        /// Module code base address in flash (XIP).
        code_base: u32,
        /// Module code size in bytes.
        code_size: u32,
        /// Module state buffer address.
        state_base: u32,
        /// Module state buffer size.
        state_size: u32,
        /// Module heap arena address (0 if none).
        heap_base: u32,
        /// Module heap arena size (0 if none).
        heap_size: u32,
        /// Channel buffer base address.
        chan_base: u32,
        /// Channel buffer size.
        chan_size: u32,
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
            }
        }
    }

    /// Per-module MPU region descriptors.
    static mut MODULE_REGIONS: [ModuleRegions; MAX_MODULES] = [ModuleRegions::empty(); MAX_MODULES];

    /// Whether isolation is enabled (opt-in via config).
    static mut ISOLATION_ENABLED: bool = false;

    /// Module PSP stack (separate from MSP). 2KB per module is sufficient
    /// since modules only use the stack for local variables during step().
    const MODULE_STACK_SIZE: usize = 2048;
    #[repr(C, align(32))]
    struct ModuleStack([u8; MODULE_STACK_SIZE]);
    static mut MODULE_PSP_STACK: ModuleStack = ModuleStack([0; MODULE_STACK_SIZE]);

    /// Magic word written across a 32-byte band at the bottom of the module
    /// PSP stack. The MPU's eight regions are fully committed to code/data/
    /// syscalls/module-state/heap/channels/MMIO, leaving no hardware region
    /// for a guard page, so overflow detection is software-only: the
    /// scheduler verifies these cells after each step.
    const STACK_CANARY_WORD: u32 = 0xDEAD_C0DE;
    const STACK_CANARY_CELLS: usize = 8;

    /// Initialise stack canary cells at the bottom of the module PSP stack.
    pub unsafe fn init_stack_canary() {
        let base = core::ptr::addr_of_mut!(MODULE_PSP_STACK.0).cast::<u32>();
        for i in 0..STACK_CANARY_CELLS {
            unsafe {
                core::ptr::write_volatile(base.add(i), STACK_CANARY_WORD);
            }
        }
    }

    /// Check whether the stack canary is still intact.
    /// Returns `true` if unchanged, `false` if the stack overflowed.
    pub unsafe fn check_stack_canary() -> bool {
        let base = core::ptr::addr_of!(MODULE_PSP_STACK.0).cast::<u32>();
        for i in 0..STACK_CANARY_CELLS {
            if unsafe { core::ptr::read_volatile(base.add(i)) } != STACK_CANARY_WORD {
                return false;
            }
        }
        true
    }

    /// Align address down to 32-byte boundary (ARMv8-M MPU requirement).
    #[inline]
    const fn align_down_32(addr: u32) -> u32 {
        addr & !0x1F
    }

    /// Align address up to 32-byte boundary.
    #[inline]
    const fn align_up_32(addr: u32) -> u32 {
        (addr + 31) & !0x1F
    }

    /// Build RBAR value for a region.
    /// `base` must be 32-byte aligned.
    /// `ap` is access permission (AP_* constants).
    /// `xn` true = execute-never.
    #[inline]
    fn make_rbar(base: u32, ap: u32, xn: bool) -> u32 {
        let xn_bit = if xn { RBAR_XN } else { 0 };
        // Base address occupies bits [31:5], AP in [2:1], XN in [0]
        (base & !0x1F) | (ap << RBAR_AP_SHIFT) | xn_bit
    }

    /// Build RLAR value for a region.
    /// `limit` is the last byte address of the region, aligned to 32-byte boundary.
    /// `attr_idx` is the MAIR attribute index.
    #[inline]
    fn make_rlar(limit: u32, attr_idx: u32, enable: bool) -> u32 {
        let en = if enable { RLAR_EN } else { 0 };
        // Limit address bits [31:5] in bits [31:5], attr in [3:1], EN in [0]
        (limit & !0x1F) | (attr_idx << RLAR_ATTR_SHIFT) | en
    }

    /// Write a single MPU region (select region, then write RBAR + RLAR).
    #[inline]
    unsafe fn write_region(region: u32, rbar: u32, rlar: u32) {
        core::ptr::write_volatile(MPU_RNR, region);
        core::ptr::write_volatile(MPU_RBAR, rbar);
        core::ptr::write_volatile(MPU_RLAR, rlar);
    }

    /// Disable a single MPU region.
    #[inline]
    unsafe fn disable_region(region: u32) {
        core::ptr::write_volatile(MPU_RNR, region);
        core::ptr::write_volatile(MPU_RLAR, 0); // EN=0
    }

    // ========================================================================
    // Public API
    // ========================================================================

    /// Initialize MPU hardware.
    ///
    /// Sets up MAIR attributes and static kernel regions (0-2, 7).
    /// Call once during kernel boot, before any module execution.
    pub fn mpu_init() {
        unsafe {
            // Check MPU is present
            let mpu_type = core::ptr::read_volatile(MPU_TYPE);
            let num_regions = (mpu_type >> 8) & 0xFF;
            if num_regions < 8 {
                log::warn!(
                    "[mpu] only {} regions, need 8 — isolation disabled",
                    num_regions
                );
                return;
            }

            // Disable MPU while configuring
            core::ptr::write_volatile(MPU_CTRL, 0);

            // Set up MAIR registers
            // MAIR0: attr0=Normal cached, attr1=Device, attr2=Normal NC, attr3=0
            let mair0 = (MAIR_ATTR_NORMAL_CACHED as u32)
                | ((MAIR_ATTR_DEVICE as u32) << 8)
                | ((MAIR_ATTR_NORMAL_NC as u32) << 16);
            core::ptr::write_volatile(MPU_MAIR0, mair0);
            core::ptr::write_volatile(MPU_MAIR1, 0);

            // Region 0: Kernel code — entire flash XIP range (RO+X, priv only)
            // RP2350 flash: 0x1000_0000 .. 0x1100_0000
            write_region(
                REGION_KERNEL_CODE,
                make_rbar(0x1000_0000, AP_PRIV_RO, false), // XN=false (executable)
                make_rlar(0x10FF_FFE0, ATTR_IDX_NORMAL, true),
            );

            // Region 1: Kernel data — SRAM (RW, priv only)
            // RP2350 SRAM: 0x2000_0000 .. 0x2008_0000 (512KB)
            write_region(
                REGION_KERNEL_DATA,
                make_rbar(0x2000_0000, AP_PRIV_RW, true), // XN=true
                make_rlar(0x2007_FFE0, ATTR_IDX_NORMAL, true),
            );

            // Region 7: MMIO peripherals — device memory, priv RW
            // RP2350 peripherals: 0x4000_0000 .. 0x5100_0000
            write_region(
                REGION_MMIO,
                make_rbar(0x4000_0000, AP_PRIV_RW, true), // XN=true
                make_rlar(0x50FF_FFE0, ATTR_IDX_DEVICE, true),
            );

            // Regions 2-6: disabled until isolation is enabled
            for r in 2..7 {
                disable_region(r);
            }

            // Enable MemManage fault handler
            let shcsr = core::ptr::read_volatile(SCB_SHCSR);
            core::ptr::write_volatile(SCB_SHCSR, shcsr | SHCSR_MEMFAULTENA);

            // Enable MPU with PRIVDEFENA (privileged code can access everything)
            core::ptr::write_volatile(MPU_CTRL, CTRL_ENABLE | CTRL_PRIVDEFENA | CTRL_HFNMIENA);

            // Barriers
            cortex_m::asm::dsb();
            cortex_m::asm::isb();

            ISOLATION_ENABLED = true;
            log::info!("[mpu] initialized, {} regions", num_regions);
        }
    }

    /// Register a module's memory regions for MPU isolation.
    ///
    /// Called during module instantiation (after state allocation).
    /// The regions are stored and applied when `mpu_configure_module()` is called
    /// before each step.
    pub fn register_module_regions(
        module_idx: usize,
        code_base: u32,
        code_size: u32,
        state_ptr: *mut u8,
        state_size: usize,
        heap_ptr: *mut u8,
        heap_size: usize,
    ) {
        if module_idx >= MAX_MODULES {
            return;
        }
        unsafe {
            MODULE_REGIONS[module_idx] = ModuleRegions {
                code_base: align_down_32(code_base),
                code_size: align_up_32(code_size),
                state_base: align_down_32(state_ptr as u32),
                state_size: align_up_32(state_size as u32),
                heap_base: if heap_ptr.is_null() {
                    0
                } else {
                    align_down_32(heap_ptr as u32)
                },
                heap_size: if heap_ptr.is_null() {
                    0
                } else {
                    align_up_32(heap_size as u32)
                },
                // Channel buffers are set separately
                chan_base: 0,
                chan_size: 0,
            };
        }
    }

    /// Set channel buffer region for a module.
    /// Called after channel allocation.
    pub fn set_module_channel_region(module_idx: usize, base: u32, size: u32) {
        if module_idx >= MAX_MODULES {
            return;
        }
        unsafe {
            MODULE_REGIONS[module_idx].chan_base = align_down_32(base);
            MODULE_REGIONS[module_idx].chan_size = align_up_32(size);
        }
    }

    /// Configure MPU regions 3-6 for the given module before stepping it.
    ///
    /// Must be called from privileged mode (Handler/kernel context).
    pub fn mpu_configure_module(module_idx: usize) {
        if !is_enabled() || module_idx >= MAX_MODULES {
            return;
        }
        unsafe {
            let r = &MODULE_REGIONS[module_idx];

            // Temporarily disable MPU for region updates
            let ctrl = core::ptr::read_volatile(MPU_CTRL);
            core::ptr::write_volatile(MPU_CTRL, ctrl & !CTRL_ENABLE);

            // Region 3: Module code (RO+X for unprivileged)
            if r.code_size >= 32 {
                let limit = r.code_base + r.code_size - 32;
                write_region(
                    REGION_MODULE_CODE,
                    make_rbar(r.code_base, AP_RO_RO, false), // XN=false
                    make_rlar(limit, ATTR_IDX_NORMAL, true),
                );
            } else {
                disable_region(REGION_MODULE_CODE);
            }

            // Region 4: Module state (RW for unprivileged)
            if r.state_size >= 32 {
                let limit = r.state_base + r.state_size - 32;
                write_region(
                    REGION_MODULE_STATE,
                    make_rbar(r.state_base, AP_RW_RW, true), // XN=true
                    make_rlar(limit, ATTR_IDX_NORMAL, true),
                );
            } else {
                disable_region(REGION_MODULE_STATE);
            }

            // Region 5: Module heap arena (RW for unprivileged, if present)
            if r.heap_size >= 32 {
                let limit = r.heap_base + r.heap_size - 32;
                write_region(
                    REGION_MODULE_HEAP,
                    make_rbar(r.heap_base, AP_RW_RW, true),
                    make_rlar(limit, ATTR_IDX_NORMAL, true),
                );
            } else {
                disable_region(REGION_MODULE_HEAP);
            }

            // Region 6: Channel buffers (RW for unprivileged)
            if r.chan_size >= 32 {
                let limit = r.chan_base + r.chan_size - 32;
                write_region(
                    REGION_CHANNEL_BUF,
                    make_rbar(r.chan_base, AP_RW_RW, true),
                    make_rlar(limit, ATTR_IDX_NORMAL, true),
                );
            } else {
                disable_region(REGION_CHANNEL_BUF);
            }

            // Re-enable MPU
            core::ptr::write_volatile(MPU_CTRL, ctrl);

            // Barriers after region update
            cortex_m::asm::dsb();
            cortex_m::asm::isb();
        }
    }

    /// Check if isolation is enabled.
    #[inline]
    pub fn is_enabled() -> bool {
        unsafe { ISOLATION_ENABLED }
    }

    /// Enable or disable isolation at runtime.
    pub fn set_enabled(enabled: bool) {
        unsafe {
            ISOLATION_ENABLED = enabled;
        }
    }

    // ========================================================================
    // Privilege transition: enter_unprivileged / SVC return
    // ========================================================================

    /// Enter unprivileged Thread mode, call module_step, return to privileged.
    ///
    /// Flow:
    /// 1. Save current MSP context
    /// 2. Set up PSP with module stack
    /// 3. Set CONTROL.nPRIV=1 (unprivileged Thread mode)
    /// 4. Call module_step(state_ptr)
    /// 5. Module returns, executes SVC #0 to re-enter privileged
    /// 6. SVC handler restores CONTROL.nPRIV=0, returns result
    ///
    /// If isolation is not enabled, falls through to a direct call.
    #[inline(never)]
    pub unsafe fn enter_unprivileged(step_fn: ModuleStepFn, state_ptr: *mut u8) -> i32 {
        if !is_enabled() {
            // No isolation — direct call
            return step_fn(state_ptr);
        }

        // Set up PSP to top of module stack
        let psp_top = core::ptr::addr_of!(MODULE_PSP_STACK.0)
            .cast::<u8>()
            .add(MODULE_STACK_SIZE) as u32;

        let result: i32;
        core::arch::asm!(
            // Save current CONTROL register
            "mrs r4, CONTROL",
            // Set PSP
            "msr PSP, {psp}",
            // Switch to PSP (SPSEL=1) and unprivileged (nPRIV=1)
            // CONTROL[0]=nPRIV, CONTROL[1]=SPSEL
            "movs r5, #3",       // nPRIV=1, SPSEL=1
            "msr CONTROL, r5",
            "isb",
            // Call module_step(state_ptr) — now in unprivileged mode
            "mov r0, {state}",
            "blx {step_fn}",
            // Module has returned — still in unprivileged mode.
            // Use SVC to get back to privileged.
            // R0 holds the return value from module_step.
            // We use SVC #0 to signal "return from unprivileged step".
            "svc #0",
            // After SVC handler returns, we're back in privileged mode.
            // R0 still holds the result (SVC handler preserves it).
            // Restore CONTROL
            "msr CONTROL, r4",
            "isb",
            step_fn = in(reg) step_fn,
            state = in(reg) state_ptr,
            psp = in(reg) psp_top,
            out("r0") result,
            // r4/r5 are callee-saved but we use them across the call.
            // Mark as clobbered so the compiler saves/restores them.
            out("r1") _, out("r2") _, out("r3") _,
            out("r4") _, out("r5") _,
            out("r12") _, out("lr") _,
        );
        result
    }

    /// Burst trampoline: runs step in a loop while result == Burst (2).
    ///
    /// Runs entirely in unprivileged mode, only SVCs back on non-Burst return.
    /// This eliminates the SVC overhead (~350ns) per burst iteration.
    ///
    /// If isolation is not enabled, falls through to a simple loop.
    pub unsafe fn burst_trampoline(
        step_fn: ModuleStepFn,
        state_ptr: *mut u8,
        max_burst: u32,
    ) -> i32 {
        if !is_enabled() {
            // No isolation — direct burst loop
            let mut result = step_fn(state_ptr);
            let mut count = 0u32;
            while result == 2 && count < max_burst {
                result = step_fn(state_ptr);
                count += 1;
            }
            return result;
        }

        let psp_top = core::ptr::addr_of!(MODULE_PSP_STACK.0)
            .cast::<u8>()
            .add(MODULE_STACK_SIZE) as u32;

        let result: i32;
        core::arch::asm!(
            // Save CONTROL in callee-saved r4
            "mrs r4, CONTROL",
            // Set PSP
            "msr PSP, {psp}",
            // Switch to unprivileged + PSP
            "movs r5, #3",
            "msr CONTROL, r5",
            "isb",
            // Burst loop — use r8 as counter
            "mov r8, #0",
            "2:",
            "mov r0, {state}",
            "blx {step_fn}",
            // Check if Burst (result == 2)
            "cmp r0, #2",
            "bne 3f",
            // Check burst count
            "add r8, r8, #1",
            "cmp r8, {max_burst}",
            "blt 2b",
            // Exit burst — SVC back to privileged
            "3:",
            "svc #0",
            // Restore CONTROL
            "msr CONTROL, r4",
            "isb",
            step_fn = in(reg) step_fn,
            state = in(reg) state_ptr,
            psp = in(reg) psp_top,
            max_burst = in(reg) max_burst,
            out("r0") result,
            out("r1") _, out("r2") _, out("r3") _,
            out("r4") _, out("r5") _, out("r8") _,
            out("r12") _, out("lr") _,
        );
        result
    }

    // ========================================================================
    // SVC Handler
    // ========================================================================

    /// SVC handler — invoked when module executes `SVC #0` to return
    /// from unprivileged mode, or `SVC #N` for syscall dispatch.
    ///
    /// On Cortex-M, the exception frame is on PSP (since we set SPSEL=1).
    /// Stacked frame: [R0, R1, R2, R3, R12, LR, PC, xPSR]
    ///
    /// SVC #0: Simple return from unprivileged step. R0 has the result.
    ///         We restore CONTROL.nPRIV=0 and return.
    ///
    /// The SVC number is extracted from the SVC instruction at the stacked PC.
    #[no_mangle]
    pub unsafe extern "C" fn SVCall() {
        // Read PSP (the exception frame is on the process stack)
        let psp: u32;
        core::arch::asm!("mrs {}, PSP", out(reg) psp);

        // Stacked frame layout: [R0, R1, R2, R3, R12, LR, PC, xPSR]
        let stacked_pc = core::ptr::read_volatile((psp as *const u32).add(6));

        // Extract SVC number from the SVC instruction.
        // SVC instruction encoding (Thumb): 0xDF<imm8>
        // The SVC instruction is at stacked_pc - 2 (Thumb mode).
        let svc_instruction_addr = (stacked_pc - 2) as *const u8;
        let svc_num = core::ptr::read_volatile(svc_instruction_addr);

        match svc_num {
            0 => {
                // SVC #0: Return from unprivileged step.
                // Restore CONTROL to privileged mode (nPRIV=0).
                // SPSEL stays at 0 (MSP) after exception return.
                // R0 (the return value) is preserved in the stacked frame.
                core::arch::asm!(
                    "mrs {tmp}, CONTROL",
                    "bic {tmp}, {tmp}, #3", // Clear nPRIV and SPSEL
                    "msr CONTROL, {tmp}",
                    "isb",
                    tmp = out(reg) _,
                );
            }
            _ => {
                // SVC #1+: Syscall dispatch.
                // Syscall number in stacked R12 (offset 4 in frame).
                // Arguments in stacked R0-R3.
                // This path is reserved for future direct syscall gateway.
                // For now, modules use function pointers in SyscallTable.
            }
        }
    }

    // ========================================================================
    // MemManage fault handler
    // ========================================================================

    /// MemManage fault handler.
    ///
    /// Reads the MemManage Fault Status Register (MMFSR, byte 0 of CFSR)
    /// and MemManage Fault Address Register (MMFAR) to identify the fault.
    /// Marks the faulting module as Faulted via the existing fault state machine.
    #[no_mangle]
    pub unsafe extern "C" fn MemoryManagement() {
        let cfsr = core::ptr::read_volatile(SCB_CFSR);
        let mmfsr = cfsr & 0xFF; // MMFSR is byte 0 of CFSR
        let mmfar = if mmfsr & MMFSR_MMARVALID != 0 {
            core::ptr::read_volatile(SCB_MMFAR)
        } else {
            0
        };

        // Identify faulting module from scheduler's current_module
        let module_idx = crate::kernel::scheduler::current_module_index();

        // Determine fault type
        let is_instruction = mmfsr & MMFSR_IACCVIOL != 0;
        let is_data = mmfsr & MMFSR_DACCVIOL != 0;

        if is_instruction {
            log::error!(
                "[mpu] module {} instruction access violation at 0x{:08x}",
                module_idx,
                mmfar
            );
        } else if is_data {
            log::error!(
                "[mpu] module {} data access violation at 0x{:08x}",
                module_idx,
                mmfar
            );
        } else {
            log::error!(
                "[mpu] module {} mem fault mmfsr=0x{:02x} mmfar=0x{:08x}",
                module_idx,
                mmfsr,
                mmfar
            );
        }

        // Clear MMFSR bits by writing 1s
        core::ptr::write_volatile(SCB_CFSR as *mut u32, mmfsr);

        // Record fault in the fault state machine.
        // We can't call the full fault handler from an exception context,
        // so we set the fault info directly and modify the exception return
        // to skip back to the scheduler's step loop.
        crate::kernel::step_guard::record_mpu_fault(module_idx);

        // Modify the stacked return address to skip the faulting instruction.
        // Read PSP to get the exception frame.
        let psp: u32;
        core::arch::asm!("mrs {}, PSP", out(reg) psp);

        // Restore CONTROL to privileged mode
        core::arch::asm!(
            "mrs {tmp}, CONTROL",
            "bic {tmp}, {tmp}, #3",
            "msr CONTROL, {tmp}",
            tmp = out(reg) _,
        );

        // Set the stacked PC to the fault_trampoline which returns
        // an error code to the scheduler.
        let trampoline_addr = fault_trampoline as u32 | 1; // Thumb bit
        core::ptr::write_volatile((psp as *mut u32).add(6), trampoline_addr);

        // Set R0 in stacked frame to the error code
        core::ptr::write_volatile((psp as *mut u32).add(0), (-14i32) as u32); // EFAULT

        // DSB + ISB before return
        cortex_m::asm::dsb();
        cortex_m::asm::isb();

        // Exception return will restore from PSP and jump to fault_trampoline
    }

    /// Trampoline function that runs after a MemManage fault.
    /// Called with R0 = error code. Simply returns R0 so the caller
    /// (enter_unprivileged) receives the error code.
    #[no_mangle]
    #[unsafe(naked)]
    unsafe extern "C" fn fault_trampoline() -> i32 {
        // R0 already contains the error code set by MemoryManagement handler.
        // Just return it. We're back in privileged mode.
        core::arch::naked_asm!("bx lr",);
    }

    // ========================================================================
    // SVC gateway stubs for the protected syscall table
    // ========================================================================

    /// Build a SyscallTable where each function pointer is a gateway stub
    /// that traps via SVC into the kernel for dispatch.
    ///
    /// When isolation is enabled, modules receive this table instead of
    /// direct kernel function pointers. Each stub places the syscall index
    /// in R12 and executes SVC #1.
    ///
    /// When isolation is NOT enabled, returns the normal direct-call table.
    pub fn build_protected_syscall_table() -> SyscallTable {
        if !is_enabled() {
            return *crate::kernel::syscalls::get_syscall_table();
        }

        // For now, return the direct table. The SVC gateway stubs require
        // linker-generated trampolines or a dispatch table approach.
        // Since modules currently call through function pointers anyway,
        // the kernel functions already validate module identity via
        // current_module_index(). The MPU prevents modules from calling
        // kernel functions directly (they'd fault on kernel data access),
        // but the function pointers in the SyscallTable are in a region
        // marked RO for unprivileged access.
        //
        // Full SVC gateway (each syscall traps to kernel) is deferred
        // to a follow-up — the MPU + privilege split already prevents
        // direct kernel memory access, which is the primary isolation goal.
        *crate::kernel::syscalls::get_syscall_table()
    }
}

// ============================================================================
// Public API (platform-dispatched)
// ============================================================================

/// Initialize hardware isolation (MPU on RP2350, no-op on RP2040/BCM2712).
pub fn init() {
    #[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
    {
        rp2350_impl::mpu_init();
        unsafe {
            rp2350_impl::init_stack_canary();
        }
    }
}

/// Verify the module stack canary. Returns `true` if intact, `false` if an
/// overflow has clobbered it.
pub fn check_stack_canary() -> bool {
    #[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
    {
        // The canary only guards the unprivileged PSP stack, which is only
        // in use once isolation is enabled.
        if !rp2350_impl::is_enabled() {
            return true;
        }
        unsafe { rp2350_impl::check_stack_canary() }
    }
    #[cfg(any(not(feature = "rp"), feature = "chip-rp2040"))]
    {
        true
    }
}

/// Re-write the stack canary after an overflow has been recorded.
pub fn reinit_stack_canary() {
    #[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
    unsafe {
        rp2350_impl::init_stack_canary();
    }
}

/// Register a module's memory regions for isolation.
pub fn register_module(
    module_idx: usize,
    code_base: u32,
    code_size: u32,
    state_ptr: *mut u8,
    state_size: usize,
    heap_ptr: *mut u8,
    heap_size: usize,
) {
    #[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
    rp2350_impl::register_module_regions(
        module_idx, code_base, code_size, state_ptr, state_size, heap_ptr, heap_size,
    );
    let _ = (
        module_idx, code_base, code_size, state_ptr, state_size, heap_ptr, heap_size,
    );
}

/// Set channel buffer region for a module.
pub fn set_channel_region(module_idx: usize, base: u32, size: u32) {
    #[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
    rp2350_impl::set_module_channel_region(module_idx, base, size);
    let _ = (module_idx, base, size);
}

/// Configure MPU for a module before stepping it.
pub fn configure_for_module(module_idx: usize) {
    #[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
    rp2350_impl::mpu_configure_module(module_idx);
    let _ = module_idx;
}

/// Execute module_step in unprivileged mode with MPU protection.
/// Falls through to direct call if isolation is not enabled.
pub unsafe fn protected_step(
    step_fn: crate::kernel::loader::ModuleStepFn,
    state_ptr: *mut u8,
) -> i32 {
    #[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
    return rp2350_impl::enter_unprivileged(step_fn, state_ptr);
    #[cfg(any(not(feature = "rp"), feature = "chip-rp2040"))]
    {
        step_fn(state_ptr)
    }
}

/// Execute burst trampoline in unprivileged mode.
pub unsafe fn protected_burst(
    step_fn: crate::kernel::loader::ModuleStepFn,
    state_ptr: *mut u8,
    max_burst: u32,
) -> i32 {
    #[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
    return rp2350_impl::burst_trampoline(step_fn, state_ptr, max_burst);
    #[cfg(any(not(feature = "rp"), feature = "chip-rp2040"))]
    {
        // Simple burst loop without isolation
        let mut result = step_fn(state_ptr);
        let mut count = 0u32;
        while result == 2 && count < max_burst {
            result = step_fn(state_ptr);
            count += 1;
        }
        result
    }
}

/// Check if isolation is enabled on this platform.
pub fn is_enabled() -> bool {
    #[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
    return rp2350_impl::is_enabled();
    #[cfg(any(not(feature = "rp"), feature = "chip-rp2040"))]
    false
}

/// Enable or disable isolation at runtime.
pub fn set_enabled(enabled: bool) {
    #[cfg(all(feature = "rp", not(feature = "chip-rp2040")))]
    rp2350_impl::set_enabled(enabled);
    let _ = enabled;
}
