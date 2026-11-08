//! BCM2712 cores and DMA: secondary-core wake through PSCI `CPU_ON` (Pi 5 /
//! QEMU) onto stacks of their own, the DMA40 and RP1 DMA engines, and the
//! non-cacheable DMA buffer arena. What the cores run once awake is the shared
//! domain runtime (`kernel::exec::domains`).

use core::sync::atomic::{AtomicU32, Ordering};

/// Secondary cores this kernel can wake.
pub const MAX_SECONDARY_CORES: usize = 3;

/// Non-cacheable DMA buffer arena size (64 KB).
pub const DMA_ARENA_SIZE: usize = 64 * 1024;

// ============================================================================
// Secondary core wake
// ============================================================================

/// Per-core stack size for secondary cores.
///
/// Matches the primary core's stack (`__stack_start..__stack_end` = 1 MB in
/// `linker/memory-bcm2712.x`), because a module in a secondary domain runs
/// the same deep call chains the primary stack is sized for — the P-256
/// primitives materialise curve constants on the stack per call, and a TLS
/// handshake nests several under its record and key-schedule frames.
/// Reserved in BSS (NOLOAD): it costs RAM, not image size.
pub const CORE_STACK_SIZE: usize = 1024 * 1024;

/// The unmapped page below every kernel stack.
pub const STACK_GUARD_SIZE: usize = 4096;

/// One secondary core's stack: a guard page, then the stack, which grows
/// down towards it. Page-aligned so the guard is a whole page the kernel's
/// table can leave unmapped.
#[repr(C, align(4096))]
struct CoreStackSlab {
    guard: [u8; STACK_GUARD_SIZE],
    stack: [u8; CORE_STACK_SIZE],
}

/// Byte size of one [`CoreStackSlab`]; the trampoline indexes slabs by it
/// and a secondary core's SP starts at the top of its slab.
const CORE_STACK_SLAB: usize = STACK_GUARD_SIZE + CORE_STACK_SIZE;
const _: () = assert!(core::mem::size_of::<CoreStackSlab>() == CORE_STACK_SLAB);

#[repr(C, align(4096))]
struct CoreStacks([CoreStackSlab; MAX_SECONDARY_CORES]);
static mut CORE_STACKS: CoreStacks = CoreStacks(
    [const {
        CoreStackSlab {
            guard: [0; STACK_GUARD_SIZE],
            stack: [0; CORE_STACK_SIZE],
        }
    }; MAX_SECONDARY_CORES],
);

/// The guard page under every kernel stack: the primary's
/// (`__stack_guard`, `linker/memory-bcm2712.x`) and each secondary core's.
/// The kernel's identity table and every isolated module's table leave these
/// pages unmapped.
pub fn kernel_stack_guards() -> [u64; 1 + MAX_SECONDARY_CORES] {
    extern "C" {
        static __stack_guard: u8;
    }
    let mut out = [0u64; 1 + MAX_SECONDARY_CORES];
    // Only the address of the linker symbol is taken.
    out[0] = core::ptr::addr_of!(__stack_guard) as u64;
    let base = core::ptr::addr_of!(CORE_STACKS) as u64;
    for (i, slot) in out[1..].iter_mut().enumerate() {
        *slot = base + (i * CORE_STACK_SLAB) as u64;
    }
    out
}

/// Which kernel stack guard page `addr` falls in: 0 for the primary core's,
/// `n` for secondary core `n`, `None` if it is in none of them.
pub fn stack_guard_core(addr: u64) -> Option<usize> {
    kernel_stack_guards()
        .iter()
        .position(|&g| addr >= g && addr < g + STACK_GUARD_SIZE as u64)
}

/// Per-core entry function pointer, set by `wake_core` and invoked by
/// the trampoline after it finishes CPU bring-up.
static mut CORE_ENTRIES: [Option<fn() -> !>; MAX_SECONDARY_CORES] = [None; MAX_SECONDARY_CORES];

/// 1 once the secondary has reached `secondary_core_entry`. Cleared
/// to 0 on boot.
static CORE_STARTED: [AtomicU32; MAX_SECONDARY_CORES] =
    [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)];

/// Last PSCI CPU_ON return code per core — surfaced by the primary
/// scheduler heartbeat as `[wake] core=N psci_rc=R` so a rig log
/// records the firmware's response without needing UART access.
/// `i32::MAX` means the core was never woken.
static LAST_PSCI_RET: [core::sync::atomic::AtomicI32; MAX_SECONDARY_CORES] = [
    core::sync::atomic::AtomicI32::new(i32::MAX),
    core::sync::atomic::AtomicI32::new(i32::MAX),
    core::sync::atomic::AtomicI32::new(i32::MAX),
];

pub fn last_psci_ret(core_id: u8) -> i32 {
    if core_id == 0 || core_id > 3 {
        return i32::MAX;
    }
    LAST_PSCI_RET[(core_id - 1) as usize].load(Ordering::Relaxed)
}

/// Wake a secondary core via PSCI `CPU_ON`, through the conduit the
/// platform configured (`smc` to the Pi 5's firmware at EL3, `hvc` to a
/// hypervisor). The firmware drops the core at `secondary_core_trampoline`
/// with the MMU off; `target_cpu` is the core's MPIDR as this machine
/// numbers its cores.
///
/// `core_id`: 1, 2, or 3 (core 0 is the boot core).
/// `entry`: function the secondary core will execute (never returns).
/// Returns `true` if PSCI accepted the request.
pub fn wake_core(core_id: u8, entry: fn() -> !) -> bool {
    if core_id == 0 || core_id > 3 {
        return false;
    }
    let idx = (core_id - 1) as usize;

    if CORE_STARTED[idx].load(Ordering::Acquire) != 0 {
        return false;
    }

    // SAFETY: boot-time slot publishing before the secondary core wakes;
    // CORE_STARTED check above ensures we're the sole writer.
    unsafe {
        CORE_ENTRIES[idx] = Some(entry);
    }

    let target_cpu = crate::arch::aarch64::cpu::mpidr_for_core(core_id);
    let entry_point: u64 = secondary_core_trampoline as usize as u64;

    // Complete the CORE_ENTRIES store before the woken core can read it.
    // Not `nomem`: the barrier must also keep the compiler from moving the
    // store past it.
    // SAFETY: DSB SY is an architectural barrier.
    unsafe {
        core::arch::asm!("dsb sy", options(nostack, preserves_flags));
    }

    // SAFETY: the trampoline is cold-core entry code and CORE_ENTRIES was
    // published by the barrier above.
    let ret = unsafe { crate::arch::aarch64::psci::cpu_on(target_cpu, entry_point, 0) };

    LAST_PSCI_RET[idx].store(ret, Ordering::Relaxed);
    ret == 0
}

/// Secondary-core entry stub. PSCI drops the core here with the MMU off,
/// at EL2 if that is where the firmware hands cores over. The trampoline drops
/// to EL1h (`drop_to_el1`, the same drop `_start` makes), installs core 0's
/// page tables (so the secondary participates in inner-shareable
/// cache coherency), enables MMU/caches/NEON, sets up its per-core
/// stack + exception vectors, and jumps into `secondary_core_entry`.
///
/// Sharing core 0's TTBR0/MAIR/TCR is what makes cross-core signals
/// (CORE_STARTED, channel rings, atomics on kernel statics) visible
/// across cores — without it the secondary's writes would bypass the
/// coherency protocol and never invalidate core 0's D-cache lines.
#[no_mangle]
#[unsafe(naked)]
unsafe extern "C" fn secondary_core_trampoline() -> ! {
    core::arch::naked_asm!(
        // core_id in x0, from the MPIDR affinity field this machine numbers
        // its cores by (the shift the platform configured in `cpu`, stored
        // before the boot core's MMU came on, so this uncached read sees it).
        "mrs x0, mpidr_el1",
        "ldr x9, ={core_id_shift}",
        "ldr w9, [x9]",
        "lsr x0, x0, x9",
        "and x0, x0, #0xFF",

        // Drop EL2 → EL1h if the firmware handed us off at EL2.
        crate::drop_to_el1!("x9", "x10", "2f"),
        "2:",

        // Clear any residual EL1 MMU/cache state before reinstalling.
        "mrs x9, sctlr_el1",
        "bic x9, x9, #(1 << 0)",
        "bic x9, x9, #(1 << 2)",
        "bic x9, x9, #(1 << 12)",
        "msr sctlr_el1, x9",
        "isb",
        "ic iallu",
        "tlbi vmalle1",
        "dsb sy",
        "isb",

        // Install core 0's captured page-table values + enable MMU.
        "ldr x1, ={mair_ptr}",
        "ldr x1, [x1]",
        "msr mair_el1, x1",
        "ldr x1, ={tcr_ptr}",
        "ldr x1, [x1]",
        "msr tcr_el1, x1",
        "ldr x1, ={ttbr_ptr}",
        "ldr x1, [x1]",
        "msr ttbr0_el1, x1",
        "dsb ish",
        "isb",
        "mrs x1, sctlr_el1",
        "bic x1, x1, #(1 << 1)",        // A: as core 0 (see boot_mmu::enable)
        "bic x1, x1, #(1 << 19)",       // WXN: as core 0
        "orr x1, x1, #(1 << 0)",        // M
        "orr x1, x1, #(1 << 2)",        // C
        "orr x1, x1, #(1 << 12)",       // I
        "msr sctlr_el1, x1",
        "isb",

        // CPACR_EL1.FPEN = 0b11 → NEON/FP at EL0/EL1.
        "mov x1, #(3 << 20)",
        "msr cpacr_el1, x1",
        "isb",

        "msr SPSel, #1",                // SP_EL1
        "isb",

        // SP = CORE_STACKS + (core_id - 1) * CORE_STACK_SLAB + CORE_STACK_SLAB:
        // the top of the core's slab, above its guard page and stack.
        "sub x1, x0, #1",
        "ldr x2, ={stack_base}",
        // 1 MiB + 4 KiB is not a valid `mov` immediate; load it.
        "ldr x3, ={stack_size}",
        "madd x2, x1, x3, x2",
        "add sp, x2, x3",

        "adr x4, exception_vectors",
        "msr vbar_el1, x4",

        "bl {entry}",
        // secondary_core_entry is -> !; the park is belt-and-braces.
        "1: wfe",
        "b 1b",

        stack_base = sym CORE_STACKS,
        stack_size = const CORE_STACK_SLAB,
        entry = sym secondary_core_entry,
        core_id_shift = sym crate::arch::aarch64::cpu::CORE_ID_SHIFT,
        mair_ptr = sym crate::arch::aarch64::boot_mmu::SECONDARY_MMU_MAIR,
        tcr_ptr = sym crate::arch::aarch64::boot_mmu::SECONDARY_MMU_TCR,
        ttbr_ptr = sym crate::arch::aarch64::boot_mmu::SECONDARY_MMU_TTBR0,
    );
}

/// Rust entry point for secondary cores. Called by the trampoline
/// with its core number in x0 once its MMU is up with core 0's tables.
#[no_mangle]
unsafe extern "C" fn secondary_core_entry(core_id: u64) -> ! {
    let idx = (core_id as usize).wrapping_sub(1);
    if idx >= MAX_SECONDARY_CORES {
        loop {
            core::arch::asm!("wfe");
        }
    }
    CORE_STARTED[idx].store(1, Ordering::Release);

    if let Some(entry) = CORE_ENTRIES[idx] {
        entry()
    } else {
        loop {
            core::arch::asm!("wfe");
        }
    }
}

/// Check if a secondary core has started.
pub fn is_core_started(core_id: u8) -> bool {
    if core_id == 0 || core_id > 3 {
        return false;
    }
    CORE_STARTED[(core_id - 1) as usize].load(Ordering::Acquire) != 0
}

// ============================================================================
// DMA40 register bridge (BCM2712)
// ============================================================================

/// BCM2712 DMA40 controller base address (40-bit DMA).
/// 16 channels (0-15), each with a 256-byte register block.
#[cfg(feature = "board-pi5")]
pub const DMA40_BASE: usize = 0x1000e000;

/// RP1 DMA base address (Synopsys AXI DMA, 8 channels).
/// Accessible via the RP1 PCIe BAR.
#[cfg(feature = "board-pi5")]
pub const RP1_DMA_BASE: usize = 0x1f00_8000;

/// DMA40 channel register offsets (per-channel, 256 bytes apart).
pub mod dma40 {
    /// Control/Status register offset.
    pub const CS: usize = 0x00;
    /// Control Block Address register offset.
    pub const CB_ADDR: usize = 0x04;
    /// Transfer Information register offset.
    pub const TI: usize = 0x08;
    /// Source Address register offset.
    pub const SRC: usize = 0x0C;
    /// Destination Address register offset.
    pub const DST: usize = 0x10;
    /// Transfer Length register offset.
    pub const LEN: usize = 0x14;
    /// Stride register offset.
    pub const STRIDE: usize = 0x18;
    /// Next Control Block Address register offset.
    pub const NEXT_CB: usize = 0x1C;
    /// Debug register offset.
    pub const DEBUG: usize = 0x20;

    /// Channel register block size.
    pub const CHANNEL_SIZE: usize = 0x100;

    /// DMA40 CS bit definitions.
    pub const CS_ACTIVE: u32 = 1 << 0;
    pub const CS_END: u32 = 1 << 1;
    pub const CS_ERROR: u32 = 1 << 8;
    pub const CS_RESET: u32 = 1 << 31;

    /// DMA40 TI: SRC_INC | DEST_INC (basic mem-to-mem).
    pub const TI_SRC_INC: u32 = 1 << 8;
    pub const TI_DEST_INC: u32 = 1 << 4;

    /// Compute base address for a DMA40 channel.
    #[cfg(feature = "board-pi5")]
    pub fn channel_base(ch: u8) -> usize {
        super::DMA40_BASE + (ch as usize) * CHANNEL_SIZE
    }

    /// Read a DMA40 channel register.
    ///
    /// # Safety
    /// Caller must ensure the address is valid and mapped.
    #[cfg(feature = "board-pi5")]
    pub unsafe fn read_reg(ch: u8, offset: usize) -> u32 {
        let addr = channel_base(ch) + offset;
        core::ptr::read_volatile(addr as *const u32)
    }

    /// Write a DMA40 channel register.
    ///
    /// # Safety
    /// Caller must ensure the address is valid and mapped.
    #[cfg(feature = "board-pi5")]
    pub unsafe fn write_reg(ch: u8, offset: usize, val: u32) {
        let addr = channel_base(ch) + offset;
        core::ptr::write_volatile(addr as *mut u32, val);
    }

    /// Start a DMA40 memory-to-memory transfer (board-pi5 real hardware).
    ///
    /// Programs the channel registers directly (no control block chain).
    /// `ch`: DMA40 channel (0-15).
    /// `src`: source physical address.
    /// `dst`: destination physical address.
    /// `len`: transfer length in bytes.
    ///
    /// # Safety
    /// Addresses must be valid and mapped. Channel must not be in use.
    #[cfg(feature = "board-pi5")]
    pub unsafe fn start_transfer(ch: u8, src: usize, dst: usize, len: usize) {
        let base = channel_base(ch);
        // Reset the channel
        core::ptr::write_volatile((base + CS) as *mut u32, CS_RESET);
        // Wait for reset to complete
        while core::ptr::read_volatile((base + CS) as *const u32) & CS_RESET != 0 {}
        // Program transfer
        core::ptr::write_volatile((base + TI) as *mut u32, TI_SRC_INC | TI_DEST_INC);
        core::ptr::write_volatile((base + SRC) as *mut u32, src as u32);
        core::ptr::write_volatile((base + DST) as *mut u32, dst as u32);
        core::ptr::write_volatile((base + LEN) as *mut u32, len as u32);
        core::ptr::write_volatile((base + NEXT_CB) as *mut u32, 0);
        // Start
        core::ptr::write_volatile((base + CS) as *mut u32, CS_ACTIVE);
    }

    /// Poll a DMA40 channel for completion.
    ///
    /// Returns `true` if the transfer is complete (or errored), `false` if still active.
    #[cfg(feature = "board-pi5")]
    pub fn poll(ch: u8) -> bool {
        // SAFETY: DMA40 CS register read at a fixed MMIO address mapped
        // by boot_mmu::init_page_tables; `read_reg` does the channel-base
        // arithmetic and the MMIO load.
        unsafe {
            let cs = read_reg(ch, CS);
            // Complete when not active, or END/ERROR flag set
            (cs & CS_ACTIVE == 0) || (cs & (CS_END | CS_ERROR) != 0)
        }
    }

    /// Start a DMA40 transfer (QEMU stub — performs memcpy immediately).
    ///
    /// # Safety
    /// `src` and `dst` must point to valid, non-overlapping memory regions
    /// of at least `len` bytes that are not aliased by any other reference
    /// for the duration of the call. Same contract as the real hardware
    /// path: this stub completes synchronously, but callers gate on `poll`
    /// for parity with `board-pi5`.
    #[cfg(not(feature = "board-pi5"))]
    pub unsafe fn start_transfer(ch: u8, src: usize, dst: usize, len: usize) {
        let _ = ch;
        core::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, len);
    }

    /// Poll a DMA40 channel (QEMU stub — always complete since start_transfer is synchronous).
    #[cfg(not(feature = "board-pi5"))]
    pub fn poll(_ch: u8) -> bool {
        true
    }
}

/// RP1 DMA register offsets (Synopsys AXI DMA, per-channel).
pub mod rp1_dma {
    /// Source Address Register (low 32 bits).
    pub const SAR_LO: usize = 0x00;
    /// Source Address Register (high 32 bits).
    pub const SAR_HI: usize = 0x04;
    /// Destination Address Register (low 32 bits).
    pub const DAR_LO: usize = 0x08;
    /// Destination Address Register (high 32 bits).
    pub const DAR_HI: usize = 0x0C;
    /// Block Transfer Size.
    pub const BLOCK_TS: usize = 0x10;
    /// Channel Control Register (low).
    pub const CTL_LO: usize = 0x18;
    /// Channel Control Register (high).
    pub const CTL_HI: usize = 0x1C;
    /// Channel Config Register (low).
    pub const CFG_LO: usize = 0x20;
    /// Channel Config Register (high).
    pub const CFG_HI: usize = 0x24;
    /// Channel Enable register (global, not per-channel).
    pub const CH_EN: usize = 0x018;

    /// Per-channel register block size.
    pub const CHANNEL_SIZE: usize = 0x100;

    /// Number of RP1 DMA channels.
    pub const NUM_CHANNELS: usize = 8;

    /// CTL_LO bits for a basic mem-to-mem transfer.
    pub const CTL_SMS_AXI: u32 = 0; // Source master select: AXI
    pub const CTL_DMS_AXI: u32 = 0; // Dest master select: AXI
    pub const CTL_SINC_INC: u32 = 0b00 << 4; // Source increment
    pub const CTL_DINC_INC: u32 = 0b00 << 6; // Dest increment
    pub const CTL_SRC_TR_WIDTH_32: u32 = 0b010 << 1; // 32-bit source width
    pub const CTL_DST_TR_WIDTH_32: u32 = 0b010 << 8; // 32-bit dest width

    /// CFG_LO bits.
    pub const CFG_CH_PRIOR: u32 = 0; // Priority 0 (highest)

    /// Compute base address for an RP1 DMA channel.
    #[cfg(feature = "board-pi5")]
    pub fn channel_base(ch: u8) -> usize {
        super::RP1_DMA_BASE + (ch as usize) * CHANNEL_SIZE
    }

    /// Read an RP1 DMA channel register.
    ///
    /// # Safety
    /// Caller must ensure the address is valid and mapped.
    #[cfg(feature = "board-pi5")]
    pub unsafe fn read_reg(ch: u8, offset: usize) -> u32 {
        let addr = channel_base(ch) + offset;
        core::ptr::read_volatile(addr as *const u32)
    }

    /// Write an RP1 DMA channel register.
    ///
    /// # Safety
    /// Caller must ensure the address is valid and mapped.
    #[cfg(feature = "board-pi5")]
    pub unsafe fn write_reg(ch: u8, offset: usize, val: u32) {
        let addr = channel_base(ch) + offset;
        core::ptr::write_volatile(addr as *mut u32, val);
    }

    /// Start an RP1 DMA memory-to-memory transfer (board-pi5 real hardware).
    ///
    /// Programs the Synopsys AXI DMA channel for a single-block transfer.
    /// `ch`: RP1 DMA channel (0-7).
    /// `src`: source physical address.
    /// `dst`: destination physical address.
    /// `len`: transfer length in bytes (will be rounded down to 4-byte words).
    ///
    /// # Safety
    /// Addresses must be valid and within RP1-accessible space. Channel must not be in use.
    #[cfg(feature = "board-pi5")]
    pub unsafe fn start_transfer(ch: u8, src: usize, dst: usize, len: usize) {
        if ch as usize >= NUM_CHANNELS {
            return;
        }
        let base = channel_base(ch);
        // Source address (64-bit)
        core::ptr::write_volatile((base + SAR_LO) as *mut u32, src as u32);
        core::ptr::write_volatile((base + SAR_HI) as *mut u32, (src >> 32) as u32);
        // Destination address (64-bit)
        core::ptr::write_volatile((base + DAR_LO) as *mut u32, dst as u32);
        core::ptr::write_volatile((base + DAR_HI) as *mut u32, (dst >> 32) as u32);
        // Block transfer size (in src_tr_width units — 32-bit words)
        let block_ts = (len >> 2) as u32;
        core::ptr::write_volatile((base + BLOCK_TS) as *mut u32, block_ts);
        // Control: mem-to-mem, 32-bit width, incrementing
        let ctl_lo = CTL_SINC_INC | CTL_DINC_INC | CTL_SRC_TR_WIDTH_32 | CTL_DST_TR_WIDTH_32;
        core::ptr::write_volatile((base + CTL_LO) as *mut u32, ctl_lo);
        core::ptr::write_volatile((base + CTL_HI) as *mut u32, block_ts);
        // Config
        core::ptr::write_volatile((base + CFG_LO) as *mut u32, CFG_CH_PRIOR);
        // Enable channel: write (1 << ch) to both enable and write-enable bits
        let ch_en_addr = super::RP1_DMA_BASE + CH_EN;
        let en_val = (1u32 << ch) | (1u32 << (ch + 8));
        core::ptr::write_volatile(ch_en_addr as *mut u32, en_val);
    }

    /// Poll an RP1 DMA channel for completion.
    ///
    /// Returns `true` if the channel is no longer enabled (transfer complete).
    #[cfg(feature = "board-pi5")]
    pub fn poll(ch: u8) -> bool {
        if ch as usize >= NUM_CHANNELS {
            return true;
        }
        // SAFETY: RP1_DMA_BASE + CH_EN is a fixed MMIO register mapped by
        // boot_mmu::init_page_tables; reading is side-effect-free.
        unsafe {
            let ch_en_addr = super::RP1_DMA_BASE + CH_EN;
            let en_val = core::ptr::read_volatile(ch_en_addr as *const u32);
            en_val & (1u32 << ch) == 0
        }
    }

    /// Start an RP1 DMA transfer (QEMU stub — performs memcpy immediately).
    ///
    /// # Safety
    /// `src` and `dst` must point to valid, non-overlapping memory regions
    /// of at least `len` bytes, not aliased by any other reference for the
    /// duration of the call. Mirrors the `board-pi5` hardware path's
    /// contract — this stub completes synchronously, callers still gate on
    /// `poll` for shared scheduling logic.
    #[cfg(not(feature = "board-pi5"))]
    pub unsafe fn start_transfer(ch: u8, src: usize, dst: usize, len: usize) {
        let _ = ch;
        core::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, len);
    }

    /// Poll an RP1 DMA channel (QEMU stub — always complete).
    #[cfg(not(feature = "board-pi5"))]
    pub fn poll(_ch: u8) -> bool {
        true
    }
}

// ============================================================================
// Non-cacheable DMA buffer arena
// ============================================================================

/// Non-cacheable DMA buffer arena.
///
/// On BCM2712, this region must be mapped with MAIR index 2 (Normal Non-cacheable)
/// in the MMU page tables. The linker script places this in a dedicated section
/// that the MMU setup maps as non-cacheable.
///
/// V1 strategy: all DMA buffers are allocated from this arena via a bump allocator.
/// V2 (future): selective cache maintenance (dc civac / dsb) on cacheable buffers.
/// Page-aligned so the MMU can remap this region as non-cacheable (MAIR index 2).
/// Use `dma_arena_base()` to get the runtime address for MMU table setup.
#[repr(C, align(4096))]
struct DmaArena([u8; DMA_ARENA_SIZE]);

static mut DMA_ARENA: DmaArena = DmaArena([0u8; DMA_ARENA_SIZE]);

/// Current allocation offset within the DMA arena.
static DMA_ARENA_OFFSET: AtomicU32 = AtomicU32::new(0);

/// Allocate a buffer from the non-cacheable DMA arena.
///
/// Returns a pointer to `size` bytes of non-cacheable memory, or null if
/// the arena is exhausted. The returned pointer is aligned to `align` bytes.
///
/// # Safety
/// The returned memory is valid for the lifetime of the program (static).
/// It is NOT zeroed — caller must initialize if needed.
pub fn dma_arena_alloc(size: usize, align: usize) -> *mut u8 {
    loop {
        let offset = DMA_ARENA_OFFSET.load(Ordering::Relaxed) as usize;
        // Align up
        let aligned = (offset + align - 1) & !(align - 1);
        let end = aligned + size;
        if end > DMA_ARENA_SIZE {
            return core::ptr::null_mut();
        }
        // CAS to claim the region
        if DMA_ARENA_OFFSET
            .compare_exchange_weak(
                offset as u32,
                end as u32,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            // SAFETY: `aligned + size <= DMA_ARENA_SIZE` (loop check); the
            // returned pointer points inside the static DMA arena.
            return unsafe { core::ptr::addr_of_mut!(DMA_ARENA).cast::<u8>().add(aligned) };
        }
    }
}

/// Get the base address of the DMA arena (for MMU mapping).
pub fn dma_arena_base() -> usize {
    core::ptr::addr_of!(DMA_ARENA) as usize
}

/// Get the total size of the DMA arena.
pub fn dma_arena_size() -> usize {
    DMA_ARENA_SIZE
}

/// Get the current allocation offset (bytes used).
pub fn dma_arena_used() -> usize {
    DMA_ARENA_OFFSET.load(Ordering::Relaxed) as usize
}

/// Reset the DMA arena (e.g. on reboot). Not safe if DMA is active.
pub fn dma_arena_reset() {
    DMA_ARENA_OFFSET.store(0, Ordering::Relaxed);
}
