//! Cross-domain communication primitives for multi-core execution.
//!
//! Provides:
//! - `CrossDomainChannel`: lock-free SPSC ring buffer for cross-core data transfer
//! - `wake_core()`: mailbox-based secondary core wake (Pi 5 / QEMU)
//! - DMA40 and RP1 DMA transfer functions
//! - Non-cacheable DMA buffer arena
//!
//! ## Cache-line alignment
//!
//! On Cortex-A76 (BCM2712) the L1 cache line is 64 bytes. All shared state
//! is aligned to 64 bytes to prevent false sharing between cores.
//!
//! ## SPSC ring buffer
//!
//! Each `CrossDomainChannel` is a single-producer, single-consumer (SPSC) ring
//! buffer with 8 slots of 64 bytes each (512 bytes total data). The head index
//! is owned by the producer, the tail by the consumer. Both are cache-line
//! aligned to avoid false sharing. The ring drops messages when full.
//!
//! ## Signaling pattern
//!
//! Producer writes data, issues a `dmb ish` (data memory barrier, inner shareable),
//! then executes `sev` (send event). Consumer calls `wfe` (wait for event) and reads.
//! The DMB ensures the consumer sees the data written before the index update.

use core::sync::atomic::{AtomicU32, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Cache line size on Cortex-A76 (BCM2712 / Pi 5).
pub const CACHE_LINE: usize = 64;

/// Maximum number of cross-domain channels.
pub const MAX_CROSS_CHANNELS: usize = 32;

/// Maximum number of cores we can wake.
pub const MAX_SECONDARY_CORES: usize = 3;

/// Number of slots in each ring buffer. Must be a power of 2.
pub const RING_SLOTS: usize = 8;

/// Mask for wrapping ring indices (RING_SLOTS - 1).
const RING_MASK: u32 = (RING_SLOTS - 1) as u32;

/// Size of each slot's data payload in bytes.
pub const SLOT_DATA_SIZE: usize = 60;

/// Legacy alias for max payload size per message.
pub const CHANNEL_DATA_SIZE: usize = SLOT_DATA_SIZE;

/// Non-cacheable DMA buffer arena size (64 KB).
pub const DMA_ARENA_SIZE: usize = 64 * 1024;

// ============================================================================
// CrossDomainChannel — lock-free SPSC ring buffer
// ============================================================================

/// A single slot in the ring buffer: 4-byte length + 60-byte data = 64 bytes.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct RingSlot {
    /// Length of valid data (0..SLOT_DATA_SIZE).
    len: u32,
    /// Data payload.
    data: [u8; SLOT_DATA_SIZE],
}

impl RingSlot {
    const fn new() -> Self {
        Self {
            len: 0,
            data: [0u8; SLOT_DATA_SIZE],
        }
    }
}

/// Sentinel value indicating no producer has claimed this channel yet.
const PRODUCER_NONE: u32 = 0xFFFF_FFFF;

/// Lock-free SPSC ring buffer for cross-core communication.
///
/// The ring has 8 slots of 64 bytes each (512 bytes total data).
/// Head and tail indices are on separate cache lines to avoid false sharing.
///
/// The `producer_core` field enforces SPSC: the first core to call `send()`
/// claims the channel. Subsequent sends from a different core are rejected.
///
/// Protocol:
/// - Producer: write slot at `head & MASK`, advance head (Release), SEV
/// - Consumer: if `head != tail`, read slot at `tail & MASK`, advance tail (Release)
/// - Full: `head - tail >= RING_SLOTS` — message is dropped
#[repr(C)]
pub struct CrossDomainChannel {
    /// Producer's write index (cache-line aligned).
    head: CacheAlignedU32,
    /// Consumer's read index (cache-line aligned, separate cache line from head).
    tail: CacheAlignedU32,
    /// Core ID of the producer (set on first send, checked thereafter).
    /// PRODUCER_NONE means unclaimed.
    producer_core: AtomicU32,
    /// Channel closed flag.
    closed: AtomicU32,
    /// Ring buffer slots.
    slots: [RingSlot; RING_SLOTS],
}

/// Cache-line-aligned atomic u32 to prevent false sharing.
#[repr(C, align(64))]
struct CacheAlignedU32 {
    val: AtomicU32,
}

impl CacheAlignedU32 {
    const fn new(v: u32) -> Self {
        Self { val: AtomicU32::new(v) }
    }
}

impl CrossDomainChannel {
    /// Create a new empty channel.
    pub const fn new() -> Self {
        Self {
            head: CacheAlignedU32::new(0),
            tail: CacheAlignedU32::new(0),
            producer_core: AtomicU32::new(PRODUCER_NONE),
            closed: AtomicU32::new(0),
            slots: [const { RingSlot::new() }; RING_SLOTS],
        }
    }

    /// Send data through the channel (producer side).
    ///
    /// Returns `true` if the data was enqueued, `false` if the ring is full,
    /// the channel is closed, or a different core is trying to produce.
    ///
    /// SPSC enforcement: the first call to `send()` records the calling core as
    /// the producer. Subsequent calls from a different core return `false`.
    pub fn send(&self, src: &[u8]) -> bool {
        if self.closed.load(Ordering::Acquire) != 0 {
            return false;
        }

        let len = src.len().min(SLOT_DATA_SIZE);

        // SPSC enforcement: claim or verify producer core
        #[cfg(target_arch = "aarch64")]
        {
            let my_core = current_core_id_inline();
            let prev = self.producer_core.compare_exchange(
                PRODUCER_NONE, my_core,
                Ordering::Relaxed, Ordering::Relaxed,
            );
            match prev {
                Ok(_) => {} // We claimed it
                Err(owner) if owner == my_core => {} // Already ours
                Err(_) => return false, // Different core owns this channel
            }
        }

        let head = self.head.val.load(Ordering::Relaxed);
        let tail = self.tail.val.load(Ordering::Acquire);

        // Check if ring is full
        if head.wrapping_sub(tail) >= RING_SLOTS as u32 {
            return false; // Drop on full
        }

        // Write slot data
        let slot_idx = (head & RING_MASK) as usize;
        unsafe {
            let slot_ptr = &self.slots[slot_idx] as *const RingSlot as *mut RingSlot;
            let data_dst = core::ptr::addr_of_mut!((*slot_ptr).data) as *mut u8;
            core::ptr::copy_nonoverlapping(src.as_ptr(), data_dst, len);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*slot_ptr).len), len as u32);
        }

        // Publish the new head (Release ensures slot writes are visible first)
        self.head.val.store(head.wrapping_add(1), Ordering::Release);

        // Wake any core waiting in WFE
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("dmb ish", "sev", options(nomem, nostack));
        }

        true
    }

    /// Try to receive data from the channel (consumer side).
    ///
    /// Returns `Some(len)` with data copied into `dst`, or `None` if empty.
    /// Returns `None` also if the channel is closed and drained.
    pub fn try_recv(&self, dst: &mut [u8]) -> Option<usize> {
        let tail = self.tail.val.load(Ordering::Relaxed);
        let head = self.head.val.load(Ordering::Acquire);

        if tail == head {
            return None; // Ring is empty
        }

        let slot_idx = (tail & RING_MASK) as usize;
        let (len, copy_len);
        unsafe {
            let slot_ptr = &self.slots[slot_idx] as *const RingSlot;
            len = core::ptr::read_volatile(core::ptr::addr_of!((*slot_ptr).len)) as usize;
            copy_len = len.min(dst.len()).min(SLOT_DATA_SIZE);
            let data_src = core::ptr::addr_of!((*slot_ptr).data) as *const u8;
            core::ptr::copy_nonoverlapping(data_src, dst.as_mut_ptr(), copy_len);
        }

        // Advance tail (Release so producer sees the freed slot)
        self.tail.val.store(tail.wrapping_add(1), Ordering::Release);

        Some(copy_len)
    }

    /// Close the channel. After closing, send() will fail. try_recv() will drain
    /// remaining messages then return None.
    pub fn close(&self) {
        self.closed.store(1, Ordering::Release);
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("dmb ish", "sev", options(nomem, nostack));
        }
    }

    /// Check if the channel is closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire) != 0
    }

    /// Check if the channel has data available.
    pub fn is_full(&self) -> bool {
        let head = self.head.val.load(Ordering::Relaxed);
        let tail = self.tail.val.load(Ordering::Acquire);
        head.wrapping_sub(tail) >= RING_SLOTS as u32
    }

    /// Number of messages currently in the ring.
    pub fn count(&self) -> u32 {
        let head = self.head.val.load(Ordering::Relaxed);
        let tail = self.tail.val.load(Ordering::Acquire);
        head.wrapping_sub(tail)
    }

    /// Reset the channel to empty, unclaimed state.
    pub fn reset(&self) {
        self.head.val.store(0, Ordering::Relaxed);
        self.tail.val.store(0, Ordering::Relaxed);
        self.producer_core.store(PRODUCER_NONE, Ordering::Relaxed);
        self.closed.store(0, Ordering::Release);
    }
}

/// Read MPIDR Aff0 (core number) inline for SPSC enforcement.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn current_core_id_inline() -> u32 {
    let mpidr: u64;
    unsafe { core::arch::asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nomem, nostack)); }
    (mpidr & 0xFF) as u32
}

// Static channel pool
static CROSS_CHANNELS: [CrossDomainChannel; MAX_CROSS_CHANNELS] = [const { CrossDomainChannel::new() }; MAX_CROSS_CHANNELS];

/// Number of allocated cross-domain channels.
static CROSS_CHANNEL_COUNT: AtomicU32 = AtomicU32::new(0);

/// Allocate a cross-domain channel, returning its index.
/// Returns `None` if all channels are in use.
pub fn alloc_cross_channel() -> Option<usize> {
    let idx = CROSS_CHANNEL_COUNT.fetch_add(1, Ordering::Relaxed) as usize;
    if idx >= MAX_CROSS_CHANNELS {
        CROSS_CHANNEL_COUNT.fetch_sub(1, Ordering::Relaxed);
        return None;
    }
    CROSS_CHANNELS[idx].reset();
    Some(idx)
}

/// Get a reference to a cross-domain channel by index.
pub fn get_cross_channel(idx: usize) -> Option<&'static CrossDomainChannel> {
    if idx < MAX_CROSS_CHANNELS {
        Some(&CROSS_CHANNELS[idx])
    } else {
        None
    }
}

// ============================================================================
// Secondary core wake — Pi 5 mailbox addresses
// ============================================================================

/// Pi 5 (BCM2712) spin-table mailbox addresses for secondary cores.
/// The ARM stub parks cores 1-3 in a WFE loop polling these addresses.
/// Writing a non-zero function pointer wakes the core.
#[cfg(feature = "board-cm5")]
const PI5_MAILBOX: [usize; 3] = [
    0xd8, // Core 1
    0xe0, // Core 2
    0xe8, // Core 3
];

/// Per-core stack size (16 KB each).
pub const CORE_STACK_SIZE: usize = 16 * 1024;

/// Stack storage for secondary cores. Each core gets its own stack region.
/// Aligned to 16 bytes (AArch64 SP alignment requirement).
#[repr(C, align(16))]
struct CoreStacks([[u8; CORE_STACK_SIZE]; MAX_SECONDARY_CORES]);
static mut CORE_STACKS: CoreStacks = CoreStacks([[0u8; CORE_STACK_SIZE]; MAX_SECONDARY_CORES]);

/// Per-core entry function pointers, set by `wake_core()` before writing mailbox.
static mut CORE_ENTRIES: [Option<fn() -> !>; MAX_SECONDARY_CORES] = [None; MAX_SECONDARY_CORES];

/// Status: whether each secondary core has started.
static CORE_STARTED: [AtomicU32; MAX_SECONDARY_CORES] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];

/// Wake a secondary core on Pi 5 (BCM2712).
///
/// Writes the trampoline address to the spin-table mailbox for the given core.
/// The trampoline sets up the stack, enables NEON, and calls the entry function.
///
/// `core_id`: 1, 2, or 3 (core 0 is the boot core).
/// `entry`: function that the secondary core will execute (never returns).
///
/// On QEMU virt, secondary cores use PSCI CPU_ON — this is a stub there.
/// Returns `true` if the wake was issued, `false` if invalid core_id or already started.
#[cfg(feature = "board-cm5")]
pub fn wake_core(core_id: u8, entry: fn() -> !) -> bool {
    if core_id == 0 || core_id > 3 {
        return false;
    }
    let idx = (core_id - 1) as usize;

    // Don't wake a core that's already started
    if CORE_STARTED[idx].load(Ordering::Acquire) != 0 {
        return false;
    }

    // Store entry point for the trampoline to pick up
    unsafe { CORE_ENTRIES[idx] = Some(entry); }

    // Write trampoline address to the spin-table mailbox
    let trampoline_addr = secondary_core_trampoline as usize as u64;
    let mailbox_addr = PI5_MAILBOX[idx] as *mut u64;
    unsafe {
        // Data barrier before writing mailbox — ensure CORE_ENTRIES is visible
        core::arch::asm!("dmb ish", options(nomem, nostack));
        core::ptr::write_volatile(mailbox_addr, trampoline_addr);
        // SEV to wake the parked core from WFE
        core::arch::asm!("dsb sy", "sev", options(nomem, nostack));
    }

    true
}

/// Wake a secondary core on QEMU virt using PSCI CPU_ON (HVC).
///
/// PSCI CPU_ON function ID: 0xC4000003 (SMC64/HVC64).
/// target_cpu: MPIDR of the core to wake.
/// entry_point: physical address of the entry function.
#[cfg(not(feature = "board-cm5"))]
pub fn wake_core(core_id: u8, entry: fn() -> !) -> bool {
    if core_id == 0 || core_id > 3 {
        return false;
    }
    let idx = (core_id - 1) as usize;

    if CORE_STARTED[idx].load(Ordering::Acquire) != 0 {
        return false;
    }

    unsafe { CORE_ENTRIES[idx] = Some(entry); }

    // PSCI CPU_ON via HVC (QEMU virt uses HVC for PSCI by default)
    let psci_cpu_on: u64 = 0xC4000003; // PSCI CPU_ON (SMC64)
    let target_cpu: u64 = core_id as u64; // MPIDR Aff0
    let entry_point: u64 = secondary_core_trampoline as usize as u64;
    let context_id: u64 = 0;

    let ret: u64;
    unsafe {
        core::arch::asm!(
            "hvc #0",
            inout("x0") psci_cpu_on => ret,
            in("x1") target_cpu,
            in("x2") entry_point,
            in("x3") context_id,
            options(nomem, nostack),
        );
    }

    // PSCI returns 0 on success
    ret == 0
}

/// Trampoline for secondary cores.
///
/// Called by the firmware stub (Pi 5) or PSCI (QEMU) after core wake.
/// Sets up per-core stack, enables NEON/FP, installs exception vectors,
/// and calls the Rust entry function.
#[no_mangle]
#[unsafe(naked)]
unsafe extern "C" fn secondary_core_trampoline() -> ! {
    core::arch::naked_asm!(
        // Read MPIDR_EL1 to determine which core we are
        "mrs x0, mpidr_el1",
        "and x0, x0, #0xFF",    // Aff0 = core number (0-3)

        // Enable NEON/FP: CPACR_EL1.FPEN = 0b11
        "mov x1, #(3 << 20)",
        "msr cpacr_el1, x1",
        "isb",

        // Compute stack pointer: CORE_STACKS + (core_id - 1) * CORE_STACK_SIZE + CORE_STACK_SIZE
        // (stack grows downward, so SP = top of the core's stack region)
        "sub x1, x0, #1",       // idx = core_id - 1
        "ldr x2, ={stack_base}",
        "mov x3, #{stack_size}",
        "madd x2, x1, x3, x2",  // x2 = base + idx * size
        "add sp, x2, x3",       // sp = base + idx * size + size (top)

        // Install exception vectors (same table as core 0)
        "adr x4, exception_vectors",
        "msr vbar_el1, x4",

        // Call into Rust: secondary_core_entry(core_id)
        "bl {entry}",

        // Should never return, but just in case:
        "1: wfe",
        "b 1b",

        stack_base = sym CORE_STACKS,
        stack_size = const CORE_STACK_SIZE,
        entry = sym secondary_core_entry,
    );
}

/// Rust entry point for secondary cores. Called by the trampoline with core_id in x0.
#[no_mangle]
unsafe extern "C" fn secondary_core_entry(core_id: u64) -> ! {
    let idx = (core_id as usize).wrapping_sub(1);
    if idx >= MAX_SECONDARY_CORES {
        loop { core::arch::asm!("wfe"); }
    }

    // Mark this core as started
    CORE_STARTED[idx].store(1, Ordering::Release);

    // Call the registered entry function
    if let Some(entry) = CORE_ENTRIES[idx] {
        entry()
    } else {
        // No entry registered — park
        loop { core::arch::asm!("wfe"); }
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
#[cfg(feature = "board-cm5")]
pub const DMA40_BASE: usize = 0x1000e000;

/// RP1 DMA base address (Synopsys AXI DMA, 8 channels).
/// Accessible via the RP1 PCIe BAR.
#[cfg(feature = "board-cm5")]
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
    #[cfg(feature = "board-cm5")]
    pub fn channel_base(ch: u8) -> usize {
        super::DMA40_BASE + (ch as usize) * CHANNEL_SIZE
    }

    /// Read a DMA40 channel register.
    ///
    /// # Safety
    /// Caller must ensure the address is valid and mapped.
    #[cfg(feature = "board-cm5")]
    pub unsafe fn read_reg(ch: u8, offset: usize) -> u32 {
        let addr = channel_base(ch) + offset;
        core::ptr::read_volatile(addr as *const u32)
    }

    /// Write a DMA40 channel register.
    ///
    /// # Safety
    /// Caller must ensure the address is valid and mapped.
    #[cfg(feature = "board-cm5")]
    pub unsafe fn write_reg(ch: u8, offset: usize, val: u32) {
        let addr = channel_base(ch) + offset;
        core::ptr::write_volatile(addr as *mut u32, val);
    }

    /// Start a DMA40 memory-to-memory transfer (board-cm5 real hardware).
    ///
    /// Programs the channel registers directly (no control block chain).
    /// `ch`: DMA40 channel (0-15).
    /// `src`: source physical address.
    /// `dst`: destination physical address.
    /// `len`: transfer length in bytes.
    ///
    /// # Safety
    /// Addresses must be valid and mapped. Channel must not be in use.
    #[cfg(feature = "board-cm5")]
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
    #[cfg(feature = "board-cm5")]
    pub fn poll(ch: u8) -> bool {
        unsafe {
            let cs = read_reg(ch, CS);
            // Complete when not active, or END/ERROR flag set
            (cs & CS_ACTIVE == 0) || (cs & (CS_END | CS_ERROR) != 0)
        }
    }

    /// Start a DMA40 transfer (QEMU stub — performs memcpy immediately).
    #[cfg(not(feature = "board-cm5"))]
    pub unsafe fn start_transfer(ch: u8, src: usize, dst: usize, len: usize) {
        let _ = ch;
        core::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, len);
    }

    /// Poll a DMA40 channel (QEMU stub — always complete since start_transfer is synchronous).
    #[cfg(not(feature = "board-cm5"))]
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
    #[cfg(feature = "board-cm5")]
    pub fn channel_base(ch: u8) -> usize {
        super::RP1_DMA_BASE + (ch as usize) * CHANNEL_SIZE
    }

    /// Read an RP1 DMA channel register.
    ///
    /// # Safety
    /// Caller must ensure the address is valid and mapped.
    #[cfg(feature = "board-cm5")]
    pub unsafe fn read_reg(ch: u8, offset: usize) -> u32 {
        let addr = channel_base(ch) + offset;
        core::ptr::read_volatile(addr as *const u32)
    }

    /// Write an RP1 DMA channel register.
    ///
    /// # Safety
    /// Caller must ensure the address is valid and mapped.
    #[cfg(feature = "board-cm5")]
    pub unsafe fn write_reg(ch: u8, offset: usize, val: u32) {
        let addr = channel_base(ch) + offset;
        core::ptr::write_volatile(addr as *mut u32, val);
    }

    /// Start an RP1 DMA memory-to-memory transfer (board-cm5 real hardware).
    ///
    /// Programs the Synopsys AXI DMA channel for a single-block transfer.
    /// `ch`: RP1 DMA channel (0-7).
    /// `src`: source physical address.
    /// `dst`: destination physical address.
    /// `len`: transfer length in bytes (will be rounded down to 4-byte words).
    ///
    /// # Safety
    /// Addresses must be valid and within RP1-accessible space. Channel must not be in use.
    #[cfg(feature = "board-cm5")]
    pub unsafe fn start_transfer(ch: u8, src: usize, dst: usize, len: usize) {
        if ch as usize >= NUM_CHANNELS { return; }
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
    #[cfg(feature = "board-cm5")]
    pub fn poll(ch: u8) -> bool {
        if ch as usize >= NUM_CHANNELS { return true; }
        unsafe {
            let ch_en_addr = super::RP1_DMA_BASE + CH_EN;
            let en_val = core::ptr::read_volatile(ch_en_addr as *const u32);
            en_val & (1u32 << ch) == 0
        }
    }

    /// Start an RP1 DMA transfer (QEMU stub — performs memcpy immediately).
    #[cfg(not(feature = "board-cm5"))]
    pub unsafe fn start_transfer(ch: u8, src: usize, dst: usize, len: usize) {
        let _ = ch;
        core::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, len);
    }

    /// Poll an RP1 DMA channel (QEMU stub — always complete).
    #[cfg(not(feature = "board-cm5"))]
    pub fn poll(_ch: u8) -> bool {
        true
    }
}

// ============================================================================
// Non-cacheable DMA buffer arena (E6-S5)
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

// ============================================================================
// Domain execution — per-core module stepping
// ============================================================================

/// Maximum number of execution domains (matches scheduler).
pub const MAX_DOMAINS: usize = 4;

/// Per-domain execution state, used by secondary core loops.
///
/// The boot core (core 0) populates these during init. Secondary cores
/// read them after being woken.
pub struct DomainExecState {
    /// Which core this domain runs on (0 = boot core).
    pub core_id: u8,
    /// Number of modules in this domain.
    pub module_count: u8,
    /// Whether this domain is active.
    pub active: bool,
    /// Tick counter for this domain's loop.
    pub tick: u64,
}

impl DomainExecState {
    pub const fn new() -> Self {
        Self {
            core_id: 0,
            module_count: 0,
            active: false,
            tick: 0,
        }
    }
}

/// Global domain execution state, indexed by domain_id (0..MAX_DOMAINS).
static mut DOMAIN_STATE: [DomainExecState; MAX_DOMAINS] = [const { DomainExecState::new() }; MAX_DOMAINS];

/// Get mutable reference to domain state.
///
/// # Safety
/// Must only be called during init (single-threaded) or from the core
/// that owns the domain.
pub unsafe fn domain_state(domain_id: usize) -> &'static mut DomainExecState {
    &mut DOMAIN_STATE[domain_id]
}

/// Get shared reference to domain state.
pub fn domain_state_ref(domain_id: usize) -> &'static DomainExecState {
    unsafe { &DOMAIN_STATE[domain_id] }
}

// ============================================================================
// Cross-domain edge tracking
// ============================================================================

/// A cross-domain edge connects a module output in one domain to a module
/// input in another domain via a CrossDomainChannel.
pub struct CrossDomainEdge {
    /// Source domain.
    pub from_domain: u8,
    /// Source module index within its domain.
    pub from_module: u8,
    /// Source output port index.
    pub from_port: u8,
    /// Destination domain.
    pub to_domain: u8,
    /// Destination module index within its domain.
    pub to_module: u8,
    /// Destination input port index.
    pub to_port: u8,
    /// Index into CROSS_CHANNELS.
    pub channel_idx: u8,
    /// Local channel handle on the producer side (module writes to this).
    pub local_out_handle: i32,
    /// Local channel handle on the consumer side (module reads from this).
    pub local_in_handle: i32,
}

impl CrossDomainEdge {
    pub const fn empty() -> Self {
        Self {
            from_domain: 0,
            from_module: 0,
            from_port: 0,
            to_domain: 0,
            to_module: 0,
            to_port: 0,
            channel_idx: 0,
            local_out_handle: -1,
            local_in_handle: -1,
        }
    }
}

/// Maximum number of cross-domain edges.
pub const MAX_CROSS_EDGES: usize = 32;

/// Global cross-domain edge table.
static mut CROSS_EDGES: [CrossDomainEdge; MAX_CROSS_EDGES] = [const { CrossDomainEdge::empty() }; MAX_CROSS_EDGES];
static CROSS_EDGE_COUNT: AtomicU32 = AtomicU32::new(0);

/// Register a cross-domain edge. Returns the edge index, or None if full.
///
/// # Safety
/// Must be called during single-threaded init.
pub unsafe fn register_cross_edge(edge: CrossDomainEdge) -> Option<usize> {
    let idx = CROSS_EDGE_COUNT.load(Ordering::Relaxed) as usize;
    if idx >= MAX_CROSS_EDGES {
        return None;
    }
    CROSS_EDGES[idx] = edge;
    CROSS_EDGE_COUNT.store((idx + 1) as u32, Ordering::Relaxed);
    Some(idx)
}

/// Get the number of registered cross-domain edges.
pub fn cross_edge_count() -> usize {
    CROSS_EDGE_COUNT.load(Ordering::Relaxed) as usize
}

/// Get a reference to a cross-domain edge.
pub fn get_cross_edge(idx: usize) -> Option<&'static CrossDomainEdge> {
    if idx < cross_edge_count() {
        unsafe { Some(&CROSS_EDGES[idx]) }
    } else {
        None
    }
}
