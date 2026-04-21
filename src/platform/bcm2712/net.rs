//! DMA ring allocator for kernel-bypass NIC.
//!
//! Provides:
//! - NicRingDescriptor: 16-byte DMA descriptor
//! - NicRing: descriptor ring (head/tail) + buffer pool
//! - Static DMA arena for physically contiguous allocation
//! - Ring create/destroy/info syscalls
//!
//! The ring uses a simple producer/consumer model:
//! - RX: NIC writes descriptors at head, driver reads at tail
//! - TX: Driver writes descriptors at head, NIC reads at tail

#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, Ordering};

// ============================================================================
// Constants
// ============================================================================

/// Maximum NIC ring instances.
pub const MAX_NIC_RINGS: usize = 8;

/// Maximum descriptors per ring (must be power of 2).
pub const MAX_DESC_COUNT: usize = 256;

/// Default buffer size per descriptor (MTU + overhead).
pub const DEFAULT_BUF_SIZE: usize = 2048;

/// Maximum buffers per ring.
pub const MAX_BUFS: usize = 256;

/// DMA arena size (2MB, naturally aligned).
pub const DMA_ARENA_SIZE: usize = 2 * 1024 * 1024;

/// DMA arena alignment (2MB for huge page compatibility).
const DMA_ARENA_ALIGN: usize = 2 * 1024 * 1024;

// ============================================================================
// NIC ring descriptor (matches Cadence GEM / generic NIC DMA descriptor)
// ============================================================================

/// 16-byte DMA descriptor for NIC ring buffers.
///
/// Layout is designed to be compatible with Cadence GEM descriptors
/// but generic enough for Intel E810 and Mellanox ConnectX-5.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct NicRingDescriptor {
    /// Physical address of the buffer (low 32 bits).
    pub addr_lo: u32,
    /// Physical address of the buffer (high 32 bits) + flags.
    pub addr_hi_flags: u32,
    /// Buffer length / bytes used.
    pub length: u32,
    /// Status/control flags.
    pub status: u32,
}

impl NicRingDescriptor {
    pub const fn empty() -> Self {
        Self {
            addr_lo: 0,
            addr_hi_flags: 0,
            length: 0,
            status: 0,
        }
    }

    /// Get the full 64-bit physical address.
    pub fn phys_addr(&self) -> u64 {
        let hi = (self.addr_hi_flags & 0x0000_FFFF) as u64;
        (hi << 32) | self.addr_lo as u64
    }

    /// Set the physical address (preserves upper flags).
    pub fn set_phys_addr(&mut self, addr: u64) {
        self.addr_lo = addr as u32;
        let hi_flags = self.addr_hi_flags & 0xFFFF_0000;
        self.addr_hi_flags = hi_flags | ((addr >> 32) as u32 & 0x0000_FFFF);
    }
}

// Descriptor status bits
pub const DESC_OWNED_BY_NIC: u32 = 1 << 0;
pub const DESC_OWNED_BY_DRIVER: u32 = 1 << 1;
pub const DESC_WRAP: u32 = 1 << 2;
pub const DESC_LAST: u32 = 1 << 3;
pub const DESC_SOP: u32 = 1 << 4; // Start of packet
pub const DESC_EOP: u32 = 1 << 5; // End of packet

// ============================================================================
// NicRing
// ============================================================================

/// State for one NIC ring (RX or TX descriptor ring + buffer pool).
pub struct NicRing {
    /// Whether this ring slot is allocated.
    active: bool,
    /// RX descriptor count.
    rx_desc_count: u16,
    /// TX descriptor count.
    tx_desc_count: u16,
    /// Buffer size per descriptor.
    buf_size: u16,
    /// Number of buffers allocated.
    buf_count: u16,

    /// Offset into DMA arena for RX descriptors.
    rx_desc_offset: usize,
    /// Offset into DMA arena for TX descriptors.
    tx_desc_offset: usize,
    /// Offset into DMA arena for buffer pool.
    buf_pool_offset: usize,

    /// RX ring head (written by NIC/driver).
    rx_head: u32,
    /// RX ring tail (read position).
    rx_tail: u32,
    /// TX ring head (written by driver).
    tx_head: u32,
    /// TX ring tail (completed by NIC).
    tx_tail: u32,

    /// Total bytes allocated from DMA arena.
    total_alloc: usize,
}

impl NicRing {
    const fn empty() -> Self {
        Self {
            active: false,
            rx_desc_count: 0,
            tx_desc_count: 0,
            buf_size: 0,
            buf_count: 0,
            rx_desc_offset: 0,
            tx_desc_offset: 0,
            buf_pool_offset: 0,
            rx_head: 0,
            rx_tail: 0,
            tx_head: 0,
            tx_tail: 0,
            total_alloc: 0,
        }
    }
}

// ============================================================================
// Static state
// ============================================================================

/// DMA arena: physically contiguous, 2MB-aligned buffer.
/// On aarch64 this is in BSS and the linker places it at a known physical address.
/// On RP targets this is unused (NIC rings are BCM2712-only).
#[cfg(feature = "chip-bcm2712")]
#[repr(C, align(2097152))]
struct DmaArena([u8; DMA_ARENA_SIZE]);

#[cfg(feature = "chip-bcm2712")]
static mut DMA_ARENA: DmaArena = DmaArena([0u8; DMA_ARENA_SIZE]);

/// Current allocation offset in the DMA arena.
#[cfg(feature = "chip-bcm2712")]
static DMA_ARENA_OFFSET: AtomicU32 = AtomicU32::new(0);

/// Return the DMA arena base address for MMU non-cacheable mapping.
/// Called once during early boot (init_page_tables) to identify which
/// 2MB L2 entry to mark as Normal Non-cacheable.
#[cfg(feature = "chip-bcm2712")]
pub fn dma_arena_base() -> usize {
    (&raw const DMA_ARENA) as *const _ as usize
}

#[cfg(not(feature = "chip-bcm2712"))]
pub fn dma_arena_base() -> usize {
    0
}

// ----------------------------------------------------------------------------
// PCIe1 (external / NVMe HAT+) DMA arena
// ----------------------------------------------------------------------------
//
// The BCM2712 PCIe1 inbound ATU — whether programmed by Linux or left at
// VPU defaults — only covers PCI bus addresses `0..0xFFFFFFFF` (see
// `hw/nvme_trace/baseline/README.md`: Linux's userspace nvme_trace fails
// with pagemap addresses above 4 GB, which is why baseline capture cuts
// off mid-Identify). Any DMA target has to be reachable in that 4 GB
// window with an identity PCI↔AXI mapping.
//
// This arena therefore lives in low DRAM as a BSS-backed static, the same
// way `DMA_ARENA` above does. `init_page_tables` flips the enclosing 2 MB
// L2 entry to Normal Non-Cacheable so CPU and device see coherent memory
// without explicit maintenance. PCI bus addr == CPU/AXI addr under the
// inbound identity window.

#[cfg(feature = "chip-bcm2712")]
pub const PCIE1_DMA_ARENA_SIZE: usize = 2 * 1024 * 1024;

#[cfg(feature = "chip-bcm2712")]
#[repr(C, align(2097152))]
struct Pcie1DmaArena([u8; PCIE1_DMA_ARENA_SIZE]);

#[cfg(feature = "chip-bcm2712")]
static mut PCIE1_DMA_ARENA: Pcie1DmaArena = Pcie1DmaArena([0u8; PCIE1_DMA_ARENA_SIZE]);

#[cfg(feature = "chip-bcm2712")]
static PCIE1_DMA_OFFSET: AtomicU32 = AtomicU32::new(0);

/// Return the PCIe1 DMA arena base (CPU physical / AXI / identity-mapped
/// virtual). Consumed by `init_page_tables` to flip the enclosing 2 MB
/// L2 entry to Normal Non-Cacheable.
#[cfg(feature = "chip-bcm2712")]
pub fn pcie1_dma_arena_base() -> usize {
    (&raw const PCIE1_DMA_ARENA) as *const _ as usize
}

#[cfg(not(feature = "chip-bcm2712"))]
pub fn pcie1_dma_arena_base() -> usize {
    0
}

/// Allocate physically contiguous memory from the PCIe1 DMA arena.
/// Returns the physical address (identity-mapped = CPU virt = PCI bus
/// addr under the VPU-default inbound window) or 0 on failure.
/// `align` must be a power of 2, minimum 16.
#[cfg(feature = "chip-bcm2712")]
pub fn pcie1_dma_alloc_contig(size: usize, align: usize) -> usize {
    let a = if align < 16 { 16 } else { align };
    let cur = PCIE1_DMA_OFFSET.load(Ordering::Relaxed) as usize;
    let aligned_start = (cur + a - 1) & !(a - 1);
    let aligned_size = (size + 15) & !15;
    let new_end = aligned_start + aligned_size;
    if new_end > PCIE1_DMA_ARENA_SIZE {
        return 0;
    }
    let prev = PCIE1_DMA_OFFSET.compare_exchange(
        cur as u32,
        new_end as u32,
        Ordering::AcqRel,
        Ordering::Relaxed,
    );
    match prev {
        Ok(_) => pcie1_dma_arena_base() + aligned_start,
        Err(_) => 0,
    }
}

#[cfg(not(feature = "chip-bcm2712"))]
pub fn pcie1_dma_alloc_contig(_size: usize, _align: usize) -> usize {
    0
}

// ----------------------------------------------------------------------------
// Streaming (cacheable) PCIe1 DMA arena
// ----------------------------------------------------------------------------
//
// Mirror of PCIE1_DMA_ARENA above, but intentionally NOT flipped to
// Normal-Non-Cacheable by `init_page_tables`. The enclosing 2 MB L2
// block stays at its default WB-WA cacheable attributes, so CPU writes
// hit the cache and must be explicitly flushed (`dc cvac`) to reach
// PoC before any device DMA reads them. Conversely, after a device
// writes into a streaming buffer the CPU must `dc ivac` before reading
// so any stale speculatively-loaded line is dropped.
//
// Lives as a BSS-backed static so its physical address is identity-
// mapped and < 4 GB (PCIe1 inbound ATU only covers PCI 0..0xFFFFFFFF).
// PCI bus addr == arm_addr | PCI_DMA_OFFSET under the BAR1 inbound
// UBUS REMAP window programmed by the PCIe platform code.

#[cfg(feature = "chip-bcm2712")]
pub const PCIE1_STREAM_ARENA_SIZE: usize = 2 * 1024 * 1024;

#[cfg(feature = "chip-bcm2712")]
#[repr(C, align(2097152))]
struct Pcie1StreamArena([u8; PCIE1_STREAM_ARENA_SIZE]);

#[cfg(feature = "chip-bcm2712")]
static mut PCIE1_STREAM_ARENA: Pcie1StreamArena = Pcie1StreamArena([0u8; PCIE1_STREAM_ARENA_SIZE]);

#[cfg(feature = "chip-bcm2712")]
static PCIE1_STREAM_OFFSET: AtomicU32 = AtomicU32::new(0);

/// Return the streaming PCIe1 DMA arena base address (CPU physical ==
/// identity-mapped virtual). Unlike `pcie1_dma_arena_base`, this region
/// stays at its default cacheable MAIR attributes.
#[cfg(feature = "chip-bcm2712")]
pub fn pcie1_stream_arena_base() -> usize {
    (&raw const PCIE1_STREAM_ARENA) as *const _ as usize
}

#[cfg(not(feature = "chip-bcm2712"))]
pub fn pcie1_stream_arena_base() -> usize {
    0
}

/// Allocate physically contiguous STREAMING (cacheable) memory from the
/// PCIe1 streaming arena. Returns the physical address or 0 on failure.
/// Callers MUST flush (`dc cvac`) before device-reads and invalidate
/// (`dc ivac`) before CPU-reads of device-written regions.
#[cfg(feature = "chip-bcm2712")]
pub fn pcie1_dma_alloc_streaming(size: usize, align: usize) -> usize {
    let a = if align < 16 { 16 } else { align };
    let cur = PCIE1_STREAM_OFFSET.load(Ordering::Relaxed) as usize;
    let aligned_start = (cur + a - 1) & !(a - 1);
    let aligned_size = (size + 15) & !15;
    let new_end = aligned_start + aligned_size;
    if new_end > PCIE1_STREAM_ARENA_SIZE {
        return 0;
    }
    let prev = PCIE1_STREAM_OFFSET.compare_exchange(
        cur as u32,
        new_end as u32,
        Ordering::AcqRel,
        Ordering::Relaxed,
    );
    match prev {
        Ok(_) => pcie1_stream_arena_base() + aligned_start,
        Err(_) => 0,
    }
}

#[cfg(not(feature = "chip-bcm2712"))]
pub fn pcie1_dma_alloc_streaming(_size: usize, _align: usize) -> usize {
    0
}

/// NIC ring slots.
static mut NIC_RINGS: [NicRing; MAX_NIC_RINGS] = [const { NicRing::empty() }; MAX_NIC_RINGS];

// ============================================================================
// DMA arena allocator
// ============================================================================

/// Allocate `size` bytes from the DMA arena (16-byte aligned).
/// Returns offset into arena, or usize::MAX on failure.
#[cfg(feature = "chip-bcm2712")]
fn dma_alloc(size: usize) -> usize {
    let aligned_size = (size + 15) & !15;
    let offset = DMA_ARENA_OFFSET.fetch_add(aligned_size as u32, Ordering::Relaxed) as usize;
    if offset + aligned_size > DMA_ARENA_SIZE {
        // Revert
        DMA_ARENA_OFFSET.fetch_sub(aligned_size as u32, Ordering::Relaxed);
        return usize::MAX;
    }
    offset
}

/// Get the virtual address for an arena offset.
#[cfg(feature = "chip-bcm2712")]
fn dma_arena_ptr(offset: usize) -> *mut u8 {
    unsafe { (&raw mut DMA_ARENA.0 as *mut u8).add(offset) }
}

/// Get the physical address for an arena offset.
/// On aarch64 bare-metal with identity mapping, phys == virt.
#[cfg(feature = "chip-bcm2712")]
fn dma_arena_phys(offset: usize) -> u64 {
    dma_arena_ptr(offset) as u64
}

/// Allocate physically contiguous memory from the DMA arena.
/// Returns the physical address, or 0 on failure.
/// `align` must be a power of 2 (minimum 16).
#[cfg(feature = "chip-bcm2712")]
pub fn dma_alloc_contig(size: usize, align: usize) -> usize {
    let a = if align < 16 { 16 } else { align };
    // Round current offset up to alignment
    let cur = DMA_ARENA_OFFSET.load(Ordering::Relaxed) as usize;
    let aligned_start = (cur + a - 1) & !(a - 1);
    let aligned_size = (size + 15) & !15;
    let new_end = aligned_start + aligned_size;
    if new_end > DMA_ARENA_SIZE {
        return 0;
    }
    // Try to claim this range
    let prev = DMA_ARENA_OFFSET.compare_exchange(
        cur as u32,
        new_end as u32,
        Ordering::AcqRel,
        Ordering::Relaxed,
    );
    match prev {
        Ok(_) => dma_arena_ptr(aligned_start) as usize,
        Err(_) => 0, // concurrent allocation, caller retries
    }
}

#[cfg(not(feature = "chip-bcm2712"))]
pub fn dma_alloc_contig(_size: usize, _align: usize) -> usize {
    0
}

// ============================================================================
// Ring create / destroy / info
// ============================================================================

/// Create a NIC ring with the specified parameters.
///
/// Returns ring handle (0..MAX_NIC_RINGS-1) on success, or negative errno.
pub fn ring_create(rx_desc_count: u16, tx_desc_count: u16, buf_size: u16, buf_count: u16) -> i32 {
    #[cfg(not(feature = "chip-bcm2712"))]
    {
        let _ = (rx_desc_count, tx_desc_count, buf_size, buf_count);
        return crate::kernel::errno::ENOSYS;
    }

    #[cfg(feature = "chip-bcm2712")]
    unsafe {
        // Validate
        if rx_desc_count as usize > MAX_DESC_COUNT
            || tx_desc_count as usize > MAX_DESC_COUNT
            || buf_count as usize > MAX_BUFS
            || buf_size == 0
        {
            return crate::kernel::errno::EINVAL;
        }

        // Find free slot
        let mut slot = MAX_NIC_RINGS;
        for i in 0..MAX_NIC_RINGS {
            if !NIC_RINGS[i].active {
                slot = i;
                break;
            }
        }
        if slot >= MAX_NIC_RINGS {
            return crate::kernel::errno::ENOMEM;
        }

        // Calculate sizes
        let desc_size = core::mem::size_of::<NicRingDescriptor>();
        let rx_desc_bytes = rx_desc_count as usize * desc_size;
        let tx_desc_bytes = tx_desc_count as usize * desc_size;
        let buf_pool_bytes = buf_count as usize * buf_size as usize;
        let total = rx_desc_bytes + tx_desc_bytes + buf_pool_bytes;

        // Allocate from DMA arena
        let rx_off = dma_alloc(rx_desc_bytes);
        if rx_off == usize::MAX {
            return crate::kernel::errno::ENOMEM;
        }
        let tx_off = dma_alloc(tx_desc_bytes);
        if tx_off == usize::MAX {
            return crate::kernel::errno::ENOMEM;
        }
        let buf_off = dma_alloc(buf_pool_bytes);
        if buf_off == usize::MAX {
            return crate::kernel::errno::ENOMEM;
        }

        // Zero the allocated regions
        core::ptr::write_bytes(dma_arena_ptr(rx_off), 0, rx_desc_bytes);
        core::ptr::write_bytes(dma_arena_ptr(tx_off), 0, tx_desc_bytes);
        core::ptr::write_bytes(dma_arena_ptr(buf_off), 0, buf_pool_bytes);

        // Initialize RX descriptors with buffer addresses
        let mut i = 0u16;
        while i < rx_desc_count {
            if (i as usize) < buf_count as usize {
                let desc_ptr =
                    dma_arena_ptr(rx_off + (i as usize) * desc_size) as *mut NicRingDescriptor;
                let buf_phys = dma_arena_phys(buf_off + (i as usize) * buf_size as usize);
                (*desc_ptr).set_phys_addr(buf_phys);
                (*desc_ptr).length = buf_size as u32;
                (*desc_ptr).status = DESC_OWNED_BY_NIC;
            }
            i += 1;
        }

        // Mark last RX descriptor with wrap bit
        if rx_desc_count > 0 {
            let last_idx = (rx_desc_count - 1) as usize;
            let last_desc = dma_arena_ptr(rx_off + last_idx * desc_size) as *mut NicRingDescriptor;
            (*last_desc).status |= DESC_WRAP;
        }

        NIC_RINGS[slot] = NicRing {
            active: true,
            rx_desc_count,
            tx_desc_count,
            buf_size,
            buf_count,
            rx_desc_offset: rx_off,
            tx_desc_offset: tx_off,
            buf_pool_offset: buf_off,
            rx_head: 0,
            rx_tail: 0,
            tx_head: 0,
            tx_tail: 0,
            total_alloc: total,
        };

        log::info!(
            "[nic_ring] ring {} created: rx={} tx={} bufs={}x{} total={}",
            slot,
            rx_desc_count,
            tx_desc_count,
            buf_count,
            buf_size,
            total
        );
        slot as i32
    }
}

/// Destroy a NIC ring and free its resources.
pub fn ring_destroy(ring_handle: i32) -> i32 {
    if ring_handle < 0 || ring_handle as usize >= MAX_NIC_RINGS {
        return crate::kernel::errno::EINVAL;
    }
    unsafe {
        let ring = &mut NIC_RINGS[ring_handle as usize];
        if !ring.active {
            return crate::kernel::errno::EINVAL;
        }
        ring.active = false;
        // Note: DMA arena is bump-allocated; we don't reclaim space.
        // This is acceptable for long-lived NIC rings.
        log::info!("[nic_ring] ring {} destroyed", ring_handle);
        0
    }
}

/// Get ring info: returns virtual addresses and sizes.
///
/// Output format (written to arg):
/// [rx_desc_addr:u64 LE, rx_desc_count:u16 LE,
///  tx_desc_addr:u64 LE, tx_desc_count:u16 LE,
///  buf_pool_addr:u64 LE, buf_size:u16 LE, buf_count:u16 LE]
/// Total: 32 bytes
pub fn ring_info(ring_handle: i32, out: *mut u8, out_len: usize) -> i32 {
    if ring_handle < 0 || ring_handle as usize >= MAX_NIC_RINGS {
        return crate::kernel::errno::EINVAL;
    }
    if out.is_null() || out_len < 32 {
        return crate::kernel::errno::EINVAL;
    }

    #[cfg(not(feature = "chip-bcm2712"))]
    {
        return crate::kernel::errno::ENOSYS;
    }

    #[cfg(feature = "chip-bcm2712")]
    unsafe {
        let ring = &NIC_RINGS[ring_handle as usize];
        if !ring.active {
            return crate::kernel::errno::EINVAL;
        }

        let rx_addr = dma_arena_ptr(ring.rx_desc_offset) as u64;
        let tx_addr = dma_arena_ptr(ring.tx_desc_offset) as u64;
        let buf_addr = dma_arena_ptr(ring.buf_pool_offset) as u64;

        let mut off = 0usize;
        // RX desc addr (8 bytes)
        core::ptr::copy_nonoverlapping(rx_addr.to_le_bytes().as_ptr(), out.add(off), 8);
        off += 8;
        // RX desc count (2 bytes)
        core::ptr::copy_nonoverlapping(ring.rx_desc_count.to_le_bytes().as_ptr(), out.add(off), 2);
        off += 2;
        // TX desc addr (8 bytes)
        core::ptr::copy_nonoverlapping(tx_addr.to_le_bytes().as_ptr(), out.add(off), 8);
        off += 8;
        // TX desc count (2 bytes)
        core::ptr::copy_nonoverlapping(ring.tx_desc_count.to_le_bytes().as_ptr(), out.add(off), 2);
        off += 2;
        // Buffer pool addr (8 bytes)
        core::ptr::copy_nonoverlapping(buf_addr.to_le_bytes().as_ptr(), out.add(off), 8);
        off += 8;
        // Buffer size (2 bytes)
        core::ptr::copy_nonoverlapping(ring.buf_size.to_le_bytes().as_ptr(), out.add(off), 2);
        off += 2;
        // Buffer count (2 bytes)
        core::ptr::copy_nonoverlapping(ring.buf_count.to_le_bytes().as_ptr(), out.add(off), 2);

        32
    }
}

// ============================================================================
// NicRing buffer acquire/release (for EdgeClass::NicRing)
// ============================================================================

/// Acquire an RX buffer: returns (buffer pointer, length) for the next
/// completed RX descriptor. Returns (null, 0) if no packets available.
#[cfg(feature = "chip-bcm2712")]
pub fn nic_ring_acquire_rx(ring_handle: i32) -> (*mut u8, usize) {
    if ring_handle < 0 || ring_handle as usize >= MAX_NIC_RINGS {
        return (core::ptr::null_mut(), 0);
    }
    unsafe {
        let ring = &mut NIC_RINGS[ring_handle as usize];
        if !ring.active || ring.rx_desc_count == 0 {
            return (core::ptr::null_mut(), 0);
        }

        let desc_size = core::mem::size_of::<NicRingDescriptor>();
        let idx = (ring.rx_tail % ring.rx_desc_count as u32) as usize;
        let desc = dma_arena_ptr(ring.rx_desc_offset + idx * desc_size) as *const NicRingDescriptor;

        // Check if NIC has completed this descriptor
        let status = core::ptr::read_volatile(&(*desc).status);
        if status & DESC_OWNED_BY_NIC != 0 {
            return (core::ptr::null_mut(), 0);
        }

        let len = core::ptr::read_volatile(&(*desc).length) as usize;
        let buf_off = ring.buf_pool_offset + idx * ring.buf_size as usize;
        let buf_ptr = dma_arena_ptr(buf_off);

        // Cache maintenance: invalidate before CPU reads
        #[cfg(target_arch = "aarch64")]
        cache_invalidate(buf_ptr, len);

        (buf_ptr, len)
    }
}

/// Release an RX buffer back to NIC ownership.
#[cfg(feature = "chip-bcm2712")]
pub fn nic_ring_release_rx(ring_handle: i32) {
    if ring_handle < 0 || ring_handle as usize >= MAX_NIC_RINGS {
        return;
    }
    unsafe {
        let ring = &mut NIC_RINGS[ring_handle as usize];
        if !ring.active || ring.rx_desc_count == 0 {
            return;
        }

        let desc_size = core::mem::size_of::<NicRingDescriptor>();
        let idx = (ring.rx_tail % ring.rx_desc_count as u32) as usize;
        let desc = dma_arena_ptr(ring.rx_desc_offset + idx * desc_size) as *mut NicRingDescriptor;

        // Reset descriptor
        (*desc).length = ring.buf_size as u32;
        let mut new_status = DESC_OWNED_BY_NIC;
        if idx == (ring.rx_desc_count - 1) as usize {
            new_status |= DESC_WRAP;
        }
        core::ptr::write_volatile(&mut (*desc).status, new_status);

        ring.rx_tail = ring.rx_tail.wrapping_add(1);
    }
}

/// Acquire an empty TX buffer. Returns (buffer pointer, max_len).
#[cfg(feature = "chip-bcm2712")]
pub fn nic_ring_acquire_tx(ring_handle: i32) -> (*mut u8, usize) {
    if ring_handle < 0 || ring_handle as usize >= MAX_NIC_RINGS {
        return (core::ptr::null_mut(), 0);
    }
    unsafe {
        let ring = &mut NIC_RINGS[ring_handle as usize];
        if !ring.active || ring.tx_desc_count == 0 {
            return (core::ptr::null_mut(), 0);
        }

        // Check if there's a free TX descriptor
        let used = ring.tx_head.wrapping_sub(ring.tx_tail);
        if used >= ring.tx_desc_count as u32 {
            return (core::ptr::null_mut(), 0);
        }

        let idx = (ring.tx_head % ring.tx_desc_count as u32) as usize;
        // TX buffers come from the second half of the buffer pool
        let buf_idx = ring.rx_desc_count as usize + idx;
        if buf_idx >= ring.buf_count as usize {
            return (core::ptr::null_mut(), 0);
        }
        let buf_off = ring.buf_pool_offset + buf_idx * ring.buf_size as usize;
        (dma_arena_ptr(buf_off), ring.buf_size as usize)
    }
}

/// Submit a TX buffer to the NIC.
#[cfg(feature = "chip-bcm2712")]
pub fn nic_ring_submit_tx(ring_handle: i32, len: usize) {
    if ring_handle < 0 || ring_handle as usize >= MAX_NIC_RINGS || len == 0 {
        return;
    }
    unsafe {
        let ring = &mut NIC_RINGS[ring_handle as usize];
        if !ring.active || ring.tx_desc_count == 0 {
            return;
        }

        let desc_size = core::mem::size_of::<NicRingDescriptor>();
        let idx = (ring.tx_head % ring.tx_desc_count as u32) as usize;
        let desc = dma_arena_ptr(ring.tx_desc_offset + idx * desc_size) as *mut NicRingDescriptor;

        let buf_idx = ring.rx_desc_count as usize + idx;
        let buf_phys = dma_arena_phys(ring.buf_pool_offset + buf_idx * ring.buf_size as usize);

        (*desc).set_phys_addr(buf_phys);
        (*desc).length = len as u32;

        // Cache maintenance: clean before NIC reads
        let buf_ptr = dma_arena_ptr(ring.buf_pool_offset + buf_idx * ring.buf_size as usize);
        #[cfg(target_arch = "aarch64")]
        cache_clean(buf_ptr, len);

        let mut new_status = DESC_OWNED_BY_NIC | DESC_SOP | DESC_EOP;
        if idx == (ring.tx_desc_count - 1) as usize {
            new_status |= DESC_WRAP;
        }
        // Write status last (memory barrier before NIC sees it)
        core::sync::atomic::fence(Ordering::Release);
        core::ptr::write_volatile(&mut (*desc).status, new_status);

        ring.tx_head = ring.tx_head.wrapping_add(1);
    }
}

// ============================================================================
// Cache maintenance
// ============================================================================

/// Clean data cache by virtual address range (write-back dirty lines).
#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn cache_clean(addr: *mut u8, size: usize) {
    let mut ptr = addr as usize & !63; // align to cache line
    let end = (addr as usize + size + 63) & !63;
    while ptr < end {
        core::arch::asm!("dc civac, {}", in(reg) ptr, options(nostack));
        ptr += 64;
    }
    core::arch::asm!("dsb sy", options(nostack));
}

/// Invalidate data cache by virtual address range.
#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn cache_invalidate(addr: *mut u8, size: usize) {
    let mut ptr = addr as usize & !63;
    let end = (addr as usize + size + 63) & !63;
    while ptr < end {
        core::arch::asm!("dc ivac, {}", in(reg) ptr, options(nostack));
        ptr += 64;
    }
    core::arch::asm!("dsb sy", options(nostack));
}

// ============================================================================
// Syscall handlers
// ============================================================================

/// NIC_RING_CREATE: arg=[rx_desc_count:u16, tx_desc_count:u16, buf_size:u16, buf_count:u16] (8 bytes).
pub unsafe fn syscall_ring_create(arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 8 {
        return crate::kernel::errno::EINVAL;
    }
    let rx_desc = u16::from_le_bytes([*arg, *arg.add(1)]);
    let tx_desc = u16::from_le_bytes([*arg.add(2), *arg.add(3)]);
    let buf_sz = u16::from_le_bytes([*arg.add(4), *arg.add(5)]);
    let buf_cnt = u16::from_le_bytes([*arg.add(6), *arg.add(7)]);
    ring_create(rx_desc, tx_desc, buf_sz, buf_cnt)
}

/// NIC_RING_DESTROY: arg=[ring_handle:u8] (1 byte).
pub unsafe fn syscall_ring_destroy(arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 1 {
        return crate::kernel::errno::EINVAL;
    }
    ring_destroy(*arg as i32)
}

/// NIC_RING_INFO: arg=output buffer (32 bytes). handle=ring_handle.
pub unsafe fn syscall_ring_info(handle: i32, arg: *mut u8, arg_len: usize) -> i32 {
    ring_info(handle, arg, arg_len)
}

// ============================================================================
// RSS (Receive-Side Scaling) — per-queue ring steering
// ============================================================================

/// Maximum number of RSS queues (one per core).
pub const MAX_RSS_QUEUES: usize = 4;

/// RSS queue-to-ring mapping.
/// Each entry maps a queue index to a NIC ring handle.
static mut RSS_QUEUE_MAP: [i32; MAX_RSS_QUEUES] = [-1; MAX_RSS_QUEUES];
static mut RSS_QUEUE_COUNT: usize = 0;

/// Register a NIC ring as an RSS queue.
///
/// Returns queue index (0..MAX_RSS_QUEUES-1) on success, or -1 if full.
pub fn rss_register_queue(ring_handle: i32) -> i32 {
    unsafe {
        if RSS_QUEUE_COUNT >= MAX_RSS_QUEUES {
            return -1;
        }
        let idx = RSS_QUEUE_COUNT;
        RSS_QUEUE_MAP[idx] = ring_handle;
        RSS_QUEUE_COUNT += 1;
        idx as i32
    }
}

/// Steer a packet to a queue based on its RSS hash.
///
/// Uses the Toeplitz hash (or any u32 hash) to select a queue/ring.
/// Returns the ring handle for the selected queue, or -1 if no queues registered.
pub fn nic_ring_steer(hash: u32) -> i32 {
    unsafe {
        if RSS_QUEUE_COUNT == 0 {
            return -1;
        }
        let idx = (hash as usize) % RSS_QUEUE_COUNT;
        RSS_QUEUE_MAP[idx]
    }
}

/// Simple RSS hash computation (XOR-fold of IP 5-tuple fields).
///
/// This is a simplified hash for initial implementation. A full Toeplitz
/// hash would be programmed into the NIC hardware for RSS.
pub fn rss_hash(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, proto: u8) -> u32 {
    let mut h = src_ip ^ dst_ip;
    h ^= ((src_port as u32) << 16) | dst_port as u32;
    h ^= proto as u32;
    // Mix
    h ^= h >> 16;
    h = h.wrapping_mul(0x45d9f3b);
    h ^= h >> 16;
    h
}
