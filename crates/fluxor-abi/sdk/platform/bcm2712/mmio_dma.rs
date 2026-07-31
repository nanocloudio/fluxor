// Platform: BCM2712 generic MMIO + DMA arena helpers (aarch64).
//
// Layer: platform/bcm2712 (chip-specific, unstable).
//
// Portable consumers use the HAL contracts and the `paged_arena`
// storage contract. These raw hooks are for kernel-bypass drivers
// (NIC, NVMe) that need direct MMIO, cache maintenance, and
// physically-contiguous DMA buffers.

/// Read a 32-bit value from a physical MMIO address (aarch64 only).
/// handle=-1, arg=[addr:u64 LE] (8 bytes input).
/// On success, writes u32 LE result to arg[8..12]. Returns 0 or negative errno.
pub const MMIO_READ32: u32 = 0x0CE4;
/// Write a 32-bit value to a physical MMIO address (aarch64 only).
/// handle=-1, arg=[addr:u64 LE, value:u32 LE] (12 bytes input). Returns 0 or negative errno.
pub const MMIO_WRITE32: u32 = 0x0CE5;
/// Allocate physically contiguous DMA memory (aarch64 only).
/// handle=-1, arg=[size:u32 LE, align:u32 LE] (8 bytes input).
/// On success, writes phys_addr:u64 LE to arg[8..16]. Returns 0 or negative errno.
pub const DMA_ALLOC_CONTIG: u32 = 0x0CE6;

/// Flush (clean + invalidate) a virtual address range from data cache.
/// Required for DMA coherency on aarch64 where DMA arena is cacheable.
/// handle=-1, arg=[addr:u64 LE, size:u32 LE] (12 bytes). Returns 0.
pub const CACHE_FLUSH_RANGE: u32 = 0x0CE7;

/// Clean (but do not invalidate) a VA range from data cache (`dc cvac`).
/// Use before handing a cacheable buffer to a device that will READ it
/// — ensures the device sees the CPU's writes.
/// handle=-1, arg=[addr:u64 LE, size:u32 LE] (12 bytes). Returns 0.
pub const DMA_FLUSH: u32 = 0x0CEA;

/// Invalidate a VA range from data cache (`dc ivac`) without cleaning.
/// Use before reading a cacheable buffer that a device has just WRITTEN
/// — drops any stale CPU cache lines so the next load returns DMA data.
/// handle=-1, arg=[addr:u64 LE, size:u32 LE] (12 bytes). Returns 0.
pub const DMA_INVALIDATE: u32 = 0x0CEB;

/// Allocate physically contiguous DMA memory from a STREAMING (cacheable)
/// arena reachable by PCIe1 (aarch64 only). Unlike `DMA_ALLOC_CONTIG`
/// which returns Normal-Non-Cacheable memory for simple coherent DMA,
/// streaming memory is normal WB-WA — callers MUST pair writes with
/// `DMA_FLUSH` before device reads and `DMA_INVALIDATE` before CPU reads
/// of device-written regions.
/// handle=-1, arg=[size:u32 LE, align:u32 LE] (8 bytes input).
/// On success, writes phys_addr:u64 LE to arg[8..16]. Returns 0 or
/// negative errno.
pub const DMA_ALLOC_STREAMING: u32 = 0x0CEC;
