// Contract: metal_device — device registers, DMA memory and cache
// maintenance for a driver module on a bare-metal aarch64 machine.
//
// Layer: contracts/hal (public).
//
// One meaning per op on every machine that serves it (Pi 5, UEFI): the
// kernel decodes the request, checks it and keeps the caches; a platform
// supplies only which addresses are device registers, where DMA memory
// comes from and which ranges are DMA memory. Errors are the same
// everywhere: a bad request is `EINVAL`, an address outside what the call
// may reach is `EFAULT`, an exhausted DMA arena is `ENOMEM`, and an op the
// machine has no hardware for is `ENOSYS`.
//
// A driver declares `requires_contract = "metal_device"`; register access
// needs `platform_raw`, DMA memory and cache maintenance need `dma`.

/// Clean and invalidate `[addr, addr+size)` (`dc civac`). handle=-1,
/// arg=[addr:u64 LE, size:u32 LE] (12 bytes). `EFAULT` unless the range lies
/// inside DMA memory this machine hands out.
pub use super::super::super::registry::metal_device::CACHE_FLUSH_RANGE;
/// Allocate DMA memory a device reaches coherently (Normal Non-cacheable
/// where the machine needs it). handle=-1, arg=[size:u32 LE, align:u32 LE]
/// (16 bytes; the address is written to arg[8..16]). `size` must be
/// non-zero and `align` a power of two of at least 64, or `EINVAL`.
pub use super::super::super::registry::metal_device::DMA_ALLOC_CONTIG;
/// Allocate cacheable DMA memory, same arg as [`DMA_ALLOC_CONTIG`]. The
/// caller keeps it coherent: [`DMA_FLUSH`] before the device reads,
/// [`DMA_INVALIDATE`] before the CPU reads what the device wrote.
pub use super::super::super::registry::metal_device::DMA_ALLOC_STREAMING;
/// Clean `[addr, addr+size)` to the point of coherency (`dc cvac`) before a
/// device reads it. Same arg and range rule as [`CACHE_FLUSH_RANGE`].
pub use super::super::super::registry::metal_device::DMA_FLUSH;
/// Invalidate `[addr, addr+size)` without cleaning (`dc ivac`) before the
/// CPU reads what a device wrote. `addr` and `size` MUST be multiples of 64,
/// or `EINVAL`: an unaligned invalidate would discard a neighbour's dirty
/// bytes in the partial first and last lines. Range rule as
/// [`CACHE_FLUSH_RANGE`].
pub use super::super::super::registry::metal_device::DMA_INVALIDATE;
/// Read a 32-bit device register. handle=-1, arg=[addr:u64 LE] (12 bytes;
/// the value is written to arg[8..12]). `EFAULT` unless `addr` is a
/// 4-byte-aligned word the machine calls device registers (never DRAM,
/// never the interrupt controller).
pub use super::super::super::registry::metal_device::MMIO_READ32;
/// Write a 32-bit device register. handle=-1, arg=[addr:u64 LE,
/// value:u32 LE] (12 bytes). `EFAULT` under the rule of [`MMIO_READ32`].
pub use super::super::super::registry::metal_device::MMIO_WRITE32;
/// Read a 32-bit config word of an enumerated device before any handle is
/// bound. handle=-1, arg=[dev_idx:u8, _pad:u8, offset:u16 LE] (8 bytes; the
/// value is written to arg[4..8]). Drivers that own a device use
/// `pcie_device` instead. `ENOSYS` where the machine has no such table.
pub use super::super::super::registry::metal_device::PCIE_CFG_READ32;
/// Write a 32-bit config word, arg=[dev_idx:u8, _pad:u8, offset:u16 LE,
/// value:u32 LE] (8 bytes). As [`PCIE_CFG_READ32`].
pub use super::super::super::registry::metal_device::PCIE_CFG_WRITE32;
/// Re-run PCIe enumeration on a machine whose link trains after boot (the
/// Pi 5's PCIe1). handle=-1, no arg. Returns the device count found.
/// `ENOSYS` where the machine enumerates once at boot.
pub use super::super::super::registry::metal_device::PCIE_RESCAN;
