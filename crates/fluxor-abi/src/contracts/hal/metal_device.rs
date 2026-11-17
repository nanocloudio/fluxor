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
// Device registers are reached through an aperture handle: `MMIO_OPEN`
// names one of the machine's device apertures by index and answers where it
// lies (an address answer), and `MMIO_READ32` / `MMIO_WRITE32` name a
// register by its offset in the aperture, never by an address.
//
// A driver declares `requires_contract = "metal_device"`; register access
// needs `metal_device.mmio`, a PCIe rescan or config access
// `metal_device.pcie`, DMA memory and cache maintenance `metal_device.dma`.
//
// DMA memory is named by the handle its allocation mints, never by an
// address: an allocation answers where it lies (an address answer, for the
// CPU to write through and the device to be told) and returns a handle;
// cache maintenance names that handle and a range within it,
// `[offset:u32 LE][len:u32 LE]`, so it reaches the caller's own allocation
// and nothing else. A handle names an allocation of the module that made it;
// any other module's call through it is `EBADF`. The arena is carved once
// and never returned, so neither is a handle.

/// Clean and invalidate a range of an allocation (`dc civac`).
/// handle = the allocation, arg=[offset:u32 LE, len:u32 LE] (8 bytes).
/// `EFAULT` unless `[offset, offset+len)` lies inside the allocation.
pub use super::super::super::registry::metal_device::CACHE_FLUSH_RANGE;
/// Allocate DMA memory a device reaches coherently (Normal Non-cacheable
/// where the machine needs it). handle=-1, arg in = [size:u32 LE,
/// align:u32 LE]; arg out = [addr:u64 LE, len:u32 LE] (12 bytes; `len` =
/// `size`), the address the CPU and the device both use. Returns the
/// allocation's handle. `size` must be non-zero and `align` a power of two
/// of at least 64, or `EINVAL`; `ENOMEM` when the arena or the allocation
/// table is exhausted.
pub use super::super::super::registry::metal_device::DMA_ALLOC_CONTIG;
/// Allocate cacheable DMA memory, same arg and answer as
/// [`DMA_ALLOC_CONTIG`]. The caller keeps it coherent: [`DMA_FLUSH`] before
/// the device reads, [`DMA_INVALIDATE`] before the CPU reads what the device
/// wrote.
pub use super::super::super::registry::metal_device::DMA_ALLOC_STREAMING;
/// Clean a range of an allocation to the point of coherency (`dc cvac`)
/// before a device reads it. Same arg and range rule as
/// [`CACHE_FLUSH_RANGE`].
pub use super::super::super::registry::metal_device::DMA_FLUSH;
/// Invalidate a range of an allocation without cleaning (`dc ivac`) before
/// the CPU reads what a device wrote. The range's start (the allocation's
/// address plus `offset`) and `len` MUST be multiples of 64, or `EINVAL`: an
/// unaligned invalidate would discard a neighbour's dirty bytes in the
/// partial first and last lines. Range rule as [`CACHE_FLUSH_RANGE`].
pub use super::super::super::registry::metal_device::DMA_INVALIDATE;
/// Open device aperture `index` of the machine's device-register apertures
/// (never DRAM, never the interrupt controller). handle=-1, arg in =
/// `[index:u8]`, arg out = `[base:u64 LE][len:u32 LE]` ([`mmio::OPEN_LEN`];
/// an address answer: where the aperture lies). Returns the aperture's
/// handle; `ENOENT` past the machine's last aperture.
pub use super::super::super::registry::metal_device::MMIO_OPEN;
/// Read a 32-bit device register. handle=an aperture, arg=`[offset:u32 LE]
/// [value:u32 LE]` ([`mmio::ARG_LEN`]; the value is written to arg[4..8]).
/// `EFAULT` unless `offset` is a 4-byte-aligned word inside the aperture.
pub use super::super::super::registry::metal_device::MMIO_READ32;
/// Write a 32-bit device register. handle=an aperture, arg=`[offset:u32 LE]
/// [value:u32 LE]` ([`mmio::ARG_LEN`]). `EFAULT` under the rule of
/// [`MMIO_READ32`].
pub use super::super::super::registry::metal_device::MMIO_WRITE32;

/// The register-access layouts.
pub mod mmio {
    /// [`super::MMIO_OPEN`]'s `arg`: `[index:u8]` in, `[base:u64][len:u32]` out.
    pub const OPEN_LEN: usize = 12;
    /// [`super::MMIO_READ32`] / [`super::MMIO_WRITE32`]'s `arg`.
    pub const ARG_LEN: usize = 8;

    /// The access argument for `offset` (and, for a write, `value`).
    pub const fn arg(offset: u32, value: u32) -> [u8; ARG_LEN] {
        let o = offset.to_le_bytes();
        let v = value.to_le_bytes();
        [o[0], o[1], o[2], o[3], v[0], v[1], v[2], v[3]]
    }
}
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
