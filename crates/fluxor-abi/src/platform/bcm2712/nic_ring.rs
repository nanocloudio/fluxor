// Platform: BCM2712 NIC BAR mapping + DMA rings.
//
// Layer: platform/bcm2712 (chip-specific, unstable).
//
// Kernel-bypass NIC surface consumed by the rp1_gem ethernet driver and
// e810 NIC driver on Pi 5. Intentionally platform-specific — nothing
// portable should touch these.

/// Map BAR `bar_idx` of enumerated PCIe device `dev_idx` and answer where it
/// lies: an address answer. handle=-1, arg in = `[dev_idx:u8][bar_idx:u8]`,
/// arg out = `[addr:u64 LE][len:u32 LE]` (12 bytes; `len` is the BAR's
/// size). Returns 0 or negative errno (`ERANGE` for a BAR of 4 GiB or more).
pub use super::super::super::registry::platform_nic_ring::NIC_BAR_MAP;
/// Release the mapping of BAR `bar_idx` of device `dev_idx`, named as it
/// was mapped. handle=-1, arg=`[dev_idx:u8][bar_idx:u8]` (2 bytes). Returns
/// 0, or `EINVAL` when that BAR is not mapped.
pub use super::super::super::registry::platform_nic_ring::NIC_BAR_UNMAP;
/// Create a NIC DMA ring (RX+TX descriptors + buffer pool).
/// handle=-1, arg=[rx_desc_count:u16, tx_desc_count:u16, buf_size:u16, buf_count:u16] (8 bytes).
/// Returns ring handle (>=0) or negative errno.
pub use super::super::super::registry::platform_nic_ring::NIC_RING_CREATE;
/// Destroy a NIC DMA ring. handle=the ring, no arg. Closes the handle.
pub use super::super::super::registry::platform_nic_ring::NIC_RING_DESTROY;
/// Where one part of a NIC ring lies: an address answer. handle=the ring,
/// arg in = `[part:u8]` ([`info::RX_DESC`], [`info::TX_DESC`],
/// [`info::BUFFERS`]), arg out = `[addr:u64 LE][len:u32 LE][count:u16 LE]
/// [size:u16 LE]` ([`info::LEN`]): the part's DMA address and byte length,
/// and its entry count and entry size. Returns 0 or negative errno.
pub use super::super::super::registry::platform_nic_ring::NIC_RING_INFO;

/// [`NIC_RING_INFO`]'s argument.
pub mod info {
    /// Exact `arg` length.
    pub const LEN: usize = 16;
    /// The RX descriptor ring.
    pub const RX_DESC: u8 = 0;
    /// The TX descriptor ring.
    pub const TX_DESC: u8 = 1;
    /// The packet buffer pool.
    pub const BUFFERS: u8 = 2;
}
