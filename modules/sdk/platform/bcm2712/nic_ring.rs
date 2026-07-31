// Platform: BCM2712 NIC BAR mapping + DMA rings.
//
// Layer: platform/bcm2712 (chip-specific, unstable).
//
// Kernel-bypass NIC surface consumed by the rp1_gem ethernet driver and
// e810 NIC driver on Pi 5. Intentionally platform-specific — nothing
// portable should touch these.

/// Map a PCIe device BAR into kernel virtual address space.
/// handle=-1, arg=[dev_idx:u8, bar_idx:u8] (2 bytes).
/// On success, writes full 64-bit address to arg[2..10] if space allows.
/// Returns lower 32 bits of mapped address, or negative errno.
pub const NIC_BAR_MAP: u32 = 0x0CF0;
/// Unmap a previously mapped BAR region.
/// handle=-1, arg=[virt_addr:u64 LE] (8 bytes). Returns 0 or negative errno.
pub const NIC_BAR_UNMAP: u32 = 0x0CF1;
/// Create a NIC DMA ring (RX+TX descriptors + buffer pool).
/// handle=-1, arg=[rx_desc_count:u16, tx_desc_count:u16, buf_size:u16, buf_count:u16] (8 bytes).
/// Returns ring handle (>=0) or negative errno.
pub const NIC_RING_CREATE: u32 = 0x0CF2;
/// Destroy a NIC DMA ring. handle=-1, arg=[ring_handle:u8] (1 byte).
pub const NIC_RING_DESTROY: u32 = 0x0CF3;
/// Get NIC ring info (addresses, sizes). handle=ring_handle, arg=32-byte output buffer.
/// Returns 32 on success (bytes written), or negative errno.
pub const NIC_RING_INFO: u32 = 0x0CF4;
