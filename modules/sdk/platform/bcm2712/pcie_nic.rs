// Platform: BCM2712 PCIe / NIC / SMMU / MSI.
//
// Layer: platform/bcm2712 (chip-specific, unstable).
//
// Consumed by the NVMe driver, rp1_gem ethernet driver, and e810
// NIC driver on Pi 5. Nothing portable should touch these — the
// kernel-bypass model is intentionally platform-specific.

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

/// Re-run PCIe bus enumeration. Intended for cold-boot recovery on
/// platforms where the link trains slowly (Pi 5 NVMe HAT+ PCIe1).
/// handle=-1, arg=[] (unused). Returns new device count.
pub const PCIE_RESCAN: u32 = 0x0CF5;
/// Read 32-bit word from a discovered device's PCI configuration
/// space. handle=-1, arg=[dev_idx:u8, _pad:u8, offset:u16 LE] (4 bytes
/// input). On success, writes value:u32 LE to arg[4..8]. Returns 0
/// or negative errno.
pub const PCIE_CFG_READ32: u32 = 0x0CF6;
/// Write 32-bit word to a discovered device's PCI configuration
/// space. handle=-1, arg=[dev_idx:u8, _pad:u8, offset:u16 LE,
///                        value:u32 LE] (8 bytes).
/// Returns 0 or negative errno.
pub const PCIE_CFG_WRITE32: u32 = 0x0CF7;

/// Map DMA for an IOMMU stream.
/// handle=-1, arg=[stream_id:u16 LE, iova:u64 LE, phys:u64 LE, size:u64 LE] (26 bytes).
pub const SMMU_MAP_DMA: u32 = 0x0CFB;
/// Unmap DMA for an IOMMU stream.
/// handle=-1, arg=[stream_id:u16 LE, iova:u64 LE, size:u64 LE] (18 bytes).
pub const SMMU_UNMAP_DMA: u32 = 0x0CFC;
/// Check for SMMU faults. handle=-1, arg=unused.
pub const SMMU_FAULT_CHECK: u32 = 0x0CFD;

// ── PCIe1 MSI: opcodes 0x0CD8-0x0CDF (BCM2712 half of 0x0CDx range).
//
// The low half 0x0CD0-0x0CD7 is reserved for RP platform raw bridges
// (ADC register bridge at 0x0CD0-0x0CD2 today; room to grow). The
// high half 0x0CD8-0x0CDF is BCM2712-only. Both chips can never run
// the same build so even a collision would be safe, but keeping the
// ranges disjoint matches the layering rule that platform opcodes
// are chip-scoped.

/// Initialise the brcmstb PCIe1 MSI controller. Idempotent.
/// handle=-1, arg=[spi_irq: u32 LE] (4 bytes) — the GIC SPI the
/// RC multiplexes all MSIs into. On success the kernel programs
/// MSI_TARGET, MSI_DATA, unmasks all 32 vectors, and registers
/// an IRQ handler that drains MSI_INT_STATUS per fire and
/// forwards to per-vector events registered via
/// `PCIE1_MSI_ALLOC_VECTOR`. Returns 0 or negative errno.
pub const PCIE1_MSI_INIT: u32 = 0x0CD8;
/// Allocate an MSI vector for `event_handle`. Returns, on
/// success, the tuple (vector_index, target_addr, data_value)
/// the caller writes into its MSI-X table entry.
/// handle=-1, arg=[event_handle: i32 LE] (input, 4 bytes). On
/// success writes [vector: u8][_pad: u8][_pad: u16][target_addr:
/// u64 LE][data: u32 LE] at offset 4 (caller must pass >= 20 B).
/// Returns 0 or negative errno.
pub const PCIE1_MSI_ALLOC_VECTOR: u32 = 0x0CD9;
