// Platform: BCM2712 SMMU / IOMMU DMA mapping.
//
// Layer: platform/bcm2712 (chip-specific, unstable).
//
// IOMMU stream map/unmap + fault polling for kernel-bypass DMA.

/// Map DMA for an IOMMU stream.
/// handle=-1, arg=[stream_id:u16 LE, iova:u64 LE, phys:u64 LE, size:u64 LE] (26 bytes).
pub const SMMU_MAP_DMA: u32 = 0x0CFB;
/// Unmap DMA for an IOMMU stream.
/// handle=-1, arg=[stream_id:u16 LE, iova:u64 LE, size:u64 LE] (18 bytes).
pub const SMMU_UNMAP_DMA: u32 = 0x0CFC;
/// Check for SMMU faults. handle=-1, arg=unused.
pub const SMMU_FAULT_CHECK: u32 = 0x0CFD;
