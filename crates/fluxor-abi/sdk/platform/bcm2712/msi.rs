// Platform: BCM2712 PCIe1 MSI controller.
//
// Layer: platform/bcm2712 (chip-specific, unstable).
//
// MSI opcodes 0x0CD8-0x0CDF (BCM2712 half of the 0x0CDx range). The low
// half 0x0CD0-0x0CD7 is reserved for RP platform raw bridges (ADC
// register bridge at 0x0CD0-0x0CD2 today). Both chips can never run the
// same build, but the ranges are kept disjoint to match the layering
// rule that platform opcodes are chip-scoped.

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
