//! Kernel syscall surfaces (minimal).

/// Core 0's MMU attributes, published after the primary has set up
/// its page tables and referenced by `secondary_core_trampoline` to
/// enable MMU with identical attributes on cores 1-3 (required so
/// their accesses participate in inner-shareable cache coherency).
#[cfg(feature = "chip-bcm2712")]
#[no_mangle]
pub static mut SECONDARY_MMU_MAIR: u64 = 0;
#[cfg(feature = "chip-bcm2712")]
#[no_mangle]
pub static mut SECONDARY_MMU_TCR: u64 = 0;
#[cfg(feature = "chip-bcm2712")]
#[no_mangle]
pub static mut SECONDARY_MMU_TTBR0: u64 = 0;

pub mod hal;
pub mod crypto;
#[cfg(feature = "chip-bcm2712")]
pub mod dtb;
pub mod key_vault;
pub mod syscalls;
pub mod blob_store;
pub mod graph_slot;
pub mod nvme_backing;
pub mod channel;
pub mod config;
pub mod scheduler;
pub mod loader;
pub mod net;
pub mod buffer_pool;
pub mod errno;
pub mod event;
pub mod log_ring;
pub mod uart_write;
pub mod usb_write;
#[cfg(feature = "rp")]
#[path = "../platform/rp_resource.rs"]
pub mod resource;
pub mod ringbuf;
pub mod fd;
pub mod provider;
#[cfg(feature = "rp")]
#[path = "../platform/rp_planner.rs"]
pub mod planner;
#[cfg(feature = "rp")]
#[path = "../platform/rp_flash_store.rs"]
pub mod flash_store;
#[cfg(feature = "rp")]
#[path = "../platform/rp_chip.rs"]
pub mod chip;
#[cfg(feature = "chip-bcm2712")]
#[path = "../platform/bcm2712_chip.rs"]
pub mod chip;
#[cfg(feature = "host-linux")]
#[path = "../platform/linux_chip.rs"]
pub mod chip;
#[cfg(feature = "rp")]
#[path = "../platform/rp_ext.rs"]
pub mod rp_ext;
pub mod guard;
pub mod heap;
pub mod step_guard;
pub mod bridge;
pub mod isr_tier;
#[cfg(feature = "chip-bcm2712")]
#[path = "../platform/bcm2712_cross_domain.rs"]
pub mod cross_domain;
#[path = "../platform/rp_mpu.rs"]
pub mod mpu;
#[cfg(feature = "chip-bcm2712")]
#[path = "../platform/bcm2712_mmu.rs"]
pub mod mmu;
#[cfg(feature = "chip-bcm2712")]
#[path = "../platform/bcm2712_pcie.rs"]
pub mod pcie;
// SMMU/IOMMU on BCM2712 lives in the `smmu` PIC module
// (`modules/foundation/smmu/`) via MMIO bridges. CM5 NVMe uses
// direct UBUS_REMAP inbound-DMA windowing and does not need SMMU.
#[cfg(feature = "chip-bcm2712")]
#[path = "../platform/bcm2712_nic_ring.rs"]
pub mod nic_ring;
pub mod page_pool;
#[path = "../platform/bcm2712_backing_store.rs"]
pub mod backing_store;
#[path = "../platform/bcm2712_pager.rs"]
pub mod pager;
#[cfg(feature = "rp")]
#[path = "../platform/rp_gpio.rs"]
pub mod gpio;
#[cfg(feature = "rp")]
#[path = "../platform/rp_pio_util.rs"]
pub mod pio_util;
