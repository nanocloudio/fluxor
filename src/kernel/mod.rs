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

pub mod crypto;
#[cfg(feature = "chip-bcm2712")]
pub mod dtb;
pub mod hal;
pub mod key_vault;
pub mod syscalls;

/// Bring up the platform-agnostic kernel services: HAL ops table,
/// syscall table, provider dispatchers. Every platform must call this
/// exactly once on core 0 before `scheduler::populate_static_state` and
/// `scheduler::prepare_graph`.
///
/// Step-guard initialisation is intentionally not included — RP wires
/// it through HAL ops, wasm has nothing to guard, linux and bcm2712
/// call `step_guard::init()` themselves.
#[inline]
pub fn boot(ops: &'static hal::HalOps) {
    hal::init(ops);
    syscalls::init_syscall_table();
    syscalls::init_providers();
}

/// Kernel-private service registries and orchestration. Mirrors the
/// `abi::internal::*` layer on the module side — these are the kernel's
/// implementation of the registration hooks that pic modules invoke.
pub mod internal {
    pub mod backing_provider;
    pub mod bridge;
}

// Top-level aliases — existing call sites reach `crate::kernel::backing_provider::*`
// and `crate::kernel::bridge::*`. Both remain kernel-private; the
// public ABI does not surface them.
pub use internal::backing_provider;
pub use internal::bridge;
pub mod buffer_pool;
pub mod channel;
pub mod config;
pub mod errno;
pub mod event;
pub mod loader;
pub mod log_ring;
pub mod scheduler;

// RP-family kernel services.
pub mod fd;
#[cfg(feature = "rp")]
#[path = "../platform/rp/config.rs"]
pub mod planner;
pub mod provider;
#[cfg(feature = "rp")]
#[path = "../platform/rp/flash.rs"]
mod rp_flash;
#[cfg(feature = "rp")]
pub use rp_flash::store as flash_store;
#[cfg(feature = "rp")]
pub use rp_flash::xip_lock as resource;
pub mod ringbuf;

// Platform-selected chip backend.
#[cfg(feature = "rp")]
#[path = "../platform/rp/chip.rs"]
pub mod chip;
#[cfg(feature = "chip-bcm2712")]
#[path = "../platform/bcm2712/chip.rs"]
pub mod chip;
#[cfg(feature = "host-linux")]
#[path = "../platform/linux/chip.rs"]
pub mod chip;
#[cfg(feature = "host-wasm")]
#[path = "../platform/wasm/chip.rs"]
pub mod chip;

pub mod guard;
pub mod heap;
pub mod isr_tier;
#[cfg(feature = "chip-bcm2712")]
#[path = "../platform/bcm2712/mmu.rs"]
pub mod mmu;
#[path = "../platform/rp/mpu.rs"]
pub mod mpu;
#[cfg(feature = "chip-bcm2712")]
#[path = "../platform/bcm2712/multicore.rs"]
pub mod multicore;
#[cfg(feature = "chip-bcm2712")]
#[path = "../platform/bcm2712/pcie.rs"]
pub mod pcie;
#[cfg(feature = "chip-bcm2712")]
#[path = "../platform/bcm2712/pcie_aliases.rs"]
pub mod pcie_aliases;
#[cfg(feature = "rp")]
#[path = "../platform/rp/providers.rs"]
pub mod rp_providers;
#[cfg(feature = "rp")]
#[path = "../platform/rp/step_guard.rs"]
pub mod rp_step_guard;
pub mod step_guard;
// SMMU/IOMMU on BCM2712 lives in the `smmu` PIC module
// (`modules/foundation/smmu/`) via MMIO bridges. CM5 NVMe uses
// direct UBUS_REMAP inbound-DMA windowing and does not need SMMU.
#[cfg(feature = "rp")]
#[path = "../platform/rp/io.rs"]
mod rp_io;
#[cfg(feature = "rp")]
pub use rp_io::gpio;
#[cfg(feature = "rp")]
pub use rp_io::pio as pio_util;
#[path = "../platform/bcm2712/memory.rs"]
mod bcm_memory;
pub use bcm_memory::backing_store;
#[cfg(feature = "chip-bcm2712")]
#[path = "../platform/bcm2712/net.rs"]
pub mod nic_ring;
pub mod page_pool;
pub use bcm_memory::pager;
