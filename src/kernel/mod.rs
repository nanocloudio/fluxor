//! Kernel syscall surfaces (minimal).

// ── Kernel domains ───────────────────────────────────────────────────────────
// Every kernel service lives under one domain directory.
pub mod boot; // config + device tree
pub mod config; // single capacity seam onto platform::chip
pub mod exec; // scheduler run loop, ISR tiers, step guard
pub mod ipc; // channels, ring buffers, buffer pool, events, fd
pub mod mem; // heap, page pool
pub mod module; // loader, provider, syscalls, el0 gateway
pub mod net_policy; // net.policy (0x1E) table store shared by every provider
pub mod pcie; // PCIe ownership: BAR aperture claims
pub mod security; // crypto + key vault
pub mod sys; // HAL seam, guard, errno, log ring
pub mod usb; // common USB semantic core: descriptors, transfer identity
pub mod workload; // owners, plans, metal 0x1A backend, bitmask, ext bridge

/// Bring up the platform-agnostic kernel services: HAL ops table,
/// syscall table, provider dispatchers. Every platform must call this
/// exactly once on core 0 before `scheduler::populate_static_state` and
/// `scheduler::prepare_graph`.
///
/// Step-guard initialisation is intentionally not included — RP wires
/// it through HAL ops, wasm has nothing to guard, linux and bcm2712
/// call `step_guard::init()` themselves.
#[inline]
pub fn boot(ops: &'static sys::hal::HalOps) {
    sys::hal::init(ops);
    module::syscalls::init_syscall_table();
    module::syscalls::init_providers();
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

// Kernel-owned memory-service aliases (module lives in `mem::backing`).
pub use mem::backing::backing_store;
pub use mem::backing::pager;
