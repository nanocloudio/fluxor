//! Linux host-platform provider modules.
//!
//! These implement Linux host-process backends and platform providers for the
//! kernel's capability surface. They compile into the `fluxor` **library** (not
//! only the `fluxor-linux` binary) so the host test harness can exercise them
//! directly — the binary at `src/platform/linux.rs` reaches them through
//! `fluxor::platform::linux::…`.
//!
//! Host-only: they use `std`/`libc` and spawn real processes, so the whole tree
//! is gated on `host-linux`.

pub mod builtin_params;
pub mod clock;
pub mod descriptors;
/// Native GPU compute over wgpu/Vulkan, headless — the provider behind the
/// `linux_gpu` built-in. In the library, not only the binary, so the host test
/// harness can drive it against a real adapter.
pub mod gpu;
pub mod host_backend;
pub mod host_mount;
#[cfg(feature = "host-hsm")]
pub mod hsm_key_vault;
/// Instance scoping: this runtime's tag, the host registry runtimes on one
/// host share, and dead-tag collection.
pub mod instance;
pub mod net_identity;
pub mod net_policy;
pub mod net_route;
pub mod owner_drain;
pub mod owner_root;
pub mod owner_status;
pub mod providers;
pub mod store;
pub mod workload;
