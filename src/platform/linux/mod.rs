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

pub mod clock;
/// The privilege and system-call surface of a host-process workload:
/// capability sets, `no_new_privs`, the system-call filter, parent death.
pub mod confine;
pub mod descriptors;
/// The picture a display sink holds: region rasters in, a retained surface
/// out, a frame presented whole.
pub mod display_surface;
/// evdev `input_event` records in, pointer records out.
pub mod evdev_pointer;
/// Native GPU compute over wgpu/Vulkan, headless — the provider behind the
/// `linux_gpu` native module. In the library, not only the binary, so the host test
/// harness can drive it against a real adapter.
pub mod gpu;
pub mod host_backend;
pub mod host_mount;
#[cfg(feature = "host-hsm")]
pub mod hsm_key_vault;
/// Where a window's input method stands: the focused editable node of an
/// accessibility tree.
pub mod ime_target;
/// The bounded record queue between a host input source and its step.
pub mod input_queue;
/// Instance scoping: this runtime's tag, the host registry runtimes on one
/// host share, and dead-tag collection.
pub mod instance;
pub mod native_params;
pub mod net_identity;
pub mod net_policy;
pub mod net_route;
pub mod owner_drain;
pub mod owner_release;
pub mod owner_root;
pub mod owner_status;
pub mod providers;
pub mod store;
/// Window events as pointer, key and text records.
pub mod window_input;
pub mod workload;
