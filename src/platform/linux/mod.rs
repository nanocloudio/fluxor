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
/// A host provider process behind ports or contracts, through a host lane.
pub mod host_lane;
pub mod host_mount;
/// Where a window's input method stands: the focused editable node of an
/// accessibility tree.
pub mod ime_target;
/// The bounded record queue between a host input source and its step.
pub mod input_queue;
pub mod native_params;
/// Where the kernel's owner facts land for the node agent.
pub mod owner_facts;
pub mod owner_release;
pub mod providers;
/// The runtime's own state directory, held exclusively.
pub mod state_dir;
/// Window events as pointer, key and text records.
pub mod window_input;
pub mod workload;
