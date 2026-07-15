//! Platform-runtime modules shared across board entry points.
//!
//! Each board's entry point (`src/platform/<board>.rs`) is included
//! directly by `src/main.rs` via `include!` and owns its own boot
//! sequence. Code that is shared across boards — and belongs in the
//! platform layer, not the kernel — lives here as ordinary modules and
//! is reached from the platform files via `fluxor::platform::...`.

pub mod debug;

// Linux host-platform provider modules (host-process isolation backend, the
// `workload` provider, and the platform providers they compose). Library
// modules (not part of the `fluxor-linux` binary's flat `include!` namespace)
// so the host test harness can reach them. Explicit
// `#[path]` so this resolves to `linux/mod.rs`, never the binary entry point at
// `src/platform/linux.rs`.
#[cfg(feature = "host-linux")]
#[path = "linux/mod.rs"]
pub mod linux;

// Linux external-process executor for external-hosted (OCI-backed) graph nodes.
// Hosted-only: spawns real processes, so it exists only when the platform has
// std.
#[cfg(feature = "host-linux")]
#[path = "linux/proc_executor.rs"]
pub mod proc_executor;
