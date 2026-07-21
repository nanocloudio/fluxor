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
#[cfg(feature = "host-hsm")]
pub mod hsm_key_vault;
pub mod oci;
pub mod owner_drain;
pub mod owner_status;
pub mod providers;
pub mod store;
pub mod workload;
