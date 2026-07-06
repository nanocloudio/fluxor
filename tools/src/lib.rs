//! Library facade for `fluxor-tools`.
//!
//! Exposes the small subset of the tool's modules that integration
//! tests under `tools/tests/` and the auxiliary backend binaries under
//! `src/bin/` import. The main CLI lives in `src/main.rs`; this
//! surface is intentionally narrow.

#![allow(
    unsafe_code,
    reason = "host CLI wraps libc, mmap, ELF parsing, UF2 packing, and IPC primitives"
)]
// The CLI prints subcommand output (`info`, `decode`, `inspect`, …)
// to stdout and errors / progress to stderr.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "CLI is the user-facing product surface; `println!`/`eprintln!` is intentional output, not log misuse"
)]

pub mod add_subgraph;
pub mod asset_bank;
pub mod cargo_index;
pub mod ci;
pub mod compose;
pub mod error;
pub mod genstore;
pub mod hash;
pub mod hygiene;
pub mod lockfile;
pub mod manifest;
pub mod node_agent;
// `modules` carries the `.fmod` pack/parse primitives that
// `modules_build` calls into. Exposed here (rather than left
// main-only) so the build orchestrator can reach it from the lib
// surface.
pub mod modules;
pub mod modules_build;
pub mod monitor;
pub mod observability;
// Local OCI image-layout content store for `.fmod` modules and workload
// bundles (`.context/fmod_registry_plan.md` P1/P2). Offline-first: publish
// and consume both touch only the local store.
pub mod oci_store;
// Standalone, unit-testable validator for `presentation.shell` /
// `presentation.browser_overlay` descriptors (RFC browser_overlay §19).
// Dependency-light (serde_json + error) so it dual-compiles cleanly
// into both the lib (tests) and the bin (called from `config.rs`).
pub mod content_render;
pub mod presentation_resolver;
pub mod presentation_shell;
pub mod project;
pub mod project_meta;
pub mod registry;
pub mod render_template;
pub mod text_distance;
pub mod trust;
pub mod workload;
pub mod workspace;

/// Wire-format constants (ABI version byte, channel-hint stride,
/// `fnv1a32`). Path-mounted from `modules/sdk/wire.rs` so the host
/// tools agree byte-for-byte with the kernel and the module SDK.
/// `#[allow(dead_code)]` because integration tests reach only a
/// subset of the constants.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[path = "../../modules/sdk/wire.rs"]
pub mod wire;

/// Canonical ABI wire-surface encoding — path-mounted from
/// `modules/sdk/abi_surface.rs` so host tools and the kernel fold the
/// exact same byte stream into the ABI-surface digest that pins graph
/// generations to a compatible substrate.
#[path = "../../modules/sdk/abi_surface.rs"]
pub mod abi_surface;
