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

pub mod abi_pin;
pub mod add_subgraph;
pub mod agent_logs;
pub mod asset_bank;
pub mod ci;
// `fluxor.toml`'s schema, gated by `fluxor ci`'s `fluxor-toml-schema`
// phase: which keys a project must carry, which its shape forbids, and
// the one meaning each key has.
pub mod capacity;
pub mod ci_schema;
pub mod compose;
pub mod error;
pub mod genstore;
pub mod hash;
pub mod hygiene;
// `fluxor build|test|lint|clean` — the lifecycle verbs, plus the
// generated `make help` block (`fluxor help --make`). Lives in the lib
// so it can reach `ci`'s own phase runners rather than re-implementing
// them; the bin dispatches to it.
pub mod lifecycle;
pub mod lockfile;
// `standards/make.md` as checkable text: preamble, target set, the
// canonical lifecycle recipe bodies, and §3 recipe complexity. Driven
// by `fluxor ci`'s `makefile` phase, which adds the live-CLI verb
// resolution on top.
pub mod makefile_lint;
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
pub mod publish;
pub mod render_template;
// The consolidated store flow: `store_publish` (the single store-write
// path), `store_resolve` (uniform `[[artifact]]` lockfile resolution),
// and `store_sync` (the one-path materialiser + `workspace publish`).
// Lib-only; the bin reaches them via `fluxor_tools::…`.
pub mod store_publish;
pub mod store_remote;
pub mod store_resolve;
pub mod store_sync;
pub mod target;
pub mod text_distance;
pub mod trust;
pub mod workload;
pub mod workspace;

/// Wire-format constants (ABI version byte, channel-hint stride,
/// `fnv1a32`). Path-mounted from `modules/sdk/wire/wire.rs` so the host
/// tools agree byte-for-byte with the kernel and the module SDK.
/// `#[allow(dead_code)]` because integration tests reach only a
/// subset of the constants.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
#[path = "../../modules/sdk/wire/wire.rs"]
pub mod wire;

/// Canonical ABI wire-surface encoding — path-mounted from
/// `modules/sdk/abi_surface.rs` so host tools and the kernel fold the
/// exact same byte stream into the ABI-surface digest that pins graph
/// generations to a compatible substrate.
#[path = "../../modules/sdk/abi_surface.rs"]
pub mod abi_surface;

/// Reusable continuity/protocol cores (rfc_protocols.md §15.1) —
/// path-mounted from `modules/sdk/cores/` so the host test suite
/// exercises the exact logic modules `include!`. `nonce_reservation`
/// carries the Phase-7 R2 fencing semantics; its tests are the
/// executable, state-machine-level form of the §18 "R2 nonce non-reuse
/// under forced recovery" verification gate.
pub mod continuity_cores;
