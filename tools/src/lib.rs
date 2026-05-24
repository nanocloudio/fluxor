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

pub mod asset_bank;
pub mod ci;
pub mod error;
mod hash;
pub mod hygiene;
pub mod manifest;
// `modules` carries the `.fmod` pack/parse primitives that
// `modules_build` calls into. Exposed here (rather than left
// main-only) so the build orchestrator can reach it from the lib
// surface.
pub mod modules;
pub mod modules_build;
pub mod monitor;
pub mod render_template;
pub mod text_distance;

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
