//! Library facade for `fluxor-tools`.
//!
//! Exposes the small subset of the tool's modules that integration
//! tests under `tools/tests/` and the auxiliary backend binaries under
//! `src/bin/` import. The main CLI lives in `src/main.rs`; this
//! surface is intentionally narrow.

pub mod error;
mod hash;
pub mod manifest;
pub mod monitor;

/// Wire-format constants (ABI version byte, channel-hint stride,
/// `fnv1a32`). Path-mounted from `modules/sdk/wire.rs` so the host
/// tools agree byte-for-byte with the kernel and the module SDK.
/// `#[allow(dead_code)]` because integration tests reach only a
/// subset of the constants.
#[allow(dead_code)]
#[path = "../../modules/sdk/wire.rs"]
pub mod wire;
