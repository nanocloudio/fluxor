//! Library facade for `fluxor-tools`.
//!
//! Exposes the small subset of the tool's modules that integration
//! tests under `tools/tests/` need to import. The CLI lives in
//! `src/main.rs`; this surface is intentionally narrow — only
//! `manifest` is public, with `error` reachable because
//! `Manifest::from_toml -> Result<Self>` names `error::Error` in its
//! return type.

pub mod error;
mod hash;
pub mod manifest;

/// Wire-format constants (ABI version byte, channel-hint stride,
/// `fnv1a32`). Path-mounted from `modules/sdk/wire.rs` so the host
/// tools agree byte-for-byte with the kernel and the module SDK.
/// `#[allow(dead_code)]` because integration tests reach only a
/// subset of the constants.
#[allow(dead_code)]
#[path = "../../modules/sdk/wire.rs"]
pub mod wire;
