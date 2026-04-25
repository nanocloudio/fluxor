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
