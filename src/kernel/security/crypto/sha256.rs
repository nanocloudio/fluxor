//! In-house SHA-256 (FIPS 180-4), NEON-accelerated on aarch64.
//!
//! Shares the single source at `modules/sdk/crypto/sha256.rs` — the same file PIC
//! modules (`tls`, `quic`, `graph_slot`) and `fluxor-sdk` already `include!()`
//! — rather than the external `sha2` crate. This keeps this module's
//! "no external crates" promise and drops the `digest` / `block-buffer` /
//! `crypto-common` / `cpufeatures` / `generic-array` tree from every kernel
//! build. API: `Sha256::new()` / `.update(&[u8])` / `.finalize() -> [u8; 32]`.
include!("../../../../modules/sdk/crypto/sha256.rs");
