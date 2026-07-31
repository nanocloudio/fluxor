//! SHA-512 (FIPS 180-4) for the loader's Ed25519 root-of-trust.
//!
//! Shares the single source at `modules/sdk/crypto/sha384.rs` — the same file
//! PIC modules (`tls`, `quic`) already `include!()` (it carries both SHA-384
//! and SHA-512, which differ only in IV and output truncation) — exactly the
//! sharing model `sha256.rs` uses. This keeps this module's "no external
//! crates" promise while guaranteeing the kernel and module SHA-512 can never
//! drift. API: `Sha512::new()` / `.update(&[u8])` / `.finalize() -> [u8; 64]`,
//! plus the `sha512(&[u8])` one-shot.
#![allow(
    dead_code,
    reason = "the shared source also carries Sha384, which the kernel does not \
              use — the loader's Ed25519 needs only Sha512"
)]
include!("../../../../modules/sdk/crypto/sha384.rs");
