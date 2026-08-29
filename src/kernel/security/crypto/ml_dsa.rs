//! ML-DSA (FIPS 204) for the key vault's post-quantum suites.
//!
//! Shares the single source at `modules/sdk/crypto/ml_dsa.rs`, the same
//! way `sha256.rs` / `sha512.rs` share theirs: the vault signs with this
//! code and a PIC module verifies with the same file, so a divergence
//! between signer and verifier is not expressible.
//!
//! The shared source expects the SHAKE surface in scope by bare name —
//! the flat-`include!` convention every PIC module uses. Here that comes
//! from the sibling `sha3` module rather than a second copy.
#![allow(
    dead_code,
    reason = "the shared source carries the full FIPS 204 surface; the vault \
              uses seed-based key generation, the public key and signing"
)]
use super::sha3::{Keccak, SHAKE128_RATE, SHAKE256_RATE, SHAKE_PAD};
include!("../../../../modules/sdk/crypto/ml_dsa.rs");
