//! SHA-3 and SHAKE (FIPS 202) for the vault's ML-DSA.
//!
//! Shares the single source at `modules/sdk/crypto/sha3.rs` — the same
//! sharing model `sha256.rs` and `sha512.rs` use, so the kernel and the
//! PIC modules can never drift on a primitive that both verify against.
//! API: `sha3_256` / `sha3_512`, `shake128` / `shake256`, and the
//! `Keccak` sponge for absorb-then-squeeze-repeatedly consumers.
#![allow(
    dead_code,
    reason = "the shared source carries all four FIPS 202 functions; the \
              kernel's ML-DSA reaches only for the two XOFs"
)]
include!("../../../../modules/sdk/crypto/sha3.rs");
