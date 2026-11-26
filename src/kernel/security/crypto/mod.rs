//! The kernel's cryptography: SHA-256 and Ed25519 verification for the
//! loader's root of trust. The loader's signature check runs before any
//! module is admitted, so it cannot be a module. The sealing-key derivation
//! is the SDK's (`fluxor_sdk::crypto::seal`); signing, key agreement and
//! AEADs are the `key_vault` module's.
//!
//! One implementation and one set of vectors for the kernel and every
//! module: the SDK's, linked as a crate.

pub use fluxor_sdk::crypto::{ed25519, sha256};
