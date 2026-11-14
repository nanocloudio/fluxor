//! Kernel-side cryptography: the loader's root of trust and the key vault.
//!
//! SHA-256, SHA-512 and Ed25519 verification stay in the kernel because the
//! loader's signature check must run before any PIC module is admitted — we
//! cannot bootstrap module verification through a module that itself awaits
//! verification. P-256, Ed25519 signing, ML-DSA (with SHA-3), RSA, ChaCha20-
//! Poly1305 and AES-256-GCM back the key vault's operations.
//!
//! No external crates: pure Rust, no_std-compatible. The implementations
//! prioritise readability over peak performance; a single Ed25519 verify takes
//! a few milliseconds on bcm2712, run at most once per module load, which is
//! well within the boot budget.

// One implementation and one set of vectors for the kernel and every module:
// the SDK's, linked as a crate. P-256 on RP2040 is the exception (see
// `p256_rp2040.rs`).
#[cfg(feature = "rsa-vault")]
pub use fluxor_sdk::crypto::rsa;
/// SHA-512, from the SDK's SHA-384 file, which carries both (they differ
/// only in IV and output truncation).
pub use fluxor_sdk::crypto::sha384 as sha512;
pub use fluxor_sdk::crypto::{aes_gcm, chacha20, ed25519, hmac, ml_dsa, sha256, sha3};

#[cfg(not(feature = "chip-rp2040"))]
pub use fluxor_sdk::crypto::p256;
#[cfg(feature = "chip-rp2040")]
pub use p256_rp2040 as p256;
/// The kernel's compact P-256, which RP2040 links as `p256`.
pub mod p256_rp2040;
