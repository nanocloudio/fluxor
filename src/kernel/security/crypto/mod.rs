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

// The AEADs, the hashes, ML-DSA and RSA are the SDK's, linked as a crate:
// one implementation and one set of vectors for the kernel and every module.
// P-256 and Ed25519 are the kernel's own until the SDK's fit RP2040 flash.
#[cfg(feature = "rsa-vault")]
pub use fluxor_sdk::crypto::rsa;
/// SHA-512, from the SDK's SHA-384 file, which carries both (they differ
/// only in IV and output truncation).
pub use fluxor_sdk::crypto::sha384 as sha512;
pub use fluxor_sdk::crypto::{aes_gcm, chacha20, ml_dsa, sha256, sha3};

pub mod ed25519;
pub mod p256;
