//! Kernel-side cryptography for the loader's root-of-trust.
//!
//! Hand-rolled SHA-512 and Ed25519 verification. These primitives intentionally
//! live in the kernel because the loader's signature check must run before any
//! PIC module is admitted — we cannot bootstrap module verification through a
//! module that itself awaits verification.
//!
//! No external crates: pure Rust, no_std-compatible. The implementations
//! prioritise readability over peak performance; a single Ed25519 verify takes
//! a few milliseconds on bcm2712, run at most once per module load, which is
//! well within the boot budget.

pub mod sha512;
pub mod ed25519;
pub mod p256;
