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

// ChaCha20-Poly1305, mounted from the SDK's implementation rather than
// copied.
//
// The kernel needs an AEAD for key sealing, and the SDK already has a
// tested one — `no_std`, no external crates, with its own KATs. Copying it
// would produce two implementations of the same primitive that could
// diverge, and the one that diverged silently would be whichever had fewer
// tests. Mounting the source keeps one implementation and one set of
// vectors.
//
// `//` rather than `///`: the included file carries its own inner doc, and
// an outer doc here would collide with it.
#[allow(
    dead_code,
    reason = "the SDK file is one implementation shared by PIC modules and the \
              kernel; the kernel uses the AEAD entry points and not every \
              helper the module builds reach for"
)]
pub mod chacha20 {
    //! ChaCha20 and ChaCha20-Poly1305 (RFC 8439).
    //!
    //! The SDK file expects `zeroize` in scope — the flat-`include!`
    //! convention every PIC module uses, where `p256.rs` supplies it. This
    //! wrapper provides it and includes the source, so the kernel gets the
    //! same implementation without mounting a second P-256 beside its own.

    /// Overwrite `buf`, volatile so the writes survive optimisation.
    fn zeroize(buf: &mut [u8]) {
        for b in buf.iter_mut() {
            // SAFETY: `b` is a live, exclusively-borrowed byte.
            unsafe { core::ptr::write_volatile(b, 0) };
        }
    }

    include!("../../../../modules/sdk/crypto/chacha20.rs");
}

pub mod ed25519;
pub mod p256;
pub mod sha256;
pub mod sha512;
