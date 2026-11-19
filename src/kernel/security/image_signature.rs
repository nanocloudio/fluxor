//! Graph-image signatures: the check every reader of a graph-image header
//! (`abi::wire::graph_image`) makes against the kernel image's signing root.
//!
//! A header is signed over its first `SIGNED_LEN` bytes: magic, version,
//! epoch, both regions' offsets and sizes, the payload's SHA-256 and the
//! ABI-surface pin. The payload is bound through its digest, so one signature
//! vouches for every module, the program section and the config together; a
//! reader that admits a signature also checks the payload against that
//! digest. The epoch is signed, so a signed image cannot be replayed under a
//! higher one.
//!
//! The root is the kernel image's signing root (`security::root`), the one
//! that verifies modules too. A kernel with a root admits only an image whose
//! record verifies against it: at boot, at OTA staging, and (through
//! `SIGNING_ROOT`) at `graph_slot`'s ACTIVATE. A rootless kernel checks no
//! signature, so it admits signed and unsigned images alike on their
//! structure, pin and digest.
//!
//! The signature is checked by the kernel's strict Ed25519 verifier, which
//! applies the same rules as the one `graph_slot` mounts, so the boot
//! selector and ACTIVATE reach the same verdict on every image. The public
//! key is the root, never read from the image.

use crate::abi::wire::graph_image;

/// Why a header was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// No `SIG1` record where one is required.
    Unsigned,
    /// A record whose key id is not the root's.
    WrongKey,
    /// A record that does not verify.
    BadSignature,
}

/// Whether `header` is admitted under `root`: `None` (a kernel image without
/// a root) admits every header, and a root admits only a header whose record
/// names it and verifies over the signed bytes. A header too short to hold a
/// record has none.
pub fn admits(header: &[u8], root: Option<&[u8; 32]>) -> Result<(), Refusal> {
    let Some(root) = root else {
        return Ok(());
    };
    let record = graph_image::signature(header).ok_or(Refusal::Unsigned)?;
    let id = {
        let mut h = crate::kernel::security::crypto::sha256::Sha256::new();
        h.update(root);
        h.finalize()
    };
    if record.key_id != id[..4] {
        return Err(Refusal::WrongKey);
    }
    if crate::kernel::security::crypto::ed25519::ed25519_verify(
        root,
        &header[..graph_image::SIGNED_LEN],
        &record.signature,
    ) {
        Ok(())
    } else {
        Err(Refusal::BadSignature)
    }
}
