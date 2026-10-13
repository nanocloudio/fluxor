//! Graph-slot signatures: the root this kernel was built to trust, and the
//! check every reader of a graph-image header makes against it.
//!
//! A graph image's 256-byte header (`flash_layout::GRAPH_SLOT_*`) is signed
//! over its first 96 bytes (`GRAPH_SLOT_SIGNED_LEN`): magic, version, epoch,
//! both regions' offsets and sizes, the SHA-256 of the payload and the
//! ABI-surface pin. The signature record follows at
//! `GRAPH_SLOT_SIGNATURE_OFFSET`:
//!
//! ```text
//!   96..100   magic "SIG1" (u32 LE 0x3147_4953)
//!   100..104  key id: the first four bytes of SHA-256(public key)
//!   104..168  Ed25519 signature, R ‖ S
//! ```
//!
//! The payload is bound through its digest, so one signature vouches for
//! every module, the program section and the config together; a reader that
//! admits a signature must also check the payload against that digest. The
//! epoch is signed, so a signed image cannot be replayed under a higher one.
//! Bytes 168..256 are neither signed nor read.
//!
//! The root is a build-time fact: `FLUXOR_SLOT_ROOT_HEX`, the 32-byte Ed25519
//! public key in 64 hex digits, compiled in; any other value fails the build.
//! A kernel built with a root admits only an image whose record verifies
//! against it: at boot slot selection, at OTA staging, and (through
//! `SLOT_SIGNING_ROOT`) at `graph_slot`'s ACTIVATE. A kernel built without
//! one checks no signature, so it admits signed and unsigned images alike on
//! their structure, pin and epoch.
//!
//! The signature is checked by the kernel's strict Ed25519 verifier, which
//! applies the same rules as the one `graph_slot` mounts, so the boot
//! selector and ACTIVATE reach the same verdict on every image. The public
//! key is the compiled-in root, never read from the image.

use crate::abi::platform::rp::flash_layout as fl;

/// `FLUXOR_SLOT_ROOT_HEX`, parsed at compile time.
const SLOT_ROOT: Option<[u8; 32]> = match super::build_time_key(option_env!("FLUXOR_SLOT_ROOT_HEX"))
{
    Ok(root) => root,
    Err(crate::kernel::security::MalformedKey) => {
        panic!("FLUXOR_SLOT_ROOT_HEX must be 64 hex digits: a 32-byte Ed25519 public key")
    }
};

/// The slot root this kernel was built with, if any.
pub fn slot_root() -> Option<[u8; 32]> {
    SLOT_ROOT
}

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

/// Whether `header` is admitted under `root`: `None` (a kernel built without
/// a root) admits every header, and a root admits only a header whose record
/// names it and verifies over the signed bytes. A header too short to hold a
/// record has none. The caller still checks the payload against the digest
/// the signed bytes name.
pub fn admits(header: &[u8], root: Option<&[u8; 32]>) -> Result<(), Refusal> {
    let Some(root) = root else {
        return Ok(());
    };
    let at = fl::GRAPH_SLOT_SIGNATURE_OFFSET;
    if header.len() < at + fl::GRAPH_SLOT_SIGNATURE_LEN {
        return Err(Refusal::Unsigned);
    }
    let magic = u32::from_le_bytes([header[at], header[at + 1], header[at + 2], header[at + 3]]);
    if magic != fl::GRAPH_SLOT_SIGNATURE_MAGIC {
        return Err(Refusal::Unsigned);
    }
    let id = {
        let mut h = crate::kernel::security::crypto::sha256::Sha256::new();
        h.update(root);
        h.finalize()
    };
    if header[at + 4..at + 8] != id[..4] {
        return Err(Refusal::WrongKey);
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&header[at + 8..at + 72]);
    if crate::kernel::security::crypto::ed25519::verify(
        root,
        &header[..fl::GRAPH_SLOT_SIGNED_LEN],
        &sig,
    ) {
        Ok(())
    } else {
        Err(Refusal::BadSignature)
    }
}

const _: () = {
    // The record sits right after the signed bytes and is magic, key id and
    // signature, inside the header.
    assert!(fl::GRAPH_SLOT_SIGNATURE_OFFSET == fl::GRAPH_SLOT_SIGNED_LEN);
    assert!(fl::GRAPH_SLOT_SIGNATURE_LEN == 4 + 4 + 64);
    assert!(
        fl::GRAPH_SLOT_SIGNATURE_OFFSET + fl::GRAPH_SLOT_SIGNATURE_LEN
            <= fl::GRAPH_SLOT_HEADER_SIZE
    );
};
