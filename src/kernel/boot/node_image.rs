//! Node-image admission: the one check every node image passes before the
//! kernel runs anything from it, wherever it came from (an RP flash slot, the
//! payload a firmware image carries after the kernel, an OTA image staged in
//! RAM, a Linux runtime's graph file).
//!
//! An image is admitted when its header (`abi::wire::node_image`) is well
//! formed for the bytes that hold it, its ABI-surface pin equals this
//! kernel's own, and, when the kernel image carries a signing root, its
//! signature verifies against that root (`security::image_signature`) and its
//! payload hashes to the digest the signature covers. Without a root nothing
//! vouches for the digest, so the payload is not hashed.

use crate::abi::wire::node_image::{Header, Malformed};
use crate::kernel::security::image_signature;

/// Why an image was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The header is not one the codec reads, or its regions do not fit.
    Malformed(Malformed),
    /// Built against another ABI surface.
    Pin,
    /// Not signed by this kernel image's root.
    Signature(image_signature::Refusal),
    /// The payload is not what the header's digest names.
    Digest,
}

impl Refusal {
    /// What a log line says of the refusal.
    pub fn reason(self) -> &'static str {
        match self {
            Refusal::Malformed(Malformed::Short) => "shorter than a header",
            Refusal::Malformed(Malformed::Magic) => "no node image header",
            Refusal::Malformed(Malformed::Version) => "header version",
            Refusal::Malformed(Malformed::Regions) => "regions do not fit",
            Refusal::Pin => "built against another ABI surface",
            Refusal::Signature(image_signature::Refusal::Unsigned) => "unsigned",
            Refusal::Signature(image_signature::Refusal::WrongKey) => "signed by another key",
            Refusal::Signature(image_signature::Refusal::BadSignature) => "signature",
            Refusal::Digest => "payload digest",
        }
    }
}

/// This kernel's ABI-surface digest: sha256 over the canonical
/// `abi_surface` stream, the value every image's pin must equal. Computed on
/// demand (a few KB of hashing).
pub fn own_abi_pin() -> [u8; 32] {
    use crate::kernel::security::crypto::sha256::Sha256;
    let mut h = Sha256::new();
    crate::abi::abi_surface::write_surface(&mut |bytes| h.update(bytes));
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Admit the node image `image`, header first, as long as what holds it:
/// shape, then pin, then (under the kernel image's signing root) signature and
/// payload digest. Answers the header, whose regions lie inside `image`.
pub fn admit(image: &[u8], own_pin: &[u8; 32]) -> Result<Header, Refusal> {
    let header = Header::decode(image, image.len() as u64).map_err(Refusal::Malformed)?;
    if header.abi_pin != *own_pin {
        return Err(Refusal::Pin);
    }
    let root = crate::kernel::security::root::signing_root();
    image_signature::admits(image, root.as_ref()).map_err(Refusal::Signature)?;
    if root.is_none() {
        return Ok(header);
    }
    let mut h = crate::kernel::security::crypto::sha256::Sha256::new();
    h.update(header.modules(image));
    h.update(header.config(image));
    if h.finalize()[..] != header.digest {
        return Err(Refusal::Digest);
    }
    Ok(header)
}
