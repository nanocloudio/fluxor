// The `.fmod` container's signed region.
//
// The one definition of which bytes a module signature covers. The signer
// (`fluxor modules sign`) and the kernel loader's verifier both feed this
// envelope to SHA-256 and sign or verify the digest, so the two cannot
// disagree about the layout.
//
// Mounted by the kernel and the SDK as `abi::wire::fmod` and by the host
// tools as `fmod`. Only scalars and functions: nothing here puts an
// absolute address in a module's `.rodata`.

/// Size of the `.fmod` module header.
pub const MODULE_HEADER_SIZE: usize = 80;

/// Header bytes `[64..66]` hold `manifest_size`. Signing appends the
/// signature block and so grows the manifest; the envelope skips them.
pub const HEADER_MANIFEST_SIZE_AT: usize = 64;

/// Size of the manifest's fixed head: magic (4), version (1), port,
/// resource and dependency counts (3), module version (2), hardware
/// targets (2), state size (2), flags (1), permissions (2).
pub const MANIFEST_HEADER_SIZE: usize = 17;

/// Byte of the manifest head holding the flag bits below.
pub const MANIFEST_FLAGS_AT: usize = 14;

/// Manifest flag: integrity hash (SHA-256 of code ‖ data) present.
pub const FLAG_INTEGRITY: u8 = 0x01;
/// Manifest flag: signature block (64-byte signature ‖ 32-byte signer
/// fingerprint) present, directly after the integrity hash.
pub const FLAG_SIGNATURE: u8 = 0x02;
/// Manifest flag: ABI-surface attestation (32 bytes) present, last.
pub const FLAG_ATTESTATION: u8 = 0x10;
/// Manifest flag: port-capacity block (8 bytes per port) present.
pub const FLAG_PORT_CAPACITY: u8 = 0x20;
/// Manifest flag: stack block (2 bytes) present.
pub const FLAG_STACK: u8 = 0x40;
/// Manifest flag: arena block (4 bytes) present.
pub const FLAG_ARENA: u8 = 0x80;

/// Size of the integrity hash and of the attestation.
pub const DIGEST_SIZE: usize = 32;
/// Size of the signature block: signature (64) ‖ signer fingerprint (32).
pub const SIGNATURE_BLOCK_SIZE: usize = 96;

/// Offsets of the manifest's flag-selected blocks, from its counts and
/// flags. Each block follows the previous one; absent blocks take no space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestLayout {
    /// Port-capacity block (`FLAG_PORT_CAPACITY`).
    pub capacity: usize,
    /// Stack block (`FLAG_STACK`).
    pub stack: usize,
    /// Arena block (`FLAG_ARENA`).
    pub arena: usize,
    /// Integrity hash (`FLAG_INTEGRITY`); the signature block follows it.
    pub hash: usize,
    /// Attestation (`FLAG_ATTESTATION`); the manifest ends 32 bytes later.
    pub attestation: usize,
}

impl ManifestLayout {
    /// Layout of a manifest with these counts and flags.
    pub const fn of(port_count: u8, resource_count: u8, dep_count: u8, flags: u8) -> Self {
        let ports = port_count as usize;
        let capacity =
            MANIFEST_HEADER_SIZE + ports * 4 + resource_count as usize * 4 + dep_count as usize * 8;
        let stack = capacity
            + if flags & FLAG_PORT_CAPACITY != 0 {
                ports * 8
            } else {
                0
            };
        let arena = stack + if flags & FLAG_STACK != 0 { 2 } else { 0 };
        let hash = arena + if flags & FLAG_ARENA != 0 { 4 } else { 0 };
        let attestation =
            hash + if flags & (FLAG_INTEGRITY | FLAG_SIGNATURE) != 0 {
                DIGEST_SIZE
            } else {
                0
            } + if flags & FLAG_SIGNATURE != 0 {
                SIGNATURE_BLOCK_SIZE
            } else {
                0
            };
        Self {
            capacity,
            stack,
            arena,
            hash,
            attestation,
        }
    }

    /// Layout read from a manifest's head; `None` when the head is short.
    pub fn read(manifest: &[u8]) -> Option<Self> {
        if manifest.len() < MANIFEST_HEADER_SIZE {
            return None;
        }
        Some(Self::of(
            manifest[5],
            manifest[6],
            manifest[7],
            manifest[MANIFEST_FLAGS_AT],
        ))
    }
}

/// Why a module image has no well-formed signing envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The image is shorter than its header, or the manifest shorter than
    /// the blocks its flags declare.
    Truncated,
    /// The manifest declares an attestation but does not end exactly after
    /// it at its canonical offset.
    NonCanonical,
}

/// Feed a module's signing envelope to `sink`, in order.
///
/// `image` is everything before the manifest (header ‖ code ‖ data ‖ export
/// table ‖ schema); `manifest` is the manifest section. The envelope is:
///
/// - `image[0..64] ‖ image[66..]`: the header without `manifest_size`, then
///   code, data, exports and schema;
/// - `manifest[0..hash]` with the integrity and signature flag bits masked:
///   the head, ports, resources, dependencies, port capacities, stack and
///   arena — the only bytes before the hash that differ between the
///   unsigned and the signed manifest are those two bits;
/// - the attestation, at its canonical offset, when present. The manifest
///   must end exactly after it: an inflated manifest could otherwise carry a
///   second, signed copy while parsers read a substituted one.
///
/// The signer may pass a manifest whose hash and signature are
/// placeholders: neither is in the envelope.
pub fn signing_envelope<F: FnMut(&[u8])>(
    image: &[u8],
    manifest: &[u8],
    mut sink: F,
) -> Result<(), EnvelopeError> {
    if image.len() < MODULE_HEADER_SIZE {
        return Err(EnvelopeError::Truncated);
    }
    let layout = match ManifestLayout::read(manifest) {
        Some(l) => l,
        None => return Err(EnvelopeError::Truncated),
    };
    if layout.hash > manifest.len() {
        return Err(EnvelopeError::Truncated);
    }
    let flags = manifest[MANIFEST_FLAGS_AT];
    if flags & FLAG_ATTESTATION != 0 && manifest.len() != layout.attestation + DIGEST_SIZE {
        return Err(EnvelopeError::NonCanonical);
    }
    sink(&image[..HEADER_MANIFEST_SIZE_AT]);
    sink(&image[HEADER_MANIFEST_SIZE_AT + 2..]);
    sink(&manifest[..MANIFEST_FLAGS_AT]);
    sink(&[flags & !(FLAG_INTEGRITY | FLAG_SIGNATURE)]);
    sink(&manifest[MANIFEST_FLAGS_AT + 1..layout.hash]);
    if flags & FLAG_ATTESTATION != 0 {
        sink(&manifest[layout.attestation..]);
    }
    Ok(())
}
