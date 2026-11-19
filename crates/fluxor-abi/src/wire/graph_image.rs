// The graph image header.
//
// Every graph a kernel runs comes as one graph image: this 256-byte header,
// the module table (with the graph's program section after it) and the static
// config. The same header opens an RP flash A/B slot, an image staged in RAM
// for OTA, the payload a combined firmware image carries after the kernel
// (RP, bcm2712, uefi) and the graph file a Linux runtime is given. The tools
// write it (`fluxor build`), the kernel admits it, and `graph_slot` and
// `ota_ingest` read it, all through this codec.
//
// Header (256 bytes, little-endian):
//
//   0..4     magic "FXSL"
//   4        version
//   5..8     unused (0xFF)
//   8..16    epoch (u64)
//   16..20   modules offset    20..24  modules size
//   24..28   config offset     28..32  config size
//   32..64   SHA-256 over the modules region then the config region
//   64..96   ABI-surface pin
//   96..168  signature record (below), or erased (0xFF) when unsigned
//   168..256 unused (0xFF)
//
// Offsets are from the header's first byte. The module table starts on a
// 4 KiB boundary of the address the image runs at (an aarch64 module's code
// base is page-aligned for ADRP) and the config on the next 256-byte boundary
// after the table ([`place`]).
//
// The signature record is `[magic "SIG1"][key id: the first four bytes of
// SHA-256(public key)][Ed25519 signature R ‖ S]` over the header's first
// [`SIGNED_LEN`] bytes: the epoch, both regions, the payload digest and the
// pin. The payload is bound through its digest, so a reader that admits a
// signature also checks the payload against that digest. A kernel image with
// a signing root admits only an image whose record verifies against it; one
// without checks no signature.

/// `"FXSL"`.
pub const MAGIC: u32 = 0x4C53_5846;
pub const VERSION: u8 = 1;
/// Bytes of the header; the payload starts at or after it.
pub const HEADER_SIZE: usize = 256;
/// Header offset of the payload's SHA-256.
pub const DIGEST_AT: usize = 32;
/// Header offset of the 32-byte ABI-surface pin: the `abi_surface` digest of
/// the substrate the image was built against. A reader admits an image only
/// when it equals its own.
pub const ABI_PIN_AT: usize = 64;
/// The header bytes a signature covers.
pub const SIGNED_LEN: usize = 96;
/// Header offset of the signature record.
pub const SIGNATURE_AT: usize = 96;
/// `"SIG1"`.
pub const SIGNATURE_MAGIC: u32 = 0x3147_4953;
/// Bytes of the signature record: magic, key id, signature.
pub const SIGNATURE_LEN: usize = 72;
/// The smallest module table: its own header.
pub const MIN_MODULES_SIZE: u32 = 16;
/// Alignment of the module table, at the address the image runs at.
pub const MODULES_ALIGN: u64 = 4096;
/// Alignment of the config after the table.
pub const CONFIG_ALIGN: u64 = 256;

const _: () = {
    assert!(SIGNATURE_AT == SIGNED_LEN);
    assert!(SIGNATURE_LEN == 4 + 4 + 64);
    assert!(SIGNATURE_AT + SIGNATURE_LEN <= HEADER_SIZE);
    assert!(ABI_PIN_AT + 32 == SIGNED_LEN);
};

/// What a header says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub epoch: u64,
    pub modules_offset: u32,
    pub modules_size: u32,
    pub config_offset: u32,
    pub config_size: u32,
    /// SHA-256 over the modules region then the config region.
    pub digest: [u8; 32],
    pub abi_pin: [u8; 32],
}

/// Why bytes are not a header a reader can act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Malformed {
    /// Fewer than [`HEADER_SIZE`] bytes.
    Short,
    /// Not `"FXSL"`.
    Magic,
    /// A version this codec does not read.
    Version,
    /// The regions overlap the header or each other, the module table is
    /// shorter than its own header, the config is empty, or the payload
    /// reaches past what holds the image.
    Regions,
}

fn word(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

impl Header {
    /// The header bytes, unsigned: the signature record and every unused
    /// byte erased (0xFF), as flash reads before it is programmed.
    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0xFFu8; HEADER_SIZE];
        out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        out[4] = VERSION;
        out[8..16].copy_from_slice(&self.epoch.to_le_bytes());
        out[16..20].copy_from_slice(&self.modules_offset.to_le_bytes());
        out[20..24].copy_from_slice(&self.modules_size.to_le_bytes());
        out[24..28].copy_from_slice(&self.config_offset.to_le_bytes());
        out[28..32].copy_from_slice(&self.config_size.to_le_bytes());
        out[DIGEST_AT..DIGEST_AT + 32].copy_from_slice(&self.digest);
        out[ABI_PIN_AT..ABI_PIN_AT + 32].copy_from_slice(&self.abi_pin);
        out
    }

    /// Read the header at the start of `bytes`, an image `extent` bytes long
    /// (a slot's size, what was staged, the window a firmware image's
    /// payload lies in, a file's length). Checks the shape only: the pin,
    /// the digest and the signature are the reader's to check.
    pub fn decode(bytes: &[u8], extent: u64) -> Result<Header, Malformed> {
        if bytes.len() < HEADER_SIZE {
            return Err(Malformed::Short);
        }
        if word(bytes, 0) != MAGIC {
            return Err(Malformed::Magic);
        }
        if bytes[4] != VERSION {
            return Err(Malformed::Version);
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[DIGEST_AT..DIGEST_AT + 32]);
        let mut abi_pin = [0u8; 32];
        abi_pin.copy_from_slice(&bytes[ABI_PIN_AT..ABI_PIN_AT + 32]);
        let h = Header {
            epoch: u64::from(word(bytes, 8)) | (u64::from(word(bytes, 12)) << 32),
            modules_offset: word(bytes, 16),
            modules_size: word(bytes, 20),
            config_offset: word(bytes, 24),
            config_size: word(bytes, 28),
            digest,
            abi_pin,
        };
        let modules_end = u64::from(h.modules_offset) + u64::from(h.modules_size);
        let fits = h.modules_offset as usize >= HEADER_SIZE
            && h.modules_size >= MIN_MODULES_SIZE
            && u64::from(h.config_offset) >= modules_end
            && h.config_size != 0
            && h.end() <= extent;
        if fits {
            Ok(h)
        } else {
            Err(Malformed::Regions)
        }
    }

    /// Where the payload ends: the config's last byte, plus one.
    pub fn end(&self) -> u64 {
        u64::from(self.config_offset) + u64::from(self.config_size)
    }

    /// The module table's bytes in `image`, which `decode` bounded.
    pub fn modules<'a>(&self, image: &'a [u8]) -> &'a [u8] {
        let at = self.modules_offset as usize;
        &image[at..at + self.modules_size as usize]
    }

    /// The config's bytes in `image`, which `decode` bounded.
    pub fn config<'a>(&self, image: &'a [u8]) -> &'a [u8] {
        let at = self.config_offset as usize;
        &image[at..at + self.config_size as usize]
    }
}

/// Where a header placed at address `base` puts a module table of
/// `modules_len` bytes and the config after it: `(modules_offset,
/// config_offset)`, from the header.
pub const fn place(base: u64, modules_len: u64) -> (u64, u64) {
    let modules_at = (base + HEADER_SIZE as u64).div_ceil(MODULES_ALIGN) * MODULES_ALIGN;
    let config_at = (modules_at + modules_len).div_ceil(CONFIG_ALIGN) * CONFIG_ALIGN;
    (modules_at - base, config_at - base)
}

/// A header's signature record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    /// The first four bytes of SHA-256 of the signer's public key.
    pub key_id: [u8; 4],
    /// Ed25519, R ‖ S, over the header's first [`SIGNED_LEN`] bytes.
    pub signature: [u8; 64],
}

/// The record a header carries, `None` for an unsigned one.
pub fn signature(header: &[u8]) -> Option<Signature> {
    if header.len() < SIGNATURE_AT + SIGNATURE_LEN || word(header, SIGNATURE_AT) != SIGNATURE_MAGIC
    {
        return None;
    }
    let mut key_id = [0u8; 4];
    key_id.copy_from_slice(&header[SIGNATURE_AT + 4..SIGNATURE_AT + 8]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&header[SIGNATURE_AT + 8..SIGNATURE_AT + SIGNATURE_LEN]);
    Some(Signature { key_id, signature })
}

/// Write a signature record into a header.
pub fn put_signature(header: &mut [u8], record: &Signature) {
    header[SIGNATURE_AT..SIGNATURE_AT + 4].copy_from_slice(&SIGNATURE_MAGIC.to_le_bytes());
    header[SIGNATURE_AT + 4..SIGNATURE_AT + 8].copy_from_slice(&record.key_id);
    header[SIGNATURE_AT + 8..SIGNATURE_AT + SIGNATURE_LEN].copy_from_slice(&record.signature);
}
