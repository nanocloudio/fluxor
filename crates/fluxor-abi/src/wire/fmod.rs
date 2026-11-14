// The `.fmod` container: its header, the module table, the manifest's
// layout, and the signed region.
//
// The one definition of these bytes. The packer, the signer (`fluxor
// modules sign`), the kernel loader and its verifier all read them from
// here, so none can disagree about the layout. Only scalars and functions:
// nothing here puts an absolute address in a module's `.rodata`.

/// The module header: named fields only, little-endian. Every reader and
/// writer — the packer, the kernel loader, the signer, the tools — takes its
/// offsets from here.
pub mod header {
    /// Size of the header.
    pub const SIZE: usize = 56;
    /// `u32` magic, `"FXMD"`.
    pub const MAGIC: usize = 0;
    /// `u8` container version.
    pub const VERSION: usize = 4;
    /// `u8` `wire::ABI_VERSION` the module was built for.
    pub const ABI_VERSION: usize = 5;
    /// `u8` module type: its dataflow role (source, transformer, sink, event
    /// handler). It carries no authority.
    pub const MODULE_TYPE: usize = 6;
    /// `u8` the [`flag`] bits.
    pub const FLAGS: usize = 7;
    /// `u32` code bytes.
    pub const CODE_SIZE: usize = 8;
    /// `u32` initialised-data bytes.
    pub const DATA_SIZE: usize = 12;
    /// `u16` export-table entries; the table follows code and data.
    pub const EXPORT_COUNT: usize = 16;
    /// `u16` params-schema bytes; the schema follows the export table.
    pub const SCHEMA_SIZE: usize = 18;
    /// `u16` manifest bytes; the manifest follows the schema. Signing grows
    /// the manifest, so the signing envelope skips this field.
    pub const MANIFEST_SIZE: usize = 20;
    /// `u8` step period in scheduler ticks (0: every tick).
    pub const STEP_PERIOD: usize = 22;
    /// `u8` step phase, below the period.
    pub const STEP_PHASE: usize = 23;
    /// `[u8; 32]` type name, NUL-padded.
    pub const NAME: usize = 24;
    /// Bytes of [`NAME`].
    pub const NAME_LEN: usize = 32;

    /// Module facts in the header's [`FLAGS`] byte. The packer sets each
    /// from the module's manifest (or, for `DRAIN` and `ISR`, from the entry
    /// point being present); the kernel reads them and never asks the
    /// module.
    pub mod flag {
        /// Consumes from mailbox channels safely.
        pub const MAILBOX_SAFE: u8 = 0x01;
        /// Writes its output buffer in place.
        pub const IN_PLACE_WRITER: u8 = 0x02;
        /// Needs init time before its downstream runs.
        pub const DEFERRED_READY: u8 = 0x04;
        /// Defines `module_drain`.
        pub const DRAIN: u8 = 0x08;
        /// Defines `module_isr_entry`.
        pub const ISR: u8 = 0x10;
        /// The body is a wasm payload.
        pub const WASM_PAYLOAD: u8 = 0x20;
        /// A provider told when a consumer's owner is released.
        pub const OBSERVES_OWNER_RELEASE: u8 = 0x40;
        /// A provider the resource ledger asks for a pool's in-use figure.
        pub const SAMPLES_POOL: u8 = 0x80;
    }

    fn u16_at(h: &[u8], at: usize) -> u16 {
        u16::from_le_bytes([h[at], h[at + 1]])
    }
    fn u32_at(h: &[u8], at: usize) -> u32 {
        u32::from_le_bytes([h[at], h[at + 1], h[at + 2], h[at + 3]])
    }

    /// A header's fields, read from its bytes.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Header {
        pub magic: u32,
        pub version: u8,
        pub abi_version: u8,
        pub module_type: u8,
        pub flags: u8,
        pub code_size: u32,
        pub data_size: u32,
        pub export_count: u16,
        pub schema_size: u16,
        pub manifest_size: u16,
        pub step_period: u8,
        pub step_phase: u8,
        pub name: [u8; NAME_LEN],
    }

    impl Header {
        /// Read a header; `None` when `h` is shorter than [`SIZE`].
        pub fn read(h: &[u8]) -> Option<Self> {
            if h.len() < SIZE {
                return None;
            }
            let mut name = [0u8; NAME_LEN];
            name.copy_from_slice(&h[NAME..NAME + NAME_LEN]);
            Some(Self {
                magic: u32_at(h, MAGIC),
                version: h[VERSION],
                abi_version: h[ABI_VERSION],
                module_type: h[MODULE_TYPE],
                flags: h[FLAGS],
                code_size: u32_at(h, CODE_SIZE),
                data_size: u32_at(h, DATA_SIZE),
                export_count: u16_at(h, EXPORT_COUNT),
                schema_size: u16_at(h, SCHEMA_SIZE),
                manifest_size: u16_at(h, MANIFEST_SIZE),
                step_period: h[STEP_PERIOD],
                step_phase: h[STEP_PHASE],
                name,
            })
        }

        /// The header's bytes.
        pub fn to_bytes(&self) -> [u8; SIZE] {
            let mut h = [0u8; SIZE];
            h[MAGIC..MAGIC + 4].copy_from_slice(&self.magic.to_le_bytes());
            h[VERSION] = self.version;
            h[ABI_VERSION] = self.abi_version;
            h[MODULE_TYPE] = self.module_type;
            h[FLAGS] = self.flags;
            h[CODE_SIZE..CODE_SIZE + 4].copy_from_slice(&self.code_size.to_le_bytes());
            h[DATA_SIZE..DATA_SIZE + 4].copy_from_slice(&self.data_size.to_le_bytes());
            h[EXPORT_COUNT..EXPORT_COUNT + 2].copy_from_slice(&self.export_count.to_le_bytes());
            h[SCHEMA_SIZE..SCHEMA_SIZE + 2].copy_from_slice(&self.schema_size.to_le_bytes());
            h[MANIFEST_SIZE..MANIFEST_SIZE + 2].copy_from_slice(&self.manifest_size.to_le_bytes());
            h[STEP_PERIOD] = self.step_period;
            h[STEP_PHASE] = self.step_phase;
            h[NAME..NAME + NAME_LEN].copy_from_slice(&self.name);
            h
        }

        /// The type name, up to its NUL.
        pub fn name_bytes(&self) -> &[u8] {
            let end = self.name.iter().position(|&b| b == 0).unwrap_or(NAME_LEN);
            &self.name[..end]
        }
    }
}

/// The module table (`FXMT`) that holds a packed image's modules: a header,
/// then one entry per module, then the modules, then the program section.
pub mod table {
    /// Size of the table header.
    pub const HEADER_SIZE: usize = 16;
    /// `u32` magic, `"FXMT"`.
    pub const MAGIC: usize = 0;
    /// `u16` table version.
    pub const VERSION: usize = 4;
    /// `u16` entries.
    pub const MODULE_COUNT: usize = 6;
    /// `u32` bytes of the whole table, modules included.
    pub const TOTAL_SIZE: usize = 8;
    /// `u32` offset of the program section from the table's start; 0 when
    /// the image carries none.
    pub const PROGRAM_SECTION_OFFSET: usize = 12;

    /// Size of one entry.
    pub const ENTRY_SIZE: usize = 12;
    /// `u32` FNV-1a hash of the module's type name.
    pub const ENTRY_NAME_HASH: usize = 0;
    /// `u32` offset of the module from the table's start.
    pub const ENTRY_OFFSET: usize = 4;
    /// `u32` bytes of the module.
    pub const ENTRY_SIZE_AT: usize = 8;
}

/// Size of the `.fmod` module header.
pub const MODULE_HEADER_SIZE: usize = header::SIZE;

/// The header's `manifest_size` field: signing appends the signature block
/// and so grows the manifest; the envelope skips these two bytes.
pub const HEADER_MANIFEST_SIZE_AT: usize = header::MANIFEST_SIZE;

/// `u32` magic opening a manifest, `"FXMF"`.
pub const MANIFEST_MAGIC: u32 = 0x464D_5846;

/// Size of the manifest's fixed head: magic (4), version (1), port,
/// resource and dependency counts (3), module version (2), hardware
/// targets (2), flags (1), provided contracts (1), state size (4), grants
/// (16).
pub const MANIFEST_HEADER_SIZE: usize = 34;

/// Byte of the manifest head holding the flag bits below.
pub const MANIFEST_FLAGS_AT: usize = 12;

/// Byte of the manifest head counting the contracts the module provides.
pub const MANIFEST_PROVIDES_AT: usize = 13;

/// `u32` of the manifest head: one instance's state, in 64-byte units
/// rounded up. Wide enough for any state a module can have, so the figure
/// is always the size, never a floor.
pub const MANIFEST_STATE_AT: usize = 14;

/// Two `u64`s of the manifest head: the module's grants. Word 0 holds a bit
/// per contract id (its `[[resources]]` claims and the contracts its
/// `grants` name), word 1 a bit per op-level grant (`registry::grant`).
pub const MANIFEST_GRANTS_AT: usize = 18;

/// Read the grants from a manifest head of at least
/// [`MANIFEST_HEADER_SIZE`] bytes.
pub fn manifest_grants(head: &[u8]) -> [u64; 2] {
    let word = |at: usize| {
        let mut b = [0u8; 8];
        b.copy_from_slice(&head[at..at + 8]);
        u64::from_le_bytes(b)
    };
    [word(MANIFEST_GRANTS_AT), word(MANIFEST_GRANTS_AT + 8)]
}

/// Most contracts one module provides: one provider state serves them all
/// through one dispatch, telling them apart by opcode class.
pub const MAX_PROVIDES: usize = 4;

/// Manifest flag: integrity hash (SHA-256 of code ‖ data) present.
pub const FLAG_INTEGRITY: u8 = 0x01;
/// Manifest flag: signature block (64-byte signature ‖ 32-byte signer
/// fingerprint) present, directly after the integrity hash.
pub const FLAG_SIGNATURE: u8 = 0x02;
/// Manifest flag: ABI-surface attestation (32 bytes) present, last.
pub const FLAG_ATTESTATION: u8 = 0x10;
/// Manifest flag: port-capacity block (8 bytes per port) present.
pub const FLAG_PORT_CAPACITY: u8 = 0x20;

/// Size of the integrity hash and of the attestation.
pub const DIGEST_SIZE: usize = 32;
/// Size of the signature block: signature (64) ‖ signer fingerprint (32).
pub const SIGNATURE_BLOCK_SIZE: usize = 96;

/// Offsets of the manifest's blocks, from its counts and flags. Each block
/// follows the previous one; a flag-selected block that is absent takes no
/// space. Stack, arena and the provided-contract list are always present:
/// every module states them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestLayout {
    /// Port-capacity block (`FLAG_PORT_CAPACITY`).
    pub capacity: usize,
    /// Stack block: `u16` stack depth in 64-byte units.
    pub stack: usize,
    /// Arena block: `u32` heap-arena bytes.
    pub arena: usize,
    /// Provided contracts: one `u16` contract id each, as many as the head's
    /// count.
    pub provides: usize,
    /// Integrity hash (`FLAG_INTEGRITY`); the signature block follows it.
    pub hash: usize,
    /// Attestation (`FLAG_ATTESTATION`); the manifest ends 32 bytes later.
    pub attestation: usize,
}

impl ManifestLayout {
    /// Layout of a manifest with these counts and flags.
    pub const fn of(
        port_count: u8,
        resource_count: u8,
        dep_count: u8,
        provides_count: u8,
        flags: u8,
    ) -> Self {
        let ports = port_count as usize;
        let capacity =
            MANIFEST_HEADER_SIZE + ports * 4 + resource_count as usize * 4 + dep_count as usize * 8;
        let stack = capacity
            + if flags & FLAG_PORT_CAPACITY != 0 {
                ports * 8
            } else {
                0
            };
        let arena = stack + 2;
        let provides = arena + 4;
        let hash = provides + provides_count as usize * 2;
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
            provides,
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
            manifest[MANIFEST_PROVIDES_AT],
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
/// - the image with the header's `manifest_size` field skipped: the header,
///   then code, data, exports and schema;
/// - `manifest[0..hash]` with the integrity and signature flag bits masked:
///   the head, ports, resources, dependencies, port capacities, stack,
///   arena and provided contracts — the only bytes before the hash that
///   differ between the unsigned and the signed manifest are those two bits;
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
