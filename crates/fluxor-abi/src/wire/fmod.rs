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

/// Byte of the manifest head counting the contracts the module provides
/// (its [`PROVIDES_COUNT_MASK`] bits), with the [`PROVIDES_WORKLOAD_INSTANTIABLE`]
/// fact in its top bit.
pub const MANIFEST_PROVIDES_AT: usize = 13;

/// Bits of the [`MANIFEST_PROVIDES_AT`] byte that count provided contracts.
pub const PROVIDES_COUNT_MASK: u8 = 0x0F;

/// Bit of the [`MANIFEST_PROVIDES_AT`] byte: the module is
/// `workload_instantiable`. A metal node runs a module a workload composes
/// unprivileged unless the node's own image carries its type and its signed
/// manifest says this: a provider other modules call into cannot be gated, so
/// only one the node vouches for may serve inside a workload. A module
/// holding grants is never admitted that way, whatever this bit says.
pub const PROVIDES_WORKLOAD_INSTANTIABLE: u8 = 0x80;

/// The provided-contract count of a [`MANIFEST_PROVIDES_AT`] byte.
pub const fn provides_count(byte: u8) -> usize {
    (byte & PROVIDES_COUNT_MASK) as usize
}

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
/// Manifest flag: conditions block present, after the attestation.
///
/// Which of the module's grants and claims a configuration exercises: the
/// sealing path of a durable log calls the key vault only when a cipher is
/// selected, a TLS instance reads files only when it names one. The grant
/// words say what the artifact may call and the resource records what it
/// claims; this block says under which params each conditional grant or
/// claim holds, so a node admitting a composition judges the composition
/// rather than the artifact. It is part of the signed manifest because the
/// kernel decides admission with it: a workload supplying its own
/// conditions would be declaring its own privileges. See [`cond`].
///
/// 0x40: bits 0x04 and 0x08 are the head's `interrupt_safe` and `pre_pass`
/// flags.
pub const FLAG_CONDITIONS: u8 = 0x40;

/// Manifest flag: the module's provider layers are workload-scoped
/// (`provider_scope = "workloads"`). Such a layer serves every caller acting
/// with an authority of its own (a workload) and no caller acting with the
/// node's: it is the one place a workload reaches what the node holds, so
/// it is registered only by a node-owned module, and only it may charge the
/// owner it serves (`resource::LEDGER_CHARGE`). Carries no block.
pub const FLAG_WORKLOAD_SCOPE: u8 = 0x80;

/// Size of the manifest's lanes block: the module's `[lanes]`, the
/// workload lanes it serves as a base-graph module. The capacity is a param
/// of the instance, so the graph that sizes the module's tables sizes the
/// kernel's too; the kernel reads it as it instantiates the module, and
/// never asks the module.
pub const LANES_BLOCK_SIZE: usize = 2;

/// Size of the integrity hash and of the attestation.
pub const DIGEST_SIZE: usize = 32;
/// Size of the signature block: signature (64) ‖ signer fingerprint (32).
pub const SIGNATURE_BLOCK_SIZE: usize = 96;

/// Offsets of the manifest's blocks, from its counts and flags. Each block
/// follows the previous one; a flag-selected block that is absent takes no
/// space. Stack, arena, lanes and the provided-contract list are always present:
/// every module states them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestLayout {
    /// Port-capacity block (`FLAG_PORT_CAPACITY`).
    pub capacity: usize,
    /// Stack block: `u16` stack depth in 64-byte units.
    pub stack: usize,
    /// Arena block: `u32` heap-arena bytes.
    pub arena: usize,
    /// Lanes block: `u8` tag of the param holding the module's lane
    /// capacity, `u8` that param's schema default. A tag of 0: the module
    /// serves no workload lanes. See [`LANES_BLOCK_SIZE`].
    pub lanes: usize,
    /// Provided contracts: one `u16` contract id each, as many as the head's
    /// count.
    pub provides: usize,
    /// Integrity hash (`FLAG_INTEGRITY`); the signature block follows it.
    pub hash: usize,
    /// Attestation (`FLAG_ATTESTATION`).
    pub attestation: usize,
    /// Conditions block (`FLAG_CONDITIONS`): a `u8` count, then that many
    /// [`cond::FIXED`]-byte entries, each followed by its values. Last: its
    /// length is walked from its own bytes ([`conditions_block_len`]).
    pub conditions: usize,
}

/// Bytes of one resource record: `[contract u8][access u8][instance u8]
/// [claim u8]`.
pub const RESOURCE_RECORD_SIZE: usize = 4;
/// Byte of a resource record holding its [`claim`] byte.
pub const RESOURCE_CLAIM_AT: usize = 3;

/// A resource record's claim byte: whether the module needs the contract
/// served to run as configured.
pub mod claim {
    /// The contract must be served.
    pub const REQUIRED: u8 = 0;
    /// The module does without it: never required.
    pub const OPTIONAL: u8 = 1;
    /// Required when the conditions block's entries for this record hold.
    pub const CONDITIONAL: u8 = 2;
    /// The last claim byte defined: a record carrying a later one is refused.
    pub const LAST: u8 = CONDITIONAL;
}

/// The conditions block: a `u8` entry count, then each entry's [`FIXED`]
/// bytes and its values.
///
/// ```text
/// [subject u8][index u8][param u16][group u8][flags u8][count u8][values]
/// ```
///
/// `subject` names what the entry conditions ([`SUBJECT_CONTRACT_GRANT`]:
/// bit `index` of the first grant word; [`SUBJECT_OP_GRANT`]: of the
/// second; [`SUBJECT_CLAIM`]: resource record `index`). `param` is the
/// instance param's TLV tag. A subject holds when every entry of some one
/// of its `group`s holds: the block states each subject in disjunctive
/// normal form. A grant with no entries holds always; a `CONDITIONAL`
/// claim has at least one.
///
/// An entry's kind ([`KIND_MASK`]):
/// - [`KIND_INT_IN`]: the param reads (sign-extended from its packed width)
///   as one of `count` `i64` LE values;
/// - [`KIND_STR_IN`]: the param's bytes equal one of `count` `[len u8]
///   [bytes]` values;
/// - [`KIND_SET`] (`count` 0): the param carries a non-empty entry.
///
/// An absent param holds an `INT_IN` or `STR_IN` entry exactly when
/// [`WHEN_UNSET`] is set: the packer, which knows the schema default the
/// kernel does not, resolves it. [`EXTENDED`] (with `SET` only) reads the
/// tag from the params' extended section, where the builder embeds a value
/// given at build (`${file:..}`) or at launch.
///
/// [`FIXED`]: cond::FIXED
/// [`SUBJECT_CONTRACT_GRANT`]: cond::SUBJECT_CONTRACT_GRANT
/// [`SUBJECT_OP_GRANT`]: cond::SUBJECT_OP_GRANT
/// [`SUBJECT_CLAIM`]: cond::SUBJECT_CLAIM
/// [`KIND_MASK`]: cond::KIND_MASK
/// [`KIND_INT_IN`]: cond::KIND_INT_IN
/// [`KIND_STR_IN`]: cond::KIND_STR_IN
/// [`KIND_SET`]: cond::KIND_SET
/// [`WHEN_UNSET`]: cond::WHEN_UNSET
/// [`EXTENDED`]: cond::EXTENDED
pub mod cond {
    /// Bytes of an entry before its values.
    pub const FIXED: usize = 7;
    /// Subject: a bit of the first grant word (a contract).
    pub const SUBJECT_CONTRACT_GRANT: u8 = 0;
    /// Subject: a bit of the second grant word (an op-level grant).
    pub const SUBJECT_OP_GRANT: u8 = 1;
    /// Subject: a resource record.
    pub const SUBJECT_CLAIM: u8 = 2;
    /// Flag: an absent param holds the entry.
    pub const WHEN_UNSET: u8 = 0x01;
    /// Flag bits holding the entry's kind.
    pub const KIND_MASK: u8 = 0x06;
    /// Kind: an integer param is one of the values.
    pub const KIND_INT_IN: u8 = 0x00;
    /// Kind: a string param is one of the values.
    pub const KIND_STR_IN: u8 = 0x02;
    /// Kind: the param carries a non-empty entry.
    pub const KIND_SET: u8 = 0x04;
    /// Flag: the tag is the extended section's (`SET` only).
    pub const EXTENDED: u8 = 0x08;
    /// Every flag bit an entry may carry.
    pub const FLAGS_KNOWN: u8 = WHEN_UNSET | KIND_MASK | EXTENDED;
    /// The largest param tag: `0xFF` ends a params TLV's basic section.
    pub const PARAM_MAX: u16 = 0xFE;
}

/// One entry of a conditions block, as [`for_each_condition`] reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Condition {
    pub subject: u8,
    pub index: u8,
    pub param: u16,
    pub group: u8,
    pub flags: u8,
    /// Offset of the entry's values within the block, and how many.
    pub values_at: usize,
    pub count: u8,
}

/// The byte length of one entry's values, or `None` when they run past
/// `block` or the entry's shape is not one [`cond`] defines.
fn entry_values_len(block: &[u8], head: &[u8], values_at: usize) -> Option<usize> {
    let flags = head[5];
    let count = head[6] as usize;
    if flags & !cond::FLAGS_KNOWN != 0 {
        return None;
    }
    match flags & cond::KIND_MASK {
        cond::KIND_INT_IN if flags & cond::EXTENDED == 0 => {
            let n = count * 8;
            (values_at + n <= block.len()).then_some(n)
        }
        cond::KIND_STR_IN if flags & cond::EXTENDED == 0 => {
            let mut at = values_at;
            for _ in 0..count {
                let len = *block.get(at)? as usize;
                at += 1 + len;
                if at > block.len() {
                    return None;
                }
            }
            Some(at - values_at)
        }
        cond::KIND_SET if count == 0 && flags & cond::WHEN_UNSET == 0 => Some(0),
        _ => None,
    }
}

/// The exact length of a conditions block, walked from its own count and
/// entry shapes; `None` when an entry is malformed or runs past `block`.
///
/// The manifest's size is checked EXACTLY, not as a lower bound, because
/// slack is corruption at best and at worst a second block appended past
/// the canonical offset for a verifier that reads from the other end. A
/// variable-length block keeps that property only if its length is
/// derivable from its own bytes, which is what this walk is for.
pub fn conditions_block_len(block: &[u8]) -> Option<usize> {
    let &count = block.first()?;
    let mut at = 1usize;
    for _ in 0..count {
        let head = block.get(at..at + cond::FIXED)?;
        if head[0] > cond::SUBJECT_CLAIM || u16::from_le_bytes([head[2], head[3]]) > cond::PARAM_MAX
        {
            return None;
        }
        let values_at = at + cond::FIXED;
        at = values_at + entry_values_len(block, head, values_at)?;
    }
    Some(at)
}

/// Walk a conditions block, calling `f` for each entry. Stops at the first
/// malformed entry rather than guessing.
pub fn for_each_condition(block: &[u8], mut f: impl FnMut(Condition)) {
    let Some(&count) = block.first() else { return };
    let mut at = 1usize;
    for _ in 0..count {
        let Some(head) = block.get(at..at + cond::FIXED) else {
            return;
        };
        let values_at = at + cond::FIXED;
        let Some(n) = entry_values_len(block, head, values_at) else {
            return;
        };
        f(Condition {
            subject: head[0],
            index: head[1],
            param: u16::from_le_bytes([head[2], head[3]]),
            group: head[4],
            flags: head[5],
            values_at,
            count: head[6],
        });
        at = values_at + n;
    }
}

/// Why a manifest's claims and conditions are refused at load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionsError {
    /// The block is malformed or runs past the manifest.
    Malformed,
    /// A resource record's claim byte is past [`claim::LAST`].
    ClaimByte,
    /// A `CONDITIONAL` record that no entry conditions.
    NoGroup,
    /// An entry naming a grant bit past 63, a record past the module's, or
    /// a record that is not `CONDITIONAL`.
    Subject,
}

/// Check a manifest's resource records (`records`, [`RESOURCE_RECORD_SIZE`]
/// bytes each) against its conditions block (`block`, empty when the
/// manifest carries none): every claim byte is one [`claim`] defines, every
/// entry is well formed and names a grant bit or a `CONDITIONAL` record the
/// manifest has, and every `CONDITIONAL` record has an entry. The block's
/// exact length on success.
pub fn validate_conditions(records: &[u8], block: Option<&[u8]>) -> Result<usize, ConditionsError> {
    let n = records.len() / RESOURCE_RECORD_SIZE;
    let claim_of = |i: usize| records[i * RESOURCE_RECORD_SIZE + RESOURCE_CLAIM_AT];
    for i in 0..n {
        if claim_of(i) > claim::LAST {
            return Err(ConditionsError::ClaimByte);
        }
    }
    let len = match block {
        Some(b) => conditions_block_len(b).ok_or(ConditionsError::Malformed)?,
        None => 0,
    };
    let block = block.map_or(&[][..], |b| &b[..len]);
    let mut bad = false;
    for_each_condition(block, |c| {
        bad |= match c.subject {
            cond::SUBJECT_CONTRACT_GRANT | cond::SUBJECT_OP_GRANT => c.index >= 64,
            _ => (c.index as usize) >= n || claim_of(c.index as usize) != claim::CONDITIONAL,
        };
    });
    if bad {
        return Err(ConditionsError::Subject);
    }
    for i in 0..n {
        if claim_of(i) != claim::CONDITIONAL {
            continue;
        }
        let mut found = false;
        for_each_condition(block, |c| {
            found |= c.subject == cond::SUBJECT_CLAIM && c.index as usize == i;
        });
        if !found {
            return Err(ConditionsError::NoGroup);
        }
    }
    Ok(len)
}

/// The first entry under `tag` in a params TLV's basic
/// section (`[0xFE][ver][len u16]` header optional), bounds-checked: `None`
/// when the instance does not set it.
fn basic_entry(params: &[u8], tag: u8) -> Option<&[u8]> {
    let mut pos = if params.first() == Some(&0xFE) { 4 } else { 0 };
    while pos + 2 <= params.len() {
        let (t, len) = (params[pos], params[pos + 1] as usize);
        if t == 0xFF {
            return None;
        }
        let v = params.get(pos + 2..pos + 2 + len)?;
        if t == tag {
            return Some(v);
        }
        pos += 2 + len;
    }
    None
}

/// Whether the extended section (past the basic section's `0xFF 0x00`,
/// entries `[tag][0x00][len u16 BE][bytes]`) carries a non-empty entry
/// under `tag`.
fn extended_set(params: &[u8], tag: u8) -> bool {
    let mut pos = if params.first() == Some(&0xFE) { 4 } else { 0 };
    loop {
        let (Some(&t), Some(&len)) = (params.get(pos), params.get(pos + 1)) else {
            return false;
        };
        pos += 2 + len as usize;
        if t == 0xFF {
            break;
        }
    }
    while let Some(h) = params.get(pos..pos + 4) {
        if h[1] != 0 {
            return false;
        }
        let len = u16::from_be_bytes([h[2], h[3]]) as usize;
        if pos + 4 + len > params.len() {
            return false;
        }
        if h[0] == tag && len != 0 {
            return true;
        }
        pos += 4 + len;
    }
    false
}

/// Whether entry `c` of `block` holds for an instance whose params TLV is
/// `params`. Every read is bounded by `block` and `params`.
fn condition_holds(block: &[u8], c: &Condition, params: &[u8]) -> bool {
    let Ok(tag) = u8::try_from(c.param) else {
        return false;
    };
    match c.flags & cond::KIND_MASK {
        cond::KIND_SET => {
            if c.flags & cond::EXTENDED != 0 {
                extended_set(params, tag)
            } else {
                basic_entry(params, tag).is_some_and(|v| !v.is_empty())
            }
        }
        kind => {
            let Some(v) = basic_entry(params, tag) else {
                return c.flags & cond::WHEN_UNSET != 0;
            };
            let mut at = c.values_at;
            if kind == cond::KIND_INT_IN {
                if v.is_empty() || v.len() > 8 {
                    return false;
                }
                let mut b = [0u8; 8];
                b[..v.len()].copy_from_slice(v);
                let shift = 64 - v.len() * 8;
                let n = (i64::from_le_bytes(b) << shift) >> shift;
                (0..c.count).any(|i| {
                    block
                        .get(at + i as usize * 8..at + i as usize * 8 + 8)
                        .and_then(|b| <[u8; 8]>::try_from(b).ok())
                        .is_some_and(|b| i64::from_le_bytes(b) == n)
                })
            } else {
                for _ in 0..c.count {
                    let Some(&len) = block.get(at) else {
                        return false;
                    };
                    let want = block.get(at + 1..at + 1 + len as usize);
                    if want == Some(v) {
                        return true;
                    }
                    at += 1 + len as usize;
                }
                false
            }
        }
    }
}

/// Whether `subject`/`index` holds for `params`: every entry of some one of
/// its groups holds. `None` when the block has no entry for it.
pub fn subject_holds(block: &[u8], subject: u8, index: u8, params: &[u8]) -> Option<bool> {
    let mut seen = [0u64; 4];
    let mut failed = [0u64; 4];
    for_each_condition(block, |c| {
        if c.subject != subject || c.index != index {
            return;
        }
        let (w, b) = ((c.group / 64) as usize, c.group % 64);
        seen[w] |= 1 << b;
        if failed[w] & (1 << b) == 0 && !condition_holds(block, &c, params) {
            failed[w] |= 1 << b;
        }
    });
    if seen == [0; 4] {
        return None;
    }
    Some((0..4).any(|w| seen[w] & !failed[w] != 0))
}

/// Whether grant `bit` of grant word `word` (0 contracts, 1 op-level) holds
/// for `params`: always, unless the block conditions it.
pub fn grant_holds(block: &[u8], word: u8, bit: u8, params: &[u8]) -> bool {
    let subject = if word == 0 {
        cond::SUBJECT_CONTRACT_GRANT
    } else {
        cond::SUBJECT_OP_GRANT
    };
    subject_holds(block, subject, bit, params).unwrap_or(true)
}

/// Whether resource record `index` (`record`, its [`RESOURCE_RECORD_SIZE`]
/// bytes) must be served for an instance whose params TLV is `params`:
/// `REQUIRED` always, `OPTIONAL` never, `CONDITIONAL` when its entries in
/// `block` hold (a record no entry conditions, which the loader refuses,
/// reads as required). The kernel's admission and the composer both ask
/// this, so they cannot disagree.
pub fn claim_required(record: &[u8], index: u8, block: &[u8], params: &[u8]) -> bool {
    match record.get(RESOURCE_CLAIM_AT) {
        Some(&claim::OPTIONAL) => false,
        Some(&claim::CONDITIONAL) => {
            subject_holds(block, cond::SUBJECT_CLAIM, index, params).unwrap_or(true)
        }
        _ => true,
    }
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
        let provides_count = provides_count & PROVIDES_COUNT_MASK;
        let capacity =
            MANIFEST_HEADER_SIZE + ports * 4 + resource_count as usize * 4 + dep_count as usize * 8;
        let stack = capacity
            + if flags & FLAG_PORT_CAPACITY != 0 {
                ports * 8
            } else {
                0
            };
        let arena = stack + 2;
        let lanes = arena + 4;
        let provides = lanes + LANES_BLOCK_SIZE;
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
        let conditions = attestation
            + if flags & FLAG_ATTESTATION != 0 {
                DIGEST_SIZE
            } else {
                0
            };
        Self {
            capacity,
            stack,
            arena,
            lanes,
            provides,
            hash,
            attestation,
            conditions,
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
/// - the attestation, at its canonical offset, when present, and the
///   conditions block after it. The manifest must end exactly after them:
///   an inflated manifest could otherwise carry a second, signed copy while
///   parsers read a substituted one.
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
    if flags & FLAG_ATTESTATION != 0 {
        let conditions = if flags & FLAG_CONDITIONS != 0 {
            manifest
                .get(layout.conditions..)
                .and_then(conditions_block_len)
                .ok_or(EnvelopeError::NonCanonical)?
        } else {
            0
        };
        if manifest.len() != layout.conditions + conditions {
            return Err(EnvelopeError::NonCanonical);
        }
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
