// gpu_pack_core — the generic GPU program-pack envelope.
//
// A pack is the ONLY way an executable reaches a GPU provider. It carries the
// artifact bytes plus the facts a provider needs in order to refuse work it
// cannot actually run: which ISA the bytes are, which toolchain produced them,
// what the entry point is called, what bindings it expects and on what terms,
// which device features and arithmetic facts it requires, and what it will
// cost in memory.
//
// The envelope is deliberately generic. Tensor shapes, model operators,
// quantisation schemes and numerical tolerance are the consumer's; this file
// knows only that a program has bindings, a workgroup shape and a budget.
//
// Three separate ideas, kept separate on purpose:
//
//   - **Artifact digest** — `sha256` over the artifact bytes alone. Content
//     identity: the same shader compiled once is the same digest wherever it
//     is shipped from.
//   - **Pack identity** — `sha256` over the whole manifest INCLUDING the
//     bindings, entry point, target and requirements. This is what a pipeline
//     cache is keyed on, because two packs that share artifact bytes but
//     declare different binding access are not interchangeable.
//   - **Trust** — neither of the above. A digest proves the bytes are the
//     bytes someone named; it proves nothing about what they do. Admission
//     still validates every command and binding independently, and a provider
//     that cannot isolate GPU memory does not accept arbitrary native
//     artifacts however well signed they are.
//
// Pure logic over a caller-owned byte slice: no allocation, no clock, no
// syscall. `no_std`.
//
// Mount alongside `sdk/wire/gpu_wire.rs` and `sdk/crypto/sha256.rs`: this core
// reads the wire contract's `TARGET_*` and `ARITH_*` facts and calls `sha256` /
// `Sha256` from the flat namespace the `include!` chain produces, the same way
// `tls` and `quic` reach the hash they share. Those numbers have one
// definition; a second copy here is exactly the drift the wire file exists to
// prevent.

// ── Layout ──────────────────────────────────────────────────────────────
//
// A flat fixed header with named offsets, little-endian, followed by three
// variable sections the header points at. Offsets are absolute within the
// pack so a section can be validated without walking the ones before it.

/// `b"FXGP"` read little-endian. A framing check, not a version: there is one
/// pack format and nothing to fall back to.
pub const PACK_MAGIC: u32 = 0x5047_5846;

pub const PACK_MAGIC_OFF: usize = 0; // u32
/// Reserved head word; must be zero, so a producer that starts writing
/// something here fails loudly rather than being ignored.
pub const PACK_RESERVED_HEAD_OFF: usize = 4; // u32
pub const PACK_TARGET_ISA_OFF: usize = 8; // u32
pub const PACK_TARGET_REV_OFF: usize = 12; // u32
pub const PACK_ENTRY_OFF: usize = 16; // u32
pub const PACK_ENTRY_LEN_OFF: usize = 20; // u32
pub const PACK_ARTIFACT_OFF: usize = 24; // u32
pub const PACK_ARTIFACT_LEN_OFF: usize = 28; // u32
pub const PACK_BINDING_OFF: usize = 32; // u32
pub const PACK_BINDING_COUNT_OFF: usize = 36; // u32
pub const PACK_FEATURE_REQ_OFF: usize = 40; // u32
pub const PACK_ARITH_OPS_REQ_OFF: usize = 44; // u32
pub const PACK_ARITH_TYPES_REQ_OFF: usize = 48; // u32
pub const PACK_ARITH_NATIVE_REQ_OFF: usize = 52; // u32
pub const PACK_WORKGROUP_X_OFF: usize = 56; // u32
pub const PACK_WORKGROUP_Y_OFF: usize = 60; // u32
pub const PACK_WORKGROUP_Z_OFF: usize = 64; // u32
pub const PACK_MIN_ALIGN_OFF: usize = 68; // u32
pub const PACK_BUDGET_RESIDENT_OFF: usize = 72; // u64
pub const PACK_BUDGET_SCRATCH_OFF: usize = 80; // u64
pub const PACK_ARTIFACT_DIGEST_OFF: usize = 88; // [u8; 32]
pub const PACK_TOOLCHAIN_OFF: usize = 120; // [u8; 16]
/// Reserved tail of the header; must be zero, so a later field cannot be
/// mistaken for a value an old reader silently ignored.
pub const PACK_RESERVED_OFF: usize = 136; // [u8; 8]
pub const PACK_HEADER_LEN: usize = 144;

/// One declared binding: `[slot u16][kind u8][access u8][min_size u32][align u32]`.
pub const PACK_BINDING_LEN: usize = 12;

/// Largest pack this reader accepts. An R2 ceiling: a program larger than
/// this is a composition problem, not something to discover at runtime.
pub const MAX_PACK_BYTES: usize = 16 * 1024 * 1024;
/// Largest entry-point name.
pub const MAX_ENTRY_LEN: usize = 128;
/// Largest binding table. Bounds the validator's work; a device's real
/// ceiling is its own `max_bindings` fact, checked against this.
pub const MAX_BINDINGS: usize = 64;

// ── Binding kinds ───────────────────────────────────────────────────────

pub const BIND_STORAGE: u8 = 1;
pub const BIND_UNIFORM: u8 = 2;
pub const BIND_TEXTURE: u8 = 3;
pub const BIND_SAMPLER: u8 = 4;
pub const BIND_VERTEX: u8 = 5;
pub const BIND_INDEX: u8 = 6;

/// Access a binding needs, in the wire contract's `RIGHT_*` terms. Only READ
/// and WRITE are meaningful here — the rest are grant-level rights, not
/// something a shader can request.
pub const BIND_ACCESS_READ: u8 = 1 << 0;
pub const BIND_ACCESS_WRITE: u8 = 1 << 1;

// ── Reject reasons ──────────────────────────────────────────────────────
//
// A pack's own small reason space, NOT the wire contract's. A provider that
// refuses a pack answers `REASON_BAD_PROGRAM` and carries one of these in the
// rejection's `detail` word, which is what `detail` is for: the wire reason
// says what class of thing went wrong, the detail says which check found it.
// Reusing the wire numbers here would either collapse seven distinct answers
// into one or add pack-shaped reasons to a contract that is not about packs.

/// Header truncated, magic wrong, a section out of bounds, or reserved bytes
/// set — the pack is not a pack.
pub const PACK_MALFORMED: u16 = 1;
/// The artifact bytes do not hash to the declared digest.
pub const PACK_DIGEST_MISMATCH: u16 = 2;
/// The target ISA (or its revision) is not one this provider accepts.
pub const PACK_BAD_TARGET: u16 = 3;
/// A binding is duplicated, unknown, mis-aligned, or beyond the device's
/// binding count.
pub const PACK_BAD_BINDING: u16 = 4;
/// A required feature or arithmetic fact is not advertised by the device.
pub const PACK_UNSUPPORTED: u16 = 5;
/// The workgroup shape or declared budget exceeds a device limit.
pub const PACK_OVER_LIMIT: u16 = 6;

/// Human-readable name for a pack reason. Diagnostics only.
#[must_use]
pub const fn pack_reason_name(reason: u16) -> &'static str {
    match reason {
        PACK_MALFORMED => "malformed",
        PACK_DIGEST_MISMATCH => "digest-mismatch",
        PACK_BAD_TARGET => "bad-target",
        PACK_BAD_BINDING => "bad-binding",
        PACK_UNSUPPORTED => "unsupported",
        PACK_OVER_LIMIT => "over-limit",
        _ => "unknown",
    }
}

// ── Validated views ─────────────────────────────────────────────────────

/// One declared binding, after validation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PackBinding {
    pub slot: u16,
    pub kind: u8,
    pub access: u8,
    /// Smallest bound range the program will read or write. A view narrower
    /// than this is refused at dispatch rather than read out of bounds.
    pub min_size: u32,
    /// Alignment the bound view's offset must satisfy.
    pub align: u32,
}

/// The structural rules one binding must satisfy.
///
/// One definition, applied when a pack is built and again when one is
/// decoded. Two copies of these rules would drift, and the direction they
/// drift in is a builder that emits packs its own decoder refuses — which
/// makes every round-trip test vacuous.
///
/// A uniform, sampler, vertex or index binding declared writable is a
/// manifest error rather than something for a device to discover: nothing in
/// any shading language this pack can carry writes through one.
#[must_use]
pub fn binding_ok(b: &PackBinding) -> bool {
    matches!(
        b.kind,
        BIND_STORAGE | BIND_UNIFORM | BIND_TEXTURE | BIND_SAMPLER | BIND_VERTEX | BIND_INDEX
    ) && b.access != 0
        && b.access & !(BIND_ACCESS_READ | BIND_ACCESS_WRITE) == 0
        && b.align != 0
        && b.align.is_power_of_two()
        && !(matches!(
            b.kind,
            BIND_UNIFORM | BIND_SAMPLER | BIND_VERTEX | BIND_INDEX
        ) && b.access & BIND_ACCESS_WRITE != 0)
}

/// Whether an entry-point name is one every shading language this pack can
/// carry would accept: ASCII alphanumerics and underscore. Stricter than
/// "valid UTF-8", and applicable by a `no_std` provider without `core::str`.
#[must_use]
pub fn entry_name_ok(entry: &[u8]) -> bool {
    !entry.is_empty()
        && entry.len() <= MAX_ENTRY_LEN
        && entry
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

/// A pack whose header, sections, digest and requirements all checked out.
/// Holding one is the evidence — every field below was validated, and the
/// offsets are known to be in bounds of the slice it was decoded from.
#[derive(Clone, Copy, Debug)]
pub struct Pack<'a> {
    bytes: &'a [u8],
    pub target_isa: u32,
    pub target_rev: u32,
    entry_off: usize,
    entry_len: usize,
    artifact_off: usize,
    artifact_len: usize,
    binding_off: usize,
    pub binding_count: usize,
    pub feature_req: u32,
    pub arith_ops_req: u32,
    pub arith_types_req: u32,
    pub arith_native_req: u32,
    pub workgroup: [u32; 3],
    pub min_align: u32,
    pub budget_resident: u64,
    pub budget_scratch: u64,
    pub artifact_digest: [u8; 32],
    pub toolchain: [u8; 16],
}

impl<'a> Pack<'a> {
    /// The artifact bytes. Sealed by the caller after acceptance: a provider
    /// copies or pins these and never reads the producer's buffer again.
    #[must_use]
    pub fn artifact(&self) -> &'a [u8] {
        &self.bytes[self.artifact_off..self.artifact_off + self.artifact_len]
    }

    /// The entry-point name, as the ASCII identifier bytes `decode` accepted.
    ///
    /// Bytes rather than `&str` because the consumers are a `no_std` provider
    /// that hands the range straight to a host call and a hosted one that
    /// builds an owned `String`; neither wants the core to depend on
    /// `core::str`, which a PIC module does not link.
    #[must_use]
    pub fn entry(&self) -> &'a [u8] {
        &self.bytes[self.entry_off..self.entry_off + self.entry_len]
    }

    /// Binding `i`, or `None` past the table.
    #[must_use]
    pub fn binding(&self, i: usize) -> Option<PackBinding> {
        if i >= self.binding_count {
            return None;
        }
        let off = self.binding_off + i * PACK_BINDING_LEN;
        let b = &self.bytes[off..off + PACK_BINDING_LEN];
        Some(PackBinding {
            slot: u16::from_le_bytes([b[0], b[1]]),
            kind: b[2],
            access: b[3],
            min_size: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            align: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
        })
    }

    /// The binding declared at `slot`, or `None`. Slots are unique — the
    /// validator rejected duplicates — so this answer is unambiguous.
    #[must_use]
    pub fn binding_at_slot(&self, slot: u16) -> Option<PackBinding> {
        let mut i = 0;
        while i < self.binding_count {
            let b = self.binding(i)?;
            if b.slot == slot {
                return Some(b);
            }
            i += 1;
        }
        None
    }

    /// The identity a pipeline cache is keyed on: a digest over the entire
    /// manifest, not just the artifact.
    ///
    /// Two packs carrying identical artifact bytes but different binding
    /// access, entry point, target revision or feature requirements are
    /// different programs, and a cache keyed on the artifact alone would
    /// serve one where the other was asked for.
    #[must_use]
    pub fn identity(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(&self.bytes[..PACK_HEADER_LEN]);
        h.update(&self.bytes[self.entry_off..self.entry_off + self.entry_len]);
        h.update(
            &self.bytes[self.binding_off..self.binding_off + self.binding_count * PACK_BINDING_LEN],
        );
        h.finalize()
    }
}

/// The device facts a pack is validated against. Filled from the provider's
/// capability record; a validator with no limits to check against would be
/// checking nothing.
#[derive(Clone, Copy, Debug)]
pub struct PackLimits {
    /// Target ISAs this provider accepts. `TARGET_NONE` entries are ignored,
    /// so a provider that takes one ISA leaves the rest zero.
    pub targets: [u32; 4],
    /// Minimum revision accepted per target slot; `0` means any.
    pub target_min_rev: [u32; 4],
    pub features: u32,
    pub arith_ops: u32,
    /// Per-type facts, indexed by the wire contract's `ARITH_I8`… slots and
    /// carrying its `ARITH_STORAGE`/`COMPUTE`/`ACCUM`/`NATIVE` bits. Bit `i`
    /// of a pack's requirement masks names entry `i` of this table.
    pub arith_types: [u8; ARITH_TYPE_COUNT],
    pub max_bindings: u32,
    pub min_align: u32,
    pub max_workgroup: [u32; 3],
    pub max_workgroup_invocations: u32,
    pub max_resident_bytes: u64,
    pub max_scratch_bytes: u64,
}

// ── Decode and validate ─────────────────────────────────────────────────

/// Read `pack` as a program pack, checking structure and digest but not
/// device fit.
///
/// Split from [`validate`] because the two answer different questions and
/// have different callers: offline tooling inspects a pack with no device in
/// hand, while a provider must do both. Structure first, always — a device
/// check on an unvalidated header would be reading attacker-chosen offsets.
pub fn decode(pack: &[u8]) -> Result<Pack<'_>, u16> {
    if pack.len() < PACK_HEADER_LEN || pack.len() > MAX_PACK_BYTES {
        return Err(PACK_MALFORMED);
    }
    let u32_at = |off: usize| -> u32 {
        u32::from_le_bytes([pack[off], pack[off + 1], pack[off + 2], pack[off + 3]])
    };
    let u64_at = |off: usize| -> u64 {
        let mut v = [0u8; 8];
        v.copy_from_slice(&pack[off..off + 8]);
        u64::from_le_bytes(v)
    };

    if u32_at(PACK_MAGIC_OFF) != PACK_MAGIC {
        return Err(PACK_MALFORMED);
    }
    if u32_at(PACK_RESERVED_HEAD_OFF) != 0 {
        return Err(PACK_MALFORMED);
    }
    // Reserved bytes must be zero: a future field written by a newer producer
    // must fail loudly here rather than be ignored into a wrong answer.
    if pack[PACK_RESERVED_OFF..PACK_HEADER_LEN]
        .iter()
        .any(|&b| b != 0)
    {
        return Err(PACK_MALFORMED);
    }

    let entry_off = u32_at(PACK_ENTRY_OFF) as usize;
    let entry_len = u32_at(PACK_ENTRY_LEN_OFF) as usize;
    let artifact_off = u32_at(PACK_ARTIFACT_OFF) as usize;
    let artifact_len = u32_at(PACK_ARTIFACT_LEN_OFF) as usize;
    let binding_off = u32_at(PACK_BINDING_OFF) as usize;
    let binding_count = u32_at(PACK_BINDING_COUNT_OFF) as usize;

    if entry_len == 0 || entry_len > MAX_ENTRY_LEN || binding_count > MAX_BINDINGS {
        return Err(PACK_MALFORMED);
    }
    // Every section must start after the header and end inside the pack, with
    // the end computed by checked arithmetic — an offset near `usize::MAX` is
    // exactly how a bounds check is defeated by wrapping.
    let section_ok = |off: usize, len: usize| -> bool {
        off >= PACK_HEADER_LEN && off.checked_add(len).is_some_and(|end| end <= pack.len())
    };
    let binding_bytes = binding_count * PACK_BINDING_LEN;
    // The binding offset is checked whether or not there are bindings to
    // read. A zero-length section still names a position, `identity` hashes
    // `bytes[off..off + 0]`, and a range whose start is past the end is a
    // panic rather than an empty slice — so an unchecked offset on the
    // count-zero path is a trap reachable from the wire.
    if !section_ok(entry_off, entry_len)
        || !section_ok(artifact_off, artifact_len)
        || !section_ok(binding_off, binding_bytes)
    {
        return Err(PACK_MALFORMED);
    }
    if artifact_len == 0 {
        return Err(PACK_MALFORMED);
    }
    // The entry point is an identifier in every shading language this pack
    // can carry, so hold it to that: ASCII alphanumerics and underscore. A
    // stricter rule than "valid UTF-8", and one a `no_std` provider can apply
    // without linking `core::str`.
    if !entry_name_ok(&pack[entry_off..entry_off + entry_len]) {
        return Err(PACK_MALFORMED);
    }

    let mut artifact_digest = [0u8; 32];
    artifact_digest.copy_from_slice(&pack[PACK_ARTIFACT_DIGEST_OFF..PACK_ARTIFACT_DIGEST_OFF + 32]);
    if sha256(&pack[artifact_off..artifact_off + artifact_len]) != artifact_digest {
        return Err(PACK_DIGEST_MISMATCH);
    }

    let mut toolchain = [0u8; 16];
    toolchain.copy_from_slice(&pack[PACK_TOOLCHAIN_OFF..PACK_TOOLCHAIN_OFF + 16]);

    let decoded = Pack {
        bytes: pack,
        target_isa: u32_at(PACK_TARGET_ISA_OFF),
        target_rev: u32_at(PACK_TARGET_REV_OFF),
        entry_off,
        entry_len,
        artifact_off,
        artifact_len,
        binding_off,
        binding_count,
        feature_req: u32_at(PACK_FEATURE_REQ_OFF),
        arith_ops_req: u32_at(PACK_ARITH_OPS_REQ_OFF),
        arith_types_req: u32_at(PACK_ARITH_TYPES_REQ_OFF),
        arith_native_req: u32_at(PACK_ARITH_NATIVE_REQ_OFF),
        workgroup: [
            u32_at(PACK_WORKGROUP_X_OFF),
            u32_at(PACK_WORKGROUP_Y_OFF),
            u32_at(PACK_WORKGROUP_Z_OFF),
        ],
        min_align: u32_at(PACK_MIN_ALIGN_OFF),
        budget_resident: u64_at(PACK_BUDGET_RESIDENT_OFF),
        budget_scratch: u64_at(PACK_BUDGET_SCRATCH_OFF),
        artifact_digest,
        toolchain,
    };

    // Bindings: each structurally sound, and slots unique. Duplicated slots
    // are rejected rather than last-one-wins — a program with two claims on
    // one slot has no single meaning, and picking one silently would bind the
    // wrong buffer.
    let mut i = 0;
    while i < binding_count {
        let b = decoded.binding(i).ok_or(PACK_MALFORMED)?;
        if !binding_ok(&b) {
            return Err(PACK_BAD_BINDING);
        }
        let mut j = 0;
        while j < i {
            if decoded.binding(j).ok_or(PACK_MALFORMED)?.slot == b.slot {
                return Err(PACK_BAD_BINDING);
            }
            j += 1;
        }
        i += 1;
    }

    if decoded.min_align == 0 || !decoded.min_align.is_power_of_two() {
        return Err(PACK_MALFORMED);
    }
    if decoded.workgroup.contains(&0) {
        return Err(PACK_MALFORMED);
    }

    Ok(decoded)
}

/// Check a decoded pack against a device's facts.
///
/// Every refusal here names a specific missing fact. Nothing is emulated on
/// the pack's behalf and nothing is assumed available because some other
/// backend has it — advertising the union of what backends *could* do is the
/// failure mode this check exists to prevent.
pub fn validate(pack: &Pack<'_>, limits: &PackLimits) -> Result<(), u16> {
    // Target ISA must be one this provider accepts, at a revision at least
    // as new as it requires.
    let mut target_ok = false;
    let mut slot = 0;
    while slot < limits.targets.len() {
        if limits.targets[slot] != 0
            && limits.targets[slot] == pack.target_isa
            && pack.target_rev >= limits.target_min_rev[slot]
        {
            target_ok = true;
            break;
        }
        slot += 1;
    }
    if !target_ok {
        return Err(PACK_BAD_TARGET);
    }

    if pack.feature_req & !limits.features != 0 {
        return Err(PACK_UNSUPPORTED);
    }
    if pack.arith_ops_req & !limits.arith_ops != 0 {
        return Err(PACK_UNSUPPORTED);
    }
    // Per-type facts. A type the program computes with must be computable;
    // a type it needs *natively* must not be quietly served by an emulation
    // path, because the cost model the consumer chose this program under
    // would be wrong.
    let mut t = 0;
    while t < ARITH_TYPE_COUNT {
        let bit = 1u32 << t;
        if pack.arith_types_req & bit != 0 && limits.arith_types[t] & ARITH_COMPUTE == 0 {
            return Err(PACK_UNSUPPORTED);
        }
        if pack.arith_native_req & bit != 0 && limits.arith_types[t] & ARITH_NATIVE == 0 {
            return Err(PACK_UNSUPPORTED);
        }
        t += 1;
    }
    // A requirement naming a type index this contract does not allocate is
    // malformed, not merely unsupported.
    let type_mask = if ARITH_TYPE_COUNT >= 32 {
        u32::MAX
    } else {
        (1u32 << ARITH_TYPE_COUNT) - 1
    };
    if (pack.arith_types_req | pack.arith_native_req) & !type_mask != 0 {
        return Err(PACK_MALFORMED);
    }

    if pack.binding_count as u32 > limits.max_bindings {
        return Err(PACK_BAD_BINDING);
    }
    // The program's alignment demand must be satisfiable by the device: a
    // pack asking for tighter packing than the device's granularity cannot
    // be honoured, so it is refused rather than rounded.
    if pack.min_align < limits.min_align {
        return Err(PACK_BAD_BINDING);
    }
    let mut i = 0;
    while i < pack.binding_count {
        let b = match pack.binding(i) {
            Some(b) => b,
            None => return Err(PACK_MALFORMED),
        };
        if b.slot as u32 >= limits.max_bindings || b.align < limits.min_align {
            return Err(PACK_BAD_BINDING);
        }
        i += 1;
    }

    let mut d = 0;
    let mut invocations: u64 = 1;
    while d < 3 {
        if pack.workgroup[d] > limits.max_workgroup[d] {
            return Err(PACK_OVER_LIMIT);
        }
        invocations = invocations.saturating_mul(pack.workgroup[d] as u64);
        d += 1;
    }
    if invocations > limits.max_workgroup_invocations as u64 {
        return Err(PACK_OVER_LIMIT);
    }

    if pack.budget_resident > limits.max_resident_bytes
        || pack.budget_scratch > limits.max_scratch_bytes
    {
        return Err(PACK_OVER_LIMIT);
    }

    Ok(())
}

/// Build a validator's limits from a provider's published capability record.
///
/// The same 152 bytes a device answers `QUERY_CAPS` with. Having one function
/// read them means an offline checker and a running consumer judge a pack
/// against exactly the facts the device published, rather than against a
/// second description of the device that someone kept up to date by hand.
#[must_use]
pub fn pack_limits_from_caps(caps: &[u8]) -> Option<PackLimits> {
    if caps.len() < CAPS_LEN {
        return None;
    }
    let mut targets = [TARGET_NONE; CAPS_TARGET_SLOTS];
    for (i, t) in targets.iter_mut().enumerate() {
        *t = get_u32(caps, CAPS_TARGETS + i * 4)?;
    }
    let mut arith_types = [0u8; ARITH_TYPE_COUNT];
    arith_types.copy_from_slice(&caps[CAPS_ARITH_TABLE..CAPS_ARITH_TABLE + ARITH_TYPE_COUNT]);
    Some(PackLimits {
        targets,
        // A capability record carries no per-target minimum revision: a device
        // that needs one refuses the pack at load. Offline validation is a
        // pre-check, and claiming to enforce a fact the record does not carry
        // would make it look like more of one than it is.
        target_min_rev: [0; CAPS_TARGET_SLOTS],
        features: get_u32(caps, CAPS_FEATURES)?,
        arith_ops: get_u32(caps, CAPS_ARITH_OPS)?,
        arith_types,
        max_bindings: get_u32(caps, CAPS_MAX_BINDINGS)?,
        min_align: get_u32(caps, CAPS_MIN_ALIGN)?,
        max_workgroup: [
            get_u32(caps, CAPS_MAX_WORKGROUP_X)?,
            get_u32(caps, CAPS_MAX_WORKGROUP_Y)?,
            get_u32(caps, CAPS_MAX_WORKGROUP_Z)?,
        ],
        max_workgroup_invocations: get_u32(caps, CAPS_MAX_WORKGROUP_INVOCATIONS)?,
        max_resident_bytes: get_u64(caps, CAPS_MAX_RESIDENT_BYTES)?,
        max_scratch_bytes: get_u64(caps, CAPS_MAX_SCRATCH_BYTES)?,
    })
}

/// Decode and check in one call — what a provider does at `LOAD_PROGRAM`.
pub fn decode_and_validate<'a>(pack: &'a [u8], limits: &PackLimits) -> Result<Pack<'a>, u16> {
    let decoded = decode(pack)?;
    validate(&decoded, limits)?;
    Ok(decoded)
}

// ── Building a pack ─────────────────────────────────────────────────────
//
// Encoding lives here, next to the decoder, so the two cannot drift and the
// round-trip is testable without a second implementation. Used by the offline
// packer in `tools/` and by test fixtures.

/// Fields a builder needs beyond the artifact and entry name.
#[derive(Clone, Copy, Debug)]
pub struct PackSpec {
    pub target_isa: u32,
    pub target_rev: u32,
    pub feature_req: u32,
    pub arith_ops_req: u32,
    pub arith_types_req: u32,
    pub arith_native_req: u32,
    pub workgroup: [u32; 3],
    pub min_align: u32,
    pub budget_resident: u64,
    pub budget_scratch: u64,
    pub toolchain: [u8; 16],
}

impl PackSpec {
    /// A minimal, valid spec: one WGSL program, 64-byte alignment, a 64×1×1
    /// workgroup and no special requirements. Callers override what they mean
    /// rather than filling eleven fields to say "nothing unusual".
    #[must_use]
    pub const fn wgsl() -> Self {
        Self {
            target_isa: TARGET_WGSL,
            target_rev: 0,
            feature_req: 0,
            arith_ops_req: 0,
            arith_types_req: 0,
            arith_native_req: 0,
            workgroup: [64, 1, 1],
            min_align: 64,
            budget_resident: 0,
            budget_scratch: 0,
            toolchain: [0u8; 16],
        }
    }
}

/// Total bytes [`encode`] will write for these inputs.
#[must_use]
pub fn encoded_len(entry: &str, bindings: usize, artifact: usize) -> usize {
    PACK_HEADER_LEN + bindings * PACK_BINDING_LEN + entry.len() + artifact
}

/// Write a pack into `out`, answering its length.
///
/// `None` when `out` is too small or an input breaks a structural rule the
/// decoder enforces — a builder that could emit a pack its own decoder
/// rejects would make every round-trip test meaningless.
pub fn encode(
    out: &mut [u8],
    spec: &PackSpec,
    entry: &str,
    bindings: &[PackBinding],
    artifact: &[u8],
) -> Option<usize> {
    if !entry_name_ok(entry.as_bytes()) || bindings.len() > MAX_BINDINGS || artifact.is_empty() {
        return None;
    }
    if spec.min_align == 0 || !spec.min_align.is_power_of_two() {
        return None;
    }
    if spec.workgroup.contains(&0) {
        return None;
    }
    // The decoder's own binding rules, applied before anything is written.
    // Emitting a pack that will not decode turns a manifest error into a
    // failure at load time on a device, which is the expensive place to find
    // it — and the one place the builder was supposed to prevent.
    for (i, b) in bindings.iter().enumerate() {
        if !binding_ok(b) || bindings[..i].iter().any(|o| o.slot == b.slot) {
            return None;
        }
    }
    let binding_off = PACK_HEADER_LEN;
    let binding_bytes = bindings.len() * PACK_BINDING_LEN;
    let entry_off = binding_off + binding_bytes;
    let artifact_off = entry_off + entry.len();
    let total = artifact_off + artifact.len();
    if out.len() < total || total > MAX_PACK_BYTES {
        return None;
    }

    out[..total].fill(0);
    let put32 =
        |out: &mut [u8], off: usize, v: u32| out[off..off + 4].copy_from_slice(&v.to_le_bytes());
    let put64 =
        |out: &mut [u8], off: usize, v: u64| out[off..off + 8].copy_from_slice(&v.to_le_bytes());

    put32(out, PACK_MAGIC_OFF, PACK_MAGIC);
    put32(out, PACK_TARGET_ISA_OFF, spec.target_isa);
    put32(out, PACK_TARGET_REV_OFF, spec.target_rev);
    put32(out, PACK_ENTRY_OFF, entry_off as u32);
    put32(out, PACK_ENTRY_LEN_OFF, entry.len() as u32);
    put32(out, PACK_ARTIFACT_OFF, artifact_off as u32);
    put32(out, PACK_ARTIFACT_LEN_OFF, artifact.len() as u32);
    put32(out, PACK_BINDING_OFF, binding_off as u32);
    put32(out, PACK_BINDING_COUNT_OFF, bindings.len() as u32);
    put32(out, PACK_FEATURE_REQ_OFF, spec.feature_req);
    put32(out, PACK_ARITH_OPS_REQ_OFF, spec.arith_ops_req);
    put32(out, PACK_ARITH_TYPES_REQ_OFF, spec.arith_types_req);
    put32(out, PACK_ARITH_NATIVE_REQ_OFF, spec.arith_native_req);
    put32(out, PACK_WORKGROUP_X_OFF, spec.workgroup[0]);
    put32(out, PACK_WORKGROUP_Y_OFF, spec.workgroup[1]);
    put32(out, PACK_WORKGROUP_Z_OFF, spec.workgroup[2]);
    put32(out, PACK_MIN_ALIGN_OFF, spec.min_align);
    put64(out, PACK_BUDGET_RESIDENT_OFF, spec.budget_resident);
    put64(out, PACK_BUDGET_SCRATCH_OFF, spec.budget_scratch);
    out[PACK_ARTIFACT_DIGEST_OFF..PACK_ARTIFACT_DIGEST_OFF + 32].copy_from_slice(&sha256(artifact));
    out[PACK_TOOLCHAIN_OFF..PACK_TOOLCHAIN_OFF + 16].copy_from_slice(&spec.toolchain);

    for (i, b) in bindings.iter().enumerate() {
        let off = binding_off + i * PACK_BINDING_LEN;
        out[off..off + 2].copy_from_slice(&b.slot.to_le_bytes());
        out[off + 2] = b.kind;
        out[off + 3] = b.access;
        put32(out, off + 4, b.min_size);
        put32(out, off + 8, b.align);
    }
    out[entry_off..entry_off + entry.len()].copy_from_slice(entry.as_bytes());
    out[artifact_off..total].copy_from_slice(artifact);
    Some(total)
}
