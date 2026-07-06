//! Genstore on-storage wire records — the byte format of the durable
//! generation store (rfc_k8s.md §12.4 / §13, k8s_plan WS-F).
//!
//! Shared byte-for-byte between the host tools (`tools/src/genstore.rs`
//! path-mounts this file, the same pattern as `wire.rs`) and the device-side
//! CM5 backend, so both ends agree on pointer-record and generation-header
//! encoding by construction rather than by mirrored copies.
//!
//! `no_std`, zero-alloc: decoding is a validated view over the caller's byte
//! slice. Hosts that want owned structures build them on top (see the host
//! `Generation`); devices read fields in place and use the in-place mutators
//! for the two fields a booting node updates (`state`, `boot_attempts`).

// ── CRC32 (IEEE) — pointer-record integrity ───────────────────────────

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        let mut i = 0;
        while i < 8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            i += 1;
        }
    }
    !crc
}

// ── Generation pointer records (A/B, epoch-selected) ─────────────────

/// Store keys for the two redundant pointer records.
pub const PTR_A_KEY: &str = "ptr.a";
pub const PTR_B_KEY: &str = "ptr.b";

pub const PTR_MAGIC: u32 = 0x4750_5452; // "GPTR"
pub const PTR_RECORD_LEN: usize = 24;

/// A generation-pointer record: which generation is committed, under a
/// monotonic epoch, integrity-checked with a CRC. A torn write fails the
/// CRC and the other record stays authoritative.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PointerRecord {
    pub epoch: u64,
    pub committed_gen: u64,
}

impl PointerRecord {
    pub fn encode(&self) -> [u8; PTR_RECORD_LEN] {
        let mut buf = [0u8; PTR_RECORD_LEN];
        buf[0..4].copy_from_slice(&PTR_MAGIC.to_be_bytes());
        buf[4..12].copy_from_slice(&self.epoch.to_be_bytes());
        buf[12..20].copy_from_slice(&self.committed_gen.to_be_bytes());
        let crc = crc32(&buf[0..20]);
        buf[20..24].copy_from_slice(&crc.to_be_bytes());
        buf
    }

    pub fn decode(bytes: &[u8]) -> Option<PointerRecord> {
        if bytes.len() != PTR_RECORD_LEN {
            return None;
        }
        if u32::from_be_bytes(bytes[0..4].try_into().ok()?) != PTR_MAGIC {
            return None;
        }
        let stored_crc = u32::from_be_bytes(bytes[20..24].try_into().ok()?);
        if crc32(&bytes[0..20]) != stored_crc {
            return None;
        }
        Some(PointerRecord {
            epoch: u64::from_be_bytes(bytes[4..12].try_into().ok()?),
            committed_gen: u64::from_be_bytes(bytes[12..20].try_into().ok()?),
        })
    }
}

// ── Generation header ─────────────────────────────────────────────────

/// Lifecycle state of a generation slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenState {
    Staging,
    Candidate,
    Committed,
    Bad,
}

impl GenState {
    pub fn to_u8(self) -> u8 {
        match self {
            GenState::Staging => 0,
            GenState::Candidate => 1,
            GenState::Committed => 2,
            GenState::Bad => 3,
        }
    }
    pub fn from_u8(b: u8) -> Option<GenState> {
        Some(match b {
            0 => GenState::Staging,
            1 => GenState::Candidate,
            2 => GenState::Committed,
            3 => GenState::Bad,
            _ => return None,
        })
    }
}

/// Layout: `magic:u32 ("FXGN") | id:u64 | state:u8 | boot_attempts:u8 |
/// plan_digest:[u8;32] | abi_surface:[u8;32] | artifact_count:u32 |
/// artifacts:[[u8;32]; artifact_count]`, big-endian.
///
/// The magic is the layout discriminator: the pre-pin legacy layout began
/// directly with `id:u64` (whose high bytes are zero for any realistic
/// id), so a current record can never be confused with a legacy one and
/// vice versa — no length-heuristic ambiguity.
///
/// `abi_surface` is the ABI wire-surface digest the generation was built
/// against (`modules/sdk/abi_surface.rs`): boot selection accepts a
/// generation only when its pin equals the running kernel's own surface
/// digest — a graph built for an incompatible substrate fails closed and
/// the store falls back, instead of loading modules whose hardcoded wire
/// values no longer match.
pub const GEN_MAGIC: u32 = 0x4658_474E; // "FXGN"
pub const GEN_STATE_OFFSET: usize = 12;
pub const GEN_BOOT_ATTEMPTS_OFFSET: usize = 13;
pub const GEN_ABI_SURFACE_OFFSET: usize = 46;
pub const GEN_FIXED_LEN: usize = 4 + 8 + 1 + 1 + 32 + 32 + 4;

/// Zero-copy validated view over an encoded generation record.
#[derive(Clone, Copy)]
pub struct GenHeaderView<'a> {
    bytes: &'a [u8],
}

impl<'a> GenHeaderView<'a> {
    /// Validate framing (fixed header present, declared artifact list in
    /// bounds, state byte known) and return the view. `None` = corrupt.
    pub fn parse(bytes: &'a [u8]) -> Option<GenHeaderView<'a>> {
        if bytes.len() < GEN_FIXED_LEN {
            return None;
        }
        if u32::from_be_bytes(bytes[0..4].try_into().ok()?) != GEN_MAGIC {
            return None;
        }
        GenState::from_u8(bytes[GEN_STATE_OFFSET])?;
        let n = u32::from_be_bytes(bytes[78..82].try_into().ok()?) as usize;
        // Checked arithmetic: on a 32-bit device a corrupt count near
        // usize::MAX/32 would wrap `GEN_FIXED_LEN + n * 32` and pass the
        // bound; overflow is corruption, so reject.
        let need = n
            .checked_mul(32)
            .and_then(|a| a.checked_add(GEN_FIXED_LEN))?;
        // EXACT length: the writer emits exact sizes; slack is corruption.
        if bytes.len() != need {
            return None;
        }
        Some(GenHeaderView { bytes })
    }

    pub fn id(&self) -> u64 {
        u64::from_be_bytes(self.bytes[4..12].try_into().unwrap())
    }
    pub fn state(&self) -> GenState {
        // Validated in `parse`.
        GenState::from_u8(self.bytes[GEN_STATE_OFFSET]).unwrap()
    }
    pub fn boot_attempts(&self) -> u8 {
        self.bytes[GEN_BOOT_ATTEMPTS_OFFSET]
    }
    pub fn plan_digest(&self) -> [u8; 32] {
        let mut d = [0u8; 32];
        d.copy_from_slice(&self.bytes[14..46]);
        d
    }
    /// ABI wire-surface digest this generation was built against.
    pub fn abi_surface(&self) -> [u8; 32] {
        let mut d = [0u8; 32];
        d.copy_from_slice(&self.bytes[46..78]);
        d
    }
    pub fn artifact_count(&self) -> usize {
        u32::from_be_bytes(self.bytes[78..82].try_into().unwrap()) as usize
    }
    pub fn artifact(&self, i: usize) -> Option<[u8; 32]> {
        if i >= self.artifact_count() {
            return None;
        }
        let off = GEN_FIXED_LEN + i * 32;
        let mut d = [0u8; 32];
        d.copy_from_slice(&self.bytes[off..off + 32]);
        Some(d)
    }
}

/// In-place mutators for the two fields a booting device updates without
/// re-encoding the whole record (boot-attempt count, Bad demotion). The
/// caller re-persists the record after mutation.
pub fn set_state_in_place(record: &mut [u8], state: GenState) -> bool {
    if record.len() < GEN_FIXED_LEN {
        return false;
    }
    record[GEN_STATE_OFFSET] = state.to_u8();
    true
}

pub fn set_boot_attempts_in_place(record: &mut [u8], attempts: u8) -> bool {
    if record.len() < GEN_FIXED_LEN {
        return false;
    }
    record[GEN_BOOT_ATTEMPTS_OFFSET] = attempts;
    true
}
