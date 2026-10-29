// Contract: offload — a hardware flow-decision provider beside the
// software director.
//
// Layer: contracts/net (public, stable).
//
// A NIC flow table, a programmable switch or an FPGA lookup may decide new
// flows in place of a software director only while it observably decides
// the same thing. This surface is what such a provider says and is told;
// the gate that decides whether to believe it is the director's (an
// equivalence gate: shadow first, any mismatch falls back). Three facts
// cross it, each checkable:
//
//   - what the provider is programmed with: one complete route generation,
//     attested as `(generation, digest)` with the capabilities it enforces
//     (`MSG_OFFLOAD_ATTEST`);
//   - what it decided for a flow, under which generation
//     (`MSG_OFFLOAD_DECIDED`), so the director can decide the same flow
//     itself and compare;
//   - its counters (`MSG_OFFLOAD_COUNTERS`): a provider that cannot report
//     them cannot be admitted (`caps::REPORTS`).
//
// The director tells it which generation it may serve and in which mode
// (`CMD_OFFLOAD_MODE`: off, shadow — decide and report, the software
// decision is used — or active). A provider never serves a generation it
// has not attested, and a mode naming a generation other than its attested
// one is answered with an attestation and serves nothing.
//
// Frames use the shared `[msg_type: u8][len: u16 LE][payload]` header.
// Opcodes 0x70..0x7F, disjoint from net_proto, datagram and packet. The
// range is session_ctrl's too; offload records travel only between a
// director and its provider, never on a session-control channel.

/// Capability bits a provider attests.
pub mod caps {
    /// Maglev lane lookup by flow hash.
    pub const MAGLEV_LOOKUP: u32 = 1 << 0;
    /// Exact-match established-flow cache.
    pub const FLOW_CACHE: u32 = 1 << 1;
    /// Per-endpoint eligibility (drain/health) applied in the lookup.
    pub const ELIGIBILITY: u32 = 1 << 2;
    /// Decision, miss and generation counters.
    pub const REPORTS: u32 = 1 << 3;
    /// What a provider must offer to decide new flows at all.
    pub const REQUIRED: u32 = MAGLEV_LOOKUP | ELIGIBILITY | REPORTS;
    /// Every bit defined.
    pub const ALL: u32 = (1 << 4) - 1;
}

/// Modes the director sets.
pub mod mode {
    pub const OFF: u8 = 0;
    /// Decide and report; the software decision is used.
    pub const SHADOW: u8 = 1;
    /// Decide; the director samples and compares.
    pub const ACTIVE: u8 = 2;
}

/// Director → provider: serve `generation` in `mode`. Payload
/// `[mode: u8][generation: u64 LE]`.
pub const CMD_OFFLOAD_MODE: u8 = 0x70;
/// Director → provider: report attestation and counters now. Empty.
pub const CMD_OFFLOAD_QUERY: u8 = 0x71;

/// Provider → director: what it holds. Payload (`ATTEST_LEN`):
/// `[provider: 16][caps: u32 LE][generation: u64 LE][digest: 32]`.
pub const MSG_OFFLOAD_ATTEST: u8 = 0x78;
/// Provider → director: one new-flow decision. Payload (`DECIDED_LEN`):
/// `[pkt_id: u32 LE][generation: u64 LE][endpoint: u16 LE][disposition: u8]`.
/// `pkt_id` is the packet seam's (`contracts/net/packet.rs`), so the
/// director decides the same held packet itself.
pub const MSG_OFFLOAD_DECIDED: u8 = 0x79;
/// Provider → director: counters. Payload (`COUNTERS_LEN`):
/// `[generation: u64 LE][decisions: u64 LE][misses: u64 LE][mode: u8]`.
pub const MSG_OFFLOAD_COUNTERS: u8 = 0x7A;

pub const MODE_LEN: usize = 1 + 8;
pub const ATTEST_LEN: usize = 16 + 4 + 8 + 32;
pub const DECIDED_LEN: usize = 4 + 8 + 2 + 1;
pub const COUNTERS_LEN: usize = 8 + 8 + 8 + 1;

fn ol_u64(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct OffloadAttest {
    pub provider: [u8; 16],
    pub caps: u32,
    pub generation: u64,
    pub digest: [u8; 32],
}

impl OffloadAttest {
    pub fn encode(&self, out: &mut [u8; ATTEST_LEN]) {
        out[..16].copy_from_slice(&self.provider);
        out[16..20].copy_from_slice(&self.caps.to_le_bytes());
        out[20..28].copy_from_slice(&self.generation.to_le_bytes());
        out[28..60].copy_from_slice(&self.digest);
    }

    /// `None` when short or naming a capability not defined here.
    pub fn decode(b: &[u8]) -> Option<Self> {
        let b = b.get(..ATTEST_LEN)?;
        let caps = u32::from_le_bytes([b[16], b[17], b[18], b[19]]);
        if caps & !caps::ALL != 0 {
            return None;
        }
        let mut provider = [0u8; 16];
        provider.copy_from_slice(&b[..16]);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&b[28..60]);
        Some(Self {
            provider,
            caps,
            generation: ol_u64(b, 20),
            digest,
        })
    }

    /// Whether it may decide new flows at all.
    pub fn sufficient(&self) -> bool {
        self.caps & caps::REQUIRED == caps::REQUIRED && self.generation != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct OffloadDecided {
    pub pkt_id: u32,
    pub generation: u64,
    pub endpoint: u16,
    pub disposition: u8,
}

impl OffloadDecided {
    pub fn encode(&self, out: &mut [u8; DECIDED_LEN]) {
        out[..4].copy_from_slice(&self.pkt_id.to_le_bytes());
        out[4..12].copy_from_slice(&self.generation.to_le_bytes());
        out[12..14].copy_from_slice(&self.endpoint.to_le_bytes());
        out[14] = self.disposition;
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let b = b.get(..DECIDED_LEN)?;
        Some(Self {
            pkt_id: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            generation: ol_u64(b, 4),
            endpoint: u16::from_le_bytes([b[12], b[13]]),
            disposition: b[14],
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct OffloadCounters {
    pub generation: u64,
    pub decisions: u64,
    pub misses: u64,
    pub mode: u8,
}

impl OffloadCounters {
    pub fn encode(&self, out: &mut [u8; COUNTERS_LEN]) {
        out[..8].copy_from_slice(&self.generation.to_le_bytes());
        out[8..16].copy_from_slice(&self.decisions.to_le_bytes());
        out[16..24].copy_from_slice(&self.misses.to_le_bytes());
        out[24] = self.mode;
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let b = b.get(..COUNTERS_LEN)?;
        if b[24] > mode::ACTIVE {
            return None;
        }
        Some(Self {
            generation: ol_u64(b, 0),
            decisions: ol_u64(b, 8),
            misses: ol_u64(b, 16),
            mode: b[24],
        })
    }
}

/// `(mode, generation)` of a `CMD_OFFLOAD_MODE` payload.
pub fn mode_parts(b: &[u8]) -> Option<(u8, u64)> {
    let b = b.get(..MODE_LEN)?;
    (b[0] <= mode::ACTIVE).then(|| (b[0], ol_u64(b, 1)))
}
