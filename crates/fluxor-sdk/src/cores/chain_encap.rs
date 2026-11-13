// chain_encap — the encapsulation a symmetric service chain carries a
// packet in, and the checks each hop makes of it.
//
// A chain director pins a flow to one instance per stage (both directions,
// one pin); the packet travels to each instance wrapped in this header,
// which names the chain, the generation the flow was pinned under, the
// stage it is at, the direction, the pinned instance, and the flow in
// canonical order — the lesser endpoint first — so both directions carry
// the same flow key and a stage can tell a return packet of a flow it saw
// from a stranger's. The header is metadata, not a route: what forwards it
// is the director's TUNNEL/CHAIN disposition (`contracts/net/packet.rs`).
//
//   magic      [2]  = b"FC"
//   version    u8   = 1
//   flags      u8   bit0 = reverse direction, bit1 = passive copy
//   chain_id   u32 BE
//   generation u64 BE
//   stage      u8   the stage this hop is (0-based)
//   stages     u8   how many inline stages the pin holds
//   instance   u16 BE the instance pinned at `stage`
//   flow       [13] canonical tuple: proto, lo addr[4], lo port[2],
//                   hi addr[4], hi port[2]
//   hops_left  u8   decremented each hop; a loop dies at zero
//   _rsv       [2]  zero
//
// `ChainHeader::next` advances a packet to its next stage in its direction
// (forward: 0, 1, …; reverse: the last stage first), so the reverse direction walks
// the same instances backwards — what "symmetric" means for a stateful
// stage. A hop that receives a header for another chain, generation,
// stage or instance than it is refuses it (`CeWhy`), which is a
// fail-closed drop, never a re-selection: re-selection is the director's,
// and only on the stage's declared policy.
//
// `no_std`, allocation-free.

pub const CE_MAGIC: [u8; 2] = *b"FC";
pub const CE_VERSION: u8 = 1;
pub const CE_LEN: usize = 2 + 1 + 1 + 4 + 8 + 1 + 1 + 2 + 13 + 1 + 2;
pub const CE_FLAG_REVERSE: u8 = 1 << 0;
pub const CE_FLAG_PASSIVE: u8 = 1 << 1;
/// Hops a header starts with, and so the most stages one pin holds: each
/// `next` spends a hop and a stage admits no header with none left, so a
/// header walks at most this many stages — a loop dies there, and
/// `ChainHeader::first` refuses a longer chain rather than let its last
/// stages refuse every packet.
pub const CE_HOPS: u8 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeWhy {
    Malformed,
    /// Another chain, generation, stage or instance than the receiver's.
    NotOurs,
    /// The hop budget ran out: a loop.
    Loop,
    /// The flow has no further stage in its direction.
    Done,
}

/// A flow's tuple, `proto` and two endpoints in arrival order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct CeTuple {
    pub proto: u8,
    pub src: [u8; 4],
    pub src_port: u16,
    pub dst: [u8; 4],
    pub dst_port: u16,
}

impl CeTuple {
    /// The flow key both directions share, and whether this packet is the
    /// reverse of that order.
    pub fn canonical(&self) -> ([u8; 13], bool) {
        let a = (self.src, self.src_port);
        let b = (self.dst, self.dst_port);
        let rev = (b.0, b.1) < (a.0, a.1);
        let (lo, hi) = if rev { (b, a) } else { (a, b) };
        let mut k = [0u8; 13];
        k[0] = self.proto;
        k[1..5].copy_from_slice(&lo.0);
        k[5..7].copy_from_slice(&lo.1.to_be_bytes());
        k[7..11].copy_from_slice(&hi.0);
        k[11..13].copy_from_slice(&hi.1.to_be_bytes());
        (k, rev)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ChainHeader {
    pub flags: u8,
    pub chain_id: u32,
    pub generation: u64,
    pub stage: u8,
    pub stages: u8,
    pub instance: u16,
    pub flow: [u8; 13],
    pub hops_left: u8,
}

impl ChainHeader {
    /// The header for a flow's first stage in the packet's direction.
    /// `forward_is_canonical` says whether the flow's forward direction (the
    /// one it was first seen in) is the canonical order
    /// (`CeTuple::canonical`); a packet whose own order differs from it is
    /// the reverse direction and starts at the last stage.
    pub fn first(
        chain_id: u32,
        generation: u64,
        stages: u8,
        instance_at: impl Fn(u8) -> u16,
        t: &CeTuple,
        forward_is_canonical: bool,
    ) -> Option<Self> {
        if stages == 0 || stages > CE_HOPS {
            return None;
        }
        let (flow, rev) = t.canonical();
        let reverse = rev == forward_is_canonical;
        let stage = if reverse { stages - 1 } else { 0 };
        Some(Self {
            flags: if reverse { CE_FLAG_REVERSE } else { 0 },
            chain_id,
            generation,
            stage,
            stages,
            instance: instance_at(stage),
            flow,
            hops_left: CE_HOPS,
        })
    }

    pub fn reverse(&self) -> bool {
        self.flags & CE_FLAG_REVERSE != 0
    }

    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let o = out.get_mut(..CE_LEN)?;
        o[0..2].copy_from_slice(&CE_MAGIC);
        o[2] = CE_VERSION;
        o[3] = self.flags;
        o[4..8].copy_from_slice(&self.chain_id.to_be_bytes());
        o[8..16].copy_from_slice(&self.generation.to_be_bytes());
        o[16] = self.stage;
        o[17] = self.stages;
        o[18..20].copy_from_slice(&self.instance.to_be_bytes());
        o[20..33].copy_from_slice(&self.flow);
        o[33] = self.hops_left;
        o[34] = 0;
        o[35] = 0;
        Some(CE_LEN)
    }

    pub fn decode(b: &[u8]) -> Result<Self, CeWhy> {
        let b = b.get(..CE_LEN).ok_or(CeWhy::Malformed)?;
        if b[0..2] != CE_MAGIC
            || b[2] != CE_VERSION
            || b[3] & !(CE_FLAG_REVERSE | CE_FLAG_PASSIVE) != 0
            || b[34] != 0
            || b[35] != 0
            || b[17] == 0
            || b[16] >= b[17]
        {
            return Err(CeWhy::Malformed);
        }
        let mut flow = [0u8; 13];
        flow.copy_from_slice(&b[20..33]);
        Ok(Self {
            flags: b[3],
            chain_id: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            generation: u64::from_be_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
            stage: b[16],
            stages: b[17],
            instance: u16::from_be_bytes([b[18], b[19]]),
            flow,
            hops_left: b[33],
        })
    }

    /// The check a stage instance makes on receipt: the header is for this
    /// chain and generation, this stage and this instance, and has hops
    /// left.
    pub fn admit(
        &self,
        chain_id: u32,
        generation: u64,
        stage: u8,
        instance: u16,
    ) -> Result<(), CeWhy> {
        if self.chain_id != chain_id
            || self.generation != generation
            || self.stage != stage
            || self.instance != instance
        {
            return Err(CeWhy::NotOurs);
        }
        if self.hops_left == 0 {
            return Err(CeWhy::Loop);
        }
        Ok(())
    }

    /// The header for the next stage in this packet's direction: forward
    /// walks up, reverse walks down, each to the instance the flow's pin
    /// names there. `Done` past the last.
    pub fn next(&self, instance_at: impl Fn(u8) -> u16) -> Result<Self, CeWhy> {
        if self.hops_left == 0 {
            return Err(CeWhy::Loop);
        }
        let stage = if self.reverse() {
            self.stage.checked_sub(1).ok_or(CeWhy::Done)?
        } else {
            let s = self.stage.checked_add(1).ok_or(CeWhy::Done)?;
            if s >= self.stages {
                return Err(CeWhy::Done);
            }
            s
        };
        Ok(Self {
            stage,
            instance: instance_at(stage),
            hops_left: self.hops_left - 1,
            ..*self
        })
    }
}
