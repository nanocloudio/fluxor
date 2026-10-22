// Contract: net.route — how the node's workloads reach each other and the
// outside world.
//
// Layer: contracts (public, stable).
//
// The node holds three tables, each replaced whole by its one writer (the
// node agent):
//
// * SEGMENTS — the L3 attachments workloads join. A workload created with a
//   network identity on segment `s ≥ 1` holds its address as a host address,
//   reaches everything through the segment's gateway (an address the node
//   holds), and is reached by the node. Segment 0 means "no segment".
// * ROUTES — peer routes: a prefix another node serves, and that node's
//   address.
// * HOLD — held addresses: addresses the node answers for on the uplink
//   whose connected prefix covers them.
//
// Policy is upstream: the writer allocates every prefix, gateway and address;
// the provider realizes what it is given and says, per entry, whether it took
// effect (`READ`). Capabilities are honest: a bit is set only when the
// realization would take effect on this node, and an entry the host defeats
// reads `refused(reason)` or `unknown`, never silently nothing.
//
// Every op answers `EACCES` to a module not acting with the node's
// authority. SEGMENTS, ROUTES, HOLD and READ also need `platform_raw`;
// REPORT and TAKE are the realizing module's, admitted from the registered
// net-identity provider alone.
//
// Little-endian integers; addresses in network order, family-tagged and 16
// bytes wide (IPv4 in the first four, the rest zero), so IPv6 needs no format
// change.

/// Provider class id (opcode class 0x20xx). Mirrors
/// `kernel::module::provider::contract::NET_ROUTE`.
pub const CLASS: u16 = 0x0020;

/// Returns 0 when a net.route provider is present. handle=-1, arg=null.
pub const PROBE: u32 = 0x2000;

/// Capability bitmap. handle=-1, arg = `[caps_out:u32]` (written). Returns 0.
pub const CAPS: u32 = 0x2001;

/// Replace the segment table, whole and atomically. handle=-1, arg =
/// `[count:u8][segment]×count` ([`segment`]). Returns 0, or `EINVAL`
/// (malformed: a segment 0, a gateway outside its prefix, two segments with
/// one id or one gateway, trailing bytes), `ENOSPC` (past capacity), `EBUSY`
/// (a segment a workload is attached to would go or change its prefix or
/// gateway, or another module is the writer), `EAGAIN` (the store stayed
/// busy; nothing changed), or the platform's error realizing it. On any
/// error the table is as it was.
pub const SEGMENTS: u32 = 0x2002;

/// Replace the peer-route table, whole and atomically. handle=-1, arg =
/// `[count:u16][route]×count` ([`peer`]). Returns 0, `EINVAL`, `ENOSPC`
/// (past capacity), `EBUSY` (another writer) or `EAGAIN`, as [`SEGMENTS`].
pub const ROUTES: u32 = 0x2003;

/// Replace the held-address table, whole. handle=-1, arg =
/// `[count:u16][held]×count` ([`held`]), one entry per address. Realization
/// is asynchronous: poll `READ`. Returns 0, `EINVAL` (malformed, or an
/// address twice), `ENOSPC`, `EBUSY` (another writer, or a node whose held
/// addresses are written to its network stack directly) or `EAGAIN`, as
/// [`SEGMENTS`].
pub const HOLD: u32 = 0x2004;

/// Read the realization state. handle=-1, arg = the out buffer:
/// `[state_generation:u64]` then one [`entry`] per segment, route and held
/// address, in table order. The generation advances whenever a table or an
/// entry's state changes, so a caller polls it. Returns the byte count
/// written; `ERANGE` when the entries do not fit (the generation is still
/// written, so a buffer of exactly 8 bytes is a cheap poll); `EINVAL` under 8
/// bytes; `EAGAIN` when a concurrent writer kept the state from being read
/// consistently (the caller keeps its previous copy).
pub const READ: u32 = 0x2005;

/// A realizing module provider (the bare-metal network stack) reports
/// per-entry state. handle=-1, arg = `[entry]×n` ([`entry`]), each indexed
/// into the tables of the provider's last [`TAKE`]. Admitted only from the
/// registered net-identity provider, without `platform_raw`; a platform that
/// realizes the tables itself never calls it. All entries are recorded or
/// none. Returns 0, `EINVAL` (malformed, or an index past its table),
/// `EACCES` (not the provider), or `EAGAIN` when the tables moved since that
/// TAKE (the provider takes again and reports against those).
pub const REPORT: u32 = 0x2006;

/// The table contents, for a realizing module provider. handle=-1, arg = the
/// out buffer: `[table_generation:u64][n_segments:u8][rsv:u8]
/// [n_routes:u16][n_held:u16][rsv:u16]` then the segments, routes and held
/// records in their wire layouts. Returns the byte count; `ERANGE` when the
/// records do not fit, with the header still written as far as the buffer
/// holds it (an 8-byte buffer is a cheap poll of the generation; a
/// [`TAKE_HEAD`]-byte one also learns the counts it is missing); `EINVAL`
/// under 8 bytes. Same admission as [`REPORT`].
pub const TAKE: u32 = 0x2007;

/// Capability bits: set only when the realization would take effect.
pub mod caps {
    /// Workloads attach to segments (CREATE with segment ≥ 1 is admitted).
    pub const SEGMENTS: u32 = 1 << 0;
    /// The node forwards between segments and uplinks.
    pub const FORWARD: u32 = 1 << 1;
    /// Peer routes are realized.
    pub const PEER_ROUTES: u32 = 1 << 2;
    /// Egress outside the cluster prefixes can be translated.
    pub const EGRESS_TRANSLATE: u32 = 1 << 3;
    /// Held addresses in `deliver` mode are realized.
    pub const HOLD_DELIVER: u32 = 1 << 4;
    /// Held addresses in `announce` mode are realized.
    pub const HOLD_ANNOUNCE: u32 = 1 << 5;
}

/// Address families (the `workload` contract's `NET_FAM_*` values).
pub const FAM_IPV4: u8 = 4;
pub const FAM_IPV6: u8 = 6;

/// Width of every address field.
pub const ADDR_LEN: usize = 16;

/// Cluster prefixes one segment carries at most: the cluster's own prefix
/// and its service range, with room for a few more. A protocol maximum.
pub const MAX_CLUSTER_PREFIXES: usize = 8;

/// Segment record:
/// ```text
/// [id:u16][family:u8][prefix_len:u8][prefix:16][gateway:16]
/// [mtu:u16][egress:u8][n_cluster:u8][cluster (family:u8, len:u8, prefix:16)×n]
/// ```
pub mod segment {
    /// Bytes before the cluster prefixes.
    pub const HEAD: usize = 2 + 1 + 1 + 16 + 16 + 2 + 1 + 1;
    /// Bytes per cluster prefix.
    pub const CLUSTER: usize = 1 + 1 + 16;
    /// `egress`: traffic outside the cluster prefixes leaves with its own
    /// source.
    pub const EGRESS_ROUTED: u8 = 0;
    /// `egress`: traffic outside the cluster prefixes leaves with the
    /// egress interface's address as its source.
    pub const EGRESS_TRANSLATED: u8 = 1;
}

/// Peer-route record:
/// `[family:u8][prefix_len:u8][carriage:u8][rsv:u8][prefix:16][peer:16]`.
pub mod peer {
    pub const SIZE: usize = 1 + 1 + 1 + 1 + 16 + 16;
    /// `carriage`: the peer is reached directly (no encapsulation).
    pub const CARRIAGE_DIRECT: u8 = 0;
}

/// Held-address record:
/// `[family:u8][mode:u8][state_req:u8][rsv:u8][addr:16]`.
pub mod held {
    pub const SIZE: usize = 1 + 1 + 1 + 1 + 16;
    /// `mode`: the node accepts traffic to the address as its own.
    pub const MODE_DELIVER: u8 = 0;
    /// `mode`: the node answers for the address on the uplink and routes it
    /// to its workloads.
    pub const MODE_ANNOUNCE: u8 = 1;
    /// `state_req`: the node should answer for the address.
    pub const ARMED: u8 = 0;
    /// `state_req`: the node must stop answering for it.
    pub const FENCED: u8 = 1;
}

/// TAKE's header before the records.
pub const TAKE_HEAD: usize = 8 + 1 + 1 + 2 + 2 + 2;

/// One entry's state, as READ answers it and REPORT states it:
/// ```text
/// [kind:u8][state:u8][reason:u8][cutoff_kind:u8][index:u16][rsv:u16]
/// [install_gen:u32][rsv:u32][cutoff:u64]
/// ```
/// `index` is the entry's position in its table. The fence evidence
/// (`install_gen`, `cutoff`, `cutoff_kind`) is meaningful for held
/// addresses and zero otherwise.
pub mod entry {
    pub const SIZE: usize = 24;
    /// `kind` values.
    pub const KIND_SEGMENT: u8 = 1;
    pub const KIND_ROUTE: u8 = 2;
    pub const KIND_HELD: u8 = 3;
}

/// Entry states.
pub mod state {
    /// Accepted, not yet in effect.
    pub const PENDING: u8 = 0;
    /// In effect.
    pub const REALIZED: u8 = 1;
    /// A held address the node has stopped answering for.
    pub const FENCED: u8 = 2;
    /// Not in effect, for the entry's reason.
    pub const REFUSED: u8 = 3;
    /// Whether it takes effect cannot be established.
    pub const UNKNOWN: u8 = 4;
}

/// Reasons a `refused` (or `unknown`) entry carries.
pub mod reason {
    pub const NONE: u8 = 0;
    /// The provider lacks the privilege to realize it.
    pub const NO_PRIVILEGE: u8 = 1;
    /// The runtime has no state directory of its own.
    pub const NO_STATE_DIR: u8 = 2;
    /// The host drops forwarded traffic.
    pub const HOST_FORWARD_DROP: u8 = 3;
    /// A host table it needs is full.
    pub const TABLE_FULL: u8 = 4;
    /// Another runtime on the host holds an overlapping prefix or address.
    pub const CONFLICT: u8 = 5;
    /// The provider cannot realize it here.
    pub const UNSUPPORTED: u8 = 6;
}

/// A prefix: family, length, address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix {
    pub family: u8,
    pub len: u8,
    pub addr: [u8; ADDR_LEN],
}

impl Prefix {
    pub const EMPTY: Prefix = Prefix {
        family: 0,
        len: 0,
        addr: [0; ADDR_LEN],
    };

    /// Bits an address of the family has.
    pub fn bits(&self) -> u8 {
        if self.family == FAM_IPV6 {
            128
        } else {
            32
        }
    }

    /// Whether `addr` (of the same family) lies inside the prefix.
    pub fn contains(&self, family: u8, addr: &[u8; ADDR_LEN]) -> bool {
        if family != self.family {
            return false;
        }
        let n = self.len as usize;
        let mut i = 0;
        while i < ADDR_LEN && i * 8 < n {
            let take = if n - i * 8 >= 8 { 8 } else { n - i * 8 };
            let mask = (0xFFu16 << (8 - take)) as u8;
            if (self.addr[i] ^ addr[i]) & mask != 0 {
                return false;
            }
            i += 1;
        }
        true
    }
}

/// A segment, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub id: u16,
    pub prefix: Prefix,
    pub gateway: [u8; ADDR_LEN],
    pub mtu: u16,
    pub egress: u8,
    pub n_cluster: u8,
    pub cluster: [Prefix; MAX_CLUSTER_PREFIXES],
}

impl Segment {
    pub const EMPTY: Segment = Segment {
        id: 0,
        prefix: Prefix::EMPTY,
        gateway: [0; ADDR_LEN],
        mtu: 0,
        egress: 0,
        n_cluster: 0,
        cluster: [Prefix::EMPTY; MAX_CLUSTER_PREFIXES],
    };

    /// The cluster prefixes it carries.
    pub fn cluster(&self) -> &[Prefix] {
        let n = (self.n_cluster as usize).min(MAX_CLUSTER_PREFIXES);
        self.cluster.get(..n).unwrap_or(&[])
    }

    /// Its wire length.
    pub fn wire_len(&self) -> usize {
        segment::HEAD + self.cluster().len() * segment::CLUSTER
    }
}

/// A peer route, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub prefix: Prefix,
    pub carriage: u8,
    pub peer: [u8; ADDR_LEN],
}

impl Route {
    pub const EMPTY: Route = Route {
        prefix: Prefix::EMPTY,
        carriage: 0,
        peer: [0; ADDR_LEN],
    };
}

/// A held address, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Held {
    pub family: u8,
    pub mode: u8,
    pub state_req: u8,
    pub addr: [u8; ADDR_LEN],
}

impl Held {
    pub const EMPTY: Held = Held {
        family: 0,
        mode: 0,
        state_req: 0,
        addr: [0; ADDR_LEN],
    };
}

/// One entry's state, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryState {
    pub kind: u8,
    pub state: u8,
    pub reason: u8,
    pub cutoff_kind: u8,
    pub index: u16,
    pub install_gen: u32,
    pub cutoff: u64,
}

impl EntryState {
    pub const EMPTY: EntryState = EntryState {
        kind: 0,
        state: state::PENDING,
        reason: reason::NONE,
        cutoff_kind: 0,
        index: 0,
        install_gen: 0,
        cutoff: 0,
    };
}

fn byte(b: &[u8], at: usize) -> Option<u8> {
    b.get(at).copied()
}

fn u16_le(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes([byte(b, at)?, byte(b, at + 1)?]))
}

fn u32_le(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        byte(b, at)?,
        byte(b, at + 1)?,
        byte(b, at + 2)?,
        byte(b, at + 3)?,
    ]))
}

fn u64_le(b: &[u8], at: usize) -> Option<u64> {
    let lo = u32_le(b, at)? as u64;
    let hi = u32_le(b, at + 4)? as u64;
    Some(lo | (hi << 32))
}

fn addr16(b: &[u8], at: usize) -> Option<[u8; ADDR_LEN]> {
    let mut a = [0u8; ADDR_LEN];
    for (i, d) in a.iter_mut().enumerate() {
        *d = byte(b, at + i)?;
    }
    Some(a)
}

fn put(out: &mut [u8], at: usize, v: u8) -> Option<()> {
    *out.get_mut(at)? = v;
    Some(())
}

fn put_bytes(out: &mut [u8], at: usize, v: &[u8]) -> Option<()> {
    for (i, b) in v.iter().enumerate() {
        put(out, at + i, *b)?;
    }
    Some(())
}

/// A family-tagged prefix is well formed: a known family, a length within
/// it, no address bits past the length, and an IPv4 address in the first
/// four bytes only.
fn prefix_ok(p: &Prefix) -> bool {
    if p.family != FAM_IPV4 && p.family != FAM_IPV6 {
        return false;
    }
    if p.len > p.bits() {
        return false;
    }
    if p.family == FAM_IPV4 && p.addr.iter().skip(4).any(|&b| b != 0) {
        return false;
    }
    let mut masked = *p;
    let n = p.len as usize;
    let mut i = 0;
    while i < ADDR_LEN {
        let keep = n.saturating_sub(i * 8).min(8);
        let mask = if keep == 0 {
            0u8
        } else {
            (0xFFu16 << (8 - keep)) as u8
        };
        masked.addr[i] &= mask;
        i += 1;
    }
    masked.addr == p.addr
}

/// An address is well formed for `family`.
fn addr_ok(family: u8, a: &[u8; ADDR_LEN]) -> bool {
    match family {
        FAM_IPV4 => a.iter().skip(4).all(|&b| b == 0),
        FAM_IPV6 => true,
        _ => false,
    }
}

/// Decode the segment at `at`: `(segment, next)`, or None when it is
/// malformed or runs past the end. A segment with more cluster prefixes than
/// [`MAX_CLUSTER_PREFIXES`] is malformed.
pub fn segment_at(b: &[u8], at: usize) -> Option<(Segment, usize)> {
    let id = u16_le(b, at)?;
    let family = byte(b, at + 2)?;
    let prefix_len = byte(b, at + 3)?;
    let prefix = Prefix {
        family,
        len: prefix_len,
        addr: addr16(b, at + 4)?,
    };
    let gateway = addr16(b, at + 20)?;
    let mtu = u16_le(b, at + 36)?;
    let egress = byte(b, at + 38)?;
    let n = byte(b, at + 39)? as usize;
    if id == 0
        || !prefix_ok(&prefix)
        || !addr_ok(family, &gateway)
        || !prefix.contains(family, &gateway)
        || egress > segment::EGRESS_TRANSLATED
        || n > MAX_CLUSTER_PREFIXES
    {
        return None;
    }
    let mut s = Segment {
        id,
        prefix,
        gateway,
        mtu,
        egress,
        n_cluster: n as u8,
        cluster: [Prefix::EMPTY; MAX_CLUSTER_PREFIXES],
    };
    let mut off = at + segment::HEAD;
    for c in s.cluster.iter_mut().take(n) {
        *c = Prefix {
            family: byte(b, off)?,
            len: byte(b, off + 1)?,
            addr: addr16(b, off + 2)?,
        };
        if !prefix_ok(c) {
            return None;
        }
        off += segment::CLUSTER;
    }
    Some((s, off))
}

/// Encode `s` at `out[at..]`; the byte count, or None when it does not fit.
pub fn write_segment(out: &mut [u8], at: usize, s: &Segment) -> Option<usize> {
    put_bytes(out, at, &s.id.to_le_bytes())?;
    put(out, at + 2, s.prefix.family)?;
    put(out, at + 3, s.prefix.len)?;
    put_bytes(out, at + 4, &s.prefix.addr)?;
    put_bytes(out, at + 20, &s.gateway)?;
    put_bytes(out, at + 36, &s.mtu.to_le_bytes())?;
    put(out, at + 38, s.egress)?;
    put(out, at + 39, s.cluster().len() as u8)?;
    let mut off = at + segment::HEAD;
    for c in s.cluster() {
        put(out, off, c.family)?;
        put(out, off + 1, c.len)?;
        put_bytes(out, off + 2, &c.addr)?;
        off += segment::CLUSTER;
    }
    Some(off - at)
}

/// Decode the route at `at`.
pub fn route_at(b: &[u8], at: usize) -> Option<Route> {
    let family = byte(b, at)?;
    let r = Route {
        prefix: Prefix {
            family,
            len: byte(b, at + 1)?,
            addr: addr16(b, at + 4)?,
        },
        carriage: byte(b, at + 2)?,
        peer: addr16(b, at + 20)?,
    };
    if !prefix_ok(&r.prefix) || !addr_ok(family, &r.peer) || r.carriage != peer::CARRIAGE_DIRECT {
        return None;
    }
    Some(r)
}

/// Encode `r` at `out[at..]`.
pub fn write_route(out: &mut [u8], at: usize, r: &Route) -> Option<usize> {
    put(out, at, r.prefix.family)?;
    put(out, at + 1, r.prefix.len)?;
    put(out, at + 2, r.carriage)?;
    put(out, at + 3, 0)?;
    put_bytes(out, at + 4, &r.prefix.addr)?;
    put_bytes(out, at + 20, &r.peer)?;
    Some(peer::SIZE)
}

/// Decode the held address at `at`.
pub fn held_at(b: &[u8], at: usize) -> Option<Held> {
    let h = Held {
        family: byte(b, at)?,
        mode: byte(b, at + 1)?,
        state_req: byte(b, at + 2)?,
        addr: addr16(b, at + 4)?,
    };
    if !addr_ok(h.family, &h.addr) || h.mode > held::MODE_ANNOUNCE || h.state_req > held::FENCED {
        return None;
    }
    Some(h)
}

/// Encode `h` at `out[at..]`.
pub fn write_held(out: &mut [u8], at: usize, h: &Held) -> Option<usize> {
    put(out, at, h.family)?;
    put(out, at + 1, h.mode)?;
    put(out, at + 2, h.state_req)?;
    put(out, at + 3, 0)?;
    put_bytes(out, at + 4, &h.addr)?;
    Some(held::SIZE)
}

/// Decode the entry state at `at`.
pub fn entry_at(b: &[u8], at: usize) -> Option<EntryState> {
    let e = EntryState {
        kind: byte(b, at)?,
        state: byte(b, at + 1)?,
        reason: byte(b, at + 2)?,
        cutoff_kind: byte(b, at + 3)?,
        index: u16_le(b, at + 4)?,
        install_gen: u32_le(b, at + 8)?,
        cutoff: u64_le(b, at + 16)?,
    };
    if !(entry::KIND_SEGMENT..=entry::KIND_HELD).contains(&e.kind)
        || e.state > state::UNKNOWN
        || e.reason > reason::UNSUPPORTED
    {
        return None;
    }
    Some(e)
}

/// Encode `e` at `out[at..]`.
pub fn write_entry(out: &mut [u8], at: usize, e: &EntryState) -> Option<usize> {
    put(out, at, e.kind)?;
    put(out, at + 1, e.state)?;
    put(out, at + 2, e.reason)?;
    put(out, at + 3, e.cutoff_kind)?;
    put_bytes(out, at + 4, &e.index.to_le_bytes())?;
    put_bytes(out, at + 6, &[0, 0])?;
    put_bytes(out, at + 8, &e.install_gen.to_le_bytes())?;
    put_bytes(out, at + 12, &[0, 0, 0, 0])?;
    put_bytes(out, at + 16, &e.cutoff.to_le_bytes())?;
    Some(entry::SIZE)
}

/// The leading u64 of a READ or TAKE buffer.
pub fn generation(b: &[u8]) -> Option<u64> {
    u64_le(b, 0)
}
