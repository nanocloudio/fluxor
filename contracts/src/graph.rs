//! The composed graph: one graph as the kernel admits it, fans materialised
//! and stepping order given, and its one codec, which the composer, the
//! kernel and modules that compose at runtime all link.
//!
//! ```text
//! header  magic u32 "FLXG" | flags u16 | module_count u16 | edge_count u16 | 0 u16
//!         | owner_uid [16] | state_cap u32 | buffer_cap u32
//! order   u16 × module_count | zero pad to 4
//! module  entry_len u16 | flags u8 | domain u8 | name_hash u32
//!         | step_deadline_us u32 | burst_us u32 | fault_policy u8 | 0 u8 | 0 u8 | 0 u8
//!         | params [entry_len - 20] | zero pad to 4
//! edge    from_kind u8 | from_port u8 | from_idx u16
//!         | to_kind u8 | to_port u8 | to_idx u16
//!         | class u8 | buffer_group u8 | rate_class u8 | flags u8 | buffer_bytes u32
//!         | lane_target u32
//! ```
//!
//! Every field is little-endian. A module's index is its position among the
//! module records, and `order[k]` is the index of the k-th module to step: a
//! permutation of `0..module_count`. A fan is an ordinary module record named
//! [`TEE_NAME_HASH`] or [`MERGE_NAME_HASH`]; its joining edges are ordinary
//! edges. `entry_len` is a module record's unpadded length; the next record
//! starts at the next 4-aligned offset.
//!
//! An edge end is one of [`Endpoint`]'s kinds. A tap is named by its
//! producer end alone (kind 2), so no edge flag repeats it. A lane end
//! (kind 3) carries its key as the index and names the module serving it in
//! `lane_target` by the name hash it declares its lanes under, which is 0
//! on an edge with no lane end; an edge has at most one lane end. An unknown flag
//! bit, endpoint kind, edge class, rate class or fault policy, a reserved or
//! pad byte that is not zero, an order that is not a permutation, a `New`
//! end past the module records, a port past [`MAX_PORT_INDEX`], or bytes
//! left after the last edge refuses the whole graph.
//!
//! Decoding allocates nothing: [`decode`] validates the blob once and
//! returns a view that reads records where they lie. Encoding is
//! [`encode_into`] over a caller's buffer, and [`encode`] with feature
//! `alloc`. The composition rules that produce a graph — the fan pass, the
//! mailbox groups, the ring plan and the order — are [`plan`].

pub mod env_bind;
pub mod plan;

pub use crate::boot_config::EdgeClass;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// `"FLXG"` read as a little-endian u32.
pub const MAGIC: u32 = u32::from_le_bytes(*b"FLXG");

/// Bytes of the header.
pub const HEADER_LEN: usize = 36;
/// Bytes of a module record before its params.
pub const MODULE_HEAD_LEN: usize = 20;
/// Bytes of one edge record.
pub const EDGE_LEN: usize = 20;
/// Every module record and the edge table start on this boundary.
pub const RECORD_ALIGN: usize = 4;

/// Header flag: the graph's owner acts with its creator's authority.
pub const FLAG_CREATOR_AUTHORITY: u16 = 0x0001;
const FLAGS_KNOWN: u16 = FLAG_CREATOR_AUTHORITY;

/// Module flag: the module runs in its domain's pre-pass.
pub const MODULE_FLAG_PRE_PASS: u8 = 0x01;
const MODULE_FLAGS_KNOWN: u8 = MODULE_FLAG_PRE_PASS;

/// Edge flag: a write on the edge wakes its consumer.
pub const EDGE_FLAG_WAKE_ON_WRITE: u8 = 0x01;
/// Edge flag: the consumer port keeps its own copy of what it sends.
pub const EDGE_FLAG_RETAINS_SEND: u8 = 0x02;
/// Edge flag: the edge ends on the consumer's control input.
pub const EDGE_FLAG_TO_CTRL: u8 = 0x04;
const EDGE_FLAGS_KNOWN: u8 = EDGE_FLAG_WAKE_ON_WRITE | EDGE_FLAG_RETAINS_SEND | EDGE_FLAG_TO_CTRL;

/// The largest port index an edge names.
pub const MAX_PORT_INDEX: u8 = 15;

/// The most pre-pass modules one domain runs: a graph with more in a domain
/// is refused by the composer and by the kernel alike.
pub const MAX_PRE_PASS_PER_DOMAIN: usize = 4;

/// The largest rate class byte (`RateClass::Transaction`).
const MAX_RATE_CLASS: u8 = 4;

/// FNV-1a over `bytes`, the name hash a module record carries.
#[must_use]
pub const fn name_hash(bytes: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    let mut i = 0;
    while i < bytes.len() {
        h ^= bytes[i] as u32;
        h = h.wrapping_mul(0x0100_0193);
        i += 1;
    }
    h
}

/// The name hash of a fan-out module.
pub const TEE_NAME_HASH: u32 = name_hash(b"tee");
/// The name hash of a fan-in module.
pub const MERGE_NAME_HASH: u32 = name_hash(b"merge");

// ── Records ─────────────────────────────────────────────────────────────────

/// What a module's fault does to it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum FaultPolicy {
    /// The module stops; the graph runs on without it.
    #[default]
    Skip = 0,
    /// The module's channels are flushed and it runs again.
    Restart = 1,
    /// A deadline overrun is recorded and never faults the module.
    Tolerate = 2,
}

impl FaultPolicy {
    /// The policy a wire byte names, or `None` for a byte no policy has.
    #[must_use]
    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Skip),
            1 => Some(Self::Restart),
            2 => Some(Self::Tolerate),
            _ => None,
        }
    }
}

/// One module of the graph.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ModuleRecord<'a> {
    pub name_hash: u32,
    pub domain: u8,
    pub pre_pass: bool,
    /// The declared step deadline; 0 takes the node's default.
    pub step_deadline_us: u32,
    /// The declared burst deadline; 0 takes the deadline's multiple.
    pub burst_us: u32,
    pub fault_policy: FaultPolicy,
    /// The module's params TLV, borrowed from wherever the record lives.
    pub params: &'a [u8],
}

/// An end of an edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// A module of this graph, by index.
    New(u16),
    /// A module already running, by global slot.
    Existing(u16),
    /// A copy of what a running module's output port already carries, by
    /// global slot. A producer end only.
    Tap(u16),
    /// A lane to a node module that serves lanes (the node's network
    /// stack), by key and the name hash the serving module declares its
    /// lanes under: an edge into it carries the lane's commands, an edge out
    /// of it the lane's events.
    Lane { key: u8, target: u32 },
    /// The module that places the graph, by key.
    Caller(u8),
}

impl Default for Endpoint {
    fn default() -> Self {
        Self::New(0)
    }
}

impl Endpoint {
    /// The endpoint's wire kind byte and index. A lane's target travels in
    /// the edge's `lane_target` ([`Endpoint::lane_target`]).
    #[must_use]
    pub const fn to_wire(self) -> (u8, u16) {
        match self {
            Self::New(i) => (0, i),
            Self::Existing(i) => (1, i),
            Self::Tap(i) => (2, i),
            Self::Lane { key, .. } => (3, key as u16),
            Self::Caller(k) => (4, k as u16),
        }
    }

    /// The endpoint a wire kind and index name, with the edge's
    /// `lane_target` for a lane end, or `None` for a kind no endpoint has, a
    /// key past a byte or a lane with no target.
    #[must_use]
    pub const fn from_wire(kind: u8, idx: u16, lane_target: u32) -> Option<Self> {
        match kind {
            0 => Some(Self::New(idx)),
            1 => Some(Self::Existing(idx)),
            2 => Some(Self::Tap(idx)),
            3 if idx <= u8::MAX as u16 && lane_target != 0 => Some(Self::Lane {
                key: idx as u8,
                target: lane_target,
            }),
            4 if idx <= u8::MAX as u16 => Some(Self::Caller(idx as u8)),
            _ => None,
        }
    }

    /// A lane end's target: the name hash the module serving it declares
    /// its lanes under.
    #[must_use]
    pub const fn lane_target(self) -> Option<u32> {
        match self {
            Self::Lane { target, .. } => Some(target),
            _ => None,
        }
    }

    /// A lane end's key.
    #[must_use]
    pub const fn lane_key(self) -> Option<u8> {
        match self {
            Self::Lane { key, .. } => Some(key),
            _ => None,
        }
    }

    /// The module index of a `New` end.
    #[must_use]
    pub const fn new_index(self) -> Option<usize> {
        match self {
            Self::New(i) => Some(i as usize),
            _ => None,
        }
    }
}

/// One edge of the graph.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EdgeRecord {
    pub from: Endpoint,
    /// Producer port index, 0..=15.
    pub from_port: u8,
    pub to: Endpoint,
    /// Consumer port index, 0..=15.
    pub to_port: u8,
    /// The edge ends on the consumer's control input rather than its data
    /// input.
    pub to_ctrl: bool,
    pub class: EdgeClass,
    /// Mailbox buffer group; 0 for none. Edges of one group share a ring.
    pub buffer_group: u8,
    /// Rate class (contracts `RateClass`).
    pub rate_class: u8,
    pub wake_on_write: bool,
    pub retains_send: bool,
    /// Requested ring bytes; 0 defers to the ports' capacities.
    pub buffer_bytes: u32,
}

// ── Errors ──────────────────────────────────────────────────────────────────

/// Why a blob was refused, naming what and where.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Fewer bytes than a header.
    Short {
        len: usize,
    },
    BadMagic {
        found: u32,
    },
    /// A header flag bit no flag names.
    UnknownFlags {
        flags: u16,
    },
    /// A reserved or pad byte is not zero.
    Reserved {
        offset: usize,
    },
    /// The order table, a module record or the edge table runs past the
    /// blob.
    Truncated {
        what: &'static str,
        offset: usize,
    },
    /// Bytes remain after the last edge.
    TrailingBytes {
        offset: usize,
    },
    /// `order` is not a permutation of the module indices.
    Order {
        position: usize,
        what: &'static str,
    },
    /// A module record holds a value outside its field.
    Module {
        index: usize,
        what: &'static str,
    },
    /// An edge record holds a value outside its field.
    Edge {
        index: usize,
        what: &'static str,
    },
}

impl DecodeError {
    /// A short name for the refusal, for a log line with no formatting
    /// machinery; [`Self::detail`] gives its number.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match *self {
            Self::Short { .. } => "short",
            Self::BadMagic { .. } => "magic",
            Self::UnknownFlags { .. } => "unknown flag",
            Self::Reserved { .. } => "reserved",
            Self::Truncated { what, .. }
            | Self::Order { what, .. }
            | Self::Module { what, .. }
            | Self::Edge { what, .. } => what,
            Self::TrailingBytes { .. } => "trailing bytes",
        }
    }

    /// The refusal's number: a length, magic, flags, offset or record index.
    #[must_use]
    pub const fn detail(&self) -> usize {
        match *self {
            Self::Short { len } => len,
            Self::BadMagic { found } => found as usize,
            Self::UnknownFlags { flags } => flags as usize,
            Self::Reserved { offset }
            | Self::Truncated { offset, .. }
            | Self::TrailingBytes { offset } => offset,
            Self::Order { position, .. } => position,
            Self::Module { index, .. } | Self::Edge { index, .. } => index,
        }
    }
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Short { len } => write!(f, "graph of {len} bytes is shorter than its header"),
            Self::BadMagic { found } => write!(f, "bad graph magic {found:#010x}"),
            Self::UnknownFlags { flags } => write!(f, "unknown graph flags {flags:#06x}"),
            Self::Reserved { offset } => write!(f, "reserved byte at {offset} is not zero"),
            Self::Truncated { what, offset } => write!(f, "{what} at {offset} runs past the graph"),
            Self::TrailingBytes { offset } => write!(f, "bytes after the last edge at {offset}"),
            Self::Order { position, what } => write!(f, "order[{position}]: {what}"),
            Self::Module { index, what } => write!(f, "module {index}: {what}"),
            Self::Edge { index, what } => write!(f, "edge {index}: {what}"),
        }
    }
}

// ── Decode ──────────────────────────────────────────────────────────────────

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(field(b, at))
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(field(b, at))
}

/// The `N` bytes at `at`, zeros past the end: every read is of a blob the
/// decoder has bounded already, and none can panic (a module links these).
fn field<const N: usize>(b: &[u8], at: usize) -> [u8; N] {
    let mut out = [0u8; N];
    for (o, v) in out.iter_mut().zip(b.iter().skip(at)) {
        *o = *v;
    }
    out
}

const fn aligned(len: usize) -> usize {
    len.next_multiple_of(RECORD_ALIGN)
}

/// The fixed header of a graph, readable before the rest is validated: a
/// kernel refuses counts past its capacity before it walks the records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub flags: u16,
    pub module_count: u16,
    pub edge_count: u16,
    pub owner_uid: [u8; 16],
    pub state_cap: u32,
    pub buffer_cap: u32,
}

impl Header {
    /// Whether the owner acts with its creator's authority.
    #[must_use]
    pub const fn creator_authority(&self) -> bool {
        self.flags & FLAG_CREATOR_AUTHORITY != 0
    }
}

/// Read and check the header alone.
///
/// # Errors
/// [`DecodeError::Short`], [`DecodeError::BadMagic`],
/// [`DecodeError::UnknownFlags`] or [`DecodeError::Reserved`].
pub fn header(bytes: &[u8]) -> Result<Header, DecodeError> {
    if bytes.len() < HEADER_LEN {
        return Err(DecodeError::Short { len: bytes.len() });
    }
    let magic = le32(bytes, 0);
    if magic != MAGIC {
        return Err(DecodeError::BadMagic { found: magic });
    }
    let flags = le16(bytes, 4);
    if flags & !FLAGS_KNOWN != 0 {
        return Err(DecodeError::UnknownFlags { flags });
    }
    if le16(bytes, 10) != 0 {
        return Err(DecodeError::Reserved { offset: 10 });
    }
    let mut owner_uid = [0u8; 16];
    owner_uid.copy_from_slice(&bytes[12..28]);
    Ok(Header {
        flags,
        module_count: le16(bytes, 6),
        edge_count: le16(bytes, 8),
        owner_uid,
        state_cap: le32(bytes, 28),
        buffer_cap: le32(bytes, 32),
    })
}

/// A validated graph: views into the bytes [`decode`] checked.
#[derive(Clone, Copy, Debug)]
pub struct ComposedGraph<'a> {
    header: Header,
    order: &'a [u8],
    modules: &'a [u8],
    edges: &'a [u8],
}

impl<'a> ComposedGraph<'a> {
    #[must_use]
    pub const fn header(&self) -> &Header {
        &self.header
    }

    #[must_use]
    pub const fn module_count(&self) -> u16 {
        self.header.module_count
    }

    #[must_use]
    pub const fn edge_count(&self) -> u16 {
        self.header.edge_count
    }

    /// The stepping order: module indices, the first to step first.
    pub fn order(&self) -> impl ExactSizeIterator<Item = u16> + 'a {
        crate::records::<2>(self.order).map(|b| le16(b, 0))
    }

    /// The module records, in index order.
    #[must_use]
    pub const fn modules(&self) -> Modules<'a> {
        Modules {
            bytes: self.modules,
            left: self.header.module_count,
        }
    }

    /// The edge records, in blob order.
    pub fn edges(&self) -> impl ExactSizeIterator<Item = EdgeRecord> + 'a {
        crate::records::<EDGE_LEN>(self.edges).map(|r| read_edge(r))
    }

    /// Edge `i`, or `None` past the last.
    #[must_use]
    pub fn edge(&self, i: usize) -> Option<EdgeRecord> {
        self.edges
            .get(i * EDGE_LEN..(i + 1) * EDGE_LEN)
            .map(read_edge)
    }
}

/// The module records of a validated graph.
#[derive(Clone, Debug)]
pub struct Modules<'a> {
    bytes: &'a [u8],
    left: u16,
}

impl<'a> Iterator for Modules<'a> {
    type Item = ModuleRecord<'a>;

    fn next(&mut self) -> Option<ModuleRecord<'a>> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        let len = usize::from(le16(self.bytes, 0));
        let r = &self.bytes[..len];
        self.bytes = &self.bytes[aligned(len)..];
        Some(ModuleRecord {
            name_hash: le32(r, 4),
            domain: r[3],
            pre_pass: r[2] & MODULE_FLAG_PRE_PASS != 0,
            step_deadline_us: le32(r, 8),
            burst_us: le32(r, 12),
            // `decode` refused every byte that names no policy.
            fault_policy: FaultPolicy::from_u8(r[16]).unwrap_or_default(),
            params: &r[MODULE_HEAD_LEN..],
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::from(self.left), Some(usize::from(self.left)))
    }
}

impl ExactSizeIterator for Modules<'_> {}

fn read_edge(r: &[u8]) -> EdgeRecord {
    let flags = r[11];
    EdgeRecord {
        // `decode` refused every kind and key that names no endpoint.
        from: Endpoint::from_wire(r[0], le16(r, 2), le32(r, 16)).unwrap_or_default(),
        from_port: r[1],
        to: Endpoint::from_wire(r[4], le16(r, 6), le32(r, 16)).unwrap_or_default(),
        to_port: r[5],
        to_ctrl: flags & EDGE_FLAG_TO_CTRL != 0,
        class: match r[8] {
            1 => EdgeClass::DmaOwned,
            2 => EdgeClass::CrossCore,
            3 => EdgeClass::NicRing,
            _ => EdgeClass::Local,
        },
        buffer_group: r[9],
        rate_class: r[10],
        wake_on_write: flags & EDGE_FLAG_WAKE_ON_WRITE != 0,
        retains_send: flags & EDGE_FLAG_RETAINS_SEND != 0,
        buffer_bytes: le32(r, 12),
    }
}

fn zeros(b: &[u8], from: usize, to: usize) -> Result<(), DecodeError> {
    match b[from..to].iter().position(|&x| x != 0) {
        Some(i) => Err(DecodeError::Reserved { offset: from + i }),
        None => Ok(()),
    }
}

/// Validate a graph and return a view into it. `bytes` is the graph whole:
/// a byte past its last edge is refused.
///
/// Checking that `order` is a permutation compares each entry with those
/// before it; a kernel bounds `module_count` from [`header`] first.
///
/// # Errors
/// The first thing that makes the graph unusable; see [`DecodeError`].
pub fn decode(bytes: &[u8]) -> Result<ComposedGraph<'_>, DecodeError> {
    let header = header(bytes)?;
    let n = usize::from(header.module_count);
    let e = usize::from(header.edge_count);

    let order_end = HEADER_LEN + 2 * n;
    let modules_start = aligned(order_end);
    if modules_start > bytes.len() {
        return Err(DecodeError::Truncated {
            what: "order",
            offset: HEADER_LEN,
        });
    }
    zeros(bytes, order_end, modules_start)?;
    let order = &bytes[HEADER_LEN..order_end];
    for k in 0..n {
        let m = le16(order, 2 * k);
        if usize::from(m) >= n {
            return Err(DecodeError::Order {
                position: k,
                what: "module index out of range",
            });
        }
        if (0..k).any(|j| le16(order, 2 * j) == m) {
            return Err(DecodeError::Order {
                position: k,
                what: "module stepped twice",
            });
        }
    }

    let mut off = modules_start;
    for index in 0..n {
        if bytes.len() - off < MODULE_HEAD_LEN {
            return Err(DecodeError::Truncated {
                what: "module record",
                offset: off,
            });
        }
        let len = usize::from(le16(bytes, off));
        if len < MODULE_HEAD_LEN {
            return Err(DecodeError::Module {
                index,
                what: "record shorter than its head",
            });
        }
        if aligned(len) > bytes.len() - off {
            return Err(DecodeError::Truncated {
                what: "module record",
                offset: off,
            });
        }
        if bytes[off + 2] & !MODULE_FLAGS_KNOWN != 0 {
            return Err(DecodeError::Module {
                index,
                what: "unknown module flag",
            });
        }
        if FaultPolicy::from_u8(bytes[off + 16]).is_none() {
            return Err(DecodeError::Module {
                index,
                what: "unknown fault policy",
            });
        }
        zeros(bytes, off + 17, off + MODULE_HEAD_LEN)?;
        zeros(bytes, off + len, off + aligned(len))?;
        off += aligned(len);
    }
    let modules = &bytes[modules_start..off];

    let edges_len = e * EDGE_LEN;
    if bytes.len() - off < edges_len {
        return Err(DecodeError::Truncated {
            what: "edge table",
            offset: off,
        });
    }
    if bytes.len() - off > edges_len {
        return Err(DecodeError::TrailingBytes {
            offset: off + edges_len,
        });
    }
    let edges = &bytes[off..];
    for (index, r) in edges.chunks_exact(EDGE_LEN).enumerate() {
        check_edge(r, n).map_err(|what| DecodeError::Edge { index, what })?;
    }

    Ok(ComposedGraph {
        header,
        order,
        modules,
        edges,
    })
}

fn check_edge(r: &[u8], n: usize) -> Result<(), &'static str> {
    let target = le32(r, 16);
    let from = Endpoint::from_wire(r[0], le16(r, 2), target).ok_or("unknown producer endpoint")?;
    let to = Endpoint::from_wire(r[4], le16(r, 6), target).ok_or("unknown consumer endpoint")?;
    match (from.lane_target(), to.lane_target()) {
        (Some(_), Some(_)) => return Err("an edge with two lane ends"),
        (None, None) if target != 0 => return Err("a lane target on an edge with no lane end"),
        _ => {}
    }
    for end in [from, to] {
        if end.new_index().is_some_and(|i| i >= n) {
            return Err("module index out of range");
        }
    }
    if matches!(to, Endpoint::Tap(_)) {
        return Err("a tap is a producer end only");
    }
    if r[1] > MAX_PORT_INDEX || r[5] > MAX_PORT_INDEX {
        return Err("port index out of range");
    }
    if r[8] > EdgeClass::NicRing as u8 {
        return Err("unknown edge class");
    }
    if r[10] > MAX_RATE_CLASS {
        return Err("unknown rate class");
    }
    if r[11] & !EDGE_FLAGS_KNOWN != 0 {
        return Err("unknown edge flag");
    }
    Ok(())
}

// ── Encode ──────────────────────────────────────────────────────────────────

/// What [`encode_into`] builds a graph from.
#[derive(Clone, Copy, Debug, Default)]
pub struct GraphSpec<'a> {
    /// The owner acts with its creator's authority.
    pub creator_authority: bool,
    pub owner_uid: [u8; 16],
    pub state_cap: u32,
    pub buffer_cap: u32,
    /// The stepping order: a permutation of `0..modules.len()`.
    pub order: &'a [u16],
    pub modules: &'a [ModuleRecord<'a>],
    pub edges: &'a [EdgeRecord],
}

/// Why a spec cannot be encoded: the field that does not fit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// A count, length or value its field cannot hold, or a spec [`decode`]
    /// would refuse.
    Field(&'static str),
    /// The output buffer is shorter than [`encoded_len`].
    BufferTooSmall { need: usize },
}

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Field(what) => write!(f, "composed graph: {what} does not fit its field"),
            Self::BufferTooSmall { need } => {
                write!(f, "composed graph: {need} bytes do not fit the buffer")
            }
        }
    }
}

/// Bytes [`encode_into`] writes for `spec`.
#[must_use]
pub fn encoded_len(spec: &GraphSpec<'_>) -> usize {
    aligned(HEADER_LEN + 2 * spec.modules.len())
        + spec
            .modules
            .iter()
            .map(|m| aligned(MODULE_HEAD_LEN + m.params.len()))
            .sum::<usize>()
        + spec.edges.len() * EDGE_LEN
}

fn check_spec(spec: &GraphSpec<'_>) -> Result<(u16, u16), EncodeError> {
    let field = EncodeError::Field;
    let n = u16::try_from(spec.modules.len()).map_err(|_| field("module count"))?;
    let e = u16::try_from(spec.edges.len()).map_err(|_| field("edge count"))?;
    if spec.order.len() != spec.modules.len() {
        return Err(field("order length"));
    }
    for (k, &m) in spec.order.iter().enumerate() {
        if m >= n || spec.order[..k].contains(&m) {
            return Err(field("order"));
        }
    }
    for m in spec.modules {
        if MODULE_HEAD_LEN + m.params.len() > usize::from(u16::MAX) {
            return Err(field("module params"));
        }
    }
    for edge in spec.edges {
        for end in [edge.from, edge.to] {
            if end.new_index().is_some_and(|i| i >= spec.modules.len()) {
                return Err(field("edge module index"));
            }
        }
        if edge.from.lane_target().is_some() && edge.to.lane_target().is_some()
            || edge.from.lane_target() == Some(0)
            || edge.to.lane_target() == Some(0)
        {
            return Err(field("edge lane end"));
        }
        if matches!(edge.to, Endpoint::Tap(_)) {
            return Err(field("edge consumer endpoint"));
        }
        if edge.from_port > MAX_PORT_INDEX || edge.to_port > MAX_PORT_INDEX {
            return Err(field("edge port index"));
        }
        if edge.rate_class > MAX_RATE_CLASS {
            return Err(field("edge rate class"));
        }
    }
    Ok((n, e))
}

/// Encode `spec` into `out`; the bytes written.
///
/// # Errors
/// A spec [`decode`] would refuse, or an `out` shorter than
/// [`encoded_len`].
pub fn encode_into(spec: &GraphSpec<'_>, out: &mut [u8]) -> Result<usize, EncodeError> {
    let (n, e) = check_spec(spec)?;
    let need = encoded_len(spec);
    if out.len() < need {
        return Err(EncodeError::BufferTooSmall { need });
    }
    let out = &mut out[..need];
    out.fill(0);
    let put16 = |o: &mut [u8], at: usize, v: u16| o[at..at + 2].copy_from_slice(&v.to_le_bytes());
    let put32 = |o: &mut [u8], at: usize, v: u32| o[at..at + 4].copy_from_slice(&v.to_le_bytes());

    put32(out, 0, MAGIC);
    put16(
        out,
        4,
        if spec.creator_authority {
            FLAG_CREATOR_AUTHORITY
        } else {
            0
        },
    );
    put16(out, 6, n);
    put16(out, 8, e);
    out[12..28].copy_from_slice(&spec.owner_uid);
    put32(out, 28, spec.state_cap);
    put32(out, 32, spec.buffer_cap);
    for (k, &m) in spec.order.iter().enumerate() {
        put16(out, HEADER_LEN + 2 * k, m);
    }

    let mut off = aligned(HEADER_LEN + 2 * spec.modules.len());
    for m in spec.modules {
        let len = MODULE_HEAD_LEN + m.params.len();
        // `check_spec` bounded every record to a u16.
        put16(out, off, len as u16);
        out[off + 2] = if m.pre_pass { MODULE_FLAG_PRE_PASS } else { 0 };
        out[off + 3] = m.domain;
        put32(out, off + 4, m.name_hash);
        put32(out, off + 8, m.step_deadline_us);
        put32(out, off + 12, m.burst_us);
        out[off + 16] = m.fault_policy as u8;
        out[off + MODULE_HEAD_LEN..off + len].copy_from_slice(m.params);
        off += aligned(len);
    }
    for edge in spec.edges {
        let (fk, fi) = edge.from.to_wire();
        let (tk, ti) = edge.to.to_wire();
        out[off] = fk;
        out[off + 1] = edge.from_port;
        put16(out, off + 2, fi);
        out[off + 4] = tk;
        out[off + 5] = edge.to_port;
        put16(out, off + 6, ti);
        out[off + 8] = edge.class as u8;
        out[off + 9] = edge.buffer_group;
        out[off + 10] = edge.rate_class;
        out[off + 11] = (u8::from(edge.wake_on_write) * EDGE_FLAG_WAKE_ON_WRITE)
            | (u8::from(edge.retains_send) * EDGE_FLAG_RETAINS_SEND)
            | (u8::from(edge.to_ctrl) * EDGE_FLAG_TO_CTRL);
        put32(out, off + 12, edge.buffer_bytes);
        put32(
            out,
            off + 16,
            edge.from
                .lane_target()
                .or(edge.to.lane_target())
                .unwrap_or(0),
        );
        off += EDGE_LEN;
    }
    Ok(need)
}

/// Encode `spec`.
///
/// # Errors
/// A spec [`decode`] would refuse.
#[cfg(feature = "alloc")]
pub fn encode(spec: &GraphSpec<'_>) -> Result<Vec<u8>, EncodeError> {
    let mut out = alloc::vec![0u8; encoded_len(spec)];
    encode_into(spec, &mut out)?;
    Ok(out)
}
