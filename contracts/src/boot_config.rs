//! The boot configuration: one checksummed blob of tagged sections, and its
//! one codec, which the composer, the kernel and the tests all link.
//!
//! ```text
//! header   magic "FXCF" | total_len u32 | crc32 u32 | section_count u16 | 0 u16
//! section  tag u32 | len u32 | payload[len] | zero pad to 8
//! ```
//!
//! Every field is little-endian. `crc32` (IEEE, bitwise) covers
//! `[12, total_len)`, so every byte the kernel acts on lies inside
//! `total_len` and under the checksum; bytes past `total_len` are not part
//! of the blob. Sections are found by tag, in any order. An unknown tag, a
//! repeated tag, a section that runs past `total_len`, a non-zero pad byte,
//! bytes left after the stated sections, or a blob without [`tag::GRAPH`]
//! refuses the whole blob: there is no skip path.
//!
//! Sections:
//!
//! ```text
//! GRPH  module_count u16 | edge_count u16 | domain_count u8 | graph_flags u8
//!       | tick_us u16 | graph_sample_rate u32
//!       module × module_count:  entry_len u32 | name_hash u32 | id u16
//!                               | domain u8 | flags u8 | params[entry_len - 12]
//!       edge × edge_count:      from u16 | to u16 | ports u8 | kind u8
//!                               | rate_class u8 | flags u8 | buffer_bytes u32
//!       domain × domain_count:  tick_us u16 | tick_min_us u16 | tick_max_us u16
//!                               | exec_mode u8 | adaptive_flags u8
//! HWRP  the platform's hardware payload, decoded by the platform that
//!       declares one; the codec carries it as bytes
//! WKLD  count u16 | (blob_len u32 | flags u8 | FLXA blob) × count
//! ENVL  count u16 | (pool u16 | n u32) × count
//! DMND  count u16 | (pool u16 | n u32) × count
//! ```
//!
//! Decoding allocates nothing: [`decode`] validates every section once and
//! returns views that borrow from the blob, so a module's params are read
//! where they lie. Counts are bounded here only by their field widths; the
//! kernel's capacity profile bounds them further and names the limit it
//! refuses on. Encoding (feature `alloc`) is [`encode`].

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// `"FXCF"` read as a little-endian u32.
pub const MAGIC: u32 = u32::from_le_bytes(*b"FXCF");

/// Bytes of the blob header.
pub const HEADER_LEN: usize = 16;

/// Bytes of a section's `tag | len` head.
pub const SECTION_HEAD_LEN: usize = 8;

/// Every section starts on this boundary from the blob's first byte.
pub const SECTION_ALIGN: usize = 8;

/// First byte the checksum covers: everything after `crc32` itself.
pub const CRC_START: usize = 12;

/// Section tags: four ASCII bytes, read as a little-endian u32.
pub mod tag {
    /// The graph: modules, edges, domains.
    pub const GRAPH: u32 = u32::from_le_bytes(*b"GRPH");
    /// The platform's hardware payload.
    pub const HARDWARE: u32 = u32::from_le_bytes(*b"HWRP");
    /// Resident workloads admitted at boot.
    pub const WORKLOADS: u32 = u32::from_le_bytes(*b"WKLD");
    /// The capacity envelope: each pool's live-add reserve.
    pub const ENVELOPE: u32 = u32::from_le_bytes(*b"ENVL");
    /// Declared demand: what the graph's modules will ask of each pool.
    pub const DEMAND: u32 = u32::from_le_bytes(*b"DMND");

    /// Every tag a blob may carry, each at most once.
    pub const ALL: [u32; 5] = [GRAPH, HARDWARE, WORKLOADS, ENVELOPE, DEMAND];
}

/// Bytes of the graph section's own header.
pub const GRAPH_HEAD_LEN: usize = 12;
/// Bytes of a module record before its params.
pub const MODULE_HEAD_LEN: usize = 12;
/// Bytes of one edge record.
pub const EDGE_LEN: usize = 12;
/// Bytes of one domain record.
pub const DOMAIN_LEN: usize = 8;
/// Bytes of one envelope or demand entry.
pub const POOL_ENTRY_LEN: usize = 6;
/// Bytes of a workload record before its FLXA blob.
pub const WORKLOAD_HEAD_LEN: usize = 5;

/// `graph_flags` bit: the author attests that the graph's cycles are
/// bidirectional feedback pairs, stepped in declaration order.
pub const GRAPH_FLAG_ACCEPT_CYCLES: u8 = 0x01;
const GRAPH_FLAGS_KNOWN: u8 = GRAPH_FLAG_ACCEPT_CYCLES;

/// Module `flags` bit: the module runs in its domain's pre-pass.
pub const MODULE_FLAG_PRE_PASS: u8 = 0x01;
const MODULE_FLAGS_KNOWN: u8 = MODULE_FLAG_PRE_PASS;

/// Edge `kind` bit: the edge ends on the consumer's control port.
const EDGE_KIND_TO_CTRL: u8 = 0x80;
/// The largest mailbox buffer group an edge names (5 bits; 0 = none).
pub const MAX_BUFFER_GROUP: u8 = 31;
/// The largest port index an edge names (4 bits).
pub const MAX_PORT_INDEX: u8 = 15;

/// Edge `flags` bit: a write on the edge wakes its consumer.
pub const EDGE_FLAG_WAKE_ON_WRITE: u8 = 0x01;
/// Edge `flags` bit: the consumer port keeps its own copy of what it sends.
pub const EDGE_FLAG_RETAINS_SEND: u8 = 0x02;
const EDGE_FLAGS_KNOWN: u8 = EDGE_FLAG_WAKE_ON_WRITE | EDGE_FLAG_RETAINS_SEND;

/// Domain `adaptive_flags` bit: demand-driven idle.
pub const ADAPTIVE_IDLE: u8 = 0x01;
/// Domain `adaptive_flags` bit: adaptive cadence.
pub const ADAPTIVE_CADENCE: u8 = 0x02;
const ADAPTIVE_FLAGS_KNOWN: u8 = ADAPTIVE_IDLE | ADAPTIVE_CADENCE;

/// Workload `flags` bit: the workload is attested idle-safe.
pub const WORKLOAD_FLAG_IDLE_SAFE: u8 = 0x01;
const WORKLOAD_FLAGS_KNOWN: u8 = WORKLOAD_FLAG_IDLE_SAFE;

// ── Records ─────────────────────────────────────────────────────────────────

/// One module of the graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModuleRecord<'a> {
    pub name_hash: u32,
    pub id: u16,
    pub domain: u8,
    pub pre_pass: bool,
    /// The module's params TLV, borrowed from wherever the record lives.
    pub params: &'a [u8],
}

/// What an edge's ring is, for placement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum EdgeClass {
    /// Same domain.
    #[default]
    Local = 0,
    /// The buffer is managed by a DMA controller.
    DmaOwned = 1,
    /// The edge joins modules in different domains.
    CrossCore = 2,
    /// A zero-copy NIC descriptor ring.
    NicRing = 3,
}

impl EdgeClass {
    const fn from_bits(bits: u8) -> Self {
        match bits & 0x03 {
            1 => Self::DmaOwned,
            2 => Self::CrossCore,
            3 => Self::NicRing,
            _ => Self::Local,
        }
    }
}

/// One edge of the graph.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EdgeRecord {
    pub from: u16,
    pub to: u16,
    /// Producer port index, 0..=15.
    pub from_port: u8,
    /// Consumer port index, 0..=15.
    pub to_port: u8,
    /// The edge ends on the consumer's control port rather than its input.
    pub to_ctrl: bool,
    pub class: EdgeClass,
    /// Mailbox buffer group, 0 (none) ..= 31.
    pub buffer_group: u8,
    /// Rate class (contracts `RateClass`).
    pub rate_class: u8,
    pub wake_on_write: bool,
    pub retains_send: bool,
    /// Requested ring bytes; 0 defers to the ports' capacities.
    pub buffer_bytes: u32,
}

/// How a domain's modules are stepped. Two families: cooperative (`Tick`,
/// `Poll`) with the full syscall surface, and interrupt (`Timer`, `Irq`)
/// with the bridge-only surface.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExecMode {
    /// One pass per tick.
    #[default]
    Tick = 0,
    /// Passes back to back, waiting for an event when idle.
    Poll = 1,
    /// Stepped at the domain's fixed cadence under the interrupt contract.
    Timer = 2,
    /// Each module's entry runs from its own interrupt.
    Irq = 3,
}

impl ExecMode {
    /// The mode a wire byte names, or `None` for a byte no mode has.
    #[must_use]
    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Tick),
            1 => Some(Self::Poll),
            2 => Some(Self::Timer),
            3 => Some(Self::Irq),
            _ => None,
        }
    }

    /// The mode's graph-config spelling (`exec:`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Tick => "tick",
            Self::Poll => "poll",
            Self::Timer => "timer",
            Self::Irq => "irq",
        }
    }

    /// The mode a graph-config spelling names.
    #[must_use]
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "tick" => Some(Self::Tick),
            "poll" => Some(Self::Poll),
            "timer" => Some(Self::Timer),
            "irq" => Some(Self::Irq),
            _ => None,
        }
    }

    /// Whether the mode runs its modules under the interrupt contract.
    #[must_use]
    pub const fn is_interrupt(self) -> bool {
        matches!(self, Self::Timer | Self::Irq)
    }
}

/// One execution domain.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DomainRecord {
    /// The domain's tick; 0 takes the graph's. A `Timer` domain's period.
    pub tick_us: u16,
    pub tick_min_us: u16,
    pub tick_max_us: u16,
    pub exec_mode: ExecMode,
    pub adaptive_flags: u8,
}

/// One envelope or demand entry: a resource pool and its count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolEntry {
    pub pool: u16,
    pub n: u32,
}

/// One resident workload: its admission flags and its FLXA blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkloadRecord<'a> {
    pub idle_safe: bool,
    pub blob: &'a [u8],
}

// ── Errors ──────────────────────────────────────────────────────────────────

/// Why a blob was refused. Each names what it found, so a boot log says which
/// section and which field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Fewer bytes than a header.
    Short {
        len: usize,
    },
    BadMagic {
        found: u32,
    },
    /// The header's reserved half-word is not zero.
    ReservedHeader,
    /// `total_len` is under a header, not a multiple of the section
    /// alignment, or past the bytes given.
    TotalLen {
        total_len: usize,
        available: usize,
    },
    Checksum {
        stored: u32,
        computed: u32,
    },
    UnknownSection {
        tag: u32,
        offset: usize,
    },
    DuplicateSection {
        tag: u32,
        offset: usize,
    },
    /// A section's head or payload runs past `total_len`.
    TruncatedSection {
        tag: u32,
        offset: usize,
    },
    /// A section's pad bytes are not zero.
    Padding {
        tag: u32,
        offset: usize,
    },
    /// Bytes remain inside `total_len` after `section_count` sections.
    TrailingBytes {
        offset: usize,
    },
    MissingGraph,
    /// A section's payload disagrees with its own counts or holds a value
    /// outside its field.
    Malformed {
        tag: u32,
        what: &'static str,
    },
}

impl DecodeError {
    /// A short name for the refusal, for a log line that carries no
    /// formatting machinery (a microcontroller kernel); [`Self::detail`]
    /// gives its numbers.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match *self {
            Self::Short { .. } => "short",
            Self::BadMagic { .. } => "magic",
            Self::ReservedHeader => "reserved",
            Self::TotalLen { .. } => "total_len",
            Self::Checksum { .. } => "checksum",
            Self::UnknownSection { .. } => "unknown section",
            Self::DuplicateSection { .. } => "repeated section",
            Self::TruncatedSection { .. } => "truncated section",
            Self::Padding { .. } => "padding",
            Self::TrailingBytes { .. } => "trailing bytes",
            Self::MissingGraph => "no GRPH",
            Self::Malformed { what, .. } => what,
        }
    }

    /// The refusal's two numbers: a tag, magic or stored checksum first,
    /// then an offset, length or computed checksum (0 where none applies).
    #[must_use]
    pub const fn detail(&self) -> (u32, usize) {
        match *self {
            Self::Short { len } => (0, len),
            Self::BadMagic { found } => (found, 0),
            Self::TotalLen { total_len, .. } => (0, total_len),
            Self::Checksum { stored, computed } => (stored, computed as usize),
            Self::UnknownSection { tag, offset }
            | Self::DuplicateSection { tag, offset }
            | Self::TruncatedSection { tag, offset }
            | Self::Padding { tag, offset } => (tag, offset),
            Self::TrailingBytes { offset } => (0, offset),
            Self::Malformed { tag, .. } => (tag, 0),
            Self::ReservedHeader | Self::MissingGraph => (0, 0),
        }
    }
}

/// The four ASCII bytes of a tag, for logs.
#[must_use]
pub const fn tag_bytes(tag: u32) -> [u8; 4] {
    tag.to_le_bytes()
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = |tag: u32| {
            let b = tag_bytes(tag);
            if b.iter().all(u8::is_ascii_graphic) {
                [b[0] as char, b[1] as char, b[2] as char, b[3] as char]
            } else {
                ['?'; 4]
            }
        };
        match *self {
            Self::Short { len } => write!(f, "blob of {len} bytes is shorter than its header"),
            Self::BadMagic { found } => write!(f, "bad magic {found:#010x}"),
            Self::ReservedHeader => write!(f, "header reserved field is not zero"),
            Self::TotalLen {
                total_len,
                available,
            } => write!(
                f,
                "total_len {total_len} does not fit the {available} bytes given"
            ),
            Self::Checksum { stored, computed } => {
                write!(
                    f,
                    "checksum mismatch stored={stored:#010x} computed={computed:#010x}"
                )
            }
            Self::UnknownSection { tag, offset } => {
                let n = name(tag);
                write!(
                    f,
                    "unknown section {tag:#010x} ({}{}{}{}) at {offset}",
                    n[0], n[1], n[2], n[3]
                )
            }
            Self::DuplicateSection { tag, offset } => {
                let n = name(tag);
                write!(
                    f,
                    "section {}{}{}{} repeated at {offset}",
                    n[0], n[1], n[2], n[3]
                )
            }
            Self::TruncatedSection { tag, offset } => {
                let n = name(tag);
                write!(
                    f,
                    "section {}{}{}{} at {offset} runs past total_len",
                    n[0], n[1], n[2], n[3]
                )
            }
            Self::Padding { tag, offset } => {
                let n = name(tag);
                write!(
                    f,
                    "section {}{}{}{} at {offset} has non-zero padding",
                    n[0], n[1], n[2], n[3]
                )
            }
            Self::TrailingBytes { offset } => write!(f, "bytes after the last section at {offset}"),
            Self::MissingGraph => write!(f, "no GRPH section"),
            Self::Malformed { tag, what } => {
                let n = name(tag);
                write!(f, "section {}{}{}{}: {what}", n[0], n[1], n[2], n[3])
            }
        }
    }
}

// ── Checksum ────────────────────────────────────────────────────────────────

/// CRC-32 (IEEE 802.3, reflected, polynomial 0xEDB88320), bitwise: no table,
/// so it costs a few dozen bytes of code on a microcontroller.
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

// ── Decode ──────────────────────────────────────────────────────────────────

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

const fn padded(len: usize) -> usize {
    len.next_multiple_of(SECTION_ALIGN)
}

/// A decoded blob: views into the bytes [`decode`] validated.
#[derive(Clone, Copy, Debug)]
pub struct BootConfig<'a> {
    total_len: usize,
    checksum: u32,
    graph: Graph<'a>,
    hardware: Option<&'a [u8]>,
    workloads: Option<Workloads<'a>>,
    envelope: Option<PoolEntries<'a>>,
    demand: Option<PoolEntries<'a>>,
}

impl<'a> BootConfig<'a> {
    /// Bytes the blob occupies, header to last pad byte.
    #[must_use]
    pub const fn total_len(&self) -> usize {
        self.total_len
    }

    /// The header's CRC-32, which [`decode`] verified.
    #[must_use]
    pub const fn checksum(&self) -> u32 {
        self.checksum
    }

    #[must_use]
    pub const fn graph(&self) -> &Graph<'a> {
        &self.graph
    }

    /// The `HWRP` payload, if the blob carries one.
    #[must_use]
    pub const fn hardware(&self) -> Option<&'a [u8]> {
        self.hardware
    }

    /// The resident workloads, if the blob carries a `WKLD` section.
    #[must_use]
    pub const fn workloads(&self) -> Option<Workloads<'a>> {
        self.workloads
    }

    /// The capacity envelope, if the blob carries an `ENVL` section.
    #[must_use]
    pub const fn envelope(&self) -> Option<PoolEntries<'a>> {
        self.envelope
    }

    /// The declared demand, if the blob carries a `DMND` section.
    #[must_use]
    pub const fn demand(&self) -> Option<PoolEntries<'a>> {
        self.demand
    }
}

/// The graph section.
#[derive(Clone, Copy, Debug)]
pub struct Graph<'a> {
    pub tick_us: u16,
    pub graph_sample_rate: u32,
    pub graph_flags: u8,
    module_count: u16,
    edge_count: u16,
    domain_count: u8,
    modules: &'a [u8],
    edges: &'a [u8],
    domains: &'a [u8],
}

impl<'a> Graph<'a> {
    #[must_use]
    pub const fn module_count(&self) -> u16 {
        self.module_count
    }

    #[must_use]
    pub const fn edge_count(&self) -> u16 {
        self.edge_count
    }

    #[must_use]
    pub const fn domain_count(&self) -> u8 {
        self.domain_count
    }

    /// Bytes of params across every module record.
    #[must_use]
    pub fn params_bytes(&self) -> usize {
        self.modules().map(|m| m.params.len()).sum()
    }

    /// The module records, in blob order.
    #[must_use]
    pub const fn modules(&self) -> Modules<'a> {
        Modules {
            bytes: self.modules,
            left: self.module_count,
        }
    }

    /// The edge records, in blob order.
    pub fn edges(&self) -> impl ExactSizeIterator<Item = EdgeRecord> + 'a {
        self.edges.chunks_exact(EDGE_LEN).map(read_edge)
    }

    /// The domain records, in domain-id order.
    pub fn domains(&self) -> impl ExactSizeIterator<Item = DomainRecord> + 'a {
        self.domains.chunks_exact(DOMAIN_LEN).map(read_domain)
    }
}

/// The module records of a validated graph section.
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
        let len = le32(self.bytes, 0) as usize;
        let (entry, rest) = self.bytes.split_at(len);
        self.bytes = rest;
        Some(ModuleRecord {
            name_hash: le32(entry, 4),
            id: le16(entry, 8),
            domain: entry[10],
            pre_pass: entry[11] & MODULE_FLAG_PRE_PASS != 0,
            params: &entry[MODULE_HEAD_LEN..],
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::from(self.left), Some(usize::from(self.left)))
    }
}

impl ExactSizeIterator for Modules<'_> {}

fn read_edge(r: &[u8]) -> EdgeRecord {
    let ports = r[4];
    let kind = r[5];
    let flags = r[7];
    EdgeRecord {
        from: le16(r, 0),
        to: le16(r, 2),
        from_port: ports >> 4,
        to_port: ports & 0x0F,
        to_ctrl: kind & EDGE_KIND_TO_CTRL != 0,
        class: EdgeClass::from_bits(kind >> 5),
        buffer_group: kind & 0x1F,
        rate_class: r[6],
        wake_on_write: flags & EDGE_FLAG_WAKE_ON_WRITE != 0,
        retains_send: flags & EDGE_FLAG_RETAINS_SEND != 0,
        buffer_bytes: le32(r, 8),
    }
}

fn read_domain(r: &[u8]) -> DomainRecord {
    DomainRecord {
        tick_us: le16(r, 0),
        tick_min_us: le16(r, 2),
        tick_max_us: le16(r, 4),
        // `decode_graph` refused every byte that names no mode.
        exec_mode: ExecMode::from_u8(r[6]).unwrap_or_default(),
        adaptive_flags: r[7],
    }
}

/// The resident workloads of a validated `WKLD` section.
#[derive(Clone, Copy, Debug)]
pub struct Workloads<'a> {
    count: u16,
    records: &'a [u8],
}

impl<'a> Workloads<'a> {
    #[must_use]
    pub const fn count(&self) -> u16 {
        self.count
    }

    /// The workloads, in blob order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = WorkloadRecord<'a>> + 'a {
        let mut bytes = self.records;
        (0..self.count).map(move |_| {
            let len = le32(bytes, 0) as usize;
            let flags = bytes[4];
            let (rec, rest) = bytes.split_at(WORKLOAD_HEAD_LEN + len);
            bytes = rest;
            WorkloadRecord {
                idle_safe: flags & WORKLOAD_FLAG_IDLE_SAFE != 0,
                blob: &rec[WORKLOAD_HEAD_LEN..],
            }
        })
    }
}

/// The entries of a validated `ENVL` or `DMND` section.
#[derive(Clone, Copy, Debug)]
pub struct PoolEntries<'a> {
    records: &'a [u8],
}

impl<'a> PoolEntries<'a> {
    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len() / POOL_ENTRY_LEN
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = PoolEntry> + 'a {
        self.records
            .chunks_exact(POOL_ENTRY_LEN)
            .map(|r| PoolEntry {
                pool: le16(r, 0),
                n: le32(r, 2),
            })
    }
}

/// Validate a blob and return views into it. `bytes` may run past the blob
/// (a mapped window); only `total_len` of it is read.
///
/// # Errors
/// The first thing that makes the blob unusable; see [`DecodeError`].
pub fn decode(bytes: &[u8]) -> Result<BootConfig<'_>, DecodeError> {
    if bytes.len() < HEADER_LEN {
        return Err(DecodeError::Short { len: bytes.len() });
    }
    let magic = le32(bytes, 0);
    if magic != MAGIC {
        return Err(DecodeError::BadMagic { found: magic });
    }
    let total_len = le32(bytes, 4) as usize;
    if total_len < HEADER_LEN || !total_len.is_multiple_of(SECTION_ALIGN) || total_len > bytes.len()
    {
        return Err(DecodeError::TotalLen {
            total_len,
            available: bytes.len(),
        });
    }
    let blob = &bytes[..total_len];
    let stored = le32(blob, 8);
    let computed = crc32(&blob[CRC_START..]);
    if stored != computed {
        return Err(DecodeError::Checksum { stored, computed });
    }
    let section_count = le16(blob, 12);
    if le16(blob, 14) != 0 {
        return Err(DecodeError::ReservedHeader);
    }

    let mut found: [Option<&[u8]>; tag::ALL.len()] = [None; tag::ALL.len()];
    let mut off = HEADER_LEN;
    for _ in 0..section_count {
        if off + SECTION_HEAD_LEN > total_len {
            return Err(DecodeError::TruncatedSection {
                tag: if off + 4 <= total_len {
                    le32(blob, off)
                } else {
                    0
                },
                offset: off,
            });
        }
        let t = le32(blob, off);
        let len = le32(blob, off + 4) as usize;
        let Some(slot) = tag::ALL.iter().position(|&k| k == t) else {
            return Err(DecodeError::UnknownSection {
                tag: t,
                offset: off,
            });
        };
        if found[slot].is_some() {
            return Err(DecodeError::DuplicateSection {
                tag: t,
                offset: off,
            });
        }
        let start = off + SECTION_HEAD_LEN;
        if len > total_len - start || padded(start + len) > total_len {
            return Err(DecodeError::TruncatedSection {
                tag: t,
                offset: off,
            });
        }
        let end = start + len;
        let next = padded(end);
        if blob[end..next].iter().any(|&b| b != 0) {
            return Err(DecodeError::Padding {
                tag: t,
                offset: off,
            });
        }
        found[slot] = Some(&blob[start..end]);
        off = next;
    }
    if off != total_len {
        return Err(DecodeError::TrailingBytes { offset: off });
    }

    let [graph, hardware, workloads, envelope, demand] = found;
    Ok(BootConfig {
        total_len,
        checksum: stored,
        graph: decode_graph(graph.ok_or(DecodeError::MissingGraph)?)?,
        hardware,
        workloads: workloads.map(decode_workloads).transpose()?,
        envelope: envelope
            .map(|p| decode_pool_entries(tag::ENVELOPE, p))
            .transpose()?,
        demand: demand
            .map(|p| decode_pool_entries(tag::DEMAND, p))
            .transpose()?,
    })
}

const fn malformed(tag: u32, what: &'static str) -> DecodeError {
    DecodeError::Malformed { tag, what }
}

fn decode_graph(p: &[u8]) -> Result<Graph<'_>, DecodeError> {
    let bad = |what| malformed(tag::GRAPH, what);
    if p.len() < GRAPH_HEAD_LEN {
        return Err(bad("shorter than its header"));
    }
    let module_count = le16(p, 0);
    let edge_count = le16(p, 2);
    let domain_count = p[4];
    let graph_flags = p[5];
    if graph_flags & !GRAPH_FLAGS_KNOWN != 0 {
        return Err(bad("unknown graph flag"));
    }
    let tick_us = le16(p, 6);
    let graph_sample_rate = le32(p, 8);

    let mut off = GRAPH_HEAD_LEN;
    for _ in 0..module_count {
        if p.len() - off < MODULE_HEAD_LEN {
            return Err(bad("module record past the section"));
        }
        let len = le32(p, off) as usize;
        if len < MODULE_HEAD_LEN || len > p.len() - off {
            return Err(bad("module record length out of range"));
        }
        if p[off + 11] & !MODULE_FLAGS_KNOWN != 0 {
            return Err(bad("unknown module flag"));
        }
        off += len;
    }
    let modules = &p[GRAPH_HEAD_LEN..off];

    let edges_len = usize::from(edge_count) * EDGE_LEN;
    let domains_len = usize::from(domain_count) * DOMAIN_LEN;
    if p.len() - off != edges_len + domains_len {
        return Err(bad("edge and domain records disagree with the counts"));
    }
    let edges = &p[off..off + edges_len];
    let domains = &p[off + edges_len..];
    if edges
        .chunks_exact(EDGE_LEN)
        .any(|r| r[7] & !EDGE_FLAGS_KNOWN != 0)
    {
        return Err(bad("unknown edge flag"));
    }
    if domains
        .chunks_exact(DOMAIN_LEN)
        .any(|r| r[7] & !ADAPTIVE_FLAGS_KNOWN != 0)
    {
        return Err(bad("unknown adaptive flag"));
    }
    if domains
        .chunks_exact(DOMAIN_LEN)
        .any(|r| ExecMode::from_u8(r[6]).is_none())
    {
        return Err(bad("unknown execution mode"));
    }
    Ok(Graph {
        tick_us,
        graph_sample_rate,
        graph_flags,
        module_count,
        edge_count,
        domain_count,
        modules,
        edges,
        domains,
    })
}

fn decode_workloads(p: &[u8]) -> Result<Workloads<'_>, DecodeError> {
    let bad = |what| malformed(tag::WORKLOADS, what);
    if p.len() < 2 {
        return Err(bad("shorter than its count"));
    }
    let count = le16(p, 0);
    let mut off = 2;
    for _ in 0..count {
        if p.len() - off < WORKLOAD_HEAD_LEN {
            return Err(bad("workload record past the section"));
        }
        let len = le32(p, off) as usize;
        if p[off + 4] & !WORKLOAD_FLAGS_KNOWN != 0 {
            return Err(bad("unknown workload flag"));
        }
        if len > p.len() - off - WORKLOAD_HEAD_LEN {
            return Err(bad("workload blob past the section"));
        }
        off += WORKLOAD_HEAD_LEN + len;
    }
    if off != p.len() {
        return Err(bad("bytes after the last workload"));
    }
    Ok(Workloads {
        count,
        records: &p[2..],
    })
}

fn decode_pool_entries(t: u32, p: &[u8]) -> Result<PoolEntries<'_>, DecodeError> {
    if p.len() < 2 || p.len() - 2 != usize::from(le16(p, 0)) * POOL_ENTRY_LEN {
        return Err(malformed(
            t,
            "entry count disagrees with the section length",
        ));
    }
    Ok(PoolEntries { records: &p[2..] })
}

// ── Encode ──────────────────────────────────────────────────────────────────

/// What [`encode`] builds a blob from.
#[derive(Clone, Copy, Debug, Default)]
pub struct BootConfigSpec<'a> {
    pub tick_us: u16,
    pub graph_sample_rate: u32,
    pub graph_flags: u8,
    pub modules: &'a [ModuleRecord<'a>],
    pub edges: &'a [EdgeRecord],
    pub domains: &'a [DomainRecord],
    /// The `HWRP` payload; `None` leaves the section out.
    pub hardware: Option<&'a [u8]>,
    /// `None` leaves the `WKLD` section out.
    pub workloads: Option<&'a [WorkloadRecord<'a>]>,
    /// `None` leaves the `ENVL` section out.
    pub envelope: Option<&'a [PoolEntry]>,
    /// `None` leaves the `DMND` section out.
    pub demand: Option<&'a [PoolEntry]>,
}

/// Why [`encode`] could not represent a spec: the field that does not fit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodeError(pub &'static str);

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "boot config: {} does not fit its field", self.0)
    }
}

#[cfg(feature = "alloc")]
fn count_u16(n: usize, what: &'static str) -> Result<u16, EncodeError> {
    u16::try_from(n).map_err(|_| EncodeError(what))
}

#[cfg(feature = "alloc")]
fn len_u32(n: usize, what: &'static str) -> Result<u32, EncodeError> {
    u32::try_from(n).map_err(|_| EncodeError(what))
}

/// Encode a spec. Sections are written in the order of [`tag::ALL`]; a
/// decoder accepts any order.
///
/// # Errors
/// A count, length or bit field that its slot cannot hold.
#[cfg(feature = "alloc")]
pub fn encode(spec: &BootConfigSpec<'_>) -> Result<Vec<u8>, EncodeError> {
    let mut sections: Vec<(u32, Vec<u8>)> = Vec::new();
    sections.push((tag::GRAPH, encode_graph(spec)?));
    if let Some(hw) = spec.hardware {
        sections.push((tag::HARDWARE, hw.to_vec()));
    }
    if let Some(w) = spec.workloads {
        sections.push((tag::WORKLOADS, encode_workloads(w)?));
    }
    if let Some(e) = spec.envelope {
        sections.push((tag::ENVELOPE, encode_pool_entries(e, "envelope entries")?));
    }
    if let Some(d) = spec.demand {
        sections.push((tag::DEMAND, encode_pool_entries(d, "demand entries")?));
    }

    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC.to_le_bytes());
    out.extend_from_slice(&[0; 8]); // total_len, crc32: filled below
    out.extend_from_slice(&count_u16(sections.len(), "section count")?.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    for (t, payload) in &sections {
        out.extend_from_slice(&t.to_le_bytes());
        out.extend_from_slice(&len_u32(payload.len(), "section length")?.to_le_bytes());
        out.extend_from_slice(payload);
        out.resize(padded(out.len()), 0);
    }
    let total = len_u32(out.len(), "total_len")?;
    out[4..8].copy_from_slice(&total.to_le_bytes());
    let crc = crc32(&out[CRC_START..]);
    out[8..12].copy_from_slice(&crc.to_le_bytes());
    Ok(out)
}

#[cfg(feature = "alloc")]
fn encode_graph(spec: &BootConfigSpec<'_>) -> Result<Vec<u8>, EncodeError> {
    if spec.graph_flags & !GRAPH_FLAGS_KNOWN != 0 {
        return Err(EncodeError("graph flags"));
    }
    let mut p = Vec::new();
    p.extend_from_slice(&count_u16(spec.modules.len(), "module count")?.to_le_bytes());
    p.extend_from_slice(&count_u16(spec.edges.len(), "edge count")?.to_le_bytes());
    p.push(u8::try_from(spec.domains.len()).map_err(|_| EncodeError("domain count"))?);
    p.push(spec.graph_flags);
    p.extend_from_slice(&spec.tick_us.to_le_bytes());
    p.extend_from_slice(&spec.graph_sample_rate.to_le_bytes());
    for m in spec.modules {
        let len = len_u32(MODULE_HEAD_LEN + m.params.len(), "module params")?;
        p.extend_from_slice(&len.to_le_bytes());
        p.extend_from_slice(&m.name_hash.to_le_bytes());
        p.extend_from_slice(&m.id.to_le_bytes());
        p.push(m.domain);
        p.push(if m.pre_pass { MODULE_FLAG_PRE_PASS } else { 0 });
        p.extend_from_slice(m.params);
    }
    for e in spec.edges {
        if e.from_port > MAX_PORT_INDEX || e.to_port > MAX_PORT_INDEX {
            return Err(EncodeError("edge port index"));
        }
        if e.buffer_group > MAX_BUFFER_GROUP {
            return Err(EncodeError("edge buffer group"));
        }
        p.extend_from_slice(&e.from.to_le_bytes());
        p.extend_from_slice(&e.to.to_le_bytes());
        p.push((e.from_port << 4) | e.to_port);
        p.push(
            if e.to_ctrl { EDGE_KIND_TO_CTRL } else { 0 } | ((e.class as u8) << 5) | e.buffer_group,
        );
        p.push(e.rate_class);
        p.push(
            if e.wake_on_write {
                EDGE_FLAG_WAKE_ON_WRITE
            } else {
                0
            } | if e.retains_send {
                EDGE_FLAG_RETAINS_SEND
            } else {
                0
            },
        );
        p.extend_from_slice(&e.buffer_bytes.to_le_bytes());
    }
    for d in spec.domains {
        if d.adaptive_flags & !ADAPTIVE_FLAGS_KNOWN != 0 {
            return Err(EncodeError("domain adaptive flags"));
        }
        p.extend_from_slice(&d.tick_us.to_le_bytes());
        p.extend_from_slice(&d.tick_min_us.to_le_bytes());
        p.extend_from_slice(&d.tick_max_us.to_le_bytes());
        p.push(d.exec_mode as u8);
        p.push(d.adaptive_flags);
    }
    Ok(p)
}

#[cfg(feature = "alloc")]
fn encode_workloads(w: &[WorkloadRecord<'_>]) -> Result<Vec<u8>, EncodeError> {
    let mut p = Vec::new();
    p.extend_from_slice(&count_u16(w.len(), "workload count")?.to_le_bytes());
    for r in w {
        p.extend_from_slice(&len_u32(r.blob.len(), "workload blob")?.to_le_bytes());
        p.push(if r.idle_safe {
            WORKLOAD_FLAG_IDLE_SAFE
        } else {
            0
        });
        p.extend_from_slice(r.blob);
    }
    Ok(p)
}

#[cfg(feature = "alloc")]
fn encode_pool_entries(e: &[PoolEntry], what: &'static str) -> Result<Vec<u8>, EncodeError> {
    let mut p = Vec::new();
    p.extend_from_slice(&count_u16(e.len(), what)?.to_le_bytes());
    for x in e {
        p.extend_from_slice(&x.pool.to_le_bytes());
        p.extend_from_slice(&x.n.to_le_bytes());
    }
    Ok(p)
}
