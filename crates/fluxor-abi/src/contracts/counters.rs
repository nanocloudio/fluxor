// Contract: counters — a cycle counter and instruction-cache hit and access
// counts, read by a module around a region of its own code.
//
// Layer: contracts (public, stable). Served by the kernel; reached by
// `grants = ["counters"]`.
//
// A node-wide instruction-cache count moves with every other owner's code,
// so the read is granted, not free. Both ops take `handle = -1` and answer
// one 16-byte record, little-endian.
//
// DESCRIBE — what this target's counters are:
//
//   [0]       present       PRESENT_CYCLES | PRESENT_ICACHE
//   [1]       cycles_clock  CLOCK_CORE | CLOCK_SYSTEM
//   [2]       icache_scope  SCOPE_NONE | SCOPE_CORE | SCOPE_NODE
//   [3]       0
//   [4..8]    cycles_hz     u32  CLOCK_CORE: the core clock at the time of
//                                the call; CLOCK_SYSTEM: the counter's rate
//   [8..16]   0
//
// READ — the counts:
//
//   [0]       present        as DESCRIBE
//   [1..4]    0
//   [4..8]    cycles         u32  wrapping; the calling core's
//   [8..12]   icache_hit     u32  wrapping; the calling core's totals when
//   [12..16]  icache_access  u32  the scope is SCOPE_CORE, the node's when
//                                 it is SCOPE_NODE
//
// Every count wraps: a caller subtracts two reads with wrapping arithmetic.
// An absent counter reads 0 with its bit clear.
//
// WHAT THE COUNTS INCLUDE is everything that ran on that core in the region
// (interrupts and kernel work too); with SCOPE_NODE, also the other cores
// and anything else reading through the cache. No attribution per module is
// claimed. The cost of a read is the caller's own to measure and subtract.

/// Contract id and opcode class.
pub const CLASS: u16 = super::super::registry::counters::ID;

/// What the target's counters are. `handle = -1`; `arg` out, one
/// `DESCRIBE_SIZE` record.
pub use super::super::registry::counters::DESCRIBE;

/// The counts. `handle = -1`; `arg` out, one `READ_SIZE` record.
pub use super::super::registry::counters::READ;

/// Record sizes.
pub const DESCRIBE_SIZE: usize = 16;
pub const READ_SIZE: usize = 16;

/// `present` bits.
pub const PRESENT_CYCLES: u8 = 0x01;
pub const PRESENT_ICACHE: u8 = 0x02;
const PRESENT_KNOWN: u8 = PRESENT_CYCLES | PRESENT_ICACHE;

/// `cycles_clock`: what a cycle is.
pub const CLOCK_CORE: u8 = 0;
pub const CLOCK_SYSTEM: u8 = 1;

/// `icache_scope`: whose instruction fetches the cache counts cover.
pub const SCOPE_NONE: u8 = 0;
pub const SCOPE_CORE: u8 = 1;
pub const SCOPE_NODE: u8 = 2;

/// Offsets shared by both records.
pub const OFF_PRESENT: usize = 0;
/// DESCRIBE offsets.
pub const OFF_CYCLES_CLOCK: usize = 1;
pub const OFF_ICACHE_SCOPE: usize = 2;
pub const OFF_DESCRIBE_RESERVED: usize = 3;
pub const OFF_CYCLES_HZ: usize = 4;
pub const OFF_DESCRIBE_TAIL: usize = 8;
/// READ offsets.
pub const OFF_READ_RESERVED: usize = 1;
pub const OFF_CYCLES: usize = 4;
pub const OFF_ICACHE_HIT: usize = 8;
pub const OFF_ICACHE_ACCESS: usize = 12;

/// A DESCRIBE answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Description {
    pub present: u8,
    pub cycles_clock: u8,
    pub icache_scope: u8,
    pub cycles_hz: u32,
}

impl Description {
    /// Whether the answer is one this contract admits: known bits and
    /// values, and a cache scope exactly when the cache counter is present.
    pub const fn is_valid(&self) -> bool {
        self.present & !PRESENT_KNOWN == 0
            && self.cycles_clock <= CLOCK_SYSTEM
            && self.icache_scope <= SCOPE_NODE
            && (self.present & PRESENT_ICACHE != 0) == (self.icache_scope != SCOPE_NONE)
    }
}

/// A READ answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reading {
    pub present: u8,
    pub cycles: u32,
    pub icache_hit: u32,
    pub icache_access: u32,
}

const fn u32_at(b: &[u8; 16], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// The DESCRIBE record for `d`, or `None` when it is not valid.
pub const fn encode_describe(d: &Description) -> Option<[u8; DESCRIBE_SIZE]> {
    if !d.is_valid() {
        return None;
    }
    let hz = d.cycles_hz.to_le_bytes();
    Some([
        d.present,
        d.cycles_clock,
        d.icache_scope,
        0,
        hz[0],
        hz[1],
        hz[2],
        hz[3],
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ])
}

/// Read a DESCRIBE record. `None` for a non-zero reserved byte or an answer
/// `Description::is_valid` refuses.
pub const fn decode_describe(b: &[u8; DESCRIBE_SIZE]) -> Option<Description> {
    if b[OFF_DESCRIBE_RESERVED] != 0 || u32_at(b, 8) != 0 || u32_at(b, 12) != 0 {
        return None;
    }
    let d = Description {
        present: b[OFF_PRESENT],
        cycles_clock: b[OFF_CYCLES_CLOCK],
        icache_scope: b[OFF_ICACHE_SCOPE],
        cycles_hz: u32_at(b, OFF_CYCLES_HZ),
    };
    if d.is_valid() {
        Some(d)
    } else {
        None
    }
}

/// The READ record for `r`, or `None` for an unknown `present` bit. An
/// absent counter is written as 0 whatever `r` holds.
pub const fn encode_read(r: &Reading) -> Option<[u8; READ_SIZE]> {
    if r.present & !PRESENT_KNOWN != 0 {
        return None;
    }
    let c = if r.present & PRESENT_CYCLES != 0 {
        r.cycles.to_le_bytes()
    } else {
        [0; 4]
    };
    let (h, a) = if r.present & PRESENT_ICACHE != 0 {
        (r.icache_hit.to_le_bytes(), r.icache_access.to_le_bytes())
    } else {
        ([0; 4], [0; 4])
    };
    Some([
        r.present, 0, 0, 0, c[0], c[1], c[2], c[3], h[0], h[1], h[2], h[3], a[0], a[1], a[2], a[3],
    ])
}

/// Read a READ record. `None` for an unknown `present` bit, a non-zero
/// reserved byte, or a count on a counter whose bit is clear.
pub const fn decode_read(b: &[u8; READ_SIZE]) -> Option<Reading> {
    let r = Reading {
        present: b[OFF_PRESENT],
        cycles: u32_at(b, OFF_CYCLES),
        icache_hit: u32_at(b, OFF_ICACHE_HIT),
        icache_access: u32_at(b, OFF_ICACHE_ACCESS),
    };
    if r.present & !PRESENT_KNOWN != 0
        || b[1] != 0
        || b[2] != 0
        || b[3] != 0
        || r.present & PRESENT_CYCLES == 0 && r.cycles != 0
        || r.present & PRESENT_ICACHE == 0 && (r.icache_hit != 0 || r.icache_access != 0)
    {
        return None;
    }
    Some(r)
}

const _: () = assert!(OFF_PRESENT == 0);
const _: () = assert!(OFF_PRESENT + 1 == OFF_CYCLES_CLOCK);
const _: () = assert!(OFF_CYCLES_CLOCK + 1 == OFF_ICACHE_SCOPE);
const _: () = assert!(OFF_ICACHE_SCOPE + 1 == OFF_DESCRIBE_RESERVED);
const _: () = assert!(OFF_DESCRIBE_RESERVED + 1 == OFF_CYCLES_HZ);
const _: () = assert!(OFF_CYCLES_HZ + 4 == OFF_DESCRIBE_TAIL);
const _: () = assert!(OFF_DESCRIBE_TAIL + 8 == DESCRIBE_SIZE);
const _: () = assert!(OFF_PRESENT + 1 == OFF_READ_RESERVED);
const _: () = assert!(OFF_READ_RESERVED + 3 == OFF_CYCLES);
const _: () = assert!(OFF_CYCLES + 4 == OFF_ICACHE_HIT);
const _: () = assert!(OFF_ICACHE_HIT + 4 == OFF_ICACHE_ACCESS);
const _: () = assert!(OFF_ICACHE_ACCESS + 4 == READ_SIZE);
