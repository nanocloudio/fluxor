//! Packet filter PIC module: the bare-metal enforcer of one `net.policy`
//! table in the frame path, or a static port filter.
//!
//! Sits between the NIC driver and `ip`, on the receive path and, when the
//! egress pair is wired, the transmit path:
//!
//!   nic.frames_rx → pkt_filter.frames_rx → [frames_tx] → ip.frames_rx
//!   ip.frames_tx  → pkt_filter.egress_rx → [egress_tx] → nic.frames_tx
//!
//! Frames are length-prefixed `[len:u16 LE][frame…]` on every port, the
//! convention between `ip` and the NIC drivers. A frame that is not IPv4
//! passes unjudged, as the tables are IPv4 only; a VLAN-tagged frame is
//! dropped in policy mode, since what it carries cannot be judged.
//!
//! # net.policy mode (`table`)
//!
//! The module enforces the named table. Every [`POLL_MS`] it polls the
//! store-wide generation (a zero-length READ) and, when it moved, re-reads
//! the table whole into a spare buffer, swapping it in only then, so a read
//! the store moved under never tears what is in force. It ATTACHes naming
//! the table — the binding that makes it the table's one enforcer — and
//! declares [`POLICY_BUF`] as the most of it this module holds, so the store
//! refuses a larger REPLACE (`E2BIG`); it re-issues ATTACH with the
//! generation it applied in full, so the table's READ state reports
//! ENFORCED only while what is in force here is what the store holds.
//!
//! **Fail closed.** A table larger than [`POLICY_BUF`] (stored before this
//! module bound) is enforced closed: every new flow is dropped (counted
//! `closed_dropped`) until a read of it fits, and nothing is reported
//! applied. The copy held before is never left in force in its place.
//!
//! **Stateful.** Verdicts are flows', by the contract's flow model
//! (`net::policy::flow`, `flows.rs`): a packet that matches a recorded flow
//! (either direction) passes on it; any other is new and is judged by the
//! shared evaluator (`net::policy::evaluate`, the same rules as the Linux
//! rendering) — an ACK without SYN that matches no flow is judged like any
//! first packet, so a default-deny table drops it. A passed first packet
//! records its flow (a TCP segment only when it may open one); a table full
//! of live flows refuses the new one: its packet is dropped and counted
//! (`flows_refused`). Rejected traffic is dropped: this module originates
//! nothing. An ICMP error whose embedded packet belongs to a recorded flow,
//! sent back to that packet's source, passes as related.
//!
//! The model needs both directions: with only the receive path wired, the
//! reply to a flow the node opened is new here, and is judged.
//!
//! **Fragments.** A datagram's first fragment carries its ports and is
//! judged as above; a later fragment passes only when the first fragment of
//! the same datagram (`src`, `dst`, protocol, identification) passed within
//! [`FRAG_MS`], and is otherwise dropped (counted `frag_dropped`). The most
//! recent [`FRAG_SLOTS`] fragmented datagrams are remembered.
//!
//! # Static mode (no `table`)
//!
//! A stateless port filter: each frame is judged on its own against up to
//! [`MAX_RULES`] rules (`rule_count`, `rule_0` … `rule_7`, each six bytes
//! `[action][proto][port_lo:u16 LE][port_hi:u16 LE]`, action 0 drop / 1
//! accept, proto 0 any, port 0 any, `port_hi` 0 the same as `port_lo`),
//! first match wins, else `default_action`.

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    dead_code,
    reason = "the PIC build mounts the whole of modules/sdk/* via include!, so every \
              module's compile sees the entire ABI surface while using a subset. This \
              allow is the SDK's textual mounting showing through"
)]
#![allow(
    unused_imports,
    reason = "same cause: the mounted SDK brings names this module does not reach for"
)]
#![allow(
    unreachable_patterns,
    reason = "defensive `_ => Error` arms in enum state-machine matches. The match is \
              exhaustive, which is why the lint fires; the arm exists so that adding a \
              variant cannot silently bypass the error path. #[expect] is not the \
              alternative — it fails the build in the configurations where the lint \
              does not fire"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

/// The shared hash index the flow table goes through.
mod index {
    include!("../../sdk/runtime/hash_index.rs");
}

mod flows;
mod params_def;

use abi::contracts::net::policy as np;
use np::flow as fm;

// ============================================================================
// Constants
// ============================================================================

/// Largest frame carried (an Ethernet frame with a VLAN tag, rounded).
const MAX_FRAME: usize = 1600;
pub const MAX_RULES: usize = 8;
/// How often the store-wide generation is polled: a table change takes
/// effect within this.
pub const POLL_MS: u32 = 100;
/// Rule bytes of the table this module holds: declared to the store at
/// ATTACH, so a larger REPLACE is refused.
pub const POLICY_BUF: usize = 4096;
/// Fragmented datagrams remembered at once, and how long a first fragment
/// admits the rest (the host's reassembly timeout).
pub const FRAG_SLOTS: usize = 8;
pub const FRAG_MS: u32 = 30_000;
/// The heap the flow table is sized into when the graph names none: room to
/// declare up to the most `max_flows` allows on aarch64, where the heap
/// commits only what is touched; the default table on MCU-class targets,
/// where it is committed whole.
#[cfg(target_arch = "aarch64")]
const HEAP_DEFAULT_BYTES: u32 = 4 * 1024 * 1024;
#[cfg(not(target_arch = "aarch64"))]
const HEAP_DEFAULT_BYTES: u32 = 4 * 1024;

const ERANGE: i32 = -34;
const ENOENT: i32 = -2;

const ACTION_DROP: u8 = 0;
const ACTION_ACCEPT: u8 = 1;

const ETH_HLEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88A8;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
struct FilterRule {
    action: u8,
    proto_match: u8,
    dst_port_lo: u16,
    dst_port_hi: u16,
    _reserved: u16,
}

impl FilterRule {
    const fn empty() -> Self {
        Self {
            action: ACTION_ACCEPT,
            proto_match: 0,
            dst_port_lo: 0,
            dst_port_hi: 0,
            _reserved: 0,
        }
    }
}

/// A fragmented datagram whose first fragment passed.
#[repr(C)]
#[derive(Clone, Copy)]
struct Frag {
    live: u8,
    proto: u8,
    id: u16,
    src: u32,
    dst: u32,
    last_ms: u32,
}

impl Frag {
    const EMPTY: Frag = Frag {
        live: 0,
        proto: 0,
        id: 0,
        src: 0,
        dst: 0,
        last_ms: 0,
    };
}

#[repr(C)]
pub struct FilterState {
    syscalls: *const SyscallTable,
    /// The receive path (in[0] → out[0]) and the transmit path (in[1] →
    /// out[1], -1 when not wired).
    rx_in: i32,
    rx_out: i32,
    tx_in: i32,
    tx_out: i32,

    // ---- static mode ----
    rule_count: u8,
    default_action: u8,
    /// `max_flows` (param): the flow table's records.
    max_flows: u16,
    rules: [FilterRule; MAX_RULES],

    // ---- counters ----
    accepted: u32,
    dropped: u32,
    /// New flows refused: the table held no free record.
    flows_refused: u32,
    flows_expired: u32,
    /// Later fragments of a datagram whose first fragment did not pass.
    frag_dropped: u32,
    /// IPv4 frames whose headers do not hold together.
    malformed: u32,
    /// New flows dropped while the table is enforced closed.
    closed_dropped: u32,
    /// Frames dropped because the next stage had no room.
    dropped_full: u32,
    flows_live: u32,

    // ---- net.policy mode ----
    table: [u8; np::MAX_TABLE_NAME],
    table_len: u8,
    attached: u8,
    /// Which buffer is in force; a read lands in the other.
    live: u8,
    /// The store holds more of the table than [`POLICY_BUF`]: enforced
    /// closed.
    closed: bool,
    len: u16,
    _pad: u16,
    polled_ms: u32,
    /// The table generation held (0: none).
    generation: u64,
    /// The store-wide generation last seen; the table is re-read only when
    /// it moves.
    store_gen: u64,
    /// The generation last reported to ATTACH as applied.
    reported: u64,

    // ---- the flow table (`flows.rs`) ----
    seed: u32,
    flow_index_len: u32,
    flow_free_top: u32,
    flow_sweep: u32,
    flows: *mut flows::Flow,
    flow_free: *mut u16,
    flow_index: *mut u32,
    frags: [Frag; FRAG_SLOTS],

    /// Frame staging (length prefix + frame), in state so `module_step`'s
    /// frame stays small.
    frame_buf: [u8; 2 + MAX_FRAME],
    bufs: [[u8; POLICY_BUF]; 2],
}

const STATE_SIZE: usize = core::mem::size_of::<FilterState>();

/// The table in force.
fn held(s: &FilterState) -> &[u8] {
    match s.bufs.get((s.live & 1) as usize) {
        Some(b) => b.get(..s.len as usize).unwrap_or(&[]),
        None => &[],
    }
}

/// Write `v` little-endian at `arg[at..]`, panic-free.
fn put_le(arg: &mut [u8], at: usize, v: u64, n: usize) {
    let b = v.to_le_bytes();
    let mut i = 0;
    while i < n && i < 8 {
        if let Some(d) = arg.get_mut(at + i) {
            *d = b[i];
        }
        i += 1;
    }
}

fn get_u64(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    let mut i = 0;
    while i < 8 {
        v[i] = b.get(at + i).copied().unwrap_or(0);
        i += 1;
    }
    u64::from_le_bytes(v)
}

// ============================================================================
// net.policy: reading and attaching
// ============================================================================

/// READ `name_len` bytes of `s.table` (0: the store) into `out` (`cap`
/// bytes); the state record lands in `state`.
unsafe fn np_read(
    s: &FilterState,
    name_len: usize,
    out: *mut u8,
    cap: usize,
    state: &mut [u8; np::state::BYTES],
) -> i32 {
    let mut arg = [0u8; 1 + np::MAX_TABLE_NAME + 8 + 4 + 8];
    arg[0] = name_len as u8;
    let mut i = 0;
    while i < name_len && i < np::MAX_TABLE_NAME {
        if let (Some(d), Some(c)) = (arg.get_mut(1 + i), s.table.get(i)) {
            *d = *c;
        }
        i += 1;
    }
    let p = 1 + name_len;
    put_le(&mut arg, p, out as u64, 8);
    put_le(&mut arg, p + 8, cap as u64, 4);
    put_le(&mut arg, p + 12, state.as_mut_ptr() as u64, 8);
    ((*s.syscalls).provider_call)(-1, np::READ, arg.as_mut_ptr(), p + 20)
}

/// ATTACH naming the table, reporting `applied` and declaring
/// [`POLICY_BUF`] as the most of it held.
unsafe fn np_attach(s: &FilterState, applied: u64) -> i32 {
    let mut arg = [0u8; 1 + np::MAX_TABLE_NAME + np::ATTACH_TAIL + np::ATTACH_CAPACITY_TAIL];
    let nl = (s.table_len as usize).min(np::MAX_TABLE_NAME);
    arg[0] = nl as u8 | np::ATTACH_CAPACITY;
    let mut i = 0;
    while i < nl {
        if let (Some(d), Some(c)) = (arg.get_mut(1 + i), s.table.get(i)) {
            *d = *c;
        }
        i += 1;
    }
    put_le(&mut arg, 1 + nl, applied, 8);
    put_le(&mut arg, 1 + nl + np::ATTACH_TAIL, POLICY_BUF as u64, 4);
    let len = 1 + nl + np::ATTACH_TAIL + np::ATTACH_CAPACITY_TAIL;
    ((*s.syscalls).provider_call)(-1, np::ATTACH, arg.as_mut_ptr(), len)
}

/// Poll the store-wide generation; re-read the table when it moved, and
/// report what was applied.
unsafe fn refresh_policy(s: &mut FilterState) {
    let mut state = [0u8; np::state::BYTES];
    if np_read(s, 0, core::ptr::null_mut(), 0, &mut state) == 0 {
        let g = get_u64(&state, np::state::GENERATION);
        if g == s.store_gen && s.attached != 0 {
            return;
        }
        s.store_gen = g;
    }
    let spare = ((s.live ^ 1) & 1) as usize;
    let out = match s.bufs.get_mut(spare) {
        Some(b) => b.as_mut_ptr(),
        None => return,
    };
    let n = np_read(s, s.table_len as usize, out, POLICY_BUF, &mut state);
    let gen = get_u64(&state, np::state::GENERATION);
    let applied = if n >= 0 {
        if gen != s.generation || s.closed {
            // The whole table landed in the spare buffer: swap it in.
            s.live = spare as u8;
            s.len = n as u16;
            s.generation = gen;
            s.closed = false;
            gen
        } else {
            s.reported
        }
    } else if n == ENOENT {
        // No such table: nothing to enforce, so nothing is filtered.
        s.len = 0;
        s.closed = false;
        s.generation = 0;
        0
    } else if n == ERANGE {
        // Too big to hold: enforced closed, never by the copy held before
        // (a policy the store no longer has). Nothing is applied.
        s.len = 0;
        s.closed = true;
        s.generation = gen;
        0
    } else {
        // A busy store (EAGAIN) or no provider: keep what is held — it is
        // not this generation, so it is not reported applied — and read the
        // table again at the next poll whatever the store-wide generation
        // says.
        s.store_gen = u64::MAX;
        s.reported
    };
    if s.attached == 0 || applied != s.reported {
        // EBUSY (another enforcer holds the table) leaves this module
        // unbound: its filtering still runs, but vouches for nothing.
        if np_attach(s, applied) == 0 {
            s.attached = 1;
            s.reported = applied;
        }
    }
}

// ============================================================================
// Judging a frame
// ============================================================================

#[inline(always)]
fn b8(f: &[u8], i: usize) -> u8 {
    f.get(i).copied().unwrap_or(0)
}
#[inline(always)]
fn b16(f: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b8(f, i), b8(f, i + 1)])
}
#[inline(always)]
fn b32(f: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b8(f, i), b8(f, i + 1), b8(f, i + 2), b8(f, i + 3)])
}

/// An IPv4 packet's header fields, from the frame.
#[derive(Clone, Copy)]
struct Ip4 {
    proto: u8,
    src: u32,
    dst: u32,
    id: u16,
    more_frags: bool,
    frag_off: u16,
    /// Where the L4 header starts in the frame, and its bytes.
    l4: usize,
    l4_len: usize,
}

/// The IPv4 header at `at`, when it holds together within `f`.
fn ip4_at(f: &[u8], at: usize) -> Option<Ip4> {
    let v = b8(f, at);
    let ihl = ((v & 0x0F) as usize) * 4;
    if v >> 4 != 4 || ihl < 20 || at + ihl > f.len() {
        return None;
    }
    let total = b16(f, at + 2) as usize;
    if total < ihl || at + total > f.len() {
        return None;
    }
    let fw = b16(f, at + 6);
    Some(Ip4 {
        proto: b8(f, at + 9),
        src: b32(f, at + 12),
        dst: b32(f, at + 16),
        id: b16(f, at + 4),
        more_frags: fw & 0x2000 != 0,
        frag_off: fw & 0x1FFF,
        l4: at + ihl,
        l4_len: total - ihl,
    })
}

/// What one IPv4 packet is, for the flow table and the evaluator.
struct Seen {
    /// Its flow key, or None for a packet that opens no flow and matches
    /// none (an ICMP message that is neither a query nor its answer).
    tuple: Option<flows::Tuple>,
    /// What the evaluator judges.
    packet: np::Packet,
    /// TCP flags (0 otherwise).
    tcp_flags: u8,
    /// An ICMP query (it opens a flow; its answer does not).
    icmp_request: bool,
    /// An ICMP error's embedded packet, as the flow it would belong to.
    related: Option<flows::Tuple>,
}

/// Classify the IPv4 packet `ip` of frame `f`; None when its L4 header is
/// cut short.
fn classify(f: &[u8], ip: &Ip4) -> Option<Seen> {
    let mut seen = Seen {
        tuple: None,
        packet: np::Packet {
            src: ip.src,
            dst: ip.dst,
            proto: ip.proto,
            dport: 0,
        },
        tcp_flags: 0,
        icmp_request: false,
        related: None,
    };
    let key = |sport: u16, dport: u16| flows::Tuple {
        proto: ip.proto,
        src: ip.src,
        dst: ip.dst,
        sport,
        dport,
    };
    match ip.proto {
        np::rule::PROTO_TCP => {
            if ip.l4_len < 20 {
                return None;
            }
            let (sp, dp) = (b16(f, ip.l4), b16(f, ip.l4 + 2));
            seen.packet.dport = dp;
            seen.tcp_flags = b8(f, ip.l4 + 13);
            seen.tuple = Some(key(sp, dp));
        }
        np::rule::PROTO_UDP => {
            if ip.l4_len < 8 {
                return None;
            }
            let (sp, dp) = (b16(f, ip.l4), b16(f, ip.l4 + 2));
            seen.packet.dport = dp;
            seen.tuple = Some(key(sp, dp));
        }
        np::rule::PROTO_ICMP => {
            if ip.l4_len < 8 {
                return None;
            }
            let t = b8(f, ip.l4);
            let id = b16(f, ip.l4 + 4);
            if fm::icmp_request(t) {
                seen.tuple = Some(key(id, 0));
                seen.icmp_request = true;
            } else if fm::icmp_reply(t) {
                seen.tuple = Some(key(0, id));
            } else if fm::icmp_error(t) {
                seen.related = embedded(f, ip);
            }
        }
        _ => seen.tuple = Some(key(0, 0)),
    }
    Some(seen)
}

/// The flow an ICMP error's embedded packet would belong to: it travelled
/// from `inner.src` to `inner.dst`, and the error goes back to its source.
fn embedded(f: &[u8], ip: &Ip4) -> Option<flows::Tuple> {
    let inner = ip4_at_loose(f, ip.l4 + 8)?;
    if inner.src != ip.dst {
        return None;
    }
    let l4 = inner.l4;
    let (sport, dport) = match inner.proto {
        np::rule::PROTO_TCP | np::rule::PROTO_UDP => (b16(f, l4), b16(f, l4 + 2)),
        np::rule::PROTO_ICMP => {
            let t = b8(f, l4);
            let id = b16(f, l4 + 4);
            if fm::icmp_request(t) {
                (id, 0)
            } else if fm::icmp_reply(t) {
                (0, id)
            } else {
                return None;
            }
        }
        _ => (0, 0),
    };
    if l4 + 8 > f.len() {
        return None;
    }
    Some(flows::Tuple {
        proto: inner.proto,
        src: inner.src,
        dst: inner.dst,
        sport,
        dport,
    })
}

/// An embedded IPv4 header: its own length must fit, but its total length
/// is the original packet's, which the error carries only the start of.
fn ip4_at_loose(f: &[u8], at: usize) -> Option<Ip4> {
    let v = b8(f, at);
    let ihl = ((v & 0x0F) as usize) * 4;
    if v >> 4 != 4 || ihl < 20 || at + ihl > f.len() {
        return None;
    }
    Some(Ip4 {
        proto: b8(f, at + 9),
        src: b32(f, at + 12),
        dst: b32(f, at + 16),
        id: b16(f, at + 4),
        more_frags: false,
        frag_off: 0,
        l4: at + ihl,
        l4_len: f.len() - (at + ihl),
    })
}

/// Whether the first fragment of `ip`'s datagram passed (refreshing it).
fn frag_admitted(s: &mut FilterState, ip: &Ip4, now: u32) -> bool {
    let mut i = 0;
    while i < FRAG_SLOTS {
        if let Some(r) = s.frags.get_mut(i) {
            if r.live != 0
                && r.proto == ip.proto
                && r.id == ip.id
                && r.src == ip.src
                && r.dst == ip.dst
                && now.wrapping_sub(r.last_ms) < FRAG_MS
            {
                r.last_ms = now;
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Remember that `ip`'s first fragment passed: in a free or expired slot,
/// else in the one least recently used.
fn frag_note(s: &mut FilterState, ip: &Ip4, now: u32) {
    let mut pick = 0usize;
    let mut oldest = 0u32;
    let mut i = 0;
    while i < FRAG_SLOTS {
        if let Some(r) = s.frags.get(i) {
            let age = now.wrapping_sub(r.last_ms);
            if r.live == 0 || age >= FRAG_MS {
                pick = i;
                break;
            }
            if age >= oldest {
                oldest = age;
                pick = i;
            }
        }
        i += 1;
    }
    if let Some(r) = s.frags.get_mut(pick) {
        *r = Frag {
            live: 1,
            proto: ip.proto,
            id: ip.id,
            src: ip.src,
            dst: ip.dst,
            last_ms: now,
        };
    }
}

/// The policy verdict on the frame in `f`: pass or drop. Moves the flow
/// table.
unsafe fn judge_policy(s: &mut FilterState, f: &[u8], now: u32) -> bool {
    if f.len() < ETH_HLEN {
        s.malformed = s.malformed.wrapping_add(1);
        return false;
    }
    match b16(f, 12) {
        ETHERTYPE_IPV4 => {}
        ETHERTYPE_VLAN | ETHERTYPE_QINQ => return false,
        _ => return true,
    }
    let Some(ip) = ip4_at(f, ETH_HLEN) else {
        s.malformed = s.malformed.wrapping_add(1);
        return false;
    };
    if ip.frag_off != 0 {
        // A later fragment: no ports to judge it by.
        if frag_admitted(s, &ip, now) {
            return true;
        }
        s.frag_dropped = s.frag_dropped.wrapping_add(1);
        return false;
    }
    let Some(seen) = classify(f, &ip) else {
        s.malformed = s.malformed.wrapping_add(1);
        return false;
    };
    // Part of a recorded flow: passes on it.
    if let Some(t) = &seen.tuple {
        if let Some((i, reply)) = flows::find(s, t, now) {
            if flows::note(s, i, reply, seen.tcp_flags, now) {
                return true;
            }
        }
    }
    if let Some(t) = &seen.related {
        if flows::find(s, t, now).is_some() {
            return true;
        }
    }
    // New: judged.
    if s.closed {
        s.closed_dropped = s.closed_dropped.wrapping_add(1);
        return false;
    }
    if np::evaluate(held(s), &seen.packet) != np::Verdict::Accept {
        return false;
    }
    if let Some(t) = &seen.tuple {
        let opens = if t.proto == np::rule::PROTO_TCP {
            fm::tcp_opens(seen.tcp_flags)
        } else if t.proto == np::rule::PROTO_ICMP {
            // Only a query opens a flow; an answer with none was judged.
            if seen.icmp_request {
                Some(0)
            } else {
                None
            }
        } else {
            Some(0)
        };
        if let Some(state) = opens {
            if !flows::make(s, t, state, now) {
                return false;
            }
        }
    }
    if ip.more_frags {
        frag_note(s, &ip, now);
    }
    true
}

/// The static rules' verdict on the frame in `f`.
fn judge_static(s: &FilterState, f: &[u8]) -> bool {
    if s.rule_count == 0 {
        return s.default_action != ACTION_DROP;
    }
    let (proto, dport) = match (b16(f, 12) == ETHERTYPE_IPV4)
        .then(|| ip4_at(f, ETH_HLEN))
        .flatten()
    {
        Some(ip)
            if ip.frag_off == 0
                && (ip.proto == np::rule::PROTO_TCP || ip.proto == np::rule::PROTO_UDP)
                && ip.l4_len >= 4 =>
        {
            (ip.proto, b16(f, ip.l4 + 2))
        }
        Some(ip) => (ip.proto, 0),
        None => (0, 0),
    };
    let mut i = 0usize;
    while i < s.rule_count as usize && i < MAX_RULES {
        if let Some(r) = s.rules.get(i) {
            let proto_ok = r.proto_match == 0 || r.proto_match == proto;
            let port_ok = r.dst_port_lo == 0 || (dport >= r.dst_port_lo && dport <= r.dst_port_hi);
            if proto_ok && port_ok {
                return r.action == ACTION_ACCEPT;
            }
        }
        i += 1;
    }
    s.default_action != ACTION_DROP
}

// ============================================================================
// Frame paths
// ============================================================================

/// Move one frame from `input` to `output`, judged. Whether a frame was
/// read.
unsafe fn pass_one(s: &mut FilterState, input: i32, output: i32, now: u32) -> bool {
    let sys = &*s.syscalls;
    if input < 0 || output < 0 {
        return false;
    }
    let poll = (sys.channel_poll)(input, POLL_IN);
    if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
        return false;
    }
    let buf = s.frame_buf.as_mut_ptr();
    if (sys.channel_read)(input, buf, 2) < 2 {
        return false;
    }
    let len = (*buf as usize) | ((*buf.add(1) as usize) << 8);
    if len == 0 || len > MAX_FRAME {
        s.malformed = s.malformed.wrapping_add(1);
        return true;
    }
    if (sys.channel_read)(input, buf.add(2), len) < len as i32 {
        s.malformed = s.malformed.wrapping_add(1);
        return true;
    }
    let frame = core::slice::from_raw_parts(buf.add(2) as *const u8, len);
    let pass = if s.table_len > 0 {
        judge_policy(s, frame, now)
    } else {
        judge_static(s, frame)
    };
    if !pass {
        s.dropped = s.dropped.wrapping_add(1);
        return true;
    }
    let p = (sys.channel_poll)(output, POLL_OUT);
    if p > 0 && (p as u32 & POLL_OUT) != 0 {
        (sys.channel_write)(output, buf as *const u8, 2 + len);
        s.accepted = s.accepted.wrapping_add(1);
    } else {
        // The next stage is full: dropped, as the medium below drops.
        s.dropped_full = s.dropped_full.wrapping_add(1);
    }
    true
}

// ============================================================================
// Module ABI
// ============================================================================

declare_module_state_bytes!(FilterState);
declare_module_arena_bytes!(HEAP_DEFAULT_BYTES);

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    STATE_SIZE
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_arena_size"]
pub extern "C" fn module_arena_size() -> u32 {
    HEAP_DEFAULT_BYTES
}

/// # Safety
/// Kernel module-ABI entry point: `syscalls` is the kernel's syscall table,
/// valid for the module's lifetime.
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes (zeroed), `syscalls` the kernel's syscall table,
/// and `params` the config TLV blob of `params_len` bytes (may be null when
/// it is empty).
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    _state_size: usize,
    syscalls: *const SyscallTable,
) -> i32 {
    // SAFETY: the loader hands a live, aligned, zeroed block of at least
    // `size_of::<FilterState>()`, exclusive to this module for the call.
    let s = unsafe { &mut *(state as *mut FilterState) };
    s.syscalls = syscalls;
    s.rx_in = in_chan;
    s.rx_out = out_chan;
    let mut i = 0;
    while i < MAX_RULES {
        if let Some(r) = s.rules.get_mut(i) {
            *r = FilterRule::empty();
        }
        i += 1;
    }
    // SAFETY: `params` is the loader-supplied blob of `params_len` bytes,
    // and `parse_tlv` reads only within it (and applies the defaults).
    unsafe { params_def::parse_tlv(s, params, params_len) };
    // SAFETY: `syscalls` is the loader's live table.
    let sys = unsafe { &*syscalls };
    // The transmit path, when the graph wires it.
    // SAFETY: as above.
    s.tx_in = unsafe { dev_channel_port(sys, 0, 1) };
    // SAFETY: as above.
    s.tx_out = unsafe { dev_channel_port(sys, 1, 1) };
    if s.tx_in < 0 || s.tx_out < 0 {
        s.tx_in = -1;
        s.tx_out = -1;
    }
    if s.table_len > 0 {
        let mut seed = [0u8; 4];
        // SAFETY: a 4-byte buffer of ours.
        if unsafe { dev_csprng_fill(sys, seed.as_mut_ptr(), 4) } < 0 {
            // SAFETY: as above.
            let t = unsafe { dev_millis(sys) } as u32;
            seed = (t ^ 0x9e37_79b9).to_le_bytes();
        }
        s.seed = u32::from_le_bytes(seed);
        // SAFETY: the heap is this module's, sized by `module_arena_size`
        // or the graph's `heap.arena_bytes`.
        if !unsafe { flows::size(s) } {
            let msg = b"[pkt_filter] refusing to construct: the heap cannot hold the flow table (max_flows)";
            // SAFETY: a static message.
            unsafe { dev_log(sys, 1, msg.as_ptr(), msg.len()) };
            return -1;
        }
    }
    0
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut FilterState);
    let sys = &*s.syscalls;
    let now = dev_millis(sys) as u32;
    if s.table_len > 0 {
        if s.polled_ms == 0 || now.wrapping_sub(s.polled_ms) >= POLL_MS {
            s.polled_ms = if now == 0 { 1 } else { now };
            refresh_policy(s);
        }
        flows::step(s, now);
    }
    let rx = pass_one(s, s.rx_in, s.rx_out, now);
    let tx = pass_one(s, s.tx_in, s.tx_out, now);
    if rx || tx {
        2 // Burst: more frames are likely queued.
    } else {
        0
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/runtime/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/runtime/wasm_entry.rs");

// ============================================================================
// Host-test API: the counters, read from the instance block, so
// `tests/harness/tests/pkt_filter.rs` drives the real entry points and checks
// what the module decided. Never compiled into the PIC firmware.
// ============================================================================

/// The module's counters.
#[cfg(feature = "host-test")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub accepted: u32,
    pub dropped: u32,
    pub flows_refused: u32,
    pub flows_expired: u32,
    pub frag_dropped: u32,
    pub malformed: u32,
    pub closed_dropped: u32,
    pub flows_live: u32,
    pub closed: bool,
}

/// # Safety
/// `state` is an instance block `module_new` initialised.
#[cfg(feature = "host-test")]
pub unsafe fn counters(state: *const u8) -> Counters {
    let s = &*(state as *const FilterState);
    Counters {
        accepted: s.accepted,
        dropped: s.dropped,
        flows_refused: s.flows_refused,
        flows_expired: s.flows_expired,
        frag_dropped: s.frag_dropped,
        malformed: s.malformed,
        closed_dropped: s.closed_dropped,
        flows_live: s.flows_live,
        closed: s.closed,
    }
}
