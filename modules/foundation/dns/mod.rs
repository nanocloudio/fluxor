//! DNS Server PIC Module
//!
//! Resolves configured hostnames locally, forwards everything else to an
//! upstream DNS server (default 8.8.8.8).
//!
//! # Supported profile
//!
//! Exactly one question per query (`QDCOUNT == 1`), opcode 0. A local answer is
//! constructed from the query header plus that question; nothing trailing the
//! question is echoed back.
//!
//! # Forwarding correlation
//!
//! A forwarded query carries a CSPRNG-drawn upstream transaction id, never the
//! client's own — two clients that pick the same id stay distinct
//! conversations, and an off-path guess must also match the rest of the tuple.
//! The pending slot retains the client id and endpoint, the upstream endpoint,
//! the question (QNAME hash, QTYPE, QCLASS), the opcode, and a deadline; an
//! answer is relayed only after reproducing all of them, and the slot is
//! consumed as it is relayed so a duplicate cannot re-fire. Only free or
//! expired slots are taken: with every slot live the NEW query is answered
//! SERVFAIL rather than displacing work already accepted.
//!
//! # Architecture
//!
//! Uses the datagram surface
//! (see `modules/sdk/contracts/net/datagram.rs` and
//! `docs/architecture/protocol_surfaces.md`) over the shared `net_in`/
//! `net_out` channel pair on the IP module:
//!
//! - **Server endpoint** — `CMD_DG_BIND` on port 53 allocates `server_ep`;
//!   inbound client queries arrive as `MSG_DG_RX_FROM` carrying the client
//!   address; replies go out as `CMD_DG_SEND_TO` to the captured client
//!   address.
//! - **Upstream endpoint** — `CMD_DG_BIND` on port 0 (ephemeral) allocates
//!   `upstream_ep`; forwarded queries go out as `CMD_DG_SEND_TO` to the
//!   upstream DNS server; upstream responses arrive as `MSG_DG_RX_FROM`.
//!
//! Frames share the 3-byte TLV header with net_proto, but datagram
//! opcodes (`0x20..0x43`) are disjoint from net_proto's (`0x01..0x13`) so
//! a shared `net_out` channel can carry both contracts unambiguously.
//!
//! # Parameters
//!
//! | Tag | Name     | Type | Default    | Description                    |
//! |-----|----------|------|------------|--------------------------------|
//! | 1   | upstream | u32  | 0x08080808 | Upstream DNS IP (LE)           |
//! | 2   | host     | str  | (none)     | "hostname=ip" (repeatable)     |
//! | 3   | ttl      | u32  | 300        | TTL for local responses (sec)  |
//! | 4   | port     | u16  | 53         | Listen port                    |

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset. unreachable_patterns: defensive `_ => Error` arms in enum state-machine matches are intentional — adding a new variant should not silently bypass the error path"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");
// Bound-endpoint bind lifecycle + addressed send, shared with log_net /
// transport_buffer / quic / dtls. dns composes two: server (port 53) + upstream
// (ephemeral), demuxed by ep_id on one channel.
include!("../../sdk/cores/datagram_endpoint.rs");

// ============================================================================
// Constants
// ============================================================================

/// DNS protocol constants
const DNS_HEADER_LEN: usize = 12;
const DNS_MAX_PACKET: usize = 512;

/// DNS record types
const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;
const QTYPE_PTR: u16 = 12;
const QCLASS_IN: u16 = 1;

/// DNS flags
const FLAG_QR: u16 = 0x8000; // Response
const FLAG_AA: u16 = 0x0400; // Authoritative
const FLAG_RA: u16 = 0x0080; // Recursion available
const FLAG_RD: u16 = 0x0100; // Recursion desired
const RCODE_NXDOMAIN: u16 = 0x0003;
const RCODE_SERVFAIL: u16 = 0x0002;

/// Opcode field of the DNS header flags word (bits 11..14).
const FLAG_OPCODE_MASK: u16 = 0x7800;
const FLAG_OPCODE_SHIFT: u32 = 11;

/// Only opcode 0 (standard query) is served or forwarded.
const OPCODE_QUERY: u8 = 0;

// datagram opcodes / DG_V4_PREFIX / DG_AF_INET come from
// modules/sdk/runtime.rs (shared across consumers).

/// Net buffer size (frame header + ep_id + addressing + DNS packet)
const NET_BUF_SIZE: usize = 600;

/// Maximum local host entries
const MAX_HOSTS: usize = 16;

/// Maximum pending upstream queries
const MAX_PENDING: usize = 8;

/// Pending query timeout (milliseconds)
const PENDING_TIMEOUT_MS: u32 = 5000;

/// Maximum dotted domain name length, in bytes. This is the DNS full-name
/// ceiling (RFC 1035 §2.3.4), not the 63-byte per-label ceiling — a name of
/// several ordinary labels must fit.
const MAX_NAME_LEN: usize = 255;

/// Maximum length of one wire-format label (RFC 1035 §2.3.4).
const MAX_LABEL_LEN: usize = 63;

/// Draws taken from the CSPRNG when allocating an upstream transaction id
/// before the forward is refused. Each draw is rejected only on collision with
/// a live pending slot, so the bound is reached with negligible probability.
const UPSTREAM_ID_DRAWS: usize = 8;

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::p_u16;
    use super::p_u32;
    use super::DnsState;
    use super::SCHEMA_MAX;

    define_params! {
        DnsState;

        1, upstream, u32, 0x08080808
            => |s, d, len| { s.upstream_ip = p_u32(d, len, 0, 0x08080808); };

        2, host, str, 0
            => |s, d, len| { super::parse_host_entry(s, d, len); };

        3, ttl, u32, 300
            => |s, d, len| { s.ttl = p_u32(d, len, 0, 300); };

        4, port, u16, 53
            => |s, d, len| { s.listen_port = p_u16(d, len, 0, 53); };

        // Head-sampling rate (per-mille, 0..=1000) for `dns.query` spans. The
        // default is the sentinel `0xFFFF` ("unset") so `module_new` can apply
        // the target-tier default (aarch64 50‰ / MCU 0‰) only when no explicit
        // value was supplied — set_defaults would otherwise clobber it.
        5, trace_sample_permille, u16, 0xFFFF
            => |s, d, len| { s.sample_permille = p_u16(d, len, 0, 0xFFFF); };

        // Destination port for forwarded (upstream) queries. Lets the
        // upstream be a delegation listener on a non-standard port;
        // default remains standard DNS.
        6, upstream_port, u16, 53
            => |s, d, len| { s.upstream_port = p_u16(d, len, 0, 53); };
    }
}

// ============================================================================
// Data structures
// ============================================================================

#[derive(Clone, Copy)]
#[repr(C)]
struct HostEntry {
    name_hash: u32,
    ip: u32,
    name_len: u8,
    _pad: [u8; 3],
    name: [u8; MAX_NAME_LEN + 1],
}

impl HostEntry {
    const fn empty() -> Self {
        Self {
            name_hash: 0,
            ip: 0,
            name_len: 0,
            _pad: [0; 3],
            name: [0; MAX_NAME_LEN + 1],
        }
    }
}

/// One forwarded query awaiting its upstream answer.
///
/// The correlation key on the wire is `upstream_id` — drawn from the CSPRNG,
/// never the client's own id — so two clients that pick the same id remain
/// distinct conversations. Everything an answer must reproduce before it is
/// relayed is retained here: the upstream endpoint it must come from, the
/// question it must repeat, and the client endpoint plus original id it is
/// rewritten for.
#[derive(Clone, Copy)]
#[repr(C)]
struct PendingQuery {
    /// Transaction id used towards the upstream resolver.
    upstream_id: u16,
    /// Transaction id the client chose, restored into the relayed answer.
    client_id: u16,
    client_port: u16,
    qtype: u16,
    qclass: u16,
    upstream_port: u16,
    client_ip: u32,
    upstream_ip: u32,
    /// `fnv1a_lower` over the dotted lowercase QNAME of the forwarded question.
    qname_hash: u32,
    /// Wall-clock millisecond deadline; the slot is dead once it passes.
    deadline_ms: u32,
    opcode: u8,
    active: u8,
    _pad: [u8; 2],
}

impl PendingQuery {
    const fn empty() -> Self {
        Self {
            upstream_id: 0,
            client_id: 0,
            client_port: 0,
            qtype: 0,
            qclass: 0,
            upstream_port: 0,
            client_ip: 0,
            upstream_ip: 0,
            qname_hash: 0,
            deadline_ms: 0,
            opcode: 0,
            active: 0,
            _pad: [0; 2],
        }
    }
}

/// The question a response must repeat exactly to be accepted.
#[derive(Clone, Copy)]
struct Question {
    qname_hash: u32,
    qtype: u16,
    qclass: u16,
    /// Offset of the first byte after the question section.
    end: usize,
}

/// True once `deadline_ms` has passed, wrap-safe over the 32-bit millisecond
/// clock.
#[inline(always)]
fn deadline_passed(now_ms: u32, deadline_ms: u32) -> bool {
    (now_ms.wrapping_sub(deadline_ms) as i32) >= 0
}

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct DnsState {
    syscalls: *const SyscallTable,
    net_in_chan: i32,
    net_out_chan: i32,

    upstream_ip: u32,
    /// Destination port for forwarded queries. Default 53; configurable so a
    /// host authority resolver on a non-standard port can be the upstream.
    upstream_port: u16,
    ttl: u32,
    listen_port: u16,
    host_count: u8,

    /// Datagram endpoints (shared `datagram_endpoint` core). `server_ep` binds
    /// `listen_port` for client queries; `upstream_ep` binds an ephemeral port
    /// to forward to / receive from the upstream DNS server. They share one
    /// channel and are demuxed by the provider-assigned ep_id; bound
    /// sequentially (server, then upstream).
    server_ep: DatagramEndpoint,
    upstream_ep: DatagramEndpoint,

    // Statistics
    queries_local: u32,
    queries_forwarded: u32,
    /// Upstream datagrams refused by correlation: wrong source endpoint, no
    /// QR bit, unexpected opcode, unparsable or mismatched question, unknown /
    /// expired transaction id, or a duplicate arriving after the first answer
    /// was consumed.
    upstream_drops: u32,
    /// Client queries refused with SERVFAIL because every pending slot was
    /// live, or because no upstream transaction id could be drawn.
    forward_refusals: u32,

    // Module-scope telemetry: cumulative byte counters + last emit timestamp
    // (cadence gated on the wallclock since dns has no per-step counter).
    tlm: TlmCounters,
    tlm_last_ms: u64,
    /// Head-sampling rate (per-mille) for `dns.query` spans. Target-tier
    /// default: 50‰ on aarch64 (pi5-class), 0‰ on MCUs. Decided per query
    /// from its minted trace id.
    sample_permille: u16,

    // Host table
    hosts: [HostEntry; MAX_HOSTS],

    // Pending upstream queries
    pending: [PendingQuery; MAX_PENDING],

    // Net protocol frame buffer (shared for TX)
    net_buf: [u8; NET_BUF_SIZE],

    // DNS packet work buffer
    tx_buf: [u8; DNS_MAX_PACKET],
}

impl DnsState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.net_in_chan = -1;
        self.net_out_chan = -1;
        self.upstream_ip = 0x08080808; // 8.8.8.8
        self.upstream_port = 53;
        self.ttl = 300;
        self.listen_port = 53;
        self.host_count = 0;
        self.server_ep = DatagramEndpoint::new();
        self.upstream_ep = DatagramEndpoint::new();
        self.queries_local = 0;
        self.queries_forwarded = 0;
        self.upstream_drops = 0;
        self.forward_refusals = 0;
        let mut i = 0;
        while i < MAX_PENDING {
            self.pending[i] = PendingQuery::empty();
            i += 1;
        }
        self.tlm = TlmCounters::new();
        self.tlm_last_ms = 0;
        // `sample_permille` is resolved in `module_new` after param parsing
        // (set_defaults would clobber any value set here), via the
        // `trace_sample_permille` param's `0xFFFF` "unset" sentinel.
    }

    #[inline(always)]
    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }
}

// ============================================================================
// FNV-1a hash (32-bit, lowercase variant)
// ============================================================================

/// FNV-1a hash over raw pointer data, lowercasing ASCII.
unsafe fn fnv1a_lower(data: *const u8, len: usize) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    let mut i = 0;
    while i < len {
        let mut b = *data.add(i);
        if b.is_ascii_uppercase() {
            b += 32;
        }
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
        i += 1;
    }
    h
}

// ============================================================================
// Helpers
// ============================================================================

#[inline(always)]
unsafe fn log_info(s: &DnsState, msg: &[u8]) {
    dev_log(s.sys(), 3, msg.as_ptr(), msg.len());
}

/// Parse a "hostname=ip" string and add to host table.
unsafe fn parse_host_entry(s: &mut DnsState, data: *const u8, len: usize) {
    if len == 0 || s.host_count as usize >= MAX_HOSTS {
        return;
    }

    // Find '=' separator
    let mut eq_pos = 0usize;
    let mut found = false;
    while eq_pos < len {
        if *data.add(eq_pos) == b'=' {
            found = true;
            break;
        }
        eq_pos += 1;
    }
    if !found || eq_pos == 0 || eq_pos + 1 >= len {
        return;
    }

    let name_len = eq_pos.min(MAX_NAME_LEN);
    let ip = parse_ipv4(data.add(eq_pos + 1), len - eq_pos - 1);
    if ip == 0 {
        return;
    }

    let idx = s.host_count as usize;
    let entry = &mut *s.hosts.as_mut_ptr().add(idx);

    // Copy name, lowercased
    let mut i = 0;
    while i < name_len {
        let mut b = *data.add(i);
        if b.is_ascii_uppercase() {
            b += 32;
        }
        *entry.name.as_mut_ptr().add(i) = b;
        i += 1;
    }
    entry.name_len = name_len as u8;
    entry.ip = ip;
    entry.name_hash = fnv1a_lower(data, name_len);

    s.host_count += 1;
}

/// Parse "a.b.c.d" IPv4 address from raw bytes. Returns IP in network byte order.
unsafe fn parse_ipv4(data: *const u8, len: usize) -> u32 {
    let mut octets = [0u8; 4];
    let op = octets.as_mut_ptr();
    let mut octet_idx = 0usize;
    let mut val: u16 = 0;
    let mut i = 0;

    while i < len {
        let b = *data.add(i);
        if b == b'.' {
            if octet_idx >= 3 {
                return 0;
            }
            if val > 255 {
                return 0;
            }
            *op.add(octet_idx) = val as u8;
            octet_idx += 1;
            val = 0;
        } else if b.is_ascii_digit() {
            val = val * 10 + (b - b'0') as u16;
        } else {
            break; // stop at non-digit/non-dot
        }
        i += 1;
    }

    if octet_idx != 3 || val > 255 {
        return 0;
    }
    *op.add(3) = val as u8;

    // Return as network byte order u32 (big endian)
    ((*op as u32) << 24)
        | ((*op.add(1) as u32) << 16)
        | ((*op.add(2) as u32) << 8)
        | (*op.add(3) as u32)
}

/// Extract QNAME from DNS question section. Converts wire format labels to
/// dotted lowercase string. Returns name length, or 0 on error.
/// Also advances `*offset` past the QNAME.
unsafe fn extract_qname(
    pkt: *const u8,
    pkt_len: usize,
    offset: &mut usize,
    name_buf: *mut u8,
) -> usize {
    let mut name_pos = 0usize;
    let mut off = *offset;

    loop {
        if off >= pkt_len {
            return 0;
        }
        let label_len = *pkt.add(off) as usize;
        off += 1;

        if label_len == 0 {
            break; // root label
        }

        // No compression pointer support needed for questions
        if label_len > MAX_LABEL_LEN || off + label_len > pkt_len {
            return 0;
        }

        // Add dot separator (not before first label)
        if name_pos > 0 {
            if name_pos >= MAX_NAME_LEN {
                return 0;
            }
            *name_buf.add(name_pos) = b'.';
            name_pos += 1;
        }

        // Copy label bytes, lowercased
        let mut i = 0;
        while i < label_len {
            if name_pos >= MAX_NAME_LEN {
                return 0;
            }
            let mut b = *pkt.add(off + i);
            if b.is_ascii_uppercase() {
                b += 32;
            }
            *name_buf.add(name_pos) = b;
            name_pos += 1;
            i += 1;
        }
        off += label_len;
    }

    *offset = off;
    name_pos
}

/// Look up a hostname in the local host table. Insertion and lookup share the
/// one `fnv1a_lower` invariant, so a caller that has not already lowercased its
/// name still matches.
unsafe fn lookup_host(s: &DnsState, name_ptr: *const u8, name_len: usize) -> Option<u32> {
    let hash = fnv1a_lower(name_ptr, name_len);
    let mut i = 0;
    while i < s.host_count as usize {
        let entry = &*s.hosts.as_ptr().add(i);
        if entry.name_hash == hash && entry.name_len as usize == name_len {
            // Byte comparison
            let mut match_ok = true;
            let mut j = 0;
            while j < name_len {
                let mut b = *name_ptr.add(j);
                if b.is_ascii_uppercase() {
                    b += 32;
                }
                if *entry.name.as_ptr().add(j) != b {
                    match_ok = false;
                    break;
                }
                j += 1;
            }
            if match_ok {
                return Some(entry.ip);
            }
        }
        i += 1;
    }
    None
}

/// Check if a name matches a reverse PTR lookup for any local host.
/// PTR queries for 1.2.3.4 come as "4.3.2.1.in-addr.arpa".
unsafe fn lookup_ptr(s: &DnsState, name_ptr: *const u8, name_len: usize) -> Option<(u32, usize)> {
    // Must end with ".in-addr.arpa"
    let suffix = b".in-addr.arpa";
    if name_len <= suffix.len() {
        return None;
    }
    let suffix_start = name_len - suffix.len();
    let mut i = 0;
    while i < suffix.len() {
        if *name_ptr.add(suffix_start + i) != *suffix.as_ptr().add(i) {
            return None;
        }
        i += 1;
    }

    // Parse reversed octets: "4.3.2.1"
    let addr_len = suffix_start;
    let mut octets = [0u8; 4];
    let op = octets.as_mut_ptr();
    let mut octet_idx: usize = 0;
    let mut val: u16 = 0;
    i = 0;
    while i < addr_len {
        let b = *name_ptr.add(i);
        if b == b'.' {
            if octet_idx >= 4 || val > 255 {
                return None;
            }
            *op.add(octet_idx) = val as u8;
            octet_idx += 1;
            val = 0;
        } else if b.is_ascii_digit() {
            val = val * 10 + (b - b'0') as u16;
        } else {
            return None;
        }
        i += 1;
    }
    if octet_idx != 3 || val > 255 {
        return None;
    }
    *op.add(3) = val as u8;

    // Reconstruct IP in network order (reversing the reversed octets)
    let ip = ((*op.add(3) as u32) << 24)
        | ((*op.add(2) as u32) << 16)
        | ((*op.add(1) as u32) << 8)
        | (*op as u32);

    // Find matching host
    let mut h = 0;
    while h < s.host_count as usize {
        if (*s.hosts.as_ptr().add(h)).ip == ip {
            return Some((ip, h));
        }
        h += 1;
    }
    None
}

/// Encode a dotted name into DNS wire format labels at dst.
/// Returns bytes written.
unsafe fn encode_name(name: *const u8, name_len: usize, dst: *mut u8) -> usize {
    let mut pos = 0usize;
    let mut label_start = 0usize;

    let mut i = 0;
    while i <= name_len {
        if i == name_len || *name.add(i) == b'.' {
            let label_len = i - label_start;
            if label_len == 0 || label_len > MAX_LABEL_LEN {
                return 0;
            }
            *dst.add(pos) = label_len as u8;
            pos += 1;
            let mut j = label_start;
            while j < i {
                *dst.add(pos) = *name.add(j);
                pos += 1;
                j += 1;
            }
            label_start = i + 1;
        }
        i += 1;
    }

    // Root label terminator
    *dst.add(pos) = 0;
    pos += 1;
    pos
}

/// Start a locally generated response: copy the query header and its FIRST
/// question, stamp the response flags, and set the record counts. Bytes after
/// the first question (further questions, additional records) are deliberately
/// not copied — a local answer is constructed, never echoed. Returns the write
/// position (the end of the question section), or 0 if the reply cannot fit.
unsafe fn begin_local_response(
    query_pkt: *const u8,
    question_end: usize,
    extra_flags: u16,
    ancount: u16,
    answer_reserve: usize,
    tx: *mut u8,
) -> usize {
    // Smallest legal question is the root label plus QTYPE/QCLASS.
    if question_end < DNS_HEADER_LEN + 5 || question_end + answer_reserve > DNS_MAX_PACKET {
        return 0;
    }

    let mut i = 0;
    while i < question_end {
        *tx.add(i) = *query_pkt.add(i);
        i += 1;
    }

    // QR=1, AA=1, RA=1, preserving the client's RD bit and opcode.
    let flags = u16::from_be_bytes([*query_pkt.add(2), *query_pkt.add(3)]);
    let new_flags =
        FLAG_QR | FLAG_AA | FLAG_RA | (flags & FLAG_RD) | (flags & FLAG_OPCODE_MASK) | extra_flags;
    let fb = new_flags.to_be_bytes();
    *tx.add(2) = fb[0];
    *tx.add(3) = fb[1];

    // QDCOUNT = 1 (the one question copied above)
    *tx.add(4) = 0;
    *tx.add(5) = 1;
    let ab = ancount.to_be_bytes();
    *tx.add(6) = ab[0];
    *tx.add(7) = ab[1];
    // NSCOUNT = 0, ARCOUNT = 0
    *tx.add(8) = 0;
    *tx.add(9) = 0;
    *tx.add(10) = 0;
    *tx.add(11) = 0;

    question_end
}

/// Bytes an A record occupies: name pointer, type, class, TTL, RDLENGTH, RDATA.
const A_RECORD_LEN: usize = 16;

/// Build a DNS A record response. Returns total packet length.
unsafe fn build_a_response(
    s: &DnsState,
    query_pkt: *const u8,
    question_end: usize,
    ip: u32,
    tx: *mut u8,
) -> usize {
    let mut pos = begin_local_response(query_pkt, question_end, 0, 1, A_RECORD_LEN, tx);
    if pos == 0 {
        return 0;
    }

    // Name pointer to question QNAME (offset 12)
    *tx.add(pos) = 0xC0;
    *tx.add(pos + 1) = 0x0C;
    pos += 2;

    // TYPE A = 1
    *tx.add(pos) = 0;
    *tx.add(pos + 1) = 1;
    pos += 2;

    // CLASS IN = 1
    *tx.add(pos) = 0;
    *tx.add(pos + 1) = 1;
    pos += 2;

    // TTL
    let ttl_bytes = s.ttl.to_be_bytes();
    *tx.add(pos) = ttl_bytes[0];
    *tx.add(pos + 1) = ttl_bytes[1];
    *tx.add(pos + 2) = ttl_bytes[2];
    *tx.add(pos + 3) = ttl_bytes[3];
    pos += 4;

    // RDLENGTH = 4
    *tx.add(pos) = 0;
    *tx.add(pos + 1) = 4;
    pos += 2;

    // RDATA = IPv4 address (network byte order)
    let ip_bytes = ip.to_be_bytes();
    *tx.add(pos) = ip_bytes[0];
    *tx.add(pos + 1) = ip_bytes[1];
    *tx.add(pos + 2) = ip_bytes[2];
    *tx.add(pos + 3) = ip_bytes[3];
    pos += 4;

    pos
}

/// Build a DNS PTR record response. Returns total packet length.
unsafe fn build_ptr_response(
    s: &DnsState,
    query_pkt: *const u8,
    question_end: usize,
    host_idx: usize,
    tx: *mut u8,
) -> usize {
    let entry = &*s.hosts.as_ptr().add(host_idx);

    // Fixed record fields plus the worst-case encoded name (one length byte per
    // label plus the root terminator).
    let reserve = 12 + entry.name_len as usize + 2;
    let mut pos = begin_local_response(query_pkt, question_end, 0, 1, reserve, tx);
    if pos == 0 {
        return 0;
    }

    // Name pointer
    *tx.add(pos) = 0xC0;
    *tx.add(pos + 1) = 0x0C;
    pos += 2;

    // TYPE PTR = 12
    *tx.add(pos) = 0;
    *tx.add(pos + 1) = 12;
    pos += 2;

    // CLASS IN
    *tx.add(pos) = 0;
    *tx.add(pos + 1) = 1;
    pos += 2;

    // TTL
    let ttl_bytes = s.ttl.to_be_bytes();
    *tx.add(pos) = ttl_bytes[0];
    *tx.add(pos + 1) = ttl_bytes[1];
    *tx.add(pos + 2) = ttl_bytes[2];
    *tx.add(pos + 3) = ttl_bytes[3];
    pos += 4;

    // RDLENGTH placeholder
    let rdlen_pos = pos;
    pos += 2;

    // Encode hostname as DNS wire format
    let name_written = encode_name(entry.name.as_ptr(), entry.name_len as usize, tx.add(pos));
    pos += name_written;

    // Fill in RDLENGTH
    let rdlen = name_written as u16;
    let rdb = rdlen.to_be_bytes();
    *tx.add(rdlen_pos) = rdb[0];
    *tx.add(rdlen_pos + 1) = rdb[1];

    pos
}

/// Build an NXDOMAIN response. Returns total packet length.
unsafe fn build_nxdomain(query_pkt: *const u8, question_end: usize, tx: *mut u8) -> usize {
    begin_local_response(query_pkt, question_end, RCODE_NXDOMAIN, 0, 0, tx)
}

/// Build a SERVFAIL response — the answer to a query the resolver accepted but
/// cannot forward, so the client learns to retry instead of waiting out its own
/// timeout.
unsafe fn build_servfail(query_pkt: *const u8, question_end: usize, tx: *mut u8) -> usize {
    begin_local_response(query_pkt, question_end, RCODE_SERVFAIL, 0, 0, tx)
}

/// Send `dns_data[..dns_len]` from `ep` to an IPv4 dst via the shared
/// `datagram_endpoint` core, bumping the module's `bytes_out` counter on a
/// successful (whole-datagram) write. Uses the raw state pointer so `net_buf`
/// (the framing scratch) is reachable independently of any live borrow.
/// Returns true when the whole datagram was accepted; false is backpressure.
unsafe fn dg_send_from(
    state: *mut DnsState,
    ep: &DatagramEndpoint,
    dst_ip: u32,
    dst_port: u16,
    dns_data: *const u8,
    dns_len: usize,
) -> bool {
    let sys = &*(*state).syscalls;
    let net_out = (*state).net_out_chan;
    let buf = (*state).net_buf.as_mut_ptr();
    let n = ep.send_to(
        sys,
        net_out,
        dst_ip,
        dst_port,
        dns_data,
        dns_len,
        buf,
        NET_BUF_SIZE,
    );
    if n > 0 {
        (*state).tlm.bytes_out = (*state).tlm.bytes_out.wrapping_add(dns_len as u32);
    }
    n > 0
}

/// Module-scope telemetry: emit cumulative `bytes_in` / `bytes_out` counters to
/// the `observe` collector when the telemetry port is wired (no-op otherwise),
/// at a ~5s wallclock cadence. Metric ids follow `[observability].metrics`
/// order: 0 = bytes_in, 1 = bytes_out. Counter semantics are monotonic, so the
/// deltas are NOT reset here. Bytes counted are DNS payload (excluding the
/// datagram framing) on both directions. Metric ids 2/3 carry the correlation
/// refusal counters (`upstream_drops`, `forward_refusals`).
#[inline(never)]
unsafe fn maybe_emit_telemetry(s: &mut DnsState) {
    let sys = &*s.syscalls;
    // Ring-based emission (§5.2): zero-cost when no consumer is subscribed.
    if !dev_telemetry_enabled(sys) {
        return;
    }
    let now = dev_millis(sys);
    if now.wrapping_sub(s.tlm_last_ms) < 5000 {
        return;
    }
    s.tlm_last_ms = now;
    let me = dev_self_index(sys);
    if me < 0 {
        return;
    }
    let midx = me as u16;
    let t = dev_micros(sys);
    let counter = abi::contracts::telemetry::METRIC_COUNTER;
    dev_telemetry_metric(sys, -1, midx, t, counter, 0, s.tlm.bytes_in as u64);
    dev_telemetry_metric(sys, -1, midx, t, counter, 1, s.tlm.bytes_out as u64);
    dev_telemetry_metric(sys, -1, midx, t, counter, 2, s.upstream_drops as u64);
    dev_telemetry_metric(sys, -1, midx, t, counter, 3, s.forward_refusals as u64);
}

/// Head-sampling decision for a new `dns.query` root, drawn deterministically
/// from the (random) minted trace id and compared to `permille`. Returns the
/// W3C trace-flags to stamp (`TRACE_FLAGS_SAMPLED` or 0). Mirrors the ip
/// module's `ingress_sample_decision` so the two stay aligned.
#[inline(always)]
fn ingress_sample_decision(permille: u16, trace_id: &[u8; 16]) -> u8 {
    let draw = u16::from_le_bytes([trace_id[0], trace_id[1]]) % 1000;
    if draw < permille {
        abi::contracts::telemetry::TRACE_FLAGS_SAMPLED
    } else {
        0
    }
}

/// Minted-per-query trace context for a `dns.query` span. Zero-sized cost when
/// the telemetry port is unwired or the query isn't head-sampled.
struct QuerySpan {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    flags: u8,
    start_us: u64,
}

/// Mint a root trace context for an incoming query when telemetry is wired.
/// Returns `None` (no work) when the telemetry port is unwired; otherwise draws
/// random ids, makes the head-sampling decision, and captures the start time
/// only for sampled queries (the clock read is gated behind the sample bit).
#[inline(never)]
unsafe fn begin_query_span(s: &DnsState) -> Option<QuerySpan> {
    let sys = &*s.syscalls;
    // No consumer subscribed → skip the id draw + span mint entirely (§5.2).
    if !dev_telemetry_enabled(sys) {
        return None;
    }
    let mut trace_id = [0u8; 16];
    let mut span_id = [0u8; 8];
    dev_csprng_fill(sys, trace_id.as_mut_ptr(), 16);
    dev_csprng_fill(sys, span_id.as_mut_ptr(), 8);
    let flags = ingress_sample_decision(s.sample_permille, &trace_id);
    let start_us = if flags & abi::contracts::telemetry::TRACE_FLAGS_SAMPLED != 0 {
        dev_micros(sys)
    } else {
        0
    };
    Some(QuerySpan {
        trace_id,
        span_id,
        flags,
        start_us,
    })
}

/// Emit the finished `dns.query` span (name_id 0, SERVER kind) for a locally
/// resolved query. No-op unless the query was head-sampled. Called at each
/// local-reply site; the bit test runs before the clock read so an unsampled
/// query does no work.
#[inline(never)]
unsafe fn emit_query_span(s: &DnsState, span: &QuerySpan) {
    if span.flags & abi::contracts::telemetry::TRACE_FLAGS_SAMPLED == 0 {
        return;
    }
    let sys = &*s.syscalls;
    let me = dev_self_index(sys);
    if me < 0 {
        return;
    }
    let end_raw = dev_micros(sys);
    let end = if end_raw < span.start_us {
        span.start_us
    } else {
        end_raw
    };
    let ctx = abi::contracts::telemetry::SpanContext {
        trace_id: span.trace_id,
        span_id: span.span_id,
        parent_id: [0u8; 8], // dns is the ingress for this query → root span
        flags: span.flags,
    };
    dev_telemetry_span(
        sys,
        -1,
        me as u16,
        0, // name_id 0 = dns.query
        abi::contracts::telemetry::SPAN_SERVER,
        abi::contracts::telemetry::STATUS_OK,
        &ctx,
        span.start_us,
        end,
    );
}

/// Send a DNS reply from the server endpoint back to the original client.
unsafe fn send_server_reply(
    state: *mut DnsState,
    dst_ip: u32,
    dst_port: u16,
    dns_data: *const u8,
    dns_len: usize,
) -> bool {
    dg_send_from(
        state,
        &(*state).server_ep,
        dst_ip,
        dst_port,
        dns_data,
        dns_len,
    )
}

/// Send a DNS query from the upstream endpoint to the configured upstream
/// DNS server.
unsafe fn send_upstream_query(state: *mut DnsState, dns_data: *const u8, dns_len: usize) -> bool {
    let upstream_ip = (*state).upstream_ip;
    let upstream_port = (*state).upstream_port;
    dg_send_from(
        state,
        &(*state).upstream_ep,
        upstream_ip,
        upstream_port,
        dns_data,
        dns_len,
    )
}

/// Index of a slot that is free or whose deadline has passed. A LIVE slot is
/// never recycled: accepted work is only ever displaced by its own timeout.
unsafe fn free_pending_slot(s: &DnsState, now_ms: u32) -> Option<usize> {
    let p = s.pending.as_ptr();
    let mut i = 0;
    while i < MAX_PENDING {
        let slot = &*p.add(i);
        if slot.active == 0 || deadline_passed(now_ms, slot.deadline_ms) {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// True if any live slot already holds `id` as its upstream transaction id.
unsafe fn upstream_id_in_use(s: &DnsState, now_ms: u32, id: u16) -> bool {
    let p = s.pending.as_ptr();
    let mut i = 0;
    while i < MAX_PENDING {
        let slot = &*p.add(i);
        if slot.active != 0 && !deadline_passed(now_ms, slot.deadline_ms) && slot.upstream_id == id
        {
            return true;
        }
        i += 1;
    }
    false
}

/// Draw an unpredictable upstream transaction id that no live slot is using.
/// Returns `None` when the CSPRNG is unavailable (the caller then refuses the
/// query rather than forwarding a guessable id) or when every draw collided.
unsafe fn alloc_upstream_id(s: &DnsState, now_ms: u32) -> Option<u16> {
    let sys = s.sys();
    let mut draw = 0usize;
    while draw < UPSTREAM_ID_DRAWS {
        let mut raw = [0u8; 2];
        // Platform CSPRNGs report success as either 0 or the byte count; any
        // negative value is a failure and must not be treated as entropy.
        if dev_csprng_fill(sys, raw.as_mut_ptr(), 2) < 0 {
            return None;
        }
        let id = u16::from_le_bytes(raw);
        if !upstream_id_in_use(s, now_ms, id) {
            return Some(id);
        }
        draw += 1;
    }
    None
}

/// Record a forwarded query in `slot`.
#[allow(
    clippy::too_many_arguments,
    reason = "the pending record is the correlation tuple; grouping it into a struct would move the argument list, not shorten it"
)]
unsafe fn store_pending(
    s: &mut DnsState,
    slot: usize,
    upstream_id: u16,
    client_id: u16,
    client_ip: u32,
    client_port: u16,
    q: &Question,
    opcode: u8,
    now_ms: u32,
) {
    let e = &mut *s.pending.as_mut_ptr().add(slot);
    e.upstream_id = upstream_id;
    e.client_id = client_id;
    e.client_ip = client_ip;
    e.client_port = client_port;
    e.qname_hash = q.qname_hash;
    e.qtype = q.qtype;
    e.qclass = q.qclass;
    e.upstream_ip = s.upstream_ip;
    e.upstream_port = s.upstream_port;
    e.opcode = opcode;
    e.deadline_ms = now_ms.wrapping_add(PENDING_TIMEOUT_MS);
    e.active = 1;
}

/// Consume the live pending slot an upstream answer correlates to. Every field
/// the answer must reproduce is checked here, and the slot is cleared before
/// returning, so a duplicate or late copy finds nothing and cannot re-fire.
unsafe fn take_pending(
    s: &mut DnsState,
    now_ms: u32,
    upstream_id: u16,
    src_ip: u32,
    src_port: u16,
    opcode: u8,
    q: &Question,
) -> Option<(u16, u32, u16)> {
    let p = s.pending.as_mut_ptr();
    let mut i = 0;
    while i < MAX_PENDING {
        let slot = &mut *p.add(i);
        if slot.active != 0
            && !deadline_passed(now_ms, slot.deadline_ms)
            && slot.upstream_id == upstream_id
            && slot.upstream_ip == src_ip
            && slot.upstream_port == src_port
            && slot.opcode == opcode
            && slot.qname_hash == q.qname_hash
            && slot.qtype == q.qtype
            && slot.qclass == q.qclass
        {
            slot.active = 0;
            return Some((slot.client_id, slot.client_ip, slot.client_port));
        }
        i += 1;
    }
    None
}

/// Release pending slots whose deadline has passed.
unsafe fn expire_pending(s: &mut DnsState) {
    let now = dev_millis(s.sys()) as u32;
    let p = s.pending.as_mut_ptr();
    let mut i = 0;
    while i < MAX_PENDING {
        let slot = &mut *p.add(i);
        if slot.active != 0 && deadline_passed(now, slot.deadline_ms) {
            slot.active = 0;
        }
        i += 1;
    }
}

/// Parse the single question section of `pkt`, writing the dotted lowercase
/// QNAME into `name_buf` (at least `MAX_NAME_LEN + 1` bytes). Returns the
/// question and the QNAME length.
unsafe fn parse_question(
    pkt: *const u8,
    pkt_len: usize,
    name_buf: *mut u8,
) -> Option<(Question, usize)> {
    let mut offset = DNS_HEADER_LEN;
    let name_len = extract_qname(pkt, pkt_len, &mut offset, name_buf);
    if name_len == 0 || offset + 4 > pkt_len {
        return None;
    }
    let qtype = u16::from_be_bytes([*pkt.add(offset), *pkt.add(offset + 1)]);
    let qclass = u16::from_be_bytes([*pkt.add(offset + 2), *pkt.add(offset + 3)]);
    Some((
        Question {
            qname_hash: fnv1a_lower(name_buf, name_len),
            qtype,
            qclass,
            end: offset + 4,
        },
        name_len,
    ))
}

/// Process a DNS query received on the server socket.
unsafe fn handle_query(
    s: &mut DnsState,
    client_ip: u32,
    client_port: u16,
    pkt: *const u8,
    pkt_len: usize,
) {
    if pkt_len < DNS_HEADER_LEN {
        return;
    }

    // Parse DNS header
    let id = u16::from_be_bytes([*pkt, *pkt.add(1)]);
    let flags = u16::from_be_bytes([*pkt.add(2), *pkt.add(3)]);
    let qdcount = u16::from_be_bytes([*pkt.add(4), *pkt.add(5)]);

    // Only process standard queries (QR=0, Opcode=0)
    if (flags & FLAG_QR) != 0
        || ((flags & FLAG_OPCODE_MASK) >> FLAG_OPCODE_SHIFT) as u8 != OPCODE_QUERY
    {
        return;
    }
    // The supported profile is exactly one question per query: local answers
    // are constructed from that question, and an upstream answer is correlated
    // against it.
    if qdcount != 1 {
        return;
    }

    let mut name_buf = [0u8; MAX_NAME_LEN + 1];
    let (question, name_len) = match parse_question(pkt, pkt_len, name_buf.as_mut_ptr()) {
        Some(v) => v,
        None => return,
    };
    let qtype = question.qtype;
    let question_end = question.end;

    // Only handle IN class
    if question.qclass != QCLASS_IN {
        // Forward unknown classes
        forward_to_upstream(s, id, client_ip, client_port, &question, pkt, pkt_len);
        return;
    }

    // Use raw pointer to tx_buf to avoid borrow checker issues
    let tx_ptr = s.tx_buf.as_mut_ptr();

    // Mint a `dns.query` trace context now (past the parse-fail returns, before
    // resolution). Emitted only at the local-reply sites below; forwarded
    // queries leave `qspan` unused. `None` when telemetry is unwired.
    let qspan = begin_query_span(s);

    match qtype {
        QTYPE_A => {
            // Look up in local host table
            match lookup_host(s, name_buf.as_ptr(), name_len) {
                Some(ip) => {
                    // Build and send local A response
                    let resp_len = build_a_response(s, pkt, question_end, ip, tx_ptr);
                    if resp_len > 0 {
                        send_server_reply(
                            s as *mut DnsState,
                            client_ip,
                            client_port,
                            tx_ptr as *const u8,
                            resp_len,
                        );
                        s.queries_local += 1;
                        if let Some(ref sp) = qspan {
                            emit_query_span(s, sp);
                        }
                    }
                }
                None => {
                    // Forward to upstream
                    forward_to_upstream(s, id, client_ip, client_port, &question, pkt, pkt_len);
                }
            }
        }
        QTYPE_AAAA => {
            // Check if it's a local host — if so, send empty response (no AAAA record)
            // instead of forwarding to upstream
            if lookup_host(s, name_buf.as_ptr(), name_len).is_some() {
                // Send empty response (no answer, no error) — host exists but no IPv6
                let resp_len = build_empty_response(pkt, question_end, tx_ptr);
                if resp_len > 0 {
                    send_server_reply(
                        s as *mut DnsState,
                        client_ip,
                        client_port,
                        tx_ptr as *const u8,
                        resp_len,
                    );
                    if let Some(ref sp) = qspan {
                        emit_query_span(s, sp);
                    }
                }
            } else {
                forward_to_upstream(s, id, client_ip, client_port, &question, pkt, pkt_len);
            }
        }
        QTYPE_PTR => {
            // Reverse lookup
            match lookup_ptr(s, name_buf.as_ptr(), name_len) {
                Some((_ip, host_idx)) => {
                    let resp_len = build_ptr_response(s, pkt, question_end, host_idx, tx_ptr);
                    if resp_len > 0 {
                        send_server_reply(
                            s as *mut DnsState,
                            client_ip,
                            client_port,
                            tx_ptr as *const u8,
                            resp_len,
                        );
                        s.queries_local += 1;
                        if let Some(ref sp) = qspan {
                            emit_query_span(s, sp);
                        }
                    }
                }
                None => {
                    forward_to_upstream(s, id, client_ip, client_port, &question, pkt, pkt_len);
                }
            }
        }
        _ => {
            // Forward all other types to upstream
            forward_to_upstream(s, id, client_ip, client_port, &question, pkt, pkt_len);
        }
    }
}

/// Build an empty response (NOERROR, 0 answers) for local hosts with no matching record type.
unsafe fn build_empty_response(query_pkt: *const u8, question_end: usize, tx: *mut u8) -> usize {
    begin_local_response(query_pkt, question_end, 0, 0, 0, tx)
}

/// Answer a query the resolver accepted but cannot forward with SERVFAIL, so
/// the client can retry immediately instead of waiting out its own timeout.
unsafe fn refuse_with_servfail(
    s: &mut DnsState,
    client_ip: u32,
    client_port: u16,
    pkt: *const u8,
    question_end: usize,
) {
    s.forward_refusals = s.forward_refusals.wrapping_add(1);
    let tx_ptr = s.tx_buf.as_mut_ptr();
    let len = build_servfail(pkt, question_end, tx_ptr);
    if len > 0 {
        send_server_reply(
            s as *mut DnsState,
            client_ip,
            client_port,
            tx_ptr as *const u8,
            len,
        );
    }
}

/// Forward a query to the upstream DNS server under a fresh, unpredictable
/// transaction id. The client's own id never reaches the wire: it is retained
/// in the pending slot and restored when the matching answer is relayed back.
///
/// A pending slot is taken before the send, and only free or expired slots are
/// taken — accepted work is never displaced. With no slot, no id, or no bound
/// upstream endpoint the query is refused with SERVFAIL.
unsafe fn forward_to_upstream(
    s: &mut DnsState,
    client_id: u16,
    client_ip: u32,
    client_port: u16,
    question: &Question,
    pkt: *const u8,
    pkt_len: usize,
) {
    if !s.upstream_ep.is_ready() || pkt_len > DNS_MAX_PACKET {
        refuse_with_servfail(s, client_ip, client_port, pkt, question.end);
        return;
    }

    let now = dev_millis(s.sys()) as u32;
    let slot = match free_pending_slot(s, now) {
        Some(i) => i,
        None => {
            refuse_with_servfail(s, client_ip, client_port, pkt, question.end);
            return;
        }
    };
    let upstream_id = match alloc_upstream_id(s, now) {
        Some(id) => id,
        None => {
            refuse_with_servfail(s, client_ip, client_port, pkt, question.end);
            return;
        }
    };

    // Copy the query into the work buffer and stamp the upstream id over the
    // client's. The rest of the query — including any EDNS additional records —
    // is forwarded unchanged.
    let tx_ptr = s.tx_buf.as_mut_ptr();
    let mut i = 0;
    while i < pkt_len {
        *tx_ptr.add(i) = *pkt.add(i);
        i += 1;
    }
    let idb = upstream_id.to_be_bytes();
    *tx_ptr = idb[0];
    *tx_ptr.add(1) = idb[1];

    let opcode = ((u16::from_be_bytes([*pkt.add(2), *pkt.add(3)]) & FLAG_OPCODE_MASK)
        >> FLAG_OPCODE_SHIFT) as u8;
    store_pending(
        s,
        slot,
        upstream_id,
        client_id,
        client_ip,
        client_port,
        question,
        opcode,
        now,
    );

    // Send query to upstream via CMD_DG_SEND_TO on the upstream endpoint. A
    // rejected write means the query was never forwarded, so the slot is
    // released again and the client is refused rather than left to time out.
    if !send_upstream_query(s as *mut DnsState, tx_ptr as *const u8, pkt_len) {
        (*s.pending.as_mut_ptr().add(slot)).active = 0;
        refuse_with_servfail(s, client_ip, client_port, pkt, question.end);
        return;
    }
    s.queries_forwarded += 1;
}

/// Process a datagram received on the upstream endpoint.
///
/// It is relayed to a client only if it is a response (QR set) from the exact
/// configured upstream endpoint, carries the expected opcode and exactly the
/// question that was forwarded, and matches a live upstream transaction id.
/// Everything else — including a query arriving on the response port, a spoofed
/// source, and a duplicate arriving after the first answer was consumed — is
/// dropped and metered.
unsafe fn handle_upstream_response(
    s: &mut DnsState,
    src_ip: u32,
    src_port: u16,
    pkt: *const u8,
    pkt_len: usize,
) {
    if !(DNS_HEADER_LEN..=DNS_MAX_PACKET).contains(&pkt_len) {
        s.upstream_drops = s.upstream_drops.wrapping_add(1);
        return;
    }

    let id = u16::from_be_bytes([*pkt, *pkt.add(1)]);
    let flags = u16::from_be_bytes([*pkt.add(2), *pkt.add(3)]);
    let qdcount = u16::from_be_bytes([*pkt.add(4), *pkt.add(5)]);
    let opcode = ((flags & FLAG_OPCODE_MASK) >> FLAG_OPCODE_SHIFT) as u8;

    if (flags & FLAG_QR) == 0 || qdcount != 1 {
        s.upstream_drops = s.upstream_drops.wrapping_add(1);
        return;
    }

    let mut name_buf = [0u8; MAX_NAME_LEN + 1];
    let question = match parse_question(pkt, pkt_len, name_buf.as_mut_ptr()) {
        Some((q, _)) => q,
        None => {
            s.upstream_drops = s.upstream_drops.wrapping_add(1);
            return;
        }
    };

    let (client_id, client_ip, client_port) = match take_pending(
        s,
        dev_millis(s.sys()) as u32,
        id,
        src_ip,
        src_port,
        opcode,
        &question,
    ) {
        Some(v) => v,
        None => {
            s.upstream_drops = s.upstream_drops.wrapping_add(1);
            return;
        }
    };

    // Restore the client's own transaction id, then relay to the endpoint the
    // query was accepted from.
    let tx_ptr = s.tx_buf.as_mut_ptr();
    let mut i = 0;
    while i < pkt_len {
        *tx_ptr.add(i) = *pkt.add(i);
        i += 1;
    }
    let idb = client_id.to_be_bytes();
    *tx_ptr = idb[0];
    *tx_ptr.add(1) = idb[1];

    send_server_reply(
        s as *mut DnsState,
        client_ip,
        client_port,
        tx_ptr as *const u8,
        pkt_len,
    );
}

// ============================================================================
// PIC Module Interface
// ============================================================================

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<DnsState>() as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() {
            return -5;
        }
        if state_size < core::mem::size_of::<DnsState>() {
            return -6;
        }

        let s = &mut *(state as *mut DnsState);
        s.init(syscalls as *const SyscallTable);

        // Net channels: in[0] = net_in (from IP), out[0] = net_out (to IP)
        s.net_in_chan = in_chan;
        s.net_out_chan = out_chan;

        // Parse TLV params
        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        // Resolve the target-tier head-sampling default only when the
        // `trace_sample_permille` param was not explicitly supplied (still the
        // `0xFFFF` sentinel): aarch64 (pi5-class) 50‰, MCUs 0‰. An explicit
        // value (including 0) is honoured as-is.
        if s.sample_permille == 0xFFFF {
            #[cfg(target_arch = "aarch64")]
            {
                s.sample_permille = 50;
            }
            #[cfg(not(target_arch = "aarch64"))]
            {
                s.sample_permille = 0;
            }
        }

        log_info(s, b"[dns] init");

        0
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut DnsState);
        if s.syscalls.is_null() {
            return -1;
        }

        // Module-scope metrics: cumulative byte counters, ~5s cadence, no-op
        // when the telemetry port is unwired.
        maybe_emit_telemetry(s);

        // Drive the two binds sequentially — server on `listen_port`, then the
        // ephemeral upstream once the server is up — so each MSG_DG_BOUND routes
        // to the single endpoint in WaitBound. The shared `datagram_endpoint`
        // core owns the bind handshake (with backoff) and the addressed send;
        // `dg_recv` classifies one inbound frame per step.
        let sys = &*s.syscalls;
        let net_out = s.net_out_chan;
        let net_in = s.net_in_chan;
        let buf = s.net_buf.as_mut_ptr();

        s.server_ep
            .poll_bind(sys, net_out, s.listen_port, buf, NET_BUF_SIZE);
        if s.server_ep.is_ready() {
            s.upstream_ep.poll_bind(sys, net_out, 0, buf, NET_BUF_SIZE);
        }

        let mut did_work = false;
        if let Some(ev) = dg_recv(sys, net_in, buf, NET_BUF_SIZE) {
            match ev {
                DgEvent::Bound { ep_id, .. } => {
                    // Sequential binds: exactly one endpoint is in WaitBound, so
                    // the completion routes unambiguously.
                    s.server_ep.on_bound(ep_id);
                    s.upstream_ep.on_bound(ep_id);
                    if s.server_ep.owns(ep_id) {
                        log_info(s, b"[dns] server bound");
                    } else if s.upstream_ep.owns(ep_id) {
                        log_info(s, b"[dns] serving");
                    }
                    did_work = true;
                }
                DgEvent::Rx {
                    ep_id,
                    src_ip,
                    src_port,
                    data,
                    len,
                } => {
                    if len >= DNS_HEADER_LEN {
                        s.tlm.bytes_in = s.tlm.bytes_in.wrapping_add(len as u32);
                        if s.server_ep.owns(ep_id) {
                            handle_query(s, src_ip, src_port, data, len);
                        } else if s.upstream_ep.owns(ep_id) {
                            handle_upstream_response(s, src_ip, src_port, data, len);
                        }
                        did_work = true;
                    }
                }
                DgEvent::Err { .. } => {
                    // Bind failure — the endpoint in WaitBound backs off + retries.
                    s.server_ep.on_error(sys);
                    s.upstream_ep.on_error(sys);
                }
                DgEvent::Closed { .. } => {}
            }
        }

        // Expire old pending queries periodically.
        expire_pending(s);

        if did_work {
            2
        } else {
            0
        } // burst when work happened, else continue
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/runtime/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/runtime/wasm_entry.rs");
