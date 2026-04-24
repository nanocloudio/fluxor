//! DNS Server PIC Module
//!
//! Resolves configured hostnames locally, forwards everything else to an
//! upstream DNS server (default 8.8.8.8).
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

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

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
const FLAG_QR: u16 = 0x8000;       // Response
const FLAG_AA: u16 = 0x0400;       // Authoritative
const FLAG_RA: u16 = 0x0080;       // Recursion available
const FLAG_RD: u16 = 0x0100;       // Recursion desired
const RCODE_NXDOMAIN: u16 = 0x0003;

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

/// Maximum domain name length
const MAX_NAME_LEN: usize = 63;

/// DNS server/proxy lifecycle phases.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum DnsPhase {
    Init = 0,
    BindingServer = 1,
    WaitBoundServer = 2,
    BindingUpstream = 3,
    WaitBoundUpstream = 4,
    Serving = 5,
    Error = 255,
}

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::DnsState;
    use super::p_u16;
    use super::p_u32;
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

#[derive(Clone, Copy)]
#[repr(C)]
struct PendingQuery {
    dns_id: u16,
    client_port: u16,
    client_ip: u32,
    timestamp: u32,
    active: u8,
    _pad: [u8; 3],
}

impl PendingQuery {
    const fn empty() -> Self {
        Self {
            dns_id: 0,
            client_port: 0,
            client_ip: 0,
            timestamp: 0,
            active: 0,
            _pad: [0; 3],
        }
    }
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
    ttl: u32,
    listen_port: u16,
    phase: DnsPhase,
    host_count: u8,

    /// Endpoint IDs assigned by the IP module via MSG_DG_BOUND.
    /// `server_ep` is bound to `listen_port`; `upstream_ep` is bound to an
    /// ephemeral port and used only to send to / receive from the upstream
    /// DNS server. Both values start as `0xFF` to distinguish unallocated.
    server_ep: u8,
    upstream_ep: u8,

    // Statistics
    queries_local: u32,
    queries_forwarded: u32,

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
        self.ttl = 300;
        self.listen_port = 53;
        self.phase = DnsPhase::Init;
        self.host_count = 0;
        self.server_ep = 0xFF;
        self.upstream_ep = 0xFF;
        self.queries_local = 0;
        self.queries_forwarded = 0;
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
        if b >= b'A' && b <= b'Z' {
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

#[inline(always)]
unsafe fn log_err(s: &DnsState, msg: &[u8]) {
    dev_log(s.sys(), 1, msg.as_ptr(), msg.len());
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
        if b >= b'A' && b <= b'Z' {
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
            if octet_idx >= 3 { return 0; }
            if val > 255 { return 0; }
            *op.add(octet_idx) = val as u8;
            octet_idx += 1;
            val = 0;
        } else if b >= b'0' && b <= b'9' {
            val = val * 10 + (b - b'0') as u16;
        } else {
            break; // stop at non-digit/non-dot
        }
        i += 1;
    }

    if octet_idx != 3 || val > 255 { return 0; }
    *op.add(3) = val as u8;

    // Return as network byte order u32 (big endian)
    ((*op as u32) << 24) | ((*op.add(1) as u32) << 16)
        | ((*op.add(2) as u32) << 8) | (*op.add(3) as u32)
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
        if off >= pkt_len { return 0; }
        let label_len = *pkt.add(off) as usize;
        off += 1;

        if label_len == 0 {
            break; // root label
        }

        // No compression pointer support needed for questions
        if label_len > 63 || off + label_len > pkt_len {
            return 0;
        }

        // Add dot separator (not before first label)
        if name_pos > 0 {
            if name_pos >= MAX_NAME_LEN { return 0; }
            *name_buf.add(name_pos) = b'.';
            name_pos += 1;
        }

        // Copy label bytes, lowercased
        let mut i = 0;
        while i < label_len {
            if name_pos >= MAX_NAME_LEN { return 0; }
            let mut b = *pkt.add(off + i);
            if b >= b'A' && b <= b'Z' {
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

/// Look up a hostname in the local host table.
unsafe fn lookup_host(s: &DnsState, name_ptr: *const u8, name_len: usize) -> Option<u32> {
    let hash = fnv1a(core::slice::from_raw_parts(name_ptr, name_len));
    let mut i = 0;
    while i < s.host_count as usize {
        let entry = &*s.hosts.as_ptr().add(i);
        if entry.name_hash == hash && entry.name_len as usize == name_len {
            // Byte comparison
            let mut match_ok = true;
            let mut j = 0;
            while j < name_len {
                if *entry.name.as_ptr().add(j) != *name_ptr.add(j) {
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
    if name_len <= suffix.len() { return None; }
    let suffix_start = name_len - suffix.len();
    let mut i = 0;
    while i < suffix.len() {
        if *name_ptr.add(suffix_start + i) != *suffix.as_ptr().add(i) { return None; }
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
            if octet_idx >= 4 || val > 255 { return None; }
            *op.add(octet_idx) = val as u8;
            octet_idx += 1;
            val = 0;
        } else if b >= b'0' && b <= b'9' {
            val = val * 10 + (b - b'0') as u16;
        } else {
            return None;
        }
        i += 1;
    }
    if octet_idx != 3 || val > 255 { return None; }
    *op.add(3) = val as u8;

    // Reconstruct IP in network order (reversing the reversed octets)
    let ip = ((*op.add(3) as u32) << 24) | ((*op.add(2) as u32) << 16)
        | ((*op.add(1) as u32) << 8) | (*op as u32);

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
            if label_len == 0 || label_len > 63 { return 0; }
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

/// Build a DNS A record response. Returns total packet length.
unsafe fn build_a_response(
    s: &DnsState,
    query_pkt: *const u8,
    query_len: usize,
    question_end: usize,
    ip: u32,
    tx: *mut u8,
) -> usize {
    if query_len < DNS_HEADER_LEN { return 0; }

    // Copy query header
    let mut i = 0;
    while i < query_len.min(DNS_MAX_PACKET) {
        *tx.add(i) = *query_pkt.add(i);
        i += 1;
    }

    // Set flags: QR=1, AA=1, RA=1, preserve RD
    let flags = u16::from_be_bytes([*query_pkt.add(2), *query_pkt.add(3)]);
    let new_flags = FLAG_QR | FLAG_AA | FLAG_RA | (flags & FLAG_RD);
    let fb = new_flags.to_be_bytes();
    *tx.add(2) = fb[0];
    *tx.add(3) = fb[1];

    // ANCOUNT = 1
    *tx.add(6) = 0;
    *tx.add(7) = 1;
    // NSCOUNT = 0, ARCOUNT = 0
    *tx.add(8) = 0; *tx.add(9) = 0;
    *tx.add(10) = 0; *tx.add(11) = 0;

    // Answer section starts after question
    let mut pos = question_end;

    // Name pointer to question QNAME (offset 12)
    *tx.add(pos) = 0xC0;
    *tx.add(pos + 1) = 0x0C;
    pos += 2;

    // TYPE A = 1
    *tx.add(pos) = 0; *tx.add(pos + 1) = 1;
    pos += 2;

    // CLASS IN = 1
    *tx.add(pos) = 0; *tx.add(pos + 1) = 1;
    pos += 2;

    // TTL
    let ttl_bytes = s.ttl.to_be_bytes();
    *tx.add(pos) = ttl_bytes[0]; *tx.add(pos + 1) = ttl_bytes[1];
    *tx.add(pos + 2) = ttl_bytes[2]; *tx.add(pos + 3) = ttl_bytes[3];
    pos += 4;

    // RDLENGTH = 4
    *tx.add(pos) = 0; *tx.add(pos + 1) = 4;
    pos += 2;

    // RDATA = IPv4 address (network byte order)
    let ip_bytes = ip.to_be_bytes();
    *tx.add(pos) = ip_bytes[0]; *tx.add(pos + 1) = ip_bytes[1];
    *tx.add(pos + 2) = ip_bytes[2]; *tx.add(pos + 3) = ip_bytes[3];
    pos += 4;

    pos
}

/// Build a DNS PTR record response. Returns total packet length.
unsafe fn build_ptr_response(
    s: &DnsState,
    query_pkt: *const u8,
    query_len: usize,
    question_end: usize,
    host_idx: usize,
    tx: *mut u8,
) -> usize {
    if query_len < DNS_HEADER_LEN { return 0; }
    let entry = &*s.hosts.as_ptr().add(host_idx);

    // Copy query up to end of question
    let mut i = 0;
    while i < query_len.min(DNS_MAX_PACKET) {
        *tx.add(i) = *query_pkt.add(i);
        i += 1;
    }

    // Set flags: QR=1, AA=1, RA=1, preserve RD
    let flags = u16::from_be_bytes([*query_pkt.add(2), *query_pkt.add(3)]);
    let new_flags = FLAG_QR | FLAG_AA | FLAG_RA | (flags & FLAG_RD);
    let fb = new_flags.to_be_bytes();
    *tx.add(2) = fb[0];
    *tx.add(3) = fb[1];

    // ANCOUNT = 1
    *tx.add(6) = 0; *tx.add(7) = 1;
    *tx.add(8) = 0; *tx.add(9) = 0;
    *tx.add(10) = 0; *tx.add(11) = 0;

    let mut pos = question_end;

    // Name pointer
    *tx.add(pos) = 0xC0; *tx.add(pos + 1) = 0x0C;
    pos += 2;

    // TYPE PTR = 12
    *tx.add(pos) = 0; *tx.add(pos + 1) = 12;
    pos += 2;

    // CLASS IN
    *tx.add(pos) = 0; *tx.add(pos + 1) = 1;
    pos += 2;

    // TTL
    let ttl_bytes = s.ttl.to_be_bytes();
    *tx.add(pos) = ttl_bytes[0]; *tx.add(pos + 1) = ttl_bytes[1];
    *tx.add(pos + 2) = ttl_bytes[2]; *tx.add(pos + 3) = ttl_bytes[3];
    pos += 4;

    // RDLENGTH placeholder
    let rdlen_pos = pos;
    pos += 2;

    // Encode hostname as DNS wire format
    let name_written = encode_name(
        entry.name.as_ptr(),
        entry.name_len as usize,
        tx.add(pos),
    );
    pos += name_written;

    // Fill in RDLENGTH
    let rdlen = name_written as u16;
    let rdb = rdlen.to_be_bytes();
    *tx.add(rdlen_pos) = rdb[0];
    *tx.add(rdlen_pos + 1) = rdb[1];

    pos
}

/// Build an NXDOMAIN response. Returns total packet length.
unsafe fn build_nxdomain(
    query_pkt: *const u8,
    query_len: usize,
    tx: *mut u8,
) -> usize {
    if query_len < DNS_HEADER_LEN { return 0; }

    // Copy entire query
    let copy_len = query_len.min(DNS_MAX_PACKET);
    let mut i = 0;
    while i < copy_len {
        *tx.add(i) = *query_pkt.add(i);
        i += 1;
    }

    // Set flags: QR=1, AA=1, RA=1, RCODE=NXDOMAIN, preserve RD
    let flags = u16::from_be_bytes([*query_pkt.add(2), *query_pkt.add(3)]);
    let new_flags = FLAG_QR | FLAG_AA | FLAG_RA | (flags & FLAG_RD) | RCODE_NXDOMAIN;
    let fb = new_flags.to_be_bytes();
    *tx.add(2) = fb[0];
    *tx.add(3) = fb[1];

    // No answer records
    *tx.add(6) = 0; *tx.add(7) = 0;
    *tx.add(8) = 0; *tx.add(9) = 0;
    *tx.add(10) = 0; *tx.add(11) = 0;

    copy_len
}

/// Emit a datagram CMD_DG_SEND_TO frame from `ep_id` to an IPv4 dst.
///
/// Frame layout:
///   `[0x21][len:2 LE][ep_id:1][af:1=4][dst_addr:4 BE][dst_port:2 LE][data...]`
///
/// Uses raw state pointer to access net_buf independently of any &mut
/// borrow, since the received frame data has already been consumed by
/// caller.
unsafe fn dg_send_to_v4(
    state: *mut DnsState,
    ep_id: u8,
    dst_ip: u32,
    dst_port: u16,
    dns_data: *const u8,
    dns_len: usize,
) {
    let net_out = (*state).net_out_chan;
    let sys = (*state).syscalls;
    if net_out < 0 || ep_id == 0xFF { return; }
    let payload_len = DG_V4_PREFIX + dns_len;
    let total = NET_FRAME_HDR + payload_len;
    if total > NET_BUF_SIZE { return; }

    let buf = (*state).net_buf.as_mut_ptr();

    *buf = DG_CMD_SEND_TO;
    let pl = (payload_len as u16).to_le_bytes();
    *buf.add(1) = pl[0];
    *buf.add(2) = pl[1];
    *buf.add(3) = ep_id;
    *buf.add(4) = DG_AF_INET;
    let ip_bytes = dst_ip.to_be_bytes();
    *buf.add(5) = ip_bytes[0]; *buf.add(6) = ip_bytes[1];
    *buf.add(7) = ip_bytes[2]; *buf.add(8) = ip_bytes[3];
    let port_bytes = dst_port.to_le_bytes();
    *buf.add(9) = port_bytes[0]; *buf.add(10) = port_bytes[1];

    let mut i = 0;
    while i < dns_len {
        *buf.add(DG_V4_PREFIX + NET_FRAME_HDR + i) = *dns_data.add(i);
        i += 1;
    }

    ((*sys).channel_write)(net_out, buf, total);
}

/// Send a DNS reply from the server endpoint back to the original client.
unsafe fn send_server_reply(
    state: *mut DnsState,
    dst_ip: u32,
    dst_port: u16,
    dns_data: *const u8,
    dns_len: usize,
) {
    let ep = (*state).server_ep;
    dg_send_to_v4(state, ep, dst_ip, dst_port, dns_data, dns_len);
}

/// Send a DNS query from the upstream endpoint to the configured upstream
/// DNS server.
unsafe fn send_upstream_query(
    state: *mut DnsState,
    dns_data: *const u8,
    dns_len: usize,
) {
    let ep = (*state).upstream_ep;
    let upstream_ip = (*state).upstream_ip;
    dg_send_to_v4(state, ep, upstream_ip, 53, dns_data, dns_len);
}

/// Store a pending upstream query.
unsafe fn store_pending(
    s: &mut DnsState,
    dns_id: u16,
    client_ip: u32,
    client_port: u16,
) -> bool {
    let now = dev_millis(s.sys()) as u32;
    let p = s.pending.as_mut_ptr();

    // Find free slot (or oldest expired)
    let mut best = 0usize;
    let mut best_time = u32::MAX;

    let mut i = 0;
    while i < MAX_PENDING {
        if (*p.add(i)).active == 0 {
            best = i;
            break;
        }
        if (*p.add(i)).timestamp < best_time {
            best_time = (*p.add(i)).timestamp;
            best = i;
        }
        i += 1;
    }

    (*p.add(best)).dns_id = dns_id;
    (*p.add(best)).client_ip = client_ip;
    (*p.add(best)).client_port = client_port;
    (*p.add(best)).timestamp = now;
    (*p.add(best)).active = 1;
    true
}

/// Find and remove a pending query by DNS transaction ID.
unsafe fn take_pending(s: &mut DnsState, dns_id: u16) -> Option<(u32, u16)> {
    let p = s.pending.as_mut_ptr();
    let mut i = 0;
    while i < MAX_PENDING {
        if (*p.add(i)).active != 0 && (*p.add(i)).dns_id == dns_id {
            let ip = (*p.add(i)).client_ip;
            let port = (*p.add(i)).client_port;
            (*p.add(i)).active = 0;
            return Some((ip, port));
        }
        i += 1;
    }
    None
}

/// Expire old pending queries.
unsafe fn expire_pending(s: &mut DnsState) {
    let now = dev_millis(s.sys()) as u32;
    let p = s.pending.as_mut_ptr();
    let mut i = 0;
    while i < MAX_PENDING {
        if (*p.add(i)).active != 0 {
            let elapsed = now.wrapping_sub((*p.add(i)).timestamp);
            if elapsed > PENDING_TIMEOUT_MS {
                (*p.add(i)).active = 0;
            }
        }
        i += 1;
    }
}

/// Process a DNS query received on the server socket.
unsafe fn handle_query(
    s: &mut DnsState,
    client_ip: u32,
    client_port: u16,
    pkt: *const u8,
    pkt_len: usize,
) {
    if pkt_len < DNS_HEADER_LEN { return; }

    // Parse DNS header
    let id = u16::from_be_bytes([*pkt, *pkt.add(1)]);
    let flags = u16::from_be_bytes([*pkt.add(2), *pkt.add(3)]);
    let qdcount = u16::from_be_bytes([*pkt.add(4), *pkt.add(5)]);

    // Only process standard queries (QR=0, Opcode=0)
    if (flags & 0xF800) != 0 { return; }
    if qdcount == 0 { return; }

    // Extract QNAME from first question
    let mut offset = DNS_HEADER_LEN;
    let mut name_buf = [0u8; MAX_NAME_LEN + 1];
    let name_len = extract_qname(pkt, pkt_len, &mut offset, name_buf.as_mut_ptr());
    if name_len == 0 { return; }

    // Parse QTYPE and QCLASS
    if offset + 4 > pkt_len { return; }
    let qtype = u16::from_be_bytes([*pkt.add(offset), *pkt.add(offset + 1)]);
    let qclass = u16::from_be_bytes([*pkt.add(offset + 2), *pkt.add(offset + 3)]);
    let question_end = offset + 4;

    // Only handle IN class
    if qclass != QCLASS_IN {
        // Forward unknown classes
        forward_to_upstream(s, id, client_ip, client_port, pkt, pkt_len);
        return;
    }

    // Use raw pointer to tx_buf to avoid borrow checker issues
    let tx_ptr = (*s).tx_buf.as_mut_ptr();

    match qtype {
        QTYPE_A => {
            // Look up in local host table
            match lookup_host(s, name_buf.as_ptr(), name_len) {
                Some(ip) => {
                    // Build and send local A response
                    let resp_len = build_a_response(
                        s, pkt, pkt_len, question_end, ip,
                        tx_ptr,
                    );
                    if resp_len > 0 {
                        send_server_reply(s as *mut DnsState, client_ip, client_port,
                            tx_ptr as *const u8, resp_len);
                        s.queries_local += 1;
                    }
                }
                None => {
                    // Forward to upstream
                    forward_to_upstream(s, id, client_ip, client_port, pkt, pkt_len);
                }
            }
        }
        QTYPE_AAAA => {
            // Check if it's a local host — if so, send empty response (no AAAA record)
            // instead of forwarding to upstream
            if lookup_host(s, name_buf.as_ptr(), name_len).is_some() {
                // Send empty response (no answer, no error) — host exists but no IPv6
                let resp_len = build_empty_response(
                    pkt, pkt_len,
                    tx_ptr,
                );
                if resp_len > 0 {
                    send_server_reply(s as *mut DnsState, client_ip, client_port,
                        tx_ptr as *const u8, resp_len);
                }
            } else {
                forward_to_upstream(s, id, client_ip, client_port, pkt, pkt_len);
            }
        }
        QTYPE_PTR => {
            // Reverse lookup
            match lookup_ptr(s, name_buf.as_ptr(), name_len) {
                Some((_ip, host_idx)) => {
                    let resp_len = build_ptr_response(
                        s, pkt, pkt_len, question_end, host_idx,
                        tx_ptr,
                    );
                    if resp_len > 0 {
                        send_server_reply(s as *mut DnsState, client_ip, client_port,
                            tx_ptr as *const u8, resp_len);
                        s.queries_local += 1;
                    }
                }
                None => {
                    forward_to_upstream(s, id, client_ip, client_port, pkt, pkt_len);
                }
            }
        }
        _ => {
            // Forward all other types to upstream
            forward_to_upstream(s, id, client_ip, client_port, pkt, pkt_len);
        }
    }
}

/// Build an empty response (NOERROR, 0 answers) for local hosts with no matching record type.
unsafe fn build_empty_response(
    query_pkt: *const u8,
    query_len: usize,
    tx: *mut u8,
) -> usize {
    if query_len < DNS_HEADER_LEN { return 0; }

    let copy_len = query_len.min(DNS_MAX_PACKET);
    let mut i = 0;
    while i < copy_len {
        *tx.add(i) = *query_pkt.add(i);
        i += 1;
    }

    // Set flags: QR=1, AA=1, RA=1, RCODE=0 (NOERROR), preserve RD
    let flags = u16::from_be_bytes([*query_pkt.add(2), *query_pkt.add(3)]);
    let new_flags = FLAG_QR | FLAG_AA | FLAG_RA | (flags & FLAG_RD);
    let fb = new_flags.to_be_bytes();
    *tx.add(2) = fb[0];
    *tx.add(3) = fb[1];

    // No answers
    *tx.add(6) = 0; *tx.add(7) = 0;
    *tx.add(8) = 0; *tx.add(9) = 0;
    *tx.add(10) = 0; *tx.add(11) = 0;

    copy_len
}

/// Forward a query to the upstream DNS server.
unsafe fn forward_to_upstream(
    s: &mut DnsState,
    dns_id: u16,
    client_ip: u32,
    client_port: u16,
    pkt: *const u8,
    pkt_len: usize,
) {
    if s.upstream_ep == 0xFF { return; }

    // Store pending entry
    store_pending(s, dns_id, client_ip, client_port);

    // Send query to upstream via CMD_DG_SEND_TO on the upstream endpoint.
    send_upstream_query(s as *mut DnsState, pkt, pkt_len);
    s.queries_forwarded += 1;
}

/// Process a response from the upstream DNS server.
unsafe fn handle_upstream_response(s: &mut DnsState, pkt: *const u8, pkt_len: usize) {
    if pkt_len < DNS_HEADER_LEN { return; }

    let id = u16::from_be_bytes([*pkt, *pkt.add(1)]);

    // Find the pending query for this transaction ID
    if let Some((client_ip, client_port)) = take_pending(s, id) {
        // Relay response back to original client via server conn
        send_server_reply(s as *mut DnsState, client_ip, client_port, pkt, pkt_len);
    }
}

// ============================================================================
// PIC Module Interface
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<DnsState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
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
        if syscalls.is_null() { return -2; }
        if state.is_null() { return -5; }
        if state_size < core::mem::size_of::<DnsState>() { return -6; }

        let s = &mut *(state as *mut DnsState);
        s.init(syscalls as *const SyscallTable);

        // Net channels: in[0] = net_in (from IP), out[0] = net_out (to IP)
        s.net_in_chan = in_chan;
        s.net_out_chan = out_chan;

        // Parse TLV params
        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        log_info(s, b"[dns] init");

        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() { return -1; }
        let s = &mut *(state as *mut DnsState);
        if s.syscalls.is_null() { return -1; }

        match s.phase {
            DnsPhase::Init => {
                s.phase = DnsPhase::BindingServer;
            }

            DnsPhase::BindingServer => {
                // CMD_DG_BIND [port: u16 LE] [flags: u8=0] — server port.
                if s.net_out_chan < 0 { return 0; }
                let sys = &*s.syscalls;
                let buf = s.net_buf.as_mut_ptr();
                let mut payload = [0u8; 3];
                let pp = payload.as_mut_ptr();
                let port_bytes = s.listen_port.to_le_bytes();
                *pp = port_bytes[0];
                *pp.add(1) = port_bytes[1];
                *pp.add(2) = 0; // flags
                let wrote = net_write_frame(
                    sys, s.net_out_chan, DG_CMD_BIND,
                    payload.as_ptr(), 3, buf, NET_BUF_SIZE,
                );
                if wrote == 0 { return 0; }
                s.phase = DnsPhase::WaitBoundServer;
                return 2;
            }

            DnsPhase::WaitBoundServer => {
                if s.net_in_chan < 0 { return 0; }
                let sys = &*s.syscalls;
                let chan = s.net_in_chan;
                let poll = (sys.channel_poll)(chan, POLL_IN);
                if poll <= 0 || (poll as u32 & POLL_IN) == 0 { return 0; }

                let buf = s.net_buf.as_mut_ptr();
                let (msg_type, payload_len) = net_read_frame(sys, chan, buf, NET_BUF_SIZE);
                if msg_type == DG_MSG_BOUND && payload_len >= 1 {
                    s.server_ep = *buf.add(NET_FRAME_HDR);
                    log_info(s, b"[dns] server bound");
                    s.phase = DnsPhase::BindingUpstream;
                    return 2;
                } else if msg_type == DG_MSG_ERROR {
                    log_err(s, b"[dns] server bind failed");
                    s.phase = DnsPhase::Error;
                    return -1;
                }
            }

            DnsPhase::BindingUpstream => {
                // CMD_DG_BIND with port=0 asks the IP module to allocate an
                // ephemeral port for the upstream endpoint.
                if s.net_out_chan < 0 { return 0; }
                let sys = &*s.syscalls;
                let buf = s.net_buf.as_mut_ptr();
                let payload = [0u8, 0u8, 0u8]; // port=0, flags=0
                let wrote = net_write_frame(
                    sys, s.net_out_chan, DG_CMD_BIND,
                    payload.as_ptr(), 3, buf, NET_BUF_SIZE,
                );
                if wrote == 0 { return 0; }
                s.phase = DnsPhase::WaitBoundUpstream;
            }

            DnsPhase::WaitBoundUpstream => {
                if s.net_in_chan < 0 { return 0; }
                let sys = &*s.syscalls;
                let chan = s.net_in_chan;
                let poll = (sys.channel_poll)(chan, POLL_IN);
                if poll <= 0 || (poll as u32 & POLL_IN) == 0 { return 0; }

                let buf = s.net_buf.as_mut_ptr();
                let (msg_type, payload_len) = net_read_frame(sys, chan, buf, NET_BUF_SIZE);
                if msg_type == DG_MSG_BOUND && payload_len >= 1 {
                    s.upstream_ep = *buf.add(NET_FRAME_HDR);
                    log_info(s, b"[dns] serving");
                    s.phase = DnsPhase::Serving;
                    return 2;
                } else if msg_type == DG_MSG_ERROR {
                    log_err(s, b"[dns] upstream bind failed");
                    s.phase = DnsPhase::Error;
                    return -1;
                }
            }

            DnsPhase::Serving => {
                let mut did_work = false;

                // Read datagram frames from net_in channel.
                let chan = s.net_in_chan;
                if chan < 0 { return 0; }

                let sys = &*s.syscalls;
                let poll = (sys.channel_poll)(chan, POLL_IN);
                if poll > 0 && (poll as u32 & POLL_IN) != 0 {
                    let buf = s.net_buf.as_mut_ptr();
                    let (msg_type, payload_len) = net_read_frame(sys, chan, buf, NET_BUF_SIZE);

                    // MSG_DG_RX_FROM payload:
                    //   [ep_id:1][af:1=4][src_addr:4 BE][src_port:2 LE][dns_data...]
                    if msg_type == DG_MSG_RX_FROM
                        && payload_len >= DG_V4_PREFIX + DNS_HEADER_LEN
                    {
                        let ep_id = *buf.add(NET_FRAME_HDR);
                        let af = *buf.add(NET_FRAME_HDR + 1);
                        if af == DG_AF_INET {
                            let p = buf.add(NET_FRAME_HDR + 2);
                            let src_ip = u32::from_be_bytes([
                                *p, *p.add(1), *p.add(2), *p.add(3),
                            ]);
                            let src_port = u16::from_le_bytes([
                                *p.add(4), *p.add(5),
                            ]);
                            let dns_data = buf.add(NET_FRAME_HDR + DG_V4_PREFIX) as *const u8;
                            let dns_len = payload_len - DG_V4_PREFIX;

                            if ep_id == s.server_ep {
                                handle_query(s, src_ip, src_port, dns_data, dns_len);
                            } else if ep_id == s.upstream_ep {
                                handle_upstream_response(s, dns_data, dns_len);
                            }
                            did_work = true;
                        }
                    }
                }

                // Expire old pending queries periodically
                expire_pending(s);

                if did_work {
                    return 2; // Burst — handle remaining queries
                }
            }

            DnsPhase::Error => {
                return 1; // Done
            }
        }

        0 // Continue
    }
}
