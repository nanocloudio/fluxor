//! DNS Server PIC Module
//!
//! Resolves configured hostnames locally, forwards everything else to an
//! upstream DNS server (default 8.8.8.8).
//!
//! # Architecture
//!
//! Uses two UDP sockets:
//! - **Server socket** — bound to port 53, unconnected (framed mode)
//!   Receives queries from any client with `[src_ip:4][src_port:2][len:2][payload]`
//! - **Upstream socket** — connected to upstream DNS (raw mode)
//!   Forwards non-local queries and relays responses
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

#[path = "../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../pic_runtime.rs");
include!("../param_macro.rs");

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

/// Framed UDP header size: [ip:4][port:2][len:2]
const FRAME_HDR_LEN: usize = 8;

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
    OpenServer = 1,
    WaitBind = 2,
    OpenUpstream = 3,
    WaitConnect = 4,
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
    in_chan: i32,
    out_chan: i32,
    server_sock: i32,
    upstream_sock: i32,

    upstream_ip: u32,
    ttl: u32,
    listen_port: u16,
    phase: DnsPhase,
    host_count: u8,

    // Statistics
    queries_local: u32,
    queries_forwarded: u32,

    // Host table
    hosts: [HostEntry; MAX_HOSTS],

    // Pending upstream queries
    pending: [PendingQuery; MAX_PENDING],

    // Packet buffers
    rx_buf: [u8; DNS_MAX_PACKET + FRAME_HDR_LEN],
    tx_buf: [u8; DNS_MAX_PACKET + FRAME_HDR_LEN],
}

impl DnsState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.in_chan = -1;
        self.out_chan = -1;
        self.server_sock = -1;
        self.upstream_sock = -1;
        self.upstream_ip = 0x08080808; // 8.8.8.8
        self.ttl = 300;
        self.listen_port = 53;
        self.phase = DnsPhase::Init;
        self.host_count = 0;
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

/// Send a DNS packet via the framed server socket.
/// Prepends [dst_ip:4][dst_port:2][len:2] header.
unsafe fn send_framed(
    s: &mut DnsState,
    dst_ip: u32,
    dst_port: u16,
    dns_data: *const u8,
    dns_len: usize,
) {
    let total = FRAME_HDR_LEN + dns_len;
    if total > s.tx_buf.len() { return; }

    let buf = s.tx_buf.as_mut_ptr();

    // Frame header
    let ip_bytes = dst_ip.to_le_bytes();
    *buf = ip_bytes[0]; *buf.add(1) = ip_bytes[1];
    *buf.add(2) = ip_bytes[2]; *buf.add(3) = ip_bytes[3];
    let port_bytes = dst_port.to_le_bytes();
    *buf.add(4) = port_bytes[0]; *buf.add(5) = port_bytes[1];
    let len_bytes = (dns_len as u16).to_le_bytes();
    *buf.add(6) = len_bytes[0]; *buf.add(7) = len_bytes[1];

    // Copy DNS payload
    let mut i = 0;
    while i < dns_len {
        *buf.add(FRAME_HDR_LEN + i) = *dns_data.add(i);
        i += 1;
    }

    dev_socket_send(s.sys(), s.server_sock, buf as *const u8, total);
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
                        tx_ptr.add(FRAME_HDR_LEN),
                    );
                    if resp_len > 0 {
                        send_framed(s, client_ip, client_port,
                            tx_ptr.add(FRAME_HDR_LEN) as *const u8, resp_len);
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
                    tx_ptr.add(FRAME_HDR_LEN),
                );
                if resp_len > 0 {
                    send_framed(s, client_ip, client_port,
                        tx_ptr.add(FRAME_HDR_LEN) as *const u8, resp_len);
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
                        tx_ptr.add(FRAME_HDR_LEN),
                    );
                    if resp_len > 0 {
                        send_framed(s, client_ip, client_port,
                            tx_ptr.add(FRAME_HDR_LEN) as *const u8, resp_len);
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
    if s.upstream_sock < 0 { return; }

    // Store pending entry
    store_pending(s, dns_id, client_ip, client_port);

    // Send query to upstream via connected socket (raw mode)
    dev_socket_send(s.sys(), s.upstream_sock, pkt, pkt_len);
    s.queries_forwarded += 1;
}

/// Process a response from the upstream DNS server.
unsafe fn handle_upstream_response(s: &mut DnsState, pkt: *const u8, pkt_len: usize) {
    if pkt_len < DNS_HEADER_LEN { return; }

    let id = u16::from_be_bytes([*pkt, *pkt.add(1)]);

    // Find the pending query for this transaction ID
    if let Some((client_ip, client_port)) = take_pending(s, id) {
        // Relay response back to original client via framed server socket
        send_framed(s, client_ip, client_port, pkt, pkt_len);
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
        s.in_chan = in_chan;
        s.out_chan = out_chan;

        // Parse TLV params
        let is_tlv_v2 = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x02;
        if is_tlv_v2 {
            params_def::parse_tlv_v2(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        log_info(s, b"[dns] ready");

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
                s.phase = DnsPhase::OpenServer;
            }

            DnsPhase::OpenServer => {
                let handle = dev_socket_open(s.sys(), SOCK_TYPE_DGRAM);
                if handle < 0 {
                    log_err(s, b"[dns] server socket_open failed");
                    s.phase = DnsPhase::Error;
                    return -1;
                }
                s.server_sock = handle;

                // Bind to listen port
                let rc = dev_socket_bind(s.sys(), handle, s.listen_port);
                if rc < 0 && rc != E_INPROGRESS {
                    log_err(s, b"[dns] bind failed");
                    s.phase = DnsPhase::Error;
                    return -1;
                }
                s.phase = DnsPhase::WaitBind;
            }

            DnsPhase::WaitBind => {
                // Bind completes synchronously for UDP
                // Move on to open upstream socket
                s.phase = DnsPhase::OpenUpstream;
            }

            DnsPhase::OpenUpstream => {
                let handle = dev_socket_open(s.sys(), SOCK_TYPE_DGRAM);
                if handle < 0 {
                    log_err(s, b"[dns] upstream socket_open failed");
                    s.phase = DnsPhase::Error;
                    return -1;
                }
                s.upstream_sock = handle;

                // Connect to upstream DNS server
                let mut addr = [0u8; 6];
                let ap = addr.as_mut_ptr();
                let ip_bytes = s.upstream_ip.to_le_bytes();
                *ap = ip_bytes[0]; *ap.add(1) = ip_bytes[1];
                *ap.add(2) = ip_bytes[2]; *ap.add(3) = ip_bytes[3];
                // Port 53
                let port_bytes = 53u16.to_le_bytes();
                *ap.add(4) = port_bytes[0]; *ap.add(5) = port_bytes[1];

                let rc = dev_socket_connect(s.sys(), handle, addr.as_mut_ptr());
                if rc < 0 && rc != E_INPROGRESS {
                    log_err(s, b"[dns] upstream connect failed");
                    s.phase = DnsPhase::Error;
                    return -1;
                }
                s.phase = DnsPhase::WaitConnect;
            }

            DnsPhase::WaitConnect => {
                let poll = dev_socket_poll(s.sys(), s.upstream_sock, POLL_CONN);
                if poll <= 0 { return 0; }
                if (poll as u8 & POLL_CONN) != 0 {
                    log_info(s, b"[dns] serving");
                    s.phase = DnsPhase::Serving;
                }
            }

            DnsPhase::Serving => {
                let mut did_work = false;
                let sys = s.syscalls;
                let rx_ptr = s.rx_buf.as_mut_ptr();
                let rx_len = s.rx_buf.len();

                // Poll server socket for incoming queries
                let poll = dev_socket_poll(&*sys, s.server_sock, POLL_IN);
                if poll > 0 && (poll as u8 & POLL_IN) != 0 {
                    // Read framed data: [src_ip:4][src_port:2][len:2][payload]
                    let n = dev_socket_recv(&*sys, s.server_sock, rx_ptr, rx_len);
                    if n >= FRAME_HDR_LEN as i32 {
                        let buf = rx_ptr as *const u8;
                        let client_ip = u32::from_le_bytes([
                            *buf, *buf.add(1), *buf.add(2), *buf.add(3)
                        ]);
                        let client_port = u16::from_le_bytes([
                            *buf.add(4), *buf.add(5)
                        ]);
                        let payload_len = u16::from_le_bytes([
                            *buf.add(6), *buf.add(7)
                        ]) as usize;

                        let actual_payload = (n as usize) - FRAME_HDR_LEN;
                        let dns_len = payload_len.min(actual_payload);

                        if dns_len >= DNS_HEADER_LEN {
                            handle_query(
                                s, client_ip, client_port,
                                buf.add(FRAME_HDR_LEN), dns_len,
                            );
                        }
                        did_work = true;
                    }
                }

                // Poll upstream socket for responses
                let poll = dev_socket_poll(&*sys, s.upstream_sock, POLL_IN);
                if poll > 0 && (poll as u8 & POLL_IN) != 0 {
                    let n = dev_socket_recv(&*sys, s.upstream_sock, rx_ptr, DNS_MAX_PACKET);
                    if n > 0 {
                        handle_upstream_response(s, rx_ptr as *const u8, n as usize);
                        did_work = true;
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

            _ => {
                s.phase = DnsPhase::Error;
                return -1;
            }
        }

        0 // Continue
    }
}
