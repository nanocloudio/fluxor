//! TCP protocol — minimal connection-oriented transport.
//!
//! Implements a basic TCP state machine for client and server connections.

use super::ipv4;

/// TCP header minimum length (no options)
pub const TCP_HEADER_LEN: usize = 20;

/// TCP flags
pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

/// TCP connection states (RFC 793 §3.2).
///
// ════════════════════════════════════════════════════════════════
// TCP State Transitions (RFC 793, simplified)
// ════════════════════════════════════════════════════════════════
//
// State        | Trigger              | Next          | Action
// ─────────────|──────────────────────|───────────────|────────────────
// Closed       | active open          | SynSent       | send SYN
// Closed       | passive open         | Listen        |
// Listen       | recv SYN             | SynReceived   | send SYN+ACK
// SynSent      | recv SYN+ACK        | Established   | send ACK
// SynReceived  | recv ACK             | Established   |
// Established  | close()              | FinWait1      | send FIN
// Established  | recv FIN             | CloseWait     | send ACK
// FinWait1     | recv ACK of FIN      | FinWait2      |
// FinWait1     | recv FIN             | TimeWait      | send ACK
// FinWait2     | recv FIN             | TimeWait      | send ACK
// CloseWait    | close()              | LastAck       | send FIN
// LastAck      | recv ACK of FIN      | Closed        |
// TimeWait     | timeout (2×MSL)      | Closed        |
//
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed = 0,
    SynSent = 1,
    Established = 2,
    FinWait1 = 3,
    FinWait2 = 4,
    CloseWait = 5,
    LastAck = 6,
    TimeWait = 7,
    Listen = 8,
    SynReceived = 9,
}

/// TCP connection block (one per socket)
#[derive(Clone, Copy)]
pub struct TcpConn {
    pub state: TcpState,
    pub local_port: u16,
    pub remote_port: u16,
    pub remote_ip: u32,
    /// Send sequence variables
    pub snd_una: u32,  // oldest unacknowledged
    pub snd_nxt: u32,  // next to send
    pub snd_wnd: u16,  // send window
    /// Receive sequence variables
    pub rcv_nxt: u32,  // next expected
    pub rcv_wnd: u16,  // receive window
    /// Initial sequence numbers
    pub iss: u32,
    /// Retransmit timer (step counts)
    pub retransmit_timer: u16,
    /// Time-wait timer
    pub timewait_timer: u16,
}

impl TcpConn {
    pub const fn new() -> Self {
        Self {
            state: TcpState::Closed,
            local_port: 0,
            remote_port: 0,
            remote_ip: 0,
            snd_una: 0,
            snd_nxt: 0,
            snd_wnd: 0,
            rcv_nxt: 0,
            rcv_wnd: 512, // match socket buffer size
            iss: 0,
            retransmit_timer: 0,
            timewait_timer: 0,
        }
    }

    pub fn is_active(&self) -> bool {
        self.state != TcpState::Closed
    }
}

/// Maximum TCP connections
pub const MAX_TCP_CONNS: usize = 4;

/// Parsed TCP header
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: usize,
    pub flags: u8,
    pub window: u16,
    pub payload_offset: usize,
    pub payload_len: usize,
}

/// Parse a TCP header from raw data.
///
/// # Safety
/// `data` must point to at least `len` valid bytes of TCP data (after IP header).
pub unsafe fn parse_tcp(data: *const u8, len: usize) -> Option<TcpHeader> {
    if len < TCP_HEADER_LEN {
        return None;
    }

    let src_port = (*data as u16) << 8 | (*data.add(1) as u16);
    let dst_port = (*data.add(2) as u16) << 8 | (*data.add(3) as u16);
    let seq_num = u32::from_be_bytes([
        *data.add(4), *data.add(5), *data.add(6), *data.add(7),
    ]);
    let ack_num = u32::from_be_bytes([
        *data.add(8), *data.add(9), *data.add(10), *data.add(11),
    ]);
    let data_offset_raw = *data.add(12);
    let data_offset = ((data_offset_raw >> 4) as usize) * 4;
    let flags = *data.add(13);
    let window = (*data.add(14) as u16) << 8 | (*data.add(15) as u16);

    if data_offset < TCP_HEADER_LEN || data_offset > len {
        return None;
    }

    let payload_len = len - data_offset;

    Some(TcpHeader {
        src_port,
        dst_port,
        seq_num,
        ack_num,
        data_offset,
        flags,
        window,
        payload_offset: data_offset,
        payload_len,
    })
}

/// Find a TCP connection matching the incoming segment.
/// # Safety
/// `conns` must point to a valid array of at least `MAX_TCP_CONNS` entries.
pub unsafe fn find_conn(
    conns: &[TcpConn; MAX_TCP_CONNS],
    remote_ip: u32,
    remote_port: u16,
    local_port: u16,
) -> Option<usize> {
    let mut i = 0;
    while i < MAX_TCP_CONNS {
        let c = &*conns.as_ptr().add(i);
        if c.is_active()
            && c.remote_ip == remote_ip
            && c.remote_port == remote_port
            && c.local_port == local_port
        {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Find a listening TCP connection matching the destination port.
pub unsafe fn find_listener(
    conns: &[TcpConn; MAX_TCP_CONNS],
    local_port: u16,
) -> Option<usize> {
    let mut i = 0;
    while i < MAX_TCP_CONNS {
        let c = &*conns.as_ptr().add(i);
        if c.state == TcpState::Listen && c.local_port == local_port {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Build a TCP header at `dst`. Does NOT compute checksum — caller must
/// call `compute_tcp_checksum` after the full segment (header + payload)
/// is assembled in the frame buffer.
///
/// # Safety
/// `dst` must point to at least 20 writable bytes.
#[inline(never)]
pub unsafe fn build_tcp_header(
    dst: *mut u8,
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
) -> usize {
    use core::ptr::write_volatile as wv;
    wv(dst, (src_port >> 8) as u8);
    wv(dst.add(1), (src_port & 0xFF) as u8);
    wv(dst.add(2), (dst_port >> 8) as u8);
    wv(dst.add(3), (dst_port & 0xFF) as u8);
    let seq = seq_num.to_be_bytes();
    wv(dst.add(4), seq[0]);
    wv(dst.add(5), seq[1]);
    wv(dst.add(6), seq[2]);
    wv(dst.add(7), seq[3]);
    let ack = ack_num.to_be_bytes();
    wv(dst.add(8), ack[0]);
    wv(dst.add(9), ack[1]);
    wv(dst.add(10), ack[2]);
    wv(dst.add(11), ack[3]);
    wv(dst.add(12), 0x50u8);
    wv(dst.add(13), flags);
    wv(dst.add(14), (window >> 8) as u8);
    wv(dst.add(15), (window & 0xFF) as u8);
    wv(dst.add(16), 0u8);
    wv(dst.add(17), 0u8);
    wv(dst.add(18), 0u8);
    wv(dst.add(19), 0u8);

    TCP_HEADER_LEN
}

/// Compute the TCP checksum over a complete segment (header + payload) that
/// has already been assembled in the frame buffer. Every byte is loaded
/// through a volatile read so LLVM cannot rewrite the loop as a NEON/TBL
/// sequence backed by ADRP — which miscompiles in a PIC module.
///
/// # Safety
/// `tcp_start` must point to at least `tcp_seg_len` valid bytes.
#[inline(never)]
pub unsafe fn compute_tcp_checksum(
    tcp_start: *mut u8,
    tcp_seg_len: usize,
    src_ip: u32,
    dst_ip: u32,
) {
    use core::ptr::{read_volatile as rv, write_volatile as wv};

    wv(tcp_start.add(16), 0u8);
    wv(tcp_start.add(17), 0u8);

    let mut sum: u32 = 0;
    sum += (src_ip >> 16) & 0xFFFF;
    sum += src_ip & 0xFFFF;
    sum += (dst_ip >> 16) & 0xFFFF;
    sum += dst_ip & 0xFFFF;
    sum += ipv4::PROTO_TCP as u32;
    sum += tcp_seg_len as u32;

    let mut i: usize = 0;
    while i < tcp_seg_len {
        let b = rv(tcp_start.add(i)) as u32;
        if (i & 1) == 0 { sum += b << 8; } else { sum += b; }
        i += 1;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let cksum = !(sum as u16);

    wv(tcp_start.add(16), (cksum >> 8) as u8);
    wv(tcp_start.add(17), (cksum & 0xFF) as u8);
}
