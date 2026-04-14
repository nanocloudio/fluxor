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

/// Reorder buffer: number of slots and bytes per slot.
pub const REORDER_SLOTS: usize = 4;
pub const REORDER_SLOT_BYTES: usize = 512;

/// A single out-of-order segment held for reassembly.
pub struct ReorderSlot {
    pub seq: u32,
    pub len: u16,
    pub valid: bool,
}

impl ReorderSlot {
    pub const fn empty() -> Self {
        Self { seq: 0, len: 0, valid: false }
    }
}

/// TCP connection block (one per socket)
pub struct TcpConn {
    pub state: TcpState,
    pub local_port: u16,
    pub remote_port: u16,
    pub remote_ip: u32,

    // Send sequence variables
    pub snd_una: u32,   // oldest unacknowledged
    pub snd_nxt: u32,   // next to send
    pub snd_wnd: u16,   // peer's advertised receive window

    // Receive sequence variables
    pub rcv_nxt: u32,   // next expected
    pub rcv_wnd: u16,   // our receive window advertisement

    pub iss: u32,
    pub retransmit_timer: u16,
    pub timewait_timer: u16,

    // NewReno congestion control (§4.2)
    pub cwnd: u16,              // congestion window (bytes)
    pub ssthresh: u16,          // slow-start threshold
    pub dup_ack_count: u8,      // consecutive duplicate ACKs
    pub in_recovery: bool,
    pub recover_seq: u32,       // snd_nxt at recovery entry

    // Jacobson/Karn RTT estimation (RFC 6298). Values are in step ticks
    // using a 3-bit fixed-point shift (srtt = RTT * 8).
    pub srtt: u16,
    pub rttvar: u16,
    pub rto: u16,
    pub rtt_seq: u32,
    pub rtt_start: u16,
    pub rtt_active: bool,

    // Dynamic receive window bookkeeping (§4.3). `delivered_bytes` is the
    // total written to the consumer channel for this connection;
    // `consumed_bytes` tracks what the consumer has read.
    pub delivered_bytes: u32,
    pub consumed_bytes: u32,

    // Bounded reorder buffer (§4.1). Per-slot payload storage lives in
    // `reorder_buf`; metadata in `reorder_slots`.
    pub reorder_slots: [ReorderSlot; REORDER_SLOTS],
    pub reorder_buf: [u8; REORDER_SLOTS * REORDER_SLOT_BYTES],
}

impl TcpConn {
    pub const fn new() -> Self {
        const EMPTY: ReorderSlot = ReorderSlot::empty();
        Self {
            state: TcpState::Closed,
            local_port: 0,
            remote_port: 0,
            remote_ip: 0,
            snd_una: 0,
            snd_nxt: 0,
            snd_wnd: 0,
            rcv_nxt: 0,
            rcv_wnd: INITIAL_RCV_WND,
            iss: 0,
            retransmit_timer: 0,
            timewait_timer: 0,
            cwnd: MSS,
            ssthresh: 0xFFFF,
            dup_ack_count: 0,
            in_recovery: false,
            recover_seq: 0,
            srtt: 0,
            rttvar: 0,
            rto: RTO_INITIAL,
            rtt_seq: 0,
            rtt_start: 0,
            rtt_active: false,
            delivered_bytes: 0,
            consumed_bytes: 0,
            reorder_slots: [EMPTY; REORDER_SLOTS],
            reorder_buf: [0u8; REORDER_SLOTS * REORDER_SLOT_BYTES],
        }
    }

    pub fn is_active(&self) -> bool {
        self.state != TcpState::Closed
    }
}

/// Path MSS used for cwnd accounting (conservative lower bound below Ethernet MTU).
pub const MSS: u16 = 1460;

/// Starting receive window. Grows dynamically up to MAX_RCV_WND.
pub const INITIAL_RCV_WND: u16 = 2048;

/// Upper bound on the advertised receive window.
pub const MAX_RCV_WND: u16 = 8192;

/// Initial retransmission timeout in step ticks (≈1 s at 1 kHz).
pub const RTO_INITIAL: u16 = 1000;

/// Minimum and maximum RTO clamps (step ticks).
pub const RTO_MIN: u16 = 200;
pub const RTO_MAX: u16 = 6000;

/// Maximum TCP connections
pub const MAX_TCP_CONNS: usize = 8;

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

// ============================================================================
// Sequence arithmetic helpers
// ============================================================================

/// Returns true if `a` is before `b` modulo 2^32 (standard TCP ordering).
#[inline]
pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

// ============================================================================
// Reorder buffer (§4.1)
// ============================================================================

/// Store an out-of-order segment in the reorder buffer. Returns true if the
/// segment was buffered, false if there is no slot (caller drops it).
pub unsafe fn reorder_insert(conn: &mut TcpConn, seq: u32, payload: *const u8, len: usize) -> bool {
    if len == 0 || len > REORDER_SLOT_BYTES { return false; }
    // Reject duplicates and overlaps — overlap detection defends against
    // reassembly-based injection.
    let mut i = 0;
    while i < REORDER_SLOTS {
        let slot = &conn.reorder_slots[i];
        if slot.valid {
            let end = slot.seq.wrapping_add(slot.len as u32);
            // New seg fully inside existing?
            if !seq_lt(seq, slot.seq) && seq_lt(seq.wrapping_add(len as u32), end.wrapping_add(1)) {
                return true; // already buffered
            }
            // Any overlap at all — reject to avoid overwrite attacks.
            let new_end = seq.wrapping_add(len as u32);
            if seq_lt(seq, end) && seq_lt(slot.seq, new_end) {
                return false;
            }
        }
        i += 1;
    }
    // Find a free slot.
    let mut slot_idx: Option<usize> = None;
    i = 0;
    while i < REORDER_SLOTS {
        if !conn.reorder_slots[i].valid { slot_idx = Some(i); break; }
        i += 1;
    }
    let si = match slot_idx {
        Some(v) => v,
        None => return false, // all slots full — drop (caller ACKs to re-trigger)
    };
    let off = si * REORDER_SLOT_BYTES;
    let dst = conn.reorder_buf.as_mut_ptr().add(off);
    core::ptr::copy_nonoverlapping(payload, dst, len);
    conn.reorder_slots[si].seq = seq;
    conn.reorder_slots[si].len = len as u16;
    conn.reorder_slots[si].valid = true;
    true
}

/// Pop the next in-order segment from the reorder buffer if its seq matches
/// `rcv_nxt`. Returns (ptr, len) on hit, None otherwise. The returned pointer
/// is valid until the next `reorder_insert` or `reorder_take_next`.
pub unsafe fn reorder_take_next<'a>(conn: &'a mut TcpConn, rcv_nxt: u32) -> Option<(&'a [u8], u32)> {
    let mut i = 0;
    while i < REORDER_SLOTS {
        if conn.reorder_slots[i].valid && conn.reorder_slots[i].seq == rcv_nxt {
            let len = conn.reorder_slots[i].len as usize;
            let off = i * REORDER_SLOT_BYTES;
            let next_seq = rcv_nxt.wrapping_add(len as u32);
            conn.reorder_slots[i].valid = false;
            let slice = core::slice::from_raw_parts(conn.reorder_buf.as_ptr().add(off), len);
            return Some((slice, next_seq));
        }
        i += 1;
    }
    None
}

// ============================================================================
// Congestion control (§4.2) — NewReno
// ============================================================================

/// Minimum useful cwnd per RFC 5681 after a loss event.
#[inline]
pub fn cwnd_min() -> u16 { 2 * MSS }

/// Handler for a new ACK that advances snd_una. Grows cwnd in slow start
/// or congestion avoidance per RFC 5681.
pub fn on_new_ack(conn: &mut TcpConn) {
    conn.dup_ack_count = 0;
    if conn.in_recovery && !seq_lt(conn.snd_una, conn.recover_seq) {
        conn.in_recovery = false;
        conn.cwnd = conn.ssthresh;
        return;
    }
    if conn.cwnd < conn.ssthresh {
        // Slow start — exponential.
        conn.cwnd = conn.cwnd.saturating_add(MSS);
    } else {
        // Congestion avoidance — ~1 MSS per RTT.
        let inc = ((MSS as u32) * (MSS as u32) / (conn.cwnd as u32).max(1)) as u16;
        conn.cwnd = conn.cwnd.saturating_add(inc.max(1));
    }
}

/// Handler for a duplicate ACK (ack == snd_una, no new data). Returns true
/// when fast-retransmit should fire.
pub fn on_dup_ack(conn: &mut TcpConn) -> bool {
    if conn.in_recovery {
        conn.cwnd = conn.cwnd.saturating_add(MSS);
        return false;
    }
    conn.dup_ack_count = conn.dup_ack_count.saturating_add(1);
    if conn.dup_ack_count == 3 {
        conn.ssthresh = (conn.cwnd / 2).max(cwnd_min());
        conn.cwnd = conn.ssthresh.saturating_add(3 * MSS);
        conn.in_recovery = true;
        conn.recover_seq = conn.snd_nxt;
        return true;
    }
    false
}

/// Handler for an RTO timeout — collapses cwnd to slow start.
pub fn on_rto(conn: &mut TcpConn) {
    conn.ssthresh = (conn.cwnd / 2).max(cwnd_min());
    conn.cwnd = MSS;
    conn.dup_ack_count = 0;
    conn.in_recovery = false;
}

/// Effective send window — minimum of peer's advertised window and cwnd.
#[inline]
pub fn effective_snd_wnd(conn: &TcpConn) -> u16 {
    core::cmp::min(conn.snd_wnd, conn.cwnd)
}

// ============================================================================
// RTT estimation (RFC 6298)
// ============================================================================

/// Update RTT estimator with a measured sample (step ticks). Fixed-point
/// srtt/rttvar with 3-bit shift (srtt = R * 8).
pub fn rtt_update(conn: &mut TcpConn, sample_ticks: u16) {
    let r = sample_ticks as u32;
    if conn.srtt == 0 {
        conn.srtt = (r << 3) as u16;
        conn.rttvar = (r << 2) as u16;
    } else {
        let srtt_shifted = (conn.srtt >> 3) as u32;
        let delta = if r > srtt_shifted { r - srtt_shifted } else { srtt_shifted - r };
        // rttvar = rttvar - (rttvar >> 2) + delta
        conn.rttvar = (conn.rttvar as u32)
            .wrapping_sub((conn.rttvar as u32) >> 2)
            .wrapping_add(delta) as u16;
        // srtt = srtt - (srtt >> 3) + R
        conn.srtt = (conn.srtt as u32)
            .wrapping_sub((conn.srtt as u32) >> 3)
            .wrapping_add(r) as u16;
    }
    // RTO = SRTT + 4 * RTTVAR (both fixed-point)
    let rto_raw = ((conn.srtt >> 3) as u32).saturating_add(conn.rttvar as u32);
    let rto = rto_raw.min(RTO_MAX as u32).max(RTO_MIN as u32) as u16;
    conn.rto = rto;
}

/// Called when sending a segment — start an RTT measurement if one is not
/// already active (Karn's algorithm: never time a retransmit).
pub fn rtt_arm(conn: &mut TcpConn, seq: u32, step_tick: u16) {
    if !conn.rtt_active {
        conn.rtt_seq = seq;
        conn.rtt_start = step_tick;
        conn.rtt_active = true;
    }
}

/// Called when `ack` arrives. If it acknowledges the timed sequence, sample
/// the RTT and update the estimator.
pub fn rtt_ack(conn: &mut TcpConn, ack: u32, step_tick: u16) {
    if conn.rtt_active && !seq_lt(ack, conn.rtt_seq.wrapping_add(1)) {
        let sample = step_tick.wrapping_sub(conn.rtt_start);
        rtt_update(conn, sample);
        conn.rtt_active = false;
    }
}
