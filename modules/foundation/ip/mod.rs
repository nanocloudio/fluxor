//! IP Stack Service Module
//!
//! Implements TCP/IP networking as a PIC module. Receives raw ethernet frames
//! from a driver module (e.g. cyw43) via channels, processes ARP/IPv4/ICMP/TCP/UDP,
//! and communicates with consumer modules (HTTP, TLS) via a channel-based net protocol.
//!
//! # Architecture
//!
//! ```text
//! Driver Module (cyw43/enc28j60)           IP Module                    Consumer (HTTP/TLS)
//! ─────────────────────────────           ─────────                    ───────────────────
//! ETH frames → [out_chan] ──────► [in_chan] → ARP/IPv4 parse
//!                                            ├── ICMP echo → reply ──► [out_chan] → driver
//!                                            ├── DHCP reply → config
//!                                            ├── TCP data ────────────► [net_out] MSG_DATA
//!                                            └── UDP datagram ────────► [net_out] MSG_DATA
//! [net_in] CMD_SEND ──────────► TCP/UDP build ──► [out_chan] → driver
//! ```
//!
//! # Channels
//!
//! - `in_chan` (in[0]): Raw ethernet frames from driver module
//! - `out_chan` (out[0]): Raw ethernet frames to driver module
//! - `net_in_chan` (in[1]): Net protocol commands from consumer (CMD_BIND, CMD_SEND, etc.)
//! - `net_out_chan` (out[1]): Net protocol messages to consumer (MSG_DATA, MSG_ACCEPTED, etc.)
//!
//! # Config Parameters
//!
//! | Tag | Name     | Type | Default | Description                |
//! |-----|----------|------|---------|----------------------------|
//! | 1   | use_dhcp | u8   | 1       | Enable DHCP (1=yes, 0=no) |

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

#[allow(dead_code)]
mod eth;
#[allow(dead_code)]
mod arp;
#[allow(dead_code)]
mod ipv4;
#[allow(dead_code)]
mod icmp;
#[allow(dead_code)]
mod udp;
#[allow(dead_code)]
mod tcp;
#[allow(dead_code)]
mod dhcp;

// ============================================================================
// Constants
// ============================================================================

/// Maximum ethernet frame size
const MAX_FRAME_SIZE: usize = 1536;

// NET_FRAME_HDR (3 bytes: msg_type + len u16 LE) defined in pic_runtime.rs

/// Net protocol: downstream messages (IP → consumer)
const NET_MSG_ACCEPTED: u8 = 0x01;
const NET_MSG_DATA: u8 = 0x02;
const NET_MSG_CLOSED: u8 = 0x03;
const NET_MSG_BOUND: u8 = 0x04;
const NET_MSG_CONNECTED: u8 = 0x05;
const NET_MSG_ERROR: u8 = 0x06;
/// Request that the consumer retransmit data from `from_seq` onwards on
/// the named connection. Fires on 3 duplicate ACKs or an RTO timeout.
const NET_MSG_RETRANSMIT: u8 = 0x07;
/// Advance the consumer-side "acknowledged bytes" watermark so the
/// consumer may free its retained send buffer up to this offset.
const NET_MSG_ACK: u8 = 0x08;

/// Net protocol: upstream commands (consumer → IP)
const NET_CMD_BIND: u8 = 0x10;
const NET_CMD_SEND: u8 = 0x11;
const NET_CMD_CLOSE: u8 = 0x12;
const NET_CMD_CONNECT: u8 = 0x13;

/// Netif dev_call opcodes (mirror abi::dev_netif)
const DEV_NETIF_STATE: u32 = 0x0704;

// ============================================================================
// Module State
// ============================================================================

#[repr(C)]
pub struct IpState {
    // Core module fields
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,

    // Config
    use_dhcp: u8,
    _cfg_pad: [u8; 3],

    // Network identity
    mac_addr: [u8; 6],
    mac_valid: bool,
    _mac_pad: u8,
    local_ip: u32,
    netmask: u32,
    gateway: u32,
    dns_server: u32,
    ip_configured: bool,
    signaled_ready: bool,
    _ip_pad: [u8; 2],

    // NetIF handle
    netif_handle: i32,

    // ARP table
    arp_table: [arp::ArpEntry; arp::ARP_TABLE_SIZE],
    arp_pending_ip: u32,
    arp_pending_state: u8,
    arp_pending_timer: u8,
    _arp_pad: [u8; 2],

    // DHCP client
    dhcp: dhcp::DhcpClient,

    // TCP connections
    tcp_conns: [tcp::TcpConn; tcp::MAX_TCP_CONNS],

    // IP identification counter
    ip_id: u16,
    _id_pad: [u8; 2],

    // Net protocol channels (consumer ↔ IP)
    net_in_chan: i32,
    net_out_chan: i32,

    // Net protocol scratch buffer: NET_FRAME_HDR(3) + conn_id(1) + TCP payload.
    net_scratch: [u8; 1600],

    // Frame buffers
    rx_frame: [u8; MAX_FRAME_SIZE],
    tx_frame: [u8; MAX_FRAME_SIZE],
    /// Length of a TX frame staged in `pending_tx_buf` awaiting channel space
    /// (0 = no pending). The frame is held in its own buffer so subsequent
    /// `send_frame` calls can reuse `tx_frame` without clobbering it.
    pending_tx_len: u16,
    _ptx_pad: [u8; 2],
    pending_tx_buf: [u8; MAX_FRAME_SIZE + 2],

    // Step counter for timers
    step_count: u32,

    // Diagnostic counters
    rx_frame_count: u32,
    tx_frame_count: u32,

    // Ephemeral port counter
    next_ephemeral_port: u16,
    _eph_pad: [u8; 2],
}

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::*;

    define_params! {
        IpState;

        1, use_dhcp, u8, 1, enum { no=0, yes=1 }
            => |s, d, len| { s.use_dhcp = p_u8(d, len, 0, 1); };
        2, expected_dhcp_server, u32, 0
            => |s, d, len| { s.dhcp.expected_server = p_u32(d, len, 0, 0); };
    }
}

// ============================================================================
// Helpers
// ============================================================================

unsafe fn log_info(s: &IpState, msg: &[u8]) {
    let sys = &*s.syscalls;
    dev_log(sys, 3, msg.as_ptr(), msg.len());
}

#[allow(dead_code)]
unsafe fn log_error(s: &IpState, msg: &[u8]) {
    let sys = &*s.syscalls;
    dev_log(sys, 1, msg.as_ptr(), msg.len());
}

// Formatting helpers (fmt_u32_raw, fmt_ip_raw) are in pic_runtime.rs

/// Write a net protocol frame to a channel.
/// Frame format: [msg_type: u8] [payload_len: u16 LE] [payload...]
/// Returns 0 on success, -1 on failure.
#[inline(always)]
/// Write a net_proto frame. Module-local variant of pic_runtime::net_write_frame
/// with i32 return (0 or -1) for IP's error handling pattern.
unsafe fn ip_net_write_frame(
    sys: &SyscallTable,
    chan: i32,
    msg_type: u8,
    payload: *const u8,
    payload_len: usize,
    scratch: *mut u8,
) -> i32 {
    // Build frame in scratch: [type][len_lo][len_hi][payload...]
    *scratch = msg_type;
    let pl = (payload_len as u16).to_le_bytes();
    *scratch.add(1) = pl[0];
    *scratch.add(2) = pl[1];
    if payload_len > 0 && !payload.is_null() {
        core::ptr::copy_nonoverlapping(payload, scratch.add(NET_FRAME_HDR), payload_len);
    }
    let total = NET_FRAME_HDR + payload_len;
    let written = (sys.channel_write)(chan, scratch, total);
    if written < total as i32 { -1 } else { 0 }
}

/// Read a net_proto frame header + payload. Module-local variant that reads
/// header and payload in two channel_read calls so the payload goes directly
/// into the caller's buffer without an intermediate copy.
#[inline(always)]
unsafe fn ip_net_read_frame(
    sys: &SyscallTable,
    chan: i32,
    buf: *mut u8,
    buf_cap: usize,
) -> (u8, u16) {
    // Read 3-byte header first, then payload
    let mut hdr = [0u8; 3];
    let n = (sys.channel_read)(chan, hdr.as_mut_ptr(), 3);
    if n < 3 { return (0, 0); }
    let msg_type = *hdr.as_ptr();
    let payload_len = (*hdr.as_ptr().add(1) as u16) | ((*hdr.as_ptr().add(2) as u16) << 8);
    if payload_len > 0 && buf_cap > 0 {
        let to_read = (payload_len as usize).min(buf_cap);
        (sys.channel_read)(chan, buf, to_read);
    }
    (msg_type, payload_len)
}

/// Send a MSG_DATA frame to the net consumer channel.
#[inline(always)]
unsafe fn net_send_data(s: &mut IpState, conn_id: u8, data: *const u8, data_len: usize) {
    if s.net_out_chan < 0 || data_len == 0 {
        return;
    }
    let sys = &*s.syscalls;
    let scratch = s.net_scratch.as_mut_ptr();
    let payload_len = 1 + data_len; // conn_id + data
    let max_copy = s.net_scratch.len() - NET_FRAME_HDR;
    if data_len > max_copy { return; } // safety: don't overflow scratch
    core::ptr::write_volatile(scratch, NET_MSG_DATA);
    let pl = (payload_len as u16).to_le_bytes();
    core::ptr::write_volatile(scratch.add(1), pl[0]);
    core::ptr::write_volatile(scratch.add(2), pl[1]);
    core::ptr::write_volatile(scratch.add(3), conn_id);
    core::ptr::copy_nonoverlapping(data, scratch.add(4), data_len);
    let total = NET_FRAME_HDR + payload_len;
    (sys.channel_write)(s.net_out_chan, scratch, total);
}

/// Send a MSG_DATA frame for a bound UDP conn, prefixed with source addressing:
/// [msg_type:1][len:2 LE][conn_id:1][src_ip:4 LE][src_port:2 LE][data...]
#[inline(always)]
unsafe fn net_send_udp_data(
    s: &mut IpState,
    conn_id: u8,
    src_ip: u32,
    src_port: u16,
    data: *const u8,
    data_len: usize,
) {
    if s.net_out_chan < 0 || data_len == 0 {
        return;
    }
    let sys = &*s.syscalls;
    let scratch = s.net_scratch.as_mut_ptr();
    let payload_len = 1 + 4 + 2 + data_len; // conn_id + ip + port + data
    use core::ptr::write_volatile as wv;
    wv(scratch, NET_MSG_DATA);
    let pl = (payload_len as u16).to_le_bytes();
    wv(scratch.add(1), pl[0]);
    wv(scratch.add(2), pl[1]);
    wv(scratch.add(3), conn_id);
    let ip_bytes = src_ip.to_le_bytes();
    wv(scratch.add(4), ip_bytes[0]);
    wv(scratch.add(5), ip_bytes[1]);
    wv(scratch.add(6), ip_bytes[2]);
    wv(scratch.add(7), ip_bytes[3]);
    let port_bytes = src_port.to_le_bytes();
    wv(scratch.add(8), port_bytes[0]);
    wv(scratch.add(9), port_bytes[1]);
    core::ptr::copy_nonoverlapping(data, scratch.add(10), data_len);
    let total = NET_FRAME_HDR + payload_len;
    (sys.channel_write)(s.net_out_chan, scratch, total);
}

/// Helper: write a short net-proto frame (MSG_ACCEPTED/CLOSED/BOUND/CONNECTED) to net_out.
/// All stores use write_volatile to prevent LLVM from eliding them in PIC on aarch64.
#[inline(always)]
unsafe fn net_send_short(s: &mut IpState, msg_type: u8, conn_id: u8) {
    if s.net_out_chan < 0 { return; }
    let sys = &*s.syscalls;
    let scratch = s.net_scratch.as_mut_ptr();
    core::ptr::write_volatile(scratch, msg_type);
    core::ptr::write_volatile(scratch.add(1), 1u8);
    core::ptr::write_volatile(scratch.add(2), 0u8);
    core::ptr::write_volatile(scratch.add(3), conn_id);
    (sys.channel_write)(s.net_out_chan, scratch, 4);
}

#[inline(always)]
unsafe fn net_send_accepted(s: &mut IpState, conn_id: u8) {
    net_send_short(s, NET_MSG_ACCEPTED, conn_id);
}

#[inline(always)]
unsafe fn net_send_closed(s: &mut IpState, conn_id: u8) {
    net_send_short(s, NET_MSG_CLOSED, conn_id);
}

#[inline(always)]
unsafe fn net_send_bound(s: &mut IpState, conn_id: u8) {
    net_send_short(s, NET_MSG_BOUND, conn_id);
}

#[inline(always)]
unsafe fn net_send_connected(s: &mut IpState, conn_id: u8) {
    net_send_short(s, NET_MSG_CONNECTED, conn_id);
}

/// Send a MSG_ERROR frame to the net consumer channel.
#[inline(always)]
unsafe fn net_send_error(s: &mut IpState, conn_id: u8, errno: i8) {
    if s.net_out_chan < 0 { return; }
    let sys = &*s.syscalls;
    let scratch = s.net_scratch.as_mut_ptr();
    core::ptr::write_volatile(scratch, NET_MSG_ERROR);
    core::ptr::write_volatile(scratch.add(1), 2u8);
    core::ptr::write_volatile(scratch.add(2), 0u8);
    core::ptr::write_volatile(scratch.add(3), conn_id);
    core::ptr::write_volatile(scratch.add(4), errno as u8);
    (sys.channel_write)(s.net_out_chan, scratch, 5);
}

/// Emit a MSG_RETRANSMIT frame. Payload: [conn_id:1][from_seq:4 LE].
#[inline(always)]
unsafe fn net_send_retransmit(s: &mut IpState, conn_id: u8, from_seq: u32) {
    if s.net_out_chan < 0 { return; }
    let sys = &*s.syscalls;
    let scratch = s.net_scratch.as_mut_ptr();
    core::ptr::write_volatile(scratch, NET_MSG_RETRANSMIT);
    core::ptr::write_volatile(scratch.add(1), 5u8);
    core::ptr::write_volatile(scratch.add(2), 0u8);
    core::ptr::write_volatile(scratch.add(3), conn_id);
    let b = from_seq.to_le_bytes();
    core::ptr::write_volatile(scratch.add(4), b[0]);
    core::ptr::write_volatile(scratch.add(5), b[1]);
    core::ptr::write_volatile(scratch.add(6), b[2]);
    core::ptr::write_volatile(scratch.add(7), b[3]);
    (sys.channel_write)(s.net_out_chan, scratch, 8);
}

/// Emit a MSG_ACK frame. Payload: [conn_id:1][acked_seq:4 LE].
#[inline(always)]
#[allow(dead_code)]
unsafe fn net_send_ack(s: &mut IpState, conn_id: u8, acked_seq: u32) {
    if s.net_out_chan < 0 { return; }
    let sys = &*s.syscalls;
    let scratch = s.net_scratch.as_mut_ptr();
    core::ptr::write_volatile(scratch, NET_MSG_ACK);
    core::ptr::write_volatile(scratch.add(1), 5u8);
    core::ptr::write_volatile(scratch.add(2), 0u8);
    core::ptr::write_volatile(scratch.add(3), conn_id);
    let b = acked_seq.to_le_bytes();
    core::ptr::write_volatile(scratch.add(4), b[0]);
    core::ptr::write_volatile(scratch.add(5), b[1]);
    core::ptr::write_volatile(scratch.add(6), b[2]);
    core::ptr::write_volatile(scratch.add(7), b[3]);
    (sys.channel_write)(s.net_out_chan, scratch, 8);
}

/// Recompute the advertised receive window from consumer-channel backpressure.
/// Called after delivering data on a connection.
unsafe fn update_rcv_wnd(s: &mut IpState, conn_idx: usize) {
    let sys = &*s.syscalls;
    // Check whether the consumer channel has drained space.
    let poll_out = (sys.channel_poll)(s.net_out_chan, POLL_OUT);
    let consumer_ready = poll_out > 0 && (poll_out as u32 & POLL_OUT) != 0;
    let conn = &mut *s.tcp_conns.as_mut_ptr().add(conn_idx);
    // Heuristic: if consumer channel reports writable, treat the
    // downstream buffer as fully drained.
    if consumer_ready {
        conn.consumed_bytes = conn.delivered_bytes;
    }
    let in_flight = conn.delivered_bytes.wrapping_sub(conn.consumed_bytes);
    let avail = (tcp::MAX_RCV_WND as u32).saturating_sub(in_flight) as u16;
    conn.rcv_wnd = core::cmp::min(avail, tcp::MAX_RCV_WND);
}

/// Unchecked TCP conn access (avoids bounds check panic in PIC).
#[inline(always)]
unsafe fn tcp_conn(s: &IpState, idx: usize) -> &tcp::TcpConn {
    &*s.tcp_conns.as_ptr().add(idx)
}

#[inline(always)]
unsafe fn tcp_conn_mut(s: &mut IpState, idx: usize) -> &mut tcp::TcpConn {
    &mut *s.tcp_conns.as_mut_ptr().add(idx)
}

/// Allocate next ephemeral port.
fn next_port(s: &mut IpState) -> u16 {
    let port = s.next_ephemeral_port;
    s.next_ephemeral_port = if port >= 65000 { 49152 } else { port + 1 };
    port
}

/// Send a raw ethernet frame via out_chan.
///
/// Frames are prefixed with a 2-byte little-endian length so the byte-stream
/// FIFO to the NIC driver preserves frame boundaries. Writes are atomic
/// (all 2+N bytes or nothing), so a partial frame cannot reach the driver.
/// If the channel is full, the frame is staged in pending_tx_buf and
/// flushed on the next step.
unsafe fn send_frame(s: &mut IpState, frame: *const u8, len: usize) {
    if s.out_chan < 0 || len == 0 || len > MAX_FRAME_SIZE - 2 { return; }
    let sys = &*s.syscalls;

    // Flush any frame pending from a previous step before writing a new one.
    if s.pending_tx_len > 0 {
        let p = (sys.channel_poll)(s.out_chan, POLL_OUT);
        if p > 0 && (p as u32 & POLL_OUT) != 0 {
            let plen = s.pending_tx_len as usize;
            (sys.channel_write)(s.out_chan, s.pending_tx_buf.as_ptr(), plen);
            s.tx_frame_count = s.tx_frame_count.wrapping_add(1);
            s.pending_tx_len = 0;
        } else {
            return; // still full; drop new frame — TCP will retransmit
        }
    }

    // Stage "[len_lo][len_hi][frame...]" in pending_tx_buf for atomic write.
    let pbuf = s.pending_tx_buf.as_mut_ptr();
    core::ptr::write_volatile(pbuf, len as u8);
    core::ptr::write_volatile(pbuf.add(1), (len >> 8) as u8);
    core::ptr::copy_nonoverlapping(frame, pbuf.add(2), len);
    let total = 2 + len;

    let poll = (sys.channel_poll)(s.out_chan, POLL_OUT);
    if poll > 0 && (poll as u32 & POLL_OUT) != 0 {
        (sys.channel_write)(s.out_chan, pbuf, total);
        s.tx_frame_count = s.tx_frame_count.wrapping_add(1);
    } else {
        s.pending_tx_len = total as u16;
    }
}

// ============================================================================
// Module ABI
// ============================================================================

#[unsafe(no_mangle)]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> u32 { 1 }

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<IpState>()
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<IpState>() {
            return -2;
        }

        // State memory is already zeroed by kernel's alloc_state()
        let s = &mut *(state as *mut IpState);

        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.ctrl_chan = ctrl_chan;

        s.use_dhcp = 1;
        s.mac_valid = false;
        s.netif_handle = -1;

        // Initialize ARP table
        let mut i = 0;
        while i < arp::ARP_TABLE_SIZE {
            *s.arp_table.as_mut_ptr().add(i) = arp::ArpEntry::empty();
            i += 1;
        }
        s.arp_pending_state = arp::ARP_PENDING_NONE;

        // Initialize DHCP
        s.dhcp = dhcp::DhcpClient::new();

        // Initialize TCP connections
        i = 0;
        while i < tcp::MAX_TCP_CONNS {
            *s.tcp_conns.as_mut_ptr().add(i) = tcp::TcpConn::new();
            i += 1;
        }

        s.ip_id = 1;
        s.next_ephemeral_port = 49152;

        // Discover net protocol channels
        let sys = &*s.syscalls;
        s.net_in_chan = dev_channel_port(sys, 0, 1);   // in[1]: net commands from consumer
        s.net_out_chan = dev_channel_port(sys, 1, 1);   // out[1]: net messages to consumer

        // Parse TLV params
        if !params.is_null() && params_len > 0 {
            params_def::parse_tlv(s, params, params_len);
        }

        log_info(s, b"[ip] module loaded");

        0
    }
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut IpState);
    s.step_count = s.step_count.wrapping_add(1);

    // 0a. Flush any pending TX frame from previous step.
    if s.pending_tx_len > 0 && s.out_chan >= 0 {
        let sys = &*s.syscalls;
        let poll = (sys.channel_poll)(s.out_chan, POLL_OUT);
        if poll > 0 && (poll as u32 & POLL_OUT) != 0 {
            let len = s.pending_tx_len as usize;
            (sys.channel_write)(s.out_chan, s.pending_tx_buf.as_ptr(), len);
            s.tx_frame_count = s.tx_frame_count.wrapping_add(1);
            s.pending_tx_len = 0;
        }
        // If still full, return Burst to try again quickly
        if s.pending_tx_len > 0 {
            return 2; // StepOutcome::Burst
        }
    }

    // 0b. Lazy-init: find an active netif to push IP config to
    if s.netif_handle < 0 {
        let sys = &*s.syscalls;
        let mut slot = 0i32;
        while slot < 4 {
            let st = (sys.dev_call)(slot, DEV_NETIF_STATE, core::ptr::null_mut(), 0);
            if st >= 0 {
                s.netif_handle = slot;
                break;
            }
            slot += 1;
        }
    }

    // 1. Receive and process incoming frames
    let mac_was_valid = s.mac_valid;
    process_rx_frames(s);

    // Diagnostic: log when MAC is first learned
    if !mac_was_valid && s.mac_valid {
        let mut buf = [0u8; 40];
        let prefix = b"[ip] mac learned ";
        let mut i = 0;
        while i < prefix.len() { buf[i] = prefix[i]; i += 1; }
        // Format MAC as hex
        let hex = b"0123456789abcdef";
        let bp = buf.as_mut_ptr();
        let hp = hex.as_ptr();
        let mut p = prefix.len();
        let mut m = 0usize;
        while m < 6 && p + 2 < 40 {
            let byte = *s.mac_addr.as_ptr().add(m);
            *bp.add(p) = *hp.add((byte >> 4) as usize);
            *bp.add(p + 1) = *hp.add((byte & 0x0F) as usize);
            p += 2;
            if m < 5 && p < 40 { *bp.add(p) = b':'; p += 1; }
            m += 1;
        }
        let sl = core::slice::from_raw_parts(bp, p);
        log_info(s, sl);
    }

    // Diagnostic: periodic status (every ~5s at 1ms steps)
    if s.step_count % 5000 == 0 {
        if !s.mac_valid {
            log_info(s, b"[ip] waiting for mac");
        } else {
            // Avoid match-returning-slice (broken in PIC) — call log_info directly
            match s.dhcp.state {
                dhcp::DhcpState::Idle => log_info(s, b"[ip] dhcp state=idle"),
                dhcp::DhcpState::Discovering => log_info(s, b"[ip] dhcp state=discover"),
                dhcp::DhcpState::Requesting => log_info(s, b"[ip] dhcp state=request"),
                dhcp::DhcpState::Bound => log_info(s, b"[ip] dhcp state=bound"),
            }
            // Log frame counters using raw pointer writes (no bounds checks)
            {
                let mut buf = [0u8; 40];
                let bp = buf.as_mut_ptr();
                let prefix = b"[ip] rx=";
                let mut p = 0usize;
                while p < prefix.len() { *bp.add(p) = prefix[p]; p += 1; }
                p += fmt_u32_raw(bp.add(p), s.rx_frame_count);
                let mid = b" tx=";
                let mut m = 0usize;
                while m < mid.len() { *bp.add(p) = mid[m]; p += 1; m += 1; }
                p += fmt_u32_raw(bp.add(p), s.tx_frame_count);
                let sl = core::slice::from_raw_parts(bp, p);
                log_info(s, sl);
            }
        }
    }

    // 2. Run DHCP state machine (if enabled and not yet configured)
    if s.use_dhcp != 0 && !s.ip_configured {
        step_dhcp(s);
    }

    // 3. Service net protocol channels (consumer ↔ IP)
    // channel_poll verified working from PIC on aarch64 after u8→u32 widening
    service_net_channels(s);

    // 4. Periodic ARP maintenance
    if s.step_count % 256 == 0 {
        arp::age_entries(&mut s.arp_table);
    }

    // 5. TCP timers
    if s.step_count % 50 == 0 {
        step_tcp_timers(s);
    }

    // Signal Ready once IP is configured (DHCP bound or static)
    if s.ip_configured && !s.signaled_ready {
        s.signaled_ready = true;
        return 3; // StepOutcome::Ready
    }

    0
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_channel_hints"]
pub extern "C" fn module_channel_hints(out: *mut u8, max_len: usize) -> i32 {
    let hints = [
        ChannelHint { port_type: 0, port_index: 0, buffer_size: 4096 }, // in[0]: RX ethernet frames
        ChannelHint { port_type: 1, port_index: 0, buffer_size: 4096 }, // out[0]: TX ethernet frames
        ChannelHint { port_type: 0, port_index: 1, buffer_size: 2048 }, // in[1]: net commands from consumer
        ChannelHint { port_type: 1, port_index: 1, buffer_size: 2048 }, // out[1]: net messages to consumer
    ];
    unsafe { write_channel_hints(out, max_len, &hints) }
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_in_place_safe"]
pub extern "C" fn module_in_place_safe() -> u32 {
    0
}

// ============================================================================
// Frame Processing
// ============================================================================

/// Read and process all pending RX frames from in_chan.
///
/// The NIC driver writes length-prefixed frames (`[len:u16 LE][frame...]`).
/// We read the 2-byte header first, then exactly `len` bytes so back-to-back
/// frames in the byte-stream channel don't concatenate into one giant "frame".
unsafe fn process_rx_frames(s: &mut IpState) {
    if s.in_chan < 0 { return; }
    let sys = &*s.syscalls;

    let mut count = 0;
    while count < 4 {
        let poll = (sys.channel_poll)(s.in_chan, POLL_IN);
        if poll <= 0 || (poll as u32 & POLL_IN) == 0 { break; }

        let mut hdr = [0u8; 2];
        let hn = (sys.channel_read)(s.in_chan, hdr.as_mut_ptr(), 2);
        if hn < 2 { break; }
        let frame_len = (hdr[0] as usize) | ((hdr[1] as usize) << 8);
        if frame_len == 0 || frame_len > MAX_FRAME_SIZE { break; }

        let r = (sys.channel_read)(s.in_chan, s.rx_frame.as_mut_ptr(), frame_len) as i32;
        if r <= 0 { break; }

        process_frame(s, r as usize);
        count += 1;
    }
}

/// Process a single received ethernet frame.
unsafe fn process_frame(s: &mut IpState, len: usize) {
    s.rx_frame_count = s.rx_frame_count.wrapping_add(1);

    let (ethertype, payload_offset) = eth::parse_eth_header(s.rx_frame.as_ptr(), len);

    // EtherType 0x0000 = MAC announcement from cyw43 driver
    if ethertype == 0 {
        if !s.mac_valid && len >= 14 {
            let dst = eth::dst_mac(s.rx_frame.as_ptr());
            // Check that it's a valid unicast MAC (not all zeros)
            if dst[0] & 0x01 == 0 && (dst[0] | dst[1] | dst[2] | dst[3] | dst[4] | dst[5]) != 0 {
                s.mac_addr = dst;
                s.mac_valid = true;
            }
        }
        return;
    }

    // Drivers must announce their MAC explicitly (ethertype=0 frame); we
    // refuse to infer it from inbound traffic, which would let a forged ARP
    // or misconfigured peer drive us to adopt an arbitrary identity.
    if !s.mac_valid {
        return;
    }

    let payload = s.rx_frame.as_ptr().add(payload_offset);
    let payload_len = len - payload_offset;

    match ethertype {
        eth::ETHERTYPE_ARP => process_arp(s, payload, payload_len),
        eth::ETHERTYPE_IPV4 => process_ipv4(s, payload, payload_len),
        _ => {}
    }
}

/// Process an ARP packet.
unsafe fn process_arp(s: &mut IpState, data: *const u8, len: usize) {
    let parsed = match arp::parse_arp(data, len) {
        Some(p) => p,
        None => return,
    };
    let (opcode, sender_ip, sender_mac, target_ip) = parsed;

    // Gratuitous-ARP conflict detection: if someone claims our IP from a
    // different MAC, defend by broadcasting a gratuitous reply asserting
    // our MAC for our IP, then notify the consumer via MSG_ERROR.
    if s.local_ip != 0 && sender_ip == s.local_ip && sender_mac != s.mac_addr {
        log_info(s, b"[ip] arp conflict");
        if s.mac_valid {
            let frame_len = arp::build_arp(
                s.tx_frame.as_mut_ptr(),
                arp::ARP_REPLY,
                &s.mac_addr,
                s.local_ip,
                &eth::BROADCAST_MAC,
                s.local_ip,
            );
            send_frame(s, s.tx_frame.as_ptr(), frame_len);
        }
        net_send_error(s, 0, -1);
        return;
    }

    // Always learn from ARP packets
    arp::insert(&mut s.arp_table, sender_ip, sender_mac, s.step_count as u16);

    // If this resolves our pending ARP request
    if s.arp_pending_state == arp::ARP_PENDING_WAITING && s.arp_pending_ip == sender_ip {
        s.arp_pending_state = arp::ARP_PENDING_NONE;
    }

    // Reply to ARP requests for our IP
    if opcode == arp::ARP_REQUEST && target_ip == s.local_ip && s.local_ip != 0 && s.mac_valid {
        let frame_len = arp::build_arp(
            s.tx_frame.as_mut_ptr(),
            arp::ARP_REPLY,
            &s.mac_addr,
            s.local_ip,
            &sender_mac,
            sender_ip,
        );
        send_frame(s, s.tx_frame.as_ptr(), frame_len);
    }
}

/// Process an IPv4 packet.
unsafe fn process_ipv4(s: &mut IpState, data: *const u8, len: usize) {
    let ip_hdr = match ipv4::parse_ipv4(data, len) {
        Some(h) => h,
        None => return,
    };

    // Opportunistic ARP: learn source IP→MAC from Ethernet header
    if ip_hdr.src_ip != 0 && ip_hdr.src_ip != 0xFFFFFFFF {
        let src_mac = eth::src_mac(s.rx_frame.as_ptr());
        if (src_mac[0] | src_mac[1] | src_mac[2] | src_mac[3] | src_mac[4] | src_mac[5]) != 0 {
            arp::insert(&mut s.arp_table, ip_hdr.src_ip, src_mac, s.step_count as u16);
        }
    }

    // Only process packets addressed to us (or broadcast)
    if s.local_ip != 0 && ip_hdr.dst_ip != s.local_ip && ip_hdr.dst_ip != 0xFFFFFFFF {
        // Not for us (also check subnet broadcast)
        if s.netmask != 0 {
            let subnet_broadcast = (s.local_ip & s.netmask) | (!s.netmask);
            if ip_hdr.dst_ip != subnet_broadcast {
                return;
            }
        } else {
            return;
        }
    }

    let proto_data = data.add(ip_hdr.header_len);
    let proto_len = ip_hdr.total_len as usize - ip_hdr.header_len;

    match ip_hdr.protocol {
        ipv4::PROTO_ICMP => process_icmp(s, &ip_hdr, proto_data, proto_len),
        ipv4::PROTO_TCP => process_tcp_segment(s, &ip_hdr, proto_data, proto_len),
        ipv4::PROTO_UDP => process_udp_packet(s, &ip_hdr, proto_data, proto_len),
        _ => {}
    }
}

/// Process ICMP packet (echo request → reply).
unsafe fn process_icmp(
    s: &mut IpState,
    ip_hdr: &ipv4::Ipv4Header,
    data: *const u8,
    len: usize,
) {
    if !s.mac_valid || s.local_ip == 0 {
        return;
    }

    // Build reply in tx_frame (after eth + ip headers)
    let icmp_dst = s.tx_frame.as_mut_ptr().add(eth::ETH_HEADER_LEN + ipv4::IPV4_HEADER_LEN);
    let reply_len = icmp::handle_icmp(data, len, icmp_dst);
    if reply_len == 0 {
        return;
    }

    // Resolve destination MAC (use source of incoming frame)
    let src_mac = eth::src_mac(s.rx_frame.as_ptr());

    // Build IPv4 header
    let ip_total = (ipv4::IPV4_HEADER_LEN + reply_len) as u16;
    let ip_start = s.tx_frame.as_mut_ptr().add(eth::ETH_HEADER_LEN);
    s.ip_id = s.ip_id.wrapping_add(1);
    ipv4::build_ipv4_header(ip_start, ip_total, ipv4::PROTO_ICMP, s.local_ip, ip_hdr.src_ip, s.ip_id);

    // Build ethernet header
    eth::build_eth_header(s.tx_frame.as_mut_ptr(), &src_mac, &s.mac_addr, eth::ETHERTYPE_IPV4);

    let total_len = eth::ETH_HEADER_LEN + ip_total as usize;
    send_frame(s, s.tx_frame.as_ptr(), total_len);
}

/// Process incoming UDP packet.
unsafe fn process_udp_packet(
    s: &mut IpState,
    ip_hdr: &ipv4::Ipv4Header,
    data: *const u8,
    len: usize,
) {
    let udp_hdr = match udp::parse_udp(data, len) {
        Some(h) => h,
        None => return,
    };

    // Check for DHCP reply
    if udp_hdr.dst_port == dhcp::DHCP_CLIENT_PORT && udp_hdr.src_port == dhcp::DHCP_SERVER_PORT {
        let dhcp_data = data.add(udp_hdr.payload_offset);
        process_dhcp_reply(s, dhcp_data, udp_hdr.payload_len);
        return;
    }

    // Deliver UDP data to matching conn slot.
    // Listen-state (bound) conns get framed addressing: [src_ip:4 LE][src_port:2 LE][data]
    // Established (connected) conns get raw data only.
    let mut i = 0;
    while i < tcp::MAX_TCP_CONNS {
        let conn = &*s.tcp_conns.as_ptr().add(i);
        if conn.local_port == udp_hdr.dst_port {
            if conn.state == tcp::TcpState::Listen {
                // Bound UDP — prefix with source addressing so consumer can reply
                let payload = data.add(udp_hdr.payload_offset);
                let addr_len = 6; // 4 bytes IP + 2 bytes port
                let total = addr_len + udp_hdr.payload_len;
                net_send_udp_data(s, i as u8, ip_hdr.src_ip, udp_hdr.src_port, payload, udp_hdr.payload_len);
                return;
            } else if conn.state == tcp::TcpState::Established
                && conn.remote_ip == ip_hdr.src_ip
                && conn.remote_port == udp_hdr.src_port
            {
                // Connected UDP — raw data only
                let payload = data.add(udp_hdr.payload_offset);
                net_send_data(s, i as u8, payload, udp_hdr.payload_len);
                return;
            }
        }
        i += 1;
    }
}

/// Process incoming TCP segment.
unsafe fn process_tcp_segment(
    s: &mut IpState,
    ip_hdr: &ipv4::Ipv4Header,
    data: *const u8,
    len: usize,
) {
    let tcp_hdr = match tcp::parse_tcp(data, len) {
        Some(h) => h,
        None => return,
    };

    // Find matching connection
    let conn_idx = tcp::find_conn(
        &s.tcp_conns,
        ip_hdr.src_ip,
        tcp_hdr.src_port,
        tcp_hdr.dst_port,
    );

    let conn_idx = match conn_idx {
        Some(i) => i,
        None => {
            // No established connection — accept SYN on a listening socket.
            // Only accept once the interface is configured; otherwise we
            // consume a listener slot but cannot send SYN-ACK.
            if (tcp_hdr.flags & tcp::SYN) != 0 && (tcp_hdr.flags & tcp::ACK) == 0
               && s.mac_valid && s.local_ip != 0 {
                if let Some(li) = tcp::find_listener(&s.tcp_conns, tcp_hdr.dst_port) {
                    log_info(s, b"[ip] tcp syn received");
                    // Accept incoming connection on the listening socket
                    let iss = s.step_count.wrapping_mul(2654435761);
                    let conn = &mut *s.tcp_conns.as_mut_ptr().add(li);
                    conn.remote_ip = ip_hdr.src_ip;
                    conn.remote_port = tcp_hdr.src_port;
                    conn.iss = iss;
                    conn.snd_nxt = iss;
                    conn.snd_una = iss;
                    conn.rcv_nxt = tcp_hdr.seq_num.wrapping_add(1);
                    conn.snd_wnd = tcp_hdr.window;
                    conn.rcv_wnd = tcp::INITIAL_RCV_WND;
                    conn.cwnd = tcp::MSS;
                    conn.ssthresh = 0xFFFF;
                    conn.rto = tcp::RTO_INITIAL;
                    conn.retransmit_timer = 0;
                    conn.state = tcp::TcpState::SynReceived;
                    send_tcp_control(s, li, tcp::SYN | tcp::ACK);
                    return;
                }
            }
            // No listener either — send RST if not RST
            if (tcp_hdr.flags & tcp::RST) == 0 && s.mac_valid && s.local_ip != 0 {
                send_tcp_rst(s, ip_hdr.src_ip, tcp_hdr.src_port, tcp_hdr.dst_port, &tcp_hdr);
            }
            return;
        }
    };

    // Process TCP state machine using deferred actions to avoid borrow conflicts.
    // First update conn state, then perform sends/notifications.
    const ACTION_NONE: u8 = 0;
    const ACTION_SEND_ACK: u8 = 1;
    const ACTION_COMPLETE_CONNECT: u8 = 2;
    const ACTION_COMPLETE_REFUSED: u8 = 3;
    const ACTION_SET_CLOSED: u8 = 4;
    const ACTION_SET_CLOSING: u8 = 5;
    const ACTION_RX_DATA: u8 = 6;
    const ACTION_COMPLETE_ACCEPT: u8 = 7;
    const ACTION_RST_TO_LISTEN: u8 = 8;
    const ACTION_RETRANSMIT_SYNACK: u8 = 9;
    const ACTION_RX_DATA_FIN: u8 = 10;

    let mut action: u8 = ACTION_NONE;
    let mut rx_payload_offset: usize = 0;
    let mut rx_payload_len: usize = 0;
    let mut reorder_pending: bool = false;
    let mut reorder_seq: u32 = 0;
    let mut reorder_offset: usize = 0;
    let mut reorder_len: usize = 0;
    let mut net_send_fast_retransmit: bool = false;
    let mut net_send_fast_retransmit_conn: u8 = 0;
    let mut net_send_fast_retransmit_seq: u32 = 0;

    {
        let conn = &mut (*s.tcp_conns.as_mut_ptr().add(conn_idx));

        match conn.state {
            tcp::TcpState::SynSent => {
                if (tcp_hdr.flags & (tcp::SYN | tcp::ACK)) == (tcp::SYN | tcp::ACK) {
                    if tcp_hdr.ack_num == conn.snd_nxt {
                        conn.rcv_nxt = tcp_hdr.seq_num.wrapping_add(1);
                        conn.snd_una = tcp_hdr.ack_num;
                        conn.snd_wnd = tcp_hdr.window;
                        conn.state = tcp::TcpState::Established;
                        conn.retransmit_timer = 0;
                        action = ACTION_COMPLETE_CONNECT;
                    }
                } else if (tcp_hdr.flags & tcp::RST) != 0 {
                    conn.state = tcp::TcpState::Closed;
                    action = ACTION_COMPLETE_REFUSED;
                }
            }
            tcp::TcpState::Established => {
                if (tcp_hdr.flags & tcp::RST) != 0 {
                    conn.state = tcp::TcpState::Closed;
                    action = ACTION_SET_CLOSED;
                } else {
                    if (tcp_hdr.flags & tcp::ACK) != 0 {
                        let prev_una = conn.snd_una;
                        if seq_between(conn.snd_una, tcp_hdr.ack_num, conn.snd_nxt.wrapping_add(1)) {
                            conn.snd_una = tcp_hdr.ack_num;
                        }
                        conn.snd_wnd = tcp_hdr.window;
                        if conn.snd_una != prev_una {
                            // New data acknowledged.
                            tcp::on_new_ack(conn);
                            tcp::rtt_ack(conn, tcp_hdr.ack_num, s.step_count as u16);
                        } else if tcp_hdr.ack_num == prev_una && tcp_hdr.payload_len == 0 {
                            // Duplicate ACK (no new data, no new ACK).
                            if tcp::on_dup_ack(conn) {
                                // Fast retransmit trigger — consumer notified.
                                net_send_fast_retransmit = true;
                                net_send_fast_retransmit_conn = conn_idx as u8;
                                net_send_fast_retransmit_seq = conn.snd_una;
                            }
                        }
                    }
                    if tcp_hdr.payload_len > 0 && tcp_hdr.seq_num == conn.rcv_nxt {
                        rx_payload_offset = tcp_hdr.payload_offset;
                        rx_payload_len = tcp_hdr.payload_len;
                        action = ACTION_RX_DATA;
                    } else if tcp_hdr.payload_len > 0 && seq_between(conn.rcv_nxt, tcp_hdr.seq_num, conn.rcv_nxt.wrapping_add(conn.rcv_wnd as u32)) {
                        // Out-of-order segment within the receive window —
                        // buffer for reassembly and send a duplicate ACK.
                        reorder_pending = true;
                        reorder_seq = tcp_hdr.seq_num;
                        reorder_offset = tcp_hdr.payload_offset;
                        reorder_len = tcp_hdr.payload_len;
                        action = ACTION_SEND_ACK; // duplicate ACK
                    }
                    if (tcp_hdr.flags & tcp::FIN) != 0 {
                        conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
                        conn.state = tcp::TcpState::CloseWait;
                        if action == ACTION_RX_DATA {
                            action = ACTION_RX_DATA_FIN;
                        } else {
                            action = ACTION_SET_CLOSING;
                        }
                    }
                }
            }
            tcp::TcpState::FinWait1 => {
                if (tcp_hdr.flags & tcp::ACK) != 0 {
                    if seq_between(conn.snd_una, tcp_hdr.ack_num, conn.snd_nxt.wrapping_add(1)) {
                        conn.snd_una = tcp_hdr.ack_num;
                    }
                    if tcp_hdr.ack_num == conn.snd_nxt {
                        // FIN has been ACK'd
                        if (tcp_hdr.flags & tcp::FIN) != 0 {
                            conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
                            conn.state = tcp::TcpState::TimeWait;
                            conn.timewait_timer = 0;
                            action = ACTION_SEND_ACK;
                        } else {
                            conn.state = tcp::TcpState::FinWait2;
                        }
                    }
                    // Partial ACK (data ACK'd but not FIN) — stay in FinWait1
                }
            }
            tcp::TcpState::FinWait2 => {
                if (tcp_hdr.flags & tcp::FIN) != 0 {
                    conn.rcv_nxt = conn.rcv_nxt.wrapping_add(1);
                    conn.state = tcp::TcpState::TimeWait;
                    conn.timewait_timer = 0;
                    action = ACTION_SEND_ACK;
                }
            }
            tcp::TcpState::LastAck => {
                if (tcp_hdr.flags & tcp::ACK) != 0 {
                    conn.state = tcp::TcpState::Closed;
                    action = ACTION_SET_CLOSED;
                }
            }
            tcp::TcpState::TimeWait => {
                if (tcp_hdr.flags & tcp::FIN) != 0 {
                    action = ACTION_SEND_ACK;
                }
            }
            tcp::TcpState::SynReceived => {
                if (tcp_hdr.flags & tcp::RST) != 0 {
                    // Connection refused — reset to listen
                    conn.remote_ip = 0;
                    conn.remote_port = 0;
                    conn.state = tcp::TcpState::Listen;
                    action = ACTION_RST_TO_LISTEN;
                } else if (tcp_hdr.flags & tcp::SYN) != 0 && (tcp_hdr.flags & tcp::ACK) == 0 {
                    // Duplicate SYN — retransmit SYN-ACK
                    conn.retransmit_timer = 0;
                    action = ACTION_RETRANSMIT_SYNACK;
                } else if (tcp_hdr.flags & tcp::ACK) != 0 {
                    // Handshake complete
                    if tcp_hdr.ack_num == conn.snd_nxt {
                        conn.snd_una = tcp_hdr.ack_num;
                        conn.snd_wnd = tcp_hdr.window;
                        conn.state = tcp::TcpState::Established;
                        conn.retransmit_timer = 0;
                        action = ACTION_COMPLETE_ACCEPT;
                        log_info(s, b"[ip] tcp established");
                        // Handle piggybacked data (ACK + request in same segment)
                        if tcp_hdr.payload_len > 0 && tcp_hdr.seq_num == conn.rcv_nxt {
                            rx_payload_offset = tcp_hdr.payload_offset;
                            rx_payload_len = tcp_hdr.payload_len;
                        }
                    }
                }
            }
            _ => {}
        }
    } // conn borrow dropped here

    // Execute deferred actions
    match action {
        ACTION_SEND_ACK => {
            send_tcp_control(s, conn_idx, tcp::ACK);
        }
        ACTION_COMPLETE_CONNECT => {
            send_tcp_control(s, conn_idx, tcp::ACK);
            net_send_connected(s, conn_idx as u8);
            let remote_ip = (*s.tcp_conns.as_ptr().add(conn_idx)).remote_ip;
            arp::pin(&mut s.arp_table, remote_ip);
        }
        ACTION_COMPLETE_REFUSED => {
            net_send_error(s, conn_idx as u8, -111i8);
            let conn = &mut *s.tcp_conns.as_mut_ptr().add(conn_idx);
            *conn = tcp::TcpConn::new();
        }
        ACTION_SET_CLOSED => {
            let remote_ip = (*s.tcp_conns.as_ptr().add(conn_idx)).remote_ip;
            if remote_ip != 0 { arp::unpin(&mut s.arp_table, remote_ip); }
            net_send_closed(s, conn_idx as u8);
            let conn = &mut *s.tcp_conns.as_mut_ptr().add(conn_idx);
            *conn = tcp::TcpConn::new();
        }
        ACTION_SET_CLOSING => {
            send_tcp_control(s, conn_idx, tcp::ACK);
            net_send_closed(s, conn_idx as u8);
        }
        ACTION_RX_DATA | ACTION_RX_DATA_FIN => {
            let payload = data.add(rx_payload_offset);
            // Deliver in-order data via net protocol channel.
            net_send_data(s, conn_idx as u8, payload, rx_payload_len);
            {
                let conn = &mut *s.tcp_conns.as_mut_ptr().add(conn_idx);
                conn.rcv_nxt = conn.rcv_nxt.wrapping_add(rx_payload_len as u32);
                conn.delivered_bytes = conn.delivered_bytes.wrapping_add(rx_payload_len as u32);
            }
            // Drain any reorder slots that are now contiguous.
            loop {
                let conn = &mut *s.tcp_conns.as_mut_ptr().add(conn_idx);
                let rcv_nxt = conn.rcv_nxt;
                let taken = tcp::reorder_take_next(conn, rcv_nxt);
                match taken {
                    Some((slice, next_seq)) => {
                        // Copy slice to stable pointer (slice aliases reorder_buf).
                        let ptr = slice.as_ptr();
                        let len = slice.len();
                        net_send_data(s, conn_idx as u8, ptr, len);
                        let conn2 = &mut *s.tcp_conns.as_mut_ptr().add(conn_idx);
                        conn2.rcv_nxt = next_seq;
                        conn2.delivered_bytes = conn2.delivered_bytes.wrapping_add(len as u32);
                    }
                    None => break,
                }
            }
            update_rcv_wnd(s, conn_idx);
            send_tcp_control(s, conn_idx, tcp::ACK);
            if action == ACTION_RX_DATA_FIN {
                net_send_closed(s, conn_idx as u8);
            }
        }
        ACTION_COMPLETE_ACCEPT => {
            let remote_ip = (*s.tcp_conns.as_ptr().add(conn_idx)).remote_ip;
            arp::pin(&mut s.arp_table, remote_ip);
            net_send_accepted(s, conn_idx as u8);
            // Deliver piggybacked data (e.g. HTTP GET in same segment as ACK)
            if rx_payload_len > 0 {
                let payload = data.add(rx_payload_offset);
                net_send_data(s, conn_idx as u8, payload, rx_payload_len);
                (*s.tcp_conns.as_mut_ptr().add(conn_idx)).rcv_nxt = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).rcv_nxt.wrapping_add(rx_payload_len as u32);
                send_tcp_control(s, conn_idx, tcp::ACK);
            }
        }
        ACTION_RST_TO_LISTEN => {
            // Connection refused during handshake — reset to listen, no notification needed
        }
        ACTION_RETRANSMIT_SYNACK => {
            send_tcp_control(s, conn_idx, tcp::SYN | tcp::ACK);
        }
        _ => {}
    }

    // Buffer an out-of-order segment if one was flagged.
    if reorder_pending {
        let payload = data.add(reorder_offset);
        let conn = &mut *s.tcp_conns.as_mut_ptr().add(conn_idx);
        tcp::reorder_insert(conn, reorder_seq, payload, reorder_len);
    }

    // Fast retransmit — signal the consumer to resend from `snd_una`.
    if net_send_fast_retransmit {
        net_send_retransmit(s, net_send_fast_retransmit_conn, net_send_fast_retransmit_seq);
    }
}

/// Check if `val` is between `start` (inclusive) and `end` (exclusive) in sequence space.
fn seq_between(start: u32, val: u32, end: u32) -> bool {
    let len = end.wrapping_sub(start);
    let pos = val.wrapping_sub(start);
    pos < len && pos > 0
}

/// Send a TCP RST in response to an unexpected segment.
unsafe fn send_tcp_rst(
    s: &mut IpState,
    remote_ip: u32,
    remote_port: u16,
    local_port: u16,
    hdr: &tcp::TcpHeader,
) {
    if !s.mac_valid || s.local_ip == 0 {
        return;
    }

    let (seq, ack, flags) = if (hdr.flags & tcp::ACK) != 0 {
        (hdr.ack_num, 0u32, tcp::RST)
    } else {
        let ack = hdr.seq_num.wrapping_add(hdr.payload_len as u32);
        (0u32, ack, tcp::RST | tcp::ACK)
    };

    // Resolve MAC
    let dst_mac = resolve_mac(s, remote_ip);
    let dst_mac = match dst_mac {
        Some(m) => m,
        None => return,
    };

    let tcp_start = s.tx_frame.as_mut_ptr().add(eth::ETH_HEADER_LEN + ipv4::IPV4_HEADER_LEN);
    tcp::build_tcp_header(
        tcp_start, local_port, remote_port,
        seq, ack, flags, 0,
    );

    let ip_total = (ipv4::IPV4_HEADER_LEN + tcp::TCP_HEADER_LEN) as u16;
    let ip_start = s.tx_frame.as_mut_ptr().add(eth::ETH_HEADER_LEN);
    s.ip_id = s.ip_id.wrapping_add(1);
    ipv4::build_ipv4_header(ip_start, ip_total, ipv4::PROTO_TCP, s.local_ip, remote_ip, s.ip_id);

    eth::build_eth_header(s.tx_frame.as_mut_ptr(), &dst_mac, &s.mac_addr, eth::ETHERTYPE_IPV4);

    tcp::compute_tcp_checksum(tcp_start, tcp::TCP_HEADER_LEN, s.local_ip, remote_ip);

    let total = eth::ETH_HEADER_LEN + ip_total as usize;
    send_frame(s, s.tx_frame.as_ptr(), total);
}

/// Send a TCP control segment (SYN, ACK, FIN, RST) for a connection.
unsafe fn send_tcp_control(s: &mut IpState, conn_idx: usize, flags: u8) {
    if !s.mac_valid || s.local_ip == 0 {
        return;
    }

    // Extract conn fields to avoid borrow conflicts
    let remote_ip = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).remote_ip;
    let local_port = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).local_port;
    let remote_port = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).remote_port;
    let snd_nxt = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).snd_nxt;
    let rcv_nxt = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).rcv_nxt;
    let rcv_wnd = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).rcv_wnd;

    let dst_mac = resolve_mac(s, remote_ip);
    let dst_mac = match dst_mac {
        Some(m) => m,
        None => {
            log_info(s, b"[ip] tcp ctrl: arp pending");
            return;
        }
    };

    let tcp_start = s.tx_frame.as_mut_ptr().add(eth::ETH_HEADER_LEN + ipv4::IPV4_HEADER_LEN);
    tcp::build_tcp_header(
        tcp_start,
        local_port, remote_port, snd_nxt, rcv_nxt,
        flags, rcv_wnd,
    );

    let ip_total = (ipv4::IPV4_HEADER_LEN + tcp::TCP_HEADER_LEN) as u16;
    let ip_start = s.tx_frame.as_mut_ptr().add(eth::ETH_HEADER_LEN);
    s.ip_id = s.ip_id.wrapping_add(1);
    ipv4::build_ipv4_header(ip_start, ip_total, ipv4::PROTO_TCP, s.local_ip, remote_ip, s.ip_id);

    eth::build_eth_header(s.tx_frame.as_mut_ptr(), &dst_mac, &s.mac_addr, eth::ETHERTYPE_IPV4);

    tcp::compute_tcp_checksum(tcp_start, tcp::TCP_HEADER_LEN, s.local_ip, remote_ip);

    let total = eth::ETH_HEADER_LEN + ip_total as usize;
    send_frame(s, s.tx_frame.as_ptr(), total);

    // Update snd_nxt for SYN/FIN (they consume sequence space)
    if (flags & tcp::SYN) != 0 || (flags & tcp::FIN) != 0 {
        (*s.tcp_conns.as_mut_ptr().add(conn_idx)).snd_nxt = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).snd_nxt.wrapping_add(1);
    }
}

/// Send TCP data segment for a connection.
#[inline(never)]
unsafe fn send_tcp_data(s: &mut IpState, conn_idx: usize, payload: *const u8, payload_len: usize) {
    if !s.mac_valid || s.local_ip == 0 || payload_len == 0 {
        return;
    }

    // Extract conn fields
    let remote_ip = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).remote_ip;
    let local_port = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).local_port;
    let remote_port = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).remote_port;
    let snd_nxt = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).snd_nxt;
    let rcv_nxt = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).rcv_nxt;
    let rcv_wnd = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).rcv_wnd;

    let dst_mac = resolve_mac(s, remote_ip);
    let dst_mac = match dst_mac {
        Some(m) => m,
        None => return,
    };

    let hdr_offset = eth::ETH_HEADER_LEN + ipv4::IPV4_HEADER_LEN;
    let tcp_start = s.tx_frame.as_mut_ptr().add(hdr_offset);

    tcp::build_tcp_header(
        tcp_start,
        local_port, remote_port, snd_nxt, rcv_nxt,
        tcp::ACK | tcp::PSH, rcv_wnd,
    );

    // Copy payload after TCP header
    let payload_dst = tcp_start.add(tcp::TCP_HEADER_LEN);
    core::ptr::copy_nonoverlapping(payload, payload_dst, payload_len);

    let ip_total = (ipv4::IPV4_HEADER_LEN + tcp::TCP_HEADER_LEN + payload_len) as u16;
    let ip_start = s.tx_frame.as_mut_ptr().add(eth::ETH_HEADER_LEN);
    s.ip_id = s.ip_id.wrapping_add(1);
    ipv4::build_ipv4_header(ip_start, ip_total, ipv4::PROTO_TCP, s.local_ip, remote_ip, s.ip_id);

    eth::build_eth_header(s.tx_frame.as_mut_ptr(), &dst_mac, &s.mac_addr, eth::ETHERTYPE_IPV4);

    tcp::compute_tcp_checksum(
        tcp_start, tcp::TCP_HEADER_LEN + payload_len,
        s.local_ip, remote_ip,
    );

    let total = eth::ETH_HEADER_LEN + ip_total as usize;
    send_frame(s, s.tx_frame.as_ptr(), total);

    // Advance snd_nxt
    (*s.tcp_conns.as_mut_ptr().add(conn_idx)).snd_nxt = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).snd_nxt.wrapping_add(payload_len as u32);
}

/// Send a UDP datagram.  Used for CMD_SEND on Listen-state (bound) conns where
/// the consumer supplies [dst_ip:4 LE][dst_port:2 LE][payload...], and for
/// Established (connected) conns where remote_ip/port come from the conn slot.
unsafe fn send_udp_data(
    s: &mut IpState,
    dst_ip: u32,
    dst_port: u16,
    src_port: u16,
    payload: *const u8,
    payload_len: usize,
) {
    if !s.mac_valid || s.local_ip == 0 || payload_len == 0 {
        return;
    }

    let dst_mac = resolve_mac(s, dst_ip);
    let dst_mac = match dst_mac {
        Some(m) => m,
        None => return,
    };

    let hdr_offset = eth::ETH_HEADER_LEN + ipv4::IPV4_HEADER_LEN;
    let udp_start = s.tx_frame.as_mut_ptr().add(hdr_offset);

    // Copy payload after UDP header first so build_udp_header can checksum it
    let payload_dst = udp_start.add(udp::UDP_HEADER_LEN);
    let mut i = 0;
    while i < payload_len {
        *payload_dst.add(i) = *payload.add(i);
        i += 1;
    }

    udp::build_udp_header(udp_start, src_port, dst_port, payload_len, s.local_ip, dst_ip, payload_dst);

    let ip_total = (ipv4::IPV4_HEADER_LEN + udp::UDP_HEADER_LEN + payload_len) as u16;
    let ip_start = s.tx_frame.as_mut_ptr().add(eth::ETH_HEADER_LEN);
    s.ip_id = s.ip_id.wrapping_add(1);
    ipv4::build_ipv4_header(ip_start, ip_total, ipv4::PROTO_UDP, s.local_ip, dst_ip, s.ip_id);

    eth::build_eth_header(s.tx_frame.as_mut_ptr(), &dst_mac, &s.mac_addr, eth::ETHERTYPE_IPV4);

    let total = eth::ETH_HEADER_LEN + ip_total as usize;
    send_frame(s, s.tx_frame.as_ptr(), total);
}

/// Resolve IP to MAC (returns cached entry or triggers ARP request).
unsafe fn resolve_mac(s: &mut IpState, ip: u32) -> Option<[u8; 6]> {
    // Broadcast
    if ip == 0xFFFFFFFF {
        return Some(eth::BROADCAST_MAC);
    }

    // Use gateway if destination is off-subnet
    let target_ip = if s.netmask != 0 && (ip & s.netmask) != (s.local_ip & s.netmask) {
        if s.gateway != 0 { s.gateway } else { ip }
    } else {
        ip
    };

    // Check ARP table
    if let Some(mac) = arp::lookup(&s.arp_table, target_ip) {
        return Some(mac);
    }

    // Send ARP request if not already pending
    if s.arp_pending_state == arp::ARP_PENDING_NONE && s.mac_valid && s.local_ip != 0 {
        s.arp_pending_ip = target_ip;
        s.arp_pending_state = arp::ARP_PENDING_WAITING;
        s.arp_pending_timer = 0;

        let frame_len = arp::build_arp(
            s.tx_frame.as_mut_ptr(),
            arp::ARP_REQUEST,
            &s.mac_addr,
            s.local_ip,
            &eth::BROADCAST_MAC,
            target_ip,
        );
        send_frame(s, s.tx_frame.as_ptr(), frame_len);
    }

    None
}

// ============================================================================
// DHCP
// ============================================================================

/// Drive the DHCP state machine.
unsafe fn step_dhcp(s: &mut IpState) {
    if !s.mac_valid {
        return;
    }

    s.dhcp.timer = s.dhcp.timer.wrapping_add(1);

    match s.dhcp.state {
        dhcp::DhcpState::Idle => {
            // Start DHCP discovery — generate an unpredictable XID from the
            // kernel CSPRNG to avoid precomputable race attacks.
            if s.dhcp.xid == 0 {
                let sys = &*s.syscalls;
                let mut xid_bytes = [0u8; 4];
                if dev_csprng_fill(sys, xid_bytes.as_mut_ptr(), 4) < 0 {
                    // Fall back to a step-count derivation if the CSPRNG is
                    // unavailable — better than 0 (which parse_dhcp_reply
                    // rejects) and better than reusing the boot constant.
                    s.dhcp.xid = s.step_count.wrapping_mul(2654435761).wrapping_add(1);
                } else {
                    s.dhcp.xid = u32::from_le_bytes(xid_bytes);
                    if s.dhcp.xid == 0 { s.dhcp.xid = 1; }
                }
            }
            s.dhcp.retries = 0;
            send_dhcp_discover(s);
            s.dhcp.state = dhcp::DhcpState::Discovering;
            s.dhcp.timer = 0;
        }
        dhcp::DhcpState::Discovering => {
            // Retransmit after ~2 seconds (2000 steps at ~1ms)
            if s.dhcp.timer > 2000 {
                s.dhcp.retries += 1;
                if s.dhcp.retries < 10 {
                    send_dhcp_discover(s);
                    s.dhcp.timer = 0;
                } else {
                    // Give up, retry from idle (keep same XID)
                    s.dhcp.state = dhcp::DhcpState::Idle;
                    s.dhcp.timer = 0;
                    s.dhcp.retries = 0;
                }
            }
        }
        dhcp::DhcpState::Requesting => {
            // Retransmit after ~2 seconds (2000 steps at ~1ms)
            if s.dhcp.timer > 2000 {
                s.dhcp.retries += 1;
                if s.dhcp.retries < 10 {
                    send_dhcp_request(s);
                    s.dhcp.timer = 0;
                } else {
                    s.dhcp.state = dhcp::DhcpState::Idle;
                    s.dhcp.timer = 0;
                    s.dhcp.retries = 0;
                }
            }
        }
        dhcp::DhcpState::Bound => {
            // Track lease expiry (RFC 2131 §4.4.5). T1 = 0.5 * lease, T2 =
            // 0.875 * lease. On T1, send a unicast REQUEST (renewal). At
            // expiry, drop back to Idle and start a fresh discover.
            if s.dhcp.lease_duration > 0 {
                let elapsed = s.step_count.wrapping_sub(s.dhcp.lease_start);
                if elapsed >= s.dhcp.lease_duration {
                    s.ip_configured = false;
                    s.dhcp.state = dhcp::DhcpState::Idle;
                    s.dhcp.xid = 0;
                    s.dhcp.timer = 0;
                    s.dhcp.renew_sent = false;
                } else if !s.dhcp.renew_sent && elapsed >= s.dhcp.lease_duration / 2 {
                    s.dhcp.renew_sent = true;
                    send_dhcp_request(s);
                }
            }
        }
    }
}

unsafe fn send_dhcp_discover(s: &mut IpState) {
    log_info(s, b"[ip] dhcp discover tx");
    let frame_len = dhcp::build_dhcp_message(
        s.tx_frame.as_mut_ptr(),
        dhcp::DHCP_DISCOVER,
        &s.mac_addr,
        s.dhcp.xid,
        0,
        0,
    );
    send_frame(s, s.tx_frame.as_ptr(), frame_len);
}

unsafe fn send_dhcp_request(s: &mut IpState) {
    let frame_len = dhcp::build_dhcp_message(
        s.tx_frame.as_mut_ptr(),
        dhcp::DHCP_REQUEST,
        &s.mac_addr,
        s.dhcp.xid,
        s.dhcp.offered_ip,
        s.dhcp.server_ip,
    );
    send_frame(s, s.tx_frame.as_ptr(), frame_len);
}

/// Process a DHCP reply (called from UDP handler).
unsafe fn process_dhcp_reply(s: &mut IpState, data: *const u8, len: usize) {
    let parsed = match dhcp::parse_dhcp_reply(data, len, s.dhcp.xid) {
        Some(p) => p,
        None => return,
    };
    let (msg_type, offered_ip, server_ip, subnet_mask, gateway, dns, lease_time) = parsed;

    // Reject replies from servers other than the configured one.
    if s.dhcp.expected_server != 0 && server_ip != s.dhcp.expected_server {
        log_info(s, b"[ip] dhcp reject: unexpected server");
        return;
    }

    // Sanity-check the offered configuration.
    if !dhcp::validate_dhcp_config(offered_ip, subnet_mask, gateway, lease_time) {
        log_info(s, b"[ip] dhcp reject: invalid config");
        return;
    }

    match msg_type {
        dhcp::DHCP_OFFER => {
            log_info(s, b"[ip] dhcp offer rx");
            if s.dhcp.state == dhcp::DhcpState::Discovering {
                s.dhcp.offered_ip = offered_ip;
                s.dhcp.server_ip = server_ip;
                s.dhcp.subnet_mask = subnet_mask;
                s.dhcp.gateway = gateway;
                s.dhcp.dns_server = dns;
                s.dhcp.lease_time = lease_time;
                s.dhcp.state = dhcp::DhcpState::Requesting;
                s.dhcp.timer = 0;
                s.dhcp.retries = 0;
                send_dhcp_request(s);
            }
        }
        dhcp::DHCP_ACK => {
            log_info(s, b"[ip] dhcp ack rx");
            // Accept ACK in either Requesting or Discovering state.
            // Some DHCP servers (e.g. QEMU SLIRP) may send ACK directly.
            if s.dhcp.state == dhcp::DhcpState::Requesting
                || s.dhcp.state == dhcp::DhcpState::Discovering {
                s.local_ip = offered_ip;
                s.netmask = if subnet_mask != 0 { subnet_mask } else { 0xFFFFFF00 };
                s.gateway = gateway;
                s.dns_server = dns;
                s.ip_configured = true;
                s.dhcp.state = dhcp::DhcpState::Bound;
                s.dhcp.lease_start = s.step_count;
                // Convert lease seconds into step ticks (one step = 100 µs or 1 ms
                // depending on config; we approximate by treating step_count as
                // an opaque tick counter and multiplying by 1000 to get ms).
                s.dhcp.lease_duration = lease_time.saturating_mul(1000);
                s.dhcp.renew_sent = false;
                // Permanently pin the gateway ARP entry if already learnt.
                if s.gateway != 0 {
                    arp::pin_gateway(&mut s.arp_table, s.gateway);
                }

                // Log the assigned IP address with startup timing
                {
                    let sys = &*s.syscalls;
                    let ms = dev_millis(sys);
                    let mut buf = [0u8; 50];
                    let bp = buf.as_mut_ptr();
                    let prefix = b"[ip] dhcp bound ";
                    let mut i = 0;
                    while i < prefix.len() { *bp.add(i) = prefix[i]; i += 1; }
                    i += fmt_ip_raw(bp.add(i), s.local_ip);
                    let mid = b" T+";
                    let mut m = 0;
                    while m < mid.len() { *bp.add(i) = mid[m]; i += 1; m += 1; }
                    i += fmt_u32_raw(bp.add(i), ms as u32);
                    *bp.add(i) = b'm'; i += 1;
                    *bp.add(i) = b's'; i += 1;
                    dev_log(sys, 1, bp, i);
                }

                // Update netif with IP configuration
                apply_ip_config(s);
            }
        }
        dhcp::DHCP_NAK => {
            s.dhcp.state = dhcp::DhcpState::Idle;
            s.dhcp.timer = 0;
        }
        _ => {}
    }
}

/// Signal netif that IP configuration is applied (state → Ready).
/// All IP config (address, mask, gateway, DNS) is managed locally by this module.
unsafe fn apply_ip_config(s: &IpState) {
    if s.netif_handle < 0 {
        return;
    }
    let sys = &*s.syscalls;
    dev_netif_set_state(sys, s.netif_handle, NETIF_STATE_READY);
}

// ============================================================================
// Net Protocol Channel Service
// ============================================================================

/// Read and dispatch net protocol commands from the consumer channel.
/// Replaces the old socket-based service_sockets().
unsafe fn service_net_channels(s: &mut IpState) {
    if s.net_in_chan < 0 { return; }
    let sys = &*s.syscalls;

    // Process up to 4 commands per step.
    // Skip channel_poll — it returns wrong results from PIC modules on aarch64.
    // ip_net_read_frame returns (0,0) when the channel is empty.
    let mut count = 0;
    while count < 4 {
        let mut buf = [0u8; 580]; // enough for MTU payload
        let (msg_type, payload_len) = ip_net_read_frame(sys, s.net_in_chan, buf.as_mut_ptr(), buf.len());
        if msg_type == 0 {
            break;
        }

        let plen = payload_len as usize;

        match msg_type {
            NET_CMD_BIND => {
                // Payload: [port: u16 LE]
                if plen >= 2 {
                    let port = u16::from_le_bytes([*buf.as_ptr(), *buf.as_ptr().add(1)]);
                    // Find a free tcp_conn and set it to Listen
                    let mut found = false;
                    let mut ci = 0;
                    while ci < tcp::MAX_TCP_CONNS {
                        let conn = &mut *s.tcp_conns.as_mut_ptr().add(ci);
                        if conn.state == tcp::TcpState::Closed {
                            conn.state = tcp::TcpState::Listen;
                            conn.local_port = port;
                            conn.remote_ip = 0;
                            conn.remote_port = 0;
                            conn.retransmit_timer = 0;
                            found = true;
                            break;
                        }
                        ci += 1;
                    }
                    if found {
                        log_info(s, b"[ip] net bind");
                        net_send_bound(s, ci as u8);
                    } else {
                        log_info(s, b"[ip] net bind: no free conn");
                        net_send_error(s, 0, -12); // ENOMEM
                    }
                }
            }
            NET_CMD_CONNECT => {
                // Payload: [sock_type: u8] [ip: u32 LE] [port: u16 LE]
                if plen >= 7 {
                    let bp = buf.as_ptr();
                    let sock_type = *bp;
                    let ip = u32::from_le_bytes([*bp.add(1), *bp.add(2), *bp.add(3), *bp.add(4)]);
                    let port = u16::from_le_bytes([*bp.add(5), *bp.add(6)]);

                    // Find a free conn slot
                    let mut conn_id: i32 = -1;
                    let mut ci = 0;
                    while ci < tcp::MAX_TCP_CONNS {
                        let conn = &*s.tcp_conns.as_ptr().add(ci);
                        if conn.state == tcp::TcpState::Closed {
                            conn_id = ci as i32;
                            break;
                        }
                        ci += 1;
                    }

                    if conn_id < 0 {
                        net_send_error(s, 0, -12); // ENOMEM
                    } else {
                        let ci = conn_id as usize;
                        if sock_type == SOCK_TYPE_STREAM {
                            let local_port = next_port(s);
                            let iss = s.step_count.wrapping_mul(2654435761);

                            let conn = &mut *s.tcp_conns.as_mut_ptr().add(ci);
                            conn.state = tcp::TcpState::SynSent;
                            conn.remote_ip = ip;
                            conn.remote_port = port;
                            conn.local_port = local_port;
                            conn.iss = iss;
                            conn.snd_nxt = iss;
                            conn.snd_una = iss;
                            conn.rcv_wnd = 512;
                            conn.retransmit_timer = 0;

                            send_tcp_control(s, ci, tcp::SYN);
                        } else {
                            // UDP: immediately connected
                            let conn = &mut *s.tcp_conns.as_mut_ptr().add(ci);
                            conn.state = tcp::TcpState::Established;
                            conn.remote_ip = ip;
                            conn.remote_port = port;
                            conn.local_port = next_port(s);
                            net_send_connected(s, ci as u8);
                        }
                    }
                }
            }
            NET_CMD_SEND => {
                // Payload: [conn_id: u8] [data...]
                if plen >= 2 {
                    let conn_id = *buf.as_ptr() as usize;
                    let data_ptr = buf.as_ptr().add(1);
                    let data_len = plen - 1;

                    if conn_id < tcp::MAX_TCP_CONNS {
                        let conn = &*s.tcp_conns.as_ptr().add(conn_id);
                        if conn.state == tcp::TcpState::Established {
                            if conn.rcv_wnd != 0 {
                                // Effective window is min(peer snd_wnd, cwnd).
                                let eff_wnd = tcp::effective_snd_wnd(conn) as usize;
                                let in_flight = conn.snd_nxt.wrapping_sub(conn.snd_una) as usize;
                                let can_send = eff_wnd.saturating_sub(in_flight).min(1400);
                                let send_len = data_len.min(can_send);
                                if send_len > 0 {
                                    let seq = conn.snd_nxt;
                                    let tick = s.step_count as u16;
                                    send_tcp_data(s, conn_id, data_ptr, send_len);
                                    let conn2 = &mut *s.tcp_conns.as_mut_ptr().add(conn_id);
                                    tcp::rtt_arm(conn2, seq, tick);
                                }
                            } else {
                                // Connected UDP — remote addr from conn slot
                                send_udp_data(
                                    s, conn.remote_ip, conn.remote_port,
                                    conn.local_port, data_ptr, data_len,
                                );
                            }
                        } else if conn.state == tcp::TcpState::Listen {
                            // Bound UDP — payload: [dst_ip:4 LE][dst_port:2 LE][data...]
                            if data_len >= 7 {
                                let dp = data_ptr;
                                let dst_ip = u32::from_le_bytes([*dp, *dp.add(1), *dp.add(2), *dp.add(3)]);
                                let dst_port = u16::from_le_bytes([*dp.add(4), *dp.add(5)]);
                                let udp_data = dp.add(6);
                                let udp_len = data_len - 6;
                                send_udp_data(s, dst_ip, dst_port, conn.local_port, udp_data, udp_len);
                            }
                        }
                    }
                }
            }
            NET_CMD_CLOSE => {
                // Payload: [conn_id: u8]
                if plen >= 1 {
                    let conn_id = *buf.as_ptr() as usize;
                    if conn_id < tcp::MAX_TCP_CONNS {
                        let conn_state = (*s.tcp_conns.as_ptr().add(conn_id)).state;
                        match conn_state {
                            tcp::TcpState::Established => {
                                send_tcp_control(s, conn_id, tcp::FIN | tcp::ACK);
                                (*s.tcp_conns.as_mut_ptr().add(conn_id)).state = tcp::TcpState::FinWait1;
                            }
                            tcp::TcpState::CloseWait => {
                                send_tcp_control(s, conn_id, tcp::FIN | tcp::ACK);
                                (*s.tcp_conns.as_mut_ptr().add(conn_id)).state = tcp::TcpState::LastAck;
                            }
                            tcp::TcpState::Listen => {
                                // Close a listening socket
                                let conn = &mut *s.tcp_conns.as_mut_ptr().add(conn_id);
                                *conn = tcp::TcpConn::new();
                                net_send_closed(s, conn_id as u8);
                            }
                            _ => {
                                // Already closing/closed — reset and notify
                                let remote_ip = (*s.tcp_conns.as_ptr().add(conn_id)).remote_ip;
                                if remote_ip != 0 { arp::unpin(&mut s.arp_table, remote_ip); }
                                let conn = &mut *s.tcp_conns.as_mut_ptr().add(conn_id);
                                *conn = tcp::TcpConn::new();
                                net_send_closed(s, conn_id as u8);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        count += 1;
    }
}

// ============================================================================
// TCP Timers
// ============================================================================

/// Process TCP timers (retransmit, time-wait).
unsafe fn step_tcp_timers(s: &mut IpState) {
    let mut i = 0;
    while i < tcp::MAX_TCP_CONNS {
        let conn = &mut *s.tcp_conns.as_mut_ptr().add(i);
        match conn.state {
            tcp::TcpState::SynSent => {
                conn.retransmit_timer += 1;
                // Retransmit SYN after ~3 seconds (60 ticks at 50ms period)
                if conn.retransmit_timer > 60 {
                    conn.retransmit_timer = 0;
                    send_tcp_control(s, i, tcp::SYN);
                }
            }
            tcp::TcpState::SynReceived => {
                conn.retransmit_timer += 1;
                // Retransmit SYN-ACK every ~3 seconds (timer doesn't reset)
                if conn.retransmit_timer % 60 == 0 && conn.retransmit_timer < 300 {
                    send_tcp_control(s, i, tcp::SYN | tcp::ACK);
                }
                // Timeout after ~15 seconds — reset to Listen
                if conn.retransmit_timer >= 300 {
                    conn.remote_ip = 0;
                    conn.remote_port = 0;
                    conn.state = tcp::TcpState::Listen;
                }
            }
            tcp::TcpState::TimeWait => {
                conn.timewait_timer += 1;
                // Exit time-wait after ~30 seconds
                if conn.timewait_timer > 600 {
                    let remote_ip = conn.remote_ip;
                    if remote_ip != 0 { arp::unpin(&mut s.arp_table, remote_ip); }
                    conn.state = tcp::TcpState::Closed;
                    net_send_closed(s, i as u8);
                    *s.tcp_conns.as_mut_ptr().add(i) = tcp::TcpConn::new();
                }
            }
            tcp::TcpState::Established => {
                // RTO: if there is unacknowledged data and the timer expires,
                // collapse cwnd, signal the consumer to retransmit, and arm
                // backoff. Karn: don't use the retransmit sample for RTT.
                if conn.snd_nxt != conn.snd_una {
                    conn.retransmit_timer = conn.retransmit_timer.saturating_add(1);
                    if conn.retransmit_timer >= conn.rto {
                        tcp::on_rto(conn);
                        let seq = conn.snd_una;
                        conn.retransmit_timer = 0;
                        // Exponential backoff — double RTO for next timeout.
                        conn.rto = core::cmp::min(conn.rto.saturating_mul(2), tcp::RTO_MAX);
                        conn.rtt_active = false; // Karn's algorithm
                        net_send_retransmit(s, i as u8, seq);
                    }
                } else {
                    conn.retransmit_timer = 0;
                }
            }
            _ => {}
        }
        i += 1;
    }
}
