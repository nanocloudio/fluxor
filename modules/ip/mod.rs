//! IP Stack Service Module
//!
//! Implements TCP/IP networking as a PIC module. Receives raw ethernet frames
//! from a driver module (e.g. cyw43) via channels, processes ARP/IPv4/ICMP/TCP/UDP,
//! and services kernel socket slots.
//!
//! # Architecture
//!
//! ```text
//! Driver Module (cyw43/enc28j60)           IP Module                    Socket Slots
//! ─────────────────────────────           ─────────                    ────────────
//! ETH frames → [out_chan] ──────► [in_chan] → ARP/IPv4 parse
//!                                            ├── ICMP echo → reply ──► [out_chan] → driver
//!                                            ├── DHCP reply → config
//!                                            ├── TCP segment → socket RX ringbuf ──► module recv()
//!                                            └── UDP datagram → socket RX ringbuf
//! module send() ──► socket TX ringbuf ──► TCP/UDP build ──► [out_chan] → driver
//! ```
//!
//! # Channels
//!
//! - `in_chan`: Raw ethernet frames from driver module
//! - `out_chan`: Raw ethernet frames to driver module
//!
//! # Config Parameters
//!
//! | Tag | Name     | Type | Default | Description                |
//! |-----|----------|------|---------|----------------------------|
//! | 1   | use_dhcp | u8   | 1       | Enable DHCP (1=yes, 0=no) |

#![no_std]

use core::ffi::c_void;

#[path = "../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../pic_runtime.rs");
include!("../param_macro.rs");

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

/// Socket service dev_call opcodes (mirror abi::dev_socket)
const DEV_SOCKET_SERVICE_INFO: u32 = 0x0810;
const DEV_SOCKET_SERVICE_TX_READ: u32 = 0x0811;
const DEV_SOCKET_SERVICE_RX_WRITE: u32 = 0x0812;
const DEV_SOCKET_SERVICE_COMPLETE_OP: u32 = 0x0813;
const DEV_SOCKET_SERVICE_SET_STATE: u32 = 0x0814;
const DEV_SOCKET_SERVICE_COUNT: u32 = 0x0815;

/// Socket lifecycle phases (module-defined, kernel stores opaquely as u8).
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum SocketPhase {
    Free = 0,
    Allocated = 1,
    Connecting = 2,
    Connected = 3,
    Listening = 4,
    Closing = 5,
    Closed = 6,
}

/// Socket operations (mirror kernel::socket::SocketOp)
const SOCKOP_NONE: u8 = 0;
const SOCKOP_CONNECT: u8 = 1;
const SOCKOP_BIND: u8 = 2;
const SOCKOP_LISTEN: u8 = 3;
const SOCKOP_ACCEPT: u8 = 4;
const SOCKOP_CLOSE: u8 = 5;

/// Netif dev_call opcodes (mirror abi::dev_netif)
const DEV_NETIF_STATE: u32 = 0x0704;

// ============================================================================
// Socket Service Info (matches abi::SocketServiceInfo)
// ============================================================================

#[repr(C)]
struct SocketServiceInfo {
    socket_type: u8,
    state: u8,
    pending_op: u8,
    _pad: u8,
    local_id: u16,
    remote_id: u16,
    remote_endpoint: u32,
    tx_pending: u16,
    rx_available: u16,
    rx_space: u16,
}

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

    // Socket service
    socket_count: u8,
    _sock_pad: [u8; 3],

    // Frame buffers
    rx_frame: [u8; MAX_FRAME_SIZE],
    tx_frame: [u8; MAX_FRAME_SIZE],

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

/// Get a socket slot's info via dev_call.
unsafe fn socket_info(s: &IpState, slot_idx: i32, info: &mut SocketServiceInfo) -> i32 {
    let sys = &*s.syscalls;
    (sys.dev_call)(
        slot_idx,
        DEV_SOCKET_SERVICE_INFO,
        info as *mut SocketServiceInfo as *mut u8,
        core::mem::size_of::<SocketServiceInfo>(),
    )
}

/// Read from socket TX buffer via dev_call.
unsafe fn socket_tx_read(s: &IpState, slot_idx: i32, buf: *mut u8, len: usize) -> i32 {
    let sys = &*s.syscalls;
    (sys.dev_call)(slot_idx, DEV_SOCKET_SERVICE_TX_READ, buf, len)
}

/// Write to socket RX buffer via dev_call.
unsafe fn socket_rx_write(s: &IpState, slot_idx: i32, data: *const u8, len: usize) -> i32 {
    let sys = &*s.syscalls;
    (sys.dev_call)(slot_idx, DEV_SOCKET_SERVICE_RX_WRITE, data as *mut u8, len)
}

/// Complete a pending socket operation via dev_call.
/// `poll_flags` sets provider-controlled readiness (POLL_CONN, POLL_HUP, POLL_ERR).
unsafe fn socket_complete_op(s: &IpState, slot_idx: i32, result: i32, new_state: SocketPhase, poll_flags: u8) {
    let sys = &*s.syscalls;
    let mut arg = [0u8; 6];
    let r = result.to_le_bytes();
    arg[0] = r[0];
    arg[1] = r[1];
    arg[2] = r[2];
    arg[3] = r[3];
    arg[4] = new_state as u8;
    arg[5] = poll_flags;
    (sys.dev_call)(
        slot_idx,
        DEV_SOCKET_SERVICE_COMPLETE_OP,
        arg.as_mut_ptr(),
        6,
    );
}

/// Set socket state via dev_call.
/// `poll_flags` sets provider-controlled readiness (POLL_CONN, POLL_HUP, POLL_ERR).
unsafe fn socket_set_state(s: &IpState, slot_idx: i32, state: SocketPhase, poll_flags: u8) {
    let sys = &*s.syscalls;
    let mut arg = [state as u8, poll_flags];
    (sys.dev_call)(
        slot_idx,
        DEV_SOCKET_SERVICE_SET_STATE,
        arg.as_mut_ptr(),
        2,
    );
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
unsafe fn send_frame(s: &mut IpState, frame: *const u8, len: usize) {
    if s.out_chan < 0 || len == 0 {
        log_info(s, b"[ip] send_frame: no out_chan");
        return;
    }
    let sys = &*s.syscalls;
    let poll = (sys.channel_poll)(s.out_chan, POLL_OUT);
    if poll > 0 && (poll as u8 & POLL_OUT) != 0 {
        (sys.channel_write)(s.out_chan, frame, len);
        s.tx_frame_count = s.tx_frame_count.wrapping_add(1);
    } else {
        log_info(s, b"[ip] send_frame: chan full");
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

        // Query socket count
        let sys = &*s.syscalls;
        let count = (sys.dev_call)(-1, DEV_SOCKET_SERVICE_COUNT, core::ptr::null_mut(), 0);
        if count > 0 {
            s.socket_count = count as u8;
        }

        // Parse TLV params
        if !params.is_null() && params_len > 0 {
            params_def::parse_tlv_v2(s, params, params_len);
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

    // 0. Lazy-init: find an active netif to push IP config to
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
        let mut p = prefix.len();
        let mut m = 0;
        while m < 6 && p + 2 < buf.len() {
            buf[p] = hex[(s.mac_addr[m] >> 4) as usize];
            buf[p + 1] = hex[(s.mac_addr[m] & 0x0F) as usize];
            p += 2;
            if m < 5 && p < buf.len() { buf[p] = b':'; p += 1; }
            m += 1;
        }
        log_info(s, &buf[..p]);
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

    // 3. Service socket slots
    service_sockets(s);

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
unsafe fn process_rx_frames(s: &mut IpState) {
    if s.in_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;

    // Process up to 4 frames per step
    let mut count = 0;
    while count < 4 {
        let poll = (sys.channel_poll)(s.in_chan, POLL_IN);
        if poll <= 0 || (poll as u8 & POLL_IN) == 0 {
            break;
        }

        let r = (sys.channel_read)(
            s.in_chan,
            s.rx_frame.as_mut_ptr(),
            MAX_FRAME_SIZE,
        );
        if r <= 0 {
            break;
        }

        let frame_len = r as usize;
        process_frame(s, frame_len);
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

    // Fallback MAC learning from frame headers (only if driver didn't provide MAC)
    if !s.mac_valid {
        let dst = eth::dst_mac(s.rx_frame.as_ptr());
        // Only learn from unicast destination (= our MAC)
        if dst[0] & 0x01 == 0 {
            s.mac_addr = dst;
            s.mac_valid = true;
        }
        // Don't learn from source MAC — that's another device's MAC
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

    // Always learn from ARP packets
    arp::insert(&mut s.arp_table, sender_ip, sender_mac);

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
            arp::insert(&mut s.arp_table, ip_hdr.src_ip, src_mac);
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

    // Deliver to matching UDP socket
    let mut i = 0;
    while i < s.socket_count as usize {
        let mut info = core::mem::zeroed::<SocketServiceInfo>();
        if socket_info(s, i as i32, &mut info) < 0 {
            i += 1;
            continue;
        }
        if info.socket_type == SOCK_TYPE_DGRAM && info.local_id == udp_hdr.dst_port {
            if info.state == SocketPhase::Allocated as u8 {
                // Framed mode for bound-but-not-connected sockets:
                // Prepend [src_ip:4][src_port:2][payload_len:2] before payload
                let total_len = 8 + udp_hdr.payload_len;
                // Check RX space before writing — avoid partial frame corruption
                if (info.rx_space as usize) < total_len {
                    return; // Drop datagram rather than corrupt framing
                }
                let mut hdr = [0u8; 8];
                let ip_bytes = ip_hdr.src_ip.to_le_bytes();
                hdr[0] = ip_bytes[0]; hdr[1] = ip_bytes[1];
                hdr[2] = ip_bytes[2]; hdr[3] = ip_bytes[3];
                let port_bytes = udp_hdr.src_port.to_le_bytes();
                hdr[4] = port_bytes[0]; hdr[5] = port_bytes[1];
                let len_bytes = (udp_hdr.payload_len as u16).to_le_bytes();
                hdr[6] = len_bytes[0]; hdr[7] = len_bytes[1];
                socket_rx_write(s, i as i32, hdr.as_ptr(), 8);
                let payload = data.add(udp_hdr.payload_offset);
                socket_rx_write(s, i as i32, payload, udp_hdr.payload_len);
                return;
            } else if info.state == SocketPhase::Connected as u8 {
                // Raw mode for connected sockets (existing behavior)
                let payload = data.add(udp_hdr.payload_offset);
                socket_rx_write(s, i as i32, payload, udp_hdr.payload_len);
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
            // No established connection — check for a listener if this is a SYN
            if (tcp_hdr.flags & tcp::SYN) != 0 && (tcp_hdr.flags & tcp::ACK) == 0 {
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
                    conn.rcv_wnd = 512;
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
                        if seq_between(conn.snd_una, tcp_hdr.ack_num, conn.snd_nxt.wrapping_add(1)) {
                            conn.snd_una = tcp_hdr.ack_num;
                        }
                        conn.snd_wnd = tcp_hdr.window;
                    }
                    if tcp_hdr.payload_len > 0 && tcp_hdr.seq_num == conn.rcv_nxt {
                        rx_payload_offset = tcp_hdr.payload_offset;
                        rx_payload_len = tcp_hdr.payload_len;
                        action = ACTION_RX_DATA;
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
            socket_complete_op(s, conn_idx as i32, 0, SocketPhase::Connected, POLL_CONN);
        }
        ACTION_COMPLETE_REFUSED => {
            socket_complete_op(s, conn_idx as i32, -111, SocketPhase::Closed, POLL_HUP | POLL_ERR);
        }
        ACTION_SET_CLOSED => {
            socket_set_state(s, conn_idx as i32, SocketPhase::Closed, POLL_HUP);
        }
        ACTION_SET_CLOSING => {
            send_tcp_control(s, conn_idx, tcp::ACK);
            socket_set_state(s, conn_idx as i32, SocketPhase::Closing, POLL_HUP);
        }
        ACTION_RX_DATA | ACTION_RX_DATA_FIN => {
            let payload = data.add(rx_payload_offset);
            let written = socket_rx_write(s, conn_idx as i32, payload, rx_payload_len);
            if written > 0 {
                (*s.tcp_conns.as_mut_ptr().add(conn_idx)).rcv_nxt = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).rcv_nxt.wrapping_add(written as u32);
            }
            send_tcp_control(s, conn_idx, tcp::ACK);
            if action == ACTION_RX_DATA_FIN {
                socket_set_state(s, conn_idx as i32, SocketPhase::Closing, POLL_HUP);
            }
        }
        ACTION_COMPLETE_ACCEPT => {
            socket_complete_op(s, conn_idx as i32, 0, SocketPhase::Connected, POLL_CONN);
            // Deliver piggybacked data (e.g. HTTP GET in same segment as ACK)
            if rx_payload_len > 0 {
                let payload = data.add(rx_payload_offset);
                let written = socket_rx_write(s, conn_idx as i32, payload, rx_payload_len);
                if written > 0 {
                    (*s.tcp_conns.as_mut_ptr().add(conn_idx)).rcv_nxt = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).rcv_nxt.wrapping_add(written as u32);
                }
                send_tcp_control(s, conn_idx, tcp::ACK);
            }
        }
        ACTION_RST_TO_LISTEN => {
            socket_set_state(s, conn_idx as i32, SocketPhase::Listening, 0);
        }
        ACTION_RETRANSMIT_SYNACK => {
            send_tcp_control(s, conn_idx, tcp::SYN | tcp::ACK);
        }
        _ => {}
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
        s.local_ip, remote_ip, 0,
    );

    let ip_total = (ipv4::IPV4_HEADER_LEN + tcp::TCP_HEADER_LEN) as u16;
    let ip_start = s.tx_frame.as_mut_ptr().add(eth::ETH_HEADER_LEN);
    s.ip_id = s.ip_id.wrapping_add(1);
    ipv4::build_ipv4_header(ip_start, ip_total, ipv4::PROTO_TCP, s.local_ip, remote_ip, s.ip_id);

    eth::build_eth_header(s.tx_frame.as_mut_ptr(), &dst_mac, &s.mac_addr, eth::ETHERTYPE_IPV4);

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
        flags, rcv_wnd, s.local_ip, remote_ip, 0,
    );

    let ip_total = (ipv4::IPV4_HEADER_LEN + tcp::TCP_HEADER_LEN) as u16;
    let ip_start = s.tx_frame.as_mut_ptr().add(eth::ETH_HEADER_LEN);
    s.ip_id = s.ip_id.wrapping_add(1);
    ipv4::build_ipv4_header(ip_start, ip_total, ipv4::PROTO_TCP, s.local_ip, remote_ip, s.ip_id);

    eth::build_eth_header(s.tx_frame.as_mut_ptr(), &dst_mac, &s.mac_addr, eth::ETHERTYPE_IPV4);

    let total = eth::ETH_HEADER_LEN + ip_total as usize;
    send_frame(s, s.tx_frame.as_ptr(), total);

    // Update snd_nxt for SYN/FIN (they consume sequence space)
    if (flags & tcp::SYN) != 0 || (flags & tcp::FIN) != 0 {
        (*s.tcp_conns.as_mut_ptr().add(conn_idx)).snd_nxt = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).snd_nxt.wrapping_add(1);
    }
}

/// Send TCP data segment for a connection.
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
        tcp::ACK | tcp::PSH, rcv_wnd, s.local_ip, remote_ip, payload_len,
    );

    // Copy payload after TCP header
    let payload_dst = tcp_start.add(tcp::TCP_HEADER_LEN);
    let mut i = 0;
    while i < payload_len {
        *payload_dst.add(i) = *payload.add(i);
        i += 1;
    }

    // Finalize TCP checksum with payload
    tcp::finalize_tcp_checksum(
        tcp_start, tcp::TCP_HEADER_LEN, payload_dst, payload_len,
        s.local_ip, remote_ip,
    );

    let ip_total = (ipv4::IPV4_HEADER_LEN + tcp::TCP_HEADER_LEN + payload_len) as u16;
    let ip_start = s.tx_frame.as_mut_ptr().add(eth::ETH_HEADER_LEN);
    s.ip_id = s.ip_id.wrapping_add(1);
    ipv4::build_ipv4_header(ip_start, ip_total, ipv4::PROTO_TCP, s.local_ip, remote_ip, s.ip_id);

    eth::build_eth_header(s.tx_frame.as_mut_ptr(), &dst_mac, &s.mac_addr, eth::ETHERTYPE_IPV4);

    let total = eth::ETH_HEADER_LEN + ip_total as usize;
    send_frame(s, s.tx_frame.as_ptr(), total);

    // Advance snd_nxt
    (*s.tcp_conns.as_mut_ptr().add(conn_idx)).snd_nxt = (*s.tcp_conns.as_mut_ptr().add(conn_idx)).snd_nxt.wrapping_add(payload_len as u32);
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
            // Start DHCP discovery — only generate XID once
            if s.dhcp.xid == 0 {
                s.dhcp.xid = s.step_count ^ 0xDEADBEEF;
                if s.dhcp.xid == 0 { s.dhcp.xid = 1; }
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
            // Already configured — nothing to do
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
            if s.dhcp.state == dhcp::DhcpState::Requesting {
                s.local_ip = offered_ip;
                s.netmask = if subnet_mask != 0 { subnet_mask } else { 0xFFFFFF00 };
                s.gateway = gateway;
                s.dns_server = dns;
                s.ip_configured = true;
                s.dhcp.state = dhcp::DhcpState::Bound;

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
// Socket Service
// ============================================================================

/// Poll socket slots and service pending operations + data transfer.
unsafe fn service_sockets(s: &mut IpState) {
    let count = s.socket_count as usize;
    let mut i = 0;
    while i < count {
        let mut info = core::mem::zeroed::<SocketServiceInfo>();
        if socket_info(s, i as i32, &mut info) < 0 {
            i += 1;
            continue;
        }

        // Skip free sockets
        if info.socket_type == 0 {
            i += 1;
            continue;
        }

        // Handle pending operations
        if info.pending_op != SOCKOP_NONE {
            service_socket_op(s, i, &info);
        }

        // Handle TX data for connected sockets and bound-unconnected datagrams
        if info.tx_pending > 0
            && (info.state == SocketPhase::Connected as u8
                || (info.state == SocketPhase::Allocated as u8 && info.socket_type == SOCK_TYPE_DGRAM))
        {
            service_socket_tx(s, i, &info);
        }

        i += 1;
    }
}

/// Service a pending socket operation.
///
// ════════════════════════════════════════════════════════════════
// Socket Phase Transitions
// ════════════════════════════════════════════════════════════════
//
// Phase      | Trigger                      | Next        | Notes
// ───────────|──────────────────────────────|─────────────|────────────────
// Free       | open()                       | Allocated   | kernel allocs slot
// Allocated  | CONNECT (TCP)                | Connecting  | send SYN
// Allocated  | CONNECT (UDP)                | Connected   | immediate
// Allocated  | BIND                         | Allocated   | set local_id
// Allocated  | LISTEN (TCP)                 | Listening   |
// Allocated  | CLOSE                        | Closed      |
// Connecting | TCP SYN+ACK received         | Connected   | complete_op
// Connecting | timeout / RST                | Closed      | complete_op + ERR
// Connected  | CLOSE / FIN received         | Closing     |
// Connected  | RST received                 | Closed      |
// Listening  | ACCEPT + SYN received        | Connected   | complete_op
// Closing    | FIN_WAIT / LAST_ACK complete | Closed      |
// Closed     | (terminal)                   | —           | kernel reclaims
//
unsafe fn service_socket_op(s: &mut IpState, slot_idx: usize, info: &SocketServiceInfo) {
    match info.pending_op {
        SOCKOP_CONNECT => {
            if info.socket_type == SOCK_TYPE_STREAM {
                if slot_idx < tcp::MAX_TCP_CONNS {
                    let local_port = if info.local_id != 0 {
                        info.local_id
                    } else {
                        next_port(s)
                    };
                    let iss = s.step_count.wrapping_mul(2654435761);

                    (*s.tcp_conns.as_mut_ptr().add(slot_idx)).state = tcp::TcpState::SynSent;
                    (*s.tcp_conns.as_mut_ptr().add(slot_idx)).remote_ip = info.remote_endpoint;
                    (*s.tcp_conns.as_mut_ptr().add(slot_idx)).remote_port = info.remote_id;
                    (*s.tcp_conns.as_mut_ptr().add(slot_idx)).local_port = local_port;
                    (*s.tcp_conns.as_mut_ptr().add(slot_idx)).iss = iss;
                    (*s.tcp_conns.as_mut_ptr().add(slot_idx)).snd_nxt = iss;
                    (*s.tcp_conns.as_mut_ptr().add(slot_idx)).snd_una = iss;
                    (*s.tcp_conns.as_mut_ptr().add(slot_idx)).rcv_wnd = 512;
                    (*s.tcp_conns.as_mut_ptr().add(slot_idx)).retransmit_timer = 0;

                    send_tcp_control(s, slot_idx, tcp::SYN);
                }
            } else if info.socket_type == SOCK_TYPE_DGRAM {
                socket_complete_op(s, slot_idx as i32, 0, SocketPhase::Connected, POLL_CONN);
            }
        }
        SOCKOP_BIND => {
            log_info(s, b"[ip] sock bind");
            socket_complete_op(s, slot_idx as i32, 0, SocketPhase::Allocated, 0);
        }
        SOCKOP_CLOSE => {
            if info.socket_type == SOCK_TYPE_STREAM && slot_idx < tcp::MAX_TCP_CONNS {
                let conn_state = (*s.tcp_conns.as_mut_ptr().add(slot_idx)).state;
                match conn_state {
                    tcp::TcpState::Established => {
                        send_tcp_control(s, slot_idx, tcp::FIN | tcp::ACK);
                        (*s.tcp_conns.as_mut_ptr().add(slot_idx)).state = tcp::TcpState::FinWait1;
                    }
                    tcp::TcpState::CloseWait => {
                        send_tcp_control(s, slot_idx, tcp::FIN | tcp::ACK);
                        (*s.tcp_conns.as_mut_ptr().add(slot_idx)).state = tcp::TcpState::LastAck;
                    }
                    _ => {
                        (*s.tcp_conns.as_mut_ptr().add(slot_idx)).state = tcp::TcpState::Closed;
                        socket_complete_op(s, slot_idx as i32, 0, SocketPhase::Closed, POLL_HUP);
                    }
                }
            } else {
                socket_complete_op(s, slot_idx as i32, 0, SocketPhase::Closed, POLL_HUP);
            }
        }
        SOCKOP_LISTEN => {
            if info.socket_type == SOCK_TYPE_STREAM && slot_idx < tcp::MAX_TCP_CONNS {
                log_info(s, b"[ip] sock listen");
                let conn = &mut *s.tcp_conns.as_mut_ptr().add(slot_idx);
                conn.state = tcp::TcpState::Listen;
                conn.local_port = info.local_id;
                conn.remote_ip = 0;
                conn.remote_port = 0;
                conn.retransmit_timer = 0;
                socket_complete_op(s, slot_idx as i32, 0, SocketPhase::Listening, 0);
            } else {
                socket_complete_op(s, slot_idx as i32, -22, SocketPhase::Allocated, POLL_ERR); // EINVAL
            }
        }
        SOCKOP_ACCEPT => {
            if info.socket_type == SOCK_TYPE_STREAM && slot_idx < tcp::MAX_TCP_CONNS {
                let conn_state = (*s.tcp_conns.as_ptr().add(slot_idx)).state;
                if conn_state == tcp::TcpState::Established {
                    // SYN already arrived and handshake completed — finish accept now
                    socket_complete_op(s, slot_idx as i32, 0, SocketPhase::Connected, POLL_CONN);
                }
                // Otherwise remain pending — completed when SYN-ACK-ACK finishes
                // in process_tcp_segment
            } else {
                socket_complete_op(s, slot_idx as i32, -22, SocketPhase::Allocated, POLL_ERR);
            }
        }
        _ => {}
    }
}

/// Drain TX data from a socket and send it.
unsafe fn service_socket_tx(s: &mut IpState, slot_idx: usize, info: &SocketServiceInfo) {
    if info.socket_type == SOCK_TYPE_STREAM && slot_idx < tcp::MAX_TCP_CONNS {
        let conn = &*s.tcp_conns.as_ptr().add(slot_idx);
        if conn.state != tcp::TcpState::Established {
            return;
        }
        let in_flight = conn.snd_nxt.wrapping_sub(conn.snd_una) as usize;
        let can_send = (conn.snd_wnd as usize).saturating_sub(in_flight).min(1400);
        if can_send == 0 {
            return;
        }
        // Only read what we can actually send — read is destructive
        let mut tx_buf = [0u8; 1400];
        let max_read = can_send.min(tx_buf.len());
        let read = socket_tx_read(s, slot_idx as i32, tx_buf.as_mut_ptr(), max_read);
        if read <= 0 {
            return;
        }
        send_tcp_data(s, slot_idx, tx_buf.as_ptr(), read as usize);
    } else if info.socket_type == SOCK_TYPE_DGRAM {
        // Read TX data from socket buffer
        let mut tx_buf = [0u8; 512];
        let read = socket_tx_read(s, slot_idx as i32, tx_buf.as_mut_ptr(), tx_buf.len());
        if read <= 0 {
            return;
        }
        let data_len = read as usize;

        if info.state == SocketPhase::Allocated as u8 && data_len >= 8 {
            // Framed mode for bound-but-not-connected sockets:
            // TX buffer contains [dst_ip:4][dst_port:2][payload_len:2][payload:N]
            let dst_ip = u32::from_le_bytes([tx_buf[0], tx_buf[1], tx_buf[2], tx_buf[3]]);
            let dst_port = u16::from_le_bytes([tx_buf[4], tx_buf[5]]);
            let payload_len = u16::from_le_bytes([tx_buf[6], tx_buf[7]]) as usize;
            if payload_len > 0 && 8 + payload_len <= data_len && s.mac_valid && s.local_ip != 0 {
                let dst_mac = resolve_mac(s, dst_ip);
                if let Some(dm) = dst_mac {
                    let hdr_offset = eth::ETH_HEADER_LEN + ipv4::IPV4_HEADER_LEN;
                    let udp_start = s.tx_frame.as_mut_ptr().add(hdr_offset);

                    udp::build_udp_header(
                        udp_start,
                        info.local_id,
                        dst_port,
                        payload_len,
                        s.local_ip,
                        dst_ip,
                        tx_buf.as_ptr().add(8),
                    );

                    // Copy payload after UDP header
                    let payload_dst = udp_start.add(udp::UDP_HEADER_LEN);
                    let mut j = 0;
                    while j < payload_len {
                        *payload_dst.add(j) = *tx_buf.as_ptr().add(8 + j);
                        j += 1;
                    }

                    let ip_total = (ipv4::IPV4_HEADER_LEN + udp::UDP_HEADER_LEN + payload_len) as u16;
                    let ip_start = s.tx_frame.as_mut_ptr().add(eth::ETH_HEADER_LEN);
                    s.ip_id = s.ip_id.wrapping_add(1);
                    ipv4::build_ipv4_header(
                        ip_start, ip_total, ipv4::PROTO_UDP,
                        s.local_ip, dst_ip, s.ip_id,
                    );

                    eth::build_eth_header(
                        s.tx_frame.as_mut_ptr(), &dm, &s.mac_addr, eth::ETHERTYPE_IPV4,
                    );

                    let total = eth::ETH_HEADER_LEN + ip_total as usize;
                    send_frame(s, s.tx_frame.as_ptr(), total);
                }
            }
        } else if info.state == SocketPhase::Connected as u8 {
            // Connected mode: use info.remote_endpoint/remote_id
            if s.mac_valid && s.local_ip != 0 {
                let dst_mac = resolve_mac(s, info.remote_endpoint);
                if let Some(dm) = dst_mac {
                    let hdr_offset = eth::ETH_HEADER_LEN + ipv4::IPV4_HEADER_LEN;
                    let udp_start = s.tx_frame.as_mut_ptr().add(hdr_offset);

                    udp::build_udp_header(
                        udp_start,
                        info.local_id,
                        info.remote_id,
                        data_len,
                        s.local_ip,
                        info.remote_endpoint,
                        tx_buf.as_ptr(),
                    );

                    // Copy payload after UDP header
                    let payload_dst = udp_start.add(udp::UDP_HEADER_LEN);
                    let mut j = 0;
                    while j < data_len {
                        *payload_dst.add(j) = *tx_buf.as_ptr().add(j);
                        j += 1;
                    }

                    let ip_total = (ipv4::IPV4_HEADER_LEN + udp::UDP_HEADER_LEN + data_len) as u16;
                    let ip_start = s.tx_frame.as_mut_ptr().add(eth::ETH_HEADER_LEN);
                    s.ip_id = s.ip_id.wrapping_add(1);
                    ipv4::build_ipv4_header(
                        ip_start, ip_total, ipv4::PROTO_UDP,
                        s.local_ip, info.remote_endpoint, s.ip_id,
                    );

                    eth::build_eth_header(
                        s.tx_frame.as_mut_ptr(), &dm, &s.mac_addr, eth::ETHERTYPE_IPV4,
                    );

                    let total = eth::ETH_HEADER_LEN + ip_total as usize;
                    send_frame(s, s.tx_frame.as_ptr(), total);
                }
            }
        }
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
                    conn.state = tcp::TcpState::Closed;
                    socket_set_state(s, i as i32, SocketPhase::Closed, POLL_HUP);
                }
            }
            _ => {}
        }
        i += 1;
    }
}
