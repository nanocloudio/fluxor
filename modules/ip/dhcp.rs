//! DHCP client — minimal DHCP for automatic IP configuration.
//!
//! Implements DISCOVER → OFFER → REQUEST → ACK flow.

use super::ipv4;
use super::udp;
use super::eth;

/// DHCP ports
pub const DHCP_CLIENT_PORT: u16 = 68;
pub const DHCP_SERVER_PORT: u16 = 67;

/// DHCP message types
pub const DHCP_DISCOVER: u8 = 1;
pub const DHCP_OFFER: u8 = 2;
pub const DHCP_REQUEST: u8 = 3;
pub const DHCP_ACK: u8 = 5;
pub const DHCP_NAK: u8 = 6;

/// DHCP opcodes
pub const BOOTREQUEST: u8 = 1;
pub const BOOTREPLY: u8 = 2;

/// DHCP header length (fixed portion before options)
pub const DHCP_HEADER_LEN: usize = 236;
/// DHCP magic cookie
pub const DHCP_MAGIC: [u8; 4] = [99, 130, 83, 99];

/// DHCP client state (RFC 2131 §4.4).
///
// ════════════════════════════════════════════════════════════════
// DHCP State Transitions (RFC 2131, simplified)
// ════════════════════════════════════════════════════════════════
//
// State        | Trigger              | Next          | Action
// ─────────────|──────────────────────|───────────────|────────────────
// Idle         | start / lease expire | Discovering   | send DISCOVER
// Discovering  | recv OFFER           | Requesting    | send REQUEST
// Discovering  | timeout              | Discovering   | retransmit
// Requesting   | recv ACK             | Bound         | apply config
// Requesting   | recv NAK             | Discovering   | restart
// Requesting   | timeout              | Discovering   | restart
// Bound        | lease expires        | Discovering   | renew
//
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DhcpState {
    Idle = 0,
    Discovering = 1,
    Requesting = 2,
    Bound = 3,
}

/// DHCP client data
pub struct DhcpClient {
    pub state: DhcpState,
    pub xid: u32,
    pub offered_ip: u32,
    pub server_ip: u32,
    pub subnet_mask: u32,
    pub gateway: u32,
    pub dns_server: u32,
    pub lease_time: u32,
    /// Timer for retransmits/renewals (in step counts)
    pub timer: u32,
    /// Retry count
    pub retries: u8,
}

impl DhcpClient {
    pub const fn new() -> Self {
        Self {
            state: DhcpState::Idle,
            xid: 0, // Set once on first discover from step_count
            offered_ip: 0,
            server_ip: 0,
            subnet_mask: 0,
            gateway: 0,
            dns_server: 0,
            lease_time: 0,
            timer: 0,
            retries: 0,
        }
    }
}

/// Build a DHCP DISCOVER or REQUEST message.
/// Returns total frame length (eth + ip + udp + dhcp).
///
/// # Safety
/// `buf` must point to at least 400 writable bytes.
/// `mac` is the client's MAC address.
pub unsafe fn build_dhcp_message(
    buf: *mut u8,
    msg_type: u8,
    mac: &[u8; 6],
    xid: u32,
    requested_ip: u32,
    server_ip: u32,
) -> usize {
    // Leave room for eth + ip + udp headers
    let dhcp_start = eth::ETH_HEADER_LEN + ipv4::IPV4_HEADER_LEN + udp::UDP_HEADER_LEN;
    let d = buf.add(dhcp_start);

    // Zero the DHCP portion
    let mut i = 0;
    while i < 300 {
        *d.add(i) = 0;
        i += 1;
    }

    // BOOTP header
    *d = BOOTREQUEST; // op
    *d.add(1) = 1;    // htype (Ethernet)
    *d.add(2) = 6;    // hlen (MAC = 6)
    *d.add(3) = 0;    // hops

    // XID (transaction ID)
    let xid_bytes = xid.to_be_bytes();
    *d.add(4) = xid_bytes[0];
    *d.add(5) = xid_bytes[1];
    *d.add(6) = xid_bytes[2];
    *d.add(7) = xid_bytes[3];

    // secs, flags (broadcast flag)
    *d.add(10) = 0x80; // Broadcast flag
    *d.add(11) = 0x00;

    // chaddr (client hardware address)
    i = 0;
    while i < 6 {
        *d.add(28 + i) = *mac.as_ptr().add(i);
        i += 1;
    }

    // Magic cookie at offset 236
    *d.add(236) = DHCP_MAGIC[0];
    *d.add(237) = DHCP_MAGIC[1];
    *d.add(238) = DHCP_MAGIC[2];
    *d.add(239) = DHCP_MAGIC[3];

    // DHCP options
    let mut opt = 240;

    // Option 53: DHCP Message Type
    *d.add(opt) = 53;
    *d.add(opt + 1) = 1;
    *d.add(opt + 2) = msg_type;
    opt += 3;

    if msg_type == DHCP_REQUEST {
        // Option 50: Requested IP Address
        if requested_ip != 0 {
            *d.add(opt) = 50;
            *d.add(opt + 1) = 4;
            let ip = requested_ip.to_be_bytes();
            *d.add(opt + 2) = ip[0];
            *d.add(opt + 3) = ip[1];
            *d.add(opt + 4) = ip[2];
            *d.add(opt + 5) = ip[3];
            opt += 6;
        }

        // Option 54: Server Identifier
        if server_ip != 0 {
            *d.add(opt) = 54;
            *d.add(opt + 1) = 4;
            let ip = server_ip.to_be_bytes();
            *d.add(opt + 2) = ip[0];
            *d.add(opt + 3) = ip[1];
            *d.add(opt + 4) = ip[2];
            *d.add(opt + 5) = ip[3];
            opt += 6;
        }
    }

    // Option 55: Parameter Request List
    *d.add(opt) = 55;
    *d.add(opt + 1) = 3;
    *d.add(opt + 2) = 1;  // Subnet Mask
    *d.add(opt + 3) = 3;  // Router
    *d.add(opt + 4) = 6;  // DNS
    opt += 5;

    // End option
    *d.add(opt) = 255;
    opt += 1;

    let dhcp_len = DHCP_HEADER_LEN + 4 + (opt - 240); // header + magic + options
    // Pad to minimum 300 bytes
    let dhcp_len = if dhcp_len < 300 { 300 } else { dhcp_len };

    // Build UDP header
    let udp_start = buf.add(eth::ETH_HEADER_LEN + ipv4::IPV4_HEADER_LEN);
    udp::build_udp_header(
        udp_start,
        DHCP_CLIENT_PORT,
        DHCP_SERVER_PORT,
        dhcp_len,
        0, // src_ip = 0.0.0.0
        0xFFFFFFFF, // dst_ip = broadcast
        d, // payload
    );

    // Build IPv4 header
    let ip_total = (ipv4::IPV4_HEADER_LEN + udp::UDP_HEADER_LEN + dhcp_len) as u16;
    let ip_start = buf.add(eth::ETH_HEADER_LEN);
    ipv4::build_ipv4_header(
        ip_start,
        ip_total,
        ipv4::PROTO_UDP,
        0,           // src = 0.0.0.0
        0xFFFFFFFF,  // dst = broadcast
        0,
    );

    // Build Ethernet header (broadcast)
    eth::build_eth_header(buf, &eth::BROADCAST_MAC, mac, eth::ETHERTYPE_IPV4);

    eth::ETH_HEADER_LEN + ip_total as usize
}

/// Parse a DHCP reply (OFFER or ACK).
/// Returns (msg_type, offered_ip, server_ip, subnet_mask, gateway, dns, lease_time).
///
/// # Safety
/// `data` must point to at least `len` bytes of DHCP payload (after UDP header).
pub unsafe fn parse_dhcp_reply(
    data: *const u8,
    len: usize,
    expected_xid: u32,
) -> Option<(u8, u32, u32, u32, u32, u32, u32)> {
    if len < DHCP_HEADER_LEN + 4 {
        return None;
    }

    // Check op = BOOTREPLY
    if *data != BOOTREPLY {
        return None;
    }

    // Check XID
    let xid = u32::from_be_bytes([
        *data.add(4), *data.add(5), *data.add(6), *data.add(7),
    ]);
    if xid != expected_xid {
        return None;
    }

    // yiaddr (your IP address) at offset 16
    let offered_ip = u32::from_be_bytes([
        *data.add(16), *data.add(17), *data.add(18), *data.add(19),
    ]);

    // Check magic cookie
    if *data.add(236) != DHCP_MAGIC[0]
        || *data.add(237) != DHCP_MAGIC[1]
        || *data.add(238) != DHCP_MAGIC[2]
        || *data.add(239) != DHCP_MAGIC[3]
    {
        return None;
    }

    // Parse options
    let mut msg_type = 0u8;
    let mut server_ip = 0u32;
    let mut subnet_mask = 0u32;
    let mut gateway = 0u32;
    let mut dns = 0u32;
    let mut lease_time = 0u32;

    let mut pos = 240;
    while pos < len {
        let opt = *data.add(pos);
        if opt == 255 {
            break; // End
        }
        if opt == 0 {
            pos += 1; // Pad
            continue;
        }
        if pos + 1 >= len {
            break;
        }
        let opt_len = *data.add(pos + 1) as usize;
        let opt_data = pos + 2;
        if opt_data + opt_len > len {
            break;
        }

        match opt {
            53 if opt_len >= 1 => {
                msg_type = *data.add(opt_data);
            }
            54 if opt_len >= 4 => {
                server_ip = u32::from_be_bytes([
                    *data.add(opt_data),
                    *data.add(opt_data + 1),
                    *data.add(opt_data + 2),
                    *data.add(opt_data + 3),
                ]);
            }
            1 if opt_len >= 4 => {
                subnet_mask = u32::from_be_bytes([
                    *data.add(opt_data),
                    *data.add(opt_data + 1),
                    *data.add(opt_data + 2),
                    *data.add(opt_data + 3),
                ]);
            }
            3 if opt_len >= 4 => {
                gateway = u32::from_be_bytes([
                    *data.add(opt_data),
                    *data.add(opt_data + 1),
                    *data.add(opt_data + 2),
                    *data.add(opt_data + 3),
                ]);
            }
            6 if opt_len >= 4 => {
                dns = u32::from_be_bytes([
                    *data.add(opt_data),
                    *data.add(opt_data + 1),
                    *data.add(opt_data + 2),
                    *data.add(opt_data + 3),
                ]);
            }
            51 if opt_len >= 4 => {
                lease_time = u32::from_be_bytes([
                    *data.add(opt_data),
                    *data.add(opt_data + 1),
                    *data.add(opt_data + 2),
                    *data.add(opt_data + 3),
                ]);
            }
            _ => {}
        }

        pos = opt_data + opt_len;
    }

    if msg_type == 0 {
        return None;
    }

    Some((msg_type, offered_ip, server_ip, subnet_mask, gateway, dns, lease_time))
}
