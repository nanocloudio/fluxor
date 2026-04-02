//! ARP protocol — address resolution for IPv4 over Ethernet.
//!
//! Maintains a small ARP table and handles request/reply.
//! All array access uses raw pointer arithmetic to avoid
//! panic_bounds_check in PIC modules.

use super::eth;

/// ARP header length (hardware type through target protocol addr)
pub const ARP_HEADER_LEN: usize = 28;

/// ARP opcodes
pub const ARP_REQUEST: u16 = 1;
pub const ARP_REPLY: u16 = 2;

/// ARP table entry
#[derive(Clone, Copy)]
pub struct ArpEntry {
    pub ip: u32,
    pub mac: [u8; 6],
    pub valid: bool,
    /// Age in step counts (for eviction)
    pub age: u16,
}

impl ArpEntry {
    pub const fn empty() -> Self {
        Self {
            ip: 0,
            mac: [0; 6],
            valid: false,
            age: 0,
        }
    }
}

/// ARP table size
pub const ARP_TABLE_SIZE: usize = 8;

/// ARP pending request state
pub const ARP_PENDING_NONE: u8 = 0;
pub const ARP_PENDING_WAITING: u8 = 1;

/// Look up MAC address for an IPv4 address.
/// Returns Some(mac) if found, None if not in table.
///
/// # Safety
/// Uses raw pointer access to avoid bounds checks in PIC.
pub fn lookup(table: &[ArpEntry; ARP_TABLE_SIZE], ip: u32) -> Option<[u8; 6]> {
    unsafe {
        let mut i = 0;
        while i < ARP_TABLE_SIZE {
            let entry = &*table.as_ptr().add(i);
            if entry.valid && entry.ip == ip {
                return Some(entry.mac);
            }
            i += 1;
        }
    }
    None
}

/// Insert or update an ARP table entry.
///
/// # Safety
/// Uses raw pointer access to avoid bounds checks in PIC.
pub fn insert(table: &mut [ArpEntry; ARP_TABLE_SIZE], ip: u32, mac: [u8; 6]) {
    unsafe {
        // Check if already exists
        let mut i = 0;
        while i < ARP_TABLE_SIZE {
            let entry = &mut *table.as_mut_ptr().add(i);
            if entry.valid && entry.ip == ip {
                entry.mac = mac;
                entry.age = 0;
                return;
            }
            i += 1;
        }

        // Find empty slot
        i = 0;
        while i < ARP_TABLE_SIZE {
            let entry = &*table.as_ptr().add(i);
            if !entry.valid {
                *table.as_mut_ptr().add(i) = ArpEntry { ip, mac, valid: true, age: 0 };
                return;
            }
            i += 1;
        }

        // Evict oldest entry
        let mut oldest_idx = 0;
        let mut oldest_age = 0u16;
        i = 0;
        while i < ARP_TABLE_SIZE {
            let entry = &*table.as_ptr().add(i);
            if entry.age > oldest_age {
                oldest_age = entry.age;
                oldest_idx = i;
            }
            i += 1;
        }
        *table.as_mut_ptr().add(oldest_idx) = ArpEntry { ip, mac, valid: true, age: 0 };
    }
}

/// Age all ARP table entries (call periodically).
///
/// # Safety
/// Uses raw pointer access to avoid bounds checks in PIC.
pub fn age_entries(table: &mut [ArpEntry; ARP_TABLE_SIZE]) {
    unsafe {
        let mut i = 0;
        while i < ARP_TABLE_SIZE {
            let entry = &mut *table.as_mut_ptr().add(i);
            if entry.valid {
                entry.age = entry.age.saturating_add(1);
                // Expire entries after ~5 minutes (at ~20ms step rate = 15000 steps)
                if entry.age > 15000 {
                    entry.valid = false;
                }
            }
            i += 1;
        }
    }
}

/// Parse an ARP packet and return (opcode, sender_ip, sender_mac, target_ip).
///
/// # Safety
/// `data` must point to at least `len` valid bytes of ARP payload (after eth header).
pub unsafe fn parse_arp(data: *const u8, len: usize) -> Option<(u16, u32, [u8; 6], u32)> {
    if len < ARP_HEADER_LEN {
        return None;
    }

    // Hardware type must be Ethernet (1)
    let hw_type = (*data as u16) << 8 | (*data.add(1) as u16);
    if hw_type != 1 {
        return None;
    }

    // Protocol type must be IPv4 (0x0800)
    let proto_type = (*data.add(2) as u16) << 8 | (*data.add(3) as u16);
    if proto_type != eth::ETHERTYPE_IPV4 {
        return None;
    }

    // Hardware addr len = 6, protocol addr len = 4
    if *data.add(4) != 6 || *data.add(5) != 4 {
        return None;
    }

    let opcode = (*data.add(6) as u16) << 8 | (*data.add(7) as u16);

    // Sender hardware address (MAC) at offset 8
    let mut sender_mac = [0u8; 6];
    let mut i = 0;
    while i < 6 {
        *sender_mac.as_mut_ptr().add(i) = *data.add(8 + i);
        i += 1;
    }

    // Sender protocol address (IP) at offset 14
    let sender_ip = u32::from_be_bytes([
        *data.add(14), *data.add(15), *data.add(16), *data.add(17),
    ]);

    // Target protocol address (IP) at offset 24
    let target_ip = u32::from_be_bytes([
        *data.add(24), *data.add(25), *data.add(26), *data.add(27),
    ]);

    Some((opcode, sender_ip, sender_mac, target_ip))
}

/// Build an ARP reply or request in `buf`.
/// Returns total frame length (eth header + ARP).
///
/// # Safety
/// `buf` must point to at least `ETH_HEADER_LEN + ARP_HEADER_LEN` writable bytes.
pub unsafe fn build_arp(
    buf: *mut u8,
    opcode: u16,
    src_mac: &[u8; 6],
    src_ip: u32,
    dst_mac: &[u8; 6],
    dst_ip: u32,
) -> usize {
    // Ethernet header
    let eth_dst = if opcode == ARP_REQUEST { &eth::BROADCAST_MAC } else { dst_mac };
    eth::build_eth_header(buf, eth_dst, src_mac, eth::ETHERTYPE_ARP);

    let p = buf.add(eth::ETH_HEADER_LEN);

    // Hardware type: Ethernet (1)
    *p.add(0) = 0x00;
    *p.add(1) = 0x01;
    // Protocol type: IPv4
    *p.add(2) = 0x08;
    *p.add(3) = 0x00;
    // Hardware addr len, protocol addr len
    *p.add(4) = 6;
    *p.add(5) = 4;
    // Opcode
    *p.add(6) = (opcode >> 8) as u8;
    *p.add(7) = (opcode & 0xFF) as u8;

    // Sender hardware address
    let mut i = 0;
    while i < 6 {
        *p.add(8 + i) = *src_mac.as_ptr().add(i);
        i += 1;
    }

    // Sender protocol address
    let src_ip_bytes = src_ip.to_be_bytes();
    *p.add(14) = src_ip_bytes[0];
    *p.add(15) = src_ip_bytes[1];
    *p.add(16) = src_ip_bytes[2];
    *p.add(17) = src_ip_bytes[3];

    // Target hardware address
    i = 0;
    while i < 6 {
        *p.add(18 + i) = *dst_mac.as_ptr().add(i);
        i += 1;
    }

    // Target protocol address
    let dst_ip_bytes = dst_ip.to_be_bytes();
    *p.add(24) = dst_ip_bytes[0];
    *p.add(25) = dst_ip_bytes[1];
    *p.add(26) = dst_ip_bytes[2];
    *p.add(27) = dst_ip_bytes[3];

    eth::ETH_HEADER_LEN + ARP_HEADER_LEN
}
