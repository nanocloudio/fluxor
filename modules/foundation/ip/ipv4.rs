//! IPv4 protocol — header parsing, building, and checksum.

/// IPv4 header minimum length (no options)
pub const IPV4_HEADER_LEN: usize = 20;

/// IPv4 protocol numbers
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// Parsed IPv4 header fields
pub struct Ipv4Header {
    pub ihl: u8,          // header length in 32-bit words
    pub total_len: u16,
    pub identification: u16,
    pub flags_frag: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub header_len: usize, // ihl * 4
}

/// Parse IPv4 header from raw data.
///
/// # Safety
/// `data` must point to at least `len` valid bytes.
pub unsafe fn parse_ipv4(data: *const u8, len: usize) -> Option<Ipv4Header> {
    if len < IPV4_HEADER_LEN {
        return None;
    }

    let ver_ihl = *data;
    let version = ver_ihl >> 4;
    let ihl = ver_ihl & 0x0F;

    if version != 4 || ihl < 5 {
        return None;
    }

    let header_len = (ihl as usize) * 4;
    if len < header_len {
        return None;
    }

    let total_len = (*data.add(2) as u16) << 8 | (*data.add(3) as u16);
    if (total_len as usize) > len {
        return None;
    }

    let identification = (*data.add(4) as u16) << 8 | (*data.add(5) as u16);
    let flags_frag = (*data.add(6) as u16) << 8 | (*data.add(7) as u16);
    let ttl = *data.add(8);
    let protocol = *data.add(9);

    let src_ip = u32::from_be_bytes([
        *data.add(12), *data.add(13), *data.add(14), *data.add(15),
    ]);
    let dst_ip = u32::from_be_bytes([
        *data.add(16), *data.add(17), *data.add(18), *data.add(19),
    ]);

    // Verify header checksum
    let cksum = checksum(data, header_len);
    if cksum != 0 {
        return None;
    }

    Some(Ipv4Header {
        ihl,
        total_len,
        identification,
        flags_frag,
        ttl,
        protocol,
        src_ip,
        dst_ip,
        header_len,
    })
}

/// Compute IP checksum over `len` bytes at `data`.
///
/// # Safety
/// `data` must point to at least `len` valid bytes.
pub unsafe fn checksum(data: *const u8, len: usize) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < len {
        sum += ((*data.add(i) as u32) << 8) | (*data.add(i + 1) as u32);
        i += 2;
    }
    if i < len {
        sum += (*data.add(i) as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an IPv4 header at `dst`. Does NOT set checksum — call finalize_checksum after.
/// Returns header length (always 20 for no-options).
///
/// # Safety
/// `dst` must point to at least 20 writable bytes.
pub unsafe fn build_ipv4_header(
    dst: *mut u8,
    total_len: u16,
    protocol: u8,
    src_ip: u32,
    dst_ip: u32,
    identification: u16,
) -> usize {
    // Version (4) + IHL (5) = 0x45
    *dst = 0x45;
    // DSCP + ECN
    *dst.add(1) = 0x00;
    // Total length
    *dst.add(2) = (total_len >> 8) as u8;
    *dst.add(3) = (total_len & 0xFF) as u8;
    // Identification
    *dst.add(4) = (identification >> 8) as u8;
    *dst.add(5) = (identification & 0xFF) as u8;
    // Flags (Don't Fragment) + Fragment offset
    *dst.add(6) = 0x40; // DF flag
    *dst.add(7) = 0x00;
    // TTL
    *dst.add(8) = 64;
    // Protocol
    *dst.add(9) = protocol;
    // Checksum placeholder (computed after)
    *dst.add(10) = 0;
    *dst.add(11) = 0;
    // Source IP
    let src = src_ip.to_be_bytes();
    *dst.add(12) = src[0];
    *dst.add(13) = src[1];
    *dst.add(14) = src[2];
    *dst.add(15) = src[3];
    // Destination IP
    let d = dst_ip.to_be_bytes();
    *dst.add(16) = d[0];
    *dst.add(17) = d[1];
    *dst.add(18) = d[2];
    *dst.add(19) = d[3];

    // Compute and set checksum
    let cksum = checksum(dst, 20);
    *dst.add(10) = (cksum >> 8) as u8;
    *dst.add(11) = (cksum & 0xFF) as u8;

    IPV4_HEADER_LEN
}

/// Compute TCP/UDP pseudo-header checksum component.
///
/// # Safety
/// This adds src_ip, dst_ip, protocol, and payload_len to the checksum accumulator.
pub fn pseudo_header_sum(src_ip: u32, dst_ip: u32, protocol: u8, payload_len: u16) -> u32 {
    let src = src_ip.to_be_bytes();
    let dst = dst_ip.to_be_bytes();
    let mut sum: u32 = 0;
    sum += ((src[0] as u32) << 8) | (src[1] as u32);
    sum += ((src[2] as u32) << 8) | (src[3] as u32);
    sum += ((dst[0] as u32) << 8) | (dst[1] as u32);
    sum += ((dst[2] as u32) << 8) | (dst[3] as u32);
    sum += protocol as u32;
    sum += payload_len as u32;
    sum
}

/// Finalize a checksum accumulator to a 16-bit ones-complement value.
pub fn finalize_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
