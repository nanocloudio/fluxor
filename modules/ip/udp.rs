//! UDP protocol — minimal connectionless datagram support.

use super::ipv4;

/// UDP header length
pub const UDP_HEADER_LEN: usize = 8;

/// Parsed UDP header
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub payload_offset: usize,
    pub payload_len: usize,
}

/// Parse a UDP header from raw data.
///
/// # Safety
/// `data` must point to at least `len` valid bytes of UDP data (after IP header).
pub unsafe fn parse_udp(data: *const u8, len: usize) -> Option<UdpHeader> {
    if len < UDP_HEADER_LEN {
        return None;
    }

    let src_port = (*data as u16) << 8 | (*data.add(1) as u16);
    let dst_port = (*data.add(2) as u16) << 8 | (*data.add(3) as u16);
    let length = (*data.add(4) as u16) << 8 | (*data.add(5) as u16);

    if (length as usize) < UDP_HEADER_LEN || (length as usize) > len {
        return None;
    }

    let payload_len = length as usize - UDP_HEADER_LEN;

    Some(UdpHeader {
        src_port,
        dst_port,
        length,
        payload_offset: UDP_HEADER_LEN,
        payload_len,
    })
}

/// Build a UDP header at `dst`.
///
/// # Safety
/// `dst` must point to at least 8 writable bytes.
pub unsafe fn build_udp_header(
    dst: *mut u8,
    src_port: u16,
    dst_port: u16,
    payload_len: usize,
    src_ip: u32,
    dst_ip: u32,
    payload: *const u8,
) -> usize {
    let udp_len = (UDP_HEADER_LEN + payload_len) as u16;

    *dst = (src_port >> 8) as u8;
    *dst.add(1) = (src_port & 0xFF) as u8;
    *dst.add(2) = (dst_port >> 8) as u8;
    *dst.add(3) = (dst_port & 0xFF) as u8;
    *dst.add(4) = (udp_len >> 8) as u8;
    *dst.add(5) = (udp_len & 0xFF) as u8;
    // Checksum placeholder
    *dst.add(6) = 0;
    *dst.add(7) = 0;

    // Compute UDP checksum (pseudo-header + header + payload)
    let mut sum = ipv4::pseudo_header_sum(src_ip, dst_ip, ipv4::PROTO_UDP, udp_len);

    // Add UDP header to checksum
    let mut i = 0;
    while i + 1 < UDP_HEADER_LEN {
        sum += ((*dst.add(i) as u32) << 8) | (*dst.add(i + 1) as u32);
        i += 2;
    }

    // Add payload to checksum
    if !payload.is_null() {
        i = 0;
        while i + 1 < payload_len {
            sum += ((*payload.add(i) as u32) << 8) | (*payload.add(i + 1) as u32);
            i += 2;
        }
        if i < payload_len {
            sum += (*payload.add(i) as u32) << 8;
        }
    }

    let cksum = ipv4::finalize_checksum(sum);
    // UDP checksum of 0 means "no checksum"; use 0xFFFF instead
    let cksum = if cksum == 0 { 0xFFFF } else { cksum };
    *dst.add(6) = (cksum >> 8) as u8;
    *dst.add(7) = (cksum & 0xFF) as u8;

    UDP_HEADER_LEN
}
