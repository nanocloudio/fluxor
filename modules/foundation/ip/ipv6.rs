//! IPv6 wire primitives: the fixed header parsed and built, the transport
//! checksum over the RFC 8200 §8.1 pseudo-header, the textual address form
//! `ip6`, `seam_v6` and `gateway6` name, and the address classes the
//! receive path refuses.
//!
//! The receive path (`process_ipv6` in `mod.rs`) takes only packets with no
//! extension header: TCP and UDP to a local IPv6 address go to the
//! transports through `v6t.rs`, to a seam address to the director, and the
//! stack itself answers neighbour solicitation (RFC 4861 §7.2.4) and echo
//! for the addresses it holds.

/// The fixed header.
pub const IPV6_HEADER_LEN: usize = 40;

pub const NH_TCP: u8 = 6;
pub const NH_UDP: u8 = 17;
pub const NH_ICMPV6: u8 = 58;

pub const ICMPV6_UNREACHABLE: u8 = 1;
/// Destination unreachable, port unreachable (RFC 4443 §3.1).
pub const ICMPV6_UNREACH_PORT: u8 = 4;
pub const ICMPV6_ECHO_REQUEST: u8 = 128;
pub const ICMPV6_ECHO_REPLY: u8 = 129;
pub const ICMPV6_NS: u8 = 135;
pub const ICMPV6_NA: u8 = 136;

/// An ICMPv6 error never exceeds the IPv6 minimum MTU (RFC 4443 §2.4(c)).
pub const MIN_MTU: usize = 1280;

/// Parsed fixed header fields.
pub struct Ipv6Header {
    pub next_header: u8,
    pub hop_limit: u8,
    /// Bytes after the fixed header, as the header states them.
    pub payload_len: usize,
    pub src: [u8; 16],
    pub dst: [u8; 16],
}

/// Parse the fixed header of the IPv6 packet at `data`.
///
/// # Safety
/// `data` must point to at least `len` valid bytes.
pub unsafe fn parse_ipv6(data: *const u8, len: usize) -> Option<Ipv6Header> {
    if len < IPV6_HEADER_LEN || (*data >> 4) != 6 {
        return None;
    }
    let payload_len = ((*data.add(4) as usize) << 8) | (*data.add(5) as usize);
    if IPV6_HEADER_LEN + payload_len > len {
        return None;
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    core::ptr::copy_nonoverlapping(data.add(8), src.as_mut_ptr(), 16);
    core::ptr::copy_nonoverlapping(data.add(24), dst.as_mut_ptr(), 16);
    Some(Ipv6Header {
        next_header: *data.add(6),
        hop_limit: *data.add(7),
        payload_len,
        src,
        dst,
    })
}

/// Ones-complement sum of `len` bytes at `data`, folded into `sum`.
///
/// # Safety
/// `data` must point to at least `len` valid bytes.
pub unsafe fn sum_bytes(mut sum: u32, data: *const u8, len: usize) -> u32 {
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
    sum
}

/// The RFC 8200 §8.1 pseudo-header's sum.
pub fn pseudo_sum(src: &[u8; 16], dst: &[u8; 16], next_header: u8, len: usize) -> u32 {
    // SAFETY: both arrays are 16 bytes.
    let mut sum = unsafe { sum_bytes(0, src.as_ptr(), 16) };
    sum = unsafe { sum_bytes(sum, dst.as_ptr(), 16) };
    sum += (len >> 16) as u32 + (len & 0xFFFF) as u32;
    sum += u32::from(next_header);
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum
}

/// The checksum to write into a transport header whose checksum field is
/// zero.
///
/// # Safety
/// `data` must point to at least `len` valid bytes.
pub unsafe fn transport_checksum(
    src: &[u8; 16],
    dst: &[u8; 16],
    next_header: u8,
    data: *const u8,
    len: usize,
) -> u16 {
    let sum = sum_bytes(pseudo_sum(src, dst, next_header, len), data, len);
    !(sum as u16)
}

/// Whether a received transport payload's checksum verifies.
///
/// # Safety
/// `data` must point to at least `len` valid bytes.
pub unsafe fn verify_transport(
    src: &[u8; 16],
    dst: &[u8; 16],
    next_header: u8,
    data: *const u8,
    len: usize,
) -> bool {
    let sum = sum_bytes(pseudo_sum(src, dst, next_header, len), data, len);
    sum == 0xFFFF
}

/// Write the fixed header at `out`.
///
/// # Safety
/// `out` must point to at least 40 writable bytes.
pub unsafe fn build_ipv6_header(
    out: *mut u8,
    payload_len: u16,
    next_header: u8,
    hop_limit: u8,
    src: &[u8; 16],
    dst: &[u8; 16],
) {
    use core::ptr::write_volatile;
    write_volatile(out, 0x60u8);
    write_volatile(out.add(1), 0u8);
    write_volatile(out.add(2), 0u8);
    write_volatile(out.add(3), 0u8);
    write_volatile(out.add(4), (payload_len >> 8) as u8);
    write_volatile(out.add(5), payload_len as u8);
    write_volatile(out.add(6), next_header);
    write_volatile(out.add(7), hop_limit);
    let mut i = 0;
    while i < 16 {
        write_volatile(out.add(8 + i), src[i]);
        write_volatile(out.add(24 + i), dst[i]);
        i += 1;
    }
}

/// The solicited-node multicast address of `a` (RFC 4291 §2.7.1):
/// `ff02::1:ff` and the low 24 bits.
pub fn solicited_node(a: &[u8; 16]) -> [u8; 16] {
    let mut m = [0u8; 16];
    m[0] = 0xff;
    m[1] = 0x02;
    m[11] = 0x01;
    m[12] = 0xff;
    m[13] = a[13];
    m[14] = a[14];
    m[15] = a[15];
    m
}

/// The Ethernet multicast a v6 multicast address maps to (RFC 2464 §7).
pub fn multicast_mac(a: &[u8; 16]) -> [u8; 6] {
    [0x33, 0x33, a[12], a[13], a[14], a[15]]
}

pub fn is_multicast(a: &[u8; 16]) -> bool {
    a[0] == 0xff
}

/// `::1` (RFC 4291 §2.5.3): never on a wire, as source or destination.
pub fn is_loopback(a: &[u8; 16]) -> bool {
    let mut i = 0;
    while i < 15 {
        if a[i] != 0 {
            return false;
        }
        i += 1;
    }
    a[15] == 1
}

/// `::ffff:0:0/96`, an IPv4-mapped address (RFC 4291 §2.5.5.2): a socket
/// API's spelling of an IPv4 peer, never a wire address.
pub fn is_v4_mapped(a: &[u8; 16]) -> bool {
    let mut i = 0;
    while i < 10 {
        if a[i] != 0 {
            return false;
        }
        i += 1;
    }
    a[10] == 0xFF && a[11] == 0xFF
}

pub fn is_unspecified(a: &[u8; 16]) -> bool {
    let mut i = 0;
    while i < 16 {
        if a[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

fn hex_digit(c: u8) -> Option<u16> {
    match c {
        b'0'..=b'9' => Some(u16::from(c - b'0')),
        b'a'..=b'f' => Some(u16::from(c - b'a' + 10)),
        b'A'..=b'F' => Some(u16::from(c - b'A' + 10)),
        _ => None,
    }
}

/// Parse a textual IPv6 address (RFC 4291 §2.2 forms 1 and 2: eight
/// groups, or fewer with one `::`). The dotted-quad form 3 is refused: a
/// seam address is named the one way.
pub fn parse_text(t: &[u8]) -> Option<[u8; 16]> {
    if t.is_empty() || t.len() > 39 {
        return None;
    }
    let mut head = [0u16; 8];
    let mut tail = [0u16; 8];
    let (mut nh, mut nt) = (0usize, 0usize);
    let mut gap = false;
    let mut i = 0usize;
    if t.len() >= 2 && t[0] == b':' && t[1] == b':' {
        gap = true;
        i = 2;
    } else if t[0] == b':' {
        return None;
    }
    while i < t.len() {
        let mut v: u16 = 0;
        let mut digits = 0;
        while i < t.len() && t[i] != b':' {
            let d = hex_digit(t[i])?;
            digits += 1;
            if digits > 4 {
                return None;
            }
            v = (v << 4) | d;
            i += 1;
        }
        if digits == 0 {
            return None;
        }
        if gap {
            if nt >= 8 {
                return None;
            }
            tail[nt] = v;
            nt += 1;
        } else {
            if nh >= 8 {
                return None;
            }
            head[nh] = v;
            nh += 1;
        }
        if i < t.len() {
            // At a ':'.
            i += 1;
            if i < t.len() && t[i] == b':' {
                if gap {
                    return None;
                }
                gap = true;
                i += 1;
                if i == t.len() {
                    break;
                }
            } else if i == t.len() {
                return None;
            }
        }
    }
    let groups = nh + nt;
    if (gap && groups > 7) || (!gap && groups != 8) {
        return None;
    }
    let mut out = [0u8; 16];
    let mut k = 0;
    while k < nh {
        out[2 * k] = (head[k] >> 8) as u8;
        out[2 * k + 1] = head[k] as u8;
        k += 1;
    }
    let start = 8 - nt;
    k = 0;
    while k < nt {
        out[2 * (start + k)] = (tail[k] >> 8) as u8;
        out[2 * (start + k) + 1] = tail[k] as u8;
        k += 1;
    }
    Some(out)
}
