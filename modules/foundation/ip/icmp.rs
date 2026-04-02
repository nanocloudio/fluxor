//! ICMP protocol — echo request/reply (ping).

use super::ipv4;

/// ICMP header length
pub const ICMP_HEADER_LEN: usize = 8;

/// ICMP types
pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_ECHO_REQUEST: u8 = 8;

/// Handle an incoming ICMP packet. If it's an echo request, build an echo reply
/// in `reply_buf` and return the total IP payload length. Otherwise return 0.
///
/// # Safety
/// `data` must point to at least `len` bytes of ICMP payload (after IP header).
/// `reply_buf` must point to at least `len` writable bytes.
pub unsafe fn handle_icmp(
    data: *const u8,
    len: usize,
    reply_buf: *mut u8,
) -> usize {
    if len < ICMP_HEADER_LEN {
        return 0;
    }

    let icmp_type = *data;

    if icmp_type != ICMP_ECHO_REQUEST {
        return 0;
    }

    // Build echo reply: change type to 0, recalculate checksum
    // Copy the entire ICMP packet
    let mut i = 0;
    while i < len {
        *reply_buf.add(i) = *data.add(i);
        i += 1;
    }

    // Set type to Echo Reply
    *reply_buf = ICMP_ECHO_REPLY;
    // Clear checksum
    *reply_buf.add(2) = 0;
    *reply_buf.add(3) = 0;

    // Recompute ICMP checksum
    let cksum = ipv4::checksum(reply_buf, len);
    *reply_buf.add(2) = (cksum >> 8) as u8;
    *reply_buf.add(3) = (cksum & 0xFF) as u8;

    len
}
