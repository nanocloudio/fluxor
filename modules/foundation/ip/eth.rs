//! Ethernet frame parsing and building.
//!
//! Minimal ethernet II frame handling for the IP stack module.
//! All operations use raw pointer arithmetic (no slice indexing)
//! to avoid panic infrastructure in PIC modules.

/// Ethernet header length (dest MAC + src MAC + ethertype)
pub const ETH_HEADER_LEN: usize = 14;

/// Ethertypes
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;

/// Parse ethernet header fields from raw frame.
///
/// # Safety
/// `data` must point to at least `len` valid bytes.
/// Returns (ethertype, payload_offset) or (0, 0) if invalid.
pub unsafe fn parse_eth_header(data: *const u8, len: usize) -> (u16, usize) {
    if len < ETH_HEADER_LEN {
        return (0, 0);
    }
    let ethertype = (*data.add(12) as u16) << 8 | (*data.add(13) as u16);
    (ethertype, ETH_HEADER_LEN)
}

/// Get destination MAC from ethernet frame.
///
/// # Safety
/// `data` must point to at least 6 valid bytes.
pub unsafe fn dst_mac(data: *const u8) -> [u8; 6] {
    let mut mac = [0u8; 6];
    let mut i = 0;
    while i < 6 {
        *mac.as_mut_ptr().add(i) = *data.add(i);
        i += 1;
    }
    mac
}

/// Get source MAC from ethernet frame.
///
/// # Safety
/// `data` must point to at least 12 valid bytes.
pub unsafe fn src_mac(data: *const u8) -> [u8; 6] {
    let mut mac = [0u8; 6];
    let mut i = 0;
    while i < 6 {
        *mac.as_mut_ptr().add(i) = *data.add(6 + i);
        i += 1;
    }
    mac
}

/// Build an ethernet header at `dst`.
///
/// # Safety
/// `dst` must point to at least 14 writable bytes.
pub unsafe fn build_eth_header(
    dst: *mut u8,
    dst_mac: &[u8; 6],
    src_mac: &[u8; 6],
    ethertype: u16,
) {
    let mut i = 0;
    while i < 6 {
        *dst.add(i) = *dst_mac.as_ptr().add(i);
        *dst.add(6 + i) = *src_mac.as_ptr().add(i);
        i += 1;
    }
    *dst.add(12) = (ethertype >> 8) as u8;
    *dst.add(13) = (ethertype & 0xFF) as u8;
}

/// Broadcast MAC address
pub const BROADCAST_MAC: [u8; 6] = [0xFF; 6];
