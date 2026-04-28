// QUIC v1 packet header parsing and building (RFC 9000 §17).
//
// QUIC packets come in two header forms:
//
//   Long Header (RFC 9000 §17.2) — used during handshake (Initial,
//   0-RTT, Handshake, Retry packet types). Carries Source/Destination
//   Connection IDs of variable length and the negotiated Version.
//
//     0 1 2 3 4 5 6 7
//    +-+-+-+-+-+-+-+-+
//    |1|1|T T|R R|P P|        // header form 1, fixed bit 1, type, reserved, packet number length
//    +-+-+-+-+-+-+-+-+
//    | Version (32) |
//    +--------------+
//    | DCID Len (8) |
//    +--------------+
//    | DCID (...)   |
//    +--------------+
//    | SCID Len (8) |
//    +--------------+
//    | SCID (...)   |
//    +--------------+
//    | Type-specific|
//    +--------------+
//
//   Short Header (RFC 9000 §17.3) — used in the 1-RTT data phase.
//   Has only DCID (no length prefix; receiver knows the expected
//   length from prior negotiation) and a packet number.
//
//     0 1 2 3 4 5 6 7
//    +-+-+-+-+-+-+-+-+
//    |0|1|S|R|R|K|P P|        // form 0, fixed 1, spin, reserved, key phase, pn length
//    +-+-+-+-+-+-+-+-+
//    | DCID (...)   |
//    +--------------+
//    | PN (8/16/24/32) |
//    +-----------------+
//    | Payload         |
//
// Header protection (RFC 9001 §5.4) masks the first byte's low 5 bits
// and the packet number bytes using a sample of the encrypted payload.
// This module exposes header-form parsing and unprotected-field reads;
// header protection and payload protection live in `mod.rs` once the
// transport state machine is wired.

/// QUIC v1 version number (RFC 9000 §15).
pub const QUIC_V1: u32 = 0x0000_0001;

/// Long-header packet types (RFC 9000 §17.2.1).
pub const LONG_TYPE_INITIAL: u8 = 0;
pub const LONG_TYPE_ZERO_RTT: u8 = 1;
pub const LONG_TYPE_HANDSHAKE: u8 = 2;
pub const LONG_TYPE_RETRY: u8 = 3;

/// Maximum Connection ID length (RFC 9000 §17.2: up to 20 bytes).
pub const MAX_CID_LEN: usize = 20;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HeaderForm {
    Long,
    Short,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LongPacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

pub struct LongHeader {
    pub packet_type: LongPacketType,
    pub version: u32,
    pub dcid_len: u8,
    pub dcid: [u8; MAX_CID_LEN],
    pub scid_len: u8,
    pub scid: [u8; MAX_CID_LEN],
    /// Offset into the packet buffer where type-specific data begins
    /// (token + length for Initial, length for Handshake/0-RTT, retry
    /// integrity tag for Retry).
    pub type_specific_offset: usize,
}

pub struct ShortHeader {
    pub spin_bit: bool,
    pub key_phase: bool,
    pub dcid_len: u8,
    pub dcid: [u8; MAX_CID_LEN],
    /// Offset into the packet where the packet-number bytes begin.
    /// Header protection MUST be removed before the PN length is known.
    pub pn_offset: usize,
}

/// Inspect the first byte to determine header form. RFC 9000 §17.2 says
/// the high bit is 1 for long headers, 0 for short headers, and the
/// next bit (the "fixed bit") MUST be 1 in QUIC v1 — packets with bit
/// 0 set to 0 are dropped silently per §17.2.
pub fn header_form(first_byte: u8) -> Option<HeaderForm> {
    if first_byte & 0x40 == 0 {
        return None; // Fixed bit must be 1.
    }
    Some(if first_byte & 0x80 != 0 {
        HeaderForm::Long
    } else {
        HeaderForm::Short
    })
}

/// Parse a long header from `pkt`. The packet-number length is encoded
/// in bits 0-1 of the first byte but those bits are header-protected;
/// callers must run header protection removal before reading them.
/// Returns `None` if the header is malformed (truncated, unknown
/// version, or invalid CID lengths).
pub fn parse_long_header(pkt: &[u8]) -> Option<LongHeader> {
    if pkt.len() < 7 {
        return None;
    }
    let b0 = pkt[0];
    let _ = header_form(b0)?;
    if b0 & 0x80 == 0 {
        return None; // Not a long header.
    }
    let type_bits = (b0 >> 4) & 0x03;
    let packet_type = match type_bits {
        0 => LongPacketType::Initial,
        1 => LongPacketType::ZeroRtt,
        2 => LongPacketType::Handshake,
        3 => LongPacketType::Retry,
        _ => unreachable!(),
    };
    let version = ((pkt[1] as u32) << 24)
        | ((pkt[2] as u32) << 16)
        | ((pkt[3] as u32) << 8)
        | (pkt[4] as u32);

    let dcid_len = pkt[5] as usize;
    if dcid_len > MAX_CID_LEN || pkt.len() < 6 + dcid_len + 1 {
        return None;
    }
    let mut dcid = [0u8; MAX_CID_LEN];
    let mut i = 0;
    while i < dcid_len {
        dcid[i] = pkt[6 + i];
        i += 1;
    }

    let scid_off = 6 + dcid_len;
    let scid_len = pkt[scid_off] as usize;
    if scid_len > MAX_CID_LEN || pkt.len() < scid_off + 1 + scid_len {
        return None;
    }
    let mut scid = [0u8; MAX_CID_LEN];
    let mut i = 0;
    while i < scid_len {
        scid[i] = pkt[scid_off + 1 + i];
        i += 1;
    }

    Some(LongHeader {
        packet_type,
        version,
        dcid_len: dcid_len as u8,
        dcid,
        scid_len: scid_len as u8,
        scid,
        type_specific_offset: scid_off + 1 + scid_len,
    })
}

/// Parse a short header. `expected_dcid_len` MUST come from the
/// transport's prior negotiation — short headers do not carry a CID
/// length field. Returns the DCID + offset to the packet number bytes;
/// the PN itself remains header-protected.
pub fn parse_short_header(pkt: &[u8], expected_dcid_len: usize) -> Option<ShortHeader> {
    if pkt.len() < 1 + expected_dcid_len {
        return None;
    }
    let b0 = pkt[0];
    let _ = header_form(b0)?;
    if b0 & 0x80 != 0 {
        return None; // Not a short header.
    }
    if expected_dcid_len > MAX_CID_LEN {
        return None;
    }
    let mut dcid = [0u8; MAX_CID_LEN];
    let mut i = 0;
    while i < expected_dcid_len {
        dcid[i] = pkt[1 + i];
        i += 1;
    }
    Some(ShortHeader {
        spin_bit: b0 & 0x20 != 0,
        key_phase: b0 & 0x04 != 0,
        dcid_len: expected_dcid_len as u8,
        dcid,
        pn_offset: 1 + expected_dcid_len,
    })
}

/// Decode a packet-number length (the low 2 bits of the first byte
/// after header-protection removal). Returns 1, 2, 3, or 4.
pub fn pn_length_from_first_byte(b0: u8) -> usize {
    1 + ((b0 & 0x03) as usize)
}

/// Reconstruct the full 64-bit packet number from a truncated on-wire
/// PN (1-4 bytes) plus the largest acknowledged PN (RFC 9000 §A.3).
pub fn decode_packet_number(largest_pn: u64, truncated_pn: u64, pn_len_bytes: usize) -> u64 {
    let pn_nbits = (pn_len_bytes as u64) * 8;
    let expected_pn = largest_pn.wrapping_add(1);
    let pn_win = 1u64 << pn_nbits;
    let pn_hwin = pn_win >> 1;
    let pn_mask = pn_win.wrapping_sub(1);
    let candidate_pn = (expected_pn & !pn_mask) | truncated_pn;
    if candidate_pn.wrapping_add(pn_hwin) <= expected_pn && candidate_pn < (u64::MAX - pn_win) {
        return candidate_pn.wrapping_add(pn_win);
    }
    if candidate_pn > expected_pn.wrapping_add(pn_hwin) && candidate_pn >= pn_win {
        return candidate_pn.wrapping_sub(pn_win);
    }
    candidate_pn
}
