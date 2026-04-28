// QUIC v1 wire protocol — packet build / parse with header protection
// + AEAD packet protection (RFC 9001 §5.3, §5.4 + RFC 9000 §17).
//
// Implements Initial, Handshake, 1-RTT (short header), Retry, Version
// Negotiation, and 0-RTT packet types.
//
// All `pn` values passed through these helpers are full 64-bit packet
// numbers; the wire encodes a truncated 1-4 byte form picked to
// convey only the bits ambiguous with the peer's largest acknowledged.

/// Pick the minimum packet-number length that resolves the gap
/// between the next PN to send and the peer's largest acked
/// (RFC 9000 §17.1 + Appendix A.2). Always returns 4 — the longest
/// form — since loss recovery here is conservative and the extra
/// bytes don't matter at our throughput.
#[allow(dead_code)]
pub fn pick_pn_len(_next: u64, _largest_acked: u64) -> usize {
    4
}

/// Encode the truncated PN into the wire buffer at `out` (1-4 bytes,
/// big-endian). The first-byte's low 2 bits encode `pn_len - 1`.
pub fn encode_pn(out: &mut [u8], pn: u64, pn_len: usize) -> usize {
    let mut i = pn_len;
    let mut v = pn;
    while i > 0 {
        out[i - 1] = (v & 0xFF) as u8;
        v >>= 8;
        i -= 1;
    }
    pn_len
}

// --------------------------------------------------------------------
// Initial packet — RFC 9000 §17.2.2
//
//   first_byte    = 1 1 0 0 R R P P  (R reserved, P = pn_len - 1)
//                            (form  fixed                 )
//   version       = 0x00000001
//   dcid_len(u8)  + dcid
//   scid_len(u8)  + scid
//   token_len(varint) + token
//   length(varint) = encoded_packet_number_len + payload_len + 16
//   packet_number (1-4 bytes, HP-protected)
//   payload (AEAD-protected)
// --------------------------------------------------------------------

pub const PKT_INITIAL: u8 = 0;
pub const PKT_ZERO_RTT: u8 = 1;
pub const PKT_HANDSHAKE: u8 = 2;
pub const PKT_RETRY: u8 = 3;

/// RFC 9001 §5.8 — Retry Integrity Tag.
/// AES-128-GCM with fixed key + nonce, AAD = Retry Pseudo-Packet,
/// plaintext = empty. The tag is appended to the Retry packet bytes.
pub const QUIC_V1_RETRY_INTEGRITY_KEY: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
pub const QUIC_V1_RETRY_INTEGRITY_NONCE: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
    0x23, 0x98, 0x25, 0xbb,
];

/// Compute the 16-byte Retry Integrity Tag for the supplied Retry
/// Pseudo-Packet (RFC 9000 §17.2.5.1). Pseudo-packet = 1-byte ODCID
/// length + ODCID + the entire Retry packet up to (but not including)
/// the integrity tag.
pub unsafe fn compute_retry_integrity_tag(
    odcid: &[u8],
    retry_packet_no_tag: &[u8],
) -> [u8; 16] {
    // Build the pseudo-packet AAD into a stack buffer.
    let mut aad = [0u8; 256];
    let mut p = 0;
    aad[p] = odcid.len() as u8;
    p += 1;
    if odcid.len() > 0 && p + odcid.len() <= aad.len() {
        core::ptr::copy_nonoverlapping(odcid.as_ptr(), aad.as_mut_ptr().add(p), odcid.len());
        p += odcid.len();
    }
    if p + retry_packet_no_tag.len() <= aad.len() {
        core::ptr::copy_nonoverlapping(
            retry_packet_no_tag.as_ptr(),
            aad.as_mut_ptr().add(p),
            retry_packet_no_tag.len(),
        );
        p += retry_packet_no_tag.len();
    }
    let gcm = AesGcm::new_128(&QUIC_V1_RETRY_INTEGRITY_KEY);
    let mut empty: [u8; 0] = [];
    gcm.encrypt(&QUIC_V1_RETRY_INTEGRITY_NONCE, &aad[..p], &mut empty)
}

/// Build a Retry packet (RFC 9000 §17.2.5).
///
/// Format:
///   first_byte    = 1 1 1 1 _ _ _ _   (form=1, fixed=1, type=Retry=3, unused=4 bits)
///   version       = 0x00000001
///   dcid_len(u8)  + dcid (= peer's SCID)
///   scid_len(u8)  + scid (server's freshly-chosen SCID; becomes the
///                         client's new DCID for subsequent Initials)
///   retry_token   (caller-supplied)
///   integrity_tag (16 bytes, RFC 9001 §5.8 over Retry Pseudo-Packet)
///
/// `odcid` is the client's first-Initial DCID, used for the integrity
/// tag's AAD.
pub unsafe fn build_retry_packet(
    odcid: &[u8],
    dcid: &[u8],
    scid: &[u8],
    token: &[u8],
    out: &mut [u8],
) -> usize {
    let total = 1 + 4 + 1 + dcid.len() + 1 + scid.len() + token.len() + 16;
    if out.len() < total {
        return 0;
    }
    out[0] = 0xF0; // form=1, fixed=1, type=3 (Retry), unused bits=0
    out[1] = 0x00;
    out[2] = 0x00;
    out[3] = 0x00;
    out[4] = 0x01;
    let mut p = 5;
    out[p] = dcid.len() as u8;
    p += 1;
    if !dcid.is_empty() {
        core::ptr::copy_nonoverlapping(dcid.as_ptr(), out.as_mut_ptr().add(p), dcid.len());
        p += dcid.len();
    }
    out[p] = scid.len() as u8;
    p += 1;
    if !scid.is_empty() {
        core::ptr::copy_nonoverlapping(scid.as_ptr(), out.as_mut_ptr().add(p), scid.len());
        p += scid.len();
    }
    if !token.is_empty() {
        core::ptr::copy_nonoverlapping(token.as_ptr(), out.as_mut_ptr().add(p), token.len());
        p += token.len();
    }
    let no_tag_len = p;
    let tag = compute_retry_integrity_tag(odcid, &out[..no_tag_len]);
    core::ptr::copy_nonoverlapping(tag.as_ptr(), out.as_mut_ptr().add(p), 16);
    p + 16
}

/// Parsed Retry packet.
pub struct ParsedRetry {
    pub dcid_off: usize,
    pub dcid_len: usize,
    pub scid_off: usize,
    pub scid_len: usize,
    pub token_off: usize,
    pub token_len: usize,
}

/// Parse + validate a Retry packet against the original DCID
/// (`expected_odcid`). On success returns offsets/lengths into `pkt`
/// for the DCID, SCID, and Retry Token. Verifies the integrity tag
/// (RFC 9001 §5.8) using AES-128-GCM with the fixed key/nonce.
pub unsafe fn parse_retry_packet(
    pkt: &[u8],
    expected_odcid: &[u8],
) -> Option<ParsedRetry> {
    if pkt.len() < 1 + 4 + 1 + 1 + 16 {
        return None;
    }
    if pkt[0] & 0x80 == 0 || pkt[0] & 0x40 == 0 {
        return None;
    }
    let pkt_type = (pkt[0] >> 4) & 0x03;
    if pkt_type != PKT_RETRY {
        return None;
    }
    let _version = ((pkt[1] as u32) << 24)
        | ((pkt[2] as u32) << 16)
        | ((pkt[3] as u32) << 8)
        | (pkt[4] as u32);
    let dcid_len = pkt[5] as usize;
    if 6 + dcid_len + 1 > pkt.len() {
        return None;
    }
    let dcid_off = 6;
    let scid_len_off = dcid_off + dcid_len;
    let scid_len = pkt[scid_len_off] as usize;
    if scid_len_off + 1 + scid_len > pkt.len() {
        return None;
    }
    let scid_off = scid_len_off + 1;
    let after_scid = scid_off + scid_len;
    if after_scid + 16 > pkt.len() {
        return None;
    }
    let token_off = after_scid;
    let token_len = pkt.len() - after_scid - 16;
    let no_tag_len = pkt.len() - 16;

    // Verify integrity tag.
    let mut expected = [0u8; 16];
    core::ptr::copy_nonoverlapping(
        pkt.as_ptr().add(no_tag_len),
        expected.as_mut_ptr(),
        16,
    );
    let actual = compute_retry_integrity_tag(expected_odcid, &pkt[..no_tag_len]);
    let mut diff = 0u8;
    let mut i = 0;
    while i < 16 {
        diff |= actual[i] ^ expected[i];
        i += 1;
    }
    if diff != 0 {
        return None;
    }
    Some(ParsedRetry {
        dcid_off,
        dcid_len,
        scid_off,
        scid_len,
        token_off,
        token_len,
    })
}

/// Build a Version Negotiation packet (RFC 9000 §17.2.1). Sent when
/// the server receives a long-header packet with an unsupported
/// version. Format:
///
///   first_byte    = 1 ? ? ? ? ? ? ? (any value with high bit 1)
///   version       = 0x00000000
///   dcid_len(u8)  + dcid
///   scid_len(u8)  + scid
///   supported_versions[1..]  (each u32 BE)
///
/// We list QUIC v1 (`0x00000001`) plus one reserved-greasing version
/// (RFC 9000 §6.3) so an implementation that mirrors back the
/// negotiated set sees that we'd accept v1.
pub unsafe fn build_version_negotiation(
    dcid: &[u8],
    scid: &[u8],
    out: &mut [u8],
) -> usize {
    let total = 1 + 4 + 1 + dcid.len() + 1 + scid.len() + 4 + 4;
    if out.len() < total {
        return 0;
    }
    // First byte: any value with high bit set (RFC 9000 §17.2.1
    // states "Servers MAY set the unused bits to any value"; we
    // pick 0x80).
    out[0] = 0x80;
    // Version = 0x00000000 marks a Version Negotiation packet.
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    out[4] = 0;
    let mut p = 5;
    out[p] = dcid.len() as u8;
    p += 1;
    core::ptr::copy_nonoverlapping(dcid.as_ptr(), out.as_mut_ptr().add(p), dcid.len());
    p += dcid.len();
    out[p] = scid.len() as u8;
    p += 1;
    core::ptr::copy_nonoverlapping(scid.as_ptr(), out.as_mut_ptr().add(p), scid.len());
    p += scid.len();
    // Supported versions list: QUIC_V1 + one reserved-greasing.
    out[p] = 0;
    out[p + 1] = 0;
    out[p + 2] = 0;
    out[p + 3] = 1;
    p += 4;
    out[p] = 0xa1;
    out[p + 1] = 0xa1;
    out[p + 2] = 0xa1;
    out[p + 3] = 0xa1;
    p += 4;
    p
}

/// Build + protect an Initial packet. `crypto_frame_payload` is a
/// pre-built sequence of frames (CRYPTO + PADDING etc.). Returns
/// total bytes written into `out`, or 0 on overflow.
pub unsafe fn build_initial_packet(
    keys: &QuicKeys,
    hp: &Aes128Hp,
    pn: u64,
    pn_len: usize,
    dcid: &[u8],
    scid: &[u8],
    token: &[u8],
    payload: &[u8],
    out: &mut [u8],
) -> usize {
    build_long_packet(keys, hp, pn, pn_len, PKT_INITIAL, dcid, scid, Some(token), payload, out)
}

pub unsafe fn build_handshake_packet(
    keys: &QuicKeys,
    hp: &Aes128Hp,
    pn: u64,
    pn_len: usize,
    dcid: &[u8],
    scid: &[u8],
    payload: &[u8],
    out: &mut [u8],
) -> usize {
    build_long_packet(keys, hp, pn, pn_len, PKT_HANDSHAKE, dcid, scid, None, payload, out)
}

unsafe fn build_long_packet(
    keys: &QuicKeys,
    hp: &Aes128Hp,
    pn: u64,
    pn_len: usize,
    pkt_type: u8,
    dcid: &[u8],
    scid: &[u8],
    token: Option<&[u8]>,
    payload: &[u8],
    out: &mut [u8],
) -> usize {
    let aead_len = pn_len + payload.len() + 16;
    let token_len = token.map(|t| t.len()).unwrap_or(0);

    // Compute total header length so we know where PN bytes go.
    let token_len_size = token.map(|t| varint_size(t.len() as u64)).unwrap_or(0);
    let length_size = varint_size(aead_len as u64);
    let hdr_len_pre_pn =
        1 + 4 + 1 + dcid.len() + 1 + scid.len() + token_len_size + token_len + length_size;
    let total_len = hdr_len_pre_pn + aead_len;
    if out.len() < total_len {
        return 0;
    }

    // First byte: 1100_RRPP = 0xC0 | (pn_len-1) | (pkt_type << 4).
    out[0] = 0xC0 | ((pkt_type & 0x03) << 4) | ((pn_len as u8 - 1) & 0x03);
    // Version = 1.
    out[1] = 0x00;
    out[2] = 0x00;
    out[3] = 0x00;
    out[4] = 0x01;
    // DCID.
    out[5] = dcid.len() as u8;
    let mut p = 6;
    core::ptr::copy_nonoverlapping(dcid.as_ptr(), out.as_mut_ptr().add(p), dcid.len());
    p += dcid.len();
    // SCID.
    out[p] = scid.len() as u8;
    p += 1;
    core::ptr::copy_nonoverlapping(scid.as_ptr(), out.as_mut_ptr().add(p), scid.len());
    p += scid.len();
    // Token (Initial only).
    if let Some(tok) = token {
        let n = varint_encode(out.as_mut_ptr().add(p), out.len() - p, tok.len() as u64);
        if n == 0 {
            return 0;
        }
        p += n;
        if !tok.is_empty() {
            core::ptr::copy_nonoverlapping(tok.as_ptr(), out.as_mut_ptr().add(p), tok.len());
            p += tok.len();
        }
    }
    // Length varint.
    let n = varint_encode(out.as_mut_ptr().add(p), out.len() - p, aead_len as u64);
    if n == 0 {
        return 0;
    }
    p += n;
    let pn_offset = p;
    // PN bytes (cleartext for now — HP applied last).
    encode_pn(&mut out[pn_offset..pn_offset + pn_len], pn, pn_len);
    p += pn_len;
    // Payload (cleartext — AEAD applied next).
    if !payload.is_empty() {
        core::ptr::copy_nonoverlapping(
            payload.as_ptr(),
            out.as_mut_ptr().add(p),
            payload.len(),
        );
    }
    p += payload.len();
    // Tag (filled by AEAD).
    p += 16;
    let _ = p;

    // AEAD: AAD = the cleartext header up to and including PN bytes;
    // payload at out[pn_offset+pn_len..pn_offset+pn_len+payload_len];
    // tag at out[pn_offset+pn_len+payload_len..pn_offset+pn_len+payload_len+16].
    let aad_end = pn_offset + pn_len;
    // Header (with peer-supplied CID lengths up to 20 bytes each + an
    // optional Retry token of up to MAX_RETRY_TOKEN_LEN=64) can be up
    // to ~115 bytes; size AAD accordingly.
    let mut aad = [0u8; 256];
    if aad_end > aad.len() {
        return 0;
    }
    core::ptr::copy_nonoverlapping(out.as_ptr(), aad.as_mut_ptr(), aad_end);

    let body_off = pn_offset + pn_len;
    let body_len = payload.len();
    let mut tag = [0u8; 16];
    quic_encrypt_payload(
        keys,
        pn,
        &aad[..aad_end],
        &mut out[body_off..body_off + body_len],
        &mut tag,
    );
    core::ptr::copy_nonoverlapping(tag.as_ptr(), out.as_mut_ptr().add(body_off + body_len), 16);

    // Apply header protection.
    apply_header_protection(hp, &mut out[..total_len], pn_offset, pn_len, true);

    total_len
}

// --------------------------------------------------------------------
// Inbound parsing for long-header packets (Initial / Handshake).
//
// On success returns:
//   - packet_type (Initial / Handshake)
//   - dcid + scid (slices into pkt[..])
//   - token (Initial only; empty otherwise)
//   - decrypted payload at pkt[pn_offset+pn_len..pn_offset+pn_len+pt_len]
//   - the fully-reconstructed packet number
//   - total_consumed bytes (so caller can iterate coalesced packets)
// --------------------------------------------------------------------

pub struct ParsedLongPacket {
    pub pkt_type: u8,
    pub dcid_off: usize,
    pub dcid_len: usize,
    pub scid_off: usize,
    pub scid_len: usize,
    pub token_off: usize,
    pub token_len: usize,
    pub payload_off: usize,
    pub payload_len: usize,
    pub pn: u64,
    pub total_consumed: usize,
}

pub unsafe fn parse_long_packet(
    keys: &QuicKeys,
    hp: &Aes128Hp,
    largest_recv_pn: u64,
    pkt: &mut [u8],
) -> Option<ParsedLongPacket> {
    if pkt.len() < 7 {
        return None;
    }
    if pkt[0] & 0x80 == 0 {
        return None; // Not a long header.
    }
    if pkt[0] & 0x40 == 0 {
        return None; // Fixed bit must be 1.
    }
    let pkt_type_pre_hp = (pkt[0] >> 4) & 0x03;

    // Cleartext fields up to the length varint.
    let _version = ((pkt[1] as u32) << 24)
        | ((pkt[2] as u32) << 16)
        | ((pkt[3] as u32) << 8)
        | (pkt[4] as u32);
    let dcid_len = pkt[5] as usize;
    if pkt.len() < 6 + dcid_len + 1 {
        return None;
    }
    let dcid_off = 6;
    let scid_len_off = dcid_off + dcid_len;
    let scid_len = pkt[scid_len_off] as usize;
    if pkt.len() < scid_len_off + 1 + scid_len {
        return None;
    }
    let scid_off = scid_len_off + 1;
    let mut p = scid_off + scid_len;

    let (token_off, token_len) = if pkt_type_pre_hp == PKT_INITIAL {
        let after = &pkt[p..];
        let (tlen, n) = varint_decode(after.as_ptr(), after.len())?;
        let toff = p + n;
        let tlen = tlen as usize;
        if pkt.len() < toff + tlen {
            return None;
        }
        p = toff + tlen;
        (toff, tlen)
    } else {
        (0, 0)
    };

    let after = &pkt[p..];
    let (length_v, n) = varint_decode(after.as_ptr(), after.len())?;
    let length = length_v as usize;
    p += n;
    let pn_offset = p;
    if pkt.len() < pn_offset + length {
        return None;
    }
    let total_consumed = pn_offset + length;

    // Remove header protection.
    let pn_len = remove_header_protection(hp, pkt, pn_offset, true);
    if pn_len == 0 || pn_offset + pn_len > pkt.len() {
        return None;
    }
    // RFC 9000 §17.2: Length covers the truncated packet number plus the
    // protected payload plus the 16-byte AEAD tag. Reject anything too
    // short before subtracting — `length - pn_len - 16` would otherwise
    // underflow on malformed input and feed a bogus body length to the
    // bounds check below.
    if length < pn_len + 16 {
        return None;
    }
    // Recover the truncated PN.
    let mut trunc = 0u64;
    let mut i = 0;
    while i < pn_len {
        trunc = (trunc << 8) | pkt[pn_offset + i] as u64;
        i += 1;
    }
    let pn = decode_packet_number(largest_recv_pn, trunc, pn_len);

    let body_off = pn_offset + pn_len;
    let body_len = length - pn_len - 16;
    if body_off + body_len + 16 > pkt.len() {
        return None;
    }
    let aad_end = pn_offset + pn_len;
    let mut aad = [0u8; 256];
    if aad_end > aad.len() {
        return None;
    }
    core::ptr::copy_nonoverlapping(pkt.as_ptr(), aad.as_mut_ptr(), aad_end);

    let mut tag = [0u8; 16];
    core::ptr::copy_nonoverlapping(
        pkt.as_ptr().add(body_off + body_len),
        tag.as_mut_ptr(),
        16,
    );

    if !quic_decrypt_payload(
        keys,
        pn,
        &aad[..aad_end],
        &mut pkt[body_off..body_off + body_len],
        &tag,
    ) {
        return None;
    }

    Some(ParsedLongPacket {
        pkt_type: pkt_type_pre_hp,
        dcid_off,
        dcid_len,
        scid_off,
        scid_len,
        token_off,
        token_len,
        payload_off: body_off,
        payload_len: body_len,
        pn,
        total_consumed,
    })
}

// --------------------------------------------------------------------
// 1-RTT (short header) packets.
//
//   first_byte = 0 1 S R R K P P
//                  (form fixed)(spin)  (key_phase)(pn_len)
//   dcid (no length field — implicit by negotiation)
//   pn (1-4 bytes, HP-protected)
//   payload (AEAD-protected)
// --------------------------------------------------------------------

pub unsafe fn build_one_rtt_packet(
    keys: &QuicKeys,
    hp: &Aes128Hp,
    pn: u64,
    pn_len: usize,
    key_phase: u8,
    dcid: &[u8],
    payload: &[u8],
    out: &mut [u8],
) -> usize {
    let total = 1 + dcid.len() + pn_len + payload.len() + 16;
    if out.len() < total {
        return 0;
    }
    // First byte: 0_1_0_0_K_R_PP — form=0, fixed=1, spin=0, reserved=0,
    // key_phase=K, pn_len. RFC 9001 §6.1: key_phase toggles on each
    // sender-initiated key update so the peer can pick the right keys.
    let kp_bit = (key_phase & 0x01) << 2;
    out[0] = 0x40 | kp_bit | ((pn_len as u8 - 1) & 0x03);
    let mut p = 1;
    core::ptr::copy_nonoverlapping(dcid.as_ptr(), out.as_mut_ptr().add(p), dcid.len());
    p += dcid.len();
    let pn_offset = p;
    encode_pn(&mut out[pn_offset..pn_offset + pn_len], pn, pn_len);
    p += pn_len;
    if !payload.is_empty() {
        core::ptr::copy_nonoverlapping(
            payload.as_ptr(),
            out.as_mut_ptr().add(p),
            payload.len(),
        );
    }
    p += payload.len();
    p += 16;
    let _ = p;

    let aad_end = pn_offset + pn_len;
    let mut aad = [0u8; 32];
    if aad_end > aad.len() {
        return 0;
    }
    core::ptr::copy_nonoverlapping(out.as_ptr(), aad.as_mut_ptr(), aad_end);

    let body_off = pn_offset + pn_len;
    let body_len = payload.len();
    let mut tag = [0u8; 16];
    quic_encrypt_payload(
        keys,
        pn,
        &aad[..aad_end],
        &mut out[body_off..body_off + body_len],
        &mut tag,
    );
    core::ptr::copy_nonoverlapping(tag.as_ptr(), out.as_mut_ptr().add(body_off + body_len), 16);

    apply_header_protection(hp, &mut out[..total], pn_offset, pn_len, false);
    total
}

pub unsafe fn parse_one_rtt_packet(
    keys: &QuicKeys,
    hp: &Aes128Hp,
    expected_dcid_len: usize,
    largest_recv_pn: u64,
    pkt: &mut [u8],
) -> Option<(usize, usize, u64)> {
    if pkt.len() < 1 + expected_dcid_len + 1 + 16 {
        return None;
    }
    if pkt[0] & 0x80 != 0 {
        return None; // Long header.
    }
    if pkt[0] & 0x40 == 0 {
        return None; // Fixed bit.
    }
    let pn_offset = 1 + expected_dcid_len;
    let pn_len = remove_header_protection(hp, pkt, pn_offset, false);
    if pn_len == 0 || pn_offset + pn_len + 16 > pkt.len() {
        return None;
    }
    let mut trunc = 0u64;
    let mut i = 0;
    while i < pn_len {
        trunc = (trunc << 8) | pkt[pn_offset + i] as u64;
        i += 1;
    }
    let pn = decode_packet_number(largest_recv_pn, trunc, pn_len);

    let body_off = pn_offset + pn_len;
    let body_len = pkt.len() - body_off - 16;
    let aad_end = pn_offset + pn_len;
    let mut aad = [0u8; 32];
    if aad_end > aad.len() {
        return None;
    }
    core::ptr::copy_nonoverlapping(pkt.as_ptr(), aad.as_mut_ptr(), aad_end);
    let mut tag = [0u8; 16];
    core::ptr::copy_nonoverlapping(
        pkt.as_ptr().add(body_off + body_len),
        tag.as_mut_ptr(),
        16,
    );
    if !quic_decrypt_payload(
        keys,
        pn,
        &aad[..aad_end],
        &mut pkt[body_off..body_off + body_len],
        &tag,
    ) {
        return None;
    }
    Some((body_off, body_len, pn))
}
