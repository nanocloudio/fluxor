// QUIC v1 packet protection keys (RFC 9001).
//
// Two derivation paths:
//
// 1. Initial keys (RFC 9001 §5.2) — derived from a known salt + the
//    client's chosen Destination Connection ID. Both sides derive
//    the same Initial keys without TLS.
//
// 2. Handshake / 1-RTT keys — derived from TLS 1.3 secrets that the
//    `HandshakeDriver` exposes via `read_secret(EncLevel, send)`.
//    QUIC re-runs HKDF-Expand-Label on those secrets with the QUIC
//    labels "quic key" / "quic iv" / "quic hp".
//
// Each direction at each EncLevel needs a triple (key, iv, hp_key):
// `key` + `iv` form the AEAD packet protection; `hp_key` masks the
// header (RFC 9001 §5.4) before/after AEAD.

/// QUIC v1 initial salt (RFC 9001 §5.2).
pub const QUIC_V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];

pub const QUIC_KEY_LEN: usize = 16; // AES-128-GCM
pub const QUIC_IV_LEN: usize = 12;
pub const QUIC_HP_KEY_LEN: usize = 16;

#[derive(Clone, Copy)]
pub struct QuicKeys {
    pub key: [u8; QUIC_KEY_LEN],
    pub iv: [u8; QUIC_IV_LEN],
    pub hp: [u8; QUIC_HP_KEY_LEN],
}

impl QuicKeys {
    pub const fn empty() -> Self {
        Self {
            key: [0; QUIC_KEY_LEN],
            iv: [0; QUIC_IV_LEN],
            hp: [0; QUIC_HP_KEY_LEN],
        }
    }
}

/// Derive Initial-level keys for both directions from a Destination
/// Connection ID (typically the one the client put in the first
/// Initial packet's DCID field). Returns (client_initial, server_initial).
pub unsafe fn derive_initial_keys(dcid: &[u8]) -> (QuicKeys, QuicKeys) {
    let mut initial_secret = [0u8; 32];
    hkdf_extract(HashAlg::Sha256, &QUIC_V1_INITIAL_SALT, dcid, &mut initial_secret);

    let mut client_secret = [0u8; 32];
    hkdf_expand_label(
        HashAlg::Sha256,
        &initial_secret,
        b"client in",
        &[],
        &mut client_secret,
    );
    let mut server_secret = [0u8; 32];
    hkdf_expand_label(
        HashAlg::Sha256,
        &initial_secret,
        b"server in",
        &[],
        &mut server_secret,
    );

    let client = secret_to_keys(&client_secret);
    let server = secret_to_keys(&server_secret);
    (client, server)
}

/// Derive QUIC packet protection keys (key/iv/hp) from a TLS 1.3
/// traffic secret. Used for Initial / Handshake / 1-RTT levels —
/// same derivation, the caller picks the source secret per level.
pub unsafe fn secret_to_keys(secret: &[u8]) -> QuicKeys {
    let mut keys = QuicKeys::empty();
    hkdf_expand_label(HashAlg::Sha256, secret, b"quic key", &[], &mut keys.key);
    hkdf_expand_label(HashAlg::Sha256, secret, b"quic iv", &[], &mut keys.iv);
    hkdf_expand_label(HashAlg::Sha256, secret, b"quic hp", &[], &mut keys.hp);
    keys
}

/// RFC 9001 §6.1 — derive the next-phase 1-RTT traffic secret from
/// the current secret via `HKDF-Expand-Label(secret, "quic ku", "",
/// hash_len)`. The HP key is NOT updated (RFC 9001 §6.1: header
/// protection key remains unchanged across key updates).
pub unsafe fn next_traffic_secret(current: &[u8], out: &mut [u8]) {
    let hl = current.len().min(out.len());
    let mut tmp = [0u8; 48];
    hkdf_expand_label(HashAlg::Sha256, current, b"quic ku", &[], &mut tmp[..hl]);
    out[..hl].copy_from_slice(&tmp[..hl]);
}

/// Derive next-phase keys: key + iv update; hp_key inherited from
/// `prev_hp` per RFC 9001 §6.1.
pub unsafe fn next_keys(next_secret: &[u8], prev_hp: [u8; QUIC_HP_KEY_LEN]) -> QuicKeys {
    let mut keys = QuicKeys::empty();
    hkdf_expand_label(HashAlg::Sha256, next_secret, b"quic key", &[], &mut keys.key);
    hkdf_expand_label(HashAlg::Sha256, next_secret, b"quic iv", &[], &mut keys.iv);
    keys.hp = prev_hp;
    keys
}

// ----------------------------------------------------------------------
// Header protection (RFC 9001 §5.4)
//
// Sample: 16 bytes of ciphertext starting `pn_offset + 4` bytes into
// the protected packet (i.e. 4 bytes past where the packet number
// starts, regardless of actual PN length).
//
// mask = AES-ECB-Encrypt(hp_key, sample) [.. 5]
//
// First-byte mask: long header XOR mask[0] & 0x0f, short header XOR
// mask[0] & 0x1f. PN bytes XOR mask[1..1+pn_len].
// ----------------------------------------------------------------------

/// Apply header protection to a packet in `pkt`. `pn_offset` is the
/// offset into `pkt` where the PN bytes begin; `pn_len` is the
/// number of PN bytes (1-4). The caller has already encoded the PN.
/// `is_long` selects the first-byte mask (4 or 5 bits).
pub unsafe fn apply_header_protection(
    hp: &Aes128Hp,
    pkt: &mut [u8],
    pn_offset: usize,
    pn_len: usize,
    is_long: bool,
) {
    if pn_offset + 4 + 16 > pkt.len() {
        return;
    }
    let mut sample = [0u8; 16];
    core::ptr::copy_nonoverlapping(
        pkt.as_ptr().add(pn_offset + 4),
        sample.as_mut_ptr(),
        16,
    );
    hp.encrypt_block(&mut sample);

    let first_mask = if is_long { sample[0] & 0x0f } else { sample[0] & 0x1f };
    pkt[0] ^= first_mask;
    let mut i = 0;
    while i < pn_len {
        pkt[pn_offset + i] ^= sample[1 + i];
        i += 1;
    }
}

/// Remove header protection from a received packet — reverses the
/// XORs applied by `apply_header_protection`. Returns the recovered
/// pn_len (1-4) so the caller can read the cleartext PN bytes.
pub unsafe fn remove_header_protection(
    hp: &Aes128Hp,
    pkt: &mut [u8],
    pn_offset: usize,
    is_long: bool,
) -> usize {
    if pn_offset + 4 + 16 > pkt.len() {
        return 0;
    }
    let mut sample = [0u8; 16];
    core::ptr::copy_nonoverlapping(
        pkt.as_ptr().add(pn_offset + 4),
        sample.as_mut_ptr(),
        16,
    );
    hp.encrypt_block(&mut sample);

    let first_mask = if is_long { sample[0] & 0x0f } else { sample[0] & 0x1f };
    pkt[0] ^= first_mask;
    let pn_len = 1 + ((pkt[0] & 0x03) as usize);
    let mut i = 0;
    while i < pn_len {
        pkt[pn_offset + i] ^= sample[1 + i];
        i += 1;
    }
    pn_len
}

// ----------------------------------------------------------------------
// Packet protection (RFC 9001 §5.3)
//
// AAD = the cleartext header (after HP removal) covering the packet
// up to (but not including) the encrypted payload.
//
// Nonce = `iv` XOR (8 high bytes of zero || 64-bit packet number, BE).
//
// AES-128-GCM seals the payload + 16-byte tag.
// ----------------------------------------------------------------------

/// Compute the AEAD nonce for a packet by XORing the static IV with
/// the packet number padded to 12 bytes.
pub fn quic_nonce(iv: &[u8; 12], pn: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let pn_bytes = pn.to_be_bytes();
    let mut i = 0;
    while i < 8 {
        nonce[12 - 8 + i] ^= pn_bytes[i];
        i += 1;
    }
    nonce
}

/// Encrypt `payload` in place with AES-128-GCM under `keys`. Writes
/// the 16-byte tag immediately after the ciphertext. Caller must
/// have already populated the cleartext header at `aad`. Returns
/// the ciphertext length (= payload_len + 16). `pn` is the packet's
/// truncated 64-bit number (used for nonce derivation).
pub fn quic_encrypt_payload(
    keys: &QuicKeys,
    pn: u64,
    aad: &[u8],
    payload: &mut [u8],
    tag_out: &mut [u8; 16],
) {
    let nonce = quic_nonce(&keys.iv, pn);
    let gcm = AesGcm::new_128(&keys.key);
    let tag = gcm.encrypt(&nonce, aad, payload);
    *tag_out = tag;
}

/// Decrypt `payload` in place with AES-128-GCM and verify the tag.
/// Returns true on success.
pub fn quic_decrypt_payload(
    keys: &QuicKeys,
    pn: u64,
    aad: &[u8],
    payload: &mut [u8],
    tag: &[u8; 16],
) -> bool {
    let nonce = quic_nonce(&keys.iv, pn);
    let gcm = AesGcm::new_128(&keys.key);
    gcm.decrypt(&nonce, aad, payload, tag)
}

/// RFC 9001 Appendix A.1 test vectors — DCID
/// `0x8394c8f03e515708` produces:
///
///   client_initial_secret =
///     c00cf151ca5be075ed0ebfb5c80323c4 2d6b7db67881289af4008f1f6c357aea
///   server_initial_secret =
///     3c9bf6a9c1c8c71819876967bd8b979e fd98ec665edf27f22c06e9845ba0ae2b
///
///   client.key  = 1f369613dd76d5467730efcbe3b1a22d
///   client.iv   = fa044b2f42a3fd3b46fb255c
///   client.hp   = 9f50449e04a0e810283a1e9933adedd2
///   server.key  = cf3a5331653c364c88f0f379b6067e37
///   server.iv   = 0ac1493ca1905853b0bba03e
///   server.hp   = c206b8d9b9f0f37644430b490eeaa314
///
/// This function exercises the derivation and is type-checked against
/// the public surface; it isn't called from the live module path so
/// it gets dead-stripped, but the compiler validates that the API
/// surface is consistent.
#[allow(dead_code)]
unsafe fn rfc9001_a1_self_check() -> bool {
    let dcid: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let (client, server) = derive_initial_keys(&dcid);

    let expected_client_key: [u8; 16] = [
        0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30,
        0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d,
    ];
    let expected_client_iv: [u8; 12] = [
        0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb,
        0x25, 0x5c,
    ];
    let expected_client_hp: [u8; 16] = [
        0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a,
        0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
    ];
    let expected_server_key: [u8; 16] = [
        0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c, 0x88, 0xf0,
        0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37,
    ];
    let expected_server_iv: [u8; 12] = [
        0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53, 0xb0, 0xbb,
        0xa0, 0x3e,
    ];
    let expected_server_hp: [u8; 16] = [
        0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76, 0x44, 0x43,
        0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14,
    ];

    bytes_eq(&client.key, &expected_client_key)
        && bytes_eq(&client.iv, &expected_client_iv)
        && bytes_eq(&client.hp, &expected_client_hp)
        && bytes_eq(&server.key, &expected_server_key)
        && bytes_eq(&server.iv, &expected_server_iv)
        && bytes_eq(&server.hp, &expected_server_hp)
}

#[allow(dead_code)]
fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    let mut diff = 0u8;
    while i < a.len() {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}
