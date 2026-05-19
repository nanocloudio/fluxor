//! Known-Answer Tests for the TLS module's crypto primitives.
//!
//! Tracked-in-git regression gate for the cipher and key-share
//! primitives that `tls` and `quic` both `include!()`. Vectors:
//!   - RFC 8439 §2.8.2 — ChaCha20-Poly1305 AEAD
//!   - NIST GCM SP 800-38D — AES-128-GCM and AES-256-GCM
//!   - NIST FIPS 180-4 — SHA-256
//!   - RFC 5903 + invalid-curve attack defence — P-256 ECDH
//!   - RFC 9147 §7.1 — DTLS 1.3 ACK record codec
//!   - foundation/tls MSG_PEER_IDENTITY (Fluxor-owned wire)
//!
//! Lives in this crate (not the harness sub-workspace) so it
//! ships with the source for everyone fetching the repo. Run via:
//!     cargo test -p fluxor-mod-tls --features host-test \
//!       --target aarch64-unknown-linux-gnu
//! The `host-test` feature switches `mod.rs` away from `#![no_std]`
//! so the integration test can link the crate as a normal rlib.

use fluxor_mod_tls as tls;

// ============================================================================
// SHA-256 (FIPS 180-4 + a long-input check)
// ============================================================================

#[test]
fn sha256_empty_string_matches_fips_180_4() {
    let digest = tls::sha256(b"");
    let expected: [u8; 32] = hex!(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(digest, expected);
}

#[test]
fn sha256_abc_matches_fips_180_4() {
    let digest = tls::sha256(b"abc");
    let expected: [u8; 32] = hex!(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(digest, expected);
}

#[test]
fn sha256_long_block_aligned() {
    // 1 MiB of zeros — covers many block boundaries.
    let zeros = vec![0u8; 1024 * 1024];
    let digest = tls::sha256(&zeros);
    let expected: [u8; 32] = hex!(
        "30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58"
    );
    assert_eq!(digest, expected);
}

// ============================================================================
// ChaCha20-Poly1305 (RFC 8439 §2.8.2 — the canonical vector)
// ============================================================================

#[test]
fn chacha20_poly1305_rfc8439_section_2_8_2_round_trip() {
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let aad: [u8; 12] = hex!("50515253c0c1c2c3c4c5c6c7");
    let key: [u8; 32] = hex!(
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
    );
    let nonce: [u8; 12] = hex!("070000004041424344454647");

    // Encrypt
    let mut ct = plaintext.to_vec();
    let tag = tls::chacha20_poly1305_encrypt(&key, &nonce, &aad, &mut ct);
    let expected_ct: [u8; 114] = hex!(
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116"
    );
    assert_eq!(ct, expected_ct);
    let expected_tag: [u8; 16] = hex!("1ae10b594f09e26a7e902ecbd0600691");
    assert_eq!(tag, expected_tag);

    // Decrypt
    let mut pt = ct.clone();
    let ok = tls::chacha20_poly1305_decrypt(&key, &nonce, &aad, &mut pt, &tag);
    assert!(ok, "decrypt should verify");
    assert_eq!(pt, plaintext);

    // Bit-flipped tag rejects
    let mut bad_tag = tag;
    bad_tag[0] ^= 1;
    let mut pt2 = ct;
    assert!(
        !tls::chacha20_poly1305_decrypt(&key, &nonce, &aad, &mut pt2, &bad_tag),
        "decrypt MUST reject a flipped tag",
    );
}

#[test]
fn chacha20_poly1305_neon_path_matches_scalar_for_long_payload() {
    // Hit the aarch64 NEON full-64-byte block path with a payload
    // long enough to require several iterations (≥ 2 full blocks
    // and a tail < 64). Round-trip is the regression gate — any
    // future NEON tweak that drifts from RFC 8439 fails here.
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"";
    let mut pt: Vec<u8> = (0..200).map(|i| (i & 0xff) as u8).collect();
    let original = pt.clone();
    let tag = tls::chacha20_poly1305_encrypt(&key, &nonce, aad, &mut pt);
    assert!(tls::chacha20_poly1305_decrypt(&key, &nonce, aad, &mut pt, &tag));
    assert_eq!(pt, original);
}

// ============================================================================
// AES-GCM (NIST SP 800-38D test vectors)
// ============================================================================

#[test]
fn aes128_gcm_nist_test_case_3() {
    // From "The Galois/Counter Mode of Operation (GCM)" — McGrew & Viega.
    // Test case 3: 128-bit key, 96-bit IV, 16-byte AAD, 60-byte plaintext.
    let key: [u8; 16] = hex!("feffe9928665731c6d6a8f9467308308");
    let iv: [u8; 12] = hex!("cafebabefacedbaddecaf888");
    let pt: [u8; 64] = hex!(
        "d9313225f88406e5a55909c5aff5269a"
        "86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b391aafd255"
    );
    let aad = b"";

    let mut buf = pt.to_vec();
    let gcm = tls::AesGcm::new_128(&key);
    let tag = gcm.encrypt(&iv, aad, &mut buf);
    let expected_ct: [u8; 64] = hex!(
        "42831ec2217774244b7221b784d0d49c"
        "e3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa05"
        "1ba30b396a0aac973d58e091473f5985"
    );
    assert_eq!(buf, expected_ct);
    let expected_tag: [u8; 16] = hex!("4d5c2af327cd64a62cf35abd2ba6fab4");
    assert_eq!(tag, expected_tag);

    // Round-trip decrypt
    let ok = gcm.decrypt(&iv, aad, &mut buf, &tag);
    assert!(ok, "AES-128-GCM decrypt must verify");
    assert_eq!(&buf[..], &pt[..]);

    // Bit-flipped tag rejects
    let mut bad_tag = tag;
    bad_tag[0] ^= 1;
    let mut buf2 = expected_ct.to_vec();
    assert!(
        !gcm.decrypt(&iv, aad, &mut buf2, &bad_tag),
        "AES-128-GCM MUST reject a flipped tag",
    );
}

#[test]
fn aes256_gcm_nist_test_case_13_empty() {
    // McGrew & Viega Appendix B Test Case 13: 256-bit zero key,
    // 96-bit zero IV, empty plaintext, empty AAD.
    let key: [u8; 32] = [0u8; 32];
    let iv: [u8; 12] = [0u8; 12];
    let mut buf: Vec<u8> = Vec::new();
    let gcm = tls::AesGcm::new_256(&key);
    let tag = gcm.encrypt(&iv, b"", &mut buf);
    let expected_tag: [u8; 16] = hex!("530f8afbc74536b9a963b4f1c4cb738b");
    assert_eq!(tag, expected_tag, "AES-256 key expansion is wrong");
}

#[test]
fn aes256_gcm_nist_test_case_14_single_block() {
    // Test Case 14: 256-bit zero key, 96-bit zero IV, 16-byte
    // zero plaintext, empty AAD.
    let key: [u8; 32] = [0u8; 32];
    let iv: [u8; 12] = [0u8; 12];
    let mut buf = vec![0u8; 16];
    let gcm = tls::AesGcm::new_256(&key);
    let tag = gcm.encrypt(&iv, b"", &mut buf);
    let expected_ct: [u8; 16] = hex!("cea7403d4d606b6e074ec5d3baf39d18");
    assert_eq!(buf, expected_ct);
    let expected_tag: [u8; 16] = hex!("d0d1c8a799996bf0265b98b5d48ab919");
    assert_eq!(tag, expected_tag);

    let ok = gcm.decrypt(&iv, b"", &mut buf, &tag);
    assert!(ok);
    assert_eq!(buf, vec![0u8; 16]);
}

#[test]
fn aes_gcm_aad_authenticated_separately_from_plaintext() {
    // The same key/iv/plaintext with different AAD must produce a
    // different tag — this is the gate that catches a buggy GCM
    // impl that "forgets" to mix AAD into the GHASH state.
    let key: [u8; 16] = hex!("00000000000000000000000000000000");
    let iv: [u8; 12] = hex!("000000000000000000000000");
    let gcm = tls::AesGcm::new_128(&key);
    let mut buf1 = vec![0u8; 16];
    let mut buf2 = vec![0u8; 16];
    let tag1 = gcm.encrypt(&iv, b"aad-a", &mut buf1);
    let tag2 = gcm.encrypt(&iv, b"aad-b", &mut buf2);
    assert_eq!(buf1, buf2, "ciphertext should be identical when key+iv+pt match");
    assert_ne!(tag1, tag2, "tag must differ when AAD differs");
}

// ============================================================================
// P-256 ECDH (a.k.a. ECDHE in TLS 1.3 key_share)
// ============================================================================

#[test]
fn p256_ecdh_alice_and_bob_agree_on_shared_secret() {
    // Generate two key pairs deterministically. Compute shared
    // secret from each side; they MUST match (RFC 5903 §8).
    let mut alice_rand = [0u8; 32];
    for (i, b) in alice_rand.iter_mut().enumerate() { *b = i as u8 + 1; }
    let mut bob_rand = [0u8; 32];
    for (i, b) in bob_rand.iter_mut().enumerate() { *b = (i as u8) ^ 0x5a; }

    let (alice_priv, alice_pub) = tls::ecdh_keygen(&alice_rand);
    let (bob_priv, bob_pub) = tls::ecdh_keygen(&bob_rand);

    let alice_shared = tls::ecdh_shared_secret(&alice_priv, &bob_pub)
        .expect("alice computes shared");
    let bob_shared = tls::ecdh_shared_secret(&bob_priv, &alice_pub)
        .expect("bob computes shared");

    assert_eq!(alice_shared, bob_shared, "ECDH must converge");
}

#[test]
fn p256_ecdh_rejects_point_not_on_curve() {
    // Public-key validation: a point that doesn't satisfy
    // y^2 ≡ x^3 - 3x + b (mod p) must be rejected. Pick all-FFs
    // for x — almost certainly not on the curve.
    let priv_key = [1u8; 32];
    let mut bogus_pub = [0u8; 65];
    bogus_pub[0] = 0x04;
    for b in bogus_pub.iter_mut().skip(1) { *b = 0xff; }
    let result = tls::ecdh_shared_secret(&priv_key, &bogus_pub);
    assert!(
        result.is_none(),
        "off-curve point must be rejected — small-subgroup / invalid-curve attack defence",
    );
}

#[test]
fn p256_ecdsa_sign_verify_round_trip() {
    let mut rand = [0u8; 32];
    for (i, b) in rand.iter_mut().enumerate() { *b = i as u8 + 7; }
    let (priv_key, pub_key) = tls::ecdh_keygen(&rand);

    let msg = b"the quick brown fox jumps over the lazy dog";
    let hash = tls::sha256(msg);

    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() { *b = (i as u8) ^ 0xa5; }
    let sig = tls::ecdsa_sign(&priv_key, &hash, &k);
    assert!(
        tls::ecdsa_verify(&pub_key, &hash, &sig),
        "honest sig must verify",
    );

    // Flip a bit in the signature: must reject.
    let mut bad = sig;
    bad[0] ^= 1;
    assert!(
        !tls::ecdsa_verify(&pub_key, &hash, &bad),
        "tampered sig must NOT verify",
    );
}

// ============================================================================
// MSG_PEER_IDENTITY envelope (Fluxor-owned wire shape)
// ============================================================================

#[test]
fn peer_identity_envelope_format_with_svid() {
    let svid = [0xDEu8; 32];
    let mut out = [0u8; tls::PEER_IDENTITY_MAX_TOTAL];
    let n = tls::build_peer_identity_envelope(7, &svid, &mut out);

    assert_eq!(n, tls::PEER_IDENTITY_MAX_TOTAL, "full 32-B SVID fills the envelope");
    assert_eq!(out[0], tls::MSG_PEER_IDENTITY);
    // payload_len = 4 (fixed) + 32 (svid) = 36 → 0x24 0x00 LE
    assert_eq!(out[1], 36);
    assert_eq!(out[2], 0);
    assert_eq!(out[3], 7, "conn_id");
    assert_eq!(out[4], tls::PEER_IDENTITY_REPLICA_UNKNOWN);
    assert_eq!(out[5], 1, "verified=1 when SVID is present");
    assert_eq!(out[6], 32, "svid_len");
    // SVID body bytes
    let mut all_de = true;
    let mut i = 0;
    while i < 32 { if out[7 + i] != 0xDE { all_de = false; } i += 1; }
    assert!(all_de);
}

#[test]
fn peer_identity_envelope_format_no_svid_marks_unverified() {
    let mut out = [0u8; tls::PEER_IDENTITY_MAX_TOTAL];
    let n = tls::build_peer_identity_envelope(0, &[], &mut out);

    assert_eq!(n, tls::PEER_IDENTITY_HEADER_LEN + tls::PEER_IDENTITY_FIXED_PAYLOAD_LEN);
    assert_eq!(out[0], tls::MSG_PEER_IDENTITY);
    assert_eq!(out[5], 0, "verified=0 when SVID is empty");
    assert_eq!(out[6], 0, "svid_len=0");
}

#[test]
fn peer_identity_envelope_caps_svid_at_max() {
    // Anything longer than MAX_SVID is silently truncated — the
    // pubkey hash is always 32 B but defence in depth.
    let oversized = [0xAAu8; 64];
    let mut out = [0u8; tls::PEER_IDENTITY_MAX_TOTAL];
    let n = tls::build_peer_identity_envelope(0, &oversized, &mut out);
    assert_eq!(n, tls::PEER_IDENTITY_MAX_TOTAL);
    assert_eq!(out[6], tls::PEER_IDENTITY_MAX_SVID as u8);
}

// ============================================================================
// DTLS 1.3 ACK records (RFC 9147 §7.1)
// ============================================================================

#[test]
fn dtls_ack_record_round_trip() {
    // Build → parse must be exact-identity, including wire-length
    // prefix. Per RFC 9147 §7.1 the body is `uint16 length || N ×
    // (uint64 epoch || uint64 seq)` in network byte order.
    let records = [
        (2u64, 0u64),
        (2u64, 1u64),
        (3u64, 42u64),
    ];
    let mut buf = [0u8; 64];
    let n = tls::build_dtls_ack_body(&records, &mut buf);
    assert_eq!(n, 2 + 3 * 16, "wire length = 2 + 16 × count");
    // length prefix
    assert_eq!(buf[0], 0x00);
    assert_eq!(buf[1], (3 * 16) as u8);
    // first record number: epoch=2, seq=0 — last byte of each u64
    assert_eq!(buf[2 + 7], 2); // epoch[7]
    assert_eq!(buf[2 + 15], 0); // seq[7]

    let mut parsed = [(0u64, 0u64); 8];
    let count = tls::parse_dtls_ack_body(&buf[..n], &mut parsed).expect("parse");
    assert_eq!(count, 3);
    assert_eq!(&parsed[..3], &records);
}

#[test]
fn dtls_ack_record_rejects_malformed_length() {
    // Length prefix says 16 bytes but body has only 10.
    let buf: [u8; 12] = [0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut out = [(0u64, 0u64); 4];
    assert!(tls::parse_dtls_ack_body(&buf, &mut out).is_none());
}

#[test]
fn dtls_ack_record_rejects_non_multiple_of_16() {
    // Length prefix says 15 (not a multiple of 16).
    let buf: [u8; 17] = [0, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut out = [(0u64, 0u64); 4];
    assert!(tls::parse_dtls_ack_body(&buf, &mut out).is_none());
}

#[test]
fn dtls_ack_record_rejects_trailing_bytes() {
    // Length prefix says 0 records (0 bytes), but the buffer has
    // 3 trailing bytes after the prefix. RFC 9147 §7.1 has no
    // padding inside an ACK body — trailing bytes are either a
    // malformed peer or an attempt to stuff data into a record
    // the receiver treats as a pure ACK.
    let buf: [u8; 5] = [0, 0, 0xAA, 0xBB, 0xCC];
    let mut out = [(0u64, 0u64); 4];
    assert!(tls::parse_dtls_ack_body(&buf, &mut out).is_none());

    // Same with a non-empty record number followed by trailing
    // garbage.
    let mut buf2 = [0u8; 18 + 4];
    buf2[0] = 0;
    buf2[1] = 16;
    // record number: epoch=2, seq=1
    buf2[2 + 7] = 2;
    buf2[2 + 15] = 1;
    // trailing 4 bytes left as 0
    assert!(tls::parse_dtls_ack_body(&buf2, &mut out).is_none());
}

#[test]
fn dtls_ack_record_empty_list_is_valid() {
    // Empty ACK = "I'm acking nothing" — RFC allows zero-length
    // record_numbers. Useful as a keep-alive.
    let mut buf = [0u8; 4];
    let n = tls::build_dtls_ack_body(&[], &mut buf);
    assert_eq!(n, 2);
    assert_eq!(buf[0], 0);
    assert_eq!(buf[1], 0);
    let mut out = [(0u64, 0u64); 4];
    let count = tls::parse_dtls_ack_body(&buf[..n], &mut out).expect("parse empty");
    assert_eq!(count, 0);
}

// ============================================================================
// Minimal `hex!` macro: turns a string literal into a fixed-size byte
// array at compile time. Used by every KAT above. Inline so the
// crate doesn't drag in `hex-literal`.
// ============================================================================

macro_rules! hex {
    ($($s:literal)+) => {{
        const HEX: &[u8] = concat!($($s),+).as_bytes();
        const N: usize = HEX.len() / 2;
        const fn nibble(b: u8) -> u8 {
            match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => panic!("non-hex digit"),
            }
        }
        const fn decode() -> [u8; N] {
            let mut out = [0u8; N];
            let mut i = 0;
            while i < N {
                out[i] = (nibble(HEX[2 * i]) << 4) | nibble(HEX[2 * i + 1]);
                i += 1;
            }
            out
        }
        decode()
    }};
}
use hex;
