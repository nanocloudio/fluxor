// TLS 1.3 Record Layer (RFC 8446 Section 5)
// Handles framing, encryption, decryption, sequence numbers

/// TLS content types
pub const CT_CHANGE_CIPHER_SPEC: u8 = 20;
pub const CT_ALERT: u8 = 21;
pub const CT_HANDSHAKE: u8 = 22;
pub const CT_APPLICATION_DATA: u8 = 23;

/// TLS 1.3 record header size
pub const RECORD_HEADER_LEN: usize = 5;
/// Max plaintext per record
pub const MAX_PLAINTEXT: usize = 16384;
/// Max ciphertext = plaintext + content_type(1) + tag(16)
pub const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 1 + 16;

/// Legacy version in record header (TLS 1.2 for compatibility)
const LEGACY_VERSION: [u8; 2] = [0x03, 0x03];

/// Cipher suite parameters
#[derive(Clone, Copy, PartialEq)]
pub enum CipherSuite {
    Aes128Gcm,       // 0x1301
    ChaCha20Poly1305, // 0x1303
    Aes256Gcm,       // 0x1302
}

impl CipherSuite {
    pub const fn id(self) -> u16 {
        match self {
            CipherSuite::Aes128Gcm => 0x1301,
            CipherSuite::ChaCha20Poly1305 => 0x1303,
            CipherSuite::Aes256Gcm => 0x1302,
        }
    }

    pub const fn key_len(self) -> usize {
        match self {
            CipherSuite::Aes128Gcm => 16,
            CipherSuite::ChaCha20Poly1305 => 32,
            CipherSuite::Aes256Gcm => 32,
        }
    }

    pub const fn iv_len(self) -> usize { 12 }
    pub const fn tag_len(self) -> usize { 16 }

    pub const fn hash_alg(self) -> HashAlg {
        match self {
            CipherSuite::Aes128Gcm => HashAlg::Sha256,
            CipherSuite::ChaCha20Poly1305 => HashAlg::Sha256,
            CipherSuite::Aes256Gcm => HashAlg::Sha384,
        }
    }

    pub const fn hash_len(self) -> usize {
        match self {
            CipherSuite::Aes128Gcm => 32,
            CipherSuite::ChaCha20Poly1305 => 32,
            CipherSuite::Aes256Gcm => 48,
        }
    }

    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(CipherSuite::Aes128Gcm),
            0x1303 => Some(CipherSuite::ChaCha20Poly1305),
            0x1302 => Some(CipherSuite::Aes256Gcm),
            _ => None,
        }
    }
}

/// Per-direction traffic keys
pub struct TrafficKeys {
    pub key: [u8; 32],   // max key length
    pub iv: [u8; 12],
    pub key_len: usize,
    pub seq: u64,
}

impl TrafficKeys {
    pub const fn empty() -> Self {
        Self {
            key: [0; 32],
            iv: [0; 12],
            key_len: 0,
            seq: 0,
        }
    }

    /// Derive traffic keys from a traffic secret
    pub fn from_secret(suite: CipherSuite, secret: &[u8]) -> Self {
        let mut keys = Self::empty();
        keys.key_len = suite.key_len();
        let alg = suite.hash_alg();
        hkdf_expand_label(alg, secret, b"key", &[], &mut keys.key[..keys.key_len]);
        hkdf_expand_label(alg, secret, b"iv", &[], &mut keys.iv);
        keys
    }

    /// Compute nonce = iv XOR padded_sequence_number
    pub fn nonce(&self) -> [u8; 12] {
        let mut n = self.iv;
        let seq_bytes = self.seq.to_be_bytes();
        // XOR sequence number into last 8 bytes of IV
        n[4] ^= seq_bytes[0]; n[5] ^= seq_bytes[1];
        n[6] ^= seq_bytes[2]; n[7] ^= seq_bytes[3];
        n[8] ^= seq_bytes[4]; n[9] ^= seq_bytes[5];
        n[10] ^= seq_bytes[6]; n[11] ^= seq_bytes[7];
        n
    }

    pub fn advance_seq(&mut self) {
        self.seq += 1;
    }
}

/// Build a plaintext record header. All stores are volatile so PIC aarch64
/// cannot dead-store part of the header.
pub fn build_record_header(content_type: u8, length: usize, out: &mut [u8; 5]) {
    unsafe {
        let p = out.as_mut_ptr();
        core::ptr::write_volatile(p, content_type);
        core::ptr::write_volatile(p.add(1), LEGACY_VERSION[0]);
        core::ptr::write_volatile(p.add(2), LEGACY_VERSION[1]);
        core::ptr::write_volatile(p.add(3), (length >> 8) as u8);
        core::ptr::write_volatile(p.add(4), length as u8);
    }
}

/// Build an encrypted record header (always type 0x17, version 0x0303)
pub fn build_encrypted_record_header(payload_len: usize, out: &mut [u8; 5]) {
    out[0] = CT_APPLICATION_DATA;
    out[1] = LEGACY_VERSION[0];
    out[2] = LEGACY_VERSION[1];
    let total = payload_len + 1 + 16; // content_type byte + tag
    out[3] = (total >> 8) as u8;
    out[4] = total as u8;
}

/// Encrypt a TLS 1.3 record in-place.
/// `plaintext` is the data to encrypt. `content_type` is the inner type.
/// On return, `out_buf` contains: encrypted_data + content_type + tag
/// Returns total encrypted length (plaintext_len + 1 + 16)
pub fn encrypt_record(
    suite: CipherSuite,
    keys: &mut TrafficKeys,
    content_type: u8,
    plaintext: &[u8],
    out_buf: &mut [u8],
) -> usize {
    let ct_len = plaintext.len() + 1 + 16; // data + content_type + tag

    // Build AAD (record header)
    let mut aad = [0u8; 5];
    aad[0] = CT_APPLICATION_DATA;
    aad[1] = 0x03; aad[2] = 0x03;
    aad[3] = (ct_len >> 8) as u8;
    aad[4] = ct_len as u8;

    // Copy plaintext + content_type into output
    unsafe { core::ptr::copy_nonoverlapping(plaintext.as_ptr(), out_buf.as_mut_ptr(), plaintext.len()); }
    out_buf[plaintext.len()] = content_type;

    let data_len = plaintext.len() + 1;
    let nonce = keys.nonce();
    keys.advance_seq();

    match suite {
        CipherSuite::ChaCha20Poly1305 => {
            let mut key = [0u8; 32];
            unsafe { core::ptr::copy_nonoverlapping(keys.key.as_ptr(), key.as_mut_ptr(), 32); }
            let tag = chacha20_poly1305_encrypt(&key, &nonce, &aad, &mut out_buf[..data_len]);
            unsafe { core::ptr::copy_nonoverlapping(tag.as_ptr(), out_buf.as_mut_ptr().add(data_len), 16); }
            zeroize(&mut key);
        }
        CipherSuite::Aes128Gcm => {
            let mut key = [0u8; 16];
            unsafe { core::ptr::copy_nonoverlapping(keys.key.as_ptr(), key.as_mut_ptr(), 16); }
            let gcm = AesGcm::new_128(&key);
            let tag = gcm.encrypt(&nonce, &aad, &mut out_buf[..data_len]);
            unsafe { core::ptr::copy_nonoverlapping(tag.as_ptr(), out_buf.as_mut_ptr().add(data_len), 16); }
            zeroize(&mut key);
        }
        CipherSuite::Aes256Gcm => {
            let mut key = [0u8; 32];
            unsafe { core::ptr::copy_nonoverlapping(keys.key.as_ptr(), key.as_mut_ptr(), 32); }
            let gcm = AesGcm::new_256(&key);
            let tag = gcm.encrypt(&nonce, &aad, &mut out_buf[..data_len]);
            unsafe { core::ptr::copy_nonoverlapping(tag.as_ptr(), out_buf.as_mut_ptr().add(data_len), 16); }
            zeroize(&mut key);
        }
    }

    ct_len
}

/// Decrypt a TLS 1.3 record in-place.
/// `ciphertext` contains: encrypted_data + tag (the record payload after header)
/// On success, returns (plaintext_len, inner_content_type).
/// On failure, returns None (bad MAC).
pub fn decrypt_record(
    suite: CipherSuite,
    keys: &mut TrafficKeys,
    record_header: &[u8; 5],
    ciphertext: &mut [u8],
) -> Option<(usize, u8)> {
    if ciphertext.len() < 17 { return None; } // at least 1 byte content_type + 16 byte tag

    let tag_start = ciphertext.len() - 16;
    let mut tag = [0u8; 16];
    unsafe { core::ptr::copy_nonoverlapping(ciphertext.as_ptr().add(tag_start), tag.as_mut_ptr(), 16); }

    let data = &mut ciphertext[..tag_start];
    let nonce = keys.nonce();
    // Sequence counter advanced AFTER MAC verification succeeds (below)

    let ok = match suite {
        CipherSuite::ChaCha20Poly1305 => {
            let mut key = [0u8; 32];
            unsafe { core::ptr::copy_nonoverlapping(keys.key.as_ptr(), key.as_mut_ptr(), 32); }
            let r = chacha20_poly1305_decrypt(&key, &nonce, record_header, data, &tag);
            zeroize(&mut key);
            r
        }
        CipherSuite::Aes128Gcm => {
            let mut key = [0u8; 16];
            unsafe { core::ptr::copy_nonoverlapping(keys.key.as_ptr(), key.as_mut_ptr(), 16); }
            let gcm = AesGcm::new_128(&key);
            let r = gcm.decrypt(&nonce, record_header, data, &tag);
            zeroize(&mut key);
            r
        }
        CipherSuite::Aes256Gcm => {
            let mut key = [0u8; 32];
            unsafe { core::ptr::copy_nonoverlapping(keys.key.as_ptr(), key.as_mut_ptr(), 32); }
            let gcm = AesGcm::new_256(&key);
            let r = gcm.decrypt(&nonce, record_header, data, &tag);
            zeroize(&mut key);
            r
        }
    };

    zeroize(&mut tag);

    if !ok { return None; }

    // MAC verified — now advance sequence counter
    keys.advance_seq();

    // Find inner content type (last non-zero byte of decrypted data)
    let mut pt_len = data.len();
    while pt_len > 0 && data[pt_len - 1] == 0 {
        pt_len -= 1;
    }
    if pt_len == 0 { return None; }
    pt_len -= 1;
    let inner_type = data[pt_len];
    // Wipe the inner-type byte — it is copied into the return value, and
    // leaving it in the scratch buffer leaks across record reuses.
    unsafe { core::ptr::write_volatile(data.as_mut_ptr().add(pt_len), 0u8); }

    Some((pt_len, inner_type))
}
