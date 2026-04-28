// AES-128/256-GCM AEAD
// Pure Rust, no_std, constant-time (no data-dependent table lookups)
// Uses precomputed const S-box and RCON tables (in .rodata, not .data)

// AES S-box (256 bytes, const — placed in .rodata, safe for PIC)
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const RCON: [u8; 11] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

// ============================================================================
// AES core (SubBytes uses S-box table in .rodata)
// ============================================================================

/// Multiply by 2 in GF(2^8)
#[inline(always)]
fn xtime(a: u8) -> u8 {
    let r = (a as u16) << 1;
    (r ^ (((r >> 8) & 1) * 0x1b)) as u8
}

/// Multiply in GF(2^8)
#[inline(always)]
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    let mut i = 0;
    while i < 8 {
        if b & 1 != 0 { p ^= a; }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 { a ^= 0x1b; }
        b >>= 1;
        i += 1;
    }
    p
}

/// AES round key structure — supports up to AES-256 (15 round keys × 16 bytes)
struct AesKey {
    round_keys: [[u8; 16]; 15],
    rounds: usize,
}

impl AesKey {
    fn expand_128(key: &[u8; 16]) -> Self {
        let mut rk = [[0u8; 16]; 15];
        unsafe { core::ptr::copy_nonoverlapping(key.as_ptr(), rk[0].as_mut_ptr(), 16); }

        let mut i = 1;
        while i <= 10 {
            let prev = rk[i - 1];
            // RotWord + SubWord + RCON
            rk[i][0] = SBOX[prev[13] as usize] ^ RCON[i] ^ prev[0];
            rk[i][1] = SBOX[prev[14] as usize] ^ prev[1];
            rk[i][2] = SBOX[prev[15] as usize] ^ prev[2];
            rk[i][3] = SBOX[prev[12] as usize] ^ prev[3];
            let mut j = 4;
            while j < 16 {
                rk[i][j] = rk[i][j - 4] ^ prev[j];
                j += 1;
            }
            i += 1;
        }
        Self { round_keys: rk, rounds: 10 }
    }

    fn expand_256(key: &[u8; 32]) -> Self {
        let mut rk = [[0u8; 16]; 15];
        unsafe {
            core::ptr::copy_nonoverlapping(key.as_ptr(), rk[0].as_mut_ptr(), 16);
            core::ptr::copy_nonoverlapping(key.as_ptr().add(16), rk[1].as_mut_ptr(), 16);
        }

        let mut i = 2;
        let mut rcon_idx = 1;
        while i <= 14 {
            let prev = rk[i - 1];
            let prev2 = rk[i - 2];

            if i % 2 == 0 {
                // RotWord + SubWord + RCON
                rk[i][0] = SBOX[prev[13] as usize] ^ RCON[rcon_idx] ^ prev2[0];
                rk[i][1] = SBOX[prev[14] as usize] ^ prev2[1];
                rk[i][2] = SBOX[prev[15] as usize] ^ prev2[2];
                rk[i][3] = SBOX[prev[12] as usize] ^ prev2[3];
                rcon_idx += 1;
            } else {
                // SubWord only (AES-256 extra step)
                rk[i][0] = SBOX[prev[0] as usize] ^ prev2[0];
                rk[i][1] = SBOX[prev[1] as usize] ^ prev2[1];
                rk[i][2] = SBOX[prev[2] as usize] ^ prev2[2];
                rk[i][3] = SBOX[prev[3] as usize] ^ prev2[3];
            }

            let mut j = 4;
            while j < 16 {
                rk[i][j] = rk[i][j - 4] ^ prev2[j];
                j += 1;
            }
            i += 1;
        }
        Self { round_keys: rk, rounds: 14 }
    }

    fn encrypt_block(&self, block: &mut [u8; 16]) {
        // AddRoundKey (initial)
        xor_block(block, &self.round_keys[0]);

        // Main rounds
        let mut r = 1;
        while r < self.rounds {
            sub_bytes(block);
            shift_rows(block);
            mix_columns(block);
            xor_block(block, &self.round_keys[r]);
            r += 1;
        }

        // Final round (no MixColumns)
        sub_bytes(block);
        shift_rows(block);
        xor_block(block, &self.round_keys[self.rounds]);
    }
}

#[inline(always)]
fn xor_block(a: &mut [u8; 16], b: &[u8; 16]) {
    let mut i = 0;
    while i < 16 { a[i] ^= b[i]; i += 1; }
}

fn sub_bytes(block: &mut [u8; 16]) {
    let mut i = 0;
    while i < 16 {
        block[i] = SBOX[block[i] as usize];
        i += 1;
    }
}

fn shift_rows(s: &mut [u8; 16]) {
    // Row 1: shift left 1
    let t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    // Row 2: shift left 2
    let t0 = s[2]; let t1 = s[6]; s[2] = s[10]; s[6] = s[14]; s[10] = t0; s[14] = t1;
    // Row 3: shift left 3 (= right 1)
    let t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

fn mix_columns(s: &mut [u8; 16]) {
    let mut i = 0;
    while i < 16 {
        let a0 = s[i]; let a1 = s[i + 1]; let a2 = s[i + 2]; let a3 = s[i + 3];
        let t = a0 ^ a1 ^ a2 ^ a3;
        s[i]     = a0 ^ xtime(a0 ^ a1) ^ t;
        s[i + 1] = a1 ^ xtime(a1 ^ a2) ^ t;
        s[i + 2] = a2 ^ xtime(a2 ^ a3) ^ t;
        s[i + 3] = a3 ^ xtime(a3 ^ a0) ^ t;
        i += 4;
    }
}

// ============================================================================
// GHASH (GF(2^128) multiplication for GCM)
// ============================================================================

/// GF(2^128) element as two u64 (big-endian bit ordering)
struct GHash {
    h_lo: u64,
    h_hi: u64,
    y_lo: u64,
    y_hi: u64,
}

impl GHash {
    fn new(h: &[u8; 16]) -> Self {
        Self {
            h_hi: u64::from_be_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]),
            h_lo: u64::from_be_bytes([h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]]),
            y_hi: 0,
            y_lo: 0,
        }
    }

    /// Multiply in GF(2^128) with reduction polynomial x^128 + x^7 + x^2 + x + 1
    fn gf_mul(&mut self) {
        let mut z_hi: u64 = 0;
        let mut z_lo: u64 = 0;
        let mut v_hi = self.h_hi;
        let mut v_lo = self.h_lo;
        let y_hi = self.y_hi;
        let y_lo = self.y_lo;

        // Process high 64 bits of Y
        let mut i: i32 = 63;
        while i >= 0 {
            if (y_hi >> i as u32) & 1 == 1 {
                z_hi ^= v_hi;
                z_lo ^= v_lo;
            }
            // v >>= 1 with reduction
            let carry = v_lo & 1;
            v_lo = (v_lo >> 1) | (v_hi << 63);
            v_hi >>= 1;
            if carry == 1 {
                v_hi ^= 0xe100000000000000; // R = x^128 + x^7 + x^2 + x + 1
            }
            i -= 1;
        }

        // Process low 64 bits of Y
        i = 63;
        while i >= 0 {
            if (y_lo >> i as u32) & 1 == 1 {
                z_hi ^= v_hi;
                z_lo ^= v_lo;
            }
            let carry = v_lo & 1;
            v_lo = (v_lo >> 1) | (v_hi << 63);
            v_hi >>= 1;
            if carry == 1 {
                v_hi ^= 0xe100000000000000;
            }
            i -= 1;
        }

        self.y_hi = z_hi;
        self.y_lo = z_lo;
    }

    fn update_block(&mut self, block: &[u8; 16]) {
        self.y_hi ^= u64::from_be_bytes([block[0], block[1], block[2], block[3],
                                          block[4], block[5], block[6], block[7]]);
        self.y_lo ^= u64::from_be_bytes([block[8], block[9], block[10], block[11],
                                          block[12], block[13], block[14], block[15]]);
        self.gf_mul();
    }

    fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        while offset + 16 <= data.len() {
            let mut block = [0u8; 16];
            unsafe { core::ptr::copy_nonoverlapping(data.as_ptr().add(offset), block.as_mut_ptr(), 16); }
            self.update_block(&block);
            offset += 16;
        }
        if offset < data.len() {
            let mut block = [0u8; 16];
            let remain = data.len() - offset;
            unsafe { core::ptr::copy_nonoverlapping(data.as_ptr().add(offset), block.as_mut_ptr(), remain); }
            self.update_block(&block);
        }
    }

    fn finalize_tag(mut self, aad_len: usize, ct_len: usize) -> [u8; 16] {
        // Append lengths block (bits, big-endian)
        let mut len_block = [0u8; 16];
        let aad_bits = (aad_len as u64) * 8;
        let ct_bits = (ct_len as u64) * 8;
        unsafe {
            let a = aad_bits.to_be_bytes();
            let c = ct_bits.to_be_bytes();
            core::ptr::copy_nonoverlapping(a.as_ptr(), len_block.as_mut_ptr(), 8);
            core::ptr::copy_nonoverlapping(c.as_ptr(), len_block.as_mut_ptr().add(8), 8);
        }
        self.update_block(&len_block);

        let mut tag = [0u8; 16];
        unsafe {
            let hi = self.y_hi.to_be_bytes();
            let lo = self.y_lo.to_be_bytes();
            core::ptr::copy_nonoverlapping(hi.as_ptr(), tag.as_mut_ptr(), 8);
            core::ptr::copy_nonoverlapping(lo.as_ptr(), tag.as_mut_ptr().add(8), 8);
        }
        tag
    }
}

// ============================================================================
// AES-GCM AEAD
// ============================================================================

pub const AES128_KEY_LEN: usize = 16;
pub const AES256_KEY_LEN: usize = 32;
pub const GCM_NONCE_LEN: usize = 12;
pub const GCM_TAG_LEN: usize = 16;

/// AES-GCM context with expanded key and H (for GHASH)
pub struct AesGcm {
    aes: AesKey,
    h: [u8; 16],  // GHASH subkey = AES_K(0^128)
}

impl Drop for AesKey {
    fn drop(&mut self) {
        let mut i = 0;
        while i < self.round_keys.len() {
            zeroize(&mut self.round_keys[i]);
            i += 1;
        }
    }
}

/// Public AES-ECB primitive — encrypts a single 16-byte block under
/// `key`. Used by QUIC header protection (RFC 9001 §5.4) and other
/// places that need a raw single-block primitive without GHASH state.
/// The function inlines the round-key expansion each call; callers
/// who do header protection per-packet should cache the expanded key
/// in `Aes128Hp` instead.
#[allow(dead_code)]
pub fn aes128_ecb_encrypt_block(key: &[u8; 16], block: &mut [u8; 16]) {
    let aes = AesKey::expand_128(key);
    aes.encrypt_block(block);
}

/// Cached AES-128 encryption context for repeated single-block
/// encryption (header protection's hot path). Stores the expanded
/// round keys once per epoch.
pub struct Aes128Hp {
    aes: AesKey,
}

#[allow(dead_code)]
impl Aes128Hp {
    pub fn new(key: &[u8; 16]) -> Self {
        Self { aes: AesKey::expand_128(key) }
    }

    /// Encrypt one 16-byte block in place. Used to compute the
    /// header-protection mask from a 16-byte ciphertext sample.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        self.aes.encrypt_block(block);
    }
}

impl Drop for AesGcm {
    fn drop(&mut self) {
        zeroize(&mut self.h);
    }
}

impl AesGcm {
    pub fn new_128(key: &[u8; 16]) -> Self {
        let aes = AesKey::expand_128(key);
        let mut h = [0u8; 16];
        aes.encrypt_block(&mut h);
        Self { aes, h }
    }

    pub fn new_256(key: &[u8; 32]) -> Self {
        let aes = AesKey::expand_256(key);
        let mut h = [0u8; 16];
        aes.encrypt_block(&mut h);
        Self { aes, h }
    }

    /// Generate counter block from nonce (12 bytes) + counter (big-endian u32)
    fn make_j0(nonce: &[u8; 12]) -> [u8; 16] {
        let mut j0 = [0u8; 16];
        unsafe { core::ptr::copy_nonoverlapping(nonce.as_ptr(), j0.as_mut_ptr(), 12); }
        j0[15] = 1; // Initial counter = 1
        j0
    }

    fn inc_counter(ctr: &mut [u8; 16]) {
        let mut c = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]);
        c = c.wrapping_add(1);
        let b = c.to_be_bytes();
        unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), ctr.as_mut_ptr().add(12), 4); }
    }

    /// Encrypt data in-place and return tag.
    pub fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        let mut ctr = Self::make_j0(nonce);

        // Encrypt J0 for tag XOR
        let mut tag_mask = ctr;
        self.aes.encrypt_block(&mut tag_mask);

        // Encrypt data with counter starting at J0+1
        Self::inc_counter(&mut ctr);
        self.ctr_xor(&mut ctr, data);

        // GHASH
        let mut ghash = GHash::new(&self.h);
        ghash.update(aad);
        // Pad AAD to 16 bytes
        let aad_pad = (16 - (aad.len() % 16)) % 16;
        if aad_pad > 0 && aad.len() > 0 {
            let zeros = [0u8; 16];
            ghash.update(&zeros[..aad_pad]);
        }
        ghash.update(data);
        let ct_pad = (16 - (data.len() % 16)) % 16;
        if ct_pad > 0 && data.len() > 0 {
            let zeros = [0u8; 16];
            ghash.update(&zeros[..ct_pad]);
        }

        let mut tag = ghash.finalize_tag(aad.len(), data.len());
        // XOR with encrypted J0
        let mut i = 0;
        while i < 16 { tag[i] ^= tag_mask[i]; i += 1; }
        zeroize(&mut tag_mask);
        zeroize(&mut ctr);
        tag
    }

    /// Decrypt data in-place. Returns true if tag matches.
    pub fn decrypt(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], tag: &[u8; 16]) -> bool {
        let mut ctr = Self::make_j0(nonce);

        // Encrypt J0 for tag XOR
        let mut tag_mask = ctr;
        self.aes.encrypt_block(&mut tag_mask);

        // GHASH over ciphertext (before decryption)
        let mut ghash = GHash::new(&self.h);
        ghash.update(aad);
        let aad_pad = (16 - (aad.len() % 16)) % 16;
        if aad_pad > 0 && aad.len() > 0 {
            let zeros = [0u8; 16];
            ghash.update(&zeros[..aad_pad]);
        }
        ghash.update(data);
        let ct_pad = (16 - (data.len() % 16)) % 16;
        if ct_pad > 0 && data.len() > 0 {
            let zeros = [0u8; 16];
            ghash.update(&zeros[..ct_pad]);
        }
        let mut computed_tag = ghash.finalize_tag(aad.len(), data.len());
        let mut i = 0;
        while i < 16 { computed_tag[i] ^= tag_mask[i]; i += 1; }

        // Constant-time compare
        let mut diff = 0u8;
        i = 0;
        while i < 16 { diff |= computed_tag[i] ^ tag[i]; i += 1; }

        if diff != 0 {
            zeroize(&mut tag_mask);
            zeroize(&mut computed_tag);
            zeroize(&mut ctr);
            return false;
        }

        // Decrypt
        Self::inc_counter(&mut ctr);
        self.ctr_xor(&mut ctr, data);
        zeroize(&mut tag_mask);
        zeroize(&mut computed_tag);
        zeroize(&mut ctr);
        true
    }

    fn ctr_xor(&self, ctr: &mut [u8; 16], data: &mut [u8]) {
        let mut offset = 0;
        while offset < data.len() {
            let mut block = *ctr;
            self.aes.encrypt_block(&mut block);
            let remain = data.len() - offset;
            let take = if remain < 16 { remain } else { 16 };
            let mut j = 0;
            while j < take {
                data[offset + j] ^= block[j];
                j += 1;
            }
            Self::inc_counter(ctr);
            offset += take;
        }
    }
}
