// ChaCha20-Poly1305 AEAD (RFC 8439)
// Pure Rust, constant-time, no lookup tables, PIC-safe

/// ChaCha20 quarter round
#[inline(always)]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(7);
}

/// Generate ChaCha20 keystream block
fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    // "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    // Key
    let mut i = 0;
    while i < 8 {
        state[4 + i] = u32::from_le_bytes([
            key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3],
        ]);
        i += 1;
    }
    // Counter
    state[12] = counter;
    // Nonce
    state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);

    let initial = state;

    // 20 rounds (10 double rounds)
    let mut r = 0;
    while r < 10 {
        // Column rounds
        quarter_round(&mut state, 0, 4,  8, 12);
        quarter_round(&mut state, 1, 5,  9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7,  8, 13);
        quarter_round(&mut state, 3, 4,  9, 14);
        r += 1;
    }

    // Add initial state
    i = 0;
    while i < 16 {
        state[i] = state[i].wrapping_add(initial[i]);
        i += 1;
    }

    // Serialize to bytes
    let mut out = [0u8; 64];
    i = 0;
    while i < 16 {
        let bytes = state[i].to_le_bytes();
        out[i * 4] = bytes[0];
        out[i * 4 + 1] = bytes[1];
        out[i * 4 + 2] = bytes[2];
        out[i * 4 + 3] = bytes[3];
        i += 1;
    }
    out
}

/// ChaCha20 encrypt/decrypt (XOR keystream)
fn chacha20_xor(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    let mut ctr = counter;
    let mut offset = 0;
    while offset < data.len() {
        let block = chacha20_block(key, ctr, nonce);
        let remain = data.len() - offset;
        let take = if remain < 64 { remain } else { 64 };
        let mut j = 0;
        while j < take {
            data[offset + j] ^= block[j];
            j += 1;
        }
        offset += take;
        ctr += 1;
    }
}

// ============================================================================
// Poly1305 MAC (RFC 8439 Section 2.5)
// ============================================================================

/// 130-bit number represented as 5 × 26-bit limbs
struct Poly1305 {
    r: [u32; 5],    // clamped key r
    h: [u32; 5],    // accumulator
    pad: [u32; 4],  // one-time pad s
    buf: [u8; 16],  // partial block buffer
    buf_len: usize,
}

impl Poly1305 {
    fn new(key: &[u8; 32]) -> Self {
        // r = key[0..16] with clamping
        let t0 = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
        let t1 = u32::from_le_bytes([key[4], key[5], key[6], key[7]]);
        let t2 = u32::from_le_bytes([key[8], key[9], key[10], key[11]]);
        let t3 = u32::from_le_bytes([key[12], key[13], key[14], key[15]]);

        Self {
            r: [
                t0 & 0x03ff_ffff,
                ((t0 >> 26) | (t1 << 6)) & 0x03ff_ff03,
                ((t1 >> 20) | (t2 << 12)) & 0x03ff_c0ff,
                ((t2 >> 14) | (t3 << 18)) & 0x03f0_3fff,
                (t3 >> 8) & 0x000f_ffff,
            ],
            h: [0; 5],
            pad: [
                u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
                u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
                u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
                u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
            ],
            buf: [0; 16],
            buf_len: 0,
        }
    }

    fn block(&mut self, msg: &[u8], hibit: u32) {
        let r0 = self.r[0] as u64;
        let r1 = self.r[1] as u64;
        let r2 = self.r[2] as u64;
        let r3 = self.r[3] as u64;
        let r4 = self.r[4] as u64;

        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let mut h0 = self.h[0] as u64;
        let mut h1 = self.h[1] as u64;
        let mut h2 = self.h[2] as u64;
        let mut h3 = self.h[3] as u64;
        let mut h4 = self.h[4] as u64;

        // Add message
        let t0 = if msg.len() >= 4 { u32::from_le_bytes([msg[0], msg[1], msg[2], msg[3]]) } else { le_bytes_partial(msg, 0) };
        let t1 = if msg.len() >= 8 { u32::from_le_bytes([msg[4], msg[5], msg[6], msg[7]]) } else { le_bytes_partial(msg, 4) };
        let t2 = if msg.len() >= 12 { u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]) } else { le_bytes_partial(msg, 8) };
        let t3 = if msg.len() >= 16 { u32::from_le_bytes([msg[12], msg[13], msg[14], msg[15]]) } else { le_bytes_partial(msg, 12) };

        h0 += (t0 as u64) & 0x03ff_ffff;
        h1 += (((t0 >> 26) | (t1 << 6)) as u64) & 0x03ff_ffff;
        h2 += (((t1 >> 20) | (t2 << 12)) as u64) & 0x03ff_ffff;
        h3 += (((t2 >> 14) | (t3 << 18)) as u64) & 0x03ff_ffff;
        h4 += ((t3 >> 8) as u64) | ((hibit as u64) << 24);

        // Multiply
        let d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1;
        let d1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2;
        let d2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3;
        let d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4;
        let d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0;

        // Carry propagation
        let mut c: u64;
        c = d0 >> 26; h0 = d0 & 0x03ff_ffff;
        let d1 = d1 + c; c = d1 >> 26; h1 = d1 & 0x03ff_ffff;
        let d2 = d2 + c; c = d2 >> 26; h2 = d2 & 0x03ff_ffff;
        let d3 = d3 + c; c = d3 >> 26; h3 = d3 & 0x03ff_ffff;
        let d4 = d4 + c; c = d4 >> 26; h4 = d4 & 0x03ff_ffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x03ff_ffff;
        h1 += c;

        self.h[0] = h0 as u32;
        self.h[1] = h1 as u32;
        self.h[2] = h2 as u32;
        self.h[3] = h3 as u32;
        self.h[4] = h4 as u32;
    }

    fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        // Fill partial buffer first
        if self.buf_len > 0 {
            let space = 16 - self.buf_len;
            let take = if data.len() < space { data.len() } else { space };
            unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), self.buf.as_mut_ptr().add(self.buf_len), take); }
            self.buf_len += take;
            offset = take;
            if self.buf_len == 16 {
                let buf = self.buf;
                self.block(&buf, 1);
                self.buf_len = 0;
            }
        }

        // Process full blocks
        while offset + 16 <= data.len() {
            self.block(&data[offset..offset + 16], 1);
            offset += 16;
        }

        // Buffer remainder
        if offset < data.len() {
            let remain = data.len() - offset;
            unsafe { core::ptr::copy_nonoverlapping(data.as_ptr().add(offset), self.buf.as_mut_ptr(), remain); }
            self.buf_len = remain;
        }
    }

    fn finalize(mut self) -> [u8; 16] {
        // Flush partial buffer
        if self.buf_len > 0 {
            let mut last = [0u8; 16];
            unsafe { core::ptr::copy_nonoverlapping(self.buf.as_ptr(), last.as_mut_ptr(), self.buf_len); }
            last[self.buf_len] = 0x01;
            self.block(&last, 0);
        }

        // Final reduction
        let mut h0 = self.h[0] as u64;
        let mut h1 = self.h[1] as u64;
        let mut h2 = self.h[2] as u64;
        let mut h3 = self.h[3] as u64;
        let mut h4 = self.h[4] as u64;

        let mut c: u64;
        c = h1 >> 26; h1 &= 0x03ff_ffff;
        h2 += c; c = h2 >> 26; h2 &= 0x03ff_ffff;
        h3 += c; c = h3 >> 26; h3 &= 0x03ff_ffff;
        h4 += c; c = h4 >> 26; h4 &= 0x03ff_ffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x03ff_ffff;
        h1 += c;

        // Compute h + -(2^130 - 5)
        let mut g0 = h0.wrapping_add(5); c = g0 >> 26; g0 &= 0x03ff_ffff;
        let mut g1 = h1.wrapping_add(c); c = g1 >> 26; g1 &= 0x03ff_ffff;
        let mut g2 = h2.wrapping_add(c); c = g2 >> 26; g2 &= 0x03ff_ffff;
        let mut g3 = h3.wrapping_add(c); c = g3 >> 26; g3 &= 0x03ff_ffff;
        let mut g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        // Select h or g (constant time)
        let mask = (g4 >> 63).wrapping_sub(1); // 0 if g4 negative, 0xFFFF.. if positive
        g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
        let nmask = !mask;
        h0 = (h0 & nmask) | g0;
        h1 = (h1 & nmask) | g1;
        h2 = (h2 & nmask) | g2;
        h3 = (h3 & nmask) | g3;
        h4 = (h4 & nmask) | g4;

        // Reassemble into 4 x 32-bit (must mask to 32 bits since h[] are u64)
        let f0 = (h0 | (h1 << 26)) & 0xFFFFFFFF;
        let f1 = ((h1 >> 6) | (h2 << 20)) & 0xFFFFFFFF;
        let f2 = ((h2 >> 12) | (h3 << 14)) & 0xFFFFFFFF;
        let f3 = ((h3 >> 18) | (h4 << 8)) & 0xFFFFFFFF;

        // Add pad
        let f0 = f0 + self.pad[0] as u64; let c = f0 >> 32;
        let f1 = f1 + self.pad[1] as u64 + c; let c = f1 >> 32;
        let f2 = f2 + self.pad[2] as u64 + c; let c = f2 >> 32;
        let f3 = f3 + self.pad[3] as u64 + c;

        let mut tag = [0u8; 16];
        let b0 = (f0 as u32).to_le_bytes();
        let b1 = (f1 as u32).to_le_bytes();
        let b2 = (f2 as u32).to_le_bytes();
        let b3 = (f3 as u32).to_le_bytes();
        unsafe {
            core::ptr::copy_nonoverlapping(b0.as_ptr(), tag.as_mut_ptr(), 4);
            core::ptr::copy_nonoverlapping(b1.as_ptr(), tag.as_mut_ptr().add(4), 4);
            core::ptr::copy_nonoverlapping(b2.as_ptr(), tag.as_mut_ptr().add(8), 4);
            core::ptr::copy_nonoverlapping(b3.as_ptr(), tag.as_mut_ptr().add(12), 4);
        }
        tag
    }
}

fn le_bytes_partial(data: &[u8], start: usize) -> u32 {
    let mut val = 0u32;
    let mut i = 0;
    while i < 4 && start + i < data.len() {
        val |= (data[start + i] as u32) << (i * 8);
        i += 1;
    }
    val
}

// ============================================================================
// ChaCha20-Poly1305 AEAD (RFC 8439 Section 2.8)
// ============================================================================

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// Encrypt in-place and produce authentication tag.
/// `data` contains plaintext; on return contains ciphertext.
/// Returns 16-byte tag.
pub fn chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
) -> [u8; 16] {
    // Generate Poly1305 one-time key (counter=0)
    let poly_key_block = chacha20_block(key, 0, nonce);
    let mut poly_key = [0u8; 32];
    unsafe { core::ptr::copy_nonoverlapping(poly_key_block.as_ptr(), poly_key.as_mut_ptr(), 32); }

    // Encrypt plaintext (counter starts at 1)
    chacha20_xor(key, 1, nonce, data);

    // Compute tag over: aad || pad || ciphertext || pad || aad_len(8) || ct_len(8)
    let mut mac = Poly1305::new(&poly_key);
    mac.update(aad);
    // Pad AAD to 16-byte boundary
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    if aad_pad > 0 {
        let zeros = [0u8; 16];
        mac.update(&zeros[..aad_pad]);
    }
    mac.update(data);
    let ct_pad = (16 - (data.len() % 16)) % 16;
    if ct_pad > 0 {
        let zeros = [0u8; 16];
        mac.update(&zeros[..ct_pad]);
    }
    // Lengths (little-endian u64)
    let mut lens = [0u8; 16];
    unsafe {
        let a = (aad.len() as u64).to_le_bytes();
        let d = (data.len() as u64).to_le_bytes();
        core::ptr::copy_nonoverlapping(a.as_ptr(), lens.as_mut_ptr(), 8);
        core::ptr::copy_nonoverlapping(d.as_ptr(), lens.as_mut_ptr().add(8), 8);
    }
    mac.update(&lens);

    mac.finalize()
}

/// Decrypt in-place. Returns true if tag is valid, false otherwise.
/// `data` contains ciphertext; on return contains plaintext (only if valid).
pub fn chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
    tag: &[u8; 16],
) -> bool {
    // Generate Poly1305 one-time key
    let poly_key_block = chacha20_block(key, 0, nonce);
    let mut poly_key = [0u8; 32];
    unsafe { core::ptr::copy_nonoverlapping(poly_key_block.as_ptr(), poly_key.as_mut_ptr(), 32); }

    // Verify tag BEFORE decrypting (ciphertext is what's authenticated)
    let mut mac = Poly1305::new(&poly_key);
    mac.update(aad);
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    if aad_pad > 0 { mac.update(&[0u8; 16][..aad_pad]); }
    mac.update(data);
    let ct_pad = (16 - (data.len() % 16)) % 16;
    if ct_pad > 0 { mac.update(&[0u8; 16][..ct_pad]); }
    let mut lens = [0u8; 16];
    unsafe {
        let a = (aad.len() as u64).to_le_bytes();
        let d = (data.len() as u64).to_le_bytes();
        core::ptr::copy_nonoverlapping(a.as_ptr(), lens.as_mut_ptr(), 8);
        core::ptr::copy_nonoverlapping(d.as_ptr(), lens.as_mut_ptr().add(8), 8);
    }
    mac.update(&lens);

    let computed_tag = mac.finalize();

    // Constant-time comparison
    let mut diff = 0u8;
    let mut i = 0;
    while i < 16 {
        diff |= computed_tag[i] ^ tag[i];
        i += 1;
    }

    if diff != 0 {
        return false;
    }

    // Decrypt
    chacha20_xor(key, 1, nonce, data);
    true
}
