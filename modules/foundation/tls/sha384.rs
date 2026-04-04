// SHA-384 implementation (truncated SHA-512, FIPS 180-4)
// Pure Rust, no_std, no heap

const K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

#[derive(Clone)]
pub struct Sha384 {
    state: [u64; 8],
    buf: [u8; 128],
    buf_len: usize,
    total_len: u64,
}

impl Sha384 {
    pub const DIGEST_LEN: usize = 48;
    pub const BLOCK_LEN: usize = 128;

    pub const fn new() -> Self {
        Self {
            state: [
                0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
                0x9159015a3070dd17, 0x152fecd8f70e5939,
                0x67332667ffc00b31, 0x8eb44a8768581511,
                0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
            ],
            buf: [0u8; 128],
            buf_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        self.total_len += data.len() as u64;

        if self.buf_len > 0 {
            let space = 128 - self.buf_len;
            let take = if data.len() < space { data.len() } else { space };
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), self.buf.as_mut_ptr().add(self.buf_len), take);
            }
            self.buf_len += take;
            offset = take;

            if self.buf_len == 128 {
                let block = self.buf;
                compress512(&mut self.state, &block);
                self.buf_len = 0;
            }
        }

        while offset + 128 <= data.len() {
            let mut block = [0u8; 128];
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr().add(offset), block.as_mut_ptr(), 128);
            }
            compress512(&mut self.state, &block);
            offset += 128;
        }

        let remain = data.len() - offset;
        if remain > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr().add(offset), self.buf.as_mut_ptr(), remain);
            }
            self.buf_len = remain;
        }
    }

    pub fn finalize(mut self) -> [u8; 48] {
        let bit_len = (self.total_len as u128) * 8;

        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 112 {
            unsafe {
                let p = self.buf.as_mut_ptr().add(self.buf_len);
                for i in 0..(128 - self.buf_len) { core::ptr::write_volatile(p.add(i), 0); }
            }
            let block = self.buf;
            compress512(&mut self.state, &block);
            self.buf_len = 0;
        }

        unsafe {
            let p = self.buf.as_mut_ptr().add(self.buf_len);
            for i in 0..(112 - self.buf_len) { core::ptr::write_volatile(p.add(i), 0); }
        }

        // Append 128-bit length (big-endian) — high 64 bits are 0 for our sizes
        let len_hi = (bit_len >> 64) as u64;
        let len_lo = bit_len as u64;
        unsafe {
            core::ptr::copy_nonoverlapping(len_hi.to_be_bytes().as_ptr(), self.buf.as_mut_ptr().add(112), 8);
            core::ptr::copy_nonoverlapping(len_lo.to_be_bytes().as_ptr(), self.buf.as_mut_ptr().add(120), 8);
        }
        let block = self.buf;
        compress512(&mut self.state, &block);

        // SHA-384 = first 48 bytes (6 words) of SHA-512
        let mut out = [0u8; 48];
        let mut i = 0;
        while i < 6 {
            let bytes = self.state[i].to_be_bytes();
            let base = i * 8;
            out[base] = bytes[0]; out[base + 1] = bytes[1];
            out[base + 2] = bytes[2]; out[base + 3] = bytes[3];
            out[base + 4] = bytes[4]; out[base + 5] = bytes[5];
            out[base + 6] = bytes[6]; out[base + 7] = bytes[7];
            i += 1;
        }
        out
    }

    pub fn finalize_into(self, out: &mut [u8; 48]) {
        *out = self.finalize();
    }
}

fn compress512(state: &mut [u64; 8], block: &[u8; 128]) {
    let mut w = [0u64; 80];

    let mut i = 0;
    while i < 16 {
        w[i] = u64::from_be_bytes([
            block[i * 8], block[i * 8 + 1], block[i * 8 + 2], block[i * 8 + 3],
            block[i * 8 + 4], block[i * 8 + 5], block[i * 8 + 6], block[i * 8 + 7],
        ]);
        i += 1;
    }

    while i < 80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        i += 1;
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    i = 0;
    while i < 80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K512[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g; g = f; f = e;
        e = d.wrapping_add(temp1);
        d = c; c = b; b = a;
        a = temp1.wrapping_add(temp2);
        i += 1;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[allow(dead_code)]
pub fn sha384(data: &[u8]) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update(data);
    h.finalize()
}
