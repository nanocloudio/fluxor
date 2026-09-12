// SHA-256 (FIPS 180-4). Pure Rust, no_std, no heap, no panic path.
//
// The round constants are a static table. A position-independent module
// reaches it PC-relative on every target (`adrp` + page offset on
// aarch64, a PC-relative literal on thumb, a fixed data-segment offset
// on wasm32), so the table needs no relocation and costs nothing per
// block. The module packer keeps module code page-aligned, which is the
// one placement guarantee `adrp` addressing depends on.
//
// Compression runs on the ARMv8 SHA-256 instructions when the compiling
// unit has `target_feature = "sha2"` — the bcm2712 module build passes
// it, as do the aarch64 kernel builds — and on the scalar rounds
// everywhere else. The gate is the feature, not the architecture: an
// aarch64 build without the extension compiles the scalar path rather
// than an instruction the core may not have.
//
// The hasher is incremental and resumable: `update` may be called across
// bounded module steps, and `Clone` snapshots a running hash.

#[rustfmt::skip]
static K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    pub const DIGEST_LEN: usize = 32;
    pub const BLOCK_LEN: usize = 64;

    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        // Top up a partial block first. `buf_len` is below 64 between
        // calls, so `space` is at least 1.
        if self.buf_len > 0 {
            let space = 64 - self.buf_len;
            let take = if data.len() < space {
                data.len()
            } else {
                space
            };
            // SAFETY: `take <= space = 64 - buf_len`, so the destination
            // range stays inside `buf`; `take <= data.len()` bounds the
            // source; the two buffers are distinct allocations.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    self.buf.as_mut_ptr().add(self.buf_len),
                    take,
                );
            }
            self.buf_len += take;
            offset = take;

            if self.buf_len == 64 {
                let block = self.buf;
                compress(&mut self.state, &block);
                self.buf_len = 0;
            }
        }

        // Whole blocks straight from the input.
        while offset + 64 <= data.len() {
            let mut block = [0u8; 64];
            // SAFETY: `offset + 64 <= data.len()` bounds the source; the
            // destination is a fresh 64-byte stack array.
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr().add(offset), block.as_mut_ptr(), 64);
            }
            compress(&mut self.state, &block);
            offset += 64;
        }

        // Hold the tail, which is shorter than a block.
        let remain = data.len() - offset;
        if remain > 0 {
            // SAFETY: `remain < 64` fits `buf`, which is empty here;
            // `offset + remain == data.len()` bounds the source.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data.as_ptr().add(offset),
                    self.buf.as_mut_ptr(),
                    remain,
                );
            }
            self.buf_len = remain;
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);

        // Padding: a 1 bit, zeros to 56 mod 64, then the bit length.
        // `buf_len < 64` on entry, so the marker always fits.
        let p = self.buf.as_mut_ptr();
        // SAFETY: `buf_len < 64` keeps the write inside `buf`.
        unsafe {
            *p.add(self.buf_len) = 0x80;
        }
        self.buf_len += 1;

        if self.buf_len > 56 {
            // SAFETY: zeroes `buf[buf_len..64]`, inside `buf`.
            unsafe {
                let n = 64 - self.buf_len;
                for i in 0..n {
                    *p.add(self.buf_len + i) = 0;
                }
            }
            let block = self.buf;
            compress(&mut self.state, &block);
            self.buf_len = 0;
        }

        // SAFETY: zeroes `buf[buf_len..56]`; `buf_len <= 56` here.
        unsafe {
            let n = 56 - self.buf_len;
            for i in 0..n {
                *p.add(self.buf_len + i) = 0;
            }
        }

        let len_bytes = bit_len.to_be_bytes();
        // SAFETY: writes `buf[56..64]` from an 8-byte source.
        unsafe {
            core::ptr::copy_nonoverlapping(len_bytes.as_ptr(), p.add(56), 8);
        }
        let block = self.buf;
        compress(&mut self.state, &block);

        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 8 {
            let bytes = self.state[i].to_be_bytes();
            out[i * 4] = bytes[0];
            out[i * 4 + 1] = bytes[1];
            out[i * 4 + 2] = bytes[2];
            out[i * 4 + 3] = bytes[3];
            i += 1;
        }
        out
    }

    /// Finalize and write digest into caller-provided buffer.
    pub fn finalize_into(self, out: &mut [u8; 32]) {
        *out = self.finalize();
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sha2"))]
fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    // SAFETY: this arm exists only when the unit is compiled with the
    // `sha2` feature, so the core the build targets has the
    // instructions `compress_sha2` is specialised on.
    unsafe { compress_sha2(state, block) }
}

// The attribute is what lets the intrinsics be called as plain
// instructions. What stays unsafe inside is the raw-pointer traffic,
// bounded as noted at each use.
#[cfg(all(target_arch = "aarch64", target_feature = "sha2"))]
#[target_feature(enable = "sha2,neon")]
unsafe fn compress_sha2(state: &mut [u32; 8], block: &[u8; 64]) {
    use core::arch::aarch64::{
        uint32x4_t, vaddq_u32, vld1q_u32, vld1q_u8, vreinterpretq_u32_u8, vrev32q_u8,
        vsha256h2q_u32, vsha256hq_u32, vsha256su0q_u32, vsha256su1q_u32, vst1q_u32,
    };

    let kp = K256.as_ptr();
    // SAFETY: `i < 16`, so `i * 4 + 3 < 64` stays inside `K256`.
    let kv = |i: usize| unsafe { vld1q_u32(kp.add(i * 4)) };

    let sp = state.as_ptr();
    // SAFETY: two 4-lane loads cover exactly the 8 words of `state`.
    let (mut abcd, mut efgh): (uint32x4_t, uint32x4_t) =
        unsafe { (vld1q_u32(sp), vld1q_u32(sp.add(4))) };
    let abcd_save = abcd;
    let efgh_save = efgh;

    // The schedule is big-endian; `vrev32q_u8` swaps within each lane.
    let bp = block.as_ptr();
    let load_be = |off: usize| -> uint32x4_t {
        // SAFETY: `off` is one of 0, 16, 32, 48, so `off + 15 < 64`.
        let v = unsafe { vld1q_u8(bp.add(off)) };
        vreinterpretq_u32_u8(vrev32q_u8(v))
    };
    let mut w0 = load_be(0);
    let mut w1 = load_be(16);
    let mut w2 = load_be(32);
    let mut w3 = load_be(48);

    // 16 quarter-rounds of 4 rounds each. Every iteration runs the two
    // hash instructions and extends the schedule for the window four
    // rounds ahead, until the last three windows need no extension.
    let mut prev: uint32x4_t;

    // Rounds 0-3
    let mut msg = vaddq_u32(w0, kv(0));
    prev = abcd;
    abcd = vsha256hq_u32(abcd, efgh, msg);
    efgh = vsha256h2q_u32(efgh, prev, msg);

    // Rounds 4-7
    msg = vaddq_u32(w1, kv(1));
    prev = abcd;
    abcd = vsha256hq_u32(abcd, efgh, msg);
    efgh = vsha256h2q_u32(efgh, prev, msg);
    w0 = vsha256su0q_u32(w0, w1);

    // Rounds 8-11
    msg = vaddq_u32(w2, kv(2));
    prev = abcd;
    abcd = vsha256hq_u32(abcd, efgh, msg);
    efgh = vsha256h2q_u32(efgh, prev, msg);
    w0 = vsha256su1q_u32(w0, w2, w3);
    w1 = vsha256su0q_u32(w1, w2);

    // Rounds 12-15
    msg = vaddq_u32(w3, kv(3));
    prev = abcd;
    abcd = vsha256hq_u32(abcd, efgh, msg);
    efgh = vsha256h2q_u32(efgh, prev, msg);
    w1 = vsha256su1q_u32(w1, w3, w0);
    w2 = vsha256su0q_u32(w2, w3);

    // Rounds 16-19
    msg = vaddq_u32(w0, kv(4));
    prev = abcd;
    abcd = vsha256hq_u32(abcd, efgh, msg);
    efgh = vsha256h2q_u32(efgh, prev, msg);
    w2 = vsha256su1q_u32(w2, w0, w1);
    w3 = vsha256su0q_u32(w3, w0);

    // Rounds 20-23
    msg = vaddq_u32(w1, kv(5));
    prev = abcd;
    abcd = vsha256hq_u32(abcd, efgh, msg);
    efgh = vsha256h2q_u32(efgh, prev, msg);
    w3 = vsha256su1q_u32(w3, w1, w2);
    w0 = vsha256su0q_u32(w0, w1);

    // Rounds 24-27
    msg = vaddq_u32(w2, kv(6));
    prev = abcd;
    abcd = vsha256hq_u32(abcd, efgh, msg);
    efgh = vsha256h2q_u32(efgh, prev, msg);
    w0 = vsha256su1q_u32(w0, w2, w3);
    w1 = vsha256su0q_u32(w1, w2);

    // Rounds 28-31
    msg = vaddq_u32(w3, kv(7));
    prev = abcd;
    abcd = vsha256hq_u32(abcd, efgh, msg);
    efgh = vsha256h2q_u32(efgh, prev, msg);
    w1 = vsha256su1q_u32(w1, w3, w0);
    w2 = vsha256su0q_u32(w2, w3);

    // Rounds 32-35
    msg = vaddq_u32(w0, kv(8));
    prev = abcd;
    abcd = vsha256hq_u32(abcd, efgh, msg);
    efgh = vsha256h2q_u32(efgh, prev, msg);
    w2 = vsha256su1q_u32(w2, w0, w1);
    w3 = vsha256su0q_u32(w3, w0);

    // Rounds 36-39
    msg = vaddq_u32(w1, kv(9));
    prev = abcd;
    abcd = vsha256hq_u32(abcd, efgh, msg);
    efgh = vsha256h2q_u32(efgh, prev, msg);
    w3 = vsha256su1q_u32(w3, w1, w2);
    w0 = vsha256su0q_u32(w0, w1);

    // Rounds 40-43
    msg = vaddq_u32(w2, kv(10));
    prev = abcd;
    abcd = vsha256hq_u32(abcd, efgh, msg);
    efgh = vsha256h2q_u32(efgh, prev, msg);
    w0 = vsha256su1q_u32(w0, w2, w3);
    w1 = vsha256su0q_u32(w1, w2);

    // Rounds 44-47
    msg = vaddq_u32(w3, kv(11));
    prev = abcd;
    abcd = vsha256hq_u32(abcd, efgh, msg);
    efgh = vsha256h2q_u32(efgh, prev, msg);
    w1 = vsha256su1q_u32(w1, w3, w0);
    w2 = vsha256su0q_u32(w2, w3);

    // Rounds 48-51
    msg = vaddq_u32(w0, kv(12));
    prev = abcd;
    abcd = vsha256hq_u32(abcd, efgh, msg);
    efgh = vsha256h2q_u32(efgh, prev, msg);
    w2 = vsha256su1q_u32(w2, w0, w1);
    w3 = vsha256su0q_u32(w3, w0);

    // Rounds 52-55
    msg = vaddq_u32(w1, kv(13));
    prev = abcd;
    abcd = vsha256hq_u32(abcd, efgh, msg);
    efgh = vsha256h2q_u32(efgh, prev, msg);
    w3 = vsha256su1q_u32(w3, w1, w2);

    // Rounds 56-59
    msg = vaddq_u32(w2, kv(14));
    prev = abcd;
    abcd = vsha256hq_u32(abcd, efgh, msg);
    efgh = vsha256h2q_u32(efgh, prev, msg);

    // Rounds 60-63
    msg = vaddq_u32(w3, kv(15));
    prev = abcd;
    abcd = vsha256hq_u32(abcd, efgh, msg);
    efgh = vsha256h2q_u32(efgh, prev, msg);

    abcd = vaddq_u32(abcd, abcd_save);
    efgh = vaddq_u32(efgh, efgh_save);
    let smp = state.as_mut_ptr();
    // SAFETY: two 4-lane stores cover exactly the 8 words of `state`.
    unsafe {
        vst1q_u32(smp, abcd);
        vst1q_u32(smp.add(4), efgh);
    }
}

#[cfg(not(all(target_arch = "aarch64", target_feature = "sha2")))]
fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];

    // Message schedule, big-endian words.
    let mut i = 0;
    let bp = block.as_ptr();
    let wp = w.as_mut_ptr();
    while i < 16 {
        // SAFETY: `i < 16`, so `i * 4 + 3 < 64` reads inside `block`
        // and `i < 64` writes inside `w`.
        unsafe {
            let off = i * 4;
            let b0 = *bp.add(off) as u32;
            let b1 = *bp.add(off + 1) as u32;
            let b2 = *bp.add(off + 2) as u32;
            let b3 = *bp.add(off + 3) as u32;
            *wp.add(i) = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
        }
        i += 1;
    }

    while i < 64 {
        // SAFETY: `16 <= i < 64`, so every index `i - 16 ..= i` is
        // inside `w`.
        unsafe {
            let w15 = *wp.add(i - 15);
            let w2 = *wp.add(i - 2);
            let w16 = *wp.add(i - 16);
            let w7 = *wp.add(i - 7);
            let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
            let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
            *wp.add(i) = w16.wrapping_add(s0).wrapping_add(w7).wrapping_add(s1);
        }
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

    let kp = K256.as_ptr();
    i = 0;
    while i < 64 {
        // SAFETY: `i < 64` indexes inside both `K256` and `w`.
        let (ki, wi) = unsafe { (*kp.add(i), *wp.add(i)) };
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(ki)
            .wrapping_add(wi);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
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

/// Compute SHA-256 hash of data in one shot.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}
