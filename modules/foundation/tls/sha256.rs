// SHA-256 implementation (FIPS 180-4)
// Pure Rust, no_std, no heap. Round constants are materialised on the stack
// via per-word volatile stores; PIC aarch64 modules cannot rely on
// ADRP-based loads from .rodata for a `const [u32; 64]` array.

/// Load SHA-256 round constants into a stack buffer via per-word volatile
/// writes. Each store goes through `k256_store` (`#[inline(never)]`) so
/// LLVM cannot batch them into a NEON literal-pool load.
#[inline(never)]
fn load_k256() -> [u32; 64] {
    let mut k = [0u32; 64];
    unsafe {
        let p = k.as_mut_ptr();
        k256_store(p,  0, 0x428a2f98); k256_store(p,  1, 0x71374491);
        k256_store(p,  2, 0xb5c0fbcf); k256_store(p,  3, 0xe9b5dba5);
        k256_store(p,  4, 0x3956c25b); k256_store(p,  5, 0x59f111f1);
        k256_store(p,  6, 0x923f82a4); k256_store(p,  7, 0xab1c5ed5);
        k256_store(p,  8, 0xd807aa98); k256_store(p,  9, 0x12835b01);
        k256_store(p, 10, 0x243185be); k256_store(p, 11, 0x550c7dc3);
        k256_store(p, 12, 0x72be5d74); k256_store(p, 13, 0x80deb1fe);
        k256_store(p, 14, 0x9bdc06a7); k256_store(p, 15, 0xc19bf174);
        k256_store(p, 16, 0xe49b69c1); k256_store(p, 17, 0xefbe4786);
        k256_store(p, 18, 0x0fc19dc6); k256_store(p, 19, 0x240ca1cc);
        k256_store(p, 20, 0x2de92c6f); k256_store(p, 21, 0x4a7484aa);
        k256_store(p, 22, 0x5cb0a9dc); k256_store(p, 23, 0x76f988da);
        k256_store(p, 24, 0x983e5152); k256_store(p, 25, 0xa831c66d);
        k256_store(p, 26, 0xb00327c8); k256_store(p, 27, 0xbf597fc7);
        k256_store(p, 28, 0xc6e00bf3); k256_store(p, 29, 0xd5a79147);
        k256_store(p, 30, 0x06ca6351); k256_store(p, 31, 0x14292967);
        k256_store(p, 32, 0x27b70a85); k256_store(p, 33, 0x2e1b2138);
        k256_store(p, 34, 0x4d2c6dfc); k256_store(p, 35, 0x53380d13);
        k256_store(p, 36, 0x650a7354); k256_store(p, 37, 0x766a0abb);
        k256_store(p, 38, 0x81c2c92e); k256_store(p, 39, 0x92722c85);
        k256_store(p, 40, 0xa2bfe8a1); k256_store(p, 41, 0xa81a664b);
        k256_store(p, 42, 0xc24b8b70); k256_store(p, 43, 0xc76c51a3);
        k256_store(p, 44, 0xd192e819); k256_store(p, 45, 0xd6990624);
        k256_store(p, 46, 0xf40e3585); k256_store(p, 47, 0x106aa070);
        k256_store(p, 48, 0x19a4c116); k256_store(p, 49, 0x1e376c08);
        k256_store(p, 50, 0x2748774c); k256_store(p, 51, 0x34b0bcb5);
        k256_store(p, 52, 0x391c0cb3); k256_store(p, 53, 0x4ed8aa4a);
        k256_store(p, 54, 0x5b9cca4f); k256_store(p, 55, 0x682e6ff3);
        k256_store(p, 56, 0x748f82ee); k256_store(p, 57, 0x78a5636f);
        k256_store(p, 58, 0x84c87814); k256_store(p, 59, 0x8cc70208);
        k256_store(p, 60, 0x90befffa); k256_store(p, 61, 0xa4506ceb);
        k256_store(p, 62, 0xbef9a3f7); k256_store(p, 63, 0xc67178f2);
    }
    k
}

/// Single u32 volatile store. `#[inline(never)]` keeps LLVM from batching
/// adjacent stores into a NEON literal load.
#[inline(never)]
unsafe fn k256_store(base: *mut u32, idx: usize, val: u32) {
    core::ptr::write_volatile(base.add(idx), val);
}

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
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        self.total_len += data.len() as u64;

        // Fill buffer if partially full
        if self.buf_len > 0 {
            let space = 64 - self.buf_len;
            let take = if data.len() < space { data.len() } else { space };
            let dst = self.buf.as_mut_ptr();
            let src = data.as_ptr();
            unsafe {
                core::ptr::copy_nonoverlapping(src, dst.add(self.buf_len), take);
            }
            self.buf_len += take;
            offset = take;

            if self.buf_len == 64 {
                let block = self.buf;
                compress(&mut self.state, &block);
                self.buf_len = 0;
            }
        }

        // Process full blocks
        while offset + 64 <= data.len() {
            let mut block = [0u8; 64];
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr().add(offset), block.as_mut_ptr(), 64);
            }
            compress(&mut self.state, &block);
            offset += 64;
        }

        // Buffer remainder
        let remain = data.len() - offset;
        if remain > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr().add(offset), self.buf.as_mut_ptr(), remain);
            }
            self.buf_len = remain;
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len * 8;

        // Padding
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            // Zero rest of current block
            let dst = self.buf.as_mut_ptr();
            unsafe {
                let p = dst.add(self.buf_len);
                let n = 64 - self.buf_len;
                for i in 0..n { core::ptr::write_volatile(p.add(i), 0); }
            }
            let block = self.buf;
            compress(&mut self.state, &block);
            self.buf_len = 0;
        }

        // Zero up to length field
        unsafe {
            let p = self.buf.as_mut_ptr().add(self.buf_len);
            let n = 56 - self.buf_len;
            for i in 0..n { core::ptr::write_volatile(p.add(i), 0); }
        }

        // Append bit length (big-endian)
        let len_bytes = bit_len.to_be_bytes();
        unsafe {
            core::ptr::copy_nonoverlapping(len_bytes.as_ptr(), self.buf.as_mut_ptr().add(56), 8);
        }
        let block = self.buf;
        compress(&mut self.state, &block);

        // Output
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

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let k = load_k256();
    let mut w = [0u32; 64];

    // Load message schedule via pointer arithmetic (no bounds checks).
    let mut i = 0;
    let bp = block.as_ptr();
    let wp = w.as_mut_ptr();
    while i < 16 {
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

    // Extend.
    while i < 64 {
        unsafe {
            let w15 = *wp.add(i - 15);
            let w2  = *wp.add(i - 2);
            let w16 = *wp.add(i - 16);
            let w7  = *wp.add(i - 7);
            let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
            let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
            *wp.add(i) = w16.wrapping_add(s0).wrapping_add(w7).wrapping_add(s1);
        }
        i += 1;
    }

    let sp = state.as_ptr();
    let mut a = unsafe { *sp.add(0) };
    let mut b = unsafe { *sp.add(1) };
    let mut c = unsafe { *sp.add(2) };
    let mut d = unsafe { *sp.add(3) };
    let mut e = unsafe { *sp.add(4) };
    let mut f = unsafe { *sp.add(5) };
    let mut g = unsafe { *sp.add(6) };
    let mut h = unsafe { *sp.add(7) };

    let kp = k.as_ptr();
    i = 0;
    while i < 64 {
        let ki = unsafe { *kp.add(i) };
        let wi = unsafe { *wp.add(i) };
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(ki).wrapping_add(wi);
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

    let smp = state.as_mut_ptr();
    unsafe {
        *smp.add(0) = (*smp.add(0)).wrapping_add(a);
        *smp.add(1) = (*smp.add(1)).wrapping_add(b);
        *smp.add(2) = (*smp.add(2)).wrapping_add(c);
        *smp.add(3) = (*smp.add(3)).wrapping_add(d);
        *smp.add(4) = (*smp.add(4)).wrapping_add(e);
        *smp.add(5) = (*smp.add(5)).wrapping_add(f);
        *smp.add(6) = (*smp.add(6)).wrapping_add(g);
        *smp.add(7) = (*smp.add(7)).wrapping_add(h);
    }
}

/// Compute SHA-256 hash of data in one shot.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}
