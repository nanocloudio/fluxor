//! SHA-512 and Ed25519 sign+verify for the `fluxor sign` subcommand.
//!
//! Pure Rust, no external crypto dependencies. Ed25519 arithmetic is ported
//! from TweetNaCl (public domain); the kernel loader runs the same verify
//! path against signatures produced here.

#![allow(clippy::needless_range_loop, dead_code)]

// ============================================================================
// SHA-512 (FIPS 180-4 §6.4).
// ============================================================================

const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

const H0: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

pub struct Sha512 {
    h: [u64; 8],
    buf: [u8; 128],
    buf_len: usize,
    bit_len: u128,
}

impl Sha512 {
    pub fn new() -> Self {
        Self {
            h: H0,
            buf: [0; 128],
            buf_len: 0,
            bit_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.bit_len = self.bit_len.wrapping_add((data.len() as u128) << 3);
        if self.buf_len > 0 {
            let take = core::cmp::min(128 - self.buf_len, data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 128 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 128 {
            let mut block = [0u8; 128];
            block.copy_from_slice(&data[..128]);
            self.compress(&block);
            data = &data[128..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 64] {
        let bit_len = self.bit_len;
        let pad_start = self.buf_len;
        self.buf[pad_start] = 0x80;
        if pad_start + 1 > 112 {
            for i in (pad_start + 1)..128 {
                self.buf[i] = 0;
            }
            let block = self.buf;
            self.compress(&block);
            self.buf = [0; 128];
        } else {
            for i in (pad_start + 1)..112 {
                self.buf[i] = 0;
            }
        }
        self.buf[112..128].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buf;
        self.compress(&block);
        let mut out = [0u8; 64];
        for (i, w) in self.h.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 128]) {
        #[inline]
        fn ch(x: u64, y: u64, z: u64) -> u64 {
            (x & y) ^ (!x & z)
        }
        #[inline]
        fn maj(x: u64, y: u64, z: u64) -> u64 {
            (x & y) ^ (x & z) ^ (y & z)
        }
        #[inline]
        fn big_s0(x: u64) -> u64 {
            x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
        }
        #[inline]
        fn big_s1(x: u64) -> u64 {
            x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
        }
        #[inline]
        fn small_s0(x: u64) -> u64 {
            x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
        }
        #[inline]
        fn small_s1(x: u64) -> u64 {
            x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
        }

        let mut w = [0u64; 80];
        for i in 0..16 {
            let off = i * 8;
            w[i] = u64::from_be_bytes([
                block[off],
                block[off + 1],
                block[off + 2],
                block[off + 3],
                block[off + 4],
                block[off + 5],
                block[off + 6],
                block[off + 7],
            ]);
        }
        for i in 16..80 {
            w[i] = small_s1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(small_s0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];
        for i in 0..80 {
            let t1 = h
                .wrapping_add(big_s1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let t2 = big_s0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }
}

pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

// ============================================================================
// Ed25519 (ported from TweetNaCl, public domain).
// ============================================================================

type Gf = [i64; 16];

const GF0: Gf = [0; 16];
const GF1: Gf = {
    let mut g = [0i64; 16];
    g[0] = 1;
    g
};

const D2: Gf = [
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e,
    0xfce7, 0x56df, 0xd9dc, 0x2406,
];
const D: Gf = [
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7,
    0xfe73, 0x2b6f, 0x6cee, 0x5203,
];
const SQRT_M1: Gf = [
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
    0xdf0b, 0x4fc1, 0x2480, 0x2b83,
];
const BX: Gf = [
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
    0x53fe, 0xcd6e, 0x36d3, 0x2169,
];
const BY: Gf = [
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666,
];

fn set(r: &mut Gf, a: &Gf) {
    r.copy_from_slice(a);
}

fn car25519(o: &mut Gf) {
    for i in 0..16 {
        o[i] = o[i].wrapping_add(1i64 << 16);
        let c = o[i] >> 16;
        if i < 15 {
            o[i + 1] = o[i + 1].wrapping_add(c - 1);
        } else {
            o[0] = o[0].wrapping_add(38 * (c - 1));
        }
        o[i] = o[i].wrapping_sub(c << 16);
    }
}

fn sel25519(p: &mut Gf, q: &mut Gf, b: i64) {
    let c = !(b - 1);
    for i in 0..16 {
        let t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

fn pack25519(o: &mut [u8; 32], n: &Gf) {
    let mut t: Gf = [0; 16];
    set(&mut t, n);
    car25519(&mut t);
    car25519(&mut t);
    car25519(&mut t);
    for _ in 0..2 {
        let mut m: Gf = [0; 16];
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        let b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel25519(&mut t, &mut m, 1 - b);
    }
    for i in 0..16 {
        o[2 * i] = (t[i] & 0xff) as u8;
        o[2 * i + 1] = ((t[i] >> 8) & 0xff) as u8;
    }
}

fn neq25519(a: &Gf, b: &Gf) -> bool {
    let mut c = [0u8; 32];
    let mut d = [0u8; 32];
    pack25519(&mut c, a);
    pack25519(&mut d, b);
    c != d
}

fn par25519(a: &Gf) -> u8 {
    let mut d = [0u8; 32];
    pack25519(&mut d, a);
    d[0] & 1
}

fn unpack25519(o: &mut Gf, n: &[u8; 32]) {
    for i in 0..16 {
        o[i] = (n[2 * i] as i64) + ((n[2 * i + 1] as i64) << 8);
    }
    o[15] &= 0x7fff;
}

fn gf_a(o: &mut Gf, a: &Gf, b: &Gf) {
    for i in 0..16 {
        o[i] = a[i] + b[i];
    }
}
fn gf_z(o: &mut Gf, a: &Gf, b: &Gf) {
    for i in 0..16 {
        o[i] = a[i] - b[i];
    }
}

fn gf_m(o: &mut Gf, a: &Gf, b: &Gf) {
    let mut t: [i64; 31] = [0; 31];
    for i in 0..16 {
        for j in 0..16 {
            t[i + j] += a[i] * b[j];
        }
    }
    for i in 0..15 {
        t[i] += 38 * t[i + 16];
    }
    o.copy_from_slice(&t[..16]);
    car25519(o);
    car25519(o);
}

fn gf_s(o: &mut Gf, a: &Gf) {
    let ac = *a;
    gf_m(o, &ac, &ac);
}

fn inv25519(o: &mut Gf, i: &Gf) {
    let mut c: Gf = *i;
    for a in (0..=253i32).rev() {
        let c_copy = c;
        gf_s(&mut c, &c_copy);
        if a != 2 && a != 4 {
            let c_copy = c;
            gf_m(&mut c, &c_copy, i);
        }
    }
    *o = c;
}

fn pow2523(o: &mut Gf, i: &Gf) {
    let mut c: Gf = *i;
    for a in (0..=250i32).rev() {
        let c_copy = c;
        gf_s(&mut c, &c_copy);
        if a != 1 {
            let c_copy = c;
            gf_m(&mut c, &c_copy, i);
        }
    }
    *o = c;
}

type Point = [Gf; 4];

fn point_add(p: &mut Point, q: &Point) {
    let mut a: Gf = [0; 16];
    let mut b: Gf = [0; 16];
    let mut c: Gf = [0; 16];
    let mut d: Gf = [0; 16];
    let mut t: Gf = [0; 16];
    let mut e: Gf = [0; 16];
    let mut f: Gf = [0; 16];
    let mut g: Gf = [0; 16];
    let mut h: Gf = [0; 16];
    gf_z(&mut a, &p[1], &p[0]);
    gf_z(&mut t, &q[1], &q[0]);
    let ac = a;
    gf_m(&mut a, &ac, &t);
    gf_a(&mut b, &p[0], &p[1]);
    gf_a(&mut t, &q[0], &q[1]);
    let bc = b;
    gf_m(&mut b, &bc, &t);
    gf_m(&mut c, &p[3], &q[3]);
    let cc = c;
    gf_m(&mut c, &cc, &D2);
    gf_m(&mut d, &p[2], &q[2]);
    let dc = d;
    gf_a(&mut d, &dc, &dc);
    gf_z(&mut e, &b, &a);
    gf_z(&mut f, &d, &c);
    gf_a(&mut g, &d, &c);
    gf_a(&mut h, &b, &a);
    gf_m(&mut p[0], &e, &f);
    gf_m(&mut p[1], &h, &g);
    gf_m(&mut p[2], &g, &f);
    gf_m(&mut p[3], &e, &h);
}

fn cswap(p: &mut Point, q: &mut Point, b: u8) {
    let bi = b as i64;
    for i in 0..4 {
        sel25519(&mut p[i], &mut q[i], bi);
    }
}

fn pack_point(r: &mut [u8; 32], p: &Point) {
    let mut zi: Gf = [0; 16];
    let mut tx: Gf = [0; 16];
    let mut ty: Gf = [0; 16];
    inv25519(&mut zi, &p[2]);
    gf_m(&mut tx, &p[0], &zi);
    gf_m(&mut ty, &p[1], &zi);
    pack25519(r, &ty);
    r[31] ^= par25519(&tx) << 7;
}

fn scalarmult(p: &mut Point, q_in: &Point, s: &[u8; 32]) {
    p[0] = GF0;
    p[1] = GF1;
    p[2] = GF1;
    p[3] = GF0;
    let mut q: Point = *q_in;
    for i in (0..=255).rev() {
        let b = (s[i / 8] >> (i & 7)) & 1;
        cswap(p, &mut q, b);
        point_add(&mut q, p);
        let pc = *p;
        point_add(p, &pc);
        cswap(p, &mut q, b);
    }
}

fn scalarbase(p: &mut Point, s: &[u8; 32]) {
    let mut q: Point = [GF0; 4];
    set(&mut q[0], &BX);
    set(&mut q[1], &BY);
    set(&mut q[2], &GF1);
    gf_m(&mut q[3], &BX, &BY);
    scalarmult(p, &q, s);
}

fn unpack_neg(r: &mut Point, p: &[u8; 32]) -> bool {
    let mut t: Gf = [0; 16];
    let mut chk: Gf = [0; 16];
    let mut num: Gf = [0; 16];
    let mut den: Gf = [0; 16];
    let mut den2: Gf = [0; 16];
    let mut den4: Gf = [0; 16];
    let mut den6: Gf = [0; 16];
    set(&mut r[2], &GF1);
    unpack25519(&mut r[1], p);
    gf_s(&mut num, &r[1]);
    gf_m(&mut den, &num, &D);
    let nc = num;
    gf_z(&mut num, &nc, &r[2]);
    let dc = den;
    gf_a(&mut den, &r[2], &dc);
    gf_s(&mut den2, &den);
    gf_s(&mut den4, &den2);
    gf_m(&mut den6, &den4, &den2);
    gf_m(&mut t, &den6, &num);
    let tc = t;
    gf_m(&mut t, &tc, &den);
    let tc = t;
    pow2523(&mut t, &tc);
    let tc = t;
    gf_m(&mut t, &tc, &num);
    let tc = t;
    gf_m(&mut t, &tc, &den);
    let tc = t;
    gf_m(&mut t, &tc, &den);
    gf_m(&mut r[0], &t, &den);
    gf_s(&mut chk, &r[0]);
    let cc = chk;
    gf_m(&mut chk, &cc, &den);
    if neq25519(&chk, &num) {
        let r0c = r[0];
        gf_m(&mut r[0], &r0c, &SQRT_M1);
    }
    gf_s(&mut chk, &r[0]);
    let cc = chk;
    gf_m(&mut chk, &cc, &den);
    if neq25519(&chk, &num) {
        return false;
    }
    if par25519(&r[0]) == (p[31] >> 7) {
        let r0c = r[0];
        gf_z(&mut r[0], &GF0, &r0c);
    }
    let r0c = r[0];
    let r1c = r[1];
    gf_m(&mut r[3], &r0c, &r1c);
    true
}

const L: [i64; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

fn mod_l(r: &mut [u8; 32], x: &mut [i64; 64]) {
    for i in (32..=63).rev() {
        let mut carry: i64 = 0;
        let mut j = i - 32;
        while j < i - 12 {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
            j += 1;
        }
        x[j] += carry;
        x[i] = 0;
    }
    let mut carry: i64 = 0;
    for j in 0..32 {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for j in 0..32 {
        x[j] -= carry * L[j];
    }
    for i in 0..32 {
        x[i + 1] += x[i] >> 8;
        r[i] = (x[i] & 255) as u8;
    }
}

fn reduce(r: &mut [u8; 64]) -> [u8; 32] {
    let mut x: [i64; 64] = [0; 64];
    for i in 0..64 {
        x[i] = r[i] as i64;
    }
    let mut out = [0u8; 32];
    mod_l(&mut out, &mut x);
    out
}

pub fn verify(public_key: &[u8; 32], msg: &[u8], signature: &[u8; 64]) -> bool {
    let mut q: Point = [GF0; 4];
    if !unpack_neg(&mut q, public_key) {
        return false;
    }
    let mut hasher = Sha512::new();
    hasher.update(&signature[..32]);
    hasher.update(public_key);
    hasher.update(msg);
    let mut h = hasher.finalize();
    let h_reduced = reduce(&mut h);
    let mut p: Point = [GF0; 4];
    scalarmult(&mut p, &q, &h_reduced);
    let mut sb: Point = [GF0; 4];
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);
    scalarbase(&mut sb, &s_bytes);
    point_add(&mut p, &sb);
    let mut t = [0u8; 32];
    pack_point(&mut t, &p);
    let mut r = [0u8; 32];
    r.copy_from_slice(&signature[..32]);
    t == r
}

/// Derive the compressed Ed25519 public key from a 32-byte seed.
pub fn derive_public_key(seed: &[u8; 32]) -> [u8; 32] {
    // RFC 8032 §5.1.5: h = SHA-512(seed); a = clamp(h[0..32])
    let h = sha512(seed);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[..32]);
    // Clamp: clear low 3 bits of byte 0, clear high bit of byte 31, set
    // second-highest bit of byte 31.
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    let mut p: Point = [GF0; 4];
    scalarbase(&mut p, &a);
    let mut pk = [0u8; 32];
    pack_point(&mut pk, &p);
    pk
}

/// Sign `msg` with the given 32-byte seed. Returns (public_key, signature).
/// Matches RFC 8032 §5.1.6.
pub fn sign(seed: &[u8; 32], msg: &[u8]) -> ([u8; 32], [u8; 64]) {
    // h = SHA-512(seed); a = clamp(h[0..32]); prefix = h[32..64]
    let h = sha512(seed);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[..32]);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    let prefix = &h[32..64];

    // A = [a]B, pk = compress(A)
    let mut big_a: Point = [GF0; 4];
    scalarbase(&mut big_a, &a);
    let mut pk = [0u8; 32];
    pack_point(&mut pk, &big_a);

    // r = SHA-512(prefix || msg) mod L
    let mut hr = Sha512::new();
    hr.update(prefix);
    hr.update(msg);
    let mut r_hash = hr.finalize();
    let r_scalar = reduce(&mut r_hash);

    // R = [r]B
    let mut big_r: Point = [GF0; 4];
    scalarbase(&mut big_r, &r_scalar);
    let mut r_bytes = [0u8; 32];
    pack_point(&mut r_bytes, &big_r);

    // k = SHA-512(R || A || msg) mod L
    let mut hk = Sha512::new();
    hk.update(&r_bytes);
    hk.update(&pk);
    hk.update(msg);
    let mut k_hash = hk.finalize();
    let k_scalar = reduce(&mut k_hash);

    // s = r + k * a (mod L). Compute via the 64-byte mod_l machinery.
    // Place k*a (little-endian product) + r_scalar into a 64-byte x,
    // then reduce.
    let mut x: [i64; 64] = [0; 64];
    for i in 0..32 {
        x[i] = r_scalar[i] as i64;
    }
    for i in 0..32 {
        for j in 0..32 {
            x[i + j] += (k_scalar[i] as i64) * (a[j] as i64);
        }
    }
    let mut s_bytes = [0u8; 32];
    mod_l(&mut s_bytes, &mut x);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..].copy_from_slice(&s_bytes);
    (pk, sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_hex(s: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0;
        while i + 1 < bytes.len() {
            let hi = match bytes[i] {
                b'0'..=b'9' => bytes[i] - b'0',
                b'a'..=b'f' => bytes[i] - b'a' + 10,
                _ => panic!(),
            };
            let lo = match bytes[i + 1] {
                b'0'..=b'9' => bytes[i + 1] - b'0',
                b'a'..=b'f' => bytes[i + 1] - b'a' + 10,
                _ => panic!(),
            };
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    fn arr32(v: &[u8]) -> [u8; 32] {
        let mut a = [0u8; 32];
        a.copy_from_slice(v);
        a
    }

    #[test]
    fn rfc_vector_1_signing() {
        // RFC 8032 TEST 1: seed, pk, signature, empty msg.
        let seed = arr32(&parse_hex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        ));
        let expected_pk = arr32(&parse_hex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        ));
        let expected_sig = parse_hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        let (pk, sig) = sign(&seed, b"");
        assert_eq!(pk, expected_pk);
        assert_eq!(&sig[..], &expected_sig[..]);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let seed = [0x11u8; 32];
        let msg = b"hello, fluxor modules";
        let (pk, sig) = sign(&seed, msg);
        assert!(verify(&pk, msg, &sig));
        // Tampered msg -> reject.
        assert!(!verify(&pk, b"hello, fluxor other", &sig));
    }
}
