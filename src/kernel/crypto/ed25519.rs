//! Ed25519 signature verification (RFC 8032 §5.1.7).
//!
//! Ported from TweetNaCl (public domain, Bernstein/Janssen/Lange/Schwabe/others),
//! which is the reference small-footprint implementation. Pure Rust, no_std,
//! no external dependencies. Used by the loader to verify per-module
//! signatures before PIC code is admitted.
//!
//! Field arithmetic is over GF(2^255 - 19) using a 16-limb signed
//! radix-2^16 representation (`gf`). Edwards group operations use extended
//! coordinates. Verification is *not* required to be constant-time; this
//! implementation is not constant-time and must not be reused for signing.

use super::sha512::Sha512;

// ============================================================================
// Field GF(2^255 - 19): gf = [i64; 16] in radix-2^16
// ============================================================================

type Gf = [i64; 16];

const GF0: Gf = [0; 16];
const GF1: Gf = {
    let mut g = [0i64; 16];
    g[0] = 1;
    g
};

// d2 = 2 * d mod p, with d = -121665/121666.
const D2: Gf = [
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e,
    0xfce7, 0x56df, 0xd9dc, 0x2406,
];

// d = -121665/121666.
const D: Gf = [
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7,
    0xfe73, 0x2b6f, 0x6cee, 0x5203,
];

// √(-1) mod p.
const SQRT_M1: Gf = [
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
    0xdf0b, 0x4fc1, 0x2480, 0x2b83,
];

// Basepoint coordinates (X, Y).
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
    let a_copy = *a;
    gf_m(o, &a_copy, &a_copy);
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

// ============================================================================
// Group operations in extended coordinates.
// ============================================================================

type Point = [Gf; 4]; // X, Y, Z, T

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
    let a_copy = a;
    gf_m(&mut a, &a_copy, &t);

    gf_a(&mut b, &p[0], &p[1]);
    gf_a(&mut t, &q[0], &q[1]);
    let b_copy = b;
    gf_m(&mut b, &b_copy, &t);

    gf_m(&mut c, &p[3], &q[3]);
    let c_copy = c;
    gf_m(&mut c, &c_copy, &D2);

    gf_m(&mut d, &p[2], &q[2]);
    let d_copy = d;
    gf_a(&mut d, &d_copy, &d_copy);

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
    // Initialise p = identity.
    p[0] = GF0;
    p[1] = GF1;
    p[2] = GF1;
    p[3] = GF0;
    let mut q: Point = *q_in;

    for i in (0..=255).rev() {
        let b = (s[i / 8] >> (i & 7)) & 1;
        cswap(p, &mut q, b);
        point_add(&mut q, p);
        let p_copy = *p;
        point_add(p, &p_copy);
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

/// Decode a compressed Edwards point and negate it in-place (tweetnacl's
/// convention, used so verify can add -A instead of subtract). Returns
/// false on invalid encoding.
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
    let num_copy = num;
    gf_z(&mut num, &num_copy, &r[2]);
    let den_copy = den;
    gf_a(&mut den, &r[2], &den_copy);

    gf_s(&mut den2, &den);
    gf_s(&mut den4, &den2);
    gf_m(&mut den6, &den4, &den2);
    gf_m(&mut t, &den6, &num);
    let t_copy = t;
    gf_m(&mut t, &t_copy, &den);

    let t_copy = t;
    pow2523(&mut t, &t_copy);
    let t_copy = t;
    gf_m(&mut t, &t_copy, &num);
    let t_copy = t;
    gf_m(&mut t, &t_copy, &den);
    let t_copy = t;
    gf_m(&mut t, &t_copy, &den);
    gf_m(&mut r[0], &t, &den);

    gf_s(&mut chk, &r[0]);
    let chk_copy = chk;
    gf_m(&mut chk, &chk_copy, &den);
    if neq25519(&chk, &num) {
        let r0_copy = r[0];
        gf_m(&mut r[0], &r0_copy, &SQRT_M1);
    }

    gf_s(&mut chk, &r[0]);
    let chk_copy = chk;
    gf_m(&mut chk, &chk_copy, &den);
    if neq25519(&chk, &num) {
        return false;
    }

    // Negate if the parity matches the sign bit (so we can add -A in verify).
    if par25519(&r[0]) == (p[31] >> 7) {
        let r0_copy = r[0];
        gf_z(&mut r[0], &GF0, &r0_copy);
    }

    let r0_copy = r[0];
    let r1_copy = r[1];
    gf_m(&mut r[3], &r0_copy, &r1_copy);
    true
}

// ============================================================================
// Scalar reduction modulo L.
// ============================================================================

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

// ============================================================================
// Public verify API
// ============================================================================

fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut d: u8 = 0;
    for i in 0..32 {
        d |= a[i] ^ b[i];
    }
    d == 0
}

pub fn verify(public_key: &[u8; 32], msg: &[u8], signature: &[u8; 64]) -> bool {
    // Unpack -A (tweetnacl negates during unpack so we can add instead of subtract).
    let mut q: Point = [GF0; 4];
    if !unpack_neg(&mut q, public_key) {
        return false;
    }

    // h = SHA-512(R || A || M), reduced mod L.
    let mut hasher = Sha512::new();
    hasher.update(&signature[..32]); // R
    hasher.update(public_key); // A
    hasher.update(msg);
    let mut h = hasher.finalize();
    let h_reduced = reduce(&mut h);

    // p = h * (-A)
    let mut p: Point = [GF0; 4];
    scalarmult(&mut p, &q, &h_reduced);

    // q = s * B
    let mut sb: Point = [GF0; 4];
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);
    scalarbase(&mut sb, &s_bytes);

    // p = p + q = h*(-A) + s*B
    point_add(&mut p, &sb);

    // Pack and compare to R.
    let mut t = [0u8; 32];
    pack_point(&mut t, &p);
    let mut r = [0u8; 32];
    r.copy_from_slice(&signature[..32]);
    ct_eq_32(&r, &t)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;

    fn parse_hex(s: &str) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::with_capacity(s.len() / 2);
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
    fn arr64(v: &[u8]) -> [u8; 64] {
        let mut a = [0u8; 64];
        a.copy_from_slice(v);
        a
    }

    #[test]
    fn rfc_8032_vector_1() {
        let pk = arr32(&parse_hex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        ));
        let sig = arr64(&parse_hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"));
        assert!(verify(&pk, b"", &sig));
    }

    #[test]
    fn rfc_8032_vector_2() {
        let pk = arr32(&parse_hex(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        ));
        let msg = parse_hex("72");
        let sig = arr64(&parse_hex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"));
        assert!(verify(&pk, &msg, &sig));
    }

    #[test]
    fn rfc_8032_vector_3() {
        let pk = arr32(&parse_hex(
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        ));
        let msg = parse_hex("af82");
        let sig = arr64(&parse_hex("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"));
        assert!(verify(&pk, &msg, &sig));
    }

    #[test]
    fn rejects_tampered_message() {
        let pk = arr32(&parse_hex(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        ));
        let msg = parse_hex("73");
        let sig = arr64(&parse_hex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"));
        assert!(!verify(&pk, &msg, &sig));
    }

    #[test]
    fn rejects_tampered_signature() {
        let pk = arr32(&parse_hex(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        ));
        let msg = parse_hex("72");
        let mut sig_bytes = parse_hex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
        sig_bytes[0] ^= 0x01;
        let sig = arr64(&sig_bytes);
        assert!(!verify(&pk, &msg, &sig));
    }
}
