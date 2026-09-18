// P-384 (secp384r1) ECDH and ECDSA
// Pure Rust, no_std, no heap
//
// The field and the scalar field are both handled by one Montgomery
// multiplication over six 64-bit limbs (CIOS), each with its own modulus,
// `-m^-1 mod 2^64` and `R^2 mod m` for `R = 2^384`. Coordinates mod p
// are kept in Montgomery form for the length of a point operation and
// converted at the byte boundaries; scalars mod n are held in plain form
// and enter Montgomery form only inside a multiplication. Either way, no
// reduction here is specific to the shape of either prime.
//
// # Timing
//
// The same layering as `p256.rs`, and the same claims: field and scalar
// arithmetic run fixed trip counts with masked corrections; point
// addition and doubling compute the generic case, the doubling and the
// identity outcomes and select between them under masks; the ladder is
// one addition and one doubling per bit with a masked swap; the Fermat
// inversions run the public exponents `p - 2` and `n - 2`. The named
// exceptions are the same too: the RFC 6979 retry, the admission checks
// that report their decision, the low-s branch on a published value, and
// ECDSA verification, which handles only public inputs and uses a
// variable-time inversion for them.
//
// This file is mounted beside `p256.rs` in one scope, so every
// curve-specific identifier carries `384` or `p384`. `der_int_into` is
// the one free function named without it; `p256.rs` defines no such
// name.

type U384 = [u64; 6];

const U384_ZERO: U384 = [0; 6];
const U384_ONE: U384 = [1, 0, 0, 0, 0, 0];

// Scalar tables of integers are PIC-safe: nothing here is an address.
const P384: U384 = [
    0x00000000ffffffff,
    0xffffffff00000000,
    0xfffffffffffffffe,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0xffffffffffffffff,
];
const N384: U384 = [
    0xecec196accc52973,
    0x581a0db248b0a77a,
    0xc7634d81f4372ddf,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0xffffffffffffffff,
];
const B384: U384 = [
    0x2a85c8edd3ec2aef,
    0xc656398d8a2ed19d,
    0x0314088f5013875a,
    0x181d9c6efe814112,
    0x988e056be3f82d19,
    0xb3312fa7e23ee7e4,
];
const GX384: U384 = [
    0x3a545e3872760ab7,
    0x5502f25dbf55296c,
    0x59f741e082542a38,
    0x6e1d3b628ba79b98,
    0x8eb1c71ef320ad74,
    0xaa87ca22be8b0537,
];
const GY384: U384 = [
    0x7a431d7c90ea0e5f,
    0x0a60b1ce1d7e819d,
    0xe9da3113b5f0b8c0,
    0xf8f41dbd289a147c,
    0x5d9e98bf9292dc29,
    0x3617de4a96262c6f,
];
const N384_HALF: U384 = [
    0x76760cb5666294b9,
    0xac0d06d9245853bd,
    0xe3b1a6c0fa1b96ef,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0x7fffffffffffffff,
];
/// `R^2 mod p` and `R^2 mod n`, `R = 2^384`.
const P384_R2: U384 = [
    0xfffffffe00000001,
    0x0000000200000000,
    0xfffffffe00000000,
    0x0000000200000000,
    0x0000000000000001,
    0x0000000000000000,
];
const N384_R2: U384 = [
    0x2d319b2419b409a9,
    0xff3d81e5df1aa419,
    0xbc3e483afcb82947,
    0xd40d49174aab1cc5,
    0x3fb05b7a28266895,
    0x0c84ee012b39bf21,
];
/// `-p^-1 mod 2^64` and `-n^-1 mod 2^64`.
const P384_N0: u64 = 0x0000000100000001;
const N384_N0: u64 = 0x6ed46089e88fdc45;

// ============================================================================
// 384-bit integers
// ============================================================================

#[inline]
fn u384_add(a: &U384, b: &U384) -> (U384, u64) {
    let mut r = [0u64; 6];
    let mut carry = 0u64;
    let mut i = 0;
    while i < 6 {
        let sum = (a[i] as u128) + (b[i] as u128) + (carry as u128);
        r[i] = sum as u64;
        carry = (sum >> 64) as u64;
        i += 1;
    }
    (r, carry)
}

/// `a - b`, with the borrow out: 1 exactly when `a < b`.
#[inline]
fn u384_sub(a: &U384, b: &U384) -> (U384, u64) {
    let mut r = [0u64; 6];
    let mut borrow = 0u64;
    let mut i = 0;
    while i < 6 {
        let diff = (a[i] as u128)
            .wrapping_sub(b[i] as u128)
            .wrapping_sub(borrow as u128);
        r[i] = diff as u64;
        borrow = ((diff >> 64) & 1) as u64;
        i += 1;
    }
    (r, borrow)
}

/// 1 when `a >= b`, 0 otherwise, from the whole borrow chain.
fn u384_gte(a: &U384, b: &U384) -> u64 {
    let (_, borrow) = u384_sub(a, b);
    1 - borrow
}

fn u384_is_zero(a: &U384) -> bool {
    a[0] | a[1] | a[2] | a[3] | a[4] | a[5] == 0
}

fn u384_is_one(a: &U384) -> bool {
    a[0] == 1 && a[1] | a[2] | a[3] | a[4] | a[5] == 0
}

fn u384_shr1(a: &U384, top: u64) -> U384 {
    [
        (a[0] >> 1) | (a[1] << 63),
        (a[1] >> 1) | (a[2] << 63),
        (a[2] >> 1) | (a[3] << 63),
        (a[3] >> 1) | (a[4] << 63),
        (a[4] >> 1) | (a[5] << 63),
        (a[5] >> 1) | (top << 63),
    ]
}

/// Select `b` where `mask` is all-ones, `a` where it is zero.
#[inline(always)]
fn ct_select_u384(a: &U384, b: &U384, mask: u64) -> U384 {
    let mut r = [0u64; 6];
    let mut i = 0;
    while i < 6 {
        r[i] = (a[i] & !mask) | (b[i] & mask);
        i += 1;
    }
    r
}

/// All-ones when `a` is zero.
#[inline(always)]
fn ct_is_zero_u384(a: &U384) -> u64 {
    let x = a[0] | a[1] | a[2] | a[3] | a[4] | a[5];
    let bit = !((x | x.wrapping_neg()) >> 63) & 1;
    bit.wrapping_neg()
}

fn zeroize_u384(v: &mut U384) {
    let mut i = 0;
    while i < 6 {
        // SAFETY: a volatile store into an owned array slot.
        unsafe { core::ptr::write_volatile(&mut v[i], 0) };
        i += 1;
    }
}

fn u384_from_be(bytes: &[u8]) -> U384 {
    let mut r = [0u64; 6];
    let mut i = 0;
    while i < 6 && i * 8 + 8 <= bytes.len() {
        let off = bytes.len() - 8 - i * 8;
        r[i] = u64::from_be_bytes([
            bytes[off],
            bytes[off + 1],
            bytes[off + 2],
            bytes[off + 3],
            bytes[off + 4],
            bytes[off + 5],
            bytes[off + 6],
            bytes[off + 7],
        ]);
        i += 1;
    }
    r
}

fn u384_to_be(a: &U384) -> [u8; 48] {
    let mut out = [0u8; 48];
    let mut i = 0;
    while i < 6 {
        let b = a[5 - i].to_be_bytes();
        out[i * 8..i * 8 + 8].copy_from_slice(&b);
        i += 1;
    }
    out
}

/// `a^-1 mod m` by the binary extended Euclidean algorithm, for odd `m`
/// and `a` in `[1, m)` coprime to it; 0 for `a == 0`. VARIABLE TIME in
/// `a`: for a verifier's public values only, as in `p256.rs`.
fn u384_inv_vartime(a: &U384, m: &U384) -> U384 {
    if u384_is_zero(a) {
        return U384_ZERO;
    }
    let mut u = *a;
    let mut v = *m;
    let mut x1 = U384_ONE;
    let mut x2 = U384_ZERO;
    let half = |x: &U384| -> U384 {
        if x[0] & 1 == 0 {
            u384_shr1(x, 0)
        } else {
            let (sum, carry) = u384_add(x, m);
            u384_shr1(&sum, carry)
        }
    };
    let sub_mod = |x: &U384, y: &U384| -> U384 {
        let (d, borrow) = u384_sub(x, y);
        if borrow != 0 {
            u384_add(&d, m).0
        } else {
            d
        }
    };
    while !u384_is_one(&u) && !u384_is_one(&v) {
        while u[0] & 1 == 0 {
            u = u384_shr1(&u, 0);
            x1 = half(&x1);
        }
        while v[0] & 1 == 0 {
            v = u384_shr1(&v, 0);
            x2 = half(&x2);
        }
        if u384_gte(&u, &v) != 0 {
            u = u384_sub(&u, &v).0;
            x1 = sub_mod(&x1, &x2);
        } else {
            v = u384_sub(&v, &u).0;
            x2 = sub_mod(&x2, &x1);
        }
    }
    if u384_is_one(&u) {
        x1
    } else {
        x2
    }
}

// ============================================================================
// Montgomery arithmetic, shared by both fields.
//
// `mont_mul384(a, b, m, n0) = a·b·R^-1 mod m` by CIOS: six outer rounds,
// each a multiply-accumulate row and a reduction row, then one masked
// subtraction of `m`. Fixed trip counts, no data-dependent addressing.
// ============================================================================

fn mont_mul384(a: &U384, b: &U384, m: &U384, n0: u64) -> U384 {
    let mut t = [0u64; 8];
    let mut i = 0;
    while i < 6 {
        // t += a * b[i]
        let mut carry: u128 = 0;
        let mut j = 0;
        while j < 6 {
            let s = (t[j] as u128) + (a[j] as u128) * (b[i] as u128) + carry;
            t[j] = s as u64;
            carry = s >> 64;
            j += 1;
        }
        let s = (t[6] as u128) + carry;
        t[6] = s as u64;
        t[7] = (s >> 64) as u64;
        // t = (t + u * m) / 2^64
        let u = t[0].wrapping_mul(n0);
        let s = (t[0] as u128) + (u as u128) * (m[0] as u128);
        let mut carry: u128 = s >> 64;
        let mut j = 1;
        while j < 6 {
            let s = (t[j] as u128) + (u as u128) * (m[j] as u128) + carry;
            t[j - 1] = s as u64;
            carry = s >> 64;
            j += 1;
        }
        let s = (t[6] as u128) + carry;
        t[5] = s as u64;
        t[6] = t[7].wrapping_add((s >> 64) as u64);
        t[7] = 0;
        i += 1;
    }
    let r: U384 = [t[0], t[1], t[2], t[3], t[4], t[5]];
    // r < 2m: subtract m under a mask when r >= m or the word above is set.
    let (sub, borrow) = u384_sub(&r, m);
    let keep_sub = ((borrow ^ 1) | t[6]).wrapping_neg();
    ct_select_u384(&r, &sub, keep_sub)
}

// ── Field mod p, in Montgomery form ──

fn fp384_mul(a: &U384, b: &U384) -> U384 {
    mont_mul384(a, b, &P384, P384_N0)
}

fn fp384_sqr(a: &U384) -> U384 {
    mont_mul384(a, a, &P384, P384_N0)
}

fn fp384_to_mont(a: &U384) -> U384 {
    mont_mul384(a, &P384_R2, &P384, P384_N0)
}

fn fp384_from_mont(a: &U384) -> U384 {
    mont_mul384(a, &U384_ONE, &P384, P384_N0)
}

fn fp384_add(a: &U384, b: &U384) -> U384 {
    let (sum, carry) = u384_add(a, b);
    let (corrected, borrow) = u384_sub(&sum, &P384);
    let need = (carry | (borrow ^ 1)).wrapping_neg();
    ct_select_u384(&sum, &corrected, need)
}

fn fp384_sub(a: &U384, b: &U384) -> U384 {
    let (diff, borrow) = u384_sub(a, b);
    let (corrected, _) = u384_add(&diff, &P384);
    ct_select_u384(&diff, &corrected, borrow.wrapping_neg())
}

/// Montgomery form of 1, i.e. `R mod p`.
fn fp384_one() -> U384 {
    fp384_to_mont(&U384_ONE)
}

/// `a^(p-2)` in Montgomery form: the constant-time inverse.
fn fp384_inv(a: &U384) -> U384 {
    let (mut result, mut base) = (fp384_one(), *a);
    let (p_minus_2, _) = u384_sub(&P384, &[2, 0, 0, 0, 0, 0]);
    let mut i = 0;
    while i < 6 {
        let mut j = 0;
        while j < 64 {
            if (p_minus_2[i] >> j) & 1 == 1 {
                result = fp384_mul(&result, &base);
            }
            base = fp384_sqr(&base);
            j += 1;
        }
        i += 1;
    }
    result
}

/// The inverse of a PUBLIC element, Montgomery form in and out.
fn fp384_inv_vartime(a: &U384) -> U384 {
    let plain = fp384_from_mont(a);
    fp384_to_mont(&u384_inv_vartime(&plain, &P384))
}

// ── Scalar field mod n, in Montgomery form ──

fn fn384_mul(a: &U384, b: &U384) -> U384 {
    mont_mul384(a, b, &N384, N384_N0)
}

fn fn384_to_mont(a: &U384) -> U384 {
    mont_mul384(a, &N384_R2, &N384, N384_N0)
}

fn fn384_from_mont(a: &U384) -> U384 {
    mont_mul384(a, &U384_ONE, &N384, N384_N0)
}

/// Reduce mod n, for `a < 2n`.
fn fn384_reduce(a: &U384) -> U384 {
    let (r, borrow) = u384_sub(a, &N384);
    ct_select_u384(&r, a, borrow.wrapping_neg())
}

/// `a + b mod n`, plain form.
fn fn384_add(a: &U384, b: &U384) -> U384 {
    let (sum, carry) = u384_add(a, b);
    let (corrected, borrow) = u384_sub(&sum, &N384);
    let need = (carry | (borrow ^ 1)).wrapping_neg();
    ct_select_u384(&sum, &corrected, need)
}

/// `a^(n-2) mod n`, plain form in and out: the constant-time inverse of
/// a secret scalar.
fn fn384_inv(a: &U384) -> U384 {
    let am = fn384_to_mont(a);
    let mut result = fn384_to_mont(&U384_ONE);
    let mut base = am;
    let (n_minus_2, _) = u384_sub(&N384, &[2, 0, 0, 0, 0, 0]);
    let mut i = 0;
    while i < 6 {
        let mut j = 0;
        while j < 64 {
            if (n_minus_2[i] >> j) & 1 == 1 {
                result = fn384_mul(&result, &base);
            }
            base = fn384_mul(&base, &base);
            j += 1;
        }
        i += 1;
    }
    fn384_from_mont(&result)
}

/// `a·b mod n` for plain-form operands.
fn fn384_mul_plain(a: &U384, b: &U384) -> U384 {
    fn384_from_mont(&fn384_mul(&fn384_to_mont(a), &fn384_to_mont(b)))
}

// ============================================================================
// Points, Jacobian coordinates, all field elements in Montgomery form.
// ============================================================================

struct Jacobian384 {
    x: U384,
    y: U384,
    z: U384,
}

fn ct_select_point384(a: &Jacobian384, b: &Jacobian384, mask: u64) -> Jacobian384 {
    Jacobian384 {
        x: ct_select_u384(&a.x, &b.x, mask),
        y: ct_select_u384(&a.y, &b.y, mask),
        z: ct_select_u384(&a.z, &b.z, mask),
    }
}

fn ct_swap384(a: &mut Jacobian384, b: &mut Jacobian384, condition: u8) {
    let mask = (condition as u64).wrapping_neg();
    let mut i = 0;
    while i < 6 {
        let tx = mask & (a.x[i] ^ b.x[i]);
        a.x[i] ^= tx;
        b.x[i] ^= tx;
        let ty = mask & (a.y[i] ^ b.y[i]);
        a.y[i] ^= ty;
        b.y[i] ^= ty;
        let tz = mask & (a.z[i] ^ b.z[i]);
        a.z[i] ^= tz;
        b.z[i] ^= tz;
        i += 1;
    }
}

impl Jacobian384 {
    /// The identity: `z = 0`. Its `y` is 1 in plain form; the addition
    /// formulas do read it, but the outcome they select when `z = 0`
    /// never depends on the value.
    const fn identity() -> Self {
        Self {
            x: U384_ZERO,
            y: U384_ONE,
            z: U384_ZERO,
        }
    }

    fn is_identity(&self) -> bool {
        u384_is_zero(&self.z)
    }

    /// From affine coordinates already in Montgomery form.
    fn from_affine_mont(x: &U384, y: &U384) -> Self {
        Self {
            x: *x,
            y: *y,
            z: fp384_one(),
        }
    }

    /// Affine coordinates given `z^-1`, all in Montgomery form.
    fn to_affine_with(&self, z_inv: &U384) -> (U384, U384) {
        let z_inv2 = fp384_sqr(z_inv);
        let z_inv3 = fp384_mul(&z_inv2, z_inv);
        (fp384_mul(&self.x, &z_inv2), fp384_mul(&self.y, &z_inv3))
    }

    fn to_affine(&self) -> (U384, U384) {
        if self.is_identity() {
            return (U384_ZERO, U384_ZERO);
        }
        self.to_affine_with(&fp384_inv(&self.z))
    }

    /// Affine coordinates of a PUBLIC point.
    fn to_affine_vartime(&self) -> (U384, U384) {
        if self.is_identity() {
            return (U384_ZERO, U384_ZERO);
        }
        self.to_affine_with(&fp384_inv_vartime(&self.z))
    }

    /// dbl-2001-b for `a = -3`; the identity (`z = 0`) yields `z3 = 0`.
    fn double(&self) -> Self {
        let s = fp384_sqr(&self.y);
        let mut m = fp384_sqr(&self.x);
        m = fp384_add(&fp384_add(&m, &m), &m);
        let z2 = fp384_sqr(&self.z);
        let z4 = fp384_sqr(&z2);
        let three_z4 = fp384_add(&fp384_add(&z4, &z4), &z4);
        m = fp384_sub(&m, &three_z4);

        let xy2 = fp384_mul(&self.x, &s);
        let t = fp384_add(&xy2, &xy2);
        let t2 = fp384_add(&t, &t);

        let x3 = fp384_sub(&fp384_sqr(&m), &fp384_add(&t2, &t2));

        let y2_4 = fp384_add(&s, &s);
        let y4_8 = fp384_sqr(&y2_4);
        let y4_8_2 = fp384_add(&y4_8, &y4_8);

        let y3 = fp384_sub(&fp384_mul(&m, &fp384_sub(&t2, &x3)), &y4_8_2);
        let z3 = fp384_mul(&fp384_add(&self.y, &self.y), &self.z);
        Jacobian384 {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    fn add_affine(&self, qx: &U384, qy: &U384) -> Self {
        let z1z1 = fp384_sqr(&self.z);
        let u2 = fp384_mul(qx, &z1z1);
        let s2 = fp384_mul(qy, &fp384_mul(&self.z, &z1z1));
        let h = fp384_sub(&u2, &self.x);
        let r = fp384_sub(&s2, &self.y);
        let hh = fp384_sqr(&h);
        let hhh = fp384_mul(&h, &hh);
        let v = fp384_mul(&self.x, &hh);
        let x3 = fp384_sub(&fp384_sub(&fp384_sqr(&r), &hhh), &fp384_add(&v, &v));
        let y3 = fp384_sub(
            &fp384_mul(&r, &fp384_sub(&v, &x3)),
            &fp384_mul(&self.y, &hhh),
        );
        let z3 = fp384_mul(&self.z, &h);
        let generic = Jacobian384 {
            x: x3,
            y: y3,
            z: z3,
        };
        let h_zero = ct_is_zero_u384(&h);
        let r_zero = ct_is_zero_u384(&r);
        let self_id = ct_is_zero_u384(&self.z);
        let out = ct_select_point384(&generic, &Jacobian384::identity(), h_zero);
        let out = ct_select_point384(&out, &self.double(), h_zero & r_zero);
        ct_select_point384(&out, &Jacobian384::from_affine_mont(qx, qy), self_id)
    }

    fn add_jacobian(&self, other: &Jacobian384) -> Self {
        let z1z1 = fp384_sqr(&self.z);
        let z2z2 = fp384_sqr(&other.z);
        let u1 = fp384_mul(&self.x, &z2z2);
        let u2 = fp384_mul(&other.x, &z1z1);
        let s1 = fp384_mul(&self.y, &fp384_mul(&other.z, &z2z2));
        let s2 = fp384_mul(&other.y, &fp384_mul(&self.z, &z1z1));
        let h = fp384_sub(&u2, &u1);
        let r = fp384_sub(&s2, &s1);
        let hh = fp384_sqr(&h);
        let hhh = fp384_mul(&h, &hh);
        let v = fp384_mul(&u1, &hh);
        let x3 = fp384_sub(&fp384_sub(&fp384_sqr(&r), &hhh), &fp384_add(&v, &v));
        let y3 = fp384_sub(&fp384_mul(&r, &fp384_sub(&v, &x3)), &fp384_mul(&s1, &hhh));
        let z3 = fp384_mul(&fp384_mul(&self.z, &other.z), &h);
        let generic = Jacobian384 {
            x: x3,
            y: y3,
            z: z3,
        };
        let h_zero = ct_is_zero_u384(&h);
        let r_zero = ct_is_zero_u384(&r);
        let self_id = ct_is_zero_u384(&self.z);
        let other_id = ct_is_zero_u384(&other.z);
        let out = ct_select_point384(&generic, &Jacobian384::identity(), h_zero);
        let out = ct_select_point384(&out, &self.double(), h_zero & r_zero);
        let out = ct_select_point384(&out, other, self_id);
        ct_select_point384(&out, self, other_id)
    }
}

/// Whether plain-form `(x, y)` satisfies `y² = x³ - 3x + b`.
pub fn p384_is_on_curve(x: &U384, y: &U384) -> bool {
    let xm = fp384_to_mont(x);
    let ym = fp384_to_mont(y);
    let lhs = fp384_sqr(&ym);
    let x2 = fp384_sqr(&xm);
    let x3 = fp384_mul(&x2, &xm);
    let three_x = fp384_add(&fp384_add(&xm, &xm), &xm);
    let rhs = fp384_add(&fp384_sub(&x3, &three_x), &fp384_to_mont(&B384));
    lhs == rhs
}

/// Decode an uncompressed point (`04 || x || y`, 97 bytes, or the bare
/// 96) into plain-form coordinates, admitting only a point on the curve
/// with coordinates below `p`.
fn p384_decode_public_point(encoded: &[u8]) -> Option<(U384, U384)> {
    let offset = if encoded.len() == 97 {
        if encoded[0] != 0x04 {
            return None;
        }
        1
    } else if encoded.len() == 96 {
        0
    } else {
        return None;
    };
    let x = u384_from_be(&encoded[offset..offset + 48]);
    let y = u384_from_be(&encoded[offset + 48..offset + 96]);
    if u384_gte(&x, &P384) != 0 || u384_gte(&y, &P384) != 0 {
        return None;
    }
    if u384_is_zero(&x) && u384_is_zero(&y) {
        return None;
    }
    if !p384_is_on_curve(&x, &y) {
        return None;
    }
    Some((x, y))
}

/// Whether `encoded` is a point this module would use.
pub fn p384_public_point_is_valid(encoded: &[u8]) -> bool {
    p384_decode_public_point(encoded).is_some()
}

/// A scalar in `[1, n-1]`.
fn p384_decode_private_scalar(private_key: &[u8; 48]) -> Option<U384> {
    let d = u384_from_be(private_key);
    if u384_is_zero(&d) || u384_gte(&d, &N384) != 0 {
        return None;
    }
    Some(d)
}

// ============================================================================
// Resumable scalar multiplication: the Montgomery ladder, `bits_per_step`
// bits per call, then the Fermat inversion of the result's `z` behind it
// so the affine conversion of a secret result is stepped too.
// ============================================================================

pub struct ScalarMulState384 {
    r0: Jacobian384,
    r1: Jacobian384,
    k: U384,
    /// Next ladder bit, 383 down to 0; -1 = done.
    bit_index: i16,
    bits_per_step: u8,
    initialised: u8,
    inv_result: U384,
    inv_base: U384,
    inv_bit: u16,
    want_affine: u8,
}

const FERMAT384_BITS_PER_LADDER_BIT: u16 = 4;
const INV384_DONE: u16 = 384;

impl ScalarMulState384 {
    pub const fn empty() -> Self {
        Self {
            r0: Jacobian384::identity(),
            r1: Jacobian384::identity(),
            k: U384_ZERO,
            bit_index: -1,
            bits_per_step: 0,
            initialised: 0,
            inv_result: U384_ZERO,
            inv_base: U384_ZERO,
            inv_bit: 0,
            want_affine: 0,
        }
    }

    /// `k · P` for plain-form affine `P`. `bits_per_step == 0` runs the
    /// whole ladder in one `step`.
    pub fn new(k: &U384, px: &U384, py: &U384, bits_per_step: u8) -> Self {
        let p = Jacobian384::from_affine_mont(&fp384_to_mont(px), &fp384_to_mont(py));
        Self {
            r0: Jacobian384::identity(),
            r1: p,
            k: *k,
            bit_index: 383,
            bits_per_step,
            initialised: 1,
            inv_result: U384_ZERO,
            inv_base: U384_ZERO,
            inv_bit: 0,
            want_affine: 1,
        }
    }

    pub fn new_base(k: &U384, bits_per_step: u8) -> Self {
        Self::new(k, &GX384, &GY384, bits_per_step)
    }

    /// The caller converts the (public) result its own way.
    pub fn skip_affine(&mut self) {
        self.want_affine = 0;
    }

    pub fn is_initialised(&self) -> bool {
        self.initialised != 0
    }

    pub fn complete(&self) -> bool {
        self.initialised != 0
            && self.bit_index < 0
            && (self.want_affine == 0 || self.inv_bit >= INV384_DONE)
    }

    pub fn step(&mut self) -> bool {
        if self.initialised == 0 {
            return false;
        }
        if self.bit_index < 0 {
            self.step_inverse();
            return self.complete();
        }
        let mut remaining: i16 = if self.bits_per_step == 0 {
            i16::MAX
        } else {
            self.bits_per_step as i16
        };
        while remaining > 0 && self.bit_index >= 0 {
            let bi = self.bit_index as u32;
            let bit = ((self.k[(bi >> 6) as usize] >> (bi & 63)) & 1) as u8;
            ct_swap384(&mut self.r0, &mut self.r1, bit);
            self.r1 = self.r0.add_jacobian(&self.r1);
            self.r0 = self.r0.double();
            ct_swap384(&mut self.r0, &mut self.r1, bit);
            self.bit_index -= 1;
            remaining -= 1;
        }
        if self.bit_index < 0 {
            self.inv_base = self.r0.z;
            self.inv_result = fp384_one();
            self.inv_bit = 0;
            if self.bits_per_step == 0 {
                self.step_inverse();
            }
        }
        self.complete()
    }

    fn step_inverse(&mut self) {
        if self.want_affine == 0 || self.inv_bit >= INV384_DONE {
            return;
        }
        let mut remaining: u16 = if self.bits_per_step == 0 {
            INV384_DONE
        } else {
            (self.bits_per_step as u16).saturating_mul(FERMAT384_BITS_PER_LADDER_BIT)
        };
        let (p_minus_2, _) = u384_sub(&P384, &[2, 0, 0, 0, 0, 0]);
        while remaining > 0 && self.inv_bit < INV384_DONE {
            let j = self.inv_bit as usize;
            if (p_minus_2[j >> 6] >> (j & 63)) & 1 == 1 {
                self.inv_result = fp384_mul(&self.inv_result, &self.inv_base);
            }
            self.inv_base = fp384_sqr(&self.inv_base);
            self.inv_bit += 1;
            remaining -= 1;
        }
    }

    /// The affine result in plain form, once `complete()`; `(0, 0)` for
    /// the identity.
    pub fn affine(&self) -> (U384, U384) {
        if self.r0.is_identity() {
            return (U384_ZERO, U384_ZERO);
        }
        let (x, y) = self.r0.to_affine_with(&self.inv_result);
        (fp384_from_mont(&x), fp384_from_mont(&y))
    }

    fn result(&self) -> Jacobian384 {
        Jacobian384 {
            x: self.r0.x,
            y: self.r0.y,
            z: self.r0.z,
        }
    }

    pub fn zeroise_scalar(&mut self) {
        zeroize_u384(&mut self.k);
        zeroize_u384(&mut self.inv_base);
        zeroize_u384(&mut self.inv_result);
    }
}

// ============================================================================
// ECDH
// ============================================================================

/// Begin a key pair from 48 random bytes: the scalar (reduced into
/// `[1, n-1]`) and the ladder for its public point.
pub fn ecdh384_keygen_init(
    random_bytes: &[u8; 48],
    bits_per_step: u8,
) -> ([u8; 48], ScalarMulState384) {
    let mut d = fn384_reduce(&u384_from_be(random_bytes));
    if u384_is_zero(&d) {
        d = U384_ONE;
    }
    (
        u384_to_be(&d),
        ScalarMulState384::new_base(&d, bits_per_step),
    )
}

/// The public key, `04 || x || y`, once the ladder is complete.
pub fn ecdh384_keygen_finalise(state: &ScalarMulState384) -> Option<[u8; 97]> {
    if state.result().is_identity() {
        return None;
    }
    let (x, y) = state.affine();
    let mut out = [0u8; 97];
    out[0] = 0x04;
    out[1..49].copy_from_slice(&u384_to_be(&x));
    out[49..97].copy_from_slice(&u384_to_be(&y));
    Some(out)
}

/// Begin the agreement `d · Q` for the peer's encoded point `Q`, which
/// must be on the curve.
pub fn ecdh384_shared_secret_init(
    my_private: &[u8; 48],
    peer_pub: &[u8],
    bits_per_step: u8,
) -> Option<ScalarMulState384> {
    let d = p384_decode_private_scalar(my_private)?;
    let (qx, qy) = p384_decode_public_point(peer_pub)?;
    Some(ScalarMulState384::new(&d, &qx, &qy, bits_per_step))
}

/// The shared x-coordinate, once the ladder is complete.
pub fn ecdh384_shared_secret_finalise(state: &ScalarMulState384) -> Option<[u8; 48]> {
    if state.result().is_identity() {
        return None;
    }
    let (x, _) = state.affine();
    Some(u384_to_be(&x))
}

/// One-shot key pair.
pub fn ecdh384_keygen(random_bytes: &[u8; 48]) -> ([u8; 48], [u8; 97]) {
    let (d, mut st) = ecdh384_keygen_init(random_bytes, 0);
    st.step();
    let pk = ecdh384_keygen_finalise(&st).unwrap_or([0u8; 97]);
    st.zeroise_scalar();
    (d, pk)
}

/// One-shot agreement.
pub fn ecdh384_shared_secret(my_private: &[u8; 48], peer_pub: &[u8]) -> Option<[u8; 48]> {
    let mut st = ecdh384_shared_secret_init(my_private, peer_pub, 0)?;
    st.step();
    let out = ecdh384_shared_secret_finalise(&st);
    st.zeroise_scalar();
    out
}

// ============================================================================
// ECDSA
// ============================================================================

/// The message hash as a scalar: the leftmost 384 bits, reduced mod n.
fn p384_hash_to_scalar(hash: &[u8]) -> U384 {
    let z = if hash.len() >= 48 {
        u384_from_be(&hash[..48])
    } else {
        let mut buf = [0u8; 48];
        buf[48 - hash.len()..].copy_from_slice(hash);
        u384_from_be(&buf)
    };
    fn384_reduce(&z)
}

/// RFC 6979 nonce with HMAC-SHA384, for a 48-byte private key and a
/// hash whose leftmost 384 bits are taken.
fn p384_rfc6979_nonce(private_key: &[u8; 48], hash: &[u8]) -> U384 {
    let h1 = u384_to_be(&p384_hash_to_scalar(hash));
    let mut v = [0x01u8; 48];
    let mut k = [0x00u8; 48];
    let mut msg = [0u8; 48 + 1 + 48 + 48];
    msg[..48].copy_from_slice(&v);
    msg[48] = 0x00;
    msg[49..97].copy_from_slice(private_key);
    msg[97..145].copy_from_slice(&h1);
    let mut tmp = [0u8; 48];
    hmac(HashAlg::Sha384, &k, &msg, &mut tmp);
    k = tmp;
    hmac(HashAlg::Sha384, &k, &v, &mut tmp);
    v = tmp;
    msg[..48].copy_from_slice(&v);
    msg[48] = 0x01;
    hmac(HashAlg::Sha384, &k, &msg, &mut tmp);
    k = tmp;
    hmac(HashAlg::Sha384, &k, &v, &mut tmp);
    v = tmp;
    loop {
        hmac(HashAlg::Sha384, &k, &v, &mut tmp);
        v = tmp;
        let candidate = u384_from_be(&v);
        if !u384_is_zero(&candidate) && u384_gte(&candidate, &N384) == 0 {
            zeroize(&mut k);
            return candidate;
        }
        let mut again = [0u8; 49];
        again[..48].copy_from_slice(&v);
        hmac(HashAlg::Sha384, &k, &again, &mut tmp);
        k = tmp;
        hmac(HashAlg::Sha384, &k, &v, &mut tmp);
        v = tmp;
    }
}

pub struct Ecdsa384SignState {
    pub scalar_mul: ScalarMulState384,
    d: U384,
    k: U384,
    z: U384,
    initialised: u8,
}

impl Ecdsa384SignState {
    pub const fn empty() -> Self {
        Self {
            scalar_mul: ScalarMulState384::empty(),
            d: U384_ZERO,
            k: U384_ZERO,
            z: U384_ZERO,
            initialised: 0,
        }
    }

    pub fn is_initialised(&self) -> bool {
        self.initialised != 0
    }

    pub fn zeroise_secrets(&mut self) {
        zeroize_u384(&mut self.k);
        zeroize_u384(&mut self.d);
        self.scalar_mul.zeroise_scalar();
    }
}

/// Begin a signature: the nonce and the ladder for `k · G`.
pub fn ecdsa384_sign_init(
    private_key: &[u8; 48],
    hash: &[u8],
    bits_per_step: u8,
) -> Option<Ecdsa384SignState> {
    let d = p384_decode_private_scalar(private_key)?;
    let k = p384_rfc6979_nonce(private_key, hash);
    let z = p384_hash_to_scalar(hash);
    Some(Ecdsa384SignState {
        scalar_mul: ScalarMulState384::new_base(&k, bits_per_step),
        d,
        k,
        z,
        initialised: 1,
    })
}

/// `r || s` (96 bytes, low-s) once the ladder is complete. Secrets are
/// scrubbed before returning.
pub fn ecdsa384_sign_finalise(mut state: Ecdsa384SignState) -> [u8; 96] {
    let (rx, _) = state.scalar_mul.affine();
    let r = fn384_reduce(&rx);
    let k_inv = fn384_inv(&state.k);
    let rd = fn384_mul_plain(&r, &state.d);
    let z_rd = fn384_add(&state.z, &rd);
    let mut s = fn384_mul_plain(&k_inv, &z_rd);
    if u384_gte(&s, &N384_HALF) != 0 {
        s = u384_sub(&N384, &s).0;
    }
    state.zeroise_secrets();
    let mut sig = [0u8; 96];
    sig[..48].copy_from_slice(&u384_to_be(&r));
    sig[48..].copy_from_slice(&u384_to_be(&s));
    sig
}

/// One-shot deterministic signature.
pub fn ecdsa384_sign(private_key: &[u8; 48], hash: &[u8]) -> Option<[u8; 96]> {
    let mut st = ecdsa384_sign_init(private_key, hash, 0)?;
    st.scalar_mul.step();
    Some(ecdsa384_sign_finalise(st))
}

/// A verification in flight: `u1 · G` and `u2 · Q` on their own ladders.
pub struct Ecdsa384VerifyJob {
    s1: ScalarMulState384,
    s2: ScalarMulState384,
    r: U384,
    initialised: u8,
}

impl Ecdsa384VerifyJob {
    pub const fn empty() -> Self {
        Self {
            s1: ScalarMulState384::empty(),
            s2: ScalarMulState384::empty(),
            r: U384_ZERO,
            initialised: 0,
        }
    }

    pub fn is_initialised(&self) -> bool {
        self.initialised != 0
    }

    /// One ladder step; completion is observed on the call after the
    /// last ladder bit, so the finalise has a step of its own.
    pub fn step(&mut self) -> bool {
        if self.initialised == 0 {
            return false;
        }
        if !self.s1.complete() {
            self.s1.step();
            return false;
        }
        if !self.s2.complete() {
            self.s2.step();
            return false;
        }
        true
    }

    pub fn complete(&self) -> bool {
        self.initialised != 0 && self.s1.complete() && self.s2.complete()
    }
}

/// Begin verifying `sig` (raw `r || s`) over `hash` under `pub_key`.
pub fn ecdsa384_verify_init(
    pub_key: &[u8],
    hash: &[u8],
    sig: &[u8],
    bits_per_step: u8,
) -> Option<Ecdsa384VerifyJob> {
    if sig.len() < 96 {
        return None;
    }
    let (qx, qy) = p384_decode_public_point(pub_key)?;
    let r = u384_from_be(&sig[..48]);
    let s = u384_from_be(&sig[48..96]);
    if u384_is_zero(&r) || u384_is_zero(&s) || u384_gte(&r, &N384) != 0 || u384_gte(&s, &N384) != 0
    {
        return None;
    }
    let z = p384_hash_to_scalar(hash);
    let s_inv = u384_inv_vartime(&s, &N384);
    let u1 = fn384_mul_plain(&z, &s_inv);
    let u2 = fn384_mul_plain(&r, &s_inv);
    let mut s1 = ScalarMulState384::new_base(&u1, bits_per_step);
    let mut s2 = ScalarMulState384::new(&u2, &qx, &qy, bits_per_step);
    s1.skip_affine();
    s2.skip_affine();
    Some(Ecdsa384VerifyJob {
        s1,
        s2,
        r,
        initialised: 1,
    })
}

/// Whether the completed job's signature verifies.
pub fn ecdsa384_verify_finalise(job: &Ecdsa384VerifyJob) -> bool {
    if !job.complete() {
        return false;
    }
    let p1 = job.s1.result();
    let p2 = job.s2.result();
    let (p2x, p2y) = p2.to_affine_vartime();
    if p2.is_identity() {
        return false;
    }
    let sum = p1.add_affine(&p2x, &p2y);
    if sum.is_identity() {
        return false;
    }
    let (rx, _) = sum.to_affine_vartime();
    fn384_reduce(&fp384_from_mont(&rx)) == job.r
}

/// One-shot verification of a raw `r || s` signature.
pub fn ecdsa384_verify(pub_key: &[u8], hash: &[u8], sig: &[u8]) -> bool {
    let Some(mut job) = ecdsa384_verify_init(pub_key, hash, sig, 0) else {
        return false;
    };
    while !job.step() {}
    ecdsa384_verify_finalise(&job)
}

// ============================================================================
// DER signatures: `SEQUENCE { r INTEGER, s INTEGER }`, one encoding each.
// ============================================================================

/// The 96-byte raw signature of a canonical DER one.
pub fn parse_der_signature384(der: &[u8]) -> Option<[u8; 96]> {
    if der.len() < 8 || der[0] != 0x30 {
        return None;
    }
    let seq_len = der[1] as usize;
    if seq_len >= 0x80 || 2 + seq_len != der.len() {
        return None;
    }
    let mut pos = 2;
    let r_bytes = der_positive_int384(der, &mut pos)?;
    let s_bytes = der_positive_int384(der, &mut pos)?;
    if pos != der.len() {
        return None;
    }
    let mut sig = [0u8; 96];
    der_int_into(r_bytes, &mut sig[..48])?;
    der_int_into(s_bytes, &mut sig[48..])?;
    Some(sig)
}

fn der_positive_int384<'a>(der: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    if *pos + 2 > der.len() || der[*pos] != 0x02 {
        return None;
    }
    let len = der[*pos + 1] as usize;
    if len == 0 || len >= 0x80 || len > 49 {
        return None;
    }
    let start = *pos + 2;
    if start + len > der.len() {
        return None;
    }
    let body = &der[start..start + len];
    if body[0] & 0x80 != 0 || (len > 1 && body[0] == 0 && body[1] & 0x80 == 0) {
        return None;
    }
    *pos = start + len;
    Some(body)
}

/// Right-align a minimal positive INTEGER into `dst`.
fn der_int_into(src: &[u8], dst: &mut [u8]) -> Option<()> {
    let src = if src.len() == dst.len() + 1 && src[0] == 0 {
        &src[1..]
    } else {
        src
    };
    if src.len() > dst.len() {
        return None;
    }
    let off = dst.len() - src.len();
    let mut i = 0;
    while i < off {
        dst[i] = 0;
        i += 1;
    }
    dst[off..].copy_from_slice(src);
    Some(())
}

/// The DER encoding of a raw `r || s` signature and its length.
pub fn encode_der_signature384(sig: &[u8; 96]) -> ([u8; 104], usize) {
    let mut out = [0u8; 104];
    let mut pos = 2;
    let mut half = 0;
    while half < 2 {
        let part = &sig[half * 48..half * 48 + 48];
        let mut start = 0;
        while start < 47 && part[start] == 0 {
            start += 1;
        }
        let body = &part[start..];
        let pad = body[0] >= 0x80;
        out[pos] = 0x02;
        out[pos + 1] = (body.len() + pad as usize) as u8;
        pos += 2;
        if pad {
            out[pos] = 0;
            pos += 1;
        }
        out[pos..pos + body.len()].copy_from_slice(body);
        pos += body.len();
        half += 1;
    }
    out[0] = 0x30;
    out[1] = (pos - 2) as u8;
    (out, pos)
}
