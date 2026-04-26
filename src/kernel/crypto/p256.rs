//! P-256 (secp256r1) ECDH and ECDSA for the kernel KEY_VAULT backend.
//!
//! Pure Rust, no_std, no heap. Field arithmetic over
//! p = 2^256 - 2^224 + 2^192 + 2^96 - 1. Jacobian coordinates for point
//! ops, constant-time Montgomery ladder for scalar multiplication, RFC 6979
//! deterministic nonces for ECDSA signing, low-s normalisation, volatile
//! zeroisation of intermediate secrets.
//!
//! The `pic_u256` / `pic_u64` helpers assemble curve constants from u32
//! immediates — harmless on kernel hosts, required on the PIC copy where
//! ADRP-based literal pool loads miscompile.

#![allow(dead_code)]

use sha2::{Digest, Sha256};

// ============================================================================
// HMAC-SHA256 (RFC 2104) — backs RFC 6979 nonce derivation.
// ============================================================================

const HMAC_BLOCK: usize = 64;
const HMAC_OUT: usize = 32;

fn hmac_sha256(key: &[u8], msg: &[u8], out: &mut [u8; HMAC_OUT]) {
    let mut k_block = [0u8; HMAC_BLOCK];
    if key.len() > HMAC_BLOCK {
        let mut h = Sha256::new();
        h.update(key);
        let d = h.finalize();
        k_block[..HMAC_OUT].copy_from_slice(&d);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; HMAC_BLOCK];
    let mut opad = [0x5Cu8; HMAC_BLOCK];
    for i in 0..HMAC_BLOCK {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let d = outer.finalize();
    out.copy_from_slice(&d);
}

/// Load P-256 prime.
#[inline(never)]
fn load_p() -> U256 {
    pic_u256([
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001,
        0xFFFFFFFF,
    ])
}

/// Load P-256 order n.
#[inline(never)]
fn load_n() -> U256 {
    pic_u256([
        0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
        0xFFFFFFFF,
    ])
}

/// Load generator point Gx.
#[inline(never)]
fn load_gx() -> U256 {
    pic_u256([
        0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81, 0x63A440F2, 0xF8BCE6E5, 0xE12C4247,
        0x6B17D1F2,
    ])
}

/// Load generator point Gy.
#[inline(never)]
fn load_gy() -> U256 {
    pic_u256([
        0x37BF51F5, 0xCBB64068, 0x6B315ECE, 0x2BCE3357, 0x7C0F9E16, 0x8EE7EB4A, 0xFE1A7F9B,
        0x4FE342E2,
    ])
}

/// Load N/2 for low-s normalisation.
#[inline(never)]
fn load_n_half() -> U256 {
    pic_u256([
        0x7E3192A8, 0x79DCE561, 0xD38BCF42, 0xDE737556, 0xFFFFFFFF, 0xFFFFFFFF, 0x80000000,
        0x7FFFFFFF,
    ])
}

// ============================================================================
// 256-bit unsigned integer arithmetic
// ============================================================================

type U256 = [u64; 4];

const ZERO: U256 = [0, 0, 0, 0];
const ONE: U256 = [1, 0, 0, 0];

/// Assemble a u64 from two u32 halves via volatile writes. Forces MOV/MOVK
/// code generation instead of an ADRP-based literal pool load.
#[inline(always)]
fn pic_u64(lo: u32, hi: u32) -> u64 {
    let mut v = 0u64;
    unsafe {
        let p = &mut v as *mut u64 as *mut u32;
        core::ptr::write_volatile(p, lo);
        core::ptr::write_volatile(p.add(1), hi);
    }
    v
}

/// Build a U256 from 8 u32 halves: `[lo0, hi0, lo1, hi1, lo2, hi2, lo3, hi3]`.
#[inline(never)]
fn pic_u256(words: [u32; 8]) -> U256 {
    [
        pic_u64(words[0], words[1]),
        pic_u64(words[2], words[3]),
        pic_u64(words[4], words[5]),
        pic_u64(words[6], words[7]),
    ]
}

/// a + b, returns (result, carry)
#[inline]
fn u256_add(a: &U256, b: &U256) -> (U256, u64) {
    let mut r = [0u64; 4];
    let mut carry = 0u64;
    let mut i = 0;
    while i < 4 {
        let sum = (a[i] as u128) + (b[i] as u128) + (carry as u128);
        r[i] = sum as u64;
        carry = (sum >> 64) as u64;
        i += 1;
    }
    (r, carry)
}

/// a - b, returns (result, borrow)
#[inline]
fn u256_sub(a: &U256, b: &U256) -> (U256, u64) {
    let mut r = [0u64; 4];
    let mut borrow = 0u64;
    let mut i = 0;
    while i < 4 {
        let diff = (a[i] as u128)
            .wrapping_sub(b[i] as u128)
            .wrapping_sub(borrow as u128);
        r[i] = diff as u64;
        borrow = if diff > (a[i] as u128) + (!borrow as u128) + 1 {
            1
        } else {
            // Check if borrow occurred: if a < b + prev_borrow
            if (a[i] as u128) < (b[i] as u128) + (borrow as u128) {
                1
            } else {
                0
            }
        };
        i += 1;
    }
    (r, borrow)
}

/// Compare: returns 1 if a >= b, 0 otherwise. Constant-time.
fn u256_gte(a: &U256, b: &U256) -> u64 {
    // Compute a - b with borrow tracking across all 4 limbs.
    // If no borrow out, a >= b.
    let mut borrow: u64 = 0;
    let mut i = 0;
    while i < 4 {
        let (diff, b1) = a[i].overflowing_sub(b[i]);
        let (_, b2) = diff.overflowing_sub(borrow);
        borrow = (b1 as u64) | (b2 as u64);
        i += 1;
    }
    // borrow is 1 if a < b, 0 if a >= b
    1 - borrow
}

fn u256_is_zero(a: &U256) -> bool {
    a[0] | a[1] | a[2] | a[3] == 0
}

// ============================================================================
// Modular arithmetic mod p (P-256 prime)
// ============================================================================

/// Reduce mod p
fn mod_p(a: &U256) -> U256 {
    let p = load_p();
    let (r, borrow) = u256_sub(a, &p);
    if borrow == 0 {
        r
    } else {
        *a
    }
}

/// Modular addition: (a + b) mod p
fn fp_add(a: &U256, b: &U256) -> U256 {
    let p = load_p();
    let (sum, carry) = u256_add(a, b);
    if carry != 0 || u256_gte(&sum, &p) != 0 {
        let (r, _) = u256_sub(&sum, &p);
        r
    } else {
        sum
    }
}

/// Modular subtraction: (a - b) mod p
fn fp_sub(a: &U256, b: &U256) -> U256 {
    let p = load_p();
    let (diff, borrow) = u256_sub(a, b);
    if borrow != 0 {
        let (r, _) = u256_add(&diff, &p);
        r
    } else {
        diff
    }
}

/// 256×256 → 512 bit multiplication
fn u256_mul_wide(a: &U256, b: &U256) -> [u64; 8] {
    let mut r = [0u128; 8];

    let mut i = 0;
    while i < 4 {
        let mut j = 0;
        while j < 4 {
            let prod = (a[i] as u128) * (b[j] as u128);
            r[i + j] += prod;
            // Propagate carry in u128 space
            r[i + j + 1] += r[i + j] >> 64;
            r[i + j] &= 0xFFFFFFFFFFFFFFFF;
            j += 1;
        }
        i += 1;
    }

    let mut out = [0u64; 8];
    i = 0;
    while i < 8 {
        out[i] = r[i] as u64;
        i += 1;
    }
    out
}

/// Barrett-like reduction mod p for P-256
/// Uses the special form of P-256 prime for fast reduction
fn fp_reduce(t: &[u64; 8]) -> U256 {
    // P-256 reduction using the NIST method (FIPS 186-4, D.2.3)
    // p = 2^256 - 2^224 + 2^192 + 2^96 - 1
    // Split 512-bit t into 32-bit words for NIST reduction
    let mut s = [0u32; 16];
    let mut i = 0;
    while i < 8 {
        s[i * 2] = t[i] as u32;
        s[i * 2 + 1] = (t[i] >> 32) as u32;
        i += 1;
    }

    // NIST reduction for P-256
    // s1 = (s7, s6, s5, s4, s3, s2, s1, s0)
    // s2 = (s15, s14, s13, s12, s11, 0, 0, 0)   * 2
    // s3 = (0, s15, s14, s13, s12, 0, 0, 0)     * 2
    // s4 = (s15, s14, 0, 0, 0, s10, s9, s8)
    // s5 = (s8, s13, s15, s14, s13, s11, s10, s9)
    // s6 = -(s10, s8, 0, 0, 0, s13, s12, s11)
    // s7 = -(s11, s9, 0, 0, s15, s14, s13, s12)
    // s8 = -(s12, 0, s10, s9, s8, s15, s14, s13)
    // s9 = -(s13, 0, s11, s10, s9, 0, s15, s14)
    // result = s1 + s2 + s3 + s4 + s5 - s6 - s7 - s8 - s9 mod p

    // Accumulate into i64 to handle carries/borrows
    let mut acc = [0i64; 8];

    // s1
    acc[0] += s[0] as i64;
    acc[1] += s[1] as i64;
    acc[2] += s[2] as i64;
    acc[3] += s[3] as i64;
    acc[4] += s[4] as i64;
    acc[5] += s[5] as i64;
    acc[6] += s[6] as i64;
    acc[7] += s[7] as i64;

    // s2 * 2: (s15, s14, s13, s12, s11, 0, 0, 0)
    acc[3] += 2 * s[11] as i64;
    acc[4] += 2 * s[12] as i64;
    acc[5] += 2 * s[13] as i64;
    acc[6] += 2 * s[14] as i64;
    acc[7] += 2 * s[15] as i64;

    // s3 * 2: (0, s15, s14, s13, s12, 0, 0, 0)
    acc[3] += 2 * s[12] as i64;
    acc[4] += 2 * s[13] as i64;
    acc[5] += 2 * s[14] as i64;
    acc[6] += 2 * s[15] as i64;

    // s4: (s15, s14, 0, 0, 0, s10, s9, s8)
    acc[0] += s[8] as i64;
    acc[1] += s[9] as i64;
    acc[2] += s[10] as i64;
    acc[6] += s[14] as i64;
    acc[7] += s[15] as i64;

    // s5: (s8, s13, s15, s14, s13, s11, s10, s9)
    acc[0] += s[9] as i64;
    acc[1] += s[10] as i64;
    acc[2] += s[11] as i64;
    acc[3] += s[13] as i64;
    acc[4] += s[14] as i64;
    acc[5] += s[15] as i64;
    acc[6] += s[13] as i64;
    acc[7] += s[8] as i64;

    // -s6: -(s10, s8, 0, 0, 0, s13, s12, s11)
    acc[0] -= s[11] as i64;
    acc[1] -= s[12] as i64;
    acc[2] -= s[13] as i64;
    acc[6] -= s[8] as i64;
    acc[7] -= s[10] as i64;

    // -s7: -(s11, s9, 0, 0, s15, s14, s13, s12)
    acc[0] -= s[12] as i64;
    acc[1] -= s[13] as i64;
    acc[2] -= s[14] as i64;
    acc[3] -= s[15] as i64;
    acc[6] -= s[9] as i64;
    acc[7] -= s[11] as i64;

    // -s8: -(s12, 0, s10, s9, s8, s15, s14, s13)
    acc[0] -= s[13] as i64;
    acc[1] -= s[14] as i64;
    acc[2] -= s[15] as i64;
    acc[3] -= s[8] as i64;
    acc[4] -= s[9] as i64;
    acc[5] -= s[10] as i64;
    acc[7] -= s[12] as i64;

    // -s9: -(s13, 0, s11, s10, s9, 0, s15, s14)
    acc[0] -= s[14] as i64;
    acc[1] -= s[15] as i64;
    acc[3] -= s[9] as i64;
    acc[4] -= s[10] as i64;
    acc[5] -= s[11] as i64;
    acc[7] -= s[13] as i64;

    // Propagate carries through the 32-bit limbs
    let mut carry: i64 = 0;
    i = 0;
    while i < 8 {
        acc[i] += carry;
        carry = acc[i] >> 32;
        acc[i] &= 0xFFFFFFFF;
        i += 1;
    }

    // Reassemble into U256
    let mut result: U256 = [
        (acc[0] as u64) | ((acc[1] as u64) << 32),
        (acc[2] as u64) | ((acc[3] as u64) << 32),
        (acc[4] as u64) | ((acc[5] as u64) << 32),
        (acc[6] as u64) | ((acc[7] as u64) << 32),
    ];

    // Handle negative carry (add p) or excess (subtract p)
    let p = load_p();
    if carry < 0 {
        let mut c = carry;
        while c < 0 {
            let (r, _) = u256_add(&result, &p);
            result = r;
            c += 1;
        }
    } else {
        let mut c = carry;
        while c > 0 {
            let (r, _) = u256_sub(&result, &p);
            result = r;
            c -= 1;
        }
    }

    // Final reduction
    while u256_gte(&result, &p) != 0 {
        let (r, borrow) = u256_sub(&result, &p);
        if borrow != 0 {
            break;
        }
        result = r;
    }

    result
}

/// Modular multiplication: (a * b) mod p
fn fp_mul(a: &U256, b: &U256) -> U256 {
    let t = u256_mul_wide(a, b);
    fp_reduce(&t)
}

/// Wide squaring: a^2 → 512-bit result.
/// Exploits symmetry: cross-products a[i]*a[j] (i≠j) computed once and doubled.
/// 10 multiplications instead of 16 for general multiply.
fn u256_sqr_wide(a: &U256) -> [u64; 8] {
    let mut r = [0u128; 8];

    // Cross-products (i < j only), then double
    let mut i = 0;
    while i < 4 {
        let mut j = i + 1;
        while j < 4 {
            let prod = (a[i] as u128) * (a[j] as u128);
            r[i + j] += prod;
            r[i + j + 1] += r[i + j] >> 64;
            r[i + j] &= 0xFFFFFFFFFFFFFFFF;
            j += 1;
        }
        i += 1;
    }

    // Double all cross-products
    i = 7;
    while i > 0 {
        r[i] = (r[i] << 1) | (r[i - 1] >> 63);
        i -= 1;
    }
    r[0] <<= 1;

    // Add squared terms a[i]*a[i]
    i = 0;
    while i < 4 {
        let sq = (a[i] as u128) * (a[i] as u128);
        r[i * 2] += sq & 0xFFFFFFFFFFFFFFFF;
        r[i * 2 + 1] += r[i * 2] >> 64;
        r[i * 2] &= 0xFFFFFFFFFFFFFFFF;
        r[i * 2 + 1] += sq >> 64;
        if i < 3 {
            r[i * 2 + 2] += r[i * 2 + 1] >> 64;
            r[i * 2 + 1] &= 0xFFFFFFFFFFFFFFFF;
        }
        i += 1;
    }

    let mut out = [0u64; 8];
    i = 0;
    while i < 8 {
        out[i] = r[i] as u64;
        i += 1;
    }
    out
}

/// Modular squaring: a^2 mod p
fn fp_sqr(a: &U256) -> U256 {
    fp_mul(a, a)
}

/// Modular inversion using Fermat's little theorem: a^(p-2) mod p
fn fp_inv(a: &U256) -> U256 {
    // p-2 = 2^256 - 2^224 + 2^192 + 2^96 - 3
    // Use square-and-multiply with optimized addition chain
    let mut result = ONE;
    let mut base = *a;

    // Simple right-to-left binary method on p-2
    let p_minus_2 = pic_u256([
        0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001,
        0xFFFFFFFF,
    ]);

    let mut i = 0;
    while i < 4 {
        let mut j = 0;
        while j < 64 {
            if (p_minus_2[i] >> j) & 1 == 1 {
                result = fp_mul(&result, &base);
            }
            base = fp_sqr(&base);
            j += 1;
        }
        i += 1;
    }
    result
}

// ============================================================================
// Modular arithmetic mod n (curve order)
// ============================================================================

fn mod_n_reduce(a: &U256) -> U256 {
    let n = load_n();
    if u256_gte(a, &n) != 0 {
        let (r, borrow) = u256_sub(a, &n);
        if borrow == 0 {
            return r;
        }
    }
    *a
}

fn fn_add(a: &U256, b: &U256) -> U256 {
    let n = load_n();
    let (sum, carry) = u256_add(a, b);
    if carry != 0 || u256_gte(&sum, &n) != 0 {
        let (r, _) = u256_sub(&sum, &n);
        r
    } else {
        sum
    }
}

fn fn_mul(a: &U256, b: &U256) -> U256 {
    let t = u256_mul_wide(a, b);
    // Use general Barrett reduction for mod n
    // For simplicity, use repeated subtraction from wide result
    fn_reduce_wide(&t)
}

fn fn_reduce_wide(t: &[u64; 8]) -> U256 {
    // Reduce 512-bit value t mod n using iterative: t_hi * R + t_lo
    // R = 2^256 - n (small, ~128 bits)
    let r_mod = pic_u256([
        0x039CDAAF, 0x0C46353D, 0x58E8617B, 0x43190552, 0x00000000, 0x00000000, 0xFFFFFFFF,
        0x00000000,
    ]);

    let mut acc = [0u64; 8];
    unsafe {
        core::ptr::copy_nonoverlapping(t.as_ptr(), acc.as_mut_ptr(), 8);
    }

    // Each iteration: acc = acc_lo + acc_hi * R
    // Convergence: ~128 bits per iteration (R is ~128 bits)
    // 512 bits → need ~4 iterations (512→384→256+→256→done)
    // But some products produce larger intermediates, need up to 10
    let mut iters = 0;
    while (acc[4] | acc[5] | acc[6] | acc[7]) != 0 && iters < 16 {
        let lo: U256 = [acc[0], acc[1], acc[2], acc[3]];
        let hi: U256 = [acc[4], acc[5], acc[6], acc[7]];
        let prod = u256_mul_wide(&hi, &r_mod);

        let mut carry = 0u128;
        let mut i = 0;
        while i < 4 {
            let s = prod[i] as u128 + lo[i] as u128 + carry;
            acc[i] = s as u64;
            carry = s >> 64;
            i += 1;
        }
        while i < 8 {
            let s = prod[i] as u128 + carry;
            acc[i] = s as u64;
            carry = s >> 64;
            i += 1;
        }
        iters += 1;
    }

    mod_n_reduce(&[acc[0], acc[1], acc[2], acc[3]])
}

/// Modular inverse mod n using Fermat's little theorem
fn fn_inv(a: &U256) -> U256 {
    let mut result = ONE;
    let mut base = *a;

    let n = load_n();
    let n_minus_2: U256 = [n[0] - 2, n[1], n[2], n[3]];

    let mut i = 0;
    while i < 4 {
        let mut j = 0;
        while j < 64 {
            if (n_minus_2[i] >> j) & 1 == 1 {
                result = fn_mul(&result, &base);
            }
            base = fn_mul(&base, &base);
            j += 1;
        }
        i += 1;
    }
    result
}

// ============================================================================
// Constant-time helpers
// ============================================================================

/// Zeroise a byte buffer via volatile writes. `#[inline(never)]` prevents
/// the compiler from eliding the stores after proving the buffer is dead.
#[inline(never)]
fn zeroize(buf: &mut [u8]) {
    let mut i = 0;
    while i < buf.len() {
        unsafe {
            core::ptr::write_volatile(buf.as_mut_ptr().add(i), 0);
        }
        i += 1;
    }
}

/// Zeroise a U256 via volatile writes.
#[inline(never)]
fn zeroize_u256(v: &mut U256) {
    let mut i = 0;
    while i < 4 {
        unsafe {
            core::ptr::write_volatile(v.as_mut_ptr().add(i), 0);
        }
        i += 1;
    }
}

// ============================================================================
// Point operations (Jacobian coordinates: X, Y, Z where x = X/Z^2, y = Y/Z^3)
// ============================================================================

struct JacobianPoint {
    x: U256,
    y: U256,
    z: U256,
}

/// Constant-time conditional swap: swap a and b if condition == 1, no-op if 0.
/// Branchless: uses arithmetic masking.
fn ct_swap(a: &mut JacobianPoint, b: &mut JacobianPoint, condition: u8) {
    let mask = (condition as u64).wrapping_neg(); // 0x0000... or 0xFFFF...
    let mut i = 0;
    while i < 4 {
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

impl JacobianPoint {
    const fn identity() -> Self {
        Self {
            x: ZERO,
            y: ONE,
            z: ZERO,
        }
    }

    fn is_identity(&self) -> bool {
        u256_is_zero(&self.z)
    }

    fn from_affine(x: &U256, y: &U256) -> Self {
        Self {
            x: *x,
            y: *y,
            z: ONE,
        }
    }

    fn to_affine(&self) -> (U256, U256) {
        if self.is_identity() {
            return (ZERO, ZERO);
        }
        let z_inv = fp_inv(&self.z);
        let z_inv2 = fp_sqr(&z_inv);
        let z_inv3 = fp_mul(&z_inv2, &z_inv);
        let x = fp_mul(&self.x, &z_inv2);
        let y = fp_mul(&self.y, &z_inv3);
        (x, y)
    }

    /// Point doubling in Jacobian coordinates
    fn double(&self) -> Self {
        if self.is_identity() {
            return JacobianPoint::identity();
        }

        // Using "dbl-2001-b" formulas (faster for a = -3)
        let s = fp_mul(&self.y, &self.y);
        let mut m = fp_mul(&self.x, &self.x);
        m = fp_add(&fp_add(&m, &m), &m); // 3 * x^2
                                         // For P-256, a = -3, so add a*z^4
        let z2 = fp_sqr(&self.z);
        let z4 = fp_sqr(&z2);
        // -3 * z^4 = p - 3*z^4
        let three_z4 = fp_add(&fp_add(&z4, &z4), &z4);
        m = fp_sub(&m, &three_z4);

        let xy2 = fp_mul(&self.x, &s);
        let t = fp_add(&xy2, &xy2); // 2 * x * y^2
        let t2 = fp_add(&t, &t); // 4 * x * y^2

        let x3 = fp_sub(&fp_sqr(&m), &fp_add(&t2, &t2)); // m^2 - 8*x*y^2

        let y2_4 = fp_add(&s, &s); // 2*y^2
        let y4_8 = fp_sqr(&y2_4); // 4*y^4
        let y4_8_2 = fp_add(&y4_8, &y4_8); // 8*y^4

        let y3 = fp_sub(&fp_mul(&m, &fp_sub(&t2, &x3)), &y4_8_2);

        let z3 = fp_mul(&fp_add(&self.y, &self.y), &self.z);

        JacobianPoint {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Point addition (mixed: Q is affine with Z=1)
    fn add_affine(&self, qx: &U256, qy: &U256) -> Self {
        if self.is_identity() {
            return JacobianPoint::from_affine(qx, qy);
        }

        let z1z1 = fp_sqr(&self.z);
        let u2 = fp_mul(qx, &z1z1);
        let s2 = fp_mul(qy, &fp_mul(&self.z, &z1z1));

        let h = fp_sub(&u2, &self.x);
        let r = fp_sub(&s2, &self.y);

        if u256_is_zero(&h) {
            if u256_is_zero(&r) {
                return self.double();
            }
            return JacobianPoint::identity();
        }

        let hh = fp_sqr(&h);
        let hhh = fp_mul(&h, &hh);
        let v = fp_mul(&self.x, &hh);

        let x3 = fp_sub(&fp_sub(&fp_sqr(&r), &hhh), &fp_add(&v, &v));
        let y3 = fp_sub(&fp_mul(&r, &fp_sub(&v, &x3)), &fp_mul(&self.y, &hhh));
        let z3 = fp_mul(&self.z, &h);

        JacobianPoint {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Full Jacobian-Jacobian point addition (both points in Jacobian coords).
    /// Required for constant-time Montgomery ladder.
    fn add_jacobian(&self, other: &JacobianPoint) -> Self {
        if self.is_identity() {
            return JacobianPoint {
                x: other.x,
                y: other.y,
                z: other.z,
            };
        }
        if other.is_identity() {
            return JacobianPoint {
                x: self.x,
                y: self.y,
                z: self.z,
            };
        }

        let z1z1 = fp_sqr(&self.z);
        let z2z2 = fp_sqr(&other.z);
        let u1 = fp_mul(&self.x, &z2z2);
        let u2 = fp_mul(&other.x, &z1z1);
        let s1 = fp_mul(&self.y, &fp_mul(&other.z, &z2z2));
        let s2 = fp_mul(&other.y, &fp_mul(&self.z, &z1z1));

        let h = fp_sub(&u2, &u1);
        let r = fp_sub(&s2, &s1);

        if u256_is_zero(&h) {
            if u256_is_zero(&r) {
                return self.double();
            }
            return JacobianPoint::identity();
        }

        let hh = fp_sqr(&h);
        let hhh = fp_mul(&h, &hh);
        let v = fp_mul(&u1, &hh);

        let x3 = fp_sub(&fp_sub(&fp_sqr(&r), &hhh), &fp_add(&v, &v));
        let y3 = fp_sub(&fp_mul(&r, &fp_sub(&v, &x3)), &fp_mul(&s1, &hhh));
        let z3 = fp_mul(&fp_mul(&self.z, &other.z), &h);

        JacobianPoint {
            x: x3,
            y: y3,
            z: z3,
        }
    }
}

/// Constant-time scalar multiplication via Montgomery ladder. R0 and R1
/// are updated on every bit regardless of its value, so execution timing
/// does not leak the secret scalar.
fn scalar_mul_ct(k: &U256, px: &U256, py: &U256) -> JacobianPoint {
    let p_jac = JacobianPoint::from_affine(px, py);
    let mut r0 = JacobianPoint::identity();
    let mut r1 = JacobianPoint {
        x: p_jac.x,
        y: p_jac.y,
        z: p_jac.z,
    };

    let mut i: i32 = 3;
    while i >= 0 {
        let word = k[i as usize];
        let mut j: i32 = 63;
        while j >= 0 {
            let bit = ((word >> j as u32) & 1) as u8;
            ct_swap(&mut r0, &mut r1, bit);
            r1 = r0.add_jacobian(&r1);
            r0 = r0.double();
            ct_swap(&mut r0, &mut r1, bit);
            j -= 1;
        }
        i -= 1;
    }

    r0
}

/// Scalar multiplication: k * G.
fn scalar_mul_base(k: &U256) -> JacobianPoint {
    let gx = load_gx();
    let gy = load_gy();
    scalar_mul_ct(k, &gx, &gy)
}

/// Scalar multiplication: k * P (arbitrary point).
fn scalar_mul(k: &U256, px: &U256, py: &U256) -> JacobianPoint {
    scalar_mul_ct(k, px, py)
}

// ============================================================================
// Serialization
// ============================================================================

fn u256_from_be(bytes: &[u8]) -> U256 {
    // Input: 32 bytes big-endian
    let mut r = [0u64; 4];
    r[3] = u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    r[2] = u64::from_be_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]);
    r[1] = u64::from_be_bytes([
        bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
    ]);
    r[0] = u64::from_be_bytes([
        bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
    ]);
    r
}

fn u256_to_be(a: &U256) -> [u8; 32] {
    let mut out = [0u8; 32];
    let b3 = a[3].to_be_bytes();
    let b2 = a[2].to_be_bytes();
    let b1 = a[1].to_be_bytes();
    let b0 = a[0].to_be_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(b3.as_ptr(), out.as_mut_ptr(), 8);
        core::ptr::copy_nonoverlapping(b2.as_ptr(), out.as_mut_ptr().add(8), 8);
        core::ptr::copy_nonoverlapping(b1.as_ptr(), out.as_mut_ptr().add(16), 8);
        core::ptr::copy_nonoverlapping(b0.as_ptr(), out.as_mut_ptr().add(24), 8);
    }
    out
}

// ============================================================================
// Public API
// ============================================================================

/// Derive the uncompressed P-256 public key (0x04 || X || Y) for the given
/// 32-byte big-endian private scalar.
pub fn public_key_from_scalar(private_key: &[u8; 32]) -> [u8; 65] {
    let mut d = u256_from_be(private_key);
    d = mod_n_reduce(&d);
    if u256_is_zero(&d) {
        d = ONE;
    }
    let point = scalar_mul_base(&d);
    let (x, y) = point.to_affine();
    let mut pk = [0u8; 65];
    pk[0] = 0x04;
    let xb = u256_to_be(&x);
    let yb = u256_to_be(&y);
    pk[1..33].copy_from_slice(&xb);
    pk[33..65].copy_from_slice(&yb);
    pk
}

/// ECDH shared secret: scalar_mult(my_private, peer_public).x
/// peer_pub should be 65 bytes (0x04 || X || Y) or 64 bytes (X || Y)
pub fn ecdh_shared_secret(my_private: &[u8; 32], peer_pub: &[u8]) -> Option<[u8; 32]> {
    let offset = if peer_pub.len() == 65 && peer_pub[0] == 0x04 {
        1
    } else if peer_pub.len() == 64 {
        0
    } else {
        return None;
    };

    let px = u256_from_be(&peer_pub[offset..offset + 32]);
    let py = u256_from_be(&peer_pub[offset + 32..offset + 64]);
    let mut k = u256_from_be(my_private);

    let result = scalar_mul(&k, &px, &py);
    zeroize_u256(&mut k);

    if result.is_identity() {
        return None;
    }
    let (x, _) = result.to_affine();
    Some(u256_to_be(&x))
}

/// RFC 6979 deterministic ECDSA nonce (Section 3.2). k is derived via
/// HMAC-DRBG over (private_key, message_hash), eliminating any dependency
/// on runtime randomness for signing and making signatures reproducible.
fn rfc6979_nonce(private_key: &[u8; 32], hash: &[u8]) -> U256 {
    let _hash_len = 32usize;

    // Truncate/pad hash to 32 bytes
    let mut h1 = [0u8; 32];
    if hash.len() >= 32 {
        unsafe {
            core::ptr::copy_nonoverlapping(hash.as_ptr(), h1.as_mut_ptr(), 32);
        }
    } else {
        let offset = 32 - hash.len();
        unsafe {
            core::ptr::copy_nonoverlapping(hash.as_ptr(), h1.as_mut_ptr().add(offset), hash.len());
        }
    }

    // Step a: h1 = Hash(message) — already have it
    // Step b: V = 0x01 0x01 ... 0x01 (32 bytes)
    let mut v = [0x01u8; 32];
    // Step c: K = 0x00 0x00 ... 0x00 (32 bytes)
    let mut k_hmac = [0x00u8; 32];

    // Step d: K = HMAC(K, V || 0x00 || private_key || h1)
    let mut msg_d = [0u8; 32 + 1 + 32 + 32]; // V(32) + 0x00(1) + x(32) + h1(32) = 97
    unsafe {
        core::ptr::copy_nonoverlapping(v.as_ptr(), msg_d.as_mut_ptr(), 32);
    }
    msg_d[32] = 0x00;
    unsafe {
        core::ptr::copy_nonoverlapping(private_key.as_ptr(), msg_d.as_mut_ptr().add(33), 32);
        core::ptr::copy_nonoverlapping(h1.as_ptr(), msg_d.as_mut_ptr().add(65), 32);
    }
    {
        let mut tmp = [0u8; 32];
        hmac_sha256(&k_hmac, &msg_d[..97], &mut tmp);
        k_hmac = tmp;
    }

    // Step e: V = HMAC(K, V)
    {
        let mut tmp = [0u8; 32];
        hmac_sha256(&k_hmac, &v, &mut tmp);
        v = tmp;
    }

    // Step f: K = HMAC(K, V || 0x01 || private_key || h1)
    unsafe {
        core::ptr::copy_nonoverlapping(v.as_ptr(), msg_d.as_mut_ptr(), 32);
    }
    msg_d[32] = 0x01;
    // private_key and h1 already in place
    {
        let mut tmp = [0u8; 32];
        hmac_sha256(&k_hmac, &msg_d[..97], &mut tmp);
        k_hmac = tmp;
    }

    // Step g: V = HMAC(K, V)
    {
        let mut tmp = [0u8; 32];
        hmac_sha256(&k_hmac, &v, &mut tmp);
        v = tmp;
    }

    // Step h: Loop until valid k is found
    loop {
        // V = HMAC(K, V) — generates candidate
        {
            let mut tmp = [0u8; 32];
            hmac_sha256(&k_hmac, &v, &mut tmp);
            v = tmp;
        }

        let candidate = u256_from_be(&v);
        // k must be in [1, n-1]
        let n = load_n();
        if !u256_is_zero(&candidate) && u256_gte(&candidate, &n) == 0 {
            zeroize(&mut k_hmac);
            return candidate;
        }

        // Retry: K = HMAC(K, V || 0x00), V = HMAC(K, V)
        let mut retry = [0u8; 33];
        unsafe {
            core::ptr::copy_nonoverlapping(v.as_ptr(), retry.as_mut_ptr(), 32);
        }
        retry[32] = 0x00;
        {
            let mut tmp = [0u8; 32];
            hmac_sha256(&k_hmac, &retry[..33], &mut tmp);
            k_hmac = tmp;
        }
        {
            let mut tmp = [0u8; 32];
            hmac_sha256(&k_hmac, &v, &mut tmp);
            v = tmp;
        }
    }
}

/// ECDSA sign over a message hash. The nonce is derived deterministically
/// from the private key and the hash (RFC 6979); the `_random_k` parameter
/// is retained for API compatibility and ignored. Returns the 64-byte
/// signature `r || s` in big-endian form, normalised to low-s.
#[cfg(test)]
mod test_vectors {
    use super::*;

    /// Known-answer ECDSA signature for priv = [0x11; 32] over
    /// sha256("abc"), with deterministic RFC 6979 nonces.
    #[test]
    fn ecdsa_sign_kat() {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"abc");
        let hash = h.finalize();
        let priv_key = [0x11u8; 32];
        let sig = ecdsa_sign(&priv_key, hash.as_slice(), &[0u8; 32]);
        let expected_r: [u8; 32] = [
            0x1e, 0xb9, 0xd8, 0x5c, 0x94, 0x8e, 0xbe, 0xfe, 0x6c, 0xd6, 0x7a, 0xa9, 0x72, 0x0e,
            0xda, 0x41, 0x29, 0xb7, 0x46, 0x8b, 0xfd, 0x52, 0x32, 0x18, 0x47, 0xc5, 0x58, 0x89,
            0xf5, 0x02, 0xa0, 0xea,
        ];
        let expected_s: [u8; 32] = [
            0x2e, 0xf9, 0x07, 0x57, 0x40, 0x35, 0x09, 0x59, 0x2d, 0xac, 0x12, 0x32, 0xea, 0x05,
            0xa1, 0x15, 0xda, 0x2c, 0x36, 0x42, 0x96, 0xd6, 0x2b, 0xeb, 0x00, 0xa1, 0xf7, 0xf8,
            0xa4, 0xa3, 0xe4, 0x23,
        ];
        assert_eq!(&sig[..32], &expected_r);
        assert_eq!(&sig[32..], &expected_s);
    }

    /// Sign / verify round-trip: the signer and the verifier agree on
    /// the same (priv_key, hash) input.
    #[test]
    fn ecdsa_sign_verify_roundtrip() {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"abc");
        let hash = h.finalize();
        let priv_key = [0x11u8; 32];
        let sig = ecdsa_sign(&priv_key, hash.as_slice(), &[0u8; 32]);
        let pub_key = public_key_from_scalar(&priv_key);
        assert!(ecdsa_verify(&pub_key, hash.as_slice(), &sig));
    }

    /// Public key derivation matches a standards-compliant reference
    /// (OpenSSL / pyca cryptography) for a fixed scalar.
    #[test]
    fn public_key_from_scalar_kat() {
        let priv_key = [0x11u8; 32];
        let got = public_key_from_scalar(&priv_key);
        let expected_x: [u8; 32] = [
            0x02, 0x17, 0xe6, 0x17, 0xf0, 0xb6, 0x44, 0x39, 0x28, 0x27, 0x8f, 0x96, 0x99, 0x9e,
            0x69, 0xa2, 0x3a, 0x4f, 0x2c, 0x15, 0x2b, 0xdf, 0x6d, 0x6c, 0xdf, 0x66, 0xe5, 0xb8,
            0x02, 0x82, 0xd4, 0xed,
        ];
        let expected_y: [u8; 32] = [
            0x19, 0x4a, 0x7d, 0xeb, 0xcb, 0x97, 0x71, 0x2d, 0x2d, 0xda, 0x3c, 0xa8, 0x5a, 0xa8,
            0x76, 0x5a, 0x56, 0xf4, 0x5f, 0xc7, 0x58, 0x59, 0x96, 0x52, 0xf2, 0x89, 0x7c, 0x65,
            0x30, 0x6e, 0x57, 0x94,
        ];
        assert_eq!(got[0], 0x04);
        assert_eq!(&got[1..33], &expected_x);
        assert_eq!(&got[33..65], &expected_y);
    }
}

pub fn ecdsa_sign(private_key: &[u8; 32], hash: &[u8], _random_k: &[u8; 32]) -> [u8; 64] {
    let d = u256_from_be(private_key);
    let mut k = rfc6979_nonce(private_key, hash);

    // r = (k * G).x mod n
    let point = scalar_mul_base(&k);
    let (rx, _) = point.to_affine();
    let r = mod_n_reduce(&rx);

    // z = hash (truncated to order bit length if needed)
    let z = if hash.len() >= 32 {
        u256_from_be(&hash[..32])
    } else {
        let mut buf = [0u8; 32];
        unsafe {
            core::ptr::copy_nonoverlapping(
                hash.as_ptr(),
                buf.as_mut_ptr().add(32 - hash.len()),
                hash.len(),
            );
        }
        u256_from_be(&buf)
    };
    let z = mod_n_reduce(&z);

    // s = k^-1 * (z + r * d) mod n
    let k_inv = fn_inv(&k);
    let rd = fn_mul(&r, &d);
    let z_rd = fn_add(&z, &rd);
    let mut s = fn_mul(&k_inv, &z_rd);

    // Low-s normalisation: if s > n/2 replace with n - s.
    let n_half = load_n_half();
    if u256_gte(&s, &n_half) != 0 {
        let n = load_n();
        let (ns, _) = u256_sub(&n, &s);
        s = ns;
    }

    zeroize_u256(&mut k);

    let mut sig = [0u8; 64];
    let rb = u256_to_be(&r);
    let sb = u256_to_be(&s);
    unsafe {
        core::ptr::copy_nonoverlapping(rb.as_ptr(), sig.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(sb.as_ptr(), sig.as_mut_ptr().add(32), 32);
    }
    sig
}

/// ECDSA verify: check (r, s) over message hash with public key
/// sig: 64 bytes (r || s), pub_key: 65 bytes (0x04 || X || Y)
pub fn ecdsa_verify(pub_key: &[u8], hash: &[u8], sig: &[u8]) -> bool {
    if sig.len() < 64 {
        return false;
    }
    let offset = if pub_key.len() == 65 && pub_key[0] == 0x04 {
        1
    } else if pub_key.len() == 64 {
        0
    } else {
        return false;
    };

    let r = u256_from_be(&sig[..32]);
    let s = u256_from_be(&sig[32..64]);
    let qx = u256_from_be(&pub_key[offset..offset + 32]);
    let qy = u256_from_be(&pub_key[offset + 32..offset + 64]);

    // Check r, s in [1, n-1]
    let n = load_n();
    if u256_is_zero(&r) || u256_is_zero(&s) {
        return false;
    }
    if u256_gte(&r, &n) != 0 {
        return false;
    }
    if u256_gte(&s, &n) != 0 {
        return false;
    }

    let z = if hash.len() >= 32 {
        u256_from_be(&hash[..32])
    } else {
        let mut buf = [0u8; 32];
        unsafe {
            core::ptr::copy_nonoverlapping(
                hash.as_ptr(),
                buf.as_mut_ptr().add(32 - hash.len()),
                hash.len(),
            );
        }
        u256_from_be(&buf)
    };
    let z = mod_n_reduce(&z);

    let s_inv = fn_inv(&s);
    let u1 = fn_mul(&z, &s_inv);
    let u2 = fn_mul(&r, &s_inv);

    // u1 * G + u2 * Q
    let p1 = scalar_mul_base(&u1);
    let p2 = scalar_mul(&u2, &qx, &qy);

    // Add p1 + p2
    let (p2x, p2y) = p2.to_affine();
    let sum = p1.add_affine(&p2x, &p2y);

    if sum.is_identity() {
        return false;
    }
    let (rx, _) = sum.to_affine();
    let rx_mod_n = mod_n_reduce(&rx);

    // Check r == rx mod n
    rx_mod_n == r
}

/// Parse DER-encoded ECDSA signature into (r, s) raw 64 bytes
/// Copy big-endian integer into fixed-size buffer, handling leading zeros
fn copy_be_padded(src: &[u8], dst: &mut [u8]) {
    // Skip leading zero bytes (DER encoding may prepend 0x00 for positive)
    let mut start = 0;
    while start < src.len() && src[start] == 0 && src.len() - start > dst.len() {
        start += 1;
    }
    let effective = &src[start..];
    if effective.len() > dst.len() {
        return;
    }
    let offset = dst.len() - effective.len();
    // Zero-fill prefix
    let mut i = 0;
    while i < offset {
        dst[i] = 0;
        i += 1;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(
            effective.as_ptr(),
            dst.as_mut_ptr().add(offset),
            effective.len(),
        );
    }
}

/// Encode raw (r,s) signature into DER format
fn skip_leading_zeros(data: &[u8]) -> usize {
    let mut i = 0;
    while i < data.len() - 1 && data[i] == 0 {
        i += 1;
    }
    i
}
