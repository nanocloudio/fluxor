//! P-256 (secp256r1) ECDH and ECDSA for the kernel KEY_VAULT backend.
//!
//! Pure Rust, no_std, no heap. Field arithmetic over
//! p = 2^256 - 2^224 + 2^192 + 2^96 - 1. Jacobian coordinates for point
//! ops, a per-bit Montgomery ladder for scalar multiplication, RFC 6979
//! deterministic nonces for ECDSA signing, low-s normalisation, volatile
//! zeroisation of intermediate secrets.
//!
//! # Timing
//!
//! Every layer that touches secret material is constant-time in its
//! operands. Stated per layer, because a blanket claim asserts more
//! than a reader can check against the code:
//!
//!   1. Field and scalar arithmetic — constant-time. `mod_p`,
//!      `fp_add`, `fp_sub`, `mod_n_reduce` and `fn_add` compute the
//!      correction unconditionally and select it with
//!      `ct_select_u256` on a carry/borrow mask. `fp_reduce` applies a
//!      fixed five masked additions then eight masked subtractions
//!      instead of correcting in value-dependent loops, and
//!      `fn_reduce_wide` folds a fixed sixteen passes. A field multiply
//!      therefore costs the same whatever it multiplies.
//!   2. Point arithmetic — constant-time. `double` has no exceptional
//!      case to branch on, and `add_jacobian`/`add_affine` compute the
//!      generic add, the doubling and the identity outcomes and choose
//!      between them with masked selects, at the cost of one extra
//!      doubling per addition.
//!   3. Inversion — constant-time. `fp_inv` and `fn_inv` are
//!      square-and-multiply over the public exponents p-2 and n-2, so
//!      the schedule was never secret, and each of their ~512
//!      multiplies is fixed-cost per (1). `fn_inv` is applied to
//!      the ECDSA nonce `k`.
//!
//! This matters because the surface is reachable from module code
//! across a privilege boundary: `key_vault.rs` drives these primitives
//! from the KEY_VAULT `SIGN` and `ECDH` opcodes, over a long-lived slot
//! key.
//!
//! Named exceptions, none of them in the arithmetic stack:
//!
//!   - `rfc6979_nonce` retries when a candidate falls outside [1, n-1],
//!     so its duration reveals how many candidates were rejected. That
//!     is the RFC 6979 construction itself, and the retry probability
//!     is about 2^-32 per attempt.
//!   - `decode_private_scalar` and `decode_public_point` branch on
//!     whether an input is admissible. That decision is reported to the
//!     caller regardless.
//!   - The low-s normalisation in `ecdsa_sign` branches on `s`, which
//!     is half of the signature it is about to publish.
//!   - ECDSA *verification* is deliberately variable-time; it handles
//!     only public inputs.
//!
//! Not claimed: that the emitted machine code is constant-time. These
//! are source-level properties — no `black_box`-style barriers are
//! placed against an optimiser reintroducing a branch, and nothing in
//! the tree measures cycle counts.
//!
//! `ed25519.rs` in this directory is the other constant-time signature
//! primitive: complete unified formulas, branchless field arithmetic,
//! branchless table lookup, no identity special cases.
//!
//! ECDSA signing uses RFC 6979 deterministic nonces and normalises
//! signatures to low-s form. Intermediate secrets are zeroised via
//! volatile writes before returning from each primitive.
//!
//! The `pic_u256` / `pic_u64` helpers assemble curve constants from u32
//! immediates — harmless on kernel hosts, required on the PIC copy where
//! ADRP-based literal pool loads miscompile.

#![allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]

use super::sha256::Sha256;

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
    inner.update(&ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_digest);
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

/// Load P-256 curve coefficient b.
#[inline(never)]
fn load_b() -> U256 {
    pic_u256([
        0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0, 0x769886BC, 0xB3EBBD55, 0xAA3A93E7,
        0x5AC635D8,
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
        0x7E3192A8, 0x79DCE561, 0xD38BCF42, 0xDE737D56, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000,
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
    // SAFETY: `&mut v` cast to `*mut u32` yields a properly-aligned
    // pointer (u64 is 8-byte aligned, so u32-aligned too); writes of
    // 4 + 4 = 8 bytes fit inside the u64 stack local.
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

/// a - b, returns (result, borrow). Branchless: the borrow-out of each
/// limb is bit 64 of the u128 difference, which is set exactly when the
/// subtraction wrapped.
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
        borrow = ((diff >> 64) & 1) as u64;
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
// Modular arithmetic mod p (P-256 prime).
//
// Every routine in this section is constant-time in its operands.
// `mod_p`, `fp_add` and `fp_sub` compute both the corrected and the
// uncorrected value and choose between them with `ct_select_u256` on a
// mask built from the carry or borrow; `fp_reduce` performs a fixed
// number of masked corrections rather than looping until the value is
// in range.
// ============================================================================

/// Reduce mod p, for `a < 2p`. Computes `a - p` and selects it over `a`
/// on the subtraction borrow; the borrow is 1 exactly when `a < p`.
fn mod_p(a: &U256) -> U256 {
    let p = load_p();
    let (r, borrow) = u256_sub(a, &p);
    ct_select_u256(&r, a, borrow.wrapping_neg())
}

/// Modular addition: (a + b) mod p. The correction is always computed
/// and selected under a mask.
fn fp_add(a: &U256, b: &U256) -> U256 {
    let p = load_p();
    let (sum, carry) = u256_add(a, b);
    let (corrected, _) = u256_sub(&sum, &p);
    // Subtract p when the 256-bit sum overflowed or is already >= p.
    // Both `carry` and `u256_gte` are 0/1 and neither is branched on.
    let need = carry | u256_gte(&sum, &p);
    ct_select_u256(&sum, &corrected, need.wrapping_neg())
}

/// Modular subtraction: (a - b) mod p. The correction is always
/// computed and selected under a mask.
fn fp_sub(a: &U256, b: &U256) -> U256 {
    let p = load_p();
    let (diff, borrow) = u256_sub(a, b);
    let (corrected, _) = u256_add(&diff, &p);
    ct_select_u256(&diff, &corrected, borrow.wrapping_neg())
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

    // Fixed-trip-count correction. The value being reduced is
    //   V = carry·2^256 + result
    // with `carry` signed. The NIST sum above adds at most
    // (1 + 2 + 2 + 1 + 1) = 7 and subtracts at most 4 full 256-bit
    // terms, so V lies in (-4·2^256, 7·2^256).
    //
    // Both phases run a fixed number of iterations and apply their
    // correction under a mask, so neither the trip count nor the
    // branch pattern depends on V.
    let p = load_p();

    // Phase 1 — lift V to non-negative. Adding p when V < 0 preserves
    // the invariant either way: if `result + p` overflows, the carry-out
    // cancels one unit of 2^256, otherwise `carry` is unchanged and the
    // whole value still rises by p. Since p > 0.99·2^256 and
    // V > -4·2^256, five additions always suffice.
    let mut i2 = 0;
    while i2 < 5 {
        // All-ones exactly when `carry` is negative.
        let neg = (carry >> 63) as u64;
        let (sum, carry_out) = u256_add(&result, &p);
        result = ct_select_u256(&result, &sum, neg);
        carry = carry.wrapping_add((carry_out & neg & 1) as i64);
        i2 += 1;
    }

    // Phase 2 — bring V below p. V is now in [0, 7·2^256), i.e. under
    // 7.01·p, so eight masked subtractions always suffice. The
    // condition is "carry is non-zero" (then V >= 2^256 > p) "or the
    // low 256 bits are already >= p".
    let mut i3 = 0;
    while i3 < 8 {
        let c = carry as u64;
        // All-ones when `carry != 0`.
        let carry_nonzero = !ct_eq_u64(c, 0);
        let need = carry_nonzero | u256_gte(&result, &p).wrapping_neg();
        let (diff, borrow) = u256_sub(&result, &p);
        result = ct_select_u256(&result, &diff, need);
        carry = carry.wrapping_sub((borrow & need & 1) as i64);
        i3 += 1;
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
// Modular arithmetic mod n (curve order).
//
// Constant-time in its operands, on the same terms as the mod-p
// section: masked corrections instead of conditional ones, and a
// fixed-trip-count fold in `fn_reduce_wide`. This layer carries the
// ECDSA nonce and the KEY_VAULT slot scalar.
// ============================================================================

/// Reduce mod n, for `a < 2n`. Since `n > 2^255`, any 256-bit input
/// satisfies that, so one masked conditional subtraction is exact.
fn mod_n_reduce(a: &U256) -> U256 {
    let n = load_n();
    let (r, borrow) = u256_sub(a, &n);
    ct_select_u256(&r, a, borrow.wrapping_neg())
}

fn fn_add(a: &U256, b: &U256) -> U256 {
    let n = load_n();
    let (sum, carry) = u256_add(a, b);
    let (corrected, _) = u256_sub(&sum, &n);
    let need = carry | u256_gte(&sum, &n);
    ct_select_u256(&sum, &corrected, need.wrapping_neg())
}

fn fn_mul(a: &U256, b: &U256) -> U256 {
    let t = u256_mul_wide(a, b);
    // Use general Barrett reduction for mod n
    // For simplicity, use repeated subtraction from wide result
    fn_reduce_wide(&t)
}

/// Reduce a 512-bit value mod n.
///
/// Constant-time: the fold runs a fixed 16 passes whatever the value.
/// A pass whose high half is already zero multiplies by zero and adds
/// the low half back unchanged, so running the full count is
/// idempotent once the value has converged — the cost is fixed rather
/// than data-dependent. `fn_inv` reduces the ECDSA nonce here.
fn fn_reduce_wide(t: &[u64; 8]) -> U256 {
    // Reduce 512-bit value t mod n using iterative: t_hi * R + t_lo
    // R = 2^256 - n (small, ~128 bits)
    let r_mod = pic_u256([
        0x039CDAAF, 0x0C46353D, 0x58E8617B, 0x43190552, 0x00000000, 0x00000000, 0xFFFFFFFF,
        0x00000000,
    ]);

    let mut acc = [0u64; 8];
    // SAFETY: both `t` and `acc` are `[u64; 8]`; 8 u64 elements = 64 bytes,
    // identical layout, disjoint stack locations.
    unsafe {
        core::ptr::copy_nonoverlapping(t.as_ptr(), acc.as_mut_ptr(), 8);
    }

    // Each iteration: acc = acc_lo + acc_hi * R.
    //
    // R = 2^256 - n is just under 2^224, so one pass takes a value of
    // bit length B to about B - 31. Sixteen passes therefore carry any
    // 512-bit input down below 2^256 with margin, and passes beyond
    // convergence are no-ops (acc_hi = 0 ⇒ the product is 0 and acc_lo
    // is copied back). The loop is unconditional so the trip count
    // does not depend on the value.
    let mut iters = 0;
    while iters < 16 {
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
        // SAFETY: `i < buf.len()` (loop bound); volatile write keeps the
        // store live even when the compiler proves the buffer is dead.
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
        // SAFETY: `i < 4 = U256::len()`; volatile write through fixed-size array.
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

/// Constant-time u64 equality: returns `0xFFFF_FFFF_FFFF_FFFF` if
/// `a == b`, else 0. No data-dependent branch.
#[inline(always)]
fn ct_eq_u64(a: u64, b: u64) -> u64 {
    let x = a ^ b;
    // `(x | -x) >> 63` is 1 when x != 0 and 0 when x == 0; invert the
    // low bit and sign-extend it to a full mask.
    let bit = !((x | x.wrapping_neg()) >> 63) & 1;
    bit.wrapping_neg()
}

/// Constant-time select on a U256: returns `b` if mask is all-ones,
/// `a` if mask is all-zeros.
#[inline(always)]
fn ct_select_u256(a: &U256, b: &U256, mask: u64) -> U256 {
    let mut r = [0u64; 4];
    let mut i = 0;
    while i < 4 {
        r[i] = (a[i] & !mask) | (b[i] & mask);
        i += 1;
    }
    r
}

/// Constant-time zero test on a U256: returns all-ones if every limb
/// is zero, else 0. Folds all four limbs, so the position of the first
/// non-zero limb is not observable.
#[inline(always)]
fn ct_is_zero_u256(a: &U256) -> u64 {
    ct_eq_u64(a[0] | a[1] | a[2] | a[3], 0)
}

/// Constant-time select on a whole Jacobian point.
#[inline(always)]
fn ct_select_point(a: &JacobianPoint, b: &JacobianPoint, mask: u64) -> JacobianPoint {
    JacobianPoint {
        x: ct_select_u256(&a.x, &b.x, mask),
        y: ct_select_u256(&a.y, &b.y, mask),
        z: ct_select_u256(&a.z, &b.z, mask),
    }
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

    /// Point doubling in Jacobian coordinates.
    ///
    /// No identity short-circuit: the dbl-2001-b formulas produce
    /// `z3 = 2yz = 0` from `z = 0`, so an identity input yields a
    /// semantically-identity output whatever x3/y3 carry. The routine
    /// therefore has no data-dependent branch.
    fn double(&self) -> Self {
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

    /// Point addition (mixed: Q is affine with Z=1).
    ///
    /// Exception-free by evaluation rather than by formula: the generic
    /// add and the doubling are both computed unconditionally, and the
    /// four outcomes — P is identity, `h == 0 && r == 0` (doubling),
    /// `h == 0 && r != 0` (inverse points, result is identity), and the
    /// generic case — are chosen between with masked selects. No input
    /// value selects a control-flow edge or a load address, so the
    /// duration of the call does not reveal which case the inputs fell
    /// into. The cost is one extra doubling per addition.
    fn add_affine(&self, qx: &U256, qy: &U256) -> Self {
        let z1z1 = fp_sqr(&self.z);
        let u2 = fp_mul(qx, &z1z1);
        let s2 = fp_mul(qy, &fp_mul(&self.z, &z1z1));

        let h = fp_sub(&u2, &self.x);
        let r = fp_sub(&s2, &self.y);

        let hh = fp_sqr(&h);
        let hhh = fp_mul(&h, &hh);
        let v = fp_mul(&self.x, &hh);

        let x3 = fp_sub(&fp_sub(&fp_sqr(&r), &hhh), &fp_add(&v, &v));
        let y3 = fp_sub(&fp_mul(&r, &fp_sub(&v, &x3)), &fp_mul(&self.y, &hhh));
        let z3 = fp_mul(&self.z, &h);
        let generic = JacobianPoint {
            x: x3,
            y: y3,
            z: z3,
        };

        let h_zero = ct_is_zero_u256(&h);
        let r_zero = ct_is_zero_u256(&r);
        let self_id = ct_is_zero_u256(&self.z);

        // h == 0, r != 0 → P and Q are inverses → identity.
        let out = ct_select_point(&generic, &JacobianPoint::identity(), h_zero);
        // h == 0, r == 0 → P == Q → doubling.
        let out = ct_select_point(&out, &self.double(), h_zero & r_zero);
        // P is the identity → the result is Q, whatever the above said.
        ct_select_point(&out, &JacobianPoint::from_affine(qx, qy), self_id)
    }

    /// Full Jacobian-Jacobian point addition (both points in Jacobian
    /// coords). Required for the Montgomery ladder.
    ///
    /// Exception-free on the same terms as `add_affine`, with a second
    /// identity test on the right-hand operand. All five outcomes are
    /// computed and selected under masks, so the leading zero bits of
    /// the ladder scalar — which leave `r0` at the identity — take the
    /// same path as the rest.
    fn add_jacobian(&self, other: &JacobianPoint) -> Self {
        let z1z1 = fp_sqr(&self.z);
        let z2z2 = fp_sqr(&other.z);
        let u1 = fp_mul(&self.x, &z2z2);
        let u2 = fp_mul(&other.x, &z1z1);
        let s1 = fp_mul(&self.y, &fp_mul(&other.z, &z2z2));
        let s2 = fp_mul(&other.y, &fp_mul(&self.z, &z1z1));

        let h = fp_sub(&u2, &u1);
        let r = fp_sub(&s2, &s1);

        let hh = fp_sqr(&h);
        let hhh = fp_mul(&h, &hh);
        let v = fp_mul(&u1, &hh);

        let x3 = fp_sub(&fp_sub(&fp_sqr(&r), &hhh), &fp_add(&v, &v));
        let y3 = fp_sub(&fp_mul(&r, &fp_sub(&v, &x3)), &fp_mul(&s1, &hhh));
        let z3 = fp_mul(&fp_mul(&self.z, &other.z), &h);
        let generic = JacobianPoint {
            x: x3,
            y: y3,
            z: z3,
        };

        let h_zero = ct_is_zero_u256(&h);
        let r_zero = ct_is_zero_u256(&r);
        let self_id = ct_is_zero_u256(&self.z);
        let other_id = ct_is_zero_u256(&other.z);

        // h == 0, r != 0 → inverse points → identity.
        let out = ct_select_point(&generic, &JacobianPoint::identity(), h_zero);
        // h == 0, r == 0 → the same point → doubling.
        let out = ct_select_point(&out, &self.double(), h_zero & r_zero);
        // Either operand being the identity overrides all of the above.
        // `other_id` is applied last so that identity + identity yields
        // the identity rather than a copy of `other`'s coordinates.
        let out = ct_select_point(&out, other, self_id);
        ct_select_point(&out, self, other_id)
    }
}

/// Scalar multiplication via a per-bit Montgomery ladder: R0 and R1 are
/// both updated on every bit, and the swap is branchless.
///
/// # Timing
///
/// Constant-time in the scalar. The ladder is regular — one add and
/// one double per bit whatever the bit is — [`ct_swap`] masks and XORs
/// all three coordinate limbs unconditionally, [`JacobianPoint::double`]
/// and [`JacobianPoint::add_jacobian`] have no exceptional-case
/// branches, and the `fp_*`/`fn_*` layers underneath have fixed trip
/// counts with masked corrections. No scalar bit selects a
/// control-flow edge or a load address anywhere beneath this function.
///
/// That property is load-bearing rather than hygiene: for ECDSA the
/// multiplied scalar is the per-signature nonce `k`, partial knowledge
/// of which across a set of signatures is the input to
/// hidden-number-problem lattice recovery of the long-term key, and for
/// ECDH it is the vault's private key itself, measured again on every
/// agreement.
///
/// What is still not covered: the compiler and the microarchitecture.
/// This file states what the source does, not what a given optimiser
/// emits, and no test in the tree measures cycle counts.
///
/// KATs in `tests/harness/tests/kernel_crypto_p256.rs` gate correctness
/// of the `(sign, verify, ECDH)` surface against expected outputs.
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
    // SAFETY: four 8-byte copies into the four 8-byte sub-slices of `out`;
    // disjoint sub-ranges totalling exactly 32 bytes.
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

/// Public-key validation: is the affine point (x, y) on the P-256 curve
/// y² ≡ x³ - 3x + b (mod p)?
///
/// Without this gate a caller can submit a point on a different curve
/// (different b) whose order has small factors, and use the resulting
/// ECDH agreements to recover bits of the vault's private scalar over
/// repeated calls — the invalid-curve attack. The KEY_VAULT slot key is
/// long-lived and reachable from module code, so the point must be
/// pinned to P-256 before any scalar multiplication touches it.
pub fn is_on_curve(x: &U256, y: &U256) -> bool {
    let y_sq = fp_sqr(y);
    let x_sq = fp_sqr(x);
    let x_cubed = fp_mul(&x_sq, x);
    let two_x = fp_add(x, x);
    let three_x = fp_add(&two_x, x);
    let rhs = fp_add(&fp_sub(&x_cubed, &three_x), &load_b());
    // Constant-time equality over the U256 limbs.
    let mut diff = 0u64;
    let mut i = 0;
    while i < 4 {
        diff |= y_sq[i] ^ rhs[i];
        i += 1;
    }
    diff == 0
}

/// The single decode-and-validate gate for every P-256 public point that
/// arrives from outside the kernel — KEY_VAULT `ECDH` peer shares and
/// `VERIFY` public keys.
///
/// Accepts the SEC 1 uncompressed encoding `0x04 || X || Y` (65 bytes)
/// and the bare `X || Y` form (64 bytes). Compressed prefixes
/// (`0x02`/`0x03`) are not supported; any other prefix or length is
/// malformed.
///
/// A point survives only if all of these hold:
///   - X and Y are canonical, each numerically less than `p` (a
///     non-reduced coordinate has two encodings, so accepting one lets
///     a caller vary the wire bytes without varying the point);
///   - the point is not the affine identity `(0, 0)`;
///   - it satisfies y² ≡ x³ - 3x + b (mod p), pinning it to P-256
///     rather than another curve over the same field with a smooth
///     order;
///   - it is therefore in the prime-order group, P-256 having cofactor
///     1 and every on-curve non-identity point generating it.
fn decode_public_point(encoded: &[u8]) -> Option<(U256, U256)> {
    let offset = if encoded.len() == 65 {
        if encoded[0] != 0x04 {
            return None;
        }
        1
    } else if encoded.len() == 64 {
        0
    } else {
        return None;
    };

    let x = u256_from_be(&encoded[offset..offset + 32]);
    let y = u256_from_be(&encoded[offset + 32..offset + 64]);

    let p = load_p();
    if u256_gte(&x, &p) != 0 || u256_gte(&y, &p) != 0 {
        return None;
    }
    if x == ZERO && y == ZERO {
        return None;
    }
    if !is_on_curve(&x, &y) {
        return None;
    }
    Some((x, y))
}

/// True when `encoded` is a P-256 public point the kernel will use.
/// Callers holding an encoded key before they need the coordinates gate
/// on this, so a bad point is refused at the boundary it entered through
/// rather than inside a scalar multiplication.
pub fn public_point_is_valid(encoded: &[u8]) -> bool {
    decode_public_point(encoded).is_some()
}

/// Decode a private scalar `d` supplied at an API boundary. `d` must lie
/// in `[1, n-1]`: `d == 0` yields the identity for every input, and
/// `d >= n` is a non-canonical encoding of `d mod n`. Key generation
/// already clamps, but a stored or imported scalar may come from
/// anywhere, so every entry point re-checks.
fn decode_private_scalar(private_key: &[u8; 32]) -> Option<U256> {
    let d = u256_from_be(private_key);
    if u256_is_zero(&d) {
        return None;
    }
    if u256_gte(&d, &load_n()) != 0 {
        return None;
    }
    Some(d)
}

/// Derive the uncompressed P-256 public key (0x04 || X || Y) for the given
/// 32-byte big-endian private scalar.
///
/// Returns None when the scalar is outside `[1, n-1]`.
pub fn public_key_from_scalar(private_key: &[u8; 32]) -> Option<[u8; 65]> {
    let d = decode_private_scalar(private_key)?;
    let point = scalar_mul_base(&d);
    let (x, y) = point.to_affine();
    let mut pk = [0u8; 65];
    pk[0] = 0x04;
    let xb = u256_to_be(&x);
    let yb = u256_to_be(&y);
    pk[1..33].copy_from_slice(&xb);
    pk[33..65].copy_from_slice(&yb);
    Some(pk)
}

/// ECDH shared secret: scalar_mult(my_private, peer_public).x
/// peer_pub should be 65 bytes (0x04 || X || Y) or 64 bytes (X || Y)
///
/// Returns None on:
///   - a private scalar outside [1, n-1];
///   - malformed encoding (wrong length, non-uncompressed prefix);
///   - non-canonical coordinates, the identity, or a point not on the
///     curve;
///   - scalar multiplication producing the point at infinity.
pub fn ecdh_shared_secret(my_private: &[u8; 32], peer_pub: &[u8]) -> Option<[u8; 32]> {
    let (px, py) = decode_public_point(peer_pub)?;
    let mut k = decode_private_scalar(my_private)?;

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
        // SAFETY: `hash.len() >= 32` (branch condition); `h1` is 32 bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(hash.as_ptr(), h1.as_mut_ptr(), 32);
        }
    } else {
        let offset = 32 - hash.len();
        // SAFETY: `offset + hash.len() = 32`; right-pad into the trailing
        // bytes of `h1`.
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
                                             // SAFETY: V is 32 bytes, msg_d is 97 bytes; in-bounds.
    unsafe {
        core::ptr::copy_nonoverlapping(v.as_ptr(), msg_d.as_mut_ptr(), 32);
    }
    msg_d[32] = 0x00;
    // SAFETY: 32+1+32 = 65 < 97; 65+32 = 97 = msg_d.len(); both copies in-bounds.
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
    // SAFETY: V is 32 bytes; msg_d[..32] in-bounds.
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
        // SAFETY: V is 32 bytes; retry[..32] in-bounds.
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
///
/// Returns None when `private_key` is not a valid scalar in [1, n-1]:
/// signing under `d == 0` produces a signature that verifies against the
/// identity, and `d >= n` silently signs under `d mod n`.
pub fn ecdsa_sign(private_key: &[u8; 32], hash: &[u8], _random_k: &[u8; 32]) -> Option<[u8; 64]> {
    let d = decode_private_scalar(private_key)?;
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
        // SAFETY: `hash.len() < 32` (else branch); right-pad into buf's
        // trailing `hash.len()` bytes.
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
    // SAFETY: two 32-byte copies into the two 32-byte halves of `sig`;
    // disjoint sub-ranges totalling exactly 64 bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(rb.as_ptr(), sig.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(sb.as_ptr(), sig.as_mut_ptr().add(32), 32);
    }
    Some(sig)
}

/// ECDSA verify: check (r, s) over message hash with public key
/// sig: 64 bytes (r || s), pub_key: 65 bytes (0x04 || X || Y)
pub fn ecdsa_verify(pub_key: &[u8], hash: &[u8], sig: &[u8]) -> bool {
    if sig.len() < 64 {
        return false;
    }
    // The public point is decoded and fully validated before it can
    // reach a scalar multiplication.
    let (qx, qy) = match decode_public_point(pub_key) {
        Some(q) => q,
        None => return false,
    };

    let r = u256_from_be(&sig[..32]);
    let s = u256_from_be(&sig[32..64]);

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
        // SAFETY: `hash.len() < 32` (else branch); right-pad into buf's
        // trailing `hash.len()` bytes.
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
    // SAFETY: `offset + effective.len() = dst.len()` by construction; copy
    // into the trailing `effective.len()` bytes of `dst`.
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
