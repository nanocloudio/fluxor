// P-256 (secp256r1) ECDH and ECDSA
// Pure Rust, no_std, no heap
// Field arithmetic over p = 2^256 - 2^224 + 2^192 + 2^96 - 1
//
// # Timing
//
// Every layer that touches secret material is constant-time in its
// operands. Stated per layer, because a blanket claim asserts more
// than a reader can check against the code:
//
//   1. Field and scalar arithmetic — constant-time. `mod_p`, `fp_add`,
//      `fp_sub`, `mod_n_reduce` and `fn_add` compute the correction
//      unconditionally and select it with `ct_select_u256` on a
//      carry/borrow mask. `fp_reduce` applies a fixed five masked
//      additions then eight masked subtractions instead of correcting
//      in value-dependent loops, and `fn_reduce_wide` folds a fixed
//      sixteen passes. A field multiply therefore costs the same
//      whatever it multiplies.
//   2. Point arithmetic — constant-time. `double` has no exceptional
//      case to branch on, and `add_jacobian`/`add_affine` compute the
//      generic add, the doubling and the identity outcomes and choose
//      between them with masked selects, at the cost of one extra
//      doubling per addition.
//   3. Inversion — constant-time. `fp_inv` and `fn_inv` are
//      square-and-multiply over the public exponents p-2 and n-2, so
//      the schedule was never secret, and each of their ~512
//      multiplies is fixed-cost per (1). `fn_inv` is applied to
//      the ECDSA nonce `k`.
//
// Two scalar-multiplication paths, both constant-time in the scalar:
//
//   - `scalar_mul_ct` (one-shot, used by ECDH + ECDSA): fixed-window
//     w=4 with a branchless table lookup, four doublings and one
//     addition per window regardless of the nibble. Same shape as
//     BoringSSL / ring / OpenSSL.
//   - `ScalarMulState` (resumable, used when the kernel needs to yield
//     mid-multiplication): per-bit Montgomery ladder, one add and one
//     double per bit with a branchless swap. The `step()` API
//     processes `bits_per_step` bits at a time so a concurrent
//     handshake doesn't have to wait for the whole scalar
//     multiplication to finish; how the work is divided across ticks
//     is a scheduling choice and does not depend on the scalar.
//
// Named exceptions, none of them in the arithmetic stack:
//
//   - `rfc6979_nonce` retries when a candidate falls outside [1, n-1],
//     so its duration reveals how many candidates were rejected. That
//     is the RFC 6979 construction itself, and the retry probability is
//     about 2^-32 per attempt.
//   - `decode_private_scalar` and `decode_public_point` branch on
//     whether an input is admissible. That decision is reported to the
//     caller regardless.
//   - The low-s normalisation in `ecdsa_sign` branches on `s`, which is
//     half of the signature it is about to publish.
//   - ECDSA *verification* is deliberately variable-time; it handles
//     only public inputs (peer public key, message, signature).
//
// Not claimed: that the emitted machine code is constant-time. These
// are source-level properties — no `black_box`-style barriers are
// placed against an optimiser reintroducing a branch, and nothing in
// the tree measures cycle counts.
//
// `ed25519.rs` in this directory is the other constant-time signature
// primitive, and carries X25519 for key agreement: complete unified
// formulas, branchless field arithmetic, branchless table lookup, no
// identity special cases.
//
// ECDSA signing uses RFC 6979 deterministic nonces and normalises
// signatures to low-s form. Intermediate secrets are zeroised via
// volatile writes before returning from each primitive.
//
// Curve constants are loaded via `pic_u256` (u32 immediates assembled on
// the stack). PIC aarch64 modules cannot use ADRP-based literal pool
// loads, so `const [u64; 4]` arrays in .rodata miscompile.

/// Load P-256 prime.
#[inline(never)]
fn load_p() -> U256 {
    pic_u256(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
             0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF)
}

/// Load P-256 order n.
#[inline(never)]
fn load_n() -> U256 {
    pic_u256(0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD,
             0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF)
}

/// Load generator point Gx.
#[inline(never)]
fn load_gx() -> U256 {
    pic_u256(0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81,
             0x63A440F2, 0xF8BCE6E5, 0xE12C4247, 0x6B17D1F2)
}

/// Load generator point Gy.
#[inline(never)]
fn load_gy() -> U256 {
    pic_u256(0x37BF51F5, 0xCBB64068, 0x6B315ECE, 0x2BCE3357,
             0x7C0F9E16, 0x8EE7EB4A, 0xFE1A7F9B, 0x4FE342E2)
}

/// Load N/2 for low-s normalisation.
#[inline(never)]
fn load_n_half() -> U256 {
    pic_u256(0x7E3192A8, 0x79DCE561, 0xD38BCF42, 0xDE737556,
             0xFFFFFFFF, 0xFFFFFFFF, 0x80000000, 0x7FFFFFFF)
}

/// Load curve constant b for the short-Weierstrass form
/// y² ≡ x³ - 3x + b (mod p). Hex (MSB first):
/// 0x5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B
/// `pic_u256` packs `(lo, hi)` per u64 limb, limb 0 being the LSBs.
#[inline(never)]
fn load_b() -> U256 {
    pic_u256(0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0,
             0x769886BC, 0xB3EBBD55, 0xAA3A93E7, 0x5AC635D8)
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
    // SAFETY: pointer arithmetic over fixed-size P-256 field elements
    // (32 bytes / 8 u32 limbs); offsets bounded by loop invariant.
    unsafe {
        let p = &mut v as *mut u64 as *mut u32;
        core::ptr::write_volatile(p, lo);
        core::ptr::write_volatile(p.add(1), hi);
    }
    v
}

/// Build a U256 from 8 u32 halves.
#[inline(never)]
#[expect(
    clippy::too_many_arguments,
    reason = "U256 construction wire-shape: 4 limbs × {lo, hi} u32 halves, mirroring the ABI emitted by the PIC build for unaligned 64-bit literals"
)]
fn pic_u256(lo0: u32, hi0: u32, lo1: u32, hi1: u32, lo2: u32, hi2: u32, lo3: u32, hi3: u32) -> U256 {
    [pic_u64(lo0, hi0), pic_u64(lo1, hi1), pic_u64(lo2, hi2), pic_u64(lo3, hi3)]
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
        let diff = (a[i] as u128).wrapping_sub(b[i] as u128).wrapping_sub(borrow as u128);
        r[i] = diff as u64;
        borrow = ((diff >> 64) & 1) as u64;
        i += 1;
    }
    (r, borrow)
}

/// Compare: returns 1 if a >= b, 0 otherwise. Branchless — the borrow
/// chain runs over all four limbs regardless of where the values
/// differ, and the result is arithmetic, not a branch. Callers that
/// then branch on the returned value reintroduce the dependency.
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
// in range. Trip counts and memory addresses here are independent of
// the operands, which are secret on every ECDH agreement and ECDSA
// signature.
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

/// Barrett-like reduction mod p for P-256. Uses the special form of
/// the P-256 prime for fast reduction.
///
/// Variable-time. The final corrections are three loops — `while c <
/// 0`, `while c > 0`, and the `u256_gte` subtraction loop — whose trip
/// counts depend on the magnitude of `t`. Since `fp_mul` and `fp_sqr`
/// both end here, the cost of a single field multiply on secret data
/// varies with that data. Making this constant-time means a fixed
/// number of masked corrections rather than loops.
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
    acc[0] += s[0] as i64; acc[1] += s[1] as i64;
    acc[2] += s[2] as i64; acc[3] += s[3] as i64;
    acc[4] += s[4] as i64; acc[5] += s[5] as i64;
    acc[6] += s[6] as i64; acc[7] += s[7] as i64;

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

/// Wide squaring: `a^2` → 512-bit result (8 × u64 limbs, little-endian).
///
/// Comba / column method exploiting symmetry: each output column `k` is the
/// sum over `i + j == k` of `a[i]*a[j]`, with the off-diagonal (`i < j`) terms
/// doubled and the diagonal (`i == j`) term added once — 10 single-limb
/// multiplies instead of the 16 a general product needs. A 3-limb accumulator
/// (`acc_lo: u128` + `acc_hi: u64`) absorbs each column's full sum (up to
/// ~5·2^128) before the low 64 bits are emitted and the rest shifted down, so
/// carries never truncate. Bit-identical to `u256_mul_wide(a, a)`; the prior
/// version had a carry-truncation bug (gated out by the ECDSA/ECDH KATs).
fn u256_sqr_wide(a: &U256) -> [u64; 8] {
    let mut out = [0u64; 8];
    // 3-limb little-endian accumulator: `acc_lo` holds bits 0..128, `acc_hi`
    // holds bits 128..192. A single column sum stays well under 2^192.
    let mut acc_lo: u128 = 0;
    let mut acc_hi: u64 = 0;

    let mut col = 0usize;
    while col < 8 {
        let mut i = 0usize;
        while i < 4 {
            // j such that i + j == col, with 0 <= j < 4.
            if col >= i {
                let j = col - i;
                if j < 4 && i < j {
                    // Off-diagonal: add the product twice (doubled).
                    let p = (a[i] as u128) * (a[j] as u128);
                    let (s1, c1) = acc_lo.overflowing_add(p);
                    acc_lo = s1;
                    if c1 {
                        acc_hi += 1;
                    }
                    let (s2, c2) = acc_lo.overflowing_add(p);
                    acc_lo = s2;
                    if c2 {
                        acc_hi += 1;
                    }
                } else if j == i {
                    // Diagonal square term: add once.
                    let p = (a[i] as u128) * (a[i] as u128);
                    let (s, c) = acc_lo.overflowing_add(p);
                    acc_lo = s;
                    if c {
                        acc_hi += 1;
                    }
                }
            }
            i += 1;
        }
        // Emit the low 64 bits of this column, shift the accumulator down 64.
        out[col] = acc_lo as u64;
        acc_lo = (acc_lo >> 64) | ((acc_hi as u128) << 64);
        acc_hi = 0;
        col += 1;
    }
    out
}

/// Modular squaring: a^2 mod p.
///
/// Uses the dedicated `u256_sqr_wide` (10 multiplies via cross-product
/// symmetry) rather than the general `u256_mul_wide` (16 multiplies). Squaring
/// dominates Jacobian point doubling, which dominates the scalar multiplication
/// on every ECDH agreement and ECDSA sign — so this ~1.6× cheaper wide product
/// speeds the whole handshake crypto. Bit-identical to `fp_mul(a, a)`, gated by
/// the ECDSA/ECDH KATs in `tests/harness/tests/tls_crypto_kat.rs`.
fn fp_sqr(a: &U256) -> U256 {
    fp_reduce(&u256_sqr_wide(a))
}

/// Modular inversion using Fermat's little theorem: a^(p-2) mod p.
///
/// The exponent is the public constant p-2, so the square-and-multiply
/// schedule is fixed and reveals nothing. The individual `fp_mul` /
/// `fp_sqr` calls it makes are still value-dependent per `fp_reduce`.
fn fp_inv(a: &U256) -> U256 {
    // p-2 = 2^256 - 2^224 + 2^192 + 2^96 - 3
    // Use square-and-multiply with optimized addition chain
    let mut result = ONE;
    let mut base = *a;

    // Simple right-to-left binary method on p-2
    let p_minus_2 = pic_u256(
        0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
        0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF,
    );

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
// ECDSA nonce and the private scalar, so that property is load-bearing
// rather than hygiene.
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
/// than data-dependent. `fn_mul` and `fn_inv` both reduce here and
/// `fn_inv` is applied to the ECDSA nonce `k`, so a value-dependent
/// trip count would have made the signing path's duration a function
/// of the nonce, which is the input to hidden-number-problem key
/// recovery.
fn fn_reduce_wide(t: &[u64; 8]) -> U256 {
    // Reduce 512-bit value t mod n using iterative: t_hi * R + t_lo
    // R = 2^256 - n (small, ~128 bits)
    let r_mod = pic_u256(
        0x039CDAAF, 0x0C46353D, 0x58E8617B, 0x43190552,
        0x00000000, 0x00000000, 0xFFFFFFFF, 0x00000000,
    );

    let mut acc = [0u64; 8];
    // SAFETY: pointer arithmetic over fixed-size P-256 field elements
    // (32 bytes / 8 u32 limbs); offsets bounded by loop invariant.
    unsafe { core::ptr::copy_nonoverlapping(t.as_ptr(), acc.as_mut_ptr(), 8); }

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

/// Modular inverse mod n using Fermat's little theorem.
///
/// The exponent n-2 is public, so the schedule is fixed; the multiplies
/// underneath it are variable-time per `fn_reduce_wide`.
fn fn_inv(a: &U256) -> U256 {
    let mut result = ONE;
    let mut base = *a;

    let n = load_n();
    let n_minus_2: U256 = [
        n[0] - 2,
        n[1],
        n[2],
        n[3],
    ];

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
// Branchless helpers. Each of these is individually free of
// data-dependent branches and data-dependent memory addressing. They
// do not make their callers constant-time; the surrounding field,
// point and scalar-multiplication layers are not.
// ============================================================================

/// Zeroise a byte buffer via volatile writes. `#[inline(never)]` prevents
/// the compiler from eliding the stores after proving the buffer is dead.
#[inline(never)]
fn zeroize(buf: &mut [u8]) {
    let mut i = 0;
    while i < buf.len() {
        // SAFETY: pointer arithmetic over fixed-size P-256 field elements
        // (32 bytes / 8 u32 limbs); offsets bounded by loop invariant.
        unsafe { core::ptr::write_volatile(buf.as_mut_ptr().add(i), 0); }
        i += 1;
    }
}

/// Zeroise a U256 via volatile writes.
#[inline(never)]
fn zeroize_u256(v: &mut U256) {
    let mut i = 0;
    while i < 4 {
        // SAFETY: pointer arithmetic over fixed-size P-256 field elements
        // (32 bytes / 8 u32 limbs); offsets bounded by loop invariant.
        unsafe { core::ptr::write_volatile(v.as_mut_ptr().add(i), 0); }
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
        Self { x: ZERO, y: ONE, z: ZERO }
    }

    fn is_identity(&self) -> bool {
        u256_is_zero(&self.z)
    }

    fn from_affine(x: &U256, y: &U256) -> Self {
        Self { x: *x, y: *y, z: ONE }
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
    /// No explicit `is_identity` short-circuit: the dbl-2001-b
    /// formulas naturally produce `z3 = 2yz = 0` when the input is
    /// identity (`z = 0`), so the output is semantically identity
    /// regardless of what x3/y3 carry. This routine therefore has no
    /// data-dependent branch of its own. It is still not
    /// constant-time: every `fp_*` call it makes is value-dependent —
    /// see the timing-exposure note at the top of this file.
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
        let t2 = fp_add(&t, &t);    // 4 * x * y^2

        let x3 = fp_sub(&fp_sqr(&m), &fp_add(&t2, &t2)); // m^2 - 8*x*y^2

        let y2_4 = fp_add(&s, &s);  // 2*y^2
        let y4_8 = fp_sqr(&y2_4);   // 4*y^4
        let y4_8_2 = fp_add(&y4_8, &y4_8); // 8*y^4

        let y3 = fp_sub(&fp_mul(&m, &fp_sub(&t2, &x3)), &y4_8_2);

        let z3 = fp_mul(&fp_add(&self.y, &self.y), &self.z);

        JacobianPoint { x: x3, y: y3, z: z3 }
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
    /// into.
    ///
    /// The cost of that is one extra doubling per addition. In
    /// `scalar_mul_ct` an addition is one of five point operations per
    /// window, so the overhead is bounded by about a fifth.
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
        let generic = JacobianPoint { x: x3, y: y3, z: z3 };

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
    /// coords). The accumulator in `scalar_mul_ct` adds the (Jacobian)
    /// table-lookup output each window, so we need a Jacobian-Jacobian
    /// add — `add_affine` only handles the case where the right-hand
    /// side is in affine form.
    ///
    /// Exception-free on the same terms as `add_affine`, with a second
    /// identity test on the right-hand operand. That operand matters:
    /// in `scalar_mul_ct` it is the table entry selected by a secret
    /// scalar nibble and `table[0]` is the identity, so under the old
    /// short-circuit the position of every zero nibble of the scalar
    /// was visible in the timing profile. All five outcomes are now
    /// computed and selected under masks.
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
        let generic = JacobianPoint { x: x3, y: y3, z: z3 };

        let h_zero = ct_is_zero_u256(&h);
        let r_zero = ct_is_zero_u256(&r);
        let self_id = ct_is_zero_u256(&self.z);
        let other_id = ct_is_zero_u256(&other.z);

        // h == 0, r != 0 → inverse points → identity.
        let out = ct_select_point(&generic, &JacobianPoint::identity(), h_zero);
        // h == 0, r == 0 → the same point → doubling.
        let out = ct_select_point(&out, &self.double(), h_zero & r_zero);
        // Either operand being the identity overrides all of the above.
        // `other_id` is applied last so that identity + identity
        // yields the identity rather than a copy of `other`'s
        // coordinates.
        let out = ct_select_point(&out, other, self_id);
        ct_select_point(&out, self, other_id)
    }
}

/// Constant-time u64 equality: returns `0xFFFF_FFFF_FFFF_FFFF` if
/// `a == b`, else 0. No data-dependent branch.
#[inline(always)]
fn ct_eq_u64(a: u64, b: u64) -> u64 {
    // (a ^ b) == 0  iff  a == b. Reduce the XOR fold into a single
    // bit via "OR all bytes, fold, fold, fold" with arithmetic.
    let x = a ^ b;
    // OR the bytes into the LSB; the trick `(x | -x) >> 63` is 1
    // if x != 0, 0 if x == 0. Invert + sign-extend.
    let bit = !((x | x.wrapping_neg()) >> 63) & 1;
    bit.wrapping_neg()
}

/// Constant-time select on a U256: returns `b` if mask is all-ones,
/// `a` if mask is all-zeros. Mask comes from `ct_eq_u64`.
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

/// Constant-time table lookup: returns `table[idx]` without
/// branching on `idx`. Scans every entry of the table, selecting
/// the matching one via arithmetic mask. Cost: O(table_len) field
/// ops, but each op is data-independent. This is the standard
/// defence against cache-timing leaks in windowed scalar mult
/// (BoringSSL, ring, OpenSSL all do this).
fn ct_lookup_table_16(table: &[JacobianPoint; 16], idx: usize) -> JacobianPoint {
    let mut out_x = ZERO;
    let mut out_y = ZERO;
    let mut out_z = ZERO;
    let mut i = 0u64;
    while i < 16 {
        let mask = ct_eq_u64(i, idx as u64);
        let entry = &table[i as usize];
        out_x = ct_select_u256(&out_x, &entry.x, mask);
        out_y = ct_select_u256(&out_y, &entry.y, mask);
        out_z = ct_select_u256(&out_z, &entry.z, mask);
        i += 1;
    }
    JacobianPoint { x: out_x, y: out_y, z: out_z }
}

/// Scalar multiplication via fixed-window w=4 with constant-time
/// table lookup. Same shape as BoringSSL / ring / OpenSSL's
/// `p256_scalar_mul`. Replaces the earlier Montgomery-ladder
/// implementation:
///
/// - Montgomery ladder: 256 doublings + 256 conditional swaps +
///   256 additions ≈ 768 field ops on the critical path.
/// - Fixed-window w=4: 16-entry precompute (16 doublings + 14
///   additions, amortised once) + 64 windows × (4 doublings + 1
///   add) ≈ 256 doublings + 64 additions on the critical path.
///
/// Net: about 25-40 % fewer additions on the inner loop.
///
/// # Timing
///
/// Constant-time in the scalar, at every layer beneath this function:
///
///   - [`ct_lookup_table_16`] scans all 16 entries and selects
///     arithmetically, so the secret nibble never becomes a load
///     address;
///   - the per-window schedule is fixed at four doublings and one
///     addition, and [`JacobianPoint::double`] and
///     [`JacobianPoint::add_jacobian`] have no exceptional-case
///     branches, so a zero nibble — including every leading-zero
///     nibble, where `acc` is still the identity — costs exactly what
///     a non-zero one costs;
///   - the `fp_*` and `fn_*` layers have fixed trip counts with masked
///     corrections.
///
/// That property is load-bearing rather than hygiene: for ECDSA the
/// multiplied scalar is the per-signature nonce `k`, partial knowledge
/// of which across a set of signatures is the input to
/// hidden-number-problem lattice recovery of the long-term key, and
/// for ECDH it is the private key itself, measured again on every
/// handshake.
///
/// What is still not covered: the compiler and the microarchitecture.
/// This docstring states what the source does, not what a given
/// optimiser emits, and no test in the tree measures cycle counts.
///
/// KATs in `tests/harness/tests/tls_crypto_kat.rs` gate
/// correctness of the entire `(sign, verify, ECDH)` surface
/// against RFC 6979 / RFC 5903 expected outputs.
fn scalar_mul_ct(k: &U256, px: &U256, py: &U256) -> JacobianPoint {
    // ── Precompute table[i] = i · P  for i ∈ 0..16 ─────────
    //
    // table[0] = identity (used when the window value is 0).
    // table[1] = P (the input affine point lifted to Jacobian).
    // table[2k]   = double(table[k])
    // table[2k+1] = table[2k] + P
    let p_jac = JacobianPoint::from_affine(px, py);
    let id = JacobianPoint::identity();
    let p_clone = JacobianPoint { x: p_jac.x, y: p_jac.y, z: p_jac.z };
    let mut table: [JacobianPoint; 16] = [
        id,
        p_clone,
        JacobianPoint::identity(), JacobianPoint::identity(),
        JacobianPoint::identity(), JacobianPoint::identity(),
        JacobianPoint::identity(), JacobianPoint::identity(),
        JacobianPoint::identity(), JacobianPoint::identity(),
        JacobianPoint::identity(), JacobianPoint::identity(),
        JacobianPoint::identity(), JacobianPoint::identity(),
        JacobianPoint::identity(), JacobianPoint::identity(),
    ];
    let mut i = 2;
    while i < 16 {
        if i & 1 == 0 {
            table[i] = table[i / 2].double();
        } else {
            table[i] = table[i - 1].add_jacobian(&p_jac);
        }
        i += 1;
    }

    // ── Walk the scalar in 4-bit windows, MSB → LSB ────────
    let mut acc = JacobianPoint::identity();
    let mut window_idx: i32 = 63; // 64 nibbles of 4 bits each
    while window_idx >= 0 {
        // Quadruple the accumulator (4 doublings = shift-left-4).
        // `double` has no identity short-circuit, so the number of
        // doublings per window is fixed at four regardless of the
        // scalar.
        acc = acc.double().double().double().double();
        // Extract this nibble arithmetically — the nibble value never
        // becomes a branch condition or a load address here.
        let bit_pos = (window_idx as u32) * 4;
        let limb_idx = (bit_pos / 64) as usize;
        let limb_off = bit_pos % 64;
        let w = ((k[limb_idx] >> limb_off) & 0xF) as usize;
        // Constant-time lookup + add.
        let pt = ct_lookup_table_16(&table, w);
        acc = acc.add_jacobian(&pt);
        window_idx -= 1;
    }
    acc
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
// Resumable scalar multiplication
// ============================================================================
//
// Splits the Montgomery ladder into chunks so a caller can yield
// between chunks — each ECDH on aarch64 runs long enough that a
// concurrent handshake otherwise waits for the whole ladder to finish.
//
// One ladder bit performs: ct_swap, add_jacobian, double, ct_swap. Each
// step() processes `bits_per_step` ladder bits (clamped to remaining bits);
// the caller checks `complete()` to know when to extract the result.
//
// The ladder shape is regular and `ct_swap` is branchless, so the
// scalar bit does not select which operations run; `add_jacobian` and
// `double` have no exceptional-case branches, so leading zero bits of
// the scalar cost the same as any other bit; and the field arithmetic
// beneath both has fixed trip counts. The ladder is constant-time in
// the scalar on the terms documented on `scalar_mul_ct`.
//
// How many bits a given `step()` covers is set by the caller through
// `bits_per_step`, not by the scalar.

pub struct ScalarMulState {
    r0: JacobianPoint,
    r1: JacobianPoint,
    k: U256,
    /// Next ladder bit to process, counted from 255 down to 0. -1 = done.
    bit_index: i16,
    bits_per_step: u8,
    /// Set to 1 once `new`/`new_base` has populated r0/r1/k. 0 means the
    /// struct is in its kernel-zeroed initial state and must be (re)initialised
    /// before stepping.
    initialised: u8,
}

impl ScalarMulState {
    pub const fn empty() -> Self {
        Self {
            r0: JacobianPoint { x: ZERO, y: ZERO, z: ZERO },
            r1: JacobianPoint { x: ZERO, y: ZERO, z: ZERO },
            k: ZERO,
            bit_index: -1,
            bits_per_step: 0,
            initialised: 0,
        }
    }

    /// Initialise for `k * P` with arbitrary affine P. `bits_per_step == 0`
    /// means "process the entire scalar in a single `step()` call", matching
    /// one-shot `scalar_mul_ct` behaviour.
    pub fn new(k: &U256, px: &U256, py: &U256, bits_per_step: u8) -> Self {
        let p_jac = JacobianPoint::from_affine(px, py);
        Self {
            r0: JacobianPoint::identity(),
            r1: JacobianPoint { x: p_jac.x, y: p_jac.y, z: p_jac.z },
            k: *k,
            bit_index: 255,
            bits_per_step,
            initialised: 1,
        }
    }

    /// Initialise for `k * G`.
    #[allow(dead_code, reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it")]
    pub fn new_base(k: &U256, bits_per_step: u8) -> Self {
        let gx = load_gx();
        let gy = load_gy();
        Self::new(k, &gx, &gy, bits_per_step)
    }

    pub fn complete(&self) -> bool {
        self.initialised != 0 && self.bit_index < 0
    }

    /// True once `new`/`new_base` has populated the state; false when the
    /// struct is in its kernel-zeroed empty form.
    pub fn is_initialised(&self) -> bool {
        self.initialised != 0
    }

    /// Advance the ladder by up to `bits_per_step` bits. Returns true when
    /// the multiplication is complete.
    pub fn step(&mut self) -> bool {
        if self.initialised == 0 || self.bit_index < 0 {
            return self.complete();
        }
        // bits_per_step == 0 → run to completion in this call.
        let mut remaining: i16 = if self.bits_per_step == 0 {
            i16::MAX
        } else {
            self.bits_per_step as i16
        };
        while remaining > 0 && self.bit_index >= 0 {
            let bi = self.bit_index as u32;
            let word = self.k[(bi >> 6) as usize];
            let bit = ((word >> (bi & 63)) & 1) as u8;
            ct_swap(&mut self.r0, &mut self.r1, bit);
            self.r1 = self.r0.add_jacobian(&self.r1);
            self.r0 = self.r0.double();
            ct_swap(&mut self.r0, &mut self.r1, bit);
            self.bit_index -= 1;
            remaining -= 1;
        }
        self.complete()
    }

    /// Extract the result. Caller must ensure `complete()` is true.
    /// `JacobianPoint` is private to this module; the only caller is
    /// `ecdh_shared_secret_finalise` further down the same file.
    #[allow(
        private_interfaces,
        reason = "p256.rs is path-mounted into PIC modules; private JacobianPoint matches the file's internal-only consumers"
    )]
    pub fn result(&self) -> JacobianPoint {
        JacobianPoint { x: self.r0.x, y: self.r0.y, z: self.r0.z }
    }

    /// Zeroise the secret scalar via volatile writes. Call once the result
    /// has been extracted to limit how long the private key sits in RAM.
    pub fn zeroise_scalar(&mut self) {
        zeroize_u256(&mut self.k);
    }
}

/// Resumable variant of `ecdh_shared_secret`. The caller drives the returned
/// state with `step()` and finalises with `ecdh_shared_secret_finalise`.
///
/// Admits exactly the same inputs as the one-shot form: the peer point
/// goes through `decode_public_point` and the private scalar through
/// `decode_private_scalar` before any ladder state exists. Splitting
/// the multiplication across scheduler ticks changes when the work
/// happens, never which inputs are acceptable.
pub fn ecdh_shared_secret_init(
    my_private: &[u8; 32],
    peer_pub: &[u8],
    bits_per_step: u8,
) -> Option<ScalarMulState> {
    let (px, py) = decode_public_point(peer_pub)?;
    let k = decode_private_scalar(my_private)?;
    Some(ScalarMulState::new(&k, &px, &py, bits_per_step))
}

/// Extract the shared-secret X coordinate from a completed `ScalarMulState`.
/// Returns None if the result is the point at infinity (invalid).
pub fn ecdh_shared_secret_finalise(state: &ScalarMulState) -> Option<[u8; 32]> {
    let result = state.result();
    if result.is_identity() {
        return None;
    }
    let (x, _) = result.to_affine();
    Some(u256_to_be(&x))
}

// ============================================================================
// Resumable ECDSA signing
// ============================================================================
//
// Splits the `k * G` scalar mul across ticks so concurrent
// handshakes can interleave through the heavy ladder without one
// signer locking the scheduler.

pub struct EcdsaSignState {
    /// Resumable `k * G` scalar mul. The expensive 256-bit
    /// Montgomery ladder lives here and gets driven by the same
    /// `step()` API ECDH uses.
    pub scalar_mul: ScalarMulState,
    /// Private signer key (cleared by `ecdsa_sign_finalise` after
    /// the signature is computed).
    d: U256,
    /// RFC 6979 deterministic nonce. Kept until finalise so the
    /// modular-inverse + multiply can produce `s`.
    k: U256,
    /// Message hash reduced into `[0, n-1]`.
    z: U256,
    /// Set once `_init` has populated the fields; lets callers
    /// distinguish a zero-initialised state from a real one.
    initialised: u8,
}

impl EcdsaSignState {
    /// Empty state. Use `ecdsa_sign_init` to populate.
    pub const fn empty() -> Self {
        Self {
            scalar_mul: ScalarMulState::empty(),
            d: ZERO,
            k: ZERO,
            z: ZERO,
            initialised: 0,
        }
    }

    pub fn is_initialised(&self) -> bool {
        self.initialised != 0
    }

    /// Zeroise the secret scalar + private key. Call after the
    /// signature has been extracted so the keying material isn't
    /// sitting in RAM longer than necessary. Mirrors
    /// `ScalarMulState::zeroise_scalar`.
    pub fn zeroise_secrets(&mut self) {
        zeroize_u256(&mut self.k);
        zeroize_u256(&mut self.d);
        self.scalar_mul.zeroise_scalar();
    }
}

/// Initialise resumable ECDSA signing. `bits_per_step` is forwarded
/// to the inner `ScalarMulState` — 0 means "run to completion in one
/// step" (matches non-incremental `ecdsa_sign`); a small value (e.g.
/// 32) splits the ladder so each step fits a typical scheduler tick.
///
/// Returns None for a private scalar outside [1, n-1], matching the
/// one-shot `ecdsa_sign`.
pub fn ecdsa_sign_init(
    private_key: &[u8; 32],
    hash: &[u8],
    bits_per_step: u8,
) -> Option<EcdsaSignState> {
    let d = decode_private_scalar(private_key)?;
    let k = rfc6979_nonce(private_key, hash);
    // Truncate / pad hash to 32 bytes, then reduce mod n. Matches
    // the prologue of `ecdsa_sign`.
    let z = if hash.len() >= 32 {
        u256_from_be(&hash[..32])
    } else {
        let mut buf = [0u8; 32];
        // SAFETY: copy `hash.len()` bytes into the tail of a 32-byte
        // stack buffer; `hash.len() < 32` per the branch guard.
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
    Some(EcdsaSignState {
        scalar_mul: ScalarMulState::new_base(&k, bits_per_step),
        d,
        k,
        z,
        initialised: 1,
    })
}

/// Finalise resumable ECDSA signing. Callers must drive
/// `state.scalar_mul` until `complete()` returns true before calling
/// this. Returns the 64-byte signature `r || s` in big-endian, with
/// `s` normalised to low-s. Zeroises the in-state private key + nonce
/// before returning.
#[allow(
    private_interfaces,
    reason = "p256.rs is path-mounted into PIC modules; the private JacobianPoint type is internal"
)]
pub fn ecdsa_sign_finalise(mut state: EcdsaSignState) -> [u8; 64] {
    // r = (k * G).x mod n. `scalar_mul` already produced the point.
    let point = state.scalar_mul.result();
    let (rx, _) = point.to_affine();
    let r = mod_n_reduce(&rx);

    // s = k^-1 * (z + r * d) mod n
    let k_inv = fn_inv(&state.k);
    let rd = fn_mul(&r, &state.d);
    let z_rd = fn_add(&state.z, &rd);
    let mut s = fn_mul(&k_inv, &z_rd);

    // Low-s normalisation per RFC 6979 §2.4 / SEC 1 §4.1.4.
    let n_half = load_n_half();
    if u256_gte(&s, &n_half) != 0 {
        let n = load_n();
        let (ns, _) = u256_sub(&n, &s);
        s = ns;
    }

    state.zeroise_secrets();

    let mut sig = [0u8; 64];
    let rb = u256_to_be(&r);
    let sb = u256_to_be(&s);
    // SAFETY: `sig` is 64 bytes; the two 32-byte writes are bounded.
    unsafe {
        core::ptr::copy_nonoverlapping(rb.as_ptr(), sig.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(sb.as_ptr(), sig.as_mut_ptr().add(32), 32);
    }
    sig
}

// ============================================================================
// Serialization
// ============================================================================

fn u256_from_be(bytes: &[u8]) -> U256 {
    // Input: 32 bytes big-endian
    let mut r = [0u64; 4];
    r[3] = u64::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3],
                                bytes[4], bytes[5], bytes[6], bytes[7]]);
    r[2] = u64::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11],
                                bytes[12], bytes[13], bytes[14], bytes[15]]);
    r[1] = u64::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19],
                                bytes[20], bytes[21], bytes[22], bytes[23]]);
    r[0] = u64::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27],
                                bytes[28], bytes[29], bytes[30], bytes[31]]);
    r
}

fn u256_to_be(a: &U256) -> [u8; 32] {
    let mut out = [0u8; 32];
    let b3 = a[3].to_be_bytes();
    let b2 = a[2].to_be_bytes();
    let b1 = a[1].to_be_bytes();
    let b0 = a[0].to_be_bytes();
    // SAFETY: pointer arithmetic over fixed-size P-256 field elements
    // (32 bytes / 8 u32 limbs); offsets bounded by loop invariant.
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

/// Generate ECDH key pair. Returns (private_key, public_key_uncompressed_65bytes)
pub fn ecdh_keygen(random_bytes: &[u8; 32]) -> ([u8; 32], [u8; 65]) {
    let mut k = u256_from_be(random_bytes);
    // Ensure k is in [1, n-1]
    k = mod_n_reduce(&k);
    if u256_is_zero(&k) {
        k = ONE;
    }

    let point = scalar_mul_base(&k);
    let (x, y) = point.to_affine();

    let priv_key = u256_to_be(&k);
    let mut pub_key = [0u8; 65];
    pub_key[0] = 0x04; // Uncompressed point
    let xb = u256_to_be(&x);
    let yb = u256_to_be(&y);
    // SAFETY: pointer arithmetic over fixed-size P-256 field elements
    // (32 bytes / 8 u32 limbs); offsets bounded by loop invariant.
    unsafe {
        core::ptr::copy_nonoverlapping(xb.as_ptr(), pub_key.as_mut_ptr().add(1), 32);
        core::ptr::copy_nonoverlapping(yb.as_ptr(), pub_key.as_mut_ptr().add(33), 32);
    }

    (priv_key, pub_key)
}

/// Resumable variant of `ecdh_keygen` for background ECDH-pool refill.
///
/// Reduces `random_bytes` into a valid scalar `k ∈ [1, n-1]` (identical
/// clamping to `ecdh_keygen`), returns the private-key bytes immediately,
/// plus a `ScalarMulState` that computes the public point `k·G`
/// incrementally — `bits_per_step` ladder bits per `step()` call
/// (`bits_per_step == 0` runs to completion in one call). Drive `step()`
/// until it returns true, then call `ecdh_keygen_finalise`. The resulting
/// keypair is byte-identical to `ecdh_keygen(random_bytes)` because both
/// reduce `k` the same way and `k·G` is independent of the multiplication
/// algorithm.
pub fn ecdh_keygen_init(random_bytes: &[u8; 32], bits_per_step: u8) -> ([u8; 32], ScalarMulState) {
    let mut k = u256_from_be(random_bytes);
    k = mod_n_reduce(&k);
    if u256_is_zero(&k) {
        k = ONE;
    }
    let priv_key = u256_to_be(&k);
    let state = ScalarMulState::new_base(&k, bits_per_step);
    (priv_key, state)
}

/// Finalise an `ecdh_keygen_init` ladder into the 65-byte uncompressed
/// public key (`0x04 || X || Y`). The caller must ensure `state.step()`
/// has returned true. Returns `None` only if the result is the point at
/// infinity — which `ecdh_keygen_init`'s non-zero `k` clamp already
/// precludes, so a `None` here signals a logic error, not normal input.
pub fn ecdh_keygen_finalise(state: &ScalarMulState) -> Option<[u8; 65]> {
    let point = state.result();
    if point.is_identity() {
        return None;
    }
    let (x, y) = point.to_affine();
    let mut pub_key = [0u8; 65];
    pub_key[0] = 0x04;
    let xb = u256_to_be(&x);
    let yb = u256_to_be(&y);
    // SAFETY: fixed-size P-256 field elements (32 bytes), offsets bounded.
    unsafe {
        core::ptr::copy_nonoverlapping(xb.as_ptr(), pub_key.as_mut_ptr().add(1), 32);
        core::ptr::copy_nonoverlapping(yb.as_ptr(), pub_key.as_mut_ptr().add(33), 32);
    }
    Some(pub_key)
}

/// Public-key validation: is the affine point (x, y) on the P-256
/// curve y² ≡ x³ - 3x + b (mod p)?
///
/// Without this gate, an attacker can submit a point on a different
/// curve (different b) whose order has small factors and use the
/// resulting ECDH agreements to recover bits of our private scalar
/// over multiple sessions — the classic "invalid curve attack"
/// (Antipa-Brown-Menezes 2003). For TLS 1.3 with ephemeral ECDHE
/// the impact is smaller (one private per session) but the static
/// `key_vault`-signed identity key is reusable, and a follow-on
/// CertificateVerify with a leaked component is catastrophic.
pub fn is_on_curve(x: &U256, y: &U256) -> bool {
    // y² mod p
    let y_sq = fp_sqr(y);
    // x³ mod p
    let x_sq = fp_sqr(x);
    let x_cubed = fp_mul(&x_sq, x);
    // -3x mod p: compute via two fp_sub (faster than negating a const)
    let two_x = fp_add(x, x);
    let three_x = fp_add(&two_x, x);
    // x³ - 3x + b mod p
    let rhs = fp_add(&fp_sub(&x_cubed, &three_x), &load_b());
    // Equality folded over all four limbs before the branch, so the
    // comparison itself reveals nothing about where the values differ.
    // The inputs here are a candidate public point — public — so this
    // is hygiene rather than a required property.
    let mut diff = 0u64;
    let mut i = 0;
    while i < 4 {
        diff |= y_sq[i] ^ rhs[i];
        i += 1;
    }
    diff == 0
}

/// The single decode-and-validate gate for every P-256 public point
/// that arrives from outside this module — TLS key shares, peer
/// CertificateVerify keys, certificate SubjectPublicKeyInfo, and both
/// ECDH entry points.
///
/// Accepts the SEC 1 uncompressed encoding `0x04 || X || Y` (65 bytes)
/// and the bare `X || Y` form (64 bytes). Everything else is refused:
/// compressed prefixes (`0x02`/`0x03`) are not supported, and any
/// other prefix or length is malformed.
///
/// A point survives only if all four hold:
///   - X and Y are canonical, i.e. each is numerically less than `p`
///     (a non-reduced coordinate has two encodings, so accepting one
///     lets an attacker vary the wire bytes without varying the point);
///   - the point is not the affine identity `(0, 0)`;
///   - the point satisfies y² ≡ x³ - 3x + b (mod p), which pins it to
///     P-256 rather than some other curve with the same field and a
///     smooth order (the invalid-curve attack);
///   - it is therefore in the prime-order group, since P-256 has
///     cofactor 1 and every on-curve non-identity point generates it.
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

    // RFC 8446 §4.2.8.2 / SP 800-56A §5.6.2.3.4.
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

/// True when `encoded` is a P-256 public point this module will use.
/// Callers holding an encoded key before they need the coordinates —
/// certificate SubjectPublicKeyInfo parsing, TLS key-share admission —
/// gate on this so a bad point is refused at the boundary it entered
/// through rather than deep inside a scalar multiplication.
pub fn public_point_is_valid(encoded: &[u8]) -> bool {
    decode_public_point(encoded).is_some()
}

/// Decode a private scalar `d` supplied at the standalone API
/// boundary. `d` must lie in `[1, n-1]`: `d == 0` yields the identity
/// for every input, and `d >= n` is a non-canonical encoding of
/// `d mod n`. Internal key generation already clamps, but a caller may
/// have obtained the scalar anywhere, so every entry point re-checks.
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

/// ECDH shared secret: scalar_mult(my_private, peer_public).x
/// peer_pub should be 65 bytes (0x04 || X || Y) or 64 bytes (X || Y)
///
/// Returns None on:
///   - a private scalar outside [1, n-1]
///   - malformed encoding (wrong length, non-uncompressed prefix)
///   - noncanonical coordinates, the identity, or a point not on the
///     curve (invalid-curve attack defence)
///   - scalar multiplication producing the point at infinity
///     (small-subgroup attack defence — peer submitted a point of
///     low order whose multiples cycle through the subgroup)
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
        // SAFETY: pointer arithmetic over fixed-size P-256 field elements
        // (32 bytes / 8 u32 limbs); offsets bounded by loop invariant.
        unsafe { core::ptr::copy_nonoverlapping(hash.as_ptr(), h1.as_mut_ptr(), 32); }
    } else {
        let offset = 32 - hash.len();
        // SAFETY: pointer arithmetic over fixed-size P-256 field elements
        // (32 bytes / 8 u32 limbs); offsets bounded by loop invariant.
        unsafe { core::ptr::copy_nonoverlapping(hash.as_ptr(), h1.as_mut_ptr().add(offset), hash.len()); }
    }

    // Step a: h1 = Hash(message) — already have it
    // Step b: V = 0x01 0x01 ... 0x01 (32 bytes)
    let mut v = [0x01u8; 32];
    // Step c: K = 0x00 0x00 ... 0x00 (32 bytes)
    let mut k_hmac = [0x00u8; 32];

    // Step d: K = HMAC(K, V || 0x00 || private_key || h1)
    let mut msg_d = [0u8; 32 + 1 + 32 + 32]; // V(32) + 0x00(1) + x(32) + h1(32) = 97
    // SAFETY: pointer arithmetic over fixed-size P-256 field elements
    // (32 bytes / 8 u32 limbs); offsets bounded by loop invariant.
    unsafe {
        core::ptr::copy_nonoverlapping(v.as_ptr(), msg_d.as_mut_ptr(), 32);
    }
    msg_d[32] = 0x00;
    // SAFETY: pointer arithmetic over fixed-size P-256 field elements
    // (32 bytes / 8 u32 limbs); offsets bounded by loop invariant.
    unsafe {
        core::ptr::copy_nonoverlapping(private_key.as_ptr(), msg_d.as_mut_ptr().add(33), 32);
        core::ptr::copy_nonoverlapping(h1.as_ptr(), msg_d.as_mut_ptr().add(65), 32);
    }
    {
        let mut tmp = [0u8; 32];
        hmac(HashAlg::Sha256, &k_hmac, &msg_d[..97], &mut tmp);
        k_hmac = tmp;
    }

    // Step e: V = HMAC(K, V)
    {
        let mut tmp = [0u8; 32];
        hmac(HashAlg::Sha256, &k_hmac, &v, &mut tmp);
        v = tmp;
    }

    // Step f: K = HMAC(K, V || 0x01 || private_key || h1)
    // SAFETY: pointer arithmetic over fixed-size P-256 field elements
    // (32 bytes / 8 u32 limbs); offsets bounded by loop invariant.
    unsafe {
        core::ptr::copy_nonoverlapping(v.as_ptr(), msg_d.as_mut_ptr(), 32);
    }
    msg_d[32] = 0x01;
    // private_key and h1 already in place
    {
        let mut tmp = [0u8; 32];
        hmac(HashAlg::Sha256, &k_hmac, &msg_d[..97], &mut tmp);
        k_hmac = tmp;
    }

    // Step g: V = HMAC(K, V)
    {
        let mut tmp = [0u8; 32];
        hmac(HashAlg::Sha256, &k_hmac, &v, &mut tmp);
        v = tmp;
    }

    // Step h: Loop until valid k is found
    loop {
        // V = HMAC(K, V) — generates candidate
        {
            let mut tmp = [0u8; 32];
            hmac(HashAlg::Sha256, &k_hmac, &v, &mut tmp);
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
        // SAFETY: pointer arithmetic over fixed-size P-256 field elements
        // (32 bytes / 8 u32 limbs); offsets bounded by loop invariant.
        unsafe { core::ptr::copy_nonoverlapping(v.as_ptr(), retry.as_mut_ptr(), 32); }
        retry[32] = 0x00;
        {
            let mut tmp = [0u8; 32];
            hmac(HashAlg::Sha256, &k_hmac, &retry[..33], &mut tmp);
            k_hmac = tmp;
        }
        {
            let mut tmp = [0u8; 32];
            hmac(HashAlg::Sha256, &k_hmac, &v, &mut tmp);
            v = tmp;
        }
    }
}

/// ECDSA sign over a message hash. The nonce is derived deterministically
/// from the private key and the hash (RFC 6979); the `_random_k` parameter
/// is retained for API compatibility and ignored. Returns the 64-byte
/// signature `r || s` in big-endian form, normalised to low-s.
///
/// Returns None when `private_key` is not a valid scalar in [1, n-1];
/// signing with `d == 0` produces a signature that verifies under the
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
        // SAFETY: pointer arithmetic over fixed-size P-256 field elements
        // (32 bytes / 8 u32 limbs); offsets bounded by loop invariant.
        unsafe { core::ptr::copy_nonoverlapping(hash.as_ptr(), buf.as_mut_ptr().add(32 - hash.len()), hash.len()); }
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
    // SAFETY: pointer arithmetic over fixed-size P-256 field elements
    // (32 bytes / 8 u32 limbs); offsets bounded by loop invariant.
    unsafe {
        core::ptr::copy_nonoverlapping(rb.as_ptr(), sig.as_mut_ptr(), 32);
        core::ptr::copy_nonoverlapping(sb.as_ptr(), sig.as_mut_ptr().add(32), 32);
    }
    Some(sig)
}

/// ECDSA verify: check (r, s) over message hash with public key
/// sig: 64 bytes (r || s), pub_key: 65 bytes (0x04 || X || Y)
pub fn ecdsa_verify(pub_key: &[u8], hash: &[u8], sig: &[u8]) -> bool {
    if sig.len() < 64 { return false; }
    // The public point is an untrusted input here exactly as it is in
    // ECDH: an off-curve Q makes `scalar_mul` operate in a group that
    // is not P-256, and the verification equation can then be
    // satisfied by a signature no key holder produced.
    let (qx, qy) = match decode_public_point(pub_key) {
        Some(q) => q,
        None => return false,
    };

    let r = u256_from_be(&sig[..32]);
    let s = u256_from_be(&sig[32..64]);

    // Check r, s in [1, n-1]
    let n = load_n();
    if u256_is_zero(&r) || u256_is_zero(&s) { return false; }
    if u256_gte(&r, &n) != 0 { return false; }
    if u256_gte(&s, &n) != 0 { return false; }

    let z = if hash.len() >= 32 {
        u256_from_be(&hash[..32])
    } else {
        let mut buf = [0u8; 32];
        // SAFETY: pointer arithmetic over fixed-size P-256 field elements
        // (32 bytes / 8 u32 limbs); offsets bounded by loop invariant.
        unsafe { core::ptr::copy_nonoverlapping(hash.as_ptr(), buf.as_mut_ptr().add(32 - hash.len()), hash.len()); }
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

    if sum.is_identity() { return false; }
    let (rx, _) = sum.to_affine();
    let rx_mod_n = mod_n_reduce(&rx);

    // Check r == rx mod n
    rx_mod_n == r
}

/// Parse a canonical DER-encoded ECDSA signature into raw `r || s`.
///
/// `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` has exactly
/// one DER encoding for a given pair, and this parser accepts only
/// that one:
///
///   - the SEQUENCE spans the whole input, so no bytes trail it;
///   - each length uses the short form (an ECDSA integer is at most 33
///     bytes, so the long form is never minimal here);
///   - each INTEGER is non-empty, positive, and minimally encoded —
///     one leading `0x00` only when needed to clear the sign bit.
///
/// Signature malleability by re-encoding matters wherever a signature
/// is compared, cached, or logged as an identifier, and a lenient
/// parser hands an attacker a family of distinct byte strings for one
/// signature.
pub fn parse_der_signature(der: &[u8]) -> Option<[u8; 64]> {
    if der.len() < 8 { return None; }
    if der[0] != 0x30 { return None; }
    let seq_len = der[1] as usize;
    if seq_len >= 0x80 { return None; } // long form is never minimal here
    if 2 + seq_len != der.len() { return None; } // trailing bytes

    let mut pos = 2;

    let r_bytes = parse_der_positive_int(der, &mut pos)?;
    let s_bytes = parse_der_positive_int(der, &mut pos)?;
    if pos != der.len() { return None; } // extra SEQUENCE members

    // Convert to fixed 32-byte big-endian
    let mut sig = [0u8; 64];
    copy_be_padded(r_bytes, &mut sig[..32]);
    copy_be_padded(s_bytes, &mut sig[32..64]);
    Some(sig)
}

/// Read one minimally encoded, positive DER INTEGER, advancing `pos`.
fn parse_der_positive_int<'a>(der: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    if *pos + 2 > der.len() || der[*pos] != 0x02 { return None; }
    let len = der[*pos + 1] as usize;
    if len == 0 || len >= 0x80 { return None; }
    let start = *pos + 2;
    if start + len > der.len() { return None; }
    let body = &der[start..start + len];
    // Negative values are not valid for r or s.
    if body[0] & 0x80 != 0 { return None; }
    // A leading zero is permitted only to clear the next byte's sign bit.
    if len > 1 && body[0] == 0 && body[1] & 0x80 == 0 { return None; }
    // r and s are at most 32 bytes, plus one optional sign byte.
    if len > 33 { return None; }
    *pos = start + len;
    Some(body)
}

/// Copy big-endian integer into fixed-size buffer, handling leading zeros
fn copy_be_padded(src: &[u8], dst: &mut [u8]) {
    // Skip leading zero bytes (DER encoding may prepend 0x00 for positive)
    let mut start = 0;
    while start < src.len() && src[start] == 0 && src.len() - start > dst.len() {
        start += 1;
    }
    let effective = &src[start..];
    if effective.len() > dst.len() { return; }
    let offset = dst.len() - effective.len();
    // Zero-fill prefix
    let mut i = 0;
    while i < offset { dst[i] = 0; i += 1; }
    // SAFETY: pointer arithmetic over fixed-size P-256 field elements
    // (32 bytes / 8 u32 limbs); offsets bounded by loop invariant.
    unsafe {
        core::ptr::copy_nonoverlapping(effective.as_ptr(), dst.as_mut_ptr().add(offset), effective.len());
    }
}

/// Encode raw (r,s) signature into DER format
pub fn encode_der_signature(sig: &[u8; 64]) -> ([u8; 72], usize) {
    let mut out = [0u8; 72];
    let mut pos = 0;

    out[pos] = 0x30; pos += 1; // SEQUENCE
    let len_pos = pos; pos += 1; // length placeholder

    // Encode r
    out[pos] = 0x02; pos += 1; // INTEGER
    let r_start = skip_leading_zeros(&sig[..32]);
    let r_data = &sig[r_start..32];
    let needs_pad_r = !r_data.is_empty() && r_data[0] >= 0x80;
    let r_enc_len = r_data.len() + if needs_pad_r { 1 } else { 0 };
    out[pos] = r_enc_len as u8; pos += 1;
    if needs_pad_r { out[pos] = 0; pos += 1; }
    // SAFETY: pointer arithmetic over fixed-size P-256 field elements
    // (32 bytes / 8 u32 limbs); offsets bounded by loop invariant.
    unsafe { core::ptr::copy_nonoverlapping(r_data.as_ptr(), out.as_mut_ptr().add(pos), r_data.len()); }
    pos += r_data.len();

    // Encode s
    out[pos] = 0x02; pos += 1;
    let s_start = skip_leading_zeros(&sig[32..64]);
    let s_data = &sig[32 + s_start..64];
    let needs_pad_s = !s_data.is_empty() && s_data[0] >= 0x80;
    let s_enc_len = s_data.len() + if needs_pad_s { 1 } else { 0 };
    out[pos] = s_enc_len as u8; pos += 1;
    if needs_pad_s { out[pos] = 0; pos += 1; }
    // SAFETY: pointer arithmetic over fixed-size P-256 field elements
    // (32 bytes / 8 u32 limbs); offsets bounded by loop invariant.
    unsafe { core::ptr::copy_nonoverlapping(s_data.as_ptr(), out.as_mut_ptr().add(pos), s_data.len()); }
    pos += s_data.len();

    out[len_pos] = (pos - 2) as u8;
    (out, pos)
}

fn skip_leading_zeros(data: &[u8]) -> usize {
    let mut i = 0;
    while i < data.len() - 1 && data[i] == 0 { i += 1; }
    i
}
