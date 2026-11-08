// Ed25519 (RFC 8032, plain — not Ed25519ph/ctx) sign / verify, and
// X25519 (RFC 7748) key agreement over the same field.
// Pure Rust, no_std, no heap
//
// REQUIRED INCLUDE SET — this file is written for the flat `include!()`
// consumption pattern (see crates/fluxor-sdk/src/lib.rs `sdk_flat`) and
// references items defined in sibling SDK files by bare name. A consumer
// that `include!()`s or `#[path]`-mounts ed25519.rs MUST also mount:
//
//   - sha384.rs — `Sha512` / `sha512` (the SHA-512 core lives there,
//     sharing `compress512`/`K512` with SHA-384)
//   - p256.rs  — `pic_u64`/`pic_u256` PIC constant loaders, the `U256`
//     type + `ZERO` const and limb helpers (`u256_add`, `u256_sub`,
//     `u256_gte`, `u256_mul_wide`), `ct_eq_u64`, and the
//     `zeroize`/`zeroize_u256` volatile-write helpers
//
// (aes_gcm.rs documents the same dependency on p256.rs for `zeroize`.)
//
// Curve: twisted Edwards -x² + y² = 1 + d·x²y² over p = 2^255 - 19,
// d = -121665/121666. Field arithmetic uses 5 × 51-bit limbs (u64 limbs,
// u128 products) — the standard radix-51 schedule. Group arithmetic uses
// extended coordinates (X, Y, Z, T with x = X/Z, y = Y/Z, T = XY/Z) and
// the unified add-2008-hwcd-3 / dbl-2008-hwcd formulas. Because a = -1
// is a square mod p (p ≡ 1 mod 4) and d is a non-square, the unified
// addition law is COMPLETE (Bernstein–Birkner–Joye–Lange–Peters): it is
// correct for every input pair including identity and low-order points,
// with no identity short-circuit branches at all.
//
// Scalar multiplication is fixed-window w=4 with a constant-time
// 16-entry table lookup — the same shape as `scalar_mul_ct` in p256.rs.
// The underlying point formulas here have NO data-dependent branches at
// all (completeness, above), where p256 reaches the same property by
// computing every exceptional case and selecting under a mask. The field
// layer is branchless too — `fe_carry`, `fe_add`, `fe_sub`, `fe_mul`
// and `fe_tobytes` are straight-line masked carry chains with fixed
// trip counts. `sc_reduce_wide`'s +L repair is a masked select, not a
// branch. Residual non-constant-time surface:
//
//   - `ed25519_verify` is VARIABLE-TIME by design: it handles only
//     public inputs (public key, message, signature).
//
// Signing is deterministic per RFC 8032 §5.1.6: nonce
// r = SHA-512(prefix ‖ msg) mod L — no runtime randomness. Verification
// is strict: rejects s ≥ L, rejects non-canonical point encodings
// (y ≥ p), rejects points not on the curve, and rejects small-order
// (8-torsion) public keys and R values ([8]·P = identity), which closes
// the trivial-forgery corner (A = identity accepts every message).
// Intermediate secrets (seed hash, clamped scalar, prefix, nonce) are
// zeroised via the volatile-write helpers before returning.
//
// Curve constants are loaded via `pic_u64` (u32 immediates assembled on
// the stack) for the same PIC-aarch64 reason documented in p256.rs.

/// Field element mod p = 2^255 - 19, radix 2^51: value = Σ limb[i]·2^(51·i).
/// Invariant maintained between operations: every limb < 2^52 (each op
/// ends with a carry pass; `fe_mul` inputs tolerate limbs < 2^54).
type Fe = [u64; 5];

const FE_ZERO: Fe = [0, 0, 0, 0, 0];
const FE_ONE: Fe = [1, 0, 0, 0, 0];
const MASK51: u64 = (1u64 << 51) - 1;

/// Load 2·d = -121665/121666 · 2 mod p (curve constant for add-2008-hwcd-3).
#[inline(never)]
fn ed_load_d2() -> Fe {
    [
        pic_u64(0x26B2F159, 0x00069B94),
        pic_u64(0x762ADD7A, 0x00035050),
        pic_u64(0xC0038052, 0x0003CF44),
        pic_u64(0xC7407977, 0x0006738C),
        pic_u64(0x9DC56DFF, 0x0002406D),
    ]
}

/// Load d = -121665/121666 mod p (for point decompression).
#[inline(never)]
fn ed_load_d() -> Fe {
    [
        pic_u64(0x135978A3, 0x00034DCA),
        pic_u64(0x3B156EBD, 0x0001A828),
        pic_u64(0x6001C029, 0x0005E7A2),
        pic_u64(0x63A03CBB, 0x000739C6),
        pic_u64(0xCEE2B6FF, 0x00052036),
    ]
}

/// Load sqrt(-1) = 2^((p-1)/4) mod p.
#[inline(never)]
fn ed_load_sqrtm1() -> Fe {
    [
        pic_u64(0x4A0EA0B0, 0x00061B27),
        pic_u64(0xFC8F189D, 0x0000D5A5),
        pic_u64(0x9CBD0C60, 0x0007EF5E),
        pic_u64(0xA6804C9E, 0x00078595),
        pic_u64(0x4804FC1D, 0x0002B832),
    ]
}

/// Load base point Bx (the even root paired with By = 4/5).
#[inline(never)]
fn ed_load_bx() -> Fe {
    [
        pic_u64(0x8F25D51A, 0x00062D60),
        pic_u64(0xB4F6592A, 0x000412A4),
        pic_u64(0x71A4B31D, 0x00075B71),
        pic_u64(0x527118FE, 0x0001FF60),
        pic_u64(0x6D3CD6E5, 0x00021693),
    ]
}

/// Load base point By = 4/5 mod p.
#[inline(never)]
fn ed_load_by() -> Fe {
    [
        pic_u64(0x66666658, 0x00066666),
        pic_u64(0xCCCCCCCC, 0x0004CCCC),
        pic_u64(0x99999999, 0x00019999),
        pic_u64(0x33333333, 0x00033333),
        pic_u64(0x66666666, 0x00066666),
    ]
}

/// Load the group order L = 2^252 + 27742317777372353535851937790883648493
/// as a `U256` (p256.rs limb layout: little-endian u64 limbs).
#[inline(never)]
fn ed_load_l() -> U256 {
    pic_u256(
        0x5CF5D3ED, 0x5812631A, 0xA2F79CD6, 0x14DEF9DE, 0x00000000, 0x00000000, 0x00000000,
        0x10000000,
    )
}

/// Load p = 2^255 - 19 as a `U256` (canonical-encoding check in decode).
#[inline(never)]
fn ed_load_p() -> U256 {
    pic_u256(
        0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0x7FFFFFFF,
    )
}

/// Load (p - 5) / 8 = 2^252 - 3 as exponent limbs for the decompression
/// square-root candidate x = u·v³·(u·v⁷)^((p-5)/8).
#[inline(never)]
fn ed_load_p58() -> U256 {
    pic_u256(
        0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0x0FFFFFFF,
    )
}

// ============================================================================
// Field arithmetic mod 2^255 - 19 (radix 2^51)
// ============================================================================

/// One carry pass: bring every limb below 2^51 (+ a few wrap bits in limb 0,
/// cleared by the second pass). Two passes fully normalise any input with
/// limbs < 2^63.
fn fe_carry(h: &mut Fe) {
    let mut pass = 0;
    while pass < 2 {
        let mut c = h[0] >> 51;
        h[0] &= MASK51;
        h[1] += c;
        c = h[1] >> 51;
        h[1] &= MASK51;
        h[2] += c;
        c = h[2] >> 51;
        h[2] &= MASK51;
        h[3] += c;
        c = h[3] >> 51;
        h[3] &= MASK51;
        h[4] += c;
        c = h[4] >> 51;
        h[4] &= MASK51;
        h[0] += c * 19;
        pass += 1;
    }
}

fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let mut r = [
        a[0] + b[0],
        a[1] + b[1],
        a[2] + b[2],
        a[3] + b[3],
        a[4] + b[4],
    ];
    fe_carry(&mut r);
    r
}

/// a - b mod p. Adds 2p per limb before subtracting so limbs never
/// underflow (inputs keep limbs < 2^52 ≤ the 2p limb values).
fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    // 2p in radix 2^51: limb0 = 2^52 - 38, limbs 1-4 = 2^52 - 2.
    let mut r = [
        a[0] + 0xFFFFFFFFFFFDA - b[0],
        a[1] + 0xFFFFFFFFFFFFE - b[1],
        a[2] + 0xFFFFFFFFFFFFE - b[2],
        a[3] + 0xFFFFFFFFFFFFE - b[3],
        a[4] + 0xFFFFFFFFFFFFE - b[4],
    ];
    fe_carry(&mut r);
    r
}

fn fe_neg(a: &Fe) -> Fe {
    fe_sub(&FE_ZERO, a)
}

/// Schoolbook radix-51 multiplication with the 19·wraparound folded into
/// the column sums (2^255 ≡ 19 mod p). u128 accumulators: worst-case
/// column < 5 · 19 · 2^54 · 2^54 < 2^116.
fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let a0 = a[0] as u128;
    let a1 = a[1] as u128;
    let a2 = a[2] as u128;
    let a3 = a[3] as u128;
    let a4 = a[4] as u128;
    let b0 = b[0] as u128;
    let b1 = b[1] as u128;
    let b2 = b[2] as u128;
    let b3 = b[3] as u128;
    let b4 = b[4] as u128;
    // 19·b_j fits a u64 (b_j < 2^54), so each wrapped product is one
    // 64×64 multiply rather than a product scaled in u128.
    let b1_19 = (b[1] * 19) as u128;
    let b2_19 = (b[2] * 19) as u128;
    let b3_19 = (b[3] * 19) as u128;
    let b4_19 = (b[4] * 19) as u128;

    let t0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
    let t1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
    let t2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
    let t3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
    let t4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
    fe_carry_wide(t0, t1, t2, t3, t4)
}

/// Carry five u128 column sums (each < 2^116) down to radix-51 limbs:
/// limbs 0 and 2-4 below 2^51, limb 1 below 2^51 + 2^13.
#[inline(always)]
fn fe_carry_wide(t0: u128, mut t1: u128, mut t2: u128, mut t3: u128, mut t4: u128) -> Fe {
    // Carry chain in u128, then fold the top carry back through ·19.
    t1 += t0 >> 51;
    let r0 = (t0 as u64) & MASK51;
    t2 += t1 >> 51;
    let r1 = (t1 as u64) & MASK51;
    t3 += t2 >> 51;
    let r2 = (t2 as u64) & MASK51;
    t4 += t3 >> 51;
    let r3 = (t3 as u64) & MASK51;
    let carry = (t4 >> 51) as u64;
    let r4 = (t4 as u64) & MASK51;
    let mut r = [r0 + carry * 19, r1, r2, r3, r4];
    let c = r[0] >> 51;
    r[0] &= MASK51;
    r[1] += c;
    r
}

/// `a²`: the symmetric products are formed once and doubled, 15
/// multiplies against `fe_mul`'s 25.
fn fe_sq(a: &Fe) -> Fe {
    let a0 = a[0] as u128;
    let a1 = a[1] as u128;
    let a2 = a[2] as u128;
    let a3 = a[3] as u128;
    let a4 = a[4] as u128;
    let d0 = (a[0] * 2) as u128;
    let d1 = (a[1] * 2) as u128;
    let a3_19 = (a[3] * 19) as u128;
    let a4_19 = (a[4] * 19) as u128;
    let d3_19 = (a[3] * 38) as u128;

    let t0 = a0 * a0 + d1 * a4_19 + (a[2] * 2) as u128 * a3_19;
    let t1 = d0 * a1 + (a[2] * 2) as u128 * a4_19 + a3 * a3_19;
    let t2 = d0 * a2 + a1 * a1 + d3_19 * a4;
    let t3 = d0 * a3 + d1 * a2 + a4 * a4_19;
    let t4 = d0 * a4 + d1 * a3 + a2 * a2;
    fe_carry_wide(t0, t1, t2, t3, t4)
}

/// `a·c` for a small constant `c < 2^20`.
fn fe_mul_small(a: &Fe, c: u64) -> Fe {
    let c = c as u128;
    fe_carry_wide(
        a[0] as u128 * c,
        a[1] as u128 * c,
        a[2] as u128 * c,
        a[3] as u128 * c,
        a[4] as u128 * c,
    )
}

/// `a + b` without a carry pass, for the ladder: its operands are
/// `fe_mul`/`fe_sq` outputs (limbs < 2^52), so the sum stays below 2^53
/// and feeds a multiply, which accepts limbs up to 2^54.
#[inline(always)]
fn fe_add_lazy(a: &Fe, b: &Fe) -> Fe {
    [
        a[0] + b[0],
        a[1] + b[1],
        a[2] + b[2],
        a[3] + b[3],
        a[4] + b[4],
    ]
}

/// `a - b + 2p` without a carry pass, on the same terms as `fe_add_lazy`
/// (b's limbs < 2^52 do not exceed 2p's, so nothing underflows).
#[inline(always)]
fn fe_sub_lazy(a: &Fe, b: &Fe) -> Fe {
    [
        a[0] + 0xFFFFFFFFFFFDA - b[0],
        a[1] + 0xFFFFFFFFFFFFE - b[1],
        a[2] + 0xFFFFFFFFFFFFE - b[2],
        a[3] + 0xFFFFFFFFFFFFE - b[3],
        a[4] + 0xFFFFFFFFFFFFE - b[4],
    ]
}

/// a^e mod p for a PUBLIC exponent `e` (U256 limbs, little-endian).
/// Simple right-to-left square-and-multiply — the branch is on constant
/// exponent bits, never on secret data (same pattern as p256 `fp_inv`).
fn fe_pow(a: &Fe, e: &U256) -> Fe {
    let mut result = FE_ONE;
    let mut base = *a;
    let mut i = 0;
    while i < 4 {
        let mut j = 0;
        while j < 64 {
            if (e[i] >> j) & 1 == 1 {
                result = fe_mul(&result, &base);
            }
            base = fe_sq(&base);
            j += 1;
        }
        i += 1;
    }
    result
}

/// Modular inversion via Fermat: a^(p-2) mod p.
fn fe_invert(a: &Fe) -> Fe {
    // a^(2^255 - 21) by the standard chain: 254 squarings, 11 multiplies.
    let z2 = fe_sq(a);
    let z8 = fe_sq_n(&z2, 2);
    let z9 = fe_mul(&z8, a);
    let z11 = fe_mul(&z9, &z2);
    let z22 = fe_sq(&z11);
    let z_5_0 = fe_mul(&z22, &z9);
    let z_10_0 = fe_mul(&fe_sq_n(&z_5_0, 5), &z_5_0);
    let z_20_0 = fe_mul(&fe_sq_n(&z_10_0, 10), &z_10_0);
    let z_40_0 = fe_mul(&fe_sq_n(&z_20_0, 20), &z_20_0);
    let z_50_0 = fe_mul(&fe_sq_n(&z_40_0, 10), &z_10_0);
    let z_100_0 = fe_mul(&fe_sq_n(&z_50_0, 50), &z_50_0);
    let z_200_0 = fe_mul(&fe_sq_n(&z_100_0, 100), &z_100_0);
    let z_250_0 = fe_mul(&fe_sq_n(&z_200_0, 50), &z_50_0);
    fe_mul(&fe_sq_n(&z_250_0, 5), &z11)
}

/// `a^(2^n)`.
fn fe_sq_n(a: &Fe, n: u32) -> Fe {
    let mut r = *a;
    let mut i = 0;
    while i < n {
        r = fe_sq(&r);
        i += 1;
    }
    r
}

/// Canonical little-endian encoding (fully reduced below p, bit 255 clear).
fn fe_tobytes(h: &Fe) -> [u8; 32] {
    let mut t = *h;
    fe_carry(&mut t); // limbs strictly < 2^51 after two passes

    // q = 1 iff t >= p (ripple the +19 carry through all limbs).
    let mut q = (t[0] + 19) >> 51;
    q = (t[1] + q) >> 51;
    q = (t[2] + q) >> 51;
    q = (t[3] + q) >> 51;
    q = (t[4] + q) >> 51;

    // t += 19·q, then mask to 255 bits: subtracts q·p in one move.
    t[0] += 19 * q;
    let mut c = t[0] >> 51;
    t[0] &= MASK51;
    t[1] += c;
    c = t[1] >> 51;
    t[1] &= MASK51;
    t[2] += c;
    c = t[2] >> 51;
    t[2] &= MASK51;
    t[3] += c;
    c = t[3] >> 51;
    t[3] &= MASK51;
    t[4] += c;
    t[4] &= MASK51; // drops the 2^255 bit

    let w0 = t[0] | (t[1] << 51);
    let w1 = (t[1] >> 13) | (t[2] << 38);
    let w2 = (t[2] >> 26) | (t[3] << 25);
    let w3 = (t[3] >> 39) | (t[4] << 12);

    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&w0.to_le_bytes());
    out[8..16].copy_from_slice(&w1.to_le_bytes());
    out[16..24].copy_from_slice(&w2.to_le_bytes());
    out[24..32].copy_from_slice(&w3.to_le_bytes());
    out
}

/// Decode 32 little-endian bytes into limbs. Bit 255 (the sign bit in
/// point encodings) is ignored, per RFC 8032 §5.1.3.
fn fe_frombytes(s: &[u8; 32]) -> Fe {
    let mut w = [0u64; 4];
    let mut i = 0;
    while i < 4 {
        w[i] = u64::from_le_bytes([
            s[i * 8],
            s[i * 8 + 1],
            s[i * 8 + 2],
            s[i * 8 + 3],
            s[i * 8 + 4],
            s[i * 8 + 5],
            s[i * 8 + 6],
            s[i * 8 + 7],
        ]);
        i += 1;
    }
    [
        w[0] & MASK51,
        ((w[0] >> 51) | (w[1] << 13)) & MASK51,
        ((w[1] >> 38) | (w[2] << 26)) & MASK51,
        ((w[2] >> 25) | (w[3] << 39)) & MASK51,
        (w[3] >> 12) & MASK51,
    ]
}

fn fe_iszero(a: &Fe) -> bool {
    let b = fe_tobytes(a);
    let mut acc = 0u8;
    let mut i = 0;
    while i < 32 {
        acc |= b[i];
        i += 1;
    }
    acc == 0
}

fn fe_eq(a: &Fe, b: &Fe) -> bool {
    fe_iszero(&fe_sub(a, b))
}

/// Parity of the canonical representative — the RFC 8032 "sign" bit.
fn fe_isnegative(a: &Fe) -> bool {
    fe_tobytes(a)[0] & 1 == 1
}

/// Constant-time select: `b` where mask is all-ones, `a` where all-zeros.
/// Mask comes from `ct_eq_u64` (p256.rs).
#[inline(always)]
fn fe_select(a: &Fe, b: &Fe, mask: u64) -> Fe {
    let mut r = [0u64; 5];
    let mut i = 0;
    while i < 5 {
        r[i] = (a[i] & !mask) | (b[i] & mask);
        i += 1;
    }
    r
}

// ============================================================================
// Group arithmetic (extended coordinates X, Y, Z, T; x = X/Z, y = Y/Z,
// T = XY/Z). Unified complete formulas — no identity special cases.
// ============================================================================

struct GeP3 {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl GeP3 {
    const fn identity() -> Self {
        Self {
            x: FE_ZERO,
            y: FE_ONE,
            z: FE_ONE,
            t: FE_ZERO,
        }
    }

    fn copy(&self) -> Self {
        Self {
            x: self.x,
            y: self.y,
            z: self.z,
            t: self.t,
        }
    }
}

/// Unified point addition, add-2008-hwcd-3 (a = -1, uses 2d). COMPLETE:
/// valid for every input pair, including identity and low-order points —
/// no data-dependent branches.
fn ge_add(p: &GeP3, q: &GeP3) -> GeP3 {
    let a = fe_mul(&fe_sub(&p.y, &p.x), &fe_sub(&q.y, &q.x));
    let b = fe_mul(&fe_add(&p.y, &p.x), &fe_add(&q.y, &q.x));
    let d2 = ed_load_d2();
    let c = fe_mul(&fe_mul(&p.t, &d2), &q.t);
    let zz = fe_mul(&p.z, &q.z);
    let d = fe_add(&zz, &zz);
    let e = fe_sub(&b, &a);
    let f = fe_sub(&d, &c);
    let g = fe_add(&d, &c);
    let h = fe_add(&b, &a);
    GeP3 {
        x: fe_mul(&e, &f),
        y: fe_mul(&g, &h),
        z: fe_mul(&f, &g),
        t: fe_mul(&e, &h),
    }
}

/// Point doubling, dbl-2008-hwcd specialised to a = -1. Branch-free.
fn ge_double(p: &GeP3) -> GeP3 {
    let a = fe_sq(&p.x);
    let b = fe_sq(&p.y);
    let zz = fe_sq(&p.z);
    let c = fe_add(&zz, &zz);
    // D = a·A = -A  (a = -1)
    let e = {
        let xy = fe_add(&p.x, &p.y);
        let xy2 = fe_sq(&xy);
        fe_sub(&fe_sub(&xy2, &a), &b)
    };
    let g = fe_sub(&b, &a); // G = D + B = B - A
    let f = fe_sub(&g, &c); // F = G - C
    let h = fe_neg(&fe_add(&a, &b)); // H = D - B = -(A + B)
    GeP3 {
        x: fe_mul(&e, &f),
        y: fe_mul(&g, &h),
        z: fe_mul(&f, &g),
        t: fe_mul(&e, &h),
    }
}

/// Constant-time 16-entry table lookup (same defence as p256's
/// `ct_lookup_table_16`): scans every entry, selecting via arithmetic
/// mask — no secret-indexed memory access.
fn ge_ct_lookup(table: &[GeP3; 16], idx: usize) -> GeP3 {
    let mut out = GeP3 {
        x: FE_ZERO,
        y: FE_ZERO,
        z: FE_ZERO,
        t: FE_ZERO,
    };
    let mut i = 0u64;
    while i < 16 {
        let mask = ct_eq_u64(i, idx as u64);
        let entry = &table[i as usize];
        out.x = fe_select(&out.x, &entry.x, mask);
        out.y = fe_select(&out.y, &entry.y, mask);
        out.z = fe_select(&out.z, &entry.z, mask);
        out.t = fe_select(&out.t, &entry.t, mask);
        i += 1;
    }
    out
}

/// Scalar multiplication `k · P`, fixed-window w=4 with constant-time
/// table lookup. `k` is a 256-bit little-endian scalar. Because the
/// point formulas are complete (no identity short-circuits) AND the
/// lookup is constant-time, the secret-scalar path here has no
/// data-dependent branch or memory access — a strictly stronger
/// property than p256's `scalar_mul_ct` (whose disclosure documents a
/// zero-nibble leak through identity short-circuits).
fn ge_scalar_mul_ct(k: &[u8; 32], p: &GeP3) -> GeP3 {
    // table[i] = i · P, i ∈ 0..16
    let mut table: [GeP3; 16] = [
        GeP3::identity(),
        p.copy(),
        GeP3::identity(),
        GeP3::identity(),
        GeP3::identity(),
        GeP3::identity(),
        GeP3::identity(),
        GeP3::identity(),
        GeP3::identity(),
        GeP3::identity(),
        GeP3::identity(),
        GeP3::identity(),
        GeP3::identity(),
        GeP3::identity(),
        GeP3::identity(),
        GeP3::identity(),
    ];
    let mut i = 2;
    while i < 16 {
        table[i] = if i & 1 == 0 {
            ge_double(&table[i / 2])
        } else {
            ge_add(&table[i - 1], p)
        };
        i += 1;
    }

    // Walk the 64 nibbles MSB → LSB.
    let mut acc = GeP3::identity();
    let mut w: i32 = 63;
    while w >= 0 {
        acc = ge_double(&ge_double(&ge_double(&ge_double(&acc))));
        let byte = k[(w as usize) / 2];
        let nibble = ((byte >> ((w as u32 & 1) * 4)) & 0xF) as usize;
        let pt = ge_ct_lookup(&table, nibble);
        acc = ge_add(&acc, &pt);
        w -= 1;
    }
    acc
}

/// Scalar multiplication of the base point B (By = 4/5, even Bx).
fn ge_scalar_mul_base(k: &[u8; 32]) -> GeP3 {
    let bx = ed_load_bx();
    let by = ed_load_by();
    let b = GeP3 {
        x: bx,
        y: by,
        z: FE_ONE,
        t: fe_mul(&bx, &by),
    };
    ge_scalar_mul_ct(k, &b)
}

/// Compress to the RFC 8032 wire form: 255-bit little-endian y with the
/// parity of x in bit 255.
fn ge_tobytes(p: &GeP3) -> [u8; 32] {
    let zinv = fe_invert(&p.z);
    let x = fe_mul(&p.x, &zinv);
    let y = fe_mul(&p.y, &zinv);
    let mut s = fe_tobytes(&y);
    s[31] |= (fe_tobytes(&x)[0] & 1) << 7;
    s
}

/// Strict RFC 8032 §5.1.3 point decompression. Variable-time (used only
/// on public inputs). Returns `None` when:
///   - the y coordinate is non-canonical (≥ p),
///   - x² = (y²-1)/(dy²+1) has no square root (not on the curve),
///   - x = 0 with the sign bit set (the RFC's excluded encoding).
fn ge_frombytes_vartime(s: &[u8; 32]) -> Option<GeP3> {
    // Canonical-y check: the 255-bit value must be < p.
    let mut y_limbs: U256 = [0; 4];
    let mut i = 0;
    while i < 4 {
        y_limbs[i] = u64::from_le_bytes([
            s[i * 8],
            s[i * 8 + 1],
            s[i * 8 + 2],
            s[i * 8 + 3],
            s[i * 8 + 4],
            s[i * 8 + 5],
            s[i * 8 + 6],
            s[i * 8 + 7],
        ]);
        i += 1;
    }
    y_limbs[3] &= 0x7FFFFFFFFFFFFFFF; // strip the sign bit
    let p_limbs = ed_load_p();
    if u256_gte(&y_limbs, &p_limbs) != 0 {
        return None;
    }
    let sign = (s[31] >> 7) & 1;

    let y = fe_frombytes(s);
    let yy = fe_sq(&y);
    let u = fe_sub(&yy, &FE_ONE); // y² - 1
    let d = ed_load_d();
    let v = fe_add(&fe_mul(&d, &yy), &FE_ONE); // d·y² + 1

    // Candidate root x = u·v³·(u·v⁷)^((p-5)/8)  (p ≡ 5 mod 8).
    let v3 = fe_mul(&fe_sq(&v), &v);
    let v7 = fe_mul(&fe_sq(&v3), &v);
    let p58 = ed_load_p58();
    let pow = fe_pow(&fe_mul(&u, &v7), &p58);
    let mut x = fe_mul(&fe_mul(&u, &v3), &pow);

    let vxx = fe_mul(&v, &fe_sq(&x));
    if !fe_eq(&vxx, &u) {
        if fe_eq(&vxx, &fe_neg(&u)) {
            let sqrtm1 = ed_load_sqrtm1();
            x = fe_mul(&x, &sqrtm1);
        } else {
            return None; // not a square — point not on the curve
        }
    }

    if fe_iszero(&x) {
        if sign == 1 {
            return None; // x = 0 with sign bit set is invalid
        }
    } else if fe_isnegative(&x) != (sign == 1) {
        x = fe_neg(&x);
    }

    let t = fe_mul(&x, &y);
    Some(GeP3 { x, y, z: FE_ONE, t })
}

fn ge_is_identity(p: &GeP3) -> bool {
    fe_iszero(&p.x) && fe_eq(&p.y, &p.z)
}

/// True when the point's order divides 8 (identity or torsion): [8]·P is
/// identity. Used to reject degenerate public keys / R values.
fn ge_is_small_order(p: &GeP3) -> bool {
    ge_is_identity(&ge_double(&ge_double(&ge_double(p))))
}

// ============================================================================
// Scalar arithmetic mod L = 2^252 + 27742317777372353535851937790883648493
// ============================================================================

fn sc_from_bytes_le(s: &[u8; 32]) -> U256 {
    let mut r: U256 = [0; 4];
    let mut i = 0;
    while i < 4 {
        r[i] = u64::from_le_bytes([
            s[i * 8],
            s[i * 8 + 1],
            s[i * 8 + 2],
            s[i * 8 + 3],
            s[i * 8 + 4],
            s[i * 8 + 5],
            s[i * 8 + 6],
            s[i * 8 + 7],
        ]);
        i += 1;
    }
    r
}

fn sc_to_bytes_le(a: &U256) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&a[i].to_le_bytes());
        i += 1;
    }
    out
}

/// Reduce a 512-bit value (8 little-endian u64 limbs) mod L.
///
/// Horner over the limbs, folding once per step with 2^252 ≡ -c0 (mod L)
/// where c0 = L - 2^252 (~125 bits): for a 320-bit intermediate
/// v = hi·2^252 + lo, v ≡ lo - hi·c0, with hi < 2^68 so hi·c0 < 2^193;
/// a single conditional +L repairs the borrow and the result stays < L.
fn sc_reduce_wide(t: &[u64; 8]) -> U256 {
    let l = ed_load_l();
    let c0 = [l[0], l[1]]; // L - 2^252, two limbs (~125 bits)

    let mut acc: U256 = ZERO;
    let mut i: i32 = 7;
    while i >= 0 {
        // v = acc·2^64 + t[i], five limbs (< L·2^64 < 2^317).
        let v = [t[i as usize], acc[0], acc[1], acc[2], acc[3]];
        // hi = v >> 252 (< 2^65), lo = v mod 2^252.
        let h0 = (v[3] >> 60) | (v[4] << 4);
        let h1 = v[4] >> 60;
        let lo: U256 = [v[0], v[1], v[2], v[3] & 0x0FFFFFFFFFFFFFFF];

        // prod = hi · c0 (≤ 2^193, four limbs). Column accumulation in u128.
        let mut prod: U256 = [0; 4];
        let mut carry: u128 = (h0 as u128) * (c0[0] as u128);
        prod[0] = carry as u64;
        carry >>= 64;
        carry += (h0 as u128) * (c0[1] as u128) + (h1 as u128) * (c0[0] as u128);
        prod[1] = carry as u64;
        carry >>= 64;
        carry += (h1 as u128) * (c0[1] as u128);
        prod[2] = carry as u64;
        prod[3] = (carry >> 64) as u64;

        // acc = lo - hi·c0 (mod L); one +L repairs any borrow. The
        // repair is computed unconditionally and selected under a mask
        // built from the borrow, so the branch does not exist: this
        // routine runs over the signing nonce.
        let (d, borrow) = u256_sub(&lo, &prod);
        let repaired = u256_add(&d, &l).0;
        acc = ct_select_u256(&d, &repaired, borrow.wrapping_neg());
        i -= 1;
    }
    acc
}

/// (a·b + c) mod L. `a` may be a full 256-bit clamped scalar (not reduced
/// mod L); `b` and `c` must already be < L.
fn sc_mul_add(a: &U256, b: &U256, c: &U256) -> U256 {
    let wide = u256_mul_wide(a, b);
    let r = sc_reduce_wide(&wide);
    let (sum, _) = u256_add(&r, c); // r, c < L so sum < 2L < 2^253: no carry
    let l = ed_load_l();
    if u256_gte(&sum, &l) != 0 {
        let (d, _) = u256_sub(&sum, &l);
        d
    } else {
        sum
    }
}

/// SHA-512 output reduced mod L (RFC 8032 nonce / challenge derivation).
fn sc_from_hash(h: &[u8; 64]) -> U256 {
    let mut wide = [0u64; 8];
    let mut i = 0;
    while i < 8 {
        wide[i] = u64::from_le_bytes([
            h[i * 8],
            h[i * 8 + 1],
            h[i * 8 + 2],
            h[i * 8 + 3],
            h[i * 8 + 4],
            h[i * 8 + 5],
            h[i * 8 + 6],
            h[i * 8 + 7],
        ]);
        i += 1;
    }
    sc_reduce_wide(&wide)
}

// ============================================================================
// Public API (RFC 8032 §5.1)
// ============================================================================

/// Expand a 32-byte seed into the clamped secret scalar and the 32-byte
/// prefix (RFC 8032 §5.1.5 steps 1-2). Caller must zeroise both.
fn ed_expand_seed(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut h = sha512(seed);
    let mut a = [0u8; 32];
    let mut prefix = [0u8; 32];
    a.copy_from_slice(&h[0..32]);
    prefix.copy_from_slice(&h[32..64]);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    zeroize(&mut h);
    (a, prefix)
}

/// Derive the 32-byte Ed25519 public key from a 32-byte seed
/// (RFC 8032 §5.1.5).
pub fn ed25519_public_key(seed: &[u8; 32]) -> [u8; 32] {
    let (mut a, mut prefix) = ed_expand_seed(seed);
    let point = ge_scalar_mul_base(&a);
    let out = ge_tobytes(&point);
    zeroize(&mut a);
    zeroize(&mut prefix);
    out
}

/// Sign `message` with the 32-byte seed (RFC 8032 §5.1.6). Deterministic:
/// the nonce is r = SHA-512(prefix ‖ message) mod L — no runtime
/// randomness. Returns the 64-byte signature `R ‖ S` (S little-endian,
/// reduced mod L). Secret intermediates are zeroised before returning.
pub fn ed25519_sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let (mut a, mut prefix) = ed_expand_seed(seed);

    // Public key A = [a]B (needed inside the challenge hash).
    let a_point = ge_scalar_mul_base(&a);
    let a_enc = ge_tobytes(&a_point);

    // r = SHA-512(prefix ‖ M) mod L; R = [r]B.
    let mut hr = Sha512::new();
    hr.update(&prefix);
    hr.update(message);
    let mut r_hash = hr.finalize();
    let mut r = sc_from_hash(&r_hash);
    zeroize(&mut r_hash);
    let mut r_bytes = sc_to_bytes_le(&r);
    let r_point = ge_scalar_mul_base(&r_bytes);
    let r_enc = ge_tobytes(&r_point);

    // k = SHA-512(R ‖ A ‖ M) mod L; S = (r + k·a) mod L.
    let mut hk = Sha512::new();
    hk.update(&r_enc);
    hk.update(&a_enc);
    hk.update(message);
    let k = sc_from_hash(&hk.finalize());
    let mut a_sc = sc_from_bytes_le(&a);
    let s = sc_mul_add(&k, &a_sc, &r);

    zeroize(&mut a);
    zeroize(&mut prefix);
    zeroize(&mut r_bytes);
    zeroize_u256(&mut r);
    zeroize_u256(&mut a_sc);

    let mut sig = [0u8; 64];
    sig[0..32].copy_from_slice(&r_enc);
    sig[32..64].copy_from_slice(&sc_to_bytes_le(&s));
    sig
}

/// Verify a 64-byte signature `R ‖ S` over `message` (RFC 8032 §5.1.7,
/// unbatched equation [S]B = R + [k]A). VARIABLE-TIME: all inputs are
/// public. Strict checks, all of which return `false`:
///   - S ≥ L (malleability rejection),
///   - non-canonical or off-curve encodings of A or R,
///   - small-order (order dividing 8) A or R — rejects the identity /
///     torsion public keys for which every (R = A, S = 0)-style forgery
///     would verify. Honest signatures always have prime-order R.
pub fn ed25519_verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    // S canonical: strictly below the group order.
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..64]);
    let s = sc_from_bytes_le(&s_bytes);
    let l = ed_load_l();
    if u256_gte(&s, &l) != 0 {
        return false;
    }

    let a_point = match ge_frombytes_vartime(public_key) {
        Some(p) => p,
        None => return false,
    };
    let mut r_enc = [0u8; 32];
    r_enc.copy_from_slice(&signature[0..32]);
    let r_point = match ge_frombytes_vartime(&r_enc) {
        Some(p) => p,
        None => return false,
    };
    if ge_is_small_order(&a_point) || ge_is_small_order(&r_point) {
        return false;
    }

    // k = SHA-512(R ‖ A ‖ M) mod L over the wire encodings as received.
    let mut hk = Sha512::new();
    hk.update(&r_enc);
    hk.update(public_key);
    hk.update(message);
    let k = sc_from_hash(&hk.finalize());
    let k_bytes = sc_to_bytes_le(&k);

    // [S]B == R + [k]A (compare compressed encodings — projective-safe).
    let lhs = ge_scalar_mul_base(&s_bytes);
    let ka = ge_scalar_mul_ct(&k_bytes, &a_point);
    let rhs = ge_add(&r_point, &ka);
    ge_tobytes(&lhs) == ge_tobytes(&rhs)
}

// ============================================================================
// X25519 key agreement (RFC 7748)
// ============================================================================
//
// Curve25519 in Montgomery form v² = u³ + 486662·u² + u over the same
// p = 2^255 - 19 and the same radix-51 `fe_*` layer above. It lives in
// this file rather than a file of its own because it reuses that layer
// verbatim; splitting it would add a mount to every consumer's include
// set for no gain.
//
// This is the constant-time key agreement for this tree. Every
// operation below is branchless with a fixed trip count:
//
//   - the ladder runs exactly 255 iterations regardless of the scalar;
//   - the conditional swap is `fe_select` on a mask built from a scalar
//     bit, never an `if`;
//   - the field layer is the branchless one documented in this file's
//     header — no value-dependent reduction loops;
//   - the Montgomery ladder on Curve25519 has no exceptional cases, so
//     there are no identity short-circuits to leak which case was hit;
//   - inversion is `fe_invert`, whose square-and-multiply schedule is
//     driven by the PUBLIC exponent p-2.
//
// The one value-dependent decision is the all-zero output check in
// `x25519_shared_secret`, which acts on the RESULT of the exchange
// after the secret scalar has been consumed and is a rejection
// condition the caller must observe.

/// Scalar clamping, RFC 7748 §5: clear the three low bits (cofactor),
/// clear bit 255 and set bit 254 (fixed ladder length, and it keeps the
/// scalar above the low-order subgroup).
fn x25519_clamp(k: &mut [u8; 32]) {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

/// The Montgomery ladder of RFC 7748 §5 over the radix-51 field, held
/// across steps.
///
/// `k` is kept already clamped. `u` is the affine u-coordinate; per §5
/// its bit 255 is ignored on decode, which `fe_frombytes` already does.
/// The ladder is constant-time in `k` and `u`: 255 fixed iterations,
/// masked swaps, no data-dependent branch or load address. How many of
/// those iterations one `step` covers is the caller's `bits_per_step`,
/// the same budget the P-256 ladder is driven at, so a key agreement
/// fits a tick on any core rather than costing one call of whatever the
/// core takes.
/// The Ed25519 base point's four-tooth comb, for X25519 key generation:
/// entry `idx` is the affine point `sum of 2^(64t)·B over the set bits t of
/// idx`, as `(y+x, y-x, 2d·x·y)` radix-51 limbs. Entry 0 is the identity
/// `(1, 1, 0)`, which the complete addition takes like any other.
static X25519_COMB: [[u64; 15]; 16] = [
    [
        0x0000000000001,
        0x0000000000000,
        0x0000000000000,
        0x0000000000000,
        0x0000000000000,
        0x0000000000001,
        0x0000000000000,
        0x0000000000000,
        0x0000000000000,
        0x0000000000000,
        0x0000000000000,
        0x0000000000000,
        0x0000000000000,
        0x0000000000000,
        0x0000000000000,
    ],
    [
        0x493c6f58c3b85,
        0x0df7181c325f7,
        0x0f50b0b3e4cb7,
        0x5329385a44c32,
        0x07cf9d3a33d4b,
        0x03905d740913e,
        0x0ba2817d673a2,
        0x23e2827f4e67c,
        0x133d2e0c21a34,
        0x44fd2f9298f81,
        0x11205877aaa68,
        0x479955893d579,
        0x50d66309b67a0,
        0x2d42d0dbee5ee,
        0x6f117b689f0c6,
    ],
    [
        0x265e777d1f515,
        0x0f1f54c1e39a5,
        0x2f01b95522646,
        0x4fdd8db9dde6d,
        0x654878cba97cc,
        0x38ec78df6b0fe,
        0x13caebea36a22,
        0x5ebc6e54e5f6a,
        0x32804903d0eb8,
        0x2102fdba2b20d,
        0x6e405055ce6a1,
        0x5024a35a532d3,
        0x1f69054daf29d,
        0x15d1d0d7a8bd5,
        0x0ad725db29ecb,
    ],
    [
        0x5c585601e59e8,
        0x56cc901cc000a,
        0x11791321e4cd0,
        0x7959f0a55687f,
        0x26ead8e64813c,
        0x5b8b69c8462a4,
        0x0acfa639af96e,
        0x04d0bd8b761bf,
        0x797e68cb97644,
        0x0975b5970fc12,
        0x72303da5ba743,
        0x02a5e374dcc79,
        0x1cd9f6812fe76,
        0x2f5199bc86855,
        0x534670479df6c,
    ],
    [
        0x304bfacad8ea2,
        0x502917d108b07,
        0x043176ca6dd0f,
        0x5d5158f2c1d84,
        0x2b5449e58eb3b,
        0x27562eb3dbe47,
        0x291d7b4170be7,
        0x5d1ca67dfa8e1,
        0x2a88061f298a2,
        0x1304e9e71627d,
        0x014d26adc9cfe,
        0x7f1691ba16f13,
        0x5e71828f06eac,
        0x349ed07f0fffc,
        0x4468de2d7c2dd,
    ],
    [
        0x0278de3bc6748,
        0x41a1641dee423,
        0x1eec6639c7ff5,
        0x6a6faa8df28e3,
        0x26a13664d0543,
        0x22d3b13a339ee,
        0x20d9b12a5252a,
        0x3d3c3c6154895,
        0x2176ff51d6a56,
        0x49d76bba79427,
        0x242338d56e61d,
        0x0d86a2533429f,
        0x6b6c6146474e5,
        0x6e1123eabb6d3,
        0x4e1fafe3a8fce,
    ],
    [
        0x7053d236a044c,
        0x62771b0fc62bc,
        0x486a0a0f376f2,
        0x5d228ccb06969,
        0x4e559a0f0fc5b,
        0x0e8769c12701c,
        0x14073876bffc0,
        0x00bac6e577370,
        0x18660b4a2a586,
        0x727021d35f875,
        0x1040727df241e,
        0x5565201a6d4ae,
        0x29a6b7b7d17be,
        0x00eff376dae30,
        0x64fcb73007bbc,
    ],
    [
        0x758cc6fd390ca,
        0x6a2e3531f871d,
        0x10b597fbde195,
        0x377c4285bc7e2,
        0x6f34c66d6fd08,
        0x3cbb43898dc04,
        0x64860f6e4f27e,
        0x0d260741e47fe,
        0x7b6ebdec04b67,
        0x0b598b8e8b849,
        0x7c18a0cc2f689,
        0x0f6a539c54239,
        0x02d6502044518,
        0x364054de02360,
        0x412128b0b1ac6,
    ],
    [
        0x5cc9dc80c1ac0,
        0x683671486d4cd,
        0x76f5f1a5e8173,
        0x6d5d3f5f9df4a,
        0x7da0b8f68d7e7,
        0x02014385675a6,
        0x6155fb53d1def,
        0x37ea32e89927c,
        0x059a668f5a82e,
        0x46115aba1d4dc,
        0x71953c3b5da76,
        0x6642233d37a81,
        0x2c9658076b1bd,
        0x5a581e63010ff,
        0x5a5f887e83674,
    ],
    [
        0x560180ca2c1f4,
        0x3798d1be80151,
        0x0bd3a66057ac3,
        0x2e06bf33d23dc,
        0x45a02890607f1,
        0x366d1fd41f184,
        0x22039fc23dfde,
        0x5429d362da528,
        0x0dd259cf0af00,
        0x4013f03d6ad35,
        0x282dc6ee065cc,
        0x7a4495cc8d7a0,
        0x2f3a1d0dae653,
        0x727a9a74d6c7f,
        0x482255c1d9f06,
    ],
    [
        0x3eacf71cef800,
        0x099515fd76780,
        0x0a711de40d9d5,
        0x2311c1ff51435,
        0x4e8593b0bc655,
        0x6114aa3e5638c,
        0x525389e41a25b,
        0x62c4e8ee8a92a,
        0x4a22b58694ebd,
        0x6bb91a497b9b7,
        0x1e646c5e7d206,
        0x1b24c7888a549,
        0x6ad4a7ac4fbe7,
        0x1cda855b67476,
        0x20cf7d79b0ebe,
    ],
    [
        0x28f4e8ae75c48,
        0x22880016c197a,
        0x2f085c0f3780a,
        0x4431b9ddce44c,
        0x7c1188539f570,
        0x4939df0fe7dca,
        0x1f9752a39cfb6,
        0x5f87477d43ae4,
        0x34e84c5f30e1a,
        0x0235623788994,
        0x6effae15a4c03,
        0x2878ef1c0a41e,
        0x267799cbd1c2a,
        0x241bcfa8501fe,
        0x38d20188d1061,
    ],
    [
        0x011ad0e6315df,
        0x0bc55d652047d,
        0x57561b02d9434,
        0x6f75bdd07acd3,
        0x043eedd45e1f4,
        0x147f2c7073217,
        0x33e75fa419ed8,
        0x107e00b1946e4,
        0x39f12c7edfeb8,
        0x173c4fa94f450,
        0x1ea60928df9c4,
        0x0c66e6ac5a7ae,
        0x2554ac96df9e0,
        0x2396cd828a651,
        0x1e2a7024993cc,
    ],
    [
        0x20fbcd45c811f,
        0x7b25d81006c03,
        0x74901fc92def1,
        0x593506573158b,
        0x5fcb43ee06225,
        0x509b93509fba4,
        0x6c0ac636ea620,
        0x100721c3636cd,
        0x3b9cbef665d29,
        0x044649f411b2e,
        0x524ad9598215f,
        0x4d986cc518181,
        0x05b73a86dfe40,
        0x2c799c717aab8,
        0x0c8a1bfa5cc0e,
    ],
    [
        0x703b5681d104c,
        0x3224c7968b1bc,
        0x395b18cf4bde9,
        0x3655738860b8e,
        0x6b857c7efcc3e,
        0x256b48b2801c0,
        0x5878801f88f3a,
        0x4cee905fa7efa,
        0x56553a8d58ea3,
        0x09de2bf5dd418,
        0x10ff3eff0687f,
        0x69e3c6f74477e,
        0x5980d357aeba8,
        0x165724f30930e,
        0x5b466e2ac3b24,
    ],
    [
        0x6eb6747fbb842,
        0x6ac102351626f,
        0x7e32269e77d71,
        0x7e12d15d3b7b8,
        0x09952a563bc8f,
        0x0cb4bdc7ef83c,
        0x74bf27844d455,
        0x1938e965ad71b,
        0x797ea75f58d83,
        0x409b4adce5c6c,
        0x53db9834350c4,
        0x0b4bea0b6889a,
        0x527fcbe24a64c,
        0x6b27d917d512c,
        0x69b968a704657,
    ],
];

/// Column `i` of the comb: bits `i`, `64+i`, `128+i` and `192+i` of the
/// little-endian scalar.
#[inline(always)]
fn x25519_comb_index(k: &[u8; 32], i: usize) -> u64 {
    let bit = |b: usize| u64::from((k[b >> 3] >> (b & 7)) & 1);
    bit(i) | (bit(64 + i) << 1) | (bit(128 + i) << 2) | (bit(192 + i) << 3)
}

/// `X25519_COMB[idx]` without branching on `idx` or using it as an
/// address: every entry is read and the match selected under a mask.
fn x25519_comb_lookup(idx: u64) -> (Fe, Fe, Fe) {
    let mut ypx = FE_ZERO;
    let mut ymx = FE_ZERO;
    let mut xy2d = FE_ZERO;
    let mut i = 0;
    while i < 16 {
        let mask = ct_eq_u64(i as u64, idx);
        let e = &X25519_COMB[i];
        ypx = fe_select(&ypx, &[e[0], e[1], e[2], e[3], e[4]], mask);
        ymx = fe_select(&ymx, &[e[5], e[6], e[7], e[8], e[9]], mask);
        xy2d = fe_select(&xy2d, &[e[10], e[11], e[12], e[13], e[14]], mask);
        i += 1;
    }
    (ypx, ymx, xy2d)
}

/// `p + q` for an affine `q` given as `(y+x, y-x, 2d·x·y)`: `ge_add` with
/// `q.z = 1`, complete like it.
fn ge_madd(p: &GeP3, ypx: &Fe, ymx: &Fe, xy2d: &Fe) -> GeP3 {
    let a = fe_mul(&fe_sub(&p.y, &p.x), ymx);
    let b = fe_mul(&fe_add(&p.y, &p.x), ypx);
    let c = fe_mul(&p.t, xy2d);
    let d = fe_add(&p.z, &p.z);
    let e = fe_sub(&b, &a);
    let f = fe_sub(&d, &c);
    let g = fe_add(&d, &c);
    let h = fe_add(&b, &a);
    GeP3 {
        x: fe_mul(&e, &f),
        y: fe_mul(&g, &h),
        z: fe_mul(&f, &g),
        t: fe_mul(&e, &h),
    }
}

pub struct X25519State {
    k: [u8; 32],
    x1: Fe,
    x2: Fe,
    z2: Fe,
    x3: Fe,
    z3: Fe,
    swap: u64,
    /// Next ladder bit, 254 down to 0, or comb column, 63 down to 0; -1 =
    /// done.
    t: i16,
    bits_per_step: u8,
    initialised: u8,
    /// 1 for `[scalar]·9` by the Edwards comb (`new_base`): `x2, z2, x3, z3`
    /// hold the accumulator's `X, Y, Z, T` and `x1` is unused.
    comb: u8,
}

impl X25519State {
    pub const fn empty() -> Self {
        Self {
            k: [0; 32],
            x1: FE_ZERO,
            x2: FE_ZERO,
            z2: FE_ZERO,
            x3: FE_ZERO,
            z3: FE_ZERO,
            swap: 0,
            t: -1,
            bits_per_step: 0,
            initialised: 0,
            comb: 0,
        }
    }

    /// `[scalar]·U` for the wire-encoded `u`. `bits_per_step == 0` runs
    /// the whole ladder in one `step`.
    pub fn new(scalar: &[u8; 32], u_in: &[u8; 32], bits_per_step: u8) -> Self {
        let mut k = *scalar;
        x25519_clamp(&mut k);
        let u = fe_frombytes(u_in);
        Self {
            k,
            x1: u,
            x2: FE_ONE,
            z2: FE_ZERO,
            x3: u,
            z3: FE_ONE,
            swap: 0,
            t: 254,
            bits_per_step,
            initialised: 1,
            comb: 0,
        }
    }

    /// `[scalar]·9`: the public key of `scalar`. The clamped scalar times the
    /// Ed25519 base point by the comb (`X25519_COMB`), one doubling and one
    /// mixed addition per column, 64 columns; `result` maps the Edwards
    /// point to the Montgomery `u = (Z+Y)/(Z-Y)`. `bits_per_step` counts
    /// columns.
    pub fn new_base(scalar: &[u8; 32], bits_per_step: u8) -> Self {
        let mut k = *scalar;
        x25519_clamp(&mut k);
        let id = GeP3::identity();
        Self {
            k,
            x1: FE_ZERO,
            x2: id.x,
            z2: id.y,
            x3: id.z,
            z3: id.t,
            swap: 0,
            t: 63,
            bits_per_step,
            initialised: 1,
            comb: 1,
        }
    }

    pub fn is_initialised(&self) -> bool {
        self.initialised != 0
    }

    pub fn complete(&self) -> bool {
        self.initialised != 0 && self.t < 0
    }

    /// Advance by up to `bits_per_step` ladder bits. True once complete.
    pub fn step(&mut self) -> bool {
        if self.initialised == 0 {
            return false;
        }
        let mut remaining: i16 = if self.bits_per_step == 0 {
            i16::MAX
        } else {
            self.bits_per_step as i16
        };
        if self.comb != 0 {
            let mut acc = GeP3 {
                x: self.x2,
                y: self.z2,
                z: self.x3,
                t: self.z3,
            };
            while remaining > 0 && self.t >= 0 {
                let (ypx, ymx, xy2d) =
                    x25519_comb_lookup(x25519_comb_index(&self.k, self.t as usize));
                acc = ge_madd(&ge_double(&acc), &ypx, &ymx, &xy2d);
                self.t -= 1;
                remaining -= 1;
            }
            self.x2 = acc.x;
            self.z2 = acc.y;
            self.x3 = acc.z;
            self.z3 = acc.t;
            return self.complete();
        }
        while remaining > 0 && self.t >= 0 {
            let t = self.t as usize;
            let bit = ((self.k[t >> 3] >> (t & 7)) & 1) as u64;
            // mask is all-ones exactly when the accumulated swap state
            // differs from the previous iteration's.
            let mask = (self.swap ^ bit).wrapping_neg();
            let nx2 = fe_select(&self.x2, &self.x3, mask);
            let nx3 = fe_select(&self.x3, &self.x2, mask);
            let nz2 = fe_select(&self.z2, &self.z3, mask);
            let nz3 = fe_select(&self.z3, &self.z2, mask);
            self.x2 = nx2;
            self.x3 = nx3;
            self.z2 = nz2;
            self.z3 = nz3;
            self.swap = bit;

            // Every lazy sum and difference below takes multiply outputs
            // and feeds a multiply; see `fe_add_lazy`.
            let a = fe_add_lazy(&self.x2, &self.z2);
            let aa = fe_sq(&a);
            let b = fe_sub_lazy(&self.x2, &self.z2);
            let bb = fe_sq(&b);
            let e = fe_sub_lazy(&aa, &bb);
            let c = fe_add_lazy(&self.x3, &self.z3);
            let d = fe_sub_lazy(&self.x3, &self.z3);
            let da = fe_mul(&d, &a);
            let cb = fe_mul(&c, &b);
            self.x3 = fe_sq(&fe_add_lazy(&da, &cb));
            self.z3 = fe_mul(&self.x1, &fe_sq(&fe_sub_lazy(&da, &cb)));
            self.x2 = fe_mul(&aa, &bb);
            self.z2 = fe_mul(&e, &fe_add_lazy(&aa, &fe_mul_small(&e, 121665)));

            self.t -= 1;
            remaining -= 1;
        }
        self.complete()
    }

    /// The u-coordinate of the result, encoded. Meaningful once `complete()`.
    pub fn result(&self) -> [u8; 32] {
        if self.comb != 0 {
            // u = (1 + y) / (1 - y) = (Z + Y) / (Z - Y).
            let num = fe_add(&self.x3, &self.z2);
            let den = fe_sub(&self.x3, &self.z2);
            return fe_tobytes(&fe_mul(&num, &fe_invert(&den)));
        }
        let mask = self.swap.wrapping_neg();
        let fx2 = fe_select(&self.x2, &self.x3, mask);
        let fz2 = fe_select(&self.z2, &self.z3, mask);
        fe_tobytes(&fe_mul(&fx2, &fe_invert(&fz2)))
    }

    /// The result as a shared secret, with the RFC 7748 §6.1 check: `None`
    /// for the all-zero value, which is what a small-order peer point
    /// yields and carries none of our scalar.
    pub fn shared_secret(&self) -> Option<[u8; 32]> {
        let mut out = self.result();
        let mut acc = 0u8;
        let mut i = 0;
        while i < 32 {
            acc |= out[i];
            i += 1;
        }
        if acc == 0 {
            zeroize(&mut out);
            return None;
        }
        Some(out)
    }

    /// Scrub the scalar and the ladder registers.
    pub fn zeroise(&mut self) {
        zeroize(&mut self.k);
        let mut i = 0;
        while i < 5 {
            // SAFETY: volatile writes to the five limbs of each register.
            unsafe {
                core::ptr::write_volatile(&mut self.x1[i], 0);
                core::ptr::write_volatile(&mut self.x2[i], 0);
                core::ptr::write_volatile(&mut self.z2[i], 0);
                core::ptr::write_volatile(&mut self.x3[i], 0);
                core::ptr::write_volatile(&mut self.z3[i], 0);
            }
            i += 1;
        }
        self.initialised = 0;
        self.t = -1;
    }
}

/// RFC 7748 §5 `X25519(k, u)` over wire encodings, with no output
/// check. This is the raw primitive: it clamps `k`, ignores bit 255 of
/// `u`, and returns the encoded u-coordinate whatever it is, so it
/// matches the §5.2 vectors (which include non-canonical `u`) and the
/// iterated test. Key agreement must use `x25519_shared_secret`, which
/// adds the check RFC 7748 §6.1 requires.
pub fn x25519(scalar: &[u8; 32], u_in: &[u8; 32]) -> [u8; 32] {
    let mut st = X25519State::new(scalar, u_in, 0);
    st.step();
    let out = st.result();
    st.zeroise();
    out
}

/// X25519 public key: `X25519(scalar, 9)`, RFC 7748 §6.1.
pub fn x25519_public_key(scalar: &[u8; 32]) -> [u8; 32] {
    let mut st = X25519State::new_base(scalar, 0);
    st.step();
    let out = st.result();
    st.zeroise();
    out
}

/// X25519 shared secret with the RFC 7748 §6.1 check.
///
/// Returns `None` when the result is the all-zero value. That happens
/// exactly when the peer's `u` lies in a small-order subgroup — the
/// eight points of order 1, 2, 4 and 8, including the non-canonical
/// encodings of them — in which case the output carries none of our
/// scalar and the exchange is not contributory. Rejecting is the
/// required behaviour for a key agreement whose result is fed to a KDF.
///
/// The check is a fold over the whole output, so it does not reveal
/// which byte differed; it does reveal that the output was zero, which
/// is the answer the caller asked for.
pub fn x25519_shared_secret(scalar: &[u8; 32], peer_u: &[u8; 32]) -> Option<[u8; 32]> {
    let mut st = X25519State::new(scalar, peer_u, 0);
    st.step();
    let out = st.shared_secret();
    st.zeroise();
    out
}
