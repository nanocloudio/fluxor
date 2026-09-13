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

/// Load p - 2 = 2^255 - 21 as exponent limbs for Fermat inversion.
#[inline(never)]
fn ed_load_p_minus_2() -> U256 {
    pic_u256(
        0xFFFFFFEB, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
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

    let t0 = a0 * b0 + 19 * (a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1);
    let mut t1 = a0 * b1 + a1 * b0 + 19 * (a2 * b4 + a3 * b3 + a4 * b2);
    let mut t2 = a0 * b2 + a1 * b1 + a2 * b0 + 19 * (a3 * b4 + a4 * b3);
    let mut t3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + 19 * (a4 * b4);
    let mut t4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

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

fn fe_sq(a: &Fe) -> Fe {
    fe_mul(a, a)
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
    let e = ed_load_p_minus_2();
    fe_pow(a, &e)
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

/// The Montgomery ladder of RFC 7748 §5 over the radix-51 field.
///
/// `k` is consumed already clamped. `u` is the affine u-coordinate; per
/// §5 its bit 255 is ignored on decode, which `fe_frombytes` already
/// does. Returns the u-coordinate of `[k]·U`.
///
/// Constant-time in `k` and `u`: 255 fixed iterations, masked swaps, no
/// data-dependent branch or load address.
fn x25519_ladder(k: &[u8; 32], u: &Fe) -> Fe {
    // a24 = (A - 2)/4 = 121665 for A = 486662. Small enough to be
    // materialised as immediates; no .rodata pointer is taken.
    let a24: Fe = [121665, 0, 0, 0, 0];

    let x1 = *u;
    let mut x2 = FE_ONE;
    let mut z2 = FE_ZERO;
    let mut x3 = *u;
    let mut z3 = FE_ONE;
    let mut swap: u64 = 0;

    let mut t: i32 = 254;
    while t >= 0 {
        let bit = ((k[(t as usize) >> 3] >> ((t as usize) & 7)) & 1) as u64;
        // mask is all-ones exactly when the accumulated swap state
        // differs from the previous iteration's.
        let mask = (swap ^ bit).wrapping_neg();
        let nx2 = fe_select(&x2, &x3, mask);
        let nx3 = fe_select(&x3, &x2, mask);
        let nz2 = fe_select(&z2, &z3, mask);
        let nz3 = fe_select(&z3, &z2, mask);
        x2 = nx2;
        x3 = nx3;
        z2 = nz2;
        z3 = nz3;
        swap = bit;

        let a = fe_add(&x2, &z2);
        let aa = fe_sq(&a);
        let b = fe_sub(&x2, &z2);
        let bb = fe_sq(&b);
        let e = fe_sub(&aa, &bb);
        let c = fe_add(&x3, &z3);
        let d = fe_sub(&x3, &z3);
        let da = fe_mul(&d, &a);
        let cb = fe_mul(&c, &b);
        x3 = fe_sq(&fe_add(&da, &cb));
        z3 = fe_mul(&x1, &fe_sq(&fe_sub(&da, &cb)));
        x2 = fe_mul(&aa, &bb);
        z2 = fe_mul(&e, &fe_add(&aa, &fe_mul(&a24, &e)));

        t -= 1;
    }

    // Final conditional swap for the last processed bit.
    let mask = swap.wrapping_neg();
    let fx2 = fe_select(&x2, &x3, mask);
    let fz2 = fe_select(&z2, &z3, mask);

    fe_mul(&fx2, &fe_invert(&fz2))
}

/// RFC 7748 §5 `X25519(k, u)` over wire encodings, with no output
/// check. This is the raw primitive: it clamps `k`, ignores bit 255 of
/// `u`, and returns the encoded u-coordinate whatever it is, so it
/// matches the §5.2 vectors (which include non-canonical `u`) and the
/// iterated test. Key agreement must use `x25519_shared_secret`, which
/// adds the check RFC 7748 §6.1 requires.
pub fn x25519(scalar: &[u8; 32], u_in: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    x25519_clamp(&mut k);
    let u = fe_frombytes(u_in);
    let r = x25519_ladder(&k, &u);
    zeroize(&mut k);
    fe_tobytes(&r)
}

/// X25519 public key: `X25519(scalar, 9)`, RFC 7748 §6.1.
pub fn x25519_public_key(scalar: &[u8; 32]) -> [u8; 32] {
    let mut base = [0u8; 32];
    base[0] = 9;
    x25519(scalar, &base)
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
    let mut out = x25519(scalar, peer_u);
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
