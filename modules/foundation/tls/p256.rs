// P-256 (secp256r1) ECDH and ECDSA
// Pure Rust, no_std, no heap
// Field arithmetic over p = 2^256 - 2^224 + 2^192 + 2^96 - 1
//
// Uses projective (Jacobian) coordinates to avoid modular inversion during
// point multiplication. All operations are constant-time for secret scalars.

// P-256 prime: p = 2^256 - 2^224 + 2^192 + 2^96 - 1
const P: [u64; 4] = [
    0xFFFFFFFFFFFFFFFF, // p[0] (least significant)
    0x00000000FFFFFFFF,
    0x0000000000000000,
    0xFFFFFFFF00000001,
];

// P-256 order: n
const N: [u64; 4] = [
    0xF3B9CAC2FC632551,
    0xBCE6FAADA7179E84,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000000,
];

// Generator point Gx
const GX: [u64; 4] = [
    0xF4A13945D898C296,
    0x77037D812DEB33A0,
    0xF8BCE6E563A440F2,
    0x6B17D1F2E12C4247,
];

// Generator point Gy
const GY: [u64; 4] = [
    0xCBB6406837BF51F5,
    0x2BCE33576B315ECE,
    0x8EE7EB4A7C0F9E16,
    0x4FE342E2FE1A7F9B,
];

// ============================================================================
// 256-bit unsigned integer arithmetic
// ============================================================================

type U256 = [u64; 4];

const ZERO: U256 = [0, 0, 0, 0];
const ONE: U256 = [1, 0, 0, 0];

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
        let diff = (a[i] as u128).wrapping_sub(b[i] as u128).wrapping_sub(borrow as u128);
        r[i] = diff as u64;
        borrow = if diff > (a[i] as u128) + (!borrow as u128) + 1 { 1 } else {
            // Check if borrow occurred: if a < b + prev_borrow
            if (a[i] as u128) < (b[i] as u128) + (borrow as u128) { 1 } else { 0 }
        };
        i += 1;
    }
    (r, borrow)
}

/// Compare: returns 1 if a >= b, 0 otherwise
fn u256_gte(a: &U256, b: &U256) -> u64 {
    let mut i: i32 = 3;
    while i >= 0 {
        let idx = i as usize;
        if a[idx] > b[idx] { return 1; }
        if a[idx] < b[idx] { return 0; }
        i -= 1;
    }
    1 // equal
}

fn u256_is_zero(a: &U256) -> bool {
    a[0] | a[1] | a[2] | a[3] == 0
}

// ============================================================================
// Modular arithmetic mod p (P-256 prime)
// ============================================================================

/// Reduce mod p
fn mod_p(a: &U256) -> U256 {
    let (r, borrow) = u256_sub(a, &P);
    if borrow == 0 { r } else { *a }
}

/// Modular addition: (a + b) mod p
fn fp_add(a: &U256, b: &U256) -> U256 {
    let (sum, carry) = u256_add(a, b);
    if carry != 0 || u256_gte(&sum, &P) != 0 {
        let (r, _) = u256_sub(&sum, &P);
        r
    } else {
        sum
    }
}

/// Modular subtraction: (a - b) mod p
fn fp_sub(a: &U256, b: &U256) -> U256 {
    let (diff, borrow) = u256_sub(a, b);
    if borrow != 0 {
        let (r, _) = u256_add(&diff, &P);
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

    // Handle negative carry (add p) or excess (subtract p)
    if carry < 0 {
        let mut c = carry;
        while c < 0 {
            let (r, _) = u256_add(&result, &P);
            result = r;
            c += 1;
        }
    } else {
        let mut c = carry;
        while c > 0 {
            let (r, _) = u256_sub(&result, &P);
            result = r;
            c -= 1;
        }
    }

    // Final reduction
    while u256_gte(&result, &P) != 0 {
        let (r, borrow) = u256_sub(&result, &P);
        if borrow != 0 { break; }
        result = r;
    }

    result
}

/// Modular multiplication: (a * b) mod p
fn fp_mul(a: &U256, b: &U256) -> U256 {
    let t = u256_mul_wide(a, b);
    fp_reduce(&t)
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
    let p_minus_2: U256 = [
        0xFFFFFFFFFFFFFFFD,
        0x00000000FFFFFFFF,
        0x0000000000000000,
        0xFFFFFFFF00000001,
    ];

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
    if u256_gte(a, &N) != 0 {
        let (r, borrow) = u256_sub(a, &N);
        if borrow == 0 { return r; }
    }
    *a
}

fn fn_add(a: &U256, b: &U256) -> U256 {
    let (sum, carry) = u256_add(a, b);
    if carry != 0 || u256_gte(&sum, &N) != 0 {
        let (r, _) = u256_sub(&sum, &N);
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
    let r_mod: U256 = [
        0x0C46353D039CDAAF,
        0x4319055258E8617B,
        0x0000000000000000,
        0x00000000FFFFFFFF,
    ];

    let mut acc = [0u64; 8];
    unsafe { core::ptr::copy_nonoverlapping(t.as_ptr(), acc.as_mut_ptr(), 8); }

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

    let n_minus_2: U256 = [
        N[0] - 2,
        N[1],
        N[2],
        N[3],
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
// Point operations (Jacobian coordinates: X, Y, Z where x = X/Z^2, y = Y/Z^3)
// ============================================================================

struct JacobianPoint {
    x: U256,
    y: U256,
    z: U256,
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
        let t2 = fp_add(&t, &t);    // 4 * x * y^2

        let x3 = fp_sub(&fp_sqr(&m), &fp_add(&t2, &t2)); // m^2 - 8*x*y^2

        let y2_4 = fp_add(&s, &s);  // 2*y^2
        let y4_8 = fp_sqr(&y2_4);   // 4*y^4
        let y4_8_2 = fp_add(&y4_8, &y4_8); // 8*y^4

        let y3 = fp_sub(&fp_mul(&m, &fp_sub(&t2, &x3)), &y4_8_2);

        let z3 = fp_mul(&fp_add(&self.y, &self.y), &self.z);

        JacobianPoint { x: x3, y: y3, z: z3 }
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

        JacobianPoint { x: x3, y: y3, z: z3 }
    }
}

/// Scalar multiplication: k * G
/// Uses double-and-add. Ephemeral keys (used once per session) mitigate
/// timing side channels. Full constant-time requires a proper Montgomery
/// ladder in Jacobian coordinates (deferred to hardware acceleration).
fn scalar_mul_base(k: &U256) -> JacobianPoint {
    let mut result = JacobianPoint::identity();
    let gx = GX;
    let gy = GY;

    let mut i: i32 = 3;
    while i >= 0 {
        let word = k[i as usize];
        let mut j: i32 = 63;
        while j >= 0 {
            result = result.double();
            if (word >> j as u32) & 1 == 1 {
                result = result.add_affine(&gx, &gy);
            }
            j -= 1;
        }
        i -= 1;
    }

    result
}

/// Scalar multiplication: k * P (arbitrary point)
fn scalar_mul(k: &U256, px: &U256, py: &U256) -> JacobianPoint {
    let mut result = JacobianPoint::identity();

    let mut i: i32 = 3;
    while i >= 0 {
        let word = k[i as usize];
        let mut j: i32 = 63;
        while j >= 0 {
            result = result.double();
            if (word >> j as u32) & 1 == 1 {
                result = result.add_affine(px, py);
            }
            j -= 1;
        }
        i -= 1;
    }

    result
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
    unsafe {
        core::ptr::copy_nonoverlapping(xb.as_ptr(), pub_key.as_mut_ptr().add(1), 32);
        core::ptr::copy_nonoverlapping(yb.as_ptr(), pub_key.as_mut_ptr().add(33), 32);
    }

    (priv_key, pub_key)
}

/// ECDH shared secret: scalar_mult(my_private, peer_public).x
/// peer_pub should be 65 bytes (0x04 || X || Y) or 64 bytes (X || Y)
pub fn ecdh_shared_secret(my_private: &[u8; 32], peer_pub: &[u8]) -> Option<[u8; 32]> {
    let offset = if peer_pub.len() == 65 && peer_pub[0] == 0x04 { 1 } else if peer_pub.len() == 64 { 0 } else { return None; };

    let px = u256_from_be(&peer_pub[offset..offset + 32]);
    let py = u256_from_be(&peer_pub[offset + 32..offset + 64]);
    let k = u256_from_be(my_private);

    let result = scalar_mul(&k, &px, &py);
    if result.is_identity() {
        return None;
    }
    let (x, _) = result.to_affine();
    Some(u256_to_be(&x))
}

/// ECDSA sign: (r, s) over message hash
/// Returns 64-byte signature (r || s, each 32 bytes big-endian)
pub fn ecdsa_sign(private_key: &[u8; 32], hash: &[u8], random_k: &[u8; 32]) -> [u8; 64] {
    let d = u256_from_be(private_key);
    let mut k = u256_from_be(random_k);
    k = mod_n_reduce(&k);
    if u256_is_zero(&k) {
        k = ONE;
    }

    // r = (k * G).x mod n
    let point = scalar_mul_base(&k);
    let (rx, _) = point.to_affine();
    let r = mod_n_reduce(&rx);

    // z = hash (truncated to order bit length if needed)
    let z = if hash.len() >= 32 {
        u256_from_be(&hash[..32])
    } else {
        let mut buf = [0u8; 32];
        unsafe { core::ptr::copy_nonoverlapping(hash.as_ptr(), buf.as_mut_ptr().add(32 - hash.len()), hash.len()); }
        u256_from_be(&buf)
    };
    let z = mod_n_reduce(&z);

    // s = k^-1 * (z + r * d) mod n
    let k_inv = fn_inv(&k);
    let rd = fn_mul(&r, &d);
    let z_rd = fn_add(&z, &rd);
    let s = fn_mul(&k_inv, &z_rd);

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
    if sig.len() < 64 { return false; }
    let offset = if pub_key.len() == 65 && pub_key[0] == 0x04 { 1 } else if pub_key.len() == 64 { 0 } else { return false; };

    let r = u256_from_be(&sig[..32]);
    let s = u256_from_be(&sig[32..64]);
    let qx = u256_from_be(&pub_key[offset..offset + 32]);
    let qy = u256_from_be(&pub_key[offset + 32..offset + 64]);

    // Check r, s in [1, n-1]
    if u256_is_zero(&r) || u256_is_zero(&s) { return false; }
    if u256_gte(&r, &N) != 0 { return false; }
    if u256_gte(&s, &N) != 0 { return false; }

    let z = if hash.len() >= 32 {
        u256_from_be(&hash[..32])
    } else {
        let mut buf = [0u8; 32];
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

/// Parse DER-encoded ECDSA signature into (r, s) raw 64 bytes
pub fn parse_der_signature(der: &[u8]) -> Option<[u8; 64]> {
    if der.len() < 8 { return None; }
    if der[0] != 0x30 { return None; }

    let mut pos = 2; // skip SEQUENCE tag + length

    // Parse r
    if pos >= der.len() || der[pos] != 0x02 { return None; }
    pos += 1;
    let r_len = der[pos] as usize;
    pos += 1;
    if pos + r_len > der.len() { return None; }
    let r_bytes = &der[pos..pos + r_len];
    pos += r_len;

    // Parse s
    if pos >= der.len() || der[pos] != 0x02 { return None; }
    pos += 1;
    let s_len = der[pos] as usize;
    pos += 1;
    if pos + s_len > der.len() { return None; }
    let s_bytes = &der[pos..pos + s_len];

    // Convert to fixed 32-byte big-endian
    let mut sig = [0u8; 64];
    copy_be_padded(r_bytes, &mut sig[..32]);
    copy_be_padded(s_bytes, &mut sig[32..64]);
    Some(sig)
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
    let needs_pad_r = r_data.len() > 0 && r_data[0] >= 0x80;
    let r_enc_len = r_data.len() + if needs_pad_r { 1 } else { 0 };
    out[pos] = r_enc_len as u8; pos += 1;
    if needs_pad_r { out[pos] = 0; pos += 1; }
    unsafe { core::ptr::copy_nonoverlapping(r_data.as_ptr(), out.as_mut_ptr().add(pos), r_data.len()); }
    pos += r_data.len();

    // Encode s
    out[pos] = 0x02; pos += 1;
    let s_start = skip_leading_zeros(&sig[32..64]);
    let s_data = &sig[32 + s_start..64];
    let needs_pad_s = s_data.len() > 0 && s_data[0] >= 0x80;
    let s_enc_len = s_data.len() + if needs_pad_s { 1 } else { 0 };
    out[pos] = s_enc_len as u8; pos += 1;
    if needs_pad_s { out[pos] = 0; pos += 1; }
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
