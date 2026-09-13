// ML-DSA (FIPS 204) — the module-lattice digital signature algorithm,
// all three parameter sets. Pure Rust, no_std, no heap.
//
// REQUIRED INCLUDE SET — this file is written for the flat `include!()`
// consumption pattern (see crates/fluxor-sdk/src/lib.rs `sdk_flat`) and
// references items defined in sibling SDK files by bare name. A consumer
// that `include!()`s or `#[path]`-mounts ml_dsa.rs MUST also mount:
//
//   - sha3.rs — `Keccak`, `SHAKE128_RATE`, `SHAKE256_RATE`, `SHAKE_PAD`
//
// ML-DSA is a Fiat-Shamir-with-aborts signature over the ring
// Z_q[X]/(X^256 + 1) with q = 8380417. Signing samples a masking vector,
// commits to its high bits, derives a sparse challenge from that
// commitment, and answers with z = y + c·s1 — rejecting and resampling
// whenever z or the commitment's low bits would leak the secret. The
// rejection loop is why a signature costs a variable number of
// iterations (a handful on average) and why `sign` reports failure
// rather than looping forever.
//
// WHAT THIS FILE COMMITS TO
//
// Deterministic signing. FIPS 204 §3.4 admits both a hedged variant
// (32 bytes of fresh randomness folded into ρ'') and a deterministic one
// (those 32 bytes all zero). This file implements the deterministic
// variant only, for the same reason ed25519.rs and p256.rs are
// deterministic here: PIC minting has no runtime entropy source it can
// depend on, and a signature that silently degrades when the entropy
// pool is empty is worse than one that never needed it. The cost is the
// usual one — a deterministic signature is a fault-injection target,
// which is a physical-access threat the vault's tiering answers, not the
// primitive.
//
// Keys by seed. KeyGen is a deterministic function of a 32-byte seed ξ,
// so a holder of ξ holds the key. Every entry point here can start from
// ξ, which is what lets a key custodian store 32 bytes per slot instead
// of an ML-DSA-87 private key's 4896.
//
// NO CONSTANT TABLES. PIC aarch64 modules cannot use ADRP-based literal
// pool loads (see p256.rs), so the 256-entry NTT twiddle table every
// reference implementation ships as `const [i32; 256]` would miscompile
// in .rodata. It is instead derived at runtime into the caller's
// workspace: ζ = 1753 is a primitive 512th root of unity mod q, the
// table is ζ^brv8(i), and building it costs 256 multiplications against
// a signature that costs millions. sha3.rs derives Keccak's constants
// the same way and for the same reason.
//
// NO HEAP, AND NO LARGE STACK FRAMES. A single ML-DSA-87 signing
// operation needs ~48 KB of polynomial scratch and an isolated module's
// stack is 64 KB, so the scratch is not a local: the caller owns a
// [`SignWorkspace`] / [`VerifyWorkspace`] and decides where it lives —
// a static in a kernel, a field of a module's state, a local in a host
// test. The workspaces are generic over the matrix dimensions, so a
// deployment that only ever uses ML-DSA-44 reserves ML-DSA-44's scratch
// and not ML-DSA-87's.
//
// CONSTANT TIME. Verification handles only public inputs and is
// variable-time by design, as in ed25519.rs. Signing is NOT constant
// time: FIPS 204's rejection loop is a data-dependent branch on secret
// intermediates by construction — the standard's own security argument
// is that a rejection reveals nothing beyond the iteration count, which
// is why every conforming implementation has the same shape. What is
// avoided is anything the standard does not force: no secret-dependent
// table indices and no secret-dependent memory addressing.

/// Polynomial degree.
pub const N: usize = 256;

/// The ML-DSA modulus, 2^23 - 2^13 + 1.
pub const Q: i32 = 8_380_417;

/// Dropped bits in Power2Round.
const D: u32 = 13;

/// A polynomial in Z_q[X]/(X^256 + 1). Coefficients are held CANONICALLY
/// in [0, Q) everywhere in this file; the signed "mod ±" reading of a
/// coefficient is produced on demand by [`mod_pm_q`]. Keeping one
/// representation is what makes the encode/decode and norm paths
/// checkable by inspection.
pub type Poly = [i32; N];

const ZERO_POLY: Poly = [0; N];

/// Which parameter set. FIPS 204 Table 1.
///
/// Named by the standard, not by any wire. A surface that carries a set
/// as a number — a key-vault suite id, a certificate algorithm id — maps
/// that number to this enum in the surface that owns the registry, so
/// the primitive holds no opinion about identifiers it does not define.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MlDsaSet {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

/// The parameters of one set, passed BY VALUE. A `&'static Params` would
/// put the struct in .rodata and take its address, which is the PIC
/// literal-pool problem this file avoids everywhere else; a small `Copy`
/// struct built from immediates by a `match` has no such address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Params {
    /// Rows of A / length of the t and s2 vectors.
    pub k: usize,
    /// Columns of A / length of the s1 and z vectors.
    pub l: usize,
    /// Secret coefficient bound.
    pub eta: i32,
    /// Hamming weight of the challenge.
    pub tau: usize,
    /// tau * eta.
    pub beta: i32,
    /// Mask coefficient bound.
    pub gamma1: i32,
    /// Low-order rounding range.
    pub gamma2: i32,
    /// Maximum number of hint bits.
    pub omega: usize,
    /// Challenge-hash length in bytes (lambda / 4).
    pub ctilde_len: usize,
    /// Encoded public key length.
    pub pk_len: usize,
    /// Encoded private key length.
    pub sk_len: usize,
    /// Encoded signature length.
    pub sig_len: usize,
}

impl MlDsaSet {
    /// The parameter set's constants.
    pub const fn params(self) -> Params {
        match self {
            MlDsaSet::MlDsa44 => Params {
                k: 4,
                l: 4,
                eta: 2,
                tau: 39,
                beta: 78,
                gamma1: 1 << 17,
                gamma2: (Q - 1) / 88,
                omega: 80,
                ctilde_len: 32,
                pk_len: 1312,
                sk_len: 2560,
                sig_len: 2420,
            },
            MlDsaSet::MlDsa65 => Params {
                k: 6,
                l: 5,
                eta: 4,
                tau: 49,
                beta: 196,
                gamma1: 1 << 19,
                gamma2: (Q - 1) / 32,
                omega: 55,
                ctilde_len: 48,
                pk_len: 1952,
                sk_len: 4032,
                sig_len: 3309,
            },
            MlDsaSet::MlDsa87 => Params {
                k: 8,
                l: 7,
                eta: 2,
                tau: 60,
                beta: 120,
                gamma1: 1 << 19,
                gamma2: (Q - 1) / 32,
                omega: 75,
                ctilde_len: 64,
                pk_len: 2592,
                sk_len: 4896,
                sig_len: 4627,
            },
        }
    }
}

/// Seed length: FIPS 204 KeyGen takes 32 bytes and derives everything
/// else from them.
pub const SEED_LEN: usize = 32;

/// Widest parameter set's matrix dimensions, for callers that want one
/// workspace able to serve every set.
pub const K_MAX: usize = 8;
pub const L_MAX: usize = 7;

/// Longest encoded public key (ML-DSA-87).
pub const PK_MAX: usize = 2592;
/// Longest encoded private key (ML-DSA-87).
pub const SK_MAX: usize = 4896;
/// Longest signature (ML-DSA-87).
pub const SIG_MAX: usize = 4627;

// ===========================================================================
// Modular arithmetic
// ===========================================================================

/// q^-1 mod 2^32, by Newton iteration at compile time rather than as a
/// quoted magic number. A 32-bit constant, which every target this file
/// reaches can materialise as immediates — see [`mulq`].
const QINV: u32 = {
    let q = Q as u32;
    let mut inv: u32 = 1;
    let mut i = 0;
    // Each step doubles the number of correct bits: 1, 2, 4, 8, 16, 32.
    while i < 5 {
        inv = inv.wrapping_mul(2u32.wrapping_sub(q.wrapping_mul(inv)));
        i += 1;
    }
    inv
};

/// 2^64 mod q, the factor that undoes one Montgomery reduction.
const R2: i64 = ((1u128 << 64) % (Q as u128)) as i64;

/// Montgomery reduction: `a * 2^-32 mod q`, in (-q, q), for `|a| < 2^31 q`.
///
/// Multiplies and one shift, with no division at all. That is not a
/// performance nicety: a 64-bit `%` compiles to a `__aeabi_ldivmod` call
/// on 32-bit targets, and a position-independent module cannot relocate a
/// call into the compiler runtime — the link fails outright. The obvious
/// alternative, a 64-bit Barrett constant, fails the other way: PIC
/// aarch64 cannot load a `u64` from a literal pool. A reduction whose only
/// constants are 32 bits wide is the shape that satisfies both.
#[inline(always)]
fn montgomery_reduce(a: i64) -> i32 {
    // The low 32 bits of `a * q^-1`, which is the multiple of q that
    // clears a's low half.
    let t = (a as u32).wrapping_mul(QINV) as i32;
    ((a - i64::from(t) * i64::from(Q)) >> 32) as i32
}

/// Multiply two canonical coefficients, canonically.
///
/// Two Montgomery reductions rather than one: the first leaves the product
/// scaled by 2^-32, and the second multiplies that by 2^64 and reduces
/// again, which cancels the factor exactly. The reference implementations
/// avoid the second by keeping every coefficient in the Montgomery domain
/// throughout — faster, and a second representation to keep straight in
/// every packing, sampling and norm path. Here one representation is
/// carried everywhere and the correction is paid per multiply, which is
/// what makes the encode and norm code checkable against the standard
/// line for line.
#[inline(always)]
fn mulq(a: i32, b: i32) -> i32 {
    let scaled = montgomery_reduce(i64::from(a) * i64::from(b));
    let r = montgomery_reduce(i64::from(scaled) * R2);
    if r < 0 {
        r + Q
    } else {
        r
    }
}

/// Reduce any i32 into [0, Q).
#[inline(always)]
fn modq(a: i32) -> i32 {
    let r = a % Q;
    if r < 0 {
        r + Q
    } else {
        r
    }
}

/// a + b, canonically, for canonical inputs.
#[inline(always)]
fn addq(a: i32, b: i32) -> i32 {
    let s = a + b;
    if s >= Q {
        s - Q
    } else {
        s
    }
}

/// a - b, canonically, for canonical inputs.
#[inline(always)]
fn subq(a: i32, b: i32) -> i32 {
    let s = a - b;
    if s < 0 {
        s + Q
    } else {
        s
    }
}

/// The signed representative of a canonical coefficient: the unique
/// r' in (-Q/2, Q/2] congruent to `a`.
#[inline(always)]
fn mod_pm_q(a: i32) -> i32 {
    if a > Q / 2 {
        a - Q
    } else {
        a
    }
}

/// `r mod± alpha` for even `alpha` and `r` in [0, Q): the unique r' in
/// (-alpha/2, alpha/2] congruent to r modulo alpha.
#[inline(always)]
fn mod_pm(r: i32, alpha: i32) -> i32 {
    let mut r0 = r % alpha;
    if r0 > alpha / 2 {
        r0 -= alpha;
    }
    r0
}

/// base^exp mod Q.
fn powq(base: i32, mut exp: u32) -> i32 {
    let mut acc = 1i32;
    let mut b = base;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = mulq(acc, b);
        }
        b = mulq(b, b);
        exp >>= 1;
    }
    acc
}

/// Number of bits needed to represent `v` (bitlen in FIPS 204 §2.3).
const fn bitlen(v: u32) -> usize {
    (u32::BITS - v.leading_zeros()) as usize
}

// ===========================================================================
// Number-theoretic transform
// ===========================================================================

/// The twiddle table, built at runtime: `zetas[i] = 1753^brv8(i) mod Q`,
/// where brv8 is the 8-bit bit reversal. Lives in the caller's
/// workspace; see the file header on why it is not a const array.
fn build_zetas(zetas: &mut [i32; N]) {
    // Powers of the primitive 512th root in order, then permuted by
    // bit-reversal — 256 multiplications rather than 256 exponentiations.
    let mut powers = [0i32; N];
    let mut acc = 1i32;
    for slot in powers.iter_mut() {
        *slot = acc;
        acc = mulq(acc, 1753);
    }
    for (i, slot) in zetas.iter_mut().enumerate() {
        *slot = powers[(i as u8).reverse_bits() as usize];
    }
}

/// Forward NTT, in place (FIPS 204 Algorithm 41).
fn ntt(p: &mut Poly, zetas: &[i32; N]) {
    let mut k = 0usize;
    let mut len = 128usize;
    while len >= 1 {
        let mut start = 0usize;
        while start < N {
            k += 1;
            let z = zetas[k];
            for j in start..start + len {
                let t = mulq(z, p[j + len]);
                p[j + len] = subq(p[j], t);
                p[j] = addq(p[j], t);
            }
            start += 2 * len;
        }
        len /= 2;
    }
}

/// Inverse NTT with the 256^-1 scaling, in place (Algorithm 42).
fn inv_ntt(p: &mut Poly, zetas: &[i32; N]) {
    let mut k = N;
    let mut len = 1usize;
    while len < N {
        let mut start = 0usize;
        while start < N {
            k -= 1;
            let z = Q - zetas[k];
            for j in start..start + len {
                let t = p[j];
                p[j] = addq(t, p[j + len]);
                p[j + len] = subq(t, p[j + len]);
                p[j + len] = mulq(z, p[j + len]);
            }
            start += 2 * len;
        }
        len *= 2;
    }
    // 256^-1 mod Q, computed rather than quoted.
    let f = powq(256, (Q - 2) as u32);
    for c in p.iter_mut() {
        *c = mulq(*c, f);
    }
}

/// Pointwise product in the NTT domain: `out += a * b`.
fn pointwise_acc(out: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        out[i] = addq(out[i], mulq(a[i], b[i]));
    }
}

/// Pointwise product in the NTT domain: `out = a * b`.
fn pointwise(out: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        out[i] = mulq(a[i], b[i]);
    }
}

// ===========================================================================
// Rounding (FIPS 204 §7.4)
// ===========================================================================

/// Power2Round: split `r` into r1·2^d + r0 with r0 in (-2^(d-1), 2^(d-1)].
/// Returns (r1, r0 as a canonical coefficient).
fn power2round(r: i32) -> (i32, i32) {
    let r0 = mod_pm(r, 1 << D);
    let r1 = (r - r0) >> D;
    (r1, modq(r0))
}

/// Decompose: r = r1·2γ2 + r0 with r0 in (-γ2, γ2], correcting the one
/// boundary case where the split would produce r1 = (q-1)/(2γ2).
fn decompose(r: i32, gamma2: i32) -> (i32, i32) {
    let r0 = mod_pm(r, 2 * gamma2);
    if r - r0 == Q - 1 {
        (0, r0 - 1)
    } else {
        ((r - r0) / (2 * gamma2), r0)
    }
}

/// The high half of [`decompose`].
fn high_bits(r: i32, gamma2: i32) -> i32 {
    decompose(r, gamma2).0
}

/// MakeHint: does adding `z` move `r` into a different high-bits bucket?
fn make_hint(z: i32, r: i32, gamma2: i32) -> bool {
    high_bits(r, gamma2) != high_bits(addq(r, z), gamma2)
}

/// UseHint: recover the signer's high bits from the verifier's
/// approximation plus one bit.
///
/// `gamma2` is a FIPS 204 parameter-set constant and is always positive, but
/// the compiler cannot see that through the parameter — so it emits the
/// division-by-zero and remainder-overflow panic paths. In a PIC module those
/// are undefined symbols at link time rather than a runtime abort, because
/// `core::panicking` is not in the symbol set a module links against.
///
/// The guard below is therefore not defensive programming, it is what makes
/// the function linkable: past it the compiler knows the divisor is positive,
/// so neither panic path is generated. Returning zero for an impossible
/// parameter set is the safe direction — it yields a wrong signature check,
/// which fails closed, rather than a module that will not load at all.
fn use_hint(hint: bool, r: i32, gamma2: i32) -> i32 {
    let two_gamma2 = 2 * gamma2;
    if two_gamma2 <= 0 {
        return 0;
    }
    let m = (Q - 1) / two_gamma2;
    if m <= 0 {
        return 0;
    }
    let (r1, r0) = decompose(r, gamma2);
    if !hint {
        r1
    } else if r0 > 0 {
        (r1 + 1) % m
    } else {
        (r1 - 1 + m) % m
    }
}

// ===========================================================================
// Bit packing (FIPS 204 §7.1)
// ===========================================================================

/// SimpleBitPack: 256 coefficients of `bits` bits each, little-endian
/// within the stream. Coefficients are read as canonical values and must
/// already fit in `bits`.
fn simple_bit_pack(p: &Poly, bits: usize, out: &mut [u8]) {
    let total = N * bits / 8;
    out[..total].fill(0);
    let mut acc: u64 = 0;
    let mut acc_bits = 0usize;
    let mut at = 0usize;
    for &c in p.iter() {
        acc |= (c as u64 & ((1u64 << bits) - 1)) << acc_bits;
        acc_bits += bits;
        while acc_bits >= 8 {
            out[at] = (acc & 0xff) as u8;
            at += 1;
            acc >>= 8;
            acc_bits -= 8;
        }
    }
}

/// Inverse of [`simple_bit_pack`]; the unpacked values are raw, not yet
/// reduced modulo Q.
fn simple_bit_unpack(src: &[u8], bits: usize, out: &mut Poly) {
    let mut acc: u64 = 0;
    let mut acc_bits = 0usize;
    let mut at = 0usize;
    for slot in out.iter_mut() {
        while acc_bits < bits {
            acc |= u64::from(src[at]) << acc_bits;
            at += 1;
            acc_bits += 8;
        }
        *slot = (acc & ((1u64 << bits) - 1)) as i32;
        acc >>= bits;
        acc_bits -= bits;
    }
}

/// BitPack: pack `b - w[i]` where `w[i]` is read as a signed
/// representative, so the packed value lies in [0, a + b].
fn bit_pack(p: &Poly, a: i32, b: i32, out: &mut [u8]) {
    let bits = bitlen((a + b) as u32);
    let mut shifted = ZERO_POLY;
    for i in 0..N {
        shifted[i] = b - mod_pm_q(p[i]);
    }
    simple_bit_pack(&shifted, bits, out);
}

/// Inverse of [`bit_pack`], producing canonical coefficients.
fn bit_unpack(src: &[u8], a: i32, b: i32, out: &mut Poly) {
    let bits = bitlen((a + b) as u32);
    simple_bit_unpack(src, bits, out);
    for slot in out.iter_mut() {
        *slot = modq(b - *slot);
    }
}

/// Bytes one polynomial occupies under [`bit_pack`] with these bounds.
const fn packed_len(a: i32, b: i32) -> usize {
    N * bitlen((a + b) as u32) / 8
}

// ===========================================================================
// Sampling (FIPS 204 §7.3)
// ===========================================================================

/// RejNTTPoly: a uniform polynomial in the NTT domain, expanded from
/// `rho ‖ column ‖ row`.
fn rej_ntt_poly(rho: &[u8; 32], row: u8, column: u8, out: &mut Poly) {
    let mut xof = Keccak::new(SHAKE128_RATE, SHAKE_PAD);
    xof.update(rho);
    xof.update(&[column, row]);
    // Squeezed a full sponge block at a time: the rejection rate is about
    // one in sixteen, so the number of three-byte groups needed is not
    // known in advance, and pulling them one group at a time costs more in
    // call overhead than the sampling itself.
    // The sponge rate is a multiple of three, so a block boundary never
    // splits a group and the stream is consumed without remainder — which
    // is what makes block-at-a-time reads equivalent to the standard's
    // continuous one.
    const _: () = assert!(SHAKE128_RATE.is_multiple_of(3));
    let mut block = [0u8; SHAKE128_RATE];
    let mut fill = SHAKE128_RATE;
    let mut at = 0usize;
    while at < N {
        if fill == SHAKE128_RATE {
            xof.squeeze(&mut block);
            fill = 0;
        }
        // CoeffFromThreeBytes: the top bit of the third byte is dropped,
        // and the remaining 23-bit value is kept only if it is < Q.
        let z = i32::from(block[fill])
            | (i32::from(block[fill + 1]) << 8)
            | (i32::from(block[fill + 2] & 0x7f) << 16);
        fill += 3;
        if z < Q {
            out[at] = z;
            at += 1;
        }
    }
}

/// RejBoundedPoly: a polynomial with coefficients in [-eta, eta],
/// expanded from `rho ‖ nonce`.
fn rej_bounded_poly(rho: &[u8; 64], nonce: u16, eta: i32, out: &mut Poly) {
    let mut xof = Keccak::new(SHAKE256_RATE, SHAKE_PAD);
    xof.update(rho);
    xof.update(&nonce.to_le_bytes());
    let mut block = [0u8; SHAKE256_RATE];
    let mut fill = SHAKE256_RATE;
    let mut at = 0usize;
    while at < N {
        if fill == SHAKE256_RATE {
            xof.squeeze(&mut block);
            fill = 0;
        }
        let byte = block[fill];
        fill += 1;
        for half in [byte & 0x0f, byte >> 4] {
            if at == N {
                break;
            }
            // CoeffFromHalfByte, the two admissible eta values.
            let coeff = if eta == 2 {
                if half < 15 {
                    Some(2 - i32::from(half % 5))
                } else {
                    None
                }
            } else if half < 9 {
                Some(4 - i32::from(half))
            } else {
                None
            };
            if let Some(c) = coeff {
                out[at] = modq(c);
                at += 1;
            }
        }
    }
}

/// SampleInBall: a polynomial with exactly `tau` coefficients in {-1, 1}
/// and the rest zero, expanded from the challenge hash.
fn sample_in_ball(seed: &[u8], tau: usize, out: &mut Poly) {
    *out = ZERO_POLY;
    let mut xof = Keccak::new(SHAKE256_RATE, SHAKE_PAD);
    xof.update(seed);
    let mut signs = [0u8; 8];
    xof.squeeze(&mut signs);
    let mut byte = [0u8; 1];
    for i in (N - tau)..N {
        let mut j;
        loop {
            xof.squeeze(&mut byte);
            j = byte[0] as usize;
            if j <= i {
                break;
            }
        }
        out[i] = out[j];
        let bit = i + tau - N;
        let sign = (signs[bit / 8] >> (bit % 8)) & 1;
        out[j] = if sign == 1 { Q - 1 } else { 1 };
    }
}

/// ExpandMask: the masking vector y for iteration `kappa`.
fn expand_mask(rho: &[u8; 64], kappa: u16, gamma1: i32, out: &mut [Poly]) {
    let bits = 1 + bitlen((gamma1 - 1) as u32);
    let mut buf = [0u8; N * 20 / 8];
    for (r, poly) in out.iter_mut().enumerate() {
        let nonce = kappa.wrapping_add(r as u16);
        let mut xof = Keccak::new(SHAKE256_RATE, SHAKE_PAD);
        xof.update(rho);
        xof.update(&nonce.to_le_bytes());
        let take = N * bits / 8;
        xof.squeeze(&mut buf[..take]);
        bit_unpack(&buf[..take], gamma1 - 1, gamma1, poly);
    }
}

// ===========================================================================
// Workspaces
// ===========================================================================

/// Scratch for a signing operation, generic over the matrix dimensions
/// so a deployment reserves what its parameter set needs. `K`/`L` must
/// be at least the set's `k`/`l`; [`K_MAX`]/[`L_MAX`] serve every set.
pub struct SignWorkspace<const K: usize, const L: usize> {
    zetas: [i32; N],
    /// s1 in the NTT domain.
    s1: [Poly; L],
    /// s2 in the NTT domain.
    s2: [Poly; K],
    /// t0 in the NTT domain.
    t0: [Poly; K],
    /// The masking vector, overwritten in place by z.
    y: [Poly; L],
    /// The masking vector in the NTT domain.
    yhat: [Poly; L],
    /// A·y.
    w: [Poly; K],
    /// w - c·s2.
    wcs2: [Poly; K],
    /// The challenge, then the challenge in the NTT domain.
    c: Poly,
    tmp: Poly,
    tmp2: Poly,
    hint: [[u8; N / 8]; K],
    rho: [u8; 32],
    key: [u8; 32],
    tr: [u8; 64],
    mu: [u8; 64],
    rho_pp: [u8; 64],
    ctilde: [u8; 64],
    packed: [u8; N * 20 / 8],
}

impl<const K: usize, const L: usize> Default for SignWorkspace<K, L> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const K: usize, const L: usize> SignWorkspace<K, L> {
    pub const fn new() -> Self {
        Self {
            zetas: [0; N],
            s1: [ZERO_POLY; L],
            s2: [ZERO_POLY; K],
            t0: [ZERO_POLY; K],
            y: [ZERO_POLY; L],
            yhat: [ZERO_POLY; L],
            w: [ZERO_POLY; K],
            wcs2: [ZERO_POLY; K],
            c: ZERO_POLY,
            tmp: ZERO_POLY,
            tmp2: ZERO_POLY,
            hint: [[0; N / 8]; K],
            rho: [0; 32],
            key: [0; 32],
            tr: [0; 64],
            mu: [0; 64],
            rho_pp: [0; 64],
            ctilde: [0; 64],
            packed: [0; N * 20 / 8],
        }
    }

    /// Overwrite every secret this workspace holds. Callers signing with
    /// a long-lived workspace call this when the operation completes.
    pub fn zeroize(&mut self) {
        let bytes = self as *mut Self as *mut u8;
        let len = core::mem::size_of::<Self>();
        for i in 0..len {
            // SAFETY: `bytes` covers exactly this live, exclusively
            // borrowed struct, and every field is plain data.
            unsafe { core::ptr::write_volatile(bytes.add(i), 0) };
        }
    }
}

/// Scratch for a verification, generic over the number of MATRIX COLUMNS
/// only.
///
/// `K` — the number of rows — does not appear, and that is the whole
/// shape of this type. Verification walks the matrix a row at a time and
/// consumes each row's product immediately: the row's high bits are
/// packed into the challenge hash and never looked at again. So one row
/// of scratch suffices where the signer needs all of them, and an
/// ML-DSA-87 verification fits in about 13 KB rather than 28.
///
/// That is what lets verification happen where it has to happen: a
/// position-independent module has no `.bss` at all — its state arrives
/// as a pointer from the kernel — so a workspace that only fits in a
/// static is a workspace a module cannot have. This one fits on the
/// stack, with room to spare in the 64 KB an isolated module gets.
///
/// Verification touches no secret, so this type has no `zeroize`.
pub struct VerifyWorkspace<const L: usize> {
    zetas: [i32; N],
    /// z, transformed in place into the NTT domain. Every column is
    /// needed at once — this is the vector the matrix multiplies.
    z: [Poly; L],
    /// One row of A·z - c·t1·2^d.
    w: Poly,
    /// One row of t1.
    t1: Poly,
    /// The challenge, then the challenge in the NTT domain.
    c: Poly,
    tmp: Poly,
    /// The hint bits, one bit per coefficient per row. Fixed at the
    /// widest parameter set because 256 bytes is not worth a dimension.
    hint: [[u8; N / 8]; K_MAX],
    mu: [u8; 64],
    tr: [u8; 64],
    ctilde: [u8; 64],
    packed: [u8; N * 20 / 8],
}

impl<const L: usize> Default for VerifyWorkspace<L> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const L: usize> VerifyWorkspace<L> {
    pub const fn new() -> Self {
        Self {
            zetas: [0; N],
            z: [ZERO_POLY; L],
            w: ZERO_POLY,
            t1: ZERO_POLY,
            c: ZERO_POLY,
            tmp: ZERO_POLY,
            hint: [[0; N / 8]; K_MAX],
            mu: [0; 64],
            tr: [0; 64],
            ctilde: [0; 64],
            packed: [0; N * 20 / 8],
        }
    }
}

/// Why an ML-DSA entry point refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MlDsaError {
    /// An input or output slice was not the length the parameter set
    /// requires.
    BadLength,
    /// The workspace is dimensioned smaller than the parameter set.
    WorkspaceTooSmall,
    /// A context string longer than the 255 bytes FIPS 204 allows.
    ContextTooLong,
    /// The rejection loop did not converge. FIPS 204 bounds the expected
    /// iteration count in the single digits; this is a corrupted key or
    /// a broken hash, not bad luck.
    NoSignature,
}

/// FIPS 204 caps the context string at 255 bytes, because its length is
/// encoded in one byte of the message prefix.
pub const MAX_CONTEXT: usize = 255;

// ===========================================================================
// Key generation
// ===========================================================================

/// Absorb the FIPS 204 message prefix and the message into `xof`. The
/// prefix is `0x00 ‖ |ctx| ‖ ctx`, which is what separates a plain
/// signature from a pre-hashed one and from a signature under a
/// different context.
fn absorb_message(xof: &mut Keccak, ctx: &[u8], msg: &[u8]) {
    xof.update(&[0u8, ctx.len() as u8]);
    xof.update(ctx);
    xof.update(msg);
}

/// Expand the seed into (rho, key, s1-hat, s2-hat, t0-hat) and the
/// encoded public key. Shared by key generation and by signing from a
/// seed, which is why it writes into the signing workspace.
fn expand_seed<const K: usize, const L: usize>(
    p: Params,
    xi: &[u8; SEED_LEN],
    ws: &mut SignWorkspace<K, L>,
    pk_out: &mut [u8],
) {
    // (rho, rho', K) <- H(xi ‖ k ‖ l, 128). The dimensions are in the
    // hash input so two parameter sets never derive the same key from
    // the same seed.
    let mut expanded = [0u8; 128];
    let mut xof = Keccak::new(SHAKE256_RATE, SHAKE_PAD);
    xof.update(xi);
    xof.update(&[p.k as u8, p.l as u8]);
    xof.squeeze(&mut expanded);
    ws.rho.copy_from_slice(&expanded[..32]);
    let mut rho_prime = [0u8; 64];
    rho_prime.copy_from_slice(&expanded[32..96]);
    ws.key.copy_from_slice(&expanded[96..128]);

    // s1, s2 <- ExpandS(rho').
    for i in 0..p.l {
        rej_bounded_poly(&rho_prime, i as u16, p.eta, &mut ws.s1[i]);
    }
    for i in 0..p.k {
        rej_bounded_poly(&rho_prime, (p.l + i) as u16, p.eta, &mut ws.s2[i]);
    }

    // t = A·s1 + s2, computed row by row so the matrix is never stored.
    // ws.yhat holds s1-hat while the product is formed; ws.s1 is
    // converted in place afterwards.
    for i in 0..p.l {
        ws.yhat[i] = ws.s1[i];
        ntt(&mut ws.yhat[i], &ws.zetas);
    }
    for r in 0..p.k {
        ws.w[r] = ZERO_POLY;
        for c in 0..p.l {
            rej_ntt_poly(&ws.rho, r as u8, c as u8, &mut ws.tmp);
            pointwise_acc(&mut ws.w[r], &ws.tmp, &ws.yhat[c]);
        }
        inv_ntt(&mut ws.w[r], &ws.zetas);
        for j in 0..N {
            ws.w[r][j] = addq(ws.w[r][j], ws.s2[r][j]);
        }
    }

    // (t1, t0) <- Power2Round(t). t1 goes into the public key; t0 stays
    // private and is kept in the NTT domain for signing.
    pk_out[..32].copy_from_slice(&ws.rho);
    for r in 0..p.k {
        for j in 0..N {
            let (t1, t0) = power2round(ws.w[r][j]);
            ws.tmp[j] = t1;
            ws.t0[r][j] = t0;
        }
        let at = 32 + r * (N * 10 / 8);
        simple_bit_pack(&ws.tmp, 10, &mut pk_out[at..at + N * 10 / 8]);
        ntt(&mut ws.t0[r], &ws.zetas);
    }

    // tr = H(pk, 64), the public key's binding into every message hash.
    let mut xof = Keccak::new(SHAKE256_RATE, SHAKE_PAD);
    xof.update(&pk_out[..p.pk_len]);
    xof.squeeze(&mut ws.tr);

    // s1, s2 into the NTT domain for signing.
    for i in 0..p.l {
        ws.s1[i] = ws.yhat[i];
    }
    for i in 0..p.k {
        ntt(&mut ws.s2[i], &ws.zetas);
    }
}

/// Generate a key pair from a 32-byte seed, writing the FIPS 204
/// encodings of both halves.
///
/// The seed IS the private key: a custodian that keeps 32 bytes can
/// reproduce `sk_out` exactly. `sk_out` exists for interoperability
/// with implementations that expect the encoded form.
pub fn ml_dsa_keygen<const K: usize, const L: usize>(
    set: MlDsaSet,
    xi: &[u8; SEED_LEN],
    ws: &mut SignWorkspace<K, L>,
    pk_out: &mut [u8],
    sk_out: &mut [u8],
) -> Result<(), MlDsaError> {
    let p = set.params();
    if K < p.k || L < p.l {
        return Err(MlDsaError::WorkspaceTooSmall);
    }
    if pk_out.len() < p.pk_len || sk_out.len() < p.sk_len {
        return Err(MlDsaError::BadLength);
    }
    build_zetas(&mut ws.zetas);
    expand_seed(p, xi, ws, pk_out);

    // skEncode: rho ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0, the vectors packed with
    // their own bounds. The workspace holds them in the NTT domain, so
    // each is transformed back into `tmp` for packing.
    sk_out[..32].copy_from_slice(&ws.rho);
    sk_out[32..64].copy_from_slice(&ws.key);
    sk_out[64..128].copy_from_slice(&ws.tr);
    let eta_len = packed_len(p.eta, p.eta);
    let mut at = 128;
    for i in 0..p.l {
        ws.tmp = ws.s1[i];
        inv_ntt(&mut ws.tmp, &ws.zetas);
        bit_pack(&ws.tmp, p.eta, p.eta, &mut sk_out[at..at + eta_len]);
        at += eta_len;
    }
    for i in 0..p.k {
        ws.tmp = ws.s2[i];
        inv_ntt(&mut ws.tmp, &ws.zetas);
        bit_pack(&ws.tmp, p.eta, p.eta, &mut sk_out[at..at + eta_len]);
        at += eta_len;
    }
    let t0_len = packed_len((1 << (D - 1)) - 1, 1 << (D - 1));
    for i in 0..p.k {
        ws.tmp = ws.t0[i];
        inv_ntt(&mut ws.tmp, &ws.zetas);
        bit_pack(
            &ws.tmp,
            (1 << (D - 1)) - 1,
            1 << (D - 1),
            &mut sk_out[at..at + t0_len],
        );
        at += t0_len;
    }
    Ok(())
}

/// The public key for a seed, without producing the private encoding.
pub fn ml_dsa_public_key<const K: usize, const L: usize>(
    set: MlDsaSet,
    xi: &[u8; SEED_LEN],
    ws: &mut SignWorkspace<K, L>,
    pk_out: &mut [u8],
) -> Result<(), MlDsaError> {
    let p = set.params();
    if K < p.k || L < p.l {
        return Err(MlDsaError::WorkspaceTooSmall);
    }
    if pk_out.len() < p.pk_len {
        return Err(MlDsaError::BadLength);
    }
    build_zetas(&mut ws.zetas);
    expand_seed(p, xi, ws, pk_out);
    Ok(())
}

/// Load an encoded private key into the workspace, in the same shape
/// [`expand_seed`] leaves it.
fn load_sk<const K: usize, const L: usize>(p: Params, sk: &[u8], ws: &mut SignWorkspace<K, L>) {
    ws.rho.copy_from_slice(&sk[..32]);
    ws.key.copy_from_slice(&sk[32..64]);
    ws.tr.copy_from_slice(&sk[64..128]);
    let eta_len = packed_len(p.eta, p.eta);
    let mut at = 128;
    for i in 0..p.l {
        bit_unpack(&sk[at..at + eta_len], p.eta, p.eta, &mut ws.s1[i]);
        ntt(&mut ws.s1[i], &ws.zetas);
        at += eta_len;
    }
    for i in 0..p.k {
        bit_unpack(&sk[at..at + eta_len], p.eta, p.eta, &mut ws.s2[i]);
        ntt(&mut ws.s2[i], &ws.zetas);
        at += eta_len;
    }
    let t0_len = packed_len((1 << (D - 1)) - 1, 1 << (D - 1));
    for i in 0..p.k {
        bit_unpack(
            &sk[at..at + t0_len],
            (1 << (D - 1)) - 1,
            1 << (D - 1),
            &mut ws.t0[i],
        );
        ntt(&mut ws.t0[i], &ws.zetas);
        at += t0_len;
    }
}

// ===========================================================================
// Signing
// ===========================================================================

/// The rejection loop, run once the workspace holds rho, key, tr and the
/// secret vectors in the NTT domain.
fn sign_expanded<const K: usize, const L: usize>(
    p: Params,
    ws: &mut SignWorkspace<K, L>,
    ctx: &[u8],
    msg: &[u8],
    sig_out: &mut [u8],
) -> Result<(), MlDsaError> {
    // mu = H(tr ‖ 0x00 ‖ |ctx| ‖ ctx ‖ M, 64).
    let mut xof = Keccak::new(SHAKE256_RATE, SHAKE_PAD);
    xof.update(&ws.tr);
    absorb_message(&mut xof, ctx, msg);
    xof.squeeze(&mut ws.mu);

    // rho'' = H(K ‖ rnd ‖ mu, 64) with rnd all zero — the deterministic
    // variant of FIPS 204 §3.4.
    let mut xof = Keccak::new(SHAKE256_RATE, SHAKE_PAD);
    xof.update(&ws.key);
    xof.update(&[0u8; 32]);
    xof.update(&ws.mu);
    xof.squeeze(&mut ws.rho_pp);

    let w1_bits = bitlen(((Q - 1) / (2 * p.gamma2) - 1) as u32);
    let w1_len = N * w1_bits / 8;
    let z_len = packed_len(p.gamma1 - 1, p.gamma1);

    // FIPS 204 bounds the expected number of iterations in the single
    // digits; a cap two orders of magnitude above that separates "bad
    // luck" from "this key or hash is broken" without ever rejecting a
    // signature that would have succeeded.
    const MAX_ITERATIONS: u16 = 1000;
    let mut kappa: u16 = 0;

    for _ in 0..MAX_ITERATIONS {
        expand_mask(&ws.rho_pp, kappa, p.gamma1, &mut ws.y[..p.l]);
        kappa = kappa.wrapping_add(p.l as u16);

        for i in 0..p.l {
            ws.yhat[i] = ws.y[i];
            ntt(&mut ws.yhat[i], &ws.zetas);
        }

        // w = A·y, and c~ = H(mu ‖ w1Encode(HighBits(w))).
        let mut xof = Keccak::new(SHAKE256_RATE, SHAKE_PAD);
        xof.update(&ws.mu);
        for r in 0..p.k {
            ws.w[r] = ZERO_POLY;
            for c in 0..p.l {
                rej_ntt_poly(&ws.rho, r as u8, c as u8, &mut ws.tmp);
                pointwise_acc(&mut ws.w[r], &ws.tmp, &ws.yhat[c]);
            }
            inv_ntt(&mut ws.w[r], &ws.zetas);
            for j in 0..N {
                ws.tmp[j] = high_bits(ws.w[r][j], p.gamma2);
            }
            simple_bit_pack(&ws.tmp, w1_bits, &mut ws.packed[..w1_len]);
            xof.update(&ws.packed[..w1_len]);
        }
        xof.squeeze(&mut ws.ctilde[..p.ctilde_len]);

        // c = SampleInBall(c~), then c-hat for the three products.
        let mut ctilde = [0u8; 64];
        ctilde[..p.ctilde_len].copy_from_slice(&ws.ctilde[..p.ctilde_len]);
        sample_in_ball(&ctilde[..p.ctilde_len], p.tau, &mut ws.c);
        ntt(&mut ws.c, &ws.zetas);

        // z = y + c·s1.
        let mut z_ok = true;
        for i in 0..p.l {
            pointwise(&mut ws.tmp, &ws.c, &ws.s1[i]);
            inv_ntt(&mut ws.tmp, &ws.zetas);
            for j in 0..N {
                ws.y[i][j] = addq(ws.y[i][j], ws.tmp[j]);
            }
            if inf_norm(&ws.y[i]) >= p.gamma1 - p.beta {
                z_ok = false;
            }
        }
        if !z_ok {
            continue;
        }

        // r0 = LowBits(w - c·s2).
        let mut r0_ok = true;
        for r in 0..p.k {
            pointwise(&mut ws.tmp, &ws.c, &ws.s2[r]);
            inv_ntt(&mut ws.tmp, &ws.zetas);
            for j in 0..N {
                ws.wcs2[r][j] = subq(ws.w[r][j], ws.tmp[j]);
            }
            for j in 0..N {
                if decompose(ws.wcs2[r][j], p.gamma2).1.abs() >= p.gamma2 - p.beta {
                    r0_ok = false;
                }
            }
        }
        if !r0_ok {
            continue;
        }

        // h = MakeHint(-c·t0, w - c·s2 + c·t0), rejected if c·t0 is too
        // large or the hint does not fit in omega bits.
        let mut hint_ok = true;
        let mut hint_weight = 0usize;
        for r in 0..p.k {
            pointwise(&mut ws.tmp2, &ws.c, &ws.t0[r]);
            inv_ntt(&mut ws.tmp2, &ws.zetas);
            if inf_norm(&ws.tmp2) >= p.gamma2 {
                hint_ok = false;
                break;
            }
            ws.hint[r] = [0u8; N / 8];
            for j in 0..N {
                let ct0 = ws.tmp2[j];
                let rr = addq(ws.wcs2[r][j], ct0);
                if make_hint(subq(0, ct0), rr, p.gamma2) {
                    ws.hint[r][j / 8] |= 1 << (j % 8);
                    hint_weight += 1;
                }
            }
        }
        if !hint_ok || hint_weight > p.omega {
            continue;
        }

        // sigEncode: c~ ‖ z ‖ HintBitPack(h).
        sig_out[..p.ctilde_len].copy_from_slice(&ws.ctilde[..p.ctilde_len]);
        let mut at = p.ctilde_len;
        for i in 0..p.l {
            bit_pack(
                &ws.y[i],
                p.gamma1 - 1,
                p.gamma1,
                &mut sig_out[at..at + z_len],
            );
            at += z_len;
        }
        let hints = &mut sig_out[at..at + p.omega + p.k];
        hints.fill(0);
        let mut index = 0usize;
        for r in 0..p.k {
            for j in 0..N {
                if ws.hint[r][j / 8] & (1 << (j % 8)) != 0 {
                    hints[index] = j as u8;
                    index += 1;
                }
            }
            hints[p.omega + r] = index as u8;
        }
        return Ok(());
    }
    Err(MlDsaError::NoSignature)
}

/// The infinity norm of a polynomial, read through the signed
/// representative of each coefficient.
fn inf_norm(p: &Poly) -> i32 {
    let mut max = 0i32;
    for &c in p.iter() {
        let v = mod_pm_q(c).abs();
        if v > max {
            max = v;
        }
    }
    max
}

/// Sign `msg` under `ctx` with the seed the key was generated from.
///
/// This is the entry point a key custodian uses: it never materialises
/// the encoded private key, so the only secret that has to be stored,
/// sealed and handled is the 32-byte seed.
pub fn ml_dsa_sign_seed<const K: usize, const L: usize>(
    set: MlDsaSet,
    xi: &[u8; SEED_LEN],
    ctx: &[u8],
    msg: &[u8],
    ws: &mut SignWorkspace<K, L>,
    sig_out: &mut [u8],
) -> Result<usize, MlDsaError> {
    let p = set.params();
    if K < p.k || L < p.l {
        return Err(MlDsaError::WorkspaceTooSmall);
    }
    if ctx.len() > MAX_CONTEXT {
        return Err(MlDsaError::ContextTooLong);
    }
    if sig_out.len() < p.sig_len {
        return Err(MlDsaError::BadLength);
    }
    build_zetas(&mut ws.zetas);
    let mut pk = [0u8; PK_MAX];
    expand_seed(p, xi, ws, &mut pk);
    sign_expanded(p, ws, ctx, msg, sig_out)?;
    Ok(p.sig_len)
}

/// Sign `msg` under `ctx` with an encoded FIPS 204 private key.
pub fn ml_dsa_sign<const K: usize, const L: usize>(
    set: MlDsaSet,
    sk: &[u8],
    ctx: &[u8],
    msg: &[u8],
    ws: &mut SignWorkspace<K, L>,
    sig_out: &mut [u8],
) -> Result<usize, MlDsaError> {
    let p = set.params();
    if K < p.k || L < p.l {
        return Err(MlDsaError::WorkspaceTooSmall);
    }
    if ctx.len() > MAX_CONTEXT {
        return Err(MlDsaError::ContextTooLong);
    }
    if sk.len() < p.sk_len || sig_out.len() < p.sig_len {
        return Err(MlDsaError::BadLength);
    }
    build_zetas(&mut ws.zetas);
    load_sk(p, sk, ws);
    sign_expanded(p, ws, ctx, msg, sig_out)?;
    Ok(p.sig_len)
}

// ===========================================================================
// Verification
// ===========================================================================

/// Verify `sig` over `msg` under `ctx` against an encoded public key.
///
/// Returns `false` for every failure, including a malformed signature: a
/// verifier that distinguished "wrong" from "malformed" would hand an
/// attacker a decoder oracle, and neither answer admits the signature.
pub fn ml_dsa_verify<const L: usize>(
    set: MlDsaSet,
    pk: &[u8],
    ctx: &[u8],
    msg: &[u8],
    sig: &[u8],
    ws: &mut VerifyWorkspace<L>,
) -> bool {
    let p = set.params();
    if L < p.l {
        return false;
    }
    if pk.len() != p.pk_len || sig.len() != p.sig_len || ctx.len() > MAX_CONTEXT {
        return false;
    }
    build_zetas(&mut ws.zetas);

    // pkDecode. t1 is unpacked a row at a time inside the product loop
    // below, so only rho is read here.
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pk[..32]);

    // sigDecode: c~, z, and the hint. A hint that does not decode is a
    // refusal, not a zero hint.
    ws.ctilde[..p.ctilde_len].copy_from_slice(&sig[..p.ctilde_len]);
    let z_len = packed_len(p.gamma1 - 1, p.gamma1);
    let mut at = p.ctilde_len;
    for i in 0..p.l {
        bit_unpack(&sig[at..at + z_len], p.gamma1 - 1, p.gamma1, &mut ws.z[i]);
        at += z_len;
    }
    if !hint_bit_unpack(p, &sig[at..at + p.omega + p.k], &mut ws.hint[..p.k]) {
        return false;
    }

    // ||z||inf < gamma1 - beta, checked before z is transformed.
    for i in 0..p.l {
        if inf_norm(&ws.z[i]) >= p.gamma1 - p.beta {
            return false;
        }
    }

    // mu = H(H(pk, 64) ‖ 0x00 ‖ |ctx| ‖ ctx ‖ M, 64).
    let mut xof = Keccak::new(SHAKE256_RATE, SHAKE_PAD);
    xof.update(pk);
    xof.squeeze(&mut ws.tr);
    let mut xof = Keccak::new(SHAKE256_RATE, SHAKE_PAD);
    xof.update(&ws.tr);
    absorb_message(&mut xof, ctx, msg);
    xof.squeeze(&mut ws.mu);

    // c = SampleInBall(c~), c-hat.
    let mut ctilde = [0u8; 64];
    ctilde[..p.ctilde_len].copy_from_slice(&ws.ctilde[..p.ctilde_len]);
    sample_in_ball(&ctilde[..p.ctilde_len], p.tau, &mut ws.c);
    ntt(&mut ws.c, &ws.zetas);

    // z-hat. Every column is needed at once, so this is the one vector
    // that is transformed up front.
    for i in 0..p.l {
        ntt(&mut ws.z[i], &ws.zetas);
    }

    // w'approx = A·z - c·t1·2^d, then w1' = UseHint(h, w'approx).
    //
    // One row at a time: the row of A is expanded, multiplied, subtracted,
    // hinted, packed and absorbed, and then nothing refers to it again.
    // That is what keeps this loop's working set at a single polynomial
    // rather than the whole k-vector.
    let w1_bits = bitlen(((Q - 1) / (2 * p.gamma2) - 1) as u32);
    let w1_len = N * w1_bits / 8;
    let mut xof = Keccak::new(SHAKE256_RATE, SHAKE_PAD);
    xof.update(&ws.mu);
    for r in 0..p.k {
        ws.w = ZERO_POLY;
        for c in 0..p.l {
            rej_ntt_poly(&rho, r as u8, c as u8, &mut ws.tmp);
            pointwise_acc(&mut ws.w, &ws.tmp, &ws.z[c]);
        }
        let at = 32 + r * (N * 10 / 8);
        simple_bit_unpack(&pk[at..at + N * 10 / 8], 10, &mut ws.t1);
        for j in 0..N {
            ws.t1[j] = mulq(ws.t1[j], 1 << D);
        }
        ntt(&mut ws.t1, &ws.zetas);
        pointwise(&mut ws.tmp, &ws.c, &ws.t1);
        for j in 0..N {
            ws.w[j] = subq(ws.w[j], ws.tmp[j]);
        }
        inv_ntt(&mut ws.w, &ws.zetas);
        for j in 0..N {
            let bit = ws.hint[r][j / 8] & (1 << (j % 8)) != 0;
            ws.tmp[j] = use_hint(bit, ws.w[j], p.gamma2);
        }
        simple_bit_pack(&ws.tmp, w1_bits, &mut ws.packed[..w1_len]);
        xof.update(&ws.packed[..w1_len]);
    }
    let mut recomputed = [0u8; 64];
    xof.squeeze(&mut recomputed[..p.ctilde_len]);

    // Equality over the challenge hash, without an early exit.
    let mut diff = 0u8;
    for (a, b) in recomputed[..p.ctilde_len]
        .iter()
        .zip(ws.ctilde[..p.ctilde_len].iter())
    {
        diff |= a ^ b;
    }
    diff == 0
}

/// HintBitUnpack (FIPS 204 Algorithm 21). Returns false for any encoding
/// the standard rejects: indices out of order, a running count that goes
/// backwards or past omega, or a non-zero byte in the unused tail.
fn hint_bit_unpack(p: Params, src: &[u8], hint: &mut [[u8; N / 8]]) -> bool {
    for h in hint.iter_mut() {
        *h = [0u8; N / 8];
    }
    let mut index = 0usize;
    for (r, row) in hint.iter_mut().enumerate().take(p.k) {
        let end = src[p.omega + r] as usize;
        if end < index || end > p.omega {
            return false;
        }
        let first = index;
        while index < end {
            if index > first && src[index - 1] >= src[index] {
                return false;
            }
            let bit = src[index] as usize;
            row[bit / 8] |= 1 << (bit % 8);
            index += 1;
        }
    }
    // The unused tail must be zero: a non-zero byte there is a second
    // encoding of the same hint, and two encodings of one signature is two
    // signatures for one message.
    if src[index..p.omega].iter().any(|&b| b != 0) {
        return false;
    }
    true
}
