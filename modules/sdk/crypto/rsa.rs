// RSA — RSASSA-PKCS1-v1_5 and RSASSA-PSS over moduli of 2048 to 4096 bits.
// Pure Rust, no_std, no heap, include!-able like the other `sdk/crypto`
// sources: every identifier is `rsa_`/`Rsa`/`RSA_`-prefixed so the file can
// share a scope with `p256.rs`, `x509.rs` and the hashes. It expects
// `sha256(&[u8]) -> [u8; 32]` and `sha384(&[u8]) -> [u8; 48]` in scope.
//
// # Shape
//
// Every long-running operation here is a job stepped by its caller. A
// modular multiplication is done a ROW at a time (one limb of the
// multiplier through the CIOS Montgomery product), and the modulus
// preparation, the exponentiations and the CRT recombination are all
// expressed in those units, so a caller with a step budget hands the job
// as many units as fit and comes back next step. Nothing here decides how
// much work a step may do; that is the caller's tick, not this file's.
//
// # Limbs
//
// The limb is the machine's natural word: `u64` where the pointer is 64
// bits, `u32` elsewhere. A 64-bit multiplier does a 2048-bit product in a
// quarter of the row work, and leaving it idle on aarch64 would put the
// private operation's cost in the wrong decade. Widths are fixed at the
// ceiling, `RSA_MODULUS_BITS_MAX`, with an explicit length in limbs, and
// every job owns its buffers, so a holder embeds one job and nothing here
// is static.
//
// # Timing
//
// Stated per layer, as `p256.rs` does.
//
//   1. Limb arithmetic — constant-time. The CIOS row, the masked
//      subtraction that finishes a product, the shift-and-reduce that
//      prepares R² and the doubling-based reduction all run a fixed
//      schedule over the modulus length and select with masks.
//   2. Public exponentiation — variable in the exponent's bits by design:
//      the exponent, the modulus and the signature are all public, as they
//      are in ECDSA verification.
//   3. Private exponentiation — constant-time in the exponent: fixed
//      4-bit windows, every window one table read through a masked scan of
//      all sixteen entries, four squarings and one multiplication per
//      window regardless of the digit. CRT recombination is masked
//      arithmetic. No blinding: the exponent schedule never depends on the
//      message, and the primes are used only through the fixed schedule.
//   4. Encoding checks — constant-time comparison of the whole encoded
//      message for PKCS#1 v1.5 (the decoded block is never parsed, which
//      is what keeps the 2006 e = 3 forgery out) and of the recovered hash
//      for PSS.
//
// Named exceptions:
//
//   - Key decoding branches on admissibility, which is reported.
//   - The PSS unmasking walks fixed lengths but the salt/padding boundary
//     check reports its outcome; the inputs are a public signature.
//
// Not claimed: that the emitted machine code is constant-time. These are
// source-level properties.

#[cfg(target_pointer_width = "64")]
pub type RsaLimb = u64;
#[cfg(target_pointer_width = "64")]
type RsaWide = u128;
#[cfg(not(target_pointer_width = "64"))]
pub type RsaLimb = u32;
#[cfg(not(target_pointer_width = "64"))]
type RsaWide = u64;

const RSA_LIMB_BITS: usize = RsaLimb::BITS as usize;

/// The widest modulus admitted, in bits. A deliberate ceiling: it sizes
/// every buffer here and every job's step cost, and no public issuer signs
/// with more.
pub const RSA_MODULUS_BITS_MAX: usize = 4096;
/// The narrowest modulus admitted. Below this the key offers less than the
/// 112-bit level the stack's weakest admitted suite gives.
pub const RSA_MODULUS_BITS_MIN: usize = 2048;
/// The widest public exponent admitted, in bits.
pub const RSA_EXPONENT_BITS_MAX: usize = 32;
/// The widest modulus, in bytes: the length of a signature and of an
/// encoded message at the ceiling.
pub const RSA_BYTES_MAX: usize = RSA_MODULUS_BITS_MAX / 8;

const RSA_LIMBS_MAX: usize = RSA_MODULUS_BITS_MAX / RSA_LIMB_BITS;
/// A private-key prime is at most half the modulus.
const RSA_HALF_LIMBS_MAX: usize = RSA_LIMBS_MAX / 2;
/// The CIOS accumulator carries two limbs past the modulus length.
const RSA_T_LIMBS: usize = RSA_LIMBS_MAX + 2;

/// A digest algorithm a signature is made over.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RsaHash {
    Sha256,
    Sha384,
}

impl RsaHash {
    pub const fn digest_len(self) -> usize {
        match self {
            RsaHash::Sha256 => 32,
            RsaHash::Sha384 => 48,
        }
    }
}

/// What a stepped job answers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RsaStep {
    /// More units remain; call again.
    Pending,
    /// The result is ready.
    Done,
}

// ── Limb arithmetic ──────────────────────────────────────────────────────

fn rsa_zeroize(v: &mut [RsaLimb]) {
    for x in v.iter_mut() {
        // SAFETY: a plain volatile store to an element of a live slice.
        unsafe { core::ptr::write_volatile(x, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

fn rsa_zeroize_bytes(v: &mut [u8]) {
    for x in v.iter_mut() {
        // SAFETY: a plain volatile store to an element of a live slice.
        unsafe { core::ptr::write_volatile(x, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// All-ones when `c != 0`, else zero. Branchless.
#[inline(always)]
fn rsa_mask(c: RsaLimb) -> RsaLimb {
    ((c | c.wrapping_neg()) >> (RSA_LIMB_BITS - 1)).wrapping_neg()
}

/// `a = b` where `m` is all-ones, unchanged where zero.
#[inline(always)]
fn rsa_select(a: &mut [RsaLimb], b: &[RsaLimb], m: RsaLimb, len: usize) {
    let mut i = 0;
    while i < len {
        a[i] = (a[i] & !m) | (b[i] & m);
        i += 1;
    }
}

/// Big-endian bytes to little-endian limbs; answers the limb count.
fn rsa_from_be(bytes: &[u8], out: &mut [RsaLimb]) -> usize {
    let bytes_per = RSA_LIMB_BITS / 8;
    let len = bytes.len().div_ceil(bytes_per);
    let mut i = 0;
    while i < out.len() {
        out[i] = 0;
        i += 1;
    }
    let mut k = 0;
    while k < bytes.len() {
        let byte = bytes[bytes.len() - 1 - k];
        out[k / bytes_per] |= (byte as RsaLimb) << (8 * (k % bytes_per));
        k += 1;
    }
    len
}

/// Little-endian limbs to big-endian bytes of exactly `out.len()`.
fn rsa_to_be(v: &[RsaLimb], out: &mut [u8]) {
    let bytes_per = RSA_LIMB_BITS / 8;
    let mut k = 0;
    while k < out.len() {
        let limb = k / bytes_per;
        let byte = if limb < v.len() {
            (v[limb] >> (8 * (k % bytes_per))) as u8
        } else {
            0
        };
        out[out.len() - 1 - k] = byte;
        k += 1;
    }
}

/// Bit length of `v[..len]`.
fn rsa_bit_len(v: &[RsaLimb], len: usize) -> usize {
    let mut i = len;
    while i > 0 {
        i -= 1;
        if v[i] != 0 {
            return i * RSA_LIMB_BITS + (RSA_LIMB_BITS - v[i].leading_zeros() as usize);
        }
    }
    0
}

/// `a - b` into `out` over `len` limbs; answers the final borrow (0 or 1).
fn rsa_sub(out: &mut [RsaLimb], a: &[RsaLimb], b: &[RsaLimb], len: usize) -> RsaLimb {
    let mut borrow: RsaLimb = 0;
    let mut i = 0;
    while i < len {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        out[i] = d2;
        borrow = (b1 as RsaLimb) | (b2 as RsaLimb);
        i += 1;
    }
    borrow
}

/// `a + b` into `out` over `len` limbs; answers the final carry.
fn rsa_add(out: &mut [RsaLimb], a: &[RsaLimb], b: &[RsaLimb], len: usize) -> RsaLimb {
    let mut carry: RsaLimb = 0;
    let mut i = 0;
    while i < len {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        out[i] = s2;
        carry = (c1 as RsaLimb) | (c2 as RsaLimb);
        i += 1;
    }
    carry
}

/// Whether `a < b` over `len` limbs, as a mask. Constant-time.
fn rsa_lt_mask(a: &[RsaLimb], b: &[RsaLimb], len: usize) -> RsaLimb {
    let mut scratch = [0 as RsaLimb; RSA_LIMBS_MAX];
    let borrow = rsa_sub(&mut scratch[..len], a, b, len);
    rsa_mask(borrow)
}

/// `v = 2v mod n` for `v < n`, `n`'s top bit set. Constant-time.
fn rsa_double_mod(v: &mut [RsaLimb], n: &[RsaLimb], len: usize) {
    let mut carry: RsaLimb = 0;
    let mut i = 0;
    while i < len {
        let next = v[i] >> (RSA_LIMB_BITS - 1);
        v[i] = (v[i] << 1) | carry;
        carry = next;
        i += 1;
    }
    // 2v < 2n, and the carry out is the (len*LIMB_BITS)th bit: subtract n
    // where 2v >= n, which is exactly where the carry is set or the
    // subtraction does not borrow.
    let mut d = [0 as RsaLimb; RSA_LIMBS_MAX];
    let borrow = rsa_sub(&mut d[..len], v, n, len);
    let keep = rsa_mask(carry) | !rsa_mask(borrow);
    rsa_select(v, &d[..len], keep, len);
}

/// `-n[0]^{-1} mod 2^LIMB_BITS` for odd `n[0]`, by Newton iteration.
fn rsa_n0_inverse(n0: RsaLimb) -> RsaLimb {
    // x = n0^{-1} mod 2^k, doubling the correct bits each round; 6 rounds
    // cover 64 bits from the initial 1 bit.
    let mut x: RsaLimb = 1;
    let mut i = 0;
    while i < 7 {
        x = x.wrapping_mul((2 as RsaLimb).wrapping_sub(n0.wrapping_mul(x)));
        i += 1;
    }
    x.wrapping_neg()
}

/// One CIOS row: fold `a * b_i` and the reduction limb into `t`, then
/// shift `t` down a limb. `t` is `len + 2` limbs.
#[inline(always)]
fn rsa_cios_row(
    t: &mut [RsaLimb],
    a: &[RsaLimb],
    bi: RsaLimb,
    n: &[RsaLimb],
    n0: RsaLimb,
    len: usize,
) {
    let mut c: RsaWide = 0;
    let mut j = 0;
    while j < len {
        let s = t[j] as RsaWide + (a[j] as RsaWide) * (bi as RsaWide) + c;
        t[j] = s as RsaLimb;
        c = s >> RSA_LIMB_BITS;
        j += 1;
    }
    let s = t[len] as RsaWide + c;
    t[len] = s as RsaLimb;
    t[len + 1] = (s >> RSA_LIMB_BITS) as RsaLimb;

    let m = t[0].wrapping_mul(n0);
    let s = t[0] as RsaWide + (m as RsaWide) * (n[0] as RsaWide);
    c = s >> RSA_LIMB_BITS;
    let mut j = 1;
    while j < len {
        let s = t[j] as RsaWide + (m as RsaWide) * (n[j] as RsaWide) + c;
        t[j - 1] = s as RsaLimb;
        c = s >> RSA_LIMB_BITS;
        j += 1;
    }
    let s = t[len] as RsaWide + c;
    t[len - 1] = s as RsaLimb;
    c = s >> RSA_LIMB_BITS;
    t[len] = t[len + 1].wrapping_add(c as RsaLimb);
    t[len + 1] = 0;
}

// ── A stepped Montgomery product ──────────────────────────────────────────

/// One Montgomery product `out = a * b * R^{-1} mod n`, a row per unit.
struct RsaMul {
    t: [RsaLimb; RSA_T_LIMBS],
    row: usize,
}

impl RsaMul {
    const fn new() -> Self {
        Self {
            t: [0; RSA_T_LIMBS],
            row: 0,
        }
    }

    fn start(&mut self) {
        let mut i = 0;
        while i < RSA_T_LIMBS {
            self.t[i] = 0;
            i += 1;
        }
        self.row = 0;
    }

    /// Run up to `units` rows of `a * b`. Answers the rows consumed and
    /// whether the product is complete; when it is, `out` holds it.
    fn step(
        &mut self,
        m: &RsaModulus,
        a: &[RsaLimb],
        b: &[RsaLimb],
        out: &mut [RsaLimb],
        units: usize,
    ) -> (usize, bool) {
        self.step_raw(&m.n, m.n0, m.len, a, b, out, units)
    }

    /// `step` over a modulus given as its parts, for the modulus's own
    /// preparation.
    #[allow(
        clippy::too_many_arguments,
        reason = "the modulus, its inverse, the two operands and the accumulator are the row's whole input; a struct for them would be built and torn down per row"
    )]
    fn step_raw(
        &mut self,
        n: &[RsaLimb],
        n0: RsaLimb,
        len: usize,
        a: &[RsaLimb],
        b: &[RsaLimb],
        out: &mut [RsaLimb],
        units: usize,
    ) -> (usize, bool) {
        let mut used = 0;
        while used < units && self.row < len {
            rsa_cios_row(&mut self.t, a, b[self.row], n, n0, len);
            self.row += 1;
            used += 1;
        }
        if self.row < len {
            return (used, false);
        }
        // t < 2n: one masked subtraction, the carry limb included.
        let mut d = [0 as RsaLimb; RSA_LIMBS_MAX];
        let borrow = rsa_sub(&mut d[..len], &self.t[..len], &n[..len], len);
        let keep = rsa_mask(self.t[len]) | !rsa_mask(borrow);
        let mut i = 0;
        while i < len {
            out[i] = self.t[i];
            i += 1;
        }
        rsa_select(out, &d[..len], keep, len);
        (used, true)
    }
}

// ── A prepared modulus ────────────────────────────────────────────────────

/// A modulus with its Montgomery constants. `r2` is prepared by stepping:
/// for a modulus whose width is a whole number of limbs, R mod n is one
/// subtraction, and R² follows from `s` doublings and `j` Montgomery
/// squarings with `s·2^j = bits` — a dozen products rather than thousands
/// of doublings. Any other width takes the doubling path from 1.
pub struct RsaModulus {
    n: [RsaLimb; RSA_LIMBS_MAX],
    r2: [RsaLimb; RSA_LIMBS_MAX],
    tmp: [RsaLimb; RSA_LIMBS_MAX],
    mul: RsaMul,
    len: usize,
    bits: usize,
    n0: RsaLimb,
    /// Doublings still owed to `r2`.
    dbl_left: usize,
    /// Squarings still owed to `r2`, after the doublings.
    sq_left: usize,
}

impl RsaModulus {
    pub const fn empty() -> Self {
        Self {
            n: [0; RSA_LIMBS_MAX],
            r2: [0; RSA_LIMBS_MAX],
            tmp: [0; RSA_LIMBS_MAX],
            mul: RsaMul::new(),
            len: 0,
            bits: 0,
            n0: 0,
            dbl_left: 0,
            sq_left: 0,
        }
    }

    /// Load a big-endian modulus. Refuses an even modulus, one outside
    /// `[min_bits, RSA_MODULUS_BITS_MAX]`, or one whose top byte is zero.
    /// `r2` is left to `prepare_step`.
    pub fn load(&mut self, be: &[u8], min_bits: usize) -> bool {
        if be.is_empty() || be[0] == 0 || be.len() > RSA_BYTES_MAX {
            return false;
        }
        let len = rsa_from_be(be, &mut self.n);
        let bits = rsa_bit_len(&self.n, len);
        if bits < min_bits || bits > RSA_MODULUS_BITS_MAX || self.n[0] & 1 == 0 {
            rsa_zeroize(&mut self.n);
            return false;
        }
        self.len = len;
        self.bits = bits;
        self.n0 = rsa_n0_inverse(self.n[0]);
        let mut i = 0;
        while i < RSA_LIMBS_MAX {
            self.r2[i] = 0;
            i += 1;
        }
        self.mul.start();
        if bits == len * RSA_LIMB_BITS {
            // R = 2^bits and n has its top bit set, so R mod n = R - n, the
            // two's complement of n over `len` limbs. Then double `s` times
            // and square `j` times where s·2^j = bits: each squaring maps
            // 2^e to 2^(2e - bits), so 2^(bits + s) becomes 2^(bits + s·2^j).
            let zero = [0 as RsaLimb; RSA_LIMBS_MAX];
            let mut r = [0 as RsaLimb; RSA_LIMBS_MAX];
            rsa_sub(&mut r[..len], &zero[..len], &self.n[..len], len);
            self.r2[..len].copy_from_slice(&r[..len]);
            let j = bits.trailing_zeros() as usize;
            self.dbl_left = bits >> j;
            self.sq_left = j;
        } else {
            self.dbl_left = 2 * len * RSA_LIMB_BITS;
            self.sq_left = 0;
            self.r2[0] = 1;
        }
        true
    }

    /// Advance `r2` by up to `units`: a doubling is one unit, a squaring
    /// costs a row per unit. Done when nothing remains.
    pub fn prepare_step(&mut self, units: usize) -> RsaStep {
        let mut left = units;
        while left > 0 && self.dbl_left > 0 {
            rsa_double_mod(&mut self.r2[..self.len], &self.n[..self.len], self.len);
            self.dbl_left -= 1;
            left -= 1;
        }
        while left > 0 && self.sq_left > 0 {
            let len = self.len;
            let n0 = self.n0;
            let (used, done) =
                self.mul
                    .step_raw(&self.n, n0, len, &self.r2, &self.r2, &mut self.tmp, left);
            left -= used;
            if done {
                self.r2[..len].copy_from_slice(&self.tmp[..len]);
                self.mul.start();
                self.sq_left -= 1;
            }
        }
        if self.dbl_left == 0 && self.sq_left == 0 {
            RsaStep::Done
        } else {
            RsaStep::Pending
        }
    }

    /// Prepare in one call, for hosts and key loads.
    pub fn prepare(&mut self) {
        while self.prepare_step(usize::MAX) == RsaStep::Pending {}
    }

    pub fn is_ready(&self) -> bool {
        self.len != 0 && self.dbl_left == 0 && self.sq_left == 0
    }

    pub fn bits(&self) -> usize {
        self.bits
    }

    pub fn byte_len(&self) -> usize {
        self.bits.div_ceil(8)
    }

    /// Units `prepare_step` still owes.
    pub fn prepare_units_left(&self) -> usize {
        self.dbl_left + self.sq_left * self.len
    }

    pub fn zeroize(&mut self) {
        rsa_zeroize(&mut self.n);
        rsa_zeroize(&mut self.r2);
        rsa_zeroize(&mut self.tmp);
        rsa_zeroize(&mut self.mul.t);
        self.len = 0;
        self.bits = 0;
        self.n0 = 0;
        self.dbl_left = 0;
        self.sq_left = 0;
    }
}

// ── Public exponentiation: verification ───────────────────────────────────

const RSA_VERIFY_LOAD_BASE: u8 = 0;
const RSA_VERIFY_SQUARE: u8 = 1;
const RSA_VERIFY_MULTIPLY: u8 = 2;
const RSA_VERIFY_OUT: u8 = 3;
const RSA_VERIFY_DONE: u8 = 4;

/// `s^e mod n` as a stepped job. The exponent is public and walked from
/// its top set bit: the accumulator starts as the base, so the schedule is
/// one product to enter Montgomery form, one square per remaining bit, one
/// product per set bit, and one to leave Montgomery form.
pub struct RsaVerifyJob {
    pub modulus: RsaModulus,
    e: u32,
    /// The next exponent bit to consume, counting down; `e_bit == 0`
    /// after the bit 0 is done.
    e_bit: u32,
    phase: u8,
    sig: [RsaLimb; RSA_LIMBS_MAX],
    base: [RsaLimb; RSA_LIMBS_MAX],
    acc: [RsaLimb; RSA_LIMBS_MAX],
    tmp: [RsaLimb; RSA_LIMBS_MAX],
    one: [RsaLimb; RSA_LIMBS_MAX],
    mul: RsaMul,
    em: [u8; RSA_BYTES_MAX],
}

impl RsaVerifyJob {
    pub const fn new() -> Self {
        Self {
            modulus: RsaModulus::empty(),
            e: 0,
            e_bit: 0,
            phase: RSA_VERIFY_DONE,
            sig: [0; RSA_LIMBS_MAX],
            base: [0; RSA_LIMBS_MAX],
            acc: [0; RSA_LIMBS_MAX],
            tmp: [0; RSA_LIMBS_MAX],
            one: [0; RSA_LIMBS_MAX],
            mul: RsaMul::new(),
            em: [0; RSA_BYTES_MAX],
        }
    }

    /// Begin `sig^e mod n`. `n` and `sig` are big-endian; the signature
    /// must be exactly the modulus length and numerically below the
    /// modulus (RFC 8017 §5.2.2 step 1). Refuses an inadmissible key.
    pub fn start(&mut self, n_be: &[u8], e: u32, sig: &[u8]) -> bool {
        if !self.modulus.load(n_be, RSA_MODULUS_BITS_MIN) {
            return false;
        }
        if e < 3 || e & 1 == 0 || sig.len() != self.modulus.byte_len() {
            self.modulus.zeroize();
            return false;
        }
        rsa_from_be(sig, &mut self.sig);
        let len = self.modulus.len;
        if rsa_lt_mask(&self.sig, &self.modulus.n, len) == 0 {
            self.modulus.zeroize();
            return false;
        }
        self.e = e;
        self.e_bit = 32 - e.leading_zeros();
        let mut i = 0;
        while i < RSA_LIMBS_MAX {
            self.one[i] = 0;
            i += 1;
        }
        self.one[0] = 1;
        self.phase = RSA_VERIFY_LOAD_BASE;
        self.mul.start();
        true
    }

    /// Units the whole job needs, asked right after `start`, for a caller
    /// pacing itself: what the modulus preparation still owes plus the
    /// rows of every product.
    pub fn units_total(&self) -> usize {
        let len = self.modulus.len;
        let bits = 32 - self.e.leading_zeros() as usize;
        let products = 1 + (bits - 1) + (self.e.count_ones() as usize - 1) + 1;
        self.modulus.prepare_units_left() + products * len
    }

    /// Spend up to `units` (doublings while preparing, rows afterwards).
    pub fn step(&mut self, units: usize) -> RsaStep {
        let mut left = units;
        if !self.modulus.is_ready() {
            let before = self.modulus.prepare_units_left();
            if self.modulus.prepare_step(left) == RsaStep::Pending {
                return RsaStep::Pending;
            }
            left = left.saturating_sub(before);
        }
        while left > 0 {
            let len = self.modulus.len;
            match self.phase {
                RSA_VERIFY_LOAD_BASE => {
                    // base = sig * R² * R^{-1} = sig * R (Montgomery form);
                    // the accumulator starts as the base: the top bit of e
                    // is set.
                    let (used, done) = self.mul.step(
                        &self.modulus,
                        &self.sig,
                        &self.modulus.r2,
                        &mut self.tmp,
                        left,
                    );
                    left -= used;
                    if done {
                        self.base[..len].copy_from_slice(&self.tmp[..len]);
                        self.acc[..len].copy_from_slice(&self.tmp[..len]);
                        self.e_bit -= 1;
                        self.mul.start();
                        self.phase = if self.e_bit == 0 {
                            RSA_VERIFY_OUT
                        } else {
                            RSA_VERIFY_SQUARE
                        };
                    }
                }
                RSA_VERIFY_SQUARE => {
                    let (used, done) =
                        self.mul
                            .step(&self.modulus, &self.acc, &self.acc, &mut self.tmp, left);
                    left -= used;
                    if done {
                        self.acc[..len].copy_from_slice(&self.tmp[..len]);
                        self.mul.start();
                        let bit = (self.e >> (self.e_bit - 1)) & 1;
                        self.phase = if bit == 1 {
                            RSA_VERIFY_MULTIPLY
                        } else {
                            self.e_bit -= 1;
                            if self.e_bit == 0 {
                                RSA_VERIFY_OUT
                            } else {
                                RSA_VERIFY_SQUARE
                            }
                        };
                    }
                }
                RSA_VERIFY_MULTIPLY => {
                    let (used, done) =
                        self.mul
                            .step(&self.modulus, &self.acc, &self.base, &mut self.tmp, left);
                    left -= used;
                    if done {
                        self.acc[..len].copy_from_slice(&self.tmp[..len]);
                        self.mul.start();
                        self.e_bit -= 1;
                        self.phase = if self.e_bit == 0 {
                            RSA_VERIFY_OUT
                        } else {
                            RSA_VERIFY_SQUARE
                        };
                    }
                }
                RSA_VERIFY_OUT => {
                    // Leave Montgomery form: acc * 1 * R^{-1}.
                    let (used, done) =
                        self.mul
                            .step(&self.modulus, &self.acc, &self.one, &mut self.tmp, left);
                    left -= used;
                    if done {
                        let k = self.modulus.byte_len();
                        rsa_to_be(&self.tmp[..len], &mut self.em[..k]);
                        self.phase = RSA_VERIFY_DONE;
                        return RsaStep::Done;
                    }
                }
                _ => return RsaStep::Done,
            }
        }
        if self.phase == RSA_VERIFY_DONE {
            RsaStep::Done
        } else {
            RsaStep::Pending
        }
    }

    pub fn is_done(&self) -> bool {
        self.phase == RSA_VERIFY_DONE
    }

    /// The encoded message `sig^e mod n`, big-endian, modulus length.
    /// Meaningful once `step` has answered `Done`.
    pub fn encoded_message(&self) -> &[u8] {
        &self.em[..self.modulus.byte_len()]
    }
}

impl Default for RsaVerifyJob {
    fn default() -> Self {
        Self::new()
    }
}

// ── Encodings ─────────────────────────────────────────────────────────────

/// DigestInfo prefix for SHA-256 (RFC 8017 §9.2 note 1).
const RSA_DIGEST_INFO_SHA256: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
/// DigestInfo prefix for SHA-384.
const RSA_DIGEST_INFO_SHA384: [u8; 19] = [
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];

fn rsa_ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    let mut i = 0;
    while i < a.len() {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}

/// Compose EMSA-PKCS1-v1_5 for `digest` into `em` (RFC 8017 §9.2). False
/// when `em` is too short for the encoding.
pub fn rsa_pkcs1_v15_encode(hash: RsaHash, digest: &[u8], em: &mut [u8]) -> bool {
    let hlen = hash.digest_len();
    if digest.len() != hlen {
        return false;
    }
    let tlen = 19 + hlen;
    if em.len() < tlen + 11 {
        return false;
    }
    let k = em.len();
    em[0] = 0x00;
    em[1] = 0x01;
    let ps_end = k - tlen - 1;
    let mut i = 2;
    while i < ps_end {
        em[i] = 0xff;
        i += 1;
    }
    em[ps_end] = 0x00;
    match hash {
        RsaHash::Sha256 => em[ps_end + 1..ps_end + 20].copy_from_slice(&RSA_DIGEST_INFO_SHA256),
        RsaHash::Sha384 => em[ps_end + 1..ps_end + 20].copy_from_slice(&RSA_DIGEST_INFO_SHA384),
    }
    em[ps_end + 20..].copy_from_slice(digest);
    true
}

/// Whether `em` (the recovered `s^e mod n`) is the PKCS#1 v1.5 encoding of
/// `digest`. The expected encoding is composed and compared whole.
pub fn rsa_pkcs1_v15_check(hash: RsaHash, digest: &[u8], em: &[u8]) -> bool {
    let mut expected = [0u8; RSA_BYTES_MAX];
    if em.len() > RSA_BYTES_MAX || !rsa_pkcs1_v15_encode(hash, digest, &mut expected[..em.len()]) {
        return false;
    }
    rsa_ct_eq(&expected[..em.len()], em)
}

/// MGF1 over `seed` into `mask`.
fn rsa_mgf1(hash: RsaHash, seed: &[u8], mask: &mut [u8]) {
    let hlen = hash.digest_len();
    let mut buf = [0u8; 48 + 4];
    let n = seed.len().min(48);
    buf[..n].copy_from_slice(&seed[..n]);
    let mut counter: u32 = 0;
    let mut off = 0;
    while off < mask.len() {
        buf[n..n + 4].copy_from_slice(&counter.to_be_bytes());
        let take = (mask.len() - off).min(hlen);
        match hash {
            RsaHash::Sha256 => {
                let d = sha256(&buf[..n + 4]);
                mask[off..off + take].copy_from_slice(&d[..take]);
            }
            RsaHash::Sha384 => {
                let d = sha384(&buf[..n + 4]);
                mask[off..off + take].copy_from_slice(&d[..take]);
            }
        }
        off += take;
        counter += 1;
    }
}

/// H = Hash(0^8 || mHash || salt).
fn rsa_pss_hash(hash: RsaHash, mhash: &[u8], salt: &[u8], out: &mut [u8]) {
    let mut m = [0u8; 8 + 48 + 48];
    let hlen = hash.digest_len();
    m[8..8 + hlen].copy_from_slice(&mhash[..hlen]);
    m[8 + hlen..8 + hlen + salt.len()].copy_from_slice(salt);
    let total = 8 + hlen + salt.len();
    match hash {
        RsaHash::Sha256 => out[..32].copy_from_slice(&sha256(&m[..total])),
        RsaHash::Sha384 => out[..48].copy_from_slice(&sha384(&m[..total])),
    }
}

/// EMSA-PSS-VERIFY (RFC 8017 §9.1.2) with salt length = hash length, over
/// an `em` of the modulus length for a modulus of `mod_bits` bits.
pub fn rsa_pss_verify(hash: RsaHash, mhash: &[u8], em: &[u8], mod_bits: usize) -> bool {
    let hlen = hash.digest_len();
    let slen = hlen;
    if mhash.len() != hlen || em.len() > RSA_BYTES_MAX {
        return false;
    }
    let em_bits = mod_bits - 1;
    let em_len = em_bits.div_ceil(8);
    // The encoded message is conveyed in a modulus-length integer; when
    // emLen is shorter by a byte the leading byte must be zero.
    if em.len() < em_len {
        return false;
    }
    let lead = em.len() - em_len;
    let mut i = 0;
    while i < lead {
        if em[i] != 0 {
            return false;
        }
        i += 1;
    }
    let em = &em[lead..];
    if em_len < hlen + slen + 2 || em[em_len - 1] != 0xbc {
        return false;
    }
    let db_len = em_len - hlen - 1;
    let masked_db = &em[..db_len];
    let h = &em[db_len..db_len + hlen];
    let unused_bits = 8 * em_len - em_bits;
    if unused_bits > 0 && masked_db[0] >> (8 - unused_bits) != 0 {
        return false;
    }
    let mut db = [0u8; RSA_BYTES_MAX];
    rsa_mgf1(hash, h, &mut db[..db_len]);
    i = 0;
    while i < db_len {
        db[i] ^= masked_db[i];
        i += 1;
    }
    if unused_bits > 0 {
        db[0] &= 0xffu8 >> unused_bits;
    }
    // DB = PS (zeros) || 0x01 || salt.
    let ps_len = em_len - hlen - slen - 2;
    let mut bad = 0u8;
    i = 0;
    while i < ps_len {
        bad |= db[i];
        i += 1;
    }
    bad |= db[ps_len] ^ 0x01;
    if bad != 0 {
        return false;
    }
    let salt = &db[ps_len + 1..ps_len + 1 + slen];
    let mut h2 = [0u8; 48];
    rsa_pss_hash(hash, mhash, salt, &mut h2);
    rsa_ct_eq(&h2[..hlen], h)
}

/// EMSA-PSS-ENCODE (RFC 8017 §9.1.1) with the given salt (its length is
/// the hash length) into `em` of the modulus length.
pub fn rsa_pss_encode(
    hash: RsaHash,
    mhash: &[u8],
    salt: &[u8],
    em: &mut [u8],
    mod_bits: usize,
) -> bool {
    let hlen = hash.digest_len();
    if mhash.len() != hlen || salt.len() != hlen || em.len() > RSA_BYTES_MAX {
        return false;
    }
    let em_bits = mod_bits - 1;
    let em_len = em_bits.div_ceil(8);
    if em.len() < em_len || em_len < 2 * hlen + 2 {
        return false;
    }
    let lead = em.len() - em_len;
    let mut i = 0;
    while i < lead {
        em[i] = 0;
        i += 1;
    }
    let mut h = [0u8; 48];
    rsa_pss_hash(hash, mhash, salt, &mut h);
    let db_len = em_len - hlen - 1;
    let ps_len = em_len - 2 * hlen - 2;
    let mut db = [0u8; RSA_BYTES_MAX];
    i = 0;
    while i < ps_len {
        db[i] = 0;
        i += 1;
    }
    db[ps_len] = 0x01;
    db[ps_len + 1..ps_len + 1 + hlen].copy_from_slice(salt);
    let mut mask = [0u8; RSA_BYTES_MAX];
    rsa_mgf1(hash, &h[..hlen], &mut mask[..db_len]);
    let out = &mut em[lead..];
    i = 0;
    while i < db_len {
        out[i] = db[i] ^ mask[i];
        i += 1;
    }
    let unused_bits = 8 * em_len - em_bits;
    if unused_bits > 0 {
        out[0] &= 0xffu8 >> unused_bits;
    }
    out[db_len..db_len + hlen].copy_from_slice(&h[..hlen]);
    out[em_len - 1] = 0xbc;
    true
}

// ── DER ───────────────────────────────────────────────────────────────────

/// A DER TLV at `at`: `(content_start, content_len)`. Minimal length
/// encodings only.
fn rsa_der_tlv(d: &[u8], at: usize, tag: u8) -> Option<(usize, usize)> {
    if at + 2 > d.len() || d[at] != tag {
        return None;
    }
    let first = d[at + 1];
    let (len, hdr) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 2 || at + 2 + n > d.len() {
            return None;
        }
        let mut len = 0usize;
        let mut i = 0;
        while i < n {
            len = (len << 8) | d[at + 2 + i] as usize;
            i += 1;
        }
        // Minimal: the long form is only for lengths the short form
        // cannot carry, and no leading zero octet.
        if len < 0x80 || (n == 2 && len < 0x100) {
            return None;
        }
        (len, 2 + n)
    };
    let start = at + hdr;
    if start + len > d.len() {
        return None;
    }
    Some((start, len))
}

/// A non-negative DER INTEGER's magnitude at `at`: the content without a
/// sign octet. Refuses a negative, an empty, or a non-minimal encoding.
fn rsa_der_uint(d: &[u8], at: usize) -> Option<(&[u8], usize)> {
    let (start, len) = rsa_der_tlv(d, at, 0x02)?;
    if len == 0 {
        return None;
    }
    let body = &d[start..start + len];
    if body[0] & 0x80 != 0 {
        return None;
    }
    let mag = if body[0] == 0 {
        // A leading zero is the sign octet and only that: the next byte
        // must need it.
        if len == 1 {
            &body[..1]
        } else if body[1] & 0x80 == 0 {
            return None;
        } else {
            &body[1..]
        }
    } else {
        body
    };
    Some((mag, start + len))
}

/// The `RSAPrivateKey` inside a PKCS#8 `PrivateKeyInfo` (RFC 5208) for an
/// rsaEncryption key, or `der` itself when it is already the PKCS#1 form.
/// A key file may come either way — `openssl genpkey` writes PKCS#8,
/// `openssl rsa -traditional` writes PKCS#1 — and the holder should not
/// have to know which. `None` for anything that is neither.
pub fn rsa_private_key_pkcs1(der: &[u8]) -> Option<&[u8]> {
    let (start, len) = rsa_der_tlv(der, 0, 0x30)?;
    if start + len != der.len() {
        return None;
    }
    // PKCS#1 opens INTEGER 0, INTEGER n (a long integer); PKCS#8 opens
    // INTEGER 0, SEQUENCE (the algorithm). Both begin with the version, so
    // the second member says which this is.
    let (_ver, at) = rsa_der_uint(der, start)?;
    if at < der.len() && der[at] == 0x02 {
        return Some(der);
    }
    let (alg_start, alg_len) = rsa_der_tlv(der, at, 0x30)?;
    // AlgorithmIdentifier: OID rsaEncryption (1.2.840.113549.1.1.1), NULL.
    const RSA_OID: [u8; 11] = [
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
    ];
    let alg = &der[alg_start..alg_start + alg_len];
    if alg.len() != RSA_OID.len() + 2
        || alg[..RSA_OID.len()] != RSA_OID
        || alg[RSA_OID.len()..] != [0x05, 0x00]
    {
        return None;
    }
    let (key_start, key_len) = rsa_der_tlv(der, alg_start + alg_len, 0x04)?;
    // Attributes may trail the key; the key itself is what is wanted.
    Some(&der[key_start..key_start + key_len])
}

/// An RSA public key as its DER carries it: modulus and exponent bytes,
/// both minimal big-endian.
pub struct RsaPublicKeyRef<'a> {
    pub n: &'a [u8],
    pub e: u32,
}

/// Parse `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent
/// INTEGER }` — the contents of an `rsaEncryption` SubjectPublicKeyInfo's
/// BIT STRING. Admits 2048..4096-bit moduli and odd exponents in
/// `[3, 2^32)`.
pub fn rsa_public_key_parse(der: &[u8]) -> Option<RsaPublicKeyRef<'_>> {
    let (start, len) = rsa_der_tlv(der, 0, 0x30)?;
    if start + len != der.len() {
        return None;
    }
    let (n, next) = rsa_der_uint(der, start)?;
    let (e_bytes, end) = rsa_der_uint(der, next)?;
    if end != start + len {
        return None;
    }
    let n_bits = n.len() * 8 - n[0].leading_zeros() as usize;
    if !(RSA_MODULUS_BITS_MIN..=RSA_MODULUS_BITS_MAX).contains(&n_bits) || n[n.len() - 1] & 1 == 0 {
        return None;
    }
    if e_bytes.is_empty() || e_bytes.len() > 4 {
        return None;
    }
    let mut e: u32 = 0;
    let mut i = 0;
    while i < e_bytes.len() {
        e = (e << 8) | e_bytes[i] as u32;
        i += 1;
    }
    if e < 3 || e & 1 == 0 {
        return None;
    }
    Some(RsaPublicKeyRef { n, e })
}

/// The modulus width in bits of a parsed key.
pub fn rsa_public_key_bits(key: &RsaPublicKeyRef<'_>) -> usize {
    key.n.len() * 8 - key.n[0].leading_zeros() as usize
}

// ── One-shot verification ─────────────────────────────────────────────────

/// `s^e mod n` in one call, running the job to completion in place of a
/// caller's step budget. Answers the encoded message length written into
/// `em`, or `None` when the key or signature is inadmissible.
pub fn rsa_public_decrypt(
    job: &mut RsaVerifyJob,
    n: &[u8],
    e: u32,
    sig: &[u8],
    em: &mut [u8],
) -> Option<usize> {
    if !job.start(n, e, sig) {
        return None;
    }
    while job.step(usize::MAX) == RsaStep::Pending {}
    let out = job.encoded_message();
    if em.len() < out.len() {
        return None;
    }
    em[..out.len()].copy_from_slice(out);
    Some(out.len())
}

/// Verify a PKCS#1 v1.5 signature over `digest` in one call.
pub fn rsa_pkcs1_v15_verify(
    job: &mut RsaVerifyJob,
    key: &RsaPublicKeyRef<'_>,
    hash: RsaHash,
    digest: &[u8],
    sig: &[u8],
) -> bool {
    let mut em = [0u8; RSA_BYTES_MAX];
    match rsa_public_decrypt(job, key.n, key.e, sig, &mut em) {
        Some(k) => rsa_pkcs1_v15_check(hash, digest, &em[..k]),
        None => false,
    }
}

/// Verify a PSS signature over `mhash` in one call.
pub fn rsa_pss_verify_sig(
    job: &mut RsaVerifyJob,
    key: &RsaPublicKeyRef<'_>,
    hash: RsaHash,
    mhash: &[u8],
    sig: &[u8],
) -> bool {
    let mut em = [0u8; RSA_BYTES_MAX];
    match rsa_public_decrypt(job, key.n, key.e, sig, &mut em) {
        Some(k) => rsa_pss_verify(hash, mhash, &em[..k], rsa_public_key_bits(key)),
        None => false,
    }
}

// ── Private keys ──────────────────────────────────────────────────────────

/// A private key in CRT form with every modulus prepared. Zeroised on
/// `zeroize` and by `Drop`-less discipline: the holder calls it.
pub struct RsaPrivateKey {
    pub n: RsaModulus,
    p: RsaModulus,
    q: RsaModulus,
    dp: [RsaLimb; RSA_HALF_LIMBS_MAX],
    dq: [RsaLimb; RSA_HALF_LIMBS_MAX],
    /// qInv in Montgomery form mod p.
    qinv_m: [RsaLimb; RSA_HALF_LIMBS_MAX],
    e: u32,
    loaded: bool,
}

impl RsaPrivateKey {
    pub const fn empty() -> Self {
        Self {
            n: RsaModulus::empty(),
            p: RsaModulus::empty(),
            q: RsaModulus::empty(),
            dp: [0; RSA_HALF_LIMBS_MAX],
            dq: [0; RSA_HALF_LIMBS_MAX],
            qinv_m: [0; RSA_HALF_LIMBS_MAX],
            e: 0,
            loaded: false,
        }
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    pub fn public_exponent(&self) -> u32 {
        self.e
    }

    pub fn zeroize(&mut self) {
        self.n.zeroize();
        self.p.zeroize();
        self.q.zeroize();
        rsa_zeroize(&mut self.dp);
        rsa_zeroize(&mut self.dq);
        rsa_zeroize(&mut self.qinv_m);
        self.e = 0;
        self.loaded = false;
    }

    /// Load `RSAPrivateKey ::= SEQUENCE { version 0, n, e, d, p, q, dP, dQ,
    /// qInv }` (PKCS#1, RFC 8017 A.1.2). The CRT fields are required; `d`
    /// is read past and not kept. Checks `p·q = n`, the widths, and the
    /// exponent; prepares every modulus (three R² computations — a key
    /// load, not a step). The caller zeroises `der` afterwards.
    pub fn load_pkcs1_der(&mut self, der: &[u8]) -> bool {
        self.zeroize();
        let Some((start, len)) = rsa_der_tlv(der, 0, 0x30) else {
            return false;
        };
        if start + len != der.len() {
            return false;
        }
        let Some((ver, at)) = rsa_der_uint(der, start) else {
            return false;
        };
        if ver != [0u8] {
            return false;
        }
        let Some((n, at)) = rsa_der_uint(der, at) else {
            return false;
        };
        let Some((e_bytes, at)) = rsa_der_uint(der, at) else {
            return false;
        };
        let Some((_d, at)) = rsa_der_uint(der, at) else {
            return false;
        };
        let Some((p, at)) = rsa_der_uint(der, at) else {
            return false;
        };
        let Some((q, at)) = rsa_der_uint(der, at) else {
            return false;
        };
        let Some((dp, at)) = rsa_der_uint(der, at) else {
            return false;
        };
        let Some((dq, at)) = rsa_der_uint(der, at) else {
            return false;
        };
        let Some((qinv, at)) = rsa_der_uint(der, at) else {
            return false;
        };
        // Trailing optional otherPrimeInfos are not admitted: two primes.
        if at != start + len {
            return false;
        }
        if e_bytes.is_empty() || e_bytes.len() > 4 {
            return false;
        }
        let mut e: u32 = 0;
        for &b in e_bytes {
            e = (e << 8) | b as u32;
        }
        if e < 3 || e & 1 == 0 {
            return false;
        }
        if !self.n.load(n, RSA_MODULUS_BITS_MIN) {
            return false;
        }
        let half_min = self.n.bits / 2 - 8;
        if !self.p.load(p, half_min) || !self.q.load(q, half_min) {
            self.zeroize();
            return false;
        }
        let hl = RSA_HALF_LIMBS_MAX;
        if self.p.len > hl || self.q.len > hl {
            self.zeroize();
            return false;
        }
        // p·q = n, by schoolbook product.
        let mut prod = [0 as RsaLimb; RSA_LIMBS_MAX + 1];
        rsa_schoolbook_mul(&self.p.n[..self.p.len], &self.q.n[..self.q.len], &mut prod);
        let mut i = 0;
        let mut same = true;
        while i < RSA_LIMBS_MAX {
            let want = if i < self.n.len { self.n.n[i] } else { 0 };
            same &= prod[i] == want;
            i += 1;
        }
        same &= prod[RSA_LIMBS_MAX] == 0;
        if !same {
            self.zeroize();
            return false;
        }
        let mut tmp = [0 as RsaLimb; RSA_LIMBS_MAX];
        if rsa_from_be(dp, &mut tmp) > hl
            || rsa_from_be(dq, &mut tmp) > hl
            || rsa_from_be(qinv, &mut tmp) > hl
        {
            self.zeroize();
            return false;
        }
        rsa_from_be(dp, &mut tmp);
        self.dp.copy_from_slice(&tmp[..hl]);
        rsa_from_be(dq, &mut tmp);
        self.dq.copy_from_slice(&tmp[..hl]);
        // dP < p, dQ < q, qInv < p, or the key is not a CRT key.
        if rsa_lt_mask(&self.dp, &self.p.n, self.p.len) == 0
            || rsa_lt_mask(&self.dq, &self.q.n, self.q.len) == 0
        {
            self.zeroize();
            return false;
        }
        rsa_from_be(qinv, &mut tmp);
        if rsa_lt_mask(&tmp, &self.p.n, self.p.len) == 0 {
            self.zeroize();
            return false;
        }
        self.n.prepare();
        self.p.prepare();
        self.q.prepare();
        // qInv into Montgomery form mod p: qInv * R² * R^{-1}.
        let mut mul = RsaMul::new();
        mul.start();
        let mut out = [0 as RsaLimb; RSA_LIMBS_MAX];
        let (_, done) = mul.step(&self.p, &tmp, &self.p.r2, &mut out, usize::MAX);
        if !done {
            self.zeroize();
            return false;
        }
        self.qinv_m.copy_from_slice(&out[..hl]);
        rsa_zeroize(&mut tmp);
        rsa_zeroize(&mut out);
        self.e = e;
        self.loaded = true;
        true
    }

    /// The public key as `RSAPublicKey` DER into `out`; answers its
    /// length. For `PUBLIC` and for composing an SPKI.
    pub fn public_key_der(&self, out: &mut [u8]) -> Option<usize> {
        if !self.loaded {
            return None;
        }
        let k = self.n.byte_len();
        let mut n_be = [0u8; RSA_BYTES_MAX];
        rsa_to_be(&self.n.n[..self.n.len], &mut n_be[..k]);
        // INTEGER n: a leading zero because the top bit is set.
        let n_len = k + 1;
        let e_bytes = self.e.to_be_bytes();
        let mut e_skip = 0;
        while e_skip < 3 && e_bytes[e_skip] == 0 {
            e_skip += 1;
        }
        let e_body = &e_bytes[e_skip..];
        let e_len = e_body.len() + usize::from(e_body[0] & 0x80 != 0);
        let inner = rsa_der_hdr_len(n_len) + n_len + rsa_der_hdr_len(e_len) + e_len;
        let total = rsa_der_hdr_len(inner) + inner;
        if out.len() < total {
            return None;
        }
        let mut at = rsa_der_put_hdr(out, 0, 0x30, inner);
        at = rsa_der_put_hdr(out, at, 0x02, n_len);
        out[at] = 0;
        out[at + 1..at + 1 + k].copy_from_slice(&n_be[..k]);
        at += n_len;
        at = rsa_der_put_hdr(out, at, 0x02, e_len);
        if e_body[0] & 0x80 != 0 {
            out[at] = 0;
            at += 1;
        }
        out[at..at + e_body.len()].copy_from_slice(e_body);
        at += e_body.len();
        Some(at)
    }
}

fn rsa_der_hdr_len(len: usize) -> usize {
    if len < 0x80 {
        2
    } else if len < 0x100 {
        3
    } else {
        4
    }
}

fn rsa_der_put_hdr(out: &mut [u8], at: usize, tag: u8, len: usize) -> usize {
    out[at] = tag;
    if len < 0x80 {
        out[at + 1] = len as u8;
        at + 2
    } else if len < 0x100 {
        out[at + 1] = 0x81;
        out[at + 2] = len as u8;
        at + 3
    } else {
        out[at + 1] = 0x82;
        out[at + 2] = (len >> 8) as u8;
        out[at + 3] = len as u8;
        at + 4
    }
}

/// Plain `a * b` into `out` (at least `a.len() + b.len()` limbs).
fn rsa_schoolbook_mul(a: &[RsaLimb], b: &[RsaLimb], out: &mut [RsaLimb]) {
    let mut i = 0;
    while i < out.len() {
        out[i] = 0;
        i += 1;
    }
    i = 0;
    while i < a.len() {
        let mut c: RsaWide = 0;
        let mut j = 0;
        while j < b.len() {
            let s = out[i + j] as RsaWide + (a[i] as RsaWide) * (b[j] as RsaWide) + c;
            out[i + j] = s as RsaLimb;
            c = s >> RSA_LIMB_BITS;
            j += 1;
        }
        out[i + b.len()] = c as RsaLimb;
        i += 1;
    }
}

// ── Private exponentiation: signing ───────────────────────────────────────

const RSA_WINDOW: usize = 4;
const RSA_TABLE: usize = 1 << RSA_WINDOW;

const RSA_SIGN_REDUCE_P: u8 = 0;
const RSA_SIGN_EXP_P: u8 = 1;
const RSA_SIGN_REDUCE_Q: u8 = 2;
const RSA_SIGN_EXP_Q: u8 = 3;
const RSA_SIGN_COMBINE: u8 = 4;
const RSA_SIGN_DONE: u8 = 5;

/// One half-exponentiation `c^d mod m` by fixed 4-bit windows, stepped.
struct RsaWindowExp {
    /// Table of base^0..base^15 in Montgomery form.
    table: [[RsaLimb; RSA_HALF_LIMBS_MAX]; RSA_TABLE],
    acc: [RsaLimb; RSA_HALF_LIMBS_MAX],
    tmp: [RsaLimb; RSA_HALF_LIMBS_MAX],
    sel: [RsaLimb; RSA_HALF_LIMBS_MAX],
    mul: RsaMul,
    /// Table entries still to compute (entry k = entry k-1 * base).
    table_next: usize,
    /// Windows still to process, counting down; the exponent has
    /// `windows` 4-bit digits over the modulus width.
    window: usize,
    windows: usize,
    /// Squarings done in the current window.
    squares: usize,
    phase: u8,
}

const RSA_WEXP_TABLE: u8 = 0;
const RSA_WEXP_SQUARE: u8 = 1;
const RSA_WEXP_MULTIPLY: u8 = 2;
const RSA_WEXP_OUT: u8 = 3;
const RSA_WEXP_DONE: u8 = 4;

impl RsaWindowExp {
    const fn new() -> Self {
        Self {
            table: [[0; RSA_HALF_LIMBS_MAX]; RSA_TABLE],
            acc: [0; RSA_HALF_LIMBS_MAX],
            tmp: [0; RSA_HALF_LIMBS_MAX],
            sel: [0; RSA_HALF_LIMBS_MAX],
            mul: RsaMul::new(),
            table_next: 0,
            window: 0,
            windows: 0,
            squares: 0,
            phase: RSA_WEXP_DONE,
        }
    }

    /// Begin with `base` already reduced mod `m` (plain form).
    fn start(&mut self, m: &RsaModulus, base: &[RsaLimb]) {
        let len = m.len;
        // table[0] = R mod m (Montgomery one): computed as 1 * R² * R^{-1}.
        // table[1] = base in Montgomery form. Both are products; the table
        // phase computes entry 0 from `one`, entry 1 from `base`, and the
        // rest by multiplication.
        let mut i = 0;
        while i < RSA_HALF_LIMBS_MAX {
            self.tmp[i] = 0;
            self.sel[i] = if i < len { base[i] } else { 0 };
            i += 1;
        }
        self.tmp[0] = 1;
        self.table_next = 0;
        self.windows = m.bits.div_ceil(RSA_WINDOW);
        self.window = self.windows;
        self.squares = 0;
        self.phase = RSA_WEXP_TABLE;
        self.mul.start();
    }

    /// The exponent digit for window `w` (counting from the top).
    fn digit(exp: &[RsaLimb], windows: usize, w: usize) -> usize {
        let bit = (windows - 1 - w) * RSA_WINDOW;
        let limb = bit / RSA_LIMB_BITS;
        let off = bit % RSA_LIMB_BITS;
        let mut v = exp[limb] >> off;
        if off + RSA_WINDOW > RSA_LIMB_BITS && limb + 1 < exp.len() {
            v |= exp[limb + 1] << (RSA_LIMB_BITS - off);
        }
        (v as usize) & (RSA_TABLE - 1)
    }

    /// Read table entry `d` into `sel` by a masked scan of every entry.
    fn select(&mut self, d: usize, len: usize) {
        let mut i = 0;
        while i < len {
            self.sel[i] = 0;
            i += 1;
        }
        let mut k = 0;
        while k < RSA_TABLE {
            let m = rsa_mask(((k ^ d) == 0) as RsaLimb);
            let mut i = 0;
            while i < len {
                self.sel[i] |= self.table[k][i] & m;
                i += 1;
            }
            k += 1;
        }
    }

    /// Spend up to `units` rows. `out` receives the plain-form result on
    /// completion.
    fn step(
        &mut self,
        m: &RsaModulus,
        exp: &[RsaLimb],
        out: &mut [RsaLimb],
        units: usize,
    ) -> (usize, bool) {
        let len = m.len;
        let mut left = units;
        let mut used = 0;
        while left > 0 {
            match self.phase {
                RSA_WEXP_TABLE => {
                    let k = self.table_next;
                    // entry 0: one * r2; entry 1: base * r2; entry k: entry
                    // k-1 * entry 1.
                    let (u, done) = if k == 0 {
                        self.mul
                            .step(m, &self.tmp[..len], &m.r2[..len], &mut self.acc, left)
                    } else if k == 1 {
                        self.mul
                            .step(m, &self.sel[..len], &m.r2[..len], &mut self.acc, left)
                    } else {
                        let (lo, _) = self.table.split_at(k);
                        self.mul
                            .step(m, &lo[k - 1][..len], &lo[1][..len], &mut self.acc, left)
                    };
                    left -= u;
                    used += u;
                    if done {
                        self.table[k][..len].copy_from_slice(&self.acc[..len]);
                        self.mul.start();
                        self.table_next += 1;
                        if self.table_next == RSA_TABLE {
                            // acc = table[0] (Montgomery one); first window
                            // has no squarings to do on a one, but a fixed
                            // schedule squares anyway.
                            self.acc[..len].copy_from_slice(&self.table[0][..len]);
                            self.window = 0;
                            self.squares = 0;
                            self.phase = RSA_WEXP_SQUARE;
                        }
                    }
                }
                RSA_WEXP_SQUARE => {
                    let (u, done) =
                        self.mul
                            .step(m, &self.acc[..len], &self.acc[..len], &mut self.tmp, left);
                    left -= u;
                    used += u;
                    if done {
                        self.acc[..len].copy_from_slice(&self.tmp[..len]);
                        self.mul.start();
                        self.squares += 1;
                        if self.squares == RSA_WINDOW {
                            let d = Self::digit(exp, self.windows, self.window);
                            self.select(d, len);
                            self.phase = RSA_WEXP_MULTIPLY;
                        }
                    }
                }
                RSA_WEXP_MULTIPLY => {
                    let (u, done) =
                        self.mul
                            .step(m, &self.acc[..len], &self.sel[..len], &mut self.tmp, left);
                    left -= u;
                    used += u;
                    if done {
                        self.acc[..len].copy_from_slice(&self.tmp[..len]);
                        self.mul.start();
                        self.window += 1;
                        self.squares = 0;
                        self.phase = if self.window == self.windows {
                            RSA_WEXP_OUT
                        } else {
                            RSA_WEXP_SQUARE
                        };
                    }
                }
                RSA_WEXP_OUT => {
                    let mut one = [0 as RsaLimb; RSA_HALF_LIMBS_MAX];
                    one[0] = 1;
                    let (u, done) =
                        self.mul
                            .step(m, &self.acc[..len], &one[..len], &mut self.tmp, left);
                    left -= u;
                    used += u;
                    if done {
                        out[..len].copy_from_slice(&self.tmp[..len]);
                        self.mul.start();
                        self.phase = RSA_WEXP_DONE;
                        return (used, true);
                    }
                }
                _ => return (used, true),
            }
        }
        (used, self.phase == RSA_WEXP_DONE)
    }

    fn zeroize(&mut self) {
        let mut k = 0;
        while k < RSA_TABLE {
            rsa_zeroize(&mut self.table[k]);
            k += 1;
        }
        rsa_zeroize(&mut self.acc);
        rsa_zeroize(&mut self.tmp);
        rsa_zeroize(&mut self.sel);
        rsa_zeroize(&mut self.mul.t);
    }
}

/// A private operation `em^d mod n` by CRT, stepped. The job holds its
/// own copies of nothing secret beyond the exponentiation state; the key
/// stays with its holder and is borrowed per step.
pub struct RsaSignJob {
    /// The encoded message, then the signature, as limbs of the modulus.
    m: [RsaLimb; RSA_LIMBS_MAX],
    /// The message reduced mod p (then the result mod p), and mod q.
    m1: [RsaLimb; RSA_HALF_LIMBS_MAX],
    m2: [RsaLimb; RSA_HALF_LIMBS_MAX],
    /// Reduction progress: bits of `m` consumed.
    reduce_bit: usize,
    exp: RsaWindowExp,
    mul: RsaMul,
    phase: u8,
    sig: [u8; RSA_BYTES_MAX],
    sig_len: usize,
}

impl RsaSignJob {
    pub const fn new() -> Self {
        Self {
            m: [0; RSA_LIMBS_MAX],
            m1: [0; RSA_HALF_LIMBS_MAX],
            m2: [0; RSA_HALF_LIMBS_MAX],
            reduce_bit: 0,
            exp: RsaWindowExp::new(),
            mul: RsaMul::new(),
            phase: RSA_SIGN_DONE,
            sig: [0; RSA_BYTES_MAX],
            sig_len: 0,
        }
    }

    /// Begin signing the encoded message `em` (modulus length, numerically
    /// below the modulus).
    pub fn start(&mut self, key: &RsaPrivateKey, em: &[u8]) -> bool {
        if !key.loaded || em.len() != key.n.byte_len() {
            return false;
        }
        rsa_from_be(em, &mut self.m);
        if rsa_lt_mask(&self.m, &key.n.n, key.n.len) == 0 {
            rsa_zeroize(&mut self.m);
            return false;
        }
        rsa_zeroize(&mut self.m1);
        rsa_zeroize(&mut self.m2);
        self.reduce_bit = 0;
        self.phase = RSA_SIGN_REDUCE_P;
        self.sig_len = key.n.byte_len();
        true
    }

    pub fn is_done(&self) -> bool {
        self.phase == RSA_SIGN_DONE
    }

    /// Reduce `m` mod `p` into `out` by a constant-time bit-serial fold,
    /// `units` bits at a time.
    fn reduce_step(
        m: &[RsaLimb],
        total_bits: usize,
        p: &RsaModulus,
        out: &mut [RsaLimb],
        at: &mut usize,
        units: usize,
    ) -> bool {
        let len = p.len;
        let mut k = 0;
        while k < units && *at < total_bits {
            let bit_index = total_bits - 1 - *at;
            let bit = (m[bit_index / RSA_LIMB_BITS] >> (bit_index % RSA_LIMB_BITS)) & 1;
            // out = 2*out + bit, then reduce once: out < p before, so
            // 2*out + 1 < 2p.
            let mut carry: RsaLimb = bit;
            let mut i = 0;
            while i < len {
                let next = out[i] >> (RSA_LIMB_BITS - 1);
                out[i] = (out[i] << 1) | carry;
                carry = next;
                i += 1;
            }
            let mut d = [0 as RsaLimb; RSA_LIMBS_MAX];
            let borrow = rsa_sub(&mut d[..len], out, &p.n[..len], len);
            let keep = rsa_mask(carry) | !rsa_mask(borrow);
            rsa_select(out, &d[..len], keep, len);
            *at += 1;
            k += 1;
        }
        *at >= total_bits
    }

    /// Spend up to `units` (bits while reducing, rows while
    /// exponentiating).
    pub fn step(&mut self, key: &RsaPrivateKey, units: usize) -> RsaStep {
        if !key.loaded {
            return RsaStep::Pending;
        }
        let mut left = units;
        let total_bits = key.n.len * RSA_LIMB_BITS;
        while left > 0 {
            match self.phase {
                RSA_SIGN_REDUCE_P => {
                    let before = self.reduce_bit;
                    let done = Self::reduce_step(
                        &self.m,
                        total_bits,
                        &key.p,
                        &mut self.m1,
                        &mut self.reduce_bit,
                        left,
                    );
                    left -= self.reduce_bit - before;
                    if done {
                        self.exp.start(&key.p, &self.m1);
                        self.phase = RSA_SIGN_EXP_P;
                    }
                }
                RSA_SIGN_EXP_P => {
                    let (u, done) = self.exp.step(&key.p, &key.dp, &mut self.m1, left);
                    left -= u;
                    if done {
                        self.reduce_bit = 0;
                        self.phase = RSA_SIGN_REDUCE_Q;
                    }
                }
                RSA_SIGN_REDUCE_Q => {
                    let before = self.reduce_bit;
                    let done = Self::reduce_step(
                        &self.m,
                        total_bits,
                        &key.q,
                        &mut self.m2,
                        &mut self.reduce_bit,
                        left,
                    );
                    left -= self.reduce_bit - before;
                    if done {
                        self.exp.start(&key.q, &self.m2);
                        self.phase = RSA_SIGN_EXP_Q;
                    }
                }
                RSA_SIGN_EXP_Q => {
                    let (u, done) = self.exp.step(&key.q, &key.dq, &mut self.m2, left);
                    left -= u;
                    if done {
                        self.mul.start();
                        self.phase = RSA_SIGN_COMBINE;
                    }
                }
                RSA_SIGN_COMBINE => {
                    // Garner: h = qInv * (m1 - m2) mod p; sig = m2 + h*q.
                    // m2 < q is folded mod p bit by bit (p and q need not
                    // be the same width), then subtracted from m1 mod p.
                    let lp = key.p.len;
                    let lq = key.q.len;
                    let mut t = [0 as RsaLimb; RSA_HALF_LIMBS_MAX];
                    let mut at = 0usize;
                    Self::reduce_step(
                        &self.m2,
                        lq * RSA_LIMB_BITS,
                        &key.p,
                        &mut t,
                        &mut at,
                        usize::MAX,
                    );
                    let mut diff = [0 as RsaLimb; RSA_HALF_LIMBS_MAX];
                    let borrow = rsa_sub(&mut diff[..lp], &self.m1[..lp], &t[..lp], lp);
                    // Where it borrowed, add p back.
                    let mut fixed = [0 as RsaLimb; RSA_HALF_LIMBS_MAX];
                    rsa_add(&mut fixed[..lp], &diff[..lp], &key.p.n[..lp], lp);
                    rsa_select(&mut diff[..lp], &fixed[..lp], rsa_mask(borrow), lp);
                    // h = diff * qInv (Montgomery form) * R^{-1} = diff*qInv.
                    let mut h = [0 as RsaLimb; RSA_HALF_LIMBS_MAX];
                    let (_, done) =
                        self.mul
                            .step(&key.p, &diff[..lp], &key.qinv_m[..lp], &mut h, left);
                    if !done {
                        // The product carries across steps in `mul`; the
                        // inputs are recomputed identically next time.
                        rsa_zeroize(&mut t);
                        rsa_zeroize(&mut diff);
                        rsa_zeroize(&mut fixed);
                        return RsaStep::Pending;
                    }
                    // sig = m2 + h * q.
                    let mut prod = [0 as RsaLimb; RSA_LIMBS_MAX + 1];
                    rsa_schoolbook_mul(&h[..lp], &key.q.n[..lq], &mut prod);
                    let ln = key.n.len;
                    let mut m2w = [0 as RsaLimb; RSA_LIMBS_MAX];
                    m2w[..lq].copy_from_slice(&self.m2[..lq]);
                    let mut sig = [0 as RsaLimb; RSA_LIMBS_MAX];
                    rsa_add(&mut sig[..ln], &prod[..ln], &m2w[..ln], ln);
                    rsa_to_be(&sig[..ln], &mut self.sig[..self.sig_len]);
                    rsa_zeroize(&mut t);
                    rsa_zeroize(&mut diff);
                    rsa_zeroize(&mut fixed);
                    rsa_zeroize(&mut h);
                    rsa_zeroize(&mut prod);
                    rsa_zeroize(&mut m2w);
                    rsa_zeroize(&mut sig);
                    rsa_zeroize(&mut self.m);
                    rsa_zeroize(&mut self.m1);
                    rsa_zeroize(&mut self.m2);
                    self.exp.zeroize();
                    self.phase = RSA_SIGN_DONE;
                    return RsaStep::Done;
                }
                _ => return RsaStep::Done,
            }
        }
        if self.phase == RSA_SIGN_DONE {
            RsaStep::Done
        } else {
            RsaStep::Pending
        }
    }

    /// The signature, big-endian, modulus length. Meaningful once `step`
    /// has answered `Done`.
    pub fn signature(&self) -> &[u8] {
        &self.sig[..self.sig_len]
    }

    pub fn zeroize(&mut self) {
        rsa_zeroize(&mut self.m);
        rsa_zeroize(&mut self.m1);
        rsa_zeroize(&mut self.m2);
        self.exp.zeroize();
        rsa_zeroize(&mut self.mul.t);
        rsa_zeroize_bytes(&mut self.sig);
        self.sig_len = 0;
        self.phase = RSA_SIGN_DONE;
    }
}

impl Default for RsaSignJob {
    fn default() -> Self {
        Self::new()
    }
}

/// Sign `mhash` with RSASSA-PSS in one call, running the job to
/// completion. `salt` is the caller's random of the hash length.
pub fn rsa_pss_sign(
    job: &mut RsaSignJob,
    key: &RsaPrivateKey,
    hash: RsaHash,
    mhash: &[u8],
    salt: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let k = key.n.byte_len();
    let mut em = [0u8; RSA_BYTES_MAX];
    if !rsa_pss_encode(hash, mhash, salt, &mut em[..k], key.n.bits()) {
        return None;
    }
    if !job.start(key, &em[..k]) {
        return None;
    }
    while job.step(key, usize::MAX) == RsaStep::Pending {}
    let sig = job.signature();
    if out.len() < sig.len() {
        return None;
    }
    out[..sig.len()].copy_from_slice(sig);
    Some(sig.len())
}
