// Resumable Ed25519 verification (RFC 8032 §5.1.7) for callers that run on
// a step budget: the TLS handshake pump (mounted by `tls` and `quic`) and
// `graph_slot`'s slot-signature check. Each mounts this file straight after
// `sdk/crypto/ed25519.rs`, whose field, point and scalar helpers it uses by
// bare name. It is module source rather than SDK source, so it sits outside
// the ABI surface digest.
//
// The job reaches the verdict `ed25519_verify` reaches, by the same checks:
// S < L; canonical (y < p), on-curve encodings of A and R; neither of small
// order; k = SHA-512(R ‖ A ‖ M) mod L over the encodings as received; and
// the cofactorless equation [S]B = R + [k]A. Only the order of work differs:
//
//   - `ed25519_verify_init` checks S and computes k, so the message need not
//     outlive the call;
//   - each point decode takes a setup step, then raises its square root's
//     exponent `ED_ROOT_BITS_PER_STEP` bits a step, the root's checks and
//     the small-order test riding on the last of those steps;
//   - the walk computes [S]B + [k](-A) by Straus–Shamir over the table
//     {B, -A, B - A}, `bits_per_step` bits of both scalars a step, one
//     doubling and at most one addition a bit;
//   - `ed25519_verify_finalise` compares the walk's point with R.
//
// A walk step costs at most 17 field products a bit (a doubling and an
// addition). A paced decode step costs at most about 100 whatever the pace:
// the heaviest is the last of A's, its final window with the root's checks,
// the small-order test and the walk table.
//
// Every input is public, so the job is variable-time, as `ed25519_verify`
// is. `tests/harness/tests/ed25519_kat.rs` holds the two to the same
// verdicts at every pace.

const ED_PHASE_DECODE_A: u8 = 0;
const ED_PHASE_DECODE_R: u8 = 1;
const ED_PHASE_WALK: u8 = 2;
const ED_PHASE_DONE: u8 = 3;
const ED_PHASE_FAILED: u8 = 4;

/// Exponent bits of a decode's square root raised per step. The exponent,
/// (p - 5)/8 = 2^252 - 3, is walked over all 256 bit positions: 256
/// squarings and 251 multiplications, eight steps of at most 64 field
/// products each.
const ED_ROOT_BITS_PER_STEP: u16 = 32;

/// A point decode in progress: `ge_frombytes_vartime` with its square root,
/// x = u·v³·(u·v⁷)^((p-5)/8), raised a window at a time. Same checks, same
/// answer.
struct EdDecode {
    y: Fe,
    u: Fe,
    v: Fe,
    v3: Fe,
    /// Right-to-left square-and-multiply state for (u·v⁷)^((p-5)/8).
    base: Fe,
    result: Fe,
    /// Next exponent bit, 0..256; 256 once raised.
    bit: u16,
    sign: u8,
    /// Whether a decode is under way.
    live: u8,
}

impl EdDecode {
    const fn idle() -> Self {
        Self {
            y: FE_ZERO,
            u: FE_ZERO,
            v: FE_ZERO,
            v3: FE_ZERO,
            base: FE_ZERO,
            result: FE_ONE,
            bit: 0,
            sign: 0,
            live: 0,
        }
    }

    /// The canonical-y check and the root's setup; `None` for a y ≥ p.
    fn begin(s: &[u8; 32]) -> Option<Self> {
        let mut y_limbs = sc_from_bytes_le(s);
        y_limbs[3] &= 0x7FFF_FFFF_FFFF_FFFF;
        if u256_gte(&y_limbs, &ed_load_p()) != 0 {
            return None;
        }
        let y = fe_frombytes(s);
        let yy = fe_sq(&y);
        let u = fe_sub(&yy, &FE_ONE);
        let v = fe_add(&fe_mul(&ed_load_d(), &yy), &FE_ONE);
        let v3 = fe_mul(&fe_sq(&v), &v);
        let v7 = fe_mul(&fe_sq(&v3), &v);
        Some(Self {
            y,
            u,
            v,
            v3,
            base: fe_mul(&u, &v7),
            result: FE_ONE,
            bit: 0,
            sign: (s[31] >> 7) & 1,
            live: 1,
        })
    }

    /// Raise up to `bits` more exponent bits; true once the root is raised.
    fn raise(&mut self, bits: u16) -> bool {
        let e = ed_load_p58();
        let mut left = bits;
        while left > 0 && self.bit < 256 {
            let b = self.bit as usize;
            if (e[b / 64] >> (b % 64)) & 1 == 1 {
                self.result = fe_mul(&self.result, &self.base);
            }
            self.base = fe_sq(&self.base);
            self.bit += 1;
            left -= 1;
        }
        self.bit >= 256
    }

    /// The root's checks and the point, as `ge_frombytes_vartime` ends.
    fn finish(&self) -> Option<GeP3> {
        let mut x = fe_mul(&fe_mul(&self.u, &self.v3), &self.result);
        let vxx = fe_mul(&self.v, &fe_sq(&x));
        if !fe_eq(&vxx, &self.u) {
            if fe_eq(&vxx, &fe_neg(&self.u)) {
                x = fe_mul(&x, &ed_load_sqrtm1());
            } else {
                return None;
            }
        }
        if fe_iszero(&x) {
            if self.sign == 1 {
                return None;
            }
        } else if fe_isnegative(&x) != (self.sign == 1) {
            x = fe_neg(&x);
        }
        let t = fe_mul(&x, &self.y);
        Some(GeP3 {
            x,
            y: self.y,
            z: FE_ONE,
            t,
        })
    }
}

/// What one decode step came to.
enum EdDecoded {
    /// More of the root is still to raise.
    Pending,
    /// The encoding decoded to a point not of small order.
    Point(GeP3),
    /// The encoding is refused.
    Refused,
}

/// One decode step for `enc`: begin, raise a window, or finish. `whole`
/// does the decode in this one call.
fn ed_decode_step(dec: &mut EdDecode, enc: &[u8; 32], whole: bool) -> EdDecoded {
    if dec.live == 0 {
        match EdDecode::begin(enc) {
            Some(started) => *dec = started,
            None => return EdDecoded::Refused,
        }
        if !whole {
            return EdDecoded::Pending;
        }
    }
    let bits = if whole { 256 } else { ED_ROOT_BITS_PER_STEP };
    if !dec.raise(bits) {
        return EdDecoded::Pending;
    }
    let point = dec.finish();
    *dec = EdDecode::idle();
    match point {
        Some(p) if !ge_is_small_order(&p) => EdDecoded::Point(p),
        _ => EdDecoded::Refused,
    }
}

/// The walk's table for a decoded A: B, -A and B - A, the points a pair of
/// scalar bits (1,0), (0,1) and (1,1) adds.
fn ed_walk_table(a: &GeP3) -> [GeP3; 3] {
    let bx = ed_load_bx();
    let by = ed_load_by();
    let b = GeP3 {
        x: bx,
        y: by,
        z: FE_ONE,
        t: fe_mul(&bx, &by),
    };
    let neg_a = GeP3 {
        x: fe_neg(&a.x),
        y: a.y,
        z: a.z,
        t: fe_neg(&a.t),
    };
    let b_minus_a = ge_add(&b, &neg_a);
    [b, neg_a, b_minus_a]
}

/// One Ed25519 verification, decided across `step` calls.
pub struct Ed25519VerifyJob {
    a_enc: [u8; 32],
    r_enc: [u8; 32],
    s: [u8; 32],
    k: [u8; 32],
    /// Decoded R, compared at the end.
    r: GeP3,
    /// B, -A and B - A (`ed_walk_table`).
    table: [GeP3; 3],
    acc: GeP3,
    /// The point decode under way, A's then R's.
    dec: EdDecode,
    /// Next scalar bit to walk, 255 down to 0; -1 once walked.
    bit: i16,
    phase: u8,
    /// Walk bits per `step`; 0 runs each decode and the whole walk in one
    /// call apiece.
    bits_per_step: u8,
}

impl Ed25519VerifyJob {
    /// A job with nothing to verify: `step` reports it decided and
    /// `ed25519_verify_finalise` refuses it.
    pub const fn empty() -> Self {
        Self {
            a_enc: [0; 32],
            r_enc: [0; 32],
            s: [0; 32],
            k: [0; 32],
            r: GeP3::identity(),
            table: [GeP3::identity(), GeP3::identity(), GeP3::identity()],
            acc: GeP3::identity(),
            dec: EdDecode::idle(),
            bit: 255,
            phase: ED_PHASE_FAILED,
            bits_per_step: 0,
        }
    }

    /// Set how many walk bits each later `step` does, for a caller that
    /// learns its budget only after the job was begun.
    pub fn pace(&mut self, bits_per_step: u8) {
        self.bits_per_step = bits_per_step;
    }

    /// Do the next unit of work. True once the job is decided, whichever
    /// way: `ed25519_verify_finalise` says which.
    pub fn step(&mut self) -> bool {
        let whole = self.bits_per_step == 0;
        match self.phase {
            ED_PHASE_DECODE_A | ED_PHASE_DECODE_R => {
                let decoding_a = self.phase == ED_PHASE_DECODE_A;
                let enc = if decoding_a { &self.a_enc } else { &self.r_enc };
                match ed_decode_step(&mut self.dec, enc, whole) {
                    EdDecoded::Pending => false,
                    EdDecoded::Point(p) => {
                        if decoding_a {
                            self.table = ed_walk_table(&p);
                            self.phase = ED_PHASE_DECODE_R;
                        } else {
                            self.r = p;
                            self.phase = ED_PHASE_WALK;
                        }
                        false
                    }
                    EdDecoded::Refused => {
                        self.phase = ED_PHASE_FAILED;
                        true
                    }
                }
            }
            ED_PHASE_WALK => {
                let mut budget: u16 = if whole {
                    256
                } else {
                    self.bits_per_step as u16
                };
                while budget > 0 && self.bit >= 0 {
                    let i = self.bit as usize;
                    let sb = (self.s[i / 8] >> (i % 8)) & 1;
                    let kb = (self.k[i / 8] >> (i % 8)) & 1;
                    self.acc = ge_double(&self.acc);
                    match (sb, kb) {
                        (1, 0) => self.acc = ge_add(&self.acc, &self.table[0]),
                        (0, 1) => self.acc = ge_add(&self.acc, &self.table[1]),
                        (1, 1) => self.acc = ge_add(&self.acc, &self.table[2]),
                        _ => {}
                    }
                    self.bit -= 1;
                    budget -= 1;
                }
                if self.bit < 0 {
                    self.phase = ED_PHASE_DONE;
                    return true;
                }
                false
            }
            _ => true,
        }
    }
}

/// Begin verifying `signature` (R ‖ S) over `message` under `public_key`,
/// walking `bits_per_step` bits a step (0: each phase whole). S must be
/// below the group order, and k = SHA-512(R ‖ A ‖ M) mod L is taken here
/// over the encodings as received, so the message need not outlive this
/// call. `None` for an S that is not canonical; a point that does not
/// decode, or is of small order, fails the job when its step comes.
pub fn ed25519_verify_init(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
    bits_per_step: u8,
) -> Option<Ed25519VerifyJob> {
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..64]);
    if u256_gte(&sc_from_bytes_le(&s_bytes), &ed_load_l()) != 0 {
        return None;
    }
    let mut r_enc = [0u8; 32];
    r_enc.copy_from_slice(&signature[0..32]);
    let mut hk = Sha512::new();
    hk.update(&r_enc);
    hk.update(public_key);
    hk.update(message);
    let k = sc_from_hash(&hk.finalize());
    let mut job = Ed25519VerifyJob::empty();
    job.a_enc = *public_key;
    job.r_enc = r_enc;
    job.s = s_bytes;
    job.k = sc_to_bytes_le(&k);
    job.phase = ED_PHASE_DECODE_A;
    job.bits_per_step = bits_per_step;
    Some(job)
}

/// Whether a decided job's signature verifies: [S]B - [k]A equals R,
/// compared as projective points (X1·Z2 = X2·Z1 and Y1·Z2 = Y2·Z1, every Z
/// nonzero under the complete addition law), so no inversion. False for a
/// job that failed or is not yet decided.
pub fn ed25519_verify_finalise(job: &Ed25519VerifyJob) -> bool {
    if job.phase != ED_PHASE_DONE {
        return false;
    }
    let p = &job.acc;
    let r = &job.r;
    fe_eq(&fe_mul(&p.x, &r.z), &fe_mul(&r.x, &p.z))
        && fe_eq(&fe_mul(&p.y, &r.z), &fe_mul(&r.y, &p.z))
}
