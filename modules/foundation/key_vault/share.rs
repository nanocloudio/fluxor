// ── Recovery shares ─────────────────────────────────────────────────────
//
// 2-of-3 Shamir over GF(2^8) and the envelope that seals one share to one
// recipient. A 32-byte key is split bytewise with the AES field polynomial
// `x^8 + x^4 + x^3 + x + 1`, share indices 1, 2 and 3, and one independent
// random coefficient per byte. Every operation on secret bytes runs in
// constant time; only the share indices, which are public, choose a path.
// A 32-byte key leaves this vault only as shares sealed to their
// recipients, and comes back only into a handle.

pub mod key_share {
    use super::{derive_key, p256, zeroize, Sha256};
    use abi::contracts::key_vault::share as env;
    use fluxor_abi as abi;

    /// Multiply in GF(2^8), constant time.
    fn gf_mul(a: u8, b: u8) -> u8 {
        let mut a = a;
        let mut b = b;
        let mut p = 0u8;
        let mut i = 0;
        while i < 8 {
            p ^= a & 0u8.wrapping_sub(b & 1);
            let carry = 0u8.wrapping_sub(a >> 7);
            a = (a << 1) ^ (0x1B & carry);
            b >>= 1;
            i += 1;
        }
        p
    }

    /// Inverse in GF(2^8) of a public, non-zero element: `a^254`.
    fn gf_inv(a: u8) -> u8 {
        let mut r = 1u8;
        let mut i = 0;
        while i < 254 {
            r = gf_mul(r, a);
            i += 1;
        }
        r
    }

    /// Split `secret` into shares for indices 1, 2 and 3 with `coeff` as the
    /// per-byte random coefficient: `y_i = secret ^ coeff·i`.
    pub fn split(secret: &[u8; 32], coeff: &[u8; 32], shares: &mut [[u8; 32]; 3]) {
        for (s, share) in shares.iter_mut().enumerate() {
            let x = s as u8 + 1;
            for j in 0..32 {
                share[j] = secret[j] ^ gf_mul(coeff[j], x);
            }
        }
    }

    /// Reconstruct from two shares with distinct non-zero indices: Lagrange
    /// interpolation at 0. `None` for a repeated or zero index.
    pub fn combine(xa: u8, ya: &[u8; 32], xb: u8, yb: &[u8; 32], out: &mut [u8; 32]) -> Option<()> {
        if xa == 0 || xb == 0 || xa == xb {
            return None;
        }
        // l_a(0) = x_b / (x_a - x_b), l_b(0) = x_a / (x_a - x_b); subtraction is
        // XOR in characteristic 2.
        let d = gf_inv(xa ^ xb);
        let la = gf_mul(xb, d);
        let lb = gf_mul(xa, d);
        for j in 0..32 {
            out[j] = gf_mul(ya[j], la) ^ gf_mul(yb[j], lb);
        }
        Some(())
    }

    /// SHA-256 of a public key: how an envelope names its recipient.
    pub fn thumbprint(public: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(public);
        h.finalize()
    }

    /// The fields an envelope binds besides its share.
    pub struct Binding<'a> {
        pub aead: u16,
        pub purpose: u8,
        pub set_id: &'a [u8],
        pub resource: &'a [u8],
        pub epoch: u32,
        pub fence: u64,
        pub expiry_ms: u64,
        pub policy: &'a [u8],
    }

    /// Whether this vault can seal an envelope under `aead`.
    pub fn aead_supported(aead: u16) -> bool {
        match aead {
            env::aead::CHACHA20_POLY1305 => true,
            env::aead::AES_256_GCM => fluxor_sdk::crypto::aes_gcm::AES_IS_CONSTANT_TIME,
            _ => false,
        }
    }

    /// Seal under a zero nonce. Every envelope's key is derived from a fresh
    /// ephemeral agreement and the envelope's own header, so no key ever seals
    /// twice.
    fn aead_seal(aead: u16, key: &[u8; 32], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
        let nonce = [0u8; 12];
        if aead == env::aead::AES_256_GCM {
            fluxor_sdk::crypto::aes_gcm::AesGcm::new_256(key).encrypt(&nonce, aad, data)
        } else {
            fluxor_sdk::crypto::chacha20::chacha20_poly1305_encrypt(key, &nonce, aad, data)
        }
    }

    fn aead_open(aead: u16, key: &[u8; 32], aad: &[u8], data: &mut [u8], tag: &[u8; 16]) -> bool {
        let nonce = [0u8; 12];
        if aead == env::aead::AES_256_GCM {
            fluxor_sdk::crypto::aes_gcm::AesGcm::new_256(key).decrypt(&nonce, aad, data, tag)
        } else {
            fluxor_sdk::crypto::chacha20::chacha20_poly1305_decrypt(key, &nonce, aad, data, tag)
        }
    }

    /// Seal share `index ‖ y` to `recipient` (an uncompressed P-256 public
    /// key) into `out`, which is [`env::P256_LEN`] bytes. `anti_replay` is
    /// fresh per envelope and `eph` a fresh P-256 scalar, the envelope's
    /// ephemeral key. `false` if the recipient is not a valid point or
    /// entropy fails.
    pub fn seal(
        out: &mut [u8; env::P256_LEN],
        b: &Binding<'_>,
        index: u8,
        y: &[u8; 32],
        recipient: &[u8],
        anti_replay: &[u8; 16],
        mut eph: [u8; 32],
    ) -> bool {
        if recipient.len() != env::P256_PUB_LEN || !p256::public_point_is_valid(recipient) {
            zeroize(&mut eph);
            return false;
        }
        let eph_pub = p256::public_key_from_scalar(&eph);
        let shared = p256::ecdh_shared_secret(&eph, recipient);
        zeroize(&mut eph);
        let (Some(eph_pub), Some(mut shared)) = (eph_pub, shared) else {
            return false;
        };
        out.fill(0);
        out[..4].copy_from_slice(&env::MAGIC);
        out[env::KEM..env::KEM + 2].copy_from_slice(&env::kem::P256.to_le_bytes());
        out[env::AEAD..env::AEAD + 2].copy_from_slice(&b.aead.to_le_bytes());
        out[env::PURPOSE] = b.purpose;
        out[env::INDEX] = index;
        out[env::THRESHOLD] = env::THRESHOLD_V1;
        out[env::COUNT] = env::COUNT_V1;
        out[env::SET_ID..env::SET_ID + 16].copy_from_slice(b.set_id);
        out[env::RESOURCE..env::RESOURCE + 16].copy_from_slice(b.resource);
        out[env::EPOCH..env::EPOCH + 4].copy_from_slice(&b.epoch.to_le_bytes());
        out[env::RECIPIENT..env::RECIPIENT + 32].copy_from_slice(&thumbprint(recipient));
        out[env::FENCE..env::FENCE + 8].copy_from_slice(&b.fence.to_le_bytes());
        out[env::EXPIRY..env::EXPIRY + 8].copy_from_slice(&b.expiry_ms.to_le_bytes());
        out[env::ANTI_REPLAY..env::ANTI_REPLAY + 16].copy_from_slice(anti_replay);
        out[env::POLICY..env::POLICY + 32].copy_from_slice(b.policy);
        out[env::ENC_LEN..env::ENC_LEN + 2]
            .copy_from_slice(&(env::P256_PUB_LEN as u16).to_le_bytes());
        out[env::ENC..env::ENC + env::P256_PUB_LEN].copy_from_slice(&eph_pub);
        let hdr = env::ENC + env::P256_PUB_LEN;
        let mut k = [0u8; 32];
        derive_key(&shared, b"share/envelope", &out[..hdr], &mut k);
        zeroize(&mut shared);
        let Some((head, body)) = out.split_at_mut_checked(hdr) else {
            return false;
        };
        let ct = &mut body[..env::SHARE_LEN];
        ct[0] = index;
        ct[1..].copy_from_slice(y);
        let tag = aead_seal(b.aead, &k, head, ct);
        zeroize(&mut k);
        body[env::SHARE_LEN..].copy_from_slice(&tag);
        true
    }

    /// An envelope binding as a split or rewrap argument carries it
    /// (`share::grant`).
    #[derive(Clone, Copy)]
    pub struct Grant {
        pub aead: u16,
        pub purpose: u8,
        pub set_id: [u8; 16],
        pub resource: [u8; 16],
        pub epoch: u32,
        pub fence: u64,
        pub expiry_ms: u64,
        pub policy: [u8; 32],
    }

    impl Grant {
        /// Read the `share::grant` layout from the front of `b`, which is at
        /// least `share::grant::LEN` bytes.
        pub fn read(b: &[u8]) -> Self {
            use abi::contracts::key_vault::share::grant as g;
            let mut set_id = [0u8; 16];
            set_id.copy_from_slice(&b[g::SET_ID..g::SET_ID + 16]);
            let mut resource = [0u8; 16];
            resource.copy_from_slice(&b[g::RESOURCE..g::RESOURCE + 16]);
            let mut policy = [0u8; 32];
            policy.copy_from_slice(&b[g::POLICY..g::POLICY + 32]);
            Self {
                aead: u16::from_le_bytes([b[g::AEAD], b[g::AEAD + 1]]),
                purpose: b[g::PURPOSE],
                set_id,
                resource,
                epoch: u32::from_le_bytes([
                    b[g::EPOCH],
                    b[g::EPOCH + 1],
                    b[g::EPOCH + 2],
                    b[g::EPOCH + 3],
                ]),
                fence: field_u64(b, g::FENCE),
                expiry_ms: field_u64(b, g::EXPIRY),
                policy,
            }
        }

        /// Whether this vault can seal an envelope under this grant.
        pub fn valid(&self) -> bool {
            aead_supported(self.aead)
                && matches!(
                    self.purpose,
                    env::purpose::ATTACHMENT | env::purpose::RECOVERY
                )
        }

        /// This grant, carrying over what the share in `envelope` IS: its set,
        /// resource, epoch and AEAD.
        pub fn carrying(&self, envelope: &[u8]) -> Self {
            let mut g = *self;
            g.set_id
                .copy_from_slice(&envelope[env::SET_ID..env::SET_ID + 16]);
            g.resource
                .copy_from_slice(&envelope[env::RESOURCE..env::RESOURCE + 16]);
            g.epoch = u32::from_le_bytes([
                envelope[env::EPOCH],
                envelope[env::EPOCH + 1],
                envelope[env::EPOCH + 2],
                envelope[env::EPOCH + 3],
            ]);
            g.aead = aead_of(envelope);
            g
        }

        pub fn binding(&self) -> Binding<'_> {
            Binding {
                aead: self.aead,
                purpose: self.purpose,
                set_id: &self.set_id,
                resource: &self.resource,
                epoch: self.epoch,
                fence: self.fence,
                expiry_ms: self.expiry_ms,
                policy: &self.policy,
            }
        }
    }

    /// Why an envelope did not open.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum OpenError {
        /// Not a well-formed v1 envelope, or its tag does not verify.
        Malformed,
        /// Wrapped to another recipient than the opener.
        NotRecipient,
    }

    /// The envelope's encapsulation: what the recipient agrees against.
    pub fn encapsulation(envelope: &[u8]) -> &[u8] {
        &envelope[env::ENC..env::ENC + env::P256_PUB_LEN]
    }

    /// Open `envelope` given the recipient's agreement with its encapsulation
    /// (`shared`) and the recipient's public key. On success the share's `y` is
    /// in `y_out` and the (authenticated) index is returned.
    ///
    /// The agreement is an argument rather than a private key so that a
    /// recipient key held in any backend can open an envelope.
    pub fn open(
        envelope: &[u8],
        shared: &[u8; 32],
        recipient_pub: &[u8],
        y_out: &mut [u8; 32],
    ) -> Result<u8, OpenError> {
        if !well_formed(envelope) {
            return Err(OpenError::Malformed);
        }
        if thumbprint(recipient_pub) != envelope[env::RECIPIENT..env::RECIPIENT + 32] {
            return Err(OpenError::NotRecipient);
        }
        let hdr = env::ENC + env::P256_PUB_LEN;
        let mut k = [0u8; 32];
        derive_key(shared, b"share/envelope", &envelope[..hdr], &mut k);
        let mut ct = [0u8; env::SHARE_LEN];
        ct.copy_from_slice(&envelope[hdr..hdr + env::SHARE_LEN]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&envelope[hdr + env::SHARE_LEN..]);
        let ok = aead_open(aead_of(envelope), &k, &envelope[..hdr], &mut ct, &tag);
        zeroize(&mut k);
        // The sealed index must be the header's: the header is what the pairing
        // checks read.
        if !ok || ct[0] != envelope[env::INDEX] {
            zeroize(&mut ct);
            return Err(OpenError::Malformed);
        }
        y_out.copy_from_slice(&ct[1..]);
        zeroize(&mut ct);
        Ok(envelope[env::INDEX])
    }

    /// The envelope's AEAD suite id.
    pub fn aead_of(envelope: &[u8]) -> u16 {
        u16::from_le_bytes([envelope[env::AEAD], envelope[env::AEAD + 1]])
    }

    /// Whether `envelope` has the shape of a v1 P-256 envelope this vault can
    /// open: magic, KEM, AEAD, threshold, count, index and length.
    pub fn well_formed(envelope: &[u8]) -> bool {
        envelope.len() == env::P256_LEN
            && envelope[..4] == env::MAGIC
            && u16::from_le_bytes([envelope[env::KEM], envelope[env::KEM + 1]]) == env::kem::P256
            && u16::from_le_bytes([envelope[env::ENC_LEN], envelope[env::ENC_LEN + 1]]) as usize
                == env::P256_PUB_LEN
            && aead_supported(aead_of(envelope))
            && envelope[env::THRESHOLD] == env::THRESHOLD_V1
            && envelope[env::COUNT] == env::COUNT_V1
            && (1..=env::COUNT_V1).contains(&envelope[env::INDEX])
            && matches!(
                envelope[env::PURPOSE],
                env::purpose::ATTACHMENT | env::purpose::RECOVERY
            )
    }

    /// Read a little-endian `u64` field.
    pub fn field_u64(envelope: &[u8], off: usize) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&envelope[off..off + 8]);
        u64::from_le_bytes(b)
    }
}

/// Suites a share split may carry, and a reconstruction may yield.
const fn splittable(suite: u16) -> bool {
    matches!(
        suite,
        kv::suite::KDF_KEY | kv::suite::AEAD_KEY | kv::suite::AEAD_AES256_GCM
    )
}

/// Whether a reconstructed key of `suite` with `usage` may be made: a
/// 32-byte symmetric suite, uses it has, never persisted.
const fn session_key_admissible(suite: u16, usage: u32) -> bool {
    splittable(suite)
        && suite_private_len(suite) == 32
        && usage != 0
        && usage & !suite_usage(suite) == 0
        && usage & kv::usage::PERSIST == 0
}

/// A fresh anti-replay id.
fn anti_replay_id(s: &State) -> Option<[u8; 16]> {
    let mut id = [0u8; 16];
    random(s, &mut id).then_some(id)
}

/// A fresh P-256 scalar in [1, n-1].
fn random_p256_scalar(s: &State) -> Option<[u8; 32]> {
    let mut k = [0u8; 32];
    if generate_into(s, kv::suite::P256, &mut k) {
        Some(k)
    } else {
        zeroize(&mut k);
        None
    }
}

// ── Consumed envelopes ──
//
// An envelope reconstructs a key once: this ring holds the anti-replay ids
// of the last `consumed` envelopes a reconstruction used.

fn consumed_ring(s: &mut State) -> &mut [[u8; 16]] {
    // SAFETY: `consumed` names `n_consumed` entries of this instance's heap.
    unsafe { core::slice::from_raw_parts_mut(s.consumed, usize::from(s.n_consumed)) }
}

fn consumed(s: &mut State, id: &[u8]) -> bool {
    let live = usize::from(s.consumed_live);
    consumed_ring(s).iter().take(live).any(|c| c[..] == *id)
}

fn consume(s: &mut State, id: &[u8]) {
    let next = usize::from(s.consumed_next);
    consumed_ring(s)[next].copy_from_slice(id);
    s.consumed_next = ((next + 1) % usize::from(s.n_consumed)) as u16;
    if s.consumed_live < s.n_consumed {
        s.consumed_live += 1;
    }
}

/// `SHARE_SPLIT`: the key of slot `i` as three envelopes, one per
/// recipient, or none.
fn share_split(s: &mut State, i: usize, arg: &[u8], out: &mut [u8]) -> i32 {
    use kv::share::{self as sh, split as a};
    if arg.len() < a::ARG_LEN {
        return EINVAL;
    }
    let sl = slots(s)[i];
    if !splittable(sl.suite) || sl.key_len != 32 {
        return EINVAL;
    }
    if !sl.permits(kv::usage::WRAP) {
        return EACCES;
    }
    let grant = key_share::Grant::read(&arg[..sh::grant::LEN]);
    if !grant.valid() {
        return EINVAL;
    }
    if out.len() < a::OUT_LEN {
        return ERANGE;
    }
    let out = &mut out[..a::OUT_LEN];
    let recipients = &arg[a::RECIPIENTS..a::ARG_LEN];
    let mut coeff = [0u8; 32];
    if !random(s, &mut coeff) {
        return ERROR;
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&sl.data[..32]);
    let mut shares = [[0u8; 32]; 3];
    key_share::split(&secret, &coeff, &mut shares);
    zeroize(&mut secret);
    zeroize(&mut coeff);
    let mut envelope = [0u8; sh::P256_LEN];
    let binding = grant.binding();
    let mut rc = a::OUT_LEN as i32;
    for (k, share) in shares.iter().enumerate() {
        let recipient = &recipients[k * sh::P256_PUB_LEN..(k + 1) * sh::P256_PUB_LEN];
        let sealed = match (anti_replay_id(s), random_p256_scalar(s)) {
            (Some(id), Some(eph)) => key_share::seal(
                &mut envelope,
                &binding,
                k as u8 + 1,
                share,
                recipient,
                &id,
                eph,
            ),
            _ => false,
        };
        if !sealed {
            rc = EINVAL;
            break;
        }
        out[k * sh::P256_LEN..(k + 1) * sh::P256_LEN].copy_from_slice(&envelope);
    }
    for share in shares.iter_mut() {
        zeroize(share);
    }
    if rc < 0 {
        // No partial set.
        out.fill(0);
    }
    rc
}

/// `Ok` when an envelope has no expiry or has not reached it. An expiry
/// with no wall clock, or a clock the platform knows is unsynchronised, is
/// refused: an unchecked grant is not one.
fn unexpired(s: &State, envelope: &[u8]) -> Result<(), i32> {
    use abi::kernel_abi::trusted_time as tt;
    let expiry = key_share::field_u64(envelope, kv::share::EXPIRY);
    if expiry == 0 {
        return Ok(());
    }
    // SAFETY: read-only kernel queries.
    let (now, trusted) = unsafe { (dev_unix_millis(s.sys()), dev_trusted_unix(s.sys())) };
    let class = trusted[tt::OFF_SOURCE_CLASS];
    let synced = trusted[tt::OFF_FLAGS] & tt::flags::SYNCHRONIZED != 0;
    if now == 0 || (class >= tt::source::NETWORK_SYNC && !synced) {
        return Err(EACCES);
    }
    if now >= expiry {
        Err(EACCES)
    } else {
        Ok(())
    }
}

/// ECDH on `opener` against `peer`, with the opener's public key: the
/// agreement a share envelope opens under, in whichever custody holds it.
/// The secret lands in `shared` and nowhere else.
fn agree(
    s: &mut State,
    jk: &JobKey,
    opener: usize,
    peer: &[u8],
    shared: &mut [u8; 32],
) -> Result<[u8; 65], i32> {
    let sl = slots(s)[opener];
    #[cfg(not(target_arch = "arm"))]
    if sl.flags & FLAG_TOKEN != 0 {
        return token_agree(s, jk, opener, peer, shared);
    }
    #[cfg(target_arch = "arm")]
    let _ = jk;
    if sl.suite != kv::suite::P256 || sl.key_len != 32 {
        return Err(EINVAL);
    }
    if !sl.permits(kv::usage::AGREE) || !sl.permits(kv::usage::EXPORT_PUBLIC) {
        return Err(EACCES);
    }
    let mut public = [0u8; 65];
    if !write_public(s, opener, &mut public) {
        return Err(ERROR);
    }
    let mut priv_key = [0u8; 32];
    priv_key.copy_from_slice(&sl.data[..32]);
    let r = p256::ecdh_shared_secret(&priv_key, peer);
    zeroize(&mut priv_key);
    match r {
        Some(mut x) => {
            shared.copy_from_slice(&x);
            zeroize(&mut x);
            Ok(public)
        }
        None => Err(EINVAL),
    }
}

/// Open `envelope` with `opener`: the share's index and `y`.
fn open_share(
    s: &mut State,
    jk: &JobKey,
    opener: usize,
    envelope: &[u8],
    y: &mut [u8; 32],
) -> Result<u8, i32> {
    if !key_share::well_formed(envelope) {
        return Err(EINVAL);
    }
    let mut shared = [0u8; 32];
    let public = agree(
        s,
        jk,
        opener,
        key_share::encapsulation(envelope),
        &mut shared,
    )?;
    let opened = key_share::open(envelope, &shared, &public, y);
    zeroize(&mut shared);
    opened.map_err(|e| match e {
        key_share::OpenError::NotRecipient => EACCES,
        key_share::OpenError::Malformed => EINVAL,
    })
}

/// `SHARE_REWRAP`: the envelope in `data`, opened with `opener`, sealed to
/// another recipient.
fn share_rewrap(s: &mut State, opener: i32, args: &[u8], data: &mut [u8]) -> i32 {
    use kv::share::{self as sh, rewrap as a};
    if args.len() < a::ARG_LEN || data.len() < sh::P256_LEN {
        return EINVAL;
    }
    let jk = job_key(s, kv::SHARE_REWRAP, opener, args, data);
    let o = match resolve(s, opener) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let grant = key_share::Grant::read(&args[..sh::grant::LEN]);
    if !grant.valid() {
        return EINVAL;
    }
    let mut envelope = [0u8; sh::P256_LEN];
    envelope.copy_from_slice(&data[..sh::P256_LEN]);
    let recipient = &args[a::RECIPIENT..a::RECIPIENT + sh::P256_PUB_LEN];
    let mut y = [0u8; 32];
    let index = match open_share(s, &jk, o, &envelope, &mut y) {
        Ok(ix) => ix,
        Err(e) => return token_settle(s, &jk, e),
    };
    token_done(s, &jk);
    if let Err(e) = unexpired(s, &envelope) {
        zeroize(&mut y);
        return e;
    }
    let carried = grant.carrying(&envelope);
    let mut out = [0u8; sh::P256_LEN];
    let sealed = match (anti_replay_id(s), random_p256_scalar(s)) {
        (Some(id), Some(eph)) => {
            key_share::seal(&mut out, &carried.binding(), index, &y, recipient, &id, eph)
        }
        _ => false,
    };
    zeroize(&mut y);
    if !sealed {
        return EINVAL;
    }
    data[..sh::P256_LEN].copy_from_slice(&out);
    sh::P256_LEN as i32
}

// ── Reconstruction, one envelope per call ──
//
// `SHARE_COMBINE` opens one envelope per call. The first share is held here
// for its caller until the second arrives, a refusal drops it, or its
// caller's occupancy ends.

/// Callers that may hold a first share at once.
const MAX_HELD: usize = 4;

#[repr(C)]
#[derive(Clone, Copy)]
struct HeldShare {
    /// The caller's occupancy; all-0xFF for a free entry.
    owner: [u8; 8],
    used: u8,
    index: u8,
    aead: [u8; 2],
    epoch: [u8; 4],
    suite: u16,
    _pad: u16,
    usage: u32,
    set_id: [u8; 16],
    resource: [u8; 16],
    anti_replay: [u8; 16],
    y: [u8; 32],
}

impl HeldShare {
    const fn empty() -> Self {
        Self {
            owner: [0xFF; 8],
            used: 0,
            index: 0,
            aead: [0; 2],
            epoch: [0; 4],
            suite: 0,
            _pad: 0,
            usage: 0,
            set_id: [0; 16],
            resource: [0; 16],
            anti_replay: [0; 16],
            y: [0; 32],
        }
    }

    fn clear(&mut self) {
        zeroize(&mut self.y);
        *self = Self::empty();
    }
}

/// Shares held for occupancies that have ended are nobody's.
fn share_owner_released(s: &mut State) {
    for k in 0..MAX_HELD {
        let h = s.held[k];
        if h.used != 0 && !occupancy_live(s, &h.owner) {
            s.held[k].clear();
        }
    }
}

/// `SHARE_COMBINE`.
fn share_combine(s: &mut State, opener: i32, args: &[u8], env: &[u8]) -> i32 {
    let jk = job_key(s, kv::SHARE_COMBINE, opener, args, env);
    let Some(who) = caller(s) else {
        return EINVAL;
    };
    share_owner_released(s);
    let mine = s
        .held
        .iter()
        .position(|h| h.used != 0 && h.owner == who.occupancy);
    let rc = combine_step(s, &jk, opener, args, env, who, mine);
    if rc == EAGAIN {
        return rc;
    }
    token_done(s, &jk);
    // A refusal drops the share held; a reconstruction spends it.
    if rc != EINPROGRESS {
        if let Some(m) = mine {
            s.held[m].clear();
        }
    }
    rc
}

/// One `SHARE_COMBINE` call: hold the first share (`EINPROGRESS`), or
/// reconstruct from the share held and this one.
fn combine_step(
    s: &mut State,
    jk: &JobKey,
    opener: i32,
    args: &[u8],
    env: &[u8],
    who: Caller,
    mine: Option<usize>,
) -> i32 {
    use kv::share::{self as sh, combine as a};
    if args.len() < a::ARG_LEN {
        return EINVAL;
    }
    let suite = u16::from_le_bytes([args[a::TARGET_SUITE], args[a::TARGET_SUITE + 1]]);
    let usage = u32::from_le_bytes([
        args[a::TARGET_USAGE],
        args[a::TARGET_USAGE + 1],
        args[a::TARGET_USAGE + 2],
        args[a::TARGET_USAGE + 3],
    ]);
    if !session_key_admissible(suite, usage) {
        return EINVAL;
    }
    if !key_share::well_formed(env) {
        return EINVAL;
    }
    if env[sh::RESOURCE..sh::RESOURCE + 16] != args[a::RESOURCE..a::RESOURCE + 16]
        || env[sh::EPOCH..sh::EPOCH + 4] != args[a::EPOCH..a::EPOCH + 4]
    {
        return EACCES;
    }
    if let Err(e) = unexpired(s, env) {
        return e;
    }
    if consumed(s, &env[sh::ANTI_REPLAY..sh::ANTI_REPLAY + 16]) {
        return EACCES;
    }
    let pairs = mine.map(|m| {
        let h = &s.held[m];
        h.set_id[..] == env[sh::SET_ID..sh::SET_ID + 16]
            && h.resource[..] == env[sh::RESOURCE..sh::RESOURCE + 16]
            && h.epoch[..] == env[sh::EPOCH..sh::EPOCH + 4]
            && h.aead[..] == env[sh::AEAD..sh::AEAD + 2]
            && h.suite == suite
            && h.usage == usage
    });
    if pairs == Some(true) && s.held[mine.unwrap_or(0)].index == env[sh::INDEX] {
        return EINVAL;
    }
    let o = match resolve(s, opener) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let mut y = [0u8; 32];
    let index = match open_share(s, jk, o, env, &mut y) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let Some(m) = mine.filter(|_| pairs == Some(true)) else {
        // A first share, or one of another set than the share held: held,
        // replacing whatever this caller held.
        let Some(k) = mine.or_else(|| s.held.iter().position(|h| h.used == 0)) else {
            zeroize(&mut y);
            return ENOMEM;
        };
        let h = &mut s.held[k];
        h.clear();
        h.used = 1;
        h.owner = who.occupancy;
        h.set_id.copy_from_slice(&env[sh::SET_ID..sh::SET_ID + 16]);
        h.resource
            .copy_from_slice(&env[sh::RESOURCE..sh::RESOURCE + 16]);
        h.epoch.copy_from_slice(&env[sh::EPOCH..sh::EPOCH + 4]);
        h.aead.copy_from_slice(&env[sh::AEAD..sh::AEAD + 2]);
        h.suite = suite;
        h.usage = usage;
        h.anti_replay
            .copy_from_slice(&env[sh::ANTI_REPLAY..sh::ANTI_REPLAY + 16]);
        h.index = index;
        h.y = y;
        zeroize(&mut y);
        return EINPROGRESS;
    };
    let first = s.held[m];
    if consumed(s, &first.anti_replay) {
        zeroize(&mut y);
        return EACCES;
    }
    let mut key = [0u8; 32];
    let combined = key_share::combine(first.index, &first.y, index, &y, &mut key);
    zeroize(&mut y);
    if combined.is_none() {
        zeroize(&mut key);
        return EINVAL;
    }
    let handle = import_session_key(s, suite, usage, &key);
    zeroize(&mut key);
    if handle >= 0 {
        consume(s, &first.anti_replay);
        consume(s, &env[sh::ANTI_REPLAY..sh::ANTI_REPLAY + 16]);
    }
    handle
}

/// Import `key` as a never-persisted key of the caller's.
fn import_session_key(s: &mut State, suite: u16, usage: u32, key: &[u8; 32]) -> i32 {
    if !session_key_admissible(suite, usage) {
        return EINVAL;
    }
    let Some((c, scope)) = caller_scope(s) else {
        return EINVAL;
    };
    let Some(idx) = alloc_slot(s) else {
        return ENOMEM;
    };
    fill_slot(s, idx, suite, usage, key, FLAG_IN_USE);
    mint(s, idx, c, scope)
}
