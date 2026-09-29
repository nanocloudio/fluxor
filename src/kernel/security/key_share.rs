//! Recovery shares for the key vault: 2-of-3 Shamir over GF(2^8) and the
//! envelope that seals one share to one recipient.
//!
//! A 32-byte key is split bytewise with the AES field polynomial
//! `x^8 + x^4 + x^3 + x + 1`, share indices 1, 2 and 3, and one independent
//! random coefficient per byte. Every operation on secret bytes runs in
//! constant time; only the share indices, which are public, choose a path.
//!
//! Shares and reconstructed keys exist only inside a vault operation. The
//! functions here fill caller-owned scratch that the vault zeroes.

use crate::abi::contracts::key_vault::share as env;
use crate::kernel::security::crypto::p256;
use crate::kernel::security::crypto::sha256::Sha256;
use crate::kernel::security::key_vault::{derive_key, random_p256_scalar, zeroize};

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
        env::aead::AES_256_GCM => crate::kernel::security::crypto::aes_gcm::AES_IS_CONSTANT_TIME,
        _ => false,
    }
}

/// Seal under a zero nonce. Every envelope's key is derived from a fresh
/// ephemeral agreement and the envelope's own header, so no key ever seals
/// twice.
fn aead_seal(aead: u16, key: &[u8; 32], aad: &[u8], data: &mut [u8]) -> [u8; 16] {
    let nonce = [0u8; 12];
    if aead == env::aead::AES_256_GCM {
        crate::kernel::security::crypto::aes_gcm::AesGcm::new_256(key).encrypt(&nonce, aad, data)
    } else {
        crate::kernel::security::crypto::chacha20::chacha20_poly1305_encrypt(key, &nonce, aad, data)
    }
}

fn aead_open(aead: u16, key: &[u8; 32], aad: &[u8], data: &mut [u8], tag: &[u8; 16]) -> bool {
    let nonce = [0u8; 12];
    if aead == env::aead::AES_256_GCM {
        crate::kernel::security::crypto::aes_gcm::AesGcm::new_256(key)
            .decrypt(&nonce, aad, data, tag)
    } else {
        crate::kernel::security::crypto::chacha20::chacha20_poly1305_decrypt(
            key, &nonce, aad, data, tag,
        )
    }
}

/// Seal share `index ‖ y` to `recipient` (an uncompressed P-256 public
/// key) into `out`, which is [`env::P256_LEN`] bytes. `anti_replay` is
/// fresh per envelope. `false` if the recipient is not a valid point or
/// entropy fails.
pub fn seal(
    out: &mut [u8; env::P256_LEN],
    b: &Binding<'_>,
    index: u8,
    y: &[u8; 32],
    recipient: &[u8],
    anti_replay: &[u8; 16],
) -> bool {
    if recipient.len() != env::P256_PUB_LEN || !p256::public_point_is_valid(recipient) {
        return false;
    }
    let Some(mut eph) = random_p256_scalar() else {
        return false;
    };
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
    out[env::ENC_LEN..env::ENC_LEN + 2].copy_from_slice(&(env::P256_PUB_LEN as u16).to_le_bytes());
    out[env::ENC..env::ENC + env::P256_PUB_LEN].copy_from_slice(&eph_pub);
    let hdr = env::ENC + env::P256_PUB_LEN;
    let mut k = [0u8; 32];
    derive_key(&shared, b"share/envelope", &out[..hdr], &mut k);
    zeroize(&mut shared);
    let (head, body) = out.split_at_mut(hdr);
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
        use crate::abi::contracts::key_vault::share::grant as g;
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

/// Longest encapsulation this vault opens: an uncompressed P-256 point.
pub const PEER_MAX: usize = env::P256_PUB_LEN;

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

// ── Consumed envelopes ──────────────────────────────────────────────────
//
// An envelope reconstructs a key once. The recipient of an attachment
// envelope is a fresh key destroyed after the attach, which already stops a
// replay to another opener; this ring stops one to the same opener while it
// lives. It holds the anti-replay ids of the last `MAX_CONSUMED` envelopes a
// reconstruction used.

/// Envelopes remembered as consumed.
pub const MAX_CONSUMED: usize = 32;
static mut CONSUMED: [[u8; 16]; MAX_CONSUMED] = [[0; 16]; MAX_CONSUMED];
static mut CONSUMED_NEXT: usize = 0;
static mut CONSUMED_LIVE: usize = 0;

/// Whether an envelope with this anti-replay id was already consumed.
///
/// # Safety
/// Kernel context, exclusive access.
pub unsafe fn consumed(id: &[u8]) -> bool {
    let ring = &raw const CONSUMED;
    (*ring).iter().take(CONSUMED_LIVE).any(|c| c[..] == *id)
}

/// Record an envelope as consumed.
///
/// # Safety
/// Kernel context, exclusive access.
pub unsafe fn consume(id: &[u8]) {
    let ring = &raw mut CONSUMED;
    (*ring)[CONSUMED_NEXT].copy_from_slice(id);
    CONSUMED_NEXT = (CONSUMED_NEXT + 1) % MAX_CONSUMED;
    if CONSUMED_LIVE < MAX_CONSUMED {
        CONSUMED_LIVE += 1;
    }
}
