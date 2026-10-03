// Contract: mesh/capability — the capability token, delegation chains,
// local verification, and how a token travels on a session.
//
// Layer: contracts (public, stable).
//
// See docs/architecture/mesh.md §Authority. Authority over an object is a
// signed, self-contained, time-bounded assertion that the receiver checks
// entirely locally against the deployment's root key. There is no "go ask a
// server" step and no revocation list: a grant ends when its window does.
//
// This file is the one codec and the one verifier. The issuer (`fluxor
// modules cap`), a storage provider, an admin plane and an S3 front door all
// link the same bytes, so a token one of them mints is exactly the token
// every other one accepts.
//
// ## Crypto is the caller's
//
// The verifier needs SHA-256 and Ed25519 verification and nothing else. It
// takes them through [`CapCrypto`] rather than naming the SDK functions, so
// the contract stays free of the crypto sources and every consumer chooses
// its own: a PIC module `include!`s `crypto/{sha256,sha384,p256,ed25519}.rs`
// and wraps `sha256` / `ed25519_verify`; a host tool wraps the same files
// through the `fluxor-sdk` crate. Signing is never done here: an issuer signs
// [`Token::signed_bytes`] with its own key — the CLI with an operator's seed,
// a module through `KEY_VAULT::SIGN` on an Ed25519 slot it owns.
//
// ## Token (96 bytes, big-endian)
//
//   [object_id:16][permissions:2][flags:2][not_before:4][not_after:4]
//   [issuer_key_id:4][signature:64]
//
// The signature is Ed25519 over [`SIGN_DOMAIN`] followed by bytes 0..32
// ([`Token::signed_bytes`]): every field is covered, and a signature made
// for any other purpose under the same key (a module's signing envelope is
// also 32 bytes) is never a valid token signature. `flags` is reserved and
// MUST be zero; a token carrying any flag is refused, because a verifier that ignored
// a caveat it did not understand would grant more than the issuer meant.
//
// ## Chain (`2 + 128 × N` bytes)
//
//   [link_count:2 BE] link × link_count
//   link = [token:96][signer_key:32]
//
// Links run leaf first and end with the link the root signed. Every link
// carries the Ed25519 public key that signed it: a delegate's key cannot be
// looked up anywhere — that is the point of a chain — so it travels with the
// link it signed, and `issuer_key_id` (the first four bytes of its SHA-256)
// must name it. The last link's signer must be one of the verifier's roots.
//
// For every link `i > 0` (a delegation):
//   - its `object_id` is the first 16 bytes of SHA-256 of link `i-1`'s
//     signer key — the subkey this link authorises;
//   - its permissions include `DELEGATE` and contain every permission of
//     link `i-1`;
//   - its validity window contains link `i-1`'s window.
// Authority therefore only narrows, in rights and in time, from the root to
// the leaf. It does not narrow in objects: a delegation authorises its subkey
// to grant its permissions on any object, so a root that delegates to a key
// trusts that key with every object it could name. The leaf's `object_id` is
// the object the grant is for.
//
// ## Verification
//
// [`ChainCheck::new`] runs every check that costs no signature — structure,
// reserved flags, key ids, root membership, key binding, narrowing, windows,
// the clock, the object and the permission — and only then
// [`ChainCheck::step`] verifies one Ed25519 signature per call, leaf first.
// Refusing on bytes before spending a verification keeps a stream of forged
// chains from costing a verifier one signature each, and one signature per
// step keeps a chain inside a step budget on a microcontroller.
//
// The clock is the `TRUSTED_UNIX` observation, read through [`Clock::from_trusted`].
// A reading the platform does not mark `TRUSTED`, or one marked
// `ROLLBACK_SUSPECT`, is no clock, and a chain is refused rather than checked
// against a guess. The reading's uncertainty is spent against the grant: a
// window is satisfied only when the whole interval `now ± uncertainty` lies
// inside it.
//
// ## On a session
//
// Mutual TLS authenticates the channel; the capability authorises the
// operation. A client presents a chain once per session with
// [`MSG_CAP_PRESENT`]; the server verifies it, answers [`MSG_CAP_ANSWER`], and
// records the grant against the session ([`SessionGrants`]). Every later
// command names its object and is admitted by [`SessionGrants::authorise`]
// against the grants that session holds, at the time the command arrives —
// a grant that has expired admits nothing more, while a command already
// admitted completes under the grant it entered with. The grants die with
// the session. A server refuses a presentation on a session whose
// `peer_identity` record does not bind an identity ([`status::UNAUTHENTICATED`]):
// a bearer token on an anonymous channel is a token anybody who saw it can
// replay.
//
// A request-scoped protocol (HTTP, S3) carries the chain in the
// [`HTTP_HEADER`] header as [`TEXT_PREFIX`] + base64url, verified per request
// or cached per connection by the server; the verification is the same.

/// Encoded token length.
pub const TOKEN_LEN: usize = 96;
/// Token bytes before the signature: every field the signature covers.
pub const BODY_LEN: usize = 32;
/// Domain tag every token signature is made under, so a signature over some
/// other 32-byte message by the same key is not a token signature.
pub const SIGN_DOMAIN: [u8; 16] = *b"fluxor.mesh.cap\0";
/// Bytes the signature covers: [`SIGN_DOMAIN`] then the token's body.
pub const SIGNED_LEN: usize = SIGN_DOMAIN.len() + BODY_LEN;
/// Ed25519 public key length.
pub const KEY_LEN: usize = 32;
/// One chain link: a token and the key that signed it.
pub const LINK_LEN: usize = TOKEN_LEN + KEY_LEN;
/// The chain's leading link count.
pub const CHAIN_HDR: usize = 2;

/// Longest chain a verifier accepts: the root's grant plus seven
/// delegations. Every link costs one signature verification, and a chain is
/// verified on every presentation, so the bound is what one presentation can
/// cost a verifier.
pub const MAX_CHAIN_LINKS: usize = 8;
/// Largest encoded chain, derived from [`MAX_CHAIN_LINKS`].
pub const MAX_CHAIN_BYTES: usize = CHAIN_HDR + MAX_CHAIN_LINKS * LINK_LEN;
/// Most roots one verifier holds: the deployment's root and, during a
/// rotation, its successor. A chain signed by either verifies.
pub const MAX_ROOTS: usize = 2;

const OFF_OBJECT: usize = 0;
const OFF_PERMISSIONS: usize = 16;
const OFF_FLAGS: usize = 18;
const OFF_NOT_BEFORE: usize = 20;
const OFF_NOT_AFTER: usize = 24;
const OFF_KEY_ID: usize = 28;
const OFF_SIGNATURE: usize = BODY_LEN;

/// Permission bits (mesh.md §Authority).
pub mod perm {
    /// Read object state snapshots.
    pub const READ_STATE: u16 = 1 << 0;
    /// Receive event streams from the object.
    pub const SUBSCRIBE: u16 = 1 << 1;
    /// Issue commands to the object.
    pub const SEND_COMMAND: u16 = 1 << 2;
    /// Change object parameters.
    pub const CONFIGURE: u16 = 1 << 3;
    /// Manage object lifecycle.
    pub const ADMIN: u16 = 1 << 4;
    /// Hand off a subset of these rights to another holder.
    pub const DELEGATE: u16 = 1 << 5;
    /// Every assigned bit. A token naming any other bit is refused: a bit
    /// the verifier cannot name is a right it cannot reason about.
    pub const ALL: u16 = READ_STATE | SUBSCRIBE | SEND_COMMAND | CONFIGURE | ADMIN | DELEGATE;
}

/// A 128-bit object identity (mesh.md §Identity).
pub type ObjectId = [u8; 16];

/// The crypto a verifier needs, supplied by the caller.
pub trait CapCrypto {
    /// SHA-256 of `data`.
    fn sha256(&self, data: &[u8]) -> [u8; 32];
    /// Ed25519 (RFC 8032, strict) verification of `sig` over `msg` by `key`.
    fn ed25519_verify(&self, key: &[u8; KEY_LEN], msg: &[u8], sig: &[u8; 64]) -> bool;
}

/// Why a chain was refused. Every value is a refusal; there is no partial
/// acceptance. The numeric value is the `refusal` byte of [`MSG_CAP_ANSWER`].
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Wrong length, a link count of zero, or a count the bytes do not hold.
    Malformed = 1,
    /// More than [`MAX_CHAIN_LINKS`] links.
    ChainTooLong = 2,
    /// A reserved flag is set, or a permission bit outside [`perm::ALL`].
    ReservedBits = 3,
    /// A link's `not_before` is after its `not_after`.
    InvertedWindow = 4,
    /// A link's `issuer_key_id` does not name the key carried with it.
    KeyIdMismatch = 5,
    /// The last link was not signed by any of the verifier's roots.
    UnknownRoot = 6,
    /// A delegation's `object_id` does not name the key it authorises.
    KeyBinding = 7,
    /// A delegation lacks [`perm::DELEGATE`].
    NotDelegable = 8,
    /// A link holds a permission the link that delegated it does not.
    PermissionWidened = 9,
    /// A link's window reaches outside the window of the link that
    /// delegated it.
    WindowWidened = 10,
    /// A signature does not verify.
    Signature = 11,
    /// No trusted clock reading, so no window can be checked.
    NoTrustedClock = 12,
    /// `now - uncertainty` is before some link's `not_before`.
    NotYetValid = 13,
    /// `now + uncertainty` is after some link's `not_after`.
    Expired = 14,
    /// The leaf names a different object.
    ObjectMismatch = 15,
    /// The leaf does not carry every permission the operation needs.
    PermissionDenied = 16,
}

impl Refusal {
    /// Decode an answer's refusal byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Malformed,
            2 => Self::ChainTooLong,
            3 => Self::ReservedBits,
            4 => Self::InvertedWindow,
            5 => Self::KeyIdMismatch,
            6 => Self::UnknownRoot,
            7 => Self::KeyBinding,
            8 => Self::NotDelegable,
            9 => Self::PermissionWidened,
            10 => Self::WindowWidened,
            11 => Self::Signature,
            12 => Self::NoTrustedClock,
            13 => Self::NotYetValid,
            14 => Self::Expired,
            15 => Self::ObjectMismatch,
            16 => Self::PermissionDenied,
            _ => return None,
        })
    }
}

// ── Token ───────────────────────────────────────────────────────────────────

/// One decoded token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token {
    pub object_id: ObjectId,
    pub permissions: u16,
    pub flags: u16,
    pub not_before: u32,
    pub not_after: u32,
    pub issuer_key_id: [u8; 4],
    pub signature: [u8; 64],
}

impl Token {
    /// An unsigned token: the issuer fills `issuer_key_id` from its key and
    /// the signature from `KEY_VAULT::SIGN` over [`Token::signed_bytes`].
    pub const fn unsigned(
        object_id: ObjectId,
        permissions: u16,
        not_before: u32,
        not_after: u32,
        issuer_key_id: [u8; 4],
    ) -> Self {
        Self {
            object_id,
            permissions,
            flags: 0,
            not_before,
            not_after,
            issuer_key_id,
            signature: [0; 64],
        }
    }

    /// Decode exactly [`TOKEN_LEN`] bytes.
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != TOKEN_LEN {
            return None;
        }
        let mut object_id = [0u8; 16];
        object_id.copy_from_slice(&b[OFF_OBJECT..OFF_OBJECT + 16]);
        let mut issuer_key_id = [0u8; 4];
        issuer_key_id.copy_from_slice(&b[OFF_KEY_ID..OFF_KEY_ID + 4]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&b[OFF_SIGNATURE..TOKEN_LEN]);
        Some(Self {
            object_id,
            permissions: be16(b, OFF_PERMISSIONS),
            flags: be16(b, OFF_FLAGS),
            not_before: be32(b, OFF_NOT_BEFORE),
            not_after: be32(b, OFF_NOT_AFTER),
            issuer_key_id,
            signature,
        })
    }

    /// Encode into [`TOKEN_LEN`] bytes.
    pub fn encode(&self) -> [u8; TOKEN_LEN] {
        let mut b = [0u8; TOKEN_LEN];
        b[..BODY_LEN].copy_from_slice(&self.body());
        b[OFF_SIGNATURE..].copy_from_slice(&self.signature);
        b
    }

    /// The bytes the signature covers: [`SIGN_DOMAIN`], then the body.
    pub fn signed_bytes(&self) -> [u8; SIGNED_LEN] {
        signed_message(&self.body())
    }

    fn body(&self) -> [u8; BODY_LEN] {
        let mut b = [0u8; BODY_LEN];
        b[OFF_OBJECT..OFF_OBJECT + 16].copy_from_slice(&self.object_id);
        b[OFF_PERMISSIONS..OFF_PERMISSIONS + 2].copy_from_slice(&self.permissions.to_be_bytes());
        b[OFF_FLAGS..OFF_FLAGS + 2].copy_from_slice(&self.flags.to_be_bytes());
        b[OFF_NOT_BEFORE..OFF_NOT_BEFORE + 4].copy_from_slice(&self.not_before.to_be_bytes());
        b[OFF_NOT_AFTER..OFF_NOT_AFTER + 4].copy_from_slice(&self.not_after.to_be_bytes());
        b[OFF_KEY_ID..OFF_KEY_ID + 4].copy_from_slice(&self.issuer_key_id);
        b
    }
}

/// [`SIGN_DOMAIN`] followed by a token's `body`.
fn signed_message(body: &[u8]) -> [u8; SIGNED_LEN] {
    let mut m = [0u8; SIGNED_LEN];
    m[..SIGN_DOMAIN.len()].copy_from_slice(&SIGN_DOMAIN);
    m[SIGN_DOMAIN.len()..].copy_from_slice(body);
    m
}

/// The key id a token names its signer by: the first four bytes of
/// SHA-256 of the signer's public key.
pub fn key_id<C: CapCrypto>(crypto: &C, key: &[u8; KEY_LEN]) -> [u8; 4] {
    let h = crypto.sha256(key);
    [h[0], h[1], h[2], h[3]]
}

/// The `object_id` a delegation carries for the subkey it authorises: the
/// first 16 bytes of SHA-256 of that key.
pub fn key_object<C: CapCrypto>(crypto: &C, key: &[u8; KEY_LEN]) -> ObjectId {
    let h = crypto.sha256(key);
    let mut o = [0u8; 16];
    o.copy_from_slice(&h[..16]);
    o
}

// ── Chain ───────────────────────────────────────────────────────────────────

/// A borrowed, structurally checked chain.
#[derive(Clone, Copy, Debug)]
pub struct Chain<'a> {
    bytes: &'a [u8],
    links: usize,
}

impl<'a> Chain<'a> {
    /// Check the framing: a count of 1..=[`MAX_CHAIN_LINKS`] and exactly the
    /// bytes it names.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Refusal> {
        if bytes.len() < CHAIN_HDR {
            return Err(Refusal::Malformed);
        }
        let links = be16(bytes, 0) as usize;
        if links == 0 {
            return Err(Refusal::Malformed);
        }
        if links > MAX_CHAIN_LINKS {
            return Err(Refusal::ChainTooLong);
        }
        if bytes.len() != CHAIN_HDR + links * LINK_LEN {
            return Err(Refusal::Malformed);
        }
        Ok(Self { bytes, links })
    }

    /// Number of links.
    pub fn len(&self) -> usize {
        self.links
    }

    /// A parsed chain always holds at least one link.
    pub fn is_empty(&self) -> bool {
        self.links == 0
    }

    /// The encoded chain.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Link `i`'s token bytes.
    pub fn token_bytes(&self, i: usize) -> &'a [u8] {
        let at = CHAIN_HDR + i * LINK_LEN;
        &self.bytes[at..at + TOKEN_LEN]
    }

    /// Link `i`'s decoded token.
    pub fn token(&self, i: usize) -> Token {
        // `parse` proved every link is whole, so the fallback is never taken;
        // were it taken, its inverted window is refused by every check.
        Token::decode(self.token_bytes(i)).unwrap_or(Token::unsigned([0; 16], 0, 1, 0, [0; 4]))
    }

    /// The key that signed link `i`.
    pub fn signer(&self, i: usize) -> [u8; KEY_LEN] {
        let at = CHAIN_HDR + i * LINK_LEN + TOKEN_LEN;
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(&self.bytes[at..at + KEY_LEN]);
        k
    }
}

/// Write a chain from leaf-first `(token, signer_key)` links into `out`.
/// Returns the length, or `None` when the count is 0 or over
/// [`MAX_CHAIN_LINKS`] or `out` is short.
pub fn encode_chain(links: &[(Token, [u8; KEY_LEN])], out: &mut [u8]) -> Option<usize> {
    if links.is_empty() || links.len() > MAX_CHAIN_LINKS {
        return None;
    }
    let total = CHAIN_HDR + links.len() * LINK_LEN;
    if out.len() < total {
        return None;
    }
    out[..2].copy_from_slice(&(links.len() as u16).to_be_bytes());
    let mut at = CHAIN_HDR;
    for (token, key) in links {
        out[at..at + TOKEN_LEN].copy_from_slice(&token.encode());
        out[at + TOKEN_LEN..at + LINK_LEN].copy_from_slice(key);
        at += LINK_LEN;
    }
    Some(total)
}

// ── Clock ───────────────────────────────────────────────────────────────────

/// A clock reading a window may be checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clock {
    /// Unix seconds.
    pub now: u64,
    /// Half-width of the reading's confidence interval, in whole seconds,
    /// rounded up.
    pub uncertainty: u64,
}

impl Clock {
    /// The clock a `TRUSTED_UNIX` record (`kernel_abi::trusted_time`)
    /// yields, or `None` when the platform does not vouch for it or
    /// suspects it went backwards.
    pub fn from_trusted(rec: &[u8]) -> Option<Self> {
        use super::super::super::kernel_abi::trusted_time as tt;
        if rec.len() < tt::LEN {
            return None;
        }
        let flags = rec[tt::OFF_FLAGS];
        if flags & tt::flags::TRUSTED == 0 || flags & tt::flags::ROLLBACK_SUSPECT != 0 {
            return None;
        }
        let mut s = [0u8; 8];
        s.copy_from_slice(&rec[tt::OFF_UNIX_SECONDS..tt::OFF_UNIX_SECONDS + 8]);
        let mut u = [0u8; 4];
        u.copy_from_slice(&rec[tt::OFF_UNCERTAINTY_MS..tt::OFF_UNCERTAINTY_MS + 4]);
        Some(Self {
            now: u64::from_le_bytes(s),
            uncertainty: (u32::from_le_bytes(u) as u64).div_ceil(1000),
        })
    }

    fn check(&self, not_before: u32, not_after: u32) -> Result<(), Refusal> {
        if self.now.saturating_sub(self.uncertainty) < not_before as u64 {
            return Err(Refusal::NotYetValid);
        }
        if self.now.saturating_add(self.uncertainty) > not_after as u64 {
            return Err(Refusal::Expired);
        }
        Ok(())
    }
}

// ── Verification ────────────────────────────────────────────────────────────

/// What a verified chain grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The object the leaf names.
    pub object_id: ObjectId,
    /// The leaf's permissions.
    pub permissions: u16,
    /// The leaf's expiry, unix seconds — the lease bound of everything
    /// admitted under this grant. Narrowing makes it the chain's earliest.
    pub not_after: u32,
    /// Which root signed the chain's last link.
    pub root: u8,
}

/// What the operation being admitted needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Demand {
    /// The object the operation targets.
    pub object_id: ObjectId,
    /// Every permission bit the operation needs; non-zero.
    pub permissions: u16,
}

/// A chain whose byte-level checks passed and whose signatures are being
/// verified, one per [`ChainCheck::step`].
pub struct ChainCheck<'a> {
    chain: Chain<'a>,
    next: usize,
    grant: Grant,
}

/// What a [`ChainCheck::step`] concluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// More signatures remain.
    Pending,
    /// Every signature verified.
    Granted(Grant),
}

impl<'a> ChainCheck<'a> {
    /// Run every check that needs no signature verification. `demand` is
    /// `None` when admitting a presentation that is not yet bound to an
    /// operation; the object and permission are then checked per command by
    /// [`SessionGrants::authorise`].
    pub fn new<C: CapCrypto>(
        crypto: &C,
        bytes: &'a [u8],
        roots: &[[u8; KEY_LEN]],
        clock: Option<Clock>,
        demand: Option<Demand>,
    ) -> Result<Self, Refusal> {
        let chain = Chain::parse(bytes)?;
        let n = chain.len();
        for i in 0..n {
            let t = chain.token(i);
            if t.flags != 0 || t.permissions & !perm::ALL != 0 {
                return Err(Refusal::ReservedBits);
            }
            if t.not_before > t.not_after {
                return Err(Refusal::InvertedWindow);
            }
            if t.issuer_key_id != key_id(crypto, &chain.signer(i)) {
                return Err(Refusal::KeyIdMismatch);
            }
        }
        let last_signer = chain.signer(n - 1);
        let root = roots
            .iter()
            .take(MAX_ROOTS)
            .position(|r| *r == last_signer)
            .ok_or(Refusal::UnknownRoot)?;
        for i in 1..n {
            let parent = chain.token(i);
            let child = chain.token(i - 1);
            if parent.object_id != key_object(crypto, &chain.signer(i - 1)) {
                return Err(Refusal::KeyBinding);
            }
            if parent.permissions & perm::DELEGATE == 0 {
                return Err(Refusal::NotDelegable);
            }
            if child.permissions & !parent.permissions != 0 {
                return Err(Refusal::PermissionWidened);
            }
            if child.not_before < parent.not_before || child.not_after > parent.not_after {
                return Err(Refusal::WindowWidened);
            }
        }
        let clock = clock.ok_or(Refusal::NoTrustedClock)?;
        for i in 0..n {
            let t = chain.token(i);
            clock.check(t.not_before, t.not_after)?;
        }
        let leaf = chain.token(0);
        if let Some(d) = demand {
            if leaf.object_id != d.object_id {
                return Err(Refusal::ObjectMismatch);
            }
            if d.permissions == 0 || leaf.permissions & d.permissions != d.permissions {
                return Err(Refusal::PermissionDenied);
            }
        }
        Ok(Self {
            chain,
            next: 0,
            grant: Grant {
                object_id: leaf.object_id,
                permissions: leaf.permissions,
                not_after: leaf.not_after,
                root: root as u8,
            },
        })
    }

    /// Verify the next link's signature.
    pub fn step<C: CapCrypto>(&mut self, crypto: &C) -> Result<Step, Refusal> {
        if self.next < self.chain.len() {
            let i = self.next;
            let tb = self.chain.token_bytes(i);
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&tb[OFF_SIGNATURE..TOKEN_LEN]);
            let msg = signed_message(&tb[..BODY_LEN]);
            if !crypto.ed25519_verify(&self.chain.signer(i), &msg, &sig) {
                return Err(Refusal::Signature);
            }
            self.next += 1;
        }
        if self.next < self.chain.len() {
            Ok(Step::Pending)
        } else {
            Ok(Step::Granted(self.grant))
        }
    }
}

/// Verify a whole chain in one call. For a caller with no step budget to
/// respect; a module running inside a scheduler step uses [`ChainCheck`].
pub fn verify<C: CapCrypto>(
    crypto: &C,
    bytes: &[u8],
    roots: &[[u8; KEY_LEN]],
    clock: Option<Clock>,
    demand: Option<Demand>,
) -> Result<Grant, Refusal> {
    let mut check = ChainCheck::new(crypto, bytes, roots, clock, demand)?;
    loop {
        if let Step::Granted(g) = check.step(crypto)? {
            return Ok(g);
        }
    }
}

// ── Grants held by a session ────────────────────────────────────────────────

/// Most grants one session holds at once. A session that presents more is
/// refused the next one ([`status::GRANTS_FULL`]) until it withdraws one;
/// nothing is evicted, because an evicted grant is an operation that
/// silently starts failing.
pub const MAX_SESSION_GRANTS: usize = 8;

/// The grants one session presented and the server verified.
#[derive(Clone, Copy, Debug)]
pub struct SessionGrants {
    slots: [Option<(u32, Grant)>; MAX_SESSION_GRANTS],
}

impl Default for SessionGrants {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionGrants {
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_SESSION_GRANTS],
        }
    }

    /// Record a verified grant under the presentation id the client chose.
    /// A presentation id already held is replaced. `false` when full.
    pub fn insert(&mut self, presentation: u32, grant: Grant) -> bool {
        if let Some(s) = self
            .slots
            .iter_mut()
            .find(|s| matches!(s, Some((p, _)) if *p == presentation))
        {
            *s = Some((presentation, grant));
            return true;
        }
        match self.slots.iter_mut().find(|s| s.is_none()) {
            Some(s) => {
                *s = Some((presentation, grant));
                true
            }
            None => false,
        }
    }

    /// Drop a presentation. `false` when it was not held.
    pub fn withdraw(&mut self, presentation: u32) -> bool {
        for s in self.slots.iter_mut() {
            if matches!(s, Some((p, _)) if *p == presentation) {
                *s = None;
                return true;
            }
        }
        false
    }

    /// Forget every grant: the session ended.
    pub fn clear(&mut self) {
        self.slots = [None; MAX_SESSION_GRANTS];
    }

    /// Admit one command: some held grant names `demand.object_id`, carries
    /// every bit of `demand.permissions`, and is still inside its window at
    /// `clock` (the start of its window was proved at presentation).
    /// Without a trusted clock nothing is admitted.
    pub fn authorise(&self, demand: Demand, clock: Option<Clock>) -> Result<Grant, Refusal> {
        let clock = clock.ok_or(Refusal::NoTrustedClock)?;
        if demand.permissions == 0 {
            return Err(Refusal::PermissionDenied);
        }
        let mut refusal = Refusal::ObjectMismatch;
        for (_, g) in self.slots.iter().flatten() {
            if g.object_id != demand.object_id {
                continue;
            }
            if g.permissions & demand.permissions != demand.permissions {
                refusal = Refusal::PermissionDenied;
                continue;
            }
            if clock.now.saturating_add(clock.uncertainty) > g.not_after as u64 {
                refusal = Refusal::Expired;
                continue;
            }
            return Ok(*g);
        }
        Err(refusal)
    }
}

// ── Session wire ────────────────────────────────────────────────────────────
//
// Frames use the `[msg_type:1][len:2 LE][payload]` header the net contracts
// share (net_proto, datagram, packet, session_ctrl, mux), in a range disjoint
// from all of them, so one channel may carry a protocol's own frames and
// these.

/// Frame header bytes.
pub const FRAME_HDR: usize = 3;

/// Client → server: `[presentation:4 LE][chain]`. The presentation id is
/// the client's handle for the grant (to withdraw it, and to match the
/// answer); the server never interprets it.
pub const MSG_CAP_PRESENT: u8 = 0xD0;
/// Server → client: `[presentation:4 LE][status:1][refusal:1]` and, when
/// `status` is [`status::GRANTED`], `[object_id:16][permissions:2 BE][not_after:4 BE]`.
pub const MSG_CAP_ANSWER: u8 = 0xD1;
/// Client → server: `[presentation:4 LE]` — drop that grant.
pub const MSG_CAP_WITHDRAW: u8 = 0xD2;

/// Largest `MSG_CAP_PRESENT` payload.
pub const PRESENT_MAX: usize = 4 + MAX_CHAIN_BYTES;
/// Fixed part of a `MSG_CAP_ANSWER` payload.
pub const ANSWER_FIXED: usize = 4 + 1 + 1;
/// A granting `MSG_CAP_ANSWER` payload.
pub const ANSWER_GRANTED: usize = ANSWER_FIXED + 16 + 2 + 4;

/// `MSG_CAP_ANSWER` status.
pub mod status {
    /// Verified and recorded against the session.
    pub const GRANTED: u8 = 0;
    /// Refused; the `refusal` byte says why ([`super::Refusal`]).
    pub const REFUSED: u8 = 1;
    /// The session's peer is not authenticated; nothing was verified.
    pub const UNAUTHENTICATED: u8 = 2;
    /// The session already holds [`super::MAX_SESSION_GRANTS`] grants.
    pub const GRANTS_FULL: u8 = 3;
}

/// Encode a granting answer payload.
pub fn encode_answer_granted(presentation: u32, g: &Grant) -> [u8; ANSWER_GRANTED] {
    let mut b = [0u8; ANSWER_GRANTED];
    b[..4].copy_from_slice(&presentation.to_le_bytes());
    b[4] = status::GRANTED;
    b[6..22].copy_from_slice(&g.object_id);
    b[22..24].copy_from_slice(&g.permissions.to_be_bytes());
    b[24..28].copy_from_slice(&g.not_after.to_be_bytes());
    b
}

/// Encode a non-granting answer payload.
pub fn encode_answer_refused(presentation: u32, st: u8, refusal: u8) -> [u8; ANSWER_FIXED] {
    let mut b = [0u8; ANSWER_FIXED];
    b[..4].copy_from_slice(&presentation.to_le_bytes());
    b[4] = st;
    b[5] = refusal;
    b
}

// ── Text form ───────────────────────────────────────────────────────────────

/// HTTP header carrying a chain on a request-scoped protocol.
pub const HTTP_HEADER: &str = "fluxor-capability";
/// Prefix of the text form, so a chain is recognisable wherever it is
/// pasted.
pub const TEXT_PREFIX: &str = "fxcap1.";
/// Longest text form, derived from [`MAX_CHAIN_BYTES`].
pub const MAX_TEXT_LEN: usize = 1375;
const _: () = assert!(MAX_TEXT_LEN == TEXT_PREFIX.len() + (MAX_CHAIN_BYTES * 4).div_ceil(3));

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode a chain's bytes as `fxcap1.<base64url, unpadded>`. Returns the
/// length, or `None` when `out` is short.
pub fn encode_text(bytes: &[u8], out: &mut [u8]) -> Option<usize> {
    let p = TEXT_PREFIX.len();
    let n = p + (bytes.len() * 4).div_ceil(3);
    if out.len() < n {
        return None;
    }
    out[..p].copy_from_slice(TEXT_PREFIX.as_bytes());
    let mut o = p;
    for chunk in bytes.chunks(3) {
        let mut v = [0u8; 3];
        v[..chunk.len()].copy_from_slice(chunk);
        let w = ((v[0] as u32) << 16) | ((v[1] as u32) << 8) | v[2] as u32;
        for k in 0..chunk.len() + 1 {
            out[o] = B64URL[((w >> (18 - 6 * k)) & 63) as usize];
            o += 1;
        }
    }
    Some(o)
}

/// Decode the text form. Strict: the prefix is required, padding and any
/// character outside the base64url alphabet are refused, and so are unused
/// trailing bits, so one chain has exactly one text form.
pub fn decode_text(text: &[u8], out: &mut [u8]) -> Option<usize> {
    let body = text.strip_prefix(TEXT_PREFIX.as_bytes())?;
    if body.len() % 4 == 1 {
        return None;
    }
    let n = body.len() * 3 / 4;
    if out.len() < n {
        return None;
    }
    let val = |c: u8| -> Option<u32> { B64URL.iter().position(|&x| x == c).map(|p| p as u32) };
    let mut o = 0;
    for chunk in body.chunks(4) {
        let mut w = 0u32;
        for (k, &c) in chunk.iter().enumerate() {
            w |= val(c)? << (18 - 6 * k);
        }
        let bytes = chunk.len() - 1;
        let unused = 24 - 8 * bytes as u32;
        if unused < 24 && w & ((1 << unused) - 1) != 0 {
            return None;
        }
        for k in 0..bytes {
            out[o] = (w >> (16 - 8 * k)) as u8;
            o += 1;
        }
    }
    Some(o)
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
