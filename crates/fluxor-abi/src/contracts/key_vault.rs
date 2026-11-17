// Contract: key_vault — backend-managed opaque keys: signing, agreement,
// sealing and MAC keys behind handles that never expose the key bytes.
//
// Layer: contracts (public, stable).
//
// All operations run in the vault; private key material never leaves it
// (the software backend's slots, a PKCS#11 token on a hardware backend).
// Callers see opaque `i32` handles. A module that calls the vault claims it
// in its manifest (`[[resources]] requires_contract = "key_vault"`), so a
// graph without a vault is refused when it is composed; nothing asks at
// run time whether one is there.
//
// ## Call shape
//
// Every op is one flat `arg` record (little-endian, tightly packed) and at
// most one bulk `data` span. No field of any record is an address or a
// handle: an op that names a key names it in the call's `handle`, and an op
// that needs two keys is two calls. Each layout has one codec below, with
// the `const fn` lengths a caller sizes its `arg` with.
//
// - Small answers (a handle's facts, a suite record, a tier, a tag) are
//   written back into `arg`; the call returns the bytes it wrote there.
// - Signatures, public keys, records, wrapped keys and envelopes are
//   written into `data`; the call returns their length.
// - Ops that transform bytes (`SIGN`, `ECDH`, the AEADs, `SHARE_REWRAP`)
//   work IN PLACE: the input is the head of `data` and the answer is
//   written over `data` from byte 0.
// - An answer that does not fit `data` is `ERANGE`. An op whose answer has
//   no fixed length carries a `len` field in `arg`; on `ERANGE` the vault
//   writes the length it needs there. Nothing is consumed or minted by a
//   call answered `ERANGE`.
//
// ## Resumable `SIGN`
//
// A suite whose signature is not cheap to compute inside one caller step
// (P-256, RSA, ML-DSA: [`describe_suite::flags::RESUMABLE_SIGN`]) signs as
// a job the vault keeps against the key:
//
// 1. The call that starts the job answers `EAGAIN`, always.
// 2. The caller repeats the IDENTICAL call — same handle, same `arg`, same
//    input bytes at the head of `data` — once per step. Each answers
//    `EAGAIN` until the last, which writes the signature over `data` and
//    returns its length.
// 3. A different `SIGN` on a key whose job is under way answers `EBUSY` and
//    starts nothing; the caller asks again later. A job not advanced for
//    [`sign::JOB_IDLE_MS`] is abandoned, and the next call on the key
//    replaces it.
// 4. `EBUSY` also answers a call that finds every job the vault can hold
//    already under way.
//
// A backend that signs whole (a token) never answers `EAGAIN`; a caller
// handles it anyway. Backend facts — which suites exist, how big each
// answer is, which sign resumably — come from [`DESCRIBE_SUITE`]; the
// isolation a backend gives comes from [`TIER`]. A consumer MUST NOT claim
// a hardware guarantee it did not read from `TIER`.

/// Import a private key. handle=-1. arg in [`store`]; `data` in = the key's
/// bytes (their length is the key's). Returns an opaque handle (>= 0) or a
/// negative errno. Pass the handle back unmodified; do not decode it.
///
/// STORE is an *import* path: the key existed outside the backend and is
/// received-then-wiped, not never-present. A non-extractable backend may
/// refuse it entirely; [`DESCRIBE_SUITE`] reports import per suite
/// ([`describe_suite::flags::IMPORT`]) because tokens differ by algorithm.
///
/// The key's length is the suite's `priv_len`, which is not always the
/// algorithm's encoded private key. FIPS 204 KeyGen is a deterministic
/// function of a 32-byte seed, so a backend may hold ML-DSA keys AS that
/// seed and report 32 — the seed reproduces the encoded key exactly, and a
/// caller holding an already-expanded key learns from the reported length
/// that this backend is not where it can import one. An RSA key is its
/// PKCS#1 `RSAPrivateKey` DER, any length up to the suite's `priv_len`.
pub use super::super::registry::key_vault::STORE;

/// ECDH: derive the shared secret. handle = the key (must permit
/// [`usage::AGREE`]). arg inout [`ecdh`]; `data` inout: the peer's public
/// key in its first `len` bytes, the shared secret written over `data` from
/// byte 0. Returns the secret's length (32 for P-256), `ERANGE` with the
/// requirement in `len`.
///
/// A signing key used for key agreement is a cross-purpose reuse, and the
/// place to stop it is the mask rather than the caller's discipline.
pub use super::super::registry::key_vault::ECDH;

/// Sign with the key. handle = the key (must permit [`usage::SIGN`]). arg
/// inout [`sign`]; `data` inout: the input in its first `len` bytes, the
/// signature written over `data` from byte 0. Returns the signature's
/// length; `ERANGE` with the requirement in `len`; `EAGAIN` / `EBUSY` under
/// the resumable rule (module header).
///
/// `mode` is on the wire rather than inferred from the suite — see
/// [`sign_mode`]. Inferring it means a caller that hands a P-256 key a
/// message rather than its digest gets a valid signature over the wrong
/// thing, with nothing on the wire saying which convention applied.
///
/// - P-256: ECDSA over the digest with `DIGEST` (at most 64 bytes). The
///   software backend uses the deterministic RFC 6979 nonce; a hardware
///   backend may use random-k, producing different-but-valid signatures
///   (verify, don't byte-compare). The 64-byte low-s `r‖s` output is
///   exactly the JWS ES256 segment. Resumable.
/// - Ed25519: `RAW` over the full message (RFC 8032 is not prehashed).
///   Output is the 64-byte `R‖S`.
/// - HMAC-SHA256: `RAW` over the full message; the 32-byte output is the
///   RFC 2104 tag.
/// - ML-DSA: `RAW` over the full message. The pure FIPS 204 variant is not
///   prehashed — HashML-DSA is a different algorithm — and `PREHASH` is
///   refused rather than answered with it. The signature is 2420 / 3309 /
///   4627 bytes by parameter set. Resumable.
/// - RSA: RSASSA-PSS-SHA256 with a 32-byte salt over a 32-byte SHA-256
///   digest (`DIGEST`); the signature is the modulus width. Resumable.
pub use super::super::registry::key_vault::SIGN;

/// Verify a signature. arg in [`verify`]; `data` in = message ‖ signature ‖
/// public key, at the lengths `arg` gives. Returns 1 if valid, 0 if not,
/// a negative errno on malformed input.
///
/// With handle=-1: ECDSA P-256 under the caller's public key (the stored
/// keys are not consulted). The message is the digest; the signature is the
/// 64-byte raw `r‖s`; the public key is SEC1 uncompressed, with or without
/// its leading 0x04.
///
/// With a key's handle: the key must hold an [`suite::HMAC_SHA256`] key
/// permitting [`usage::VERIFY`]; the message is the whole message, the
/// signature the 32-byte tag, and the public key empty. The vault recomputes
/// the tag and compares in constant time, so the comparison cannot be
/// written wrong at any of the places it would otherwise be written.
pub use super::super::registry::key_vault::VERIFY;

/// Zeroise and free the key. handle = the key. Returns 0.
pub use super::super::registry::key_vault::DESTROY;

/// Generate a key inside the backend. handle=-1. arg inout [`generate`];
/// `data` out = the public key. Returns an opaque handle (>= 0), with the
/// public key's length in `len`; `ERANGE` with the requirement in `len`.
///
/// The private key is born in backend custody and never exists in the
/// clear anywhere — the only path that gives true "key never leaves", and
/// the only one a non-extractable HSM supports.
///
/// `usage` is sealed into the key here and checked on every later
/// operation: sealed at birth rather than checked at the call site, because
/// a call-site check is one some call site will not have.
pub use super::super::registry::key_vault::GENERATE;

/// The key's public half (for JWK/JWKS/kid derivation). handle = the key
/// (must permit [`usage::EXPORT_PUBLIC`], which never implies the private
/// half may be exported). arg out [`public`]; `data` out = the public key.
/// Returns its length; `ERANGE` with the requirement in `arg`.
pub use super::super::registry::key_vault::PUBLIC;

/// The backend's isolation tier. handle=-1. arg out `[tier u8]` (a
/// [`tier`] ordinal); returns 1.
///
/// Tiers are mutually-exclusive ordinal levels (not independent
/// capabilities, hence not per-suite); a consumer with a security
/// requirement checks `tier >= N` and MUST NOT claim a hardware guarantee
/// it did not read from here.
pub use super::super::registry::key_vault::TIER;

/// Open the key named by `label`, generating it if it does not exist.
/// handle=-1. arg inout [`open`]; `data` out = the public key. Returns an
/// opaque handle (>= 0) with the public key's length in `len`, or:
/// - `EACCES`: the key exists under another suite, or with fewer uses than
///   `usage` asks for;
/// - `EBUSY`: another instance of the caller's module type holds it open;
/// - `ENOMEM`: no slot is free;
/// - `ERANGE`: `data` is short for the public key, whose length is in
///   `len` (nothing was opened or made);
/// - `EAGAIN`: the vault's store cannot be read yet, or the key (`PERSIST`)
///   is not on the store's medium yet; asked again, the same key is
///   answered once it is;
/// - `ERROR`: the store's medium refused the key's record.
///
/// **This is the operation that makes an issuer key survive a restart**,
/// and it is one operation rather than "does it exist?" then "create it"
/// because those two are a race: two instances starting together would
/// both see absence and both generate.
///
/// `usage` is sealed into the key at creation. On an existing key it is
/// CHECKED, not applied: a key's permitted uses must not be something a
/// later caller can widen by asking.
pub use super::super::registry::key_vault::OPEN_OR_GENERATE;

/// Open an existing key by label, failing (`ENOENT`) if absent. handle=-1,
/// as [`OPEN_OR_GENERATE`].
///
/// Separate from `OPEN_OR_GENERATE` because "use the existing issuer key"
/// and "use it, creating one if needed" are different intentions, and a
/// verifier that silently generated a key would verify nothing while
/// appearing to work.
pub use super::super::registry::key_vault::OPEN;

/// Destroy the key named by `label`, wherever it is stored. handle=-1. arg
/// in [`destroy_by_label`]. Returns 0, `ENOENT` when no key has the label,
/// `EAGAIN` while the vault's store cannot be read yet or its medium still
/// holds the record (asked again once it does not, the label names nothing:
/// `ENOENT`), or `ERROR` when the sealed record could not be removed (it
/// would come back).
///
/// By label rather than by handle because the point is to remove the
/// PERSISTED key: destroying a handle frees a slot and leaves the sealed
/// record, which would come back on the next open.
pub use super::super::registry::key_vault::DESTROY_BY_LABEL;

/// What a key is. handle = the key. arg out [`describe`]; returns 8.
///
/// Exists so a consumer can check what it actually got rather than what it
/// asked for. `persisted` sits next to `tier` and is deliberately separate
/// from it: a caller that conflates the two is the failure mode this whole
/// surface is shaped to prevent.
pub use super::super::registry::key_vault::DESCRIBE;

/// What the vault can do with a suite. handle=-1. arg inout
/// [`describe_suite`]: in a cursor, out the record of the first suite the
/// vault supports whose id is at least the cursor, and the cursor that
/// follows it. Returns [`describe_suite::LEN`]; `ENOENT` past the last.
///
/// One op answers both questions a caller has: "can you use suite S?"
/// (cursor = S; the answer is S's record exactly when the record's `suite`
/// is S) and "which suites can you use?" (cursor 0, then each `next` until
/// `ENOENT`).
///
/// Lengths rather than a capability bitmap, because a bitmap answers "is
/// P-256 supported" and cannot answer "how big is an ML-DSA-65 signature",
/// which is what a caller sizing a buffer needs.
pub use super::super::registry::key_vault::DESCRIBE_SUITE;

/// Sign the running composition. handle = a signing key. arg inout
/// [`attest_composition`]; `data` out = `[record][signature]`, where the
/// record is the kernel's composition record (`scheduler::attest`, prefix
/// `"FXAT"`) ending in the vault's tier byte, and the signature is over the
/// record in the key's suite convention: ECDSA over the record's SHA-256 for
/// P-256, the whole record for Ed25519 and ML-DSA. Returns the length
/// written; `ERANGE` with the requirement in `len`.
///
/// The challenge is the caller's, so the answer cannot be replayed; the
/// record carries the boot incarnation, so it cannot outlive the boot. What
/// the signature MEANS is the tier byte's: `DEVICE_HW` says this hardware
/// runs exactly this closure, `SOFTWARE` says a readable process does. The
/// composition digest — SHA-256 of the record with the challenge zeroed —
/// is the identity [`KEY_WRAP`] binds to.
pub use super::super::registry::key_vault::ATTEST_COMPOSITION;

/// Wrap the key for one destination vault. handle = the key (must permit
/// [`usage::WRAP`]). arg inout [`key_wrap`]; `data` out = the wrapped key
/// (layout [`wrap`]). Returns its length; `ERANGE` with the requirement in
/// `len`.
///
/// The wrapped key is `["FXKW"][eph_pub:65][attest_digest:32][nonce:12]
/// [sealed][tag:16]`, `sealed` being `[suite:u16][usage:u32][key_len:u8]
/// [key]` under a key derived from an ephemeral ECDH with `dest_pub`,
/// salted by `attest_digest`, and authenticated with every header byte
/// before it (magic to nonce) as AAD. The key never appears in the clear on
/// any surface: only the vault holding `dest_pub`'s private half can open
/// it, and only while its composition still digests to `attest_digest`.
pub use super::super::registry::key_vault::KEY_WRAP;

/// Unwrap into a fresh key. handle = the key holding this vault's P-256
/// private key (must permit [`usage::AGREE`]). No arg; `data` in = the
/// wrapped key. Returns the new key's handle, or `EACCES` when the wrapped
/// key's `attest_digest` is not this composition's digest — the composition
/// changed since it was attested, and the key was wrapped for the one that
/// was — or `EINVAL` when it does not open.
pub use super::super::registry::key_vault::KEY_UNWRAP;

/// Seal bytes under an [`suite::AEAD_KEY`] key (must permit
/// [`usage::SEAL`]) with a nonce the vault draws. arg inout [`aead`]: in
/// the associated data and the plaintext's length, out the nonce; `data`
/// inout: the plaintext in its first `len` bytes, sealed in place with the
/// 16-byte tag appended. Returns `len + 16`; `ERANGE` (with `len + 16` in
/// `len`) when `data` is shorter.
///
/// The nonce is fresh from the CSPRNG per call; the caller keeps it with
/// the ciphertext. What the bytes mean — a resumption ticket, a checkpoint
/// — is the caller's; the vault only guarantees that the key never leaves
/// it.
pub use super::super::registry::key_vault::AEAD_SEAL;

/// Open what [`AEAD_SEAL`] produced. handle = the key (must permit
/// [`usage::OPEN`]). arg in [`aead`]: the nonce, the associated data and
/// the sealed length (ciphertext and tag); `data` inout: the sealed bytes,
/// opened in place. Returns `len - 16`, or `EINVAL` when the tag does not
/// verify (the bytes are zeroed: unauthenticated plaintext is never left
/// behind).
pub use super::super::registry::key_vault::AEAD_OPEN;

/// Derive a purpose key from a [`suite::KDF_KEY`] key. handle = the master
/// (must permit [`usage::DERIVE`]). arg in [`derive`]. Returns a new handle,
/// owned by the caller, holding `HKDF-SHA256(ikm = master, salt =
/// derive::SALT, info = label ‖ context)` as a key of the target suite with
/// the target uses. A derived key is never persisted: it is derived again
/// when needed.
pub use super::super::registry::key_vault::DERIVE;

/// Seal one storage unit in place under an AEAD key ([`suite::AEAD_KEY`] or
/// [`suite::AEAD_AES256_GCM`], must permit [`usage::SEAL`]) with the nonce
/// the caller names. arg inout [`units`]: in the nonce and associated data,
/// out the 16-byte tag; `data` inout = the unit, sealed in place. Returns 0.
///
/// The caller chooses the nonce, so its uniqueness under the key is the
/// caller's obligation — the reason this exists beside [`AEAD_SEAL`], whose
/// vault-drawn random nonces suit a record now and then and not a storage
/// device writing the same key for years. The tag stays apart from the unit
/// because a block device keeps it apart.
pub use super::super::registry::key_vault::AEAD_SEAL_UNITS;

/// Open one storage unit in place, checking its tag. arg in [`units`] (the
/// nonce, the tag, the associated data); `data` inout = the unit. Returns 0,
/// or `EINVAL` when the tag does not verify (the unit is zeroed, so
/// unauthenticated plaintext is never left behind).
pub use super::super::registry::key_vault::AEAD_OPEN_UNITS;

/// Split a 32-byte key 2-of-3 and wrap each share to its own recipient.
/// handle = the key (must permit [`usage::WRAP`]; a [`suite::KDF_KEY`],
/// [`suite::AEAD_KEY`] or [`suite::AEAD_AES256_GCM`]). arg in
/// [`share::split`]; `data` out = three [`share`] envelopes, for share
/// indices 1, 2 and 3 in recipient order. Returns
/// [`share::split::OUT_LEN`]; `ERANGE` when `data` is shorter.
///
/// The shares exist only inside the call: each is sealed to its recipient
/// as it is made, and the scratch is zeroed. Any two envelopes, opened by
/// their recipients, give the key back through [`SHARE_COMBINE`]; one gives
/// nothing.
pub use super::super::registry::key_vault::SHARE_SPLIT;

/// Open one share envelope and seal the share to another recipient.
/// handle = the P-256 key the envelope is wrapped to (must permit
/// [`usage::AGREE`] and [`usage::EXPORT_PUBLIC`]: an envelope names its
/// recipient by public key). arg in [`share::rewrap`]; `data` inout = the
/// envelope, rewrapped in place. Returns [`share::P256_LEN`].
///
/// What a custodian does to release its share: the share leaves this vault
/// only sealed to the new recipient, bound to a new purpose, lease fence,
/// expiry and policy digest. The recovery set, protected resource, epoch
/// and share index are carried over and cannot be changed.
pub use super::super::registry::key_vault::SHARE_REWRAP;

/// Reconstruct a key from two share envelopes, one envelope per call.
/// handle = the key the envelope is wrapped to (must permit
/// [`usage::AGREE`] and [`usage::EXPORT_PUBLIC`], held in any backend).
/// arg in [`share::combine`]; `data` in = the envelope.
///
/// The first envelope is opened and its share held by the vault for the
/// caller: the call answers `EINPROGRESS`. The second — the same recovery
/// set, resource, epoch and AEAD, another share index, the same `arg` —
/// reconstructs the key into a fresh handle, owned by the caller, which the
/// call returns. Each call answers, without holding anything:
/// - `EINVAL`: the envelope is malformed or does not open, or it does not
///   pair with the share held (another set, resource, epoch or AEAD, or the
///   same index);
/// - `EACCES`: the envelope is not wrapped to the handle opening it, has
///   expired (or carries an expiry with no wall clock to check it), was
///   already consumed, or is for another resource or epoch than asked.
///
/// A refusal drops the share held, so the caller starts again from the
/// first envelope; a first envelope of another set replaces it. Neither a
/// share nor the key is ever written to the caller, and the new key is
/// never persisted: a volume attaches again after a restart.
pub use super::super::registry::key_vault::SHARE_COMBINE;

/// Attest a key: evidence of what a handle is, bound to a caller's
/// challenge, never its bytes. handle = the key attested. arg in
/// `[challenge:32]` ([`attest_key`]); `data` out = the record. Returns
/// [`attest_key::RECORD_LEN`].
///
/// The record commits to the key without revealing it, names its suite,
/// uses, owner namespace, persistence and the vault's tier, and carries the
/// composition digest. The caller signs it with the key it attests under
/// ([`SIGN`]: P-256 over the record's SHA-256 with `DIGEST`, Ed25519 and
/// ML-DSA over the record with `RAW`), so a verifier that trusts that key's
/// public half learns which composition holds which kind of key under which
/// policy.
pub use super::super::registry::key_vault::ATTEST_KEY;

/// Key suites: what a key's bytes mean, which operations it admits, and
/// how big each answer is.
///
/// A `u16` because the space this has to hold is large: each post-quantum
/// family comes in several parameter sets, and every hybrid is its own
/// entry.
///
/// **Naming a suite is not implementing it.** [`DESCRIBE_SUITE`] is the
/// only thing that says whether a backend can use one.
pub mod suite {
    /// No suite. Never valid: a key that does not say what it is cannot be
    /// used, and defaulting one picks the answer for the caller.
    pub const NONE: u16 = 0;
    /// P-256, for ECDSA and ECDH.
    pub const P256: u16 = 1;
    /// Ed25519 (RFC 8032).
    pub const ED25519: u16 = 2;
    pub const P384: u16 = 3;
    pub const ML_DSA_44: u16 = 4;
    pub const ML_DSA_65: u16 = 5;
    pub const ML_DSA_87: u16 = 6;
    pub const ML_KEM_768: u16 = 7;
    /// A 32-byte ChaCha20-Poly1305 key for [`super::AEAD_SEAL`] /
    /// [`super::AEAD_OPEN`]: the shape a resumption-ticket key or any other
    /// sealing key takes. It signs nothing and has no public half.
    pub const AEAD_KEY: u16 = 8;
    /// A 32-byte HMAC-SHA256 key (RFC 2104): a shared secret whose tag is
    /// produced by [`super::SIGN`] and checked by [`super::VERIFY`] against
    /// the key. The shape a TSIG key (RFC 8945) takes. It has no public half
    /// and is never readable back: the only answers a holder gets are tags.
    pub const HMAC_SHA256: u16 = 9;
    /// RSA keys by modulus width, for RSASSA-PSS-SHA256 signatures over a
    /// caller-supplied SHA-256 digest with a 32-byte salt — the one encoding
    /// TLS 1.3 asks of an rsaEncryption key. One suite per width because
    /// [`super::DESCRIBE_SUITE`] reports fixed lengths per suite. The
    /// private key is the PKCS#1 `RSAPrivateKey` DER with its CRT fields;
    /// the reported private length is the CEILING for the width. A
    /// signature is the modulus width; the public half is the
    /// `RSAPublicKey` DER.
    pub const RSA_2048: u16 = 10;
    pub const RSA_3072: u16 = 11;
    pub const RSA_4096: u16 = 12;
    /// A sealing key for AES-256-GCM, 32 bytes, no public half. Offered
    /// only where the block cipher runs in constant time: elsewhere
    /// [`super::DESCRIBE_SUITE`] skips it, and `AEAD_KEY` is the sealing
    /// suite.
    pub const AEAD_AES256_GCM: u16 = 13;
    /// A key-derivation master, 32 bytes, no public half: its only use is
    /// [`super::usage::DERIVE`], which makes purpose keys from it. A volume,
    /// WAL or snapshot key is one, so no purpose key is ever the master.
    pub const KDF_KEY: u16 = 14;

    /// Highest id this registry defines.
    pub const MAX_ID: u16 = KDF_KEY;
}

/// How [`SIGN`] treats the bytes it is given.
///
/// On the wire rather than inferred from the suite. Inference would hold
/// only while each suite has one convention, and it requires the caller to
/// know which without the wire ever saying.
pub mod sign_mode {
    /// Sign the bytes as given. Ed25519's convention (RFC 8032 signs the
    /// full message).
    pub const RAW: u8 = 0;
    /// The bytes ARE the digest; sign them directly. ECDSA's convention.
    pub const DIGEST: u8 = 1;
    /// The bytes are a message; the backend hashes with the suite's hash
    /// before signing.
    pub const PREHASH: u8 = 2;
    /// As `RAW`, with a domain-separation context string prefixed
    /// (Ed25519ctx, ML-DSA's context parameter). The [`super::sign`] layout
    /// carries no context field, so a backend refuses it rather than
    /// signing under the empty context: a signature in a domain the caller
    /// did not ask for is worse than no signature, because it verifies.
    pub const CONTEXT: u8 = 3;
}

/// What a key may be used for, sealed at creation and checked per
/// operation.
///
/// A key created for signing must not later be usable for key agreement,
/// however convenient that would be at the call site. Cross-purpose reuse
/// is the shape behind a long list of protocol breaks, and the only
/// reliable place to stop it is where the key is born.
pub mod usage {
    pub const SIGN: u32 = 1 << 0;
    pub const VERIFY: u32 = 1 << 1;
    pub const AGREE: u32 = 1 << 2;
    /// The public half may be exported. Never implies the private half
    /// can be.
    pub const EXPORT_PUBLIC: u32 = 1 << 3;
    /// The key may be persisted across a restart — and persistence says
    /// nothing about isolation, which is [`super::TIER`]'s business.
    pub const PERSIST: u32 = 1 << 4;
    /// The key may leave the vault WRAPPED ([`super::KEY_WRAP`]): sealed to
    /// a destination vault's public key and bound to that vault's attested
    /// composition, never in the clear. A key without this bit never leaves
    /// at all.
    pub const WRAP: u32 = 1 << 5;
    /// The key may seal ([`super::AEAD_SEAL`], [`super::AEAD_SEAL_UNITS`]).
    pub const SEAL: u32 = 1 << 6;
    /// The key may open ([`super::AEAD_OPEN`], [`super::AEAD_OPEN_UNITS`]).
    pub const OPEN: u32 = 1 << 7;
    /// Derive purpose keys from this key ([`super::DERIVE`]).
    pub const DERIVE: u32 = 1 << 8;
}

/// Longest key label. Labels name a key across restarts, so this bounds
/// what a backend must be able to store and index.
pub const MAX_LABEL: usize = 64;

/// The little-endian `u16` at `b[at..]`.
fn rd16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

/// The little-endian `u32` at `b[at..]`.
fn rd32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Write `bytes` at `b[at..]`; false when they do not fit.
fn wr(b: &mut [u8], at: usize, bytes: &[u8]) -> bool {
    match at
        .checked_add(bytes.len())
        .and_then(|end| b.get_mut(at..end))
    {
        Some(d) => {
            d.copy_from_slice(bytes);
            true
        }
        None => false,
    }
}

/// The `len` field of an op that has one: read and rewritten at `at`.
fn len_at(arg: &[u8], at: usize) -> Option<usize> {
    rd32(arg, at).map(|n| n as usize)
}

/// Write `n` into the `len` field at `at`; false when `arg` is short.
fn set_len_at(arg: &mut [u8], at: usize, n: usize) -> bool {
    wr(arg, at, &(n as u32).to_le_bytes())
}

/// [`STORE`]: arg in `[suite:u16][usage:u32]`; `data` in = the key.
pub mod store {
    pub const ARG_LEN: usize = 6;
    /// Most bytes a key may hold: the RSA-4096 DER ceiling, with room.
    pub const KEY_MAX: usize = 4096;

    pub const fn encode(suite: u16, usage: u32) -> [u8; ARG_LEN] {
        let s = suite.to_le_bytes();
        let u = usage.to_le_bytes();
        [s[0], s[1], u[0], u[1], u[2], u[3]]
    }

    /// `(suite, usage)`.
    pub fn parse(arg: &[u8]) -> Option<(u16, u32)> {
        Some((super::rd16(arg, 0)?, super::rd32(arg, 2)?))
    }
}

/// [`SIGN`]: arg inout `[mode:u8][0:u8][len:u32]`. In: `len` is how many
/// bytes at the head of `data` are the input. Out on `ERANGE`: `len` is the
/// signature length `data` must hold.
pub mod sign {
    pub const ARG_LEN: usize = 6;
    pub const LEN: usize = 2;
    /// Most bytes a P-256 `DIGEST` input may hold.
    pub const DIGEST_MAX: usize = 64;
    /// A resumable job not advanced for this long is abandoned.
    pub const JOB_IDLE_MS: u64 = 1000;

    pub const fn encode(mode: u8, len: u32) -> [u8; ARG_LEN] {
        let l = len.to_le_bytes();
        [mode, 0, l[0], l[1], l[2], l[3]]
    }

    /// `(mode, len)`.
    pub fn parse(arg: &[u8]) -> Option<(u8, usize)> {
        if arg.len() < ARG_LEN {
            return None;
        }
        Some((arg[0], super::len_at(arg, LEN)?))
    }

    /// The length field: the requirement after `ERANGE`.
    pub fn len(arg: &[u8]) -> Option<usize> {
        super::len_at(arg, LEN)
    }

    pub fn set_len(arg: &mut [u8], n: usize) -> bool {
        super::set_len_at(arg, LEN, n)
    }
}

/// [`ECDH`]: arg inout `[len:u32]`. In: `len` is the peer key's length at
/// the head of `data`. Out on `ERANGE`: the secret's length.
pub mod ecdh {
    pub const ARG_LEN: usize = 4;
    pub const LEN: usize = 0;
    /// Most bytes a peer key may hold.
    pub const PEER_MAX: usize = 256;

    pub const fn encode(len: u32) -> [u8; ARG_LEN] {
        len.to_le_bytes()
    }

    pub fn parse(arg: &[u8]) -> Option<usize> {
        super::len_at(arg, LEN)
    }

    pub fn set_len(arg: &mut [u8], n: usize) -> bool {
        super::set_len_at(arg, LEN, n)
    }
}

/// [`VERIFY`]: arg in `[msg_len:u32][sig_len:u16][pub_len:u16]`; `data` in =
/// message ‖ signature ‖ public key.
pub mod verify {
    pub const ARG_LEN: usize = 8;

    /// The lengths of the three parts of `data`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Lens {
        pub msg: usize,
        pub sig: usize,
        pub public: usize,
    }

    impl Lens {
        /// Bytes of `data` the three parts take.
        pub const fn total(&self) -> usize {
            self.msg + self.sig + self.public
        }
    }

    pub const fn encode(msg: u32, sig: u16, public: u16) -> [u8; ARG_LEN] {
        let m = msg.to_le_bytes();
        let s = sig.to_le_bytes();
        let p = public.to_le_bytes();
        [m[0], m[1], m[2], m[3], s[0], s[1], p[0], p[1]]
    }

    pub fn parse(arg: &[u8]) -> Option<Lens> {
        Some(Lens {
            msg: super::rd32(arg, 0)? as usize,
            sig: super::rd16(arg, 4)? as usize,
            public: super::rd16(arg, 6)? as usize,
        })
    }

    /// `data` split into `(message, signature, public key)`, or `None` when
    /// it does not hold them.
    pub fn split(data: &[u8], l: Lens) -> Option<(&[u8], &[u8], &[u8])> {
        let msg_end = l.msg;
        let sig_end = msg_end.checked_add(l.sig)?;
        let end = sig_end.checked_add(l.public)?;
        if end > data.len() {
            return None;
        }
        Some((
            &data[..msg_end],
            &data[msg_end..sig_end],
            &data[sig_end..end],
        ))
    }
}

/// [`GENERATE`]: arg inout `[suite:u16][usage:u32][flags:u8][0:u8][len:u32]`.
/// Out: `len` is the public key's length (written, or required on
/// `ERANGE`).
pub mod generate {
    pub const ARG_LEN: usize = 12;
    pub const LEN: usize = 8;

    /// Bits of `flags`.
    pub mod flags {
        /// Request a non-extractable private key. A backend that cannot
        /// honour this refuses the GENERATE outright rather than silently
        /// producing an extractable key — a caller asking for
        /// non-extractability is asking for a guarantee, and quietly not
        /// providing it is worse than saying no.
        pub const NON_EXTRACTABLE: u8 = 0x01;
    }

    pub const fn encode(suite: u16, usage: u32, flags: u8) -> [u8; ARG_LEN] {
        let s = suite.to_le_bytes();
        let u = usage.to_le_bytes();
        [s[0], s[1], u[0], u[1], u[2], u[3], flags, 0, 0, 0, 0, 0]
    }

    /// `(suite, usage, flags)`.
    pub fn parse(arg: &[u8]) -> Option<(u16, u32, u8)> {
        if arg.len() < ARG_LEN {
            return None;
        }
        Some((super::rd16(arg, 0)?, super::rd32(arg, 2)?, arg[6]))
    }

    pub fn len(arg: &[u8]) -> Option<usize> {
        super::len_at(arg, LEN)
    }

    pub fn set_len(arg: &mut [u8], n: usize) -> bool {
        super::set_len_at(arg, LEN, n)
    }
}

/// [`PUBLIC`]: arg out `[len:u32]`, written only on `ERANGE` (the
/// requirement).
pub mod public {
    pub const ARG_LEN: usize = 4;
    /// Longest public key any suite has (ML-DSA-87's 2592 bytes, with room).
    pub const MAX: usize = 4096;

    pub fn len(arg: &[u8]) -> Option<usize> {
        super::len_at(arg, 0)
    }

    pub fn set_len(arg: &mut [u8], n: usize) -> bool {
        super::set_len_at(arg, 0, n)
    }
}

/// [`TIER`]: arg out `[tier:u8]`.
pub mod tier_arg {
    pub const ARG_LEN: usize = 1;
}

/// [`OPEN`] / [`OPEN_OR_GENERATE`]: arg inout
/// `[suite:u16][usage:u32][flags:u8][label_len:u8][len:u32][label]`. Out:
/// `len` is the public key's length (written, or required on `ERANGE`).
pub mod open {
    pub const HEADER: usize = 12;
    pub const LEN: usize = 8;
    pub const LABEL: usize = HEADER;
    pub const MAX_ARG: usize = HEADER + super::MAX_LABEL;

    pub const fn arg_len(label_len: usize) -> usize {
        HEADER + label_len
    }

    #[derive(Clone, Copy, Debug)]
    pub struct Request<'a> {
        pub suite: u16,
        pub usage: u32,
        pub flags: u8,
        pub label: &'a [u8],
    }

    /// Encode `r` into `out`; the bytes written, `None` when the label is
    /// empty, too long or `out` short.
    pub fn encode(out: &mut [u8], r: &Request<'_>) -> Option<usize> {
        let n = arg_len(r.label.len());
        if r.label.is_empty() || r.label.len() > super::MAX_LABEL || out.len() < n {
            return None;
        }
        out[..HEADER].fill(0);
        out[0..2].copy_from_slice(&r.suite.to_le_bytes());
        out[2..6].copy_from_slice(&r.usage.to_le_bytes());
        out[6] = r.flags;
        out[7] = r.label.len() as u8;
        out[LABEL..n].copy_from_slice(r.label);
        Some(n)
    }

    pub fn parse(arg: &[u8]) -> Option<Request<'_>> {
        if arg.len() < HEADER {
            return None;
        }
        let label_len = arg[7] as usize;
        if label_len == 0 || label_len > super::MAX_LABEL {
            return None;
        }
        Some(Request {
            suite: super::rd16(arg, 0)?,
            usage: super::rd32(arg, 2)?,
            flags: arg[6],
            label: arg.get(LABEL..LABEL + label_len)?,
        })
    }

    pub fn len(arg: &[u8]) -> Option<usize> {
        super::len_at(arg, LEN)
    }

    pub fn set_len(arg: &mut [u8], n: usize) -> bool {
        super::set_len_at(arg, LEN, n)
    }
}

/// [`DESTROY_BY_LABEL`]: arg in `[label_len:u8][label]`.
pub mod destroy_by_label {
    pub const MAX_ARG: usize = 1 + super::MAX_LABEL;

    pub const fn arg_len(label_len: usize) -> usize {
        1 + label_len
    }

    pub fn encode(out: &mut [u8], label: &[u8]) -> Option<usize> {
        let n = arg_len(label.len());
        if label.is_empty() || label.len() > super::MAX_LABEL || out.len() < n {
            return None;
        }
        out[0] = label.len() as u8;
        out[1..n].copy_from_slice(label);
        Some(n)
    }

    pub fn parse(arg: &[u8]) -> Option<&[u8]> {
        let n = *arg.first()? as usize;
        if n == 0 || n > super::MAX_LABEL {
            return None;
        }
        arg.get(1..1 + n)
    }
}

/// [`DESCRIBE`]: arg out `[suite:u16][usage:u32][tier:u8][persisted:u8]`.
pub mod describe {
    pub const ARG_LEN: usize = 8;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Described {
        pub suite: u16,
        pub usage: u32,
        pub tier: u8,
        /// A [`super::persisted`] value.
        pub persisted: u8,
    }

    pub const fn encode(d: &Described) -> [u8; ARG_LEN] {
        let s = d.suite.to_le_bytes();
        let u = d.usage.to_le_bytes();
        [s[0], s[1], u[0], u[1], u[2], u[3], d.tier, d.persisted]
    }

    pub fn parse(arg: &[u8]) -> Option<Described> {
        if arg.len() < ARG_LEN {
            return None;
        }
        Some(Described {
            suite: super::rd16(arg, 0)?,
            usage: super::rd32(arg, 2)?,
            tier: arg[6],
            persisted: arg[7],
        })
    }
}

/// `persisted` values of [`DESCRIBE`].
pub mod persisted {
    /// Gone after a restart.
    pub const NO: u8 = 0;
    /// Kept sealed: the medium holds it opaque.
    pub const SEALED: u8 = 1;
    /// Kept READABLE (the vault's store is seal mode `none`): whoever holds
    /// the medium holds the key. A consumer that needs a key protected at
    /// rest refuses this, as it refuses a tier it did not ask for.
    pub const CLEAR: u8 = 2;
}

/// [`DESCRIBE_SUITE`]: arg inout. In `[cursor:u16]`; out the record
/// `[suite:u16][next:u16][usage:u32][priv_len:u16][pub_len:u16]
/// [sig_len:u16][secret_len:u16][flags:u8][0:u8 ×3]`.
///
/// `usage` is every use the vault permits a key of the suite (its supported
/// operations); `priv_len` what [`STORE`] takes (0 where import is refused),
/// `pub_len` the longest public key, `sig_len` the signature (or tag),
/// `secret_len` the [`ECDH`] secret, each 0 where the suite has none.
pub mod describe_suite {
    pub const LEN: usize = 20;
    pub const ARG_LEN: usize = LEN;

    pub mod flags {
        /// [`super::super::STORE`] imports a key of the suite.
        pub const IMPORT: u8 = 0x01;
        /// [`super::super::GENERATE`] makes one.
        pub const GENERATE: u8 = 0x02;
        /// [`super::super::SIGN`] runs as a resumable job (module header).
        pub const RESUMABLE_SIGN: u8 = 0x04;
    }

    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct Record {
        pub suite: u16,
        /// The cursor that continues the enumeration.
        pub next: u16,
        pub usage: u32,
        pub priv_len: u16,
        pub pub_len: u16,
        pub sig_len: u16,
        pub secret_len: u16,
        pub flags: u8,
    }

    pub const fn encode_cursor(cursor: u16) -> [u8; ARG_LEN] {
        let c = cursor.to_le_bytes();
        let mut a = [0u8; ARG_LEN];
        a[0] = c[0];
        a[1] = c[1];
        a
    }

    pub fn parse_cursor(arg: &[u8]) -> Option<u16> {
        super::rd16(arg, 0)
    }

    pub const fn encode(r: &Record) -> [u8; LEN] {
        let s = r.suite.to_le_bytes();
        let n = r.next.to_le_bytes();
        let u = r.usage.to_le_bytes();
        let pr = r.priv_len.to_le_bytes();
        let pu = r.pub_len.to_le_bytes();
        let sg = r.sig_len.to_le_bytes();
        let se = r.secret_len.to_le_bytes();
        [
            s[0], s[1], n[0], n[1], u[0], u[1], u[2], u[3], pr[0], pr[1], pu[0], pu[1], sg[0],
            sg[1], se[0], se[1], r.flags, 0, 0, 0,
        ]
    }

    pub fn parse(arg: &[u8]) -> Option<Record> {
        if arg.len() < LEN {
            return None;
        }
        Some(Record {
            suite: super::rd16(arg, 0)?,
            next: super::rd16(arg, 2)?,
            usage: super::rd32(arg, 4)?,
            priv_len: super::rd16(arg, 8)?,
            pub_len: super::rd16(arg, 10)?,
            sig_len: super::rd16(arg, 12)?,
            secret_len: super::rd16(arg, 14)?,
            flags: arg[16],
        })
    }
}

/// [`ATTEST_COMPOSITION`]: arg inout `[challenge:32][len:u32]`. Out on
/// `ERANGE`: `len` is the length `data` must hold.
pub mod attest_composition {
    pub const ARG_LEN: usize = 36;
    pub const LEN: usize = 32;

    pub fn encode(challenge: &[u8; 32]) -> [u8; ARG_LEN] {
        let mut a = [0u8; ARG_LEN];
        a[..32].copy_from_slice(challenge);
        a
    }

    pub fn parse(arg: &[u8]) -> Option<[u8; 32]> {
        let mut c = [0u8; 32];
        c.copy_from_slice(arg.get(..32)?);
        Some(c)
    }

    pub fn len(arg: &[u8]) -> Option<usize> {
        super::len_at(arg, LEN)
    }

    pub fn set_len(arg: &mut [u8], n: usize) -> bool {
        super::set_len_at(arg, LEN, n)
    }
}

/// [`KEY_WRAP`]: arg inout `[dest_pub:65][attest_digest:32][len:u32]`, the
/// destination's P-256 public key and the composition digest from its
/// [`ATTEST_COMPOSITION`] record. Out on `ERANGE`: `len` is the wrapped
/// key's length.
pub mod key_wrap {
    pub const DEST_PUB: usize = 0;
    pub const ATTEST: usize = super::wrap::EPH_PUB_LEN;
    pub const LEN: usize = ATTEST + 32;
    pub const ARG_LEN: usize = LEN + 4;

    pub fn encode(dest_pub: &[u8; super::wrap::EPH_PUB_LEN], attest: &[u8; 32]) -> [u8; ARG_LEN] {
        let mut a = [0u8; ARG_LEN];
        a[DEST_PUB..ATTEST].copy_from_slice(dest_pub);
        a[ATTEST..LEN].copy_from_slice(attest);
        a
    }

    /// `(dest_pub, attest_digest)`.
    pub fn parse(arg: &[u8]) -> Option<(&[u8], &[u8])> {
        if arg.len() < ARG_LEN {
            return None;
        }
        Some((&arg[DEST_PUB..ATTEST], &arg[ATTEST..LEN]))
    }

    pub fn len(arg: &[u8]) -> Option<usize> {
        super::len_at(arg, LEN)
    }

    pub fn set_len(arg: &mut [u8], n: usize) -> bool {
        super::set_len_at(arg, LEN, n)
    }
}

/// [`AEAD_SEAL`] / [`AEAD_OPEN`]: arg `[nonce:12][len:u32][aad_len:u16]
/// [aad]`. `AEAD_SEAL`: `nonce` out (the vault draws it), `len` in = the
/// plaintext's length (out on `ERANGE`: `len + TAG_LEN`). `AEAD_OPEN`:
/// `nonce` in, `len` in = the sealed length (ciphertext and tag).
pub mod aead {
    pub const NONCE: usize = 0;
    pub const NONCE_LEN: usize = 12;
    pub const LEN: usize = 12;
    pub const AAD_LEN: usize = 16;
    pub const AAD: usize = 18;
    pub const HEADER: usize = AAD;
    pub const MAX_AAD: usize = 256;
    pub const MAX_ARG: usize = HEADER + MAX_AAD;
    pub const TAG_LEN: usize = 16;
    /// Longest plaintext one call seals: a ticket, a checkpoint chunk.
    pub const MAX_LEN: usize = 65536;

    pub const fn arg_len(aad_len: usize) -> usize {
        HEADER + aad_len
    }

    /// Encode a request into `out`: the bytes written, `None` when `aad` is
    /// too long or `out` short. `nonce` is ignored by `AEAD_SEAL`.
    pub fn encode(out: &mut [u8], nonce: &[u8; NONCE_LEN], len: u32, aad: &[u8]) -> Option<usize> {
        let n = arg_len(aad.len());
        if aad.len() > MAX_AAD || out.len() < n {
            return None;
        }
        out[NONCE..NONCE + NONCE_LEN].copy_from_slice(nonce);
        out[LEN..LEN + 4].copy_from_slice(&len.to_le_bytes());
        out[AAD_LEN..AAD_LEN + 2].copy_from_slice(&(aad.len() as u16).to_le_bytes());
        out[AAD..n].copy_from_slice(aad);
        Some(n)
    }

    #[derive(Clone, Copy, Debug)]
    pub struct Request<'a> {
        pub nonce: [u8; NONCE_LEN],
        pub len: usize,
        pub aad: &'a [u8],
    }

    pub fn parse(arg: &[u8]) -> Option<Request<'_>> {
        let aad_len = super::rd16(arg, AAD_LEN)? as usize;
        if aad_len > MAX_AAD {
            return None;
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(arg.get(NONCE..NONCE + NONCE_LEN)?);
        Some(Request {
            nonce,
            len: super::len_at(arg, LEN)?,
            aad: arg.get(AAD..AAD + aad_len)?,
        })
    }

    pub fn set_nonce(arg: &mut [u8], nonce: &[u8; NONCE_LEN]) -> bool {
        super::wr(arg, NONCE, nonce)
    }

    pub fn nonce(arg: &[u8]) -> Option<[u8; NONCE_LEN]> {
        let mut n = [0u8; NONCE_LEN];
        n.copy_from_slice(arg.get(NONCE..NONCE + NONCE_LEN)?);
        Some(n)
    }

    pub fn set_len(arg: &mut [u8], n: usize) -> bool {
        super::set_len_at(arg, LEN, n)
    }

    pub fn len(arg: &[u8]) -> Option<usize> {
        super::len_at(arg, LEN)
    }
}

/// [`DERIVE`]: arg in `[target_suite:u16][target_usage:u32][label_len:u8]
/// [0:u8][context_len:u16][label][context]`.
pub mod derive {
    pub const TARGET_SUITE: usize = 0;
    pub const TARGET_USAGE: usize = 2;
    pub const LABEL_LEN: usize = 6;
    pub const CONTEXT_LEN: usize = 8;
    /// Where the label starts; the context follows it.
    pub const LABEL: usize = 10;
    pub const MAX_LABEL: usize = 64;
    pub const MAX_CONTEXT: usize = 128;
    pub const MAX_ARG: usize = LABEL + MAX_LABEL + MAX_CONTEXT;
    /// The HKDF salt every derivation uses.
    pub const SALT: &[u8] = b"fluxor/v1";

    pub const fn arg_len(label_len: usize, context_len: usize) -> usize {
        LABEL + label_len + context_len
    }

    #[derive(Clone, Copy, Debug)]
    pub struct Request<'a> {
        pub suite: u16,
        pub usage: u32,
        pub label: &'a [u8],
        pub context: &'a [u8],
    }

    pub fn encode(out: &mut [u8], r: &Request<'_>) -> Option<usize> {
        let n = arg_len(r.label.len(), r.context.len());
        if r.label.is_empty()
            || r.label.len() > MAX_LABEL
            || r.context.len() > MAX_CONTEXT
            || out.len() < n
        {
            return None;
        }
        out[..LABEL].fill(0);
        out[TARGET_SUITE..TARGET_SUITE + 2].copy_from_slice(&r.suite.to_le_bytes());
        out[TARGET_USAGE..TARGET_USAGE + 4].copy_from_slice(&r.usage.to_le_bytes());
        out[LABEL_LEN] = r.label.len() as u8;
        out[CONTEXT_LEN..CONTEXT_LEN + 2].copy_from_slice(&(r.context.len() as u16).to_le_bytes());
        let c = LABEL + r.label.len();
        out[LABEL..c].copy_from_slice(r.label);
        out[c..n].copy_from_slice(r.context);
        Some(n)
    }

    pub fn parse(arg: &[u8]) -> Option<Request<'_>> {
        let label_len = *arg.get(LABEL_LEN)? as usize;
        let context_len = super::rd16(arg, CONTEXT_LEN)? as usize;
        if label_len == 0 || label_len > MAX_LABEL || context_len > MAX_CONTEXT {
            return None;
        }
        let c = LABEL + label_len;
        Some(Request {
            suite: super::rd16(arg, TARGET_SUITE)?,
            usage: super::rd32(arg, TARGET_USAGE)?,
            label: arg.get(LABEL..c)?,
            context: arg.get(c..c + context_len)?,
        })
    }
}

/// [`AEAD_SEAL_UNITS`] / [`AEAD_OPEN_UNITS`]: arg `[nonce:12][tag:16]
/// [aad_len:u16][aad]`. Seal: `tag` out. Open: `tag` in. `data` = the unit.
pub mod units {
    pub const NONCE: usize = 0;
    pub const TAG: usize = 12;
    pub const TAG_LEN: usize = 16;
    pub const AAD_LEN: usize = 28;
    pub const AAD: usize = 30;
    pub const HEADER: usize = AAD;
    /// Longest associated data per unit.
    pub const MAX_AAD: usize = 128;
    pub const MAX_ARG: usize = HEADER + MAX_AAD;
    /// Longest unit one call seals or opens: bounds the work done inside
    /// the caller's step.
    pub const MAX_UNIT: usize = 65536;

    pub const fn arg_len(aad_len: usize) -> usize {
        HEADER + aad_len
    }

    /// Encode a request into `out`: the bytes written. `tag` is ignored by
    /// a seal.
    pub fn encode(
        out: &mut [u8],
        nonce: &[u8; 12],
        tag: &[u8; TAG_LEN],
        aad: &[u8],
    ) -> Option<usize> {
        let n = arg_len(aad.len());
        if aad.len() > MAX_AAD || out.len() < n {
            return None;
        }
        out[NONCE..NONCE + 12].copy_from_slice(nonce);
        out[TAG..TAG + TAG_LEN].copy_from_slice(tag);
        out[AAD_LEN..AAD_LEN + 2].copy_from_slice(&(aad.len() as u16).to_le_bytes());
        out[AAD..n].copy_from_slice(aad);
        Some(n)
    }

    #[derive(Clone, Copy, Debug)]
    pub struct Request<'a> {
        pub nonce: [u8; 12],
        pub tag: [u8; TAG_LEN],
        pub aad: &'a [u8],
    }

    pub fn parse(arg: &[u8]) -> Option<Request<'_>> {
        let aad_len = super::rd16(arg, AAD_LEN)? as usize;
        if aad_len > MAX_AAD {
            return None;
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(arg.get(NONCE..NONCE + 12)?);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(arg.get(TAG..TAG + TAG_LEN)?);
        Some(Request {
            nonce,
            tag,
            aad: arg.get(AAD..AAD + aad_len)?,
        })
    }

    pub fn tag(arg: &[u8]) -> Option<[u8; TAG_LEN]> {
        let mut t = [0u8; TAG_LEN];
        t.copy_from_slice(arg.get(TAG..TAG + TAG_LEN)?);
        Some(t)
    }

    pub fn set_tag(arg: &mut [u8], tag: &[u8; TAG_LEN]) -> bool {
        super::wr(arg, TAG, tag)
    }
}

/// Share envelopes (the recovery and attachment format): one 2-of-3 share
/// of a 32-byte key, sealed to one recipient's P-256 key.
///
/// ```text
/// [magic "FXSE"][kem:u16][aead:u16][purpose:u8][index:u8][threshold:u8]
/// [count:u8][set_id:16][resource:16][epoch:u32][recipient_thumbprint:32]
/// [fence:u64][expiry_ms:u64][anti_replay:16][policy:32][enc_len:u16]
/// [encapsulation][ciphertext:33][tag:16]
/// ```
///
/// `recipient_thumbprint` is SHA-256 of the recipient's uncompressed public
/// key. The key is `HKDF-SHA256(ikm = ECDH(ephemeral, recipient),
/// salt = derive::SALT, info = "share/envelope" ‖ header)` and the AEAD
/// seals `index ‖ y` under a zero nonce with the header as associated data,
/// the header being every byte before the ciphertext. The nonce is fixed
/// because every envelope's key comes from a fresh ephemeral key.
pub mod share {
    pub const MAGIC: [u8; 4] = *b"FXSE";
    pub const KEM: usize = 4;
    pub const AEAD: usize = 6;
    pub const PURPOSE: usize = 8;
    pub const INDEX: usize = 9;
    pub const THRESHOLD: usize = 10;
    pub const COUNT: usize = 11;
    pub const SET_ID: usize = 12;
    pub const RESOURCE: usize = 28;
    pub const EPOCH: usize = 44;
    pub const RECIPIENT: usize = 48;
    pub const FENCE: usize = 80;
    pub const EXPIRY: usize = 88;
    pub const ANTI_REPLAY: usize = 96;
    pub const POLICY: usize = 112;
    pub const ENC_LEN: usize = 144;
    pub const ENC: usize = 146;
    /// The sealed share: `index(1) ‖ y(32)`.
    pub const SHARE_LEN: usize = 33;
    pub const TAG_LEN: usize = 16;

    /// KEM suites.
    pub mod kem {
        /// P-256 ECDH with an ephemeral key; the encapsulation is its
        /// 65-byte uncompressed public key.
        pub const P256: u16 = 1;
    }
    /// Envelope AEAD suites, the ids the storage formats record.
    pub mod aead {
        pub const CHACHA20_POLY1305: u16 = 1;
        /// Offered where the vault offers [`super::super::suite::AEAD_AES256_GCM`].
        pub const AES_256_GCM: u16 = 2;
    }
    pub mod purpose {
        /// Released to a node for one attach, bound to its lease fence.
        pub const ATTACHMENT: u8 = 1;
        /// Held by a recovery custodian.
        pub const RECOVERY: u8 = 2;
    }

    pub const P256_PUB_LEN: usize = 65;
    /// An envelope under [`kem::P256`].
    pub const P256_LEN: usize = ENC + P256_PUB_LEN + SHARE_LEN + TAG_LEN;
    pub const THRESHOLD_V1: u8 = 2;
    pub const COUNT_V1: u8 = 3;

    /// What a split or rewrap binds an envelope to, as the argument
    /// carries it:
    /// `[purpose:u8][_pad:u8][aead:u16][set_id:16][resource:16][epoch:u32]
    ///  [fence:u64][expiry_ms:u64][policy:32]`. A rewrap reads only the
    /// purpose, fence, expiry and policy and carries the rest over.
    pub mod grant {
        pub const PURPOSE: usize = 0;
        pub const AEAD: usize = 2;
        pub const SET_ID: usize = 4;
        pub const RESOURCE: usize = 20;
        pub const EPOCH: usize = 36;
        pub const FENCE: usize = 40;
        pub const EXPIRY: usize = 48;
        pub const POLICY: usize = 56;
        pub const LEN: usize = 88;
    }

    /// [`super::SHARE_SPLIT`]: arg in `[grant][recipient:65 ×3]`; `data` out
    /// = the three envelopes.
    pub mod split {
        use super::{grant, P256_LEN, P256_PUB_LEN};
        pub const RECIPIENTS: usize = grant::LEN;
        pub const ARG_LEN: usize = RECIPIENTS + 3 * P256_PUB_LEN;
        /// Bytes `data` must hold.
        pub const OUT_LEN: usize = 3 * P256_LEN;
    }

    /// [`super::SHARE_REWRAP`]: arg in `[grant][recipient:65]`; `data` inout
    /// = the envelope.
    pub mod rewrap {
        use super::{grant, P256_PUB_LEN};
        pub const RECIPIENT: usize = grant::LEN;
        pub const ARG_LEN: usize = RECIPIENT + P256_PUB_LEN;
    }

    /// [`super::SHARE_COMBINE`]: arg in `[target_suite:u16][target_usage:u32]
    /// [0:u16][resource:16][epoch:u32]`; `data` in = one envelope. The
    /// target suite is one a split source may hold, and the uses may not
    /// include [`super::super::usage::PERSIST`].
    pub mod combine {
        pub const TARGET_SUITE: usize = 0;
        pub const TARGET_USAGE: usize = 2;
        pub const RESOURCE: usize = 8;
        pub const EPOCH: usize = 24;
        pub const ARG_LEN: usize = 28;

        pub fn encode(suite: u16, usage: u32, resource: &[u8; 16], epoch: u32) -> [u8; ARG_LEN] {
            let mut a = [0u8; ARG_LEN];
            a[TARGET_SUITE..TARGET_SUITE + 2].copy_from_slice(&suite.to_le_bytes());
            a[TARGET_USAGE..TARGET_USAGE + 4].copy_from_slice(&usage.to_le_bytes());
            a[RESOURCE..RESOURCE + 16].copy_from_slice(resource);
            a[EPOCH..EPOCH + 4].copy_from_slice(&epoch.to_le_bytes());
            a
        }
    }
}

/// [`ATTEST_KEY`]: arg in `[challenge:32]`; `data` out = the record.
///
/// record: `["FXHA"][challenge:32][composition:32][backend:u8][tier:u8]
/// [persisted:u8][_pad:u8][suite:u16][_pad:u16][usage:u32][namespace:u32]
/// [commitment:32][public_thumbprint:32]`, where `composition` is the
/// composition digest [`KEY_WRAP`] binds to, `commitment` is
/// `HMAC-SHA256(key, "fluxor/v1 attest/commitment")` — the same key always
/// gives the same commitment and the commitment gives nothing of the key —
/// and `public_thumbprint` is SHA-256 of the public half, zero for a key
/// without one. A key a hardware backend holds has no readable bytes to
/// commit to: its commitment is zero and its public thumbprint names it.
pub mod attest_key {
    pub const ARG_LEN: usize = 32;

    pub const MAGIC: [u8; 4] = *b"FXHA";
    pub const R_CHALLENGE: usize = 4;
    pub const R_COMPOSITION: usize = 36;
    pub const R_BACKEND: usize = 68;
    pub const R_TIER: usize = 69;
    pub const R_PERSISTED: usize = 70;
    pub const R_SUITE: usize = 72;
    pub const R_USAGE: usize = 76;
    pub const R_NAMESPACE: usize = 80;
    pub const R_COMMITMENT: usize = 84;
    pub const R_THUMBPRINT: usize = 116;
    pub const RECORD_LEN: usize = 148;
    pub const COMMITMENT_LABEL: &[u8] = b"fluxor/v1 attest/commitment";

    /// Which backend holds the key.
    pub mod backend {
        pub const KERNEL: u8 = 0;
        pub const PKCS11: u8 = 1;
    }
}

/// Layout constants for [`KEY_WRAP`] output.
pub mod wrap {
    pub const MAGIC: [u8; 4] = *b"FXKW";
    pub const EPH_PUB_LEN: usize = 65;
    pub const ATTEST_OFF: usize = 4 + EPH_PUB_LEN;
    pub const NONCE_OFF: usize = ATTEST_OFF + 32;
    pub const SEALED_OFF: usize = NONCE_OFF + 12;
    /// Sealed payload prefix before the key bytes.
    pub const SEALED_PREFIX: usize = 2 + 4 + 1;
    pub const TAG_LEN: usize = 16;
    /// Longest wrapped key: a 64-byte key.
    pub const MAX_LEN: usize = SEALED_OFF + SEALED_PREFIX + 64 + TAG_LEN;
}

/// Isolation-tier ordinals written by the [`TIER`] opcode.
pub mod tier {
    /// The software backend — in-process on hosted platforms. Isolates
    /// against a compromised module, not a compromised host/kernel.
    pub const SOFTWARE: u8 = 0;
    /// Host process talking to an HSM (e.g. PKCS#11 to a token).
    /// Isolates against host compromise to the extent the token does.
    pub const PROCESS_HW: u8 = 1;
    /// On-die secure element / TPM.
    pub const DEVICE_HW: u8 = 2;
}
