// Contract: key_vault — backend-managed opaque keys: signing, agreement,
// sealing and MAC keys behind handles that never expose the key bytes.
//
// Layer: contracts (public, stable).
//
// All operations run in the registered backend; private key material
// never leaves it (kernel static slots on the software backend, a
// PKCS#11 token on a hardware backend). Callers see opaque `i32`
// handles. Arg buffers use little-endian tightly-packed layouts;
// fields starting with `*_out` are written back by the backend.
//
// Backend discovery is three-step: `PROBE` answers "is any backend
// wired", `SUITE_QUERY` answers "can you use this suite, and what does it
// cost" (per-suite, with sizes), and `TIER` answers "what isolation level
// does it provide" (ordinal, [`tier`]). A consumer MUST NOT claim a
// hardware guarantee it did not read from `TIER`.

/// Returns 1 if a key-vault backend is present, 0 if not. Call with
/// handle=-1 and arg=null to detect at `module_new`.
pub const PROBE: u32 = 0x1000;

/// Store (import) a private key. handle=-1.
///
/// arg layout:
/// ```text
/// [suite:u16][usage_mask:u32][key_len:u32][key_bytes[key_len]]
/// ```
/// Returns an opaque handle (>= 0) or negative errno. Pass the handle back
/// unmodified to SIGN / ECDH / PUBLIC / DESTROY; do not decode it.
///
/// `key_len` is a `u32` so that the field never bounds a key's encoding: an
/// ML-DSA-87 private key is 4896 bytes.
///
/// STORE is an *import* path: the key existed outside the backend and is
/// received-then-wiped, not never-present. A non-extractable HSM may refuse
/// it entirely; [`SUITE_QUERY`] reports import support per suite rather
/// than as one global bit, because tokens differ by algorithm.
///
/// `key_len` is what [`SUITE_QUERY`] reported as `priv_len_out` for the
/// suite, which is not always the algorithm's encoded private key. FIPS
/// 204 KeyGen is a deterministic function of a 32-byte seed, so a backend
/// may hold ML-DSA keys AS that seed and report 32 — the seed reproduces
/// the encoded key exactly, and a caller holding an already-expanded key
/// learns from the reported length that this backend is not where it can
/// import one.
pub const STORE: u32 = 0x1001;

/// ECDH: derive shared secret. handle = slot.
///
/// arg layout:
/// ```text
/// [peer_len:u32][peer_bytes[peer_len]]
/// [out_ptr:u64][out_cap:u16][out_len_out:u16]
/// ```
/// Returns 0 on success, `-ERANGE` with the requirement in `out_len_out`
/// when short, negative errno otherwise.
///
/// Refused unless the slot's `usage_mask` carries [`usage::AGREE`]. A
/// signing key used for key agreement is a cross-purpose reuse, and the
/// place to stop it is the mask rather than the caller's discipline.
pub const ECDH: u32 = 0x1002;

/// Sign with the slot's private key. handle = slot.
///
/// arg layout:
/// ```text
/// [sign_mode:u8][_pad:u8][input_len:u32][input[input_len]]
/// [sig_out_ptr:u64][sig_out_cap:u16][sig_len_out:u16]
/// ```
/// Returns 0 on success, `-ERANGE` with `sig_len_out` set to the
/// requirement when the buffer is short, negative errno otherwise.
///
/// `sign_mode` is on the wire rather than inferred from the suite — see
/// [`sign_mode`]. Inferring it means a caller that hands a P-256 slot a
/// message rather than its digest gets a valid signature over the wrong
/// thing, with nothing on the wire saying which convention applied.
///
/// The signature is variable-length. A fixed `[u8; 64]` is exactly right
/// for ES256 and Ed25519 and wrong for every suite past them: ML-DSA-65's
/// is 3309 bytes. Sizing from [`SUITE_QUERY`] is what lets a caller
/// allocate correctly without knowing which suite the slot holds.
///
/// - P-256: ECDSA over the digest with `DIGEST`. The software backend uses
///   the deterministic RFC 6979 nonce; a hardware backend may use random-k,
///   producing different-but-valid signatures (verify, don't byte-compare).
///   The 64-byte low-s `r‖s` output is exactly the JWS ES256 segment.
/// - Ed25519: `RAW` over the full message (RFC 8032 is not prehashed).
///   Output is the 64-byte `R‖S`, deterministic by spec on every backend.
/// - HMAC-SHA256: `RAW` over the full message; the 32-byte output is the
///   RFC 2104 tag. Deterministic, and the only thing the key ever yields.
/// - ML-DSA: `RAW` over the full message. The pure FIPS 204 variant is not
///   prehashed — HashML-DSA is a different algorithm, not a mode of this
///   one — and `PREHASH` is refused rather than answered with it. The
///   signature is 2420 / 3309 / 4627 bytes by parameter set, so a caller
///   must size its buffer from [`SUITE_QUERY`] and not from a constant.
pub const SIGN: u32 = 0x1003;

/// ECDSA verify (P-256) with a caller-supplied public key — the stored
/// slots are not consulted. handle=-1.
/// arg layout: [hash_len:u16][sig_len:u16][pub_len:u16][_pad:u16]
///             [hash_bytes[hash_len]][sig_bytes[sig_len]][pub_bytes[pub_len]]
/// - sig_len must be 64 (raw r‖s); pub_len >= 64 (SEC1 uncompressed,
///   with or without the leading 0x04 byte).
///
/// With a slot handle instead of -1 the slot must hold an
/// [`suite::HMAC_SHA256`] key permitting [`usage::VERIFY`], and the same
/// layout carries the message in the hash field, the 32-byte tag in the
/// signature field and `pub_len = 0`; the backend recomputes the tag and
/// compares in constant time. The tag is checked inside the backend rather
/// than handed to the caller to compare, so the comparison cannot be
/// written wrong at any of the places it would otherwise be written.
///
/// Returns 1 if valid, 0 if invalid, negative errno on malformed input.
pub const VERIFY: u32 = 0x1004;

/// Zeroise and free the slot. handle = slot. Returns 0.
pub const DESTROY: u32 = 0x1005;

/// Generate a keypair inside the backend. handle=-1.
///
/// arg layout:
/// ```text
/// [suite:u16][usage_mask:u32][flags:u8][_pad:u8]
/// [pub_out_ptr:u64][pub_out_cap:u16][pub_len_out:u16]
/// ```
/// Returns an opaque handle (>= 0) or negative errno, with the public key
/// written into `pub_out_ptr` and its length into `pub_len_out`;
/// `-ERANGE` with the requirement in `pub_len_out` when short.
///
/// The private key is born in backend custody and never exists in the
/// clear anywhere — the only path that gives true "key never leaves", and
/// the only one a non-extractable HSM supports.
///
/// `usage_mask` is sealed into the key here and checked on every later
/// operation. Sealed at birth rather than checked at the call site,
/// because a call-site check is one some call site will not have.
pub const GENERATE: u32 = 0x1006;

/// Return the public key for a slot (for JWK/JWKS/kid derivation).
///
/// handle = slot. arg layout:
/// `[out_ptr:u64][out_cap:u16][out_len_out:u16]`. Returns 0, or `-ERANGE`
/// with the requirement in `out_len_out`.
///
/// Public material only, and refused unless the slot's `usage_mask`
/// carries [`usage::EXPORT_PUBLIC`] — which never implies the private half
/// may be exported.
pub const PUBLIC: u32 = 0x1007;

/// Report the backend's isolation tier. handle=-1, arg → 1-byte
/// buffer; writes a `u8` ordinal (see [`tier`]), returns 1.
///
/// Tiers are mutually-exclusive ordinal levels (not independent
/// capabilities, hence not per-suite); a consumer with a security
/// requirement checks `tier >= N` and MUST NOT claim a hardware
/// guarantee it did not read from here.
pub const TIER: u32 = 0x1008;

/// Key suites: what a slot's key bytes mean, which operations it admits,
/// and how big each answer is.
///
/// A `u16` because the space this has to hold is large: each post-quantum
/// family comes in several parameter sets, and every hybrid is its own
/// entry.
///
/// **Naming a suite is not implementing it.** [`SUITE_QUERY`] is the only
/// thing that says whether a backend can use one: `P384` and `ML_KEM_768`
/// are ids a backend may report `ENOSYS` for.
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
    /// A 32-byte ChaCha20-Poly1305 key for [`AEAD_SEAL`] / [`AEAD_OPEN`]:
    /// the shape a resumption-ticket key or any other sealing key takes.
    /// It signs nothing and has no public half.
    pub const AEAD_KEY: u16 = 8;
    /// A 32-byte HMAC-SHA256 key (RFC 2104): a shared secret whose tag is
    /// produced by [`SIGN`] and checked by [`VERIFY`] against the slot.
    /// The shape a TSIG key (RFC 8945) takes. It has no public half and is
    /// never readable back: the only answers a holder gets are tags.
    pub const HMAC_SHA256: u16 = 9;
    /// RSA keys by modulus width, for RSASSA-PSS-SHA256 signatures over a
    /// caller-supplied SHA-256 digest ([`sign_mode::DIGEST`]) with a
    /// 32-byte salt — the one encoding TLS 1.3 asks of an rsaEncryption
    /// key. One suite per width because [`SUITE_QUERY`] reports fixed
    /// lengths per suite. The private key a backend holds is the PKCS#1
    /// `RSAPrivateKey` DER with its CRT fields; the reported private
    /// length is the CEILING for the width, and [`STORE`] admits any DER
    /// up to it. A signature is the modulus width; the public half is the
    /// `RSAPublicKey` DER.
    ///
    /// A private operation is milliseconds on the fastest target this
    /// runs on, and a [`SIGN`] runs inside the caller's step, so RSA
    /// signing is RESUMABLE: the first `SIGN` on a slot starts the
    /// operation and answers `EAGAIN` after a bounded amount of it; each
    /// further `SIGN` with the same digest advances it and answers
    /// `EAGAIN` until the last, which answers the signature. A `SIGN`
    /// with another digest, or on another slot, while one is in progress
    /// answers `EBUSY`. A backend that signs whole (a token) simply never
    /// answers `EAGAIN`.
    pub const RSA_2048: u16 = 10;
    pub const RSA_3072: u16 = 11;
    pub const RSA_4096: u16 = 12;

    /// A sealing key for AES-256-GCM, 32 bytes, no public half. Offered
    /// only where the block cipher runs in constant time: elsewhere
    /// `SUITE_QUERY` answers `ENOSYS`, and `AEAD_KEY` is the sealing suite.
    pub const AEAD_AES256_GCM: u16 = 13;
    /// A key-derivation master, 32 bytes, no public half: its only use is
    /// [`super::usage::DERIVE`], which makes purpose keys from it. A volume,
    /// WAL or snapshot key is one, so no purpose key is ever the master.
    pub const KDF_KEY: u16 = 14;

    /// Highest id this registry defines.
    pub const MAX_ID: u16 = KDF_KEY;
}

/// How [`SIGN`] should treat the bytes it is given.
///
/// On the wire rather than inferred from the suite. Inference would hold
/// only while each suite has one convention — a P-256 slot gets a digest,
/// an Ed25519 slot gets the whole message — and it requires the caller to
/// know which without the wire ever saying, so a caller that hands a P-256
/// slot a message rather than its digest gets a valid signature over the
/// wrong thing.
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
    /// (Ed25519ctx, ML-DSA's context parameter).
    ///
    /// The [`SIGN`] arg layout carries no context field, so a backend
    /// that cannot express the request refuses it rather than signing
    /// under the empty context: a signature in a domain the caller did
    /// not ask for is worse than no signature, because it verifies.
    pub const CONTEXT: u8 = 3;
}

/// What a key may be used for, sealed at creation and checked per
/// operation.
///
/// A key created for signing must not later be usable for key agreement,
/// however convenient that would be at the call site. Cross-purpose reuse
/// is the shape behind a long list of protocol breaks, and the only
/// reliable place to stop it is where the key is born — a check at the
/// call site is a check some call site will not have.
pub mod usage {
    pub const SIGN: u32 = 1 << 0;
    pub const VERIFY: u32 = 1 << 1;
    pub const AGREE: u32 = 1 << 2;
    /// The public half may be exported. Never implies the private half
    /// can be.
    pub const EXPORT_PUBLIC: u32 = 1 << 3;
    /// The key may be persisted across a restart — and note that
    /// persistence says nothing about isolation, which is [`TIER`]'s
    /// business.
    pub const PERSIST: u32 = 1 << 4;
    /// The key may leave the vault WRAPPED ([`KEY_WRAP`]): sealed to a
    /// destination vault's public key and bound to that vault's attested
    /// composition, never in the clear. A key without this bit never
    /// leaves at all.
    pub const WRAP: u32 = 1 << 5;
    /// The key may seal ([`AEAD_SEAL`], [`AEAD_SEAL_UNITS`]).
    pub const SEAL: u32 = 1 << 6;
    /// Derive purpose keys from this key ([`super::DERIVE`]).
    pub const DERIVE: u32 = 1 << 8;
    /// The key may open ([`AEAD_OPEN`], [`AEAD_OPEN_UNITS`]).
    pub const OPEN: u32 = 1 << 7;
}

/// Longest key label. Labels name a key across restarts, so this bounds
/// what a backend must be able to store and index.
pub const MAX_LABEL: usize = 64;

/// Open the key named by `label`, generating it if it does not exist.
///
/// handle=-1. arg layout:
/// ```text
/// [suite:u16][usage_mask:u32][flags:u8][label_len:u8]
/// [label[label_len]]
/// [pub_out_ptr:u64][pub_out_cap:u16][pub_len_out:u16]
/// ```
/// Returns an opaque handle (>= 0), or a negative errno:
/// - `-EACCES`: the key exists under another suite, or with fewer uses than
///   `usage_mask` asks for;
/// - `-EBUSY`: another instance of the caller's module type holds the key
///   open;
/// - `-ENOMEM`: no slot is free;
/// - `-ERANGE`: the public-key buffer is short (nothing was opened or made).
///
/// **This is the operation that makes an issuer key survive a restart**,
/// and it is one operation rather than "does it exist?" then "create it"
/// because those two are a race: two instances starting together would
/// both see absence and both generate, and one would then be signing
/// under a key nothing else trusts.
///
/// `usage_mask` is sealed into the key at creation. On an existing key it
/// is CHECKED, not applied: reopening with a wider mask than the key was
/// born with is refused, because a key's permitted uses must not be
/// something a later caller can widen by asking.
///
/// Writes the public key into `pub_out_ptr` and its length into
/// `pub_len_out`. When the buffer is too small the call returns `-ERANGE`
/// with `pub_len_out` set to what was required — the caller resizes once
/// rather than guessing, which matters when a suite's public key is 2 KB.
pub const OPEN_OR_GENERATE: u32 = 0x1009;

/// Open an existing key by label, failing if absent.
///
/// handle=-1, same arg layout as [`OPEN_OR_GENERATE`]. Returns `-ENOENT`
/// when no key of that label exists.
///
/// Separate from `OPEN_OR_GENERATE` because "use the existing issuer key"
/// and "use it, creating one if needed" are different intentions, and a
/// verifier that silently generated a key would verify nothing while
/// appearing to work.
pub const OPEN: u32 = 0x100A;

/// Destroy the key named by `label`, wherever it is stored.
///
/// handle=-1. arg layout: `[label_len:u8][label[label_len]]`.
/// Returns 0, `-ENOENT` when no key has the label, or the generic error
/// (`-1`) when the sealed record could not be removed (it would come back).
///
/// By label rather than by handle because the point is to remove the
/// PERSISTED key: destroying a handle frees a slot and leaves the sealed
/// blob, which would come back on the next open.
pub const DESTROY_BY_LABEL: u32 = 0x100B;

/// Report what a slot is.
///
/// handle = slot. arg layout:
/// `[suite_out:u16][usage_out:u32][tier_out:u8][persisted_out:u8]`.
/// Returns 8 on success.
///
/// Exists so a consumer can check what it actually got rather than what
/// it asked for. `persisted_out` sits next to `tier_out` and is
/// deliberately separate from it: a caller that conflates the two is the
/// failure mode this whole surface is shaped to prevent.
pub const DESCRIBE: u32 = 0x100C;

/// Ask whether a backend can use `suite`, and what it costs.
///
/// handle=-1. arg layout:
/// ```text
/// [suite:u16][_pad:u16]
/// [usage_out:u32][priv_len_out:u16][pub_len_out:u16][sig_len_out:u16]
/// ```
/// Returns 14 when the suite is supported, `-ENOSYS` when it is not.
///
/// Lengths rather than a capability bitmap, because a bitmap answers "is
/// P-256 supported" and cannot answer "how big is an ML-DSA-65
/// signature" — which is what a caller sizing a buffer actually needs,
/// and the question a suite whose signature is 4627 bytes forces.
pub const SUITE_QUERY: u32 = 0x100D;

/// Enumerate supported suites.
///
/// handle=-1. arg layout:
/// `[cursor:u16][_pad:u16][out_ptr:u64][out_cap:u16][count_out:u16]`;
/// writes `count_out` `u16` suite ids. Returns the next cursor, or 0 when
/// the enumeration is complete.
pub const SUITE_ENUM: u32 = 0x100E;

/// Sign the running composition. handle = a signing slot. arg layout:
/// `[challenge:32][out_ptr:u64][out_cap:u16][out_len_out:u16]`; the
/// output is `[record][signature]`, where the record is the kernel's
/// composition record (`scheduler::attest`, prefix `"FXAT"`) ending in
/// the vault's tier byte, and the signature is over the record in the
/// slot's suite convention: ECDSA over the record's SHA-256 for P-256,
/// the whole record for Ed25519 and ML-DSA. Returns 0, or `-ERANGE` with
/// the requirement in `out_len_out`.
///
/// The challenge is the caller's, so the answer cannot be replayed; the
/// record carries the boot incarnation, so it cannot outlive the boot.
/// What the signature MEANS is the tier byte's: `DEVICE_HW` says this
/// hardware runs exactly this closure, `SOFTWARE` says a readable process
/// does. It proves bytes and wiring, never that they are correct or
/// intended. The composition digest — SHA-256 of the record with the
/// challenge zeroed — is the identity [`KEY_WRAP`] binds to.
pub const ATTEST_COMPOSITION: u32 = 0x100F;

/// Wrap a slot's key for one destination vault. handle = the slot (must
/// permit [`usage::WRAP`]). arg layout:
/// `[dest_pub_len:u16][dest_pub][attest_digest:32][out_ptr:u64][out_cap:u16][out_len_out:u16]`
/// where `dest_pub` is the destination's P-256 public key and
/// `attest_digest` the composition digest from its [`ATTEST_COMPOSITION`]
/// record. Output: `["FXKW"][eph_pub:65][attest_digest:32][nonce:12][sealed][tag:16]`,
/// `sealed` being `[suite:u16][usage:u32][key_len:u8][key]` under a key
/// derived from an ephemeral ECDH with `dest_pub`, salted by
/// `attest_digest`. Returns 0, or `-ERANGE`.
///
/// The key never appears in the clear on any surface: only the vault
/// holding `dest_pub`'s private half can open it, and only while its
/// composition still digests to `attest_digest` ([`KEY_UNWRAP`]).
pub const KEY_WRAP: u32 = 0x1010;

/// Unwrap into a fresh slot. handle = the slot holding this vault's P-256
/// private key (must permit [`usage::AGREE`]). arg layout:
/// `[blob_len:u16][blob]`. Returns the new slot's handle, or `-EACCES`
/// when the blob's `attest_digest` is not this composition's digest —
/// the composition changed since it was attested, and the key was wrapped
/// for the one that was — or `-EINVAL` when the blob does not open.
pub const KEY_UNWRAP: u32 = 0x1011;

/// Seal bytes under an [`suite::AEAD_KEY`] slot. handle = the slot (must
/// permit [`usage::SEAL`]). arg layout:
/// `[aad_len:u16][aad][pt_len:u16][pt][out_ptr:u64][out_cap:u16][out_len_out:u16]`;
/// output `[nonce:12][ct][tag:16]`. Returns 0, or `-ERANGE`.
///
/// The nonce is fresh from the CSPRNG per call. What the bytes mean — a
/// resumption ticket, a checkpoint — is the caller's; the vault only
/// guarantees that the key never leaves it.
pub const AEAD_SEAL: u32 = 0x1012;

/// Open what [`AEAD_SEAL`] produced. handle = the slot (must permit
/// [`usage::OPEN`]). arg layout:
/// `[aad_len:u16][aad][blob_len:u16][blob][out_ptr:u64][out_cap:u16][out_len_out:u16]`;
/// output the plaintext. Returns 0, `-EINVAL` when the tag does not
/// verify, or `-ERANGE`.
pub const AEAD_OPEN: u32 = 0x1013;

/// Derive a purpose key from a [`suite::KDF_KEY`] slot. handle = the
/// master (must permit [`usage::DERIVE`]). arg layout: see [`derive`].
/// Returns a new handle, owned by the caller, holding
/// `HKDF-SHA256(ikm = master, salt = derive::SALT, info = label ‖ context)`
/// as a key of the target suite with the target uses. A derived key is
/// never persisted: it is derived again when needed.
pub const DERIVE: u32 = 0x1014;

/// Seal up to [`units::MAX_ENTRIES`] buffers in place under an AEAD slot
/// ([`suite::AEAD_KEY`] or [`suite::AEAD_AES256_GCM`], must permit
/// [`usage::SEAL`]), each with the nonce its entry names. arg layout: see
/// [`units`]. Returns 0 when every entry sealed, or a negative errno when
/// the request was refused before any.
///
/// The caller chooses the nonces, so their uniqueness under the key is the
/// caller's obligation — the reason this exists beside [`AEAD_SEAL`], whose
/// vault-drawn random nonces suit a record now and then and not a storage
/// device writing the same key for years. The slot is owned by one module,
/// so no other can seal under it.
pub const AEAD_SEAL_UNITS: u32 = 0x1015;

/// Open up to [`units::MAX_ENTRIES`] buffers in place, verifying each tag.
/// An entry whose tag does not verify has its status set to
/// [`units::STATUS_AUTH_FAILED`] and its buffer zeroed, so unauthenticated
/// plaintext is never left behind. Returns the number of entries that
/// failed, or a negative errno when the request was refused before any.
pub const AEAD_OPEN_UNITS: u32 = 0x1016;

/// Split a 32-byte key 2-of-3 and wrap each share to its own recipient.
/// handle = the key (must permit [`usage::WRAP`]; a [`suite::KDF_KEY`],
/// [`suite::AEAD_KEY`] or [`suite::AEAD_AES256_GCM`]). arg layout: see
/// [`share::split`]. Writes three [`share`] envelopes, for share indices 1,
/// 2 and 3 in recipient order. Returns 0, or `-ERANGE` with the requirement
/// in `out_len_out`.
///
/// The shares exist only inside the call: each is sealed to its recipient
/// as it is made, and the scratch is zeroed. Any two envelopes, opened by
/// their recipients, give the key back through [`SHARE_COMBINE`]; one gives
/// nothing.
pub const SHARE_SPLIT: u32 = 0x1017;

/// Open one share envelope and seal the share to another recipient.
/// handle = the P-256 key the envelope is wrapped to (must permit
/// [`usage::AGREE`] and [`usage::EXPORT_PUBLIC`]: an envelope names its
/// recipient by public key). arg layout: see [`share::rewrap`]. Returns 0, or
/// `-ERANGE`.
///
/// What a custodian does to release its share: the share leaves this vault
/// only sealed to the new recipient, bound to a new purpose, lease fence,
/// expiry and policy digest. The recovery set, protected resource, epoch
/// and share index are carried over and cannot be changed.
pub const SHARE_REWRAP: u32 = 0x1018;

/// Open two share envelopes and reconstruct their key into a fresh handle,
/// owned by the caller. handle=-1. arg layout: see [`share::combine`]. The
/// two opener handles are the caller's recipient keys, each permitting
/// [`usage::AGREE`] and [`usage::EXPORT_PUBLIC`], held in any backend.
/// Returns the handle, or:
/// - `-EINVAL`: an envelope is malformed or does not open, or the two do
///   not belong together — another recovery set, resource, epoch or AEAD,
///   or the same share index twice;
/// - `-EACCES`: an envelope is not wrapped to the handle opening it, has
///   expired (or carries an expiry with no wall clock to check it), was
///   already consumed, or is for another resource or epoch than asked.
///
/// Reconstruction happens only here, and the key it yields is a handle:
/// neither share nor key is ever written to the caller. The new key is
/// never persisted; a volume attaches again after a restart.
pub const SHARE_COMBINE: u32 = 0x1019;

/// Attest a key: signed evidence of what a handle is, bound to a caller's
/// challenge, never its bytes. handle = the key attested. arg layout: see
/// [`attest_key`]. The output is `[record][signature]`, the signature made
/// by the signer handle the argument names (must permit [`usage::SIGN`]) in
/// its suite's convention, as [`ATTEST_COMPOSITION`] signs. Returns 0, or
/// `-ERANGE` with the requirement in `out_len_out`.
///
/// The record commits to the key without revealing it, names its suite,
/// uses, owner namespace, persistence and the vault's tier, and carries the
/// composition digest, so a verifier that trusts the signer's public key
/// learns which composition holds which kind of key under which policy.
pub const ATTEST_KEY: u32 = 0x101A;

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

    /// [`super::SHARE_SPLIT`]:
    /// `[grant][recipient:65 ×3][out_ptr:u64][out_cap:u32][out_len_out:u32]`.
    pub mod split {
        use super::{grant, P256_PUB_LEN};
        pub const RECIPIENTS: usize = grant::LEN;
        pub const OUT_PTR: usize = RECIPIENTS + 3 * P256_PUB_LEN;
        pub const OUT_CAP: usize = OUT_PTR + 8;
        pub const OUT_LEN: usize = OUT_CAP + 4;
        pub const LEN: usize = OUT_LEN + 4;
    }

    /// [`super::SHARE_REWRAP`]:
    /// `[grant][recipient:65][out_ptr:u64][out_cap:u32][out_len_out:u32]
    ///  [env_len:u16][envelope]`.
    pub mod rewrap {
        use super::{grant, P256_PUB_LEN};
        pub const RECIPIENT: usize = grant::LEN;
        pub const OUT_PTR: usize = RECIPIENT + P256_PUB_LEN;
        pub const OUT_CAP: usize = OUT_PTR + 8;
        pub const OUT_LEN: usize = OUT_CAP + 4;
        pub const ENV_LEN: usize = OUT_LEN + 4;
        pub const ENV: usize = ENV_LEN + 2;
    }

    /// [`super::SHARE_COMBINE`]:
    /// `[target_suite:u16][target_usage:u32][_pad:u16][opener_a:i32]
    ///  [opener_b:i32][resource:16][epoch:u32][env_a_len:u16][env_b_len:u16]
    ///  [env_a][env_b]`. The target suite is one a split source may hold,
    /// and the uses may not include [`super::super::usage::PERSIST`].
    pub mod combine {
        pub const TARGET_SUITE: usize = 0;
        pub const TARGET_USAGE: usize = 2;
        pub const OPENER_A: usize = 8;
        pub const OPENER_B: usize = 12;
        pub const RESOURCE: usize = 16;
        pub const EPOCH: usize = 32;
        pub const ENV_A_LEN: usize = 36;
        pub const ENV_B_LEN: usize = 38;
        pub const ENVS: usize = 40;
    }
}

/// [`ATTEST_KEY`]: the argument, and the record it signs.
///
/// arg: `[challenge:32][signer:i32][_pad:u32][out_ptr:u64][out_cap:u32]
/// [out_len_out:u32]`.
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
    pub const CHALLENGE: usize = 0;
    pub const SIGNER: usize = 32;
    pub const OUT_PTR: usize = 40;
    pub const OUT_CAP: usize = 48;
    pub const OUT_LEN: usize = 52;
    pub const ARG_LEN: usize = 56;

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

/// Layout of a [`DERIVE`] argument.
///
/// `[target_suite:u16][target_usage:u32][label_len:u8][_pad:u8]
///  [context_len:u16][label][context]`
pub mod derive {
    pub const TARGET_SUITE: usize = 0;
    pub const TARGET_USAGE: usize = 2;
    pub const LABEL_LEN: usize = 6;
    pub const CONTEXT_LEN: usize = 8;
    /// Where the label starts; the context follows it.
    pub const LABEL: usize = 10;
    pub const MAX_LABEL: usize = 64;
    pub const MAX_CONTEXT: usize = 128;
    /// The HKDF salt every derivation uses.
    pub const SALT: &[u8] = b"fluxor/v1";
}

/// Layout of an [`AEAD_SEAL_UNITS`] / [`AEAD_OPEN_UNITS`] argument:
/// a header, then `count` entries.
pub mod units {
    /// `[count:u16][_pad:u16]`
    pub const HEADER_LEN: usize = 4;
    pub const COUNT: usize = 0;
    /// One entry: `[nonce:12][aad_len:u16][status:u8][_pad:u8]
    /// [aad_ptr:u64][data_ptr:u64][data_len:u32][_pad:u32][tag_ptr:u64]`.
    pub const ENTRY_LEN: usize = 48;
    pub const NONCE: usize = 0;
    pub const AAD_LEN: usize = 12;
    /// Written by the vault: 0, or [`STATUS_AUTH_FAILED`].
    pub const STATUS: usize = 14;
    pub const AAD_PTR: usize = 16;
    pub const DATA_PTR: usize = 24;
    pub const DATA_LEN: usize = 32;
    /// 16 bytes: written by a seal, checked by an open.
    pub const TAG_PTR: usize = 40;
    pub const STATUS_AUTH_FAILED: u8 = 1;
    /// Entries one call carries.
    pub const MAX_ENTRIES: usize = 32;
    /// Bytes one call seals or opens, across its entries: bounds the work
    /// done inside the caller's step.
    pub const MAX_BYTES: usize = 256 * 1024;
    /// Longest associated data per entry.
    pub const MAX_AAD: usize = 128;
}

/// Layout constants for [`KEY_WRAP`] blobs.
pub mod wrap {
    pub const MAGIC: [u8; 4] = *b"FXKW";
    pub const EPH_PUB_LEN: usize = 65;
    pub const ATTEST_OFF: usize = 4 + EPH_PUB_LEN;
    pub const NONCE_OFF: usize = ATTEST_OFF + 32;
    pub const SEALED_OFF: usize = NONCE_OFF + 12;
    /// Sealed payload prefix before the key bytes.
    pub const SEALED_PREFIX: usize = 2 + 4 + 1;
    pub const TAG_LEN: usize = 16;
}

/// Flag bits for the [`GENERATE`] `flags` byte.
pub mod generate_flags {
    /// Request a non-extractable private key. A backend that cannot
    /// honour this refuses the GENERATE outright rather than silently
    /// producing an extractable key — a caller asking for
    /// non-extractability is asking for a guarantee, and quietly not
    /// providing it is worse than saying no.
    pub const NON_EXTRACTABLE: u8 = 0x01;
}

/// Isolation-tier ordinals written by the [`TIER`] opcode.
pub mod tier {
    /// Kernel static slots — in-process on hosted platforms. Isolates
    /// against a compromised module, not a compromised host/kernel.
    pub const SOFTWARE: u8 = 0;
    /// Host process talking to an HSM (e.g. PKCS#11 to a token).
    /// Isolates against host compromise to the extent the token does.
    pub const PROCESS_HW: u8 = 1;
    /// On-die secure element / TPM.
    pub const DEVICE_HW: u8 = 2;
}
