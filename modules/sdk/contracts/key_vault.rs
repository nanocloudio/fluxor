// Contract: key_vault — backend-managed asymmetric keys (ECDSA / EdDSA / ECDH).
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
/// `key_len` is a `u32` because an ML-DSA-87 private key is 4896 bytes; no
/// narrower field can express one.
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
/// A `u16` because the space this has to hold is large: ML-DSA and
/// SLH-DSA come in three parameter sets each, ML-KEM in three more, and
/// every hybrid is its own entry. A byte would have been enough for a
/// decade and then not, and widening a field that eleven modules index by
/// is the change nobody wants to make under time pressure.
///
/// **Naming a suite is not implementing it.** [`SUITE_QUERY`] is the only
/// thing that says whether a backend can use one; the ids exist so sizes
/// and policies are already suite-shaped when the primitives arrive.
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

    /// Highest id this registry defines.
    pub const MAX_ID: u16 = HMAC_SHA256;
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
    /// The key may seal ([`AEAD_SEAL`]).
    pub const SEAL: u32 = 1 << 6;
    /// The key may open ([`AEAD_OPEN`]).
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
/// Returns an opaque handle (>= 0), or a negative errno.
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
/// Returns 0, or `-ENOENT`.
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
