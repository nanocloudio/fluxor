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
//
// `SUITE_QUERY` replaced a `caps` bitmap whose own documentation described
// a reserve-then-implement extension dance — compatibility machinery, which
// `C15` exists to remove. It also could not answer the question a caller
// actually has: a bit says P-256 is supported and cannot say how many bytes
// an ML-DSA-65 signature needs.

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
/// `suite` replaces `key_type: u8` and `key_len` is a `u32` — an ML-DSA-87
/// private key is 4896 bytes, which the previous `u8` length could not
/// express at all.
///
/// STORE is an *import* path: the key existed outside the backend and is
/// received-then-wiped, not never-present. A non-extractable HSM may refuse
/// it entirely; [`SUITE_QUERY`] reports import support per suite rather
/// than as one global bit, because tokens differ by algorithm.
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
/// `sign_mode` is on the wire rather than inferred from `key_type` — see
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
pub const SIGN: u32 = 0x1003;

/// ECDSA verify (P-256) with a caller-supplied public key — the stored
/// slots are not consulted. handle=-1.
/// arg layout: [hash_len:u16][sig_len:u16][pub_len:u16][_pad:u16]
///             [hash_bytes[hash_len]][sig_bytes[sig_len]][pub_bytes[pub_len]]
/// - sig_len must be 64 (raw r‖s); pub_len >= 64 (SEC1 uncompressed,
///   with or without the leading 0x04 byte).
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

/// Key suites. Replaces the two-value `key_type: u8`.
///
/// A `u16` because the space this has to hold is not two: ML-DSA and
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

    /// Highest id this registry defines.
    pub const MAX_ID: u16 = ML_KEM_768;
}

/// How [`SIGN`] should treat the bytes it is given.
///
/// On the wire rather than inferred from `key_type`. Inference works while
/// there are two algorithms and one convention each — a P-256 slot gets a
/// digest, an Ed25519 slot gets the whole message — but it requires the
/// caller to know which without the wire ever saying, and a caller that
/// hands a P-256 slot a message rather than its digest gets a valid
/// signature over the wrong thing.
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
/// This replaced a `caps` bitmap, now deleted. That bitmap documented its
/// own extension procedure as "reserve the bit, make every backend return
/// 0, implement later" — a reserve-then-implement dance, which is
/// compatibility machinery, which is what `C15` exists to remove. More
/// practically, a bitmap answers "is P-256 supported" and cannot answer
/// "how big is an ML-DSA-65 signature", which is what a caller sizing a
/// buffer actually needs.
pub const SUITE_QUERY: u32 = 0x100D;

/// Enumerate supported suites.
///
/// handle=-1. arg layout:
/// `[cursor:u16][_pad:u16][out_ptr:u64][out_cap:u16][count_out:u16]`;
/// writes `count_out` `u16` suite ids. Returns the next cursor, or 0 when
/// the enumeration is complete.
pub const SUITE_ENUM: u32 = 0x100E;

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
