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
// wired", `CAPS` answers "which optional ops / algorithms does this
// backend implement" (bitmap, [`caps`]), and `TIER` answers "what
// isolation level does it provide" (ordinal, [`tier`]). A consumer
// MUST NOT claim a hardware guarantee it did not read from `TIER`.

/// Returns 1 if a key-vault backend is present, 0 if not. Call with
/// handle=-1 and arg=null to detect at `module_new`.
pub const PROBE: u32 = 0x1000;

/// Store (import) a private key. handle=-1.
/// arg layout: [key_type:u8][len:u8][_pad:u16][bytes[len]]
/// - key_type 1 = raw 32-byte P-256 scalar (for ECDSA + ECDH)
/// - key_type 2 = raw 32-byte Ed25519 seed (RFC 8032, for SIGN)
/// - len is the key-material length in bytes
///
/// Returns: opaque handle (>= 0) or negative errno. Pass the handle
/// back unmodified to SIGN / ECDH / PUBLIC / DESTROY; do not decode it.
///
/// STORE is an *import* path: the key existed outside the backend and
/// is received-then-wiped, not never-present. Non-extractable hardware
/// backends generally cannot import and clear [`caps::STORE_IMPORT`];
/// consumers that require hardware isolation use [`GENERATE`].
pub const STORE: u32 = 0x1001;

/// ECDH: derive shared secret. handle = slot.
/// arg layout: [peer_pub_len:u16][_pad:u16][peer_pub_bytes[len]][out[32]]
/// On success, the 32-byte X coordinate is written into the trailing
/// out region. Returns 0 on success, negative errno otherwise.
pub const ECDH: u32 = 0x1002;

/// Sign with the slot's private key. handle = slot.
/// arg layout: [hash_len:u16][_pad:u16][hash_bytes[hash_len]][sig_out[64]]
/// Returns 0 on success.
///
/// - P-256 slots (key_type 1): ECDSA over the caller-supplied digest.
///   The software backend uses the deterministic RFC 6979 nonce; a
///   hardware backend may use random-k, producing different-but-valid
///   signatures (verify, don't byte-compare, against such a backend).
///   The 64-byte low-s `r‖s` output is exactly the JWS ES256 segment.
/// - Ed25519 slots (key_type 2): the `hash_bytes` field carries the
///   *message itself* (Ed25519 is not prehashed; RFC 8032 signs the
///   full message). Output is the 64-byte `R‖S` signature,
///   deterministic by spec on every backend.
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
/// arg layout: [key_type:u8][flags:u8][_pad:u16][pub_out[N]]
/// - key_type selects the algorithm (see STORE); N is fixed by it:
///   P-256 → 65-byte SEC1 uncompressed point, Ed25519 → 32-byte point.
/// - flags: see [`generate_flags`].
///
/// Returns: opaque handle (>= 0) or negative errno, with the public
/// key written into `pub_out`. Because the return value is the handle
/// (not a length), the caller sizes `pub_out` a-priori from key_type.
///
/// The private key is born in backend custody and never exists in the
/// clear anywhere — the only path that gives true "key never leaves"
/// (and the only one a non-extractable HSM supports). Optional op:
/// gated by [`caps::GENERATE`].
pub const GENERATE: u32 = 0x1006;

/// Return the public key for a slot (for JWK/JWKS/kid derivation).
/// handle = slot. arg layout: [pub_out[N]], N fixed by the slot's
/// key_type (see GENERATE). Public material only. Returns 0 on
/// success. Optional op: gated by [`caps::PUBLIC`].
pub const PUBLIC: u32 = 0x1007;

/// Report the backend's isolation tier. handle=-1, arg → 1-byte
/// buffer; writes a `u8` ordinal (see [`tier`]), returns 1.
///
/// Tiers are mutually-exclusive ordinal levels (not independent
/// capabilities, hence not CAPS bits); a consumer with a security
/// requirement checks `tier >= N` and MUST NOT claim a hardware
/// guarantee it did not read from here.
pub const TIER: u32 = 0x1008;

/// Report the backend's op/algorithm-presence bitmap. handle=-1,
/// arg → 4-byte buffer; writes a `u32` LE bitmap (see [`caps`]),
/// returns 4. Last-in-range by convention (mirrors `fs::CAPS`).
pub const CAPS: u32 = 0x10FF;

/// Flag bits for the [`GENERATE`] `flags` byte.
pub mod generate_flags {
    /// Request a non-extractable private key. A backend that cannot
    /// honor this clears [`super::caps::NON_EXTRACTABLE`]; callers
    /// that require the guarantee check the CAPS bit, not the flag.
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

/// Capability bits returned by the [`CAPS`] opcode. A backend sets
/// bit B iff invoking the corresponding opcode/algorithm would
/// succeed for valid input (rather than returning `ENOSYS`/`EINVAL`).
///
/// Adding a new op or algorithm is a two-step ABI change:
///   1. Reserve the next bit here and document it as "implemented by
///      no backend yet, backends MUST return 0".
///   2. Implement the op/algorithm and flip the bit on per-backend.
///
/// Bit positions are stable forever — never renumber.
pub mod caps {
    // ── Optional operations ─────────────────────────────────
    /// [`GENERATE`](super::GENERATE) — in-backend keygen.
    pub const GENERATE:        u32 = 1 << 0;
    /// [`PUBLIC`](super::PUBLIC) — export the public key of a slot.
    pub const PUBLIC:          u32 = 1 << 1;
    /// [`STORE`](super::STORE) accepts an external private key. The
    /// software backend sets it; a non-extractable HSM clears it (it
    /// can only GENERATE), so a consumer knows at runtime whether the
    /// import path is available at all.
    pub const STORE_IMPORT:    u32 = 1 << 2;
    /// [`GENERATE`](super::GENERATE) can enforce
    /// [`generate_flags::NON_EXTRACTABLE`](super::generate_flags::NON_EXTRACTABLE).
    pub const NON_EXTRACTABLE: u32 = 1 << 3;

    // ── Algorithms (key_type support) ───────────────────────
    /// key_type 1 — P-256 (ECDSA / ECDH).
    pub const ALG_P256:    u32 = 1 << 8;
    /// key_type 2 — Ed25519 (RFC 8032 EdDSA).
    pub const ALG_ED25519: u32 = 1 << 9;
    // Reserved, MUST read 0 until op + every backend land together:
    //   ALG_P384    = 1 << 10 (key_type 3)
    //   ALG_X25519  = 1 << 11 (key_type 4)
    //   ALG_RSA2048 = 1 << 12 (key_type 5)
}
