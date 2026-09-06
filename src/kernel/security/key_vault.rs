//! KEY_VAULT device class — the kernel *software backend* for the
//! `key_vault` contract (kernel-managed asymmetric-key slots).
//!
//! Callers STORE or GENERATE a private key and receive an opaque handle.
//! The raw bytes live in kernel static memory and are never returned to
//! callers. Keys are zeroised on DESTROY and on scheduler reset.
//!
//! ECDH, SIGN and VERIFY run the kernel P-256 / Ed25519 primitives
//! directly: the vault is authoritative for any slot holding private
//! key material.
//!
//! This is the platform-overridable *default* backend: a hardware
//! platform may re-register both the KEY_VAULT class dispatch and its
//! vtable at platform boot (e.g. the Linux PKCS#11 backend), swapping
//! custody transparently behind the same contract. Isolation honesty:
//! this backend reports `TIER = SOFTWARE` — kernel static memory
//! isolates against a compromised *module*, not a compromised
//! host/kernel.
use crate::abi::contracts::key_vault as dev_key_vault;
use crate::abi::errno::{EACCES, EINVAL, ENOENT, ENOMEM, ENOSYS, ERANGE, ERROR};

/// Read a little-endian `u64` from `p`.
///
/// # Safety
/// `p` must be readable for 8 bytes.
unsafe fn read_u64(p: *const u8) -> u64 {
    let mut b = [0u8; 8];
    for (i, v) in b.iter_mut().enumerate() {
        *v = *p.add(i);
    }
    u64::from_le_bytes(b)
}
use crate::kernel::ipc::fd;
use crate::kernel::security::crypto::{ed25519, ml_dsa, p256};

/// The ML-DSA parameter set a VAULT SUITE names, or `None` on a target
/// without the `pq-vault` capability.
///
/// The crossing between the vault's suite registry and the primitive's own
/// naming is this one function, so the two can be renumbered independently
/// and every call site reads the mapping from one place. It is also the
/// single gate: every length, usage mask and enumeration the ML-DSA suites
/// appear in flows from this answer, so a target that cannot afford the
/// signing workspace reports them unsupported everywhere at once rather
/// than admitting a key it could not then sign with.
#[cfg(feature = "pq-vault")]
const fn ml_dsa_set_for(suite: u16) -> Option<ml_dsa::MlDsaSet> {
    match suite {
        dev_key_vault::suite::ML_DSA_44 => Some(ml_dsa::MlDsaSet::MlDsa44),
        dev_key_vault::suite::ML_DSA_65 => Some(ml_dsa::MlDsaSet::MlDsa65),
        dev_key_vault::suite::ML_DSA_87 => Some(ml_dsa::MlDsaSet::MlDsa87),
        _ => None,
    }
}

#[cfg(not(feature = "pq-vault"))]
const fn ml_dsa_set_for(_suite: u16) -> Option<ml_dsa::MlDsaSet> {
    None
}

/// Scratch for the vault's ML-DSA operations.
///
/// Static rather than a local because an ML-DSA-87 signature needs more
/// polynomial scratch than the stack any caller reaches this code on. One
/// workspace serves all three parameter sets — it carries the widest
/// dimensions and each operation uses the prefix its own set needs — so
/// the cost is paid once for the backend rather than once per suite.
///
/// This is ~58 KB of `.bss`, which is what makes ML-DSA a per-target
/// capability rather than something every kernel carries.
///
/// Serialised by the same single-core cooperative model as `SLOTS`.
#[cfg(feature = "pq-vault")]
static mut ML_DSA_WS: ml_dsa::SignWorkspace<{ ml_dsa::K_MAX }, { ml_dsa::L_MAX }> =
    ml_dsa::SignWorkspace::new();

/// Staging for an ML-DSA signature and public key. Both are larger than
/// any value this backend can return in a register-sized buffer, and both
/// are public, so they are staged here and copied to the caller.
#[cfg(feature = "pq-vault")]
static mut ML_DSA_SIG: [u8; ml_dsa::SIG_MAX] = [0; ml_dsa::SIG_MAX];
#[cfg(feature = "pq-vault")]
static mut ML_DSA_PK: [u8; ml_dsa::PK_MAX] = [0; ml_dsa::PK_MAX];
/// P-256 group order n (big-endian). Every P-256 scalar this vault
/// holds must lie in [1, n-1]: GENERATE rejection-samples into that
/// range and STORE refuses anything outside it. `d == 0` signs under
/// the identity and `d >= n` is a non-canonical encoding of `d mod n`.
const P256_ORDER_BE: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];
/// Number of key slots. Sized for TLS session fan-out.
pub const MAX_SLOTS: usize = 8;
/// Maximum key material length per slot. 32 bytes fits a P-256 scalar;
/// the extra 32 bytes allow larger keying material without breaking ABI.
pub const MAX_KEY_BYTES: usize = 64;
/// Slot flags.
const FLAG_IN_USE: u8 = 0x01;
/// This slot's key is backed by a sealed blob and survives a restart.
///
/// Reported by `DESCRIBE` NEXT TO the tier and deliberately separate from
/// it: durability and isolation are different properties, and a consumer
/// that conflates them is the failure this whole surface is shaped to
/// prevent.
const FLAG_PERSISTED: u8 = 0x02;

/// Longest label, mirroring the contract's `MAX_LABEL`.
pub const MAX_LABEL: usize = 64;

#[repr(C)]
struct Slot {
    flags: u8,
    key_len: u8,
    /// The key's suite (`key_vault::suite`), replacing `key_type: u8`.
    suite: u16,
    /// Permitted uses, sealed at creation and checked per operation.
    ///
    /// Sealed rather than passed per call, because a per-call permission
    /// is one the caller grants itself.
    usage: u32,
    /// The label this key is filed under, empty for an unnamed slot.
    label: [u8; MAX_LABEL],
    label_len: u8,
    data: [u8; MAX_KEY_BYTES],
}
impl Slot {
    const fn empty() -> Self {
        Self {
            flags: 0,
            key_len: 0,
            suite: 0,
            usage: 0,
            label: [0; MAX_LABEL],
            label_len: 0,
            data: [0; MAX_KEY_BYTES],
        }
    }

    fn label_bytes(&self) -> &[u8] {
        &self.label[..self.label_len as usize]
    }

    /// Whether this slot permits `want`.
    ///
    /// A slot with an EMPTY usage mask permits nothing. That is the
    /// fail-closed direction and it is deliberate: a zero mask is what an
    /// uninitialised slot has, and reading "no restrictions" out of "no
    /// information" is how a key ends up usable for everything.
    const fn permits(&self, want: u32) -> bool {
        self.usage & want == want
    }
}
// Static slot table. Access is serialised via the scheduler's single-core
// cooperative model; no explicit lock needed.
static mut SLOTS: [Slot; MAX_SLOTS] = [
    Slot::empty(),
    Slot::empty(),
    Slot::empty(),
    Slot::empty(),
    Slot::empty(),
    Slot::empty(),
    Slot::empty(),
    Slot::empty(),
];
// ── Persistence: the label → sealed-blob store ──────────────────────────
//
// A key named by a label survives a restart, because that is what an issuer
// key has to do — a signing key regenerated at every boot invalidates every
// credential the previous boot issued.
//
// It survives by being SEALED, through `hal::seal`, and the platform says
// what that is worth via `hal::seal_provenance`. This store deliberately
// does not care which answer it gets: it persists either way, and `TIER`
// reports the provenance separately. Wiring persistence to the tier here
// would be the exact conflation the surface exists to prevent — a key that
// survives a restart is not thereby protected from the host.

/// Persisted entries. Bounded because this is kernel static memory; a
/// deployment needing more keys than this needs a real HSM, which is the
/// tier the policy would already be asking for.
const MAX_PERSISTED: usize = 8;

/// Longest sealed blob: the key material plus the AEAD's nonce and tag,
/// with room for a larger suite than P-256.
const MAX_SEALED: usize = MAX_KEY_BYTES + 12 + 16;

#[repr(C)]
#[derive(Clone, Copy)]
struct Persisted {
    live: bool,
    label: [u8; MAX_LABEL],
    label_len: u8,
    suite: u16,
    usage: u32,
    sealed: [u8; MAX_SEALED],
    sealed_len: u8,
}

impl Persisted {
    const fn empty() -> Self {
        Self {
            live: false,
            label: [0; MAX_LABEL],
            label_len: 0,
            suite: 0,
            usage: 0,
            sealed: [0; MAX_SEALED],
            sealed_len: 0,
        }
    }
}

static mut PERSISTED: [Persisted; MAX_PERSISTED] = [Persisted::empty(); MAX_PERSISTED];

/// Find a persisted entry by label.
///
/// # Safety
/// Kernel context, exclusive access to `PERSISTED`.
unsafe fn find_persisted(label: &[u8]) -> Option<usize> {
    let table = &raw const PERSISTED;
    for (i, e) in (*table).iter().enumerate() {
        if e.live && e.label_len as usize == label.len() && e.label[..label.len()] == *label {
            return Some(i);
        }
    }
    // Not in RAM — this may be a fresh process. Ask the platform whether it
    // kept one, which is what makes a labelled key survive a COLD restart
    // rather than only a scheduler reset. Before this, an issuer re-keyed on
    // every start and every credential it had signed stopped verifying,
    // silently: a verifier just sees a bad signature.
    rehydrate_persisted(label)
}

/// Pull a sealed blob back from the platform into the RAM table.
///
/// Only the sealed bytes are stored, so `suite` and `usage` come back with
/// them — they are written into the blob's own record by `persist_key`, and
/// a blob whose header does not parse is treated as absent rather than
/// guessed at.
///
/// # Safety
/// Kernel context, exclusive access to `PERSISTED`.
unsafe fn rehydrate_persisted(label: &[u8]) -> Option<usize> {
    if label.is_empty() || label.len() > MAX_LABEL {
        return None;
    }
    let mut blob = [0u8; MAX_SEALED + 8];
    let n = crate::kernel::sys::hal::seal_blob_read(label, &mut blob)?;
    // `[suite:u16][usage:u32][sealed...]` — see `persist_key`.
    if n < 6 || n - 6 > MAX_SEALED {
        return None;
    }
    let suite = u16::from_le_bytes([blob[0], blob[1]]);
    let usage = u32::from_le_bytes([blob[2], blob[3], blob[4], blob[5]]);
    let table = &raw const PERSISTED;
    let idx = (*table).iter().position(|e| !e.live)?;
    PERSISTED[idx] = Persisted::empty();
    PERSISTED[idx].label[..label.len()].copy_from_slice(label);
    #[expect(clippy::cast_possible_truncation, reason = "bounded by MAX_LABEL")]
    {
        PERSISTED[idx].label_len = label.len() as u8;
    }
    PERSISTED[idx].suite = suite;
    PERSISTED[idx].usage = usage;
    PERSISTED[idx].sealed[..n - 6].copy_from_slice(&blob[6..n]);
    #[expect(clippy::cast_possible_truncation, reason = "bounded by MAX_SEALED")]
    {
        PERSISTED[idx].sealed_len = (n - 6) as u8;
    }
    PERSISTED[idx].live = true;
    for b in blob.iter_mut() {
        core::ptr::write_volatile(b, 0);
    }
    Some(idx)
}

/// Seal `key` under `label`. Returns false when the platform cannot seal,
/// or the table is full.
///
/// # Safety
/// Kernel context, exclusive access to `PERSISTED`.
unsafe fn persist_key(label: &[u8], suite: u16, usage: u32, key: &[u8]) -> bool {
    if label.is_empty() || label.len() > MAX_LABEL {
        return false;
    }
    let mut sealed = [0u8; MAX_SEALED];
    let Some(n) = crate::kernel::sys::hal::seal(key, &mut sealed) else {
        // No sealing on this platform. The key still works for this boot;
        // it simply will not come back, and `DESCRIBE` reports that
        // truthfully rather than claiming a persistence that is not there.
        return false;
    };
    let idx = match find_persisted(label) {
        Some(i) => i,
        None => {
            let table = &raw const PERSISTED;
            match (*table).iter().position(|e| !e.live) {
                Some(i) => i,
                None => return false,
            }
        }
    };
    PERSISTED[idx] = Persisted::empty();
    PERSISTED[idx].label[..label.len()].copy_from_slice(label);
    PERSISTED[idx].label_len = label.len() as u8;
    PERSISTED[idx].suite = suite;
    PERSISTED[idx].usage = usage;
    PERSISTED[idx].sealed[..n].copy_from_slice(&sealed[..n]);
    PERSISTED[idx].sealed_len = n as u8;
    PERSISTED[idx].live = true;
    // Write THROUGH to the platform's durable store, so the key outlives the
    // process and not merely the scheduler reset. `false` means this platform
    // has nowhere to put it, which is not an error: the in-RAM entry above
    // still stands and the vault behaves exactly as it did before durable
    // blobs existed.
    // `[suite:u16][usage:u32][sealed]` — the blob has to carry what the slot
    // was born with, or a rehydrated key would have to be told its own suite
    // and permitted uses by whoever opened it, which is exactly the widening
    // the sealed mask exists to prevent.
    let mut record = [0u8; MAX_SEALED + 8];
    record[0..2].copy_from_slice(&suite.to_le_bytes());
    record[2..6].copy_from_slice(&usage.to_le_bytes());
    record[6..6 + n].copy_from_slice(&sealed[..n]);
    let _ = crate::kernel::sys::hal::seal_blob_write(label, &record[..6 + n]);
    for b in record.iter_mut() {
        core::ptr::write_volatile(b, 0);
    }
    for b in sealed.iter_mut() {
        core::ptr::write_volatile(b, 0);
    }
    true
}

/// Load a slot from a persisted entry. Returns the slot index.
///
/// # Safety
/// Kernel context, exclusive access to `SLOTS` and `PERSISTED`.
unsafe fn open_persisted(idx: usize) -> Option<usize> {
    let entry = PERSISTED[idx];
    let mut key = [0u8; MAX_KEY_BYTES];
    let n = crate::kernel::sys::hal::unseal(&entry.sealed[..entry.sealed_len as usize], &mut key)?;
    if n == 0 || n > MAX_KEY_BYTES {
        return None;
    }
    let slot = alloc_slot()?;
    SLOTS[slot].suite = entry.suite;
    SLOTS[slot].usage = entry.usage;
    SLOTS[slot].key_len = n as u8;
    SLOTS[slot].label[..entry.label_len as usize]
        .copy_from_slice(&entry.label[..entry.label_len as usize]);
    SLOTS[slot].label_len = entry.label_len;
    for (j, b) in key.iter().take(n).enumerate() {
        core::ptr::write_volatile(&raw mut SLOTS[slot].data[j], *b);
    }
    for b in key.iter_mut() {
        core::ptr::write_volatile(b, 0);
    }
    // In-use last, so a partial fill is never observable.
    SLOTS[slot].flags = FLAG_IN_USE | FLAG_PERSISTED;
    Some(slot)
}

/// First free slot.
///
/// # Safety
/// Kernel context, exclusive access to `SLOTS`.
/// Largest plaintext [`AEAD_SEAL`] / [`AEAD_OPEN`] handle in one call: a
/// resumption ticket or a checkpoint chunk, never a bulk stream.
const MAX_SEAL_BYTES: usize = 2048;
/// Scratch for seal/open, a static so PIC callers' stacks stay small.
static mut SEAL_SCRATCH: [u8; MAX_SEAL_BYTES] = [0; MAX_SEAL_BYTES];
/// Scratch for the composition record: sized for the largest table the
/// host profile admits (192 blobs and instances, 128 edges).
const MAX_ATTEST_RECORD: usize = 4096 + 192 * 40 + 192 * 37 + 128 * 5;
static mut ATTEST_RECORD: [u8; MAX_ATTEST_RECORD] = [0; MAX_ATTEST_RECORD];

#[inline]
fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a live, exclusively-borrowed byte.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
}

/// The tier this vault reports: decided by the sealing key's provenance.
fn current_tier() -> u8 {
    match crate::kernel::sys::hal::seal_provenance() {
        crate::kernel::sys::hal::SealProvenance::DeviceUnique => dev_key_vault::tier::DEVICE_HW,
        _ => dev_key_vault::tier::SOFTWARE,
    }
}

/// HMAC-SHA256 (RFC 2104).
fn hmac_sha256(key: &[u8], data: &[&[u8]]) -> [u8; 32] {
    use crate::kernel::security::crypto::sha256::Sha256;
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let mut h = Sha256::new();
        h.update(key);
        k[..32].copy_from_slice(&h.finalize());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    for d in data {
        inner.update(d);
    }
    let ih = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&ih);
    let out = outer.finalize();
    zeroize(&mut k);
    zeroize(&mut ipad);
    zeroize(&mut opad);
    out
}

/// The key-wrap KEK: HKDF-SHA256 (RFC 5869), one block —
/// `salt = attest_digest`, `ikm = ECDH shared secret`,
/// `info = "fluxor key_wrap v1" || dest_pub`. Salting with the
/// destination's composition digest is what binds the wrap to it.
fn wrap_kek(shared: &[u8; 32], attest: &[u8; 32], dest_pub: &[u8], out: &mut [u8; 32]) {
    let mut prk = hmac_sha256(attest, &[shared]);
    let okm = hmac_sha256(&prk, &[b"fluxor key_wrap v1", dest_pub, &[1u8]]);
    zeroize(&mut prk);
    out.copy_from_slice(&okm);
}

/// Sign `msg` with `slot` in its suite's convention, writing `sig_len`
/// bytes to `out`. `None` on failure.
unsafe fn sign_bytes(slot_idx: usize, msg: &[u8], out: *mut u8, sig_len: usize) -> Option<usize> {
    use crate::kernel::security::crypto::sha256::Sha256;
    let slot = &SLOTS[slot_idx];
    #[cfg(feature = "pq-vault")]
    if let Some(set) = ml_dsa_set_for(slot.suite) {
        let mut seed = [0u8; ml_dsa::SEED_LEN];
        seed.copy_from_slice(&slot.data[..ml_dsa::SEED_LEN]);
        let ws_ptr = &raw mut ML_DSA_WS;
        let sig_ptr_staged = &raw mut ML_DSA_SIG;
        let ws = &mut *ws_ptr;
        let staged = &mut *sig_ptr_staged;
        let signed =
            ml_dsa::ml_dsa_sign_seed(set, &seed, &[], msg, ws, &mut staged[..sig_len]).is_ok();
        ws.zeroize();
        zeroize(&mut seed);
        if !signed {
            return None;
        }
        if !out.is_null() {
            core::ptr::copy_nonoverlapping(staged.as_ptr(), out, sig_len);
        }
        return Some(sig_len);
    }
    let mut priv_key = [0u8; 32];
    priv_key.copy_from_slice(&slot.data[..32]);
    let sig = match slot.suite {
        dev_key_vault::suite::P256 => {
            let mut h = Sha256::new();
            h.update(msg);
            let digest = h.finalize();
            p256::ecdsa_sign(&priv_key, &digest, &[0u8; 32])
        }
        dev_key_vault::suite::ED25519 => Some(ed25519::sign(&priv_key, msg)),
        _ => None,
    };
    zeroize(&mut priv_key);
    let sig = sig?;
    if !out.is_null() {
        core::ptr::copy_nonoverlapping(sig.as_ptr(), out, sig_len.min(64));
    }
    Some(sig_len.min(64))
}

unsafe fn alloc_slot() -> Option<usize> {
    let slots = &raw const SLOTS;
    (*slots).iter().position(|s| (s.flags & FLAG_IN_USE) == 0)
}

/// Private-key length for a suite, or 0 when this backend cannot use it.
///
/// The single place the backend's suite support is decided, so
/// `SUITE_QUERY` and the operations cannot disagree about what is
/// supported — which they would, eventually, if each carried its own list.
const fn suite_private_len(suite: u16) -> usize {
    match suite {
        dev_key_vault::suite::P256 | dev_key_vault::suite::ED25519 => 32,
        // A sealing key: 32 bytes of ChaCha20-Poly1305 key, no public half.
        dev_key_vault::suite::AEAD_KEY => 32,
        // The ML-DSA private key this backend holds is the 32-byte FIPS
        // 204 seed, not the 2560/4032/4896-byte encoded key. KeyGen is a
        // deterministic function of that seed, so the seed IS the key: it
        // reproduces the encoded form exactly, and it is what STORE
        // imports and what the sealed blob carries.
        //
        // The consequence is on the wire and is deliberate: a caller
        // holding an ALREADY-EXPANDED key cannot import it here, because
        // an expanded key does not reduce back to a seed. `SUITE_QUERY`
        // reporting 32 is what tells that caller so, before it allocates.
        _ if ml_dsa_set_for(suite).is_some() => ml_dsa::SEED_LEN,
        _ => 0,
    }
}

/// Public-key length for a suite, or 0.
const fn suite_public_len(suite: u16) -> usize {
    match suite {
        dev_key_vault::suite::P256 => 65,
        dev_key_vault::suite::ED25519 => 32,
        // Sizes come from the primitive's own parameter table rather than
        // being repeated here, so the vault and the signer cannot come to
        // disagree about how big an answer is.
        _ => match ml_dsa_set_for(suite) {
            Some(set) => set.params().pk_len,
            None => 0,
        },
    }
}

/// Signature length for a suite, or 0.
const fn suite_signature_len(suite: u16) -> usize {
    match suite {
        dev_key_vault::suite::P256 | dev_key_vault::suite::ED25519 => 64,
        _ => match ml_dsa_set_for(suite) {
            Some(set) => set.params().sig_len,
            None => 0,
        },
    }
}

/// What this backend permits for a suite it supports.
const fn suite_usage(suite: u16) -> u32 {
    match suite {
        dev_key_vault::suite::P256 => {
            dev_key_vault::usage::SIGN
                | dev_key_vault::usage::VERIFY
                | dev_key_vault::usage::AGREE
                | dev_key_vault::usage::EXPORT_PUBLIC
                | dev_key_vault::usage::PERSIST
                | dev_key_vault::usage::WRAP
        }
        dev_key_vault::suite::ED25519 => {
            dev_key_vault::usage::SIGN
                | dev_key_vault::usage::VERIFY
                | dev_key_vault::usage::EXPORT_PUBLIC
                | dev_key_vault::usage::PERSIST
                | dev_key_vault::usage::WRAP
        }
        dev_key_vault::suite::AEAD_KEY => {
            dev_key_vault::usage::SEAL
                | dev_key_vault::usage::OPEN
                | dev_key_vault::usage::PERSIST
                | dev_key_vault::usage::WRAP
        }
        // ML-DSA signs and nothing else. No `AGREE`: a signature scheme
        // has no key-agreement half, and the post-quantum one that does is
        // ML-KEM, which is a different suite with a different key.
        _ if ml_dsa_set_for(suite).is_some() => {
            dev_key_vault::usage::SIGN
                | dev_key_vault::usage::VERIFY
                | dev_key_vault::usage::EXPORT_PUBLIC
                | dev_key_vault::usage::PERSIST
        }
        _ => 0,
    }
}

/// Generate a fresh private key for `suite` into `out`.
///
/// One place, so `GENERATE` and `OPEN_OR_GENERATE` cannot come to disagree
/// about how a key is born — and the P-256 rejection sampling in particular
/// is the kind of thing that gets copied once correctly and once not.
///
/// # Safety
/// Kernel context; `out` must be `suite_private_len(suite)` bytes.
unsafe fn generate_into(suite: u16, out: &mut [u8]) -> bool {
    match suite {
        // A sealing key is any 32 random bytes.
        dev_key_vault::suite::AEAD_KEY => {
            out.len() == 32 && crate::kernel::sys::hal::csprng_fill(out.as_mut_ptr(), 32) == 0
        }
        dev_key_vault::suite::P256 => {
            if out.len() != 32 {
                return false;
            }
            // Rejection sampling into [1, n-1]. A scalar outside it is
            // either the identity or a non-canonical encoding of `d mod n`,
            // and signing under either is signing under a key nobody
            // intended.
            for _ in 0..128 {
                if crate::kernel::sys::hal::csprng_fill(out.as_mut_ptr(), 32) != 0 {
                    return false;
                }
                let mut scalar = [0u8; 32];
                scalar.copy_from_slice(out);
                let ok = p256_scalar_in_range(&scalar);
                for b in scalar.iter_mut() {
                    core::ptr::write_volatile(b, 0);
                }
                if ok {
                    return true;
                }
            }
            false
        }
        // Both are 32-byte seeds and any 32 bytes are valid: RFC 8032 for
        // Ed25519, FIPS 204 KeyGen for ML-DSA. Neither needs rejection
        // sampling, which is what separates them from P-256.
        dev_key_vault::suite::ED25519 => {
            out.len() == 32 && crate::kernel::sys::hal::csprng_fill(out.as_mut_ptr(), 32) == 0
        }
        _ if ml_dsa_set_for(suite).is_some() => {
            out.len() == 32 && crate::kernel::sys::hal::csprng_fill(out.as_mut_ptr(), 32) == 0
        }
        _ => false,
    }
}

/// Derive slot `idx`'s public key into `out_ptr`.
///
/// # Safety
/// Kernel context; `out_ptr` must be writable for `pub_len` bytes, and
/// `pub_len` must be `suite_public_len` of the slot's suite.
unsafe fn write_public(idx: usize, out_ptr: *mut u8, pub_len: usize) -> bool {
    let slot = &SLOTS[idx];
    // A sealing key has no public half: nothing to write is success.
    if slot.suite == dev_key_vault::suite::AEAD_KEY {
        return pub_len == 0;
    }
    let mut priv_key = [0u8; 32];
    if slot.key_len as usize != 32 {
        return false;
    }
    priv_key.copy_from_slice(&slot.data[..32]);
    let ok = match slot.suite {
        dev_key_vault::suite::P256 => match p256::public_key_from_scalar(&priv_key) {
            Some(pk) if pub_len == 65 => {
                core::ptr::copy_nonoverlapping(pk.as_ptr(), out_ptr, 65);
                true
            }
            _ => false,
        },
        dev_key_vault::suite::ED25519 if pub_len == 32 => {
            let pk = ed25519::public_key(&priv_key);
            core::ptr::copy_nonoverlapping(pk.as_ptr(), out_ptr, 32);
            true
        }
        // ML-DSA derives its public key from the seed the same way KeyGen
        // does, so a slot holding 32 bytes can answer PUBLIC without ever
        // materialising the encoded private key.
        suite => match ml_dsa_set_for(suite) {
            #[cfg(feature = "pq-vault")]
            Some(set) if pub_len == set.params().pk_len => {
                let ws_ptr = &raw mut ML_DSA_WS;
                let pk_ptr = &raw mut ML_DSA_PK;
                let ws = &mut *ws_ptr;
                let staged = &mut *pk_ptr;
                let ok =
                    ml_dsa::ml_dsa_public_key(set, &priv_key, ws, &mut staged[..pub_len]).is_ok();
                ws.zeroize();
                if ok {
                    core::ptr::copy_nonoverlapping(staged.as_ptr(), out_ptr, pub_len);
                }
                ok
            }
            _ => false,
        },
    };
    for b in priv_key.iter_mut() {
        core::ptr::write_volatile(b, 0);
    }
    ok
}

/// Zeroise every slot. Called on scheduler reset / graph reconfigure.
///
/// # Safety
/// Must be called from kernel context with exclusive access to `SLOTS`
/// (i.e. while no module is mid-`provider_dispatch`). Wipes all key
/// material in place via volatile writes; concurrent SIGN/ECDH would
/// observe partially-zeroed keys.
pub unsafe fn reset_all() {
    for i in 0..MAX_SLOTS {
        zeroise_slot(i);
    }
}

/// Drop every RAM-resident persisted entry, as a fresh PROCESS would find it.
///
/// Test-only, and it exists because `reset_all` is not a restart:
/// `reset_all` models a graph reconfigure, where `PERSISTED` deliberately
/// survives so a labelled key comes back. A new process has neither table,
/// and the only thing that can bring a key back then is the platform's
/// durable store — which is precisely the path this clears the way to test.
///
/// # Safety
/// Kernel context, exclusive access to `PERSISTED`.
pub unsafe fn forget_persisted_for_test() {
    let table = &raw mut PERSISTED;
    for entry in (*table).iter_mut() {
        *entry = Persisted::empty();
    }
}
/// True iff `k` (big-endian) is a valid P-256 scalar: 1 <= k < n.
fn p256_scalar_in_range(k: &[u8; 32]) -> bool {
    // Big-endian compare against the group order: first differing
    // byte decides. Not constant-time — a rejected sample is never
    // used, and an accepted one reveals only "in range".
    let mut less_than_n = false;
    for i in 0..32 {
        if k[i] < P256_ORDER_BE[i] {
            less_than_n = true;
            break;
        }
        if k[i] > P256_ORDER_BE[i] {
            return false;
        }
    }
    less_than_n && k.iter().any(|&b| b != 0)
}
unsafe fn zeroise_slot(i: usize) {
    if i >= MAX_SLOTS {
        return;
    }
    // Volatile writes so the compiler doesn't optimise the wipe away.
    let p = (&raw mut SLOTS[i].data) as *mut u8;
    for j in 0..MAX_KEY_BYTES {
        core::ptr::write_volatile(p.add(j), 0);
    }
    SLOTS[i].flags = 0;
    SLOTS[i].suite = 0;
    SLOTS[i].usage = 0;
    SLOTS[i].label_len = 0;
    SLOTS[i].key_len = 0;
}
/// Provider dispatch function registered against dev_class::KEY_VAULT.
/// Signature matches the `provider_dispatch` contract.
///
/// Slot-bound ops (DESTROY / SIGN / ECDH) take a `FD_TAG_KEY_VAULT`-tagged
/// handle; PROBE / STORE / VERIFY take `handle=-1`. Tagging keeps KV
/// handles distinct from other drivers' untagged integer handles in the
/// kernel's global handle-tracking table.
///
/// # Safety
/// `arg` must be valid for `arg_len` bytes for both reads (input fields
/// per the opcode's TLV layout) and writes (signature / shared-secret
/// output regions). Caller must not retain `arg` after return.
pub unsafe fn provider_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    let slot_handle = match opcode {
        // Global (handle=-1) ops: anything not listed here must carry a
        // FD_TAG_KEY_VAULT-tagged slot handle or is rejected with EINVAL.
        dev_key_vault::PROBE
        | dev_key_vault::STORE
        | dev_key_vault::VERIFY
        | dev_key_vault::GENERATE
        | dev_key_vault::OPEN_OR_GENERATE
        | dev_key_vault::OPEN
        | dev_key_vault::DESTROY_BY_LABEL
        | dev_key_vault::SUITE_QUERY
        | dev_key_vault::SUITE_ENUM
        | dev_key_vault::TIER => handle,
        _ => {
            if handle < 0 {
                return EINVAL;
            }
            let (tag, slot) = fd::untag_fd(handle);
            if tag != fd::FD_TAG_KEY_VAULT {
                return EINVAL;
            }
            slot
        }
    };
    match opcode {
        dev_key_vault::PROBE => {
            // Presence indicator — 1 means the vault is available.
            1
        }
        dev_key_vault::STORE => {
            // arg: [suite:u16][usage_mask:u32][key_len:u32][key[key_len]]
            if arg.is_null() || arg_len < 10 {
                return EINVAL;
            }
            let suite = u16::from_le_bytes([*arg, *arg.add(1)]);
            let usage = u32::from_le_bytes([*arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5)]);
            let key_len =
                u32::from_le_bytes([*arg.add(6), *arg.add(7), *arg.add(8), *arg.add(9)]) as usize;
            let want = suite_private_len(suite);
            if want == 0 || key_len != want || 10 + key_len > arg_len {
                return EINVAL;
            }
            // A caller may not ask for a use the suite does not have — an
            // Ed25519 key that claimed AGREE would be a key nothing could
            // honour, discovered at the first agreement rather than here.
            if usage == 0 || usage & !suite_usage(suite) != 0 {
                return EINVAL;
            }
            // A P-256 slot must hold a scalar in [1, n-1]. Admitting
            // `d == 0` or `d >= n` here would make SIGN, ECDH and PUBLIC
            // operate under a degenerate key.
            if suite == dev_key_vault::suite::P256 {
                let mut scalar = [0u8; 32];
                for (j, b) in scalar.iter_mut().enumerate() {
                    *b = *arg.add(10 + j);
                }
                let in_range = p256_scalar_in_range(&scalar);
                for byte in scalar.iter_mut() {
                    core::ptr::write_volatile(byte as *mut u8, 0);
                }
                if !in_range {
                    return EINVAL;
                }
            }
            let Some(idx) = alloc_slot() else {
                return ENOMEM;
            };
            SLOTS[idx].suite = suite;
            SLOTS[idx].usage = usage;
            SLOTS[idx].key_len = key_len as u8;
            let src = arg.add(10);
            for j in 0..key_len {
                core::ptr::write_volatile(&raw mut SLOTS[idx].data[j], *src.add(j));
            }
            // Mark in-use last so partial fills can't be observed.
            SLOTS[idx].flags = FLAG_IN_USE;
            fd::tag_fd(fd::FD_TAG_KEY_VAULT, idx as i32)
        }
        dev_key_vault::DESTROY => {
            if slot_handle < 0 || (slot_handle as usize) >= MAX_SLOTS {
                return EINVAL;
            }
            zeroise_slot(slot_handle as usize);
            0
        }
        dev_key_vault::SIGN => {
            // arg: [sign_mode:u8][_pad:u8][input_len:u32][input[input_len]]
            //      [sig_out_ptr:u64][sig_out_cap:u16][sig_len_out:u16]
            if arg.is_null() || arg_len < 6 {
                return EINVAL;
            }
            if slot_handle < 0 || (slot_handle as usize) >= MAX_SLOTS {
                return EINVAL;
            }
            let slot = &SLOTS[slot_handle as usize];
            if (slot.flags & FLAG_IN_USE) == 0 {
                return EINVAL;
            }
            // The mask, checked here rather than trusted from the caller.
            if !slot.permits(dev_key_vault::usage::SIGN) {
                return EACCES;
            }
            let mode = *arg;
            let input_len =
                u32::from_le_bytes([*arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5)]) as usize;
            if input_len == 0 || 6 + input_len + 12 > arg_len {
                return EINVAL;
            }
            let tail = arg.add(6 + input_len);
            let sig_ptr = read_u64(tail) as *mut u8;
            let sig_cap = u16::from_le_bytes([*tail.add(8), *tail.add(9)]) as usize;
            let sig_len = suite_signature_len(slot.suite);
            if sig_len == 0 {
                return ENOSYS;
            }
            if sig_cap < sig_len {
                let need = (sig_len as u16).to_le_bytes();
                core::ptr::copy_nonoverlapping(need.as_ptr(), tail.add(10), 2);
                return ERANGE;
            }

            // The mode must be the one the suite actually uses. A P-256
            // slot handed `RAW` would sign a message as though it were a
            // digest — a valid signature over the wrong thing, which is
            // exactly the trap the inferred convention set.
            //
            // ML-DSA takes the whole message, like Ed25519 — the pure
            // variant of FIPS 204 is not prehashed, and HashML-DSA is a
            // different algorithm rather than a mode of this one. It also
            // takes a context string, and `CONTEXT` is refused here rather
            // than silently signing with an empty one: the SIGN arg layout
            // carries no context field, so a caller asking for one is
            // asking for something this wire cannot express, and answering
            // it with the empty context would produce a signature over a
            // different domain than the caller asked for.
            let want_mode = match slot.suite {
                dev_key_vault::suite::P256 => dev_key_vault::sign_mode::DIGEST,
                dev_key_vault::suite::ED25519 => dev_key_vault::sign_mode::RAW,
                _ if ml_dsa_set_for(slot.suite).is_some() => dev_key_vault::sign_mode::RAW,
                _ => return ENOSYS,
            };
            if mode != want_mode {
                return EINVAL;
            }

            // ML-DSA's signature does not fit the fixed 64-byte path
            // below, and its scratch is a static rather than a local, so
            // it answers here and returns.
            #[cfg(feature = "pq-vault")]
            if let Some(set) = ml_dsa_set_for(slot.suite) {
                let mut seed = [0u8; ml_dsa::SEED_LEN];
                seed.copy_from_slice(&slot.data[..ml_dsa::SEED_LEN]);
                let msg = core::slice::from_raw_parts(arg.add(6), input_len);
                let ws_ptr = &raw mut ML_DSA_WS;
                let sig_ptr_staged = &raw mut ML_DSA_SIG;
                let ws = &mut *ws_ptr;
                let staged = &mut *sig_ptr_staged;
                let signed =
                    ml_dsa::ml_dsa_sign_seed(set, &seed, &[], msg, ws, &mut staged[..sig_len])
                        .is_ok();
                ws.zeroize();
                for byte in seed.iter_mut() {
                    core::ptr::write_volatile(byte as *mut u8, 0);
                }
                if !signed {
                    return ERROR;
                }
                if !sig_ptr.is_null() {
                    core::ptr::copy_nonoverlapping(staged.as_ptr(), sig_ptr, sig_len);
                }
                let wrote = (sig_len as u16).to_le_bytes();
                core::ptr::copy_nonoverlapping(wrote.as_ptr(), tail.add(10), 2);
                return 0;
            }

            let mut priv_key = [0u8; 32];
            priv_key.copy_from_slice(&slot.data[..32]);
            let sig = match slot.suite {
                dev_key_vault::suite::P256 => {
                    // ECDSA over a caller-supplied digest, at most 64 bytes.
                    if input_len > 64 {
                        for byte in priv_key.iter_mut() {
                            core::ptr::write_volatile(byte as *mut u8, 0);
                        }
                        return EINVAL;
                    }
                    let hash = core::slice::from_raw_parts(arg.add(6), input_len);
                    // RFC 6979 derives its nonce deterministically; the
                    // `_random` arg on ecdsa_sign is unused.
                    p256::ecdsa_sign(&priv_key, hash, &[0u8; 32])
                }
                dev_key_vault::suite::ED25519 => {
                    let msg = core::slice::from_raw_parts(arg.add(6), input_len);
                    Some(ed25519::sign(&priv_key, msg))
                }
                _ => {
                    for byte in priv_key.iter_mut() {
                        core::ptr::write_volatile(byte as *mut u8, 0);
                    }
                    return EINVAL;
                }
            };
            for byte in priv_key.iter_mut() {
                core::ptr::write_volatile(byte as *mut u8, 0);
            }
            let Some(sig) = sig else {
                return EINVAL;
            };
            if !sig_ptr.is_null() {
                core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_ptr, sig_len);
            }
            let wrote = (sig_len as u16).to_le_bytes();
            core::ptr::copy_nonoverlapping(wrote.as_ptr(), tail.add(10), 2);
            0
        }
        dev_key_vault::ECDH => {
            // arg: [peer_len:u32][peer[peer_len]]
            //      [out_ptr:u64][out_cap:u16][out_len_out:u16]
            if arg.is_null() || arg_len < 4 {
                return EINVAL;
            }
            if slot_handle < 0 || (slot_handle as usize) >= MAX_SLOTS {
                return EINVAL;
            }
            let slot = &SLOTS[slot_handle as usize];
            if (slot.flags & FLAG_IN_USE) == 0
                || slot.suite != dev_key_vault::suite::P256
                || slot.key_len != 32
            {
                return EINVAL;
            }
            // A signing key used for key agreement is a cross-purpose
            // reuse, and the mask is where it stops.
            if !slot.permits(dev_key_vault::usage::AGREE) {
                return EACCES;
            }
            let peer_len =
                u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]) as usize;
            if peer_len == 0 || 4 + peer_len + 12 > arg_len {
                return EINVAL;
            }
            let tail = arg.add(4 + peer_len);
            let out_ptr = read_u64(tail) as *mut u8;
            let out_cap = u16::from_le_bytes([*tail.add(8), *tail.add(9)]) as usize;
            if out_cap < 32 {
                let need = 32u16.to_le_bytes();
                core::ptr::copy_nonoverlapping(need.as_ptr(), tail.add(10), 2);
                return ERANGE;
            }
            let peer = core::slice::from_raw_parts(arg.add(4), peer_len);
            let mut priv_key = [0u8; 32];
            priv_key.copy_from_slice(&slot.data[..32]);
            let result = p256::ecdh_shared_secret(&priv_key, peer);
            for byte in priv_key.iter_mut() {
                core::ptr::write_volatile(byte as *mut u8, 0);
            }
            match result {
                Some(shared) => {
                    if !out_ptr.is_null() {
                        core::ptr::copy_nonoverlapping(shared.as_ptr(), out_ptr, 32);
                    }
                    let wrote = 32u16.to_le_bytes();
                    core::ptr::copy_nonoverlapping(wrote.as_ptr(), tail.add(10), 2);
                    0
                }
                None => EINVAL,
            }
        }
        dev_key_vault::VERIFY => {
            // VERIFY is independent of the stored key — it takes a
            // caller-supplied public key in the peer field of the argument.
            // Layout: `[hash_len:u16][sig_len:u16][pub_len:u16][pad:u16]
            // [hash][sig][pub]`. v1 has only this shape; shorter
            // payloads are rejected as EINVAL.
            if arg.is_null() || arg_len < 8 {
                return EINVAL;
            }
            let hash_len = u16::from_le_bytes([*arg, *arg.add(1)]) as usize;
            let sig_len = u16::from_le_bytes([*arg.add(2), *arg.add(3)]) as usize;
            let pub_len = u16::from_le_bytes([*arg.add(4), *arg.add(5)]) as usize;
            if hash_len == 0
                || sig_len != 64
                || pub_len < 64
                || 8 + hash_len + sig_len + pub_len > arg_len
            {
                return EINVAL;
            }
            let hash = core::slice::from_raw_parts(arg.add(8), hash_len);
            let sig = core::slice::from_raw_parts(arg.add(8 + hash_len), sig_len);
            let pk = core::slice::from_raw_parts(arg.add(8 + hash_len + sig_len), pub_len);
            if p256::ecdsa_verify(pk, hash, sig) {
                1
            } else {
                0
            }
        }
        dev_key_vault::GENERATE => {
            // arg: [suite:u16][usage_mask:u32][flags:u8][_pad:u8]
            //      [pub_out_ptr:u64][pub_out_cap:u16][pub_len_out:u16]
            if arg.is_null() || arg_len < 20 {
                return EINVAL;
            }
            let suite = u16::from_le_bytes([*arg, *arg.add(1)]);
            let usage = u32::from_le_bytes([*arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5)]);
            let flags = *arg.add(6);
            let priv_len = suite_private_len(suite);
            let pub_len = suite_public_len(suite);
            if priv_len == 0 {
                return ENOSYS;
            }
            if usage == 0 || usage & !suite_usage(suite) != 0 {
                return EINVAL;
            }
            // A caller asking for non-extractability is asking for a
            // guarantee this backend cannot give — its keys live in kernel
            // memory the host can read. Refused rather than accepted and
            // ignored: quietly not providing a guarantee is worse than
            // saying no, because the caller proceeds believing it has one.
            if flags & dev_key_vault::generate_flags::NON_EXTRACTABLE != 0 {
                return ENOSYS;
            }
            let tail = arg.add(8);
            let pub_ptr = read_u64(tail) as *mut u8;
            let pub_cap = u16::from_le_bytes([*tail.add(8), *tail.add(9)]) as usize;
            if pub_cap < pub_len {
                let need = (pub_len as u16).to_le_bytes();
                core::ptr::copy_nonoverlapping(need.as_ptr(), tail.add(10), 2);
                return ERANGE;
            }
            let Some(idx) = alloc_slot() else {
                return ENOMEM;
            };
            let mut key = [0u8; MAX_KEY_BYTES];
            if !generate_into(suite, &mut key[..priv_len]) {
                return ERROR;
            }
            SLOTS[idx].suite = suite;
            SLOTS[idx].usage = usage;
            SLOTS[idx].key_len = priv_len as u8;
            for (j, b) in key.iter().take(priv_len).enumerate() {
                core::ptr::write_volatile(&raw mut SLOTS[idx].data[j], *b);
            }
            for byte in key.iter_mut() {
                core::ptr::write_volatile(byte as *mut u8, 0);
            }
            // Mark in-use last so partial fills can't be observed.
            SLOTS[idx].flags = FLAG_IN_USE;
            if !pub_ptr.is_null() && !write_public(idx, pub_ptr, pub_len) {
                zeroise_slot(idx);
                return ERROR;
            }
            let wrote = (pub_len as u16).to_le_bytes();
            core::ptr::copy_nonoverlapping(wrote.as_ptr(), tail.add(10), 2);
            fd::tag_fd(fd::FD_TAG_KEY_VAULT, idx as i32)
        }
        dev_key_vault::PUBLIC => {
            // arg: [out_ptr:u64][out_cap:u16][out_len_out:u16]
            if arg.is_null() || arg_len < 12 {
                return EINVAL;
            }
            if slot_handle < 0 || (slot_handle as usize) >= MAX_SLOTS {
                return EINVAL;
            }
            let slot = &SLOTS[slot_handle as usize];
            if (slot.flags & FLAG_IN_USE) == 0 {
                return EINVAL;
            }
            // Exporting the PUBLIC half is still a permitted use, and one
            // a key can be created without — a key whose public half must
            // not be published is a real thing.
            if !slot.permits(dev_key_vault::usage::EXPORT_PUBLIC) {
                return EACCES;
            }
            let pub_len = suite_public_len(slot.suite);
            if pub_len == 0 {
                return ENOSYS;
            }
            let out_ptr = read_u64(arg) as *mut u8;
            let out_cap = u16::from_le_bytes([*arg.add(8), *arg.add(9)]) as usize;
            if out_cap < pub_len {
                let need = (pub_len as u16).to_le_bytes();
                core::ptr::copy_nonoverlapping(need.as_ptr(), arg.add(10), 2);
                return ERANGE;
            }
            if !out_ptr.is_null() && !write_public(slot_handle as usize, out_ptr, pub_len) {
                return ERROR;
            }
            let wrote = (pub_len as u16).to_le_bytes();
            core::ptr::copy_nonoverlapping(wrote.as_ptr(), arg.add(10), 2);
            0
        }
        dev_key_vault::ATTEST_COMPOSITION => {
            // arg: [challenge:32][out_ptr:u64][out_cap:u16][out_len_out:u16]
            if arg.is_null() || arg_len < 32 + 12 {
                return EINVAL;
            }
            if slot_handle < 0 || (slot_handle as usize) >= MAX_SLOTS {
                return EINVAL;
            }
            let slot = &SLOTS[slot_handle as usize];
            if (slot.flags & FLAG_IN_USE) == 0 || !slot.permits(dev_key_vault::usage::SIGN) {
                return EACCES;
            }
            let sig_len = suite_signature_len(slot.suite);
            if sig_len == 0 {
                return ENOSYS;
            }
            let mut challenge = [0u8; 32];
            core::ptr::copy_nonoverlapping(arg, challenge.as_mut_ptr(), 32);
            let tail = arg.add(32);
            let out_ptr = read_u64(tail) as *mut u8;
            let out_cap = u16::from_le_bytes([*tail.add(8), *tail.add(9)]) as usize;
            let tier = current_tier();
            let rec_ptr = &raw mut ATTEST_RECORD;
            let rec = &mut *rec_ptr;
            let Some(rec_len) = crate::kernel::exec::scheduler::attest::write_record(
                &challenge,
                tier,
                &mut rec[..],
            ) else {
                return ENOMEM;
            };
            let need = rec_len + sig_len;
            if out_cap < need {
                let n = (need.min(u16::MAX as usize) as u16).to_le_bytes();
                core::ptr::copy_nonoverlapping(n.as_ptr(), tail.add(10), 2);
                return ERANGE;
            }
            let Some(sig_written) = sign_bytes(
                slot_handle as usize,
                &rec[..rec_len],
                out_ptr.add(rec_len),
                sig_len,
            ) else {
                return ERROR;
            };
            if !out_ptr.is_null() {
                core::ptr::copy_nonoverlapping(rec.as_ptr(), out_ptr, rec_len);
            }
            let wrote = ((rec_len + sig_written) as u16).to_le_bytes();
            core::ptr::copy_nonoverlapping(wrote.as_ptr(), tail.add(10), 2);
            0
        }
        dev_key_vault::KEY_WRAP => {
            // arg: [dest_pub_len:u16][dest_pub][attest_digest:32]
            //      [out_ptr:u64][out_cap:u16][out_len_out:u16]
            use dev_key_vault::wrap as w;
            if arg.is_null() || arg_len < 2 {
                return EINVAL;
            }
            if slot_handle < 0 || (slot_handle as usize) >= MAX_SLOTS {
                return EINVAL;
            }
            let pub_len = u16::from_le_bytes([*arg, *arg.add(1)]) as usize;
            if pub_len != w::EPH_PUB_LEN || 2 + pub_len + 32 + 12 > arg_len {
                return EINVAL;
            }
            let slot = &SLOTS[slot_handle as usize];
            if (slot.flags & FLAG_IN_USE) == 0 {
                return EINVAL;
            }
            if !slot.permits(dev_key_vault::usage::WRAP) {
                return EACCES;
            }
            let dest_pub = core::slice::from_raw_parts(arg.add(2), pub_len);
            if !p256::public_point_is_valid(dest_pub) {
                return EINVAL;
            }
            let mut attest = [0u8; 32];
            core::ptr::copy_nonoverlapping(arg.add(2 + pub_len), attest.as_mut_ptr(), 32);
            let tail = arg.add(2 + pub_len + 32);
            let out_ptr = read_u64(tail) as *mut u8;
            let out_cap = u16::from_le_bytes([*tail.add(8), *tail.add(9)]) as usize;
            let key_len = slot.key_len as usize;
            let need = w::SEALED_OFF + w::SEALED_PREFIX + key_len + w::TAG_LEN;
            if out_cap < need {
                let n = (need as u16).to_le_bytes();
                core::ptr::copy_nonoverlapping(n.as_ptr(), tail.add(10), 2);
                return ERANGE;
            }
            // Ephemeral agreement key, used once and zeroised.
            let mut eph = [0u8; 32];
            if !generate_into(dev_key_vault::suite::P256, &mut eph) {
                return ERROR;
            }
            let Some(eph_pub) = p256::public_key_from_scalar(&eph) else {
                zeroize(&mut eph);
                return ERROR;
            };
            let shared = p256::ecdh_shared_secret(&eph, dest_pub);
            zeroize(&mut eph);
            let Some(mut shared) = shared else {
                return EINVAL;
            };
            let mut kek = [0u8; 32];
            wrap_kek(&shared, &attest, dest_pub, &mut kek);
            zeroize(&mut shared);
            let mut nonce = [0u8; 12];
            if crate::kernel::sys::hal::csprng_fill(nonce.as_mut_ptr(), 12) != 0 {
                zeroize(&mut kek);
                return ERROR;
            }
            let mut sealed = [0u8; dev_key_vault::wrap::SEALED_PREFIX + MAX_KEY_BYTES];
            sealed[0..2].copy_from_slice(&slot.suite.to_le_bytes());
            sealed[2..6].copy_from_slice(&slot.usage.to_le_bytes());
            sealed[6] = slot.key_len;
            sealed[7..7 + key_len].copy_from_slice(&slot.data[..key_len]);
            let sealed_len = w::SEALED_PREFIX + key_len;
            let tag = crate::kernel::security::crypto::chacha20::chacha20_poly1305_encrypt(
                &kek,
                &nonce,
                &attest,
                &mut sealed[..sealed_len],
            );
            zeroize(&mut kek);
            if !out_ptr.is_null() {
                core::ptr::copy_nonoverlapping(w::MAGIC.as_ptr(), out_ptr, 4);
                core::ptr::copy_nonoverlapping(eph_pub.as_ptr(), out_ptr.add(4), w::EPH_PUB_LEN);
                core::ptr::copy_nonoverlapping(attest.as_ptr(), out_ptr.add(w::ATTEST_OFF), 32);
                core::ptr::copy_nonoverlapping(nonce.as_ptr(), out_ptr.add(w::NONCE_OFF), 12);
                core::ptr::copy_nonoverlapping(
                    sealed.as_ptr(),
                    out_ptr.add(w::SEALED_OFF),
                    sealed_len,
                );
                core::ptr::copy_nonoverlapping(
                    tag.as_ptr(),
                    out_ptr.add(w::SEALED_OFF + sealed_len),
                    16,
                );
            }
            zeroize(&mut sealed);
            let wrote = (need as u16).to_le_bytes();
            core::ptr::copy_nonoverlapping(wrote.as_ptr(), tail.add(10), 2);
            0
        }
        dev_key_vault::KEY_UNWRAP => {
            // arg: [blob_len:u16][blob]
            use dev_key_vault::wrap as w;
            if arg.is_null() || arg_len < 2 {
                return EINVAL;
            }
            if slot_handle < 0 || (slot_handle as usize) >= MAX_SLOTS {
                return EINVAL;
            }
            let blob_len = u16::from_le_bytes([*arg, *arg.add(1)]) as usize;
            if 2 + blob_len > arg_len || blob_len < w::SEALED_OFF + w::SEALED_PREFIX + w::TAG_LEN {
                return EINVAL;
            }
            let blob = core::slice::from_raw_parts(arg.add(2), blob_len);
            if blob[..4] != w::MAGIC {
                return EINVAL;
            }
            let slot = &SLOTS[slot_handle as usize];
            if (slot.flags & FLAG_IN_USE) == 0
                || slot.suite != dev_key_vault::suite::P256
                || slot.key_len != 32
            {
                return EINVAL;
            }
            if !slot.permits(dev_key_vault::usage::AGREE) {
                return EACCES;
            }
            // The blob was wrapped for a composition; it opens only while
            // this one still IS that composition.
            let mut attest = [0u8; 32];
            attest.copy_from_slice(&blob[w::ATTEST_OFF..w::ATTEST_OFF + 32]);
            let rec_ptr = &raw mut ATTEST_RECORD;
            let rec = &mut *rec_ptr;
            let Some(ours) = crate::kernel::exec::scheduler::attest::composition_digest(
                current_tier(),
                &mut rec[..],
            ) else {
                return ENOMEM;
            };
            let mut diff = 0u8;
            let mut i = 0;
            while i < 32 {
                diff |= ours[i] ^ attest[i];
                i += 1;
            }
            if diff != 0 {
                return EACCES;
            }
            let eph_pub = &blob[4..4 + w::EPH_PUB_LEN];
            let mut my_priv = [0u8; 32];
            my_priv.copy_from_slice(&slot.data[..32]);
            let shared = p256::ecdh_shared_secret(&my_priv, eph_pub);
            zeroize(&mut my_priv);
            let Some(mut shared) = shared else {
                return EINVAL;
            };
            let mut k = [0u8; 32];
            k.copy_from_slice(&slot.data[..32]);
            let my_pub = p256::public_key_from_scalar(&k);
            zeroize(&mut k);
            let Some(my_pub) = my_pub else {
                zeroize(&mut shared);
                return ERROR;
            };
            let mut kek = [0u8; 32];
            wrap_kek(&shared, &attest, &my_pub, &mut kek);
            zeroize(&mut shared);
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&blob[w::NONCE_OFF..w::NONCE_OFF + 12]);
            let sealed_len = blob_len - w::SEALED_OFF - w::TAG_LEN;
            if sealed_len < w::SEALED_PREFIX || sealed_len > w::SEALED_PREFIX + MAX_KEY_BYTES {
                zeroize(&mut kek);
                return EINVAL;
            }
            let mut sealed = [0u8; dev_key_vault::wrap::SEALED_PREFIX + MAX_KEY_BYTES];
            sealed[..sealed_len].copy_from_slice(&blob[w::SEALED_OFF..w::SEALED_OFF + sealed_len]);
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&blob[w::SEALED_OFF + sealed_len..]);
            let ok = crate::kernel::security::crypto::chacha20::chacha20_poly1305_decrypt(
                &kek,
                &nonce,
                &attest,
                &mut sealed[..sealed_len],
                &tag,
            );
            zeroize(&mut kek);
            if !ok {
                zeroize(&mut sealed);
                return EINVAL;
            }
            let suite = u16::from_le_bytes([sealed[0], sealed[1]]);
            let usage = u32::from_le_bytes([sealed[2], sealed[3], sealed[4], sealed[5]]);
            let key_len = sealed[6] as usize;
            if suite_private_len(suite) != key_len || usage & !suite_usage(suite) != 0 || usage == 0
            {
                zeroize(&mut sealed);
                return EINVAL;
            }
            let Some(new_slot) = alloc_slot() else {
                zeroize(&mut sealed);
                return ENOMEM;
            };
            let dst = &mut SLOTS[new_slot];
            *dst = Slot::empty();
            dst.suite = suite;
            dst.usage = usage;
            dst.key_len = key_len as u8;
            dst.data[..key_len].copy_from_slice(&sealed[7..7 + key_len]);
            dst.flags = FLAG_IN_USE;
            zeroize(&mut sealed);
            fd::tag_fd(fd::FD_TAG_KEY_VAULT, new_slot as i32)
        }
        dev_key_vault::AEAD_SEAL => {
            // arg: [aad_len:u16][aad][pt_len:u16][pt][out_ptr:u64][out_cap:u16][out_len_out:u16]
            if arg.is_null() || arg_len < 4 {
                return EINVAL;
            }
            if slot_handle < 0 || (slot_handle as usize) >= MAX_SLOTS {
                return EINVAL;
            }
            let slot = &SLOTS[slot_handle as usize];
            if (slot.flags & FLAG_IN_USE) == 0 || slot.suite != dev_key_vault::suite::AEAD_KEY {
                return EINVAL;
            }
            if !slot.permits(dev_key_vault::usage::SEAL) {
                return EACCES;
            }
            let aad_len = u16::from_le_bytes([*arg, *arg.add(1)]) as usize;
            if 2 + aad_len + 2 > arg_len {
                return EINVAL;
            }
            let pt_off = 2 + aad_len + 2;
            let pt_len =
                u16::from_le_bytes([*arg.add(2 + aad_len), *arg.add(2 + aad_len + 1)]) as usize;
            if pt_off + pt_len + 12 > arg_len || pt_len > MAX_SEAL_BYTES {
                return EINVAL;
            }
            let tail = arg.add(pt_off + pt_len);
            let out_ptr = read_u64(tail) as *mut u8;
            let out_cap = u16::from_le_bytes([*tail.add(8), *tail.add(9)]) as usize;
            let need = 12 + pt_len + 16;
            if out_cap < need {
                let n = (need as u16).to_le_bytes();
                core::ptr::copy_nonoverlapping(n.as_ptr(), tail.add(10), 2);
                return ERANGE;
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&slot.data[..32]);
            let mut nonce = [0u8; 12];
            if crate::kernel::sys::hal::csprng_fill(nonce.as_mut_ptr(), 12) != 0 {
                zeroize(&mut key);
                return ERROR;
            }
            let aad = core::slice::from_raw_parts(arg.add(2), aad_len);
            let buf_ptr = &raw mut SEAL_SCRATCH;
            let buf = &mut *buf_ptr;
            core::ptr::copy_nonoverlapping(arg.add(pt_off), buf.as_mut_ptr(), pt_len);
            let tag = crate::kernel::security::crypto::chacha20::chacha20_poly1305_encrypt(
                &key,
                &nonce,
                aad,
                &mut buf[..pt_len],
            );
            zeroize(&mut key);
            if !out_ptr.is_null() {
                core::ptr::copy_nonoverlapping(nonce.as_ptr(), out_ptr, 12);
                core::ptr::copy_nonoverlapping(buf.as_ptr(), out_ptr.add(12), pt_len);
                core::ptr::copy_nonoverlapping(tag.as_ptr(), out_ptr.add(12 + pt_len), 16);
            }
            zeroize(&mut buf[..pt_len]);
            let wrote = (need as u16).to_le_bytes();
            core::ptr::copy_nonoverlapping(wrote.as_ptr(), tail.add(10), 2);
            0
        }
        dev_key_vault::AEAD_OPEN => {
            // arg: [aad_len:u16][aad][blob_len:u16][blob][out_ptr:u64][out_cap:u16][out_len_out:u16]
            if arg.is_null() || arg_len < 4 {
                return EINVAL;
            }
            if slot_handle < 0 || (slot_handle as usize) >= MAX_SLOTS {
                return EINVAL;
            }
            let slot = &SLOTS[slot_handle as usize];
            if (slot.flags & FLAG_IN_USE) == 0 || slot.suite != dev_key_vault::suite::AEAD_KEY {
                return EINVAL;
            }
            if !slot.permits(dev_key_vault::usage::OPEN) {
                return EACCES;
            }
            let aad_len = u16::from_le_bytes([*arg, *arg.add(1)]) as usize;
            if 2 + aad_len + 2 > arg_len {
                return EINVAL;
            }
            let blob_off = 2 + aad_len + 2;
            let blob_len =
                u16::from_le_bytes([*arg.add(2 + aad_len), *arg.add(2 + aad_len + 1)]) as usize;
            if blob_off + blob_len + 12 > arg_len
                || blob_len < 12 + 16
                || blob_len - 28 > MAX_SEAL_BYTES
            {
                return EINVAL;
            }
            let pt_len = blob_len - 28;
            let tail = arg.add(blob_off + blob_len);
            let out_ptr = read_u64(tail) as *mut u8;
            let out_cap = u16::from_le_bytes([*tail.add(8), *tail.add(9)]) as usize;
            if out_cap < pt_len {
                let n = (pt_len as u16).to_le_bytes();
                core::ptr::copy_nonoverlapping(n.as_ptr(), tail.add(10), 2);
                return ERANGE;
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&slot.data[..32]);
            let mut nonce = [0u8; 12];
            core::ptr::copy_nonoverlapping(arg.add(blob_off), nonce.as_mut_ptr(), 12);
            let mut tag = [0u8; 16];
            core::ptr::copy_nonoverlapping(arg.add(blob_off + 12 + pt_len), tag.as_mut_ptr(), 16);
            let aad = core::slice::from_raw_parts(arg.add(2), aad_len);
            let buf_ptr = &raw mut SEAL_SCRATCH;
            let buf = &mut *buf_ptr;
            core::ptr::copy_nonoverlapping(arg.add(blob_off + 12), buf.as_mut_ptr(), pt_len);
            let ok = crate::kernel::security::crypto::chacha20::chacha20_poly1305_decrypt(
                &key,
                &nonce,
                aad,
                &mut buf[..pt_len],
                &tag,
            );
            zeroize(&mut key);
            if !ok {
                zeroize(&mut buf[..pt_len]);
                return EINVAL;
            }
            if !out_ptr.is_null() {
                core::ptr::copy_nonoverlapping(buf.as_ptr(), out_ptr, pt_len);
            }
            zeroize(&mut buf[..pt_len]);
            let wrote = (pt_len as u16).to_le_bytes();
            core::ptr::copy_nonoverlapping(wrote.as_ptr(), tail.add(10), 2);
            0
        }
        dev_key_vault::TIER => {
            // Isolation honesty, and the one place
            // persistence must NOT be allowed to speak.
            //
            // This backend can now seal keys so they survive a restart —
            // see `seal_slot`. That is durability, and durability is not
            // isolation. The tier is derived from where the platform's
            // sealing key COMES FROM, never from whether sealing works:
            //
            //   - no sealing, or a key the host can also read
            //       → `SOFTWARE`. The blob is opaque to a compromised
            //         module and transparent to a compromised host, which
            //         is exactly what `SOFTWARE` already means. Persisting
            //         it changes nothing about that.
            //   - a key bound to the device and not extractable from it
            //       → `DEVICE_HW`. Only here has anything actually been
            //         isolated from the host.
            //
            // A backend that reported a higher tier because it had learned
            // to persist would hand every consumer checking `tier >= N` a
            // guarantee nobody implemented. The consumers are checking in
            // order to refuse; giving them the wrong answer defeats the
            // refusal silently.
            if arg.is_null() || arg_len < 1 {
                return EINVAL;
            }
            *arg = match crate::kernel::sys::hal::seal_provenance() {
                crate::kernel::sys::hal::SealProvenance::DeviceUnique => {
                    dev_key_vault::tier::DEVICE_HW
                }
                _ => dev_key_vault::tier::SOFTWARE,
            };
            1
        }
        dev_key_vault::SUITE_QUERY => {
            // arg: [suite:u16][_pad:u16][usage_out:u32]
            //      [priv_len_out:u16][pub_len_out:u16][sig_len_out:u16]
            if arg.is_null() || arg_len < 14 {
                return EINVAL;
            }
            let suite = u16::from_le_bytes([*arg, *arg.add(1)]);
            let priv_len = suite_private_len(suite);
            if priv_len == 0 {
                // A suite this backend cannot use is `ENOSYS`, not a
                // zero-filled answer: the sizes are what a caller allocates
                // from, and zeros would read as "supported, needs nothing".
                return ENOSYS;
            }
            let usage = suite_usage(suite).to_le_bytes();
            core::ptr::copy_nonoverlapping(usage.as_ptr(), arg.add(4), 4);
            let pl = (priv_len as u16).to_le_bytes();
            core::ptr::copy_nonoverlapping(pl.as_ptr(), arg.add(8), 2);
            let pub_l = (suite_public_len(suite) as u16).to_le_bytes();
            core::ptr::copy_nonoverlapping(pub_l.as_ptr(), arg.add(10), 2);
            let sig_l = (suite_signature_len(suite) as u16).to_le_bytes();
            core::ptr::copy_nonoverlapping(sig_l.as_ptr(), arg.add(12), 2);
            14
        }
        dev_key_vault::SUITE_ENUM => {
            // arg: [cursor:u16][_pad:u16][out_ptr:u64][out_cap:u16][count_out:u16]
            if arg.is_null() || arg_len < 16 {
                return EINVAL;
            }
            let cursor = u16::from_le_bytes([*arg, *arg.add(1)]);
            let out_ptr = read_u64(arg.add(4)) as *mut u8;
            let out_cap = u16::from_le_bytes([*arg.add(12), *arg.add(13)]) as usize;
            let mut written = 0usize;
            let mut next = cursor;
            while next <= dev_key_vault::suite::MAX_ID {
                if suite_private_len(next) != 0 {
                    if (written + 1) * 2 > out_cap {
                        break;
                    }
                    if !out_ptr.is_null() {
                        let b = next.to_le_bytes();
                        core::ptr::copy_nonoverlapping(b.as_ptr(), out_ptr.add(written * 2), 2);
                    }
                    written += 1;
                }
                next += 1;
            }
            let cw = (written as u16).to_le_bytes();
            core::ptr::copy_nonoverlapping(cw.as_ptr(), arg.add(14), 2);
            // 0 when the enumeration is complete, so a caller loops until
            // it sees zero rather than having to know how many suites exist.
            if next > dev_key_vault::suite::MAX_ID {
                0
            } else {
                i32::from(next)
            }
        }
        dev_key_vault::DESCRIBE => {
            // arg: [suite_out:u16][usage_out:u32][tier_out:u8][persisted_out:u8]
            if arg.is_null() || arg_len < 8 {
                return EINVAL;
            }
            if slot_handle < 0 || (slot_handle as usize) >= MAX_SLOTS {
                return EINVAL;
            }
            let slot = &SLOTS[slot_handle as usize];
            if (slot.flags & FLAG_IN_USE) == 0 {
                return EINVAL;
            }
            let sb = slot.suite.to_le_bytes();
            core::ptr::copy_nonoverlapping(sb.as_ptr(), arg, 2);
            let ub = slot.usage.to_le_bytes();
            core::ptr::copy_nonoverlapping(ub.as_ptr(), arg.add(2), 4);
            // Reported side by side and meaning different things. The tier
            // says what this key is isolated from; `persisted` says whether
            // it comes back after a restart. A key can be persisted and
            // isolated from nothing, which is the ordinary case on a host
            // with no device-unique sealing key.
            *arg.add(6) = match crate::kernel::sys::hal::seal_provenance() {
                crate::kernel::sys::hal::SealProvenance::DeviceUnique => {
                    dev_key_vault::tier::DEVICE_HW
                }
                _ => dev_key_vault::tier::SOFTWARE,
            };
            *arg.add(7) = u8::from((slot.flags & FLAG_PERSISTED) != 0);
            8
        }
        dev_key_vault::OPEN_OR_GENERATE | dev_key_vault::OPEN => {
            // arg: [suite:u16][usage_mask:u32][flags:u8][label_len:u8]
            //      [label[label_len]]
            //      [pub_out_ptr:u64][pub_out_cap:u16][pub_len_out:u16]
            if arg.is_null() || arg_len < 8 {
                return EINVAL;
            }
            let suite = u16::from_le_bytes([*arg, *arg.add(1)]);
            let usage = u32::from_le_bytes([*arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5)]);
            let label_len = *arg.add(7) as usize;
            if label_len == 0 || label_len > MAX_LABEL || 8 + label_len + 12 > arg_len {
                return EINVAL;
            }
            let mut label = [0u8; MAX_LABEL];
            for (j, b) in label.iter_mut().take(label_len).enumerate() {
                *b = *arg.add(8 + j);
            }
            let label = &label[..label_len];
            let tail = arg.add(8 + label_len);
            let pub_ptr = read_u64(tail) as *mut u8;
            let pub_cap = u16::from_le_bytes([*tail.add(8), *tail.add(9)]) as usize;

            let priv_len = suite_private_len(suite);
            let pub_len = suite_public_len(suite);
            if priv_len == 0 {
                return ENOSYS;
            }

            // An already-open slot under this label is returned as-is. Two
            // handles onto one key would each be destroyable independently,
            // and the second destroy would find a slot the first had freed.
            let slots = &raw const SLOTS;
            let existing = (*slots)
                .iter()
                .position(|s| (s.flags & FLAG_IN_USE) != 0 && s.label_bytes() == label);

            let idx = match existing {
                Some(i) => i,
                None => match find_persisted(label) {
                    Some(pi) => {
                        // The mask is CHECKED against what the key was born
                        // with, never applied. A reopen asking for more than
                        // the key has is refused: permitted uses must not be
                        // something a later caller widens by asking.
                        if usage & !PERSISTED[pi].usage != 0 {
                            return EACCES;
                        }
                        match open_persisted(pi) {
                            Some(i) => i,
                            None => {
                                log::warn!(
                                    "[vault] open refused: persisted entry would not reopen (suite={suite})"
                                );
                                return ERROR;
                            }
                        }
                    }
                    None => {
                        if opcode == dev_key_vault::OPEN {
                            return ENOENT;
                        }
                        if usage == 0 || usage & !suite_usage(suite) != 0 {
                            log::warn!(
                                "[vault] open refused: usage {usage:#x} outside suite {suite}'s mask"
                            );
                            return EINVAL;
                        }
                        let Some(i) = alloc_slot() else {
                            log::warn!("[vault] open refused: no free slot (suite={suite})");
                            return ENOMEM;
                        };
                        let mut key = [0u8; MAX_KEY_BYTES];
                        if !generate_into(suite, &mut key[..priv_len]) {
                            log::warn!("[vault] open refused: keygen failed (suite={suite})");
                            return ERROR;
                        }
                        SLOTS[i].suite = suite;
                        SLOTS[i].usage = usage;
                        SLOTS[i].key_len = priv_len as u8;
                        SLOTS[i].label[..label_len].copy_from_slice(label);
                        SLOTS[i].label_len = label_len as u8;
                        for (j, b) in key.iter().take(priv_len).enumerate() {
                            core::ptr::write_volatile(&raw mut SLOTS[i].data[j], *b);
                        }
                        let sealed = if usage & dev_key_vault::usage::PERSIST != 0 {
                            persist_key(label, suite, usage, &key[..priv_len])
                        } else {
                            false
                        };
                        for b in key.iter_mut() {
                            core::ptr::write_volatile(b, 0);
                        }
                        SLOTS[i].flags = FLAG_IN_USE | if sealed { FLAG_PERSISTED } else { 0 };
                        i
                    }
                },
            };

            // Public half back to the caller, sized honestly.
            if pub_cap < pub_len {
                let need = (pub_len as u16).to_le_bytes();
                core::ptr::copy_nonoverlapping(need.as_ptr(), tail.add(10), 2);
                return ERANGE;
            }
            if !pub_ptr.is_null() && !write_public(idx, pub_ptr, pub_len) {
                log::warn!("[vault] open refused: public-key derivation failed (suite={suite})");
                return ERROR;
            }
            let wrote = (pub_len as u16).to_le_bytes();
            core::ptr::copy_nonoverlapping(wrote.as_ptr(), tail.add(10), 2);
            fd::tag_fd(fd::FD_TAG_KEY_VAULT, idx as i32)
        }
        dev_key_vault::DESTROY_BY_LABEL => {
            // arg: [label_len:u8][label[label_len]]
            if arg.is_null() || arg_len < 2 {
                return EINVAL;
            }
            let label_len = *arg as usize;
            if label_len == 0 || label_len > MAX_LABEL || 1 + label_len > arg_len {
                return EINVAL;
            }
            let mut label = [0u8; MAX_LABEL];
            for (j, b) in label.iter_mut().take(label_len).enumerate() {
                *b = *arg.add(1 + j);
            }
            let label = &label[..label_len];
            let mut found = false;
            // The live slot AND the sealed blob. Destroying only the handle
            // would free a slot and leave the blob, which comes back on the
            // next open — so a revocation that used it would not revoke.
            // Collected first: `zeroise_slot` takes a mutable borrow, so
            // the scan and the wipe cannot share one iteration.
            let slots = &raw const SLOTS;
            let mut victims = [usize::MAX; MAX_SLOTS];
            let mut n = 0usize;
            for (i, sl) in (*slots).iter().enumerate() {
                if (sl.flags & FLAG_IN_USE) != 0 && sl.label_bytes() == label {
                    victims[n] = i;
                    n += 1;
                }
            }
            for &i in victims.iter().take(n) {
                zeroise_slot(i);
                found = true;
            }
            if let Some(pi) = find_persisted(label) {
                let e = &raw mut PERSISTED[pi];
                for b in (*e).sealed.iter_mut() {
                    core::ptr::write_volatile(b, 0);
                }
                PERSISTED[pi] = Persisted::empty();
                found = true;
            }
            if found {
                0
            } else {
                ENOENT
            }
        }
        _ => ENOSYS,
    }
}
