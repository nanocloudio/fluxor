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
        }
        dev_key_vault::suite::ED25519 => {
            dev_key_vault::usage::SIGN
                | dev_key_vault::usage::VERIFY
                | dev_key_vault::usage::EXPORT_PUBLIC
                | dev_key_vault::usage::PERSIST
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
