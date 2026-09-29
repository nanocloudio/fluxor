//! KEY_VAULT device class — the kernel *software backend* for the
//! `key_vault` contract: opaque custody of asymmetric and symmetric keys.
//!
//! Callers STORE or GENERATE a private key and receive an opaque handle.
//! The raw bytes live in kernel static memory and are never returned to
//! callers. Keys are zeroised on DESTROY, and once the module that owns one
//! is gone: its scheduler slot has been reoccupied by a restart, a
//! replacement or a graph rebuild, so no handle to the key can resolve any
//! more (`reap_orphans`).
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
#[cfg(feature = "rsa-vault")]
use crate::abi::errno::EAGAIN;
use crate::abi::errno::{EACCES, EBUSY, EINVAL, ENOENT, ENOMEM, ENOSYS, ERANGE, ERROR};

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
#[cfg(feature = "rsa-vault")]
use crate::kernel::security::crypto::rsa;
use crate::kernel::security::crypto::{ed25519, ml_dsa, p256};
use crate::kernel::security::key_share;

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
/// The RSA keys this backend holds, and the one signing job that runs
/// over them.
///
/// A CRT key is kilobytes rather than the 64 bytes a slot carries, so an
/// RSA slot's `data` names an entry here instead. Two entries: an identity
/// and its successor during a rotation. Statics for the same reason as
/// the ML-DSA workspace — no caller reaches this code on a stack that could
/// hold them — and gated as a per-target capability for the same reason.
///
/// `RSA_JOB_SLOT` is the vault slot whose signature is in progress, or -1;
/// `RSA_JOB_DIGEST` is what it is signing, so a `SIGN` that continues the
/// job can be told from one that would start another.
#[cfg(feature = "rsa-vault")]
const RSA_ENTRIES: usize = 2;
#[cfg(feature = "rsa-vault")]
static mut RSA_KEYS: [rsa::RsaPrivateKey; RSA_ENTRIES] =
    [rsa::RsaPrivateKey::empty(), rsa::RsaPrivateKey::empty()];
#[cfg(feature = "rsa-vault")]
static mut RSA_SIGN: rsa::RsaSignJob = rsa::RsaSignJob::new();
#[cfg(feature = "rsa-vault")]
static mut RSA_JOB_SLOT: i32 = -1;
#[cfg(feature = "rsa-vault")]
static mut RSA_JOB_DIGEST: [u8; 32] = [0; 32];
/// Limb-rows of a Montgomery product one `SIGN` call advances a job by:
/// a row of a half-modulus costs one pass over its limbs, so the budget
/// is spent as 256 rows of a 2048-bit key's 16-limb halves or 128 rows
/// of a 4096-bit key's, so a call is a bounded slice of the work however
/// wide the key; a 2048-bit signature completes in on the order of two
/// hundred calls, a 4096-bit one in about eight times as many.
#[cfg(feature = "rsa-vault")]
const RSA_SIGN_LIMB_ROWS_PER_CALL: usize = 256 * 16;

/// The rows one `SIGN` call advances `key` by; see
/// `RSA_SIGN_LIMB_ROWS_PER_CALL`.
#[cfg(feature = "rsa-vault")]
fn rsa_sign_rows_per_call(key: &rsa::RsaPrivateKey) -> usize {
    let limb_bits = core::mem::size_of::<rsa::RsaLimb>() * 8;
    let half_limbs = (key.n.bits() / 2).div_ceil(limb_bits).max(1);
    (RSA_SIGN_LIMB_ROWS_PER_CALL / half_limbs).max(1)
}

/// The RSA suite a modulus width belongs to.
#[cfg(feature = "rsa-vault")]
const fn rsa_suite_for_bits(bits: usize) -> u16 {
    match bits {
        2048 => dev_key_vault::suite::RSA_2048,
        3072 => dev_key_vault::suite::RSA_3072,
        4096 => dev_key_vault::suite::RSA_4096,
        _ => dev_key_vault::suite::NONE,
    }
}

const fn is_rsa_suite(suite: u16) -> bool {
    matches!(
        suite,
        dev_key_vault::suite::RSA_2048
            | dev_key_vault::suite::RSA_3072
            | dev_key_vault::suite::RSA_4096
    )
}

/// P-256 group order n (big-endian). Every P-256 scalar this vault
/// holds must lie in [1, n-1]: GENERATE rejection-samples into that
/// range and STORE refuses anything outside it. `d == 0` signs under
/// the identity and `d >= n` is a non-canonical encoding of `d mod n`.
const P256_ORDER_BE: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];
/// Number of key slots, per profile.
///
/// A slot is held by each open key: a TLS identity, a labelled sealing or
/// MAC key, a volume master, and every purpose key derived from one or
/// reconstructed from shares. With no free slot, generate, import, open,
/// derive and unwrap are refused `ENOMEM`: a consumer refuses its operation
/// rather than falling back.
#[cfg(target_arch = "aarch64")]
pub const MAX_SLOTS: usize = 64;
#[cfg(not(target_arch = "aarch64"))]
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
#[derive(Clone, Copy)]
struct Slot {
    flags: u8,
    key_len: u8,
    /// The key's suite (`key_vault::suite`).
    suite: u16,
    /// Permitted uses, sealed at creation and checked per operation.
    ///
    /// Sealed rather than passed per call, because a per-call permission
    /// is one the caller grants itself.
    usage: u32,
    /// The label this key is filed under, empty for an unnamed slot.
    label: [u8; MAX_LABEL],
    label_len: u8,
    /// Scheduler slot of the module that owns this key, or `KERNEL_OWNER`.
    owner: u8,
    _pad: [u8; 2],
    /// Which occupancy of that scheduler slot: a module restarted or
    /// replaced in the same slot is another owner.
    owner_generation: u32,
    /// The label namespace: the owner's module type. Labels are unique
    /// within a namespace, and no module reaches another type's labels.
    namespace: u32,
    /// Bumped each time this slot is freed, and carried in every handle to
    /// it, so a handle to a freed key cannot reach whatever key the slot
    /// holds next.
    generation: u32,
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
            owner: KERNEL_OWNER,
            _pad: [0; 2],
            owner_generation: 0,
            namespace: 0,
            generation: 0,
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
static mut SLOTS: [Slot; MAX_SLOTS] = [Slot::empty(); MAX_SLOTS];

// ── Handle authority ────────────────────────────────────────────────────
//
// A handle names one key for one owner. It carries the slot index and the
// slot's generation, so it stops working when the key is destroyed rather
// than reaching whatever the slot holds next; and the slot records the
// module that created it, so a handle is useless to any other module.
// Every slot-bound operation resolves its handle through `resolve`, which
// checks all of that before anything touches key material.

/// Owner of a key created by kernel code outside any module.
const KERNEL_OWNER: u8 = u8::MAX;
/// Handle bits naming the slot; the generation sits above them.
const SLOT_BITS: u32 = 6;
const SLOT_MASK: i32 = (1 << SLOT_BITS) - 1;
/// Generation bits a handle carries: the tagged-fd slot field less the
/// slot index and the router's backend bit.
const GENERATION_MASK: u32 = (1 << 19) - 1;
const _: () = assert!(MAX_SLOTS <= 1 << SLOT_BITS);

/// Who is asking.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Caller {
    slot: u8,
    generation: u32,
    namespace: u32,
}

/// The module whose code is running — the one a key it creates belongs to.
fn caller() -> Caller {
    use crate::kernel::exec::scheduler;
    let idx = scheduler::current_module_index();
    if idx >= scheduler::MAX_MODULES || idx >= KERNEL_OWNER as usize {
        return Caller {
            slot: KERNEL_OWNER,
            generation: 0,
            namespace: 0,
        };
    }
    Caller {
        slot: idx as u8,
        generation: scheduler::module_slot_generation(idx),
        namespace: scheduler::module_type_hash(idx),
    }
}

/// The calling module as a key owner, `(scheduler slot, occupancy)`: what
/// another backend records so its handles are owner-scoped the same way.
#[cfg(feature = "host-hsm")]
pub(crate) fn caller_owner() -> (u8, u32) {
    let c = caller();
    (c.slot, c.generation)
}

/// Whether the module occupancy `(slot, generation)` still exists: a
/// scheduler slot holds a new occupancy after a restart, a replacement or a
/// graph rebuild, and everything the old one owned is unreachable. Kernel
/// code has no scheduler slot and is always live.
pub(crate) fn owner_is_live(slot: u8, generation: u32) -> bool {
    slot == KERNEL_OWNER
        || crate::kernel::exec::scheduler::module_slot_generation(slot as usize) == generation
}

/// Zeroise every key whose owning module occupancy has ended.
///
/// Such a key can no longer be used, destroyed or reopened by anyone: its
/// handles resolve `EACCES` to every other occupancy, and a labelled one
/// would keep every later instance of its module type out with `EBUSY`.
/// Run before anything that allocates a slot or looks a label up, so an
/// orphan never holds a slot or a label against a live module.
///
/// # Safety
/// Kernel context, exclusive access to `SLOTS`.
unsafe fn reap_orphans() {
    for i in 0..MAX_SLOTS {
        if is_orphan(i) {
            zeroise_slot(i);
        }
    }
}

/// Whether slot `i` holds a key whose owning module occupancy has ended.
///
/// # Safety
/// Kernel context, exclusive access to `SLOTS`.
unsafe fn is_orphan(i: usize) -> bool {
    SLOTS[i].flags & FLAG_IN_USE != 0 && !owner_is_live(SLOTS[i].owner, SLOTS[i].owner_generation)
}

/// Whether `c` owns slot `i`.
///
/// # Safety
/// Kernel context, exclusive access to `SLOTS`.
unsafe fn owned_by(i: usize, c: Caller) -> bool {
    SLOTS[i].owner == c.slot && SLOTS[i].owner_generation == c.generation
}

/// Give slot `i` to the caller and return its handle.
///
/// # Safety
/// Kernel context, exclusive access to `SLOTS`.
unsafe fn mint(i: usize) -> i32 {
    let c = caller();
    SLOTS[i].owner = c.slot;
    SLOTS[i].owner_generation = c.generation;
    SLOTS[i].namespace = c.namespace;
    handle_of(i)
}

/// The handle naming slot `i` at its current generation.
///
/// # Safety
/// Kernel context, exclusive access to `SLOTS`.
unsafe fn handle_of(i: usize) -> i32 {
    let g = (SLOTS[i].generation & GENERATION_MASK) as i32;
    fd::tag_fd(fd::FD_TAG_KEY_VAULT, (g << SLOT_BITS) | i as i32)
}

/// The slot `handle` names, if the caller may use it: `EINVAL` for
/// something that is not a vault handle, `ENOENT` for a key that no longer
/// exists, `EACCES` for another module's key.
///
/// # Safety
/// Kernel context, exclusive access to `SLOTS`.
unsafe fn resolve(handle: i32) -> Result<usize, i32> {
    if handle < 0 {
        return Err(EINVAL);
    }
    let (tag, field) = fd::untag_fd(handle);
    // A key another backend holds is not this backend's to resolve.
    if tag != fd::FD_TAG_KEY_VAULT
        || field & crate::kernel::security::key_vault_router::HARDWARE_FIELD_BIT != 0
    {
        return Err(EINVAL);
    }
    let i = (field & SLOT_MASK) as usize;
    let g = (field >> SLOT_BITS) as u32;
    if i >= MAX_SLOTS {
        return Err(EINVAL);
    }
    if (SLOTS[i].flags & FLAG_IN_USE) == 0 || SLOTS[i].generation & GENERATION_MASK != g {
        return Err(ENOENT);
    }
    // A key whose owner is gone no longer exists, for anyone.
    if !owner_is_live(SLOTS[i].owner, SLOTS[i].owner_generation) {
        zeroise_slot(i);
        return Err(ENOENT);
    }
    if !owned_by(i, caller()) {
        return Err(EACCES);
    }
    Ok(i)
}
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

/// Persisted entries, per profile like the slot table. Bounded because this
/// is kernel static memory. A durable record needs no entry to exist; the
/// entry is the RAM copy that lets a labelled key come back after a scheduler
/// reset without the platform's store. A record that proves out when every
/// entry is taken refuses the open `ENOMEM` rather than reading as absent.
#[cfg(target_arch = "aarch64")]
const MAX_PERSISTED: usize = 64;
#[cfg(not(target_arch = "aarch64"))]
const MAX_PERSISTED: usize = 8;

/// Longest sealed blob: the key material plus the AEAD's nonce and tag,
/// with room for a larger suite than P-256.
const MAX_SEALED: usize = MAX_KEY_BYTES + 12 + 16;

/// A persisted record's header: `FXVK ‖ namespace:u32 ‖ suite:u16 ‖
/// usage:u32 ‖ label_len:u8 ‖ label`. It is the associated data of the key's
/// seal, so every fact a key is filed under is authenticated with the key: a
/// header altered at rest — a widened usage, another suite, another label —
/// makes the record not open, rather than open as something else.
const RECORD_MAGIC: [u8; 4] = *b"FXVK";
const MAX_HEADER: usize = 4 + 4 + 2 + 4 + 1 + MAX_LABEL;
/// Longest durable name: `namespace:u32 (big-endian) ‖ label`.
const MAX_BLOB_NAME: usize = 4 + MAX_LABEL;

#[repr(C)]
#[derive(Clone, Copy)]
struct Persisted {
    live: bool,
    label: [u8; MAX_LABEL],
    label_len: u8,
    suite: u16,
    usage: u32,
    namespace: u32,
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
            namespace: 0,
            sealed: [0; MAX_SEALED],
            sealed_len: 0,
        }
    }

    fn label_bytes(&self) -> &[u8] {
        &self.label[..self.label_len as usize]
    }
}

static mut PERSISTED: [Persisted; MAX_PERSISTED] = [Persisted::empty(); MAX_PERSISTED];

/// The record header for a key, written into `out`; returns its length.
fn record_header(
    namespace: u32,
    label: &[u8],
    suite: u16,
    usage: u32,
    out: &mut [u8; MAX_HEADER],
) -> usize {
    out[0..4].copy_from_slice(&RECORD_MAGIC);
    out[4..8].copy_from_slice(&namespace.to_le_bytes());
    out[8..10].copy_from_slice(&suite.to_le_bytes());
    out[10..14].copy_from_slice(&usage.to_le_bytes());
    #[expect(clippy::cast_possible_truncation, reason = "bounded by MAX_LABEL")]
    {
        out[14] = label.len() as u8;
    }
    out[15..15 + label.len()].copy_from_slice(label);
    15 + label.len()
}

/// The durable name a key is filed under: its namespace, then its label.
fn blob_name(namespace: u32, label: &[u8], out: &mut [u8; MAX_BLOB_NAME]) -> usize {
    out[0..4].copy_from_slice(&namespace.to_be_bytes());
    out[4..4 + label.len()].copy_from_slice(label);
    4 + label.len()
}

/// Find a persisted entry by namespace and label: `Ok(None)` when no such
/// key exists, `Err(ENOMEM)` when one does but the RAM table has no entry
/// free to hold it. The two must not be confused: a caller that takes the
/// second for the first would generate a key over the one that exists.
///
/// # Safety
/// Kernel context, exclusive access to `PERSISTED`.
unsafe fn find_persisted(namespace: u32, label: &[u8]) -> Result<Option<usize>, i32> {
    let table = &raw const PERSISTED;
    for (i, e) in (*table).iter().enumerate() {
        if e.live && e.namespace == namespace && e.label_bytes() == label {
            return Ok(Some(i));
        }
    }
    // Not in RAM — this may be a fresh process. Ask the platform whether it
    // kept one, which is what makes a labelled key survive a COLD restart
    // rather than only a scheduler reset. Without it an issuer would re-key
    // on every start and every credential it had signed would stop verifying,
    // silently: a verifier just sees a bad signature.
    rehydrate_persisted(namespace, label)
}

/// Pull a sealed record back from the platform into the RAM table.
///
/// The header is checked against what was asked for and then proven by
/// unsealing with it: a record whose header does not parse, names another
/// key, or does not open under its own header is treated as absent rather
/// than guessed at. A record that proves out but has no RAM entry to land in
/// is `Err(ENOMEM)`, not absent.
///
/// # Safety
/// Kernel context, exclusive access to `PERSISTED`.
unsafe fn rehydrate_persisted(namespace: u32, label: &[u8]) -> Result<Option<usize>, i32> {
    if label.is_empty() || label.len() > MAX_LABEL {
        return Ok(None);
    }
    let mut name = [0u8; MAX_BLOB_NAME];
    let name_len = blob_name(namespace, label, &mut name);
    let mut blob = [0u8; MAX_HEADER + MAX_SEALED];
    let Some(n) = crate::kernel::sys::hal::seal_blob_read(&name[..name_len], &mut blob) else {
        return Ok(None);
    };
    if n < 15 || blob[0..4] != RECORD_MAGIC {
        return Ok(None);
    }
    let suite = u16::from_le_bytes([blob[8], blob[9]]);
    let usage = u32::from_le_bytes([blob[10], blob[11], blob[12], blob[13]]);
    let mut header = [0u8; MAX_HEADER];
    let h = record_header(namespace, label, suite, usage, &mut header);
    if n <= h || blob[..h] != header[..h] || n - h > MAX_SEALED {
        return Ok(None);
    }
    // Proven here, not at first use: a record that does not open under its
    // own header is not this key.
    let mut probe = [0u8; MAX_KEY_BYTES];
    let opened = crate::kernel::sys::hal::unseal(&header[..h], &blob[h..n], &mut probe);
    zeroize(&mut probe);
    if opened.is_none() {
        return Ok(None);
    }
    let table = &raw const PERSISTED;
    let Some(idx) = (*table).iter().position(|e| !e.live) else {
        return Err(ENOMEM);
    };
    PERSISTED[idx] = Persisted::empty();
    PERSISTED[idx].label[..label.len()].copy_from_slice(label);
    #[expect(clippy::cast_possible_truncation, reason = "bounded by MAX_LABEL")]
    {
        PERSISTED[idx].label_len = label.len() as u8;
    }
    PERSISTED[idx].namespace = namespace;
    PERSISTED[idx].suite = suite;
    PERSISTED[idx].usage = usage;
    PERSISTED[idx].sealed[..n - h].copy_from_slice(&blob[h..n]);
    #[expect(clippy::cast_possible_truncation, reason = "bounded by MAX_SEALED")]
    {
        PERSISTED[idx].sealed_len = (n - h) as u8;
    }
    PERSISTED[idx].live = true;
    zeroize(&mut blob);
    Ok(Some(idx))
}

/// What persisting a key achieved.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Persist {
    /// Sealed and durably stored: the key survives a restart.
    Durable,
    /// This platform cannot seal, or has no durable store: the key serves
    /// this process and does not come back after a restart. `DESCRIBE`
    /// reports it unpersisted.
    Unavailable,
    /// The platform stores keys and this one could not be stored. The key
    /// must not be handed out as persistent.
    Failed,
}

/// Seal `key` under `namespace`/`label` and store it durably.
///
/// # Safety
/// Kernel context, exclusive access to `PERSISTED`.
unsafe fn persist_key(namespace: u32, label: &[u8], suite: u16, usage: u32, key: &[u8]) -> Persist {
    if label.is_empty() || label.len() > MAX_LABEL {
        return Persist::Failed;
    }
    let mut header = [0u8; MAX_HEADER];
    let h = record_header(namespace, label, suite, usage, &mut header);
    let mut sealed = [0u8; MAX_SEALED];
    let Some(n) = crate::kernel::sys::hal::seal(&header[..h], key, &mut sealed) else {
        // No sealing on this platform. The key still works for this boot;
        // it simply will not come back, and `DESCRIBE` reports that
        // truthfully rather than claiming a persistence that is not there.
        return Persist::Unavailable;
    };
    let mut record = [0u8; MAX_HEADER + MAX_SEALED];
    record[..h].copy_from_slice(&header[..h]);
    record[h..h + n].copy_from_slice(&sealed[..n]);
    let mut name = [0u8; MAX_BLOB_NAME];
    let name_len = blob_name(namespace, label, &mut name);
    let outcome = if crate::kernel::sys::hal::seal_blob_write(&name[..name_len], &record[..h + n]) {
        Persist::Durable
    } else if crate::kernel::sys::hal::seal_blob_store() {
        log::warn!("[vault] persist failed: sealed record not durably stored (suite={suite})");
        Persist::Failed
    } else {
        Persist::Unavailable
    };
    zeroize(&mut record);
    if outcome == Persist::Failed {
        zeroize(&mut sealed);
        return outcome;
    }
    // The RAM entry carries the key across a scheduler reset, whether or not
    // the platform could keep it across a restart.
    let idx = match find_persisted(namespace, label) {
        Ok(Some(i)) => i,
        Ok(None) | Err(_) => {
            let table = &raw const PERSISTED;
            match (*table).iter().position(|e| !e.live) {
                Some(i) => i,
                None => {
                    zeroize(&mut sealed);
                    return if outcome == Persist::Durable {
                        outcome
                    } else {
                        Persist::Unavailable
                    };
                }
            }
        }
    };
    PERSISTED[idx] = Persisted::empty();
    PERSISTED[idx].label[..label.len()].copy_from_slice(label);
    PERSISTED[idx].label_len = label.len() as u8;
    PERSISTED[idx].namespace = namespace;
    PERSISTED[idx].suite = suite;
    PERSISTED[idx].usage = usage;
    PERSISTED[idx].sealed[..n].copy_from_slice(&sealed[..n]);
    PERSISTED[idx].sealed_len = n as u8;
    PERSISTED[idx].live = true;
    zeroize(&mut sealed);
    outcome
}

/// Load a slot from a persisted entry. Returns the slot index, `ENOMEM`
/// when no slot is free, or `ERROR` when the entry does not unseal.
///
/// # Safety
/// Kernel context, exclusive access to `SLOTS` and `PERSISTED`.
unsafe fn open_persisted(idx: usize) -> Result<usize, i32> {
    let entry = PERSISTED[idx];
    let mut header = [0u8; MAX_HEADER];
    let h = record_header(
        entry.namespace,
        entry.label_bytes(),
        entry.suite,
        entry.usage,
        &mut header,
    );
    let mut key = [0u8; MAX_KEY_BYTES];
    let Some(n) = crate::kernel::sys::hal::unseal(
        &header[..h],
        &entry.sealed[..entry.sealed_len as usize],
        &mut key,
    ) else {
        return Err(ERROR);
    };
    if n == 0 || n > MAX_KEY_BYTES {
        zeroize(&mut key);
        return Err(ERROR);
    }
    let Some(slot) = alloc_slot() else {
        zeroize(&mut key);
        return Err(ENOMEM);
    };
    SLOTS[slot].suite = entry.suite;
    SLOTS[slot].usage = entry.usage;
    SLOTS[slot].key_len = n as u8;
    SLOTS[slot].label[..entry.label_len as usize]
        .copy_from_slice(&entry.label[..entry.label_len as usize]);
    SLOTS[slot].label_len = entry.label_len;
    SLOTS[slot].namespace = entry.namespace;
    for (j, b) in key.iter().take(n).enumerate() {
        core::ptr::write_volatile(&raw mut SLOTS[slot].data[j], *b);
    }
    zeroize(&mut key);
    // In-use last, so a partial fill is never observable.
    SLOTS[slot].flags = FLAG_IN_USE | FLAG_PERSISTED;
    Ok(slot)
}

/// Remove a persisted key: its RAM entry and its durable record. Returns
/// whether there was one, and whether no durable record remains — false when
/// the platform could not remove it, so it would come back.
///
/// # Safety
/// Kernel context, exclusive access to `PERSISTED`.
unsafe fn forget_persisted(namespace: u32, label: &[u8]) -> (bool, bool) {
    let mut found = false;
    let table = &raw mut PERSISTED;
    for e in (*table).iter_mut() {
        if e.live && e.namespace == namespace && e.label_bytes() == label {
            zeroize(&mut e.sealed);
            *e = Persisted::empty();
            found = true;
        }
    }
    let mut name = [0u8; MAX_BLOB_NAME];
    let name_len = blob_name(namespace, label, &mut name);
    let mut blob = [0u8; MAX_HEADER + MAX_SEALED];
    if crate::kernel::sys::hal::seal_blob_read(&name[..name_len], &mut blob).is_some() {
        found = true;
    }
    zeroize(&mut blob);
    let removed = crate::kernel::sys::hal::seal_blob_delete(&name[..name_len]);
    (found, removed)
}

/// Provision `key` as a persisted key of module type `namespace` under
/// `label`, exactly as the vault seals a key it generated, so the module's
/// later `OPEN` by label finds it. For out-of-band provisioning of a secret
/// another party also holds.
///
/// # Safety
/// Kernel context, exclusive access to `PERSISTED`.
pub unsafe fn import_persisted(
    namespace: u32,
    label: &[u8],
    suite: u16,
    usage: u32,
    key: &[u8],
) -> Result<(), i32> {
    if label.is_empty() || label.len() > MAX_LABEL || key.len() != suite_private_len(suite) {
        return Err(EINVAL);
    }
    if usage == 0 || usage & !suite_usage(suite) != 0 || usage & dev_key_vault::usage::PERSIST == 0
    {
        return Err(EINVAL);
    }
    match persist_key(namespace, label, suite, usage, key) {
        Persist::Durable => Ok(()),
        Persist::Unavailable => Err(ENOSYS),
        Persist::Failed => Err(ERROR),
    }
}

/// Largest plaintext [`AEAD_SEAL`] / [`AEAD_OPEN`] handle in one call: a
/// resumption ticket or a checkpoint chunk, never a bulk stream.
const MAX_SEAL_BYTES: usize = 2048;
/// Scratch for seal/open, a static so PIC callers' stacks stay small.
static mut SEAL_SCRATCH: [u8; MAX_SEAL_BYTES] = [0; MAX_SEAL_BYTES];
/// Scratch for the composition record: sized for the largest table this
/// profile admits — one blob and one instance entry per module slot, and
/// one entry per graph edge.
const MAX_ATTEST_RECORD: usize = 4096
    + crate::abi::config::kernel::MAX_MODULES * 40
    + crate::abi::config::kernel::MAX_MODULES * 37
    + crate::kernel::boot::config::MAX_GRAPH_EDGES * 5;
static mut ATTEST_RECORD: [u8; MAX_ATTEST_RECORD] = [0; MAX_ATTEST_RECORD];

#[inline]
pub(crate) fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a live, exclusively-borrowed byte.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
}

/// The tier this vault reports: decided by the sealing key's provenance,
/// and only by a sealing key the platform can actually seal with.
///
/// A device-unique key that no seal uses protects nothing: the platform
/// that reads its OTP key and stubs `seal` holds every key in RAM with
/// nothing bound to the device, and reporting `DEVICE_HW` there would pass
/// every `tier >= DEVICE_HW` refusal on a claim nobody implemented.
fn current_tier() -> u8 {
    if crate::kernel::sys::hal::seal_provenance()
        != crate::kernel::sys::hal::SealProvenance::DeviceUnique
    {
        return dev_key_vault::tier::SOFTWARE;
    }
    let mut probe = [0u8; 1 + 32];
    if crate::kernel::sys::hal::seal(b"fluxor/tier", &[0u8], &mut probe).is_some() {
        dev_key_vault::tier::DEVICE_HW
    } else {
        dev_key_vault::tier::SOFTWARE
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

/// A purpose key: HKDF-SHA256 (RFC 5869), one block —
/// `salt = derive::SALT`, `ikm = master`, `info = label ‖ context`.
pub(crate) fn derive_key(master: &[u8], label: &[u8], context: &[u8], out: &mut [u8; 32]) {
    let mut prk = hmac_sha256(dev_key_vault::derive::SALT, &[master]);
    let okm = hmac_sha256(&prk, &[label, context, &[1u8]]);
    zeroize(&mut prk);
    out.copy_from_slice(&okm);
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

/// A fresh P-256 private scalar in `[1, n-1]`, or `None` when entropy
/// fails.
pub(crate) fn random_p256_scalar() -> Option<[u8; 32]> {
    let mut k = [0u8; 32];
    // SAFETY: `generate_into` touches no shared state for P-256.
    if unsafe { generate_into(dev_key_vault::suite::P256, &mut k) } {
        Some(k)
    } else {
        zeroize(&mut k);
        None
    }
}

/// First free slot, after reaping the keys of modules that are gone.
///
/// # Safety
/// Kernel context, exclusive access to `SLOTS`.
unsafe fn alloc_slot() -> Option<usize> {
    reap_orphans();
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
        // An HMAC key: 32 bytes of shared secret, no public half.
        dev_key_vault::suite::HMAC_SHA256 => 32,
        // A derivation master: 32 bytes, no public half.
        dev_key_vault::suite::KDF_KEY => 32,
        // AES-256-GCM, only where the block cipher is constant-time: a
        // table-driven AES leaks its key through the data cache, and a
        // storage key is used for years.
        dev_key_vault::suite::AEAD_AES256_GCM
            if crate::kernel::security::crypto::aes_gcm::AES_IS_CONSTANT_TIME =>
        {
            32
        }
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
        // The PKCS#1 RSAPrivateKey DER with CRT fields, at its ceiling for
        // the width: the actual encoding is a few bytes shorter or longer
        // by the sizes of its INTEGERs, and STORE admits any up to this.
        #[cfg(feature = "rsa-vault")]
        dev_key_vault::suite::RSA_2048 => 1216,
        #[cfg(feature = "rsa-vault")]
        dev_key_vault::suite::RSA_3072 => 1792,
        #[cfg(feature = "rsa-vault")]
        dev_key_vault::suite::RSA_4096 => 2368,
        _ => 0,
    }
}

/// Public-key length for a suite, or 0. For RSA this is the RSAPublicKey
/// DER at its longest for the width; `PUBLIC` reports the exact length.
const fn suite_public_len(suite: u16) -> usize {
    match suite {
        dev_key_vault::suite::P256 => 65,
        dev_key_vault::suite::ED25519 => 32,
        dev_key_vault::suite::RSA_2048 => 270,
        dev_key_vault::suite::RSA_3072 => 398,
        dev_key_vault::suite::RSA_4096 => 526,
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
        // The RFC 2104 tag.
        dev_key_vault::suite::HMAC_SHA256 => 32,
        // The modulus width.
        dev_key_vault::suite::RSA_2048 => 256,
        dev_key_vault::suite::RSA_3072 => 384,
        dev_key_vault::suite::RSA_4096 => 512,
        _ => match ml_dsa_set_for(suite) {
            Some(set) => set.params().sig_len,
            None => 0,
        },
    }
}

/// What this backend permits for a suite it supports.
const fn suite_usage(suite: u16) -> u32 {
    match suite {
        // Signing and publishing the public half. Not PERSIST or WRAP: the
        // sealed-blob store is sized for a 64-byte key, and an RSA key is
        // minted and imported by an operator's tooling each boot.
        dev_key_vault::suite::RSA_2048
        | dev_key_vault::suite::RSA_3072
        | dev_key_vault::suite::RSA_4096 => {
            dev_key_vault::usage::SIGN | dev_key_vault::usage::EXPORT_PUBLIC
        }
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
        dev_key_vault::suite::AEAD_KEY | dev_key_vault::suite::AEAD_AES256_GCM => {
            dev_key_vault::usage::SEAL
                | dev_key_vault::usage::OPEN
                | dev_key_vault::usage::PERSIST
                | dev_key_vault::usage::WRAP
        }
        // A master derives, and is kept and moved; it seals nothing itself.
        dev_key_vault::suite::KDF_KEY => {
            dev_key_vault::usage::DERIVE
                | dev_key_vault::usage::PERSIST
                | dev_key_vault::usage::WRAP
        }
        // A MAC key tags and checks tags. No `EXPORT_PUBLIC`: there is no
        // public half, and the mask is what keeps `PUBLIC` from ever
        // answering with the secret.
        dev_key_vault::suite::HMAC_SHA256 => {
            dev_key_vault::usage::SIGN
                | dev_key_vault::usage::VERIFY
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
        // A sealing, MAC or derivation key is any 32 random bytes.
        dev_key_vault::suite::AEAD_KEY
        | dev_key_vault::suite::AEAD_AES256_GCM
        | dev_key_vault::suite::HMAC_SHA256
        | dev_key_vault::suite::KDF_KEY => {
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
    // A sealing, MAC or derivation key has no public half: nothing to write
    // is success.
    if suite_public_len(slot.suite) == 0 {
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

/// Zeroise every slot, whoever owns it. The persisted table is untouched: a
/// labelled key comes back from it on the next `OPEN`.
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
/// `reset_all` models a graph rebuild, where `PERSISTED` deliberately
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
/// One vault's in-RAM state — the open slots and the sealed-at-rest
/// table — as a value.
///
/// Test-only, like [`forget_persisted_for_test`]. The tables are process
/// statics, so a harness that needs two independent vaults — one per host
/// of a continuity pair — holds one image per host and swaps it in around
/// each call. Opaque on purpose: a test moves a key between images by
/// label and never handles the bytes.
///
/// This covers only what this file owns. A labelled key the RAM tables lack
/// is rehydrated from the platform's durable store, so a harness modelling
/// a second host must isolate that store as well, or the second host reads
/// what the first wrote and the two are one vault after all.
pub struct VaultImage {
    slots: [Slot; MAX_SLOTS],
    persisted: [Persisted; MAX_PERSISTED],
}

impl VaultImage {
    /// A vault that has never held a key.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            slots: [Slot::empty(); MAX_SLOTS],
            persisted: [Persisted::empty(); MAX_PERSISTED],
        }
    }

    /// Copy the key filed under `label` — its open slot and its sealed
    /// entry, whichever `other` holds — into this image, replacing any entry
    /// already filed under that label. Answers whether `other` held one.
    ///
    /// This is out-of-band provisioning: the only way a key reaches a host
    /// that did not generate it.
    pub fn copy_labelled_from(&mut self, other: &VaultImage, label: &[u8]) -> bool {
        let mut found = false;
        if let Some(src) = other
            .slots
            .iter()
            .find(|s| (s.flags & FLAG_IN_USE) != 0 && s.label_bytes() == label)
        {
            let dst = self
                .slots
                .iter()
                .position(|s| (s.flags & FLAG_IN_USE) != 0 && s.label_bytes() == label)
                .or_else(|| self.slots.iter().position(|s| (s.flags & FLAG_IN_USE) == 0));
            if let Some(i) = dst {
                self.slots[i] = *src;
                found = true;
            }
        }
        if let Some(src) = other
            .persisted
            .iter()
            .find(|e| e.live && e.label[..e.label_len as usize] == *label)
        {
            let dst = self
                .persisted
                .iter()
                .position(|e| e.live && e.label[..e.label_len as usize] == *label)
                .or_else(|| self.persisted.iter().position(|e| !e.live));
            if let Some(i) = dst {
                self.persisted[i] = *src;
                found = true;
            }
        }
        found
    }
}

/// Snapshot the live tables into an image.
///
/// # Safety
/// Kernel context, exclusive access to `SLOTS` and `PERSISTED`.
pub unsafe fn capture_for_test() -> VaultImage {
    VaultImage {
        slots: core::ptr::read(&raw const SLOTS),
        persisted: core::ptr::read(&raw const PERSISTED),
    }
}

/// Make `image` the live tables, replacing whatever they held.
///
/// # Safety
/// Kernel context, exclusive access to `SLOTS` and `PERSISTED`; no module
/// mid-`provider_dispatch`.
pub unsafe fn restore_for_test(image: &VaultImage) {
    core::ptr::write(&raw mut SLOTS, image.slots);
    core::ptr::write(&raw mut PERSISTED, image.persisted);
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
    #[cfg(feature = "rsa-vault")]
    if is_rsa_suite(SLOTS[i].suite) && SLOTS[i].key_len == 1 {
        let entry = SLOTS[i].data[0] as usize;
        if entry < RSA_ENTRIES {
            let keys = &raw mut RSA_KEYS;
            (*keys)[entry].zeroize();
        }
        if RSA_JOB_SLOT == i as i32 {
            let job = &raw mut RSA_SIGN;
            (*job).zeroize();
            RSA_JOB_SLOT = -1;
        }
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
    SLOTS[i].owner = KERNEL_OWNER;
    SLOTS[i].owner_generation = 0;
    SLOTS[i].namespace = 0;
    // Every handle to the key just destroyed stops resolving.
    SLOTS[i].generation = SLOTS[i].generation.wrapping_add(1) & GENERATION_MASK;
}
/// Provider dispatch function registered against dev_class::KEY_VAULT.
/// Signature matches the `provider_dispatch` contract.
///
/// Slot-bound ops (DESTROY, SIGN, ECDH, PUBLIC, DERIVE, AEAD and share
/// operations, ...) take a `FD_TAG_KEY_VAULT`-tagged handle; the global ops
/// listed in the match below (PROBE, STORE, GENERATE, OPEN, ...) take
/// `handle=-1`. Tagging keeps KV handles distinct from other drivers'
/// untagged integer handles in the kernel's global handle-tracking table.
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
        _ => match resolve(handle) {
            Ok(i) => i as i32,
            Err(e) => return e,
        },
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
            // An RSA DER is variable-length up to its ceiling; every other
            // suite's key is exactly the reported length.
            let fits = if is_rsa_suite(suite) {
                key_len > 0 && key_len <= want
            } else {
                key_len == want
            };
            if want == 0 || !fits || 10 + key_len > arg_len {
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
            #[cfg(feature = "rsa-vault")]
            if is_rsa_suite(suite) {
                // The DER goes into an RSA entry, checked and prepared
                // there; the slot names the entry. A key whose width is not
                // the suite's is refused: the suite is what every later
                // length is derived from.
                let keys = &raw mut RSA_KEYS;
                let Some(entry) = (*keys).iter().position(|k| !k.is_loaded()) else {
                    return ENOMEM;
                };
                let der = core::slice::from_raw_parts(arg.add(10), key_len);
                let key = &mut (*keys)[entry];
                if !key.load_pkcs1_der(der) || rsa_suite_for_bits(key.n.bits()) != suite {
                    key.zeroize();
                    return EINVAL;
                }
                SLOTS[idx].key_len = 1;
                core::ptr::write_volatile(&raw mut SLOTS[idx].data[0], entry as u8);
                SLOTS[idx].flags = FLAG_IN_USE;
                return mint(idx);
            }
            SLOTS[idx].key_len = key_len as u8;
            let src = arg.add(10);
            for j in 0..key_len {
                core::ptr::write_volatile(&raw mut SLOTS[idx].data[j], *src.add(j));
            }
            // Mark in-use last so partial fills can't be observed.
            SLOTS[idx].flags = FLAG_IN_USE;
            mint(idx)
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
            if input_len == 0 || input_len > arg_len.saturating_sub(6 + 12) {
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
            // exactly the trap an inferred convention sets.
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
            // RSA: a resumable RSASSA-PSS-SHA256 over a 32-byte digest. The
            // first call starts the job; each answers EAGAIN until the
            // signature is complete, and a call for another slot or digest
            // while one is in progress is EBUSY.
            #[cfg(feature = "rsa-vault")]
            if is_rsa_suite(slot.suite) {
                if mode != dev_key_vault::sign_mode::DIGEST || input_len != 32 {
                    return EINVAL;
                }
                let entry = slot.data[0] as usize;
                if slot.key_len != 1 || entry >= RSA_ENTRIES {
                    return EINVAL;
                }
                let keys = &raw const RSA_KEYS;
                let key = &(*keys)[entry];
                let job_ptr = &raw mut RSA_SIGN;
                let job = &mut *job_ptr;
                let digest = core::slice::from_raw_parts(arg.add(6), 32);
                let held_ptr = &raw const RSA_JOB_DIGEST;
                let held = &*held_ptr;
                let mut same_digest = true;
                for (k, byte) in digest.iter().enumerate() {
                    same_digest &= held[k] == *byte;
                }
                if RSA_JOB_SLOT >= 0 && (RSA_JOB_SLOT != slot_handle || !same_digest) {
                    return EBUSY;
                }
                if RSA_JOB_SLOT < 0 {
                    let mut salt = [0u8; 32];
                    if crate::kernel::sys::hal::csprng_fill(salt.as_mut_ptr(), 32) != 0 {
                        return ERROR;
                    }
                    let k = key.n.byte_len();
                    let mut em = [0u8; rsa::RSA_BYTES_MAX];
                    if !rsa::rsa_pss_encode(
                        rsa::RsaHash::Sha256,
                        digest,
                        &salt,
                        &mut em[..k],
                        key.n.bits(),
                    ) || !job.start(key, &em[..k])
                    {
                        return ERROR;
                    }
                    core::ptr::copy_nonoverlapping(
                        digest.as_ptr(),
                        (&raw mut RSA_JOB_DIGEST) as *mut u8,
                        32,
                    );
                    RSA_JOB_SLOT = slot_handle;
                }
                if job.step(key, rsa_sign_rows_per_call(key)) == rsa::RsaStep::Pending {
                    return EAGAIN;
                }
                let signature = job.signature();
                if !sig_ptr.is_null() {
                    core::ptr::copy_nonoverlapping(signature.as_ptr(), sig_ptr, signature.len());
                }
                let wrote = (signature.len() as u16).to_le_bytes();
                core::ptr::copy_nonoverlapping(wrote.as_ptr(), tail.add(10), 2);
                job.zeroize();
                RSA_JOB_SLOT = -1;
                return 0;
            }
            let want_mode = match slot.suite {
                dev_key_vault::suite::P256 => dev_key_vault::sign_mode::DIGEST,
                dev_key_vault::suite::ED25519 => dev_key_vault::sign_mode::RAW,
                dev_key_vault::suite::HMAC_SHA256 => dev_key_vault::sign_mode::RAW,
                _ if ml_dsa_set_for(slot.suite).is_some() => dev_key_vault::sign_mode::RAW,
                _ => return ENOSYS,
            };
            if mode != want_mode {
                return EINVAL;
            }

            // An HMAC tag is 32 bytes and takes the whole message; it
            // answers here so the 64-byte signature path below stays the
            // asymmetric one.
            if slot.suite == dev_key_vault::suite::HMAC_SHA256 {
                let msg = core::slice::from_raw_parts(arg.add(6), input_len);
                let mut tag = hmac_sha256(&slot.data[..32], &[msg]);
                if !sig_ptr.is_null() {
                    core::ptr::copy_nonoverlapping(tag.as_ptr(), sig_ptr, 32);
                }
                zeroize(&mut tag);
                let wrote = 32u16.to_le_bytes();
                core::ptr::copy_nonoverlapping(wrote.as_ptr(), tail.add(10), 2);
                return 0;
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
            if peer_len == 0 || peer_len > arg_len.saturating_sub(4 + 12) {
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
            // With handle=-1, VERIFY is independent of the stored keys — it
            // takes a caller-supplied public key in the peer field of the
            // argument. Layout: `[hash_len:u16][sig_len:u16][pub_len:u16]
            // [pad:u16][hash][sig][pub]`; shorter payloads are rejected as
            // EINVAL. With a slot handle the slot must hold an HMAC key,
            // the hash field is the message, the sig field the tag, and
            // the comparison happens here in constant time.
            if arg.is_null() || arg_len < 8 {
                return EINVAL;
            }
            let hash_len = u16::from_le_bytes([*arg, *arg.add(1)]) as usize;
            let sig_len = u16::from_le_bytes([*arg.add(2), *arg.add(3)]) as usize;
            let pub_len = u16::from_le_bytes([*arg.add(4), *arg.add(5)]) as usize;
            if handle >= 0 {
                let slot_idx = match resolve(handle) {
                    Ok(i) => i,
                    Err(e) => return e,
                };
                let slot = &SLOTS[slot_idx];
                if (slot.flags & FLAG_IN_USE) == 0
                    || slot.suite != dev_key_vault::suite::HMAC_SHA256
                {
                    return EINVAL;
                }
                if !slot.permits(dev_key_vault::usage::VERIFY) {
                    return EACCES;
                }
                if hash_len == 0 || sig_len != 32 || pub_len != 0 || 8 + hash_len + 32 > arg_len {
                    return EINVAL;
                }
                let msg = core::slice::from_raw_parts(arg.add(8), hash_len);
                let presented = core::slice::from_raw_parts(arg.add(8 + hash_len), 32);
                let mut expect = hmac_sha256(&slot.data[..32], &[msg]);
                // Every byte is visited whatever the first mismatch, so the
                // time taken says nothing about where the tag went wrong.
                let mut diff: u8 = 0;
                for (a, b) in expect.iter().zip(presented) {
                    diff |= a ^ b;
                }
                zeroize(&mut expect);
                return i32::from(diff == 0);
            }
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
            // RSA keys are imported, never minted here: prime generation is
            // seconds of work no target's step can host, and an operator's
            // tooling mints them anyway. The contract says so per suite.
            if priv_len == 0 || is_rsa_suite(suite) {
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
                zeroize(&mut key);
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
            // A symmetric key has no public half to write.
            if pub_len != 0 && !pub_ptr.is_null() && !write_public(idx, pub_ptr, pub_len) {
                zeroise_slot(idx);
                return ERROR;
            }
            let wrote = (pub_len as u16).to_le_bytes();
            core::ptr::copy_nonoverlapping(wrote.as_ptr(), tail.add(10), 2);
            mint(idx)
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
            #[cfg(feature = "rsa-vault")]
            if is_rsa_suite(slot.suite) {
                // The RSAPublicKey DER, at its exact length.
                let entry = slot.data[0] as usize;
                if slot.key_len != 1 || entry >= RSA_ENTRIES {
                    return EINVAL;
                }
                let keys = &raw const RSA_KEYS;
                let key = &(*keys)[entry];
                let mut der = [0u8; 526];
                let Some(n) = key.public_key_der(&mut der) else {
                    return ERROR;
                };
                if out_cap < n {
                    let need = (n as u16).to_le_bytes();
                    core::ptr::copy_nonoverlapping(need.as_ptr(), arg.add(10), 2);
                    return ERANGE;
                }
                if !out_ptr.is_null() {
                    core::ptr::copy_nonoverlapping(der.as_ptr(), out_ptr, n);
                }
                let wrote = (n as u16).to_le_bytes();
                core::ptr::copy_nonoverlapping(wrote.as_ptr(), arg.add(10), 2);
                return 0;
            }
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
            let sig_out = if out_ptr.is_null() {
                out_ptr
            } else {
                out_ptr.add(rec_len)
            };
            let Some(sig_written) =
                sign_bytes(slot_handle as usize, &rec[..rec_len], sig_out, sig_len)
            else {
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
            // The generation is what keeps handles to the slot's earlier keys
            // stale, so it survives the reset of everything else.
            let dst = &mut SLOTS[new_slot];
            let generation = dst.generation;
            *dst = Slot::empty();
            dst.generation = generation;
            dst.suite = suite;
            dst.usage = usage;
            dst.key_len = key_len as u8;
            dst.data[..key_len].copy_from_slice(&sealed[7..7 + key_len]);
            dst.flags = FLAG_IN_USE;
            zeroize(&mut sealed);
            mint(new_slot)
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
            // This backend seals keys so they survive a restart — see
            // `persist_key`. That is durability, and durability is not
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
            *arg = current_tier();
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
            *arg.add(6) = current_tier();
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
            // Sized before anything is opened or made: a refusal after a
            // key was minted would leave a slot nobody holds a handle to,
            // and the retry the caller makes with a larger buffer would
            // mint another.
            if pub_cap < pub_len {
                let need = (pub_len as u16).to_le_bytes();
                core::ptr::copy_nonoverlapping(need.as_ptr(), tail.add(10), 2);
                return ERANGE;
            }

            reap_orphans();
            // Labels live in the caller's namespace: its module type. An
            // already-open slot under this label is returned to its owner
            // as-is — two handles onto one key would each be destroyable
            // independently, and the second destroy would find a slot the
            // first had freed. Another instance of the same module type is
            // refused: the key is in use, and it is not that instance's.
            let who = caller();
            let slots = &raw const SLOTS;
            let existing = (*slots).iter().position(|s| {
                (s.flags & FLAG_IN_USE) != 0
                    && s.namespace == who.namespace
                    && s.label_bytes() == label
            });
            if let Some(i) = existing {
                if !owned_by(i, who) {
                    return EBUSY;
                }
                if SLOTS[i].suite != suite || usage & !SLOTS[i].usage != 0 {
                    return EACCES;
                }
            }

            let idx = match existing {
                Some(i) => i,
                None => match find_persisted(who.namespace, label) {
                    // A key exists that this table has no room to hold:
                    // never answered by generating another over it.
                    Err(e) => return e,
                    Ok(Some(pi)) => {
                        // The suite must be the one the key was born with,
                        // and the mask is CHECKED against its uses, never
                        // applied. A reopen asking for another suite or for
                        // more than the key has is refused: permitted uses
                        // must not be something a later caller widens by
                        // asking.
                        if PERSISTED[pi].suite != suite || usage & !PERSISTED[pi].usage != 0 {
                            return EACCES;
                        }
                        match open_persisted(pi) {
                            Ok(i) => i,
                            Err(e) => {
                                log::warn!(
                                    "[vault] open refused: persisted entry would not reopen (suite={suite})"
                                );
                                return e;
                            }
                        }
                    }
                    Ok(None) => {
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
                            zeroize(&mut key);
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
                        let persisted = if usage & dev_key_vault::usage::PERSIST != 0 {
                            persist_key(who.namespace, label, suite, usage, &key[..priv_len])
                        } else {
                            Persist::Unavailable
                        };
                        zeroize(&mut key);
                        if persisted == Persist::Failed {
                            // A key asked to persist that could not be stored is
                            // not handed out: its owner would build on a key
                            // that does not come back.
                            zeroise_slot(i);
                            return ERROR;
                        }
                        SLOTS[i].flags = FLAG_IN_USE
                            | if persisted == Persist::Durable {
                                FLAG_PERSISTED
                            } else {
                                0
                            };
                        i
                    }
                },
            };

            // Public half back to the caller.
            if !pub_ptr.is_null() && !write_public(idx, pub_ptr, pub_len) {
                log::warn!("[vault] open refused: public-key derivation failed (suite={suite})");
                if existing.is_none() {
                    // Opened or made by this call and handed to no one.
                    zeroise_slot(idx);
                }
                return ERROR;
            }
            let wrote = (pub_len as u16).to_le_bytes();
            core::ptr::copy_nonoverlapping(wrote.as_ptr(), tail.add(10), 2);
            if existing.is_some() {
                handle_of(idx)
            } else {
                mint(idx)
            }
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
            let who = caller();
            let slots = &raw const SLOTS;
            let mut victims = [usize::MAX; MAX_SLOTS];
            let mut n = 0usize;
            for (i, sl) in (*slots).iter().enumerate() {
                if (sl.flags & FLAG_IN_USE) != 0
                    && sl.namespace == who.namespace
                    && sl.label_bytes() == label
                {
                    victims[n] = i;
                    n += 1;
                }
            }
            for &i in victims.iter().take(n) {
                zeroise_slot(i);
                found = true;
            }
            let (had, removed) = forget_persisted(who.namespace, label);
            if !removed {
                log::warn!("[vault] destroy: sealed record could not be removed");
                return ERROR;
            }
            if found || had {
                0
            } else {
                ENOENT
            }
        }
        dev_key_vault::DERIVE => {
            use dev_key_vault::derive as d;
            if arg.is_null() || arg_len < d::LABEL {
                return EINVAL;
            }
            let master = &SLOTS[slot_handle as usize];
            if master.suite != dev_key_vault::suite::KDF_KEY {
                return EINVAL;
            }
            if !master.permits(dev_key_vault::usage::DERIVE) {
                return EACCES;
            }
            let suite =
                u16::from_le_bytes([*arg.add(d::TARGET_SUITE), *arg.add(d::TARGET_SUITE + 1)]);
            let usage = u32::from_le_bytes([
                *arg.add(d::TARGET_USAGE),
                *arg.add(d::TARGET_USAGE + 1),
                *arg.add(d::TARGET_USAGE + 2),
                *arg.add(d::TARGET_USAGE + 3),
            ]);
            let label_len = *arg.add(d::LABEL_LEN) as usize;
            let context_len =
                u16::from_le_bytes([*arg.add(d::CONTEXT_LEN), *arg.add(d::CONTEXT_LEN + 1)])
                    as usize;
            if label_len == 0
                || label_len > d::MAX_LABEL
                || context_len > d::MAX_CONTEXT
                || d::LABEL + label_len + context_len > arg_len
            {
                return EINVAL;
            }
            // A derived key is the same 32 bytes whenever it is derived, so it
            // is never persisted: persisting it would be a second copy of the
            // master's secret with its own lifetime.
            let derivable = matches!(
                suite,
                dev_key_vault::suite::AEAD_KEY
                    | dev_key_vault::suite::AEAD_AES256_GCM
                    | dev_key_vault::suite::HMAC_SHA256
                    | dev_key_vault::suite::KDF_KEY
            );
            if !derivable || suite_private_len(suite) != 32 {
                return if derivable { ENOSYS } else { EINVAL };
            }
            if usage == 0
                || usage & !suite_usage(suite) != 0
                || usage & dev_key_vault::usage::PERSIST != 0
            {
                return EINVAL;
            }
            let label = core::slice::from_raw_parts(arg.add(d::LABEL), label_len);
            let context = core::slice::from_raw_parts(arg.add(d::LABEL + label_len), context_len);
            let mut key = [0u8; 32];
            derive_key(
                &master.data[..master.key_len as usize],
                label,
                context,
                &mut key,
            );
            let Some(idx) = alloc_slot() else {
                zeroize(&mut key);
                return ENOMEM;
            };
            SLOTS[idx].suite = suite;
            SLOTS[idx].usage = usage;
            SLOTS[idx].key_len = 32;
            for (j, b) in key.iter().enumerate() {
                core::ptr::write_volatile(&raw mut SLOTS[idx].data[j], *b);
            }
            zeroize(&mut key);
            SLOTS[idx].flags = FLAG_IN_USE;
            mint(idx)
        }
        dev_key_vault::AEAD_SEAL_UNITS | dev_key_vault::AEAD_OPEN_UNITS => {
            use dev_key_vault::units as u;
            let seal = opcode == dev_key_vault::AEAD_SEAL_UNITS;
            if arg.is_null() || arg_len < u::HEADER_LEN {
                return EINVAL;
            }
            let slot = &SLOTS[slot_handle as usize];
            let aes = match slot.suite {
                dev_key_vault::suite::AEAD_KEY => false,
                dev_key_vault::suite::AEAD_AES256_GCM => true,
                _ => return EINVAL,
            };
            let want = if seal {
                dev_key_vault::usage::SEAL
            } else {
                dev_key_vault::usage::OPEN
            };
            if !slot.permits(want) {
                return EACCES;
            }
            let count = u16::from_le_bytes([*arg.add(u::COUNT), *arg.add(u::COUNT + 1)]) as usize;
            if count == 0
                || count > u::MAX_ENTRIES
                || u::HEADER_LEN + count * u::ENTRY_LEN > arg_len
            {
                return EINVAL;
            }
            let entry = |i: usize| arg.add(u::HEADER_LEN + i * u::ENTRY_LEN);
            // Every entry is checked before any is touched: a batch refused
            // halfway would leave some buffers sealed and some not.
            let mut total = 0usize;
            for i in 0..count {
                let e = entry(i);
                let aad_len =
                    u16::from_le_bytes([*e.add(u::AAD_LEN), *e.add(u::AAD_LEN + 1)]) as usize;
                let aad_ptr = read_u64(e.add(u::AAD_PTR));
                let data_ptr = read_u64(e.add(u::DATA_PTR));
                let data_len = u32::from_le_bytes([
                    *e.add(u::DATA_LEN),
                    *e.add(u::DATA_LEN + 1),
                    *e.add(u::DATA_LEN + 2),
                    *e.add(u::DATA_LEN + 3),
                ]) as usize;
                let tag_ptr = read_u64(e.add(u::TAG_PTR));
                if aad_len > u::MAX_AAD
                    || (aad_len > 0 && aad_ptr == 0)
                    || (data_len > 0 && data_ptr == 0)
                    || tag_ptr == 0
                {
                    return EINVAL;
                }
                // Checked against the bound before it is added: a 32-bit
                // `usize` would wrap a hostile length past it.
                if data_len > u::MAX_BYTES - total {
                    return EINVAL;
                }
                total += data_len;
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&slot.data[..32]);
            let cipher = if aes {
                Some(crate::kernel::security::crypto::aes_gcm::AesGcm::new_256(
                    &key,
                ))
            } else {
                None
            };
            let mut failed = 0i32;
            for i in 0..count {
                let e = entry(i);
                let mut nonce = [0u8; 12];
                core::ptr::copy_nonoverlapping(e.add(u::NONCE), nonce.as_mut_ptr(), 12);
                let aad_len =
                    u16::from_le_bytes([*e.add(u::AAD_LEN), *e.add(u::AAD_LEN + 1)]) as usize;
                let aad: &[u8] = if aad_len == 0 {
                    &[]
                } else {
                    core::slice::from_raw_parts(read_u64(e.add(u::AAD_PTR)) as *const u8, aad_len)
                };
                let data_len = u32::from_le_bytes([
                    *e.add(u::DATA_LEN),
                    *e.add(u::DATA_LEN + 1),
                    *e.add(u::DATA_LEN + 2),
                    *e.add(u::DATA_LEN + 3),
                ]) as usize;
                let data: &mut [u8] = if data_len == 0 {
                    &mut []
                } else {
                    core::slice::from_raw_parts_mut(
                        read_u64(e.add(u::DATA_PTR)) as *mut u8,
                        data_len,
                    )
                };
                let tag_ptr = read_u64(e.add(u::TAG_PTR)) as *mut u8;
                if seal {
                    let tag = match &cipher {
                        Some(c) => c.encrypt(&nonce, aad, data),
                        None => {
                            crate::kernel::security::crypto::chacha20::chacha20_poly1305_encrypt(
                                &key, &nonce, aad, data,
                            )
                        }
                    };
                    core::ptr::copy_nonoverlapping(tag.as_ptr(), tag_ptr, 16);
                    *e.add(u::STATUS) = 0;
                } else {
                    let mut tag = [0u8; 16];
                    core::ptr::copy_nonoverlapping(tag_ptr, tag.as_mut_ptr(), 16);
                    let ok = match &cipher {
                        Some(c) => c.decrypt(&nonce, aad, data, &tag),
                        None => {
                            crate::kernel::security::crypto::chacha20::chacha20_poly1305_decrypt(
                                &key, &nonce, aad, data, &tag,
                            )
                        }
                    };
                    if ok {
                        *e.add(u::STATUS) = 0;
                    } else {
                        // Never leave unauthenticated plaintext behind.
                        zeroize(data);
                        *e.add(u::STATUS) = u::STATUS_AUTH_FAILED;
                        failed += 1;
                    }
                }
            }
            drop(cipher);
            zeroize(&mut key);
            failed
        }
        dev_key_vault::SHARE_SPLIT => share_split(slot_handle as usize, arg, arg_len),
        _ => ENOSYS,
    }
}

// ── Recovery shares and key attestation ─────────────────────────────────
//
// A 32-byte key leaves this vault only as 2-of-3 shares sealed to their
// recipients (`key_share`), and comes back only into a handle. Neither a
// share nor the key is ever written to a caller.

/// Suites a share split may carry, and a reconstruction may yield: the
/// 32-byte symmetric keys.
const fn splittable(suite: u16) -> bool {
    matches!(
        suite,
        dev_key_vault::suite::KDF_KEY
            | dev_key_vault::suite::AEAD_KEY
            | dev_key_vault::suite::AEAD_AES256_GCM
    )
}

/// Write an output length into a `u32` `out_len_out` field.
///
/// # Safety
/// `at` writable for 4 bytes.
unsafe fn write_out_len(at: *mut u8, n: usize) {
    let b = (n as u32).to_le_bytes();
    core::ptr::copy_nonoverlapping(b.as_ptr(), at, 4);
}

/// A fresh anti-replay id.
fn anti_replay_id() -> Option<[u8; 16]> {
    let mut id = [0u8; 16];
    (crate::kernel::sys::hal::csprng_fill(id.as_mut_ptr(), 16) == 0).then_some(id)
}

/// # Safety
/// Kernel context, exclusive access to `SLOTS`; `i` resolved; `arg` valid
/// for `arg_len` bytes.
unsafe fn share_split(i: usize, arg: *mut u8, arg_len: usize) -> i32 {
    use dev_key_vault::share::{self as sh, split as a};
    if arg.is_null() || arg_len < a::LEN {
        return EINVAL;
    }
    let slot = &SLOTS[i];
    if !splittable(slot.suite) || slot.key_len != 32 {
        return EINVAL;
    }
    if !slot.permits(dev_key_vault::usage::WRAP) {
        return EACCES;
    }
    let grant = key_share::Grant::read(core::slice::from_raw_parts(
        arg,
        dev_key_vault::share::grant::LEN,
    ));
    if !grant.valid() {
        return EINVAL;
    }
    let out_ptr = read_u64(arg.add(a::OUT_PTR)) as *mut u8;
    let out_cap = u32::from_le_bytes([
        *arg.add(a::OUT_CAP),
        *arg.add(a::OUT_CAP + 1),
        *arg.add(a::OUT_CAP + 2),
        *arg.add(a::OUT_CAP + 3),
    ]) as usize;
    let need = 3 * sh::P256_LEN;
    if out_cap < need || out_ptr.is_null() {
        write_out_len(arg.add(a::OUT_LEN), need);
        return ERANGE;
    }
    let recipients = core::slice::from_raw_parts(arg.add(a::RECIPIENTS), 3 * sh::P256_PUB_LEN);
    let mut coeff = [0u8; 32];
    if crate::kernel::sys::hal::csprng_fill(coeff.as_mut_ptr(), 32) != 0 {
        return ERROR;
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&slot.data[..32]);
    let mut shares = [[0u8; 32]; 3];
    key_share::split(&secret, &coeff, &mut shares);
    zeroize(&mut secret);
    zeroize(&mut coeff);
    let mut envelope = [0u8; sh::P256_LEN];
    let binding = grant.binding();
    let mut rc = 0;
    for (s, share) in shares.iter().enumerate() {
        let recipient = &recipients[s * sh::P256_PUB_LEN..(s + 1) * sh::P256_PUB_LEN];
        let sealed = match anti_replay_id() {
            Some(id) => {
                key_share::seal(&mut envelope, &binding, s as u8 + 1, share, recipient, &id)
            }
            None => false,
        };
        if !sealed {
            rc = EINVAL;
            break;
        }
        core::ptr::copy_nonoverlapping(
            envelope.as_ptr(),
            out_ptr.add(s * sh::P256_LEN),
            sh::P256_LEN,
        );
    }
    for share in shares.iter_mut() {
        zeroize(share);
    }
    if rc != 0 {
        // No partial set: a caller must not hold two envelopes of a split
        // it was told failed.
        core::ptr::write_bytes(out_ptr, 0, need);
        return rc;
    }
    write_out_len(arg.add(a::OUT_LEN), need);
    0
}

// ── What the router asks of this backend ────────────────────────────────

/// Whether a reconstructed key of `suite` with `usage` may be made: a
/// 32-byte symmetric suite, uses it has, never persisted.
pub(crate) const fn session_key_admissible(suite: u16, usage: u32) -> bool {
    splittable(suite)
        && suite_private_len(suite) == 32
        && usage != 0
        && usage & !suite_usage(suite) == 0
        && usage & dev_key_vault::usage::PERSIST == 0
}

/// Import `key` as a never-persisted key of the caller's: a session key
/// the router reconstructed. Returns its handle, or `ENOMEM`.
///
/// # Safety
/// Kernel context, exclusive access to `SLOTS`.
pub(crate) unsafe fn import_session_key(suite: u16, usage: u32, key: &[u8; 32]) -> i32 {
    if !session_key_admissible(suite, usage) {
        return EINVAL;
    }
    let Some(idx) = alloc_slot() else {
        return ENOMEM;
    };
    SLOTS[idx].suite = suite;
    SLOTS[idx].usage = usage;
    SLOTS[idx].key_len = 32;
    for (j, b) in key.iter().enumerate() {
        core::ptr::write_volatile(&raw mut SLOTS[idx].data[j], *b);
    }
    SLOTS[idx].flags = FLAG_IN_USE;
    mint(idx)
}

/// The calling module's label namespace.
pub(crate) fn caller_namespace() -> u32 {
    caller().namespace
}

/// A suite's signature length, or 0.
pub(crate) const fn signature_len(suite: u16) -> usize {
    suite_signature_len(suite)
}

/// What an attestation says of a key this backend holds, beyond
/// `DESCRIBE`.
pub(crate) struct Attestable {
    pub namespace: u32,
    /// `HMAC-SHA256(key, attest_key::COMMITMENT_LABEL)`.
    pub commitment: [u8; 32],
    /// SHA-256 of the public half, zero without one (or without
    /// `EXPORT_PUBLIC`).
    pub public_thumbprint: [u8; 32],
}

/// The attestable facts of `handle`, the caller's; `None` for a key this
/// backend cannot attest (RSA) or a handle that does not resolve.
///
/// # Safety
/// Kernel context, exclusive access to `SLOTS`.
pub(crate) unsafe fn attestable(handle: i32) -> Option<Attestable> {
    use crate::kernel::security::crypto::sha256::Sha256;
    let i = resolve(handle).ok()?;
    let slot = &SLOTS[i];
    if is_rsa_suite(slot.suite) || slot.key_len == 0 {
        return None;
    }
    let mut public_thumbprint = [0u8; 32];
    let pub_len = suite_public_len(slot.suite);
    if pub_len != 0 && slot.permits(dev_key_vault::usage::EXPORT_PUBLIC) {
        let rec_ptr = &raw mut ATTEST_RECORD;
        let scratch = &mut *rec_ptr;
        if pub_len > scratch.len() || !write_public(i, scratch.as_mut_ptr(), pub_len) {
            return None;
        }
        let mut h = Sha256::new();
        h.update(&scratch[..pub_len]);
        public_thumbprint = h.finalize();
    }
    Some(Attestable {
        namespace: slot.namespace,
        commitment: hmac_sha256(
            &slot.data[..slot.key_len as usize],
            &[dev_key_vault::attest_key::COMMITMENT_LABEL],
        ),
        public_thumbprint,
    })
}

/// The composition digest `KEY_WRAP` binds to, under `tier`.
///
/// # Safety
/// Kernel context, exclusive access to the attestation scratch.
pub(crate) unsafe fn composition_digest(tier: u8) -> Option<[u8; 32]> {
    let rec_ptr = &raw mut ATTEST_RECORD;
    let rec = &mut *rec_ptr;
    crate::kernel::exec::scheduler::attest::composition_digest(tier, &mut rec[..])
}

/// The composition record for `challenge`, ending in `tier`, in the
/// attestation scratch.
///
/// # Safety
/// Kernel context, exclusive access to the attestation scratch; the slice
/// is valid until the next attestation.
pub(crate) unsafe fn composition_record(challenge: &[u8; 32], tier: u8) -> Option<&'static [u8]> {
    let rec_ptr = &raw mut ATTEST_RECORD;
    let rec = &mut *rec_ptr;
    let n = crate::kernel::exec::scheduler::attest::write_record(challenge, tier, &mut rec[..])?;
    Some(&rec[..n])
}
