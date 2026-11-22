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
//! this backend reports `CUSTODY = SOFTWARE` — kernel static memory
//! isolates against a compromised *module*, not a compromised
//! host/kernel.
use crate::abi::contracts::key_vault as dev_key_vault;
use crate::abi::errno::{EACCES, EAGAIN, EBUSY, EINVAL, ENOENT, ENOMEM, ENOSYS, ERANGE, ERROR};

use crate::kernel::exec::scheduler::{ModuleId, NO_MODULE};
use crate::kernel::module::user_span::UserSpan;
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
/// `RSA_JOB_SLOT` is the vault slot whose signature `RSA_SIGN` holds, or
/// -1; the job's bookkeeping is its entry in `SIGN_JOBS`.
#[cfg(feature = "rsa-vault")]
const RSA_ENTRIES: usize = 2;
#[cfg(feature = "rsa-vault")]
static mut RSA_KEYS: [rsa::RsaPrivateKey; RSA_ENTRIES] =
    [rsa::RsaPrivateKey::empty(), rsa::RsaPrivateKey::empty()];
#[cfg(feature = "rsa-vault")]
static mut RSA_SIGN: rsa::RsaSignJob = rsa::RsaSignJob::new();
#[cfg(feature = "rsa-vault")]
static mut RSA_JOB_SLOT: i32 = -1;
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
/// Reported by `DESCRIBE` NEXT TO the custody and deliberately separate from
/// it: durability and isolation are different properties, and a consumer
/// that conflates them is the failure this whole surface is shaped to
/// prevent.
const FLAG_PERSISTED: u8 = 0x02;
/// This slot's key is kept in a workload's own vault, sealed under the key
/// the workload's owner supplied (`workload::vault`): its custody is
/// `SOFTWARE` whatever the platform's sealing key is worth, since whoever
/// holds the volume and that key holds the key.
const FLAG_OWNER_SEALED: u8 = 0x04;
/// This slot's key is persisted READABLE: the vault's store keeps records
/// unsealed (`vault_store` seal mode `none`). `DESCRIBE` reports it
/// persisted in the clear, and its custody `SOFTWARE`: whoever holds the
/// medium holds the key.
const FLAG_CLEAR: u8 = 0x08;

/// The realm of a key made by node code: every module the node runs itself.
/// A workload's realm is its owner uid ([`Scope`]).
const NODE_REALM: [u8; 16] = [0; 16];

/// Where a label lives: its owner's module type (`namespace`) within its
/// owner's realm — the node's, or one workload's, named by the workload's
/// durable owner uid. Labels are unique within a scope, and no module
/// reaches another scope's: two workloads running one module type, or a
/// workload and the node, never share a label.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Scope {
    namespace: u32,
    realm: [u8; 16],
}

impl Scope {
    /// The node's own scope for module type `namespace`.
    const fn node(namespace: u32) -> Self {
        Scope {
            namespace,
            realm: NODE_REALM,
        }
    }

    fn is_node(&self) -> bool {
        self.realm == NODE_REALM
    }
}

/// Who keeps a scope's persisted records, and under which sealing key.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Keeper {
    /// The platform's store (`hal::seal_blob_*`), sealed under the
    /// platform's key (`hal::seal`): the node's records, and a workload's
    /// when it brings no vault of its own.
    Platform,
    /// The workload's own vault, on a volume it is lent, sealed under the
    /// key its owner supplied (`workload::vault`): the records follow the
    /// volume and that key, not the node.
    #[cfg(feature = "host-linux")]
    Volume(crate::kernel::workload::owner::OwnerHandle),
}

/// The keeper of `scope`'s records: the workload's own vault while the
/// workload that holds `scope.realm` is live and brought one.
fn keeper_of(scope: Scope) -> Keeper {
    #[cfg(feature = "host-linux")]
    if !scope.is_node() {
        if let Some(h) = crate::kernel::exec::scheduler::owners().find_by_uid(scope.realm) {
            // SAFETY: scheduler thread, as every vault call.
            if unsafe { crate::platform::linux::owner_root::vault_present(h) } {
                return Keeper::Volume(h);
            }
        }
    }
    let _ = scope;
    Keeper::Platform
}

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
    owner: ModuleId,
    _pad: u8,
    /// Which occupancy of that scheduler slot: a module restarted or
    /// replaced in the same slot is another owner.
    owner_generation: u32,
    /// The label namespace: the owner's module type. Labels are unique
    /// within a namespace, and no module reaches another type's labels.
    namespace: u32,
    /// The owner's realm (see [`Scope`]).
    realm: [u8; 16],
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
            _pad: 0,
            owner_generation: 0,
            namespace: 0,
            realm: NODE_REALM,
            generation: 0,
            data: [0; MAX_KEY_BYTES],
        }
    }

    fn label_bytes(&self) -> &[u8] {
        &self.label[..self.label_len as usize]
    }

    /// Whether this slot is filed under `label` in `scope`.
    fn filed_as(&self, scope: Scope, label: &[u8]) -> bool {
        (self.flags & FLAG_IN_USE) != 0
            && self.namespace == scope.namespace
            && self.realm == scope.realm
            && self.label_bytes() == label
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
const KERNEL_OWNER: ModuleId = NO_MODULE;
/// A slot's generation, moved each time the slot is freed.
const GENERATION_MASK: u32 = (1 << 19) - 1;
const _: () =
    assert!(MAX_SLOTS <= crate::kernel::security::key_vault_router::HARDWARE_FIELD_BIT as usize);

/// Who is asking.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Caller {
    slot: ModuleId,
    generation: u32,
    namespace: u32,
    /// The realm of the module's owner (see [`Scope`]).
    realm: [u8; 16],
}

impl Caller {
    fn scope(&self) -> Scope {
        Scope {
            namespace: self.namespace,
            realm: self.realm,
        }
    }
}

/// The realm of the module in scheduler slot `idx`: its owner's uid when a
/// workload owns it, the node's otherwise.
fn realm_of(idx: usize) -> [u8; 16] {
    use crate::kernel::exec::scheduler;
    let owner = scheduler::module_owner(idx);
    if owner.is_node() {
        return NODE_REALM;
    }
    scheduler::owners()
        .lookup(owner)
        .map_or(NODE_REALM, |e| e.owner_uid)
}

/// The module whose code is running — the one a key it creates belongs to.
fn caller() -> Caller {
    use crate::kernel::exec::scheduler;
    let idx = scheduler::current_module_index();
    if idx >= scheduler::MAX_MODULES {
        return Caller {
            slot: KERNEL_OWNER,
            generation: 0,
            namespace: 0,
            realm: NODE_REALM,
        };
    }
    Caller {
        slot: idx as ModuleId,
        generation: scheduler::module_slot_generation(idx),
        namespace: scheduler::module_type_hash(idx),
        realm: realm_of(idx),
    }
}

/// The calling module as a key owner, `(scheduler slot, occupancy)`: what
/// another backend records so its handles are owner-scoped the same way.
pub(crate) fn caller_owner() -> (ModuleId, u32) {
    let c = caller();
    (c.slot, c.generation)
}

/// Whether the module occupancy `(slot, generation)` still exists: a
/// scheduler slot holds a new occupancy after a restart, a replacement or a
/// graph rebuild, and everything the old one owned is unreachable. Kernel
/// code has no scheduler slot and is always live.
pub(crate) fn owner_is_live(slot: ModuleId, generation: u32) -> bool {
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
    SLOTS[i].realm = c.realm;
    handle_of(i)
}

/// What this backend calls slot `i`: its index. The kernel wraps it in a
/// handle whose generation guards a caller's staleness.
///
/// # Safety
/// Kernel context, exclusive access to `SLOTS`.
unsafe fn handle_of(i: usize) -> i32 {
    i as i32
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
    // A key another backend holds is not this backend's to resolve.
    if handle & crate::kernel::security::key_vault_router::HARDWARE_FIELD_BIT != 0 {
        return Err(EINVAL);
    }
    let i = handle as usize;
    if i >= MAX_SLOTS {
        return Err(EINVAL);
    }
    if (SLOTS[i].flags & FLAG_IN_USE) == 0 {
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
// does not care which answer it gets: it persists either way, and `CUSTODY`
// reports the provenance separately. Wiring persistence to the custody here
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
///
/// A workload's record kept in the platform's store is `FXVW`, its header
/// followed by the workload's realm: the realm is authenticated with the key,
/// so no other workload's record, nor the node's, opens as it. A record in a
/// workload's own vault is `FXVK` and names no realm: it is the volume's and
/// its sealing key's, wherever the workload holding them runs.
const RECORD_MAGIC: [u8; 4] = *b"FXVK";
const REALM_RECORD_MAGIC: [u8; 4] = *b"FXVW";
/// A record kept READABLE (`vault_store` seal mode `none`): `FXVC` for the
/// node's, `FXVR` for a workload's, the key itself after the header. The
/// magic is part of the header a sealed record authenticates, so neither
/// kind reads as the other.
const CLEAR_RECORD_MAGIC: [u8; 4] = *b"FXVC";
const CLEAR_REALM_RECORD_MAGIC: [u8; 4] = *b"FXVR";
const MAX_HEADER: usize = 4 + 4 + 2 + 4 + 1 + MAX_LABEL + 16;
/// Longest durable name: `namespace:u32 (big-endian) ‖ [realm:16] ‖ label`.
const MAX_BLOB_NAME: usize = 4 + 16 + MAX_LABEL;

#[repr(C)]
#[derive(Clone, Copy)]
struct Persisted {
    live: bool,
    label: [u8; MAX_LABEL],
    label_len: u8,
    suite: u16,
    usage: u32,
    namespace: u32,
    realm: [u8; 16],
    /// Who sealed `sealed`: an entry whose scope's keeper is another now
    /// (the workload that held the vault is gone) is not this key.
    kept: Keeper,
    /// `sealed` holds the key itself: the store keeps records readable.
    clear: bool,
    /// The store's image sequence this record waits on to be durable; 0
    /// once it is (`vault_store`).
    pending: u64,
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
            realm: NODE_REALM,
            kept: Keeper::Platform,
            clear: false,
            pending: 0,
            sealed: [0; MAX_SEALED],
            sealed_len: 0,
        }
    }

    fn label_bytes(&self) -> &[u8] {
        &self.label[..self.label_len as usize]
    }

    fn scope(&self) -> Scope {
        Scope {
            namespace: self.namespace,
            realm: self.realm,
        }
    }
}

static mut PERSISTED: [Persisted; MAX_PERSISTED] = [Persisted::empty(); MAX_PERSISTED];

/// The record header for a key, written into `out`; returns its length.
fn record_header(
    scope: Scope,
    kept: Keeper,
    label: &[u8],
    suite: u16,
    usage: u32,
    clear: bool,
    out: &mut [u8; MAX_HEADER],
) -> usize {
    let realm_bound = !scope.is_node() && kept == Keeper::Platform;
    out[0..4].copy_from_slice(match (realm_bound, clear) {
        (true, false) => &REALM_RECORD_MAGIC,
        (false, false) => &RECORD_MAGIC,
        (true, true) => &CLEAR_REALM_RECORD_MAGIC,
        (false, true) => &CLEAR_RECORD_MAGIC,
    });
    out[4..8].copy_from_slice(&scope.namespace.to_le_bytes());
    out[8..10].copy_from_slice(&suite.to_le_bytes());
    out[10..14].copy_from_slice(&usage.to_le_bytes());
    #[expect(clippy::cast_possible_truncation, reason = "bounded by MAX_LABEL")]
    {
        out[14] = label.len() as u8;
    }
    out[15..15 + label.len()].copy_from_slice(label);
    if realm_bound {
        out[15 + label.len()..31 + label.len()].copy_from_slice(&scope.realm);
        return 31 + label.len();
    }
    15 + label.len()
}

/// The durable name a key is filed under: its namespace, then (a
/// workload's, in the platform's store) its realm, then its label.
fn blob_name(scope: Scope, kept: Keeper, label: &[u8], out: &mut [u8; MAX_BLOB_NAME]) -> usize {
    out[0..4].copy_from_slice(&scope.namespace.to_be_bytes());
    let mut at = 4;
    if !scope.is_node() && kept == Keeper::Platform {
        out[4..20].copy_from_slice(&scope.realm);
        at = 20;
    }
    out[at..at + label.len()].copy_from_slice(label);
    at + label.len()
}

/// Seal `plain` under `aad` as `kept` seals: `[nonce:12][ciphertext][tag:16]`.
fn keeper_seal(kept: Keeper, aad: &[u8], plain: &[u8], out: &mut [u8]) -> Option<usize> {
    match kept {
        Keeper::Platform => crate::kernel::sys::hal::seal(aad, plain, out),
        #[cfg(feature = "host-linux")]
        Keeper::Volume(h) => {
            // SAFETY: scheduler thread, as every vault call.
            let mut key = unsafe { crate::platform::linux::owner_root::vault_key(h) }?;
            let total = 12 + plain.len() + 16;
            if out.len() < total {
                zeroize(&mut key);
                return None;
            }
            let mut nonce = [0u8; 12];
            if crate::kernel::sys::hal::csprng_fill(&mut nonce) < 0 {
                zeroize(&mut key);
                return None;
            }
            out[..12].copy_from_slice(&nonce);
            out[12..12 + plain.len()].copy_from_slice(plain);
            let tag = crate::kernel::security::crypto::chacha20::chacha20_poly1305_encrypt(
                &key,
                &nonce,
                aad,
                &mut out[12..12 + plain.len()],
            );
            out[12 + plain.len()..total].copy_from_slice(&tag);
            zeroize(&mut key);
            Some(total)
        }
    }
}

/// Open what [`keeper_seal`] sealed; `None` (and `out` wiped) when it does
/// not open under `aad` and `kept`'s key.
fn keeper_unseal(kept: Keeper, aad: &[u8], sealed: &[u8], out: &mut [u8]) -> Option<usize> {
    match kept {
        Keeper::Platform => crate::kernel::sys::hal::unseal(aad, sealed, out),
        #[cfg(feature = "host-linux")]
        Keeper::Volume(h) => {
            // SAFETY: scheduler thread, as every vault call.
            let mut key = unsafe { crate::platform::linux::owner_root::vault_key(h) }?;
            if sealed.len() < 12 + 16 || out.len() < sealed.len() - 28 {
                zeroize(&mut key);
                return None;
            }
            let body = sealed.len() - 28;
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&sealed[..12]);
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&sealed[12 + body..]);
            out[..body].copy_from_slice(&sealed[12..12 + body]);
            let ok = crate::kernel::security::crypto::chacha20::chacha20_poly1305_decrypt(
                &key,
                &nonce,
                aad,
                &mut out[..body],
                &tag,
            );
            zeroize(&mut key);
            if ok {
                Some(body)
            } else {
                zeroize(&mut out[..body]);
                None
            }
        }
    }
}

/// Whether the node's records go to a `vault_store` module's store rather
/// than the platform's: the graph carries one.
fn module_store() -> bool {
    crate::kernel::security::vault_store::active()
}

/// Whether `kept` keeps records readable: the store's seal mode is `none`.
fn keeps_clear(kept: Keeper) -> bool {
    kept == Keeper::Platform && crate::kernel::security::vault_store::clear()
}

/// What storing (or removing) a record achieved.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kept {
    /// On the medium.
    Durable,
    /// In the store's image at this sequence, not on the medium yet.
    Pending(u64),
    /// The store refused it, or its medium did.
    Failed,
    /// There is no durable store at all.
    NoStore,
}

impl From<crate::kernel::security::vault_store::Durability> for Kept {
    fn from(d: crate::kernel::security::vault_store::Durability) -> Self {
        use crate::kernel::security::vault_store::Durability as D;
        match d {
            D::Durable => Kept::Durable,
            D::Pending(seq) => Kept::Pending(seq),
            D::Failed => Kept::Failed,
        }
    }
}

/// Read the record `kept` holds under `name`.
fn keeper_read(kept: Keeper, name: &[u8], out: &mut [u8]) -> Option<usize> {
    match kept {
        Keeper::Platform if module_store() => crate::kernel::security::vault_store::read(name, out),
        Keeper::Platform => crate::kernel::sys::hal::seal_blob_read(name, out),
        #[cfg(feature = "host-linux")]
        // SAFETY: scheduler thread, as every vault call.
        Keeper::Volume(h) => unsafe {
            crate::platform::linux::owner_root::vault_read(h, name, out)
        },
    }
}

/// Store `blob` under `name` with `kept`.
fn keeper_write(kept: Keeper, name: &[u8], blob: &[u8]) -> Kept {
    match kept {
        Keeper::Platform if module_store() => {
            crate::kernel::security::vault_store::write(name, blob).into()
        }
        Keeper::Platform => {
            if crate::kernel::sys::hal::seal_blob_write(name, blob) {
                Kept::Durable
            } else if crate::kernel::sys::hal::seal_blob_store() {
                Kept::Failed
            } else {
                Kept::NoStore
            }
        }
        #[cfg(feature = "host-linux")]
        Keeper::Volume(h) => {
            // SAFETY: scheduler thread, as every vault call.
            if unsafe { crate::platform::linux::owner_root::vault_write(h, name, blob) } {
                Kept::Durable
            } else {
                Kept::Failed
            }
        }
    }
}

/// Remove the record `kept` holds under `name`. `Durable` when none remains.
fn keeper_delete(kept: Keeper, name: &[u8]) -> Kept {
    match kept {
        Keeper::Platform if module_store() => {
            crate::kernel::security::vault_store::delete(name).into()
        }
        Keeper::Platform => {
            if !crate::kernel::sys::hal::seal_blob_store() {
                Kept::NoStore
            } else if crate::kernel::sys::hal::seal_blob_delete(name) {
                Kept::Durable
            } else {
                Kept::Failed
            }
        }
        #[cfg(feature = "host-linux")]
        Keeper::Volume(h) => {
            // SAFETY: scheduler thread, as every vault call.
            if unsafe { crate::platform::linux::owner_root::vault_delete(h, name) } {
                Kept::Durable
            } else {
                Kept::Failed
            }
        }
    }
}

/// Whether a record waiting on the store's image at `seq` is durable yet:
/// `Ok` when it is (or never waited), `EAGAIN` while the store writes it,
/// `ERROR` when the store's medium refused the write.
fn settled(pending: u64) -> Result<(), i32> {
    if pending == 0 {
        return Ok(());
    }
    match crate::kernel::security::vault_store::durability(pending) {
        crate::kernel::security::vault_store::Durability::Durable => Ok(()),
        crate::kernel::security::vault_store::Durability::Pending(_) => Err(EAGAIN),
        crate::kernel::security::vault_store::Durability::Failed => Err(ERROR),
    }
}

/// [`settled`] for a `PERSISTED` entry, which forgets its wait once durable.
///
/// # Safety
/// Kernel context, exclusive access to `PERSISTED`.
unsafe fn settle(pi: usize) -> Result<(), i32> {
    settled(PERSISTED[pi].pending)?;
    PERSISTED[pi].pending = 0;
    Ok(())
}

/// The platform has a durable store and it cannot be read yet (its medium
/// still coming up). Such a store is not an empty one: answered as empty, a
/// labelled open would generate a fresh key over the one already stored,
/// and a delete would leave the record to come back. Those paths answer
/// `EAGAIN` until it reads.
fn store_not_ready(scope: Scope) -> bool {
    if keeper_of(scope) != Keeper::Platform {
        return false;
    }
    if module_store() {
        return !crate::kernel::security::vault_store::ready();
    }
    crate::kernel::sys::hal::seal_blob_store() && !crate::kernel::sys::hal::seal_blob_ready()
}

/// Find a persisted entry by namespace and label: `Ok(None)` when no such
/// key exists, `Err(ENOMEM)` when one does but the RAM table has no entry
/// free to hold it. The two must not be confused: a caller that takes the
/// second for the first would generate a key over the one that exists.
///
/// # Safety
/// Kernel context, exclusive access to `PERSISTED`.
unsafe fn find_persisted(scope: Scope, label: &[u8]) -> Result<Option<usize>, i32> {
    let kept = keeper_of(scope);
    let table = &raw mut PERSISTED;
    for (i, e) in (*table).iter_mut().enumerate() {
        if e.live && e.scope() == scope && e.label_bytes() == label {
            if e.kept == kept {
                return Ok(Some(i));
            }
            // Sealed by a keeper this scope no longer has (the workload
            // that brought the vault is gone): not this key. What the
            // scope's keeper holds now is read afresh.
            zeroize(&mut e.sealed);
            *e = Persisted::empty();
        }
    }
    // Not in RAM — this may be a fresh process. Ask the platform whether it
    // kept one, which is what makes a labelled key survive a COLD restart
    // rather than only a scheduler reset. Without it an issuer would re-key
    // on every start and every credential it had signed would stop verifying,
    // silently: a verifier just sees a bad signature.
    rehydrate_persisted(scope, label)
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
unsafe fn rehydrate_persisted(scope: Scope, label: &[u8]) -> Result<Option<usize>, i32> {
    if label.is_empty() || label.len() > MAX_LABEL {
        return Ok(None);
    }
    let kept = keeper_of(scope);
    let mut name = [0u8; MAX_BLOB_NAME];
    let name_len = blob_name(scope, kept, label, &mut name);
    let mut blob = [0u8; MAX_HEADER + MAX_SEALED];
    let Some(n) = keeper_read(kept, &name[..name_len], &mut blob) else {
        return Ok(None);
    };
    // In a workload's own vault a record that is there and is not this key
    // (another seal key, a header altered at rest) is refused, never read as
    // absent: answered as absent, a labelled open would generate a key and
    // write it over the record — a misconfigured seal key would destroy the
    // key it cannot open.
    let unreadable = if kept == Keeper::Platform {
        Ok(None)
    } else {
        Err(EACCES)
    };
    if n < 15 {
        zeroize(&mut blob);
        return unreadable;
    }
    let suite = u16::from_le_bytes([blob[8], blob[9]]);
    let usage = u32::from_le_bytes([blob[10], blob[11], blob[12], blob[13]]);
    // A readable record is the key itself, and only a store kept readable
    // may hold one: in a sealed store it is a key planted on the medium.
    let clear = blob[0..4] == CLEAR_RECORD_MAGIC || blob[0..4] == CLEAR_REALM_RECORD_MAGIC;
    if clear && !keeps_clear(kept) {
        zeroize(&mut blob);
        return unreadable;
    }
    let mut header = [0u8; MAX_HEADER];
    let h = record_header(scope, kept, label, suite, usage, clear, &mut header);
    if n <= h || blob[..h] != header[..h] || n - h > MAX_SEALED {
        zeroize(&mut blob);
        return unreadable;
    }
    if clear {
        if n - h != suite_private_len(suite) {
            zeroize(&mut blob);
            return unreadable;
        }
    } else {
        // Proven here, not at first use: a record that does not open under
        // its own header is not this key.
        let mut probe = [0u8; MAX_KEY_BYTES];
        let opened = keeper_unseal(kept, &header[..h], &blob[h..n], &mut probe);
        zeroize(&mut probe);
        if opened.is_none() {
            zeroize(&mut blob);
            return unreadable;
        }
    }
    let Some(idx) = free_persisted() else {
        return Err(ENOMEM);
    };
    PERSISTED[idx] = Persisted::empty();
    PERSISTED[idx].label[..label.len()].copy_from_slice(label);
    #[expect(clippy::cast_possible_truncation, reason = "bounded by MAX_LABEL")]
    {
        PERSISTED[idx].label_len = label.len() as u8;
    }
    PERSISTED[idx].namespace = scope.namespace;
    PERSISTED[idx].realm = scope.realm;
    PERSISTED[idx].kept = kept;
    PERSISTED[idx].suite = suite;
    PERSISTED[idx].usage = usage;
    PERSISTED[idx].clear = clear;
    // Read from a store's image the medium may not hold yet: the record is
    // only as durable as that image.
    PERSISTED[idx].pending = if kept == Keeper::Platform && module_store() {
        match crate::kernel::security::vault_store::image_durability() {
            crate::kernel::security::vault_store::Durability::Durable => 0,
            _ => crate::kernel::security::vault_store::live_seq(),
        }
    } else {
        0
    };
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
    /// In the store's image at this sequence, which the `vault_store`
    /// module has not reported durable yet: the key is not handed out
    /// until it is (the caller asks again, `EAGAIN`).
    Pending(u64),
}

/// Seal `key` under `namespace`/`label` and store it durably.
///
/// # Safety
/// Kernel context, exclusive access to `PERSISTED`.
unsafe fn persist_key(scope: Scope, label: &[u8], suite: u16, usage: u32, key: &[u8]) -> Persist {
    if label.is_empty() || label.len() > MAX_LABEL {
        return Persist::Failed;
    }
    let kept = keeper_of(scope);
    let clear = keeps_clear(kept);
    let mut header = [0u8; MAX_HEADER];
    let h = record_header(scope, kept, label, suite, usage, clear, &mut header);
    let mut sealed = [0u8; MAX_SEALED];
    let n = if clear {
        if key.len() > MAX_SEALED {
            return Persist::Failed;
        }
        sealed[..key.len()].copy_from_slice(key);
        key.len()
    } else {
        match keeper_seal(kept, &header[..h], key, &mut sealed) {
            Some(n) => n,
            None => {
                // No sealing on this platform. The key still works for this
                // boot; it simply will not come back, and `DESCRIBE` reports
                // that truthfully rather than claiming a persistence that is
                // not there. A graph that asked for a sealed store on a board
                // with no sealing key is told why, once.
                if kept == Keeper::Platform && module_store() {
                    warn_unsealable();
                }
                return Persist::Unavailable;
            }
        }
    };
    let mut record = [0u8; MAX_HEADER + MAX_SEALED];
    record[..h].copy_from_slice(&header[..h]);
    record[h..h + n].copy_from_slice(&sealed[..n]);
    let mut name = [0u8; MAX_BLOB_NAME];
    let name_len = blob_name(scope, kept, label, &mut name);
    let outcome = match keeper_write(kept, &name[..name_len], &record[..h + n]) {
        Kept::Durable => Persist::Durable,
        Kept::Pending(seq) => Persist::Pending(seq),
        Kept::Failed => {
            log::warn!("[vault] persist failed: sealed record not durably stored (suite={suite})");
            Persist::Failed
        }
        Kept::NoStore => Persist::Unavailable,
    };
    zeroize(&mut record);
    if outcome == Persist::Failed {
        zeroize(&mut sealed);
        return outcome;
    }
    // The RAM entry carries the key across a scheduler reset, whether or not
    // the platform could keep it across a restart.
    let idx = match find_persisted(scope, label) {
        Ok(Some(i)) => i,
        Ok(None) | Err(_) => match free_persisted() {
            Some(i) => i,
            None => {
                zeroize(&mut sealed);
                return match outcome {
                    // In the store: a later open finds it there.
                    Persist::Durable | Persist::Pending(_) => outcome,
                    _ => Persist::Unavailable,
                };
            }
        },
    };
    PERSISTED[idx] = Persisted::empty();
    PERSISTED[idx].label[..label.len()].copy_from_slice(label);
    PERSISTED[idx].label_len = label.len() as u8;
    PERSISTED[idx].namespace = scope.namespace;
    PERSISTED[idx].realm = scope.realm;
    PERSISTED[idx].kept = kept;
    PERSISTED[idx].suite = suite;
    PERSISTED[idx].usage = usage;
    PERSISTED[idx].clear = clear;
    PERSISTED[idx].pending = match outcome {
        Persist::Pending(seq) => seq,
        _ => 0,
    };
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
        entry.scope(),
        entry.kept,
        entry.label_bytes(),
        entry.suite,
        entry.usage,
        entry.clear,
        &mut header,
    );
    let mut key = [0u8; MAX_KEY_BYTES];
    let n = if entry.clear {
        let n = entry.sealed_len as usize;
        if n > MAX_KEY_BYTES {
            return Err(ERROR);
        }
        key[..n].copy_from_slice(&entry.sealed[..n]);
        n
    } else {
        let Some(n) = keeper_unseal(
            entry.kept,
            &header[..h],
            &entry.sealed[..entry.sealed_len as usize],
            &mut key,
        ) else {
            return Err(ERROR);
        };
        n
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
    SLOTS[slot].realm = entry.realm;
    for (j, b) in key.iter().take(n).enumerate() {
        core::ptr::write_volatile(&raw mut SLOTS[slot].data[j], *b);
    }
    zeroize(&mut key);
    // In-use last, so a partial fill is never observable.
    SLOTS[slot].flags = FLAG_IN_USE
        | FLAG_PERSISTED
        | owner_sealed_flag(entry.kept)
        | if entry.clear { FLAG_CLEAR } else { 0 };
    Ok(slot)
}

/// A `PERSISTED` entry free to take: one not live, or one a workload's
/// vault sealed whose workload is gone (its keeper can never open it again,
/// and a workload churning through vaults must not fill the table).
///
/// # Safety
/// Kernel context, exclusive access to `PERSISTED`.
unsafe fn free_persisted() -> Option<usize> {
    let table = &raw mut PERSISTED;
    if let Some(i) = (*table).iter().position(|e| !e.live) {
        return Some(i);
    }
    #[cfg(feature = "host-linux")]
    for (i, e) in (*table).iter_mut().enumerate() {
        if let Keeper::Volume(h) = e.kept {
            if !crate::platform::linux::owner_root::vault_present(h) {
                zeroize(&mut e.sealed);
                *e = Persisted::empty();
                return Some(i);
            }
        }
    }
    None
}

/// [`FLAG_OWNER_SEALED`] for a key `kept` holds in a workload's own vault.
fn owner_sealed_flag(kept: Keeper) -> u8 {
    if kept == Keeper::Platform {
        0
    } else {
        FLAG_OWNER_SEALED
    }
}

/// Remove a persisted key: its RAM entry and its durable record. Returns
/// whether there was one, and where its removal stands: `Durable` (or
/// `NoStore`) when no durable record remains, `Pending` while the store's
/// medium still holds it, `Failed` when the store could not remove it, so it
/// would come back.
///
/// # Safety
/// Kernel context, exclusive access to `PERSISTED`.
unsafe fn forget_persisted(scope: Scope, label: &[u8]) -> (bool, Kept) {
    let mut found = false;
    let table = &raw mut PERSISTED;
    for e in (*table).iter_mut() {
        if e.live && e.scope() == scope && e.label_bytes() == label {
            zeroize(&mut e.sealed);
            *e = Persisted::empty();
            found = true;
        }
    }
    let kept = keeper_of(scope);
    let mut name = [0u8; MAX_BLOB_NAME];
    let name_len = blob_name(scope, kept, label, &mut name);
    let mut blob = [0u8; MAX_HEADER + MAX_SEALED];
    if keeper_read(kept, &name[..name_len], &mut blob).is_some() {
        found = true;
    }
    zeroize(&mut blob);
    let removed = keeper_delete(kept, &name[..name_len]);
    (found, removed)
}

/// Warn, once, that a sealed store was asked for on a board that cannot seal.
fn warn_unsealable() {
    static WARNED: portable_atomic::AtomicBool = portable_atomic::AtomicBool::new(false);
    if !WARNED.swap(true, portable_atomic::Ordering::Relaxed) {
        log::warn!(
            "[vault] store is seal: hardware and this board has no sealing key: keys are not persisted (seal: none keeps them readable)"
        );
    }
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
    let scope = Scope::node(namespace);
    if store_not_ready(scope) {
        return Err(EAGAIN);
    }
    // An import already waiting on the store is answered by that wait, not
    // made again: a fresh record would restart the write it waits on.
    if let Ok(Some(pi)) = find_persisted(scope, label) {
        if PERSISTED[pi].pending != 0 {
            return settle(pi);
        }
    }
    match persist_key(scope, label, suite, usage, key) {
        Persist::Durable => Ok(()),
        Persist::Pending(_) => Err(EAGAIN),
        Persist::Unavailable => Err(ENOSYS),
        Persist::Failed => Err(ERROR),
    }
}

/// The P-256 signing identity of module type `namespace` under `label`:
/// its public key, generating and persisting the key first when it does not
/// exist (uses `SIGN | EXPORT_PUBLIC | PERSIST`, as a module asks for its
/// own). The private half is generated here and only ever sealed. For an
/// operator enrolling a host: the public half is what a relying party is
/// told to trust, read before any evidence the key signs is seen.
///
/// # Safety
/// Kernel context, exclusive access to `SLOTS` and `PERSISTED`.
pub unsafe fn identity_public(namespace: u32, label: &[u8]) -> Result<[u8; 65], i32> {
    use dev_key_vault::{suite, usage};
    let want = usage::SIGN | usage::EXPORT_PUBLIC | usage::PERSIST;
    if label.is_empty() || label.len() > MAX_LABEL {
        return Err(EINVAL);
    }
    let scope = Scope::node(namespace);
    if store_not_ready(scope) {
        return Err(EAGAIN);
    }
    let mut key = [0u8; 32];
    match find_persisted(scope, label)? {
        Some(pi) => {
            if PERSISTED[pi].suite != suite::P256 || want & !PERSISTED[pi].usage != 0 {
                return Err(EACCES);
            }
            settle(pi)?;
            let slot = open_persisted(pi)?;
            key.copy_from_slice(&SLOTS[slot].data[..32]);
            zeroise_slot(slot);
        }
        None => {
            if !generate_into(suite::P256, &mut key) {
                zeroize(&mut key);
                return Err(ERROR);
            }
            match persist_key(scope, label, suite::P256, want, &key) {
                Persist::Durable => {}
                Persist::Pending(_) => {
                    // Kept, not yet on the medium: asked again, the same
                    // key is answered once it is.
                    zeroize(&mut key);
                    return Err(EAGAIN);
                }
                Persist::Unavailable => {
                    zeroize(&mut key);
                    return Err(ENOSYS);
                }
                Persist::Failed => {
                    zeroize(&mut key);
                    return Err(ERROR);
                }
            }
        }
    }
    let public = p256::public_key_from_scalar(&key);
    zeroize(&mut key);
    public.ok_or(ERROR)
}

/// Scratch for the composition record: sized for the largest table this
/// profile admits — one blob and one instance entry per module slot, and
/// one entry per graph edge.
const MAX_ATTEST_RECORD: usize = 4096
    + crate::kernel::config::MAX_MODULES * 40
    + crate::kernel::config::MAX_MODULES * 37
    + crate::kernel::boot::config::MAX_GRAPH_EDGES * 5;
static mut ATTEST_RECORD: [u8; MAX_ATTEST_RECORD] = [0; MAX_ATTEST_RECORD];

#[inline]
pub(crate) fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a live, exclusively-borrowed byte.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
}

/// The custody this vault reports: decided by the sealing key's provenance,
/// and only by a sealing key the platform can actually seal with.
///
/// A device-unique key that no seal uses protects nothing: the platform
/// that reads its OTP key and stubs `seal` holds every key in RAM with
/// nothing bound to the device, and reporting `DEVICE_HW` there would pass
/// every `custody >= DEVICE_HW` refusal on a claim nobody implemented.
fn current_custody() -> u8 {
    // A store kept readable holds the node's keys in the clear on its medium.
    if crate::kernel::security::vault_store::clear() {
        return dev_key_vault::custody::SOFTWARE;
    }
    if crate::kernel::sys::hal::seal_provenance()
        != crate::kernel::sys::hal::SealProvenance::DeviceUnique
    {
        return dev_key_vault::custody::SOFTWARE;
    }
    let mut probe = [0u8; 1 + 32];
    if crate::kernel::sys::hal::seal(b"fluxor/custody", &[0u8], &mut probe).is_some() {
        dev_key_vault::custody::DEVICE_HW
    } else {
        dev_key_vault::custody::SOFTWARE
    }
}

/// HMAC-SHA256 (RFC 2104) over the concatenation of `data`.
fn hmac_sha256(key: &[u8], data: &[&[u8]]) -> [u8; 32] {
    use crate::kernel::security::crypto::hmac::{hmac_parts, HashAlg};
    let mut out = [0u8; 32];
    hmac_parts(HashAlg::Sha256, key, data, &mut out);
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

// The key-wrap KEK and the wrapped object are the SDK core's
// (`security::custody_wrap`, `src/kernel/security/custody_wrap.rs`):
// HKDF-SHA256 with `salt = attest_digest`, `ikm = ECDH shared secret`,
// `info = KW_INFO || dest_pub || 0x01`, then ChaCha20-Poly1305 with the
// object's header (magic, ephemeral key, digest, nonce) as AAD. Salting
// with the destination's composition digest is what binds the wrap to it.
use crate::kernel::security::custody_wrap as cw;

/// Sign `msg` whole with slot `slot_idx` in its suite's convention (ECDSA
/// over its SHA-256 for P-256), the signature written into `out`, whose
/// length is the suite's signature length. `None` on failure.
///
/// # Safety
/// Kernel context, exclusive access to `SLOTS` and the ML-DSA scratch.
unsafe fn sign_bytes(slot_idx: usize, msg: &[u8], out: &mut [u8]) -> Option<usize> {
    use crate::kernel::security::crypto::sha256::Sha256;
    let slot = &SLOTS[slot_idx];
    #[cfg(feature = "pq-vault")]
    if let Some(set) = ml_dsa_set_for(slot.suite) {
        let mut seed = [0u8; ml_dsa::SEED_LEN];
        seed.copy_from_slice(&slot.data[..ml_dsa::SEED_LEN]);
        let ws = &mut *core::ptr::addr_of_mut!(ML_DSA_WS);
        let signed = ml_dsa::ml_dsa_sign_seed(set, &seed, &[], msg, ws, out).is_ok();
        ws.zeroize();
        zeroize(&mut seed);
        return signed.then_some(out.len());
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
        dev_key_vault::suite::ED25519 => Some(ed25519::ed25519_sign(&priv_key, msg)),
        _ => None,
    };
    zeroize(&mut priv_key);
    let sig = sig?;
    let n = out.len().min(64);
    out[..n].copy_from_slice(&sig[..n]);
    Some(n)
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
/// `DESCRIBE_SUITE` and the operations cannot disagree about what is
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
        // an expanded key does not reduce back to a seed. `DESCRIBE_SUITE`
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
            out.len() == 32 && crate::kernel::sys::hal::csprng_fill(&mut out[..32]) == 0
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
                if crate::kernel::sys::hal::csprng_fill(&mut out[..32]) != 0 {
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
            out.len() == 32 && crate::kernel::sys::hal::csprng_fill(&mut out[..32]) == 0
        }
        _ if ml_dsa_set_for(suite).is_some() => {
            out.len() == 32 && crate::kernel::sys::hal::csprng_fill(&mut out[..32]) == 0
        }
        _ => false,
    }
}

/// Derive slot `idx`'s public key into `out`, whose length must be
/// `suite_public_len` of the slot's suite.
///
/// # Safety
/// Kernel context, exclusive access to `SLOTS`.
unsafe fn write_public(idx: usize, out: &mut [u8]) -> bool {
    let pub_len = out.len();
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
                out.copy_from_slice(&pk);
                true
            }
            _ => false,
        },
        dev_key_vault::suite::ED25519 if pub_len == 32 => {
            let pk = ed25519::ed25519_public_key(&priv_key);
            out.copy_from_slice(&pk);
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
                    out.copy_from_slice(&staged[..pub_len]);
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
    drop_jobs_of(i);
    #[cfg(feature = "rsa-vault")]
    if is_rsa_suite(SLOTS[i].suite) && SLOTS[i].key_len == 1 {
        let entry = SLOTS[i].data[0] as usize;
        if entry < RSA_ENTRIES {
            let keys = &raw mut RSA_KEYS;
            (*keys)[entry].zeroize();
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
    SLOTS[i].realm = NODE_REALM;
    // Every handle to the key just destroyed stops resolving.
    SLOTS[i].generation = SLOTS[i].generation.wrapping_add(1) & GENERATION_MASK;
}
/// Provider dispatch function registered against the `key_vault` contract.
///
/// Key-bound ops (DESTROY, SIGN, ECDH, PUBLIC, DERIVE, the AEADs, ...) take
/// a `FD_TAG_KEY_VAULT`-tagged handle; the global ops listed in the match
/// below (STORE, GENERATE, OPEN, ...) take `handle=-1`.
pub fn provider_dispatch(handle: i32, opcode: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32 {
    // SAFETY: kernel context on the scheduler thread, one provider call at
    // a time: the slot tables and the vault's scratch are touched by this
    // call alone.
    unsafe { dispatch_slots(handle, opcode, arg, data) }
}

/// [`provider_dispatch`] over the slot tables.
///
/// # Safety
/// Kernel context, exclusive access to `SLOTS`, the sign jobs and the vault
/// scratch.
unsafe fn dispatch_slots(handle: i32, opcode: u32, arg: &mut [u8], mut data: UserSpan<'_>) -> i32 {
    let idx = match opcode {
        // Global (handle=-1) ops: anything not listed here must carry a
        // FD_TAG_KEY_VAULT-tagged handle or is rejected with EINVAL.
        dev_key_vault::STORE
        | dev_key_vault::VERIFY
        | dev_key_vault::GENERATE
        | dev_key_vault::OPEN_OR_GENERATE
        | dev_key_vault::OPEN
        | dev_key_vault::DESTROY_BY_LABEL
        | dev_key_vault::DESCRIBE_SUITE
        | dev_key_vault::CUSTODY => usize::MAX,
        _ => match resolve(handle) {
            Ok(i) => i,
            Err(e) => return e,
        },
    };
    let buf = data.as_mut();
    match opcode {
        dev_key_vault::STORE => store(arg, buf),
        dev_key_vault::DESTROY => {
            zeroise_slot(idx);
            0
        }
        dev_key_vault::SIGN => sign(idx, handle, arg, buf),
        dev_key_vault::ECDH => ecdh(idx, arg, buf),
        dev_key_vault::VERIFY => verify(handle, arg, buf),
        dev_key_vault::GENERATE => generate(arg, buf),
        dev_key_vault::PUBLIC => public(idx, arg, buf),
        dev_key_vault::ATTEST_COMPOSITION => attest_composition(idx, arg, buf),
        dev_key_vault::KEY_WRAP => key_wrap(idx, arg, buf),
        dev_key_vault::KEY_UNWRAP => key_unwrap(idx, buf),
        dev_key_vault::AEAD_SEAL => aead_seal(idx, arg, buf),
        dev_key_vault::AEAD_OPEN => aead_open(idx, arg, buf),
        dev_key_vault::CUSTODY => {
            // Isolation honesty, and the one place persistence must NOT be
            // allowed to speak.
            //
            // This backend seals keys so they survive a restart — see
            // `persist_key`. That is durability, and durability is not
            // isolation. The custody is derived from where the platform's
            // sealing key COMES FROM, never from whether sealing works:
            //
            //   - no sealing, or a key the host can also read
            //       → `SOFTWARE`. The record is opaque to a compromised
            //         module and transparent to a compromised host, which
            //         is exactly what `SOFTWARE` already means.
            //   - a key bound to the device and not extractable from it
            //       → `DEVICE_HW`. Only here has anything actually been
            //         isolated from the host.
            //
            // A backend that reported a stronger custody because it had learned
            // to persist would hand every consumer checking `custody >= N` a
            // guarantee nobody implemented.
            let Some(t) = arg.first_mut() else {
                return EINVAL;
            };
            *t = current_custody();
            1
        }
        dev_key_vault::DESCRIBE_SUITE => describe_suite(arg),
        dev_key_vault::DESCRIBE => {
            let slot = &SLOTS[idx];
            // Reported side by side and meaning different things. The custody
            // says what this key is isolated from; `persisted` says whether
            // it comes back after a restart. A key a workload's own vault
            // holds is sealed under a key its owner supplied, and a key kept
            // readable on the medium is isolated from no one who holds the
            // medium: both are `SOFTWARE` whatever the platform's key is.
            let d = dev_key_vault::describe::Described {
                suite: slot.suite,
                usage: slot.usage,
                custody: if slot.flags & (FLAG_OWNER_SEALED | FLAG_CLEAR) != 0 {
                    dev_key_vault::custody::SOFTWARE
                } else {
                    current_custody()
                },
                persisted: if slot.flags & FLAG_PERSISTED == 0 {
                    dev_key_vault::persisted::NO
                } else if slot.flags & FLAG_CLEAR != 0 {
                    dev_key_vault::persisted::CLEAR
                } else {
                    dev_key_vault::persisted::SEALED
                },
            };
            let Some(out) = arg.get_mut(..dev_key_vault::describe::ARG_LEN) else {
                return EINVAL;
            };
            out.copy_from_slice(&dev_key_vault::describe::encode(&d));
            dev_key_vault::describe::ARG_LEN as i32
        }
        dev_key_vault::OPEN_OR_GENERATE | dev_key_vault::OPEN => open_labelled(opcode, arg, buf),
        dev_key_vault::DESTROY_BY_LABEL => destroy_by_label(arg),
        dev_key_vault::DERIVE => derive(idx, arg),
        dev_key_vault::AEAD_SEAL_UNITS => seal_unit(idx, arg, buf),
        dev_key_vault::AEAD_OPEN_UNITS => open_unit(idx, arg, buf),
        dev_key_vault::SHARE_SPLIT => share_split(idx, arg, buf),
        _ => ENOSYS,
    }
}

/// Copy `key` into slot `i` (volatile, so the wipe of the source is not the
/// only copy the compiler keeps honest) and mark it in use last, so a
/// partial fill is never observed.
///
/// # Safety
/// Kernel context, exclusive access to `SLOTS`; `key.len() <= MAX_KEY_BYTES`.
unsafe fn fill_slot(i: usize, suite: u16, usage: u32, key: &[u8], flags: u8) {
    SLOTS[i].suite = suite;
    SLOTS[i].usage = usage;
    SLOTS[i].key_len = key.len() as u8;
    for (j, b) in key.iter().enumerate() {
        core::ptr::write_volatile(&raw mut SLOTS[i].data[j], *b);
    }
    SLOTS[i].flags = flags;
}

/// # Safety
/// As [`dispatch_slots`].
unsafe fn store(arg: &[u8], key: &[u8]) -> i32 {
    let Some((suite, usage)) = dev_key_vault::store::parse(arg) else {
        return EINVAL;
    };
    let key_len = key.len();
    let want = suite_private_len(suite);
    // An RSA DER is variable-length up to its ceiling; every other suite's
    // key is exactly the reported length.
    let fits = if is_rsa_suite(suite) {
        key_len > 0 && key_len <= want
    } else {
        key_len == want
    };
    if want == 0 || !fits {
        return EINVAL;
    }
    // A caller may not ask for a use the suite does not have — an Ed25519
    // key that claimed AGREE would be a key nothing could honour, discovered
    // at the first agreement rather than here.
    if usage == 0 || usage & !suite_usage(suite) != 0 {
        return EINVAL;
    }
    // A P-256 key must be a scalar in [1, n-1]. Admitting `d == 0` or
    // `d >= n` would make SIGN, ECDH and PUBLIC operate under a degenerate
    // key.
    if suite == dev_key_vault::suite::P256 {
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&key[..32]);
        let in_range = p256_scalar_in_range(&scalar);
        zeroize(&mut scalar);
        if !in_range {
            return EINVAL;
        }
    }
    let Some(idx) = alloc_slot() else {
        return ENOMEM;
    };
    #[cfg(feature = "rsa-vault")]
    if is_rsa_suite(suite) {
        // The DER goes into an RSA entry, checked and prepared there; the
        // slot names the entry. A key whose width is not the suite's is
        // refused: the suite is what every later length is derived from.
        let keys = &raw mut RSA_KEYS;
        let Some(entry) = (*keys).iter().position(|k| !k.is_loaded()) else {
            return ENOMEM;
        };
        let k = &mut (*keys)[entry];
        if !k.load_pkcs1_der(key) || rsa_suite_for_bits(k.n.bits()) != suite {
            k.zeroize();
            return EINVAL;
        }
        fill_slot(idx, suite, usage, &[entry as u8], FLAG_IN_USE);
        return mint(idx);
    }
    fill_slot(idx, suite, usage, key, FLAG_IN_USE);
    mint(idx)
}

/// The sign mode `suite` takes, or `None` for a suite that does not sign.
///
/// The mode must be the one the suite actually uses. A P-256 key handed
/// `RAW` would sign a message as though it were a digest — a valid
/// signature over the wrong thing, which is exactly the trap an inferred
/// convention sets. ML-DSA takes the whole message, like Ed25519: the pure
/// variant of FIPS 204 is not prehashed. `CONTEXT` is refused for every
/// suite: the SIGN layout carries no context field, and answering it with
/// the empty context would sign a different domain than the caller asked
/// for.
const fn sign_mode_of(suite: u16) -> Option<u8> {
    match suite {
        dev_key_vault::suite::P256 => Some(dev_key_vault::sign_mode::DIGEST),
        dev_key_vault::suite::ED25519 | dev_key_vault::suite::HMAC_SHA256 => {
            Some(dev_key_vault::sign_mode::RAW)
        }
        dev_key_vault::suite::RSA_2048
        | dev_key_vault::suite::RSA_3072
        | dev_key_vault::suite::RSA_4096 => Some(dev_key_vault::sign_mode::DIGEST),
        _ if ml_dsa_set_for(suite).is_some() => Some(dev_key_vault::sign_mode::RAW),
        _ => None,
    }
}

/// Whether `suite` signs as a resumable job.
const fn signs_resumably(suite: u16) -> bool {
    suite == dev_key_vault::suite::P256 || is_rsa_suite(suite) || ml_dsa_set_for(suite).is_some()
}

/// # Safety
/// As [`dispatch_slots`]; `idx` resolved.
unsafe fn sign(idx: usize, handle: i32, arg: &mut [u8], buf: &mut [u8]) -> i32 {
    let Some((mode, input_len)) = dev_key_vault::sign::parse(arg) else {
        return EINVAL;
    };
    let slot = &SLOTS[idx];
    // The mask, checked here rather than trusted from the caller.
    if !slot.permits(dev_key_vault::usage::SIGN) {
        return EACCES;
    }
    let sig_len = suite_signature_len(slot.suite);
    let Some(want_mode) = sign_mode_of(slot.suite) else {
        return ENOSYS;
    };
    if sig_len == 0 {
        return ENOSYS;
    }
    if mode != want_mode || input_len == 0 || input_len > buf.len() {
        return EINVAL;
    }
    // ECDSA signs a digest of at most 64 bytes; RSA-PSS a SHA-256 digest.
    if (slot.suite == dev_key_vault::suite::P256 && input_len > dev_key_vault::sign::DIGEST_MAX)
        || (is_rsa_suite(slot.suite) && input_len != 32)
    {
        return EINVAL;
    }
    if buf.len() < sig_len {
        dev_key_vault::sign::set_len(arg, sig_len);
        return ERANGE;
    }
    if signs_resumably(slot.suite) {
        return sign_job(idx, handle, mode, input_len, buf, sig_len);
    }
    let mut priv_key = [0u8; 32];
    priv_key.copy_from_slice(&slot.data[..32]);
    let n = match slot.suite {
        // An HMAC tag is 32 bytes over the whole message.
        dev_key_vault::suite::HMAC_SHA256 => {
            let mut tag = hmac_sha256(&priv_key, &[&buf[..input_len]]);
            buf[..32].copy_from_slice(&tag);
            zeroize(&mut tag);
            32
        }
        dev_key_vault::suite::ED25519 => {
            let sig = ed25519::ed25519_sign(&priv_key, &buf[..input_len]);
            buf[..64].copy_from_slice(&sig);
            64
        }
        _ => {
            zeroize(&mut priv_key);
            return ENOSYS;
        }
    };
    zeroize(&mut priv_key);
    n
}

// ── Resumable signing ───────────────────────────────────────────────────
//
// A suite whose signature is not cheap inside one caller step signs as a
// job kept against the key (`key_vault` contract, "Resumable SIGN"): the
// call that starts it answers EAGAIN, each identical call advances it, and
// the last writes the signature. A job is identified by its key's handle and
// the SHA-256 of `mode ‖ input`, so a repeated call is recognised without
// keeping the input.

/// Jobs the vault holds at once, across all keys.
#[cfg(target_arch = "aarch64")]
const MAX_SIGN_JOBS: usize = 8;
#[cfg(not(target_arch = "aarch64"))]
const MAX_SIGN_JOBS: usize = 2;

/// Comb columns (and their share of the inversion) a P-256 job advances per
/// call: the rest of the signature in one call where a core signs in well
/// under a step, a bounded slice of it elsewhere.
#[cfg(target_arch = "aarch64")]
const P256_SIGN_BITS_PER_CALL: u8 = 0;
#[cfg(not(target_arch = "aarch64"))]
const P256_SIGN_BITS_PER_CALL: u8 = 16;

struct SignJob {
    /// The key's slot, or -1 for a free entry.
    slot: i32,
    /// The handle the job was started through.
    handle: i32,
    /// SHA-256 of `mode ‖ input`.
    fingerprint: [u8; 32],
    /// When the job was last advanced (`hal::now_millis`).
    touched: u64,
    p256: p256::EcdsaSignState,
}

impl SignJob {
    const fn empty() -> Self {
        Self {
            slot: -1,
            handle: -1,
            fingerprint: [0; 32],
            touched: 0,
            p256: p256::EcdsaSignState::empty(),
        }
    }

    fn idle(&self, now: u64) -> bool {
        now.saturating_sub(self.touched) >= dev_key_vault::sign::JOB_IDLE_MS
    }

    /// Wipe the job: its nonce and key copy, then the entry.
    fn clear(&mut self) {
        self.p256.zeroise_secrets();
        self.p256 = p256::EcdsaSignState::empty();
        self.slot = -1;
        self.handle = -1;
        self.fingerprint = [0; 32];
    }
}

static mut SIGN_JOBS: [SignJob; MAX_SIGN_JOBS] = [const { SignJob::empty() }; MAX_SIGN_JOBS];

/// Drop every job on slot `i`.
///
/// # Safety
/// Kernel context, exclusive access to the sign jobs.
unsafe fn drop_jobs_of(i: usize) {
    let jobs = &raw mut SIGN_JOBS;
    for j in (*jobs).iter_mut() {
        if j.slot == i as i32 {
            j.clear();
        }
    }
    #[cfg(feature = "rsa-vault")]
    if RSA_JOB_SLOT == i as i32 {
        let job = &raw mut RSA_SIGN;
        (*job).zeroize();
        RSA_JOB_SLOT = -1;
    }
}

/// Run `SIGN` on slot `idx` as a job: start it (EAGAIN), advance it
/// (EAGAIN), or finish it (the signature over `buf`, its length).
///
/// # Safety
/// As [`dispatch_slots`]; `idx` resolved, `buf` holds the input in its
/// first `input_len` bytes and is at least `sig_len` long.
unsafe fn sign_job(
    idx: usize,
    handle: i32,
    mode: u8,
    input_len: usize,
    buf: &mut [u8],
    sig_len: usize,
) -> i32 {
    use crate::kernel::security::crypto::sha256::Sha256;
    let mut h = Sha256::new();
    h.update(&[mode]);
    h.update(&buf[..input_len]);
    let fingerprint = h.finalize();
    let now = crate::kernel::sys::hal::now_millis();
    let jobs = &mut *core::ptr::addr_of_mut!(SIGN_JOBS);
    let suite = SLOTS[idx].suite;

    if let Some(j) = jobs
        .iter()
        .position(|j| j.slot == idx as i32 && j.handle == handle)
    {
        if jobs[j].fingerprint == fingerprint {
            jobs[j].touched = now;
            return advance_job(j, idx, input_len, buf, sig_len);
        }
        // Another signature on this key is under way; one left alone past
        // the idle bound was abandoned and gives way.
        if !jobs[j].idle(now) {
            return EBUSY;
        }
        if is_rsa_suite(suite) {
            #[cfg(feature = "rsa-vault")]
            {
                (*core::ptr::addr_of_mut!(RSA_SIGN)).zeroize();
                RSA_JOB_SLOT = -1;
            }
        }
        jobs[j].clear();
    }
    // The RSA state is one job wide.
    #[cfg(feature = "rsa-vault")]
    if is_rsa_suite(suite) && RSA_JOB_SLOT >= 0 {
        let rsa_slot = RSA_JOB_SLOT;
        let holder = jobs.iter_mut().find(|j| j.slot == rsa_slot);
        match holder {
            Some(j) if !j.idle(now) => return EBUSY,
            Some(j) => j.clear(),
            None => {}
        }
        (*core::ptr::addr_of_mut!(RSA_SIGN)).zeroize();
        RSA_JOB_SLOT = -1;
    }
    let free = match jobs.iter().position(|j| j.slot < 0) {
        Some(f) => f,
        None => match jobs.iter().position(|j| j.idle(now)) {
            Some(stale) => {
                #[cfg(feature = "rsa-vault")]
                if RSA_JOB_SLOT == jobs[stale].slot {
                    (*core::ptr::addr_of_mut!(RSA_SIGN)).zeroize();
                    RSA_JOB_SLOT = -1;
                }
                jobs[stale].clear();
                stale
            }
            None => return EBUSY,
        },
    };
    let started = start_job(free, idx, &buf[..input_len]);
    if started != 0 {
        return started;
    }
    let job = &mut jobs[free];
    job.slot = idx as i32;
    job.handle = handle;
    job.fingerprint = fingerprint;
    job.touched = now;
    EAGAIN
}

/// Set up job `j`'s state for slot `idx` over `input`. 0, or the errno that
/// refuses the signature.
///
/// # Safety
/// As [`sign_job`].
unsafe fn start_job(j: usize, idx: usize, input: &[u8]) -> i32 {
    let jobs = &mut *core::ptr::addr_of_mut!(SIGN_JOBS);
    let slot = &SLOTS[idx];
    match slot.suite {
        dev_key_vault::suite::P256 => {
            let mut priv_key = [0u8; 32];
            priv_key.copy_from_slice(&slot.data[..32]);
            let st = p256::ecdsa_sign_init(&priv_key, input, P256_SIGN_BITS_PER_CALL);
            zeroize(&mut priv_key);
            match st {
                Some(st) => {
                    jobs[j].p256 = st;
                    0
                }
                None => EINVAL,
            }
        }
        #[cfg(feature = "rsa-vault")]
        s if is_rsa_suite(s) => {
            let entry = slot.data[0] as usize;
            if slot.key_len != 1 || entry >= RSA_ENTRIES {
                return EINVAL;
            }
            let key = &(*core::ptr::addr_of!(RSA_KEYS))[entry];
            let mut salt = [0u8; 32];
            if crate::kernel::sys::hal::csprng_fill(&mut salt) != 0 {
                return ERROR;
            }
            let k = key.n.byte_len();
            let mut em = [0u8; rsa::RSA_BYTES_MAX];
            let job = &mut *core::ptr::addr_of_mut!(RSA_SIGN);
            if !rsa::rsa_pss_encode(
                rsa::RsaHash::Sha256,
                input,
                &salt,
                &mut em[..k],
                key.n.bits(),
            ) || !job.start(key, &em[..k])
            {
                return ERROR;
            }
            RSA_JOB_SLOT = idx as i32;
            0
        }
        // ML-DSA signs whole on the call that finishes the job.
        _ => 0,
    }
}

/// Advance job `j` by one call's budget: EAGAIN, or the signature written
/// over `buf` and its length.
///
/// # Safety
/// As [`sign_job`].
unsafe fn advance_job(
    j: usize,
    idx: usize,
    input_len: usize,
    buf: &mut [u8],
    sig_len: usize,
) -> i32 {
    let jobs = &mut *core::ptr::addr_of_mut!(SIGN_JOBS);
    let suite = SLOTS[idx].suite;
    let rc = match suite {
        dev_key_vault::suite::P256 => {
            let st = &mut jobs[j].p256;
            if !st.scalar_mul.complete() && !st.scalar_mul.step() {
                return EAGAIN;
            }
            let st = core::mem::replace(&mut jobs[j].p256, p256::EcdsaSignState::empty());
            let sig = p256::ecdsa_sign_finalise(st);
            buf[..64].copy_from_slice(&sig);
            64
        }
        #[cfg(feature = "rsa-vault")]
        s if is_rsa_suite(s) => {
            let entry = SLOTS[idx].data[0] as usize;
            let key = &(*core::ptr::addr_of!(RSA_KEYS))[entry];
            let job = &mut *core::ptr::addr_of_mut!(RSA_SIGN);
            if job.step(key, rsa_sign_rows_per_call(key)) == rsa::RsaStep::Pending {
                return EAGAIN;
            }
            let signature = job.signature();
            let n = signature.len();
            buf[..n].copy_from_slice(signature);
            job.zeroize();
            RSA_JOB_SLOT = -1;
            n as i32
        }
        _ => match ml_dsa_sign(idx, &mut buf[..], input_len, sig_len) {
            Some(n) => n as i32,
            None => ERROR,
        },
    };
    jobs[j].clear();
    rc
}

/// ML-DSA over `buf[..input_len]` with slot `idx`'s seed, the signature
/// written over `buf`. `None` when the target holds no ML-DSA or the
/// signature fails.
///
/// # Safety
/// Kernel context, exclusive access to `SLOTS` and the ML-DSA scratch.
unsafe fn ml_dsa_sign(
    idx: usize,
    buf: &mut [u8],
    input_len: usize,
    sig_len: usize,
) -> Option<usize> {
    #[cfg(feature = "pq-vault")]
    if let Some(set) = ml_dsa_set_for(SLOTS[idx].suite) {
        let mut seed = [0u8; ml_dsa::SEED_LEN];
        seed.copy_from_slice(&SLOTS[idx].data[..ml_dsa::SEED_LEN]);
        let ws = &mut *core::ptr::addr_of_mut!(ML_DSA_WS);
        let staged = &mut *core::ptr::addr_of_mut!(ML_DSA_SIG);
        let signed = ml_dsa::ml_dsa_sign_seed(
            set,
            &seed,
            &[],
            &buf[..input_len],
            ws,
            &mut staged[..sig_len],
        )
        .is_ok();
        ws.zeroize();
        zeroize(&mut seed);
        if !signed {
            return None;
        }
        buf[..sig_len].copy_from_slice(&staged[..sig_len]);
        return Some(sig_len);
    }
    let _ = (idx, buf, input_len, sig_len);
    None
}

/// # Safety
/// As [`dispatch_slots`]; `idx` resolved.
unsafe fn ecdh(idx: usize, arg: &mut [u8], buf: &mut [u8]) -> i32 {
    let Some(peer_len) = dev_key_vault::ecdh::parse(arg) else {
        return EINVAL;
    };
    let slot = &SLOTS[idx];
    if slot.suite != dev_key_vault::suite::P256 || slot.key_len != 32 {
        return EINVAL;
    }
    // A signing key used for key agreement is a cross-purpose reuse, and
    // the mask is where it stops.
    if !slot.permits(dev_key_vault::usage::AGREE) {
        return EACCES;
    }
    if peer_len == 0 || peer_len > buf.len() {
        return EINVAL;
    }
    if buf.len() < 32 {
        dev_key_vault::ecdh::set_len(arg, 32);
        return ERANGE;
    }
    let mut priv_key = [0u8; 32];
    priv_key.copy_from_slice(&slot.data[..32]);
    let result = p256::ecdh_shared_secret(&priv_key, &buf[..peer_len]);
    zeroize(&mut priv_key);
    match result {
        Some(mut shared) => {
            buf[..32].copy_from_slice(&shared);
            zeroize(&mut shared);
            32
        }
        None => EINVAL,
    }
}

/// # Safety
/// As [`dispatch_slots`].
unsafe fn verify(handle: i32, arg: &[u8], data: &[u8]) -> i32 {
    let Some(lens) = dev_key_vault::verify::parse(arg) else {
        return EINVAL;
    };
    let Some((msg, sig, pk)) = dev_key_vault::verify::split(data, lens) else {
        return EINVAL;
    };
    // With a key's handle the key must hold an HMAC key: the message is the
    // whole message, the signature its tag, and the comparison happens here
    // in constant time.
    if handle >= 0 {
        let i = match resolve(handle) {
            Ok(i) => i,
            Err(e) => return e,
        };
        let slot = &SLOTS[i];
        if slot.suite != dev_key_vault::suite::HMAC_SHA256 {
            return EINVAL;
        }
        if !slot.permits(dev_key_vault::usage::VERIFY) {
            return EACCES;
        }
        if msg.is_empty() || sig.len() != 32 || !pk.is_empty() {
            return EINVAL;
        }
        let mut expect = hmac_sha256(&slot.data[..32], &[msg]);
        // Every byte is visited whatever the first mismatch, so the time
        // taken says nothing about where the tag went wrong.
        let mut diff: u8 = 0;
        for (a, b) in expect.iter().zip(sig) {
            diff |= a ^ b;
        }
        zeroize(&mut expect);
        return i32::from(diff == 0);
    }
    // With handle=-1, independent of the stored keys: ECDSA P-256 under the
    // caller's public key.
    if msg.is_empty() || sig.len() != 64 || pk.len() < 64 {
        return EINVAL;
    }
    i32::from(p256::ecdsa_verify(pk, msg, sig))
}

/// # Safety
/// As [`dispatch_slots`].
unsafe fn generate(arg: &mut [u8], buf: &mut [u8]) -> i32 {
    let Some((suite, usage, flags)) = dev_key_vault::generate::parse(arg) else {
        return EINVAL;
    };
    let priv_len = suite_private_len(suite);
    let pub_len = suite_public_len(suite);
    // RSA keys are imported, never minted here: prime generation is seconds
    // of work no target's step can host, and an operator's tooling mints
    // them anyway. DESCRIBE_SUITE says so per suite.
    if priv_len == 0 || is_rsa_suite(suite) {
        return ENOSYS;
    }
    if usage == 0 || usage & !suite_usage(suite) != 0 {
        return EINVAL;
    }
    // A caller asking for non-extractability is asking for a guarantee this
    // backend cannot give — its keys live in memory the host can read.
    // Refused rather than accepted and ignored: quietly not providing a
    // guarantee is worse than saying no.
    if flags & dev_key_vault::generate::flags::NON_EXTRACTABLE != 0 {
        return ENOSYS;
    }
    if buf.len() < pub_len {
        dev_key_vault::generate::set_len(arg, pub_len);
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
    fill_slot(idx, suite, usage, &key[..priv_len], FLAG_IN_USE);
    zeroize(&mut key);
    // A symmetric key has no public half to write.
    if !write_public(idx, &mut buf[..pub_len]) {
        zeroise_slot(idx);
        return ERROR;
    }
    dev_key_vault::generate::set_len(arg, pub_len);
    mint(idx)
}

/// # Safety
/// As [`dispatch_slots`]; `idx` resolved.
unsafe fn public(idx: usize, arg: &mut [u8], buf: &mut [u8]) -> i32 {
    let slot = &SLOTS[idx];
    // Exporting the PUBLIC half is still a permitted use, and one a key can
    // be created without — a key whose public half must not be published is
    // a real thing.
    if !slot.permits(dev_key_vault::usage::EXPORT_PUBLIC) {
        return EACCES;
    }
    let pub_len = suite_public_len(slot.suite);
    if pub_len == 0 {
        return ENOSYS;
    }
    #[cfg(feature = "rsa-vault")]
    if is_rsa_suite(slot.suite) {
        // The RSAPublicKey DER, at its exact length.
        let entry = slot.data[0] as usize;
        if slot.key_len != 1 || entry >= RSA_ENTRIES {
            return EINVAL;
        }
        let key = &(*core::ptr::addr_of!(RSA_KEYS))[entry];
        let mut der = [0u8; 526];
        let Some(n) = key.public_key_der(&mut der) else {
            return ERROR;
        };
        if buf.len() < n {
            dev_key_vault::public::set_len(arg, n);
            return ERANGE;
        }
        buf[..n].copy_from_slice(&der[..n]);
        return n as i32;
    }
    if buf.len() < pub_len {
        dev_key_vault::public::set_len(arg, pub_len);
        return ERANGE;
    }
    if !write_public(idx, &mut buf[..pub_len]) {
        return ERROR;
    }
    pub_len as i32
}

/// # Safety
/// As [`dispatch_slots`]; `idx` resolved.
unsafe fn attest_composition(idx: usize, arg: &mut [u8], buf: &mut [u8]) -> i32 {
    let Some(challenge) = dev_key_vault::attest_composition::parse(arg) else {
        return EINVAL;
    };
    if arg.len() < dev_key_vault::attest_composition::ARG_LEN {
        return EINVAL;
    }
    let slot = &SLOTS[idx];
    if !slot.permits(dev_key_vault::usage::SIGN) {
        return EACCES;
    }
    let sig_len = suite_signature_len(slot.suite);
    if sig_len == 0 {
        return ENOSYS;
    }
    let custody = current_custody();
    let rec = &mut *core::ptr::addr_of_mut!(ATTEST_RECORD);
    let Some(rec_len) =
        crate::kernel::exec::scheduler::attest::write_record(&challenge, custody, &mut rec[..])
    else {
        return ENOMEM;
    };
    let need = rec_len + sig_len;
    if buf.len() < need {
        dev_key_vault::attest_composition::set_len(arg, need);
        return ERANGE;
    }
    let Some(sig_written) = sign_bytes(idx, &rec[..rec_len], &mut buf[rec_len..need]) else {
        return ERROR;
    };
    buf[..rec_len].copy_from_slice(&rec[..rec_len]);
    (rec_len + sig_written) as i32
}

/// # Safety
/// As [`dispatch_slots`]; `idx` resolved.
unsafe fn key_wrap(idx: usize, arg: &mut [u8], buf: &mut [u8]) -> i32 {
    use dev_key_vault::wrap as w;
    let Some((dest, attest_in)) = dev_key_vault::key_wrap::parse(arg) else {
        return EINVAL;
    };
    let slot = &SLOTS[idx];
    if !slot.permits(dev_key_vault::usage::WRAP) {
        return EACCES;
    }
    let mut dest_pub = [0u8; w::EPH_PUB_LEN];
    dest_pub.copy_from_slice(dest);
    let mut attest = [0u8; 32];
    attest.copy_from_slice(attest_in);
    if !p256::public_point_is_valid(&dest_pub) {
        return EINVAL;
    }
    let key_len = slot.key_len as usize;
    let need = w::SEALED_OFF + w::SEALED_PREFIX + key_len + w::TAG_LEN;
    if buf.len() < need {
        dev_key_vault::key_wrap::set_len(arg, need);
        return ERANGE;
    }
    // Ephemeral agreement key, used once and zeroised.
    let mut eph = [0u8; 32];
    if !generate_into(dev_key_vault::suite::P256, &mut eph) {
        zeroize(&mut eph);
        return ERROR;
    }
    let Some(eph_pub) = p256::public_key_from_scalar(&eph) else {
        zeroize(&mut eph);
        return ERROR;
    };
    let shared = p256::ecdh_shared_secret(&eph, &dest_pub);
    zeroize(&mut eph);
    let Some(mut shared) = shared else {
        return EINVAL;
    };
    let mut nonce = [0u8; 12];
    if crate::kernel::sys::hal::csprng_fill(&mut nonce) != 0 {
        zeroize(&mut shared);
        return ERROR;
    }
    let sealed = cw::kw_seal(
        &shared,
        &eph_pub,
        &dest_pub,
        &attest,
        &nonce,
        slot.suite,
        slot.usage,
        &slot.data[..key_len],
        &mut buf[..need],
    );
    zeroize(&mut shared);
    if sealed != Some(need) {
        zeroize(&mut buf[..need]);
        return ERROR;
    }
    need as i32
}

/// # Safety
/// As [`dispatch_slots`]; `idx` resolved.
unsafe fn key_unwrap(idx: usize, blob: &[u8]) -> i32 {
    use dev_key_vault::wrap as w;
    if blob.len() < w::SEALED_OFF + w::SEALED_PREFIX + w::TAG_LEN || blob[..4] != w::MAGIC {
        return EINVAL;
    }
    let slot = &SLOTS[idx];
    if slot.suite != dev_key_vault::suite::P256 || slot.key_len != 32 {
        return EINVAL;
    }
    if !slot.permits(dev_key_vault::usage::AGREE) {
        return EACCES;
    }
    // The key was wrapped for a composition; it opens only while this one
    // still IS that composition.
    let Some(attest) = cw::kw_attest(blob) else {
        return EINVAL;
    };
    let rec = &mut *core::ptr::addr_of_mut!(ATTEST_RECORD);
    let Some(ours) =
        crate::kernel::exec::scheduler::attest::composition_digest(current_custody(), &mut rec[..])
    else {
        return ENOMEM;
    };
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= ours[i] ^ attest[i];
    }
    if diff != 0 {
        return EACCES;
    }
    let Some(eph_pub) = cw::kw_eph_pub(blob) else {
        return EINVAL;
    };
    let mut my_priv = [0u8; 32];
    my_priv.copy_from_slice(&slot.data[..32]);
    let shared = p256::ecdh_shared_secret(&my_priv, eph_pub);
    let my_pub = p256::public_key_from_scalar(&my_priv);
    zeroize(&mut my_priv);
    let Some(mut shared) = shared else {
        return EINVAL;
    };
    let Some(my_pub) = my_pub else {
        zeroize(&mut shared);
        return ERROR;
    };
    let mut key = [0u8; MAX_KEY_BYTES];
    let opened = cw::kw_open(&shared, &my_pub, &attest, blob, &mut key);
    zeroize(&mut shared);
    let Ok(opened) = opened else {
        zeroize(&mut key);
        return EINVAL;
    };
    let (suite, usage, key_len) = (opened.suite, opened.usage, opened.key_len);
    if suite_private_len(suite) != key_len || usage & !suite_usage(suite) != 0 || usage == 0 {
        zeroize(&mut key);
        return EINVAL;
    }
    let Some(new_slot) = alloc_slot() else {
        zeroize(&mut key);
        return ENOMEM;
    };
    // The generation is what keeps handles to the slot's earlier keys stale,
    // so it survives the reset of everything else.
    let generation = SLOTS[new_slot].generation;
    SLOTS[new_slot] = Slot::empty();
    SLOTS[new_slot].generation = generation;
    fill_slot(new_slot, suite, usage, &key[..key_len], FLAG_IN_USE);
    zeroize(&mut key);
    mint(new_slot)
}

/// # Safety
/// As [`dispatch_slots`]; `idx` resolved.
unsafe fn aead_seal(idx: usize, arg: &mut [u8], buf: &mut [u8]) -> i32 {
    use dev_key_vault::aead as a;
    let slot = &SLOTS[idx];
    if slot.suite != dev_key_vault::suite::AEAD_KEY {
        return EINVAL;
    }
    if !slot.permits(dev_key_vault::usage::SEAL) {
        return EACCES;
    }
    let Some(req) = a::parse(arg) else {
        return EINVAL;
    };
    let pt_len = req.len;
    if pt_len > a::MAX_LEN {
        return EINVAL;
    }
    let need = pt_len + a::TAG_LEN;
    if buf.len() < need {
        a::set_len(arg, need);
        return ERANGE;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&slot.data[..32]);
    let mut nonce = [0u8; a::NONCE_LEN];
    if crate::kernel::sys::hal::csprng_fill(&mut nonce) != 0 {
        zeroize(&mut key);
        return ERROR;
    }
    let tag = crate::kernel::security::crypto::chacha20::chacha20_poly1305_encrypt(
        &key,
        &nonce,
        req.aad,
        &mut buf[..pt_len],
    );
    zeroize(&mut key);
    buf[pt_len..need].copy_from_slice(&tag[..a::TAG_LEN]);
    a::set_nonce(arg, &nonce);
    need as i32
}

/// # Safety
/// As [`dispatch_slots`]; `idx` resolved.
unsafe fn aead_open(idx: usize, arg: &[u8], buf: &mut [u8]) -> i32 {
    use dev_key_vault::aead as a;
    let slot = &SLOTS[idx];
    if slot.suite != dev_key_vault::suite::AEAD_KEY {
        return EINVAL;
    }
    if !slot.permits(dev_key_vault::usage::OPEN) {
        return EACCES;
    }
    let Some(req) = a::parse(arg) else {
        return EINVAL;
    };
    let len = req.len;
    if len < a::TAG_LEN || len - a::TAG_LEN > a::MAX_LEN || len > buf.len() {
        return EINVAL;
    }
    let pt_len = len - a::TAG_LEN;
    let mut key = [0u8; 32];
    key.copy_from_slice(&slot.data[..32]);
    let mut tag = [0u8; a::TAG_LEN];
    tag.copy_from_slice(&buf[pt_len..len]);
    let ok = crate::kernel::security::crypto::chacha20::chacha20_poly1305_decrypt(
        &key,
        &req.nonce,
        req.aad,
        &mut buf[..pt_len],
        &tag,
    );
    zeroize(&mut key);
    if !ok {
        zeroize(&mut buf[..len]);
        return EINVAL;
    }
    pt_len as i32
}

/// What the vault can do with each suite it supports, in id order from
/// `cursor`.
///
/// # Safety
/// As [`dispatch_slots`].
unsafe fn describe_suite(arg: &mut [u8]) -> i32 {
    use dev_key_vault::describe_suite as ds;
    let Some(cursor) = ds::parse_cursor(arg) else {
        return EINVAL;
    };
    if arg.len() < ds::LEN {
        return EINVAL;
    }
    match suite_record(cursor) {
        Some(r) => {
            arg[..ds::LEN].copy_from_slice(&ds::encode(&r));
            ds::LEN as i32
        }
        None => ENOENT,
    }
}

/// The record of the first suite this backend supports at or after
/// `cursor`.
pub(crate) fn suite_record(cursor: u16) -> Option<dev_key_vault::describe_suite::Record> {
    use dev_key_vault::describe_suite as ds;
    let mut s = cursor;
    while s <= dev_key_vault::suite::MAX_ID {
        let priv_len = suite_private_len(s);
        if priv_len != 0 {
            let mut flags = ds::flags::IMPORT;
            if !is_rsa_suite(s) {
                flags |= ds::flags::GENERATE;
            }
            if signs_resumably(s) {
                flags |= ds::flags::RESUMABLE_SIGN;
            }
            return Some(ds::Record {
                suite: s,
                next: s + 1,
                usage: suite_usage(s),
                priv_len: priv_len as u16,
                pub_len: suite_public_len(s) as u16,
                sig_len: suite_signature_len(s) as u16,
                secret_len: if s == dev_key_vault::suite::P256 {
                    32
                } else {
                    0
                },
                flags,
            });
        }
        s += 1;
    }
    None
}

/// # Safety
/// As [`dispatch_slots`].
unsafe fn open_labelled(opcode: u32, arg: &mut [u8], buf: &mut [u8]) -> i32 {
    let Some(req) = dev_key_vault::open::parse(arg) else {
        return EINVAL;
    };
    let (suite, usage) = (req.suite, req.usage);
    let label_len = req.label.len();
    let mut label = [0u8; MAX_LABEL];
    label[..label_len].copy_from_slice(req.label);
    let label = &label[..label_len];

    let priv_len = suite_private_len(suite);
    let pub_len = suite_public_len(suite);
    if priv_len == 0 {
        return ENOSYS;
    }
    // Sized before anything is opened or made: a refusal after a key was
    // minted would leave a slot nobody holds a handle to, and the retry the
    // caller makes with a larger buffer would mint another.
    if buf.len() < pub_len {
        dev_key_vault::open::set_len(arg, pub_len);
        return ERANGE;
    }

    reap_orphans();
    // Labels live in the caller's namespace: its module type. An already-
    // open slot under this label is returned to its owner as-is — two
    // handles onto one key would each be destroyable independently, and the
    // second destroy would find a slot the first had freed. Another instance
    // of the same module type is refused: the key is in use, and it is not
    // that instance's.
    let who = caller();
    let scope = who.scope();
    let slots = &raw const SLOTS;
    let existing = (*slots).iter().position(|s| s.filed_as(scope, label));
    if let Some(i) = existing {
        if !owned_by(i, who) {
            return EBUSY;
        }
        if SLOTS[i].suite != suite || usage & !SLOTS[i].usage != 0 {
            return EACCES;
        }
    }

    // A durable store that cannot be read yet is not an empty one: reading
    // it as empty would generate a fresh key over one already stored (a
    // node's CA, minted anew on every boot). The caller asks again once the
    // medium is up.
    if existing.is_none() && store_not_ready(scope) {
        return EAGAIN;
    }
    let idx = match existing {
        Some(i) => i,
        None => match find_persisted(scope, label) {
            // A key exists that this table has no room to hold: never
            // answered by generating another over it.
            Err(e) => return e,
            Ok(Some(pi)) => {
                // The suite must be the one the key was born with, and the
                // mask is CHECKED against its uses, never applied.
                if PERSISTED[pi].suite != suite || usage & !PERSISTED[pi].usage != 0 {
                    return EACCES;
                }
                // Made by an earlier call and still on its way to the
                // medium: not handed out until it is there.
                if let Err(e) = settle(pi) {
                    return e;
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
                SLOTS[i].label[..label_len].copy_from_slice(label);
                SLOTS[i].label_len = label_len as u8;
                fill_slot(i, suite, usage, &key[..priv_len], 0);
                let persisted = if usage & dev_key_vault::usage::PERSIST != 0 {
                    persist_key(scope, label, suite, usage, &key[..priv_len])
                } else {
                    Persist::Unavailable
                };
                zeroize(&mut key);
                if persisted == Persist::Failed {
                    // A key asked to persist that could not be stored is not
                    // handed out: its owner would build on a key that does
                    // not come back.
                    zeroise_slot(i);
                    return ERROR;
                }
                if matches!(persisted, Persist::Pending(_)) {
                    // Kept in the store's image and not yet on its medium.
                    // Its owner asks again; the same key is answered once
                    // the medium holds it.
                    zeroise_slot(i);
                    return EAGAIN;
                }
                SLOTS[i].flags = FLAG_IN_USE
                    | if persisted == Persist::Durable {
                        FLAG_PERSISTED
                            | owner_sealed_flag(keeper_of(scope))
                            | if keeps_clear(keeper_of(scope)) {
                                FLAG_CLEAR
                            } else {
                                0
                            }
                    } else {
                        0
                    };
                i
            }
        },
    };

    // Public half back to the caller.
    if !write_public(idx, &mut buf[..pub_len]) {
        log::warn!("[vault] open refused: public-key derivation failed (suite={suite})");
        if existing.is_none() {
            // Opened or made by this call and handed to no one.
            zeroise_slot(idx);
        }
        return ERROR;
    }
    dev_key_vault::open::set_len(arg, pub_len);
    if existing.is_some() {
        handle_of(idx)
    } else {
        mint(idx)
    }
}

/// # Safety
/// As [`dispatch_slots`].
unsafe fn destroy_by_label(arg: &[u8]) -> i32 {
    let Some(l) = dev_key_vault::destroy_by_label::parse(arg) else {
        return EINVAL;
    };
    let mut label = [0u8; MAX_LABEL];
    label[..l.len()].copy_from_slice(l);
    let label = &label[..l.len()];
    // The record may be in a store that cannot be read yet: a delete
    // answered there would leave it to come back once it can.
    let scope = caller().scope();
    if store_not_ready(scope) {
        return EAGAIN;
    }
    // The live slot AND the sealed record. Destroying only the handle would
    // free a slot and leave the record, which comes back on the next open —
    // so a revocation that used it would not revoke.
    let mut found = false;
    let slots = &raw const SLOTS;
    let mut victims = [usize::MAX; MAX_SLOTS];
    let mut n = 0usize;
    for (i, sl) in (*slots).iter().enumerate() {
        if sl.filed_as(scope, label) {
            victims[n] = i;
            n += 1;
        }
    }
    for &i in victims.iter().take(n) {
        zeroise_slot(i);
        found = true;
    }
    let (had, removed) = forget_persisted(scope, label);
    match removed {
        Kept::Durable | Kept::NoStore => {}
        // Gone from the store's image, still on its medium: asked again,
        // answered once the medium lacks it too (a retry finds nothing to
        // remove and answers `ENOENT` then).
        Kept::Pending(_) => return EAGAIN,
        Kept::Failed => {
            log::warn!("[vault] destroy: sealed record could not be removed");
            return ERROR;
        }
    }
    if found || had {
        0
    } else {
        ENOENT
    }
}

/// # Safety
/// As [`dispatch_slots`]; `idx` resolved.
unsafe fn derive(idx: usize, arg: &[u8]) -> i32 {
    let master = &SLOTS[idx];
    if master.suite != dev_key_vault::suite::KDF_KEY {
        return EINVAL;
    }
    if !master.permits(dev_key_vault::usage::DERIVE) {
        return EACCES;
    }
    let Some(req) = dev_key_vault::derive::parse(arg) else {
        return EINVAL;
    };
    let (suite, usage) = (req.suite, req.usage);
    // A derived key is the same 32 bytes whenever it is derived, so it is
    // never persisted: persisting it would be a second copy of the master's
    // secret with its own lifetime.
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
    if usage == 0 || usage & !suite_usage(suite) != 0 || usage & dev_key_vault::usage::PERSIST != 0
    {
        return EINVAL;
    }
    let mut key = [0u8; 32];
    derive_key(
        &master.data[..master.key_len as usize],
        req.label,
        req.context,
        &mut key,
    );
    let Some(new) = alloc_slot() else {
        zeroize(&mut key);
        return ENOMEM;
    };
    fill_slot(new, suite, usage, &key, FLAG_IN_USE);
    zeroize(&mut key);
    mint(new)
}

/// The cipher a unit key seals under: `None` for ChaCha20-Poly1305, the
/// AES-GCM context otherwise; `Err` for a key that is not a unit key.
///
/// # Safety
/// As [`dispatch_slots`]; `idx` resolved.
unsafe fn unit_key(idx: usize, want: u32, key: &mut [u8; 32]) -> Result<bool, i32> {
    let slot = &SLOTS[idx];
    let aes = match slot.suite {
        dev_key_vault::suite::AEAD_KEY => false,
        dev_key_vault::suite::AEAD_AES256_GCM => true,
        _ => return Err(EINVAL),
    };
    if !slot.permits(want) {
        return Err(EACCES);
    }
    key.copy_from_slice(&slot.data[..32]);
    Ok(aes)
}

/// # Safety
/// As [`dispatch_slots`]; `idx` resolved.
unsafe fn seal_unit(idx: usize, arg: &mut [u8], unit: &mut [u8]) -> i32 {
    use dev_key_vault::units as u;
    let Some(req) = u::parse(arg) else {
        return EINVAL;
    };
    if unit.len() > u::MAX_UNIT {
        return EINVAL;
    }
    let mut key = [0u8; 32];
    let aes = match unit_key(idx, dev_key_vault::usage::SEAL, &mut key) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let tag = if aes {
        crate::kernel::security::crypto::aes_gcm::AesGcm::new_256(&key)
            .encrypt(&req.nonce, req.aad, unit)
    } else {
        crate::kernel::security::crypto::chacha20::chacha20_poly1305_encrypt(
            &key, &req.nonce, req.aad, unit,
        )
    };
    zeroize(&mut key);
    let mut t = [0u8; u::TAG_LEN];
    t.copy_from_slice(&tag[..u::TAG_LEN]);
    u::set_tag(arg, &t);
    0
}

/// # Safety
/// As [`dispatch_slots`]; `idx` resolved.
unsafe fn open_unit(idx: usize, arg: &[u8], unit: &mut [u8]) -> i32 {
    use dev_key_vault::units as u;
    let Some(req) = u::parse(arg) else {
        return EINVAL;
    };
    if unit.len() > u::MAX_UNIT {
        return EINVAL;
    }
    let mut key = [0u8; 32];
    let aes = match unit_key(idx, dev_key_vault::usage::OPEN, &mut key) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let ok = if aes {
        crate::kernel::security::crypto::aes_gcm::AesGcm::new_256(&key)
            .decrypt(&req.nonce, req.aad, unit, &req.tag)
    } else {
        crate::kernel::security::crypto::chacha20::chacha20_poly1305_decrypt(
            &key, &req.nonce, req.aad, unit, &req.tag,
        )
    };
    zeroize(&mut key);
    if ok {
        0
    } else {
        // Never leave unauthenticated plaintext behind.
        zeroize(unit);
        EINVAL
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

/// A fresh anti-replay id.
fn anti_replay_id() -> Option<[u8; 16]> {
    let mut id = [0u8; 16];
    (crate::kernel::sys::hal::csprng_fill(&mut id) == 0).then_some(id)
}

/// # Safety
/// Kernel context, exclusive access to `SLOTS`; `i` resolved.
unsafe fn share_split(i: usize, arg: &[u8], out: &mut [u8]) -> i32 {
    use dev_key_vault::share::{self as sh, split as a};
    if arg.len() < a::ARG_LEN {
        return EINVAL;
    }
    let slot = &SLOTS[i];
    if !splittable(slot.suite) || slot.key_len != 32 {
        return EINVAL;
    }
    if !slot.permits(dev_key_vault::usage::WRAP) {
        return EACCES;
    }
    let grant = key_share::Grant::read(&arg[..sh::grant::LEN]);
    if !grant.valid() {
        return EINVAL;
    }
    if out.len() < a::OUT_LEN {
        return ERANGE;
    }
    let out = &mut out[..a::OUT_LEN];
    let recipients = &arg[a::RECIPIENTS..a::ARG_LEN];
    let mut coeff = [0u8; 32];
    if crate::kernel::sys::hal::csprng_fill(&mut coeff) != 0 {
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
    let mut rc = a::OUT_LEN as i32;
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
        out[s * sh::P256_LEN..(s + 1) * sh::P256_LEN].copy_from_slice(&envelope);
    }
    for share in shares.iter_mut() {
        zeroize(share);
    }
    if rc < 0 {
        // No partial set: a caller must not hold two envelopes of a split it
        // was told failed.
        out.fill(0);
    }
    rc
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

/// Whether the calling module is a workload's: its labels live in its
/// workload's realm, which only this backend keeps (a token's labels name
/// a module type and nothing narrower).
pub(crate) fn caller_in_workload() -> bool {
    caller().realm != NODE_REALM
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
        if pub_len > scratch.len() || !write_public(i, &mut scratch[..pub_len]) {
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

/// The composition digest `KEY_WRAP` binds to, under `custody`.
///
/// # Safety
/// Kernel context, exclusive access to the attestation scratch.
pub(crate) unsafe fn composition_digest(custody: u8) -> Option<[u8; 32]> {
    let rec_ptr = &raw mut ATTEST_RECORD;
    let rec = &mut *rec_ptr;
    crate::kernel::exec::scheduler::attest::composition_digest(custody, &mut rec[..])
}

/// The composition record for `challenge`, ending in `custody`, in the
/// attestation scratch.
///
/// # Safety
/// Kernel context, exclusive access to the attestation scratch; the slice
/// is valid until the next attestation.
pub(crate) unsafe fn composition_record(
    challenge: &[u8; 32],
    custody: u8,
) -> Option<&'static [u8]> {
    let rec_ptr = &raw mut ATTEST_RECORD;
    let rec = &mut *rec_ptr;
    let n = crate::kernel::exec::scheduler::attest::write_record(challenge, custody, &mut rec[..])?;
    Some(&rec[..n])
}
