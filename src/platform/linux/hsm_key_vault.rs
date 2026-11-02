//! PKCS#11 (HSM/token) `key_vault` backend — Linux platform.
//!
//! Registers behind the KEY_VAULT router (`key_vault_router`) when a token
//! is configured. The software backend stays beside it: the router sends
//! this backend the P-256 keys it generates, the labelled P-256 keys asked
//! to persist that the software backend does not already hold, every label
//! lookup and destroy the software backend cannot answer, and every handle
//! it minted; the software backend gets everything else. Maps the vault
//! opcodes onto PKCS#11:
//!
//! - `GENERATE` → `C_GenerateKeyPair` with `CKA_SENSITIVE=true`,
//!   `CKA_EXTRACTABLE=false` — the private key is born inside the token
//!   and can never be read out; fluxor only ever sends a digest in and
//!   gets 64 signature bytes back.
//! - `SIGN` → `C_Sign` with raw `CKM_ECDSA` (not `CKM_ECDSA_SHA256`) over
//!   the caller-supplied digest. `CKM_ECDSA` returns the fixed-length
//!   `r ‖ s` form (64 bytes for P-256); the backend then folds `s` into
//!   the low-s range so the output is exactly the contract's low-s JWS
//!   ES256 segment. NOTE: tokens typically use random-k ECDSA, so
//!   signatures are different-but-valid versus the deterministic
//!   software backend — consumers verify, they don't byte-compare.
//! - `ECDH` → `C_DeriveKey` with `CKM_ECDH1_DERIVE` (CKD_NULL KDF): the
//!   32-byte X coordinate lands in a throwaway extractable session
//!   secret, is copied to the caller per the contract, and the object
//!   is destroyed. The P-256 usage mask covers both SIGN and AGREE, so a
//!   backend reporting it must implement both.
//! - `PUBLIC` → read `CKA_EC_POINT` (DER OCTET STRING unwrapped to the
//!   65-byte SEC1 point).
//! - `VERIFY` → delegated to the kernel software implementation: it takes
//!   a caller-supplied public key and touches no custodial material.
//! - `STORE` → `ENOSYS`. A non-extractable token cannot import an
//!   external private key; `SUITE_QUERY` reports a private length of 0,
//!   so consumers know to use `GENERATE`.
//! - `TIER` → `PROCESS_HW`: a host process talking to a token isolates
//!   the key from host-memory compromise to the extent the token does.
//! - `OPEN_OR_GENERATE` / `OPEN` → `C_FindObjects` on the key's token
//!   name, then — for `OPEN_OR_GENERATE` with nothing found — the
//!   `GENERATE` key pair, as token objects when the mask carries
//!   `PERSIST`. See "Labelled keys" below.
//! - `DESTROY_BY_LABEL` → `C_DestroyObject` on every token object filed
//!   under the key's name, after retiring any handle open on it.
//! - `DESCRIBE` → P-256, the key's sealed uses, `PROCESS_HW`, and
//!   persisted exactly when the key is a token object.
//!
//! This backend is P-256-scoped. `SUITE_QUERY` answers `ENOSYS` for every
//! other suite and `SUITE_ENUM` lists only P-256, so a consumer that needs
//! EdDSA learns it before it commits and falls back per its own policy.
//!
//! An unlabelled key (`GENERATE`) is a *session* object (`CKA_TOKEN=false`)
//! whatever its mask says: it has no name to be reopened by, so a token
//! object would only leak one keypair per run. It lives as long as its
//! owning module and the process. A key whose owning module is gone
//! (restart, replacement or graph rebuild) is destroyed in the token when a
//! slot is next needed.
//!
//! # Labelled keys
//!
//! A labelled key is named per caller namespace — the calling module's
//! type, the same namespace the software backend files its labels under —
//! so no module reaches another type's keys, and every instance of one type
//! reaches the same key. One asked for with `PERSIST` is a pair of *token*
//! objects (`CKA_TOKEN=true`; the private half `CKA_PRIVATE`,
//! `CKA_SENSITIVE`, never extractable), which a later process — a new
//! session on the same token — reopens by the same name. One asked for
//! without it is a session object carrying its label for this process only,
//! as the software backend's unpersisted labelled key is. A token key that
//! already exists is reopened whatever the new mask says about `PERSIST`.
//!
//! Both halves of a token key carry the same two attributes, and both are
//! created `CKA_MODIFIABLE=false`, so nothing on this side of the token can
//! rewrite them afterwards:
//!
//! - `CKA_LABEL` is the name: `fluxor-kv/` ‖ the namespace as 8 lowercase
//!   hex digits ‖ `/` ‖ the label as lowercase hex. Text, because tokens
//!   and their tools treat the label as a string; hex, because a vault
//!   label is any bytes.
//! - `CKA_ID` is the sealed record: `FXVK` ‖ namespace:u32 ‖ suite:u16 ‖
//!   usage:u32, little-endian. The usage mask is sealed here at creation and
//!   CHECKED on every reopen, never applied: a reopen asking for another
//!   suite or for a use the record lacks is `EACCES`, and so is a key under
//!   the name whose record this backend cannot read (it is never generated
//!   over).
//!
//! Lookup and creation run under the one session lock, so within a process
//! "is it there?" and "make it" are one step: two module instances starting
//! together cannot both generate. PKCS#11 has no create-if-absent across
//! processes; two processes sharing one token and one namespace are not
//! serialised by it, and a name the token holds two private keys under is
//! refused (`ERROR`) rather than resolved by picking one.
//!
//! `DESTROY` on a token key frees its slot and retires the handle and leaves
//! the key on the token — the next open finds it again, as the software
//! backend's sealed record is found again. `DESTROY_BY_LABEL` is what
//! removes it.
//!
//! Configuration (all read once at platform boot by
//! [`try_register_from_env`]; the backend activates only when the module
//! path is set — otherwise the kernel software default stays live):
//!
//! - `FLUXOR_HSM_PKCS11_MODULE` — path to the PKCS#11 shared object
//!   (e.g. `/usr/lib/softhsm/libsofthsm2.so`).
//! - `FLUXOR_HSM_TOKEN_LABEL` — match the token whose `CKA_LABEL` equals
//!   this string, **or** `FLUXOR_HSM_SLOT_ID` — a raw slot id.
//! - `FLUXOR_HSM_USER_PIN` — the normal-user (`CKU_USER`) PIN.
//!
//! # Thread-safety
//!
//! `cryptoki::session::Session` is `Send` but deliberately `!Sync`; it is
//! held behind a `Mutex` and locked per call. PKCS#11 calls are blocking
//! and run inline on the scheduler thread — adequate for signing-custody
//! rates; a throughput-sensitive deployment would front this with a
//! worker.

use std::sync::{Mutex, OnceLock};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use crate::abi::contracts::key_vault as dev_key_vault;
use crate::abi::errno::{EACCES, EBUSY, EINVAL, ENOENT, ENOMEM, ENOSYS, ERROR};
use crate::kernel::ipc::fd;

/// DER encoding of the `secp256r1` (NIST P-256, a.k.a. `prime256v1`)
/// named-curve OID `1.2.840.10045.3.1.7`, as required for `CKA_EC_PARAMS`.
const SECP256R1_OID_DER: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// P-256 group order `n`, big-endian.
const P256_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// `n / 2`, big-endian — the low-s threshold.
const P256_N_HALF: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
];

/// Fold the `s` half of a raw 64-byte `r ‖ s` ECDSA signature into the
/// low-s range: the contract's SIGN output is low-s (the JWS ES256
/// segment), but `CKM_ECDSA` hands back whichever of `s` / `n − s` the
/// token's random nonce produced. `(r, s)` and `(r, n − s)` verify
/// identically, so the fold is pure canonicalisation. Signatures are
/// public values — no constant-time requirement.
fn normalise_low_s(sig: &mut [u8; 64]) {
    // Equal-length big-endian compare is plain lexicographic order.
    if sig[32..64] <= P256_N_HALF[..] {
        return;
    }
    // s ← n − s, borrow-propagating from the least-significant byte.
    // A token-produced scalar satisfies 0 < s < n, so no final borrow.
    let mut borrow = 0u8;
    for i in (0..32).rev() {
        let (d, b1) = P256_N[i].overflowing_sub(sig[32 + i]);
        let (d, b2) = d.overflowing_sub(borrow);
        sig[32 + i] = d;
        borrow = (b1 || b2) as u8;
    }
}

/// Slots this backend holds: the vault contract exposes a small fixed handle
/// space, not the token's whole object store.
const MAX_SLOTS: usize = 8;

/// What this backend permits for the one suite it supports.
///
/// `PERSIST` is a permission, as the contract has it, and a labelled key
/// holding it is born a token object; an unlabelled one stays a session
/// object, since nothing could reopen it. There is no `WRAP`: a token key's
/// bytes are nowhere to wrap. Nor is there a `STORE_IMPORT` equivalent —
/// import is refused per-suite through `SUITE_QUERY` rather than as one
/// global bit, because tokens differ by algorithm and a single bit could not
/// say which.
const HSM_P256_USAGE: u32 = dev_key_vault::usage::SIGN
    | dev_key_vault::usage::VERIFY
    | dev_key_vault::usage::AGREE
    | dev_key_vault::usage::EXPORT_PUBLIC
    | dev_key_vault::usage::PERSIST;

/// Longest label, mirroring the contract's `MAX_LABEL`.
const MAX_LABEL: usize = dev_key_vault::MAX_LABEL;

/// Magic opening a token key's `CKA_ID` record.
const RECORD_MAGIC: [u8; 4] = *b"FXVK";
/// `FXVK ‖ namespace:u32 ‖ suite:u16 ‖ usage:u32`.
const RECORD_LEN: usize = 14;

/// The `CKA_LABEL` a labelled key is filed under on the token:
/// `fluxor-kv/<namespace:8 hex>/<label hex>`.
fn token_name(namespace: u32, label: &[u8]) -> Vec<u8> {
    use std::fmt::Write;
    let mut s = format!("fluxor-kv/{namespace:08x}/");
    for b in label {
        let _ = write!(s, "{b:02x}");
    }
    s.into_bytes()
}

/// A token key's `CKA_ID`: what it is and what it may do, sealed at birth.
fn token_record(namespace: u32, suite: u16, usage: u32) -> [u8; RECORD_LEN] {
    let mut r = [0u8; RECORD_LEN];
    r[..4].copy_from_slice(&RECORD_MAGIC);
    r[4..8].copy_from_slice(&namespace.to_le_bytes());
    r[8..10].copy_from_slice(&suite.to_le_bytes());
    r[10..14].copy_from_slice(&usage.to_le_bytes());
    r
}

/// `(suite, usage)` from a `CKA_ID` record of `namespace`, or `None` for one
/// this backend did not write.
fn parse_record(namespace: u32, r: &[u8]) -> Option<(u16, u32)> {
    if r.len() != RECORD_LEN || r[..4] != RECORD_MAGIC || r[4..8] != namespace.to_le_bytes() {
        return None;
    }
    Some((
        u16::from_le_bytes([r[8], r[9]]),
        u32::from_le_bytes([r[10], r[11], r[12], r[13]]),
    ))
}

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

/// One generated keypair living inside the token.
struct HsmSlot {
    private: ObjectHandle,
    public: ObjectHandle,
    /// The module that generated this key: scheduler slot and occupancy.
    owner: (crate::kernel::exec::scheduler::ModuleId, u32),
    /// Permitted uses, sealed at generation and checked per operation.
    usage: u32,
    /// The owner's label namespace (its module type).
    namespace: u32,
    /// The label this key is filed under, `None` for an unnamed key.
    label: Option<Vec<u8>>,
    /// A token object: it outlives the process, and freeing the slot leaves
    /// it on the token.
    persisted: bool,
}

/// The process-wide backend state, initialised once at platform boot.
struct HsmVault {
    /// `Session` is `!Sync`; the mutex serialises token access and holds
    /// the login for the process lifetime.
    session: Mutex<Session>,
    /// Keeps the loaded PKCS#11 library alive as long as the session.
    _ctx: Pkcs11,
    slots: Mutex<[Option<HsmSlot>; MAX_SLOTS]>,
    /// Per-slot generation, bumped when a key is destroyed and carried in
    /// every handle, so a handle to a destroyed key never reaches the next.
    generations: Mutex<[u32; MAX_SLOTS]>,
}

static VAULT: OnceLock<HsmVault> = OnceLock::new();

/// Which token to bind to within the loaded module.
enum TokenSelector {
    Label(String),
    SlotId(u64),
}

/// Read the backend configuration from the environment. `None` when the
/// module path is unset — the activation switch.
fn config_from_env() -> Option<(String, TokenSelector, String)> {
    let module = std::env::var("FLUXOR_HSM_PKCS11_MODULE").ok()?;
    let token = if let Ok(label) = std::env::var("FLUXOR_HSM_TOKEN_LABEL") {
        TokenSelector::Label(label)
    } else if let Ok(id) = std::env::var("FLUXOR_HSM_SLOT_ID") {
        match id.parse::<u64>() {
            Ok(n) => TokenSelector::SlotId(n),
            Err(_) => {
                log::error!("hsm_key_vault: FLUXOR_HSM_SLOT_ID {id:?} is not a number");
                return None;
            }
        }
    } else {
        log::error!(
            "hsm_key_vault: FLUXOR_HSM_PKCS11_MODULE set but neither \
             FLUXOR_HSM_TOKEN_LABEL nor FLUXOR_HSM_SLOT_ID given"
        );
        return None;
    };
    let pin = match std::env::var("FLUXOR_HSM_USER_PIN") {
        Ok(p) => p,
        Err(_) => {
            log::error!("hsm_key_vault: FLUXOR_HSM_USER_PIN not set");
            return None;
        }
    };
    Some((module, token, pin))
}

/// Find the slot for a [`TokenSelector`] within a loaded context.
fn resolve_slot(ctx: &Pkcs11, token: &TokenSelector) -> Result<Slot, String> {
    match token {
        TokenSelector::SlotId(id) => {
            Slot::try_from(*id).map_err(|e| format!("invalid PKCS#11 slot id {id}: {e}"))
        }
        TokenSelector::Label(label) => {
            let slots = ctx
                .get_slots_with_token()
                .map_err(|e| format!("failed to enumerate PKCS#11 slots: {e}"))?;
            for slot in slots {
                let info = ctx
                    .get_token_info(slot)
                    .map_err(|e| format!("failed to read PKCS#11 token info: {e}"))?;
                if info.label().trim_end() == label {
                    return Ok(slot);
                }
            }
            Err(format!("no PKCS#11 token found with label {label:?}"))
        }
    }
}

/// Load the module, open an authenticated session on the configured
/// token, and build the vault state.
fn open_vault(module: &str, token: &TokenSelector, pin: &str) -> Result<HsmVault, String> {
    let ctx = Pkcs11::new(module)
        .map_err(|e| format!("failed to load PKCS#11 module at {module}: {e}"))?;
    // OS_LOCKING_OK lets the module use native OS locking, which is what
    // SoftHSM2 and virtually every real HSM want. "Already initialized"
    // counts as success so construction stays idempotent.
    match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(())
        | Err(cryptoki::error::Error::Pkcs11(
            cryptoki::error::RvError::CryptokiAlreadyInitialized,
            _,
        )) => {}
        Err(e) => return Err(format!("C_Initialize failed: {e}")),
    }
    let slot = resolve_slot(&ctx, token)?;
    let session = ctx
        .open_rw_session(slot)
        .map_err(|e| format!("failed to open PKCS#11 session: {e}"))?;
    // Login state is per-token; a second login reports "already logged
    // in", which for our purposes is success.
    match session.login(UserType::User, Some(&AuthPin::new(pin.to_owned().into()))) {
        Ok(())
        | Err(cryptoki::error::Error::Pkcs11(cryptoki::error::RvError::UserAlreadyLoggedIn, _)) => {
        }
        Err(e) => return Err(format!("PKCS#11 login failed (check user PIN): {e}")),
    }
    Ok(HsmVault {
        session: Mutex::new(session),
        _ctx: ctx,
        slots: Mutex::new([const { None }; MAX_SLOTS]),
        generations: Mutex::new([0; MAX_SLOTS]),
    })
}

/// Activate the PKCS#11 backend if the environment configures one: register
/// it behind the KEY_VAULT router. Returns `true` when it registered; on
/// `false` the software backend serves everything alone (a consumer
/// requiring hardware sees `TIER = SOFTWARE` and refuses — the vault never
/// silently overclaims).
pub fn try_register_from_env() -> bool {
    let Some((module, token, pin)) = config_from_env() else {
        return false;
    };
    let vault = match open_vault(&module, &token, &pin) {
        Ok(v) => v,
        Err(e) => {
            log::error!(
                "hsm_key_vault: PKCS#11 backend configured but unavailable ({e}); \
                 KEY_VAULT stays on the kernel software backend (TIER=SOFTWARE)"
            );
            return false;
        }
    };
    if VAULT.set(vault).is_err() {
        log::error!("hsm_key_vault: already registered");
        return false;
    }
    // SAFETY: platform boot, before any module runs.
    unsafe { crate::kernel::security::key_vault_router::register_hardware(hsm_key_vault_dispatch) };
    log::info!("hsm_key_vault: PKCS#11 backend registered (module {module}, TIER=PROCESS_HW)");
    true
}

/// Read `CKA_EC_POINT` and return the raw 65-byte SEC1 uncompressed
/// point. PKCS#11 returns the attribute as a DER `OCTET STRING` wrapping
/// the ANSI X9.62 point, so a leading `04 41` (OCTET STRING, length 65)
/// prefix is stripped when present.
fn read_public_point(session: &Session, public_key: ObjectHandle) -> Result<[u8; 65], String> {
    let attrs = session
        .get_attributes(public_key, &[AttributeType::EcPoint])
        .map_err(|e| format!("failed to read CKA_EC_POINT: {e}"))?;
    let raw = attrs
        .into_iter()
        .find_map(|attr| match attr {
            Attribute::EcPoint(point) => Some(point),
            _ => None,
        })
        .ok_or_else(|| "PKCS#11 public key has no CKA_EC_POINT attribute".to_owned())?;
    let sec1: &[u8] = if raw.len() == 67 && raw[0] == 0x04 && raw[1] == 0x41 && raw[2] == 0x04 {
        &raw[2..]
    } else if raw.len() == 65 && raw[0] == 0x04 {
        &raw
    } else {
        return Err(format!(
            "unexpected CKA_EC_POINT encoding ({} bytes); expected a DER-wrapped \
             or raw 65-byte uncompressed P-256 point",
            raw.len()
        ));
    };
    let mut out = [0u8; 65];
    out.copy_from_slice(sec1);
    Ok(out)
}

/// Handle bits naming the slot; the generation sits above them.
const SLOT_BITS: u32 = 6;
const GENERATION_MASK: u32 = (1 << 19) - 1;
/// Set on every handle this backend mints, so the router sends it here.
const BACKEND_BIT: i32 = crate::kernel::security::key_vault_router::HARDWARE_FIELD_BIT;
const _: () = assert!(MAX_SLOTS <= 1 << SLOT_BITS);

/// The slot a handle names, if the caller may use it — the same rule as
/// the software backend: `EINVAL` for something that is not a vault handle,
/// `ENOENT` for a key that no longer exists, `EACCES` for another module's.
fn resolve(vault: &HsmVault, handle: i32) -> Result<usize, i32> {
    if handle < 0 {
        return Err(EINVAL);
    }
    let (tag, field) = fd::untag_fd(handle);
    if tag != fd::FD_TAG_KEY_VAULT || field & BACKEND_BIT == 0 {
        return Err(EINVAL);
    }
    let field = field & !BACKEND_BIT;
    let idx = (field & ((1 << SLOT_BITS) - 1)) as usize;
    let g = (field >> SLOT_BITS) as u32;
    if idx >= MAX_SLOTS {
        return Err(EINVAL);
    }
    let slots = vault.slots.lock().map_err(|_| ERROR)?;
    let generations = vault.generations.lock().map_err(|_| ERROR)?;
    let Some(slot) = &slots[idx] else {
        return Err(ENOENT);
    };
    if generations[idx] & GENERATION_MASK != g {
        return Err(ENOENT);
    }
    // A key whose owner is gone no longer exists, for anyone; its slot is
    // freed when the next GENERATE needs one.
    if !crate::kernel::security::key_vault::owner_is_live(slot.owner.0, slot.owner.1) {
        return Err(ENOENT);
    }
    if slot.owner != crate::kernel::security::key_vault::caller_owner() {
        return Err(EACCES);
    }
    Ok(idx)
}

/// The handle naming slot `idx` at its current generation.
fn handle_of(vault: &HsmVault, idx: usize) -> i32 {
    let g = vault
        .generations
        .lock()
        .map(|g| (g[idx] & GENERATION_MASK) as i32)
        .unwrap_or(0);
    fd::tag_fd(
        fd::FD_TAG_KEY_VAULT,
        BACKEND_BIT | (g << SLOT_BITS) | idx as i32,
    )
}

/// Retire a slot's handles — the generation moves on, so a handle to the
/// key stops resolving — and destroy its session objects. A token key's
/// objects stay on the token: `DESTROY_BY_LABEL` is what removes them.
fn release_slot(vault: &HsmVault, session: &Session, idx: usize, slot: HsmSlot) {
    if !slot.persisted {
        let _ = session.destroy_object(slot.private);
        let _ = session.destroy_object(slot.public);
    }
    if let Ok(mut g) = vault.generations.lock() {
        g[idx] = g[idx].wrapping_add(1) & GENERATION_MASK;
    }
}

/// Free the slots of keys whose owning module is gone: they are
/// unreachable. Run before a slot is allocated or a label looked up, so an
/// orphan never holds a slot or a label against a live module.
fn reap_orphans(vault: &HsmVault, session: &Session, slots: &mut [Option<HsmSlot>; MAX_SLOTS]) {
    for (i, entry) in slots.iter_mut().enumerate() {
        let orphan = matches!(
            entry,
            Some(k) if !crate::kernel::security::key_vault::owner_is_live(k.owner.0, k.owner.1)
        );
        if orphan {
            if let Some(k) = entry.take() {
                release_slot(vault, session, i, k);
            }
        }
    }
}

/// Generate a P-256 key pair in the token: session objects when `token` is
/// `None`, otherwise token objects filed under its `(CKA_LABEL, CKA_ID)`.
/// The private key is sensitive + non-extractable whatever the caller
/// asked: this backend has nothing weaker to offer, so a caller asking for
/// the guarantee always gets it. Returns `(public, private)`.
fn generate_pair(
    session: &Session,
    token: Option<(&[u8], &[u8])>,
) -> Result<(ObjectHandle, ObjectHandle), String> {
    let on_token = token.is_some();
    let mut pub_template = vec![
        Attribute::Token(on_token),
        Attribute::Private(false),
        Attribute::KeyType(KeyType::EC),
        Attribute::Verify(true),
        Attribute::EcParams(SECP256R1_OID_DER.to_vec()),
    ];
    let mut priv_template = vec![
        Attribute::Token(on_token),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
        // ECDH (CKM_ECDH1_DERIVE) needs CKA_DERIVE; many tokens
        // default it to false.
        Attribute::Derive(true),
    ];
    if let Some((name, record)) = token {
        // The name and the sealed record, fixed for the key's life: a
        // usage mask that could be rewritten in place is not sealed.
        for t in [&mut pub_template, &mut priv_template] {
            t.push(Attribute::Label(name.to_vec()));
            t.push(Attribute::Id(record.to_vec()));
            t.push(Attribute::Modifiable(false));
        }
    }
    session
        .generate_key_pair(&Mechanism::EccKeyPairGen, &pub_template, &priv_template)
        .map_err(|e| format!("C_GenerateKeyPair failed: {e}"))
}

/// A token key found by name.
struct TokenKey {
    private: ObjectHandle,
    public: ObjectHandle,
    suite: u16,
    usage: u32,
}

/// Find the token key `namespace`/`label` names. `Ok(None)` when the token
/// holds no private key under the name; `Err(EACCES)` for one whose record
/// this backend did not write (never generated over); `Err(ERROR)` when the
/// token cannot be searched or the name is ambiguous.
fn find_token_key(
    session: &Session,
    namespace: u32,
    label: &[u8],
) -> Result<Option<TokenKey>, i32> {
    let name = token_name(namespace, label);
    let privs = session
        .find_objects(&[
            Attribute::Token(true),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(name.clone()),
        ])
        .map_err(|e| {
            log::warn!("hsm_key_vault: C_FindObjects failed: {e}");
            ERROR
        })?;
    let private = match privs.as_slice() {
        [] => return Ok(None),
        [one] => *one,
        many => {
            log::warn!(
                "hsm_key_vault: the token holds {} private keys under one name; refusing to pick",
                many.len()
            );
            return Err(ERROR);
        }
    };
    let record = session
        .get_attributes(private, &[AttributeType::Id])
        .ok()
        .and_then(|attrs| {
            attrs.into_iter().find_map(|a| match a {
                Attribute::Id(v) => Some(v),
                _ => None,
            })
        })
        .unwrap_or_default();
    let Some((suite, usage)) = parse_record(namespace, &record) else {
        log::warn!("hsm_key_vault: a token key under a vault name carries no vault record");
        return Err(EACCES);
    };
    let pubs = session
        .find_objects(&[
            Attribute::Token(true),
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Label(name),
            Attribute::Id(record),
        ])
        .map_err(|e| {
            log::warn!("hsm_key_vault: C_FindObjects failed: {e}");
            ERROR
        })?;
    let [public] = pubs.as_slice() else {
        log::warn!(
            "hsm_key_vault: a token key has {} public halves under its name",
            pubs.len()
        );
        return Err(ERROR);
    };
    Ok(Some(TokenKey {
        private,
        public: *public,
        suite,
        usage,
    }))
}

/// `OPEN_OR_GENERATE` / `OPEN`, under the contract's rules: `EBUSY` for a
/// key another instance of the caller's module type holds open, `EACCES`
/// for another suite or a wider mask than the key was born with, `ENOENT`
/// for `OPEN` of an absent key, `ENOMEM` with no slot free, `ERANGE`
/// (checked before anything is opened or made) for a short public buffer.
///
/// # Safety
/// As [`hsm_key_vault_dispatch`].
unsafe fn open_labelled(vault: &HsmVault, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
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
    let label = core::slice::from_raw_parts(arg.add(8), label_len).to_vec();
    let tail = arg.add(8 + label_len);
    let pub_out = read_u64(tail) as *mut u8;
    let pub_cap = u16::from_le_bytes([*tail.add(8), *tail.add(9)]) as usize;
    if suite != dev_key_vault::suite::P256 {
        return ENOSYS;
    }
    // Sized before anything is opened or made: a refusal after a key was
    // minted would leave a slot nobody holds a handle to.
    if pub_cap < 65 {
        core::ptr::copy_nonoverlapping(65u16.to_le_bytes().as_ptr(), tail.add(10), 2);
        return crate::abi::errno::ERANGE;
    }
    let mut slots = match vault.slots.lock() {
        Ok(s) => s,
        Err(_) => return ERROR,
    };
    let session = match vault.session.lock() {
        Ok(s) => s,
        Err(_) => return ERROR,
    };
    reap_orphans(vault, &session, &mut slots);
    let owner = crate::kernel::security::key_vault::caller_owner();
    let namespace = crate::kernel::security::key_vault::caller_namespace();

    // Already open in this process: returned to its owner as-is (two
    // handles onto one key would each be destroyable independently), and
    // refused to another instance of the same module type.
    let existing = slots.iter().position(|s| {
        matches!(s, Some(k) if k.namespace == namespace && k.label.as_deref() == Some(&label[..]))
    });
    let idx = if let Some(i) = existing {
        let Some(k) = &slots[i] else {
            return ERROR;
        };
        if k.owner != owner {
            return EBUSY;
        }
        if usage & !k.usage != 0 {
            return EACCES;
        }
        i
    } else {
        let found = match find_token_key(&session, namespace, &label) {
            Ok(f) => f,
            Err(e) => return e,
        };
        // The mask is CHECKED against the key's sealed uses, never applied:
        // permitted uses must not be something a later caller widens by
        // asking. Checked before a slot is looked for, so a key under
        // another suite or a narrower mask answers EACCES whatever the table.
        match &found {
            Some(k) if k.suite != suite || usage & !k.usage != 0 => return EACCES,
            Some(_) => {}
            None if opcode == dev_key_vault::OPEN => return ENOENT,
            None if usage == 0 || usage & !HSM_P256_USAGE != 0 => return EINVAL,
            None => {}
        }
        let Some(idx) = slots.iter().position(Option::is_none) else {
            return ENOMEM;
        };
        let slot = match found {
            Some(k) => HsmSlot {
                private: k.private,
                public: k.public,
                owner,
                usage: k.usage,
                namespace,
                label: Some(label),
                persisted: true,
            },
            None => {
                let persist = usage & dev_key_vault::usage::PERSIST != 0;
                let name = token_name(namespace, &label);
                let record = token_record(namespace, suite, usage);
                if persist {
                    // A public half left behind by a pair whose private half
                    // is gone would make the new pair's public ambiguous.
                    if let Ok(stray) = session
                        .find_objects(&[Attribute::Token(true), Attribute::Label(name.clone())])
                    {
                        for o in stray {
                            let _ = session.destroy_object(o);
                        }
                    }
                }
                let token = persist.then_some((&name[..], &record[..]));
                let (public, private) = match generate_pair(&session, token) {
                    Ok(pair) => pair,
                    Err(e) => {
                        log::warn!("hsm_key_vault: {e}");
                        return ERROR;
                    }
                };
                HsmSlot {
                    private,
                    public,
                    owner,
                    usage,
                    namespace,
                    label: Some(label),
                    persisted: persist,
                }
            }
        };
        slots[idx] = Some(slot);
        idx
    };

    let Some(k) = &slots[idx] else {
        return ERROR;
    };
    let point = match read_public_point(&session, k.public) {
        Ok(p) => p,
        Err(e) => {
            log::warn!("hsm_key_vault: {e}");
            if existing.is_none() {
                // Opened or made by this call and handed to no one. A
                // token key stays on the token; a session one goes.
                if let Some(k) = slots[idx].take() {
                    release_slot(vault, &session, idx, k);
                }
            }
            return ERROR;
        }
    };
    if !pub_out.is_null() {
        core::ptr::copy_nonoverlapping(point.as_ptr(), pub_out, 65);
    }
    core::ptr::copy_nonoverlapping(65u16.to_le_bytes().as_ptr(), tail.add(10), 2);
    drop(session);
    drop(slots);
    handle_of(vault, idx)
}

/// `DESTROY_BY_LABEL`: retire any handle open on the key and remove its
/// token objects. `0`, `ENOENT` when nothing has the label, `ERROR` when a
/// token object could not be removed (it would come back).
///
/// # Safety
/// As [`hsm_key_vault_dispatch`].
unsafe fn destroy_labelled(vault: &HsmVault, arg: *mut u8, arg_len: usize) -> i32 {
    // arg: [label_len:u8][label[label_len]]
    if arg.is_null() || arg_len < 2 {
        return EINVAL;
    }
    let label_len = *arg as usize;
    if label_len == 0 || label_len > MAX_LABEL || 1 + label_len > arg_len {
        return EINVAL;
    }
    let label = core::slice::from_raw_parts(arg.add(1), label_len);
    let mut slots = match vault.slots.lock() {
        Ok(s) => s,
        Err(_) => return ERROR,
    };
    let session = match vault.session.lock() {
        Ok(s) => s,
        Err(_) => return ERROR,
    };
    let namespace = crate::kernel::security::key_vault::caller_namespace();
    let mut found = false;
    for (i, entry) in slots.iter_mut().enumerate() {
        let named = matches!(entry, Some(k) if k.namespace == namespace && k.label.as_deref() == Some(label));
        if named {
            if let Some(k) = entry.take() {
                release_slot(vault, &session, i, k);
                found = true;
            }
        }
    }
    // Both halves, and anything else filed under the name: a key whose
    // objects stayed would come back on the next open, so a revocation that
    // used this would not revoke.
    let objects = match session.find_objects(&[
        Attribute::Token(true),
        Attribute::Label(token_name(namespace, label)),
    ]) {
        Ok(o) => o,
        Err(e) => {
            log::warn!("hsm_key_vault: C_FindObjects failed: {e}");
            return ERROR;
        }
    };
    let had = !objects.is_empty();
    for o in objects {
        if let Err(e) = session.destroy_object(o) {
            log::warn!("hsm_key_vault: destroy: token object could not be removed: {e}");
            return ERROR;
        }
    }
    if found || had {
        0
    } else {
        ENOENT
    }
}

/// Whether slot `idx` permits `want`: `Err(EACCES)` when it does not.
fn permits(vault: &HsmVault, idx: usize, want: u32) -> Result<(), i32> {
    let slots = vault.slots.lock().map_err(|_| ERROR)?;
    match &slots[idx] {
        Some(slot) if slot.usage & want == want => Ok(()),
        Some(_) => Err(EACCES),
        None => Err(ENOENT),
    }
}

/// KEY_VAULT provider dispatch backed by the PKCS#11 token.
///
/// # Safety
/// `arg` must be valid for `arg_len` bytes for reads (input fields per
/// the opcode's layout) and writes (`*_out` regions). Caller must not
/// retain `arg` after return.
pub unsafe fn hsm_key_vault_dispatch(
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    let Some(vault) = VAULT.get() else {
        // Registration only happens after VAULT.set succeeds; reaching
        // here means a wiring bug, not a missing token.
        return ENOSYS;
    };
    match opcode {
        dev_key_vault::PROBE => 1,
        dev_key_vault::SUITE_QUERY => {
            // arg: [suite:u16][_pad:u16][usage_out:u32]
            //      [priv_len_out:u16][pub_len_out:u16][sig_len_out:u16]
            if arg.is_null() || arg_len < 14 {
                return EINVAL;
            }
            let suite = u16::from_le_bytes([*arg, *arg.add(1)]);
            if suite != dev_key_vault::suite::P256 {
                return crate::abi::errno::ENOSYS;
            }
            let usage = HSM_P256_USAGE.to_le_bytes();
            core::ptr::copy_nonoverlapping(usage.as_ptr(), arg.add(4), 4);
            // The private length is 0 and that is the answer, not a gap:
            // this backend never hands out a private key and never takes
            // one, so there is no private length a caller could allocate
            // for. `STORE` refuses accordingly.
            core::ptr::copy_nonoverlapping(0u16.to_le_bytes().as_ptr(), arg.add(8), 2);
            core::ptr::copy_nonoverlapping(65u16.to_le_bytes().as_ptr(), arg.add(10), 2);
            core::ptr::copy_nonoverlapping(64u16.to_le_bytes().as_ptr(), arg.add(12), 2);
            14
        }
        dev_key_vault::SUITE_ENUM => {
            // One suite, so the enumeration is short and always complete.
            if arg.is_null() || arg_len < 16 {
                return EINVAL;
            }
            let cursor = u16::from_le_bytes([*arg, *arg.add(1)]);
            let out_ptr = {
                let mut b = [0u8; 8];
                for (i, v) in b.iter_mut().enumerate() {
                    *v = *arg.add(4 + i);
                }
                u64::from_le_bytes(b) as *mut u8
            };
            let out_cap = u16::from_le_bytes([*arg.add(12), *arg.add(13)]) as usize;
            let mut written = 0u16;
            if cursor <= dev_key_vault::suite::P256 && out_cap >= 2 && !out_ptr.is_null() {
                core::ptr::copy_nonoverlapping(
                    dev_key_vault::suite::P256.to_le_bytes().as_ptr(),
                    out_ptr,
                    2,
                );
                written = 1;
            }
            core::ptr::copy_nonoverlapping(written.to_le_bytes().as_ptr(), arg.add(14), 2);
            0
        }
        dev_key_vault::TIER => {
            if arg.is_null() || arg_len < 1 {
                return EINVAL;
            }
            *arg = dev_key_vault::tier::PROCESS_HW;
            1
        }
        // Import is unavailable against a non-extractable token, which
        // SUITE_QUERY already reported as a private length of 0.
        dev_key_vault::STORE => ENOSYS,
        dev_key_vault::ECDH => {
            // arg: [peer_len:u32][peer[peer_len]]
            //      [out_ptr:u64][out_cap:u16][out_len_out:u16]
            if arg.is_null() || arg_len < 4 {
                return EINVAL;
            }
            let idx = match resolve(vault, handle) {
                Ok(i) => i,
                Err(e) => return e,
            };
            if let Err(e) = permits(vault, idx, dev_key_vault::usage::AGREE) {
                return e;
            }
            let peer_len =
                u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]) as usize;
            if peer_len == 0 || peer_len > 65 || 4 + peer_len + 12 > arg_len {
                return EINVAL;
            }
            let ecdh_tail = arg.add(4 + peer_len);
            let ecdh_out = read_u64(ecdh_tail) as *mut u8;
            let ecdh_cap = u16::from_le_bytes([*ecdh_tail.add(8), *ecdh_tail.add(9)]) as usize;
            if ecdh_cap < 32 {
                core::ptr::copy_nonoverlapping(32u16.to_le_bytes().as_ptr(), ecdh_tail.add(10), 2);
                return crate::abi::errno::ERANGE;
            }
            let peer = core::slice::from_raw_parts(arg.add(4), peer_len);
            // CKM_ECDH1_DERIVE takes the peer point as the raw ANSI
            // X9.62 octet string (`04 ‖ X ‖ Y`); also accept the bare
            // 64-byte `X ‖ Y` form, mirroring the software backend's
            // with-or-without-0x04 handling. The token validates the
            // point is on the curve.
            let mut prefixed = [0u8; 65];
            let public_data: &[u8] = match (peer_len, peer.first()) {
                (65, Some(0x04)) => peer,
                (64, _) => {
                    prefixed[0] = 0x04;
                    prefixed[1..].copy_from_slice(peer);
                    &prefixed
                }
                _ => return EINVAL,
            };
            let slots = match vault.slots.lock() {
                Ok(s) => s,
                Err(_) => return ERROR,
            };
            let Some(slot) = &slots[idx] else {
                return EINVAL;
            };
            let session = match vault.session.lock() {
                Ok(s) => s,
                Err(_) => return ERROR,
            };
            // Derive into a throwaway extractable session secret: the
            // 32-byte X coordinate goes to the caller per the contract,
            // so the object holds nothing the caller doesn't receive.
            let template = [
                Attribute::Token(false),
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::GENERIC_SECRET),
                Attribute::Sensitive(false),
                Attribute::Extractable(true),
                Attribute::ValueLen(32.into()),
            ];
            let mechanism =
                Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null(), public_data));
            let derived = match session.derive_key(&mechanism, slot.private, &template) {
                Ok(k) => k,
                Err(e) => {
                    log::warn!("hsm_key_vault: C_DeriveKey (ECDH) failed: {e}");
                    return ERROR;
                }
            };
            let attrs = session.get_attributes(derived, &[AttributeType::Value]);
            let _ = session.destroy_object(derived);
            let mut secret = match attrs {
                Ok(list) => match list.into_iter().find_map(|attr| match attr {
                    Attribute::Value(v) => Some(v),
                    _ => None,
                }) {
                    Some(v) => v,
                    None => {
                        log::warn!("hsm_key_vault: derived ECDH secret has no CKA_VALUE");
                        return ERROR;
                    }
                },
                Err(e) => {
                    log::warn!("hsm_key_vault: failed to read derived ECDH secret: {e}");
                    return ERROR;
                }
            };
            let rc = if secret.len() == 32 {
                if !ecdh_out.is_null() {
                    core::ptr::copy_nonoverlapping(secret.as_ptr(), ecdh_out, 32);
                }
                core::ptr::copy_nonoverlapping(32u16.to_le_bytes().as_ptr(), ecdh_tail.add(10), 2);
                0
            } else {
                log::warn!(
                    "hsm_key_vault: expected a 32-byte ECDH secret, got {} bytes",
                    secret.len()
                );
                ERROR
            };
            // The shared secret transited host memory; wipe our copy
            // (volatile, matching the software backend's discipline).
            for byte in secret.iter_mut() {
                core::ptr::write_volatile(byte as *mut u8, 0);
            }
            rc
        }
        // VERIFY takes a caller-supplied public key and touches no
        // custodial material — reuse the kernel software implementation
        // rather than a token round-trip.
        dev_key_vault::VERIFY => {
            crate::kernel::security::key_vault::provider_dispatch(handle, opcode, arg, arg_len)
        }
        dev_key_vault::GENERATE => {
            // arg: [suite:u16][usage_mask:u32][flags:u8][_pad:u8]
            //      [pub_out_ptr:u64][pub_out_cap:u16][pub_len_out:u16]
            if arg.is_null() || arg_len < 20 {
                return EINVAL;
            }
            let suite = u16::from_le_bytes([*arg, *arg.add(1)]);
            if suite != dev_key_vault::suite::P256 {
                // ES256-scoped backend: `SUITE_QUERY` answers ENOSYS for
                // everything else, and so does this.
                return ENOSYS;
            }
            let usage = u32::from_le_bytes([*arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5)]);
            if usage == 0 || usage & !HSM_P256_USAGE != 0 {
                return EINVAL;
            }
            let gen_tail = arg.add(8);
            let gen_out = read_u64(gen_tail) as *mut u8;
            let gen_cap = u16::from_le_bytes([*gen_tail.add(8), *gen_tail.add(9)]) as usize;
            if gen_cap < 65 {
                core::ptr::copy_nonoverlapping(65u16.to_le_bytes().as_ptr(), gen_tail.add(10), 2);
                return crate::abi::errno::ERANGE;
            }
            let mut slots = match vault.slots.lock() {
                Ok(s) => s,
                Err(_) => return ERROR,
            };
            let session = match vault.session.lock() {
                Ok(s) => s,
                Err(_) => return ERROR,
            };
            // Keys whose owning module is gone are unreachable: free their
            // slots and session objects before looking for one.
            reap_orphans(vault, &session, &mut slots);
            let Some(idx) = slots.iter().position(Option::is_none) else {
                return ENOMEM;
            };
            // Session objects whatever the mask: an unnamed key has nothing
            // to be reopened by, so a token object would only leak.
            let (public, private) = match generate_pair(&session, None) {
                Ok(pair) => pair,
                Err(e) => {
                    log::warn!("hsm_key_vault: {e}");
                    return ERROR;
                }
            };
            let point = match read_public_point(&session, public) {
                Ok(p) => p,
                Err(e) => {
                    log::warn!("hsm_key_vault: {e}");
                    let _ = session.destroy_object(private);
                    let _ = session.destroy_object(public);
                    return ERROR;
                }
            };
            if !gen_out.is_null() {
                core::ptr::copy_nonoverlapping(point.as_ptr(), gen_out, 65);
            }
            core::ptr::copy_nonoverlapping(65u16.to_le_bytes().as_ptr(), gen_tail.add(10), 2);
            slots[idx] = Some(HsmSlot {
                private,
                public,
                owner: crate::kernel::security::key_vault::caller_owner(),
                usage,
                namespace: crate::kernel::security::key_vault::caller_namespace(),
                label: None,
                persisted: false,
            });
            drop(slots);
            handle_of(vault, idx)
        }
        dev_key_vault::PUBLIC => {
            // arg: [out_ptr:u64][out_cap:u16][out_len_out:u16]
            if arg.is_null() || arg_len < 12 {
                return EINVAL;
            }
            let idx = match resolve(vault, handle) {
                Ok(i) => i,
                Err(e) => return e,
            };
            if let Err(e) = permits(vault, idx, dev_key_vault::usage::EXPORT_PUBLIC) {
                return e;
            }
            let pub_out = read_u64(arg) as *mut u8;
            let pub_cap = u16::from_le_bytes([*arg.add(8), *arg.add(9)]) as usize;
            if pub_cap < 65 {
                core::ptr::copy_nonoverlapping(65u16.to_le_bytes().as_ptr(), arg.add(10), 2);
                return crate::abi::errno::ERANGE;
            }
            let slots = match vault.slots.lock() {
                Ok(s) => s,
                Err(_) => return ERROR,
            };
            let Some(slot) = &slots[idx] else {
                return EINVAL;
            };
            let session = match vault.session.lock() {
                Ok(s) => s,
                Err(_) => return ERROR,
            };
            match read_public_point(&session, slot.public) {
                Ok(point) => {
                    if !pub_out.is_null() {
                        core::ptr::copy_nonoverlapping(point.as_ptr(), pub_out, 65);
                    }
                    core::ptr::copy_nonoverlapping(65u16.to_le_bytes().as_ptr(), arg.add(10), 2);
                    0
                }
                Err(e) => {
                    log::warn!("hsm_key_vault: {e}");
                    ERROR
                }
            }
        }
        dev_key_vault::SIGN => {
            // arg: [sign_mode:u8][_pad:u8][input_len:u32][input[input_len]]
            //      [sig_out_ptr:u64][sig_out_cap:u16][sig_len_out:u16]
            if arg.is_null() || arg_len < 6 {
                return EINVAL;
            }
            let idx = match resolve(vault, handle) {
                Ok(i) => i,
                Err(e) => return e,
            };
            if let Err(e) = permits(vault, idx, dev_key_vault::usage::SIGN) {
                return e;
            }
            // P-256 signs a DIGEST. Explicit rather than inferred: a caller
            // that handed this a message would otherwise get a valid
            // signature over the wrong thing.
            if *arg != dev_key_vault::sign_mode::DIGEST {
                return EINVAL;
            }
            let hash_len =
                u32::from_le_bytes([*arg.add(2), *arg.add(3), *arg.add(4), *arg.add(5)]) as usize;
            if hash_len == 0 || hash_len > 64 || 6 + hash_len + 12 > arg_len {
                return EINVAL;
            }
            let sig_tail = arg.add(6 + hash_len);
            let sig_out = read_u64(sig_tail) as *mut u8;
            let sig_cap = u16::from_le_bytes([*sig_tail.add(8), *sig_tail.add(9)]) as usize;
            if sig_cap < 64 {
                core::ptr::copy_nonoverlapping(64u16.to_le_bytes().as_ptr(), sig_tail.add(10), 2);
                return crate::abi::errno::ERANGE;
            }
            let slots = match vault.slots.lock() {
                Ok(s) => s,
                Err(_) => return ERROR,
            };
            let Some(slot) = &slots[idx] else {
                return EINVAL;
            };
            let digest = core::slice::from_raw_parts(arg.add(6), hash_len);
            let session = match vault.session.lock() {
                Ok(s) => s,
                Err(_) => return ERROR,
            };
            let signature = match session.sign(&Mechanism::Ecdsa, slot.private, digest) {
                Ok(sig) => sig,
                Err(e) => {
                    log::warn!("hsm_key_vault: C_Sign failed: {e}");
                    return ERROR;
                }
            };
            let Ok(mut sig): Result<[u8; 64], _> = signature.as_slice().try_into() else {
                log::warn!(
                    "hsm_key_vault: expected a 64-byte r||s ECDSA signature, got {} bytes",
                    signature.len()
                );
                return ERROR;
            };
            // Contract SIGN output is low-s; the token's raw CKM_ECDSA
            // result is not guaranteed to be.
            normalise_low_s(&mut sig);
            if !sig_out.is_null() {
                core::ptr::copy_nonoverlapping(sig.as_ptr(), sig_out, 64);
            }
            core::ptr::copy_nonoverlapping(64u16.to_le_bytes().as_ptr(), sig_tail.add(10), 2);
            0
        }
        dev_key_vault::DESTROY => {
            let idx = match resolve(vault, handle) {
                Ok(i) => i,
                Err(e) => return e,
            };
            let mut slots = match vault.slots.lock() {
                Ok(s) => s,
                Err(_) => return ERROR,
            };
            let Some(slot) = slots[idx].take() else {
                return 0;
            };
            let session = match vault.session.lock() {
                Ok(s) => s,
                Err(_) => return ERROR,
            };
            release_slot(vault, &session, idx, slot);
            0
        }
        dev_key_vault::DESCRIBE => {
            // arg: [suite_out:u16][usage_out:u32][tier_out:u8][persisted_out:u8]
            if arg.is_null() || arg_len < 8 {
                return EINVAL;
            }
            let idx = match resolve(vault, handle) {
                Ok(i) => i,
                Err(e) => return e,
            };
            let (usage, persisted) = match vault.slots.lock() {
                Ok(s) => s[idx]
                    .as_ref()
                    .map_or((0, false), |slot| (slot.usage, slot.persisted)),
                Err(_) => return ERROR,
            };
            core::ptr::copy_nonoverlapping(
                dev_key_vault::suite::P256.to_le_bytes().as_ptr(),
                arg,
                2,
            );
            core::ptr::copy_nonoverlapping(usage.to_le_bytes().as_ptr(), arg.add(2), 4);
            *arg.add(6) = dev_key_vault::tier::PROCESS_HW;
            // Reported beside the tier and meaning something else: a token
            // object comes back in the next process; a session object does
            // not.
            *arg.add(7) = u8::from(persisted);
            8
        }
        dev_key_vault::OPEN_OR_GENERATE | dev_key_vault::OPEN => {
            open_labelled(vault, opcode, arg, arg_len)
        }
        dev_key_vault::DESTROY_BY_LABEL => destroy_labelled(vault, arg, arg_len),
        _ => ENOSYS,
    }
}
