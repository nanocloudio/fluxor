//! PKCS#11 (HSM/token) `key_vault` backend — Linux platform.
//!
//! Registers as the KEY_VAULT provider (class dispatch + vtable, see the
//! registration note in `kernel/syscalls.rs`) when a token is configured,
//! overriding the kernel software backend. Maps the vault opcodes onto
//! PKCS#11 (rfc_crypto_extensions §4.3):
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
//!   software backend — consumers verify, they don't byte-compare
//!   (RFC §6.3).
//! - `ECDH` → `C_DeriveKey` with `CKM_ECDH1_DERIVE` (CKD_NULL KDF): the
//!   32-byte X coordinate lands in a throwaway extractable session
//!   secret, is copied to the caller per the contract, and the object
//!   is destroyed. `ALG_P256` in CAPS covers ECDSA *and* ECDH, so a
//!   backend advertising it must implement both.
//! - `PUBLIC` → read `CKA_EC_POINT` (DER OCTET STRING unwrapped to the
//!   65-byte SEC1 point).
//! - `VERIFY` → delegated to the kernel software implementation: it takes
//!   a caller-supplied public key and touches no custodial material.
//! - `STORE` → `ENOSYS`. A non-extractable token cannot import an
//!   external private key; CAPS clears `STORE_IMPORT` so consumers know
//!   to use `GENERATE` (RFC §6.2).
//! - `TIER` → `PROCESS_HW`: a host process talking to a token isolates
//!   the key from host-memory compromise to the extent the token does.
//!
//! CAPS advertises `GENERATE | PUBLIC | NON_EXTRACTABLE | ALG_P256` only:
//! this backend is P-256-scoped, so `ALG_ED25519` reads 0 here per the
//! CAPS discipline — a consumer that needs EdDSA sees the bit clear and
//! falls back per its own policy.
//!
//! Generated keys are *session* objects (`CKA_TOKEN=false`): vault slots
//! are per-run (the software backend wipes on scheduler reset), so
//! persistent token objects would leak one keypair per boot. A
//! bind-existing-key op is a contract extension for a future workload.
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
use crate::abi::errno::{EINVAL, ENOMEM, ENOSYS, ERROR};
use crate::kernel::fd;
use crate::kernel::provider;

/// DER encoding of the `secp256r1` (NIST P-256, a.k.a. `prime256v1`)
/// named-curve OID `1.2.840.10045.3.1.7`, as required for `CKA_EC_PARAMS`.
const SECP256R1_OID_DER: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// P-256 raw-scalar key type (contract `key_type` byte 1) — the only
/// algorithm this backend implements.
const KEY_TYPE_P256_SCALAR: u8 = 1;

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

/// Same slot count as the software backend: the vault contract exposes a
/// small fixed handle space, not the token's whole object store.
const MAX_SLOTS: usize = 8;

/// CAPS bitmap: what this backend actually does — and, as importantly,
/// what it doesn't (`STORE_IMPORT` and `ALG_ED25519` read 0).
const HSM_CAPS: u32 = dev_key_vault::caps::GENERATE
    | dev_key_vault::caps::PUBLIC
    | dev_key_vault::caps::NON_EXTRACTABLE
    | dev_key_vault::caps::ALG_P256;

/// One generated keypair living inside the token.
struct HsmSlot {
    private: ObjectHandle,
    public: ObjectHandle,
}

/// The process-wide backend state, initialised once at platform boot.
struct HsmVault {
    /// `Session` is `!Sync`; the mutex serialises token access and holds
    /// the login for the process lifetime.
    session: Mutex<Session>,
    /// Keeps the loaded PKCS#11 library alive as long as the session.
    _ctx: Pkcs11,
    slots: Mutex<[Option<HsmSlot>; MAX_SLOTS]>,
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
    })
}

/// Activate the PKCS#11 backend if the environment configures one:
/// override the KEY_VAULT registration on *both* dispatch paths (class
/// byte + vtable — see `kernel/syscalls.rs`). Returns `true` when the
/// override happened; on `false` the kernel software default stays live
/// (a consumer requiring hardware sees `TIER = SOFTWARE` and refuses —
/// the vault never silently overclaims).
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
    provider::register(provider::contract::KEY_VAULT, hsm_key_vault_dispatch);
    provider::register_vtable(&HSM_KEY_VAULT_VTABLE);
    log::info!("hsm_key_vault: PKCS#11 backend registered (module {module}, TIER=PROCESS_HW)");
    true
}

static HSM_KEY_VAULT_VTABLE: provider::ProviderVTable = provider::ProviderVTable {
    contract: provider::contract::KEY_VAULT,
    call: hsm_key_vault_dispatch,
    query: None,
    default_close_op: dev_key_vault::DESTROY,
};

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

/// Untag and range-check a slot-bound handle.
fn slot_index(handle: i32) -> Option<usize> {
    if handle < 0 {
        return None;
    }
    let (tag, slot) = fd::untag_fd(handle);
    if tag != fd::FD_TAG_KEY_VAULT || slot < 0 || (slot as usize) >= MAX_SLOTS {
        return None;
    }
    Some(slot as usize)
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
        dev_key_vault::CAPS => {
            if arg.is_null() || arg_len < 4 {
                return EINVAL;
            }
            let bytes = HSM_CAPS.to_le_bytes();
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), arg, 4);
            4
        }
        dev_key_vault::TIER => {
            if arg.is_null() || arg_len < 1 {
                return EINVAL;
            }
            *arg = dev_key_vault::tier::PROCESS_HW;
            1
        }
        // Import is unavailable against a non-extractable token; CAPS
        // clears STORE_IMPORT so consumers already know (RFC §6.2).
        dev_key_vault::STORE => ENOSYS,
        dev_key_vault::ECDH => {
            // arg layout: [peer_pub_len:u16][pad:u16][peer_pub[len]][out[32]]
            if arg.is_null() || arg_len < 4 {
                return EINVAL;
            }
            let Some(idx) = slot_index(handle) else {
                return EINVAL;
            };
            let peer_len = u16::from_le_bytes([*arg, *arg.add(1)]) as usize;
            if peer_len == 0 || peer_len > 65 || 4 + peer_len + 32 > arg_len {
                return EINVAL;
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
                core::ptr::copy_nonoverlapping(secret.as_ptr(), arg.add(4 + peer_len), 32);
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
            crate::kernel::key_vault::provider_dispatch(handle, opcode, arg, arg_len)
        }
        dev_key_vault::GENERATE => {
            // arg layout: [key_type:u8][flags:u8][pad:u16][pub_out[65]]
            if arg.is_null() || arg_len < 4 {
                return EINVAL;
            }
            let key_type = *arg;
            if key_type != KEY_TYPE_P256_SCALAR {
                // ES256-scoped backend: ALG_ED25519 reads 0 in CAPS.
                return EINVAL;
            }
            if 4 + 65 > arg_len {
                return EINVAL;
            }
            let mut slots = match vault.slots.lock() {
                Ok(s) => s,
                Err(_) => return ERROR,
            };
            let Some(idx) = slots.iter().position(Option::is_none) else {
                return ENOMEM;
            };
            let session = match vault.session.lock() {
                Ok(s) => s,
                Err(_) => return ERROR,
            };
            // The private key is sensitive + non-extractable regardless
            // of the flags byte: this backend has nothing weaker to
            // offer, and CAPS NON_EXTRACTABLE advertises the guarantee.
            // Session objects (Token=false): vault slots are per-run.
            let pub_template = [
                Attribute::Token(false),
                Attribute::Private(false),
                Attribute::KeyType(KeyType::EC),
                Attribute::Verify(true),
                Attribute::EcParams(SECP256R1_OID_DER.to_vec()),
            ];
            let priv_template = [
                Attribute::Token(false),
                Attribute::Private(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Sign(true),
                // ECDH (CKM_ECDH1_DERIVE) needs CKA_DERIVE; many tokens
                // default it to false.
                Attribute::Derive(true),
            ];
            let (public, private) = match session.generate_key_pair(
                &Mechanism::EccKeyPairGen,
                &pub_template,
                &priv_template,
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    log::warn!("hsm_key_vault: C_GenerateKeyPair failed: {e}");
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
            core::ptr::copy_nonoverlapping(point.as_ptr(), arg.add(4), 65);
            slots[idx] = Some(HsmSlot { private, public });
            fd::tag_fd(fd::FD_TAG_KEY_VAULT, idx as i32)
        }
        dev_key_vault::PUBLIC => {
            // arg layout: [pub_out[65]]
            if arg.is_null() || arg_len < 65 {
                return EINVAL;
            }
            let Some(idx) = slot_index(handle) else {
                return EINVAL;
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
            match read_public_point(&session, slot.public) {
                Ok(point) => {
                    core::ptr::copy_nonoverlapping(point.as_ptr(), arg, 65);
                    0
                }
                Err(e) => {
                    log::warn!("hsm_key_vault: {e}");
                    ERROR
                }
            }
        }
        dev_key_vault::SIGN => {
            // arg layout: [hash_len:u16][pad:u16][hash[hash_len]][sig_out[64]]
            if arg.is_null() || arg_len < 4 {
                return EINVAL;
            }
            let Some(idx) = slot_index(handle) else {
                return EINVAL;
            };
            let hash_len = u16::from_le_bytes([*arg, *arg.add(1)]) as usize;
            if hash_len == 0 || hash_len > 64 || 4 + hash_len + 64 > arg_len {
                return EINVAL;
            }
            let slots = match vault.slots.lock() {
                Ok(s) => s,
                Err(_) => return ERROR,
            };
            let Some(slot) = &slots[idx] else {
                return EINVAL;
            };
            let digest = core::slice::from_raw_parts(arg.add(4), hash_len);
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
            core::ptr::copy_nonoverlapping(sig.as_ptr(), arg.add(4 + hash_len), 64);
            0
        }
        dev_key_vault::DESTROY => {
            let Some(idx) = slot_index(handle) else {
                return EINVAL;
            };
            let mut slots = match vault.slots.lock() {
                Ok(s) => s,
                Err(_) => return ERROR,
            };
            let Some(slot) = slots[idx].take() else {
                // Matches the software backend: destroying a free slot
                // is a no-op success.
                return 0;
            };
            let session = match vault.session.lock() {
                Ok(s) => s,
                Err(_) => return ERROR,
            };
            let _ = session.destroy_object(slot.private);
            let _ = session.destroy_object(slot.public);
            0
        }
        _ => ENOSYS,
    }
}
