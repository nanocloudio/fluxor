//! `fluxor-provider-hsm` — the `key_custody` contract over a PKCS#11 token.
//!
//! A host provider: started by `host_lane serves = "key_custody"`, it holds
//! the PKCS#11 module and one logged-in session on the configured token and
//! answers the six custody ops through the lane.
//!
//! - `GENERATE` → `C_GenerateKeyPair` with `CKA_SENSITIVE=true`,
//!   `CKA_EXTRACTABLE=false`: the private key is born inside the token and
//!   never leaves it. A labelled key asked to persist is a pair of token
//!   objects (`CKA_TOKEN=true`); every other key is a pair of session
//!   objects, living as long as this process.
//! - `SIGN` → `C_Sign` with raw `CKM_ECDSA` over the caller's digest; the
//!   64-byte `r ‖ s` is folded into the low-s range. Tokens use random-k,
//!   so signatures verify but do not repeat.
//! - `ECDH` → `C_DeriveKey` with `CKM_ECDH1_DERIVE` (null KDF) into a
//!   throwaway extractable session secret, read and destroyed.
//! - `PUBLIC` → `CKA_EC_POINT`, unwrapped from its DER `OCTET STRING` to the
//!   65-byte SEC1 point.
//! - `FIND` → `C_FindObjects` on the key's token name.
//! - `DESTROY` → free the handle (a session key's objects go with it, a
//!   token key's stay); with `REMOVE`, `C_DestroyObject` on every token
//!   object filed under the key's name.
//!
//! # Names
//!
//! A token key carries two attributes, both halves, created
//! `CKA_MODIFIABLE=false` so nothing on this side can rewrite them:
//!
//! - `CKA_LABEL` is the name: `fluxor-kv/` ‖ the namespace as 8 lowercase
//!   hex digits ‖ `/` ‖ the label as lowercase hex.
//! - `CKA_ID` is the sealed record: `FXVK` ‖ namespace:u32 ‖ suite:u16 ‖
//!   usage:u32, little-endian. The usage is sealed at creation and checked
//!   on every op; a key under the name whose record this provider did not
//!   write is refused (`EACCES`), never generated over.
//!
//! These are the names the in-kernel PKCS#11 backend writes, so a token
//! keeps its keys across the move.
//!
//! # Configuration
//!
//! The argument (`host_lane`'s `args`) is `module=<path>;token=<label>` or
//! `module=<path>;slot=<id>`. The user PIN is read from
//! `FLUXOR_HSM_USER_PIN` and nowhere else — params land in the node image,
//! and a secret does not; the runtime passes it through by its per-provider
//! environment allowlist, with `SOFTHSM2_CONF` for a SoftHSM token store.
//! The token is opened before the provider says `HELLO`, so a provider that
//! cannot reach its token never opens a lane.

#![allow(
    clippy::print_stderr,
    reason = "a provider process reports what it could not do on its stderr, the runtime's"
)]

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use fluxor_abi::contracts::key_custody as kc;
use fluxor_abi::contracts::key_vault::{suite, usage};
use fluxor_abi::errno::{EACCES, EBUSY, EEXIST, EINVAL, ENOENT, ENOMEM, ENOSYS, ERANGE, ERROR};
use fluxor_host_lane::provider::{args, Call, Handler, Identity, Provider};

/// DER of the `secp256r1` named-curve OID `1.2.840.10045.3.1.7`, for
/// `CKA_EC_PARAMS`.
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

/// Keys this provider holds open at once.
const MAX_SLOTS: usize = 16;

/// Magic opening a token key's `CKA_ID` record.
const RECORD_MAGIC: [u8; 4] = *b"FXVK";
/// `FXVK ‖ namespace:u32 ‖ suite:u16 ‖ usage:u32`.
const RECORD_LEN: usize = 14;

/// Fold the `s` half of a raw `r ‖ s` signature into the low-s range.
/// `(r, s)` and `(r, n − s)` verify identically; signatures are public, so
/// no constant-time requirement.
fn normalise_low_s(sig: &mut [u8; 64]) {
    if sig[32..64] <= P256_N_HALF[..] {
        return;
    }
    let mut borrow = 0u8;
    for i in (0..32).rev() {
        let (d, b1) = P256_N[i].overflowing_sub(sig[32 + i]);
        let (d, b2) = d.overflowing_sub(borrow);
        sig[32 + i] = d;
        borrow = u8::from(b1 || b2);
    }
}

/// The `CKA_LABEL` a named key is filed under.
fn token_name(ns: u32, label: &[u8]) -> Vec<u8> {
    use std::fmt::Write;
    let mut s = format!("fluxor-kv/{ns:08x}/");
    for b in label {
        let _ = write!(s, "{b:02x}");
    }
    s.into_bytes()
}

/// A token key's `CKA_ID`.
fn token_record(ns: u32, usage: u32) -> [u8; RECORD_LEN] {
    let mut r = [0u8; RECORD_LEN];
    r[..4].copy_from_slice(&RECORD_MAGIC);
    r[4..8].copy_from_slice(&ns.to_le_bytes());
    r[8..10].copy_from_slice(&suite::P256.to_le_bytes());
    r[10..14].copy_from_slice(&usage.to_le_bytes());
    r
}

/// `(suite, usage)` of a record of `ns`, or `None` for one this provider
/// did not write.
fn parse_record(ns: u32, r: &[u8]) -> Option<(u16, u32)> {
    if r.len() != RECORD_LEN || r[..4] != RECORD_MAGIC || r[4..8] != ns.to_le_bytes() {
        return None;
    }
    Some((
        u16::from_le_bytes([r[8], r[9]]),
        u32::from_le_bytes([r[10], r[11], r[12], r[13]]),
    ))
}

/// One key open for a caller.
struct Key {
    private: ObjectHandle,
    public: ObjectHandle,
    /// The caller that minted the handle: `(slot, generation)`.
    owner: (u16, u32),
    usage: u32,
    ns: u32,
    label: Option<Vec<u8>>,
    /// Token objects: they outlive the process, and freeing the handle
    /// leaves them on the token.
    persisted: bool,
}

struct Hsm {
    session: Session,
    _ctx: Pkcs11,
    keys: [Option<Key>; MAX_SLOTS],
}

/// Which token to bind to.
enum Token {
    Label(String),
    Slot(u64),
}

/// `module=<path>;token=<label>` or `module=<path>;slot=<id>`.
fn parse_args(a: &str) -> Result<(String, Token), String> {
    let mut module = None;
    let mut token = None;
    for kv in a.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| format!("argument {kv:?} is not key=value"))?;
        match k.trim() {
            "module" => module = Some(v.trim().to_string()),
            "token" => token = Some(Token::Label(v.trim().to_string())),
            "slot" => {
                let id = v
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| format!("slot {v:?} is not a number"))?;
                token = Some(Token::Slot(id));
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    let module = module.ok_or("no module=<path>")?;
    let token = token.ok_or("neither token=<label> nor slot=<id>")?;
    Ok((module, token))
}

fn resolve_slot(ctx: &Pkcs11, token: &Token) -> Result<Slot, String> {
    match token {
        Token::Slot(id) => Slot::try_from(*id).map_err(|e| format!("slot id {id}: {e}")),
        Token::Label(label) => {
            let slots = ctx
                .get_slots_with_token()
                .map_err(|e| format!("enumerating PKCS#11 slots: {e}"))?;
            for slot in slots {
                let info = ctx
                    .get_token_info(slot)
                    .map_err(|e| format!("reading token info: {e}"))?;
                if info.label().trim_end() == label {
                    return Ok(slot);
                }
            }
            Err(format!("no PKCS#11 token labelled {label:?}"))
        }
    }
}

fn open(module: &str, token: &Token, pin: &str) -> Result<Hsm, String> {
    let ctx = Pkcs11::new(module).map_err(|e| format!("loading {module}: {e}"))?;
    match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(())
        | Err(cryptoki::error::Error::Pkcs11(
            cryptoki::error::RvError::CryptokiAlreadyInitialized,
            _,
        )) => {}
        Err(e) => return Err(format!("C_Initialize: {e}")),
    }
    let slot = resolve_slot(&ctx, token)?;
    let session = ctx
        .open_rw_session(slot)
        .map_err(|e| format!("opening a session: {e}"))?;
    match session.login(UserType::User, Some(&AuthPin::new(pin.to_owned().into()))) {
        Ok(())
        | Err(cryptoki::error::Error::Pkcs11(cryptoki::error::RvError::UserAlreadyLoggedIn, _)) => {
        }
        Err(e) => return Err(format!("login (check the user PIN): {e}")),
    }
    Ok(Hsm {
        session,
        _ctx: ctx,
        keys: [const { None }; MAX_SLOTS],
    })
}

/// The 65-byte SEC1 point of a public key object; `CKA_EC_POINT` comes as a
/// DER `OCTET STRING` (`04 41 …`) or bare.
fn read_point(session: &Session, public: ObjectHandle) -> Result<[u8; 65], String> {
    let attrs = session
        .get_attributes(public, &[AttributeType::EcPoint])
        .map_err(|e| format!("reading CKA_EC_POINT: {e}"))?;
    let raw = attrs
        .into_iter()
        .find_map(|a| match a {
            Attribute::EcPoint(p) => Some(p),
            _ => None,
        })
        .ok_or("a public key without CKA_EC_POINT")?;
    let sec1: &[u8] = if raw.len() == 67 && raw[0] == 0x04 && raw[1] == 0x41 && raw[2] == 0x04 {
        &raw[2..]
    } else if raw.len() == 65 && raw[0] == 0x04 {
        &raw
    } else {
        return Err(format!(
            "CKA_EC_POINT of {} bytes is not a P-256 point",
            raw.len()
        ));
    };
    let mut out = [0u8; 65];
    out.copy_from_slice(sec1);
    Ok(out)
}

/// Generate a pair: session objects without `name`, token objects filed
/// under `(CKA_LABEL, CKA_ID)` with it. Sensitive and never extractable
/// either way. `(public, private)`.
fn generate_pair(
    session: &Session,
    name: Option<(&[u8], &[u8])>,
) -> Result<(ObjectHandle, ObjectHandle), String> {
    let on_token = name.is_some();
    let mut public = vec![
        Attribute::Token(on_token),
        Attribute::Private(false),
        Attribute::KeyType(KeyType::EC),
        Attribute::Verify(true),
        Attribute::EcParams(SECP256R1_OID_DER.to_vec()),
    ];
    let mut private = vec![
        Attribute::Token(on_token),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
        Attribute::Derive(true),
    ];
    if let Some((label, record)) = name {
        for t in [&mut public, &mut private] {
            t.push(Attribute::Label(label.to_vec()));
            t.push(Attribute::Id(record.to_vec()));
            t.push(Attribute::Modifiable(false));
        }
    }
    session
        .generate_key_pair(&Mechanism::EccKeyPairGen, &public, &private)
        .map_err(|e| format!("C_GenerateKeyPair: {e}"))
}

/// A token key found by name.
struct Found {
    private: ObjectHandle,
    public: ObjectHandle,
    suite: u16,
    usage: u32,
}

/// The token key `(ns, label)` names: `Ok(None)` when none, `EACCES` for one
/// whose record this provider did not write, `ERROR` when the token cannot
/// be searched or the name holds more than one key.
fn find_token_key(session: &Session, ns: u32, label: &[u8]) -> Result<Option<Found>, i32> {
    let name = token_name(ns, label);
    let privs = session
        .find_objects(&[
            Attribute::Token(true),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(name.clone()),
        ])
        .map_err(|e| {
            eprintln!("fluxor-provider-hsm: C_FindObjects: {e}");
            ERROR
        })?;
    let private = match privs.as_slice() {
        [] => return Ok(None),
        [one] => *one,
        many => {
            eprintln!(
                "fluxor-provider-hsm: the token holds {} private keys under one name; refusing to pick",
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
    let Some((suite, usage)) = parse_record(ns, &record) else {
        eprintln!("fluxor-provider-hsm: a token key under a vault name carries no vault record");
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
            eprintln!("fluxor-provider-hsm: C_FindObjects: {e}");
            ERROR
        })?;
    let [public] = pubs.as_slice() else {
        eprintln!(
            "fluxor-provider-hsm: a token key has {} public halves under its name",
            pubs.len()
        );
        return Err(ERROR);
    };
    Ok(Some(Found {
        private,
        public: *public,
        suite,
        usage,
    }))
}

impl Hsm {
    /// Free a key's handle: an unpersisted key's objects go with it.
    fn release(&mut self, idx: usize) {
        if let Some(k) = self.keys[idx].take() {
            if !k.persisted {
                let _ = self.session.destroy_object(k.private);
                let _ = self.session.destroy_object(k.public);
            }
        }
    }

    /// The key `handle` names, if `caller` minted it: `EINVAL` for a value
    /// that is no handle, `ENOENT` for a freed one, `EACCES` for another
    /// caller's; and whether it permits `want`.
    fn resolve(&self, handle: i32, caller: (u16, u32), want: u32) -> Result<usize, i32> {
        let idx = usize::try_from(handle).map_err(|_| EINVAL)?;
        let Some(slot) = self.keys.get(idx) else {
            return Err(EINVAL);
        };
        let Some(k) = slot else {
            return Err(ENOENT);
        };
        if k.owner != caller {
            return Err(EACCES);
        }
        if k.usage & want != want {
            return Err(EACCES);
        }
        Ok(idx)
    }

    fn free_slot(&self) -> Option<usize> {
        self.keys.iter().position(Option::is_none)
    }

    fn named(&self, ns: u32, label: &[u8]) -> Option<usize> {
        self.keys
            .iter()
            .position(|k| matches!(k, Some(k) if k.ns == ns && k.label.as_deref() == Some(label)))
    }

    fn generate(&mut self, caller: (u16, u32), arg: &[u8], out: &mut [u8]) -> (i32, usize) {
        let Some(req) = kc::generate::parse(arg) else {
            return (EINVAL, 0);
        };
        if !kc::generate::usage_ok(&req) {
            return (EINVAL, 0);
        }
        if out.len() < kc::PUB_LEN {
            return (ERANGE, 0);
        }
        let label = req.label.to_vec();
        if !label.is_empty() {
            if self.named(req.ns, &label).is_some() {
                return (EEXIST, 0);
            }
            match find_token_key(&self.session, req.ns, &label) {
                Ok(None) => {}
                Ok(Some(_)) => return (EEXIST, 0),
                Err(e) => return (e, 0),
            }
        }
        let Some(idx) = self.free_slot() else {
            return (ENOMEM, 0);
        };
        let persist = req.usage & usage::PERSIST != 0;
        let name = token_name(req.ns, &label);
        let record = token_record(req.ns, req.usage);
        let (public, private) =
            match generate_pair(&self.session, persist.then_some((&name[..], &record[..]))) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("fluxor-provider-hsm: {e}");
                    return (ERROR, 0);
                }
            };
        let point = match read_point(&self.session, public) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("fluxor-provider-hsm: {e}");
                let _ = self.session.destroy_object(private);
                let _ = self.session.destroy_object(public);
                return (ERROR, 0);
            }
        };
        out[..kc::PUB_LEN].copy_from_slice(&point);
        self.keys[idx] = Some(Key {
            private,
            public,
            owner: caller,
            usage: req.usage,
            ns: req.ns,
            label: (!label.is_empty()).then_some(label),
            persisted: persist,
        });
        (idx as i32, kc::PUB_LEN)
    }

    fn find(&mut self, caller: (u16, u32), arg: &[u8], out: &mut [u8]) -> (i32, usize) {
        let Some((ns, label)) = kc::name::parse(arg) else {
            return (EINVAL, 0);
        };
        if label.is_empty() {
            return (EINVAL, 0);
        }
        if out.len() < kc::find::OUT_LEN {
            return (ERANGE, 0);
        }
        let label = label.to_vec();
        let idx = if let Some(i) = self.named(ns, &label) {
            // One handle per open key: two would each free it.
            if self.keys[i].as_ref().is_some_and(|k| k.owner != caller) {
                return (EBUSY, 0);
            }
            i
        } else {
            let found = match find_token_key(&self.session, ns, &label) {
                Ok(Some(f)) => f,
                Ok(None) => return (ENOENT, 0),
                Err(e) => return (e, 0),
            };
            if found.suite != suite::P256 {
                return (EACCES, 0);
            }
            let Some(i) = self.free_slot() else {
                return (ENOMEM, 0);
            };
            self.keys[i] = Some(Key {
                private: found.private,
                public: found.public,
                owner: caller,
                usage: found.usage,
                ns,
                label: Some(label),
                persisted: true,
            });
            i
        };
        let Some(k) = &self.keys[idx] else {
            return (ERROR, 0);
        };
        let point = match read_point(&self.session, k.public) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("fluxor-provider-hsm: {e}");
                return (ERROR, 0);
            }
        };
        let f = kc::find::Found {
            usage: k.usage,
            persisted: k.persisted,
            public: point,
        };
        match kc::find::encode_found(&f, out) {
            Some(n) => (idx as i32, n),
            None => (ERANGE, 0),
        }
    }

    fn sign(
        &mut self,
        caller: (u16, u32),
        handle: i32,
        arg: &[u8],
        out: &mut [u8],
    ) -> (i32, usize) {
        let idx = match self.resolve(handle, caller, usage::SIGN) {
            Ok(i) => i,
            Err(e) => return (e, 0),
        };
        let Some(digest) = kc::sign::parse(arg) else {
            return (EINVAL, 0);
        };
        if out.len() < kc::SIG_LEN {
            return (ERANGE, 0);
        }
        let Some(k) = &self.keys[idx] else {
            return (ENOENT, 0);
        };
        let sig = match self.session.sign(&Mechanism::Ecdsa, k.private, digest) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("fluxor-provider-hsm: C_Sign: {e}");
                return (ERROR, 0);
            }
        };
        let Ok(mut sig): Result<[u8; 64], _> = sig.as_slice().try_into() else {
            eprintln!(
                "fluxor-provider-hsm: a {}-byte signature, not r‖s",
                sig.len()
            );
            return (ERROR, 0);
        };
        normalise_low_s(&mut sig);
        out[..kc::SIG_LEN].copy_from_slice(&sig);
        (kc::SIG_LEN as i32, kc::SIG_LEN)
    }

    fn ecdh(
        &mut self,
        caller: (u16, u32),
        handle: i32,
        arg: &[u8],
        out: &mut [u8],
    ) -> (i32, usize) {
        let idx = match self.resolve(handle, caller, usage::AGREE) {
            Ok(i) => i,
            Err(e) => return (e, 0),
        };
        let Some(peer) = kc::ecdh::parse(arg) else {
            return (EINVAL, 0);
        };
        if out.len() < kc::SECRET_LEN {
            return (ERANGE, 0);
        }
        // CKM_ECDH1_DERIVE takes the peer as `04 ‖ X ‖ Y`; the bare `X ‖ Y`
        // is accepted too. The token checks the point is on the curve.
        let mut point = [0u8; 65];
        match peer.len() {
            65 if peer[0] == 0x04 => point.copy_from_slice(peer),
            64 => {
                point[0] = 0x04;
                point[1..].copy_from_slice(peer);
            }
            _ => return (EINVAL, 0),
        }
        let Some(k) = &self.keys[idx] else {
            return (ENOENT, 0);
        };
        let template = [
            Attribute::Token(false),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
            Attribute::ValueLen(32.into()),
        ];
        let mechanism = Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null(), &point));
        let derived = match self.session.derive_key(&mechanism, k.private, &template) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("fluxor-provider-hsm: C_DeriveKey (ECDH): {e}");
                return (EINVAL, 0);
            }
        };
        let attrs = self
            .session
            .get_attributes(derived, &[AttributeType::Value]);
        let _ = self.session.destroy_object(derived);
        let mut secret = match attrs {
            Ok(list) => match list.into_iter().find_map(|a| match a {
                Attribute::Value(v) => Some(v),
                _ => None,
            }) {
                Some(v) => v,
                None => return (ERROR, 0),
            },
            Err(e) => {
                eprintln!("fluxor-provider-hsm: reading the derived secret: {e}");
                return (ERROR, 0);
            }
        };
        let r = if secret.len() == kc::SECRET_LEN {
            out[..kc::SECRET_LEN].copy_from_slice(&secret);
            (kc::SECRET_LEN as i32, kc::SECRET_LEN)
        } else {
            (ERROR, 0)
        };
        // The secret crossed this process's memory on its way to the caller;
        // this copy goes now rather than with the allocator.
        secret.fill(0);
        std::hint::black_box(&secret);
        r
    }

    fn public(&mut self, caller: (u16, u32), handle: i32, out: &mut [u8]) -> (i32, usize) {
        let idx = match self.resolve(handle, caller, usage::EXPORT_PUBLIC) {
            Ok(i) => i,
            Err(e) => return (e, 0),
        };
        if out.len() < kc::PUB_LEN {
            return (ERANGE, 0);
        }
        let Some(k) = &self.keys[idx] else {
            return (ENOENT, 0);
        };
        match read_point(&self.session, k.public) {
            Ok(p) => {
                out[..kc::PUB_LEN].copy_from_slice(&p);
                (kc::PUB_LEN as i32, kc::PUB_LEN)
            }
            Err(e) => {
                eprintln!("fluxor-provider-hsm: {e}");
                (ERROR, 0)
            }
        }
    }

    /// Free `handle`; with `REMOVE`, also remove its key from the token and
    /// retire every other handle open on its name.
    fn destroy(&mut self, caller: (u16, u32), handle: i32, arg: &[u8]) -> i32 {
        let Some(flags) = kc::destroy::parse(arg) else {
            return EINVAL;
        };
        let idx = match self.resolve(handle, caller, 0) {
            Ok(i) => i,
            Err(e) => return e,
        };
        if flags & kc::destroy::REMOVE == 0 {
            self.release(idx);
            return 0;
        }
        let Some(k) = &self.keys[idx] else {
            return ENOENT;
        };
        let (ns, label) = (k.ns, k.label.clone());
        let Some(label) = label else {
            // An unnamed key is held nowhere but its handle.
            self.release(idx);
            return 0;
        };
        for i in 0..MAX_SLOTS {
            if matches!(&self.keys[i], Some(k) if k.ns == ns && k.label.as_deref() == Some(&label[..]))
            {
                self.release(i);
            }
        }
        // Both halves and anything else filed under the name: a key whose
        // objects stayed would come back on the next FIND.
        let objects = match self.session.find_objects(&[
            Attribute::Token(true),
            Attribute::Label(token_name(ns, &label)),
        ]) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("fluxor-provider-hsm: C_FindObjects: {e}");
                return ERROR;
            }
        };
        for o in objects {
            if let Err(e) = self.session.destroy_object(o) {
                eprintln!("fluxor-provider-hsm: a token object could not be removed: {e}");
                return ERROR;
            }
        }
        0
    }
}

impl Handler for Hsm {
    fn call(&mut self, call: &Call<'_>, out: &mut [u8]) -> (i32, usize) {
        let caller = (call.caller.slot, call.caller.generation);
        match call.opcode {
            kc::GENERATE => self.generate(caller, call.arg, out),
            kc::FIND => self.find(caller, call.arg, out),
            kc::SIGN => self.sign(caller, call.handle, call.arg, out),
            kc::ECDH => self.ecdh(caller, call.handle, call.arg, out),
            kc::PUBLIC => self.public(caller, call.handle, out),
            kc::DESTROY => (self.destroy(caller, call.handle, call.arg), 0),
            _ => (ENOSYS, 0),
        }
    }

    fn released(&mut self, slot: u16, generation: u32) {
        for i in 0..MAX_SLOTS {
            if self.keys[i]
                .as_ref()
                .is_some_and(|k| k.owner == (slot, generation))
            {
                self.release(i);
            }
        }
    }
}

fn main() {
    let (module, token) = match parse_args(&args()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fluxor-provider-hsm: {e}");
            std::process::exit(2);
        }
    };
    let Ok(pin) = std::env::var("FLUXOR_HSM_USER_PIN") else {
        eprintln!("fluxor-provider-hsm: FLUXOR_HSM_USER_PIN is not in the environment");
        std::process::exit(2);
    };
    let mut hsm = match open(&module, &token, &pin) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("fluxor-provider-hsm: the token is unavailable: {e}");
            std::process::exit(2);
        }
    };
    let id = Identity {
        contracts: &[fluxor_abi::registry::key_custody::ID],
        ports: "",
        requires_caps: &[],
        wants: 0,
    };
    let mut lane = match Provider::connect(&id, fluxor_host_lane::ABI_SURFACE_DIGEST) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("fluxor-provider-hsm: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = lane.serve(&mut hsm) {
        eprintln!("fluxor-provider-hsm: {e}");
        std::process::exit(1);
    }
}
