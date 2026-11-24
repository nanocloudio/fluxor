//! The KEY_VAULT provider every module calls: a router over the kernel
//! software backend and at most one hardware backend.
//!
//! Each handle names the backend that holds its key, and each backend
//! resolves only its own handles, so an operation on a handle goes to that
//! backend and nowhere else. An operation without a handle goes where its
//! suite is served: a hardware backend generates the suites it supports —
//! the identity and attachment-recipient keys — and imports and symmetric
//! keys stay in software.
//!
//! A label names one key across both backends. A lookup of a suite the
//! hardware serves asks software first, then the token, so a key either
//! already holds is the one opened — a software key persisted before the
//! token was configured keeps its identity. Only when neither has it is one
//! made: in the token when it is asked to persist with uses the token can
//! give (a token object is what survives a restart there), in software
//! otherwise, where labels that die with the process have always lived.
//! Every step runs inside the one dispatch, so "is it there?" and "make it"
//! stay one operation. A destroy by label goes to both.
//!
//! Operations that reach a key the call does not name by its handle —
//! opening share envelopes, attesting a key — reach it through the
//! contract's own opcodes on whichever backend holds it. A hardware
//! recipient key agrees an envelope's secret inside its token; that secret
//! crosses only bounded kernel scratch, zeroed on every path, into the
//! software session key the reconstruction makes. The key made is reported
//! as the software custody it is.

use crate::abi::contracts::key_vault as kv;
use crate::abi::errno::{EACCES, EINPROGRESS, EINVAL, ENOENT, ENOMEM, ENOSYS, ERANGE};
use crate::kernel::module::user_span::UserSpan;
use crate::kernel::security::crypto::sha256::Sha256;
use crate::kernel::security::key_share;
use crate::kernel::security::key_vault::{self as software, zeroize};

/// A backend's contract dispatch.
pub type Dispatch = crate::kernel::module::provider::VTableCallFn;

/// Bit set on every index the hardware backend answers: the router's own
/// split of the vault's index space, the software backend's below it.
pub const HARDWARE_FIELD_BIT: i32 = 1 << 24;

static mut HARDWARE: Option<Dispatch> = None;

/// Put a hardware backend behind the router. The software backend stays:
/// it holds what the hardware backend does not.
///
/// # Safety
/// Platform boot, before any module runs.
pub unsafe fn register_hardware(dispatch: Dispatch) {
    HARDWARE = Some(dispatch);
}

fn hardware() -> Option<Dispatch> {
    // SAFETY: written once at platform boot, read-only after.
    unsafe { core::ptr::read(&raw const HARDWARE) }
}

/// Whether `handle` names a key the hardware backend holds.
pub fn is_hardware(handle: i32) -> bool {
    if handle < 0 {
        return false;
    }
    handle & HARDWARE_FIELD_BIT != 0
}

/// The hardware backend's record for `suite`, if it serves it.
fn hardware_record(hw: Dispatch, suite: u16) -> Option<kv::describe_suite::Record> {
    let mut q = kv::describe_suite::encode_cursor(suite);
    if hw(-1, kv::DESCRIBE_SUITE, &mut q, UserSpan::empty()) < 0 {
        return None;
    }
    kv::describe_suite::parse(&q).filter(|r| r.suite == suite)
}

/// The uses the hardware backend permits for `suite`, if it serves it.
fn hardware_usage(hw: Dispatch, suite: u16) -> Option<u32> {
    hardware_record(hw, suite).map(|r| r.usage)
}

/// The backend `handle` names.
fn backend_of(handle: i32) -> Result<Dispatch, i32> {
    if is_hardware(handle) {
        hardware().ok_or(EINVAL)
    } else {
        Ok(software::provider_dispatch)
    }
}

/// KEY_VAULT provider dispatch.
pub fn dispatch(handle: i32, opcode: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32 {
    // SAFETY: kernel context on the scheduler thread, one provider call at
    // a time: the held shares are touched by this call alone.
    unsafe { route(handle, opcode, arg, data) }
}

/// [`dispatch`]'s routing.
///
/// # Safety
/// Kernel context, exclusive access to the held shares.
unsafe fn route(handle: i32, opcode: u32, arg: &mut [u8], mut data: UserSpan<'_>) -> i32 {
    match opcode {
        // The store the software vault persists to, kept by `vault_store`.
        op if crate::abi::internal::vault_store::is_store_op(op) => {
            crate::kernel::security::vault_store::dispatch(op, arg, data)
        }
        kv::SHARE_REWRAP => share_rewrap(handle, arg, data.as_mut()),
        kv::SHARE_COMBINE => share_combine(handle, arg, data.as_slice()),
        kv::ATTEST_KEY => attest_key(handle, arg, data.as_mut()),
        kv::ATTEST_COMPOSITION if is_hardware(handle) => {
            attest_composition(handle, arg, data.as_mut())
        }
        // A key held where its bytes cannot be read cannot be split.
        kv::SHARE_SPLIT if is_hardware(handle) => ENOSYS,
        kv::GENERATE if handle < 0 && arg.len() >= 2 => {
            let suite = u16::from_le_bytes([arg[0], arg[1]]);
            match hardware() {
                Some(hw) if hardware_record(hw, suite).is_some() => hw(handle, opcode, arg, data),
                _ => software::provider_dispatch(handle, opcode, arg, data),
            }
        }
        kv::DESCRIBE_SUITE if handle < 0 => describe_suite(arg),
        kv::OPEN | kv::OPEN_OR_GENERATE if handle < 0 && arg.len() >= kv::open::HEADER => {
            open_by_label(handle, opcode, arg, data)
        }
        kv::DESTROY_BY_LABEL if handle < 0 => {
            let sw = software::provider_dispatch(handle, opcode, arg, data.reborrow());
            // A workload's labels are its realm's, which only software keeps.
            let Some(hw) = hardware().filter(|_| !software::caller_in_workload()) else {
                return sw;
            };
            let hw = hw(handle, opcode, arg, data);
            // A refusal from either is the answer, so a key one backend
            // could not remove is never reported gone.
            if sw < 0 && sw != ENOENT {
                sw
            } else if hw < 0 && hw != ENOENT {
                hw
            } else if sw == 0 || hw == 0 {
                0
            } else {
                ENOENT
            }
        }
        // The custody of the backend that holds the identity keys a node
        // attests with; each key's own custody is its `DESCRIBE`.
        kv::CUSTODY => match hardware() {
            Some(hw) => hw(handle, opcode, arg, data),
            None => software::provider_dispatch(handle, opcode, arg, data),
        },
        _ => match backend_of(handle) {
            Ok(b) => b(handle, opcode, arg, data),
            Err(e) => e,
        },
    }
}

/// `DESCRIBE_SUITE` across both backends: from the cursor, the lower of the
/// two backends' next suites, the hardware's record where both serve one
/// (it is the backend `GENERATE` sends that suite to).
fn describe_suite(arg: &mut [u8]) -> i32 {
    use kv::describe_suite as ds;
    let Some(cursor) = ds::parse_cursor(arg) else {
        return EINVAL;
    };
    if arg.len() < ds::LEN {
        return EINVAL;
    }
    let sw = software::suite_record(cursor);
    let hw = hardware().and_then(|hw| {
        let mut q = ds::encode_cursor(cursor);
        (hw(-1, kv::DESCRIBE_SUITE, &mut q, UserSpan::empty()) >= 0)
            .then(|| ds::parse(&q))
            .flatten()
    });
    let pick = match (sw, hw) {
        (Some(s), Some(h)) if h.suite <= s.suite => Some(h),
        (Some(s), _) => Some(s),
        (None, h) => h,
    };
    match pick {
        Some(mut r) => {
            r.next = r.suite + 1;
            arg[..ds::LEN].copy_from_slice(&ds::encode(&r));
            ds::LEN as i32
        }
        None => ENOENT,
    }
}

/// `OPEN` / `OPEN_OR_GENERATE` across both backends (a workload's: software
/// alone): software first, then the token, then — for `OPEN_OR_GENERATE`
/// with neither holding the key — made in the token if it is asked to
/// persist with uses the token permits, in software otherwise. Any answer
/// other than `ENOENT` (the key itself, or `EBUSY`, `EACCES`, `EAGAIN`,
/// `ERANGE`, ...) is final: a key that exists somewhere is never made again
/// somewhere else. `arg` holds at least the open header.
fn open_by_label(handle: i32, opcode: u32, arg: &mut [u8], mut data: UserSpan<'_>) -> i32 {
    // A workload's labels live in its realm (its owner uid), which only
    // the software backend keeps: a token names a label by module type and
    // nothing narrower, so a workload reaching it would reach the node's
    // keys of its type, and every other workload's.
    if software::caller_in_workload() {
        return software::provider_dispatch(handle, opcode, arg, data);
    }
    let suite = u16::from_le_bytes([arg[0], arg[1]]);
    let usage = u32::from_le_bytes([arg[2], arg[3], arg[4], arg[5]]);
    let Some((hw, hw_usage)) = hardware().and_then(|hw| hardware_usage(hw, suite).map(|u| (hw, u)))
    else {
        return software::provider_dispatch(handle, opcode, arg, data);
    };
    let rc = software::provider_dispatch(handle, kv::OPEN, arg, data.reborrow());
    if rc != ENOENT {
        return rc;
    }
    let rc = hw(handle, kv::OPEN, arg, data.reborrow());
    if rc != ENOENT || opcode == kv::OPEN {
        return rc;
    }
    // A use the token cannot give (WRAP: its key's bytes are nowhere to
    // wrap) keeps the key in software rather than refusing it.
    if usage & kv::usage::PERSIST != 0 && usage & !hw_usage == 0 {
        hw(handle, opcode, arg, data)
    } else {
        software::provider_dispatch(handle, opcode, arg, data)
    }
}

/// Call `op` on `handle` in the backend that holds it, with `data` as the
/// call's span: the key ops the share and attestation paths make
/// (`DESCRIBE`, `PUBLIC`, `ECDH`, `SIGN`), each of which [`route`] sends to
/// that backend unchanged. Going to the backend directly keeps the router
/// from calling itself, so its depth is bounded.
///
/// # Safety
/// As [`route`].
unsafe fn call(handle: i32, op: u32, arg: &mut [u8], data: &mut [u8]) -> i32 {
    match backend_of(handle) {
        Ok(backend) => backend(handle, op, arg, UserSpan::of(data)),
        Err(e) => e,
    }
}

/// What `DESCRIBE` says of a key.
unsafe fn describe(handle: i32) -> Result<kv::describe::Described, i32> {
    let mut d = [0u8; kv::describe::ARG_LEN];
    let rc = call(handle, kv::DESCRIBE, &mut d, &mut []);
    if rc < 0 {
        return Err(rc);
    }
    kv::describe::parse(&d).ok_or(EINVAL)
}

/// A P-256 key's public half.
unsafe fn p256_public(handle: i32) -> Result<[u8; 65], i32> {
    let mut out = [0u8; 65];
    let mut arg = [0u8; kv::public::ARG_LEN];
    let rc = call(handle, kv::PUBLIC, &mut arg, &mut out);
    if rc < 0 {
        return Err(rc);
    }
    if rc != 65 {
        return Err(EINVAL);
    }
    Ok(out)
}

/// ECDH on `opener`, in whichever backend holds it, against `peer`, with
/// the opener's public key: the agreement a share envelope opens under.
/// The shared secret lands in `shared` and nowhere else.
unsafe fn agree(opener: i32, peer: &[u8], shared: &mut [u8; 32]) -> Result<[u8; 65], i32> {
    let public = p256_public(opener)?;
    if peer.len() > key_share::PEER_MAX {
        return Err(EINVAL);
    }
    let mut buf = [0u8; key_share::PEER_MAX];
    buf[..peer.len()].copy_from_slice(peer);
    let mut arg = kv::ecdh::encode(peer.len() as u32);
    let n = peer.len().max(32);
    let rc = call(opener, kv::ECDH, &mut arg, &mut buf[..n]);
    if rc != 32 {
        zeroize(&mut buf);
        zeroize(shared);
        return Err(if rc < 0 { rc } else { EINVAL });
    }
    shared.copy_from_slice(&buf[..32]);
    zeroize(&mut buf);
    Ok(public)
}

/// Open `envelope` with `opener`: the share's index and `y`.
unsafe fn open_share(opener: i32, envelope: &[u8], y: &mut [u8; 32]) -> Result<u8, i32> {
    if !key_share::well_formed(envelope) {
        return Err(EINVAL);
    }
    let mut shared = [0u8; 32];
    let public = agree(opener, key_share::encapsulation(envelope), &mut shared)?;
    let opened = key_share::open(envelope, &shared, &public, y);
    zeroize(&mut shared);
    opened.map_err(|e| match e {
        key_share::OpenError::NotRecipient => EACCES,
        key_share::OpenError::Malformed => EINVAL,
    })
}

/// # Safety
/// As [`route`].
unsafe fn share_rewrap(opener: i32, args: &[u8], data: &mut [u8]) -> i32 {
    use kv::share::{self as sh, rewrap as a};
    if args.len() < a::ARG_LEN || data.len() < sh::P256_LEN {
        return EINVAL;
    }
    let grant = key_share::Grant::read(&args[..sh::grant::LEN]);
    if !grant.valid() {
        return EINVAL;
    }
    let mut envelope = [0u8; sh::P256_LEN];
    envelope.copy_from_slice(&data[..sh::P256_LEN]);
    let recipient = &args[a::RECIPIENT..a::RECIPIENT + sh::P256_PUB_LEN];
    let mut y = [0u8; 32];
    let index = match open_share(opener, &envelope, &mut y) {
        Ok(ix) => ix,
        Err(e) => return e,
    };
    if let Err(e) = unexpired(&envelope) {
        zeroize(&mut y);
        return e;
    }
    // What the share IS stays with it: its set, resource, epoch and AEAD.
    let carried = grant.carrying(&envelope);
    let mut out = [0u8; sh::P256_LEN];
    let sealed = match anti_replay_id() {
        Some(id) => key_share::seal(&mut out, &carried.binding(), index, &y, recipient, &id),
        None => false,
    };
    zeroize(&mut y);
    if !sealed {
        return EINVAL;
    }
    data[..sh::P256_LEN].copy_from_slice(&out);
    sh::P256_LEN as i32
}

/// A fresh anti-replay id.
fn anti_replay_id() -> Option<[u8; 16]> {
    let mut id = [0u8; 16];
    (crate::kernel::sys::hal::csprng_fill(&mut id) == 0).then_some(id)
}

/// `Ok` when an envelope has no expiry or has not reached it. An expiry
/// with no wall clock, or a clock the platform knows is unsynchronised, is
/// refused: the grant cannot be checked, and an unchecked grant is not one.
fn unexpired(envelope: &[u8]) -> Result<(), i32> {
    let expiry = key_share::field_u64(envelope, kv::share::EXPIRY);
    if expiry == 0 {
        return Ok(());
    }
    let now = crate::kernel::sys::hal::now_unix_millis();
    if now == 0
        || matches!(
            crate::kernel::sys::hal::clock_sync_status(),
            Some((false, _))
        )
    {
        return Err(EACCES);
    }
    if now >= expiry {
        Err(EACCES)
    } else {
        Ok(())
    }
}

// ── Reconstruction, one envelope per call ───────────────────────────────
//
// `SHARE_COMBINE` opens one envelope per call. The first share is held here
// for its caller — inside the vault, never written out — until the second
// arrives, a refusal drops it, or its caller's occupancy ends.

/// Callers that may hold a first share at once.
const MAX_HELD: usize = 4;

struct HeldShare {
    /// The caller, `(scheduler slot, occupancy)`; `None` for a free entry.
    owner: Option<(crate::kernel::exec::scheduler::ModuleId, u32)>,
    /// The envelope's header fields a second share must match: set id,
    /// resource, epoch, AEAD.
    set_id: [u8; 16],
    resource: [u8; 16],
    epoch: [u8; 4],
    aead: [u8; 2],
    /// The call's target, which the second call must repeat.
    suite: u16,
    usage: u32,
    anti_replay: [u8; 16],
    index: u8,
    y: [u8; 32],
}

impl HeldShare {
    const fn empty() -> Self {
        Self {
            owner: None,
            set_id: [0; 16],
            resource: [0; 16],
            epoch: [0; 4],
            aead: [0; 2],
            suite: 0,
            usage: 0,
            anti_replay: [0; 16],
            index: 0,
            y: [0; 32],
        }
    }

    fn clear(&mut self) {
        zeroize(&mut self.y);
        *self = Self::empty();
    }
}

static mut HELD: [HeldShare; MAX_HELD] = [const { HeldShare::empty() }; MAX_HELD];

/// # Safety
/// As [`route`].
unsafe fn share_combine(opener: i32, args: &[u8], env: &[u8]) -> i32 {
    let held = &mut *core::ptr::addr_of_mut!(HELD);
    let who = software::caller_owner();
    // Shares held for occupancies that have ended are nobody's.
    for h in held.iter_mut() {
        if let Some((slot, generation)) = h.owner {
            if !software::owner_is_live(slot, generation) {
                h.clear();
            }
        }
    }
    let mine = held.iter().position(|h| h.owner == Some(who));
    let rc = combine_step(opener, args, env, who, mine);
    // A refusal drops the share held; a reconstruction spends it.
    if rc != EINPROGRESS {
        if let Some(m) = mine {
            held[m].clear();
        }
    }
    rc
}

/// One `SHARE_COMBINE` call: hold the first share (`EINPROGRESS`), or
/// reconstruct from the share held and this one.
///
/// # Safety
/// As [`route`].
unsafe fn combine_step(
    opener: i32,
    args: &[u8],
    env: &[u8],
    who: (crate::kernel::exec::scheduler::ModuleId, u32),
    mine: Option<usize>,
) -> i32 {
    use kv::share::{self as sh, combine as a};
    let held = &mut *core::ptr::addr_of_mut!(HELD);
    if args.len() < a::ARG_LEN {
        return EINVAL;
    }
    let suite = u16::from_le_bytes([args[a::TARGET_SUITE], args[a::TARGET_SUITE + 1]]);
    let usage = u32::from_le_bytes([
        args[a::TARGET_USAGE],
        args[a::TARGET_USAGE + 1],
        args[a::TARGET_USAGE + 2],
        args[a::TARGET_USAGE + 3],
    ]);
    if !software::session_key_admissible(suite, usage) {
        return EINVAL;
    }
    if !key_share::well_formed(env) {
        return EINVAL;
    }
    if env[sh::RESOURCE..sh::RESOURCE + 16] != args[a::RESOURCE..a::RESOURCE + 16]
        || env[sh::EPOCH..sh::EPOCH + 4] != args[a::EPOCH..a::EPOCH + 4]
    {
        return EACCES;
    }
    if let Err(e) = unexpired(env) {
        return e;
    }
    if key_share::consumed(&env[sh::ANTI_REPLAY..sh::ANTI_REPLAY + 16]) {
        return EACCES;
    }
    // The second share must be another share of the key the first is of:
    // same set, resource, epoch and AEAD, and the same target. Checked on
    // the header before anything opens; the open authenticates the header.
    let pairs = mine.map(|m| {
        let h = &held[m];
        h.set_id[..] == env[sh::SET_ID..sh::SET_ID + 16]
            && h.resource[..] == env[sh::RESOURCE..sh::RESOURCE + 16]
            && h.epoch[..] == env[sh::EPOCH..sh::EPOCH + 4]
            && h.aead[..] == env[sh::AEAD..sh::AEAD + 2]
            && h.suite == suite
            && h.usage == usage
    });
    if pairs == Some(true) && held[mine.unwrap_or(0)].index == env[sh::INDEX] {
        return EINVAL;
    }
    let mut y = [0u8; 32];
    let index = match open_share(opener, env, &mut y) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let Some(m) = mine.filter(|_| pairs == Some(true)) else {
        // A first share, or one of another set than the share held: held,
        // replacing whatever this caller held.
        let slot = match mine.or_else(|| held.iter().position(|h| h.owner.is_none())) {
            Some(s) => s,
            None => {
                zeroize(&mut y);
                return ENOMEM;
            }
        };
        let h = &mut held[slot];
        h.clear();
        h.owner = Some(who);
        h.set_id.copy_from_slice(&env[sh::SET_ID..sh::SET_ID + 16]);
        h.resource
            .copy_from_slice(&env[sh::RESOURCE..sh::RESOURCE + 16]);
        h.epoch.copy_from_slice(&env[sh::EPOCH..sh::EPOCH + 4]);
        h.aead.copy_from_slice(&env[sh::AEAD..sh::AEAD + 2]);
        h.suite = suite;
        h.usage = usage;
        h.anti_replay
            .copy_from_slice(&env[sh::ANTI_REPLAY..sh::ANTI_REPLAY + 16]);
        h.index = index;
        h.y = y;
        zeroize(&mut y);
        return EINPROGRESS;
    };
    let first = &held[m];
    if key_share::consumed(&first.anti_replay) {
        zeroize(&mut y);
        return EACCES;
    }
    let mut key = [0u8; 32];
    let combined = key_share::combine(first.index, &first.y, index, &y, &mut key);
    zeroize(&mut y);
    if combined.is_none() {
        zeroize(&mut key);
        return EINVAL;
    }
    let handle = software::import_session_key(suite, usage, &key);
    zeroize(&mut key);
    if handle >= 0 {
        key_share::consume(&first.anti_replay);
        key_share::consume(&env[sh::ANTI_REPLAY..sh::ANTI_REPLAY + 16]);
    }
    handle
}

/// # Safety
/// As [`route`].
unsafe fn attest_key(subject: i32, args: &[u8], out: &mut [u8]) -> i32 {
    use kv::attest_key as a;
    if args.len() < a::ARG_LEN {
        return EINVAL;
    }
    let d = match describe(subject) {
        Ok(d) => d,
        Err(e) => return e,
    };
    if out.len() < a::RECORD_LEN {
        return ERANGE;
    }
    let mut record = [0u8; a::RECORD_LEN];
    record[..4].copy_from_slice(&a::MAGIC);
    record[a::R_CHALLENGE..a::R_CHALLENGE + 32].copy_from_slice(&args[..32]);
    record[a::R_CUSTODY] = d.custody;
    record[a::R_PERSISTED] = u8::from(d.persisted != kv::persisted::NO);
    record[a::R_SUITE..a::R_SUITE + 2].copy_from_slice(&d.suite.to_le_bytes());
    record[a::R_USAGE..a::R_USAGE + 4].copy_from_slice(&d.usage.to_le_bytes());
    if is_hardware(subject) {
        // The token holds the key where no commitment can be computed; the
        // public half identifies it.
        record[a::R_BACKEND] = a::backend::PKCS11;
        record[a::R_NAMESPACE..a::R_NAMESPACE + 4]
            .copy_from_slice(&software::caller_namespace().to_le_bytes());
        if d.usage & kv::usage::EXPORT_PUBLIC != 0 {
            match p256_public(subject) {
                Ok(p) => {
                    let mut h = Sha256::new();
                    h.update(&p);
                    record[a::R_THUMBPRINT..a::R_THUMBPRINT + 32].copy_from_slice(&h.finalize());
                }
                Err(e) => return e,
            }
        }
    } else {
        record[a::R_BACKEND] = a::backend::KERNEL;
        let Some(facts) = software::attestable(subject) else {
            return ENOSYS;
        };
        record[a::R_NAMESPACE..a::R_NAMESPACE + 4].copy_from_slice(&facts.namespace.to_le_bytes());
        record[a::R_COMMITMENT..a::R_COMMITMENT + 32].copy_from_slice(&facts.commitment);
        record[a::R_THUMBPRINT..a::R_THUMBPRINT + 32].copy_from_slice(&facts.public_thumbprint);
    }
    let Some(composition) = software::composition_digest(d.custody) else {
        return ENOMEM;
    };
    record[a::R_COMPOSITION..a::R_COMPOSITION + 32].copy_from_slice(&composition);
    out[..a::RECORD_LEN].copy_from_slice(&record);
    a::RECORD_LEN as i32
}

/// `ATTEST_COMPOSITION` with a hardware signer: the kernel's composition
/// record, ending in the hardware custody, its SHA-256 signed inside the token.
///
/// # Safety
/// As [`route`].
unsafe fn attest_composition(signer: i32, args: &mut [u8], out: &mut [u8]) -> i32 {
    use kv::attest_composition as a;
    if args.len() < a::ARG_LEN {
        return EINVAL;
    }
    let d = match describe(signer) {
        Ok(d) => d,
        Err(e) => return e,
    };
    if d.usage & kv::usage::SIGN == 0 {
        return EACCES;
    }
    // The composition record is longer than any signer takes whole, so a
    // hardware signer signs its digest; a token signs P-256 only.
    if d.suite != kv::suite::P256 {
        return ENOSYS;
    }
    let sig_len = software::signature_len(d.suite);
    let Some(challenge) = a::parse(args) else {
        return EINVAL;
    };
    let Some(record) = software::composition_record(&challenge, d.custody) else {
        return ENOMEM;
    };
    let need = record.len() + sig_len;
    if out.len() < need {
        a::set_len(args, need);
        return ERANGE;
    }
    let mut h = Sha256::new();
    h.update(record);
    let digest = h.finalize();
    let sig = &mut out[record.len()..need];
    sig[..32].copy_from_slice(&digest);
    let mut sa = kv::sign::encode(kv::sign_mode::DIGEST, 32);
    let rc = call(signer, kv::SIGN, &mut sa, sig);
    if rc < 0 {
        return rc;
    }
    out[..record.len()].copy_from_slice(record);
    (record.len() + rc as usize) as i32
}
