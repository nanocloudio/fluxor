//! The KEY_VAULT provider every module calls: a router over the kernel
//! software backend and at most one hardware backend.
//!
//! Each handle names the backend that holds its key, and each backend
//! resolves only its own handles, so an operation on a handle goes to that
//! backend and nowhere else. An operation without a handle goes where its
//! suite is served: a hardware backend generates the suites it supports —
//! the identity and attachment-recipient keys — and labels, imports and
//! symmetric keys stay in software.
//!
//! Operations that span keys — opening share envelopes, attesting a key —
//! reach each key through the contract's own opcodes on whichever backend
//! holds it. A hardware recipient key agrees an envelope's secret inside its
//! token; that secret crosses only bounded kernel scratch, zeroed on every
//! path, into the software session key the reconstruction makes. The key
//! made is reported as the software tier it is.

use crate::abi::contracts::key_vault as kv;
use crate::abi::errno::{EACCES, EINVAL, ENOMEM, ENOSYS, ERANGE, ERROR};
use crate::kernel::ipc::fd;
use crate::kernel::security::crypto::sha256::Sha256;
use crate::kernel::security::key_share;
use crate::kernel::security::key_vault::{self as software, zeroize};

/// A backend's contract dispatch.
pub type Dispatch = unsafe fn(i32, u32, *mut u8, usize) -> i32;

/// Handle-field bit set on every handle the hardware backend mints.
pub const HARDWARE_FIELD_BIT: i32 = 1 << 25;

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
    let (tag, field) = fd::untag_fd(handle);
    tag == fd::FD_TAG_KEY_VAULT && field & HARDWARE_FIELD_BIT != 0
}

/// Whether the hardware backend serves `suite`.
unsafe fn hardware_serves(hw: Dispatch, suite: u16) -> bool {
    let mut q = [0u8; 14];
    q[..2].copy_from_slice(&suite.to_le_bytes());
    hw(-1, kv::SUITE_QUERY, q.as_mut_ptr(), q.len()) >= 0
}

/// The backend `handle` names.
unsafe fn backend_of(handle: i32) -> Result<Dispatch, i32> {
    if is_hardware(handle) {
        hardware().ok_or(EINVAL)
    } else {
        Ok(software::provider_dispatch)
    }
}

/// KEY_VAULT provider dispatch.
///
/// # Safety
/// `arg` valid for `arg_len` bytes, as each opcode's layout requires.
pub unsafe fn dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    match opcode {
        kv::SHARE_REWRAP => share_rewrap(handle, arg, arg_len),
        kv::SHARE_COMBINE => share_combine(arg, arg_len),
        kv::ATTEST_KEY => attest_key(handle, arg, arg_len),
        kv::ATTEST_COMPOSITION if is_hardware(handle) => attest_composition(handle, arg, arg_len),
        // A key held where its bytes cannot be read cannot be split.
        kv::SHARE_SPLIT if is_hardware(handle) => ENOSYS,
        kv::GENERATE | kv::SUITE_QUERY if handle < 0 && arg_len >= 2 && !arg.is_null() => {
            let suite = u16::from_le_bytes([*arg, *arg.add(1)]);
            match hardware() {
                Some(hw) if hardware_serves(hw, suite) => hw(handle, opcode, arg, arg_len),
                _ => software::provider_dispatch(handle, opcode, arg, arg_len),
            }
        }
        // The tier of the backend that holds the identity keys a node
        // attests with; each key's own custody is its `DESCRIBE`.
        kv::TIER => match hardware() {
            Some(hw) => hw(handle, opcode, arg, arg_len),
            None => software::provider_dispatch(handle, opcode, arg, arg_len),
        },
        _ => match backend_of(handle) {
            Ok(b) => b(handle, opcode, arg, arg_len),
            Err(e) => e,
        },
    }
}

/// Call `op` on `handle` through the router.
unsafe fn call(handle: i32, op: u32, arg: &mut [u8]) -> i32 {
    dispatch(handle, op, arg.as_mut_ptr(), arg.len())
}

/// What `DESCRIBE` says of a key.
struct Described {
    suite: u16,
    usage: u32,
    tier: u8,
    persisted: bool,
}

unsafe fn describe(handle: i32) -> Result<Described, i32> {
    let mut d = [0u8; 8];
    let rc = call(handle, kv::DESCRIBE, &mut d);
    if rc < 0 {
        return Err(rc);
    }
    Ok(Described {
        suite: u16::from_le_bytes([d[0], d[1]]),
        usage: u32::from_le_bytes([d[2], d[3], d[4], d[5]]),
        tier: d[6],
        persisted: d[7] != 0,
    })
}

/// A P-256 key's public half.
unsafe fn p256_public(handle: i32) -> Result<[u8; 65], i32> {
    let mut out = [0u8; 65];
    let mut arg = [0u8; 12];
    arg[..8].copy_from_slice(&(out.as_mut_ptr() as u64).to_le_bytes());
    arg[8..10].copy_from_slice(&65u16.to_le_bytes());
    let rc = call(handle, kv::PUBLIC, &mut arg);
    if rc < 0 {
        return Err(rc);
    }
    if u16::from_le_bytes([arg[10], arg[11]]) != 65 {
        return Err(EINVAL);
    }
    Ok(out)
}

/// ECDH on `opener`, in whichever backend holds it, against `peer`, with
/// the opener's public key: the agreement a share envelope opens under.
/// The shared secret lands in `shared` and nowhere else.
unsafe fn agree(opener: i32, peer: &[u8], shared: &mut [u8; 32]) -> Result<[u8; 65], i32> {
    let public = p256_public(opener)?;
    let mut arg = [0u8; 4 + key_share::PEER_MAX + 12];
    if peer.len() > key_share::PEER_MAX {
        return Err(EINVAL);
    }
    arg[..4].copy_from_slice(&(peer.len() as u32).to_le_bytes());
    arg[4..4 + peer.len()].copy_from_slice(peer);
    let tail = 4 + peer.len();
    arg[tail..tail + 8].copy_from_slice(&(shared.as_mut_ptr() as u64).to_le_bytes());
    arg[tail + 8..tail + 10].copy_from_slice(&32u16.to_le_bytes());
    let rc = dispatch(opener, kv::ECDH, arg.as_mut_ptr(), tail + 12);
    if rc < 0 || u16::from_le_bytes([arg[tail + 10], arg[tail + 11]]) != 32 {
        zeroize(shared);
        return Err(if rc < 0 { rc } else { EINVAL });
    }
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
/// `arg` valid for `arg_len` bytes.
unsafe fn share_rewrap(opener: i32, arg: *mut u8, arg_len: usize) -> i32 {
    use kv::share::{self as sh, rewrap as a};
    if arg.is_null() || arg_len < a::ENV {
        return EINVAL;
    }
    let args = core::slice::from_raw_parts_mut(arg, arg_len);
    let env_len = u16::from_le_bytes([args[a::ENV_LEN], args[a::ENV_LEN + 1]]) as usize;
    if a::ENV + env_len > arg_len {
        return EINVAL;
    }
    let grant = key_share::Grant::read(&args[..sh::grant::LEN]);
    if !grant.valid() {
        return EINVAL;
    }
    let out_ptr = u64::from_le_bytes(
        args[a::OUT_PTR..a::OUT_PTR + 8]
            .try_into()
            .unwrap_or([0; 8]),
    ) as *mut u8;
    let out_cap = u32::from_le_bytes(
        args[a::OUT_CAP..a::OUT_CAP + 4]
            .try_into()
            .unwrap_or([0; 4]),
    ) as usize;
    if out_cap < sh::P256_LEN || out_ptr.is_null() {
        args[a::OUT_LEN..a::OUT_LEN + 4].copy_from_slice(&(sh::P256_LEN as u32).to_le_bytes());
        return ERANGE;
    }
    let mut envelope = [0u8; sh::P256_LEN];
    if env_len != sh::P256_LEN {
        return EINVAL;
    }
    envelope.copy_from_slice(&args[a::ENV..a::ENV + env_len]);
    let mut recipient = [0u8; sh::P256_PUB_LEN];
    recipient.copy_from_slice(&args[a::RECIPIENT..a::RECIPIENT + sh::P256_PUB_LEN]);
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
        Some(id) => key_share::seal(&mut out, &carried.binding(), index, &y, &recipient, &id),
        None => false,
    };
    zeroize(&mut y);
    if !sealed {
        return EINVAL;
    }
    core::ptr::copy_nonoverlapping(out.as_ptr(), out_ptr, sh::P256_LEN);
    args[a::OUT_LEN..a::OUT_LEN + 4].copy_from_slice(&(sh::P256_LEN as u32).to_le_bytes());
    0
}

/// A fresh anti-replay id.
fn anti_replay_id() -> Option<[u8; 16]> {
    let mut id = [0u8; 16];
    (crate::kernel::sys::hal::csprng_fill(id.as_mut_ptr(), 16) == 0).then_some(id)
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

/// # Safety
/// `arg` valid for `arg_len` bytes.
unsafe fn share_combine(arg: *mut u8, arg_len: usize) -> i32 {
    use kv::share::{self as sh, combine as a};
    if arg.is_null() || arg_len < a::ENVS {
        return EINVAL;
    }
    let args = core::slice::from_raw_parts(arg, arg_len);
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
    let len_a = u16::from_le_bytes([args[a::ENV_A_LEN], args[a::ENV_A_LEN + 1]]) as usize;
    let len_b = u16::from_le_bytes([args[a::ENV_B_LEN], args[a::ENV_B_LEN + 1]]) as usize;
    if a::ENVS + len_a + len_b > arg_len {
        return EINVAL;
    }
    let env_a = &args[a::ENVS..a::ENVS + len_a];
    let env_b = &args[a::ENVS + len_a..a::ENVS + len_a + len_b];
    if !key_share::well_formed(env_a) || !key_share::well_formed(env_b) {
        return EINVAL;
    }
    // The pair must be two shares of one key: same set, resource, epoch and
    // AEAD, distinct indices. Checked on the headers before anything opens;
    // the headers are authenticated by the opens that follow.
    let same = |off: usize, len: usize| env_a[off..off + len] == env_b[off..off + len];
    if !same(sh::SET_ID, 16) || !same(sh::RESOURCE, 16) || !same(sh::EPOCH, 4) || !same(sh::AEAD, 2)
    {
        return EINVAL;
    }
    if env_a[sh::INDEX] == env_b[sh::INDEX] {
        return EINVAL;
    }
    if env_a[sh::RESOURCE..sh::RESOURCE + 16] != args[a::RESOURCE..a::RESOURCE + 16]
        || env_a[sh::EPOCH..sh::EPOCH + 4] != args[a::EPOCH..a::EPOCH + 4]
    {
        return EACCES;
    }
    for e in [env_a, env_b] {
        if let Err(err) = unexpired(e) {
            return err;
        }
        if key_share::consumed(&e[sh::ANTI_REPLAY..sh::ANTI_REPLAY + 16]) {
            return EACCES;
        }
    }
    let read_i32 =
        |off: usize| i32::from_le_bytes([args[off], args[off + 1], args[off + 2], args[off + 3]]);
    let mut ys = [[0u8; 32]; 2];
    let mut xs = [0u8; 2];
    for (n, (opener, e)) in [
        (read_i32(a::OPENER_A), env_a),
        (read_i32(a::OPENER_B), env_b),
    ]
    .into_iter()
    .enumerate()
    {
        match open_share(opener, e, &mut ys[n]) {
            Ok(x) => xs[n] = x,
            Err(err) => {
                zeroize(&mut ys[0]);
                zeroize(&mut ys[1]);
                return err;
            }
        }
    }
    let mut key = [0u8; 32];
    let combined = key_share::combine(xs[0], &ys[0], xs[1], &ys[1], &mut key);
    zeroize(&mut ys[0]);
    zeroize(&mut ys[1]);
    if combined.is_none() {
        zeroize(&mut key);
        return EINVAL;
    }
    let handle = software::import_session_key(suite, usage, &key);
    zeroize(&mut key);
    if handle >= 0 {
        key_share::consume(&env_a[sh::ANTI_REPLAY..sh::ANTI_REPLAY + 16]);
        key_share::consume(&env_b[sh::ANTI_REPLAY..sh::ANTI_REPLAY + 16]);
    }
    handle
}

/// The sign mode `suite` signs a record in, or `None` for a suite whose
/// signature is no evidence to a third party (a MAC) or that signs only
/// resumably (RSA).
fn record_sign_mode(suite: u16) -> Option<u8> {
    match suite {
        kv::suite::P256 => Some(kv::sign_mode::DIGEST),
        kv::suite::ED25519 | kv::suite::ML_DSA_44 | kv::suite::ML_DSA_65 | kv::suite::ML_DSA_87 => {
            Some(kv::sign_mode::RAW)
        }
        _ => None,
    }
}

/// Sign `record` with `signer` into `out`, in the signer's suite
/// convention: ECDSA over the record's SHA-256, the whole record otherwise.
/// Returns the signature length.
unsafe fn sign_record(signer: i32, record: &[u8], out: *mut u8, cap: usize) -> Result<usize, i32> {
    let d = describe(signer)?;
    let Some(mode) = record_sign_mode(d.suite) else {
        return Err(ENOSYS);
    };
    let digest;
    let input: &[u8] = if mode == kv::sign_mode::DIGEST {
        let mut h = Sha256::new();
        h.update(record);
        digest = h.finalize();
        &digest
    } else {
        record
    };
    if input.len() > MAX_SIGNED_INPUT {
        return Err(EINVAL);
    }
    let mut arg = [0u8; 6 + MAX_SIGNED_INPUT + 12];
    arg[0] = mode;
    arg[2..6].copy_from_slice(&(input.len() as u32).to_le_bytes());
    arg[6..6 + input.len()].copy_from_slice(input);
    let t = 6 + input.len();
    arg[t..t + 8].copy_from_slice(&(out as u64).to_le_bytes());
    arg[t + 8..t + 10].copy_from_slice(&(cap.min(u16::MAX as usize) as u16).to_le_bytes());
    let rc = dispatch(signer, kv::SIGN, arg.as_mut_ptr(), t + 12);
    if rc < 0 {
        return Err(rc);
    }
    Ok(u16::from_le_bytes([arg[t + 10], arg[t + 11]]) as usize)
}

/// Longest input a record signature takes: the key-attestation record.
const MAX_SIGNED_INPUT: usize = kv::attest_key::RECORD_LEN;

/// # Safety
/// `arg` valid for `arg_len` bytes.
unsafe fn attest_key(subject: i32, arg: *mut u8, arg_len: usize) -> i32 {
    use kv::attest_key as a;
    if arg.is_null() || arg_len < a::ARG_LEN {
        return EINVAL;
    }
    let args = core::slice::from_raw_parts_mut(arg, arg_len);
    let signer = i32::from_le_bytes([
        args[a::SIGNER],
        args[a::SIGNER + 1],
        args[a::SIGNER + 2],
        args[a::SIGNER + 3],
    ]);
    let out_ptr = u64::from_le_bytes(
        args[a::OUT_PTR..a::OUT_PTR + 8]
            .try_into()
            .unwrap_or([0; 8]),
    ) as *mut u8;
    let out_cap = u32::from_le_bytes(
        args[a::OUT_CAP..a::OUT_CAP + 4]
            .try_into()
            .unwrap_or([0; 4]),
    ) as usize;
    let d = match describe(subject) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let signer_d = match describe(signer) {
        Ok(s) => s,
        Err(e) => return e,
    };
    if signer_d.usage & kv::usage::SIGN == 0 {
        return EACCES;
    }
    if record_sign_mode(signer_d.suite).is_none() {
        return ENOSYS;
    }
    let sig_len = software::signature_len(signer_d.suite);
    let need = a::RECORD_LEN + sig_len;
    if out_cap < need || out_ptr.is_null() {
        args[a::OUT_LEN..a::OUT_LEN + 4].copy_from_slice(&(need as u32).to_le_bytes());
        return ERANGE;
    }
    let mut record = [0u8; a::RECORD_LEN];
    record[..4].copy_from_slice(&a::MAGIC);
    record[a::R_CHALLENGE..a::R_CHALLENGE + 32]
        .copy_from_slice(&args[a::CHALLENGE..a::CHALLENGE + 32]);
    record[a::R_TIER] = d.tier;
    record[a::R_PERSISTED] = u8::from(d.persisted);
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
    let Some(composition) = software::composition_digest(d.tier) else {
        return ENOMEM;
    };
    record[a::R_COMPOSITION..a::R_COMPOSITION + 32].copy_from_slice(&composition);
    let written = match sign_record(
        signer,
        &record,
        out_ptr.add(a::RECORD_LEN),
        out_cap - a::RECORD_LEN,
    ) {
        Ok(n) => n,
        Err(e) => return e,
    };
    core::ptr::copy_nonoverlapping(record.as_ptr(), out_ptr, a::RECORD_LEN);
    args[a::OUT_LEN..a::OUT_LEN + 4]
        .copy_from_slice(&((a::RECORD_LEN + written) as u32).to_le_bytes());
    0
}

/// `ATTEST_COMPOSITION` with a hardware signer: the kernel's composition
/// record, ending in the hardware tier, signed inside the token.
///
/// # Safety
/// `arg` valid for `arg_len` bytes.
unsafe fn attest_composition(signer: i32, arg: *mut u8, arg_len: usize) -> i32 {
    // arg: [challenge:32][out_ptr:u64][out_cap:u16][out_len_out:u16]
    if arg.is_null() || arg_len < 32 + 12 {
        return EINVAL;
    }
    let args = core::slice::from_raw_parts_mut(arg, arg_len);
    let d = match describe(signer) {
        Ok(d) => d,
        Err(e) => return e,
    };
    if d.usage & kv::usage::SIGN == 0 {
        return EACCES;
    }
    let sig_len = software::signature_len(d.suite);
    if record_sign_mode(d.suite).is_none() || sig_len == 0 {
        return ENOSYS;
    }
    let mut challenge = [0u8; 32];
    challenge.copy_from_slice(&args[..32]);
    let out_ptr = u64::from_le_bytes(args[32..40].try_into().unwrap_or([0; 8])) as *mut u8;
    let out_cap = u16::from_le_bytes([args[40], args[41]]) as usize;
    let Some(record) = software::composition_record(&challenge, d.tier) else {
        return ENOMEM;
    };
    let need = record.len() + sig_len;
    if out_cap < need || out_ptr.is_null() {
        args[42..44].copy_from_slice(&(need.min(u16::MAX as usize) as u16).to_le_bytes());
        return ERANGE;
    }
    // The composition record is longer than any signer takes whole, so a
    // hardware signer signs its digest; a token signs P-256 only.
    if record_sign_mode(d.suite) != Some(kv::sign_mode::DIGEST) {
        return ENOSYS;
    }
    let written = match sign_record(
        signer,
        record,
        out_ptr.add(record.len()),
        out_cap - record.len(),
    ) {
        Ok(n) => n,
        Err(e) => return e,
    };
    core::ptr::copy_nonoverlapping(record.as_ptr(), out_ptr, record.len());
    let n = record.len() + written;
    if n > u16::MAX as usize {
        return ERROR;
    }
    args[42..44].copy_from_slice(&(n as u16).to_le_bytes());
    0
}
