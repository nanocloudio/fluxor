//! key_vault — opaque custody of asymmetric and symmetric keys.
//!
//! Callers in this instance's execution domain claim `key_vault` and reach
//! it through `provider_call`; the vault runs in the caller's frame. A
//! caller STOREs, GENERATEs or OPENs a key by label and holds a handle: the
//! key's bytes live in this instance's heap and are never written to a
//! caller. A handle names one key for one module occupancy (the caller's
//! scheduler slot and generation, `CALLER_MODULE`), so a key is useless to
//! any other module and dies with its owner's occupancy (`MODULE_LIVE`,
//! checked before every use and every allocation).
//!
//! Labels live in a scope: the owning module's type (`CALLER_MODULE`'s type
//! hash) within its owner's realm (`CALLER_OWNER_UID`, zero for the node).
//! No module reaches another type's labels, and no workload another
//! realm's.
//!
//! **Persistence.** A labelled key asked to `PERSIST` is filed as a record
//! (`fluxor_sdk::cores::vault_record`) in an FXVS image
//! (`fluxor_sdk::cores::vault_image`) of `image` bytes, kept in two A/B
//! slots on the block source wired to `blocks`. A new image goes to the slot
//! not holding the durable one, block by block, then a flush, and only then
//! is a key made since handed out; a boot loads the valid slot with the
//! higher sequence. Labelled ops answer `EAGAIN` until the image is loaded.
//! With nothing wired, keys live as long as the instance and `DESCRIBE`
//! says so.
//!
//! **Sealing** (`seal`): `hardware` seals records under a key derived from
//! the platform's sealing key (`SEAL_KEY_DERIVE`, context `records`), which
//! the medium never holds; a board without one refuses to construct with a
//! store wired. `owner` seals them under a key derived from the 32 bytes
//! the node agent writes to the `seal_in` port, over the caller lane the
//! composer gives a workload's vault: the vault takes one 32-byte frame,
//! derives its record key from it and zeroes it; a later frame is drained
//! and zeroed with no effect, and a frame of another length is refused.
//! Labelled ops answer `EAGAIN` until the key has arrived, and `seal_in` is
//! read from the step and at the start of every op. The records follow that
//! key and the medium, not the node. `none` keeps them readable, and each
//! key says so.
//!
//! **Custody.** `CUSTODY` and each key's `DESCRIBE` say what a key is
//! isolated from: `DEVICE_HW` only for records sealed under a device-unique
//! key, `PROCESS_HW` for a key the `key_custody` provider holds, otherwise
//! `SOFTWARE`. With `custody = token`, labelled P-256 keys asked to persist
//! with uses the token gives are made and held by the token; a label is
//! looked up here first, then on the token, so a key either holds is the one
//! opened. A token that does not answer is never replaced by software.
//! The `key_custody` provider is a Linux host lane: a build for
//! `target_arch = "arm"` (RP) carries no token client and refuses
//! `custody = token` at construction.
//!
//! Every token call is resumable: an op that needs one answers `EAGAIN`
//! until the token has answered, and its caller repeats it unchanged. The
//! vault makes one token call per vault call and holds a multi-call op's
//! progress against the caller and the op's bytes.
//!
//! **Suites** are the variant's: `p256_ed25519` (P-256, Ed25519, HMAC,
//! ChaCha20-Poly1305 and AES-256-GCM keys, KDF masters), `pq` adds ML-DSA,
//! `rsa` adds imported RSA identities, `full` both. P-256 signs as a job of
//! `sign_bits` ladder bits per call (whole by default on aarch64 and Linux,
//! 16 on a microcontroller); RSA and ML-DSA sign as jobs too.
//!
//! Parameters: `slots`, `persisted`, `sign_jobs`, `consumed` size the
//! tables (from the heap the composer sizes for them); `image`,
//! `start_sector`, `sector_count` the store; `seal`; `sign_bits`;
//! `custody`.

#![cfg_attr(not(feature = "host-test"), no_std)]
#![cfg_attr(not(feature = "host-test"), no_main)]
#![deny(clippy::unwrap_used)]
#![allow(
    clippy::too_many_arguments,
    reason = "the vault's record and suite helpers take each field of a fixed wire layout"
)]

use core::ffi::c_void;

use abi::contracts::key_vault as kv;
use abi::contracts::storage::block as blk;
use abi::registry::errno::{
    EACCES, EAGAIN, EBUSY, EINPROGRESS, EINVAL, ENODEV, ENOENT, ENOMEM, ENOSYS, ERANGE, ERROR,
};
use abi::SyscallTable;
use fluxor_abi as abi;
use fluxor_rt::*;
use fluxor_sdk::cores::vault_image as image;
use fluxor_sdk::cores::vault_record as record;
use fluxor_sdk::crypto::chacha20::{chacha20_poly1305_decrypt, chacha20_poly1305_encrypt};
use fluxor_sdk::crypto::ed25519;
use fluxor_sdk::crypto::hmac::{hmac_parts, HashAlg};
#[cfg(feature = "ml_dsa")]
use fluxor_sdk::crypto::ml_dsa;
#[cfg(not(all(target_arch = "arm", not(target_has_atomic = "ptr"))))]
use fluxor_sdk::crypto::p256;
#[cfg(all(target_arch = "arm", not(target_has_atomic = "ptr")))]
use fluxor_sdk::crypto::p256_m0 as p256;
#[cfg(feature = "rsa")]
use fluxor_sdk::crypto::rsa;
use fluxor_sdk::crypto::sha256::Sha256;

include!("slots.rs");
include!("suites.rs");
include!("sign.rs");
include!("persist.rs");
include!("store.rs");
include!("ops.rs");
include!("share.rs");
include!("wrap.rs");
#[cfg(not(target_arch = "arm"))]
include!("custody.rs");
include!("attest.rs");

/// Without the token client no vault op is a token job: the job key that
/// threads through a multi-call op carries nothing.
#[cfg(target_arch = "arm")]
#[derive(Clone, Copy)]
struct JobKey;

#[cfg(target_arch = "arm")]
fn job_key(_: &State, _: u32, _: i32, _: &[u8], _: &[u8]) -> JobKey {
    JobKey
}

#[cfg(target_arch = "arm")]
fn token_done(_: &mut State, _: &JobKey) {}

#[cfg(target_arch = "arm")]
fn token_settle(_: &mut State, _: &JobKey, e: i32) -> i32 {
    e
}

/// `seal` values.
pub mod seal_mode {
    pub const HARDWARE: u8 = 0;
    pub const NONE: u8 = 1;
    pub const OWNER: u8 = 2;
}

/// `custody` values.
pub mod custody_mode {
    pub const SOFTWARE: u8 = 0;
    pub const TOKEN: u8 = 1;
}

use abi::kernel_abi::seal::provenance;

/// Where the record key stands.
mod record_key {
    /// No record key: nothing is sealed (no store, or `seal = none`).
    pub const NONE: u8 = 0;
    /// Waiting for the owner's key (`seal = owner`, nothing on `seal_in`
    /// yet).
    pub const AWAITING: u8 = 1;
    pub const READY: u8 = 2;
}

#[repr(C)]
pub struct State {
    syscalls: *const SyscallTable,
    // ── Parameters ──
    n_slots: u16,
    n_persisted: u16,
    n_jobs: u8,
    seal: u8,
    custody: u8,
    _pad0: u8,
    n_consumed: u16,
    sign_bits: u16,
    image_len: u32,
    start_sector: u32,
    sector_count: u32,
    // ── Tables, from the heap ──
    slots: *mut Slot,
    persisted: *mut Persisted,
    jobs: *mut SignJob,
    consumed: *mut [u8; 16],
    consumed_next: u16,
    consumed_live: u16,
    #[cfg(feature = "ml_dsa")]
    ml: *mut MlScratch,
    #[cfg(feature = "rsa")]
    rsa: *mut RsaScratch,
    held: [HeldShare; MAX_HELD],
    #[cfg(not(target_arch = "arm"))]
    custody_call: CustodyCall,
    // ── Sealing ──
    record_key: [u8; 32],
    key_state: u8,
    /// Provenance of the platform key the record key came from.
    provenance: u8,
    /// The `seal_in` port: the owner's key, one 32-byte frame over the lane
    /// the node agent writes (`seal = owner`); -1 unwired.
    seal_in: i32,
    _pad1: u8,
    warned_unsealable: u8,
    // ── A removal waiting on the medium ──
    /// The scope and label `DESTROY_BY_LABEL` removed from the image, and
    /// the image sequence that removal waits on: its repeat is answered
    /// from here once nothing is left to remove.
    removing: Removal,
    // ── The durable store ──
    store: Store,
}

impl State {
    fn sys(&self) -> &SyscallTable {
        // SAFETY: set at construction to the kernel's table, which outlives
        // every instance.
        unsafe { &*self.syscalls }
    }
}

mod params_def {
    use super::{p_u16, p_u32, p_u8, State};

    fluxor_rt::define_params! {
        State;

        1, slots, u16, 8, range 1..=super::MAX_HANDLE_SLOTS
            => |s, d, len| { s.n_slots = p_u16(d, len, 0, 8); };

        2, persisted, u16, 8
            => |s, d, len| { s.n_persisted = p_u16(d, len, 0, 8); };

        3, sign_jobs, u8, 2
            => |s, d, len| { s.n_jobs = p_u8(d, len, 0, 2); };

        4, image, u32, 0
            => |s, d, len| { s.image_len = p_u32(d, len, 0, 0); };

        5, consumed, u16, 32
            => |s, d, len| { s.n_consumed = p_u16(d, len, 0, 32); };

        6, seal, u8, 0, enum { hardware=0, none=1, owner=2 }
            => |s, d, len| { s.seal = p_u8(d, len, 0, 0); };

        7, start_sector, u32, 0
            => |s, d, len| { s.start_sector = p_u32(d, len, 0, 0); };

        8, sector_count, u32, 0
            => |s, d, len| { s.sector_count = p_u32(d, len, 0, 0); };

        9, sign_bits, u16, 0
            => |s, d, len| { s.sign_bits = p_u16(d, len, 0, 0); };

        10, custody, u8, 0, enum { software=0, token=1 }
            => |s, d, len| { s.custody = p_u8(d, len, 0, 0); };
    }
}

// ── Kernel services ─────────────────────────────────────────────────────

/// Log `msg` at `level` (1 error, 2 warn, 3 info).
fn log(s: &State, level: u8, msg: &[u8]) {
    // SAFETY: `msg` is live for the call.
    unsafe { dev_log(s.sys(), level, msg.as_ptr(), msg.len()) };
}

/// Log `msg` followed by a decimal `n`.
fn log_n(s: &State, level: u8, msg: &[u8], n: u32) {
    let mut line = [0u8; 112];
    let m = msg.len().min(96);
    line[..m].copy_from_slice(&msg[..m]);
    // SAFETY: `line` has room for `m` bytes and a u32's ten digits.
    let k = unsafe { fmt_u32_raw(line.as_mut_ptr().add(m), n) };
    log(s, level, &line[..m + k]);
}

/// A kernel op with `arg` and `data`.
fn kcall(s: &State, handle: i32, op: u32, arg: &mut [u8], data: &mut [u8]) -> i32 {
    let (dp, dl) = if data.is_empty() {
        (core::ptr::null_mut(), 0)
    } else {
        (data.as_mut_ptr(), data.len())
    };
    let (ap, al) = if arg.is_empty() {
        (core::ptr::null_mut(), 0)
    } else {
        (arg.as_mut_ptr(), arg.len())
    };
    // SAFETY: both spans are this frame's own, live and disjoint for the call.
    unsafe { (s.sys().provider_call)(handle, op, ap, al, dp, dl) }
}

/// Fill `out` from the kernel's CSPRNG, all of it or none.
fn random(s: &State, out: &mut [u8]) -> bool {
    kcall(s, -1, abi::kernel_abi::RANDOM_FILL, &mut [], out) == 0
}

/// Milliseconds since boot.
fn now_ms(s: &State) -> u64 {
    // SAFETY: a read-only kernel query.
    unsafe { dev_millis(s.sys()) }
}

/// A kernel query into `out`; its answer.
fn query(s: &State, key: u32, out: &mut [u8]) -> i32 {
    // SAFETY: `out` is this frame's own, live for the call.
    unsafe { (s.sys().provider_query)(-1, key, out.as_mut_ptr(), out.len()) }
}

/// Zeroise `buf` with writes the optimiser keeps.
#[inline]
fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a live, exclusively borrowed byte.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
}

/// HMAC-SHA256 over the concatenation of `data`.
fn hmac_sha256(key: &[u8], data: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hmac_parts(HashAlg::Sha256, key, data, &mut out);
    out
}

/// One table of `n` entries of `T` from the heap, zeroed; null when the heap
/// cannot hold it (or `n` is 0).
fn take_table<T>(s: &State, n: usize) -> *mut T {
    let bytes = n.saturating_mul(core::mem::size_of::<T>());
    if bytes == 0 {
        return core::ptr::null_mut();
    }
    let Ok(b) = u32::try_from(bytes) else {
        return core::ptr::null_mut();
    };
    // SAFETY: the kernel's heap allocator, for this instance's heap.
    let p = unsafe { heap_alloc(s.sys(), b) };
    if !p.is_null() {
        // SAFETY: `p` names `bytes` fresh bytes.
        unsafe { core::ptr::write_bytes(p, 0, bytes) };
    }
    p.cast()
}

// ── Construction ────────────────────────────────────────────────────────

/// Refuse to construct, saying why.
fn refuse(s: &State, why: &[u8]) -> i32 {
    log(s, 1, why);
    -1
}

/// Take every table and the sealing key. 0, or the refusal.
fn construct(s: &mut State, blocks: i32) -> i32 {
    // SAFETY: the kernel's table, live for the instance.
    s.seal_in = unsafe { dev_channel_port(s.sys(), 0, 1) };
    if s.n_slots == 0 || usize::from(s.n_slots) > MAX_HANDLE_SLOTS {
        return refuse(
            s,
            b"[key_vault] refusing to construct: `slots` must be 1..=4096",
        );
    }
    if s.n_jobs == 0 {
        return refuse(
            s,
            b"[key_vault] refusing to construct: `sign_jobs` must be at least 1",
        );
    }
    if s.n_consumed == 0 {
        return refuse(
            s,
            b"[key_vault] refusing to construct: `consumed` must be at least 1",
        );
    }
    if s.seal > seal_mode::OWNER || s.custody > custody_mode::TOKEN {
        return refuse(
            s,
            b"[key_vault] refusing to construct: unknown `seal` or `custody`",
        );
    }
    if cfg!(target_arch = "arm") && s.custody == custody_mode::TOKEN {
        return refuse(
            s,
            b"[key_vault] refusing to construct: `custody: token` needs a `key_custody` provider, which this target has none of (use `custody: software`)",
        );
    }
    let wired = blocks >= 0;
    if wired && !image::valid_len(s.image_len as usize) {
        return refuse(
            s,
            b"[key_vault] refusing to construct: `blocks` is wired and `image` is not a multiple of 512 of at least 512",
        );
    }
    if !wired {
        s.image_len = 0;
    }
    s.slots = take_table::<Slot>(s, usize::from(s.n_slots));
    s.persisted = take_table::<Persisted>(s, usize::from(s.n_persisted));
    s.jobs = take_table::<SignJob>(s, usize::from(s.n_jobs));
    s.consumed = take_table::<[u8; 16]>(s, usize::from(s.n_consumed));
    #[cfg(feature = "ml_dsa")]
    {
        s.ml = take_table::<MlScratch>(s, 1);
    }
    #[cfg(feature = "rsa")]
    {
        s.rsa = take_table::<RsaScratch>(s, 1);
    }
    #[cfg(feature = "ml_dsa")]
    let ml_short = s.ml.is_null();
    #[cfg(not(feature = "ml_dsa"))]
    let ml_short = false;
    #[cfg(feature = "rsa")]
    let rsa_short = s.rsa.is_null();
    #[cfg(not(feature = "rsa"))]
    let rsa_short = false;
    if s.slots.is_null()
        || s.jobs.is_null()
        || s.consumed.is_null()
        || (s.n_persisted != 0 && s.persisted.is_null())
        || ml_short
        || rsa_short
    {
        return refuse(
            s,
            b"[key_vault] refusing to construct: the heap cannot hold the tables (heap.arena_bytes below what heap_per_param sizes)",
        );
    }
    for i in 0..usize::from(s.n_jobs) {
        jobs(s)[i] = SignJob::empty();
    }
    #[cfg(feature = "rsa")]
    rsa_init(s);
    if wired && !store_init(s, blocks) {
        return refuse(
            s,
            b"[key_vault] refusing to construct: the heap cannot hold the store image",
        );
    }
    match s.seal {
        seal_mode::HARDWARE => {
            let mut a = [0u8; 1 + abi::kernel_abi::seal::MAX_CTX];
            a[0] = RECORDS_CTX.len() as u8;
            a[1..1 + RECORDS_CTX.len()].copy_from_slice(&RECORDS_CTX);
            let rc = kcall(s, -1, abi::kernel_abi::SEAL_KEY_DERIVE, &mut a, &mut []);
            if rc == abi::kernel_abi::seal::OUT_LEN as i32 {
                s.provenance = a[0];
                s.record_key.copy_from_slice(&a[1..33]);
                s.key_state = record_key::READY;
                zeroize(&mut a);
            } else if wired {
                return refuse(
                    s,
                    b"[key_vault] refusing to construct: `seal: hardware` with a store wired and this platform has no sealing key (`seal: none` keeps records readable)",
                );
            } else {
                s.key_state = record_key::NONE;
            }
        }
        seal_mode::OWNER => s.key_state = record_key::AWAITING,
        _ => {
            s.key_state = record_key::NONE;
            if wired {
                log(
                    s,
                    2,
                    b"[key_vault] store kept readable (seal: none): keys on the medium are not sealed",
                );
            }
        }
    }
    0
}

/// The context the record key is derived under.
const RECORDS_CTX: [u8; 7] = *b"records";

/// The custody this vault reports for a key it holds in its own heap: what
/// its records are sealed under, never whether they persist.
fn current_custody(s: &State) -> u8 {
    if s.seal == seal_mode::HARDWARE
        && s.key_state == record_key::READY
        && s.provenance == provenance::DEVICE_UNIQUE
    {
        kv::custody::DEVICE_HW
    } else {
        kv::custody::SOFTWARE
    }
}

// ── Entry points ────────────────────────────────────────────────────────

/// The heap besides the param-sized tables (`[capacities] heap_per_param`
/// `base`, per variant): the allocator's per-table rounding, and the ML-DSA
/// and RSA scratch of the variants that carry them.
const HEAP_BASE: usize = 256
    + if cfg!(feature = "ml_dsa") { 66_816 } else { 0 }
    + if cfg!(feature = "rsa") { 21_776 } else { 0 };
const _: () = {
    #[cfg(feature = "ml_dsa")]
    assert!(core::mem::size_of::<MlScratch>() <= 66_816);
    #[cfg(feature = "rsa")]
    assert!(core::mem::size_of::<RsaScratch>() <= 21_776);
};

fluxor_rt::module_facts! { state: State, arena: HEAP_BASE }

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_init")]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_new")]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if syscalls.is_null() || state.is_null() {
        return -1;
    }
    if state_size < core::mem::size_of::<State>() {
        return -2;
    }
    // SAFETY: the loader hands a block of at least `State`'s size, zeroed
    // here before it is read as one; every field is valid at all-zero bytes.
    let s = unsafe {
        core::ptr::write_bytes(state, 0, core::mem::size_of::<State>());
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        params_def::set_defaults(s);
        if !params.is_null() && params_len > 0 {
            params_def::parse_tlv(s, params, params_len);
        }
        s
    };
    construct(s, in_chan)
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_step")]
pub extern "C" fn module_step(state: *mut u8) -> StepReturn {
    if state.is_null() {
        return StepReturn::error(-1);
    }
    // SAFETY: the kernel passes the block `module_new` initialised.
    let s = unsafe { &mut *(state as *mut State) };
    seal_in_step(s);
    store_step(s);
    #[cfg(not(target_arch = "arm"))]
    custody_step(s);
    StepReturn::Continue
}

/// # Safety
/// Kernel provider-dispatch entry point: `state` is the instance block this
/// module's `module_new` initialised, `arg` points to `arg_len` bytes and
/// `data` to `data_len` bytes (either may be null when its length is 0),
/// disjoint and valid for the call.
#[cfg_attr(
    not(feature = "host-test"),
    link_section = ".text.module_provider_dispatch"
)]
#[cfg_attr(not(feature = "host-test"), export_name = "module_provider_dispatch")]
pub unsafe extern "C" fn key_vault_dispatch(
    state: *mut u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
    data: *mut u8,
    data_len: usize,
) -> i32 {
    if state.is_null() {
        return EINVAL;
    }
    // SAFETY: the kernel passes the state block `module_new` initialised.
    let s = unsafe { &mut *(state as *mut State) };
    if s.slots.is_null() {
        return ENOSYS;
    }
    let a: &mut [u8] = if arg.is_null() || arg_len == 0 {
        &mut []
    } else {
        // SAFETY: the caller named `arg_len` bytes at `arg` for the call.
        unsafe { core::slice::from_raw_parts_mut(arg, arg_len) }
    };
    let d: &mut [u8] = if data.is_null() || data_len == 0 {
        &mut []
    } else {
        // SAFETY: the caller named `data_len` bytes at `data`, disjoint
        // from `arg`, for the call.
        unsafe { core::slice::from_raw_parts_mut(data, data_len) }
    };
    if opcode == abi::internal::reconfigure::OWNER_RELEASED {
        owner_released(s, a);
        return 0;
    }
    seal_in_step(s);
    dispatch(s, handle, opcode, a, d)
}

/// The length of the owner's key on `seal_in`.
const OWNER_KEY_LEN: usize = 32;

/// Take what `seal_in` holds: the first 32-byte frame of a vault kept under
/// its owner's key becomes the record key; every other frame is drained
/// with no effect, a frame of another length refused. Every byte read is
/// zeroed.
fn seal_in_step(s: &mut State) {
    if s.seal_in < 0 {
        return;
    }
    loop {
        // SAFETY: the kernel's table and this module's own port.
        let rl = unsafe { dev_channel_record_len(s.sys(), s.seal_in) };
        if rl <= 0 {
            return;
        }
        let mut frame = [0u8; OWNER_KEY_LEN];
        let mut left = rl as usize;
        let mut got = 0usize;
        while left > 0 {
            let n = left.min(OWNER_KEY_LEN);
            // SAFETY: `frame` is this frame's own, `n` bytes of it.
            let r = unsafe { (s.sys().channel_read)(s.seal_in, frame.as_mut_ptr(), n) };
            if r <= 0 {
                break;
            }
            got += r as usize;
            left = left.saturating_sub(r as usize);
            if left > 0 {
                zeroize(&mut frame);
            }
        }
        if got != OWNER_KEY_LEN || rl as usize != OWNER_KEY_LEN {
            zeroize(&mut frame);
            log(
                s,
                1,
                b"[key_vault] seal_in: a frame that is not a 32-byte key is refused",
            );
            continue;
        }
        if s.seal == seal_mode::OWNER && s.key_state == record_key::AWAITING {
            s.record_key = fluxor_sdk::crypto::seal::derive_owner(&frame, &RECORDS_CTX);
            s.key_state = record_key::READY;
        }
        zeroize(&mut frame);
    }
}

fluxor_rt::wasm_entry!();
