//! `rsa_bench` — how long the RSA core's units take on this silicon.
//!
//! The tls module steps every RSA operation in rows of a Montgomery
//! product and units of a modulus preparation, and pays for them against
//! the graph's tick. How many of those units fit a step is a number that
//! belongs to the board, so it is measured here rather than estimated. Each
//! measurement is itself spread over steps — a bounded chunk per step, its
//! time added to a running total — so the fixture never asks a step for
//! more than the guard allows, and the sum of the chunks is the whole cost.
//! Results are logged as `[rsa_bench] <name> us=<n>`, then
//! `[rsa_bench] done`.
//!
//! What is measured, in order:
//!
//!   - `prep<bits>`: preparing a modulus (R² by subtraction, doublings and
//!     Montgomery squarings), whole;
//!   - `mul<bits>`: one whole Montgomery product (`len` rows);
//!   - `exp<bits>_r<rows>`: one whole `s^65537 mod n`, preparation included,
//!     stepped at `rows` units per step — the cost of one certificate
//!     signature or CertificateVerify — with the steps taken and the
//!     longest step;
//!   - `sizes`: the byte sizes of the verify job, the sign job and a
//!     private key, so the state cost is read at the target's limb width;
//!   - `p256_verify`: one ECDSA P-256 verification, in one step because the
//!     primitive has no other shape — the elliptic-curve baseline the RSA
//!     numbers are read against. Last, so a board whose guard refuses it
//!     has already reported the rest.
//!
//! No key material: the moduli are odd numbers with their top bit set,
//! drawn from a hash, and the P-256 key is derived from a fixed seed inside
//! the fixture. Arithmetic cost does not depend on primality.

#![no_std]
#![allow(
    dead_code,
    reason = "the PIC build mounts the whole of modules/sdk/* via include!, so every \
              module's compile sees the entire ABI surface while using a subset. This \
              allow is the SDK's textual mounting showing through"
)]
#![allow(
    unused_imports,
    reason = "same cause: the mounted SDK brings names this module does not reach for"
)]
#![allow(
    unreachable_patterns,
    reason = "defensive `_ => Error` arms in enum state-machine matches. The match is \
              exhaustive, which is why the lint fires; the arm exists so that adding a \
              variant cannot silently bypass the error path. #[expect] is not the \
              alternative — it fails the build in the configurations where the lint \
              does not fire"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");
include!("../../sdk/crypto/sha256.rs");
include!("../../sdk/crypto/sha384.rs");
include!("../../sdk/crypto/hmac.rs");
include!("../../sdk/crypto/p256.rs");
include!("../../sdk/crypto/rsa.rs");

/// Units of preparation per step: doublings and squaring rows alike.
const PREP_CHUNK: usize = 32;
/// Rows of a product per step.
const MUL_CHUNK: usize = 8;

/// The measurements, in order.
const M_PREP2048: u8 = 0;
const M_PREP4096: u8 = 1;
const M_MUL2048: u8 = 2;
const M_MUL3072: u8 = 3;
const M_MUL4096: u8 = 4;
const M_EXP2048_R8: u8 = 5;
const M_EXP2048_R32: u8 = 6;
const M_EXP2048_R64: u8 = 7;
const M_EXP3072_R32: u8 = 8;
const M_EXP4096_R8: u8 = 9;
const M_EXP4096_R32: u8 = 10;
const M_SIZES: u8 = 11;
const M_P256_VERIFY: u8 = 12;
const M_DONE: u8 = 13;

/// Where a measurement is: not started, its untimed setup, its timed
/// body.
const S_START: u8 = 0;
const S_SETUP: u8 = 1;
const S_BODY: u8 = 2;

#[repr(C)]
struct BenchState {
    syscalls: *const SyscallTable,
    measurement: u8,
    stage: u8,
    _pad: [u8; 6],
    /// Running totals of the measurement in progress.
    total_us: u64,
    steps: u64,
    worst_us: u64,
    job: RsaVerifyJob,
    modulus: RsaModulus,
    mul: RsaMul,
    a: [RsaLimb; RSA_LIMBS_MAX],
    out: [RsaLimb; RSA_LIMBS_MAX],
    n_be: [u8; RSA_BYTES_MAX],
    s_be: [u8; RSA_BYTES_MAX],
}

unsafe fn sys(s: &BenchState) -> &SyscallTable {
    &*s.syscalls
}

/// Fill `out` from a SHA-256 counter stream.
fn fill(seed: u8, out: &mut [u8]) {
    let mut off = 0;
    let mut counter: u32 = 0;
    while off < out.len() {
        let mut block = [0u8; 8];
        block[0] = seed;
        block[4..8].copy_from_slice(&counter.to_le_bytes());
        let d = sha256(&block);
        let take = (out.len() - off).min(32);
        out[off..off + take].copy_from_slice(&d[..take]);
        off += take;
        counter += 1;
    }
}

/// An odd modulus of exactly `bits` bits and an operand below it.
fn synthetic(s: &mut BenchState, bits: usize) -> usize {
    let k = bits / 8;
    fill(1, &mut s.n_be[..k]);
    s.n_be[0] |= 0x80;
    s.n_be[k - 1] |= 0x01;
    fill(2, &mut s.s_be[..k]);
    s.s_be[0] &= 0x7f;
    k
}

/// Write `[rsa_bench] <name> us=<n> [<key>=<v>]...` at info.
unsafe fn report(s: &BenchState, name: &[u8], us: u64, k1: &[u8], v1: u64, k2: &[u8], v2: u64) {
    let mut line = [0u8; 112];
    let mut at = 0;
    at = put(&mut line, at, b"[rsa_bench] ");
    at = put(&mut line, at, name);
    at = put(&mut line, at, b" us=");
    at = put_dec(&mut line, at, us);
    if !k1.is_empty() {
        at = put(&mut line, at, b" ");
        at = put(&mut line, at, k1);
        at = put(&mut line, at, b"=");
        at = put_dec(&mut line, at, v1);
    }
    if !k2.is_empty() {
        at = put(&mut line, at, b" ");
        at = put(&mut line, at, k2);
        at = put(&mut line, at, b"=");
        at = put_dec(&mut line, at, v2);
    }
    dev_log(sys(s), 2, line.as_ptr(), at);
}

fn put(line: &mut [u8], at: usize, text: &[u8]) -> usize {
    let n = text.len().min(line.len() - at);
    line[at..at + n].copy_from_slice(&text[..n]);
    at + n
}

/// Decimal digits of `v`. Cortex-M33 has no 64-bit divide and the PIC
/// build links no runtime for one, so the value is formatted in `u32`;
/// every number here is a microsecond count or a byte size far below
/// that.
fn put_dec(line: &mut [u8], at: usize, v: u64) -> usize {
    let mut w = if v > u32::MAX as u64 {
        u32::MAX
    } else {
        v as u32
    };
    let mut digits = [0u8; 10];
    let mut n = 0;
    if w == 0 {
        digits[0] = b'0';
        n = 1;
    }
    while w > 0 {
        digits[n] = b'0' + (w % 10) as u8;
        w /= 10;
        n += 1;
    }
    let mut at = at;
    while n > 0 && at < line.len() {
        n -= 1;
        line[at] = digits[n];
        at += 1;
    }
    at
}

fn bits_of(m: u8) -> usize {
    match m {
        M_PREP2048 | M_MUL2048 | M_EXP2048_R8 | M_EXP2048_R32 | M_EXP2048_R64 => 2048,
        M_MUL3072 | M_EXP3072_R32 => 3072,
        _ => 4096,
    }
}

fn rows_of(m: u8) -> usize {
    match m {
        M_EXP2048_R8 | M_EXP4096_R8 => 8,
        M_EXP2048_R64 => 64,
        _ => 32,
    }
}

/// Report the measurement in progress under its name. Each arm names its
/// literal at the call: a match RETURNING one of several literals compiles
/// to a table of their addresses, which a flat module image never
/// relocates, and the first read through it is a bus fault.
unsafe fn report_named(s: &BenchState, m: u8, us: u64, k1: &[u8], v1: u64, k2: &[u8], v2: u64) {
    match m {
        M_PREP2048 => report(s, b"prep2048", us, k1, v1, k2, v2),
        M_PREP4096 => report(s, b"prep4096", us, k1, v1, k2, v2),
        M_MUL2048 => report(s, b"mul2048", us, k1, v1, k2, v2),
        M_MUL3072 => report(s, b"mul3072", us, k1, v1, k2, v2),
        M_MUL4096 => report(s, b"mul4096", us, k1, v1, k2, v2),
        M_EXP2048_R8 => report(s, b"exp2048_r8", us, k1, v1, k2, v2),
        M_EXP2048_R32 => report(s, b"exp2048_r32", us, k1, v1, k2, v2),
        M_EXP2048_R64 => report(s, b"exp2048_r64", us, k1, v1, k2, v2),
        M_EXP3072_R32 => report(s, b"exp3072_r32", us, k1, v1, k2, v2),
        M_EXP4096_R8 => report(s, b"exp4096_r8", us, k1, v1, k2, v2),
        M_EXP4096_R32 => report(s, b"exp4096_r32", us, k1, v1, k2, v2),
        _ => report(s, b"unknown", us, k1, v1, k2, v2),
    }
}

/// Add one timed chunk to the running totals.
fn account(s: &mut BenchState, us: u64) {
    s.total_us += us;
    s.steps += 1;
    if us > s.worst_us {
        s.worst_us = us;
    }
}

fn begin(s: &mut BenchState) {
    s.total_us = 0;
    s.steps = 0;
    s.worst_us = 0;
}

/// One step of the measurement in progress. True when it has reported.
unsafe fn advance(s: &mut BenchState) -> bool {
    let m = s.measurement;
    let bits = bits_of(m);
    match m {
        M_PREP2048 | M_PREP4096 => {
            if s.stage == S_START {
                let k = synthetic(s, bits);
                s.modulus.load(&s.n_be[..k], RSA_MODULUS_BITS_MIN);
                begin(s);
                s.stage = S_BODY;
            }
            let t0 = dev_micros(sys(s));
            let r = s.modulus.prepare_step(PREP_CHUNK);
            let d = dev_micros(sys(s)) - t0;
            account(s, d);
            if r == RsaStep::Done {
                report_named(s, m, s.total_us, b"steps", s.steps, b"worst", s.worst_us);
                return true;
            }
            false
        }
        M_MUL2048 | M_MUL3072 | M_MUL4096 => {
            if s.stage == S_START {
                let k = synthetic(s, bits);
                s.modulus.load(&s.n_be[..k], RSA_MODULUS_BITS_MIN);
                rsa_from_be(&s.s_be[..k], &mut s.a);
                s.stage = S_SETUP;
            }
            if s.stage == S_SETUP {
                // The preparation is not what this measures; it is stepped
                // untimed until the modulus is ready.
                if s.modulus.prepare_step(PREP_CHUNK) == RsaStep::Done {
                    s.mul.start();
                    begin(s);
                    s.stage = S_BODY;
                }
                return false;
            }
            let t0 = dev_micros(sys(s));
            let (_, done) = s
                .mul
                .step(&s.modulus, &s.a, &s.modulus.r2, &mut s.out, MUL_CHUNK);
            let d = dev_micros(sys(s)) - t0;
            account(s, d);
            if done {
                report_named(
                    s,
                    m,
                    s.total_us,
                    b"rows",
                    (bits / RSA_LIMB_BITS) as u64,
                    b"",
                    0,
                );
                return true;
            }
            false
        }
        M_EXP2048_R8 | M_EXP2048_R32 | M_EXP2048_R64 | M_EXP3072_R32 | M_EXP4096_R8
        | M_EXP4096_R32 => {
            if s.stage == S_START {
                let k = synthetic(s, bits);
                if !s.job.start(&s.n_be[..k], 65537, &s.s_be[..k]) {
                    report_named(s, m, u64::MAX, b"", 0, b"", 0);
                    return true;
                }
                begin(s);
                s.stage = S_BODY;
            }
            let t0 = dev_micros(sys(s));
            let r = s.job.step(rows_of(m));
            let d = dev_micros(sys(s)) - t0;
            account(s, d);
            if r == RsaStep::Done {
                report_named(s, m, s.total_us, b"steps", s.steps, b"worst", s.worst_us);
                return true;
            }
            false
        }
        M_SIZES => {
            report(
                s,
                b"size_verify_job",
                core::mem::size_of::<RsaVerifyJob>() as u64,
                b"limb_bits",
                RSA_LIMB_BITS as u64,
                b"",
                0,
            );
            report(
                s,
                b"size_sign_job",
                core::mem::size_of::<RsaSignJob>() as u64,
                b"",
                0,
                b"",
                0,
            );
            report(
                s,
                b"size_private_key",
                core::mem::size_of::<RsaPrivateKey>() as u64,
                b"",
                0,
                b"",
                0,
            );
            true
        }
        M_P256_VERIFY => {
            let mut seed = [0u8; 32];
            fill(3, &mut seed);
            let (private, public) = ecdh_keygen(&seed);
            let digest = sha256(b"rsa_bench");
            let Some(sig) = ecdsa_sign(&private, &digest, &seed) else {
                report(s, b"p256_verify", u64::MAX, b"", 0, b"", 0);
                return true;
            };
            let t0 = dev_micros(sys(s));
            let ok = ecdsa_verify(&public, &digest, &sig);
            let d = dev_micros(sys(s)) - t0;
            report(
                s,
                b"p256_verify",
                if ok { d } else { u64::MAX },
                b"",
                0,
                b"",
                0,
            );
            true
        }
        _ => true,
    }
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<BenchState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() || state_size < core::mem::size_of::<BenchState>() {
            return -3;
        }
        core::ptr::write_bytes(state, 0, core::mem::size_of::<BenchState>());
        let s = &mut *(state as *mut BenchState);
        s.syscalls = syscalls as *const SyscallTable;
        s.measurement = M_PREP2048;
        s.stage = S_START;
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut BenchState);
        if s.syscalls.is_null() {
            return -1;
        }
        if s.measurement >= M_DONE {
            let line = b"[rsa_bench] done";
            dev_log(sys(s), 2, line.as_ptr(), line.len());
            return 1;
        }
        if advance(s) {
            s.measurement += 1;
            s.stage = S_START;
        }
        0
    }
}
