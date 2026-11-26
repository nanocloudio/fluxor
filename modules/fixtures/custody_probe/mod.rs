//! custody_probe — a graph module calling a host provider's `key_custody`.
//! See `manifest.toml`.

#![no_std]

use core::ffi::c_void;

use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

use abi::contracts::key_custody as kc;
use abi::contracts::key_vault::usage;

/// The ops in the order the probe makes them.
const GENERATE: u8 = 0;
const SIGN: u8 = 1;
const PUBLIC: u8 = 2;
const DESTROY: u8 = 3;
const DONE: u8 = 4;

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    phase: u8,
    handle: i32,
    waits: u32,
    sig: [u8; kc::SIG_LEN],
    public: [u8; kc::PUB_LEN],
}

fluxor_rt::module_facts! { state: State }

/// # Safety
/// Kernel module-ABI entry point: `syscalls` is the kernel's syscall table,
/// valid for the module's lifetime.
#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes and `syscalls` the kernel's syscall table.
#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if state.is_null() || syscalls.is_null() {
        return -1;
    }
    if state_size < core::mem::size_of::<State>() {
        return -2;
    }
    core::ptr::write_bytes(state, 0, core::mem::size_of::<State>());
    let s = &mut *(state as *mut State);
    s.syscalls = syscalls as *const SyscallTable;
    s.handle = -1;
    0
}

unsafe fn put(out: *mut u8, at: usize, b: &[u8]) -> usize {
    let mut i = 0usize;
    while i < b.len() {
        *out.add(at + i) = b[i];
        i += 1;
    }
    at + b.len()
}

fn nibble(v: u8) -> u8 {
    if v < 10 {
        b'0' + v
    } else {
        b'a' + (v - 10)
    }
}

unsafe fn put_hex(out: *mut u8, mut at: usize, b: &[u8]) -> usize {
    let mut i = 0usize;
    while i < b.len() {
        *out.add(at) = nibble(b[i] >> 4);
        *out.add(at + 1) = nibble(b[i] & 15);
        at += 2;
        i += 1;
    }
    at
}

unsafe fn fail(s: &mut State, op: &[u8], rc: i32) {
    let sys = &*s.syscalls;
    let mut line = [0u8; 64];
    let p = line.as_mut_ptr();
    let mut n = put(p, 0, b"[custody_probe] FAIL op=");
    n = put(p, n, op);
    n = put(p, n, b" rc=-");
    n += fmt_u32_raw(p.add(n), rc.unsigned_abs());
    dev_log(sys, 4, p, n);
    s.phase = DONE;
}

unsafe fn report(s: &State) {
    let sys = &*s.syscalls;
    let mut line = [0u8; 400];
    let p = line.as_mut_ptr();
    let mut n = put(p, 0, b"[custody_probe] ok waits=");
    n += fmt_u32_raw(p.add(n), s.waits);
    n = put(p, n, b" pub=");
    n = put_hex(p, n, &s.public);
    n = put(p, n, b" sig=");
    n = put_hex(p, n, &s.sig);
    dev_log(sys, 3, p, n);
}

/// The answer to one call, or `None` while it is out (EAGAIN).
unsafe fn call(s: &mut State, handle: i32, op: u32, arg: &mut [u8]) -> Option<i32> {
    let sys = &*s.syscalls;
    let rc = dev_call(sys, handle, op, arg.as_mut_ptr(), arg.len());
    if rc == E_AGAIN {
        s.waits = s.waits.wrapping_add(1);
        return None;
    }
    Some(rc)
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> StepReturn {
    let s = &mut *(state as *mut State);
    match s.phase {
        GENERATE => {
            let mut arg = [0u8; kc::generate::ARG_LEN];
            let uses = usage::SIGN | usage::EXPORT_PUBLIC;
            if kc::generate::encode(0x5052_4f42, uses, &[], &mut arg).is_none() {
                fail(s, b"encode", 22);
                return StepReturn::Continue;
            }
            let Some(rc) = call(s, -1, kc::GENERATE, &mut arg) else {
                return StepReturn::Continue;
            };
            if rc < 0 {
                fail(s, b"generate", rc);
                return StepReturn::Continue;
            }
            s.handle = rc;
            s.phase = SIGN;
        }
        SIGN => {
            let mut digest = [0u8; 32];
            let mut i = 0usize;
            while i < 32 {
                digest[i] = (7 * i + 1) as u8;
                i += 1;
            }
            let mut arg = [0u8; kc::sign::ARG_LEN];
            if kc::sign::encode(&digest, &mut arg).is_none() {
                fail(s, b"encode", 22);
                return StepReturn::Continue;
            }
            let Some(rc) = call(s, s.handle, kc::SIGN, &mut arg) else {
                return StepReturn::Continue;
            };
            if rc != kc::SIG_LEN as i32 {
                fail(s, b"sign", rc);
                return StepReturn::Continue;
            }
            let mut i = 0usize;
            while i < kc::SIG_LEN {
                s.sig[i] = arg[i];
                i += 1;
            }
            s.phase = PUBLIC;
        }
        PUBLIC => {
            let mut arg = [0u8; kc::public::ARG_LEN];
            let Some(rc) = call(s, s.handle, kc::PUBLIC, &mut arg) else {
                return StepReturn::Continue;
            };
            if rc != kc::PUB_LEN as i32 {
                fail(s, b"public", rc);
                return StepReturn::Continue;
            }
            s.public = arg;
            s.phase = DESTROY;
        }
        DESTROY => {
            let mut arg = [0u8; kc::destroy::ARG_LEN];
            let Some(rc) = call(s, s.handle, kc::DESTROY, &mut arg) else {
                return StepReturn::Continue;
            };
            if rc != 0 {
                fail(s, b"destroy", rc);
                return StepReturn::Continue;
            }
            s.phase = DONE;
            report(s);
        }
        _ => {}
    }
    StepReturn::Continue
}

fluxor_rt::wasm_entry!();
