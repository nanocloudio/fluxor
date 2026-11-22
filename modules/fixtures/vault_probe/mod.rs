//! vault_probe — does a node keep its keys? See `manifest.toml`.

#![no_std]

use core::ffi::c_void;

use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

use abi::contracts::key_vault as kv;

const USAGE: u32 = kv::usage::SIGN | kv::usage::EXPORT_PUBLIC | kv::usage::PERSIST;
const MAX_LABEL: usize = 64;
const REPORT_MS: u64 = 5000;

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    label: [u8; MAX_LABEL],
    label_len: u8,
    done: u8,
    custody: u8,
    persisted: u8,
    waits: u32,
    rc: i32,
    pub_key: [u8; 8],
    last_report_ms: u64,
}

mod params_def {
    use super::*;
    fluxor_rt::define_params! {
        State;

        1, label, str, 0
            => |s, d, len| {
                if len == 0 || len > super::MAX_LABEL { return; }
                let mut i = 0usize;
                while i < len { *s.label.as_mut_ptr().add(i) = *d.add(i); i += 1; }
                s.label_len = len as u8;
            };
    }
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
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() || state_size < core::mem::size_of::<State>() {
            return -1;
        }
        let s = &mut *(state as *mut State);
        core::ptr::write_bytes(
            core::ptr::from_mut(s).cast::<u8>(),
            0,
            core::mem::size_of::<State>(),
        );
        s.syscalls = syscalls as *const SyscallTable;
        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
        if s.label_len == 0 {
            let d = b"fluxor/vault_probe";
            let mut i = 0usize;
            while i < d.len() {
                s.label[i] = d[i];
                i += 1;
            }
            s.label_len = d.len() as u8;
        }
        0
    }
}

/// Append `v` as decimal; the new length.
unsafe fn put_dec(out: *mut u8, at: usize, v: u64) -> usize {
    at + fmt_u32_raw(out.add(at), v as u32)
}

unsafe fn put(out: *mut u8, at: usize, b: &[u8]) -> usize {
    let mut i = 0usize;
    while i < b.len() {
        *out.add(at + i) = b[i];
        i += 1;
    }
    at + b.len()
}

unsafe fn report(s: &State) {
    let sys = &*s.syscalls;
    let mut line = [0u8; 128];
    let p = line.as_mut_ptr();
    let mut n;
    if s.rc < 0 {
        n = put(p, 0, b"[vault_probe] FAIL rc=-");
        n = put_dec(p, n, s.rc.unsigned_abs() as u64);
        dev_log(sys, 4, p, n);
        return;
    }
    n = put(p, 0, b"[vault_probe] key waits=");
    n = put_dec(p, n, u64::from(s.waits));
    n = put(p, n, b" pub=");
    let hex = b"0123456789abcdef";
    let mut i = 0usize;
    while i < 8 {
        let b = s.pub_key[i];
        *p.add(n) = hex[(b >> 4) as usize];
        *p.add(n + 1) = hex[(b & 15) as usize];
        n += 2;
        i += 1;
    }
    n = put(p, n, b" custody=");
    n = put_dec(p, n, u64::from(s.custody));
    n = put(p, n, b" persisted=");
    n = put_dec(p, n, u64::from(s.persisted));
    dev_log(sys, 3, p, n);
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> StepReturn {
    let s = &mut *(state as *mut State);
    let sys = &*s.syscalls;
    if s.done != 0 {
        let now = dev_millis(sys);
        if now.saturating_sub(s.last_report_ms) >= REPORT_MS {
            s.last_report_ms = now;
            report(s);
        }
        return StepReturn::Continue;
    }
    let ll = s.label_len as usize;
    let mut arg = [0u8; kv::open::MAX_ARG];
    let mut pub_out = [0u8; 64];
    let req = kv::open::Request {
        suite: kv::suite::ED25519,
        usage: USAGE,
        flags: 0,
        label: &s.label[..ll],
    };
    let Some(n) = kv::open::encode(&mut arg, &req) else {
        s.done = 1;
        s.rc = -22;
        report(s);
        return StepReturn::Continue;
    };
    let h = (sys.provider_call)(
        -1,
        kv::OPEN_OR_GENERATE,
        arg.as_mut_ptr(),
        n,
        pub_out.as_mut_ptr(),
        pub_out.len(),
    );
    if h == E_AGAIN {
        s.waits = s.waits.wrapping_add(1);
        return StepReturn::Continue;
    }
    s.done = 1;
    s.last_report_ms = dev_millis(sys);
    if h < 0 {
        s.rc = h;
        report(s);
        return StepReturn::Continue;
    }
    let mut i = 0usize;
    while i < 8 {
        s.pub_key[i] = pub_out[i];
        i += 1;
    }
    let mut d = [0u8; kv::describe::ARG_LEN];
    if (sys.provider_call)(
        h,
        kv::DESCRIBE,
        d.as_mut_ptr(),
        d.len(),
        core::ptr::null_mut(),
        0,
    ) >= 0
    {
        if let Some(described) = kv::describe::parse(&d) {
            s.custody = described.custody;
            s.persisted = described.persisted;
        }
    }
    report(s);
    StepReturn::Continue
}

fluxor_rt::wasm_entry!();
