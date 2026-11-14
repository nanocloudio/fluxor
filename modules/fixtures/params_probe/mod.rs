//! params_probe — reports the params it was given.
//!
//! The graph hands it any number of blobs under `payload`; the kernel borrows
//! them from the config blob in place and the module sees each as a run of
//! TLV chunks. It counts the bytes and folds them into an FNV-1a, and logs
//! both on its first step, once.

#![cfg_attr(not(feature = "host-test"), no_std)]

use core::ffi::c_void;

use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

#[repr(C)]
pub struct State {
    syscalls: *const SyscallTable,
    bytes: u32,
    chunks: u32,
    fnv: u32,
    reported: u8,
}

/// Fold one chunk of the payload into the running count and hash. A
/// zero-length call is the SDK applying the blob's default (`set_defaults`,
/// run before the TLV walk and again at its start), not a chunk.
fn take(s: &mut State, d: *const u8, len: usize) {
    if d.is_null() || len == 0 {
        return;
    }
    let mut i = 0;
    while i < len {
        // SAFETY: the kernel hands the handler `len` readable bytes.
        let b = unsafe { *d.add(i) };
        s.fnv = (s.fnv ^ u32::from(b)).wrapping_mul(0x0100_0193);
        i += 1;
    }
    s.bytes = s.bytes.wrapping_add(len as u32);
    s.chunks = s.chunks.wrapping_add(1);
}

mod params_def {
    use super::take;
    use super::State;

    fluxor_rt::define_params! {
        State;
        1, payload, blob, 0 => |s, d, len| { take(s, d, len); };
    }
}

fn put(line: &mut [u8], n: &mut usize, b: &[u8]) {
    let mut i = 0;
    while i < b.len() && *n < line.len() {
        line[*n] = b[i];
        *n += 1;
        i += 1;
    }
}

fn put_dec(line: &mut [u8], n: &mut usize, mut v: u32) {
    let mut d = [0u8; 10];
    let mut k = 0;
    loop {
        d[k] = b'0' + (v % 10) as u8;
        k += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    while k > 0 {
        k -= 1;
        put(line, n, &[d[k]]);
    }
}

fn put_hex32(line: &mut [u8], n: &mut usize, v: u32) {
    const H: [u8; 16] = *b"0123456789abcdef";
    let mut i = 0;
    while i < 8 {
        put(line, n, &[H[((v >> (28 - 4 * i)) & 15) as usize]]);
        i += 1;
    }
}

fluxor_rt::module_facts! { state: State }

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
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if syscalls.is_null() || state.is_null() || state_size < core::mem::size_of::<State>() {
        return -22;
    }
    core::ptr::write_bytes(state, 0, core::mem::size_of::<State>());
    let s = &mut *(state as *mut State);
    s.syscalls = syscalls as *const SyscallTable;
    s.fnv = 0x811c_9dc5;
    params_def::set_defaults(s);
    if !params.is_null() && params_len > 0 {
        params_def::parse_tlv(s, params, params_len);
    }
    0
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_step")]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> StepReturn {
    let s = &mut *(state as *mut State);
    if s.reported == 0 {
        s.reported = 1;
        let mut line = [0u8; 64];
        let mut n = 0;
        put(&mut line, &mut n, b"[params] bytes=");
        put_dec(&mut line, &mut n, s.bytes);
        put(&mut line, &mut n, b" chunks=");
        put_dec(&mut line, &mut n, s.chunks);
        put(&mut line, &mut n, b" fnv=");
        put_hex32(&mut line, &mut n, s.fnv);
        dev_log(&*s.syscalls, 3, line.as_ptr(), n);
    }
    StepReturn::Continue
}

fluxor_rt::wasm_entry!();
