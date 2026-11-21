//! rebuild_driver — asks for a live rebuild after a number of its own steps.
//!
//! Each step counts one; at `after_ticks` it issues
//! `reconfigure::TRIGGER_REBUILD` with an empty configuration (rebuild from
//! the boot configuration) and logs the answer once. The kernel serves the
//! request between passes and instantiates the graph again, this module
//! with it, so the count starts over.

#![cfg_attr(not(feature = "host-test"), no_std)]

use core::ffi::c_void;

use abi::internal::reconfigure::TRIGGER_REBUILD;
use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

#[repr(C)]
pub struct State {
    syscalls: *const SyscallTable,
    /// Steps before the request.
    after_ticks: u32,
    /// Steps taken.
    ticks: u32,
    fired: u8,
}

mod params_def {
    use super::p_u32;
    use super::State;

    fluxor_rt::define_params! {
        State;
        1, after_ticks, u32, 50_000
            => |s, d, len| { s.after_ticks = p_u32(d, len, 0, 50_000); };
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

fn put_dec(line: &mut [u8], n: &mut usize, v: i64) {
    if v < 0 {
        put(line, n, b"-");
    }
    let mut x = v.unsigned_abs();
    let mut d = [0u8; 20];
    let mut k = 0;
    loop {
        d[k] = b'0' + (x % 10) as u8;
        k += 1;
        x /= 10;
        if x == 0 {
            break;
        }
    }
    while k > 0 {
        k -= 1;
        put(line, n, &[d[k]]);
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
    if s.fired != 0 {
        return StepReturn::Continue;
    }
    s.ticks = s.ticks.saturating_add(1);
    if s.ticks < s.after_ticks {
        return StepReturn::Continue;
    }
    s.fired = 1;
    let sys = &*s.syscalls;
    let rc = (sys.provider_call)(
        -1,
        TRIGGER_REBUILD,
        core::ptr::null_mut(),
        0,
        core::ptr::null_mut(),
        0,
    );
    let mut line = [0u8; 48];
    let mut n = 0;
    put(&mut line, &mut n, b"[rdrv] rebuild tick=");
    put_dec(&mut line, &mut n, i64::from(s.ticks));
    put(&mut line, &mut n, b" rc=");
    put_dec(&mut line, &mut n, i64::from(rc));
    dev_log(sys, 3, line.as_ptr(), n);
    StepReturn::Continue
}

fluxor_rt::wasm_entry!();
