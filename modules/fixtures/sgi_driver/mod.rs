//! sgi_driver — raises a software-generated interrupt on another core.
//!
//! Every `every_ticks` of its own steps it issues `SIGNAL_CORE` with
//! `[core][sgi]`, the interrupt an IRQ-owned module on that core is bound
//! to. It logs the first answer, and the first refusal after that.

#![cfg_attr(not(feature = "host-test"), no_std)]

use core::ffi::c_void;

use abi::kernel_abi::SIGNAL_CORE;
use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

#[repr(C)]
pub struct State {
    syscalls: *const SyscallTable,
    /// Steps between signals.
    every_ticks: u32,
    /// Steps since the last signal.
    ticks: u32,
    /// The core signalled.
    core: u8,
    /// The SGI raised (0..=15).
    sgi: u8,
    /// Whether the first answer, and a refusal after it, were logged.
    logged_first: u8,
    logged_refusal: u8,
}

mod params_def {
    use super::State;
    use super::{p_u32, p_u8};

    fluxor_rt::define_params! {
        State;
        1, core, u8, 1
            => |s, d, len| { s.core = p_u8(d, len, 0, 1); };
        2, sgi, u8, 15
            => |s, d, len| { s.sgi = p_u8(d, len, 0, 15); };
        3, every_ticks, u32, 2000
            => |s, d, len| { let v = p_u32(d, len, 0, 2000); s.every_ticks = if v == 0 { 2000 } else { v }; };
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

unsafe fn report(s: &State, rc: i32) {
    let mut line = [0u8; 48];
    let mut n = 0;
    put(&mut line, &mut n, b"[sgi] core=");
    put_dec(&mut line, &mut n, i64::from(s.core));
    put(&mut line, &mut n, b" sgi=");
    put_dec(&mut line, &mut n, i64::from(s.sgi));
    put(&mut line, &mut n, b" rc=");
    put_dec(&mut line, &mut n, i64::from(rc));
    dev_log(&*s.syscalls, 3, line.as_ptr(), n);
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
    s.ticks = s.ticks.saturating_add(1);
    if s.ticks < s.every_ticks {
        return StepReturn::Continue;
    }
    s.ticks = 0;
    let mut arg = [s.core, s.sgi];
    let rc = ((*s.syscalls).provider_call)(
        -1,
        SIGNAL_CORE,
        arg.as_mut_ptr(),
        arg.len(),
        core::ptr::null_mut(),
        0,
    );
    if s.logged_first == 0 {
        s.logged_first = 1;
        report(s, rc);
    } else if rc < 0 && s.logged_refusal == 0 {
        s.logged_refusal = 1;
        report(s, rc);
    }
    StepReturn::Continue
}

fluxor_rt::wasm_entry!();
