//! el0_cost — what a step costs a module behind the gateway.
//!
//! Each step reads what its peer wrote, makes `writes` channel writes and
//! `calls` `timer.MICROS` provider calls, and times its own body. Every
//! 1000 steps it reports the bodies' total and the window's wall time, so a
//! pair of instances — one isolated, one privileged — at 0 and at 10 ops
//! gives the EL0 round trip and the per-op slope.

#![cfg_attr(not(feature = "host-test"), no_std)]

use core::ffi::c_void;

use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

/// Steps per report.
const WINDOW: u32 = 1000;

#[repr(C)]
pub struct State {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    /// When the window began, microseconds; 0 before the first step.
    window_start_us: u64,
    /// The window's step bodies, microseconds.
    body_us: u64,
    steps: u32,
    tag: u8,
    writes: u8,
    calls: u8,
}

mod params_def {
    use super::p_u8;
    use super::State;

    fluxor_rt::define_params! {
        State;
        1, tag, u8, 97
            => |s, d, len| { s.tag = p_u8(d, len, 0, 97); };
        2, writes, u8, 0
            => |s, d, len| { s.writes = p_u8(d, len, 0, 0); };
        3, calls, u8, 0
            => |s, d, len| { s.calls = p_u8(d, len, 0, 0); };
    }
}

fn put(line: &mut [u8], n: &mut usize, b: &[u8]) {
    for &c in b {
        if *n < line.len() {
            line[*n] = c;
            *n += 1;
        }
    }
}

fn put_dec(line: &mut [u8], n: &mut usize, v: u64) {
    let mut x = v;
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
    in_chan: i32,
    out_chan: i32,
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
    s.in_chan = in_chan;
    s.out_chan = out_chan;
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
    let sys = &*s.syscalls;
    let t0 = dev_micros(sys);
    if s.window_start_us == 0 {
        s.window_start_us = t0;
    }
    let mut buf = [0u8; 16];
    if s.in_chan >= 0 {
        while (sys.channel_read)(s.in_chan, buf.as_mut_ptr(), buf.len()) > 0 {}
    }
    let mut i = 0;
    while i < s.writes {
        if s.out_chan >= 0 {
            let _ = (sys.channel_write)(s.out_chan, buf.as_ptr(), 4);
        }
        i += 1;
    }
    let mut i = 0;
    while i < s.calls {
        let _ = dev_micros(sys);
        i += 1;
    }
    let t1 = dev_micros(sys);
    s.body_us += t1.saturating_sub(t0);
    s.steps = s.steps.wrapping_add(1);
    if s.steps.is_multiple_of(WINDOW) {
        let mut line = [0u8; 96];
        let mut n = 0;
        put(&mut line, &mut n, b"[el0_cost] ");
        put(&mut line, &mut n, &[s.tag]);
        put(&mut line, &mut n, b" steps=");
        put_dec(&mut line, &mut n, u64::from(s.steps));
        put(&mut line, &mut n, b" body_us=");
        put_dec(&mut line, &mut n, s.body_us);
        put(&mut line, &mut n, b" win_us=");
        put_dec(&mut line, &mut n, t1.saturating_sub(s.window_start_us));
        dev_log(sys, 3, line.as_ptr(), n);
        s.body_us = 0;
        s.window_start_us = t1;
    }
    StepReturn::Continue
}

fluxor_rt::wasm_entry!();
