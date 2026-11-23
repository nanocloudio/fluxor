//! step_probe — a module whose stepping is the evidence.
//!
//! Placed in a domain, it shows that domain's loop kept running: it reports
//! its steps and the longest it waited between two of them. It holds no
//! grant, so it may be placed on any core.

#![cfg_attr(not(feature = "host-test"), no_std)]

use core::ffi::c_void;

use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

/// How often it reports.
const REPORT_US: u64 = 1_000_000;

#[repr(C)]
pub struct State {
    syscalls: *const SyscallTable,
    /// When the last step ran, microseconds; 0 before the first.
    last_step_us: u64,
    /// When the next report is due, microseconds.
    next_due_us: u64,
    /// Steps taken.
    steps: u32,
    /// The longest wait between two steps since the last report.
    gap_us: u32,
    /// One letter naming this instance in its lines.
    tag: u8,
    /// Ask to be stepped again at once, as a module with work always
    /// pending does.
    busy: u8,
}

mod params_def {
    use super::p_u8;
    use super::State;

    fluxor_rt::define_params! {
        State;
        1, tag, u8, 97
            => |s, d, len| { s.tag = p_u8(d, len, 0, 97); };
        2, busy, u8, 0
            => |s, d, len| { s.busy = p_u8(d, len, 0, 0); };
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

fn put_dec(line: &mut [u8], n: &mut usize, v: u32) {
    let mut x = v;
    let mut d = [0u8; 10];
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
    s.steps = s.steps.wrapping_add(1);
    let sys = &*s.syscalls;
    let now = dev_micros(sys);
    if s.last_step_us != 0 {
        let gap = now.saturating_sub(s.last_step_us).min(u64::from(u32::MAX)) as u32;
        if gap > s.gap_us {
            s.gap_us = gap;
        }
    }
    s.last_step_us = now;
    let again = if s.busy != 0 {
        StepReturn::Burst
    } else {
        StepReturn::Continue
    };
    if s.next_due_us == 0 {
        s.next_due_us = now + REPORT_US;
        return again;
    }
    if now < s.next_due_us {
        return again;
    }
    s.next_due_us = now + REPORT_US;

    let mut line = [0u8; 64];
    let mut n = 0;
    put(&mut line, &mut n, b"[step_probe] ");
    put(&mut line, &mut n, &[s.tag]);
    put(&mut line, &mut n, b" steps=");
    put_dec(&mut line, &mut n, s.steps);
    put(&mut line, &mut n, b" gap_us=");
    put_dec(&mut line, &mut n, s.gap_us);
    s.gap_us = 0;
    dev_log(sys, 3, line.as_ptr(), n);
    again
}

fluxor_rt::wasm_entry!();
