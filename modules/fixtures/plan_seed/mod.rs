//! plan_seed — reports how many workload owners the node holds.
//!
//! Subscribes to the kernel telemetry ring for PSTATUS records at
//! `interval_ms`, and logs the `owners` pool's in-use figure from each `POOL`
//! record for it, when it differs from the last one logged.

#![cfg_attr(not(feature = "host-test"), no_std)]

use core::ffi::c_void;

use abi::contracts::resource::POOL_OWNERS;
use abi::contracts::telemetry as tlm;
use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

/// Bytes drained per step; whole records only.
const BATCH: usize = 256;

#[repr(C)]
pub struct State {
    syscalls: *const SyscallTable,
    /// The telemetry slot `TLM_SUBSCRIBE` answered, or the errno.
    slot: i32,
    /// The PSTATUS cadence asked of the kernel, in ms.
    interval_ms: u32,
    /// The last in-use figure logged, `u64::MAX` before the first.
    last: u64,
}

mod params_def {
    use super::p_u32;
    use super::State;

    fluxor_rt::define_params! {
        State;
        1, interval_ms, u32, 1000
            => |s, d, len| { let v = p_u32(d, len, 0, 1000); s.interval_ms = if v == 0 { 1000 } else { v }; };
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

fn put_dec(line: &mut [u8], n: &mut usize, mut x: u64) {
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

/// Log the owners pool from one `POOL` record, when its figure changed.
unsafe fn take(s: &mut State, rec: &[u8]) {
    if tlm::signal(rec) != tlm::SIGNAL_PSTATUS
        || tlm::kind(rec) != tlm::PSTATUS_POOL
        || tlm::pstatus_pool_id(rec) != POOL_OWNERS
    {
        return;
    }
    let cur = tlm::pstatus_pool_cur(rec);
    if cur == s.last {
        return;
    }
    s.last = cur;
    let mut line = [0u8; 64];
    let mut n = 0;
    put(&mut line, &mut n, b"[plan] owners in_use=");
    put_dec(&mut line, &mut n, cur);
    put(&mut line, &mut n, b" cap=");
    put_dec(&mut line, &mut n, tlm::pstatus_pool_cap(rec));
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
    s.last = u64::MAX;
    params_def::set_defaults(s);
    if !params.is_null() && params_len > 0 {
        params_def::parse_tlv(s, params, params_len);
    }
    // `[filter u32][interval ms u64]`: PSTATUS records, at this cadence.
    let mut sub = [0u8; tlm::SUBSCRIBE_INTERVAL_OFFSET + 8];
    sub[..4].copy_from_slice(&tlm::FILTER_PSTATUS.to_le_bytes());
    sub[tlm::SUBSCRIBE_INTERVAL_OFFSET..].copy_from_slice(&u64::from(s.interval_ms).to_le_bytes());
    s.slot = ((*s.syscalls).provider_call)(
        -1,
        tlm::TLM_SUBSCRIBE,
        sub.as_mut_ptr(),
        sub.len(),
        core::ptr::null_mut(),
        0,
    );
    0
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_step")]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> StepReturn {
    let s = &mut *(state as *mut State);
    if s.slot < 0 {
        return StepReturn::Continue;
    }
    let mut batch = [0u8; BATCH];
    let n = ((*s.syscalls).provider_call)(
        s.slot,
        tlm::TLM_DRAIN,
        core::ptr::null_mut(),
        0,
        batch.as_mut_ptr(),
        BATCH,
    );
    if n <= 0 {
        return StepReturn::Continue;
    }
    let n = n as usize;
    let mut off = 0;
    while off + tlm::HEADER_SIZE <= n {
        let len = tlm::record_len(tlm::signal(&batch[off..]), tlm::kind(&batch[off..]));
        if len == 0 || off + len > n {
            break;
        }
        take(s, &batch[off..off + len]);
        off += len;
    }
    StepReturn::Continue
}

fluxor_rt::wasm_entry!();
