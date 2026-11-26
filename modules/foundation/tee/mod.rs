//! tee — one producer's port to several consumers.
//!
//! The composer puts a tee on an output wired to more than one input: the
//! producer writes to the tee's `in0`, and each consumer reads one of its
//! outputs. Every output gets every unit the producer wrote, in order and
//! whole, and a record is taken off `in0` only once every output can take it:
//! one slow consumer holds the stream for all of them, so back pressure
//! reaches the producer and nothing is dropped or held between steps.
//!
//! A unit is one record — one write of the producer, whatever it holds —
//! moved whole, up to `frames_per_step` a step (see `fan.rs`).

#![cfg_attr(not(feature = "host-test"), no_std)]

use core::ffi::c_void;

use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

include!("fan.rs");

/// Move one record to every output: `Ok(false)` when none moved.
unsafe fn tee_record(s: &mut FanState) -> Result<bool, i32> {
    let n = s.lanes_len as usize;
    let room = |len: usize| (0..n).all(|k| takes(s, s.lanes[k], len));
    let Some(len) = take(s, s.one, room)? else {
        return Ok(false);
    };
    for k in 0..n {
        put(s, s.lanes[k], len)?;
    }
    Ok(true)
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
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
    construct(
        Wiring {
            one: in_chan,
            first: out_chan,
            many_dir: 1,
        },
        params,
        params_len,
        state,
        state_size,
        syscalls,
    )
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> StepReturn {
    let s = &mut *(state as *mut FanState);
    burst(s, |s| tee_record(s))
}

fluxor_rt::wasm_entry!();
