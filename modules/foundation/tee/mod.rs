//! tee — one producer's port to several consumers.
//!
//! The composer puts a tee on an output wired to more than one input: the
//! producer writes to the tee's `in0`, and each consumer reads one of its
//! outputs. Every output gets every unit the producer wrote, in order and
//! whole, and a unit is taken off `in0` only once every output can take it:
//! one slow consumer holds the stream for all of them, so back pressure
//! reaches the producer and nothing is dropped or held between steps.
//!
//! What a unit is comes from the `frame_kind` param (see `fan.rs`): a
//! stream moves as many bytes as every output has room for, one transfer a
//! step; a framed kind moves whole frames, up to `frames_per_step` a step; a
//! record kind moves one mailbox record per transfer.

#![cfg_attr(not(feature = "host-test"), no_std)]

use core::ffi::c_void;

use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

include!("fan.rs");

/// Move one stream transfer: as many bytes as the scratch and every output
/// take.
unsafe fn tee_stream(s: &mut FanState) -> Result<(), i32> {
    let n = s.lanes_len as usize;
    let mut amount = s.scratch_len as usize;
    for k in 0..n {
        amount = amount.min(writable(s, s.lanes[k]));
    }
    if amount == 0 {
        return Ok(());
    }
    let read = ((*s.syscalls).channel_read)(s.one, s.scratch, amount);
    if read <= 0 {
        return Ok(());
    }
    for k in 0..n {
        put(s, s.lanes[k], read as usize)?;
    }
    Ok(())
}

/// Move one whole frame to every output: `Ok(false)` when none moved.
unsafe fn tee_frame(s: &mut FanState) -> Result<bool, i32> {
    let n = s.lanes_len as usize;
    let room = |total: usize| (0..n).all(|k| writable(s, s.lanes[k]) >= total);
    let Some(total) = take_frame(s, s.one, room)? else {
        return Ok(false);
    };
    for k in 0..n {
        put(s, s.lanes[k], total)?;
    }
    Ok(true)
}

/// Move one record to every output, once every output is free to take it:
/// `Ok(false)` when none moved.
unsafe fn tee_record(s: &mut FanState) -> Result<bool, i32> {
    let n = s.lanes_len as usize;
    if !polls(s, s.one, POLL_IN) || !(0..n).all(|k| polls(s, s.lanes[k], POLL_OUT)) {
        return Ok(false);
    }
    let Some(len) = take_record(s, s.one)? else {
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
    match s.frame_kind {
        KIND_STREAM => match tee_stream(s) {
            Ok(()) => StepReturn::Continue,
            Err(e) => StepReturn::error(e),
        },
        KIND_RECORD => burst(s, |s| tee_record(s)),
        _ => burst(s, |s| tee_frame(s)),
    }
}

fluxor_rt::wasm_entry!();
