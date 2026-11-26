//! merge — several producers into one consumer's port.
//!
//! The composer puts a merge on an input wired from more than one output:
//! each producer writes to one of the merge's inputs, and the consumer
//! reads its `out0`. The inputs are served round robin, so a producer that
//! always has something waiting cannot keep the others out, and a unit
//! moves only when the output can take it whole: nothing is consumed that
//! cannot be written in the same step, and nothing is held between steps.
//!
//! A unit is one record — one write of a producer, whatever it holds —
//! moved whole, up to `frames_per_step` a step (see `../tee/fan.rs`), so no
//! producer's record is ever split by another's.

#![cfg_attr(not(feature = "host-test"), no_std)]

use core::ffi::c_void;

use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

include!("../tee/fan.rs");

/// The input after the round robin's last, advancing it.
#[inline(always)]
fn next_lane(s: &mut FanState) -> usize {
    // `next` stays below `lanes_len`, which is fixed at construction, so a
    // compare wraps it (no divide on a core without one).
    let k = s.next;
    s.next = if k + 1 >= s.lanes_len { 0 } else { k + 1 };
    k as usize
}

/// One round-robin pass, moving the first record waiting that the output
/// takes: `Ok(false)` when the pass moved nothing.
unsafe fn merge_record(s: &mut FanState) -> Result<bool, i32> {
    for _ in 0..s.lanes_len {
        let chan = s.lanes[next_lane(s)];
        let room = |len: usize| takes(s, s.one, len);
        if let Some(len) = take(s, chan, room)? {
            put(s, s.one, len)?;
            return Ok(true);
        }
    }
    Ok(false)
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
            one: out_chan,
            first: in_chan,
            many_dir: 0,
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
    burst(s, |s| merge_record(s))
}

fluxor_rt::wasm_entry!();
