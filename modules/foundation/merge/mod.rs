//! merge — several producers into one consumer's port.
//!
//! The composer puts a merge on an input wired from more than one output:
//! each producer writes to one of the merge's inputs, and the consumer
//! reads its `out0`. The inputs are served round robin, so a producer that
//! always has something waiting cannot keep the others out, and a unit
//! moves only when the output can take it whole: nothing is consumed that
//! cannot be written in the same step, and nothing is held between steps.
//!
//! What a unit is comes from the `frame_kind` param (see `../tee/fan.rs`):
//! a stream moves one transfer a step, and an input a transfer was cut
//! short on is drained to empty before another is read, so a unit the cut
//! split is finished before another producer's bytes follow it; a framed
//! kind moves whole frames, up to `frames_per_step` a step; a record kind
//! moves one mailbox record per transfer.

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

/// One stream transfer from the owed input, else the first in the round
/// robin with bytes waiting.
unsafe fn merge_stream(s: &mut FanState) -> Result<(), i32> {
    if s.owed >= 0 && !polls(s, s.lanes[s.owed as usize], POLL_IN) {
        s.owed = -1;
    }
    for _ in 0..s.lanes_len {
        let k = if s.owed >= 0 {
            s.owed as usize
        } else {
            next_lane(s)
        };
        let chan = s.lanes[k];
        if !polls(s, chan, POLL_IN) {
            continue;
        }
        let amount = (s.scratch_len as usize).min(writable(s, s.one));
        if amount == 0 {
            if s.owed >= 0 {
                // The owed input waits for room; nothing else may go first.
                return Ok(());
            }
            continue;
        }
        let read = ((*s.syscalls).channel_read)(chan, s.scratch, amount);
        if read <= 0 {
            continue;
        }
        put(s, s.one, read as usize)?;
        // Cut short when the transfer filled `amount` and bytes remain.
        s.owed = if read as usize == amount && polls(s, chan, POLL_IN) {
            k as i8
        } else {
            -1
        };
        return Ok(());
    }
    Ok(())
}

/// One round-robin pass, moving the first whole frame that fits the output:
/// `Ok(false)` when the pass moved nothing.
unsafe fn merge_frame(s: &mut FanState) -> Result<bool, i32> {
    for _ in 0..s.lanes_len {
        let chan = s.lanes[next_lane(s)];
        let room = |total: usize| writable(s, s.one) >= total;
        if let Some(total) = take_frame(s, chan, room)? {
            put(s, s.one, total)?;
            return Ok(true);
        }
    }
    Ok(false)
}

/// One round-robin pass, moving the first record waiting once the output is
/// free: `Ok(false)` when the pass moved nothing.
unsafe fn merge_record(s: &mut FanState) -> Result<bool, i32> {
    if !polls(s, s.one, POLL_OUT) {
        return Ok(false);
    }
    for _ in 0..s.lanes_len {
        let chan = s.lanes[next_lane(s)];
        if !polls(s, chan, POLL_IN) {
            continue;
        }
        if let Some(len) = take_record(s, chan)? {
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
    match s.frame_kind {
        KIND_STREAM => match merge_stream(s) {
            Ok(()) => StepReturn::Continue,
            Err(e) => StepReturn::error(e),
        },
        KIND_RECORD => burst(s, |s| merge_record(s)),
        _ => burst(s, |s| merge_frame(s)),
    }
}

fluxor_rt::wasm_entry!();
