//! block_wipe — zero the first `sectors` blocks of a block source.
//!
//! One block per request, a bounded number per step, then a `FLUSH`. The
//! verdict repeats on the log, because it lands long before a network log
//! transport is up to carry a single line:
//!
//! ```text
//! [block_wipe] done <sectors> worst_us=<slowest write>
//! [block_wipe] FAIL rc=<errno>
//! ```

#![no_std]
#![allow(
    dead_code,
    reason = "the PIC build mounts the whole of modules/sdk/* via include!, so every \
              module's compile sees the entire ABI surface while using a subset. This \
              allow is the SDK's textual mounting showing through"
)]
#![allow(
    unused_imports,
    reason = "same cause: the mounted SDK brings names this module does not reach for"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

/// Largest block this fixture writes.
const BLOCK_MAX: usize = 4096;
/// Blocks written per step: each is a synchronous request, and one device
/// round trip is all a step may hold.
const PER_STEP: u32 = 1;
/// Steps between repeats of the verdict.
const BEAT_STEPS: u32 = 5000;

#[repr(C)]
struct WipeState {
    syscalls: *const SyscallTable,
    blk: BlockClient,
    sectors: u32,
    cursor: u32,
    since_beat: u32,
    /// Slowest single write, in microseconds.
    worst_us: u32,
    /// 0 writing, 1 flushing, 2 done, 3 failed.
    phase: u8,
    _pad: [u8; 3],
    rc: i32,
}

mod params_def {
    use super::*;
    define_params! {
        WipeState;
        1, sectors, u32, 0 => |s, d, len| { s.sectors = p_u32(d, len, 0, 0); };
    }
}

unsafe fn say(s: &WipeState) {
    let mut out = [0u8; 48];
    let (head, n): (&[u8], u32) = if s.phase == 2 {
        (b"[block_wipe] done ", s.sectors)
    } else {
        (b"[block_wipe] FAIL rc=-", s.rc.unsigned_abs())
    };
    out[..head.len()].copy_from_slice(head);
    let mut pos = head.len();
    pos += fmt_u32_raw(out.as_mut_ptr().add(pos), n);
    if s.phase == 2 {
        let tail = b" worst_us=";
        out[pos..pos + tail.len()].copy_from_slice(tail);
        pos += tail.len();
        pos += fmt_u32_raw(out.as_mut_ptr().add(pos), s.worst_us);
    }
    dev_log(&*s.syscalls, 3, out.as_ptr(), pos);
}

unsafe fn finish(s: &mut WipeState, rc: i32) {
    s.rc = rc;
    s.phase = if rc == 0 { 2 } else { 3 };
    say(s);
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<WipeState>()
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<WipeState>() {
            return -2;
        }
        let s = &mut *(state as *mut WipeState);
        core::ptr::write_bytes(
            core::ptr::from_mut(s).cast::<u8>(),
            0,
            core::mem::size_of::<WipeState>(),
        );
        s.syscalls = syscalls as *const SyscallTable;
        s.blk.bind(in_chan);
        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
        0
    }
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut WipeState);
    let sys = &*s.syscalls;
    if s.phase >= 2 {
        s.since_beat += 1;
        if s.since_beat >= BEAT_STEPS {
            s.since_beat = 0;
            say(s);
        }
        return 0;
    }
    if s.sectors == 0 {
        finish(s, 0);
        return 0;
    }
    let rc = s.blk.caps(sys);
    if rc == E_AGAIN {
        return 0;
    }
    if rc != 0 {
        finish(s, rc);
        return 0;
    }
    let bs = s.blk.block_size() as usize;
    if bs == 0 || bs > BLOCK_MAX {
        finish(s, -22);
        return 0;
    }
    if u64::from(s.sectors) > s.blk.block_count() {
        finish(s, -22);
        return 0;
    }
    if s.phase == 0 {
        let zero = [0u8; BLOCK_MAX];
        let mut n = 0;
        while s.cursor < s.sectors && n < PER_STEP {
            let t0 = dev_micros(sys);
            let rc = s
                .blk
                .write(sys, u64::from(s.cursor), 1, zero.as_ptr(), false);
            let took = dev_micros(sys).wrapping_sub(t0);
            s.worst_us = s.worst_us.max(took.min(u64::from(u32::MAX)) as u32);
            if rc == E_AGAIN {
                return 0;
            }
            if rc < 0 {
                finish(s, rc);
                return 0;
            }
            s.cursor += 1;
            n += 1;
        }
        if s.cursor >= s.sectors {
            s.phase = 1;
        }
        return 0;
    }
    let rc = s.blk.flush(sys);
    if rc == E_AGAIN {
        return 0;
    }
    finish(s, rc);
    0
}
