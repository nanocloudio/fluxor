//! stateful_probe — the smallest stateful workload over a block source.
//!
//! Block 0 of the source holds `[magic:4][epoch:4]`. Every start reads it,
//! takes the epoch (0 when the magic is absent), adds one, writes the block
//! back, flushes, and logs:
//!
//! ```text
//! [stateful_probe] epoch=<n>
//! [stateful_probe] FAIL <phase> rc=-<errno>
//! ```
//!
//! Staged as a workload's subgraph over a volume — a block source that
//! outlives the workload, such as loam's `loam_volume` — epoch=1 then
//! epoch=2 across two starts proves the workload's state lived in the
//! volume between them: a stateful workload on a node that runs module
//! subgraphs rather than processes.

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
#![allow(
    unreachable_patterns,
    reason = "defensive `_ => Error` arms in enum state-machine matches. The match is \
              exhaustive, which is why the lint fires; the arm exists so that adding a \
              variant cannot silently bypass the error path. #[expect] is not the \
              alternative — it fails the build in the configurations where the lint \
              does not fire"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

/// Largest block this fixture handles.
const BLOCK_MAX: usize = 4096;
/// Steps between repeats of the verdict.
const BEAT_STEPS: u32 = 5000;
/// "STFL"
const MAGIC: u32 = 0x5354_464C;

const PH_READ: u8 = 0;
const PH_WRITE: u8 = 1;
const PH_FLUSH: u8 = 2;
const PH_DONE: u8 = 3;
const PH_FAILED: u8 = 4;

name_table!(PHASE_NAMES = [b"read", b"write", b"flush", b"done", b"failed"]);

#[repr(C)]
struct ProbeState {
    syscalls: *const SyscallTable,
    blk: BlockClient,
    epoch: u32,
    since_beat: u32,
    phase: u8,
    _pad: [u8; 3],
    rc: i32,
    verdict_phase: u8,
    _pad2: [u8; 3],
    block: [u8; BLOCK_MAX],
}

mod params_def {
    use super::*;
    define_params! {
        ProbeState;
    }
}

unsafe fn say(s: &ProbeState) {
    let mut out = [0u8; 64];
    let mut pos = 0usize;
    if s.phase == PH_DONE {
        let head = b"[stateful_probe] epoch=";
        core::ptr::copy_nonoverlapping(head.as_ptr(), out.as_mut_ptr(), head.len());
        pos += head.len();
        pos += fmt_u32_raw(out.as_mut_ptr().add(pos), s.epoch);
        dev_log(&*s.syscalls, 3, out.as_ptr(), pos);
    } else {
        let head = b"[stateful_probe] FAIL ";
        core::ptr::copy_nonoverlapping(head.as_ptr(), out.as_mut_ptr(), head.len());
        pos += head.len();
        let name = PHASE_NAMES.get(s.verdict_phase as usize);
        core::ptr::copy_nonoverlapping(name.as_ptr(), out.as_mut_ptr().add(pos), name.len());
        pos += name.len();
        let mid = b" rc=-";
        core::ptr::copy_nonoverlapping(mid.as_ptr(), out.as_mut_ptr().add(pos), mid.len());
        pos += mid.len();
        pos += fmt_u32_raw(out.as_mut_ptr().add(pos), s.rc.unsigned_abs());
        dev_log(&*s.syscalls, 4, out.as_ptr(), pos);
    }
}

unsafe fn fail(s: &mut ProbeState, rc: i32) {
    s.rc = rc;
    s.verdict_phase = s.phase;
    s.phase = PH_FAILED;
    say(s);
}

declare_module_state_bytes!(ProbeState);

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<ProbeState>()
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
        if state_size < core::mem::size_of::<ProbeState>() {
            return -2;
        }
        let s = &mut *(state as *mut ProbeState);
        core::ptr::write_bytes(
            core::ptr::from_mut(s).cast::<u8>(),
            0,
            core::mem::size_of::<ProbeState>(),
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
    let s = &mut *(state as *mut ProbeState);
    let sys = &*s.syscalls;
    if s.phase >= PH_DONE {
        s.since_beat += 1;
        if s.since_beat >= BEAT_STEPS {
            s.since_beat = 0;
            say(s);
        }
        return 0;
    }
    let rc = s.blk.caps(sys);
    if rc == E_AGAIN {
        return 0;
    }
    if rc != 0 {
        fail(s, rc);
        return 0;
    }
    let bs = s.blk.block_size() as usize;
    if bs == 0 || bs > BLOCK_MAX || s.blk.block_count() == 0 {
        fail(s, E_INVAL);
        return 0;
    }
    match s.phase {
        PH_READ => {
            let rc = s.blk.read(sys, 0, 1, s.block.as_mut_ptr());
            if rc == E_AGAIN {
                return 0;
            }
            if rc < 0 {
                fail(s, rc);
                return 0;
            }
            let magic = u32::from_le_bytes([s.block[0], s.block[1], s.block[2], s.block[3]]);
            let was = if magic == MAGIC {
                u32::from_le_bytes([s.block[4], s.block[5], s.block[6], s.block[7]])
            } else {
                0
            };
            s.epoch = was.wrapping_add(1);
            let mut i = 0usize;
            while i < bs {
                s.block[i] = 0;
                i += 1;
            }
            let m = MAGIC.to_le_bytes();
            let e = s.epoch.to_le_bytes();
            let mut i = 0usize;
            while i < 4 {
                s.block[i] = m[i];
                s.block[4 + i] = e[i];
                i += 1;
            }
            s.phase = PH_WRITE;
            0
        }
        PH_WRITE => {
            let rc = s.blk.write(sys, 0, 1, s.block.as_ptr(), false);
            if rc == E_AGAIN {
                return 0;
            }
            if rc < 0 {
                fail(s, rc);
                return 0;
            }
            s.phase = PH_FLUSH;
            0
        }
        PH_FLUSH => {
            let rc = s.blk.flush(sys);
            if rc == E_AGAIN {
                return 0;
            }
            if rc < 0 {
                fail(s, rc);
                return 0;
            }
            s.phase = PH_DONE;
            say(s);
            0
        }
        _ => 0,
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
include!("../../sdk/runtime/wasm_entry.rs");
