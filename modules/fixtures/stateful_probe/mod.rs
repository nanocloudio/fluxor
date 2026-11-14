//! stateful_probe — the smallest stateful workload over a block source.
//!
//! Block 0 of the source holds `[magic:4][epoch:4]`. Every start reads it,
//! takes the epoch (0 when the magic is absent), adds one, writes the block
//! back, flushes, reads it again to check the device returns what it was
//! given, and logs:
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
    unreachable_patterns,
    reason = "defensive `_ => Error` arms in enum state-machine matches. The match is \
              exhaustive, which is why the lint fires; the arm exists so that adding a \
              variant cannot silently bypass the error path. #[expect] is not the \
              alternative — it fails the build in the configurations where the lint \
              does not fire"
)]

use core::ffi::c_void;

use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

/// Largest block this fixture handles.
const BLOCK_MAX: usize = 4096;
/// Steps between repeats of the verdict.
const BEAT_STEPS: u32 = 5000;
/// "STFL"
const MAGIC: u32 = 0x5354_464C;

const PH_READ: u8 = 0;
const PH_WRITE: u8 = 1;
const PH_FLUSH: u8 = 2;
const PH_VERIFY: u8 = 3;
const PH_DONE: u8 = 4;
const PH_FAILED: u8 = 5;

fluxor_rt::name_table!(PHASE_NAMES = [b"read", b"write", b"flush", b"verify", b"done", b"failed"]);

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
    fluxor_rt::define_params! {
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

fluxor_rt::module_facts! { state: ProbeState }

/// # Safety
/// Kernel module-ABI entry point: `syscalls` is the kernel's syscall table,
/// valid for the module's lifetime.
#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
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

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> StepReturn {
    let s = &mut *(state as *mut ProbeState);
    let sys = &*s.syscalls;
    if s.phase >= PH_DONE {
        s.since_beat += 1;
        if s.since_beat >= BEAT_STEPS {
            s.since_beat = 0;
            say(s);
        }
        return StepReturn::Continue;
    }
    let rc = s.blk.caps(sys);
    if rc == E_AGAIN {
        return StepReturn::Continue;
    }
    if rc != 0 {
        fail(s, rc);
        return StepReturn::Continue;
    }
    let bs = s.blk.block_size() as usize;
    if bs == 0 || bs > BLOCK_MAX || s.blk.block_count() == 0 {
        fail(s, E_INVAL);
        return StepReturn::Continue;
    }
    match s.phase {
        PH_READ => {
            let rc = s.blk.read(sys, 0, 1, s.block.as_mut_ptr());
            if rc == E_AGAIN {
                return StepReturn::Continue;
            }
            if rc < 0 {
                fail(s, rc);
                return StepReturn::Continue;
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
            StepReturn::Continue
        }
        PH_WRITE => {
            let rc = s.blk.write(sys, 0, 1, s.block.as_ptr(), false);
            if rc == E_AGAIN {
                return StepReturn::Continue;
            }
            if rc < 0 {
                fail(s, rc);
                return StepReturn::Continue;
            }
            s.phase = PH_FLUSH;
            StepReturn::Continue
        }
        PH_FLUSH => {
            let rc = s.blk.flush(sys);
            if rc == E_AGAIN {
                return StepReturn::Continue;
            }
            if rc < 0 {
                fail(s, rc);
                return StepReturn::Continue;
            }
            s.phase = PH_VERIFY;
            StepReturn::Continue
        }
        PH_VERIFY => {
            let rc = s.blk.read(sys, 0, 1, s.block.as_mut_ptr());
            if rc == E_AGAIN {
                return StepReturn::Continue;
            }
            if rc < 0 {
                fail(s, rc);
                return StepReturn::Continue;
            }
            let magic = u32::from_le_bytes([s.block[0], s.block[1], s.block[2], s.block[3]]);
            let epoch = u32::from_le_bytes([s.block[4], s.block[5], s.block[6], s.block[7]]);
            if magic != MAGIC || epoch != s.epoch {
                fail(s, E_IO);
                return StepReturn::Continue;
            }
            s.phase = PH_DONE;
            say(s);
            StepReturn::Continue
        }
        _ => StepReturn::Continue,
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
fluxor_rt::wasm_entry!();
