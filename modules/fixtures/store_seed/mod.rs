//! Write one store object at boot — the bare-metal counterpart of the Linux
//! runtime's `FLUXOR_STORE_DIR` log.
//!
//! On Linux an E2E seeds the store by appending to its log before the runtime
//! starts: single writer, runtime down. Bare metal has no log and no
//! filesystem, so a graph that wants to exercise a store-driven chain has
//! nothing to react to — the store comes up empty and every source sits idle,
//! correctly and uselessly.
//!
//! This writes its `key` = `value` once, on its first step, and then does
//! nothing. It is a FIXTURE: in a real deployment objects arrive from whatever
//! writes them, and seeding from a graph parameter is how a test supplies a
//! precondition that would otherwise have to be created by that writer.
//!
//! Writes ONCE, not every step: a repeated PUT bumps the revision each time,
//! which would wake every watcher on the prefix forever and make an idle graph
//! look busy.

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

// The opcode comes from the contract this fixture drives, not from a
// literal: a seeder that restates the wire can write against its own copy.
const OBJ_PUT: u32 = abi::contracts::storage::object::PUT;
const MAX_KEY: usize = 192;
const MAX_VALUE: usize = 1024;

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    key: [u8; MAX_KEY],
    key_len: u32,
    value: [u8; MAX_VALUE],
    value_len: u32,
    written: u32,
    ticks: u32,
    rc: i32,
}

mod params_def {
    use super::ptr_copy;
    use super::State;
    use super::MAX_KEY;
    use super::MAX_VALUE;
    use super::SCHEMA_MAX;

    define_params! {
        State;

        1, key, str, 0
            => |s, d, len| {
                let n = if len > MAX_KEY { MAX_KEY } else { len };
                s.key_len = n as u32;
                if n > 0 { ptr_copy(s.key.as_mut_ptr(), d, n); }
            };

        2, value, str, 0
            => |s, d, len| {
                let n = if len > MAX_VALUE { MAX_VALUE } else { len };
                s.value_len = n as u32;
                if n > 0 { ptr_copy(s.value.as_mut_ptr(), d, n); }
            };
    }
}

#[inline(always)]
unsafe fn ptr_copy(dst: *mut u8, src: *const u8, n: usize) {
    core::ptr::copy_nonoverlapping(src, dst, n);
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point.
#[no_mangle]
#[link_section = ".text.module_new"]
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
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<State>() {
            return -2;
        }
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        s.key_len = 0;
        s.value_len = 0;
        s.written = 0;
        s.ticks = 0;
        s.rc = 0;
        params_def::set_defaults(s);
        params_def::parse_tlv(s, params, params_len);
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return 0;
        }
        let s = &mut *(state as *mut State);
        if s.syscalls.is_null() {
            return 0;
        }
        // Unconditional heartbeat, ahead of every other check: "did this module
        // step at all" and "did it do its work" are different questions, and
        // answering only the second leaves silence meaning both.
        s.ticks = s.ticks.wrapping_add(1);
        if s.ticks % 1000 == 1 {
            let m = b"[seed] alive";
            dev_log(&*s.syscalls, 3, m.as_ptr(), m.len());
        }
        if s.written != 0 {
            return 0;
        }
        // An EMPTY key is reported, not skipped. Returning quietly here is how
        // a params mistake becomes a graph that boots, looks healthy and seeds
        // nothing — the failure mode is indistinguishable from a store that
        // dropped the write, and it costs a rig cycle to tell them apart.
        if s.key_len == 0 {
            s.written = 1;
            // Level 3, like the success line: a diagnostic that only appears
            // at a level the transport filters is a diagnostic that does not
            // exist. This one exists precisely for the case where something
            // upstream went wrong, so it must not be the quiet one.
            let m = b"[seed] NO KEY - params did not reach the module";
            dev_log(&*s.syscalls, 3, m.as_ptr(), m.len());
            return 0;
        }
        let sys = &*s.syscalls;
        let key = &s.key[..s.key_len as usize];
        let val = &s.value[..s.value_len as usize];

        // [key_len:u16][key][ct_len:u8][body_ptr:u64][body_len:u64]
        // [precondition:u8][etag_len:u8][fence_ptr:u64][fence_cap:u16]
        let mut arg = [0u8; 256];
        let mut p = 0usize;
        arg[0..2].copy_from_slice(&(key.len() as u16).to_le_bytes());
        p += 2;
        arg[p..p + key.len()].copy_from_slice(key);
        p += key.len();
        arg[p] = 0;
        p += 1;
        arg[p..p + 8].copy_from_slice(&(val.as_ptr() as u64).to_le_bytes());
        p += 8;
        arg[p..p + 8].copy_from_slice(&(val.len() as u64).to_le_bytes());
        p += 8;
        arg[p] = 0; // precondition ANY
        arg[p + 1] = 0;
        p += 2;
        arg[p..p + 8].copy_from_slice(&0u64.to_le_bytes());
        p += 8;
        arg[p..p + 2].copy_from_slice(&0u16.to_le_bytes());
        p += 2;
        s.rc = (sys.provider_call)(-1, OBJ_PUT, arg.as_mut_ptr(), p);
        s.written = 1;

        let mut buf = [0u8; 96];
        let pb = buf.as_mut_ptr();
        let pre = b"[seed] rc=";
        core::ptr::copy_nonoverlapping(pre.as_ptr(), pb, pre.len());
        let mut pos = pre.len();
        let v = s.rc.unsigned_abs();
        let mut tmp = [0u8; 10];
        let mut n = 0usize;
        let mut x = v;
        if x == 0 {
            tmp[0] = b'0';
            n = 1;
        }
        while x > 0 {
            tmp[n] = b'0' + (x % 10) as u8;
            x /= 10;
            n += 1;
        }
        for i in 0..n {
            *pb.add(pos + i) = tmp[n - 1 - i];
        }
        pos += n;
        let k = b" key=";
        core::ptr::copy_nonoverlapping(k.as_ptr(), pb.add(pos), k.len());
        pos += k.len();
        let kn = key.len().min(48);
        core::ptr::copy_nonoverlapping(key.as_ptr(), pb.add(pos), kn);
        pos += kn;
        dev_log(sys, 3, pb, pos);
        0
    }
}
