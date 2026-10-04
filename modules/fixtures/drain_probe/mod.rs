//! drain_probe — a module whose drain takes several steps.
//!
//! `module_drain` marks it draining and answers 0: it has work in flight.
//! It then keeps stepping for `finish_after_steps` steps, logs that it has
//! drained and returns Done. With `hold` set it never finishes, so the
//! runtime's drain deadline is what ends the stop.

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

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    started: u8,
    draining: u8,
    /// Never finish draining.
    hold: u8,
    /// Steps of drain work left.
    left: u32,
    /// Steps a drain takes. Default 20.
    finish_after_steps: u32,
}

mod params_def {
    use super::p_u32;
    use super::p_u8;
    use super::State;
    use super::SCHEMA_MAX;

    define_params! {
        State;

        1, finish_after_steps, u32, 20
            => |s, d, len| { s.finish_after_steps = p_u32(d, len, 0, 20); };

        2, hold, u8, 0
            => |s, d, len| { s.hold = p_u8(d, len, 0, 0); };
    }
}

unsafe fn say(s: &State, m: &[u8]) {
    dev_log(&*s.syscalls, 3, m.as_ptr(), m.len());
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if state.is_null() || syscalls.is_null() {
        return -1;
    }
    if state_size < core::mem::size_of::<State>() {
        return -2;
    }
    unsafe {
        core::ptr::write_bytes(state, 0, core::mem::size_of::<State>());
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
    }
    0
}

#[no_mangle]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(state: *mut u8) -> i32 {
    if state.is_null() {
        return -1;
    }
    unsafe {
        let s = &mut *(state as *mut State);
        s.draining = 1;
        s.left = s.finish_after_steps;
        say(s, b"[drain_probe] draining");
    }
    0
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut State);
        if s.syscalls.is_null() {
            return 0;
        }
        if s.started == 0 {
            s.started = 1;
            say(s, b"[drain_probe] up");
        }
        if s.draining == 0 || s.hold != 0 {
            return 0;
        }
        if s.left > 0 {
            s.left -= 1;
            return 0;
        }
        say(s, b"[drain_probe] drained");
        1
    }
}

include!("../../sdk/runtime/wasm_entry.rs");
