//! Churn workload body. `mode` 0 (source): write a LE u32 step counter on
//! `data_out` each step. `mode` 1 (relay): copy `data_in` to `data_out`.
//! Silent — the workload is created and reaped hundreds of times per run, and
//! the driver reports what reaches its lane.

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

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    mode: u8,
    _pad: [u8; 3],
    count: u32,
}

mod params_def {
    use super::p_u8;
    use super::State;
    use super::SCHEMA_MAX;

    define_params! {
        State;

        1, mode, u8, 0, enum { source=0, relay=1 }
            => |s, d, len| { s.mode = p_u8(d, len, 0, 0); };
    }
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
    in_chan: i32,
    out_chan: i32,
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
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.mode = 0;
        s.count = 0;
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
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut State);
        if s.syscalls.is_null() || s.out_chan < 0 {
            return 0;
        }
        let sys = &*s.syscalls;
        if s.mode == 0 {
            s.count = s.count.wrapping_add(1);
            let b = s.count.to_le_bytes();
            let _ = (sys.channel_write)(s.out_chan, b.as_ptr(), b.len());
        } else if s.in_chan >= 0 {
            let mut buf = [0u8; 64];
            let n = (sys.channel_read)(s.in_chan, buf.as_mut_ptr(), buf.len());
            if n > 0 {
                let _ = (sys.channel_write)(s.out_chan, buf.as_ptr(), n as usize);
            }
        }
        0
    }
}

include!("../../sdk/runtime/wasm_entry.rs");
