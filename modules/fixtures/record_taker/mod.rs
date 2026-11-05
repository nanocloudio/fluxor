//! record_taker: one read per step; each read's first byte and length go out
//! as a two-byte record, so a read that held two records, or part of one,
//! shows in what a test reads off the output.

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

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    /// A report waiting for room on the output; its length byte is non-zero.
    pending: [u8; 2],
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
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes and `syscalls` the kernel's syscall table.
#[no_mangle]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if state.is_null() || syscalls.is_null() || state_size < core::mem::size_of::<State>() {
        return -1;
    }
    unsafe {
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.pending = [0; 2];
    }
    0
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        let s = &mut *(state as *mut State);
        let sys = &*s.syscalls;
        if s.pending[1] == 0 {
            let mut rec = [0u8; 200];
            let n = (sys.channel_read)(s.in_chan, rec.as_mut_ptr(), rec.len());
            if n <= 0 {
                return 0;
            }
            s.pending = [rec[0], n as u8];
        }
        if (sys.channel_write)(s.out_chan, s.pending.as_ptr(), 2) == 2 {
            s.pending = [0; 2];
        }
        0
    }
}

include!("../../sdk/runtime/wasm_entry.rs");
