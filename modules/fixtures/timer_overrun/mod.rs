//! timer_overrun — a module a `timer` domain steps from its interrupt, whose
//! step runs past the interrupt-mode cycle budget.
//!
//! Each step spins for [`SPIN`] turns of an empty loop and then adds one to
//! a counter in its own state: several times the 2,000 cycles an
//! interrupt-mode step is allowed, on any core. It makes no call, so it is
//! safe wherever the module timer's handler runs, and it takes no
//! parameter.

#![cfg_attr(not(feature = "host-test"), no_std)]

use core::ffi::c_void;

use fluxor_rt::*;

/// Turns of the empty loop each step makes before it counts.
const SPIN: u32 = 4000;

#[repr(C)]
pub struct State {
    /// Steps taken.
    beats: u32,
}

fluxor_rt::module_facts! { state: State }

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_init")]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_new")]
pub unsafe extern "C" fn module_new(
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    _syscalls: *const c_void,
) -> i32 {
    if state.is_null() || state_size < core::mem::size_of::<State>() {
        return -22;
    }
    core::ptr::write_bytes(state, 0, core::mem::size_of::<State>());
    0
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_step")]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> StepReturn {
    let s = &mut *(state as *mut State);
    let mut turn = 0u32;
    while turn < SPIN {
        turn = core::hint::black_box(turn) + 1;
    }
    s.beats = s.beats.wrapping_add(1);
    StepReturn::Continue
}

fluxor_rt::wasm_entry!();
