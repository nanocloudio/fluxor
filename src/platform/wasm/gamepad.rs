//! `wasm_browser_gamepad` built-in: gamepad input source backed by
//! the W3C Gamepad API. The host shim polls
//! `navigator.getGamepads()` each requestAnimationFrame and pushes
//! per-slot state into a per-handle event queue; this module drains
//! that queue into the configured output channel.
//!
//! Wire shape on `gamepad.events`:
//!   `modules/sdk/contracts/input/gamepad.rs::MSG_STATE` /
//!   `MSG_CONNECTION` — 16-byte records.
//!
//! Host shim contract: `host_gamepad_pop(buf, len)` returns one
//! 16-byte event record per call, or 0 when the queue is empty.

use crate::kernel::{channel, scheduler, syscalls};

extern "C" {
    fn host_gamepad_pop(buf: *mut u8, len: usize) -> i32;
}

const EVENT_RECORD: usize = 16;

#[repr(C)]
pub(crate) struct GamepadState {
    pub out_chan: i32,
    pub buf: [u8; EVENT_RECORD],
}

unsafe fn alloc_state(out_chan: i32) -> *mut GamepadState {
    let table = syscalls::get_syscall_table();
    let size = core::mem::size_of::<GamepadState>() as u32;
    let raw = (table.heap_alloc)(size) as *mut GamepadState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::write(
        raw,
        GamepadState {
            out_chan,
            buf: [0u8; EVENT_RECORD],
        },
    );
    raw
}

fn gamepad_step(state: *mut u8) -> i32 {
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut GamepadState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;
        if st.out_chan < 0 {
            return 0;
        }

        loop {
            let n = host_gamepad_pop(st.buf.as_mut_ptr(), st.buf.len());
            if n <= 0 {
                break;
            }
            let n = n as usize;
            let written = channel::channel_write(
                st.out_chan,
                st.buf.as_ptr(),
                n.min(st.buf.len()),
            );
            if written <= 0 {
                break;
            }
        }
        0
    }
}

pub(crate) unsafe fn build(out_chan: i32) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_gamepad", gamepad_step);
    let raw = alloc_state(out_chan);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut GamepadState, raw);
    m
}
