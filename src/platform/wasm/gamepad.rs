//! `wasm_browser_gamepad` native module: gamepad input source backed by
//! the W3C Gamepad API. The host shim polls
//! `navigator.getGamepads()` each requestAnimationFrame and pushes
//! per-slot state into a per-handle event queue; this module drains
//! that queue into the configured output channel.
//!
//! Wire shape on `gamepad.events`:
//!   `crates/fluxor-abi/src/contracts/input/gamepad.rs::MSG_STATE` /
//!   `MSG_CONNECTION` — 16-byte records.
//!
//! Host shim contract: `host_gamepad_pop(buf, len)` returns one
//! 16-byte event record per call, or 0 when the queue is empty.

use crate::abi::platform::native::wasm::wasm_browser_gamepad as tags;
use crate::kernel::exec::scheduler;
use crate::kernel::exec::scheduler::{NativeInit, NativeVtable};
use crate::kernel::ipc::channel;
use crate::kernel::module::syscalls;

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

/// # Safety
/// `state` is this module's own arena state, exclusively the
/// step's for its duration.
unsafe extern "C" fn gamepad_step(state: *mut u8) -> i32 {
    // SAFETY: state is the kernel-provided opaque state pointer for
    // this module instance; we cast it back to the module-private state
    // type allocated by the constructor and operate within that allocation.
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
            let written = channel::channel_write(st.out_chan, st.buf.as_ptr(), n.min(st.buf.len()));
            if written <= 0 {
                break;
            }
        }
        0
    }
}

/// The `wasm_browser_gamepad` native module.
pub static WASM_BROWSER_GAMEPAD: NativeVtable = super::heap_native(new, gamepad_step);

/// # Safety
/// `state` is the instance's zeroed arena state; the current module is
/// `init.slot`.
unsafe fn new(state: *mut u8, init: &NativeInit<'_>) -> i32 {
    let out_chan = scheduler::module_port(init.slot, tags::PORT_EVENTS);
    // SAFETY: the constructor's own contract; the instance is built on
    // the slot's heap, which the current module allocates through.
    unsafe {
        super::seat_heap_instance(state, init.slot, super::heap_for::<GamepadState>(), || {
            alloc_state(out_chan).cast()
        })
    }
}
