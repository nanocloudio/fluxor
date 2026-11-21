//! `wasm_browser_keyboard` native module: keyboard input source that
//! pulls events from the host shim's DOM-keyboard queue and forwards
//! them on the output channel as `input::key::MSG_EVENT` records.
//!
//! Replaces the previous `wasm_browser_dom_input` (which merged
//! keyboard + future pointer in one module — split per-class to
//! match the `stacks/{keyboard, pointer, gamepad}.toml` capability-
//! surface architecture).
//!
//! Wire shape on `keyboard.events`:
//!   `crates/fluxor-abi/src/contracts/input/key.rs::MSG_EVENT` —
//!   8-byte records (msg_type / kind / modifiers / repeat /
//!   key_code:u16 / scan_code:u16).
//!
//! Host shim contract: `host_keyboard_pop(buf, len)` returns one
//! 8-byte record on each call, or 0 when the queue is empty.

use crate::abi::platform::native::wasm::wasm_browser_keyboard as tags;
use crate::kernel::exec::scheduler;
use crate::kernel::exec::scheduler::{NativeInit, NativeVtable};
use crate::kernel::ipc::channel;
use crate::kernel::module::syscalls;

extern "C" {
    /// Pop the next pending DOM keyboard event into `buf` (kernel-
    /// side pointer, written by the shim). Returns the number of
    /// bytes written, 0 if the queue is empty, or negative on
    /// error. Event format matches `EVENT_RECORD` below.
    fn host_keyboard_pop(buf: *mut u8, len: usize) -> i32;
}

/// Wire size of one event record (matches input::key::EVENT_SIZE).
const EVENT_RECORD: usize = 8;

#[repr(C)]
pub(crate) struct KeyboardState {
    pub out_chan: i32,
    pub buf: [u8; EVENT_RECORD],
}

unsafe fn alloc_state(out_chan: i32) -> *mut KeyboardState {
    let table = syscalls::get_syscall_table();
    let size = core::mem::size_of::<KeyboardState>() as u32;
    let raw = (table.heap_alloc)(size) as *mut KeyboardState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::write(
        raw,
        KeyboardState {
            out_chan,
            buf: [0u8; EVENT_RECORD],
        },
    );
    raw
}

/// # Safety
/// `state` is this module's own arena state, exclusively the
/// step's for its duration.
unsafe extern "C" fn keyboard_step(state: *mut u8) -> i32 {
    // SAFETY: state is the kernel-provided opaque state pointer for
    // this module instance; we cast it back to the module-private state
    // type allocated by the constructor and operate within that allocation.
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut KeyboardState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;
        if st.out_chan < 0 {
            return 0;
        }

        loop {
            let n = host_keyboard_pop(st.buf.as_mut_ptr(), st.buf.len());
            if n <= 0 {
                break;
            }
            let n = n as usize;
            let written = channel::channel_write(st.out_chan, st.buf.as_ptr(), n.min(st.buf.len()));
            if written <= 0 {
                // Channel full — drop the event. Input is latency-
                // sensitive; queueing stale events would compound
                // the problem.
                break;
            }
        }
        0
    }
}

/// The `wasm_browser_keyboard` native module.
pub static WASM_BROWSER_KEYBOARD: NativeVtable = super::heap_native(new, keyboard_step);

/// # Safety
/// `state` is the instance's zeroed arena state; the current module is
/// `init.slot`.
unsafe fn new(state: *mut u8, init: &NativeInit<'_>) -> i32 {
    let out_chan = scheduler::module_port(init.slot, tags::PORT_EVENTS);
    // SAFETY: the constructor's own contract; the instance is built on
    // the slot's heap, which the current module allocates through.
    unsafe {
        super::seat_heap_instance(state, init.slot, super::heap_for::<KeyboardState>(), || {
            alloc_state(out_chan).cast()
        })
    }
}
