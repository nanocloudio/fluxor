//! `wasm_browser_keyboard` native module: keyboard input source that
//! pulls key records from the host shim's keyboard queue and forwards them
//! on the output channel.
//!
//! Wire shape on `keyboard.events`: `abi::contracts::input::key` records.
//! The host defers each key by one task so it can flag `KEY_TEXT` on a key
//! whose effect arrived on `TextEvents`.
//!
//! Host shim contract: `host_keyboard_pop(buf, len)` writes one record on
//! each call and returns its length, or 0 when the queue is empty.

use crate::abi::contracts::input::key;
use crate::abi::platform::native::wasm::wasm_browser_keyboard as tags;
use crate::kernel::exec::scheduler;
use crate::kernel::exec::scheduler::{NativeInit, NativeVtable};
use crate::kernel::module::syscalls;

extern "C" {
    /// Pop the next pending key record into `buf` (kernel-side pointer,
    /// written by the shim). Returns the number of bytes written, 0 if the
    /// queue is empty, or negative on error.
    fn host_keyboard_pop(buf: *mut u8, len: usize) -> i32;
}

#[repr(C)]
pub(crate) struct KeyboardState {
    pub out_chan: i32,
    /// The record in hand; `relay_records` holds one the channel refused.
    pub buf: [u8; key::EVENT_SIZE],
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
            buf: [0u8; key::EVENT_SIZE],
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

        super::relay_records(st.out_chan, &mut st.buf, host_keyboard_pop, |b| {
            key::decode(b).is_some()
        });
        0
    }
}

/// The `wasm_browser_keyboard` native module.
pub static WASM_BROWSER_KEYBOARD: NativeVtable = super::heap_native(
    new,
    keyboard_step,
    crate::abi::platform::native::wasm::wasm_browser_keyboard::STATE_BYTES,
);

/// # Safety
/// `state` is the instance's zeroed arena state; the current module is
/// `init.slot`.
unsafe fn new(state: *mut u8, init: &NativeInit<'_>) -> i32 {
    let out_chan = scheduler::module_port(init.slot, tags::PORT_EVENTS);
    // SAFETY: the constructor's own contract; the instance is built on
    // the slot's heap, which the current module allocates through.
    unsafe {
        super::seat_heap_instance(
            state,
            init.slot,
            &crate::abi::platform::native::wasm::wasm_browser_keyboard::HEAP_SEAT,
            init.params,
            || alloc_state(out_chan).cast(),
        )
    }
}

const _: () = assert!(
    crate::abi::platform::native::wasm::wasm_browser_keyboard::HEAP_SEAT[0] as usize
        >= super::heap_for::<KeyboardState>(),
    "the declared heap seat holds the instance"
);
