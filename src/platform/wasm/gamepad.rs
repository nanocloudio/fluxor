//! `wasm_browser_gamepad` native module: gamepad input source backed by
//! the W3C Gamepad API. The host polls `navigator.getGamepads()` each
//! animation frame and queues a record when a slot changes; this module
//! drains that queue into the output channel.
//!
//! Wire shape on `gamepad.events`: `abi::contracts::input::gamepad`
//! `MSG_STATE` / `MSG_CONNECTION` records.
//!
//! Host shim contract: `host_gamepad_pop(buf, len)` writes one record per
//! call and returns its length, or 0 when the queue is empty.

use crate::abi::contracts::input::gamepad;
use crate::abi::platform::native::wasm::wasm_browser_gamepad as tags;
use crate::kernel::exec::scheduler;
use crate::kernel::exec::scheduler::{NativeInit, NativeVtable};
use crate::kernel::module::syscalls;

extern "C" {
    fn host_gamepad_pop(buf: *mut u8, len: usize) -> i32;
}

#[repr(C)]
pub(crate) struct GamepadState {
    pub out_chan: i32,
    /// The record in hand; `relay_records` holds one the channel refused.
    pub buf: [u8; gamepad::EVENT_SIZE],
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
            buf: [0u8; gamepad::EVENT_SIZE],
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

        super::relay_records(st.out_chan, &mut st.buf, host_gamepad_pop, |b| {
            matches!(
                gamepad::decode(b),
                Some(gamepad::Event::State { .. } | gamepad::Event::Connection { .. })
            )
        });
        0
    }
}

/// The `wasm_browser_gamepad` native module.
pub static WASM_BROWSER_GAMEPAD: NativeVtable = super::heap_native(
    new,
    gamepad_step,
    crate::abi::platform::native::wasm::wasm_browser_gamepad::STATE_BYTES,
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
            &crate::abi::platform::native::wasm::wasm_browser_gamepad::HEAP_SEAT,
            init.params,
            || alloc_state(out_chan).cast(),
        )
    }
}

const _: () = assert!(
    crate::abi::platform::native::wasm::wasm_browser_gamepad::HEAP_SEAT[0] as usize
        >= super::heap_for::<GamepadState>(),
    "the declared heap seat holds the instance"
);
