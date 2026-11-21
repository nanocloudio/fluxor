//! `wasm_browser_button` native module: browser-side BUTTON capability
//! driver — the wasm equivalent of `flash_rp` on rp boards and
//! `modules/foundation/button` on bare-metal GPIO.
//!
//! Drains a host-side button-transition queue (populated by the
//! runtime shell when the user taps an interactive surface) and
//! writes one byte per debounced edge to the output channel:
//!
//!   0x01 = pressed
//!   0x00 = released
//!
//! Same wire shape `flash_rp.raw` / `button.raw` emit on hardware.
//! Downstream `gesture` does click counting + FMP mapping, exactly
//! the same module + parameters every other platform uses. The
//! whole point of having a dedicated wasm driver (rather than the
//! old `pointer → adapter` chain) is uniformity: one driver per
//! platform, exposing the canonical button capability.
//!
//! Host shim contract: `host_button_pop(buf, len)` returns one
//! byte (0x01 or 0x00) per call, or 0 when the queue is empty.

use crate::abi::platform::native::wasm::wasm_browser_button as tags;
use crate::kernel::exec::scheduler;
use crate::kernel::exec::scheduler::{NativeInit, NativeVtable};
use crate::kernel::ipc::channel;
use crate::kernel::module::syscalls;

extern "C" {
    fn host_button_pop(buf: *mut u8, len: usize) -> i32;
}

#[repr(C)]
pub(crate) struct ButtonState {
    pub out_chan: i32,
    pub buf: [u8; 1],
}

unsafe fn alloc_state(out_chan: i32) -> *mut ButtonState {
    let table = syscalls::get_syscall_table();
    let size = core::mem::size_of::<ButtonState>() as u32;
    let raw = (table.heap_alloc)(size) as *mut ButtonState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::write(
        raw,
        ButtonState {
            out_chan,
            buf: [0u8; 1],
        },
    );
    raw
}

/// # Safety
/// `state` is this module's own arena state, exclusively the
/// step's for its duration.
unsafe extern "C" fn button_step(state: *mut u8) -> i32 {
    // SAFETY: state is the kernel-provided opaque state pointer for
    // this module instance; we cast it back to the module-private state
    // type allocated by the constructor and operate within that allocation.
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut ButtonState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;
        if st.out_chan < 0 {
            return 0;
        }

        // Drain every queued transition this tick. Each pop returns
        // exactly one 1-byte transition; 0 means the queue is empty.
        loop {
            let n = host_button_pop(st.buf.as_mut_ptr(), st.buf.len());
            if n <= 0 {
                break;
            }
            let written = channel::channel_write(st.out_chan, st.buf.as_ptr(), n as usize);
            if written <= 0 {
                // Channel full — leave the rest in the host queue
                // for next tick rather than dropping transitions.
                break;
            }
        }
        0
    }
}

/// The `wasm_browser_button` native module.
pub static WASM_BROWSER_BUTTON: NativeVtable = super::heap_native(new, button_step);

/// # Safety
/// `state` is the instance's zeroed arena state; the current module is
/// `init.slot`.
unsafe fn new(state: *mut u8, init: &NativeInit<'_>) -> i32 {
    let out_chan = scheduler::module_port(init.slot, tags::PORT_RAW);
    // SAFETY: the constructor's own contract; the instance is built on
    // the slot's heap, which the current module allocates through.
    unsafe {
        super::seat_heap_instance(state, init.slot, super::heap_for::<ButtonState>(), || {
            alloc_state(out_chan).cast()
        })
    }
}
