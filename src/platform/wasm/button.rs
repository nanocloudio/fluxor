//! `wasm_browser_button` built-in: browser-side BUTTON capability
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

use crate::kernel::{channel, scheduler, syscalls};

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

fn button_step(state: *mut u8) -> i32 {
    // SAFETY: state is the kernel-provided opaque state pointer for
    // this module instance; we cast it back to the module-private state
    // type allocated by the new_fn and operate within that allocation.
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

pub(crate) unsafe fn build(out_chan: i32) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_button", button_step);
    let raw = alloc_state(out_chan);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut ButtonState, raw);
    m
}
