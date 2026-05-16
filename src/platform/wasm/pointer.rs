//! `wasm_browser_pointer` built-in: pointer / touch input source.
//!
//! Pulls W3C PointerEvent state from the host shim's DOM queue and
//! emits `input::pointer::MSG_EVENT` records on the output channel.
//! Multi-pointer (touch) is supported: each contact gets its own
//! `pointer_id` and the shim emits events for all active pointers.
//!
//! Wire shape on `pointer.events`:
//!   `modules/sdk/contracts/input/pointer.rs::MSG_EVENT` —
//!   16-byte records (msg_type / pointer_id / event_kind / buttons /
//!   modifiers / pressure / x:i16 / y:i16).
//!
//! Host shim contract: `host_pointer_pop(buf, len)` returns one
//! 16-byte record per call.

use crate::kernel::{channel, scheduler, syscalls};

extern "C" {
    fn host_pointer_pop(buf: *mut u8, len: usize) -> i32;
}

const EVENT_RECORD: usize = 16;

#[repr(C)]
pub(crate) struct PointerState {
    pub out_chan: i32,
    pub buf: [u8; EVENT_RECORD],
}

unsafe fn alloc_state(out_chan: i32) -> *mut PointerState {
    let table = syscalls::get_syscall_table();
    let size = core::mem::size_of::<PointerState>() as u32;
    let raw = (table.heap_alloc)(size) as *mut PointerState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::write(
        raw,
        PointerState {
            out_chan,
            buf: [0u8; EVENT_RECORD],
        },
    );
    raw
}

fn pointer_step(state: *mut u8) -> i32 {
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut PointerState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;
        if st.out_chan < 0 {
            return 0;
        }

        loop {
            let n = host_pointer_pop(st.buf.as_mut_ptr(), st.buf.len());
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
    let mut m = scheduler::BuiltInModule::new("wasm_browser_pointer", pointer_step);
    let raw = alloc_state(out_chan);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut PointerState, raw);
    m
}
