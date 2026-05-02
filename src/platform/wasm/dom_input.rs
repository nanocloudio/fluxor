//! `wasm_browser_dom_input` built-in: keyboard input source that
//! pulls events from the host shim's queue (populated by DOM
//! `keydown` / `keyup` listeners) and forwards them to the configured
//! output channel as `InputBinaryState` snapshots.
//!
//! Wire format on the output channel — a compact 8-byte
//! `InputBinaryState` snapshot:
//!
//! ```text
//! [seq: u32 LE][modifier: u8][_pad: u8][key_code_lo: u8][key_code_hi: u8]
//! ```
//!
//! Mapper modules and emulator cores normalise this into the full
//! `InputBinaryEvent` shape per `input_capability_surface.md`.

use crate::kernel::{channel, scheduler, syscalls};

extern "C" {
    /// Pop the next pending DOM input event into `buf` (kernel-side
    /// pointer, written by the shim). Returns the number of bytes
    /// written, 0 if the queue is empty, or negative on error.
    /// Event format matches `EVENT_RECORD` below.
    fn host_input_pop(buf: *mut u8, len: usize) -> i32;
}

/// Wire size of one event record on the output channel.
const EVENT_RECORD: usize = 8;

#[repr(C)]
pub(crate) struct DomInputState {
    pub out_chan: i32,
    pub seq: u32,
    pub buf: [u8; EVENT_RECORD],
}

unsafe fn alloc_state(out_chan: i32) -> *mut DomInputState {
    let table = syscalls::get_syscall_table();
    let size = core::mem::size_of::<DomInputState>() as u32;
    let raw = (table.heap_alloc)(size) as *mut DomInputState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::write(
        raw,
        DomInputState {
            out_chan,
            seq: 0,
            buf: [0u8; EVENT_RECORD],
        },
    );
    raw
}

fn dom_input_step(state: *mut u8) -> i32 {
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut DomInputState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;
        if st.out_chan < 0 {
            return 0;
        }

        loop {
            let n = host_input_pop(st.buf.as_mut_ptr(), st.buf.len());
            if n <= 0 {
                break;
            }
            // Stamp the seq into the first 4 bytes so consumers can
            // detect dropped events. The host writes the rest.
            let seq_bytes = st.seq.to_le_bytes();
            st.buf[0..4].copy_from_slice(&seq_bytes);
            st.seq = st.seq.wrapping_add(1);

            let n = n as usize;
            let written =
                channel::channel_write(st.out_chan, st.buf.as_ptr(), n.min(st.buf.len()));
            if written <= 0 {
                // Channel full — drop the event rather than backing
                // up. Input is latency-sensitive; queueing stale
                // events would compound the problem.
                break;
            }
        }
        0
    }
}

pub(crate) unsafe fn build(out_chan: i32) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_dom_input", dom_input_step);
    let raw = alloc_state(out_chan);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut DomInputState, raw);
    m
}
