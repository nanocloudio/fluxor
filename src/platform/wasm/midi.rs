//! `wasm_browser_midi_in` / `wasm_browser_midi_out` built-ins — STUB.
//!
//! Real implementations pending. When wired, these will bridge the
//! Web MIDI API (`navigator.requestMIDIAccess`) via the host shim:
//!
//! - `wasm_browser_midi_in` subscribes to the user-selected input
//!   port, decodes raw MIDI status bytes into the `input::midi`
//!   4-byte frame shape (per
//!   `modules/sdk/contracts/input/midi.rs`), and writes one frame
//!   per event to the `events` output channel.
//!
//! - `wasm_browser_midi_out` consumes 4-byte frames from the
//!   `events` input channel, re-encodes them as standard MIDI 1.0
//!   status + data bytes, and dispatches via the Web MIDI API
//!   output port selected by `port_filter`.
//!
//! Stub behaviour:
//!   - modules register in the built-in table so configs load
//!     cleanly,
//!   - the dispatch arms in `wasm.rs` log a STUB marker on
//!     construction,
//!   - **`midi_out` drains** the input channel every step so a
//!     producer wired to it doesn't backpressure. Reads are
//!     discarded. `midi_in` has no input port and is a pure no-op.

use crate::kernel::{channel, scheduler, syscalls};

#[repr(C)]
pub(crate) struct MidiInState {
    pub _placeholder: u8,
}

#[repr(C)]
pub(crate) struct MidiOutState {
    /// `events` channel handle (input port). The stub drains this
    /// every step. `-1` when no producer is wired.
    pub events_in: i32,
}

unsafe fn alloc_state_in() -> *mut MidiInState {
    let table = syscalls::get_syscall_table();
    let size = core::mem::size_of::<MidiInState>() as u32;
    let raw = (table.heap_alloc)(size) as *mut MidiInState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::write(raw, MidiInState { _placeholder: 0 });
    raw
}

unsafe fn alloc_state_out(events_in: i32) -> *mut MidiOutState {
    let table = syscalls::get_syscall_table();
    let size = core::mem::size_of::<MidiOutState>() as u32;
    let raw = (table.heap_alloc)(size) as *mut MidiOutState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::write(raw, MidiOutState { events_in });
    raw
}

fn midi_in_step(_state: *mut u8) -> i32 {
    // No input port — pure no-op until Web MIDI integration lands.
    0
}

fn midi_out_step(state: *mut u8) -> i32 {
    // SAFETY: state is the kernel-provided opaque state pointer for
    // this module instance; we cast it back to the module-private state
    // type allocated by the new_fn and operate within that allocation.
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut MidiOutState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &*st_ptr;
        if st.events_in >= 0 {
            let mut scratch = [0u8; 256];
            let _ = channel::channel_read(st.events_in, scratch.as_mut_ptr(), scratch.len());
        }
        0
    }
}

pub(crate) unsafe fn build_in() -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_midi_in", midi_in_step);
    let raw = alloc_state_in();
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut MidiInState, raw);
    m
}

pub(crate) unsafe fn build_out(events_in: i32) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_midi_out", midi_out_step);
    let raw = alloc_state_out(events_in);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut MidiOutState, raw);
    m
}
