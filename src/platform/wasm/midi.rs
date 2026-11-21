//! `wasm_browser_midi_in` / `wasm_browser_midi_out` native modules — STUB.
//!
//! Real implementations pending. When wired, these will bridge the
//! Web MIDI API (`navigator.requestMIDIAccess`) via the host shim:
//!
//! - `wasm_browser_midi_in` subscribes to the user-selected input
//!   port, decodes raw MIDI status bytes into the `input::midi`
//!   4-byte frame shape (per
//!   `crates/fluxor-abi/src/contracts/input/midi.rs`), and writes one frame
//!   per event to the `events` output channel.
//!
//! - `wasm_browser_midi_out` consumes 4-byte frames from the
//!   `events` input channel, re-encodes them as standard MIDI 1.0
//!   status + data bytes, and dispatches via the Web MIDI API
//!   output port selected by `port_filter`.
//!
//! Stub behaviour:
//!   - modules register in the native module table so configs load
//!     cleanly,
//!   - the constructors log a STUB marker on
//!     construction,
//!   - **`midi_out` drains** the input channel every step so a
//!     producer wired to it doesn't backpressure. Reads are
//!     discarded. `midi_in` has no input port and is a pure no-op.

use crate::abi::platform::native::wasm::wasm_browser_midi_out as midi_out_tags;
use crate::kernel::exec::scheduler;
use crate::kernel::exec::scheduler::{NativeInit, NativeVtable};
use crate::kernel::ipc::channel;
use crate::kernel::module::syscalls;

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

/// # Safety
/// `state` is this module's own arena state, exclusively the
/// step's for its duration.
unsafe extern "C" fn midi_in_step(_state: *mut u8) -> i32 {
    // No input port — pure no-op until Web MIDI integration lands.
    0
}

/// # Safety
/// `state` is this module's own arena state, exclusively the
/// step's for its duration.
unsafe extern "C" fn midi_out_step(state: *mut u8) -> i32 {
    // SAFETY: state is the kernel-provided opaque state pointer for
    // this module instance; we cast it back to the module-private state
    // type allocated by the constructor and operate within that allocation.
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

/// The `wasm_browser_midi_in` native module.
pub static WASM_BROWSER_MIDI_IN: NativeVtable = super::heap_native(new_in, midi_in_step);

/// # Safety
/// `state` is the instance's zeroed arena state; the current module is
/// `init.slot`.
unsafe fn new_in(state: *mut u8, init: &NativeInit<'_>) -> i32 {
    log::warn!(
        "[wasm-kernel] module {}: wasm_browser_midi_in is a STUB (Web MIDI not yet implemented)",
        init.slot
    );
    // SAFETY: the constructor's own contract; the instance is built on
    // the slot's heap, which the current module allocates through.
    unsafe {
        super::seat_heap_instance(state, init.slot, super::heap_for::<MidiInState>(), || {
            alloc_state_in().cast()
        })
    }
}

/// The `wasm_browser_midi_out` native module.
pub static WASM_BROWSER_MIDI_OUT: NativeVtable = super::heap_native(new_out, midi_out_step);

/// # Safety
/// `state` is the instance's zeroed arena state; the current module is
/// `init.slot`.
unsafe fn new_out(state: *mut u8, init: &NativeInit<'_>) -> i32 {
    log::warn!("[wasm-kernel] module {}: wasm_browser_midi_out is a STUB (Web MIDI not yet implemented; drains input channel)", init.slot);
    let events_in = scheduler::module_port(init.slot, midi_out_tags::PORT_EVENTS);
    // SAFETY: the constructor's own contract; the instance is built on
    // the slot's heap, which the current module allocates through.
    unsafe {
        super::seat_heap_instance(state, init.slot, super::heap_for::<MidiOutState>(), || {
            alloc_state_out(events_in).cast()
        })
    }
}
