//! `wasm_browser_pointer` native module: pointer, touch and wheel input
//! source.
//!
//! Pulls pointer records from the host shim's queue and forwards them on
//! the output channel. Each contact has its own `pointer_id`; positions and
//! pixel wheel deltas are in surface pixels.
//!
//! Wire shape on `pointer.events`: `abi::contracts::input::pointer` records.
//!
//! Host shim contract: `host_pointer_pop(buf, len)` writes one record per
//! call and returns its length, or 0 when the queue is empty.

use crate::abi::contracts::input::pointer;
use crate::abi::platform::native::wasm::wasm_browser_pointer as tags;
use crate::kernel::exec::scheduler;
use crate::kernel::exec::scheduler::{NativeInit, NativeVtable};
use crate::kernel::module::syscalls;

extern "C" {
    fn host_pointer_pop(buf: *mut u8, len: usize) -> i32;
}

#[repr(C)]
pub(crate) struct PointerState {
    pub out_chan: i32,
    /// The record in hand; `relay_records` holds one the channel refused.
    pub buf: [u8; pointer::EVENT_SIZE],
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
            buf: [0u8; pointer::EVENT_SIZE],
        },
    );
    raw
}

/// # Safety
/// `state` is this module's own arena state, exclusively the
/// step's for its duration.
unsafe extern "C" fn pointer_step(state: *mut u8) -> i32 {
    // SAFETY: state is the kernel-provided opaque state pointer for
    // this module instance; we cast it back to the module-private state
    // type allocated by the constructor and operate within that allocation.
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut PointerState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;
        if st.out_chan < 0 {
            return 0;
        }

        super::relay_records(st.out_chan, &mut st.buf, host_pointer_pop, |b| {
            pointer::decode(b).is_some()
        });
        0
    }
}

/// The `wasm_browser_pointer` native module.
pub static WASM_BROWSER_POINTER: NativeVtable = super::heap_native(
    new,
    pointer_step,
    crate::abi::platform::native::wasm::wasm_browser_pointer::STATE_BYTES,
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
            &crate::abi::platform::native::wasm::wasm_browser_pointer::HEAP_SEAT,
            init.params,
            || alloc_state(out_chan).cast(),
        )
    }
}

const _: () = assert!(
    crate::abi::platform::native::wasm::wasm_browser_pointer::HEAP_SEAT[0] as usize
        >= super::heap_for::<PointerState>(),
    "the declared heap seat holds the instance"
);
