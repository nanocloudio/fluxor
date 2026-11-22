//! `wasm_browser_pointer` native module: pointer / touch input source.
//!
//! Pulls W3C PointerEvent state from the host shim's DOM queue and
//! emits `input::pointer::MSG_EVENT` records on the output channel.
//! Multi-pointer (touch) is supported: each contact gets its own
//! `pointer_id` and the shim emits events for all active pointers.
//!
//! Wire shape on `pointer.events`:
//!   `crates/fluxor-abi/src/contracts/input/pointer.rs::MSG_EVENT` —
//!   16-byte records (msg_type / pointer_id / event_kind / buttons /
//!   modifiers / pressure / x:i16 / y:i16).
//!
//! Host shim contract: `host_pointer_pop(buf, len)` returns one
//! 16-byte record per call.

use crate::abi::platform::native::wasm::wasm_browser_pointer as tags;
use crate::kernel::exec::scheduler;
use crate::kernel::exec::scheduler::{NativeInit, NativeVtable};
use crate::kernel::ipc::channel;
use crate::kernel::module::syscalls;

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

        loop {
            let n = host_pointer_pop(st.buf.as_mut_ptr(), st.buf.len());
            if n <= 0 {
                break;
            }
            let n = n as usize;
            let written = channel::channel_write(st.out_chan, st.buf.as_ptr(), n.min(st.buf.len()));
            if written <= 0 {
                break;
            }
        }
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
