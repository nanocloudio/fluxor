//! `wasm_browser_scan_out` native module: surfaces a decoded byte result (the qr_scan
//! token) from the graph to JS via the host shim's `host_scan_result` import. The
//! counterpart of the camera source — a small sink so the wasm app can hand the
//! scanned token to the page (which enrolls + authenticates).
//!
//! Wire shape on `scan_out.result`: raw bytes (the token). Each channel read is
//! forwarded verbatim; qr_scan emits the token once, so one call is the norm.
//!
//! Host shim contract: `host_scan_result(ptr, len)` — the shim copies the bytes
//! and stashes them for the page (e.g. `window.__fluxor_scan_result`).

use crate::abi::platform::native::wasm::wasm_browser_scan_out as tags;
use crate::kernel::exec::scheduler;
use crate::kernel::exec::scheduler::{NativeInit, NativeVtable};
use crate::kernel::ipc::channel;
use crate::kernel::module::syscalls;

extern "C" {
    /// Hand a decoded result (kernel pointer + length) to the host page.
    fn host_scan_result(ptr: *const u8, len: usize);
}

const RESULT_MAX: usize = 256;

#[repr(C)]
pub(crate) struct ScanOutState {
    pub in_chan: i32,
    pub buf: [u8; RESULT_MAX],
}

unsafe fn alloc_state(in_chan: i32) -> *mut ScanOutState {
    let table = syscalls::get_syscall_table();
    let raw = (table.heap_alloc)(core::mem::size_of::<ScanOutState>() as u32) as *mut ScanOutState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::write(
        raw,
        ScanOutState {
            in_chan,
            buf: [0u8; RESULT_MAX],
        },
    );
    raw
}

/// # Safety
/// `state` is this module's own arena state, exclusively the
/// step's for its duration.
unsafe extern "C" fn scan_out_step(state: *mut u8) -> i32 {
    // SAFETY: `state` is the kernel-provided opaque state pointer for this module
    // instance; cast back to the module-private type allocated by the constructor.
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut ScanOutState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;
        if st.in_chan < 0 {
            return 0;
        }
        loop {
            let n = channel::channel_read(st.in_chan, st.buf.as_mut_ptr(), RESULT_MAX);
            if n <= 0 {
                break;
            }
            host_scan_result(st.buf.as_ptr(), n as usize);
        }
        0
    }
}

/// The `wasm_browser_scan_out` native module.
pub static WASM_BROWSER_SCAN_OUT: NativeVtable = super::heap_native(new, scan_out_step);

/// # Safety
/// `state` is the instance's zeroed arena state; the current module is
/// `init.slot`.
unsafe fn new(state: *mut u8, init: &NativeInit<'_>) -> i32 {
    let in_chan = scheduler::module_port(init.slot, tags::PORT_RESULT);
    // SAFETY: the constructor's own contract; the instance is built on
    // the slot's heap, which the current module allocates through.
    unsafe {
        super::seat_heap_instance(state, init.slot, super::heap_for::<ScanOutState>(), || {
            alloc_state(in_chan).cast()
        })
    }
}
