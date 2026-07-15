//! `wasm_browser_scan_out` built-in: surfaces a decoded byte result (the qr_scan
//! token) from the graph to JS via the host shim's `host_scan_result` import. The
//! counterpart of the camera source — a small sink so the wasm app can hand the
//! scanned token to the page (which enrolls + authenticates).
//!
//! Wire shape on `scan_out.result`: raw bytes (the token). Each channel read is
//! forwarded verbatim; qr_scan emits the token once, so one call is the norm.
//!
//! Host shim contract: `host_scan_result(ptr, len)` — the shim copies the bytes
//! and stashes them for the page (e.g. `window.__fluxor_scan_result`).

use crate::kernel::{channel, scheduler, syscalls};

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

fn scan_out_step(state: *mut u8) -> i32 {
    // SAFETY: `state` is the kernel-provided opaque state pointer for this module
    // instance; cast back to the module-private type allocated by `build`.
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

pub(crate) unsafe fn build(in_chan: i32) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_scan_out", scan_out_step);
    let raw = alloc_state(in_chan);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut ScanOutState, raw);
    m
}
