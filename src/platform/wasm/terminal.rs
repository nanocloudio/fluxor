//! `wasm_browser_terminal` native module: DOM scrollback widget that
//! drains the kernel log ring and renders each line into a `<pre>`
//! element through the host shim. Same role the UART has on
//! embedded targets — see the log strings flow at runtime without
//! needing F12 / DevTools.
//!
//! Drains via the diag-contract `LOG_RING_DRAIN` opcode (`diag::LOG_RING_DRAIN`),
//! identical to `modules/foundation/log_net` on the embedded side.
//! Multi-consumer: the kernel's log ring supports independent
//! tails, so a graph can wire both `wasm_browser_terminal` AND
//! `log_net` (or the host-console host_log path) without either
//! stealing bytes from the other.
//!
//! Host shim contract: `host_terminal_emit(ptr, len)` — append the
//! bytes verbatim to the in-page terminal's scrollback. The shim
//! handles auto-scroll and line wrapping; this module just hands
//! over UTF-8 bytes as they come off the ring.

use crate::kernel::exec::scheduler::{NativeInit, NativeVtable};
use crate::kernel::module::syscalls;

extern "C" {
    /// Append `len` bytes to the in-page terminal scrollback. The
    /// shim renders verbatim; embedded newlines split rows.
    fn host_terminal_emit(ptr: *const u8, len: usize);
}

/// LOG_RING_DRAIN opcode (diag contract). Returns the number of
/// bytes written into the caller's buffer, or 0 when the ring is
/// empty. Matches the opcode used by `log_net`.
use crate::abi::registry::diag::LOG_RING_DRAIN;

/// Per-tick drain budget. Sized to keep one step under a few
/// hundred microseconds even on the slowest paths; the host shim
/// can absorb bursts faster than the kernel can generate them, so
/// the cap is really about scheduler-fairness, not flow control.
const DRAIN_CHUNK: usize = 1024;

#[repr(C)]
pub(crate) struct TerminalState {
    pub buf: [u8; DRAIN_CHUNK],
}

unsafe fn alloc_state() -> *mut TerminalState {
    let table = syscalls::get_syscall_table();
    let size = core::mem::size_of::<TerminalState>() as u32;
    let raw = (table.heap_alloc)(size) as *mut TerminalState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::write(
        raw,
        TerminalState {
            buf: [0u8; DRAIN_CHUNK],
        },
    );
    raw
}

/// # Safety
/// `state` is this module's own arena state, exclusively the
/// step's for its duration.
unsafe extern "C" fn terminal_step(state: *mut u8) -> i32 {
    // SAFETY: state is the kernel-provided opaque state pointer for
    // this module instance; we cast it back to the module-private state
    // type allocated by the constructor and operate within that allocation.
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut TerminalState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;
        let table = syscalls::get_syscall_table();
        // Drain in a single tight loop so multi-line bursts land in
        // one step. The provider returns 0 on empty; we stop then.
        loop {
            let n = (table.provider_call)(
                -1,
                LOG_RING_DRAIN,
                core::ptr::null_mut(),
                0,
                st.buf.as_mut_ptr(),
                st.buf.len(),
            );
            if n <= 0 {
                break;
            }
            host_terminal_emit(st.buf.as_ptr(), n as usize);
        }
        0
    }
}

/// The `wasm_browser_terminal` native module.
pub static WASM_BROWSER_TERMINAL: NativeVtable = super::heap_native(new, terminal_step);

/// # Safety
/// `state` is the instance's zeroed arena state; the current module is
/// `init.slot`.
unsafe fn new(state: *mut u8, init: &NativeInit<'_>) -> i32 {
    // SAFETY: the constructor's own contract; the instance is built on
    // the slot's heap, which the current module allocates through.
    unsafe {
        super::seat_heap_instance(state, init.slot, super::heap_for::<TerminalState>(), || {
            alloc_state().cast()
        })
    }
}
