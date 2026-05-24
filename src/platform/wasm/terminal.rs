//! `wasm_browser_terminal` built-in: DOM scrollback widget that
//! drains the kernel log ring and renders each line into a `<pre>`
//! element through the host shim. Same role the UART has on
//! embedded targets — see the log strings flow at runtime without
//! needing F12 / DevTools.
//!
//! Drains via the diag-contract `LOG_RING_DRAIN` opcode (0x0C64),
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

use crate::kernel::{scheduler, syscalls};

extern "C" {
    /// Append `len` bytes to the in-page terminal scrollback. The
    /// shim renders verbatim; embedded newlines split rows.
    fn host_terminal_emit(ptr: *const u8, len: usize);
}

/// LOG_RING_DRAIN opcode (diag contract). Returns the number of
/// bytes written into the caller's buffer, or 0 when the ring is
/// empty. Matches the opcode used by `log_net`.
const LOG_RING_DRAIN: u32 = 0x0C64;

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

fn terminal_step(state: *mut u8) -> i32 {
    // SAFETY: state is the kernel-provided opaque state pointer for
    // this module instance; we cast it back to the module-private state
    // type allocated by the new_fn and operate within that allocation.
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
            let n = (table.provider_call)(-1, LOG_RING_DRAIN, st.buf.as_mut_ptr(), st.buf.len());
            if n <= 0 {
                break;
            }
            host_terminal_emit(st.buf.as_ptr(), n as usize);
        }
        0
    }
}

pub(crate) unsafe fn build() -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_terminal", terminal_step);
    let raw = alloc_state();
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut TerminalState, raw);
    m
}
