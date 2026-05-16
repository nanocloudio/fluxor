//! `wasm_browser_ws_source` built-in: receive-only WebSocket source
//! that emits its incoming binary messages on the output channel as a
//! `VideoRaster` byte stream.
//!
//! This is the "thin viewer" half of the split-deployment image
//! pipeline: an upstream component (e.g. a Pi 5 running
//! `host_image_codec → ws_stream → http`) decodes images and pushes
//! RGB565 frames over `/ws`; the browser hosts this module, which
//! pulls the bytes via the existing `host_ws_*` shim and forwards
//! them to `wasm_browser_canvas` for paint. The same canvas module
//! is wired in the pure-wasm graph behind `wasm_browser_image_codec`,
//! so swapping decoder location is purely a graph-wiring concern —
//! the canvas, the wire shape, and the user-visible behaviour are
//! identical between deployments.
//!
//! State is heap-allocated; the BuiltInModule's 64-byte inline state
//! holds a `*mut WsSourceState` pointer.
//!
//! Backpressure: any non-positive `channel_write` return value stashes
//! the unwritten tail in `rx` and gates further pulls from the JS
//! rxQueue until the channel accepts again. Same pattern as
//! `wasm_browser_websocket`.

use crate::kernel::{channel, scheduler, syscalls};

extern "C" {
    /// Open a WebSocket. Shared with `wasm_browser_websocket` — the
    /// shim is socket-typed, not module-typed; multiple kernel-side
    /// modules can each hold their own handle.
    fn host_ws_open(url_ptr: *const u8, url_len: usize) -> i32;

    /// Receive the oldest pending message bytes from the WebSocket
    /// into `buf`. Returns the number of bytes written, 0 if the queue
    /// is empty, or negative on error / EOF. Large messages may be
    /// returned across multiple calls; this module is byte-stream
    /// oriented and lets the downstream consumer (canvas) accumulate
    /// `width * height * 2` bytes per frame from arbitrary chunks.
    fn host_ws_recv(handle: i32, buf: *mut u8, len: usize) -> i32;
}

const RX_BUF_BYTES: usize = 65536;
const URL_BUF_BYTES: usize = 256;

#[repr(C)]
pub(crate) struct WsSourceState {
    pub out_chan: i32,
    pub handle: i32,
    pub url_len: u32,
    pub url: [u8; URL_BUF_BYTES],
    /// RX retry buffer: bytes pulled from `host_ws_recv` but not yet
    /// accepted by `out_chan`. Drained-first semantics gate further
    /// JS-side reads while back-pressured.
    pub rx: [u8; RX_BUF_BYTES],
    pub rx_pending_len: usize,
    pub opened: bool,
}

unsafe fn alloc_state(out_chan: i32, url: &[u8]) -> *mut WsSourceState {
    let table = syscalls::get_syscall_table();
    let size = core::mem::size_of::<WsSourceState>() as u32;
    let raw = (table.heap_alloc)(size) as *mut WsSourceState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    let mut url_buf = [0u8; URL_BUF_BYTES];
    let copy_len = url.len().min(URL_BUF_BYTES);
    url_buf[..copy_len].copy_from_slice(&url[..copy_len]);
    core::ptr::write(
        raw,
        WsSourceState {
            out_chan,
            handle: -1,
            url_len: copy_len as u32,
            url: url_buf,
            rx: [0u8; RX_BUF_BYTES],
            rx_pending_len: 0,
            opened: false,
        },
    );
    raw
}

unsafe fn shift_consume(buf: *mut u8, len: usize, consumed: usize) -> usize {
    if consumed == 0 || consumed > len {
        return len;
    }
    let remaining = len - consumed;
    if remaining > 0 {
        core::ptr::copy(buf.add(consumed), buf, remaining);
    }
    remaining
}

fn ws_source_step(state: *mut u8) -> i32 {
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut WsSourceState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;

        // Lazy connect on first step.
        if !st.opened {
            let h = host_ws_open(st.url.as_ptr(), st.url_len as usize);
            if h >= 0 {
                st.handle = h;
                st.opened = true;
            } else {
                return 0;
            }
        }

        if st.out_chan < 0 {
            return 0;
        }

        // Drain pending retry buffer first.
        if st.rx_pending_len > 0 {
            let written =
                channel::channel_write(st.out_chan, st.rx.as_ptr(), st.rx_pending_len);
            if written > 0 {
                let w = (written as usize).min(st.rx_pending_len);
                st.rx_pending_len = shift_consume(st.rx.as_mut_ptr(), st.rx_pending_len, w);
            }
        }

        // Pull new WS chunks until the channel back-pressures.
        while st.rx_pending_len == 0 {
            let n = host_ws_recv(st.handle, st.rx.as_mut_ptr(), st.rx.len());
            if n <= 0 {
                break;
            }
            let n = n as usize;
            let written = channel::channel_write(st.out_chan, st.rx.as_ptr(), n);
            let w = if written > 0 {
                (written as usize).min(n)
            } else {
                0
            };
            if w < n {
                st.rx_pending_len = shift_consume(st.rx.as_mut_ptr(), n, w);
                break;
            }
        }
        0
    }
}

pub(crate) unsafe fn build(url: &[u8], out_chan: i32) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_ws_source", ws_source_step);
    let raw = alloc_state(out_chan, url);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut WsSourceState, raw);
    m
}
