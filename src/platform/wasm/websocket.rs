//! `wasm_browser_websocket` built-in: WebSocket client. Connects to
//! a configured URL via the host shim and tunnels raw bytes between
//! the input/output channels and the WS.
//!
//! State: heap-allocated; the BuiltInModule's 64-byte inline state
//! holds a `*mut WsState` pointer.
//!
//! ## Backpressure (lossless under steady-state)
//!
//! Each direction owns a per-instance retry buffer. When the
//! downstream surface (host WS queue on TX, `out_chan` on RX) accepts
//! less than offered, the unsent tail stays in the retry buffer and
//! drains first on the next step. New input is only pulled when the
//! retry buffer is empty. No bytes are dropped under back-pressure.
//!
//! Caveats:
//!   - The retry buffers are fixed-size. While the downstream stays
//!     blocked the buffer fills and `step()` returns without reading
//!     new input; upstream channel back-pressure applies normally.
//!   - The WS handle opens asynchronously. Until `opened`, neither
//!     direction makes progress; this is the normal
//!     connection-pending state.

use crate::kernel::{channel, scheduler, syscalls};

extern "C" {
    /// Open a WebSocket to `url_ptr[..url_len]` (URL is a UTF-8 string
    /// in kernel memory). Returns a non-negative socket handle on
    /// success or negative errno. The shim opens the connection
    /// asynchronously — `host_ws_send` / `host_ws_recv` may return
    /// 0 / pending until the handshake completes.
    fn host_ws_open(url_ptr: *const u8, url_len: usize) -> i32;

    /// Send bytes on the WebSocket as a single binary message. The
    /// shim copies the bytes into a fresh `Uint8Array` and calls
    /// `socket.send`. Returns the number of bytes accepted, 0 if the
    /// socket isn't ready, or negative on error.
    fn host_ws_send(handle: i32, data: *const u8, len: usize) -> i32;

    /// Receive the oldest pending message from the WebSocket into
    /// `buf`. Returns the number of bytes written, 0 if the queue
    /// is empty, or negative on error / EOF.
    fn host_ws_recv(handle: i32, buf: *mut u8, len: usize) -> i32;
}

const TX_BUF_BYTES: usize = 4096;
const RX_BUF_BYTES: usize = 4096;
const URL_BUF_BYTES: usize = 256;

#[repr(C)]
pub(crate) struct WsState {
    pub in_chan: i32,
    pub out_chan: i32,
    pub handle: i32,
    pub url_len: u32,
    pub url: [u8; URL_BUF_BYTES],
    /// TX retry buffer: bytes pulled from `in_chan` but not yet
    /// accepted by `host_ws_send`. The first `tx_pending_len` bytes
    /// of `tx` are queued for the next send attempt; further input
    /// reads are gated until this drains.
    pub tx: [u8; TX_BUF_BYTES],
    pub tx_pending_len: usize,
    /// RX retry buffer: bytes pulled from `host_ws_recv` but not yet
    /// accepted by `out_chan`. Same gating semantics.
    pub rx: [u8; RX_BUF_BYTES],
    pub rx_pending_len: usize,
    pub opened: bool,
}

unsafe fn alloc_state(in_chan: i32, out_chan: i32, url: &[u8]) -> *mut WsState {
    let table = syscalls::get_syscall_table();
    let size = core::mem::size_of::<WsState>() as u32;
    let raw = (table.heap_alloc)(size) as *mut WsState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    let mut url_buf = [0u8; URL_BUF_BYTES];
    let copy_len = url.len().min(URL_BUF_BYTES);
    url_buf[..copy_len].copy_from_slice(&url[..copy_len]);
    core::ptr::write(
        raw,
        WsState {
            in_chan,
            out_chan,
            handle: -1,
            url_len: copy_len as u32,
            url: url_buf,
            tx: [0u8; TX_BUF_BYTES],
            tx_pending_len: 0,
            rx: [0u8; RX_BUF_BYTES],
            rx_pending_len: 0,
            opened: false,
        },
    );
    raw
}

/// Shift-compact the leading `consumed` bytes out of `buf[..len]`.
/// Returns the new length.
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

fn ws_step(state: *mut u8) -> i32 {
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut WsState);
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

        // ── TX: in_chan → host_ws_send ──
        if st.in_chan >= 0 {
            // Drain pending retry buffer first.
            if st.tx_pending_len > 0 {
                let sent = host_ws_send(st.handle, st.tx.as_ptr(), st.tx_pending_len);
                if sent > 0 {
                    let s = sent as usize;
                    let s = s.min(st.tx_pending_len);
                    st.tx_pending_len = shift_consume(st.tx.as_mut_ptr(), st.tx_pending_len, s);
                }
            }
            // Only pull new input if pending drained.
            while st.tx_pending_len == 0 {
                let n = channel::channel_read(st.in_chan, st.tx.as_mut_ptr(), st.tx.len());
                if n <= 0 {
                    break;
                }
                let n = n as usize;
                let sent = host_ws_send(st.handle, st.tx.as_ptr(), n);
                // Treat any non-positive return as a 0-byte partial
                // send and stash the tail — the bytes were already
                // pulled from `in_chan`, so dropping on back-pressure
                // would lose stream data.
                let s = if sent > 0 { (sent as usize).min(n) } else { 0 };
                if s < n {
                    st.tx_pending_len = shift_consume(st.tx.as_mut_ptr(), n, s);
                    break;
                }
                // Fully sent — loop to read more.
            }
        }

        // ── RX: host_ws_recv → out_chan ──
        if st.out_chan >= 0 {
            // Drain pending retry buffer first.
            if st.rx_pending_len > 0 {
                let written = channel::channel_write(
                    st.out_chan,
                    st.rx.as_ptr(),
                    st.rx_pending_len,
                );
                if written > 0 {
                    let w = (written as usize).min(st.rx_pending_len);
                    st.rx_pending_len = shift_consume(st.rx.as_mut_ptr(), st.rx_pending_len, w);
                }
            }
            // Only pull new WS frames if pending drained.
            while st.rx_pending_len == 0 {
                let n = host_ws_recv(st.handle, st.rx.as_mut_ptr(), st.rx.len());
                if n <= 0 {
                    break;
                }
                let n = n as usize;
                let written = channel::channel_write(st.out_chan, st.rx.as_ptr(), n);
                // Treat any non-positive return (CHAN_EAGAIN, error)
                // as a 0-byte partial write and stash the tail. The
                // bytes were already pulled from the JS rxQueue, so
                // dropping on back-pressure would lose stream data.
                let w = if written > 0 { (written as usize).min(n) } else { 0 };
                if w < n {
                    // Stash unwritten tail.
                    st.rx_pending_len = shift_consume(st.rx.as_mut_ptr(), n, w);
                    break;
                }
            }
        }
        0
    }
}

pub(crate) unsafe fn build(url: &[u8], in_chan: i32, out_chan: i32) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_websocket", ws_step);
    let raw = alloc_state(in_chan, out_chan, url);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut WsState, raw);
    m
}
