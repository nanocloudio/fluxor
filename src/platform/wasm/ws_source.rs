//! `wasm_browser_ws_source` native module: receive-only WebSocket source
//! that emits its incoming binary messages on the output channel as a
//! `VideoRaster` byte stream.
//!
//! This is the "thin viewer" half of a split-deployment image pipeline: an
//! upstream node decodes images and pushes raster records over `/ws`; the
//! browser hosts this module, which pulls the bytes through the `host_ws_*`
//! shim and forwards them to `wasm_browser_canvas`. It relays bytes and
//! reads none of them: the remote producer writes each record's region
//! header (`abi::contracts::video_raster`) and the consumer checks it. The
//! same canvas module is wired in the pure-wasm graph behind
//! `wasm_browser_image_codec`, so where the decoder runs is a graph-wiring
//! choice.
//!
//! State: heap-allocated on the module's own heap; its arena state
//! holds the `*mut WsSourceState` pointer.
//!
//! Backpressure: any non-positive `channel_write` return value stashes
//! the unwritten tail in `rx` and gates further pulls from the JS
//! rxQueue until the channel accepts again. Same pattern as
//! `wasm_browser_websocket`.

use crate::abi::platform::native::wasm::wasm_browser_ws_source as tags;
use crate::kernel::exec::scheduler;
use crate::kernel::exec::scheduler::{NativeInit, NativeVtable};
use crate::kernel::ipc::channel;
use crate::kernel::module::syscalls;

extern "C" {
    /// Open a WebSocket. Shared with `wasm_browser_websocket` — the
    /// shim is socket-typed, not module-typed; multiple kernel-side
    /// modules can each hold their own handle.
    fn host_ws_open(url_ptr: *const u8, url_len: usize) -> i32;

    /// Receive the oldest pending message bytes from the WebSocket
    /// into `buf`. Returns the number of bytes written, 0 if the queue
    /// is empty, or negative on error / EOF. Large messages may be
    /// returned across multiple calls; this module is byte-stream
    /// oriented, and the downstream consumer reassembles each record
    /// from arbitrary chunks by the length its header states.
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

/// # Safety
/// `state` is this module's own arena state, exclusively the
/// step's for its duration.
unsafe extern "C" fn ws_source_step(state: *mut u8) -> i32 {
    // SAFETY: state is the kernel-provided opaque state pointer for
    // this module instance; we cast it back to the module-private state
    // type allocated by the constructor and operate within that allocation.
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
            let written = channel::channel_write(st.out_chan, st.rx.as_ptr(), st.rx_pending_len);
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

/// The `wasm_browser_ws_source` native module.
pub static WASM_BROWSER_WS_SOURCE: NativeVtable = super::heap_native(
    new,
    ws_source_step,
    crate::abi::platform::native::wasm::wasm_browser_ws_source::STATE_BYTES,
);

/// # Safety
/// `state` is the instance's zeroed arena state; the current module is
/// `init.slot`.
unsafe fn new(state: *mut u8, init: &NativeInit<'_>) -> i32 {
    let mut url_buf = [0u8; 256];
    let url = super::param_bytes(init.params, tags::TAG_URL, &mut url_buf);
    let out_chan = scheduler::module_port(init.slot, tags::PORT_BYTES);
    // SAFETY: the constructor's own contract; the instance is built on
    // the slot's heap, which the current module allocates through.
    unsafe {
        super::seat_heap_instance(
            state,
            init.slot,
            &crate::abi::platform::native::wasm::wasm_browser_ws_source::HEAP_SEAT,
            init.params,
            || alloc_state(out_chan, url).cast(),
        )
    }
}

const _: () = assert!(
    crate::abi::platform::native::wasm::wasm_browser_ws_source::HEAP_SEAT[0] as usize
        >= super::heap_for::<WsSourceState>(),
    "the declared heap seat holds the instance"
);
