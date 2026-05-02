//! WsFrame ↔ OctetStream adapter.
//!
//! Sits between `foundation/http`'s WebSocket fan-out ports and any
//! transport-agnostic byte-stream carrier (e.g.
//! `foundation/remote_channel`). The adapter strips/adds the 8-byte
//! `WsFrame` header so the byte-stream layer above doesn't have to
//! know about WebSocket framing.
//!
//! Wire layout (matches `modules/foundation/http/server.rs` ::
//! `ws_emit_fanout_frame`):
//!
//! ```text
//! [conn_id  u32 LE]
//! [opcode   u8 ]
//! [fin      u8 ]
//! [payload_len u16 LE]
//! [payload  payload_len bytes]
//! ```
//!
//! Single-connection model: the adapter latches `active_conn_id`
//! from the most recently observed inbound frame and stamps it on
//! outbound frames. A second connection arriving (different
//! `conn_id`) replaces the latch — its bytes flow, the previous
//! connection's outbound queue starves silently. Multi-client session
//! routing is a layer above this; the adapter is a framing
//! conversion, nothing more.
//!
//! Opcode handling:
//!   - 0x0 continuation, 0x1 text, 0x2 binary → payload forwarded to
//!     `rx_out` as raw bytes (OctetStream consumers don't care which).
//!   - 0x8 close, 0x9 ping, 0xA pong → silently dropped. The http
//!     module handles ping/close at the WS layer; the adapter
//!     tolerates them defensively if any leak through.
//!
//! Outbound frames are always opcode = 0x2 (binary) with fin = 1.
//!
//! ## Backpressure (lossless under steady-state)
//!
//! Both directions own a per-instance retry buffer. The inbound
//! retry holds an in-flight WsFrame's payload that didn't fit in
//! `rx_out`; the outbound retry holds a framed message that
//! didn't fit in `tx_out`. Drained first on the next step before
//! pulling new input. No bytes are dropped under back-pressure;
//! upstream channel back-pressure applies normally if the retry
//! buffer is held full for a sustained period.

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

const WS_FRAME_HDR: usize = 8;
const FRAME_BUF_BYTES: usize = abi::CHANNEL_BUFFER_SIZE;
const WS_OPCODE_BINARY: u8 = 0x2;

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    tx_in: i32,
    tx_out: i32,
    rx_in: i32,
    rx_out: i32,
    active_conn_id: u32,
    has_conn: bool,
    /// Outbound retry buffer: a fully-framed WsFrame waiting to be
    /// written to `tx_out`. `tx_pending_len == 0` means the buffer
    /// is drained and a new TX read may proceed.
    tx_pending: [u8; FRAME_BUF_BYTES],
    tx_pending_len: usize,
    /// Inbound retry buffer: a WsFrame's payload waiting to be
    /// written to `rx_out`. Same drain-first semantics.
    rx_pending: [u8; FRAME_BUF_BYTES],
    rx_pending_len: usize,
    /// Inbound parse scratch: holds the raw WsFrame as read from
    /// `rx_in` while we extract the payload. Reused per frame; not
    /// retained across steps.
    scratch: [u8; FRAME_BUF_BYTES],
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if state.is_null() || state_size < core::mem::size_of::<State>() || syscalls.is_null() {
        return -1;
    }
    let sys = syscalls as *const SyscallTable;
    let sys_ref = unsafe { &*sys };
    let s = unsafe { &mut *(state as *mut State) };
    s.syscalls = sys;
    s.tx_in = unsafe { dev_channel_port(sys_ref, 0, 0) };
    s.rx_in = unsafe { dev_channel_port(sys_ref, 0, 1) };
    s.tx_out = unsafe { dev_channel_port(sys_ref, 1, 0) };
    s.rx_out = unsafe { dev_channel_port(sys_ref, 1, 1) };
    s.active_conn_id = 0;
    s.has_conn = false;
    s.tx_pending = [0u8; FRAME_BUF_BYTES];
    s.tx_pending_len = 0;
    s.rx_pending = [0u8; FRAME_BUF_BYTES];
    s.rx_pending_len = 0;
    s.scratch = [0u8; FRAME_BUF_BYTES];
    0
}

/// Shift-compact the leading `consumed` bytes out of `buf[..len]`.
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

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    if state.is_null() {
        return -1;
    }
    let s = unsafe { &mut *(state as *mut State) };
    if s.syscalls.is_null() {
        return -1;
    }
    let sys = unsafe { &*s.syscalls };

    // ── Inbound: rx_in (WsFrame) → rx_out (OctetStream) ──
    if s.rx_in >= 0 && s.rx_out >= 0 {
        // Drain the pending retry buffer first.
        if s.rx_pending_len > 0 {
            let written = unsafe {
                (sys.channel_write)(s.rx_out, s.rx_pending.as_ptr(), s.rx_pending_len)
            };
            if written > 0 {
                let w = (written as usize).min(s.rx_pending_len);
                s.rx_pending_len =
                    unsafe { shift_consume(s.rx_pending.as_mut_ptr(), s.rx_pending_len, w) };
            }
        }
        // Pull new frames only when retry buffer drained.
        while s.rx_pending_len == 0 {
            let n = unsafe {
                (sys.channel_read)(s.rx_in, s.scratch.as_mut_ptr(), s.scratch.len())
            };
            if n < WS_FRAME_HDR as i32 {
                break;
            }
            let n = n as usize;
            let conn_id = u32::from_le_bytes([s.scratch[0], s.scratch[1], s.scratch[2], s.scratch[3]]);
            let opcode = s.scratch[4];
            let _fin = s.scratch[5];
            let payload_len = u16::from_le_bytes([s.scratch[6], s.scratch[7]]) as usize;
            if WS_FRAME_HDR + payload_len > n {
                break;
            }
            s.active_conn_id = conn_id;
            s.has_conn = true;
            let is_data = matches!(opcode, 0x0 | 0x1 | WS_OPCODE_BINARY);
            if !is_data || payload_len == 0 {
                continue;
            }
            // Try to write directly first.
            let written = unsafe {
                (sys.channel_write)(
                    s.rx_out,
                    s.scratch.as_ptr().add(WS_FRAME_HDR),
                    payload_len,
                )
            };
            // CHAN_EAGAIN (negative return) is back-pressure, not
            // an error. The payload was already pulled from rx_in,
            // so treat any non-positive return as a 0-byte partial
            // write and stash the tail in `rx_pending` for the
            // next step rather than dropping bytes.
            let w = if written > 0 { (written as usize).min(payload_len) } else { 0 };
            if w < payload_len {
                // Stash unwritten tail in retry buffer.
                let tail = payload_len - w;
                let cap = s.rx_pending.len();
                let take = tail.min(cap);
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        s.scratch.as_ptr().add(WS_FRAME_HDR + w),
                        s.rx_pending.as_mut_ptr(),
                        take,
                    );
                }
                s.rx_pending_len = take;
                break;
            }
        }
    }

    // ── Outbound: tx_in (OctetStream) → tx_out (WsFrame) ──
    //
    // No `has_conn` gate: the http gateway ignores conn_id when only
    // one client is active (server.rs ws_drain_fanout_input), and
    // bundles like zedex-pi5-split push data outbound before the
    // browser sends anything inbound. Stamping conn_id = 0 until we
    // observe a real inbound frame is harmless under that semantic
    // and unblocks the producer-first flow.
    if s.tx_in >= 0 && s.tx_out >= 0 {
        // Drain the pending framed message first.
        if s.tx_pending_len > 0 {
            let written = unsafe {
                (sys.channel_write)(s.tx_out, s.tx_pending.as_ptr(), s.tx_pending_len)
            };
            if written > 0 {
                let w = (written as usize).min(s.tx_pending_len);
                s.tx_pending_len =
                    unsafe { shift_consume(s.tx_pending.as_mut_ptr(), s.tx_pending_len, w) };
            }
        }
        // Pull new input only when pending drained.
        let max_payload = FRAME_BUF_BYTES - WS_FRAME_HDR;
        while s.tx_pending_len == 0 {
            let n = unsafe {
                (sys.channel_read)(
                    s.tx_in,
                    s.tx_pending.as_mut_ptr().add(WS_FRAME_HDR),
                    max_payload,
                )
            };
            if n <= 0 {
                break;
            }
            let payload_len = n as usize;
            let conn_le = s.active_conn_id.to_le_bytes();
            s.tx_pending[0] = conn_le[0];
            s.tx_pending[1] = conn_le[1];
            s.tx_pending[2] = conn_le[2];
            s.tx_pending[3] = conn_le[3];
            s.tx_pending[4] = WS_OPCODE_BINARY;
            s.tx_pending[5] = 1;
            let plen_le = (payload_len as u16).to_le_bytes();
            s.tx_pending[6] = plen_le[0];
            s.tx_pending[7] = plen_le[1];
            let total = WS_FRAME_HDR + payload_len;
            // Try direct write first.
            let written =
                unsafe { (sys.channel_write)(s.tx_out, s.tx_pending.as_ptr(), total) };
            if written < 0 {
                // tx_out back-pressured. Stash the whole frame and
                // break — looping back to read more from tx_in would
                // shred the stream.
                s.tx_pending_len = total;
                break;
            }
            let w = (written as usize).min(total);
            if w < total {
                // Hold tail; tx_pending_len remembers what's left.
                s.tx_pending_len =
                    unsafe { shift_consume(s.tx_pending.as_mut_ptr(), total, w) };
                break;
            }
            // Fully sent; loop reads more.
        }
    }

    0
}

#[no_mangle]
pub extern "C" fn module_arena_size() -> u32 {
    0
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
include!("../../sdk/wasm_entry.rs");
