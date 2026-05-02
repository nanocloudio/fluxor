//! Remote-channel multiplexer.
//!
//! Multiplexes up to 4 logical Fluxor channels onto a single byte
//! transport. See `manifest.toml` for the wire format and port
//! layout. Transport-agnostic: works over WebSocket, TCP, serial,
//! anything that carries bytes in order.
//!
//! Per-tick budget: drains the outbound retry buffer first, then
//! pulls from each local-input channel in order and frames each
//! block to the transport. On the inbound side, drains the inbound
//! retry buffer first, then peels complete frames from the parse
//! buffer and dispatches each to its target output channel. If
//! either downstream surface (transport-tx or a local-output
//! channel) accepts less than offered, the unsent tail stays in the
//! corresponding retry buffer and drains first on the next step.
//!
//! ## Backpressure (lossless under steady-state)
//!
//! No bytes are dropped under back-pressure. The retry buffers are
//! fixed-size; while one is held full the module pauses ingest in
//! that direction, so upstream channel back-pressure applies
//! normally. There is no DROP path on overflow.

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

const N_CHANNELS: usize = 4;
const FRAME_MAGIC: u8 = 0xFC;
const HEADER_BYTES: usize = 4;
/// Maximum payload bytes per frame. Must fit in u16 length field.
const MAX_PAYLOAD: usize = 1024;
const FRAME_TOTAL_MAX: usize = HEADER_BYTES + MAX_PAYLOAD;
/// Parse buffer for partial inbound frames. Sized to hold one max
/// frame plus a little slack for resync.
const PARSE_BUF_BYTES: usize = HEADER_BYTES + MAX_PAYLOAD + 64;

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    /// `[ch0..ch3, transport_rx]` input handles.
    in_chans: [i32; N_CHANNELS + 1],
    /// `[ch0_rx..ch3_rx, transport_tx]` output handles.
    out_chans: [i32; N_CHANNELS + 1],
    /// Inbound parse buffer: raw bytes from the transport waiting to
    /// have complete frames peeled off the front.
    parse_buf: [u8; PARSE_BUF_BYTES],
    parse_len: usize,
    /// Outbound retry: a fully-framed message waiting to write to
    /// `transport_tx`. `out_pending_len == 0` means drained and a new
    /// outbound read may proceed.
    out_pending: [u8; FRAME_TOTAL_MAX],
    out_pending_len: usize,
    /// Inbound retry: a payload waiting to write to `out_chans[in_pending_target]`.
    in_pending: [u8; MAX_PAYLOAD],
    in_pending_len: usize,
    in_pending_target: u8,
    /// Round-robin starting channel for the next outbound iteration.
    /// Avoids starving channels 1..3 when channel 0 is always busy.
    rr_start: u8,
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
    let s = unsafe { &mut *(state as *mut State) };
    s.syscalls = sys;

    let sys_ref = unsafe { &*sys };
    for i in 0..N_CHANNELS {
        s.in_chans[i] = unsafe { dev_channel_port(sys_ref, 0, i as u8) };
        s.out_chans[i] = unsafe { dev_channel_port(sys_ref, 1, i as u8) };
    }
    s.in_chans[N_CHANNELS] = unsafe { dev_channel_port(sys_ref, 0, N_CHANNELS as u8) };
    s.out_chans[N_CHANNELS] = unsafe { dev_channel_port(sys_ref, 1, N_CHANNELS as u8) };

    s.parse_buf = [0u8; PARSE_BUF_BYTES];
    s.parse_len = 0;
    s.out_pending = [0u8; FRAME_TOTAL_MAX];
    s.out_pending_len = 0;
    s.in_pending = [0u8; MAX_PAYLOAD];
    s.in_pending_len = 0;
    s.in_pending_target = 0;
    s.rr_start = 0;
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
    let transport_tx = s.out_chans[N_CHANNELS];
    let transport_rx = s.in_chans[N_CHANNELS];

    // ── Outbound: each local channel → transport ──
    if transport_tx >= 0 {
        // Drain the pending frame first.
        if s.out_pending_len > 0 {
            let written = unsafe {
                (sys.channel_write)(transport_tx, s.out_pending.as_ptr(), s.out_pending_len)
            };
            if written > 0 {
                let w = (written as usize).min(s.out_pending_len);
                s.out_pending_len = unsafe {
                    shift_consume(s.out_pending.as_mut_ptr(), s.out_pending_len, w)
                };
            }
        }
        // Round-robin scan local inputs only when pending drained.
        if s.out_pending_len == 0 {
            for off in 0..N_CHANNELS {
                let ch = ((s.rr_start as usize + off) % N_CHANNELS) as u8;
                let in_chan = s.in_chans[ch as usize];
                if in_chan < 0 {
                    continue;
                }
                let n = unsafe {
                    (sys.channel_read)(
                        in_chan,
                        s.out_pending.as_mut_ptr().add(HEADER_BYTES),
                        MAX_PAYLOAD,
                    )
                };
                if n <= 0 {
                    continue;
                }
                let n = n as usize;
                s.out_pending[0] = FRAME_MAGIC;
                s.out_pending[1] = ch;
                s.out_pending[2] = (n & 0xFF) as u8;
                s.out_pending[3] = ((n >> 8) & 0xFF) as u8;
                let total = HEADER_BYTES + n;
                let written = unsafe {
                    (sys.channel_write)(transport_tx, s.out_pending.as_ptr(), total)
                };
                if written < 0 {
                    // Transport error — drop this frame and stop.
                    break;
                }
                let w = (written as usize).min(total);
                if w < total {
                    s.out_pending_len = unsafe {
                        shift_consume(s.out_pending.as_mut_ptr(), total, w)
                    };
                    s.rr_start = ((ch as usize + 1) % N_CHANNELS) as u8;
                    break;
                }
                // Fully sent; advance round-robin and continue scanning.
                s.rr_start = ((ch as usize + 1) % N_CHANNELS) as u8;
            }
        }
    }

    // ── Inbound: transport → parse → fan out to local channels ──
    if transport_rx >= 0 {
        // Drain the pending payload first (writes to in_pending_target).
        if s.in_pending_len > 0 {
            let target = s.in_pending_target as usize;
            if target < N_CHANNELS {
                let out = s.out_chans[target];
                if out >= 0 {
                    let written = unsafe {
                        (sys.channel_write)(out, s.in_pending.as_ptr(), s.in_pending_len)
                    };
                    if written > 0 {
                        let w = (written as usize).min(s.in_pending_len);
                        s.in_pending_len = unsafe {
                            shift_consume(s.in_pending.as_mut_ptr(), s.in_pending_len, w)
                        };
                    }
                } else {
                    // Target channel disappeared; drop.
                    s.in_pending_len = 0;
                }
            } else {
                s.in_pending_len = 0;
            }
        }

        // Top up parse_buf only when pending drained.
        if s.in_pending_len == 0 {
            let space = PARSE_BUF_BYTES - s.parse_len;
            if space > 0 {
                let n = unsafe {
                    (sys.channel_read)(
                        transport_rx,
                        s.parse_buf.as_mut_ptr().add(s.parse_len),
                        space,
                    )
                };
                if n > 0 {
                    s.parse_len += n as usize;
                }
            }

            loop {
                // Resync to the next FRAME_MAGIC byte.
                let mut start = 0usize;
                while start < s.parse_len && s.parse_buf[start] != FRAME_MAGIC {
                    start += 1;
                }
                if start > 0 {
                    s.parse_len = unsafe {
                        shift_consume(s.parse_buf.as_mut_ptr(), s.parse_len, start)
                    };
                }
                if s.parse_len < HEADER_BYTES {
                    break;
                }
                let ch = s.parse_buf[1] as usize;
                let len = (s.parse_buf[2] as usize) | ((s.parse_buf[3] as usize) << 8);
                if len > MAX_PAYLOAD {
                    s.parse_len = unsafe {
                        shift_consume(s.parse_buf.as_mut_ptr(), s.parse_len, 1)
                    };
                    continue;
                }
                let total = HEADER_BYTES + len;
                if s.parse_len < total {
                    break;
                }

                if ch < N_CHANNELS && len > 0 {
                    let out = s.out_chans[ch];
                    if out >= 0 {
                        let written = unsafe {
                            (sys.channel_write)(
                                out,
                                s.parse_buf.as_ptr().add(HEADER_BYTES),
                                len,
                            )
                        };
                        let w = if written > 0 { (written as usize).min(len) } else { 0 };
                        if w < len {
                            // Stash unwritten tail into in_pending; consume the
                            // frame from parse_buf either way.
                            let tail = len - w;
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    s.parse_buf.as_ptr().add(HEADER_BYTES + w),
                                    s.in_pending.as_mut_ptr(),
                                    tail,
                                );
                            }
                            s.in_pending_len = tail;
                            s.in_pending_target = ch as u8;
                            s.parse_len = unsafe {
                                shift_consume(s.parse_buf.as_mut_ptr(), s.parse_len, total)
                            };
                            break;
                        }
                    }
                }
                // Frame fully delivered (or dropped for invalid ch).
                s.parse_len = unsafe {
                    shift_consume(s.parse_buf.as_mut_ptr(), s.parse_len, total)
                };
            }
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
