//! Asset Bank PIC Module (Seekable Version)
//!
//! File selector and audio streamer for the sd->fat32->bank pipeline.
//! Receives audio data from fat32, handles FMP commands for navigation,
//! and outputs audio to downstream modules.
//!
//! # Architecture
//!
//! ```text
//! gesture ---[ctrl]---> [bank] --out.0--> decoder ---> i2s
//!                          ^       \--out.1--> notifications (FMP)
//! fat32 ------[data]------/
//!        ^
//!        |
//!        +--- IOCTL_NOTIFY(file_index) when selection changes
//! ```
//!
//! # Configuration
//!
//! Params layout:
//!   [0-1]   file_count: u16 (total files available)
//!   [2]     mode: u8 (0=once, 1=loop navigation)
//!   [3]     initial_index: u8
//!   [4]     auto_advance: u8 (1=auto-advance on EOF, 0=pause on EOF; default 1)
//!
//! # FMP Commands (accepted on ctrl_chan)
//!
//!   - `next`: advance to next file
//!   - `prev`: go to previous file
//!   - `toggle`: play/pause
//!   - `select`: jump to specific file (payload[0..2] = u16 index)
//!
//! # FMP Notifications (emitted on out[1])
//!
//!   - `status`: { index: u16, count: u16, file_type: u8, flags: u8 }
//!
//! # Behavior
//!
//! - On init: Sends IOCTL_NOTIFY to select initial file
//! - On control message: Sends IOCTL_NOTIFY to switch files
//! - In steady state: Passes file data through to output

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

// ============================================================================
// Constants
// ============================================================================

/// Buffer size for pass-through
const BUF_SIZE: usize = 512;

/// Bank modes
const MODE_LOOP: u8 = 1;

// ============================================================================
// State Machine
// ============================================================================

/// Bank module phases.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum BankPhase {
    Init = 0,
    Running = 1,
}

// ============================================================================
// State Structure
// ============================================================================

#[repr(C)]
struct BankState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    /// Output channels: [0]=data, [1]=state notifications
    out_chans: [i32; 2],
    ctrl_chan: i32,

    /// Total number of files
    count: u16,
    /// Current selection index
    index: u16,
    /// Navigation mode
    mode: u8,
    /// Module phase
    phase: BankPhase,
    /// Number of active output ports
    out_count: u8,
    /// Paused flag
    paused: u8,
    /// Auto-advance on EOF (1=advance to next, 0=pause)
    auto_advance: u8,

    /// Pending write tracking for data output
    pending_out: u16,
    pending_offset: u16,

    /// Pass-through buffer
    buf: [u8; BUF_SIZE],
    /// Scratch buffer for FMP message payloads
    msg_buf: [u8; 16],
}

impl BankState {
    #[inline(always)]
    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }
}

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::BankState;
    use super::{p_u8, p_u16};
    use super::SCHEMA_MAX;

    define_params! {
        BankState;

        1, file_count, u16, 0
            => |s, d, len| { s.count = p_u16(d, len, 0, 0); };

        2, mode, u8, 1, enum { once=0, loop=1 }
            => |s, d, len| { s.mode = p_u8(d, len, 0, 1); };

        3, initial_index, u8, 0
            => |s, d, len| { s.index = p_u8(d, len, 0, 0) as u16; };

        4, auto_advance, u8, 1, enum { off=0, on=1 }
            => |s, d, len| { s.auto_advance = p_u8(d, len, 0, 1); };
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

#[inline(always)]
unsafe fn read_u16_at(ptr: *const u8, offset: usize) -> u16 {
    let p = ptr.add(offset);
    u16::from_le_bytes([*p, *p.add(1)])
}

#[inline(always)]
unsafe fn log_info(s: &BankState, msg: &[u8]) {
    dev_log(s.sys(), 3, msg.as_ptr(), msg.len());
}

/// Send seek request to input channel (fat32)
#[inline]
unsafe fn seek_file(s: &BankState, index: u16) -> i32 {
    let mut pos = index as u32;
    let pos_ptr = &mut pos as *mut u32 as *mut u8;
    // Signal decoder to reset — it will flush its own input when it sees HUP.
    // Don't flush out_chans[0] here: FLUSH clears eof_flag, and the decoder
    // hasn't polled yet (cooperative scheduler). Let decoder own the cleanup.
    if s.out_chans[0] >= 0 {
        dev_channel_ioctl(s.sys(), s.out_chans[0], IOCTL_EOF, core::ptr::null_mut());
    }
    // Flush input channel (clears fat32's eof_flag + buffer) and seek to new file
    dev_channel_ioctl(s.sys(), s.in_chan, IOCTL_FLUSH, core::ptr::null_mut());
    dev_channel_ioctl(s.sys(), s.in_chan, IOCTL_NOTIFY, pos_ptr)
}

/// Advance to next file (shared by `next` command and auto-advance).
/// Returns true if index changed.
#[inline]
unsafe fn advance_next(s: &mut BankState) -> bool {
    if s.count == 0 {
        return false;
    }
    let new_index = s.index + 1;
    if new_index >= s.count {
        if s.mode == MODE_LOOP {
            s.index = 0;
        } else {
            return false; // No wrap, already at end
        }
    } else {
        s.index = new_index;
    }
    true
}

/// Send state notification as FMP message on out_chans[1] (if wired)
/// Payload: { index: u16, count: u16, file_type: u8, flags: u8 }
#[inline]
unsafe fn emit_notification(s: &BankState) {
    if s.out_count < 2 {
        return;
    }
    let chan = s.out_chans[1];
    let poll = (s.sys().channel_poll)(chan, POLL_OUT);
    if poll > 0 && (poll as u32 & POLL_OUT) != 0 {
        let mut payload = [0u8; 6];
        let ib = s.index.to_le_bytes();
        payload[0] = ib[0]; payload[1] = ib[1];
        let cb = s.count.to_le_bytes();
        payload[2] = cb[0]; payload[3] = cb[1];
        payload[4] = 0; // file_type: unknown until decoder reports
        payload[5] = s.paused;
        msg_write(s.sys(), chan, MSG_STATUS, payload.as_ptr(), 6);
    }
}

// ============================================================================
// Module API
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<BankState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<BankState>() {
            return -2;
        }
        let s = &mut *(state as *mut BankState);
        let sys = syscalls as *const SyscallTable;
        s.syscalls = sys;
        s.in_chan = in_chan;
        s.out_chans[0] = out_chan;
        // Discover second output port (state notifications) via channel_port
        s.out_chans[1] = dev_channel_port(&*sys, 1, 1);
        s.out_count = if s.out_chans[1] >= 0 { 2 } else { 1 };
        s.ctrl_chan = ctrl_chan;

        s.phase = BankPhase::Init;
        s.paused = 0;

        // Parse params
        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;

        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else if !params.is_null() && params_len >= 2 {
            s.count = read_u16_at(params, 0);
            s.mode = if params_len >= 3 { *params.add(2) } else { MODE_LOOP };
            s.index = if params_len >= 4 { *params.add(3) as u16 } else { 0 };
        } else {
            params_def::set_defaults(s);
        }

        if s.index >= s.count && s.count > 0 {
            s.index = 0;
        }

        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut BankState);
        if s.syscalls.is_null() {
            return -1;
        }

        // Initialization: seek to initial file
        if s.phase == BankPhase::Init {
            if s.in_chan >= 0 && s.count > 0 {
                // Don't use seek_file() here — it sends EOF on the output
                // channel, but there's no prior stream to close. A spurious
                // HUP would cause downstream to reset immediately.
                let mut pos = s.index as u32;
                let pos_ptr = &mut pos as *mut u32 as *mut u8;
                dev_channel_ioctl(s.sys(), s.in_chan, IOCTL_FLUSH, core::ptr::null_mut());
                dev_channel_ioctl(s.sys(), s.in_chan, IOCTL_NOTIFY, pos_ptr);
                emit_notification(s);
                log_info(s, b"[bank] init seek");
            }
            s.phase = BankPhase::Running;
            return 0;
        }

        // Process FMP commands from ctrl_chan
        if s.ctrl_chan >= 0 {
            let sys = &*s.syscalls;
            let poll_ctrl = (sys.channel_poll)(s.ctrl_chan, POLL_IN);
            if poll_ctrl > 0 && (poll_ctrl as u32 & POLL_IN) != 0 {
                let (ty, _len) = msg_read(sys, s.ctrl_chan, s.msg_buf.as_mut_ptr(), 16);
                if ty != 0 {
                    match ty {
                        MSG_TOGGLE => {
                            s.paused = if s.paused != 0 { 0 } else { 1 };
                            emit_notification(s);
                            log_info(s, b"[bank] toggle");
                        }
                        MSG_NEXT => {
                            if advance_next(s) {
                                s.paused = 0;
                                seek_file(s, s.index);
                                emit_notification(s);
                                log_info(s, b"[bank] next");
                            }
                        }
                        MSG_PREV => {
                            if s.count > 0 {
                                if s.index == 0 {
                                    if s.mode == MODE_LOOP {
                                        s.index = s.count - 1;
                                    }
                                } else {
                                    s.index -= 1;
                                }
                                s.paused = 0;
                                seek_file(s, s.index);
                                emit_notification(s);
                                log_info(s, b"[bank] prev");
                            }
                        }
                        MSG_SELECT => {
                            // Payload: u16 index
                            if _len >= 2 {
                                let target = u16::from_le_bytes([s.msg_buf[0], s.msg_buf[1]]);
                                if s.count > 0 && target < s.count {
                                    s.index = target;
                                    s.paused = 0;
                                    seek_file(s, s.index);
                                    emit_notification(s);
                                    log_info(s, b"[bank] select");
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // EOF handling: detect EOF from fat32 (file finished streaming)
        if s.paused == 0 && s.in_chan >= 0 && s.phase == BankPhase::Running {
            let poll = (s.sys().channel_poll)(s.in_chan, POLL_IN | POLL_HUP);
            if poll > 0 && ((poll as u32) & POLL_HUP) != 0 && ((poll as u32) & POLL_IN) == 0 {
                if s.auto_advance != 0 {
                    // Auto-advance to next file
                    if advance_next(s) {
                        seek_file(s, s.index);
                        emit_notification(s);
                        log_info(s, b"[bank] auto");
                    }
                } else {
                    // Pause and wait for explicit next/prev command
                    s.paused = 1;
                    emit_notification(s);
                }
            }
        }

        // Pass-through: read from fat32, write to data output
        // When paused, skip reading — backpressure propagates naturally
        if s.paused == 0 && s.in_chan >= 0 && s.out_chans[0] >= 0 {
            // Check if we can read
            let poll_in = (s.sys().channel_poll)(s.in_chan, POLL_IN);
            // Drain any pending data from previous partial write
            if s.pending_out > 0 {
                let sys = &*s.syscalls;
                if !drain_pending(
                    sys, s.out_chans[0],
                    s.buf.as_ptr(),
                    &mut s.pending_out,
                    &mut s.pending_offset,
                ) {
                    return 0; // Still draining pending
                }
            }

            if poll_in > 0 && (poll_in as u32 & POLL_IN) != 0 {
                // Check if we can write
                let poll_out = (s.sys().channel_poll)(s.out_chans[0], POLL_OUT);
                if poll_out > 0 && (poll_out as u32 & POLL_OUT) != 0 {
                    // Read data
                    let read = (s.sys().channel_read)(
                        s.in_chan,
                        s.buf.as_mut_ptr(),
                        BUF_SIZE,
                    );

                    if read > 0 {
                        // Write to data output with pending tracking
                        let written = (s.sys().channel_write)(
                            s.out_chans[0],
                            s.buf.as_ptr(),
                            read as usize,
                        );
                        track_pending(written, read as usize, &mut s.pending_out, &mut s.pending_offset);
                    }
                }
            }
        }

        0
    }
}

// ============================================================================
// Channel Hints
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_channel_hints"]
pub extern "C" fn module_channel_hints(out: *mut u8, max_len: usize) -> i32 {
    let hints = [
        ChannelHint { port_type: 1, port_index: 1, buffer_size: 256 }, // out[1]: bank notifications
        ChannelHint { port_type: 2, port_index: 0, buffer_size: 256 }, // ctrl[0]: control events
    ];
    unsafe { write_channel_hints(out, max_len, &hints) }
}

// ============================================================================
// Panic Handler
// ============================================================================

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/wasm_entry.rs");
