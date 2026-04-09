//! File Source Module - Stream audio from file
//!
//! Reads raw audio data from a file and outputs it as audio samples.
//! Supports loop mode for continuous playback.
//!
//! **Params (from config):**
//! - `loop_mode`: 0=once (stop at EOF), 1=loop (restart from beginning)
//! - `sample_rate`: Hz (for timing, must match file format)
//! - `channels`: 1=mono, 2=stereo (default)
//! - `bits`: 8 or 16 (default: 16)
//!
//! **Input:** Control events from bank or direct file path
//! - Event format: { path_ptr: u32, path_len: u32 } to load new file
//! - Or: { index: u16, count: u16, size: u32 } from bank selection
//!
//! **Output:** Raw audio samples (i16 stereo)
//!
//! The module maintains a read buffer and streams data from the filesystem
//! via dev_call with FS opcodes (0x0900-0x09FF).

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


// FS opcodes (from abi::dev_fs)
const FS_OPEN: u32 = 0x0900;
const FS_READ: u32 = 0x0901;
const FS_SEEK: u32 = 0x0902;
const FS_CLOSE: u32 = 0x0903;
const FS_STAT: u32 = 0x0904;

/// Read buffer size (must be multiple of 4 for alignment)
const READ_BUF_SIZE: usize = 512;

/// Output buffer size (stereo samples)
const OUT_BUF_SIZE: usize = 512;

/// Samples per output chunk
const SAMPLES_PER_CHUNK: usize = 128;

/// Maximum path length
const MAX_PATH_LEN: usize = 128;

/// File source playback phases.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum PlayPhase {
    Stopped = 0,
    Playing = 1,
}

// ============================================================================
// Module State
// ============================================================================

#[repr(C)]
struct State {
    /// File descriptor (-1 = not open)
    fd: i32,
    /// File size
    file_size: u32,
    /// Current file position
    file_pos: u32,
    /// Read buffer
    read_buf: [u8; READ_BUF_SIZE],
    /// Bytes available in read buffer
    buf_avail: u16,
    /// Read position in buffer
    buf_pos: u16,
    /// Output buffer
    out_buf: [i16; OUT_BUF_SIZE],
    /// Current file path
    current_path: [u8; MAX_PATH_LEN],
    current_path_len: u8,
    /// Playback phase
    play_phase: PlayPhase,
    /// End of file reached
    eof: bool,
    /// Pending file load
    pending_load: bool,
    /// Pending path
    pending_path: [u8; MAX_PATH_LEN],
    pending_path_len: u8,
    // --- Params (parsed once in module_new) ---
    /// Loop mode: 0=once, 1=loop
    loop_mode: u8,
    /// Number of channels: 1=mono, 2=stereo
    channels: u8,
    /// Bits per sample: 8 or 16
    bits: u8,
    /// Sample rate (for reference, must match file)
    sample_rate: u32,
}

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::State;
    use super::{p_u8, p_u32};
    use super::SCHEMA_MAX;

    define_params! {
        State;

        1, loop_mode, u8, 0, enum { once=0, loop=1 }
            => |s, d, len| { s.loop_mode = p_u8(d, len, 0, 0); };

        2, channels, u8, 2, enum { mono=1, stereo=2 }
            => |s, d, len| { s.channels = p_u8(d, len, 0, 2); };

        3, bits, u8, 16
            => |s, d, len| { s.bits = p_u8(d, len, 0, 16); };

        4, sample_rate, u32, 44100
            => |s, d, len| { s.sample_rate = p_u32(d, len, 0, 44100); };
    }
}

// ============================================================================
// Module Entry Points
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// Module initialization
#[no_mangle]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    _syscalls: *const SyscallTable,
) -> i32 {
    if state.is_null() || state_size < core::mem::size_of::<State>() {
        return -1;
    }

    let state = &mut *(state as *mut State);

    // Initialize state
    state.fd = -1;
    state.file_size = 0;
    state.file_pos = 0;
    state.buf_avail = 0;
    state.buf_pos = 0;
    state.current_path_len = 0;
    state.play_phase = PlayPhase::Stopped;
    state.eof = false;
    state.pending_load = false;
    state.pending_path_len = 0;

    // Parse params
    let is_tlv = !params.is_null() && params_len >= 4
        && *params == 0xFE && *params.add(1) == 0x01;

    if is_tlv {
        params_def::parse_tlv(state, params, params_len);
    } else if !params.is_null() && params_len >= 1 {
        // Legacy flat layout: [loop_mode, channels, bits, _pad, sample_rate(u32)]
        state.loop_mode = *params;
        state.channels = if params_len >= 2 { *params.add(1) } else { 2 };
        state.bits = if params_len >= 3 { *params.add(2) } else { 16 };
        if params_len >= 8 {
            state.sample_rate = u32::from_le_bytes([
                *params.add(4), *params.add(5), *params.add(6), *params.add(7),
            ]);
        } else {
            state.sample_rate = 44100;
        }
    } else {
        params_def::set_defaults(state);
    }

    0 // Success
}

/// Module poll function
#[no_mangle]
pub unsafe extern "C" fn module_poll(
    in_chan: i32,
    out_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    _state_size: usize,
    syscalls: *const SyscallTable,
) -> i32 {
    if state.is_null() || syscalls.is_null() {
        return 0;
    }

    let state = &mut *(state as *mut State);
    let sys = &*syscalls;

    // Check for pending file load
    if state.pending_load {
        state.pending_load = false;
        load_file(state, &state.pending_path.clone(), state.pending_path_len as usize, sys);
    }

    // Check for input events (file selection)
    if in_chan >= 0 {
        let events = (sys.channel_poll)(in_chan, POLL_IN);
        if events & POLL_IN as i32 != 0 {
            // Read event - could be bank selection or direct path
            let mut event_buf = [0u8; 16];
            let bytes = (sys.channel_read)(in_chan, event_buf.as_mut_ptr(), event_buf.len());

            if bytes >= 8 {
                // Simple trigger: any event restarts playback
                if state.fd >= 0 {
                    // Seek to beginning
                    let mut pos_buf = 0u32.to_le_bytes();
                    (sys.dev_call)(state.fd, FS_SEEK, pos_buf.as_mut_ptr(), 4);
                    state.file_pos = 0;
                    state.buf_avail = 0;
                    state.buf_pos = 0;
                    state.eof = false;
                    state.play_phase = PlayPhase::Playing;
                }
            }
        }
    }

    // Output audio if playing and output channel ready
    if state.play_phase == PlayPhase::Playing && out_chan >= 0 {
        let events = (sys.channel_poll)(out_chan, POLL_OUT);
        if events & POLL_OUT as i32 != 0 {
            // Fill output buffer
            let samples_needed = SAMPLES_PER_CHUNK;
            let mut samples_written = 0;

            while samples_written < samples_needed && !state.eof {
                // Refill read buffer if needed
                if state.buf_avail == 0 {
                    if state.fd >= 0 {
                        let bytes_read = (sys.dev_call)(
                            state.fd,
                            FS_READ,
                            state.read_buf.as_mut_ptr(),
                            READ_BUF_SIZE,
                        );

                        if bytes_read > 0 {
                            state.buf_avail = bytes_read as u16;
                            state.buf_pos = 0;
                            state.file_pos += bytes_read as u32;
                        } else if bytes_read == 0 {
                            // EOF
                            if state.loop_mode == 1 {
                                // Loop: seek to beginning
                                let mut pos_buf = 0u32.to_le_bytes();
                                (sys.dev_call)(state.fd, FS_SEEK, pos_buf.as_mut_ptr(), 4);
                                state.file_pos = 0;
                                continue;
                            } else {
                                // Stop
                                state.eof = true;
                                state.play_phase = PlayPhase::Stopped;
                                break;
                            }
                        } else {
                            // Error
                            state.eof = true;
                            break;
                        }
                    } else {
                        break;
                    }
                }

                // Convert samples based on format
                let bytes_per_sample = if state.bits == 8 { 1 } else { 2 };
                let bytes_per_frame = bytes_per_sample * state.channels as usize;

                while state.buf_avail >= bytes_per_frame as u16
                    && samples_written < samples_needed
                {
                    let pos = state.buf_pos as usize;

                    // Read sample(s)
                    let (left, right) = if state.bits == 8 {
                        // 8-bit unsigned, convert to 16-bit signed
                        let l = ((state.read_buf[pos] as i16) - 128) << 8;
                        let r = if state.channels == 2 && pos + 1 < READ_BUF_SIZE {
                            ((state.read_buf[pos + 1] as i16) - 128) << 8
                        } else {
                            l
                        };
                        (l, r)
                    } else {
                        // 16-bit signed little-endian
                        let l = i16::from_le_bytes([
                            state.read_buf[pos],
                            state.read_buf[pos + 1],
                        ]);
                        let r = if state.channels == 2 && pos + 3 < READ_BUF_SIZE {
                            i16::from_le_bytes([
                                state.read_buf[pos + 2],
                                state.read_buf[pos + 3],
                            ])
                        } else {
                            l
                        };
                        (l, r)
                    };

                    // Write stereo output
                    let out_idx = samples_written * 2;
                    state.out_buf[out_idx] = left;
                    state.out_buf[out_idx + 1] = right;

                    state.buf_pos += bytes_per_frame as u16;
                    state.buf_avail -= bytes_per_frame as u16;
                    samples_written += 1;
                }
            }

            // Zero-fill remaining samples if we hit EOF
            while samples_written < samples_needed {
                let out_idx = samples_written * 2;
                state.out_buf[out_idx] = 0;
                state.out_buf[out_idx + 1] = 0;
                samples_written += 1;
            }

            // Write to output channel
            let bytes_to_write = samples_written * 4; // stereo i16
            (sys.channel_write)(
                out_chan,
                state.out_buf.as_ptr() as *const u8,
                bytes_to_write,
            );
        }
    }

    0
}

/// Module cleanup
#[no_mangle]
pub unsafe extern "C" fn module_drop(
    state: *mut u8,
    _state_size: usize,
    syscalls: *const SyscallTable,
) {
    if state.is_null() || syscalls.is_null() {
        return;
    }

    let state = &mut *(state as *mut State);
    let sys = &*syscalls;

    // Close file if open
    if state.fd >= 0 {
        (sys.dev_call)(state.fd, FS_CLOSE, core::ptr::null_mut(), 0);
        state.fd = -1;
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

unsafe fn load_file(state: &mut State, path: &[u8], path_len: usize, sys: &SyscallTable) {
    // Close existing file
    if state.fd >= 0 {
        (sys.dev_call)(state.fd, FS_CLOSE, core::ptr::null_mut(), 0);
        state.fd = -1;
    }

    // Open new file
    let fd = (sys.dev_call)(-1, FS_OPEN, path.as_ptr() as *mut u8, path_len);
    if fd >= 0 {
        state.fd = fd;

        // Get file size (stat returns [size: u32, mtime: u32])
        let mut stat_buf = [0u8; 8];
        (sys.dev_call)(fd, FS_STAT, stat_buf.as_mut_ptr(), 8);
        let size = u32::from_le_bytes([stat_buf[0], stat_buf[1], stat_buf[2], stat_buf[3]]);
        state.file_size = size;
        state.file_pos = 0;
        state.buf_avail = 0;
        state.buf_pos = 0;
        state.eof = false;
        state.play_phase = PlayPhase::Playing;

        // Copy path
        let copy_len = path_len.min(MAX_PATH_LEN);
        state.current_path[..copy_len].copy_from_slice(&path[..copy_len]);
        state.current_path_len = copy_len as u8;
    } else {
        state.play_phase = PlayPhase::Stopped;
    }
}

/// Set file path for loading (called from config or control)
#[no_mangle]
pub unsafe extern "C" fn file_source_set_path(
    state: *mut u8,
    path: *const u8,
    path_len: usize,
) {
    if state.is_null() || path.is_null() || path_len == 0 {
        return;
    }

    let state = &mut *(state as *mut State);
    let copy_len = path_len.min(MAX_PATH_LEN);

    // Copy to pending path
    let path_slice = core::slice::from_raw_parts(path, copy_len);
    state.pending_path[..copy_len].copy_from_slice(path_slice);
    state.pending_path_len = copy_len as u8;
    state.pending_load = true;
}
