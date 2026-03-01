//! Flash Module — BOOTSEL Button + Blob Serving + Runtime Parameter Store
//!
//! Three functions in one module:
//!
//! 1. **BOOTSEL button** — Reads via flash sideband (QSPI CS pin),
//!    debounces, detects click patterns, emits FMP commands on out[0].
//!
//! 2. **Blob serving** — Stores inline data blobs from config presets,
//!    serves them on out[1] via IOCTL_SEEK protocol (replaces data_source).
//!
//! 3. **Param store provider** — Registers via FLASH_STORE_ENABLE. Other
//!    modules persist params via PARAM_STORE/DELETE/CLEAR_ALL syscalls.
//!
//! **Params (from config):**
//! - `mode`: 0=gesture (default), 1=direct (on/off tracks button state)
//! - `debounce_ms`: debounce window in ms (default 50, gesture mode only)
//! - `multi_click_ms`: multi-click timeout window in ms (default 300)
//! - `long_press_ms`: long press threshold in ms (default 500)
//! - `click`: FMP message for single click (default "toggle")
//! - `double_click`: FMP message for double click (default "next")
//! - `triple_click`: FMP message for triple click (default "prev")
//! - `long_press_cmd`: FMP message for long press (default "long_press")
//! - `presets`: inline blob data (type=blob, up to 8 blobs, 4KB total)
//!
//! **Outputs:**
//!   - out[0]: FMP messages (gesture/direct mode commands)
//!   - out[1]: Blob stream (IOCTL_SEEK indexed, 512B chunks, IOCTL_EOF)

#![no_std]

use core::ffi::c_void;

#[path = "../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../pic_runtime.rs");
include!("../param_macro.rs");

// ============================================================================
// Constants — BOOTSEL
// ============================================================================

/// dev_call opcode: FLASH_SIDEBAND
const FLASH_SIDEBAND: u32 = 0x0C10;

/// Flash sideband operation: READ_CS
const READ_CS: u8 = 0;

// Click-mapping defaults (same as gesture module)
const DEFAULT_CLICK: u32 = fnv1a(b"toggle");
const DEFAULT_DOUBLE: u32 = fnv1a(b"next");
const DEFAULT_TRIPLE: u32 = fnv1a(b"prev");
const DEFAULT_LONG: u32 = fnv1a(b"long_press");

// ============================================================================
// Constants — Flash Store Provider
// ============================================================================

const FLASH_STORE_ENABLE: u32 = 0x0C37;
const FLASH_RAW_ERASE: u32 = 0x0C38;
const FLASH_RAW_PROGRAM: u32 = 0x0C39;

const PARAM_STORE_OP: u32 = 0x0C34;
const PARAM_DELETE_OP: u32 = 0x0C35;
const PARAM_CLEAR_ALL_OP: u32 = 0x0C36;

const XIP_BASE: u32 = 0x1000_0000;
const STORE_OFFSET: u32 = 0x003F_F000;
const STORE_XIP: u32 = XIP_BASE + STORE_OFFSET;
const SECTOR_SIZE: usize = 4096;
const HEADER_SIZE: usize = 8;
const ENTRY_HEADER_SIZE: usize = 4;
const MAX_VALUE_LEN: usize = 250;
const PAGE_SIZE: usize = 256;

const STORE_MAGIC: u32 = 0x4650_5846;
const STORE_VERSION: u8 = 1;

const FLAG_TOMBSTONE: u8 = 0x01;
const FLAG_CLEAR_ALL: u8 = 0x02;

const MAX_COMPACT_ENTRIES: usize = 32;
const COMPACT_ARENA_SIZE: usize = 384;

// ============================================================================
// Constants — Blob Serving
// ============================================================================

/// Maximum number of inline blobs
const MAX_BLOBS: usize = 8;

/// Maximum total blob storage (all blobs combined)
const MAX_BLOB_STORAGE: usize = 4096;

/// Write chunk size per step
const BLOB_CHUNK_SIZE: usize = 512;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum StreamPhase {
    Idle = 0,
    Streaming = 1,
}

// ============================================================================
// Gesture State Machine
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum GestureState {
    /// Idle, waiting for first press
    Idle = 0,
    /// Button is currently pressed
    Pressed = 1,
    /// Released, waiting for possible follow-up click
    WaitingForClick = 2,
}

// ============================================================================
// Compact entry — stored in module state for compaction scratch
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
struct CompactEntry {
    module_id: u8,
    tag: u8,
    arena_off: u16,
    value_len: u8,
}

// ============================================================================
// State Structure
// ============================================================================

#[repr(C)]
struct FlashState {
    syscalls: *const SyscallTable,
    out_chan: i32,
    // --- Config params ---
    /// 0=gesture (click/long_press), 1=direct (on/off tracks button state)
    mode: u8,
    _pad0: u8,
    debounce_ms: u16,
    multi_click_ms: u16,
    long_press_ms: u16,
    // --- Debounce state ---
    /// Current debounced state (0=released, 1=pressed)
    current_state: u8,
    /// Raw reading from last sample
    last_raw: u8,
    /// Whether current debounced transition has been processed
    state_processed: u8,
    _pad1: u8,
    /// Timestamp when raw state last changed (for debounce)
    state_change_time: u32,
    // --- Gesture state ---
    gesture: GestureState,
    click_count: u8,
    long_press_emitted: u8,
    _pad2: u8,
    press_time: u32,
    release_time: u32,
    // --- Click-mapping ---
    map_click: u32,
    map_double: u32,
    map_triple: u32,
    map_long_press: u32,
    // --- Error tracking ---
    error_count: u32,
    // --- Flash store provider ---
    registered: u8,
    signaled_ready: u8,
    _pad3: [u8; 2],
    free_offset: u16,
    compact_arena_off: u16,
    compact_count: u8,
    _pad4: [u8; 3],
    compact_entries: [CompactEntry; MAX_COMPACT_ENTRIES],
    compact_arena: [u8; COMPACT_ARENA_SIZE],
    // --- Blob serving (out[1]) ---
    stream_chan: i32,
    blob_count: u8,
    current_blob: u8,
    stream_phase: StreamPhase,
    _blob_pad: u8,
    blob_write_pos: u16,
    blob_remaining: u16,     // bytes remaining for current blob during TLV parsing
    blob_storage_used: u16,
    blob_offsets: [u16; MAX_BLOBS],
    blob_lengths: [u16; MAX_BLOBS],
    blob_storage: [u8; MAX_BLOB_STORAGE],
}

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::FlashState;
    use super::{p_u8, p_u16, p_u32};
    use super::{DEFAULT_CLICK, DEFAULT_DOUBLE, DEFAULT_TRIPLE, DEFAULT_LONG};
    use super::SCHEMA_MAX;

    define_params! {
        FlashState;

        1, debounce_ms, u16, 50
            => |s, d, len| { s.debounce_ms = p_u16(d, len, 0, 50); };

        2, multi_click_ms, u16, 300
            => |s, d, len| { s.multi_click_ms = p_u16(d, len, 0, 300); };

        3, long_press_ms, u16, 500
            => |s, d, len| { s.long_press_ms = p_u16(d, len, 0, 500); };

        4, mode, u8, 0
            => |s, d, len| { s.mode = p_u8(d, len, 0, 0); };

        5, click, u32, 0
            => |s, d, len| { s.map_click = p_u32(d, len, 0, DEFAULT_CLICK); };

        6, double_click, u32, 0
            => |s, d, len| { s.map_double = p_u32(d, len, 0, DEFAULT_DOUBLE); };

        7, triple_click, u32, 0
            => |s, d, len| { s.map_triple = p_u32(d, len, 0, DEFAULT_TRIPLE); };

        8, long_press_cmd, u32, 0
            => |s, d, len| { s.map_long_press = p_u32(d, len, 0, DEFAULT_LONG); };

        9, item_count, u8, 0
            => |s, d, len| { let _ = p_u8(d, len, 0, 0); };

        10, presets, blob, 0
            => |s, d, len| {
                // Self-delimiting blob chunks. First chunk of each blob starts
                // with a 2-byte LE total length header. Subsequent chunks are
                // pure data. blob_remaining tracks bytes left for current blob.
                if len == 0 { return; }

                let mut data = d;
                let mut data_len = len;

                // If no blob in progress, this is the first chunk of a new blob.
                // Read the 2-byte total length header and start a new entry.
                if s.blob_remaining == 0 {
                    if data_len < 2 { return; }
                    let total = (*data.add(0) as u16) | ((*data.add(1) as u16) << 8);
                    data = data.add(2);
                    data_len -= 2;
                    s.blob_remaining = total;

                    let idx = s.blob_count as usize;
                    if idx >= 8 { return; }
                    core::ptr::write_volatile(
                        s.blob_offsets.as_mut_ptr().add(idx),
                        s.blob_storage_used,
                    );
                    core::ptr::write_volatile(
                        s.blob_lengths.as_mut_ptr().add(idx),
                        0,
                    );
                    s.blob_count += 1;
                }

                if data_len == 0 || s.blob_count == 0 { return; }

                // Append data to current blob
                let idx = (s.blob_count - 1) as usize;
                let copy_len = if data_len < s.blob_remaining as usize {
                    data_len
                } else {
                    s.blob_remaining as usize
                };
                if (s.blob_storage_used as usize) + copy_len <= 4096 {
                    let off = s.blob_storage_used as usize;
                    let dst = s.blob_storage.as_mut_ptr().add(off);
                    let mut i = 0usize;
                    while i < copy_len {
                        core::ptr::write_volatile(dst.add(i), *data.add(i));
                        i += 1;
                    }
                    let prev_len = core::ptr::read_volatile(
                        s.blob_lengths.as_ptr().add(idx),
                    );
                    core::ptr::write_volatile(
                        s.blob_lengths.as_mut_ptr().add(idx),
                        prev_len + copy_len as u16,
                    );
                    s.blob_storage_used += copy_len as u16;
                }
                s.blob_remaining -= copy_len as u16;
            };
    }
}

// ============================================================================
// Module API
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<FlashState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> i32 {
    1
}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    _in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
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
        if state_size < core::mem::size_of::<FlashState>() {
            return -2;
        }

        let s = &mut *(state as *mut FlashState);
        s.syscalls = syscalls as *const SyscallTable;
        s.out_chan = out_chan;

        // Initialize runtime state
        s.current_state = 0;
        s.last_raw = 0;
        s.state_change_time = 0;
        s.state_processed = 1;
        s.mode = 0;
        s._pad0 = 0;
        s._pad1 = 0;
        s.gesture = GestureState::Idle;
        s.click_count = 0;
        s.long_press_emitted = 0;
        s._pad2 = 0;
        s.press_time = 0;
        s.release_time = 0;
        s.map_click = DEFAULT_CLICK;
        s.map_double = DEFAULT_DOUBLE;
        s.map_triple = DEFAULT_TRIPLE;
        s.map_long_press = DEFAULT_LONG;
        s.error_count = 0;

        // Flash store provider state
        s.registered = 0;
        s.signaled_ready = 0;
        s._pad3 = [0; 2];
        s.free_offset = 0;
        s.compact_arena_off = 0;
        s.compact_count = 0;
        s._pad4 = [0; 3];

        // Blob serving state
        s.stream_chan = dev_channel_port(&*(syscalls as *const SyscallTable), 1, 1); // out[1]
        s.blob_count = 0;
        s.current_blob = 0;
        s.stream_phase = StreamPhase::Idle;
        s._blob_pad = 0;
        s.blob_write_pos = 0;
        s.blob_storage_used = 0;

        // Parse params
        let is_tlv_v2 = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x02;

        if is_tlv_v2 {
            params_def::parse_tlv_v2(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        // Log blob state if any blobs loaded
        if s.blob_count > 0 {
            let sys = &*s.syscalls;
            let mut lb = [0u8; 40];
            let pfx = b"[flash] blobs=";
            let mut p = 0usize;
            while p < pfx.len() {
                *lb.as_mut_ptr().add(p) = *pfx.as_ptr().add(p);
                p += 1;
            }
            p += fmt_u32_raw(lb.as_mut_ptr().add(p), s.blob_count as u32);
            let mid = b" bytes=";
            let mut mi = 0usize;
            while mi < mid.len() {
                *lb.as_mut_ptr().add(p) = *mid.as_ptr().add(mi);
                p += 1; mi += 1;
            }
            p += fmt_u32_raw(lb.as_mut_ptr().add(p), s.blob_storage_used as u32);
            let ch = b" ch=";
            let mut ci = 0usize;
            while ci < ch.len() {
                *lb.as_mut_ptr().add(p) = *ch.as_ptr().add(ci);
                p += 1; ci += 1;
            }
            p += fmt_u32_raw(lb.as_mut_ptr().add(p), s.stream_chan as u32);
            dev_log(sys, 3, lb.as_ptr(), p);
        }

        // No GPIO claim needed — BOOTSEL is accessed via flash sideband

        // Seed debouncer with initial read to prevent ghost press at boot
        {
            let sys = &*s.syscalls;
            let mut arg = [READ_CS];
            let level = (sys.dev_call)(-1, FLASH_SIDEBAND, arg.as_mut_ptr(), 1);

            if level >= 0 {
                // Kernel returns 1=pressed, 0=not pressed
                let raw = if level != 0 { 1u8 } else { 0u8 };
                s.last_raw = raw;
                s.current_state = raw;
                s.state_processed = 1;
            }
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
        let s = &mut *(state as *mut FlashState);
        if s.syscalls.is_null() {
            return -1;
        }

        let sys = &*s.syscalls;

        // ---- Register as flash store provider on first step ----
        if s.registered == 0 {
            let fn_addr = flash_store_dispatch as usize as u32;
            let mut args = fn_addr.to_le_bytes();
            let result = (sys.dev_call)(-1, FLASH_STORE_ENABLE, args.as_mut_ptr(), 4);
            if result < 0 {
                return result;
            }
            s.registered = 1;
            init_free_offset(s);
        }

        // ---- Signal ready (once) — gates downstream modules ----
        if s.signaled_ready == 0 {
            s.signaled_ready = 1;
            return 3; // StepOutcome::Ready
        }

        let now = dev_millis(sys) as u32;

        // ---- Read BOOTSEL via flash sideband ----

        let mut arg = [READ_CS];
        let level = (sys.dev_call)(-1, FLASH_SIDEBAND, arg.as_mut_ptr(), 1);

        if level < 0 {
            s.error_count = s.error_count.wrapping_add(1);
            if s.error_count == 1 || s.error_count % 5000 == 0 {
                let mut lb = [0u8; 32];
                let bp = lb.as_mut_ptr();
                let mut p = 0usize;
                let tag = b"[flash] err=";
                let mut t = 0usize;
                while t < tag.len() {
                    *bp.add(p) = *tag.as_ptr().add(t);
                    p += 1; t += 1;
                }
                if level < 0 {
                    *bp.add(p) = b'-'; p += 1;
                    p += fmt_u32_raw(bp.add(p), (0i32.wrapping_sub(level)) as u32);
                } else {
                    p += fmt_u32_raw(bp.add(p), level as u32);
                }
                let tag2 = b" cnt=";
                t = 0;
                while t < tag2.len() {
                    *bp.add(p) = *tag2.as_ptr().add(t);
                    p += 1; t += 1;
                }
                p += fmt_u32_raw(bp.add(p), s.error_count);
                dev_log(sys, 1, bp, p);
            }
            return 0;
        }

        let raw_state = if level != 0 { 1u8 } else { 0u8 };

        // ---- Direct mode: emit on/off immediately, no debounce ----

        if s.mode == 1 {
            if raw_state != s.current_state {
                s.current_state = raw_state;
                if raw_state == 1 {
                    emit_msg(s, sys, MSG_ON, core::ptr::null(), 0);
                } else {
                    emit_msg(s, sys, MSG_OFF, core::ptr::null(), 0);
                }
            }
            return 0;
        }

        // ---- Debounce (gesture mode only) ----

        if raw_state != s.last_raw {
            s.last_raw = raw_state;
            s.state_change_time = now;
        } else if raw_state != s.current_state {
            let elapsed = now.wrapping_sub(s.state_change_time);
            if elapsed >= s.debounce_ms as u32 {
                s.current_state = raw_state;
                s.state_processed = 0;
            }
        }

        // ---- Feed debounced transitions into output (gesture mode) ----

        if s.state_processed == 0 {
            s.state_processed = 1;

            // Gesture mode: click counting + long press detection
            if s.current_state == 1 {
                // Press
                s.press_time = now;
                s.long_press_emitted = 0;
                match s.gesture {
                    GestureState::Idle => {
                        s.click_count = 0;
                        s.gesture = GestureState::Pressed;
                    }
                    GestureState::WaitingForClick => {
                        s.gesture = GestureState::Pressed;
                    }
                    GestureState::Pressed => {} // spurious
                }
            } else {
                // Release
                if s.gesture == GestureState::Pressed {
                    if s.long_press_emitted != 0 {
                        // Long press already fired while held — suppress click
                        s.gesture = GestureState::Idle;
                        s.click_count = 0;
                    } else {
                        let duration = now.wrapping_sub(s.press_time);
                        if duration >= s.long_press_ms as u32 {
                            emit_msg(s, sys, s.map_long_press, core::ptr::null(), 0);
                            s.gesture = GestureState::Idle;
                            s.click_count = 0;
                        } else {
                            s.click_count += 1;
                            s.release_time = now;
                            s.gesture = GestureState::WaitingForClick;
                        }
                    }
                }
            }
        }

        // ---- Check long press while held ----

        if s.gesture == GestureState::Pressed && s.long_press_emitted == 0 {
            let duration = now.wrapping_sub(s.press_time);
            if duration >= s.long_press_ms as u32 {
                emit_msg(s, sys, s.map_long_press, core::ptr::null(), 0);
                s.long_press_emitted = 1;
            }
        }

        // ---- Check multi-click timeout ----

        if s.gesture == GestureState::WaitingForClick {
            let elapsed = now.wrapping_sub(s.release_time);
            if elapsed >= s.multi_click_ms as u32 {
                let msg = match s.click_count {
                    2 => s.map_double,
                    3 => s.map_triple,
                    _ => s.map_click,
                };
                emit_msg(s, sys, msg, core::ptr::null(), 0);
                s.gesture = GestureState::Idle;
                s.click_count = 0;
            }
        }

        // ---- Blob serving on out[1] ----

        if s.stream_chan >= 0 {
            match s.stream_phase {
                StreamPhase::Idle => {
                    // Poll for seek request from downstream (bank)
                    let mut seek_pos: u32 = 0;
                    let seek_ptr = &mut seek_pos as *mut u32 as *mut u8;
                    let res = dev_channel_ioctl(sys, s.stream_chan, IOCTL_GET_SEEK, seek_ptr);
                    if res == 0 && (seek_pos as u8) < s.blob_count {
                        s.current_blob = seek_pos as u8;
                        s.blob_write_pos = 0;
                        s.stream_phase = StreamPhase::Streaming;
                        return 2; // Burst — start writing immediately
                    }
                }
                StreamPhase::Streaming => {
                    // Check if output channel is ready for writing
                    let poll = (sys.channel_poll)(s.stream_chan, POLL_OUT);
                    if poll <= 0 || ((poll as u8) & POLL_OUT) == 0 {
                        return 0; // Backpressure — try next tick
                    }

                    let idx = s.current_blob as usize;
                    let blob_off = *s.blob_offsets.as_ptr().add(idx) as usize;
                    let blob_len = *s.blob_lengths.as_ptr().add(idx) as usize;
                    let pos = s.blob_write_pos as usize;

                    if pos >= blob_len {
                        // Done — send EOF and return to idle
                        dev_channel_ioctl(sys, s.stream_chan, IOCTL_EOF, core::ptr::null_mut());
                        s.stream_phase = StreamPhase::Idle;
                        return 0;
                    }

                    // Write a chunk
                    let remaining = blob_len - pos;
                    let chunk = if remaining < BLOB_CHUNK_SIZE { remaining } else { BLOB_CHUNK_SIZE };
                    let src = s.blob_storage.as_ptr().add(blob_off + pos);
                    let written = (sys.channel_write)(s.stream_chan, src, chunk);
                    if written > 0 {
                        s.blob_write_pos += written as u16;
                    }

                    // Check if we finished
                    if s.blob_write_pos as usize >= blob_len {
                        dev_channel_ioctl(sys, s.stream_chan, IOCTL_EOF, core::ptr::null_mut());
                        s.stream_phase = StreamPhase::Idle;
                        return 0;
                    }

                    return 2; // Burst — keep writing
                }
            }
        }

        0
    }
}

/// Emit an FMP message on the output channel.
unsafe fn emit_msg(s: &FlashState, sys: &SyscallTable, msg_type: u32, payload: *const u8, payload_len: u16) {
    let poll = (sys.channel_poll)(s.out_chan, POLL_OUT);
    if poll > 0 && ((poll as u8) & POLL_OUT) != 0 {
        msg_write(sys, s.out_chan, msg_type, payload, payload_len);
    }
}

// ============================================================================
// Flash Store Provider Dispatch
// ============================================================================

/// Provider dispatch function — called by kernel when modules use
/// PARAM_STORE/DELETE/CLEAR_ALL syscalls. The kernel prepends the caller's
/// module_id to the arg buffer before forwarding here.
#[no_mangle]
#[link_section = ".text.flash_store_dispatch"]
pub unsafe extern "C" fn flash_store_dispatch(
    state: *mut u8,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    if state.is_null() {
        return -22; // EINVAL
    }
    let s = &mut *(state as *mut FlashState);
    if s.syscalls.is_null() {
        return -22;
    }
    let sys = &*s.syscalls;

    match opcode {
        PARAM_STORE_OP => {
            // arg = [module_id:u8, tag:u8, value_bytes...]
            if arg.is_null() || arg_len < 2 { return -22; }
            let module_id = *arg;
            let tag = *arg.add(1);
            let value_len = arg_len - 2;
            if value_len > MAX_VALUE_LEN { return -22; }
            store_param(s, sys, module_id, tag, arg.add(2), value_len)
        }
        PARAM_DELETE_OP => {
            // arg = [module_id:u8, tag:u8]
            if arg.is_null() || arg_len < 2 { return -22; }
            delete_param(s, sys, *arg, *arg.add(1))
        }
        PARAM_CLEAR_ALL_OP => {
            // arg = [module_id:u8] or [0xFF] for factory reset
            if arg.is_null() || arg_len < 1 { return -22; }
            if *arg == 0xFF {
                erase_store(s, sys)
            } else {
                clear_all(s, sys, *arg)
            }
        }
        _ => -38, // ENOSYS
    }
}

// ============================================================================
// Flash Store Domain Logic (PIC-safe: pointer arithmetic only)
// ============================================================================

/// Store a parameter override for the given module.
unsafe fn store_param(
    s: &mut FlashState, sys: &SyscallTable,
    module_id: u8, tag: u8, value: *const u8, value_len: usize,
) -> i32 {
    let entry_size = ENTRY_HEADER_SIZE + value_len;

    // If sector is virgin (never written), initialize it
    if s.free_offset == 0 {
        if write_header_and_entry(s, sys, module_id, tag, 0, value, value_len) < 0 {
            return -12; // ENOMEM
        }
        s.free_offset = (HEADER_SIZE + entry_size) as u16;
        return 0;
    }

    // Check if there's room
    if (s.free_offset as usize) + entry_size > SECTOR_SIZE {
        if compact(s, sys) < 0 {
            return -12;
        }
        if (s.free_offset as usize) + entry_size > SECTOR_SIZE {
            return -12; // still no room
        }
    }

    // Append entry
    if append_entry(s, sys, module_id, tag, 0, value, value_len) < 0 {
        return -1; // ERROR
    }
    s.free_offset += entry_size as u16;
    0
}

/// Append a tombstone for a specific tag.
unsafe fn delete_param(
    s: &mut FlashState, sys: &SyscallTable,
    module_id: u8, tag: u8,
) -> i32 {
    let entry_size = ENTRY_HEADER_SIZE;
    if s.free_offset == 0 {
        return 0; // nothing to delete in virgin sector
    }
    if (s.free_offset as usize) + entry_size > SECTOR_SIZE {
        if compact(s, sys) < 0 {
            return -12;
        }
    }
    if append_entry(s, sys, module_id, tag, FLAG_TOMBSTONE, core::ptr::null(), 0) < 0 {
        return -1;
    }
    s.free_offset += entry_size as u16;
    0
}

/// Append a clear-all marker for a module.
unsafe fn clear_all(
    s: &mut FlashState, sys: &SyscallTable,
    module_id: u8,
) -> i32 {
    let entry_size = ENTRY_HEADER_SIZE;
    if s.free_offset == 0 {
        return 0;
    }
    if (s.free_offset as usize) + entry_size > SECTOR_SIZE {
        if compact(s, sys) < 0 {
            return -12;
        }
    }
    if append_entry(s, sys, module_id, 0, FLAG_CLEAR_ALL, core::ptr::null(), 0) < 0 {
        return -1;
    }
    s.free_offset += entry_size as u16;
    0
}

/// Erase the entire runtime store (factory reset).
unsafe fn erase_store(s: &mut FlashState, sys: &SyscallTable) -> i32 {
    let result = raw_flash_erase(sys, STORE_OFFSET);
    if result < 0 {
        return result;
    }
    s.free_offset = 0;
    0
}

// ============================================================================
// Entry write helpers
// ============================================================================

/// Write sector header + first entry to a virgin sector.
unsafe fn write_header_and_entry(
    s: &mut FlashState, sys: &SyscallTable,
    module_id: u8, tag: u8, flags: u8, value: *const u8, value_len: usize,
) -> i32 {
    let total = HEADER_SIZE + ENTRY_HEADER_SIZE + value_len;
    if total > SECTOR_SIZE {
        return -12;
    }

    // Build in page buffer (on stack)
    let mut page_buf = [0xFFu8; PAGE_SIZE];
    let pb = page_buf.as_mut_ptr();

    // Header
    let magic_bytes = STORE_MAGIC.to_le_bytes();
    *pb = magic_bytes[0];
    *pb.add(1) = magic_bytes[1];
    *pb.add(2) = magic_bytes[2];
    *pb.add(3) = magic_bytes[3];
    *pb.add(4) = STORE_VERSION;
    *pb.add(5) = 0;
    *pb.add(6) = 1; // entry_count = 1
    *pb.add(7) = 0;

    // Entry
    *pb.add(HEADER_SIZE) = module_id;
    *pb.add(HEADER_SIZE + 1) = tag;
    *pb.add(HEADER_SIZE + 2) = flags;
    *pb.add(HEADER_SIZE + 3) = value_len as u8;

    let mut i = 0usize;
    while i < value_len && HEADER_SIZE + ENTRY_HEADER_SIZE + i < PAGE_SIZE {
        *pb.add(HEADER_SIZE + ENTRY_HEADER_SIZE + i) = *value.add(i);
        i += 1;
    }

    // Erase first (sector may have garbage)
    let r = raw_flash_erase(sys, STORE_OFFSET);
    if r < 0 { return r; }

    // Program first page
    let r = raw_flash_program(sys, STORE_OFFSET, pb);
    if r < 0 { return r; }

    // If entry spans into second page
    if total > PAGE_SIZE {
        let mut page2 = [0xFFu8; PAGE_SIZE];
        let p2 = page2.as_mut_ptr();
        let remaining_start = PAGE_SIZE - (HEADER_SIZE + ENTRY_HEADER_SIZE);
        let mut j = 0usize;
        while remaining_start + j < value_len {
            *p2.add(j) = *value.add(remaining_start + j);
            j += 1;
        }
        let r = raw_flash_program(sys, STORE_OFFSET + PAGE_SIZE as u32, p2);
        if r < 0 { return r; }
    }

    0
}

/// Append an entry at free_offset.
unsafe fn append_entry(
    s: &mut FlashState, sys: &SyscallTable,
    module_id: u8, tag: u8, flags: u8, value: *const u8, value_len: usize,
) -> i32 {
    let start = s.free_offset as usize;
    let entry_size = ENTRY_HEADER_SIZE + value_len;

    if start + entry_size > SECTOR_SIZE {
        return -12;
    }

    // Determine which page(s) this entry spans
    // Use bit masking instead of division: page_start = start & !(PAGE_SIZE - 1)
    let page_mask = !(PAGE_SIZE - 1);
    let page_start = start & page_mask;
    let page_end_entry = (start + entry_size - 1) & page_mask;

    let mut page_buf = [0xFFu8; PAGE_SIZE];
    let pb = page_buf.as_mut_ptr();
    let entry_offset_in_page = start - page_start;

    // Write entry header
    *pb.add(entry_offset_in_page) = module_id;
    *pb.add(entry_offset_in_page + 1) = tag;
    *pb.add(entry_offset_in_page + 2) = flags;
    *pb.add(entry_offset_in_page + 3) = value_len as u8;

    // Write value (may partially fit in this page)
    let space_in_page = PAGE_SIZE - (entry_offset_in_page + ENTRY_HEADER_SIZE);
    let first_chunk = if value_len < space_in_page { value_len } else { space_in_page };
    let mut i = 0usize;
    while i < first_chunk {
        *pb.add(entry_offset_in_page + ENTRY_HEADER_SIZE + i) = *value.add(i);
        i += 1;
    }

    let r = raw_flash_program(sys, STORE_OFFSET + page_start as u32, pb);
    if r < 0 { return r; }

    // If entry spans to next page
    if page_end_entry > page_start {
        let mut page2 = [0xFFu8; PAGE_SIZE];
        let p2 = page2.as_mut_ptr();
        let remaining = value_len - first_chunk;
        let mut j = 0usize;
        while j < remaining {
            *p2.add(j) = *value.add(first_chunk + j);
            j += 1;
        }
        let r = raw_flash_program(sys, STORE_OFFSET + page_end_entry as u32, p2);
        if r < 0 { return r; }
    }

    0
}

// ============================================================================
// Compaction
// ============================================================================

/// Compact the sector: scan active entries, copy values to compact_arena,
/// erase sector, rewrite entries page-by-page.
unsafe fn compact(s: &mut FlashState, sys: &SyscallTable) -> i32 {
    let sector = STORE_XIP as *const u8;
    let magic = read_u32_xip(sector);
    if magic != STORE_MAGIC {
        s.free_offset = 0;
        return 0;
    }

    // Reset compaction scratch
    s.compact_arena_off = 0;
    s.compact_count = 0;

    let mut off = HEADER_SIZE;

    while off + ENTRY_HEADER_SIZE <= SECTOR_SIZE {
        let mid = *sector.add(off);
        if mid == 0xFF { break; }
        let tag = *sector.add(off + 1);
        let flags = *sector.add(off + 2);
        let vlen = *sector.add(off + 3) as usize;

        if off + ENTRY_HEADER_SIZE + vlen > SECTOR_SIZE { break; }

        if flags & FLAG_CLEAR_ALL != 0 {
            // Remove all entries for this module
            let mut i = 0u8;
            while (i as usize) < (s.compact_count as usize) {
                let ep = s.compact_entries.as_ptr().add(i as usize);
                if (*ep).module_id == mid {
                    let last = (s.compact_count - 1) as usize;
                    let ep_mut = s.compact_entries.as_mut_ptr().add(i as usize);
                    if (i as usize) < last {
                        *ep_mut = *s.compact_entries.as_ptr().add(last);
                    }
                    s.compact_count -= 1;
                } else {
                    i += 1;
                }
            }
        } else if flags & FLAG_TOMBSTONE != 0 {
            // Remove specific tag
            let mut i = 0u8;
            while (i as usize) < (s.compact_count as usize) {
                let ep = s.compact_entries.as_ptr().add(i as usize);
                if (*ep).module_id == mid && (*ep).tag == tag {
                    let last = (s.compact_count - 1) as usize;
                    let ep_mut = s.compact_entries.as_mut_ptr().add(i as usize);
                    if (i as usize) < last {
                        *ep_mut = *s.compact_entries.as_ptr().add(last);
                    }
                    s.compact_count -= 1;
                    break;
                }
                i += 1;
            }
        } else {
            // Copy value from XIP into compact_arena
            let arena_off = s.compact_arena_off as usize;
            if arena_off + vlen > COMPACT_ARENA_SIZE { break; }

            let src = sector.add(off + ENTRY_HEADER_SIZE);
            let dst = s.compact_arena.as_mut_ptr().add(arena_off);
            let mut k = 0usize;
            while k < vlen {
                *dst.add(k) = *src.add(k);
                k += 1;
            }
            s.compact_arena_off = (arena_off + vlen) as u16;

            // Upsert into compact_entries
            let mut found = false;
            let mut i = 0u8;
            while (i as usize) < (s.compact_count as usize) {
                let ep = s.compact_entries.as_mut_ptr().add(i as usize);
                if (*ep).module_id == mid && (*ep).tag == tag {
                    (*ep).arena_off = arena_off as u16;
                    (*ep).value_len = vlen as u8;
                    found = true;
                    break;
                }
                i += 1;
            }
            if !found && (s.compact_count as usize) < MAX_COMPACT_ENTRIES {
                let ep = s.compact_entries.as_mut_ptr().add(s.compact_count as usize);
                (*ep).module_id = mid;
                (*ep).tag = tag;
                (*ep).arena_off = arena_off as u16;
                (*ep).value_len = vlen as u8;
                s.compact_count += 1;
            }
        }

        off += ENTRY_HEADER_SIZE + vlen;
    }

    // Erase sector
    let r = raw_flash_erase(sys, STORE_OFFSET);
    if r < 0 { return r; }

    let count = s.compact_count as usize;

    // Build and write pages
    let mut page_buf = [0xFFu8; PAGE_SIZE];
    let pb = page_buf.as_mut_ptr();
    let mut entry_idx = 0usize;

    // Write header
    let magic_bytes = STORE_MAGIC.to_le_bytes();
    *pb = magic_bytes[0];
    *pb.add(1) = magic_bytes[1];
    *pb.add(2) = magic_bytes[2];
    *pb.add(3) = magic_bytes[3];
    *pb.add(4) = STORE_VERSION;
    *pb.add(5) = 0;
    let count_bytes = (count as u16).to_le_bytes();
    *pb.add(6) = count_bytes[0];
    *pb.add(7) = count_bytes[1];
    let mut write_off = HEADER_SIZE;

    // Write entries into page buffer, flushing pages as they fill
    while entry_idx < count {
        let ep = s.compact_entries.as_ptr().add(entry_idx);
        let mid = (*ep).module_id;
        let tag = (*ep).tag;
        let arena_off = (*ep).arena_off as usize;
        let vlen = (*ep).value_len as usize;
        let entry_size = ENTRY_HEADER_SIZE + vlen;

        if write_off + entry_size > SECTOR_SIZE { break; }

        // Write entry byte-by-byte into page buffer
        let hdr = [mid, tag, 0u8, vlen as u8];
        let mut byte_idx = 0usize;
        while byte_idx < entry_size {
            // pos_in_page = write_off & (PAGE_SIZE - 1)
            let pos_in_page = write_off & (PAGE_SIZE - 1);

            if byte_idx < ENTRY_HEADER_SIZE {
                *pb.add(pos_in_page) = *hdr.as_ptr().add(byte_idx);
            } else {
                let val_idx = byte_idx - ENTRY_HEADER_SIZE;
                *pb.add(pos_in_page) = *s.compact_arena.as_ptr().add(arena_off + val_idx);
            }

            write_off += 1;
            byte_idx += 1;

            // Flush page if full
            if (write_off & (PAGE_SIZE - 1)) == 0 {
                let page_off = write_off - PAGE_SIZE;
                let r = raw_flash_program(sys, STORE_OFFSET + page_off as u32, pb);
                if r < 0 { return r; }
                // Reset page buffer
                let mut k = 0usize;
                while k < PAGE_SIZE {
                    *pb.add(k) = 0xFF;
                    k += 1;
                }
            }
        }

        entry_idx += 1;
    }

    // Flush final partial page
    if (write_off & (PAGE_SIZE - 1)) != 0 {
        let page_start = write_off & !(PAGE_SIZE - 1);
        let r = raw_flash_program(sys, STORE_OFFSET + page_start as u32, pb);
        if r < 0 { return r; }
    }

    s.free_offset = write_off as u16;
    0
}

// ============================================================================
// Flash bridge wrappers
// ============================================================================

/// Call kernel to erase runtime store sector.
unsafe fn raw_flash_erase(sys: &SyscallTable, offset: u32) -> i32 {
    let mut buf = offset.to_le_bytes();
    (sys.dev_call)(-1, FLASH_RAW_ERASE, buf.as_mut_ptr(), 4)
}

/// Call kernel to program a 256-byte page.
unsafe fn raw_flash_program(sys: &SyscallTable, offset: u32, page: *const u8) -> i32 {
    // Build [offset:4, data:256] on stack
    let mut buf = [0u8; 260];
    let bp = buf.as_mut_ptr();
    let ob = offset.to_le_bytes();
    *bp = ob[0];
    *bp.add(1) = ob[1];
    *bp.add(2) = ob[2];
    *bp.add(3) = ob[3];
    // Copy 256 bytes of page data
    let mut i = 0usize;
    while i < PAGE_SIZE {
        *bp.add(4 + i) = *page.add(i);
        i += 1;
    }
    (sys.dev_call)(-1, FLASH_RAW_PROGRAM, bp, 260)
}

/// Initialize free_offset by scanning XIP sector.
unsafe fn init_free_offset(s: &mut FlashState) {
    let sector = STORE_XIP as *const u8;
    let magic = read_u32_xip(sector);
    if magic != STORE_MAGIC {
        s.free_offset = if magic == 0xFFFF_FFFF { 0 } else { 0 };
        return;
    }
    let mut off = HEADER_SIZE;
    while off + ENTRY_HEADER_SIZE <= SECTOR_SIZE {
        let mid = *sector.add(off);
        if mid == 0xFF { break; }
        let vlen = *sector.add(off + 3) as usize;
        if off + ENTRY_HEADER_SIZE + vlen > SECTOR_SIZE { break; }
        off += ENTRY_HEADER_SIZE + vlen;
    }
    s.free_offset = off as u16;
}

/// Read u32 from XIP (unaligned, little-endian).
unsafe fn read_u32_xip(ptr: *const u8) -> u32 {
    let b0 = *ptr as u32;
    let b1 = (*ptr.add(1) as u32) << 8;
    let b2 = (*ptr.add(2) as u32) << 16;
    let b3 = (*ptr.add(3) as u32) << 24;
    b0 | b1 | b2 | b3
}

// ============================================================================
// Channel Hints
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_channel_hints"]
pub extern "C" fn module_channel_hints(out: *mut u8, max_len: usize) -> i32 {
    let hints = [
        ChannelHint { port_type: 1, port_index: 0, buffer_size: 256 },  // out[0]: FMP messages
        ChannelHint { port_type: 1, port_index: 1, buffer_size: 2048 }, // out[1]: blob stream
    ];
    unsafe { write_channel_hints(out, max_len, &hints) }
}

// ============================================================================
// Panic Handler
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
