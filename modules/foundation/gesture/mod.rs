//! Gesture PIC Module
//!
//! Reads raw button state bytes (0x00=released, 0x01=pressed) and performs
//! click counting, long press detection, then emits FMP command messages.
//!
//! Sits between a raw input module (flash, button) and a consumer module
//! (bank, voip, etc.), enabling input-device-agnostic control.
//!
//! # Modes
//!
//! - **mode 0 (gesture):** Click counting + long press detection.
//!   Single click→toggle, double→next, triple→prev, long→long_press (configurable).
//! - **mode 1 (direct):** Immediate on/off — 0x01→MSG_ON, 0x00→MSG_OFF.
//!
//! # Configuration
//!
//! ```yaml
//! - name: gesture
//!   click: toggle           # single click → fnv1a("toggle")
//!   double_click: next      # double click → fnv1a("next")
//!   triple_click: prev      # triple click → fnv1a("prev")
//!   long_press: long_press  # long press   → fnv1a("long_press")
//!   multi_click_ms: 300     # click window (ms)
//!   long_press_ms: 500      # hold threshold (ms)
//!   mode: 0                 # 0=gesture, 1=direct
//! ```

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

const DEFAULT_CLICK: u32 = fnv1a(b"toggle");
const DEFAULT_DOUBLE: u32 = fnv1a(b"next");
const DEFAULT_TRIPLE: u32 = fnv1a(b"prev");
const DEFAULT_LONG_PRESS: u32 = fnv1a(b"long_press");

// Multi-click window: how long after a release a subsequent press
// still counts as part of the same click chain. 300ms was too tight
// for natural double-/triple-taps in a browser — most users land
// the second tap in the 350-450ms window. 500ms is the de-facto
// UX default (Android, iOS, most desktop file managers).
const DEFAULT_MULTI_CLICK_MS: u16 = 500;
// 500 ms was too tight: a normal browser-pointer click is 100-200 ms,
// but a user pausing mid-tap chain (or a slightly heavier click) can
// land at 500-700 ms and trigger long_press, which then suppresses
// the subsequent release as a click (release sees long_press_emitted
// and resets state). 1000 ms matches iOS/Android long-press defaults
// and leaves clean headroom for natural taps.
const DEFAULT_LONG_PRESS_MS: u16 = 1000;

// ============================================================================
// State
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum DetectState {
    Idle = 0,
    Pressed = 1,
    WaitingForClick = 2,
}

#[repr(C)]
struct GestureState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,

    // Timing config
    multi_click_ms: u16,
    long_press_ms: u16,

    // Detection state
    detect: DetectState,
    click_count: u8,
    long_press_emitted: u8,
    mode: u8, // 0=gesture, 1=direct

    press_time: u32,
    release_time: u32,

    // Output mappings
    map_click: u32,
    map_double: u32,
    map_triple: u32,
    map_long_press: u32,

    // Diagnostics — heartbeat counters surfaced every 5000 ticks
    tick_count: u32,
    total_bytes_seen: u32,
    total_emits: u16,
    _pad: [u8; 2],
}

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::GestureState;
    use super::{p_u8, p_u16, p_u32};
    use super::{DEFAULT_CLICK, DEFAULT_DOUBLE, DEFAULT_TRIPLE, DEFAULT_LONG_PRESS};
    use super::{DEFAULT_MULTI_CLICK_MS, DEFAULT_LONG_PRESS_MS};
    use super::SCHEMA_MAX;

    define_params! {
        GestureState;

        // The macro's `$default` literal seeds `set_defaults()`'s
        // pre-packed buffer. `p_u*` only falls through to the lambda's
        // own default arg when the buffer is *short* — so the literal
        // here MUST be the real default, not 0, or set_defaults will
        // stamp the field with 0 and the emit path will short-circuit
        // on `msg_type == 0`.
        1, click, u32, DEFAULT_CLICK
            => |s, d, len| { s.map_click = p_u32(d, len, 0, DEFAULT_CLICK); };

        2, double_click, u32, DEFAULT_DOUBLE
            => |s, d, len| { s.map_double = p_u32(d, len, 0, DEFAULT_DOUBLE); };

        3, triple_click, u32, DEFAULT_TRIPLE
            => |s, d, len| { s.map_triple = p_u32(d, len, 0, DEFAULT_TRIPLE); };

        4, long_press, u32, DEFAULT_LONG_PRESS
            => |s, d, len| { s.map_long_press = p_u32(d, len, 0, DEFAULT_LONG_PRESS); };

        5, multi_click_ms, u16, DEFAULT_MULTI_CLICK_MS
            => |s, d, len| { s.multi_click_ms = p_u16(d, len, 0, DEFAULT_MULTI_CLICK_MS); };

        6, long_press_ms, u16, DEFAULT_LONG_PRESS_MS
            => |s, d, len| { s.long_press_ms = p_u16(d, len, 0, DEFAULT_LONG_PRESS_MS); };

        7, mode, u8, 0, enum { gesture=0, direct=1 }
            => |s, d, len| { s.mode = p_u8(d, len, 0, 0); };
    }
}

// ============================================================================
// Helpers
// ============================================================================

unsafe fn emit_mapped(sys: &SyscallTable, out_chan: i32, msg_type: u32) {
    if msg_type != 0 && out_chan >= 0 {
        let poll = (sys.channel_poll)(out_chan, POLL_OUT);
        if poll > 0 && ((poll as u32) & POLL_OUT) != 0 {
            msg_write_empty(sys, out_chan, msg_type);
        }
    }
}

// ============================================================================
// Module API
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<GestureState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
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
        if state_size < core::mem::size_of::<GestureState>() {
            return -2;
        }

        let s = &mut *(state as *mut GestureState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;

        // Defaults
        s.multi_click_ms = DEFAULT_MULTI_CLICK_MS;
        s.long_press_ms = DEFAULT_LONG_PRESS_MS;
        s.map_click = DEFAULT_CLICK;
        s.map_double = DEFAULT_DOUBLE;
        s.map_triple = DEFAULT_TRIPLE;
        s.map_long_press = DEFAULT_LONG_PRESS;

        // Parse params
        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;

        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        // Log mode for diagnostics
        if s.mode == 1 {
            dev_log(&*s.syscalls, 0, b"[gesture] direct mode".as_ptr(), 21);
        } else {
            dev_log(&*s.syscalls, 0, b"[gesture] click mode".as_ptr(), 20);
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
        let s = &mut *(state as *mut GestureState);
        if s.syscalls.is_null() || s.in_chan < 0 || s.out_chan < 0 {
            return 0;
        }

        let sys = &*s.syscalls;
        let now = dev_millis(sys) as u32;

        // Periodic heartbeat — surface in/out chans + counters so we
        // can tell whether bytes are reaching gesture at all.
        s.tick_count = s.tick_count.wrapping_add(1);
        if s.tick_count % 5000 == 0 {
            let mut buf = [0u8; 96];
            let p = buf.as_mut_ptr();
            let pfx = b"[gesture] hb in=";
            let mut q = 0usize;
            let mut t = 0;
            while t < pfx.len() { *p.add(q) = pfx[t]; q += 1; t += 1; }
            q += fmt_u32_raw(p.add(q), s.in_chan as u32);
            let oc = b" out=";
            let mut t = 0;
            while t < oc.len() { *p.add(q) = oc[t]; q += 1; t += 1; }
            q += fmt_u32_raw(p.add(q), s.out_chan as u32);
            let by = b" bytes_in=";
            let mut t = 0;
            while t < by.len() { *p.add(q) = by[t]; q += 1; t += 1; }
            q += fmt_u32_raw(p.add(q), s.total_bytes_seen);
            let em = b" emits=";
            let mut t = 0;
            while t < em.len() { *p.add(q) = em[t]; q += 1; t += 1; }
            q += fmt_u32_raw(p.add(q), s.total_emits as u32);
            let dt = b" detect=";
            let mut t = 0;
            while t < dt.len() { *p.add(q) = dt[t]; q += 1; t += 1; }
            q += fmt_u32_raw(p.add(q), s.detect as u32);
            let cc = b" cc=";
            let mut t = 0;
            while t < cc.len() { *p.add(q) = cc[t]; q += 1; t += 1; }
            q += fmt_u32_raw(p.add(q), s.click_count as u32);
            dev_log(sys, 3, p, q);
        }

        // Read raw byte transitions from input
        let poll = (sys.channel_poll)(s.in_chan, POLL_IN);
        if poll > 0 && (poll as u32 & POLL_IN) != 0 {
            let mut byte = [0u8; 1];
            let n = (sys.channel_read)(s.in_chan, byte.as_mut_ptr(), 1);
            if n == 1 {
                s.total_bytes_seen = s.total_bytes_seen.saturating_add(1);
                let pressed = byte[0] != 0;

                // Direct mode: immediate on/off
                if s.mode == 1 {
                    if pressed {
                        emit_mapped(sys, s.out_chan, MSG_ON);
                    } else {
                        emit_mapped(sys, s.out_chan, MSG_OFF);
                    }
                    return 0;
                }

                // Gesture mode: track transitions
                if pressed {
                    s.press_time = now;
                    s.long_press_emitted = 0;
                    if s.detect == DetectState::Idle || s.detect == DetectState::WaitingForClick {
                        s.detect = DetectState::Pressed;
                    }
                } else if s.detect == DetectState::Pressed {
                    if s.long_press_emitted != 0 {
                        // Long press already fired — suppress click
                        s.detect = DetectState::Idle;
                        s.click_count = 0;
                    } else {
                        s.click_count = s.click_count.wrapping_add(1);
                        s.release_time = now;
                        s.detect = DetectState::WaitingForClick;
                    }
                }
            }
        }

        // Skip timing checks in direct mode
        if s.mode == 1 {
            return 0;
        }

        // Long press detection while held
        if s.detect == DetectState::Pressed && s.long_press_emitted == 0 {
            let duration = now.wrapping_sub(s.press_time);
            if duration >= s.long_press_ms as u32 {
                emit_mapped(sys, s.out_chan, s.map_long_press);
                s.long_press_emitted = 1;
            }
        }

        // Multi-click timeout — emit mapped command
        if s.detect == DetectState::WaitingForClick {
            let elapsed = now.wrapping_sub(s.release_time);
            if elapsed >= s.multi_click_ms as u32 {
                let out_type = match s.click_count {
                    2 => s.map_double,
                    3 => s.map_triple,
                    _ => s.map_click,
                };
                emit_mapped(sys, s.out_chan, out_type);
                s.total_emits = s.total_emits.saturating_add(1);
                s.detect = DetectState::Idle;
                s.click_count = 0;
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
        ChannelHint { port_type: 0, port_index: 0, buffer_size: 64 },  // in[0]: raw 0/1 bytes
        ChannelHint { port_type: 1, port_index: 0, buffer_size: 256 }, // out[0]: FMP commands
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
