//! Button PIC Module
//!
//! GPIO button input with debouncing. Reads a GPIO pin, debounces the signal,
//! and emits raw state bytes (0x01=pressed, 0x00=released) on state change.
//!
//! Downstream `gesture` module handles click counting, long press detection,
//! and command mapping.
//!
//! **Params (from config):**
//! - `pin`: GPIO pin number (0xFF = board user button, default)
//! - `control_id`: button identity (default 0)
//! - `active_low`: 0=active high, 1=active low (default 1)
//! - `pull`: 0=none, 1=pull-up (default), 2=pull-down
//!
//! **Output:** single byte 0x01 (pressed) or 0x00 (released) on debounced transition

#![no_std]

use core::ffi::c_void;

#[path = "../../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../pic_runtime.rs");
include!("../../param_macro.rs");

// ============================================================================
// Constants
// ============================================================================

/// Debounce time in milliseconds
const DEBOUNCE_MS: u32 = 30;

// ============================================================================
// State Structure
// ============================================================================

#[repr(C)]
struct ButtonState {
    syscalls: *const SyscallTable,
    out_chan: i32,
    gpio_handle: i32,
    // --- Config params ---
    pin: u8,
    control_id: u8,
    active_low: u8,
    pull: u8,
    // --- Debounce state ---
    current_state: u8,
    last_raw: u8,
    state_processed: u8,
    _pad: u8,
    state_change_time: u32,
}

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::ButtonState;
    use super::p_u8;
    use super::SCHEMA_MAX;

    define_params! {
        ButtonState;

        1, pin, u8, 0xFF
            => |s, d, len| { s.pin = p_u8(d, len, 0, 0xFF); };

        2, control_id, u8, 0
            => |s, d, len| { s.control_id = p_u8(d, len, 0, 0); };

        3, active_low, u8, 1
            => |s, d, len| { s.active_low = p_u8(d, len, 0, 1); };

        4, pull, u8, 1, enum { none=0, up=1, down=2 }
            => |s, d, len| { s.pull = p_u8(d, len, 0, 1); };
    }
}

// ============================================================================
// Module API
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ButtonState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

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
        if state_size < core::mem::size_of::<ButtonState>() {
            return -2;
        }

        let s = &mut *(state as *mut ButtonState);
        s.syscalls = syscalls as *const SyscallTable;
        s.out_chan = out_chan;

        // Initialize runtime state
        s.current_state = 0;
        s.last_raw = 0;
        s.state_change_time = 0;
        s.state_processed = 1;

        // Parse params
        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;

        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else if !params.is_null() && params_len >= 4 {
            // Legacy: [pin, control_id, active_low, pull]
            s.pin = *params.add(0);
            s.control_id = *params.add(1);
            s.active_low = *params.add(2);
            s.pull = *params.add(3);
        } else {
            params_def::set_defaults(s);
        }

        // Request GPIO as input via dev_call
        let sys = &*s.syscalls;
        let mut gpio_arg = [s.pin, s.pull];
        let handle = (sys.dev_call)(-1, 0x0107, gpio_arg.as_mut_ptr(), 2);
        if handle < 0 {
            return -4;
        }
        s.gpio_handle = handle;

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
        let s = &mut *(state as *mut ButtonState);
        if s.syscalls.is_null() {
            return -1;
        }

        let sys = &*s.syscalls;
        let now = dev_millis(sys) as u32;

        // ---- Read GPIO + debounce ----

        let level = (sys.dev_call)(s.gpio_handle, 0x0105, core::ptr::null_mut(), 0);
        if level < 0 {
            return 0; // GPIO error, skip
        }

        let pressed = if s.active_low != 0 { level == 0 } else { level != 0 };
        let raw_state = if pressed { 1u8 } else { 0u8 };

        if raw_state != s.last_raw {
            s.last_raw = raw_state;
            s.state_change_time = now;
        } else if raw_state != s.current_state {
            let elapsed = now.wrapping_sub(s.state_change_time);
            if elapsed >= DEBOUNCE_MS {
                s.current_state = raw_state;
                s.state_processed = 0;
            }
        }

        // ---- Emit raw byte on debounced transition ----

        if s.state_processed == 0 {
            s.state_processed = 1;
            let byte = [s.current_state]; // 0x01=pressed, 0x00=released
            let poll = (sys.channel_poll)(s.out_chan, POLL_OUT);
            if poll > 0 && ((poll as u8) & POLL_OUT) != 0 {
                (sys.channel_write)(s.out_chan, byte.as_ptr(), 1);
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
        ChannelHint { port_type: 1, port_index: 0, buffer_size: 64 }, // out[0]: raw 0/1 bytes
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
