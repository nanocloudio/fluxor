//! PWM Output PIC Module
//!
//! Reads brightness bytes (0-255) from the input channel and drives a hardware
//! PWM pin at the corresponding duty cycle.
//!
//! **Params:**
//! - `pin`: GPIO pin number for PWM output (default 25)
//!
//! **Input:** single brightness byte per message (0=off, 255=full on)

#![no_std]

use core::ffi::c_void;

#[path = "../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../pic_runtime.rs");
include!("../param_macro.rs");

mod params_def;

// ============================================================================
// PWM dev_call opcodes (from abi::dev_pwm)
// ============================================================================

const PWM_OPEN: u32 = 0x0F00;
const PWM_SET_DUTY: u32 = 0x0F03;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct PwmOutState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    pwm_handle: i32,
    pin: u8,
    initialized: bool,
    last_brightness: u8,
}

// ============================================================================
// Module API
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<PwmOutState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    _out_chan: i32,
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
        if state_size < core::mem::size_of::<PwmOutState>() {
            return -2;
        }

        let s = &mut *(state as *mut PwmOutState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.pwm_handle = -1;
        s.initialized = false;
        s.last_brightness = 0;

        // Parse params (sets s.pin)
        let is_tlv_v2 = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x02;

        if is_tlv_v2 {
            params_def::parse_tlv_v2(s, params, params_len);
        } else {
            params_def::set_defaults(s);
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
        let s = &mut *(state as *mut PwmOutState);
        if s.syscalls.is_null() {
            return -1;
        }

        let sys = &*s.syscalls;

        // Lazy init: open PWM handle on first step
        if !s.initialized {
            let mut pin_arg = [s.pin];
            let handle = (sys.dev_call)(-1, PWM_OPEN, pin_arg.as_mut_ptr(), 1);
            if handle < 0 {
                return -3; // PWM open failed
            }
            s.pwm_handle = handle;
            s.initialized = true;
            return 0;
        }

        // Poll input channel for brightness data
        let poll = (sys.channel_poll)(s.in_chan, POLL_IN);
        if poll <= 0 || ((poll as u8) & POLL_IN) == 0 {
            return 0;
        }

        // Read brightness byte(s) — take the latest
        let mut buf = [0u8; 32];
        let n = (sys.channel_read)(s.in_chan, buf.as_mut_ptr(), buf.len());
        if n <= 0 {
            return 0;
        }

        // Use last byte as brightness (pointer arithmetic, no bounds check)
        let brightness = *buf.as_ptr().add((n as usize) - 1);

        // Skip if unchanged
        if brightness == s.last_brightness {
            return 0;
        }
        s.last_brightness = brightness;

        // Map 0-255 to 0-65534 (DEFAULT_TOP)
        // duty = brightness * 257 (maps 255 → 65535 ≈ 65534)
        // More precisely: duty = (brightness * 65534 + 127) / 255
        let duty: u16 = if brightness == 255 {
            0xFFFE // match DEFAULT_TOP exactly for 100% duty
        } else if brightness == 0 {
            0
        } else {
            ((brightness as u32 * 0xFFFE + 127) / 255) as u16
        };

        let mut duty_bytes = duty.to_le_bytes();
        (sys.dev_call)(s.pwm_handle, PWM_SET_DUTY, duty_bytes.as_mut_ptr(), 2);

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
        ChannelHint { port_type: 0, port_index: 0, buffer_size: 64 }, // in[0]: brightness bytes
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
