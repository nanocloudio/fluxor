//! Temperature Sensor PIC Module
//!
//! Periodically reads the RP2350 onboard temperature sensor (ADC channel 4),
//! converts the raw 12-bit value to millidegrees Celsius, and writes 4 bytes
//! (i32 LE) to the output channel.
//!
//! **Params:**
//! - `interval_ms`: Read interval in milliseconds (default 5000)
//!
//! **Output:** 4 bytes i32 LE — temperature in millidegrees Celsius
//!   e.g., 27000 = 27.000 C

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

/// ADC channel for RP2350 onboard temperature sensor
const TEMP_CHANNEL: u8 = 4;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct TempState {
    syscalls: *const SyscallTable,
    out_chan: i32,
    adc_handle: i32,
    timer_fd: i32,
    interval_ms: u32,
    reading: bool,
    initialized: bool,
}

// ============================================================================
// Parameters
// ============================================================================

mod params_def {
    use super::TempState;
    use super::p_u32;
    use super::SCHEMA_MAX;

    define_params! {
        TempState;

        1, interval_ms, u32, 5000
            => |s, d, len| { s.interval_ms = p_u32(d, len, 0, 5000); };
    }
}

// ============================================================================
// Temperature conversion (integer-only, no floats)
// ============================================================================

/// Convert 12-bit ADC raw value to millidegrees Celsius.
///
/// RP2350 temp sensor: T = 27 - (V - 0.706) / 0.001721
/// V = raw * 3300 / 4096 (millivolts)
/// T_milli = 27000 - (V_mV - 706) * 1000 / 1721
fn raw_to_milli_celsius(raw: u16) -> i32 {
    let v_mv = (raw as i32 * 3300) / 4096;
    27000 - ((v_mv - 706) * 1000) / 1721
}

// ============================================================================
// Module API
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<TempState>() as u32
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
        if state_size < core::mem::size_of::<TempState>() {
            return -2;
        }

        let s = &mut *(state as *mut TempState);
        s.syscalls = syscalls as *const SyscallTable;
        s.out_chan = out_chan;
        s.adc_handle = -1;
        s.timer_fd = -1;
        s.reading = false;
        s.initialized = false;

        // Parse params
        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;

        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
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
        let s = &mut *(state as *mut TempState);
        if s.syscalls.is_null() {
            return -1;
        }

        let sys = &*s.syscalls;

        // Lazy init: open ADC handle + create timer on first step
        if !s.initialized {
            // Open ADC channel 4 (temp sensor)
            let mut ch = [TEMP_CHANNEL];
            let handle = (sys.dev_call)(-1, 0x0E00, ch.as_mut_ptr(), 1);
            if handle < 0 {
                return -3;
            }
            s.adc_handle = handle;

            // Create timer fd
            let timer_fd = (sys.dev_call)(-1, 0x0604, core::ptr::null_mut(), 0);
            if timer_fd < 0 {
                return -4;
            }
            s.timer_fd = timer_fd;

            // Arm timer for first read
            let mut delay = s.interval_ms.to_le_bytes();
            (sys.dev_call)(s.timer_fd, 0x0605, delay.as_mut_ptr(), 4);

            s.initialized = true;
            return 0;
        }

        // Not currently reading: wait for timer to expire
        if !s.reading {
            let poll = dev_fd_poll(sys, s.timer_fd, POLL_IN);
            if poll <= 0 || ((poll as u32) & POLL_IN) == 0 {
                return 0;
            }
            // Timer expired — start ADC read
            (sys.dev_call)(s.adc_handle, 0x0E02, core::ptr::null_mut(), 0);
            s.reading = true;
            return 0;
        }

        // ADC read in progress — poll for result
        let result = (sys.dev_call)(s.adc_handle, 0x0E02, core::ptr::null_mut(), 0);
        if result <= 0 {
            return 0; // still pending
        }

        // Got raw ADC value — convert to millidegrees Celsius
        let temp_mc = raw_to_milli_celsius(result as u16);

        // Write 4 bytes (i32 LE) to output channel
        let poll = (sys.channel_poll)(s.out_chan, POLL_OUT);
        if poll > 0 && ((poll as u32) & POLL_OUT) != 0 {
            let bytes = temp_mc.to_le_bytes();
            (sys.channel_write)(s.out_chan, bytes.as_ptr(), 4);
        }

        // Re-arm timer for next read
        let mut delay = s.interval_ms.to_le_bytes();
        (sys.dev_call)(s.timer_fd, 0x0605, delay.as_mut_ptr(), 4);
        s.reading = false;

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
        ChannelHint { port_type: 1, port_index: 0, buffer_size: 64 }, // out[0]: temp readings (4 bytes each)
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
