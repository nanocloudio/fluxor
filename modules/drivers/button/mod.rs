//! Button PIC Module — GPIO button driver.
//!
//! Reads a GPIO pin, debounces, and emits the canonical
//! `input::button` raw transition contract on the output port:
//! one byte per debounced edge (0x01=pressed, 0x00=released).
//! Same wire shape `flash_rp.raw` (BOOTSEL) and
//! `wasm_browser_button.raw` produce — every platform's button
//! driver speaks the same contract.
//!
//! Downstream `gesture` module handles click counting, long press
//! detection, and FMP command mapping.
//!
//! **For BOOTSEL on rp boards** use the dedicated `flash_rp`
//! driver instead — it reads the QSPI sideband, not GPIO.
//!
//! **Params (from config):**
//! - `pin`: GPIO pin number (required — must be a real pin in
//!   the board's valid GPIO range)
//! - `control_id`: button identity (default 0)
//! - `active_low`: 0=active high, 1=active low (default 1)
//! - `pull`: 0=none, 1=pull-up (default), 2=pull-down
//!
//! **Output:** single byte 0x01 (pressed) or 0x00 (released) on debounced transition

#![no_std]
#![allow(
    unreachable_patterns,
    reason = "defensive `_ => Error` arms in enum state-machine matches. The match is \
              exhaustive, which is why the lint fires; the arm exists so that adding a \
              variant cannot silently bypass the error path. #[expect] is not the \
              alternative — it fails the build in the configurations where the lint \
              does not fire"
)]

use core::ffi::c_void;

use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

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
    use super::p_u8;
    use super::ButtonState;

    fluxor_rt::define_params! {
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

fluxor_rt::module_facts! { state: ButtonState }

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[no_mangle]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
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
        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;

        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else if !params.is_null() && params_len >= 4 {
            // Flat byte layout: [pin, control_id, active_low, pull]
            s.pin = *params.add(0);
            s.control_id = *params.add(1);
            s.active_low = *params.add(2);
            s.pull = *params.add(3);
        } else {
            params_def::set_defaults(s);
        }

        // Open a GPIO input handle via provider_open. The returned
        // handle is the pin number; the kernel tracks it against the
        // HAL_GPIO contract so GET_LEVEL / RELEASE dispatch routes by
        // handle rather than opcode class byte.
        let sys = &*s.syscalls;
        let mut gpio_arg = [s.pin, s.pull];
        let handle = (sys.provider_open)(GPIO_CONTRACT, GPIO_SET_INPUT, gpio_arg.as_mut_ptr(), 2);
        if handle < 0 {
            return -4;
        }
        s.gpio_handle = handle;

        0
    }
}

// Contract id + opcodes mirror `abi::kernel::module::provider::contract::HAL_GPIO`
// and `abi::contracts::hal::gpio::*`. Pinned here to keep the PIC
// module self-contained (no imports into kernel paths).
const GPIO_CONTRACT: u32 = abi::registry::gpio::ID as u32;
const GPIO_SET_INPUT: u32 = abi::registry::gpio::SET_INPUT;
const GPIO_GET_LEVEL: u32 = abi::registry::gpio::GET_LEVEL;

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> StepReturn {
    unsafe {
        if state.is_null() {
            return StepReturn::error(-1);
        }
        let s = &mut *(state as *mut ButtonState);
        if s.syscalls.is_null() {
            return StepReturn::error(-1);
        }

        let sys = &*s.syscalls;
        let now = dev_millis(sys) as u32;

        // ---- Read GPIO + debounce ----

        let level = (sys.provider_call)(
            s.gpio_handle,
            GPIO_GET_LEVEL,
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
            0,
        );
        if level < 0 {
            return StepReturn::Continue; // GPIO error, skip
        }

        let pressed = if s.active_low != 0 {
            level == 0
        } else {
            level != 0
        };
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
            if poll > 0 && ((poll as u32) & POLL_OUT) != 0 {
                (sys.channel_write)(s.out_chan, byte.as_ptr(), 1);
            }
        }

        StepReturn::Continue
    }
}

// ============================================================================
// Panic Handler
// ============================================================================

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `crates/fluxor-rt/src/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
fluxor_rt::wasm_entry!();
