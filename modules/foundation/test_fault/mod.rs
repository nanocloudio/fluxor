//! Fault-injection test module
//!
//! A diagnostic PIC module that deliberately triggers faults for testing
//! the step guard timer and fault recovery infrastructure.
//!
//! **Params:**
//!   mode (u8, tag 1): fault type to trigger
//!     0 = infinite loop (triggers step guard timeout)
//!     1 = return error code after N steps
//!     2 = busy-wait for configurable microseconds
//!     3 = normal operation (no fault, for baseline testing)
//!   delay_steps (u16, tag 2): steps before triggering fault (default 10)
//!   busy_us (u16, tag 3): microseconds to busy-wait in mode 2 (default 5000)
//!
//! **Pipeline:** standalone (no input/output channels needed)

#![no_std]

use core::ffi::c_void;

#[path = "../../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../pic_runtime.rs");
include!("../../param_macro.rs");

// ============================================================================
// Module State
// ============================================================================

#[repr(C)]
struct TestFaultState {
    syscalls: *const SyscallTable,
    /// Fault mode (0=infinite_loop, 1=error, 2=busy_wait, 3=normal)
    mode: u8,
    /// Steps remaining before triggering fault
    delay_steps: u16,
    /// Microseconds to busy-wait in mode 2
    busy_us: u16,
    /// Step counter
    step_count: u32,
    /// Whether fault has been triggered
    faulted: u8,
}

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::TestFaultState;
    use super::p_u8;
    use super::p_u16;
    use super::SCHEMA_MAX;

    define_params! {
        TestFaultState;

        1, mode, u8, 0, enum { infinite_loop=0, error=1, busy_wait=2, normal=3 }
            => |s, d, len| { s.mode = p_u8(d, len, 0, 0); };

        2, delay_steps, u16, 10
            => |s, d, len| { s.delay_steps = p_u16(d, len, 0, 10); };

        3, busy_us, u16, 5000
            => |s, d, len| { s.busy_us = p_u16(d, len, 0, 5000); };
    }
}

// ============================================================================
// Exported functions
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<TestFaultState>() as u32
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
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() || state_size < core::mem::size_of::<TestFaultState>() {
            return -3;
        }

        let s = &mut *(state as *mut TestFaultState);
        s.syscalls = syscalls as *const SyscallTable;
        s.step_count = 0;
        s.faulted = 0;

        // Parse params
        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;

        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        dev_log(
            &*s.syscalls,
            3, // INFO
            b"[test_fault] init\0".as_ptr(),
            17,
        );

        0 // Ready
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        let s = &mut *(state as *mut TestFaultState);
        s.step_count += 1;

        // Pre-fault normal operation
        if s.step_count < s.delay_steps as u32 {
            return 0; // Continue
        }

        match s.mode {
            0 => {
                // Mode 0: Infinite loop — step guard timer should catch this
                loop {
                    core::hint::spin_loop();
                }
            }
            1 => {
                // Mode 1: Return error code
                if s.faulted == 0 {
                    s.faulted = 1;
                    return -1; // Error
                }
                // After restart, will error again when step_count >= delay_steps
                0
            }
            2 => {
                // Mode 2: Busy-wait (advisory timeout test)
                let iterations = (s.busy_us as u32).saturating_mul(38);
                let mut i = 0u32;
                while i < iterations {
                    core::hint::spin_loop();
                    i += 1;
                }
                0 // Continue (but may have exceeded deadline)
            }
            _ => {
                // Mode 3+: Normal operation
                0
            }
        }
    }
}
