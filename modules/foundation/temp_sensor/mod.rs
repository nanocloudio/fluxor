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
#![allow(
    dead_code,
    reason = "the PIC build mounts the whole of modules/sdk/* via include!, so every \
              module's compile sees the entire ABI surface while using a subset. This \
              allow is the SDK's textual mounting showing through"
)]
#![allow(
    unused_imports,
    reason = "same cause: the mounted SDK brings names this module does not reach for"
)]
#![allow(
    unreachable_patterns,
    reason = "defensive `_ => Error` arms in enum state-machine matches. The match is \
              exhaustive, which is why the lint fires; the arm exists so that adding a \
              variant cannot silently bypass the error path. #[expect] is not the \
              alternative — it fails the build in the configurations where the lint \
              does not fire"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

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
    /// Which sensor this is, stamped on every reading. A graph may place several
    /// of these against different ADC channels, and a consumer folding them into
    /// keyed lanes needs to tell them apart without inferring it from the edge.
    sensor_id: u16,
    /// Monotonic per-sensor sequence. A consumer detects a gap — a reading the
    /// ring dropped — by the step, which a timestamp cannot distinguish from a
    /// sensor that simply read late.
    seq: u32,
    reading: bool,
    initialized: bool,
}

// ============================================================================
// Parameters
// ============================================================================

mod params_def {
    use super::p_u32;
    use super::TempState;
    use super::SCHEMA_MAX;

    define_params! {
        TempState;

        1, interval_ms, u32, 5000
            => |s, d, len| { s.interval_ms = p_u32(d, len, 0, 5000); };
        2, sensor_id, u32, 0
            => |s, d, len| { s.sensor_id = p_u32(d, len, 0, 0) as u16; };
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

// Same figure as data, so `pack` records it and a sensor graph's arena demand is
// summable at compose time.
declare_module_state_bytes!(TempState);

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
        s.sensor_id = 0;
        s.seq = 0;

        // Parse params
        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;

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

        // Lazy init: open ADC handle + create timer on first step.
        // Both go through the handle-scoped provider API so the
        // kernel tracks the returned handles against their contracts.
        if !s.initialized {
            // Open ADC channel 4 (temp sensor)
            let mut ch = [TEMP_CHANNEL];
            let handle = (sys.provider_open)(HAL_ADC_CONTRACT, ADC_OPEN, ch.as_mut_ptr(), 1);
            if handle < 0 {
                return -3;
            }
            s.adc_handle = handle;

            // Create timer fd
            let timer_fd =
                (sys.provider_open)(TIMER_CONTRACT, TIMER_CREATE, core::ptr::null_mut(), 0);
            if timer_fd < 0 {
                return -4;
            }
            s.timer_fd = timer_fd;

            // Arm timer for first read
            let mut delay = s.interval_ms.to_le_bytes();
            (sys.provider_call)(s.timer_fd, TIMER_SET, delay.as_mut_ptr(), 4);

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
            (sys.provider_call)(s.adc_handle, ADC_READ, core::ptr::null_mut(), 0);
            s.reading = true;
            return 0;
        }

        // ADC read in progress — poll for result
        let result = (sys.provider_call)(s.adc_handle, ADC_READ, core::ptr::null_mut(), 0);
        if result <= 0 {
            return 0; // still pending
        }

        // Got raw ADC value — convert to millidegrees Celsius
        let temp_mc = raw_to_milli_celsius(result as u16);

        // Emit one `SensorSample`: a TYPED measurement rather than anonymous
        // bytes a consumer has to be told the meaning of.
        //
        // What the quantity IS travels as the `quantity = temperature`
        // capability fact, which the composer checks when it binds this port;
        // what the reading is scaled BY travels in the record, so millidegrees
        // is `value` in units of `10^-3`. Between them a consumer needs no
        // out-of-band knowledge of this driver, which is the coupling the graph
        // model exists to remove.
        let poll = (sys.channel_poll)(s.out_chan, POLL_OUT);
        if poll > 0 && ((poll as u32) & POLL_OUT) != 0 {
            let mut rec = [0u8; abi::contracts::sensor::SAMPLE_SIZE];
            // Monotonic device time: the reading's own time, which is what an
            // event-time window folds on. Not the delivery time.
            let t_micros = dev_micros(sys);
            if abi::contracts::sensor::encode(
                &mut rec,
                s.sensor_id,
                0,
                -3,
                s.seq,
                t_micros,
                temp_mc as i64,
            )
            .is_some()
            {
                (sys.channel_write)(s.out_chan, rec.as_ptr(), rec.len());
                s.seq = s.seq.wrapping_add(1);
            }
        }

        // Re-arm timer for next read
        let mut delay = s.interval_ms.to_le_bytes();
        (sys.provider_call)(s.timer_fd, TIMER_SET, delay.as_mut_ptr(), 4);
        s.reading = false;

        0
    }
}

// Contract ids + opcodes (mirror kernel::module::provider::contract + abi paths).
const HAL_ADC_CONTRACT: u32 = 0x000E;
const TIMER_CONTRACT: u32 = 0x0006;
const ADC_OPEN: u32 = 0x0E00;
const ADC_READ: u32 = 0x0E02;
const TIMER_CREATE: u32 = 0x0604;
const TIMER_SET: u32 = 0x0605;

// ============================================================================
// Panic Handler
// ============================================================================

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/runtime/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/runtime/wasm_entry.rs");
