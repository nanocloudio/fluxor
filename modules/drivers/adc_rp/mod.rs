//! ADC Driver — PIC module provider
//!
//! Manages ADC access using kernel register bridge.
//! Registers as the HAL_ADC provider (contract id 0x0E).
//! Single-shot conversions via register polling.

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

const MAX_HANDLES: usize = 4;

// RP2350 ADC register offsets
const ADC_CS: u8 = 0x00;
const ADC_RESULT: u8 = 0x04;
const ADC_FCS: u8 = 0x08;

// CS bits
const CS_EN: u32 = 1 << 0;
const CS_START_ONCE: u32 = 1 << 2;
const CS_READY: u32 = 1 << 8;

#[repr(C)]
struct AdcHandle {
    in_use: u8,
    channel: u8, // ADC channel (0-4: GPIO26-29 + temp)
    owner: u8,
    _pad: u8,
}

#[repr(C)]
struct AdcTransfer {
    pending: u8,
    active: u8,
    _pad: [u8; 2],
    result: i32, // raw ADC value (12-bit) or error
}

#[repr(C)]
struct AdcState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    handles: [AdcHandle; MAX_HANDLES],
    transfers: [AdcTransfer; MAX_HANDLES],
    initialized: u8,
    next_handle: u8,
    _pad: [u8; 2],
    step_count: u32,
}

use abi::platform::rp::adc_raw::{REG_WRITE as ADC_REG_WRITE, REG_READ as ADC_REG_READ};

unsafe fn adc_reg_write(sys: &SyscallTable, offset: u8, val: u32) {
    let mut buf = [0u8; 5];
    let bp = buf.as_mut_ptr();
    *bp = offset;
    let v = val.to_le_bytes();
    *bp.add(1) = v[0]; *bp.add(2) = v[1]; *bp.add(3) = v[2]; *bp.add(4) = v[3];
    (sys.provider_call)(-1, ADC_REG_WRITE, bp, 5);
}

unsafe fn adc_reg_read(sys: &SyscallTable, offset: u8) -> u32 {
    let mut buf = [0u8; 5];
    let bp = buf.as_mut_ptr();
    *bp = offset;
    (sys.provider_call)(-1, ADC_REG_READ, bp, 5);
    u32::from_le_bytes([*bp.add(1), *bp.add(2), *bp.add(3), *bp.add(4)])
}

unsafe fn adc_init(sys: &SyscallTable) {
    // Enable ADC
    adc_reg_write(sys, ADC_CS, CS_EN);
    // Disable FIFO
    adc_reg_write(sys, ADC_FCS, 0);
}

const ADC_OPEN: u32 = 0x0E00;
const ADC_CLOSE: u32 = 0x0E01;
const ADC_READ: u32 = 0x0E02;
const ADC_POLL: u32 = 0x0E03;

#[unsafe(no_mangle)]
#[link_section = ".text.module_provider_dispatch"]
#[export_name = "module_provider_dispatch"]
pub unsafe extern "C" fn adc_dispatch(
    state: *mut u8, handle: i32, opcode: u32, arg: *mut u8, arg_len: usize,
) -> i32 {
    let s = &mut *(state as *mut AdcState);
    let sys = &*s.syscalls;

    match opcode {
        ADC_OPEN => {
            // arg=[channel:u8] (1 byte). Channel 0-3=GPIO26-29, 4=temp sensor.
            if arg.is_null() || arg_len < 1 { return -22; }
            let ch = *arg;
            if ch > 4 { return -22; }

            // Init ADC hardware on first open
            if s.initialized == 0 {
                adc_init(sys);
                s.initialized = 1;
            }

            // Init pin for GPIO channels
            if ch < 4 {
                let mut pin_buf = [26 + ch];
                (sys.provider_call)(-1, abi::platform::rp::adc_raw::PIN_INIT, pin_buf.as_mut_ptr(), 1);
            }

            let mut i = 0usize;
            while i < MAX_HANDLES {
                let idx = (s.next_handle as usize + i) % MAX_HANDLES;
                let hp = s.handles.as_mut_ptr().add(idx);
                if (*hp).in_use == 0 {
                    (*hp).in_use = 1;
                    (*hp).channel = ch;
                    s.next_handle = ((idx + 1) % MAX_HANDLES) as u8;
                    return idx as i32;
                }
                i += 1;
            }
            -16
        }
        ADC_CLOSE => {
            let idx = handle as usize;
            if idx >= MAX_HANDLES { return -22; }
            (*s.handles.as_mut_ptr().add(idx)).in_use = 0;
            0
        }
        ADC_READ => {
            // Start single-shot conversion
            let idx = handle as usize;
            if idx >= MAX_HANDLES { return -22; }
            let tp = s.transfers.as_mut_ptr().add(idx);
            if (*tp).active != 0 { return -16; }

            let ch = (*s.handles.as_ptr().add(idx)).channel;
            // Select channel and start conversion
            let cs = CS_EN | CS_START_ONCE | ((ch as u32) << 12);
            adc_reg_write(sys, ADC_CS, cs);
            (*tp).active = 1;
            (*tp).result = 0;
            0
        }
        ADC_POLL => {
            let idx = handle as usize;
            if idx >= MAX_HANDLES { return -22; }
            let tp = s.transfers.as_mut_ptr().add(idx);
            if (*tp).active == 0 { return (*tp).result; }

            // Check if conversion is done
            let cs = adc_reg_read(sys, ADC_CS);
            if (cs & CS_READY) != 0 {
                (*tp).result = adc_reg_read(sys, ADC_RESULT) as i32 & 0xFFF;
                (*tp).active = 0;
                (*tp).result
            } else {
                0 // still converting
            }
        }
        _ => -38,
    }
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> u32 { 1 }

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize { core::mem::size_of::<AdcState>() }

#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32, out_chan: i32, ctrl_chan: i32,
    _params: *const u8, _params_len: usize,
    state: *mut u8, state_size: usize, syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<AdcState>() { return -2; }
        let s = &mut *(state as *mut AdcState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan; s.out_chan = out_chan; s.ctrl_chan = ctrl_chan;

        let sys = &*s.syscalls;
        dev_log(sys, 3, b"[adc] ready".as_ptr(), 10);
        0
    }
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_provides_contract"]
pub extern "C" fn module_provides_contract() -> u32 {
    0x000E // HAL_ADC
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    // ADC conversions complete in ~2μs — polling in dispatch is sufficient.
    // No work needed in step.
    let _ = state;
    0
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/wasm_entry.rs");
