//! Microphone Source PIC Module (I2S RX via PIO)
//!
//! Captures audio from an I2S MEMS microphone (INMP441 or similar) using
//! PIO RX stream with continuous DMA. Outputs raw i16 stereo PCM to channel.
//!
//! **Params (TLV v2):**
//!   tag 1: in_pin (u8, default 22) — GPIO for microphone data
//!   tag 2: clock_base (u8, default 18) — GPIO for BCLK (LRCLK = clock_base+1)
//!   tag 3: sample_rate (u32, default 16000) — sample rate in Hz
//!
//! Output: raw u32 words from PIO (I2S stereo frames, 4 bytes each)

#![no_std]

use core::ffi::c_void;

#[path = "../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../pic_runtime.rs");
include!("../param_macro.rs");

mod pio;

// ============================================================================
// dev_pio RX opcodes (mirrors abi::dev_pio)
// ============================================================================

const DEV_PIO_RX_STREAM_ALLOC: u32 = 0x0420;
const DEV_PIO_RX_STREAM_LOAD_PROGRAM: u32 = 0x0421;
const DEV_PIO_RX_STREAM_CONFIGURE: u32 = 0x0422;
const DEV_PIO_RX_STREAM_CAN_PULL: u32 = 0x0423;
const DEV_PIO_RX_STREAM_PULL: u32 = 0x0424;
const DEV_PIO_RX_STREAM_FREE: u32 = 0x0425;
const DEV_PIO_RX_STREAM_GET_BUFFER: u32 = 0x0426;
const DEV_PIO_RX_STREAM_SET_RATE: u32 = 0x0427;

// ============================================================================
// dev_call argument structs
// ============================================================================

#[repr(C)]
struct PioLoadProgramArgs {
    program: *const u16,
    program_len: u32,
    wrap_target: u8,
    wrap: u8,
    sideset_bits: u8,
    options: u8,
}

#[repr(C)]
struct PioRxConfigureArgs {
    clock_div: u32,
    in_pin: u8,
    sideset_base: u8,
    shift_bits: u8,
    _pad: u8,
}

// ============================================================================
// State
// ============================================================================

/// Microphone capture phases.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum MicPhase {
    Init = 0,
    Running = 1,
    Error = 2,
}

/// Output buffer size in bytes (matches RX_BUFFER_WORDS * 4)
const OUT_BUF_SIZE: usize = pio::RX_BUFFER_WORDS * 4;

#[repr(C)]
struct MicState {
    syscalls: *const SyscallTable,
    out_chan: i32,
    rx_handle: i32,
    phase: MicPhase,
    in_pin: u8,
    clock_base: u8,
    _pad: u8,
    sample_rate: u32,
    pending_out: u16,
    pending_offset: u16,
    io_buf: [u8; OUT_BUF_SIZE],
}

impl MicState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.out_chan = -1;
        self.rx_handle = -1;
        self.phase = MicPhase::Init;
        self.in_pin = 22;
        self.clock_base = 18;
        self._pad = 0;
        self.sample_rate = 16000;
        self.pending_out = 0;
        self.pending_offset = 0;
    }
}

// ============================================================================
// Parameters
// ============================================================================

mod params_def {
    use super::MicState;
    use super::{p_u8, p_u32};
    use super::SCHEMA_MAX;

    define_params! {
        MicState;

        1, in_pin, u8, 22
            => |s, d, len| {
                let v = p_u8(d, len, 0, 22);
                s.in_pin = if v == 0 { 22 } else { v };
            };

        2, clock_base, u8, 18
            => |s, d, len| {
                let v = p_u8(d, len, 0, 18);
                s.clock_base = if v == 0 { 18 } else { v };
            };

        3, sample_rate, u32, 16000
            => |s, d, len| {
                let v = p_u32(d, len, 0, 16000);
                s.sample_rate = if v == 0 { 16000 } else { v };
            };
    }
}

// ============================================================================
// PIC Module Interface
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<MicState>() as u32
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
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() || state_size < core::mem::size_of::<MicState>() {
            return -5;
        }

        let s = &mut *(state as *mut MicState);
        s.init(syscalls as *const SyscallTable);
        s.out_chan = out_chan;

        // Parse params
        let is_tlv_v2 = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x02;

        if is_tlv_v2 {
            params_def::parse_tlv_v2(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        let sys = &*s.syscalls;
        dev_log(sys, 3, b"[mic] ready".as_ptr(), 11);

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
        let s = &mut *(state as *mut MicState);
        if s.syscalls.is_null() {
            return -1;
        }

        match s.phase {
            MicPhase::Init => {
                let r = step_init(s);
                if r < 0 { return r; }
                step_running(s)
            }
            MicPhase::Running => step_running(s),
            MicPhase::Error => -1,
            _ => -1,
        }
    }
}

// ============================================================================
// Init: allocate PIO RX stream, load program, configure
// ============================================================================

unsafe fn step_init(s: &mut MicState) -> i32 {
    let sys = &*s.syscalls;
    let dev_call = sys.dev_call;

    // Allocate PIO RX stream
    let handle = (dev_call)(-1, DEV_PIO_RX_STREAM_ALLOC, core::ptr::null_mut(), 0);
    if handle < 0 {
        dev_log(sys, 1, b"[mic] alloc fail".as_ptr(), 16);
        s.phase = MicPhase::Error;
        return -1;
    }

    // Load RX PIO program
    let load_args = PioLoadProgramArgs {
        program: pio::RX_PROGRAM.as_ptr(),
        program_len: pio::RX_PROGRAM.len() as u32,
        wrap_target: pio::WRAP_TARGET,
        wrap: pio::WRAP,
        sideset_bits: pio::SIDESET_BITS,
        options: pio::OPTIONS,
    };
    let result = (dev_call)(
        handle,
        DEV_PIO_RX_STREAM_LOAD_PROGRAM,
        &load_args as *const _ as *mut u8,
        core::mem::size_of::<PioLoadProgramArgs>(),
    );
    if result < 0 {
        dev_log(sys, 1, b"[mic] load fail".as_ptr(), 15);
        (dev_call)(handle, DEV_PIO_RX_STREAM_FREE, core::ptr::null_mut(), 0);
        s.phase = MicPhase::Error;
        return -1;
    }

    // Configure RX stream (pins, clock divider, shift width)
    let clock_div = pio::calc_clock_div_88(pio::SYS_FREQ_HZ, s.sample_rate);
    let cfg_args = PioRxConfigureArgs {
        clock_div,
        in_pin: s.in_pin,
        sideset_base: s.clock_base,
        shift_bits: pio::SHIFT_BITS,
        _pad: 0,
    };
    let result = (dev_call)(
        handle,
        DEV_PIO_RX_STREAM_CONFIGURE,
        &cfg_args as *const _ as *mut u8,
        core::mem::size_of::<PioRxConfigureArgs>(),
    );
    if result < 0 {
        dev_log(sys, 1, b"[mic] cfg fail".as_ptr(), 14);
        (dev_call)(handle, DEV_PIO_RX_STREAM_FREE, core::ptr::null_mut(), 0);
        s.phase = MicPhase::Error;
        return -1;
    }

    // Set stream rate (Q16.16)
    let rate_q16 = s.sample_rate << 16;
    let mut rate_arg = rate_q16.to_le_bytes();
    (dev_call)(handle, DEV_PIO_RX_STREAM_SET_RATE, rate_arg.as_mut_ptr(), 4);

    s.rx_handle = handle;
    s.phase = MicPhase::Running;

    dev_log(sys, 3, b"[mic] running".as_ptr(), 13);
    0
}

// ============================================================================
// Running: pull captured audio and write to output channel
// ============================================================================

unsafe fn step_running(s: &mut MicState) -> i32 {
    let sys = &*s.syscalls;
    let dev_call = sys.dev_call;
    let out_chan = s.out_chan;
    let rx_handle = s.rx_handle;

    // Drain any pending output from previous step
    if !drain_pending(sys, out_chan, s.io_buf.as_ptr(), &mut s.pending_out, &mut s.pending_offset) {
        return 0;
    }

    // Check output channel ready
    let out_poll = (sys.channel_poll)(out_chan, POLL_OUT);
    if out_poll <= 0 || ((out_poll as u8) & POLL_OUT) == 0 {
        return 0;
    }

    // Check if RX buffer is ready
    let can_pull = (dev_call)(rx_handle, DEV_PIO_RX_STREAM_CAN_PULL, core::ptr::null_mut(), 0);
    if can_pull <= 0 {
        return 0;
    }

    // Get buffer pointer
    let mut buf_ptr: u32 = 0;
    let words = (dev_call)(
        rx_handle,
        DEV_PIO_RX_STREAM_GET_BUFFER,
        &mut buf_ptr as *mut u32 as *mut u8,
        4,
    );
    if buf_ptr == 0 || words <= 0 {
        return 0;
    }

    let byte_count = (words as usize) * 4;
    let copy_len = if byte_count > OUT_BUF_SIZE { OUT_BUF_SIZE } else { byte_count };

    // Copy from RX buffer to io_buf
    __aeabi_memcpy(
        s.io_buf.as_mut_ptr(),
        buf_ptr as *const u8,
        copy_len,
    );

    // Acknowledge the pull (release buffer for DMA reuse)
    (dev_call)(rx_handle, DEV_PIO_RX_STREAM_PULL, core::ptr::null_mut(), 0);

    // Write to output channel
    let written = (sys.channel_write)(out_chan, s.io_buf.as_ptr(), copy_len);
    if written < 0 && written != E_AGAIN {
        return -1;
    }

    track_pending(written, copy_len, &mut s.pending_out, &mut s.pending_offset);

    0
}

// ============================================================================
// Channel Hints
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_channel_hints"]
pub extern "C" fn module_channel_hints(out: *mut u8, max_len: usize) -> i32 {
    let hints = [
        ChannelHint { port_type: 1, port_index: 0, buffer_size: OUT_BUF_SIZE as u16 },
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
