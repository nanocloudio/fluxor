//! I2S PIC Module
//!
//! Outputs 16-bit stereo audio to I2S via PIO with double-buffered DMA.
//! PIO operations use the generic dev_call/dev_query interface.
//!
//! # Configuration
//!
//! Via I2sParams:
//! - data_pin: GPIO pin for serial data output
//! - clock_base: GPIO pin for BCLK (LRCLK is clock_base + 1)
//! - sample_rate: Output sample rate in Hz (default: 44100)
//!
//! # Mailbox contract
//!
//! When the input channel is a mailbox (buffer_group alias), the producer must
//! fill exactly `PIO_BUFFER_WORDS * 4` bytes (currently 512 × 4 = 2048) per
//! release — one complete DMA buffer of frame-aligned stereo i16 data. A size
//! mismatch is a fatal contract violation (I2sPhase::Error, no recovery).
//!
//! If `PIO_BUFFER_WORDS` changes, either update the producer's buffer size to
//! match or use the FIFO (channel_read) path, which handles partial frames.
//! The default channel hint (2048 bytes = `abi::CHANNEL_BUFFER_SIZE`) already
//! matches 512 words × 4, so the two stay in sync as long as both reference
//! the same constant.
//!
//! # PIC Safety
//!
//! - No panicking operations
//! - All syscalls through function pointer table
//! - No 64-bit division

#![no_std]

use core::ffi::c_void;

#[path = "../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../pic_runtime.rs");
include!("../param_macro.rs");

mod pio;
mod params_def;

// ============================================================================
// dev_pio opcodes (mirrors abi::dev_pio)
// ============================================================================

const DEV_PIO_STREAM_ALLOC: u32 = 0x0400;
const DEV_PIO_STREAM_LOAD_PROGRAM: u32 = 0x0401;
const DEV_PIO_STREAM_GET_BUFFER: u32 = 0x0402;
const DEV_PIO_STREAM_CONFIGURE: u32 = 0x0403;
const DEV_PIO_STREAM_CAN_PUSH: u32 = 0x0404;
const DEV_PIO_STREAM_PUSH: u32 = 0x0405;
const DEV_PIO_STREAM_FREE: u32 = 0x0406;
const DEV_PIO_STREAM_SET_RATE: u32 = 0x040B;

// ============================================================================
// dev_call argument structs (mirrors abi::PioLoadProgramArgs, PioConfigureArgs)
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
struct PioConfigureArgs {
    clock_div: u32,
    data_pin: u8,
    clock_base: u8,
    shift_bits: u8,
    _pad: u8,
}

// ============================================================================
// Constants
// ============================================================================

/// Input buffer size (bytes) — matches CHANNEL_BUFFER_SIZE from abi.rs
const IN_BUF_SIZE: usize = abi::CHANNEL_BUFFER_SIZE;

// ============================================================================
// Module Parameters
// ============================================================================

/// Parameters for I2S module (from YAML config).
/// Layout:
///   [0]     data_pin: u8
///   [1]     clock_base: u8
///   [2-3]   padding
///   [4-7]   sample_rate: u32
#[repr(C)]
struct I2sParams {
    data_pin: u8,
    clock_base: u8,
    _pad: [u8; 2],
    sample_rate: u32,
}

// ============================================================================
// State
// ============================================================================

/// I2S output phases.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum I2sPhase {
    Init = 0,
    Running = 1,
    Error = 2,
}

#[repr(C)]
struct I2sState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    stream_handle: i32,
    data_pin: u8,
    clock_base: u8,
    phase: I2sPhase,
    /// How many bytes in partial_buf (0-3)
    partial_len: u8,
    sample_rate: u32,
    /// Buffer for partial stereo pair from previous read
    partial_buf: [u8; 4],
    /// Diagnostic: count of audio buffers vs silence buffers
    audio_count: u16,
    silence_count: u16,
    /// Last packed I2S sample (L/R u32) for hold-padding
    last_sample: u32,
    /// Input buffer (i16 stereo pairs = 4 bytes per sample)
    in_buf: [u8; IN_BUF_SIZE],
}

impl I2sState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.in_chan = -1;
        self.stream_handle = -1;
        self.data_pin = 28;
        self.clock_base = 26;
        self.phase = I2sPhase::Init;
        self.partial_len = 0;
        self.sample_rate = 44100;
        self.partial_buf = [0; 4];
        self.audio_count = 0;
        self.silence_count = 0;
        self.last_sample = 0;
    }

    #[inline(always)]
    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }
}

// ============================================================================
// PIC Module Interface
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<I2sState>() as u32
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
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() {
            return -5;
        }
        if state_size < core::mem::size_of::<I2sState>() {
            return -6;
        }

        let s = &mut *(state as *mut I2sState);
        s.init(syscalls as *const SyscallTable);
        s.in_chan = in_chan;

        let is_tlv_v2 = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x02;

        if is_tlv_v2 {
            params_def::parse_tlv_v2(s, params, params_len);
        } else if !params.is_null() && params_len >= core::mem::size_of::<I2sParams>() {
            let p = &*(params as *const I2sParams);
            s.data_pin = if p.data_pin == 0 { 28 } else { p.data_pin };
            s.clock_base = if p.clock_base == 0 { 26 } else { p.clock_base };
            s.sample_rate = if p.sample_rate == 0 { 44100 } else { p.sample_rate };
        }

        let sys = s.sys();
        dev_log(sys, 3, b"[i2s] ready".as_ptr(), 11);

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
        let s = &mut *(state as *mut I2sState);
        if s.syscalls.is_null() {
            return -1;
        }

        match s.phase {
            I2sPhase::Init => {
                let r = step_init(s);
                if r < 0 { return r; }
                // Fall through to consume any data already waiting so
                // upstream buffers aren't stuck in READY for a tick.
                step_running(s)
            }
            I2sPhase::Running => step_running(s),
            I2sPhase::Error => -1,
            _ => -1,
        }
    }
}

/// Initialize PIO stream via dev_call
unsafe fn step_init(s: &mut I2sState) -> i32 {
    let sys = &*s.syscalls;
    let dev_call = sys.dev_call;
    let dev_query = sys.dev_query;
    let sample_rate = s.sample_rate;
    let data_pin = s.data_pin;
    let clock_base = s.clock_base;

    // Allocate PIO stream
    let mut alloc_arg = (pio::PIO_BUFFER_WORDS as u32).to_le_bytes();
    let handle = (dev_call)(0, DEV_PIO_STREAM_ALLOC, alloc_arg.as_mut_ptr(), 4);
    if handle < 0 {
        dev_log(sys, 1, b"[i2s] alloc fail".as_ptr(), 16);
        s.phase = I2sPhase::Error;
        return -1;
    }

    // Load PIO program
    let load_args = PioLoadProgramArgs {
        program: pio::PROGRAM.as_ptr(),
        program_len: pio::PROGRAM.len() as u32,
        wrap_target: pio::WRAP_TARGET,
        wrap: pio::WRAP,
        sideset_bits: pio::SIDESET_BITS,
        options: pio::OPTIONS,
    };
    let result = (dev_call)(
        handle,
        DEV_PIO_STREAM_LOAD_PROGRAM,
        &load_args as *const _ as *mut u8,
        core::mem::size_of::<PioLoadProgramArgs>(),
    );
    if result < 0 {
        dev_log(sys, 1, b"[i2s] load fail".as_ptr(), 15);
        (dev_call)(handle, DEV_PIO_STREAM_FREE, core::ptr::null_mut(), 0);
        s.phase = I2sPhase::Error;
        return -1;
    }

    // Configure stream (pins, clock divider, shift width)
    let sys_freq = dev_sys_clock_hz(sys);
    let clock_div = pio::calc_clock_div_88(sys_freq, sample_rate);
    let cfg_args = PioConfigureArgs {
        clock_div,
        data_pin,
        clock_base,
        shift_bits: pio::SHIFT_BITS,
        _pad: 0,
    };
    let result = (dev_call)(
        handle,
        DEV_PIO_STREAM_CONFIGURE,
        &cfg_args as *const _ as *mut u8,
        core::mem::size_of::<PioConfigureArgs>(),
    );
    if result < 0 {
        dev_log(sys, 1, b"[i2s] config fail".as_ptr(), 17);
        (dev_call)(handle, DEV_PIO_STREAM_FREE, core::ptr::null_mut(), 0);
        s.phase = I2sPhase::Error;
        return -1;
    }

    // Set stream consumption rate for stream_time (Q16.16: sample_rate << 16)
    let rate_q16 = (s.sample_rate as u32) << 16;
    let mut rate_arg = rate_q16.to_le_bytes();
    (dev_call)(handle, DEV_PIO_STREAM_SET_RATE, rate_arg.as_mut_ptr(), 4);

    s.stream_handle = handle;
    s.phase = I2sPhase::Running;

    dev_log(sys, 3, b"[i2s] running".as_ptr(), 13);
    0
}

/// Get PIO stream buffer via dev_query
#[inline(always)]
unsafe fn pio_get_buffer(dev_query: unsafe extern "C" fn(i32, u32, *mut u8, usize) -> i32, handle: i32) -> *mut u32 {
    let mut buf_ptr: *mut u32 = core::ptr::null_mut();
    (dev_query)(
        handle,
        DEV_PIO_STREAM_GET_BUFFER,
        &mut buf_ptr as *mut _ as *mut u8,
        4,
    );
    buf_ptr
}

/// Push words to PIO stream via dev_call
#[inline(always)]
unsafe fn pio_push(dev_call: unsafe extern "C" fn(i32, u32, *mut u8, usize) -> i32, handle: i32, words: usize) -> i32 {
    let mut arg = (words as u32).to_le_bytes();
    (dev_call)(handle, DEV_PIO_STREAM_PUSH, arg.as_mut_ptr(), 4)
}

/// Process audio data - loop to fill both DMA buffers
unsafe fn step_running(s: &mut I2sState) -> i32 {
    let syscalls = &*s.syscalls;
    let dev_call = syscalls.dev_call;
    let dev_query = syscalls.dev_query;
    let channel_read = syscalls.channel_read;
    let stream_handle = s.stream_handle;
    let in_chan = s.in_chan;

    let mut buffers_filled = 0;
    while buffers_filled < 2 {
        let can_push = (dev_call)(stream_handle, DEV_PIO_STREAM_CAN_PUSH, core::ptr::null_mut(), 0);
        if can_push == 0 {
            break;
        }

        // === Zero-copy mailbox path ===
        // Contract: producer must fill exactly one DMA buffer worth of
        // frame-aligned stereo data (PIO_BUFFER_WORDS * 4 bytes).
        // Size mismatch is a fatal contract violation — the producer is
        // misconfigured and will never recover, so we go to I2sPhase::Error.
        let mut mailbox_len: u32 = 0;
        let mailbox_ptr = dev_buffer_acquire_read(syscalls, in_chan, &mut mailbox_len);
        if !mailbox_ptr.is_null() {
            let expected = (pio::PIO_BUFFER_WORDS * 4) as u32;
            if mailbox_len != expected {
                // Log actual vs expected: "[i2s] mbox got NNNN need 2048"
                let mut msg = *b"[i2s] mbox got       need     \0";
                let mp = msg.as_mut_ptr();
                let n1 = fmt_u32_raw(mp.add(15), mailbox_len);
                // Shift " need " to right after the number
                let src = b" need ";
                let mut j = 0usize;
                while j < 6 {
                    *mp.add(15 + n1 + j) = *src.as_ptr().add(j);
                    j += 1;
                }
                let n2 = fmt_u32_raw(mp.add(15 + n1 + 6), expected);
                dev_log(syscalls, 1, msg.as_ptr(), 15 + n1 + 6 + n2);
                dev_buffer_release_read(syscalls, in_chan);
                s.phase = I2sPhase::Error;
                return -1;
            }

            let buffer = pio_get_buffer(dev_query, stream_handle);
            if buffer.is_null() {
                dev_buffer_release_read(syscalls, in_chan);
                dev_log(syscalls, 1, b"[i2s] null buf".as_ptr(), 14);
                s.phase = I2sPhase::Error;
                return -1;
            }

            let in_ptr = mailbox_ptr;
            let mut last = s.last_sample;
            let mut i = 0;
            while i < pio::PIO_BUFFER_WORDS {
                let base = i * 4;
                let l0 = *in_ptr.add(base);
                let l1 = *in_ptr.add(base + 1);
                let r0 = *in_ptr.add(base + 2);
                let r1 = *in_ptr.add(base + 3);
                let left = i16::from_le_bytes([l0, l1]);
                let right = i16::from_le_bytes([r0, r1]);
                last = ((right as u16 as u32) << 16) | (left as u16 as u32);
                core::ptr::write_volatile(buffer.add(i), last);
                i += 1;
            }
            s.last_sample = last;

            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            let result = pio_push(dev_call, stream_handle, pio::PIO_BUFFER_WORDS);
            dev_buffer_release_read(syscalls, in_chan);

            if result < 0 {
                dev_log(syscalls, 1, b"[i2s] push err".as_ptr(), 14);
                s.phase = I2sPhase::Error;
                return -1;
            }

            buffers_filled += 1;
            s.audio_count = s.audio_count.wrapping_add(1);
            continue;
        }

        // === channel_read path (FIFO + transparent mailbox fallback) ===
        let partial = s.partial_len as usize;
        if partial > 0 {
            let src = s.partial_buf.as_ptr();
            let dst = s.in_buf.as_mut_ptr();
            let mut i = 0;
            while i < partial {
                *dst.add(i) = *src.add(i);
                i += 1;
            }
        }

        let max_bytes = pio::PIO_BUFFER_WORDS * 4;
        let available_space = if max_bytes < IN_BUF_SIZE { max_bytes } else { IN_BUF_SIZE };
        let read_bytes = available_space - partial;

        let read = (channel_read)(in_chan, s.in_buf.as_mut_ptr().add(partial), read_bytes);
        if read == E_AGAIN || read == 0 {
            // No data available. Push a hold buffer (repeat last sample)
            // to keep I2S clocks continuous. Letting the SM stall causes
            // clock discontinuities that many DACs hear as clicks.
            // Fill ALL available buffers — gating on buffers_filled==0
            // would leave the second buffer empty, causing periodic starvation.
            if partial == 0 {
                let buffer = pio_get_buffer(dev_query, stream_handle);
                if !buffer.is_null() {
                    let fill = s.last_sample;
                    let mut i = 0;
                    while i < pio::PIO_BUFFER_WORDS {
                        core::ptr::write_volatile(buffer.add(i), fill);
                        i += 1;
                    }
                    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
                    pio_push(dev_call, stream_handle, pio::PIO_BUFFER_WORDS);
                    s.silence_count = s.silence_count.wrapping_add(1);
                    buffers_filled += 1;
                    continue;
                }
            }
            break;
        }
        if read < 0 {
            dev_log(syscalls, 1, b"[i2s] read err".as_ptr(), 14);
            s.phase = I2sPhase::Error;
            return -1;
        }

        let total_bytes = partial + (read as usize);
        let sample_pairs = (total_bytes / 4).min(pio::PIO_BUFFER_WORDS);
        let used_bytes = sample_pairs * 4;
        let trailing = total_bytes - used_bytes;

        if sample_pairs == 0 {
            s.partial_len = total_bytes as u8;
            break;
        }

        let buffer = pio_get_buffer(dev_query, stream_handle);
        if buffer.is_null() {
            dev_log(syscalls, 1, b"[i2s] null buf".as_ptr(), 14);
            s.phase = I2sPhase::Error;
            return -1;
        }

        // Convert interleaved i16 stereo to packed u32 for I2S
        let in_ptr = s.in_buf.as_ptr();
        let mut last = s.last_sample;
        let mut i = 0;
        while i < sample_pairs {
            let base = i * 4;
            let l0 = *in_ptr.add(base);
            let l1 = *in_ptr.add(base + 1);
            let r0 = *in_ptr.add(base + 2);
            let r1 = *in_ptr.add(base + 3);
            let left = i16::from_le_bytes([l0, l1]);
            let right = i16::from_le_bytes([r0, r1]);
            last = ((right as u16 as u32) << 16) | (left as u16 as u32);
            core::ptr::write_volatile(buffer.add(i), last);
            i += 1;
        }
        s.last_sample = last;

        // Pad remainder with last sample for continuous I2S clocks
        while i < pio::PIO_BUFFER_WORDS {
            core::ptr::write_volatile(buffer.add(i), last);
            i += 1;
        }

        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let result = pio_push(dev_call, stream_handle, pio::PIO_BUFFER_WORDS);
        if result < 0 {
            dev_log(syscalls, 1, b"[i2s] push err".as_ptr(), 14);
            s.phase = I2sPhase::Error;
            return -1;
        }

        buffers_filled += 1;
        s.audio_count = s.audio_count.wrapping_add(1);

        // Save trailing bytes for next read
        if trailing > 0 {
            let src = s.in_buf.as_ptr().add(used_bytes);
            let dst = s.partial_buf.as_mut_ptr();
            let mut j = 0;
            while j < trailing {
                *dst.add(j) = *src.add(j);
                j += 1;
            }
        }
        s.partial_len = trailing as u8;
    }

    0
}

/// Declare that the I2S module can safely consume from mailbox channels.
/// It uses buffer_acquire_read (read-only) and channel_read (which handles
/// mailbox transparently), but does NOT modify the buffer in place.
#[no_mangle]
#[link_section = ".text.module_mailbox_safe"]
pub extern "C" fn module_mailbox_safe() -> i32 {
    1
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
