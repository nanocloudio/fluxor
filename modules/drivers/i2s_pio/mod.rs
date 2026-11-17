//! I2S PIC Module
//!
//! Outputs 16-bit stereo audio to I2S via PIO with double-buffered DMA.
//! PIO operations use the HAL_PIO provider_call/provider_query interface.
//!
//! # Configuration
//!
//! Via I2sParams:
//! - data_pin: GPIO pin for serial data output
//! - clock_base: GPIO pin for BCLK (LRCLK is clock_base + 1)
//! - sample_rate: Output sample rate in Hz (default: 44100)
//!
//! # Mailbox input
//!
//! Input is read with `channel_read` on both FIFO and mailbox edges. On a
//! mailbox edge a read takes one whole message or nothing, so the input
//! buffer holds one partly filled PIO buffer plus one message: any message up
//! to `abi::CHANNEL_BUFFER_SIZE` (one PIO buffer, `PIO_BUFFER_WORDS * 4` bytes)
//! is accepted at any fill level, and a larger one stays unread. Messages need
//! not be PIO-buffer sized; the module pushes a PIO buffer whenever a full
//! one has accumulated.
//!
//! # PIC Safety
//!
//! - No panicking operations
//! - All syscalls through function pointer table
//! - No 64-bit division

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

mod params_def;
mod pio;

// ============================================================================
// Provider contract id + PIO opcodes (mirror
// `kernel::module::provider::contract::HAL_PIO` and `abi::platform::rp::pio`).
// ============================================================================

const HAL_PIO_CONTRACT: u32 = abi::registry::pio::ID as u32;
const DEV_PIO_STREAM_ALLOC: u32 = abi::registry::pio::STREAM_ALLOC;
const DEV_PIO_STREAM_LOAD_PROGRAM: u32 = abi::registry::pio::STREAM_LOAD_PROGRAM;
const DEV_PIO_STREAM_CONFIGURE: u32 = abi::registry::pio::STREAM_CONFIGURE;
const DEV_PIO_STREAM_CAN_PUSH: u32 = abi::registry::pio::STREAM_CAN_PUSH;
const DEV_PIO_STREAM_PUSH: u32 = abi::registry::pio::STREAM_PUSH;
const DEV_PIO_STREAM_FREE: u32 = abi::registry::pio::STREAM_FREE;
const DEV_PIO_STREAM_SET_RATE: u32 = abi::registry::pio::STREAM_SET_RATE;

// ============================================================================
// HAL_PIO argument structs (mirrors the STREAM_CONFIGURE layout)
// ============================================================================

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

/// Input buffer: two PIO buffers, so one whole mailbox message fits beside a
/// partly filled PIO buffer. A mailbox read takes a whole message or leaves it
/// in place when the space is too small.
const IN_BUF_SIZE: usize = abi::CHANNEL_BUFFER_SIZE * 2; // 4096 bytes

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
    _pad0: u8,
    sample_rate: u32,
    /// Bytes accumulated in in_buf waiting for a full PIO buffer
    in_buf_fill: u16,
    _pad1: u16,
    /// Diagnostic: count of audio buffers vs silence buffers
    audio_count: u16,
    silence_count: u16,
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
        self._pad0 = 0;
        self.sample_rate = 44100;
        self.in_buf_fill = 0;
        self._pad1 = 0;
        self.audio_count = 0;
        self.silence_count = 0;
    }

    #[inline(always)]
    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }
}

// ============================================================================
// PIC Module Interface
// ============================================================================

fluxor_rt::module_facts! { state: I2sState }

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

        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;

        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else if !params.is_null() && params_len >= core::mem::size_of::<I2sParams>() {
            let p = &*(params as *const I2sParams);
            s.data_pin = if p.data_pin == 0 { 28 } else { p.data_pin };
            s.clock_base = if p.clock_base == 0 { 26 } else { p.clock_base };
            s.sample_rate = p.sample_rate; // 0 = from the stream's format record
        }

        let sys = s.sys();
        dev_log(sys, 3, b"[i2s] ready".as_ptr(), 11);

        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> StepReturn {
    unsafe {
        if state.is_null() {
            return StepReturn::error(-1);
        }
        let s = &mut *(state as *mut I2sState);
        if s.syscalls.is_null() {
            return StepReturn::error(-1);
        }

        match s.phase {
            I2sPhase::Init => {
                // A format record at the head of the input states the rate
                // the stream is initialised at.
                while take_format(s) {}
                let r = step_init(s);
                if r.is_error() {
                    return r;
                }
                step_running(s)
            }
            I2sPhase::Running => step_running(s),
            I2sPhase::Error => StepReturn::error(-1),
            _ => StepReturn::error(-1),
        }
    }
}

/// Initialize PIO stream via provider_open / provider_call.
unsafe fn step_init(s: &mut I2sState) -> StepReturn {
    let sys = &*s.syscalls;
    let provider_open = sys.provider_open;
    let provider_call = sys.provider_call;
    let _provider_query = sys.provider_query;
    let sample_rate = s.sample_rate;
    let data_pin = s.data_pin;
    let clock_base = s.clock_base;

    // Open PIO stream handle — tracked against HAL_PIO contract.
    let handle = (provider_open)(
        HAL_PIO_CONTRACT,
        DEV_PIO_STREAM_ALLOC,
        core::ptr::null_mut(),
        0,
    );
    if handle < 0 {
        dev_log(sys, 1, b"[i2s] alloc fail".as_ptr(), 16);
        s.phase = I2sPhase::Error;
        return StepReturn::error(-1);
    }

    // Load PIO program
    let mut load_arg = abi::platform::rp::pio::load_program::encode(
        pio::WRAP_TARGET,
        pio::WRAP,
        pio::SIDESET_BITS,
        pio::OPTIONS,
    );
    let mut program = [0u8; 2 * pio::PROGRAM.len()];
    let mut i = 0usize;
    while i < pio::PROGRAM.len() {
        let w = pio::PROGRAM[i].to_le_bytes();
        program[2 * i] = w[0];
        program[2 * i + 1] = w[1];
        i += 1;
    }
    let result = (provider_call)(
        handle,
        DEV_PIO_STREAM_LOAD_PROGRAM,
        load_arg.as_mut_ptr(),
        load_arg.len(),
        program.as_mut_ptr(),
        program.len(),
    );
    if result < 0 {
        dev_log(sys, 1, b"[i2s] load fail".as_ptr(), 15);
        (provider_call)(
            handle,
            DEV_PIO_STREAM_FREE,
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
            0,
        );
        s.phase = I2sPhase::Error;
        return StepReturn::error(-1);
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
    let result = (provider_call)(
        handle,
        DEV_PIO_STREAM_CONFIGURE,
        &cfg_args as *const _ as *mut u8,
        core::mem::size_of::<PioConfigureArgs>(),
        core::ptr::null_mut(),
        0,
    );
    if result < 0 {
        dev_log(sys, 1, b"[i2s] config fail".as_ptr(), 17);
        (provider_call)(
            handle,
            DEV_PIO_STREAM_FREE,
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
            0,
        );
        s.phase = I2sPhase::Error;
        return StepReturn::error(-1);
    }

    // Set stream consumption rate for stream_time (Q16.16: sample_rate << 16)
    let rate_q16 = s.sample_rate << 16;
    let mut rate_arg = rate_q16.to_le_bytes();
    (provider_call)(
        handle,
        DEV_PIO_STREAM_SET_RATE,
        rate_arg.as_mut_ptr(),
        4,
        core::ptr::null_mut(),
        0,
    );

    s.stream_handle = handle;
    s.phase = I2sPhase::Running;

    // Log actual rate used for PIO configuration
    {
        let mut lb = [0u8; 24];
        let bp = lb.as_mut_ptr();
        let tag = b"[i2s] @";
        let mut p = 0usize;
        let mut t = 0usize;
        while t < tag.len() {
            *bp.add(p) = *tag.as_ptr().add(t);
            p += 1;
            t += 1;
        }
        p += fmt_u32_raw(bp.add(p), s.sample_rate);
        *bp.add(p) = b'H';
        p += 1;
        *bp.add(p) = b'z';
        p += 1;
        dev_log(sys, 3, bp, p);
    }
    StepReturn::Continue
}

/// Push `bytes` (whole words, u32 LE) at `words` to the PIO stream; the
/// provider copies them into its back buffer.
#[inline(always)]
unsafe fn pio_push(
    provider_call: unsafe extern "C" fn(i32, u32, *mut u8, usize, *mut u8, usize) -> i32,
    handle: i32,
    words: *const u8,
    bytes: usize,
) -> i32 {
    (provider_call)(
        handle,
        DEV_PIO_STREAM_PUSH,
        core::ptr::null_mut(),
        0,
        words as *mut u8,
        bytes,
    )
}

/// Take a format record (`audio_sample::format`) at the head of the input
/// and remember its rate. `false` when the head holds no format record (or
/// nothing).
unsafe fn take_format(s: &mut I2sState) -> bool {
    use abi::contracts::audio_sample::format;
    let sys = &*s.syscalls;
    if dev_channel_record_len(sys, s.in_chan) != format::LEN as i32 {
        return false;
    }
    let mut rec = [0u8; format::LEN];
    if (sys.channel_read)(s.in_chan, rec.as_mut_ptr(), format::LEN) != format::LEN as i32 {
        return false;
    }
    if let Some(rate) = format::parse(&rec) {
        if rate > 0 {
            s.sample_rate = rate;
        }
    }
    true
}

/// Move what the input holds into `in_buf`, record by record, so a read never
/// runs past a sample record into a format record. A format record's rate is
/// remembered for the next stream init: reconfiguring a running state
/// machine resets it to Ready and breaks its DMA. Stops when the input is
/// empty or the next record does not fit (a mailbox record is taken whole).
unsafe fn read_input(s: &mut I2sState) {
    use abi::contracts::audio_sample::format;
    let sys = &*s.syscalls;
    loop {
        let rec = dev_channel_record_len(sys, s.in_chan);
        if rec <= 0 {
            return;
        }
        let rec = rec as usize;
        if rec == format::LEN {
            if !take_format(s) {
                return;
            }
            continue;
        }
        let fill = s.in_buf_fill as usize;
        let space = IN_BUF_SIZE - fill;
        if space == 0 {
            return;
        }
        let read = (sys.channel_read)(s.in_chan, s.in_buf.as_mut_ptr().add(fill), rec.min(space));
        if read <= 0 {
            return;
        }
        s.in_buf_fill += read as u16;
    }
}

/// Process audio data - loop to fill both DMA buffers
unsafe fn step_running(s: &mut I2sState) -> StepReturn {
    let syscalls = &*s.syscalls;
    let provider_call = syscalls.provider_call;
    let stream_handle = s.stream_handle;

    let mut buffers_filled = 0;
    while buffers_filled < 2 {
        let can_push = (provider_call)(
            stream_handle,
            DEV_PIO_STREAM_CAN_PUSH,
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
            0,
        );
        if can_push == 0 {
            break;
        }

        // in_buf is 4096 bytes (2× PIO buffer) so there's always room for
        // one partial PIO buffer + one full mailbox message.
        let max_bytes = pio::PIO_BUFFER_WORDS * 4; // 2048
        read_input(s);

        let total = s.in_buf_fill as usize;
        if total < max_bytes {
            // Not enough for a full PIO buffer yet.
            // Don't push anything — PIO double-buffer replays the last real buffer.
            // Pushing held-sample data would REPLACE the real audio in the back buffer.
            break;
        }

        // Full PIO buffer accumulated — process and push
        let sample_pairs = pio::PIO_BUFFER_WORDS; // total / 4, always == PIO_BUFFER_WORDS
        let used_bytes = sample_pairs * 4;
        let trailing = total - used_bytes;

        // Interleaved i16 LE stereo is the packed I2S word ((right << 16) |
        // left, u32 LE) byte for byte: the words go out as they came in.
        let result = pio_push(provider_call, stream_handle, s.in_buf.as_ptr(), used_bytes);
        if result == E_BUSY {
            // The last buffer still waits for the DMA — keep these for next tick.
            break;
        }
        if result < 0 {
            dev_log(syscalls, 1, b"[i2s] push err".as_ptr(), 14);
            s.phase = I2sPhase::Error;
            return StepReturn::error(-1);
        }

        buffers_filled += 1;
        if s.audio_count == 0 {
            dev_log(syscalls, 3, b"[i2s] audio".as_ptr(), 11);
        }

        s.audio_count = s.audio_count.wrapping_add(1);

        // Move trailing bytes to start of in_buf
        if trailing > 0 {
            let mut j = 0;
            while j < trailing {
                *s.in_buf.as_mut_ptr().add(j) = *s.in_buf.as_ptr().add(used_bytes + j);
                j += 1;
            }
        }
        s.in_buf_fill = trailing as u16;
    }

    StepReturn::Continue
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `crates/fluxor-rt/src/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
fluxor_rt::wasm_entry!();
