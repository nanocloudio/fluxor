//! Brightness PIC Module
//!
//! Converts sequencer events or audio amplitude to LED brightness values (0-255)
//! with configurable gamma curve correction.
//!
//! **Modes:**
//! - `mode: 0` (sequencer) — reads 8-byte note events, extracts freq as brightness
//! - `mode: 1` (audio) — reads i16 stereo samples, envelope follower → brightness
//!
//! **Curves:**
//! - `curve: 0` — linear (no transform)
//! - `curve: 1` — gamma 2.2 (standard perceptual)
//! - `curve: 2` — gamma 2.8 (aggressive, cheap LEDs)
//! - `curve: 3` — inverse gamma (pre-corrected sources)
//!
//! **Output:** single brightness byte (0-255) on output channel.

#![no_std]

use core::ffi::c_void;

#[path = "../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../pic_runtime.rs");
include!("../param_macro.rs");

mod params_def;

// ============================================================================
// Constants
// ============================================================================

/// Sequencer note event size (target_frame:4 + freq:2 + velocity:1 + flags:1)
const NOTE_EVENT_SIZE: usize = 8;

/// Audio input buffer (stereo i16 pairs)
const AUDIO_BUF_SIZE: usize = 128;

/// Mode constants
const MODE_SEQUENCER: u8 = 0;
const MODE_AUDIO: u8 = 1;

/// Curve constants
const CURVE_LINEAR: u8 = 0;
const CURVE_GAMMA22: u8 = 1;
const CURVE_GAMMA28: u8 = 2;
const CURVE_INV_GAMMA: u8 = 3;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct BrightnessState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,

    mode: u8,
    curve: u8,
    _pad: [u8; 2],

    // Envelope follower (audio mode)
    envelope: u32,       // 16.16 fixed-point
    attack_coeff: u16,
    release_coeff: u16,

    // Output state
    last_brightness: u8,
    output_divider: u8,
    div_counter: u8,
    _pad2: u8,

    // Gamma LUT
    gamma_lut: [u8; 256],

    // Audio scratch buffer
    audio_buf: [u8; AUDIO_BUF_SIZE],
}

// ============================================================================
// Gamma LUT Generation (integer-only)
// ============================================================================

/// Generate gamma lookup table.
/// Uses integer approximations — no floating point.
unsafe fn generate_gamma_lut(lut: *mut u8, curve: u8) {
    let mut i: usize = 0;
    while i < 256 {
        let val = match curve {
            CURVE_LINEAR => i as u8,
            CURVE_GAMMA22 => {
                // Approximate gamma 2.2 with cube: (i/255)^2.2 ≈ (i/255)^2 * (i/255)^0.2
                // Simpler: use (i*i*i) >> 16 which gives ~gamma 3, too aggressive.
                // Better: (i*i + i) >> 9 blended with (i*i*i) >> 16
                // Best practical: quadratic+linear blend = (i*i*3 + i*253) >> 10
                // This produces a curve between 2.0 and 2.5, close to 2.2
                let v = (i * i * 3 + i * 253) >> 10;
                if v > 255 { 255 } else { v as u8 }
            }
            CURVE_GAMMA28 => {
                // Approximate gamma 2.8: heavier compression of low values
                // (i*i*i) >> 16 gives gamma 3.0 which is close enough to 2.8
                let v = (i * i * i) >> 16;
                if v > 255 { 255 } else { v as u8 }
            }
            CURVE_INV_GAMMA => {
                // Inverse gamma ~2.2: sqrt-like expansion
                // Approximate with: isqrt(i * 255) or piecewise
                // Simple: (isqrt(i << 8) * 255) >> 8
                // Practical: use Newton's method for isqrt(i * 65025)
                let product = i * 65025; // i * 255^2
                let v = isqrt_u32(product as u32);
                if v > 255 { 255 } else { v as u8 }
            }
            _ => i as u8,
        };
        core::ptr::write_volatile(lut.add(i), val);
        i += 1;
    }
}

/// Integer square root (bit-by-bit method, no division).
#[inline]
fn isqrt_u32(n: u32) -> u32 {
    if n == 0 { return 0; }
    let mut result: u32 = 0;
    let mut bit: u32 = 1 << 30; // Start from the highest bit
    let mut num = n;

    // Find highest set bit pair
    while bit > num {
        bit >>= 2;
    }

    while bit != 0 {
        if num >= result + bit {
            num -= result + bit;
            result = (result >> 1) + bit;
        } else {
            result >>= 1;
        }
        bit >>= 2;
    }
    result
}

// ============================================================================
// Module API
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<BrightnessState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
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
        if state_size < core::mem::size_of::<BrightnessState>() {
            return -2;
        }

        // State memory is already zeroed by kernel's alloc_state()
        let s = &mut *(state as *mut BrightnessState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.ctrl_chan = ctrl_chan;

        // Defaults
        s.mode = MODE_SEQUENCER;
        s.curve = CURVE_GAMMA22;
        s.attack_coeff = 2000;
        s.release_coeff = 200;
        s.output_divider = 1;
        s.last_brightness = 0;
        s.div_counter = 0;
        s.envelope = 0;

        // Parse TLV params
        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;

        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        // Generate gamma LUT based on selected curve
        generate_gamma_lut(s.gamma_lut.as_mut_ptr(), s.curve);

        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut c_void) -> i32 {
    unsafe {
        let s = &mut *(state as *mut BrightnessState);
        if s.syscalls.is_null() || s.in_chan < 0 || s.out_chan < 0 {
            return 0;
        }

        match s.mode {
            MODE_AUDIO => step_audio(s),
            _ => step_sequencer(s),
        }

        0
    }
}

// ============================================================================
// Sequencer Mode
// ============================================================================

/// Read sequencer note events, extract freq as brightness, apply gamma.
unsafe fn step_sequencer(s: &mut BrightnessState) {
    let sys = &*s.syscalls;

    let poll = (sys.channel_poll)(s.in_chan, POLL_IN);
    if poll <= 0 || (poll as u8 & POLL_IN) == 0 {
        return;
    }

    let mut buf = [0u8; NOTE_EVENT_SIZE];
    let r = (sys.channel_read)(s.in_chan, buf.as_mut_ptr(), NOTE_EVENT_SIZE);
    if r < NOTE_EVENT_SIZE as i32 {
        return;
    }

    // Extract freq (bytes 4-5, u16 LE) as raw brightness value
    let freq = u16::from_le_bytes([buf[4], buf[5]]);
    let raw = if freq > 255 { 255u8 } else { freq as u8 };

    // Apply gamma curve
    let brightness = *s.gamma_lut.as_ptr().add(raw as usize);

    // Only write if changed
    if brightness != s.last_brightness {
        let out_poll = (sys.channel_poll)(s.out_chan, POLL_OUT);
        if out_poll > 0 && (out_poll as u8 & POLL_OUT) != 0 {
            let b = [brightness];
            (sys.channel_write)(s.out_chan, b.as_ptr(), 1);
            s.last_brightness = brightness;
        }
    }
}

// ============================================================================
// Audio Mode
// ============================================================================

/// Read audio samples, compute envelope, map to brightness.
unsafe fn step_audio(s: &mut BrightnessState) {
    let sys = &*s.syscalls;

    let poll = (sys.channel_poll)(s.in_chan, POLL_IN);
    if poll <= 0 || (poll as u8 & POLL_IN) == 0 {
        return;
    }

    // Read available audio data (i16 stereo = 4 bytes per frame)
    let r = (sys.channel_read)(s.in_chan, s.audio_buf.as_mut_ptr(), AUDIO_BUF_SIZE);
    if r <= 0 {
        return;
    }

    let bytes = r as usize;
    let frames = bytes / 4; // 4 bytes per stereo i16 frame

    // Find peak amplitude across all frames
    let buf_ptr = s.audio_buf.as_ptr();
    let mut peak: u32 = 0;
    let mut i = 0;
    while i < frames {
        let offset = i * 4;
        let left = i16::from_le_bytes([
            *buf_ptr.add(offset),
            *buf_ptr.add(offset + 1),
        ]);
        let right = i16::from_le_bytes([
            *buf_ptr.add(offset + 2),
            *buf_ptr.add(offset + 3),
        ]);

        let abs_l = (left as i32).unsigned_abs();
        let abs_r = (right as i32).unsigned_abs();
        let sample_peak = if abs_l > abs_r { abs_l } else { abs_r };
        if sample_peak > peak {
            peak = sample_peak;
        }
        i += 1;
    }

    // Envelope follower (16.16 fixed-point)
    let peak_fp = peak << 16; // Convert to fixed-point
    if peak_fp > s.envelope {
        // Attack: move toward peak
        let delta = peak_fp - s.envelope;
        let step = (delta >> 16).wrapping_mul(s.attack_coeff as u32);
        s.envelope = s.envelope.wrapping_add(step.max(1));
        if s.envelope > peak_fp {
            s.envelope = peak_fp;
        }
    } else {
        // Release: decay toward peak
        let delta = s.envelope - peak_fp;
        let step = (delta >> 16).wrapping_mul(s.release_coeff as u32);
        if step >= s.envelope {
            s.envelope = 0;
        } else {
            s.envelope = s.envelope.wrapping_sub(step.max(1));
        }
        if s.envelope < peak_fp {
            s.envelope = peak_fp;
        }
    }

    // Output throttle
    s.div_counter = s.div_counter.wrapping_add(1);
    if s.div_counter < s.output_divider {
        return;
    }
    s.div_counter = 0;

    // Map envelope to 0-255
    // envelope is 16.16 fixed-point, max value = 32767 << 16
    // Shift right by 23 to get 0-255: (32767 << 16) >> 23 = 255
    let raw = (s.envelope >> 23) as u8;

    // Apply gamma curve
    let brightness = *s.gamma_lut.as_ptr().add(raw as usize);

    if brightness != s.last_brightness {
        let out_poll = (sys.channel_poll)(s.out_chan, POLL_OUT);
        if out_poll > 0 && (out_poll as u8 & POLL_OUT) != 0 {
            let b = [brightness];
            (sys.channel_write)(s.out_chan, b.as_ptr(), 1);
            s.last_brightness = brightness;
        }
    }
}
