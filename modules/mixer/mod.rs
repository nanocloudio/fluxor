//! Mixer Channel Strip PIC Module
//!
//! Stereo channel strip: input gain → 3-band EQ → pan → output gain.
//! Supports in-place buffer processing when aliased in a linear chain.
//!
//! Input/Output: interleaved stereo i16 samples.

#![no_std]

use core::ffi::c_void;

#[path = "../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../pic_runtime.rs");
include!("../param_macro.rs");

mod eq;
mod params;

// ============================================================================
// Constants
// ============================================================================

const PARAMS_SIZE: usize = 64;
/// i16 samples per buffer — derived from CHANNEL_BUFFER_SIZE (2048 bytes / 2)
const BUF_SAMPLES: usize = abi::CHANNEL_BUFFER_SIZE / 2;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct MixerState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    inplace: u8,
    sample_rate: u32,
    gain_in: u8,
    gain_out: u8,
    pan: u8,
    eq_enabled: u8,
    params: [u8; PARAMS_SIZE],
    params_len: u16,
    eq_coefs: [[i32; 5]; eq::NUM_BANDS],
    eq_state_l: [[i32; 4]; eq::NUM_BANDS],
    eq_state_r: [[i32; 4]; eq::NUM_BANDS],
    pending_out: u16,
    pending_offset: u16,
    step_count: u16,
    /// Saved trailing byte from odd-length channel_read (0xFF = none)
    trail_byte: u8,
    _diag_pad: u8,
    // Raw EQ params (for TLV v2 post-parse computation)
    eq_low_freq: u16,
    eq_low_gain: u8,
    eq_mid_freq: u16,
    eq_mid_gain: u8,
    eq_mid_q: u8,
    eq_high_freq: u16,
    eq_high_gain: u8,
    _eq_pad: u8,
    buf: [i16; BUF_SAMPLES],
}

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::MixerState;
    use super::{p_u8, p_u16, p_u32};
    use super::SCHEMA_MAX;

    define_params! {
        MixerState;

        1, sample_rate, u32, 44100
            => |s, d, len| {
                let v = p_u32(d, len, 0, 44100);
                s.sample_rate = if v > 0 { v } else { 44100 };
            };

        2, gain_out, u8, 200
            => |s, d, len| { s.gain_out = p_u8(d, len, 0, 200); };

        3, gain_in, u8, 128
            => |s, d, len| { s.gain_in = p_u8(d, len, 0, 128); };

        4, pan, u8, 128
            => |s, d, len| { s.pan = p_u8(d, len, 0, 128); };

        5, eq_low_freq, u16, 200
            => |s, d, len| {
                s.eq_low_freq = p_u16(d, len, 0, 200).clamp(50, 500);
            };

        6, eq_low_gain, u8, 128
            => |s, d, len| {
                s.eq_low_gain = p_u8(d, len, 0, 128);
            };

        7, eq_mid_freq, u16, 1000
            => |s, d, len| {
                s.eq_mid_freq = p_u16(d, len, 0, 1000).clamp(200, 5000);
            };

        8, eq_mid_gain, u8, 128
            => |s, d, len| {
                s.eq_mid_gain = p_u8(d, len, 0, 128);
            };

        9, eq_mid_q, u8, 128
            => |s, d, len| {
                s.eq_mid_q = p_u8(d, len, 0, 128);
            };

        10, eq_high_freq, u16, 4000
            => |s, d, len| {
                s.eq_high_freq = p_u16(d, len, 0, 4000).clamp(1000, 8000);
            };

        11, eq_high_gain, u8, 128
            => |s, d, len| {
                s.eq_high_gain = p_u8(d, len, 0, 128);
            };
    }
}

/// Compute EQ biquad coefficients from raw params (call after TLV v2 parse)
unsafe fn compute_eq_coefs(s: &mut MixerState) {
    if s.eq_enabled != 0 {
        let sr = s.sample_rate;
        s.eq_coefs[0] = eq::calc_low_shelf(s.eq_low_gain, s.eq_low_freq as u32, sr);
        s.eq_coefs[1] = eq::calc_parametric(s.eq_mid_gain, s.eq_mid_freq as u32, s.eq_mid_q, sr);
        s.eq_coefs[2] = eq::calc_high_shelf(s.eq_high_gain, s.eq_high_freq as u32, sr);
    }
}

// ============================================================================
// Sample Processing
// ============================================================================

#[inline(always)]
unsafe fn process_samples(samples: *mut i16, count: usize, s: &mut MixerState) {
    let gain_in = s.gain_in as i32;
    let gain_out = s.gain_out as i32;
    let pan_r = s.pan as i32;
    let pan_l = 255 - pan_r;
    let eq_on = s.eq_enabled != 0;

    let mut i = 0;
    while i < count {
        let mut sl = *samples.add(i) as i32;
        let mut sr = *samples.add(i + 1) as i32;

        // Input gain
        sl = (sl * gain_in) >> 7;
        sr = (sr * gain_in) >> 7;

        // EQ
        if eq_on {
            let mut band = 0;
            while band < eq::NUM_BANDS {
                sl = eq::biquad_process(sl, &s.eq_coefs[band], &mut s.eq_state_l[band]);
                sr = eq::biquad_process(sr, &s.eq_coefs[band], &mut s.eq_state_r[band]);
                band += 1;
            }
        }

        // Pan
        sl = (sl * pan_l) >> 8;
        sr = (sr * pan_r) >> 8;

        // Output gain
        sl = ((sl * gain_out) >> 7).clamp(-32768, 32767);
        sr = ((sr * gain_out) >> 7).clamp(-32768, 32767);

        *samples.add(i) = sl as i16;
        *samples.add(i + 1) = sr as i16;
        i += 2;
    }
}

// ============================================================================
// Module API
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<MixerState>()
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_in_place_safe"]
pub extern "C" fn module_in_place_safe() -> i32 {
    1
}

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
        if state.is_null() || syscalls.is_null() { return -1; }
        if state_size < core::mem::size_of::<MixerState>() { return -2; }

        let s = &mut *(state as *mut MixerState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.ctrl_chan = ctrl_chan;

        // Detect in-place aliasing
        s.inplace = if in_chan >= 0 && in_chan == out_chan { 1 } else { 0 };
        s.trail_byte = 0xFF; // No trailing byte

        // Initialize raw EQ params
        s.eq_low_freq = 200;
        s.eq_low_gain = 128;
        s.eq_mid_freq = 1000;
        s.eq_mid_gain = 128;
        s.eq_mid_q = 128;
        s.eq_high_freq = 4000;
        s.eq_high_gain = 128;
        s._eq_pad = 0;

        // Unity EQ coefficients (default)
        let mut b = 0;
        while b < eq::NUM_BANDS {
            s.eq_coefs[b] = [32768, 0, 0, 0, 0];
            s.eq_state_l[b] = [0; 4];
            s.eq_state_r[b] = [0; 4];
            b += 1;
        }

        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;

        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
            // Enable EQ only if any band gain differs from unity (128 = 0 dB)
            if s.eq_low_gain != 128 || s.eq_mid_gain != 128 || s.eq_high_gain != 128 {
                s.eq_enabled = 1;
            }
            compute_eq_coefs(s);
        } else {
            // Copy params blob for TLV v1 parser
            let copy_len = if !params.is_null() && params_len > 0 {
                params_len.min(PARAMS_SIZE)
            } else { 0 };

            let dst = s.params.as_mut_ptr();
            let mut i = 0;
            while i < PARAMS_SIZE {
                core::ptr::write_volatile(dst.add(i), 0u8);
                i += 1;
            }
            if copy_len > 0 {
                let mut i = 0;
                while i < copy_len {
                    core::ptr::write_volatile(dst.add(i), *params.add(i));
                    i += 1;
                }
            }
            s.params_len = copy_len as u16;
            params::apply_params(s);
        }

        s.pending_out = 0;
        s.pending_offset = 0;
        s.step_count = 0;

        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        let s = &mut *(state as *mut MixerState);
        let sys = &*s.syscalls;

        s.step_count = s.step_count.wrapping_add(1);

        if s.inplace != 0 {
            // In-place mode: acquire buffer, process, release
            let mut len: u32 = 0;
            let ptr = dev_buffer_acquire_inplace(sys, s.in_chan, &mut len);
            if ptr.is_null() {
                return 0; // not ready yet
            }

            let sample_count = (len as usize) / 2; // i16 samples
            let stereo_count = sample_count & !1; // ensure even
            if stereo_count > 0 {
                process_samples(ptr as *mut i16, stereo_count, s);
            }

            dev_buffer_release_write(sys, s.in_chan, len);
            return 0;
        }

        // Normal mode: read → process → write
        // Drain any pending output first
        if s.pending_out > 0 {
            if !drain_pending(
                sys, s.out_chan,
                s.buf.as_ptr() as *const u8,
                &mut s.pending_out,
                &mut s.pending_offset,
            ) {
                return 0;
            }
        }

        // Forward sample rate IOCTL from input to output
        {
            let mut rate_val = [0u8; 4];
            let rv = rate_val.as_mut_ptr();
            let res = dev_channel_ioctl(sys, s.in_chan, IOCTL_POLL_NOTIFY, rv);
            if res == 0 {
                let new_rate = u32::from_le_bytes(rate_val);
                if new_rate > 0 {
                    s.sample_rate = new_rate;
                    dev_channel_ioctl(sys, s.out_chan, IOCTL_NOTIFY, rv);
                }
            }
        }

        // Check output ready
        let out_poll = (sys.channel_poll)(s.out_chan, POLL_OUT);
        if out_poll & POLL_OUT as i32 == 0 {
            return 0;
        }

        // Check input
        let in_poll = (sys.channel_poll)(s.in_chan, POLL_IN | POLL_HUP);
        if in_poll & POLL_HUP as i32 != 0 {
            return 1; // upstream done
        }
        if in_poll & POLL_IN as i32 == 0 {
            return 0;
        }

        // Read input with trailing-byte handling to maintain i16 alignment.
        // If the previous read had an odd byte count, prepend the saved byte.
        let buf_ptr = s.buf.as_mut_ptr() as *mut u8;
        let mut fill: usize = 0;
        if s.trail_byte != 0xFF {
            *buf_ptr = s.trail_byte;
            s.trail_byte = 0xFF;
            fill = 1;
        }
        let max_read = BUF_SAMPLES * 2 - fill;
        let read = (sys.channel_read)(s.in_chan, buf_ptr.add(fill), max_read);
        if read <= 0 && fill == 0 {
            return 0;
        }
        let total = fill + (if read > 0 { read as usize } else { 0 });
        // Save trailing byte if odd
        if (total & 1) != 0 {
            s.trail_byte = *buf_ptr.add(total - 1);
        } else {
            s.trail_byte = 0xFF;
        }
        let sample_count = total / 2;
        let stereo_count = sample_count & !1;

        if stereo_count > 0 {
            process_samples(s.buf.as_mut_ptr(), stereo_count, s);
        }


        // Write output — channel_write handles both FIFO and mailbox transparently
        let out_bytes = stereo_count * 2;
        let written = (sys.channel_write)(s.out_chan, s.buf.as_ptr() as *const u8, out_bytes);
        if written < out_bytes as i32 {
            // Partial write — track pending
            let written_samples = if written > 0 { written as u16 / 2 } else { 0 };
            s.pending_out = stereo_count as u16;
            s.pending_offset = written_samples;
        }

        0
    }
}

#[no_mangle]
#[link_section = ".text.module_channel_hints"]
pub extern "C" fn module_channel_hints(hints: *mut ChannelHint, max_hints: usize) -> usize {
    if hints.is_null() || max_hints == 0 { return 0; }
    unsafe {
        // Output: 2048 bytes (256 stereo frames × 4 bytes)
        *hints = ChannelHint { port_type: 1, port_index: 0, buffer_size: 2048 };
    }
    1
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
