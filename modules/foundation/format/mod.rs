//! Format PIC Module
//!
//! Format conversion: 8-bit unsigned or 16-bit signed input (mono/stereo)
//! to 16-bit signed stereo output. Includes resampling via 16.16 fixed-point
//! linear interpolation.
//!
//! This is an input normalisation stage. For gain control, use the mixer module.
//!
//! **Params (from config):**
//! - `input_rate`: Source sample rate (e.g., 11025)
//! - `output_rate`: Target sample rate (e.g., 44100)
//! - `input_bits`: 8 (unsigned 8-bit) or 16 (signed 16-bit)
//! - `input_channels`: 1 (mono) or 2 (stereo)
//! - `dither`: 0 (off) or 1 (TPDF dither for 8-bit sources)

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

/// Input buffer size (8-bit samples)
const IN_BUF_SIZE: usize = 1024;
/// Output buffer size (16-bit stereo samples = 4 bytes each)
const OUT_BUF_SIZE: usize = 2048;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct AudioFormatState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    /// Resampling step (16.16 fixed-point: input_rate / output_rate)
    step: u32,
    /// Resampling accumulator (16.16 fixed-point)
    accum: u32,
    /// Previous sample for interpolation (8-bit mode)
    prev_sample: u8,
    /// Input bit depth: 8 or 16
    input_bits: u8,
    /// Pending output bytes (from partial write)
    pending_out: u16,
    /// Offset into out_buf for pending data
    pending_offset: u16,
    /// Number of input channels: 1 (mono) or 2 (stereo)
    input_channels: u8,
    _pad1: u8,
    /// Source sample rate
    input_rate: u32,
    /// Target sample rate
    output_rate: u32,
    /// Previous sample for interpolation (16-bit mode)
    prev_sample_16: i16,
    /// Dither mode: 0=off, 1=TPDF
    dither: u8,
    _pad2: u8,
    /// PRNG state for TPDF dither
    rng_state: u32,
    /// Input buffer
    in_buf: [u8; IN_BUF_SIZE],
    /// Output buffer (i16 stereo pairs)
    out_buf: [u8; OUT_BUF_SIZE],
}

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::AudioFormatState;
    use super::{p_u8, p_u32};
    use super::SCHEMA_MAX;

    define_params! {
        AudioFormatState;

        1, input_rate, u32, 11025
            => |s, d, len| { s.input_rate = p_u32(d, len, 0, 11025); };

        2, output_rate, u32, 44100
            => |s, d, len| { s.output_rate = p_u32(d, len, 0, 44100); };

        3, input_bits, u8, 8, enum { u8pcm=8, s16pcm=16 }
            => |s, d, len| {
                let v = p_u8(d, len, 0, 8);
                s.input_bits = if v == 16 { 16 } else { 8 };
            };

        4, input_channels, u8, 1, enum { mono=1, stereo=2 }
            => |s, d, len| {
                let v = p_u8(d, len, 0, 1);
                s.input_channels = if v == 2 { 2 } else { 1 };
            };

        5, dither, u8, 0, enum { off=0, tpdf=1 }
            => |s, d, len| {
                let v = p_u8(d, len, 0, 0);
                s.dither = if v >= 1 { 1 } else { 0 };
            };
    }
}

/// Compute resampling step from input_rate and output_rate
#[inline]
fn compute_step(input_rate: u32, output_rate: u32) -> u32 {
    if output_rate > 0 && input_rate > 0 {
        let safe_input = if input_rate > 65535 { 65535 } else { input_rate };
        (safe_input << 16) / output_rate
    } else {
        1 << 16 // 1.0 (no resampling)
    }
}

impl AudioFormatState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.in_chan = -1;
        self.out_chan = -1;
        self.step = 1 << 16; // 1.0 default (no resampling)
        self.accum = 0;
        self.prev_sample = 128; // Silence in unsigned 8-bit
        self.input_bits = 8;
        self.pending_out = 0;
        self.pending_offset = 0;
        self.input_rate = 11025;
        self.output_rate = 44100;
        self.input_channels = 1;
        self._pad1 = 0;
        self.prev_sample_16 = 0;
        self.dither = 0;
        self._pad2 = 0;
        self.rng_state = 0xDEAD_BEEF;
        // Buffers zero-initialized by kernel
    }

    #[inline(always)]
    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }
}

// ============================================================================
// Conversion Helpers
// ============================================================================

/// Convert 8-bit unsigned to 16-bit signed (no gain)
#[inline(always)]
fn u8_to_i16(sample: u8) -> i16 {
    // Center around zero: 0..255 -> -128..127, scale to 16-bit range
    (((sample as i32) - 128) << 8) as i16
}

/// Linear interpolation between two i16 samples
#[inline(always)]
fn lerp_i16(s0: i16, s1: i16, frac: u32) -> i16 {
    // frac is 0..65535 (16-bit fractional part)
    let s0_i = s0 as i32;
    let s1_i = s1 as i32;
    (s0_i + (((s1_i - s0_i) * (frac as i32)) >> 16)) as i16
}

/// TPDF dither: triangular distribution noise, ±1 LSB of 8-bit source.
/// Two LCG draws summed → triangular PDF centered at zero.
#[inline(always)]
fn tpdf_dither(rng: &mut u32) -> i32 {
    *rng = rng.wrapping_mul(1103515245).wrapping_add(12345);
    let r1 = (*rng >> 16) as i32;
    *rng = rng.wrapping_mul(1103515245).wrapping_add(12345);
    let r2 = (*rng >> 16) as i32;
    (r1 - r2) >> 8 // ±~128, i.e. ±0.5 LSB in i16 terms for 8-bit source
}

// ============================================================================
// Processing
// ============================================================================

/// Process 8-bit unsigned input buffer, producing stereo i16 output with resampling.
/// Returns number of stereo sample pairs written to out_buf.
unsafe fn process_samples(s: &mut AudioFormatState, in_count: usize) -> usize {
    if in_count == 0 {
        return 0;
    }

    let max_out_pairs = OUT_BUF_SIZE / 4; // 4 bytes per stereo pair (2 × i16)
    let in_ptr = s.in_buf.as_ptr();
    let out_ptr = s.out_buf.as_mut_ptr() as *mut i16;
    let mut out_idx = 0;

    let dither_on = s.dither != 0;

    // No resampling case (step == 1.0)
    if s.step == (1 << 16) {
        let pairs = if in_count < max_out_pairs { in_count } else { max_out_pairs };
        let mut i = 0;
        while i < pairs {
            let mut sample = u8_to_i16(*in_ptr.add(i));
            if dither_on {
                let d = tpdf_dither(&mut s.rng_state);
                sample = ((sample as i32 + d).clamp(-32768, 32767)) as i16;
            }
            *out_ptr.add(i * 2) = sample;
            *out_ptr.add(i * 2 + 1) = sample;
            i += 1;
        }
        if in_count > 0 {
            s.prev_sample = *in_ptr.add(in_count - 1);
        }
        return pairs;
    }

    // Resampling loop: convert to i16 first, then interpolate in i16 domain
    while out_idx < max_out_pairs {
        let src_idx = (s.accum >> 16) as usize;
        if src_idx >= in_count {
            break;
        }
        let frac = s.accum & 0xFFFF;

        let s0 = u8_to_i16(*in_ptr.add(src_idx));
        let s1 = if src_idx + 1 < in_count {
            u8_to_i16(*in_ptr.add(src_idx + 1))
        } else {
            s0
        };

        let mut sample = lerp_i16(s0, s1, frac);
        if dither_on {
            let d = tpdf_dither(&mut s.rng_state);
            sample = ((sample as i32 + d).clamp(-32768, 32767)) as i16;
        }

        *out_ptr.add(out_idx * 2) = sample;
        *out_ptr.add(out_idx * 2 + 1) = sample;

        s.accum = s.accum.wrapping_add(s.step);
        out_idx += 1;
    }

    // Store last sample for next buffer
    if in_count > 0 {
        s.prev_sample = *in_ptr.add(in_count - 1);
    }

    // Subtract consumed samples from accumulator, preserve fractional part
    s.accum -= (in_count as u32) << 16;

    out_idx
}

// ============================================================================
// 16-bit Processing
// ============================================================================

/// Read one input frame as mono i16 from byte buffer.
/// For stereo, averages L+R channels.
#[inline(always)]
unsafe fn read_frame_16(ptr: *const u8, idx: usize, bytes_per_frame: usize, stereo: bool) -> i16 {
    let off = idx * bytes_per_frame;
    let lo = *ptr.add(off) as u16;
    let hi = *ptr.add(off + 1) as u16;
    let l = (lo | (hi << 8)) as i16;
    if stereo {
        let rlo = *ptr.add(off + 2) as u16;
        let rhi = *ptr.add(off + 3) as u16;
        let r = (rlo | (rhi << 8)) as i16;
        ((l as i32 + r as i32) >> 1) as i16
    } else {
        l
    }
}

/// Process 16-bit input buffer, producing stereo output with resampling.
/// Returns number of stereo sample pairs written to out_buf.
unsafe fn process_samples_16(s: &mut AudioFormatState, in_bytes: usize) -> usize {
    let stereo_in = s.input_channels >= 2;
    let bpf_shift = if stereo_in { 2usize } else { 1usize };
    let bytes_per_frame = 1usize << bpf_shift;
    let in_count = in_bytes >> bpf_shift;
    if in_count == 0 {
        return 0;
    }

    let max_out_pairs = OUT_BUF_SIZE / 4;
    let in_ptr = s.in_buf.as_ptr();
    let out_ptr = s.out_buf.as_mut_ptr() as *mut i16;
    let mut out_idx = 0;

    // No resampling case (step == 1.0)
    if s.step == (1 << 16) {
        let pairs = if in_count < max_out_pairs { in_count } else { max_out_pairs };
        let mut i = 0;
        while i < pairs {
            let sample = read_frame_16(in_ptr, i, bytes_per_frame, stereo_in);
            *out_ptr.add(i * 2) = sample;
            *out_ptr.add(i * 2 + 1) = sample;
            i += 1;
        }
        if in_count > 0 {
            s.prev_sample_16 = read_frame_16(in_ptr, in_count - 1, bytes_per_frame, stereo_in);
        }
        return pairs;
    }

    // Resampling loop: single pass with linear interpolation
    while out_idx < max_out_pairs {
        let src_idx = (s.accum >> 16) as usize;
        if src_idx >= in_count {
            break;
        }
        let frac = s.accum & 0xFFFF;

        let s0 = read_frame_16(in_ptr, src_idx, bytes_per_frame, stereo_in);
        let s1 = if src_idx + 1 < in_count {
            read_frame_16(in_ptr, src_idx + 1, bytes_per_frame, stereo_in)
        } else {
            s0
        };

        let sample = lerp_i16(s0, s1, frac);

        *out_ptr.add(out_idx * 2) = sample;
        *out_ptr.add(out_idx * 2 + 1) = sample;

        s.accum = s.accum.wrapping_add(s.step);
        out_idx += 1;
    }

    // Store last sample for next buffer
    if in_count > 0 {
        s.prev_sample_16 = read_frame_16(in_ptr, in_count - 1, bytes_per_frame, stereo_in);
    }

    // Subtract consumed samples from accumulator, preserve fractional part
    s.accum -= (in_count as u32) << 16;

    out_idx
}

// ============================================================================
// PIC Module Interface
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<AudioFormatState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
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
        if state.is_null() {
            return -5;
        }
        if state_size < core::mem::size_of::<AudioFormatState>() {
            return -6;
        }

        let s = &mut *(state as *mut AudioFormatState);
        s.init(syscalls as *const SyscallTable);

        s.in_chan = in_chan;
        s.out_chan = out_chan;

        // Parse params
        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;

        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else if !params.is_null() && params_len >= 8 {
            // Legacy format: input_rate(0-3), output_rate(4-7)
            #[inline(always)]
            unsafe fn read_u32_at(ptr: *const u8, offset: usize) -> u32 {
                let p = ptr.add(offset);
                u32::from_le_bytes([*p, *p.add(1), *p.add(2), *p.add(3)])
            }
            s.input_rate = read_u32_at(params, 0);
            s.output_rate = read_u32_at(params, 4);
        } else {
            params_def::set_defaults(s);
        }

        // Compute resampling step from rates
        s.step = compute_step(s.input_rate, s.output_rate);

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
        let s = &mut *(state as *mut AudioFormatState);
        if s.syscalls.is_null() {
            return -1;
        }

        // Cache syscall function pointers to avoid borrow conflicts
        let syscalls = &*s.syscalls;
        let channel_poll = syscalls.channel_poll;
        let channel_read = syscalls.channel_read;
        let channel_write = syscalls.channel_write;
        let in_chan = s.in_chan;
        let out_chan = s.out_chan;

        if !drain_pending(syscalls, out_chan, s.out_buf.as_ptr(), &mut s.pending_out, &mut s.pending_offset) {
            return 0;
        }

        // Check output ready
        let out_poll = (channel_poll)(out_chan, POLL_OUT);
        if out_poll <= 0 || ((out_poll as u32) & POLL_OUT) == 0 {
            return 0;
        }

        // Check input available
        let in_poll = (channel_poll)(in_chan, POLL_IN);
        if in_poll <= 0 || ((in_poll as u32) & POLL_IN) == 0 {
            return 0;
        }

        // Calculate max input bytes we can convert based on output buffer capacity.
        let bytes_per_frame = if s.input_bits == 16 {
            (s.input_channels as usize) * 2
        } else {
            1 // 8-bit mono: 1 byte per frame
        };
        let max_out_pairs = (OUT_BUF_SIZE / 4) as u32;
        let max_in = if s.step < (1 << 16) {
            // Upsampling: limit input frames to what output buffer can hold
            let max_frames = ((max_out_pairs * s.step) >> 16) as usize;
            (max_frames.max(1) * bytes_per_frame).min(IN_BUF_SIZE)
        } else {
            // Downsampling or 1:1: can use full input buffer
            IN_BUF_SIZE
        };

        // Read input (capped to what we can actually convert)
        let read = (channel_read)(
            in_chan,
            s.in_buf.as_mut_ptr(),
            max_in,
        );
        if read == E_AGAIN || read == 0 {
            return 0;
        }
        if read < 0 {
            dev_log(syscalls, 1, b"[fmt] read err".as_ptr(), 14);
            return -1;
        }

        let in_count = read as usize;

        // Process samples (dispatch based on input format)
        let out_pairs = if s.input_bits == 16 {
            process_samples_16(s, in_count)
        } else {
            process_samples(s, in_count)
        };
        if out_pairs == 0 {
            return 0;
        }

        let out_bytes = out_pairs * 4;

        let written = (channel_write)(
            out_chan,
            s.out_buf.as_ptr(),
            out_bytes,
        );
        if written < 0 && written != E_AGAIN {
            dev_log(syscalls, 1, b"[fmt] write err".as_ptr(), 15);
            return -1;
        }

        track_pending(written, out_bytes, &mut s.pending_out, &mut s.pending_offset);

        0
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
