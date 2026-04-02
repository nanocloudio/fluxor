// Internal pitch shift effect (time-domain overlap-add with crossfade).
//
// Two read pointers advance at a rate determined by the pitch ratio.
// Crossfade between them hides discontinuities.

use super::constants::*;
use super::state::EffectsState;

/// Convert semitones to read increment (16.16 fixed point).
/// semitones: signed value (-12 to +12).
pub fn semitones_to_inc(semitones: i8) -> u32 {
    if semitones == 0 {
        return 65536; // Unity
    }
    let abs_semi = if semitones >= 0 { semitones } else { -semitones } as usize;
    if abs_semi > 12 {
        if semitones > 0 { 131072 } else { 32768 }
    } else if semitones > 0 {
        // Pitch up: read faster
        SEMITONE_RATIOS[abs_semi]
    } else {
        // Pitch down: reciprocal (65536^2 / ratio)
        let ratio = SEMITONE_RATIOS[abs_semi];
        if ratio > 0 {
            let div = 65536u32 / ratio;
            let rem = 65536u32 - (div * ratio);
            (div * 65536) + ((rem * 65536) / ratio.max(1))
        } else {
            65536
        }
    }
}

/// Linear interpolation read from pitch buffer.
#[inline(always)]
unsafe fn read_interp(buf_ptr: *const i16, pos: u32) -> i32 {
    let idx = (pos >> 16) as usize;
    let frac = (pos & 0xFFFF) as i32;
    // Use if-else wrapping instead of modulo for PIC safety
    let idx0 = if idx >= PITCH_BUF_SIZE { idx - PITCH_BUF_SIZE } else { idx };
    let idx1 = if idx0 + 1 >= PITCH_BUF_SIZE { 0 } else { idx0 + 1 };
    let s0 = *buf_ptr.add(idx0) as i32;
    let s1 = *buf_ptr.add(idx1) as i32;
    s0 + (((s1 - s0) * frac) >> 16)
}

pub fn process_pitch_shift(sample_l: &mut i32, sample_r: &mut i32, s: &mut EffectsState) {
    // Bypass if unity
    if s.ps_direction == 0 {
        return;
    }

    unsafe {
        let in_l = *sample_l;
        let in_r = *sample_r;
        let mix = s.ps_mix as i32;
        let dry_mix = 255 - mix;

        // Write to circular buffers
        let write_pos = s.ps_write_pos as usize;
        let buf_l_ptr = s.ps_buf_l.as_mut_ptr();
        let buf_r_ptr = s.ps_buf_r.as_mut_ptr();
        *buf_l_ptr.add(write_pos) = in_l.clamp(-32768, 32767) as i16;
        *buf_r_ptr.add(write_pos) = in_r.clamp(-32768, 32767) as i16;
        let next_wp = s.ps_write_pos + 1;
        s.ps_write_pos = if next_wp >= PITCH_BUF_SIZE as u16 { 0 } else { next_wp };

        // Read from both positions
        let sample_a_l = read_interp(buf_l_ptr, s.ps_read_pos_a);
        let sample_a_r = read_interp(buf_r_ptr, s.ps_read_pos_a);
        let sample_b_l = read_interp(buf_l_ptr, s.ps_read_pos_b);
        let sample_b_r = read_interp(buf_r_ptr, s.ps_read_pos_b);

        // Crossfade weights
        let xfade = s.ps_xfade_pos as i32;
        let window = s.ps_window_size as i32;
        let weight_a = if window > 0 { ((window - xfade) * 256) / window.max(1) } else { 256 };
        let weight_b = 256 - weight_a;

        let pitched_l = ((sample_a_l * weight_a) + (sample_b_l * weight_b)) >> 8;
        let pitched_r = ((sample_a_r * weight_a) + (sample_b_r * weight_b)) >> 8;

        // Advance read positions
        s.ps_read_pos_a = s.ps_read_pos_a.wrapping_add(s.ps_read_inc);
        s.ps_read_pos_b = s.ps_read_pos_b.wrapping_add(s.ps_read_inc);

        // Wrap read positions
        let buf_size_fixed = (PITCH_BUF_SIZE as u32) << 16;
        if s.ps_read_pos_a >= buf_size_fixed {
            s.ps_read_pos_a -= buf_size_fixed;
        }
        if s.ps_read_pos_b >= buf_size_fixed {
            s.ps_read_pos_b -= buf_size_fixed;
        }

        // Advance crossfade
        s.ps_xfade_pos += 1;
        if s.ps_xfade_pos >= s.ps_window_size {
            s.ps_xfade_pos = 0;
            // Reset the trailing reader to write position
            if s.ps_active_reader == 0 {
                s.ps_read_pos_b = (s.ps_write_pos as u32) << 16;
                s.ps_active_reader = 1;
            } else {
                s.ps_read_pos_a = (s.ps_write_pos as u32) << 16;
                s.ps_active_reader = 0;
            }
        }

        // Mix dry and wet
        *sample_l = ((in_l * dry_mix) + (pitched_l * mix)) >> 8;
        *sample_r = ((in_r * dry_mix) + (pitched_r * mix)) >> 8;
    }
}
