// Internal harmonizer effect (two-voice pitch shifting with mono buffer).
//
// Creates harmony by mixing original with pitch-shifted voices.
// Voice 1 is centered, voice 2 has slight stereo spread.

use super::constants::*;
use super::state::EffectsState;

/// Linear interpolation read from mono pitch buffer.
#[inline(always)]
unsafe fn read_interp(buf_ptr: *const i16, pos: u32) -> i32 {
    let idx = (pos >> 16) as usize;
    let frac = (pos & 0xFFFF) as i32;
    let idx0 = if idx >= PITCH_BUF_SIZE { idx - PITCH_BUF_SIZE } else { idx };
    let idx1 = if idx0 + 1 >= PITCH_BUF_SIZE { 0 } else { idx0 + 1 };
    let s0 = *buf_ptr.add(idx0) as i32;
    let s1 = *buf_ptr.add(idx1) as i32;
    s0 + (((s1 - s0) * frac) >> 16)
}

/// Process one harmonizer voice. Returns the pitched+leveled sample.
#[inline(always)]
unsafe fn process_voice(
    read_inc: u32,
    level: u8,
    active: u8,
    read_pos_a: &mut u32,
    read_pos_b: &mut u32,
    xfade_pos: &mut u16,
    active_reader: &mut u8,
    buf_ptr: *const i16,
    write_pos: u16,
) -> i32 {
    if active == 0 {
        return 0;
    }

    let buf_size = PITCH_BUF_SIZE as u32;
    let window = HARM_WINDOW_SIZE;

    let sample_a = read_interp(buf_ptr, *read_pos_a);
    let sample_b = read_interp(buf_ptr, *read_pos_b);

    // Crossfade weights
    let xf = *xfade_pos as i32;
    let win = window as i32;
    let weight_a = if win > 0 { ((win - xf) * 256) / win.max(1) } else { 256 };
    let weight_b = 256 - weight_a;

    let pitched = ((sample_a * weight_a) + (sample_b * weight_b)) >> 8;

    // Advance read positions
    *read_pos_a = (*read_pos_a).wrapping_add(read_inc);
    *read_pos_b = (*read_pos_b).wrapping_add(read_inc);

    let buf_size_fixed = buf_size << 16;
    if *read_pos_a >= buf_size_fixed {
        *read_pos_a -= buf_size_fixed;
    }
    if *read_pos_b >= buf_size_fixed {
        *read_pos_b -= buf_size_fixed;
    }

    // Advance crossfade
    *xfade_pos += 1;
    if *xfade_pos >= window {
        *xfade_pos = 0;
        if *active_reader == 0 {
            *read_pos_b = (write_pos as u32) << 16;
            *active_reader = 1;
        } else {
            *read_pos_a = (write_pos as u32) << 16;
            *active_reader = 0;
        }
    }

    // Apply level
    (pitched * level as i32) >> 8
}

pub fn process_harmonizer(sample_l: &mut i32, sample_r: &mut i32, s: &mut EffectsState) {
    unsafe {
        let in_l = *sample_l;
        let in_r = *sample_r;
        let in_mono = (in_l + in_r) >> 1;

        // Write to mono buffer
        let write_pos = s.harm_write_pos as usize;
        let buf_ptr = s.harm_buf.as_mut_ptr();
        *buf_ptr.add(write_pos) = in_mono.clamp(-32768, 32767) as i16;
        let next_wp = s.harm_write_pos + 1;
        s.harm_write_pos = if next_wp >= PITCH_BUF_SIZE as u16 { 0 } else { next_wp };

        // Process voice 1
        let v1_out = process_voice(
            s.harm_v1_read_inc,
            s.harm_v1_level,
            s.harm_v1_active,
            &mut s.harm_v1_read_pos_a,
            &mut s.harm_v1_read_pos_b,
            &mut s.harm_v1_xfade_pos,
            &mut s.harm_v1_active_reader,
            s.harm_buf.as_ptr(),
            s.harm_write_pos,
        );

        // Process voice 2
        let v2_out = process_voice(
            s.harm_v2_read_inc,
            s.harm_v2_level,
            s.harm_v2_active,
            &mut s.harm_v2_read_pos_a,
            &mut s.harm_v2_read_pos_b,
            &mut s.harm_v2_xfade_pos,
            &mut s.harm_v2_active_reader,
            s.harm_buf.as_ptr(),
            s.harm_write_pos,
        );

        // Mix: dry + voice1 (center) + voice2 (stereo spread: 140/116)
        let dry_l = (in_l * s.harm_dry_level as i32) >> 8;
        let dry_r = (in_r * s.harm_dry_level as i32) >> 8;

        *sample_l = dry_l + v1_out + ((v2_out * 140) >> 8);
        *sample_r = dry_r + v1_out + ((v2_out * 116) >> 8);
    }
}
