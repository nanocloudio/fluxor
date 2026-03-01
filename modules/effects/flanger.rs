// Internal flanger effect.
//
// Short variable delay with LFO modulation and feedback.
// Uses flanger_* fields and flanger_buf_l/r in EffectsState.

use super::constants::*;
use super::state::EffectsState;

/// Sine LFO for flanger (returns -110 to +110)
#[inline(always)]
fn flanger_lfo(phase: u8) -> i8 {
    let quadrant = phase >> 6;
    let idx = (phase & 0x3F) as usize;
    match quadrant {
        0 => SINE_TABLE[idx],
        1 => SINE_TABLE[63 - idx],
        2 => -SINE_TABLE[idx],
        _ => -SINE_TABLE[63 - idx],
    }
}

/// Linear interpolation from delay buffer
#[inline(always)]
unsafe fn lerp_delay(buf_ptr: *const i16, write_idx: usize, delay_int: usize) -> i32 {
    let buf_len = FLANGER_BUF_SIZE;
    let read_idx = if write_idx >= delay_int {
        write_idx - delay_int
    } else {
        buf_len + write_idx - delay_int
    };
    let idx = if read_idx < buf_len { read_idx } else { 0 };
    *buf_ptr.add(idx) as i32
}

#[inline(always)]
pub fn process_flanger(sample_l: &mut i32, sample_r: &mut i32, s: &mut EffectsState, mix: u8) {
    // LFO
    let lfo_val = flanger_lfo((s.flanger_lfo_phase >> 24) as u8) as i32;
    s.flanger_lfo_phase = s.flanger_lfo_phase.wrapping_add(s.flanger_lfo_inc);

    // Calculate delay time (samples)
    let manual = s.flanger_manual as i32;
    let depth = s.flanger_depth as i32;
    let base_delay = ((manual * 80) / 255) + 1;
    let mod_amount = (lfo_val * depth * 40) / (110 * 255);
    let delay_samples = (base_delay + mod_amount).clamp(1, (FLANGER_BUF_SIZE - 2) as i32) as usize;

    // Add feedback to input
    let feedback = s.flanger_feedback as i32;
    let fb_l = (s.flanger_feedback_l as i32 * feedback) >> 8;
    let fb_r = (s.flanger_feedback_r as i32 * feedback) >> 8;
    let input_l = *sample_l + fb_l;
    let input_r = *sample_r + fb_r;

    unsafe {
        let write_idx = s.flanger_write_idx as usize;
        let buf_l = s.flanger_buf_l.as_mut_ptr();
        let buf_r = s.flanger_buf_r.as_mut_ptr();

        // Write to delay buffer
        *buf_l.add(write_idx) = input_l.clamp(-32768, 32767) as i16;
        *buf_r.add(write_idx) = input_r.clamp(-32768, 32767) as i16;

        // Read from delay
        let delayed_l = lerp_delay(buf_l, write_idx, delay_samples);
        let delayed_r = lerp_delay(buf_r, write_idx, delay_samples);

        // Store feedback
        s.flanger_feedback_l = delayed_l.clamp(-32768, 32767) as i16;
        s.flanger_feedback_r = delayed_r.clamp(-32768, 32767) as i16;

        // Advance write index
        let next = write_idx + 1;
        s.flanger_write_idx = if next >= FLANGER_BUF_SIZE { 0 } else { next as u16 };

        // Mix dry/wet
        let mix_i = mix as i32;
        let dry = 255 - mix_i;
        *sample_l = ((*sample_l * dry) + (delayed_l * mix_i)) >> 8;
        *sample_r = ((*sample_r * dry) + (delayed_r * mix_i)) >> 8;
    }
}
