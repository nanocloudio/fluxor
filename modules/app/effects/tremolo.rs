// Internal tremolo effect.
//
// Amplitude modulation via LFO. Supports sine, triangle, and square shapes.

use super::constants::SINE_TABLE;
use super::state::EffectsState;

/// Unsigned sine LFO for tremolo (returns 0-255, 128=center).
#[inline(always)]
fn tremolo_lfo(phase: u8, shape: u8) -> u8 {
    match shape {
        // Sine (from signed SINE_TABLE: -110..110 -> 0..255)
        0 => {
            let quadrant = phase >> 6;
            let idx = (phase & 0x3F) as usize;
            let signed = match quadrant {
                0 => SINE_TABLE[idx] as i32,
                1 => SINE_TABLE[63 - idx] as i32,
                2 => -(SINE_TABLE[idx] as i32),
                _ => -(SINE_TABLE[63 - idx] as i32),
            };
            // Map -110..110 to 0..255
            ((signed + 110) * 255 / 220).clamp(0, 255) as u8
        }
        // Triangle
        1 => {
            if phase < 128 { phase * 2 } else { 255 - ((phase - 128) * 2) }
        }
        // Square
        _ => {
            if phase < 128 { 255 } else { 0 }
        }
    }
}

/// Process one stereo sample pair through tremolo.
#[inline(always)]
pub fn process_tremolo(sample_l: &mut i32, sample_r: &mut i32, s: &mut EffectsState) {
    let depth = s.tremolo_depth as i32;
    if depth == 0 { return; }

    let lfo_val = tremolo_lfo((s.tremolo_lfo_phase >> 24) as u8, s.tremolo_shape) as i32;
    s.tremolo_lfo_phase = s.tremolo_lfo_phase.wrapping_add(s.tremolo_lfo_inc);

    // Gain: at depth=0 always 256 (unity). At depth=255, varies 0-256 with LFO.
    let min_gain = 256 - depth;
    let gain = min_gain + ((depth * lfo_val) >> 8);

    *sample_l = (*sample_l * gain) >> 8;
    *sample_r = (*sample_r * gain) >> 8;
}
