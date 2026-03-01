// Internal phaser effect.
//
// Cascaded allpass filters with LFO modulation.
// Uses phaser_* fields in EffectsState.

use super::constants::*;
use super::state::EffectsState;

/// First-order allpass filter
#[inline(always)]
fn allpass(input: i32, state: &mut i16, coef: i32) -> i32 {
    let z = *state as i32;
    let y = z + ((coef * (input - z)) >> 8);
    *state = input.clamp(-32768, 32767) as i16;
    y
}

/// Sine LFO for phaser (returns -110 to +110)
#[inline(always)]
fn phaser_lfo(phase: u8) -> i8 {
    let quadrant = phase >> 6;
    let idx = (phase & 0x3F) as usize;
    match quadrant {
        0 => SINE_TABLE[idx],
        1 => SINE_TABLE[63 - idx],
        2 => -SINE_TABLE[idx],
        _ => -SINE_TABLE[63 - idx],
    }
}

#[inline(always)]
pub fn process_phaser(sample_l: &mut i32, sample_r: &mut i32, s: &mut EffectsState, mix: u8) {
    // LFO
    let lfo_val = phaser_lfo((s.phaser_lfo_phase >> 24) as u8) as i32;
    s.phaser_lfo_phase = s.phaser_lfo_phase.wrapping_add(s.phaser_lfo_inc);

    // Allpass coefficient from LFO
    let mod_amount = (lfo_val * s.phaser_depth as i32) / 110;
    let coef = (128i32 + mod_amount).clamp(20, 230);

    // Add feedback
    let feedback = s.phaser_feedback as i32;
    let fb_l = (s.phaser_feedback_l as i32 * feedback) >> 8;
    let fb_r = (s.phaser_feedback_r as i32 * feedback) >> 8;
    let mut sig_l = *sample_l - fb_l;
    let mut sig_r = *sample_r - fb_r;

    // Process through allpass cascade
    let stages = (s.phaser_stages as usize).min(MAX_PHASER_STAGES);
    let mut stage = 0;
    while stage < stages {
        sig_l = allpass(sig_l, &mut s.phaser_allpass_l[stage], coef);
        sig_r = allpass(sig_r, &mut s.phaser_allpass_r[stage], coef);
        stage += 1;
    }

    // Store feedback
    s.phaser_feedback_l = sig_l.clamp(-32768, 32767) as i16;
    s.phaser_feedback_r = sig_r.clamp(-32768, 32767) as i16;

    // Mix dry/wet
    let mix_i = mix as i32;
    let dry = 255 - mix_i;
    *sample_l = ((*sample_l * dry) + (sig_l * mix_i)) >> 8;
    *sample_r = ((*sample_r * dry) + (sig_r * mix_i)) >> 8;
}
