// Internal ring modulator effect.
//
// Multiplies input by a carrier sine oscillator, creating sum and difference
// frequency sidebands. Mix controls blend with dry signal.

use super::constants::SINE_TABLE;
use super::state::EffectsState;

/// Carrier oscillator (sine, returns -110..110).
#[inline(always)]
fn carrier_sine(phase: u8) -> i32 {
    let quadrant = phase >> 6;
    let idx = (phase & 0x3F) as usize;
    match quadrant {
        0 => SINE_TABLE[idx] as i32,
        1 => SINE_TABLE[63 - idx] as i32,
        2 => -(SINE_TABLE[idx] as i32),
        _ => -(SINE_TABLE[63 - idx] as i32),
    }
}

/// Process one stereo sample pair through ring modulator.
#[inline(always)]
pub fn process_ring_mod(sample_l: &mut i32, sample_r: &mut i32, s: &mut EffectsState) {
    let mix = s.ringmod_mix as i32;
    if mix == 0 { return; }

    let carrier = carrier_sine((s.ringmod_carrier_phase >> 24) as u8);
    s.ringmod_carrier_phase = s.ringmod_carrier_phase.wrapping_add(s.ringmod_carrier_inc);

    // Ring modulation: multiply by carrier normalized to ±1 (divide by 110)
    let mod_l = (*sample_l * carrier) / 110;
    let mod_r = (*sample_r * carrier) / 110;

    let dry_mix = 255 - mix;
    *sample_l = ((*sample_l * dry_mix) + (mod_l * mix)) >> 8;
    *sample_r = ((*sample_r * dry_mix) + (mod_r * mix)) >> 8;
}
