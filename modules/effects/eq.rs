// Internal 3-band parametric EQ effect.
//
// Low shelf + parametric mid + high shelf using biquad filters.
// Coefficients stored in eq_coefs, runtime state in eq_state_l/eq_state_r.

use super::state::EffectsState;
use super::constants::*;

/// Process one sample through a biquad filter.
/// Coefficients: coefs[0..5] = [b0, b1, b2, a1, a2] in Q15.
/// State: state[0..4] = [x1, x2, y1, y2].
#[inline(always)]
fn biquad_process(input: i32, coefs: &[i32; 5], state: &mut [i32; 4]) -> i32 {
    let output = ((coefs[0] * input) >> 15)
        + ((coefs[1] * state[0]) >> 15)
        + ((coefs[2] * state[1]) >> 15)
        - ((coefs[3] * state[2]) >> 15)
        - ((coefs[4] * state[3]) >> 15);

    state[1] = state[0];
    state[0] = input;
    state[3] = state[2];
    state[2] = output;

    output
}

/// Calculate low shelf biquad coefficients.
/// gain: 0-255 (128=0dB), freq: Hz, sample_rate: Hz.
pub fn calc_low_shelf(gain: u8, freq: u32, sample_rate: u32) -> [i32; 5] {
    let gain_offset = gain as i32 - 128;
    let gain_lin = (256 + (gain_offset * 13) / 10).max(1);

    let sr_k = if sample_rate >= 1000 { sample_rate / 1000 } else { 1 };
    let omega = (freq * 205) / sr_k.max(1);
    let omega_clamped = omega.clamp(100, 8000) as i32;

    let (b0, b1) = if gain_lin > 256 {
        let denom = (omega_clamped + (65536 / gain_lin.max(1))).max(1);
        let b0 = (gain_lin * (omega_clamped + 256)) / denom;
        let b1 = ((gain_lin - 256) * omega_clamped) / denom;
        (b0, b1)
    } else if gain_lin < 256 {
        let inv_gain = (65536 / gain_lin.max(1)) as i32;
        let denom = (omega_clamped + inv_gain).max(1);
        let b0 = (256 * (omega_clamped + 256)) / denom;
        let b1 = ((256 - gain_lin) * omega_clamped) / denom;
        (b0, -b1)
    } else {
        (256, 0)
    };

    [
        (b0 * 128).clamp(-65536, 65536),
        (b1 * 128).clamp(-65536, 65536),
        0, 0, 0,
    ]
}

/// Calculate high shelf biquad coefficients.
pub fn calc_high_shelf(gain: u8, freq: u32, sample_rate: u32) -> [i32; 5] {
    let gain_offset = gain as i32 - 128;
    let gain_lin = (256 + (gain_offset * 13) / 10).max(1);

    let sr_k = if sample_rate >= 1000 { sample_rate / 1000 } else { 1 };
    let omega = (freq * 205) / sr_k.max(1);
    let omega_clamped = omega.clamp(100, 8000) as i32;

    let (b0, b1) = if gain_lin > 256 {
        let denom = (omega_clamped + (65536 / gain_lin.max(1))).max(1);
        let b0 = (gain_lin * (omega_clamped + 256)) / denom;
        let b1 = -((gain_lin - 256) * 256) / denom;
        (b0, b1)
    } else if gain_lin < 256 {
        let inv_gain = (65536 / gain_lin.max(1)) as i32;
        let denom = (omega_clamped + inv_gain).max(1);
        let b0 = (256 * (omega_clamped + 256)) / denom;
        let b1 = ((256 - gain_lin) * 256) / denom;
        (b0, b1)
    } else {
        (256, 0)
    };

    [
        (b0 * 128).clamp(-65536, 65536),
        (b1 * 128).clamp(-65536, 65536),
        0, 0, 0,
    ]
}

/// Calculate parametric (peaking) biquad coefficients.
pub fn calc_parametric(gain: u8, freq: u32, q: u8, sample_rate: u32) -> [i32; 5] {
    let gain_offset = gain as i32 - 128;
    let gain_lin = (256 + (gain_offset * 13) / 10).max(1);

    let sr_k = if sample_rate >= 1000 { sample_rate / 1000 } else { 1 };
    let omega = ((freq * 205) / sr_k.max(1)).clamp(100, 16000) as i32;

    let q_factor = ((q as i32 * 30) / 256 + 16).max(1);
    let bandwidth = (omega / q_factor).max(1);

    if gain_lin > 256 {
        let boost = gain_lin - 256;
        let b0 = 32768 + (boost * bandwidth) / 512;
        let b2 = 32768 - (boost * bandwidth) / 512;
        let a2 = -((bandwidth * 128) / (bandwidth + 256).max(1));
        [b0, 0, b2, 0, a2]
    } else if gain_lin < 256 {
        let cut = 256 - gain_lin;
        let b0 = 32768 - (cut * bandwidth) / 512;
        let b2 = 32768 + (cut * bandwidth) / 512;
        let a2 = (bandwidth * 128) / (bandwidth + 256).max(1);
        [b0, 0, b2, 0, a2]
    } else {
        [32768, 0, 32768, 0, 0] // unity
    }
}

#[inline(always)]
pub fn process_eq(sample_l: &mut i32, sample_r: &mut i32, s: &mut EffectsState) {
    let mut sig_l = *sample_l;
    let mut sig_r = *sample_r;

    let mut band = 0;
    while band < NUM_EQ_BANDS {
        sig_l = biquad_process(sig_l, &s.eq_coefs[band], &mut s.eq_state_l[band]);
        sig_r = biquad_process(sig_r, &s.eq_coefs[band], &mut s.eq_state_r[band]);
        band += 1;
    }

    *sample_l = sig_l.clamp(-32768, 32767);
    *sample_r = sig_r.clamp(-32768, 32767);
}
