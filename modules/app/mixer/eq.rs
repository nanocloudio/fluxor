//! 3-band EQ — Q15 biquad (low shelf + parametric mid + high shelf)
//!
//! Ported from synth/eq.rs for standalone use in the mixer channel strip.

pub const NUM_BANDS: usize = 3;

#[inline(always)]
pub fn biquad_process(input: i32, coefs: &[i32; 5], state: &mut [i32; 4]) -> i32 {
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
        [32768, 0, 32768, 0, 0]
    }
}
