// Internal compressor effect.
//
// Dynamic range compression with threshold, ratio, attack/release,
// makeup gain, and parallel compression (mix).

use super::state::EffectsState;

/// Process one stereo sample pair through compressor.
#[inline(always)]
pub fn process_compressor(sample_l: &mut i32, sample_r: &mut i32, s: &mut EffectsState) {
    let threshold = s.comp_threshold as i32;
    let ratio = s.comp_ratio as i32;
    let attack_coef = s.comp_attack_coef as i32;
    let release_coef = s.comp_release_coef as i32;
    let makeup = s.comp_makeup as i32;
    let mix = s.comp_mix as i32;

    // Peak detection
    let level_l = if *sample_l >= 0 { *sample_l } else { -*sample_l };
    let level_r = if *sample_r >= 0 { *sample_r } else { -*sample_r };
    let peak = (if level_l > level_r { level_l } else { level_r }) as u16;

    // Envelope follower
    let env = s.comp_envelope as i32;
    let peak_i = peak as i32;
    if peak_i > env {
        let delta = ((peak_i - env) * attack_coef) >> 16;
        s.comp_envelope = (env + delta.max(1)) as u16;
    } else {
        let delta = ((env - peak_i) * release_coef) >> 16;
        s.comp_envelope = (env - delta.max(1)).max(0) as u16;
    }

    // Calculate target gain
    let env_level = s.comp_envelope as i32;
    let target_gain = if env_level > threshold && ratio > 1 {
        let over = env_level - threshold;
        let reduced_over = over / ratio.max(1);
        let target_level = threshold + reduced_over;
        ((target_level * 256) / env_level.max(1)) as u16
    } else { 256 };

    // Smooth gain changes
    let current = s.comp_current_gain as i32;
    let target = target_gain as i32;
    if target < current {
        let delta = ((current - target) * attack_coef) >> 16;
        s.comp_current_gain = (current - delta.max(1)).max(1) as u16;
    } else if target > current {
        let delta = ((target - current) * release_coef) >> 16;
        s.comp_current_gain = (current + delta.max(1)).min(512) as u16;
    }

    // Apply gain + makeup
    let gain = s.comp_current_gain as i32;
    let compressed_l = (*sample_l * gain) >> 8;
    let compressed_r = (*sample_r * gain) >> 8;
    let made_up_l = (compressed_l * makeup) >> 7;
    let made_up_r = (compressed_r * makeup) >> 7;

    // Parallel mix
    let dry_mix = 255 - mix;
    *sample_l = ((*sample_l * dry_mix) + (made_up_l * mix)) >> 8;
    *sample_r = ((*sample_r * dry_mix) + (made_up_r * mix)) >> 8;
}
