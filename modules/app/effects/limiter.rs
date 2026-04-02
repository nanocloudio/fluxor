// Internal limiter effect.
//
// Prevents signal from exceeding threshold. Hard or soft clip modes.

use super::state::EffectsState;

/// Hard clip to threshold
#[inline(always)]
fn hard_clip(sample: i32, threshold: i32) -> i32 {
    sample.clamp(-threshold, threshold)
}

/// Soft clip using cubic approximation above threshold
#[inline(always)]
fn soft_clip(sample: i32, threshold: i32) -> i32 {
    let abs_s = if sample >= 0 { sample } else { -sample };
    if abs_s <= threshold {
        sample
    } else {
        let max_excess = 32767 - threshold;
        if max_excess <= 0 {
            return if sample > 0 { threshold } else { -threshold };
        }
        let excess = abs_s - threshold;
        let excess_scaled = (excess << 10) / max_excess.max(1);
        let excess_sq = (excess_scaled * excess_scaled) >> 10;
        let excess_cu = (excess_sq * excess_scaled) >> 10;
        let compressed = excess_scaled - (excess_cu / 3);
        let result = threshold + ((compressed * max_excess) >> 10);
        let result = result.min(32767);
        if sample > 0 { result } else { -result }
    }
}

/// Process one stereo sample pair through limiter.
#[inline(always)]
pub fn process_limiter(sample_l: &mut i32, sample_r: &mut i32, s: &mut EffectsState) {
    let threshold = s.limiter_threshold as i32;
    if threshold <= 0 { return; }

    if s.limiter_mode == 1 {
        *sample_l = soft_clip(*sample_l, threshold);
        *sample_r = soft_clip(*sample_r, threshold);
    } else {
        *sample_l = hard_clip(*sample_l, threshold);
        *sample_r = hard_clip(*sample_r, threshold);
    }
}
