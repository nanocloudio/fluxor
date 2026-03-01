// Internal waveshaper effect.
//
// Distortion using transfer function curves. Multiple curve types available.


/// Soft clip (tanh-like: x - x^3/3)
#[inline(always)]
fn shape_soft(x: i32) -> i32 {
    let x = x.clamp(-32767, 32767);
    let x_sq = (x * x) >> 15;
    let x_cu = (x_sq * x) >> 15;
    x - (x_cu / 3)
}

/// Hard clip
#[inline(always)]
fn shape_hard(x: i32) -> i32 {
    x.clamp(-24000, 24000)
}

/// Fold back distortion
#[inline(always)]
fn shape_fold(x: i32) -> i32 {
    let threshold: i32 = 20000;
    let mut y = x;
    if y > threshold { y = threshold - (y - threshold); }
    else if y < -threshold { y = -threshold - (y + threshold); }
    if y > threshold { y = threshold - (y - threshold); }
    else if y < -threshold { y = -threshold - (y + threshold); }
    y
}

/// Asymmetric clipping (tube-like)
#[inline(always)]
fn shape_asymmetric(x: i32) -> i32 {
    if x >= 0 {
        let x = x.min(32767);
        let x_sq = (x * x) >> 15;
        let x_cu = (x_sq * x) >> 15;
        x - (x_cu >> 2)
    } else {
        let x = x.max(-32767);
        let xa = -x;
        let x_sq = (xa * xa) >> 15;
        let x_cu = (x_sq * xa) >> 15;
        -(xa - (x_cu >> 3))
    }
}

/// Half-wave rectify
#[inline(always)]
fn shape_rectify(x: i32) -> i32 {
    if x > 0 { x } else { 0 }
}

/// Apply waveshaping based on curve type
#[inline(always)]
fn apply_shape(x: i32, curve: u8) -> i32 {
    match curve {
        0 => shape_soft(x),
        1 => shape_hard(x),
        2 => shape_fold(x),
        3 => shape_asymmetric(x),
        _ => shape_rectify(x),
    }
}

/// Process one stereo sample pair through waveshaper.
#[inline(always)]
pub fn process_waveshaper(sample_l: &mut i32, sample_r: &mut i32, curve: u8, amount: u8, mix: u8) {
    let amount = amount as i32;
    if amount == 0 { return; }
    let mix = mix as i32;
    if mix == 0 { return; }

    // Drive gain: 1x to 8x based on amount
    let gain = 256 + (amount * 7);
    let driven_l = (*sample_l * gain) >> 8;
    let driven_r = (*sample_r * gain) >> 8;

    let shaped_l = apply_shape(driven_l, curve);
    let shaped_r = apply_shape(driven_r, curve);

    let dry_mix = 255 - mix;
    *sample_l = ((*sample_l * dry_mix) + (shaped_l * mix)) >> 8;
    *sample_r = ((*sample_r * dry_mix) + (shaped_r * mix)) >> 8;
}
