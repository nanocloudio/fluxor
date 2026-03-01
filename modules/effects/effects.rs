// Built-in effect processing functions.

/// Overdrive with soft clipping
#[inline(always)]
pub fn process_overdrive(sample: i32, gain: u8, tone: u8) -> i32 {
    if gain == 0 { return sample; }

    // Apply gain
    let drive_scale = 256 + (gain as i32) * 4;
    let x = (sample * drive_scale) >> 8;

    // Soft clip
    let x_clamped = x.clamp(-32768, 32767);
    let x_norm = x_clamped as i64;
    let x_cubed = (x_norm * x_norm * x_norm) >> 30;
    let clipped = (x_norm - (x_cubed / 3)) as i32;

    // Tone control (simple lowpass blend)
    let tone_i = tone as i32;
    (clipped * tone_i + sample * (255 - tone_i)) >> 8
}

/// Bitcrush effect
#[inline(always)]
pub fn process_bitcrush(sample: i16, bits: u8) -> i16 {
    if bits >= 16 { return sample; }
    let shift = 16 - bits;
    let mask = !((1i16 << shift) - 1);
    sample & mask
}
