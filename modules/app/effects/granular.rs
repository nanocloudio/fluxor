// Internal granular processing effect.
//
// Multiple overlapping grains read from a circular buffer with
// envelope windowing and optional pitch/position randomness.

use super::constants::*;
use super::state::EffectsState;

/// Simple LFSR random number generator.
#[inline(always)]
fn lfsr_next(lfsr: &mut u16) -> u16 {
    let bit = ((*lfsr >> 0) ^ (*lfsr >> 2) ^ (*lfsr >> 3) ^ (*lfsr >> 5)) & 1;
    *lfsr = (*lfsr >> 1) | (bit << 15);
    *lfsr
}

/// Hann window envelope approximation (parabolic, output 0-255).
#[inline(always)]
fn grain_envelope(pos: u16, len: u16) -> u16 {
    if len == 0 {
        return 0;
    }
    // Normalize position to 0-255
    let norm_pos = ((pos as u32 * 256) / len.max(1) as u32) as u32;
    let x = if norm_pos < 128 { norm_pos } else { 256 - norm_pos };
    // Parabola: x * (128 - x) / 16, max ~256 at x=64
    let y = if x <= 128 { (x * (128 - x)) >> 4 } else { 0 };
    y.min(255) as u16
}

pub fn process_granular(sample_l: &mut i32, sample_r: &mut i32, s: &mut EffectsState, mix: u8) {
    unsafe {
        let in_l = *sample_l;
        let in_r = *sample_r;
        let in_mono = ((in_l + in_r) >> 1) as i16;
        let mix_i = mix as i32;
        let dry_mix = 255 - mix_i;
        let grain_size = s.granular_grain_size;
        let spread = s.granular_spread as u32;
        let buf_size = GRAIN_BUF_SIZE as u16;

        // Write to circular buffer
        let write_pos = s.granular_write_pos as usize;
        let buf_ptr = s.granular_buf.as_mut_ptr();
        *buf_ptr.add(write_pos) = in_mono;
        let next_wp = s.granular_write_pos + 1;
        s.granular_write_pos = if next_wp >= buf_size { 0 } else { next_wp };

        // Check if we should trigger a new grain
        s.granular_trigger_counter += 1;
        if s.granular_trigger_counter >= s.granular_trigger_interval {
            s.granular_trigger_counter = 0;

            let grain_idx = s.granular_next_grain as usize;
            let next = s.granular_next_grain + 1;
            s.granular_next_grain = if next >= MAX_GRAINS as u8 { 0 } else { next };

            // Calculate start position with random spread
            let rand_val = lfsr_next(&mut s.granular_lfsr);
            let spread_samples = ((spread * grain_size as u32) >> 8) as u16;
            let rand_offset = if spread_samples > 1 {
                (rand_val % spread_samples.max(1)) as i32 - (spread_samples as i32 / 2)
            } else {
                0
            };

            // Start position: write_pos minus grain_size plus random offset
            let base_start = if s.granular_write_pos >= grain_size {
                s.granular_write_pos - grain_size
            } else {
                buf_size - (grain_size - s.granular_write_pos)
            };

            let raw = (base_start as i32 + rand_offset + buf_size as i32) as u32;
            let start = (raw % GRAIN_BUF_SIZE as u32) as u16;

            if grain_idx < MAX_GRAINS {
                s.grain_active[grain_idx] = 1;
                s.grain_start_pos[grain_idx] = start;
                s.grain_read_pos[grain_idx] = (start as u32) << 16;
                s.grain_read_inc[grain_idx] = s.granular_pitch_inc;
                s.grain_env_pos[grain_idx] = 0;
                s.grain_len[grain_idx] = grain_size;
            }
        }

        // Process all active grains
        let mut grain_sum: i32 = 0;
        let mut active_count: i32 = 0;
        let grain_buf_ptr = s.granular_buf.as_ptr();

        let mut g = 0;
        while g < MAX_GRAINS {
            if s.grain_active[g] != 0 {
                let env = grain_envelope(s.grain_env_pos[g], s.grain_len[g]) as i32;

                // Read with interpolation
                let read_idx = (s.grain_read_pos[g] >> 16) as usize;
                let frac = (s.grain_read_pos[g] & 0xFFFF) as i32;
                let idx0 = if read_idx >= GRAIN_BUF_SIZE {
                    read_idx - GRAIN_BUF_SIZE
                } else {
                    read_idx
                };
                let idx1 = if idx0 + 1 >= GRAIN_BUF_SIZE { 0 } else { idx0 + 1 };

                let s0 = *grain_buf_ptr.add(idx0) as i32;
                let s1 = *grain_buf_ptr.add(idx1) as i32;
                let sample = s0 + (((s1 - s0) * frac) >> 16);

                grain_sum += (sample * env) >> 8;
                active_count += 1;

                // Advance grain
                s.grain_read_pos[g] = s.grain_read_pos[g].wrapping_add(s.grain_read_inc[g]);
                s.grain_env_pos[g] += 1;

                if s.grain_env_pos[g] >= s.grain_len[g] {
                    s.grain_active[g] = 0;
                }
            }
            g += 1;
        }

        // Normalize by active grain count
        let wet = if active_count > 1 {
            grain_sum / active_count.max(1)
        } else {
            grain_sum
        };

        // Mix dry and wet
        *sample_l = ((in_l * dry_mix) + (wet * mix_i)) >> 8;
        *sample_r = ((in_r * dry_mix) + (wet * mix_i)) >> 8;
    }
}
