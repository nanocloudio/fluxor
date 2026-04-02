// Internal reverb effect (Schroeder-style).
//
// 4 parallel comb filters + 2 series allpass + pre-delay.
// Operates per-sample on EffectsState fields.

use super::constants::*;
use super::state::EffectsState;

#[inline(always)]
const fn comb_offset(n: usize) -> usize {
    match n {
        0 => 0,
        1 => REVERB_COMB_LEN_1,
        2 => REVERB_COMB_LEN_1 + REVERB_COMB_LEN_2,
        3 => REVERB_COMB_LEN_1 + REVERB_COMB_LEN_2 + REVERB_COMB_LEN_3,
        _ => 0,
    }
}

#[inline(always)]
const fn comb_len(n: usize) -> usize {
    match n {
        0 => REVERB_COMB_LEN_1,
        1 => REVERB_COMB_LEN_2,
        2 => REVERB_COMB_LEN_3,
        3 => REVERB_COMB_LEN_4,
        _ => 1,
    }
}

const ALLPASS_BASE: usize =
    REVERB_COMB_LEN_1 + REVERB_COMB_LEN_2 + REVERB_COMB_LEN_3 + REVERB_COMB_LEN_4;

#[inline(always)]
const fn allpass_offset(n: usize) -> usize {
    match n {
        0 => ALLPASS_BASE,
        1 => ALLPASS_BASE + REVERB_ALLPASS_LEN_1,
        _ => ALLPASS_BASE,
    }
}

#[inline(always)]
const fn allpass_len(n: usize) -> usize {
    match n {
        0 => REVERB_ALLPASS_LEN_1,
        1 => REVERB_ALLPASS_LEN_2,
        _ => 1,
    }
}

const PREDELAY_OFFSET: usize = ALLPASS_BASE + REVERB_ALLPASS_LEN_1 + REVERB_ALLPASS_LEN_2;

pub fn process_reverb(sample_l: &mut i32, sample_r: &mut i32, s: &mut EffectsState, mix: u8) {
    unsafe {
        let in_l = *sample_l;
        let in_r = *sample_r;
        let in_mono = (in_l + in_r) >> 1;

        let buf_ptr = s.reverb_buf.as_mut_ptr();
        let decay = s.reverb_decay as i32;
        let damping = s.reverb_damping as i32;
        let mix = mix as i32;
        let dry_mix = 255 - mix;
        let predelay_len = s.reverb_predelay_len as usize;

        // Feedback coefficient: decay=0 -> 128 (0.5), decay=255 -> 243 (0.95)
        let fb_coef = 128 + ((decay * 115) >> 8);

        // Pre-delay
        let pd_idx = s.reverb_predelay_idx as usize;
        let predelayed = *buf_ptr.add(PREDELAY_OFFSET + pd_idx) as i32;
        *buf_ptr.add(PREDELAY_OFFSET + pd_idx) = in_mono.clamp(-32768, 32767) as i16;
        let next_pd = pd_idx + 1;
        s.reverb_predelay_idx = if next_pd >= predelay_len { 0 } else { next_pd as u16 };

        // 4 parallel comb filters
        let mut comb_sum: i32 = 0;
        let mut comb_n = 0;
        while comb_n < 4 {
            let offset = comb_offset(comb_n);
            let len = comb_len(comb_n);
            let idx = s.reverb_comb_idx[comb_n] as usize;

            let delayed = *buf_ptr.add(offset + idx) as i32;

            // Damping: one-pole lowpass on feedback (0=bright, 255=dark)
            let damp_state = if comb_n < 2 { s.reverb_damp_l } else { s.reverb_damp_r };
            let damped = damp_state as i32
                + (((delayed - damp_state as i32) * (256 - damping)) >> 8);
            if comb_n < 2 {
                s.reverb_damp_l = damped.clamp(-32768, 32767) as i16;
            } else {
                s.reverb_damp_r = damped.clamp(-32768, 32767) as i16;
            }

            let feedback = (damped * fb_coef) >> 8;
            let comb_input = predelayed + feedback;
            *buf_ptr.add(offset + idx) = comb_input.clamp(-32768, 32767) as i16;

            comb_sum += delayed;

            let next_idx = idx + 1;
            s.reverb_comb_idx[comb_n] = if next_idx >= len { 0 } else { next_idx as u16 };

            comb_n += 1;
        }

        // Scale comb sum (divide by 4)
        let mut reverb_sig = comb_sum >> 2;

        // 2 series allpass filters
        let mut ap_n = 0;
        while ap_n < 2 {
            let offset = allpass_offset(ap_n);
            let len = allpass_len(ap_n);
            let idx = s.reverb_allpass_idx[ap_n] as usize;

            let delayed = *buf_ptr.add(offset + idx) as i32;
            let ap_coef: i32 = 154; // ~0.6 in Q8

            let output = delayed - ((ap_coef * reverb_sig) >> 8);
            let to_write = reverb_sig + ((ap_coef * delayed) >> 8);

            *buf_ptr.add(offset + idx) = to_write.clamp(-32768, 32767) as i16;
            reverb_sig = output;

            let next_idx = idx + 1;
            s.reverb_allpass_idx[ap_n] = if next_idx >= len { 0 } else { next_idx as u16 };

            ap_n += 1;
        }

        // Dry/wet crossfade
        *sample_l = ((in_l * dry_mix) + (reverb_sig * mix)) >> 8;
        *sample_r = ((in_r * dry_mix) + (reverb_sig * mix)) >> 8;
    }
}
