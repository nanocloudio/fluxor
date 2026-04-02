// Internal comb filter effect.
//
// Short delay with high feedback for metallic/hollow tones.
// Uses 8-bit mono buffer for minimal RAM.
// Uses comb_* fields and comb_buf in EffectsState.

use super::constants::*;
use super::state::EffectsState;

#[inline(always)]
pub fn process_comb(sample_l: &mut i32, sample_r: &mut i32, s: &mut EffectsState) {
    // Convert stereo to mono input
    let mono_in = (*sample_l + *sample_r) >> 1;

    let buf_size = COMB_BUF_SIZE as u16;
    let delay = s.comb_delay_samples;
    let feedback = s.comb_feedback as i32;
    let mix = s.comb_mix as i32;

    unsafe {
        let comb_ptr = s.comb_buf.as_mut_ptr();

        // Read from comb buffer (8-bit, scale to 16-bit)
        let read_pos = ((s.comb_write_pos + buf_size - delay) % buf_size) as usize;
        let delayed = (*comb_ptr.add(read_pos) as i32) << 8;

        // Comb filter: output = input + delayed * feedback
        let comb_out = mono_in + ((delayed * feedback) >> 8);

        // Write to comb buffer (convert to 8-bit)
        let write_val = (comb_out >> 8).clamp(-128, 127) as i8;
        *comb_ptr.add(s.comb_write_pos as usize) = write_val;
        s.comb_write_pos = (s.comb_write_pos + 1) % buf_size;

        // Mix dry/wet
        let dry = 256 - mix;
        let mixed = ((mono_in * dry) >> 8) + ((comb_out * mix) >> 8);
        let output = mixed.clamp(-32768, 32767);

        *sample_l = output;
        *sample_r = output;
    }
}
