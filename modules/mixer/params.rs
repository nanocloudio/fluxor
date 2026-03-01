//! TLV parameter parsing for the mixer channel strip.

use super::eq::{self, NUM_BANDS};
use super::{p_u8, p_u16, p_u32};
use super::MixerState;

// TLV tags
const TAG_CORE: u8 = 0x01; // sample_rate:u32, gain_out:u8
const TAG_EQ: u8 = 0x1D; // low_freq:u16, low_gain:u8, mid_freq:u16, mid_gain:u8, mid_q:u8, high_freq:u16, high_gain:u8
const TAG_GAIN: u8 = 0x40; // gain_in:u8, pan:u8
const TAG_END: u8 = 0xFF;

pub unsafe fn apply_params(s: &mut MixerState) {
    let p = s.params.as_ptr();
    let len = s.params_len as usize;

    // Defaults
    s.sample_rate = 44100;
    s.gain_in = 128;
    s.gain_out = 200;
    s.pan = 128;
    s.eq_enabled = 0;

    // Unity EQ coefficients
    let mut b = 0;
    while b < NUM_BANDS {
        s.eq_coefs[b] = [32768, 0, 0, 0, 0];
        s.eq_state_l[b] = [0; 4];
        s.eq_state_r[b] = [0; 4];
        b += 1;
    }

    // Check TLV magic
    if len < 4 || *p != 0xFE || *p.add(1) != 0x01 {
        return;
    }

    let mut offset = 4; // skip magic(1) + version(1) + length(2)
    while offset + 2 <= len {
        let tag = *p.add(offset);
        let entry_len = *p.add(offset + 1) as usize;
        offset += 2;
        if offset + entry_len > len { break; }

        let d = p.add(offset);
        match tag {
            TAG_CORE => {
                let sr = p_u32(d, entry_len, 0, 44100);
                s.sample_rate = if sr > 0 { sr } else { 44100 };
                s.gain_out = p_u8(d, entry_len, 4, 200);
            }
            TAG_GAIN => {
                s.gain_in = p_u8(d, entry_len, 0, 128);
                s.pan = p_u8(d, entry_len, 1, 128);
            }
            TAG_EQ => {
                s.eq_enabled = 1;
                let low_freq = p_u16(d, entry_len, 0, 200).clamp(50, 500) as u32;
                let low_gain = p_u8(d, entry_len, 2, 128);
                let mid_freq = p_u16(d, entry_len, 3, 1000).clamp(200, 5000) as u32;
                let mid_gain = p_u8(d, entry_len, 5, 128);
                let mid_q = p_u8(d, entry_len, 6, 128);
                let high_freq = p_u16(d, entry_len, 7, 4000).clamp(1000, 8000) as u32;
                let high_gain = p_u8(d, entry_len, 9, 128);

                let sr = s.sample_rate;
                s.eq_coefs[0] = eq::calc_low_shelf(low_gain, low_freq, sr);
                s.eq_coefs[1] = eq::calc_parametric(mid_gain, mid_freq, mid_q, sr);
                s.eq_coefs[2] = eq::calc_high_shelf(high_gain, high_freq, sr);
            }
            TAG_END => break,
            _ => {} // skip unknown tags
        }

        offset += entry_len;
    }
}
