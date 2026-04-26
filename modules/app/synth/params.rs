// Parameter parsing and application.
//
// Supports two formats:
// - TLV: params[0] == 0xFE → extensible tag-length-value encoding
// - Legacy: fixed 45-byte blob with hardcoded offsets (backward compat)

use super::constants::*;
use super::params_def;
use super::state::SynthState;
use super::tlv;
use super::{p_u16, p_u32, p_u8};

#[inline(always)]
pub fn ms_to_env_rate(ms: u16, sample_rate: u32) -> u16 {
    if ms == 0 {
        return 65535;
    }
    let sr_k = if sample_rate >= 1000 {
        sample_rate / 1000
    } else {
        1
    };
    let samples = (sr_k * (ms as u32)).max(1);
    (65535u32 / samples).clamp(1, 65535) as u16
}

#[inline(always)]
pub fn freq_to_inc(freq: u16, sample_rate: u32) -> u32 {
    if freq == 0 || sample_rate == 0 {
        return 0;
    }
    // Compute the low 32 bits of `(freq << 32) / sample_rate` without
    // invoking `__aeabi_uldivmod` — PIC modules can't link the 64-bit
    // divide intrinsic. Long division over the 48-bit numerator
    // `(freq << 32)`: 16 high-bit iterations build the remainder out of
    // freq's bits (their quotient bits live above bit 31 and are
    // discarded — matches the original `as u32` truncation when
    // freq ≥ sample_rate), then 32 low-bit iterations process the
    // trailing zeros and accumulate the result.
    let freq_u32 = freq as u32;
    let mut rem = 0u32;
    let mut k = 16i32;
    while k > 0 {
        k -= 1;
        let bit = (freq_u32 >> k) & 1;
        let carry = rem >> 31;
        rem = (rem << 1) | bit;
        if carry != 0 || rem >= sample_rate {
            rem = rem.wrapping_sub(sample_rate);
        }
    }
    let mut quotient = 0u32;
    let mut i = 0;
    while i < 32 {
        let carry = rem >> 31;
        rem <<= 1;
        quotient <<= 1;
        if carry != 0 || rem >= sample_rate {
            rem = rem.wrapping_sub(sample_rate);
            quotient |= 1;
        }
        i += 1;
    }
    quotient
}

/// Apply all parameters from the stored params blob to runtime state.
///
/// Detects TLV vs legacy format and dispatches accordingly.
/// Called from module_new (initial config) and from the ctrl handler
/// (runtime param changes). Does NOT reset runtime state like oscillator
/// phase, filter state, envelope position, or effect buffers.
pub unsafe fn apply_params(s: &mut SynthState) {
    let p = s.params.as_ptr();
    let len = s.params_len as usize;

    if tlv::is_tlv(p, len) {
        params_def::parse_tlv(s, p, len);
    } else {
        apply_legacy_params(s);
    }

    // Propagate envelope rates from template to all voices
    let n = s.poly_count as usize;
    let vp = s.voices.as_mut_ptr();
    let mut i = 0;
    while i < n {
        let v = &mut *vp.add(i);
        v.filter_env.attack_rate = s.filter_env.attack_rate;
        v.filter_env.decay_rate = s.filter_env.decay_rate;
        v.filter_env.sustain_level = s.filter_env.sustain_level;
        v.filter_env.release_rate = s.filter_env.release_rate;
        v.amp_env.attack_rate = s.amp_env.attack_rate;
        v.amp_env.decay_rate = s.amp_env.decay_rate;
        v.amp_env.sustain_level = s.amp_env.sustain_level;
        v.amp_env.release_rate = s.amp_env.release_rate;
        i += 1;
    }
}

/// Legacy fixed-offset parameter parsing (backward compatibility).
unsafe fn apply_legacy_params(s: &mut SynthState) {
    let p = s.params.as_ptr();
    let len = s.params_len as usize;

    // Sample rate
    let sr = p_u32(p, len, 0, 8000);
    let sample_rate = if sr > 0 { sr } else { 8000 };
    s.sample_rate = sample_rate;

    // Oscillator
    s.waveform = p_u8(p, len, 4, WAVE_SAW).min(5);
    s.pulse_width = p_u8(p, len, 5, 128);
    s.sub_level = p_u8(p, len, 6, 0);

    // Filter
    s.cutoff = p_u8(p, len, 8, 200);
    s.resonance = p_u8(p, len, 9, 100);
    s.env_amount = p_u8(p, len, 10, 128);
    s.key_track = p_u8(p, len, 11, 64);

    // Filter envelope (derived: ms -> rate)
    s.filter_env.attack_rate = ms_to_env_rate(p_u16(p, len, 12, 5), sample_rate);
    s.filter_env.decay_rate = ms_to_env_rate(p_u16(p, len, 14, 200), sample_rate);
    s.filter_env.sustain_level = (p_u8(p, len, 16, 50) as u16) << 8;
    s.filter_env.release_rate = ms_to_env_rate(p_u16(p, len, 17, 100), sample_rate);

    // Amp envelope (derived: ms -> rate)
    s.amp_env.attack_rate = ms_to_env_rate(p_u16(p, len, 19, 5), sample_rate);
    s.amp_env.decay_rate = ms_to_env_rate(p_u16(p, len, 21, 200), sample_rate);
    s.amp_env.sustain_level = (p_u8(p, len, 23, 100) as u16) << 8;
    s.amp_env.release_rate = ms_to_env_rate(p_u16(p, len, 24, 100), sample_rate);

    // Performance
    s.accent = p_u8(p, len, 26, 100);
    s.glide_ms = p_u16(p, len, 27, 0);
    s.glide_mode = p_u8(p, len, 29, GLIDE_OFF).min(2);
    s.drive = p_u8(p, len, 30, 0);
    s.level = p_u8(p, len, 31, 200);
}
