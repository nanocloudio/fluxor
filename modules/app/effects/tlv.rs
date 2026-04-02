// TLV (Tag-Length-Value) parameter parser for effects module.
//
// Wire format: same as synth TLV.
// Presence of an FX tag implicitly enables that effect.

use super::constants::*;
use super::state::EffectsState;
use super::{p_u8, p_u16, p_u32};

pub const TLV_MAGIC: u8 = 0xFE;
pub const TLV_VERSION: u8 = 0x01;
pub const TLV_HEADER_SIZE: usize = 4;

// Tag assignments (effects only)
pub const TAG_CORE: u8 = 0x01;
pub const TAG_CHORUS: u8 = 0x10;
pub const TAG_DELAY: u8 = 0x11;
pub const TAG_OVERDRIVE: u8 = 0x12;
pub const TAG_BITCRUSH: u8 = 0x13;
pub const TAG_REVERB: u8 = 0x14;
pub const TAG_PHASER: u8 = 0x15;
pub const TAG_FLANGER: u8 = 0x16;
pub const TAG_TREMOLO: u8 = 0x17;
pub const TAG_RING_MOD: u8 = 0x18;
pub const TAG_WAVESHAPER: u8 = 0x19;
pub const TAG_COMPRESSOR: u8 = 0x1A;
pub const TAG_LIMITER: u8 = 0x1B;
pub const TAG_GATE: u8 = 0x1C;
pub const TAG_EQ: u8 = 0x1D;
pub const TAG_GRANULAR: u8 = 0x1E;
pub const TAG_PITCH_SHIFT: u8 = 0x1F;
pub const TAG_HARMONIZER: u8 = 0x20;
pub const TAG_COMB: u8 = 0x21;
pub const TAG_END: u8 = 0xFF;

#[inline(always)]
pub unsafe fn is_tlv(params: *const u8, len: usize) -> bool {
    len >= TLV_HEADER_SIZE && *params == TLV_MAGIC
}

pub unsafe fn parse_tlv(s: &mut EffectsState) {
    let p = s.params.as_ptr();
    let len = s.params_len as usize;

    set_defaults(s);

    if len < TLV_HEADER_SIZE { return; }

    let _version = *p.add(1);
    let total_len = u16::from_le_bytes([*p.add(2), *p.add(3)]) as usize;
    let end = TLV_HEADER_SIZE + total_len;
    let end = if end > len { len } else { end };

    let mut offset = TLV_HEADER_SIZE;
    while offset + 2 <= end {
        let tag = *p.add(offset);
        let entry_len = *p.add(offset + 1) as usize;
        offset += 2;
        if offset + entry_len > end { break; }

        let d = p.add(offset);
        match tag {
            TAG_CORE => parse_core(s, d, entry_len),
            TAG_CHORUS => { s.fx_enable |= FX_CHORUS; parse_chorus(s, d, entry_len); }
            TAG_DELAY => { s.fx_enable |= FX_DELAY; parse_delay(s, d, entry_len); }
            TAG_OVERDRIVE => { s.fx_enable |= FX_OVERDRIVE; parse_overdrive(s, d, entry_len); }
            TAG_BITCRUSH => { s.fx_enable |= FX_BITCRUSH; parse_bitcrush(s, d, entry_len); }
            TAG_TREMOLO => { s.fx_enable |= FX_TREMOLO; parse_tremolo(s, d, entry_len); }
            TAG_RING_MOD => { s.fx_enable |= FX_RING_MOD; parse_ring_mod(s, d, entry_len); }
            TAG_WAVESHAPER => { s.fx_enable |= FX_WAVESHAPER; parse_waveshaper(s, d, entry_len); }
            TAG_COMPRESSOR => { s.fx_enable |= FX_COMPRESSOR; parse_compressor(s, d, entry_len); }
            TAG_LIMITER => { s.fx_enable |= FX_LIMITER; parse_limiter(s, d, entry_len); }
            TAG_GATE => { s.fx_enable |= FX_GATE; parse_gate(s, d, entry_len); }
            TAG_PHASER => { s.fx_enable |= FX_PHASER; parse_phaser(s, d, entry_len); }
            TAG_EQ => { s.fx_enable |= FX_EQ; parse_eq(s, d, entry_len); }
            TAG_FLANGER => { s.fx_enable |= FX_FLANGER; parse_flanger(s, d, entry_len); }
            TAG_COMB => { s.fx_enable |= FX_COMB; parse_comb(s, d, entry_len); }
            TAG_REVERB => { s.fx_enable |= FX_REVERB; parse_reverb(s, d, entry_len); }
            TAG_PITCH_SHIFT => { s.fx_enable |= FX_PITCH_SHIFT; parse_pitch_shift(s, d, entry_len); }
            TAG_HARMONIZER => { s.fx_enable |= FX_HARMONIZER; parse_harmonizer(s, d, entry_len); }
            TAG_GRANULAR => { s.fx_enable |= FX_GRANULAR; parse_granular(s, d, entry_len); }
            TAG_END => break,
            _ => {}
        }
        offset += entry_len;
    }

    derive_chorus(s);
    derive_delay(s);
}

pub unsafe fn set_defaults(s: &mut EffectsState) {
    s.sample_rate = 8000;
    s.fx_enable = 0;
    s.macro1_depth = 0;
    s.macro2_depth = 0;
    s.fx_lfo_depth = 0;
    s.fx_lfo_shape = 0;
    s.fx_lfo_target = 0;
    s.fx_lfo_rate = 0;
    s.fx_lfo_phase = 0;
    s.fx_lfo_inc = 0;
    s.fx_lfo_lfsr = 0xBEEF_CAFE;
    s.fx_lfo_sh_value = 0;
    s.duck_target = 0;
    s.duck_amount = 0;
    let sr_k = if s.sample_rate >= 1000 { s.sample_rate / 1000 } else { 1 };
    let samples = (200 * sr_k).saturating_add(1);
    s.duck_release_coef = (65536u32 / samples).min(65535) as u16;
    s.duck_env = 0;

    s.chorus_mix = 128;
    s.chorus_base_delay = 0;
    s.chorus_mod_depth = 0;
    s.chorus_lfo_inc = 0;
    s.delay_frames = 1;
    s.delay_feedback = 128;
    s.delay_mix = 128;
    s.delay_filter_coef = 200;
    s.bitcrush_bits = 16;
    s.bitcrush_rate_div = 1;
    s.overdrive_gain = 0;
    s.overdrive_tone = 200;

    s.tremolo_lfo_phase = 0;
    s.tremolo_lfo_inc = 0;
    s.tremolo_depth = 0;
    s.tremolo_shape = 0;

    s.ringmod_carrier_phase = 0;
    s.ringmod_carrier_inc = 0;
    s.ringmod_mix = 0;

    s.waveshaper_curve = 0;
    s.waveshaper_amount = 0;
    s.waveshaper_mix = 0;

    s.limiter_threshold = 32000;
    s.limiter_mode = 0;

    s.gate_threshold = 0;
    s.gate_attack_coef = 0;
    s.gate_release_coef = 0;
    s.gate_hold_samples = 0;
    s.gate_state = GATE_CLOSED;
    s.gate_range = 80;
    s.gate_gain = 0;
    s.gate_env_level = 0;
    s.gate_hold_counter = 0;

    s.comp_threshold = 0;
    s.comp_ratio = 4;
    s.comp_makeup = 128;
    s.comp_mix = 255;
    s.comp_attack_coef = 0;
    s.comp_release_coef = 0;
    s.comp_current_gain = 256;
    s.comp_envelope = 0;

    s.phaser_lfo_phase = 0;
    s.phaser_lfo_inc = 0;
    s.phaser_depth = 0;
    s.phaser_feedback = 0;
    s.phaser_stages = 4;
    s.phaser_mix = 0;
    s.phaser_feedback_l = 0;
    s.phaser_feedback_r = 0;

    s.eq_low_freq_raw = 200;
    s.eq_low_gain_raw = 128;
    s.eq_mid_freq_raw = 1000;
    s.eq_mid_gain_raw = 128;
    s.eq_mid_q_raw = 128;
    s.eq_high_freq_raw = 4000;
    s.eq_high_gain_raw = 128;

    let mut b = 0;
    while b < NUM_EQ_BANDS {
        s.eq_coefs[b] = [32768, 0, 0, 0, 0];
        s.eq_state_l[b] = [0; 4];
        s.eq_state_r[b] = [0; 4];
        b += 1;
    }

    s.flanger_lfo_phase = 0;
    s.flanger_lfo_inc = 0;
    s.flanger_depth = 0;
    s.flanger_feedback = 0;
    s.flanger_manual = 128;
    s.flanger_mix = 0;
    s.flanger_write_idx = 0;
    s.flanger_feedback_l = 0;
    s.flanger_feedback_r = 0;

    s.comb_delay_samples = 80;
    s.comb_feedback = 0;
    s.comb_mix = 0;
    s.comb_write_pos = 0;

    s.reverb_decay = 180;
    s.reverb_damping = 100;
    s.reverb_mix = 0;
    s.reverb_predelay_len = 1;
    s.reverb_predelay_idx = 0;
    s.reverb_comb_idx = [0; 4];
    s.reverb_allpass_idx = [0; 2];
    s.reverb_damp_l = 0;
    s.reverb_damp_r = 0;

    s.ps_read_inc = 65536;
    s.ps_window_size = 200;
    s.ps_mix = 0;
    s.ps_direction = 0;
    s.ps_write_pos = 0;
    s.ps_xfade_pos = 0;
    s.ps_read_pos_a = 0;
    s.ps_read_pos_b = (100u32) << 16;
    s.ps_active_reader = 0;

    s.harm_v1_read_inc = 65536;
    s.harm_v1_level = 0;
    s.harm_v1_active = 0;
    s.harm_v1_active_reader = 0;
    s.harm_v1_read_pos_a = 0;
    s.harm_v1_read_pos_b = (HARM_WINDOW_SIZE as u32 / 2) << 16;
    s.harm_v1_xfade_pos = 0;
    s.harm_v2_read_inc = 65536;
    s.harm_v2_level = 0;
    s.harm_v2_active = 0;
    s.harm_v2_active_reader = 0;
    s.harm_v2_read_pos_a = (HARM_WINDOW_SIZE as u32 / 4) << 16;
    s.harm_v2_read_pos_b = ((HARM_WINDOW_SIZE as u32 * 3) / 4) << 16;
    s.harm_v2_xfade_pos = 0;
    s.harm_dry_level = 255;
    s.harm_write_pos = 0;

    s.granular_grain_size = 400;
    s.granular_trigger_interval = 100;
    s.granular_trigger_counter = 0;
    s.granular_next_grain = 0;
    s.granular_spread = 0;
    s.granular_pitch_inc = 65536;
    s.granular_mix = 0;
    s.granular_write_pos = 0;
    s.granular_lfsr = 0xACE1;
    {
        let mut g = 0;
        while g < MAX_GRAINS {
            s.grain_active[g] = 0;
            s.grain_read_pos[g] = 0;
            s.grain_read_inc[g] = 65536;
            s.grain_env_pos[g] = 0;
            s.grain_len[g] = 400;
            s.grain_start_pos[g] = 0;
            g += 1;
        }
    }
}

// ============================================================================
// Per-tag parsers
// ============================================================================

#[inline(always)]
unsafe fn parse_core(s: &mut EffectsState, d: *const u8, len: usize) {
    let sr = p_u32(d, len, 0, 8000);
    s.sample_rate = if sr > 0 { sr } else { 8000 };
}

#[inline(always)]
unsafe fn parse_chorus(s: &mut EffectsState, d: *const u8, len: usize) {
    s.chorus_mod_depth = p_u8(d, len, 0, 5) as u16;
    s.chorus_base_delay = p_u8(d, len, 1, 100) as u16;
    s.chorus_mix = p_u8(d, len, 2, 128);
}

#[inline(always)]
unsafe fn parse_delay(s: &mut EffectsState, d: *const u8, len: usize) {
    s.delay_frames = p_u16(d, len, 0, 50);
    s.delay_feedback = p_u8(d, len, 2, 128);
    s.delay_mix = p_u8(d, len, 3, 128);
    s.delay_filter_coef = p_u8(d, len, 4, 200);
}

#[inline(always)]
unsafe fn parse_overdrive(s: &mut EffectsState, d: *const u8, len: usize) {
    s.overdrive_gain = p_u8(d, len, 0, 0);
    s.overdrive_tone = p_u8(d, len, 1, 200);
}

#[inline(always)]
unsafe fn parse_bitcrush(s: &mut EffectsState, d: *const u8, len: usize) {
    s.bitcrush_bits = p_u8(d, len, 0, 16);
    s.bitcrush_rate_div = p_u8(d, len, 1, 1).max(1);
}

#[inline(always)]
unsafe fn parse_tremolo(s: &mut EffectsState, d: *const u8, len: usize) {
    let rate_mhz = p_u32(d, len, 0, 5000);
    s.tremolo_depth = p_u8(d, len, 4, 180);
    s.tremolo_shape = p_u8(d, len, 5, 0).min(2);
    let sr_k = if s.sample_rate >= 1000 { s.sample_rate / 1000 } else { 1 };
    s.tremolo_lfo_inc = (rate_mhz * 4295) / sr_k.max(1);
}

#[inline(always)]
unsafe fn parse_ring_mod(s: &mut EffectsState, d: *const u8, len: usize) {
    let freq = p_u16(d, len, 0, 200) as u32;
    s.ringmod_mix = p_u8(d, len, 2, 200);
    let sr_256 = if s.sample_rate >= 256 { s.sample_rate / 256 } else { 1 };
    s.ringmod_carrier_inc = (freq * 16777216) / sr_256.max(1);
}

#[inline(always)]
unsafe fn parse_waveshaper(s: &mut EffectsState, d: *const u8, len: usize) {
    s.waveshaper_curve = p_u8(d, len, 0, 0).min(4);
    s.waveshaper_amount = p_u8(d, len, 1, 128);
    s.waveshaper_mix = p_u8(d, len, 2, 200);
}

#[inline(always)]
unsafe fn parse_compressor(s: &mut EffectsState, d: *const u8, len: usize) {
    let threshold_raw = p_u8(d, len, 0, 180);
    s.comp_threshold = (threshold_raw as u16) * 128;
    let ratio = p_u8(d, len, 1, 4);
    s.comp_ratio = if ratio >= 1 && ratio <= 16 { ratio } else { 4 };
    let attack_ms = p_u16(d, len, 2, 10).min(500);
    let release_ms = p_u16(d, len, 4, 100).min(2000);
    s.comp_makeup = p_u8(d, len, 6, 128);
    s.comp_mix = p_u8(d, len, 7, 255);
    let sr_k = if s.sample_rate >= 1000 { s.sample_rate / 1000 } else { 1 };
    let attack_samples = sr_k * (attack_ms as u32);
    s.comp_attack_coef = (65536u32 / attack_samples.max(1)).clamp(1, 65535) as u16;
    let release_samples = sr_k * (release_ms as u32);
    s.comp_release_coef = (65536u32 / release_samples.max(1)).clamp(1, 65535) as u16;
    s.comp_current_gain = 256;
    s.comp_envelope = 0;
}

#[inline(always)]
unsafe fn parse_limiter(s: &mut EffectsState, d: *const u8, len: usize) {
    let thresh_raw = p_u8(d, len, 0, 250) as u16;
    s.limiter_threshold = (thresh_raw * 128).min(32767) as i16;
    s.limiter_mode = p_u8(d, len, 1, 0).min(1);
}

#[inline(always)]
unsafe fn parse_gate(s: &mut EffectsState, d: *const u8, len: usize) {
    let threshold_raw = p_u8(d, len, 0, 30);
    s.gate_threshold = (threshold_raw as u16) * 128;
    let attack_ms = p_u16(d, len, 1, 1) as u32;
    let release_ms = p_u16(d, len, 3, 100) as u32;
    let sr_k = if s.sample_rate >= 1000 { s.sample_rate / 1000 } else { 1 };
    let attack_samples = (attack_ms * sr_k).saturating_add(1);
    s.gate_attack_coef = (65536u32 / attack_samples).min(65535) as u16;
    let release_samples = (release_ms * sr_k).saturating_add(1);
    s.gate_release_coef = (65536u32 / release_samples).min(65535) as u16;
    s.gate_hold_samples = (50 * sr_k).min(65535) as u16;
    s.gate_range = 80;
    s.gate_state = GATE_CLOSED;
    s.gate_gain = 0;
    s.gate_env_level = 0;
    s.gate_hold_counter = 0;
}

#[inline(always)]
unsafe fn parse_phaser(s: &mut EffectsState, d: *const u8, len: usize) {
    let rate_mhz = p_u32(d, len, 0, 1000);
    s.phaser_depth = p_u8(d, len, 4, 200);
    s.phaser_feedback = p_u8(d, len, 5, 100);
    let stages = p_u8(d, len, 6, 4);
    s.phaser_stages = stages.clamp(2, MAX_PHASER_STAGES as u8);
    s.phaser_mix = p_u8(d, len, 7, 128);
    let sr_k = if s.sample_rate >= 1000 { s.sample_rate / 1000 } else { 1 };
    s.phaser_lfo_inc = (rate_mhz * 4295) / sr_k.max(1);
    let mut i = 0;
    while i < MAX_PHASER_STAGES {
        s.phaser_allpass_l[i] = 0;
        s.phaser_allpass_r[i] = 0;
        i += 1;
    }
    s.phaser_feedback_l = 0;
    s.phaser_feedback_r = 0;
}

#[inline(always)]
unsafe fn parse_eq(s: &mut EffectsState, d: *const u8, len: usize) {
    let low_freq = p_u16(d, len, 0, 200).clamp(50, 500) as u32;
    let low_gain = p_u8(d, len, 2, 128);
    let mid_freq = p_u16(d, len, 3, 1000).clamp(200, 5000) as u32;
    let mid_gain = p_u8(d, len, 5, 128);
    let mid_q = p_u8(d, len, 6, 128);
    let high_freq = p_u16(d, len, 7, 4000).clamp(1000, 8000) as u32;
    let high_gain = p_u8(d, len, 9, 128);

    let sr = s.sample_rate;
    s.eq_coefs[0] = super::eq::calc_low_shelf(low_gain, low_freq, sr);
    s.eq_coefs[1] = super::eq::calc_parametric(mid_gain, mid_freq, mid_q, sr);
    s.eq_coefs[2] = super::eq::calc_high_shelf(high_gain, high_freq, sr);
    let mut b = 0;
    while b < NUM_EQ_BANDS {
        s.eq_state_l[b] = [0; 4];
        s.eq_state_r[b] = [0; 4];
        b += 1;
    }
}

#[inline(always)]
unsafe fn parse_flanger(s: &mut EffectsState, d: *const u8, len: usize) {
    let rate_mhz = p_u32(d, len, 0, 500);
    s.flanger_depth = p_u8(d, len, 4, 200);
    s.flanger_feedback = p_u8(d, len, 5, 100);
    s.flanger_manual = p_u8(d, len, 6, 128);
    s.flanger_mix = p_u8(d, len, 7, 128);
    let sr_k = if s.sample_rate >= 1000 { s.sample_rate / 1000 } else { 1 };
    s.flanger_lfo_inc = (rate_mhz * 4295) / sr_k.max(1);
}

#[inline(always)]
unsafe fn parse_comb(s: &mut EffectsState, d: *const u8, len: usize) {
    let delay_ms = p_u16(d, len, 0, 10).clamp(1, 50) as u32;
    s.comb_feedback = p_u8(d, len, 2, 200);
    s.comb_mix = p_u8(d, len, 3, 128);
    let delay_samples = (8 * delay_ms) as u16;
    s.comb_delay_samples = if delay_samples > 0 && (delay_samples as usize) < COMB_BUF_SIZE {
        delay_samples
    } else {
        80
    };
}

#[inline(always)]
unsafe fn parse_reverb(s: &mut EffectsState, d: *const u8, len: usize) {
    s.reverb_decay = p_u8(d, len, 0, 180);
    s.reverb_damping = p_u8(d, len, 1, 100);
    let predelay_ms = p_u16(d, len, 2, 10).min(50) as u32;
    s.reverb_mix = p_u8(d, len, 4, 80);
    let sr_k = if s.sample_rate >= 1000 { s.sample_rate / 1000 } else { 1 };
    let predelay_samples = (predelay_ms * sr_k) as usize;
    s.reverb_predelay_len = if predelay_samples > REVERB_PREDELAY_MAX {
        REVERB_PREDELAY_MAX as u16
    } else if predelay_samples < 1 {
        1
    } else {
        predelay_samples as u16
    };
    s.reverb_comb_idx = [0; 4];
    s.reverb_allpass_idx = [0; 2];
    s.reverb_predelay_idx = 0;
    s.reverb_damp_l = 0;
    s.reverb_damp_r = 0;
}

#[inline(always)]
unsafe fn parse_pitch_shift(s: &mut EffectsState, d: *const u8, len: usize) {
    let semitones_raw = p_u8(d, len, 0, 128) as i16 - 128;
    let semitones = semitones_raw.clamp(-12, 12) as i8;
    s.ps_read_inc = super::pitch_shift::semitones_to_inc(semitones);
    s.ps_direction = if semitones > 0 { 1 } else if semitones < 0 { -1 } else { 0 };

    let window_ms = p_u8(d, len, 1, 30).clamp(10, 100) as u32;
    let sr_k = if s.sample_rate >= 1000 { s.sample_rate / 1000 } else { 1 };
    s.ps_window_size = ((window_ms * sr_k) as u16).min(PITCH_BUF_SIZE as u16 / 2);

    s.ps_mix = p_u8(d, len, 2, 255);

    s.ps_write_pos = 0;
    s.ps_read_pos_a = 0;
    s.ps_read_pos_b = (s.ps_window_size as u32 / 2) << 16;
    s.ps_xfade_pos = 0;
    s.ps_active_reader = 0;
}

#[inline(always)]
unsafe fn parse_harmonizer(s: &mut EffectsState, d: *const u8, len: usize) {
    let v1_semi_raw = p_u8(d, len, 0, 135) as i16 - 128;
    let v1_semi = v1_semi_raw.clamp(-12, 12) as i8;
    let v1_level = p_u8(d, len, 1, 200);
    s.harm_v1_read_inc = super::pitch_shift::semitones_to_inc(v1_semi);
    s.harm_v1_level = v1_level;
    s.harm_v1_active = if v1_level > 0 && v1_semi != 0 { 1 } else { 0 };
    s.harm_v1_active_reader = 0;
    s.harm_v1_read_pos_a = 0;
    s.harm_v1_read_pos_b = (HARM_WINDOW_SIZE as u32 / 2) << 16;
    s.harm_v1_xfade_pos = 0;

    let v2_semi_raw = p_u8(d, len, 2, 128) as i16 - 128;
    let v2_semi = v2_semi_raw.clamp(-12, 12) as i8;
    let v2_level = p_u8(d, len, 3, 0);
    s.harm_v2_read_inc = super::pitch_shift::semitones_to_inc(v2_semi);
    s.harm_v2_level = v2_level;
    s.harm_v2_active = if v2_level > 0 && v2_semi != 0 { 1 } else { 0 };
    s.harm_v2_active_reader = 0;
    s.harm_v2_read_pos_a = (HARM_WINDOW_SIZE as u32 / 4) << 16;
    s.harm_v2_read_pos_b = ((HARM_WINDOW_SIZE as u32 * 3) / 4) << 16;
    s.harm_v2_xfade_pos = 0;

    s.harm_dry_level = p_u8(d, len, 4, 255);
    s.harm_write_pos = 0;
}

#[inline(always)]
unsafe fn parse_granular(s: &mut EffectsState, d: *const u8, len: usize) {
    let grain_size_ms = p_u8(d, len, 0, 50).clamp(10, 200) as u32;
    let density = p_u8(d, len, 1, 4).clamp(1, 8);
    let pitch = p_u8(d, len, 2, 128);
    s.granular_spread = p_u8(d, len, 3, 50);
    s.granular_mix = p_u8(d, len, 4, 180);

    let sr_k = if s.sample_rate >= 1000 { s.sample_rate / 1000 } else { 1 };
    let grain_samples = (grain_size_ms * sr_k) as u16;
    s.granular_grain_size = grain_samples.min(GRAIN_BUF_SIZE as u16 - 1);

    let interval = s.granular_grain_size / density.max(1) as u16;
    s.granular_trigger_interval = interval.max(1);
    s.granular_trigger_counter = 0;
    s.granular_next_grain = 0;

    s.granular_pitch_inc = if pitch >= 128 {
        65536 + ((pitch as u32 - 128) * 512)
    } else {
        32768 + ((pitch as u32) * 256)
    };

    s.granular_write_pos = 0;
    s.granular_lfsr = 0xACE1;

    let mut g = 0;
    while g < MAX_GRAINS {
        s.grain_active[g] = 0;
        s.grain_read_pos[g] = 0;
        s.grain_read_inc[g] = 65536;
        s.grain_env_pos[g] = 0;
        s.grain_len[g] = s.granular_grain_size;
        s.grain_start_pos[g] = 0;
        g += 1;
    }
}

// ============================================================================
// Derived value computation
// ============================================================================

pub unsafe fn derive_chorus(s: &mut EffectsState) {
    if (s.fx_enable & FX_CHORUS) == 0 { return; }
    let sr_k = s.sample_rate / 1000;
    let chorus_depth = s.chorus_mod_depth as u8;
    let chorus_rate = s.chorus_base_delay as u8;
    s.chorus_base_delay = (sr_k * 10) as u16;
    s.chorus_mod_depth = ((chorus_depth as u32 * sr_k) / 1000 * 8) as u16;
    let rate_mhz = 100 + (chorus_rate as u32) * 19;
    s.chorus_lfo_inc = (rate_mhz * 4295) / sr_k.max(1);
}

pub unsafe fn derive_delay(s: &mut EffectsState) {
    if (s.fx_enable & FX_DELAY) == 0 { return; }
    let sr_k = s.sample_rate / 1000; // samples per ms
    let delay_ms = s.delay_frames as u32;
    let delay_frames = delay_ms * sr_k;
    s.delay_frames = delay_frames.min((DELAY_BUF_FRAMES - 1) as u32).max(1) as u16;
}
