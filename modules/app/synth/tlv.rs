// TLV (Tag-Length-Value) parameter parser.
//
// Wire format:
//   Byte 0:   Magic = 0xFE (distinguishes from legacy where byte 0 is low byte of sample_rate)
//   Byte 1:   Version = 0x01
//   Bytes 2-3: Total payload length (u16 LE)
//   Bytes 4+:  TLV entries: [tag: u8, length: u8, value: [u8; length]]

use super::constants::*;
use super::state::SynthState;
use super::{p_u8, p_u16, p_u32};

pub const TLV_MAGIC: u8 = 0xFE;
pub const TLV_VERSION: u8 = 0x01;
pub const TLV_HEADER_SIZE: usize = 4;

// Tag assignments
pub const TAG_CORE: u8 = 0x01;
pub const TAG_OSCILLATOR: u8 = 0x02;
pub const TAG_FILTER: u8 = 0x03;
pub const TAG_FILTER_ENV: u8 = 0x04;
pub const TAG_AMP_ENV: u8 = 0x05;
pub const TAG_PERFORMANCE: u8 = 0x06;
pub const TAG_POLYPHONY: u8 = 0x07;
pub const TAG_VOICE_NAV: u8 = 0x30;
pub const TAG_END: u8 = 0xFF;

/// Check if the params buffer starts with TLV magic.
#[inline(always)]
pub unsafe fn is_tlv(params: *const u8, len: usize) -> bool {
    len >= TLV_HEADER_SIZE && *params == TLV_MAGIC
}

/// Parse TLV params and apply to SynthState.
/// Caller must have already verified is_tlv().
pub unsafe fn parse_tlv(s: &mut SynthState) {
    let p = s.params.as_ptr();
    let len = s.params_len as usize;

    // Set defaults first
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
            TAG_OSCILLATOR => parse_oscillator(s, d, entry_len),
            TAG_FILTER => parse_filter(s, d, entry_len),
            TAG_FILTER_ENV => parse_filter_env(s, d, entry_len),
            TAG_AMP_ENV => parse_amp_env(s, d, entry_len),
            TAG_PERFORMANCE => parse_performance(s, d, entry_len),
            TAG_POLYPHONY => parse_polyphony(s, d, entry_len),
            TAG_VOICE_NAV => parse_voice_nav(s, d, entry_len),
            TAG_END => break,
            _ => {} // skip unknown tags (including FX tags 0x10-0x21)
        }
        offset += entry_len;
    }
}

/// Set all synth params to sensible defaults (called before TLV parsing).
unsafe fn set_defaults(s: &mut SynthState) {
    s.sample_rate = 8000;
    s.waveform = WAVE_SAW;
    s.pulse_width = 128;
    s.sub_level = 0;
    s.cutoff = 200;
    s.resonance = 100;
    s.env_amount = 128;
    s.key_track = 64;

    // Filter envelope defaults
    let sr = 8000u32; // will be overwritten if TAG_CORE present
    s.filter_env.attack_rate = super::params::ms_to_env_rate(5, sr);
    s.filter_env.decay_rate = super::params::ms_to_env_rate(200, sr);
    s.filter_env.sustain_level = 50 << 8;
    s.filter_env.release_rate = super::params::ms_to_env_rate(100, sr);

    // Amp envelope defaults
    s.amp_env.attack_rate = super::params::ms_to_env_rate(5, sr);
    s.amp_env.decay_rate = super::params::ms_to_env_rate(200, sr);
    s.amp_env.sustain_level = 100 << 8;
    s.amp_env.release_rate = super::params::ms_to_env_rate(100, sr);

    s.accent = 100;
    s.glide_ms = 0;
    s.glide_mode = GLIDE_OFF;
    s.drive = 0;
    s.level = 200;

    // Pluck oscillator defaults
    s.pluck_decay = 250;
    s.pluck_brightness = 200;

    // Polyphony defaults (mono)
    s.poly_count = 1;
    s.voice_alloc_counter = 0;
}

// ============================================================================
// Per-tag parsers
// ============================================================================

/// Core: [0-3] sample_rate:u32, [4] level:u8
#[inline(always)]
unsafe fn parse_core(s: &mut SynthState, d: *const u8, len: usize) {
    let sr = p_u32(d, len, 0, 8000);
    s.sample_rate = if sr > 0 { sr } else { 8000 };
    s.level = p_u8(d, len, 4, 200);

    // Recompute envelope rates with actual sample rate
    let sr = s.sample_rate;
    s.filter_env.attack_rate = super::params::ms_to_env_rate(5, sr);
    s.filter_env.decay_rate = super::params::ms_to_env_rate(200, sr);
    s.filter_env.release_rate = super::params::ms_to_env_rate(100, sr);
    s.amp_env.attack_rate = super::params::ms_to_env_rate(5, sr);
    s.amp_env.decay_rate = super::params::ms_to_env_rate(200, sr);
    s.amp_env.release_rate = super::params::ms_to_env_rate(100, sr);
}

/// Oscillator: [0] waveform:u8, [1] pulse_width:u8, [2] sub_level:u8,
///             [3] pluck_decay:u8 (opt), [4] pluck_brightness:u8 (opt)
#[inline(always)]
unsafe fn parse_oscillator(s: &mut SynthState, d: *const u8, len: usize) {
    s.waveform = p_u8(d, len, 0, WAVE_SAW).min(6); // 0-6 including WAVE_PLUCK
    s.pulse_width = p_u8(d, len, 1, 128);
    s.sub_level = p_u8(d, len, 2, 0);
    s.pluck_decay = p_u8(d, len, 3, 250);
    s.pluck_brightness = p_u8(d, len, 4, 200);
}

/// Filter: [0] cutoff:u8, [1] resonance:u8, [2] env_amount:u8, [3] key_track:u8
#[inline(always)]
unsafe fn parse_filter(s: &mut SynthState, d: *const u8, len: usize) {
    s.cutoff = p_u8(d, len, 0, 200);
    s.resonance = p_u8(d, len, 1, 100);
    s.env_amount = p_u8(d, len, 2, 128);
    s.key_track = p_u8(d, len, 3, 64);
}

/// Filter Envelope: [0-1] attack_ms:u16, [2-3] decay_ms:u16, [4] sustain:u8, [5-6] release_ms:u16
#[inline(always)]
unsafe fn parse_filter_env(s: &mut SynthState, d: *const u8, len: usize) {
    let sr = s.sample_rate;
    s.filter_env.attack_rate = super::params::ms_to_env_rate(p_u16(d, len, 0, 5), sr);
    s.filter_env.decay_rate = super::params::ms_to_env_rate(p_u16(d, len, 2, 200), sr);
    s.filter_env.sustain_level = (p_u8(d, len, 4, 50) as u16) << 8;
    s.filter_env.release_rate = super::params::ms_to_env_rate(p_u16(d, len, 5, 100), sr);
}

/// Amp Envelope: [0-1] attack_ms:u16, [2-3] decay_ms:u16, [4] sustain:u8, [5-6] release_ms:u16
#[inline(always)]
unsafe fn parse_amp_env(s: &mut SynthState, d: *const u8, len: usize) {
    let sr = s.sample_rate;
    s.amp_env.attack_rate = super::params::ms_to_env_rate(p_u16(d, len, 0, 5), sr);
    s.amp_env.decay_rate = super::params::ms_to_env_rate(p_u16(d, len, 2, 200), sr);
    s.amp_env.sustain_level = (p_u8(d, len, 4, 100) as u16) << 8;
    s.amp_env.release_rate = super::params::ms_to_env_rate(p_u16(d, len, 5, 100), sr);
}

/// Performance: [0] accent:u8, [1-2] glide_ms:u16, [3] glide_mode:u8, [4] drive:u8
#[inline(always)]
unsafe fn parse_performance(s: &mut SynthState, d: *const u8, len: usize) {
    s.accent = p_u8(d, len, 0, 100);
    s.glide_ms = p_u16(d, len, 1, 0);
    s.glide_mode = p_u8(d, len, 3, GLIDE_OFF).min(2);
    s.drive = p_u8(d, len, 4, 0);
}

/// Polyphony: [0] poly_count:u8
#[inline(always)]
unsafe fn parse_polyphony(s: &mut SynthState, d: *const u8, len: usize) {
    let n = p_u8(d, len, 0, 1);
    s.poly_count = n.clamp(1, MAX_POLY as u8);
}

/// Voice Navigation: [0] voice_count:u8
#[inline(always)]
unsafe fn parse_voice_nav(s: &mut SynthState, d: *const u8, len: usize) {
    let vc = p_u8(d, len, 0, 0);
    s.voice_count = if vc > MAX_VOICES as u8 { MAX_VOICES as u8 } else { vc };
}
