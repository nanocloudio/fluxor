// Synth parameter definitions (single source of truth).
//
// Generates: dispatch_param(), set_defaults(), parse_tlv_v2(), PARAM_SCHEMA.
// The schema is embedded in the .fmod via #[link_section = ".param_schema"].
//
// IMPORTANT: sample_rate must be first — its apply closure recomputes
// envelope rate defaults with the actual SR. Subsequent envelope tags
// (if present) override with user values using the correct SR.

use super::constants::*;
use super::state::SynthState;
use super::{p_u8, p_u16, p_u32};
use super::params::ms_to_env_rate;
use super::SCHEMA_MAX;

define_params! {
    SynthState;

    // --- Core ---
    1, sample_rate, u32, 8000
        => |s, d, len| {
            let sr = p_u32(d, len, 0, 8000);
            s.sample_rate = if sr > 0 { sr } else { 8000 };
            // Recompute envelope rate defaults with actual sample rate.
            // Any subsequent envelope tags will overwrite with correct values.
            let sr = s.sample_rate;
            s.filter_env.attack_rate = ms_to_env_rate(5, sr);
            s.filter_env.decay_rate = ms_to_env_rate(200, sr);
            s.filter_env.release_rate = ms_to_env_rate(100, sr);
            s.amp_env.attack_rate = ms_to_env_rate(5, sr);
            s.amp_env.decay_rate = ms_to_env_rate(200, sr);
            s.amp_env.release_rate = ms_to_env_rate(100, sr);
        };

    2, level, u8, 200
        => |s, d, len| { s.level = p_u8(d, len, 0, 200); };

    // --- Oscillator ---
    3, waveform, u8, 0, enum { saw=0, sawtooth=0, square=1, triangle=2, tri=2, pulse=3, noise=4, sine=5, sin=5, pluck=6 }
        => |s, d, len| { s.waveform = p_u8(d, len, 0, 0).min(6); };

    4, pulse_width, u8, 128
        => |s, d, len| { s.pulse_width = p_u8(d, len, 0, 128); };

    5, sub_level, u8, 0
        => |s, d, len| { s.sub_level = p_u8(d, len, 0, 0); };

    6, pluck_decay, u8, 250
        => |s, d, len| { s.pluck_decay = p_u8(d, len, 0, 250); };

    7, pluck_brightness, u8, 200
        => |s, d, len| { s.pluck_brightness = p_u8(d, len, 0, 200); };

    // --- Filter ---
    8, cutoff, u8, 200
        => |s, d, len| { s.cutoff = p_u8(d, len, 0, 200); };

    9, resonance, u8, 100
        => |s, d, len| { s.resonance = p_u8(d, len, 0, 100); };

    10, env_amount, u8, 128
        => |s, d, len| { s.env_amount = p_u8(d, len, 0, 128); };

    11, key_track, u8, 64
        => |s, d, len| { s.key_track = p_u8(d, len, 0, 64); };

    // --- Filter envelope ---
    12, filter_attack_ms, u16, 5
        => |s, d, len| {
            s.filter_env.attack_rate = ms_to_env_rate(p_u16(d, len, 0, 5), s.sample_rate);
        };

    13, filter_decay_ms, u16, 200
        => |s, d, len| {
            s.filter_env.decay_rate = ms_to_env_rate(p_u16(d, len, 0, 200), s.sample_rate);
        };

    14, filter_sustain, u8, 50
        => |s, d, len| {
            s.filter_env.sustain_level = (p_u8(d, len, 0, 50) as u16) << 8;
        };

    15, filter_release_ms, u16, 100
        => |s, d, len| {
            s.filter_env.release_rate = ms_to_env_rate(p_u16(d, len, 0, 100), s.sample_rate);
        };

    // --- Amp envelope ---
    16, amp_attack_ms, u16, 5
        => |s, d, len| {
            s.amp_env.attack_rate = ms_to_env_rate(p_u16(d, len, 0, 5), s.sample_rate);
        };

    17, amp_decay_ms, u16, 200
        => |s, d, len| {
            s.amp_env.decay_rate = ms_to_env_rate(p_u16(d, len, 0, 200), s.sample_rate);
        };

    18, amp_sustain, u8, 100
        => |s, d, len| {
            s.amp_env.sustain_level = (p_u8(d, len, 0, 100) as u16) << 8;
        };

    19, amp_release_ms, u16, 100
        => |s, d, len| {
            s.amp_env.release_rate = ms_to_env_rate(p_u16(d, len, 0, 100), s.sample_rate);
        };

    // --- Performance ---
    20, accent, u8, 100
        => |s, d, len| { s.accent = p_u8(d, len, 0, 100); };

    21, glide_ms, u16, 0
        => |s, d, len| { s.glide_ms = p_u16(d, len, 0, 0); };

    22, glide_mode, u8, 0, enum { off=0, always=1, on=1, legato=2 }
        => |s, d, len| { s.glide_mode = p_u8(d, len, 0, 0).min(2); };

    23, drive, u8, 0
        => |s, d, len| { s.drive = p_u8(d, len, 0, 0); };

    // --- Polyphony ---
    24, polyphony, u8, 1
        => |s, d, len| {
            let n = p_u8(d, len, 0, 1);
            s.poly_count = n.clamp(1, MAX_POLY as u8);
        };

    // --- Voice navigation ---
    25, voice_count, u8, 0
        => |s, d, len| {
            let vc = p_u8(d, len, 0, 0);
            s.voice_count = if vc > MAX_VOICES as u8 { MAX_VOICES as u8 } else { vc };
        };

    // --- LFO ---
    27, lfo_rate, u16, 0
        => |s, d, len| {
            s.lfo_rate = p_u16(d, len, 0, 0);
            let sr = if s.sample_rate > 0 { s.sample_rate } else { 8000 };
            if s.lfo_rate > 0 {
                let phase_per_centihz = (0xFFFFFFFFu32 / sr) / 100;
                s.lfo_freq_inc = (s.lfo_rate as u32) * phase_per_centihz;
            } else {
                s.lfo_freq_inc = 0;
            }
        };

    28, lfo_depth, u8, 0
        => |s, d, len| { s.lfo_depth = p_u8(d, len, 0, 0); };

    29, lfo_waveform, u8, 5, enum { saw=0, square=1, triangle=2, sine=5, sample_hold=7 }
        => |s, d, len| { s.lfo_waveform = p_u8(d, len, 0, 5).min(7); };

    30, lfo_target, u8, 0
        => |s, d, len| { s.lfo_target = p_u8(d, len, 0, 0); };

    // --- Output / Modulation ---
    31, pan, u8, 128
        => |s, d, len| { s.pan = p_u8(d, len, 0, 128); };

    32, vel_to_cutoff, u8, 0
        => |s, d, len| { s.vel_to_cutoff = p_u8(d, len, 0, 0); };

    33, vel_to_drive, u8, 0
        => |s, d, len| { s.vel_to_drive = p_u8(d, len, 0, 0); };

    34, vel_to_lfo_depth, u8, 0
        => |s, d, len| { s.vel_to_lfo_depth = p_u8(d, len, 0, 0); };

    35, vel_to_env_amt, u8, 0
        => |s, d, len| { s.vel_to_env_amt = p_u8(d, len, 0, 0); };

    // --- Detune ---
    36, voice_detune_cents, u8, 0
        => |s, d, len| { s.voice_detune_cents = p_u8(d, len, 0, 0).min(30); };

    37, detune_curve, u8, 0, enum { linear=0, random=1 }
        => |s, d, len| { s.detune_curve = p_u8(d, len, 0, 0).min(1); };

    // --- Envelope loop ---
    38, env_loop, u8, 0, enum { off=0, ad=1, adr=2 }
        => |s, d, len| { s.env_loop = p_u8(d, len, 0, 0).min(2); };

    39, loop_rate_scale, u8, 100
        => |s, d, len| { s.loop_rate_scale = p_u8(d, len, 0, 100).max(1); };
}
