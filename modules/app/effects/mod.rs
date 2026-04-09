//! Effects Chain PIC Module
//!
//! Standalone stereo effects processor with 18 configurable effects.
//! Reads stereo i16 audio, applies the effects chain, writes stereo i16.
//!
//! Effects chain order:
//!   Gate → Compressor → Overdrive → Bitcrush → Waveshaper →
//!   Chorus → Flanger → Phaser → Comb → Tremolo → RingMod →
//!   PitchShift → Harmonizer → Granular → EQ → Delay → Reverb → Limiter
//!
//! All effects are optional, enabled via TLV tag presence.

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

mod constants;
mod state;
mod effects;
mod tlv;
mod tremolo;
mod ring_mod;
mod waveshaper;
mod limiter;
mod gate;
mod compressor;
mod phaser;
mod eq;
mod flanger;
mod comb;
mod reverb;
mod pitch_shift;
mod harmonizer;
mod granular;

use constants::*;
use state::EffectsState;
use effects::*;

// ============================================================================
// Parameter Definitions (schema + dispatch for TLV v2)
// ============================================================================

mod params_def {
    use super::EffectsState;
    use super::constants::*;
    use super::{p_u8, p_u16, p_u32};
    use super::SCHEMA_MAX;

    define_params! {
        EffectsState;

        // === Core ===
        1, sample_rate, u32, 8000
            => |s, d, len| { let sr = p_u32(d, len, 0, 8000); s.sample_rate = if sr > 0 { sr } else { 8000 }; };
        2, buffer_mode, u8, 0, enum { auto=0, inplace=1, fifo=2 }
            => |s, d, len| { s.buffer_mode = p_u8(d, len, 0, 0); };

        // === Chorus (tags 16-18) ===
        // Raw values: depth_ms stored in chorus_mod_depth, rate stored in chorus_base_delay
        // derive_chorus() converts to actual delay/LFO values using sample_rate
        16, chorus_depth_ms, u8, 5
            => |s, d, len| { s.chorus_mod_depth = p_u8(d, len, 0, 5) as u16; };
        17, chorus_rate, u8, 100
            => |s, d, len| { s.chorus_base_delay = p_u8(d, len, 0, 100) as u16; };
        18, chorus_mix, u8, 128
            => |s, d, len| { s.chorus_mix = p_u8(d, len, 0, 128); };

        // === Delay (tags 19-22) ===
        // Raw delay_ms stored in delay_frames; derive_delay() converts to frames
        19, delay_ms, u16, 50
            => |s, d, len| { s.delay_frames = p_u16(d, len, 0, 50); };
        20, delay_feedback, u8, 128
            => |s, d, len| { s.delay_feedback = p_u8(d, len, 0, 128); };
        21, delay_mix, u8, 128
            => |s, d, len| { s.delay_mix = p_u8(d, len, 0, 128); };
        22, delay_filter, u8, 200
            => |s, d, len| { s.delay_filter_coef = p_u8(d, len, 0, 200); };

        // === Overdrive (tags 24-25) ===
        24, overdrive_gain, u8, 0
            => |s, d, len| { s.overdrive_gain = p_u8(d, len, 0, 0); };
        25, overdrive_tone, u8, 200
            => |s, d, len| { s.overdrive_tone = p_u8(d, len, 0, 200); };

        // === Bitcrush (tags 26-27) ===
        26, bitcrush_bits, u8, 16
            => |s, d, len| { s.bitcrush_bits = p_u8(d, len, 0, 16); };
        27, bitcrush_rate_div, u8, 1
            => |s, d, len| { s.bitcrush_rate_div = p_u8(d, len, 0, 1).max(1); };

        // === Tremolo (tags 28-30) ===
        28, tremolo_rate, u32, 5000
            => |s, d, len| {
                let rate_mhz = p_u32(d, len, 0, 5000);
                let sr_k = if s.sample_rate >= 1000 { s.sample_rate / 1000 } else { 1 };
                s.tremolo_lfo_inc = (rate_mhz * 4295) / sr_k.max(1);
            };
        29, tremolo_depth, u8, 180
            => |s, d, len| { s.tremolo_depth = p_u8(d, len, 0, 180); };
        30, tremolo_shape, u8, 0, enum { sine=0, triangle=1, square=2 }
            => |s, d, len| { s.tremolo_shape = p_u8(d, len, 0, 0).min(2); };

        // === Ring Mod (tags 31-32) ===
        31, ring_mod_freq, u16, 200
            => |s, d, len| {
                let freq = p_u16(d, len, 0, 200) as u32;
                let sr_256 = if s.sample_rate >= 256 { s.sample_rate / 256 } else { 1 };
                s.ringmod_carrier_inc = (freq * 16777216) / sr_256.max(1);
            };
        32, ring_mod_mix, u8, 200
            => |s, d, len| { s.ringmod_mix = p_u8(d, len, 0, 200); };

        // === Waveshaper (tags 33-35) ===
        33, waveshaper_curve, u8, 0, enum { soft=0, hard=1, fold=2, asymmetric=3, rectify=4 }
            => |s, d, len| { s.waveshaper_curve = p_u8(d, len, 0, 0).min(4); };
        34, waveshaper_amount, u8, 128
            => |s, d, len| { s.waveshaper_amount = p_u8(d, len, 0, 128); };
        35, waveshaper_mix, u8, 200
            => |s, d, len| { s.waveshaper_mix = p_u8(d, len, 0, 200); };

        // === Compressor (tags 36-41) ===
        36, compressor_threshold, u8, 180
            => |s, d, len| {
                let raw = p_u8(d, len, 0, 180);
                s.comp_threshold = (raw as u16) * 128;
            };
        37, compressor_ratio, u8, 4
            => |s, d, len| {
                let r = p_u8(d, len, 0, 4);
                s.comp_ratio = if r >= 1 && r <= 16 { r } else { 4 };
            };
        38, compressor_attack_ms, u16, 10
            => |s, d, len| {
                let ms = p_u16(d, len, 0, 10).min(500);
                let sr_k = if s.sample_rate >= 1000 { s.sample_rate / 1000 } else { 1 };
                let samples = sr_k * (ms as u32);
                s.comp_attack_coef = (65536u32 / samples.max(1)).clamp(1, 65535) as u16;
            };
        39, compressor_release_ms, u16, 100
            => |s, d, len| {
                let ms = p_u16(d, len, 0, 100).min(2000);
                let sr_k = if s.sample_rate >= 1000 { s.sample_rate / 1000 } else { 1 };
                let samples = sr_k * (ms as u32);
                s.comp_release_coef = (65536u32 / samples.max(1)).clamp(1, 65535) as u16;
            };
        40, compressor_makeup, u8, 128
            => |s, d, len| { s.comp_makeup = p_u8(d, len, 0, 128); };
        41, compressor_mix, u8, 255
            => |s, d, len| { s.comp_mix = p_u8(d, len, 0, 255); };

        // === Limiter (tags 42-43) ===
        42, limiter_threshold, u8, 250
            => |s, d, len| {
                let raw = p_u8(d, len, 0, 250) as u16;
                s.limiter_threshold = (raw * 128).min(32767) as i16;
            };
        43, limiter_mode, u8, 0, enum { hard=0, soft=1 }
            => |s, d, len| { s.limiter_mode = p_u8(d, len, 0, 0).min(1); };

        // === Gate (tags 44-46) ===
        44, gate_threshold, u8, 30
            => |s, d, len| {
                let raw = p_u8(d, len, 0, 30);
                s.gate_threshold = (raw as u16) * 128;
                let sr_k = if s.sample_rate >= 1000 { s.sample_rate / 1000 } else { 1 };
                s.gate_hold_samples = (50 * sr_k).min(65535) as u16;
                s.gate_range = 80;
                s.gate_state = GATE_CLOSED;
                s.gate_gain = 0;
                s.gate_env_level = 0;
                s.gate_hold_counter = 0;
            };
        45, gate_attack_ms, u16, 1
            => |s, d, len| {
                let ms = p_u16(d, len, 0, 1) as u32;
                let sr_k = if s.sample_rate >= 1000 { s.sample_rate / 1000 } else { 1 };
                let samples = (ms * sr_k).saturating_add(1);
                s.gate_attack_coef = (65536u32 / samples).min(65535) as u16;
            };
        46, gate_release_ms, u16, 100
            => |s, d, len| {
                let ms = p_u16(d, len, 0, 100) as u32;
                let sr_k = if s.sample_rate >= 1000 { s.sample_rate / 1000 } else { 1 };
                let samples = (ms * sr_k).saturating_add(1);
                s.gate_release_coef = (65536u32 / samples).min(65535) as u16;
            };

        // === Phaser (tags 47-51) ===
        47, phaser_rate, u32, 1000
            => |s, d, len| {
                let rate_mhz = p_u32(d, len, 0, 1000);
                let sr_k = if s.sample_rate >= 1000 { s.sample_rate / 1000 } else { 1 };
                s.phaser_lfo_inc = (rate_mhz * 4295) / sr_k.max(1);
            };
        48, phaser_depth, u8, 200
            => |s, d, len| { s.phaser_depth = p_u8(d, len, 0, 200); };
        49, phaser_feedback, u8, 100
            => |s, d, len| { s.phaser_feedback = p_u8(d, len, 0, 100); };
        50, phaser_stages, u8, 4
            => |s, d, len| { s.phaser_stages = p_u8(d, len, 0, 4).clamp(2, MAX_PHASER_STAGES as u8); };
        51, phaser_mix, u8, 128
            => |s, d, len| { s.phaser_mix = p_u8(d, len, 0, 128); };

        // === EQ (tags 52-58) ===
        52, eq_low_freq, u16, 200
            => |s, d, len| { s.eq_low_freq_raw = p_u16(d, len, 0, 200).clamp(50, 500); };
        53, eq_low_gain, u8, 128
            => |s, d, len| { s.eq_low_gain_raw = p_u8(d, len, 0, 128); };
        54, eq_mid_freq, u16, 1000
            => |s, d, len| { s.eq_mid_freq_raw = p_u16(d, len, 0, 1000).clamp(200, 5000); };
        55, eq_mid_gain, u8, 128
            => |s, d, len| { s.eq_mid_gain_raw = p_u8(d, len, 0, 128); };
        56, eq_mid_q, u8, 128
            => |s, d, len| { s.eq_mid_q_raw = p_u8(d, len, 0, 128); };
        57, eq_high_freq, u16, 4000
            => |s, d, len| { s.eq_high_freq_raw = p_u16(d, len, 0, 4000).clamp(1000, 8000); };
        58, eq_high_gain, u8, 128
            => |s, d, len| { s.eq_high_gain_raw = p_u8(d, len, 0, 128); };

        // === Flanger (tags 59-63) ===
        59, flanger_rate, u32, 500
            => |s, d, len| {
                let rate_mhz = p_u32(d, len, 0, 500);
                let sr_k = if s.sample_rate >= 1000 { s.sample_rate / 1000 } else { 1 };
                s.flanger_lfo_inc = (rate_mhz * 4295) / sr_k.max(1);
            };
        60, flanger_depth, u8, 200
            => |s, d, len| { s.flanger_depth = p_u8(d, len, 0, 200); };
        61, flanger_feedback, u8, 100
            => |s, d, len| { s.flanger_feedback = p_u8(d, len, 0, 100); };
        62, flanger_manual, u8, 128
            => |s, d, len| { s.flanger_manual = p_u8(d, len, 0, 128); };
        63, flanger_mix, u8, 128
            => |s, d, len| { s.flanger_mix = p_u8(d, len, 0, 128); };

        // === Comb (tags 64-66) ===
        64, comb_delay_ms, u16, 10
            => |s, d, len| {
                let ms = p_u16(d, len, 0, 10).clamp(1, 50) as u32;
                let samples = (8 * ms) as u16;
                s.comb_delay_samples = if samples > 0 && (samples as usize) < COMB_BUF_SIZE { samples } else { 80 };
            };
        65, comb_feedback, u8, 200
            => |s, d, len| { s.comb_feedback = p_u8(d, len, 0, 200); };
        66, comb_mix, u8, 128
            => |s, d, len| { s.comb_mix = p_u8(d, len, 0, 128); };

        // === Reverb (tags 67-70) ===
        67, reverb_decay, u8, 180
            => |s, d, len| { s.reverb_decay = p_u8(d, len, 0, 180); };
        68, reverb_damping, u8, 100
            => |s, d, len| { s.reverb_damping = p_u8(d, len, 0, 100); };
        69, reverb_predelay_ms, u16, 10
            => |s, d, len| {
                let ms = p_u16(d, len, 0, 10).min(50) as u32;
                let sr_k = if s.sample_rate >= 1000 { s.sample_rate / 1000 } else { 1 };
                let samples = (ms * sr_k) as usize;
                s.reverb_predelay_len = if samples > REVERB_PREDELAY_MAX {
                    REVERB_PREDELAY_MAX as u16
                } else if samples < 1 { 1 } else { samples as u16 };
            };
        70, reverb_mix, u8, 80
            => |s, d, len| { s.reverb_mix = p_u8(d, len, 0, 80); };

        // === Pitch Shift (tags 71-73) ===
        // semitones: 128 = no shift, 116-140 = -12 to +12
        71, pitch_shift_semitones, u8, 128
            => |s, d, len| {
                let raw = p_u8(d, len, 0, 128) as i16 - 128;
                let semi = raw.clamp(-12, 12) as i8;
                s.ps_read_inc = super::pitch_shift::semitones_to_inc(semi);
                s.ps_direction = if semi > 0 { 1 } else if semi < 0 { -1 } else { 0 };
            };
        72, pitch_shift_window_ms, u8, 30
            => |s, d, len| {
                let ms = p_u8(d, len, 0, 30).clamp(10, 100) as u32;
                let sr_k = if s.sample_rate >= 1000 { s.sample_rate / 1000 } else { 1 };
                s.ps_window_size = ((ms * sr_k) as u16).min(PITCH_BUF_SIZE as u16 / 2);
                s.ps_read_pos_b = (s.ps_window_size as u32 / 2) << 16;
            };
        73, pitch_shift_mix, u8, 255
            => |s, d, len| { s.ps_mix = p_u8(d, len, 0, 255); };

        // === Harmonizer (tags 74-78) ===
        // semitones: 128 = no shift
        74, harmonizer_voice1_semitones, u8, 135
            => |s, d, len| {
                let raw = p_u8(d, len, 0, 135) as i16 - 128;
                let semi = raw.clamp(-12, 12) as i8;
                s.harm_v1_read_inc = super::pitch_shift::semitones_to_inc(semi);
                s.harm_v1_active = if s.harm_v1_level > 0 && semi != 0 { 1 } else { 0 };
            };
        75, harmonizer_voice1_level, u8, 200
            => |s, d, len| { s.harm_v1_level = p_u8(d, len, 0, 200); };
        76, harmonizer_voice2_semitones, u8, 128
            => |s, d, len| {
                let raw = p_u8(d, len, 0, 128) as i16 - 128;
                let semi = raw.clamp(-12, 12) as i8;
                s.harm_v2_read_inc = super::pitch_shift::semitones_to_inc(semi);
                s.harm_v2_active = if s.harm_v2_level > 0 && semi != 0 { 1 } else { 0 };
            };
        77, harmonizer_voice2_level, u8, 0
            => |s, d, len| { s.harm_v2_level = p_u8(d, len, 0, 0); };
        78, harmonizer_dry_level, u8, 255
            => |s, d, len| { s.harm_dry_level = p_u8(d, len, 0, 255); };

        // === Granular (tags 79-83) ===
        79, granular_grain_size_ms, u8, 50
            => |s, d, len| {
                let ms = p_u8(d, len, 0, 50).clamp(10, 200) as u32;
                let sr_k = if s.sample_rate >= 1000 { s.sample_rate / 1000 } else { 1 };
                let samples = (ms * sr_k) as u16;
                s.granular_grain_size = samples.min(GRAIN_BUF_SIZE as u16 - 1);
            };
        80, granular_density, u8, 4
            => |s, d, len| {
                let density = p_u8(d, len, 0, 4).clamp(1, 8);
                let interval = s.granular_grain_size / density.max(1) as u16;
                s.granular_trigger_interval = interval.max(1);
            };
        81, granular_pitch, u8, 128
            => |s, d, len| {
                let pitch = p_u8(d, len, 0, 128);
                s.granular_pitch_inc = if pitch >= 128 {
                    65536 + ((pitch as u32 - 128) * 512)
                } else {
                    32768 + ((pitch as u32) * 256)
                };
            };
        82, granular_spread, u8, 50
            => |s, d, len| { s.granular_spread = p_u8(d, len, 0, 50); };
        83, granular_mix, u8, 180
            => |s, d, len| { s.granular_mix = p_u8(d, len, 0, 180); };

        // === Macros / Modulation (tags 84-92) ===
        84, macro1_depth, u8, 0
            => |s, d, len| { s.macro1_depth = p_u8(d, len, 0, 0); };
        85, macro2_depth, u8, 0
            => |s, d, len| { s.macro2_depth = p_u8(d, len, 0, 0); };
        86, fx_lfo_rate, u16, 0
            => |s, d, len| {
                s.fx_lfo_rate = p_u16(d, len, 0, 0);
                let sr = if s.sample_rate > 0 { s.sample_rate } else { 8000 };
                if s.fx_lfo_rate > 0 {
                    let phase_per_centihz = (0xFFFFFFFFu32 / sr) / 100;
                    s.fx_lfo_inc = (s.fx_lfo_rate as u32) * phase_per_centihz;
                } else {
                    s.fx_lfo_inc = 0;
                }
            };
        87, fx_lfo_depth, u8, 0
            => |s, d, len| { s.fx_lfo_depth = p_u8(d, len, 0, 0); };
        88, fx_lfo_shape, u8, 0, enum { sine=0, triangle=1, square=2, sample_hold=3 }
            => |s, d, len| { s.fx_lfo_shape = p_u8(d, len, 0, 0).min(3); };
        89, fx_lfo_target, u8, 0
            => |s, d, len| { s.fx_lfo_target = p_u8(d, len, 0, 0); };
        90, duck_target, u8, 0, enum { off=0, delay=1, reverb=2, both=3 }
            => |s, d, len| { s.duck_target = p_u8(d, len, 0, 0).min(3); };
        91, duck_amount, u8, 0
            => |s, d, len| { s.duck_amount = p_u8(d, len, 0, 0); };
        92, duck_release_ms, u16, 200
            => |s, d, len| {
                let ms = p_u16(d, len, 0, 200).min(2000) as u32;
                let sr_k = if s.sample_rate >= 1000 { s.sample_rate / 1000 } else { 1 };
                let samples = (ms * sr_k).saturating_add(1);
                s.duck_release_coef = (65536u32 / samples).min(65535) as u16;
            };
    }
}

// ============================================================================
// LFO helper (needed for inline chorus)
// ============================================================================

#[inline(always)]
fn sine_lfo(phase: u8) -> i8 {
    let quadrant = phase >> 6;
    let idx = (phase & 0x3F) as usize;
    match quadrant {
        0 => SINE_TABLE[idx],
        1 => SINE_TABLE[63 - idx],
        2 => -SINE_TABLE[idx],
        _ => -SINE_TABLE[63 - idx],
    }
}

#[inline(always)]
fn fx_lfo_sample(phase: u8, shape: u8, sh_value: i16) -> i16 {
    match shape {
        // triangle
        1 => {
            let x = phase as i16;
            if x < 128 { (x - 64) * 2 } else { (191 - x) * 2 }
        }
        // square
        2 => if phase < 128 { 127 } else { -127 },
        // sample & hold
        3 => sh_value,
        // sine
        _ => sine_lfo(phase) as i16,
    }
}

// ============================================================================
// Module API
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<EffectsState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<EffectsState>() { return -2; }

        let s = &mut *(state as *mut EffectsState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.ctrl_chan = ctrl_chan;
        s.nav_chan = -1;
        s.voice_count = 0;
        s.current_voice = 0;

        // Copy params blob into state
        let copy_len = if !params.is_null() && params_len > 0 {
            params_len.min(PARAMS_SIZE)
        } else { 0 };

        let params_dst = s.params.as_mut_ptr();
        let mut i = 0;
        while i < PARAMS_SIZE {
            core::ptr::write_volatile(params_dst.add(i), 0u8);
            i += 1;
        }
        if copy_len > 0 {
            let mut i = 0;
            while i < copy_len {
                core::ptr::write_volatile(params_dst.add(i), *params.add(i));
                i += 1;
            }
        }
        s.params_len = copy_len as u16;

        // Apply TLV params
        apply_params(s);

        // Scan params TLV for 0xFD voice entries and populate voice_table
        if copy_len >= 4 && !params.is_null()
            && *params == 0xFE && *params.add(1) == 0x01
        {
            let mut vcount = 0u8;
            let mut off = 4usize;
            while off + 2 <= copy_len && (vcount as usize) < MAX_VOICES {
                let tag = *params.add(off);
                let elen = *params.add(off + 1) as usize;
                off += 2;
                if tag == 0xFF { break; }
                if tag == 0xFD && off + elen <= copy_len {
                    let dst = s.voice_table.as_mut_ptr()
                        .add(vcount as usize) as *mut u8;
                    let clen = elen.min(PARAMS_SIZE);
                    let mut j = 0;
                    while j < clen {
                        core::ptr::write_volatile(dst.add(j), *params.add(off + j));
                        j += 1;
                    }
                    vcount += 1;
                }
                off += elen;
            }
            if vcount > 0 {
                s.voice_count = vcount;
                s.current_voice = 0;
                // Apply first voice as active params
                let src = s.voice_table.as_ptr() as *const u8;
                let pdst = s.params.as_mut_ptr();
                let mut j = 0;
                while j < PARAMS_SIZE {
                    core::ptr::write_volatile(pdst.add(j), *src.add(j));
                    j += 1;
                }
                s.params_len = PARAMS_SIZE as u16;
                apply_params(s);
                // Enable voice navigation on ctrl channel
                if vcount > 1 {
                    s.nav_chan = ctrl_chan;
                }
            }
        }

        // Initialize runtime state (arena pre-zeroes memory)
        s.pending_out = 0;
        s.pending_offset = 0;
        s.chorus_lfo_phase = 0;
        s.chorus_write_pos = 0;
        s.delay_write_pos = 0;
        s.delay_filter_l = 0;
        s.delay_filter_r = 0;
        s.bitcrush_counter = 0;
        s.bitcrush_hold_l = 0;
        s.bitcrush_hold_r = 0;
        s.tremolo_lfo_phase = 0;
        s.ringmod_carrier_phase = 0;
        s.gate_state = 0;
        s.gate_gain = 0;
        s.gate_env_level = 0;
        s.gate_hold_counter = 0;
        s.comp_current_gain = 256;
        s.comp_envelope = 0;
        s.phaser_lfo_phase = 0;
        s.phaser_feedback_l = 0;
        s.phaser_feedback_r = 0;
        s.flanger_lfo_phase = 0;
        s.flanger_write_idx = 0;
        s.flanger_feedback_l = 0;
        s.flanger_feedback_r = 0;
        s.comb_write_pos = 0;
        s.reverb_predelay_idx = 0;
        s.reverb_damp_l = 0;
        s.reverb_damp_r = 0;
        s.ps_write_pos = 0;
        s.ps_xfade_pos = 0;
        s.ps_read_pos_a = 0;
        s.ps_read_pos_b = 0;
        s.ps_active_reader = 0;
        s.harm_write_pos = 0;
        s.harm_v1_read_pos_a = 0;
        s.harm_v1_read_pos_b = 0;
        s.harm_v1_xfade_pos = 0;
        s.harm_v1_active_reader = 0;
        s.harm_v2_read_pos_a = 0;
        s.harm_v2_read_pos_b = 0;
        s.harm_v2_xfade_pos = 0;
        s.harm_v2_active_reader = 0;
        s.granular_write_pos = 0;
        s.granular_trigger_counter = 0;
        s.granular_next_grain = 0;
        s.granular_lfsr = 0xBEEF;

        // Report processing latency to kernel for downstream compensation
        let sys = &*s.syscalls;
        let mut latency_frames: u32 = 0;
        if (s.fx_enable & FX_DELAY) != 0 {
            latency_frames = latency_frames.saturating_add(s.delay_frames as u32);
        }
        if (s.fx_enable & FX_REVERB) != 0 {
            latency_frames = latency_frames.saturating_add(s.reverb_predelay_len as u32);
        }
        if (s.fx_enable & FX_PITCH_SHIFT) != 0 {
            latency_frames = latency_frames.saturating_add(s.ps_window_size as u32);
        }
        if (s.fx_enable & FX_GRANULAR) != 0 {
            latency_frames = latency_frames.saturating_add(s.granular_grain_size as u32);
        }
        if latency_frames > 0 {
            dev_report_latency(sys, latency_frames);
        }

        0
    }
}

unsafe fn apply_params(s: &mut EffectsState) {
    let p = s.params.as_ptr();
    let len = s.params_len as usize;

    if len >= 4 && *p == 0xFE {
        match *p.add(1) {
            0x02 => {
                // TLV v2: flat per-param tags with schema
                parse_tlv(s);
                return;
            }
            0x01 => {
                // TLV v1: grouped tags (legacy)
                tlv::parse_tlv(s);
                return;
            }
            _ => {}
        }
    }
    // Fallback for unknown format
    if tlv::is_tlv(p, len) {
        tlv::parse_tlv(s);
    }
}

/// TLV v2 parser with two-pass approach:
/// 1. First pass: extract sample_rate so derivation closures can use it
/// 2. Second pass: dispatch all params, tracking fx_enable
unsafe fn parse_tlv(s: &mut EffectsState) {
    tlv::set_defaults(s);
    s.fx_enable = 0;

    let p = s.params.as_ptr();
    let len = s.params_len as usize;
    if len < 4 { return; }

    let total = u16::from_le_bytes([*p.add(2), *p.add(3)]) as usize;
    let end = (4 + total).min(len);

    // First pass: find sample_rate (tag 1)
    let mut off = 4usize;
    while off + 2 <= end {
        let tag = *p.add(off);
        let elen = *p.add(off + 1) as usize;
        off += 2;
        if tag == 0xFF { break; }
        if off + elen > end { break; }
        if tag == 1 {
            let sr = p_u32(p.add(off), elen, 0, 8000);
            s.sample_rate = if sr > 0 { sr } else { 8000 };
        }
        off += elen;
    }

    // Second pass: dispatch all params
    off = 4;
    while off + 2 <= end {
        let tag = *p.add(off);
        let elen = *p.add(off + 1) as usize;
        off += 2;
        if tag == 0xFF { break; }
        if off + elen > end { break; }
        params_def::dispatch_param(s, tag, p.add(off), elen);
        enable_fx_for_tag(s, tag);
        off += elen;
    }

    // Post-parse derivations
    tlv::derive_chorus(s);
    tlv::derive_delay(s);

    // Derive EQ biquad coefficients from raw params
    if (s.fx_enable & FX_EQ) != 0 {
        let sr = s.sample_rate;
        s.eq_coefs[0] = eq::calc_low_shelf(s.eq_low_gain_raw, s.eq_low_freq_raw as u32, sr);
        s.eq_coefs[1] = eq::calc_parametric(s.eq_mid_gain_raw, s.eq_mid_freq_raw as u32, s.eq_mid_q_raw, sr);
        s.eq_coefs[2] = eq::calc_high_shelf(s.eq_high_gain_raw, s.eq_high_freq_raw as u32, sr);
        let mut b = 0;
        while b < NUM_EQ_BANDS {
            s.eq_state_l[b] = [0; 4];
            s.eq_state_r[b] = [0; 4];
            b += 1;
        }
    }
}

/// Set fx_enable bits based on which tag range a param belongs to.
fn enable_fx_for_tag(s: &mut EffectsState, tag: u8) {
    match tag {
        16..=18 => s.fx_enable |= FX_CHORUS,
        19..=22 => s.fx_enable |= FX_DELAY,
        24..=25 => s.fx_enable |= FX_OVERDRIVE,
        26..=27 => s.fx_enable |= FX_BITCRUSH,
        28..=30 => s.fx_enable |= FX_TREMOLO,
        31..=32 => s.fx_enable |= FX_RING_MOD,
        33..=35 => s.fx_enable |= FX_WAVESHAPER,
        36..=41 => s.fx_enable |= FX_COMPRESSOR,
        42..=43 => s.fx_enable |= FX_LIMITER,
        44..=46 => s.fx_enable |= FX_GATE,
        47..=51 => s.fx_enable |= FX_PHASER,
        52..=58 => s.fx_enable |= FX_EQ,
        59..=63 => s.fx_enable |= FX_FLANGER,
        64..=66 => s.fx_enable |= FX_COMB,
        67..=70 => s.fx_enable |= FX_REVERB,
        71..=73 => s.fx_enable |= FX_PITCH_SHIFT,
        74..=78 => s.fx_enable |= FX_HARMONIZER,
        79..=83 => s.fx_enable |= FX_GRANULAR,
        _ => {}
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() { return -1; }
        let s = &mut *(state as *mut EffectsState);
        if s.syscalls.is_null() { return -1; }

        let sys = &*s.syscalls;
        let in_chan = s.in_chan;
        let out_chan = s.out_chan;
        let ctrl_chan = s.ctrl_chan;

        // Read voice navigation commands (FMP messages)
        if s.nav_chan >= 0 && s.voice_count > 1 {
            let nav_poll = (sys.channel_poll)(s.nav_chan, POLL_IN);
            if nav_poll > 0 && ((nav_poll as u32) & POLL_IN) != 0 {
                let (ty, _len) = msg_read(sys, s.nav_chan, s.nav_buf.as_mut_ptr(), 16);
                if ty != 0 {
                    let vc = s.voice_count;
                    let switched = match ty {
                        MSG_NEXT => {
                            let next = s.current_voice + 1;
                            s.current_voice = if next >= vc { 0 } else { next };
                            true
                        }
                        MSG_PREV => {
                            s.current_voice = if s.current_voice == 0 { vc - 1 } else { s.current_voice - 1 };
                            true
                        }
                        _ => false,
                    };
                    if switched {
                        // Copy voice_table[current_voice] → params and apply
                        let v = s.current_voice as usize;
                        let vt_base = s.voice_table.as_ptr() as *const u8;
                        let src = vt_base.add(v * PARAMS_SIZE);
                        let dst = s.params.as_mut_ptr();
                        let mut i = 0;
                        while i < PARAMS_SIZE {
                            *dst.add(i) = *src.add(i);
                            i += 1;
                        }
                        s.params_len = PARAMS_SIZE as u16;
                        apply_params(s);
                    }
                }
            }
        }

        // Read control messages
        if ctrl_chan >= 0 {
            loop {
                let ctrl_poll = (sys.channel_poll)(ctrl_chan, POLL_IN);
                if ctrl_poll <= 0 || ((ctrl_poll as u32) & POLL_IN) == 0 { break; }

                let mut hdr: [u8; 1] = [0];
                let r = (sys.channel_read)(ctrl_chan, hdr.as_mut_ptr(), 1);
                if r != 1 { break; }

                match hdr[0] {
                    CTRL_PATCH => {
                        let mut patch: [u8; 3] = [0; 3];
                        let r = (sys.channel_read)(ctrl_chan, patch.as_mut_ptr(), 3);
                        if r != 3 { break; }
                        let offset = patch[0] as usize;
                        if offset + 1 < PARAMS_SIZE {
                            s.params[offset] = patch[1];
                            s.params[offset + 1] = patch[2];
                        }
                        apply_params(s);
                    }
                    CTRL_RELOAD => {
                        let r = (sys.channel_read)(ctrl_chan, s.params.as_mut_ptr(), PARAMS_SIZE);
                        if r < 4 { break; }
                        s.params_len = r as u16;
                        apply_params(s);
                    }
                    _ => { break; }
                }
            }
        }

        // Drain any pending output (FIFO path only — skipped in zero-copy mode)
        if !drain_pending(sys, out_chan, s.out_buf.as_ptr(), &mut s.pending_out, &mut s.pending_offset) {
            return 0;
        }

        // Read-process-write loop
        loop {
            // Buffer mode selection:
            //   0 (auto): try in-place, fall back to FIFO
            //   1 (inplace): require in-place, fail if unavailable
            //   2 (fifo): skip in-place probe, always use FIFO
            let mut inplace_len: u32 = 0;
            let inplace_ptr = if s.buffer_mode == 2 {
                core::ptr::null_mut()
            } else {
                dev_buffer_acquire_inplace(sys, in_chan, &mut inplace_len)
            };
            let is_inplace = !inplace_ptr.is_null() && inplace_len >= 4;
            if !is_inplace && s.buffer_mode == 1 {
                // inplace required but unavailable — signal done (config error)
                return 1;
            }

            let (samples, stereo_frames, total_bytes) = if is_inplace {
                (inplace_ptr as *mut i16, (inplace_len as usize) / 4, inplace_len as usize)
            } else {
                // FIFO fallback: check output space and input availability
                let out_poll = (sys.channel_poll)(out_chan, POLL_OUT);
                if out_poll <= 0 || ((out_poll as u32) & POLL_OUT) == 0 { break; }

                let in_poll = (sys.channel_poll)(in_chan, POLL_IN | POLL_HUP);
                if in_poll & POLL_HUP as i32 != 0 { return 1; }
                if in_poll & POLL_IN as i32 == 0 { break; }

                let max_bytes = SAMPLES_PER_CHUNK * 4; // stereo i16 = 4 bytes per frame
                let read = (sys.channel_read)(in_chan, s.out_buf.as_mut_ptr(), max_bytes);
                if read <= 0 { break; }

                let total = read as usize;
                (s.out_buf.as_mut_ptr() as *mut i16, total / 4, total)
            };

            if stereo_frames == 0 {
                if is_inplace { dev_buffer_release_write(sys, in_chan, 0); }
                break;
            }

            let fx_enable = s.fx_enable;

            let gate_enabled = (fx_enable & FX_GATE) != 0;
            let compressor_enabled = (fx_enable & FX_COMPRESSOR) != 0;
            let overdrive_enabled = (fx_enable & FX_OVERDRIVE) != 0;
            let bitcrush_enabled = (fx_enable & FX_BITCRUSH) != 0;
            let waveshaper_enabled = (fx_enable & FX_WAVESHAPER) != 0;
            let chorus_enabled = (fx_enable & FX_CHORUS) != 0;
            let flanger_enabled = (fx_enable & FX_FLANGER) != 0;
            let phaser_enabled = (fx_enable & FX_PHASER) != 0;
            let comb_enabled = (fx_enable & FX_COMB) != 0;
            let tremolo_enabled = (fx_enable & FX_TREMOLO) != 0;
            let ringmod_enabled = (fx_enable & FX_RING_MOD) != 0;
            let eq_enabled = (fx_enable & FX_EQ) != 0;
            let pitch_shift_enabled = (fx_enable & FX_PITCH_SHIFT) != 0;
            let harmonizer_enabled = (fx_enable & FX_HARMONIZER) != 0;
            let granular_enabled = (fx_enable & FX_GRANULAR) != 0;
            let delay_enabled = (fx_enable & FX_DELAY) != 0;
            let reverb_enabled = (fx_enable & FX_REVERB) != 0;
            let limiter_enabled = (fx_enable & FX_LIMITER) != 0;

            // Macro / LFO modulation (per buffer)
            let macro1 = s.macro1_depth as i32;
            let macro2 = s.macro2_depth as i32;

            let mut delay_frames_eff = s.delay_frames as i32;
            let mut delay_feedback_eff = s.delay_feedback as i32;
            let mut delay_mix_eff = s.delay_mix as i32;
            let mut reverb_mix_eff = s.reverb_mix as i32;
            let mut chorus_mix_eff = s.chorus_mix as i32;
            let mut flanger_mix_eff = s.flanger_mix as i32;
            let mut phaser_mix_eff = s.phaser_mix as i32;
            let mut granular_mix_eff = s.granular_mix as i32;

            if macro1 > 0 {
                delay_frames_eff = (delay_frames_eff + (delay_frames_eff * macro1) / 255)
                    .clamp(1, (DELAY_BUF_FRAMES as i32) - 1);
                delay_feedback_eff = (delay_feedback_eff + (macro1 / 2)).clamp(0, 255);
                reverb_mix_eff = (reverb_mix_eff + (macro1 / 2)).clamp(0, 255);
            }
            delay_frames_eff = delay_frames_eff.clamp(1, (DELAY_BUF_FRAMES as i32) - 1);

            let mut overdrive_gain_eff = s.overdrive_gain as i32;
            let mut bitcrush_bits_eff = s.bitcrush_bits as i32;
            let mut waveshaper_amount_eff = s.waveshaper_amount as i32;
            let mut waveshaper_mix_eff = s.waveshaper_mix as i32;
            if macro2 > 0 {
                overdrive_gain_eff = (overdrive_gain_eff + (macro2 / 2)).clamp(0, 255);
                bitcrush_bits_eff = (bitcrush_bits_eff - (macro2 / 32)).clamp(2, 16);
                waveshaper_amount_eff = (waveshaper_amount_eff + (macro2 / 2)).clamp(0, 255);
                waveshaper_mix_eff = (waveshaper_mix_eff + (macro2 / 2)).clamp(0, 255);
            }

            let mut fx_lfo_mod: i32 = 0;
            if s.fx_lfo_depth > 0 && s.fx_lfo_inc > 0 {
                let phase = (s.fx_lfo_phase >> 24) as u8;
                let raw = fx_lfo_sample(phase, s.fx_lfo_shape, s.fx_lfo_sh_value);
                let old_phase = s.fx_lfo_phase;
                let advance = s.fx_lfo_inc.wrapping_mul(SAMPLES_PER_CHUNK as u32);
                s.fx_lfo_phase = old_phase.wrapping_add(advance);
                if s.fx_lfo_shape == 3 && s.fx_lfo_phase < old_phase {
                    s.fx_lfo_lfsr = s.fx_lfo_lfsr.wrapping_mul(1664525).wrapping_add(1013904223);
                    s.fx_lfo_sh_value = ((s.fx_lfo_lfsr >> 16) as i16) >> 8;
                }
                fx_lfo_mod = (raw as i32 * s.fx_lfo_depth as i32) >> 8;
            }

            if (s.fx_lfo_target & FX_LFO_TGT_DELAY_MIX) != 0 {
                delay_mix_eff = (delay_mix_eff + fx_lfo_mod).clamp(0, 255);
            }
            if (s.fx_lfo_target & FX_LFO_TGT_REVERB_MIX) != 0 {
                reverb_mix_eff = (reverb_mix_eff + fx_lfo_mod).clamp(0, 255);
            }
            if (s.fx_lfo_target & FX_LFO_TGT_CHORUS_MIX) != 0 {
                chorus_mix_eff = (chorus_mix_eff + fx_lfo_mod).clamp(0, 255);
            }
            if (s.fx_lfo_target & FX_LFO_TGT_FLANGER_MIX) != 0 {
                flanger_mix_eff = (flanger_mix_eff + fx_lfo_mod).clamp(0, 255);
            }
            if (s.fx_lfo_target & FX_LFO_TGT_PHASER_MIX) != 0 {
                phaser_mix_eff = (phaser_mix_eff + fx_lfo_mod).clamp(0, 255);
            }
            if (s.fx_lfo_target & FX_LFO_TGT_GRANULAR_MIX) != 0 {
                granular_mix_eff = (granular_mix_eff + fx_lfo_mod).clamp(0, 255);
            }

            let duck_active = s.duck_target != 0 && s.duck_amount > 0;

            // Process each stereo frame through the effects chain
            let mut f = 0;
            while f < stereo_frames {
                let mut sample_l = *samples.add(f * 2) as i32;
                let mut sample_r = *samples.add(f * 2 + 1) as i32;

                let mut duck_gain: i32 = 255;
                if duck_active {
                    let mag_l = sample_l.abs() as u32;
                    let mag_r = sample_r.abs() as u32;
                    let level = ((mag_l.max(mag_r) >> 7).min(255)) as u16;
                    if level > s.duck_env {
                        s.duck_env = level;
                    } else if s.duck_release_coef > 0 && s.duck_env > 0 {
                        let mut dec = ((s.duck_env as u32 * s.duck_release_coef as u32) >> 16) as u16;
                        if dec == 0 { dec = 1; }
                        s.duck_env = s.duck_env.saturating_sub(dec);
                    }
                    duck_gain = (255u32.saturating_sub(((s.duck_env as u32 * s.duck_amount as u32) >> 8))).min(255) as i32;
                }

                // === EFFECTS CHAIN ===
                // Order: Gate -> Compressor -> Overdrive -> Bitcrush -> Waveshaper ->
                //        Chorus -> Flanger -> Phaser -> Comb -> Tremolo -> RingMod ->
                //        PitchShift -> Harmonizer -> Granular ->
                //        EQ -> Delay -> Reverb -> Limiter

                if gate_enabled {
                    gate::process_gate(&mut sample_l, &mut sample_r, s);
                }

                if compressor_enabled {
                    compressor::process_compressor(&mut sample_l, &mut sample_r, s);
                }

                if overdrive_enabled && overdrive_gain_eff > 0 {
                    sample_l = process_overdrive(sample_l, overdrive_gain_eff as u8, s.overdrive_tone);
                    sample_r = sample_l;
                }

                if bitcrush_enabled {
                    s.bitcrush_counter += 1;
                    if s.bitcrush_counter >= s.bitcrush_rate_div {
                        s.bitcrush_counter = 0;
                        let crushed = process_bitcrush(sample_l.clamp(-32768, 32767) as i16, bitcrush_bits_eff as u8);
                        s.bitcrush_hold_l = (crushed >> 8) as i8;
                        s.bitcrush_hold_r = s.bitcrush_hold_l;
                    }
                    sample_l = (s.bitcrush_hold_l as i32) << 8;
                    sample_r = (s.bitcrush_hold_r as i32) << 8;
                }

                if waveshaper_enabled {
                    waveshaper::process_waveshaper(
                        &mut sample_l,
                        &mut sample_r,
                        s.waveshaper_curve,
                        waveshaper_amount_eff as u8,
                        waveshaper_mix_eff as u8,
                    );
                }

                // Chorus (inline)
                if chorus_enabled {
                    let chorus_ptr = s.chorus_buf.as_mut_ptr();
                    let buf_frames = CHORUS_BUF_FRAMES as u8;

                    let lfo_phase_8bit = (s.chorus_lfo_phase >> 24) as u8;
                    let lfo_val = sine_lfo(lfo_phase_8bit) as i32;
                    s.chorus_lfo_phase = s.chorus_lfo_phase.wrapping_add(s.chorus_lfo_inc);

                    let delay_mod = (lfo_val * s.chorus_mod_depth as i32) / 110;
                    let delay = (s.chorus_base_delay as i32 + delay_mod).clamp(1, (buf_frames - 1) as i32) as u8;

                    let read_pos = ((s.chorus_write_pos as i32 + buf_frames as i32 - delay as i32) % buf_frames as i32) as u8;
                    let delayed_l = (*chorus_ptr.add((read_pos * 2) as usize) as i32) << 8;
                    let delayed_r = (*chorus_ptr.add((read_pos * 2 + 1) as usize) as i32) << 8;

                    *chorus_ptr.add((s.chorus_write_pos * 2) as usize) = (sample_l >> 8) as i8;
                    *chorus_ptr.add((s.chorus_write_pos * 2 + 1) as usize) = (sample_r >> 8) as i8;
                    s.chorus_write_pos = (s.chorus_write_pos + 1) % buf_frames;

                    let mix = chorus_mix_eff as i32;
                    sample_l = ((sample_l * (256 - mix)) >> 8) + ((delayed_l * mix) >> 8);
                    sample_r = ((sample_r * (256 - mix)) >> 8) + ((delayed_r * mix) >> 8);
                }

                if flanger_enabled {
                    flanger::process_flanger(&mut sample_l, &mut sample_r, s, flanger_mix_eff as u8);
                }

                if phaser_enabled {
                    phaser::process_phaser(&mut sample_l, &mut sample_r, s, phaser_mix_eff as u8);
                }

                if comb_enabled {
                    comb::process_comb(&mut sample_l, &mut sample_r, s);
                }

                if tremolo_enabled {
                    tremolo::process_tremolo(&mut sample_l, &mut sample_r, s);
                }

                if ringmod_enabled {
                    ring_mod::process_ring_mod(&mut sample_l, &mut sample_r, s);
                }

                if pitch_shift_enabled {
                    pitch_shift::process_pitch_shift(&mut sample_l, &mut sample_r, s);
                }

                if harmonizer_enabled {
                    harmonizer::process_harmonizer(&mut sample_l, &mut sample_r, s);
                }

                if granular_enabled {
                    granular::process_granular(&mut sample_l, &mut sample_r, s, granular_mix_eff as u8);
                }

                if eq_enabled {
                    eq::process_eq(&mut sample_l, &mut sample_r, s);
                }

                // Delay (inline)
                if delay_enabled {
                    let delay_ptr = s.delay_buf.as_mut_ptr();
                    let buf_size = DELAY_BUF_FRAMES as u16;
                    let delay_frames = delay_frames_eff as u16;
                    let feedback = delay_feedback_eff as i32;
                    let mut mix = delay_mix_eff as i32;
                    if duck_active && (s.duck_target & 0x01) != 0 {
                        mix = (mix * duck_gain) >> 8;
                    }
                    let filter_coef = s.delay_filter_coef as i32;

                    let read_pos = if s.delay_write_pos >= delay_frames {
                        s.delay_write_pos - delay_frames
                    } else {
                        buf_size - (delay_frames - s.delay_write_pos)
                    } as usize;

                    let wet_l = *delay_ptr.add(read_pos * 2) as i32;
                    let wet_r = *delay_ptr.add(read_pos * 2 + 1) as i32;

                    let filtered_l = ((s.delay_filter_l as i32 * (256 - filter_coef)) + (wet_l * filter_coef)) >> 8;
                    let filtered_r = ((s.delay_filter_r as i32 * (256 - filter_coef)) + (wet_r * filter_coef)) >> 8;
                    s.delay_filter_l = filtered_l.clamp(-32768, 32767) as i16;
                    s.delay_filter_r = filtered_r.clamp(-32768, 32767) as i16;

                    let fb_l = (filtered_l * feedback) >> 8;
                    let fb_r = (filtered_r * feedback) >> 8;
                    let write_idx = (s.delay_write_pos as usize) * 2;
                    *delay_ptr.add(write_idx) = (sample_l + fb_l).clamp(-32768, 32767) as i16;
                    *delay_ptr.add(write_idx + 1) = (sample_r + fb_r).clamp(-32768, 32767) as i16;
                    s.delay_write_pos = (s.delay_write_pos + 1) % buf_size;

                    let dry_mix = 255 - mix;
                    sample_l = ((sample_l * dry_mix) >> 8) + ((wet_l * mix) >> 8);
                    sample_r = ((sample_r * dry_mix) >> 8) + ((wet_r * mix) >> 8);
                }

                if reverb_enabled {
                    let mut mix = reverb_mix_eff as i32;
                    if duck_active && (s.duck_target & 0x02) != 0 {
                        mix = (mix * duck_gain) >> 8;
                    }
                    reverb::process_reverb(&mut sample_l, &mut sample_r, s, mix.clamp(0, 255) as u8);
                }

                if limiter_enabled {
                    limiter::process_limiter(&mut sample_l, &mut sample_r, s);
                }

                *samples.add(f * 2) = sample_l.clamp(-32768, 32767) as i16;
                *samples.add(f * 2 + 1) = sample_r.clamp(-32768, 32767) as i16;
                f += 1;
            }

            // Output
            if is_inplace {
                // Zero-copy: release the in-place buffer back to READY for downstream
                dev_buffer_release_write(sys, in_chan, total_bytes as u32);
                break; // One buffer per step in mailbox mode
            } else {
                // FIFO: copy processed data to output channel
                let written = (sys.channel_write)(out_chan, s.out_buf.as_ptr(), total_bytes);
                track_pending(written, total_bytes, &mut s.pending_out, &mut s.pending_offset);
                if s.pending_out != 0 { break; }
            }
        }

        0
    }
}

/// Declare that the effects module can operate in-place on its input buffer.
/// The config tool reads this from the .fmod header to enable buffer aliasing
/// (buffer_group assignment) for linear chains like synth → effects → i2s.
#[no_mangle]
#[link_section = ".text.module_in_place_safe"]
pub extern "C" fn module_in_place_safe() -> i32 {
    1
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
