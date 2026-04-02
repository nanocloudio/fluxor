// Effects state structure.

use super::abi::SyscallTable;
use super::constants::*;

#[repr(C)]
pub struct EffectsState {
    pub syscalls: *const SyscallTable,
    pub in_chan: i32,
    pub out_chan: i32,
    pub ctrl_chan: i32,

    // Voice navigation
    pub nav_chan: i32,
    pub current_voice: u8,
    pub voice_count: u8,
    pub _nav_pad: [u8; 2],
    pub voice_table: [[u8; PARAMS_SIZE]; MAX_VOICES],
    pub nav_buf: [u8; 16],

    // Stored params blob
    pub params: [u8; PARAMS_SIZE],
    pub params_len: u16,
    pub _params_pad: [u8; 2],

    // Core config
    pub sample_rate: u32,
    /// Buffer mode: 0=auto (default), 1=inplace (fail if unavailable), 2=fifo (force copy)
    pub buffer_mode: u8,
    pub _bm_pad: [u8; 3],

    // Macro controls / shared modulation
    pub macro1_depth: u8,
    pub macro2_depth: u8,
    pub fx_lfo_depth: u8,
    pub fx_lfo_shape: u8,
    pub fx_lfo_target: u8,
    pub _fxlfo_pad: [u8; 3],
    pub fx_lfo_rate: u16,
    pub fx_lfo_phase: u32,
    pub fx_lfo_inc: u32,
    pub fx_lfo_lfsr: u32,
    pub fx_lfo_sh_value: i16,
    pub _fxlfo_pad2: [u8; 2],

    // Ducking (sidechain-like)
    pub duck_target: u8,
    pub duck_amount: u8,
    pub _duck_pad: [u8; 2],
    pub duck_release_coef: u16,
    pub duck_env: u16,

    // Output tracking
    pub pending_out: u16,
    pub pending_offset: u16,

    // Effect enables (bitmask)
    pub fx_enable: u32,

    // Chorus state
    pub chorus_base_delay: u16,
    pub chorus_mod_depth: u16,
    pub chorus_lfo_phase: u32,
    pub chorus_lfo_inc: u32,
    pub chorus_mix: u8,
    pub chorus_write_pos: u8,
    pub _chorus_pad: u16,

    // Delay state
    pub delay_frames: u16,
    pub delay_feedback: u8,
    pub delay_mix: u8,
    pub delay_write_pos: u16,
    pub delay_filter_l: i16,
    pub delay_filter_r: i16,
    pub delay_filter_coef: u8,
    pub _delay_pad: [u8; 3],

    // Bitcrush state
    pub bitcrush_bits: u8,
    pub bitcrush_rate_div: u8,
    pub bitcrush_counter: u8,
    pub bitcrush_hold_l: i8,
    pub bitcrush_hold_r: i8,
    pub _bc_pad: [u8; 3],

    // Overdrive state
    pub overdrive_gain: u8,
    pub overdrive_tone: u8,
    pub _od_pad: u16,

    // Tremolo state
    pub tremolo_lfo_phase: u32,
    pub tremolo_lfo_inc: u32,
    pub tremolo_depth: u8,
    pub tremolo_shape: u8,
    pub _tremolo_pad: u16,

    // Ring modulator state
    pub ringmod_carrier_phase: u32,
    pub ringmod_carrier_inc: u32,
    pub ringmod_mix: u8,
    pub _ringmod_pad: [u8; 3],

    // Waveshaper state
    pub waveshaper_curve: u8,
    pub waveshaper_amount: u8,
    pub waveshaper_mix: u8,
    pub _waveshaper_pad: u8,

    // Limiter state
    pub limiter_threshold: i16,
    pub limiter_mode: u8,
    pub _limiter_pad: u8,

    // Gate state
    pub gate_threshold: u16,
    pub gate_attack_coef: u16,
    pub gate_release_coef: u16,
    pub gate_hold_samples: u16,
    pub gate_state: u8,
    pub gate_range: u8,
    pub gate_gain: u16,
    pub gate_env_level: u16,
    pub gate_hold_counter: u16,

    // Compressor state
    pub comp_threshold: u16,
    pub comp_ratio: u8,
    pub comp_makeup: u8,
    pub comp_mix: u8,
    pub _comp_pad: u8,
    pub comp_attack_coef: u16,
    pub comp_release_coef: u16,
    pub comp_current_gain: u16,
    pub comp_envelope: u16,

    // Phaser state
    pub phaser_lfo_phase: u32,
    pub phaser_lfo_inc: u32,
    pub phaser_depth: u8,
    pub phaser_feedback: u8,
    pub phaser_stages: u8,
    pub phaser_mix: u8,
    pub phaser_allpass_l: [i16; MAX_PHASER_STAGES],
    pub phaser_allpass_r: [i16; MAX_PHASER_STAGES],
    pub phaser_feedback_l: i16,
    pub phaser_feedback_r: i16,

    // EQ raw params (for TLV v2 post-parse derivation)
    pub eq_low_freq_raw: u16,
    pub eq_low_gain_raw: u8,
    pub eq_mid_gain_raw: u8,
    pub eq_mid_freq_raw: u16,
    pub eq_mid_q_raw: u8,
    pub eq_high_gain_raw: u8,
    pub eq_high_freq_raw: u16,
    pub _eq_raw_pad: u16,

    // EQ state (3 bands, biquad coefficients and per-channel state)
    pub eq_coefs: [[i32; 5]; NUM_EQ_BANDS],    // [band][b0,b1,b2,a1,a2]
    pub eq_state_l: [[i32; 4]; NUM_EQ_BANDS],  // [band][x1,x2,y1,y2]
    pub eq_state_r: [[i32; 4]; NUM_EQ_BANDS],  // [band][x1,x2,y1,y2]

    // Flanger state
    pub flanger_lfo_phase: u32,
    pub flanger_lfo_inc: u32,
    pub flanger_depth: u8,
    pub flanger_feedback: u8,
    pub flanger_manual: u8,
    pub flanger_mix: u8,
    pub flanger_write_idx: u16,
    pub flanger_feedback_l: i16,
    pub flanger_feedback_r: i16,
    pub _flanger_pad: u16,

    // Comb filter state
    pub comb_delay_samples: u16,
    pub comb_feedback: u8,
    pub comb_mix: u8,
    pub comb_write_pos: u16,
    pub _comb_pad: u16,

    // Reverb state
    pub reverb_decay: u8,
    pub reverb_damping: u8,
    pub reverb_mix: u8,
    pub _reverb_param_pad: u8,
    pub reverb_predelay_len: u16,
    pub reverb_predelay_idx: u16,
    pub reverb_comb_idx: [u16; 4],
    pub reverb_allpass_idx: [u16; 2],
    pub reverb_damp_l: i16,
    pub reverb_damp_r: i16,

    // Pitch shift state
    pub ps_read_inc: u32,
    pub ps_window_size: u16,
    pub ps_mix: u8,
    pub ps_direction: i8,
    pub ps_write_pos: u16,
    pub ps_xfade_pos: u16,
    pub ps_read_pos_a: u32,
    pub ps_read_pos_b: u32,
    pub ps_active_reader: u8,
    pub _ps_pad: [u8; 3],

    // Harmonizer state
    pub harm_v1_read_inc: u32,
    pub harm_v1_level: u8,
    pub harm_v1_active: u8,
    pub harm_v1_active_reader: u8,
    pub _harm_v1_pad: u8,
    pub harm_v1_read_pos_a: u32,
    pub harm_v1_read_pos_b: u32,
    pub harm_v1_xfade_pos: u16,
    pub harm_v2_read_inc: u32,
    pub harm_v2_level: u8,
    pub harm_v2_active: u8,
    pub harm_v2_active_reader: u8,
    pub _harm_v2_pad: u8,
    pub harm_v2_read_pos_a: u32,
    pub harm_v2_read_pos_b: u32,
    pub harm_v2_xfade_pos: u16,
    pub harm_dry_level: u8,
    pub _harm_pad: u8,
    pub harm_write_pos: u16,

    // Granular state
    pub granular_grain_size: u16,
    pub granular_trigger_interval: u16,
    pub granular_trigger_counter: u16,
    pub granular_next_grain: u8,
    pub granular_spread: u8,
    pub granular_pitch_inc: u32,
    pub granular_mix: u8,
    pub _granular_pad: u8,
    pub granular_write_pos: u16,
    pub granular_lfsr: u16,
    pub _granular_pad2: u16,
    pub grain_active: [u8; MAX_GRAINS],
    pub grain_read_pos: [u32; MAX_GRAINS],
    pub grain_read_inc: [u32; MAX_GRAINS],
    pub grain_env_pos: [u16; MAX_GRAINS],
    pub grain_len: [u16; MAX_GRAINS],
    pub grain_start_pos: [u16; MAX_GRAINS],

    // Buffers (at end for alignment)
    pub chorus_buf: [i8; CHORUS_BUF_FRAMES * 2],
    pub delay_buf: [i16; DELAY_BUF_FRAMES * 2],
    pub flanger_buf_l: [i16; FLANGER_BUF_SIZE],
    pub flanger_buf_r: [i16; FLANGER_BUF_SIZE],
    pub comb_buf: [i8; COMB_BUF_SIZE],
    pub reverb_buf: [i16; REVERB_TOTAL_BUF],
    pub ps_buf_l: [i16; PITCH_BUF_SIZE],
    pub ps_buf_r: [i16; PITCH_BUF_SIZE],
    pub harm_buf: [i16; PITCH_BUF_SIZE],
    pub granular_buf: [i16; GRAIN_BUF_SIZE],
    pub out_buf: [u8; OUT_BUF_SIZE],
}
