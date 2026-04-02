// Synth state structures.

use super::abi::SyscallTable;
use super::constants::*;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NoteEvent {
    pub target_frame: u32,
    pub freq: u16,
    pub velocity: u8,
    pub flags: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EnvState {
    pub phase: EnvPhase,
    pub _pad: u8,
    pub level: u16,
    pub attack_rate: u16,
    pub decay_rate: u16,
    pub sustain_level: u16,
    pub release_rate: u16,
}

/// Per-voice state: oscillator, filter, envelopes, pluck buffer.
#[repr(C)]
pub struct VoiceState {
    pub phase: u32,
    pub sub_phase: u32,
    pub freq_inc: u32,
    pub target_freq_inc: u32,
    pub glide_rate: u32,
    pub lfsr: u32,
    pub filter_low: i32,
    pub filter_band: i32,
    pub filter_env: EnvState,
    pub amp_env: EnvState,
    pub note_on: u8,
    pub last_velocity: u8,
    pub age: u16,
    pub pluck_delay_len: u16,
    pub pluck_read_pos: u16,
    pub pluck_prev_sample: i16,
    pub _voice_pad: u16,
    pub pluck_buf: [i16; PLUCK_BUF_SIZE],
}

#[repr(C)]
pub struct SynthState {
    pub syscalls: *const SyscallTable,
    pub in_chan: i32,
    pub out_chan: i32,
    pub ctrl_chan: i32,

    // Voice navigation (ctrl.1)
    pub nav_chan: i32,
    pub current_voice: u8,
    pub voice_count: u8,
    pub _nav_pad: [u8; 2],
    pub voice_table: [[u8; PARAMS_SIZE]; MAX_VOICES],
    pub nav_buf: [u8; 16],

    // Stored params blob (canonical config interface)
    pub params: [u8; PARAMS_SIZE],
    pub params_len: u16,
    pub _params_pad: [u8; 2],

    // Core synth (shared across voices)
    pub sample_rate: u32,
    pub render_frame: u32,
    pub waveform: u8,
    pub pulse_width: u8,
    pub sub_level: u8,
    pub _osc_pad: u8,

    // Filter (shared params)
    pub cutoff: u8,
    pub resonance: u8,
    pub env_amount: u8,
    pub key_track: u8,

    // Template envelopes (TLV parsers write rates here, propagated to voices)
    pub filter_env: EnvState,
    pub amp_env: EnvState,

    // Performance (shared)
    pub accent: u8,
    pub glide_mode: u8,
    pub glide_ms: u16,
    pub drive: u8,
    pub level: u8,
    pub pluck_decay: u8,
    pub pluck_brightness: u8,
    pub pan: u8,
    pub vel_to_cutoff: u8,
    pub vel_to_drive: u8,
    pub vel_to_lfo_depth: u8,
    pub vel_to_env_amt: u8,
    pub voice_detune_cents: u8,
    pub detune_curve: u8,
    pub env_loop: u8,
    pub loop_rate_scale: u8,
    pub last_note_velocity: u8,
    pub _perf_pad: u8,

    // Output tracking
    pub pending_out: u16,
    pub pending_offset: u16,

    // Event queue
    pub event_queue: [NoteEvent; EVENT_QUEUE_SIZE],
    pub queue_head: u8,
    pub queue_tail: u8,

    // Polyphony
    pub poly_count: u8,
    pub _poly_pad: u8,
    pub voice_alloc_counter: u16,

    // Diagnostics
    pub event_count: u16,
    pub audio_count: u16,
    pub step_count: u16,
    pub _diag_pad: u16,

    // LFO
    pub lfo_phase: u32,
    pub lfo_freq_inc: u32,
    pub lfo_rate: u16,
    pub lfo_depth: u8,
    pub lfo_waveform: u8,
    pub lfo_target: u8,
    pub _lfo_pad: [u8; 3],
    pub lfo_lfsr: u32,
    pub lfo_sh_value: i16,
    pub _lfo_pad2: [u8; 2],

    // Per-voice state (at end for alignment)
    pub voices: [VoiceState; MAX_POLY],

    pub out_buf: [u8; OUT_BUF_SIZE],
}
