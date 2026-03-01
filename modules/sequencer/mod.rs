//! Sequencer PIC Module
//!
//! Position-independent module for sequence-based value generation.
//! Produces timestamped events with frame-accurate timing.
//!
//! Output format: { target_frame: u32, freq: u16, velocity: u8, flags: u8 } (8 bytes)
//!
//! Control input (FMP messages from bank/gesture):
//!   - `status`: { index: u16, count: u16, ... } — switch to preset[index]
//!   - `toggle`: pause/resume playback
//!   - `select`: { index: u16 } — jump to specific preset
//!
//! Timing is based on frames (stream clock) not wall-clock (millis).

#![no_std]

use core::ffi::c_void;

#[path = "../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../pic_runtime.rs");
include!("../param_macro.rs");

mod presets;
mod params_def;

// ============================================================================
// Constants
// ============================================================================

/// Maximum sequence length
pub const MAX_SEQUENCE_LEN: usize = 128;

/// Note event size (8 bytes)
const NOTE_EVENT_SIZE: usize = 8;

/// Maximum number of presets that can be stored
pub const MAX_PRESETS: usize = 4;

/// Maximum length of each preset sequence
pub const MAX_PRESET_LEN: usize = 128;

/// Default sample rate (Hz)
const DEFAULT_SAMPLE_RATE: u32 = 8000;

/// Sequencer playback modes
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum SeqMode {
    OneShot = 0,
    Loop = 1,
    PingPong = 2,
}

/// Sequencer state
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum SeqState {
    Stopped = 0,
    Running = 1,
    Paused = 2,
    Finished = 3,
}

// ============================================================================
// State Structure
// ============================================================================

#[repr(C)]
pub struct Sequencer {
    syscalls: *const SyscallTable,
    pub in_chan: i32,
    pub out_chan: i32,
    pub values: [u16; MAX_SEQUENCE_LEN],
    pub length: u8,
    pub position: u8,
    pub mode: SeqMode,
    pub state: SeqState,
    pub direction: i8,
    pub started: u8,
    pub current_preset: u8,
    pub preset_count: u8,
    pub sample_rate: u32,
    pub step_frames: u32,
    pub next_change_frame: u32,
    pub current_value: u16,
    pub last_value_sent: u16,
    pub step_count: u32,
    pub event_count: u16,
    pub diag_count: u16,
    /// PIO consumed_units at first step (anchor for hw-synced frame counting)
    pub hw_frame_base: u64,
    /// Whether we've synced to hardware stream time
    pub hw_synced: u8,
    /// Retrigger: send events even for repeated same values (for drum patterns)
    pub retrigger: u8,
    pub _hw_pad: [u8; 2],
    /// Accumulated downstream latency in frames (from kernel graph walk)
    pub downstream_latency_frames: u32,
    /// Millis timestamp of last step advance (for timing gate)
    pub last_advance_ms: u32,

    // Generative
    pub lfsr: u32,
    pub probability: u8,
    pub random_pitch: u8,
    pub octave_range: u8,
    pub velocity_min: u8,
    pub velocity_max: u8,
    pub timing_jitter_ms: u8,
    pub velocity_jitter_pct: u8,
    pub humanize_prob: u8,
    pub ratchet_count: u8,
    pub ratchet_spacing: u8,
    pub ratchet_vel_falloff: u8,
    pub play_every_n_loops: u8,
    pub skip_probability: u8,
    pub fill_on_loop_end: u8,
    pub auto_advance_preset: u8,
    pub _gen_pad: [u8; 2],
    pub output_freq: u16,
    pub output_vel: u8,
    pub _out_pad: u8,

    // Conditional/ratchet state
    pub loop_count: u32,
    pub loop_just_ended: u8,
    pub ratchet_pending: u8,
    pub ratchet_index: u8,
    pub _ratchet_pad: [u8; 2],
    pub ratchet_base_frame: u32,
    pub ratchet_freq: u16,
    pub ratchet_vel: u8,
    pub _ratchet_pad2: u8,

    pub preset_lengths: [u8; MAX_PRESETS],
    pub preset_values: [[u16; MAX_PRESET_LEN]; MAX_PRESETS],
    pub msg_buf: [u8; 16],
}

// ============================================================================
// Helper functions
// ============================================================================

/// Write u16 as 4-char hex to buffer.
#[inline(always)]
unsafe fn write_u16_hex(dst: *mut u8, val: u16) {
    const HEX: [u8; 16] = *b"0123456789ABCDEF";
    *dst = HEX[((val >> 12) & 0xF) as usize];
    *dst.add(1) = HEX[((val >> 8) & 0xF) as usize];
    *dst.add(2) = HEX[((val >> 4) & 0xF) as usize];
    *dst.add(3) = HEX[(val & 0xF) as usize];
}

/// Write u8 as 2-char hex to buffer.
#[inline(always)]
unsafe fn write_u8_hex(dst: *mut u8, val: u8) {
    const HEX: [u8; 16] = *b"0123456789ABCDEF";
    *dst = HEX[((val >> 4) & 0xF) as usize];
    *dst.add(1) = HEX[(val & 0xF) as usize];
}

#[inline(always)]
unsafe fn read_u16_at(ptr: *const u8, offset: usize) -> u16 {
    let p = ptr.add(offset);
    u16::from_le_bytes([*p, *p.add(1)])
}

#[inline(always)]
unsafe fn read_u32_at(ptr: *const u8, offset: usize) -> u32 {
    let p = ptr.add(offset);
    u32::from_le_bytes([*p, *p.add(1), *p.add(2), *p.add(3)])
}

// ============================================================================
// Helpers
// ============================================================================

#[inline(always)]
fn lfsr_next(lfsr: &mut u32) -> u32 {
    let bit = ((*lfsr) ^ (*lfsr >> 1) ^ (*lfsr >> 21) ^ (*lfsr >> 31)) & 1;
    *lfsr = (*lfsr >> 1) | (bit << 31);
    *lfsr
}

// ============================================================================
// Module API
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<Sequencer>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<Sequencer>() {
            return -2;
        }

        let seq = &mut *(state as *mut Sequencer);
        seq.syscalls = syscalls as *const SyscallTable;
        seq.in_chan = in_chan;
        seq.out_chan = out_chan;

        // Zero-initialize runtime state
        let values_ptr = seq.values.as_mut_ptr();
        for i in 0..MAX_SEQUENCE_LEN {
            core::ptr::write_volatile(values_ptr.add(i), 0);
        }
        seq.length = 0;
        seq.position = 0;
        seq.state = SeqState::Running;
        seq.direction = 1;
        seq.started = 0;
        seq.current_preset = 0;
        seq.preset_count = 0;
        seq.sample_rate = DEFAULT_SAMPLE_RATE;
        seq.step_frames = (500u32 * DEFAULT_SAMPLE_RATE) / 1000;
        seq.next_change_frame = 0;
        seq.current_value = 0;
        seq.last_value_sent = 0xFFFF;
        seq.step_count = 0;
        seq.event_count = 0;
        seq.diag_count = 0;

        // Generative defaults (all off — deterministic behavior preserved)
        let sys_tmp = &*seq.syscalls;
        let seed = dev_millis(sys_tmp) as u32;
        seq.lfsr = if seed != 0 { seed } else { 0xDEAD_BEEF };
        seq.probability = 255;
        seq.random_pitch = 0;
        seq.octave_range = 0;
        seq.velocity_min = 200;
        seq.velocity_max = 200;
        seq.timing_jitter_ms = 0;
        seq.velocity_jitter_pct = 0;
        seq.humanize_prob = 0;
        seq.ratchet_count = 1;
        seq.ratchet_spacing = 0;
        seq.ratchet_vel_falloff = 0;
        seq.play_every_n_loops = 0;
        seq.skip_probability = 0;
        seq.fill_on_loop_end = 0;
        seq.auto_advance_preset = 0;
        seq.output_freq = 0;
        seq.output_vel = 200;
        seq.loop_count = 0;
        seq.loop_just_ended = 0;
        seq.ratchet_pending = 0;
        seq.ratchet_index = 0;
        seq.ratchet_base_frame = 0;
        seq.ratchet_freq = 0;
        seq.ratchet_vel = 0;

        // Zero-initialize preset storage
        let lengths_ptr = seq.preset_lengths.as_mut_ptr();
        let values_base = seq.preset_values.as_mut_ptr() as *mut u16;
        for i in 0..MAX_PRESETS {
            core::ptr::write_volatile(lengths_ptr.add(i), 0);
            for j in 0..MAX_PRESET_LEN {
                core::ptr::write_volatile(values_base.add(i * MAX_PRESET_LEN + j), 0);
            }
        }

        // Parse params: detect TLV v2 vs legacy format
        let is_tlv_v2 = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x02;

        if is_tlv_v2 {
            // TLV v2: per-param tags (schema-driven)
            // set_defaults sets sample_rate, step_frames, mode.
            // Preset u16_array tags accumulate via preset_count.
            params_def::parse_tlv_v2(seq, params, params_len);
        } else {
            // Legacy fixed-offset format
            let sample_rate = if !params.is_null() && params_len >= 4 {
                let sr = read_u32_at(params, 0);
                if sr > 0 { sr } else { DEFAULT_SAMPLE_RATE }
            } else {
                DEFAULT_SAMPLE_RATE
            };
            let step_ms = if !params.is_null() && params_len >= 6 {
                read_u16_at(params, 4)
            } else {
                500
            };
            let mode_val = if !params.is_null() && params_len >= 7 {
                *params.add(6)
            } else {
                2
            };
            seq.mode = match mode_val {
                0 => SeqMode::OneShot,
                1 => SeqMode::Loop,
                _ => SeqMode::PingPong,
            };
            seq.sample_rate = sample_rate;
            seq.step_frames = (step_ms as u32 * sample_rate) / 1000;

            // Load presets from legacy format or defaults
            let preset_count = if !params.is_null() && params_len >= 8 {
                (*params.add(7)).min(MAX_PRESETS as u8)
            } else {
                0
            };
            if preset_count > 0 && !params.is_null() && params_len >= 8 + preset_count as usize {
                presets::init_from_params(seq, params, params_len, preset_count);
            }
        }

        // No presets = nothing to play. The config tool should have caught this.
        if seq.preset_count == 0 {
            dev_log(
                &*seq.syscalls, 1,
                b"[seq] error: no presets provided\0".as_ptr(), 31,
            );
            return -10;
        }

        presets::load_preset(seq, 0);

        // Sync to hardware time if a PIO stream is available (rate_q16 > 0).
        // When no stream is present (LED-only configs, etc.), fall back to
        // millis-based timing in the step gate.
        let sys = &*seq.syscalls;
        let (_, _, rate_q16, _) = dev_stream_time(sys);
        if rate_q16 > 0 {
            seq.hw_synced = 1;
            seq.hw_frame_base = 0;
        } else {
            seq.hw_synced = 0;
        }
        seq.downstream_latency_frames = dev_downstream_latency(sys);

        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let seq = &mut *(state as *mut Sequencer);
        if seq.syscalls.is_null() {
            return -1;
        }

        let sys = &*seq.syscalls;

        // Process control input events (FMP messages)
        if seq.in_chan >= 0 {
            let poll_in = (sys.channel_poll)(seq.in_chan, POLL_IN);
            if poll_in > 0 && ((poll_in as u8) & POLL_IN) != 0 {
                let (ty, len) = msg_read(sys, seq.in_chan, seq.msg_buf.as_mut_ptr(), 16);
                if ty != 0 {
                    match ty {
                        MSG_STATUS => {
                            // Bank status: { index: u16, count: u16, file_type: u8, paused: u8 }
                            if len >= 2 {
                                let index = u16::from_le_bytes([seq.msg_buf[0], seq.msg_buf[1]]);
                                if seq.preset_count > 0 && (index as usize) < seq.preset_count as usize {
                                    presets::load_preset(seq, index as u8);
                                }
                            }
                            if len >= 6 {
                                let paused = seq.msg_buf[5];
                                if paused != 0 {
                                    seq.state = SeqState::Paused;
                                } else {
                                    seq.state = SeqState::Running;
                                }
                            }
                        }
                        MSG_TOGGLE => {
                            if seq.state == SeqState::Running {
                                seq.state = SeqState::Paused;
                            } else if seq.state == SeqState::Paused {
                                seq.state = SeqState::Running;
                            }
                        }
                        MSG_SELECT => {
                            if len >= 2 {
                                let index = u16::from_le_bytes([seq.msg_buf[0], seq.msg_buf[1]]);
                                if seq.preset_count > 0 && (index as usize) < seq.preset_count as usize {
                                    presets::load_preset(seq, index as u8);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        let out_chan = seq.out_chan;

        if seq.state != SeqState::Running || seq.length == 0 {
            return 0;
        }

        // Timing gate: don't advance until the hardware stream has played past
        // next_change_frame. Uses the PIO consumed-frame counter for sample-accurate
        // timing on an absolute grid (no jitter accumulation). Falls back to millis
        // when hw stream isn't synced yet.
        if seq.started != 0 && seq.step_frames > 0 {
            if seq.hw_synced != 0 {
                let (consumed, _, _, _) = dev_stream_time(sys);
                let played = (consumed as u32).wrapping_sub(seq.hw_frame_base as u32);
                if played < seq.next_change_frame {
                    return 0;
                }
            } else {
                let now_ms = dev_millis(sys) as u32;
                let step_ms_val = (seq.step_frames * 1000) / seq.sample_rate.max(1);
                if step_ms_val > 0 && now_ms.wrapping_sub(seq.last_advance_ms) < step_ms_val {
                    return 0;
                }
            }
        }

        // Advance to next note after current event has been sent (and ratchets complete)
        if seq.started != 0 && seq.current_value == seq.last_value_sent && seq.ratchet_pending == 0 {
            seq.next_change_frame = seq.next_change_frame.wrapping_add(seq.step_frames);
            seq.step_count += 1;
            seq.last_advance_ms = dev_millis(sys) as u32;

            let len = seq.length as i8;
            let mut new_pos = seq.position as i8 + seq.direction;

            match seq.mode {
                SeqMode::OneShot => {
                    if new_pos >= len || new_pos < 0 {
                        seq.state = SeqState::Finished;
                        return 0;
                    }
                }
                SeqMode::Loop => {
                    if new_pos >= len {
                        new_pos = 0;
                    } else if new_pos < 0 {
                        new_pos = len - 1;
                    }
                }
                SeqMode::PingPong => {
                    if new_pos >= len {
                        seq.direction = -1;
                        new_pos = len - 2;
                        if new_pos < 0 { new_pos = 0; }
                    } else if new_pos < 0 {
                        seq.direction = 1;
                        new_pos = 1;
                        if new_pos >= len { new_pos = 0; }
                    }
                }
            }

            seq.position = new_pos as u8;
            seq.current_value = *seq.values.as_ptr().add(new_pos as usize);

            // Track loop boundary (used by conditional steps + auto-advance)
            if seq.mode != SeqMode::OneShot && seq.position == 0 && seq.started != 0 {
                seq.loop_count = seq.loop_count.wrapping_add(1);
                seq.loop_just_ended = 1;
                // Auto-advance to next preset on loop boundary
                if seq.auto_advance_preset != 0 && seq.preset_count > 1 {
                    let next = seq.current_preset + 1;
                    let next = if (next as usize) >= seq.preset_count as usize { 0 } else { next };
                    presets::load_preset(seq, next);
                }
            }
        }

        // Send pending ratchets (if any)
        if seq.ratchet_pending > 0 {
            let poll = (sys.channel_poll)(out_chan, POLL_OUT);
            if poll > 0 && ((poll as u8) & POLL_OUT) != 0 {
                let idx = seq.ratchet_index;
                let count = if seq.ratchet_count == 0 { 1 } else { seq.ratchet_count };

                // Compute ratchet offset in frames
                let step_frames = seq.step_frames.max(1);
                let offset = if count <= 1 {
                    0
                } else {
                    match seq.ratchet_spacing {
                        // even
                        0 => (step_frames * (idx as u32)) / (count as u32),
                        // accel (early wide, later tight)
                        1 => {
                            let n = count as u32;
                            let sum = n * (n + 1) / 2;
                            let mut acc = 0u32;
                            let mut k = 0u32;
                            while k < idx as u32 {
                                acc += n - k;
                                k += 1;
                            }
                            (step_frames * acc) / sum.max(1)
                        }
                        // decel (early tight, later wide)
                        _ => {
                            let n = count as u32;
                            let sum = n * (n + 1) / 2;
                            let mut acc = 0u32;
                            let mut k = 0u32;
                            while k < idx as u32 {
                                acc += k + 1;
                                k += 1;
                            }
                            (step_frames * acc) / sum.max(1)
                        }
                    }
                };

                let mut abs_frame = if seq.hw_synced != 0 {
                    let abs = (seq.hw_frame_base as u32).wrapping_add(seq.ratchet_base_frame.wrapping_add(offset));
                    abs.wrapping_sub(seq.downstream_latency_frames)
                } else {
                    seq.ratchet_base_frame.wrapping_add(offset)
                };

                // Apply optional timing jitter (humanize)
                if seq.humanize_prob > 0 && seq.timing_jitter_ms > 0 {
                    let roll = (lfsr_next(&mut seq.lfsr) % 100) as u8;
                    if roll < seq.humanize_prob {
                        let jitter_frames = (seq.timing_jitter_ms as u32 * seq.sample_rate) / 1000;
                        if jitter_frames > 0 {
                            let span = (jitter_frames * 2 + 1) as u32;
                            let r = (lfsr_next(&mut seq.lfsr) % span) as i32;
                            let jitter = r - (jitter_frames as i32);
                            abs_frame = (abs_frame as i32 + jitter).max(0) as u32;
                        }
                    }
                }

                // Avoid scheduling in the past
                if seq.hw_synced != 0 {
                    let (consumed, _, _, _) = dev_stream_time(sys);
                    if abs_frame < consumed as u32 {
                        abs_frame = consumed as u32;
                    }
                }

                let mut vel = seq.ratchet_vel;
                if seq.ratchet_vel_falloff > 0 && idx > 0 {
                    let fall = (seq.ratchet_vel_falloff as u32 * idx as u32) / 100;
                    let dec = (vel as u32 * fall) / 100;
                    vel = vel.saturating_sub(dec as u8);
                }

                let mut msg_buf: [u8; NOTE_EVENT_SIZE] = [0; NOTE_EVENT_SIZE];
                let frame_bytes = abs_frame.to_le_bytes();
                msg_buf[0] = frame_bytes[0];
                msg_buf[1] = frame_bytes[1];
                msg_buf[2] = frame_bytes[2];
                msg_buf[3] = frame_bytes[3];
                let freq_bytes = seq.ratchet_freq.to_le_bytes();
                msg_buf[4] = freq_bytes[0];
                msg_buf[5] = freq_bytes[1];
                msg_buf[6] = vel;
                let written = (sys.channel_write)(out_chan, msg_buf.as_ptr(), NOTE_EVENT_SIZE);
                if written == NOTE_EVENT_SIZE as i32 {
                    seq.ratchet_pending -= 1;
                    seq.ratchet_index = seq.ratchet_index.wrapping_add(1);
                    if seq.ratchet_pending == 0 {
                        seq.last_value_sent = seq.current_value;
                    }
                }
            }
        }

        // Send event if value has changed, or retrigger mode forces re-send
        if seq.ratchet_pending == 0 && (seq.current_value != seq.last_value_sent || seq.retrigger != 0) {
            let is_fill = seq.fill_on_loop_end != 0 && seq.loop_just_ended != 0;

            // --- Generative: probability gate ---
            if !is_fill && seq.probability < 255 {
                let roll = (lfsr_next(&mut seq.lfsr) & 0xFF) as u8;
                if roll >= seq.probability {
                    seq.last_value_sent = seq.current_value;
                    seq.started = 1; // Enable advancement past gated notes
                    seq.loop_just_ended = 0;
                    return 0;
                }
            }

            // --- Conditional: play every N loops ---
            if !is_fill && seq.play_every_n_loops > 1 {
                let n = seq.play_every_n_loops as u32;
                if n > 0 && (seq.loop_count % n) != 0 {
                    seq.last_value_sent = seq.current_value;
                    seq.started = 1;
                    seq.loop_just_ended = 0;
                    return 0;
                }
            }

            // --- Conditional: skip probability ---
            if !is_fill && seq.skip_probability > 0 {
                let roll = (lfsr_next(&mut seq.lfsr) % 100) as u8;
                if roll < seq.skip_probability {
                    seq.last_value_sent = seq.current_value;
                    seq.started = 1;
                    seq.loop_just_ended = 0;
                    return 0;
                }
            }

            // --- Generative: random pitch ---
            let mut freq = if seq.random_pitch != 0 && seq.length > 0 {
                let idx = (lfsr_next(&mut seq.lfsr) % seq.length as u32) as usize;
                *seq.values.as_ptr().add(idx)
            } else {
                seq.current_value
            };

            // --- Generative: octave shift ---
            if seq.octave_range > 0 {
                let range = (seq.octave_range as u32) * 2 + 1;
                let r = lfsr_next(&mut seq.lfsr) % range;
                let shift = r as i8 - seq.octave_range as i8;
                if shift > 0 {
                    let shifted = (freq as u32) << (shift as u32);
                    freq = if shifted > 20000 { 20000 } else { shifted as u16 };
                } else if shift < 0 {
                    freq >>= (-shift) as u32;
                    if freq < 20 { freq = 20; }
                }
            }

            // --- Generative: velocity variation ---
            let vel = if seq.velocity_min >= seq.velocity_max {
                seq.velocity_min
            } else {
                let range = (seq.velocity_max - seq.velocity_min) as u32 + 1;
                seq.velocity_min + (lfsr_next(&mut seq.lfsr) % range) as u8
            };

            let mut vel = vel;
            // --- Humanize: velocity jitter ---
            if seq.humanize_prob > 0 && seq.velocity_jitter_pct > 0 {
                let roll = (lfsr_next(&mut seq.lfsr) % 100) as u8;
                if roll < seq.humanize_prob {
                    let span = ((vel as u32 * seq.velocity_jitter_pct as u32) / 100) as i32;
                    if span > 0 {
                        let r = (lfsr_next(&mut seq.lfsr) % ((span * 2 + 1) as u32)) as i32;
                        let jitter = r - span;
                        vel = (vel as i32 + jitter).clamp(0, 255) as u8;
                    }
                }
            }

            seq.output_freq = freq;
            seq.output_vel = vel;

            let poll = (sys.channel_poll)(out_chan, POLL_OUT);
            if poll > 0 && ((poll as u8) & POLL_OUT) != 0 {
                // Compute absolute target frame: hw base + relative position - downstream latency
                let mut abs_frame = if seq.hw_synced != 0 {
                    let abs = (seq.hw_frame_base as u32).wrapping_add(seq.next_change_frame);
                    abs.wrapping_sub(seq.downstream_latency_frames)
                } else {
                    seq.next_change_frame
                };

                // Apply timing jitter to base event
                if seq.humanize_prob > 0 && seq.timing_jitter_ms > 0 {
                    let roll = (lfsr_next(&mut seq.lfsr) % 100) as u8;
                    if roll < seq.humanize_prob {
                        let jitter_frames = (seq.timing_jitter_ms as u32 * seq.sample_rate) / 1000;
                        if jitter_frames > 0 {
                            let span = (jitter_frames * 2 + 1) as u32;
                            let r = (lfsr_next(&mut seq.lfsr) % span) as i32;
                            let jitter = r - (jitter_frames as i32);
                            abs_frame = (abs_frame as i32 + jitter).max(0) as u32;
                        }
                    }
                }

                if seq.hw_synced != 0 {
                    let (consumed, _, _, _) = dev_stream_time(sys);
                    if abs_frame < consumed as u32 {
                        abs_frame = consumed as u32;
                    }
                }

                // Initialize ratchet state (at least one hit)
                let rc = if seq.ratchet_count == 0 { 1 } else { seq.ratchet_count };
                seq.ratchet_pending = rc;
                seq.ratchet_index = 0;
                seq.ratchet_base_frame = seq.next_change_frame;
                seq.ratchet_freq = freq;
                seq.ratchet_vel = vel;

                let mut msg_buf: [u8; NOTE_EVENT_SIZE] = [0; NOTE_EVENT_SIZE];
                let frame_bytes = abs_frame.to_le_bytes();
                msg_buf[0] = frame_bytes[0];
                msg_buf[1] = frame_bytes[1];
                msg_buf[2] = frame_bytes[2];
                msg_buf[3] = frame_bytes[3];
                let freq_bytes = freq.to_le_bytes();
                msg_buf[4] = freq_bytes[0];
                msg_buf[5] = freq_bytes[1];
                msg_buf[6] = vel;

                let written = (sys.channel_write)(out_chan, msg_buf.as_ptr(), NOTE_EVENT_SIZE);
                if written == NOTE_EVENT_SIZE as i32 {
                    seq.ratchet_pending = seq.ratchet_pending.saturating_sub(1);
                    seq.ratchet_index = seq.ratchet_index.wrapping_add(1);
                    if seq.ratchet_pending == 0 {
                        seq.last_value_sent = seq.current_value;
                    }
                    if seq.started == 0 {
                        seq.last_advance_ms = dev_millis(sys) as u32;
                    }
                    seq.started = 1;
                    seq.event_count = seq.event_count.wrapping_add(1);
                    seq.loop_just_ended = 0;
                }
            }
        }

        0
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
