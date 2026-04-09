//! Synth PIC Module
//!
//! Synthesizer voice:
//! - Multi-waveform oscillator (saw, square, triangle, pulse, noise, sine, pluck)
//! - Sub-oscillator (one octave down)
//! - Resonant lowpass filter with envelope modulation
//! - Filter and amplitude ADSR envelopes
//! - Glide/portamento
//! - Soft drive
//! - N-voice polyphony (1-4, default mono)
//!
//! Effects are handled by the separate `effects` module in the graph.
//!
//! # Channels
//! - `in`: Note events [target_frame: u32, freq_hz: u16, velocity: u8, flags: u8]
//! - `ctrl.0`: Runtime parameter changes (see Ctrl Protocol below)
//! - `ctrl.1`: Navigation commands (FMP messages, optional)
//! - `out`: Stereo i16 audio samples
//!
//! # Voice Navigation (ctrl.1)
//!
//! When a second ctrl port is wired, the synth listens for FMP navigation
//! messages to cycle between stored voice presets:
//!   - `next`: advance to next voice preset
//!   - `prev`: go to previous voice preset
//!
//! # Ctrl Protocol
//!
//! Messages are discriminated by the first byte:
//!
//! - `[0x00, offset, value_lo, value_hi]` -- 4 bytes: patch single param
//!   Writes value_lo and value_hi to params[offset] and params[offset+1].
//!   Sender zeros value_hi for u8 params.
//!
//! - `[0x01, ...params_blob...]` -- 1 + N bytes: full voice reload
//!   Replaces the entire params blob. N can be up to PARAMS_SIZE.

#![no_std]

use core::ffi::c_void;

#[path = "../../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../pic_runtime.rs");
include!("../../param_macro.rs");

mod constants;
mod state;
mod oscillator;
mod envelope;
mod filter;
mod params;
mod params_def;
mod tlv;

use constants::*;
use state::*;
use oscillator::*;
use envelope::*;
use filter::*;
use params::*;

// ============================================================================
// Voice allocator
// ============================================================================

/// Allocate a voice for a new note. Priority:
/// 1. Idle voice (envelope finished)
/// 2. Oldest releasing voice
/// 3. Oldest active voice
unsafe fn alloc_voice(s: &mut SynthState) -> usize {
    let n = s.poly_count as usize;
    let vp = s.voices.as_ptr();

    // Pass 1: idle voice
    let mut i = 0;
    while i < n {
        let v = &*vp.add(i);
        if v.amp_env.phase == EnvPhase::Idle && v.amp_env.level == 0 {
            return i;
        }
        i += 1;
    }

    // Pass 2: oldest releasing voice
    let mut best = 0usize;
    let mut best_age = u16::MAX;
    i = 0;
    while i < n {
        let v = &*vp.add(i);
        if v.amp_env.phase == EnvPhase::Release && v.age < best_age {
            best = i;
            best_age = v.age;
        }
        i += 1;
    }
    if best_age < u16::MAX { return best; }

    // Pass 3: oldest active voice
    best_age = u16::MAX;
    i = 0;
    while i < n {
        let v = &*vp.add(i);
        if v.age < best_age {
            best = i;
            best_age = v.age;
        }
        i += 1;
    }
    best
}

/// Release all currently held voices (for poly mode where sequencer
/// doesn't send explicit note-off events).
unsafe fn release_held_voices(s: &mut SynthState) {
    let n = s.poly_count as usize;
    let vp = s.voices.as_mut_ptr();
    let mut i = 0;
    while i < n {
        let v = &mut *vp.add(i);
        if v.note_on != 0 {
            v.note_on = 0;
            env_release(&mut v.filter_env);
            env_release(&mut v.amp_env);
        }
        i += 1;
    }
}

/// Check if any voice has an active envelope.
unsafe fn any_voice_active(s: &SynthState) -> bool {
    let n = s.poly_count as usize;
    let vp = s.voices.as_ptr();
    let mut i = 0;
    while i < n {
        let v = &*vp.add(i);
        if v.amp_env.phase != EnvPhase::Idle || v.amp_env.level > 0 {
            return true;
        }
        i += 1;
    }
    false
}

#[inline(always)]
fn detune_inc(base: u32, cents: i32) -> u32 {
    if cents == 0 { return base; }
    let base_div = (base / 1200) as i32;
    let delta = base_div.saturating_mul(cents);
    if delta >= 0 {
        base.saturating_add(delta as u32)
    } else {
        base.saturating_sub((-delta) as u32)
    }
}

// ============================================================================
// Module API
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<SynthState>() as u32
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
        if state_size < core::mem::size_of::<SynthState>() { return -2; }

        let s = &mut *(state as *mut SynthState);
        let sys = syscalls as *const SyscallTable;
        s.syscalls = sys;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.ctrl_chan = ctrl_chan;
        s.nav_chan = -1;

        // Copy primary params blob into state
        let copy_len = if !params.is_null() && params_len > 0 {
            params_len.min(PARAMS_SIZE)
        } else { 0 };

        // Zero the params buffer first
        let params_dst = s.params.as_mut_ptr();
        let mut i = 0;
        while i < PARAMS_SIZE {
            core::ptr::write_volatile(params_dst.add(i), 0u8);
            i += 1;
        }

        // Copy incoming params
        if copy_len > 0 {
            let mut i = 0;
            while i < copy_len {
                core::ptr::write_volatile(params_dst.add(i), *params.add(i));
                i += 1;
            }
        }
        s.params_len = copy_len as u16;

        // Voice navigation
        s.voice_count = 0;
        s.current_voice = 0;

        // Defaults for new modulation/utility params (legacy format doesn't set these)
        s.pan = 128;
        s.vel_to_cutoff = 0;
        s.vel_to_drive = 0;
        s.vel_to_lfo_depth = 0;
        s.vel_to_env_amt = 0;
        s.voice_detune_cents = 0;
        s.detune_curve = 0;
        s.env_loop = 0;
        s.loop_rate_scale = 100;
        s.last_note_velocity = 128;

        // Apply all params to runtime state (sets poly_count, envelope rates, etc.)
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

        // Initialize runtime state
        s.render_frame = 0;
        s.pending_out = 0;
        s.pending_offset = 0;
        s.queue_head = 0;
        s.queue_tail = 0;
        s.event_count = 0;
        s.audio_count = 0;
        s.step_count = 0;

        // Initialize all voice slots
        let vp = s.voices.as_mut_ptr();
        let mut vi = 0;
        while vi < MAX_POLY {
            let v = &mut *vp.add(vi);
            v.phase = 0;
            v.sub_phase = 0;
            v.freq_inc = 0;
            v.target_freq_inc = 0;
            v.glide_rate = 0;
            v.lfsr = 0xACE1_u32.wrapping_add((vi as u32) * 0x1234);
            v.filter_low = 0;
            v.filter_band = 0;
            v.filter_env.phase = EnvPhase::Idle;
            v.filter_env.level = 0;
            v.amp_env.phase = EnvPhase::Idle;
            v.amp_env.level = 0;
            v.note_on = 0;
            v.last_velocity = 0;
            v.age = 0;
            v.pluck_delay_len = 0;
            v.pluck_read_pos = 0;
            v.pluck_prev_sample = 0;
            vi += 1;
        }

        // LFO init
        s.lfo_phase = 0;
        s.lfo_lfsr = 0xBEEF_CAFE;
        s.lfo_sh_value = 0;

        // NOTE: Skipping write_volatile buffer clearing loops.
        // The arena allocator already zeroes the memory via write_bytes.

        0
    }
}

/// Write u16 as 4-char hex to buffer (no null terminator).
#[inline(always)]
unsafe fn write_u16_hex(dst: *mut u8, val: u16) {
    const HEX: [u8; 16] = *b"0123456789ABCDEF";
    *dst = HEX[((val >> 12) & 0xF) as usize];
    *dst.add(1) = HEX[((val >> 8) & 0xF) as usize];
    *dst.add(2) = HEX[((val >> 4) & 0xF) as usize];
    *dst.add(3) = HEX[(val & 0xF) as usize];
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() { return -1; }
        let s = &mut *(state as *mut SynthState);
        if s.syscalls.is_null() { return -1; }

        let sys = &*s.syscalls;
        let in_chan = s.in_chan;
        let out_chan = s.out_chan;
        let ctrl_chan = s.ctrl_chan;

        // Read navigation commands from ctrl.1 (FMP messages)
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
                        // Copy voice params from table and apply
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

                // Read discriminator byte
                let mut hdr: [u8; 1] = [0];
                let r = (sys.channel_read)(ctrl_chan, hdr.as_mut_ptr(), 1);
                if r != 1 { break; }

                match hdr[0] {
                    CTRL_PATCH => {
                        // Single param patch: [offset, value_lo, value_hi]
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
                        // Full voice reload: read up to PARAMS_SIZE bytes
                        let r = (sys.channel_read)(ctrl_chan, s.params.as_mut_ptr(), PARAMS_SIZE);
                        if r < 4 { break; }
                        s.params_len = r as u16;
                        apply_params(s);
                    }
                    _ => { break; }
                }
            }
        }

        // Read note events
        loop {
            let next_tail = (s.queue_tail + 1) & ((EVENT_QUEUE_SIZE - 1) as u8);
            if next_tail == s.queue_head { break; }
            let in_poll = (sys.channel_poll)(in_chan, POLL_IN);
            if in_poll <= 0 || ((in_poll as u32) & POLL_IN) == 0 { break; }
            let mut msg_buf: [u8; NOTE_EVENT_SIZE] = [0; NOTE_EVENT_SIZE];
            let read = (sys.channel_read)(in_chan, msg_buf.as_mut_ptr(), NOTE_EVENT_SIZE);
            if read >= 6 {
                let msg_ptr = msg_buf.as_ptr();
                let target_frame = u32::from_le_bytes([*msg_ptr, *msg_ptr.add(1), *msg_ptr.add(2), *msg_ptr.add(3)]);
                let freq = u16::from_le_bytes([*msg_ptr.add(4), *msg_ptr.add(5)]);
                let velocity = if read >= 7 { *msg_ptr.add(6) } else { 200 };
                let flags = if read >= 8 { *msg_ptr.add(7) } else { 0 };
                *s.event_queue.as_mut_ptr().add(s.queue_tail as usize) = NoteEvent { target_frame, freq, velocity, flags };
                s.queue_tail = next_tail;
                s.event_count = s.event_count.wrapping_add(1);
            } else { break; }
        }

        if !drain_pending(sys, out_chan, s.out_buf.as_ptr(), &mut s.pending_out, &mut s.pending_offset) {
            return 0;
        }

        // Early exit: nothing to render (no queued notes, no active voice).
        // Must check BEFORE acquiring the mailbox buffer — acquiring transitions
        // the buffer to PRODUCER, and if we break out without writing, we'd
        // never call buffer_release_write, leaving it stuck in PRODUCER forever.
        {
            let queue_empty = s.queue_head == s.queue_tail;
            if queue_empty && !any_voice_active(s) { return 0; }
        }

        // Try zero-copy mailbox write. Acquired once, filled with multiple
        // chunks, then released. This fills the shared buffer so downstream
        // modules (mixer, effects, i2s) get a full buffer per scheduler tick.
        let mut mailbox_cap: u32 = 0;
        let mailbox_ptr = dev_buffer_acquire_write(sys, out_chan, &mut mailbox_cap);
        let is_mailbox = !mailbox_ptr.is_null() && mailbox_cap >= (SAMPLES_PER_CHUNK * 4) as u32;

        // Mailbox channel but buffer busy (downstream hasn't consumed yet).
        // Skip this tick — do NOT fall back to FIFO, which would corrupt the
        // pending mailbox data sharing the same physical buffer.
        // Advance render_frame to hardware stream time so events don't bunch up
        // when the mailbox becomes available again.
        if mailbox_ptr.is_null() && mailbox_cap > 0 {
            let (consumed, _, _, _) = dev_stream_time(sys);
            let hw_frame = consumed as u32;
            if hw_frame.wrapping_sub(s.render_frame) < 0x8000_0000 {
                s.render_frame = hw_frame;
            }
            return 0;
        }

        // Max stereo frames that fit in the mailbox buffer
        let mailbox_max_frames = if is_mailbox { (mailbox_cap as usize) / 4 } else { 0 };
        let mut mailbox_frames_written: usize = 0;

        // Compute render-ahead: how far render_frame leads consumed (hardware clock).
        // Events are scheduled relative to consumed, but we compare against
        // render_frame which leads by the pipeline buffer depth.  Adding
        // render_ahead to target_frame compensates.
        // Floor at mailbox_max_frames so the value is stable from the very first
        // step — without the floor, render_ahead starts at 0 and grows to
        // pipeline depth, skewing the first note's duration.
        let (consumed_now, _, _, _) = dev_stream_time(sys);
        let hw_frame_sync = consumed_now as u32;
        let measured_ahead = if s.render_frame.wrapping_sub(hw_frame_sync) < 0x8000_0000 {
            s.render_frame.wrapping_sub(hw_frame_sync)
        } else {
            0
        };
        let render_ahead = if mailbox_max_frames > 0 {
            measured_ahead.max(mailbox_max_frames as u32)
        } else {
            measured_ahead
        };

        let is_mono = s.poly_count <= 1;
        let sample_rate = s.sample_rate;

        // Generate loop - fill output channel to avoid partial DMA buffers
        loop {
        // Check if we should continue generating (envelopes may have finished mid-buffer)
        let queue_empty = s.queue_head == s.queue_tail;
        if queue_empty && !any_voice_active(s) { break; }

        if !is_mailbox {
            // FIFO path: check output channel has space
            let out_poll = (sys.channel_poll)(out_chan, POLL_OUT);
            if out_poll <= 0 || ((out_poll as u32) & POLL_OUT) == 0 { break; }
        } else if mailbox_frames_written + SAMPLES_PER_CHUNK > mailbox_max_frames {
            // Mailbox buffer full
            break;
        }

        // Generate samples — write directly to mailbox buffer when available,
        // otherwise to the module's out_buf for FIFO channel_write.
        let out_ptr = if is_mailbox {
            (mailbox_ptr as *mut i16).add(mailbox_frames_written * 2)
        } else {
            s.out_buf.as_mut_ptr() as *mut i16
        };

        // Compute LFO modulation for this chunk (once per 64 samples)
        let lfo_mod: i32;
        let pitch_mod: i32;
        let mut lfo_depth_eff = s.lfo_depth as i32;
        if s.vel_to_lfo_depth > 0 {
            let vel_mod = ((s.last_note_velocity as i32 - 128) * s.vel_to_lfo_depth as i32) >> 7;
            lfo_depth_eff = (lfo_depth_eff + vel_mod).clamp(0, 255);
        }
        if lfo_depth_eff > 0 && s.lfo_freq_inc > 0 {
            let lfo_raw: i16 = match s.lfo_waveform {
                WAVE_SAW => gen_saw(s.lfo_phase),
                WAVE_SQUARE => gen_square(s.lfo_phase),
                WAVE_TRIANGLE => gen_triangle(s.lfo_phase),
                WAVE_SAMPLE_HOLD => s.lfo_sh_value,
                _ => gen_sine(s.lfo_phase),
            };
            let old_phase = s.lfo_phase;
            let advance = s.lfo_freq_inc.wrapping_mul(SAMPLES_PER_CHUNK as u32);
            s.lfo_phase = old_phase.wrapping_add(advance);
            if s.lfo_waveform == WAVE_SAMPLE_HOLD && s.lfo_phase < old_phase {
                s.lfo_sh_value = gen_noise(&mut s.lfo_lfsr);
            }
            lfo_mod = (lfo_raw as i32 * lfo_depth_eff as i32) >> 8;
            pitch_mod = if (s.lfo_target & LFO_TGT_PITCH) != 0 { lfo_mod } else { 0 };
        } else {
            lfo_mod = 0;
            pitch_mod = 0;
        }

        let mut frame_offset = 0;
        while frame_offset < SAMPLES_PER_CHUNK {
            let current_frame = s.render_frame.wrapping_add(frame_offset as u32);

            while s.queue_head != s.queue_tail {
                let event = *s.event_queue.as_ptr().add(s.queue_head as usize);
                let adjusted_target = event.target_frame.wrapping_add(render_ahead);
                let diff = adjusted_target.wrapping_sub(current_frame) as i32;
                if diff <= 0 {
                    if event.freq > 0 && event.velocity > 0 {
                        let voices_ptr = s.voices.as_mut_ptr();
                        if is_mono {
                            // Mono: direct on voice 0 with glide/legato
                            let v = &mut *voices_ptr;
                            let mut new_freq_inc = freq_to_inc(event.freq, sample_rate);
                            if s.voice_detune_cents > 0 && s.poly_count > 1 {
                                let detune = s.voice_detune_cents as i32;
                                new_freq_inc = detune_inc(new_freq_inc, detune);
                            }
                            let is_legato = (event.flags & 0x01) != 0;
                            let was_playing = v.note_on != 0;

                            let should_glide = match s.glide_mode {
                                GLIDE_ALWAYS => true,
                                GLIDE_LEGATO => was_playing && is_legato,
                                _ => false,
                            };

                            if should_glide && s.glide_ms > 0 && was_playing {
                                v.target_freq_inc = new_freq_inc;
                                let sr_k = if sample_rate >= 1000 { sample_rate / 1000 } else { 1 };
                                let glide_samples = sr_k * (s.glide_ms as u32);
                                if glide_samples > 0 {
                                    let freq_diff = if new_freq_inc > v.freq_inc { new_freq_inc - v.freq_inc } else { v.freq_inc - new_freq_inc };
                                    v.glide_rate = (freq_diff / glide_samples.max(1)).max(1);
                                }
                            } else {
                                v.freq_inc = new_freq_inc;
                                v.target_freq_inc = new_freq_inc;
                                v.glide_rate = 0;
                            }

                            v.note_on = 1;
                            v.last_velocity = event.velocity;
                            s.last_note_velocity = event.velocity;
                            if !is_legato || !was_playing {
                                env_trigger(&mut v.filter_env);
                                env_trigger(&mut v.amp_env);
                            }

                            // Pluck: set delay length from frequency and trigger
                            if s.waveform == WAVE_PLUCK && event.freq > 0 {
                                let new_len = (sample_rate / event.freq as u32) as u16;
                                v.pluck_delay_len = new_len.clamp(2, PLUCK_BUF_SIZE as u16);
                                trigger_pluck(v, event.velocity);
                            }
                        } else {
                            // Poly: release held voices, allocate new one
                            release_held_voices(s);
                            let vi = alloc_voice(s);
                            let mut new_freq_inc = freq_to_inc(event.freq, sample_rate);

                            s.voice_alloc_counter = s.voice_alloc_counter.wrapping_add(1);
                            let v = &mut *voices_ptr.add(vi);
                            if s.voice_detune_cents > 0 && s.poly_count > 1 {
                                let max_cents = s.voice_detune_cents as i32;
                                let detune = if s.detune_curve == 0 {
                                    let n = s.poly_count as i32;
                                    let center = (n - 1) / 2;
                                    if center > 0 {
                                        let offset = vi as i32 - center;
                                        (offset * max_cents) / center
                                    } else { 0 }
                                } else {
                                    let noise = gen_noise(&mut v.lfsr) as i32;
                                    let span = max_cents * 2 + 1;
                                    (noise.abs() % span) - max_cents
                                };
                                new_freq_inc = detune_inc(new_freq_inc, detune);
                            }
                            v.freq_inc = new_freq_inc;
                            v.target_freq_inc = new_freq_inc;
                            v.glide_rate = 0;
                            v.phase = 0;
                            v.sub_phase = 0;
                            v.filter_low = 0;
                            v.filter_band = 0;
                            v.note_on = 1;
                            v.last_velocity = event.velocity;
                            s.last_note_velocity = event.velocity;
                            v.age = s.voice_alloc_counter;
                            env_trigger(&mut v.filter_env);
                            env_trigger(&mut v.amp_env);

                            // Pluck
                            if s.waveform == WAVE_PLUCK && event.freq > 0 {
                                let new_len = (sample_rate / event.freq as u32) as u16;
                                v.pluck_delay_len = new_len.clamp(2, PLUCK_BUF_SIZE as u16);
                                trigger_pluck(v, event.velocity);
                            }
                        }
                    } else {
                        // Note off
                        if is_mono {
                            let v0 = &mut *s.voices.as_mut_ptr();
                            v0.note_on = 0;
                            env_release(&mut v0.filter_env);
                            env_release(&mut v0.amp_env);
                        } else {
                            release_held_voices(s);
                        }
                    }
                    s.queue_head = (s.queue_head + 1) & ((EVENT_QUEUE_SIZE - 1) as u8);
                } else { break; }
            }

            // Sum voices
            let mut sum_l: i32 = 0;
            let mut sum_r: i32 = 0;

            let n = s.poly_count as usize;
            let waveform = s.waveform;
            let pulse_width = if (s.lfo_target & LFO_TGT_PULSE_WIDTH) != 0 {
                (s.pulse_width as i32 + lfo_mod).clamp(0, 255) as u8
            } else { s.pulse_width };
            let sub_level = s.sub_level;
            let cutoff_base = if (s.lfo_target & LFO_TGT_CUTOFF) != 0 {
                (s.cutoff as i32 + lfo_mod).clamp(0, 255)
            } else { s.cutoff as i32 };
            let resonance = if (s.lfo_target & LFO_TGT_RESONANCE) != 0 {
                (s.resonance as i32 + lfo_mod).clamp(0, 255) as u8
            } else { s.resonance };
            let env_amount_base = s.env_amount as i32;
            let key_track = s.key_track;
            let accent = s.accent;
            let pluck_decay = s.pluck_decay;
            let pluck_brightness = s.pluck_brightness;

            let voice_ptr = s.voices.as_mut_ptr();
            let mut vi = 0;
            while vi < n {
                let v = &mut *voice_ptr.add(vi);

                // Skip idle voices
                if v.amp_env.phase == EnvPhase::Idle && v.amp_env.level == 0 {
                    vi += 1;
                    continue;
                }

                // Apply glide (mono only — poly voices don't glide)
                if is_mono && v.glide_rate > 0 {
                    if v.freq_inc < v.target_freq_inc {
                        v.freq_inc = v.freq_inc.saturating_add(v.glide_rate);
                        if v.freq_inc >= v.target_freq_inc { v.freq_inc = v.target_freq_inc; v.glide_rate = 0; }
                    } else if v.freq_inc > v.target_freq_inc {
                        v.freq_inc = v.freq_inc.saturating_sub(v.glide_rate);
                        if v.freq_inc <= v.target_freq_inc { v.freq_inc = v.target_freq_inc; v.glide_rate = 0; }
                    }
                }

                // Generate oscillator
                let osc_sample = match waveform {
                    WAVE_SAW => gen_saw(v.phase),
                    WAVE_SQUARE => gen_square(v.phase),
                    WAVE_TRIANGLE => gen_triangle(v.phase),
                    WAVE_PULSE => gen_pulse(v.phase, pulse_width),
                    WAVE_NOISE => gen_noise(&mut v.lfsr),
                    WAVE_SINE => gen_sine(v.phase),
                    WAVE_PLUCK => gen_pluck(v, pluck_decay, pluck_brightness),
                    _ => gen_saw(v.phase),
                };
                if waveform != WAVE_PLUCK {
                    let actual_inc = if pitch_mod != 0 {
                        let delta = ((v.freq_inc >> 11) as i32 * pitch_mod) >> 4;
                        (v.freq_inc as i32 + delta).max(0) as u32
                    } else { v.freq_inc };
                    v.phase = v.phase.wrapping_add(actual_inc);
                }

                // Sub oscillator
                let sub_sample = if sub_level > 0 {
                    let sub = gen_square(v.sub_phase);
                    let sub_inc = if pitch_mod != 0 {
                        let base = v.freq_inc >> 1;
                        let delta = ((base >> 11) as i32 * pitch_mod) >> 4;
                        (base as i32 + delta).max(0) as u32
                    } else { v.freq_inc >> 1 };
                    v.sub_phase = v.sub_phase.wrapping_add(sub_inc);
                    ((sub as i32 * sub_level as i32) >> 8) as i16
                } else { 0 };

                let mixed = (osc_sample as i32) + (sub_sample as i32);

                // Filter envelope
                let filter_env_level = env_process_loop(&mut v.filter_env, s.env_loop, s.loop_rate_scale);
                let vel_cutoff_mod = if s.vel_to_cutoff > 0 {
                    ((v.last_velocity as i32 - 128) * s.vel_to_cutoff as i32) >> 7
                } else { 0 };
                let env_amount = if s.vel_to_env_amt > 0 {
                    (env_amount_base + (((v.last_velocity as i32 - 128) * s.vel_to_env_amt as i32) >> 7)).clamp(0, 255)
                } else { env_amount_base };
                let env_mod = ((filter_env_level as i32) * env_amount) >> 16;
                let key_mod = if key_track > 0 && v.freq_inc > 0 {
                    let pitch_factor = (v.freq_inc >> 20) as i32;
                    (pitch_factor * key_track as i32) >> 6
                } else { 0 };
                let accent_mod = if accent > 0 {
                    let vel_factor = (v.last_velocity as i32 - 128) * (accent as i32);
                    vel_factor >> 9
                } else { 0 };
                let total_cutoff = (cutoff_base + vel_cutoff_mod + env_mod + key_mod + accent_mod).clamp(0, 255) as u8;

                // Bypass filter when fully open
                let filtered = if total_cutoff >= 255 && resonance == 0 {
                    v.filter_low = 0;
                    v.filter_band = 0;
                    mixed.clamp(-32768, 32767)
                } else {
                    svf_process(mixed, total_cutoff, resonance, &mut v.filter_low, &mut v.filter_band)
                };

                // Amp envelope
                let amp_env_level = env_process_loop(&mut v.amp_env, s.env_loop, s.loop_rate_scale);
                let voice_l = (filtered * (amp_env_level as i32)) >> 16;

                sum_l += voice_l;
                sum_r += voice_l;

                vi += 1;
            }

            // Headroom reduction for polyphony
            if !is_mono {
                if n <= 2 {
                    sum_l >>= 1;
                    sum_r >>= 1;
                } else {
                    sum_l >>= 2;
                    sum_r >>= 2;
                }
            }

            // Apply soft drive
            let mut drive = s.drive as i32;
            if s.vel_to_drive > 0 {
                let vel_mod = ((s.last_note_velocity as i32 - 128) * s.vel_to_drive as i32) >> 7;
                drive = (drive + vel_mod).clamp(0, 255);
            }
            if drive > 0 {
                let drive_scale = 256 + drive * 3;
                let x = (sum_l * drive_scale) >> 8;
                let x_clamped = x.clamp(-32768, 32767);
                let x_norm = x_clamped as i64;
                let x_cubed = (x_norm * x_norm * x_norm) >> 30;
                sum_l = (x_norm - (x_cubed / 3)) as i32;
                sum_r = sum_l;
            }

            // Output level (with optional LFO modulation)
            let eff_level = if (s.lfo_target & LFO_TGT_LEVEL) != 0 {
                (s.level as i32 + lfo_mod).clamp(0, 255)
            } else { s.level as i32 };
            let mut pan = s.pan as i32;
            if (s.lfo_target & LFO_TGT_PAN) != 0 {
                pan = (pan + lfo_mod).clamp(0, 255);
            }
            let mixed = ((sum_l * eff_level) >> 8).clamp(-32768, 32767);
            let pan_l = 255 - pan;
            let pan_r = pan;
            let output_l = ((mixed * pan_l) >> 8).clamp(-32768, 32767) as i16;
            let output_r = ((mixed * pan_r) >> 8).clamp(-32768, 32767) as i16;

            *out_ptr.add(frame_offset * 2) = output_l;
            *out_ptr.add(frame_offset * 2 + 1) = output_r;

            frame_offset += 1;
        }

        // Write output
        if is_mailbox {
            // Zero-copy: accumulate frames in the mailbox buffer, release at end
            mailbox_frames_written += SAMPLES_PER_CHUNK;
            s.render_frame = s.render_frame.wrapping_add(SAMPLES_PER_CHUNK as u32);
            s.audio_count = s.audio_count.wrapping_add(1);
            // Continue loop to fill more of the buffer
        } else {
            // FIFO: copy from out_buf to channel
            let bytes_to_write = SAMPLES_PER_CHUNK * 4;
            let written = (sys.channel_write)(out_chan, s.out_buf.as_ptr(), bytes_to_write);
            track_pending(written, bytes_to_write, &mut s.pending_out, &mut s.pending_offset);
            if s.pending_out != 0 { break; }
            if written > 0 {
                s.render_frame = s.render_frame.wrapping_add(SAMPLES_PER_CHUNK as u32);
                s.audio_count = s.audio_count.wrapping_add(1);
            }
        }

        } // end generate loop

        // Release mailbox buffer with all accumulated frames
        if is_mailbox && mailbox_frames_written > 0 {
            let total_bytes = mailbox_frames_written * 4;
            dev_buffer_release_write(sys, out_chan, total_bytes as u32);
        }

        // If render_frame fell behind hardware stream time (output was busy),
        // catch up to prevent generating stale audio.
        {
            let (consumed_end, _, _, _) = dev_stream_time(sys);
            let hw_end = consumed_end as u32;
            if hw_end.wrapping_sub(s.render_frame) < 0x8000_0000
                && hw_end.wrapping_sub(s.render_frame) > SAMPLES_PER_CHUNK as u32
            {
                s.render_frame = hw_end;
            }
        }

        0
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
