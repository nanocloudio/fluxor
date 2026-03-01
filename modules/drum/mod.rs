//! Drum PIC Module
//!
//! Multi-voice percussion synthesizer. TR-808/909 style:
//! - Kick: sine oscillator with pitch envelope sweep
//! - Snare: triangle + noise mix with fast decay
//! - Closed hi-hat: filtered noise, very short decay
//! - Open hi-hat: filtered noise, longer decay
//! - Clap: noise burst with medium decay
//!
//! Note events encode drum type in the freq field:
//!   freq=1 kick, freq=2 snare, freq=3 closed hat, freq=4 open hat, freq=5 clap
//!   freq=0 rest (ignored), velocity controls hit intensity.
//!
//! Output: stereo i16 audio (mono duplicated to both channels).

#![no_std]

use core::ffi::c_void;

#[path = "../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../pic_runtime.rs");
include!("../param_macro.rs");

mod params_def;

// ============================================================================
// Constants
// ============================================================================

const NOTE_EVENT_SIZE: usize = 8;
const SAMPLES_PER_CHUNK: usize = 64;
const OUT_BUF_SIZE: usize = 256; // 64 stereo i16 samples = 256 bytes
const MAX_DRUM_VOICES: usize = 8;
const EVENT_QUEUE_SIZE: usize = 8;

// Drum type IDs (encoded as freq in NoteEvent)
pub const DRUM_KICK: u16 = 1;
pub const DRUM_SNARE: u16 = 2;
pub const DRUM_HAT_CLOSED: u16 = 3;
pub const DRUM_HAT_OPEN: u16 = 4;
pub const DRUM_CLAP: u16 = 5;

// Quarter-wave sine table (64 entries, i16, 0..32767)
// sin(i * pi/128) * 32767 for i = 0..63
const SINE_Q64: [i16; 64] = [
        0,   804,  1608,  2410,  3212,  4011,  4808,  5602,
     6393,  7179,  7962,  8739,  9512, 10278, 11039, 11793,
    12539, 13279, 14010, 14732, 15446, 16151, 16846, 17530,
    18204, 18868, 19519, 20159, 20787, 21403, 22005, 22594,
    23170, 23731, 24279, 24811, 25329, 25832, 26319, 26790,
    27245, 27683, 28105, 28510, 28898, 29268, 29621, 29956,
    30273, 30571, 30852, 31113, 31356, 31580, 31785, 31971,
    32137, 32285, 32412, 32521, 32609, 32678, 32728, 32757,
];

// ============================================================================
// State
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DrumVoice {
    pub active: u8,
    pub drum_type: u8,
    pub amplitude: u16,
    pub amp_decay: u16,
    pub _pad: u16,
    pub phase: u32,
    pub pitch: u32,
    pub pitch_target: u32,
    pub pitch_decay: u16,
    pub tone_mix: u16,
    pub lfsr: u32,
    pub filter_state: i32,
}

#[repr(C)]
pub struct DrumState {
    pub syscalls: *const SyscallTable,
    pub in_chan: i32,
    pub out_chan: i32,
    pub sample_rate: u32,
    pub render_frame: u32,

    // Params
    pub level: u8,
    pub kick_decay: u8,
    pub kick_pitch: u8,
    pub snare_decay: u8,
    pub snare_tone: u8,
    pub hat_decay: u8,
    pub _pad: [u8; 2],

    // Precomputed from params + sample_rate (set in module_new, used in trigger_voice)
    pub phase_per_hz: u32,
    pub kick_amp_decay: u16,
    pub kick_phase_inc: u32,
    pub snare_amp_decay: u16,
    pub snare_phase_inc: u32,
    pub hat_closed_decay: u16,
    pub hat_open_decay: u16,
    pub clap_amp_decay: u16,
    pub _pad2: u16,

    // Voice pool
    pub voices: [DrumVoice; MAX_DRUM_VOICES],

    // Event queue
    pub eq_frame: [u32; EVENT_QUEUE_SIZE],
    pub eq_freq: [u16; EVENT_QUEUE_SIZE],
    pub eq_vel: [u8; EVENT_QUEUE_SIZE],
    pub eq_head: u8,
    pub eq_tail: u8,
    pub _eq_pad: [u8; 2],

    // Output
    pub out_buf: [u8; OUT_BUF_SIZE],
}

// ============================================================================
// Helpers
// ============================================================================

/// Software unsigned division via shift-and-subtract.
/// Avoids the `/` operator which emits `panic_const_div_by_zero` in PIC builds.
#[inline(always)]
fn div_u32(num: u32, den: u32) -> u32 {
    if den == 0 { return 0; }
    let mut q: u32 = 0;
    let mut r: u32 = 0;
    let mut i: i32 = 31;
    while i >= 0 {
        r = (r << 1) | ((num >> (i as u32)) & 1);
        if r >= den {
            r -= den;
            q |= 1 << (i as u32);
        }
        i -= 1;
    }
    q
}

#[inline(always)]
fn lfsr_next(lfsr: &mut u32) -> i16 {
    let bit = ((*lfsr) ^ (*lfsr >> 1) ^ (*lfsr >> 21) ^ (*lfsr >> 31)) & 1;
    *lfsr = (*lfsr >> 1) | (bit << 31);
    (*lfsr & 0xFFFF) as i16
}

/// Sine from 64-entry quarter-wave table. Phase is u32 (full range = one cycle).
#[inline(always)]
fn sine(phase: u32) -> i16 {
    let idx8 = (phase >> 24) as u8; // top 8 bits: 2 quadrant + 6 index
    let quadrant = idx8 >> 6;
    let idx = (idx8 & 0x3F) as usize;
    unsafe {
        let ptr = SINE_Q64.as_ptr();
        match quadrant {
            0 => *ptr.add(idx),
            1 => *ptr.add(63 - idx),
            2 => -*ptr.add(idx),
            _ => -*ptr.add(63 - idx),
        }
    }
}

/// Triangle wave from phase accumulator.
#[inline(always)]
fn triangle(phase: u32) -> i16 {
    let p = (phase >> 16) as i32;
    if p < 32768 { (p * 2 - 32768) as i16 }
    else { (32767 - (p - 32768) * 2) as i16 }
}

/// Convert decay param (0-255) + sample rate to per-sample decay factor (u16).
/// factor = 65535 - 65535/samples, where samples = (5 + param*2) * sr / 1000.
/// Uses div_u32 to avoid `/` operator panic infrastructure.
#[inline(always)]
fn compute_decay(param: u8, sr: u32) -> u16 {
    if param == 0 { return 0; }
    let ms = 5u32 + (param as u32) * 2;
    let samples = div_u32(ms * sr, 1000);
    if samples == 0 { return 0; }
    let inv = div_u32(65535, samples);
    (65535u32 - inv).min(65535) as u16
}

/// Precompute all division-dependent values from params + sample_rate.
/// Called once from module_new after params are parsed.
unsafe fn precompute(s: &mut DrumState) {
    let sr = s.sample_rate;
    if sr == 0 { return; }

    // Phase increment per Hz: 2^32 / sr
    s.phase_per_hz = div_u32(0xFFFF_FFFF, sr);

    // Kick base pitch: param 0→30Hz, 255→200Hz
    // (param * 170 / 255) ≈ (param * 171) >> 8
    let kick_hz = 30u32 + (((s.kick_pitch as u32) * 171) >> 8);
    s.kick_phase_inc = s.phase_per_hz.wrapping_mul(kick_hz);

    // Snare: fixed 200Hz triangle
    s.snare_phase_inc = s.phase_per_hz.wrapping_mul(200);

    // Decay factors
    s.kick_amp_decay = compute_decay(s.kick_decay, sr);
    s.snare_amp_decay = compute_decay(s.snare_decay, sr);
    s.hat_open_decay = compute_decay(s.hat_decay, sr);
    // Closed hat: faster decay (~1/3 of param)
    let hat_cl_param = (((s.hat_decay as u32) * 85) >> 8).min(255) as u8;
    s.hat_closed_decay = compute_decay(hat_cl_param, sr);
    s.clap_amp_decay = compute_decay(120, sr);
}

// ============================================================================
// Module API
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<DrumState>() as u32
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
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<DrumState>() { return -2; }

        let s = &mut *(state as *mut DrumState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.sample_rate = 8000;
        s.render_frame = 0;

        // Init voices
        let vp = s.voices.as_mut_ptr();
        let mut i = 0;
        while i < MAX_DRUM_VOICES {
            let v = &mut *vp.add(i);
            v.active = 0;
            v.amplitude = 0;
            v.phase = 0;
            v.pitch = 0;
            v.pitch_target = 0;
            v.lfsr = 0xACE1_u32.wrapping_add((i as u32) * 0x5678);
            v.filter_state = 0;
            i += 1;
        }

        s.eq_head = 0;
        s.eq_tail = 0;

        // Parse params (sets defaults then applies TLV overrides)
        let is_tlv_v2 = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x02;
        if is_tlv_v2 {
            params_def::parse_tlv_v2(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        // Precompute division-dependent values
        precompute(s);

        0
    }
}

// ============================================================================
// Voice allocation
// ============================================================================

/// Find a free voice slot, or steal the quietest active voice.
unsafe fn alloc_voice(s: &mut DrumState) -> usize {
    let vp = s.voices.as_mut_ptr();
    let mut quietest_idx = 0usize;
    let mut quietest_amp = u16::MAX;

    let mut i = 0;
    while i < MAX_DRUM_VOICES {
        let v = &*vp.add(i);
        if v.active == 0 {
            return i;
        }
        if v.amplitude < quietest_amp {
            quietest_amp = v.amplitude;
            quietest_idx = i;
        }
        i += 1;
    }
    quietest_idx
}

/// Trigger a drum voice using precomputed values (no divisions).
unsafe fn trigger_voice(s: &mut DrumState, drum_type: u16, velocity: u8) {
    let idx = alloc_voice(s);
    let v = &mut *s.voices.as_mut_ptr().add(idx);
    let vel_scale = velocity as u32;

    v.active = 1;
    v.drum_type = drum_type as u8;
    v.phase = 0;
    v.filter_state = 0;
    // Scale amplitude by velocity: (vel << 7) | (vel >> 1) ≈ vel * 128.5 → range 0..32767
    v.amplitude = ((vel_scale << 7) | (vel_scale >> 1)) as u16;

    match drum_type {
        DRUM_KICK => {
            let base_inc = s.kick_phase_inc;
            v.pitch = base_inc.wrapping_mul(6); // start ~6x higher
            v.pitch_target = base_inc;
            v.pitch_decay = 200;
            v.amp_decay = s.kick_amp_decay;
            v.tone_mix = 0;
        }
        DRUM_SNARE => {
            v.pitch = s.snare_phase_inc;
            v.pitch_target = v.pitch;
            v.pitch_decay = 0;
            v.amp_decay = s.snare_amp_decay;
            v.tone_mix = s.snare_tone as u16;
        }
        DRUM_HAT_CLOSED => {
            v.pitch = 0;
            v.pitch_target = 0;
            v.pitch_decay = 0;
            v.amp_decay = s.hat_closed_decay;
            v.tone_mix = 0;
        }
        DRUM_HAT_OPEN => {
            v.pitch = 0;
            v.pitch_target = 0;
            v.pitch_decay = 0;
            v.amp_decay = s.hat_open_decay;
            v.tone_mix = 0;
        }
        DRUM_CLAP => {
            v.pitch = 0;
            v.pitch_target = 0;
            v.pitch_decay = 0;
            v.amp_decay = s.clap_amp_decay;
            v.tone_mix = 0;
        }
        _ => {
            v.active = 0; // unknown drum type
        }
    }
}

// ============================================================================
// Per-sample synthesis
// ============================================================================

#[inline(always)]
unsafe fn render_voice(v: &mut DrumVoice) -> i32 {
    if v.active == 0 { return 0; }

    let sample: i32 = match v.drum_type as u16 {
        DRUM_KICK => {
            // Pitch envelope: exponential decay toward target
            if v.pitch > v.pitch_target {
                let delta = v.pitch - v.pitch_target;
                v.pitch -= delta >> 6; // ~6ms time constant at 8kHz
                if v.pitch < v.pitch_target { v.pitch = v.pitch_target; }
            }
            v.phase = v.phase.wrapping_add(v.pitch);
            sine(v.phase) as i32
        }
        DRUM_SNARE => {
            v.phase = v.phase.wrapping_add(v.pitch);
            let tone = triangle(v.phase) as i32;
            let noise = lfsr_next(&mut v.lfsr) as i32;
            let mix = v.tone_mix as i32;
            ((tone * mix) + (noise * (256 - mix))) >> 8
        }
        DRUM_HAT_CLOSED | DRUM_HAT_OPEN => {
            // High-pass filtered noise
            let noise = lfsr_next(&mut v.lfsr) as i32;
            let hp = noise - v.filter_state;
            v.filter_state += hp >> 2; // cutoff ~= sr/8
            hp
        }
        DRUM_CLAP => {
            // Filtered noise burst
            let noise = lfsr_next(&mut v.lfsr) as i32;
            let bp = noise - v.filter_state;
            v.filter_state += bp >> 3;
            bp
        }
        _ => 0,
    };

    // Apply amplitude envelope
    let out = (sample * v.amplitude as i32) >> 15;

    // Decay amplitude
    v.amplitude = ((v.amplitude as u32 * v.amp_decay as u32) >> 16) as u16;
    if v.amplitude < 8 {
        v.active = 0;
        v.amplitude = 0;
    }

    out
}

// ============================================================================
// module_step
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() { return -1; }
        let s = &mut *(state as *mut DrumState);
        if s.syscalls.is_null() { return -1; }
        let sys = &*s.syscalls;
        let in_chan = s.in_chan;
        let out_chan = s.out_chan;

        // Read incoming note events
        if in_chan >= 0 {
            loop {
                let next_tail = (s.eq_tail + 1) & (EVENT_QUEUE_SIZE as u8 - 1);
                if next_tail == s.eq_head { break; } // queue full

                let poll_in = (sys.channel_poll)(in_chan, POLL_IN);
                if poll_in <= 0 || ((poll_in as u8) & POLL_IN) == 0 { break; }

                let mut buf: [u8; NOTE_EVENT_SIZE] = [0; NOTE_EVENT_SIZE];
                let read = (sys.channel_read)(in_chan, buf.as_mut_ptr(), NOTE_EVENT_SIZE);
                if read < 6 { break; }

                let target_frame = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                let freq = u16::from_le_bytes([buf[4], buf[5]]);
                let velocity = if read >= 7 { buf[6] } else { 200 };

                if freq >= 1 && freq <= 5 && velocity > 0 {
                    let t = s.eq_tail as usize;
                    *s.eq_frame.as_mut_ptr().add(t) = target_frame;
                    *s.eq_freq.as_mut_ptr().add(t) = freq;
                    *s.eq_vel.as_mut_ptr().add(t) = velocity;
                    s.eq_tail = next_tail;
                }
            }
        }

        // Check if any voice is active (must check BEFORE acquiring mailbox —
        // acquiring transitions to PRODUCER, must release or it stalls).
        let mut any_active = false;
        {
            let vcheck = s.voices.as_ptr();
            let mut i = 0;
            while i < MAX_DRUM_VOICES {
                if (*vcheck.add(i)).active != 0 { any_active = true; break; }
                i += 1;
            }
        }
        let queue_empty = s.eq_head == s.eq_tail;
        if !any_active && queue_empty { return 0; }

        if out_chan < 0 { return 0; }

        // Try zero-copy mailbox write path (same pattern as synth module).
        // Acquire once, fill with multiple 64-frame chunks, release at end.
        // This fills the shared buffer so downstream i2s gets a complete
        // DMA buffer per scheduler tick.
        let mut mbox_cap: u32 = 0;
        let mbox_ptr = dev_buffer_acquire_write(sys, out_chan, &mut mbox_cap);
        let is_mailbox = !mbox_ptr.is_null() && mbox_cap >= (SAMPLES_PER_CHUNK * 4) as u32;

        // Mailbox channel but buffer busy (downstream hasn't consumed yet).
        // Advance render_frame to hardware stream time so events don't bunch up
        // when the mailbox becomes available again. A brief silence gap from the
        // skipped buffer is inaudible; a timing jump from stale events is not.
        if mbox_ptr.is_null() && mbox_cap > 0 {
            let (consumed, _, _, _) = dev_stream_time(sys);
            let hw_frame = consumed as u32;
            if hw_frame.wrapping_sub(s.render_frame) < 0x8000_0000 {
                s.render_frame = hw_frame;
            }
            return 0;
        }

        let mbox_max_frames = if is_mailbox { (mbox_cap as usize) / 4 } else { 0 };
        let mut mbox_frames_written: usize = 0;

        // Compute render-ahead: how far render_frame leads consumed (hardware clock).
        // Events are scheduled relative to consumed, but we compare against
        // render_frame which leads by the pipeline buffer depth.  Adding
        // render_ahead to target_frame compensates.
        // Floor at mbox_max_frames so the value is stable from the very first
        // step — without the floor, render_ahead starts at 0 and grows to
        // pipeline depth, skewing the first note's duration.
        let (consumed_now, _, _, _) = dev_stream_time(sys);
        let hw_frame = consumed_now as u32;
        let measured_ahead = if s.render_frame.wrapping_sub(hw_frame) < 0x8000_0000 {
            s.render_frame.wrapping_sub(hw_frame)
        } else {
            0
        };
        let render_ahead = if mbox_max_frames > 0 {
            measured_ahead.max(mbox_max_frames as u32)
        } else {
            measured_ahead
        };

        let level = s.level as i32;
        let vp = s.voices.as_mut_ptr();

        loop {
            // Check if voices are still active or pending events exist
            let mut still_active = false;
            {
                let mut i = 0;
                while i < MAX_DRUM_VOICES {
                    if (*vp.add(i)).active != 0 { still_active = true; break; }
                    i += 1;
                }
            }
            let pending_events = s.eq_head != s.eq_tail;
            if !still_active && !pending_events { break; }

            if !is_mailbox {
                let out_poll = (sys.channel_poll)(out_chan, POLL_OUT);
                if out_poll <= 0 || ((out_poll as u8) & POLL_OUT) == 0 { break; }
            } else if mbox_frames_written + SAMPLES_PER_CHUNK > mbox_max_frames {
                break; // mailbox full
            }

            // Render one chunk — directly into mailbox or local buffer
            let out_ptr = if is_mailbox {
                (mbox_ptr as *mut i16).add(mbox_frames_written * 2)
            } else {
                s.out_buf.as_mut_ptr() as *mut i16
            };

            let mut frame = 0usize;
            while frame < SAMPLES_PER_CHUNK {
                let current_frame = s.render_frame.wrapping_add(frame as u32);
                while s.eq_head != s.eq_tail {
                    let h = s.eq_head as usize;
                    let tf = (*s.eq_frame.as_ptr().add(h)).wrapping_add(render_ahead);
                    let diff = tf.wrapping_sub(current_frame) as i32;
                    if diff <= 0 {
                        let freq = *s.eq_freq.as_ptr().add(h);
                        let vel = *s.eq_vel.as_ptr().add(h);
                        s.eq_head = (s.eq_head + 1) & (EVENT_QUEUE_SIZE as u8 - 1);
                        trigger_voice(s, freq, vel);
                    } else {
                        break;
                    }
                }

                let mut mix: i32 = 0;

                let mut vi = 0;
                while vi < MAX_DRUM_VOICES {
                    mix += render_voice(&mut *vp.add(vi));
                    vi += 1;
                }

                let sample = ((mix * level) >> 8).clamp(-32768, 32767) as i16;
                *out_ptr.add(frame * 2) = sample;
                *out_ptr.add(frame * 2 + 1) = sample; // mono → stereo

                frame += 1;
            }

            if is_mailbox {
                mbox_frames_written += SAMPLES_PER_CHUNK;
                s.render_frame = s.render_frame.wrapping_add(SAMPLES_PER_CHUNK as u32);
            } else {
                let bytes = SAMPLES_PER_CHUNK * 4;
                (sys.channel_write)(out_chan, s.out_buf.as_ptr(), bytes);
                s.render_frame = s.render_frame.wrapping_add(SAMPLES_PER_CHUNK as u32);
                break; // one chunk per step in FIFO mode
            }
        }

        // Release mailbox with all accumulated frames
        if is_mailbox && mbox_frames_written > 0 {
            let total_bytes = mbox_frames_written * 4;
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
