// Sequencer parameter definitions (single source of truth).
//
// Generates: dispatch_param(), set_defaults(), parse_tlv_v2(), PARAM_SCHEMA.
//
// IMPORTANT: sample_rate must be first — step_ms depends on it for
// computing step_frames.

use super::{Sequencer, SeqMode, MAX_PRESETS, MAX_PRESET_LEN};
use super::{p_u8, p_u16, p_u32, read_u16_at};
use super::SCHEMA_MAX;

define_params! {
    Sequencer;

    1, sample_rate, u32, 8000
        => |s, d, len| {
            let sr = p_u32(d, len, 0, 8000);
            s.sample_rate = if sr > 0 { sr } else { 8000 };
        };

    2, step_ms, u16, 500
        => |s, d, len| {
            let ms = p_u16(d, len, 0, 500);
            s.step_frames = (ms as u32 * s.sample_rate) / 1000;
        };

    3, mode, u8, 2, enum { one_shot=0, oneshot=0, loop=1, ping_pong=2, pingpong=2 }
        => |s, d, len| {
            let m = p_u8(d, len, 0, 2);
            s.mode = match m {
                0 => SeqMode::OneShot,
                1 => SeqMode::Loop,
                _ => SeqMode::PingPong,
            };
        };

    // --- Generative ---
    5, probability, u8, 255
        => |s, d, len| { s.probability = p_u8(d, len, 0, 255); };

    6, random_pitch, u8, 0, enum { off=0, random=1 }
        => |s, d, len| { s.random_pitch = p_u8(d, len, 0, 0).min(1); };

    7, octave_range, u8, 0
        => |s, d, len| { s.octave_range = p_u8(d, len, 0, 0).min(2); };

    8, velocity_min, u8, 200
        => |s, d, len| { s.velocity_min = p_u8(d, len, 0, 200); };

    9, velocity_max, u8, 200
        => |s, d, len| { s.velocity_max = p_u8(d, len, 0, 200); };

    10, retrigger, u8, 0, enum { off=0, on=1 }
        => |s, d, len| { s.retrigger = p_u8(d, len, 0, 0).min(1); };

    // --- Humanize ---
    11, timing_jitter_ms, u8, 0
        => |s, d, len| { s.timing_jitter_ms = p_u8(d, len, 0, 0).min(20); };

    12, velocity_jitter_pct, u8, 0
        => |s, d, len| { s.velocity_jitter_pct = p_u8(d, len, 0, 0).min(30); };

    13, humanize_prob, u8, 0
        => |s, d, len| { s.humanize_prob = p_u8(d, len, 0, 0).min(100); };

    // --- Ratchets ---
    14, ratchet_count, u8, 1
        => |s, d, len| { s.ratchet_count = p_u8(d, len, 0, 1).clamp(1, 8); };

    15, ratchet_spacing, u8, 0, enum { even=0, accel=1, decel=2 }
        => |s, d, len| { s.ratchet_spacing = p_u8(d, len, 0, 0).min(2); };

    16, ratchet_velocity_falloff, u8, 0
        => |s, d, len| { s.ratchet_vel_falloff = p_u8(d, len, 0, 0).min(100); };

    // --- Conditional steps ---
    17, play_every_n_loops, u8, 0
        => |s, d, len| { s.play_every_n_loops = p_u8(d, len, 0, 0); };

    18, skip_probability, u8, 0
        => |s, d, len| { s.skip_probability = p_u8(d, len, 0, 0).min(100); };

    19, fill_on_loop_end, u8, 0, enum { off=0, on=1 }
        => |s, d, len| { s.fill_on_loop_end = p_u8(d, len, 0, 0).min(1); };

    // --- Auto-advance ---
    20, auto_advance_preset, u8, 0, enum { off=0, on=1 }
        => |s, d, len| { s.auto_advance_preset = p_u8(d, len, 0, 0).min(1); };

    4, preset, u16_array, 0
        => |s, d, len| {
            // Each TLV entry with this tag carries one preset's u16 values.
            // Accumulate into the next available preset slot.
            let idx = s.preset_count as usize;
            if idx < MAX_PRESETS && len >= 2 {
                let count = (len / 2).min(MAX_PRESET_LEN);
                s.preset_lengths[idx] = count as u8;
                let base = s.preset_values.as_mut_ptr() as *mut u16;
                let mut j = 0;
                while j < count {
                    let val = u16::from_le_bytes([*d.add(j * 2), *d.add(j * 2 + 1)]);
                    core::ptr::write_volatile(base.add(idx * MAX_PRESET_LEN + j), val);
                    j += 1;
                }
                s.preset_count += 1;
            }
        };
}
