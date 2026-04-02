// Internal noise gate effect.
//
// Threshold-based gate with attack/hold/release envelope and hysteresis.

use super::constants::*;
use super::state::EffectsState;

/// Process one stereo sample pair through noise gate.
#[inline(always)]
pub fn process_gate(sample_l: &mut i32, sample_r: &mut i32, s: &mut EffectsState) {
    // Envelope follower (peak detection)
    let abs_l = if *sample_l >= 0 { *sample_l } else { -*sample_l } as u32;
    let abs_r = if *sample_r >= 0 { *sample_r } else { -*sample_r } as u32;
    let peak = if abs_l > abs_r { abs_l } else { abs_r };

    // Smooth envelope
    let env = s.gate_env_level as u32;
    let new_env = if peak > env {
        env + ((peak - env) >> 2) // fast attack
    } else {
        env - (env >> 6) // slow decay
    };
    s.gate_env_level = new_env.min(65535) as u16;

    let threshold = s.gate_threshold as u32;
    let above_threshold = new_env > threshold;
    let below_close = new_env < (threshold >> 1); // hysteresis

    let attack_coef = s.gate_attack_coef as u32;
    let release_coef = s.gate_release_coef as u32;

    // Min gain from range (dB approximation)
    let min_gain = if s.gate_range >= 80 {
        0u32
    } else {
        let shift = (s.gate_range as u32) / 6;
        256 >> shift.min(8)
    };

    // Gate state machine
    match s.gate_state {
        GATE_CLOSED => {
            if above_threshold { s.gate_state = GATE_ATTACK; }
        }
        GATE_ATTACK => {
            let gain = s.gate_gain as u32;
            let new_gain = gain + ((256 - gain) * attack_coef >> 16);
            s.gate_gain = new_gain.min(256) as u16;
            if s.gate_gain >= 255 {
                s.gate_state = GATE_OPEN;
                s.gate_gain = 256;
            }
        }
        GATE_OPEN => {
            if below_close {
                s.gate_state = GATE_HOLD;
                s.gate_hold_counter = s.gate_hold_samples;
            }
        }
        GATE_HOLD => {
            if above_threshold {
                s.gate_state = GATE_OPEN;
            } else if s.gate_hold_counter > 0 {
                s.gate_hold_counter -= 1;
            } else {
                s.gate_state = GATE_RELEASE;
            }
        }
        GATE_RELEASE => {
            if above_threshold {
                s.gate_state = GATE_ATTACK;
            } else {
                let gain = s.gate_gain as u32;
                let new_gain = if gain > min_gain {
                    let diff = gain - min_gain;
                    gain - ((diff * release_coef) >> 16).max(1)
                } else {
                    min_gain
                };
                s.gate_gain = new_gain as u16;
                if s.gate_gain <= min_gain as u16 + 1 {
                    s.gate_state = GATE_CLOSED;
                    s.gate_gain = min_gain as u16;
                }
            }
        }
        _ => { s.gate_state = GATE_CLOSED; }
    }

    let gain = s.gate_gain as i32;
    *sample_l = (*sample_l * gain) >> 8;
    *sample_r = (*sample_r * gain) >> 8;
}
