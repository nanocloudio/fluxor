// ADSR envelope processing.

use super::constants::*;
use super::state::EnvState;

#[inline(always)]
pub fn env_trigger(env: &mut EnvState) {
    env.phase = EnvPhase::Attack;
}

#[inline(always)]
pub fn env_release(env: &mut EnvState) {
    if env.phase != EnvPhase::Idle { env.phase = EnvPhase::Release; }
}

#[inline(always)]
fn scale_rate(rate: u16, loop_scale: u8) -> u16 {
    if loop_scale == 100 { return rate; }
    let scaled = ((rate as u32) * (loop_scale as u32) / 100).clamp(1, 65535);
    scaled as u16
}

#[inline(always)]
pub fn env_process_loop(env: &mut EnvState, loop_mode: u8, loop_scale: u8) -> u16 {
    let attack_rate = if loop_mode != 0 { scale_rate(env.attack_rate, loop_scale) } else { env.attack_rate };
    let decay_rate = if loop_mode != 0 { scale_rate(env.decay_rate, loop_scale) } else { env.decay_rate };
    let release_rate = if loop_mode != 0 { scale_rate(env.release_rate, loop_scale) } else { env.release_rate };

    match env.phase {
        EnvPhase::Attack => {
            let new_level = env.level.saturating_add(attack_rate);
            if new_level >= 65535 {
                env.level = 65535;
                env.phase = EnvPhase::Decay;
            } else {
                env.level = new_level;
            }
        }
        EnvPhase::Decay => {
            if env.level > env.sustain_level {
                let diff = env.level - env.sustain_level;
                if diff <= decay_rate {
                    env.level = env.sustain_level;
                    if loop_mode == 1 {
                        // AD loop
                        env.phase = EnvPhase::Attack;
                    } else if loop_mode == 2 {
                        // ADR loop
                        env.phase = EnvPhase::Release;
                    } else {
                        env.phase = EnvPhase::Sustain;
                    }
                } else {
                    env.level -= decay_rate;
                }
            } else {
                if loop_mode == 1 {
                    env.phase = EnvPhase::Attack;
                } else if loop_mode == 2 {
                    env.phase = EnvPhase::Release;
                } else {
                    env.phase = EnvPhase::Sustain;
                }
            }
        }
        EnvPhase::Sustain => { env.level = env.sustain_level; }
        EnvPhase::Release => {
            if env.level <= release_rate {
                env.level = 0;
                if loop_mode == 2 {
                    env.phase = EnvPhase::Attack;
                } else {
                    env.phase = EnvPhase::Idle;
                }
            } else {
                env.level -= release_rate;
            }
        }
        _ => { env.level = 0; }
    }
    env.level
}

#[inline(always)]
pub fn env_process(env: &mut EnvState) -> u16 {
    env_process_loop(env, 0, 100)
}
