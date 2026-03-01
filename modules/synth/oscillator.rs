// Waveform generators for the synth oscillator.

use super::constants::*;
use super::state::VoiceState;

#[inline(always)]
pub fn gen_saw(phase: u32) -> i16 {
    let p = (phase >> 16) as i32;
    (p - 32768) as i16
}

#[inline(always)]
pub fn gen_square(phase: u32) -> i16 {
    if phase < 0x80000000 { 32767 } else { -32768 }
}

#[inline(always)]
pub fn gen_triangle(phase: u32) -> i16 {
    let p = (phase >> 16) as i32;
    if p < 32768 { (p * 2 - 32768) as i16 }
    else { (32767 - (p - 32768) * 2) as i16 }
}

#[inline(always)]
pub fn gen_pulse(phase: u32, width: u8) -> i16 {
    let threshold = (width as u32) << 24;
    if phase < threshold { 32767 } else { -32768 }
}

#[inline(always)]
pub fn gen_noise(lfsr: &mut u32) -> i16 {
    let bit = ((*lfsr >> 0) ^ (*lfsr >> 1) ^ (*lfsr >> 21) ^ (*lfsr >> 31)) & 1;
    *lfsr = (*lfsr >> 1) | (bit << 31);
    (*lfsr & 0xFFFF) as i16
}

#[inline(always)]
pub fn gen_sine(phase: u32) -> i16 {
    // Use top 10 bits: 2 for quadrant, 8 for table index
    // Next 6 bits for linear interpolation fraction
    let idx10 = (phase >> 22) as u16;
    let quadrant = (idx10 >> 8) as u8;
    let idx = (idx10 & 0xFF) as usize;
    let frac = ((phase >> 16) & 0x3F) as i32; // 6-bit fraction (0..63)
    unsafe {
        let ptr = SINE_QUARTER.as_ptr();
        let (a, b) = match quadrant {
            0 => {
                let a = *ptr.add(idx) as i32;
                let b = if idx < 255 { *ptr.add(idx + 1) as i32 } else { 32767 };
                (a, b)
            }
            1 => {
                let a = *ptr.add(255 - idx) as i32;
                let b = if idx < 255 { *ptr.add(254 - idx) as i32 } else { 0 };
                (a, b)
            }
            2 => {
                let a = -(*ptr.add(idx) as i32);
                let b = if idx < 255 { -(*ptr.add(idx + 1) as i32) } else { -32767 };
                (a, b)
            }
            _ => {
                let a = -(*ptr.add(255 - idx) as i32);
                let b = if idx < 255 { -(*ptr.add(254 - idx) as i32) } else { 0 };
                (a, b)
            }
        };
        (a + ((b - a) * frac >> 6)) as i16
    }
}

#[inline(always)]
pub fn sine_lfo(phase: u8) -> i8 {
    let quadrant = phase >> 6;
    let idx = (phase & 0x3F) as usize;
    unsafe {
        let ptr = SINE_TABLE.as_ptr();
        match quadrant {
            0 => *ptr.add(idx),
            1 => *ptr.add(63 - idx),
            2 => -*ptr.add(idx),
            _ => -*ptr.add(63 - idx),
        }
    }
}

/// Trigger pluck excitation: fill delay buffer with noise scaled by velocity.
pub fn trigger_pluck(v: &mut VoiceState, velocity: u8) {
    let len = v.pluck_delay_len as usize;
    if len == 0 || len > PLUCK_BUF_SIZE {
        return;
    }
    let amplitude = (velocity as i32) * 128; // 0..32640
    let buf_ptr = v.pluck_buf.as_mut_ptr();
    let lfsr = &mut v.lfsr;
    let mut i = 0;
    while i < len {
        let noise = gen_noise(lfsr);
        let scaled = ((noise as i32 * amplitude) >> 15) as i16;
        unsafe { *buf_ptr.add(i) = scaled; }
        i += 1;
    }
    v.pluck_read_pos = 0;
    v.pluck_prev_sample = 0;
}

/// Generate one pluck sample using Karplus-Strong algorithm.
#[inline(always)]
pub fn gen_pluck(v: &mut VoiceState, pluck_decay: u8, pluck_brightness: u8) -> i16 {
    let len = v.pluck_delay_len as usize;
    if len == 0 {
        return 0;
    }
    let pos = v.pluck_read_pos as usize;
    let buf_ptr = v.pluck_buf.as_mut_ptr();
    unsafe {
        let current = *buf_ptr.add(pos) as i32;
        let next_pos = if pos + 1 >= len { 0 } else { pos + 1 };
        let next = *buf_ptr.add(next_pos) as i32;

        // Karplus-Strong lowpass: blend current and averaged by brightness
        let averaged = (current + next) >> 1;
        let bright = pluck_brightness as i32;
        let filtered = ((current * (256 - bright)) + (averaged * bright)) >> 8;

        // Apply decay
        let decayed = (filtered * pluck_decay as i32) >> 8;
        *buf_ptr.add(pos) = decayed.clamp(-32768, 32767) as i16;

        v.pluck_read_pos = next_pos as u16;
        v.pluck_prev_sample = current as i16;
        current.clamp(-32768, 32767) as i16
    }
}
