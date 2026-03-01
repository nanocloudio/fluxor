//! I2S RX PIO program and hardware constants for microphone capture.
//!
//! Master mode: generates BCLK/LRCLK via sideset, samples data via `in pins`.
//! Mirrors the TX program structure but uses `in` instead of `out`.

/// System clock frequency (RP2350)
pub const SYS_FREQ_HZ: u32 = 150_000_000;

/// Cycles per stereo sample (32 bits x 2 cycles/bit)
pub const CYCLES_PER_SAMPLE: u32 = 64;

/// Buffer size in 32-bit words for PIO RX stream.
/// 512 words x 4 bytes = 2048 = abi::CHANNEL_BUFFER_SIZE.
pub const RX_BUFFER_WORDS: usize = 512;

/// Shift bits for I2S (32-bit stereo frame)
pub const SHIFT_BITS: u8 = 32;

/// I2S RX PIO program (pre-assembled, master mode)
///
/// Side-set: bit 1 = LRCLK, bit 0 = BCLK (sideset_base+0=BCLK, +1=LRCLK)
///
/// The program generates standard I2S timing and captures data:
/// - 16-bit per channel, stereo (32-bit frame)
/// - MSB first
/// - LRCLK high = right channel, low = left channel
/// - Data sampled on rising BCLK edge (side 0bx1)
pub static RX_PROGRAM: [u16; 8] = [
    // bitloop1: (right channel, LRCLK=1) — sample on rising BCLK
    0x5801, // in pins, 1       side 0b11      ; BCLK=1, LRCLK=1, sample bit
    0x1040, // jmp x-- 0        side 0b10      ; BCLK=0, LRCLK=1, loop if x>0
    // Last bit of right channel, transition LRCLK low
    0x4801, // in pins, 1       side 0b01      ; BCLK=1, LRCLK->0, sample last
    0xe02e, // set x, 14        side 0b00      ; BCLK=0, LRCLK=0, reload counter
    // bitloop0: (left channel, LRCLK=0)
    0x4801, // in pins, 1       side 0b01      ; BCLK=1, LRCLK=0, sample bit
    0x0044, // jmp x-- 4        side 0b00      ; BCLK=0, LRCLK=0, loop if x>0
    // Last bit of left channel, transition LRCLK high
    0x5801, // in pins, 1       side 0b11      ; BCLK=1, LRCLK->1, sample last
    // entry_point:
    0xf02e, // set x, 14        side 0b10      ; BCLK=0, LRCLK=1, setup for right
];

pub const WRAP_TARGET: u8 = 0;
pub const WRAP: u8 = 7;
pub const SIDESET_BITS: u8 = 2;
pub const OPTIONS: u8 = 0;

/// Calculate clock divider in 8.8 fixed point.
/// Uses 32-bit arithmetic to avoid __aeabi_uldivmod.
#[inline(always)]
pub fn calc_clock_div_88(sys_freq: u32, sample_rate: u32) -> u32 {
    if sample_rate == 0 {
        return 1 << 8;
    }
    let base = sys_freq / CYCLES_PER_SAMPLE;
    let shifted = base << 8; // Fits in u32: ~600M
    shifted / sample_rate
}
