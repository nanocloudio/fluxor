//! I2S PIO program and hardware constants.

/// System clock frequency (RP2350)
pub const SYS_FREQ_HZ: u32 = 150_000_000;

/// Cycles per stereo sample (32 bits × 2 cycles/bit)
pub const CYCLES_PER_SAMPLE: u32 = 64;

/// Buffer size in 32-bit words for PIO stream.
/// 512 words × 4 bytes = 2048 = abi::CHANNEL_BUFFER_SIZE.
/// Mailbox producers must fill exactly this many words per release;
/// I2S treats a size mismatch as a fatal error (see mod.rs §Mailbox contract).
pub const PIO_BUFFER_WORDS: usize = 512;

/// Shift bits for I2S (32-bit stereo frame)
pub const SHIFT_BITS: u8 = 32;

/// I2S PIO program (pre-assembled, matches pico-extras reference)
///
/// Side-set: bit 1 = LRCLK, bit 0 = BCLK (sideset_base+0=BCLK, +1=LRCLK)
///
/// The program generates standard I2S timing:
/// - 16-bit per channel, stereo
/// - MSB first
/// - LRCLK high = right channel, low = left channel
/// - Data changes on falling BCLK edge
pub static PROGRAM: [u16; 8] = [
    // bitloop1: (right channel, LRCLK=1)
    0x7001, // out pins, 1       side 0b10      ; Output bit, BCLK=0, LRCLK=1
    0x1840, // jmp x-- bitloop1  side 0b11      ; BCLK=1, LRCLK=1, loop if x>0
    // Last bit of right channel, transition LRCLK low
    0x6001, // out pins, 1       side 0b00      ; Output bit, BCLK=0, LRCLK->0
    0xe82e, // set x, 14         side 0b01      ; BCLK=1, LRCLK=0, setup for left
    // bitloop0: (left channel, LRCLK=0)
    0x6001, // out pins, 1       side 0b00      ; Output bit, BCLK=0, LRCLK=0
    0x0844, // jmp x-- bitloop0  side 0b01      ; BCLK=1, LRCLK=0, loop if x>0
    // Last bit of left channel, transition LRCLK high
    0x7001, // out pins, 1       side 0b10      ; Output bit, BCLK=0, LRCLK->1
    // entry_point:
    0xf82e, // set x, 14         side 0b11      ; BCLK=1, LRCLK=1, setup for right
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
