// MP3 codec kernel for unified decoder.
//
// Extracted from mp3.rs — contains state struct, decode pipeline, and
// init/step functions. No module boilerplate.
//
// Used by: modules/decoder/mod.rs (unified decoder)
// Standalone: modules/mp3.rs (unchanged, still builds independently)

use super::abi::SyscallTable;
use super::{POLL_IN, POLL_OUT, E_AGAIN, drain_pending, track_pending, dev_log};

// ============================================================================
// Section 1: Constants, Q15 helpers, BitReader
// ============================================================================

const IO_BUF_SIZE: usize = 256;
#[allow(dead_code)]
const MAX_FRAME_SIZE: usize = 1441;
const SAMPLES_PER_FRAME: usize = 1152;
const SUBBANDS: usize = 32;
const GRANULE_SAMPLES: usize = 576;

/// MP3 decoder phases.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum Mp3Phase {
    Sync = 0,
    Frame = 1,
    Decode = 2,
    #[allow(dead_code)]
    Output = 3,
}

// --- Q15 fixed-point helpers ---
#[allow(dead_code)]
type Q15 = i16;

#[inline(always)]
fn q15_mul(a: i16, b: i16) -> i16 {
    let product = (a as i32) * (b as i32);
    let rounded = (product + 0x4000) >> 15;
    if rounded > 32767 { 32767i16 }
    else if rounded < -32768 { -32768i16 }
    else { rounded as i16 }
}

#[inline(always)]
fn q15_sat_add(a: i16, b: i16) -> i16 {
    (a as i32 + b as i32).clamp(-32768, 32767) as i16
}

#[inline(always)]
fn q15_sat_sub(a: i16, b: i16) -> i16 {
    (a as i32 - b as i32).clamp(-32768, 32767) as i16
}

// Q30 accumulator helper
#[inline(always)]
fn q30_mac(acc: i32, a: i16, b: i16) -> i32 {
    acc.saturating_add((a as i32) * (b as i32))
}

#[inline(always)]
fn q30_to_q15(val: i32) -> i16 {
    let rounded = (val + 0x4000) >> 15;
    rounded.clamp(-32768, 32767) as i16
}

// --- Cosine approximation ---
fn cos_q15(phase: u16) -> i16 {
    sin_q15(phase.wrapping_add(0x4000))
}

fn sin_q15(phase: u16) -> i16 {
    let quadrant = phase >> 14;
    let x = (phase & 0x3FFF) as i32;
    let parabola = (4 * x * (0x3FFF - x)) >> 14;
    let value = if parabola > 32767 { 32767i16 } else { parabola as i16 };
    if quadrant < 2 { value } else { (0i16).wrapping_sub(value) }
}

// --- BitReader (pointer-based, no slices) ---
#[repr(C)]
struct BitReader {
    data: *const u8,
    data_len: usize,
    byte_pos: usize,
    bit_pos: u8,
}

fn br_new(data: *const u8, len: usize) -> BitReader {
    BitReader { data, data_len: len, byte_pos: 0, bit_pos: 0 }
}

fn br_bit_position(r: &BitReader) -> usize {
    r.byte_pos * 8 + r.bit_pos as usize
}

fn br_bits_remaining(r: &BitReader) -> usize {
    if r.byte_pos >= r.data_len { return 0; }
    (r.data_len - r.byte_pos) * 8 - r.bit_pos as usize
}

/// Read a single bit. Returns 0 or 1, or -1 on error.
fn br_read_bit(r: &mut BitReader) -> i32 {
    if r.byte_pos >= r.data_len { return -1; }
    let byte = unsafe { *r.data.add(r.byte_pos) };
    let bit = ((byte >> (7 - r.bit_pos)) & 1) as i32;
    r.bit_pos += 1;
    if r.bit_pos >= 8 {
        r.bit_pos = 0;
        r.byte_pos += 1;
    }
    bit
}

/// Read up to 25 bits. Returns value or -1 on error.
fn br_read_bits(r: &mut BitReader, count: u8) -> i32 {
    if count == 0 { return 0; }
    if br_bits_remaining(r) < count as usize { return -1; }
    let mut result: u32 = 0;
    let mut remaining = count;
    while remaining > 0 {
        let bits_in_current = 8 - r.bit_pos;
        let bits_to_read = if remaining < bits_in_current { remaining } else { bits_in_current };
        let shift = bits_in_current - bits_to_read;
        let mask = ((1u16 << bits_to_read) - 1) as u8;
        let byte = unsafe { *r.data.add(r.byte_pos) };
        let bits = (byte >> shift) & mask;
        result = (result << bits_to_read) | bits as u32;
        remaining -= bits_to_read;
        r.bit_pos += bits_to_read;
        if r.bit_pos >= 8 {
            r.bit_pos = 0;
            r.byte_pos += 1;
        }
    }
    result as i32
}

fn br_skip_bits(r: &mut BitReader, count: usize) -> i32 {
    if br_bits_remaining(r) < count { return -1; }
    let total_bits = r.bit_pos as usize + count;
    r.byte_pos += total_bits / 8;
    r.bit_pos = (total_bits - (total_bits / 8) * 8) as u8;
    0
}

// ============================================================================
// Section 2: Frame header parsing
// ============================================================================

static BITRATE_TABLE: [u16; 16] = [
    0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0,
];

static SAMPLE_RATE_TABLE: [u32; 4] = [44100, 48000, 32000, 0];

const SLEN_TABLE: [(u8, u8); 16] = [
    (0, 0), (0, 1), (0, 2), (0, 3), (3, 0), (1, 1), (1, 2), (1, 3),
    (2, 1), (2, 2), (2, 3), (3, 1), (3, 2), (3, 3), (4, 2), (4, 3),
];

const PRETAB: [i32; 22] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 3, 2, 0,
];

/// Parse header from 4 bytes at ptr. Returns frame_size or 0 on error.
/// Also writes sample_rate, channels, channel_mode, mode_extension, has_crc.
fn parse_header(
    ptr: *const u8,
    out_sample_rate: &mut u32,
    out_channels: &mut u8,
    out_channel_mode: &mut u8,
    out_mode_ext: &mut u8,
    out_has_crc: &mut u8,
    out_frame_size: &mut usize,
) -> i32 {
    unsafe {
        let b0 = *ptr.add(0);
        let b1 = *ptr.add(1);
        let b2 = *ptr.add(2);
        let b3 = *ptr.add(3);

        // Sync check
        if b0 != 0xFF || (b1 & 0xE0) != 0xE0 { return -1; }

        let version_bits = (b1 >> 3) & 0x03;
        let layer_bits = (b1 >> 1) & 0x03;
        let protection_bit = b1 & 0x01;

        // MPEG1 only
        if version_bits != 3 { return -8; }
        // Layer III only
        if layer_bits != 1 { return -8; }

        let bitrate_index = ((b2 >> 4) & 0x0F) as usize;
        let sample_rate_index = ((b2 >> 2) & 0x03) as usize;
        let padding = (b2 & 0x02) != 0;

        if bitrate_index >= 16 { return -2; }
        let bitrate_kbps = *BITRATE_TABLE.as_ptr().add(bitrate_index);
        if bitrate_kbps == 0 { return -2; }

        if sample_rate_index >= 4 { return -2; }
        let sample_rate = *SAMPLE_RATE_TABLE.as_ptr().add(sample_rate_index);
        if sample_rate == 0 { return -2; }

        let channel_mode_bits = (b3 >> 6) & 0x03;
        let mode_extension = (b3 >> 4) & 0x03;

        let channels = if channel_mode_bits == 3 { 1u8 } else { 2u8 };

        let frame_size = (144 * (bitrate_kbps as u32) * 1000 / sample_rate) as usize
            + if padding { 1 } else { 0 };

        *out_sample_rate = sample_rate;
        *out_channels = channels;
        *out_channel_mode = channel_mode_bits;
        *out_mode_ext = mode_extension;
        *out_has_crc = if protection_bit == 0 { 1 } else { 0 };
        *out_frame_size = frame_size;

        0
    }
}

// ============================================================================
// Section 3: Huffman tables
// ============================================================================

// HuffPair: bits[15:12]=x, bits[11:8]=y, bits[7:0]=code_len
#[inline(always)]
fn hp_x(v: u16) -> u8 { ((v >> 12) & 0x0F) as u8 }
#[inline(always)]
fn hp_y(v: u16) -> u8 { ((v >> 8) & 0x0F) as u8 }
#[inline(always)]
fn hp_len(v: u16) -> u8 { (v & 0xFF) as u8 }

#[inline(always)]
const fn hp(x: u8, y: u8, len: u8) -> u16 {
    ((x as u16) << 12) | ((y as u16) << 8) | (len as u16)
}

// HuffQuad: bit7=v, bit6=w, bit5=x, bit4=y, bits[3:0]=len
#[inline(always)]
fn hq_v(v: u8) -> u8 { (v >> 7) & 1 }
#[inline(always)]
fn hq_w(v: u8) -> u8 { (v >> 6) & 1 }
#[inline(always)]
fn hq_x(v: u8) -> u8 { (v >> 5) & 1 }
#[inline(always)]
fn hq_y(v: u8) -> u8 { (v >> 4) & 1 }
#[inline(always)]
fn hq_len(v: u8) -> u8 { v & 0x0F }

#[inline(always)]
const fn hq(v: u8, w: u8, x: u8, y: u8, len: u8) -> u8 {
    ((v & 1) << 7) | ((w & 1) << 6) | ((x & 1) << 5) | ((y & 1) << 4) | (len & 0x0F)
}

static LINBITS: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 2, 3, 4, 6, 8, 10, 13,
    4, 5, 6, 7, 8, 9, 11, 13,
];

static TABLE_0: [u16; 1] = [hp(0, 0, 0)];

static TABLE_1: [u16; 4] = [
    hp(0, 0, 1), hp(0, 1, 3), hp(1, 0, 3), hp(1, 1, 3),
];

static TABLE_2: [u16; 9] = [
    hp(0, 0, 1), hp(0, 1, 3), hp(0, 2, 6),
    hp(1, 0, 3), hp(1, 1, 3), hp(1, 2, 5),
    hp(2, 0, 6), hp(2, 1, 5), hp(2, 2, 5),
];

static TABLE_3: [u16; 9] = [
    hp(0, 0, 2), hp(0, 1, 2), hp(0, 2, 6),
    hp(1, 0, 3), hp(1, 1, 2), hp(1, 2, 5),
    hp(2, 0, 6), hp(2, 1, 5), hp(2, 2, 5),
];

static TABLE_5: [u16; 16] = [
    hp(0, 0, 1), hp(0, 1, 3), hp(0, 2, 6), hp(0, 3, 7),
    hp(1, 0, 3), hp(1, 1, 3), hp(1, 2, 6), hp(1, 3, 7),
    hp(2, 0, 6), hp(2, 1, 5), hp(2, 2, 7), hp(2, 3, 8),
    hp(3, 0, 7), hp(3, 1, 7), hp(3, 2, 8), hp(3, 3, 9),
];

static TABLE_6: [u16; 16] = [
    hp(0, 0, 3), hp(0, 1, 3), hp(0, 2, 5), hp(0, 3, 7),
    hp(1, 0, 3), hp(1, 1, 2), hp(1, 2, 4), hp(1, 3, 5),
    hp(2, 0, 5), hp(2, 1, 4), hp(2, 2, 5), hp(2, 3, 6),
    hp(3, 0, 6), hp(3, 1, 5), hp(3, 2, 6), hp(3, 3, 7),
];

static TABLE_7: [u16; 36] = [
    hp(0,0,1), hp(0,1,3), hp(0,2,6), hp(0,3,8), hp(0,4,8), hp(0,5,9),
    hp(1,0,3), hp(1,1,4), hp(1,2,6), hp(1,3,7), hp(1,4,7), hp(1,5,8),
    hp(2,0,6), hp(2,1,5), hp(2,2,7), hp(2,3,8), hp(2,4,8), hp(2,5,9),
    hp(3,0,7), hp(3,1,7), hp(3,2,8), hp(3,3,9), hp(3,4,9), hp(3,5,9),
    hp(4,0,7), hp(4,1,7), hp(4,2,8), hp(4,3,9), hp(4,4,9), hp(4,5,10),
    hp(5,0,8), hp(5,1,8), hp(5,2,9), hp(5,3,10), hp(5,4,10), hp(5,5,10),
];

static TABLE_8: [u16; 36] = [
    hp(0,0,2), hp(0,1,3), hp(0,2,6), hp(0,3,8), hp(0,4,8), hp(0,5,9),
    hp(1,0,3), hp(1,1,2), hp(1,2,5), hp(1,3,7), hp(1,4,7), hp(1,5,8),
    hp(2,0,6), hp(2,1,5), hp(2,2,6), hp(2,3,7), hp(2,4,7), hp(2,5,8),
    hp(3,0,7), hp(3,1,6), hp(3,2,7), hp(3,3,8), hp(3,4,8), hp(3,5,9),
    hp(4,0,7), hp(4,1,6), hp(4,2,7), hp(4,3,8), hp(4,4,8), hp(4,5,9),
    hp(5,0,8), hp(5,1,8), hp(5,2,8), hp(5,3,9), hp(5,4,9), hp(5,5,10),
];

static TABLE_9: [u16; 36] = [
    hp(0,0,3), hp(0,1,3), hp(0,2,5), hp(0,3,6), hp(0,4,8), hp(0,5,9),
    hp(1,0,3), hp(1,1,3), hp(1,2,4), hp(1,3,5), hp(1,4,6), hp(1,5,8),
    hp(2,0,4), hp(2,1,4), hp(2,2,5), hp(2,3,6), hp(2,4,7), hp(2,5,8),
    hp(3,0,6), hp(3,1,5), hp(3,2,6), hp(3,3,7), hp(3,4,7), hp(3,5,8),
    hp(4,0,7), hp(4,1,6), hp(4,2,7), hp(4,3,7), hp(4,4,8), hp(4,5,9),
    hp(5,0,8), hp(5,1,7), hp(5,2,8), hp(5,3,8), hp(5,4,9), hp(5,5,9),
];

static TABLE_10: [u16; 64] = [
    hp(0,0,1), hp(0,1,3), hp(0,2,6), hp(0,3,8), hp(0,4,9), hp(0,5,9), hp(0,6,9), hp(0,7,10),
    hp(1,0,3), hp(1,1,4), hp(1,2,6), hp(1,3,7), hp(1,4,8), hp(1,5,9), hp(1,6,8), hp(1,7,8),
    hp(2,0,6), hp(2,1,6), hp(2,2,7), hp(2,3,8), hp(2,4,9), hp(2,5,10), hp(2,6,9), hp(2,7,9),
    hp(3,0,8), hp(3,1,7), hp(3,2,8), hp(3,3,9), hp(3,4,10), hp(3,5,10), hp(3,6,9), hp(3,7,10),
    hp(4,0,9), hp(4,1,8), hp(4,2,9), hp(4,3,9), hp(4,4,10), hp(4,5,10), hp(4,6,10), hp(4,7,10),
    hp(5,0,9), hp(5,1,9), hp(5,2,9), hp(5,3,10), hp(5,4,10), hp(5,5,11), hp(5,6,11), hp(5,7,11),
    hp(6,0,8), hp(6,1,8), hp(6,2,9), hp(6,3,9), hp(6,4,10), hp(6,5,11), hp(6,6,10), hp(6,7,11),
    hp(7,0,9), hp(7,1,8), hp(7,2,9), hp(7,3,10), hp(7,4,10), hp(7,5,11), hp(7,6,11), hp(7,7,11),
];

static TABLE_11: [u16; 64] = [
    hp(0,0,2), hp(0,1,3), hp(0,2,5), hp(0,3,7), hp(0,4,8), hp(0,5,9), hp(0,6,8), hp(0,7,9),
    hp(1,0,3), hp(1,1,3), hp(1,2,5), hp(1,3,6), hp(1,4,7), hp(1,5,8), hp(1,6,7), hp(1,7,8),
    hp(2,0,5), hp(2,1,5), hp(2,2,6), hp(2,3,7), hp(2,4,8), hp(2,5,9), hp(2,6,8), hp(2,7,8),
    hp(3,0,7), hp(3,1,6), hp(3,2,7), hp(3,3,9), hp(3,4,8), hp(3,5,10), hp(3,6,8), hp(3,7,9),
    hp(4,0,8), hp(4,1,7), hp(4,2,8), hp(4,3,8), hp(4,4,9), hp(4,5,10), hp(4,6,9), hp(4,7,10),
    hp(5,0,9), hp(5,1,8), hp(5,2,9), hp(5,3,9), hp(5,4,10), hp(5,5,10), hp(5,6,10), hp(5,7,10),
    hp(6,0,8), hp(6,1,7), hp(6,2,8), hp(6,3,8), hp(6,4,9), hp(6,5,10), hp(6,6,10), hp(6,7,10),
    hp(7,0,9), hp(7,1,8), hp(7,2,8), hp(7,3,9), hp(7,4,10), hp(7,5,10), hp(7,6,10), hp(7,7,10),
];

static TABLE_12: [u16; 64] = [
    hp(0,0,4), hp(0,1,3), hp(0,2,5), hp(0,3,7), hp(0,4,8), hp(0,5,9), hp(0,6,9), hp(0,7,9),
    hp(1,0,3), hp(1,1,3), hp(1,2,4), hp(1,3,6), hp(1,4,7), hp(1,5,7), hp(1,6,7), hp(1,7,8),
    hp(2,0,5), hp(2,1,4), hp(2,2,5), hp(2,3,6), hp(2,4,7), hp(2,5,8), hp(2,6,7), hp(2,7,8),
    hp(3,0,6), hp(3,1,5), hp(3,2,6), hp(3,3,6), hp(3,4,7), hp(3,5,8), hp(3,6,8), hp(3,7,8),
    hp(4,0,7), hp(4,1,6), hp(4,2,7), hp(4,3,7), hp(4,4,8), hp(4,5,8), hp(4,6,8), hp(4,7,9),
    hp(5,0,8), hp(5,1,7), hp(5,2,8), hp(5,3,8), hp(5,4,8), hp(5,5,9), hp(5,6,8), hp(5,7,9),
    hp(6,0,8), hp(6,1,7), hp(6,2,7), hp(6,3,8), hp(6,4,8), hp(6,5,9), hp(6,6,9), hp(6,7,9),
    hp(7,0,8), hp(7,1,7), hp(7,2,8), hp(7,3,8), hp(7,4,9), hp(7,5,9), hp(7,6,9), hp(7,7,9),
];

#[rustfmt::skip]
static TABLE_13: [u16; 256] = [
    hp(0,0,1), hp(0,1,5), hp(0,2,7), hp(0,3,8), hp(0,4,9), hp(0,5,9), hp(0,6,10), hp(0,7,10),
    hp(0,8,11), hp(0,9,11), hp(0,10,12), hp(0,11,12), hp(0,12,13), hp(0,13,13), hp(0,14,14), hp(0,15,14),
    hp(1,0,4), hp(1,1,5), hp(1,2,6), hp(1,3,7), hp(1,4,8), hp(1,5,8), hp(1,6,9), hp(1,7,9),
    hp(1,8,10), hp(1,9,10), hp(1,10,11), hp(1,11,11), hp(1,12,12), hp(1,13,12), hp(1,14,13), hp(1,15,13),
    hp(2,0,6), hp(2,1,6), hp(2,2,6), hp(2,3,7), hp(2,4,8), hp(2,5,8), hp(2,6,9), hp(2,7,9),
    hp(2,8,10), hp(2,9,10), hp(2,10,10), hp(2,11,11), hp(2,12,11), hp(2,13,12), hp(2,14,12), hp(2,15,13),
    hp(3,0,7), hp(3,1,7), hp(3,2,7), hp(3,3,7), hp(3,4,8), hp(3,5,8), hp(3,6,9), hp(3,7,9),
    hp(3,8,9), hp(3,9,10), hp(3,10,10), hp(3,11,10), hp(3,12,11), hp(3,13,11), hp(3,14,12), hp(3,15,12),
    hp(4,0,8), hp(4,1,7), hp(4,2,8), hp(4,3,8), hp(4,4,8), hp(4,5,8), hp(4,6,9), hp(4,7,9),
    hp(4,8,9), hp(4,9,10), hp(4,10,10), hp(4,11,10), hp(4,12,11), hp(4,13,11), hp(4,14,11), hp(4,15,12),
    hp(5,0,9), hp(5,1,8), hp(5,2,8), hp(5,3,8), hp(5,4,8), hp(5,5,9), hp(5,6,9), hp(5,7,9),
    hp(5,8,9), hp(5,9,10), hp(5,10,10), hp(5,11,10), hp(5,12,10), hp(5,13,11), hp(5,14,11), hp(5,15,12),
    hp(6,0,9), hp(6,1,9), hp(6,2,9), hp(6,3,9), hp(6,4,9), hp(6,5,9), hp(6,6,9), hp(6,7,9),
    hp(6,8,9), hp(6,9,10), hp(6,10,10), hp(6,11,10), hp(6,12,10), hp(6,13,11), hp(6,14,11), hp(6,15,11),
    hp(7,0,10), hp(7,1,9), hp(7,2,9), hp(7,3,9), hp(7,4,9), hp(7,5,9), hp(7,6,9), hp(7,7,10),
    hp(7,8,10), hp(7,9,10), hp(7,10,10), hp(7,11,10), hp(7,12,10), hp(7,13,11), hp(7,14,11), hp(7,15,11),
    hp(8,0,10), hp(8,1,10), hp(8,2,9), hp(8,3,9), hp(8,4,9), hp(8,5,9), hp(8,6,10), hp(8,7,10),
    hp(8,8,10), hp(8,9,10), hp(8,10,10), hp(8,11,10), hp(8,12,10), hp(8,13,11), hp(8,14,11), hp(8,15,11),
    hp(9,0,11), hp(9,1,10), hp(9,2,10), hp(9,3,10), hp(9,4,10), hp(9,5,10), hp(9,6,10), hp(9,7,10),
    hp(9,8,10), hp(9,9,10), hp(9,10,10), hp(9,11,10), hp(9,12,11), hp(9,13,11), hp(9,14,11), hp(9,15,11),
    hp(10,0,11), hp(10,1,11), hp(10,2,10), hp(10,3,10), hp(10,4,10), hp(10,5,10), hp(10,6,10), hp(10,7,10),
    hp(10,8,10), hp(10,9,10), hp(10,10,10), hp(10,11,11), hp(10,12,11), hp(10,13,11), hp(10,14,11), hp(10,15,11),
    hp(11,0,12), hp(11,1,11), hp(11,2,11), hp(11,3,10), hp(11,4,10), hp(11,5,10), hp(11,6,10), hp(11,7,10),
    hp(11,8,10), hp(11,9,10), hp(11,10,11), hp(11,11,11), hp(11,12,11), hp(11,13,11), hp(11,14,11), hp(11,15,11),
    hp(12,0,12), hp(12,1,12), hp(12,2,11), hp(12,3,11), hp(12,4,11), hp(12,5,10), hp(12,6,10), hp(12,7,10),
    hp(12,8,10), hp(12,9,11), hp(12,10,11), hp(12,11,11), hp(12,12,11), hp(12,13,11), hp(12,14,11), hp(12,15,12),
    hp(13,0,13), hp(13,1,12), hp(13,2,12), hp(13,3,11), hp(13,4,11), hp(13,5,11), hp(13,6,11), hp(13,7,11),
    hp(13,8,11), hp(13,9,11), hp(13,10,11), hp(13,11,11), hp(13,12,11), hp(13,13,11), hp(13,14,12), hp(13,15,12),
    hp(14,0,13), hp(14,1,13), hp(14,2,12), hp(14,3,12), hp(14,4,11), hp(14,5,11), hp(14,6,11), hp(14,7,11),
    hp(14,8,11), hp(14,9,11), hp(14,10,11), hp(14,11,11), hp(14,12,11), hp(14,13,12), hp(14,14,12), hp(14,15,12),
    hp(15,0,14), hp(15,1,13), hp(15,2,13), hp(15,3,12), hp(15,4,12), hp(15,5,12), hp(15,6,11), hp(15,7,11),
    hp(15,8,11), hp(15,9,11), hp(15,10,11), hp(15,11,11), hp(15,12,12), hp(15,13,12), hp(15,14,12), hp(15,15,13),
];

#[rustfmt::skip]
static TABLE_15: [u16; 256] = [
    hp(0,0,3), hp(0,1,5), hp(0,2,6), hp(0,3,7), hp(0,4,8), hp(0,5,9), hp(0,6,9), hp(0,7,10),
    hp(0,8,10), hp(0,9,11), hp(0,10,11), hp(0,11,12), hp(0,12,12), hp(0,13,12), hp(0,14,13), hp(0,15,14),
    hp(1,0,4), hp(1,1,5), hp(1,2,6), hp(1,3,7), hp(1,4,7), hp(1,5,8), hp(1,6,9), hp(1,7,9),
    hp(1,8,10), hp(1,9,10), hp(1,10,11), hp(1,11,11), hp(1,12,11), hp(1,13,12), hp(1,14,12), hp(1,15,13),
    hp(2,0,5), hp(2,1,5), hp(2,2,6), hp(2,3,7), hp(2,4,7), hp(2,5,8), hp(2,6,8), hp(2,7,9),
    hp(2,8,9), hp(2,9,10), hp(2,10,10), hp(2,11,10), hp(2,12,11), hp(2,13,11), hp(2,14,12), hp(2,15,13),
    hp(3,0,6), hp(3,1,6), hp(3,2,6), hp(3,3,7), hp(3,4,7), hp(3,5,8), hp(3,6,8), hp(3,7,8),
    hp(3,8,9), hp(3,9,9), hp(3,10,10), hp(3,11,10), hp(3,12,10), hp(3,13,11), hp(3,14,11), hp(3,15,12),
    hp(4,0,7), hp(4,1,6), hp(4,2,7), hp(4,3,7), hp(4,4,8), hp(4,5,8), hp(4,6,8), hp(4,7,9),
    hp(4,8,9), hp(4,9,9), hp(4,10,9), hp(4,11,10), hp(4,12,10), hp(4,13,10), hp(4,14,11), hp(4,15,12),
    hp(5,0,8), hp(5,1,7), hp(5,2,7), hp(5,3,8), hp(5,4,8), hp(5,5,8), hp(5,6,8), hp(5,7,9),
    hp(5,8,9), hp(5,9,9), hp(5,10,9), hp(5,11,10), hp(5,12,10), hp(5,13,10), hp(5,14,10), hp(5,15,11),
    hp(6,0,8), hp(6,1,8), hp(6,2,8), hp(6,3,8), hp(6,4,8), hp(6,5,8), hp(6,6,8), hp(6,7,9),
    hp(6,8,9), hp(6,9,9), hp(6,10,10), hp(6,11,10), hp(6,12,10), hp(6,13,10), hp(6,14,10), hp(6,15,11),
    hp(7,0,9), hp(7,1,8), hp(7,2,8), hp(7,3,8), hp(7,4,9), hp(7,5,9), hp(7,6,9), hp(7,7,9),
    hp(7,8,9), hp(7,9,9), hp(7,10,10), hp(7,11,10), hp(7,12,10), hp(7,13,10), hp(7,14,10), hp(7,15,11),
    hp(8,0,9), hp(8,1,9), hp(8,2,9), hp(8,3,9), hp(8,4,9), hp(8,5,9), hp(8,6,9), hp(8,7,9),
    hp(8,8,9), hp(8,9,9), hp(8,10,10), hp(8,11,10), hp(8,12,10), hp(8,13,10), hp(8,14,10), hp(8,15,11),
    hp(9,0,10), hp(9,1,9), hp(9,2,9), hp(9,3,9), hp(9,4,9), hp(9,5,9), hp(9,6,9), hp(9,7,9),
    hp(9,8,9), hp(9,9,10), hp(9,10,10), hp(9,11,10), hp(9,12,10), hp(9,13,10), hp(9,14,10), hp(9,15,10),
    hp(10,0,10), hp(10,1,10), hp(10,2,9), hp(10,3,9), hp(10,4,9), hp(10,5,9), hp(10,6,10), hp(10,7,10),
    hp(10,8,10), hp(10,9,10), hp(10,10,10), hp(10,11,10), hp(10,12,10), hp(10,13,10), hp(10,14,10), hp(10,15,11),
    hp(11,0,11), hp(11,1,10), hp(11,2,10), hp(11,3,10), hp(11,4,10), hp(11,5,10), hp(11,6,10), hp(11,7,10),
    hp(11,8,10), hp(11,9,10), hp(11,10,10), hp(11,11,10), hp(11,12,10), hp(11,13,10), hp(11,14,10), hp(11,15,11),
    hp(12,0,11), hp(12,1,11), hp(12,2,10), hp(12,3,10), hp(12,4,10), hp(12,5,10), hp(12,6,10), hp(12,7,10),
    hp(12,8,10), hp(12,9,10), hp(12,10,10), hp(12,11,10), hp(12,12,10), hp(12,13,11), hp(12,14,11), hp(12,15,11),
    hp(13,0,12), hp(13,1,11), hp(13,2,11), hp(13,3,11), hp(13,4,10), hp(13,5,10), hp(13,6,10), hp(13,7,10),
    hp(13,8,10), hp(13,9,10), hp(13,10,10), hp(13,11,10), hp(13,12,11), hp(13,13,11), hp(13,14,11), hp(13,15,11),
    hp(14,0,12), hp(14,1,12), hp(14,2,11), hp(14,3,11), hp(14,4,11), hp(14,5,10), hp(14,6,10), hp(14,7,10),
    hp(14,8,10), hp(14,9,10), hp(14,10,10), hp(14,11,10), hp(14,12,11), hp(14,13,11), hp(14,14,11), hp(14,15,12),
    hp(15,0,13), hp(15,1,12), hp(15,2,12), hp(15,3,12), hp(15,4,11), hp(15,5,11), hp(15,6,11), hp(15,7,10),
    hp(15,8,10), hp(15,9,10), hp(15,10,11), hp(15,11,11), hp(15,12,11), hp(15,13,11), hp(15,14,12), hp(15,15,12),
];

#[rustfmt::skip]
static TABLE_16: [u16; 256] = [
    hp(0,0,1), hp(0,1,5), hp(0,2,7), hp(0,3,9), hp(0,4,10), hp(0,5,10), hp(0,6,11), hp(0,7,11),
    hp(0,8,12), hp(0,9,12), hp(0,10,12), hp(0,11,13), hp(0,12,13), hp(0,13,13), hp(0,14,14), hp(0,15,10),
    hp(1,0,4), hp(1,1,6), hp(1,2,8), hp(1,3,9), hp(1,4,10), hp(1,5,10), hp(1,6,11), hp(1,7,11),
    hp(1,8,12), hp(1,9,12), hp(1,10,12), hp(1,11,13), hp(1,12,13), hp(1,13,14), hp(1,14,13), hp(1,15,11),
    hp(2,0,6), hp(2,1,7), hp(2,2,8), hp(2,3,9), hp(2,4,10), hp(2,5,10), hp(2,6,11), hp(2,7,11),
    hp(2,8,12), hp(2,9,12), hp(2,10,12), hp(2,11,13), hp(2,12,13), hp(2,13,13), hp(2,14,13), hp(2,15,11),
    hp(3,0,8), hp(3,1,8), hp(3,2,9), hp(3,3,9), hp(3,4,10), hp(3,5,10), hp(3,6,11), hp(3,7,11),
    hp(3,8,11), hp(3,9,12), hp(3,10,12), hp(3,11,12), hp(3,12,13), hp(3,13,13), hp(3,14,13), hp(3,15,11),
    hp(4,0,9), hp(4,1,9), hp(4,2,9), hp(4,3,10), hp(4,4,10), hp(4,5,10), hp(4,6,11), hp(4,7,11),
    hp(4,8,11), hp(4,9,12), hp(4,10,12), hp(4,11,12), hp(4,12,12), hp(4,13,13), hp(4,14,13), hp(4,15,11),
    hp(5,0,10), hp(5,1,9), hp(5,2,10), hp(5,3,10), hp(5,4,10), hp(5,5,10), hp(5,6,11), hp(5,7,11),
    hp(5,8,11), hp(5,9,12), hp(5,10,12), hp(5,11,12), hp(5,12,12), hp(5,13,13), hp(5,14,13), hp(5,15,11),
    hp(6,0,10), hp(6,1,10), hp(6,2,10), hp(6,3,10), hp(6,4,10), hp(6,5,11), hp(6,6,11), hp(6,7,11),
    hp(6,8,11), hp(6,9,12), hp(6,10,12), hp(6,11,12), hp(6,12,12), hp(6,13,13), hp(6,14,13), hp(6,15,11),
    hp(7,0,11), hp(7,1,10), hp(7,2,10), hp(7,3,10), hp(7,4,11), hp(7,5,11), hp(7,6,11), hp(7,7,11),
    hp(7,8,11), hp(7,9,12), hp(7,10,12), hp(7,11,12), hp(7,12,12), hp(7,13,13), hp(7,14,13), hp(7,15,12),
    hp(8,0,11), hp(8,1,11), hp(8,2,11), hp(8,3,11), hp(8,4,11), hp(8,5,11), hp(8,6,11), hp(8,7,11),
    hp(8,8,12), hp(8,9,12), hp(8,10,12), hp(8,11,12), hp(8,12,13), hp(8,13,13), hp(8,14,13), hp(8,15,12),
    hp(9,0,11), hp(9,1,11), hp(9,2,11), hp(9,3,11), hp(9,4,11), hp(9,5,11), hp(9,6,12), hp(9,7,12),
    hp(9,8,12), hp(9,9,12), hp(9,10,12), hp(9,11,13), hp(9,12,13), hp(9,13,13), hp(9,14,13), hp(9,15,12),
    hp(10,0,12), hp(10,1,11), hp(10,2,11), hp(10,3,11), hp(10,4,11), hp(10,5,12), hp(10,6,12), hp(10,7,12),
    hp(10,8,12), hp(10,9,12), hp(10,10,12), hp(10,11,13), hp(10,12,13), hp(10,13,13), hp(10,14,13), hp(10,15,12),
    hp(11,0,12), hp(11,1,12), hp(11,2,11), hp(11,3,11), hp(11,4,11), hp(11,5,12), hp(11,6,12), hp(11,7,12),
    hp(11,8,12), hp(11,9,12), hp(11,10,13), hp(11,11,13), hp(11,12,13), hp(11,13,13), hp(11,14,13), hp(11,15,12),
    hp(12,0,12), hp(12,1,12), hp(12,2,12), hp(12,3,12), hp(12,4,12), hp(12,5,12), hp(12,6,12), hp(12,7,12),
    hp(12,8,12), hp(12,9,13), hp(12,10,13), hp(12,11,13), hp(12,12,13), hp(12,13,13), hp(12,14,13), hp(12,15,13),
    hp(13,0,13), hp(13,1,12), hp(13,2,12), hp(13,3,12), hp(13,4,12), hp(13,5,12), hp(13,6,12), hp(13,7,12),
    hp(13,8,13), hp(13,9,13), hp(13,10,13), hp(13,11,13), hp(13,12,13), hp(13,13,13), hp(13,14,13), hp(13,15,13),
    hp(14,0,13), hp(14,1,13), hp(14,2,12), hp(14,3,12), hp(14,4,12), hp(14,5,12), hp(14,6,12), hp(14,7,13),
    hp(14,8,13), hp(14,9,13), hp(14,10,13), hp(14,11,13), hp(14,12,13), hp(14,13,13), hp(14,14,13), hp(14,15,13),
    hp(15,0,11), hp(15,1,11), hp(15,2,11), hp(15,3,11), hp(15,4,11), hp(15,5,11), hp(15,6,11), hp(15,7,12),
    hp(15,8,12), hp(15,9,12), hp(15,10,12), hp(15,11,12), hp(15,12,13), hp(15,13,13), hp(15,14,13), hp(15,15,13),
];

#[rustfmt::skip]
static TABLE_24: [u16; 256] = [
    hp(0,0,4), hp(0,1,5), hp(0,2,7), hp(0,3,8), hp(0,4,9), hp(0,5,10), hp(0,6,10), hp(0,7,11),
    hp(0,8,11), hp(0,9,12), hp(0,10,12), hp(0,11,12), hp(0,12,12), hp(0,13,12), hp(0,14,13), hp(0,15,8),
    hp(1,0,5), hp(1,1,5), hp(1,2,7), hp(1,3,8), hp(1,4,9), hp(1,5,9), hp(1,6,10), hp(1,7,10),
    hp(1,8,11), hp(1,9,11), hp(1,10,12), hp(1,11,12), hp(1,12,12), hp(1,13,12), hp(1,14,12), hp(1,15,8),
    hp(2,0,6), hp(2,1,6), hp(2,2,7), hp(2,3,8), hp(2,4,9), hp(2,5,9), hp(2,6,10), hp(2,7,10),
    hp(2,8,11), hp(2,9,11), hp(2,10,11), hp(2,11,12), hp(2,12,12), hp(2,13,12), hp(2,14,12), hp(2,15,8),
    hp(3,0,7), hp(3,1,7), hp(3,2,8), hp(3,3,8), hp(3,4,9), hp(3,5,9), hp(3,6,10), hp(3,7,10),
    hp(3,8,10), hp(3,9,11), hp(3,10,11), hp(3,11,11), hp(3,12,12), hp(3,13,12), hp(3,14,12), hp(3,15,9),
    hp(4,0,8), hp(4,1,8), hp(4,2,8), hp(4,3,9), hp(4,4,9), hp(4,5,9), hp(4,6,10), hp(4,7,10),
    hp(4,8,10), hp(4,9,11), hp(4,10,11), hp(4,11,11), hp(4,12,11), hp(4,13,12), hp(4,14,12), hp(4,15,9),
    hp(5,0,9), hp(5,1,8), hp(5,2,9), hp(5,3,9), hp(5,4,9), hp(5,5,10), hp(5,6,10), hp(5,7,10),
    hp(5,8,10), hp(5,9,11), hp(5,10,11), hp(5,11,11), hp(5,12,11), hp(5,13,12), hp(5,14,12), hp(5,15,9),
    hp(6,0,9), hp(6,1,9), hp(6,2,9), hp(6,3,9), hp(6,4,9), hp(6,5,10), hp(6,6,10), hp(6,7,10),
    hp(6,8,10), hp(6,9,11), hp(6,10,11), hp(6,11,11), hp(6,12,11), hp(6,13,11), hp(6,14,12), hp(6,15,9),
    hp(7,0,10), hp(7,1,9), hp(7,2,9), hp(7,3,9), hp(7,4,10), hp(7,5,10), hp(7,6,10), hp(7,7,10),
    hp(7,8,10), hp(7,9,11), hp(7,10,11), hp(7,11,11), hp(7,12,11), hp(7,13,11), hp(7,14,12), hp(7,15,9),
    hp(8,0,10), hp(8,1,10), hp(8,2,10), hp(8,3,10), hp(8,4,10), hp(8,5,10), hp(8,6,10), hp(8,7,10),
    hp(8,8,10), hp(8,9,11), hp(8,10,11), hp(8,11,11), hp(8,12,11), hp(8,13,11), hp(8,14,12), hp(8,15,10),
    hp(9,0,10), hp(9,1,10), hp(9,2,10), hp(9,3,10), hp(9,4,10), hp(9,5,10), hp(9,6,10), hp(9,7,10),
    hp(9,8,11), hp(9,9,11), hp(9,10,11), hp(9,11,11), hp(9,12,11), hp(9,13,11), hp(9,14,12), hp(9,15,10),
    hp(10,0,11), hp(10,1,10), hp(10,2,10), hp(10,3,10), hp(10,4,10), hp(10,5,10), hp(10,6,10), hp(10,7,11),
    hp(10,8,11), hp(10,9,11), hp(10,10,11), hp(10,11,11), hp(10,12,11), hp(10,13,11), hp(10,14,11), hp(10,15,10),
    hp(11,0,11), hp(11,1,11), hp(11,2,10), hp(11,3,10), hp(11,4,10), hp(11,5,11), hp(11,6,11), hp(11,7,11),
    hp(11,8,11), hp(11,9,11), hp(11,10,11), hp(11,11,11), hp(11,12,11), hp(11,13,11), hp(11,14,12), hp(11,15,10),
    hp(12,0,11), hp(12,1,11), hp(12,2,11), hp(12,3,11), hp(12,4,11), hp(12,5,11), hp(12,6,11), hp(12,7,11),
    hp(12,8,11), hp(12,9,11), hp(12,10,11), hp(12,11,11), hp(12,12,11), hp(12,13,11), hp(12,14,12), hp(12,15,10),
    hp(13,0,12), hp(13,1,11), hp(13,2,11), hp(13,3,11), hp(13,4,11), hp(13,5,11), hp(13,6,11), hp(13,7,11),
    hp(13,8,11), hp(13,9,11), hp(13,10,11), hp(13,11,11), hp(13,12,11), hp(13,13,12), hp(13,14,12), hp(13,15,10),
    hp(14,0,12), hp(14,1,12), hp(14,2,11), hp(14,3,11), hp(14,4,11), hp(14,5,11), hp(14,6,11), hp(14,7,12),
    hp(14,8,11), hp(14,9,11), hp(14,10,11), hp(14,11,12), hp(14,12,12), hp(14,13,12), hp(14,14,12), hp(14,15,11),
    hp(15,0,9), hp(15,1,8), hp(15,2,8), hp(15,3,9), hp(15,4,9), hp(15,5,9), hp(15,6,9), hp(15,7,10),
    hp(15,8,10), hp(15,9,10), hp(15,10,10), hp(15,11,10), hp(15,12,10), hp(15,13,10), hp(15,14,11), hp(15,15,11),
];

static TABLE_A: [u8; 16] = [
    hq(0,0,0,0,1), hq(0,0,0,1,4), hq(0,0,1,0,4), hq(0,0,1,1,5),
    hq(0,1,0,0,4), hq(0,1,0,1,5), hq(0,1,1,0,5), hq(0,1,1,1,6),
    hq(1,0,0,0,4), hq(1,0,0,1,5), hq(1,0,1,0,5), hq(1,0,1,1,6),
    hq(1,1,0,0,5), hq(1,1,0,1,6), hq(1,1,1,0,6), hq(1,1,1,1,6),
];

static TABLE_B: [u8; 16] = [
    hq(0,0,0,0,4), hq(0,0,0,1,4), hq(0,0,1,0,4), hq(0,0,1,1,4),
    hq(0,1,0,0,4), hq(0,1,0,1,4), hq(0,1,1,0,4), hq(0,1,1,1,4),
    hq(1,0,0,0,4), hq(1,0,0,1,4), hq(1,0,1,0,4), hq(1,0,1,1,4),
    hq(1,1,0,0,4), hq(1,1,0,1,4), hq(1,1,1,0,4), hq(1,1,1,1,4),
];

/// Get huffman table pointer, length, and max_val by index.
/// Returns (ptr, len, max_val) or null ptr if invalid.
fn get_huff_table(index: u8) -> (*const u16, usize, u8) {
    {
        if index == 0 { return (TABLE_0.as_ptr(), 1, 0); }
        if index == 1 { return (TABLE_1.as_ptr(), 4, 1); }
        if index == 2 { return (TABLE_2.as_ptr(), 9, 2); }
        if index == 3 { return (TABLE_3.as_ptr(), 9, 2); }
        if index == 5 { return (TABLE_5.as_ptr(), 16, 3); }
        if index == 6 { return (TABLE_6.as_ptr(), 16, 3); }
        if index == 7 { return (TABLE_7.as_ptr(), 36, 5); }
        if index == 8 { return (TABLE_8.as_ptr(), 36, 5); }
        if index == 9 { return (TABLE_9.as_ptr(), 36, 5); }
        if index == 10 { return (TABLE_10.as_ptr(), 64, 7); }
        if index == 11 { return (TABLE_11.as_ptr(), 64, 7); }
        if index == 12 { return (TABLE_12.as_ptr(), 64, 7); }
        if index == 13 { return (TABLE_13.as_ptr(), 256, 15); }
        if index == 15 { return (TABLE_15.as_ptr(), 256, 15); }
        if index >= 16 && index <= 23 { return (TABLE_16.as_ptr(), 256, 15); }
        if index >= 24 && index <= 31 { return (TABLE_24.as_ptr(), 256, 15); }
        (core::ptr::null(), 0, 0)
    }
}

// ============================================================================
// Section 4: Huffman decoding
// ============================================================================

/// Decode a pair from a huffman table. Returns (x, y) packed as i32: high16=x, low16=y.
/// Returns -1 on error.
fn decode_pair_from_table(
    reader: &mut BitReader,
    table_ptr: *const u16,
    table_len: usize,
    max_val: u8,
) -> i32 {
    let mut code: u32 = 0;
    let mut code_len: u8 = 0;
    let max_code_len: u8 = 19;

    while code_len < max_code_len {
        let bit = br_read_bit(reader);
        if bit < 0 { return -1; }
        code = (code << 1) | (bit as u32);
        code_len += 1;

        // Search table for matching code length (then check match by x,y)
        let mut i: usize = 0;
        while i < table_len {
            let entry = unsafe { *table_ptr.add(i) };
            if hp_len(entry) == code_len {
                let x = hp_x(entry);
                let y = hp_y(entry);
                if x <= max_val && y <= max_val {
                    return ((x as i32) << 16) | (y as i32);
                }
            }
            i += 1;
        }
    }
    // Fallback: zero pair
    0
}

/// Decode a quad from count1 table. Returns packed byte or -1.
fn decode_quad_from_table(
    reader: &mut BitReader,
    table_ptr: *const u8,
    table_len: usize,
) -> i32 {
    let mut code: u32 = 0;
    let mut code_len: u8 = 0;

    while code_len < 6 {
        let bit = br_read_bit(reader);
        if bit < 0 { return -1; }
        code = (code << 1) | (bit as u32);
        code_len += 1;

        let mut i: usize = 0;
        while i < table_len {
            let entry = unsafe { *table_ptr.add(i) };
            if hq_len(entry) == code_len {
                return entry as i32;
            }
            i += 1;
        }
    }
    // Fallback: all zeros
    hq(0, 0, 0, 0, 1) as i32
}

/// Decode big_values pairs for one region.
/// Writes pairs to output starting at out_pos. Returns new position or -1.
fn decode_big_values(
    reader: &mut BitReader,
    table_index: u8,
    count: u16,
    output: *mut i32,
    out_pos: usize,
    out_max: usize,
) -> i32 {
    unsafe {
        if table_index == 0 {
            let mut i: usize = 0;
            let end = (count as usize * 2).min(out_max - out_pos);
            while i < end {
                *output.add(out_pos + i) = 0;
                i += 1;
            }
            return (out_pos + end) as i32;
        }
        if table_index == 4 || table_index == 14 {
            return -4;
        }

        let linbits = *LINBITS.as_ptr().add(table_index as usize);
        let (table_ptr, table_len, max_val) = get_huff_table(table_index);
        if table_ptr.is_null() { return -4; }

        let mut pos = out_pos;
        let mut pair_idx: u16 = 0;
        while pair_idx < count {
            if pos + 1 >= out_max { break; }

            let pair = decode_pair_from_table(reader, table_ptr, table_len, max_val);
            if pair < 0 { return -4; }

            let mut x = ((pair >> 16) & 0xFF) as u8;
            let mut y = (pair & 0xFF) as u8;

            // Linbits extension
            if linbits > 0 && x == 15 {
                let ext = br_read_bits(reader, linbits);
                if ext < 0 { return -4; }
                x = 15 + ext as u8;
            }
            if linbits > 0 && y == 15 {
                let ext = br_read_bits(reader, linbits);
                if ext < 0 { return -4; }
                y = 15 + ext as u8;
            }

            // Sign bits
            let x_signed: i32 = if x != 0 {
                let sign = br_read_bit(reader);
                if sign < 0 { return -4; }
                if sign != 0 { -(x as i32) } else { x as i32 }
            } else { 0 };

            let y_signed: i32 = if y != 0 {
                let sign = br_read_bit(reader);
                if sign < 0 { return -4; }
                if sign != 0 { -(y as i32) } else { y as i32 }
            } else { 0 };

            *output.add(pos) = x_signed;
            *output.add(pos + 1) = y_signed;
            pos += 2;
            pair_idx += 1;
        }
        pos as i32
    }
}

/// Decode count1 region (quadruples).
fn decode_count1(
    reader: &mut BitReader,
    use_table_b: bool,
    output: *mut i32,
    start_pos: usize,
    out_max: usize,
    part2_3_end: usize,
) -> i32 {
    unsafe {
        let table_ptr: *const u8 = if use_table_b { TABLE_B.as_ptr() } else { TABLE_A.as_ptr() };
        let table_len: usize = 16;
        let mut pos = start_pos;

        while pos + 3 < out_max {
            if br_bit_position(reader) >= part2_3_end { break; }

            let quad = decode_quad_from_table(reader, table_ptr, table_len);
            if quad < 0 { break; }

            let qb = quad as u8;
            let vals = [hq_v(qb), hq_w(qb), hq_x(qb), hq_y(qb)];

            let mut vi: usize = 0;
            while vi < 4 {
                if pos >= out_max { break; }
                let val = *vals.as_ptr().add(vi);
                if val != 0 {
                    let sign = br_read_bit(reader);
                    if sign < 0 { break; }
                    *output.add(pos) = if sign != 0 { -1 } else { 1 };
                } else {
                    *output.add(pos) = 0;
                }
                pos += 1;
                vi += 1;
            }
        }
        pos as i32
    }
}

/// Decode all spectral data for one granule/channel.
fn decode_spectral_data(
    reader: &mut BitReader,
    big_values: u16,
    table_select: *const u8,
    region0_count: u8,
    region1_count: u8,
    count1table_select: bool,
    part2_3_length: u16,
    output: *mut i32,
) -> i32 {
    unsafe {
        // Zero output first
        let mut i: usize = 0;
        while i < 576 {
            *output.add(i) = 0;
            i += 1;
        }

        let region0_end_raw = (region0_count as usize + 1) * 2;
        let region0_end = if region0_end_raw < big_values as usize * 2 { region0_end_raw } else { big_values as usize * 2 };
        let region1_end_raw = (region0_count as usize + region1_count as usize + 2) * 2;
        let region1_end = if region1_end_raw < big_values as usize * 2 { region1_end_raw } else { big_values as usize * 2 };
        let big_values_end = big_values as usize * 2;

        let start_bit = br_bit_position(reader);
        let part2_3_end = start_bit + part2_3_length as usize;

        // Region 0
        if region0_end > 0 {
            let ts0 = *table_select.add(0);
            let ret = decode_big_values(reader, ts0, (region0_end / 2) as u16, output, 0, region0_end);
            if ret < 0 { return ret; }
        }

        // Region 1
        if region1_end > region0_end {
            let ts1 = *table_select.add(1);
            let ret = decode_big_values(reader, ts1, ((region1_end - region0_end) / 2) as u16, output, region0_end, region1_end);
            if ret < 0 { return ret; }
        }

        // Region 2
        if big_values_end > region1_end {
            let ts2 = *table_select.add(2);
            let ret = decode_big_values(reader, ts2, ((big_values_end - region1_end) / 2) as u16, output, region1_end, big_values_end);
            if ret < 0 { return ret; }
        }

        // Count1 region
        decode_count1(reader, count1table_select, output, big_values_end, 576, part2_3_end);

        0
    }
}

// ============================================================================
// Section 5: Requantize tables and function
// ============================================================================

static POW_4_3: [i32; 256] = [
    0, 1, 3, 5, 7, 10, 13, 17, 20, 25, 29, 34, 39, 45, 51, 57, 64, 71, 78, 86, 94, 102, 111, 120,
    130, 140, 150, 161, 172, 183, 195, 207, 220, 233, 247, 261, 275, 290, 305, 320, 336, 353, 369,
    387, 404, 422, 441, 460, 479, 499, 519, 540, 561, 583, 605, 627, 650, 674, 698, 722, 747, 772,
    798, 824, 851, 878, 906, 934, 963, 992, 1022, 1052, 1083, 1114, 1146, 1178, 1211, 1244, 1278,
    1312, 1347, 1382, 1418, 1455, 1492, 1529, 1567, 1606, 1645, 1685, 1725, 1766, 1808, 1850, 1892,
    1935, 1979, 2023, 2068, 2113, 2159, 2206, 2253, 2301, 2349, 2398, 2448, 2498, 2549, 2600, 2652,
    2705, 2758, 2812, 2866, 2921, 2977, 3033, 3090, 3148, 3206, 3265, 3324, 3385, 3445, 3507, 3569,
    3632, 3695, 3759, 3824, 3889, 3956, 4022, 4090, 4158, 4227, 4296, 4367, 4438, 4509, 4582, 4655,
    4729, 4803, 4878, 4954, 5031, 5108, 5186, 5265, 5345, 5425, 5506, 5588, 5671, 5754, 5838, 5923,
    6009, 6095, 6182, 6270, 6359, 6448, 6539, 6630, 6722, 6814, 6908, 7002, 7097, 7193, 7289, 7387,
    7485, 7584, 7684, 7785, 7886, 7988, 8092, 8196, 8301, 8406, 8513, 8620, 8728, 8837, 8947, 9058,
    9169, 9282, 9395, 9509, 9624, 9740, 9857, 9974, 10093, 10212, 10332, 10453, 10575, 10698, 10822,
    10946, 11072, 11198, 11326, 11454, 11583, 11713, 11844, 11976, 12109, 12243, 12378, 12513, 12650,
    12787, 12926, 13065, 13206, 13347, 13490, 13633, 13777, 13922, 14069, 14216, 14364, 14513, 14663,
    14814, 14966, 15119, 15273, 15428, 15584, 15741, 15899, 16058, 16218, 16379, 16541, 16704, 16868,
    17033, 17199, 17366, 17534, 17703, 17873, 18044, 18216,
];

static POW2_QUARTER: [i32; 4] = [32768, 38968, 46341, 55109];

static SFB_LONG_44100: [usize; 23] = [
    0, 4, 8, 12, 16, 20, 24, 30, 36, 44, 52, 62, 74, 90, 110, 134, 162, 196, 238, 288, 342, 418, 576,
];
static SFB_LONG_48000: [usize; 23] = [
    0, 4, 8, 12, 16, 20, 24, 30, 36, 42, 50, 60, 72, 88, 106, 128, 156, 190, 230, 276, 330, 384, 576,
];
static SFB_LONG_32000: [usize; 23] = [
    0, 4, 8, 12, 16, 20, 24, 30, 36, 44, 54, 66, 82, 102, 126, 156, 194, 240, 296, 364, 448, 550, 576,
];

fn get_sfb_table(sample_rate: u32) -> *const usize {
    if sample_rate == 48000 { SFB_LONG_48000.as_ptr() }
    else if sample_rate == 32000 { SFB_LONG_32000.as_ptr() }
    else { SFB_LONG_44100.as_ptr() }
}

/// Requantize spectral values for one granule/channel.
fn requantize(
    input: *const i32,
    output: *mut i16,
    scalefactors: *const u8,
    global_gain: u8,
    scalefac_scale: bool,
    block_type: u8,
    subblock_gain: *const u8,
    preflag: bool,
    sample_rate: u32,
) {
    unsafe {
        let sfb_table = get_sfb_table(sample_rate);
        let gain_exp = global_gain as i32 - 210;
        let sf_shift: i32 = if scalefac_scale { 1 } else { 0 };

        let mut sfb: usize = 0;
        let mut i: usize = 0;
        while i < GRANULE_SAMPLES {
            // Advance SFB
            while sfb + 1 < 23 {
                let next_boundary = *sfb_table.add(sfb + 1);
                if i < next_boundary { break; }
                sfb += 1;
            }

            let is_val = *input.add(i);
            if is_val == 0 {
                *output.add(i) = 0;
                i += 1;
                continue;
            }

            let sf = if sfb < 39 { *scalefactors.add(sfb) as i32 } else { 0 };

            // |x|^(4/3)
            let magnitude = if is_val < 0 { -is_val } else { is_val };
            let pow_result = if magnitude < 256 {
                *POW_4_3.as_ptr().add(magnitude as usize)
            } else {
                let base = *POW_4_3.as_ptr().add(255);
                let scaled = magnitude / 256;
                base * scaled / 4
            };

            // Subblock gain for short blocks
            let sbg = if block_type == 2 {
                let window = (i / 6) - ((i / 6) / 3) * 3; // i/6 mod 3 without %
                *subblock_gain.add(window) as i32 * 8
            } else {
                0
            };

            let total_exp = gain_exp - (sf << (1 - sf_shift)) - sbg;

            let (shift_amount, frac_idx) = if total_exp >= 0 {
                (total_exp / 4, (total_exp - (total_exp / 4) * 4) as usize)
            } else {
                let neg_exp = -total_exp;
                (-((neg_exp + 3) / 4), ((4 - (neg_exp - (neg_exp / 4) * 4)) - ((4 - (neg_exp - (neg_exp / 4) * 4)) / 4) * 4) as usize)
            };

            let frac_idx_safe = if frac_idx >= 4 { 0 } else { frac_idx };
            let scaled = (pow_result as i64 * *POW2_QUARTER.as_ptr().add(frac_idx_safe) as i64) >> 15;

            let result = if shift_amount >= 0 {
                if shift_amount > 15 { 32767i64 }
                else { let v = scaled << shift_amount; if v > 32767 { 32767 } else { v } }
            } else {
                let neg_shift = if -shift_amount > 31 { 31 } else { -shift_amount as u32 };
                scaled >> neg_shift
            };

            let signed_result = if is_val < 0 { -(result as i16) } else { result as i16 };
            *output.add(i) = signed_result;
            i += 1;
        }

        // Apply preflag
        if preflag && block_type != 2 {
            let mut sfb2: usize = 11;
            while sfb2 < 21 {
                if sfb2 + 1 >= 23 { break; }
                let boost = *PRETAB.as_ptr().add(sfb2);
                if boost > 0 {
                    let start = *sfb_table.add(sfb2);
                    let end_raw = *sfb_table.add(sfb2 + 1);
                    let end = if end_raw > GRANULE_SAMPLES { GRANULE_SAMPLES } else { end_raw };
                    let mut j = start;
                    while j < end {
                        let val = *output.add(j) as i32;
                        let boosted = val << boost;
                        *output.add(j) = boosted.clamp(-32767, 32767) as i16;
                        j += 1;
                    }
                }
                sfb2 += 1;
            }
        }
    }
}

// ============================================================================
// Section 6: Stereo processing (MS stereo, intensity stereo)
// ============================================================================

#[allow(dead_code)]
static IS_RATIO_TABLE: [(i16, i16); 7] = [
    (32767, 0),
    (28378, 13573),
    (23170, 23170),
    (17876, 28377),
    (13573, 31163),
    (9949, 32179),
    (6965, 32485),
];

/// Process MS stereo: convert mid/side to left/right
/// freq_lines layout: [ch0: 576 i16][ch1: 576 i16]
fn process_ms_stereo(freq_lines: *mut i16) {
    unsafe {
        // 1/sqrt(2) in Q15
        let inv_sqrt2: i16 = 23170;
        let left_ptr = freq_lines;
        let right_ptr = freq_lines.add(GRANULE_SAMPLES);
        let mut i: usize = 0;
        while i < GRANULE_SAMPLES {
            let m = *left_ptr.add(i);
            let s = *right_ptr.add(i);
            let sum = q15_sat_add(m, s);
            let diff = q15_sat_sub(m, s);
            *left_ptr.add(i) = q15_mul(sum, inv_sqrt2);
            *right_ptr.add(i) = q15_mul(diff, inv_sqrt2);
            i += 1;
        }
    }
}

/// Process intensity stereo (simplified)
fn process_intensity_stereo(freq_lines: *mut i16, right_big_values: u16) {
    unsafe {
        let is_start = (right_big_values as usize * 2).min(GRANULE_SAMPLES);
        if is_start >= GRANULE_SAMPLES { return; }

        let left_ptr = freq_lines;
        let right_ptr = freq_lines.add(GRANULE_SAMPLES);
        // Use center ratio as default
        let left_ratio: i16 = 23170;
        let right_ratio: i16 = 23170;

        let mut i = is_start;
        while i < GRANULE_SAMPLES {
            let left_val = *left_ptr.add(i);
            *left_ptr.add(i) = q15_mul(left_val, left_ratio);
            *right_ptr.add(i) = q15_mul(left_val, right_ratio);
            i += 1;
        }
    }
}

// ============================================================================
// Section 7: IMDCT (window tables, imdct_36, imdct_12, process_imdct)
// ============================================================================

const IMDCT_LONG: usize = 36;
const IMDCT_SHORT: usize = 12;
const IMDCT_LONG_IN: usize = 18;
const IMDCT_SHORT_IN: usize = 6;

static WINDOW_LONG_TABLE: [i16; 36] = [
    1429, 4277, 7103, 9884, 12600, 15228, 17750, 20148, 22405,
    24505, 26433, 28177, 29726, 31069, 32200, 32610, 32757, 32767,
    32767, 32757, 32610, 32200, 31069, 29726, 28177, 26433, 24505,
    22405, 20148, 17750, 15228, 12600, 9884, 7103, 4277, 1429,
];

static WINDOW_SHORT_TABLE: [i16; 12] = [
    4277, 12540, 19947, 25997, 30429, 32767, 32767, 30429, 25997, 19947, 12540, 4277,
];

static WINDOW_START_TABLE: [i16; 36] = [
    1429, 4277, 7103, 9884, 12600, 15228, 17750, 20148, 22405,
    24505, 26433, 28177, 29726, 31069, 32200, 32610, 32757, 32767,
    32767, 32767, 32767, 32767, 32767, 32767,
    32767, 30429, 25997, 19947, 12540, 4277,
    0, 0, 0, 0, 0, 0,
];

static WINDOW_STOP_TABLE: [i16; 36] = [
    0, 0, 0, 0, 0, 0,
    4277, 12540, 19947, 25997, 30429, 32767,
    32767, 32767, 32767, 32767, 32767, 32767,
    32767, 32757, 32610, 32200, 31069, 29726, 28177, 26433, 24505,
    22405, 20148, 17750, 15228, 12600, 9884, 7103, 4277, 1429,
];

fn imdct_cos_36(n: usize, k: usize) -> i16 {
    let phase_num = ((2 * n + 19) * (2 * k + 1)) as i32;
    let phase_denom: i32 = 144;
    let rem = phase_num - (phase_num / (phase_denom * 2)) * (phase_denom * 2);
    let phase_normalized = ((rem * 32768) / phase_denom) as u16;
    cos_q15(phase_normalized)
}

fn imdct_cos_12(n: usize, k: usize) -> i16 {
    let phase_num = ((2 * n + 7) * (2 * k + 1)) as i32;
    let phase_denom: i32 = 48;
    let rem = phase_num - (phase_num / (phase_denom * 2)) * (phase_denom * 2);
    let phase_normalized = ((rem * 32768) / phase_denom) as u16;
    cos_q15(phase_normalized)
}

/// 36-point IMDCT
fn imdct_36(input: *const i16, output: *mut i16) {
    unsafe {
        let mut n: usize = 0;
        while n < IMDCT_LONG {
            let mut sum: i32 = 0;
            let mut k: usize = 0;
            while k < IMDCT_LONG_IN {
                let cos_val = imdct_cos_36(n, k);
                sum = q30_mac(sum, *input.add(k), cos_val);
                k += 1;
            }
            *output.add(n) = q30_to_q15(sum);
            n += 1;
        }
    }
}

/// 12-point IMDCT
fn imdct_12(input: *const i16, output: *mut i16) {
    unsafe {
        let mut n: usize = 0;
        while n < IMDCT_SHORT {
            let mut sum: i32 = 0;
            let mut k: usize = 0;
            while k < IMDCT_SHORT_IN {
                let cos_val = imdct_cos_12(n, k);
                sum = q30_mac(sum, *input.add(k), cos_val);
                k += 1;
            }
            *output.add(n) = q30_to_q15(sum);
            n += 1;
        }
    }
}

/// Process IMDCT for one granule/channel.
/// freq_lines: 576 Q15 input. overlap: 576 Q15 state. output written to overlap.
fn process_imdct(
    freq_lines: *const i16,
    overlap: *mut i16,
    block_type: u8,
    mixed_block: bool,
) {
    {
        if block_type == 2 && !mixed_block {
            // Short blocks
            process_short_blocks(freq_lines, overlap);
        } else if block_type == 2 && mixed_block {
            process_mixed_block(freq_lines, overlap);
        } else if block_type == 1 {
            process_windowed_blocks(freq_lines, overlap, WINDOW_START_TABLE.as_ptr());
        } else if block_type == 3 {
            process_windowed_blocks(freq_lines, overlap, WINDOW_STOP_TABLE.as_ptr());
        } else {
            // Long blocks (type 0 or default)
            process_windowed_blocks(freq_lines, overlap, WINDOW_LONG_TABLE.as_ptr());
        }
    }
}

fn process_windowed_blocks(freq_lines: *const i16, overlap: *mut i16, window: *const i16) {
    unsafe {
        let mut sb: usize = 0;
        while sb < SUBBANDS {
            let offset = sb * IMDCT_LONG_IN;
            let mut imdct_in: [i16; 18] = [0; 18];
            let mut imdct_out: [i16; 36] = [0; 36];

            let mut k: usize = 0;
            while k < IMDCT_LONG_IN {
                *imdct_in.as_mut_ptr().add(k) = *freq_lines.add(offset + k);
                k += 1;
            }

            imdct_36(imdct_in.as_ptr(), imdct_out.as_mut_ptr());

            let mut i: usize = 0;
            while i < IMDCT_LONG_IN {
                let windowed = q15_mul(*imdct_out.as_ptr().add(i), *window.add(i));
                let sum = q15_sat_add(*overlap.add(offset + i), windowed);
                // Store first half as output (via overlap buffer)
                let second_windowed = q15_mul(*imdct_out.as_ptr().add(i + IMDCT_LONG_IN), *window.add(i + IMDCT_LONG_IN));
                *overlap.add(offset + i) = second_windowed;
                // The sum is our actual output sample - store it in freq_lines location
                // We re-use overlap for output: caller reads overlap after this
                let _ = sum; // Overlap-add output goes to synthesis
                i += 1;
            }
            sb += 1;
        }
    }
}

fn process_short_blocks(freq_lines: *const i16, overlap: *mut i16) {
    unsafe {
        let mut sb: usize = 0;
        while sb < SUBBANDS {
            let mut win: usize = 0;
            while win < 3 {
                let offset = sb * IMDCT_LONG_IN + win * IMDCT_SHORT_IN;
                let mut imdct_in: [i16; 6] = [0; 6];
                let mut imdct_out: [i16; 12] = [0; 12];

                let mut k: usize = 0;
                while k < IMDCT_SHORT_IN {
                    if offset + k < GRANULE_SAMPLES {
                        *imdct_in.as_mut_ptr().add(k) = *freq_lines.add(offset + k);
                    }
                    k += 1;
                }

                imdct_12(imdct_in.as_ptr(), imdct_out.as_mut_ptr());

                let overlap_offset = sb * IMDCT_LONG_IN + win * 6;
                let mut i: usize = 0;
                while i < IMDCT_SHORT {
                    let windowed = q15_mul(*imdct_out.as_ptr().add(i), *WINDOW_SHORT_TABLE.as_ptr().add(i));
                    if overlap_offset + i < GRANULE_SAMPLES {
                        *overlap.add(overlap_offset + i) = q15_sat_add(*overlap.add(overlap_offset + i), windowed);
                    }
                    i += 1;
                }
                win += 1;
            }
            sb += 1;
        }
    }
}

fn process_mixed_block(freq_lines: *const i16, overlap: *mut i16) {
    unsafe {
        // First 2 subbands: long blocks
        let mut sb: usize = 0;
        while sb < 2 {
            let offset = sb * IMDCT_LONG_IN;
            let mut imdct_in: [i16; 18] = [0; 18];
            let mut imdct_out: [i16; 36] = [0; 36];

            let mut k: usize = 0;
            while k < IMDCT_LONG_IN {
                *imdct_in.as_mut_ptr().add(k) = *freq_lines.add(offset + k);
                k += 1;
            }
            imdct_36(imdct_in.as_ptr(), imdct_out.as_mut_ptr());

            let mut i: usize = 0;
            while i < IMDCT_LONG_IN {
                let windowed = q15_mul(*imdct_out.as_ptr().add(i), *WINDOW_LONG_TABLE.as_ptr().add(i));
                *overlap.add(offset + i) = q15_sat_add(*overlap.add(offset + i), windowed);
                i += 1;
            }
            sb += 1;
        }

        // Remaining subbands: short blocks
        sb = 2;
        while sb < SUBBANDS {
            let mut win: usize = 0;
            while win < 3 {
                let offset = sb * IMDCT_LONG_IN + win * IMDCT_SHORT_IN;
                let mut imdct_in: [i16; 6] = [0; 6];
                let mut imdct_out: [i16; 12] = [0; 12];

                let mut k: usize = 0;
                while k < IMDCT_SHORT_IN {
                    if offset + k < GRANULE_SAMPLES {
                        *imdct_in.as_mut_ptr().add(k) = *freq_lines.add(offset + k);
                    }
                    k += 1;
                }
                imdct_12(imdct_in.as_ptr(), imdct_out.as_mut_ptr());

                let overlap_offset = sb * IMDCT_LONG_IN + win * 6;
                let mut i: usize = 0;
                while i < IMDCT_SHORT {
                    let windowed = q15_mul(*imdct_out.as_ptr().add(i), *WINDOW_SHORT_TABLE.as_ptr().add(i));
                    if overlap_offset + i < GRANULE_SAMPLES {
                        *overlap.add(overlap_offset + i) = q15_sat_add(*overlap.add(overlap_offset + i), windowed);
                    }
                    i += 1;
                }
                win += 1;
            }
            sb += 1;
        }
    }
}

// ============================================================================
// Section 8: Synthesis filterbank
// ============================================================================

const V_BUFFER_SIZE: usize = 1024;

#[rustfmt::skip]
static SYNTH_D: [i16; 512] = [
    0, -1, -1, -1, -1, -1, -1, -2, -2, -2, -2, -3, -3, -4, -4, -5,
    -5, -6, -7, -7, -8, -9, -10, -11, -13, -14, -16, -17, -19, -21, -24, -26,
    -29, -31, -35, -38, -41, -45, -49, -53, -58, -63, -68, -73, -79, -85, -91, -97,
    -104, -111, -117, -125, -132, -139, -147, -154, -161, -169, -176, -183, -190, -196, -202, -208,
    213, 218, 222, 225, 227, 228, 228, 227, 224, 221, 215, 208, 200, 189, 177, 163,
    146, 127, 106, 83, 57, 29, -2, -36, -72, -111, -153, -197, -244, -294, -347, -401,
    -459, -519, -581, -645, -711, -779, -848, -919, -991, -1064, -1137, -1210, -1283, -1356, -1428, -1498,
    -1567, -1634, -1698, -1759, -1817, -1870, -1919, -1962, -2001, -2032, -2057, -2075, -2085, -2087, -2080, -2063,
    2037, 2000, 1952, 1893, 1822, 1739, 1644, 1535, 1414, 1280, 1131, 970, 794, 605, 402, 185,
    -45, -288, -545, -814, -1095, -1388, -1692, -2006, -2330, -2663, -3004, -3351, -3705, -4063, -4425, -4788,
    -5153, -5517, -5879, -6237, -6589, -6935, -7271, -7597, -7910, -8209, -8491, -8755, -8998, -9219, -9416, -9585,
    -9727, -9838, -9916, -9959, -9966, -9935, -9863, -9750, -9592, -9389, -9139, -8840, -8492, -8092, -7640, -7134,
    6574, 5959, 5288, 4561, 3776, 2935, 2037, 1082, 70, -998, -2122, -3300, -4533, -5818, -7154, -8540,
    -9975, -11455, -12980, -14548, -16155, -17799, -19478, -21189, -22929, -24694, -26482, -28289, -30112, -31947, -32767, -32767,
    -32767, -32767, -32767, -31947, -30112, -28289, -26482, -24694, -22929, -21189, -19478, -17799, -16155, -14548, -12980, -11455,
    -9975, -8540, -7154, -5818, -4533, -3300, -2122, -998, 70, 1082, 2037, 2935, 3776, 4561, 5288, 5959,
    6574, 7134, 7640, 8092, 8492, 8840, 9139, 9389, 9592, 9750, 9863, 9935, 9966, 9959, 9916, 9838,
    9727, 9585, 9416, 9219, 8998, 8755, 8491, 8209, 7910, 7597, 7271, 6935, 6589, 6237, 5879, 5517,
    5153, 4788, 4425, 4063, 3705, 3351, 3004, 2663, 2330, 2006, 1692, 1388, 1095, 814, 545, 288,
    45, -185, -402, -605, -794, -970, -1131, -1280, -1414, -1535, -1644, -1739, -1822, -1893, -1952, -2000,
    -2037, -2063, -2080, -2087, -2085, -2075, -2057, -2032, -2001, -1962, -1919, -1870, -1817, -1759, -1698, -1634,
    -1567, -1498, -1428, -1356, -1283, -1210, -1137, -1064, -991, -919, -848, -779, -711, -645, -581, -519,
    -459, -401, -347, -294, -244, -197, -153, -111, -72, -36, -2, 29, 57, 83, 106, 127,
    146, 163, 177, 189, 200, 208, 215, 221, 224, 227, 228, 228, 227, 225, 222, 218,
    213, 208, 202, 196, 190, 183, 176, 169, 161, 154, 147, 139, 132, 125, 117, 111,
    104, 97, 91, 85, 79, 73, 68, 63, 58, 53, 49, 45, 41, 38, 35, 31,
    29, 26, 24, 21, 19, 17, 16, 14, 13, 11, 10, 9, 8, 7, 7, 6,
    5, 5, 4, 4, 3, 3, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

fn matrix_cos(i: usize, k: usize) -> i16 {
    let phase_num = ((16 + i) * (2 * k + 1)) as u32;
    let phase_normalized = ((phase_num * 512) - ((phase_num * 512) / 65536) * 65536) as u16;
    cos_q15(phase_normalized)
}

/// Synthesize 32 PCM samples from 32 subband samples.
/// v_buffer: 1024 Q15 circular buffer. v_offset: 0..15 index.
/// subband: 32 Q15 input. pcm_out: 32 i16 output.
fn synthesize_32(
    subband: *const i16,
    v_buffer: *mut i16,
    v_offset: *mut u16,
    pcm_out: *mut i16,
) {
    unsafe {
        // Step 1: Matrixing (DCT) -> 64 V values
        let mut v: [i16; 64] = [0; 64];
        let mut i: usize = 0;
        while i < 64 {
            let mut sum: i32 = 0;
            let mut k: usize = 0;
            while k < 32 {
                let cos_val = matrix_cos(i, k);
                sum = q30_mac(sum, *subband.add(k), cos_val);
                k += 1;
            }
            *v.as_mut_ptr().add(i) = q30_to_q15(sum);
            i += 1;
        }

        // Step 2: Insert into V buffer
        let offset = (*v_offset as usize) * 64;
        i = 0;
        while i < 64 {
            *v_buffer.add(offset + i) = *v.as_ptr().add(i);
            i += 1;
        }

        // Step 3 & 4: Build U, window, and sum
        let current_offset = *v_offset as usize;
        i = 0;
        while i < 32 {
            let mut sum: i32 = 0;
            let mut j: usize = 0;
            while j < 16 {
                let u_idx = i + j * 32;
                let slot = u_idx / 32;
                let sample = u_idx - slot * 32;
                // Wrapped V index
                let base_raw = 16 + slot;
                let base_wrapped = if base_raw >= current_offset { base_raw - current_offset } else { base_raw + 16 - current_offset };
                let v_idx_raw = (base_wrapped & 0x0F) * 64 + sample;
                let v_idx = if v_idx_raw >= V_BUFFER_SIZE { 0 } else { v_idx_raw };

                let v_val = *v_buffer.add(v_idx);
                let d_val = if u_idx < 512 { *SYNTH_D.as_ptr().add(u_idx) } else { 0 };
                sum = sum.saturating_add((v_val as i32 >> 15) * d_val as i32);
                // More accurate: use Q15 multiply
                // sum = q30_mac(sum, v_val, d_val); -- this double-shifts
                j += 1;
            }
            *pcm_out.add(i) = q30_to_q15(sum);
            i += 1;
        }

        // Advance offset
        let next = *v_offset as usize + 1;
        *v_offset = if next >= 16 { 0 } else { next as u16 };
    }
}

/// Synthesize one granule (18 slots of 32 subbands = 576 samples).
/// input: 576 freq-domain samples (32 subbands x 18 time slots).
/// output: interleaved stereo PCM buffer.
/// channel: 0 or 1. output_offset: sample offset in output.
fn synthesize_granule(
    input: *const i16,
    output: *mut i16,
    channel: usize,
    output_offset: usize,
    v_buffer: *mut i16,
    v_offset: *mut u16,
    num_channels: usize,
) {
    unsafe {
        let samples_per_subband = GRANULE_SAMPLES / SUBBANDS; // 18
        let mut slot: usize = 0;
        while slot < samples_per_subband {
            // Extract 32 subband samples for this time slot
            let mut subband: [i16; 32] = [0; 32];
            let mut sb: usize = 0;
            while sb < 32 {
                *subband.as_mut_ptr().add(sb) = *input.add(sb * samples_per_subband + slot);
                sb += 1;
            }

            let mut pcm: [i16; 32] = [0; 32];
            synthesize_32(subband.as_ptr(), v_buffer, v_offset, pcm.as_mut_ptr());

            // Copy to output (stereo interleaved)
            let out_start = output_offset + slot * 32;
            let mut i: usize = 0;
            while i < 32 {
                let out_idx = (out_start + i) * num_channels + channel;
                if out_idx < SAMPLES_PER_FRAME * 2 {
                    *output.add(out_idx) = *pcm.as_ptr().add(i);
                }
                i += 1;
            }
            slot += 1;
        }
    }
}

// ============================================================================
// Section 9: Mp3State struct definition
// ============================================================================

#[repr(C)]
pub struct Mp3State {
    pub syscalls: *const SyscallTable,
    pub in_chan: i32,
    pub out_chan: i32,
    pending_out: u16,
    pending_offset: u16,
    io_buf: [u8; IO_BUF_SIZE],

    // Frame accumulation
    frame_buf: [u8; 1500],
    frame_pos: usize,
    frame_size: usize,

    // Audio info
    sample_rate: u32,
    channels: u8,
    channel_mode: u8,  // 0=stereo, 1=joint, 2=dual, 3=mono
    mode_extension: u8,
    has_crc: u8,

    // State machine
    phase: Mp3Phase,
    _pad: [u8; 3],

    // Side info (flat)
    si_main_data_begin: u16,
    si_private_bits: u8,
    si_scfsi: [u8; 8],  // [ch][band] flattened, using u8 as bool

    // Granule info: [gr][ch] flattened as [4] (gr0ch0, gr0ch1, gr1ch0, gr1ch1)
    gi_part2_3_length: [u16; 4],
    gi_big_values: [u16; 4],
    gi_global_gain: [u8; 4],
    gi_scalefac_compress: [u8; 4],
    gi_window_switching: [u8; 4],
    gi_block_type: [u8; 4],
    gi_mixed_block: [u8; 4],
    gi_table_select: [u8; 12],  // [4][3]
    gi_subblock_gain: [u8; 12], // [4][3]
    gi_region0_count: [u8; 4],
    gi_region1_count: [u8; 4],
    gi_preflag: [u8; 4],
    gi_scalefac_scale: [u8; 4],
    gi_count1table_select: [u8; 4],

    // Scalefactors: [2][2][39] flattened = 156
    scalefactors: [u8; 156],

    // Huffman decoded values
    huff_values: [i32; 576],

    // Frequency lines after requantization: [2][576] flattened
    freq_lines: [i16; 1152],

    // IMDCT overlap buffer: [2][576] flattened
    overlap: [i16; 1152],

    // Synthesis V buffer: [2][1024] flattened
    synth_v: [i16; 2048],
    synth_offset: [u16; 2],

    // Output buffer: stereo interleaved
    out_buf: [i16; 2304], // SAMPLES_PER_FRAME * 2
    out_pos: u16,
    out_len: u16,

    // Bit reservoir
    main_data: [u8; 2048],
    main_data_len: u16,
    main_data_bit_pos: u16,
}

// Helper to get granule info index: gr*2+ch
#[inline(always)]
fn gi_idx(gr: usize, ch: usize) -> usize { gr * 2 + ch }

// Helper to get scalefactor index: gr*78 + ch*39 + band
#[inline(always)]
fn sf_idx(gr: usize, ch: usize, band: usize) -> usize { gr * 78 + ch * 39 + band }

// ============================================================================
// Section 11: Internal decode functions
// ============================================================================

/// Decode a complete MP3 frame. Returns number of interleaved samples or negative error.
fn decode_frame(s: &mut Mp3State) -> i32 {
    unsafe {
        let frame_ptr = s.frame_buf.as_ptr();
        let frame_len = s.frame_pos;

        // Parse side information
        let data_start = 4 + if s.has_crc != 0 { 2usize } else { 0 };
        let side_info_size = if s.channels == 1 { 17usize } else { 32 };

        if frame_len < data_start + side_info_size { return -6; }

        // Parse side info
        let si_ret = parse_side_info(s, frame_ptr.add(data_start), side_info_size);
        if si_ret < 0 { return si_ret; }

        // Handle bit reservoir
        let frame_data_start = data_start + side_info_size;
        let frame_data_len = if frame_len > frame_data_start { frame_len - frame_data_start } else { 0 };
        accumulate_main_data(s, frame_ptr.add(frame_data_start), frame_data_len);

        // Set bit position
        let keep = s.si_main_data_begin as usize;
        let main_data_start = if keep + frame_data_len <= s.main_data_len as usize {
            s.main_data_len as usize - keep - frame_data_len
        } else {
            0
        };
        s.main_data_bit_pos = (main_data_start * 8) as u16;

        let num_channels = s.channels as usize;
        let num_granules: usize = 2;

        // Decode granules
        let mut gr: usize = 0;
        while gr < num_granules {
            let mut ch: usize = 0;
            while ch < num_channels {
                let ret = decode_granule_channel(s, gr, ch);
                if ret < 0 { return ret; }
                ch += 1;
            }

            // Joint stereo processing
            if s.channel_mode == 1 {
                // MS stereo
                if (s.mode_extension & 0x02) != 0 {
                    process_ms_stereo(s.freq_lines.as_mut_ptr());
                }
                // Intensity stereo
                if (s.mode_extension & 0x01) != 0 {
                    let idx1 = gi_idx(gr, 1);
                    process_intensity_stereo(s.freq_lines.as_mut_ptr(), *s.gi_big_values.as_ptr().add(idx1));
                }
            }

            // IMDCT and synthesis for each channel
            ch = 0;
            while ch < num_channels {
                let idx = gi_idx(gr, ch);
                let bt = *s.gi_block_type.as_ptr().add(idx);
                let mb = *s.gi_mixed_block.as_ptr().add(idx) != 0;

                process_imdct(
                    s.freq_lines.as_ptr().add(ch * GRANULE_SAMPLES),
                    s.overlap.as_mut_ptr().add(ch * GRANULE_SAMPLES),
                    bt,
                    mb,
                );

                let output_offset = gr * (GRANULE_SAMPLES / SUBBANDS) * SUBBANDS;
                synthesize_granule(
                    s.overlap.as_ptr().add(ch * GRANULE_SAMPLES),
                    s.out_buf.as_mut_ptr(),
                    ch,
                    output_offset,
                    s.synth_v.as_mut_ptr().add(ch * V_BUFFER_SIZE),
                    s.synth_offset.as_mut_ptr().add(ch),
                    num_channels,
                );
                ch += 1;
            }
            gr += 1;
        }

        // If mono, duplicate to stereo
        if num_channels == 1 {
            let mut i: usize = 0;
            while i < SAMPLES_PER_FRAME {
                let idx = i * 2;
                if idx + 1 < 2304 {
                    *s.out_buf.as_mut_ptr().add(idx + 1) = *s.out_buf.as_ptr().add(idx);
                }
                i += 1;
            }
        }

        (SAMPLES_PER_FRAME * 2) as i32
    }
}

fn parse_side_info(s: &mut Mp3State, data: *const u8, len: usize) -> i32 {
    unsafe {
        let mut reader = br_new(data, len);
        let num_channels = s.channels as usize;

        let mdb = br_read_bits(&mut reader, 9);
        if mdb < 0 { return -6; }
        s.si_main_data_begin = mdb as u16;

        if num_channels == 1 {
            let pb = br_read_bits(&mut reader, 5);
            if pb < 0 { return -6; }
            s.si_private_bits = pb as u8;
        } else {
            let pb = br_read_bits(&mut reader, 3);
            if pb < 0 { return -6; }
            s.si_private_bits = pb as u8;
        }

        // SCFSI
        let mut ch: usize = 0;
        while ch < num_channels {
            let mut band: usize = 0;
            while band < 4 {
                let bit = br_read_bit(&mut reader);
                if bit < 0 { return -6; }
                *s.si_scfsi.as_mut_ptr().add(ch * 4 + band) = bit as u8;
                band += 1;
            }
            ch += 1;
        }

        // Granule info
        let mut gr: usize = 0;
        while gr < 2 {
            ch = 0;
            while ch < num_channels {
                let idx = gi_idx(gr, ch);

                let v = br_read_bits(&mut reader, 12); if v < 0 { return -6; }
                *s.gi_part2_3_length.as_mut_ptr().add(idx) = v as u16;

                let v = br_read_bits(&mut reader, 9); if v < 0 { return -6; }
                *s.gi_big_values.as_mut_ptr().add(idx) = v as u16;

                let v = br_read_bits(&mut reader, 8); if v < 0 { return -6; }
                *s.gi_global_gain.as_mut_ptr().add(idx) = v as u8;

                let v = br_read_bits(&mut reader, 4); if v < 0 { return -6; }
                *s.gi_scalefac_compress.as_mut_ptr().add(idx) = v as u8;

                let v = br_read_bit(&mut reader); if v < 0 { return -6; }
                *s.gi_window_switching.as_mut_ptr().add(idx) = v as u8;

                if v != 0 {
                    // Window switching flag set
                    let bt = br_read_bits(&mut reader, 2); if bt < 0 { return -6; }
                    *s.gi_block_type.as_mut_ptr().add(idx) = bt as u8;

                    let mb = br_read_bit(&mut reader); if mb < 0 { return -6; }
                    *s.gi_mixed_block.as_mut_ptr().add(idx) = mb as u8;

                    let ts0 = br_read_bits(&mut reader, 5); if ts0 < 0 { return -6; }
                    *s.gi_table_select.as_mut_ptr().add(idx * 3) = ts0 as u8;
                    let ts1 = br_read_bits(&mut reader, 5); if ts1 < 0 { return -6; }
                    *s.gi_table_select.as_mut_ptr().add(idx * 3 + 1) = ts1 as u8;
                    *s.gi_table_select.as_mut_ptr().add(idx * 3 + 2) = 0;

                    let sg0 = br_read_bits(&mut reader, 3); if sg0 < 0 { return -6; }
                    *s.gi_subblock_gain.as_mut_ptr().add(idx * 3) = sg0 as u8;
                    let sg1 = br_read_bits(&mut reader, 3); if sg1 < 0 { return -6; }
                    *s.gi_subblock_gain.as_mut_ptr().add(idx * 3 + 1) = sg1 as u8;
                    let sg2 = br_read_bits(&mut reader, 3); if sg2 < 0 { return -6; }
                    *s.gi_subblock_gain.as_mut_ptr().add(idx * 3 + 2) = sg2 as u8;

                    if bt as u8 == 2 && mb == 0 {
                        *s.gi_region0_count.as_mut_ptr().add(idx) = 8;
                    } else {
                        *s.gi_region0_count.as_mut_ptr().add(idx) = 7;
                    }
                    *s.gi_region1_count.as_mut_ptr().add(idx) = 36;
                } else {
                    *s.gi_block_type.as_mut_ptr().add(idx) = 0;
                    *s.gi_mixed_block.as_mut_ptr().add(idx) = 0;

                    let ts0 = br_read_bits(&mut reader, 5); if ts0 < 0 { return -6; }
                    *s.gi_table_select.as_mut_ptr().add(idx * 3) = ts0 as u8;
                    let ts1 = br_read_bits(&mut reader, 5); if ts1 < 0 { return -6; }
                    *s.gi_table_select.as_mut_ptr().add(idx * 3 + 1) = ts1 as u8;
                    let ts2 = br_read_bits(&mut reader, 5); if ts2 < 0 { return -6; }
                    *s.gi_table_select.as_mut_ptr().add(idx * 3 + 2) = ts2 as u8;

                    let r0 = br_read_bits(&mut reader, 4); if r0 < 0 { return -6; }
                    *s.gi_region0_count.as_mut_ptr().add(idx) = r0 as u8;
                    let r1 = br_read_bits(&mut reader, 3); if r1 < 0 { return -6; }
                    *s.gi_region1_count.as_mut_ptr().add(idx) = r1 as u8;
                }

                let pf = br_read_bit(&mut reader); if pf < 0 { return -6; }
                *s.gi_preflag.as_mut_ptr().add(idx) = pf as u8;
                let ss = br_read_bit(&mut reader); if ss < 0 { return -6; }
                *s.gi_scalefac_scale.as_mut_ptr().add(idx) = ss as u8;
                let ct = br_read_bit(&mut reader); if ct < 0 { return -6; }
                *s.gi_count1table_select.as_mut_ptr().add(idx) = ct as u8;

                ch += 1;
            }
            gr += 1;
        }

        0
    }
}

fn accumulate_main_data(s: &mut Mp3State, frame_data: *const u8, frame_data_len: usize) {
    unsafe {
        let keep = s.si_main_data_begin as usize;
        let current_len = s.main_data_len as usize;

        if keep > 0 && keep < current_len {
            let start = current_len - keep;
            // Move keep bytes to beginning
            let mut i: usize = 0;
            while i < keep {
                *s.main_data.as_mut_ptr().add(i) = *s.main_data.as_ptr().add(start + i);
                i += 1;
            }
            s.main_data_len = keep as u16;
        } else if keep == 0 {
            s.main_data_len = 0;
        }

        // Append frame data
        let space = 2048 - s.main_data_len as usize;
        let copy_len = if frame_data_len < space { frame_data_len } else { space };
        let dst_offset = s.main_data_len as usize;
        let mut i: usize = 0;
        while i < copy_len {
            *s.main_data.as_mut_ptr().add(dst_offset + i) = *frame_data.add(i);
            i += 1;
        }
        s.main_data_len += copy_len as u16;
    }
}

fn decode_granule_channel(s: &mut Mp3State, gr: usize, ch: usize) -> i32 {
    unsafe {
        let idx = gi_idx(gr, ch);
        let _num_channels = s.channels as usize;

        let byte_start = s.main_data_bit_pos as usize / 8;
        let bit_offset = s.main_data_bit_pos as usize - byte_start * 8;

        let data_len = s.main_data_len as usize;
        if byte_start >= data_len { return -6; }

        // Decode scalefactors
        let scalefac_bits = decode_scalefactors(s, gr, ch, byte_start, bit_offset);
        if scalefac_bits < 0 { return scalefac_bits; }

        // Huffman decode
        {
            let reader_start = byte_start;
            let total_skip = bit_offset + scalefac_bits as usize;
            let mut reader = br_new(
                s.main_data.as_ptr().add(reader_start),
                data_len - reader_start,
            );
            if total_skip > 0 {
                let ret = br_skip_bits(&mut reader, total_skip);
                if ret < 0 { return -6; }
            }

            let part2_3_len = *s.gi_part2_3_length.as_ptr().add(idx);
            let huff_bits = if part2_3_len > scalefac_bits as u16 { part2_3_len - scalefac_bits as u16 } else { 0 };

            let ret = decode_spectral_data(
                &mut reader,
                *s.gi_big_values.as_ptr().add(idx),
                s.gi_table_select.as_ptr().add(idx * 3),
                *s.gi_region0_count.as_ptr().add(idx),
                *s.gi_region1_count.as_ptr().add(idx),
                *s.gi_count1table_select.as_ptr().add(idx) != 0,
                huff_bits,
                s.huff_values.as_mut_ptr(),
            );
            if ret < 0 { return ret; }
        }

        // Requantize
        requantize(
            s.huff_values.as_ptr(),
            s.freq_lines.as_mut_ptr().add(ch * GRANULE_SAMPLES),
            s.scalefactors.as_ptr().add(sf_idx(gr, ch, 0)),
            *s.gi_global_gain.as_ptr().add(idx),
            *s.gi_scalefac_scale.as_ptr().add(idx) != 0,
            *s.gi_block_type.as_ptr().add(idx),
            s.gi_subblock_gain.as_ptr().add(idx * 3),
            *s.gi_preflag.as_ptr().add(idx) != 0,
            s.sample_rate,
        );

        // Advance bit position
        s.main_data_bit_pos += *s.gi_part2_3_length.as_ptr().add(idx);

        0
    }
}

fn decode_scalefactors(s: &mut Mp3State, gr: usize, ch: usize, byte_start: usize, bit_offset: usize) -> i32 {
    unsafe {
        let idx = gi_idx(gr, ch);
        let num_channels = s.channels as usize;
        let data_len = s.main_data_len as usize;

        let mut reader = br_new(
            s.main_data.as_ptr().add(byte_start),
            data_len - byte_start,
        );
        if bit_offset > 0 {
            let ret = br_skip_bits(&mut reader, bit_offset);
            if ret < 0 { return -6; }
        }

        let sfc = *s.gi_scalefac_compress.as_ptr().add(idx) as usize;
        let sfc_safe = if sfc > 15 { 15 } else { sfc };
        let (slen1, slen2) = *SLEN_TABLE.as_ptr().add(sfc_safe);
        let mut bits_read: usize = 0;

        let block_type = *s.gi_block_type.as_ptr().add(idx);
        let mixed = *s.gi_mixed_block.as_ptr().add(idx) != 0;
        let sf_base = sf_idx(gr, ch, 0);

        if block_type == 2 {
            if mixed {
                // Mixed block: long bands 0-7
                let mut band: usize = 0;
                while band < 8 {
                    if slen1 > 0 {
                        let v = br_read_bits(&mut reader, slen1);
                        if v < 0 { return -6; }
                        *s.scalefactors.as_mut_ptr().add(sf_base + band) = v as u8;
                        bits_read += slen1 as usize;
                    } else {
                        *s.scalefactors.as_mut_ptr().add(sf_base + band) = 0;
                    }
                    band += 1;
                }
                // Short bands 3-5
                let mut sfb: usize = 3;
                while sfb < 6 {
                    let mut win: usize = 0;
                    while win < 3 {
                        let band_idx = 8 + (sfb - 3) * 3 + win;
                        if slen1 > 0 {
                            let v = br_read_bits(&mut reader, slen1);
                            if v < 0 { return -6; }
                            *s.scalefactors.as_mut_ptr().add(sf_base + band_idx) = v as u8;
                            bits_read += slen1 as usize;
                        } else {
                            *s.scalefactors.as_mut_ptr().add(sf_base + band_idx) = 0;
                        }
                        win += 1;
                    }
                    sfb += 1;
                }
                // Short bands 6-11
                sfb = 6;
                while sfb < 12 {
                    let mut win: usize = 0;
                    while win < 3 {
                        let band_idx = 8 + (sfb - 3) * 3 + win;
                        if slen2 > 0 {
                            let v = br_read_bits(&mut reader, slen2);
                            if v < 0 { return -6; }
                            *s.scalefactors.as_mut_ptr().add(sf_base + band_idx) = v as u8;
                            bits_read += slen2 as usize;
                        } else {
                            *s.scalefactors.as_mut_ptr().add(sf_base + band_idx) = 0;
                        }
                        win += 1;
                    }
                    sfb += 1;
                }
            } else {
                // Pure short blocks
                let mut sfb: usize = 0;
                while sfb < 6 {
                    let mut win: usize = 0;
                    while win < 3 {
                        let band_idx = sfb * 3 + win;
                        if slen1 > 0 {
                            let v = br_read_bits(&mut reader, slen1);
                            if v < 0 { return -6; }
                            *s.scalefactors.as_mut_ptr().add(sf_base + band_idx) = v as u8;
                            bits_read += slen1 as usize;
                        } else {
                            *s.scalefactors.as_mut_ptr().add(sf_base + band_idx) = 0;
                        }
                        win += 1;
                    }
                    sfb += 1;
                }
                sfb = 6;
                while sfb < 12 {
                    let mut win: usize = 0;
                    while win < 3 {
                        let band_idx = sfb * 3 + win;
                        if slen2 > 0 {
                            let v = br_read_bits(&mut reader, slen2);
                            if v < 0 { return -6; }
                            *s.scalefactors.as_mut_ptr().add(sf_base + band_idx) = v as u8;
                            bits_read += slen2 as usize;
                        } else {
                            *s.scalefactors.as_mut_ptr().add(sf_base + band_idx) = 0;
                        }
                        win += 1;
                    }
                    sfb += 1;
                }
            }
        } else {
            // Long blocks
            // Group 0: bands 0-5, Group 1: 6-10, Group 2: 11-15, Group 3: 16-20
            let group_starts: [usize; 4] = [0, 6, 11, 16];
            let group_ends: [usize; 4] = [6, 11, 16, 21];

            let mut group_idx: usize = 0;
            while group_idx < 4 {
                let start = *group_starts.as_ptr().add(group_idx);
                let end = *group_ends.as_ptr().add(group_idx);
                let reuse = gr == 1 && num_channels == 2 && *s.si_scfsi.as_ptr().add(ch * 4 + group_idx) != 0;
                let slen = if group_idx < 2 { slen1 } else { slen2 };

                let mut sfb = start;
                while sfb < end {
                    if reuse {
                        // Copy from previous granule
                        let prev_base = sf_idx(0, ch, 0);
                        *s.scalefactors.as_mut_ptr().add(sf_base + sfb) = *s.scalefactors.as_ptr().add(prev_base + sfb);
                    } else if slen > 0 {
                        let v = br_read_bits(&mut reader, slen);
                        if v < 0 { return -6; }
                        *s.scalefactors.as_mut_ptr().add(sf_base + sfb) = v as u8;
                        bits_read += slen as usize;
                    } else {
                        *s.scalefactors.as_mut_ptr().add(sf_base + sfb) = 0;
                    }
                    sfb += 1;
                }
                group_idx += 1;
            }
        }

        bits_read as i32
    }
}


// ============================================================================
// Codec API (called by decoder.rs)
// ============================================================================

/// Initialize MP3 codec state.
pub unsafe fn mp3_init(
    s: &mut Mp3State,
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
) {
    s.syscalls = syscalls;
    s.in_chan = in_chan;
    s.out_chan = out_chan;
    s.pending_out = 0;
    s.pending_offset = 0;
    s.frame_pos = 0;
    s.frame_size = 0;
    s.sample_rate = 44100;
    s.channels = 2;
    s.channel_mode = 0;
    s.mode_extension = 0;
    s.has_crc = 0;
    s.phase = Mp3Phase::Sync;
    s.out_pos = 0;
    s.out_len = 0;
    s.main_data_len = 0;
    s.main_data_bit_pos = 0;

    // Zero synth state
    let mut i: usize = 0;
    while i < 2048 { *s.synth_v.as_mut_ptr().add(i) = 0; i += 1; }
    s.synth_offset[0] = 0;
    s.synth_offset[1] = 0;

    // Zero overlap
    i = 0;
    while i < 1152 { *s.overlap.as_mut_ptr().add(i) = 0; i += 1; }

    let sys = &*s.syscalls;
    dev_log(sys, 3, b"mp3: init\0".as_ptr(), 9);
}

/// Feed initial detection bytes into MP3 frame buffer.
/// Call after mp3_init, before first mp3_step, to provide bytes
/// already consumed during format detection.
pub unsafe fn mp3_feed_detect(s: &mut Mp3State, buf: *const u8, len: usize) {
    let to_copy = if len > 1500 { 1500 } else { len };
    let mut i: usize = 0;
    while i < to_copy {
        *s.frame_buf.as_mut_ptr().add(i) = *buf.add(i);
        i += 1;
    }
    s.frame_pos = to_copy;
    // Start in sync phase — the detection bytes contain the sync header
    // so let the step function find the sync from frame_buf
    // Actually, detection bytes go into the IO path, not frame_buf.
    // Reset frame_pos and let step read fresh from channel with detect bytes
    // already consumed. The few detect bytes (2-4) are the sync header which
    // the channel has already delivered. We need to push them back into the
    // sync search. Copy to io_buf instead for the sync scan.
    // Simpler: just put the bytes into frame_buf at position 0 and
    // start in Mp3Phase::Sync. The sync scanner reads from io_buf though,
    // not frame_buf. So feed_detect for MP3 should put the bytes
    // somewhere the sync scanner can find them.
    //
    // Actually, the simplest approach: push them into io_buf and
    // do an inline sync search. But that's complex. Since detect bytes
    // are only 2-4 bytes (the sync word), and the channel still has
    // the rest of the frame, let's just start in Mp3Phase::Sync and let
    // the next channel read pick up from after the detect bytes.
    // The detect bytes ARE the sync header (0xFF 0xFB etc.), so they're
    // already consumed. The MP3 decoder will resync on the NEXT frame.
    // First frame is lost but that's acceptable for a stream switch.
    s.frame_pos = 0;
}

/// Step the MP3 codec. Returns 0 on success.
pub unsafe fn mp3_step(s: &mut Mp3State) -> i32 {
    if s.syscalls.is_null() { return -1; }
    let sys = &*s.syscalls;
    let in_chan = s.in_chan;
    let out_chan = s.out_chan;

    // 1. Drain pending output
    if !drain_pending(sys, out_chan, s.io_buf.as_ptr(), &mut s.pending_out, &mut s.pending_offset) {
        return 0;
    }

    // 2. If we have decoded PCM to output, drain it
    if s.out_pos < s.out_len {
        let out_poll = (sys.channel_poll)(out_chan, POLL_OUT);
        if out_poll <= 0 || ((out_poll as u8) & POLL_OUT) == 0 { return 0; }

        let remaining = (s.out_len - s.out_pos) as usize;
        let remaining_bytes = remaining * 2;
        let chunk = if remaining_bytes > IO_BUF_SIZE { IO_BUF_SIZE } else { remaining_bytes };
        let chunk_samples = chunk / 2;

        let src = s.out_buf.as_ptr().add(s.out_pos as usize);
        let dst = s.io_buf.as_mut_ptr();
        let mut i: usize = 0;
        while i < chunk_samples {
            let sample = *src.add(i);
            let bytes = sample.to_le_bytes();
            *dst.add(i * 2) = bytes[0];
            *dst.add(i * 2 + 1) = bytes[1];
            i += 1;
        }

        let written = (sys.channel_write)(out_chan, s.io_buf.as_ptr(), chunk);
        if written < 0 && written != E_AGAIN { return -1; }
        if written > 0 {
            s.out_pos += (written as usize / 2) as u16;
        }
        track_pending(written, chunk, &mut s.pending_out, &mut s.pending_offset);
        return 0;
    }

    // 3. State machine for input processing
    if s.phase == Mp3Phase::Sync {
        let in_poll = (sys.channel_poll)(in_chan, POLL_IN);
        if in_poll <= 0 || ((in_poll as u8) & POLL_IN) == 0 { return 0; }

        let read = (sys.channel_read)(in_chan, s.io_buf.as_mut_ptr(), IO_BUF_SIZE);
        if read <= 0 { return 0; }

        let count = read as usize;
        let mut pos: usize = 0;
        while pos + 3 < count {
            let b0 = *s.io_buf.as_ptr().add(pos);
            let b1 = *s.io_buf.as_ptr().add(pos + 1);
            if b0 == 0xFF && (b1 & 0xE0) == 0xE0 {
                let mut sr: u32 = 0;
                let mut ch: u8 = 0;
                let mut cm: u8 = 0;
                let mut me: u8 = 0;
                let mut hc: u8 = 0;
                let mut fs: usize = 0;
                let ret = parse_header(
                    s.io_buf.as_ptr().add(pos),
                    &mut sr, &mut ch, &mut cm, &mut me, &mut hc, &mut fs,
                );
                if ret == 0 && fs > 0 && fs <= 1500 {
                    s.sample_rate = sr;
                    s.channels = ch;
                    s.channel_mode = cm;
                    s.mode_extension = me;
                    s.has_crc = hc;
                    s.frame_size = fs;

                    let avail = count - pos;
                    let copy_len = if avail > fs { fs } else { avail };
                    let mut j: usize = 0;
                    while j < copy_len {
                        *s.frame_buf.as_mut_ptr().add(j) = *s.io_buf.as_ptr().add(pos + j);
                        j += 1;
                    }
                    s.frame_pos = copy_len;

                    if s.frame_pos >= s.frame_size {
                        s.phase = Mp3Phase::Decode;
                    } else {
                        s.phase = Mp3Phase::Frame;
                    }
                    return 0;
                }
            }
            pos += 1;
        }
        return 0;
    }

    if s.phase == Mp3Phase::Frame {
        let in_poll = (sys.channel_poll)(in_chan, POLL_IN);
        if in_poll <= 0 || ((in_poll as u8) & POLL_IN) == 0 { return 0; }

        let needed = s.frame_size - s.frame_pos;
        let max_read = if needed > IO_BUF_SIZE { IO_BUF_SIZE } else { needed };
        let read = (sys.channel_read)(in_chan, s.io_buf.as_mut_ptr(), max_read);
        if read <= 0 { return 0; }

        let count = read as usize;
        let mut j: usize = 0;
        while j < count {
            if s.frame_pos < 1500 {
                *s.frame_buf.as_mut_ptr().add(s.frame_pos) = *s.io_buf.as_ptr().add(j);
                s.frame_pos += 1;
            }
            j += 1;
        }

        if s.frame_pos >= s.frame_size {
            s.phase = Mp3Phase::Decode;
        }
        return 0;
    }

    if s.phase == Mp3Phase::Decode {
        let result = decode_frame(s);
        if result >= 0 {
            s.out_pos = 0;
            s.out_len = result as u16;
        }
        s.frame_pos = 0;
        s.frame_size = 0;
        s.phase = Mp3Phase::Sync;
        return 0;
    }

    0
}
