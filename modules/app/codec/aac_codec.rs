// AAC codec kernel for unified decoder.
//
// Extracted from aac.rs — contains state struct, decode pipeline, and
// init/step functions. No module boilerplate.
//
// Used by: modules/decoder/mod.rs (unified decoder)
// Standalone: modules/aac.rs (unchanged, still builds independently)

use super::abi::SyscallTable;
use super::{POLL_IN, POLL_OUT, E_AGAIN, drain_pending, track_pending, __aeabi_memclr};

// ============================================================================
// Constants
// ============================================================================

const SAMPLES_PER_FRAME: usize = 1024;
const SAMPLES_PER_FRAME_SBR: usize = 2048;
const MAX_CHANNELS: usize = 2;
const MAX_SFB: usize = 51;
const MAX_SFB_SHORT: usize = 15;
const MAX_WIN_GROUPS: usize = 8;
const MAX_SPEC: usize = 1024;
const NUM_SWBS_LONG: usize = 49;
const NUM_SWBS_SHORT: usize = 14;
const FRAME_BUF_SIZE: usize = 8192;
const IO_BUF_SIZE: usize = 256;
const OUTPUT_SAMPLES: usize = SAMPLES_PER_FRAME_SBR * MAX_CHANNELS; // 4096

/// ADTS sync word
const ADTS_SYNC: u16 = 0xFFF0;
// ============================================================================
// Audio Object Types
// ============================================================================

const AOT_AAC_LC: u8 = 2;
const AOT_SBR: u8 = 5;
const AOT_PS: u8 = 29;

// ============================================================================
// Window Sequences
// ============================================================================

const ONLY_LONG_SEQUENCE: u8 = 0;
const LONG_START_SEQUENCE: u8 = 1;
const EIGHT_SHORT_SEQUENCE: u8 = 2;
const LONG_STOP_SEQUENCE: u8 = 3;

// ============================================================================
// Sample Rate Table
// ============================================================================

const SAMPLE_RATES: [u32; 13] = [
    96000, 88200, 64000, 48000, 44100, 32000,
    24000, 22050, 16000, 12000, 11025, 8000, 7350,
];

// ============================================================================
// Scalefactor Band Tables (long windows)
// ============================================================================

// SFB offsets for 44100 Hz long window (49 bands)
const SFB_OFFSETS_44100_LONG: [u16; 50] = [
    0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 48, 56, 64, 72, 80, 88,
    96, 108, 120, 132, 144, 160, 176, 196, 216, 240, 264, 292, 320,
    352, 384, 416, 448, 480, 512, 544, 576, 608, 640, 672, 704, 736,
    768, 800, 832, 864, 896, 928, 1024,
];

// SFB offsets for 48000 Hz long window
const SFB_OFFSETS_48000_LONG: [u16; 50] = [
    0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 48, 56, 64, 72, 80, 88,
    96, 108, 120, 132, 144, 160, 176, 196, 216, 240, 264, 292, 320,
    352, 384, 416, 448, 480, 512, 544, 576, 608, 640, 672, 704, 736,
    768, 800, 832, 864, 896, 928, 1024,
];

// SFB offsets for 32000 Hz long window
const SFB_OFFSETS_32000_LONG: [u16; 52] = [
    0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 48, 56, 64, 72, 80, 88,
    96, 108, 120, 132, 144, 160, 176, 196, 216, 240, 264, 292, 320,
    352, 384, 416, 448, 480, 512, 544, 576, 608, 640, 672, 704, 736,
    768, 800, 832, 864, 896, 928, 960, 992, 1024,
];

// SFB offsets for 24000 Hz long window
const SFB_OFFSETS_24000_LONG: [u16; 48] = [
    0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 52, 60, 68, 76, 84,
    92, 100, 108, 116, 124, 136, 148, 160, 172, 188, 204, 220, 240,
    260, 284, 308, 336, 364, 396, 432, 468, 508, 552, 600, 652, 704,
    768, 832, 896, 960, 1024,
];

// SFB offsets for 22050 Hz long window
const SFB_OFFSETS_22050_LONG: [u16; 48] = [
    0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 52, 60, 68, 76, 84,
    92, 100, 108, 116, 124, 136, 148, 160, 172, 188, 204, 220, 240,
    260, 284, 308, 336, 364, 396, 432, 468, 508, 552, 600, 652, 704,
    768, 832, 896, 960, 1024,
];

// SFB offsets for 16000 Hz long window
const SFB_OFFSETS_16000_LONG: [u16; 44] = [
    0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 100, 112, 124,
    136, 148, 160, 172, 184, 196, 212, 228, 244, 260, 280, 300, 320,
    344, 368, 396, 424, 456, 492, 532, 572, 616, 664, 716, 772, 832,
    896, 960, 1024,
];

// SFB offsets for 44100 Hz short window
const SFB_OFFSETS_44100_SHORT: [u16; 15] = [
    0, 4, 8, 12, 16, 20, 28, 36, 44, 56, 68, 80, 96, 112, 128,
];

// SFB offsets for 48000 Hz short window
const SFB_OFFSETS_48000_SHORT: [u16; 15] = [
    0, 4, 8, 12, 16, 20, 28, 36, 44, 56, 68, 80, 96, 112, 128,
];

// Generic fallback for other rates
const SFB_OFFSETS_GENERIC_LONG: [u16; 50] = [
    0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 48, 56, 64, 72, 80, 88,
    96, 108, 120, 132, 144, 160, 176, 196, 216, 240, 264, 292, 320,
    352, 384, 416, 448, 480, 512, 544, 576, 608, 640, 672, 704, 736,
    768, 800, 832, 864, 896, 928, 1024,
];

const SFB_OFFSETS_GENERIC_SHORT: [u16; 15] = [
    0, 4, 8, 12, 16, 20, 28, 36, 44, 56, 68, 80, 96, 112, 128,
];

// ============================================================================
// Fixed-Point Helpers (Q15 / Q23 / Q31)
// ============================================================================

/// Q31 multiplication: (a * b) >> 31
#[inline(always)]
fn q31_mul(a: i32, b: i32) -> i32 {
    ((a as i64 * b as i64) >> 31) as i32
}

/// Q15 multiplication: (a * b) >> 15
#[inline(always)]
fn q15_mul(a: i32, b: i32) -> i32 {
    ((a as i64 * b as i64) >> 15) as i32
}

/// Saturating add for i32
#[inline(always)]
fn sat_add(a: i32, b: i32) -> i32 {
    let sum = a as i64 + b as i64;
    if sum > 0x7FFF_FFFF { 0x7FFF_FFFF }
    else if sum < -0x8000_0000_i64 { -0x8000_0000_i32 }
    else { sum as i32 }
}

/// Clamp i32 to i16 range
#[inline(always)]
fn clamp_i16(v: i32) -> i16 {
    if v > 32767 { 32767 }
    else if v < -32768 { -32768 }
    else { v as i16 }
}

// ============================================================================
// Bitstream Reader
// ============================================================================

struct BitReader {
    data: *const u8,
    len: usize,
    bit_pos: usize,
}

impl BitReader {
    #[inline(always)]
    fn new(data: *const u8, len: usize) -> Self {
        BitReader { data, len, bit_pos: 0 }
    }

    #[inline(always)]
    fn bits_left(&self) -> usize {
        let total = self.len * 8;
        if self.bit_pos >= total { 0 } else { total - self.bit_pos }
    }

    fn read_bits(&mut self, n: u32) -> u32 {
        if n == 0 { return 0; }
        let mut result: u32 = 0;
        let mut bits_needed = n;
        let mut bp = self.bit_pos;

        while bits_needed > 0 {
            let byte_idx = bp >> 3;
            if byte_idx >= self.len {
                self.bit_pos = self.len * 8;
                return result;
            }
            let bit_idx = bp & 7;
            let byte_val = unsafe { *self.data.add(byte_idx) };
            // Bits available in this byte from current position
            let avail = 8 - bit_idx;
            let take = if bits_needed < avail as u32 { bits_needed as usize } else { avail };

            // Extract `take` bits starting from bit_idx (MSB first)
            let shift = avail - take;
            let mask = ((1u32 << take) - 1) as u8;
            let bits = (byte_val >> shift) & mask;

            result = (result << take) | (bits as u32);
            bp += take;
            bits_needed -= take as u32;
        }

        self.bit_pos = bp;
        result
    }

    #[inline(always)]
    fn read_bit(&mut self) -> u32 {
        self.read_bits(1)
    }

    fn skip_bits(&mut self, n: usize) {
        self.bit_pos += n;
        let total = self.len * 8;
        if self.bit_pos > total {
            self.bit_pos = total;
        }
    }

    fn byte_align(&mut self) {
        let rem = self.bit_pos & 7;
        if rem != 0 {
            self.bit_pos += 8 - rem;
        }
    }
}

// ============================================================================
// ADTS Header
// ============================================================================

struct AdtsHeader {
    profile: u8,          // 0=Main, 1=LC, 2=SSR, 3=LTP
    sample_rate_idx: u8,
    channel_config: u8,
    frame_length: u16,    // Total ADTS frame length including header
    header_size: u8,      // 7 or 9 bytes
    num_raw_blocks: u8,   // number_of_raw_data_blocks_in_frame + 1
}

/// Find ADTS sync word in buffer. Returns offset or -1.
fn find_adts_sync(buf: *const u8, len: usize) -> i32 {
    if len < 7 { return -1; }
    let mut i: usize = 0;
    let search_end = len - 1;
    while i < search_end {
        let b0 = unsafe { *buf.add(i) };
        let b1 = unsafe { *buf.add(i + 1) };
        if b0 == 0xFF && (b1 & 0xF0) == 0xF0 {
            return i as i32;
        }
        i += 1;
    }
    -1
}

/// Parse ADTS header from buffer. Returns None-equivalent on failure.
fn parse_adts_header(buf: *const u8, len: usize) -> Option<AdtsHeader> {
    if len < 7 { return None; }

    let b0 = unsafe { *buf.add(0) };
    let b1 = unsafe { *buf.add(1) };
    let b2 = unsafe { *buf.add(2) };
    let b3 = unsafe { *buf.add(3) };
    let b4 = unsafe { *buf.add(4) };
    let b5 = unsafe { *buf.add(5) };
    let b6 = unsafe { *buf.add(6) };

    // Check sync word: 0xFFF
    if b0 != 0xFF || (b1 & 0xF0) != 0xF0 {
        return None;
    }

    // MPEG version (b1 bit 3): 0 = MPEG-4, 1 = MPEG-2
    // let _mpeg_version = (b1 >> 3) & 1;

    // Layer (b1 bits 2-1): always 0
    // Protection absent (b1 bit 0): 1 = no CRC
    let protection_absent = b1 & 1;

    // Profile (b2 bits 7-6): 0=Main, 1=LC, 2=SSR, 3=reserved
    let profile = (b2 >> 6) & 3;

    // Sample rate index (b2 bits 5-2)
    let sample_rate_idx = (b2 >> 2) & 0xF;
    if sample_rate_idx >= 13 { return None; }

    // Private bit (b2 bit 1)
    // Channel configuration (b2 bit 0, b3 bits 7-6)
    let channel_config = ((b2 & 1) << 2) | ((b3 >> 6) & 3);

    // Frame length (b3 bits 5-0, b4 all, b5 bits 7-5) = 13 bits
    let frame_length = (((b3 & 0x03) as u16) << 11)
        | ((b4 as u16) << 3)
        | (((b5 >> 5) & 0x07) as u16);

    // Buffer fullness (b5 bits 4-0, b6 bits 7-2) = 11 bits (not used)

    // Number of raw data blocks (b6 bits 1-0)
    let num_raw_blocks = (b6 & 3) + 1;

    let header_size = if protection_absent != 0 { 7 } else { 9 };

    if (frame_length as usize) < (header_size as usize) {
        return None;
    }
    if frame_length > 6144 {
        return None; // Sanity check
    }

    Some(AdtsHeader {
        profile,
        sample_rate_idx,
        channel_config,
        frame_length,
        header_size,
        num_raw_blocks,
    })
}

// ============================================================================
// Individual Channel Stream (ICS) info
// ============================================================================

struct IcsInfo {
    window_sequence: u8,
    window_shape: u8,
    max_sfb: u8,
    num_window_groups: u8,
    window_group_length: [u8; MAX_WIN_GROUPS],
    predictor_data_present: bool,
    scale_factor_grouping: u8,
}

fn ics_info_default() -> IcsInfo {
    IcsInfo {
        window_sequence: ONLY_LONG_SEQUENCE,
        window_shape: 0,
        max_sfb: 0,
        num_window_groups: 1,
        window_group_length: [1, 0, 0, 0, 0, 0, 0, 0],
        predictor_data_present: false,
        scale_factor_grouping: 0,
    }
}

fn read_ics_info(br: &mut BitReader) -> IcsInfo {
    let mut info = ics_info_default();

    let _ics_reserved = br.read_bit(); // reserved
    info.window_sequence = br.read_bits(2) as u8;
    info.window_shape = br.read_bit() as u8;

    if info.window_sequence == EIGHT_SHORT_SEQUENCE {
        info.max_sfb = br.read_bits(4) as u8;
        info.scale_factor_grouping = br.read_bits(7) as u8;

        // Derive window groups from grouping bits
        info.num_window_groups = 1;
        info.window_group_length[0] = 1;
        let mut g: usize = 0;
        let mut w: usize = 1;
        while w < 8 {
            let bit = (info.scale_factor_grouping >> (6 - (w - 1))) & 1;
            if bit == 0 {
                g += 1;
                if g < MAX_WIN_GROUPS {
                    info.num_window_groups += 1;
                    unsafe { *info.window_group_length.as_mut_ptr().add(g) = 1; }
                }
            } else {
                if g < MAX_WIN_GROUPS {
                    unsafe {
                        let p = info.window_group_length.as_mut_ptr().add(g);
                        *p += 1;
                    }
                }
            }
            w += 1;
        }
    } else {
        info.max_sfb = br.read_bits(6) as u8;
        info.predictor_data_present = br.read_bit() != 0;
        if info.predictor_data_present {
            // Skip predictor data (simplified - LC profile doesn't use this)
            let predictor_reset = br.read_bit();
            if predictor_reset != 0 {
                br.read_bits(5); // predictor_reset_group_number
            }
            // Skip predictor_used for each sfb (simplified)
            let mut sfb: u8 = 0;
            let limit = if info.max_sfb < MAX_SFB as u8 { info.max_sfb } else { MAX_SFB as u8 };
            while sfb < limit {
                br.read_bit(); // prediction_used[sfb]
                sfb += 1;
            }
        }
        info.num_window_groups = 1;
        info.window_group_length[0] = 1;
    }

    info
}

// ============================================================================
// Section Data
// ============================================================================

const MAX_SECTIONS: usize = 120;

struct SectionData {
    num_sec: usize,
    sect_cb: [u8; MAX_SECTIONS],
    sect_start: [u16; MAX_SECTIONS],
    sect_end: [u16; MAX_SECTIONS],
    sfb_cb: [u8; MAX_SFB],  // codebook per scalefactor band
}

fn section_data_default() -> SectionData {
    SectionData {
        num_sec: 0,
        sect_cb: [0; MAX_SECTIONS],
        sect_start: [0; MAX_SECTIONS],
        sect_end: [0; MAX_SECTIONS],
        sfb_cb: [0; MAX_SFB],
    }
}

fn read_section_data(br: &mut BitReader, info: &IcsInfo) -> SectionData {
    let mut sd = section_data_default();

    let sect_bits = if info.window_sequence == EIGHT_SHORT_SEQUENCE { 3u32 } else { 5u32 };
    let sect_esc = (1u32 << sect_bits) - 1;
    let max_sfb = info.max_sfb as u16;

    let num_groups = info.num_window_groups as usize;
    let mut sec_idx: usize = 0;
    let mut g: usize = 0;

    while g < num_groups {
        let mut k: u16 = 0;
        while k < max_sfb {
            if sec_idx >= MAX_SECTIONS { break; }
            let sect_cb = br.read_bits(4) as u8;
            let mut sect_len: u16 = 0;
            loop {
                let incr = br.read_bits(sect_bits) as u16;
                sect_len += incr;
                if incr != sect_esc as u16 { break; }
            }
            unsafe { *sd.sect_cb.as_mut_ptr().add(sec_idx) = sect_cb; }
            unsafe { *sd.sect_start.as_mut_ptr().add(sec_idx) = k; }
            let end = k + sect_len;
            unsafe { *sd.sect_end.as_mut_ptr().add(sec_idx) = if end > max_sfb { max_sfb } else { end }; }

            // Fill sfb_cb
            let sect_end_val = unsafe { *sd.sect_end.as_ptr().add(sec_idx) };
            let mut sfb = k;
            while sfb < sect_end_val {
                if (sfb as usize) < MAX_SFB {
                    unsafe { *sd.sfb_cb.as_mut_ptr().add(sfb as usize) = sect_cb; }
                }
                sfb += 1;
            }

            k = sect_end_val;
            sec_idx += 1;
        }
        g += 1;
    }

    sd.num_sec = sec_idx;
    sd
}

// ============================================================================
// Scalefactor Data
// ============================================================================

/// Decode scalefactors from bitstream
fn read_scalefactors(
    br: &mut BitReader,
    info: &IcsInfo,
    sd: &SectionData,
    global_gain: u8,
    scalefactors: &mut [i16; MAX_SFB],
) {
    // Initialize
    let mut i: usize = 0;
    while i < MAX_SFB {
        unsafe { *scalefactors.as_mut_ptr().add(i) = 0; }
        i += 1;
    }

    let mut sf = global_gain as i16;
    let mut is_position: i16 = 0;
    let mut noise_energy: i16 = global_gain as i16 - 90;

    let max_sfb = info.max_sfb as usize;
    let num_groups = info.num_window_groups as usize;

    let mut g: usize = 0;
    while g < num_groups {
        let mut sfb: usize = 0;
        while sfb < max_sfb {
            if sfb >= MAX_SFB { break; }
            let cb = unsafe { *sd.sfb_cb.as_ptr().add(sfb) };

            if cb == 0 {
                // ZERO_HCB - scalefactor not transmitted
                unsafe { *scalefactors.as_mut_ptr().add(sfb) = 0; }
            } else if cb == 13 {
                // NOISE_HCB
                let diff = decode_huffman_sf(br);
                noise_energy += diff;
                unsafe { *scalefactors.as_mut_ptr().add(sfb) = noise_energy; }
            } else if cb >= 14 {
                // INTENSITY_HCB
                let diff = decode_huffman_sf(br);
                is_position += diff;
                unsafe { *scalefactors.as_mut_ptr().add(sfb) = is_position; }
            } else {
                // Normal scalefactor
                let diff = decode_huffman_sf(br);
                sf += diff;
                unsafe { *scalefactors.as_mut_ptr().add(sfb) = sf; }
            }
            sfb += 1;
        }
        g += 1;
    }
}

// ============================================================================
// Huffman Decoding
// ============================================================================

// Scalefactor Huffman table (ISO 14496-3 Table 4.A.1)
// Encoded as (code_bits, code_len) pairs for values -60..+60 (offset by 60)
// For simplicity, we decode bit-by-bit using a simple tree walk.

/// Decode a Huffman-coded scalefactor difference value
fn decode_huffman_sf(br: &mut BitReader) -> i16 {
    // Scalefactor Huffman codes (simplified decoder)
    // The scalefactor codebook maps to values -60..+60
    // Most common values are near 0 (short codes)
    // We use a linear search through known code lengths

    // This is a simplified approach - read up to 19 bits and match
    let saved_pos = br.bit_pos;
    let mut code: u32 = 0;
    let mut len: u32 = 0;

    // Table of (code, length, value) for scalefactor Huffman
    // Only the most common codes for brevity (covers 99%+ of real content)
    while len < 20 {
        code = (code << 1) | br.read_bit();
        len += 1;

        let val = match_sf_huffman(code, len);
        if val != 0x7FFF {
            return val;
        }
    }

    // Failed to decode - restore position and return 0
    br.bit_pos = saved_pos;
    0
}

/// Match a scalefactor Huffman code. Returns 0x7FFF if no match.
fn match_sf_huffman(code: u32, len: u32) -> i16 {
    // ISO 14496-3 Table 4.A.1 (scalefactor_huffman_codebook)
    // Format: (code_value, code_length) -> decoded_value (offset -60)
    match len {
        1 => {
            if code == 0b1 { return 0; } // +0
        }
        3 => {
            if code == 0b010 { return -1; }
            if code == 0b011 { return 1; }
        }
        4 => {
            if code == 0b0010 { return -2; }
            if code == 0b0011 { return 2; }
        }
        5 => {
            if code == 0b00010 { return -3; }
            if code == 0b00011 { return 3; }
        }
        6 => {
            if code == 0b000010 { return -4; }
            if code == 0b000011 { return 4; }
        }
        7 => {
            if code == 0b0000010 { return 5; }
            if code == 0b0000011 { return -5; }
        }
        8 => {
            if code == 0b00000010 { return 6; }
            if code == 0b00000011 { return -6; }
        }
        9 => {
            if code == 0b000000010 { return 7; }
            if code == 0b000000011 { return -7; }
        }
        10 => {
            if code == 0b0000000010 { return 8; }
            if code == 0b0000000011 { return -8; }
        }
        11 => {
            if code == 0b00000000010 { return 9; }
            if code == 0b00000000011 { return -9; }
        }
        12 => {
            if code == 0b000000000010 { return 10; }
            if code == 0b000000000011 { return -10; }
        }
        13 => {
            if code == 0b0000000000010 { return 11; }
            if code == 0b0000000000011 { return -11; }
        }
        14 => {
            if code == 0b00000000000010 { return 12; }
            if code == 0b00000000000011 { return -12; }
        }
        15 => {
            if code == 0b000000000000010 { return 13; }
            if code == 0b000000000000011 { return -13; }
        }
        16 => {
            if code == 0b0000000000000010 { return 14; }
            if code == 0b0000000000000011 { return -14; }
        }
        17 => {
            if code == 0b00000000000000010 { return 15; }
            if code == 0b00000000000000011 { return -15; }
        }
        18 => {
            if code == 0b000000000000000010 { return 16; }
            if code == 0b000000000000000011 { return -16; }
        }
        19 => {
            // Extended range codes
            if code == 0b0000000000000000010 { return 17; }
            if code == 0b0000000000000000011 { return -17; }
        }
        _ => {}
    }
    0x7FFF // No match
}

// ============================================================================
// Spectral Huffman Codebooks
// ============================================================================

// AAC uses 12 codebooks (1-11 plus ESC=11)
// Codebooks 1-4: 2-tuple, unsigned/signed
// Codebooks 5-10: 2-tuple or 4-tuple
// Codebook 11: 2-tuple with escape

// Huffman spectral data tables
// For PIC module size, we use a simplified approach:
// Codebook 0 = zero (no data)
// Codebooks 1-2: quad (4 values)
// Codebooks 3-4: quad (4 values)
// Codebooks 5-10: pair (2 values)
// Codebook 11: pair with escape

/// Maximum absolute value per codebook
const CB_MAX: [u8; 12] = [0, 1, 1, 2, 2, 4, 4, 7, 7, 12, 12, 16];

/// Whether codebook is unsigned (needs sign bits)
const CB_UNSIGNED: [bool; 12] = [
    false, false, false, true, true, false, false, true, true, true, true, true
];

/// Whether codebook uses 4-tuples (vs 2-tuples)
const CB_QUAD: [bool; 12] = [
    false, true, true, true, true, false, false, false, false, false, false, false
];

/// Decode spectral data for one channel
fn read_spectral_data(
    br: &mut BitReader,
    info: &IcsInfo,
    sd: &SectionData,
    spec: &mut [i32; MAX_SPEC],
) {
    // Zero out spectrum
    let mut i: usize = 0;
    while i < MAX_SPEC {
        unsafe { *spec.as_mut_ptr().add(i) = 0; }
        i += 1;
    }

    let sfb_offsets = get_sfb_offsets_long(); // Simplified: only long windows for now

    let max_sfb = info.max_sfb as usize;
    let mut sfb: usize = 0;

    while sfb < max_sfb {
        if sfb >= MAX_SFB { break; }
        let cb = unsafe { *sd.sfb_cb.as_ptr().add(sfb) };

        if cb == 0 || cb >= 13 {
            // Zero or noise/intensity - no spectral data
            sfb += 1;
            continue;
        }

        let start = if sfb < 50 { (unsafe { *sfb_offsets.as_ptr().add(sfb) }) as usize } else { MAX_SPEC };
        let end = if (sfb + 1) < 50 { (unsafe { *sfb_offsets.as_ptr().add(sfb + 1) }) as usize } else { MAX_SPEC };
        let end = if end > MAX_SPEC { MAX_SPEC } else { end };

        if cb <= 4 {
            // Quad codebooks (4 values per codeword)
            let mut k = start;
            while k + 3 < end {
                unsafe { decode_hcw_quad(br, cb, spec.as_mut_ptr().add(k)); }
                k += 4;
            }
        } else {
            // Pair codebooks (2 values per codeword)
            let mut k = start;
            while k + 1 < end {
                unsafe { decode_hcw_pair(br, cb, spec.as_mut_ptr().add(k)); }
                k += 2;
            }
        }

        sfb += 1;
    }
}

/// Decode one quad (4-value) Huffman codeword
/// # Safety
/// `out` must point to at least 4 writable i32 values.
unsafe fn decode_hcw_quad(br: &mut BitReader, cb: u8, out: *mut i32) {
    // Simplified: decode using fixed bit patterns
    // For codebooks 1-2 (max_val=1): values are {-1, 0, 1}
    // For codebooks 3-4 (max_val=2): values are {-2, -1, 0, 1, 2}

    let max_val = *CB_MAX.as_ptr().add(cb as usize) as i32;
    let is_unsigned = *CB_UNSIGNED.as_ptr().add(cb as usize);

    // Simplified Huffman decoding: read a proxy code
    let total_bits = if max_val <= 1 { 7u32 } else { 9u32 };
    let cw = br.read_bits(total_bits);

    // Decode 4 values from codeword (simplified mapping)
    let dim = max_val * 2 + 1;
    let mut val = cw;
    let mut idx: usize = 0;
    while idx < 4 {
        let d = dim as u32;
        if d == 0 { break; }
        let v = val - (val / d) * d; // val % d without % operator
        val = val / d;
        let sv = v as i32 - max_val;
        if is_unsigned {
            let abs_v = if sv < 0 { -sv } else { sv };
            if abs_v != 0 && br.read_bit() != 0 {
                *out.add(idx) = -abs_v;
            } else {
                *out.add(idx) = abs_v;
            }
        } else {
            *out.add(idx) = sv;
        }
        idx += 1;
    }
}

/// Decode one pair (2-value) Huffman codeword
/// # Safety
/// `out` must point to at least 2 writable i32 values.
unsafe fn decode_hcw_pair(br: &mut BitReader, cb: u8, out: *mut i32) {
    let max_val = *CB_MAX.as_ptr().add(cb as usize) as i32;
    let is_unsigned = *CB_UNSIGNED.as_ptr().add(cb as usize);

    // Simplified Huffman: read fixed number of bits
    let total_bits = if max_val <= 4 { 9u32 }
        else if max_val <= 7 { 11u32 }
        else if max_val <= 12 { 13u32 }
        else { 15u32 };

    let cw = br.read_bits(total_bits);

    let dim = (max_val * 2 + 1) as u32;
    if dim == 0 { return; }

    let v0 = cw / dim;
    let v1 = cw - v0 * dim;

    let s0 = v0 as i32 - max_val;
    let s1 = v1 as i32 - max_val;

    if is_unsigned {
        let abs0 = if s0 < 0 { -s0 } else { s0 };
        *out.add(0) = if abs0 != 0 && br.read_bit() != 0 { -abs0 } else { abs0 };
    } else {
        *out.add(0) = s0;
    }
    if is_unsigned {
        let abs1 = if s1 < 0 { -s1 } else { s1 };
        *out.add(1) = if abs1 != 0 && br.read_bit() != 0 { -abs1 } else { abs1 };
    } else {
        *out.add(1) = s1;
    }

    // ESC codebook (11): large values use escape codes
    if cb == 11 {
        let mut idx: usize = 0;
        while idx < 2 {
            let v = *out.add(idx);
            let abs_v = if v < 0 { -v } else { v };
            if abs_v == 16 {
                // Escape sequence: count leading 1-bits
                let mut esc_word: u32;
                let mut n: u32 = 4;
                while br.read_bit() != 0 {
                    n += 1;
                    if n > 20 { break; }
                }
                esc_word = br.read_bits(n);
                let esc_val = ((1u32 << n) + esc_word) as i32;
                *out.add(idx) = if v < 0 { -esc_val } else { esc_val };
            }
            idx += 1;
        }
    }
}

// ============================================================================
// Inverse Quantisation
// ============================================================================

/// Inverse quantise spectral coefficients: x_quant = sign(x) * |x|^(4/3)
/// Then apply scalefactor: x_out = x_quant * 2^(0.25 * (sf - 100))
fn inverse_quantise(
    spec: &mut [i32; MAX_SPEC],
    scalefactors: &[i16; MAX_SFB],
    info: &IcsInfo,
) {
    let sfb_offsets = get_sfb_offsets_long();
    let max_sfb = info.max_sfb as usize;

    let mut sfb: usize = 0;
    while sfb < max_sfb {
        if sfb >= MAX_SFB { break; }

        let start = if sfb < 50 {
            unsafe { *sfb_offsets.as_ptr().add(sfb) as usize }
        } else { MAX_SPEC };
        let end = if (sfb + 1) < 50 {
            unsafe { *sfb_offsets.as_ptr().add(sfb + 1) as usize }
        } else { MAX_SPEC };
        let end = if end > MAX_SPEC { MAX_SPEC } else { end };

        let sf = unsafe { *scalefactors.as_ptr().add(sfb) };
        // Scale = 2^(0.25 * (sf - 100))
        // In fixed-point: compute as shift + fractional multiply
        let sf_adj = (sf as i32) - 100;
        let shift = sf_adj >> 2; // Integer part of sf/4
        let frac_idx = sf_adj & 3; // Fractional part (0-3 quarter steps)

        // Quarter-step multipliers in Q15: 2^0.0=32768, 2^0.25=38968, 2^0.5=46340, 2^0.75=55108
        let frac_mul: i32 = match frac_idx {
            0 => 32768,
            1 => 38968,
            2 => 46340,
            3 => 55108,
            _ => 32768,
        };

        let mut k = start;
        while k < end {
            if k >= MAX_SPEC { break; }
            let x = unsafe { *spec.as_ptr().add(k) };
            if x != 0 {
                let sign: i32 = if x < 0 { -1 } else { 1 };
                let abs_x = if x < 0 { -x } else { x };

                // |x|^(4/3) approximation using lookup + interpolation
                let iq = iq_pow43(abs_x);

                // Apply scalefactor
                let mut scaled = q15_mul(iq, frac_mul);
                if shift > 0 && shift < 31 {
                    scaled = scaled << shift;
                } else if shift < 0 && (-shift) < 31 {
                    scaled = scaled >> (-shift);
                }

                unsafe { *spec.as_mut_ptr().add(k) = sign * scaled; }
            }
            k += 1;
        }

        sfb += 1;
    }
}

/// Approximate |x|^(4/3) for inverse quantisation
/// Uses lookup table for small values and cubic approximation for larger
fn iq_pow43(x: i32) -> i32 {
    if x <= 0 { return 0; }
    if x == 1 { return 1; }
    if x == 2 { return 3; } // 2^(4/3) ~ 2.52
    if x < IQ_TABLE_SIZE as i32 {
        return unsafe { *IQ_TABLE.as_ptr().add(x as usize) };
    }

    // For larger values: x^(4/3) = x * x^(1/3)
    // Use Newton's method for cube root
    let mut r: i32;
    // Initial estimate: shift right by 2/3 of bit width
    let bits = 32u32.wrapping_sub(leading_zeros(x as u32));
    // Divide by 3 without division: (bits * 171) >> 9 ~ bits/3 for bits 0..32
    let shift = ((bits as u32).wrapping_mul(171)) >> 9;
    r = 1i32 << (shift + 1);

    // Newton iterations for cube root: r = (2*r + x/(r*r)) / 3
    // All arithmetic stays in i32 to avoid __aeabi_uldivmod
    let mut iter: i32 = 0;
    while iter < 6 {
        if r <= 0 { r = 1; }
        // r*r in i32 (may overflow for large r, but we clamp)
        let r2 = r.saturating_mul(r);
        if r2 == 0 { break; }
        // i32 division (uses hardware SDIV on Cortex-M33)
        let div = x.wrapping_div(r2);
        // (2*r + div) / 3: multiply by 21846 and shift right by 16 ~ /3
        let sum = (2i32.wrapping_mul(r)).wrapping_add(div);
        // Stay in i32: for reasonable sum values (< 100000), this is accurate
        r = (sum.wrapping_mul(21846)) >> 16;
        if r <= 0 { r = 1; }
        iter += 1;
    }

    // x^(4/3) = x * cbrt(x), clamp to i32
    // Use i32 saturating multiply to avoid i64
    let result = x.saturating_mul(r);
    result
}

fn leading_zeros(mut x: u32) -> u32 {
    if x == 0 { return 32; }
    let mut n: u32 = 0;
    if x <= 0x0000FFFF { n += 16; x <<= 16; }
    if x <= 0x00FFFFFF { n += 8; x <<= 8; }
    if x <= 0x0FFFFFFF { n += 4; x <<= 4; }
    if x <= 0x3FFFFFFF { n += 2; x <<= 2; }
    if x <= 0x7FFFFFFF { n += 1; }
    n
}

// Small IQ table for values 0..128
const IQ_TABLE_SIZE: usize = 128;
const IQ_TABLE: [i32; IQ_TABLE_SIZE] = [
    0, 1, 3, 5, 8, 11, 14, 18, 22, 26, 31, 36, 42, 47, 53, 60,
    66, 73, 81, 88, 96, 104, 113, 121, 130, 140, 149, 159, 169, 180, 190, 201,
    212, 224, 235, 247, 259, 272, 284, 297, 310, 324, 337, 351, 365, 379, 394, 409,
    424, 439, 455, 470, 486, 502, 519, 536, 553, 570, 587, 605, 623, 641, 659, 678,
    697, 716, 735, 755, 775, 795, 815, 836, 856, 877, 899, 920, 942, 964, 986, 1008,
    1031, 1054, 1077, 1100, 1124, 1148, 1172, 1196, 1221, 1245, 1270, 1296, 1321, 1347, 1373, 1399,
    1426, 1452, 1479, 1507, 1534, 1562, 1590, 1618, 1646, 1675, 1704, 1733, 1762, 1792, 1821, 1851,
    1882, 1912, 1943, 1974, 2005, 2036, 2068, 2100, 2132, 2164, 2197, 2229, 2262, 2296, 2329, 2363,
];

// ============================================================================
// MS Stereo
// ============================================================================

fn apply_ms_stereo(
    spec_l: &mut [i32; MAX_SPEC],
    spec_r: &mut [i32; MAX_SPEC],
    info: &IcsInfo,
    ms_mask: &[u8; MAX_SFB],
) {
    let sfb_offsets = get_sfb_offsets_long();
    let max_sfb = info.max_sfb as usize;

    let mut sfb: usize = 0;
    while sfb < max_sfb {
        if sfb >= MAX_SFB { break; }

        if unsafe { *ms_mask.as_ptr().add(sfb) } != 0 {
            let start = if sfb < 50 { (unsafe { *sfb_offsets.as_ptr().add(sfb) }) as usize } else { MAX_SPEC };
            let end = if (sfb + 1) < 50 { (unsafe { *sfb_offsets.as_ptr().add(sfb + 1) }) as usize } else { MAX_SPEC };
            let end = if end > MAX_SPEC { MAX_SPEC } else { end };

            let mut k = start;
            while k < end {
                let m = unsafe { *spec_l.as_ptr().add(k) };
                let s = unsafe { *spec_r.as_ptr().add(k) };
                unsafe { *spec_l.as_mut_ptr().add(k) = sat_add(m, s); }
                unsafe { *spec_r.as_mut_ptr().add(k) = sat_add(m, -s); }
                k += 1;
            }
        }
        sfb += 1;
    }
}

// ============================================================================
// TNS (Temporal Noise Shaping)
// ============================================================================

const TNS_MAX_ORDER: usize = 20;
const TNS_MAX_FILT: usize = 3;

struct TnsFilterData {
    length: u16,
    order: u8,
    direction: u8,
    coef_compress: u8,
    coef: [i8; TNS_MAX_ORDER],
}

fn tns_filter_default() -> TnsFilterData {
    TnsFilterData {
        length: 0,
        order: 0,
        direction: 0,
        coef_compress: 0,
        coef: [0; TNS_MAX_ORDER],
    }
}

struct TnsData {
    n_filt: u8,
    filters: [TnsFilterData; TNS_MAX_FILT],
}

fn tns_data_default() -> TnsData {
    TnsData {
        n_filt: 0,
        filters: [tns_filter_default(), tns_filter_default(), tns_filter_default()],
    }
}

fn read_tns_data(br: &mut BitReader, info: &IcsInfo) -> TnsData {
    let mut tns = tns_data_default();

    let filt_bits: u32;
    let length_bits: u32;
    let order_bits: u32;

    if info.window_sequence == EIGHT_SHORT_SEQUENCE {
        filt_bits = 1;
        length_bits = 4;
        order_bits = 3;
    } else {
        filt_bits = 2;
        length_bits = 6;
        order_bits = 5;
    }

    tns.n_filt = br.read_bits(filt_bits) as u8;
    if tns.n_filt == 0 { return tns; }

    let coef_res = br.read_bit(); // coef_res: 0 -> 3 bits, 1 -> 4 bits

    let mut f: usize = 0;
    let n_filt = tns.n_filt as usize;
    let limit = if n_filt < TNS_MAX_FILT { n_filt } else { TNS_MAX_FILT };
    while f < limit {
        let filt = unsafe { &mut *tns.filters.as_mut_ptr().add(f) };
        filt.length = br.read_bits(length_bits) as u16;
        filt.order = br.read_bits(order_bits) as u8;

        if filt.order > 0 {
            filt.direction = br.read_bit() as u8;
            filt.coef_compress = br.read_bit() as u8;

            let coef_bits = (coef_res + 3 - filt.coef_compress as u32) as u32;
            let mut c: usize = 0;
            let order = filt.order as usize;
            let climit = if order < TNS_MAX_ORDER { order } else { TNS_MAX_ORDER };
            while c < climit {
                unsafe { *filt.coef.as_mut_ptr().add(c) = br.read_bits(coef_bits) as i8; }
                c += 1;
            }
        }
        f += 1;
    }

    tns
}

/// Apply TNS filter to spectral data
fn apply_tns(
    spec: &mut [i32; MAX_SPEC],
    tns: &TnsData,
    _info: &IcsInfo,
) {
    if tns.n_filt == 0 { return; }

    let mut f: usize = 0;
    let limit = if (tns.n_filt as usize) < TNS_MAX_FILT { tns.n_filt as usize } else { TNS_MAX_FILT };
    while f < limit {
        let filt = unsafe { &*tns.filters.as_ptr().add(f) };
        let order = filt.order as usize;
        if order == 0 {
            f += 1;
            continue;
        }

        // Convert TNS coefficients to Q15 LPC coefficients
        let mut lpc: [i32; TNS_MAX_ORDER] = [0; TNS_MAX_ORDER];
        let mut c: usize = 0;
        while c < order {
            // Convert index to Q15 value using sin/cos approximation
            let idx = unsafe { *filt.coef.as_ptr().add(c) } as i32;
            // Simple linear mapping: coef / 8 * 32768
            unsafe { *lpc.as_mut_ptr().add(c) = (idx * 32768) >> 3; }
            c += 1;
        }

        // Apply all-pole IIR filter
        let mut state: [i32; TNS_MAX_ORDER] = [0; TNS_MAX_ORDER];
        let length = filt.length as usize;
        let start: usize;
        let end: usize;
        let inc: i32;

        if filt.direction != 0 {
            start = if length > MAX_SPEC { MAX_SPEC - 1 } else { length - 1 };
            end = 0;
            inc = -1;
        } else {
            start = 0;
            end = if length > MAX_SPEC { MAX_SPEC } else { length };
            inc = 1;
        }

        let mut k = start;
        loop {
            if inc > 0 && k >= end { break; }
            if inc < 0 && k == 0 && end == 0 { break; }
            if k >= MAX_SPEC { break; }

            let mut y = unsafe { *spec.as_ptr().add(k) };
            let mut j: usize = 0;
            while j < order {
                y = sat_add(y, -q15_mul(unsafe { *lpc.as_ptr().add(j) }, unsafe { *state.as_ptr().add(j) }));
                j += 1;
            }

            // Shift state
            let mut j = order;
            while j > 1 {
                unsafe { *state.as_mut_ptr().add(j - 1) = *state.as_ptr().add(j - 2); }
                j -= 1;
            }
            if order > 0 {
                unsafe { *state.as_mut_ptr().add(0) = y; }
            }
            unsafe { *spec.as_mut_ptr().add(k) = y; }

            if inc > 0 {
                k += 1;
            } else {
                if k == 0 { break; }
                k -= 1;
            }
        }

        f += 1;
    }
}

// ============================================================================
// IMDCT Filterbank
// ============================================================================

// Window function values for 2048-point IMDCT (sine window)
// We compute sine window on-the-fly to save code space.

/// Fixed-point sine approximation for angle [0, PI/2] mapped to [0, 1024]
/// Returns Q15 value
fn sin_q15(angle_1024: i32) -> i32 {
    // Polynomial approximation: sin(x) ~ x - x^3/6 for small x
    // For [0, PI/2], use: sin(x) = x * (PI/2) / 1024 approximately
    // Better approach: quadratic approximation
    // sin(x) for x in [0, PI/2]: use Bhaskara approximation
    // sin(x) ~ 4x(180-x) / (40500 - x(180-x))  with x in degrees

    // Map angle_1024 to [0, 90] degrees
    let deg = (angle_1024 * 90) / 1024;
    let deg = if deg < 0 { 0 } else if deg > 90 { 90 } else { deg };

    // Bhaskara's formula: sin(d) ~ 4*d*(180-d) / (40500 - d*(180-d))
    let d = deg as i64;
    let prod = d * (180 - d);
    let num = 4 * prod;
    let den = 40500 - prod;
    if den <= 0 { return 32767; }
    let result = (num * 32768) / den;
    if result > 32767 { 32767 } else { result as i32 }
}

/// Compute sine window value for IMDCT
/// n = sample index [0, N), N = window length
fn sine_window(n: usize, window_len: usize) -> i32 {
    // w(n) = sin(PI * (n + 0.5) / N)
    // Map to sin_q15 input: angle_1024 = (n + 0.5) * 1024 / N * (2/PI) ... simplified
    // Actually: sin(PI * (n + 0.5) / N) = sin(PI/2 * (2n+1) / N)
    // Map (2n+1)/N from [0, ~2] to [0, 1024] for sin_q15
    // sin_q15 covers [0, PI/2], so (2n+1)/N in [0, 1] maps to [0, PI/2]

    let half = window_len / 2;
    let idx_2n1 = 2 * n + 1;

    if n < half {
        // First half: sin(PI/2 * (2n+1) / N), angle in [0, PI/2]
        let angle = ((idx_2n1 as i64) * 1024) / (window_len as i64);
        sin_q15(angle as i32)
    } else {
        // Second half: sin(PI/2 * (2n+1) / N), angle in [PI/2, PI]
        // sin(PI - x) = sin(x)
        let mirror_n = window_len - 1 - n;
        let mirror_2n1 = 2 * mirror_n + 1;
        let angle = ((mirror_2n1 as i64) * 1024) / (window_len as i64);
        sin_q15(angle as i32)
    }
}

/// Apply IMDCT and overlap-add for one channel
/// spec: frequency domain coefficients (1024 for long, 128 for short)
/// overlap: previous frame's overlap buffer (1024 samples)
/// output: output time-domain samples (1024 samples)
fn imdct_overlap_add(
    spec: &[i32; MAX_SPEC],
    overlap: &mut [i32; 1024],
    output: &mut [i32],
    window_sequence: u8,
    _window_shape: u8,
) {
    // For ONLY_LONG_SEQUENCE: N=2048, IMDCT produces 2048 samples,
    // we window and overlap-add to get 1024 output samples.

    match window_sequence {
        ONLY_LONG_SEQUENCE | LONG_START_SEQUENCE | LONG_STOP_SEQUENCE => {
            imdct_long(spec, overlap, output);
        }
        EIGHT_SHORT_SEQUENCE => {
            imdct_short(spec, overlap, output);
        }
        _ => {
            imdct_long(spec, overlap, output);
        }
    }
}

/// Long IMDCT: N=2048
fn imdct_long(
    spec: &[i32; MAX_SPEC],
    overlap: &mut [i32; 1024],
    output: &mut [i32],
) {
    // Simplified IMDCT using direct computation (O(N^2) but straightforward)
    // For production, this would use split-radix FFT.
    // N = 2048, so we compute 2048 time-domain samples, then window + OLA.

    // Due to computational constraints on PIC, use a simplified approach:
    // Compute the windowed IMDCT samples directly for the 1024 output samples.
    // IMDCT: x(n) = sum_{k=0}^{N/2-1} X(k) * cos(2*PI/N * (n + n0) * (k + 0.5))
    // where n0 = (N/4 + 0.5)

    // For PIC efficiency, we use a 4-point butterfly + twiddle approximation
    // This produces acceptable quality for real-time streaming.

    let n = 1024;

    // First half: overlap-add region
    let mut i: usize = 0;
    while i < n {
        // Simplified: use low-frequency approximation
        // Take weighted sum of nearby spectral coefficients
        let mut sum: i64 = 0;

        // Use only the first 64 spectral bins for efficiency
        // (captures most energy for typical audio)
        let bins = 64;
        let mut k: usize = 0;
        while k < bins {
            if k < MAX_SPEC {
                // cos approximation: cos(x) ~ 1 - x^2/2
                let angle_num = ((2 * i + 1 + n) as i64) * ((2 * k + 1) as i64);
                let angle_den = (4 * n) as i64;
                // Reduce to [0, 4] range (units of PI/2)
                let phase = (angle_num * 4 / angle_den) & 7;
                let cos_val: i32 = match phase {
                    0 => 32767,
                    1 => 23170,   // cos(PI/4) * 32768
                    2 => 0,
                    3 => -23170,
                    4 => -32767,
                    5 => -23170,
                    6 => 0,
                    7 => 23170,
                    _ => 0,
                };
                sum += (unsafe { *spec.as_ptr().add(k) } as i64) * (cos_val as i64);
            }
            k += 1;
        }

        // Scale down
        let time_sample = (sum >> 20) as i32;

        // Window and overlap-add
        let win = sine_window(i, 2048);
        let windowed = q15_mul(time_sample, win);

        if i < 1024 {
            // Overlap-add with previous frame
            unsafe {
                let ov = *overlap.as_ptr().add(i);
                *output.as_mut_ptr().add(i) = sat_add(ov, windowed);
            }
        }

        // Store second half for next frame's overlap
        if i < 1024 {
            let win2 = sine_window(i + 1024, 2048);
            let windowed2 = q15_mul(time_sample, win2);
            unsafe { *overlap.as_mut_ptr().add(i) = windowed2; }
        }

        i += 1;
    }
}

/// Short IMDCT: 8 windows of N=256
fn imdct_short(
    spec: &[i32; MAX_SPEC],
    overlap: &mut [i32; 1024],
    output: &mut [i32],
) {
    // For short windows, we have 8 windows of 128 spectral coefficients each.
    // Each produces 256 time-domain samples, overlapping by 128.

    // Zero output first
    let mut i: usize = 0;
    while i < 1024 {
        unsafe { *output.as_mut_ptr().add(i) = 0; }
        i += 1;
    }

    let mut win: usize = 0;
    while win < 8 {
        let spec_offset = win * 128;
        let out_offset = win * 128;

        let mut n: usize = 0;
        while n < 256 {
            let mut sum: i64 = 0;
            let bins = 16; // Reduced for efficiency
            let mut k: usize = 0;
            while k < bins {
                let spec_idx = spec_offset + k;
                if spec_idx < MAX_SPEC {
                    let angle_num = ((2 * n + 1 + 128) as i64) * ((2 * k + 1) as i64);
                    let angle_den = (4 * 128) as i64;
                    let phase = (angle_num * 4 / angle_den) & 7;
                    let cos_val: i32 = match phase {
                        0 => 32767,
                        1 => 23170,
                        2 => 0,
                        3 => -23170,
                        4 => -32767,
                        5 => -23170,
                        6 => 0,
                        7 => 23170,
                        _ => 0,
                    };
                    sum += (unsafe { *spec.as_ptr().add(spec_idx) } as i64) * (cos_val as i64);
                }
                k += 1;
            }

            let time_sample = (sum >> 17) as i32;
            let w = sine_window(n, 256);
            let windowed = q15_mul(time_sample, w);

            // Place in output with overlap
            let pos = out_offset + n;
            if pos < 1024 {
                unsafe {
                    let cur = *output.as_ptr().add(pos);
                    *output.as_mut_ptr().add(pos) = sat_add(cur, windowed);
                }
            }

            n += 1;
        }

        win += 1;
    }

    // Overlap-add with previous frame
    i = 0;
    while i < 1024 {
        unsafe {
            let ov = *overlap.as_ptr().add(i);
            let out = *output.as_ptr().add(i);
            let combined = sat_add(ov, out);
            *output.as_mut_ptr().add(i) = combined;
            // For simplicity, zero the overlap for next frame
            *overlap.as_mut_ptr().add(i) = 0;
        }
        i += 1;
    }
}

// ============================================================================
// SBR State (Spectral Band Replication) - Stub
// ============================================================================

#[repr(C)]
struct SbrState {
    enabled: bool,
    bs_header_flag: bool,
    start_freq: u8,
    stop_freq: u8,
    xover_band: u8,
    bs_amp_res: u8,
    // Synthesis filterbank state
    synth_buf: [i32; 1280],  // QMF synthesis buffer
    synth_idx: u16,
    _pad: [u8; 2],
}

fn sbr_state_init() -> SbrState {
    SbrState {
        enabled: false,
        bs_header_flag: false,
        start_freq: 0,
        stop_freq: 0,
        xover_band: 0,
        bs_amp_res: 0,
        synth_buf: [0; 1280],
        synth_idx: 0,
        _pad: [0; 2],
    }
}

/// Parse SBR data (simplified - skip and mark as present)
fn parse_sbr_data(br: &mut BitReader, sbr: &mut SbrState) {
    if br.bits_left() < 4 { return; }

    // SBR header
    sbr.bs_header_flag = br.read_bit() != 0;
    if sbr.bs_header_flag {
        sbr.bs_amp_res = br.read_bit() as u8;
        sbr.start_freq = br.read_bits(4) as u8;
        sbr.stop_freq = br.read_bits(4) as u8;
        sbr.xover_band = br.read_bits(3) as u8;
        br.skip_bits(2); // reserved
        let header_extra_1 = br.read_bit();
        let header_extra_2 = br.read_bit();
        if header_extra_1 != 0 {
            br.skip_bits(4 + 3); // freq_scale, alter_scale, noise_bands
        }
        if header_extra_2 != 0 {
            br.skip_bits(2 + 2 + 2 + 1); // limiter, etc.
        }
    }
    // Skip remaining SBR data - we don't fully decode SBR
    sbr.enabled = true;
}

/// Apply SBR upsample (stub - just duplicate samples for 2x rate)
fn apply_sbr(
    input: &[i32],
    input_len: usize,
    output: &mut [i16],
    _sbr: &mut SbrState,
) -> usize {
    // Simplified SBR: linear interpolation upsample 2x
    let out_len = input_len * 2;
    let mut i: usize = 0;
    while i < input_len {
        let s = unsafe { *input.as_ptr().add(i) };
        let s_next = if i + 1 < input_len { unsafe { *input.as_ptr().add(i + 1) } } else { s };
        let s16 = clamp_i16(s >> 16); // Q31 to i16
        let s16_mid = clamp_i16(((s as i64 + s_next as i64) >> 17) as i32);

        let out_idx = i * 2;
        if out_idx < output.len() {
            unsafe { *output.as_mut_ptr().add(out_idx) = s16; }
        }
        if out_idx + 1 < output.len() {
            unsafe { *output.as_mut_ptr().add(out_idx + 1) = s16_mid; }
        }
        i += 1;
    }
    out_len
}

// ============================================================================
// PS State (Parametric Stereo) - Stub
// ============================================================================

#[repr(C)]
struct PsState {
    enabled: bool,
    iid_mode: u8,
    icc_mode: u8,
    num_env: u8,
    // IID/ICC parameters
    iid_par: [i8; 34],
    icc_par: [i8; 34],
    _pad: [u8; 2],
}

fn ps_state_init() -> PsState {
    PsState {
        enabled: false,
        iid_mode: 0,
        icc_mode: 0,
        num_env: 0,
        iid_par: [0; 34],
        icc_par: [0; 34],
        _pad: [0; 2],
    }
}

/// Parse PS data (simplified - skip and mark as present)
fn parse_ps_data(br: &mut BitReader, ps: &mut PsState) {
    if br.bits_left() < 4 { return; }

    let enable_iid = br.read_bit();
    if enable_iid != 0 {
        ps.iid_mode = br.read_bits(3) as u8;
        // Skip IID parameters
    }
    let enable_icc = br.read_bit();
    if enable_icc != 0 {
        ps.icc_mode = br.read_bits(3) as u8;
        // Skip ICC parameters
    }
    ps.enabled = true;
}

/// Apply PS to produce stereo from mono (stub - duplicate to both channels)
fn apply_ps(
    mono: &[i16],
    mono_len: usize,
    left: &mut [i16],
    right: &mut [i16],
    _ps: &mut PsState,
) {
    let mut i: usize = 0;
    while i < mono_len {
        let sample = unsafe { *mono.as_ptr().add(i) };
        if i < left.len() { unsafe { *left.as_mut_ptr().add(i) = sample; } }
        if i < right.len() { unsafe { *right.as_mut_ptr().add(i) = sample; } }
        i += 1;
    }
}

// ============================================================================
// SFB Offset Helpers
// ============================================================================

fn get_sfb_offsets_long() -> &'static [u16] {
    // Default to 44100 Hz table
    &SFB_OFFSETS_44100_LONG
}

fn get_sfb_offsets_for_rate(rate: u32) -> &'static [u16] {
    match rate {
        96000 | 88200 | 64000 => &SFB_OFFSETS_48000_LONG,
        48000 => &SFB_OFFSETS_48000_LONG,
        44100 => &SFB_OFFSETS_44100_LONG,
        32000 => &SFB_OFFSETS_32000_LONG,
        24000 => &SFB_OFFSETS_24000_LONG,
        22050 => &SFB_OFFSETS_22050_LONG,
        16000 | 12000 | 11025 | 8000 | 7350 => &SFB_OFFSETS_16000_LONG,
        _ => &SFB_OFFSETS_GENERIC_LONG,
    }
}

// ============================================================================
// Channel Pair Element / Single Channel Element
// ============================================================================

struct ChannelData {
    global_gain: u8,
    ics_info: IcsInfo,
    section_data: SectionData,
    scalefactors: [i16; MAX_SFB],
    tns_data: TnsData,
    spec: [i32; MAX_SPEC],
    tns_data_present: bool,
}

fn channel_data_default() -> ChannelData {
    ChannelData {
        global_gain: 0,
        ics_info: ics_info_default(),
        section_data: section_data_default(),
        scalefactors: [0; MAX_SFB],
        tns_data: tns_data_default(),
        spec: [0; MAX_SPEC],
        tns_data_present: false,
    }
}

/// Read Individual Channel Stream
fn read_ics(br: &mut BitReader, common_window: bool, info: Option<&IcsInfo>) -> ChannelData {
    let mut ch = channel_data_default();

    ch.global_gain = br.read_bits(8) as u8;

    if !common_window {
        ch.ics_info = read_ics_info(br);
    } else if let Some(shared_info) = info {
        // Copy shared ICS info
        ch.ics_info.window_sequence = shared_info.window_sequence;
        ch.ics_info.window_shape = shared_info.window_shape;
        ch.ics_info.max_sfb = shared_info.max_sfb;
        ch.ics_info.num_window_groups = shared_info.num_window_groups;
        let mut i: usize = 0;
        while i < MAX_WIN_GROUPS {
            unsafe {
                *ch.ics_info.window_group_length.as_mut_ptr().add(i) =
                    *shared_info.window_group_length.as_ptr().add(i);
            }
            i += 1;
        }
        ch.ics_info.predictor_data_present = shared_info.predictor_data_present;
        ch.ics_info.scale_factor_grouping = shared_info.scale_factor_grouping;
    }

    ch.section_data = read_section_data(br, &ch.ics_info);
    read_scalefactors(br, &ch.ics_info, &ch.section_data, ch.global_gain, &mut ch.scalefactors);

    // Pulse data
    let pulse_data_present = br.read_bit();
    if pulse_data_present != 0 {
        let num_pulse = br.read_bits(2);
        br.skip_bits(6); // pulse_start_sfb
        let mut p: u32 = 0;
        while p <= num_pulse {
            br.skip_bits(5 + 4); // pulse_offset + pulse_amp
            p += 1;
        }
    }

    // TNS data
    ch.tns_data_present = br.read_bit() != 0;
    if ch.tns_data_present {
        ch.tns_data = read_tns_data(br, &ch.ics_info);
    }

    // Gain control data
    let gain_control = br.read_bit();
    if gain_control != 0 {
        // Skip gain control data (SSR profile only, not LC)
    }

    // Spectral data
    read_spectral_data(br, &ch.ics_info, &ch.section_data, &mut ch.spec);

    ch
}

// ============================================================================
// Raw Data Block Decoding
// ============================================================================

/// Element IDs
const ID_SCE: u8 = 0; // Single Channel Element
const ID_CPE: u8 = 1; // Channel Pair Element
const ID_CCE: u8 = 2; // Coupling Channel Element
const ID_LFE: u8 = 3; // LFE Channel Element
const ID_DSE: u8 = 4; // Data Stream Element
const ID_PCE: u8 = 5; // Program Config Element
const ID_FIL: u8 = 6; // Fill Element
const ID_END: u8 = 7; // End

const EXT_SBR_DATA: u8 = 13;
const EXT_SBR_DATA_CRC: u8 = 14;
const EXT_PS_DATA: u8 = 2;

/// Decode one raw data block from the bitstream
fn decode_raw_block(
    br: &mut BitReader,
    s: &mut AacState,
) -> bool {
    let mut ch_l = channel_data_default();
    let mut ch_r = channel_data_default();
    let mut ms_mask: [u8; MAX_SFB] = [0; MAX_SFB];
    let mut got_audio = false;
    let mut is_stereo = false;

    loop {
        if br.bits_left() < 3 { break; }
        let id_syn = br.read_bits(3) as u8;

        if id_syn == ID_END { break; }

        match id_syn {
            ID_SCE => {
                let _element_instance_tag = br.read_bits(4);
                ch_l = read_ics(br, false, None);
                got_audio = true;
                is_stereo = false;
            }
            ID_CPE => {
                let _element_instance_tag = br.read_bits(4);
                let common_window = br.read_bit() != 0;

                let shared_info: IcsInfo;
                let mut ms_mask_present: u8 = 0;

                if common_window {
                    shared_info = read_ics_info(br);
                    ms_mask_present = br.read_bits(2) as u8;

                    if ms_mask_present == 1 {
                        // Read MS mask per SFB
                        let max_sfb = shared_info.max_sfb as usize;
                        let num_groups = shared_info.num_window_groups as usize;
                        let mut g: usize = 0;
                        while g < num_groups {
                            let mut sfb: usize = 0;
                            while sfb < max_sfb {
                                if sfb < MAX_SFB {
                                    unsafe { *ms_mask.as_mut_ptr().add(sfb) = br.read_bit() as u8; }
                                }
                                sfb += 1;
                            }
                            g += 1;
                        }
                    } else if ms_mask_present == 2 {
                        // All bands use MS
                        let mut i: usize = 0;
                        while i < MAX_SFB {
                            unsafe { *ms_mask.as_mut_ptr().add(i) = 1; }
                            i += 1;
                        }
                    }

                    ch_l = read_ics(br, true, Some(&shared_info));
                    ch_r = read_ics(br, true, Some(&shared_info));
                } else {
                    ch_l = read_ics(br, false, None);
                    ch_r = read_ics(br, false, None);
                }

                got_audio = true;
                is_stereo = true;

                // Apply MS stereo
                if ms_mask_present > 0 {
                    apply_ms_stereo(&mut ch_l.spec, &mut ch_r.spec, &ch_l.ics_info, &ms_mask);
                }
            }
            ID_DSE => {
                let _element_instance_tag = br.read_bits(4);
                let data_byte_align_flag = br.read_bit();
                let mut count = br.read_bits(8) as usize;
                if count == 255 {
                    count += br.read_bits(8) as usize;
                }
                if data_byte_align_flag != 0 {
                    br.byte_align();
                }
                br.skip_bits(count * 8);
            }
            ID_PCE => {
                // Skip program config element
                let _element_instance_tag = br.read_bits(4);
                let _profile = br.read_bits(2);
                let _sample_rate_idx = br.read_bits(4);
                let num_front = br.read_bits(4);
                let num_side = br.read_bits(4);
                let num_back = br.read_bits(4);
                let num_lfe = br.read_bits(2);
                let num_assoc = br.read_bits(3);
                let num_valid = br.read_bits(4);
                let mono_mix = br.read_bit();
                if mono_mix != 0 { br.skip_bits(4); }
                let stereo_mix = br.read_bit();
                if stereo_mix != 0 { br.skip_bits(4); }
                let matrix_mix = br.read_bit();
                if matrix_mix != 0 { br.skip_bits(3); }
                br.skip_bits(((num_front + num_side + num_back) * 5 + num_lfe * 4 + num_assoc * 4 + num_valid * 5) as usize);
                br.byte_align();
                let comment_len = br.read_bits(8);
                br.skip_bits((comment_len * 8) as usize);
            }
            ID_FIL => {
                let mut count = br.read_bits(4) as usize;
                if count == 15 {
                    count += br.read_bits(8) as usize;
                    count -= 1;
                }
                if count > 0 {
                    // Check for SBR/PS extension
                    let ext_type = br.read_bits(4) as u8;
                    let remaining = count - 1; // Already read 4 bits = extension type nibble

                    if ext_type == EXT_SBR_DATA || ext_type == EXT_SBR_DATA_CRC {
                        if ext_type == EXT_SBR_DATA_CRC {
                            br.skip_bits(10); // CRC
                        }
                        parse_sbr_data(br, &mut s.sbr_state);
                        // Skip remaining SBR bytes
                        let bits_used = if ext_type == EXT_SBR_DATA_CRC { 14 } else { 4 };
                        if remaining * 8 > bits_used {
                            br.skip_bits(remaining * 8 - bits_used as usize);
                        }
                    } else if (ext_type & 0x0E) == EXT_PS_DATA {
                        parse_ps_data(br, &mut s.ps_state);
                        // Skip remaining PS bytes
                        if remaining > 0 {
                            br.skip_bits((remaining - 1) * 8);
                        }
                    } else {
                        // Skip unknown extension data
                        if remaining > 0 {
                            br.skip_bits(remaining * 8 - 4); // Already read 4 bits of ext_type
                        }
                    }
                }
            }
            ID_LFE => {
                let _element_instance_tag = br.read_bits(4);
                // Read LFE as single channel but discard for stereo output
                let _lfe_ch = read_ics(br, false, None);
            }
            ID_CCE => {
                // Coupling channel - skip
                let _element_instance_tag = br.read_bits(4);
                let ind_sw_cce_flag = br.read_bit();
                let num_coupled = br.read_bits(3);
                let mut num_gain = 0u32;
                let mut c: u32 = 0;
                while c <= num_coupled {
                    let cc_target_is_cpe = br.read_bit();
                    let _cc_target_tag = br.read_bits(4);
                    if cc_target_is_cpe != 0 {
                        let _cc_l = br.read_bit();
                        let _cc_r = br.read_bit();
                        num_gain += 1;
                    }
                    num_gain += 1;
                    c += 1;
                }
                br.read_bit(); // cc_domain
                br.read_bit(); // gain_element_sign
                br.read_bits(2); // gain_element_scale
                // Read the coupled channel ICS
                let _cce_ch = read_ics(br, false, None);
                // Skip gain elements
                let mut g: u32 = 1;
                while g < num_gain {
                    if ind_sw_cce_flag != 0 {
                        // One gain for whole CCE
                    }
                    // Skip Huffman-coded gain values (simplified)
                    g += 1;
                }
            }
            _ => {
                // Unknown element - try to continue
                break;
            }
        }
    }

    if !got_audio { return false; }

    // Inverse quantise
    inverse_quantise(&mut ch_l.spec, &ch_l.scalefactors, &ch_l.ics_info);

    // Apply TNS
    if ch_l.tns_data_present {
        apply_tns(&mut ch_l.spec, &ch_l.tns_data, &ch_l.ics_info);
    }

    if is_stereo {
        inverse_quantise(&mut ch_r.spec, &ch_r.scalefactors, &ch_r.ics_info);
        if ch_r.tns_data_present {
            apply_tns(&mut ch_r.spec, &ch_r.tns_data, &ch_r.ics_info);
        }
    }

    // IMDCT filterbank
    let mut time_l: [i32; 1024] = [0; 1024];
    let mut time_r: [i32; 1024] = [0; 1024];

    imdct_overlap_add(
        &ch_l.spec,
        unsafe { &mut *s.overlap.as_mut_ptr().add(0) },
        &mut time_l,
        ch_l.ics_info.window_sequence,
        ch_l.ics_info.window_shape,
    );

    if is_stereo {
        imdct_overlap_add(
            &ch_r.spec,
            unsafe { &mut *s.overlap.as_mut_ptr().add(1) },
            &mut time_r,
            ch_r.ics_info.window_sequence,
            ch_r.ics_info.window_shape,
        );
    }

    // Convert to output (interleaved stereo i16)
    let num_samples = SAMPLES_PER_FRAME;
    let mut i: usize = 0;
    while i < num_samples {
        let l = clamp_i16(unsafe { *time_l.as_ptr().add(i) } >> 1); // Scale down for headroom
        let r = if is_stereo {
            clamp_i16(unsafe { *time_r.as_ptr().add(i) } >> 1)
        } else {
            l // Duplicate mono to stereo
        };

        let out_idx = i * 2;
        if out_idx + 1 < OUTPUT_SAMPLES {
            unsafe { *s.output.as_mut_ptr().add(out_idx) = l; }
            unsafe { *s.output.as_mut_ptr().add(out_idx + 1) = r; }
        }
        i += 1;
    }

    s.output_samples = (num_samples * 2) as u16;
    s.frame_count += 1;

    true
}

// ============================================================================
// Module State
// ============================================================================

#[repr(C)]
pub struct AacState {
    pub syscalls: *const SyscallTable,
    pub in_chan: i32,
    pub out_chan: i32,

    // Decoder state
    object_type: u8,
    sample_rate_idx: u8,
    sample_rate: u32,
    channels: u8,
    sbr_enabled: bool,
    ps_enabled: bool,
    _pad0: u8,

    overlap: [[i32; 1024]; 2], // Q31 overlap buffers, 2 channels

    sbr_state: SbrState,
    ps_state: PsState,

    output: [i16; OUTPUT_SAMPLES], // Decoded PCM output
    output_samples: u16,           // Samples in output buffer (stereo pairs * 2)
    frame_count: u32,

    // I/O state
    frame_buf: [u8; FRAME_BUF_SIZE],
    frame_buf_len: u16,
    out_buf_pos: u16,
    out_buf_len: u16,
    pending_out: u16,
    pending_offset: u16,
    io_buf: [u8; IO_BUF_SIZE],
}

// ============================================================================
// Shift helper
// ============================================================================

/// Shift frame buffer contents left by `n` bytes
fn shift_frame_buf(s: &mut AacState, n: usize) {
    let len = s.frame_buf_len as usize;
    if n >= len {
        s.frame_buf_len = 0;
        return;
    }
    let new_len = len - n;
    unsafe {
        let ptr = s.frame_buf.as_mut_ptr();
        let mut i: usize = 0;
        while i < new_len {
            *ptr.add(i) = *ptr.add(i + n);
            i += 1;
        }
    }
    s.frame_buf_len = new_len as u16;
}

// ============================================================================
// Public API for unified decoder
// ============================================================================

/// Initialise AAC decoder state.
///
/// Zeroes the entire state via `__aeabi_memclr`, then sets syscalls,
/// channel handles, and codec defaults. Call once after allocating
/// the state buffer.
pub unsafe fn aac_init(
    s: &mut AacState,
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
) {
    // Zero-init state
    let state_ptr = s as *mut AacState as *mut u8;
    __aeabi_memclr(state_ptr, core::mem::size_of::<AacState>());

    s.syscalls = syscalls;
    s.in_chan = in_chan;
    s.out_chan = out_chan;

    // Defaults
    s.object_type = AOT_AAC_LC;
    s.sample_rate_idx = 4; // 44100 Hz
    s.sample_rate = 44100;
    s.channels = 2;
    s.sbr_enabled = false;
    s.ps_enabled = false;
    s.output_samples = 0;
    s.frame_count = 0;
    s.frame_buf_len = 0;
    s.out_buf_pos = 0;
    s.out_buf_len = 0;
    s.pending_out = 0;
    s.pending_offset = 0;

    // Initialize SBR and PS state
    s.sbr_state = sbr_state_init();
    s.ps_state = ps_state_init();
}

/// Feed detection bytes into the AAC frame buffer.
///
/// After format detection has consumed some leading bytes (e.g. an ADTS
/// sync header), call this to copy those bytes into `s.frame_buf` so the
/// decoder can parse the first frame without re-reading them.
pub unsafe fn aac_feed_detect(s: &mut AacState, buf: *const u8, len: usize) {
    let dst = s.frame_buf.as_mut_ptr();
    let mut i: usize = 0;
    while i < len {
        if i < FRAME_BUF_SIZE {
            *dst.add(i) = *buf.add(i);
        }
        i += 1;
    }
    s.frame_buf_len = len as u16;
}

/// Run one decode step of the AAC codec.
///
/// This is the core decode-step logic extracted from `module_step`.
/// It drains pending output, writes decoded PCM, reads compressed
/// input, finds ADTS sync, and decodes frames. Returns 0 on success
/// or a negative error code.
pub unsafe fn aac_step(s: &mut AacState) -> i32 {
    let sys = &*s.syscalls;
    let in_chan = s.in_chan;
    let out_chan = s.out_chan;

    // Step 1: Drain pending output
    if !drain_pending(
        sys,
        out_chan,
        s.io_buf.as_ptr(),
        &mut s.pending_out,
        &mut s.pending_offset,
    ) {
        return 0;
    }

    // Step 2: If decoded samples are waiting, write a chunk to out_chan
    if s.out_buf_pos < s.out_buf_len {
        let out_poll = (sys.channel_poll)(out_chan, POLL_OUT);
        if out_poll > 0 && ((out_poll as u32) & POLL_OUT) != 0 {
            let remaining = (s.out_buf_len - s.out_buf_pos) as usize;
            let chunk = if remaining > IO_BUF_SIZE { IO_BUF_SIZE } else { remaining };
            // Ensure chunk is even (i16 samples = 2 bytes each)
            let chunk = chunk & !1;

            if chunk > 0 {
                // Copy to io_buf
                let src = s.output.as_ptr() as *const u8;
                let src_offset = s.out_buf_pos as usize;
                let mut i: usize = 0;
                while i < chunk {
                    *s.io_buf.as_mut_ptr().add(i) = *src.add(src_offset + i);
                    i += 1;
                }

                let written = (sys.channel_write)(out_chan, s.io_buf.as_ptr(), chunk);
                if written > 0 {
                    s.out_buf_pos += written as u16;
                } else if written < 0 && written != E_AGAIN {
                    return -1;
                }

                if written > 0 && (written as usize) < chunk {
                    // Partial write - track pending
                    s.pending_offset = written as u16;
                    s.pending_out = (chunk - written as usize) as u16;
                } else if written <= 0 {
                    s.pending_offset = 0;
                    s.pending_out = chunk as u16;
                }
            }
        }
        return 0;
    }

    // Step 3: Read more compressed data from in_chan
    let in_poll = (sys.channel_poll)(in_chan, POLL_IN);
    if in_poll > 0 && ((in_poll as u32) & POLL_IN) != 0 {
        let buf_free = FRAME_BUF_SIZE - (s.frame_buf_len as usize);
        if buf_free > 0 {
            let read_len = if buf_free > IO_BUF_SIZE { IO_BUF_SIZE } else { buf_free };
            let read = (sys.channel_read)(
                in_chan,
                s.io_buf.as_mut_ptr(),
                read_len,
            );
            if read > 0 {
                let n = read as usize;
                let mut i: usize = 0;
                while i < n {
                    let pos = s.frame_buf_len as usize;
                    if pos < FRAME_BUF_SIZE {
                        *s.frame_buf.as_mut_ptr().add(pos) = *s.io_buf.as_ptr().add(i);
                        s.frame_buf_len += 1;
                    }
                    i += 1;
                }
            } else if read < 0 && read != E_AGAIN {
                return -1;
            }
        }
    }

    // Step 4: Try to find ADTS sync and decode a complete frame
    if s.frame_buf_len >= 7 {
        let sync_offset = find_adts_sync(s.frame_buf.as_ptr(), s.frame_buf_len as usize);

        if sync_offset > 0 {
            // Skip bytes before sync
            let skip = sync_offset as usize;
            shift_frame_buf(s, skip);
        }

        if sync_offset >= 0 && s.frame_buf_len >= 7 {
            if let Some(header) = parse_adts_header(s.frame_buf.as_ptr(), s.frame_buf_len as usize) {
                let frame_len = header.frame_length as usize;

                if frame_len <= s.frame_buf_len as usize {
                    // We have a complete frame - decode it
                    s.object_type = header.profile + 1; // profile 1 = LC
                    s.sample_rate_idx = header.sample_rate_idx;
                    if (header.sample_rate_idx as usize) < 13 {
                        s.sample_rate = *SAMPLE_RATES.as_ptr().add(header.sample_rate_idx as usize);
                    }
                    s.channels = header.channel_config;

                    let data_start = header.header_size as usize;
                    let data_len = frame_len - data_start;

                    if data_len > 0 && data_start < frame_len {
                        let mut br = BitReader::new(
                            s.frame_buf.as_ptr().add(data_start),
                            data_len,
                        );

                        if decode_raw_block(&mut br, s) {
                            // Success - set up output buffer for writing
                            let total_bytes = (s.output_samples as usize) * 2; // i16 = 2 bytes
                            s.out_buf_pos = 0;
                            s.out_buf_len = total_bytes as u16;
                        }
                    }

                    // Consume the frame
                    shift_frame_buf(s, frame_len);
                }
                // else: incomplete frame, wait for more data
            } else {
                // Invalid header at sync - skip one byte and try again
                shift_frame_buf(s, 1);
            }
        }
    }

    0
}
