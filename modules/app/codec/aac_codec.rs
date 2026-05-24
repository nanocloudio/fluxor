// AAC-LC codec kernel for unified decoder.
//
// f32 port of faad2's AAC-LC decode path. Standalone replica at
// /tmp/aac_probe/src/main.rs matches faad PCM to correlation 0.9911 on
// cmajor.aac; this file is the no_std build of the same decoder.
//
// Pipeline (mirrors faad2 libfaad/{syntax,specrec,filtbank,…}.c):
//   ADTS sync → raw_data_block → SCE/CPE elements → ICS info →
//     section_data → scale_factor_data (HCB_SF) → spectral_data
//     (HCB1..HCB11) → quant_to_spec (x^(4/3) lookup + 2^(0.25·(sf−25))
//     gain, deinterleaving for short blocks) → ms_decode (per-(g,sfb)
//     L+R / L-R) → ifilter_bank (IMDCT + sine/KBD window + 50%
//     overlap-add, dispatched by window_sequence) → f32 → i16 PCM.
//
// Not yet ported: TNS inverse filter, PNS noise substitution,
// intensity-stereo replication, pulse coding. Their bitstream is read
// and skipped (so alignment stays correct).
//
// Math: all trig / power functions are pure-Rust polynomial
// approximations (no_std, no libm). Pre-computed IQ_TABLE and sine
// windows are built at codec init in static mut state.

#![allow(dead_code, non_upper_case_globals, reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it / matches external constant naming")]

use super::abi::SyscallTable;
use super::{POLL_IN, POLL_OUT, E_AGAIN, drain_pending, __aeabi_memclr, dev_log};

mod hcb {
    include!("aac_hcb_tables.rs");
}
mod kbd_t {
    include!("aac_kbd_tables.rs");
}
mod iq_t {
    include!("aac_iq_table.rs");
}
mod sine_t {
    include!("aac_sine_tables.rs");
}
mod pow_t {
    include!("aac_pow_tables.rs");
}
mod cos_t {
    include!("aac_cos_lut.rs");
}
use self::hcb::*;
use self::kbd_t::{KBD_LONG_1024, KBD_SHORT_128};
use self::iq_t::IQ_TABLE_CONST;
use self::sine_t::{SINE_LONG_CONST, SINE_SHORT_CONST};
use self::pow_t::{POW2SF_TAB_CONST, POW2_FRAC_CONST};
use self::cos_t::{COS_LUT, COS_LUT_N};

// ============================================================================
// no_std math (polynomial approximations)
// ============================================================================

const PI_F32: f32 = 3.141592653589793_f32;
const TWO_PI: f32 = PI_F32 * 2.0;
const PI_OVER_2: f32 = PI_F32 * 0.5;

/// Reduce x to [-π, π].
#[inline]
fn reduce_two_pi(x: f32) -> f32 {
    // floor(x / 2π)
    let n = (x / TWO_PI) as i32;
    let mut r = x - (n as f32) * TWO_PI;
    if r > PI_F32 { r -= TWO_PI; }
    else if r < -PI_F32 { r += TWO_PI; }
    r
}

/// cos(x) via 16384-entry LUT + linear interp.
///
/// CRITICAL: must range-reduce x BEFORE scaling to the LUT index. f32
/// has ~7 decimal digits of precision; IMDCT arguments reach ~6440
/// rad (cmajor.aac long-window IMDCT), and 6440 × 16384/(2π) ≈
/// 1.68e7 — above f32's continuous-integer range. The fractional part
/// of `idx_f` is then quantised to 1.0 (lost), making the interp
/// step a no-op and corrupting the IMDCT output.
///
/// Cody-Waite f32 reduction: split 2π = TWO_PI_HI + TWO_PI_LO with
/// HI exactly representable in f32 (201/32) and LO carrying the tail.
/// Compute `r = (x − q·HI) − q·LO` so the cancellation in the first
/// subtraction stays within f32 precision and the LO correction
/// recovers what the truncated HI lost. Over |x| ≤ ~8 k rad (the
/// IMDCT input range) this yields |r| precision ≲ 6e-7 — ~600×
/// smaller than the LUT granularity Δ = 2π/16384 ≈ 3.8e-4. The whole
/// PIC-module tree is f32-only by convention, and this function
/// honours it on every target (rp2040 / rp2350 / bcm2712 / wasm).
fn cosf(x: f32) -> f32 {
    // 2π ≈ TWO_PI_HI + TWO_PI_LO; HI is exact in f32, LO carries the
    // tail. `q` is the truncated quotient (sufficient for x ≥ 0,
    // which is the only regime imdct_direct exercises).
    const TWO_PI_HI: f32 = 6.28125;     // 201/32 — exact in f32
    const TWO_PI_LO: f32 = 0.001935307; // 2π - TWO_PI_HI
    let q = (x / TWO_PI) as i32;        // floor for x ≥ 0
    let qf = q as f32;
    let mut r = (x - qf * TWO_PI_HI) - qf * TWO_PI_LO;
    if r < 0.0 { r += TWO_PI; }
    let scale = COS_LUT_N as f32 / TWO_PI;
    let idx_f = r * scale; // idx_f ∈ [0, N)
    let mut idx_i = idx_f as i32;
    if (idx_i as f32) > idx_f { idx_i -= 1; }
    let frac = idx_f - (idx_i as f32);
    let i0 = (idx_i as usize) % COS_LUT_N;
    let i1 = if i0 + 1 < COS_LUT_N { i0 + 1 } else { 0 };
    COS_LUT[i0] + frac * (COS_LUT[i1] - COS_LUT[i0])
}

/// sin(x) = cos(π/2 - x).
fn sinf(x: f32) -> f32 { cosf(PI_OVER_2 - x) }

/// cube root by Halley's iteration. Used to build the iq_table without
/// needing pow(x, 4/3) directly.
fn cbrtf(x: f32) -> f32 {
    if x == 0.0 { return 0.0; }
    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let a = if x < 0.0 { -x } else { x };
    // Initial guess from float exponent: y₀ ≈ a^(1/3) via bit-fiddle.
    // Simpler & branch-free: Newton from y=a/3+0.5.
    let mut y = a * 0.333333_f32 + 0.5;
    // 6 Halley iterations (~1e-7 precision).
    for _ in 0..6 {
        let y2 = y * y;
        let y3 = y2 * y;
        y = y - (y3 - a) / (3.0 * y2);
    }
    sign * y
}

/// x^(4/3) — used by iq_table init only.
#[inline]
fn pow_4_over_3(x: f32) -> f32 {
    let c = cbrtf(x);
    c * c * c * c
}

/// 2^x via Taylor on [-0.5, 0.5] · integer power-of-two for the rest.
fn exp2f(x: f32) -> f32 {
    // Split x into integer + frac.
    let xi = if x >= 0.0 { x as i32 } else { (x as i32) - 1 };
    let xf = x - xi as f32;
    // xf is in [0, 1) — reduce to [-0.5, 0.5).
    let (xf, mul) = if xf >= 0.5 { (xf - 1.0, 2.0_f32) } else { (xf, 1.0) };
    // 2^xf ≈ 1 + xf·ln2 + xf²·ln2²/2 + xf³·ln2³/6 + xf⁴·ln2⁴/24
    let ln2 = 0.6931472_f32;
    let a1 = ln2;
    let a2 = ln2 * ln2 * 0.5;
    let a3 = a2 * ln2 * (1.0 / 3.0);
    let a4 = a3 * ln2 * 0.25;
    let frac_part = 1.0 + xf * (a1 + xf * (a2 + xf * (a3 + xf * a4)));
    // Multiply by 2^xi via bit fiddling.
    let pow_int = if xi >= -126 && xi <= 127 {
        f32::from_bits(((xi + 127) as u32) << 23)
    } else if xi > 127 { f32::INFINITY }
    else { 0.0 };
    pow_int * mul * frac_part
}

// ============================================================================
// Constants
// ============================================================================

const SAMPLES_PER_FRAME: usize = 1024;
const MAX_CHANNELS: usize = 2;
const MAX_SFB: usize = 51;
const MAX_WIN_GROUPS: usize = 8;
const MAX_SECTIONS: usize = 120;
const FRAME_BUF_SIZE: usize = 8192;
/// Bytes per `channel_write` to `out_chan`. Sized to one full AAC frame's
/// PCM (1024 stereo i16 = 4096 bytes) so the downstream `ws.tx_in` →
/// `ws.tx_out` → `http.ws_in` chain delivers exactly one WS BINARY
/// envelope per AAC frame. Smaller chunks (e.g. 256 B) accumulate in
/// the FIFO between `ws_stream` and `http`; `ws_drain_fanout_input`
/// processes only the first envelope per `channel_read` and discards
/// trailing envelopes, so the receiver sees a misaligned, partial
/// stream. 4096 keeps each codec write atomic at every hop.
const IO_BUF_SIZE: usize = 4096;
const OUTPUT_SAMPLES: usize = SAMPLES_PER_FRAME * MAX_CHANNELS; // 2048 i16

const ONLY_LONG_SEQUENCE: u8 = 0;
const LONG_START_SEQUENCE: u8 = 1;
const EIGHT_SHORT_SEQUENCE: u8 = 2;
const LONG_STOP_SEQUENCE: u8 = 3;

const ID_SCE: u8 = 0;
const ID_CPE: u8 = 1;
const ID_CCE: u8 = 2;
const ID_LFE: u8 = 3;
const ID_DSE: u8 = 4;
const ID_PCE: u8 = 5;
const ID_FIL: u8 = 6;
const ID_END: u8 = 7;

const ZERO_HCB: u8 = 0;
const FIRST_PAIR_HCB: u8 = 5;
const ESC_HCB: u8 = 11;
const NOISE_HCB: u8 = 13;
const INTENSITY_HCB2: u8 = 14;
const INTENSITY_HCB: u8 = 15;

const HCB_N: [u8; 12] = [0, 5, 5, 0, 5, 0, 5, 0, 5, 0, 6, 5];

const SAMPLE_RATES: [u32; 13] = [
    96000, 88200, 64000, 48000, 44100, 32000,
    24000, 22050, 16000, 12000, 11025, 8000, 7350,
];

static SWB_OFFSET_1024_48: [u16; 50] = [
    0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 48, 56, 64, 72, 80, 88,
    96, 108, 120, 132, 144, 160, 176, 196, 216, 240, 264, 292, 320,
    352, 384, 416, 448, 480, 512, 544, 576, 608, 640, 672, 704, 736,
    768, 800, 832, 864, 896, 928, 1024,
];
static SWB_OFFSET_128_48: [u16; 15] = [0, 4, 8, 12, 16, 20, 28, 36, 44, 56, 68, 80, 96, 112, 128];

fn swb_offset_long() -> &'static [u16] { &SWB_OFFSET_1024_48 }
fn swb_offset_short() -> &'static [u16] { &SWB_OFFSET_128_48 }

#[inline]
fn sf_idx(g: usize, sfb: usize) -> usize { g * MAX_SFB + sfb }

// ============================================================================
// BitReader
// ============================================================================

struct BitReader {
    data: *const u8,
    data_len: usize,
    bit_pos: usize,
}

impl BitReader {
    fn new(data: *const u8, len: usize) -> Self { BitReader { data, data_len: len, bit_pos: 0 } }

    #[inline]
    fn bits_left(&self) -> usize {
        let total = self.data_len * 8;
        total.saturating_sub(self.bit_pos)
    }

    fn read_bits(&mut self, n: u32) -> u32 {
        if n == 0 { return 0; }
        let mut result: u32 = 0;
        let mut bits_needed = n as usize;
        let mut bp = self.bit_pos;
        while bits_needed > 0 {
            let byte_idx = bp >> 3;
            if byte_idx >= self.data_len {
                self.bit_pos = self.data_len * 8;
                return result;
            }
            let bit_idx = bp & 7;
            let byte_val = unsafe { *self.data.add(byte_idx) };
            let avail = 8 - bit_idx;
            let take = bits_needed.min(avail);
            let shift = avail - take;
            let mask = ((1u32 << take) - 1) as u8;
            let bits = (byte_val >> shift) & mask;
            result = (result << take) | (bits as u32);
            bp += take;
            bits_needed -= take;
        }
        self.bit_pos = bp;
        result
    }
    fn read_bit(&mut self) -> u32 { self.read_bits(1) }
    fn show_bits(&self, n: u32) -> u32 {
        let mut bp = self.bit_pos;
        let mut bits_needed = n as usize;
        let mut result: u32 = 0;
        while bits_needed > 0 {
            let byte_idx = bp >> 3;
            if byte_idx >= self.data_len { return result << bits_needed; }
            let bit_idx = bp & 7;
            let byte_val = unsafe { *self.data.add(byte_idx) };
            let avail = 8 - bit_idx;
            let take = bits_needed.min(avail);
            let shift = avail - take;
            let mask = ((1u32 << take) - 1) as u8;
            let bits = (byte_val >> shift) & mask;
            result = (result << take) | (bits as u32);
            bp += take;
            bits_needed -= take;
        }
        result
    }
    fn flush_bits(&mut self, n: u32) {
        let total = self.data_len * 8;
        self.bit_pos = (self.bit_pos + n as usize).min(total);
    }
    fn skip_bits(&mut self, n: usize) { self.flush_bits(n as u32) }
    fn byte_align(&mut self) {
        let rem = self.bit_pos & 7;
        if rem != 0 { self.bit_pos += 8 - rem; }
    }
}

// ============================================================================
// ADTS
// ============================================================================

struct AdtsHeader {
    profile: u8,
    sample_rate_idx: u8,
    channel_config: u8,
    frame_length: u16,
    header_size: u8,
}

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

fn parse_adts_header(buf: *const u8, len: usize) -> Option<AdtsHeader> {
    if len < 7 { return None; }
    let b0 = unsafe { *buf.add(0) };
    let b1 = unsafe { *buf.add(1) };
    let b2 = unsafe { *buf.add(2) };
    let b3 = unsafe { *buf.add(3) };
    let b4 = unsafe { *buf.add(4) };
    let b5 = unsafe { *buf.add(5) };
    if b0 != 0xFF || (b1 & 0xF0) != 0xF0 { return None; }
    let protection_absent = b1 & 1;
    let profile = (b2 >> 6) & 3;
    let sample_rate_idx = (b2 >> 2) & 0xF;
    if sample_rate_idx >= 13 { return None; }
    let channel_config = ((b2 & 1) << 2) | ((b3 >> 6) & 3);
    let frame_length = (((b3 & 0x03) as u16) << 11)
        | ((b4 as u16) << 3)
        | (((b5 >> 5) & 0x07) as u16);
    let header_size = if protection_absent != 0 { 7 } else { 9 };
    if (frame_length as usize) < (header_size as usize) { return None; }
    if frame_length > 8192 { return None; }
    Some(AdtsHeader { profile, sample_rate_idx, channel_config, frame_length, header_size })
}

// ============================================================================
// ICS / Section / Scalefactor parsers
// ============================================================================

#[derive(Default, Clone, Copy)]
struct IcsInfo {
    window_sequence: u8,
    window_shape: u8,
    max_sfb: u8,
    num_window_groups: u8,
    window_group_length: [u8; MAX_WIN_GROUPS],
    scale_factor_grouping: u8,
}

#[derive(Clone, Copy)]
struct SectionData {
    num_sec: usize,
    sect_cb:    [u8;  MAX_SECTIONS],
    sect_start: [u16; MAX_SECTIONS],
    sect_end:   [u16; MAX_SECTIONS],
}

impl Default for SectionData {
    fn default() -> Self {
        SectionData {
            num_sec: 0,
            sect_cb:    [0u8;  MAX_SECTIONS],
            sect_start: [0u16; MAX_SECTIONS],
            sect_end:   [0u16; MAX_SECTIONS],
        }
    }
}

fn read_ics_info(br: &mut BitReader) -> IcsInfo {
    let mut info = IcsInfo::default();
    info.num_window_groups = 1;
    info.window_group_length[0] = 1;

    let _reserved = br.read_bit();
    info.window_sequence = br.read_bits(2) as u8;
    info.window_shape = br.read_bit() as u8;

    if info.window_sequence == EIGHT_SHORT_SEQUENCE {
        info.max_sfb = br.read_bits(4) as u8;
        info.scale_factor_grouping = br.read_bits(7) as u8;
        let mut g = 0usize;
        for w in 1..8 {
            let bit = (info.scale_factor_grouping >> (6 - (w - 1))) & 1;
            if bit == 0 {
                g += 1;
                if g < MAX_WIN_GROUPS {
                    info.num_window_groups += 1;
                    info.window_group_length[g] = 1;
                }
            } else if g < MAX_WIN_GROUPS {
                info.window_group_length[g] += 1;
            }
        }
    } else {
        info.max_sfb = br.read_bits(6) as u8;
        let _predictor_data_present = br.read_bit();
        // For AAC-LC, predictor_data_present is informational only — no
        // follow-up bits are read regardless of value (faad: empty body
        // unless `object_type == MAIN`, which we skip).
    }
    info
}

fn read_section_data(br: &mut BitReader, info: &IcsInfo) -> SectionData {
    let mut sd = SectionData::default();
    let sect_bits = if info.window_sequence == EIGHT_SHORT_SEQUENCE { 3u32 } else { 5u32 };
    let sect_esc = (1u32 << sect_bits) - 1;
    let max_sfb = info.max_sfb as u16;
    let num_groups = info.num_window_groups as usize;
    let mut sec_idx = 0usize;
    for _g in 0..num_groups {
        let mut k: u16 = 0;
        while k < max_sfb {
            if sec_idx >= MAX_SECTIONS { break; }
            let sect_cb = br.read_bits(4) as u8;
            let mut sect_len: u16 = 0;
            loop {
                let incr = br.read_bits(sect_bits) as u16;
                sect_len += incr;
                if (incr as u32) != sect_esc { break; }
            }
            sd.sect_cb[sec_idx] = sect_cb;
            sd.sect_start[sec_idx] = k;
            let end = (k + sect_len).min(max_sfb);
            sd.sect_end[sec_idx] = end;
            k = end;
            sec_idx += 1;
        }
    }
    sd.num_sec = sec_idx;
    sd
}

fn decode_hcb_sf(br: &mut BitReader) -> i8 {
    let mut offset: usize = 0;
    while HCB_SF[offset][1] != 0 {
        let b = br.read_bit() as usize;
        offset += HCB_SF[offset][b] as usize;
        if offset >= HCB_SF.len() { return 0; }
    }
    HCB_SF[offset][0] as i8
}

fn read_scalefactors(
    br: &mut BitReader, info: &IcsInfo, sd: &SectionData,
    global_gain: u8, scalefactors: &mut [i16],
) {
    let mut sf: i16 = global_gain as i16;
    let mut is_position: i16 = 0;
    let mut noise_energy: i16 = (global_gain as i16) - 90;
    let mut noise_pcm_flag: bool = true;
    let max_sfb = info.max_sfb as usize;

    let mut sec_idx: usize = 0;
    for g in 0..info.num_window_groups as usize {
        // Slice this group's sections via sect_start==0 boundary.
        let g_sec_start = sec_idx;
        sec_idx += 1;
        while sec_idx < sd.num_sec && sd.sect_start[sec_idx] != 0 {
            sec_idx += 1;
        }
        let mut sfb_cb_local = [0u8; MAX_SFB];
        for sec in g_sec_start..sec_idx {
            let cb = sd.sect_cb[sec];
            let s = sd.sect_start[sec] as usize;
            let e = sd.sect_end[sec] as usize;
            for sfb in s..e.min(MAX_SFB) {
                sfb_cb_local[sfb] = cb;
            }
        }
        for sfb in 0..max_sfb {
            if sfb >= MAX_SFB { break; }
            let cb = sfb_cb_local[sfb];
            let idx = sf_idx(g, sfb);
            if idx >= scalefactors.len() { break; }
            if cb == ZERO_HCB {
                scalefactors[idx] = 0;
            } else if cb == NOISE_HCB {
                let diff: i16 = if noise_pcm_flag {
                    noise_pcm_flag = false;
                    (br.read_bits(9) as i16) - 256
                } else {
                    (decode_hcb_sf(br) as i16) - 60
                };
                noise_energy += diff;
                scalefactors[idx] = noise_energy;
            } else if cb >= INTENSITY_HCB2 {
                let diff = decode_hcb_sf(br) as i16 - 60;
                is_position += diff;
                scalefactors[idx] = is_position;
            } else {
                let diff = decode_hcb_sf(br) as i16 - 60;
                sf += diff;
                scalefactors[idx] = sf;
            }
        }
    }
}

// ============================================================================
// Huffman spectral decoding
// ============================================================================

fn huffman_sign_bits(br: &mut BitReader, sp: &mut [i16], len: usize) {
    for i in 0..len {
        if sp[i] != 0 && (br.read_bit() & 1) != 0 {
            sp[i] = -sp[i];
        }
    }
}

fn huffman_getescape(br: &mut BitReader, x: &mut i16) {
    let xv = *x;
    let neg = if xv == 16 { false }
              else if xv == -16 { true }
              else { return; };
    let mut i: u32 = 4;
    while i < 16 {
        if br.read_bit() == 0 { break; }
        i += 1;
    }
    if i >= 16 { return; }
    let off = br.read_bits(i) as i64;
    let mut j: i64 = off | (1_i64 << i);
    if neg { j = -j; }
    *x = j.clamp(-32768, 32767) as i16;
}

/// Inner body of 2-step pair/quad — generic in HcbPair/HcbQuad shape.
/// Split out so each (cb)→table dispatch is a separate function call,
/// preventing LLVM from emitting a `.data.rel.ro` switch table with
/// absolute pointer values (those aren't relocated by the mmap-only
/// PIC module loader, so a switch-table hit would SIGSEGV).
fn huffman_2step_quad_inner(
    root_disp: &[HcbDisp], root_bits: u8, table: &[HcbQuad],
    br: &mut BitReader, sp: &mut [i16; 4],
) {
    let cw = br.show_bits(root_bits as u32) as usize;
    if cw >= root_disp.len() { return; }
    let mut offset = root_disp[cw].offset as usize;
    let extra_bits = root_disp[cw].extra_bits;
    if extra_bits != 0 {
        br.flush_bits(root_bits as u32);
        offset += br.show_bits(extra_bits as u32) as usize;
        if offset >= table.len() { return; }
        let bits = table[offset].bits;
        let to_flush = if bits >= root_bits { bits - root_bits } else { 0 };
        br.flush_bits(to_flush as u32);
    } else {
        if offset >= table.len() { return; }
        br.flush_bits(table[offset].bits as u32);
    }
    if offset >= table.len() { return; }
    sp[0] = table[offset].x as i16;
    sp[1] = table[offset].y as i16;
    sp[2] = table[offset].v as i16;
    sp[3] = table[offset].w as i16;
}

fn huffman_2step_pair_inner(
    root_disp: &[HcbDisp], root_bits: u8, table: &[HcbPair],
    br: &mut BitReader, sp: &mut [i16; 2],
) {
    let cw = br.show_bits(root_bits as u32) as usize;
    if cw >= root_disp.len() { return; }
    let mut offset = root_disp[cw].offset as usize;
    let extra_bits = root_disp[cw].extra_bits;
    if extra_bits != 0 {
        br.flush_bits(root_bits as u32);
        offset += br.show_bits(extra_bits as u32) as usize;
        if offset >= table.len() { return; }
        let bits = table[offset].bits;
        let to_flush = if bits >= root_bits { bits - root_bits } else { 0 };
        br.flush_bits(to_flush as u32);
    } else {
        if offset >= table.len() { return; }
        br.flush_bits(table[offset].bits as u32);
    }
    if offset >= table.len() { return; }
    sp[0] = table[offset].x as i16;
    sp[1] = table[offset].y as i16;
}

/// cb→(table, root) dispatch via if/else (NOT match) — see comment above.
fn huffman_2step_quad(cb: u8, br: &mut BitReader, sp: &mut [i16; 4]) {
    if cb == 1 {
        huffman_2step_quad_inner(&HCB1_1, HCB_N[1], &HCB1_2, br, sp);
    } else if cb == 2 {
        huffman_2step_quad_inner(&HCB2_1, HCB_N[2], &HCB2_2, br, sp);
    } else if cb == 4 {
        huffman_2step_quad_inner(&HCB4_1, HCB_N[4], &HCB4_2, br, sp);
    }
}

fn huffman_2step_pair(cb: u8, br: &mut BitReader, sp: &mut [i16; 2]) {
    if cb == 6 {
        huffman_2step_pair_inner(&HCB6_1, HCB_N[6], &HCB6_2, br, sp);
    } else if cb == 8 {
        huffman_2step_pair_inner(&HCB8_1, HCB_N[8], &HCB8_2, br, sp);
    } else if cb == 10 {
        huffman_2step_pair_inner(&HCB10_1, HCB_N[10], &HCB10_2, br, sp);
    } else if cb == 11 {
        huffman_2step_pair_inner(&HCB11_1, HCB_N[11], &HCB11_2, br, sp);
    }
}

fn huffman_binary_quad(br: &mut BitReader, sp: &mut [i16; 4]) {
    let len = HCB3.len();
    let mut offset: usize = 0;
    let mut iter = 0;
    while offset < len && HCB3[offset].is_leaf == 0 && iter < 32 {
        let b = br.read_bit() as usize;
        let delta = HCB3[offset].data[b] as i16 as i32;
        let new_off = offset as i32 + delta;
        if new_off < 0 || (new_off as usize) >= len { return; }
        offset = new_off as usize;
        iter += 1;
    }
    if offset >= len { return; }
    sp[0] = HCB3[offset].data[0] as i16;
    sp[1] = HCB3[offset].data[1] as i16;
    sp[2] = HCB3[offset].data[2] as i16;
    sp[3] = HCB3[offset].data[3] as i16;
}

/// Inner: shared by HCB5/7/9. Split out so cb dispatch doesn't emit a
/// switch table (see huffman_2step_pair comment).
fn huffman_binary_pair_inner(table: &[HcbBinPair], br: &mut BitReader, sp: &mut [i16; 2]) {
    let len = table.len();
    let mut offset: usize = 0;
    let mut iter = 0;
    while offset < len && table[offset].is_leaf == 0 && iter < 32 {
        let b = br.read_bit() as usize;
        let delta = table[offset].data[b] as i32;
        let new_off = offset as i32 + delta;
        if new_off < 0 || (new_off as usize) >= len { return; }
        offset = new_off as usize;
        iter += 1;
    }
    if offset >= len { return; }
    sp[0] = table[offset].data[0] as i16;
    sp[1] = table[offset].data[1] as i16;
}

fn huffman_binary_pair(cb: u8, br: &mut BitReader, sp: &mut [i16; 2]) {
    if cb == 5 {
        huffman_binary_pair_inner(&HCB5, br, sp);
    } else if cb == 7 {
        huffman_binary_pair_inner(&HCB7, br, sp);
    } else if cb == 9 {
        huffman_binary_pair_inner(&HCB9, br, sp);
    }
}

fn huffman_spectral_data(cb: u8, br: &mut BitReader, sp: &mut [i16; 4]) -> usize {
    match cb {
        1 | 2 => { huffman_2step_quad(cb, br, sp); 4 }
        3 => { huffman_binary_quad(br, sp); huffman_sign_bits(br, sp, 4); 4 }
        4 => { huffman_2step_quad(cb, br, sp); huffman_sign_bits(br, sp, 4); 4 }
        5 => {
            let mut tmp = [sp[0], sp[1]]; huffman_binary_pair(5, br, &mut tmp);
            sp[0] = tmp[0]; sp[1] = tmp[1]; 2
        }
        6 => {
            let mut tmp = [sp[0], sp[1]]; huffman_2step_pair(6, br, &mut tmp);
            sp[0] = tmp[0]; sp[1] = tmp[1]; 2
        }
        7 | 9 => {
            let mut tmp = [sp[0], sp[1]]; huffman_binary_pair(cb, br, &mut tmp);
            sp[0] = tmp[0]; sp[1] = tmp[1]; huffman_sign_bits(br, sp, 2); 2
        }
        8 | 10 => {
            let mut tmp = [sp[0], sp[1]]; huffman_2step_pair(cb, br, &mut tmp);
            sp[0] = tmp[0]; sp[1] = tmp[1]; huffman_sign_bits(br, sp, 2); 2
        }
        11 => {
            let mut tmp = [sp[0], sp[1]]; huffman_2step_pair(11, br, &mut tmp);
            sp[0] = tmp[0]; sp[1] = tmp[1]; huffman_sign_bits(br, sp, 2);
            huffman_getescape(br, &mut sp[0]);
            huffman_getescape(br, &mut sp[1]);
            2
        }
        _ => 0,
    }
}

// ============================================================================
// Spectral data section walk
// ============================================================================

fn read_spectral_data(
    br: &mut BitReader, info: &IcsInfo, sd: &SectionData, spec_quant: &mut [i16],
) {
    let is_short = info.window_sequence == EIGHT_SHORT_SEQUENCE;
    let swb_off: &[u16] = if is_short { swb_offset_short() } else { swb_offset_long() };
    if is_short {
        let nshort = 128usize;
        let mut groups_total: usize = 0;
        let mut sec_idx: usize = 0;
        for g in 0..info.num_window_groups as usize {
            let group_len = info.window_group_length[g] as usize;
            let mut p = groups_total * nshort;
            let sec_start = sec_idx;
            sec_idx += 1;
            while sec_idx < sd.num_sec && sd.sect_start[sec_idx] != 0 {
                sec_idx += 1;
            }
            for sec in sec_start..sec_idx {
                let cb = sd.sect_cb[sec];
                let start_sfb = sd.sect_start[sec] as usize;
                let end_sfb   = sd.sect_end[sec] as usize;
                if start_sfb >= swb_off.len() - 1 { continue; }
                let end_clamped = end_sfb.min(swb_off.len() - 1);
                let span = (swb_off[end_clamped] as usize
                          - swb_off[start_sfb] as usize) * group_len;
                if cb == ZERO_HCB || cb == NOISE_HCB
                   || cb == INTENSITY_HCB || cb == INTENSITY_HCB2 {
                    p += span; continue;
                }
                if cb > 11 { p += span; continue; }
                let group_size = if cb < FIRST_PAIR_HCB { 4 } else { 2 };
                let mut remaining = span;
                while remaining >= group_size {
                    let mut sp = [0i16; 4];
                    let _ = huffman_spectral_data(cb, br, &mut sp);
                    for j in 0..group_size {
                        if p + j < spec_quant.len() { spec_quant[p + j] = sp[j]; }
                    }
                    p += group_size;
                    remaining -= group_size;
                }
            }
            groups_total += group_len;
        }
        return;
    }

    for sec in 0..sd.num_sec {
        let cb = sd.sect_cb[sec];
        let start_sfb = sd.sect_start[sec] as usize;
        let end_sfb   = sd.sect_end[sec] as usize;
        if start_sfb >= swb_off.len() - 1 { continue; }
        let start = swb_off[start_sfb] as usize;
        let end = swb_off[end_sfb.min(swb_off.len() - 1)] as usize;
        if cb == ZERO_HCB || cb == NOISE_HCB
           || cb == INTENSITY_HCB || cb == INTENSITY_HCB2 { continue; }
        if cb > 11 { continue; }
        let group_size = if cb < FIRST_PAIR_HCB { 4 } else { 2 };
        let mut k = start;
        let mut iters = 0u32;
        while k + group_size <= end && iters < 4096 {
            let mut sp = [0i16; 4];
            let _n = huffman_spectral_data(cb, br, &mut sp);
            for j in 0..group_size {
                if k + j < spec_quant.len() { spec_quant[k + j] = sp[j]; }
            }
            k += group_size;
            iters += 1;
        }
    }
}

// ============================================================================
// Inverse quantization: x^(4/3) + scalefactor gain
// ============================================================================

// Tables now live in `pub static` (rodata) — no Tables struct needed in
// state, no init phase. iquant just reads from the const arrays.

fn iquant(q: i16) -> f32 {
    let m = q.unsigned_abs() as usize;
    let v = if m < 8192 { IQ_TABLE_CONST[m] } else { IQ_TABLE_CONST[8191] };
    if q < 0 { -v } else { v }
}

fn quant_to_spec(
    info: &IcsInfo, scalefactors: &[i16],
    spec_quant: &[i16], spec: &mut [f32],
) {
    let is_short = info.window_sequence == EIGHT_SHORT_SEQUENCE;
    let swb = if is_short { swb_offset_short() } else { swb_offset_long() };
    let max_sfb = (info.max_sfb as usize).min(swb.len() - 1);

    if is_short {
        let nshort = 128usize;
        let mut gindex: usize = 0;
        let mut groups_total: usize = 0;
        for g in 0..info.num_window_groups as usize {
            let group_len = info.window_group_length[g] as usize;
            let win_inc = nshort;
            let mut k: usize = groups_total * nshort;
            let mut j: u16 = 0;
            for sfb in 0..max_sfb {
                let scale_factor = scalefactors[sf_idx(g, sfb)] as i32;
                let exp = (scale_factor >> 2).clamp(0, 63) as usize;
                let frac = (scale_factor & 3) as usize;
                let gain = POW2SF_TAB_CONST[exp] * POW2_FRAC_CONST[frac];
                let width = (swb[sfb + 1] - swb[sfb]) as usize;
                let mut wa = gindex + j as usize;
                for _win in 0..group_len {
                    for bin in 0..width {
                        let wb = wa + bin;
                        if wb < spec.len() && k < spec_quant.len() {
                            spec[wb] = iquant(spec_quant[k]) * gain;
                        }
                        k += 1;
                    }
                    wa += win_inc;
                }
                j += width as u16;
            }
            gindex += group_len * win_inc;
            groups_total += group_len;
        }
        return;
    }

    for sfb in 0..max_sfb {
        let scale_factor = scalefactors[sf_idx(0, sfb)] as i32;
        let exp = (scale_factor >> 2).clamp(0, 63) as usize;
        let frac = (scale_factor & 3) as usize;
        let gain = POW2SF_TAB_CONST[exp] * POW2_FRAC_CONST[frac];
        let start = swb[sfb] as usize;
        let end = swb[sfb + 1] as usize;
        for k in start..end.min(spec.len()) {
            spec[k] = iquant(spec_quant[k]) * gain;
        }
    }
}

// ============================================================================
// MS stereo
// ============================================================================

fn ms_decode(
    l_info: &IcsInfo, l_spec: &mut [f32], r_spec: &mut [f32],
    ms_used_arr: &[[u8; MAX_SFB]; MAX_WIN_GROUPS],
) {
    let is_short = l_info.window_sequence == EIGHT_SHORT_SEQUENCE;
    let swb = if is_short { swb_offset_short() } else { swb_offset_long() };
    let max_sfb = (l_info.max_sfb as usize).min(swb.len() - 1);

    if !is_short {
        for sfb in 0..max_sfb {
            if ms_used_arr[0][sfb] == 0 { continue; }
            let start = swb[sfb] as usize;
            let end = swb[sfb + 1] as usize;
            for k in start..end.min(l_spec.len()) {
                let m = l_spec[k]; let s = r_spec[k];
                l_spec[k] = m + s; r_spec[k] = m - s;
            }
        }
        return;
    }
    let nshort = 128usize;
    let mut groups_total = 0usize;
    for g in 0..l_info.num_window_groups as usize {
        let group_len = l_info.window_group_length[g] as usize;
        for sfb in 0..max_sfb {
            if ms_used_arr[g][sfb] == 0 { continue; }
            let width = (swb[sfb + 1] - swb[sfb]) as usize;
            for w in 0..group_len {
                let base = (groups_total + w) * nshort + (swb[sfb] as usize);
                for k in base..(base + width).min(l_spec.len()) {
                    let m = l_spec[k]; let s = r_spec[k];
                    l_spec[k] = m + s; r_spec[k] = m - s;
                }
            }
        }
        groups_total += group_len;
    }
}

// ============================================================================
// Direct-DFT IMDCT (slow but no_std-clean) + windowing + overlap-add
// ============================================================================

fn imdct_direct(input: &[f32], output: &mut [f32]) {
    let n2 = input.len();
    let n = output.len();
    let inv_n = 2.0 / n as f32;
    let phase = PI_F32 / (2 * n) as f32;
    for i in 0..n {
        let mut s = 0.0f32;
        let base = phase * ((2 * i + 1 + n2) as f32);
        for k in 0..n2 {
            s += input[k] * cosf(base * ((2 * k + 1) as f32));
        }
        output[i] = inv_n * s;
    }
}

fn pick_long_window(shape: u8) -> &'static [f32] {
    if shape == 0 { &SINE_LONG_CONST } else { &KBD_LONG_1024 }
}
fn pick_short_window(shape: u8) -> &'static [f32] {
    if shape == 0 { &SINE_SHORT_CONST } else { &KBD_SHORT_128 }
}

fn ifilter_bank_long(
    freq_in: &[f32], time_out: &mut [f32], overlap: &mut [f32],
    buf: &mut [f32], window_long: &[f32], window_long_prev: &[f32],
) {
    let nlong = 1024usize;
    imdct_direct(freq_in, &mut buf[..2 * nlong]);
    for i in 0..nlong {
        time_out[i] = overlap[i] + buf[i] * window_long_prev[i];
    }
    for i in 0..nlong {
        overlap[i] = buf[nlong + i] * window_long[nlong - 1 - i];
    }
}

fn ifilter_bank_long_start(
    freq_in: &[f32], time_out: &mut [f32], overlap: &mut [f32],
    buf: &mut [f32], window_long_prev: &[f32], window_short: &[f32],
) {
    let nlong = 1024usize;
    let nshort = 128usize;
    let nflat_ls = (nlong - nshort) / 2;
    imdct_direct(freq_in, &mut buf[..2 * nlong]);
    for i in 0..nlong { time_out[i] = overlap[i] + buf[i] * window_long_prev[i]; }
    for i in 0..nflat_ls { overlap[i] = buf[nlong + i]; }
    for i in 0..nshort {
        overlap[nflat_ls + i] = buf[nlong + nflat_ls + i] * window_short[nshort - 1 - i];
    }
    for i in 0..nflat_ls { overlap[nflat_ls + nshort + i] = 0.0; }
}

fn ifilter_bank_long_stop(
    freq_in: &[f32], time_out: &mut [f32], overlap: &mut [f32],
    buf: &mut [f32], window_long: &[f32], window_short_prev: &[f32],
) {
    let nlong = 1024usize;
    let nshort = 128usize;
    let nflat_ls = (nlong - nshort) / 2;
    imdct_direct(freq_in, &mut buf[..2 * nlong]);
    for i in 0..nflat_ls { time_out[i] = overlap[i]; }
    for i in 0..nshort {
        time_out[nflat_ls + i] = overlap[nflat_ls + i]
            + buf[nflat_ls + i] * window_short_prev[i];
    }
    for i in 0..nflat_ls {
        time_out[nflat_ls + nshort + i] =
            overlap[nflat_ls + nshort + i] + buf[nflat_ls + nshort + i];
    }
    for i in 0..nlong { overlap[i] = buf[nlong + i] * window_long[nlong - 1 - i]; }
}

fn ifilter_bank_eight_short(
    freq_in: &[f32], time_out: &mut [f32], overlap: &mut [f32],
    buf: &mut [f32], window_short: &[f32], window_short_prev: &[f32],
) {
    let nlong = 1024usize;
    let nshort = 128usize;
    let trans = nshort / 2;
    let nflat_ls = (nlong - nshort) / 2;
    for w in 0..8 {
        let in_off = w * nshort;
        let out_off = 2 * nshort * w;
        imdct_direct(
            &freq_in[in_off..in_off + nshort],
            &mut buf[out_off..out_off + 2 * nshort],
        );
    }
    for i in 0..nflat_ls { time_out[i] = overlap[i]; }
    for i in 0..nshort {
        time_out[nflat_ls + i] = overlap[nflat_ls + i]
            + buf[i] * window_short_prev[i];
        time_out[nflat_ls + nshort + i] = overlap[nflat_ls + nshort + i]
            + buf[nshort * 1 + i] * window_short[nshort - 1 - i]
            + buf[nshort * 2 + i] * window_short[i];
        time_out[nflat_ls + 2 * nshort + i] = overlap[nflat_ls + 2 * nshort + i]
            + buf[nshort * 3 + i] * window_short[nshort - 1 - i]
            + buf[nshort * 4 + i] * window_short[i];
        time_out[nflat_ls + 3 * nshort + i] = overlap[nflat_ls + 3 * nshort + i]
            + buf[nshort * 5 + i] * window_short[nshort - 1 - i]
            + buf[nshort * 6 + i] * window_short[i];
        if i < trans {
            time_out[nflat_ls + 4 * nshort + i] = overlap[nflat_ls + 4 * nshort + i]
                + buf[nshort * 7 + i] * window_short[nshort - 1 - i]
                + buf[nshort * 8 + i] * window_short[i];
        }
    }
    for i in 0..nshort {
        if i >= trans {
            overlap[nflat_ls + 4 * nshort + i - nlong] =
                buf[nshort * 7 + i] * window_short[nshort - 1 - i]
              + buf[nshort * 8 + i] * window_short[i];
        }
        overlap[nflat_ls + 5 * nshort + i - nlong] =
            buf[nshort * 9 + i] * window_short[nshort - 1 - i]
          + buf[nshort * 10 + i] * window_short[i];
        overlap[nflat_ls + 6 * nshort + i - nlong] =
            buf[nshort * 11 + i] * window_short[nshort - 1 - i]
          + buf[nshort * 12 + i] * window_short[i];
        overlap[nflat_ls + 7 * nshort + i - nlong] =
            buf[nshort * 13 + i] * window_short[nshort - 1 - i]
          + buf[nshort * 14 + i] * window_short[i];
        overlap[nflat_ls + 8 * nshort + i - nlong] =
            buf[nshort * 15 + i] * window_short[nshort - 1 - i];
    }
    for i in 0..nflat_ls { overlap[nflat_ls + nshort + i] = 0.0; }
}

// ============================================================================
// TNS / fill / DSE skips
// ============================================================================

// ============================================================================
// TNS (Temporal Noise Shaping) — bitstream parse + inverse AR filter.
// ============================================================================
//
// The encoder applies a forward AR filter to the spectral coefficients
// of a small set of upper-band SFBs to flatten transient peaks. The
// decoder runs the matching all-pole synthesis filter to re-expand
// them. cmajor.aac doesn't use TNS, but other AAC content (especially
// rich/transient material at low bitrates) does — implement once
// here, no runtime cost when the bitstream's `tns_data_present` flag
// is zero. Mirrors faad2 libfaad/tns.c.

// num_swb counts per sample-rate index (faad2 libfaad/specrec.c).
// Used by TNS to clamp `bottom` / `top` SFB indices to the valid range
// for this asset's window length.
const NUM_SWB_1024_WINDOW: [u8; 12] = [41, 41, 47, 49, 49, 51, 47, 47, 43, 43, 43, 40];
const NUM_SWB_128_WINDOW:  [u8; 12] = [12, 12, 12, 14, 14, 14, 15, 15, 15, 15, 15, 15];

const TNS_MAX_ORDER:   usize = 20;
const TNS_MAX_FILTERS: usize = 3;
const TNS_MAX_WINDOWS: usize = 8;

#[repr(C)]
#[derive(Clone, Copy)]
struct TnsInfo {
    present: u8,
    n_filt:        [u8; TNS_MAX_WINDOWS],
    coef_res:      [u8; TNS_MAX_WINDOWS],
    length:        [[u8; TNS_MAX_FILTERS]; TNS_MAX_WINDOWS],
    order:         [[u8; TNS_MAX_FILTERS]; TNS_MAX_WINDOWS],
    direction:     [[u8; TNS_MAX_FILTERS]; TNS_MAX_WINDOWS],
    coef_compress: [[u8; TNS_MAX_FILTERS]; TNS_MAX_WINDOWS],
    coef:          [[[u8; TNS_MAX_ORDER]; TNS_MAX_FILTERS]; TNS_MAX_WINDOWS],
}

impl Default for TnsInfo {
    fn default() -> Self {
        TnsInfo {
            present: 0,
            n_filt:        [0; TNS_MAX_WINDOWS],
            coef_res:      [0; TNS_MAX_WINDOWS],
            length:        [[0; TNS_MAX_FILTERS]; TNS_MAX_WINDOWS],
            order:         [[0; TNS_MAX_FILTERS]; TNS_MAX_WINDOWS],
            direction:     [[0; TNS_MAX_FILTERS]; TNS_MAX_WINDOWS],
            coef_compress: [[0; TNS_MAX_FILTERS]; TNS_MAX_WINDOWS],
            coef:          [[[0; TNS_MAX_ORDER]; TNS_MAX_FILTERS]; TNS_MAX_WINDOWS],
        }
    }
}

fn read_tns_data(br: &mut BitReader, info: &IcsInfo, tns: &mut TnsInfo) {
    tns.present = 1;
    let is_short = info.window_sequence == EIGHT_SHORT_SEQUENCE;
    let (n_filt_bits, length_bits, order_bits, num_windows) =
        if is_short { (1u32, 4u32, 3u32, 8usize) }
        else        { (2u32, 6u32, 5u32, 1usize) };
    for w in 0..num_windows {
        let n_filt = (br.read_bits(n_filt_bits) as usize).min(TNS_MAX_FILTERS);
        tns.n_filt[w] = n_filt as u8;
        if n_filt == 0 { continue; }
        let coef_res = br.read_bit() as u8;
        tns.coef_res[w] = coef_res;
        let start_coef_bits = 3u32 + coef_res as u32;
        for filt in 0..n_filt {
            tns.length[w][filt] = br.read_bits(length_bits) as u8;
            let order_raw = br.read_bits(order_bits) as usize;
            let order = order_raw.min(TNS_MAX_ORDER);
            tns.order[w][filt] = order as u8;
            if order > 0 {
                tns.direction[w][filt]     = br.read_bit() as u8;
                tns.coef_compress[w][filt] = br.read_bit() as u8;
                let coef_bits = start_coef_bits - tns.coef_compress[w][filt] as u32;
                for i in 0..order {
                    tns.coef[w][filt][i] = br.read_bits(coef_bits) as u8;
                }
            }
        }
    }
}

// faad2 tns.c coefficient tables (faad2 libfaad/tns.c).
const TNS_COEF_0_3: [f32; 16] = [
    0.0,            0.4338837391,  0.7818314825,  0.9749279122,
    -0.9848077530, -0.8660254038, -0.6427876097, -0.3420201433,
    -0.4338837391, -0.7818314825, -0.9749279122, -0.9749279122,
    -0.9848077530, -0.8660254038, -0.6427876097, -0.3420201433,
];
const TNS_COEF_0_4: [f32; 16] = [
    0.0,            0.2079116908,  0.4067366431,  0.5877852523,
    0.7431448255,   0.8660254038,  0.9510565163,  0.9945218954,
    -0.9957341763, -0.9618256432, -0.8951632914, -0.7980172273,
    -0.6736956436, -0.5264321629, -0.3612416662, -0.1837495178,
];
const TNS_COEF_1_3: [f32; 16] = [
    0.0,            0.4338837391, -0.6427876097, -0.3420201433,
    0.9749279122,   0.7818314825, -0.6427876097, -0.3420201433,
    -0.4338837391, -0.7818314825, -0.6427876097, -0.3420201433,
    -0.7818314825, -0.4338837391, -0.6427876097, -0.3420201433,
];
const TNS_COEF_1_4: [f32; 16] = [
    0.0,            0.2079116908,  0.4067366431,  0.5877852523,
    -0.6736956436, -0.5264321629, -0.3612416662, -0.1837495178,
    0.9945218954,   0.9510565163,  0.8660254038,  0.7431448255,
    -0.6736956436, -0.5264321629, -0.3612416662, -0.1837495178,
];

fn tns_decode_coef(
    order: usize, coef_res: u8, coef_compress: u8,
    raw_coef: &[u8; TNS_MAX_ORDER], a: &mut [f32; TNS_MAX_ORDER + 1],
) {
    let coef_res_bits = (coef_res + 3) as usize;
    let table_index = 2 * (coef_compress != 0) as usize + (coef_res_bits != 3) as usize;
    let table: &[f32; 16] = match table_index {
        0 => &TNS_COEF_0_3,
        1 => &TNS_COEF_0_4,
        2 => &TNS_COEF_1_3,
        _ => &TNS_COEF_1_4,
    };
    let mut tmp = [0.0f32; TNS_MAX_ORDER + 1];
    for i in 0..order { tmp[i] = table[(raw_coef[i] as usize) & 0x0F]; }
    let mut b = [0.0f32; TNS_MAX_ORDER + 1];
    a[0] = 1.0;
    for m in 1..=order {
        a[m] = tmp[m - 1];
        for i in 1..m { b[i] = a[i] + a[m] * a[m - i]; }
        for i in 1..m { a[i] = b[i]; }
    }
}

fn tns_ar_filter(
    spec: &mut [f32], start: usize, size: usize, inc: i32,
    lpc: &[f32; TNS_MAX_ORDER + 1], order: usize,
) {
    let mut state = [0.0f32; TNS_MAX_ORDER];
    let mut idx = start as isize;
    for _ in 0..size {
        if idx < 0 || (idx as usize) >= spec.len() { return; }
        let x = spec[idx as usize];
        let mut y_acc = 0.0f32;
        for j in 0..order { y_acc += state[j] * lpc[j + 1]; }
        let y = x - y_acc;
        let mut j = order;
        while j > 1 { state[j - 1] = state[j - 2]; j -= 1; }
        if order > 0 { state[0] = y; }
        spec[idx as usize] = y;
        idx += inc as isize;
    }
}

// max_tns_sfb table (LC profile only — long & short cols, indexed by sr_idx).
const MAX_TNS_SFB_LC: [[u8; 2]; 13] = [
    [31,  9], [31,  9], [34, 10], [40, 14], [42, 14], [51, 14],
    [46, 14], [46, 14], [42, 14], [42, 14], [42, 14], [39, 14],
    [39, 14],
];

fn max_tns_sfb(sr_idx: usize, is_short: bool) -> usize {
    if sr_idx < MAX_TNS_SFB_LC.len() {
        MAX_TNS_SFB_LC[sr_idx][is_short as usize] as usize
    } else { 0 }
}

fn tns_decode_frame(info: &IcsInfo, tns: &TnsInfo, spec: &mut [f32], sr_idx: usize) {
    if tns.present == 0 { return; }
    let is_short = info.window_sequence == EIGHT_SHORT_SEQUENCE;
    let num_windows = if is_short { 8 } else { 1 };
    let nshort = if is_short { 128usize } else { 1024 };
    let swb = if is_short { swb_offset_short() } else { swb_offset_long() };
    let num_swb = if is_short {
        NUM_SWB_128_WINDOW[sr_idx.min(11)] as usize
    } else {
        NUM_SWB_1024_WINDOW[sr_idx.min(11)] as usize
    };
    let swb_offset_max = nshort as u16;
    let max_tns = max_tns_sfb(sr_idx, is_short);
    let max_sfb = info.max_sfb as usize;
    let mut lpc = [0.0f32; TNS_MAX_ORDER + 1];

    for w in 0..num_windows {
        let n_filt = tns.n_filt[w] as usize;
        if n_filt == 0 { continue; }
        let mut bottom = num_swb;
        for f in 0..n_filt {
            let top = bottom;
            let len = tns.length[w][f] as usize;
            bottom = top.saturating_sub(len);
            let order = (tns.order[w][f] as usize).min(TNS_MAX_ORDER);
            if order == 0 { continue; }
            tns_decode_coef(order, tns.coef_res[w], tns.coef_compress[w][f],
                            &tns.coef[w][f], &mut lpc);
            let start_sfb = bottom.min(max_tns).min(max_sfb).min(swb.len() - 1);
            let end_sfb   = top   .min(max_tns).min(max_sfb).min(swb.len() - 1);
            let mut start = swb[start_sfb];
            let mut end   = swb[end_sfb];
            if start > swb_offset_max { start = swb_offset_max; }
            if end   > swb_offset_max { end   = swb_offset_max; }
            if end <= start { continue; }
            let size = (end - start) as usize;
            let (filt_start, inc) = if tns.direction[w][f] != 0 {
                ((end - 1) as usize, -1i32)
            } else {
                (start as usize, 1)
            };
            tns_ar_filter(spec, w * nshort + filt_start, size, inc, &lpc, order);
        }
    }
}

// ============================================================================
// Intensity-stereo decode (faad libfaad/is.c).
// ============================================================================
//
// IS reconstructs the right channel from the left × per-SFB scalefactor
// for any band the encoder tagged with INTENSITY_HCB(15)/INTENSITY_HCB2(14).
// cmajor.aac uses 2-4 IS sections per CPE on the right channel for the
// upper-band transient energy; without this pass the listener hears
// "compressed fuzz at note onsets" because the right channel goes
// silent on attacks.

fn is_intensity_cb(cb: u8) -> i8 {
    match cb {
        INTENSITY_HCB  => 1,
        INTENSITY_HCB2 => -1,
        _ => 0,
    }
}

fn is_decode(
    info_r: &IcsInfo, section_r: &SectionData, scalefactors_r: &[i16],
    ms_mask_present: u8, ms_used_arr: &[[u8; MAX_SFB]; MAX_WIN_GROUPS],
    spec_l: &[f32], spec_r: &mut [f32],
) {
    let is_short = info_r.window_sequence == EIGHT_SHORT_SEQUENCE;
    let swb = if is_short { swb_offset_short() } else { swb_offset_long() };
    let swb_offset_max = if is_short { 128u16 } else { 1024 };
    let max_sfb = (info_r.max_sfb as usize).min(swb.len() - 1);
    let nshort = if is_short { 128usize } else { 1024 };
    let num_window_groups = info_r.num_window_groups as usize;

    let mut sec_idx = 0usize;
    let mut window_index = 0usize;
    for g in 0..num_window_groups {
        let g_sec_start = sec_idx;
        sec_idx += 1;
        while sec_idx < section_r.num_sec && section_r.sect_start[sec_idx] != 0 {
            sec_idx += 1;
        }
        let mut sfb_cb_r = [0u8; MAX_SFB];
        for sec in g_sec_start..sec_idx {
            let cb = section_r.sect_cb[sec];
            let s = section_r.sect_start[sec] as usize;
            let e = section_r.sect_end[sec] as usize;
            for sfb in s..e.min(MAX_SFB) { sfb_cb_r[sfb] = cb; }
        }
        let group_len = info_r.window_group_length[g] as usize;
        for b in 0..group_len {
            let group = window_index + b;
            for sfb in 0..max_sfb {
                let is_int = is_intensity_cb(sfb_cb_r[sfb]);
                if is_int == 0 { continue; }
                let sf_raw = scalefactors_r[sf_idx(g, sfb)] as i32;
                let sf = sf_raw.clamp(-120, 120) as f32;
                // 0.5^(sf/4) using pow_4_over_3 → no, just use exp2.
                let mut scale = exp2f(-0.25 * sf);
                let inv: i8 = if ms_mask_present == 1 {
                    if ms_used_arr[g][sfb] != 0 { -1 } else { 1 }
                } else { 1 };
                if is_int != inv { scale = -scale; }
                let start = swb[sfb] as u16;
                let end   = swb[sfb + 1].min(swb_offset_max) as u16;
                let base = group * nshort;
                for i in start as usize..end as usize {
                    let idx = base + i;
                    if idx < spec_r.len() && idx < spec_l.len() {
                        spec_r[idx] = spec_l[idx] * scale;
                    }
                }
            }
        }
        window_index += group_len;
    }
}
fn skip_fill_element(br: &mut BitReader) {
    let mut count = br.read_bits(4) as usize;
    if count == 15 { count += br.read_bits(8) as usize - 1; }
    for _ in 0..count { br.read_bits(8); }
}
fn skip_dse(br: &mut BitReader) {
    let _tag = br.read_bits(4);
    let align = br.read_bit();
    let mut count = br.read_bits(8) as usize;
    if count == 255 { count += br.read_bits(8) as usize; }
    if align != 0 { br.byte_align(); }
    br.skip_bits(count * 8);
}

// ============================================================================
// State + decode_frame
// ============================================================================

#[repr(C)]
pub struct AacState {
    pub syscalls: *const SyscallTable,
    pub in_chan: i32,
    pub out_chan: i32,

    object_type: u8,
    sample_rate_idx: u8,
    channels: u8,
    initialised: u8,
    sample_rate: u32,

    output: [i16; OUTPUT_SAMPLES],
    output_samples: u16,
    out_buf_pos: u16,
    out_buf_len: u16,

    frame_count: u32,

    frame_buf: [u8; FRAME_BUF_SIZE],
    frame_buf_len: u16,
    pending_out: u16,
    pending_offset: u16,
    io_buf: [u8; IO_BUF_SIZE],

    // Per-channel decoder state.
    overlap: [[f32; 1024]; MAX_CHANNELS],
    prev_window_shape: [u8; MAX_CHANNELS],
    // Per-channel parsed-frame scratch (avoid stack frame blowup).
    spec_l: [f32; 1024],
    spec_r: [f32; 1024],
    spec_quant_l: [i16; 1024],
    spec_quant_r: [i16; 1024],
    scalefactors_l: [i16; MAX_WIN_GROUPS * MAX_SFB],
    scalefactors_r: [i16; MAX_WIN_GROUPS * MAX_SFB],
    section_l: SectionData,
    section_r: SectionData,
    ics_info_l: IcsInfo,
    ics_info_r: IcsInfo,
    tns_l: TnsInfo,
    tns_r: TnsInfo,
    // IMDCT scratch (2048 samples).
    imdct_buf: [f32; 2048],
    // Time-domain scratch (per channel, 1024 samples each).
    time_l: [f32; 1024],
    time_r: [f32; 1024],
    // Payload copy buffer for decode_aac_frame (avoids stack overflow on
    // embedded targets with small kernel stacks).
    payload_buf: [u8; 8192],
    // Pre-computed IQ/sine/pow tables (in state, not .bss).

}

fn shift_frame_buf(s: &mut AacState, n: usize) {
    let len = s.frame_buf_len as usize;
    if n >= len { s.frame_buf_len = 0; return; }
    let new_len = len - n;
    unsafe {
        let ptr = s.frame_buf.as_mut_ptr();
        let mut i = 0usize;
        while i < new_len { *ptr.add(i) = *ptr.add(i + n); i += 1; }
    }
    s.frame_buf_len = new_len as u16;
}

fn decode_aac_frame(payload: *const u8, payload_len: usize, s: &mut AacState) -> bool {
    let mut br = BitReader::new(payload, payload_len);

    let mut have_l = false;
    let mut have_r = false;
    let mut ms_used: [[u8; MAX_SFB]; MAX_WIN_GROUPS] = [[0u8; MAX_SFB]; MAX_WIN_GROUPS];
    let mut ms_mask_present: u8 = 0;
    let mut left_gg: u8 = 0;
    let mut right_gg: u8 = 0;

    // Reset per-channel scratch.
    for v in s.spec_quant_l.iter_mut() { *v = 0; }
    for v in s.spec_quant_r.iter_mut() { *v = 0; }
    for v in s.spec_l.iter_mut() { *v = 0.0; }
    for v in s.spec_r.iter_mut() { *v = 0.0; }
    for v in s.scalefactors_l.iter_mut() { *v = 0; }
    for v in s.scalefactors_r.iter_mut() { *v = 0; }
    s.ics_info_l = IcsInfo::default();
    s.ics_info_r = IcsInfo::default();
    s.section_l = SectionData::default();
    s.section_r = SectionData::default();
    s.tns_l = TnsInfo::default();
    s.tns_r = TnsInfo::default();

    let mut audio_seen = false;
    let mut elem_count = 0;
    while br.bits_left() >= 3 && elem_count < 16 {
        let id_syn = br.read_bits(3) as u8;
        elem_count += 1;
        if id_syn == ID_END { break; }
        if audio_seen && (id_syn == ID_SCE || id_syn == ID_CPE
                          || id_syn == ID_CCE || id_syn == ID_LFE) { break; }
        match id_syn {
            ID_SCE | ID_LFE => {
                let _tag = br.read_bits(4);
                read_individual_channel(
                    s.syscalls, &mut br, false, None,
                    &mut left_gg, &mut s.ics_info_l, &mut s.section_l,
                    &mut s.scalefactors_l, &mut s.spec_quant_l,
                    &mut s.tns_l,
                );
                have_l = true; audio_seen = true;
            }
            ID_CPE => {
                            let _tag = br.read_bits(4);
                let common_window = br.read_bit() != 0;
                if common_window {
                                    let shared_info = read_ics_info(&mut br);
                                    ms_mask_present = br.read_bits(2) as u8;
                    if ms_mask_present == 1 {
                        let max_sfb = shared_info.max_sfb as usize;
                        let n_groups = shared_info.num_window_groups as usize;
                        for g in 0..n_groups {
                            for sfb in 0..max_sfb.min(MAX_SFB) {
                                ms_used[g][sfb] = br.read_bit() as u8;
                            }
                        }
                    } else if ms_mask_present == 2 {
                        for g in 0..MAX_WIN_GROUPS {
                            for sfb in 0..MAX_SFB { ms_used[g][sfb] = 1; }
                        }
                    }
                                    read_individual_channel(
                        s.syscalls, &mut br, true, Some(&shared_info),
                        &mut left_gg, &mut s.ics_info_l, &mut s.section_l,
                        &mut s.scalefactors_l, &mut s.spec_quant_l,
                        &mut s.tns_l,
                    );
                                    read_individual_channel(
                        s.syscalls, &mut br, true, Some(&shared_info),
                        &mut right_gg, &mut s.ics_info_r, &mut s.section_r,
                        &mut s.scalefactors_r, &mut s.spec_quant_r,
                        &mut s.tns_r,
                    );
                                } else {
                    read_individual_channel(
                        s.syscalls, &mut br, false, None,
                        &mut left_gg, &mut s.ics_info_l, &mut s.section_l,
                        &mut s.scalefactors_l, &mut s.spec_quant_l,
                        &mut s.tns_l,
                    );
                    read_individual_channel(
                        s.syscalls, &mut br, false, None,
                        &mut right_gg, &mut s.ics_info_r, &mut s.section_r,
                        &mut s.scalefactors_r, &mut s.spec_quant_r,
                        &mut s.tns_r,
                    );
                }
                have_l = true; have_r = true; audio_seen = true;
            }
            ID_DSE => skip_dse(&mut br),
            ID_FIL => skip_fill_element(&mut br),
            _ => break,
        }
    }

    if !have_l {
        // No audio in this frame — emit silence to keep pipeline ticking.
        for v in s.output.iter_mut() { *v = 0; }
        s.output_samples = (SAMPLES_PER_FRAME * 2) as u16;
        s.frame_count = s.frame_count.wrapping_add(1);
        return true;
    }

    // iquant → MS → IS → TNS (faad2 reconstruct_channel_pair order).
    quant_to_spec(&s.ics_info_l, &s.scalefactors_l, &s.spec_quant_l, &mut s.spec_l);
    if have_r {
        quant_to_spec(&s.ics_info_r, &s.scalefactors_r, &s.spec_quant_r, &mut s.spec_r);
        if ms_mask_present > 0 {
            ms_decode(&s.ics_info_l, &mut s.spec_l, &mut s.spec_r, &ms_used);
        }
        // Intensity stereo: bands the encoder tagged INTENSITY_HCB
        // /HCB2 on the right channel have no spectral data and need
        // reconstruction from the left × per-SFB scalefactor. cmajor.aac
        // relies on this for upper-band transient energy on the right
        // channel — without it the listener hears the missing right-
        // channel attack as "compressed fuzz at note onsets".
        is_decode(
            &s.ics_info_r, &s.section_r, &s.scalefactors_r,
            ms_mask_present, &ms_used, &s.spec_l, &mut s.spec_r,
        );
    }
    // TNS inverse filter (per-channel). No-op if `tns_data_present`
    // was 0 in the bitstream (cmajor.aac case); other content uses TNS
    // to flatten encoder-side transient shaping.
    let sr_idx = s.sample_rate_idx as usize;
    tns_decode_frame(&s.ics_info_l, &s.tns_l, &mut s.spec_l, sr_idx);
    if have_r {
        tns_decode_frame(&s.ics_info_r, &s.tns_r, &mut s.spec_r, sr_idx);
    }

    // Filter bank (per-channel; uses imdct_buf scratch sequentially).
    // Time scratch is in state (avoid 8KB stack frame).
    // Clear before filterbank.
    for v in s.time_l.iter_mut() { *v = 0.0; }
    for v in s.time_r.iter_mut() { *v = 0.0; }

    // Borrow split: filterbank needs &mut on different fields.
    let (info_l_local, info_r_local) = (s.ics_info_l, s.ics_info_r);
    let prev0 = s.prev_window_shape[0];
    let prev1 = s.prev_window_shape[1];
    {
        let (left_overlap, right_overlap) = s.overlap.split_at_mut(1);
        run_filterbank(
            &info_l_local, &s.spec_l, &mut s.time_l, &mut left_overlap[0],
            &mut s.imdct_buf, prev0,
        );
        if have_r {
            run_filterbank(
                &info_r_local, &s.spec_r, &mut s.time_r, &mut right_overlap[0],
                &mut s.imdct_buf, prev1,
            );
        } else {
            let copy_len = s.time_l.len();
            // Can't borrow s.time_l for read AND s.time_r for write. Copy manually.
            for i in 0..copy_len {
                s.time_r[i] = s.time_l[i];
            }
        }
    }
    s.prev_window_shape[0] = info_l_local.window_shape;
    if have_r { s.prev_window_shape[1] = info_r_local.window_shape; }

    let nlong = 1024;
    for n in 0..nlong {
        let l = s.time_l[n];
        let r = s.time_r[n];
        let li = if l >= 32767.0 { 32767 }
                 else if l <= -32768.0 { -32768 }
                 else { (l + if l < 0.0 { -0.5 } else { 0.5 }) as i16 };
        let ri = if r >= 32767.0 { 32767 }
                 else if r <= -32768.0 { -32768 }
                 else { (r + if r < 0.0 { -0.5 } else { 0.5 }) as i16 };
        s.output[2 * n] = li;
        s.output[2 * n + 1] = ri;
    }
    s.output_samples = (SAMPLES_PER_FRAME * 2) as u16;
    s.frame_count = s.frame_count.wrapping_add(1);
    true
}

fn read_individual_channel(
    sys: *const SyscallTable,
    br: &mut BitReader, common_window: bool, shared_info: Option<&IcsInfo>,
    out_gg: &mut u8, out_info: &mut IcsInfo, out_sd: &mut SectionData,
    out_sf: &mut [i16], out_quant: &mut [i16],
    out_tns: &mut TnsInfo,
) {
    *out_gg = br.read_bits(8) as u8;
    if !common_window {
        *out_info = read_ics_info(br);
    } else if let Some(info) = shared_info {
        *out_info = *info;
    }
    *out_sd = read_section_data(br, out_info);
    read_scalefactors(br, out_info, out_sd, *out_gg, out_sf);

    let pulse_data_present = br.read_bit();
    if pulse_data_present != 0 {
        let num_pulse = br.read_bits(2);
        br.skip_bits(6);
        for _ in 0..=num_pulse { br.skip_bits(5 + 4); }
    }
    let tns_data_present = br.read_bit();
    if tns_data_present != 0 {
        read_tns_data(br, out_info, out_tns);
    }
    let _gain_control = br.read_bit();

    read_spectral_data(br, out_info, out_sd, out_quant);
    let _ = sys;
}

fn run_filterbank(
    info: &IcsInfo, spec: &[f32], time_out: &mut [f32], overlap: &mut [f32],
    buf: &mut [f32], prev_shape: u8,
) {
    let window_long_cur  = pick_long_window(info.window_shape);
    let window_long_prev = pick_long_window(prev_shape);
    let window_short_cur  = pick_short_window(info.window_shape);
    let window_short_prev = pick_short_window(prev_shape);
    match info.window_sequence {
        ONLY_LONG_SEQUENCE => {
            ifilter_bank_long(spec, time_out, overlap, buf, window_long_cur, window_long_prev);
        }
        LONG_START_SEQUENCE => {
            ifilter_bank_long_start(spec, time_out, overlap, buf,
                window_long_prev, window_short_cur);
        }
        LONG_STOP_SEQUENCE => {
            ifilter_bank_long_stop(spec, time_out, overlap, buf,
                window_long_cur, window_short_prev);
        }
        EIGHT_SHORT_SEQUENCE => {
            ifilter_bank_eight_short(spec, time_out, overlap, buf,
                window_short_cur, window_short_prev);
        }
        _ => {}
    }
}

// ============================================================================
// Public API
// ============================================================================

pub unsafe fn aac_init(
    s: &mut AacState, syscalls: *const SyscallTable, in_chan: i32, out_chan: i32,
) {
    let state_ptr = s as *mut AacState as *mut u8;
    __aeabi_memclr(state_ptr, core::mem::size_of::<AacState>());
    s.syscalls = syscalls;
    s.in_chan = in_chan;
    s.out_chan = out_chan;
    s.object_type = 2;
    s.sample_rate_idx = 4;
    s.sample_rate = 44100;
    s.channels = 2;

}

pub unsafe fn aac_feed_detect(s: &mut AacState, buf: *const u8, len: usize) {
    let dst = s.frame_buf.as_mut_ptr();
    let mut i: usize = 0;
    while i < len && i < FRAME_BUF_SIZE {
        *dst.add(i) = *buf.add(i);
        i += 1;
    }
    s.frame_buf_len = i as u16;
}

pub unsafe fn aac_step(s: &mut AacState) -> i32 {
    let sys = &*s.syscalls;
    let in_chan = s.in_chan;
    let out_chan = s.out_chan;

    if !drain_pending(
        sys, out_chan, s.io_buf.as_ptr(),
        &mut s.pending_out, &mut s.pending_offset,
    ) { return 0; }

    if s.out_buf_pos < s.out_buf_len {
        let out_poll = (sys.channel_poll)(out_chan, POLL_OUT);
        if out_poll > 0 && ((out_poll as u32) & POLL_OUT) != 0 {
            let remaining = (s.out_buf_len - s.out_buf_pos) as usize;
            let chunk = if remaining > IO_BUF_SIZE { IO_BUF_SIZE } else { remaining };
            let chunk = chunk & !1;
            if chunk > 0 {
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
                } else if written < 0 && written != E_AGAIN { return -1; }
                if written > 0 && (written as usize) < chunk {
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

    let in_poll = (sys.channel_poll)(in_chan, POLL_IN);
    if in_poll > 0 && ((in_poll as u32) & POLL_IN) != 0 {
        let buf_free = FRAME_BUF_SIZE - (s.frame_buf_len as usize);
        if buf_free > 0 {
            let read_len = if buf_free > IO_BUF_SIZE { IO_BUF_SIZE } else { buf_free };
            let read = (sys.channel_read)(in_chan, s.io_buf.as_mut_ptr(), read_len);
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
            } else if read < 0 && read != E_AGAIN { return -1; }
        }
    }

    if s.frame_buf_len >= 7 {
        let sync_offset = find_adts_sync(s.frame_buf.as_ptr(), s.frame_buf_len as usize);
        if sync_offset > 0 { shift_frame_buf(s, sync_offset as usize); }

        if sync_offset >= 0 && s.frame_buf_len >= 7 {
            if let Some(header) = parse_adts_header(s.frame_buf.as_ptr(), s.frame_buf_len as usize) {
                let frame_len = header.frame_length as usize;
                if frame_len <= s.frame_buf_len as usize {
                    s.object_type = header.profile + 1;
                    s.sample_rate_idx = header.sample_rate_idx;
                    if (header.sample_rate_idx as usize) < 13 {
                        s.sample_rate = *SAMPLE_RATES.as_ptr().add(header.sample_rate_idx as usize);
                    }
                    s.channels = header.channel_config;
                    let data_start = header.header_size as usize;
                    let data_len = frame_len - data_start;
                    if data_len > 0 && data_start < frame_len {
                        // Copy payload into state-resident buffer to avoid
                        // pointer-aliasing UB between `payload` (slice of
                        // s.frame_buf) and `&mut s` passed into decode.
                        let copy_len = data_len.min(s.payload_buf.len());
                        let src = s.frame_buf.as_ptr().add(data_start);
                        for i in 0..copy_len {
                            s.payload_buf[i] = *src.add(i);
                        }
                        let payload_ptr = s.payload_buf.as_ptr();
                        if decode_aac_frame(payload_ptr, copy_len, s) {
                            s.out_buf_pos = 0;
                            s.out_buf_len = (s.output_samples as usize * 2) as u16;
                        }
                    }
                    shift_frame_buf(s, frame_len);
                }
            } else {
                shift_frame_buf(s, 1);
            }
        }
    }
    0
}
