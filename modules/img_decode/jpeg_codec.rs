//! JPEG baseline decoder — 1/8 IDCT (DC-only) for display preview.
//!
//! Decodes baseline JPEG (SOF0) using only DC coefficients from each 8×8 block,
//! producing 1 pixel per block. This gives roughly 1/8 resolution, which is
//! then scaled to the target display size via Bresenham DDA.
//!
//! Supports 4:2:0, 4:2:2, and 4:4:4 chroma subsampling.

use super::scale::ScaleParams;

// ============================================================================
// Constants
// ============================================================================

/// Maximum marker data we accumulate (DHT can be ~420 bytes)
const MARKER_BUF_SIZE: usize = 768;

/// Entropy data input buffer
const IN_BUF_SIZE: usize = 2048;

/// Reduced-resolution row buffer (RGB565)
/// For 4:2:0 at max ~512px wide: 512 × 2 rows × 2 bytes = 2048
const ROW_BUF_SIZE: usize = 2048;

/// Output row buffer (480 × 2 bytes RGB565)
const OUT_ROW_SIZE: usize = 960;

/// Maximum components
const MAX_COMP: usize = 3;

/// Maximum blocks per MCU (4:2:0 = 6)
const MAX_BLOCKS_MCU: usize = 6;

// ============================================================================
// Phases
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum JpegPhase {
    /// Parsing JFIF markers (DQT, DHT, SOF0, SOS)
    Markers = 0,
    /// Decoding entropy-coded MCU data
    ScanData = 1,
    /// Writing scaled output row to channel
    FlushRow = 2,
    /// Decoding complete
    Done = 3,
    /// Unrecoverable error
    Error = 255,
}

// ============================================================================
// Marker parse sub-states
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum MarkerState {
    /// Looking for 0xFF
    Search = 0,
    /// Got 0xFF, reading marker type
    GotFF = 1,
    /// Reading length byte 0
    Len0 = 2,
    /// Reading length byte 1
    Len1 = 3,
    /// Accumulating marker data
    Data = 4,
}

// ============================================================================
// Huffman table
// ============================================================================

#[repr(C)]
pub struct HuffTable {
    pub bits: [u8; 16],       // Code counts per bit length (1-16)
    pub vals: [u8; 162],      // Symbol values
    pub num_vals: u8,
    pub _pad: u8,
}

impl HuffTable {
    pub const fn new() -> Self {
        Self {
            bits: [0; 16],
            vals: [0; 162],
            num_vals: 0,
            _pad: 0,
        }
    }
}

// ============================================================================
// Component info
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CompInfo {
    pub h_samp: u8,
    pub v_samp: u8,
    pub quant_id: u8,
    pub dc_table: u8,
    pub ac_table: u8,
    pub _pad: u8,
}

impl CompInfo {
    pub const fn new() -> Self {
        Self { h_samp: 0, v_samp: 0, quant_id: 0, dc_table: 0, ac_table: 0, _pad: 0 }
    }
}

// ============================================================================
// JPEG State
// ============================================================================

#[repr(C)]
pub struct JpegState {
    pub phase: JpegPhase,

    // Marker parsing
    pub mk_state: MarkerState,
    pub mk_type: u8,
    pub _pad0: u8,
    pub mk_len: u16,
    pub mk_pos: u16,
    pub mk_buf: [u8; MARKER_BUF_SIZE],

    // Image info (from SOF0)
    pub width: u16,
    pub height: u16,
    pub num_comp: u8,
    pub max_h: u8,
    pub max_v: u8,
    pub sof_seen: u8,
    pub comp: [CompInfo; MAX_COMP],

    // Quantization tables (up to 4, 64 bytes each)
    pub quant: [[u8; 64]; 4],

    // Huffman tables (2 DC + 2 AC)
    pub dc_tab: [HuffTable; 2],
    pub ac_tab: [HuffTable; 2],

    // Bit reader
    pub bit_buf: u32,
    pub bits_left: u8,
    pub saw_ff: u8,
    pub eof_seen: u8,
    pub mcu_fail_log: u8,

    // Entropy input buffer
    pub in_buf: [u8; IN_BUF_SIZE],
    pub in_pos: u16,
    pub in_len: u16,

    // MCU iteration
    pub mcu_x: u16,
    pub mcu_y: u16,
    pub mcus_wide: u16,
    pub mcus_tall: u16,
    pub blocks_per_mcu: u8,
    pub _pad2: u8,
    pub restart_interval: u16,
    pub restart_count: u16,
    pub _pad3: u16,

    // DC prediction per component
    pub dc_pred: [i16; MAX_COMP],
    pub _pad4: u16,

    // Block decode order: for each block in MCU, which component?
    pub block_comp: [u8; MAX_BLOCKS_MCU],
    pub _pad5: [u8; 2],

    // Reduced-resolution row buffer (RGB565)
    pub row_buf: [u8; ROW_BUF_SIZE],
    pub row_w: u16,       // Reduced row width in pixels
    pub row_h: u8,        // Rows per MCU row (max_v)
    pub row_cur: u8,      // Current sub-row being output
    pub reduced_y: u16,   // Next reduced row index to produce

    // Scale
    pub scale: ScaleParams,

    // Output
    pub out_row: [u8; OUT_ROW_SIZE],
    pub out_pos: u16,
    pub dst_row: u16,
    pub needed_y: u16,    // Reduced row needed for current output row
    pub need_computed: u8,
    pub _pad6: u8,
}

// ============================================================================
// Marker parsing
// ============================================================================

/// Feed bytes to the marker parser. Returns true when SOS has been parsed
/// and we should transition to ScanData.
pub unsafe fn feed_markers(s: &mut JpegState, data: *const u8, len: usize) -> bool {
    let mut i = 0usize;
    while i < len {
        let b = *data.add(i);
        i += 1;

        match s.mk_state {
            MarkerState::Search => {
                if b == 0xFF {
                    s.mk_state = MarkerState::GotFF;
                }
            }
            MarkerState::GotFF => {
                if b == 0xFF {
                    // Padding FF, stay in GotFF
                } else if b == 0x00 {
                    // Stuffed byte, back to search
                    s.mk_state = MarkerState::Search;
                } else if b == 0xD8 {
                    // SOI — start of image, continue searching
                    s.mk_state = MarkerState::Search;
                } else if b == 0xD9 {
                    // EOI — end of image
                    s.phase = JpegPhase::Done;
                    return false;
                } else if b >= 0xD0 && b <= 0xD7 {
                    // Restart marker, no data
                    s.mk_state = MarkerState::Search;
                } else {
                    // Marker with length field
                    s.mk_type = b;
                    s.mk_state = MarkerState::Len0;
                }
            }
            MarkerState::Len0 => {
                s.mk_len = (b as u16) << 8;
                s.mk_state = MarkerState::Len1;
            }
            MarkerState::Len1 => {
                s.mk_len |= b as u16;
                // Length includes the 2-byte length field itself
                if s.mk_len >= 2 {
                    s.mk_len -= 2;
                }
                s.mk_pos = 0;
                if s.mk_len == 0 {
                    // Empty marker, process it
                    process_marker(s);
                    if s.mk_type == 0xDA {
                        // SOS — remaining bytes are entropy data
                        // Copy remaining input to entropy buffer
                        let remaining = len - i;
                        if remaining > 0 {
                            let copy = if remaining > IN_BUF_SIZE { IN_BUF_SIZE } else { remaining };
                            let dst = s.in_buf.as_mut_ptr();
                            let src = data.add(i);
                            let mut j = 0usize;
                            while j < copy {
                                *dst.add(j) = *src.add(j);
                                j += 1;
                            }
                            s.in_pos = 0;
                            s.in_len = copy as u16;
                        }
                        return true;
                    }
                    s.mk_state = MarkerState::Search;
                } else {
                    s.mk_state = MarkerState::Data;
                }
            }
            MarkerState::Data => {
                if (s.mk_pos as usize) < MARKER_BUF_SIZE {
                    *s.mk_buf.as_mut_ptr().add(s.mk_pos as usize) = b;
                }
                s.mk_pos += 1;
                if s.mk_pos >= s.mk_len {
                    // Marker data complete
                    process_marker(s);
                    if s.mk_type == 0xDA {
                        // SOS — remaining bytes are entropy data
                        let remaining = len - i;
                        if remaining > 0 {
                            let copy = if remaining > IN_BUF_SIZE { IN_BUF_SIZE } else { remaining };
                            let dst = s.in_buf.as_mut_ptr();
                            let src = data.add(i);
                            let mut j = 0usize;
                            while j < copy {
                                *dst.add(j) = *src.add(j);
                                j += 1;
                            }
                            s.in_pos = 0;
                            s.in_len = copy as u16;
                        }
                        return true;
                    }
                    s.mk_state = MarkerState::Search;
                }
            }
        }
    }
    false
}

/// Process a completed marker segment.
unsafe fn process_marker(s: &mut JpegState) {
    match s.mk_type {
        0xDB => parse_dqt(s),
        0xC4 => parse_dht(s),
        0xC0 => parse_sof0(s),
        0xDA => parse_sos(s),
        // Skip all other markers (APP0-APPn, COM, etc.)
        _ => {}
    }
}

/// Parse DQT (Define Quantization Table) marker.
unsafe fn parse_dqt(s: &mut JpegState) {
    let buf = s.mk_buf.as_ptr();
    let len = s.mk_pos as usize;
    let mut off = 0usize;

    while off < len {
        let pq_tq = *buf.add(off);
        off += 1;
        let precision = pq_tq >> 4; // 0 = 8-bit, 1 = 16-bit
        let table_id = (pq_tq & 0x0F) as usize;
        if table_id >= 4 { return; }

        let dst = s.quant.as_mut_ptr().add(table_id) as *mut u8;
        if precision == 0 {
            // 8-bit values
            let mut i = 0usize;
            while i < 64 && off < len {
                *dst.add(i) = *buf.add(off);
                off += 1;
                i += 1;
            }
        } else {
            // 16-bit values — take high byte only (for DC-only decode)
            let mut i = 0usize;
            while i < 64 && off + 1 < len {
                *dst.add(i) = *buf.add(off); // high byte
                off += 2;
                i += 1;
            }
        }
    }
}

/// Parse DHT (Define Huffman Table) marker.
unsafe fn parse_dht(s: &mut JpegState) {
    let buf = s.mk_buf.as_ptr();
    let len = s.mk_pos as usize;
    let mut off = 0usize;

    while off < len {
        let tc_th = *buf.add(off);
        off += 1;
        let table_class = tc_th >> 4; // 0 = DC, 1 = AC
        let table_id = (tc_th & 0x0F) as usize;
        if table_id >= 2 { return; }

        // Read 16 code counts
        let mut total_syms = 0u16;
        let mut i = 0usize;
        while i < 16 && off < len {
            let count = *buf.add(off);
            off += 1;
            if table_class == 0 {
                *s.dc_tab.as_mut_ptr().add(table_id).cast::<HuffTable>().as_mut().unwrap_unchecked().bits.as_mut_ptr().add(i) = count;
            } else {
                *s.ac_tab.as_mut_ptr().add(table_id).cast::<HuffTable>().as_mut().unwrap_unchecked().bits.as_mut_ptr().add(i) = count;
            }
            total_syms += count as u16;
            i += 1;
        }

        // Read symbol values
        let max_syms = if table_class == 0 { 16usize } else { 162usize };
        let n = if (total_syms as usize) < max_syms { total_syms as usize } else { max_syms };
        i = 0;
        while i < n && off < len {
            if table_class == 0 {
                let tab = &mut *s.dc_tab.as_mut_ptr().add(table_id);
                *tab.vals.as_mut_ptr().add(i) = *buf.add(off);
            } else {
                let tab = &mut *s.ac_tab.as_mut_ptr().add(table_id);
                *tab.vals.as_mut_ptr().add(i) = *buf.add(off);
            }
            off += 1;
            i += 1;
        }

        if table_class == 0 {
            let tab = &mut *s.dc_tab.as_mut_ptr().add(table_id);
            tab.num_vals = n as u8;
        } else {
            let tab = &mut *s.ac_tab.as_mut_ptr().add(table_id);
            tab.num_vals = n as u8;
        }
    }
}

/// Parse SOF0 (Start of Frame — baseline) marker.
unsafe fn parse_sof0(s: &mut JpegState) {
    let buf = s.mk_buf.as_ptr();
    let len = s.mk_pos as usize;
    if len < 6 { s.phase = JpegPhase::Error; return; }

    let _precision = *buf.add(0); // Should be 8 for baseline
    s.height = ((*buf.add(1) as u16) << 8) | (*buf.add(2) as u16);
    s.width = ((*buf.add(3) as u16) << 8) | (*buf.add(4) as u16);
    s.num_comp = *buf.add(5);

    if s.num_comp == 0 || s.num_comp as usize > MAX_COMP {
        s.phase = JpegPhase::Error;
        return;
    }

    if len < 6 + (s.num_comp as usize) * 3 {
        s.phase = JpegPhase::Error;
        return;
    }

    s.max_h = 1;
    s.max_v = 1;

    let mut ci = 0u8;
    while (ci as usize) < s.num_comp as usize {
        let off = 6 + (ci as usize) * 3;
        // _component_id = *buf.add(off);
        let hv = *buf.add(off + 1);
        let h = hv >> 4;
        let v = hv & 0x0F;
        let qt = *buf.add(off + 2);

        let comp = &mut *s.comp.as_mut_ptr().add(ci as usize);
        comp.h_samp = h;
        comp.v_samp = v;
        comp.quant_id = qt;

        if h > s.max_h { s.max_h = h; }
        if v > s.max_v { s.max_v = v; }

        ci += 1;
    }

    s.sof_seen = 1;
}

/// Parse SOS (Start of Scan) marker.
unsafe fn parse_sos(s: &mut JpegState) {
    let buf = s.mk_buf.as_ptr();
    let len = s.mk_pos as usize;
    if len < 1 { return; }

    let ns = *buf.add(0) as usize;
    if len < 1 + ns * 2 { return; }

    let mut i = 0usize;
    while i < ns && i < MAX_COMP {
        let off = 1 + i * 2;
        let _cs = *buf.add(off); // component selector
        let td_ta = *buf.add(off + 1);
        let td = td_ta >> 4;
        let ta = td_ta & 0x0F;

        // Map by order (i), not by component selector
        let comp = &mut *s.comp.as_mut_ptr().add(i);
        comp.dc_table = td;
        comp.ac_table = ta;

        i += 1;
    }
}

// ============================================================================
// Initialization after headers parsed
// ============================================================================

/// Prepare for entropy decoding after all headers are parsed.
/// Computes MCU grid, block order, scaling params.
pub unsafe fn init_scan(s: &mut JpegState, dst_w: u16, dst_h: u16, scale_mode: u8) {
    if s.width == 0 || s.height == 0 || s.max_h == 0 || s.max_v == 0 {
        s.phase = JpegPhase::Error;
        return;
    }

    let mcu_w = (s.max_h as u16) << 3; // max_h * 8
    let mcu_h = (s.max_v as u16) << 3; // max_v * 8

    // MCU grid dimensions (ceiling division via shift)
    // mcus_wide = (width + mcu_w - 1) / mcu_w
    s.mcus_wide = div_ceil_pow2(s.width, mcu_w);
    s.mcus_tall = div_ceil_pow2(s.height, mcu_h);

    // Build block decode order for each MCU
    let mut block_idx = 0u8;
    let mut ci = 0u8;
    while (ci as usize) < s.num_comp as usize && (block_idx as usize) < MAX_BLOCKS_MCU {
        let comp = &*s.comp.as_ptr().add(ci as usize);
        let n_blocks = (comp.h_samp as u16) * (comp.v_samp as u16);
        let mut bi = 0u16;
        while bi < n_blocks && (block_idx as usize) < MAX_BLOCKS_MCU {
            *s.block_comp.as_mut_ptr().add(block_idx as usize) = ci;
            block_idx += 1;
            bi += 1;
        }
        ci += 1;
    }
    s.blocks_per_mcu = block_idx;

    // Reduced image dimensions (1/8 IDCT: 1 pixel per 8×8 block)
    // = mcus_wide * max_h, mcus_tall * max_v
    let red_w = s.mcus_wide * (s.max_h as u16);
    let red_h = s.mcus_tall * (s.max_v as u16);
    s.row_w = red_w;
    s.row_h = s.max_v;

    // Compute scaling from reduced image to display
    s.scale = super::scale::compute_scale(red_w, red_h, dst_w, dst_h, scale_mode);

    // Reset iteration state
    s.mcu_x = 0;
    s.mcu_y = 0;
    s.dc_pred = [0; MAX_COMP];
    s.bit_buf = 0;
    s.bits_left = 0;
    s.saw_ff = 0;
    s.eof_seen = 0;
    s.dst_row = 0;
    s.out_pos = 0;
    s.reduced_y = 0;
    s.need_computed = 0;
    s.restart_count = 0;
}

/// Ceiling division where divisor is a power of 2 (8, 16, or 32).
/// JPEG MCU dimensions are always multiples of 8, so d is always a power of 2.
fn div_ceil_pow2(n: u16, d: u16) -> u16 {
    if d == 0 { return 0; }
    let shift = d.trailing_zeros();
    ((n as u32 + d as u32 - 1) >> shift) as u16
}

// ============================================================================
// Bit reader
// ============================================================================

/// Ensure at least `need` bits are available in bit_buf.
/// Returns true if enough bits available, false if need to refill from channel.
unsafe fn ensure_bits(s: &mut JpegState, need: u8) -> bool {
    while s.bits_left < need {
        if s.in_pos >= s.in_len {
            return false; // Need more input data
        }

        let b = *s.in_buf.as_ptr().add(s.in_pos as usize);
        s.in_pos += 1;

        if s.saw_ff != 0 {
            s.saw_ff = 0;
            if b == 0x00 {
                // Byte-stuffed 0xFF
                s.bit_buf = (s.bit_buf << 8) | 0xFF;
                s.bits_left += 8;
            } else if b >= 0xD0 && b <= 0xD7 {
                // Restart marker — reset DC predictors
                s.dc_pred = [0; MAX_COMP];
                s.bit_buf = 0;
                s.bits_left = 0;
                // Continue reading
            } else if b == 0xD9 {
                // EOI
                s.eof_seen = 1;
                return false;
            }
            // Other markers: skip (shouldn't happen in baseline scan)
            continue;
        }

        if b == 0xFF {
            s.saw_ff = 1;
            continue;
        }

        s.bit_buf = (s.bit_buf << 8) | (b as u32);
        s.bits_left += 8;
    }
    true
}

/// Read n bits from the bit buffer (MSB-first). Caller must ensure bits are available.
#[inline(always)]
unsafe fn get_bits(s: &mut JpegState, n: u8) -> u32 {
    s.bits_left -= n;
    (s.bit_buf >> s.bits_left) & ((1u32 << n) - 1)
}

/// Peek at the top n bits without consuming. Caller must ensure bits are available.
#[inline(always)]
unsafe fn peek_bits(s: &JpegState, n: u8) -> u32 {
    (s.bit_buf >> (s.bits_left - n)) & ((1u32 << n) - 1)
}

// ============================================================================
// Huffman decoding
// ============================================================================

/// Decode one Huffman symbol. Returns symbol value, or -1 on error.
unsafe fn huff_decode(s: &mut JpegState, table: *const HuffTable) -> i32 {
    let bits_ptr = (*table).bits.as_ptr();
    let vals_ptr = (*table).vals.as_ptr();

    let mut code: u32 = 0;
    let mut val_offset: usize = 0;
    let mut length = 0u8;

    while length < 16 {
        // Need one more bit
        if !ensure_bits(s, 1) {
            return -1;
        }
        code = (code << 1) | get_bits(s, 1);
        length += 1;

        let count = *bits_ptr.add(length as usize - 1) as u32;
        if count > 0 {
            // There are `count` codes at this length
            // First code at this length = code - (code - first_code)
            // We track codes sequentially: codes at length L start at
            // the value we compute by tracking through the tree
            if code < count {
                // This code matches
                let idx = val_offset + code as usize;
                if idx < (*table).num_vals as usize {
                    return *vals_ptr.add(idx) as i32;
                }
                return -1;
            }
            code -= count;
            val_offset += count as usize;
        }
    }

    -1 // Code too long
}

/// Receive additional bits for a DC/AC coefficient and extend sign.
unsafe fn receive_extend(s: &mut JpegState, nbits: u8) -> i16 {
    if nbits == 0 {
        return 0;
    }
    if !ensure_bits(s, nbits) {
        return 0;
    }
    let val = get_bits(s, nbits) as i32;
    // Sign extension: if MSB is 0, value is negative
    let threshold = 1i32 << (nbits - 1);
    if val < threshold {
        val as i16 + ((-1i32 << nbits) + 1) as i16
    } else {
        val as i16
    }
}

// ============================================================================
// MCU decoding
// ============================================================================

/// Decode one 8×8 block's DC coefficient (and skip all AC coefficients).
/// Returns the dequantized DC value.
unsafe fn decode_block_dc(s: &mut JpegState, comp_idx: usize) -> i32 {
    let comp = &*s.comp.as_ptr().add(comp_idx);
    let dc_tid = comp.dc_table as usize;
    let ac_tid = comp.ac_table as usize;

    // --- DC coefficient ---
    let dc_tab = s.dc_tab.as_ptr().add(if dc_tid < 2 { dc_tid } else { 0 });
    let category = huff_decode(s, dc_tab);
    if category < 0 {
        return 0; // Error, return 0
    }

    let dc_diff = receive_extend(s, category as u8);
    let pred = *s.dc_pred.as_ptr().add(comp_idx);
    let dc_val = pred as i32 + dc_diff as i32;
    *s.dc_pred.as_mut_ptr().add(comp_idx) = dc_val as i16;

    // --- Skip AC coefficients ---
    let ac_tab = s.ac_tab.as_ptr().add(if ac_tid < 2 { ac_tid } else { 0 });
    let mut k = 1u8;
    while k < 64 {
        let rs = huff_decode(s, ac_tab);
        if rs < 0 {
            break; // Error
        }
        let rs = rs as u8;
        if rs == 0x00 {
            break; // EOB — remaining coefficients are zero
        }
        let run = rs >> 4;
        let size = rs & 0x0F;
        k += run + 1;
        if size > 0 {
            // Read and discard the coefficient bits
            if !ensure_bits(s, size) {
                break;
            }
            let _ = get_bits(s, size);
        }
    }

    // Dequantize DC: dc_val * quant[0]
    let qt_id = comp.quant_id as usize;
    let qt_dc = if qt_id < 4 {
        *s.quant.as_ptr().add(qt_id).cast::<u8>() as i32
    } else {
        1
    };

    // 1/8 IDCT for DC: pixel = DC * quant[0] / 8 + 128
    // The DC coefficient in JPEG is the average * 8 (due to FDCT scaling),
    // so dividing by 8 gives the average pixel value.
    let pixel = ((dc_val * qt_dc) >> 3) + 128;
    pixel
}

/// Decode one complete MCU and write reduced-resolution pixels to row_buf.
pub unsafe fn decode_mcu(s: &mut JpegState) -> bool {
    // Collect DC values for all blocks in this MCU
    let mut dc_vals = [0i32; MAX_BLOCKS_MCU];
    let mut bi = 0u8;
    while (bi as usize) < s.blocks_per_mcu as usize {
        let comp_idx = *s.block_comp.as_ptr().add(bi as usize) as usize;
        *dc_vals.as_mut_ptr().add(bi as usize) = decode_block_dc(s, comp_idx);
        bi += 1;
    }

    if s.eof_seen != 0 || s.phase == JpegPhase::Error {
        return false;
    }

    // Convert to RGB565 and write to row_buf
    // Layout depends on subsampling:
    //   4:2:0: blocks 0-3 = Y (2×2 grid), block 4 = Cb, block 5 = Cr
    //   4:2:2: blocks 0-1 = Y (2×1), block 2 = Cb, block 3 = Cr
    //   4:4:4: block 0 = Y, block 1 = Cb, block 2 = Cr
    let max_h = s.max_h as u16;
    let max_v = s.max_v as u16;
    let mcu_x = s.mcu_x;

    if s.num_comp == 1 {
        // Grayscale
        let y_val = clamp_u8(*dc_vals.as_ptr().add(0));
        let rgb = gray_to_rgb565(y_val);
        let x = mcu_x as usize;
        let off = x * 2;
        if off + 1 < ROW_BUF_SIZE {
            *s.row_buf.as_mut_ptr().add(off) = rgb as u8;
            *s.row_buf.as_mut_ptr().add(off + 1) = (rgb >> 8) as u8;
        }
    } else {
        // YCbCr — get Cb and Cr from last two blocks
        let cb_idx = s.blocks_per_mcu as usize - 2;
        let cr_idx = s.blocks_per_mcu as usize - 1;
        let cb = clamp_u8(*dc_vals.as_ptr().add(cb_idx)) as i32;
        let cr = clamp_u8(*dc_vals.as_ptr().add(cr_idx)) as i32;

        // Y blocks are arranged in h_samp × v_samp grid for component 0
        let h = s.comp.as_ptr().add(0).read().h_samp as u16;
        let v = s.comp.as_ptr().add(0).read().v_samp as u16;

        let mut vy = 0u16;
        while vy < v {
            let mut hx = 0u16;
            while hx < h {
                let y_block_idx = (vy * h + hx) as usize;
                let y_val = clamp_u8(*dc_vals.as_ptr().add(y_block_idx)) as i32;
                let rgb = ycbcr_to_rgb565(y_val, cb, cr);

                let px = mcu_x * max_h + hx;
                let py = vy;
                // Write to row_buf at (row py, column px)
                let row_offset = (py as usize) * (s.row_w as usize) * 2;
                let col_offset = (px as usize) * 2;
                let off = row_offset + col_offset;
                if off + 1 < ROW_BUF_SIZE {
                    *s.row_buf.as_mut_ptr().add(off) = rgb as u8;
                    *s.row_buf.as_mut_ptr().add(off + 1) = (rgb >> 8) as u8;
                }

                hx += 1;
            }
            vy += 1;
        }
    }

    // Advance MCU position
    s.mcu_x += 1;
    if s.mcu_x >= s.mcus_wide {
        s.mcu_x = 0;
        s.mcu_y += 1;
    }

    // Handle restart interval
    if s.restart_interval > 0 {
        s.restart_count += 1;
        if s.restart_count >= s.restart_interval {
            s.restart_count = 0;
            // DC predictors will be reset when restart marker is encountered in bit reader
            // Align to byte boundary
            s.bits_left = 0;
            s.bit_buf = 0;
            s.saw_ff = 0;
        }
    }

    true
}

// ============================================================================
// Color conversion
// ============================================================================

/// Clamp i32 to 0-255 range.
#[inline(always)]
fn clamp_u8(val: i32) -> u8 {
    if val < 0 { 0 }
    else if val > 255 { 255 }
    else { val as u8 }
}

/// Convert YCbCr to RGB565 (ITU-R BT.601 / JPEG standard).
/// All integer math, no float, no division.
#[inline(always)]
fn ycbcr_to_rgb565(y: i32, cb: i32, cr: i32) -> u16 {
    let cb_off = cb - 128;
    let cr_off = cr - 128;

    let r = clamp_u8(y + ((359 * cr_off) >> 8));
    let g = clamp_u8(y - ((88 * cb_off + 183 * cr_off) >> 8));
    let b = clamp_u8(y + ((454 * cb_off) >> 8));

    ((r as u16 >> 3) << 11) | ((g as u16 >> 2) << 5) | (b as u16 >> 3)
}

/// Convert grayscale to RGB565.
#[inline(always)]
fn gray_to_rgb565(y: u8) -> u16 {
    let r5 = (y >> 3) as u16;
    let g6 = (y >> 2) as u16;
    let b5 = (y >> 3) as u16;
    (r5 << 11) | (g6 << 5) | b5
}

// ============================================================================
// Refill input buffer from channel
// ============================================================================

/// Try to refill the entropy input buffer from the channel.
/// Returns true if data is available, false if channel is empty.
pub unsafe fn refill_input(s: &mut JpegState, sys: &super::abi::SyscallTable, in_chan: i32) -> bool {
    // Shift remaining data to front
    if s.in_pos > 0 && s.in_len > s.in_pos {
        let remaining = (s.in_len - s.in_pos) as usize;
        let src = s.in_buf.as_ptr().add(s.in_pos as usize);
        let dst = s.in_buf.as_mut_ptr();
        let mut i = 0usize;
        while i < remaining {
            *dst.add(i) = *src.add(i);
            i += 1;
        }
        s.in_pos = 0;
        s.in_len = remaining as u16;
    } else if s.in_pos >= s.in_len {
        s.in_pos = 0;
        s.in_len = 0;
    }

    // Read more data
    let space = IN_BUF_SIZE - s.in_len as usize;
    if space == 0 {
        return true; // Buffer is full
    }

    let poll = (sys.channel_poll)(in_chan, super::POLL_IN);
    if poll <= 0 || ((poll as u8) & super::POLL_IN) == 0 {
        return s.in_len > s.in_pos; // Return true if we still have data
    }

    let dst = s.in_buf.as_mut_ptr().add(s.in_len as usize);
    let n = (sys.channel_read)(in_chan, dst, space);
    if n > 0 {
        s.in_len += n as u16;
    }

    s.in_len > s.in_pos
}
