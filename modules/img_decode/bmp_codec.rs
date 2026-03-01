//! BMP codec — parses BMP headers and decodes rows to RGB565.
//!
//! Supports 24-bit uncompressed BMPs only (biCompression=0).
//! Handles both top-down (negative height) and bottom-up (positive height).
//! Bottom-up BMPs are rejected for streaming since we can't seek backward.

use super::scale::{ScaleParams, compute_scale, v_step, h_scale_row_rgb888, fill_row_rgb565};

/// BMP file header size (BITMAPFILEHEADER)
const BMP_FILE_HDR: usize = 14;
/// BMP info header size (BITMAPINFOHEADER)
const BMP_INFO_HDR: usize = 40;
/// Minimum total header size
pub const BMP_HDR_SIZE: usize = BMP_FILE_HDR + BMP_INFO_HDR;

/// Maximum source row width (pixels) we support
const MAX_SRC_WIDTH: usize = 2730;  // 8192 / 3 bytes per pixel

/// Source row buffer size (RGB888)
pub const SRC_ROW_BUF: usize = MAX_SRC_WIDTH * 3;

/// Output row buffer size (RGB565, 480px)
pub const OUT_ROW_BUF: usize = 480 * 2;

/// BMP decode phase
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum BmpPhase {
    /// Accumulating header bytes
    Header = 0,
    /// Skipping to pixel data offset
    SkipToData = 1,
    /// Reading pixel rows
    Decoding = 2,
    /// Flushing output row
    Flushing = 3,
    /// Image complete
    Done = 4,
    /// Error state
    Error = 255,
}

/// BMP codec state
#[repr(C)]
pub struct BmpState {
    pub phase: BmpPhase,
    pub _pad0: u8,
    // Image properties from header
    pub img_width: u16,
    pub img_height: u16,
    pub bits_per_pixel: u16,
    pub top_down: u8,
    pub _pad1: u8,
    pub data_offset: u32,
    pub row_stride: u32,      // Bytes per source row (padded to 4-byte boundary)
    // Header accumulation
    pub hdr_buf: [u8; BMP_HDR_SIZE],
    pub hdr_len: u8,
    pub _pad2: u8,
    // Row reading state
    pub bytes_skipped: u32,   // Bytes skipped toward data_offset
    pub src_row_pos: u32,     // Bytes accumulated in current source row
    pub src_rows_read: u16,   // Number of source rows fully read
    pub _pad3: u16,
    // Scaling
    pub scale: ScaleParams,
    pub dst_row: u16,         // Current destination row being output
    pub out_pos: u16,         // Bytes written from current output row
    // Pending source row for vertical DDA (need to track which src_y was last)
    pub last_src_y: u16,
    pub row_ready: u8,        // Current source row is fully decoded
    pub _pad4: u8,
    // Buffers
    pub src_row: [u8; SRC_ROW_BUF],
    pub out_row: [u8; OUT_ROW_BUF],
}

/// Parse BMP header. Returns 0 on success, negative on error.
pub fn parse_header(s: &mut BmpState, dst_w: u16, dst_h: u16, scale_mode: u8) -> i32 {
    let h = &s.hdr_buf;

    // Validate BMP signature
    let b0 = unsafe { *h.as_ptr().add(0) };
    let b1 = unsafe { *h.as_ptr().add(1) };
    if b0 != 0x42 || b1 != 0x4D {
        return -1; // Not a BMP
    }

    // Data offset (bytes 10-13)
    s.data_offset = read_u32_le(h, 10);

    // Info header size (bytes 14-17), must be >= 40
    let info_size = read_u32_le(h, 14);
    if info_size < 40 {
        return -2; // Unsupported header type
    }

    // Width (bytes 18-21, signed but always positive)
    let width = read_u32_le(h, 18);
    if width == 0 || width > MAX_SRC_WIDTH as u32 {
        return -3; // Width out of range
    }
    s.img_width = width as u16;

    // Height (bytes 22-25, signed: negative = top-down)
    let raw_height = read_i32_le(h, 22);
    if raw_height == 0 {
        return -4;
    }
    if raw_height < 0 {
        s.top_down = 1;
        s.img_height = (0i32.wrapping_sub(raw_height)) as u16;
    } else {
        s.top_down = 0;
        s.img_height = raw_height as u16;
    }

    // Bits per pixel (bytes 28-29)
    s.bits_per_pixel = read_u16_le(h, 28);
    if s.bits_per_pixel != 24 {
        return -5; // Only 24-bit supported
    }

    // Compression (bytes 30-33), must be 0 (BI_RGB)
    let compression = read_u32_le(h, 30);
    if compression != 0 {
        return -6; // Only uncompressed supported
    }

    // Row stride: each row is padded to 4-byte boundary
    // stride = ((width * bpp + 31) / 32) * 4
    // Without division: stride = ((width * 3) + 3) & !3
    let raw_stride = (s.img_width as u32) * 3;
    s.row_stride = (raw_stride + 3) & !3;

    // Compute scaling parameters
    s.scale = compute_scale(s.img_width, s.img_height, dst_w, dst_h, scale_mode);

    0
}

/// Process incoming bytes during header accumulation.
/// Returns number of bytes consumed.
pub unsafe fn feed_header(s: &mut BmpState, data: *const u8, len: usize) -> usize {
    let need = BMP_HDR_SIZE - s.hdr_len as usize;
    let take = if len < need { len } else { need };

    let dst = s.hdr_buf.as_mut_ptr().add(s.hdr_len as usize);
    let mut i: usize = 0;
    while i < take {
        *dst.add(i) = *data.add(i);
        i += 1;
    }
    s.hdr_len += take as u8;
    take
}

/// Process incoming bytes during skip-to-data phase.
/// Returns number of bytes consumed.
pub fn feed_skip(s: &mut BmpState, len: usize) -> usize {
    let need = s.data_offset - s.bytes_skipped;
    let available = len as u32;
    let skip = if available < need { available } else { need };
    s.bytes_skipped += skip;
    skip as usize
}

/// Process incoming bytes during row decoding.
/// Accumulates source row bytes. When a full row is read, marks row_ready.
/// Returns number of bytes consumed.
pub unsafe fn feed_row(s: &mut BmpState, data: *const u8, len: usize) -> usize {
    let row_bytes = s.row_stride as usize;
    let pos = s.src_row_pos as usize;
    let need = row_bytes - pos;
    let take = if len < need { len } else { need };

    // Copy pixel data into source row buffer (only up to actual pixel bytes)
    let pixel_bytes = (s.img_width as usize) * 3;
    let dst = s.src_row.as_mut_ptr();
    let mut i: usize = 0;
    while i < take {
        let dst_pos = pos + i;
        if dst_pos < pixel_bytes {
            *dst.add(dst_pos) = *data.add(i);
        }
        // Skip padding bytes (just consume them)
        i += 1;
    }
    s.src_row_pos += take as u32;

    if s.src_row_pos >= row_bytes as u32 {
        s.src_row_pos = 0;
        s.src_rows_read += 1;
        s.row_ready = 1;
    }

    take
}

/// Scale the current source row into the output buffer.
/// Should be called when row_ready=1 and the source row matches
/// the current destination row's required source Y.
pub unsafe fn scale_row(s: &mut BmpState, bg_color: u16) {
    let out = s.out_row.as_mut_ptr();
    let dst_w = s.scale.dst_w;
    let out_x = s.scale.out_x;
    let out_w = s.scale.out_w;

    // Fill left letterbox region
    if out_x > 0 {
        fill_row_rgb565(out, out_x, bg_color);
    }

    // Scale source row into output region
    h_scale_row_rgb888(
        s.src_row.as_ptr(),
        s.scale.crop_x,
        s.scale.crop_w,
        out.add((out_x as usize) * 2),
        out_w,
    );

    // Fill right letterbox region
    let right_start = out_x + out_w;
    if right_start < dst_w {
        fill_row_rgb565(
            out.add((right_start as usize) * 2),
            dst_w - right_start,
            bg_color,
        );
    }

    s.out_pos = 0;
}

/// Generate a full letterbox row (all bg_color) for top/bottom padding.
pub unsafe fn letterbox_row(s: &mut BmpState, bg_color: u16) {
    fill_row_rgb565(s.out_row.as_mut_ptr(), s.scale.dst_w, bg_color);
    s.out_pos = 0;
}

// ============================================================================
// Helper functions — read little-endian values without array indexing
// ============================================================================

fn read_u16_le(buf: &[u8; BMP_HDR_SIZE], offset: usize) -> u16 {
    let p = buf.as_ptr();
    unsafe {
        let lo = *p.add(offset) as u16;
        let hi = *p.add(offset + 1) as u16;
        lo | (hi << 8)
    }
}

fn read_u32_le(buf: &[u8; BMP_HDR_SIZE], offset: usize) -> u32 {
    let p = buf.as_ptr();
    unsafe {
        let b0 = *p.add(offset) as u32;
        let b1 = *p.add(offset + 1) as u32;
        let b2 = *p.add(offset + 2) as u32;
        let b3 = *p.add(offset + 3) as u32;
        b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }
}

fn read_i32_le(buf: &[u8; BMP_HDR_SIZE], offset: usize) -> i32 {
    read_u32_le(buf, offset) as i32
}
