//! Image Decoder PIC Module
//!
//! Detects image format from stream header and decodes to RGB565 for display.
//! Supports BMP (24-bit uncompressed, top-down) and JPEG (baseline, 1/8 IDCT).
//!
//! # Format Detection
//!
//! First bytes of input determine codec:
//! - `BM` (2 bytes) → BMP
//! - `0xFF 0xD8` → JPEG baseline (1/8 IDCT DC-only decode)
//!
//! # Stream Reset
//!
//! When bank switches files (EOF signal), the decoder resets to format
//! detection for the next image. Follows the same pattern as audio decoder.
//!
//! # Parameters
//!
//! - `width`: output width in pixels (default 480)
//! - `height`: output height in pixels (default 480)
//! - `scale_mode`: 0=fit (letterbox), 1=fill (center-crop)
//! - `bg_color`: letterbox fill color, RGB565 (default 0x0000 = black)

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

pub mod scale;
mod bmp_codec;
pub mod jpeg_codec;

// ============================================================================
// Constants
// ============================================================================

/// Format tags
const FMT_DETECTING: u8 = 0;
const FMT_BMP: u8 = 1;
const FMT_JPEG: u8 = 2;

/// IO read buffer for detection / row feeding
const IO_BUF_SIZE: usize = 512;

/// Codec state buffer size — must be >= largest codec state.
/// Uses union overlay pattern (same as audio decoder).
const CODEC_STATE_SIZE: usize = {
    let bmp_size = core::mem::size_of::<bmp_codec::BmpState>();
    let jpeg_size = core::mem::size_of::<jpeg_codec::JpegState>();
    let mut max = bmp_size;
    if jpeg_size > max { max = jpeg_size; }
    // Align up to 4 bytes
    (max + 3) & !3
};

// ============================================================================
// Module phases
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum DecodePhase {
    /// Accumulating header bytes for format detection
    Detecting = 0,
    /// Active codec decoding
    Active = 1,
    /// Image fully decoded, output complete
    Done = 2,
}

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct ImgDecodeState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,

    phase: DecodePhase,
    format: u8,
    detect_pos: u16,

    // Config
    dst_w: u16,
    dst_h: u16,
    scale_mode: u8,
    decode_scale: u8,   // JPEG IDCT scale: 0=auto(1/8), 1=eighth, 2=quarter(future)
    bg_color: u16,

    // IO buffer (used during detection and BMP row feeding)
    io_buf: [u8; IO_BUF_SIZE],

    // Codec state overlay (BmpState or JpegState)
    codec: [u8; CODEC_STATE_SIZE],
}

impl ImgDecodeState {
    #[inline(always)]
    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }

    #[inline(always)]
    unsafe fn bmp(&mut self) -> &mut bmp_codec::BmpState {
        &mut *(self.codec.as_mut_ptr() as *mut bmp_codec::BmpState)
    }

    #[inline(always)]
    unsafe fn jpeg(&mut self) -> &mut jpeg_codec::JpegState {
        &mut *(self.codec.as_mut_ptr() as *mut jpeg_codec::JpegState)
    }
}

// ============================================================================
// Parameters
// ============================================================================

mod params_def {
    use super::ImgDecodeState;
    use super::{p_u8, p_u16};
    use super::SCHEMA_MAX;

    define_params! {
        ImgDecodeState;

        1, width, u16, 480
            => |s, d, len| { s.dst_w = p_u16(d, len, 0, 480); };

        2, height, u16, 480
            => |s, d, len| { s.dst_h = p_u16(d, len, 0, 480); };

        3, scale_mode, u8, 0, enum { fit=0, fill=1, stretch=2 }
            => |s, d, len| { s.scale_mode = p_u8(d, len, 0, 0); };

        4, bg_color, u16, 0
            => |s, d, len| { s.bg_color = p_u16(d, len, 0, 0); };

        5, decode_scale, u8, 0, enum { auto=0, eighth=1, quarter=2 }
            => |s, d, len| { s.decode_scale = p_u8(d, len, 0, 0); };
    }
}

// ============================================================================
// Reset
// ============================================================================

/// Reset decoder state for next image
unsafe fn reset_decoder(s: &mut ImgDecodeState) {
    s.phase = DecodePhase::Detecting;
    s.format = FMT_DETECTING;
    s.detect_pos = 0;

    // Zero codec union (all codec initial states want zeros)
    let cp = s.codec.as_mut_ptr();
    let mut i = 0usize;
    while i < CODEC_STATE_SIZE {
        core::ptr::write_volatile(cp.add(i), 0);
        i += 1;
    }
}

// ============================================================================
// BMP step function
// ============================================================================

/// Run one step of BMP decoding. Returns StepOutcome value.
/// Uses raw pointer for syscalls to avoid borrow conflicts.
unsafe fn bmp_step(s: *mut ImgDecodeState) -> i32 {
    let sys = &*(*s).syscalls;
    let in_chan = (*s).in_chan;
    let out_chan = (*s).out_chan;
    let dst_w = (*s).dst_w;
    let dst_h = (*s).dst_h;
    let scale_mode = (*s).scale_mode;
    let bg_color = (*s).bg_color;
    let bmp = &mut *((*s).codec.as_mut_ptr() as *mut bmp_codec::BmpState);
    let io_buf = (*s).io_buf.as_mut_ptr();

    match bmp.phase {
        bmp_codec::BmpPhase::Header => {
            // Need more header bytes
            if bmp.hdr_len as usize >= bmp_codec::BMP_HDR_SIZE {
                // Header complete — parse it
                let rc = bmp_codec::parse_header(bmp, dst_w, dst_h, scale_mode);
                if rc < 0 {
                    dev_log(sys, 1, b"[img] bmp hdr err".as_ptr(), 17);
                    bmp.phase = bmp_codec::BmpPhase::Error;
                    return 0;
                }
                if bmp.top_down == 0 {
                    dev_log(sys, 1, b"[img] bmp bottom-up unsup".as_ptr(), 25);
                    bmp.phase = bmp_codec::BmpPhase::Error;
                    return 0;
                }
                // Skip to pixel data
                let already = bmp.hdr_len as u32;
                bmp.bytes_skipped = already;
                if already >= bmp.data_offset {
                    bmp.phase = bmp_codec::BmpPhase::Decoding;
                } else {
                    bmp.phase = bmp_codec::BmpPhase::SkipToData;
                }
                dev_log(sys, 3, b"[img] bmp ok".as_ptr(), 12);
                return 2; // Burst
            }

            // Read more header data
            let poll = (sys.channel_poll)(in_chan, POLL_IN);
            if poll <= 0 || ((poll as u32) & POLL_IN) == 0 {
                return 0;
            }
            let to_read = bmp_codec::BMP_HDR_SIZE - bmp.hdr_len as usize;
            let cap = if to_read > IO_BUF_SIZE { IO_BUF_SIZE } else { to_read };
            let n = (sys.channel_read)(in_chan, io_buf, cap);
            if n > 0 {
                bmp_codec::feed_header(bmp, io_buf as *const u8, n as usize);
            }
            0
        }

        bmp_codec::BmpPhase::SkipToData => {
            let poll = (sys.channel_poll)(in_chan, POLL_IN);
            if poll <= 0 || ((poll as u32) & POLL_IN) == 0 {
                return 0;
            }
            let need = (bmp.data_offset - bmp.bytes_skipped) as usize;
            let cap = if need > IO_BUF_SIZE { IO_BUF_SIZE } else { need };
            let n = (sys.channel_read)(in_chan, io_buf, cap);
            if n > 0 {
                bmp.bytes_skipped += n as u32;
            }
            if bmp.bytes_skipped >= bmp.data_offset {
                bmp.phase = bmp_codec::BmpPhase::Decoding;
                return 2; // Burst
            }
            0
        }

        bmp_codec::BmpPhase::Decoding => {
            // Check if we're done (all destination rows output)
            if bmp.dst_row >= dst_h {
                bmp.phase = bmp_codec::BmpPhase::Done;
                (*s).phase = DecodePhase::Done;
                dev_log(sys, 3, b"[img] done".as_ptr(), 10);
                return 0;
            }

            // Top/bottom letterbox rows
            let out_y = bmp.scale.out_y;
            let out_h = bmp.scale.out_h;
            if bmp.dst_row < out_y || bmp.dst_row >= out_y + out_h {
                // Letterbox row — output solid bg_color
                bmp_codec::letterbox_row(bmp, bg_color);
                bmp.phase = bmp_codec::BmpPhase::Flushing;
                return 2; // Burst
            }

            // Determine which source row we need for this destination row
            let needed_src_y = bmp.scale.crop_y + scale::v_step(&mut bmp.scale);

            // Do we need to skip source rows to reach the needed one?
            while bmp.src_rows_read < needed_src_y {
                // Need to consume source rows we don't need
                let poll = (sys.channel_poll)(in_chan, POLL_IN);
                if poll <= 0 || ((poll as u32) & POLL_IN) == 0 {
                    return 0; // Wait for input
                }
                let stride = bmp.row_stride as usize;
                let pos = bmp.src_row_pos as usize;
                let need = stride - pos;
                let cap = if need > IO_BUF_SIZE { IO_BUF_SIZE } else { need };
                let n = (sys.channel_read)(in_chan, io_buf, cap);
                if n <= 0 {
                    return 0;
                }
                bmp.src_row_pos += n as u32;
                if bmp.src_row_pos >= stride as u32 {
                    bmp.src_row_pos = 0;
                    bmp.src_rows_read += 1;
                }
            }

            // Now read the actual source row we need
            if bmp.src_rows_read == needed_src_y {
                // Need to accumulate this row
                if bmp.row_ready == 0 {
                    let poll = (sys.channel_poll)(in_chan, POLL_IN);
                    if poll <= 0 || ((poll as u32) & POLL_IN) == 0 {
                        return 0;
                    }
                    let stride = bmp.row_stride as usize;
                    let pos = bmp.src_row_pos as usize;
                    let need = stride - pos;
                    let cap = if need > IO_BUF_SIZE { IO_BUF_SIZE } else { need };
                    let n = (sys.channel_read)(in_chan, io_buf, cap);
                    if n > 0 {
                        bmp_codec::feed_row(bmp, io_buf as *const u8, n as usize);
                    }
                    if bmp.row_ready == 0 {
                        return 0; // Need more data
                    }
                }
            }

            // Source row is ready (either fresh or reused for upscaling)
            // Scale it and prepare output
            bmp_codec::scale_row(bmp, bg_color);

            // Diagnostic: dump first 8 pixels of first output row
            if bmp.dst_row == 0 && bmp.last_src_y == 0 {
                bmp.last_src_y = 0xFFFF; // one-shot
                let hex = b"0123456789abcdef";
                // Source row bytes (first 24 = 8 pixels × 3 bytes)
                let mut lb = [0u8; 80];
                let bp = lb.as_mut_ptr();
                let tag = b"[img] src: ";
                let mut p = 0usize;
                let mut t = 0usize;
                while t < tag.len() { *bp.add(p) = *tag.as_ptr().add(t); p += 1; t += 1; }
                let mut i = 0usize;
                while i < 24 {
                    let b = *bmp.src_row.as_ptr().add(i);
                    *bp.add(p) = *hex.as_ptr().add((b >> 4) as usize); p += 1;
                    *bp.add(p) = *hex.as_ptr().add((b & 0xf) as usize); p += 1;
                    i += 1;
                }
                dev_log(sys, 3, bp, p);

                // Output row bytes (first 16 pixels = 32 bytes RGB565)
                let mut lb2 = [0u8; 80];
                let bp2 = lb2.as_mut_ptr();
                let tag2 = b"[img] out: ";
                p = 0;
                t = 0;
                while t < tag2.len() { *bp2.add(p) = *tag2.as_ptr().add(t); p += 1; t += 1; }
                i = 0;
                while i < 32 {
                    let b = *bmp.out_row.as_ptr().add(i);
                    *bp2.add(p) = *hex.as_ptr().add((b >> 4) as usize); p += 1;
                    *bp2.add(p) = *hex.as_ptr().add((b & 0xf) as usize); p += 1;
                    i += 1;
                }
                dev_log(sys, 3, bp2, p);

                // Log scale params
                let mut lb3 = [0u8; 64];
                let bp3 = lb3.as_mut_ptr();
                let tag3 = b"[img] sc cw=";
                p = 0;
                t = 0;
                while t < tag3.len() { *bp3.add(p) = *tag3.as_ptr().add(t); p += 1; t += 1; }
                p += fmt_u32_raw(bp3.add(p), bmp.scale.crop_w as u32);
                let s1 = b" ow=";
                t = 0;
                while t < s1.len() { *bp3.add(p) = *s1.as_ptr().add(t); p += 1; t += 1; }
                p += fmt_u32_raw(bp3.add(p), bmp.scale.out_w as u32);
                let s2 = b" ox=";
                t = 0;
                while t < s2.len() { *bp3.add(p) = *s2.as_ptr().add(t); p += 1; t += 1; }
                p += fmt_u32_raw(bp3.add(p), bmp.scale.out_x as u32);
                let s3 = b" cx=";
                t = 0;
                while t < s3.len() { *bp3.add(p) = *s3.as_ptr().add(t); p += 1; t += 1; }
                p += fmt_u32_raw(bp3.add(p), bmp.scale.crop_x as u32);
                dev_log(sys, 3, bp3, p);
            }

            bmp.row_ready = 0;
            bmp.phase = bmp_codec::BmpPhase::Flushing;
            2 // Burst
        }

        bmp_codec::BmpPhase::Flushing => {
            // Write output row to channel
            let out_poll = (sys.channel_poll)(out_chan, POLL_OUT);
            if out_poll <= 0 || ((out_poll as u32) & POLL_OUT) == 0 {
                return 0; // Wait for output space
            }

            let row_bytes = (dst_w as usize) * 2;
            let pos = bmp.out_pos as usize;
            let remaining = row_bytes - pos;

            let src_ptr = bmp.out_row.as_ptr().add(pos);
            let written = (sys.channel_write)(out_chan, src_ptr, remaining);
            if written > 0 {
                bmp.out_pos += written as u16;
            }

            if bmp.out_pos as usize >= row_bytes {
                // Row fully output
                bmp.out_pos = 0;
                bmp.dst_row += 1;
                bmp.phase = bmp_codec::BmpPhase::Decoding;
                return 0; // Yield — let display module drain channel
            }
            0
        }

        bmp_codec::BmpPhase::Done => 0,
        bmp_codec::BmpPhase::Error => 0,
        _ => 0,
    }
}

// ============================================================================
// JPEG step function
// ============================================================================

/// Run one step of JPEG decoding. Returns StepOutcome value.
unsafe fn jpeg_step(s: *mut ImgDecodeState) -> i32 {
    let sys = &*(*s).syscalls;
    let in_chan = (*s).in_chan;
    let out_chan = (*s).out_chan;
    let dst_w = (*s).dst_w;
    let dst_h = (*s).dst_h;
    let bg_color = (*s).bg_color;
    let jpeg = &mut *((*s).codec.as_mut_ptr() as *mut jpeg_codec::JpegState);
    let io_buf = (*s).io_buf.as_mut_ptr();

    match jpeg.phase {
        jpeg_codec::JpegPhase::Markers => {
            // Read more data and feed to marker parser
            let poll = (sys.channel_poll)(in_chan, POLL_IN);
            if poll <= 0 || ((poll as u32) & POLL_IN) == 0 {
                return 0;
            }
            let n = (sys.channel_read)(in_chan, io_buf, IO_BUF_SIZE);
            if n <= 0 { return 0; }

            // One-shot: dump first 64 bytes of file data
            let sos = jpeg_codec::feed_markers(jpeg, io_buf as *const u8, n as usize);
            if sos {
                // SOS parsed — initialize scan decoding
                if jpeg.sof_seen == 0 {
                    dev_log(sys, 1, b"[img] jpeg no sof".as_ptr(), 17);
                    jpeg.phase = jpeg_codec::JpegPhase::Error;
                    return 0;
                }
                jpeg_codec::init_scan(jpeg, dst_w, dst_h, (*s).scale_mode);
                if jpeg.phase == jpeg_codec::JpegPhase::Error {
                    dev_log(sys, 1, b"[img] jpeg init err".as_ptr(), 19);
                    return 0;
                }
                jpeg.phase = jpeg_codec::JpegPhase::ScanData;
                return 2; // Burst
            }
            if jpeg.phase == jpeg_codec::JpegPhase::Error {
                dev_log(sys, 1, b"[img] jpeg hdr err".as_ptr(), 18);
                return 0;
            }
            0
        }

        jpeg_codec::JpegPhase::ScanData => {
            // Check if all output rows done
            if jpeg.dst_row >= dst_h {
                jpeg.phase = jpeg_codec::JpegPhase::Done;
                (*s).phase = DecodePhase::Done;
                dev_log(sys, 3, b"[img] done".as_ptr(), 10);
                return 0;
            }

            // Letterbox rows (top/bottom)
            let out_y = jpeg.scale.out_y;
            let out_h = jpeg.scale.out_h;
            if jpeg.dst_row < out_y || jpeg.dst_row >= out_y + out_h {
                scale::fill_row_rgb565(jpeg.out_row.as_mut_ptr(), dst_w, bg_color);
                jpeg.out_pos = 0;
                jpeg.phase = jpeg_codec::JpegPhase::FlushRow;
                return 2;
            }

            // Compute needed reduced-resolution row for this output row
            if jpeg.need_computed == 0 {
                jpeg.needed_y = jpeg.scale.crop_y + scale::v_step(&mut jpeg.scale);
                jpeg.need_computed = 1;
            }

            // Decode MCUs until the needed reduced row is available
            if jpeg.needed_y >= jpeg.reduced_y {
                // Need more decoded data — try to refill input buffer
                if (jpeg.in_len - jpeg.in_pos) < 128 {
                    jpeg_codec::refill_input(jpeg, sys, in_chan);
                }
                if jpeg.in_len <= jpeg.in_pos {
                    return 0; // No input data available
                }

                // Decode MCUs in a batch until MCU row completes or input runs low
                let mut decoded = 0u16;
                while jpeg.needed_y >= jpeg.reduced_y {
                    if (jpeg.in_len - jpeg.in_pos) < 64 {
                        // Input running low, refill
                        jpeg_codec::refill_input(jpeg, sys, in_chan);
                        if jpeg.in_len <= jpeg.in_pos {
                            break; // No more input
                        }
                    }

                    if !jpeg_codec::decode_mcu(jpeg) {
                        if jpeg.eof_seen != 0 {
                            jpeg.phase = jpeg_codec::JpegPhase::Done;
                            (*s).phase = DecodePhase::Done;
                            return 0;
                        }
                        // Log MCU decode failure (one-time: only when no MCUs decoded yet)
                        if decoded == 0 && jpeg.mcu_fail_log == 0 {
                            jpeg.mcu_fail_log = 1;
                            let mut lb = [0u8; 48];
                            let bp = lb.as_mut_ptr();
                            let tag = b"[img] mcu fail x=";
                            let mut p = 0usize;
                            let mut t = 0usize;
                            while t < tag.len() { *bp.add(p) = *tag.as_ptr().add(t); p += 1; t += 1; }
                            p += fmt_u32_raw(bp.add(p), jpeg.mcu_x as u32);
                            *bp.add(p) = b' '; p += 1;
                            *bp.add(p) = b'y'; p += 1;
                            *bp.add(p) = b'='; p += 1;
                            p += fmt_u32_raw(bp.add(p), jpeg.mcu_y as u32);
                            *bp.add(p) = b' '; p += 1;
                            *bp.add(p) = b'b'; p += 1;
                            *bp.add(p) = b'='; p += 1;
                            p += fmt_u32_raw(bp.add(p), jpeg.bits_left as u32);
                            *bp.add(p) = b' '; p += 1;
                            *bp.add(p) = b'i'; p += 1;
                            *bp.add(p) = b'='; p += 1;
                            p += fmt_u32_raw(bp.add(p), (jpeg.in_len - jpeg.in_pos) as u32);
                            dev_log(sys, 1, bp, p);
                        }
                        break; // Error or need more data
                    }

                    decoded += 1;

                    // Check if MCU row completed (mcu_x wrapped to 0)
                    if jpeg.mcu_x == 0 {
                        jpeg.reduced_y += jpeg.row_h as u16;
                    }

                    // Limit batch size — yield to scheduler to prevent
                    // watchdog timeout on large images (252 MCUs/row for 4K)
                    if decoded >= 8 {
                        return 0; // Yield
                    }
                }

                if jpeg.needed_y >= jpeg.reduced_y {
                    return 0; // Yield — need more MCU data
                }
            }

            // Needed reduced row is now available in row_buf.
            // Determine which sub-row within the MCU row.
            let row_h = jpeg.row_h as u16;
            let sub_row = jpeg.needed_y - (jpeg.reduced_y - row_h);
            let row_offset = (sub_row as usize) * (jpeg.row_w as usize) * 2;
            let src = jpeg.row_buf.as_ptr().add(row_offset);

            // Horizontal scaling with letterboxing
            let p_out_x = jpeg.scale.out_x;
            let p_out_w = jpeg.scale.out_w;
            let p_crop_x = jpeg.scale.crop_x;
            let p_crop_w = jpeg.scale.crop_w;

            // Left letterbox
            if p_out_x > 0 {
                scale::fill_row_rgb565(jpeg.out_row.as_mut_ptr(), p_out_x, bg_color);
            }

            // Scaled content
            scale::h_scale_row_rgb565(
                src,
                p_crop_x, p_crop_w,
                jpeg.out_row.as_mut_ptr().add((p_out_x as usize) * 2),
                p_out_w,
            );

            // Right letterbox
            let right_start = p_out_x + p_out_w;
            if right_start < dst_w {
                let right_count = dst_w - right_start;
                scale::fill_row_rgb565(
                    jpeg.out_row.as_mut_ptr().add((right_start as usize) * 2),
                    right_count,
                    bg_color,
                );
            }

            jpeg.out_pos = 0;
            jpeg.need_computed = 0;
            jpeg.phase = jpeg_codec::JpegPhase::FlushRow;
            2 // Burst
        }

        jpeg_codec::JpegPhase::FlushRow => {
            let out_poll = (sys.channel_poll)(out_chan, POLL_OUT);
            if out_poll <= 0 || ((out_poll as u32) & POLL_OUT) == 0 {
                return 0;
            }

            let row_bytes = (dst_w as usize) * 2;
            let pos = jpeg.out_pos as usize;
            let remaining = row_bytes - pos;

            let src_ptr = jpeg.out_row.as_ptr().add(pos);
            let written = (sys.channel_write)(out_chan, src_ptr, remaining);
            if written > 0 {
                jpeg.out_pos += written as u16;
            }

            if jpeg.out_pos as usize >= row_bytes {
                jpeg.out_pos = 0;
                jpeg.dst_row += 1;
                jpeg.phase = jpeg_codec::JpegPhase::ScanData;
                return 0; // Yield — let display module drain channel
            }
            0
        }

        jpeg_codec::JpegPhase::Done => 0,
        jpeg_codec::JpegPhase::Error => 0,
        _ => 0,
    }
}

// ============================================================================
// Module API
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<ImgDecodeState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<ImgDecodeState>() {
            return -2;
        }

        let s = &mut *(state as *mut ImgDecodeState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.phase = DecodePhase::Detecting;
        s.format = FMT_DETECTING;
        s.detect_pos = 0;

        // Defaults
        s.dst_w = 480;
        s.dst_h = 480;
        s.scale_mode = 0;
        s.decode_scale = 0;
        s.bg_color = 0;

        // Parse params
        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;

        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        // Validate scale_mode (0=fit, 1=fill, 2=stretch)
        if s.scale_mode > 2 {
            dev_log(&*s.syscalls, 2, b"[img] unknown scale_mode, using fit".as_ptr(), 37);
            s.scale_mode = 0;
        }

        // Validate decode_scale (0=auto, 1=eighth — higher not yet implemented)
        if s.decode_scale >= 2 {
            dev_log(&*s.syscalls, 2,
                b"[img] decode_scale not yet available, using auto".as_ptr(), 48);
            s.decode_scale = 0;
        }

        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut ImgDecodeState);
        if s.syscalls.is_null() || s.in_chan < 0 || s.out_chan < 0 {
            return 0;
        }

        let sys = &*s.syscalls;

        // Check for stream reset (EOF from bank on file switch)
        // Only reset if HUP *and* no more readable data in channel
        if s.phase != DecodePhase::Detecting {
            let in_poll = (sys.channel_poll)(s.in_chan, POLL_IN | POLL_HUP);
            if (in_poll as u32) & POLL_HUP != 0
                && ((in_poll as u32) & POLL_IN) == 0
            {
                dev_channel_ioctl(sys, s.in_chan, IOCTL_FLUSH, core::ptr::null_mut());
                dev_log(sys, 3, b"[img] rst".as_ptr(), 9);
                reset_decoder(s);
                return 0;
            }
        }

        match s.phase {
            DecodePhase::Detecting => {
                let poll = (sys.channel_poll)(s.in_chan, POLL_IN);
                if poll <= 0 || ((poll as u32) & POLL_IN) == 0 {
                    return 0;
                }

                // Read a small amount for format detection (max 8 bytes)
                let pos = s.detect_pos as usize;
                let want = if 8 > pos { 8 - pos } else { 0 };
                if want == 0 {
                    dev_log(sys, 1, b"[img] unknown fmt".as_ptr(), 17);
                    s.phase = DecodePhase::Done;
                    return 0;
                }

                let n = (sys.channel_read)(s.in_chan, s.io_buf.as_mut_ptr().add(pos), want);
                if n <= 0 { return 0; }
                s.detect_pos += n as u16;

                if s.detect_pos < 2 { return 0; }

                let b0 = *s.io_buf.as_ptr();
                let b1 = *s.io_buf.as_ptr().add(1);

                // Capture values before codec accessor borrows s
                let io_ptr = s.io_buf.as_ptr();
                let det_len = s.detect_pos as usize;

                if b0 == 0x42 && b1 == 0x4D {
                    // BMP detected
                    s.format = FMT_BMP;
                    s.phase = DecodePhase::Active;
                    let bmp = s.bmp();
                    bmp.phase = bmp_codec::BmpPhase::Header;
                    bmp.hdr_len = 0;
                    bmp_codec::feed_header(bmp, io_ptr, det_len);
                    dev_log(sys, 3, b"[img] fmt=bmp".as_ptr(), 13);
                    return 2; // Burst — start BMP decode
                }

                if b0 == 0xFF && b1 == 0xD8 {
                    // JPEG detected
                    s.format = FMT_JPEG;
                    s.phase = DecodePhase::Active;
                    let jpeg = s.jpeg();
                    jpeg.phase = jpeg_codec::JpegPhase::Markers;
                    jpeg.mk_state = jpeg_codec::MarkerState::Search;
                    jpeg_codec::feed_markers(jpeg, io_ptr, det_len);
                    dev_log(sys, 3, b"[img] fmt=jpeg".as_ptr(), 14);
                    return 2; // Burst — start JPEG marker parsing
                }

                if s.detect_pos >= 8 {
                    dev_log(sys, 1, b"[img] unknown fmt".as_ptr(), 17);
                    s.phase = DecodePhase::Done;
                }
                0
            }

            DecodePhase::Active => {
                match s.format {
                    FMT_BMP => bmp_step(s as *mut ImgDecodeState),
                    FMT_JPEG => jpeg_step(s as *mut ImgDecodeState),
                    _ => 0,
                }
            }

            DecodePhase::Done => 0,
        }
    }
}

// ============================================================================
// Channel Hints
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_channel_hints"]
pub extern "C" fn module_channel_hints(out: *mut u8, max_len: usize) -> i32 {
    let hints = [
        // Request larger input buffer for pixel data throughput
        ChannelHint { port_type: 0, port_index: 0, buffer_size: 4096 },
    ];
    unsafe { write_channel_hints(out, max_len, &hints) }
}

// ============================================================================
// Panic Handler
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
