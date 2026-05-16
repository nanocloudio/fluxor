// Image codec kernel — unified dispatcher for all bare-metal image
// formats. Same shape as the audio codecs (init / feed_detect /
// step), no module boilerplate — the parent `mod.rs` owns the PIC
// entry points and the detect_format dispatch.
//
// Format dispatch is internal: `ImageState::image_format` selects
// the per-format decompressor inside `decode_buffer`. Each format
// lives in its own file alongside this one — BMP inline below
// (smallest, no decompression), GIF in `image_gif.rs` (LZW), PNG
// in `image_png.rs` (DEFLATE + filters), JPEG in `image_jpeg.rs`
// (Huffman + IDCT + YCbCr). The Phase machine, channel I/O,
// nearest-neighbour scaling, and RGB565 output path are shared.
//
// Memory layout (heap, via syscalls.heap_alloc):
//   * encoded[]  — accumulator for the encoded source bytes
//                  (up to `max_bytes`, 8 MiB default = 1920×1080 24-bit + slack)
//   * pending[]  — decoded RGB565 LE frame (width × height × 2)
// Both freed and re-allocated when dimensions change; allocated
// lazily on first byte / first decode so audio-only deployments
// don't pay the cost. Per-format scratch (LZW dictionary, DEFLATE
// window, JPEG tables, etc.) is heap_alloc'd inside the decoder
// and freed before return.

use super::abi::SyscallTable;
use super::dev_log;

// ── Format dispatch ───────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum ImageFormat {
    Bmp = 0,
    Gif = 1,
    Png = 2,
    Jpeg = 3,
}

// ── Format magics ─────────────────────────────────────────────────────────
//
// Used by the parent's `detect_format` to identify the stream from
// the first few bytes. Each format-specific decoder re-checks the
// magic at the top of its `*_decode` function — `detect_format` is
// a fast happy-path commit, not a security boundary.

pub const BMP_MAGIC: &[u8; 2] = b"BM";
pub const GIF_MAGIC: &[u8; 4] = b"GIF8";              // GIF87a / GIF89a
pub const PNG_MAGIC: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
pub const JPEG_MAGIC: &[u8; 3] = b"\xff\xd8\xff";     // SOI (FF D8) + first segment marker (FF xx)

// Back-compat aliases so the BMP submodule (still inline below) can
// reference the magic bytes by their historical names.
pub const BMP_MAGIC_0: u8 = BMP_MAGIC[0];
pub const BMP_MAGIC_1: u8 = BMP_MAGIC[1];

const BMP_HEADER_LEN: usize = 54;
const IN_CHUNK: usize = 1024;
const WRITE_CHUNK: usize = 1024;
const EOF_TICKS: u32 = 200;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum Phase {
    Ingest = 0,
    Decoded = 1,
    Draining = 2,
    Error = 3,
}

// ── State ─────────────────────────────────────────────────────────────────

#[repr(C)]
pub struct ImageState {
    pub syscalls: *const SyscallTable,
    pub in_chan: i32,
    pub out_chan: i32, // pixels port

    // params (parent walks TLV into these before calling image_init)
    pub dst_w: u16,
    pub dst_h: u16,
    pub scale_mode: u8,
    _pad0: u8,
    pub max_bytes: u32,

    // accumulator
    pub(super) encoded: *mut u8,
    pub encoded_used: u32,
    encoded_cap: u32,

    // decoded RGB565 LE
    pub(super) pending: *mut u8,
    pub(super) pending_size: u32,
    pub(super) pending_pos: u32,

    // state
    pub phase: Phase,
    /// Set by the parent before `image_init` so `decode_buffer` knows
    /// which decompressor to dispatch to. Defaults to Bmp (0) so
    /// existing BMP fixtures keep working without explicit init.
    pub image_format: ImageFormat,
    /// Number of bytes in `last_err` (0 = no recorded error).
    pub(super) last_err_len: u8,
    _pad1: u8,
    /// Last decode-failure reason — sticky, surfaced via the parent's
    /// heartbeat so the rig telemetry sees the diagnosis even when
    /// log_net dropped the one-shot dev_log fired from inside
    /// `decode_buffer`.
    pub(super) last_err: [u8; 48],
    quiet_ticks: u32,
}

// ── Lifecycle ─────────────────────────────────────────────────────────────

pub unsafe fn image_init(
    s: &mut ImageState,
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
) {
    s.syscalls = syscalls;
    s.in_chan = in_chan;
    s.out_chan = out_chan;
    // params (dst_w / dst_h / scale_mode / max_bytes) are written by
    // the parent's TLV walker before image_init is called; we leave
    // them alone here. Buffers + phase are reset though.
    s.encoded = core::ptr::null_mut();
    s.encoded_used = 0;
    s.encoded_cap = 0;
    s.pending = core::ptr::null_mut();
    s.pending_size = 0;
    s.pending_pos = 0;
    s.phase = Phase::Ingest;
    s.quiet_ticks = 0;
    // `image_format` is staged by the parent's `init_codec` BEFORE
    // `image_init` is called, so we leave it untouched here.
    dev_log(&*syscalls, 3, b"[dec] image".as_ptr(), 11);
}

/// Replay the bytes the parent consumed during format detection so
/// the BMP header parser sees them. The parent feeds the
/// `detect_buf` bytes here before the first `image_step` call.
pub unsafe fn image_feed_detect(s: &mut ImageState, buf: *const u8, len: usize) {
    if !ensure_encoded(s) {
        s.phase = Phase::Error;
        return;
    }
    if s.encoded_used as usize + len > s.encoded_cap as usize {
        log(s, b"[img] detect bytes overflow");
        s.phase = Phase::Error;
        return;
    }
    core::ptr::copy_nonoverlapping(buf, s.encoded.add(s.encoded_used as usize), len);
    s.encoded_used += len as u32;
}

#[allow(dead_code)]
pub unsafe fn image_is_done(s: &ImageState) -> bool {
    matches!(s.phase, Phase::Error)
        || (matches!(s.phase, Phase::Draining) && s.pending_pos >= s.pending_size)
}

// ── Step ──────────────────────────────────────────────────────────────────

pub unsafe fn image_step(s: &mut ImageState) -> i32 {
    match s.phase {
        Phase::Error => {
            // A bad header is permanent for the current encoded
            // buffer — there's nothing the codec can do to recover
            // from a malformed file by re-running the parser. Stay
            // in Error until the upstream serves NEW bytes (= bank
            // advanced to the next file), at which point reset to
            // Ingest and start accumulating again. The freshly-read
            // bytes are replayed into the encoded buffer so they
            // become the head of the next image.
            let mut scratch = [0u8; IN_CHUNK];
            let n = ((*s.syscalls).channel_read)(s.in_chan, scratch.as_mut_ptr(), scratch.len());
            if n > 0 {
                s.encoded_used = 0;
                s.quiet_ticks = 0;
                s.phase = Phase::Ingest;
                if !ensure_encoded(s) {
                    s.phase = Phase::Error;
                } else {
                    let nn = n as usize;
                    if s.encoded_used + nn as u32 <= s.encoded_cap {
                        core::ptr::copy_nonoverlapping(
                            scratch.as_ptr(),
                            s.encoded.add(s.encoded_used as usize),
                            nn,
                        );
                        s.encoded_used += nn as u32;
                    }
                }
            }
            0
        }

        Phase::Draining => {
            if s.pending_pos < s.pending_size {
                let take = (s.pending_size - s.pending_pos).min(WRITE_CHUNK as u32);
                let w = ((*s.syscalls).channel_write)(
                    s.out_chan,
                    s.pending.add(s.pending_pos as usize),
                    take as usize,
                );
                if w > 0 {
                    s.pending_pos += w as u32;
                }
                return 0;
            }
            // Fully drained — reset for the next image. Bank's
            // IOCTL_FLUSH on the next file lines this up.
            s.pending_pos = 0;
            s.encoded_used = 0;
            s.quiet_ticks = 0;
            s.phase = Phase::Ingest;
            0
        }

        Phase::Decoded => {
            s.phase = Phase::Draining;
            0
        }

        Phase::Ingest => {
            let mut chunk = [0u8; IN_CHUNK];
            let n = ((*s.syscalls).channel_read)(s.in_chan, chunk.as_mut_ptr(), chunk.len());
            if n > 0 {
                let n = n as usize;
                if !ensure_encoded(s) {
                    s.phase = Phase::Error;
                    return 0;
                }
                if s.encoded_used + n as u32 > s.encoded_cap {
                    log(s, b"[img] encoded buffer overflow");
                    s.phase = Phase::Error;
                    return 0;
                }
                core::ptr::copy_nonoverlapping(
                    chunk.as_ptr(),
                    s.encoded.add(s.encoded_used as usize),
                    n,
                );
                s.encoded_used += n as u32;
                s.quiet_ticks = 0;
                return 0;
            }
            if s.encoded_used == 0 {
                return 0;
            }
            // EOF heuristic: `EOF_TICKS` of upstream quiet → batch decode.
            s.quiet_ticks = s.quiet_ticks.saturating_add(1);
            if s.quiet_ticks < EOF_TICKS {
                return 0;
            }
            if !decode_buffer(s) {
                s.phase = Phase::Error;
                return 0;
            }
            s.phase = Phase::Decoded;
            0
        }
    }
}

// ── Decode helpers ───────────────────────────────────────────────────────
//
// `pub(super)` so the sibling format files (`image_gif.rs`, `image_png.rs`,
// `image_jpeg.rs`) can share the encoded/pending/scaling chassis.

pub(super) unsafe fn ensure_encoded(s: &mut ImageState) -> bool {
    if !s.encoded.is_null() {
        return true;
    }
    let cap = if s.max_bytes == 0 { 8 * 1024 * 1024 } else { s.max_bytes };
    let p = ((*s.syscalls).heap_alloc)(cap);
    if p.is_null() {
        log(s, b"[img] encoded alloc failed");
        return false;
    }
    s.encoded = p;
    s.encoded_cap = cap;
    true
}

#[inline(always)]
pub(super) fn le_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

#[inline(always)]
pub(super) fn le_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

#[inline(always)]
fn le_i32(b: &[u8], off: usize) -> i32 {
    i32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

#[inline(always)]
pub(super) fn be_u16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

#[inline(always)]
pub(super) fn be_u32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Allocate or re-allocate `s.pending` to fit `dst_w × dst_h × 2`
/// bytes (RGB565 LE). Format decoders call this once per decode after
/// they have parsed their dimensions. Re-uses the buffer when the
/// size matches the previous decode.
pub(super) unsafe fn ensure_pending(s: &mut ImageState, dst_w: usize, dst_h: usize) -> bool {
    let dst_bytes = dst_w * dst_h * 2;
    if s.pending.is_null() || s.pending_size as usize != dst_bytes {
        if !s.pending.is_null() {
            ((*s.syscalls).heap_free)(s.pending);
        }
        let p = ((*s.syscalls).heap_alloc)(dst_bytes as u32);
        if p.is_null() {
            log(s, b"[img] pending alloc failed");
            return false;
        }
        s.pending = p;
        s.pending_size = dst_bytes as u32;
    }
    s.pending_pos = 0;
    true
}

/// Pack a (r,g,b) triple (each 0..=255) into RGB565 little-endian
/// at `dst[off..off+2]`.
#[inline(always)]
pub(super) unsafe fn store_rgb565(dst: *mut u8, off: usize, r: u8, g: u8, b: u8) {
    let v = (((r as u16) >> 3) << 11) | (((g as u16) >> 2) << 5) | ((b as u16) >> 3);
    *dst.add(off)     = (v & 0xFF) as u8;
    *dst.add(off + 1) = (v >> 8) as u8;
}

/// Decode `s.encoded[..s.encoded_used]` into `s.pending` (RGB565 LE).
/// Dispatch by `s.image_format`; format-specific decoders live in
/// their own files (`image_gif.rs`, `image_png.rs`, `image_jpeg.rs`)
/// and write straight into `s.pending` via the shared helpers below.
/// Returns false on any parse / format failure.
unsafe fn decode_buffer(s: &mut ImageState) -> bool {
    match s.image_format {
        ImageFormat::Bmp => bmp_decode(s),
        ImageFormat::Gif => super::image_gif::gif_decode(s),
        ImageFormat::Png => super::image_png::png_decode(s),
        ImageFormat::Jpeg => super::image_jpeg::jpeg_decode(s),
    }
}

/// BMP-specific decoder (24-bit uncompressed BI_RGB only).
unsafe fn bmp_decode(s: &mut ImageState) -> bool {
    let buf = core::slice::from_raw_parts(s.encoded, s.encoded_used as usize);
    if buf.len() < BMP_HEADER_LEN {
        log(s, b"[img] truncated header");
        return false;
    }
    if buf[0] != BMP_MAGIC_0 || buf[1] != BMP_MAGIC_1 {
        log(s, b"[img] missing BM magic");
        return false;
    }
    let pixel_offset = le_u32(buf, 10) as usize;
    let src_w = le_i32(buf, 18);
    let src_h_signed = le_i32(buf, 22);
    let bpp = le_u16(buf, 28);
    let compression = le_u32(buf, 30);

    if src_w <= 0 || src_h_signed == 0 {
        log(s, b"[img] invalid dimensions");
        return false;
    }
    if bpp != 24 {
        log(s, b"[img] only 24-bit BMP supported");
        return false;
    }
    if compression != 0 {
        log(s, b"[img] only uncompressed BI_RGB supported");
        return false;
    }
    let src_w = src_w as usize;
    let src_h = src_h_signed.unsigned_abs() as usize;
    let bottom_up = src_h_signed > 0;
    let row_stride = (src_w * 3 + 3) & !3;
    let needed = pixel_offset + row_stride * src_h;
    if needed > buf.len() {
        log(s, b"[img] pixel data truncated");
        return false;
    }

    let dst_w = s.dst_w as usize;
    let dst_h = s.dst_h as usize;
    if !ensure_pending(s, dst_w, dst_h) {
        return false;
    }

    let pixel_data = &buf[pixel_offset..pixel_offset + row_stride * src_h];

    let _ = s.scale_mode; // stretch / fit / fill — only stretch in v1

    // Precompute src_x for each dst_x to keep the divide out of the hot loop.
    let xmap_bytes = dst_w * core::mem::size_of::<u32>();
    let xmap_raw = ((*s.syscalls).heap_alloc)(xmap_bytes as u32) as *mut u32;
    if xmap_raw.is_null() {
        log(s, b"[img] xmap alloc failed");
        return false;
    }
    let xmap = core::slice::from_raw_parts_mut(xmap_raw, dst_w);
    for dx in 0..dst_w {
        xmap[dx] = (((dx as u32) * 2 + 1) * src_w as u32) / (dst_w as u32 * 2);
    }

    for dy in 0..dst_h {
        let sy_raw = (((dy as u32) * 2 + 1) * src_h as u32) / (dst_h as u32 * 2);
        let sy = if bottom_up {
            (src_h - 1).saturating_sub(sy_raw as usize)
        } else {
            sy_raw as usize
        };
        let row = &pixel_data[sy * row_stride..sy * row_stride + src_w * 3];
        let dst_row_off = dy * dst_w * 2;
        for dx in 0..dst_w {
            let sx = xmap[dx] as usize;
            let b = row[sx * 3];
            let g = row[sx * 3 + 1];
            let r = row[sx * 3 + 2];
            store_rgb565(s.pending, dst_row_off + dx * 2, r, g, b);
        }
    }

    ((*s.syscalls).heap_free)(xmap_raw as *mut u8);
    log_dims(s, b"[img] decoded ", src_w as u32, src_h as u32, dst_w as u32, dst_h as u32);
    true
}

// ── Logging helpers ──────────────────────────────────────────────────────

/// Emit a log line AND record it in `last_err` so the parent's
/// heartbeat can resurface the reason later. Used by per-format
/// decoders on every error branch — the original one-shot
/// `dev_log` from inside `decode_buffer` is often dropped by
/// log_net during early boot before its UDP stream is fully
/// draining, so the sticky copy is the reliable diagnosis path.
#[inline]
pub(super) unsafe fn log(s: &mut ImageState, msg: &[u8]) {
    dev_log(&*s.syscalls, 3, msg.as_ptr(), msg.len());
    let n = msg.len().min(s.last_err.len());
    for i in 0..n {
        s.last_err[i] = msg[i];
    }
    s.last_err_len = n as u8;
}

pub(super) unsafe fn log_dims(s: &ImageState, prefix: &[u8], sw: u32, sh: u32, dw: u32, dh: u32) {
    let mut buf = [0u8; 96];
    let p = buf.as_mut_ptr();
    let mut q = 0usize;
    let mut t = 0;
    while t < prefix.len() {
        *p.add(q) = prefix[t];
        q += 1;
        t += 1;
    }
    q += super::fmt_u32_raw(p.add(q), sw);
    *p.add(q) = b'x';
    q += 1;
    q += super::fmt_u32_raw(p.add(q), sh);
    let arrow = b" -> ";
    let mut t = 0;
    while t < arrow.len() {
        *p.add(q) = arrow[t];
        q += 1;
        t += 1;
    }
    q += super::fmt_u32_raw(p.add(q), dw);
    *p.add(q) = b'x';
    q += 1;
    q += super::fmt_u32_raw(p.add(q), dh);
    dev_log(&*s.syscalls, 3, p, q);
}
