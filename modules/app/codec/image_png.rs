// PNG decoder for the unified image codec.
//
// Pipeline: PNG signature → IHDR → IDAT chunk accumulation → zlib
// strip → DEFLATE → (optional Adam7 7-pass deinterlace) → per-
// scanline filter unfilter → bit-unpack (1/2/4/16-bit → 8) →
// colour conversion → nearest-neighbour scale → RGB565.
//
// Supported subset:
//   * IHDR: any width/height (≤ 4096 enforced).
//   * bit_depth: 1, 2, 4, 8, 16 (16-bit samples are reduced to 8-bit
//                via MSB take).
//   * colour types: 0 (grayscale), 2 (RGB), 3 (palette), 4 (G+A,
//                   alpha discarded), 6 (RGBA, alpha discarded).
//   * Compression method 0 (DEFLATE), filter method 0.
//   * interlace 0 (no interlace) AND 1 (Adam7).
//
// Memory: a zlib-IDAT accumulator, a 32 KiB DEFLATE window (inside
// the inflater), a raw-bytes buffer sized to the inflated scanline
// stream, and (for interlaced PNGs) a full-res 8-bits-per-sample
// assembly buffer all live on the heap and are freed before return.

use super::image_codec::{
    be_u32, ensure_pending, log, log_dims, store_rgb565, ImageState,
};

const PNG_SIG: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

// Adam7 interlace parameters per pass: (x_start, y_start, x_step, y_step).
const A7_X_START: [usize; 7] = [0, 4, 0, 2, 0, 1, 0];
const A7_Y_START: [usize; 7] = [0, 0, 4, 0, 2, 0, 1];
const A7_X_STEP:  [usize; 7] = [8, 8, 4, 4, 2, 2, 1];
const A7_Y_STEP:  [usize; 7] = [8, 8, 8, 4, 4, 2, 2];

pub unsafe fn png_decode(s: &mut ImageState) -> bool {
    let buf = core::slice::from_raw_parts(s.encoded, s.encoded_used as usize);
    if buf.len() < 8 + 8 + 13 + 4 {
        log(s, b"[img] png: too short");
        return false;
    }
    if &buf[0..8] != PNG_SIG {
        log(s, b"[img] png: bad sig");
        return false;
    }

    // ── IHDR ────────────────────────────────────────────────────────────
    let mut cur = 8usize;
    let (ihdr_len, ihdr_type, ihdr_data, next) = match read_chunk(buf, cur) {
        Some(c) => c,
        None => {
            log(s, b"[img] png: IHDR read fail");
            return false;
        }
    };
    if ihdr_type != *b"IHDR" || ihdr_len != 13 {
        log(s, b"[img] png: missing IHDR");
        return false;
    }
    cur = next;
    let src_w = be_u32(ihdr_data, 0) as usize;
    let src_h = be_u32(ihdr_data, 4) as usize;
    let bit_depth = ihdr_data[8];
    let colour_type = ihdr_data[9];
    let compress = ihdr_data[10];
    let filter = ihdr_data[11];
    let interlace = ihdr_data[12];
    if src_w == 0 || src_h == 0 || src_w > 4096 || src_h > 4096 {
        log(s, b"[img] png: bad dims");
        return false;
    }
    if compress != 0 || filter != 0 || interlace > 1 {
        log(s, b"[img] png: unsupported method");
        return false;
    }
    let samples = match colour_type {
        0 => 1, // grayscale
        2 => 3, // RGB
        3 => 1, // palette (1-byte index, only for bit_depth ≤ 8)
        4 => 2, // grayscale + alpha
        6 => 4, // RGBA
        _ => {
            log(s, b"[img] png: bad colour type");
            return false;
        }
    };
    let allowed_depths: u16 = match colour_type {
        0 => 0b0_0000_0001_0001_0101_0u16, // 1, 2, 4, 8, 16
        3 => 0b0_0000_0000_0001_0101_0u16, // 1, 2, 4, 8 (no 16)
        2 | 4 | 6 => 0b0_0000_0001_0001_0000_0u16, // 8, 16
        _ => 0,
    };
    let _ = allowed_depths;
    if !matches!(bit_depth, 1 | 2 | 4 | 8 | 16) {
        log(s, b"[img] png: bad bit_depth");
        return false;
    }
    if colour_type == 3 && bit_depth == 16 {
        log(s, b"[img] png: palette+16 invalid");
        return false;
    }
    if matches!(colour_type, 2 | 4 | 6) && bit_depth < 8 {
        log(s, b"[img] png: RGB needs 8/16 depth");
        return false;
    }

    // ── Walk PLTE / tRNS / IDAT / IEND ───────────────────────────────────
    let mut palette = [(0u8, 0u8, 0u8); 256];
    let mut palette_len = 0usize;
    let mut trns = [255u8; 256];
    let mut trns_len = 0usize;

    // Compute total IDAT size first so we can alloc one accumulator.
    let mut idat_total = 0usize;
    let mut walk = cur;
    let mut saw_iend = false;
    loop {
        let (clen, ctype, _cdata, cnext) = match read_chunk(buf, walk) {
            Some(c) => c,
            None => {
                log(s, b"[img] png: chunk parse fail");
                return false;
            }
        };
        if ctype == *b"IDAT" {
            idat_total += clen as usize;
        } else if ctype == *b"IEND" {
            saw_iend = true;
            break;
        }
        walk = cnext;
        if walk >= buf.len() {
            break;
        }
    }
    if !saw_iend {
        log(s, b"[img] png: no IEND");
        return false;
    }
    if idat_total == 0 {
        log(s, b"[img] png: no IDAT");
        return false;
    }

    let zlib_raw = ((*s.syscalls).heap_alloc)(idat_total as u32);
    if zlib_raw.is_null() {
        log(s, b"[img] png: zlib alloc fail");
        return false;
    }
    let zlib_buf = core::slice::from_raw_parts_mut(zlib_raw, idat_total);

    let mut zlib_pos = 0usize;
    let mut walk = cur;
    loop {
        let (clen, ctype, cdata, cnext) = match read_chunk(buf, walk) {
            Some(c) => c,
            None => {
                ((*s.syscalls).heap_free)(zlib_raw);
                return false;
            }
        };
        if ctype == *b"PLTE" {
            let entries = (clen as usize) / 3;
            if entries > 256 || cdata.len() < entries * 3 {
                ((*s.syscalls).heap_free)(zlib_raw);
                log(s, b"[img] png: bad PLTE");
                return false;
            }
            for i in 0..entries {
                palette[i] = (cdata[i * 3], cdata[i * 3 + 1], cdata[i * 3 + 2]);
            }
            palette_len = entries;
        } else if ctype == *b"tRNS" && colour_type == 3 {
            let entries = (clen as usize).min(256);
            for i in 0..entries {
                trns[i] = cdata[i];
            }
            trns_len = entries;
        } else if ctype == *b"IDAT" {
            zlib_buf[zlib_pos..zlib_pos + (clen as usize)]
                .copy_from_slice(&cdata[..clen as usize]);
            zlib_pos += clen as usize;
        } else if ctype == *b"IEND" {
            break;
        }
        walk = cnext;
    }
    let _ = trns_len;

    // ── Inflate zlib(IDAT) → raw filtered scanline stream ───────────────
    if zlib_pos < 6 {
        ((*s.syscalls).heap_free)(zlib_raw);
        log(s, b"[img] png: zlib too short");
        return false;
    }
    let cmf = zlib_buf[0];
    let flg = zlib_buf[1];
    if (cmf & 0x0F) != 8 || (flg & 0x20) != 0 {
        ((*s.syscalls).heap_free)(zlib_raw);
        log(s, b"[img] png: bad zlib header");
        return false;
    }

    // For interlaced PNGs the stream is the concatenation of 7
    // mini-images. Each pass has its own (pass_w, pass_h) and its
    // own filtered scanline group. Compute the total raw size up
    // front.
    let bits_per_pixel = (samples as u16) * (bit_depth as u16);
    let bpp_bytes = ((bits_per_pixel + 7) / 8) as usize; // for filter neighbour stride
    let row_bytes = |pixel_w: usize| -> usize {
        ((pixel_w as u32 * bits_per_pixel as u32 + 7) / 8) as usize
    };

    let raw_len = if interlace == 0 {
        src_h * (1 + row_bytes(src_w))
    } else {
        let mut total = 0usize;
        for p in 0..7 {
            let xs = A7_X_STEP[p];
            let ys = A7_Y_STEP[p];
            if xs == 0 || ys == 0 {
                continue;
            }
            let pw = (src_w.saturating_sub(A7_X_START[p]) + xs - 1) / xs;
            let ph = (src_h.saturating_sub(A7_Y_START[p]) + ys - 1) / ys;
            if pw == 0 || ph == 0 {
                continue;
            }
            total += ph * (1 + row_bytes(pw));
        }
        total
    };

    if raw_len == 0 {
        ((*s.syscalls).heap_free)(zlib_raw);
        log(s, b"[img] png: zero raw len");
        return false;
    }
    let raw_ptr = ((*s.syscalls).heap_alloc)(raw_len as u32);
    if raw_ptr.is_null() {
        ((*s.syscalls).heap_free)(zlib_raw);
        log(s, b"[img] png: raw alloc fail");
        return false;
    }

    let inflate_ok = super::image_deflate::inflate(
        &zlib_buf[2..zlib_pos - 4],
        raw_ptr,
        raw_len,
        s.syscalls,
    );
    ((*s.syscalls).heap_free)(zlib_raw);
    if !inflate_ok {
        ((*s.syscalls).heap_free)(raw_ptr);
        log(s, b"[img] png: inflate fail");
        return false;
    }

    // ── Unfilter + (if interlaced) assemble into a full-res 8bpp buf ───
    let full_samples_per_pixel = match colour_type {
        0 | 3 => 1, // 1 byte: grayscale or palette index
        2 => 3,     // RGB
        4 => 1,     // grayscale (alpha dropped)
        6 => 3,     // RGB (alpha dropped)
        _ => return false,
    };
    let full_stride = src_w * full_samples_per_pixel;
    let full_buf = ((*s.syscalls).heap_alloc)((full_stride * src_h) as u32);
    if full_buf.is_null() {
        ((*s.syscalls).heap_free)(raw_ptr);
        log(s, b"[img] png: full alloc fail");
        return false;
    }

    let raw = core::slice::from_raw_parts_mut(raw_ptr, raw_len);
    let full = core::slice::from_raw_parts_mut(full_buf, full_stride * src_h);

    if interlace == 0 {
        // Single pass = full image. Unfilter then copy bit-unpacked
        // / depth-reduced samples row-by-row into `full`.
        let rstride = 1 + row_bytes(src_w);
        if !unfilter(raw, src_w, src_h, bpp_bytes, rstride) {
            ((*s.syscalls).heap_free)(raw_ptr);
            ((*s.syscalls).heap_free)(full_buf);
            log(s, b"[img] png: unfilter fail");
            return false;
        }
        for y in 0..src_h {
            let row_in = &raw[y * rstride + 1..y * rstride + rstride];
            let row_out = &mut full[y * full_stride..y * full_stride + full_stride];
            unpack_row(
                row_in,
                row_out,
                src_w,
                bit_depth,
                samples,
                colour_type,
                full_samples_per_pixel,
            );
        }
    } else {
        // 7-pass Adam7. Walk each pass: unfilter its own scanline
        // group, unpack samples, scatter into `full` at the correct
        // (x_start + col * x_step, y_start + row * y_step) positions.
        let mut raw_off = 0usize;
        for p in 0..7 {
            let xs = A7_X_STEP[p];
            let ys = A7_Y_STEP[p];
            if xs == 0 || ys == 0 {
                continue;
            }
            let pw = (src_w.saturating_sub(A7_X_START[p]) + xs - 1) / xs;
            let ph = (src_h.saturating_sub(A7_Y_START[p]) + ys - 1) / ys;
            if pw == 0 || ph == 0 {
                continue;
            }
            let rstride = 1 + row_bytes(pw);
            let pass_len = ph * rstride;
            let pass_buf = &mut raw[raw_off..raw_off + pass_len];
            if !unfilter(pass_buf, pw, ph, bpp_bytes, rstride) {
                ((*s.syscalls).heap_free)(raw_ptr);
                ((*s.syscalls).heap_free)(full_buf);
                log(s, b"[img] png: pass unfilter fail");
                return false;
            }
            // Temporary row scratch (max width = src_w).
            let mut scratch = [0u8; 4096 * 4];
            for ry in 0..ph {
                let row_in = &pass_buf[ry * rstride + 1..ry * rstride + rstride];
                unpack_row(
                    row_in,
                    &mut scratch[..pw * full_samples_per_pixel],
                    pw,
                    bit_depth,
                    samples,
                    colour_type,
                    full_samples_per_pixel,
                );
                let dst_y = A7_Y_START[p] + ry * ys;
                for rx in 0..pw {
                    let dst_x = A7_X_START[p] + rx * xs;
                    let src_off = rx * full_samples_per_pixel;
                    let dst_off = dst_y * full_stride + dst_x * full_samples_per_pixel;
                    for k in 0..full_samples_per_pixel {
                        full[dst_off + k] = scratch[src_off + k];
                    }
                }
            }
            raw_off += pass_len;
        }
    }
    ((*s.syscalls).heap_free)(raw_ptr);

    // ── Render: scale + colour-convert → RGB565 in s.pending ───────────
    let dst_w = s.dst_w as usize;
    let dst_h = s.dst_h as usize;
    if !ensure_pending(s, dst_w, dst_h) {
        ((*s.syscalls).heap_free)(full_buf);
        return false;
    }

    let xmap_bytes = dst_w * core::mem::size_of::<u32>();
    let xmap_raw = ((*s.syscalls).heap_alloc)(xmap_bytes as u32) as *mut u32;
    if xmap_raw.is_null() {
        ((*s.syscalls).heap_free)(full_buf);
        log(s, b"[img] png: xmap alloc fail");
        return false;
    }
    let xmap = core::slice::from_raw_parts_mut(xmap_raw, dst_w);
    for dx in 0..dst_w {
        xmap[dx] = (((dx as u32) * 2 + 1) * src_w as u32) / (dst_w as u32 * 2);
    }

    for dy in 0..dst_h {
        let sy = ((((dy as u32) * 2 + 1) * src_h as u32) / (dst_h as u32 * 2)) as usize;
        let row_off = sy * full_stride;
        let dst_row_off = dy * dst_w * 2;
        for dx in 0..dst_w {
            let sx = xmap[dx] as usize;
            let px = row_off + sx * full_samples_per_pixel;
            let (r, g, b) = match colour_type {
                0 | 4 => {
                    let v = full[px];
                    (v, v, v)
                }
                2 | 6 => (full[px], full[px + 1], full[px + 2]),
                3 => {
                    let idx = full[px] as usize;
                    if idx < palette_len {
                        palette[idx]
                    } else {
                        (0, 0, 0)
                    }
                }
                _ => (0, 0, 0),
            };
            store_rgb565(s.pending, dst_row_off + dx * 2, r, g, b);
        }
    }

    ((*s.syscalls).heap_free)(xmap_raw as *mut u8);
    ((*s.syscalls).heap_free)(full_buf);

    log_dims(
        s,
        b"[img] decoded ",
        src_w as u32,
        src_h as u32,
        dst_w as u32,
        dst_h as u32,
    );
    true
}

// ── PNG chunk reader ────────────────────────────────────────────────────

fn read_chunk(buf: &[u8], pos: usize) -> Option<(u32, [u8; 4], &[u8], usize)> {
    if pos + 8 > buf.len() {
        return None;
    }
    let len = be_u32(buf, pos);
    let type_bytes = [
        buf[pos + 4],
        buf[pos + 5],
        buf[pos + 6],
        buf[pos + 7],
    ];
    let data_start = pos + 8;
    let data_end = data_start + len as usize;
    let chunk_end = data_end + 4; // skip CRC
    if chunk_end > buf.len() {
        return None;
    }
    Some((len, type_bytes, &buf[data_start..data_end], chunk_end))
}

// ── Scanline filter unfilter (in place, per-pass) ───────────────────────

unsafe fn unfilter(raw: &mut [u8], src_w: usize, src_h: usize, bpp: usize, rstride: usize) -> bool {
    let row_pixel_bytes = rstride - 1;
    for row in 0..src_h {
        let row_off = row * rstride;
        let filter = raw[row_off];
        let prev_row_off = if row > 0 { row_off - rstride } else { usize::MAX };
        for i in 0..row_pixel_bytes {
            let raw_byte = raw[row_off + 1 + i];
            let left = if i >= bpp { raw[row_off + 1 + i - bpp] } else { 0 };
            let above = if prev_row_off != usize::MAX {
                raw[prev_row_off + 1 + i]
            } else {
                0
            };
            let upper_left = if prev_row_off != usize::MAX && i >= bpp {
                raw[prev_row_off + 1 + i - bpp]
            } else {
                0
            };
            let recon = match filter {
                0 => raw_byte,
                1 => raw_byte.wrapping_add(left),
                2 => raw_byte.wrapping_add(above),
                3 => raw_byte.wrapping_add(((left as u16 + above as u16) / 2) as u8),
                4 => raw_byte.wrapping_add(paeth(left, above, upper_left)),
                _ => return false,
            };
            raw[row_off + 1 + i] = recon;
        }
    }
    let _ = src_w;
    true
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let pa = (b as i32 - c as i32).unsigned_abs() as i32;
    let pb = (a as i32 - c as i32).unsigned_abs() as i32;
    let pc = ((a as i32 + b as i32) - 2 * c as i32).unsigned_abs() as i32;
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

// ── Bit-unpack + depth reduction (1/2/4/16 → 8) ─────────────────────────
//
// Takes one row of filtered/unfiltered raw bytes (`row_in`, length =
// row_bytes(pixel_w) = ceil(pixel_w × samples × bit_depth / 8)) and
// produces one row of 8-bits-per-sample data into `row_out` (length =
// pixel_w × full_samples_per_pixel). Depth-1/2/4 samples are
// expanded by replicating the high bits across the 8-bit slot
// (255/((1<<depth)-1) scale). Depth-16 takes the high byte only.

unsafe fn unpack_row(
    row_in: &[u8],
    row_out: &mut [u8],
    pixel_w: usize,
    bit_depth: u8,
    samples: u8,
    colour_type: u8,
    out_samples_per_pixel: usize,
) {
    let s = samples as usize;
    match bit_depth {
        8 => {
            // Direct copy or drop trailing alpha channel.
            for x in 0..pixel_w {
                let in_off = x * s;
                let out_off = x * out_samples_per_pixel;
                match colour_type {
                    0 => row_out[out_off] = row_in[in_off],
                    2 => {
                        row_out[out_off] = row_in[in_off];
                        row_out[out_off + 1] = row_in[in_off + 1];
                        row_out[out_off + 2] = row_in[in_off + 2];
                    }
                    3 => row_out[out_off] = row_in[in_off],
                    4 => row_out[out_off] = row_in[in_off], // drop alpha (in_off+1)
                    6 => {
                        row_out[out_off] = row_in[in_off];
                        row_out[out_off + 1] = row_in[in_off + 1];
                        row_out[out_off + 2] = row_in[in_off + 2];
                        // alpha (in_off+3) dropped
                    }
                    _ => {}
                }
            }
        }
        16 => {
            // 2 bytes per sample. Take MSB.
            for x in 0..pixel_w {
                let in_off = x * s * 2;
                let out_off = x * out_samples_per_pixel;
                match colour_type {
                    0 => row_out[out_off] = row_in[in_off],
                    2 => {
                        row_out[out_off] = row_in[in_off];
                        row_out[out_off + 1] = row_in[in_off + 2];
                        row_out[out_off + 2] = row_in[in_off + 4];
                    }
                    4 => row_out[out_off] = row_in[in_off],
                    6 => {
                        row_out[out_off] = row_in[in_off];
                        row_out[out_off + 1] = row_in[in_off + 2];
                        row_out[out_off + 2] = row_in[in_off + 4];
                    }
                    _ => {}
                }
            }
        }
        // 1, 2, 4: sub-byte packing. Per spec bytes hold samples
        // MSB-first, padded to a byte at the end of each scanline.
        // (mask, mul) come from a literal match instead of `1<<d -
        // 1` arithmetic so the PIC linker doesn't pull in a
        // panic_const_div_by_zero — mask is provably non-zero, but
        // the analysis doesn't survive the shift.
        1 | 2 | 4 => {
            let (mask, mul) = match bit_depth {
                1 => (1u8, 255u8),
                2 => (3u8, 85u8),
                4 => (15u8, 17u8),
                _ => return,
            };
            for x in 0..pixel_w {
                let bit_idx = x * (bit_depth as usize);
                let byte_idx = bit_idx / 8;
                let shift = 8 - (bit_idx % 8) - (bit_depth as usize);
                let v = (row_in[byte_idx] >> shift) & mask;
                let out_off = x * out_samples_per_pixel;
                // colour_type ∈ {0, 3}: 1 sample per pixel.
                if colour_type == 3 {
                    row_out[out_off] = v; // palette index — leave raw
                } else {
                    row_out[out_off] = v.wrapping_mul(mul); // greyscale → expand
                }
            }
        }
        _ => {}
    }
}
