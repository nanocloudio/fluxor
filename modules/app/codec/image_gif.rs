// GIF (LZW) decoder for the unified image codec.
//
// Supports GIF87a and GIF89a, including multi-frame animation.
// Each frame is composed onto a logical-screen canvas honouring
// Graphics Control Extension (GCE) disposal methods:
//   * 0 / 1  no disposal — frame stays on canvas as-is
//   * 2      restore to background colour
//   * 3      restore to previous (pre-frame) canvas state
// Transparency from the GCE is honoured (skipped pixels preserve
// the canvas underneath).
//
// Output policy: the chassis emits a single decoded frame per
// `decode_buffer` call. For multi-frame GIFs we walk all frames
// in order so the cumulative canvas state is correct, then render
// the FINAL canvas to `s.pending` — same `[img] decoded` signal
// as the single-frame path. Per-frame streaming (animation
// playback) would need a different codec chassis surface; the
// decoder here parses every frame correctly and applies every
// disposal so that surface can be bolted on without re-doing the
// parse.
//
// Memory: LZW dictionary (~24 KiB) and a working palette-indexed
// pixel buffer for each frame plus a logical-screen RGB canvas
// (W × H × 3) are heap-allocated and freed before return.

use super::image_codec::{
    ensure_pending, le_u16, log, log_dims, store_rgb565, ImageState,
};

const LZW_MAX_BITS: u32 = 12;
const LZW_DICT_SIZE: usize = 1 << LZW_MAX_BITS;

#[derive(Clone, Copy)]
struct LzwEntry {
    prefix: u16,
    first: u8,
    suffix: u8,
}

const LZW_INVALID: u16 = 0xFFFF;

pub unsafe fn gif_decode(s: &mut ImageState) -> bool {
    let buf = core::slice::from_raw_parts(s.encoded, s.encoded_used as usize);
    if buf.len() < 13 {
        log(s, b"[img] gif: too short");
        return false;
    }
    if &buf[0..3] != b"GIF" || buf[3] != b'8' || (buf[4] != b'7' && buf[4] != b'9') || buf[5] != b'a' {
        log(s, b"[img] gif: bad magic");
        return false;
    }

    // ── Logical Screen Descriptor ──────────────────────────────────────
    let lsd = &buf[6..13];
    let logical_w = le_u16(lsd, 0) as usize;
    let logical_h = le_u16(lsd, 2) as usize;
    let packed = lsd[4];
    let gct_present = (packed & 0x80) != 0;
    let gct_size = if gct_present { 1usize << ((packed & 0x07) + 1) } else { 0 };
    let bg_index = lsd[5];
    let _ = bg_index;
    if logical_w == 0 || logical_h == 0 || logical_w > 4096 || logical_h > 4096 {
        log(s, b"[img] gif: bad LSD dims");
        return false;
    }

    let mut global_palette = [(0u8, 0u8, 0u8); 256];
    let mut cursor = 13usize;
    if gct_present {
        if cursor + gct_size * 3 > buf.len() {
            log(s, b"[img] gif: GCT truncated");
            return false;
        }
        for i in 0..gct_size {
            global_palette[i] = (buf[cursor], buf[cursor + 1], buf[cursor + 2]);
            cursor += 3;
        }
    }
    let bg_color = if gct_present && (bg_index as usize) < gct_size {
        global_palette[bg_index as usize]
    } else {
        (0u8, 0u8, 0u8)
    };

    // Logical-screen RGB canvas. Initial fill = background colour.
    let canvas_size = logical_w * logical_h * 3;
    let canvas_ptr = ((*s.syscalls).heap_alloc)(canvas_size as u32);
    if canvas_ptr.is_null() {
        log(s, b"[img] gif: canvas alloc fail");
        return false;
    }
    let canvas = core::slice::from_raw_parts_mut(canvas_ptr, canvas_size);
    for px in 0..(logical_w * logical_h) {
        canvas[px * 3] = bg_color.0;
        canvas[px * 3 + 1] = bg_color.1;
        canvas[px * 3 + 2] = bg_color.2;
    }
    // "Previous" canvas for disposal=3 (restore-to-previous).
    let prev_ptr = ((*s.syscalls).heap_alloc)(canvas_size as u32);
    if prev_ptr.is_null() {
        ((*s.syscalls).heap_free)(canvas_ptr);
        log(s, b"[img] gif: prev alloc fail");
        return false;
    }
    let prev = core::slice::from_raw_parts_mut(prev_ptr, canvas_size);
    prev.copy_from_slice(canvas);

    // Pending GCE state (applies to the next image descriptor).
    let mut gce_transparent: i16 = -1;
    let mut gce_disposal: u8 = 0;

    // Frame loop: walk blocks until trailer (0x3B).
    'frames: loop {
        if cursor >= buf.len() {
            log(s, b"[img] gif: truncated");
            ((*s.syscalls).heap_free)(canvas_ptr);
            ((*s.syscalls).heap_free)(prev_ptr);
            return false;
        }
        let intro = buf[cursor];
        cursor += 1;
        match intro {
            0x21 => {
                // Extension. label(1), then sub-blocks.
                if cursor >= buf.len() {
                    ((*s.syscalls).heap_free)(canvas_ptr);
                    ((*s.syscalls).heap_free)(prev_ptr);
                    return false;
                }
                let label = buf[cursor];
                cursor += 1;
                if label == 0xF9 {
                    // Graphics Control Extension: 4-byte body inside
                    // sub-block of size 4.
                    if cursor + 6 > buf.len() {
                        ((*s.syscalls).heap_free)(canvas_ptr);
                        ((*s.syscalls).heap_free)(prev_ptr);
                        return false;
                    }
                    let blk_size = buf[cursor] as usize;
                    if blk_size != 4 {
                        // Tolerate odd encodings — still skip via the
                        // generic sub-block walker.
                        cursor -= 1;
                        if !skip_sub_blocks(buf, &mut cursor) {
                            ((*s.syscalls).heap_free)(canvas_ptr);
                            ((*s.syscalls).heap_free)(prev_ptr);
                            return false;
                        }
                    } else {
                        let gce_packed = buf[cursor + 1];
                        // delay_time @+2..+4 (1/100 s) — ignored
                        let transp_index = buf[cursor + 4];
                        gce_disposal = (gce_packed >> 2) & 0x07;
                        let transp_flag = (gce_packed & 0x01) != 0;
                        gce_transparent = if transp_flag { transp_index as i16 } else { -1 };
                        cursor += 5; // 1 size byte + 4 body
                        // Trailer sub-block (size=0).
                        if !skip_sub_blocks(buf, &mut cursor) {
                            ((*s.syscalls).heap_free)(canvas_ptr);
                            ((*s.syscalls).heap_free)(prev_ptr);
                            return false;
                        }
                    }
                } else {
                    // Other extensions (comment, application,
                    // plain-text): skip via sub-block walker.
                    if !skip_sub_blocks(buf, &mut cursor) {
                        ((*s.syscalls).heap_free)(canvas_ptr);
                        ((*s.syscalls).heap_free)(prev_ptr);
                        return false;
                    }
                }
            }
            0x2C => {
                // Image Descriptor. Save canvas if disposal=3
                // applies AFTER this frame.
                if gce_disposal == 3 {
                    prev.copy_from_slice(canvas);
                }
                let ok = decode_one_frame(
                    s,
                    buf,
                    &mut cursor,
                    canvas,
                    prev,
                    logical_w,
                    logical_h,
                    &global_palette,
                    gct_present,
                    gce_transparent,
                    gce_disposal,
                    bg_color,
                );
                if !ok {
                    ((*s.syscalls).heap_free)(canvas_ptr);
                    ((*s.syscalls).heap_free)(prev_ptr);
                    return false;
                }
                gce_transparent = -1;
                gce_disposal = 0;
            }
            0x3B => {
                break 'frames;
            }
            _ => {
                log(s, b"[img] gif: unknown block");
                ((*s.syscalls).heap_free)(canvas_ptr);
                ((*s.syscalls).heap_free)(prev_ptr);
                return false;
            }
        }
    }

    // ── Render final canvas → s.pending (scaled, RGB565) ───────────────
    let dst_w = s.dst_w as usize;
    let dst_h = s.dst_h as usize;
    if !ensure_pending(s, dst_w, dst_h) {
        ((*s.syscalls).heap_free)(canvas_ptr);
        ((*s.syscalls).heap_free)(prev_ptr);
        return false;
    }
    let xmap_bytes = dst_w * core::mem::size_of::<u32>();
    let xmap_raw = ((*s.syscalls).heap_alloc)(xmap_bytes as u32) as *mut u32;
    if xmap_raw.is_null() {
        ((*s.syscalls).heap_free)(canvas_ptr);
        ((*s.syscalls).heap_free)(prev_ptr);
        log(s, b"[img] gif: xmap alloc fail");
        return false;
    }
    let xmap = core::slice::from_raw_parts_mut(xmap_raw, dst_w);
    for dx in 0..dst_w {
        xmap[dx] = (((dx as u32) * 2 + 1) * logical_w as u32) / (dst_w as u32 * 2);
    }
    for dy in 0..dst_h {
        let sy = ((((dy as u32) * 2 + 1) * logical_h as u32) / (dst_h as u32 * 2)) as usize;
        let row_off = sy * logical_w * 3;
        let dst_row_off = dy * dst_w * 2;
        for dx in 0..dst_w {
            let sx = xmap[dx] as usize;
            let p = row_off + sx * 3;
            store_rgb565(s.pending, dst_row_off + dx * 2, canvas[p], canvas[p + 1], canvas[p + 2]);
        }
    }
    ((*s.syscalls).heap_free)(xmap_raw as *mut u8);
    ((*s.syscalls).heap_free)(canvas_ptr);
    ((*s.syscalls).heap_free)(prev_ptr);

    log_dims(
        s,
        b"[img] decoded ",
        logical_w as u32,
        logical_h as u32,
        dst_w as u32,
        dst_h as u32,
    );
    true
}

// ── Per-frame decode + composite onto canvas ────────────────────────────

unsafe fn decode_one_frame(
    s: &mut ImageState,
    buf: &[u8],
    cursor: &mut usize,
    canvas: &mut [u8],
    prev: &mut [u8],
    logical_w: usize,
    logical_h: usize,
    global_palette: &[(u8, u8, u8); 256],
    gct_present: bool,
    gce_transparent: i16,
    gce_disposal: u8,
    bg_color: (u8, u8, u8),
) -> bool {
    // Image Descriptor: 9 bytes.
    if *cursor + 9 > buf.len() {
        log(s, b"[img] gif: img desc trunc");
        return false;
    }
    let img_left = le_u16(buf, *cursor) as usize;
    let img_top = le_u16(buf, *cursor + 2) as usize;
    let img_w = le_u16(buf, *cursor + 4) as usize;
    let img_h = le_u16(buf, *cursor + 6) as usize;
    let img_packed = buf[*cursor + 8];
    *cursor += 9;
    if img_w == 0 || img_h == 0 || img_w > 4096 || img_h > 4096 {
        log(s, b"[img] gif: bad img dims");
        return false;
    }
    if img_left + img_w > logical_w || img_top + img_h > logical_h {
        // Some GIFs encode sub-regions that overflow the logical
        // screen. Tolerate by clipping at render time — we still
        // need to decode the full LZW data so subsequent frames'
        // bit stream stays in sync.
    }
    let lct_present = (img_packed & 0x80) != 0;
    let interlaced = (img_packed & 0x40) != 0;
    let lct_size = if lct_present { 1usize << ((img_packed & 0x07) + 1) } else { 0 };

    // Frame palette: either local (if LCT set) or global (else).
    let mut palette = *global_palette;
    if lct_present {
        if *cursor + lct_size * 3 > buf.len() {
            log(s, b"[img] gif: LCT trunc");
            return false;
        }
        for i in 0..lct_size {
            palette[i] = (buf[*cursor], buf[*cursor + 1], buf[*cursor + 2]);
            *cursor += 3;
        }
    } else if !gct_present {
        log(s, b"[img] gif: no palette");
        return false;
    }

    if *cursor >= buf.len() {
        return false;
    }
    let min_code_size = buf[*cursor];
    *cursor += 1;
    if min_code_size < 2 || min_code_size > 8 {
        log(s, b"[img] gif: bad min code");
        return false;
    }

    let indexed = ((*s.syscalls).heap_alloc)((img_w * img_h) as u32);
    if indexed.is_null() {
        log(s, b"[img] gif: indexed alloc fail");
        return false;
    }
    let dict_bytes = LZW_DICT_SIZE * core::mem::size_of::<LzwEntry>();
    let dict_raw = ((*s.syscalls).heap_alloc)(dict_bytes as u32) as *mut LzwEntry;
    if dict_raw.is_null() {
        ((*s.syscalls).heap_free)(indexed);
        log(s, b"[img] gif: dict alloc fail");
        return false;
    }
    let dict = core::slice::from_raw_parts_mut(dict_raw, LZW_DICT_SIZE);

    let ok = lzw_decode(buf, cursor, min_code_size, dict, indexed, img_w * img_h);
    ((*s.syscalls).heap_free)(dict_raw as *mut u8);
    if !ok {
        ((*s.syscalls).heap_free)(indexed);
        log(s, b"[img] gif: lzw decode fail");
        return false;
    }

    // De-interlace if needed.
    let pixel_src = if interlaced {
        let scratch = ((*s.syscalls).heap_alloc)((img_w * img_h) as u32);
        if scratch.is_null() {
            ((*s.syscalls).heap_free)(indexed);
            log(s, b"[img] gif: deint alloc fail");
            return false;
        }
        deinterlace(indexed, scratch, img_w, img_h);
        ((*s.syscalls).heap_free)(indexed);
        scratch
    } else {
        indexed
    };

    // Composite frame pixels onto the canvas, honouring transparency.
    let clip_w = if img_left + img_w > logical_w { logical_w.saturating_sub(img_left) } else { img_w };
    let clip_h = if img_top + img_h > logical_h { logical_h.saturating_sub(img_top) } else { img_h };
    for ry in 0..clip_h {
        let src_row = ry * img_w;
        let dst_row = (img_top + ry) * logical_w + img_left;
        for rx in 0..clip_w {
            let idx = *pixel_src.add(src_row + rx) as i16;
            if idx == gce_transparent {
                continue;
            }
            let (r, g, b) = palette[idx as usize];
            let p = (dst_row + rx) * 3;
            canvas[p] = r;
            canvas[p + 1] = g;
            canvas[p + 2] = b;
        }
    }
    ((*s.syscalls).heap_free)(pixel_src);

    // Apply disposal AFTER this frame's pixels are visible — affects
    // the canvas state seen by the NEXT frame's compositing.
    match gce_disposal {
        2 => {
            // Restore-to-background within this frame's bounding box.
            for ry in 0..clip_h {
                let dst_row = (img_top + ry) * logical_w + img_left;
                for rx in 0..clip_w {
                    let p = (dst_row + rx) * 3;
                    canvas[p] = bg_color.0;
                    canvas[p + 1] = bg_color.1;
                    canvas[p + 2] = bg_color.2;
                }
            }
        }
        3 => {
            // Restore-to-previous: replace canvas with `prev`.
            canvas.copy_from_slice(prev);
        }
        _ => {} // 0/1: leave as is
    }
    true
}

// ── Sub-block walker ─────────────────────────────────────────────────────

unsafe fn skip_sub_blocks(buf: &[u8], cursor: &mut usize) -> bool {
    loop {
        if *cursor >= buf.len() {
            return false;
        }
        let n = buf[*cursor] as usize;
        *cursor += 1;
        if n == 0 {
            return true;
        }
        if *cursor + n > buf.len() {
            return false;
        }
        *cursor += n;
    }
}

// ── LZW decoder ──────────────────────────────────────────────────────────

unsafe fn lzw_decode(
    buf: &[u8],
    cursor: &mut usize,
    min_code_size: u8,
    dict: &mut [LzwEntry],
    out: *mut u8,
    out_len: usize,
) -> bool {
    let clear_code = 1u16 << min_code_size;
    let eoi_code = clear_code + 1;

    for i in 0..(clear_code as usize) {
        dict[i] = LzwEntry { prefix: LZW_INVALID, first: i as u8, suffix: i as u8 };
    }

    let mut next_code = (eoi_code + 1) as u32;
    let mut code_size = (min_code_size + 1) as u32;
    let mut max_code = 1u32 << code_size;
    let mut prev_code: u32 = LZW_INVALID as u32;

    let mut bit_buf: u32 = 0;
    let mut bit_count: u32 = 0;
    let mut sub_block_remaining: usize = 0;

    let mut out_pos: usize = 0;
    let mut stack = [0u8; LZW_DICT_SIZE];

    loop {
        while bit_count < code_size {
            if sub_block_remaining == 0 {
                if *cursor >= buf.len() {
                    return false;
                }
                let n = buf[*cursor] as usize;
                *cursor += 1;
                if n == 0 {
                    return out_pos == out_len;
                }
                sub_block_remaining = n;
            }
            if *cursor >= buf.len() {
                return false;
            }
            bit_buf |= (buf[*cursor] as u32) << bit_count;
            *cursor += 1;
            sub_block_remaining -= 1;
            bit_count += 8;
        }
        let code = (bit_buf & ((1u32 << code_size) - 1)) as u32;
        bit_buf >>= code_size;
        bit_count -= code_size;

        if code == eoi_code as u32 {
            while sub_block_remaining > 0 {
                if *cursor >= buf.len() {
                    return false;
                }
                *cursor += 1;
                sub_block_remaining -= 1;
            }
            return skip_sub_blocks(buf, cursor) && out_pos == out_len;
        }

        if code == clear_code as u32 {
            next_code = (eoi_code + 1) as u32;
            code_size = (min_code_size + 1) as u32;
            max_code = 1u32 << code_size;
            prev_code = LZW_INVALID as u32;
            continue;
        }

        let expand_code = if code < next_code {
            code
        } else if code == next_code && prev_code != LZW_INVALID as u32 {
            prev_code
        } else {
            return false;
        };

        let mut walk = expand_code as u16;
        let mut sp = 0usize;
        loop {
            stack[sp] = dict[walk as usize].suffix;
            sp += 1;
            if dict[walk as usize].prefix == LZW_INVALID {
                break;
            }
            walk = dict[walk as usize].prefix;
            if sp >= stack.len() {
                return false;
            }
        }
        let first_byte = stack[sp - 1];
        while sp > 0 {
            sp -= 1;
            if out_pos >= out_len {
                return out_pos == out_len;
            }
            *out.add(out_pos) = stack[sp];
            out_pos += 1;
        }
        if code == next_code && prev_code != LZW_INVALID as u32 {
            if out_pos < out_len {
                *out.add(out_pos) = first_byte;
                out_pos += 1;
            }
        }

        if prev_code != LZW_INVALID as u32 && (next_code as usize) < LZW_DICT_SIZE {
            dict[next_code as usize] = LzwEntry {
                prefix: prev_code as u16,
                first: dict[prev_code as usize].first,
                suffix: first_byte,
            };
            next_code += 1;
            if next_code == max_code && code_size < LZW_MAX_BITS {
                code_size += 1;
                max_code = 1u32 << code_size;
            }
        }
        prev_code = code;
    }
}

// ── De-interlace ─────────────────────────────────────────────────────────

unsafe fn deinterlace(src: *const u8, dst: *mut u8, w: usize, h: usize) {
    const STARTS: [usize; 4] = [0, 4, 2, 1];
    const STEPS: [usize; 4] = [8, 8, 4, 2];
    let mut src_y = 0usize;
    for pass in 0..4 {
        let mut y = STARTS[pass];
        while y < h {
            core::ptr::copy_nonoverlapping(
                src.add(src_y * w),
                dst.add(y * w),
                w,
            );
            src_y += 1;
            y += STEPS[pass];
        }
    }
}
