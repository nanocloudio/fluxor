//! Bresenham nearest-neighbor image scaling (no division operator).
//!
//! Uses DDA (digital differential analyzer) accumulators to map source
//! pixels to destination pixels without requiring division.

/// Scaling mode
pub const SCALE_FIT: u8 = 0;      // Scale uniformly, letterbox with bg_color
pub const SCALE_FILL: u8 = 1;     // Scale uniformly, center-crop overflow
pub const SCALE_STRETCH: u8 = 2;  // Non-aspect-preserving stretch to fill display

/// Pre-computed scaling parameters (computed once per image).
#[repr(C)]
pub struct ScaleParams {
    // Source dimensions
    pub src_w: u16,
    pub src_h: u16,
    // Destination (display) dimensions
    pub dst_w: u16,
    pub dst_h: u16,
    // Actual output region within destination (after fit/fill)
    pub out_x: u16,      // X offset into destination
    pub out_y: u16,      // Y offset into destination
    pub out_w: u16,      // Output region width
    pub out_h: u16,      // Output region height
    // Source crop region (for fill mode center-crop)
    pub crop_x: u16,     // X offset into source
    pub crop_y: u16,     // Y offset into source
    pub crop_w: u16,     // Cropped source width
    pub crop_h: u16,     // Cropped source height
    // Vertical DDA state
    pub v_error: u32,
    pub v_src_y: u16,
    pub _pad: u16,
}

/// Compute scaling parameters for an image.
/// Uses only multiplication, subtraction, comparison — no division.
pub fn compute_scale(
    src_w: u16, src_h: u16,
    dst_w: u16, dst_h: u16,
    mode: u8,
) -> ScaleParams {
    let mut p = ScaleParams {
        src_w, src_h, dst_w, dst_h,
        out_x: 0, out_y: 0,
        out_w: dst_w, out_h: dst_h,
        crop_x: 0, crop_y: 0,
        crop_w: src_w, crop_h: src_h,
        v_error: 0, v_src_y: 0, _pad: 0,
    };

    if src_w == 0 || src_h == 0 || dst_w == 0 || dst_h == 0 {
        return p;
    }

    // Compare aspect ratios without division:
    // src_w/src_h vs dst_w/dst_h  =>  src_w * dst_h vs dst_w * src_h
    let src_aspect = (src_w as u32) * (dst_h as u32);
    let dst_aspect = (dst_w as u32) * (src_h as u32);

    if mode == SCALE_STRETCH {
        // Stretch: map full source to full destination, ignoring aspect ratio.
        // out_w/h already set to dst_w/h, crop_w/h already set to src_w/h.
        // Nothing more to compute — DDA will handle the non-uniform scaling.
    } else if mode == SCALE_FIT {
        // Scale to fit: use smaller scale factor, letterbox the rest
        if src_aspect > dst_aspect {
            // Source is wider — fit width, letterbox top/bottom
            // out_w = dst_w
            // out_h = dst_w * src_h / src_w  (computed via DDA at runtime)
            p.out_w = dst_w;
            p.out_h = div_u32_u16(
                (dst_w as u32) * (src_h as u32),
                src_w,
            );
            if p.out_h > dst_h { p.out_h = dst_h; }
            p.out_y = (dst_h - p.out_h) >> 1;
        } else {
            // Source is taller — fit height, letterbox left/right
            p.out_h = dst_h;
            p.out_w = div_u32_u16(
                (dst_h as u32) * (src_w as u32),
                src_h,
            );
            if p.out_w > dst_w { p.out_w = dst_w; }
            p.out_x = (dst_w - p.out_w) >> 1;
        }
    } else {
        // Scale to fill: use larger scale factor, center-crop overflow
        if src_aspect < dst_aspect {
            // Source is taller — fill width, crop top/bottom
            // crop_h = src_w * dst_h / dst_w
            p.crop_w = src_w;
            p.crop_h = div_u32_u16(
                (src_w as u32) * (dst_h as u32),
                dst_w,
            );
            if p.crop_h > src_h { p.crop_h = src_h; }
            p.crop_y = (src_h - p.crop_h) >> 1;
        } else {
            // Source is wider — fill height, crop left/right
            p.crop_h = src_h;
            p.crop_w = div_u32_u16(
                (src_h as u32) * (dst_w as u32),
                dst_h,
            );
            if p.crop_w > src_w { p.crop_w = src_w; }
            p.crop_x = (src_w - p.crop_w) >> 1;
        }
    }

    p
}

/// Advance vertical DDA for one destination row.
/// Returns true if a new source row is needed (v_src_y advanced).
/// Returns the current source Y that should be used for this output row.
pub fn v_step(p: &mut ScaleParams) -> u16 {
    let y = p.v_src_y;
    p.v_error += p.crop_h as u32;
    while p.v_error >= p.out_h as u32 {
        p.v_error -= p.out_h as u32;
        if p.v_src_y < p.crop_h {
            p.v_src_y += 1;
        }
    }
    y
}

/// Scale one source row horizontally into an RGB565 output buffer.
/// `src` is an RGB888 row (3 bytes per pixel) starting at crop_x.
/// `dst` is an RGB565 output row.
/// `out_w` is the number of output pixels to produce.
/// `crop_w` is the number of source pixels in the cropped region.
///
/// Uses Bresenham DDA — no division.
pub unsafe fn h_scale_row_rgb888(
    src: *const u8,
    crop_x: u16,
    crop_w: u16,
    dst: *mut u8,
    out_w: u16,
) {
    let mut h_error: u32 = 0;
    let mut src_x: u16 = 0;
    let mut dst_i: usize = 0;

    let mut di: usize = 0;
    while di < out_w as usize {
        // Read RGB888 pixel at (crop_x + src_x)
        let pixel_offset = ((crop_x as usize) + (src_x as usize)) * 3;
        let b = *src.add(pixel_offset);
        let g = *src.add(pixel_offset + 1);
        let r = *src.add(pixel_offset + 2);

        // Convert RGB888 → RGB565
        let r5 = (r >> 3) as u16;
        let g6 = (g >> 2) as u16;
        let b5 = (b >> 3) as u16;
        let rgb565 = (r5 << 11) | (g6 << 5) | b5;

        // Write RGB565 little-endian
        *dst.add(dst_i) = rgb565 as u8;
        *dst.add(dst_i + 1) = (rgb565 >> 8) as u8;
        dst_i += 2;

        // Advance horizontal DDA
        h_error += crop_w as u32;
        while h_error >= out_w as u32 {
            h_error -= out_w as u32;
            if src_x < crop_w {
                src_x += 1;
            }
        }

        di += 1;
    }
}

/// Scale one source row horizontally from RGB565 input to RGB565 output.
/// `src` is an RGB565 row (2 bytes per pixel, little-endian).
/// Uses Bresenham DDA — no division.
pub unsafe fn h_scale_row_rgb565(
    src: *const u8,
    crop_x: u16,
    crop_w: u16,
    dst: *mut u8,
    out_w: u16,
) {
    let mut h_error: u32 = 0;
    let mut src_x: u16 = 0;
    let mut dst_i: usize = 0;

    let mut di: usize = 0;
    while di < out_w as usize {
        // Read RGB565 pixel at (crop_x + src_x)
        let pixel_offset = ((crop_x as usize) + (src_x as usize)) * 2;
        let lo = *src.add(pixel_offset);
        let hi = *src.add(pixel_offset + 1);

        // Write RGB565 little-endian (direct copy)
        *dst.add(dst_i) = lo;
        *dst.add(dst_i + 1) = hi;
        dst_i += 2;

        // Advance horizontal DDA
        h_error += crop_w as u32;
        while h_error >= out_w as u32 {
            h_error -= out_w as u32;
            if src_x < crop_w {
                src_x += 1;
            }
        }

        di += 1;
    }
}

/// Fill an RGB565 row with a solid color.
pub unsafe fn fill_row_rgb565(dst: *mut u8, count: u16, color: u16) {
    let lo = color as u8;
    let hi = (color >> 8) as u8;
    let mut i: usize = 0;
    while i < count as usize {
        *dst.add(i * 2) = lo;
        *dst.add(i * 2 + 1) = hi;
        i += 1;
    }
}

/// Integer division: numerator / denominator, using repeated subtraction
/// with binary search (shift-subtract). No `/` operator.
/// Returns 0 if denominator is 0.
fn div_u32_u16(numerator: u32, denominator: u16) -> u16 {
    if denominator == 0 {
        return 0;
    }
    let d = denominator as u32;
    let mut n = numerator;
    let mut q: u32 = 0;

    // Find highest power of 2 * d that fits in n
    let mut shift: u32 = 0;
    let mut shifted_d = d;
    while shifted_d <= (n >> 1) && shift < 31 {
        shifted_d <<= 1;
        shift += 1;
    }

    // Subtract from largest to smallest
    loop {
        if n >= shifted_d {
            n -= shifted_d;
            q += 1 << shift;
        }
        if shift == 0 {
            break;
        }
        shift -= 1;
        shifted_d >>= 1;
    }

    if q > 0xFFFF { 0xFFFF } else { q as u16 }
}
