//! The band: the rows being drawn, as 8-bit red, green and blue. Compositing
//! happens here, in full precision; the output format is a conversion after.

use super::round::{div255, div255_pair, to_rgb565};
use fluxor_abi::contracts::video_draw::{Colour, PRect};

/// Bytes a band pixel takes.
pub const BAND_BPP: usize = 3;

/// A rectangle of the surface under construction: `rows` rows of `width`
/// pixels starting at `(x, y)`, three bytes a pixel, rows top to bottom.
pub struct Band<'a> {
    x: i32,
    y: i32,
    width: i32,
    rows: i32,
    pixels: &'a mut [u8],
}

impl<'a> Band<'a> {
    /// A band over `region`, drawn into the front of `pixels`. `None` when
    /// `pixels` is shorter than `Band::bytes(region)`.
    pub fn new(pixels: &'a mut [u8], region: PRect) -> Option<Band<'a>> {
        let pixels = pixels.get_mut(..Band::bytes(region))?;
        Some(Band {
            x: i32::from(region.x),
            y: i32::from(region.y),
            width: i32::from(region.w),
            rows: i32::from(region.h),
            pixels,
        })
    }

    /// Bytes a band over `region` needs.
    pub const fn bytes(region: PRect) -> usize {
        region.w as usize * region.h as usize * BAND_BPP
    }

    /// The region the band covers.
    pub fn region(&self) -> PRect {
        PRect {
            x: self.x as u16,
            y: self.y as u16,
            w: self.width as u16,
            h: self.rows as u16,
        }
    }

    /// The columns the band holds: `first..end`.
    pub fn columns(&self) -> (i32, i32) {
        (self.x, self.x + self.width)
    }

    /// The rows the band holds: `first..end`.
    pub fn row_span(&self) -> (i32, i32) {
        (self.y, self.y + self.rows)
    }

    /// Every pixel opaque black: what a band holds before a frame's first
    /// operation on a consumer that retains no pixels.
    pub fn clear(&mut self) {
        self.pixels.fill(0);
    }

    /// Row `py` of the surface, when the band holds it.
    pub fn row(&self, py: i32) -> Option<&[u8]> {
        if py < self.y || py >= self.y + self.rows {
            return None;
        }
        let stride = self.width as usize * BAND_BPP;
        let at = (py - self.y) as usize * stride;
        self.pixels.get(at..at + stride)
    }

    /// Columns `x0..x1` of row `py`, clamped to the band, with the column
    /// the slice starts at.
    pub(super) fn span(&mut self, py: i32, x0: i32, x1: i32) -> Option<(i32, &mut [u8])> {
        if py < self.y || py >= self.y + self.rows {
            return None;
        }
        let x0 = x0.max(self.x);
        let x1 = x1.min(self.x + self.width);
        if x0 >= x1 {
            return None;
        }
        let stride = self.width as usize * BAND_BPP;
        let at = (py - self.y) as usize * stride + (x0 - self.x) as usize * BAND_BPP;
        let len = (x1 - x0) as usize * BAND_BPP;
        Some((x0, self.pixels.get_mut(at..at + len)?))
    }

    /// Row `py` as RGB565, little-endian, into the front of `out`: the bytes
    /// written, or `None` when the band does not hold the row or `out` is
    /// too short.
    ///
    /// Where the row and `out` both start on a word boundary, four pixels
    /// are converted at a time, three words in and two out, and four that
    /// equal the four before them are not converted again: a row of drawn
    /// interface is mostly runs of one colour.
    pub fn row_rgb565(&self, py: i32, out: &mut [u8]) -> Option<usize> {
        let row = self.row(py)?;
        let out = out.get_mut(..self.width as usize * 2)?;
        let mut done = 0usize;
        {
            // SAFETY: every bit pattern is a `u32`, and `align_to` keeps
            // the words inside the bytes they are made of.
            let (before, words, _) = unsafe { row.align_to::<u32>() };
            // SAFETY: as above; any `u32` written is four valid bytes.
            let (out_before, out_words, _) = unsafe { out.align_to_mut::<u32>() };
            if before.is_empty() && out_before.is_empty() {
                // Black converts to black: a true pair to start from.
                let (mut w0, mut w1, mut w2) = (0u32, 0u32, 0u32);
                let (mut lo, mut hi) = (0u32, 0u32);
                for (src, dst) in words.chunks_exact(3).zip(out_words.chunks_exact_mut(2)) {
                    // Bytes r g b r, g b r g, b r g b: four pixels.
                    let (a, b, c) = (
                        u32::from_le(src[0]),
                        u32::from_le(src[1]),
                        u32::from_le(src[2]),
                    );
                    if a != w0 || b != w1 || c != w2 {
                        (w0, w1, w2) = (a, b, c);
                        let p0 = to_rgb565(a as u8, (a >> 8) as u8, (a >> 16) as u8);
                        let p1 = to_rgb565((a >> 24) as u8, b as u8, (b >> 8) as u8);
                        let p2 = to_rgb565((b >> 16) as u8, (b >> 24) as u8, c as u8);
                        let p3 = to_rgb565((c >> 8) as u8, (c >> 16) as u8, (c >> 24) as u8);
                        lo = (u32::from(p0) | u32::from(p1) << 16).to_le();
                        hi = (u32::from(p2) | u32::from(p3) << 16).to_le();
                    }
                    dst[0] = lo;
                    dst[1] = hi;
                    done += 4;
                }
            }
        }
        let rest = row.get(done * BAND_BPP..).unwrap_or(&[]);
        let out_rest = out.get_mut(done * 2..).unwrap_or(&mut []);
        for (src, dst) in rest
            .chunks_exact(BAND_BPP)
            .zip(out_rest.chunks_exact_mut(2))
        {
            let p = to_rgb565(src[0], src[1], src[2]).to_le_bytes();
            dst[0] = p[0];
            dst[1] = p[1];
        }
        Some(self.width as usize * 2)
    }

    /// Row `py` as RGBA8, alpha 255, into the front of `out`.
    pub fn row_rgba8(&self, py: i32, out: &mut [u8]) -> Option<usize> {
        let row = self.row(py)?;
        let out = out.get_mut(..self.width as usize * 4)?;
        for (src, dst) in row.chunks_exact(BAND_BPP).zip(out.chunks_exact_mut(4)) {
            dst[0] = src[0];
            dst[1] = src[1];
            dst[2] = src[2];
            dst[3] = 255;
        }
        Some(out.len())
    }
}

/// Solid paint: `colour` over the pixel at the front of `px`, through
/// `coverage` (`0..=255`).
#[inline(always)]
pub(super) fn solid(px: &mut [u8], colour: Colour, coverage: u32) {
    solid_alpha(px, colour, div255(u32::from(colour[3]) * coverage));
}

/// Solid paint through a final alpha `a` (`0..=255`): the colour's own
/// alpha and the coverage already combined.
#[inline(always)]
pub(super) fn solid_alpha(px: &mut [u8], colour: Colour, a: u32) {
    if a == 255 {
        px[0] = colour[0];
        px[1] = colour[1];
        px[2] = colour[2];
    } else if a != 0 {
        let na = 255 - a;
        // Red and blue share each multiply, a half of the word apiece.
        let paint = u32::from(colour[0]) | u32::from(colour[2]) << 16;
        let under = u32::from(px[0]) | u32::from(px[2]) << 16;
        let both = div255_pair(paint * a + under * na);
        px[0] = both as u8;
        px[1] = div255(u32::from(colour[1]) * a + u32::from(px[1]) * na) as u8;
        px[2] = (both >> 16) as u8;
    }
}

/// Solid paint of one pixel two colours share: `first` through
/// `coverage_first` and `second` through `coverage_second`, which together
/// are at most 255. The two parts do not overlap, so they composite in one
/// step: `out = div255(c1 × a1 + c2 × a2 + dst × (255 − a1 − a2))`.
#[inline(always)]
pub(super) fn solid_pair(
    px: &mut [u8],
    first: Colour,
    coverage_first: u32,
    second: Colour,
    coverage_second: u32,
) {
    let a1 = div255(u32::from(first[3]) * coverage_first);
    let a2 = div255(u32::from(second[3]) * coverage_second);
    if a1 + a2 == 0 {
        return;
    }
    let na = 255u32.saturating_sub(a1 + a2);
    for ch in 0..3 {
        let v = u32::from(first[ch]) * a1 + u32::from(second[ch]) * a2 + u32::from(px[ch]) * na;
        px[ch] = div255(v).min(255) as u8;
    }
}

/// Sampled paint: a premultiplied sample `[r, g, b, a]` over the pixel at
/// the front of `px`, through `coverage`.
#[inline(always)]
pub(super) fn sampled(px: &mut [u8], sample: [u32; 4], coverage: u32) {
    if coverage == 255 && sample[3] == 255 {
        px[0] = sample[0] as u8;
        px[1] = sample[1] as u8;
        px[2] = sample[2] as u8;
        return;
    }
    let a = div255(sample[3] * coverage);
    if a == 0 {
        return;
    }
    let na = 255 - a;
    for ch in 0..3 {
        let p = div255(sample[ch] * coverage);
        px[ch] = (p + div255(u32::from(px[ch]) * na)).min(255) as u8;
    }
}
