//! The rounding rules: every division the rasteriser makes on a colour or a
//! coverage value. A conforming rasteriser reproduces each bit for bit.

/// `x / 255`, rounded to nearest, for `x` up to `255 × 255`. Halves cannot
/// occur: 255 is odd.
#[inline(always)]
pub fn div255(x: u32) -> u32 {
    (x + 127) / 255
}

/// `div255` of two values at once, one in each half of a word: each half
/// of `x` is up to `255 × 255`, and each half of the answer is its
/// `div255`. `(t + (t >> 8)) >> 8` with `t = x + 128` is `x / 255` rounded
/// to nearest over that range, and no half reaches 65,536 on the way, so
/// nothing carries from one into the other.
#[inline(always)]
pub fn div255_pair(x: u32) -> u32 {
    let t = x + 0x0080_0080;
    ((t + ((t >> 8) & 0x00FF_00FF)) >> 8) & 0x00FF_00FF
}

/// An area in 1/4096 pixel (`0..=4096`) as a coverage `0..=255`.
#[inline(always)]
pub fn quantise(area: u32) -> u32 {
    (area * 255 + 2048) >> 12
}

/// One 8-bit colour as RGB565: each channel rounded to nearest, no dither.
/// `r5 = (r × 31 + 127) / 255` and `g6 = (g × 63 + 127) / 255`, computed
/// as `(r × 249 + 1014) >> 11` and `(g × 253 + 505) >> 10`, which give the
/// same value for every 8-bit input. Red and blue share one multiply, each
/// in its own half of a word: `v × 249 + 1014` is below 65,536.
#[inline(always)]
pub fn to_rgb565(r: u8, g: u8, b: u8) -> u16 {
    let both = (u32::from(r) | u32::from(b) << 16) * 249 + 0x03F6_03F6;
    let g6 = (u32::from(g) * 253 + 505) >> 10;
    ((both & 0xF800) | (g6 << 5) | (both >> 27)) as u16
}

/// One RGB565 pixel as 8-bit red, green and blue.
#[inline(always)]
pub fn from_rgb565(p: u16) -> [u8; 3] {
    let p = u32::from(p);
    let r = ((p >> 11) * 255 + 15) / 31;
    let g = (((p >> 5) & 63) * 255 + 31) / 63;
    let b = ((p & 31) * 255 + 15) / 31;
    [r as u8, g as u8, b as u8]
}
