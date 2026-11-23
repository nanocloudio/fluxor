//! What a draw list draws with: glyph strikes, pixmaps and surfaces, as the
//! painter reads them.

use super::round::{div255, from_rgb565};
use fluxor_abi::contracts::glyph_pack::{self as gp, Bitmap, FORMAT_A1};
use fluxor_abi::contracts::video_draw::{PIXMAP_RGB565, PIXMAP_RGBA8};
use fluxor_abi::contracts::video_raster;

/// One strike's glyphs, read in place and looked up by position in its
/// entry table, which is what a GLYPHS record names a glyph by.
#[derive(Clone, Copy)]
pub struct Strike<'a> {
    format: u8,
    strike: gp::Strike<'a>,
}

impl<'a> Strike<'a> {
    /// The strike at the front of `bytes`, as `glyph_pack` lays one out,
    /// its bitmaps in `format`. `None` when the tables do not fit.
    pub fn parse(bytes: &'a [u8], format: u8) -> Option<Strike<'a>> {
        Some(Strike {
            format,
            strike: gp::Strike::parse(bytes)?,
        })
    }

    /// Glyphs in the strike.
    pub fn len(&self) -> u32 {
        self.strike.len() as u32
    }

    pub fn is_empty(&self) -> bool {
        self.strike.is_empty()
    }

    /// A glyph format byte (`glyph_pack::FORMAT_*`).
    pub fn format(&self) -> u8 {
        self.format
    }

    /// The rows of the glyph at position `index`: its bitmap's first row
    /// above the baseline and its height.
    #[inline]
    pub fn rows(&self, index: u16) -> Option<(i16, u16)> {
        self.strike.rows(usize::from(index))
    }

    /// The bitmap of the glyph at position `index`; `None` past the strike
    /// or when the entry names bytes the strike does not hold.
    pub fn glyph(&self, index: u16) -> Option<Bitmap<'a>> {
        self.strike.entry(usize::from(index), self.format)
    }
}

/// The coverage of column `x` in one bitmap row: `0..=255`.
#[inline(always)]
pub(super) fn glyph_coverage(format: u8, row: &[u8], x: usize) -> u32 {
    if format == FORMAT_A1 {
        match row.get(x >> 3) {
            Some(b) if b & (0x80 >> (x & 7)) != 0 => 255,
            _ => 0,
        }
    } else {
        row.get(x).map_or(0, |v| u32::from(*v))
    }
}

/// How a texel is stored.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TexelFormat {
    /// Bytes red, green, blue, alpha, not premultiplied.
    Rgba8,
    /// A little-endian `u16`, opaque.
    Rgb565,
}

/// Pixels a PIXMAP or SURFACE record samples: `height` rows of `width`
/// texels, top to bottom, tightly packed.
#[derive(Clone, Copy)]
pub struct Texels<'a> {
    data: &'a [u8],
    width: u16,
    height: u16,
    format: TexelFormat,
}

impl<'a> Texels<'a> {
    /// `None` when `data` is shorter than the extent needs or the extent is
    /// empty.
    pub fn new(data: &'a [u8], width: u16, height: u16, format: TexelFormat) -> Option<Self> {
        let bpp = match format {
            TexelFormat::Rgba8 => 4,
            TexelFormat::Rgb565 => 2,
        };
        let len = usize::from(width)
            .checked_mul(usize::from(height))?
            .checked_mul(bpp)?;
        if len == 0 {
            return None;
        }
        Some(Texels {
            data: data.get(..len)?,
            width,
            height,
            format,
        })
    }

    /// A pixmap resource's pixels, by its `video_draw::PIXMAP_*` byte.
    pub fn pixmap(data: &'a [u8], width: u16, height: u16, format: u8) -> Option<Self> {
        let format = match format {
            PIXMAP_RGBA8 => TexelFormat::Rgba8,
            PIXMAP_RGB565 => TexelFormat::Rgb565,
            _ => return None,
        };
        Texels::new(data, width, height, format)
    }

    /// A raster surface's pixels, by its `video_raster::FORMAT_*` byte.
    pub fn raster(data: &'a [u8], width: u16, height: u16, format: u8) -> Option<Self> {
        let format = match format {
            video_raster::FORMAT_RGBA8 => TexelFormat::Rgba8,
            video_raster::FORMAT_RGB565 => TexelFormat::Rgb565,
            _ => return None,
        };
        Texels::new(data, width, height, format)
    }

    pub fn width(&self) -> u16 {
        self.width
    }

    pub fn height(&self) -> u16 {
        self.height
    }

    /// Whether every texel is opaque by its format.
    pub fn opaque(&self) -> bool {
        self.format == TexelFormat::Rgb565
    }

    /// Texel `(x, y)`, premultiplied: `[r, g, b, a]`. Outside the extent it
    /// is transparent.
    #[inline(always)]
    pub(super) fn texel(&self, x: u32, y: u32) -> [u32; 4] {
        if x >= u32::from(self.width) || y >= u32::from(self.height) {
            return [0; 4];
        }
        let i = y as usize * usize::from(self.width) + x as usize;
        match self.format {
            TexelFormat::Rgb565 => match self.data.get(i * 2..i * 2 + 2) {
                Some(p) => {
                    let [r, g, b] = from_rgb565(u16::from_le_bytes([p[0], p[1]]));
                    [u32::from(r), u32::from(g), u32::from(b), 255]
                }
                None => [0; 4],
            },
            TexelFormat::Rgba8 => match self.data.get(i * 4..i * 4 + 4) {
                Some(p) => {
                    let a = u32::from(p[3]);
                    if a == 255 {
                        [u32::from(p[0]), u32::from(p[1]), u32::from(p[2]), 255]
                    } else {
                        [
                            div255(u32::from(p[0]) * a),
                            div255(u32::from(p[1]) * a),
                            div255(u32::from(p[2]) * a),
                            a,
                        ]
                    }
                }
                None => [0; 4],
            },
        }
    }
}

/// The resources of the stream being drawn.
pub trait Resources {
    /// The strike glyph resource `id` draws from, when it is usable.
    fn strike(&self, id: u16) -> Option<Strike<'_>>;
    /// Pixmap resource `id`, when it is usable.
    fn pixmap(&self, id: u16) -> Option<Texels<'_>>;
}

/// The consumer's raster inputs.
pub trait Surfaces {
    /// The latest committed frame of raster input `input`; `None` before it
    /// has committed one.
    fn surface(&self, input: u8) -> Option<Texels<'_>>;
}

/// A consumer with no raster inputs.
pub struct NoSurfaces;

impl Surfaces for NoSurfaces {
    fn surface(&self, _input: u8) -> Option<Texels<'_>> {
        None
    }
}
