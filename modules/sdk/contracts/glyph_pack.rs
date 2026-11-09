// Contract: glyph_pack — a font face baked for drawing text, read in place.
//
// Layer: contracts (public, stable).
//
// A glyph pack is what `font_bake` (bound as `@font_baker`) makes from a font
// file at build or package time. A project supplies the font; Fluxor ships
// none. A producer of text (a layout engine, a game's HUD, a menu) measures
// with the pack's metrics, character map and advances, shapes with its
// OpenType layout tables, and draws glyphs from its strikes.
//
// VARIANTS. A pack's strikes are in one format, named by its `format` byte,
// a position in `fluxor_contracts::vocabulary::GLYPH_FORMATS`, the way an
// encoded stream names its codec. The format travels with the data: a
// consumer reads it in band and refuses a variant it cannot draw. A new
// variant is a new position there and a new strike encoding here; nothing
// else in the pack changes.
//
//   a1 — a bit a pixel, most significant bit first, rows padded to bytes
//   a8 — a coverage byte a pixel, 0 transparent to 255 opaque
//
// LAYOUT. Little-endian. A 16-byte header, then a section directory sorted by
// tag, then the sections, each 4-byte aligned:
//
//   header   ["GPK1"][format u8][flags u8][sections u16]
//            [units_per_em u16][glyphs u16][reserved u32]
//   dir      [tag u32][offset u32][len u32] × sections   (offsets from 0)
//
// Sections (tags are four ASCII bytes, read big-endian into the u32):
//
//   name  [weight u16][style u8][0][family_len u16][subfamily_len u16]
//         [family utf-8][subfamily utf-8]
//         The font's own names (typographic family when it has one), its
//         `OS/2` weight class, and its style (STYLE_*).
//   mtrc  16 × i16, font units: hhea ascent, descent, line gap; OS/2 typo
//         ascent, descent, line gap; OS/2 win ascent, win descent (both
//         positive); flags (METRIC_*); underline position, thickness;
//         strikeout position, thickness; x-height; cap height; reserved.
//   cmap  [ranges u32] then [first u32][last u32][glyph_of_first u32] each,
//         sorted, disjoint: code points first..=last map to consecutive
//         glyphs. A code point in no range has no glyph (glyph 0).
//   hmtx  the advance of every glyph, u16 font units.
//   srcd  the SHA-256 of the font file the pack was baked from.
//   GDEF, GSUB, GPOS, kern
//         the font's OpenType tables, verbatim, when it has them. Glyph ids
//         throughout the pack are the font's own, so they need no rewriting.
//   strk  [strikes u32] then [ppem u16][0 u16][offset u32] each, sorted by
//         ppem, offsets from the section's start. A strike is
//         [ppem u16][0 u16][glyphs u32][ids u16 × glyphs, padded to 4]
//         [entry × glyphs][bitmap bytes]; an entry is
//         [w u16][h u16][left i16][top i16][offset u32], `offset` from the
//         start of the strike's bitmap bytes. `ids` are sorted. `left` is the
//         bitmap's first column right of the pen, `top` its first row above
//         the baseline, in pixels; y grows down within the bitmap.
//
// Readers skip sections whose tags they do not know.

/// The first four bytes of every pack.
pub const MAGIC: [u8; 4] = *b"GPK1";

/// Format bytes: positions in `vocabulary::GLYPH_FORMATS`.
pub const FORMAT_A1: u8 = 0;
pub const FORMAT_A8: u8 = 1;
/// Number of allocated format bytes.
pub const FORMAT_COUNT: u8 = 2;

pub const HEADER: usize = 16;
pub const DIR_ENTRY: usize = 12;
pub const STRIKE_ENTRY: usize = 12;
pub const METRICS_LEN: usize = 32;

/// `name` styles.
pub const STYLE_NORMAL: u8 = 0;
pub const STYLE_ITALIC: u8 = 1;
pub const STYLE_OBLIQUE: u8 = 2;

/// `mtrc` flags: the font sets `OS/2` `USE_TYPO_METRICS`.
pub const METRIC_USE_TYPO: i16 = 1;

/// A section tag from its four ASCII bytes.
pub const fn tag(b: &[u8; 4]) -> u32 {
    (b[0] as u32) << 24 | (b[1] as u32) << 16 | (b[2] as u32) << 8 | b[3] as u32
}

pub const TAG_NAME: u32 = tag(b"name");
pub const TAG_METRICS: u32 = tag(b"mtrc");
pub const TAG_CMAP: u32 = tag(b"cmap");
pub const TAG_HMTX: u32 = tag(b"hmtx");
pub const TAG_SOURCE_DIGEST: u32 = tag(b"srcd");
pub const TAG_GDEF: u32 = tag(b"GDEF");
pub const TAG_GSUB: u32 = tag(b"GSUB");
pub const TAG_GPOS: u32 = tag(b"GPOS");
pub const TAG_KERN: u32 = tag(b"kern");
pub const TAG_STRIKES: u32 = tag(b"strk");

#[inline]
fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

#[inline]
fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// The face's vertical metrics and decoration positions, font units.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Metrics {
    pub hhea_ascent: i16,
    pub hhea_descent: i16,
    pub hhea_line_gap: i16,
    pub typo_ascent: i16,
    pub typo_descent: i16,
    pub typo_line_gap: i16,
    pub win_ascent: i16,
    pub win_descent: i16,
    pub flags: i16,
    pub underline_position: i16,
    pub underline_thickness: i16,
    pub strikeout_position: i16,
    pub strikeout_thickness: i16,
    pub x_height: i16,
    pub cap_height: i16,
}

impl Metrics {
    /// The 32 bytes of a `mtrc` section.
    pub fn to_bytes(self) -> [u8; METRICS_LEN] {
        let v = [
            self.hhea_ascent,
            self.hhea_descent,
            self.hhea_line_gap,
            self.typo_ascent,
            self.typo_descent,
            self.typo_line_gap,
            self.win_ascent,
            self.win_descent,
            self.flags,
            self.underline_position,
            self.underline_thickness,
            self.strikeout_position,
            self.strikeout_thickness,
            self.x_height,
            self.cap_height,
            0,
        ];
        let mut out = [0u8; METRICS_LEN];
        let mut i = 0;
        while i < 16 {
            let b = v[i].to_le_bytes();
            out[i * 2] = b[0];
            out[i * 2 + 1] = b[1];
            i += 1;
        }
        out
    }

    fn from_bytes(b: &[u8]) -> Option<Metrics> {
        if b.len() < METRICS_LEN {
            return None;
        }
        let f = |i: usize| i16::from_le_bytes([b[i * 2], b[i * 2 + 1]]);
        Some(Metrics {
            hhea_ascent: f(0),
            hhea_descent: f(1),
            hhea_line_gap: f(2),
            typo_ascent: f(3),
            typo_descent: f(4),
            typo_line_gap: f(5),
            win_ascent: f(6),
            win_descent: f(7),
            flags: f(8),
            underline_position: f(9),
            underline_thickness: f(10),
            strikeout_position: f(11),
            strikeout_thickness: f(12),
            x_height: f(13),
            cap_height: f(14),
        })
    }
}

/// A pack, checked and read in place.
#[derive(Clone, Copy)]
pub struct Pack<'a> {
    bytes: &'a [u8],
    pub format: u8,
    pub flags: u8,
    pub units_per_em: u16,
    pub glyphs: u16,
    sections: u16,
    cmap: &'a [u8],
    hmtx: &'a [u8],
}

impl<'a> Pack<'a> {
    /// Check the header, the directory and the sections every reader needs
    /// (`cmap`, `hmtx`, `mtrc`), and the format byte. `None` when any is
    /// malformed or the format is unallocated.
    pub fn parse(bytes: &'a [u8]) -> Option<Pack<'a>> {
        if bytes.get(..4)? != MAGIC {
            return None;
        }
        let format = *bytes.get(4)?;
        if format >= FORMAT_COUNT {
            return None;
        }
        let sections = u16_at(bytes, 6)?;
        let units_per_em = u16_at(bytes, 8)?;
        let glyphs = u16_at(bytes, 10)?;
        if units_per_em == 0 || glyphs == 0 {
            return None;
        }
        let mut p = Pack {
            bytes,
            format,
            flags: bytes[5],
            units_per_em,
            glyphs,
            sections,
            cmap: &[],
            hmtx: &[],
        };
        let mut last = None;
        for i in 0..sections as usize {
            let at = HEADER + i * DIR_ENTRY;
            let t = u32_at(bytes, at)?;
            let off = u32_at(bytes, at + 4)? as usize;
            let len = u32_at(bytes, at + 8)? as usize;
            if last.is_some_and(|l| t <= l)
                || !off.is_multiple_of(4)
                || bytes.get(off..off.checked_add(len)?).is_none()
            {
                return None;
            }
            last = Some(t);
        }
        p.cmap = p.section(TAG_CMAP)?;
        let ranges = u32_at(p.cmap, 0)? as usize;
        if p.cmap.len() < 4 + ranges.checked_mul(12)? {
            return None;
        }
        p.hmtx = p.section(TAG_HMTX)?;
        if p.hmtx.len() < glyphs as usize * 2 {
            return None;
        }
        p.section(TAG_METRICS).and_then(Metrics::from_bytes)?;
        Some(p)
    }

    /// The whole pack.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// A section's bytes, by tag.
    pub fn section(&self, t: u32) -> Option<&'a [u8]> {
        let (mut lo, mut hi) = (0usize, self.sections as usize);
        while lo < hi {
            let mid = lo.midpoint(hi);
            let at = HEADER + mid * DIR_ENTRY;
            let mt = u32_at(self.bytes, at)?;
            if mt == t {
                let off = u32_at(self.bytes, at + 4)? as usize;
                let len = u32_at(self.bytes, at + 8)? as usize;
                return self.bytes.get(off..off + len);
            }
            if mt < t {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        None
    }

    /// The glyph for a code point; 0 (`.notdef`) when the face has none.
    pub fn glyph(&self, cp: u32) -> u16 {
        let n = u32_at(self.cmap, 0).unwrap_or(0) as usize;
        let (mut lo, mut hi) = (0usize, n);
        while lo < hi {
            let mid = lo.midpoint(hi);
            let at = 4 + mid * 12;
            let first = u32_at(self.cmap, at).unwrap_or(0);
            let last = u32_at(self.cmap, at + 4).unwrap_or(0);
            if cp < first {
                hi = mid;
            } else if cp > last {
                lo = mid + 1;
            } else {
                let g = u32_at(self.cmap, at + 8).unwrap_or(0) + (cp - first);
                return if g < self.glyphs as u32 { g as u16 } else { 0 };
            }
        }
        0
    }

    /// Whether the face maps `cp` to a glyph.
    pub fn has(&self, cp: u32) -> bool {
        self.glyph(cp) != 0
    }

    /// The `cmap` ranges: `(first, last, glyph of first)`.
    pub fn ranges(&self) -> impl Iterator<Item = (u32, u32, u32)> + 'a {
        let c = self.cmap;
        let n = u32_at(c, 0).unwrap_or(0) as usize;
        (0..n).map(move |i| {
            let at = 4 + i * 12;
            (
                u32_at(c, at).unwrap_or(0),
                u32_at(c, at + 4).unwrap_or(0),
                u32_at(c, at + 8).unwrap_or(0),
            )
        })
    }

    /// A glyph's advance, font units.
    pub fn advance(&self, glyph: u16) -> u16 {
        u16_at(self.hmtx, glyph as usize * 2).unwrap_or(0)
    }

    pub fn metrics(&self) -> Metrics {
        self.section(TAG_METRICS)
            .and_then(Metrics::from_bytes)
            .unwrap_or_default()
    }

    /// The family name, the subfamily name, the weight and the style.
    pub fn name(&self) -> (&'a [u8], &'a [u8], u16, u8) {
        let Some(s) = self.section(TAG_NAME) else {
            return (&[], &[], 400, STYLE_NORMAL);
        };
        let weight = u16_at(s, 0).unwrap_or(400);
        let style = s.get(2).copied().unwrap_or(0);
        let fl = u16_at(s, 4).unwrap_or(0) as usize;
        let sl = u16_at(s, 6).unwrap_or(0) as usize;
        let family = s.get(8..8 + fl).unwrap_or(&[]);
        let sub = s.get(8 + fl..8 + fl + sl).unwrap_or(&[]);
        (family, sub, weight, style)
    }

    /// The SHA-256 of the font file the pack was baked from.
    pub fn source_digest(&self) -> Option<&'a [u8]> {
        self.section(TAG_SOURCE_DIGEST).filter(|d| d.len() == 32)
    }

    /// The number of strikes.
    pub fn strikes(&self) -> usize {
        self.section(TAG_STRIKES)
            .and_then(|s| u32_at(s, 0))
            .unwrap_or(0) as usize
    }

    /// The ppem of strike `i`.
    pub fn strike_ppem(&self, i: usize) -> Option<u16> {
        let s = self.section(TAG_STRIKES)?;
        if i >= self.strikes() {
            return None;
        }
        u16_at(s, 4 + i * 8)
    }

    /// The strike for `ppem`, when the pack has one.
    pub fn strike(&self, ppem: u16) -> Option<Strike<'a>> {
        let s = self.section(TAG_STRIKES)?;
        let n = self.strikes();
        for i in 0..n {
            if u16_at(s, 4 + i * 8)? == ppem {
                let off = u32_at(s, 4 + i * 8 + 4)? as usize;
                return Strike::parse(s.get(off..)?);
            }
        }
        None
    }
}

/// One glyph's bitmap in a strike.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bitmap<'a> {
    pub w: u16,
    pub h: u16,
    pub left: i16,
    pub top: i16,
    /// `h` rows: `w` bytes each for a8, `(w + 7) / 8` for a1.
    pub data: &'a [u8],
}

/// The glyph bitmaps at one ppem.
#[derive(Clone, Copy)]
pub struct Strike<'a> {
    pub ppem: u16,
    count: usize,
    ids: &'a [u8],
    entries: &'a [u8],
    bits: &'a [u8],
}

impl<'a> Strike<'a> {
    fn parse(s: &'a [u8]) -> Option<Strike<'a>> {
        let ppem = u16_at(s, 0)?;
        let count = u32_at(s, 4)? as usize;
        let ids_len = (count * 2 + 3) & !3;
        let ids = s.get(8..8 + count * 2)?;
        let e0 = 8 + ids_len;
        let entries = s.get(e0..e0 + count.checked_mul(STRIKE_ENTRY)?)?;
        let bits = s.get(e0 + count * STRIKE_ENTRY..)?;
        Some(Strike {
            ppem,
            count,
            ids,
            entries,
            bits,
        })
    }

    /// The number of glyphs the strike draws.
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The bitmap for `glyph`, when the strike has it. A glyph that draws
    /// nothing (a space) has a 0×0 bitmap.
    pub fn bitmap(&self, glyph: u16, format: u8) -> Option<Bitmap<'a>> {
        let (mut lo, mut hi) = (0usize, self.count);
        while lo < hi {
            let mid = lo.midpoint(hi);
            let g = u16_at(self.ids, mid * 2)?;
            if g == glyph {
                let e = mid * STRIKE_ENTRY;
                let w = u16_at(self.entries, e)?;
                let h = u16_at(self.entries, e + 2)?;
                let left = u16_at(self.entries, e + 4)? as i16;
                let top = u16_at(self.entries, e + 6)? as i16;
                let off = u32_at(self.entries, e + 8)? as usize;
                let row = row_bytes(format, w);
                let data = self.bits.get(off..off + row * h as usize)?;
                return Some(Bitmap {
                    w,
                    h,
                    left,
                    top,
                    data,
                });
            }
            if g < glyph {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        None
    }
}

/// Bytes in one bitmap row of `w` pixels.
pub const fn row_bytes(format: u8, w: u16) -> usize {
    if format == FORMAT_A1 {
        (w as usize).div_ceil(8)
    } else {
        w as usize
    }
}
