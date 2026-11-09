//! Baking a TrueType font into a glyph pack (`abi::contracts::glyph_pack`).
//!
//! Pure: a font's bytes and the options in, the pack's bytes out, into a
//! buffer the caller provides. The module around it reads the file, hashes
//! it, and writes the pack to its output.

use super::closure::{self, GlyphSet};
use super::gp;
use super::raster::{ceil, floor, Bounds, Raster};
use super::ttf::{self, be16, be32, bei16, Font, FontError, Point};

/// What to bake.
pub struct Options<'a> {
    /// A `glyph_pack::FORMAT_*` byte.
    pub format: u8,
    /// The strikes, pixels per em, sorted and distinct.
    pub ppems: &'a [u16],
    /// The code points to keep, as inclusive ranges; empty keeps every one
    /// the font maps.
    pub chars: &'a [(u32, u32)],
}

/// Working memory the caller provides.
pub struct Scratch<'a> {
    /// A bit per glyph: `(glyphs + 7) / 8` bytes.
    pub set: &'a mut [u8],
    /// One contour's points.
    pub points: &'a mut [Point],
    /// Rasterising accumulation; the largest glyph bitmap plus a row.
    pub acc: &'a mut [f32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BakeError {
    Font(FontError),
    /// The output buffer is too small.
    Room,
    /// The scratch buffers are too small for this font.
    Scratch,
    /// A glyph's bitmap at a ppem is larger than the rasteriser's buffer.
    GlyphTooLarge {
        glyph: u16,
        ppem: u16,
    },
}

impl From<FontError> for BakeError {
    fn from(e: FontError) -> Self {
        BakeError::Font(e)
    }
}

/// Bytes appended to a buffer, failing softly when it is full.
pub struct Out<'a> {
    pub buf: &'a mut [u8],
    pub len: usize,
    pub full: bool,
}

impl<'a> Out<'a> {
    pub fn new(buf: &'a mut [u8]) -> Out<'a> {
        Out {
            buf,
            len: 0,
            full: false,
        }
    }

    pub fn bytes(&mut self, b: &[u8]) {
        match self.buf.get_mut(self.len..self.len + b.len()) {
            Some(d) => {
                d.copy_from_slice(b);
                self.len += b.len();
            }
            None => self.full = true,
        }
    }

    pub fn u8(&mut self, v: u8) {
        self.bytes(&[v]);
    }
    pub fn u16(&mut self, v: u16) {
        self.bytes(&v.to_le_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.bytes(&v.to_le_bytes());
    }

    pub fn align4(&mut self) {
        while !self.len.is_multiple_of(4) && !self.full {
            self.u8(0);
        }
    }

    /// Reserve `n` zero bytes; their offset.
    pub fn reserve(&mut self, n: usize) -> usize {
        let at = self.len;
        match self.buf.get_mut(self.len..self.len + n) {
            Some(d) => {
                d.fill(0);
                self.len += n;
            }
            None => self.full = true,
        }
        at
    }

    pub fn put_u16(&mut self, at: usize, v: u16) {
        if let Some(d) = self.buf.get_mut(at..at + 2) {
            d.copy_from_slice(&v.to_le_bytes());
        }
    }

    pub fn put_u32(&mut self, at: usize, v: u32) {
        if let Some(d) = self.buf.get_mut(at..at + 4) {
            d.copy_from_slice(&v.to_le_bytes());
        }
    }
}

fn in_chars(chars: &[(u32, u32)], cp: u32) -> bool {
    chars.is_empty() || chars.iter().any(|&(a, b)| cp >= a && cp <= b)
}

/// Ranges as they are found, coalesced, written as `cmap` entries.
struct Ranges {
    count: u32,
    first: u32,
    last: u32,
    glyph: u32,
    open: bool,
}

impl Ranges {
    fn push(&mut self, out: &mut Out, set: &mut GlyphSet, cp: u32, g: u16) {
        if g == 0 || g >= set.glyphs {
            return;
        }
        set.add(g);
        if self.open && cp == self.last + 1 && g as u32 == self.glyph + (cp - self.first) {
            self.last = cp;
            return;
        }
        self.flush(out);
        *self = Ranges {
            count: self.count,
            first: cp,
            last: cp,
            glyph: g as u32,
            open: true,
        };
    }

    fn flush(&mut self, out: &mut Out) {
        if self.open {
            out.u32(self.first);
            out.u32(self.last);
            out.u32(self.glyph);
            self.count += 1;
            self.open = false;
        }
    }
}

/// The font's `cmap`, restricted to `chars`, as pack ranges; the glyphs it
/// maps are added to `set`.
fn write_cmap(
    font: &Font,
    chars: &[(u32, u32)],
    set: &mut GlyphSet,
    out: &mut Out,
) -> Result<(), BakeError> {
    let cmap = font.table(b"cmap").ok_or(FontError::Missing(ttf::T_CMAP))?;
    let n = be16(cmap, 2).unwrap_or(0) as usize;
    let mut best: Option<(u32, usize)> = None; // (rank, offset)
    for i in 0..n {
        let r = 4 + i * 8;
        let (Some(p), Some(e), Some(off)) = (be16(cmap, r), be16(cmap, r + 2), be32(cmap, r + 4))
        else {
            continue;
        };
        let off = off as usize;
        let format = be16(cmap, off).unwrap_or(0);
        let rank = match (p, e, format) {
            (3, 10, 12) | (0, 4, 12) | (0, 6, 12) => 3,
            (3, 1, 4) | (0, 3, 4) => 2,
            (0, _, 4) => 1,
            _ => 0,
        };
        if rank > 0 && best.is_none_or(|b| rank > b.0) {
            best = Some((rank, off));
        }
    }
    let (_, sub) = best.ok_or(FontError::Malformed(ttf::T_CMAP))?;
    let count_at = out.reserve(4);
    let mut ranges = Ranges {
        count: 0,
        first: 0,
        last: 0,
        glyph: 0,
        open: false,
    };
    match be16(cmap, sub) {
        Some(12) => {
            let groups = be32(cmap, sub + 12).unwrap_or(0) as usize;
            for k in 0..groups {
                let g = sub + 16 + k * 12;
                let (Some(s), Some(e), Some(g0)) =
                    (be32(cmap, g), be32(cmap, g + 4), be32(cmap, g + 8))
                else {
                    break;
                };
                if e < s || e > 0x10_FFFF {
                    continue;
                }
                for cp in s..=e {
                    let gid = g0 + (cp - s);
                    if gid < 0x1_0000 && in_chars(chars, cp) {
                        ranges.push(out, set, cp, gid as u16);
                    }
                }
            }
        }
        Some(4) => {
            let segs = be16(cmap, sub + 6).unwrap_or(0) as usize / 2;
            let ends = sub + 14;
            let starts = ends + segs * 2 + 2;
            let deltas = starts + segs * 2;
            let offsets = deltas + segs * 2;
            for k in 0..segs {
                let (Some(e), Some(s), Some(d), Some(ro)) = (
                    be16(cmap, ends + k * 2),
                    be16(cmap, starts + k * 2),
                    be16(cmap, deltas + k * 2),
                    be16(cmap, offsets + k * 2),
                ) else {
                    break;
                };
                if e < s {
                    continue;
                }
                for c in s..=e {
                    if c == 0xFFFF {
                        break;
                    }
                    let gid = if ro == 0 {
                        c.wrapping_add(d)
                    } else {
                        let at = offsets + k * 2 + ro as usize + (c - s) as usize * 2;
                        match be16(cmap, at) {
                            Some(0) | None => 0,
                            Some(g) => g.wrapping_add(d),
                        }
                    };
                    if in_chars(chars, c as u32) {
                        ranges.push(out, set, c as u32, gid);
                    }
                }
            }
        }
        _ => return Err(FontError::Malformed(ttf::T_CMAP).into()),
    }
    ranges.flush(out);
    out.put_u32(count_at, ranges.count);
    Ok(())
}

/// A UTF-8 copy of a `name` record (UTF-16BE on Windows and Unicode
/// platforms, ASCII taken as is on Macintosh).
fn name_text(font: &Font, id: u16, out: &mut [u8]) -> usize {
    let Some(t) = font.table(b"name") else {
        return 0;
    };
    let count = be16(t, 2).unwrap_or(0) as usize;
    let strings = be16(t, 4).unwrap_or(0) as usize;
    let mut pick: Option<(u32, usize, usize, bool)> = None;
    for i in 0..count {
        let r = 6 + i * 12;
        let (Some(p), Some(e), Some(lang), Some(nid), Some(len), Some(off)) = (
            be16(t, r),
            be16(t, r + 2),
            be16(t, r + 4),
            be16(t, r + 6),
            be16(t, r + 8),
            be16(t, r + 10),
        ) else {
            break;
        };
        if nid != id {
            continue;
        }
        let rank = match (p, e, lang) {
            (3, 1, 0x409) => 4,
            (3, 1, _) | (0, _, _) => 3,
            (1, 0, 0) => 2,
            _ => 0,
        };
        if rank > 0 && pick.is_none_or(|b| rank > b.0) {
            pick = Some((rank, strings + off as usize, len as usize, p != 1));
        }
    }
    let Some((_, at, len, utf16)) = pick else {
        return 0;
    };
    let Some(s) = t.get(at..at + len) else {
        return 0;
    };
    let mut n = 0;
    let mut put = |c: u32, n: &mut usize| {
        let mut b = [0u8; 4];
        let enc = match char::from_u32(c) {
            Some(ch) => ch.encode_utf8(&mut b).len(),
            None => 0,
        };
        if *n + enc <= out.len() {
            out[*n..*n + enc].copy_from_slice(&b[..enc]);
            *n += enc;
        }
    };
    if utf16 {
        let mut i = 0;
        while i + 1 < s.len() {
            let u = u16::from_be_bytes([s[i], s[i + 1]]) as u32;
            i += 2;
            if (0xD800..0xDC00).contains(&u) && i + 1 < s.len() {
                let lo = u16::from_be_bytes([s[i], s[i + 1]]) as u32;
                i += 2;
                put(
                    0x10000 + ((u - 0xD800) << 10) + (lo.wrapping_sub(0xDC00) & 0x3FF),
                    &mut n,
                );
            } else {
                put(u, &mut n);
            }
        }
    } else {
        for &c in s {
            put(if c < 0x80 { c as u32 } else { '?' as u32 }, &mut n);
        }
    }
    n
}

fn write_name(font: &Font, out: &mut Out) {
    let mut family = [0u8; 256];
    let mut sub = [0u8; 256];
    let mut fl = name_text(font, 16, &mut family);
    if fl == 0 {
        fl = name_text(font, 1, &mut family);
    }
    let mut sl = name_text(font, 17, &mut sub);
    if sl == 0 {
        sl = name_text(font, 2, &mut sub);
    }
    let os2 = font.table(b"OS/2");
    let weight = os2.and_then(|t| be16(t, 4)).unwrap_or(400);
    let selection = os2.and_then(|t| be16(t, 62)).unwrap_or(0);
    let mac_style = font.table(b"head").and_then(|t| be16(t, 44)).unwrap_or(0);
    let style = if selection & 0x0200 != 0 {
        gp::STYLE_OBLIQUE
    } else if selection & 0x0001 != 0 || mac_style & 0x0002 != 0 {
        gp::STYLE_ITALIC
    } else {
        gp::STYLE_NORMAL
    };
    out.u16(weight);
    out.u8(style);
    out.u8(0);
    out.u16(fl as u16);
    out.u16(sl as u16);
    out.bytes(&family[..fl]);
    out.bytes(&sub[..sl]);
}

fn metrics(font: &Font) -> gp::Metrics {
    let hhea = font.table(b"hhea").unwrap_or(&[]);
    let os2 = font.table(b"OS/2").unwrap_or(&[]);
    let post = font.table(b"post").unwrap_or(&[]);
    let i = |t: &[u8], at: usize| bei16(t, at).unwrap_or(0);
    let version = be16(os2, 0).unwrap_or(0);
    let selection = be16(os2, 62).unwrap_or(0);
    gp::Metrics {
        hhea_ascent: i(hhea, 4),
        hhea_descent: i(hhea, 6),
        hhea_line_gap: i(hhea, 8),
        typo_ascent: i(os2, 68),
        typo_descent: i(os2, 70),
        typo_line_gap: i(os2, 72),
        win_ascent: i(os2, 74),
        win_descent: i(os2, 76),
        flags: if selection & 0x0080 != 0 {
            gp::METRIC_USE_TYPO
        } else {
            0
        },
        underline_position: i(post, 8),
        underline_thickness: i(post, 10),
        strikeout_position: i(os2, 28),
        strikeout_thickness: i(os2, 26),
        x_height: if version >= 2 { i(os2, 86) } else { 0 },
        cap_height: if version >= 2 { i(os2, 88) } else { 0 },
    }
}

/// One strike: every glyph in `set` at `ppem`.
fn write_strike(
    font: &Font,
    o: &Options,
    ppem: u16,
    set: &GlyphSet,
    points: &mut [Point],
    acc: &mut [f32],
    out: &mut Out,
) -> Result<(), BakeError> {
    let scale = ppem as f32 / font.units_per_em as f32;
    let count = set.count();
    out.u16(ppem);
    out.u16(0);
    out.u32(count as u32);
    for g in 0..set.glyphs {
        if set.has(g) {
            out.u16(g);
        }
    }
    out.align4();
    let entries = out.reserve(count * gp::STRIKE_ENTRY);
    let bits0 = out.len;
    let mut k = 0;
    for g in 0..set.glyphs {
        if !set.has(g) {
            continue;
        }
        let mut b = Bounds::new();
        font.outline(g, points, &mut b);
        let e = entries + k * gp::STRIKE_ENTRY;
        k += 1;
        out.put_u32(e + 8, (out.len - bits0) as u32);
        if !b.any {
            continue;
        }
        let left = floor(b.x0 * scale);
        let right = ceil(b.x1 * scale);
        let top = ceil(b.y1 * scale);
        let bottom = floor(b.y0 * scale);
        let w = (right - left) as usize;
        let h = (top - bottom) as usize;
        if w == 0 || h == 0 {
            continue;
        }
        if w > 0xFFFF || h > 0xFFFF || w * h + w + 4 > acc.len() {
            return Err(BakeError::GlyphTooLarge { glyph: g, ppem });
        }
        let mut r = Raster::new(acc, w, h, scale, left, top);
        font.outline(g, points, &mut r);
        let size = gp::row_bytes(o.format, w as u16) * h;
        let at = out.reserve(size);
        if out.full {
            return Err(BakeError::Room);
        }
        let dst = &mut out.buf[at..at + size];
        if o.format == gp::FORMAT_A1 {
            r.a1(dst);
        } else {
            r.a8(dst);
        }
        out.put_u16(e, w as u16);
        out.put_u16(e + 2, h as u16);
        out.put_u16(e + 4, left as i16 as u16);
        out.put_u16(e + 6, top as i16 as u16);
    }
    out.align4();
    Ok(())
}

/// Insertion sort by tag: core's sorts reference a panic PIC modules cannot
/// link.
fn sort_by_tag<T: Copy>(v: &mut [T], key: impl Fn(&T) -> u32) {
    for i in 1..v.len() {
        let mut j = i;
        while j > 0 && key(&v[j - 1]) > key(&v[j]) {
            v.swap(j - 1, j);
            j -= 1;
        }
    }
}

/// Bake `font` into a pack in `buf`; the pack's length.
pub fn bake(
    data: &[u8],
    o: &Options,
    digest: &[u8; 32],
    scratch: &mut Scratch,
    buf: &mut [u8],
) -> Result<usize, BakeError> {
    let font = Font::parse(data)?;
    let words = (font.glyphs as usize).div_ceil(8);
    if scratch.set.len() < words {
        return Err(BakeError::Scratch);
    }
    scratch.set[..words].fill(0);
    let mut set = GlyphSet {
        bits: &mut scratch.set[..words],
        glyphs: font.glyphs,
    };
    set.add(0);

    let mut tags: [(u32, Option<&[u8]>); 10] = [
        (gp::TAG_NAME, None),
        (gp::TAG_METRICS, None),
        (gp::TAG_CMAP, None),
        (gp::TAG_HMTX, None),
        (gp::TAG_SOURCE_DIGEST, None),
        (gp::TAG_STRIKES, None),
        (gp::TAG_GDEF, font.table(b"GDEF")),
        (gp::TAG_GSUB, font.table(b"GSUB")),
        (gp::TAG_GPOS, font.table(b"GPOS")),
        (gp::TAG_KERN, font.table(b"kern")),
    ];
    let n = tags
        .iter()
        .filter(|(t, v)| {
            v.is_some()
                || !matches!(
                    *t,
                    gp::TAG_GDEF | gp::TAG_GSUB | gp::TAG_GPOS | gp::TAG_KERN
                )
        })
        .count();
    sort_by_tag(&mut tags, |t| t.0);

    let mut out = Out::new(buf);
    out.bytes(&gp::MAGIC);
    out.u8(o.format);
    out.u8(0);
    out.u16(n as u16);
    out.u16(font.units_per_em);
    out.u16(font.glyphs);
    out.u32(0);
    let dir = out.reserve(n * gp::DIR_ENTRY);
    // cmap first: it fills the glyph set the strikes need, after the closure.
    let mut placed: [(u32, usize, usize); 10] = [(0, 0, 0); 10];
    let mut np = 0;
    let mut place = |out: &mut Out, tag: u32, start: usize, np: &mut usize| {
        placed[*np] = (tag, start, out.len - start);
        *np += 1;
    };

    out.align4();
    let s = out.len;
    write_cmap(&font, o.chars, &mut set, &mut out)?;
    place(&mut out, gp::TAG_CMAP, s, &mut np);
    if let Some(gsub) = font.table(b"GSUB") {
        closure::close(gsub, &mut set);
    }

    for &(tag, table) in tags.iter() {
        out.align4();
        let s = out.len;
        match tag {
            gp::TAG_CMAP => continue,
            gp::TAG_NAME => write_name(&font, &mut out),
            gp::TAG_METRICS => out.bytes(&metrics(&font).to_bytes()),
            gp::TAG_HMTX => {
                for g in 0..font.glyphs {
                    out.u16(font.advance(g));
                }
            }
            gp::TAG_SOURCE_DIGEST => out.bytes(digest),
            gp::TAG_STRIKES => {
                out.u32(o.ppems.len() as u32);
                let table = out.reserve(o.ppems.len() * 8);
                for (i, &ppem) in o.ppems.iter().enumerate() {
                    out.align4();
                    out.put_u16(table + i * 8, ppem);
                    out.put_u32(table + i * 8 + 4, (out.len - s) as u32);
                    write_strike(&font, o, ppem, &set, scratch.points, scratch.acc, &mut out)?;
                }
            }
            _ => match table {
                Some(t) => out.bytes(t),
                None => continue,
            },
        }
        place(&mut out, tag, s, &mut np);
    }
    out.align4();
    if out.full {
        return Err(BakeError::Room);
    }
    sort_by_tag(&mut placed[..np], |p| p.0);
    for (i, &(tag, off, len)) in placed[..np].iter().enumerate() {
        let at = dir + i * gp::DIR_ENTRY;
        out.put_u32(at, tag);
        out.put_u32(at + 4, off as u32);
        out.put_u32(at + 8, len as u32);
    }
    Ok(out.len)
}
