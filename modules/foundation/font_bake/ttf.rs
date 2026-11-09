//! Reading a TrueType font: its table directory, the tables a glyph pack
//! needs, and glyph outlines (`glyf`, simple and composite).
//!
//! Every read is bounds-checked: a malformed font reads as missing data, never
//! out of range.

pub fn be16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at + 2)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

pub fn bei16(b: &[u8], at: usize) -> Option<i16> {
    be16(b, at).map(|v| v as i16)
}

pub fn be32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at + 4)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// The tables a pack is made from, by index (messages name them).
pub const T_HEAD: u8 = 0;
pub const T_MAXP: u8 = 1;
pub const T_HHEA: u8 = 2;
pub const T_HMTX: u8 = 3;
pub const T_LOCA: u8 = 4;
pub const T_GLYF: u8 = 5;
pub const T_CMAP: u8 = 6;

/// Why a font cannot be baked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FontError {
    /// Not a TrueType font at all.
    NotTrueType,
    /// A table it needs is malformed (`T_*`).
    Malformed(u8),
    /// CFF outlines (`OTTO`): not yet parsed.
    Cff,
    /// A font collection (`ttcf`).
    Collection,
    /// A table the pack needs is missing (`T_*`).
    Missing(u8),
}

pub struct Font<'a> {
    pub data: &'a [u8],
    tables: usize,
    pub units_per_em: u16,
    pub glyphs: u16,
    long_loca: bool,
    loca: &'a [u8],
    glyf: &'a [u8],
    hmtx: &'a [u8],
    hmetrics: u16,
}

impl<'a> Font<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Font<'a>, FontError> {
        let version = be32(data, 0).ok_or(FontError::NotTrueType)?;
        match version {
            0x0001_0000 | 0x7472_7565 => {}
            0x4F54_544F => return Err(FontError::Cff),
            0x7474_6366 => return Err(FontError::Collection),
            _ => return Err(FontError::NotTrueType),
        }
        let tables = be16(data, 4).ok_or(FontError::NotTrueType)? as usize;
        let mut f = Font {
            data,
            tables,
            units_per_em: 0,
            glyphs: 0,
            long_loca: false,
            loca: &[],
            glyf: &[],
            hmtx: &[],
            hmetrics: 0,
        };
        let head = f.table(b"head").ok_or(FontError::Missing(T_HEAD))?;
        f.units_per_em = be16(head, 18).ok_or(FontError::Malformed(T_HEAD))?;
        f.long_loca = be16(head, 50).ok_or(FontError::Malformed(T_HEAD))? != 0;
        let maxp = f.table(b"maxp").ok_or(FontError::Missing(T_MAXP))?;
        f.glyphs = be16(maxp, 4).ok_or(FontError::Malformed(T_MAXP))?;
        let hhea = f.table(b"hhea").ok_or(FontError::Missing(T_HHEA))?;
        f.hmetrics = be16(hhea, 34).ok_or(FontError::Malformed(T_HHEA))?;
        f.hmtx = f.table(b"hmtx").ok_or(FontError::Missing(T_HMTX))?;
        f.loca = f.table(b"loca").ok_or(FontError::Missing(T_LOCA))?;
        f.glyf = f.table(b"glyf").ok_or(FontError::Missing(T_GLYF))?;
        if f.units_per_em == 0 || f.glyphs == 0 || f.hmetrics == 0 {
            return Err(FontError::Malformed(T_HEAD));
        }
        if f.hmtx.len() < f.hmetrics as usize * 4 {
            return Err(FontError::Malformed(T_HMTX));
        }
        let loca_entry = if f.long_loca { 4 } else { 2 };
        if f.loca.len() < (f.glyphs as usize + 1) * loca_entry {
            return Err(FontError::Malformed(T_LOCA));
        }
        Ok(f)
    }

    /// A table's bytes, by tag.
    pub fn table(&self, tag: &[u8; 4]) -> Option<&'a [u8]> {
        for i in 0..self.tables {
            let at = 12 + i * 16;
            if self.data.get(at..at + 4)? == tag {
                let off = be32(self.data, at + 8)? as usize;
                let len = be32(self.data, at + 12)? as usize;
                return self.data.get(off..off.checked_add(len)?);
            }
        }
        None
    }

    pub fn advance(&self, glyph: u16) -> u16 {
        let i = (glyph.min(self.hmetrics - 1)) as usize;
        be16(self.hmtx, i * 4).unwrap_or(0)
    }

    /// A glyph's `glyf` record; empty for a glyph with no outline.
    fn glyph_data(&self, glyph: u16) -> &'a [u8] {
        let g = glyph as usize;
        let (a, b) = if self.long_loca {
            (be32(self.loca, g * 4), be32(self.loca, g * 4 + 4))
        } else {
            (
                be16(self.loca, g * 2).map(|v| v as u32 * 2),
                be16(self.loca, g * 2 + 2).map(|v| v as u32 * 2),
            )
        };
        match (a, b) {
            (Some(a), Some(b)) if b > a => self.glyf.get(a as usize..b as usize).unwrap_or(&[]),
            _ => &[],
        }
    }

    /// Emit `glyph`'s contours, in font units, to `sink`. Composite glyphs
    /// are resolved, their components transformed; nesting deeper than
    /// eight is ignored.
    /// `scratch` holds one contour's points; a longer contour is cut short.
    pub fn outline<S: Sink>(&self, glyph: u16, scratch: &mut [Point], sink: &mut S) {
        self.outline_at(glyph, &IDENTITY, scratch, sink, 0);
    }

    fn outline_at<S: Sink>(
        &self,
        glyph: u16,
        m: &Transform,
        scratch: &mut [Point],
        sink: &mut S,
        depth: u32,
    ) {
        if depth > 8 {
            return;
        }
        let d = self.glyph_data(glyph);
        let Some(contours) = bei16(d, 0) else {
            return;
        };
        if contours >= 0 {
            simple(d, contours as usize, m, scratch, sink);
        } else {
            self.composite(d, m, scratch, sink, depth);
        }
    }

    fn composite<S: Sink>(
        &self,
        d: &[u8],
        m: &Transform,
        scratch: &mut [Point],
        sink: &mut S,
        depth: u32,
    ) {
        const WORDS: u16 = 0x0001;
        const XY: u16 = 0x0002;
        const SCALE: u16 = 0x0008;
        const MORE: u16 = 0x0020;
        const XY_SCALE: u16 = 0x0040;
        const TWO_BY_TWO: u16 = 0x0080;
        const SCALED_OFFSET: u16 = 0x0800;
        let mut at = 10;
        loop {
            let (Some(flags), Some(glyph)) = (be16(d, at), be16(d, at + 2)) else {
                return;
            };
            at += 4;
            let (dx, dy) = if flags & WORDS != 0 {
                let r = (bei16(d, at), bei16(d, at + 2));
                at += 4;
                match r {
                    (Some(a), Some(b)) => (a as f32, b as f32),
                    _ => return,
                }
            } else {
                let r = (d.get(at), d.get(at + 1));
                at += 2;
                match r {
                    (Some(&a), Some(&b)) => (a as i8 as f32, b as i8 as f32),
                    _ => return,
                }
            };
            let f2 = |at: usize| bei16(d, at).map_or(0.0, |v| v as f32 / 16384.0);
            let (mut a, mut b, mut c, mut e) = (1.0, 0.0, 0.0, 1.0);
            if flags & SCALE != 0 {
                a = f2(at);
                e = a;
                at += 2;
            } else if flags & XY_SCALE != 0 {
                a = f2(at);
                e = f2(at + 2);
                at += 4;
            } else if flags & TWO_BY_TWO != 0 {
                a = f2(at);
                b = f2(at + 2);
                c = f2(at + 4);
                e = f2(at + 6);
                at += 8;
            }
            // Point-matched placement (args are point numbers) is rare and
            // places the component at its own origin here.
            let (dx, dy) = if flags & XY == 0 {
                (0.0, 0.0)
            } else if flags & SCALED_OFFSET != 0 {
                (a * dx + c * dy, b * dx + e * dy)
            } else {
                (dx, dy)
            };
            let local = Transform {
                xx: a,
                xy: c,
                yx: b,
                yy: e,
                dx,
                dy,
            };
            let combined = m.then(&local);
            self.outline_at(glyph, &combined, scratch, sink, depth + 1);
            if flags & MORE == 0 {
                return;
            }
        }
    }
}

/// An affine transform: x' = xx·x + xy·y + dx, y' = yx·x + yy·y + dy.
#[derive(Clone, Copy)]
pub struct Transform {
    pub xx: f32,
    pub xy: f32,
    pub yx: f32,
    pub yy: f32,
    pub dx: f32,
    pub dy: f32,
}

pub const IDENTITY: Transform = Transform {
    xx: 1.0,
    xy: 0.0,
    yx: 0.0,
    yy: 1.0,
    dx: 0.0,
    dy: 0.0,
};

impl Transform {
    pub fn apply(&self, x: f32, y: f32) -> (f32, f32) {
        (
            self.xx * x + self.xy * y + self.dx,
            self.yx * x + self.yy * y + self.dy,
        )
    }

    /// `self` after `inner`: a point is transformed by `inner`, then `self`.
    fn then(&self, inner: &Transform) -> Transform {
        Transform {
            xx: self.xx * inner.xx + self.xy * inner.yx,
            xy: self.xx * inner.xy + self.xy * inner.yy,
            yx: self.yx * inner.xx + self.yy * inner.yx,
            yy: self.yx * inner.xy + self.yy * inner.yy,
            dx: self.xx * inner.dx + self.xy * inner.dy + self.dx,
            dy: self.yx * inner.dx + self.yy * inner.dy + self.dy,
        }
    }
}

/// Where outlines go: closed contours of lines and quadratic curves.
pub trait Sink {
    fn move_to(&mut self, x: f32, y: f32);
    fn line_to(&mut self, x: f32, y: f32);
    fn quad_to(&mut self, cx: f32, cy: f32, x: f32, y: f32);
    fn close(&mut self);
}

/// A simple glyph's contours.
/// A point of a contour: x, y, and whether it is on the curve.
pub type Point = (f32, f32, bool);

fn simple<S: Sink>(d: &[u8], contours: usize, m: &Transform, scratch: &mut [Point], sink: &mut S) {
    const ON: u8 = 0x01;
    const X_SHORT: u8 = 0x02;
    const Y_SHORT: u8 = 0x04;
    const REPEAT: u8 = 0x08;
    const X_SAME: u8 = 0x10;
    const Y_SAME: u8 = 0x20;
    if contours == 0 {
        return;
    }
    let Some(last) = be16(d, 10 + (contours - 1) * 2) else {
        return;
    };
    let points = last as usize + 1;
    let Some(ins) = be16(d, 10 + contours * 2) else {
        return;
    };
    let mut at = 10 + contours * 2 + 2 + ins as usize;
    // Flags, expanded later by walking them again: find where x starts.
    let flags_at = at;
    let mut n = 0;
    while n < points {
        let Some(&f) = d.get(at) else { return };
        at += 1;
        let mut rep = 1;
        if f & REPEAT != 0 {
            let Some(&r) = d.get(at) else { return };
            at += 1;
            rep += r as usize;
        }
        n += rep;
    }
    let xs_at = at;
    // Size of the x array.
    let mut fi = FlagIter::new(d, flags_at, points);
    let mut xlen = 0;
    while let Some(f) = fi.next() {
        if f & X_SHORT != 0 {
            xlen += 1;
        } else if f & X_SAME == 0 {
            xlen += 2;
        }
    }
    let ys_at = xs_at + xlen;

    let mut fi = FlagIter::new(d, flags_at, points);
    let (mut xa, mut ya) = (xs_at, ys_at);
    let (mut x, mut y) = (0i32, 0i32);
    let mut contour = 0;
    let mut end = be16(d, 10).unwrap_or(0) as usize;
    let mut n = 0usize;
    let mut i = 0;
    while let Some(f) = fi.next() {
        if f & X_SHORT != 0 {
            let v = *d.get(xa).unwrap_or(&0) as i32;
            xa += 1;
            x += if f & X_SAME != 0 { v } else { -v };
        } else if f & X_SAME == 0 {
            x += bei16(d, xa).unwrap_or(0) as i32;
            xa += 2;
        }
        if f & Y_SHORT != 0 {
            let v = *d.get(ya).unwrap_or(&0) as i32;
            ya += 1;
            y += if f & Y_SAME != 0 { v } else { -v };
        } else if f & Y_SAME == 0 {
            y += bei16(d, ya).unwrap_or(0) as i32;
            ya += 2;
        }
        let (tx, ty) = m.apply(x as f32, y as f32);
        if let Some(slot) = scratch.get_mut(n) {
            *slot = (tx, ty, f & ON != 0);
            n += 1;
        }
        if i == end {
            emit(&scratch[..n], sink);
            n = 0;
            contour += 1;
            if contour < contours {
                end = be16(d, 10 + contour * 2).unwrap_or(0) as usize;
            }
        }
        i += 1;
    }
}

struct FlagIter<'a> {
    d: &'a [u8],
    at: usize,
    left: usize,
    flag: u8,
    rep: usize,
}

impl<'a> FlagIter<'a> {
    fn new(d: &'a [u8], at: usize, points: usize) -> FlagIter<'a> {
        FlagIter {
            d,
            at,
            left: points,
            flag: 0,
            rep: 0,
        }
    }

    fn next(&mut self) -> Option<u8> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        if self.rep > 0 {
            self.rep -= 1;
            return Some(self.flag);
        }
        let f = *self.d.get(self.at)?;
        self.at += 1;
        if f & 0x08 != 0 {
            self.rep = *self.d.get(self.at)? as usize;
            self.at += 1;
        }
        self.flag = f;
        Some(f)
    }
}

/// Emit one closed contour of TrueType points (an on-curve point is implied
/// between two off-curve ones).
fn emit<S: Sink>(pts: &[Point], sink: &mut S) {
    let n = pts.len();
    if n < 2 {
        return;
    }
    let mut ctrl: Option<(f32, f32)> = None;
    let mut step = |q: (f32, f32, bool), sink: &mut S| {
        if q.2 {
            match ctrl.take() {
                Some(c) => sink.quad_to(c.0, c.1, q.0, q.1),
                None => sink.line_to(q.0, q.1),
            }
        } else {
            if let Some(c) = ctrl {
                sink.quad_to(c.0, c.1, (c.0 + q.0) / 2.0, (c.1 + q.1) / 2.0);
            }
            ctrl = Some((q.0, q.1));
        }
    };
    match pts.iter().position(|p| p.2) {
        Some(i) => {
            sink.move_to(pts[i].0, pts[i].1);
            for k in 1..=n {
                step(pts[(i + k) % n], sink);
            }
        }
        None => {
            let (a, b) = (pts[n - 1], pts[0]);
            let start = ((a.0 + b.0) / 2.0, (a.1 + b.1) / 2.0, true);
            sink.move_to(start.0, start.1);
            for &p in pts {
                step(p, sink);
            }
            step(start, sink);
        }
    }
    sink.close();
}
