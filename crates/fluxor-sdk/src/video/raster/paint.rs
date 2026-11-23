//! The painter: the paint state of a frame (translation, clip rectangle,
//! rounded clips, the SAVE stack) and every drawing operation, composited
//! into a band.
//!
//! Each operation is translated, then clipped, then composited. A
//! rectangle's coverage is the exact area of the rectangle inside the clip
//! rectangle; any other shape's coverage is combined with the clip
//! rectangle's own area coverage; then each rounded clip combines in, in
//! the order they were set. Combining two coverages is `div255(c1 × c2)`.

use super::band::{sampled, solid, solid_alpha, solid_pair, Band, BAND_BPP};
use super::coverage::{join, Reach, Shape, NEAR_PIXELS, PIXEL, WHOLE};
use super::round::div255;
use super::source::{glyph_coverage, Resources, Surfaces, Texels};
use fluxor_abi::contracts::glyph_pack::{row_bytes, FORMAT_A8};
use fluxor_abi::contracts::video_draw::{
    Colour, Glyphs, PRect, Radii, Record, Rect, FILTER_BILINEAR,
};

/// One saved paint state.
#[derive(Clone, Copy)]
pub struct Saved {
    tx: i32,
    ty: i32,
    clip: Shape,
    rounded: usize,
}

impl Saved {
    /// An empty slot, to build the stack a `Painter` borrows.
    pub const EMPTY: Saved = Saved {
        tx: 0,
        ty: 0,
        clip: Shape::EMPTY,
        rounded: 0,
    };
}

/// The paint state and the operations that draw through it.
///
/// It borrows a SAVE stack and a rounded-clip list, each as deep as the
/// stream's `max_depth`. A SAVE past the stack or a rounded clip past the
/// list, which a validated stream never sends, is counted and otherwise
/// ignored, so its RESTORE still pairs.
pub struct Painter<'s> {
    stack: &'s mut [Saved],
    clips: &'s mut [Shape],
    depth: usize,
    unsaved: usize,
    tx: i32,
    ty: i32,
    clip: Shape,
    rounded: usize,
}

fn clamp_fx(v: i64) -> i32 {
    v.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

/// Fill whole pixels with `colour` at full coverage.
#[inline]
fn fill_run(run: &mut [u8], colour: Colour) {
    if colour[3] == 255 {
        // Twelve bytes, four pixels, are three whole words: the run is
        // written a word at a time between its unaligned ends.
        let rgb = [colour[0], colour[1], colour[2]];
        // SAFETY: any `u32` written is four valid bytes, and `align_to_mut`
        // keeps the words inside the bytes they are made of.
        let (before, words, after) = unsafe { run.align_to_mut::<u32>() };
        // Which of the three bytes comes next.
        let mut k = 0usize;
        let step = |k: usize| if k >= 2 { 0 } else { k + 1 };
        for b in before.iter_mut() {
            *b = rgb[k];
            k = step(k);
        }
        let (c0, c1, c2) = (rgb[k], rgb[step(k)], rgb[step(step(k))]);
        let three = [
            u32::from_ne_bytes([c0, c1, c2, c0]),
            u32::from_ne_bytes([c1, c2, c0, c1]),
            u32::from_ne_bytes([c2, c0, c1, c2]),
        ];
        let mut threes = words.chunks_exact_mut(3);
        for w in threes.by_ref() {
            w[0] = three[0];
            w[1] = three[1];
            w[2] = three[2];
        }
        // A word moves the phase on by one byte of the three.
        for (w, v) in threes.into_remainder().iter_mut().zip(three) {
            *w = v;
            k = step(k);
        }
        for b in after.iter_mut() {
            *b = rgb[k];
            k = step(k);
        }
    } else if colour[3] != 0 {
        let a = u32::from(colour[3]);
        let na = 255 - a;
        let (r, g, b) = (
            u32::from(colour[0]) * a,
            u32::from(colour[1]) * a,
            u32::from(colour[2]) * a,
        );
        for px in run.chunks_exact_mut(BAND_BPP) {
            px[0] = div255(r + u32::from(px[0]) * na) as u8;
            px[1] = div255(g + u32::from(px[1]) * na) as u8;
            px[2] = div255(b + u32::from(px[2]) * na) as u8;
        }
    }
}

/// A shape's reach, row after row: computed once for the rows across
/// which it does not change.
struct Reaches<'a> {
    shape: &'a Shape,
    steady: (i32, i32),
    held: Option<Reach>,
}

impl<'a> Reaches<'a> {
    fn of(shape: &'a Shape) -> Self {
        Reaches {
            shape,
            steady: shape.steady_rows(),
            held: None,
        }
    }

    #[inline]
    fn at(&mut self, py: i32) -> Reach {
        if py < self.steady.0 || py >= self.steady.1 {
            return self.shape.reach(py);
        }
        match self.held {
            Some(reach) => reach,
            None => {
                let reach = self.shape.reach(py);
                self.held = Some(reach);
                reach
            }
        }
    }
}

/// What the clip leaves of each row an operation paints: the rounded
/// clips' reach, met with the clip rectangle's for a shape not already cut
/// to it.
struct ClipRows<'a, 's> {
    painter: &'a Painter<'s>,
    rect: Option<Reaches<'a>>,
}

impl ClipRows<'_, '_> {
    #[inline]
    fn at(&mut self, py: i32) -> Reach {
        let rounded = if self.painter.rounded == 0 {
            Reach::ALL
        } else {
            self.painter.rounded_reach(py)
        };
        match self.rect.as_mut() {
            Some(rect) => rounded.meet(&rect.at(py)),
            None => rounded,
        }
    }
}

/// Which border side or sides own a pixel.
enum Owner {
    One(usize),
    /// A horizontal side, a vertical side, and the horizontal side's share
    /// of the pixel out of `WHOLE`.
    Two(usize, usize, u32),
}

const TOP: usize = 0;
const RIGHT: usize = 1;
const BOTTOM: usize = 2;
const LEFT: usize = 3;

/// A border's two boxes and what its sides are.
struct Ring {
    outer: Shape,
    inner: Shape,
    widths: [i32; 4],
    /// Both boxes are near the origin (`Shape::near`).
    near: bool,
}

/// The body of `Ring::owner` in the integer type `$t`: `i64` for any ring
/// and pixel, `i32` where `Ring::near` holds, every edge then being within
/// 2^26 fx of the origin and every sum inside ±2^28.
macro_rules! owner_of {
    ($t:ty, $ring:expr, $px:expr, $py:expr) => {{
        let (o, i): (&Shape, &Shape) = (&$ring.outer, &$ring.inner);
        const ONE: $t = PIXEL as $t;
        let cx = <$t>::from($px) * ONE + ONE / 2;
        let cy = <$t>::from($py) * ONE + ONE / 2;
        let top = cy < <$t>::from(i.y0);
        let bottom = !top && cy >= <$t>::from(i.y1);
        let left = cx < <$t>::from(i.x0);
        let right = !left && cx >= <$t>::from(i.x1);
        match (top || bottom, left || right) {
            (true, false) => Owner::One(if top { TOP } else { BOTTOM }),
            (false, true) => Owner::One(if left { LEFT } else { RIGHT }),
            _ => {
                let upper = top || (!bottom && 2 * cy < <$t>::from(i.y0) + <$t>::from(i.y1));
                let west = left || (!right && 2 * cx < <$t>::from(i.x0) + <$t>::from(i.x1));
                let (h, ey) = if upper {
                    (TOP, cy - <$t>::from(o.y0))
                } else {
                    (BOTTOM, <$t>::from(o.y1) - cy)
                };
                let (v, ex) = if west {
                    (LEFT, cx - <$t>::from(o.x0))
                } else {
                    (RIGHT, <$t>::from(o.x1) - cx)
                };
                let share = join(
                    $ring.widths[h],
                    $ring.widths[v],
                    clamp_fx(i64::from(ex)),
                    clamp_fx(i64::from(ey)),
                );
                Owner::Two(h, v, share)
            }
        }
    }};
}

impl Ring {
    /// The side or sides owning pixel `(px, py)`, by its centre.
    ///
    /// A centre above the inner box is the top side's, below it the
    /// bottom's, left of it the left's, right of it the right's. Where two
    /// of those hold, the pixel is in a corner and `join` splits it; a
    /// centre inside the inner box (under a rounded inner corner) is split
    /// the same way at the corner of the quadrant it lies in.
    fn owner(&self, px: i32, py: i32) -> Owner {
        if self.near && (px as u32) < NEAR_PIXELS && (py as u32) < NEAR_PIXELS {
            owner_of!(i32, self, px, py)
        } else {
            owner_of!(i64, self, px, py)
        }
    }

    /// The columns of row `py` one side owns alone: `first..end` and the
    /// side. A row whose centre is above or below the inner box has one
    /// such run, the top or bottom side's, between the inner box's left
    /// and right edges; any other row has two, the left side's and the
    /// right side's, either side of the inner box.
    fn alone(&self, py: i32) -> [(i32, i32, usize); 2] {
        let i = &self.inner;
        let cy = i64::from(py) * PIXEL + 32;
        // The first column whose centre is at or right of each edge.
        let west = ((i64::from(i.x0) + 31) >> 6).clamp(MIN_COLUMN, MAX_COLUMN) as i32;
        let east = ((i64::from(i.x1) + 31) >> 6).clamp(MIN_COLUMN, MAX_COLUMN) as i32;
        if cy < i64::from(i.y0) {
            [(west, east, TOP), (0, 0, TOP)]
        } else if cy >= i64::from(i.y1) {
            [(west, east, BOTTOM), (0, 0, BOTTOM)]
        } else {
            [(i32::MIN, west, LEFT), (east, i32::MAX, RIGHT)]
        }
    }
}

const MIN_COLUMN: i64 = i32::MIN as i64;
const MAX_COLUMN: i64 = i32::MAX as i64;

impl<'s> Painter<'s> {
    /// A painter over a SAVE stack and a rounded-clip list.
    pub fn new(stack: &'s mut [Saved], clips: &'s mut [Shape]) -> Self {
        Painter {
            stack,
            clips,
            depth: 0,
            unsaved: 0,
            tx: 0,
            ty: 0,
            clip: Shape::EMPTY,
            rounded: 0,
        }
    }

    /// Reset the state for a frame or a band: an empty stack, no
    /// translation, no rounded clips, and the clip rectangle `region`.
    pub fn begin(&mut self, region: PRect) {
        self.depth = 0;
        self.unsaved = 0;
        self.tx = 0;
        self.ty = 0;
        self.rounded = 0;
        let x0 = i64::from(region.x) * PIXEL;
        let y0 = i64::from(region.y) * PIXEL;
        self.clip = Shape::edges(
            x0,
            y0,
            x0 + i64::from(region.w) * PIXEL,
            y0 + i64::from(region.h) * PIXEL,
        );
    }

    /// The current translation, fx.
    pub fn translation(&self) -> (i32, i32) {
        (self.tx, self.ty)
    }

    /// `rect` in device space, inside the clip rectangle.
    pub fn placed(&self, rect: &Rect) -> Shape {
        Shape::rect(rect, self.tx, self.ty).clipped(&self.clip)
    }

    /// Apply `record` when it is a paint-state record: whether it was.
    pub fn state(&mut self, record: &Record<'_>) -> bool {
        match record {
            Record::Save => {
                if let Some(slot) = self.stack.get_mut(self.depth) {
                    *slot = Saved {
                        tx: self.tx,
                        ty: self.ty,
                        clip: self.clip,
                        rounded: self.rounded,
                    };
                    self.depth += 1;
                } else {
                    self.unsaved += 1;
                }
            }
            Record::Restore => {
                if self.unsaved > 0 {
                    self.unsaved -= 1;
                } else if self.depth > 0 {
                    self.depth -= 1;
                    let s = self.stack[self.depth];
                    self.tx = s.tx;
                    self.ty = s.ty;
                    self.clip = s.clip;
                    self.rounded = s.rounded;
                }
            }
            Record::ClipRect(rect) => self.clip = self.placed(rect),
            Record::ClipRRect { rect, radii } => {
                if let Some(slot) = self.clips.get_mut(self.rounded) {
                    *slot = Shape::rounded(rect, radii, self.tx, self.ty);
                    self.rounded += 1;
                }
            }
            Record::Translate { dx, dy } => {
                self.tx = clamp_fx(i64::from(self.tx) + i64::from(*dx));
                self.ty = clamp_fx(i64::from(self.ty) + i64::from(*dy));
            }
            _ => return false,
        }
        true
    }

    /// Apply one paint-state or drawing record to `band`. Any other record
    /// is ignored.
    pub fn apply<R: Resources, S: Surfaces>(
        &mut self,
        band: &mut Band<'_>,
        record: &Record<'_>,
        resources: &R,
        surfaces: &S,
    ) {
        if self.state(record) {
            return;
        }
        match record {
            Record::FillRect { rect, colour } => self.fill_rect(band, rect, *colour),
            Record::FillRRect {
                rect,
                radii,
                colour,
            } => self.fill_rrect(band, rect, radii, *colour),
            Record::Border {
                rect,
                radii,
                widths,
                colours,
            } => self.border(band, rect, radii, widths, colours),
            Record::Pixmap {
                id,
                filter,
                src,
                dst,
            } => {
                if let Some(texels) = resources.pixmap(*id) {
                    self.sample(band, &texels, *filter, *src, dst);
                }
            }
            Record::Glyphs(glyphs) => self.glyphs(band, glyphs, resources),
            Record::Surface {
                input,
                filter,
                src,
                dst,
            } => {
                if let Some(texels) = surfaces.surface(*input) {
                    self.sample(band, &texels, *filter, *src, dst);
                }
            }
            _ => {}
        }
    }

    /// SAVE records the painter holds a state for.
    pub(super) fn saved(&self) -> usize {
        self.depth
    }

    /// Whether `record` paints every pixel of `region` with one opaque
    /// colour in the current state: an opaque FILL_RECT that, inside the
    /// clip rectangle, reaches every edge of the region, with no rounded
    /// clip set. What those pixels held before does not show.
    pub(super) fn covers(&self, record: &Record<'_>, region: PRect) -> bool {
        let Record::FillRect { rect, colour } = record else {
            return false;
        };
        if colour[3] != 255 || self.rounded != 0 {
            return false;
        }
        let shape = self.placed(rect);
        let x0 = i64::from(region.x) * PIXEL;
        let y0 = i64::from(region.y) * PIXEL;
        i64::from(shape.x0) <= x0
            && i64::from(shape.y0) <= y0
            && i64::from(shape.x1) >= x0 + i64::from(region.w) * PIXEL
            && i64::from(shape.y1) >= y0 + i64::from(region.h) * PIXEL
    }

    /// The rows a drawing record can paint in the current state:
    /// `first..end`, empty when `first >= end`. `None` for any other
    /// record. Every operation paints inside these rows whatever the band,
    /// so a band they do not meet needs no visit to the record.
    pub(super) fn rows_of<R: Resources>(
        &self,
        record: &Record<'_>,
        resources: &R,
    ) -> Option<(i32, i32)> {
        let (c0, c1) = self.clip.rows();
        let within = |shape: Shape| {
            if shape.is_empty() {
                return (0, 0);
            }
            let (first, end) = shape.rows();
            (first.max(c0), end.min(c1))
        };
        Some(match record {
            Record::FillRect { rect, .. } => within(self.placed(rect)),
            Record::FillRRect { rect, .. } | Record::Border { rect, .. } => {
                within(Shape::rect(rect, self.tx, self.ty))
            }
            Record::Pixmap { dst, .. } | Record::Surface { dst, .. } => within(self.placed(dst)),
            Record::Glyphs(run) => {
                let Some(strike) = resources.strike(run.res) else {
                    return Some((0, 0));
                };
                let oy = i64::from(run.y) + i64::from(self.ty);
                let (mut first, mut end) = (i64::from(c1), i64::from(c0));
                for (glyph, _, dy) in run.iter() {
                    let Some((rise, height)) = strike.rows(glyph) else {
                        continue;
                    };
                    if height == 0 {
                        continue;
                    }
                    let top = ((oy + i64::from(dy) + 32) >> 6) - i64::from(rise);
                    first = first.min(top);
                    end = end.max(top + i64::from(height));
                }
                (
                    first.max(i64::from(c0)) as i32,
                    end.min(i64::from(c1)) as i32,
                )
            }
            _ => return None,
        })
    }

    /// The rows both `first..end` and the band hold.
    fn rows(band: &Band<'_>, first: i32, end: i32) -> (i32, i32) {
        let (b0, b1) = band.row_span();
        (first.max(b0), end.min(b1))
    }

    /// What the rounded clips leave of row `py`.
    fn rounded_reach(&self, py: i32) -> Reach {
        let mut reach = Reach::ALL;
        for clip in self.clips.iter().take(self.rounded) {
            reach = reach.meet(&clip.reach(py));
        }
        reach
    }

    /// `coverage` of pixel `(px, py)` through the rounded clips, in order.
    #[inline]
    fn through_rounded(&self, px: i32, py: i32, mut coverage: u32) -> u32 {
        for clip in self.clips.iter().take(self.rounded) {
            if coverage == 0 {
                break;
            }
            coverage = div255(coverage * clip.at(px, py));
        }
        coverage
    }

    /// `coverage` of pixel `(px, py)` through the clip: the clip
    /// rectangle's area coverage when the shape is not already cut to it,
    /// then the rounded clips.
    #[inline]
    fn through_clip(&self, px: i32, py: i32, coverage: u32, cut: bool) -> u32 {
        let c = if cut {
            coverage
        } else {
            div255(coverage * self.clip.at(px, py))
        };
        self.through_rounded(px, py, c)
    }

    /// What the clip leaves of the rows an operation paints, for a shape
    /// already cut to the clip rectangle (`cut`) or not.
    fn clip_rows(&self, cut: bool) -> ClipRows<'_, 's> {
        ClipRows {
            painter: self,
            rect: if cut {
                None
            } else {
                Some(Reaches::of(&self.clip))
            },
        }
    }

    /// Paint one row of a solid shape: `reach` says which columns it
    /// touches and which it covers whole, `cover` answers the rest.
    #[allow(
        clippy::too_many_arguments,
        reason = "one row's whole description: where, what the shape and the clip reach, the paint"
    )]
    fn solid_row<F: Fn(i32) -> u32>(
        &self,
        band: &mut Band<'_>,
        py: i32,
        reach: Reach,
        clip: Reach,
        cut: bool,
        colour: Colour,
        cover: F,
    ) {
        if reach.is_empty() || colour[3] == 0 {
            return;
        }
        let both = reach.meet(&clip);
        let Some((x0, run)) = band.span(py, both.lo, both.hi) else {
            return;
        };
        let x1 = x0 + (run.len() / BAND_BPP) as i32;
        let whole_lo = both.full_lo.max(x0).min(x1);
        let whole_hi = both.full_hi.min(x1).max(whole_lo);
        let Some((head, rest)) = run.split_at_mut_checked((whole_lo - x0) as usize * BAND_BPP)
        else {
            return;
        };
        let Some((middle, tail)) =
            rest.split_at_mut_checked((whole_hi - whole_lo) as usize * BAND_BPP)
        else {
            return;
        };
        let edge = |px: i32, out: &mut [u8]| {
            let c = if reach.whole(px) { 255 } else { cover(px) };
            if c == 0 {
                return;
            }
            let c = if clip.whole(px) {
                c
            } else {
                self.through_clip(px, py, c, cut)
            };
            solid(out, colour, c);
        };
        for (i, px) in head.chunks_exact_mut(BAND_BPP).enumerate() {
            edge(x0 + i as i32, px);
        }
        fill_run(middle, colour);
        for (i, px) in tail.chunks_exact_mut(BAND_BPP).enumerate() {
            edge(whole_hi + i as i32, px);
        }
    }

    fn fill_rect(&self, band: &mut Band<'_>, rect: &Rect, colour: Colour) {
        let shape = self.placed(rect);
        if shape.is_empty() {
            return;
        }
        let (first, end) = shape.rows();
        let (first, end) = Self::rows(band, first, end);
        let mut reaches = Reaches::of(&shape);
        let mut clips = self.clip_rows(true);
        for py in first..end {
            self.solid_row(band, py, reaches.at(py), clips.at(py), true, colour, |px| {
                shape.at(px, py)
            });
        }
    }

    fn fill_rrect(&self, band: &mut Band<'_>, rect: &Rect, radii: &Radii, colour: Colour) {
        let shape = Shape::rect(rect, self.tx, self.ty);
        if shape.is_empty() {
            return;
        }
        let (first, end) = shape.rows();
        let (c0, c1) = self.clip.rows();
        let (first, end) = Self::rows(band, first.max(c0), end.min(c1));
        if first >= end {
            return;
        }
        let shape = shape.with_radii(radii);
        let mut reaches = Reaches::of(&shape);
        let mut clips = self.clip_rows(false);
        for py in first..end {
            self.solid_row(
                band,
                py,
                reaches.at(py),
                clips.at(py),
                false,
                colour,
                |px| shape.at(px, py),
            );
        }
    }

    /// A border: the ring between the border box and the box drawn in by
    /// the four widths. A pixel's coverage is the outer shape's less the
    /// inner shape's. Sides of one colour are painted as one; where two
    /// sides of different colours share a pixel, `join` gives the
    /// horizontal side `coverage × share / 64` (rounded down) and the
    /// vertical side the rest.
    fn border(
        &self,
        band: &mut Band<'_>,
        rect: &Rect,
        radii: &Radii,
        widths: &[i32; 4],
        colours: &[Colour; 4],
    ) {
        let outer = Shape::rect(rect, self.tx, self.ty);
        if outer.is_empty() {
            return;
        }
        let (first, end) = outer.rows();
        let (c0, c1) = self.clip.rows();
        let (first, end) = Self::rows(band, first.max(c0), end.min(c1));
        if first >= end {
            return;
        }
        let outer = outer.with_radii(radii);
        let inner = outer.inset(widths);
        let ring = Ring {
            outer,
            inner,
            widths: *widths,
            near: outer.near() && inner.near(),
        };
        let hollow = !ring.inner.is_empty();
        let mut outers = Reaches::of(&outer);
        let mut inners = Reaches::of(&ring.inner);
        let mut clips = self.clip_rows(false);
        for py in first..end {
            let reach = outers.at(py);
            let within = if hollow { inners.at(py) } else { Reach::NONE };
            let clip = clips.at(py);
            let Some((x0, run)) = band.span(py, reach.lo.max(clip.lo), reach.hi.min(clip.hi))
            else {
                continue;
            };
            let x1 = x0 + (run.len() / BAND_BPP) as i32;
            // Where one side owns whole pixels the inner box does not
            // touch, outside nothing the clip cuts: runs of one colour.
            let plain_lo = reach.full_lo.max(clip.full_lo).max(x0);
            let plain_hi = reach.full_hi.min(clip.full_hi).min(x1);
            let mut plain = ring.alone(py);
            for (first, end, _) in plain.iter_mut() {
                *first = (*first).max(plain_lo);
                *end = (*end).min(plain_hi);
                // A column the inner box reaches is not plain.
                if *first < within.hi && *end > within.lo {
                    if *first >= within.lo {
                        *first = within.hi;
                    } else {
                        *end = within.lo;
                    }
                }
            }
            let mut next = x0;
            while next < x1 {
                let px = next;
                // The hole: nothing of the ring is in it.
                if within.whole(px) {
                    next = within.full_hi.max(px + 1);
                    continue;
                }
                let at = (px - x0) as usize * BAND_BPP;
                if let Some((_, end, side)) = plain.iter().find(|p| p.0 == px && p.1 > px) {
                    let len = (*end - px) as usize * BAND_BPP;
                    if let Some(out) = run.get_mut(at..at + len) {
                        // A short run is not worth the word fill's setup.
                        if len < 8 * BAND_BPP {
                            for one in out.chunks_exact_mut(BAND_BPP) {
                                solid(one, colours[*side], 255);
                            }
                        } else {
                            fill_run(out, colours[*side]);
                        }
                    }
                    next = *end;
                    continue;
                }
                next = px + 1;
                let Some(out) = run.get_mut(at..at + BAND_BPP) else {
                    break;
                };
                let o = if reach.whole(px) {
                    255
                } else {
                    outer.at(px, py)
                };
                let inside = if px >= within.lo && px < within.hi {
                    ring.inner.at(px, py)
                } else {
                    0
                };
                let mut c = o.saturating_sub(inside);
                if c != 0 && !clip.whole(px) {
                    c = self.through_clip(px, py, c, false);
                }
                if c == 0 {
                    continue;
                }
                match ring.owner(px, py) {
                    Owner::One(side) => solid(out, colours[side], c),
                    Owner::Two(h, v, share) => {
                        if colours[h] == colours[v] || share == WHOLE {
                            solid(out, colours[h], c);
                        } else if share == 0 {
                            solid(out, colours[v], c);
                        } else {
                            let first = c * share / WHOLE;
                            solid_pair(out, colours[h], first, colours[v], c - first);
                        }
                    }
                }
            }
        }
    }

    /// A glyph run. Glyph `i`'s origin is the run's origin plus the `dx` of
    /// every entry up to and including its own, with its `dy` added to the
    /// baseline for that glyph alone; the origin is rounded to a whole
    /// pixel (`(v + 32) >> 6`) and the strike entry's `left` and `top` place
    /// the bitmap. A glyph the strike does not hold draws nothing.
    fn glyphs<R: Resources>(&self, band: &mut Band<'_>, run: &Glyphs<'_>, resources: &R) {
        let Some(strike) = resources.strike(run.res) else {
            return;
        };
        let format = strike.format();
        let (c0, c1) = self.clip.rows();
        let (first, end) = Self::rows(band, c0, c1);
        if first >= end || run.colour[3] == 0 {
            return;
        }
        let (b0, b1) = band.columns();
        let plain = self.rounded == 0;
        let alpha = u32::from(run.colour[3]);
        let mut ox = i64::from(run.x) + i64::from(self.tx);
        let oy = i64::from(run.y) + i64::from(self.ty);
        let mut clips = self.clip_rows(false);
        let mut clip_rect = Reaches::of(&self.clip);
        for (glyph, dx, dy) in run.iter() {
            ox += i64::from(dx);
            let Some((rise, height)) = strike.rows(glyph) else {
                continue;
            };
            let gy = (oy + i64::from(dy) + 32) >> 6;
            let top = gy - i64::from(rise);
            if top >= i64::from(end) || top + i64::from(height) <= i64::from(first) {
                continue;
            }
            let Some(bitmap) = strike.glyph(glyph) else {
                continue;
            };
            if bitmap.w == 0 || bitmap.h == 0 {
                continue;
            }
            let left = ((ox + 32) >> 6) + i64::from(bitmap.left);
            let (left, top) = (clamp_fx(left), clamp_fx(top));
            let stride = row_bytes(format, bitmap.w);
            let reach = Reach {
                lo: left,
                hi: left.saturating_add(i32::from(bitmap.w)),
                full_lo: left,
                full_hi: left,
            };
            let r0 = first.max(top);
            let r1 = end.min(top.saturating_add(i32::from(bitmap.h)));
            // A glyph needs no clipping when no rounded clip is set and its
            // first and last rows, and so all of them, lie whole inside the
            // clip rectangle with its columns inside both it and the band.
            let unclipped = plain && r0 < r1 && {
                let (above, below) = (clip_rect.at(r0), clip_rect.at(r1 - 1));
                below.full_lo < below.full_hi
                    && left >= above.full_lo.max(b0)
                    && reach.hi <= above.full_hi.min(b1)
            };
            for py in r0..r1 {
                let at = (py - top) as usize * stride;
                let Some(row) = bitmap.data.get(at..at + stride) else {
                    break;
                };
                if unclipped {
                    let Some((_, out)) = band.span(py, reach.lo, reach.hi) else {
                        continue;
                    };
                    let pixels = out.chunks_exact_mut(BAND_BPP);
                    if format != FORMAT_A8 {
                        for (x, px) in pixels.enumerate() {
                            let c = glyph_coverage(format, row, x);
                            solid_alpha(px, run.colour, div255(alpha * c));
                        }
                    } else if alpha == 255 {
                        // A sample is the alpha.
                        for (px, c) in pixels.zip(row) {
                            solid_alpha(px, run.colour, u32::from(*c));
                        }
                    } else {
                        for (px, c) in pixels.zip(row) {
                            solid_alpha(px, run.colour, div255(alpha * u32::from(*c)));
                        }
                    }
                    continue;
                }
                self.solid_row(band, py, reach, clips.at(py), false, run.colour, |px| {
                    glyph_coverage(format, row, (px - left) as usize)
                });
            }
        }
    }

    /// Scale `src` of `texels` into `dst`.
    ///
    /// For destination pixel `px`, centre `x_c = 64 px + 32`, the source
    /// position in 1/256 texel relative to `src.x` is
    /// `S = floor((x_c − dst.x) × src.w × 256 / dst.w) − 128`. Nearest
    /// reads texel `src.x + clamp(floor((S + 128) / 256), 0, src.w − 1)`.
    /// Bilinear reads `i0 = floor(S / 256)` and `i0 + 1`, each clamped to
    /// `0..=src.w − 1`, with weights `256 − f` and `f`, `f = S − 256 i0`;
    /// the same in y; each premultiplied channel and alpha is
    /// `(Σ v × wx × wy + 32768) >> 16`.
    ///
    /// A `src` reaching outside the texels is cut to them; one wholly
    /// outside, or an empty `src` or `dst`, draws nothing.
    fn sample(&self, band: &mut Band<'_>, texels: &Texels<'_>, filter: u8, src: PRect, dst: &Rect) {
        let sx0 = u32::from(src.x);
        let sy0 = u32::from(src.y);
        let sx1 = (sx0 + u32::from(src.w)).min(u32::from(texels.width()));
        let sy1 = (sy0 + u32::from(src.h)).min(u32::from(texels.height()));
        if sx0 >= sx1 || sy0 >= sy1 || dst.w <= 0 || dst.h <= 0 {
            return;
        }
        let (sw, sh) = (i64::from(sx1 - sx0), i64::from(sy1 - sy0));
        let (dw, dh) = (i64::from(dst.w), i64::from(dst.h));
        let dx0 = i64::from(dst.x) + i64::from(self.tx);
        let dy0 = i64::from(dst.y) + i64::from(self.ty);
        let shape = self.placed(dst);
        if shape.is_empty() {
            return;
        }
        let (first, end) = shape.rows();
        let (first, end) = Self::rows(band, first, end);
        let bilinear = filter == FILTER_BILINEAR;
        let mut reaches = Reaches::of(&shape);
        let mut clips = self.clip_rows(true);
        // The texel pair and the weight of the second, for position `s`.
        let taps = |s: i64, extent: i64, origin: u32| -> (u32, u32, u32) {
            if bilinear {
                let i0 = s >> 8;
                let f = (s & 255) as u32;
                (
                    origin + i0.min(extent - 1).max(0) as u32,
                    origin + (i0 + 1).min(extent - 1).max(0) as u32,
                    f,
                )
            } else {
                let i = origin + ((s + 128) >> 8).min(extent - 1).max(0) as u32;
                (i, i, 0)
            }
        };
        for py in first..end {
            let reach = reaches.at(py);
            let clip = clips.at(py);
            let both = reach.meet(&clip);
            let Some((x0, run)) = band.span(py, both.lo, both.hi) else {
                continue;
            };
            let ny = (i64::from(py) * PIXEL + 32 - dy0) * sh * 256;
            let (ya, yb, fy) = taps(ny.div_euclid(dh) - 128, sh, sy0);
            let nx = (i64::from(x0) * PIXEL + 32 - dx0) * sw * 256;
            let (mut q, mut r) = (nx.div_euclid(dw), nx.rem_euclid(dw));
            let step = sw * 256 * PIXEL;
            let (step_q, step_r) = (step / dw, step % dw);
            for (i, out) in run.chunks_exact_mut(BAND_BPP).enumerate() {
                let px = x0 + i as i32;
                let s = q - 128;
                q += step_q;
                r += step_r;
                if r >= dw {
                    q += 1;
                    r -= dw;
                }
                let mut c = if reach.whole(px) {
                    255
                } else {
                    shape.at(px, py)
                };
                if c != 0 && !clip.whole(px) {
                    c = self.through_rounded(px, py, c);
                }
                if c == 0 {
                    continue;
                }
                let (xa, xb, fx) = taps(s, sw, sx0);
                let value = if fx == 0 && fy == 0 {
                    texels.texel(xa, ya)
                } else {
                    let t = [
                        texels.texel(xa, ya),
                        texels.texel(xb, ya),
                        texels.texel(xa, yb),
                        texels.texel(xb, yb),
                    ];
                    let w = [
                        (256 - fx) * (256 - fy),
                        fx * (256 - fy),
                        (256 - fx) * fy,
                        fx * fy,
                    ];
                    let mut v = [0u32; 4];
                    for (ch, out) in v.iter_mut().enumerate() {
                        *out = (t[0][ch] * w[0]
                            + t[1][ch] * w[1]
                            + t[2][ch] * w[2]
                            + t[3][ch] * w[3]
                            + 32768)
                            >> 16;
                    }
                    v
                };
                sampled(out, value, c);
            }
        }
    }
}
