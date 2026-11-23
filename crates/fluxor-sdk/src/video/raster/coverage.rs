//! Coverage: how much of a pixel a shape covers.
//!
//! `corner` and `join` are the reference functions of the `VideoDraw`
//! contract: their code is the specification of a rounded corner's
//! antialiasing and of how two border sides share a pixel, and the
//! conformance vectors pin them. Everything is integer arithmetic of
//! explicit width.
//!
//! Lengths are in fx (1/64 pixel). Pixel `p` spans `[64p, 64p + 64)` and its
//! centre is at `64p + 32`.

use super::round::quantise;
use fluxor_abi::contracts::video_draw::{Radii, Rect};

/// One pixel, in fx.
pub const PIXEL: i64 = 64;
/// Full coverage of a `corner` or `join` answer.
pub const WHOLE: u32 = 64;

/// The square root of `v`, rounded down.
pub fn isqrt(v: u64) -> u32 {
    if v <= u64::from(u32::MAX) {
        return isqrt32(v as u32);
    }
    let mut rem = v;
    let mut root = 0u64;
    let mut bit = 1u64 << 62;
    while bit != 0 {
        if rem >= root + bit {
            rem -= root + bit;
            root = (root >> 1) + bit;
        } else {
            root >>= 1;
        }
        bit >>= 2;
    }
    root as u32
}

fn isqrt32(v: u32) -> u32 {
    let mut rem = v;
    let mut root = 0u32;
    // The highest power of four at or below `v`.
    let mut bit = (1u32 << 30) >> ((v | 1).leading_zeros() & !1);
    while bit != 0 {
        if rem >= root + bit {
            rem -= root + bit;
            root = (root >> 1) + bit;
        } else {
            root >>= 1;
        }
        bit >>= 2;
    }
    root
}

/// Lengths below this many fx (512 pixels) square and sum inside 32 bits.
const SMALL: u32 = 1 << 15;
/// Edges within this many fx of the origin (2^20 pixels), with pixels
/// `0..NEAR_PIXELS`, keep every sum `Shape::at` makes inside `i32`.
const NEAR: i32 = 1 << 26;
pub(super) const NEAR_PIXELS: u32 = 1 << 20;

/// `corner` for a circular corner of radius `r` with `r`, `dx` and `dy` all
/// below `SMALL`: the same answer from 32-bit arithmetic. `dx² + dy²` is
/// below 2^31 and `(r + 32)²` below 2^32. Past the two early answers the
/// distance lies in `r − 31..=r + 31`, so its root is found from `r − 32`
/// (or 0 for a radius under half a pixel) in six steps.
fn corner_small(r: u32, dx: u32, dy: u32) -> u32 {
    let q = dx * dx + dy * dy;
    let outside = r + 32;
    if q >= outside * outside {
        return 0;
    }
    let mut root = 0;
    if r >= 32 {
        let whole = r - 31;
        if q < whole * whole {
            return WHOLE;
        }
        root = r - 32;
    }
    let mut bit = 32;
    while bit != 0 {
        let next = root + bit;
        if next * next <= q {
            root = next;
        }
        bit >>= 1;
    }
    (outside - root).min(WHOLE)
}

/// How much of pixel `p` the span `[lo, hi)` covers along one axis:
/// `0..=64`.
#[inline]
pub fn axis(lo: i32, hi: i32, p: i32) -> u32 {
    let start = i64::from(p) * PIXEL;
    let a = i64::from(lo).max(start);
    let b = i64::from(hi).min(start + PIXEL);
    if b > a {
        (b - a) as u32
    } else {
        0
    }
}

/// How far inside a rounded corner a pixel is: 0 (outside) to `WHOLE`.
///
/// The corner is a quarter ellipse with radii `rx`, `ry`. `dx`, `dy` are
/// the pixel centre's distance from the ellipse's centre, measured toward
/// the corner; negative values read as 0. A radius of 0 or less is a square
/// corner: `WHOLE`.
///
/// A circular corner (`rx == ry`) answers `r − d + 32` clamped to
/// `0..=64`, where `d` is the centre's distance from the circle's centre,
/// rounded down: a ramp one pixel wide across the arc. An elliptical corner
/// measures the same ramp along the ray from the centre: the centre's
/// position is normalised to a circle of radius 65,536, and the distance to
/// the arc is `(65536 − n) × p / n`, rounded down, with `n` the normalised
/// and `p` the true distance from the centre.
///
/// Values of 2^30 fx or more are halved, with the pixel, until they are
/// below it.
pub fn corner(rx: i32, ry: i32, dx: i32, dy: i32) -> u32 {
    if rx <= 0 || ry <= 0 {
        return WHOLE;
    }
    let (dx, dy) = (dx.max(0), dy.max(0));
    if rx == ry && ((rx | dx | dy) as u32) < SMALL {
        return corner_small(rx as u32, dx as u32, dy as u32);
    }
    let (mut rx, mut ry) = (rx as u64, ry as u64);
    let (mut dx, mut dy) = (dx as u64, dy as u64);
    let mut unit = PIXEL as u64;
    while (rx | ry | dx | dy) >> 30 != 0 {
        rx >>= 1;
        ry >>= 1;
        dx >>= 1;
        dy >>= 1;
        unit >>= 1;
    }
    if rx == 0 || ry == 0 {
        return WHOLE;
    }
    let half = unit / 2;
    let q = dx * dx + dy * dy;
    let inside = if rx == ry {
        let r = rx;
        if q >= (r + half) * (r + half) {
            return 0;
        }
        if r >= half && q < (r - half + 1) * (r - half + 1) {
            return WHOLE;
        }
        (r + half).saturating_sub(u64::from(isqrt(q))).min(unit)
    } else {
        const ONE: u64 = 1 << 16;
        let un = ((dx << 16) / rx).min(1 << 24);
        let vn = ((dy << 16) / ry).min(1 << 24);
        let n = u64::from(isqrt(un * un + vn * vn));
        if n == 0 {
            return WHOLE;
        }
        let p = i64::from(isqrt(q));
        let distance = ((ONE as i64 - n as i64) * p).div_euclid(n as i64);
        (distance + half as i64).min(unit as i64).max(0) as u64
    };
    (inside * PIXEL as u64 / unit) as u32
}

/// The share of a pixel that belongs to the horizontal side (top or
/// bottom) where it meets a vertical side (left or right) at a border's
/// corner: 0 to `WHOLE`; the rest is the vertical side's.
///
/// The two sides meet on the line from the border box's outer corner to its
/// inner corner. `horizontal` and `vertical` are the two sides' widths;
/// `ex`, `ey` are the pixel centre's distance from the outer corner, inward
/// along x and y. The share is `32 + (ex × horizontal − ey × vertical) /
/// (horizontal + vertical)`, rounded down and clamped: exact where the line
/// misses the pixel, linear across it. A side of no width owns nothing.
pub fn join(horizontal: i32, vertical: i32, ex: i32, ey: i32) -> u32 {
    if horizontal <= 0 {
        return 0;
    }
    if vertical <= 0 {
        return WHOLE;
    }
    // Widths and distances below `SMALL`: each product is inside 2^30 and
    // their difference inside `i32`.
    if ((horizontal | vertical) as u32) < SMALL && (ex.unsigned_abs() | ey.unsigned_abs()) < SMALL {
        let e = ex * horizontal - ey * vertical;
        return (e.div_euclid(horizontal + vertical) + 32).clamp(0, WHOLE as i32) as u32;
    }
    let (h, v) = (i64::from(horizontal), i64::from(vertical));
    let e = i64::from(ex) * h - i64::from(ey) * v;
    let sum = h + v;
    (e.div_euclid(sum) + 32).clamp(0, WHOLE as i64) as u32
}

/// The columns of one pixel row a shape reaches: `lo..hi` may be covered,
/// `full_lo..full_hi` is covered whole.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Reach {
    pub lo: i32,
    pub hi: i32,
    pub full_lo: i32,
    pub full_hi: i32,
}

impl Reach {
    pub const NONE: Reach = Reach {
        lo: 0,
        hi: 0,
        full_lo: 0,
        full_hi: 0,
    };

    /// Every column, whole.
    pub const ALL: Reach = Reach {
        lo: i32::MIN,
        hi: i32::MAX,
        full_lo: i32::MIN,
        full_hi: i32::MAX,
    };

    pub fn is_empty(&self) -> bool {
        self.lo >= self.hi
    }

    /// Whether column `px` is covered whole.
    #[inline(always)]
    pub fn whole(&self, px: i32) -> bool {
        px >= self.full_lo && px < self.full_hi
    }

    /// The columns both reach, whole where both are whole.
    pub fn meet(&self, other: &Reach) -> Reach {
        Reach {
            lo: self.lo.max(other.lo),
            hi: self.hi.min(other.hi),
            full_lo: self.full_lo.max(other.full_lo),
            full_hi: self.full_hi.min(other.full_hi),
        }
    }
}

fn floor_px(v: i64) -> i32 {
    v.div_euclid(PIXEL) as i32
}

fn ceil_px(v: i64) -> i32 {
    (v + PIXEL - 1).div_euclid(PIXEL) as i32
}

fn clamp_fx(v: i64) -> i32 {
    v.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

/// A rectangle with rounded corners, placed in device space.
///
/// The functions below make one; they keep the radii inside the overlap
/// rule and the two private facts true to the edges. The fields are public
/// to be read.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    pub x0: i32,
    pub y0: i32,
    pub x1: i32,
    pub y1: i32,
    /// `[rx, ry]` for the top-left, top-right, bottom-right and bottom-left
    /// corners, after the overlap rule; a square corner is `[0, 0]`.
    pub radii: [[i32; 2]; 4],
    rounded: bool,
    /// Every edge is within `NEAR` of the origin.
    near: bool,
}

/// Whether the four edges are all within `NEAR` of the origin.
fn near(x0: i32, y0: i32, x1: i32, y1: i32) -> bool {
    let within = |v: i32| v.unsigned_abs() <= NEAR as u32;
    within(x0) && within(y0) && within(x1) && within(y1)
}

/// The body of `Shape::at` in the integer type `$t`: `i64` for any shape
/// and pixel, `i32` for a near shape and a pixel in `0..NEAR_PIXELS`, where
/// every sum is inside ±2^27 (a corner's radii reach no further than the
/// opposite edge).
macro_rules! coverage_at {
    ($t:ty, $shape:expr, $px:expr, $py:expr) => {{
        let s: &Shape = $shape;
        const ONE: $t = PIXEL as $t;
        let (left, top) = (<$t>::from($px) * ONE, <$t>::from($py) * ONE);
        let (x0, y0) = (<$t>::from(s.x0), <$t>::from(s.y0));
        let (x1, y1) = (<$t>::from(s.x1), <$t>::from(s.y1));
        let ax = x1.min(left + ONE) - x0.max(left);
        let ay = y1.min(top + ONE) - y0.max(top);
        if ax <= 0 || ay <= 0 {
            return 0;
        }
        let area = ax as u32 * ay as u32;
        if !s.rounded {
            return quantise(area);
        }
        let (cx, cy) = (left + ONE / 2, top + ONE / 2);
        let r = |c: usize, axis: usize| <$t>::from(s.radii[c][axis]);
        // The corner whose square holds the centre, with the centre's
        // distance from the ellipse's centre toward that corner.
        let (c, dx, dy) = if r(0, 0) > 0 && cx < x0 + r(0, 0) && cy < y0 + r(0, 1) {
            (0, x0 + r(0, 0) - cx, y0 + r(0, 1) - cy)
        } else if r(1, 0) > 0 && cx > x1 - r(1, 0) && cy < y0 + r(1, 1) {
            (1, cx - (x1 - r(1, 0)), y0 + r(1, 1) - cy)
        } else if r(2, 0) > 0 && cx > x1 - r(2, 0) && cy > y1 - r(2, 1) {
            (2, cx - (x1 - r(2, 0)), cy - (y1 - r(2, 1)))
        } else if r(3, 0) > 0 && cx < x0 + r(3, 0) && cy > y1 - r(3, 1) {
            (3, x0 + r(3, 0) - cx, cy - (y1 - r(3, 1)))
        } else {
            return quantise(area);
        };
        let inside = corner(s.radii[c][0], s.radii[c][1], dx as i32, dy as i32);
        if inside == 0 {
            return 0;
        }
        // The edges opposite the corner.
        let far_x = if c == 0 || c == 3 {
            (x1 - left).clamp(0, ONE)
        } else {
            (left + ONE - x0).clamp(0, ONE)
        } as u32;
        let far_y = if c < 2 {
            (y1 - top).clamp(0, ONE)
        } else {
            (top + ONE - y0).clamp(0, ONE)
        } as u32;
        quantise(inside * far_x * far_y / 64)
    }};
}

/// The body of `Shape::reach` in the integer type `$t`, on the terms of
/// `coverage_at`.
macro_rules! reach_of {
    ($t:ty, $shape:expr, $py:expr) => {{
        let s: &Shape = $shape;
        const ONE: $t = PIXEL as $t;
        let floor = |v: $t| (v >> 6) as i32;
        let ceil = |v: $t| ((v + ONE - 1) >> 6) as i32;
        let top = <$t>::from($py) * ONE;
        let (x0, y0) = (<$t>::from(s.x0), <$t>::from(s.y0));
        let (x1, y1) = (<$t>::from(s.x1), <$t>::from(s.y1));
        let ay = y1.min(top + ONE) - y0.max(top);
        if ay <= 0 || x0 >= x1 {
            return Reach::NONE;
        }
        let (lo, hi) = (floor(x0), ceil(x1));
        if ay != ONE {
            return Reach {
                lo,
                hi,
                full_lo: lo,
                full_hi: lo,
            };
        }
        let mut full_lo = ceil(x0);
        let mut full_hi = floor(x1);
        if s.rounded {
            let cy = top + ONE / 2;
            let r = |c: usize, axis: usize| <$t>::from(s.radii[c][axis]);
            // The last corner asked about and its answer: the two corners
            // a row crosses are most often the same arc.
            let mut held = ([0i32; 2], 0 as $t, 0 as $t);
            let mut inward = |c: usize, dy: $t| {
                if held.0 != s.radii[c] || held.1 != dy {
                    held = (s.radii[c], dy, <$t>::from(s.inward(c, i64::from(dy))));
                }
                held.2
            };
            // A column is clear of a left corner when its centre is at or
            // right of the corner's centre, and of a right corner when at or
            // left of it; inside a circular corner it is whole as far as
            // `inward` toward the corner.
            let above = |c: usize| y0 + r(c, 1) - cy;
            let below = |c: usize| cy - (y1 - r(c, 1));
            if cy < y0 + r(0, 1) {
                full_lo = full_lo.max(ceil(x0 + r(0, 0) - inward(0, above(0)) - 32));
            }
            if cy > y1 - r(3, 1) {
                full_lo = full_lo.max(ceil(x0 + r(3, 0) - inward(3, below(3)) - 32));
            }
            if cy < y0 + r(1, 1) {
                full_hi = full_hi.min(floor(x1 - r(1, 0) + inward(1, above(1)) - 32) + 1);
            }
            if cy > y1 - r(2, 1) {
                full_hi = full_hi.min(floor(x1 - r(2, 0) + inward(2, below(2)) - 32) + 1);
            }
        }
        Reach {
            lo,
            hi,
            full_lo: full_lo.min(hi),
            full_hi: full_hi.max(full_lo.min(hi)),
        }
    }};
}

impl Shape {
    pub const EMPTY: Shape = Shape {
        x0: 0,
        y0: 0,
        x1: 0,
        y1: 0,
        radii: [[0; 2]; 4],
        rounded: false,
        near: true,
    };

    /// The edges `x0, y0, x1, y1` with square corners. An inverted pair of
    /// edges is an empty shape.
    pub fn edges(x0: i64, y0: i64, x1: i64, y1: i64) -> Shape {
        let (x0, y0) = (clamp_fx(x0), clamp_fx(y0));
        let (x1, y1) = (clamp_fx(x1).max(x0), clamp_fx(y1).max(y0));
        Shape {
            x0,
            y0,
            x1,
            y1,
            radii: [[0; 2]; 4],
            rounded: false,
            near: near(x0, y0, x1, y1),
        }
    }

    /// `rect` moved by `(tx, ty)`, with square corners.
    pub fn rect(rect: &Rect, tx: i32, ty: i32) -> Shape {
        let x0 = i64::from(rect.x) + i64::from(tx);
        let y0 = i64::from(rect.y) + i64::from(ty);
        Shape::edges(
            x0,
            y0,
            x0 + i64::from(rect.w.max(0)),
            y0 + i64::from(rect.h.max(0)),
        )
    }

    /// `rect` moved by `(tx, ty)`, with `radii`. Radii that overlap along a
    /// side are scaled down together: by the smallest `side / (r_a + r_b)`
    /// over the four sides, each radius becoming `r × side / (r_a + r_b)`
    /// rounded down. A corner with a radius of 0 on either axis is square.
    pub fn rounded(rect: &Rect, radii: &Radii, tx: i32, ty: i32) -> Shape {
        Shape::rect(rect, tx, ty).with_radii(radii)
    }

    /// This shape's edges with `radii`, under the overlap rule of
    /// `rounded`.
    pub fn with_radii(mut self, radii: &Radii) -> Shape {
        self.set_radii(&radii.0);
        self
    }

    fn set_radii(&mut self, radii: &[[i32; 2]; 4]) {
        let w = i64::from(self.x1) - i64::from(self.x0);
        let h = i64::from(self.y1) - i64::from(self.y0);
        let r = |c: usize, axis: usize| i64::from(radii[c][axis].max(0));
        // (side, sum of the two radii along it)
        let sides = [
            (w, r(0, 0) + r(1, 0)),
            (w, r(3, 0) + r(2, 0)),
            (h, r(0, 1) + r(3, 1)),
            (h, r(1, 1) + r(2, 1)),
        ];
        let (mut num, mut den) = (1i64, 1i64);
        for (side, sum) in sides {
            // side / sum < num / den, both denominators positive.
            if sum > side && side * den < num * sum {
                num = side;
                den = sum;
            }
        }
        self.rounded = false;
        let fit = num == den;
        for c in 0..4 {
            let (rx, ry) = if fit {
                (r(c, 0), r(c, 1))
            } else {
                (
                    (r(c, 0) * num).checked_div(den).unwrap_or(0),
                    (r(c, 1) * num).checked_div(den).unwrap_or(0),
                )
            };
            self.radii[c] = if rx > 0 && ry > 0 {
                self.rounded = true;
                [rx as i32, ry as i32]
            } else {
                [0, 0]
            };
        }
    }

    /// This shape drawn in by `top, right, bottom, left`, with each radius
    /// reduced by the insets beside it; a corner an inset reaches is
    /// square. Insets that cross leave an empty shape.
    pub fn inset(&self, insets: &[i32; 4]) -> Shape {
        let [top, right, bottom, left] = insets.map(|v| i64::from(v.max(0)));
        let x0 = (i64::from(self.x0) + left).min(i64::from(self.x1));
        let y0 = (i64::from(self.y0) + top).min(i64::from(self.y1));
        let x1 = (i64::from(self.x1) - right).max(x0);
        let y1 = (i64::from(self.y1) - bottom).max(y0);
        let mut s = Shape::edges(x0, y0, x1, y1);
        let beside = [[left, top], [right, top], [right, bottom], [left, bottom]];
        let mut radii = [[0i32; 2]; 4];
        for c in 0..4 {
            let rx = i64::from(self.radii[c][0]) - beside[c][0];
            let ry = i64::from(self.radii[c][1]) - beside[c][1];
            if rx > 0 && ry > 0 {
                radii[c] = [rx as i32, ry as i32];
            }
        }
        s.set_radii(&radii);
        s
    }

    /// The part of this shape inside `other`'s edges, with square corners.
    pub fn clipped(&self, other: &Shape) -> Shape {
        let x0 = self.x0.max(other.x0);
        let y0 = self.y0.max(other.y0);
        let x1 = self.x1.min(other.x1).max(x0);
        let y1 = self.y1.min(other.y1).max(y0);
        Shape {
            x0,
            y0,
            x1,
            y1,
            radii: [[0; 2]; 4],
            rounded: false,
            near: near(x0, y0, x1, y1),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.x0 >= self.x1 || self.y0 >= self.y1
    }

    /// Whether every edge is within 2^26 fx of the origin: the arithmetic
    /// on a pixel in `0..NEAR_PIXELS` then fits `i32`.
    pub(super) fn near(&self) -> bool {
        self.near
    }

    /// The pixel rows the shape reaches: `first..end`.
    pub fn rows(&self) -> (i32, i32) {
        (floor_px(i64::from(self.y0)), ceil_px(i64::from(self.y1)))
    }

    /// The pixel rows `first..end` across which `reach` gives one answer:
    /// rows the shape covers from top to bottom, clear of every corner.
    /// Empty (`first >= end`) when there is none.
    pub fn steady_rows(&self) -> (i32, i32) {
        let (y0, y1) = (i64::from(self.y0), i64::from(self.y1));
        let mut first = ceil_px(y0);
        let mut end = floor_px(y1);
        if self.rounded {
            // A row is clear of the top corners when its centre is at or
            // below both their centres, and of the bottom ones likewise.
            let top = i64::from(self.radii[0][1].max(self.radii[1][1]));
            let bottom = i64::from(self.radii[2][1].max(self.radii[3][1]));
            first = first.max(ceil_px(y0 + top - 32));
            end = end.min(floor_px(y1 - bottom - 32) + 1);
        }
        (first, end)
    }

    /// The pixel columns the shape reaches: `first..end`.
    pub fn columns(&self) -> (i32, i32) {
        (floor_px(i64::from(self.x0)), ceil_px(i64::from(self.x1)))
    }

    /// How far from corner `c`'s centre, toward the corner, a pixel centre
    /// `dy` from it along y is still wholly inside the arc: every `dx` up
    /// to the answer has `dx² + dy² <= (r − 32)²`, where `corner` answers
    /// `WHOLE`. 0 for an elliptical corner, or a row the arc's inside does
    /// not reach.
    fn inward(&self, c: usize, dy: i64) -> i32 {
        let [rx, ry] = self.radii[c];
        let reach = i64::from(rx) - 32;
        if rx != ry || reach <= 0 || dy <= 0 || dy > reach || rx >= 1 << 30 {
            return 0;
        }
        if (rx as u32) < SMALL {
            // Both squares are below 2^30.
            let (reach, dy) = (reach as u32, dy as u32);
            return isqrt32(reach * reach - dy * dy) as i32;
        }
        isqrt((reach * reach - dy * dy) as u64) as i32
    }

    /// The columns of pixel row `py` the shape reaches. Where it says a
    /// column is whole, `at` answers 255.
    pub fn reach(&self, py: i32) -> Reach {
        if self.near && (py as u32) < NEAR_PIXELS {
            reach_of!(i32, self, py)
        } else {
            reach_of!(i64, self, py)
        }
    }

    /// The coverage of pixel `(px, py)`: `0..=255`.
    ///
    /// A pixel whose centre lies inside a corner's square (within `rx` and
    /// `ry` of the corner, strictly) takes `corner`, scaled by how much of
    /// the pixel the two far edges leave: `corner × ax × ay / 64` in 1/4096.
    /// Any other pixel takes the exact area of the rectangle in it.
    pub fn at(&self, px: i32, py: i32) -> u32 {
        if self.near && (px as u32) < NEAR_PIXELS && (py as u32) < NEAR_PIXELS {
            coverage_at!(i32, self, px, py)
        } else {
            coverage_at!(i64, self, px, py)
        }
    }
}
