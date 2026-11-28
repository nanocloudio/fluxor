//! Paths: the reference code for the PATHS rules of the `VideoDraw`
//! contract. A path is placed through its transform, flattened in device
//! space, stroked into an outline if it is a stroke, and its coverage is
//! the signed area its segments leave in a strip of pixel cells.
//!
//! Everything is integer arithmetic of explicit width, and the sums in the
//! cells are commutative: the order segments arrive in changes nothing,
//! and each row is computed alone, so any strip or band height gives the
//! same pixels. A curve whose control points all lie outside the strip's
//! rows (widened by a stroke's reach) is taken as its chord: every segment
//! either gives misses those rows, so no cell changes.

use super::coverage::isqrt;
use fluxor_abi::contracts::video_draw::path::{Command, Header, Path};
use fluxor_abi::contracts::video_draw::{
    unit_circle, Transform, CAP_ROUND, CAP_SQUARE, CURVE_SEGMENTS_MAX, JOIN_MITER, JOIN_ROUND,
    MATRIX_MAX, MITER_MAX, MITER_MIN, PATH_COORD_MAX, PLACE_MAX, STROKE_WIDTH_MAX,
};

/// A cell sum of a pixel covered once: twice its area in 1/4096 pixel.
pub const FULL: i32 = 8192;

// Every division here has a positive divisor its caller has checked;
// each is written so that no input can make it panic.

/// `n / d` rounded down, `d > 0`.
#[inline(always)]
fn floor_div(n: i64, d: i64) -> i64 {
    n.checked_div_euclid(d).unwrap_or(0)
}

/// `n / d` rounded down, `d > 0`, in 32 bits.
#[inline(always)]
fn floor_div32(n: i32, d: i32) -> i32 {
    n.checked_div_euclid(d).unwrap_or(0)
}

/// `n / d` rounded to nearest (the floor of the value plus a half),
/// `d > 0`.
#[inline(always)]
fn round_div(n: i64, d: i64) -> i64 {
    floor_div(2 * n + d, 2 * d)
}

/// A path's transform with the paint state's translation added, held to
/// the contract's bounds (which a validated stream is already inside).
#[derive(Clone, Copy)]
pub struct Place {
    a: i64,
    b: i64,
    c: i64,
    d: i64,
    tx: i64,
    ty: i64,
}

impl Place {
    pub fn new(t: &Transform, dx: i32, dy: i32) -> Place {
        let m = |v: i32| i64::from(v.clamp(-MATRIX_MAX, MATRIX_MAX));
        let p = |v: i64| v.clamp(-i64::from(PLACE_MAX), i64::from(PLACE_MAX));
        Place {
            a: m(t.a),
            b: m(t.b),
            c: m(t.c),
            d: m(t.d),
            tx: p(i64::from(t.tx) + i64::from(dx)),
            ty: p(i64::from(t.ty) + i64::from(dy)),
        }
    }

    /// Path point `p` in device fx: `((a x + c y + 2^15) >> 16) + tx`.
    #[inline]
    pub fn point(&self, p: [i32; 2]) -> [i32; 2] {
        let x = i64::from(p[0].clamp(-PATH_COORD_MAX, PATH_COORD_MAX));
        let y = i64::from(p[1].clamp(-PATH_COORD_MAX, PATH_COORD_MAX));
        [
            (((self.a * x + self.c * y + (1 << 15)) >> 16) + self.tx) as i32,
            (((self.b * x + self.d * y + (1 << 15)) >> 16) + self.ty) as i32,
        ]
    }

    /// The device box, fx, inclusive, of everything a path inside `h`'s
    /// box places: its corners through the transform, widened by 1 fx.
    pub fn bounds(&self, h: &Header) -> [i32; 4] {
        let (mut x0, mut y0, mut x1, mut y1) = (i32::MAX, i32::MAX, i32::MIN, i32::MIN);
        for corner in [[h.x0, h.y0], [h.x1, h.y0], [h.x0, h.y1], [h.x1, h.y1]] {
            let [x, y] = self.point(corner);
            x0 = x0.min(x);
            y0 = y0.min(y);
            x1 = x1.max(x);
            y1 = y1.max(y);
        }
        [x0 - 1, y0 - 1, x1 + 1, y1 + 1]
    }

    /// The reach of a stroke's pen beyond its path, fx, along x and y.
    pub fn reach(&self, width: i32, join: u8, miter_limit: u16) -> [i32; 2] {
        let width = i64::from(width.clamp(0, STROKE_WIDTH_MAX));
        let limit = if join == JOIN_MITER {
            i64::from(miter_limit.clamp(MITER_MIN, MITER_MAX))
        } else {
            0
        };
        // h × max(limit, 1.5), h = width / 2, limit in 8.8.
        let r = (width * limit.max(384)) >> 9;
        let r = r + (r >> 10) + 4;
        [
            (((self.a.abs() + self.c.abs()) * r) >> 16) as i32 + 2,
            (((self.b.abs() + self.d.abs()) * r) >> 16) as i32 + 2,
        ]
    }
}

/// The strip of pixel cells a path is accumulated into: `rows` rows from
/// row `top`, each `width` columns from column `lo`, one `i32` a pixel.
pub struct Cells<'c> {
    cells: &'c mut [i32],
    lo: i32,
    width: i32,
    top: i32,
    rows: i32,
}

impl<'c> Cells<'c> {
    /// The strip over the front of `cells`, cleared. `None` when it does
    /// not fit.
    pub fn new(cells: &'c mut [i32], lo: i32, width: i32, top: i32, rows: i32) -> Option<Self> {
        if width <= 0 || rows <= 0 {
            return None;
        }
        let len = (width as usize).checked_mul(rows as usize)?;
        let cells = cells.get_mut(..len)?;
        cells.fill(0);
        Some(Cells {
            cells,
            lo,
            width,
            top,
            rows,
        })
    }

    /// The cells of row `py`.
    pub fn row(&self, py: i32) -> &[i32] {
        let r = py - self.top;
        if r < 0 || r >= self.rows {
            return &[];
        }
        let at = (r * self.width) as usize;
        self.cells.get(at..at + self.width as usize).unwrap_or(&[])
    }

    /// Accumulate the segment from `p` to `q`, device fx.
    pub fn edge(&mut self, p: [i32; 2], q: [i32; 2]) {
        if p[1] == q[1] {
            return;
        }
        // Top endpoint first; a segment going up counts negative.
        let (sign, [xa, ya], [xb, yb]) = if p[1] < q[1] { (1, p, q) } else { (-1, q, p) };
        // Rows are pixel rows of a surface: their fx fit 32 bits.
        if yb <= self.top * 64 || ya >= (self.top + self.rows) * 64 {
            return;
        }
        let first = (ya >> 6).max(self.top);
        let end = ((yb + 63) >> 6).min(self.top + self.rows);
        let (dx, dy) = (i64::from(xb) - i64::from(xa), i64::from(yb) - i64::from(ya));
        let small = dx.unsigned_abs() < 1 << 15 && dy < 1 << 16;
        // x at row boundary `y`, anchored at the top endpoint.
        let x_at = |y: i32| -> i32 {
            if small {
                let n = (y - ya) * dx as i32;
                xa + floor_div32(n, dy as i32)
            } else {
                (i64::from(xa) + floor_div((i64::from(y) - i64::from(ya)) * dx, dy)) as i32
            }
        };
        // Each row boundary's x is computed once, for the rows on both
        // sides of it; at an endpoint the formula gives the endpoint.
        let mut ys = ya.max(first * 64);
        let mut xs = x_at(ys);
        for r in first..end {
            let ye = yb.min(r * 64 + 64);
            if ye <= ys {
                continue;
            }
            let xe = x_at(ye);
            self.piece(r, xs, ys, xe, ye, sign);
            (xs, ys) = (xe, ye);
        }
    }

    /// One row's piece of a segment, from `(xs, ys)` down to `(xe, ye)`.
    fn piece(&mut self, r: i32, xs: i32, ys: i32, xe: i32, ye: i32, sign: i32) {
        let base = ((r - self.top) * self.width) as usize;
        let lo = self.lo;
        let (xl, yl, xr, yr, flip) = if xs <= xe {
            (xs, ys, xe, ye, false)
        } else {
            (xe, ye, xs, ys, true)
        };
        let (cl, cr) = (xl >> 6, xr >> 6);
        if cl == cr {
            self.add(base, cl, sign * (ye - ys), xl - 64 * cl, xr - 64 * cl);
            return;
        }
        let span = xr - xl;
        let dyw = yr - yl;
        // y at column boundary `x`, anchored at the piece's left end;
        // |dyw| <= 64.
        let y_at = |x: i32| -> i32 {
            if span < 1 << 24 {
                yl + floor_div32((x - xl) * dyw, span)
            } else {
                (i64::from(yl)
                    + floor_div(
                        (i64::from(x) - i64::from(xl)) * i64::from(dyw),
                        i64::from(span),
                    )) as i32
            }
        };
        let down = |from: i32, to: i32| if flip { from - to } else { to - from };
        let end = lo + self.width;
        let (mut c, mut x_in, mut y_in) = (cl, xl, yl);
        if c < lo {
            // Everything left of the drawn columns sums into the first.
            let cut = lo * 64;
            let (x_cut, y_cut) = if cut >= xr {
                (xr, yr)
            } else {
                (cut, y_at(cut))
            };
            self.add_left(base, sign * down(yl, y_cut));
            if x_cut >= xr {
                return;
            }
            (c, x_in, y_in) = (lo, x_cut, y_cut);
        }
        let last = cr.min(end - 1);
        while c <= last {
            let boundary = c * 64 + 64;
            let (x_out, y_out) = if boundary >= xr {
                (xr, yr)
            } else {
                (boundary, y_at(boundary))
            };
            self.add(
                base,
                c,
                sign * down(y_in, y_out),
                x_in - 64 * c,
                x_out - 64 * c,
            );
            (x_in, y_in) = (x_out, y_out);
            c += 1;
        }
    }

    /// A part of a piece in cell `c`: downward height `d` between the
    /// positions `fa` and `fb` inside the cell.
    #[inline(always)]
    fn add(&mut self, base: usize, c: i32, d: i32, fa: i32, fb: i32) {
        if d == 0 {
            return;
        }
        if c < self.lo {
            self.add_left(base, d);
            return;
        }
        let i = (c - self.lo) as usize;
        if i >= self.width as usize {
            return;
        }
        let a = d * (fa + fb);
        if let Some(v) = self.cells.get_mut(base + i) {
            *v = v.wrapping_add(128 * d - a);
        }
        if i + 1 < self.width as usize {
            if let Some(v) = self.cells.get_mut(base + i + 1) {
                *v = v.wrapping_add(a);
            }
        }
    }

    /// Downward height `d` left of the drawn columns.
    #[inline(always)]
    fn add_left(&mut self, base: usize, d: i32) {
        if let Some(v) = self.cells.get_mut(base) {
            *v = v.wrapping_add(128 * d);
        }
    }
}

/// A pixel's coverage, `0..=255`, from the running sum of its row's cells.
#[inline(always)]
pub fn coverage(sum: i32, evenodd: bool) -> u32 {
    let v = sum.unsigned_abs();
    let v = if evenodd {
        let m = v % (2 * FULL as u32);
        if m > FULL as u32 {
            2 * FULL as u32 - m
        } else {
            m
        }
    } else {
        v.min(FULL as u32)
    };
    (v * 255 + 4096) >> 13
}

/// Where flattened points go.
pub trait Outline {
    /// A subpath starts at `p`.
    fn start(&mut self, p: [i32; 2]);
    /// The subpath goes on to `p`. `corner`: `p` ends a command (rather
    /// than lying inside a flattened curve).
    fn to(&mut self, p: [i32; 2], corner: bool);
    /// CLOSE.
    fn close(&mut self);
    /// The subpath ends open.
    fn finish(&mut self);
}

/// The L1 length of `p − 2q + r`.
fn second(p: [i32; 2], q: [i32; 2], r: [i32; 2]) -> i64 {
    let d = |i: usize| (i64::from(p[i]) - 2 * i64::from(q[i]) + i64::from(r[i])).abs();
    d(0) + d(1)
}

/// The least `k` with `factor × 4^k >= d`, at most log2 of the cap.
fn segments(d: i64, factor: i64) -> u32 {
    let mut k = 0;
    while (1u32 << k) < CURVE_SEGMENTS_MAX && factor << (2 * k) < d {
        k += 1;
    }
    k
}

/// Hand `out` the points of a curve whose numerator, per axis, is the
/// cubic `a i³ + b i² + c i + d` (a quadratic has `a` 0) over `2^shift`,
/// for `i` in `1..=n`.
fn forward(coef: [[i64; 4]; 2], n: u32, shift: u32, end: [i32; 2], out: &mut impl Outline) {
    let half = (1i64 << shift) >> 1;
    let mut num = [coef[0][3], coef[1][3]];
    let mut d1 = [0i64; 2];
    let mut d2 = [0i64; 2];
    let mut d3 = [0i64; 2];
    for ax in 0..2 {
        let [a, b, c, _] = coef[ax];
        d1[ax] = a + b + c;
        d2[ax] = 6 * a + 2 * b;
        d3[ax] = 6 * a;
    }
    for _ in 1..n {
        for ax in 0..2 {
            num[ax] += d1[ax];
            d1[ax] += d2[ax];
            d2[ax] += d3[ax];
        }
        out.to(
            [
                ((num[0] + half) >> shift) as i32,
                ((num[1] + half) >> shift) as i32,
            ],
            false,
        );
    }
    out.to(end, true);
}

fn quad(p0: [i32; 2], p1: [i32; 2], p2: [i32; 2], out: &mut impl Outline) {
    let k = segments(second(p0, p1, p2), 12);
    let n = 1i64 << k;
    let coef = [0, 1].map(|ax| {
        let (p0, p1, p2) = (i64::from(p0[ax]), i64::from(p1[ax]), i64::from(p2[ax]));
        [0, p0 - 2 * p1 + p2, 2 * (p1 - p0) * n, p0 * n * n]
    });
    forward(coef, 1 << k, 2 * k, p2, out);
}

fn cubic(p0: [i32; 2], p1: [i32; 2], p2: [i32; 2], p3: [i32; 2], out: &mut impl Outline) {
    let k = segments(second(p0, p1, p2).max(second(p1, p2, p3)), 4);
    let n = 1i64 << k;
    let coef = [0, 1].map(|ax| {
        let (p0, p1, p2, p3) = (
            i64::from(p0[ax]),
            i64::from(p1[ax]),
            i64::from(p2[ax]),
            i64::from(p3[ax]),
        );
        [
            p3 - 3 * p2 + 3 * p1 - p0,
            3 * (p0 - 2 * p1 + p2) * n,
            3 * (p1 - p0) * n * n,
            p0 * n * n * n,
        ]
    });
    forward(coef, 1 << k, 3 * k, p3, out);
}

/// Flatten `path` through `place` into `out`. A curve whose points all lie
/// above `rows.0` or below `rows.1` (device fx) is taken as its chord.
pub fn flatten(path: &Path<'_>, place: &Place, rows: (i32, i32), out: &mut impl Outline) {
    let mut open = false;
    let (mut at, mut start) = ([0i32; 2], [0i32; 2]);
    let outside = |ys: &[i32]| ys.iter().all(|y| *y <= rows.0) || ys.iter().all(|y| *y >= rows.1);
    for command in path.commands() {
        match command {
            Command::Move(p) => {
                if open {
                    out.finish();
                }
                at = place.point(p);
                start = at;
                out.start(at);
                open = true;
            }
            Command::Close => {
                if open {
                    out.close();
                }
                open = false;
                at = start;
            }
            _ if !open => {}
            Command::Line(p) => {
                at = place.point(p);
                out.to(at, true);
            }
            Command::Quad(c, p) => {
                let (c, p) = (place.point(c), place.point(p));
                if outside(&[at[1], c[1], p[1]]) {
                    out.to(p, true);
                } else {
                    quad(at, c, p, out);
                }
                at = p;
            }
            Command::Cubic(c1, c2, p) => {
                let (c1, c2, p) = (place.point(c1), place.point(c2), place.point(p));
                if outside(&[at[1], c1[1], c2[1], p[1]]) {
                    out.to(p, true);
                } else {
                    cubic(at, c1, c2, p, out);
                }
                at = p;
            }
        }
    }
    if open {
        out.finish();
    }
}

/// A fill: every subpath closed, its segments into the cells.
pub struct Fill<'a, 'c> {
    cells: &'a mut Cells<'c>,
    start: [i32; 2],
    at: [i32; 2],
}

impl<'a, 'c> Fill<'a, 'c> {
    pub fn new(cells: &'a mut Cells<'c>) -> Self {
        Fill {
            cells,
            start: [0; 2],
            at: [0; 2],
        }
    }
}

impl Outline for Fill<'_, '_> {
    fn start(&mut self, p: [i32; 2]) {
        self.start = p;
        self.at = p;
    }

    fn to(&mut self, p: [i32; 2], _corner: bool) {
        self.cells.edge(self.at, p);
        self.at = p;
    }

    fn close(&mut self) {
        self.cells.edge(self.at, self.start);
        self.at = self.start;
    }

    fn finish(&mut self) {
        self.close();
    }
}

/// A unit vector, 2^14 long, in the path's own coordinates.
type Unit = [i64; 2];

const UNIT: i64 = 1 << 14;

fn cross(u: Unit, v: Unit) -> i64 {
    u[0] * v[1] - u[1] * v[0]
}

fn dot(u: Unit, v: Unit) -> i64 {
    u[0] * v[0] + u[1] * v[1]
}

fn neg(u: Unit) -> Unit {
    [-u[0], -u[1]]
}

/// A segment's direction, its left normal and the device offset of the
/// normal: the left side is `p + o`, the right `p − o`.
#[derive(Clone, Copy)]
struct Dir {
    u: Unit,
    n: Unit,
    o: [i32; 2],
}

/// Point `k` of the unit circle as a `Unit`.
fn circle(k: u32) -> Unit {
    let (c, s) = unit_circle(k);
    [i64::from(c), i64::from(s)]
}

/// The unit-circle point at or before `v`'s angle: `0..64`.
fn angle_index(v: Unit) -> u32 {
    let (q, x, y) = match (v[0] > 0, v[1] >= 0, v[0] <= 0 && v[1] > 0, v[0] < 0) {
        (true, true, _, _) => (0, v[0], v[1]),
        (_, _, true, _) => (1, v[1], -v[0]),
        (_, _, _, true) => (2, -v[0], -v[1]),
        _ => (3, -v[1], v[0]),
    };
    // The last of points 0..16 of the quarter at or before (x, y).
    let (mut lo, mut hi) = (0u32, 16u32);
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        let u = circle(mid);
        if u[0] * y - u[1] * x >= 0 {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    16 * q + lo
}

fn moved(p: [i32; 2], o: [i32; 2]) -> [i32; 2] {
    [p[0] + o[0], p[1] + o[1]]
}

fn back(p: [i32; 2], o: [i32; 2]) -> [i32; 2] {
    [p[0] - o[0], p[1] - o[1]]
}

/// The pen of a stroke.
pub struct Pen {
    place: Place,
    width: i64,
    join: u8,
    cap: u8,
    miter: i64,
    /// Unit-circle points round parts take: every `2^shift`th.
    shift: u32,
}

impl Pen {
    pub fn new(place: Place, width: i32, join: u8, cap: u8, miter_limit: u16) -> Pen {
        let width = i64::from(width.clamp(0, STROKE_WIDTH_MAX));
        let r = (width * (place.a.abs() + place.b.abs() + place.c.abs() + place.d.abs())) >> 17;
        let mut n = 8i64;
        while n < 64 && 3 * n * n < 5 * r {
            n *= 2;
        }
        Pen {
            place,
            width,
            join,
            cap,
            miter: i64::from(miter_limit.clamp(MITER_MIN, MITER_MAX)),
            shift: 6 - n.trailing_zeros(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.width == 0
    }

    /// The direction of device segment `p → q` in the path's coordinates.
    fn dir(&self, p: [i32; 2], q: [i32; 2]) -> Option<Dir> {
        let (dx, dy) = (
            i64::from(q[0]) - i64::from(p[0]),
            i64::from(q[1]) - i64::from(p[1]),
        );
        let pl = &self.place;
        let mut v = [pl.d * dx - pl.c * dy, pl.a * dy - pl.b * dx];
        if pl.a * pl.d - pl.b * pl.c < 0 {
            v = neg(v);
        }
        while v[0].abs() >= 1 << 15 || v[1].abs() >= 1 << 15 {
            v = [v[0] >> 1, v[1] >> 1];
        }
        // Each part is below 2^15: the squares, the root and the products
        // with 2^14 fit 32 bits.
        let (x, y) = (v[0] as i32, v[1] as i32);
        let len = isqrt((x * x + y * y) as u64) as i32;
        if len == 0 {
            return None;
        }
        let unit = |c: i32| floor_div32(2 * c * UNIT as i32 + len, 2 * len);
        let u = [i64::from(unit(x)), i64::from(unit(y))];
        let n = [-u[1], u[0]];
        Some(Dir {
            u,
            n,
            o: self.offset(n),
        })
    }

    /// The device offset of pen offset `k` (2^14 units of half the width).
    fn offset(&self, k: Unit) -> [i32; 2] {
        let pl = &self.place;
        let w = self.width;
        [
            (((pl.a * k[0] + pl.c * k[1]) * w + (1 << 30)) >> 31) as i32,
            (((pl.b * k[0] + pl.d * k[1]) * w + (1 << 30)) >> 31) as i32,
        ]
    }

    /// `p` moved by pen offset `k`.
    fn at(&self, p: [i32; 2], k: Unit) -> [i32; 2] {
        moved(p, self.offset(k))
    }
}

/// A stroke: the outline of each subpath into the cells. Geometry about a
/// vertex outside the strip's rows (widened by the pen's reach), and a
/// segment both of whose ends are outside on one side, is left out: none
/// of it reaches the strip.
pub struct Stroke<'a, 'c> {
    cells: &'a mut Cells<'c>,
    pen: &'a Pen,
    /// The rows, fx, outside which geometry is left out.
    rows: (i32, i32),
    start: [i32; 2],
    at: [i32; 2],
    /// `at` ends a command.
    corner: bool,
    /// The first and last segments' directions, `None` for one left out.
    first: Option<Dir>,
    last: Option<Dir>,
    /// The subpath has a segment of some length.
    segments: bool,
    /// The subpath has a drawing command.
    drew: bool,
    open: bool,
}

impl<'a, 'c> Stroke<'a, 'c> {
    /// A stroke into `cells`, leaving out geometry about points above
    /// `rows.0` or below `rows.1` (device fx).
    pub fn new(cells: &'a mut Cells<'c>, pen: &'a Pen, rows: (i32, i32)) -> Self {
        Stroke {
            cells,
            pen,
            rows,
            start: [0; 2],
            at: [0; 2],
            corner: true,
            first: None,
            last: None,
            segments: false,
            drew: false,
            open: false,
        }
    }

    fn line(&mut self, p: [i32; 2], q: [i32; 2]) {
        self.cells.edge(p, q);
    }

    /// The edges of a polyline through `points`.
    fn chain(&mut self, points: &[[i32; 2]]) {
        for pair in points.windows(2) {
            self.line(pair[0], pair[1]);
        }
    }

    fn outside(&self, p: [i32; 2]) -> bool {
        p[1] < self.rows.0 || p[1] > self.rows.1
    }

    /// One side's join at `p`, from outline point `a` (offset `from`) to
    /// `b` (offset `to`): through the vertex on the inner side, the join on
    /// the outer. `turn` is the way round an arc goes when the two offsets
    /// are opposite.
    #[allow(clippy::too_many_arguments, reason = "one side of one join, whole")]
    fn side(
        &mut self,
        p: [i32; 2],
        (from, a): (Unit, [i32; 2]),
        (to, b): (Unit, [i32; 2]),
        outer: bool,
        join: u8,
        turn: i64,
    ) {
        if !outer {
            self.chain(&[a, p, b]);
            return;
        }
        match join {
            JOIN_MITER => {
                let den = UNIT * UNIT + dot(from, to);
                if den * self.pen.miter * self.pen.miter >= 1 << 45 {
                    let m = [
                        round_div((from[0] + to[0]) * (UNIT * UNIT), den),
                        round_div((from[1] + to[1]) * (UNIT * UNIT), den),
                    ];
                    let m = self.pen.at(p, m);
                    self.chain(&[a, m, b]);
                } else {
                    self.line(a, b);
                }
            }
            JOIN_ROUND => {
                let c = cross(from, to);
                let turn = if c != 0 { c.signum() } else { turn };
                self.arc(p, (from, a), b, to, turn);
            }
            _ => self.line(a, b),
        }
    }

    /// An arc about `p` from outline point `a` (offset `from`) to `b`
    /// (offset `to`), turning `turn` (1 the way of increasing angle),
    /// through the unit-circle points strictly between them.
    fn arc(&mut self, p: [i32; 2], (from, a): (Unit, [i32; 2]), b: [i32; 2], to: Unit, turn: i64) {
        let shift = self.pen.shift;
        let inside = |u: Unit| {
            let (s, t) = (cross(from, u), cross(u, to));
            if turn > 0 {
                s > 0 && t > 0
            } else {
                s < 0 && t < 0
            }
        };
        let k = angle_index(from);
        let mut prev = a;
        for i in 1..=64u32.wrapping_shr(shift) {
            let index = if turn > 0 {
                (k.wrapping_shr(shift) + i).wrapping_shl(shift)
            } else {
                let exact = cross(circle(k), from) == 0 && dot(circle(k), from) > 0;
                let ceil = if exact { k } else { k + 1 };
                let up = (ceil + (1u32.wrapping_shl(shift) - 1)).wrapping_shr(shift);
                (up + 64 - i).wrapping_shl(shift)
            };
            let u = circle(index);
            if !inside(u) {
                break;
            }
            let next = self.pen.at(p, u);
            self.line(prev, next);
            prev = next;
        }
        self.line(prev, b);
    }

    /// The joins of vertex `p` between segments `a` and `b`.
    fn join(&mut self, p: [i32; 2], a: Dir, b: Dir, corner: bool) {
        let kind = if corner { self.pen.join } else { JOIN_ROUND };
        let c = cross(a.u, b.u);
        let (la, lb) = (moved(p, a.o), moved(p, b.o));
        let (ra, rb) = (back(p, a.o), back(p, b.o));
        if c == 0 && dot(a.u, b.u) > 0 {
            self.line(la, lb);
            self.line(rb, ra);
            return;
        }
        // Turning toward the left normal leaves the left side inner; a
        // reversal takes the left side as outer, its arc through `a.u`.
        let left_outer = c <= 0;
        self.side(p, (a.n, la), (b.n, lb), left_outer, kind, -1);
        self.side(p, (neg(b.n), rb), (neg(a.n), ra), !left_outer, kind, -1);
    }

    /// A cap at `p` from the outline's left point round to its right, out
    /// along `u`; `n` the left normal and `o` its device offset.
    fn cap(&mut self, p: [i32; 2], n: Unit, o: [i32; 2], u: Unit) {
        let (a, b) = (moved(p, o), back(p, o));
        match self.pen.cap {
            CAP_SQUARE => {
                let c = self.pen.at(p, [n[0] + u[0], n[1] + u[1]]);
                let d = self.pen.at(p, [u[0] - n[0], u[1] - n[1]]);
                self.chain(&[a, c, d, b]);
            }
            CAP_ROUND => self.arc(p, (n, a), b, neg(n), -1),
            _ => self.line(a, b),
        }
    }

    /// A subpath of no length: a disc, a square along the path's x axis,
    /// or nothing.
    fn dot(&mut self, p: [i32; 2]) {
        if self.outside(p) {
            return;
        }
        match self.pen.cap {
            CAP_ROUND => {
                let shift = self.pen.shift;
                let mut prev = self.pen.at(p, circle(0));
                for i in 1..=64u32.wrapping_shr(shift) {
                    let next = self.pen.at(p, circle(i.wrapping_shl(shift)));
                    self.line(prev, next);
                    prev = next;
                }
            }
            CAP_SQUARE => {
                let corners = [[1, 1], [-1, 1], [-1, -1], [1, -1], [1, 1]]
                    .map(|[x, y]| self.pen.at(p, [x * UNIT, y * UNIT]));
                self.chain(&corners);
            }
            _ => {}
        }
    }

    fn reset(&mut self) {
        self.first = None;
        self.last = None;
        self.segments = false;
        self.drew = false;
        self.open = false;
        self.corner = true;
    }
}

impl Outline for Stroke<'_, '_> {
    fn start(&mut self, p: [i32; 2]) {
        self.reset();
        self.start = p;
        self.at = p;
        self.open = true;
    }

    fn to(&mut self, p: [i32; 2], corner: bool) {
        if !self.open {
            return;
        }
        self.drew = true;
        if p == self.at {
            self.corner |= corner;
            return;
        }
        let at = self.at;
        let first = !self.segments;
        self.segments = true;
        let (above, below) = (
            at[1] < self.rows.0 && p[1] < self.rows.0,
            at[1] > self.rows.1 && p[1] > self.rows.1,
        );
        let dir = if above || below {
            None
        } else {
            self.pen.dir(at, p)
        };
        if let Some(dir) = dir {
            if let Some(last) = self.last {
                if !self.outside(at) {
                    self.join(at, last, dir, self.corner);
                }
            }
            self.line(moved(at, dir.o), moved(p, dir.o));
            self.line(back(p, dir.o), back(at, dir.o));
        }
        if first {
            self.first = dir;
        }
        self.last = dir;
        self.at = p;
        self.corner = corner;
    }

    fn close(&mut self) {
        if !self.open {
            return;
        }
        self.drew = true;
        let start = self.start;
        self.to(start, true);
        if !self.segments {
            self.dot(start);
        } else if let (Some(first), Some(last)) = (self.first, self.last) {
            if !self.outside(start) {
                self.join(start, last, first, true);
            }
        }
        self.reset();
    }

    fn finish(&mut self) {
        if !self.open {
            return;
        }
        if !self.segments {
            if self.drew {
                let start = self.start;
                self.dot(start);
            }
        } else {
            let (end, start) = (self.at, self.start);
            if let Some(last) = self.last {
                if !self.outside(end) {
                    self.cap(end, last.n, last.o, last.u);
                }
            }
            if let Some(first) = self.first {
                if !self.outside(start) {
                    self.cap(
                        start,
                        neg(first.n),
                        [-first.o[0], -first.o[1]],
                        neg(first.u),
                    );
                }
            }
        }
        self.reset();
    }
}
