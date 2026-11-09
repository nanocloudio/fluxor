//! Coverage rasterising: a glyph outline, scaled to pixels, as the exact area
//! of each pixel it covers.
//!
//! Each line segment adds its signed area to an accumulation buffer, row by
//! row; a running sum over the buffer then gives each pixel's winding-weighted
//! coverage, clamped to one. Quadratic curves are flattened first, finely
//! enough that the error stays well under a pixel's coverage step.

use super::ttf::Sink;

pub fn floor(v: f32) -> f32 {
    let t = v as i32 as f32;
    if t > v {
        t - 1.0
    } else {
        t
    }
}

pub fn ceil(v: f32) -> f32 {
    let t = v as i32 as f32;
    if t < v {
        t + 1.0
    } else {
        t
    }
}

fn sqrt(v: f32) -> f32 {
    if v <= 0.0 {
        return 0.0;
    }
    let mut x = f32::from_bits((v.to_bits() >> 1) + 0x1fbd_1df5);
    for _ in 0..4 {
        x = 0.5 * (x + v / x);
    }
    x
}

fn abs(v: f32) -> f32 {
    if v < 0.0 {
        -v
    } else {
        v
    }
}

/// The bounds of an outline, from every point and control point.
pub struct Bounds {
    pub x0: f32,
    pub y0: f32,
    pub x1: f32,
    pub y1: f32,
    pub any: bool,
}

impl Bounds {
    pub fn new() -> Bounds {
        Bounds {
            x0: 0.0,
            y0: 0.0,
            x1: 0.0,
            y1: 0.0,
            any: false,
        }
    }

    fn add(&mut self, x: f32, y: f32) {
        if !self.any {
            *self = Bounds {
                x0: x,
                y0: y,
                x1: x,
                y1: y,
                any: true,
            };
            return;
        }
        self.x0 = self.x0.min(x);
        self.y0 = self.y0.min(y);
        self.x1 = self.x1.max(x);
        self.y1 = self.y1.max(y);
    }
}

impl Default for Bounds {
    fn default() -> Self {
        Bounds::new()
    }
}

impl Sink for Bounds {
    fn move_to(&mut self, x: f32, y: f32) {
        self.add(x, y);
    }
    fn line_to(&mut self, x: f32, y: f32) {
        self.add(x, y);
    }
    fn quad_to(&mut self, cx: f32, cy: f32, x: f32, y: f32) {
        self.add(cx, cy);
        self.add(x, y);
    }
    fn close(&mut self) {}
}

/// Rasterises into `acc`, `w × h` pixels plus slack, from an outline in
/// font units: a point (x, y) lands at pixel ((x·scale − left),
/// (top − y·scale)).
pub struct Raster<'a> {
    pub w: usize,
    pub h: usize,
    acc: &'a mut [f32],
    scale: f32,
    left: f32,
    top: f32,
    cur: (f32, f32),
    start: (f32, f32),
}

impl<'a> Raster<'a> {
    /// `acc` must hold at least `w * h + w + 4` values; it is cleared here.
    pub fn new(
        acc: &'a mut [f32],
        w: usize,
        h: usize,
        scale: f32,
        left: f32,
        top: f32,
    ) -> Raster<'a> {
        let n = (w * h + w + 4).min(acc.len());
        for v in acc[..n].iter_mut() {
            *v = 0.0;
        }
        Raster {
            w,
            h,
            acc,
            scale,
            left,
            top,
            cur: (0.0, 0.0),
            start: (0.0, 0.0),
        }
    }

    fn map(&self, x: f32, y: f32) -> (f32, f32) {
        (x * self.scale - self.left, self.top - y * self.scale)
    }

    fn add(&mut self, i: isize, v: f32) {
        if i >= 0 {
            if let Some(a) = self.acc.get_mut(i as usize) {
                *a += v;
            }
        }
    }

    fn line(&mut self, p0: (f32, f32), p1: (f32, f32)) {
        if p0.1 == p1.1 {
            return;
        }
        let w = self.w as f32;
        let clamp = |v: f32| v.max(0.0).min(w);
        let (dir, p0, p1) = if p0.1 < p1.1 {
            (1.0, p0, p1)
        } else {
            (-1.0, p1, p0)
        };
        let dxdy = (p1.0 - p0.0) / (p1.1 - p0.1);
        let mut x = p0.0;
        let y_start = p0.1.max(0.0);
        if p0.1 < 0.0 {
            x -= p0.1 * dxdy;
        }
        let y_end = (ceil(p1.1) as usize).min(self.h);
        let mut y = y_start as usize;
        while y < y_end {
            let line_start = (y * self.w) as isize;
            let dy = ((y + 1) as f32).min(p1.1) - (y as f32).max(p0.1);
            let x_next = x + dxdy * dy;
            let d = dy * dir;
            let (x0, x1) = if x < x_next { (x, x_next) } else { (x_next, x) };
            let (x0, x1) = (clamp(x0), clamp(x1));
            let x0f = floor(x0);
            let x0i = x0f as isize;
            let x1c = ceil(x1);
            let x1i = x1c as isize;
            if x1i <= x0i + 1 {
                let xmf = 0.5 * (clamp(x) + clamp(x_next)) - x0f;
                self.add(line_start + x0i, d - d * xmf);
                self.add(line_start + x0i + 1, d * xmf);
            } else {
                let s = 1.0 / (x1 - x0);
                let x0r = x0 - x0f;
                let a0 = 0.5 * s * (1.0 - x0r) * (1.0 - x0r);
                let x1r = x1 - x1c + 1.0;
                let am = 0.5 * s * x1r * x1r;
                self.add(line_start + x0i, d * a0);
                if x1i == x0i + 2 {
                    self.add(line_start + x0i + 1, d * (1.0 - a0 - am));
                } else {
                    let a1 = s * (1.5 - x0r);
                    self.add(line_start + x0i + 1, d * (a1 - a0));
                    let mut xi = x0i + 2;
                    while xi < x1i - 1 {
                        self.add(line_start + xi, d * s);
                        xi += 1;
                    }
                    let a2 = a1 + (x1i - x0i - 3) as f32 * s;
                    self.add(line_start + x1i - 1, d * (1.0 - a2 - am));
                }
                self.add(line_start + x1i, d * am);
            }
            x = x_next;
            y += 1;
        }
    }

    /// Write the coverage as a8, one byte a pixel, rows of `w` bytes.
    pub fn a8(&self, out: &mut [u8]) {
        let mut sum = 0.0;
        for (i, o) in out.iter_mut().enumerate().take(self.w * self.h) {
            sum += self.acc[i];
            let c = abs(sum).min(1.0);
            *o = (c * 255.0 + 0.5) as u8;
        }
    }

    /// Write the coverage as a1: a pixel is set when at least half covered;
    /// rows padded to whole bytes, most significant bit first.
    pub fn a1(&self, out: &mut [u8]) {
        let row = self.w.div_ceil(8);
        for b in out.iter_mut().take(row * self.h) {
            *b = 0;
        }
        let mut sum = 0.0;
        for y in 0..self.h {
            for x in 0..self.w {
                sum += self.acc[y * self.w + x];
                if abs(sum) >= 0.5 {
                    out[y * row + x / 8] |= 0x80 >> (x % 8);
                }
            }
        }
    }
}

impl Sink for Raster<'_> {
    fn move_to(&mut self, x: f32, y: f32) {
        let p = self.map(x, y);
        self.cur = p;
        self.start = p;
    }

    fn line_to(&mut self, x: f32, y: f32) {
        let p = self.map(x, y);
        self.line(self.cur, p);
        self.cur = p;
    }

    fn quad_to(&mut self, cx: f32, cy: f32, x: f32, y: f32) {
        let p0 = self.cur;
        let p1 = self.map(cx, cy);
        let p2 = self.map(x, y);
        let devx = p0.0 - 2.0 * p1.0 + p2.0;
        let devy = p0.1 - 2.0 * p1.1 + p2.1;
        // A quadratic strays at most |p0 − 2p1 + p2| / 4 from its chord, and
        // n chords cut that by n²: enough of them to keep within 1/50 px.
        let dev = sqrt(devx * devx + devy * devy);
        if dev < 0.08 {
            self.line(p0, p2);
            self.cur = p2;
            return;
        }
        let n = (1 + floor(sqrt(dev * 12.5)) as usize).min(64);
        let step = 1.0 / n as f32;
        let mut t = 0.0;
        let mut prev = p0;
        for _ in 0..n - 1 {
            t += step;
            let mt = 1.0 - t;
            let q = (
                mt * mt * p0.0 + 2.0 * mt * t * p1.0 + t * t * p2.0,
                mt * mt * p0.1 + 2.0 * mt * t * p1.1 + t * t * p2.1,
            );
            self.line(prev, q);
            prev = q;
        }
        self.line(prev, p2);
        self.cur = p2;
    }

    fn close(&mut self) {
        if self.cur != self.start {
            self.line(self.cur, self.start);
        }
        self.cur = self.start;
    }
}
