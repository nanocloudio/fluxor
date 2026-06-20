//! Content-plane control renderer — the in-raster widget backend
//! (`.context/rfc_adaptive_presentation.md` §11.3). When a control resolves to
//! the `content` plane (a bare-metal panel that owns its framebuffer, no host
//! chrome), it is drawn *into the app's raster* rather than as DOM chrome. This
//! is the reusable renderer for that: it lays controls out in a grid, draws each
//! as a labelled/iconned button into an RGB565 buffer, and returns hit regions
//! so touch input maps back to a control.
//!
//! Pure + integer-only (no float, no alloc beyond the returned `Vec`), so the
//! on-device `content_controls` PIC module mirrors this exact logic with fixed
//! arrays, and it is fully unit-tested host-side by blitting into a `Vec<u16>`.
//! RGB565 little-endian matches `VideoRaster` / the display sinks.

/// A rectangle in pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

/// The glyph drawn on a control — transport icons cover the common media panel;
/// `Generic` is a plain filled button for anything else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    Play,
    Pause,
    Next,
    Prev,
    Stop,
    Generic,
}

/// Map a canonical `action.*` id (or FMP verb) to a transport icon.
pub fn icon_for_action(action: &str) -> Icon {
    if action.contains("toggle") || action.ends_with(".play") {
        Icon::Play
    } else if action.contains("pause") {
        Icon::Pause
    } else if action.contains("next") {
        Icon::Next
    } else if action.contains("prev") {
        Icon::Prev
    } else if action.contains("stop") {
        Icon::Stop
    } else {
        Icon::Generic
    }
}

/// One drawable control.
#[derive(Clone, Copy, Debug)]
pub struct Control {
    pub icon: Icon,
    pub pressed: bool,
}

/// Colour theme (RGB565).
#[derive(Clone, Copy, Debug)]
pub struct Theme {
    pub bg: u16,
    pub button: u16,
    pub button_pressed: u16,
    pub border: u16,
    pub icon: u16,
}

impl Default for Theme {
    fn default() -> Self {
        Theme {
            bg: rgb565(16, 16, 20),
            button: rgb565(34, 34, 40),
            button_pressed: rgb565(40, 136, 102), // accent green
            border: rgb565(80, 80, 90),
            icon: rgb565(235, 235, 240),
        }
    }
}

/// Pack 8-bit RGB into RGB565.
pub const fn rgb565(r: u8, g: u8, b: u8) -> u16 {
    (((r as u16) & 0xF8) << 8) | (((g as u16) & 0xFC) << 3) | ((b as u16) >> 3)
}

/// Smallest `c` with `c*c >= n` (integer ceil-sqrt), for grid column counts.
fn isqrt_ceil(n: usize) -> usize {
    if n <= 1 {
        return 1;
    }
    let mut c = 1usize;
    while c * c < n {
        c += 1;
    }
    c
}

/// Lay `n` controls out as a grid of buttons within `width`×`height`, each
/// inset by `pad`. Deterministic; row-major.
pub fn grid_layout(n: usize, width: u16, height: u16, pad: u16) -> Vec<Rect> {
    let mut out = Vec::with_capacity(n);
    if n == 0 || width == 0 || height == 0 {
        return out;
    }
    let cols = isqrt_ceil(n).max(1);
    let rows = n.div_ceil(cols);
    let cell_w = width / cols as u16;
    let cell_h = height / rows as u16;
    for i in 0..n {
        let col = (i % cols) as u16;
        let row = (i / cols) as u16;
        let x = col * cell_w + pad;
        let y = row * cell_h + pad;
        let w = cell_w.saturating_sub(2 * pad);
        let h = cell_h.saturating_sub(2 * pad);
        out.push(Rect { x, y, w, h });
    }
    out
}

#[inline]
fn put(fb: &mut [u16], stride: u16, x: u16, y: u16, c: u16) {
    let idx = (y as usize) * (stride as usize) + (x as usize);
    if idx < fb.len() {
        fb[idx] = c;
    }
}

/// Fill a rectangle.
pub fn fill_rect(fb: &mut [u16], stride: u16, r: Rect, c: u16) {
    for yy in r.y..r.y.saturating_add(r.h) {
        for xx in r.x..r.x.saturating_add(r.w) {
            put(fb, stride, xx, yy, c);
        }
    }
}

/// Draw a 1px border around a rect.
pub fn draw_border(fb: &mut [u16], stride: u16, r: Rect, c: u16) {
    if r.w == 0 || r.h == 0 {
        return;
    }
    let (x1, y1) = (r.x.saturating_add(r.w - 1), r.y.saturating_add(r.h - 1));
    for xx in r.x..=x1 {
        put(fb, stride, xx, r.y, c);
        put(fb, stride, xx, y1, c);
    }
    for yy in r.y..=y1 {
        put(fb, stride, r.x, yy, c);
        put(fb, stride, x1, yy, c);
    }
}

/// Draw a transport icon centred in `r` (inset to ~50%).
pub fn draw_icon(fb: &mut [u16], stride: u16, r: Rect, icon: Icon, c: u16) {
    // Inset region the glyph draws into.
    let iw = (r.w / 2).max(2);
    let ih = (r.h / 2).max(2);
    let ox = r.x + (r.w.saturating_sub(iw)) / 2;
    let oy = r.y + (r.h.saturating_sub(ih)) / 2;
    match icon {
        Icon::Generic => fill_rect(
            fb,
            stride,
            Rect {
                x: ox,
                y: oy,
                w: iw,
                h: ih,
            },
            c,
        ),
        Icon::Stop => fill_rect(
            fb,
            stride,
            Rect {
                x: ox,
                y: oy,
                w: iw,
                h: ih,
            },
            c,
        ),
        Icon::Pause => {
            let bw = (iw / 3).max(1);
            fill_rect(
                fb,
                stride,
                Rect {
                    x: ox,
                    y: oy,
                    w: bw,
                    h: ih,
                },
                c,
            );
            fill_rect(
                fb,
                stride,
                Rect {
                    x: ox + iw.saturating_sub(bw),
                    y: oy,
                    w: bw,
                    h: ih,
                },
                c,
            );
        }
        Icon::Play => draw_play(fb, stride, ox, oy, iw, ih, false, c),
        Icon::Next => {
            // A play triangle plus a bar on the right edge.
            draw_play(fb, stride, ox, oy, iw.saturating_sub(2), ih, false, c);
            let bw = 2.min(iw);
            fill_rect(
                fb,
                stride,
                Rect {
                    x: ox + iw.saturating_sub(bw),
                    y: oy,
                    w: bw,
                    h: ih,
                },
                c,
            );
        }
        Icon::Prev => {
            // A bar on the left edge plus a left-pointing triangle.
            let bw = 2.min(iw);
            fill_rect(
                fb,
                stride,
                Rect {
                    x: ox,
                    y: oy,
                    w: bw,
                    h: ih,
                },
                c,
            );
            draw_play(fb, stride, ox + bw, oy, iw.saturating_sub(bw), ih, true, c);
        }
    }
}

/// Draw a filled triangle pointing right (or left if `flip`).
#[allow(
    clippy::too_many_arguments,
    reason = "raster draw primitive: target buffer + geometry + flip + colour"
)]
fn draw_play(fb: &mut [u16], stride: u16, ox: u16, oy: u16, w: u16, h: u16, flip: bool, c: u16) {
    if w == 0 || h == 0 {
        return;
    }
    for yy in 0..h {
        // Distance from vertical centre, 0 at middle → full width.
        let from_mid = (2 * yy).abs_diff(h);
        let span = (w as u32 * (h as u32 - from_mid as u32) / h as u32) as u16;
        for xx in 0..span {
            let px = if flip {
                ox + w.saturating_sub(1 + xx)
            } else {
                ox + xx
            };
            put(fb, stride, px, oy + yy, c);
        }
    }
}

/// Hit-test a point against the laid-out rects → control index.
pub fn hit_test(rects: &[Rect], x: u16, y: u16) -> Option<usize> {
    rects.iter().position(|r| {
        x >= r.x && x < r.x.saturating_add(r.w) && y >= r.y && y < r.y.saturating_add(r.h)
    })
}

/// Render a control panel into `fb` (`width`×`height`, RGB565). Clears to the
/// theme background, draws each control as a button + icon, and returns the hit
/// rects (parallel to `controls`).
pub fn render_panel(
    fb: &mut [u16],
    width: u16,
    height: u16,
    controls: &[Control],
    theme: &Theme,
    pad: u16,
) -> Vec<Rect> {
    for px in fb.iter_mut() {
        *px = theme.bg;
    }
    let rects = grid_layout(controls.len(), width, height, pad);
    for (ctl, r) in controls.iter().zip(rects.iter()) {
        let bg = if ctl.pressed {
            theme.button_pressed
        } else {
            theme.button
        };
        fill_rect(fb, width, *r, bg);
        draw_border(fb, width, *r, theme.border);
        draw_icon(fb, width, *r, ctl.icon, theme.icon);
    }
    rects
}
