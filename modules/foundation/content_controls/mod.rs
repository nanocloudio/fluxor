//! Content-plane control panel — the in-raster widget backend
//! (`.context/rfc_adaptive_presentation.md` §11.3). On a surface with no host
//! chrome (a bare-metal panel that owns its framebuffer), controls that resolve
//! to the `content` plane are drawn *into the app's raster*. This module is that
//! renderer for a touch transport bar: it draws prev / play-pause / next buttons
//! into an RGB565 `VideoRaster` frame and, on a touch hit, emits the matching
//! FMP verb on `commands` — the same verb vocabulary `gesture` emits, so it
//! drives a `bank`/player identically. The pixel + hit-test logic mirrors
//! `tools/src/content_render.rs` (host-unit-tested; drift-guarded).
//!
//! Ports:
//!   in  `pointer`  — input::pointer events (touch); hit-tested against buttons
//!   out `raster`   — VideoRaster RGB565 frame (the drawn panel)
//!   out `commands` — FmpMessage verbs (prev / toggle / next) on tap
//!
//! Params: width, height, pad (transport layout is fixed: prev, play, next).

#![no_std]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

use abi::contracts::input::pointer as ptr;

const MAX_CONTROLS: usize = 8;

// ── Icon codes (mirror tools content_render::Icon ordering) ──────────
const ICON_PLAY: u8 = 0;
const ICON_PAUSE: u8 = 1;
const ICON_NEXT: u8 = 2;
const ICON_PREV: u8 = 3;
const ICON_STOP: u8 = 4;
const ICON_GENERIC: u8 = 5;

// ── Theme (RGB565) ───────────────────────────────────────────────────
const COL_BG: u16 = rgb565(16, 16, 20);
const COL_BUTTON: u16 = rgb565(34, 34, 40);
const COL_PRESSED: u16 = rgb565(40, 136, 102);
const COL_BORDER: u16 = rgb565(80, 80, 90);
const COL_ICON: u16 = rgb565(235, 235, 240);

#[derive(Clone, Copy)]
struct Rect {
    x: u16,
    y: u16,
    w: u16,
    h: u16,
}

const fn rgb565(r: u8, g: u8, b: u8) -> u16 {
    (((r as u16) & 0xF8) << 8) | (((g as u16) & 0xFC) << 3) | ((b as u16) >> 3)
}

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

/// Lay `n` controls out as a grid into `rects` (mirror of content_render::grid_layout).
fn grid_layout(n: usize, width: u16, height: u16, pad: u16, rects: &mut [Rect]) {
    if n == 0 || width == 0 || height == 0 {
        return;
    }
    let cols = isqrt_ceil(n).max(1);
    let rows = n.div_ceil(cols);
    // `.max(1)` on the u16 divisor so the no_std build can prove it is nonzero
    // (a bare `cols as u16` could wrap to 0 and emit a div-by-zero panic call).
    let cols_w = (cols as u16).max(1);
    let rows_w = (rows as u16).max(1);
    let cell_w = width / cols_w;
    let cell_h = height / rows_w;
    for i in 0..n.min(rects.len()) {
        let col = (i % cols) as u16;
        let row = (i / cols) as u16;
        rects[i] = Rect {
            x: col * cell_w + pad,
            y: row * cell_h + pad,
            w: cell_w.saturating_sub(2 * pad),
            h: cell_h.saturating_sub(2 * pad),
        };
    }
}

#[inline]
fn put(fb: &mut [u16], stride: u16, x: u16, y: u16, c: u16) {
    let idx = (y as usize) * (stride as usize) + (x as usize);
    if idx < fb.len() {
        fb[idx] = c;
    }
}

fn fill_rect(fb: &mut [u16], stride: u16, r: Rect, c: u16) {
    for yy in r.y..r.y.saturating_add(r.h) {
        for xx in r.x..r.x.saturating_add(r.w) {
            put(fb, stride, xx, yy, c);
        }
    }
}

fn draw_border(fb: &mut [u16], stride: u16, r: Rect, c: u16) {
    if r.w == 0 || r.h == 0 {
        return;
    }
    let x1 = r.x.saturating_add(r.w - 1);
    let y1 = r.y.saturating_add(r.h - 1);
    let mut xx = r.x;
    while xx <= x1 {
        put(fb, stride, xx, r.y, c);
        put(fb, stride, xx, y1, c);
        xx += 1;
    }
    let mut yy = r.y;
    while yy <= y1 {
        put(fb, stride, r.x, yy, c);
        put(fb, stride, x1, yy, c);
        yy += 1;
    }
}

fn draw_play(fb: &mut [u16], stride: u16, ox: u16, oy: u16, w: u16, h: u16, flip: bool, c: u16) {
    if w == 0 || h == 0 {
        return;
    }
    for yy in 0..h {
        let from_mid = if 2 * yy >= h { 2 * yy - h } else { h - 2 * yy };
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

fn draw_icon(fb: &mut [u16], stride: u16, r: Rect, icon: u8, c: u16) {
    let iw = (r.w / 2).max(2);
    let ih = (r.h / 2).max(2);
    let ox = r.x + r.w.saturating_sub(iw) / 2;
    let oy = r.y + r.h.saturating_sub(ih) / 2;
    match icon {
        ICON_GENERIC | ICON_STOP => fill_rect(fb, stride, Rect { x: ox, y: oy, w: iw, h: ih }, c),
        ICON_PAUSE => {
            let bw = (iw / 3).max(1);
            fill_rect(fb, stride, Rect { x: ox, y: oy, w: bw, h: ih }, c);
            fill_rect(
                fb,
                stride,
                Rect { x: ox + iw.saturating_sub(bw), y: oy, w: bw, h: ih },
                c,
            );
        }
        ICON_NEXT => {
            draw_play(fb, stride, ox, oy, iw.saturating_sub(2), ih, false, c);
            let bw = 2.min(iw);
            fill_rect(
                fb,
                stride,
                Rect { x: ox + iw.saturating_sub(bw), y: oy, w: bw, h: ih },
                c,
            );
        }
        ICON_PREV => {
            let bw = 2.min(iw);
            fill_rect(fb, stride, Rect { x: ox, y: oy, w: bw, h: ih }, c);
            draw_play(fb, stride, ox + bw, oy, iw.saturating_sub(bw), ih, true, c);
        }
        _ => draw_play(fb, stride, ox, oy, iw, ih, false, c), // ICON_PLAY
    }
}

fn hit_test(rects: &[Rect], n: usize, x: u16, y: u16) -> Option<usize> {
    for (i, r) in rects.iter().enumerate().take(n) {
        if x >= r.x && x < r.x.saturating_add(r.w) && y >= r.y && y < r.y.saturating_add(r.h) {
            return Some(i);
        }
    }
    None
}

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    in_chan: i32,
    raster_chan: i32,
    cmd_chan: i32,
    fb: *mut u16,
    width: u16,
    height: u16,
    pad: u16,
    n: usize,
    icons: [u8; MAX_CONTROLS],
    verbs: [u32; MAX_CONTROLS],
    pressed: [bool; MAX_CONTROLS],
    rects: [Rect; MAX_CONTROLS],
    dirty: bool,
    // Frame streaming: a frame is written to the raster channel in chunks
    // (the sink accumulates), respecting backpressure across steps.
    pending: bool,
    pending_off: u32,
    initialized: bool,
}

mod params_def {
    use super::p_u32;
    use super::State;
    use super::SCHEMA_MAX;

    define_params! {
        State;

        1, width, u32, 160
            => |s, d, len| { s.width = p_u32(d, len, 0, 160) as u16; };
        2, height, u32, 40
            => |s, d, len| { s.height = p_u32(d, len, 0, 40) as u16; };
        3, pad, u32, 2
            => |s, d, len| { s.pad = p_u32(d, len, 0, 2) as u16; };
    }
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

/// Extra per-module heap for the RGB565 framebuffer (`width*height*2`). A
/// control bar is wide-and-short; 48 KiB covers the 160×40 default (12 800 B)
/// with wide margin and any plausible bar up to ~256×96 (49 152 B) / 240×80
/// (38 400 B, the documented raster channel max). It is deliberately bounded
/// so the module fits a constrained host's state arena — an over-large frame
/// just fails the `heap_alloc` (module_step returns -3), never silently
/// over-reserves. A PIC module that omits this export gets only a page and the
/// framebuffer alloc fails.
const FB_ARENA_BYTES: u32 = 48 * 1024;

#[no_mangle]
#[link_section = ".text.module_arena_size"]
pub extern "C" fn module_arena_size() -> u32 {
    FB_ARENA_BYTES
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
#[allow(clippy::too_many_arguments, reason = "fixed module_new ABI signature")]
pub extern "C" fn module_new(
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<State>() {
            return -2;
        }
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = -1;
        s.raster_chan = -1;
        s.cmd_chan = -1;
        s.fb = core::ptr::null_mut();
        s.pad = 2;
        s.width = 160;
        s.height = 40;
        s.dirty = true;
        s.pending = false;
        s.pending_off = 0;
        s.initialized = false;

        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        // Fixed transport layout: prev, play/pause, next.
        s.n = 3;
        s.icons[0] = ICON_PREV;
        s.icons[1] = ICON_PLAY;
        s.icons[2] = ICON_NEXT;
        s.verbs[0] = fnv1a(b"prev");
        s.verbs[1] = fnv1a(b"toggle");
        s.verbs[2] = fnv1a(b"next");
        for p in s.pressed.iter_mut() {
            *p = false;
        }
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut State);
        if s.syscalls.is_null() {
            return -1;
        }
        let sys = &*s.syscalls;

        if !s.initialized {
            s.in_chan = dev_channel_port(sys, 0, 0); // input port 0: pointer
            s.raster_chan = dev_channel_port(sys, 1, 0); // output 0: raster
            s.cmd_chan = dev_channel_port(sys, 1, 1); // output 1: commands
            let px = (s.width as u32) * (s.height as u32);
            s.fb = (sys.heap_alloc)(px * 2) as *mut u16;
            if s.fb.is_null() {
                return -3;
            }
            grid_layout(s.n, s.width, s.height, s.pad, &mut s.rects);
            s.initialized = true;
        }

        // Drain pointer events → hit-test → emit verb + repaint.
        if s.in_chan >= 0 {
            let mut buf = [0u8; ptr::EVENT_SIZE];
            loop {
                let nread = (sys.channel_read)(s.in_chan, buf.as_mut_ptr(), buf.len());
                if nread < ptr::EVENT_SIZE as i32 {
                    break;
                }
                let kind = buf[2];
                let x = i16::from_le_bytes([buf[8], buf[9]]);
                let y = i16::from_le_bytes([buf[10], buf[11]]);
                if kind == ptr::KIND_DOWN && x >= 0 && y >= 0 {
                    if let Some(i) = hit_test(&s.rects, s.n, x as u16, y as u16) {
                        s.pressed[i] = true;
                        if s.cmd_chan >= 0 {
                            msg_write_empty(sys, s.cmd_chan, s.verbs[i]);
                        }
                        s.dirty = true;
                    }
                } else if kind == ptr::KIND_UP || kind == ptr::KIND_CANCEL {
                    for p in s.pressed.iter_mut().take(s.n) {
                        if *p {
                            s.dirty = true;
                        }
                        *p = false;
                    }
                }
            }
        }

        // Render the frame into the buffer when state changed, then begin
        // streaming it (the sink accumulates a frame's worth of bytes). Never
        // repaint while a frame is still in flight (`s.pending`): the sink has
        // already received a prefix of the old frame, so restarting at offset 0
        // with new pixels would splice two frames. `s.dirty` stays latched, so
        // the new state is rendered on a later step once the current frame has
        // fully drained.
        if s.dirty && !s.pending && !s.fb.is_null() {
            let px = (s.width as usize) * (s.height as usize);
            let fb = core::slice::from_raw_parts_mut(s.fb, px);
            for p in fb.iter_mut() {
                *p = COL_BG;
            }
            for i in 0..s.n {
                let r = s.rects[i];
                let bg = if s.pressed[i] { COL_PRESSED } else { COL_BUTTON };
                fill_rect(fb, s.width, r, bg);
                draw_border(fb, s.width, r, COL_BORDER);
                draw_icon(fb, s.width, r, s.icons[i], COL_ICON);
            }
            s.dirty = false;
            s.pending = true;
            s.pending_off = 0;
        }

        // Stream the rendered frame out in chunks ≤ the channel buffer,
        // respecting backpressure (resume next step if the sink is behind).
        if s.pending && s.raster_chan >= 0 && !s.fb.is_null() {
            let frame_bytes = (s.width as u32) * (s.height as u32) * 2;
            const CHUNK: u32 = 8192;
            loop {
                if s.pending_off >= frame_bytes {
                    s.pending = false;
                    break;
                }
                let poll = (sys.channel_poll)(s.raster_chan, POLL_OUT);
                if poll <= 0 || ((poll as u32) & POLL_OUT) == 0 {
                    break; // backpressure — resume next step
                }
                let remaining = frame_bytes - s.pending_off;
                let nbytes = remaining.min(CHUNK);
                let src = (s.fb as *const u8).add(s.pending_off as usize);
                let n = (sys.channel_write)(s.raster_chan, src, nbytes as usize);
                if n <= 0 {
                    break;
                }
                s.pending_off += n as u32;
            }
        }
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_channel_hints"]
pub extern "C" fn module_channel_hints(out: *mut u8, max_len: usize) -> i32 {
    let hints = [
        // raster: one RGB565 frame is written atomically, so the buffer must
        // hold a whole frame (≈ width*height*2). 96 KiB covers a 240×80 panel
        // (38 400 B) with headroom up to ~256×192.
        ChannelHint { port_type: 1, port_index: 0, buffer_size: 96 * 1024 },
        ChannelHint { port_type: 1, port_index: 1, buffer_size: 64 }, // commands (FMP)
    ];
    unsafe { write_channel_hints(out, max_len, &hints) }
}

include!("../../sdk/wasm_entry.rs");
