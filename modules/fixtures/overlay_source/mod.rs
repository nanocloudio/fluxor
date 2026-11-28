//! overlay_source — a drawn menu over a moving picture, for a rasteriser's
//! SURFACE path under test.
//!
//! `draw` carries one static `VideoDraw` frame: a SURFACE record placing
//! the consumer's raster input 0 across the whole surface, then a
//! translucent rounded panel and three menu rows. `surface` carries the
//! picture that input shows: a checkerboard with a bar that moves a step
//! each frame, a frame every `FRAME_STEPS` steps.

#![cfg_attr(not(feature = "host-test"), no_std)]

use core::ffi::c_void;

use abi::contracts::video_draw::{self as vd, Record};
use abi::contracts::video_raster as raster;
use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

/// The surface both streams describe.
const WIDTH: u16 = 256;
const HEIGHT: u16 = 192;
/// Rows in a band of the picture.
const BAND_ROWS: u16 = 8;
const ROW_BYTES: usize = WIDTH as usize * 2;
/// Steps between the picture's frames.
const FRAME_STEPS: u32 = 32;
/// The draw stream, with room to spare.
const STREAM_BYTES: usize = 384;

/// The picture's colours, RGB565.
const DARK: u16 = 0x2104;
const LIGHT: u16 = 0x4A69;
const BAR: u16 = 0xFD20;

#[repr(C)]
pub struct State {
    syscalls: *const SyscallTable,
    draw: i32,
    surface: i32,
    stream: [u8; STREAM_BYTES],
    len: usize,
    sent: usize,
    /// Steps since the picture's last frame began, and frames begun.
    steps: u32,
    frames: u32,
    /// The frame being sent.
    painting: bool,
    band: u16,
    row: u16,
    header_sent: bool,
}

fluxor_rt::module_facts! { state: State }

/// Write the draw stream into `out`: its length, or `None` when a record
/// does not fit.
fn compose(out: &mut [u8]) -> Option<usize> {
    let mut at = 0usize;
    let mut put = |record: &Record<'_>| -> Option<()> {
        at += vd::write(out.get_mut(at..)?, record)?;
        Some(())
    };
    let whole = vd::PRect {
        x: 0,
        y: 0,
        w: WIDTH,
        h: HEIGHT,
    };
    let fx = |v: i32| v * vd::FX_ONE;
    put(&Record::Stream(vd::Stream {
        width: WIDTH,
        height: HEIGHT,
        band_rows: 0,
        max_depth: 0,
        max_resources: 0,
        resource_bytes: 0,
        generation: 1,
    }))?;
    put(&Record::Frame {
        generation: 1,
        revision: 1,
        damage: whole,
    })?;
    // The picture, pixel for pixel across the whole surface.
    put(&Record::Surface {
        input: 0,
        filter: vd::FILTER_NEAREST,
        src: whole,
        dst: vd::Rect {
            x: 0,
            y: 0,
            w: fx(i32::from(WIDTH)),
            h: fx(i32::from(HEIGHT)),
        },
    })?;
    // The menu: a translucent panel, and three rows with the second chosen.
    put(&Record::FillRRect {
        rect: vd::Rect {
            x: fx(48),
            y: fx(40),
            w: fx(160),
            h: fx(112),
        },
        radii: vd::Radii([[fx(10); 2]; 4]),
        colour: [16, 24, 40, 200],
        current: false,
    })?;
    for item in 0..3i32 {
        let chosen = item == 1;
        put(&Record::FillRect {
            rect: vd::Rect {
                x: fx(60),
                y: fx(54 + item * 30),
                w: fx(136),
                h: fx(22),
            },
            colour: if chosen {
                [230, 120, 30, 255]
            } else {
                [200, 208, 220, 96]
            },
            current: false,
        })?;
    }
    put(&Record::Commit { revision: 1 })?;
    put(&Record::End)?;
    Some(at)
}

/// Row `y` of picture `frame`: a checkerboard of 16-pixel squares with a
/// 16-pixel bar that stands one square further right each frame.
fn paint_row(frame: u32, y: u16, row: &mut [u8; ROW_BYTES]) {
    let bar = (frame % u32::from(WIDTH / 16)) as u16;
    for (x, px) in row.chunks_exact_mut(2).enumerate() {
        let square = x as u16 / 16;
        let colour = if square == bar {
            BAR
        } else if (square + y / 16).is_multiple_of(2) {
            DARK
        } else {
            LIGHT
        };
        if let [lo, hi] = px {
            [*lo, *hi] = colour.to_le_bytes();
        }
    }
}

/// Send the picture's frame a band at a time: a region header, then the
/// band's rows. Each write is whole or not made, and the frame resumes
/// where the channel stopped taking it.
unsafe fn send_frame(s: &mut State, sys: &SyscallTable) {
    while s.painting {
        let y0 = s.band * BAND_ROWS;
        if !s.header_sent {
            let last = y0 + BAND_ROWS >= HEIGHT;
            let header = raster::Header {
                surface_w: WIDTH,
                surface_h: HEIGHT,
                format: raster::FORMAT_RGB565,
                flags: if last { raster::FLAG_LAST } else { 0 },
                x: 0,
                y: y0,
                w: WIDTH,
                h: BAND_ROWS,
            };
            let Ok(bytes) = header.encode() else {
                s.painting = false;
                return;
            };
            if dev_channel_writable(sys, s.surface) < bytes.len() as i32
                || (sys.channel_write)(s.surface, bytes.as_ptr(), bytes.len()) != bytes.len() as i32
            {
                return;
            }
            s.header_sent = true;
        }
        while s.row < BAND_ROWS {
            if dev_channel_writable(sys, s.surface) < ROW_BYTES as i32 {
                return;
            }
            let mut row = [0u8; ROW_BYTES];
            paint_row(s.frames, y0 + s.row, &mut row);
            if (sys.channel_write)(s.surface, row.as_ptr(), ROW_BYTES) != ROW_BYTES as i32 {
                return;
            }
            s.row += 1;
        }
        s.band += 1;
        s.row = 0;
        s.header_sent = false;
        if s.band * BAND_ROWS >= HEIGHT {
            s.painting = false;
            s.frames = s.frames.wrapping_add(1);
        }
    }
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes and `syscalls` the kernel's syscall table.
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    _in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if syscalls.is_null() || state.is_null() {
        return abi::errno::EINVAL;
    }
    if state_size < core::mem::size_of::<State>() {
        return abi::errno::ENOMEM;
    }
    core::ptr::write_bytes(state, 0, core::mem::size_of::<State>());
    let s = &mut *(state as *mut State);
    s.syscalls = syscalls as *const SyscallTable;
    let sys = &*s.syscalls;
    s.draw = out_chan;
    s.surface = dev_channel_port(sys, 1, 1);
    if s.draw < 0 {
        let m = b"[overlay_source] refusing to construct: `draw` must be wired";
        dev_log(sys, 1, m.as_ptr(), m.len());
        return abi::errno::EINVAL;
    }
    match compose(&mut s.stream) {
        Some(len) => s.len = len,
        None => return abi::errno::EINVAL,
    }
    // The first picture is sent at once.
    s.painting = true;
    0
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> StepReturn {
    let s = &mut *(state as *mut State);
    let sys = &*s.syscalls;
    while s.sent < s.len {
        let room = dev_channel_writable(sys, s.draw);
        if room <= 0 {
            break;
        }
        let n = (s.len - s.sent).min(room as usize);
        if (sys.channel_write)(s.draw, s.stream.as_ptr().add(s.sent), n) != n as i32 {
            break;
        }
        s.sent += n;
    }
    if s.surface >= 0 {
        s.steps = s.steps.wrapping_add(1);
        if !s.painting && s.steps >= FRAME_STEPS {
            s.steps = 0;
            s.painting = true;
            s.band = 0;
            s.row = 0;
            s.header_sent = false;
        }
        send_frame(s, sys);
    }
    StepReturn::Continue
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

fluxor_rt::wasm_entry!();
