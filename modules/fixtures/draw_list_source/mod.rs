//! draw_list_source — one static `VideoDraw` frame, for a consumer under
//! test.
//!
//! At construction the module writes its whole stream into its state: a
//! STREAM, the definition of a small a8 strike it makes up (its SHA-256
//! computed here), and one frame of a background, a rounded rectangle and
//! 32 glyphs. Each step sends as much of it as `draw` takes; once it is all
//! sent the module rests.

#![cfg_attr(not(feature = "host-test"), no_std)]

use core::ffi::c_void;

use abi::contracts::glyph_pack::{FORMAT_A8, STRIKE_ENTRY};
use abi::contracts::video_draw::{self as vd, Record};
use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;
use fluxor_sdk::crypto::sha256::sha256;

/// Glyphs in the strike, each `GLYPH_W × GLYPH_H`.
const GLYPHS: usize = 8;
const GLYPH_W: usize = 6;
const GLYPH_H: usize = 9;
/// Glyphs in the run.
const RUN: usize = 32;
/// The strike: its header, ids, entries and bitmaps.
const STRIKE_BYTES: usize = 8 + GLYPHS * 2 + GLYPHS * STRIKE_ENTRY + GLYPHS * GLYPH_W * GLYPH_H;
/// The whole stream, with room to spare.
const STREAM_BYTES: usize = 1024;

const WIDTH_DEFAULT: u16 = 480;
const HEIGHT_DEFAULT: u16 = 480;

#[repr(C)]
pub struct State {
    syscalls: *const SyscallTable,
    draw: i32,
    width: u16,
    height: u16,
    stream: [u8; STREAM_BYTES],
    len: usize,
    sent: usize,
}

mod params_def {
    use super::*;
    fluxor_rt::define_params! {
        State;
        1, width, u16, WIDTH_DEFAULT => |s, d, len| { s.width = p_u16(d, len, 0, WIDTH_DEFAULT); };
        2, height, u16, HEIGHT_DEFAULT => |s, d, len| { s.height = p_u16(d, len, 0, HEIGHT_DEFAULT); };
    }
}

fluxor_rt::module_facts! { state: State }

/// The strike: glyph `g` is a box whose inside is a ramp of coverage that
/// differs per glyph.
fn strike() -> [u8; STRIKE_BYTES] {
    let mut out = [0u8; STRIKE_BYTES];
    out[0] = 12;
    out[4] = GLYPHS as u8;
    let entries = 8 + GLYPHS * 2;
    let bitmaps = entries + GLYPHS * STRIKE_ENTRY;
    for g in 0..GLYPHS {
        out[8 + g * 2] = g as u8 + 1;
        let e = entries + g * STRIKE_ENTRY;
        out[e] = GLYPH_W as u8;
        out[e + 2] = GLYPH_H as u8;
        // left 1, top GLYPH_H: the bitmap sits on the baseline.
        out[e + 4] = 1;
        out[e + 6] = GLYPH_H as u8;
        let offset = (g * GLYPH_W * GLYPH_H) as u32;
        out[e + 8..e + 12].copy_from_slice(&offset.to_le_bytes());
        for y in 0..GLYPH_H {
            for x in 0..GLYPH_W {
                let edge = x == 0 || y == 0 || x == GLYPH_W - 1 || y == GLYPH_H - 1;
                let v = if edge {
                    255
                } else {
                    (x * 31 + y * 17 + g * 43) as u8
                };
                out[bitmaps + offset as usize + y * GLYPH_W + x] = v;
            }
        }
    }
    out
}

/// Write the stream for a `width × height` surface into `out`: its length,
/// or `None` when a record does not fit.
fn compose(out: &mut [u8], width: u16, height: u16) -> Option<usize> {
    let strike = strike();
    let mut at = 0usize;
    let mut put = |record: &Record<'_>| -> Option<()> {
        at += vd::write(out.get_mut(at..)?, record)?;
        Some(())
    };
    put(&Record::Stream(vd::Stream {
        width,
        height,
        band_rows: 0,
        max_depth: 0,
        max_resources: 1,
        resource_bytes: STRIKE_BYTES as u32,
        generation: 1,
    }))?;
    put(&Record::ResDef(vd::ResDef {
        id: 0,
        kind: vd::RES_GLYPH_STRIKE,
        format: FORMAT_A8,
        total_len: STRIKE_BYTES as u32,
        digest: sha256(&strike),
        width: 0,
        height: 0,
    }))?;
    put(&Record::ResData {
        id: 0,
        offset: 0,
        bytes: &strike,
    })?;
    put(&Record::Frame {
        generation: 1,
        revision: 1,
        damage: vd::PRect {
            x: 0,
            y: 0,
            w: width,
            h: height,
        },
    })?;
    let (w, h) = (
        i32::from(width) * vd::FX_ONE,
        i32::from(height) * vd::FX_ONE,
    );
    put(&Record::FillRect {
        rect: vd::Rect { x: 0, y: 0, w, h },
        colour: [16, 24, 40, 255],
        current: false,
    })?;
    put(&Record::FillRRect {
        rect: vd::Rect {
            x: w / 8,
            y: h / 8,
            w: w - w / 4,
            h: h / 4,
        },
        radii: vd::Radii([[12 * vd::FX_ONE; 2]; 4]),
        colour: [230, 120, 30, 255],
        current: false,
    })?;
    let mut entries = [0u8; RUN * vd::GLYPH_ENTRY];
    for i in 0..RUN {
        let dx = if i == 0 { 0 } else { (GLYPH_W as i16 + 2) * 64 };
        let entry = vd::glyph_entry((i % GLYPHS) as u16, dx, 0);
        entries[i * vd::GLYPH_ENTRY..(i + 1) * vd::GLYPH_ENTRY].copy_from_slice(&entry);
    }
    let run = vd::Glyphs::new(0, [255, 255, 255, 255], w / 8, h / 2, &entries)?;
    put(&Record::Glyphs(run))?;
    put(&Record::Commit { revision: 1 })?;
    put(&Record::End)?;
    Some(at)
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    _in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
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
    if !params.is_null() && params_len > 0 {
        params_def::parse_tlv(s, params, params_len);
    } else {
        params_def::set_defaults(s);
    }
    s.draw = out_chan;
    if s.draw < 0 || s.width == 0 || s.height == 0 {
        let m = b"[draw_list_source] refusing to construct: `draw` must be wired, width and height non-zero";
        dev_log(&*s.syscalls, 1, m.as_ptr(), m.len());
        return abi::errno::EINVAL;
    }
    match compose(&mut s.stream, s.width, s.height) {
        Some(len) => s.len = len,
        None => return abi::errno::EINVAL,
    }
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
            return StepReturn::Continue;
        }
        let n = (s.len - s.sent).min(room as usize);
        if (sys.channel_write)(s.draw, s.stream.as_ptr().add(s.sent), n) != n as i32 {
            return StepReturn::Continue;
        }
        s.sent += n;
    }
    StepReturn::Done
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

fluxor_rt::wasm_entry!();
