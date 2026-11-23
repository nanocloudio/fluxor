//! draw_raster — a draw list in, pixels out.
//!
//! The reference rasteriser (`fluxor_sdk::video::raster`) behind two ports:
//! `draw` takes a `VideoDraw` stream, `pixels` sends the frames it draws as
//! `VideoRaster` regions. The module retains the last committed frame's
//! records and draws them a band at a time into one band buffer, so its
//! memory is a few kilobytes of records and one band whatever the surface.
//!
//! A step reads what the raster inputs hold, then either moves the frame
//! being sent forward by at most one band, or takes records from `draw`
//! until a frame commits. Nothing waits: a full output or an empty input
//! ends the step.

#![cfg_attr(not(feature = "host-test"), no_std)]

use core::ffi::c_void;

use abi::contracts::video_draw as vd;
use abi::contracts::video_raster::{self as vr, FLAG_DAMAGE, FLAG_LAST};
use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::asset::{self, Asset};
use fluxor_rt::*;
use fluxor_sdk::video::raster::{
    self, Band, Entry, Event, Held, Index, Ingest, Input, Painter, Shape, Slot, Store, Surfaces,
    Texels, BAND_BPP,
};

/// The deepest SAVE nesting and the most live rounded clips
/// (`max_depth` on the `draw` port).
const MAX_DEPTH: usize = 8;
/// Resource ids (`max_resources` on the `draw` port).
const MAX_RESOURCES: usize = 16;
/// Raster inputs (`surfaces` on the `draw` port).
const INPUTS: usize = 2;
/// Byte strings the instance holds in place for RES_REF records: the
/// `pack0` to `pack3` params.
const PACKS: usize = 4;
/// Bytes of a `pack` param kept: a program reference.
const PACK_PARAM: usize = 16;
/// Records of a retained frame whose rows are indexed; a frame with more
/// is drawn by walking the rest record by record.
const INDEX_RECORDS: usize = 256;
/// Bytes of the held byte strings hashed in one step.
const HASH_BYTES_PER_STEP: usize = 4096;
/// The heap besides what the params size: the block header and the padding
/// between the parts (`heap_per_param.base`).
const ARENA_BASE: u32 = 192;
/// Bytes of a raster input read in one step.
const INPUT_BYTES_PER_STEP: usize = 16 * 1024;

const WIDTH_DEFAULT: u16 = 480;
const HEIGHT_DEFAULT: u16 = 480;
const BAND_BYTES_DEFAULT: u32 = 23_040;
const FRAME_BYTES_DEFAULT: u32 = 8192;
const RESOURCE_BYTES_DEFAULT: u32 = 16_384;
const RECORD_BYTES_DEFAULT: u32 = 2048;

/// Nothing of the band has been sent.
const SEND_NONE: u8 = 0;
/// The band's header is next.
const SEND_HEADER: u8 = 1;
/// Rows of the band are being sent.
const SEND_ROWS: u8 = 2;

/// A frame on its way out: a region of the surface, drawn and sent a band
/// at a time.
struct Job {
    active: bool,
    /// Send black: no frame is retained.
    black: bool,
    surface: (u16, u16),
    region: vd::PRect,
    /// The band being sent, or the next to draw.
    band: vd::PRect,
    send: u8,
    /// Rows of the band sent.
    row: u16,
    /// Bytes of the row in the row buffer, and how many are sent.
    row_len: usize,
    row_sent: usize,
}

#[repr(C)]
pub struct State {
    syscalls: *const SyscallTable,
    draw: i32,
    pixels: i32,
    width: u16,
    height: u16,
    format: u8,
    band_bytes: u32,
    frame_bytes: u32,
    resource_bytes: u32,
    record_bytes: u32,
    surface_bytes: u32,
    resources: [vd::Resource; MAX_RESOURCES],
    saves: [vd::Saved; MAX_DEPTH],
    slots: [Slot; MAX_RESOURCES],
    pack_params: [[u8; PACK_PARAM]; PACKS],
    pack_lens: [u8; PACKS],
    held: [Held<'static>; PACKS],
    index: [Entry; INDEX_RECORDS],
    stack: [raster::Saved; MAX_DEPTH],
    clips: [Shape; MAX_DEPTH],
    ingest: Option<Ingest<'static>>,
    painter: Option<Painter<'static>>,
    band: *mut u8,
    row: *mut u8,
    inputs: [Input; INPUTS],
    /// Inputs that committed a frame the retained frame has not been drawn
    /// with: bit `i` for input `i`.
    stale: u32,
    /// The surface the consumer of `pixels` was last sent.
    shown: Option<(u16, u16)>,
    job: Job,
}

mod params_def {
    use super::*;
    fluxor_rt::define_params! {
        State;
        1, width, u16, WIDTH_DEFAULT => |s, d, len| { s.width = p_u16(d, len, 0, WIDTH_DEFAULT); };
        2, height, u16, HEIGHT_DEFAULT => |s, d, len| { s.height = p_u16(d, len, 0, HEIGHT_DEFAULT); };
        3, format, u8, 0, enum { rgb565 = 0, rgba8 = 1 }
            => |s, d, len| { s.format = p_u8(d, len, 0, 0); };
        4, band_bytes, u32, BAND_BYTES_DEFAULT
            => |s, d, len| { s.band_bytes = p_u32(d, len, 0, BAND_BYTES_DEFAULT); };
        5, frame_bytes, u32, FRAME_BYTES_DEFAULT
            => |s, d, len| { s.frame_bytes = p_u32(d, len, 0, FRAME_BYTES_DEFAULT); };
        6, resource_bytes, u32, RESOURCE_BYTES_DEFAULT
            => |s, d, len| { s.resource_bytes = p_u32(d, len, 0, RESOURCE_BYTES_DEFAULT); };
        7, record_bytes, u32, RECORD_BYTES_DEFAULT
            => |s, d, len| { s.record_bytes = p_u32(d, len, 0, RECORD_BYTES_DEFAULT); };
        8, surface_bytes, u32, 0 => |s, d, len| { s.surface_bytes = p_u32(d, len, 0, 0); };
        9, pack0, str, 0 => |s, d, len| { keep_pack(s, 0, d, len); };
        10, pack1, str, 0 => |s, d, len| { keep_pack(s, 1, d, len); };
        11, pack2, str, 0 => |s, d, len| { keep_pack(s, 2, d, len); };
        12, pack3, str, 0 => |s, d, len| { keep_pack(s, 3, d, len); };
    }
}

/// Keep the value of `pack<i>`. One too long to be a program reference is
/// kept as its first bytes, which `asset::open` then answers as a path:
/// `module_new` refuses it.
unsafe fn keep_pack(s: &mut State, i: usize, d: *const u8, len: usize) {
    let n = len.min(PACK_PARAM);
    let mut k = 0;
    while k < n {
        s.pack_params[i][k] = *d.add(k);
        k += 1;
    }
    s.pack_lens[i] = n as u8;
}

fluxor_rt::module_facts! { state: State, arena: ARENA_BASE }

/// The raster inputs, as SURFACE records read them.
struct Rasters<'a>(&'a [Input; INPUTS]);

impl Surfaces for Rasters<'_> {
    fn surface(&self, input: u8) -> Option<Texels<'_>> {
        self.0.get(usize::from(input))?.texels()
    }
}

unsafe fn log(sys: &SyscallTable, msg: &[u8]) {
    dev_log(sys, 1, msg.as_ptr(), msg.len());
}

/// One diagnostic for a refused stream: the fault and where it was.
unsafe fn log_fault(sys: &SyscallTable, fault: vd::Fault, offset: u64) {
    let mut line = [0u8; 96];
    let mut n = 0;
    let mut put = |bytes: &[u8]| {
        for &b in bytes {
            if n < line.len() {
                line[n] = b;
                n += 1;
            }
        }
    };
    put(b"[draw_raster] stream refused: ");
    put(raster::fault_text(fault));
    put(b" at byte ");
    let mut digits = [0u8; 10];
    let len = fmt_u32_raw(digits.as_mut_ptr(), offset.min(u64::from(u32::MAX)) as u32);
    put(&digits[..len.min(digits.len())]);
    dev_log(sys, 1, line.as_ptr(), n);
}

/// `n` rounded up to the alignment every part of the heap block starts on.
const fn aligned(n: usize) -> usize {
    (n + 7) & !7
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
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
    // The tables the rasteriser borrows are reached through `me`: they live
    // as long as the instance, not as long as this call's `s`.
    let me = state as *mut State;
    let s = &mut *me;
    s.syscalls = syscalls as *const SyscallTable;
    let sys = &*s.syscalls;
    if !params.is_null() && params_len > 0 {
        params_def::parse_tlv(s, params, params_len);
    } else {
        params_def::set_defaults(s);
    }
    s.draw = in_chan;
    s.pixels = out_chan;
    // A band is at least one row of the widest stream.
    let widest = (s.band_bytes / BAND_BPP as u32).min(u32::from(s.width)) as u16;
    let refuse: Option<&[u8]> = if s.draw < 0 || s.pixels < 0 {
        Some(b"[draw_raster] refusing to construct: `draw` and `pixels` must be wired")
    } else if s.format >= vr::FORMAT_COUNT {
        Some(b"[draw_raster] refusing to construct: format is rgb565 or rgba8")
    } else if widest == 0 || s.height == 0 {
        Some(b"[draw_raster] refusing to construct: width, height and band_bytes must be non-zero")
    } else if s.frame_bytes == 0 || (s.record_bytes as usize) < vd::HEADER + vd::BORDER_LEN {
        Some(b"[draw_raster] refusing to construct: frame_bytes must be non-zero and record_bytes at least 84")
    } else {
        None
    };
    if let Some(m) = refuse {
        log(sys, m);
        return abi::errno::EINVAL;
    }
    let parts = [
        s.record_bytes as usize,
        s.frame_bytes as usize,
        s.frame_bytes as usize,
        s.resource_bytes as usize,
        s.band_bytes as usize,
        usize::from(s.width) * 4,
        s.surface_bytes as usize,
        s.surface_bytes as usize,
        s.surface_bytes as usize,
        s.surface_bytes as usize,
    ];
    let mut total = 0usize;
    for part in parts {
        total = total.saturating_add(aligned(part));
    }
    let Ok(total32) = u32::try_from(total) else {
        return abi::errno::ENOMEM;
    };
    let block = (sys.heap_alloc)(total32);
    if block.is_null() {
        log(
            sys,
            b"[draw_raster] refusing to construct: the heap cannot hold the buffers the params size \
              (heap.arena_bytes below what heap_per_param sizes)",
        );
        return abi::errno::ENOMEM;
    }
    core::ptr::write_bytes(block, 0, total);
    let mut at = 0usize;
    let mut carve = |len: usize| {
        let p = block.add(at);
        at += aligned(len);
        p
    };
    let carry = carve(parts[0]);
    let frame_a = carve(parts[1]);
    let frame_b = carve(parts[2]);
    let arena = carve(parts[3]);
    s.band = carve(parts[4]);
    s.row = carve(parts[5]);
    let cap = s.surface_bytes as usize;
    for i in 0..INPUTS {
        let buffers = if cap == 0 {
            [core::ptr::null_mut(); 2]
        } else {
            [carve(cap), carve(cap)]
        };
        let chan = dev_channel_port(sys, 0, 1 + i as u8);
        core::ptr::write(&raw mut s.inputs[i], Input::new(chan, buffers, cap));
    }
    // The byte strings RES_REF records resolve against: each `pack` param
    // names a program of this instance, read where the node image holds it.
    let mut held = 0usize;
    for i in 0..PACKS {
        let len = usize::from(s.pack_lens[i]);
        if len == 0 {
            continue;
        }
        let param = s.pack_params[i];
        let Ok(Asset::InPlace(bytes)) = asset::open(sys, &param[..len]) else {
            log(
                sys,
                b"[draw_raster] refusing to construct: a `pack` param must name an asset this \
                  target keeps readable in place (a program of the instance)",
            );
            return abi::errno::EINVAL;
        };
        core::ptr::write(
            (&raw mut s.held).cast::<Held<'static>>().add(held),
            Held::new(bytes),
        );
        held += 1;
    }
    let limits = vd::Limits {
        ops: vd::OPS_ALL,
        pixmap_formats: (1 << vd::PIXMAP_RGBA8) | (1 << vd::PIXMAP_RGB565),
        glyph_formats: (1 << vd::GLYPH_A1) | (1 << vd::GLYPH_A8),
        max_width: widest,
        max_height: s.height,
        max_depth: MAX_DEPTH as u8,
        max_resources: MAX_RESOURCES as u16,
        resource_bytes: s.resource_bytes,
        frame_bytes: s.frame_bytes,
        band_rows: 0,
        damage_full: true,
        surfaces: INPUTS as u8,
    };
    // SAFETY: each slice is a distinct part of this instance's state or
    // heap block, both of which live, unmoved, as long as the instance; the
    // state was zeroed above, and each table is filled before it is read.
    let sequence = vd::Sequence::new(limits, &mut (*me).resources, &mut (*me).saves);
    let store = Store::new(
        &mut (*me).slots,
        core::slice::from_raw_parts_mut(arena, parts[3]),
        core::slice::from_raw_parts_mut((&raw mut s.held).cast::<Held<'static>>(), held),
    );
    core::ptr::write(
        &raw mut s.ingest,
        Some(Ingest::new(
            sequence,
            store,
            core::slice::from_raw_parts_mut(carry, parts[0]),
            [
                core::slice::from_raw_parts_mut(frame_a, parts[1]),
                core::slice::from_raw_parts_mut(frame_b, parts[2]),
            ],
            Index::new(&mut (*me).index),
        )),
    );
    core::ptr::write(
        &raw mut s.painter,
        Some(Painter::new(&mut (*me).stack, &mut (*me).clips)),
    );
    0
}

/// Begin sending `region` of a `surface`-sized picture.
fn start(job: &mut Job, surface: (u16, u16), region: vd::PRect, black: bool) {
    *job = Job {
        active: true,
        black,
        surface,
        region,
        band: vd::PRect {
            x: region.x,
            y: region.y,
            w: region.w,
            h: 0,
        },
        send: SEND_NONE,
        row: 0,
        row_len: 0,
        row_sent: 0,
    };
}

/// Move the frame being sent forward: finish sending the band in hand,
/// then draw the next. At most one band is drawn. Whether anything moved.
unsafe fn run_job(s: &mut State) -> bool {
    let sys = &*s.syscalls;
    let mut moved = false;
    let mut drawn = false;
    loop {
        let job = &mut s.job;
        let region_end = u32::from(job.region.y) + u32::from(job.region.h);
        match job.send {
            SEND_NONE => {
                let y = u32::from(job.band.y) + u32::from(job.band.h);
                if y >= region_end {
                    job.active = false;
                    s.shown = Some(job.surface);
                    return true;
                }
                if drawn {
                    return moved;
                }
                let fit = (s.band_bytes as usize)
                    .checked_div(usize::from(job.region.w) * BAND_BPP)
                    .unwrap_or(0);
                let rows = (fit as u32).min(region_end - y);
                if rows == 0 {
                    // No band of this width fits: nothing can be sent.
                    job.active = false;
                    return true;
                }
                job.band = vd::PRect {
                    x: job.region.x,
                    y: y as u16,
                    w: job.region.w,
                    h: rows as u16,
                };
                let pixels = core::slice::from_raw_parts_mut(s.band, s.band_bytes as usize);
                let Some(mut band) = Band::new(pixels, job.band) else {
                    job.active = false;
                    return true;
                };
                let retained = match (s.ingest.as_ref(), job.black) {
                    (Some(ingest), false) => ingest.frame().map(|f| (f, ingest.store())),
                    _ => None,
                };
                // A band the frame's first operation paints whole needs no
                // black under it.
                let painted = retained.is_some_and(|((_, index), _)| {
                    index
                        .backdrop()
                        .is_some_and(|d| raster::intersect(d, job.band) == Some(job.band))
                });
                if !painted {
                    band.clear();
                }
                if let (Some(((frame, index), store)), Some(painter)) =
                    (retained, s.painter.as_mut())
                {
                    raster::replay(frame, index, painter, &mut band, store, &Rasters(&s.inputs));
                }
                job.send = SEND_HEADER;
                job.row = 0;
                drawn = true;
                moved = true;
            }
            SEND_HEADER => {
                let last = u32::from(job.band.y) + u32::from(job.band.h) >= region_end;
                let header = vr::Header {
                    surface_w: job.surface.0,
                    surface_h: job.surface.1,
                    format: s.format,
                    flags: FLAG_DAMAGE | if last { FLAG_LAST } else { 0 },
                    x: job.band.x,
                    y: job.band.y,
                    w: job.band.w,
                    h: job.band.h,
                };
                let Ok(bytes) = header.encode() else {
                    job.active = false;
                    return true;
                };
                if (sys.channel_write)(s.pixels, bytes.as_ptr(), bytes.len()) != bytes.len() as i32
                {
                    return moved;
                }
                job.send = SEND_ROWS;
                job.row_len = 0;
                moved = true;
            }
            _ => {
                if job.row_len == 0 {
                    if job.row >= job.band.h {
                        job.send = SEND_NONE;
                        continue;
                    }
                    let pixels = core::slice::from_raw_parts_mut(s.band, s.band_bytes as usize);
                    let out = core::slice::from_raw_parts_mut(s.row, usize::from(s.width) * 4);
                    let py = i32::from(job.band.y) + i32::from(job.row);
                    let len = Band::new(pixels, job.band).and_then(|band| {
                        if s.format == vr::FORMAT_RGBA8 {
                            band.row_rgba8(py, out)
                        } else {
                            band.row_rgb565(py, out)
                        }
                    });
                    let Some(len) = len else {
                        job.active = false;
                        return true;
                    };
                    job.row_len = len;
                    job.row_sent = 0;
                }
                let room = dev_channel_writable(sys, s.pixels);
                if room <= 0 {
                    return moved;
                }
                let n = (job.row_len - job.row_sent).min(room as usize);
                if (sys.channel_write)(s.pixels, s.row.add(job.row_sent), n) != n as i32 {
                    return moved;
                }
                job.row_sent += n;
                moved = true;
                if job.row_sent == job.row_len {
                    job.row_len = 0;
                    job.row += 1;
                }
            }
        }
    }
}

/// With nothing being sent: show the raster frames that are ready, redraw
/// what they changed, or take records from `draw` until a frame commits.
/// Whether a frame was started.
unsafe fn idle(s: &mut State) -> bool {
    let sys = &*s.syscalls;
    for (i, input) in s.inputs.iter_mut().enumerate() {
        if input.ready {
            input.commit();
            s.stale |= 1 << i;
        }
    }
    let (Some(ingest), Some(painter)) = (s.ingest.as_mut(), s.painter.as_mut()) else {
        return false;
    };
    // No stream is taken until every held byte string has its digest.
    if !ingest.prepare(HASH_BYTES_PER_STEP) {
        return false;
    }
    if s.stale != 0 {
        let stale = core::mem::take(&mut s.stale);
        let (width, height) = ingest.extent();
        if let Some((frame, _)) = ingest.frame() {
            if let Some(region) = raster::surface_reach(frame, painter, stale, width, height) {
                start(&mut s.job, (width, height), region, false);
                return true;
            }
        }
    }
    let space = ingest.space();
    if !space.is_empty() {
        let n = (sys.channel_read)(s.draw, space.as_mut_ptr(), space.len());
        if n > 0 {
            ingest.filled(n as usize);
        }
    }
    loop {
        match ingest.advance() {
            Event::NeedMore => return false,
            Event::Ended => {}
            Event::Faulted { fault, offset } => log_fault(sys, fault, offset),
            Event::Opened => {
                // The retained frame is gone: what was shown goes black.
                if let Some((w, h)) = s.shown.take() {
                    let whole = vd::PRect { x: 0, y: 0, w, h };
                    start(&mut s.job, (w, h), whole, true);
                    return true;
                }
            }
            Event::Committed => {
                ingest.present(painter);
                s.stale = 0;
                let (w, h) = ingest.extent();
                let whole = vd::PRect { x: 0, y: 0, w, h };
                start(&mut s.job, (w, h), whole, false);
                return true;
            }
        }
    }
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> StepReturn {
    let s = &mut *(state as *mut State);
    let sys = &*s.syscalls;
    for input in s.inputs.iter_mut() {
        input.pump(sys, INPUT_BYTES_PER_STEP);
    }
    let moved = if s.job.active { run_job(s) } else { idle(s) };
    if moved && s.job.active {
        StepReturn::Burst
    } else {
        StepReturn::Continue
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

fluxor_rt::wasm_entry!();
