//! draw_vector_source — a conformance vector replayed into a graph.
//!
//! The module reads one vector file (`abi::contracts::video_draw::vector`)
//! from `file` into its state. When the bytes held are a whole vector it
//! sends the file's raster inputs, each a whole-surface `VideoRaster`
//! record, on `surface0` and `surface1`, then the draw stream on `draw`,
//! all as the file holds them; then it rests.

#![cfg_attr(not(feature = "host-test"), no_std)]

use core::ffi::c_void;

use abi::contracts::video_draw::vector::Vector;
use abi::contracts::video_raster as vr;
use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

/// The largest vector file held.
const FILE_BYTES: usize = 8192;
/// Raster inputs a vector's SURFACE records may name.
const SURFACES: usize = 2;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Reading,
    Sending,
    Rest,
}

#[repr(C)]
pub struct State {
    syscalls: *const SyscallTable,
    file: i32,
    draw: i32,
    surfaces: [i32; SURFACES],
    phase: Phase,
    /// The part being sent: a raster input, then (`SURFACES`) the stream.
    part: u8,
    /// Bytes of that part sent.
    sent: usize,
    len: usize,
    bytes: [u8; FILE_BYTES],
}

fluxor_rt::module_facts! { state: State }

/// Where part `part` of the vector in `file` lies, and the channel it goes
/// to: `None` past the last part, a channel below zero for a part not
/// sent.
fn part_of(s: &State, part: u8) -> Option<(usize, usize, i32)> {
    let file = s.bytes.get(..s.len)?;
    let v = Vector::decode(file)?;
    let at = |inner: &[u8]| inner.as_ptr() as usize - file.as_ptr() as usize;
    if usize::from(part) < SURFACES {
        let Some((_, pixels)) = v.surface(part) else {
            return Some((0, 0, -1));
        };
        // The record is the header, then the pixels.
        let end = at(pixels) + pixels.len();
        let start = at(pixels).checked_sub(vr::HEADER)?;
        Some((start, end, s.surfaces[usize::from(part)]))
    } else if usize::from(part) == SURFACES {
        let start = at(v.stream);
        Some((start, start + v.stream.len(), s.draw))
    } else {
        None
    }
}

unsafe fn log(sys: &SyscallTable, level: u8, line: &[u8]) {
    dev_log(sys, level, line.as_ptr(), line.len());
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
    s.file = in_chan;
    s.draw = out_chan;
    s.surfaces = [dev_channel_port(sys, 1, 1), dev_channel_port(sys, 1, 2)];
    s.phase = Phase::Reading;
    if s.file < 0 || s.draw < 0 {
        log(
            sys,
            1,
            b"[draw_vector_source] refusing to construct: `file` and `draw` must be wired",
        );
        return abi::errno::EINVAL;
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
    if s.phase == Phase::Reading {
        let space = FILE_BYTES - s.len;
        let n = (sys.channel_read)(s.file, s.bytes.as_mut_ptr().add(s.len), space);
        if n > 0 {
            s.len += n as usize;
        }
        if part_of(s, 0).is_some() {
            s.phase = Phase::Sending;
        } else if s.len == FILE_BYTES {
            log(
                sys,
                1,
                b"[draw_vector_source] the file is not a vector of at most 8192 bytes: nothing is sent",
            );
            s.phase = Phase::Rest;
        } else {
            return StepReturn::Continue;
        }
    }
    while s.phase == Phase::Sending {
        let Some((start, end, chan)) = part_of(s, s.part) else {
            log(sys, 3, b"[draw_vector_source] sent");
            s.phase = Phase::Rest;
            break;
        };
        let at = start + s.sent;
        if chan < 0 || at >= end {
            s.part += 1;
            s.sent = 0;
            continue;
        }
        let room = dev_channel_writable(sys, chan);
        if room <= 0 {
            return StepReturn::Continue;
        }
        let n = (end - at).min(room as usize);
        if (sys.channel_write)(chan, s.bytes.as_ptr().add(at), n) != n as i32 {
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
