//! draw_vector_source — a conformance vector replayed into a graph.
//!
//! The module reads one vector file (`abi::contracts::video_draw::vector`)
//! from `file` into a heap block of `file_bytes`, the one allocation its
//! params size (`heap_per_param`). When the bytes held are a whole vector it
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

/// The largest vector file held when the graph leaves `file_bytes` unset.
const FILE_BYTES_DEFAULT: u32 = 8192;
/// The heap besides the file: the block header, rounding to the
/// allocator's 16-byte granularity and the canary (`heap_per_param.base`).
const ARENA_BASE: u32 = 64;
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
    /// The heap block the file is read into, `cap` bytes.
    bytes: *mut u8,
    cap: usize,
}

fluxor_rt::module_facts! { state: State, arena: ARENA_BASE }

mod params_def {
    use super::*;
    fluxor_rt::define_params! {
        State;
        1, file_bytes, u32, FILE_BYTES_DEFAULT
            => |s, d, len| { s.cap = p_u32(d, len, 0, FILE_BYTES_DEFAULT) as usize; };
    }
}

/// The bytes of the file read so far.
fn held(s: &State) -> &[u8] {
    // SAFETY: `bytes` is the instance's heap block of `cap` bytes, taken
    // at construction and live as long as the instance; `len <= cap`.
    unsafe { core::slice::from_raw_parts(s.bytes, s.len) }
}

/// Where part `part` of the vector in `file` lies, and the channel it goes
/// to: `None` past the last part, a channel below zero for a part not
/// sent.
fn part_of(s: &State, part: u8) -> Option<(usize, usize, i32)> {
    let file = held(s);
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
    let sys = &*s.syscalls;
    if !params.is_null() && params_len > 0 {
        params_def::parse_tlv(s, params, params_len);
    } else {
        params_def::set_defaults(s);
    }
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
    if s.cap == 0 {
        log(
            sys,
            1,
            b"[draw_vector_source] refusing to construct: file_bytes must be non-zero",
        );
        return abi::errno::EINVAL;
    }
    let Ok(cap) = u32::try_from(s.cap) else {
        return abi::errno::EINVAL;
    };
    s.bytes = (sys.heap_alloc)(cap);
    if s.bytes.is_null() {
        log(
            sys,
            1,
            b"[draw_vector_source] refusing to construct: the heap cannot hold file_bytes \
              (heap.arena_bytes below what heap_per_param sizes)",
        );
        return abi::errno::ENOMEM;
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
        let space = s.cap - s.len;
        let n = (sys.channel_read)(s.file, s.bytes.add(s.len), space);
        if n > 0 {
            s.len += n as usize;
        }
        if part_of(s, 0).is_some() {
            s.phase = Phase::Sending;
        } else if s.len == s.cap {
            log(
                sys,
                1,
                b"[draw_vector_source] the file is not a vector of at most file_bytes bytes: nothing is sent",
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
        if (sys.channel_write)(chan, s.bytes.add(at), n) != n as i32 {
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
