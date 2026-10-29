//! frame_split — fixture router: one `[type][len u16 LE][payload]` stream
//! split by frame type onto up to four outputs.
//!
//! A rig that drives several ports of one graph from one pipe (the
//! runtime's stdin) cannot fan the pipe out to all of them: a port that
//! parses frames of its own kind misreads another's, and one whose records
//! carry their own framing misreads every one. This hands each output only
//! the frame types its list names — whole, or with `raw` the payload alone
//! — and drops, counting, a type no output names. A frame goes out once
//! every output it is for has taken it; until then it holds the stream, so
//! nothing is reordered and back pressure reaches the producer.

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    dead_code,
    reason = "the PIC build mounts the whole of modules/sdk/* via include!, so every \
              module's compile sees the entire ABI surface while using a subset. This \
              allow is the SDK's textual mounting showing through"
)]
#![allow(
    unused_imports,
    reason = "same cause: the mounted SDK brings names this module does not reach for"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

/// Outputs.
pub const OUTPUTS: usize = 4;
/// Frame header bytes.
const HDR: usize = 3;
/// The longest frame moved: the outputs' buffer (`buffer_size` 16384), so
/// every frame taken is one each output can hold whole. A longer one could
/// never be written and would hold the stream for good; it is skipped and
/// counted (`oversize`).
pub const FRAME_MAX: usize = 16384;
/// Frames moved per step.
const FRAMES_PER_STEP: usize = 32;
/// Steps between heartbeats, at most.
const LOG_PERIOD: u32 = 4096;

#[repr(C)]
pub struct SplitState {
    syscalls: *const SyscallTable,
    input: i32,
    outs: [i32; OUTPUTS],
    /// Per output, one bit per frame type it takes.
    types: [[u32; 8]; OUTPUTS],
    raw: u8,
    /// Outputs that have taken the frame at the head of the input.
    done: u8,
    /// Bytes of an oversize frame still to skip.
    skip: u32,
    step_count: u32,
    logged: [u32; 3],
    pub frames: u32,
    pub dropped: u32,
    pub oversize: u32,
    /// A type list did not parse: construction refuses.
    bad_list: bool,
    buf: [u8; FRAME_MAX],
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// `c3,c5` → the types' bits; `None` when an item is not one hex byte.
pub fn parse_types(text: &[u8]) -> Option<[u32; 8]> {
    let mut bits = [0u32; 8];
    for item in text.split(|&b| b == b',') {
        let item: &[u8] = {
            let mut t = item;
            while let [b' ', rest @ ..] = t {
                t = rest;
            }
            while let [rest @ .., b' '] = t {
                t = rest;
            }
            t
        };
        if item.is_empty() {
            continue;
        }
        let item = item
            .strip_prefix(b"0x")
            .or_else(|| item.strip_prefix(b"0X"))
            .unwrap_or(item);
        let v = match item {
            [a] => hex(*a)?,
            [a, b] => (hex(*a)? << 4) | hex(*b)?,
            _ => return None,
        };
        bits[v as usize / 32] |= 1 << (v % 32);
    }
    Some(bits)
}

unsafe fn set_list(s: &mut SplitState, k: usize, d: *const u8, len: usize) {
    let text = core::slice::from_raw_parts(d, len);
    match parse_types(text) {
        Some(bits) => s.types[k] = bits,
        None => s.bad_list = true,
    }
}

mod params_def {
    use super::*;
    define_params! {
        SplitState;
        1, out0, str, 0 => |s, d, len| { set_list(s, 0, d, len); };
        2, out1, str, 0 => |s, d, len| { set_list(s, 1, d, len); };
        3, out2, str, 0 => |s, d, len| { set_list(s, 2, d, len); };
        4, out3, str, 0 => |s, d, len| { set_list(s, 3, d, len); };
        5, raw, u8, 0 => |s, d, len| { s.raw = p_u8(d, len, 0, 0); };
    }
}

fn takes(s: &SplitState, k: usize, t: u8) -> bool {
    s.outs[k] >= 0 && s.types[k][t as usize / 32] & (1 << (t % 32)) != 0
}

/// Move what can move: each frame to every output it is for, whole.
unsafe fn service(s: &mut SplitState) {
    let sys = &*s.syscalls;
    for _ in 0..FRAMES_PER_STEP {
        if s.skip > 0 {
            let n = (sys.channel_read)(
                s.input,
                s.buf.as_mut_ptr(),
                (s.skip as usize).min(FRAME_MAX),
            );
            if n <= 0 {
                return;
            }
            s.skip -= n as u32;
            continue;
        }
        let n = (sys.channel_peek)(s.input, s.buf.as_mut_ptr(), HDR);
        if n < HDR as i32 {
            return;
        }
        let t = s.buf[0];
        let total = HDR + u16::from_le_bytes([s.buf[1], s.buf[2]]) as usize;
        if total > FRAME_MAX {
            s.oversize = s.oversize.wrapping_add(1);
            s.skip = total as u32;
            continue;
        }
        if (sys.channel_peek)(s.input, s.buf.as_mut_ptr(), total) < total as i32 {
            return;
        }
        let mut wanted = false;
        for k in 0..OUTPUTS {
            if !takes(s, k, t) {
                continue;
            }
            wanted = true;
            if s.done & (1 << k) != 0 {
                continue;
            }
            let from = if s.raw & (1 << k) != 0 { HDR } else { 0 };
            let bytes = &s.buf[from..total];
            if bytes.is_empty()
                || (sys.channel_write)(s.outs[k], bytes.as_ptr(), bytes.len()) == bytes.len() as i32
            {
                s.done |= 1 << k;
            }
        }
        let all = (0..OUTPUTS).all(|k| !takes(s, k, t) || s.done & (1 << k) != 0);
        if !all {
            // An output has no room: the frame, and the stream behind it,
            // wait for it.
            return;
        }
        (sys.channel_discard)(s.input, total);
        s.done = 0;
        if wanted {
            s.frames = s.frames.wrapping_add(1);
        } else {
            s.dropped = s.dropped.wrapping_add(1);
        }
    }
}

unsafe fn heartbeat(s: &mut SplitState) {
    let now = [s.frames, s.dropped, s.oversize];
    if now == s.logged {
        return;
    }
    s.logged = now;
    let mut line = [0u8; 96];
    let mut at = 0;
    let mut put = |b: &[u8], at: &mut usize| {
        line[*at..*at + b.len()].copy_from_slice(b);
        *at += b.len();
    };
    let mut num = [0u8; 10];
    for (label, v) in [
        (&b"[frame_split] frames="[..], now[0]),
        (&b" dropped="[..], now[1]),
        (&b" oversize="[..], now[2]),
    ] {
        put(label, &mut at);
        let n = fmt_u32_raw(num.as_mut_ptr(), v);
        put(&num[..n], &mut at);
    }
    dev_log(&*s.syscalls, 3, line.as_ptr(), at);
}

declare_module_state_bytes!(SplitState);

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<SplitState>() as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

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
        return -22;
    }
    if state_size < core::mem::size_of::<SplitState>() {
        return -6;
    }
    core::ptr::write_bytes(state, 0, core::mem::size_of::<SplitState>());
    let s = &mut *(state as *mut SplitState);
    s.syscalls = syscalls as *const SyscallTable;
    let sys = &*s.syscalls;
    s.input = in_chan;
    s.outs[0] = out_chan;
    for k in 1..OUTPUTS {
        s.outs[k] = dev_channel_port(sys, 1, k as u8);
    }
    if !params.is_null() && params_len > 0 {
        params_def::parse_tlv(s, params, params_len);
    }
    if s.bad_list {
        let m =
            b"[frame_split] refusing to construct: a type list is not comma-separated hex bytes";
        dev_log(sys, 1, m.as_ptr(), m.len());
        return -22;
    }
    0
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut SplitState);
    s.step_count = s.step_count.wrapping_add(1);
    service(s);
    if s.step_count.is_multiple_of(LOG_PERIOD) {
        heartbeat(s);
    }
    0
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
pub extern "C" fn module_arena_size() -> u32 {
    0
}
