//! Workload-churn driver.
//!
//! Admits and reaps a two-module workload `cycles` times through the metal
//! `workload` backend (0x1A), as a node agent does, then stages two faulting
//! workloads. See the manifest for the log lines; the kernel's `[live]` line
//! reports the arenas beside them.

#![no_std]
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
#![allow(
    unreachable_patterns,
    reason = "defensive `_ => Error` arms in enum state-machine matches. The match is \
              exhaustive, which is why the lint fires; the arm exists so that adding a \
              variant cannot silently bypass the error path. #[expect] is not the \
              alternative — it fails the build in the configurations where the lint \
              does not fire"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::contracts::workload as wl;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

/// FLXA magic ("FLXA") and wire version.
const FLXA_MAGIC: u32 = 0x464C_5841;
const FLXA_VERSION: u16 = 1;
const EP_NEW: u8 = 0;
const EP_CALLER: u8 = 4;

/// CREATE header + an FLXA blob of at most two modules and two edges.
const ARG_BYTES: usize = 256;
/// The largest module pack `pack_hex` carries (pack mode).
const PACK_MAX: usize = 16 * 1024;

const PH_WAIT_START: u8 = 0;
const PH_IDLE: u8 = 1;
const PH_RUNNING: u8 = 2;
const PH_FAULT: u8 = 3;
const PH_DONE: u8 = 4;

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    cycles: u32,
    chan_bytes: u32,
    start_at_ms: u32,
    read_timeout_ms: u32,
    fault: u8,
    phase: u8,
    /// Fault-phase index: 0 = mode error, 1 = mode infinite_loop.
    fault_idx: u8,
    consecutive_cf: u8,
    exhausted: u8,
    /// WAIT state reported for each faulting workload (0xFF = not reached).
    fault_state: [u8; 2],
    _pad: u8,
    handle: i32,
    lane: i32,
    n: u32,
    ok: u32,
    tmo: u32,
    cf: u32,
    cmax_us: u32,
    dmax_us: u32,
    gapmax_ms: u32,
    since_ms: u64,
    last_step_ms: u64,
    last_hb_ms: u64,
    arg: [u8; ARG_BYTES],
    /// Pack mode: the module pack (an FXMT table) every churn workload
    /// brings with it, and the pin its module is admitted by. Empty = the
    /// workload's modules come from the node's own image.
    pack_len: u32,
    pin_set: u8,
    /// A hex digit of `pack_hex` whose pair continues in the next chunk:
    /// its value + 1 (0 = none). The encoder's chunks are 255 bytes, an odd
    /// length, so every chunk boundary splits a pair.
    half: u8,
    _pad2: [u8; 2],
    pin: [u8; 32],
    pack: [u8; PACK_MAX],
}

mod params_def {
    use super::State;
    use super::SCHEMA_MAX;
    use super::{p_u32, p_u8};

    define_params! {
        State;

        1, cycles, u32, 500
            => |s, d, len| { s.cycles = p_u32(d, len, 0, 500); };

        2, chan_bytes, u32, 16384
            => |s, d, len| { s.chan_bytes = p_u32(d, len, 0, 16384); };

        3, start_at_ms, u32, 20000
            => |s, d, len| { s.start_at_ms = p_u32(d, len, 0, 20000); };

        4, read_timeout_ms, u32, 2000
            => |s, d, len| { s.read_timeout_ms = p_u32(d, len, 0, 2000); };

        5, fault, u8, 1
            => |s, d, len| { s.fault = p_u8(d, len, 0, 1); };

        // Pack mode: the module pack as hex, appended chunk by chunk (the TLV
        // encoder splits a long string into repeated entries).
        6, pack_hex, str_chunked, 0
            => |s, d, len| {
                let mut i = 0usize;
                while i < len {
                    let Some(v) = super::hexv(*d.add(i)) else { return; };
                    i += 1;
                    if s.half == 0 {
                        s.half = v + 1;
                        continue;
                    }
                    let at = s.pack_len as usize;
                    if at >= super::PACK_MAX { return; }
                    *s.pack.as_mut_ptr().add(at) = ((s.half - 1) << 4) | v;
                    s.pack_len = (at + 1) as u32;
                    s.half = 0;
                }
            };

        // Pack mode: the SHA-256 pin of the pack's module, as 64 hex digits.
        7, pin_hex, str, 0
            => |s, d, len| {
                if len != 64 { return; }
                let mut i = 0usize;
                while i < 32 {
                    let (Some(hi), Some(lo)) = (super::hexv(*d.add(2 * i)), super::hexv(*d.add(2 * i + 1))) else { return; };
                    *s.pin.as_mut_ptr().add(i) = (hi << 4) | lo;
                    i += 1;
                }
                s.pin_set = 1;
            };
    }
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
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
    if state.is_null() || syscalls.is_null() {
        return -1;
    }
    if state_size < core::mem::size_of::<State>() {
        return -2;
    }
    unsafe {
        core::ptr::write_bytes(state, 0, core::mem::size_of::<State>());
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        s.handle = -1;
        s.lane = -1;
        s.fault_state = [0xFF; 2];
        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
    }
    0
}

/// A cursor over the CREATE buffer that reports overflow instead of panicking.
struct Out<'b> {
    buf: &'b mut [u8],
    n: usize,
    ok: bool,
}

impl Out<'_> {
    fn u8(&mut self, v: u8) {
        match self.buf.get_mut(self.n) {
            Some(b) => {
                *b = v;
                self.n += 1;
            }
            None => self.ok = false,
        }
    }
    fn be16(&mut self, v: u16) {
        for b in v.to_be_bytes() {
            self.u8(b);
        }
    }
    fn be32(&mut self, v: u32) {
        for b in v.to_be_bytes() {
            self.u8(b);
        }
    }
}

/// FNV-1a over a module type name: the hash a module is resolved by.
fn type_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &c in name {
        h ^= c as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// One FLXA module whose params are a single u8 entry (tag 1).
fn module_u8(o: &mut Out<'_>, name: &[u8], tag1: u8) {
    o.be32(type_hash(name));
    o.u8(0); // domain
             // SDK TLV: [FE 01][payload_len LE] [tag][len][value] [FF 00]
    o.be16(9);
    for b in [0xFE, 0x01, 5, 0, 1, 1, tag1, 0xFF, 0x00] {
        o.u8(b);
    }
}

fn edge(o: &mut Out<'_>, from: (u8, u16, u8), to: (u8, u16, u8), bytes: u32) {
    o.u8(from.0);
    o.be16(from.1);
    o.u8(from.2);
    o.u8(to.0);
    o.be16(to.1);
    o.u8(to.2);
    o.be32(bytes);
}

/// Lay the CREATE header and FLXA blob for workload `id` into `s.arg`; returns the
/// total length, or 0 on overflow. `fault_mode` None = the churn workload.
fn build(s: &mut State, id: u32, fault_mode: Option<u8>) -> usize {
    let chan = s.chan_bytes;
    for b in s.arg.iter_mut() {
        *b = 0;
    }
    // Identity: "churn" + the workload id, unique per admission.
    let ident = b"churn-uid-";
    for (i, &c) in ident.iter().enumerate() {
        s.arg[i] = c;
    }
    let idb = id.to_le_bytes();
    for (i, &c) in idb.iter().enumerate() {
        s.arg[12 + i] = c;
    }
    // Pack mode: the churn workload brings its modules — the pack reference
    // and its pin come first in the source section, the FLXA after them.
    let pack = fault_mode.is_none() && s.pack_len > 0 && s.pin_set != 0;
    let pack_ptr = s.pack.as_ptr() as u64;
    let pack_len = s.pack_len;
    let pin = s.pin;
    if pack {
        s.arg[17] = wl::SOURCE_FMOD_PACK;
    }
    let mut o = Out {
        buf: &mut s.arg[wl::CREATE_HEADER_SIZE..],
        n: 0,
        ok: true,
    };
    if pack {
        for b in pack_ptr.to_le_bytes() {
            o.u8(b);
        }
        for b in pack_len.to_le_bytes() {
            o.u8(b);
        }
        o.u8(1); // pin_count
        o.u8(0);
        o.u8(0);
        o.u8(0);
        for b in pin {
            o.u8(b);
        }
    }
    o.be32(FLXA_MAGIC);
    o.be16(FLXA_VERSION);
    o.be16(0);
    for _ in 0..16 {
        o.u8(0); // owner_uid: the kernel copies the header identity in
    }
    o.be32(0); // state_cap
    o.be32(0); // buffer_cap
    match fault_mode {
        None => {
            o.u8(2);
            o.u8(2);
            module_u8(&mut o, b"churn_probe", 0); // source
            module_u8(&mut o, b"churn_probe", 1); // relay
            edge(&mut o, (EP_NEW, 0, 0), (EP_NEW, 1, 0), chan);
            edge(&mut o, (EP_NEW, 1, 0), (EP_CALLER, 0, 0), chan);
        }
        Some(mode) => {
            o.u8(1);
            o.u8(0);
            module_u8(&mut o, b"test_fault", mode);
        }
    }
    if !o.ok {
        return 0;
    }
    let src_len = o.n;
    let l = (src_len as u16).to_le_bytes();
    s.arg[40] = l[0];
    s.arg[41] = l[1];
    wl::CREATE_HEADER_SIZE + src_len
}

/// A hex digit's value.
fn hexv(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Append `v` as decimal at `msg[len..]`; returns the new length.
fn put_dec(msg: &mut [u8], mut len: usize, v: i64) -> usize {
    let mut x = if v < 0 {
        if let Some(b) = msg.get_mut(len) {
            *b = b'-';
            len += 1;
        }
        v.unsigned_abs()
    } else {
        v as u64
    };
    let mut digits = [0u8; 20];
    let mut d = 0usize;
    loop {
        digits[d] = b'0' + (x % 10) as u8;
        d += 1;
        x /= 10;
        if x == 0 || d >= digits.len() {
            break;
        }
    }
    while d > 0 {
        d -= 1;
        match msg.get_mut(len) {
            Some(b) => {
                *b = digits[d];
                len += 1;
            }
            None => break,
        }
    }
    len
}

fn put(msg: &mut [u8], mut len: usize, s: &[u8]) -> usize {
    for &c in s {
        match msg.get_mut(len) {
            Some(b) => {
                *b = c;
                len += 1;
            }
            None => break,
        }
    }
    len
}

/// Log `[churn] <head>` followed by ` key=value` pairs.
unsafe fn report(sys: &SyscallTable, head: &[u8], kv: &[(&[u8], i64)]) {
    let mut msg = [0u8; 160];
    let mut len = put(&mut msg, 0, b"[churn] ");
    len = put(&mut msg, len, head);
    for (k, v) in kv {
        len = put(&mut msg, len, b" ");
        len = put(&mut msg, len, k);
        len = put(&mut msg, len, b"=");
        len = put_dec(&mut msg, len, *v);
    }
    dev_log(sys, 3, msg.as_ptr(), len);
}

unsafe fn progress(sys: &SyscallTable, s: &State) {
    report(
        sys,
        b"progress",
        &[
            (b"n", s.n as i64),
            (b"ok", s.ok as i64),
            (b"tmo", s.tmo as i64),
            (b"cf", s.cf as i64),
            (b"cmax_us", s.cmax_us as i64),
            (b"dmax_us", s.dmax_us as i64),
            (b"gapmax_ms", s.gapmax_ms as i64),
        ],
    );
}

/// CREATE + START the workload laid in `s.arg`; the handle, or a negative errno.
unsafe fn admit(sys: &SyscallTable, s: &mut State, len: usize) -> i32 {
    let t0 = dev_micros(sys);
    // A large subgraph is staged a batch of modules per call; ask again with
    // the same spec until the handle comes back.
    let mut h = (sys.provider_call)(-1, wl::CREATE, s.arg.as_mut_ptr(), len);
    while h == abi::kernel_abi::errno::EINPROGRESS {
        h = (sys.provider_call)(-1, wl::CREATE, s.arg.as_mut_ptr(), len);
    }
    let dt = dev_micros(sys).saturating_sub(t0).min(u32::MAX as u64) as u32;
    if h < 0 {
        return h;
    }
    s.cmax_us = s.cmax_us.max(dt);
    let rc = (sys.provider_call)(h, wl::START, core::ptr::null_mut(), 0);
    if rc < 0 {
        reap(sys, s, h);
        return rc;
    }
    h
}

unsafe fn reap(sys: &SyscallTable, s: &mut State, h: i32) {
    let t0 = dev_micros(sys);
    let _ = (sys.provider_call)(h, wl::DESTROY, core::ptr::null_mut(), 0);
    let dt = dev_micros(sys).saturating_sub(t0).min(u32::MAX as u64) as u32;
    s.dmax_us = s.dmax_us.max(dt);
}

/// The channel the workload writes this module's lane 0 on, or -1.
unsafe fn lane0(sys: &SyscallTable, h: i32) -> i32 {
    let mut out = [0u8; 1 + wl::MAX_CALLER_LANES * 9];
    let n = (sys.provider_call)(h, wl::LANES, out.as_mut_ptr(), out.len());
    if n < 10 || out[0] == 0 {
        return -1;
    }
    for i in 0..(out[0] as usize).min(wl::MAX_CALLER_LANES) {
        let o = 1 + i * 9;
        if out[o] == 0 {
            return i32::from_le_bytes([out[o + 1], out[o + 2], out[o + 3], out[o + 4]]);
        }
    }
    -1
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
            return 0;
        }
        let sys = &*s.syscalls;
        let now = dev_millis(sys);
        if s.last_step_ms != 0 && s.phase != PH_WAIT_START {
            let gap = now.saturating_sub(s.last_step_ms).min(u32::MAX as u64) as u32;
            s.gapmax_ms = s.gapmax_ms.max(gap);
        }
        s.last_step_ms = now;
        if now.saturating_sub(s.last_hb_ms) >= 5000 {
            s.last_hb_ms = now;
            // The whole outcome rides every heartbeat: a one-shot line can
            // lose the race with `log_net` under the churn burst.
            report(
                sys,
                b"hb",
                &[
                    (b"ms", now as i64),
                    (b"phase", s.phase as i64),
                    (b"n", s.n as i64),
                    (b"ok", s.ok as i64),
                    (b"tmo", s.tmo as i64),
                    (b"cf", s.cf as i64),
                    (b"exh", s.exhausted as i64),
                    (b"f1", s.fault_state[0] as i64),
                    (b"f0", s.fault_state[1] as i64),
                    (b"pack", s.pack_len as i64),
                ],
            );
        }

        match s.phase {
            PH_WAIT_START => {
                if now >= s.start_at_ms as u64 {
                    report(
                        sys,
                        b"start",
                        &[
                            (b"cycles", s.cycles as i64),
                            (b"chan_bytes", s.chan_bytes as i64),
                        ],
                    );
                    s.phase = PH_IDLE;
                }
            }
            PH_IDLE => {
                if s.n >= s.cycles {
                    progress(sys, s);
                    s.phase = if s.fault != 0 { PH_FAULT } else { PH_DONE };
                    s.since_ms = 0;
                    return 0;
                }
                let len = build(s, s.n, None);
                let h = if len == 0 { -22 } else { admit(sys, s, len) };
                if h < 0 {
                    s.cf += 1;
                    s.consecutive_cf += 1;
                    report(
                        sys,
                        b"create_fail",
                        &[(b"n", s.n as i64), (b"rc", h as i64)],
                    );
                    if s.consecutive_cf >= 3 {
                        s.exhausted = 1;
                        report(sys, b"exhausted", &[(b"n", s.n as i64), (b"rc", h as i64)]);
                        progress(sys, s);
                        s.phase = PH_DONE;
                    }
                    return 0;
                }
                s.consecutive_cf = 0;
                s.handle = h;
                s.lane = lane0(sys, h);
                s.since_ms = now;
                s.phase = PH_RUNNING;
            }
            PH_RUNNING => {
                let mut got = false;
                if s.lane >= 0 {
                    let mut buf = [0u8; 64];
                    let n = (sys.channel_read)(s.lane, buf.as_mut_ptr(), buf.len());
                    got = n >= 4;
                }
                let late = now.saturating_sub(s.since_ms) >= s.read_timeout_ms as u64;
                if !got && !late {
                    return 0;
                }
                if got {
                    s.ok += 1;
                } else {
                    s.tmo += 1;
                    if s.tmo <= 3 {
                        report(
                            sys,
                            b"timeout",
                            &[(b"n", s.n as i64), (b"lane", s.lane as i64)],
                        );
                    }
                }
                let h = s.handle;
                reap(sys, s, h);
                s.handle = -1;
                s.lane = -1;
                s.n += 1;
                if s.n.checked_rem(25) == Some(0) {
                    progress(sys, s);
                }
                s.phase = PH_IDLE;
            }
            PH_FAULT => {
                // Mode `error` (1), then `infinite_loop` (0).
                let mode: u8 = if s.fault_idx == 0 { 1 } else { 0 };
                if s.since_ms == 0 {
                    let len = build(s, 0x8000_0000 | s.fault_idx as u32, Some(mode));
                    let h = if len == 0 { -22 } else { admit(sys, s, len) };
                    if h < 0 {
                        report(
                            sys,
                            b"fault_create_fail",
                            &[(b"mode", mode as i64), (b"rc", h as i64)],
                        );
                        s.fault_idx += 1;
                        if s.fault_idx >= 2 {
                            s.phase = PH_DONE;
                        }
                        return 0;
                    }
                    s.handle = h;
                    s.since_ms = now;
                    return 0;
                }
                let mut out = [0u8; 5];
                let _ = (sys.provider_call)(s.handle, wl::WAIT, out.as_mut_ptr(), out.len());
                let st = out[0];
                let code = i32::from_le_bytes([out[1], out[2], out[3], out[4]]);
                let el = now.saturating_sub(s.since_ms);
                let terminal = st == wl::STATE_SIGNALLED || st == wl::STATE_EXITED;
                if !terminal && el < 5000 {
                    return 0;
                }
                report(
                    sys,
                    b"fault",
                    &[
                        (b"mode", mode as i64),
                        (b"state", st as i64),
                        (b"code", code as i64),
                        (b"ms", el as i64),
                    ],
                );
                if let Some(f) = s.fault_state.get_mut(s.fault_idx as usize) {
                    *f = st;
                }
                let h = s.handle;
                reap(sys, s, h);
                s.handle = -1;
                s.since_ms = 0;
                s.fault_idx += 1;
                if s.fault_idx >= 2 {
                    s.phase = PH_DONE;
                }
            }
            PH_DONE => {
                if s.fault_idx != 0xFF {
                    s.fault_idx = 0xFF;
                    report(sys, b"done", &[(b"n", s.n as i64), (b"ok", s.ok as i64)]);
                }
            }
            _ => {}
        }
        0
    }
}

include!("../../sdk/runtime/wasm_entry.rs");
