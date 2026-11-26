//! Workload-churn driver.
//!
//! Admits and reaps a two-module workload `cycles` times through the metal
//! `workload` backend (0x1A), as a node agent does, then stages up to two
//! faulting workloads (`fault`). See the manifest for the log lines; the
//! kernel's `[live]` line reports the arenas beside them.

#![no_std]
#![allow(
    unreachable_patterns,
    reason = "defensive `_ => Error` arms in enum state-machine matches. The match is \
              exhaustive, which is why the lint fires; the arm exists so that adding a \
              variant cannot silently bypass the error path. #[expect] is not the \
              alternative — it fails the build in the configurations where the lint \
              does not fire"
)]

use core::ffi::c_void;

use abi::contracts::workload as wl;
use abi::SyscallTable;
use fluxor_abi as abi;
use fluxor_contracts::graph::{self, plan, EdgeRecord, Endpoint, GraphSpec, ModuleRecord};
use fluxor_contracts::params_tlv::{TLV_END, TLV_MAGIC, TLV_VERSION};

use fluxor_rt::*;

/// CREATE header + a composed graph of at most two modules and two edges.
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

    use super::{p_u32, p_u8};

    fluxor_rt::define_params! {
        State;

        1, cycles, u32, 500
            => |s, d, len| { s.cycles = p_u32(d, len, 0, 500); };

        2, chan_bytes, u32, 16384
            => |s, d, len| { s.chan_bytes = p_u32(d, len, 0, 16384); };

        3, start_at_ms, u32, 20000
            => |s, d, len| { s.start_at_ms = p_u32(d, len, 0, 20000); };

        4, read_timeout_ms, u32, 2000
            => |s, d, len| { s.read_timeout_ms = p_u32(d, len, 0, 2000); };

        // How many faulting workloads the fault phase stages: 0 none, 1 mode
        // `error`, 2 mode `error` then mode `infinite_loop`.
        5, fault, u8, 1
            => |s, d, len| { s.fault = p_u8(d, len, 0, 2); };

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

fluxor_rt::module_facts! { state: State }

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[no_mangle]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
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

/// The most modules and edges a churn or fault workload declares.
const WORKLOAD_MODULES: usize = 2;
const WORKLOAD_EDGES: usize = 2;

/// A one-entry params TLV: tag 1 = `v` as a u8.
const fn params_u8(v: u8) -> [u8; 9] {
    [TLV_MAGIC, TLV_VERSION, 5, 0, 1, 1, v, TLV_END, 0]
}

/// A module of the workload: `name` with params `params`, in domain 0, on
/// the node's default step budget.
fn module<'p>(name: &[u8], params: &'p [u8]) -> ModuleRecord<'p> {
    ModuleRecord {
        name_hash: graph::name_hash(name),
        params,
        ..ModuleRecord::default()
    }
}

/// Compose `modules` joined by `edges` and encode the graph into `out`, as
/// the composer composes a workload: the fan pass, then the stepping order.
/// The bytes written, or `None` when the graph does not compose or fit.
fn compose_into(
    modules: &[ModuleRecord<'_>],
    edges: &[EdgeRecord],
    out: &mut [u8],
) -> Option<usize> {
    let plan_modules = [plan::PlanModule::default(); WORKLOAD_MODULES];
    let plan_modules = plan_modules.get(..modules.len())?;
    // A fan adds a module and an edge; a churn workload fans nothing, so
    // room for one of each says so rather than assuming it.
    let mut all = [EdgeRecord::default(); WORKLOAD_EDGES + 1];
    all.get_mut(..edges.len())?.copy_from_slice(edges);
    let mut fans = [plan::Fan {
        dir: plan::FanDir::Out,
        of: Endpoint::New(0),
        port: 0,
        mailbox: false,
        domain: 0,
    }; 1];
    let groups = fluxor_contracts::ring_size::buffer_groups(edges.len());
    let counts = plan::fan_pass(plan_modules, &mut all, edges.len(), &mut fans, groups).ok()?;
    if counts.fans != 0 {
        return None;
    }
    let edges = &all[..counts.edges];
    let mut order = [0u16; WORKLOAD_MODULES];
    let mut indeg = [0u16; WORKLOAD_MODULES];
    plan::order(modules.len(), edges, false, &mut order, &mut indeg).ok()?;
    let spec = GraphSpec {
        order: &order[..modules.len()],
        modules,
        edges,
        ..GraphSpec::default()
    };
    graph::encode_into(&spec, out).ok()
}

/// Lay the CREATE header and composed graph for workload `id` into `s.arg`;
/// returns the total length, or 0 on overflow. `fault_mode` None = the churn
/// workload.
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
    // and its pin come first in the source section, the graph after them.
    let pack = fault_mode.is_none() && s.pack_len > 0 && s.pin_set != 0;
    let mut at = wl::CREATE_HEADER_SIZE;
    if pack {
        s.arg[17] = wl::SOURCE_FMOD_PACK;
        // The pack's bytes travel as the call's `data`; the reference
        // carries its pins: a count, three zero bytes, then each pin.
        s.arg[at] = 1;
        at += 4;
        s.arg[at..at + 32].copy_from_slice(&s.pin);
        at += 32;
    }
    let (source, relay) = (params_u8(0), params_u8(1));
    let fault = params_u8(fault_mode.unwrap_or(0));
    let churn = [
        module(b"churn_probe", &source),
        module(b"churn_probe", &relay),
    ];
    let faulting = [module(b"test_fault", &fault)];
    let link = |from, to| EdgeRecord {
        from,
        to,
        buffer_bytes: chan,
        ..EdgeRecord::default()
    };
    let churn_edges = [
        link(Endpoint::New(0), Endpoint::New(1)),
        link(Endpoint::New(1), Endpoint::Caller(0)),
    ];
    let (modules, edges): (&[ModuleRecord<'_>], &[EdgeRecord]) = match fault_mode {
        None => (&churn, &churn_edges),
        Some(_) => (&faulting, &[]),
    };
    let Some(n) = compose_into(modules, edges, &mut s.arg[at..]) else {
        return 0;
    };
    let src_len = at + n - wl::CREATE_HEADER_SIZE;
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
    let (data, data_len) = if s.arg[17] == wl::SOURCE_FMOD_PACK {
        (s.pack.as_mut_ptr(), s.pack_len as usize)
    } else {
        (core::ptr::null_mut(), 0)
    };
    let mut h = (sys.provider_call)(-1, wl::CREATE, s.arg.as_mut_ptr(), len, data, data_len);
    while h == abi::kernel_abi::errno::EINPROGRESS {
        h = (sys.provider_call)(-1, wl::CREATE, s.arg.as_mut_ptr(), len, data, data_len);
    }
    let dt = dev_micros(sys).saturating_sub(t0).min(u32::MAX as u64) as u32;
    if h < 0 {
        return h;
    }
    s.cmax_us = s.cmax_us.max(dt);
    let rc = (sys.provider_call)(
        h,
        wl::START,
        core::ptr::null_mut(),
        0,
        core::ptr::null_mut(),
        0,
    );
    if rc < 0 {
        reap(sys, s, h);
        return rc;
    }
    h
}

unsafe fn reap(sys: &SyscallTable, s: &mut State, h: i32) {
    let t0 = dev_micros(sys);
    let _ = (sys.provider_call)(
        h,
        wl::DESTROY,
        core::ptr::null_mut(),
        0,
        core::ptr::null_mut(),
        0,
    );
    let dt = dev_micros(sys).saturating_sub(t0).min(u32::MAX as u64) as u32;
    s.dmax_us = s.dmax_us.max(dt);
}

/// The channel the workload writes this module's lane 0 on, or -1.
unsafe fn lane0(sys: &SyscallTable, h: i32) -> i32 {
    let mut arg = [0u8, wl::lane::TO_CALLER];
    let ch = (sys.provider_call)(
        h,
        wl::LANE,
        arg.as_mut_ptr(),
        arg.len(),
        core::ptr::null_mut(),
        0,
    );
    if ch < 0 {
        -1
    } else {
        ch
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> StepReturn {
    unsafe {
        if state.is_null() {
            return StepReturn::error(-1);
        }
        let s = &mut *(state as *mut State);
        if s.syscalls.is_null() {
            return StepReturn::Continue;
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
                    return StepReturn::Continue;
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
                    return StepReturn::Continue;
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
                    return StepReturn::Continue;
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
                        if s.fault_idx >= s.fault {
                            s.phase = PH_DONE;
                        }
                        return StepReturn::Continue;
                    }
                    s.handle = h;
                    s.since_ms = now;
                    return StepReturn::Continue;
                }
                let mut out = [0u8; 5];
                let _ = (sys.provider_call)(
                    s.handle,
                    wl::WAIT,
                    out.as_mut_ptr(),
                    out.len(),
                    core::ptr::null_mut(),
                    0,
                );
                let st = out[0];
                let code = i32::from_le_bytes([out[1], out[2], out[3], out[4]]);
                let el = now.saturating_sub(s.since_ms);
                let terminal = st == wl::STATE_SIGNALLED || st == wl::STATE_EXITED;
                if !terminal && el < 5000 {
                    return StepReturn::Continue;
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
                if s.fault_idx >= s.fault {
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
        StepReturn::Continue
    }
}

fluxor_rt::wasm_entry!();
