//! transport_continuity — the `TRANSPORT_CONTINUITY` provider over this
//! graph's `ip` and `tls`.
//!
//! An anchor drives one flow at a time through the operations
//! (`contracts/net/transport_continuity.rs`) on `tc_ctl` / `tc_evt`; this
//! module turns them into the per-layer continuity commands `ip` and `tls`
//! already answer (`contracts/net/session_ctrl.rs` §Transport continuity) on
//! their `cont_in` / `cont_out` pairs, builds the canonical record from the
//! two per-layer records a primary exports, and splits a standby's record
//! back into the two the modules import. The logic is `stack.rs` (pure, host
//! tested); this file moves frames.
//!
//! Ports (index: input / output):
//!
//! - 0 `tc_ctl` / `tc_evt` — the anchor's operations and the events.
//! - 1 `ip_cont` / `ip_ctl` — from `ip.cont_out`, to `ip.cont_in`.
//! - 2 `tls_cont` / `tls_ctl` — from `tls.cont_out`, to `tls.cont_in`.
//! - 3 `key_in` / `key_out` — the wrapped continuity object (the TLS half's
//!   secret set, still sealed by `tls`'s vault, and the session identity the
//!   record names by digest), on whatever custody path the graph wires.
//! - 4 `auth_rsp` / `auth_req` — ACTIVATE's token check: `auth_req` carries
//!   the 48-byte per-flow emission token this module rebuilt for its own
//!   anchor, `auth_rsp` the authority's verdict. Unwired, nothing activates.
//!
//! Each input is a byte stream of `[type][len u16 LE][payload]` frames and is
//! reassembled whole; each port takes only its own frames, so an anchor
//! cannot hand in a verdict or a key. Every output frame is written whole.
//! A crash-continuous half's frame is taken only when what it becomes has
//! room (`TcStack::layer_room`); otherwise it stays on `ip_cont` / `tls_cont`
//! and that port is read no further this step — back-pressure the half's
//! own horizons carry to the connection, never the end of the pairing.
//!
//! Params: `anchor_id` (16 hex digits: the 8-byte anchor identity tokens
//! are minted for); `flows` (u16, default 2): the flows this instance moves
//! at once. Their table is taken from the module's heap at instantiation —
//! the composer sizes the heap for the count (`[capacities] heap_per_param`)
//! — and a pairing past it is refused `CAPACITY`. An instance whose heap
//! cannot hold the table, or with `flows = 0`, refuses to start, saying so.

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
use abi::contracts::net::session_ctrl as sc;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");
include!("../../sdk/crypto/sha256.rs");
include!("../../sdk/contracts/net/transport_continuity.rs");
include!("heap_table.rs");
include!("../../sdk/cores/transport_continuity.rs");
include!("../../sdk/cores/session_handoff.rs");
include!("stack.rs");

// ── ports ─────────────────────────────────────────────────────────────────

const PORTS: usize = 5;
const P_CTL: usize = 0;
const P_IP: usize = 1;
const P_TLS: usize = 2;
const P_KEY: usize = 3;
const P_AUTH: usize = 4;

/// The largest frame any input carries: a delta or chunk from the anchor,
/// or a strict `tls` delta carrying a whole protected record still partial
/// and a record's whole plaintext. A larger frame is skipped, and the
/// stream it belonged to is reported broken (`layer_overrun`).
const RX_MAX: usize = 40 * 1024;
const _: () = assert!(RX_MAX >= TC_FRAME_MAX);
/// Output queues, sized for the largest burst each port takes at once: a
/// whole checkpoint as chunks, a whole CT_TLS record as per-layer frames.
const Q_EVT: usize = TS_CKPT_MAX + 32 * 1024;
const Q_IP: usize = 8 * 1024;
const Q_TLS: usize = 64 * 1024;
const Q_KEY: usize = 2 * 1024;
const Q_AUTH: usize = 1024;
const Q_MAX: usize = Q_EVT;
const Q_CAP: [usize; PORTS] = [Q_EVT, Q_IP, Q_TLS, Q_KEY, Q_AUTH];
// A half's frame is taken only with this much room on the event queue
// (`TcStack::layer_room`); an empty queue always has it.
const _: () = assert!(Q_EVT >= TCS_FRAME_EVT);

/// One input's reassembly buffer, and the bytes of an overlong frame
/// still to be discarded.
#[repr(C)]
struct Rx {
    len: usize,
    skip: usize,
    buf: [u8; RX_MAX],
}

/// One output's queue of whole frames.
#[repr(C)]
struct Q {
    start: usize,
    end: usize,
    buf: [u8; Q_MAX],
}

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    ins: [i32; PORTS],
    outs: [i32; PORTS],
    anchor_id: [u8; 8],
    /// The `flows` param: the flow table's length.
    flows: u16,
    step_count: u32,
    queue_full: u32,
    logged_refusals: u32,
    rx: [Rx; PORTS],
    q: [Q; PORTS],
    core: TcStack,
}

/// The outputs as `stack.rs` sees them.
struct Out<'a> {
    outs: &'a [i32; PORTS],
    q: &'a mut [Q; PORTS],
    full: &'a mut u32,
}

fn port_index(port: TcsPort) -> usize {
    match port {
        TcsPort::Evt => P_CTL,
        TcsPort::Ip => P_IP,
        TcsPort::Tls => P_TLS,
        TcsPort::Key => P_KEY,
        TcsPort::Auth => P_AUTH,
    }
}

impl TcsOut for Out<'_> {
    fn room(&self, port: TcsPort) -> usize {
        let k = port_index(port);
        let q = &self.q[k];
        Q_CAP[k] - (q.end - q.start)
    }

    fn send(&mut self, port: TcsPort, frame: &[u8]) -> bool {
        let k = port_index(port);
        if self.outs[k] < 0 {
            return false;
        }
        let q = &mut self.q[k];
        let cap = Q_CAP[k];
        if q.end + frame.len() > cap && q.start > 0 {
            q.buf.copy_within(q.start..q.end, 0);
            q.end -= q.start;
            q.start = 0;
        }
        if q.end + frame.len() > cap {
            *self.full = self.full.wrapping_add(1);
            return false;
        }
        q.buf[q.end..q.end + frame.len()].copy_from_slice(frame);
        q.end += frame.len();
        true
    }
}

/// Write queued frames, each whole, until a channel is full.
unsafe fn flush(s: &mut State) {
    let sys = &*s.syscalls;
    for k in 0..PORTS {
        let ch = s.outs[k];
        let q = &mut s.q[k];
        while ch >= 0 && q.end - q.start >= TCS_HDR {
            let len =
                TCS_HDR + usize::from(u16::from_le_bytes([q.buf[q.start + 1], q.buf[q.start + 2]]));
            if (sys.channel_write)(ch, q.buf.as_ptr().add(q.start), len) != len as i32 {
                break;
            }
            q.start += len;
        }
        if q.start == q.end {
            q.start = 0;
            q.end = 0;
        }
    }
}

/// Read what input `k` has and hand each whole frame on.
unsafe fn pump(s: &mut State, k: usize, now: u64) {
    let ch = s.ins[k];
    if ch < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let mut budget = 32;
    while budget > 0 {
        budget -= 1;
        let rx = &mut s.rx[k];
        if rx.skip > 0 {
            let n = (sys.channel_read)(ch, rx.buf.as_mut_ptr(), rx.skip.min(RX_MAX));
            if n <= 0 {
                return;
            }
            rx.skip -= n as usize;
            continue;
        }
        if rx.len < RX_MAX {
            let n = (sys.channel_read)(ch, rx.buf.as_mut_ptr().add(rx.len), RX_MAX - rx.len);
            if n > 0 {
                rx.len += n as usize;
            }
        }
        let rx = &s.rx[k];
        if rx.len < TCS_HDR {
            return;
        }
        let total = TCS_HDR + usize::from(u16::from_le_bytes([rx.buf[1], rx.buf[2]]));
        if total > RX_MAX {
            // A frame larger than any this module reads: skipped whole, so
            // the stream stays in step; what it carried is lost.
            let held = rx.len;
            s.rx[k].skip = total - held;
            s.rx[k].len = 0;
            let port = match k {
                P_IP => TcsPort::Ip,
                P_TLS => TcsPort::Tls,
                _ => TcsPort::Evt,
            };
            let State {
                outs,
                q,
                queue_full,
                core,
                ..
            } = s;
            let mut out = Out {
                outs,
                q,
                full: queue_full,
            };
            core.layer_overrun(port, &mut out);
            continue;
        }
        if rx.len < total {
            return;
        }
        if k == P_IP || k == P_TLS {
            // A crash-continuous half's frame waits on its port while what
            // it would become has no room (`TcStack::layer_room`): the
            // half's horizons hold the connection meanwhile.
            let port = if k == P_IP { TcsPort::Ip } else { TcsPort::Tls };
            let State {
                outs,
                q,
                queue_full,
                core,
                rx,
                ..
            } = s;
            let out = Out {
                outs,
                q,
                full: queue_full,
            };
            if !core.layer_room(port, &rx[k].buf[..total], &out) {
                return;
            }
        }
        let rx = &s.rx[k];
        let mut frame = [0u8; RX_MAX];
        frame[..total].copy_from_slice(&rx.buf[..total]);
        let rest = rx.len - total;
        s.rx[k].buf.copy_within(total..total + rest, 0);
        s.rx[k].len = rest;
        let f = &frame[..total];
        let State {
            outs,
            q,
            queue_full,
            core,
            ..
        } = s;
        let mut out = Out {
            outs,
            q,
            full: queue_full,
        };
        match k {
            P_CTL => core.ctl(f, now, &mut out),
            P_IP => core.layer(TcsPort::Ip, f, now, &mut out),
            P_TLS => core.layer(TcsPort::Tls, f, now, &mut out),
            P_KEY => core.wrapped_in(f),
            _ => core.verdict_in(f, now, &mut out),
        }
    }
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

mod params_def {
    use super::*;
    define_params! {
        State;
        1, anchor_id, str, 0 => |s, d, len| {
            if len == 16 {
                let mut id = [0u8; 8];
                let mut ok = true;
                let mut i = 0usize;
                while i < 8 {
                    match (hex_nibble(*d.add(2 * i)), hex_nibble(*d.add(2 * i + 1))) {
                        (Some(a), Some(b)) => id[i] = (a << 4) | b,
                        _ => ok = false,
                    }
                    i += 1;
                }
                if ok {
                    s.anchor_id = id;
                }
            }
        };
        2, flows, u16, 2 => |s, d, len| { s.flows = p_u16(d, len, 0, 2); };
    }
}

/// The heap the module needs besides its flow table: the table's one block
/// header (8 B), its rounding to the allocator's 16-byte granularity and
/// the 4-byte canary under `canary_enabled`, within 64 B.
const ARENA_BASE: u32 = 64;
declare_module_arena_bytes!(ARENA_BASE);

// ── entry points ──────────────────────────────────────────────────────────

declare_module_state_bytes!(State);

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_arena_size"]
pub extern "C" fn module_arena_size() -> u32 {
    ARENA_BASE
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
    if state_size < core::mem::size_of::<State>() {
        return -6;
    }
    // In place: the state is far larger than any stack frame here, and
    // all-zero memory is the empty provider (`TcStack::new`).
    core::ptr::write_bytes(state, 0, core::mem::size_of::<State>());
    let s = &mut *(state as *mut State);
    s.syscalls = syscalls as *const SyscallTable;
    let sys = &*s.syscalls;
    s.ins[0] = in_chan;
    s.outs[0] = out_chan;
    let mut k = 1;
    while k < PORTS {
        s.ins[k] = dev_channel_port(sys, 0, k as u8);
        s.outs[k] = dev_channel_port(sys, 1, k as u8);
        k += 1;
    }
    s.flows = 2;
    if !params.is_null() && params_len > 0 {
        params_def::parse_tlv(s, params, params_len);
    }
    s.core.anchor_id = s.anchor_id;
    // The flow table, from the heap the composer sized for `flows`. Zeroed
    // memory is the unpaired flow, as it is the empty provider.
    if s.flows == 0 {
        let msg = b"[tc] refusing to construct: flows = 0 leaves no flow to move";
        dev_log(sys, 1, msg.as_ptr(), msg.len());
        return abi::errno::EINVAL;
    }
    match TcsFlows::take(sys.heap_alloc, usize::from(s.flows)) {
        Some(table) => s.core.flows = table,
        None => {
            let msg = b"[tc] refusing to construct: the heap cannot hold `flows` flows \
                        (heap.arena_bytes below what heap_per_param sizes)";
            dev_log(sys, 1, msg.as_ptr(), msg.len());
            return abi::errno::ENOMEM;
        }
    }
    0
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut State);
    s.step_count = s.step_count.wrapping_add(1);
    let now = dev_millis(&*s.syscalls);
    // The modules' replies first, so an operation they finish this step
    // makes room for the anchor's next.
    pump(s, P_IP, now);
    pump(s, P_TLS, now);
    pump(s, P_KEY, now);
    pump(s, P_AUTH, now);
    pump(s, P_CTL, now);
    {
        let State {
            outs,
            q,
            queue_full,
            core,
            ..
        } = s;
        let mut out = Out {
            outs,
            q,
            full: queue_full,
        };
        core.poll(now, &mut out);
    }
    flush(s);
    if s.core.counters.layer_refusals != s.logged_refusals {
        s.logged_refusals = s.core.counters.layer_refusals;
        log_refusal(s);
    }
    0
}

/// One line per refused operation: why, and the send side an export saw.
unsafe fn log_refusal(s: &mut State) {
    let c = s.core.counters;
    let mut line = [0u8; 160];
    let mut n = 0usize;
    let mut put = |b: &[u8]| {
        let k = b.len().min(line.len() - n);
        line[n..n + k].copy_from_slice(&b[..k]);
        n += k;
    };
    put(b"[tc] refused why=0x");
    let mut hex = [0u8; 2];
    let digits = b"0123456789abcdef";
    hex[0] = digits[usize::from(c.last_refusal >> 4)];
    hex[1] = digits[usize::from(c.last_refusal & 0xF)];
    put(&hex);
    let mut num = |label: &[u8], v: u32| {
        put(label);
        let mut d = [0u8; 10];
        // SAFETY: ten bytes hold any u32 in decimal.
        let k = unsafe { fmt_u32_raw(d.as_mut_ptr(), v) };
        put(&d[..k]);
    };
    num(b" una=", c.last_send[0]);
    num(b" nxt=", c.last_send[1]);
    num(b" retx_base=", c.last_send[2]);
    num(b" retx_len=", c.last_send[3]);
    num(b" anchored=", c.last_send[4]);
    dev_log(&*s.syscalls, 2, line.as_ptr(), n);
}

include!("../../sdk/runtime/wasm_entry.rs");
