//! quic_continuity — the `TRANSPORT_CONTINUITY` provider for this graph's
//! `quic` (`TcTransport::Quic`). Logic in `qcs.rs` (host tested); this
//! file moves frames.
//!
//! Ports (index: input / output):
//!
//! - 0 `tc_ctl` / `tc_evt` — the anchor's operations and the events.
//! - 1 `quic_cont` / `quic_ctl` — from `quic.cont_out`, to `quic.cont_in`.
//! - 2 `auth_rsp` / `auth_req` — ACTIVATE's token check (`0xC2` the 48-byte
//!   per-flow token, `0xC3` the verdict). Unwired, nothing activates.
//!
//! Params: `anchor_id` (16 hex digits); `flows` (u16, default 2): the flows
//! this instance moves at once. Their table is taken from the module's heap
//! at instantiation — the composer sizes the heap for the count
//! (`[capacities] heap_per_param`) — and a pairing past it is refused
//! `CAPACITY`. An instance whose heap cannot hold the table, or with
//! `flows = 0`, refuses to start, saying so.

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
include!("../transport_continuity/heap_table.rs");
include!("../../sdk/cores/transport_continuity.rs");
include!("../../sdk/cores/session_handoff.rs");
include!("qcs.rs");

const PORTS: usize = 3;
const P_CTL: usize = 0;
const P_QUIC: usize = 1;
const P_AUTH: usize = 2;
const HDR: usize = 3;
const RX_MAX: usize = TC_FRAME_MAX + 64;
/// Output queues: a whole `WHQ1` record as chunks and the deltas behind it
/// to the anchor, per-layer frames to `quic`, token checks.
const Q_CAP: [usize; PORTS] = [QCS_REC_MAX + 64 * 1024, 64 * 1024, 1024];
const Q_MAX: usize = QCS_REC_MAX + 64 * 1024;

#[repr(C)]
struct Rx {
    len: usize,
    skip: usize,
    buf: [u8; RX_MAX],
}

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
    queue_full: u32,
    rx: [Rx; PORTS],
    q: [Q; PORTS],
    frame: [u8; RX_MAX],
    core: QcStack,
}

struct Out<'a> {
    outs: &'a [i32; PORTS],
    q: &'a mut [Q; PORTS],
    full: &'a mut u32,
}

impl QcsOut for Out<'_> {
    fn send(&mut self, port: QcsPort, frame: &[u8]) -> bool {
        let k = match port {
            QcsPort::Evt => P_CTL,
            QcsPort::Quic => P_QUIC,
            QcsPort::Auth => P_AUTH,
        };
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

unsafe fn flush(s: &mut State) {
    let sys = &*s.syscalls;
    for k in 0..PORTS {
        let ch = s.outs[k];
        let q = &mut s.q[k];
        while ch >= 0 && q.end - q.start >= HDR {
            let len =
                HDR + usize::from(u16::from_le_bytes([q.buf[q.start + 1], q.buf[q.start + 2]]));
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

unsafe fn pump(s: &mut State, k: usize, now: u64) {
    let ch = s.ins[k];
    if ch < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let mut budget = 64;
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
        if rx.len < HDR {
            return;
        }
        let total = HDR + usize::from(u16::from_le_bytes([rx.buf[1], rx.buf[2]]));
        if total > RX_MAX {
            rx.skip = total - rx.len;
            rx.len = 0;
            continue;
        }
        if rx.len < total {
            return;
        }
        s.frame[..total].copy_from_slice(&rx.buf[..total]);
        let rest = rx.len - total;
        rx.buf.copy_within(total..total + rest, 0);
        rx.len = rest;
        let State {
            outs,
            q,
            queue_full,
            core,
            frame,
            ..
        } = s;
        let mut out = Out {
            outs,
            q,
            full: queue_full,
        };
        let f = &frame[..total];
        match k {
            P_CTL => core.ctl(f, now, &mut out),
            P_QUIC => core.layer_in(f, now, &mut out),
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
    // In place: all-zero memory is the empty provider (`QcStack::new`).
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
        let msg = b"[qc] refusing to construct: flows = 0 leaves no flow to move";
        dev_log(sys, 1, msg.as_ptr(), msg.len());
        return abi::errno::EINVAL;
    }
    match QcsFlows::take(sys.heap_alloc, usize::from(s.flows)) {
        Some(table) => s.core.flows = table,
        None => {
            let msg = b"[qc] refusing to construct: the heap cannot hold `flows` flows \
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
    let now = dev_millis(&*s.syscalls);
    pump(s, P_QUIC, now);
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
        core.tick(now, &mut out);
    }
    flush(s);
    0
}

include!("../../sdk/runtime/wasm_entry.rs");
