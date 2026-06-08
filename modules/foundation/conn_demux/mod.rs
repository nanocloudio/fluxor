//! Connection-level demultiplexer for horizontally-scaled TLS+HTTP lanes.
//!
//! Sits on a single shared `ip` module's `net_out` and fans each net_proto
//! frame out to one of N downstream TLS+HTTP compute lanes:
//!
//!   ip.net_out        → conn_demux.conn_in
//!   conn_demux.lane_0 → tls_0.cipher_in
//!   conn_demux.lane_1 → tls_1.cipher_in   (… lane_2, lane_3)
//!
//! Routing key is the per-connection `conn_id` — the first payload byte of
//! every per-connection net_proto message (MSG_ACCEPTED `[conn_id][port]`,
//! MSG_DATA `[conn_id][data]`, MSG_CLOSED `[conn_id]`, MSG_TRACE_CTX, …). All
//! frames of one connection share a conn_id and therefore land on the same
//! lane, giving stable per-connection affinity without any per-flow table.
//!
//! Why this and not the frame-level `demux`: the baseline shows the `ip`
//! stack is ~99.6% idle while `tls` saturates the core, and N independent
//! `ip` instances cannot share one IP/MAC identity (ARP/DHCP race). So we keep
//! ONE `ip` (one identity, one TCP accept loop) and replicate only the
//! compute-heavy `tls`+`http` stages — the parallelism lands on the actual
//! bottleneck. The return path (lane `cipher_out` → `ip.net_in`) is a plain
//! `merge` edge in the graph; this module is unidirectional (ip → lanes).
//!
//! Frame format on every port: `[msg_type:u8][len:u16 LE][payload:len]`
//! (net_proto / NET_FRAME_HDR = 3), matching `modules/sdk/runtime.rs`.

#![no_std]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset. unreachable_patterns: defensive arms are intentional"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

/// Net-proto header: `[msg_type:u8][len:u16 LE]`.
const HDR: usize = 3;
/// `NET_MSG_BOUND` (IP→TLS): the reply to a listener `CMD_BIND`. It is a
/// CONTROL-plane frame, not per-connection — its `payload[0]` is a listener
/// id (typically 0), NOT a routable `conn_id`. With one shared `ip` and N
/// lanes each binding the same port, `ip` emits one BOUND per lane's bind,
/// and every lane's TLS waits for its own (filtering by `local_port`, see
/// `tls/mod.rs` "multi-anchor fan-out"). So BOUND must fan to ALL lanes;
/// routing it by `payload[0]` would deliver it to one lane and wedge the
/// others in their bind path.
const NET_MSG_BOUND: u8 = 0x04;
/// Max payload we route in one frame. MSG_DATA caps at one TCP MSS
/// (MAX_DATA_FRAGMENT = 1460); 2048 leaves slack for any framing.
const MAX_PAYLOAD: usize = 2048;
/// Largest number of lanes (one TLS+HTTP pipeline per A76 core, minus the
/// core hosting ip/conn_demux). `lane_0` is `out[0]`; `lane_1..` are
/// discovered via `dev_channel_port`.
const MAX_LANES: usize = 4;

#[repr(C)]
pub struct ConnDemuxState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    /// `lane_chan[0..lane_count]` are the live downstream lane channels.
    lane_chan: [i32; MAX_LANES],
    lane_count: u32,
    /// Per-lane routed-frame counters (diagnostics).
    to_lane: [u32; MAX_LANES],
    /// Frames with no conn_id (len == 0) broadcast to every lane.
    broadcast: u32,
    /// Step counter, drives the distribution heartbeat.
    step_count: u32,
    /// Bitmask of lanes that still owe delivery of the frame currently
    /// held in `frame_buf`. Non-zero ⇒ a frame is pending: we retry it
    /// (and read NO new input) until it clears, so downstream backpressure
    /// propagates to `in_chan` instead of silently dropping the frame.
    pending_mask: u32,
    /// Total bytes (HDR + payload) of the held frame.
    pending_total: usize,
    /// Whether the held frame is a control broadcast (counts `broadcast`)
    /// vs a per-connection unicast (counts `to_lane[lane]`).
    pending_is_bcast: bool,
    /// Frames dropped because they were oversized/malformed (never routable).
    /// Backpressured frames are retained, not dropped, so this stays 0 in
    /// normal operation — a non-zero value flags a real framing fault.
    dropped: u32,
    frame_buf: [u8; HDR + MAX_PAYLOAD],
}

const STATE_SIZE: usize = core::mem::size_of::<ConnDemuxState>();

/// Map a connection id to a lane index in `0..lane_count`. FNV-style mix so
/// adjacent conn_ids spread across lanes; modulo over the (static) lane
/// count gives a fixed assignment for the life of the graph.
#[inline]
fn lane_for_conn(conn_id: u8, lane_count: u32) -> usize {
    if lane_count <= 1 {
        return 0;
    }
    let mut h = (conn_id as u32).wrapping_add(0x9E37_79B1);
    h = h.wrapping_mul(0x0100_0193); // FNV prime
    h ^= h >> 16;
    (h % lane_count) as usize
}

/// Attempt to write the whole framed packet to `chan`. Kernel ring writes
/// are **all-or-nothing**: `channel_write` returns `total` only if the ring
/// had room for every byte, else a short count / `CHAN_EAGAIN`. A channel can
/// report writable (`POLL_OUT`) yet still reject a full frame that exceeds the
/// remaining room, so the poll is a fast-reject gate, not a capacity check —
/// the `== total` test is what actually proves delivery. Returns `true` only
/// when the entire frame landed.
unsafe fn write_framed(sys: &SyscallTable, chan: i32, buf: *const u8, total: usize) -> bool {
    if chan < 0 {
        return false;
    }
    let poll = (sys.channel_poll)(chan, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 {
        return false;
    }
    (sys.channel_write)(chan, buf, total) == total as i32
}

/// Deliver the held frame to every lane still set in `pending_mask`, clearing
/// each lane's bit only on a confirmed full write. Lanes that reject the frame
/// (full ring) keep their bit and are retried next step. On full delivery the
/// matching counter is bumped (per-lane for unicast, `broadcast` once for a
/// control frame).
unsafe fn flush_pending(s: &mut ConnDemuxState, sys: &SyscallTable) {
    let buf = s.frame_buf.as_ptr();
    let total = s.pending_total;
    let mut i = 0usize;
    while i < s.lane_count as usize && i < MAX_LANES {
        let bit = 1u32 << i;
        if (s.pending_mask & bit) != 0 && write_framed(sys, s.lane_chan[i], buf, total) {
            s.pending_mask &= !bit;
            if !s.pending_is_bcast {
                s.to_lane[i] = s.to_lane[i].wrapping_add(1);
            }
        }
        i += 1;
    }
    if s.pending_mask == 0 && s.pending_is_bcast {
        s.broadcast = s.broadcast.wrapping_add(1);
        s.pending_is_bcast = false;
    }
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    STATE_SIZE
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_arena_size"]
pub extern "C" fn module_arena_size() -> u32 {
    0
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    _state_size: usize,
    syscalls: *const SyscallTable,
) -> i32 {
    let s = unsafe { &mut *(state as *mut ConnDemuxState) };
    s.syscalls = syscalls;
    s.in_chan = in_chan;
    s.lane_chan = [-1; MAX_LANES];
    s.to_lane = [0; MAX_LANES];
    s.broadcast = 0;
    s.step_count = 0;
    s.pending_mask = 0;
    s.pending_total = 0;
    s.pending_is_bcast = false;
    s.dropped = 0;

    // lane_0 is out[0]; lane_1.. are discovered. A lane is live iff its
    // channel resolves to a non-negative handle. Lanes must be contiguous
    // from 0 (the graph wires them densely), so stop at the first gap.
    s.lane_chan[0] = out_chan;
    let mut count = if out_chan >= 0 { 1 } else { 0 };
    unsafe {
        let sys = &*s.syscalls;
        let mut i = 1usize;
        while i < MAX_LANES {
            let ch = dev_channel_port(sys, 1, i as u8);
            if ch < 0 {
                break;
            }
            s.lane_chan[i] = ch;
            count += 1;
            i += 1;
        }
    }
    s.lane_count = count;
    0
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut ConnDemuxState);
    let sys = &*s.syscalls;

    // Distribution heartbeat — surfaces the per-lane routed-frame counts so
    // load can be confirmed even across lanes (helps diagnose whether a
    // conn_id % lane_count skew is starving a lane). Same ~50k-step cadence
    // the tls/ip heartbeats use.
    s.step_count = s.step_count.wrapping_add(1);
    if s.step_count.is_multiple_of(50_000) {
        let mut line = [0u8; 96];
        let lp = line.as_mut_ptr();
        let cap = line.len();
        let mut p = 0usize;
        // `lp` is a raw pointer (Copy) so the closure doesn't alias `line`.
        let emit = |bytes: &[u8], p: &mut usize| {
            let mut k = 0;
            while k < bytes.len() && *p < cap {
                *lp.add(*p) = bytes[k];
                *p += 1;
                k += 1;
            }
        };
        emit(b"[cdx] lanes=", &mut p);
        p += fmt_u32_dec(s.lane_count, lp.add(p));
        let mut i = 0usize;
        while i < s.lane_count as usize && i < MAX_LANES {
            emit(b" l", &mut p);
            p += fmt_u32_dec(i as u32, lp.add(p));
            emit(b"=", &mut p);
            p += fmt_u32_dec(s.to_lane[i], lp.add(p));
            i += 1;
        }
        emit(b" bc=", &mut p);
        p += fmt_u32_dec(s.broadcast, lp.add(p));
        emit(b" drop=", &mut p);
        p += fmt_u32_dec(s.dropped, lp.add(p));
        dev_log(sys, 3, lp, p);
    }

    if s.in_chan < 0 || s.lane_count == 0 {
        return 0;
    }

    // A frame held from a prior step takes priority: retry it, and read NO
    // new input until it fully clears. While it is blocked we leave the
    // upstream `in_chan` undrained, so `ip`'s `net_out` ring fills and back-
    // pressure propagates to the source instead of dropping frames here.
    if s.pending_mask != 0 {
        flush_pending(s, sys);
        return if s.pending_mask == 0 { 2 } else { 0 };
    }

    let poll = (sys.channel_poll)(s.in_chan, 0x01);
    if poll <= 0 || (poll as u32 & 0x01) == 0 {
        return 0;
    }

    let buf = s.frame_buf.as_mut_ptr();
    // Read the 3-byte net_proto header: [msg_type][len:u16 LE].
    let hn = (sys.channel_read)(s.in_chan, buf, HDR);
    if hn < HDR as i32 {
        return 0;
    }
    let payload_len = (*buf.add(1) as usize) | ((*buf.add(2) as usize) << 8);
    if payload_len > MAX_PAYLOAD {
        // Oversized / malformed — cannot route safely; drop the header and
        // resync on the next frame boundary.
        s.dropped = s.dropped.wrapping_add(1);
        return 0;
    }

    if payload_len > 0 {
        let r = (sys.channel_read)(s.in_chan, buf.add(HDR), payload_len);
        if r < payload_len as i32 {
            return 0;
        }
    }
    s.pending_total = HDR + payload_len;
    let msg_type = *buf;

    // Latch the frame's target lane(s) into `pending_mask`, then attempt
    // delivery. Any lane that can't accept the full frame keeps its bit set
    // and is retried (input-blocked) on the next step — no silent drop.
    //
    // Broadcast (fan to every live lane) when the frame is control-plane:
    //   * `payload_len == 0` — no conn_id at all (edge/control frame), or
    //   * `NET_MSG_BOUND`    — a listener bind reply whose payload[0] is a
    //     listener id, not a routable conn_id; each lane's TLS waits for its
    //     own BOUND and filters by local_port.
    // Everything else is per-connection: route by `payload[0]` (the conn_id).
    let is_broadcast = payload_len == 0 || msg_type == NET_MSG_BOUND;
    if is_broadcast {
        s.pending_is_bcast = true;
        s.pending_mask = if s.lane_count >= 32 {
            u32::MAX
        } else {
            (1u32 << s.lane_count) - 1
        };
    } else {
        // payload[0] is the conn_id for every per-connection message.
        let conn_id = *buf.add(HDR);
        let lane = lane_for_conn(conn_id, s.lane_count);
        s.pending_is_bcast = false;
        s.pending_mask = 1u32 << lane;
    }

    flush_pending(s, sys);
    // Burst (re-pass) only when the frame fully cleared; otherwise return
    // Continue so we wait for the blocked lane to drain rather than spin.
    if s.pending_mask == 0 {
        2
    } else {
        0
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
include!("../../sdk/wasm_entry.rs");
