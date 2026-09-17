//! log_net — netconsole-style log forwarding.
//!
//! Drains the kernel log ring (via LOG_RING_DRAIN (diag) 0x0C64) and
//! forwards chunks as UDP datagrams through the IP module using the
//! datagram surface
//! (see `modules/sdk/contracts/net/datagram.rs`). Use this when the
//! UART is unavailable (HAT blocking GPIO14/15, remote bring-up, etc.).
//!
//! # Wiring
//!
//!   ip.net_out  →  log_net.net_in       (inbound frames from ip — discarded)
//!   log_net.net_out →  ip.net_in        (CMD_DG_BIND + CMD_DG_SEND_TO)
//!
//! # Parameters
//!
//! | Tag | Name      | Type | Default      | Description                     |
//! |-----|-----------|------|--------------|---------------------------------|
//! | 1   | dst_ip    | u32  | 0 (disabled) | Destination IP (LE). Setting `0` or an L2 broadcast (`0xFFFFFFFF`) leaves the module dormant — broadcast would flood the subnet at tick rate. The stack injection in `stacks/debug.toml` pins `dst_ip` via `|required` against `~/.config/fluxor/host.toml` so a missing collector fails at build time, not at runtime. |
//! | 2   | dst_port  | u16  | 6666         | UDP destination port            |
//! | 3   | bind_port | u16  | 6667         | Local UDP source port           |
//!
//! # Host-side capture
//!
//!   nc -ul 6666
//!   socat -u UDP-RECV:6666 -

#![no_std]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset. unreachable_patterns: defensive `_ => Error` arms in enum state-machine matches are intentional — adding a new variant should not silently bypass the error path"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");
// Shared UDP datagram-endpoint lifecycle + send (also used by `transport_buffer`).
include!("../../sdk/cores/datagram_endpoint.rs");

// ============================================================================
// Constants
// ============================================================================

// datagram opcodes / DG_V4_PREFIX / DG_AF_INET come from
// modules/sdk/runtime.rs (shared across consumers).

/// Frame buffer: FRAME_HDR + DG_V4_PREFIX + log chunk.
const NET_BUF_SIZE: usize = 600;

/// Per-datagram log payload budget. Leaves ~72 B of slack vs NET_BUF_SIZE.
const CHUNK_SIZE: usize = 512;

/// LOG_RING_DRAIN (diag) opcode. Kept local to avoid bumping the SDK
/// include surface for a single constant.
const LOG_RING_DRAIN: u32 = 0x0C64;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct LogNetState {
    syscalls: *const SyscallTable,
    net_in_chan: i32,
    net_out_chan: i32,

    dst_ip: u32,
    dst_port: u16,
    bind_port: u16,

    /// Shared datagram-endpoint lifecycle + send (`datagram_endpoint` core). Owns the
    /// bind handshake, ep_id, and backoff — the same machine `transport_buffer`
    /// uses, so it lives in one place.
    endpoint: DatagramEndpoint,
    /// One-shot flag so a disabled (dst unset/broadcast) endpoint warns once.
    disabled_warned: u8,

    /// Length of drained-but-unsent bytes in `chunk`. Preserves data across
    /// channel-full retries — if emit_datagram fails, we keep the bytes and
    /// try again next tick instead of losing them.
    pending_len: u16,
    /// Wall clock at which an unbound endpoint reports itself again, and
    /// whether the last step was bound. Together they make the module say
    /// why the collector is receiving nothing: an endpoint that never binds
    /// and a ring with nothing in it are otherwise indistinguishable from
    /// the collector's end, which sees silence either way.
    next_status_ms: u32,
    was_ready: bool,

    /// Stats (informational; readable via memory dump if needed).
    datagrams_sent: u32,
    bytes_forwarded: u32,

    /// Frame buffer for CMD_BIND / CMD_SEND assembly and net_in drain.
    net_buf: [u8; NET_BUF_SIZE],
    /// Scratch for log ring drain chunks.
    chunk: [u8; CHUNK_SIZE],
    /// Steps between datagrams; see the `send_stride` param.
    send_stride: u16,
    /// Steps since the last datagram left.
    since_send: u16,
}

impl LogNetState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.net_in_chan = -1;
        self.net_out_chan = -1;
        // `dst_ip = 0` = not configured. The module stays dormant
        // until a valid unicast dst_ip is supplied via params.
        self.dst_ip = 0;
        self.dst_port = 6666;
        self.bind_port = 6667;
        self.endpoint = DatagramEndpoint::new();
        self.send_stride = 8;
        self.since_send = 0;
        self.disabled_warned = 0;
        self.pending_len = 0;
        self.next_status_ms = 0;
        self.was_ready = false;
        self.datagrams_sent = 0;
        self.bytes_forwarded = 0;
    }
}

// ============================================================================
// Parameters
// ============================================================================

mod params_def {
    use super::p_u16;
    use super::p_u32;
    use super::LogNetState;
    use super::SCHEMA_MAX;

    define_params! {
        LogNetState;

        1, dst_ip, u32, 0
            => |s, d, len| { s.dst_ip = p_u32(d, len, 0, 0); };

        2, dst_port, u16, 6666
            => |s, d, len| { s.dst_port = p_u16(d, len, 0, 6666); };

        3, bind_port, u16, 6667
            => |s, d, len| { s.bind_port = p_u16(d, len, 0, 6667); };

        // Steps between datagrams. One datagram per step is a flood the
        // moment there is a backlog to clear: the ring hands over its
        // whole retained span when this module first attaches, which is
        // tens of datagrams back to back, into an outbound queue of
        // `NET_OUT_QUEUE_SLOTS`. A full queue drops the oldest of that
        // burst, which is the boot window — the reason the replay exists
        // — so delivery of exactly the records that matter becomes a
        // matter of chance. Measured on the Pi 5 rig.
        //
        // Steady-state logging is nowhere near one datagram per step, so
        // a stride costs live output nothing and paces only the
        // catch-up. 0 disables it.
        4, send_stride, u16, 8
            => |s, d, len| { s.send_stride = p_u16(d, len, 0, 8); };
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Send `payload` to the configured unicast destination via the shared
/// `datagram_endpoint` core (one `CMD_DG_SEND_TO` datagram). Returns true iff the
/// channel accepted it. Caller must have observed `endpoint.is_ready()`.
unsafe fn emit_datagram(s: &mut LogNetState, payload: *const u8, payload_len: usize) -> bool {
    let sys = &*s.syscalls;
    let n = s.endpoint.send_to(
        sys,
        s.net_out_chan,
        s.dst_ip,
        s.dst_port,
        payload,
        payload_len,
        s.net_buf.as_mut_ptr(),
        NET_BUF_SIZE,
    );
    if n > 0 {
        s.datagrams_sent = s.datagrams_sent.wrapping_add(1);
        s.bytes_forwarded = s.bytes_forwarded.wrapping_add(payload_len as u32);
        true
    } else {
        false
    }
}

/// How often an endpoint that is not forwarding repeats why. Wall clock,
/// so the cadence does not change with the scheduler's tick, and far apart
/// enough that the report costs a negligible share of the ring it shares
/// with the logs it exists to explain.
const STATUS_PERIOD_MS: u32 = 5_000;

/// Say whether the forwarder is carrying logs, and keep saying so while it
/// is not.
///
/// Both of this module's failures are silent at the collector: an endpoint
/// that never binds and a ring that yields nothing both present as no
/// datagrams arriving. So the state that separates them is reported on
/// every transition, and repeated while the endpoint is unbound — the state
/// someone is waiting on. A forwarder that is working says so once and then
/// leaves the ring to the logs.
unsafe fn report_status(s: &mut LogNetState, sys: &SyscallTable, ready: bool) {
    let now = dev_millis(sys) as u32;
    let changed = ready != s.was_ready;
    let due = !ready && now.wrapping_sub(s.next_status_ms) < 0x8000_0000;
    if !changed && !due {
        return;
    }
    s.was_ready = ready;
    s.next_status_ms = now.wrapping_add(STATUS_PERIOD_MS);

    let mut buf = [0u8; 64];
    let p = buf.as_mut_ptr();
    let mut i = 0usize;
    let head: &[u8] = if ready {
        b"[log_net] forwarding sent="
    } else if s.endpoint.is_disabled() {
        b"[log_net] disabled sent="
    } else {
        b"[log_net] binding sent="
    };
    while i < head.len() {
        *p.add(i) = head[i];
        i += 1;
    }
    i += fmt_u32_raw(p.add(i), s.datagrams_sent);
    dev_log(sys, 3, p, i);
}

/// Frames drained from `net_in` per step. This port is one reader of a
/// fanned `ip.net_out`, so every frame ip hands its other consumer lands
/// here too and the fan stalls the moment this ring is full: the drain
/// must keep pace with the fan's own per-step budget, not with the
/// handful of datagram events the endpoint itself expects.
const DISCARD_PER_STEP: usize = 128;

/// Drain inbound frames on net_in and discard them. The IP module may
/// publish MSG_DG_RX_FROM for our bound endpoint — we don't act on
/// remote control input — and a fanned port carries the other
/// consumer's traffic as well.
unsafe fn discard_net_in(s: &mut LogNetState) {
    if s.net_in_chan < 0 {
        return;
    }
    let sys_ptr = s.syscalls;
    let chan = s.net_in_chan;
    let buf = s.net_buf.as_mut_ptr();
    let mut n = 0;
    while n < DISCARD_PER_STEP {
        let poll = ((*sys_ptr).channel_poll)(chan, 0x01 /* POLL_IN */);
        if poll <= 0 || (poll & 0x01) == 0 {
            break;
        }
        let (msg, _) = net_read_frame(&*sys_ptr, chan, buf, NET_BUF_SIZE);
        if msg == 0 {
            break;
        }
        n += 1;
    }
}

// ============================================================================
// Module interface
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<LogNetState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() {
            return -5;
        }
        if state_size < core::mem::size_of::<LogNetState>() {
            return -6;
        }

        let s = &mut *(state as *mut LogNetState);
        s.init(syscalls as *const SyscallTable);
        s.net_in_chan = in_chan;
        s.net_out_chan = out_chan;

        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut LogNetState);
        if s.syscalls.is_null() {
            return -1;
        }

        let sys = &*s.syscalls;
        // Drive the shared datagram-endpoint lifecycle (bind handshake + backoff);
        // forward only once the endpoint is bound.
        let ready = s.endpoint.poll(
            sys,
            s.net_out_chan,
            s.net_in_chan,
            s.bind_port,
            s.dst_ip,
            s.net_buf.as_mut_ptr(),
            NET_BUF_SIZE,
        );
        if s.endpoint.is_disabled() && s.disabled_warned == 0 {
            let msg = if s.dst_ip == 0 {
                b"[log_net] dst_ip unset; UDP log forwarding disabled".as_ref()
            } else {
                b"[log_net] dst_ip = broadcast rejected; UDP log forwarding disabled".as_ref()
            };
            dev_log(sys, 2, msg.as_ptr(), msg.len());
            s.disabled_warned = 1;
        }
        report_status(s, sys, ready);

        if !ready {
            // The endpoint's own poll reads through net_in while it binds.
            return 0;
        }

        // ── Serving: forward the log ring over the bound endpoint ──
        // Always drain inbound data: net_in is one reader of a fanned port,
        // and a reader that stops draining stops the fan for every reader.
        discard_net_in(s);

        // If a previous chunk couldn't be sent (channel full), retry
        // it now before draining new bytes from the ring — otherwise
        // the ring tail advances and we leak log data on the floor.
        if s.pending_len > 0 {
            let len = s.pending_len as usize;
            if emit_datagram(s, s.chunk.as_ptr(), len) {
                s.pending_len = 0;
            } else {
                // Still can't write. Wait for the downstream channel
                // to drain. New ring bytes accumulate in-place and
                // are handled by the ring's own drop-new policy.
                // Blocked on downstream capacity → Waiting: do NOT heat
                // the pacer (a channel-drain event wakes us); the held
                // data is best-effort telemetry. Forwarding itself
                // returns Burst below, so the
                // hot path is already covered.
                dev_report_step_effect(&*s.syscalls, step_effect::WAITING);
                return 0;
            }
        }

        // Pace. A step that is not due emits nothing and leaves the
        // ring alone, so the backlog stays in the ring rather than
        // being staged here and lost to a full outbound queue.
        if s.send_stride > 0 {
            if s.since_send < s.send_stride {
                s.since_send += 1;
                return 0;
            }
            s.since_send = 0;
        }

        // Drain up to CHUNK_SIZE bytes from the ring.
        let sys_ptr = s.syscalls;
        let chunk_ptr = s.chunk.as_mut_ptr();
        let ret = ((*sys_ptr).provider_call)(-1, LOG_RING_DRAIN, chunk_ptr, CHUNK_SIZE);
        if ret <= 0 {
            return 0;
        }
        let len = (ret as u32) & 0xFFFF;
        let dropped = ((ret as u32) >> 16) & 0xFFFF;

        // If drops happened, emit a marker datagram so viewers know
        // there is a gap. Hex (4-bit shift) encoding avoids runtime
        // division, which RP2350 PIC modules cannot link. Marker is
        // fire-and-forget — if the channel is full, the marker is
        // dropped and the main chunk still goes into pending_len.
        if dropped > 0 {
            let mut mark = [0u8; 40];
            let prefix = b"[log_net: dropped 0x";
            let mut pos = 0usize;
            while pos < prefix.len() {
                mark[pos] = prefix[pos];
                pos += 1;
            }
            let hex = b"0123456789abcdef";
            let mut shift: i32 = 12;
            while shift >= 0 {
                let nib = ((dropped >> shift as u32) & 0xF) as usize;
                mark[pos] = hex[nib];
                pos += 1;
                shift -= 4;
            }
            let suffix = b" bytes]\n";
            let mut k = 0usize;
            while k < suffix.len() && pos < mark.len() {
                mark[pos] = suffix[k];
                pos += 1;
                k += 1;
            }
            emit_datagram(s, mark.as_ptr(), pos);
        }

        if len > 0 {
            if !emit_datagram(s, chunk_ptr, len as usize) {
                // Hold the chunk across ticks until the channel
                // accepts it. No data is lost.
                s.pending_len = len as u16;
            }
            return 2;
        }

        0
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/runtime/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/runtime/wasm_entry.rs");
