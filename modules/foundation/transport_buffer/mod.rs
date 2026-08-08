//! transport_buffer — a transport-agnostic byte-egress buffer.
//!
//! The stream-buffer stage between an encoder (e.g. `otel.export`) and the wire:
//! it drains length-framed payloads from its `payload` input and forwards each to
//! a selected transport, holding one in-flight payload against backpressure
//! (resuming a partial write where the sink allows). One generic buffer core; the
//! transport is a capability chosen by the `transport` param, not a module per
//! protocol (`rfc_observability_surface.md` §5.5).
//!
//! Transports:
//!   - `udp` (0)  — via the shared `datagram_endpoint` core over the ip datagram
//!     surface: it owns the bind lifecycle and the addressed send
//!     (the same core `log_net` uses). Needs the net channels wired:
//!     in[1]=net_in, out[0]=net_out; params dst_ip / dst_port /
//!     bind_port.
//!   - `uart` (1) — via the raw `SERIAL_WRITE` sink (debug UART / USB-CDC). No
//!     network, no addressing; net channels left unwired.
//!
//! A stream transport (TCP) or downstream client (HTTP/gRPC) is a new `send`
//! arm — and, if datagram-shaped, reuses `datagram_endpoint` — not a new module.
//!
//! # Wiring
//!
//!   otel.export        →  transport_buffer.payload   (framed bytes to send)
//!   ip.net_out         →  transport_buffer.net_in     (udp only)
//!   transport_buffer.net_out →  ip.net_in             (udp only)
//!
//! # Framing
//!
//! The `payload` port carries the `net_proto` frame `[msg_type][len: u16 LE]
//! [payload]` (`sdk/runtime/net.rs`): one frame per record, `msg_type` ignored.
//!
//! # Parameters
//!
//! | Tag | Name      | Type | Default | Description                              |
//! |-----|-----------|------|---------|------------------------------------------|
//! | 1   | dst_ip    | u32  | 0       | udp: destination IP (LE); 0/broadcast = dormant. |
//! | 2   | dst_port  | u16  | 4317    | udp: destination port.                   |
//! | 3   | bind_port | u16  | 4316    | udp: local source port.                  |
//! | 4   | transport | u8   | 0 (udp) | 0 = udp, 1 = uart.                        |

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset. unreachable_patterns: defensive `_ => Error` arms in enum state-machine matches are intentional — adding a new variant should not silently bypass the error path"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::kernel_abi::SERIAL_WRITE;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");
// Shared UDP datagram-endpoint lifecycle + send (also used by `log_net`).
include!("../../sdk/cores/datagram_endpoint.rs");

// ============================================================================
// Constants
// ============================================================================

/// Transport selector (`transport` param).
const TRANSPORT_UDP: u8 = 0;
const TRANSPORT_UART: u8 = 1;

/// Largest single payload buffered / forwarded. Holds an `otel(fxtl-compact)`
/// batch comfortably while staying inside a safe UDP payload (no fragmentation);
/// UART has no MTU, so this only bounds the retain buffer there. A larger inbound
/// frame is truncated frame-aligned (tail dropped) rather than desyncing the FIFO.
const PAYLOAD_MAX: usize = 1400;

/// Frame assembly / read scratch: NET_FRAME_HDR + DG_V4_PREFIX + payload.
const NET_BUF_SIZE: usize = NET_FRAME_HDR + DG_V4_PREFIX + PAYLOAD_MAX + 8;

/// Bound on payloads sent per step so a flooded input can't starve the tick.
const MAX_SEND_PER_STEP: u32 = 32;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct TransportBufferState {
    syscalls: *const SyscallTable,
    payload_in_chan: i32,
    net_in_chan: i32,
    net_out_chan: i32,

    /// Selected transport (`TRANSPORT_UDP` | `TRANSPORT_UART`).
    transport: u8,
    /// One-shot flag so a disabled udp endpoint warns only once.
    disabled_warned: u8,

    // udp destination / bind (parsed from params, passed to `endpoint`).
    dst_ip: u32,
    dst_port: u16,
    bind_port: u16,
    /// Shared datagram-endpoint lifecycle + send (udp transport only).
    endpoint: DatagramEndpoint,

    /// A payload read from `payload_in` but not yet fully accepted by the sink
    /// (`pending_off` bytes sent so far). `pending_len == 0` means none held. The
    /// buffer resumes from `pending_off` — a serial sink can partial-accept; a
    /// datagram is atomic (off stays 0 until the whole payload goes out).
    pending_len: u16,
    pending_off: u16,

    /// Stats (informational; readable via memory dump).
    frames_sent: u32,

    /// Held payload awaiting (further) send.
    pending: [u8; PAYLOAD_MAX],
    /// Frame assembly / read scratch (bind frames, net_in drain, datagram send).
    net_buf: [u8; NET_BUF_SIZE],
}

impl TransportBufferState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.payload_in_chan = -1;
        self.net_in_chan = -1;
        self.net_out_chan = -1;
        self.transport = TRANSPORT_UDP;
        self.disabled_warned = 0;
        self.dst_ip = 0;
        self.dst_port = 4317;
        self.bind_port = 4316;
        self.endpoint = DatagramEndpoint::new();
        self.pending_len = 0;
        self.pending_off = 0;
        self.frames_sent = 0;
    }
}

// ============================================================================
// Parameters
// ============================================================================

mod params_def {
    use super::p_u16;
    use super::p_u32;
    use super::p_u8;
    use super::TransportBufferState;
    use super::SCHEMA_MAX;

    define_params! {
        TransportBufferState;

        1, dst_ip, u32, 0
            => |s, d, len| { s.dst_ip = p_u32(d, len, 0, 0); };

        2, dst_port, u16, 4317
            => |s, d, len| { s.dst_port = p_u16(d, len, 0, 4317); };

        3, bind_port, u16, 4316
            => |s, d, len| { s.bind_port = p_u16(d, len, 0, 4316); };

        4, transport, u8, 0
            => |s, d, len| { s.transport = p_u8(d, len, 0, 0); };
    }
}

// ============================================================================
// Transport `send` — the only per-protocol code
// ============================================================================

/// Send as much of the held payload (from `pending_off`) as the selected
/// transport accepts NOW. Returns the number of payload bytes accepted this call
/// — `0` if the sink is not ready. UDP is atomic (whole payload or nothing, via
/// the shared `datagram_endpoint` core); UART may partial-accept (buffer resumes).
unsafe fn send_one(s: &mut TransportBufferState) -> usize {
    let off = s.pending_off as usize;
    let len = s.pending_len as usize;
    let remaining = len - off;
    let sys = &*s.syscalls;
    if s.transport == TRANSPORT_UART {
        let n = (sys.provider_call)(-1, SERIAL_WRITE, s.pending.as_mut_ptr().add(off), remaining);
        if n > 0 {
            n as usize
        } else {
            0
        }
    } else {
        s.endpoint.send_to(
            sys,
            s.net_out_chan,
            s.dst_ip,
            s.dst_port,
            s.pending.as_ptr().add(off),
            remaining,
            s.net_buf.as_mut_ptr(),
            NET_BUF_SIZE,
        )
    }
}

// ============================================================================
// Generic buffer core (transport-blind)
// ============================================================================

/// Send the held payload (from `pending_off`); advance the offset by what the
/// sink accepted. Returns true iff the whole payload is out (or nothing held);
/// false if the sink took only part / nothing (the remainder stays held).
unsafe fn flush_pending(s: &mut TransportBufferState) -> bool {
    if s.pending_len == 0 {
        return true;
    }
    let accepted = send_one(s);
    s.pending_off += accepted as u16;
    if s.pending_off >= s.pending_len {
        s.frames_sent = s.frames_sent.wrapping_add(1);
        s.pending_len = 0;
        s.pending_off = 0;
        true
    } else {
        false // sink full / partial — hold the remainder for a later step.
    }
}

/// Drain framed payloads from `payload_in`, forwarding each. Any held payload is
/// flushed first; reading stops the moment a send can't complete, so nothing
/// already-read is lost.
unsafe fn pump(s: &mut TransportBufferState) {
    if s.payload_in_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let chan = s.payload_in_chan;

    let mut sent = 0u32;
    while sent < MAX_SEND_PER_STEP {
        if !flush_pending(s) {
            break; // sink not ready — retry next step; nothing lost.
        }
        let (_msg, copied, _payload_len) =
            net_read_frame_aligned(sys, chan, s.net_buf.as_mut_ptr(), NET_BUF_SIZE);
        if copied == 0 {
            break; // no full frame available.
        }
        let take = if copied < PAYLOAD_MAX {
            copied
        } else {
            PAYLOAD_MAX
        };
        core::ptr::copy_nonoverlapping(
            s.net_buf.as_ptr().add(NET_FRAME_HDR),
            s.pending.as_mut_ptr(),
            take,
        );
        s.pending_len = take as u16;
        s.pending_off = 0;
        if flush_pending(s) {
            sent += 1;
        } else {
            break; // held for next step.
        }
    }
}

/// Drain any inbound frame on net_in and discard (udp): ip may publish
/// MSG_DG_RX_FROM for our bound endpoint — this is a one-way sender.
unsafe fn discard_net_in(s: &mut TransportBufferState) {
    if s.net_in_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let chan = s.net_in_chan;
    let poll = (sys.channel_poll)(chan, 0x01 /* POLL_IN */);
    if poll > 0 && (poll & 0x01) != 0 {
        let buf = s.net_buf.as_mut_ptr();
        let _ = net_read_frame_aligned(sys, chan, buf, NET_BUF_SIZE);
    }
}

// ============================================================================
// Module interface
// ============================================================================

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<TransportBufferState>() as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
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
    unsafe {
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() {
            return -5;
        }
        if state_size < core::mem::size_of::<TransportBufferState>() {
            return -6;
        }
        let s = &mut *(state as *mut TransportBufferState);
        s.init(syscalls as *const SyscallTable);
        let sys = &*s.syscalls;
        s.payload_in_chan = dev_channel_port(sys, 0, 0); // in[0]: framed payloads
        s.net_in_chan = dev_channel_port(sys, 0, 1); // in[1]: frames from ip (udp)
        s.net_out_chan = dev_channel_port(sys, 1, 0); // out[0]: frames to ip (udp)

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

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut TransportBufferState);
        if s.syscalls.is_null() {
            return -1;
        }

        if s.transport == TRANSPORT_UART {
            // No endpoint to bind — the serial sink is always available.
            pump(s);
            return 0;
        }

        // UDP: drive the shared datagram-endpoint lifecycle; forward once bound.
        let sys = &*s.syscalls;
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
            let msg = b"[transport_buffer] udp dst_ip unset/broadcast; forwarding disabled";
            dev_log(sys, 2, msg.as_ptr(), msg.len());
            s.disabled_warned = 1;
        }
        if ready {
            discard_net_in(s);
            pump(s);
        }
        0
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets.
include!("../../sdk/runtime/wasm_entry.rs");
