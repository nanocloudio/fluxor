//! exchange_poster — framed-payload → exchange-request adapter.
//!
//! Sits between the `otel` export engine and an exchange-contract request
//! client (wave's `http` in exchange mode, or any provider of that surface):
//! each framed body read from `payload` becomes one `MSG_PUBLISH` whose
//! request record is `[method u8][path_len u16 LE][body_len u16 LE][path…]
//! [body…]` (the exchange request-record framing), and the correlated
//! `MSG_REPLY` maps to one `otel.delivery` status byte. See `manifest.toml`
//! for the port and mapping contract.
//!
//! One request in flight at a time, matching the exchange client's own
//! concurrency model. A new payload arriving while one is in flight replaces
//! it (the producer's resend already decided the old batch's fate); a reply
//! for a superseded corr is ignored.
//!
//! # Parameters
//!
//! | Tag | Name    | Type | Default        | Description                        |
//! |-----|---------|------|----------------|------------------------------------|
//! | 1   | path    | str  | `/v1/metrics`  | Request path                       |
//! | 2   | method  | u8   | 3 (POST)       | `wire::method` verb code           |

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
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

use abi::contracts::exchange as ex;
use abi::contracts::telemetry as tlm;

// ============================================================================
// Constants
// ============================================================================

/// Body ceiling: the exchange payload ceiling minus this adapter's request
/// record head. A larger framed payload is refused with a permanent DROP —
/// fragmenting one encoded document would corrupt it, and the producer's
/// encoding choice (compact protobuf, not JSON) is the actual fix.
const REQ_HEAD: usize = 1 + 2 + 2;
const MAX_PATH: usize = 128;
const BODY_MAX: usize = ex::PAYLOAD_MAX - REQ_HEAD - MAX_PATH;

/// Publish frame scratch: channel envelope + publish overhead + key + record.
const KEY: &[u8] = b"otel";
const PUB_BUF: usize =
    NET_FRAME_HDR + ex::PUBLISH_OVERHEAD + KEY.len() + REQ_HEAD + MAX_PATH + BODY_MAX;

/// Inbound frame scratch (payload reads and reply reads share it — the two
/// never overlap: a payload is adopted before the next drain, and a reply is
/// consumed within the step that read it).
const IN_BUF: usize = NET_FRAME_HDR + ex::PUBLISH_OVERHEAD + ex::KEY_MAX + ex::PAYLOAD_MAX;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct PosterState {
    syscalls: *const SyscallTable,
    payload_chan: i32,
    publish_chan: i32,
    reply_chan: i32,
    delivery_chan: i32,

    /// Request path (param 1).
    path: [u8; MAX_PATH],
    path_len: u16,
    /// `wire::method` verb code (param 2; default 3 = POST).
    method: u8,

    /// Correlation of the publish in flight; `0` = idle (the contract
    /// reserves 0, so it can mean idle here too).
    corr: u64,
    /// Monotonic corr source; skips 0 on wrap.
    next_corr: u64,
    /// The composed publish frame awaiting (further) acceptance by the
    /// channel: `pub_len` bytes, `pub_sent` already taken.
    pub_len: u32,
    pub_sent: u32,
    pub_buf: [u8; PUB_BUF],
    /// Inbound scratch.
    in_buf: [u8; IN_BUF],
}

impl PosterState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.payload_chan = -1;
        self.publish_chan = -1;
        self.reply_chan = -1;
        self.delivery_chan = -1;
        self.path = [0; MAX_PATH];
        let default = b"/v1/metrics";
        self.path[..default.len()].copy_from_slice(default);
        self.path_len = default.len() as u16;
        self.method = 3; // POST
        self.corr = 0;
        self.next_corr = 1;
        self.pub_len = 0;
        self.pub_sent = 0;
    }
}

// ============================================================================
// Parameters
// ============================================================================

mod params_def {
    use super::PosterState;
    use super::SCHEMA_MAX;
    use super::{p_u8, MAX_PATH};

    define_params! {
        PosterState;
        1, path, str, 0 => |s, d, len| {
            let n = len.min(MAX_PATH);
            let mut i = 0usize;
            while i < n {
                s.path[i] = *d.add(i);
                i += 1;
            }
            if n > 0 {
                s.path_len = n as u16;
            }
        };
        2, method, u8, 3 => |s, d, len| { s.method = p_u8(d, len, 0, 3); };
    }
}

// ============================================================================
// Steps
// ============================================================================

/// Send one framed delivery status byte to the engine's backchannel.
unsafe fn send_delivery(s: &mut PosterState, status: u8) {
    let sys = &*s.syscalls;
    let byte = [status];
    let mut scratch = [0u8; NET_FRAME_HDR + 1];
    let _ = net_write_frame(
        sys,
        s.delivery_chan,
        0x01,
        byte.as_ptr(),
        1,
        scratch.as_mut_ptr(),
        scratch.len(),
    );
}

/// Drain replies; a reply for the corr in flight resolves it into a delivery
/// status. Stale corrs (a superseded batch) are ignored.
unsafe fn step_replies(s: &mut PosterState) {
    let sys = &*s.syscalls;
    loop {
        let poll = (sys.channel_poll)(s.reply_chan, POLL_IN);
        if poll <= 0 || (poll as u32) & POLL_IN == 0 {
            return;
        }
        let (_msg, len) = net_read_frame(sys, s.reply_chan, s.in_buf.as_mut_ptr(), IN_BUF);
        if len == 0 {
            return;
        }
        let Some(reply) = ex::Reply::decode(&s.in_buf[NET_FRAME_HDR..NET_FRAME_HDR + len]) else {
            continue;
        };
        if s.corr == 0 || reply.corr != s.corr {
            continue;
        }
        // Mapping per the manifest: OK → delivered; UNROUTABLE (the exchange
        // itself failed — connect refused, link down mid-flight) → retry;
        // UPSTREAM (the peer's own status code, carried u16 LE in the reply
        // payload when the client runs `surface_status`) → retry for the
        // transient family (5xx and 429, the OTLP spec's retryables), drop
        // for the rest; everything else (OVERSIZE included) → permanent drop.
        let status = match reply.status {
            ex::STATUS_OK => tlm::DELIVERY_DELIVERED,
            ex::REFUSE_UNROUTABLE => tlm::DELIVERY_RETRY,
            ex::REFUSE_UPSTREAM => {
                let code = if reply.payload.len() >= 2 {
                    u16::from_le_bytes([reply.payload[0], reply.payload[1]])
                } else {
                    0
                };
                if code >= 500 || code == 429 {
                    tlm::DELIVERY_RETRY
                } else {
                    tlm::DELIVERY_DROP
                }
            }
            _ => tlm::DELIVERY_DROP,
        };
        s.corr = 0;
        s.pub_len = 0;
        s.pub_sent = 0;
        send_delivery(s, status);
    }
}

/// Push the pending publish frame; whole-frame writes only (the channel takes
/// a record atomically or refuses it).
unsafe fn step_send(s: &mut PosterState) {
    if s.pub_len == 0 || s.pub_sent >= s.pub_len {
        return;
    }
    let sys = &*s.syscalls;
    let poll = (sys.channel_poll)(s.publish_chan, POLL_OUT);
    if poll <= 0 || (poll as u32) & POLL_OUT == 0 {
        return;
    }
    let len = s.pub_len as usize;
    if (sys.channel_write)(s.publish_chan, s.pub_buf.as_ptr(), len) == len as i32 {
        s.pub_sent = s.pub_len;
    }
}

/// Adopt the next framed payload as a publish, when idle (or supersede a
/// batch the producer has already re-sent past).
unsafe fn step_payload(s: &mut PosterState) {
    let sys = &*s.syscalls;
    // Hold while a composed frame is still leaving; the producer's retention
    // machinery paces itself on the delivery backchannel.
    if s.pub_len != 0 && s.pub_sent < s.pub_len {
        return;
    }
    let poll = (sys.channel_poll)(s.payload_chan, POLL_IN);
    if poll <= 0 || (poll as u32) & POLL_IN == 0 {
        return;
    }
    let (_msg, body_len) = net_read_frame(sys, s.payload_chan, s.in_buf.as_mut_ptr(), IN_BUF);
    if body_len == 0 {
        return;
    }
    if body_len > BODY_MAX {
        // One document cannot be fragmented; permanent, reported, and the
        // producer's encoding choice is the fix (see BODY_MAX).
        send_delivery(s, tlm::DELIVERY_DROP);
        return;
    }

    let corr = s.next_corr;
    s.next_corr = if s.next_corr == u64::MAX { 1 } else { s.next_corr + 1 };

    // Request record: [method][path_len][body_len][path][body].
    let plen = s.path_len as usize;
    let rec_len = REQ_HEAD + plen + body_len;
    let mut rec = [0u8; REQ_HEAD + MAX_PATH];
    rec[0] = s.method;
    rec[1..3].copy_from_slice(&(plen as u16).to_le_bytes());
    rec[3..5].copy_from_slice(&(body_len as u16).to_le_bytes());
    rec[REQ_HEAD..REQ_HEAD + plen].copy_from_slice(&s.path[..plen]);

    // Compose [MSG_PUBLISH][len][Publish…] in place, writing the publish
    // fields manually — the contract's `Publish::encode` takes one contiguous
    // payload, and the body sits in `in_buf`; a bounce copy through a
    // PAYLOAD_MAX stack buffer would be the largest allocation in the module
    // for no purpose. Field order and widths mirror `exchange.rs::Publish`.
    let payload_len = rec_len;
    let publish_len = ex::PUBLISH_OVERHEAD + KEY.len() + payload_len;
    let total = NET_FRAME_HDR + publish_len;
    if total > PUB_BUF {
        send_delivery(s, tlm::DELIVERY_DROP);
        return;
    }
    let b = &mut s.pub_buf;
    b[0] = ex::MSG_PUBLISH;
    b[1..3].copy_from_slice(&(publish_len as u16).to_le_bytes());
    let mut p = NET_FRAME_HDR;
    b[p..p + 8].copy_from_slice(&corr.to_le_bytes());
    p += 8;
    b[p] = 0; // flags
    p += 1;
    b[p..p + 2].copy_from_slice(&(KEY.len() as u16).to_le_bytes());
    p += 2;
    b[p..p + 2].copy_from_slice(&(payload_len as u16).to_le_bytes());
    p += 2;
    b[p..p + KEY.len()].copy_from_slice(KEY);
    p += KEY.len();
    b[p..p + REQ_HEAD + plen].copy_from_slice(&rec[..REQ_HEAD + plen]);
    p += REQ_HEAD + plen;
    b[p..p + body_len].copy_from_slice(&s.in_buf[NET_FRAME_HDR..NET_FRAME_HDR + body_len]);
    p += body_len;

    s.corr = corr;
    s.pub_len = p as u32;
    s.pub_sent = 0;
    step_send(s);
}

// ============================================================================
// Module entry points
// ============================================================================

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<PosterState>() as u32
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
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
        if state.is_null() || state_size < core::mem::size_of::<PosterState>() {
            return -5;
        }
        let s = &mut *(state as *mut PosterState);
        s.init(syscalls as *const SyscallTable);
        let sys = &*s.syscalls;
        s.payload_chan = in_chan; // in[0]
        s.publish_chan = out_chan; // out[0]
        s.reply_chan = dev_channel_port(sys, 0, 1); // in[1]
        s.delivery_chan = dev_channel_port(sys, 1, 1); // out[1]

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
        let s = &mut *(state as *mut PosterState);
        step_replies(s);
        step_send(s);
        step_payload(s);
        0
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
pub extern "C" fn module_destroy(_state: *mut u8) {}
