//! exchange_poster — framed payloads in, exchange requests out.
//!
//! Sits between the `otel` export engine and any provider of the exchange
//! contract (`modules/sdk/contracts/exchange.rs`), as its requester: each
//! framed body read from `payload` becomes one request HEAD on `request_out`
//! carrying the whole batch inline, and the terminal response for it on
//! `response_in` maps to one `otel.delivery` status byte. See
//! `manifest.toml` for the ports and the mapping.
//!
//! One exchange is in flight at a time. A new payload arriving while one is
//! in flight replaces it — the producer's resend has already decided the old
//! batch's fate — and the superseded exchange is aborted, so the provider
//! stops working on an answer nobody will read.
//!
//! # Parameters
//!
//! | Tag | Name         | Type | Default       | Description                        |
//! |-----|--------------|------|---------------|------------------------------------|
//! | 1   | path         | str  | `/v1/metrics` | Request target                     |
//! | 2   | method       | u8   | 3 (POST)      | Exchange method constant           |
//! | 3   | content_type | str  | (none)        | `content-type` header of a request |

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
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

use abi::contracts::exchange as ex;
use abi::contracts::telemetry as tlm;

// ============================================================================
// Constants
// ============================================================================

/// The longest request target the `path` param holds.
const MAX_PATH: usize = 128;
/// The longest `content-type` value the param holds.
const MAX_CONTENT_TYPE: usize = 96;
/// The header block a content type becomes: `content-type: <value>\r\n`.
const CT_NAME: &[u8] = b"content-type: ";
const MAX_HEADERS: usize = CT_NAME.len() + MAX_CONTENT_TYPE + 2;

/// Response-body bytes granted with each request. The poster reads only the
/// status, but a provider answering a sink-like endpoint usually has a short
/// body to go with it; granting one record's room lets that arrive inside the
/// response HEAD instead of leaving an exchange waiting on credit.
const RESP_CREDIT: u32 = ex::BODY_MAX as u32;

/// Inbound scratch, shared by payload reads and response reads — the two
/// never overlap: a payload is copied into the request record as it is
/// adopted, and a response record is consumed within the step that read it.
const IN_BUF: usize = NET_FRAME_HDR + ex::PAYLOAD_MAX + ex::KEY_MAX;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct PosterState {
    syscalls: *const SyscallTable,
    payload_chan: i32,
    request_chan: i32,
    response_chan: i32,
    delivery_chan: i32,

    /// Request target (param 1).
    path: [u8; MAX_PATH],
    path_len: u16,
    /// Exchange method constant (param 2; default POST).
    method: u8,
    /// The header block every request carries, `hdr_len` bytes (param 3).
    headers: [u8; MAX_HEADERS],
    hdr_len: u16,

    /// Counter the exchange in flight was named from; `0` = idle.
    corr: u64,
    /// Monotonic counter source; skips 0 on wrap.
    next_corr: u64,
    /// Exchanges owed an ABORT, `0` for an empty entry: one superseded by a
    /// newer batch, one whose answer is still streaming after its status was
    /// read. Each is sent before any further request.
    aborts: [u64; 2],

    /// The composed request HEAD, held while the channel has no room.
    req_outbox: ExchangeOutbox,
    req_buf: [u8; ex::RECORD_MAX],
    /// The composed ABORT, held likewise.
    abort_outbox: ExchangeOutbox,
    abort_buf: [u8; ex::HDR + 1],
    /// Inbound scratch.
    in_buf: [u8; IN_BUF],
}

impl PosterState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.payload_chan = -1;
        self.request_chan = -1;
        self.response_chan = -1;
        self.delivery_chan = -1;
        self.path = [0; MAX_PATH];
        let default = b"/v1/metrics";
        self.path[..default.len()].copy_from_slice(default);
        self.path_len = default.len() as u16;
        self.method = ex::METHOD_POST;
        self.headers = [0; MAX_HEADERS];
        self.hdr_len = 0;
        self.corr = 0;
        self.next_corr = 1;
        self.aborts = [0; 2];
        self.req_outbox = ExchangeOutbox::new();
        self.abort_outbox = ExchangeOutbox::new();
    }

    /// Whether the request in flight has left: once it has, the provider
    /// owns an answer for it.
    fn request_sent(&self) -> bool {
        self.corr != 0 && !self.req_outbox.holding()
    }
}

// ============================================================================
// Parameters
// ============================================================================

mod params_def {
    use super::PosterState;
    use super::SCHEMA_MAX;
    use super::{p_u8, CT_NAME, MAX_CONTENT_TYPE, MAX_PATH};

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
        3, content_type, str, 0 => |s, d, len| {
            let n = len.min(MAX_CONTENT_TYPE);
            if n > 0 {
                let mut at = 0usize;
                let mut i = 0usize;
                while i < CT_NAME.len() {
                    s.headers[at] = CT_NAME[i];
                    at += 1;
                    i += 1;
                }
                i = 0;
                while i < n {
                    s.headers[at] = *d.add(i);
                    at += 1;
                    i += 1;
                }
                s.headers[at] = b'\r';
                s.headers[at + 1] = b'\n';
                s.hdr_len = (at + 2) as u16;
            }
        };
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

/// The delivery a terminal response status means: 2xx is delivered; 429 and
/// every 5xx — the OTLP retryable family, which includes the 502 and 504 a
/// provider raises when the collector is unreachable or silent — retry;
/// anything else is permanent, because retrying a refusal wedges the pipe.
fn delivery_for_status(status: u16) -> u8 {
    match status {
        200..=299 => tlm::DELIVERY_DELIVERED,
        429 | 500..=599 => tlm::DELIVERY_RETRY,
        _ => tlm::DELIVERY_DROP,
    }
}

/// The delivery a provider's ABORT means: a batch the provider could not
/// carry is permanent, an exchange it lost partway is worth repeating.
fn delivery_for_abort(reason: u8) -> u8 {
    match reason {
        ex::abort::TOO_LARGE | ex::abort::MALFORMED | ex::abort::CREDIT_OVERRUN => {
            tlm::DELIVERY_DROP
        }
        _ => tlm::DELIVERY_RETRY,
    }
}

/// Resolve the exchange in flight with `status`.
unsafe fn resolve(s: &mut PosterState, status: u8) {
    s.corr = 0;
    send_delivery(s, status);
}

/// Owe an ABORT for exchange `corr`: the poster has stopped wanting its
/// answer. There is room for every abort the poster can owe at once — one
/// superseded batch and one streaming answer — because a further payload is
/// not adopted while any is owed.
fn owe_abort(s: &mut PosterState, corr: u64) {
    if let Some(slot) = s.aborts.iter_mut().find(|c| **c == 0) {
        *slot = corr;
    }
}

/// Whether an ABORT is owed or still leaving.
fn aborts_owed(s: &PosterState) -> bool {
    s.abort_outbox.holding() || s.aborts.iter().any(|&c| c != 0)
}

/// Drain responses. A terminal record for the exchange in flight resolves it
/// into a delivery status; records for any other id (a superseded batch) are
/// ignored. LINK DOWN makes the exchange in flight unknowable: the batch is
/// handed back for retry, which is how this requester issues it again.
unsafe fn step_responses(s: &mut PosterState) {
    let sys = &*s.syscalls;
    loop {
        let poll = (sys.channel_poll)(s.response_chan, POLL_IN);
        if poll <= 0 || (poll as u32) & POLL_IN == 0 {
            return;
        }
        let n = (sys.channel_read)(s.response_chan, s.in_buf.as_mut_ptr(), IN_BUF);
        if n <= 0 {
            return;
        }
        let Some(record) = ex::parse_response(&s.in_buf[..n as usize]) else {
            continue;
        };
        let live = ex::ExchangeId::from_u64(s.corr);
        let open = s.corr != 0;
        // What the record decides, read out before acting on it: the record
        // borrows the scratch the state also owns.
        let (delivery, streaming) = match record {
            ex::Record::Link { state } if state == ex::link::DOWN && s.request_sent() => {
                (Some(tlm::DELIVERY_RETRY), false)
            }
            // The status decides; the body is not read.
            ex::Record::Head(head) if open && head.id == live => (
                Some(delivery_for_status(head.status)),
                head.flags & ex::flag::MORE != 0,
            ),
            ex::Record::Abort { id, reason } if open && id == live => {
                (Some(delivery_for_abort(reason)), false)
            }
            _ => (None, false),
        };
        if streaming {
            // A response still streaming is ended from this side, so the
            // provider stops sending what nobody will take.
            owe_abort(s, s.corr);
        }
        if let Some(status) = delivery {
            resolve(s, status);
        }
    }
}

/// Place what is owed: every ABORT, then the request.
unsafe fn step_send(s: &mut PosterState) {
    let sys = &*s.syscalls;
    loop {
        if !s.abort_outbox.flush(sys, s.request_chan, &s.abort_buf) {
            return;
        }
        let Some(slot) = s.aborts.iter().position(|&c| c != 0) else {
            break;
        };
        let id = ex::ExchangeId::from_u64(s.aborts[slot]);
        s.aborts[slot] = 0;
        if let Some(n) = ex::write_abort(&id, ex::abort::UNDELIVERABLE, &mut s.abort_buf) {
            s.abort_outbox.send(sys, s.request_chan, &s.abort_buf, n);
        }
    }
    s.req_outbox.flush(sys, s.request_chan, &s.req_buf);
}

/// Adopt the next framed payload as a request, when nothing is waiting to
/// leave. A batch in flight is superseded: its exchange is aborted, and an
/// answer to it is no longer read.
unsafe fn step_payload(s: &mut PosterState) {
    let sys = &*s.syscalls;
    // Hold while a composed record is still leaving; the producer's retention
    // machinery paces itself on the delivery backchannel.
    if s.req_outbox.holding() || aborts_owed(s) {
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

    let corr = s.next_corr;
    let plen = s.path_len as usize;
    let hlen = s.hdr_len as usize;
    let head = ex::RequestHead {
        id: ex::ExchangeId::from_u64(corr),
        flags: 0,
        method: s.method,
        target: &s.path[..plen],
        headers: &s.headers[..hlen],
        peer: &[],
        resp_credit: RESP_CREDIT,
        body: &s.in_buf[NET_FRAME_HDR..NET_FRAME_HDR + body_len],
    };
    // A batch is one encoded document and travels as one record. One that
    // does not fit is refused, permanently and reported: the producer's
    // encoding choice (compact protobuf, not JSON) is the fix, and a resend
    // would not fit either.
    let Some(n) = ex::write_request_head(&head, &mut s.req_buf) else {
        send_delivery(s, tlm::DELIVERY_DROP);
        return;
    };
    s.next_corr = if corr == u64::MAX { 1 } else { corr + 1 };

    if s.request_sent() {
        owe_abort(s, s.corr);
    }
    s.corr = corr;
    // Held rather than sent here: an owed ABORT goes first.
    s.req_outbox.hold(n);
    step_send(s);
}

// ============================================================================
// Module entry points
// ============================================================================

declare_module_state_bytes!(PosterState);

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
        s.request_chan = out_chan; // out[0]
        s.response_chan = dev_channel_port(sys, 0, 1); // in[1]
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
        step_send(s);
        step_responses(s);
        step_send(s);
        step_payload(s);
        0
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
pub extern "C" fn module_destroy(_state: *mut u8) {}
