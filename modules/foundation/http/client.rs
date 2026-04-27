//! HTTP client — connects to a peer, issues a request, streams the
//! response body to the module's data output channel.
//!
//! State, request/response state machine, and outbound request
//! formatting all live here. Pure-byte parse and build helpers come
//! from `super::wire::h1`; framing constants come from
//! `super::connection`.

use super::connection::{
    NET_BUF_SIZE, NET_CMD_CLOSE, NET_CMD_CONNECT, NET_CMD_SEND, NET_MSG_CLOSED, NET_MSG_CONNECTED,
    NET_MSG_DATA, NET_MSG_ERROR,
};
use super::wire_h1 as h1;
use super::HttpState;
use super::{
    dev_channel_port, dev_log, dev_millis, net_read_frame, net_write_frame, E_AGAIN,
    NET_FRAME_HDR, POLL_IN, POLL_OUT, SOCK_TYPE_STREAM,
};

// ── Sizes / capacities ─────────────────────────────────────────────────────

pub(crate) const RECV_BUF_SIZE: usize = 2048;
pub(crate) const MAX_PATH_LEN: usize = 128;
pub(crate) const REQUEST_BUF_SIZE: usize = 256;
pub(crate) const REQUEST_BODY_SIZE: usize = 256;

const CONNECT_TIMEOUT_MS: u64 = 10_000;

// ── Error codes returned from step ─────────────────────────────────────────

pub(crate) const E_NET_FAILED: i32 = -30;
pub(crate) const E_CONNECT_FAILED: i32 = -31;
pub(crate) const E_SEND_FAILED: i32 = -32;
pub(crate) const E_WRITE_FAILED: i32 = -34;

// ── Phase machine ─────────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Phase {
    Init = 0,
    Connecting = 1,
    WaitConnect = 2,
    SendRequest = 3,
    WaitSend = 4,
    RecvHeaders = 5,
    RecvBody = 6,
    Writing = 7,
    Done = 8,
    Error = 255,
}

// ── Client state ──────────────────────────────────────────────────────────

#[repr(C)]
pub(crate) struct ClientState {
    pub(crate) conn_id: u8,
    _conn_pad: [u8; 3],
    pub(crate) out_chan: i32,
    /// `in[1]` — when wired (≥ 0), the WS client reads outgoing
    /// payloads from this channel and emits them as WS TEXT frames.
    /// Channel HUP triggers a clean WS CLOSE. Unwired (−1) keeps the
    /// one-shot `request_body` behavior.
    pub(crate) data_in_chan: i32,

    pub(crate) host_ip: u32,
    pub(crate) port: u16,
    pub(crate) path_len: u16,

    pub(crate) phase: Phase,
    pub(crate) headers_done: u8,
    /// Wire protocol — 0 = HTTP/1.1, 1 = HTTP/2 cleartext (h2c).
    /// Read by `mod.rs::module_step` to pick the right state machine.
    pub(crate) protocol: u8,
    /// HTTP/2 client sub-state. Interpreted as `client_h2::H2Phase` when
    /// `protocol == 1`; ignored otherwise.
    pub(crate) h2_phase: u8,
    /// 1 = bootstrap a WebSocket session (RFC 8441 extended CONNECT)
    /// after the h2 handshake instead of issuing a GET/POST. Only
    /// honored when `protocol == 1`.
    pub(crate) websocket: u8,
    /// WS phase: 0 = haven't sent CLOSE, 1 = CLOSE queued, 2 = peer
    /// CLOSE echo observed → exit on next tick.
    pub(crate) ws_done: u8,
    /// 1 = a connection-level WINDOW_UPDATE should be queued in
    /// `request_buf` once it's free, refilling our recv flow-control
    /// window. Tracked per client (h2 only).
    pub(crate) window_update_pending: u8,

    pub(crate) connect_start_ms: u64,

    pub(crate) pending_offset: u16,
    pub(crate) recv_len: u16,

    pub(crate) content_length: u32,
    pub(crate) bytes_received: u32,

    pub(crate) request_len: u16,
    pub(crate) request_sent: u16,

    /// Optional request body (POST). Empty length means GET.
    pub(crate) request_body_len: u16,
    /// Bytes of the body already framed onto the wire. Used by the h2
    /// client to fragment large bodies across multiple DATA frames.
    pub(crate) request_body_sent: u16,
    /// Connection-level recv flow-control window for h2 (RFC 7540
    /// §6.9.1). Decremented as response DATA frames arrive; refilled
    /// via WINDOW_UPDATE when it crosses the threshold.
    pub(crate) recv_window: i32,

    pub(crate) path: [u8; MAX_PATH_LEN],
    pub(crate) recv_buf: [u8; RECV_BUF_SIZE],
    pub(crate) request_buf: [u8; REQUEST_BUF_SIZE],
    pub(crate) request_body: [u8; REQUEST_BODY_SIZE],
}

// ClientState lives inside HttpState, which the kernel allocates as a
// zeroed buffer of `module_state_size()` bytes. `init()` below sets
// only those fields whose default is not zero.

// ── Param parsers ─────────────────────────────────────────────────────────

pub(crate) unsafe fn parse_request_body(s: &mut HttpState, d: *const u8, len: usize) {
    let n = len.min(REQUEST_BODY_SIZE);
    let mut i = 0;
    while i < n {
        s.client.request_body[i] = *d.add(i);
        i += 1;
    }
    s.client.request_body_len = n as u16;
}

// ── Init / post-params ────────────────────────────────────────────────────

pub(crate) unsafe fn init(s: &mut HttpState) {
    s.client.out_chan = -1;
    s.client.data_in_chan = -1;
    s.client.port = 80;
    s.client.phase = Phase::Init;
    // h2 connection-level recv window starts at the spec default.
    s.client.recv_window = 65535;
}

pub(crate) unsafe fn post_params(s: &mut HttpState) {
    let sys = &*s.syscalls;
    s.client.out_chan = dev_channel_port(sys, 1, 1); // out[1]: body data
    s.client.data_in_chan = dev_channel_port(sys, 0, 1); // in[1]: outbound WS payload data

    if s.client.path_len == 0 {
        s.client.path[0] = b'/';
        s.client.path_len = 1;
    }

    log(s, b"[http] client configured");
}

#[inline(always)]
unsafe fn log(s: &HttpState, msg: &[u8]) {
    dev_log(&*s.syscalls, 3, msg.as_ptr(), msg.len());
}

unsafe fn build_request(s: &mut HttpState) {
    let len = h1::write_request_line(
        s.client.request_buf.as_mut_ptr(),
        REQUEST_BUF_SIZE,
        s.client.path.as_ptr(),
        s.client.path_len as usize,
        s.client.host_ip,
    );
    s.client.request_len = len as u16;
    s.client.request_sent = 0;
}

unsafe fn send_close_frame(s: &mut HttpState) {
    if s.client.conn_id == 0 || s.net_out_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let chan = s.net_out_chan;
    let buf = s.net_buf.as_mut_ptr();
    let mut payload = [0u8; 1];
    payload[0] = s.client.conn_id;
    net_write_frame(sys, chan, NET_CMD_CLOSE, payload.as_ptr(), 1, buf, NET_BUF_SIZE);
    s.client.conn_id = 0;
}

// ── Per-tick step machine ──────────────────────────────────────────────────

pub(crate) unsafe fn step(s: &mut HttpState) -> i32 {
    loop {
        match s.client.phase {
            Phase::Init => {
                log(s, b"[http] connecting");
                s.client.phase = Phase::Connecting;
                continue;
            }

            Phase::Connecting => {
                if s.net_out_chan < 0 {
                    s.client.phase = Phase::Error;
                    return E_NET_FAILED;
                }
                let sys = &*s.syscalls;
                let chan = s.net_out_chan;
                let buf = s.net_buf.as_mut_ptr();
                // CMD_CONNECT payload: [sock_type: u8] [ip: u32 LE] [port: u16 LE]
                let mut payload = [0u8; 7];
                payload[0] = SOCK_TYPE_STREAM;
                let ip_bytes = s.client.host_ip.to_le_bytes();
                payload[1] = ip_bytes[0];
                payload[2] = ip_bytes[1];
                payload[3] = ip_bytes[2];
                payload[4] = ip_bytes[3];
                payload[5] = (s.client.port & 0xFF) as u8;
                payload[6] = (s.client.port >> 8) as u8;
                let wrote = net_write_frame(sys, chan, NET_CMD_CONNECT, payload.as_ptr(), 7, buf, NET_BUF_SIZE);
                if wrote == 0 {
                    return 0;
                }
                s.client.connect_start_ms = dev_millis(sys);
                s.client.phase = Phase::WaitConnect;
                return 0;
            }

            Phase::WaitConnect => {
                if s.net_in_chan < 0 {
                    return 0;
                }
                let sys = &*s.syscalls;
                let chan = s.net_in_chan;
                let poll = (sys.channel_poll)(chan, POLL_IN);
                if poll > 0 && (poll as u32 & POLL_IN) != 0 {
                    let buf = s.net_buf.as_mut_ptr();
                    let (msg_type, payload_len) = net_read_frame(sys, chan, buf, NET_BUF_SIZE);
                    if msg_type == NET_MSG_CONNECTED && payload_len >= 1 {
                        s.client.conn_id = *buf.add(NET_FRAME_HDR);
                        log(s, b"[http] connected");
                        build_request(s);
                        s.client.phase = Phase::SendRequest;
                        continue;
                    } else if msg_type == NET_MSG_ERROR {
                        log(s, b"[http] connect error");
                        s.client.phase = Phase::Error;
                        return E_CONNECT_FAILED;
                    }
                }
                if dev_millis(sys).wrapping_sub(s.client.connect_start_ms) >= CONNECT_TIMEOUT_MS {
                    log(s, b"[http] connect timeout");
                    s.client.phase = Phase::Error;
                    return E_CONNECT_FAILED;
                }
                return 0;
            }

            Phase::SendRequest => {
                if s.net_out_chan < 0 {
                    return E_SEND_FAILED;
                }
                let sys = &*s.syscalls;
                let out_chan = s.net_out_chan;
                let conn_id = s.client.conn_id;
                let remaining = (s.client.request_len - s.client.request_sent) as usize;
                let data_ptr = s.client.request_buf.as_ptr().add(s.client.request_sent as usize);

                let max_data = NET_BUF_SIZE - NET_FRAME_HDR - 1;
                let to_send = remaining.min(max_data);
                let scratch = s.net_buf.as_mut_ptr();
                let payload_len = 1 + to_send;
                *scratch = NET_CMD_SEND;
                *scratch.add(1) = (payload_len & 0xFF) as u8;
                *scratch.add(2) = ((payload_len >> 8) & 0xFF) as u8;
                *scratch.add(3) = conn_id;
                core::ptr::copy_nonoverlapping(data_ptr, scratch.add(4), to_send);
                let total = NET_FRAME_HDR + payload_len;
                let written = (sys.channel_write)(out_chan, scratch, total);

                if written < total as i32 {
                    return 0;
                }

                s.client.request_sent += to_send as u16;
                if s.client.request_sent >= s.client.request_len {
                    log(s, b"[http] request sent");
                    s.client.headers_done = 0;
                    s.client.recv_len = 0;
                    s.client.phase = Phase::RecvHeaders;
                }
                return 0;
            }

            Phase::RecvHeaders => {
                if s.net_in_chan < 0 {
                    return 0;
                }
                let sys = &*s.syscalls;
                let chan = s.net_in_chan;
                let poll = (sys.channel_poll)(chan, POLL_IN);
                if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
                    return 0;
                }

                let nbuf = s.net_buf.as_mut_ptr();
                let (msg_type, payload_len) = net_read_frame(sys, chan, nbuf, NET_BUF_SIZE);

                if msg_type == NET_MSG_CLOSED {
                    log(s, b"[http] premature close");
                    s.client.phase = Phase::Done;
                    return 1;
                }

                if msg_type == NET_MSG_DATA && payload_len > 1 {
                    let data_ptr = nbuf.add(NET_FRAME_HDR + 1) as *const u8;
                    let data_len = payload_len - 1;

                    let cur = s.client.recv_len as usize;
                    let space = RECV_BUF_SIZE - cur;
                    let to_copy = data_len.min(space);
                    if to_copy > 0 {
                        core::ptr::copy_nonoverlapping(
                            data_ptr,
                            s.client.recv_buf.as_mut_ptr().add(cur),
                            to_copy,
                        );
                        s.client.recv_len += to_copy as u16;
                    }

                    if let Some(body_start) =
                        h1::find_header_end(&s.client.recv_buf, s.client.recv_len as usize)
                    {
                        let body_len = (s.client.recv_len as usize) - body_start;
                        if body_len > 0 {
                            let buf_ptr = s.client.recv_buf.as_mut_ptr();
                            let mut i = 0;
                            while i < body_len {
                                *buf_ptr.add(i) = *buf_ptr.add(body_start + i);
                                i += 1;
                            }
                            s.client.recv_len = body_len as u16;
                            s.client.pending_offset = 0;
                            s.client.phase = Phase::Writing;
                        } else {
                            s.client.recv_len = 0;
                            s.client.phase = Phase::RecvBody;
                        }
                        log(s, b"[http] headers done");
                        continue;
                    }
                }

                return 0;
            }

            Phase::RecvBody => {
                let sys = &*s.syscalls;
                if s.client.out_chan >= 0 {
                    let poll = (sys.channel_poll)(s.client.out_chan, POLL_OUT);
                    if poll <= 0 || (poll as u32 & POLL_OUT) == 0 {
                        return 0;
                    }
                }

                if s.net_in_chan < 0 {
                    return 0;
                }
                let chan = s.net_in_chan;
                let poll = (sys.channel_poll)(chan, POLL_IN);
                if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
                    return 0;
                }

                let nbuf = s.net_buf.as_mut_ptr();
                let (msg_type, payload_len) = net_read_frame(sys, chan, nbuf, NET_BUF_SIZE);

                if msg_type == NET_MSG_CLOSED {
                    log(s, b"[http] transfer done");
                    s.client.phase = Phase::Done;
                    return 1;
                }

                if msg_type == NET_MSG_DATA && payload_len > 1 {
                    let data_ptr = nbuf.add(NET_FRAME_HDR + 1) as *const u8;
                    let data_len = payload_len - 1;

                    let to_copy = data_len.min(RECV_BUF_SIZE);
                    core::ptr::copy_nonoverlapping(
                        data_ptr,
                        s.client.recv_buf.as_mut_ptr(),
                        to_copy,
                    );
                    s.client.recv_len = to_copy as u16;
                    s.client.pending_offset = 0;
                    s.client.bytes_received += to_copy as u32;
                    s.client.phase = Phase::Writing;
                    continue;
                }

                return 0;
            }

            Phase::Writing => {
                if s.client.out_chan < 0 {
                    s.client.phase = Phase::RecvBody;
                    continue;
                }

                let sys = &*s.syscalls;
                let out_chan = s.client.out_chan;
                let offset = s.client.pending_offset as usize;
                let remaining = (s.client.recv_len as usize) - offset;

                let written = (sys.channel_write)(
                    out_chan,
                    s.client.recv_buf.as_ptr().add(offset),
                    remaining,
                );

                if written < 0 {
                    if written == E_AGAIN {
                        return 0;
                    }
                    log(s, b"[http] write failed");
                    s.client.phase = Phase::Error;
                    return E_WRITE_FAILED;
                }

                s.client.pending_offset += written as u16;
                if s.client.pending_offset >= s.client.recv_len {
                    s.client.phase = Phase::RecvBody;
                }
                return 0;
            }

            Phase::Done => {
                send_close_frame(s);
                return 1;
            }

            Phase::Error => {
                send_close_frame(s);
                return -1;
            }

            _ => return -1,
        }
    }
}
