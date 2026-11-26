// Contract: net_proto — Stream Surface.
//
// Layer: contracts/net (public, stable).
//
// In the protocol-surface taxonomy (docs/architecture/protocol_surfaces.md)
// this contract is the **Stream Surface**: bind, accept, connect, data,
// close, error and the stream's peer, consumed unchanged by HTTP, MQTT and
// TLS. Nothing a particular pair of stages shares rides here: the
// retransmission hand-off between a transport and a record layer that keeps
// its own copy is `stream_retx`, the trace context is `stream_trace`, and
// the continuity cursors are `stream_cursor`. A connection carries those
// only when it asked for them and the transport granted them
// ([`flag`]), on the same channel and in order with its stream.
//
// Stream only. Datagram traffic (UDP and friends) lives on the `datagram`
// surface; packet-preserving flows (QUIC/SRTP/classifiers) live on
// `packet`. The ABI registry's `net_tlv` msgset (`abi/registry.toml`) gives
// every message type of every surface sharing this header a distinct value
// inside the range its surface owns, so a shared channel carries several
// contracts unambiguously.
//
// Frame format: `[msg_type: u8] [len: u16 LE] [payload: len bytes]`. Every
// record has exactly one length (`MSG_DATA` and `CMD_SEND` carry their data
// after a fixed head); a record of any other length is malformed and its
// accessor answers `None`.
//
// Record size. No constant bounds a record on this surface. Each port that
// writes it declares the largest frame it writes (`max_record`, header
// included) and each port that reads it the largest it accepts
// (`accepts_record`); the composer refuses an edge, fans included, whose
// producer may write more than a consumer accepts. A module states both
// figures once, in `module_facts!`, and its manifest must agree.
//
// Consumers on a fanned channel. Every stage reading a fanned `net_out`
// skips a message type it does not know and a `conn_id` it does not hold:
// a sideband granted to another consumer's connection, or that connection's
// data, is not its business.

/// Frame header size (msg_type + len).
///
/// No surface assigns message type 0: a frame reader answers 0 for "no
/// frame".
pub const FRAME_HDR: usize = 3;

/// Wire width of a connection id (u16 LE — see the limit register:
/// 65,535 ids; the connection tables bind long before the id space does).
pub const CONN_ID_LEN: usize = 2;

/// The `msg_type` of a frame, from its header.
///
/// Callers bounds-check `frame.len() >= FRAME_HDR` first.
#[inline]
#[must_use]
pub fn msg_type(frame: &[u8]) -> u8 {
    frame[0]
}

/// The payload length a frame's header declares.
///
/// A reader framing this protocol off a byte stream has only the header and has
/// to know how much more to take; one that reads a whole buffer and acts on the
/// first frame drops whatever was queued behind it. Both need this field, so the
/// contract reads it rather than each of them open-coding the same two bytes.
///
/// Callers bounds-check `frame.len() >= FRAME_HDR` first.
#[inline]
#[must_use]
pub fn payload_len(frame: &[u8]) -> usize {
    u16::from_le_bytes([frame[1], frame[2]]) as usize
}

/// The whole wire length of a frame, header included.
///
/// Callers bounds-check `frame.len() >= FRAME_HDR` first.
#[inline]
#[must_use]
pub fn frame_len(frame: &[u8]) -> usize {
    FRAME_HDR + payload_len(frame)
}

/// Write a frame header for `payload_len` bytes of `msg_type` into `out`;
/// `None` when `out` is shorter than [`FRAME_HDR`] or the length does not
/// fit the `u16` field.
#[inline]
pub fn put_header(out: &mut [u8], msg_type: u8, payload_len: usize) -> Option<()> {
    let n = u16::try_from(payload_len).ok()?.to_le_bytes();
    let h = out.get_mut(..FRAME_HDR)?;
    h[0] = msg_type;
    h[1] = n[0];
    h[2] = n[1];
    Some(())
}

/// Read the leading `conn_id` of a payload. Callers bounds-check
/// `payload.len() >= CONN_ID_LEN` first (frame validation).
#[inline]
pub fn conn_id(payload: &[u8]) -> u16 {
    u16::from_le_bytes([payload[0], payload[1]])
}

/// Write `conn_id` into the leading bytes of a payload.
#[inline]
pub fn put_conn_id(payload: &mut [u8], conn_id: u16) {
    payload[0..2].copy_from_slice(&conn_id.to_le_bytes());
}

/// The leading `conn_id` of a payload of any record that opens with one,
/// or `None` when it is shorter than one.
#[inline]
pub fn conn_id_of(payload: &[u8]) -> Option<u16> {
    let p = payload.get(..CONN_ID_LEN)?;
    Some(u16::from_le_bytes([p[0], p[1]]))
}

fn u16_at(p: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([p[at], p[at + 1]])
}

/// Per-connection sidebands, asked for in `CMD_BIND` / `CMD_CONNECT_TO`'s
/// `flags` and answered in `MSG_BOUND` / `MSG_ACCEPTED` / `MSG_CONNECTED`'s
/// `flags_granted`. A sideband frame for a connection is emitted only when
/// its bit was granted on it; a bit the provider does not serve is left
/// clear in the grant, and an undefined bit in a request is refused
/// `EINVAL`. A listener's grant carries to every connection it accepts.
pub mod flag {
    /// `stream_trace`: the transport hands the connection's trace context
    /// (`MSG_TRACE_CTX`) up before its first data.
    pub const TRACE: u8 = 0x01;
    /// `stream_cursor`: the record layer reports the output horizon
    /// (`MSG_CURSOR_HORIZON`) and holds what it delivered until the
    /// consumer acknowledges it (`CMD_CURSOR_DELIVERED`); a takeover hands
    /// the resuming consumer `MSG_CURSOR_RESUMED`.
    pub const CURSORS: u8 = 0x02;
    /// Every bit a consumer may ask for.
    pub const REQUESTABLE: u8 = TRACE | CURSORS;
    /// `stream_retx`, granted and never asked for: the transport keeps no
    /// copy of what this connection sends. It reports the peer's
    /// acknowledgements (`MSG_RETX_ACK`) and asks for bytes again
    /// (`MSG_RETX_REQUEST`); the consumer keeps what it sent until it is
    /// acknowledged and answers with `CMD_RETX_RESEND`. The transport grants
    /// it only on a channel whose every consumer retains what it sends
    /// (the manifest port fact `retains_send`); without the grant the
    /// consumer keeps nothing and the transport retransmits from its own
    /// copy.
    pub const RETX: u8 = 0x04;
    /// Every bit a provider may grant.
    pub const GRANTABLE: u8 = REQUESTABLE | RETX;
}

/// Bytes a requester tag occupies on the wire (`u16` LE).
pub const REQUESTER_TAG_LEN: usize = 2;
/// Bytes a session generation occupies.
pub const SESSION_GENERATION_LEN: usize = 2;
/// Longest negotiated application protocol name a record carries.
pub const ALPN_MAX: usize = 255;

/// A session's opening facts, common to `MSG_ACCEPTED` and `MSG_CONNECTED`:
/// the sidebands granted on it, the session generation (a stage that
/// terminates sessions over the transport's connections, `tls`, numbers each
/// session it opens so a consumer can tell a connection id's current session
/// from a closed one's; 0 from a transport) and the application protocol the
/// session negotiated (TLS ALPN; empty for none).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Opening<'a> {
    pub flags_granted: u8,
    pub generation: u16,
    pub alpn: &'a [u8],
}

impl Opening<'_> {
    /// No sideband, generation 0, no protocol: what a transport reports.
    pub const PLAIN: Opening<'static> = Opening {
        flags_granted: 0,
        generation: 0,
        alpn: &[],
    };
}

/// Bytes of `[flags_granted u8][generation u16][alpn_len u8]`.
const OPENING_HEAD: usize = 1 + SESSION_GENERATION_LEN + 1;

fn read_opening(p: &[u8], at: usize) -> Option<Opening<'_>> {
    let head = p.get(at..at + OPENING_HEAD)?;
    let n = head[3] as usize;
    let alpn = p.get(at + OPENING_HEAD..)?;
    if alpn.len() != n || head[0] & !flag::GRANTABLE != 0 {
        return None;
    }
    Some(Opening {
        flags_granted: head[0],
        generation: u16::from_le_bytes([head[1], head[2]]),
        alpn,
    })
}

fn put_opening(buf: &mut [u8], at: usize, o: &Opening<'_>) -> Option<usize> {
    let n = u8::try_from(o.alpn.len()).ok()?;
    let end = at.checked_add(OPENING_HEAD + o.alpn.len())?;
    let dst = buf.get_mut(at..end)?;
    dst[0] = o.flags_granted;
    dst[1..3].copy_from_slice(&o.generation.to_le_bytes());
    dst[3] = n;
    dst[OPENING_HEAD..].copy_from_slice(o.alpn);
    Some(end)
}

// ─── Downstream: provider → consumer ─────────────────────────────────

/// New connection accepted. Payload:
/// `[conn_id: u16 LE][local_port: u16 LE][flags_granted: u8]
/// [generation: u16 LE][alpn_len: u8][alpn…]` ([`ACCEPTED_FIXED`] +
/// `alpn_len` bytes exactly).
///
/// `local_port` is the listener port the connection was accepted on. When
/// `net_out` is fanned to several stream consumers each bound to a distinct
/// port (a multi-anchor graph), every consumer claims only the connections
/// accepted on its own `CMD_BIND`. `flags_granted` is the listener's grant.
pub use super::super::super::registry::msg::net_proto::MSG_ACCEPTED;
/// `MSG_ACCEPTED`'s length without its protocol name.
pub const ACCEPTED_FIXED: usize = CONN_ID_LEN + 2 + OPENING_HEAD;

/// A `MSG_ACCEPTED` payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Accepted<'a> {
    pub conn_id: u16,
    pub local_port: u16,
    pub opening: Opening<'a>,
}

/// Read a `MSG_ACCEPTED` payload; `None` unless it is exactly one.
#[inline]
pub fn accepted_parts(p: &[u8]) -> Option<Accepted<'_>> {
    if p.len() < ACCEPTED_FIXED {
        return None;
    }
    Some(Accepted {
        conn_id: u16_at(p, 0),
        local_port: u16_at(p, 2),
        opening: read_opening(p, 4)?,
    })
}

/// Write a `MSG_ACCEPTED` payload into `buf`; its length, or `None` when
/// `buf` cannot hold it or the protocol name is over [`ALPN_MAX`] bytes.
#[inline]
pub fn put_accepted(buf: &mut [u8], a: &Accepted<'_>) -> Option<usize> {
    buf.get_mut(..4)?;
    buf[0..2].copy_from_slice(&a.conn_id.to_le_bytes());
    buf[2..4].copy_from_slice(&a.local_port.to_le_bytes());
    put_opening(buf, 4, &a.opening)
}

/// Received data. Payload: `[conn_id: u16 LE][data…]`, at least one byte
/// of data. How much one frame carries is bounded by the producing port's
/// `max_record` (header included); a producer with more bytes splits them
/// across frames.
pub use super::super::super::registry::msg::net_proto::MSG_DATA;
/// `MSG_DATA` / `CMD_SEND` bytes before the data.
pub const DATA_HEAD: usize = CONN_ID_LEN;

/// `(conn_id, data)` of a `MSG_DATA` or `CMD_SEND` payload; `None` when it
/// carries no data.
#[inline]
pub fn data_parts(p: &[u8]) -> Option<(u16, &[u8])> {
    if p.len() <= DATA_HEAD {
        return None;
    }
    Some((u16_at(p, 0), &p[DATA_HEAD..]))
}

/// The largest data a frame of `record` bytes (header included) carries on
/// `MSG_DATA` / `CMD_SEND`: what a port declaring `max_record` /
/// `accepts_record` of `record` moves per frame.
#[inline]
#[must_use]
pub const fn data_capacity(record: usize) -> usize {
    record.saturating_sub(FRAME_HDR + DATA_HEAD)
}

/// The connection closed, or its peer finished sending. Payload:
/// `[conn_id: u16 LE][kind: u8]` ([`CLOSED_LEN`] bytes), `kind` one of:
///
/// - [`CLOSED_PEER_FIN`] — the peer finished sending (its FIN). The
///   connection is still writable and its id is held: a consumer that
///   half-closes keeps sending and closes when it is done.
/// - [`CLOSED_GONE`] — the connection itself is gone: reset, aborted, timed
///   out or released. Nothing more can be sent on it, and a consumer that
///   half-closes must not take this as a FIN.
///
/// Release rule. After `MSG_CLOSED` the connection id stays RESERVED for the
/// consumer's [`CMD_CLOSE`]: the transport does not hand it to a new accept
/// until the consumer has closed or a bounded grace interval has elapsed
/// ([`CLOSED_ID_GRACE_MS`]). So a consumer may always answer `MSG_CLOSED`
/// with `CMD_CLOSE` and never hit a newcomer, and a consumer that never
/// answers cannot leak the id for good. Both transports implement it: the
/// bare-metal `ip` (which holds the TCP slot in CloseWait until the close,
/// then times it out) and the Linux host adapter (which holds the freed
/// slot's id for the grace interval).
pub use super::super::super::registry::msg::net_proto::MSG_CLOSED;
/// How long a transport keeps a closed connection's id reserved for the
/// consumer's [`CMD_CLOSE`] after [`MSG_CLOSED`] before releasing it itself.
/// Five seconds: several scheduler passes on the slowest target and far
/// longer than any consumer takes to notice a close, while short enough that
/// a consumer which never closes cannot pin a 16-slot table through a burst.
pub const CLOSED_ID_GRACE_MS: u32 = 5_000;
/// `MSG_CLOSED` payload length.
pub const CLOSED_LEN: usize = CONN_ID_LEN + 1;
/// `MSG_CLOSED` kind: the peer finished sending; the connection is still
/// writable.
pub const CLOSED_PEER_FIN: u8 = 1;
/// `MSG_CLOSED` kind: the connection is gone.
pub const CLOSED_GONE: u8 = 2;

/// Parts of a `MSG_CLOSED` payload: `(conn_id, kind)`, or `None` unless it
/// is exactly [`CLOSED_LEN`] bytes with a defined kind.
#[inline]
pub fn closed_parts(payload: &[u8]) -> Option<(u16, u8)> {
    if payload.len() != CLOSED_LEN {
        return None;
    }
    let kind = payload[CONN_ID_LEN];
    if kind != CLOSED_PEER_FIN && kind != CLOSED_GONE {
        return None;
    }
    Some((u16_at(payload, 0), kind))
}

/// Bind/listen completed. Payload: `[conn_id: u16 LE][local_port: u16 LE]
/// [flags_granted: u8]` ([`BOUND_LEN`] bytes). `local_port` echoes the port
/// from the consumer's `CMD_BIND`; a multi-anchor consumer records it and
/// matches it against the `local_port` of later `MSG_ACCEPTED` frames.
/// `flags_granted` is what every connection the listener accepts carries.
pub use super::super::super::registry::msg::net_proto::MSG_BOUND;
/// `MSG_BOUND` payload length.
pub const BOUND_LEN: usize = CONN_ID_LEN + 2 + 1;

/// `(conn_id, local_port, flags_granted)` of a `MSG_BOUND` payload, or
/// `None` unless it is exactly one.
#[inline]
pub fn bound_parts(p: &[u8]) -> Option<(u16, u16, u8)> {
    if p.len() != BOUND_LEN || p[4] & !flag::GRANTABLE != 0 {
        return None;
    }
    Some((u16_at(p, 0), u16_at(p, 2), p[4]))
}

/// A `MSG_BOUND` payload.
#[inline]
#[must_use]
pub fn bound(conn_id: u16, local_port: u16, flags_granted: u8) -> [u8; BOUND_LEN] {
    let c = conn_id.to_le_bytes();
    let p = local_port.to_le_bytes();
    [c[0], c[1], p[0], p[1], flags_granted]
}

/// Outbound connect completed. Payload: `[conn_id: u16 LE]
/// [requester_tag: u16 LE][flags_granted: u8][generation: u16 LE]
/// [alpn_len: u8][alpn…]` ([`CONNECTED_FIXED`] + `alpn_len` bytes
/// exactly). `requester_tag` echoes the tag of the `CMD_CONNECT_TO` that
/// opened it, so that when `net_out` is fanned to several stream consumers
/// each claims only the connections it opened.
pub use super::super::super::registry::msg::net_proto::MSG_CONNECTED;
/// `MSG_CONNECTED`'s length without its protocol name.
pub const CONNECTED_FIXED: usize = CONN_ID_LEN + REQUESTER_TAG_LEN + OPENING_HEAD;

/// A `MSG_CONNECTED` payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Connected<'a> {
    pub conn_id: u16,
    pub requester_tag: RequesterTag,
    pub opening: Opening<'a>,
}

/// Read a `MSG_CONNECTED` payload; `None` unless it is exactly one.
#[inline]
pub fn connected_parts(p: &[u8]) -> Option<Connected<'_>> {
    if p.len() < CONNECTED_FIXED {
        return None;
    }
    Some(Connected {
        conn_id: u16_at(p, 0),
        requester_tag: u16_at(p, 2),
        opening: read_opening(p, 4)?,
    })
}

/// Write a `MSG_CONNECTED` payload into `buf`; its length, or `None` when
/// `buf` cannot hold it or the protocol name is over [`ALPN_MAX`] bytes.
#[inline]
pub fn put_connected(buf: &mut [u8], c: &Connected<'_>) -> Option<usize> {
    buf.get_mut(..4)?;
    buf[0..2].copy_from_slice(&c.conn_id.to_le_bytes());
    buf[2..4].copy_from_slice(&c.requester_tag.to_le_bytes());
    put_opening(buf, 4, &c.opening)
}

/// Error. Payload: `[conn_id: u16 LE][errno: i8][requester_tag: u16 LE]`
/// ([`ERROR_LEN`] bytes). An error with tag [`REQUESTER_TAG_NONE`] is an
/// established connection's (or a bind's) and routes by `conn_id`. An error
/// with a tag is a connect-phase failure and is attributed by tag ALONE:
/// its `conn_id` is meaningless on that path — the id already allocated if
/// the dial failed after allocation, and `0` if it failed before (bad
/// `sock_type`, no free slot), which is indistinguishable from a valid id
/// `0` — so a consumer matches a connect failure on `requester_tag`, never
/// on a conn_id it has not yet been assigned.
pub use super::super::super::registry::msg::net_proto::MSG_ERROR;
/// `MSG_ERROR` payload length.
pub const ERROR_LEN: usize = CONN_ID_LEN + 1 + REQUESTER_TAG_LEN;

/// `(conn_id, errno, requester_tag)` of a `MSG_ERROR` payload, or `None`
/// unless it is exactly one. This accessor exists so no consumer re-derives
/// the tag/conn_id discriminator from literal offsets — mis-reading it is
/// exactly how a module claims another module's connect failure.
#[inline]
pub fn error_parts(p: &[u8]) -> Option<(u16, i8, RequesterTag)> {
    if p.len() != ERROR_LEN {
        return None;
    }
    Some((u16_at(p, 0), p[2] as i8, u16_at(p, 3)))
}

/// A `MSG_ERROR` payload.
#[inline]
#[must_use]
pub fn error(conn_id: u16, errno: i8, tag: RequesterTag) -> [u8; ERROR_LEN] {
    let c = conn_id.to_le_bytes();
    let t = tag.to_le_bytes();
    [c[0], c[1], errno as u8, t[0], t[1]]
}

/// The stream's peer: who is at the other end of `conn_id`. Payload:
/// `[conn_id: u16 LE][family: u8][addr: 16][port: u16 LE]` ([`PEER_LEN`]
/// bytes) — `family` is [`AF_INET`] (the address in the first four bytes,
/// network order, the rest zero) or [`AF_INET6`].
///
/// Sent once per stream, right after its `MSG_ACCEPTED` (the client that
/// connected) or its `MSG_CONNECTED` (the address the dial reached; for a
/// dial to a service address, that service address and port, not the backend
/// it was translated to). It is ordered like a control frame — queued with
/// `MSG_ACCEPTED` and delivered before the stream's first `MSG_DATA` — so a
/// consumer that reads it has it before any byte of the stream. A stage that
/// relabels connection ids (`tls`, a demultiplexer) re-emits it with its own
/// id.
pub use super::super::super::registry::msg::net_proto::MSG_PEER;

/// `MSG_PEER` payload length.
pub const PEER_LEN: usize = CONN_ID_LEN + 1 + 16 + 2;

/// Write a whole `MSG_PEER` frame (header included) into `out`; its length,
/// or `None` when `out` is too short.
#[inline]
pub fn write_peer(
    out: &mut [u8],
    conn_id: u16,
    family: u8,
    addr: &[u8; 16],
    port: u16,
) -> Option<usize> {
    let total = FRAME_HDR + PEER_LEN;
    let frame = out.get_mut(..total)?;
    let len = (PEER_LEN as u16).to_le_bytes();
    let id = conn_id.to_le_bytes();
    let pt = port.to_le_bytes();
    let head = [MSG_PEER, len[0], len[1], id[0], id[1], family];
    for (i, b) in frame.iter_mut().enumerate() {
        *b = if i < head.len() {
            head[i]
        } else if i < head.len() + 16 {
            addr[i - head.len()]
        } else if i == head.len() + 16 {
            pt[0]
        } else {
            pt[1]
        };
    }
    Some(total)
}

/// Parts of a `MSG_PEER` payload: `(conn_id, family, addr, port)`, or
/// `None` unless it is exactly one.
#[inline]
pub fn peer_parts(payload: &[u8]) -> Option<(u16, u8, [u8; 16], u16)> {
    if payload.len() != PEER_LEN {
        return None;
    }
    let p = payload;
    let mut addr = [0u8; 16];
    for (i, a) in addr.iter_mut().enumerate() {
        *a = *p.get(3 + i)?;
    }
    Some((u16_at(p, 0), p[2], addr, u16_at(p, 19)))
}

// ─── Upstream: consumer → provider ───────────────────────────────────

/// Bind to a port and listen. Payload: `[port: u16 LE][flags: u8]`
/// ([`BIND_LEN`] bytes); `flags` asks for sidebands ([`flag`]) on every
/// connection the listener accepts. Answered `MSG_BOUND` with the grant, or
/// `MSG_ERROR` (`EINVAL` for an undefined flag bit). The bind is made as the
/// owner the kernel attests for the channel it arrived on, never as one the
/// record names.
pub use super::super::super::registry::msg::net_proto::CMD_BIND;
/// `CMD_BIND` payload length.
pub const BIND_LEN: usize = 2 + 1;

/// `(port, flags)` of a `CMD_BIND` payload, or `None` unless it is exactly
/// one. The flags are returned as sent; a provider refuses bits outside
/// [`flag::REQUESTABLE`].
#[inline]
pub fn bind_parts(p: &[u8]) -> Option<(u16, u8)> {
    if p.len() != BIND_LEN {
        return None;
    }
    Some((u16_at(p, 0), p[2]))
}

/// A `CMD_BIND` payload.
#[inline]
#[must_use]
pub fn bind(port: u16, flags: u8) -> [u8; BIND_LEN] {
    let b = port.to_le_bytes();
    [b[0], b[1], flags]
}

/// Send data on a connection. Payload: `[conn_id: u16 LE][data…]`, at least
/// one byte of data ([`data_parts`]). How much one command carries is bounded
/// by the receiving port's `accepts_record` (header included); a consumer
/// with more bytes issues several. The transport re-segments to its MSS on
/// the wire.
pub use super::super::super::registry::msg::net_proto::CMD_SEND;

/// Close a connection. Payload: `[conn_id: u16 LE][how: u8]`
/// ([`CLOSE_LEN`] bytes), `how` [`CLOSE_ORDERLY`] (FIN after everything
/// queued) or [`CLOSE_ABORT`]: an abortive close — the connection is reset
/// (RST) instead of closed in order, and whatever is queued or in flight is
/// dropped (`SO_LINGER` zero). A record layer forwards an abort without its
/// own close (no close_notify).
///
/// Always safe after [`MSG_CLOSED`] within [`CLOSED_ID_GRACE_MS`] — the id
/// is still the consumer's — and a no-op on an id the transport has already
/// released.
pub use super::super::super::registry::msg::net_proto::CMD_CLOSE;
/// `CMD_CLOSE` payload length.
pub const CLOSE_LEN: usize = CONN_ID_LEN + 1;
/// `CMD_CLOSE`'s `how`: close in order.
pub const CLOSE_ORDERLY: u8 = 0;
/// `CMD_CLOSE`'s `how`: reset the connection.
pub const CLOSE_ABORT: u8 = 1;

/// `(conn_id, abort)` of a `CMD_CLOSE` payload, or `None` unless it is
/// exactly one with a defined `how`.
#[inline]
pub fn close_parts(p: &[u8]) -> Option<(u16, bool)> {
    if p.len() != CLOSE_LEN {
        return None;
    }
    match p[2] {
        CLOSE_ORDERLY => Some((u16_at(p, 0), false)),
        CLOSE_ABORT => Some((u16_at(p, 0), true)),
        _ => None,
    }
}

/// A `CMD_CLOSE` payload.
#[inline]
#[must_use]
pub fn close(conn_id: u16, abort: bool) -> [u8; CLOSE_LEN] {
    let c = conn_id.to_le_bytes();
    [c[0], c[1], if abort { CLOSE_ABORT } else { CLOSE_ORDERLY }]
}

/// Initiate an outbound connection to a target.
/// Payload: `[sock_type: u8][flags: u8][af: u8][port: u16 LE][addr…]
/// [requester_tag: u16 LE]`
///
/// - `af = AF_INET (4)`: `addr` is 4 bytes, network order.
/// - `af = AF_INET6 (6)`: `addr` is 16 bytes, network order.
/// - `af = AF_NAME (1)`: `addr` is `[len: u8][name: len bytes]`, a DNS name
///   of 1..=[`MAX_NAME_LEN`] ASCII bytes with no NUL, resolved by the
///   provider that receives the record: `linux_net` through the host's
///   resolver, `ip` through its stub resolver. A provider may hold a
///   narrower name ceiling than this one and refuse a longer name
///   `EINVAL`.
///
/// `flags` asks for sidebands on the connection ([`flag`]); the grant comes
/// back in `MSG_CONNECTED`. `AF_INET` / `AF_INET6` are the datagram
/// surface's values, so the two surfaces spell an address the same way. Only
/// `SOCK_TYPE_STREAM` is accepted; any other `sock_type`, an undefined flag
/// bit, a name outside 1..=253 bytes, or an `af` the provider does not serve
/// fails `EINVAL` synchronously on the requester tag. A failed resolution is
/// `ENOENT` on the tag. The `requester_tag` is echoed in `MSG_CONNECTED` /
/// `MSG_ERROR`; it carries the requesting module's index **+ 1**
/// (`dev_requester_tag`), never the raw index, or [`REQUESTER_TAG_NONE`].
///
/// Emit with [`write_connect_to`], read with [`read_connect_to`]; parse a
/// `host[:port]` authority with [`Target::parse`] so a literal is never
/// mistaken for a name.
pub use super::super::super::registry::msg::net_proto::CMD_CONNECT_TO;

/// Address family on `CMD_CONNECT_TO`: a DNS name, `[len: u8][name…]`.
pub const AF_NAME: u8 = 1;
/// Address family on `CMD_CONNECT_TO`: IPv4, 4 bytes network order (the
/// datagram surface's value).
pub const AF_INET: u8 = 4;
/// Address family on `CMD_CONNECT_TO`: IPv6, 16 bytes network order (the
/// datagram surface's value).
pub const AF_INET6: u8 = 6;
/// Longest DNS name `AF_NAME` carries (RFC 1035 presentation form).
pub const MAX_NAME_LEN: usize = 253;
/// Bytes before `addr…` in a `CMD_CONNECT_TO` payload.
pub const CONNECT_TO_HEAD: usize = 1 + 1 + 1 + 2;
/// Largest `CMD_CONNECT_TO` payload: head, a name with its length, a tag.
pub const CONNECT_TO_MAX: usize = CONNECT_TO_HEAD + 1 + MAX_NAME_LEN + REQUESTER_TAG_LEN;

/// Where a connection is opened to. The name variant borrows the caller's
/// bytes: nothing here allocates, and a provider that resolves copies the
/// name into its own slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Target<'a> {
    V4([u8; 4]),
    V6([u8; 16]),
    Name(&'a [u8]),
}

impl<'a> Target<'a> {
    /// The address family byte this target is carried under.
    pub fn af(&self) -> u8 {
        match self {
            Target::V4(_) => AF_INET,
            Target::V6(_) => AF_INET6,
            Target::Name(_) => AF_NAME,
        }
    }

    /// Bytes of `addr…` this target occupies on the wire.
    pub fn wire_len(&self) -> usize {
        match self {
            Target::V4(_) => 4,
            Target::V6(_) => 16,
            Target::Name(n) => 1 + n.len(),
        }
    }

    /// Parse an authority: `host[:port]`, where `host` is a DNS name, a
    /// dotted quad, or a bracketed IPv6 literal (`[::1]:443`). The port,
    /// when present, is decimal 1..=65535. Literals are recognised as
    /// literals so no caller ever hashes or resolves one. `None` for
    /// anything else: an empty host, a bare v6 literal without brackets,
    /// a port of 0, a name over [`MAX_NAME_LEN`] bytes or with a byte a
    /// hostname cannot hold.
    pub fn parse(authority: &'a [u8]) -> Option<(Target<'a>, Option<u16>)> {
        let (host, port_text) = split_authority(authority)?;
        let port = match port_text {
            Some(p) => Some(parse_port(p)?),
            None => None,
        };
        if let Some(stripped) = strip_brackets(host) {
            return Some((Target::V6(parse_v6(stripped)?), port));
        }
        if let Some(v4) = parse_v4(host) {
            return Some((Target::V4(v4), port));
        }
        if !name_ok(host) {
            return None;
        }
        Some((Target::Name(host), port))
    }
}

/// `host` and the text after its port separator. A bracketed host keeps
/// its brackets; a host with more than one bare `:` is not an authority.
fn split_authority(a: &[u8]) -> Option<(&[u8], Option<&[u8]>)> {
    if a.is_empty() {
        return None;
    }
    if a[0] == b'[' {
        let close = a.iter().position(|&c| c == b']')?;
        let host = &a[..=close];
        let rest = &a[close + 1..];
        return if rest.is_empty() {
            Some((host, None))
        } else if rest[0] == b':' {
            Some((host, Some(&rest[1..])))
        } else {
            None
        };
    }
    let mut colons = 0usize;
    let mut last = 0usize;
    let mut i = 0usize;
    while i < a.len() {
        if a[i] == b':' {
            colons += 1;
            last = i;
        }
        i += 1;
    }
    match colons {
        0 => Some((a, None)),
        1 => Some((&a[..last], Some(&a[last + 1..]))),
        _ => None,
    }
}

fn strip_brackets(host: &[u8]) -> Option<&[u8]> {
    if host.len() >= 2 && host[0] == b'[' && host[host.len() - 1] == b']' {
        Some(&host[1..host.len() - 1])
    } else {
        None
    }
}

fn parse_port(text: &[u8]) -> Option<u16> {
    if text.is_empty() || text.len() > 5 {
        return None;
    }
    let mut v: u32 = 0;
    for &c in text {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u32::from(c - b'0');
    }
    if v == 0 || v > 0xFFFF {
        return None;
    }
    Some(v as u16)
}

/// A decimal octet with no sign, no leading zeros beyond a lone `0`.
fn parse_octet(text: &[u8]) -> Option<u8> {
    if text.is_empty() || text.len() > 3 || (text.len() > 1 && text[0] == b'0') {
        return None;
    }
    let mut v: u16 = 0;
    for &c in text {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u16::from(c - b'0');
    }
    if v > 255 {
        return None;
    }
    Some(v as u8)
}

/// A dotted quad, exactly four octets. Anything else — including
/// `10.1` or `1.2.3.4.5` — is not one, and is judged as a name instead.
pub fn parse_v4(text: &[u8]) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut n = 0usize;
    let mut start = 0usize;
    let mut i = 0usize;
    while i <= text.len() {
        if i == text.len() || text[i] == b'.' {
            if n == 4 {
                return None;
            }
            out[n] = parse_octet(&text[start..i])?;
            n += 1;
            start = i + 1;
        }
        i += 1;
    }
    if n == 4 {
        Some(out)
    } else {
        None
    }
}

fn hex_val(c: u8) -> Option<u16> {
    match c {
        b'0'..=b'9' => Some(u16::from(c - b'0')),
        b'a'..=b'f' => Some(u16::from(c - b'a') + 10),
        b'A'..=b'F' => Some(u16::from(c - b'A') + 10),
        _ => None,
    }
}

fn parse_hextet(text: &[u8]) -> Option<u16> {
    if text.is_empty() || text.len() > 4 {
        return None;
    }
    let mut v: u16 = 0;
    for &c in text {
        v = (v << 4) | hex_val(c)?;
    }
    Some(v)
}

/// An IPv6 literal without brackets: up to eight hextets, one `::`
/// compression, an optional dotted-quad tail (`::ffff:1.2.3.4`).
pub fn parse_v6(text: &[u8]) -> Option<[u8; 16]> {
    let mut groups = [0u16; 8];
    let mut head = 0usize; // groups before `::`
    let mut tail = [0u16; 8];
    let mut tail_n = 0usize; // groups after `::`
    let mut seen_gap = false;
    let mut i = 0usize;
    let mut start = 0usize;
    // Groups are pushed to `head` until the gap, then to `tail`.
    let mut push = |g: u16, gap: bool| -> bool {
        if !gap {
            if head == 8 {
                return false;
            }
            groups[head] = g;
            head += 1;
        } else {
            if head + tail_n == 8 {
                return false;
            }
            tail[tail_n] = g;
            tail_n += 1;
        }
        true
    };
    while i <= text.len() {
        let at_end = i == text.len();
        if at_end || text[i] == b':' {
            let piece = &text[start..i];
            if piece.is_empty() {
                if at_end && start == 0 {
                    return None; // empty literal
                }
                if !at_end && i + 1 < text.len() && text[i + 1] == b':' {
                    if seen_gap {
                        return None; // two `::`
                    }
                    seen_gap = true;
                    i += 2;
                    start = i;
                    if i == text.len() {
                        break; // trailing `::`
                    }
                    continue;
                }
                if at_end && seen_gap && start == i {
                    break; // `…::` already consumed
                }
                return None; // a lone `:` at an edge or `:::`
            }
            // `[u8]::contains` lowers to `core::slice::memchr`, which a
            // flat module image has no symbol for; the explicit walk is
            // what links.
            #[allow(clippy::manual_contains, reason = "memchr is not linkable here")]
            let dotted = piece.iter().any(|&c| c == b'.');
            if dotted {
                // A dotted-quad tail is the last two groups.
                if !at_end {
                    return None;
                }
                let v4 = parse_v4(piece)?;
                let a = u16::from_be_bytes([v4[0], v4[1]]);
                let b = u16::from_be_bytes([v4[2], v4[3]]);
                if !push(a, seen_gap) || !push(b, seen_gap) {
                    return None;
                }
                break;
            }
            if !push(parse_hextet(piece)?, seen_gap) {
                return None;
            }
            start = i + 1;
        }
        i += 1;
    }
    if seen_gap {
        if head + tail_n >= 8 {
            return None; // `::` must stand for at least one group
        }
        let mut j = 0;
        while j < tail_n {
            groups[8 - tail_n + j] = tail[j];
            j += 1;
        }
    } else if head != 8 {
        return None;
    }
    let mut out = [0u8; 16];
    let mut g = 0;
    while g < 8 {
        let b = groups[g].to_be_bytes();
        out[2 * g] = b[0];
        out[2 * g + 1] = b[1];
        g += 1;
    }
    Some(out)
}

/// Whether `host` may travel as an `AF_NAME`: 1..=[`MAX_NAME_LEN`] bytes of
/// letters, digits, `-`, `_` and `.`, with no empty label and no label over
/// 63 bytes, and at least one letter somewhere — an all-digit host is a
/// mistyped literal, not a name. A trailing dot is accepted and dropped by
/// the resolver.
pub fn name_ok(host: &[u8]) -> bool {
    if host.is_empty() || host.len() > MAX_NAME_LEN {
        return false;
    }
    let mut label = 0usize;
    let mut letter = false;
    let mut i = 0usize;
    while i < host.len() {
        let c = host[i];
        if c == b'.' {
            if label == 0 || (i + 1 == host.len() && i == 0) {
                return false;
            }
            label = 0;
        } else if c.is_ascii_alphanumeric() || c == b'-' || c == b'_' {
            letter |= c.is_ascii_alphabetic();
            label += 1;
            if label > 63 {
                return false;
            }
        } else {
            return false;
        }
        i += 1;
    }
    letter
}

/// A `CMD_CONNECT_TO` payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ConnectTo<'a> {
    pub sock_type: u8,
    pub flags: u8,
    /// The connector's resolved port: the authority's when it named one,
    /// else the protocol default.
    pub port: u16,
    pub target: Target<'a>,
    pub requester_tag: RequesterTag,
}

/// Compose a `CMD_CONNECT_TO` payload into `buf`, answering its length,
/// or `0` when `buf` cannot hold it or the name is not one `AF_NAME`
/// carries.
pub fn write_connect_to(buf: &mut [u8], c: &ConnectTo<'_>) -> usize {
    let n = CONNECT_TO_HEAD + c.target.wire_len() + REQUESTER_TAG_LEN;
    if buf.len() < n {
        return 0;
    }
    buf[0] = c.sock_type;
    buf[1] = c.flags;
    buf[2] = c.target.af();
    buf[3..5].copy_from_slice(&c.port.to_le_bytes());
    let mut at = CONNECT_TO_HEAD;
    match c.target {
        Target::V4(a) => {
            buf[at..at + 4].copy_from_slice(&a);
            at += 4;
        }
        Target::V6(a) => {
            buf[at..at + 16].copy_from_slice(&a);
            at += 16;
        }
        Target::Name(name) => {
            if name.is_empty() || name.len() > MAX_NAME_LEN {
                return 0;
            }
            buf[at] = name.len() as u8;
            at += 1;
            buf[at..at + name.len()].copy_from_slice(name);
            at += name.len();
        }
    }
    buf[at..at + REQUESTER_TAG_LEN].copy_from_slice(&c.requester_tag.to_le_bytes());
    at + REQUESTER_TAG_LEN
}

/// Read a `CMD_CONNECT_TO` payload. `None` for a malformed record — a
/// truncated address, an unknown `af`, a name of 0 or over 253 bytes or
/// holding a NUL or a non-ASCII byte, or a length other than the head, the
/// address and the tag exactly — which the provider answers `EINVAL` on the
/// record's last two bytes read as a tag ([`malformed_connect_to_tag`]):
/// the emitter is broken either way, and those bytes are the closest thing
/// to its name. The flags are returned as sent; a provider refuses bits
/// outside [`flag::REQUESTABLE`] on the tag.
pub fn read_connect_to(payload: &[u8]) -> Option<ConnectTo<'_>> {
    if payload.len() < CONNECT_TO_HEAD {
        return None;
    }
    let sock_type = payload[0];
    let flags = payload[1];
    let af = payload[2];
    let port = u16_at(payload, 3);
    let rest = &payload[CONNECT_TO_HEAD..];
    let (target, used) = match af {
        AF_INET => {
            let a = rest.get(..4)?;
            (Target::V4([a[0], a[1], a[2], a[3]]), 4)
        }
        AF_INET6 => {
            let a = rest.get(..16)?;
            let mut v = [0u8; 16];
            v.copy_from_slice(a);
            (Target::V6(v), 16)
        }
        AF_NAME => {
            let len = usize::from(*rest.first()?);
            if len == 0 || len > MAX_NAME_LEN {
                return None;
            }
            let name = rest.get(1..1 + len)?;
            if name.iter().any(|&c| c == 0 || !c.is_ascii()) {
                return None;
            }
            (Target::Name(name), 1 + len)
        }
        _ => return None,
    };
    if rest.len() != used + REQUESTER_TAG_LEN {
        return None;
    }
    Some(ConnectTo {
        sock_type,
        flags,
        port,
        target,
        requester_tag: u16_at(rest, used),
    })
}

/// The tag a provider answers a malformed `CMD_CONNECT_TO` on: the
/// record's last two bytes LE, where the tag sits, or
/// `REQUESTER_TAG_NONE` when the record is shorter than a tag.
pub fn malformed_connect_to_tag(payload: &[u8]) -> RequesterTag {
    match payload.len().checked_sub(REQUESTER_TAG_LEN) {
        Some(at) => u16_at(payload, at),
        None => REQUESTER_TAG_NONE,
    }
}

/// Only socket type accepted by `CMD_CONNECT_TO` — this is a STREAM-only
/// surface. Datagram traffic uses the `datagram` surface (`CMD_DG_BIND` /
/// `CMD_DG_SEND_TO`); a dial with any other `sock_type` fails EINVAL.
pub const SOCK_TYPE_STREAM: u8 = 1;

/// A requester tag: the requesting module's index **+ 1**, carried as
/// `u16` LE wherever it appears on the wire.
pub type RequesterTag = u16;

/// `requester_tag` value meaning "no routing tag": a consumer that does not
/// tag its connects, and every established-connection error.
///
/// The wire tag is the requester's **module index + 1**, so `0` can never be a
/// valid tag (module index `0` maps to wire tag `1`). Encode with
/// `dev_requester_tag`; a filtering consumer claims a frame iff its tag equals
/// the consumer's own `dev_requester_tag` OR is `REQUESTER_TAG_NONE`
/// (sole-consumer graphs).
pub const REQUESTER_TAG_NONE: RequesterTag = 0;

// Netif state propagation: drivers emit state transitions as
// `MSG_NETIF_STATE` frames on a dedicated `netif_state` output port;
// consumers read from a wired input port of the same name. All
// inter-module networking uses channel-based net_proto (this file) or
// direct FMP messaging — there is no separate netif dispatch surface.

/// The grants a workload owner holds for a network stack, read through the
/// kernel's `OWNER_GRANTS` by the stack that holds the owner's lanes: what
/// the committed owner plan grants it, and what its admission granted it (a
/// resident workload's record in the boot config, or the `net`/`endpoint`
/// options of the `CREATE` that made it). The kernel carries them as opaque
/// `[kind u16][len u16][bytes]` records; the kinds and their bytes are
/// defined here and interpreted by the stack.
///
/// A workload owner's lane listens (binds a nonzero port) only where the
/// owner holds an [`ENDPOINT`] grant for that protocol and port: an owner
/// with none listens nowhere (`EACCES`). The grant is what lets an owner
/// that holds no address of its own listen on the node's shared addresses;
/// an owner holding an address listens on its own addresses alone. Port 0
/// (an ephemeral source) is never a claim and never gated. The node owner's
/// lanes are not gated: they listen on the node's addresses, any port.
pub mod grant {
    /// `net.endpoint`: the owner may bind `[protocol u8][port u16 LE]`
    /// (`protocol` an IP protocol number, [`PROTO_TCP`] or [`PROTO_UDP`]).
    pub const ENDPOINT: u16 = 1;
    /// Bytes of an [`ENDPOINT`] grant.
    pub const ENDPOINT_LEN: usize = 3;
    /// Bytes of a grant record's `[kind u16][len u16]` head.
    pub const HEAD: usize = 4;
    /// IP protocol numbers an endpoint names.
    pub const PROTO_TCP: u8 = 6;
    pub const PROTO_UDP: u8 = 17;
    /// The most [`ENDPOINT`] grants an owner's admission carries (a
    /// resident workload's record, a `CREATE`'s options): the kernel keeps
    /// them per owner slot. A plan's grants are read from the plan and are
    /// bounded by it alone.
    pub const MAX_ADMITTED_ENDPOINTS: usize = 8;

    /// Whether the grant records in `grants` hold an [`ENDPOINT`] for
    /// `(protocol, port)`. A malformed record ends the walk.
    pub fn grants_endpoint(grants: &[u8], protocol: u8, port: u16) -> bool {
        let mut at = 0usize;
        loop {
            let (Some(&k0), Some(&k1), Some(&l0), Some(&l1)) = (
                grants.get(at),
                grants.get(at + 1),
                grants.get(at + 2),
                grants.get(at + 3),
            ) else {
                return false;
            };
            let kind = u16::from_le_bytes([k0, k1]);
            let len = u16::from_le_bytes([l0, l1]) as usize;
            let body = at + HEAD;
            if kind == ENDPOINT && len == ENDPOINT_LEN {
                if let (Some(&p), Some(&a), Some(&b)) =
                    (grants.get(body), grants.get(body + 1), grants.get(body + 2))
                {
                    if p == protocol && u16::from_le_bytes([a, b]) == port {
                        return true;
                    }
                }
            }
            at = body + len;
        }
    }
}
