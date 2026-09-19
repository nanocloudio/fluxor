// Contract: mux — multiplexed session protocol surface.
//
// Layer: contracts/net (public, stable).
//
// See docs/architecture/protocol_surfaces.md §Multiplexed Session
// Surface.
//
// The multiplexed session surface is a channel contract for transports
// that expose many logical streams or message channels over one
// transport association. Intended consumers: QUIC engines (the canonical
// case), future SCTP-data-channel-style transports, and application-
// defined mux layers that don't want to be forced through a TCP-shaped
// `transport.stream` abstraction.
//
// Status: live. The QUIC foundation module is the provider; `mux_echo`
// (fixtures) is the in-tree consumer, and consuming HTTP/3 and MQTT-over-QUIC
// modules live downstream.
//
// This surface is PROTOCOL-NEUTRAL and complete. A provider implements
// the whole lifecycle below for every session it carries, whatever
// application protocol the session negotiated — there is no reduced
// profile, no ALPN-conditional subset, and no application vocabulary in
// any payload. Everything a transport knows about an application is
// carried as opaque bytes: the negotiated ALPN token, stream contents,
// datagram contents, and application error codes.
//
// Frames use the same [msg_type: u8] [len: u16 LE] [payload...] TLV
// header as net_proto, datagram, packet, and session_ctrl so the
// shared SDK helpers (net_read_frame, net_write_frame) work unchanged.
// Opcode ranges are disjoint from the other four contracts:
//
//     net_proto     0x01..0x14   (Stream Surface v1)
//     datagram      0x20..0x43   (Datagram Surface v1)
//     packet        0x50..0x63   (Packet Surface v1)
//     session_ctrl  0x70..0x9F   (SessionCtrlV1 control sideband)
//     mux           0xB0..0xCF   (this file — Multiplexed Session Surface)
//
// so a single channel pair may carry multiple contracts unambiguously.
//
// Identity model:
//
//   session_id: u32 LE
//     Transport-association handle. One mux-capable transport (one QUIC
//     connection, one SCTP association) maps to one session_id. Allocated
//     by the provider and announced in MSG_MUX_SESSION_OPENED.
//
//   stream_id: u32 LE
//     Stream-within-session handle. Per-session namespace — stream_id
//     space is independent across sessions. Allocated by the provider
//     in MSG_MUX_STREAM_OPENED / MSG_MUX_STREAM_ACCEPTED.
//
// Why `stream_id` is u32 LE rather than QUIC's 62-bit varint: it is an
// OPAQUE LOCAL HANDLE for addressing the stream over this channel, not
// the wire id. Every data-plane command (`CMD_MUX_STREAM_SEND`,
// `_CLOSE`, `_ACK`, `_RESET`, `_STOP_SENDING`) addresses a stream by
// this handle, which keeps the hot-path prefix a fixed 8 bytes and lets
// the provider index its slot table directly.
//
// An application that needs the transport's own stream identity — HTTP/3
// needs it for GOAWAY and PRIORITY_UPDATE — reads the `quic_stream_id`
// field carried on MSG_MUX_STREAM_OPENED / MSG_MUX_STREAM_ACCEPTED and
// keeps its own handle→id mapping. The two are NOT derivable from each
// other: a consumer must never do arithmetic on a handle to guess a wire
// id, and a provider must never truncate a wire id into a handle.
//
// Handles are not reused while the application can still observe them: a
// provider reclaims a handle only after the stream's terminal event
// (MSG_MUX_STREAM_CLOSED / _RESET) has actually been delivered.
//
// Continuity integration: a QUIC `session_id` is the natural unit of
// `transport_migratable` continuity. A migrated QUIC connection
// retains its session_id; SessionCtrlV1 EPOCH_BUMP / RELOCATE
// coordinate the migration with anchors / workers above.

/// Frame header size (msg_type + len).
pub const FRAME_HDR: usize = 3;

/// Read the leading `session_id` of a session-scoped payload. Callers
/// bounds-check `payload.len() >= SESSION_ID_BYTES` first (frame
/// validation), as with `net_proto::conn_id`.
#[inline]
pub fn session_id(payload: &[u8]) -> u32 {
    u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]])
}

/// Write `session_id` into the leading bytes of a session-scoped payload.
#[inline]
pub fn put_session_id(payload: &mut [u8], session_id: u32) {
    payload[0..SESSION_ID_BYTES].copy_from_slice(&session_id.to_le_bytes());
}

/// Read the `stream_id` of a stream-scoped payload
/// (`[session_id: u32 LE][stream_id: u32 LE]…`). Callers bounds-check
/// `payload.len() >= SESSION_ID_BYTES + STREAM_ID_BYTES` first.
#[inline]
pub fn stream_id(payload: &[u8]) -> u32 {
    u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]])
}

/// Write `stream_id` into a stream-scoped payload, after the session id.
#[inline]
pub fn put_stream_id(payload: &mut [u8], stream_id: u32) {
    payload[SESSION_ID_BYTES..SESSION_ID_BYTES + STREAM_ID_BYTES]
        .copy_from_slice(&stream_id.to_le_bytes());
}

/// Bytes of session_id (u32 LE) carried on session-scoped messages.
pub const SESSION_ID_BYTES: usize = 4;
/// Bytes of stream_id (u32 LE) carried on stream-scoped messages.
pub const STREAM_ID_BYTES: usize = 4;
/// Bytes of the transport's own stream identity (u64 LE) carried as
/// metadata on MSG_MUX_STREAM_OPENED / MSG_MUX_STREAM_ACCEPTED.
pub const QUIC_STREAM_ID_BYTES: usize = 8;
/// Bytes of an application error code (u64 LE) on reset / stop-sending.
pub const APP_ERROR_BYTES: usize = 8;

// ─── Stream flags (open command + opened/accepted events) ──────────

/// Bidirectional stream (both halves usable).
pub const STREAM_FLAG_BIDI: u8 = 1 << 0;
/// Unidirectional stream — send-only from whoever opened it, and
/// receive-only for the peer.
pub const STREAM_FLAG_UNI: u8 = 1 << 1;
/// Mark this stream as urgent / high priority.
pub const STREAM_FLAG_URGENT: u8 = 1 << 2;
/// Set on MSG_MUX_STREAM_OPENED / MSG_MUX_STREAM_ACCEPTED when the LOCAL
/// endpoint initiated the stream; clear when the peer did.
///
/// This is the generic initiator bit. It exists so a consumer never has
/// to recover direction and initiator by masking the low bits of a QUIC
/// stream id — that arithmetic is transport-specific, and a consumer
/// doing it has reached through the contract into the provider.
pub const STREAM_FLAG_LOCAL_INIT: u8 = 1 << 3;

// ─── Session flags (MSG_MUX_SESSION_OPENED) ────────────────────────

/// Set when the LOCAL endpoint initiated the session (client role for a
/// QUIC connection); clear when it was accepted from a peer.
///
/// The provider assigns no application meaning to the role — it reports
/// which side dialled, and the application decides what that implies.
pub const SESSION_FLAG_LOCAL_INIT: u8 = 1 << 0;

// ─── Status codes ──────────────────────────────────────────────────

pub const STATUS_OK: u8 = 0;
pub const STATUS_NO_CAPACITY: u8 = 1;
pub const STATUS_PROTOCOL_ERROR: u8 = 2;
pub const STATUS_CLOSED: u8 = 3;
pub const STATUS_TIMEOUT: u8 = 4;
pub const STATUS_FLOW_BLOCKED: u8 = 5;
/// The stream was terminated by RESET_STREAM (local or peer) rather than
/// finishing cleanly. Carried as the `reason` on MSG_MUX_STREAM_CLOSED
/// where a terminal event is owed but the detail already went out on
/// MSG_MUX_STREAM_RESET.
pub const STATUS_RESET: u8 = 6;

// ─── Upstream: consumer → provider ─────────────────────────────────

/// Open a new transport-level session.
/// Payload: [af: u8 = 4 or 6] [addr: 4 or 16 BE] [port: u16 LE] [flags: u8]
/// (`flags` reserved). Provider responds with MSG_MUX_SESSION_OPENED.
pub const CMD_MUX_SESSION_OPEN: u8 = 0xB0;

/// Close a transport-level session and all streams in it.
/// Payload: [session_id: u32 LE] [reason: u8].
///
/// Optionally followed by [app_error: u64 LE], which the provider places
/// in the transport's application-close frame (QUIC CONNECTION_CLOSE of
/// type 0x1d). The provider does not interpret the code.
pub const CMD_MUX_SESSION_CLOSE: u8 = 0xB1;

/// Open a stream within an existing session.
/// Payload: [session_id: u32 LE] [flags: u8].
/// `flags` carries STREAM_FLAG_BIDI / STREAM_FLAG_UNI /
/// STREAM_FLAG_URGENT. Provider responds with MSG_MUX_STREAM_OPENED,
/// whose `status` is STATUS_NO_CAPACITY when no slot or no peer
/// MAX_STREAMS credit is available.
pub const CMD_MUX_STREAM_OPEN: u8 = 0xB2;

/// Close the LOCAL SEND HALF of a stream — the clean end-of-stream
/// signal (QUIC STREAM frame with the FIN bit) emitted after every byte
/// already queued on the stream has drained.
/// Payload: [session_id: u32 LE] [stream_id: u32 LE] [flags: u8].
pub const CMD_MUX_STREAM_CLOSE: u8 = 0xB3;

/// Send bytes on a stream.
/// Payload: [session_id: u32 LE] [stream_id: u32 LE] [data: ...].
///
/// Reliable and all-or-nothing: a write the provider cannot take whole
/// is refused with MSG_MUX_STREAM_ERROR rather than truncated, and the
/// stream cursor does not advance.
pub const CMD_MUX_STREAM_SEND: u8 = 0xB4;

/// Acknowledge a flow-control credit grant from the consumer (consumer
/// has drained `bytes` from its receive buffer for this stream).
/// Payload: [session_id: u32 LE] [stream_id: u32 LE] [bytes: u32 LE].
///
/// This is what advances the provider's MAX_STREAM_DATA and MAX_DATA
/// windows. A consumer that never sends it will eventually be stalled by
/// the peer running out of credit — the provider must not invent credit
/// on the consumer's behalf.
pub const CMD_MUX_STREAM_ACK: u8 = 0xB5;

/// Send an unreliable datagram on the session (RFC 9221 QUIC DATAGRAM).
/// Session-scoped, not stream-scoped: there is no stream_id and no
/// retransmission. Payload: [session_id: u32 LE] [data: ...]. A datagram
/// larger than the peer's advertised max is dropped by the provider.
///
/// Available on every session. The provider never inspects the payload
/// and never gates this on the negotiated protocol.
pub const CMD_MUX_DATAGRAM_SEND: u8 = 0xB6;

/// Abruptly terminate the LOCAL SEND HALF of a stream (QUIC
/// RESET_STREAM, RFC 9000 §19.4). Queued bytes are discarded.
/// Payload: [session_id: u32 LE] [stream_id: u32 LE] [app_error: u64 LE].
///
/// `app_error` is an opaque application error code — the provider copies
/// it into the transport frame and never interprets it. HTTP/3 and QPACK
/// error codes are the application's values.
pub const CMD_MUX_STREAM_RESET: u8 = 0xB7;

/// Ask the peer to stop sending on a stream (QUIC STOP_SENDING,
/// RFC 9000 §19.5).
/// Payload: [session_id: u32 LE] [stream_id: u32 LE] [app_error: u64 LE].
///
/// The peer is expected to answer with RESET_STREAM, which surfaces
/// locally as MSG_MUX_STREAM_RESET. `app_error` is opaque.
pub const CMD_MUX_STREAM_STOP_SENDING: u8 = 0xB8;

/// Open a stream AND queue its first bytes atomically.
/// Payload: [session_id: u32 LE] [flags: u8] [data: ...].
///
/// Equivalent to CMD_MUX_STREAM_OPEN immediately followed by
/// CMD_MUX_STREAM_SEND on the resulting handle, but without the
/// round trip through MSG_MUX_STREAM_OPENED — which matters only for a
/// protocol whose connection preamble opens several streams and writes a
/// short prefix on each before anything else may flow. The provider
/// still answers with MSG_MUX_STREAM_OPENED; on STATUS_NO_CAPACITY the
/// data is discarded with the failed open, so nothing is half-applied.
///
/// RESERVED: the opcode is allocated and the semantics fixed, but no
/// provider implements it. A consumer MUST implement the plain
/// open/send path regardless and treat this purely as a latency
/// optimisation.
pub const CMD_MUX_STREAM_OPEN_WITH: u8 = 0xB9;

// ─── Downstream: provider → consumer ───────────────────────────────

/// Session established and ready to carry streams.
/// Payload:
/// `[session_id: u32 LE] [status: u8] [flags: u8] [alpn_len: u8]
///  [alpn: alpn_len bytes]`
///
/// Emitted exactly once per session, before any stream event for that
/// session, and retried under backpressure rather than dropped. This is
/// how a consumer learns a session exists — it must never assume session
/// `0`, infer a session from the first stream that arrives on it, or
/// reach into the provider's connection table.
///
/// `flags` carries SESSION_FLAG_LOCAL_INIT. `alpn` is the negotiated
/// application-layer protocol token as OPAQUE BYTES (RFC 7301), with
/// `alpn_len == 0` meaning no ALPN was negotiated. The provider performs
/// the negotiation but assigns the token no meaning: selecting behaviour
/// from it is the consumer's job.
pub const MSG_MUX_SESSION_OPENED: u8 = 0xC0;

/// Session closed (peer-initiated, drain timeout, or local close).
/// Payload: [session_id: u32 LE] [reason: u8].
///
/// Optionally followed by [app_error: u64 LE] when the close carried an
/// application error code the contract can convey. Emitted exactly once
/// per session that was announced with MSG_MUX_SESSION_OPENED.
pub const MSG_MUX_SESSION_CLOSED: u8 = 0xC1;

/// Stream opened locally (response to CMD_MUX_STREAM_OPEN or
/// CMD_MUX_STREAM_OPEN_WITH).
/// Payload:
/// `[session_id: u32 LE] [stream_id: u32 LE] [status: u8] [flags: u8]
///  [quic_stream_id: u64 LE]`
///
/// `flags` carries STREAM_FLAG_BIDI / _UNI and STREAM_FLAG_LOCAL_INIT
/// (always set here). `quic_stream_id` is the transport's own stream
/// identity; it is meaningful only when `status == STATUS_OK`.
pub const MSG_MUX_STREAM_OPENED: u8 = 0xC2;

/// Stream opened by the remote peer.
/// Payload:
/// `[session_id: u32 LE] [stream_id: u32 LE] [flags: u8]
///  [quic_stream_id: u64 LE]`
///
/// Emitted for EVERY peer-initiated stream, bidirectional and
/// unidirectional alike, before any bytes from that stream. `flags`
/// carries STREAM_FLAG_BIDI / _UNI with STREAM_FLAG_LOCAL_INIT clear.
///
/// The provider does not read, classify, rewrite, or withhold any byte
/// of the stream — including the leading varint that some application
/// protocols use as a stream type. Every byte the peer sent reaches the
/// consumer in order, on MSG_MUX_STREAM_RX.
pub const MSG_MUX_STREAM_ACCEPTED: u8 = 0xC3;

/// Stream closed cleanly (peer FIN, or confirmation of a local close).
/// Payload: [session_id: u32 LE] [stream_id: u32 LE] [reason: u8].
///
/// Emitted exactly once per stream and retried under backpressure — an
/// empty FIN that carries no data still produces it. Delivery of the
/// terminal event is tracked independently of data delivery, so a
/// backpressured close never causes already-delivered bytes to repeat.
pub const MSG_MUX_STREAM_CLOSED: u8 = 0xC4;

/// Received bytes on a stream.
/// Payload: [session_id: u32 LE] [stream_id: u32 LE] [data: ...].
pub const MSG_MUX_STREAM_RX: u8 = 0xC5;

/// Stream is ready to accept more outbound bytes (flow-control credit
/// granted by the peer).
/// Payload: [session_id: u32 LE] [stream_id: u32 LE] [bytes: u32 LE].
pub const MSG_MUX_STREAM_READY: u8 = 0xC6;

/// Received an unreliable datagram on the session (RFC 9221 QUIC
/// DATAGRAM). Session-scoped. Payload: [session_id: u32 LE] [data: ...].
///
/// Delivered on every session that negotiated DATAGRAM support. The
/// provider enforces the negotiated size and preserves unreliable
/// semantics; it never interprets the payload and never gates delivery
/// on the negotiated protocol.
pub const MSG_MUX_DATAGRAM_RX: u8 = 0xC7;

/// Peer-identity sideband for the session: a one-shot event a transport
/// emits once the underlying secure handshake binds the peer, so an
/// application consuming the mux surface (e.g. an mqtt codec) learns the
/// authenticated peer identity without reaching into the transport.
/// Session-scoped.
///
/// The payload is byte-identical to the TLS module's `MSG_PEER_IDENTITY`
/// record, which owns the format:
///
/// ```text
/// [session_id: u32 LE]
/// [verification_result: u8]
/// [credential_kind: u8]
/// [profile_id: u16 LE]
/// [not_before: u64 LE][not_after: u64 LE]
/// [verification_flags: u32 LE]
/// [key_fp_alg: u8][key_fp_len: u8]
/// [principal_len: u16 LE]
/// [key_fingerprint: key_fp_len][principal: principal_len]
/// ```
///
/// It replaced `[verified: u8][svid_len: u16 LE][svid]`, which differed
/// from the TLS record for no reason anyone could state — same fact,
/// two layouts, so a consumer wanting both wrote two parsers. Worse,
/// `verified` was a single bit standing in for a set of independent
/// checks: a consumer could not tell a chain validated to a configured
/// anchor from a self-signed certificate that merely parsed, and so had
/// no basis for deciding whether the name in it meant anything.
/// `verification_flags` says which checks actually ran, and the
/// principal is absent unless the chain and the SAN were both verified.
///
/// This is a first-class mux downstream event — it must NOT be smuggled as
/// an out-of-contract opcode. `0x5A` is the tempting one and the wrong one:
/// it sits inside the reserved `packet` range `0x50..0x63`.
///
/// Emitted for every mux session, whatever protocol it negotiated. A
/// session whose peer presented no credential still gets one, with
/// `verification_result = NO_CREDENTIAL` and no principal: silence
/// would be indistinguishable from an event still in flight.
pub const MSG_MUX_PEER_IDENTITY: u8 = 0xC8;

/// Fixed portion of a `MSG_MUX_PEER_IDENTITY` payload; the fingerprint
/// and principal follow.
pub const PEER_IDENTITY_FIXED_LEN: usize = 4 + 1 + 1 + 2 + 8 + 8 + 4 + 1 + 1 + 2;

/// Peer reset a stream abruptly (QUIC RESET_STREAM, RFC 9000 §19.4), or
/// confirmation that a locally requested reset was applied.
/// Payload: [session_id: u32 LE] [stream_id: u32 LE] [app_error: u64 LE].
///
/// Terminal for the stream's receive half. `app_error` is the peer's
/// opaque application error code, passed through uninterpreted.
pub const MSG_MUX_STREAM_RESET: u8 = 0xCA;

/// Peer asked us to stop sending on a stream (QUIC STOP_SENDING,
/// RFC 9000 §19.5).
/// Payload: [session_id: u32 LE] [stream_id: u32 LE] [app_error: u64 LE].
///
/// The consumer is expected to stop producing on that stream and answer
/// with CMD_MUX_STREAM_RESET carrying an application error code of its
/// choosing. `app_error` is opaque.
pub const MSG_MUX_STREAM_STOPPED: u8 = 0xCB;

// Opcodes 0xCC and 0xCD are unallocated.

/// Generic session-scoped error.
/// Payload: [session_id: u32 LE] [errno: i8].
pub const MSG_MUX_SESSION_ERROR: u8 = 0xCE;

/// Generic stream-scoped error.
/// Payload: [session_id: u32 LE] [stream_id: u32 LE] [errno: i8].
///
/// This is how a refused reliable command is reported. A provider that
/// cannot take a `CMD_MUX_STREAM_SEND` whole — no capacity, no
/// flow-control credit, unknown handle — emits this rather than
/// truncating or silently dropping the write, so the consumer knows the
/// bytes did not go out and can retry them.
pub const MSG_MUX_STREAM_ERROR: u8 = 0xCF;

// ─── Payload layout helpers ────────────────────────────────────────

/// Byte offset of the first data byte after the session+stream prefix
/// on stream-scoped data messages (`CMD_MUX_STREAM_SEND` /
/// `MSG_MUX_STREAM_RX`):
/// `[session_id:4][stream_id:4] = 8 bytes`.
pub const STREAM_DATA_PREFIX: usize = SESSION_ID_BYTES + STREAM_ID_BYTES;

/// Payload length of `MSG_MUX_STREAM_OPENED` after the session+stream
/// prefix: `[status:1][flags:1][quic_stream_id:8]`.
pub const STREAM_OPENED_BODY: usize = 1 + 1 + QUIC_STREAM_ID_BYTES;

/// Payload length of `MSG_MUX_STREAM_ACCEPTED` after the session+stream
/// prefix: `[flags:1][quic_stream_id:8]`.
pub const STREAM_ACCEPTED_BODY: usize = 1 + QUIC_STREAM_ID_BYTES;

/// Parts of a `MSG_MUX_STREAM_ACCEPTED` body: `(flags, quic_stream_id)`.
/// The QUIC stream id is transport identity — consumers read it through
/// this accessor rather than literal offsets. Callers bounds-check
/// `body.len() >= STREAM_ACCEPTED_BODY` first.
#[inline]
pub fn stream_accepted_parts(body: &[u8]) -> (u8, u64) {
    (
        body[0],
        u64::from_le_bytes([
            body[1], body[2], body[3], body[4], body[5], body[6], body[7], body[8],
        ]),
    )
}

/// Payload length of `MSG_MUX_STREAM_RESET` / `_STOPPED` and of
/// `CMD_MUX_STREAM_RESET` / `_STOP_SENDING` after the session+stream
/// prefix: `[app_error:8]`.
pub const STREAM_APP_ERROR_BODY: usize = APP_ERROR_BYTES;

/// Minimum payload length of `MSG_MUX_SESSION_OPENED` after the session
/// id: `[status:1][flags:1][alpn_len:1]`, plus `alpn_len` opaque bytes.
pub const SESSION_OPENED_BODY_MIN: usize = 1 + 1 + 1;

/// Maximum data bytes the QUIC provider accepts in one
/// `CMD_MUX_STREAM_SEND` (it matches the engine's single-MTU stream send
/// buffer). A reliable write larger than this is refused with
/// `MSG_MUX_STREAM_ERROR`, not truncated — the engine reads frames with
/// an alignment-preserving reader, so an oversize frame neither desyncs
/// the FIFO nor silently loses its tail.
///
/// This is a real transport bound, independent of any protocol: it is
/// how much unframed application data one stream can hold pending
/// packetisation.
pub const MUX_QUIC_STREAM_SEND_MAX: usize = 1200;

/// Maximum data bytes the QUIC provider delivers in one
/// `MSG_MUX_STREAM_RX`, matching its per-stream receive buffer.
///
/// Published for the same reason the send bound is: a consumer has to size
/// the scratch it copies a frame into, and the only safe number is the one
/// the provider will actually emit. Sizing that scratch from a PROTOCOL
/// budget instead — a maximum header block, a slot accumulator — silently
/// couples two unrelated limits, and the failure is a truncated copy of a
/// frame the channel has already consumed: no error, no retry, and a
/// request or response that is simply short.
///
/// This is larger than [`MUX_QUIC_STREAM_SEND_MAX`], and deliberately so.
/// The send bound is what one stream may hold pending packetisation; this
/// is what a peer's packets may already have delivered, and the transport
/// does not get to choose how much a peer sends.
///
/// A consumer that cannot accept this much MUST fail the stream explicitly
/// rather than copy a prefix of it.
pub const MUX_QUIC_STREAM_RX_MAX: usize = 1500;

/// Largest whole `MSG_MUX_STREAM_RX` payload: the stream prefix plus the
/// data bound above. This is the number to size a receive scratch from.
pub const MUX_QUIC_STREAM_RX_FRAME_MAX: usize = STREAM_DATA_PREFIX + MUX_QUIC_STREAM_RX_MAX;
