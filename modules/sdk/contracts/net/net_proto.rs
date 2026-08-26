// Contract: net_proto — Stream Surface v1.
//
// Layer: contracts/net (public, stable).
//
// In the protocol-surface taxonomy (docs/architecture/protocol_surfaces.md)
// this contract is **Stream Surface v1**: its upstream commands and
// downstream events match the stream surface vocabulary directly and
// are consumed unchanged by HTTP, MQTT, and TLS.
//
// Stream only. Datagram traffic (UDP and friends) lives on the
// `datagram` surface in the sibling `datagram.rs`; packet-preserving
// flows (QUIC/SRTP/classifiers) live on `packet.rs`. Opcode ranges
// are disjoint across the three so a shared channel can carry multiple
// contracts unambiguously.
//
// Frame format: [msg_type: u8] [len: u16 LE] [payload: len bytes]
// Carried over channels between IP / TLS / HTTP / MQTT modules. The
// kernel does not interpret these bytes — protocol state lives entirely
// in the modules.

/// Frame header size (msg_type + len).
pub const FRAME_HDR: usize = 3;

/// Wire width of a connection id (u16 LE — see the limit register:
/// 65,535 ids; the R1 conn tables bind long before the id space does).
pub const CONN_ID_LEN: usize = 2;

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

/// Parts of a `MSG_CONNECTED` payload: `(conn_id, requester_tag)`.
///
/// The legacy 2-byte form carries no tag and yields `REQUESTER_TAG_NONE`.
/// Callers bounds-check `payload.len() >= CONN_ID_LEN` first (frame
/// validation), as with `conn_id`.
#[inline]
pub fn connected_parts(payload: &[u8]) -> (u16, u8) {
    let tag = if payload.len() > CONN_ID_LEN {
        payload[CONN_ID_LEN]
    } else {
        REQUESTER_TAG_NONE
    };
    (conn_id(payload), tag)
}

/// Parts of a `MSG_ERROR` payload: `(conn_id, errno, requester_tag)`.
///
/// The 3-byte form carries no tag and yields `REQUESTER_TAG_NONE` — an
/// UNTAGGED error is an established-connection error and routes by
/// `conn_id`; a TAGGED error is a connect-phase failure and is attributed
/// by tag ALONE, because its `conn_id` is meaningless on that path (see
/// `MSG_ERROR`). This accessor exists so no consumer re-derives that
/// discriminator from literal offsets — mis-reading it is exactly how a
/// module claims another module's connect failure. Callers bounds-check
/// `payload.len() >= CONN_ID_LEN + 1` first.
#[inline]
pub fn error_parts(payload: &[u8]) -> (u16, i8, u8) {
    let errno = payload[CONN_ID_LEN] as i8;
    let tag = if payload.len() > CONN_ID_LEN + 1 {
        payload[CONN_ID_LEN + 1]
    } else {
        REQUESTER_TAG_NONE
    };
    (conn_id(payload), errno, tag)
}

/// Parts of a `MSG_ACCEPTED` / `MSG_BOUND` payload: `(conn_id, local_port)`.
/// Callers bounds-check `payload.len() >= CONN_ID_LEN + 2` first; a consumer
/// that ignores the port reads just `conn_id`.
#[inline]
pub fn accepted_parts(payload: &[u8]) -> (u16, u16) {
    (
        conn_id(payload),
        u16::from_le_bytes([payload[CONN_ID_LEN], payload[CONN_ID_LEN + 1]]),
    )
}

// Downstream: IP/net → consumer
/// New connection accepted. Payload: `[conn_id: u16 LE][local_port: u16 LE]`.
/// `local_port` is the listener port the connection was accepted on. When
/// `net_out` is fanned to several stream consumers each bound to a
/// distinct port (a multi-anchor graph), every consumer filters on
/// `local_port` and claims only the connections accepted on its own
/// `CMD_BIND` — otherwise they would all `alloc` the same `conn_id` and
/// corrupt each other's subsequent `MSG_DATA`. A single-consumer graph
/// may ignore the trailing port bytes and read just `conn_id`.
pub const MSG_ACCEPTED: u8 = 0x01;
/// Received data. Payload: `[conn_id: u16 LE][data…]`. The `data` portion of a
/// single `MSG_DATA` frame MUST NOT exceed [`MAX_DATA_FRAGMENT`] — a producer
/// that has more bytes splits them across multiple frames. This bounds every
/// consumer's per-frame scratch (so the alignment-safe reader never has to drop
/// a tail) and matches the natural TCP-MSS segmentation of the bare-metal stack.
pub const MSG_DATA: u8 = 0x02;

/// Normative maximum `data` bytes in one [`MSG_DATA`] frame (one TCP MSS). A
/// `net_out` producer (IP, the Linux host adapter, …) chunks larger reads into
/// multiple frames; a consumer may therefore size its frame scratch to
/// `FRAME_HDR + CONN_ID_LEN + MAX_DATA_FRAGMENT` and be sure a whole frame always fits.
pub const MAX_DATA_FRAGMENT: usize = 1460;
/// Remote closed connection. Payload: `[conn_id: u16 LE]`
pub const MSG_CLOSED: u8 = 0x03;
/// Bind/listen completed. Payload: `[conn_id: u16 LE][local_port: u16 LE]`.
/// `local_port` echoes the port from the consumer's `CMD_BIND`; a
/// multi-anchor consumer records it and matches it against the
/// `local_port` in subsequent `MSG_ACCEPTED` frames (see `MSG_ACCEPTED`).
pub const MSG_BOUND: u8 = 0x04;
/// Outbound connect completed. Payload: `[conn_id: u16 LE][requester_tag: u8]`.
/// `requester_tag` echoes the tag the consumer put on its `CMD_CONNECT` (its
/// module index **+ 1** — the `dev_requester_tag` wire encoding, NOT the raw
/// index) so that when `ip.net_out` is fanned to several stream consumers (e.g.
/// TLS + an OTLP exporter), each claims only the connections it opened. A
/// consumer that doesn't filter just reads `conn_id` and ignores the trailing
/// byte; untagged connects echo tag `0` (`REQUESTER_TAG_NONE`).
pub const MSG_CONNECTED: u8 = 0x05;
/// Error. Payload: `[conn_id: u16 LE][errno: i8][requester_tag: u8?]`. For a
/// connect-phase failure the trailing `requester_tag` echoes the failing
/// `CMD_CONNECT`'s tag so a consumer that has no conn_id yet can recognise its
/// own failure on a fanned `net_out`; established-connection errors carry the
/// owning connection's conn_id (filter by that). 3-byte form = tag 0.
/// On a connect-phase failure `conn_id` is MEANINGLESS — it is the id already
/// allocated if the dial failed after allocation, and `0` if it failed before
/// (bad `sock_type`, no free slot), which is indistinguishable from a valid id
/// `0` — so a consumer must match a connect failure on `requester_tag` ALONE,
/// never on a conn_id it has not yet been assigned.
pub const MSG_ERROR: u8 = 0x06;
// 0x07 / 0x08 are reserved: the IP module privately uses them for
// `MSG_RETRANSMIT` / `MSG_ACK` (consumer-side retransmit + send-buffer release)
// on the same channel. The next free downstream opcode is 0x09.

/// Observability trace context for a connection (W3C). Emitted by the ingress
/// (IP) right after `MSG_ACCEPTED`, and re-emitted by each forwarding stage
/// (TLS) with its own span id, so the next stage parents its span correctly.
/// Payload: `[conn_id: u16 LE][trace_id: 16][parent_span_id: 8][trace_flags: u8]`
/// (27 bytes). Purely additive and best-effort (direct write, dropped if the
/// channel is full) — a stage that doesn't trace discards it like any unknown
/// frame, so it never affects the data path. The trailing `trace_flags` byte is
/// the W3C flags (low bit = `sampled`), so the head-sampling decision survives
/// each hop. See `standards/observability.md`.
pub const MSG_TRACE_CTX: u8 = 0x09;

/// `MSG_TRACE_CTX` payload length: conn_id + 16-byte trace id + 8-byte span id
/// + 1-byte W3C trace-flags.
pub const TRACE_CTX_LEN: usize = CONN_ID_LEN + 16 + 8 + 1;

// Upstream: consumer → IP/net
/// Bind to port and listen. Payload: [port: u16 LE]
pub const CMD_BIND: u8 = 0x10;
/// Send data on connection. Payload: `[conn_id: u16 LE][data…]`. The `data` portion
/// MUST NOT exceed [`MAX_CMD_DATA`]; a consumer with more bytes issues multiple
/// `CMD_SEND`s. The net stack (IP / host adapter) re-segments to MSS on the
/// wire. This bounds the receiver's command scratch; an oversized frame is
/// drained and rejected alignment-safely rather than mis-parsed.
pub const CMD_SEND: u8 = 0x11;

/// Normative maximum `data` bytes in one upstream command frame (`CMD_SEND`).
/// Receivers (IP, the Linux host adapter) size their command scratch to
/// `FRAME_HDR + CONN_ID_LEN + MAX_CMD_DATA` and drain anything larger to stay frame-aligned.
pub const MAX_CMD_DATA: usize = 8192;
/// Close connection. Payload: `[conn_id: u16 LE]`
pub const CMD_CLOSE: u8 = 0x12;
/// Initiate outbound connection.
/// Payload: `[sock_type: u8][ip: u32 LE][port: u16 LE][requester_tag: u8?]`.
/// Only `SOCK_TYPE_STREAM` is accepted; other values fail with EINVAL. The
/// trailing `requester_tag` is OPTIONAL (7-byte form = tag `0`); when present it
/// is echoed back in `MSG_CONNECTED` so a consumer sharing `ip.net_out` with
/// other stream consumers can recognise its own outbound connection. The wire
/// tag is the requesting module's index **+ 1** (`dev_requester_tag`), NOT the
/// raw index — so the untagged sentinel `REQUESTER_TAG_NONE` (0) never collides
/// with module index 0.
pub const CMD_CONNECT: u8 = 0x13;

/// Only socket type accepted by `CMD_CONNECT` — this is a STREAM-only surface.
/// Datagram traffic uses the `datagram` surface (`CMD_DG_BIND` /
/// `CMD_DG_SEND_TO`); a `CMD_CONNECT` with any other `sock_type` fails EINVAL.
pub const SOCK_TYPE_STREAM: u8 = 1;

/// `requester_tag` value meaning "no routing tag" — the legacy 7-byte
/// `CMD_CONNECT` and any consumer that doesn't tag its connects.
///
/// The wire tag is the requester's **module index + 1**, so `0` can never be a
/// valid tag (module index `0` maps to wire tag `1`). This avoids the collision
/// a raw zero-based index would have with this sentinel. Encode with
/// `dev_requester_tag`; a filtering consumer claims a frame iff its tag equals
/// the consumer's own `dev_requester_tag` OR is `REQUESTER_TAG_NONE` (legacy /
/// sole-consumer graphs).
pub const REQUESTER_TAG_NONE: u8 = 0;

// Netif state propagation: drivers emit state transitions as
// `MSG_NETIF_STATE` frames on a dedicated `netif_state` output port;
// consumers read from a wired input port of the same name. All
// inter-module networking uses channel-based net_proto (this file) or
// direct FMP messaging — there is no separate netif dispatch surface.
