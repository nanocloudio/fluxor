// Contract: mux — multiplexed session protocol surface (v1 wire format).
//
// Layer: contracts/net (public, stable).
//
// See docs/architecture/protocol_surfaces.md §Multiplexed Session
// Surface and the RFC in .context/rfc_protocols.md §6.4.
//
// The multiplexed session surface is a channel contract for transports
// that expose many logical streams or message channels over one
// transport association. Intended consumers: QUIC engines (the canonical
// case), future SCTP-data-channel-style transports, and application-
// defined mux layers that don't want to be forced through a TCP-shaped
// `transport.stream` abstraction.
//
// Status: envelope reserved. No module consumes this contract today;
// the first consumer is planned to be the QUIC foundation module in
// Phase 6 of the RFC. The fields below derive from the RFC's
// operations list (RFC §6.4) and should remain source-compatible with
// that first consumer, but minor revisions are possible before the
// first .fmod ships against this contract.
//
// Frames use the same [msg_type: u8] [len: u16 LE] [payload...] TLV
// header as net_proto, datagram, packet, and session_ctrl so the
// shared SDK helpers (net_read_frame, net_write_frame) work unchanged.
// Opcode ranges are disjoint from the other four contracts:
//
//     net_proto     0x01..0x13   (Stream Surface v1)
//     datagram      0x20..0x43   (Datagram Surface v1)
//     packet        0x50..0x63   (Packet Surface v1)
//     session_ctrl  0x70..0x9F   (SessionCtrlV1 control sideband)
//     mux           0xB0..0xCF   (this file — Multiplexed Session Surface v1)
//
// so a single channel pair may carry multiple contracts unambiguously.
//
// Identity model:
//
//   session_id: u32 LE
//     Transport-association handle. One mux-capable transport (one QUIC
//     connection, one SCTP association) maps to one session_id. Allocated
//     by the provider in MSG_MUX_SESSION_OPENED.
//
//   stream_id: u32 LE
//     Stream-within-session handle. Per-session namespace — stream_id
//     space is independent across sessions. Allocated by the provider
//     in MSG_MUX_STREAM_OPENED / MSG_MUX_STREAM_ACCEPTED.
//
// Why u32 LE rather than QUIC's 62-bit varint: this is a module-to-
// module local handle, not the wire ID. The QUIC engine maps its own
// 62-bit varint connection/stream IDs onto these compact 32-bit
// handles for channel-side use.
//
// Continuity integration: a QUIC `session_id` is the natural unit of
// `transport_migratable` continuity (RFC §7.1). A migrated QUIC
// connection retains its session_id; SessionCtrlV1 EPOCH_BUMP /
// RELOCATE coordinate the migration with anchors / workers above.

/// Frame header size (msg_type + len).
pub const FRAME_HDR: usize = 3;

/// Bytes of session_id (u32 LE) carried on session-scoped messages.
pub const SESSION_ID_BYTES: usize = 4;
/// Bytes of stream_id (u32 LE) carried on stream-scoped messages.
pub const STREAM_ID_BYTES: usize = 4;

// ─── Stream open flags (CMD_MUX_STREAM_OPEN) ───────────────────────

/// Bidirectional stream (QUIC client-initiated bidi).
pub const STREAM_FLAG_BIDI: u8 = 1 << 0;
/// Unidirectional, send-only stream from the opener.
pub const STREAM_FLAG_UNI: u8 = 1 << 1;
/// Mark this stream as urgent / high priority.
pub const STREAM_FLAG_URGENT: u8 = 1 << 2;

// ─── Status codes ──────────────────────────────────────────────────

pub const STATUS_OK: u8 = 0;
pub const STATUS_NO_CAPACITY: u8 = 1;
pub const STATUS_PROTOCOL_ERROR: u8 = 2;
pub const STATUS_CLOSED: u8 = 3;
pub const STATUS_TIMEOUT: u8 = 4;
pub const STATUS_FLOW_BLOCKED: u8 = 5;

// ─── Upstream: consumer → provider ─────────────────────────────────

/// Open a new transport-level session.
/// Payload: [af: u8 = 4 or 6] [addr: 4 or 16 BE] [port: u16 LE] [flags: u8]
/// (`flags` reserved). Provider responds with MSG_MUX_SESSION_OPENED.
pub const CMD_MUX_SESSION_OPEN: u8 = 0xB0;

/// Close a transport-level session and all streams in it.
/// Payload: [session_id: u32 LE] [reason: u8].
pub const CMD_MUX_SESSION_CLOSE: u8 = 0xB1;

/// Open a stream within an existing session.
/// Payload: [session_id: u32 LE] [flags: u8].
/// `flags` carries STREAM_FLAG_BIDI / STREAM_FLAG_UNI /
/// STREAM_FLAG_URGENT. Provider responds with MSG_MUX_STREAM_OPENED.
pub const CMD_MUX_STREAM_OPEN: u8 = 0xB2;

/// Close a stream (clean shutdown of one direction or both).
/// Payload: [session_id: u32 LE] [stream_id: u32 LE] [flags: u8].
pub const CMD_MUX_STREAM_CLOSE: u8 = 0xB3;

/// Send bytes on a stream.
/// Payload: [session_id: u32 LE] [stream_id: u32 LE] [data: ...].
pub const CMD_MUX_STREAM_SEND: u8 = 0xB4;

/// Acknowledge a flow-control credit grant from the consumer (consumer
/// has drained `bytes` from its receive buffer for this stream).
/// Payload: [session_id: u32 LE] [stream_id: u32 LE] [bytes: u32 LE].
pub const CMD_MUX_STREAM_ACK: u8 = 0xB5;

// ─── Downstream: provider → consumer ───────────────────────────────

/// Session opened and ready to carry streams.
/// Payload: [session_id: u32 LE] [status: u8].
pub const MSG_MUX_SESSION_OPENED: u8 = 0xC0;

/// Session closed (peer-initiated, drain timeout, or local close).
/// Payload: [session_id: u32 LE] [reason: u8].
pub const MSG_MUX_SESSION_CLOSED: u8 = 0xC1;

/// Stream opened locally (response to CMD_MUX_STREAM_OPEN).
/// Payload: [session_id: u32 LE] [stream_id: u32 LE] [status: u8].
pub const MSG_MUX_STREAM_OPENED: u8 = 0xC2;

/// Stream opened by the remote peer; consumer should accept or close.
/// Payload: [session_id: u32 LE] [stream_id: u32 LE] [flags: u8].
pub const MSG_MUX_STREAM_ACCEPTED: u8 = 0xC3;

/// Stream closed (remote FIN or local close confirmation).
/// Payload: [session_id: u32 LE] [stream_id: u32 LE] [reason: u8].
pub const MSG_MUX_STREAM_CLOSED: u8 = 0xC4;

/// Received bytes on a stream.
/// Payload: [session_id: u32 LE] [stream_id: u32 LE] [data: ...].
pub const MSG_MUX_STREAM_RX: u8 = 0xC5;

/// Stream is ready to accept more outbound bytes (flow-control credit
/// granted by the peer).
/// Payload: [session_id: u32 LE] [stream_id: u32 LE] [bytes: u32 LE].
pub const MSG_MUX_STREAM_READY: u8 = 0xC6;

/// Generic session-scoped error.
/// Payload: [session_id: u32 LE] [errno: i8].
pub const MSG_MUX_SESSION_ERROR: u8 = 0xCE;

/// Generic stream-scoped error.
/// Payload: [session_id: u32 LE] [stream_id: u32 LE] [errno: i8].
pub const MSG_MUX_STREAM_ERROR: u8 = 0xCF;

// ─── Payload layout helpers ────────────────────────────────────────

/// Byte offset of the first data byte after the session+stream prefix
/// on stream-scoped data messages (`CMD_MUX_STREAM_SEND` /
/// `MSG_MUX_STREAM_RX`):
/// `[session_id:4][stream_id:4] = 8 bytes`.
pub const STREAM_DATA_PREFIX: usize = SESSION_ID_BYTES + STREAM_ID_BYTES;
