// Contract: datagram — datagram protocol surface (v1 wire format).
//
// Layer: contracts/net (public, stable).
//
// See docs/architecture/protocol_surfaces.md §Datagram Surface and the
// RFC in .context/rfc_protocols.md.
//
// The datagram surface is a channel contract for message-oriented
// transports (UDP, DTLS, RTP, DNS, STUN/TURN, discovery/telemetry). It
// replaces the current practice of carrying UDP through net_proto with
// SOCK_TYPE_DGRAM and a variable payload prefix whose presence depends
// on whether the endpoint is bound or connected.
//
// Frames use the same [msg_type: u8] [len: u16 LE] [payload...] TLV
// header as net_proto (Stream Surface v1) so existing SDK helpers
// (net_read_frame, net_write_frame) work unchanged. Opcode ranges are
// disjoint from net_proto so a misconfigured channel fails loudly
// rather than silently misparsing.
//
// Endpoint identity: endpoint IDs (`ep_id: u8`) are allocated by the
// datagram provider (IP module today, ch9120 tomorrow) in response to
// CMD_DG_BIND and echoed in MSG_DG_BOUND. They are per-provider handles,
// not kernel resources. 256 concurrent endpoints per provider is
// sufficient for every near-term workload.
//
// Address families: `af = 4` is IPv4 (4-byte address); `af = 6` is IPv6
// (16-byte address). Addresses are wire-order big-endian so the IP
// module can memcpy them into the outgoing IPv4/IPv6 header. Ports are
// little-endian for consistency with net_proto. Only IPv4 is currently
// emitted; IPv6 is envelope-ready for a later phase.
//
// Source is always carried on RX — there is no "connected-default" RX
// shape. Consumers that want connected-default semantics can remember
// their peer locally. This removes the bound-vs-connected variable
// prefix that the current UDP shape has.

/// Frame header size (msg_type + len).
pub const FRAME_HDR: usize = 3;

/// Address family: IPv4 (4-byte address, big-endian).
pub const AF_INET: u8 = 4;
/// Address family: IPv6 (16-byte address, big-endian).
pub const AF_INET6: u8 = 6;

/// CMD_DG_BIND flag: receive-only endpoint (no TX allowed). Advisory;
/// providers may ignore. Reserved for future admission policy use.
pub const BIND_FLAG_RX_ONLY: u8 = 0x01;

// ─── Upstream: consumer → provider ─────────────────────────────────

/// Bind a new datagram endpoint to a local port.
/// Payload: [port: u16 LE] [flags: u8].
/// Port 0 requests ephemeral allocation. Provider responds with
/// MSG_DG_BOUND carrying the allocated ep_id and local_port.
pub const CMD_DG_BIND: u8 = 0x20;

/// Send a datagram from `ep_id` to the given destination. Source
/// is always the endpoint's bound port; there is no per-frame source
/// override.
///
/// IPv4 payload: [ep_id: u8] [af: u8 = 4] [addr: 4 bytes BE] [port: u16 LE] [data...]
/// IPv6 payload: [ep_id: u8] [af: u8 = 6] [addr: 16 bytes BE] [port: u16 LE] [data...]
pub const CMD_DG_SEND_TO: u8 = 0x21;

/// Close an endpoint and release its resources.
/// Payload: [ep_id: u8].
pub const CMD_DG_CLOSE: u8 = 0x22;

// ─── Downstream: provider → consumer ───────────────────────────────

/// Bind completed. Consumer learns ep_id and the actual local port
/// (which may differ from the requested port if port 0 was used).
/// Payload: [ep_id: u8] [local_port: u16 LE].
pub const MSG_DG_BOUND: u8 = 0x40;

/// Received datagram. Source address and port are always present.
///
/// IPv4 payload: [ep_id: u8] [af: u8 = 4] [src_addr: 4 bytes BE] [src_port: u16 LE] [data...]
/// IPv6 payload: [ep_id: u8] [af: u8 = 6] [src_addr: 16 bytes BE] [src_port: u16 LE] [data...]
pub const MSG_DG_RX_FROM: u8 = 0x41;

/// Endpoint closed (by consumer request or provider teardown).
/// Payload: [ep_id: u8].
pub const MSG_DG_CLOSED: u8 = 0x42;

/// Endpoint error. Payload: [ep_id: u8] [errno: i8].
pub const MSG_DG_ERROR: u8 = 0x43;

// ─── Payload layout helpers ────────────────────────────────────────

/// Byte offset of the first data byte after the ep_id + af + addr +
/// port prefix, for IPv4 (`af = AF_INET`). Layout for SEND_TO / RX_FROM:
/// `[ep_id:1][af:1][addr:4][port:2] = 8 bytes`.
pub const V4_ADDR_PREFIX: usize = 1 + 1 + 4 + 2;

/// Byte offset of the first data byte after the ep_id + af + addr +
/// port prefix, for IPv6 (`af = AF_INET6`). Layout for SEND_TO / RX_FROM:
/// `[ep_id:1][af:1][addr:16][port:2] = 20 bytes`.
pub const V6_ADDR_PREFIX: usize = 1 + 1 + 16 + 2;
