// Contract: packet — packet protocol surface (v1 wire format).
//
// Layer: contracts/net (public, stable).
//
// See docs/architecture/protocol_surfaces.md §Packet Surface and the
// RFC in .context/rfc_protocols.md.
//
// The packet surface is a channel contract for flows that need
// packet-preserving behaviour and richer ingress metadata than the
// datagram surface exposes. Intended consumers: QUIC engines, DTLS /
// SRTP packet processors, packet policy modules, packet classifiers,
// direct NIC fast paths, market-data and control-plane packet flows.
//
// Status: envelope reserved. No module consumes this contract today;
// the first consumer is planned to be the QUIC foundation module in
// Phase 6 of the RFC. The fields below are derived from the RFC's
// envelope description and should remain source-compatible with that
// first consumer, but minor revisions are possible before the first
// .fmod ships against this contract.
//
// Frames use the same [msg_type: u8] [len: u16 LE] [payload...] TLV
// header as net_proto and datagram so the shared SDK helpers
// (net_read_frame, net_write_frame) work unchanged. Opcode ranges are
// disjoint from net_proto (0x01..0x1F) and datagram (0x20..0x4F) so
// misconfigured channels fail loudly.
//
// Relationship to datagram: the packet surface subsumes the datagram
// envelope and adds ingress/egress metadata (timestamp, lane, ECN/DSCP,
// offload status, flow hint). A module that only cares about payload
// bytes and src/dst should use datagram instead; the packet surface is
// for modules that want to see ingress side-information.
//
// Address families and byte order match datagram exactly.

/// Frame header size (msg_type + len).
pub const FRAME_HDR: usize = 3;

/// Address family: IPv4 (4-byte address, big-endian).
pub const AF_INET: u8 = 4;
/// Address family: IPv6 (16-byte address, big-endian).
pub const AF_INET6: u8 = 6;

// ─── RX flags (provider → consumer, MSG_PKT_RX) ────────────────────

/// The ingress packet had ECN codepoint CE (congestion experienced).
pub const RX_FLAG_ECN_CE: u8 = 1 << 0;
/// Hardware or driver verified the L4 checksum as correct.
pub const RX_FLAG_CSUM_OK: u8 = 1 << 1;
/// The `flow_hint` field is meaningful (non-zero is not sufficient by itself
/// — some providers may supply `flow_hint = 0` legitimately).
pub const RX_FLAG_HAS_FLOW_HINT: u8 = 1 << 2;
/// The `ts_us` field is meaningful. If clear, `ts_us` is provider-synthesised
/// and may be approximate.
pub const RX_FLAG_HAS_TIMESTAMP: u8 = 1 << 3;
/// Packet arrived via a fast path (e.g. mailbox edge, zero-copy NIC ring).
pub const RX_FLAG_FAST_PATH: u8 = 1 << 4;

// ─── TX flags (consumer → provider, CMD_PKT_TX) ────────────────────

/// Request ECN-capable transmit (set ECT(0) or ECT(1) per policy).
pub const TX_FLAG_ECN_CAPABLE: u8 = 1 << 0;
/// Skip L4 checksum offload hint (checksum is already in the payload).
pub const TX_FLAG_NO_CSUM: u8 = 1 << 1;
/// Urgent: bypass egress pacing queues if supported.
pub const TX_FLAG_URGENT: u8 = 1 << 2;

// ─── Upstream: consumer → provider ─────────────────────────────────

/// Bind a new packet endpoint to a local port.
/// Payload: [port: u16 LE] [flags: u8].
/// Port 0 requests ephemeral allocation. Provider responds with
/// MSG_PKT_BOUND carrying the allocated ep_id and local_port.
pub const CMD_PKT_BIND: u8 = 0x50;

/// Send a packet from `ep_id` to the given destination.
///
/// IPv4 payload:
///   [ep_id: u8] [af: u8 = 4] [dst_addr: 4 bytes BE] [dst_port: u16 LE]
///   [lane_hint: u8] [flags: u8] [dscp: u8]
///   [ts_us: u64 LE] [flow_hint: u32 LE]
///   [packet: ...]
///
/// IPv6 payload:
///   [ep_id: u8] [af: u8 = 6] [dst_addr: 16 bytes BE] [dst_port: u16 LE]
///   [lane_hint: u8] [flags: u8] [dscp: u8]
///   [ts_us: u64 LE] [flow_hint: u32 LE]
///   [packet: ...]
///
/// On TX, `ts_us` is a caller-supplied desired transmit timestamp (0 = send
/// now). `lane_hint = 0` means the provider chooses.
pub const CMD_PKT_TX: u8 = 0x51;

/// Close an endpoint and release its resources.
/// Payload: [ep_id: u8].
pub const CMD_PKT_CLOSE: u8 = 0x52;

// ─── Downstream: provider → consumer ───────────────────────────────

/// Bind completed. Payload: [ep_id: u8] [local_port: u16 LE].
pub const MSG_PKT_BOUND: u8 = 0x60;

/// Received packet with full ingress metadata.
///
/// IPv4 payload:
///   [ep_id: u8] [af: u8 = 4] [src_addr: 4 bytes BE] [src_port: u16 LE]
///   [lane: u8] [flags: u8] [dscp: u8]
///   [ts_us: u64 LE] [flow_hint: u32 LE]
///   [packet: ...]
///
/// IPv6 payload:
///   [ep_id: u8] [af: u8 = 6] [src_addr: 16 bytes BE] [src_port: u16 LE]
///   [lane: u8] [flags: u8] [dscp: u8]
///   [ts_us: u64 LE] [flow_hint: u32 LE]
///   [packet: ...]
///
/// `ts_us` is monotonic microseconds at ingress (from `TIMER_MICROS`) when
/// `RX_FLAG_HAS_TIMESTAMP` is set; approximate otherwise.
pub const MSG_PKT_RX: u8 = 0x61;

/// Endpoint closed. Payload: [ep_id: u8].
pub const MSG_PKT_CLOSED: u8 = 0x62;

/// Endpoint error. Payload: [ep_id: u8] [errno: i8].
pub const MSG_PKT_ERROR: u8 = 0x63;

// ─── Payload layout helpers ────────────────────────────────────────

/// Size of the metadata block that follows the address fields in both
/// CMD_PKT_TX and MSG_PKT_RX: `[lane:1][flags:1][dscp:1][ts_us:8 LE][flow_hint:4 LE]`.
pub const META_BLOCK: usize = 1 + 1 + 1 + 8 + 4;

/// Byte offset of the first packet byte in a CMD_PKT_TX / MSG_PKT_RX payload
/// when the address family is IPv4. Layout:
/// `[ep_id:1][af:1][addr:4][port:2][lane:1][flags:1][dscp:1][ts_us:8][flow_hint:4]`.
pub const V4_META_PREFIX: usize = 1 + 1 + 4 + 2 + META_BLOCK;

/// Byte offset of the first packet byte in a CMD_PKT_TX / MSG_PKT_RX payload
/// when the address family is IPv6.
pub const V6_META_PREFIX: usize = 1 + 1 + 16 + 2 + META_BLOCK;
