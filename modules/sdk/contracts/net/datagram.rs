// Contract: datagram — datagram protocol surface (v1 wire format).
//
// Layer: contracts/net (public, stable).
//
// See docs/architecture/protocol_surfaces.md §Datagram Surface.
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
// Endpoint authority: an `ep_id` is an index, not an authority. The graph
// model permits several consumer modules to feed one provider command
// channel — the kernel merges them into a single stream — and channel reads
// carry no producer identity, so an index alone cannot say who sent the
// command. The owner tag supplies that: CMD_DG_BIND records an `owner_tag`
// against the endpoint, and CMD_DG_SEND_TO / CMD_DG_CLOSE present the tag
// they claim. The provider admits a command only when the presented tag
// equals the recorded one, and refuses a mismatch with `EPERM`.
//
// The tag is the consumer module's own owner slot, read from the kernel
// (`kernel_abi::OWNER_TAG`) — the same value, on the same axis, that
// `net_proto`'s `NET_CMD_BIND` already carries. It is asserted in the frame,
// not proved: it says which owner the consumer named at bind, and is not an
// unguessable capability.
//
// An absent tag reads as tag 0. Owner slot 0 is the host, so a base-graph
// module binds untagged and its endpoint accepts untagged commands from any
// consumer on the shared channel; that is the whole of what an untagged
// command permits, and it is why the tag separates owners rather than
// individual modules. Any endpoint bound with a nonzero tag is reachable only
// by a command carrying that exact tag, tagged or otherwise.
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
/// Payload: [port: u16 LE] [flags: u8] [owner_tag: u16 LE]?
/// Port 0 requests ephemeral allocation. Provider responds with
/// MSG_DG_BOUND carrying the allocated ep_id and local_port. A trailing
/// `owner_tag` stamps the endpoint's owner; absent means tag 0.
pub const CMD_DG_BIND: u8 = 0x20;

/// Send a datagram from `ep_id` to the given destination. Source
/// is always the endpoint's bound port; there is no per-frame source
/// override.
///
/// IPv4 payload: [ep_id: u8] [af: u8 = 4] [addr: 4 bytes BE] [port: u16 LE] [data...]
/// IPv6 payload: [ep_id: u8] [af: u8 = 6] [addr: 16 bytes BE] [port: u16 LE] [data...]
///
/// Owner-tagged form — `OWNER_TAG_MARK` sits where `af` sits, so the two
/// shapes are told apart at a fixed offset and the tag never has to be
/// distinguished from the variable-length data:
///
/// [ep_id: u8] [OWNER_TAG_MARK] [owner_tag: u16 LE] [af: u8] [addr] [port: u16 LE] [data...]
pub const CMD_DG_SEND_TO: u8 = 0x21;

/// Close an endpoint and release its resources.
/// Payload: [ep_id: u8], or the owner-tagged form
/// [ep_id: u8] [OWNER_TAG_MARK] [owner_tag: u16 LE].
pub const CMD_DG_CLOSE: u8 = 0x22;

/// Marker byte introducing the owner tag on CMD_DG_SEND_TO and
/// CMD_DG_CLOSE. It occupies the byte that otherwise holds `af`, and is
/// distinct from every defined address family, so the tagged and untagged
/// shapes are unambiguous without a length rule over variable-length data.
pub const OWNER_TAG_MARK: u8 = 0xFF;

/// Bytes the owner-tag field adds ahead of the untagged payload:
/// `[OWNER_TAG_MARK][owner_tag: u16 LE]`.
pub const OWNER_TAG_FIELD: usize = 1 + 2;

/// Tag value meaning "no owner" — the host wildcard. It is what an absent
/// tag decodes to, and an endpoint recorded with it is reachable by any
/// consumer sharing the provider's command channel.
pub const OWNER_TAG_NONE: u16 = 0;

// ─── Downstream: provider → consumer ───────────────────────────────

/// Bind completed. Consumer learns ep_id and the actual local port
/// (which may differ from the requested port if port 0 was used).
/// Payload: [ep_id: u8] [local_port: u16 LE].
pub const MSG_DG_BOUND: u8 = 0x40;

/// Parts of a `MSG_DG_BOUND` payload: `(ep_id, local_port)`.
///
/// On a fanned provider output every consumer sees every BOUND, and an
/// endpoint id is an identity: a consumer that grabs the first BOUND it
/// polls claims another module's endpoint, then filters every later
/// datagram against the wrong id (found live on the Pi 5 SIP rig,
/// 2026-08-26 — three binds, three BOUNDs, whoever read first won).
/// A consumer that requested a specific port claims a BOUND only when
/// `local_port` matches it. Callers bounds-check `payload.len() >= 3`.
#[inline]
pub fn dg_bound_parts(payload: &[u8]) -> (u8, u16) {
    (payload[0], u16::from_le_bytes([payload[1], payload[2]]))
}

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
