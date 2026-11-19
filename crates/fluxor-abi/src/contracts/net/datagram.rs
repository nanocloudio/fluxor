// Contract: datagram — the datagram protocol surface.
//
// Layer: contracts/net (public, stable).
//
// See docs/architecture/protocol_surfaces.md §Datagram Surface.
//
// The datagram surface is a channel contract for message-oriented
// transports (UDP, DTLS, RTP, DNS, STUN/TURN, discovery/telemetry):
// every datagram names its endpoint and its peer address explicitly,
// whether the endpoint is bound or connected.
//
// Frames use the same [msg_type: u8] [len: u16 LE] [payload...] TLV
// header as net_proto so the same SDK helpers (net_read_frame,
// net_write_frame) serve both, and
// the ABI registry's `net_tlv` msgset (`abi/registry.toml`) gives every
// message type of every surface sharing this header a distinct value,
// so a misconfigured channel fails loudly rather than silently misparsing.
//
// Endpoint identity: endpoint IDs (`ep_id: u8`) are allocated by the
// datagram provider (`ip`, `linux_net`) in response to
// CMD_DG_BIND and echoed in MSG_DG_BOUND. They are per-provider handles,
// not kernel resources. 256 concurrent endpoints per provider is
// the ceiling.
//
// Endpoint authority: an `ep_id` is an index, not an authority. The
// provider records against each endpoint the owner the kernel attests for
// the channel its bind arrived on (`channel::FACTS`'s producer owner), and
// admits a send or close on it only from a channel of that same owner
// (`EPERM` otherwise). No record names an owner: a consumer cannot claim
// one it is not.
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
/// Address family on `CMD_DG_SEND_TO`: a DNS name, `[len: u8][name…]`
/// (1..=253 ASCII bytes), resolved by the provider exactly as a stream
/// `CMD_CONNECT_TO` name is. A name the provider does not yet hold starts a
/// lookup and the datagram is DROPPED; a datagram sender retransmits, and
/// the next send after the answer lands goes out. A provider that cannot
/// resolve answers `MSG_DG_ERROR` `EAFNOSUPPORT`; literals work everywhere.
pub const AF_NAME: u8 = 1;

/// CMD_DG_BIND flag: receive-only endpoint (no TX allowed). Advisory;
/// providers may ignore. Reserved for future admission policy use.
pub const BIND_FLAG_RX_ONLY: u8 = 0x01;

// ─── Upstream: consumer → provider ─────────────────────────────────

/// Bind a new datagram endpoint to a local port.
/// Payload: `[port: u16 LE][flags: u8]` ([`BIND_LEN`] bytes exactly).
/// Port 0 requests ephemeral allocation. Provider responds with
/// MSG_DG_BOUND carrying the allocated ep_id and local_port.
pub use super::super::super::registry::msg::datagram::CMD_DG_BIND;
/// `CMD_DG_BIND` payload length.
pub const BIND_LEN: usize = 2 + 1;

/// `(port, flags)` of a `CMD_DG_BIND` payload, or `None` unless it is
/// exactly one.
#[inline]
pub fn bind_parts(p: &[u8]) -> Option<(u16, u8)> {
    if p.len() != BIND_LEN {
        return None;
    }
    Some((u16::from_le_bytes([p[0], p[1]]), p[2]))
}

/// A `CMD_DG_BIND` payload.
#[inline]
#[must_use]
pub fn bind(port: u16, flags: u8) -> [u8; BIND_LEN] {
    let b = port.to_le_bytes();
    [b[0], b[1], flags]
}

/// Send a datagram from `ep_id` to the given destination. Source
/// is always the endpoint's bound port; there is no per-frame source
/// override.
///
/// IPv4 payload: [ep_id: u8] [af: u8 = 4] [addr: 4 bytes BE] [port: u16 LE] [data...]
/// IPv6 payload: [ep_id: u8] [af: u8 = 6] [addr: 16 bytes BE] [port: u16 LE] [data...]
/// Name payload: [ep_id: u8] [af: u8 = 1] [len: u8] [name: len bytes] [port: u16 LE] [data...]
pub use super::super::super::registry::msg::datagram::CMD_DG_SEND_TO;

/// Close an endpoint and release its resources.
/// Payload: `[ep_id: u8]` (1 byte exactly).
pub use super::super::super::registry::msg::datagram::CMD_DG_CLOSE;
/// `CMD_DG_CLOSE` payload length.
pub const CLOSE_LEN: usize = 1;

// ─── Downstream: provider → consumer ───────────────────────────────

/// Bind completed. Consumer learns ep_id and the actual local port
/// (which may differ from the requested port if port 0 was used).
/// Payload: [ep_id: u8] [local_port: u16 LE].
pub use super::super::super::registry::msg::datagram::MSG_DG_BOUND;

/// Parts of a `MSG_DG_BOUND` payload: `(ep_id, local_port)`.
///
/// On a fanned provider output every consumer sees every BOUND, and an
/// endpoint id is an identity: a consumer that grabs the first BOUND it
/// polls claims another module's endpoint, then filters every later
/// datagram against the wrong id — three binds raise three BOUNDs, and
/// whoever reads first wins.
/// A consumer that requested a specific port claims a BOUND only when
/// `local_port` matches it. `None` unless the payload is exactly
/// [`BOUND_LEN`] bytes.
#[inline]
pub fn dg_bound_parts(payload: &[u8]) -> Option<(u8, u16)> {
    if payload.len() != BOUND_LEN {
        return None;
    }
    Some((payload[0], u16::from_le_bytes([payload[1], payload[2]])))
}

/// `MSG_DG_BOUND` payload length.
pub const BOUND_LEN: usize = 1 + 2;

/// Received datagram. Source address and port are always present.
///
/// IPv4 payload: [ep_id: u8] [af: u8 = 4] [src_addr: 4 bytes BE] [src_port: u16 LE] [data...]
/// IPv6 payload: [ep_id: u8] [af: u8 = 6] [src_addr: 16 bytes BE] [src_port: u16 LE] [data...]
pub use super::super::super::registry::msg::datagram::MSG_DG_RX_FROM;

/// Endpoint closed (by consumer request or provider teardown).
/// Payload: [ep_id: u8].
pub use super::super::super::registry::msg::datagram::MSG_DG_CLOSED;

/// Endpoint error. Payload: [ep_id: u8] [errno: i8] ([`ERROR_LEN`] bytes).
pub use super::super::super::registry::msg::datagram::MSG_DG_ERROR;
/// `MSG_DG_ERROR` payload length.
pub const ERROR_LEN: usize = 2;

// ─── Payload layout helpers ────────────────────────────────────────

/// Byte offset of the first data byte after the ep_id + af + addr +
/// port prefix, for IPv4 (`af = AF_INET`). Layout for SEND_TO / RX_FROM:
/// `[ep_id:1][af:1][addr:4][port:2] = 8 bytes`.
pub const V4_ADDR_PREFIX: usize = 1 + 1 + 4 + 2;

/// Byte offset of the first data byte after the ep_id + af + addr +
/// port prefix, for IPv6 (`af = AF_INET6`). Layout for SEND_TO / RX_FROM:
/// `[ep_id:1][af:1][addr:16][port:2] = 20 bytes`.
pub const V6_ADDR_PREFIX: usize = 1 + 1 + 16 + 2;

/// The largest datagram payload a transport delivers: one Ethernet MTU of
/// IPv4 payload. A larger datagram is dropped and counted, never cut.
pub const PAYLOAD_MAX: usize = 1472;
/// The largest record a stream transport writes toward its consumers, header
/// included: a `MSG_DG_RX_FROM` carrying [`PAYLOAD_MAX`] bytes from an IPv4
/// peer. It bounds the transport's `MSG_DATA` too, so it is the
/// `max_record` of the ip module's and the host adapter's `net_out` and of
/// tls's clear side, and what a consumer of any of them accepts.
pub const TRANSPORT_RECORD_MAX: usize = super::net_proto::FRAME_HDR + V4_ADDR_PREFIX + PAYLOAD_MAX;
