// Contract: stream_retx — a stream sideband.
//
// Layer: contracts/net (public, stable).
//
// `stream_retx`: the retransmission hand-off between a transport that
// keeps no copy of a connection's send bytes and the consumer that does
// (granted as `net_proto::flag::RETX`). Same channel as the stream, in order with
// it.
//
// Its frames share the `net_tlv` header and range of values with
// `net_proto` (registry `net_tlv` msgset) and ride the stream's own
// channel, in order with it. A consumer that was not granted the sideband
// never sees its frames; one reading a fanned channel skips frames whose
// `conn_id` it does not hold.

use super::net_proto::CONN_ID_LEN;

fn u16_at(p: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([p[at], p[at + 1]])
}

fn u32_at(p: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([p[at], p[at + 1], p[at + 2], p[at + 3]])
}

/// The peer's cumulative acknowledgement moved. Payload: `[conn_id: u16
/// LE][acked_seq: u32 LE][isn: u32 LE]` ([`ACK_LEN`]): everything before
/// `acked_seq` arrived, so the consumer may release what it retained
/// below it. `isn` is the sequence number of the stream's first byte
/// (ISS + 1): it places the consumer's retained bytes in sequence space
/// however many it handed down before the first report reached it. Sent
/// when it moves, not per segment.
pub use super::super::super::registry::msg::stream_retx::MSG_RETX_ACK;
/// `MSG_RETX_ACK` payload length.
pub const ACK_LEN: usize = CONN_ID_LEN + 4 + 4;

/// `(conn_id, acked_seq, isn)` of a `MSG_RETX_ACK` payload, or `None`
/// unless it is exactly one.
#[inline]
pub fn ack_parts(p: &[u8]) -> Option<(u16, u32, u32)> {
    if p.len() != ACK_LEN {
        return None;
    }
    Some((u16_at(p, 0), u32_at(p, 2), u32_at(p, 6)))
}

/// A `MSG_RETX_ACK` payload.
#[inline]
#[must_use]
pub fn ack(conn_id: u16, acked_seq: u32, isn: u32) -> [u8; ACK_LEN] {
    let mut o = [0u8; ACK_LEN];
    o[0..2].copy_from_slice(&conn_id.to_le_bytes());
    o[2..6].copy_from_slice(&acked_seq.to_le_bytes());
    o[6..10].copy_from_slice(&isn.to_le_bytes());
    o
}

/// Send the retained bytes again from `from_seq`. Payload: `[conn_id:
/// u16 LE][from_seq: u32 LE]` ([`REQUEST_LEN`]). The transport emits it
/// on three duplicate ACKs, an RTO and each partial acknowledgement in
/// recovery, after the `MSG_RETX_ACK` that places `from_seq`; the
/// consumer answers with [`CMD_RETX_RESEND`].
pub use super::super::super::registry::msg::stream_retx::MSG_RETX_REQUEST;
/// `MSG_RETX_REQUEST` payload length.
pub const REQUEST_LEN: usize = CONN_ID_LEN + 4;

/// `(conn_id, from_seq)` of a `MSG_RETX_REQUEST` payload, or `None`
/// unless it is exactly one.
#[inline]
pub fn request_parts(p: &[u8]) -> Option<(u16, u32)> {
    if p.len() != REQUEST_LEN {
        return None;
    }
    Some((u16_at(p, 0), u32_at(p, 2)))
}

/// A `MSG_RETX_REQUEST` payload.
#[inline]
#[must_use]
pub fn request(conn_id: u16, from_seq: u32) -> [u8; REQUEST_LEN] {
    let mut o = [0u8; REQUEST_LEN];
    o[0..2].copy_from_slice(&conn_id.to_le_bytes());
    o[2..6].copy_from_slice(&from_seq.to_le_bytes());
    o
}

/// Bytes the consumer already handed down, sent again at their own
/// sequence numbers — its answer to [`MSG_RETX_REQUEST`]. Payload:
/// `[conn_id: u16 LE][seq: u32 LE][data…]`, at least one byte and at
/// most one segment of data. Unlike `CMD_SEND` it allocates nothing: of
/// the bytes it carries, those in `[SND.UNA, SND.NXT)` go out again and
/// the rest (acknowledged since, or never sent) are dropped.
pub use super::super::super::registry::msg::stream_retx::CMD_RETX_RESEND;
/// `CMD_RETX_RESEND` bytes before its data.
pub const RESEND_HEAD: usize = CONN_ID_LEN + 4;

/// `(conn_id, seq, data)` of a `CMD_RETX_RESEND` payload, or `None`
/// when it carries no data.
#[inline]
pub fn resend_parts(p: &[u8]) -> Option<(u16, u32, &[u8])> {
    if p.len() <= RESEND_HEAD {
        return None;
    }
    Some((u16_at(p, 0), u32_at(p, 2), &p[RESEND_HEAD..]))
}
