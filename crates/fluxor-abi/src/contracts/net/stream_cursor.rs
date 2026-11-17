// Contract: stream_cursor — a stream sideband.
//
// Layer: contracts/net (public, stable).
//
// `stream_cursor`: the continuity cursors between a record layer and its
// consumer, on a connection granted `net_proto::flag::CURSORS`.
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

fn u64_at(p: &[u8], at: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&p[at..at + 8]);
    u64::from_le_bytes(b)
}

/// The connection's output horizon moved: every clear byte the consumer
/// handed down on `conn_id` up to `bytes_through` is in records the
/// transport has put on the wire — under a crash-continuous continuity
/// pairing, records the standby acknowledged before they left, so the
/// primary's loss cannot take them. Payload: `[conn_id: u16 LE]
/// [bytes_through: u64 LE]` ([`HORIZON_LEN`]), sent when it moves.
/// Counted from the first byte this consumer sent on the stream as it
/// holds it — a connection moved to another host starts again at 0 for
/// its consumer there. Bytes, not commands, so a stage that splits or
/// joins commands between the consumer and the record layer keeps the
/// numbering.
pub use super::super::super::registry::msg::stream_cursor::MSG_CURSOR_HORIZON;
/// `MSG_CURSOR_HORIZON` payload length.
pub const HORIZON_LEN: usize = CONN_ID_LEN + 8;

/// `(conn_id, bytes_through)` of a `MSG_CURSOR_HORIZON` payload, or
/// `None` unless it is exactly one.
#[inline]
pub fn horizon_parts(p: &[u8]) -> Option<(u16, u64)> {
    if p.len() != HORIZON_LEN {
        return None;
    }
    Some((u16_at(p, 0), u64_at(p, 2)))
}

/// A `MSG_CURSOR_HORIZON` payload.
#[inline]
#[must_use]
pub fn horizon(conn_id: u16, bytes_through: u64) -> [u8; HORIZON_LEN] {
    let mut o = [0u8; HORIZON_LEN];
    o[0..2].copy_from_slice(&conn_id.to_le_bytes());
    o[2..10].copy_from_slice(&bytes_through.to_le_bytes());
    o
}

/// The stream was resumed here by a transport-continuity takeover:
/// where the consumer's predecessor on the old host stood, so this
/// consumer continues exactly. Payload: `[conn_id: u16 LE]
/// [consumer_cursor: u64 LE][in_bytes: u64 LE][out_bytes: u64 LE]`
/// ([`RESUMED_LEN`]). `consumer_cursor` and `in_bytes` are what the
/// predecessor's last `CMD_CURSOR_DELIVERED` carried (both 0 when none
/// was mirrored): it had consumed the stream's first `in_bytes` clear
/// bytes and stood at `consumer_cursor` there. Redelivery of what was
/// handed up and not acknowledged starts at exactly byte `in_bytes`, so
/// this consumer counts on from `in_bytes` in its own
/// `CMD_CURSOR_DELIVERED`s. `out_bytes` is the output horizon in
/// `MSG_CURSOR_HORIZON`'s numbering. Sent once, after the activated
/// stream's `MSG_PEER` and before any of its data, redelivered or new.
pub use super::super::super::registry::msg::stream_cursor::MSG_CURSOR_RESUMED;
/// `MSG_CURSOR_RESUMED` payload length.
pub const RESUMED_LEN: usize = CONN_ID_LEN + 8 + 8 + 8;

/// `(conn_id, consumer_cursor, in_bytes, out_bytes)` of a
/// `MSG_CURSOR_RESUMED` payload, or `None` unless it is exactly one.
#[inline]
pub fn resumed_parts(p: &[u8]) -> Option<(u16, u64, u64, u64)> {
    if p.len() != RESUMED_LEN {
        return None;
    }
    Some((u16_at(p, 0), u64_at(p, 2), u64_at(p, 10), u64_at(p, 18)))
}

/// A `MSG_CURSOR_RESUMED` payload.
#[inline]
#[must_use]
pub fn resumed(conn_id: u16, cursor: u64, in_bytes: u64, out_bytes: u64) -> [u8; RESUMED_LEN] {
    let mut o = [0u8; RESUMED_LEN];
    o[0..2].copy_from_slice(&conn_id.to_le_bytes());
    o[2..10].copy_from_slice(&cursor.to_le_bytes());
    o[10..18].copy_from_slice(&in_bytes.to_le_bytes());
    o[18..26].copy_from_slice(&out_bytes.to_le_bytes());
    o
}

/// The consumer has consumed the first `in_bytes` clear bytes a stage
/// handed up on `conn_id`, and stands at `consumer_cursor` there.
/// Payload: `[conn_id: u16 LE][consumer_cursor: u64 LE][in_bytes: u64
/// LE]` ([`DELIVERED_LEN`]). `in_bytes` counts the stream's clear bytes
/// from its start (after a takeover, on from `MSG_CURSOR_RESUMED`'s
/// `in_bytes`) and may fall inside a record; `consumer_cursor` is the
/// consumer's own position there, opaque to the transport. The record
/// layer counts as consumed only the records whose plaintext ends at or
/// before `in_bytes`, keeps the cursor with its byte offset, mirrors both
/// under transport continuity and hands them to the consumer that
/// resumes the stream after a takeover.
pub use super::super::super::registry::msg::stream_cursor::CMD_CURSOR_DELIVERED;
/// `CMD_CURSOR_DELIVERED` payload length.
pub const DELIVERED_LEN: usize = CONN_ID_LEN + 16;

/// `(conn_id, consumer_cursor, in_bytes)` of a `CMD_CURSOR_DELIVERED`
/// payload, or `None` unless it is exactly one.
#[inline]
pub fn delivered_parts(p: &[u8]) -> Option<(u16, u64, u64)> {
    if p.len() != DELIVERED_LEN {
        return None;
    }
    Some((u16_at(p, 0), u64_at(p, 2), u64_at(p, 10)))
}

/// A `CMD_CURSOR_DELIVERED` payload.
#[inline]
#[must_use]
pub fn delivered(conn_id: u16, cursor: u64, in_bytes: u64) -> [u8; DELIVERED_LEN] {
    let mut o = [0u8; DELIVERED_LEN];
    o[0..2].copy_from_slice(&conn_id.to_le_bytes());
    o[2..10].copy_from_slice(&cursor.to_le_bytes());
    o[10..18].copy_from_slice(&in_bytes.to_le_bytes());
    o
}
