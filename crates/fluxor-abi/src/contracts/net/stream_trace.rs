// Contract: stream_trace — a stream sideband.
//
// Layer: contracts/net (public, stable).
//
// `stream_trace`: a connection's trace context, handed up by the transport
// right after its `MSG_ACCEPTED` / `MSG_PEER` and before its first data, and
// re-emitted by each forwarding stage with its own span id so the next
// stage parents its span correctly. Only on a connection granted
// `net_proto::flag::TRACE`; ordered like a control frame, never dropped.
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

/// Payload: `[conn_id: u16 LE][trace_id: 16][parent_span_id: 8]
/// [trace_flags: u8]` ([`CTX_LEN`]); `trace_flags` is the W3C flags
/// byte (low bit = `sampled`), so the head-sampling decision survives
/// each hop.
pub use super::super::super::registry::msg::stream_trace::MSG_TRACE_CTX;
/// `MSG_TRACE_CTX` payload length.
pub const CTX_LEN: usize = CONN_ID_LEN + 16 + 8 + 1;

/// `(conn_id, trace_id, parent_span_id, trace_flags)` of a
/// `MSG_TRACE_CTX` payload, or `None` unless it is exactly one.
#[inline]
pub fn ctx_parts(p: &[u8]) -> Option<(u16, [u8; 16], [u8; 8], u8)> {
    if p.len() != CTX_LEN {
        return None;
    }
    let mut t = [0u8; 16];
    t.copy_from_slice(&p[2..18]);
    let mut s = [0u8; 8];
    s.copy_from_slice(&p[18..26]);
    Some((u16_at(p, 0), t, s, p[26]))
}

/// A `MSG_TRACE_CTX` payload.
#[inline]
#[must_use]
pub fn ctx(conn_id: u16, trace_id: &[u8; 16], span_id: &[u8; 8], flags: u8) -> [u8; CTX_LEN] {
    let mut o = [0u8; CTX_LEN];
    o[0..2].copy_from_slice(&conn_id.to_le_bytes());
    o[2..18].copy_from_slice(trace_id);
    o[18..26].copy_from_slice(span_id);
    o[26] = flags;
    o
}
