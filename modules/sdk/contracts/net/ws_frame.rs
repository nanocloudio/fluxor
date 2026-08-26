// Contract: ws_frame — the `WsFrame` channel envelope.
//
// Layer: contracts/net (public, stable).
//
// `WsFrame` is the connection-addressed WebSocket frame envelope carried
// between an HTTP server terminating RFC 6455 upgrades and the module
// consuming or producing frames.
//
// Fluxor is authoritative for the content-type name AND for the envelope
// layout below. Both belong here for the same reason: a layout each consumer
// restates privately is one every consumer can get subtly wrong on its own,
// and the connection-identity accessors exist so no consumer has to restate
// it at all.
//
// ─── Envelope ───────────────────────────────────────────────────────
//
//   [conn: u32 LE] [opcode: u8] [fin: u8] [payload_len: u16 LE] [payload…]
//
// One envelope per channel write, delivered atomically. `opcode` and `fin`
// are the RFC 6455 values for the frame the payload came from (or is to be
// sent as); `payload_len` is the byte count that follows the header.
//
// ─── Connection identity ────────────────────────────────────────────
//
// `conn` is the transport connection id, widened to u32 on this envelope.
// Real ids fit u16 (the `net_proto` conn-id width); bytes 2..4 are zero for
// a real id. The all-ones value is the UNCLAIMED sentinel: a producer that
// does not yet know its connection writes `CONN_UNCLAIMED`, and the server
// resolves it to the active fan-out slot. `0xFFFFFFFF` — not `0` — is the
// sentinel precisely so that a valid connection id 0 is never read as
// absence.

/// Envelope header size: conn (4) + opcode (1) + fin (1) + payload_len (2).
pub const FRAME_HDR: usize = 8;

/// Wire width of the envelope's connection id (u32 LE).
pub const CONN_ID_LEN: usize = 4;

/// The "no connection claimed yet" sentinel. All ones, never zero:
/// connection id 0 is a valid id, not absence.
pub const CONN_UNCLAIMED: u32 = u32::MAX;

/// Read the envelope's connection id. Callers bounds-check
/// `frame.len() >= FRAME_HDR` first (envelope validation).
#[inline]
pub fn conn_id(frame: &[u8]) -> u32 {
    u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]])
}

/// Write the envelope's connection id.
#[inline]
pub fn put_conn_id(frame: &mut [u8], conn_id: u32) {
    frame[0..CONN_ID_LEN].copy_from_slice(&conn_id.to_le_bytes());
}

/// Read the envelope's opcode byte.
#[inline]
pub fn opcode(frame: &[u8]) -> u8 {
    frame[4]
}

/// Read the envelope's fin byte.
#[inline]
pub fn fin(frame: &[u8]) -> u8 {
    frame[5]
}

/// Read the envelope's payload length.
#[inline]
pub fn payload_len(frame: &[u8]) -> u16 {
    u16::from_le_bytes([frame[6], frame[7]])
}

/// Write a complete envelope header into `frame[..FRAME_HDR]`.
#[inline]
pub fn put_header(frame: &mut [u8], conn_id: u32, opcode: u8, fin: u8, payload_len: u16) {
    frame[0..4].copy_from_slice(&conn_id.to_le_bytes());
    frame[4] = opcode;
    frame[5] = fin;
    frame[6..8].copy_from_slice(&payload_len.to_le_bytes());
}
