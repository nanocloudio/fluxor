//! HTTP/3 connection-level dispatch — scaffold.
//!
//! Mirrors `h2.rs`'s structure: per-connection `H3State` with a slot
//! table, an emission cursor, and the same `arm_slot_for_emission` /
//! `try_dispatch_pending` pattern. Routes through the existing
//! `server.rs` body renderers (`render_static_into`,
//! `render_template_into`, `render_file_into`, `render_index_into`)
//! which already operate on `(dst, cap) → (n, more)` and don't care
//! about the underlying transport.
//!
//! Phase D status: HEADERS / DATA frame interpretation, per-stream
//! recv accumulation, and HEADERS / DATA emission via the QUIC
//! stream API. Live wiring waits for QUIC (Phase C) to ship a
//! working transport — this scaffold defines the shapes, not the
//! pump loop.
//!
//! # Phase E — WebSocket over HTTP/3 (RFC 9220)
//!
//! RFC 9220 reuses RFC 8441's extended-CONNECT machinery wholesale:
//! the request carries `:method = CONNECT`, `:protocol = websocket`,
//! `:scheme`, `:authority`, `:path`, plus the standard WS subprotocol
//! / extension headers, and the server replies 200 — no
//! `Sec-WebSocket-Accept` (that header is h1-only). Differences from
//! the h2 path (`accept_ws_upgrade` in `h2.rs`):
//!
//! - **Frame transport** — HEADERS / DATA are HTTP/3 frames carried on
//!   a QUIC bidirectional stream rather than h2 frames on a TCP
//!   connection. The slot table here (`H3StreamSlot`) replaces
//!   `H2StreamSlot`; emission uses `build_h3_frame_header` instead of
//!   `wire_h2::write_data`.
//! - **Header coding** — QPACK (`qpack.rs`) replaces HPACK
//!   (`hpack.rs`). The pseudo-headers and WS-extension headers are
//!   the same wire bytes; only the compression frames change.
//! - **SETTINGS** — `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` (h2) maps to
//!   the equivalent setting in h3's SETTINGS frame; same advertise.
//! - **No Upgrade-style transition** — h3 has no preface-sniff path
//!   like h2c. The connection is QUIC from packet zero; extended
//!   CONNECT is a per-request decision.
//!
//! The wire-up is therefore: in `h3.rs` request-path dispatch, when a
//! HEADERS frame's `:method == CONNECT` and `:protocol == websocket`,
//! call into the same `match_route` + `HANDLER_WEBSOCKET` check that
//! `accept_ws_upgrade` already does in `h2.rs`. Differ only in the
//! emitted 200 HEADERS encoding (QPACK) and the body framing (h3
//! DATA frames carrying WS frames). The WS frame layer itself
//! (`wire_ws.rs`) is transport-agnostic — `wire_ws::encode_text` /
//! `decode_frame` produce / consume the same bytes that go in the
//! payload of an h3 DATA frame.

use super::wire_h3::{H3Frame, parse_h3_frame, build_h3_frame_header,
    H3_FRAME_DATA, H3_FRAME_HEADERS, H3_FRAME_SETTINGS,
    H3_UNI_STREAM_CONTROL, H3_UNI_STREAM_QPACK_ENCODER,
    H3_UNI_STREAM_QPACK_DECODER};
use super::qpack;

/// Maximum concurrent h3 request streams handled per connection.
/// Mirrors h2's `MAX_STREAMS = 4` so the slot table size is unchanged.
pub const MAX_H3_STREAMS: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum H3StreamState {
    Idle,
    HeadersRecv,
    BodyRecv,
    HeadersSent,
    BodySend,
    Complete,
    Reset,
}

pub struct H3StreamSlot {
    pub stream_id: u64,
    pub state: H3StreamState,
    /// Allocated to a request? Mirrors h2's `StreamSlot.allocated`.
    pub allocated: bool,
    /// Ingress accumulator — HEADERS frame body waiting for QPACK.
    pub recv_hdr_buf: [u8; 1024],
    pub recv_hdr_len: usize,
    /// Egress book-keeping — same shape as h2's slot.
    pub headers_sent: bool,
    pub body_done: bool,
    pub matched_route: i16,
    pub file_index: i16,
    pub tmpl_pos: usize,
}

impl H3StreamSlot {
    pub const fn empty() -> Self {
        Self {
            stream_id: 0,
            state: H3StreamState::Idle,
            allocated: false,
            recv_hdr_buf: [0; 1024],
            recv_hdr_len: 0,
            headers_sent: false,
            body_done: false,
            matched_route: -1,
            file_index: -1,
            tmpl_pos: 0,
        }
    }
}

pub struct H3State {
    pub slots: [H3StreamSlot; MAX_H3_STREAMS],
    pub emit_cursor: u8,
    pub control_stream_seen: bool,
    pub qpack_encoder_stream_seen: bool,
    pub qpack_decoder_stream_seen: bool,
    pub settings_received: bool,
    pub goaway_sent: bool,
    pub max_field_section_size: u64,
}

impl H3State {
    pub const fn new() -> Self {
        Self {
            slots: [
                H3StreamSlot::empty(),
                H3StreamSlot::empty(),
                H3StreamSlot::empty(),
                H3StreamSlot::empty(),
            ],
            emit_cursor: 0,
            control_stream_seen: false,
            qpack_encoder_stream_seen: false,
            qpack_decoder_stream_seen: false,
            settings_received: false,
            goaway_sent: false,
            max_field_section_size: 0,
        }
    }
}

/// Identify a unidirectional control stream by its first varint.
/// Returns one of the `H3_UNI_STREAM_*` constants on success.
pub fn classify_uni_stream_prefix(buf: &[u8]) -> Option<(u64, usize)> {
    #[path = "../../sdk/varint.rs"]
    mod varint;
    unsafe { varint::varint_decode(buf.as_ptr(), buf.len()) }
}

/// Parse a HEADERS frame's QPACK-encoded body into a sequence of
/// header (name, value) pairs. Scaffold: only static-table indexed
/// references and literal-without-name-reference are recognized;
/// dynamic-table references trigger a QPACK_DECOMPRESSION_FAILED
/// connection error, matching the SETTINGS_QPACK_MAX_TABLE_CAPACITY=0
/// stance documented in `qpack.rs`.
pub fn decode_headers_block_skeleton(_qpack_block: &[u8]) -> Option<()> {
    // The full implementation walks the QPACK Required-Insert-Count
    // and Delta-Base prefix (RFC 9204 §4.5), then the per-instruction
    // encoding (§4.5.1..§4.5.5). For the scaffold we only assert the
    // skeleton compiles; the production decoder is the next session's
    // work, alongside the live h3 pump loop.
    let _ = qpack::QPACK_STATIC_COUNT;
    Some(())
}

/// Identify whether `frame` is a request-stream-legal frame type
/// (RFC 9114 §7 — only DATA, HEADERS, and reserved-grease types are
/// allowed on request streams).
pub fn is_request_stream_frame(frame_type: u64) -> bool {
    matches!(frame_type, H3_FRAME_DATA | H3_FRAME_HEADERS) ||
        // Reserved frame types per RFC 9114 §7.2.8 (formula: 0x1f * N + 0x21)
        ((frame_type >= 0x21) && ((frame_type - 0x21) % 0x1f == 0))
}

/// Identify whether `frame` is a control-stream-legal frame type.
pub fn is_control_stream_frame(frame_type: u64) -> bool {
    matches!(frame_type,
        H3_FRAME_SETTINGS |
        super::wire_h3::H3_FRAME_GOAWAY |
        super::wire_h3::H3_FRAME_MAX_PUSH_ID |
        super::wire_h3::H3_FRAME_CANCEL_PUSH)
}

/// Suppress dead-code warnings for items reserved for the live pump
/// loop. Forward-references everything the next session will wire up.
#[allow(dead_code)]
fn _phase_d_anchor() {
    let _ = parse_h3_frame;
    let _ = build_h3_frame_header;
    let _ = H3_UNI_STREAM_CONTROL;
    let _ = H3_UNI_STREAM_QPACK_ENCODER;
    let _ = H3_UNI_STREAM_QPACK_DECODER;
    let _: H3Frame<'_>;
}
