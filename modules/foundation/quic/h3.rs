// HTTP/3 connection-preamble framing (RFC 9114) — the part of h3 a
// TRANSPORT owes its application.
//
// Frames carried on a QUIC bidirectional stream are
//   <varint type> <varint length> <payload[length]>
// with the recognised type values declared as the `H3_FRAME_*`
// constants below.
//
// What is here is deliberately only what the connection preamble needs:
// frame header build/parse, and the codecs for the frames this module
// itself speaks on the CONTROL stream — SETTINGS, GOAWAY and
// PRIORITY_UPDATE. Those are connection-scoped, they are exchanged
// before any request exists, and `h3_open_uni_streams` in `mod.rs` must
// emit SETTINGS for the connection to be usable at all.
//
// What is NOT here is the request layer: header field encode/decode
// (QPACK), method/path dispatch, and response generation. Those are
// HTTP semantics, they belong to whatever owns the request streams, and
// this module surfaces those streams to the application over the `mux`
// contract rather than answering them. See `docs/architecture/
// protocol_surfaces.md`, and Wave's `http` module for the other side.

pub const H3_FRAME_DATA: u64 = 0x00;
pub const H3_FRAME_HEADERS: u64 = 0x01;
pub const H3_FRAME_CANCEL_PUSH: u64 = 0x03;
pub const H3_FRAME_SETTINGS: u64 = 0x04;
pub const H3_FRAME_GOAWAY: u64 = 0x07;
pub const H3_FRAME_MAX_PUSH_ID: u64 = 0x0D;
/// PRIORITY_UPDATE frame for request streams (RFC 9218 §7.2):
///   frame type 0xF0700 — encoded as 4-byte varint.
pub const H3_FRAME_PRIORITY_UPDATE_REQUEST: u64 = 0xF0700;
/// PRIORITY_UPDATE frame for push streams (RFC 9218 §7.2):
///   frame type 0xF0701 — also 4-byte varint.
pub const H3_FRAME_PRIORITY_UPDATE_PUSH: u64 = 0xF0701;

// Unidirectional stream type prefixes (RFC 9114 §6.2).
pub const H3_UNI_TYPE_CONTROL: u64 = 0x00;
pub const H3_UNI_TYPE_PUSH: u64 = 0x01;
pub const H3_UNI_TYPE_QPACK_ENCODER: u64 = 0x02;
pub const H3_UNI_TYPE_QPACK_DECODER: u64 = 0x03;

// SETTINGS identifiers (RFC 9114 §7.2.4 + RFC 9204 §5 + RFC 9220 §3).
pub const H3_SETTING_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
pub const H3_SETTING_MAX_FIELD_SECTION_SIZE: u64 = 0x06;
pub const H3_SETTING_QPACK_BLOCKED_STREAMS: u64 = 0x07;
pub const H3_SETTING_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;

/// Build the (type, length) header for an HTTP/3 frame. Returns bytes
/// written. The caller appends the payload separately.
pub unsafe fn h3_build_frame_header(frame_type: u64, payload_len: usize, out: &mut [u8]) -> usize {
    let type_size = varint_size(frame_type);
    let len_size = varint_size(payload_len as u64);
    let total = type_size + len_size;
    if out.len() < total {
        return 0;
    }
    let mut cursor = 0;
    let n = varint_encode(out.as_mut_ptr().add(cursor), out.len() - cursor, frame_type);
    if n == 0 {
        return 0;
    }
    cursor += n;
    let n = varint_encode(
        out.as_mut_ptr().add(cursor),
        out.len() - cursor,
        payload_len as u64,
    );
    if n == 0 {
        return 0;
    }
    cursor + n
}

pub struct H3FrameView<'a> {
    pub frame_type: u64,
    pub payload: &'a [u8],
}

/// Parse one HTTP/3 frame from `buf`. Returns the frame + total bytes
/// consumed (header + payload), or None on truncation.
pub unsafe fn h3_parse_frame(buf: &[u8]) -> Option<(H3FrameView<'_>, usize)> {
    let (frame_type, n1) = varint_decode(buf.as_ptr(), buf.len())?;
    let after = &buf[n1..];
    let (length, n2) = varint_decode(after.as_ptr(), after.len())?;
    let length = length as usize;
    let payload_off = n1 + n2;
    if buf.len() < payload_off + length {
        return None;
    }
    Some((
        H3FrameView {
            frame_type,
            payload: &buf[payload_off..payload_off + length],
        },
        payload_off + length,
    ))
}


// ---------------------------------------------------------------------
// SETTINGS frame helpers (RFC 9114 §7.2.4).
//
// Payload = sequence of (varint id, varint value) pairs.
// ---------------------------------------------------------------------

/// Build a SETTINGS frame body listing the (id, value) pairs in
/// `settings`. Returns bytes written, or 0 on overflow.
pub unsafe fn h3_build_settings_payload(settings: &[(u64, u64)], out: &mut [u8]) -> usize {
    let mut pos = 0;
    let mut i = 0;
    while i < settings.len() {
        let (id, val) = settings[i];
        let n = varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, id);
        if n == 0 {
            return 0;
        }
        pos += n;
        let n = varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, val);
        if n == 0 {
            return 0;
        }
        pos += n;
        i += 1;
    }
    pos
}

/// The peer's HTTP/3 settings, as far as this stack recognises them.
///
/// Everything here is a limit on how a REQUEST is encoded, which is why it is
/// captured rather than discarded: the identifiers arrive on the connection's
/// control stream, which only the transport reads, but they bind the
/// application that owns the request streams. `quic` forwards this over
/// `MSG_MUX_PEER_SETTINGS`.
pub struct H3PeerSettings {
    /// RFC 9114 §7.2.4.1 cap on the uncompressed header-section size.
    /// `u32::MAX` = the identifier was absent, whose default is unlimited.
    /// Distinct from an advertised `0`, which forbids header sections.
    pub max_field_section_size: u32,
    pub qpack_max_table_capacity: u32,
    pub qpack_blocked_streams: u32,
    /// RFC 9220 §3 — the peer permits extended CONNECT.
    pub enable_connect_protocol: bool,
}

impl H3PeerSettings {
    pub const fn defaults() -> Self {
        Self {
            max_field_section_size: u32::MAX,
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
            enable_connect_protocol: false,
        }
    }
}

/// Walk a SETTINGS payload, capturing the identifiers this stack recognises
/// into `out`. Returns false on truncation / malformed varints — the payload is
/// a whole number of (varint id, varint value) pairs with nothing left over, and
/// anything else is H3_FRAME_ERROR (RFC 9114 §7.2.4).
///
/// Unrecognised identifiers are skipped, not rejected: RFC 9114 §7.2.4.1
/// requires reserved and unknown settings to be ignored, and the greasing
/// identifiers exist precisely to catch an implementation that does not.
///
/// **Fills a fixed struct; takes no callback.** A per-entry
/// `&mut dyn FnMut(u64, u64)` is a trait object, and a trait object is a
/// vtable: these modules are position-independent with no relocation
/// processing for one, so calling through it jumps to an unrelocated address.
/// That failure is invisible to both the build and the host harness — it
/// segfaults the runtime the first time a peer's SETTINGS arrives, which is
/// immediately after the handshake completes.
pub unsafe fn h3_parse_settings(payload: &[u8], out: &mut H3PeerSettings) -> bool {
    let mut pos = 0;
    while pos < payload.len() {
        let after = &payload[pos..];
        let (id, n1) = match varint_decode(after.as_ptr(), after.len()) {
            Some(t) => t,
            None => return false,
        };
        pos += n1;
        let after = &payload[pos..];
        let (val, n2) = match varint_decode(after.as_ptr(), after.len()) {
            Some(t) => t,
            None => return false,
        };
        pos += n2;
        // The wire type is a varint up to 2^62; these fields are u32. Saturate
        // rather than truncate — a truncated 2^32 would read as 0, which for
        // `max_field_section_size` means "no header section may be sent" and
        // would wedge every request on the connection. Saturation is lossless
        // in effect: nothing this stack emits approaches u32::MAX.
        let val32 = if val > u32::MAX as u64 {
            u32::MAX
        } else {
            val as u32
        };
        if id == H3_SETTING_MAX_FIELD_SECTION_SIZE {
            out.max_field_section_size = val32;
        } else if id == H3_SETTING_QPACK_MAX_TABLE_CAPACITY {
            out.qpack_max_table_capacity = val32;
        } else if id == H3_SETTING_QPACK_BLOCKED_STREAMS {
            out.qpack_blocked_streams = val32;
        } else if id == H3_SETTING_ENABLE_CONNECT_PROTOCOL {
            out.enable_connect_protocol = val == 1;
        }
    }
    true
}

// ----------------------------------------------------------------------
// GOAWAY frame (RFC 9114 §5.2 + §7.2.6)
//
// Body = single varint: highest stream ID for which the receiver MAY
// have committed processing (push id on push direction). Sent on the
// control stream to cleanly drain the connection.
// ----------------------------------------------------------------------

pub unsafe fn h3_build_goaway(stream_id_or_push: u64, out: &mut [u8]) -> usize {
    let payload_size = varint_size(stream_id_or_push);
    let mut hdr = [0u8; 8];
    let hdr_n = h3_build_frame_header(H3_FRAME_GOAWAY, payload_size, &mut hdr);
    if hdr_n == 0 || hdr_n + payload_size > out.len() {
        return 0;
    }
    out[..hdr_n].copy_from_slice(&hdr[..hdr_n]);
    let n = varint_encode(out.as_mut_ptr().add(hdr_n), out.len() - hdr_n, stream_id_or_push);
    if n == 0 {
        return 0;
    }
    hdr_n + n
}

pub unsafe fn h3_parse_goaway(payload: &[u8]) -> Option<u64> {
    let (id, _n) = varint_decode(payload.as_ptr(), payload.len())?;
    Some(id)
}

// ----------------------------------------------------------------------
// PRIORITY_UPDATE frame (RFC 9218 §7.2)
//
// Body = varint Prioritized Element ID + ASCII Priority Field Value
// (e.g. "u=3, i" — urgency + incremental flag, RFC 9218 §4.1).
// We parse the prioritized element ID and surface the priority value
// for inspection; the scheduler does not yet honor `urgency` or
// `incremental` to interleave streams.
// ----------------------------------------------------------------------

pub struct ParsedPriorityUpdate<'a> {
    pub prioritized_id: u64,
    pub field_value: &'a [u8],
}

pub unsafe fn h3_parse_priority_update<'a>(payload: &'a [u8]) -> Option<ParsedPriorityUpdate<'a>> {
    let (id, n) = varint_decode(payload.as_ptr(), payload.len())?;
    if n > payload.len() {
        return None;
    }
    Some(ParsedPriorityUpdate {
        prioritized_id: id,
        field_value: &payload[n..],
    })
}
