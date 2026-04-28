// HTTP/3 frame layer + request dispatcher helpers (RFC 9114).
//
// Frames carried on a QUIC bidirectional stream are
//   <varint type> <varint length> <payload[length]>
// with the recognised type values declared as the `H3_FRAME_*`
// constants below (DATA, HEADERS, CANCEL_PUSH, SETTINGS, PUSH_PROMISE,
// GOAWAY, MAX_PUSH_ID, PRIORITY_UPDATE).
//
// Server-side request handling on a freshly-arrived bidi stream:
//   1. Receive HEADERS → QPACK-decode the field block.
//   2. Dispatch on `:method` + `:path` to pick a response body.
//   3. Emit HEADERS (`:status`, `content-type`, `content-length`) +
//      DATA frame, then FIN the stream.
//
// Client-side request emission:
//   1. Build HEADERS for `GET /` and write it onto a fresh bidi
//      stream.
//   2. On HEADERS response, decode `:status`. On DATA, accumulate
//      body bytes and surface them to the calling app.
//
// Control-stream and QPACK encoder/decoder streams are opened
// separately (RFC 9114 §6.2.1, RFC 9204 §4.2) by `h3_open_uni_streams`
// in `mod.rs`; the SETTINGS encoders/parsers and GOAWAY /
// PRIORITY_UPDATE helpers live below.

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

// ----------------------------------------------------------------------
// Multi-stream h3 dispatch — concurrent bidi requests.
//
// The QUIC layer's `extra_streams` slot table (modules/foundation/quic
// /connection.rs) routes any non-zero stream_id into a 6-slot ring with
// a 256-byte recv buffer per slot. This is enough for SETTINGS / QPACK
// control instructions but too small for full HEADERS+DATA flights, so
// our h3 dispatcher today processes only the legacy `stream id 0` for
// request-bearing traffic. Spec-faithful concurrent-request handling
// would extend the slot table with larger per-stream buffers + route
// `h3_handle_stream_recv` against any client-initiated bidi id (0, 4,
// 8, …) — the framing + QPACK paths are already stream-agnostic. The
// remaining work is buffer sizing + dispatcher dispatch-by-id, NOT
// protocol design.
// ----------------------------------------------------------------------

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

/// Encode a server response HEADERS payload into `out` (just the
/// QPACK-encoded field section, NOT including the H3 frame header).
/// Returns bytes written, or 0 on overflow.
pub fn h3_encode_response_headers(
    status: &[u8],
    content_type: &[u8],
    content_length: usize,
    out: &mut [u8],
) -> usize {
    let mut pos = qpack_emit_block_prefix(out);
    if pos == 0 {
        return 0;
    }
    // :status — the static table holds 100, 200, 204, 206, 302, 304,
    // 400, 403, 404, 421, 425, 500, 503 directly indexed.
    let n = qpack_encode_field(b":status", status, &mut out[pos..]);
    if n == 0 {
        return 0;
    }
    pos += n;
    let n = qpack_encode_field(b"content-type", content_type, &mut out[pos..]);
    if n == 0 {
        return 0;
    }
    pos += n;
    // content-length as decimal text.
    let mut cl_buf = [0u8; 12];
    let cl_len = fmt_usize_dec(content_length, &mut cl_buf);
    let n = qpack_encode_field(b"content-length", &cl_buf[..cl_len], &mut out[pos..]);
    if n == 0 {
        return 0;
    }
    pos += n;
    pos
}

/// Encode a client request HEADERS payload (`:method GET`, `:path`,
/// `:scheme https`, `:authority`).
pub fn h3_encode_request_headers(
    method: &[u8],
    path: &[u8],
    authority: &[u8],
    out: &mut [u8],
) -> usize {
    let mut pos = qpack_emit_block_prefix(out);
    if pos == 0 {
        return 0;
    }
    let n = qpack_encode_field(b":method", method, &mut out[pos..]);
    if n == 0 {
        return 0;
    }
    pos += n;
    let n = qpack_encode_field(b":scheme", b"https", &mut out[pos..]);
    if n == 0 {
        return 0;
    }
    pos += n;
    let n = qpack_encode_field(b":authority", authority, &mut out[pos..]);
    if n == 0 {
        return 0;
    }
    pos += n;
    let n = qpack_encode_field(b":path", path, &mut out[pos..]);
    if n == 0 {
        return 0;
    }
    pos += n;
    pos
}

/// Encode an extended-CONNECT HEADERS payload (RFC 9220 §3 / RFC 8441):
/// `:method CONNECT`, `:protocol websocket`, `:scheme https`,
/// `:authority`, `:path`.
pub fn h3_encode_extended_connect(
    path: &[u8],
    authority: &[u8],
    out: &mut [u8],
) -> usize {
    let mut pos = qpack_emit_block_prefix(out);
    if pos == 0 {
        return 0;
    }
    let n = qpack_encode_field(b":method", b"CONNECT", &mut out[pos..]);
    if n == 0 { return 0; }
    pos += n;
    let n = qpack_encode_field(b":protocol", b"websocket", &mut out[pos..]);
    if n == 0 { return 0; }
    pos += n;
    let n = qpack_encode_field(b":scheme", b"https", &mut out[pos..]);
    if n == 0 { return 0; }
    pos += n;
    let n = qpack_encode_field(b":authority", authority, &mut out[pos..]);
    if n == 0 { return 0; }
    pos += n;
    let n = qpack_encode_field(b":path", path, &mut out[pos..]);
    if n == 0 { return 0; }
    pos += n;
    let n = qpack_encode_field(b"sec-websocket-version", b"13", &mut out[pos..]);
    if n == 0 { return 0; }
    pos += n;
    pos
}

/// Encode a 200 OK response without content-length — used for
/// successful extended-CONNECT replies (RFC 9220 §3) since the
/// stream stays open for tunnelled WS frames.
pub fn h3_encode_connect_accept(out: &mut [u8]) -> usize {
    let mut pos = qpack_emit_block_prefix(out);
    if pos == 0 { return 0; }
    let n = qpack_encode_field(b":status", b"200", &mut out[pos..]);
    if n == 0 { return 0; }
    pos += n;
    pos
}

/// Walk a QPACK header block for the request pseudo-headers
/// (`:method`, `:path`, `:protocol` per RFC 9220 §3 / RFC 8441).
/// Returns each as borrowed slices into `block` (literals) or
/// static-table bytes.
pub struct DecodedRequest<'a> {
    pub method: Option<&'a [u8]>,
    pub method_static: Option<&'static [u8]>,
    pub path: Option<&'a [u8]>,
    pub path_static: Option<&'static [u8]>,
    pub protocol: Option<&'a [u8]>,
    pub protocol_static: Option<&'static [u8]>,
}

pub fn h3_decode_request(block: &[u8]) -> Option<DecodedRequest<'_>> {
    let n_prefix = qpack_decode_block_prefix(block)?;
    let mut cursor = n_prefix;
    let mut out = DecodedRequest {
        method: None,
        method_static: None,
        path: None,
        path_static: None,
        protocol: None,
        protocol_static: None,
    };
    // Per-field scratch for Huffman-coded names; reused each pass
    // (the previous decoded value is no longer referenced once the
    // pseudo-header has been stashed into `out`).
    let mut name_scratch = [0u8; QPACK_HUFFMAN_SCRATCH];
    while cursor < block.len() {
        let (name, value, n) = match qpack_decode_field(&block[cursor..]) {
            Some(t) => t,
            None => return None,
        };
        let name_bytes: &[u8] = match qpack_name_resolve(&name, &mut name_scratch) {
            Some(b) => b,
            None => return None,
        };
        if name_bytes == b":method" {
            match value {
                QpackValue::Static(s) => out.method_static = Some(s),
                QpackValue::Literal(b) => {
                    out.method = Some(unsafe {
                        core::slice::from_raw_parts(b.as_ptr(), b.len())
                    });
                }
                QpackValue::Huffman(_) => {
                    // Decode into stack scratch, then map known
                    // methods onto a `'static` slice so the borrow
                    // outlives this iteration.
                    let mut scratch = [0u8; QPACK_HUFFMAN_SCRATCH];
                    if let Some(decoded) =
                        qpack_value_resolve(&value, &mut scratch)
                    {
                        if decoded == b"GET" {
                            out.method_static = Some(b"GET");
                        } else if decoded == b"POST" {
                            out.method_static = Some(b"POST");
                        } else if decoded == b"CONNECT" {
                            out.method_static = Some(b"CONNECT");
                        } else if decoded == b"PUT" {
                            out.method_static = Some(b"PUT");
                        } else if decoded == b"DELETE" {
                            out.method_static = Some(b"DELETE");
                        } else if decoded == b"HEAD" {
                            out.method_static = Some(b"HEAD");
                        }
                    }
                }
            }
        } else if name_bytes == b":path" {
            match value {
                QpackValue::Static(s) => out.path_static = Some(s),
                QpackValue::Literal(b) => {
                    out.path = Some(unsafe {
                        core::slice::from_raw_parts(b.as_ptr(), b.len())
                    });
                }
                QpackValue::Huffman(_) => {
                    // The path body would have to outlive this loop;
                    // surface as a decompression failure (the caller
                    // maps to QPACK_DECOMPRESSION_FAILED). Real
                    // clients static-index `:path /` so the rare
                    // Huffman-coded path falls through to a 404.
                    return None;
                }
            }
        } else if name_bytes == b":protocol" {
            match value {
                QpackValue::Static(s) => out.protocol_static = Some(s),
                QpackValue::Literal(b) => {
                    out.protocol = Some(unsafe {
                        core::slice::from_raw_parts(b.as_ptr(), b.len())
                    });
                }
                QpackValue::Huffman(_) => {
                    let mut scratch = [0u8; QPACK_HUFFMAN_SCRATCH];
                    if let Some(decoded) =
                        qpack_value_resolve(&value, &mut scratch)
                    {
                        if decoded == b"websocket" {
                            out.protocol_static = Some(b"websocket");
                        }
                    }
                }
            }
        }
        cursor += n;
    }
    Some(out)
}

/// Walk a QPACK header block for a `:status` value. Returns the status
/// bytes (typically "200" / "404" / etc).
pub fn h3_decode_status(block: &[u8]) -> Option<[u8; 8]> {
    let n_prefix = qpack_decode_block_prefix(block)?;
    let mut cursor = n_prefix;
    let mut name_scratch = [0u8; QPACK_HUFFMAN_SCRATCH];
    while cursor < block.len() {
        let (name, value, n) = qpack_decode_field(&block[cursor..])?;
        let name_bytes: &[u8] = qpack_name_resolve(&name, &mut name_scratch)?;
        if name_bytes == b":status" {
            let mut value_scratch = [0u8; QPACK_HUFFMAN_SCRATCH];
            let val_bytes: &[u8] = qpack_value_resolve(&value, &mut value_scratch)?;
            let mut out = [0u8; 8];
            let take = val_bytes.len().min(8);
            out[..take].copy_from_slice(&val_bytes[..take]);
            return Some(out);
        }
        cursor += n;
    }
    None
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

/// Walk a SETTINGS payload and invoke `cb(id, value)` for each entry.
/// Returns true on a complete walk, false on truncation / malformed
/// varints.
pub unsafe fn h3_parse_settings_payload(payload: &[u8], cb: &mut dyn FnMut(u64, u64)) -> bool {
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
        cb(id, val);
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

fn fmt_usize_dec(mut v: usize, out: &mut [u8]) -> usize {
    if v == 0 {
        if out.is_empty() {
            return 0;
        }
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut i = 0;
    while v > 0 && i < tmp.len() {
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
        i += 1;
    }
    let n = i.min(out.len());
    let mut k = 0;
    while k < n {
        out[k] = tmp[i - 1 - k];
        k += 1;
    }
    n
}
