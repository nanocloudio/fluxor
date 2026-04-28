// QUIC v1 frames (RFC 9000 §19).
//
// Every QUIC packet payload is a sequence of frames. The first byte
// (or varint, for newer types) is the frame type; subsequent fields
// are length-prefixed via the SDK's RFC 9000 §16 variable-length
// integer codec (`varint_*`).
//
// Exposes the frame-type table, parsers for every type, and builders
// for the frames the transport emits.

// ----------------------------------------------------------------------
// Frame type constants (RFC 9000 §19, table 3)
// ----------------------------------------------------------------------

pub const FRAME_PADDING: u8 = 0x00;
pub const FRAME_PING: u8 = 0x01;
pub const FRAME_ACK: u8 = 0x02; // 0x02..0x03
pub const FRAME_ACK_ECN: u8 = 0x03;
pub const FRAME_RESET_STREAM: u8 = 0x04;
pub const FRAME_STOP_SENDING: u8 = 0x05;
pub const FRAME_CRYPTO: u8 = 0x06;
pub const FRAME_NEW_TOKEN: u8 = 0x07;
pub const FRAME_STREAM_BASE: u8 = 0x08; // 0x08..0x0F (LEN/FIN/OFF bits)
pub const FRAME_STREAM_END: u8 = 0x0F;
pub const FRAME_MAX_DATA: u8 = 0x10;
pub const FRAME_MAX_STREAM_DATA: u8 = 0x11;
pub const FRAME_MAX_STREAMS_BIDI: u8 = 0x12;
pub const FRAME_MAX_STREAMS_UNI: u8 = 0x13;
pub const FRAME_DATA_BLOCKED: u8 = 0x14;
pub const FRAME_STREAM_DATA_BLOCKED: u8 = 0x15;
pub const FRAME_STREAMS_BLOCKED_BIDI: u8 = 0x16;
pub const FRAME_STREAMS_BLOCKED_UNI: u8 = 0x17;
pub const FRAME_NEW_CONNECTION_ID: u8 = 0x18;
pub const FRAME_RETIRE_CONNECTION_ID: u8 = 0x19;
pub const FRAME_PATH_CHALLENGE: u8 = 0x1A;
pub const FRAME_PATH_RESPONSE: u8 = 0x1B;
pub const FRAME_CONNECTION_CLOSE_TRANSPORT: u8 = 0x1C;
pub const FRAME_CONNECTION_CLOSE_APP: u8 = 0x1D;
pub const FRAME_HANDSHAKE_DONE: u8 = 0x1E;

// STREAM frame bit flags inside the type byte (RFC 9000 §19.8).
pub const STREAM_FLAG_OFF: u8 = 0x04;
pub const STREAM_FLAG_LEN: u8 = 0x02;
pub const STREAM_FLAG_FIN: u8 = 0x01;

/// Coarse classification used by the transport. Per-frame-type parsing
/// returns this so a caller can dispatch without re-decoding.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Padding,
    Ping,
    Ack,
    ResetStream,
    StopSending,
    Crypto,
    NewToken,
    Stream,
    MaxData,
    MaxStreamData,
    MaxStreams,
    Blocked,
    NewConnectionId,
    RetireConnectionId,
    PathChallenge,
    PathResponse,
    ConnectionClose,
    HandshakeDone,
    Unknown,
}

pub fn classify(frame_type: u64) -> FrameKind {
    match frame_type {
        x if x == FRAME_PADDING as u64 => FrameKind::Padding,
        x if x == FRAME_PING as u64 => FrameKind::Ping,
        0x02 | 0x03 => FrameKind::Ack,
        0x04 => FrameKind::ResetStream,
        0x05 => FrameKind::StopSending,
        0x06 => FrameKind::Crypto,
        0x07 => FrameKind::NewToken,
        0x08..=0x0F => FrameKind::Stream,
        0x10 => FrameKind::MaxData,
        0x11 => FrameKind::MaxStreamData,
        0x12 | 0x13 => FrameKind::MaxStreams,
        0x14..=0x17 => FrameKind::Blocked,
        0x18 => FrameKind::NewConnectionId,
        0x19 => FrameKind::RetireConnectionId,
        0x1A => FrameKind::PathChallenge,
        0x1B => FrameKind::PathResponse,
        0x1C | 0x1D => FrameKind::ConnectionClose,
        0x1E => FrameKind::HandshakeDone,
        _ => FrameKind::Unknown,
    }
}

/// CRYPTO frame contents (RFC 9000 §19.6) extracted by the parser.
pub struct CryptoFrame<'a> {
    pub offset: u64,
    pub data: &'a [u8],
}

/// Parse one CRYPTO frame body assuming the type byte (0x06) has
/// already been consumed by the caller. Returns the frame contents
/// and the number of bytes consumed (the two varints + the data),
/// or None on truncation / malformed varints.
pub fn parse_crypto(body: &[u8]) -> Option<(CryptoFrame<'_>, usize)> {
    let (offset, off_len) =
        unsafe { varint_decode(body.as_ptr(), body.len()) }?;
    let after_off = &body[off_len..];
    let (length, len_len) =
        unsafe { varint_decode(after_off.as_ptr(), after_off.len()) }?;
    let length = length as usize;
    let data_off = off_len + len_len;
    if body.len() < data_off + length {
        return None;
    }
    Some((
        CryptoFrame {
            offset,
            data: &body[data_off..data_off + length],
        },
        data_off + length,
    ))
}

/// STREAM frame contents (RFC 9000 §19.8). `fin` marks end-of-stream;
/// `offset` is 0 for type bytes without OFF bit; `data` is the payload.
pub struct StreamFrame<'a> {
    pub stream_id: u64,
    pub offset: u64,
    pub fin: bool,
    pub data: &'a [u8],
}

/// Parse one STREAM frame. `type_byte` is the consumed first byte
/// (0x08..0x0F); `body` is the payload that follows. Returns the parsed
/// frame plus the number of body bytes consumed.
pub fn parse_stream(type_byte: u8, body: &[u8]) -> Option<(StreamFrame<'_>, usize)> {
    if type_byte < FRAME_STREAM_BASE || type_byte > FRAME_STREAM_END {
        return None;
    }
    let has_off = type_byte & STREAM_FLAG_OFF != 0;
    let has_len = type_byte & STREAM_FLAG_LEN != 0;
    let fin = type_byte & STREAM_FLAG_FIN != 0;

    let (stream_id, sid_len) =
        unsafe { varint_decode(body.as_ptr(), body.len()) }?;
    let mut cursor = sid_len;

    let offset = if has_off {
        let after = &body[cursor..];
        let (v, n) =
            unsafe { varint_decode(after.as_ptr(), after.len()) }?;
        cursor += n;
        v
    } else {
        0
    };

    let length = if has_len {
        let after = &body[cursor..];
        let (v, n) =
            unsafe { varint_decode(after.as_ptr(), after.len()) }?;
        cursor += n;
        v as usize
    } else {
        body.len() - cursor
    };

    if body.len() < cursor + length {
        return None;
    }
    Some((
        StreamFrame {
            stream_id,
            offset,
            fin,
            data: &body[cursor..cursor + length],
        },
        cursor + length,
    ))
}

/// Build an ACK frame (RFC 9000 §19.3) covering the ranges in
/// `tracker`. Returns bytes written, or 0 on buffer overflow / no
/// ranges to acknowledge.
///
/// Ranges in `tracker` are sorted descending by `high`. The wire
/// format starts with the largest acknowledged, then iterates back
/// through gaps + range-lengths.
pub fn build_ack_frame(tracker: &AckTracker, ack_delay: u64, out: &mut [u8]) -> usize {
    if tracker.count == 0 {
        return 0;
    }
    let mut n = tracker.count as usize;
    let largest = tracker.ranges[0].high;
    if tracker.ranges[0].low > tracker.ranges[0].high {
        return 0;
    }
    let first_range = tracker.ranges[0].high - tracker.ranges[0].low;
    // Trim trailing ranges that violate the descending-disjoint invariant
    // rather than emit a corrupt frame. With a correct `coalesce` this
    // can't trigger; the guard is defense-in-depth.
    let mut k = 1;
    while k < n {
        let prev_low = tracker.ranges[k - 1].low;
        let cur_high = tracker.ranges[k].high;
        let cur_low = tracker.ranges[k].low;
        if cur_low > cur_high || prev_low < cur_high + 2 {
            n = k;
            break;
        }
        k += 1;
    }
    let extra_range_count = (n - 1) as u64;

    let mut pos = 0;
    if out.is_empty() {
        return 0;
    }
    out[pos] = FRAME_ACK;
    pos += 1;

    let nb = unsafe { varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, largest) };
    if nb == 0 {
        return 0;
    }
    pos += nb;
    let nb = unsafe { varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, ack_delay) };
    if nb == 0 {
        return 0;
    }
    pos += nb;
    let nb = unsafe {
        varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, extra_range_count)
    };
    if nb == 0 {
        return 0;
    }
    pos += nb;
    let nb = unsafe { varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, first_range) };
    if nb == 0 {
        return 0;
    }
    pos += nb;

    // Subsequent ranges: gap + range_length pairs.
    // RFC 9000 §19.3.1: gap = prev_smallest - cur_largest - 2 (encoded relative).
    // Validation above already trimmed `n` to a prefix where this is safe.
    let mut i = 1;
    while i < n {
        let prev_low = tracker.ranges[i - 1].low;
        let cur_high = tracker.ranges[i].high;
        let gap = prev_low - cur_high - 2;
        let range_len = tracker.ranges[i].high - tracker.ranges[i].low;
        let nb = unsafe { varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, gap) };
        if nb == 0 {
            return 0;
        }
        pos += nb;
        let nb = unsafe { varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, range_len) };
        if nb == 0 {
            return 0;
        }
        pos += nb;
        i += 1;
    }
    pos
}

/// Build a STREAM frame with the OFF + LEN bits set (offset + length
/// explicit). Returns bytes written, or 0 on overflow.
pub fn build_stream(stream_id: u64, offset: u64, fin: bool, data: &[u8], out: &mut [u8]) -> usize {
    let mut type_byte = FRAME_STREAM_BASE | STREAM_FLAG_OFF | STREAM_FLAG_LEN;
    if fin {
        type_byte |= STREAM_FLAG_FIN;
    }
    let sid_size = varint_size(stream_id);
    let off_size = varint_size(offset);
    let len_size = varint_size(data.len() as u64);
    let total = 1 + sid_size + off_size + len_size + data.len();
    if out.len() < total {
        return 0;
    }
    out[0] = type_byte;
    let mut pos = 1;
    let n = unsafe { varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, stream_id) };
    if n == 0 { return 0; }
    pos += n;
    let n = unsafe { varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, offset) };
    if n == 0 { return 0; }
    pos += n;
    let n = unsafe {
        varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, data.len() as u64)
    };
    if n == 0 { return 0; }
    pos += n;
    out[pos..pos + data.len()].copy_from_slice(data);
    pos + data.len()
}

/// Build a NEW_CONNECTION_ID frame (RFC 9000 §19.15). Body:
///   sequence_number (varint) + retire_prior_to (varint) +
///   length (u8, 1..20) + connection_id + stateless_reset_token (16 bytes).
pub fn build_new_connection_id(
    sequence: u64,
    retire_prior_to: u64,
    cid: &[u8],
    stateless_reset_token: &[u8; 16],
    out: &mut [u8],
) -> usize {
    if cid.is_empty() || cid.len() > 20 {
        return 0;
    }
    let mut pos = 0;
    if out.is_empty() { return 0; }
    out[pos] = FRAME_NEW_CONNECTION_ID;
    pos += 1;
    let n = unsafe { varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, sequence) };
    if n == 0 { return 0; }
    pos += n;
    let n = unsafe { varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, retire_prior_to) };
    if n == 0 { return 0; }
    pos += n;
    if pos + 1 + cid.len() + 16 > out.len() { return 0; }
    out[pos] = cid.len() as u8;
    pos += 1;
    out[pos..pos + cid.len()].copy_from_slice(cid);
    pos += cid.len();
    out[pos..pos + 16].copy_from_slice(stateless_reset_token);
    pos + 16
}

/// Build a RETIRE_CONNECTION_ID frame (RFC 9000 §19.16).
pub fn build_retire_connection_id(sequence: u64, out: &mut [u8]) -> usize {
    let mut pos = 0;
    if out.is_empty() { return 0; }
    out[pos] = FRAME_RETIRE_CONNECTION_ID;
    pos += 1;
    let n = unsafe { varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, sequence) };
    if n == 0 { return 0; }
    pos + n
}

/// Build a MAX_DATA frame (RFC 9000 §19.9). Bumps the connection-level
/// flow-control credit the peer may consume.
pub fn build_max_data(maximum_data: u64, out: &mut [u8]) -> usize {
    let mut pos = 0;
    if out.is_empty() { return 0; }
    out[pos] = FRAME_MAX_DATA;
    pos += 1;
    let n = unsafe { varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, maximum_data) };
    if n == 0 { return 0; }
    pos + n
}

/// Build a MAX_STREAM_DATA frame (RFC 9000 §19.10). Bumps the peer's
/// per-stream send window for `stream_id`.
pub fn build_max_stream_data(stream_id: u64, maximum: u64, out: &mut [u8]) -> usize {
    let mut pos = 0;
    if out.is_empty() { return 0; }
    out[pos] = FRAME_MAX_STREAM_DATA;
    pos += 1;
    let n = unsafe { varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, stream_id) };
    if n == 0 { return 0; }
    pos += n;
    let n = unsafe { varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, maximum) };
    if n == 0 { return 0; }
    pos + n
}

/// Build a DATA_BLOCKED frame (RFC 9000 §19.12). Sender uses this to
/// signal it would have written more but for the connection-level cap.
pub fn build_data_blocked(maximum_data: u64, out: &mut [u8]) -> usize {
    let mut pos = 0;
    if out.is_empty() { return 0; }
    out[pos] = FRAME_DATA_BLOCKED;
    pos += 1;
    let n = unsafe { varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, maximum_data) };
    if n == 0 { return 0; }
    pos + n
}

/// Build a CONNECTION_CLOSE frame (RFC 9000 §19.19).
/// `app_layer = false` builds a transport-level close (frame type 0x1c)
/// carrying error_code + frame_type_that_caused + reason_phrase;
/// `app_layer = true` builds an application-level close (frame type
/// 0x1d) without the frame_type field.
pub fn build_connection_close(
    error_code: u64,
    frame_type_cause: u64,
    reason: &[u8],
    app_layer: bool,
    out: &mut [u8],
) -> usize {
    let frame_type: u64 = if app_layer {
        FRAME_CONNECTION_CLOSE_APP as u64
    } else {
        FRAME_CONNECTION_CLOSE_TRANSPORT as u64
    };
    let mut pos = 0;
    let n = unsafe { varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, frame_type) };
    if n == 0 { return 0; }
    pos += n;
    let n = unsafe { varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, error_code) };
    if n == 0 { return 0; }
    pos += n;
    if !app_layer {
        let n = unsafe {
            varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, frame_type_cause)
        };
        if n == 0 { return 0; }
        pos += n;
    }
    let n = unsafe {
        varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, reason.len() as u64)
    };
    if n == 0 { return 0; }
    pos += n;
    if pos + reason.len() > out.len() { return 0; }
    out[pos..pos + reason.len()].copy_from_slice(reason);
    pos + reason.len()
}

/// Build a RESET_STREAM frame (RFC 9000 §19.4).
///   stream_id (varint) + application_protocol_error_code (varint) +
///   final_size (varint).
pub fn build_reset_stream(
    stream_id: u64,
    error_code: u64,
    final_size: u64,
    out: &mut [u8],
) -> usize {
    let mut pos = 0;
    if out.is_empty() { return 0; }
    out[pos] = FRAME_RESET_STREAM;
    pos += 1;
    let n = unsafe { varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, stream_id) };
    if n == 0 { return 0; }
    pos += n;
    let n = unsafe { varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, error_code) };
    if n == 0 { return 0; }
    pos += n;
    let n = unsafe { varint_encode(out.as_mut_ptr().add(pos), out.len() - pos, final_size) };
    if n == 0 { return 0; }
    pos + n
}

/// Build a CRYPTO frame into `out`. Returns the bytes written, or 0
/// if the buffer is too small.
pub fn build_crypto(offset: u64, data: &[u8], out: &mut [u8]) -> usize {
    let off_len = varint_size(offset);
    let len_len = varint_size(data.len() as u64);
    let total = 1 + off_len + len_len + data.len();
    if out.len() < total {
        return 0;
    }
    out[0] = FRAME_CRYPTO;
    let mut cursor = 1;
    let n = unsafe {
        varint_encode(out.as_mut_ptr().add(cursor), out.len() - cursor, offset)
    };
    if n == 0 {
        return 0;
    }
    cursor += n;
    let n = unsafe {
        varint_encode(
            out.as_mut_ptr().add(cursor),
            out.len() - cursor,
            data.len() as u64,
        )
    };
    if n == 0 {
        return 0;
    }
    cursor += n;
    out[cursor..cursor + data.len()].copy_from_slice(data);
    total
}
