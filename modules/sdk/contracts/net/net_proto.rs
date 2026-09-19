// Contract: net_proto — Stream Surface v1.
//
// Layer: contracts/net (public, stable).
//
// In the protocol-surface taxonomy (docs/architecture/protocol_surfaces.md)
// this contract is **Stream Surface v1**: its upstream commands and
// downstream events match the stream surface vocabulary directly and
// are consumed unchanged by HTTP, MQTT, and TLS.
//
// Stream only. Datagram traffic (UDP and friends) lives on the
// `datagram` surface in the sibling `datagram.rs`; packet-preserving
// flows (QUIC/SRTP/classifiers) live on `packet.rs`. Opcode ranges
// are disjoint across the three so a shared channel can carry multiple
// contracts unambiguously.
//
// Frame format: [msg_type: u8] [len: u16 LE] [payload: len bytes]
// Carried over channels between IP / TLS / HTTP / MQTT modules. The
// kernel does not interpret these bytes — protocol state lives entirely
// in the modules.

/// Frame header size (msg_type + len).
pub const FRAME_HDR: usize = 3;

/// Wire width of a connection id (u16 LE — see the limit register:
/// 65,535 ids; the R1 conn tables bind long before the id space does).
pub const CONN_ID_LEN: usize = 2;

/// Read the leading `conn_id` of a payload. Callers bounds-check
/// `payload.len() >= CONN_ID_LEN` first (frame validation).
#[inline]
pub fn conn_id(payload: &[u8]) -> u16 {
    u16::from_le_bytes([payload[0], payload[1]])
}

/// Write `conn_id` into the leading bytes of a payload.
#[inline]
pub fn put_conn_id(payload: &mut [u8], conn_id: u16) {
    payload[0..2].copy_from_slice(&conn_id.to_le_bytes());
}

/// Parts of a `MSG_CONNECTED` payload: `(conn_id, requester_tag)`.
///
/// The 2-byte form carries no tag and yields `REQUESTER_TAG_NONE`.
/// Callers bounds-check `payload.len() >= CONN_ID_LEN` first (frame
/// validation), as with `conn_id`.
#[inline]
pub fn connected_parts(payload: &[u8]) -> (u16, u8) {
    let tag = if payload.len() > CONN_ID_LEN {
        payload[CONN_ID_LEN]
    } else {
        REQUESTER_TAG_NONE
    };
    (conn_id(payload), tag)
}

/// Parts of a `MSG_ERROR` payload: `(conn_id, errno, requester_tag)`.
///
/// The 3-byte form carries no tag and yields `REQUESTER_TAG_NONE` — an
/// UNTAGGED error is an established-connection error and routes by
/// `conn_id`; a TAGGED error is a connect-phase failure and is attributed
/// by tag ALONE, because its `conn_id` is meaningless on that path (see
/// `MSG_ERROR`). This accessor exists so no consumer re-derives that
/// discriminator from literal offsets — mis-reading it is exactly how a
/// module claims another module's connect failure. Callers bounds-check
/// `payload.len() >= CONN_ID_LEN + 1` first.
#[inline]
pub fn error_parts(payload: &[u8]) -> (u16, i8, u8) {
    let errno = payload[CONN_ID_LEN] as i8;
    let tag = if payload.len() > CONN_ID_LEN + 1 {
        payload[CONN_ID_LEN + 1]
    } else {
        REQUESTER_TAG_NONE
    };
    (conn_id(payload), errno, tag)
}

/// Parts of a `MSG_ACCEPTED` / `MSG_BOUND` payload: `(conn_id, local_port)`.
/// Callers bounds-check `payload.len() >= CONN_ID_LEN + 2` first; a consumer
/// that ignores the port reads just `conn_id`.
#[inline]
pub fn accepted_parts(payload: &[u8]) -> (u16, u16) {
    (
        conn_id(payload),
        u16::from_le_bytes([payload[CONN_ID_LEN], payload[CONN_ID_LEN + 1]]),
    )
}

// Downstream: IP/net → consumer
/// New connection accepted. Payload: `[conn_id: u16 LE][local_port: u16 LE]`.
/// `local_port` is the listener port the connection was accepted on. When
/// `net_out` is fanned to several stream consumers each bound to a
/// distinct port (a multi-anchor graph), every consumer filters on
/// `local_port` and claims only the connections accepted on its own
/// `CMD_BIND` — otherwise they would all `alloc` the same `conn_id` and
/// corrupt each other's subsequent `MSG_DATA`. A single-consumer graph
/// may ignore the trailing port bytes and read just `conn_id`.
pub const MSG_ACCEPTED: u8 = 0x01;
/// Received data. Payload: `[conn_id: u16 LE][data…]`. The `data` portion of a
/// single `MSG_DATA` frame MUST NOT exceed [`MAX_DATA_FRAGMENT`] — a producer
/// that has more bytes splits them across multiple frames. This bounds every
/// consumer's per-frame scratch (so the alignment-safe reader never has to drop
/// a tail) and matches the natural TCP-MSS segmentation of the bare-metal stack.
pub const MSG_DATA: u8 = 0x02;

/// Normative maximum `data` bytes in one [`MSG_DATA`] frame (one TCP MSS). A
/// `net_out` producer (IP, the Linux host adapter, …) chunks larger reads into
/// multiple frames; a consumer may therefore size its frame scratch to
/// `FRAME_HDR + CONN_ID_LEN + MAX_DATA_FRAGMENT` and be sure a whole frame always fits.
pub const MAX_DATA_FRAGMENT: usize = 1460;
/// Remote closed connection. Payload: `[conn_id: u16 LE]`
///
/// Release rule. After `MSG_CLOSED` the connection id stays RESERVED for the
/// consumer's [`CMD_CLOSE`]: the transport does not hand it to a new accept
/// until the consumer has closed or a bounded grace interval has elapsed
/// ([`CLOSED_ID_GRACE_MS`]). So a consumer may always answer `MSG_CLOSED`
/// with `CMD_CLOSE` and never hit a newcomer, and a consumer that never
/// answers cannot leak the id for good. Both transports implement it: the
/// bare-metal `ip` (which holds the TCP slot in CloseWait until the close,
/// then times it out) and the Linux host adapter (which holds the freed
/// slot's id for the grace interval). Without the rule the two failure
/// modes meet: a transport that holds CloseWait indefinitely, and a consumer
/// that withholds its close because some other transport freed the id
/// underneath it — between them every client-closed keepalive connection
/// leaks a slot until the table is full.
pub const MSG_CLOSED: u8 = 0x03;
/// How long a transport keeps a closed connection's id reserved for the
/// consumer's [`CMD_CLOSE`] after [`MSG_CLOSED`] before releasing it itself.
/// Five seconds: several scheduler passes on the slowest target and far
/// longer than any consumer takes to notice a close, while short enough that
/// a consumer which never closes cannot pin a 16-slot table through a burst.
pub const CLOSED_ID_GRACE_MS: u32 = 5_000;
/// Bind/listen completed. Payload: `[conn_id: u16 LE][local_port: u16 LE]`.
/// `local_port` echoes the port from the consumer's `CMD_BIND`; a
/// multi-anchor consumer records it and matches it against the
/// `local_port` in subsequent `MSG_ACCEPTED` frames (see `MSG_ACCEPTED`).
pub const MSG_BOUND: u8 = 0x04;
/// Outbound connect completed. Payload: `[conn_id: u16 LE][requester_tag: u8]`.
/// `requester_tag` echoes the tag the consumer put on its `CMD_CONNECT_TO` (its
/// module index **+ 1** — the `dev_requester_tag` wire encoding, NOT the raw
/// index) so that when `ip.net_out` is fanned to several stream consumers (e.g.
/// TLS + an OTLP exporter), each claims only the connections it opened. A
/// consumer that doesn't filter just reads `conn_id` and ignores the trailing
/// byte; untagged connects echo tag `0` (`REQUESTER_TAG_NONE`).
pub const MSG_CONNECTED: u8 = 0x05;
/// Error. Payload: `[conn_id: u16 LE][errno: i8][requester_tag: u8?]`. For a
/// connect-phase failure the trailing `requester_tag` echoes the failing
/// `CMD_CONNECT_TO`'s tag so a consumer that has no conn_id yet can recognise its
/// own failure on a fanned `net_out`; established-connection errors carry the
/// owning connection's conn_id (filter by that). 3-byte form = tag 0.
/// On a connect-phase failure `conn_id` is MEANINGLESS — it is the id already
/// allocated if the dial failed after allocation, and `0` if it failed before
/// (bad `sock_type`, no free slot), which is indistinguishable from a valid id
/// `0` — so a consumer must match a connect failure on `requester_tag` ALONE,
/// never on a conn_id it has not yet been assigned.
pub const MSG_ERROR: u8 = 0x06;
// 0x07 / 0x08 are reserved: the IP module privately uses them for
// `MSG_RETRANSMIT` / `MSG_ACK` (consumer-side retransmit + send-buffer release)
// on the same channel. The next free downstream opcode is 0x09.

/// Observability trace context for a connection (W3C). Emitted by the ingress
/// (IP) right after `MSG_ACCEPTED`, and re-emitted by each forwarding stage
/// (TLS) with its own span id, so the next stage parents its span correctly.
/// Payload: `[conn_id: u16 LE][trace_id: 16][parent_span_id: 8][trace_flags: u8]`
/// (27 bytes). Purely additive and best-effort (direct write, dropped if the
/// channel is full) — a stage that doesn't trace discards it like any unknown
/// frame, so it never affects the data path. The trailing `trace_flags` byte is
/// the W3C flags (low bit = `sampled`), so the head-sampling decision survives
/// each hop. See `standards/observability.md`.
pub const MSG_TRACE_CTX: u8 = 0x09;

/// `MSG_TRACE_CTX` payload length: conn_id + 16-byte trace id + 8-byte span id
/// + 1-byte W3C trace-flags.
pub const TRACE_CTX_LEN: usize = CONN_ID_LEN + 16 + 8 + 1;

// Upstream: consumer → IP/net
/// Bind to port and listen. Payload: [port: u16 LE]
pub const CMD_BIND: u8 = 0x10;
/// Send data on connection. Payload: `[conn_id: u16 LE][data…]`. The `data` portion
/// MUST NOT exceed [`MAX_CMD_DATA`]; a consumer with more bytes issues multiple
/// `CMD_SEND`s. The net stack (IP / host adapter) re-segments to MSS on the
/// wire. This bounds the receiver's command scratch; an oversized frame is
/// drained and rejected alignment-safely rather than mis-parsed.
pub const CMD_SEND: u8 = 0x11;

/// Normative maximum `data` bytes in one upstream command frame (`CMD_SEND`).
/// Receivers (IP, the Linux host adapter) size their command scratch to
/// `FRAME_HDR + CONN_ID_LEN + MAX_CMD_DATA` and drain anything larger to stay frame-aligned.
pub const MAX_CMD_DATA: usize = 8192;
/// Close connection. Payload: `[conn_id: u16 LE]`
///
/// Always safe after [`MSG_CLOSED`] within [`CLOSED_ID_GRACE_MS`] — the id
/// is still the consumer's — and a no-op on an id the transport has already
/// released.
pub const CMD_CLOSE: u8 = 0x12;
/// RETIRED. The 7/8-byte `[sock_type][ip: u32 LE][port: u16 LE][tag?]`
/// dial. Every provider answers it with `MSG_ERROR` `ENOSYS` on the
/// requester tag (byte 7 when present) and one log line naming
/// [`CMD_CONNECT_TO`], so a stale emitter fails loudly on its first dial
/// instead of dialling a garbage address: byte 1 of this payload is the
/// address's last octet, which would alias `af` if the two shapes shared
/// an opcode. One opcode dials; this one only says no.
pub const CMD_CONNECT: u8 = 0x13;

/// Initiate an outbound connection to a target.
/// Payload: `[sock_type: u8][af: u8][port: u16 LE][addr…][requester_tag: u8?]`
///
/// - `af = AF_INET (4)`: `addr` is 4 bytes, network order.
/// - `af = AF_INET6 (6)`: `addr` is 16 bytes, network order.
/// - `af = AF_NAME (1)`: `addr` is `[len: u8][name: len bytes]`, a DNS name
///   of 1..=[`MAX_NAME_LEN`] ASCII bytes with no NUL, resolved by the
///   provider that receives the record: `linux_net` through the host's
///   resolver, `ip` through its stub resolver. A provider may hold a
///   narrower name ceiling than this one and refuse a longer name
///   `EINVAL`.
///
/// `AF_INET` / `AF_INET6` are the datagram surface's values, so the two
/// surfaces spell an address the same way. Only `SOCK_TYPE_STREAM` is
/// accepted; any other `sock_type`, a name outside 1..=253 bytes, or an
/// `af` the provider does not serve fails `EINVAL` synchronously on the
/// requester tag. A failed resolution is `ENOENT` on the tag. The trailing
/// `requester_tag` is optional; when present it is echoed in
/// `MSG_CONNECTED` / `MSG_ERROR`, and it carries the requesting module's
/// index **+ 1** (`dev_requester_tag`), never the raw index.
///
/// Emit with [`write_connect_to`], read with [`read_connect_to`]; parse a
/// `host[:port]` authority with [`Target::parse`] so a literal is never
/// mistaken for a name.
pub const CMD_CONNECT_TO: u8 = 0x14;

/// Address family on `CMD_CONNECT_TO`: a DNS name, `[len: u8][name…]`.
pub const AF_NAME: u8 = 1;
/// Address family on `CMD_CONNECT_TO`: IPv4, 4 bytes network order (the
/// datagram surface's value).
pub const AF_INET: u8 = 4;
/// Address family on `CMD_CONNECT_TO`: IPv6, 16 bytes network order (the
/// datagram surface's value).
pub const AF_INET6: u8 = 6;
/// Longest DNS name `AF_NAME` carries (RFC 1035 presentation form).
pub const MAX_NAME_LEN: usize = 253;
/// Bytes before `addr…` in a `CMD_CONNECT_TO` payload.
pub const CONNECT_TO_HEAD: usize = 1 + 1 + 2;
/// Largest `CMD_CONNECT_TO` payload: head, a name with its length, a tag.
pub const CONNECT_TO_MAX: usize = CONNECT_TO_HEAD + 1 + MAX_NAME_LEN + 1;

/// Where a connection is opened to. The name variant borrows the caller's
/// bytes: nothing here allocates, and a provider that resolves copies the
/// name into its own slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Target<'a> {
    V4([u8; 4]),
    V6([u8; 16]),
    Name(&'a [u8]),
}

impl<'a> Target<'a> {
    /// The address family byte this target is carried under.
    pub fn af(&self) -> u8 {
        match self {
            Target::V4(_) => AF_INET,
            Target::V6(_) => AF_INET6,
            Target::Name(_) => AF_NAME,
        }
    }

    /// Bytes of `addr…` this target occupies on the wire.
    pub fn wire_len(&self) -> usize {
        match self {
            Target::V4(_) => 4,
            Target::V6(_) => 16,
            Target::Name(n) => 1 + n.len(),
        }
    }

    /// Parse an authority: `host[:port]`, where `host` is a DNS name, a
    /// dotted quad, or a bracketed IPv6 literal (`[::1]:443`). The port,
    /// when present, is decimal 1..=65535. Literals are recognised as
    /// literals so no caller ever hashes or resolves one. `None` for
    /// anything else: an empty host, a bare v6 literal without brackets,
    /// a port of 0, a name over [`MAX_NAME_LEN`] bytes or with a byte a
    /// hostname cannot hold.
    pub fn parse(authority: &'a [u8]) -> Option<(Target<'a>, Option<u16>)> {
        let (host, port_text) = split_authority(authority)?;
        let port = match port_text {
            Some(p) => Some(parse_port(p)?),
            None => None,
        };
        if let Some(stripped) = strip_brackets(host) {
            return Some((Target::V6(parse_v6(stripped)?), port));
        }
        if let Some(v4) = parse_v4(host) {
            return Some((Target::V4(v4), port));
        }
        if !name_ok(host) {
            return None;
        }
        Some((Target::Name(host), port))
    }
}

/// `host` and the text after its port separator. A bracketed host keeps
/// its brackets; a host with more than one bare `:` is not an authority.
fn split_authority(a: &[u8]) -> Option<(&[u8], Option<&[u8]>)> {
    if a.is_empty() {
        return None;
    }
    if a[0] == b'[' {
        let close = a.iter().position(|&c| c == b']')?;
        let host = &a[..=close];
        let rest = &a[close + 1..];
        return if rest.is_empty() {
            Some((host, None))
        } else if rest[0] == b':' {
            Some((host, Some(&rest[1..])))
        } else {
            None
        };
    }
    let mut colons = 0usize;
    let mut last = 0usize;
    let mut i = 0usize;
    while i < a.len() {
        if a[i] == b':' {
            colons += 1;
            last = i;
        }
        i += 1;
    }
    match colons {
        0 => Some((a, None)),
        1 => Some((&a[..last], Some(&a[last + 1..]))),
        _ => None,
    }
}

fn strip_brackets(host: &[u8]) -> Option<&[u8]> {
    if host.len() >= 2 && host[0] == b'[' && host[host.len() - 1] == b']' {
        Some(&host[1..host.len() - 1])
    } else {
        None
    }
}

fn parse_port(text: &[u8]) -> Option<u16> {
    if text.is_empty() || text.len() > 5 {
        return None;
    }
    let mut v: u32 = 0;
    for &c in text {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u32::from(c - b'0');
    }
    if v == 0 || v > 0xFFFF {
        return None;
    }
    Some(v as u16)
}

/// A decimal octet with no sign, no leading zeros beyond a lone `0`.
fn parse_octet(text: &[u8]) -> Option<u8> {
    if text.is_empty() || text.len() > 3 || (text.len() > 1 && text[0] == b'0') {
        return None;
    }
    let mut v: u16 = 0;
    for &c in text {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u16::from(c - b'0');
    }
    if v > 255 {
        return None;
    }
    Some(v as u8)
}

/// A dotted quad, exactly four octets. Anything else — including
/// `10.1` or `1.2.3.4.5` — is not one, and is judged as a name instead.
pub fn parse_v4(text: &[u8]) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut n = 0usize;
    let mut start = 0usize;
    let mut i = 0usize;
    while i <= text.len() {
        if i == text.len() || text[i] == b'.' {
            if n == 4 {
                return None;
            }
            out[n] = parse_octet(&text[start..i])?;
            n += 1;
            start = i + 1;
        }
        i += 1;
    }
    if n == 4 {
        Some(out)
    } else {
        None
    }
}

fn hex_val(c: u8) -> Option<u16> {
    match c {
        b'0'..=b'9' => Some(u16::from(c - b'0')),
        b'a'..=b'f' => Some(u16::from(c - b'a') + 10),
        b'A'..=b'F' => Some(u16::from(c - b'A') + 10),
        _ => None,
    }
}

fn parse_hextet(text: &[u8]) -> Option<u16> {
    if text.is_empty() || text.len() > 4 {
        return None;
    }
    let mut v: u16 = 0;
    for &c in text {
        v = (v << 4) | hex_val(c)?;
    }
    Some(v)
}

/// An IPv6 literal without brackets: up to eight hextets, one `::`
/// compression, an optional dotted-quad tail (`::ffff:1.2.3.4`).
pub fn parse_v6(text: &[u8]) -> Option<[u8; 16]> {
    let mut groups = [0u16; 8];
    let mut head = 0usize; // groups before `::`
    let mut tail = [0u16; 8];
    let mut tail_n = 0usize; // groups after `::`
    let mut seen_gap = false;
    let mut i = 0usize;
    let mut start = 0usize;
    // Groups are pushed to `head` until the gap, then to `tail`.
    let mut push = |g: u16, gap: bool| -> bool {
        if !gap {
            if head == 8 {
                return false;
            }
            groups[head] = g;
            head += 1;
        } else {
            if head + tail_n == 8 {
                return false;
            }
            tail[tail_n] = g;
            tail_n += 1;
        }
        true
    };
    while i <= text.len() {
        let at_end = i == text.len();
        if at_end || text[i] == b':' {
            let piece = &text[start..i];
            if piece.is_empty() {
                if at_end && start == 0 {
                    return None; // empty literal
                }
                if !at_end && i + 1 < text.len() && text[i + 1] == b':' {
                    if seen_gap {
                        return None; // two `::`
                    }
                    seen_gap = true;
                    i += 2;
                    start = i;
                    if i == text.len() {
                        break; // trailing `::`
                    }
                    continue;
                }
                if at_end && seen_gap && start == i {
                    break; // `…::` already consumed
                }
                return None; // a lone `:` at an edge or `:::`
            }
            // `[u8]::contains` lowers to `core::slice::memchr`, which a
            // flat module image has no symbol for; the explicit walk is
            // what links.
            #[allow(clippy::manual_contains, reason = "memchr is not linkable here")]
            let dotted = piece.iter().any(|&c| c == b'.');
            if dotted {
                // A dotted-quad tail is the last two groups.
                if !at_end {
                    return None;
                }
                let v4 = parse_v4(piece)?;
                let a = u16::from_be_bytes([v4[0], v4[1]]);
                let b = u16::from_be_bytes([v4[2], v4[3]]);
                if !push(a, seen_gap) || !push(b, seen_gap) {
                    return None;
                }
                break;
            }
            if !push(parse_hextet(piece)?, seen_gap) {
                return None;
            }
            start = i + 1;
        }
        i += 1;
    }
    if seen_gap {
        if head + tail_n >= 8 {
            return None; // `::` must stand for at least one group
        }
        let mut j = 0;
        while j < tail_n {
            groups[8 - tail_n + j] = tail[j];
            j += 1;
        }
    } else if head != 8 {
        return None;
    }
    let mut out = [0u8; 16];
    let mut g = 0;
    while g < 8 {
        let b = groups[g].to_be_bytes();
        out[2 * g] = b[0];
        out[2 * g + 1] = b[1];
        g += 1;
    }
    Some(out)
}

/// Whether `host` may travel as an `AF_NAME`: 1..=[`MAX_NAME_LEN`] bytes of
/// letters, digits, `-`, `_` and `.`, with no empty label and no label over
/// 63 bytes, and at least one letter somewhere — an all-digit host is a
/// mistyped literal, not a name. A trailing dot is accepted and dropped by
/// the resolver.
pub fn name_ok(host: &[u8]) -> bool {
    if host.is_empty() || host.len() > MAX_NAME_LEN {
        return false;
    }
    let mut label = 0usize;
    let mut letter = false;
    let mut i = 0usize;
    while i < host.len() {
        let c = host[i];
        if c == b'.' {
            if label == 0 || (i + 1 == host.len() && i == 0) {
                return false;
            }
            label = 0;
        } else if c.is_ascii_alphanumeric() || c == b'-' || c == b'_' {
            letter |= c.is_ascii_alphabetic();
            label += 1;
            if label > 63 {
                return false;
            }
        } else {
            return false;
        }
        i += 1;
    }
    letter
}

/// Compose a `CMD_CONNECT_TO` payload into `buf`, answering its length,
/// or `0` when `buf` cannot hold it or the name is not one `AF_NAME`
/// carries. `port` is the connector's resolved port: the authority's when
/// it named one, else the protocol default.
pub fn write_connect_to(
    buf: &mut [u8],
    sock_type: u8,
    port: u16,
    t: &Target<'_>,
    tag: Option<u8>,
) -> usize {
    let n = CONNECT_TO_HEAD + t.wire_len() + usize::from(tag.is_some());
    if buf.len() < n {
        return 0;
    }
    buf[0] = sock_type;
    buf[1] = t.af();
    buf[2..4].copy_from_slice(&port.to_le_bytes());
    let mut at = CONNECT_TO_HEAD;
    match t {
        Target::V4(a) => {
            buf[at..at + 4].copy_from_slice(a);
            at += 4;
        }
        Target::V6(a) => {
            buf[at..at + 16].copy_from_slice(a);
            at += 16;
        }
        Target::Name(name) => {
            if name.is_empty() || name.len() > MAX_NAME_LEN {
                return 0;
            }
            buf[at] = name.len() as u8;
            at += 1;
            buf[at..at + name.len()].copy_from_slice(name);
            at += name.len();
        }
    }
    if let Some(tag) = tag {
        buf[at] = tag;
        at += 1;
    }
    at
}

/// Read a `CMD_CONNECT_TO` payload: `(sock_type, port, target, tag)`.
/// `None` for a malformed record — a truncated address, an unknown `af`,
/// a name of 0 or over 253 bytes or holding a NUL or a non-ASCII byte, or
/// trailing bytes past the tag — which the provider answers `EINVAL` on
/// the record's last byte, the one a tag would occupy: the emitter is
/// broken either way, and that byte is the closest thing to its name.
///
/// The tag is `None` when the record carries none; a provider treats that
/// as `REQUESTER_TAG_NONE`.
pub fn read_connect_to(payload: &[u8]) -> Option<(u8, u16, Target<'_>, Option<u8>)> {
    if payload.len() < CONNECT_TO_HEAD {
        return None;
    }
    let sock_type = payload[0];
    let af = payload[1];
    let port = u16::from_le_bytes([payload[2], payload[3]]);
    let rest = &payload[CONNECT_TO_HEAD..];
    let (target, used) = match af {
        AF_INET => {
            let a = rest.get(..4)?;
            (Target::V4([a[0], a[1], a[2], a[3]]), 4)
        }
        AF_INET6 => {
            let a = rest.get(..16)?;
            let mut v = [0u8; 16];
            v.copy_from_slice(a);
            (Target::V6(v), 16)
        }
        AF_NAME => {
            let len = usize::from(*rest.first()?);
            if len == 0 || len > MAX_NAME_LEN {
                return None;
            }
            let name = rest.get(1..1 + len)?;
            if name.iter().any(|&c| c == 0 || !c.is_ascii()) {
                return None;
            }
            (Target::Name(name), 1 + len)
        }
        _ => return None,
    };
    let tag = match rest.len() - used {
        0 => None,
        1 => Some(rest[used]),
        _ => return None,
    };
    Some((sock_type, port, target, tag))
}

/// The requester tag of a RETIRED [`CMD_CONNECT`] payload, so a provider
/// can address its `ENOSYS` to the emitter that dialled. Byte 7 when the
/// 8-byte form was sent; `REQUESTER_TAG_NONE` otherwise.
pub fn retired_connect_tag(payload: &[u8]) -> u8 {
    match payload.get(7) {
        Some(&t) => t,
        None => REQUESTER_TAG_NONE,
    }
}

/// Only socket type accepted by `CMD_CONNECT_TO` — this is a STREAM-only
/// surface. Datagram traffic uses the `datagram` surface (`CMD_DG_BIND` /
/// `CMD_DG_SEND_TO`); a dial with any other `sock_type` fails EINVAL.
pub const SOCK_TYPE_STREAM: u8 = 1;

/// `requester_tag` value meaning "no routing tag" — an untagged
/// `CMD_CONNECT_TO` and any consumer that doesn't tag its connects.
///
/// The wire tag is the requester's **module index + 1**, so `0` can never be a
/// valid tag (module index `0` maps to wire tag `1`). This avoids the collision
/// a raw zero-based index would have with this sentinel. Encode with
/// `dev_requester_tag`; a filtering consumer claims a frame iff its tag equals
/// the consumer's own `dev_requester_tag` OR is `REQUESTER_TAG_NONE`
/// (sole-consumer graphs).
pub const REQUESTER_TAG_NONE: u8 = 0;

// Netif state propagation: drivers emit state transitions as
// `MSG_NETIF_STATE` frames on a dedicated `netif_state` output port;
// consumers read from a wired input port of the same name. All
// inter-module networking uses channel-based net_proto (this file) or
// direct FMP messaging — there is no separate netif dispatch surface.
