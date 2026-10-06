// Contract: exchange — one request and its answer, between any two modules.
//
// Layer: contracts (portable capability vocabulary).
//
// Every request a graph carries travels in these records: an HTTP request a
// server hands to an application, a call a pipeline makes to an HTTP or S3
// endpoint, a record a producer publishes to a broker or a table. The party
// that ASKS is the requester; the party that ANSWERS is the provider. A
// requester writes request records and reads response records; a provider
// does the reverse. Neither learns what the other is.
//
// Records (multi-byte integers little-endian), one channel record each:
//
//   [kind u8][flags u8][id: 14 bytes]                             16 bytes
//   kind payload
//
//   Request direction (requester -> provider):
//     HEAD     [method u8][target_len u16][hdr_len u16][peer_len u16]
//              [resp_credit u32] target | headers | peer | body
//     BODY     body bytes
//     ABORT    [reason u8]
//     CREDIT   [bytes u32]          response-body credit
//     DATAGRAM [context u64] payload
//
//   Response direction (provider -> requester):
//     HEAD     [status u16][ct_len u8][hdr_len u16] content_type | headers | body
//     BODY     body bytes
//     ABORT    [reason u8]
//     CREDIT   [bytes u32]          request-body credit
//     DATAGRAM [context u64] payload
//     LINK     [state u8]           id all zero: the provider's link to its backend
//
// The `id` names the exchange. The requester chooses it — an HTTP server packs
// its transport, connection and stream into it, a pipeline its correlation
// counter — and the provider echoes it verbatim on every record it writes for
// that exchange. It is opaque to the provider, so any number of exchanges from
// any number of sources share one channel pair.
//
// A HEAD carries the first body bytes inline, as many as fit the record; MORE
// says further BODY records follow in that direction, and a HEAD or BODY
// without it ends the direction. An exchange ends when its response direction
// ends, or on an ABORT from either side; nothing further is written for it.
// A response that ends before the request does ends the exchange: the
// provider stops reading the request body.
//
// Flow is credit-based in both directions, and only body bytes count. The
// requester sends request-body bytes past the HEAD only up to the credit the
// provider grants with CREDIT records; the provider sends response-body bytes
// only up to `resp_credit` plus the requester's CREDIT grants. A side that
// holds a body back stops granting, and the other stops sending that
// exchange's body and nothing else's. The first request-body credit is also
// the provider's consent to the body: an HTTP client that asked for
// `100 Continue` is answered then.
//
// `status` is an HTTP status code for every provider, HTTP or not: 200 is an
// answer (for a sink, durable acceptance, with an empty body), and a provider
// that relays a peer's answer reports the peer's own status. The refusals a
// provider raises itself are named in `status` below.
//
// LINK carries the provider's connection to whatever backs it, not an
// exchange. LINK_DOWN says every exchange the requester has open without a
// terminal response is now unknowable — the requester must issue each again
// after LINK_UP, which says the provider is (re)connected and accepting.
//
// The definition lives here rather than with any one requester or provider:
// every party depends on fluxor, so this is the one place a layout costs nobody
// a dependency, and a layout mounted from one place cannot drift between the
// parties that speak it.

// ── Capabilities ──────────────────────────────────────────────────────────
//
// What a provider promises beyond answering. A provider that only answers — an
// application route, an HTTP or S3 endpoint — declares nothing; these name the
// delivery terms of a destination that durably accepts records in order.

/// What a requester REQUIRES when it publishes for durable, ordered delivery:
/// satisfied by either role below, under the registry's parent-matches-child
/// rule.
pub const CAP_ORDERED_ACK: &str = "stream.ordered_ack";
/// A provider that durably ACCEPTS records and answers with a status alone: an
/// MQTT topic, a Kafka partition, an INSERT.
pub const CAP_ORDERED_ACK_SINK: &str = "stream.ordered_ack.sink";
/// A provider that durably accepts and also ANSWERS WITH DATA: an HTTP call, a
/// SELECT. It does everything a sink does and more, which is why it is a
/// sibling of `.sink` under a shared parent.
pub const CAP_ORDERED_ACK_EXCHANGE: &str = "stream.ordered_ack.exchange";

// Terms a provider of either role satisfies: an answer with status 200 means
// durable acceptance at the strongest level its configuration offers; order is
// kept per `target` within a connection; nothing is dropped silently — every
// exchange is answered or invalidated by LINK_DOWN; backpressure is by channel
// and credit, never by dropping; a BROADCAST request reaches every ordering
// unit and is answered once, after the slowest. A provider that offers less
// says so in its `[capability_facts]`.

// ── Sizes ─────────────────────────────────────────────────────────────────

/// Fixed prefix of every record.
pub const HDR: usize = 16;
/// Largest record either side writes: one channel record.
pub const RECORD_MAX: usize = 8192;
/// Largest body one BODY record carries.
pub const BODY_MAX: usize = RECORD_MAX - HDR;
/// Fixed part of a request HEAD after the prefix.
pub const REQ_HEAD_FIXED: usize = 1 + 2 + 2 + 2 + 4;
/// Fixed part of a response HEAD after the prefix.
pub const RESP_HEAD_FIXED: usize = 2 + 1 + 2;
/// Length of the exchange id.
pub const ID_LEN: usize = 14;

/// The largest body a collected exchange carries — the figure a module that
/// takes requests whole sizes its buffer from, and the one a requester holds
/// itself to when no provider fact says otherwise. A provider whose backend
/// takes less declares the smaller number as its `max_payload` capability
/// fact, and the build checks it against the requester's own.
pub const PAYLOAD_MAX: usize = 8192;
/// The largest `target` a publish carries: a table or topic identifier plus a
/// natural key, with room for requesters whose ordering unit is wider.
pub const KEY_MAX: usize = 512;

// ── Vocabulary ────────────────────────────────────────────────────────────

/// Record kinds. The same values in both directions; HEAD alone differs in
/// payload by direction.
pub mod kind {
    pub const HEAD: u8 = 0x01;
    pub const BODY: u8 = 0x02;
    pub const ABORT: u8 = 0x03;
    pub const CREDIT: u8 = 0x04;
    pub const DATAGRAM: u8 = 0x05;
    /// Response direction only.
    pub const LINK: u8 = 0x06;
}

/// Record flags.
pub mod flag {
    /// More BODY records follow in this direction.
    pub const MORE: u8 = 0x01;
    /// Response: the provider holds the exchange open on purpose (a watch, an
    /// event stream) and ends it itself; its progress deadline is the long one.
    pub const HOLD: u8 = 0x02;
    /// Request: an extended CONNECT for a WebSocket on a route that delegates
    /// the upgrade. Response: the upgrade is accepted, and the exchange
    /// becomes a WebSocket tunnel the server terminates.
    pub const WEBSOCKET: u8 = 0x04;
    /// Request: an extended CONNECT for a WebTransport session. Response: the
    /// session is accepted; BODY records then carry the session stream.
    pub const WEBTRANSPORT: u8 = 0x08;
    /// Request: the route is a file route this server delegates.
    pub const ROUTE_FILE: u8 = 0x10;
    /// Request: the route is a proxy route this server delegates.
    pub const ROUTE_PROXY: u8 = 0x20;
    /// Request: deliver to every ordering unit, not the one `target` names.
    pub const BROADCAST: u8 = 0x40;
}

/// Why an exchange was aborted.
pub mod abort {
    /// The peer closed or reset before the exchange finished.
    pub const PEER_GONE: u8 = 1;
    /// A body's framing was malformed.
    pub const MALFORMED: u8 = 2;
    /// A body passed the ceiling of the side receiving it.
    pub const TOO_LARGE: u8 = 3;
    /// The other side stopped sending or reading past the stall deadline.
    pub const STALLED: u8 = 4;
    /// The side aborting is draining.
    pub const DRAINING: u8 = 5;
    /// The answer can no longer reach whoever asked.
    pub const UNDELIVERABLE: u8 = 6;
    /// The other side sent body bytes past its credit.
    pub const CREDIT_OVERRUN: u8 = 7;
    /// The side aborting could not finish the exchange.
    pub const FAILED: u8 = 8;
}

/// LINK states.
pub mod link {
    /// Every open exchange is unknowable; issue each again after `UP`.
    pub const DOWN: u8 = 1;
    /// (Re)connected and accepting.
    pub const UP: u8 = 2;
}

/// The statuses a provider raises itself. Everything else a status carries is
/// an answer, including a relayed peer's own.
pub mod status {
    /// Answered; for a sink, durably accepted.
    pub const OK: u16 = 200;
    /// The request was not a well-formed request for this provider: an
    /// unknown method, a target it cannot route.
    pub const BAD_REQUEST: u16 = 400;
    /// The request or its body passed what this provider takes.
    pub const TOO_LARGE: u16 = 413;
    /// The provider failed answering it.
    pub const FAILED: u16 = 500;
    /// The peer behind the provider could not be reached, or answered with
    /// something the provider could not carry back.
    pub const BAD_GATEWAY: u16 = 502;
    /// The provider holds as many exchanges as it can; the request may be
    /// repeated.
    pub const BUSY: u16 = 503;
    /// The peer behind the provider did not answer in time.
    pub const TIMEOUT: u16 = 504;
}

// The method vocabulary. A request names its method as one byte, and every
// reader of that byte needs the same table. Deliberately NOT a Rust enum: the
// value crosses a channel as a byte, and a `#[repr(u8)]` enum would make every
// decode a fallible transmute at the receiver for no gain over a `u8` plus
// these constants.

/// No method parsed, or an unrecognised token.
pub const METHOD_NONE: u8 = 0;
pub const METHOD_GET: u8 = 1;
/// CONNECT, which h2 and h3 also use as the extended CONNECT that opens a
/// WebSocket or WebTransport session.
pub const METHOD_CONNECT: u8 = 2;
pub const METHOD_POST: u8 = 3;
pub const METHOD_HEAD: u8 = 4;
pub const METHOD_PUT: u8 = 5;
pub const METHOD_PATCH: u8 = 6;
pub const METHOD_DELETE: u8 = 7;
pub const METHOD_OPTIONS: u8 = 8;
/// A record for a durable destination: `target` is its ordering key, the body
/// is the record. Not an HTTP method; an HTTP provider refuses it.
pub const METHOD_PUBLISH: u8 = 9;

/// The method constant for an HTTP request-line token, or [`METHOD_NONE`] for
/// any token this table does not name. Case-sensitive: RFC 9110 §9.1 makes the
/// method token case-sensitive, so `get` is not a method.
pub fn method_from_token(tok: &[u8]) -> u8 {
    match tok {
        b"GET" => METHOD_GET,
        b"HEAD" => METHOD_HEAD,
        b"POST" => METHOD_POST,
        b"PUT" => METHOD_PUT,
        b"PATCH" => METHOD_PATCH,
        b"DELETE" => METHOD_DELETE,
        b"OPTIONS" => METHOD_OPTIONS,
        b"CONNECT" => METHOD_CONNECT,
        _ => METHOD_NONE,
    }
}

/// Every token end to end, so [`method_name`] can answer with a span of this
/// rather than a table of separate literals.
const TOKENS: &[u8] = b"GETCONNECTPOSTHEADPUTPATCHDELETEOPTIONSPUBLISH";

/// `(offset, length)` into [`TOKENS`] per method constant, indexed by the
/// constant itself. [`METHOD_NONE`] and anything past the table is `(0, 0)`.
const TOKEN_SPAN: [(u8, u8); 10] = [
    (0, 0),  // METHOD_NONE
    (0, 3),  // GET
    (3, 7),  // CONNECT
    (10, 4), // POST
    (14, 4), // HEAD
    (18, 3), // PUT
    (21, 5), // PATCH
    (26, 6), // DELETE
    (32, 7), // OPTIONS
    (39, 7), // PUBLISH
];

/// The token for a method constant — for a request line, a log line, or the
/// `method` a browser API is handed. Empty for [`METHOD_NONE`].
///
/// The span table holds integers, not string references, and that is
/// load-bearing. A `match` returning a different `&'static [u8]` per arm
/// compiles to a table of `{pointer, length}` pairs that the linker fills with
/// absolute addresses. A `.fmod` is a flat image mapped at whatever base the
/// loader picks, with no relocations applied, so every pointer in such a table
/// is wrong by the load address. Offsets into one literal need no relocation.
pub fn method_name(m: u8) -> &'static [u8] {
    let (off, len) = match TOKEN_SPAN.get(m as usize) {
        Some(&(off, len)) => (off as usize, len as usize),
        None => return &[],
    };
    match TOKENS.get(off..off + len) {
        Some(tok) => tok,
        None => &[],
    }
}

// ── Records ───────────────────────────────────────────────────────────────

/// The exchange a record belongs to: 14 bytes the requester chooses and the
/// provider echoes verbatim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ExchangeId(pub [u8; ID_LEN]);

impl ExchangeId {
    /// The all-zero id LINK records carry.
    pub const NONE: ExchangeId = ExchangeId([0; ID_LEN]);

    /// An id from a requester's 64-bit counter, the rest zero.
    pub const fn from_u64(n: u64) -> Self {
        let b = n.to_le_bytes();
        ExchangeId([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], 0, 0, 0, 0, 0, 0,
        ])
    }

    /// The counter [`ExchangeId::from_u64`] made it from.
    pub const fn as_u64(&self) -> u64 {
        let b = &self.0;
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    }

    fn read(b: &[u8]) -> Option<Self> {
        let mut id = [0u8; ID_LEN];
        id.copy_from_slice(b.get(2..HDR)?);
        Some(ExchangeId(id))
    }
}

/// A request HEAD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestHead<'a> {
    pub id: ExchangeId,
    pub flags: u8,
    pub method: u8,
    pub target: &'a [u8],
    pub headers: &'a [u8],
    pub peer: &'a [u8],
    pub resp_credit: u32,
    /// The first body bytes, inline.
    pub body: &'a [u8],
}

/// A response HEAD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseHead<'a> {
    pub id: ExchangeId,
    pub flags: u8,
    pub status: u16,
    pub content_type: &'a [u8],
    pub headers: &'a [u8],
    /// The first body bytes, inline.
    pub body: &'a [u8],
}

/// One decoded record. `Head` carries the direction's own head type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Record<'a, H> {
    Head(H),
    Body {
        id: ExchangeId,
        flags: u8,
        data: &'a [u8],
    },
    Abort {
        id: ExchangeId,
        reason: u8,
    },
    Credit {
        id: ExchangeId,
        bytes: u32,
    },
    Datagram {
        id: ExchangeId,
        context: u64,
        data: &'a [u8],
    },
    /// Response direction only.
    Link {
        state: u8,
    },
}

/// A record as a provider reads it.
pub type RequestRecord<'a> = Record<'a, RequestHead<'a>>;
/// A record as a requester reads it.
pub type ResponseRecord<'a> = Record<'a, ResponseHead<'a>>;

impl<'a> RequestRecord<'a> {
    /// The body bytes this record counts against credit.
    pub fn body_len(&self) -> usize {
        match self {
            Record::Head(h) => h.body.len(),
            Record::Body { data, .. } => data.len(),
            _ => 0,
        }
    }
}

impl<'a> ResponseRecord<'a> {
    /// The body bytes this record counts against credit.
    pub fn body_len(&self) -> usize {
        match self {
            Record::Head(h) => h.body.len(),
            Record::Body { data, .. } => data.len(),
            _ => 0,
        }
    }
}

/// A record's kind byte, or `None` when it is too short to be a record.
pub fn record_kind(record: &[u8]) -> Option<u8> {
    if record.len() < HDR {
        return None;
    }
    record.first().copied()
}

/// A record's exchange id, or `None` when it is too short to be a record.
pub fn record_id(record: &[u8]) -> Option<ExchangeId> {
    if record.len() < HDR {
        return None;
    }
    ExchangeId::read(record)
}

/// Whether a record ends its direction of the exchange: a HEAD or BODY
/// without MORE, or an ABORT.
pub fn ends_direction(record: &[u8]) -> bool {
    match record_kind(record) {
        Some(kind::HEAD) | Some(kind::BODY) => record[1] & flag::MORE == 0,
        Some(kind::ABORT) => true,
        _ => false,
    }
}

fn u16_at(b: &[u8], at: usize) -> Option<usize> {
    Some(u16::from_le_bytes([*b.get(at)?, *b.get(at + 1)?]) as usize)
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *b.get(at)?,
        *b.get(at + 1)?,
        *b.get(at + 2)?,
        *b.get(at + 3)?,
    ]))
}

fn prefix(k: u8, flags: u8, id: &ExchangeId, out: &mut [u8]) -> Option<()> {
    if out.len() < HDR {
        return None;
    }
    out[0] = k;
    out[1] = flags;
    out[2..HDR].copy_from_slice(&id.0);
    Some(())
}

/// Decode the kinds both directions share. `None` for HEAD (each direction
/// decodes its own), for LINK, and for a malformed record.
fn common<'a, H>(b: &'a [u8], id: ExchangeId) -> Option<Record<'a, H>> {
    let flags = b[1];
    let rest = &b[HDR..];
    match b[0] {
        kind::BODY => Some(Record::Body {
            id,
            flags,
            data: rest,
        }),
        kind::ABORT if rest.len() == 1 => Some(Record::Abort {
            id,
            reason: rest[0],
        }),
        kind::CREDIT if rest.len() == 4 => Some(Record::Credit {
            id,
            bytes: u32_at(rest, 0)?,
        }),
        kind::DATAGRAM if rest.len() >= 8 => Some(Record::Datagram {
            id,
            context: u64::from_le_bytes([
                rest[0], rest[1], rest[2], rest[3], rest[4], rest[5], rest[6], rest[7],
            ]),
            data: &rest[8..],
        }),
        _ => None,
    }
}

/// Decode one request-direction record. `None` when it is malformed: a record
/// is exactly one channel read, so a length that disagrees with it is refused
/// rather than read past or short.
pub fn parse_request(b: &[u8]) -> Option<RequestRecord<'_>> {
    if b.len() > RECORD_MAX {
        return None;
    }
    let id = record_id(b)?;
    if b[0] != kind::HEAD {
        return common(b, id);
    }
    let p = HDR;
    let method = *b.get(p)?;
    let target_len = u16_at(b, p + 1)?;
    let hdr_len = u16_at(b, p + 3)?;
    let peer_len = u16_at(b, p + 5)?;
    let resp_credit = u32_at(b, p + 7)?;
    let target_at = p + REQ_HEAD_FIXED;
    let hdr_at = target_at.checked_add(target_len)?;
    let peer_at = hdr_at.checked_add(hdr_len)?;
    let body_at = peer_at.checked_add(peer_len)?;
    if body_at > b.len() {
        return None;
    }
    Some(Record::Head(RequestHead {
        id,
        flags: b[1],
        method,
        target: &b[target_at..hdr_at],
        headers: &b[hdr_at..peer_at],
        peer: &b[peer_at..body_at],
        resp_credit,
        body: &b[body_at..],
    }))
}

/// Decode one response-direction record. `None` when it is malformed.
pub fn parse_response(b: &[u8]) -> Option<ResponseRecord<'_>> {
    if b.len() > RECORD_MAX {
        return None;
    }
    let id = record_id(b)?;
    match b[0] {
        kind::HEAD => {}
        kind::LINK if b.len() == HDR + 1 && id == ExchangeId::NONE => {
            return Some(Record::Link { state: b[HDR] });
        }
        _ => return common(b, id),
    }
    let p = HDR;
    let status = u16_at(b, p)? as u16;
    let ct_len = *b.get(p + 2)? as usize;
    let hdr_len = u16_at(b, p + 3)?;
    let ct_at = p + RESP_HEAD_FIXED;
    let hdr_at = ct_at.checked_add(ct_len)?;
    let body_at = hdr_at.checked_add(hdr_len)?;
    if body_at > b.len() {
        return None;
    }
    Some(Record::Head(ResponseHead {
        id,
        flags: b[1],
        status,
        content_type: &b[ct_at..hdr_at],
        headers: &b[hdr_at..body_at],
        body: &b[body_at..],
    }))
}

/// Encode a request HEAD. `None` when it does not fit `out` or one record.
pub fn write_request_head(h: &RequestHead<'_>, out: &mut [u8]) -> Option<usize> {
    let end = HDR
        .checked_add(REQ_HEAD_FIXED)?
        .checked_add(h.target.len())?
        .checked_add(h.headers.len())?
        .checked_add(h.peer.len())?
        .checked_add(h.body.len())?;
    if end > out.len()
        || end > RECORD_MAX
        || h.target.len() > u16::MAX as usize
        || h.headers.len() > u16::MAX as usize
        || h.peer.len() > u16::MAX as usize
    {
        return None;
    }
    prefix(kind::HEAD, h.flags, &h.id, out)?;
    let p = HDR;
    out[p] = h.method;
    out[p + 1..p + 3].copy_from_slice(&(h.target.len() as u16).to_le_bytes());
    out[p + 3..p + 5].copy_from_slice(&(h.headers.len() as u16).to_le_bytes());
    out[p + 5..p + 7].copy_from_slice(&(h.peer.len() as u16).to_le_bytes());
    out[p + 7..p + 11].copy_from_slice(&h.resp_credit.to_le_bytes());
    let mut at = p + REQ_HEAD_FIXED;
    for part in [h.target, h.headers, h.peer, h.body] {
        out[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    Some(at)
}

/// Encode a response HEAD. `None` when it does not fit `out` or one record.
pub fn write_response_head(h: &ResponseHead<'_>, out: &mut [u8]) -> Option<usize> {
    let end = HDR
        .checked_add(RESP_HEAD_FIXED)?
        .checked_add(h.content_type.len())?
        .checked_add(h.headers.len())?
        .checked_add(h.body.len())?;
    if end > out.len()
        || end > RECORD_MAX
        || h.content_type.len() > u8::MAX as usize
        || h.headers.len() > u16::MAX as usize
    {
        return None;
    }
    prefix(kind::HEAD, h.flags, &h.id, out)?;
    let p = HDR;
    out[p..p + 2].copy_from_slice(&h.status.to_le_bytes());
    out[p + 2] = h.content_type.len() as u8;
    out[p + 3..p + 5].copy_from_slice(&(h.headers.len() as u16).to_le_bytes());
    let mut at = p + RESP_HEAD_FIXED;
    for part in [h.content_type, h.headers, h.body] {
        out[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    Some(at)
}

/// Encode a BODY record (either direction).
pub fn write_body(id: &ExchangeId, flags: u8, data: &[u8], out: &mut [u8]) -> Option<usize> {
    let end = HDR.checked_add(data.len())?;
    if end > out.len() || end > RECORD_MAX {
        return None;
    }
    prefix(kind::BODY, flags, id, out)?;
    out[HDR..end].copy_from_slice(data);
    Some(end)
}

/// Seal a BODY record whose `data_len` payload bytes are already in place at
/// `out[HDR..]`: writes the prefix and returns the record length. For a writer
/// that decodes straight into the record rather than through a copy.
pub fn seal_body(id: &ExchangeId, flags: u8, data_len: usize, out: &mut [u8]) -> Option<usize> {
    let end = HDR.checked_add(data_len)?;
    if end > out.len() || end > RECORD_MAX {
        return None;
    }
    prefix(kind::BODY, flags, id, out)?;
    Some(end)
}

/// Encode an ABORT record (either direction).
pub fn write_abort(id: &ExchangeId, reason: u8, out: &mut [u8]) -> Option<usize> {
    if out.len() < HDR + 1 {
        return None;
    }
    prefix(kind::ABORT, 0, id, out)?;
    out[HDR] = reason;
    Some(HDR + 1)
}

/// Encode a CREDIT record (either direction).
pub fn write_credit(id: &ExchangeId, bytes: u32, out: &mut [u8]) -> Option<usize> {
    if out.len() < HDR + 4 {
        return None;
    }
    prefix(kind::CREDIT, 0, id, out)?;
    out[HDR..HDR + 4].copy_from_slice(&bytes.to_le_bytes());
    Some(HDR + 4)
}

/// Encode a DATAGRAM record (either direction).
pub fn write_datagram(id: &ExchangeId, context: u64, data: &[u8], out: &mut [u8]) -> Option<usize> {
    let end = HDR.checked_add(8)?.checked_add(data.len())?;
    if end > out.len() || end > RECORD_MAX {
        return None;
    }
    prefix(kind::DATAGRAM, 0, id, out)?;
    out[HDR..HDR + 8].copy_from_slice(&context.to_le_bytes());
    out[HDR + 8..end].copy_from_slice(data);
    Some(end)
}

/// Encode a LINK record (response direction).
pub fn write_link(state: u8, out: &mut [u8]) -> Option<usize> {
    if out.len() < HDR + 1 {
        return None;
    }
    prefix(kind::LINK, 0, &ExchangeId::NONE, out)?;
    out[HDR] = state;
    Some(HDR + 1)
}

/// Encode a whole response: one HEAD carrying the entire body, no MORE.
pub fn write_response(
    id: &ExchangeId,
    status: u16,
    content_type: &[u8],
    body: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    write_response_head(
        &ResponseHead {
            id: *id,
            flags: 0,
            status,
            content_type,
            headers: &[],
            body,
        },
        out,
    )
}

/// Where a whole response's body starts, for a content type of `ct_len` bytes
/// and no extra headers — for a writer that renders the body in place.
pub const fn response_body_at(ct_len: usize) -> usize {
    HDR + RESP_HEAD_FIXED + ct_len
}

/// Seal a whole response whose `body_len` bytes are already at
/// [`response_body_at`]. Returns the record length.
pub fn seal_response(
    id: &ExchangeId,
    status: u16,
    content_type: &[u8],
    body_len: usize,
    out: &mut [u8],
) -> Option<usize> {
    let at = response_body_at(content_type.len());
    let end = at.checked_add(body_len)?;
    if end > out.len() || end > RECORD_MAX || content_type.len() > u8::MAX as usize {
        return None;
    }
    write_response_head(
        &ResponseHead {
            id: *id,
            flags: 0,
            status,
            content_type,
            headers: &[],
            body: &[],
        },
        out,
    )?;
    Some(end)
}

// ── Header blocks ─────────────────────────────────────────────────────────

/// The value of the first header named `name` (ASCII case-insensitive) in a
/// `name: value\r\n` block, with optional whitespace trimmed.
pub fn header<'a>(headers: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    header_lines(headers)
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
}

/// The `name: value\r\n` lines of a header block, in order.
pub struct HeaderLines<'a> {
    rest: &'a [u8],
}

/// Iterate a header block's fields as `(name, value)` with optional whitespace
/// trimmed from the value. A line without a colon is skipped.
pub fn header_lines(headers: &[u8]) -> HeaderLines<'_> {
    HeaderLines { rest: headers }
}

impl<'a> Iterator for HeaderLines<'a> {
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        while !self.rest.is_empty() {
            let end = self
                .rest
                .windows(2)
                .position(|w| w == b"\r\n")
                .unwrap_or(self.rest.len());
            let line = &self.rest[..end];
            self.rest = self.rest.get(end + 2..).unwrap_or(&[]);
            let Some(colon) = line.iter().position(|&c| c == b':') else {
                continue;
            };
            let mut v = &line[colon + 1..];
            while let [b' ' | b'\t', tail @ ..] = v {
                v = tail;
            }
            while let [head @ .., b' ' | b'\t'] = v {
                v = head;
            }
            return Some((&line[..colon], v));
        }
        None
    }
}

// ── Collecting requests whole ─────────────────────────────────────────────
//
// A provider that answers a request only once all of it is in hand — an
// endpoint deciding on a body, an engine that transforms one record at a
// time — collects each exchange to a bound, then answers it in one record.
// The collecting lives here rather than in each such provider because every
// copy of an id table and a body accumulator is a place to drift, and the
// drift is silent: a half-collected request looks like one that never came.
//
// A request past a bound is refused, never truncated, and the refusal is
// always answered: a decision the caller never hears is indistinguishable
// from a provider that hung.

/// Why a request was not collected.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refuse {
    /// No free slot: more exchanges arrived at once than the provider holds.
    Busy,
    /// The target, headers or body passed what the provider holds.
    TooLarge,
    /// A record that does not belong to a collected exchange, or arrived out
    /// of order.
    Unexpected,
}

impl Refuse {
    /// The status a caller is owed for this refusal.
    pub const fn status(self) -> u16 {
        match self {
            Self::Busy => status::BUSY,
            Self::TooLarge => status::TOO_LARGE,
            Self::Unexpected => status::BAD_REQUEST,
        }
    }
}

#[derive(Clone, Copy)]
struct Slot<const TARGET: usize, const HEADERS: usize, const BODY: usize> {
    live: bool,
    done: bool,
    id: ExchangeId,
    method: u8,
    flags: u8,
    target: [u8; TARGET],
    target_len: u16,
    headers: [u8; HEADERS],
    headers_len: u16,
    body: [u8; BODY],
    body_len: u32,
    resp_credit: u32,
}

impl<const TARGET: usize, const HEADERS: usize, const BODY: usize> Slot<TARGET, HEADERS, BODY> {
    const EMPTY: Self = Slot {
        live: false,
        done: false,
        id: ExchangeId::NONE,
        method: 0,
        flags: 0,
        target: [0; TARGET],
        target_len: 0,
        headers: [0; HEADERS],
        headers_len: 0,
        body: [0; BODY],
        body_len: 0,
        resp_credit: 0,
    };
}

/// A request whose body is complete.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub id: ExchangeId,
    pub method: u8,
    pub flags: u8,
    pub target: &'a [u8],
    pub headers: &'a [u8],
    pub body: &'a [u8],
    /// Response body bytes the requester has granted so far.
    pub resp_credit: u32,
}

/// The exchanges a provider is collecting: `SLOTS` at once, each holding up to
/// `TARGET`, `HEADERS` and `BODY` bytes. Each module sets the four from what it
/// actually serves.
pub struct Collector<
    const SLOTS: usize,
    const TARGET: usize,
    const HEADERS: usize,
    const BODY: usize,
> {
    slots: [Slot<TARGET, HEADERS, BODY>; SLOTS],
    /// A request-body credit owed to the requester. A provider that grants
    /// nothing never receives a body, and the symptom is not an error but a
    /// request that stays half-collected, so the grant is owed the moment an
    /// exchange opens with a body to come.
    grant: Option<(ExchangeId, u32)>,
    /// A refusal owed to a caller, with the exchange it answers. Kept beside the
    /// grant and taken the same way, because the collector does no I/O —
    /// whoever owns the port sends it.
    refusal: Option<(ExchangeId, Refuse)>,
}

impl<const SLOTS: usize, const TARGET: usize, const HEADERS: usize, const BODY: usize>
    Collector<SLOTS, TARGET, HEADERS, BODY>
{
    pub const fn new() -> Self {
        Collector {
            slots: [Slot::EMPTY; SLOTS],
            grant: None,
            refusal: None,
        }
    }

    fn find(&self, id: &ExchangeId) -> Option<usize> {
        self.slots.iter().position(|s| s.live && s.id == *id)
    }

    /// Take one request-direction record.
    ///
    /// `Ok(Some(i))` is an exchange whose request is complete: read it with
    /// [`Collector::request`] and free it with [`Collector::release`] once
    /// answered. `Ok(None)` is progress with nothing finished yet.
    pub fn accept(&mut self, record: &[u8]) -> Result<Option<usize>, Refuse> {
        match parse_request(record).ok_or(Refuse::Unexpected)? {
            Record::Head(head) => self.open(&head),
            Record::Body { id, flags, data } => self.extend(&id, flags, data),
            // An abort ends the exchange: an answer would have nowhere to go.
            Record::Abort { id, .. } => {
                if let Some(i) = self.find(&id) {
                    self.slots[i] = Slot::EMPTY;
                }
                Ok(None)
            }
            // Credit raises what a response may carry.
            Record::Credit { id, bytes } => {
                if let Some(i) = self.find(&id) {
                    self.slots[i].resp_credit = self.slots[i].resp_credit.saturating_add(bytes);
                }
                Ok(None)
            }
            Record::Datagram { .. } | Record::Link { .. } => Ok(None),
        }
    }

    fn open(&mut self, head: &RequestHead<'_>) -> Result<Option<usize>, Refuse> {
        if head.target.len() > TARGET || head.headers.len() > HEADERS || head.body.len() > BODY {
            return Err(self.refuse(head.id, Refuse::TooLarge));
        }
        // A repeat HEAD for an exchange already open restarts it; take the
        // newer one rather than two half-requests.
        let at = match self.find(&head.id) {
            Some(i) => i,
            None => match self.slots.iter().position(|s| !s.live) {
                Some(i) => i,
                None => return Err(self.refuse(head.id, Refuse::Busy)),
            },
        };
        let slot = &mut self.slots[at];
        *slot = Slot::EMPTY;
        slot.live = true;
        slot.id = head.id;
        slot.method = head.method;
        slot.flags = head.flags;
        slot.resp_credit = head.resp_credit;
        slot.target[..head.target.len()].copy_from_slice(head.target);
        slot.headers[..head.headers.len()].copy_from_slice(head.headers);
        slot.body[..head.body.len()].copy_from_slice(head.body);
        // Every length was bounded above by a const that fits.
        slot.target_len = head.target.len() as u16;
        slot.headers_len = head.headers.len() as u16;
        slot.body_len = head.body.len() as u32;
        slot.done = head.flags & flag::MORE == 0;
        if !slot.done {
            // The rest of the body this provider will hold, granted at once: it
            // answers in one record and has no use for a smaller window.
            let room = (BODY - head.body.len()) as u32;
            self.grant = Some((head.id, room));
            return Ok(None);
        }
        Ok(Some(at))
    }

    fn extend(&mut self, id: &ExchangeId, flags: u8, data: &[u8]) -> Result<Option<usize>, Refuse> {
        let at = self.find(id).ok_or(Refuse::Unexpected)?;
        let slot = &mut self.slots[at];
        if slot.done {
            return Err(Refuse::Unexpected);
        }
        let have = slot.body_len as usize;
        let want = have.checked_add(data.len()).ok_or(Refuse::TooLarge)?;
        if want > BODY {
            // Refused, not truncated, and the slot goes: a decision on part of
            // a body is worse than no decision.
            let id = slot.id;
            *slot = Slot::EMPTY;
            return Err(self.refuse(id, Refuse::TooLarge));
        }
        slot.body[have..want].copy_from_slice(data);
        slot.body_len = want as u32;
        slot.done = flags & flag::MORE == 0;
        Ok(if slot.done { Some(at) } else { None })
    }

    /// The complete request in slot `at`.
    pub fn request(&self, at: usize) -> Option<Request<'_>> {
        let slot = self.slots.get(at)?;
        if !slot.live || !slot.done {
            return None;
        }
        Some(Request {
            id: slot.id,
            method: slot.method,
            flags: slot.flags,
            target: slot.target.get(..usize::from(slot.target_len))?,
            headers: slot.headers.get(..usize::from(slot.headers_len))?,
            body: slot.body.get(..slot.body_len as usize)?,
            resp_credit: slot.resp_credit,
        })
    }

    /// Free slot `at`, once its answer is away.
    pub fn release(&mut self, at: usize) {
        if let Some(slot) = self.slots.get_mut(at) {
            *slot = Slot::EMPTY;
        }
    }

    /// A request-body credit to write to the requester, if one is owed. Taken
    /// after every [`Collector::accept`].
    pub fn take_grant(&mut self) -> Option<(ExchangeId, u32)> {
        self.grant.take()
    }

    /// A refusal to answer, and the exchange it belongs to. `None` when the
    /// refused record named no exchange — an unparseable record has no id, so
    /// there is nowhere to send a status.
    pub fn take_refusal(&mut self) -> Option<(ExchangeId, Refuse)> {
        self.refusal.take()
    }

    fn refuse(&mut self, id: ExchangeId, why: Refuse) -> Refuse {
        self.refusal = Some((id, why));
        why
    }

    /// Exchanges being collected.
    pub fn live(&self) -> usize {
        self.slots.iter().filter(|s| s.live).count()
    }
}

impl<const SLOTS: usize, const TARGET: usize, const HEADERS: usize, const BODY: usize> Default
    for Collector<SLOTS, TARGET, HEADERS, BODY>
{
    fn default() -> Self {
        Self::new()
    }
}
