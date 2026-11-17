// Binding: HTTP over the exchange contract.
//
// Layer: contracts (portable capability vocabulary).
//
// The exchange records (`exchange.rs`) are neutral; this is what a party that
// speaks HTTP puts in their binding fields, and the one table every such
// party reads them with:
//
//   - `verb` is the request method, one byte from `method`. CONNECT,
//     WS_CONNECT and WT_CONNECT are the opening verbs: a request carrying one
//     is an OPEN, and an OPEN carries one of them. WS_CONNECT and WT_CONNECT
//     are the extended CONNECTs that open a WebSocket and a WebTransport
//     session; on a request line all three are `CONNECT`.
//   - `detail` is the response status. The outcome is the class
//     `outcome_of` gives it, computed by the encoders here, and a decoder
//     speaking `Http` refuses a HEAD where the two disagree. A 1xx status is
//     never carried: `100 Continue` is the HTTP side's own answer to the
//     first request-body CREDIT (`expects_continue`), and no other interim
//     response crosses. An answer with no detail is written to an HTTP client
//     with `canonical_status`.
//   - `meta` fields are header fields: the key is the field name in lower
//     case, the value its value with optional whitespace trimmed, in the
//     order the fields came. A key starting `:` is the binding's own and never
//     leaves as a header line: `:route` (`META_ROUTE`) says how the server
//     routed the request it delegates.
//
// A provider that speaks this binding declares it on its `request_in` port
// (`[ports.facts] binding = ["http"]`, under `exchange.request`); a
// requester that sends these verbs declares it on its `request_out`, and the
// build refuses the edge when the provider does not.

use super::exchange::{self as ex, outcome, Binding, ExchangeId, ResponseHead};

/// The name this binding is declared under in a port's `binding` fact.
pub const BINDING: &str = "http";

/// The request methods, one byte each. Deliberately NOT a Rust enum: the
/// value crosses a channel as a byte, and a `#[repr(u8)]` enum would make
/// every decode a fallible transmute at the receiver for no gain over a `u8`
/// plus these constants.
pub mod method {
    pub const GET: u8 = 1;
    pub const HEAD: u8 = 2;
    pub const POST: u8 = 3;
    pub const PUT: u8 = 4;
    pub const PATCH: u8 = 5;
    pub const DELETE: u8 = 6;
    pub const OPTIONS: u8 = 7;
    /// CONNECT: a tunnel to the target's authority.
    pub const CONNECT: u8 = 8;
    /// The extended CONNECT that opens a WebSocket on a route that delegates
    /// the upgrade. The session's BODY records carry the server-terminated
    /// WebSocket's messages.
    pub const WS_CONNECT: u8 = 9;
    /// The extended CONNECT that opens a WebTransport session; its BODY
    /// records carry the session stream.
    pub const WT_CONNECT: u8 = 10;

    /// Whether `m` is a method this table names.
    pub const fn known(m: u8) -> bool {
        m >= GET && m <= WT_CONNECT
    }

    /// Whether `m` opens a session: the verbs of an OPEN, and of nothing
    /// else.
    pub const fn opens(m: u8) -> bool {
        m == CONNECT || m == WS_CONNECT || m == WT_CONNECT
    }
}

/// The statuses the parties in this tree write by name. Any status from 200
/// to 599 crosses; these are the ones a provider here raises or answers.
pub mod status {
    pub const CONTINUE: u16 = 100;
    pub const OK: u16 = 200;
    pub const NO_CONTENT: u16 = 204;
    pub const PARTIAL_CONTENT: u16 = 206;
    pub const BAD_REQUEST: u16 = 400;
    pub const FORBIDDEN: u16 = 403;
    pub const NOT_FOUND: u16 = 404;
    pub const CONFLICT: u16 = 409;
    pub const PRECONDITION_FAILED: u16 = 412;
    pub const PAYLOAD_TOO_LARGE: u16 = 413;
    pub const RANGE_NOT_SATISFIABLE: u16 = 416;
    pub const LOCKED: u16 = 423;
    pub const TOO_MANY_REQUESTS: u16 = 429;
    pub const INTERNAL_SERVER_ERROR: u16 = 500;
    pub const NOT_IMPLEMENTED: u16 = 501;
    pub const BAD_GATEWAY: u16 = 502;
    pub const SERVICE_UNAVAILABLE: u16 = 503;
    pub const GATEWAY_TIMEOUT: u16 = 504;
}

/// The binding, as a type parameter of the exchange decoders and encoders.
pub struct Http;

impl Binding for Http {
    fn admits(op: u8, verb: u8) -> bool {
        match op {
            ex::op::OPEN => method::opens(verb),
            ex::op::PUBLISH => verb == 0,
            _ => verb == 0 || (method::known(verb) && !method::opens(verb)),
        }
    }

    fn admits_detail(o: u8, detail: u16) -> bool {
        outcome_of(detail) == Some(o)
    }
}

/// The outcome class of status `s`; `None` for a status this binding does
/// not carry (1xx, and anything outside 100..=599).
pub const fn outcome_of(s: u16) -> Option<u8> {
    Some(match s {
        200..=299 => outcome::OK,
        300..=399 => outcome::OTHER,
        400 | 405 | 422 => outcome::REFUSED,
        401 | 403 => outcome::DENIED,
        404 | 410 => outcome::NOT_FOUND,
        409 | 412 => outcome::CONFLICT,
        413 => outcome::TOO_LARGE,
        429 | 503 => outcome::BUSY,
        502 => outcome::UNAVAILABLE,
        504 => outcome::TIMEOUT,
        401..=499 => outcome::REFUSED,
        500..=599 => outcome::FAILED,
        _ => return None,
    })
}

/// The status an answer without a detail is written with: the class's own
/// status. OTHER, and anything that is not a class, is 500 — an answer the
/// provider could not put in a class is not one an HTTP client can act on.
pub const fn canonical_status(o: u8) -> u16 {
    match o {
        outcome::OK => status::OK,
        outcome::REFUSED => status::BAD_REQUEST,
        outcome::NOT_FOUND => status::NOT_FOUND,
        outcome::DENIED => status::FORBIDDEN,
        outcome::CONFLICT => status::CONFLICT,
        outcome::TOO_LARGE => status::PAYLOAD_TOO_LARGE,
        outcome::BUSY => status::SERVICE_UNAVAILABLE,
        outcome::UNAVAILABLE => status::BAD_GATEWAY,
        outcome::TIMEOUT => status::GATEWAY_TIMEOUT,
        _ => status::INTERNAL_SERVER_ERROR,
    }
}

/// The status a response HEAD is written to an HTTP client with: its detail
/// when it has one, the outcome's canonical status otherwise.
pub const fn status_of(h: &ResponseHead<'_>) -> u16 {
    if h.detail != 0 {
        h.detail
    } else {
        canonical_status(h.outcome)
    }
}

// ── Methods ───────────────────────────────────────────────────────────────

/// The method for a request-line token, or 0 for any token this table does
/// not name. Case-sensitive: RFC 9110 §9.1 makes the method token
/// case-sensitive, so `get` is not a method. `CONNECT` is the plain CONNECT;
/// an extended CONNECT is [`method_for_protocol`]'s.
pub fn method_from_token(tok: &[u8]) -> u8 {
    match tok {
        b"GET" => method::GET,
        b"HEAD" => method::HEAD,
        b"POST" => method::POST,
        b"PUT" => method::PUT,
        b"PATCH" => method::PATCH,
        b"DELETE" => method::DELETE,
        b"OPTIONS" => method::OPTIONS,
        b"CONNECT" => method::CONNECT,
        _ => 0,
    }
}

/// The method of an extended CONNECT naming `:protocol` `proto`, or 0 for a
/// protocol this binding does not open.
pub fn method_for_protocol(proto: &[u8]) -> u8 {
    match proto {
        b"websocket" => method::WS_CONNECT,
        b"webtransport" => method::WT_CONNECT,
        _ => 0,
    }
}

/// Every token end to end, so [`method_name`] can answer with a span of this
/// rather than a table of separate literals.
const TOKENS: &[u8] = b"GETHEADPOSTPUTPATCHDELETEOPTIONSCONNECT";

/// `(offset, length)` into [`TOKENS`] per method, indexed by the method
/// itself. 0 and anything past the table is `(0, 0)`.
const TOKEN_SPAN: [(u8, u8); 11] = [
    (0, 0),  // none
    (0, 3),  // GET
    (3, 4),  // HEAD
    (7, 4),  // POST
    (11, 3), // PUT
    (14, 5), // PATCH
    (19, 6), // DELETE
    (25, 7), // OPTIONS
    (32, 7), // CONNECT
    (32, 7), // WS_CONNECT
    (32, 7), // WT_CONNECT
];

/// The request-line token for a method — for a request line, a log line, or
/// the `method` a browser API is handed. Empty for 0 and for anything this
/// table does not name; `CONNECT` for every opening verb.
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
    TOKENS.get(off..off + len).unwrap_or(&[])
}

// ── Responses ─────────────────────────────────────────────────────────────

/// A response HEAD carrying status `s`, its outcome computed. `None` for a
/// status this binding does not carry.
pub const fn head<'a>(
    id: ExchangeId,
    s: u16,
    meta: &'a [u8],
    body: &'a [u8],
) -> Option<ResponseHead<'a>> {
    match outcome_of(s) {
        Some(o) => Some(ResponseHead {
            id,
            flags: 0,
            outcome: o,
            detail: s,
            meta,
            body,
        }),
        None => None,
    }
}

/// Encode a whole response with status `s`: one HEAD carrying the entire
/// body, no MORE.
pub fn write_response(
    id: &ExchangeId,
    s: u16,
    meta: &[u8],
    body: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    ex::write_response_head::<Http>(&head(*id, s, meta, body)?, out)
}

/// Encode a status this provider raised itself: a terminal HEAD carrying
/// `s`, marked RAISED, with no meta or body.
pub fn write_refusal(id: &ExchangeId, s: u16, out: &mut [u8]) -> Option<usize> {
    let mut h = head(*id, s, &[], &[])?;
    h.flags = ex::flag::RAISED;
    ex::write_response_head::<Http>(&h, out)
}

// ── 100 Continue ──────────────────────────────────────────────────────────

/// Whether a request's meta asks for `100 Continue` (`expect:
/// 100-continue`). The first request-body CREDIT its provider grants is the
/// consent to the body; an HTTP server answers its client `100 Continue`
/// when that CREDIT arrives, and sends no interim response otherwise. A
/// provider refusing the body answers instead, and the client never sees a
/// `100`.
pub fn expects_continue(meta: &[u8]) -> bool {
    ex::meta_get(meta, b"expect").is_some_and(|v| v.eq_ignore_ascii_case(b"100-continue"))
}

// ── Header lines and meta ─────────────────────────────────────────────────

/// The meta key under which a server says how it routed a request it
/// delegates: [`ROUTE_FILE`] or [`ROUTE_PROXY`].
pub const META_ROUTE: &[u8] = b":route";
/// The route is a file route this server delegates.
pub const ROUTE_FILE: &[u8] = b"file";
/// The route is a proxy route this server delegates.
pub const ROUTE_PROXY: &[u8] = b"proxy";

/// The `name: value\r\n` lines of a header block, in order.
pub struct HeaderLines<'a> {
    rest: &'a [u8],
}

/// Iterate a header block's fields as `(name, value)` with optional whitespace
/// trimmed from the value. A line without a colon is skipped.
pub fn header_lines(block: &[u8]) -> HeaderLines<'_> {
    HeaderLines { rest: block }
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
            // Checked slicing throughout: a PIC module links no panic path.
            let line = self.rest.get(..end).unwrap_or(self.rest);
            self.rest = self.rest.get(end + 2..).unwrap_or(&[]);
            let Some(colon) = line.iter().position(|&c| c == b':') else {
                continue;
            };
            let name = line.get(..colon).unwrap_or(&[]);
            let mut v = line.get(colon + 1..).unwrap_or(&[]);
            while let [b' ' | b'\t', tail @ ..] = v {
                v = tail;
            }
            while let [head @ .., b' ' | b'\t'] = v {
                v = head;
            }
            return Some((name, v));
        }
        None
    }
}

/// The value of the first header named `name` (ASCII case-insensitive) in a
/// `name: value\r\n` block.
pub fn header<'a>(block: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    header_lines(block)
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
}

/// A header block as a meta run in `out`: each field a meta field keyed by
/// its name in lower case, in order. Returns the run's length; `None` when it
/// does not fit, or a name is empty or longer than a key.
pub fn meta_from_header_lines(block: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut w = ex::MetaWriter::new(out);
    for (name, value) in header_lines(block) {
        if name.is_empty() || name.len() > ex::META_KEY_MAX {
            return None;
        }
        let mut key = [0u8; ex::META_KEY_MAX];
        let key = key.get_mut(..name.len())?;
        for (k, c) in key.iter_mut().zip(name) {
            *k = c.to_ascii_lowercase();
        }
        w.put(key, value);
    }
    w.finish()
}

/// A meta run as a header block in `out`: `key: value\r\n` per field, in
/// order, the binding's own `:` keys left out. Returns the block's length;
/// `None` when it does not fit, or a value holds a CR or LF, which would end
/// the line and smuggle in another.
pub fn header_lines_from_meta(meta: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut at = 0usize;
    for (key, val) in ex::meta_fields(meta) {
        if key.first() == Some(&b':') {
            continue;
        }
        if val.iter().any(|&c| c == b'\r' || c == b'\n') {
            return None;
        }
        for part in [key, b": ", val, b"\r\n"] {
            out.get_mut(at..at + part.len())?.copy_from_slice(part);
            at += part.len();
        }
    }
    Some(at)
}
