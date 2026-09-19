// Contract: http_exchange — the records an HTTP connector is asked through.
//
// Layer: contracts/net (public, stable).
//
// These records are the seam a caller asks THROUGH: one request, and the
// answer to it. A graph node ISSUES a request that a connector performs,
// over `stream.ordered_ack.exchange` — the exchange surface carries records
// and never learns what they mean, and what they mean is here.
//
// Three parties speak this layout and none may restate it: the consumer
// that composes a request and reads the answer, the connector that performs
// it on a socket, and the connector that performs it through a browser.
// Every one of them depends on fluxor and on nothing else in common, which
// is why the layout lives here rather than with whichever connector came
// first — a layout owned by one implementor is one the others must copy,
// and a copy is where an offset drifts. Mounted from here, the three cannot
// disagree about a byte without the build refusing the mismatch.
//
// The method vocabulary is here for the same reason: a request names its
// method as one byte, and every reader of that byte needs the same table.
//
// Layouts (multi-byte ints LE):
//
//   Request, plain -- answered with the response BODY alone:
//     [method:u8][path_len:u16][body_len:u16][path…][body…]
//
//   Request, extended -- the verb's high bit asks for the whole response and
//   says the record carries a header block of its own. Verb codes are small,
//   so the bit is free, and a producer that leaves it clear composes the
//   plain record above:
//     [method|0x80][path_len:u16][body_len:u16][hdr_len:u16]
//     [path…][headers…][body…]
//
//   Reply to an extended request -- the response's head. Its BODY streams
//   separately, because a reply is one record on a surface whose ceiling
//   every provider sizes its buffers from, and a response of any length
//   cannot be one:
//     [status:u16][hdr_len:u16][headers…]
//
//   One streamed body chunk. A zero-length chunk ends the body: without it a
//   reader cannot tell a pause from an ending.
//     [len:u16][bytes…]
//
//   Either request form may carry ONE optional trailing field after its
//   last counted byte, the authority the request is for:
//     […request…][auth_len:u8][authority…]
//   Every counted field keeps its offset, so a producer that names no
//   authority composes exactly the records above, and a reader with no use
//   for the field stops at the last counted byte. An absent field means
//   "the connector's own authority". A connector whose `authority` parameter is
//   set dials that and refuses a record naming another (a pinned client is
//   pinned); a connector with none set dials the record's, and is open.
//
// `headers` in both directions is a block as it goes on the wire, each line
// ending CRLF.

/// The verb's high bit: this record is extended.
pub const EXTENDED: u8 = 0x80;
/// Bytes before the fields of a plain request.
pub const REQ_HEAD: usize = 1 + 2 + 2;
/// Bytes before the fields of an extended request.
pub const REQ_HEAD_EXTENDED: usize = REQ_HEAD + 2;
/// Bytes before the header block of a reply.
pub const RESP_HEAD: usize = 2 + 2;
/// The length that precedes each chunk of a streamed body.
///
/// The reply to an extended request carries the head and goes before the
/// body, so nothing else says where that body ends. A zero-length chunk does,
/// and a length on every chunk is what makes the zero one readable rather
/// than an empty record a channel might not carry at all.
pub const CHUNK_HEAD: usize = 2;

/// What a request record says, with the fields still inside the caller's
/// buffer. Nothing is copied: a parser hands back where things are, and a
/// module that wants them elsewhere copies them itself.
pub struct Request<'a> {
    pub method: u8,
    pub extended: bool,
    pub path: &'a [u8],
    pub headers: &'a [u8],
    pub body: &'a [u8],
    /// The trailing authority field, `host[:port]`; empty when the record
    /// carries none and the connector's own applies.
    pub authority: &'a [u8],
}

/// Longest authority the trailing field carries: its length is one byte.
pub const AUTHORITY_MAX: usize = 255;

/// The ceilings a request is held to. They belong to the module rather than
/// to the layout -- a consumer with more room is not reading a different
/// record -- so they are passed in rather than written here.
pub struct Limits {
    pub path: usize,
    pub headers: usize,
    pub body: usize,
}

/// Why a request record was not accepted. The two are answered differently:
/// a malformed record is unroutable, an oversize one is a record this
/// consumer cannot hold, and a caller can act on the difference.
pub enum RequestParse<'a> {
    Ok(Request<'a>),
    Malformed,
    Oversize,
}

fn u16_at(bytes: &[u8], at: usize) -> usize {
    match bytes.get(at..at + 2) {
        Some(pair) => usize::from(u16::from_le_bytes([pair[0], pair[1]])),
        None => 0,
    }
}

/// Read a request record.
///
/// Every length is checked against the record's own length before any field
/// is named, so a record whose fields do not add up is refused rather than
/// read past. `path_len == 0` is malformed: a request names a resource.
pub fn parse_request<'a>(payload: &'a [u8], limits: &Limits) -> RequestParse<'a> {
    if payload.len() < REQ_HEAD {
        return RequestParse::Malformed;
    }
    let raw = payload[0];
    let extended = raw & EXTENDED != 0;
    let method = raw & !EXTENDED;
    let path_len = u16_at(payload, 1);
    let body_len = u16_at(payload, 3);
    let head = if extended {
        REQ_HEAD_EXTENDED
    } else {
        REQ_HEAD
    };
    if payload.len() < head {
        return RequestParse::Malformed;
    }
    let headers_len = if extended {
        u16_at(payload, REQ_HEAD)
    } else {
        0
    };
    let path_at = head;
    let headers_at = path_at + path_len;
    let body_at = headers_at + headers_len;
    let body_end = body_at + body_len;
    if path_len == 0 || body_end > payload.len() {
        return RequestParse::Malformed;
    }
    // The optional tail: nothing, or exactly one length-prefixed authority.
    let authority = match payload.get(body_end..) {
        Some([]) | None => &payload[0..0],
        Some(tail) => {
            let len = usize::from(tail[0]);
            if len == 0 || tail.len() != 1 + len || !authority_ok(&tail[1..]) {
                return RequestParse::Malformed;
            }
            &tail[1..]
        }
    };
    let Some(headers) = payload.get(headers_at..body_at) else {
        return RequestParse::Malformed;
    };
    if !header_block_ok(headers) {
        return RequestParse::Malformed;
    }
    // Shape first, size second: a record that does not parse is malformed
    // whatever its lengths claim, and answering "too big" to a record that
    // was never well formed tells a caller to retry smaller for no reason.
    if path_len > limits.path || headers_len > limits.headers || body_len > limits.body {
        return RequestParse::Oversize;
    }
    let (Some(path), Some(body)) = (
        payload.get(path_at..headers_at),
        payload.get(body_at..body_at + body_len),
    ) else {
        return RequestParse::Malformed;
    };
    RequestParse::Ok(Request {
        method,
        extended,
        path,
        headers,
        body,
        authority,
    })
}

/// Whether bytes may travel as the trailing authority: printable ASCII with
/// no space, so a `Host:` line spliced from it cannot carry a second field.
pub fn authority_ok(a: &[u8]) -> bool {
    !a.is_empty() && a.len() <= AUTHORITY_MAX && a.iter().all(|&c| c > 0x20 && c < 0x7F)
}

/// Compose a request record into `out`, answering its length.
///
/// `None` when `out` cannot hold it, which is the only way this can fail:
/// every field is already bounded by the lengths it writes. Composes no
/// trailing authority; [`write_request_to`] does.
pub fn write_request(
    method: u8,
    extended: bool,
    path: &[u8],
    headers: &[u8],
    body: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    write_request_to(method, extended, path, headers, body, &[], out)
}

/// Compose a request record naming the authority it is for, into `out`,
/// answering its length. An empty `authority` composes the plain record;
/// one that [`authority_ok`] refuses is `None`.
pub fn write_request_to(
    method: u8,
    extended: bool,
    path: &[u8],
    headers: &[u8],
    body: &[u8],
    authority: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let head = if extended {
        REQ_HEAD_EXTENDED
    } else {
        REQ_HEAD
    };
    let tail = if authority.is_empty() {
        0
    } else if authority_ok(authority) {
        1 + authority.len()
    } else {
        return None;
    };
    let total = head + path.len() + if extended { headers.len() } else { 0 } + body.len() + tail;
    if total > out.len()
        || path.len() > u16::MAX as usize
        || headers.len() > u16::MAX as usize
        || body.len() > u16::MAX as usize
    {
        return None;
    }
    out[0] = if extended {
        method | EXTENDED
    } else {
        method & !EXTENDED
    };
    let path_len = (path.len() as u16).to_le_bytes();
    out[1] = path_len[0];
    out[2] = path_len[1];
    let body_len = (body.len() as u16).to_le_bytes();
    out[3] = body_len[0];
    out[4] = body_len[1];
    if extended {
        let headers_len = (headers.len() as u16).to_le_bytes();
        out[REQ_HEAD] = headers_len[0];
        out[REQ_HEAD + 1] = headers_len[1];
    }
    let mut at = head;
    for field in [path, if extended { headers } else { &[] }, body] {
        let end = at + field.len();
        match out.get_mut(at..end) {
            Some(slot) => slot.copy_from_slice(field),
            None => return None,
        }
        at = end;
    }
    if tail > 0 {
        // Written through the same bounds-checked shape as the fields above:
        // a copy whose lengths the compiler cannot prove equal carries a
        // panic path, and a module image links none.
        out[at] = authority.len() as u8;
        at += 1;
        let end = at + authority.len();
        match out.get_mut(at..end) {
            Some(slot) => slot.copy_from_slice(authority),
            None => return None,
        }
        at = end;
    }
    Some(at)
}

/// Compose a reply head into `out`, answering its length.
pub fn write_reply_head(status: u16, headers: &[u8], out: &mut [u8]) -> Option<usize> {
    let total = RESP_HEAD + headers.len();
    if total > out.len() || headers.len() > u16::MAX as usize {
        return None;
    }
    let code = status.to_le_bytes();
    out[0] = code[0];
    out[1] = code[1];
    let head_len = (headers.len() as u16).to_le_bytes();
    out[2] = head_len[0];
    out[3] = head_len[1];
    out.get_mut(RESP_HEAD..total)?.copy_from_slice(headers);
    Some(total)
}

/// Read a reply head, answering the status and the block behind it.
pub fn parse_reply_head(payload: &[u8]) -> Option<(u16, &[u8])> {
    if payload.len() < RESP_HEAD {
        return None;
    }
    let status = u16::from_le_bytes([payload[0], payload[1]]);
    let head_len = u16_at(payload, 2);
    let headers = payload.get(RESP_HEAD..RESP_HEAD + head_len)?;
    Some((status, headers))
}

/// Frame one body chunk into `out`, answering its length. A zero-length
/// `bytes` composes the chunk that ends the body.
pub fn write_chunk(bytes: &[u8], out: &mut [u8]) -> Option<usize> {
    let total = CHUNK_HEAD + bytes.len();
    if total > out.len() || bytes.len() > u16::MAX as usize {
        return None;
    }
    let length = (bytes.len() as u16).to_le_bytes();
    out[0] = length[0];
    out[1] = length[1];
    out.get_mut(CHUNK_HEAD..total)?.copy_from_slice(bytes);
    Some(total)
}

/// Read one body chunk, answering its bytes and how much of `buffer` it
/// took. `None` while the chunk is still arriving -- a reader keeps what it
/// has and asks again, rather than reading a length that is not all there.
pub fn parse_chunk(buffer: &[u8]) -> Option<(&[u8], usize)> {
    if buffer.len() < CHUNK_HEAD {
        return None;
    }
    let length = u16_at(buffer, 0);
    let bytes = buffer.get(CHUNK_HEAD..CHUNK_HEAD + length)?;
    Some((bytes, CHUNK_HEAD + length))
}

fn eq_name(name: &[u8], lower: &[u8]) -> bool {
    if name.len() != lower.len() {
        return false;
    }
    let mut i = 0;
    while i < name.len() {
        if name[i].to_ascii_lowercase() != lower[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Whether a field name may appear in a caller's block.
///
/// Four names are the connector's own: it sets the length or the encoding
/// from what it is actually sending, and the host and connection from the
/// endpoint it was wired to. A caller that could set them could describe a
/// body it did not send, which is a request smuggled past whatever read the
/// record.
fn field_name_ok(name: &[u8]) -> bool {
    let mut i = 0;
    while i < name.len() {
        if name[i] <= 0x20 || name[i] == 0x7F {
            return false;
        }
        i += 1;
    }
    !eq_name(name, b"content-length")
        && !eq_name(name, b"transfer-encoding")
        && !eq_name(name, b"host")
        && !eq_name(name, b"connection")
}

/// Whether a caller's header block may be spliced into a request head.
pub fn header_block_ok(b: &[u8]) -> bool {
    if b.is_empty() {
        return true;
    }
    if b.len() < 2 || &b[b.len() - 2..] != b"\r\n" {
        return false;
    }
    let mut line_start = 0usize;
    let mut colon = false;
    let mut i = 0usize;
    while i + 1 < b.len() {
        match b[i] {
            b'\r' => {
                // A CRLF with nothing before it is the blank line that ends a
                // head; a CR without its LF splits a line on some peers and
                // not others, which is the same ambiguity by a shorter route.
                if b[i + 1] != b'\n' || i == line_start || !colon {
                    return false;
                }
                line_start = i + 2;
                colon = false;
                i += 2;
            }
            b'\n' => return false,
            b':' if !colon => {
                // The first colon on the line ends the name, and a name must
                // precede it.
                if i == line_start || !field_name_ok(&b[line_start..i]) {
                    return false;
                }
                colon = true;
                i += 1;
            }
            // Inside a value: horizontal tab is legal there, nothing else
            // below a space is.
            c if colon && c < 0x20 && c != b'\t' => return false,
            c if colon && c == 0x7F => return false,
            _ => i += 1,
        }
    }
    line_start == b.len()
}

// ── Method vocabulary ───────────────────────────────────────────────
//
// A request names its method as one byte, so every reader of a request
// decodes it with this table. The values are STABLE and PUBLIC: appending a
// method is safe, renumbering one is a wire-format break, exactly as for
// the content-type table.
//
// `GET`/`CONNECT`/`POST` are 1/2/3 because HTTP/2 and HTTP/3 servers test
// `method == 2` for the RFC 8441 / RFC 9220 extended CONNECT that carries a
// WebSocket upgrade; the rest are appended after them.
//
// Deliberately NOT a Rust enum: the value crosses a channel as a byte, and a
// `#[repr(u8)]` enum would make every decode a fallible transmute at the
// receiver for no gain over a `u8` plus these constants.

/// No method parsed yet, or an unrecognised token.
pub const METHOD_NONE: u8 = 0;
pub const METHOD_GET: u8 = 1;
/// Kept at 2: h2 and h3 test `method == 2` for extended CONNECT.
pub const METHOD_CONNECT: u8 = 2;
pub const METHOD_POST: u8 = 3;
pub const METHOD_HEAD: u8 = 4;
pub const METHOD_PUT: u8 = 5;
pub const METHOD_PATCH: u8 = 6;
pub const METHOD_DELETE: u8 = 7;
pub const METHOD_OPTIONS: u8 = 8;

/// The method constant for a request-line token, or [`METHOD_NONE`] for
/// any token this table does not name. Case-sensitive: RFC 9110 §9.1
/// makes the method token case-sensitive, so `get` is not a method.
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

/// Every token end to end, so [`method_name`] can answer with a span of
/// this rather than a table of eight separate literals.
const TOKENS: &[u8] = b"GETCONNECTPOSTHEADPUTPATCHDELETEOPTIONS";

/// `(offset, length)` into [`TOKENS`] per method constant, indexed by the
/// constant itself. [`METHOD_NONE`] and anything past the table is `(0, 0)`,
/// which spans no bytes.
const TOKEN_SPAN: [(u8, u8); 9] = [
    (0, 0),  // METHOD_NONE
    (0, 3),  // GET
    (3, 7),  // CONNECT
    (10, 4), // POST
    (14, 4), // HEAD
    (18, 3), // PUT
    (21, 5), // PATCH
    (26, 6), // DELETE
    (32, 7), // OPTIONS
];

/// The token for a method constant — for a request line, a log line, or
/// the `method` a browser API is handed. Empty for [`METHOD_NONE`].
///
/// The span table holds integers, not string references, and that is
/// load-bearing. A `match` returning a different `&'static [u8]` per arm
/// compiles to a table of `{pointer, length}` pairs that the linker fills
/// with absolute addresses and marks for relocation. A `.fmod` is a flat
/// image mapped at whatever base the loader picks, with no relocations
/// applied, so every pointer in such a table is wrong by the load address
/// and the first read walks into unmapped memory. Offsets into one literal
/// need no relocation, and the single reference to `TOKENS` is materialised
/// PC-relative like any other code-adjacent constant.
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
