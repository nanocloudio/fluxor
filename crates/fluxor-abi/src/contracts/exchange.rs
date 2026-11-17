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
//     HEAD     [op u8][verb u8][target_len u16][meta_len u16][peer_len u16]
//              [resp_credit u32] target | meta | peer | body
//     BODY     body bytes
//     ABORT    [reason u8]
//     CREDIT   [bytes u32]          response-body credit
//     DATAGRAM [context u64] payload
//
//   Response direction (provider -> requester):
//     HEAD     [outcome u8][detail u16][meta_len u16] meta | body
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
// A request names what it is with `op`: a CALL asks for an answer, a PUBLISH
// hands a record to a durable destination (`target` is its ordering key, the
// body the record), an OPEN asks for a session whose BODY records then carry
// the session's own stream. `verb` belongs to a BINDING — a protocol whose
// vocabulary a provider speaks on top of these records, such as HTTP
// (`exchange_http.rs`) — and is 0 outside one. The rules hold for every
// binding and are enforced where a HEAD is decoded or encoded: a PUBLISH
// carries verb 0; an OPEN carries one of its binding's opening verbs and a
// CALL never does; a verb its binding does not name is refused.
//
// `meta` is a run of fields `[key_len u8][key][val_len u16][val]`: a key of 1
// to 255 bytes with no ASCII upper-case letter, a value of up to 65535 bytes.
// A field means whatever its key names; the content type of a body, either
// direction, is the field `content-type` and travels nowhere else. A binding
// maps its own metadata onto fields (HTTP's header lines), and may reserve
// keys starting `:` for facts of its own that never leave as metadata.
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
// the provider's consent to the body.
//
// A response says how the exchange went with `outcome`, one of the classes in
// `outcome`, which every requester can act on without knowing the provider.
// `detail` is the binding's own account (an HTTP status), or 0. When detail is
// not 0 it determines the outcome: the outcome is the binding's class for that
// detail, an encoder that knows the binding computes it, and a decoder that
// knows the binding refuses a HEAD where the two disagree. A party that knows
// no binding carries `detail` without reading it.
//
// A HEAD whose answer the provider raised itself — it could not reach a peer,
// the peer did not answer in time, it refused the request before asking — is
// marked RAISED; without it, the answer is the peer's own. A relay forwards
// outcome, detail and RAISED verbatim.
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

use core::marker::PhantomData;

use crate::errno::EINVAL;

// ── Capabilities ──────────────────────────────────────────────────────────
//
// What a provider promises beyond answering. A provider that only answers — an
// application route, an HTTP or S3 endpoint — declares nothing; these name the
// delivery terms of a destination that durably accepts records in order.

/// What a requester REQUIRES when it publishes for durable, ordered delivery:
/// satisfied by either role below, under the registry's parent-matches-child
/// rule.
pub const CAP_ORDERED_ACK: &str = "stream.ordered_ack";
/// A provider that durably ACCEPTS records and answers with an outcome alone:
/// an MQTT topic, a Kafka partition, an INSERT.
pub const CAP_ORDERED_ACK_SINK: &str = "stream.ordered_ack.sink";
/// A provider that durably accepts and also ANSWERS WITH DATA: an HTTP call, a
/// SELECT. It does everything a sink does and more, which is why it is a
/// sibling of `.sink` under a shared parent.
pub const CAP_ORDERED_ACK_EXCHANGE: &str = "stream.ordered_ack.exchange";

// Terms a provider of either role satisfies: an answer with outcome OK means
// durable acceptance at the strongest level its configuration offers; order is
// kept per `target` within a connection; nothing is dropped silently — every
// exchange is answered or invalidated by LINK_DOWN; backpressure is by channel
// and credit, never by dropping; a BROADCAST request reaches every ordering
// unit and is answered once, after the slowest. A provider that offers less
// says so in its `[capability_facts]`.

/// The port-scoped capability of an `ExchangeRequest` port. Its one fact,
/// `binding`, lists the bindings whose verbs the port carries: a requester's
/// `request_out` declares the bindings it sends verbs of, a provider's
/// `request_in` the bindings it speaks. The build refuses an edge whose
/// producer declares a binding its consumer does not; a port that declares
/// none carries verb 0 only.
pub const CAP_EXCHANGE_REQUEST: &str = "exchange.request";

// ── Sizes ─────────────────────────────────────────────────────────────────

/// Fixed prefix of every record.
pub const HDR: usize = 16;
/// Largest record either side writes: one channel record.
pub const RECORD_MAX: usize = 8192;
/// Largest body one BODY record carries.
pub const BODY_MAX: usize = RECORD_MAX - HDR;
/// Fixed part of a request HEAD after the prefix.
pub const REQ_HEAD_FIXED: usize = 1 + 1 + 2 + 2 + 2 + 4;
/// Where a request HEAD's `peer_len` sits in its record, for a relay that
/// rewrites `peer` in place.
pub const REQ_PEER_LEN_AT: usize = HDR + 1 + 1 + 2 + 2;
/// Fixed part of a response HEAD after the prefix.
pub const RESP_HEAD_FIXED: usize = 1 + 2 + 2;
/// Length of the exchange id.
pub const ID_LEN: usize = 14;
/// Fixed part of one meta field: the key's and the value's lengths.
pub const META_FIELD_FIXED: usize = 1 + 2;
/// Longest meta key.
pub const META_KEY_MAX: usize = u8::MAX as usize;

/// The largest body a collected exchange carries — the figure a module that
/// takes requests whole sizes its buffer from, and the one a requester holds
/// itself to when no provider fact says otherwise. A provider whose backend
/// takes less declares the smaller number as its `max_payload` capability
/// fact, and the build checks it against the requester's own.
pub const PAYLOAD_MAX: usize = 8192;
/// The largest `target` a publish carries: a table or topic identifier plus a
/// natural key, with room for requesters whose ordering unit is wider.
pub const KEY_MAX: usize = 512;

/// The meta key a body's content type travels under, in either direction.
pub const META_CONTENT_TYPE: &[u8] = b"content-type";

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

/// What a request asks for.
pub mod op {
    /// Answer it.
    pub const CALL: u8 = 1;
    /// Accept a record for a durable destination: `target` is its ordering
    /// key, the body is the record. Carries verb 0.
    pub const PUBLISH: u8 = 2;
    /// Open a session: an answer with outcome OK accepts it, and BODY records
    /// in both directions then carry the session's stream. Carries one of its
    /// binding's opening verbs.
    pub const OPEN: u8 = 3;
}

/// Record flags.
pub mod flag {
    /// HEAD or BODY: more BODY records follow in this direction.
    pub const MORE: u8 = 0x01;
    /// Request HEAD: the requester asks for a held exchange (a watch, an
    /// event stream) that its provider keeps open until the origin ends it; a
    /// provider that grants it answers HOLD|MORE on the response HEAD and,
    /// once that head has come, applies no whole-exchange or stall deadline
    /// to it (liveness is the transport's own, e.g. an h2 PING). Response
    /// HEAD: the provider holds the exchange open on purpose and ends it
    /// itself; its progress deadline is the long one.
    pub const HOLD: u8 = 0x02;
    /// Request HEAD: deliver to every ordering unit, not the one `target`
    /// names.
    pub const BROADCAST: u8 = 0x04;
    /// Response HEAD: the provider raised this answer itself, and no peer
    /// answered — it could not reach one, the peer did not answer in time,
    /// or the provider refused the request before asking. Without it, the
    /// answer is the peer's own. A requester that must tell "the origin said
    /// it was unavailable" from "there was no origin to say anything" reads
    /// this bit; one that relays the answer onward needs nothing else.
    ///
    /// A body, if any — inline or in the BODY records that follow under
    /// MORE — is the provider's own account of what happened, never a
    /// peer's; a requester that wants no such account ABORTs the exchange
    /// rather than leave it waiting for credit. A relay forwards it verbatim;
    /// one that answers from a peer that set it keeps it, since its own
    /// requester was not answered by a peer either.
    pub const RAISED: u8 = 0x08;

    /// The flags a request HEAD may carry.
    pub const REQUEST_HEAD: u8 = MORE | HOLD | BROADCAST;
    /// The flags a response HEAD may carry.
    pub const RESPONSE_HEAD: u8 = MORE | HOLD | RAISED;
}

/// How an exchange went: the class of its answer, the same for every binding.
/// A requester branches on these alone.
pub mod outcome {
    /// Answered; for a sink, durably accepted.
    pub const OK: u8 = 1;
    /// Not a request this provider performs: malformed, an unknown verb, a
    /// target it cannot route, a header it would have to drop.
    pub const REFUSED: u8 = 2;
    /// What the request names does not exist.
    pub const NOT_FOUND: u8 = 3;
    /// The requester is not allowed to do this.
    pub const DENIED: u8 = 4;
    /// The request contradicts the state it names: a precondition that did
    /// not hold, a version that moved.
    pub const CONFLICT: u8 = 5;
    /// The request or its body passed what the provider takes.
    pub const TOO_LARGE: u8 = 6;
    /// The provider holds as many exchanges as it can, or was asked to slow
    /// down; the request may be repeated.
    pub const BUSY: u8 = 7;
    /// The peer behind the provider could not be reached, or answered with
    /// something the provider could not carry back.
    pub const UNAVAILABLE: u8 = 8;
    /// The peer behind the provider did not answer in time.
    pub const TIMEOUT: u8 = 9;
    /// The provider failed answering it.
    pub const FAILED: u8 = 10;
    /// An answer of no class above; `detail` says what it is.
    pub const OTHER: u8 = 11;

    /// Whether `o` is one of the classes above.
    pub const fn valid(o: u8) -> bool {
        o >= OK && o <= OTHER
    }
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

// ── Bindings ──────────────────────────────────────────────────────────────

/// What a party knows of the binding its records speak, and so what it
/// checks beyond the rules every binding shares. Decoders and encoders take
/// one as a type parameter.
pub trait Binding {
    /// Whether a request may carry `verb` under `op`. Asked only after the
    /// shared rules held: `op` is one of [`op`], a PUBLISH carries 0, an OPEN
    /// carries something else.
    fn admits(op: u8, verb: u8) -> bool;
    /// Whether a response may carry the non-zero `detail` under `outcome`.
    fn admits_detail(outcome: u8, detail: u16) -> bool;
}

/// A party that speaks no binding: its requests carry verb 0, so it opens no
/// session, and a detail on an answer is carried without being read.
pub struct Plain;

impl Binding for Plain {
    fn admits(_op: u8, verb: u8) -> bool {
        verb == 0
    }
    fn admits_detail(_outcome: u8, _detail: u16) -> bool {
        true
    }
}

/// A party that carries records between two others without speaking their
/// binding — a relay. It checks the shared rules and passes every verb and
/// detail through for the ends to judge.
pub struct Relayed;

impl Binding for Relayed {
    fn admits(_op: u8, _verb: u8) -> bool {
        true
    }
    fn admits_detail(_outcome: u8, _detail: u16) -> bool {
        true
    }
}

/// The rules every binding shares for a request's `op` and `verb`, then the
/// binding's own.
pub fn request_admitted<B: Binding>(op: u8, verb: u8) -> bool {
    let shared = match op {
        op::CALL => true,
        op::PUBLISH => verb == 0,
        op::OPEN => verb != 0,
        _ => false,
    };
    shared && B::admits(op, verb)
}

/// The rules every binding shares for a response's `outcome` and `detail`,
/// then the binding's own.
pub fn answer_admitted<B: Binding>(outcome: u8, detail: u16) -> bool {
    outcome::valid(outcome) && (detail == 0 || B::admits_detail(outcome, detail))
}

// ── Meta ──────────────────────────────────────────────────────────────────

fn meta_key_ok(key: &[u8]) -> bool {
    !key.is_empty() && key.len() <= META_KEY_MAX && !key.iter().any(u8::is_ascii_uppercase)
}

/// The fields of a meta run, in order, as `(key, value)`. Stops at the first
/// field that does not decode; a run a decoder accepted decodes whole.
pub struct MetaFields<'a> {
    rest: &'a [u8],
}

/// Iterate the fields of `meta`.
pub fn meta_fields(meta: &[u8]) -> MetaFields<'_> {
    MetaFields { rest: meta }
}

impl<'a> Iterator for MetaFields<'a> {
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let b = self.rest;
        let kl = usize::from(*b.first()?);
        let key = b.get(1..1 + kl)?;
        let vl = u16_at(b, 1 + kl)?;
        let at = 1 + kl + 2;
        let val = b.get(at..at + vl)?;
        self.rest = b.get(at + vl..).unwrap_or(&[]);
        Some((key, val))
    }
}

/// Whether `meta` is a whole run of well-formed fields.
pub fn meta_valid(meta: &[u8]) -> bool {
    let mut b = meta;
    while !b.is_empty() {
        let kl = usize::from(b[0]);
        let Some(key) = b.get(1..1 + kl) else {
            return false;
        };
        if !meta_key_ok(key) {
            return false;
        }
        let Some(vl) = u16_at(b, 1 + kl) else {
            return false;
        };
        match b.get(1 + kl + 2 + vl..) {
            Some(rest) => b = rest,
            None => return false,
        }
    }
    true
}

/// The value of the first field keyed `key`.
pub fn meta_get<'a>(meta: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    meta_fields(meta).find(|(k, _)| *k == key).map(|(_, v)| v)
}

/// The bytes one field of a `key_len`-byte key and a `val_len`-byte value
/// takes.
pub const fn meta_field_len(key_len: usize, val_len: usize) -> usize {
    META_FIELD_FIXED + key_len + val_len
}

/// Writes a meta run into a buffer, a field at a time. A field is whole or
/// absent: `over` records that something did not fit or a key broke the
/// rules, and [`MetaWriter::finish`] then answers `None`, so a run is never
/// sent short.
pub struct MetaWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
    /// Where the open field's value length sits, while a field is open.
    open: Option<usize>,
    over: bool,
}

impl<'a> MetaWriter<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        MetaWriter {
            buf,
            len: 0,
            open: None,
            over: false,
        }
    }

    /// One whole field.
    pub fn put(&mut self, key: &[u8], val: &[u8]) {
        self.begin(key);
        self.push(val);
        self.end();
    }

    /// Start a field keyed `key`; its value follows through
    /// [`MetaWriter::push`] or [`MetaWriter::spare`], and
    /// [`MetaWriter::end`] closes it.
    pub fn begin(&mut self, key: &[u8]) {
        if self.open.is_some() || !meta_key_ok(key) {
            self.over = true;
            return;
        }
        let at = self.len;
        let end = at + 1 + key.len() + 2;
        match self.buf.get_mut(at..end) {
            Some(d) => {
                d[0] = key.len() as u8;
                d[1..1 + key.len()].copy_from_slice(key);
                self.len = end;
                self.open = Some(end - 2);
            }
            None => self.over = true,
        }
    }

    /// Append value bytes to the open field.
    pub fn push(&mut self, bytes: &[u8]) {
        if self.open.is_none() {
            self.over = true;
            return;
        }
        match self.buf.get_mut(self.len..self.len + bytes.len()) {
            Some(d) => {
                d.copy_from_slice(bytes);
                self.len += bytes.len();
            }
            None => self.over = true,
        }
    }

    /// The room after the open field's value, for a writer that renders the
    /// value in place; [`MetaWriter::advance`] then takes what it wrote.
    pub fn spare(&mut self) -> &mut [u8] {
        self.buf.get_mut(self.len..).unwrap_or(&mut [])
    }

    /// Take `n` bytes written in place into [`MetaWriter::spare`].
    pub fn advance(&mut self, n: usize) {
        if self.open.is_none() || self.len + n > self.buf.len() {
            self.over = true;
            return;
        }
        self.len += n;
    }

    /// Mark the run short: something its writer meant to put did not fit.
    pub fn refuse(&mut self) {
        self.over = true;
    }

    /// Close the open field.
    pub fn end(&mut self) {
        let Some(at) = self.open.take() else {
            self.over = true;
            return;
        };
        let vl = self.len - at - 2;
        if vl > u16::MAX as usize {
            self.over = true;
            return;
        }
        match self.buf.get_mut(at..at + 2) {
            Some(d) => d.copy_from_slice(&(vl as u16).to_le_bytes()),
            None => self.over = true,
        }
    }

    /// The run's length, or `None` when it is not whole.
    pub fn finish(&self) -> Option<usize> {
        if self.over || self.open.is_some() {
            return None;
        }
        Some(self.len)
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

    pub fn read(b: &[u8]) -> Option<Self> {
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
    /// One of [`op`].
    pub op: u8,
    /// The binding's verb, or 0.
    pub verb: u8,
    pub target: &'a [u8],
    pub meta: &'a [u8],
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
    /// One of [`outcome`].
    pub outcome: u8,
    /// The binding's own account of the answer, or 0.
    pub detail: u16,
    pub meta: &'a [u8],
    /// The first body bytes, inline.
    pub body: &'a [u8],
}

impl<'a> ResponseHead<'a> {
    /// A head with no binding detail: `outcome`, `meta` and the inline body.
    pub const fn answer(id: ExchangeId, outcome: u8, meta: &'a [u8], body: &'a [u8]) -> Self {
        ResponseHead {
            id,
            flags: 0,
            outcome,
            detail: 0,
            meta,
            body,
        }
    }

    /// The body's content type, empty when the head names none.
    pub fn content_type(&self) -> &'a [u8] {
        meta_get(self.meta, META_CONTENT_TYPE).unwrap_or(&[])
    }
}

impl<'a> RequestHead<'a> {
    /// The body's content type, empty when the head names none.
    pub fn content_type(&self) -> &'a [u8] {
        meta_get(self.meta, META_CONTENT_TYPE).unwrap_or(&[])
    }
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
        kind::BODY if flags & !flag::MORE == 0 => Some(Record::Body {
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

/// Decode one request-direction record as a party speaking binding `B`.
/// `Err(EINVAL)` when it is malformed: a record is exactly one channel read,
/// so a length that disagrees with it is refused rather than read past or
/// short, and a HEAD whose `op`, `verb`, flags or meta break the rules is
/// refused whole.
pub fn parse_request<B: Binding>(b: &[u8]) -> Result<RequestRecord<'_>, i32> {
    if b.len() > RECORD_MAX {
        return Err(EINVAL);
    }
    let id = record_id(b).ok_or(EINVAL)?;
    if b[0] != kind::HEAD {
        return common(b, id).ok_or(EINVAL);
    }
    let p = HDR;
    let op = *b.get(p).ok_or(EINVAL)?;
    let verb = *b.get(p + 1).ok_or(EINVAL)?;
    let target_len = u16_at(b, p + 2).ok_or(EINVAL)?;
    let meta_len = u16_at(b, p + 4).ok_or(EINVAL)?;
    let peer_len = u16_at(b, REQ_PEER_LEN_AT).ok_or(EINVAL)?;
    let resp_credit = u32_at(b, p + 8).ok_or(EINVAL)?;
    let target_at = p + REQ_HEAD_FIXED;
    let meta_at = target_at + target_len;
    let peer_at = meta_at + meta_len;
    let body_at = peer_at + peer_len;
    if body_at > b.len() || b[1] & !flag::REQUEST_HEAD != 0 || !request_admitted::<B>(op, verb) {
        return Err(EINVAL);
    }
    let meta = &b[meta_at..peer_at];
    if !meta_valid(meta) {
        return Err(EINVAL);
    }
    Ok(Record::Head(RequestHead {
        id,
        flags: b[1],
        op,
        verb,
        target: &b[target_at..meta_at],
        meta,
        peer: &b[peer_at..body_at],
        resp_credit,
        body: &b[body_at..],
    }))
}

/// Decode one response-direction record as a party speaking binding `B`.
/// `Err(EINVAL)` when it is malformed, including a HEAD whose detail its
/// binding puts in another class than its outcome.
pub fn parse_response<B: Binding>(b: &[u8]) -> Result<ResponseRecord<'_>, i32> {
    if b.len() > RECORD_MAX {
        return Err(EINVAL);
    }
    let id = record_id(b).ok_or(EINVAL)?;
    match b[0] {
        kind::HEAD => {}
        kind::LINK if b.len() == HDR + 1 && id == ExchangeId::NONE => {
            return Ok(Record::Link { state: b[HDR] });
        }
        _ => return common(b, id).ok_or(EINVAL),
    }
    let p = HDR;
    let outcome = *b.get(p).ok_or(EINVAL)?;
    let detail = u16_at(b, p + 1).ok_or(EINVAL)? as u16;
    let meta_len = u16_at(b, p + 3).ok_or(EINVAL)?;
    let meta_at = p + RESP_HEAD_FIXED;
    let body_at = meta_at + meta_len;
    if body_at > b.len()
        || b[1] & !flag::RESPONSE_HEAD != 0
        || !answer_admitted::<B>(outcome, detail)
    {
        return Err(EINVAL);
    }
    let meta = &b[meta_at..body_at];
    if !meta_valid(meta) {
        return Err(EINVAL);
    }
    Ok(Record::Head(ResponseHead {
        id,
        flags: b[1],
        outcome,
        detail,
        meta,
        body: &b[body_at..],
    }))
}

/// Encode a request HEAD as a party speaking binding `B`. `None` when it
/// does not fit `out` or one record, or breaks a rule its decoder enforces.
pub fn write_request_head<B: Binding>(h: &RequestHead<'_>, out: &mut [u8]) -> Option<usize> {
    let end = HDR
        .checked_add(REQ_HEAD_FIXED)?
        .checked_add(h.target.len())?
        .checked_add(h.meta.len())?
        .checked_add(h.peer.len())?
        .checked_add(h.body.len())?;
    if end > out.len()
        || end > RECORD_MAX
        || h.target.len() > u16::MAX as usize
        || h.meta.len() > u16::MAX as usize
        || h.peer.len() > u16::MAX as usize
        || h.flags & !flag::REQUEST_HEAD != 0
        || !request_admitted::<B>(h.op, h.verb)
        || !meta_valid(h.meta)
    {
        return None;
    }
    prefix(kind::HEAD, h.flags, &h.id, out)?;
    let p = HDR;
    out[p] = h.op;
    out[p + 1] = h.verb;
    out[p + 2..p + 4].copy_from_slice(&(h.target.len() as u16).to_le_bytes());
    out[p + 4..p + 6].copy_from_slice(&(h.meta.len() as u16).to_le_bytes());
    out[REQ_PEER_LEN_AT..REQ_PEER_LEN_AT + 2].copy_from_slice(&(h.peer.len() as u16).to_le_bytes());
    out[p + 8..p + 12].copy_from_slice(&h.resp_credit.to_le_bytes());
    let mut at = p + REQ_HEAD_FIXED;
    for part in [h.target, h.meta, h.peer, h.body] {
        out[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    Some(at)
}

/// Encode a response HEAD as a party speaking binding `B`. `None` when it
/// does not fit `out` or one record, or breaks a rule its decoder enforces —
/// a detail its binding puts in another class than the outcome among them.
pub fn write_response_head<B: Binding>(h: &ResponseHead<'_>, out: &mut [u8]) -> Option<usize> {
    let at = seal_response_head::<B>(h, h.body.len(), out)?;
    let start = at - h.body.len();
    out[start..at].copy_from_slice(h.body);
    Some(at)
}

/// Seal a response HEAD whose `body_len` inline body bytes are already in
/// place at [`response_body_at`]`(h.meta.len())`, for a writer that renders
/// the body in place; `h.body` is not read. Returns the record length.
pub fn seal_response_head<B: Binding>(
    h: &ResponseHead<'_>,
    body_len: usize,
    out: &mut [u8],
) -> Option<usize> {
    let at = response_body_at(h.meta.len());
    out.get_mut(HDR + RESP_HEAD_FIXED..at)?
        .copy_from_slice(h.meta);
    seal_response_in_place::<B>(
        &h.id,
        h.flags,
        h.outcome,
        h.detail,
        h.meta.len(),
        body_len,
        out,
    )
}

/// Seal a response HEAD whose `meta_len` meta bytes and then `body_len`
/// inline body bytes are already in place at `out[HDR + RESP_HEAD_FIXED..]`,
/// for a writer that renders the meta in place too: writes the prefix and the
/// fixed part, checks what is in place as a decoder would, and returns the
/// record length.
pub fn seal_response_in_place<B: Binding>(
    id: &ExchangeId,
    flags: u8,
    outcome: u8,
    detail: u16,
    meta_len: usize,
    body_len: usize,
    out: &mut [u8],
) -> Option<usize> {
    let at = response_body_at(meta_len);
    let end = at.checked_add(body_len)?;
    if end > out.len()
        || end > RECORD_MAX
        || meta_len > u16::MAX as usize
        || flags & !flag::RESPONSE_HEAD != 0
        || !answer_admitted::<B>(outcome, detail)
        || !meta_valid(out.get(HDR + RESP_HEAD_FIXED..at)?)
    {
        return None;
    }
    prefix(kind::HEAD, flags, id, out)?;
    let p = HDR;
    out[p] = outcome;
    out[p + 1..p + 3].copy_from_slice(&detail.to_le_bytes());
    out[p + 3..p + 5].copy_from_slice(&(meta_len as u16).to_le_bytes());
    Some(end)
}

/// Where a response HEAD's inline body starts, for `meta_len` bytes of
/// meta — for a writer that renders the body in place.
pub const fn response_body_at(meta_len: usize) -> usize {
    HDR + RESP_HEAD_FIXED + meta_len
}

/// Encode a BODY record (either direction).
pub fn write_body(id: &ExchangeId, flags: u8, data: &[u8], out: &mut [u8]) -> Option<usize> {
    let end = HDR.checked_add(data.len())?;
    if end > out.len() || end > RECORD_MAX || flags & !flag::MORE != 0 {
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
    if end > out.len() || end > RECORD_MAX || flags & !flag::MORE != 0 {
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

/// Encode a whole response with no binding detail: one HEAD carrying
/// `outcome`, `meta` and the entire body, no MORE.
pub fn write_response(
    id: &ExchangeId,
    outcome: u8,
    meta: &[u8],
    body: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    write_response_head::<Plain>(&ResponseHead::answer(*id, outcome, meta, body), out)
}

/// Encode an answer the provider raises itself: a terminal HEAD carrying
/// `outcome` and no detail, marked [`flag::RAISED`], with no meta or body.
pub fn write_refusal(id: &ExchangeId, outcome: u8, out: &mut [u8]) -> Option<usize> {
    let mut h = ResponseHead::answer(*id, outcome, &[], &[]);
    h.flags = flag::RAISED;
    write_response_head::<Plain>(&h, out)
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
    /// The target, meta or body passed what the provider holds.
    TooLarge,
    /// A record that does not decode, does not belong to a collected
    /// exchange, or arrived out of order.
    Unexpected,
}

impl Refuse {
    /// The outcome a caller is owed for this refusal.
    pub const fn outcome(self) -> u8 {
        match self {
            Self::Busy => outcome::BUSY,
            Self::TooLarge => outcome::TOO_LARGE,
            Self::Unexpected => outcome::REFUSED,
        }
    }
}

#[derive(Clone, Copy)]
struct Slot<const TARGET: usize, const META: usize, const BODY: usize> {
    live: bool,
    done: bool,
    id: ExchangeId,
    op: u8,
    verb: u8,
    flags: u8,
    target: [u8; TARGET],
    target_len: u16,
    meta: [u8; META],
    meta_len: u16,
    body: [u8; BODY],
    body_len: u32,
    resp_credit: u32,
}

impl<const TARGET: usize, const META: usize, const BODY: usize> Slot<TARGET, META, BODY> {
    pub const EMPTY: Self = Slot {
        live: false,
        done: false,
        id: ExchangeId::NONE,
        op: 0,
        verb: 0,
        flags: 0,
        target: [0; TARGET],
        target_len: 0,
        meta: [0; META],
        meta_len: 0,
        body: [0; BODY],
        body_len: 0,
        resp_credit: 0,
    };
}

/// A request whose body is complete.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub id: ExchangeId,
    pub op: u8,
    pub verb: u8,
    pub flags: u8,
    pub target: &'a [u8],
    pub meta: &'a [u8],
    pub body: &'a [u8],
    /// Response body bytes the requester has granted so far.
    pub resp_credit: u32,
}

/// The exchanges a provider speaking binding `B` is collecting: `SLOTS` at
/// once, each holding up to `TARGET`, `META` and `BODY` bytes. Each module
/// sets the four from what it actually serves.
pub struct Collector<
    B: Binding,
    const SLOTS: usize,
    const TARGET: usize,
    const META: usize,
    const BODY: usize,
> {
    slots: [Slot<TARGET, META, BODY>; SLOTS],
    /// A request-body credit owed to the requester. A provider that grants
    /// nothing never receives a body, and the symptom is not an error but a
    /// request that stays half-collected, so the grant is owed the moment an
    /// exchange opens with a body to come.
    grant: Option<(ExchangeId, u32)>,
    /// A refusal owed to a caller, with the exchange it answers. Kept beside the
    /// grant and taken the same way, because the collector does no I/O —
    /// whoever owns the port sends it.
    refusal: Option<(ExchangeId, Refuse)>,
    binding: PhantomData<fn() -> B>,
}

impl<B: Binding, const SLOTS: usize, const TARGET: usize, const META: usize, const BODY: usize>
    Collector<B, SLOTS, TARGET, META, BODY>
{
    pub const fn new() -> Self {
        Collector {
            slots: [Slot::EMPTY; SLOTS],
            grant: None,
            refusal: None,
            binding: PhantomData,
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
        let rec = match parse_request::<B>(record) {
            Ok(rec) => rec,
            Err(_) => {
                // A HEAD that breaks a rule still names its exchange, and is
                // owed an answer; anything else malformed has nowhere to
                // send one.
                return match (record_kind(record), record_id(record)) {
                    (Some(kind::HEAD), Some(id)) => Err(self.refuse(id, Refuse::Unexpected)),
                    _ => Err(Refuse::Unexpected),
                };
            }
        };
        match rec {
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
        if head.target.len() > TARGET || head.meta.len() > META || head.body.len() > BODY {
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
        slot.op = head.op;
        slot.verb = head.verb;
        slot.flags = head.flags;
        slot.resp_credit = head.resp_credit;
        slot.target[..head.target.len()].copy_from_slice(head.target);
        slot.meta[..head.meta.len()].copy_from_slice(head.meta);
        slot.body[..head.body.len()].copy_from_slice(head.body);
        // Every length was bounded above by a const that fits.
        slot.target_len = head.target.len() as u16;
        slot.meta_len = head.meta.len() as u16;
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
            op: slot.op,
            verb: slot.verb,
            flags: slot.flags,
            target: slot.target.get(..usize::from(slot.target_len))?,
            meta: slot.meta.get(..usize::from(slot.meta_len))?,
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
    /// refused record named no exchange — a record too short to carry an id
    /// has nowhere to send an answer.
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

impl<B: Binding, const SLOTS: usize, const TARGET: usize, const META: usize, const BODY: usize>
    Default for Collector<B, SLOTS, TARGET, META, BODY>
{
    fn default() -> Self {
        Self::new()
    }
}
