// Contract: ordered-ack record exchange (`stream.ordered_ack`).
//
// Layer: contracts (portable capability vocabulary).
//
// The surface a producer of records binds to reach ANY destination that can
// durably accept them in order — and, when the destination answers, to get
// that answer back on the same correlation: an MQTT topic, a Kafka
// partition, an AMQP queue, a table, an HTTP endpoint. A producer emits
// publish frames and consumes acks; it never learns which of those a
// deployment wired, and the provider never learns what the records mean.
// That mutual ignorance is the point — it is what lets one graph swap a
// broker for a database by pin.
//
// Ports:
//
//   publish_in (input):  [corr:u64][flags:u8][msg_key_len:u16][msg_key…]
//                        [payload_len:u16][payload…]
//   ack_out    (output): [corr:u64][status:u8]
//   reply_out  (output): [corr:u64][status:u8][msg_key_len:u16][msg_key…]
//                        [payload_len:u16][payload…]      — OPTIONAL
//
// `reply_out` is what makes this an EXCHANGE surface rather than a sink. A
// destination that only accepts records (an MQTT topic, a Kafka partition,
// an INSERT) implements `publish_in` + `ack_out` and declares
// `stream.ordered_ack.sink`. A destination that answers with data (an HTTP
// GET, a SELECT) additionally implements `reply_out` and declares
// `stream.ordered_ack.exchange`. The frames and the correlation are
// identical; only the presence of an answer differs, and the capability name
// is the single place that says which.
//
// A provider that replies answers each publish EXACTLY ONCE, on `reply_out` —
// the reply carries the status, so it is the ack. `ack_out` then carries only
// the `corr = 0` link-state signals. A provider that does not reply answers on
// `ack_out`. Nothing is ever answered on both.
//
// The reply ECHOES the publish's `msg_key` unchanged. That is deliberate and
// it is what lets a consumer be stateless: a producer stage puts whatever it
// needs to rejoin the answer into the key, and the stage handling the reply
// gets it back beside the payload without anyone keeping a correlation table.
// A request built from one pipeline stage and a response handled by the next
// therefore needs no shared state — only the graph edge between them.
//
// `corr` is never 0 on a publish. Ack statuses: 0 = durably accepted at the
// strongest level the provider's configuration offers; 1..=15 typed refusals;
// and two `corr = 0` LINK-STATE signals that are not replies — LINK_DOWN
// (every unacked corr is now unknowable; the producer MUST re-publish all of
// them after the next LINK_UP) and LINK_UP.
//
// `msg_key` is OPAQUE to the provider. It is the ordering unit: a partitioned
// backend partitions by it, an unpartitioned one ignores it. A producer that
// wants per-key ordering puts its own key there, in whatever encoding it
// likes, and the provider never decodes it.
//
// Terms a conforming provider must satisfy: ack = durable acceptance;
// per-key order within a connection; no silent drops (every non-zero corr
// answered, or invalidated by LINK_DOWN); backpressure by channel, never by
// dropping; broadcast delivered to every ordering unit and acked once after
// the slowest. Where a provider offers less, it says so in its
// `[capability_facts]` — an unstated term is a promise to meet the strong
// form, which is why the weaker ones have names to declare.
//
// The definition lives here rather than with its first producer, because a
// contract owned by one consumer and implemented by another is an inversion:
// the implementor would have to depend on the definer to know what it is
// implementing. Every party depends on fluxor, so this is the one place that
// costs nobody a dependency they would not otherwise have.
//
// What a `payload` MEANS is not part of this surface. A change-data-capture
// envelope — event kinds, commit timestamps, a staleness rule — is one
// possible payload, and it stays with the producer that defines it.

/// The capability a consumer REQUIRES when it only publishes: satisfied by
/// either provider role below, under the registry's parent-matches-child
/// rule.
pub const CAP_ORDERED_ACK: &str = "stream.ordered_ack";
/// A provider that ACCEPTS records and does not answer with data: an MQTT
/// topic, a Kafka partition, an INSERT.
pub const CAP_ORDERED_ACK_SINK: &str = "stream.ordered_ack.sink";
/// A provider that ANSWERS WITH DATA: an HTTP GET, a SELECT. It does
/// everything a sink does and more, which is why it is a SIBLING of `.sink`
/// under a shared parent rather than a separate capability — a consumer that
/// only publishes requires the parent and accepts either.
pub const CAP_ORDERED_ACK_EXCHANGE: &str = "stream.ordered_ack.exchange";

// ── Port frames ───────────────────────────────────────────────────────

/// Publish flags.
pub const FLAG_BROADCAST: u8 = 0x01;

/// Ack statuses. `0` = durably accepted; `1..=15` typed refusals;
/// `16`/`17` link-state signals carried with `corr = 0`.
pub const STATUS_OK: u8 = 0;
pub const REFUSE_OVERSIZE: u8 = 1;
pub const REFUSE_UNROUTABLE: u8 = 2;
/// Connection lost: every corr issued and not yet acked is now
/// unknowable; the pump MUST re-publish all of them after LINK_UP.
pub const STATUS_LINK_DOWN: u8 = 16;
/// (Re)connected and writable.
pub const STATUS_LINK_UP: u8 = 17;

/// A publish frame on `publish_in`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Publish<'a> {
    /// Correlation id; never 0.
    pub corr: u64,
    pub flags: u8,
    pub msg_key: &'a [u8],
    pub payload: &'a [u8],
}

/// Fixed publish-frame overhead: corr(8)+flags(1)+klen(2)+plen(2).
pub const PUBLISH_OVERHEAD: usize = 8 + 1 + 2 + 2;

// ── The size envelope ─────────────────────────────────────────────────────
//
// One anchor, here, because a ceiling chosen per provider is a ceiling chosen
// as many ways as there are providers — and none of them discoverable by the
// producer that has to stay under it. Sinks in practice sit anywhere from a
// kilobyte to the full record, set by a broker build, a negotiated frame size
// or a column width; a producer cannot derive any of that from the protocol
// name.
//
// So the SURFACE names one number and providers derive their buffers from it.
// A provider whose backend cannot accept the full ceiling declares the
// smaller number as its `max_payload` capability fact — which is what that
// fact is for. The build compares it against the PRODUCER's own
// `max_payload` fact, never against a port's `max_record`: the two measure
// different things, a record being a payload plus this file's framing. A
// mismatch is then a build failure rather than an OVERSIZE refusal on every
// full-size record at runtime.

/// The payload a publish or reply may carry — the number every provider of
/// this surface sizes its buffers from, and the one a producer holds itself
/// to when no provider fact says otherwise.
pub const PAYLOAD_MAX: usize = 8192;

/// The largest `msg_key`. Sized to carry a table or topic identifier plus a
/// 256-byte natural key, with room left for producers whose ordering unit is
/// wider than that.
pub const KEY_MAX: usize = 512;

/// A whole publish frame at the ceiling — what a `publish_in` port must be
/// able to take as one record, and what a producer declares as `max_record`.
pub const PUBLISH_FRAME_MAX: usize = PUBLISH_OVERHEAD + KEY_MAX + PAYLOAD_MAX;

impl<'a> Publish<'a> {
    pub fn wire_len(&self) -> usize {
        PUBLISH_OVERHEAD + self.msg_key.len() + self.payload.len()
    }

    /// Encode. `None` on a zero corr, an over-length field, or a
    /// too-small buffer.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        if self.corr == 0
            || self.msg_key.len() > u16::MAX as usize
            || self.payload.len() > u16::MAX as usize
        {
            return None;
        }
        let need = self.wire_len();
        if out.len() < need {
            return None;
        }
        let mut p = 0usize;
        out[p..p + 8].copy_from_slice(&self.corr.to_le_bytes());
        p += 8;
        out[p] = self.flags;
        p += 1;
        out[p..p + 2].copy_from_slice(&(self.msg_key.len() as u16).to_le_bytes());
        p += 2;
        out[p..p + 2].copy_from_slice(&(self.payload.len() as u16).to_le_bytes());
        p += 2;
        out[p..p + self.msg_key.len()].copy_from_slice(self.msg_key);
        p += self.msg_key.len();
        out[p..p + self.payload.len()].copy_from_slice(self.payload);
        p += self.payload.len();
        Some(p)
    }

    pub fn decode(src: &'a [u8]) -> Option<Self> {
        if src.len() < PUBLISH_OVERHEAD {
            return None;
        }
        let corr = u64::from_le_bytes(src[0..8].try_into().ok()?);
        if corr == 0 {
            return None;
        }
        let flags = src[8];
        let klen = u16::from_le_bytes([src[9], src[10]]) as usize;
        let plen = u16::from_le_bytes([src[11], src[12]]) as usize;
        let p = PUBLISH_OVERHEAD;
        let msg_key = src.get(p..p + klen)?;
        let payload = src.get(p + klen..p + klen + plen)?;
        if p + klen + plen != src.len() {
            return None;
        }
        Some(Self {
            corr,
            flags,
            msg_key,
            payload,
        })
    }
}

/// An ack (or link-state) frame on `ack_out`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ack {
    /// `0` = link-state signal, otherwise the answered publish.
    pub corr: u64,
    pub status: u8,
}

pub const ACK_WIRE_LEN: usize = 9;

impl Ack {
    /// A per-publish reply. Refuses the reserved link-state statuses —
    /// those never answer a corr.
    pub fn reply(corr: u64, status: u8) -> Option<Self> {
        if corr == 0 || status >= STATUS_LINK_DOWN {
            return None;
        }
        Some(Self { corr, status })
    }

    /// A link-state signal (corr 0).
    pub fn link(status: u8) -> Option<Self> {
        if status != STATUS_LINK_DOWN && status != STATUS_LINK_UP {
            return None;
        }
        Some(Self { corr: 0, status })
    }

    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        if out.len() < ACK_WIRE_LEN {
            return None;
        }
        out[0..8].copy_from_slice(&self.corr.to_le_bytes());
        out[8] = self.status;
        Some(ACK_WIRE_LEN)
    }

    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() != ACK_WIRE_LEN {
            return None;
        }
        Some(Self {
            corr: u64::from_le_bytes(src[0..8].try_into().ok()?),
            status: src[8],
        })
    }

    /// Is this a link-state signal rather than a reply?
    pub fn is_link_state(&self) -> bool {
        self.corr == 0
    }
}

/// A reply frame on `reply_out`: an answer carrying data.
///
/// Distinct from [`Ack`] because an ack says only whether a record was
/// taken, while a reply also carries what came back. Both correlate the same
/// way, so a producer that starts sink-only and later needs answers changes
/// which port it reads, not how it identifies them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply<'a> {
    /// The publish this answers; never 0 — a reply is never a link-state
    /// signal, those stay on `ack_out`.
    pub corr: u64,
    /// `0` = answered; `1..=15` the same typed refusals an ack uses.
    pub status: u8,
    /// The publish's `msg_key`, echoed unchanged.
    pub msg_key: &'a [u8],
    /// What the destination returned. Empty is legitimate — a 204, a DELETE
    /// affecting no rows — and is not the same as a refusal.
    pub payload: &'a [u8],
}

/// Fixed reply-frame overhead: corr(8)+status(1)+klen(2)+plen(2).
pub const REPLY_OVERHEAD: usize = 8 + 1 + 2 + 2;

/// A whole reply frame at the ceiling — what a `reply_out` port must be able
/// to emit as one record.
pub const REPLY_FRAME_MAX: usize = REPLY_OVERHEAD + KEY_MAX + PAYLOAD_MAX;

impl<'a> Reply<'a> {
    pub fn wire_len(&self) -> usize {
        REPLY_OVERHEAD + self.msg_key.len() + self.payload.len()
    }

    /// Encode. `None` on a zero corr, a reserved link-state status (those are
    /// never replies), an over-length field, or a too-small buffer.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        if self.corr == 0
            || self.status >= STATUS_LINK_DOWN
            || self.msg_key.len() > u16::MAX as usize
            || self.payload.len() > u16::MAX as usize
        {
            return None;
        }
        let need = self.wire_len();
        if out.len() < need {
            return None;
        }
        let mut p = 0usize;
        out[p..p + 8].copy_from_slice(&self.corr.to_le_bytes());
        p += 8;
        out[p] = self.status;
        p += 1;
        out[p..p + 2].copy_from_slice(&(self.msg_key.len() as u16).to_le_bytes());
        p += 2;
        out[p..p + 2].copy_from_slice(&(self.payload.len() as u16).to_le_bytes());
        p += 2;
        out[p..p + self.msg_key.len()].copy_from_slice(self.msg_key);
        p += self.msg_key.len();
        out[p..p + self.payload.len()].copy_from_slice(self.payload);
        p += self.payload.len();
        Some(p)
    }

    pub fn decode(src: &'a [u8]) -> Option<Self> {
        if src.len() < REPLY_OVERHEAD {
            return None;
        }
        let corr = u64::from_le_bytes(src[0..8].try_into().ok()?);
        if corr == 0 {
            return None;
        }
        let status = src[8];
        if status >= STATUS_LINK_DOWN {
            return None;
        }
        let klen = u16::from_le_bytes([src[9], src[10]]) as usize;
        let plen = u16::from_le_bytes([src[11], src[12]]) as usize;
        let p = REPLY_OVERHEAD;
        let msg_key = src.get(p..p + klen)?;
        let payload = src.get(p + klen..p + klen + plen)?;
        if p + klen + plen != src.len() {
            return None;
        }
        Some(Self {
            corr,
            status,
            msg_key,
            payload,
        })
    }
}

// ── Channel message types ─────────────────────────────────────────────
//
// The producer↔sink pair rides the standard 3-byte envelope
// (`[msg_type:u8][len:u16 LE]`), so `net_read_frame` / `net_write_frame`
// work unchanged. The 0xE0..0xEF band is this surface's; it is disjoint from
// every other contract sharing a channel (`protocol_surfaces.md`).

/// A `Publish` frame, producer → sink.
pub const MSG_PUBLISH: u8 = 0xED;
/// An `Ack` frame, sink → producer.
pub const MSG_ACK: u8 = 0xEE;
/// A `Reply` frame, sink → producer. Only a provider declaring
/// `stream.ordered_ack.exchange` ever emits one.
pub const MSG_REPLY: u8 = 0xEF;
