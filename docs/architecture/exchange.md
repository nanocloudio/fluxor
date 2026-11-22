# Exchange

One request and its answer, between any two modules. An HTTP server handing
a route to an application, a pipeline calling an HTTP or S3 endpoint, a
producer publishing to a broker or a table: every request a graph carries
travels in the same records. The party that asks is the **requester**, the
party that answers is the **provider**, and neither learns what the other is.

The contract is `crates/fluxor-abi/src/contracts/exchange.rs`, mounted for every module
as `abi::contracts::exchange`. It is neutral: nothing in it is HTTP's. A
**binding** — a protocol's vocabulary on top of the records — fills the two
fields the contract leaves to one; the HTTP binding is
`crates/fluxor-abi/src/contracts/exchange_http.rs` (`abi::contracts::exchange_http`).
The two files are the authority for every byte; this page describes what the
records are for.

## Ports

| Role | Writes | Reads |
|------|--------|-------|
| Requester | `request_out` (`ExchangeRequest`) | `response_in` (`ExchangeResponse`) |
| Provider | `response_out` (`ExchangeResponse`) | `request_in` (`ExchangeRequest`) |

Both content types are `Framed`: a reader must receive each record whole. The
build gives every framed edge a mailbox `buffer_group` of its own, so a graph
wires `requester.request_out -> provider.request_in` and
`provider.response_out -> requester.response_in` and writes nothing else. A
group the wiring names explicitly is kept. Fanning one of these ports keeps
every edge a mailbox of its own: the inserted tee or merge moves one record
per transfer.

## Records

Every record is one channel record: a 16-byte prefix
`[kind u8][flags u8][id: 14 bytes]`, then the kind's payload. `RECORD_MAX`
(8192) bounds a record in either direction; a record longer than that, or one
whose lengths disagree with its size, is refused rather than read short.

| Kind | Request direction | Response direction |
|------|-------------------|--------------------|
| `HEAD` | op, verb, target, meta, peer, response credit, first body bytes | outcome, detail, meta, first body bytes |
| `BODY` | more request body | more response body |
| `ABORT` | the requester gives up the exchange | the provider could not finish it |
| `CREDIT` | response-body bytes the requester will take | request-body bytes the provider will take |
| `DATAGRAM` | a message on the exchange outside its body, tagged by a `context` | the same, toward the requester |
| `LINK` | — | the provider's link to its backend: `DOWN` or `UP` |

The request HEAD is `[op u8][verb u8][target_len u16][meta_len u16]
[peer_len u16][resp_credit u32]` then target, meta, peer and the first body
bytes; the response HEAD is `[outcome u8][detail u16][meta_len u16]` then
meta and the first body bytes. A HEAD carries as much of the body inline as
fits; `MORE` in its flags says BODY records follow, and a HEAD or BODY
without `MORE` ends that direction. The other flags are `HOLD` (a held
exchange, either direction), `BROADCAST` (request: every ordering unit) and
`RAISED` (response: below).

`op` says what a request is: `CALL` asks for an answer; `PUBLISH` hands a
record to a durable destination, its `target` the ordering key (up to
`KEY_MAX`) and its body the record; `OPEN` asks for a session whose BODY
records then carry the session's own stream, accepted by an answer with
outcome `OK`. `verb` is the binding's, and 0 outside one. Every decoder and
encoder holds the rules: a PUBLISH carries verb 0, an OPEN carries one of its
binding's opening verbs and a CALL never does, and a verb the binding does
not name is refused (`EINVAL`). The decoders take the binding as a type
parameter: `Http`, `Plain` for a party that speaks none (verb 0 only), or
`Relayed` for a party that carries records it does not read.

`meta` is a run of fields `[key_len u8][key][val_len u16][val]`, keys of 1 to
255 bytes with no upper-case ASCII letter, written with `MetaWriter` and read
with `meta_fields` and `meta_get`. A body's content type is the field
`content-type` in either direction (`META_CONTENT_TYPE`) and travels nowhere
else.

## Exchange ids

The requester chooses the 14-byte id — an HTTP server packs its transport,
connection and stream into it, a pipeline uses `ExchangeId::from_u64` on its
own counter — and the provider echoes it verbatim on every record it writes
for that exchange. The id is opaque to the provider, so any number of
exchanges from any number of sources share one channel pair. The all-zero id
is reserved for LINK records.

## Answers and outcomes

A provider answers every exchange exactly once with a terminal record: a
response HEAD or BODY without `MORE`, or an ABORT. Nothing further is written
for an exchange after its terminal record, and an ABORT from the requester
ends it too. A response that ends before the request does ends the exchange.

`outcome` is the class of the answer, the same for every provider, and a
requester branches on it alone:

| Outcome | Meaning |
|---------|---------|
| `OK` | answered; for a sink, durably accepted |
| `REFUSED` | not a request this provider performs: malformed, an unknown verb, a target it cannot route |
| `NOT_FOUND` | what the request names does not exist |
| `DENIED` | the requester is not allowed to do this |
| `CONFLICT` | a precondition did not hold, a version moved |
| `TOO_LARGE` | the request or its body passed what the provider takes |
| `BUSY` | the provider holds as many exchanges as it can, or was asked to slow down; the request may be repeated |
| `UNAVAILABLE` | the peer behind the provider was unreachable, or answered with something it could not carry back |
| `TIMEOUT` | the peer behind the provider did not answer in time |
| `FAILED` | the provider failed answering it |
| `OTHER` | no class above; `detail` says what it is |

`detail` is the binding's own account of the answer — an HTTP status — or 0.
A non-zero detail determines the outcome: the outcome is the binding's class
for it, encoders that know the binding compute it, and a decoder that knows
the binding refuses a HEAD where the two disagree. A party that knows no
binding carries the detail without reading it.

A HEAD whose answer the provider raised itself is marked `RAISED`, and
`write_refusal` writes one. The bit is the only thing that tells "the peer
said it was unavailable" from "there was no peer to answer": a requester that
relays the answer onward — an HTTP server answering its client — needs
nothing more than outcome and detail, while one that reports a failure
differently from an answer — a script runtime whose `fetch` rejects on a
network error — reads the flag. A peer's own answer is never marked,
whatever its outcome; an origin's 503 is an answer. A relay forwards outcome,
detail and the flag verbatim.

## The HTTP binding

`exchange_http.rs` is what a party that speaks HTTP puts in the binding
fields:

- `verb` is the method: `GET` 1, `HEAD` 2, `POST` 3, `PUT` 4, `PATCH` 5,
  `DELETE` 6, `OPTIONS` 7, and the opening verbs `CONNECT` 8, `WS_CONNECT` 9
  and `WT_CONNECT` 10 — the extended CONNECTs that open a WebSocket and a
  WebTransport session. `method_from_token`, `method_for_protocol` and
  `method_name` convert to and from the request line (every opening verb is
  `CONNECT` there).
- `detail` is the status, and `outcome_of` its class: 2xx `OK`; 3xx `OTHER`;
  400, 405 and 422 `REFUSED`; 401 and 403 `DENIED`; 404 and 410
  `NOT_FOUND`; 409 and 412 `CONFLICT`; 413 `TOO_LARGE`; 429 and 503 `BUSY`;
  502 `UNAVAILABLE`; 504 `TIMEOUT`; any other 4xx `REFUSED`, any other 5xx
  `FAILED`. A 1xx is never carried. An answer with no detail is written to an
  HTTP client with `canonical_status` (`OK` 200, `REFUSED` 400, `NOT_FOUND`
  404, `DENIED` 403, `CONFLICT` 409, `TOO_LARGE` 413, `BUSY` 503,
  `UNAVAILABLE` 502, `TIMEOUT` 504, `FAILED` and `OTHER` 500).
- `meta` fields are header fields, keyed by the name in lower case, in order:
  `meta_from_header_lines` and `header_lines_from_meta` map one to the other.
  Keys starting `:` are the binding's own and never leave as header lines:
  `:route` says how a server routed a request it delegates (`file`,
  `proxy`).
- `100 Continue`: the first request-body CREDIT is the provider's consent to
  the body, and an HTTP server answers a client that asked for it
  (`expects_continue`) when that CREDIT arrives — never as a response HEAD.

A provider that speaks the binding declares it on its `request_in` port, and a
requester that sends its verbs on its `request_out`:

```toml
[ports.facts]
binding = ["http"]
```

The composer refuses an edge whose producer declares a binding its consumer
does not; a port that declares none carries verb 0 only. A relay declares the
binding on the input it takes requests on and none on the output it hands
them on, since only the far graph sees its provider.

## Credit

Flow is credit-based in both directions, and only body bytes count. The
requester names in its HEAD how many response-body bytes it will take
(`resp_credit`) and raises that with CREDIT records; the provider never sends
past it. The provider grants request-body credit the same way, and the
requester sends no request body past its HEAD until it has some. The first
request-body credit is also the provider's consent to the body. A side that
holds a body back stops granting, and the other stops sending that exchange's
body and nothing else's.

## LINK

A provider whose backend connection can drop writes `LINK DOWN` when it does:
every exchange the requester has open without a terminal response is now
unknowable. `LINK UP` says the provider is connected and accepting, and the
requester issues each of those exchanges again.

## Ordered acceptance

A provider that durably accepts records in order declares a capability under
`stream.ordered_ack`: `stream.ordered_ack.sink` answers with an outcome alone
(an MQTT topic, a Kafka partition, an INSERT), and
`stream.ordered_ack.exchange` also answers with data (an HTTP call, a SELECT).
A requester that only publishes requires the parent and accepts either. The
terms either role satisfies: outcome `OK` means durable acceptance at the strongest
level its configuration offers; order is kept per `target` within a
connection; nothing is dropped silently — every exchange is answered or
invalidated by `LINK DOWN`; backpressure is by channel and credit, never by
dropping; a `BROADCAST` request reaches every ordering unit and is answered
once, after the slowest. A provider that offers less says so in its
`[capability_facts]`, and a requester's `max_payload` fact is checked against
its provider's at build.

## Taking requests whole

A provider that answers a request only once all of it is in hand uses
`Collector<B, SLOTS, TARGET, META, BODY>`, sized from what it serves and
decoding as binding `B`. It
takes request records one at a time and hands over a request whose body is
complete; it owes the requester the remaining body credit the moment an
exchange opens with a body to come; and it refuses — never truncates — a
request past a bound with `TOO_LARGE`, one past its slots with `BUSY`, or a
HEAD that breaks its binding's rules with `REFUSED`, freeing whatever the
refused exchange held. A requester ABORT frees the exchange's
slot, and CREDIT records accumulate on it. The collector does no I/O: the
grant and the refusal it owes are taken after each record and written by the
module that owns the port.

A module that writes answers places them through `ExchangeOutbox`
(`crates/fluxor-rt/src/exchange.rs`): a record the channel has no room for is
held and placed on a later step, so no answer is dropped.

## Contracts behind an exchange

A layer's owner fronts its contract with an exchange provider, so an
application wires only exchange edges and reaches the layer the same way
whether it runs in the same graph or across a network: embedding or going
remote is a placement choice, not a different client. The front holds the
resource; its requesters do not.

`modules/foundation/object_exchange` is the front of `storage.object`, the contract
the key stores, `fs_object` and replicated stores all serve. It is a provider
that never collects a request whole — a body runs to whatever the store takes —
so it streams instead of using `Collector`: a request body moves to the
store's `PUT_STREAMED_*` sequence a record at a time, under request-body
credit it grants one window at a time as the stream takes what it was sent,
and an object moves to the requester through `RANGE_GET` straight into
response records, never past the response credit granted. Every record
leaves through one `ExchangeOutbox`.

| Request | Answer |
|---|---|
| `GET /<name>` | `200` with the object, or `206` for a `range: bytes=…`; `404` when absent |
| `HEAD /<name>` | `200` with `content-length`, no body |
| `PUT /<name>` | `200`: a single-shot put when the HEAD carries the whole body, a streamed one when it continues |
| `DELETE /<name>` | `204` |
| `PATCH /<name>` with `retain-until`, `legal-hold` or both | `200`: extends the object's retention, sets or clears its hold |
| `GET /?list&prefix=…&after=…&max=…` | `200`, one page of names, one per line, with `next` when there is more |

It speaks the HTTP binding: requests are calls with a method, headers are
meta fields, and every answer's detail is its status. The name is the target
after its `/`, verbatim. Every success carries the
store's fence as `fence: <hex of Fence::encode>`, and the statuses map the
store's refusals precisely: absent `404`, a condition that did not hold `412`,
a body the store will not take `413`, an object its retention or hold protects
`423`, a store that cannot keep what was asked `501`, a busy store `503`. A
store's "not yet" (`EAGAIN` on a read, `EINPROGRESS` on a write) is asked again
with the same request and is never an answer. A header that would change what
the request means and that the method does not honour — a conditional on a
read, a vendor's object-lock or encryption header — is refused `400`, never
dropped.

Authority is a capability the graph gives the front (`scope`, `capability`):
the front presents it to the store once and makes every call, for every
request, under the grant the store answers, which the store checks on each
call — the scope, the permissions, the window. Without one, every call names
no grant, and a store with mesh roots refuses it `403`. Who may send requests
is the graph's wiring: every requester wired to the front acts with its
capability. The capability belongs to the front's instance, so it goes where
the front is placed (below) and is presented to that node's store. A public S3
front with its own signatures can sit in front of it as a requester. The full
surface is the module's
[README](../../modules/foundation/object_exchange/README.md).

## Placement

Where a provider runs is a placement choice: the requester reaches a
provider on another node with the same records it uses on a local edge,
wired to a stand-in instead of the provider. `modules/foundation/remote_channel`
carries one exchange across its authenticated sessions. With
`exchange: near` it stands in for the remote provider, with the provider's
ports (`request_in`, `response_out`); with `exchange: far`, on the
provider's node, it stands in for the remote requesters, with a
requester's ports (`request_out`, `response_in`), wired to the real
provider. Request records cross near to far and response records far to
near, each direction a `mailbox` channel of its own at `RECORD_MAX`, whole
and under that channel's credit. The near side carries its requester's ids
verbatim — so one requester per near endpoint; the far side, which may
serve several near endpoints at once (one session each), hands the provider
every exchange under an id of its own and maps it back on every answer, and
writes each request HEAD's `peer` as the session's verified key
fingerprint (empty without `require_peer`), whatever the requester wrote —
a HEAD that no longer fits is answered `TOO_LARGE`. The relay reads no
binding: verb, outcome, detail and `RAISED` cross as written. A placed member (`node:`) is never named by
a wire; the graph wires the requester to a near endpoint as it would to the
provider.

The composer checks the placement as far as one graph shows it. A wire
naming a placed member is refused. An instance's `exchange` mode must match
the ports its wiring uses — `near` wires `request_in` and `response_out`,
`far` wires `request_out` and `response_in`, `none` wires none of them —
and both halves of an endpoint's pair must reach one module, a single
requester or a single provider. A graph that places an exchange provider
(a member whose manifest takes `ExchangeRequest` and answers
`ExchangeResponse`) must hold a near endpoint for each one. Which provider a
near endpoint reaches is its `authority`, a network name, and the far side
is in the provider node's graph, so those two are not checked from the
requester's.

A session is the requester's backend link, and LINK is how it hears of it:

- Before the first session, a request waits on its edge. Nothing is written
  to the requester: LINK reports a change, and none has happened.
- When a session ends, the near side delivers the answers that crossed
  whole, writes `LINK DOWN`, and discards what the requester writes until it
  has taken the DOWN and while the session stays down; the far side ABORTs
  every exchange that session handed the provider without a terminal record
  yet — no other session's — and drops what the provider writes for them.
- The far side opens each session's answer channel with a LINK record
  stating the provider's link. The near side writes `LINK UP` when that
  record says up, and the requester issues its open exchanges again under
  the same ids; each is a new exchange to the provider, under a new id of
  the far side's, so none can meet a record of the exchange before.
- The provider's own LINK records cross; the requester hears the state the
  session and the provider make together, each change once.

Each exchange is answered once, with the answer to the last issue under its
id. One whose answer was lost with the session was performed and is issued
again, as a provider's own LINK DOWN already allows. The module's
[README](../../modules/foundation/remote_channel/README.md) has the wire,
the bounds and the counters.
