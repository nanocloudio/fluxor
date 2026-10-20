# Exchange

One request and its answer, between any two modules. An HTTP server handing
a route to an application, a pipeline calling an HTTP or S3 endpoint, a
producer publishing to a broker or a table: every request a graph carries
travels in the same records. The party that asks is the **requester**, the
party that answers is the **provider**, and neither learns what the other is.

The contract is `modules/sdk/contracts/exchange.rs`, mounted for every module
as `abi::contracts::exchange`. It is the authority for every byte; this page
describes what the records are for.

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
| `HEAD` | method, target, headers, peer, response credit, first body bytes | status, content type, headers, first body bytes |
| `BODY` | more request body | more response body |
| `ABORT` | the requester gives up the exchange | the provider could not finish it |
| `CREDIT` | response-body bytes the requester will take | request-body bytes the provider will take |
| `DATAGRAM` | a message on the exchange outside its body, tagged by a `context` | the same, toward the requester |
| `LINK` | — | the provider's link to its backend: `DOWN` or `UP` |

A HEAD carries as much of the body inline as fits; `MORE` in its flags says
BODY records follow, and a HEAD or BODY without `MORE` ends that direction.
Headers travel as a `name: value\r\n` block, read with `header` and
`header_lines`. Methods are one byte (`METHOD_GET` … `METHOD_OPTIONS`);
`method_from_token` and `method_name` convert to and from the request-line
token. `METHOD_PUBLISH` is not an HTTP method: it is a record for a durable
destination, its `target` the ordering key (up to `KEY_MAX`) and its body the
record. An HTTP provider refuses it.

## Exchange ids

The requester chooses the 14-byte id — an HTTP server packs its transport,
connection and stream into it, a pipeline uses `ExchangeId::from_u64` on its
own counter — and the provider echoes it verbatim on every record it writes
for that exchange. The id is opaque to the provider, so any number of
exchanges from any number of sources share one channel pair. The all-zero id
is reserved for LINK records.

## Answers and statuses

A provider answers every exchange exactly once with a terminal record: a
response HEAD or BODY without `MORE`, or an ABORT. Nothing further is written
for an exchange after its terminal record, and an ABORT from the requester
ends it too. A response that ends before the request does ends the exchange.

`status` is an HTTP status code for every provider, HTTP or not. 200 is an
answer — for a sink, durable acceptance with an empty body. A provider that
relays a peer reports the peer's own status. The statuses a provider raises
itself are named in `status`:

| Status | Meaning |
|--------|---------|
| 400 | not a request this provider can perform: an unknown method, a target it cannot route |
| 413 | the request or its body passed what the provider takes |
| 500 | the provider failed answering it |
| 502 | the peer behind the provider was unreachable, or answered with something it could not carry back |
| 503 | the provider holds as many exchanges as it can; the request may be repeated |
| 504 | the peer behind the provider did not answer in time |

A HEAD carrying a status the provider raised is marked `RAISED` (`0x80`), and
`write_refusal` writes one. The bit is the only thing that tells "the peer
answered 502" from "there was no peer to answer": a requester that relays the
status onward — an HTTP server answering its client — needs nothing more than
the number, while one that reports a failure differently from an answer — a
script runtime whose `fetch` rejects on a network error — reads the flag. A
peer's own answer is never marked, whatever its status; an origin's 503 is an
answer. A relay that forwards response records unchanged forwards the flag
with them.

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
`stream.ordered_ack`: `stream.ordered_ack.sink` answers with a status alone
(an MQTT topic, a Kafka partition, an INSERT), and
`stream.ordered_ack.exchange` also answers with data (an HTTP call, a SELECT).
A requester that only publishes requires the parent and accepts either. The
terms either role satisfies: a 200 means durable acceptance at the strongest
level its configuration offers; order is kept per `target` within a
connection; nothing is dropped silently — every exchange is answered or
invalidated by `LINK DOWN`; backpressure is by channel and credit, never by
dropping; a `BROADCAST` request reaches every ordering unit and is answered
once, after the slowest. A provider that offers less says so in its
`[capability_facts]`, and a requester's `max_payload` fact is checked against
its provider's at build.

## Taking requests whole

A provider that answers a request only once all of it is in hand uses
`Collector<SLOTS, TARGET, HEADERS, BODY>`, sized from what it serves. It
takes request records one at a time and hands over a request whose body is
complete; it owes the requester the remaining body credit the moment an
exchange opens with a body to come; and it refuses — never truncates — a
request past a bound with 413, or one past its slots with 503, freeing
whatever the refused exchange held. A requester ABORT frees the exchange's
slot, and CREDIT records accumulate on it. The collector does no I/O: the
grant and the refusal it owes are taken after each record and written by the
module that owns the port.

A module that writes answers places them through `ExchangeOutbox`
(`modules/sdk/runtime/exchange.rs`): a record the channel has no room for is
held and placed on a later step, so no answer is dropped.

## Contracts behind an exchange

A layer's owner fronts its contract with an exchange provider, so an
application wires only exchange edges and reaches the layer the same way
whether it runs in the same graph or across a network: embedding or going
remote is a placement choice, not a different client. The front holds the
resource; its requesters do not.

`foundation/object_exchange` is the front of `storage.object`, the contract
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
| `GET /?list&prefix=…&after=…&max=…` | `200`, one page of names, one per line, with `next` when there is more |

The name is the target after its `/`, verbatim. Every success carries the
store's fence as `fence: <hex of Fence::encode>`, and the statuses map the
store's refusals precisely: absent `404`, a condition that did not hold `412`,
a body the store will not take `413`, a busy store `503`. A store's "not yet"
(`EAGAIN` on a read, `EINPROGRESS` on a write) is asked again with the same
request and is never an answer.

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
wired to a stand-in instead of the provider. `foundation/remote_channel`
carries one exchange across its authenticated session. With
`exchange: near` it stands in for the remote provider, with the provider's
ports (`request_in`, `response_out`); with `exchange: far`, on the
provider's node, it stands in for the remote requester, with the
requester's (`request_out`, `response_in`), wired to the real provider.
Request records cross near to far and response records far to near, each
direction a `mailbox` channel of its own at `RECORD_MAX`, whole and under
that channel's credit, ids verbatim — so one requester per near endpoint,
whose id space crosses intact. A placed member (`node:`) is never named by
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
  every exchange it handed the provider without a terminal record yet, and
  drops what the provider writes for them.
- The far side opens each session's answer channel with a LINK record
  stating the provider's link, and only once the provider has taken every
  ABORT and its answers are drained. The near side writes `LINK UP` when
  that record says up, and the requester issues its open exchanges again
  under the same ids; none can meet a record of the exchange before.
- The provider's own LINK records cross; the requester hears the state the
  session and the provider make together, each change once.

Each exchange is answered once, with the answer to the last issue under its
id. One whose answer was lost with the session was performed and is issued
again, as a provider's own LINK DOWN already allows. The module's
[README](../../modules/foundation/remote_channel/README.md) has the wire,
the bounds and the counters.
