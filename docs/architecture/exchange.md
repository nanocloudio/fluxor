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
group the wiring names explicitly is kept.

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
