# `object_exchange` — the exchange front of `storage.object`

`object_exchange` is a provider of the exchange contract
(`modules/sdk/contracts/exchange.rs`, [docs/architecture/exchange.md](../../../docs/architecture/exchange.md))
that answers each request by reading or writing objects through the
`storage.object` provider the graph binds. A graph that wires a requester to
it reaches storage through ordinary exchange edges and never holds the
storage resource itself, so whether the store is embedded in the graph or
remote is a placement choice, not something the requester knows.

The `storage.object` contract is fluxor's, and every store that serves it — the
Linux and bcm2712 key stores, `fs_object`, a replicated store — is reachable
through this one front. An HTTP server's application route, a pipeline relay or
any other requester can sit in front of it:

```text
http.request_out ─► relay.request_in   relay.request_out ─► object_exchange.request_in
http.response_in ◄─ relay.response_out relay.response_in ◄─ object_exchange.response_out
                                                            object_exchange ─► storage.object
```

Source: `mod.rs`.

## Wiring

| Port | Direction | Content type | Edge |
|---|---|---|---|
| `request_in` | input | `ExchangeRequest` | from a requester's `request_out` |
| `response_out` | output | `ExchangeResponse` | to the requester's `response_in` |

Resources: `storage.object` (`write`, which covers reads).

## Parameters

| Tag | Name | Default | Meaning |
|---|---|---|---|
| 1 | `scope` | none | The key prefix the capability grants, ending `/`, and the root every request names objects under; at most 255 bytes (`grant::SCOPE_MAX`) |
| 2 | `capability` | none | The capability chain over `scope`, in its text form (`fxcap1.…`); at most 1375 bytes (`capability::MAX_TEXT_LEN`), up to 8 links |

`scope` and `capability` are given together or not at all. Given one without
the other, a scope that does not end `/`, a capability that is not `fxcap1`
text or does not decode to a capability chain, and either past its bound, the
module refuses construction and logs why. A chain whose leaf names the scope's
object is minted with `fluxor modules cap mint --scope <scope>`.

## Authority

The module acts under the one capability its graph gives it, for every
request.

- **Presenting.** Given `scope` and `capability`, the module presents them to
  the store once (`PRESENT`, `contracts/storage/object.rs`), and every call it
  makes for every request — `HEAD`, `GET`, `PUT`, `PUT_STREAMED_OPEN`,
  `DELETE`, `LIST` — names the grant the store answered. The grant is held for
  the module's life and dropped (`CLOSE`) when the module is destroyed.
- **None given.** Every call names no grant (`-1`). A store with no mesh roots
  serves those calls; a store with roots refuses each `EACCES`, which arrives
  as `403`.
- **Not yet.** While the store has not decided the presentation (`EAGAIN`, or
  `EINPROGRESS`), it is asked again on every step with the same request, byte
  for byte, and requests wait in their slots: none reaches the store and none
  is answered.
- **Refused.** A presentation the store refuses — the chain does not verify
  against its roots or its clock (`EACCES`), the store keeps no authority
  (`ENOSYS`, so the scope would be enforced by nothing), anything else but a
  busy store — is final. It is logged once, and every request is answered
  `403` without a call to the store: a streamed put is refused before any
  request-body credit is granted, so nothing of a body is taken.
- **Busy.** A store with no room for the grant (`ENOMEM`, `EBUSY`) is asked
  again, at most once a step, when a request needs it; a request it still
  has no room for is answered `503`.

What a request may do is the store's decision, on every call: a key outside
the scope, an operation the grant's permissions do not cover and a grant whose
window has closed are each refused `EACCES` by the store, and answered `403`.
The module checks nothing itself and holds no list of what the grant covers.

Who may send requests is the graph's wiring. Every requester wired to
`request_in` acts with the module's capability, so the trust boundary for
in-graph callers is the graph: a module that should not hold the grant is not
wired to the front. The graph's author decides which requesters those are, as
with any resource a graph binds.

Where the front runs is a placement choice ([Placement](../../../docs/architecture/exchange.md#placement)).
The capability is a parameter of the front's own instance, so it goes where
the front is placed, and the front presents it to the `storage.object`
provider of the node it runs on. A requester on another node reaches the front
through `remote_channel` and never holds the grant.

## Requests

A front's scope is its root. The request target `/<rest>` names the object
`<scope><rest>`: the scope followed by everything after the leading `/`, taken
verbatim as opaque bytes. With scope `tenant/a/`, `/x/y` names the object
`tenant/a/x/y`; with no scope, `/x/y` names `x/y`. Nothing in the target is
decoded: `/a%41` names `<scope>a%41`.

A target cannot name anything outside the scope. Names are opaque bytes, so
the module resolves no path segments: `..` is two dots, and `/../x` names
`<scope>../x`, a key that starts with the scope like every other. The store
still judges every call under the grant (see [Authority](#authority)).

A target that does not start with `/`, an empty `<rest>` (`/` names the scope
itself, which is not an object this front serves), a full name
`<scope><rest>` longer than `STORAGE_KEY_MAX` (255 bytes) and a `<rest>`
starting with `?` (the listing's own target) are refused `400`.

| Request | Operation | Answer |
|---|---|---|
| `GET /<name>` | `HEAD`, then `GET` and `RANGE_GET` | `200` with the object as the body; `206` for a range |
| `HEAD /<name>` | `HEAD` | `200`, no body |
| `PUT /<name>`, body inline in the HEAD | `PUT` | `200`, no body |
| `PUT /<name>`, body continuing (`MORE`) | `PUT_STREAMED_OPEN`, `_WRITE`, `_COMMIT` | `200`, no body |
| `DELETE /<name>` | `DELETE` | `204` |
| `GET /?list…` | `LIST` | `200`, one page of names below the scope |

Any other method — `POST`, `PATCH`, `OPTIONS`, `CONNECT`, `PUBLISH` — and a
request flagged `WEBSOCKET`, `WEBTRANSPORT` or `BROADCAST` are refused `400`.

### Request headers

| Header | Requests | Meaning |
|---|---|---|
| `range` | `GET` | `bytes=a-b`, `bytes=a-` or `bytes=-n`: one range, answered `206` |
| `content-type` | `PUT` | stored with the object; at most 255 bytes |
| `content-length` | `PUT` | the streamed put's size hint; digits only |
| `if-none-match: *` | `PUT` | create only: the store refuses an existing name |
| `if-match: <hex etag>` | `PUT`, `DELETE` | only if the object's entity tag is this one; quoted or not |

`if-none-match` with any other value, both conditions at once, and an
`if-match` that is not hex or names more than `ETAG_MAX` bytes are refused
`400`. A condition is the store's to judge, at the write's own linearization
point: the module never reads first to decide.

A `range` that is not one of the three forms, including a list of ranges, is
refused `400`. A last-byte position past the end means the end. A range that
starts at or past the end, a suffix of zero bytes, and any range of an empty
object are answered `416` with `content-range: bytes */<size>`.

### Response headers

| Header | Answers | Value |
|---|---|---|
| `content-length` | `GET`, `HEAD` | the body's length (the range's, for `206`) |
| `content-range` | `206`, `416` | `bytes a-b/<size>`, or `bytes */<size>` |
| `etag` | `GET`, `HEAD` | the object's entity tag, lowercase hex, when the store keeps one |
| `fence` | every success | the lowercase hex of `Fence::encode` |
| `next` | a listing page that is not the last | the cursor to resume after, below the scope, encoded as a listing line |

The response's content type is the one the store keeps for the object; a store
that keeps none answers an empty one. A read's fence is the one its read handle
reports (`LAST_FENCE`), or the `HEAD` record's when the provider reports none;
a write's is the one its commit reported.

## Listing

`GET /?list` lists one page of the names below the scope, in ascending
bytewise order. Like a target, a listing is rooted at the scope: the names it
takes and the names it answers are the part after `<scope>`. The query takes,
each at most once and in any order:

| Parameter | Meaning |
|---|---|
| `list` | required; marks the target as a listing |
| `prefix=<p>` | only names starting with `p`: the store is asked for `<scope><p>` |
| `after=<k>` | resume strictly after `k` — the `next` a previous page answered: the store is asked to resume after `<scope><k>`; an empty `k` is the first page |
| `max=<n>` | at most `n` names, 1 to 1000 (`LIST_PAGE_MAX`); 1000 when absent |

With no `prefix` the store is asked for `<scope>`, so every listing stays
within the scope. Values are percent-decoded (`%XX`; `+` is a plus). An
unknown parameter, a repeated one, a value that does not decode, a `prefix` or
`after` whose full name `<scope><value>` is longer than `STORAGE_KEY_MAX`, and
a `max` out of range are refused `400`. A page may hold fewer than `max` names
— as many as one body record's worth of the provider's page holds — and says
so with `next`.

Every name the page answers, and its `next` cursor, is written with `<scope>`
taken off. A page from the store that names a key, or a cursor, not starting
with the scope is not answered: the listing is refused `500`, `RAISED`, and
none of its names is written.

The body is `text/plain`, one name per line, each ended by `\n`. A name is
written verbatim except for the bytes that would end or split a line, a header
value or a query value — every byte up to and including space, `0x7F`, `%`,
`&`, `=` and `#` — which are written `%XX`. A `next` value is encoded the same
way, so it goes back into `after=` as it came.

## Statuses

`status` is an HTTP code, as the exchange contract requires. The refusals the
module raises itself are marked `RAISED`; every other status is the store's
answer and is not.

| Status | When | `RAISED` |
|---|---|---|
| `200` | answered; a write is durable at the fence named | no |
| `204` | deleted | no |
| `206` | a range | no |
| `400` | a request this module cannot route or parse (see above) | yes |
| `400` | the store refused the request as malformed (`EINVAL`) | no |
| `403` | the store refused access (`EACCES`), or refused the module's capability | no |
| `404` | the store has no such object (`ENXIO`, `ENOENT`) | no |
| `412` | a condition did not hold (`EEXIST`; `EAGAIN` on a write) | no |
| `413` | the store will not take the body (`ENOSPC`, `E2BIG`) | no |
| `416` | an unsatisfiable range | no |
| `500` | the store failed, or answered something the module cannot carry | yes when the module could not answer, no when the store failed |
| `501` | the store does not offer the operation (`ENOSYS`) | no |
| `503` | every exchange slot is taken | yes |
| `503` | the store is busy (`EBUSY`, `ENOMEM`), or had no room for the capability's grant | no |

`DELETE` answers what the store decided: a store whose delete of an absent
name is `ENXIO` is answered `404`, and one whose delete is idempotent (the
Linux store) is answered `204`. The module does not read first to tell them
apart; that read would be a second request racing the first.

A failure after a response has begun — the object ended before its
`content-length`, a read failed mid-stream — ends the exchange with an ABORT
(`FAILED`), since the status has already gone.

## Flow control

Both directions are paced by credit, as the exchange contract requires.

- **Responses.** A read's response HEAD carries as much of the body inline as
  the requester's credit and the record allow; the rest follows in BODY
  records only as CREDIT arrives. Nothing is sent past `resp_credit` plus the
  grants. Each body record is read with `RANGE_GET` straight into the record,
  so the module never holds an object.
- **Request bodies.** A streamed put grants one window of request-body credit
  (one body record, `BODY_MAX`) once the stream is open, and grants again only
  when the stream has taken everything sent. The first grant is the module's
  consent to the body: a put the store refuses at the open is answered
  without one. A body past the credit granted is aborted `CREDIT_OVERRUN`.

## "Not yet"

The store's "not yet" is never an answer. A presentation the store has not
decided holds every request, as [Authority](#authority) says. A read that answers `EAGAIN` and a
write that answers `EINPROGRESS` are asked again on a later step with the same
request, byte for byte, and every buffer the request names stays where it is
until the answer comes. A streamed chunk the store pushes back (`EAGAIN` from
`PUT_STREAMED_WRITE`) is kept whole, sent again first on a later step — never
within the step that refused it — and while it waits no further credit is
granted, so the body stops at what is already in flight.

## Exactly once

Every exchange is answered exactly once: one terminal response record, or an
ABORT. Every record leaves through one `ExchangeOutbox`, so a full
`response_out` holds the record and the module places it on a later step;
none is dropped. While a refusal cannot be written the module stops reading
`request_in`, so the requester's own channel carries the backpressure.

A requester's ABORT ends its exchange at once: an open read handle is closed,
a streamed put whose body is still open is aborted (nothing of it lands), and
a record of that exchange still held in the outbox is withdrawn. A write the
store has already taken and not yet decided — a single-shot put, a delete, a
streamed put's commit — is the store's to decide: the module does not ask
about it again, and a commit's handle is released with `PUT_STREAMED_ABORT`,
so whether that write lands is the store's answer, never collected. A repeat HEAD for an exchange already open restarts it: a record still
held for the earlier issue is withdrawn, and only the newer request is
answered.

The module keeps no link to its store that can drop, so it writes no `LINK`
records.

## Limits

Each refuses rather than clamps.

| Limit | Value | Refusal |
|---|---|---|
| Exchanges in flight (`EXCHANGE_SLOTS`) | 16 on host-class targets, 2 on MCUs | `503`, `RAISED` |
| Object name, the scope included | `STORAGE_KEY_MAX`, 255 bytes | `400` |
| Listing `prefix` and `after`, the scope included | `STORAGE_KEY_MAX`, 255 bytes | `400` |
| Stored content type | 255 bytes | `400` |
| `if-match` entity tag (`ETAG_MAX`) | 32 bytes | `400` |
| Listing page | `max` 1 to 1000 | `400` |
| Request body past its credit | the window granted | ABORT `CREDIT_OVERRUN` |
| Records read, and written, per step (`STEP_RECORD_BUDGET`) | 16 | the rest wait for the next step |
| `scope` parameter | 255 bytes, ending `/` | construction |
| `capability` parameter | 1375 bytes of text, 8 links | construction |

Object size is the store's to bound: the module streams every body and holds
none whole.

## Targets and sizing

`bcm2712`, `rp2350` and `linux`. Each exchange slot carries one body record's
worth of buffer for its put window, `HEAD` record or listing page, so the slot
count follows `abi::config::TARGET_CLASS`: 16 on host-class targets, 2 on an
MCU, where the module's state is about 38 KiB. `rp2040` is not a target: the
two exchange edges are 8 KiB mailboxes each, the whole of its channel arena.

## Telemetry

Counters, in `[observability].metrics` order: `requests`, `bytes_in`
(request-body bytes taken for puts), `bytes_out` (response-body bytes sent),
`errors` (answers of 400 or more, and ABORTs the module sent), `refused` (`503`
for want of a slot), `aborts` (exchanges the requester aborted).

## Not offered

- **A capability per requester.** The module holds one grant, for every
  request. Authority that varies by caller belongs to a front that verifies
  each caller and holds the grants itself, or to a gate in front of this
  module.
- **A public S3 surface.** Request signatures, S3's XML and multipart uploads
  belong to an S3 front, which can sit in front of this module as a
  requester.
- **Multiple ranges, conditional reads** (`if-match` on `GET`), and server-side
  copies.
