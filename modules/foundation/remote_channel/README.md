# `remote_channel` — local channels and exchanges across nodes

`remote_channel` carries up to eight local channels record for record across
one authenticated transport session, and optionally one exchange
(`modules/sdk/contracts/exchange.rs`,
[docs/architecture/exchange.md](../../../docs/architecture/exchange.md)). Two
instances, one on each node, are the two ends of one session. The transport
authenticates: `net` speaks `net_proto` to the clear side of mutual `tls`,
`mux` speaks the mux contract to `quic` with one stream per channel. The
module authenticates and encrypts nothing itself.

Sources: `mod.rs` (behaviour), `wire.rs` (the protocol), `manifest.toml`
(ports and parameters).

## Channels

The `channels` table, `content_type:framing:max_record;…`, names each
channel's content type, how its records are delimited on the local ports
(`tlv16`, `len32`, `mailbox`, `bytes`) and its largest record. Channel `N`
is the port pair `chN` (in) and `chN_rx` (out). Both ends exchange tables
when a session opens and refuse the session on any difference. A record is
reassembled whole before any byte of it is delivered; one over its maximum
is refused and counted, never truncated. Every channel has its own credit,
so a stalled consumer holds up its own channel and no other, and nothing is
dropped under backpressure. A record whose sending had begun when its
session ended is lost and counted; one not yet begun waits for the next
session. The `session` output says when a session opens and ends
(`contracts/mesh/remote_session.rs`).

## Exchange endpoint

An exchange provider is a placement choice: the requester that reaches a
provider in its own graph over a local edge reaches one on another node
with the same records, wired to a stand-in instead. `exchange` names which
stand-in an instance is.

| Side | Stands in for | Ports | Wired to |
|---|---|---|---|
| `near` | the remote provider | `request_in` (`ExchangeRequest`), `response_out` (`ExchangeResponse`) | the requester's `request_out` and `response_in` |
| `far` | the remote requester | `request_out` (`ExchangeRequest`), `response_in` (`ExchangeResponse`) | the provider's `request_in` and `response_out` |

The names are the exchange vocabulary's own: the near side's pair is a
provider's, the far side's a requester's, so each edge is content-type
checked like any other exchange edge and the build gives it its mailbox.
The build refuses an instance whose wiring does not match its side: one
side's pair must be wired, both halves to the same module, and the other's
must not, and an instance with `exchange: none` wires none of the four.

```text
node A                                         node B
requester.request_out ─► near.request_in       far.request_out ─► provider.request_in
requester.response_in ◄─ near.response_out     far.response_in ◄─ provider.response_out
                         near ═══ session (tls / quic) ═══ far
```

A placed member (`node:`) is never named by a wire; the graph reaches it
through a remote channel it wires explicitly. For an exchange provider that
is a `near` instance in the requester's graph, wired as the provider would
be, and a `far` instance beside the provider on its node:

```yaml
# node A
modules:
  - name: to_store
    type: remote_channel
    exchange: near
    role: dial
    authority: store.local:9100
wiring:
  - { from: app.request_out, to: to_store.request_in }
  - { from: to_store.response_out, to: app.response_in }
  # to_store's transport_in, transport_out and peer_identity to tls

# node B
modules:
  - name: from_app
    type: remote_channel
    exchange: far
    role: listen
wiring:
  - { from: from_app.request_out, to: objects.request_in }
  - { from: objects.response_out, to: from_app.response_in }
  # from_app's transport as on node A
```

### On the wire

The endpoint is two channels appended after the `channels` entries:
`ExchangeRequest` carries request records near to far, `ExchangeResponse`
carries response records far to near, both `mailbox` at the exchange
contract's `RECORD_MAX` (8192). Each record crosses whole, under its
channel's credit, like any mailbox record. The `HELLO` table carries the
two entries and then the sender's side; a peer's table matches only when it
states the same entries and the other side, so two `near` ends, or an
endpoint against none, are refused as a table mismatch. `channels` may be
empty when `exchange` is set, and holds at most six entries beside it.

Each side keeps only the half of a mailbox channel's region its direction
uses: the sending side a send stage (8192), the receiving side a ring and a
delivery stage (16388), 24580 bytes a side. That is why an instance carries
one endpoint: on an MCU it is three quarters of `REASSEMBLY_BYTES`, and a
second would not fit. A node that both fronts a remote provider and serves
a remote requester runs two instances.

### Ids

Records cross verbatim, ids included: the provider echoes the requester's
id and the near side hands the echo back unchanged. The id space is the
requester's, so **one requester per near endpoint**; requesters that share
a provider remotely share it through a local relay that owns their ids,
exactly as they would locally.

### Session loss

The exchange contract's LINK is the requester's whole account of a session.

- **First session.** The near side writes no LINK before the first session:
  LINK reports a change, and the requester's provider is up until it hears
  otherwise. A request written before the session exists waits on
  `request_in`; the near side does not read it, so the requester is held by
  its own edge and nothing is dropped. The near side forwards once the far
  side's opening LINK record arrives — written when a session opens and the
  far side holds nothing of a previous one, and stating the provider's link
  (DOWN, written to the requester, when the provider's backend is down).
- **Near side, on loss.** Answers that arrived whole are delivered first —
  each is the requester's, and the far side does not abort an exchange whose
  terminal answer it has already sent. Then LINK DOWN. Until the requester
  has taken the DOWN, every record it writes — the body of an exchange it
  has not yet learnt is lost, a request it wrote before it knew — is
  discarded: after the DOWN it issues every open exchange again, so each of
  those records belongs to an exchange that will be issued anew. Once the
  DOWN is taken and `request_in` drained, records written while the session
  is down are discarded too: the contract has the requester hold new
  requests while down. A request staged or part-sent when the session ended
  is dropped with it. LINK UP follows when the next session's opening LINK
  record says the provider is up.
- **Far side, on loss.** The far side tracks every exchange it handed the
  provider, from its request HEAD to the provider's terminal record (or the
  requester's ABORT). Each one still open is ABORTed (`PEER_GONE`) to the
  provider, and whatever the provider writes for it is dropped. Requests
  that had crossed whole and not been handed over are dropped, as is an
  answer taken from the provider and not yet sent. Nothing more is handed
  to the provider until it has taken the last ABORT and its answers are
  drained; only then does the far side open the next session's answer
  channel with its LINK record, so an exchange issued again under the same
  id never meets a record of the one before.
- **Exactly once.** Each exchange the requester issues is answered once: the
  terminal answer it reads is the one to the issue it last made under that
  id. An exchange whose answer was lost with the session was performed once
  by the provider and is issued again, so a provider whose operations are
  not idempotent sees it twice — the contract's "unknowable".
- **The provider's LINK.** The provider's own LINK records cross like any
  answer. The near side writes the requester the state the session and the
  provider make together, and only when it changes: a provider DOWN while
  the session is up is written as it came, a provider UP is written only
  while the session is up, and a session that comes back while the
  provider is down writes nothing until the provider's UP. A provider DOWN
  ends every exchange the far side tracks, since the requester issues each
  again after the UP.

The far side treats a provider's records for an exchange as finished once
the provider has taken that exchange's ABORT and its response edge is
drained. That is the contract's own rule — nothing is written for an
exchange after its ABORT — together with the order every provider writes
in: what it built before reading the ABORT reaches its edge before it reads
anything else (`ExchangeOutbox`).

### Bounds

| Limit | Value | On reaching it |
|---|---|---|
| `OPEN_EXCHANGES_MAX` | 256 on host-class targets, 32 on MCUs | a request HEAD past it is answered `503`, marked RAISED, and never reaches the provider; records that follow for it are dropped |
| record | the exchange contract's `RECORD_MAX` | a larger record is refused by the edge, never cut |
| channels | six beside an endpoint | a longer table is refused at construction |

### Counters

`x_refused` (requests answered `503` at the far side), `x_aborted` (ABORTs
written for exchanges a session left open), `x_discarded` (records an
endpoint dropped as belonging to an ended exchange).

## Limitations

- One exchange endpoint per instance, and one requester per near endpoint.
- On `mux`, the endpoint's two channels are two streams; `quic` opens three
  at a time, so an endpoint leaves room for one more channel.
- `fluxor build` and `--check` check what one graph shows: a wire naming a
  placed member is refused; every instance's `exchange` mode must match the
  ports its wiring uses (`near`: `request_in` and `response_out`; `far`:
  `request_out` and `response_in`; `none`: none of the four), both halves of
  an endpoint's pair must reach one module, and one only; and a graph that
  places an exchange provider on another node must hold a `near` endpoint
  for each such provider. Which provider a near endpoint dials is its
  `authority`, a network name, and its far side is in the provider node's
  graph, so neither the pairing of a near endpoint with a particular placed
  provider nor the far side's mode is checked from the requester's graph.
