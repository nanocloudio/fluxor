# `remote_channel` — local channels and exchanges across nodes

`remote_channel` carries up to eight local channels record for record
across authenticated transport sessions, and optionally one exchange
(`modules/sdk/contracts/exchange.rs`,
[docs/architecture/exchange.md](../../../docs/architecture/exchange.md)). Two
instances, one on each node, are the two ends of a session; a listener
serves up to `sessions` of them at once, one per verified peer. The transport
authenticates: `net` speaks `net_proto` to the clear side of mutual `tls`,
`mux` speaks the mux contract to `quic` with one stream per channel. The
module authenticates and encrypts nothing itself.

Sources: `mod.rs` (behaviour), `wire.rs` (the protocol), `manifest.toml`
(ports and parameters).

## Channels

The `channels` table, `content_type:framing:max_record;…`, names each
channel's content type, how its records are delimited on the local ports
and its largest record. Channel `N` is the port pair `chN` (in) and
`chN_rx` (out). Both ends exchange tables when a session opens and refuse
the session on any difference.

| Framing | Local record |
|---|---|
| `len16@<off>+<add>`, `len32@<off>+<add>` | a little-endian 16- or 32-bit length field at byte `off` of the record's own header; the whole record is the field's value plus `add`. The header (`off` plus the field) is at most 64 bytes |
| `tlv16` | `len16@1+3`: `[type:1][len:2 LE][payload]`, the header the net contracts share |
| `len32` | `len32@0+4`: `[len:4 LE][payload]` |
| `mailbox` | one buffer of a `buffer_group` edge is one record; an empty buffer is skipped |
| `bytes` | a stream with no records, carried in order; `max_record` bounds one piece |

A length framing is what a FIFO edge needs: a record is taken as one record
however the producer's writes split it or join it to the next, and
delivered whole, one wire record per local record. `mailbox` is for an edge
whose every buffer is one record — a FIFO producer behind it would have its
records joined or split by the edge. A delimited record must carry, in its
own header, the length the wire gave it; a peer whose record does not is
refused. `max_record` is at least the header and `add`, and for a 16-bit
field at most `add + 65535`; a malformed framing is refused at
construction. A record is
reassembled whole before any byte of it is delivered; one over its maximum
is refused and counted, never truncated. Every channel has its own credit,
so a stalled consumer holds up its own channel and no other, and nothing is
dropped under backpressure. A record whose sending had begun when its
session ended is lost and counted; one not yet begun waits for the next
session. The `session` output says when a session opens and ends
(`contracts/mesh/remote_session.rs`).

## Sessions

A dialler holds one session. A `net` listener serves up to `sessions` (at
most `SESSIONS_MAX`: 8 on host-class targets, 4 on MCUs), one per peer. With
`require_peer` a session belongs to the peer its transport verified, named
by the key fingerprint of that identity (`peer_identity::fingerprint` — the
bytes an HTTP server stamps as a request's `peer`), and a new session from
a peer that already has one replaces it: the older is closed and the newer
takes its place, its retained streams included, so a half-dead connection
never shuts its own peer out. The listener holds one transport session more
than it serves for exactly that. A peer arriving to find every session in
use is closed (`sessions_refused`). Without `require_peer` the sessions are
anonymous and never replace one another.

Each session has its own reassembly ring per channel and its own credit, so
a slow session holds up only itself. What the local side sees depends on
`peer_tag`:

- `peer_tag: 0` — the sessions are interchangeable. Records arriving on any
  of them are merged onto the channel's output record by record, each
  session's in order. A record written to a channel goes to every session
  open when it is taken; one whose session ended before it had it all is
  counted lost.
- `peer_tag: 1` — every local record carries, ahead of its own bytes, a
  32-byte fingerprint prefix: an inbound record its session's peer, an
  outbound record the peer it goes to. All zero sends to every session; a
  fingerprint with no session is dropped and counted (`unrouted`). Needs
  `require_peer`.

A `bytes` channel has no records to merge, route or prefix, so it needs one
session and no `peer_tag`; a `near` endpoint serves one requester's ids, so
one session. The `session` output reports open while any session is.

## Resume

With `resume` (on `net` or `mux`) a session ending takes nothing with it. Across several sessions each peer's streams are its own —
numbered, retained and resumed per peer, held by its verified identity (so
`require_peer` is needed). A record written to a channel is retained for
every peer whose streams are held (with `peer_tag`, the one its prefix
names), and is taken off the input only once every one of them has room: a
peer gone holds the channel once its window is full, for at most
`retain_ms`. A peer with no session for `retain_ms` (by default 30 × the
larger of `keepalive_ms` and `redial_ms`, at least 30 s; 0 keeps it for
ever) gives its slot and retained streams up (`peers_expired`): what was
retained for it, and a record being taken for it, is counted `lost`, and the
channel's input goes on to the peers still held — or, with none held, waits
for the next. A new peer finding every slot held takes the slot of the peer
gone longest whose records have all been delivered, and that peer's
retained streams are given up (`peers_evicted`). A peer whose streams were
given up either way and that comes back is served afresh: a slot of its
own, this side's streams going on from the next record taken for it,
numbered from the point it names (it never sees a record twice; the ones it
missed were counted lost when its slot went), and its own retained records
sent again from 1 (at least once, as across a restart). Every record on every channel is numbered from 1 within
the sender's incarnation (16 random bytes drawn at construction) and kept
in a retained window (`window` bytes per channel, four records at the
channel's maximum by default) until the receiver's `ACK` says it arrived
whole; a full window stops reading the channel's input. The next session's
`HELLO` carries, after the table, `['R'][incarnation][held][next × channels]`:
which peer incarnation's streams this end holds and the next record it
expects on each. A peer holding this end's incarnation is resumed exactly —
records before its `next` released, the rest sent again from it — so each
record is delivered once and in order across reconnects. A peer naming
another incarnation never saw this stream (its first session, or it
restarted): what is retained is renumbered from 1 and sent to it, and its
own streams start afresh here (at least once across a peer's restart).

Inside a session a numbered record (`RBEGIN`, `[record_len:4][seq:8]`) must
carry exactly the next number: one the receiver already has is refused as a
replay, one past it as a gap, an acknowledgement of a record never sent or
behind one released ends the session, and so does a resume point outside
the retained window (`refuse::SEQUENCE`). An idle session acknowledges
every `keepalive_ms`; one that hears nothing for three of those is ended,
and the next resumes it — a link that died without a close on this end
cannot hold the one session for ever. A resume prints
`[remote_channel] resumed: records going again=<n>`.

Beside an exchange endpoint `resume` numbers, retains and resumes the
`channels` entries — at least one — and never the endpoint's own two. An
exchange is the requester's to issue again (the exchange contract's LINK),
so a session that ends ends the exchanges it carried exactly as without
`resume` ([Session loss](#session-loss)): the far side ABORTs each still
open to the provider, the near side writes LINK DOWN and then UP once the
next session opens, and the reissue is a new exchange to the provider. The
channels beside it resume across the same reconnect, record for record. The
endpoint's records are unnumbered `BEGIN`s inside the resume session, are
never acknowledged, and its channels have no `next` in the `HELLO` trailer.
One link therefore carries both a stream that must not lose a record and an
exchange that must not be performed twice unknowingly.

On `mux` each channel is a stream of the QUIC session and every stream's
`HELLO` carries the same trailer, fixed when the session attached. The
trailer arrives on every stream but is applied once per session, before any
record of the session goes.
A QUIC session that ends takes its streams and what was on them; the next
session's streams resume each channel exactly as on `net`.

A typical end runs over mutual `tls` with vault-held host identities
(`net`), or over `quic` (`mux`), one instance on each node; `mux` carries
one session.

## Exchange endpoint

An exchange provider is a placement choice: the requester that reaches a
provider in its own graph over a local edge reaches one on another node
with the same records, wired to a stand-in instead. `exchange` names which
stand-in an instance is.

| Side | Stands in for | Ports | Wired to |
|---|---|---|---|
| `near` | the remote provider | `request_in` (`ExchangeRequest`), `response_out` (`ExchangeResponse`) | the requester's `request_out` and `response_in` |
| `far` | the remote requesters | `request_out` (`ExchangeRequest`), `response_in` (`ExchangeResponse`) | the provider's `request_in` and `response_out` |

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
empty when `exchange` is set, and holds up to eight entries beside it: the
endpoint's two have ports of their own and take no port pair.

Each side keeps only the half of a mailbox channel's region its direction
uses: the sending side a send stage (8192), the receiving side a ring and a
delivery stage (16388), 24580 bytes a side. That is why an instance carries
one endpoint: on an MCU it is three quarters of `REASSEMBLY_BYTES`, and a
second would not fit. A node that both fronts a remote provider and serves
a remote requester runs two instances.

### Ids and the peer

The near side carries its requester's records verbatim, so **one requester
per near endpoint**; requesters that share a provider remotely share it
through a local relay that owns their ids, exactly as they would locally.

The far side hands the provider every exchange under an id of its own and
maps it back on every answer, per session: any number of near endpoints on
any number of sessions share one provider, each in its own id space, and a
record of an exchange the far side has ended — the provider's late answer to
an exchange whose session was lost — can never reach a newer exchange,
whatever id its requester reissues it under.

The far side also writes each request HEAD's `peer` itself: the session's
verified key fingerprint under `require_peer`, empty without it. What the
requester put there is never passed on, so a provider authorises on the
peer the transport proved. A HEAD that no longer fits one record once its
`peer` is written is answered `413` (RAISED) and never reaches the
provider; a request HEAD that does not parse is answered `400`.

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
  requester's ABORT), with the session that issued it. Each one of the lost
  session's still open is ABORTed (`PEER_GONE`) to the provider — no other
  session's — and whatever the provider writes for it is dropped. Requests
  that had crossed whole on that session and not been handed over are
  dropped, as is an answer taken from the provider for it and not yet sent.
  The ABORTs reach the provider before any request after them; the next
  session's answer channel opens with its LINK record, and an exchange
  issued again is a new exchange to the provider, under a new id.
- **Exactly once.** Each exchange the requester issues is answered once: the
  terminal answer it reads is the one to the issue it last made under that
  id. An exchange whose answer was lost with the session was performed once
  by the provider and is issued again, so a provider whose operations are
  not idempotent sees it twice — the contract's "unknowable".
- **The provider's LINK.** The provider's own LINK records cross like any
  answer, to every session. The near side writes the requester the state the session and the
  provider make together, and only when it changes: a provider DOWN while
  the session is up is written as it came, a provider UP is written only
  while the session is up, and a session that comes back while the
  provider is down writes nothing until the provider's UP. A provider DOWN
  ends every exchange the far side tracks, since each requester issues them
  again after the UP.

### Bounds

| Limit | Value | On reaching it |
|---|---|---|
| `OPEN_EXCHANGES_MAX` | 256 on host-class targets, 32 on MCUs, across every session | a request HEAD past it is answered `503`, marked RAISED, and never reaches the provider; records that follow for it are dropped |
| `SESSIONS_MAX` | 8 on host-class targets, 4 on MCUs | `sessions` past it is refused at construction |
| record | the exchange contract's `RECORD_MAX` | a larger record is refused by the edge, never cut |
| channels | `PORT_CHANNELS`, 8, beside an endpoint as without one (the table holds `MAX_CHANNELS`, 10) | a longer table is refused at construction |

### Counters

`x_refused` (requests the far side answered itself: `503`, `413`, `400`),
`x_aborted` (ABORTs written for exchanges a session left open),
`x_discarded` (records an endpoint dropped as belonging to an ended
exchange). Per instance: `sessions` (opened, ever), `sessions_replaced`,
`sessions_refused`, `peers_evicted`, `peers_expired`; per channel `unrouted` (`peer_tag`
records whose prefix named no session) and `lost`.

## Limitations

- `resume` resumes the `channels` entries, never an exchange endpoint's: an
  exchange a session leaves open ends with it and is issued again. Across a
  peer's restart a resumed channel is at least once, not exactly once.
- One exchange endpoint per instance, and one requester per near endpoint.
- Several sessions are a `net` listener's; `mux` carries one.
- Under `resume` across several sessions a peer that never returns holds a
  channel's input once its retained window is full, until `retain_ms`
  passes or a new peer takes its slot; a peer back after that has lost what
  it missed (counted), and what it had sent but not seen acknowledged
  arrives again.
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
