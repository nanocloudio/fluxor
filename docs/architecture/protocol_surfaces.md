# Protocol Surfaces and Session Continuity

This document defines Fluxor's protocol substrate above channels: the
protocol surfaces (stream, datagram, packet, multiplexed session, and
the session-control sideband), the five session continuity classes, and
the architectural roles (transport anchor, session worker, session
directory) that sit above them. It is the reference that modules,
manifests, and graph configs use for protocol-surface vocabulary.

Every surface is a channel contract under
`modules/sdk/contracts/net/`. The kernel does not learn any of them:
protocol state lives entirely in modules.

## The Contract Files

Source: `modules/sdk/contracts/net/`.

| File | Surface | Opcodes | Status |
|------|---------|---------|--------|
| `net_proto.rs` | stream | `0x01..0x13` | live: `ip`, `tls`, `ota_registry`, `linux_net`, downstream `http` |
| `datagram.rs` | datagram | `0x20..0x43` | live: `ip`, `linux_net`, `dns`, `log_net`, `quic`, `tls` (DTLS mode) |
| `packet.rs` | packet | `0x50..0x63` | reserved: envelope defined, no consumer |
| `identity.rs` | address control | `0x60..0x61` | live: net identity self-registration |
| `session_ctrl.rs` | session control | `0x70..0x9F` | live: `echo_anchor` / `echo_worker` fixtures |
| `mux.rs` | multiplexed session | `0xB0..0xCF` | live: `quic`, `mux_echo` fixture |
| `../exchange.rs` | ordered-ack record exchange | `0xED..0xEF` | live: downstream broker, queue and table sinks, and the producers that feed them |

The exchange row sits outside `contracts/net/` — it is an application-effect
surface rather than a transport, and it rides whatever transport its provider
speaks. It is listed here because it shares the same envelope and must hold a
disjoint opcode range: the 0xE0..0xEF band is reserved for it.

Every row above shares the 3-byte TLV header `[msg_type: u8][len: u16 LE]`,
so the `net_read_frame` / `net_write_frame` helpers in
`modules/sdk/runtime/net.rs` work unchanged on all of them.

`contracts/net/ws_frame.rs` is the seventh file in that directory and
deliberately carries no row: it defines a connection-addressed envelope
(`[conn: u32][opcode: u8][fin: u8][payload_len: u16]`) rather than a
message-type range, so it holds no opcodes and the TLV helpers do not apply
to it.

Opcode ranges are disjoint across the
files that can share a channel, so a misconfigured channel fails
loudly rather than silently misparsing. The one numeric overlap is
`identity.rs` (`ADDR_ADD` 0x60 / `ADDR_DEL` 0x61 inside the packet
range); those opcodes travel only on a dedicated single-writer
`addr_ctl` port and never share a channel with packet frames.

## The Protocol Surfaces

### Stream Surface

Contract: `modules/sdk/contracts/net/net_proto.rs`. Full opcode and
payload reference: `network.md`.

Ordered byte streams: TCP, TLS-over-TCP, HTTP/1.x, MQTT, WebSocket
after upgrade. Operations: bind/listen, connect, accept/connected,
send, receive, close, error. The contract is stream-only: only
`SOCK_TYPE_STREAM` (1) is accepted on `CMD_CONNECT`, and any other
`sock_type` fails with EINVAL. The retransmit hints (`MSG_RETRANSMIT`
0x07 / `MSG_ACK` 0x08) are reserved in the contract and defined
privately by the `ip` module.

### Datagram Surface

Contract: `modules/sdk/contracts/net/datagram.rs`.

Message-oriented transports: UDP, DTLS, DNS, telemetry. Endpoints are
provider-allocated one-byte handles (`ep_id`), and the source address
rides every RX frame so a consumer can survive peer migration.
Addresses are big-endian, ports little-endian.

| Opcode | Name | Payload |
|--------|------|---------|
| `0x20` | `CMD_DG_BIND` | `[port: u16 LE][flags: u8][owner_tag: u16 LE]?` — `BIND_FLAG_RX_ONLY` (0x01) is advisory |
| `0x21` | `CMD_DG_SEND_TO` | `[ep_id: u8][af: u8][addr: 4\|16 BE][port: u16 LE][data…]` |
| `0x22` | `CMD_DG_CLOSE` | `[ep_id: u8]` |
| `0x40` | `MSG_DG_BOUND` | `[ep_id: u8][local_port: u16 LE]` |
| `0x41` | `MSG_DG_RX_FROM` | `[ep_id: u8][af: u8][src_addr: 4\|16 BE][src_port: u16 LE][data…]` |
| `0x42` | `MSG_DG_CLOSED` | `[ep_id: u8]` |
| `0x43` | `MSG_DG_ERROR` | `[ep_id: u8][errno: i8]` |

`af` is 4 (IPv4) or 6 (IPv6) as literal values (not POSIX constants),
giving address prefixes of 8 (`V4_ADDR_PREFIX`) or 20
(`V6_ADDR_PREFIX`) bytes before the payload. Every `CMD_DG_SEND_TO`
carries an explicit destination; there is no connected-default TX
form.

`CMD_DG_SEND_TO` and `CMD_DG_CLOSE` have an owner-tagged form that
inserts `[OWNER_TAG_MARK = 0xFF][owner_tag: u16 LE]` between `ep_id`
and the rest — at the offset `af` occupies, a value no address family
takes, so the two shapes separate at a fixed position rather than by a
length rule over variable-length data. The provider admits a command
only when the presented tag equals the tag `CMD_DG_BIND` recorded, and
refuses a mismatch with `EPERM`. An absent tag decodes as 0, so an
endpoint bound with `owner_tag = 0` accepts untagged commands from any
consumer sharing the channel.

### Packet Surface

Contract: `modules/sdk/contracts/net/packet.rs`.

Packet-preserving flows with richer metadata: packet classifiers,
policy modules, NIC fast paths. The endpoint verbs are an envelope with
no consumer yet; the decision-seam verbs below are consumed by `ip`.

TX (`CMD_PKT_TX` 0x51) and RX (`MSG_PKT_RX` 0x61) share the shape
`[ep_id: u8][af: u8][addr: 4|16 BE][port: u16 LE][lane: u8][flags: u8]
[dscp: u8][ts_us: u64 LE][flow_hint: u32 LE][packet…]` — a 15-byte
metadata block after the address, prefixes 23 (`V4_META_PREFIX`) or 35
(`V6_META_PREFIX`) bytes. RX flags: ECN-CE, checksum-ok,
has-flow-hint, has-timestamp, fast-path. TX flags: ECN-capable,
no-checksum, urgent. Bind/close/error opcodes mirror the datagram
surface (`CMD_PKT_BIND` 0x50, `MSG_PKT_BOUND` 0x60, `CMD_PKT_CLOSE`
0x52, `MSG_PKT_CLOSED` 0x62, `MSG_PKT_ERROR` 0x63).

The surface composes with mailbox and in-place buffer edges where
available, but it remains a channel contract.

#### Pre-transport decision seam

The same contract carries a second family of verbs, consumed by the `ip`
module with `packet_decision = pre_transport`: a point between L3
validation and transport demux where a director settles every inbound
IPv4 packet before any connection state exists for it. The stack's own
control traffic never reaches it: ICMP, and the DHCP server-to-client
replies that give the stack its address, are answered locally, so a
director decides flows and never whether the host is on the network.

`ip` parses and validates each packet once — whole (fragments are
refused before the seam and counted), L3 checksum, addressed to one of
its local addresses, L4 header parsed and its checksum verified — then
writes a `MSG_PKT_DECIDE` (0x64) record on `packet_out` and holds the
frame. The record carries `pkt_id`, family, protocol, the canonical
tuple, ingress interface and RX queue, `RX_FLAG_*` (checksum-ok set only
after verification), timestamp, frame length and the L4 offset: enough
to decide on, never the bytes, so a director does not re-parse.

The director answers with one `CMD_PKT_DISPOSE` (0x53) on `packet_in`:

| Disposition | Effect | Arguments |
|---|---|---|
| `LOCAL` | resume the ordinary transport path | — |
| `DROP` | release silently | reason |
| `REJECT` | release and answer the sender: TCP RST, ICMP port-unreachable, or nothing | reason, response |
| `TUNNEL` | hand the whole frame to `packet_fwd` as `MSG_PKT_FORWARD` (0x65) | attach id, flow epoch |
| `DSR` | as TUNNEL | endpoint id, rewrite id |

Ownership follows the disposition: a buffer has one owner at a time and
a second disposition for the same `pkt_id` is stale — `pkt_id` is
`[slot:8][generation:24]`, so a released or reused slot cannot be acted
on twice. The split is lopsided deliberately: the slot takes the bits it
needs and the generation takes the rest, because a generation coming all
the way round while one disposition is still in flight is the only way a
stale id could match a live hold. Twenty-four bits is 16.7 million
intakes against a hold the deadline already bounds — a generation narrow
enough for a line-rate burst to wrap would put that match back within
reach. `CMD_PKT_CLONE` (0x54) holds a second copy under a new id
(`MSG_PKT_CLONED` 0x66) for a director that mirrors.

The hold is bounded twice. `abi::config::ip::MAX_PACKET_HOLD` slots
(one frame each; 32 on the host profile) — a packet arriving with every
slot taken is refused and counted, never displaces one. And
`packet_hold_ms` per packet: a hold past its deadline is released and
reported (`MSG_PKT_EXPIRED` 0x67). A forward that does not fit the
forward ring stays held with its disposition pending and is retried each
step until it goes or expires.

Those two bounds are what a director is sized against. The slots are the
in-flight decision window, so a director answering in `t` sustains an
offered rate of at most `MAX_PACKET_HOLD / t` decidable packets per
second before arrivals start being refused; `packet_hold_ms` is the hard
ceiling on any single decision, past which the packet is released whether
the director has answered or not. Both are arithmetic over declared
constants and hold regardless of hardware. What is NOT declared here is
the seam's own per-packet cost — the frame copy into the slot and the
round trip to the director — which is a measured quantity per platform
and profile, not a property of the contract. A director design that
depends on it needs that measurement, not this relation.

The seam is wholly present or wholly absent: `packet_decision = off`
(the default) with the ports unwired is byte-identical to a stack without
it, and either half without the other is refused at construct. Tables,
affinity, health and policy are the director's; `ip` supplies the
validated headers, the buffer, and the ownership rules.
`modules/fixtures/packet_echo_director` is the reference director for
the harness and the rig.

`MSG_PKT_FORWARD` hands the whole frame to whatever consumes `packet_fwd`,
and that consumer does the wire work a TUNNEL or DSR disposition implies:
encapsulation, address and MAC rewrite, egress, and the return path. That
work is a fluxor capability rather than a director's, by the same test
every contract here answers to — encapsulating a frame means the same
thing on bare metal and on a host stack, it is a primitive rather than a
policy, and it is consumed across tenants. The director chooses WHICH
attachment or endpoint; it does not put bytes on the wire. Nothing in the
tree consumes `packet_fwd` beyond the harness fixture, so a composition
using TUNNEL or DSR supplies that consumer itself.

### Multiplexed Session Surface

Contract: `modules/sdk/contracts/net/mux.rs`.

Transports exposing many logical streams over one association. This
keeps QUIC-class transports off a false TCP-shaped abstraction: a
consumer sees streams, not packet protection. Operations: session
open/close, stream open/accept/close, per-stream send/receive,
per-stream and per-session error, readiness signalling.

Every stream-scoped message carries `session_id` (u32 LE, the
transport association) and `stream_id` (u32 LE, per session). The
`stream_id` is an OPAQUE LOCAL HANDLE, not the transport's own stream
identity: data-plane commands address a stream by the handle, and the
wire id travels as metadata on the opened/accepted event for the
applications that need it (HTTP/3 names streams by it in GOAWAY and
PRIORITY_UPDATE). Neither is derivable from the other.

Stream open takes bidi / unidirectional / urgent flags; opened and
accepted events add a generic initiator bit. Flow-control credit is
carried by `MSG_MUX_STREAM_READY` (0xC6) and `CMD_MUX_STREAM_ACK`
(0xB5) — the consumer's acknowledgement is what advances the provider's
receive windows. Abrupt termination is `CMD_MUX_STREAM_RESET` (0xB7) /
`CMD_MUX_STREAM_STOP_SENDING` (0xB8) outbound and
`MSG_MUX_STREAM_RESET` (0xCA) / `MSG_MUX_STREAM_STOPPED` (0xCB) inbound,
each carrying an opaque application error code the provider never
interprets. Peer identity is `MSG_MUX_PEER_IDENTITY` (0xC8).

The surface is protocol-neutral and complete: the provider implements
the whole lifecycle for every session it carries, whatever ALPN was
negotiated. The negotiated ALPN itself crosses as opaque bytes on
`MSG_MUX_SESSION_OPENED`, so choosing behaviour from it is the
consumer's decision, not the transport's.

The live consumers are the `quic` module (provider), the `mux_echo`
fixture, and downstream HTTP/3 and MQTT-over-QUIC modules. `quic` bounds one reliable write at
`MUX_QUIC_STREAM_SEND_MAX` (1200 bytes) — a transport bound, not a
profile restriction — and refuses an oversize write rather than
truncating it.

### Session Control Sideband

Contract: `modules/sdk/contracts/net/session_ctrl.rs`. See
§SessionCtrl Envelope for the opcode table.

The control plane between transport anchors, session workers, and
session directories: attach/detach, drain, chunked opaque state
export/import with CRC32 integrity, resume, epoch bump, relocation,
and a hello handshake carrying role constants (`ROLE_ANCHOR` 1,
`ROLE_WORKER` 2, `ROLE_DIRECTORY` 3). The same framing carries the
transport-continuity commands (`0x7A..0x88`, one reply opcode `0x9A`
with a record type) a transport provider answers for the connections
it owns — see `network.md` §Transport Continuity.

## The Five Continuity Classes

Sources: `tools/src/config/validate.rs`,
`tools/src/config/manifest.rs` (`CONTINUITY_CLASSES`),
`modules/sdk/contracts/net/session_ctrl.rs` (`CC_*` wire constants).

Session continuity is a declared, validated graph property. A graph
declares the class its workload requires in a top-level `continuity`
block (`id`, `class`, and per-class member fields), and the config
tool confirms the structural pieces exist at build time. The five
classes, with the structure the validator requires:

### `reroutable`

The service may move freely; existing flows may be dropped or retried,
new flows route elsewhere. Examples: DNS, short HTTP, stateless UDP
request/response. Required structure: none.

### `drain_only`

Existing flows finish gracefully; nothing is resumed or preserved
beyond drain. Examples: HTTP request/response services, short broker
operations, simple relays. Required structure: none checked by the
validator; the operational expectation is that the consuming module is
drain-capable (exports `module_drain` — see `reconfigure.md`).

### `resumable`

The client may reconnect and the application session resumes from a
token, cursor, lease, or session identifier. Examples: MQTT session
resume, watch-stream cursors, delivery cursors. Required structure: at
least one declared member (the anchor or a worker) provides the
`session.resume` capability.

### `edge_anchored`

The client-visible transport stays attached to a stable anchor while
the session worker moves behind it. Examples: broker front doors, push
gateways, long-lived watch streams. Required structure: an `anchor`
member providing a `transport.anchor.*` capability, one or more
`workers` providing `session.worker`, and, when more than one worker
is declared, `session.handoff` on every worker. This class delivers
no-reconnect maintenance for TCP/TLS workloads without live TCP
migration.

### `transport_migratable`

The transport association itself may change path or attachment point
without client reconnect. Required structure: a declared `mechanism`,
one of:

- `native_primitive` — the graph contains a `transport.mux.*`
  provider (a transport whose connection model supports migration,
  such as QUIC).
- `platform_replicated_state` — the anchor must provide one of
  `transport.anchor.datagram`, `transport.anchor.stream.secure` or
  `transport.anchor.mux`, and a stream or mux anchor is admitted only on
  a bare-metal target, where Fluxor owns the whole transport (on a
  hosted target TCP belongs to the host kernel and cannot be
  checkpointed); a `directory` member must provide `session.directory`;
  the graph must contain providers for `session.reservation`,
  `security.key_wrap`, `fence.enforceable`, and `durable.rpo_zero`, and
  the fence in two halves — the ip module's, whose `cutoff` reaches
  `wire` on the target, and an out-of-band fence agent declaring
  `cutoff = "wire"` for itself; the declared `aead` class must be
  `on_wire_sequence` or `unencrypted` (`implicit_counter` is rejected
  outright: a transport whose AEAD nonces cannot survive an anchor
  move honestly tops out at `resumable`); and the declared
  `failover_budget_ms` must be strictly below `client_keepalive_ms`.

Declaring `mechanism` or `aead` under any other class is a hard
error. The validator checks structure only (the presence of the
declared providers, the target facts and the budget inequality), not
behaviour under fault.

The transport providers here — `ip` for TCP, `tls` for the record
layer, `quic` for the mux — answer the session-control contract's
transport-continuity commands (`network.md` §Transport Continuity);
`ip` provides `fence.enforceable`. The directory, reservation, key-wrap
and durable providers, and the out-of-band fence agent, are composed into
the graph from outside — a graph that lacks any of them is refused.

## Architectural Roles

These are module roles, not kernel features. The role constants are on
the wire in the session-control hello; the capability names live in
the shared vocabulary (`contracts/src/vocabulary.rs`) and are
documented in `capability_surface.md`.

### Transport Anchor

Owns the client-visible transport attachment: the listening socket or
inbound endpoint, accepted client transport state, the TLS or QUIC
attachment point, a stable front-door identity. The anchor is
deliberately conservative about movement: it stays put so the client
connection does not have to. Anchors suit server-class and edge-class
targets; constrained devices usually act as clients served by an
anchor elsewhere. Capabilities: `transport.anchor.stream`,
`transport.anchor.stream.secure` (declared by the `tls` module),
`transport.anchor.datagram`, `transport.anchor.mux`.

### Session Worker

Owns movable state: application session state, routing state,
watch/filter state, fan-out planning, durable interaction with
backends. Workers may be local or remote relative to the anchor, and
are moved, drained, resumed, or replaced according to continuity
policy. Capabilities: `session.worker`, plus `session.handoff` and
`session.resume` where supported.

### Session Directory

Provides placement and continuity metadata: `session_id` → current
worker binding, continuity class, `session_epoch`, resumption
metadata. It is a role, not necessarily a dedicated binary. Its own
continuity class is normally `resumable`: replicated and
recoverable, but with no client-facing transport to preserve.

No directory implementation exists in this repository; the following
semantics are the design contract a directory must satisfy. The
minimum write semantic is single-writer authority per
`(session_id, session_epoch)`: one authoritative owner decides the
active worker binding for a session generation, and competing stale
writers are rejected. During short directory outages an anchor may
keep serving already-attached sessions from cached bindings but must
not create conflicting new ownership. New-session admission under
partition is per-protocol policy (reject, queue, or tightly scoped
provisional binding), never competing durable ownership.

## Session Identity Model

Source: `modules/sdk/contracts/net/session_ctrl.rs`,
`modules/sdk/contracts/net/net_proto.rs`.

Four identifiers at three scopes:

| Identifier | Wire shape | Scope |
|------------|-----------|-------|
| `conn_id` | u16 LE | per-provider-instance fast-path handle (stream surface) |
| `session_id` | 16 bytes BE | stable logical session |
| `anchor_id` / `worker_id` | 8 bytes BE | stable front-door / worker identity |
| `session_epoch` | u32 LE | monotonic per `session_id`; orders handoffs |

- `conn_id` stays module-local and cheap; it is not a kernel
  resource, and 0 is a valid handle.
- `session_id` is the continuity-aware identifier used by anchors,
  workers, and directories; it is minted by the protocol owner at the
  continuity boundary (usually the anchor at first attach), scoped to
  a deployment rather than globally, and need not appear on the
  public wire.
- `session_epoch` increases on every authoritative rebind; a peer
  presenting a stale epoch is rejected.
- Identity fields are big-endian so raw byte comparison matches the
  canonical rendered identity; epoch, status, and length fields are
  little-endian like the rest of the net contracts. Note the mux
  surface's `session_id` is a different, unrelated identifier (u32 LE
  transport association).

## Content Contracts

The envelope vocabulary is declared as content types alongside the
registry in `capability_surface.md` (canonical names in
`contracts/src/vocabulary.rs`): `NetStreamCmdV1` / `NetStreamEvtV1`
(stream), `NetDatagramTxV1` / `NetDatagramRxV1` (datagram),
`NetPacketV1` (packet), `NetMuxCmdV1` / `NetMuxEvtV1` (multiplexed
session), and `NetSessionCtrlV1` (session control). These are declared
vocabulary; current manifests type their net ports as `NetProto` or
`OctetStream`.

## SessionCtrl Envelope

Source: `modules/sdk/contracts/net/session_ctrl.rs`.

Commands (anchor/directory → worker):

| Opcode | Name | Payload after `[session_id: 16 BE]` |
|--------|------|-------------------------------------|
| `0x70` | `CMD_SC_HELLO` | (no session id) `[role: u8][self_id: 8 BE][flags: u8]` |
| `0x71` | `CMD_SC_ATTACH` | `[anchor_id: 8 BE][epoch: u32 LE][cc: u8][worker_id: 8 BE or zero]` |
| `0x72` | `CMD_SC_DETACH` | `[epoch: u32 LE][reason: u8]` |
| `0x73` | `CMD_SC_DRAIN` | `[epoch: u32 LE][deadline_ms: u32 LE]` |
| `0x74` | `CMD_SC_EXPORT_BEGIN` | `[epoch: u32 LE][total_len: u32 LE][in_consumed: u64 LE][out_produced: u64 LE]` |
| `0x75` | `CMD_SC_EXPORT_CHUNK` | `[epoch: u32 LE][offset: u32 LE][data…]` |
| `0x76` | `CMD_SC_EXPORT_END` | `[epoch: u32 LE][crc32: u32 LE]` |
| `0x77` | `CMD_SC_RESUME` | `[new_epoch: u32 LE]` |
| `0x78` | `CMD_SC_EPOCH_BUMP` | `[old_epoch: u32 LE][new_epoch: u32 LE]` |
| `0x79` | `CMD_SC_RELOCATE` | `[epoch: u32 LE][new_worker: 8 BE]` |

Events (worker → anchor/directory):

| Opcode | Name | Payload after `[session_id: 16 BE]` |
|--------|------|-------------------------------------|
| `0x90` | `MSG_SC_HELLO_ACK` | (no session id) `[role: u8][peer_id: 8 BE]` |
| `0x91` | `MSG_SC_ATTACHED` | `[epoch: u32 LE][status: u8]` |
| `0x92` | `MSG_SC_DETACHED` | `[epoch: u32 LE]` |
| `0x93` | `MSG_SC_DRAINED` | `[epoch: u32 LE]` |
| `0x94` | `MSG_SC_IMPORT_BEGIN` | `[epoch: u32 LE][status: u8]` |
| `0x95` | `MSG_SC_IMPORT_CHUNK` | `[epoch: u32 LE][offset: u32 LE]` |
| `0x96` | `MSG_SC_IMPORT_END` | `[epoch: u32 LE][status: u8]` — `CORRUPT` on CRC mismatch |
| `0x97` | `MSG_SC_RESUMED` | `[new_epoch: u32 LE]` |
| `0x98` | `MSG_SC_EPOCH_CONFIRMED` | `[new_epoch: u32 LE]` |
| `0x99` | `MSG_SC_RELOCATED` | `[epoch: u32 LE][status: u8]` |
| `0x9F` | `MSG_SC_ERROR` | `[epoch: u32 LE][errno: i8]` |

Detach reasons: normal (0), drain timeout (1), stale epoch (2), error
(3), client gone (4). Status codes: OK (0), stale epoch (1), unknown
session (2), no capacity (3), corrupt (4), not ready (5).

Stale-epoch rejection is the contract's ordering invariant: a receiver
rejects any message whose epoch is below the last authoritative epoch
it holds for that `session_id`. The in-tree worker fixture rejects and
reports the event on the monitor path; replying with `MSG_SC_ERROR` is
the contract's provision for peers that want an in-band signal.

## Observability

Anchors, workers, and directories emit `MON_SESSION` lines at
session-control transitions, on the same telemetry channel used for
other per-module visibility. The line format is specified in
`monitor-protocol.md`: one line per transition, with `session=`
rendered as 32 big-endian hex characters so a single grep follows a
session across all emitters. The fixtures emit via the
`dev_mon_session` SDK helper (`modules/sdk/runtime/telemetry.rs`) and
the `SELF_INDEX` syscall.

Event constants for replicated-state failover (`fence_initiated` /
`fence_confirmed`, `vip_moved`, `reservation_granted` /
`reservation_exhausted_stall`, `rpo_loss`,
`unsafe_recovery_epoch_void`, `class_report`) are defined in the
telemetry vocabulary and in `monitor-protocol.md`, but no emitter
exists yet — they are reserved for the replicated-state mechanism.

## Deployment Patterns

The stacks below are design guidance for composing the surfaces and
roles; apart from the fixture demonstration (§Reference Fixtures),
none of the named front-door modules exist in this repository.

- **Stateless DNS / short HTTP** (`reroutable` / `drain_only`):
  driver → `ip` → consumer. VIPs, anycast, and drain suffice.
- **Broker front door** (`edge_anchored`): an edge anchor owns the
  TCP/TLS client attachment, the protocol parser, keepalive timers,
  and bounded ingress/egress buffers sized to survive a short worker
  rebinding; the worker owns subscriptions, retained state, shard
  routing, and the durable in-flight ledger keyed by packet id and
  `session_epoch`; a directory tracks placement. Worker replacement:
  the anchor enters rebinding mode and pauses new deliveries while
  keeping wire-liveness traffic flowing; the old worker exports its
  state; the directory advances `session_epoch` and rebinds; the new
  worker imports, reclaims the ledger, and resumes from the exported
  cursor; the anchor reopens forwarding once the new worker is ready
  for that epoch. The rebinding buffer's size and overflow policy
  belong in the anchor's declared configuration, not implicit
  defaults.
- **Push gateways and watch streams** (`edge_anchored` or
  `resumable`): the same split, tuned for very large numbers of
  mostly idle long-lived sessions.
- **Internal replication** (`resumable`): both endpoints are under
  platform control and the protocol has its own indices and retry
  logic, so `resumable` is usually enough.
- **QUIC-based services** (`transport_migratable` via
  `native_primitive`): the `quic` module provides the mux surface
  over the datagram surface; its connection model is designed for
  path movement.

## Delivery Cursors

The exported blob is opaque, but its position in the session is not.
`CMD_SC_EXPORT_BEGIN` carries two session-scoped counters — inbound
bytes the blob accounts for, and outbound bytes it has already emitted
toward the client — and the anchor keeps the same pair for the worker
it is feeding. At export the two must agree exactly.

Equality is what makes a handoff lossless: it says the blob accounts
for every byte the anchor delivered and claims none it did not, and it
hands the importing worker the offsets to resume from. Disagreement is
a fault, not a race — a short inbound cursor means the worker exported
before its inbound tail ran dry and those bytes are in no blob; an
over-claimed one means a misbound session; an outbound mismatch means
the drain never finished and the client has seen a different prefix
than the blob believes. The anchor refuses such a handoff with
`STATUS_CURSOR_MISMATCH` and leaves the session on the exporting
worker, because a refused handoff costs a maintenance window while an
admitted one costs bytes nobody will ever learn were dropped.

The sequencing that keeps the cursors equal is the two halves of one
obligation: the anchor holds new client bytes from the moment it
issues `DRAIN`, and the worker consumes its inbound tail to dry before
it declares `DRAINED`. The cursors are how that obligation is checked
rather than assumed.

## Handoff and Reconfigure Integration

Drain-first reconfigure is necessary but not sufficient for classes
above `drain_only`. Protocol modules additionally need opaque state
export/import, epoch coordination, preserved anchor behaviour where
applicable, and ready signalling so a replacement is not made live too
early.

Handoff is module-owned and opaque. The kernel preserves channels,
module identity mapping, lifecycle hooks, and opaque exported state
blobs; it never interprets TCP control blocks, QUIC packet spaces, TLS
secrets, subscription state, or cursors.

For `edge_anchored` maintenance the anchor survives, the worker drains
and exports, the new worker imports and attaches, and the client
transport stays alive. The target is planned maintenance and
controlled relocation: if the anchor itself crashes, client-visible
continuity is only as strong as the protocol's resume story or a
separate anchor-HA mechanism.

Machinery that fits anchor-preserved replacement: staged graph images
via `graph_slot` with activation by epoch change, and deferred
readiness (`module_deferred_ready`) so a module delays live
participation until import and attach complete. `graph_slot`
activation is whole-graph, so anchor-preserved worker swap uses an
equivalent staging mechanism instead: both worker generations resident
and statically wired, with the anchor's forwarding flip as the
activation (§Reference Fixtures). On quorum-durable deployments a
cluster-coordinated epoch transition serves the same role; the
architecture requires staged, fenced handoff with explicit ready and
epoch semantics, not a particular staging primitive.

## Remote Channels and Placement

`modules/foundation/remote_channel/` is the natural fabric between
anchors and movable workers: when the worker moves, the
anchor–worker boundary is a channel boundary, and remote channels let
it cross nodes without rewriting the module model. When an anchor
terminates TLS, DTLS, or QUIC crypto and forwards post-decrypt traffic
to a worker on another node, that hop becomes the trust boundary, and
the remote-channel transport must provide mutual authentication,
integrity protection, and encryption. Continuity expectations differ
per edge: internal cluster streams may be `resumable` while external
client sessions are `edge_anchored`.

## Shared Continuity Cores

Source: `modules/sdk/cores/`.

Reusable continuity logic lives in cores that modules mount with
`include!`:

- `session_handoff.rs` — opaque export/import chunking with
  incremental CRC32 (`HandoffExport` / `HandoffImport`), plus the
  delivery cursors that place a blob in the session's byte streams
  (`SessionCursors` / `cursors_admit`, §Delivery Cursors); consumed by
  `echo_worker` for the anchor-preserved swap and by `echo_anchor` to
  admit it.
- `nonce_reservation.rs` — windowed egress-counter reservation with
  epoch fencing (`NonceReservation`): the holder never emits a counter
  value it has not been granted, grants are refused across an epoch
  boundary, `void_outstanding` invalidates the rest of a block after
  unsafe recovery, and `needs_refill` drives refill-ahead
  double-buffering. This is the anchor side; the granting authority (a
  durable single-writer directory) is not implemented in this
  repository.
- `protocol_timer.rs` — nearest-deadline tracking (`ProtocolTimers`)
  with post-import rebase, so imported sessions re-anchor their timers
  on the new host's clock.

Further cores are extracted from real implementations once two
consumers exist; packaging (monolithic `ip`, `ip` plus `quic`, or
individual modules) is a per-target decision that must expose the same
surfaces, continuity classes, and capabilities either way.

## Reference Fixtures

- `modules/fixtures/echo_anchor/` — a transport anchor
  (`transport.anchor.stream`). Binds a TCP port on the stream
  surface, accepts one client at a time, mints a `session_id`, and
  attaches a worker with `CMD_SC_ATTACH`.
- `modules/fixtures/echo_worker/` — a session worker
  (`session.worker`, `session.handoff`, `session.resume`). Handles
  attach / drain / detach, uppercases the data plane, and replies
  with the corresponding events.

A graph wires the pair against a network provider; the anchor↔worker
feedback edges require `scheduler.accept_cycles`. With a second worker
on the anchor's `ctrl2_*` / `data2_*` ports and a non-zero
`handoff_after_bytes` param, the anchor runs the full session-control
swap every `handoff_after_bytes` client bytes — drain, chunked export
relayed opaquely, import, resume at epoch + 1, forwarding flip, detach
of the old worker — while the client's TCP stream stays open; client
bytes arriving during the rebinding window are held in the anchor's
bounded ingress buffer and flushed when the new worker goes live. This
is the statically wired active/standby form of the staged handoff
described in §Handoff and Reconfigure Integration.

## Target-Class Fit

Transport anchors are primarily for server-class and edge-class
targets. Constrained devices typically act as clients, session
workers, resumable peers, or protocol consumers. The surfaces and
continuity vocabulary are the same everywhere.

## Related Documentation

- `network.md` — the stream contract wire format, driver layering,
  TLS as channel transformer
- `capability_surface.md` — capability vocabulary, content types, the
  `transport.*` and `session.*` capability names
- `reconfigure.md` — drain and migrate phases, `module_drain`, staged
  reconfigure
- `pipeline.md` — channel mechanics, mailbox mode, deferred ready
- `monitor-protocol.md` — `MON_*` telemetry families, including
  `MON_SESSION`
