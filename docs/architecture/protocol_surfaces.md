# Protocol Surfaces and Session Continuity

This document defines Fluxor's protocol substrate above channels: the four
standard protocol surfaces, the five session continuity classes, and the
architectural roles (transport anchor, session worker, session directory)
that sit above those surfaces.

It is the canonical reference for the RFC in `.context/rfc_protocols.md`.
The RFC explains the motivation and end state; this document is what modules,
manifests, and graph configs refer to for normative vocabulary.

## Scope

This architecture defines:

- the four **protocol surfaces** (stream, datagram, packet, multiplexed
  session) as channel-level contracts
- the five **session continuity classes** (reroutable, drain_only, resumable,
  edge_anchored, transport_migratable) that classify what maintenance
  behaviour a workload requires
- the three **architectural roles** (transport anchor, session worker,
  session directory) that express where client-visible transport identity,
  movable session state, and placement metadata live
- the **session identity model** (`conn_id`, `session_id`, `anchor_id`,
  `session_epoch`) that makes continuity a validatable graph property

It does not define:

- kernel changes (there are none required by this document)
- concrete Rust contract types — those land in phases that touch
  `modules/sdk/contracts/net/`
- packaging of reusable protocol cores — deferred by design
- auto-wiring behaviour beyond what `capability_surface.md` already defines

## Relationship to Existing Architecture

This document extends, not replaces:

- `architecture/network.md` — the current single `net_proto` contract is
  reclassified as **Stream Surface v1** and remains wire-compatible with
  everything that already speaks it
- `architecture/capability_surface.md` — capability matching rules are
  unchanged; new capability names live alongside the existing
  `frame.*` / `audio.*` / `file.*` / `storage.*` taxonomy
- `architecture/reconfigure.md` — `edge_anchored` and `transport_migratable`
  continuity depend on reconfigure's drain/migrate phases plus opaque
  state export/import hooks added in later phases
- `architecture/pipeline.md` — channels remain the only module-to-module
  data path; every surface here is a channel contract
- `.context/future/rfc_remote_channels.md` — remote channels are the
  natural fabric between anchors and remote session workers

## The Four Protocol Surfaces

Every protocol surface is a channel contract. The kernel does not learn
any of them.

### Stream Surface

For ordered byte streams: TCP, TLS-over-TCP, HTTP/1.x, MQTT, SSH-class
protocols, WebSocket after upgrade.

Operations:

- bind / listen
- connect
- accept / connected
- send bytes
- receive bytes
- close
- error
- optional flow-control and retransmit hints

**The current `net_proto` TLV format codifies Stream Surface v1.** The
`MSG_ACCEPTED` / `MSG_DATA` / `MSG_CLOSED` / `CMD_BIND` / `CMD_CONNECT` /
`CMD_SEND` / `CMD_CLOSE` / `MSG_RETRANSMIT` / `MSG_ACK` frames described
in `network.md` are Stream Surface v1 in all but name.

### Datagram Surface

For message-oriented transports: UDP, DTLS, RTP, DNS, STUN/TURN,
discovery and telemetry protocols.

Operations:

- bind endpoint
- optionally connect a default remote endpoint
- send datagram with explicit or default destination
- receive datagram with explicit source metadata
- close
- error

This removes UDP from its current awkward position sharing `net_proto`'s
stream-shaped slots with a payload prefix. A future
`contracts/net/datagram.rs` will define the envelope; until then, UDP
consumers continue to use the existing `SOCK_TYPE_DGRAM` shape described
in `network.md`.

### Packet Surface

For modules that need packet-preserving behaviour and richer metadata:
QUIC engines, DTLS/SRTP packet processors, policy modules, packet
classifiers, direct NIC fast paths, market-data and control-plane packet
flows.

Packet envelope metadata may include:

- ingress lane / interface
- timestamp
- ECN / DSCP / traffic class
- checksum / offload status
- flow hint / connection ID hint
- segmentation or batching markers

The packet surface composes naturally with mailbox and in-place buffer
edge classes where available, but it remains a channel contract. The
zero-copy fast path depends on the mailbox/in-place edge classes and the
NIC-bypass work tracked separately in `rfc_kernel_bypass_nic.md`; this
document only defines the protocol surface that those optimizations
would use.

### Multiplexed Session Surface

For transports that expose many logical streams or message channels over
one transport association: QUIC, future SCTP-data-channel-style
transports, application-defined mux layers.

Operations:

- session open / close
- stream open / accept / close
- per-stream send / receive
- per-stream and per-session error
- readiness and flow-control signaling

This prevents QUIC and similar transports from being forced through a
false TCP-shaped abstraction. HTTP/3 consumes `transport.mux`, not
`transport.stream`.

## The Five Continuity Classes

Session continuity is classified. A graph or module declares the class
its workload requires; the config tool validates that the structural
pieces needed for that class are present.

### `reroutable`

The service may move freely. Existing flows may be dropped or retried.
New flows are simply routed elsewhere.

Examples: DNS, short HTTP, stateless UDP request/response.

Required structure: none beyond the protocol surface itself.

### `drain_only`

Existing flows are allowed to finish gracefully, but no attempt is made
to resume or preserve them beyond drain.

Examples: many HTTP request/response services, short broker operations,
simple stream relays.

Required structure: the consuming module must export `module_drain`
(see `reconfigure.md`).

### `resumable`

The client may reconnect, but the application session can resume from a
token, cursor, lease, or session identifier.

Examples: MQTT session resume, Lattice watch cursor, Chronicle command
cursor or checkpoint, push delivery cursor.

Required structure:

- a declared resumption state shape (token / cursor / lease / session id)
- opaque state export / import hooks compatible with reconfigure's
  migrate phase
- a `session_id` convention for the protocol

### `edge_anchored`

The client-visible transport remains attached to a stable anchor while
the session or application worker may move behind it.

Examples: large MQTT front doors, push notification gateways, long-lived
watch streams, Chronicle agent control channels.

Required structure:

- a module providing `transport.anchor.*` (stream / datagram / mux) for
  the protocol in question
- a session worker providing `session.worker` with export / import hooks
- a session directory providing `session.directory` for placement and
  epoch tracking
- `session_id` and `session_epoch` conventions

This is the most important continuity class for TCP/TLS workloads
because it delivers no-reconnect maintenance without requiring full live
TCP migration.

### `transport_migratable`

The transport association itself may change path or attachment point
without client reconnect.

Examples: QUIC and future QUIC-based services; selected internal
remote-channel transports under full platform control.

Required structure:

- a transport with migration semantics (QUIC connection migration, an
  internal remote-channel transport declaring migration support)
- everything required for `edge_anchored`, because anchor movement may
  participate in the migration handoff

This is the strongest and most ambitious class. It is not required for
all workloads.

### Validation Rule

Continuity class is a validated graph property, not a comment. If a
graph or module declares a class above `drain_only`, the config tool
must confirm the required structural pieces exist. A graph that declares
`edge_anchored` without an anchor provider fails validation at build
time.

## Architectural Roles

These roles sit above the protocol surfaces. They are module roles, not
kernel features.

### Transport Anchor

A transport anchor owns the client-visible transport attachment:

- listening socket or inbound transport endpoint
- accepted client transport state
- TLS or QUIC attachment point where appropriate
- stable front-door identity

The anchor is intentionally conservative about movement. It is the part
that stays put so the client connection does not have to. The anchor
does not have to own all session or application logic.

Anchors typically run on server-class or edge-class targets.
Constrained devices rarely host anchors; they usually act as clients
served by an anchor elsewhere.

### Session Worker

A session worker owns movable state:

- application session state
- broker routing state
- watch / filter state
- fan-out or delivery planning
- durable interaction with backend shards or storage

Session workers may be local or remote relative to the anchor. They may
be moved, drained, resumed, or replaced according to continuity policy.

### Session Directory

A session directory provides placement and continuity metadata:

- logical `session_id` -> current worker location
- continuity class
- `session_epoch` / generation
- resumption metadata
- optional anchor binding metadata

The session directory is an architectural role, not necessarily a
dedicated binary. It may be implemented by a shared service or by a
sibling system such as Lattice for bounded clusters.

The expected continuity class of the directory itself is normally
`resumable`, not `edge_anchored`. It should be replicated and
recoverable, but it does not need to preserve a client-facing transport.

**Write semantics.** The minimum authoritative write semantic is
single-writer authority per `(session_id, session_epoch)`: one
authoritative owner decides the active worker binding for a session
generation. Competing stale writers must be rejected.

**Bootstrap and failure.** Anchors may continue to serve already-attached
sessions using cached bindings during short directory outages, but they
must not create conflicting new ownership. If the directory is
partitioned, the safety rule is *preserve one authoritative owner per
session generation*, not *accept progress everywhere*.

**New-session admission under partition** is per-protocol policy. A
protocol may reject, queue, or use tightly scoped provisional binding,
but it must not create competing durable ownership while authority is
uncertain.

## Session Identity Model

Four distinct identifiers, at three different scopes.

| Identifier     | Scope                          | Notes                                                  |
|----------------|--------------------------------|--------------------------------------------------------|
| `conn_id`      | per-module, per-IP-instance    | cheap local fast-path handle; already in `net_proto`   |
| `session_id`   | stable logical session         | required for continuity classes above `drain_only`     |
| `anchor_id`    | stable front-door anchor       | identifies the transport anchor a session is bound to  |
| `session_epoch`| monotonic per `session_id`     | orders handoffs; stale epochs are rejected             |

- `conn_id` remains module-local and cheap. It is not a kernel resource.
- `session_id` is the continuity-aware identifier used by anchors,
  workers, and directories. It is not required for all protocols.
- `anchor_id` identifies the anchor a session is currently attached to.
- `session_epoch` increases on every authoritative rebind. A worker
  that presents a stale epoch to the anchor or directory is rejected.

**Minting.** In most `edge_anchored` designs, `session_id` is minted by
the protocol owner at the continuity boundary — usually the anchor
during first attach, or the resumption layer during reconnect. It is
typically scoped to a tenant or cluster continuity domain rather than
globally across all deployments. It does not need to appear on the
public wire unless the protocol already exposes a resume token or
session key; many stacks can keep it purely internal.

## Content Contracts

Content contracts carry the envelope metadata each surface needs. They
live alongside the existing content types defined in
`capability_surface.md`.

| Content contract   | Surface             | Purpose                                               |
|--------------------|---------------------|-------------------------------------------------------|
| `NetStreamCmdV1`   | stream              | upstream commands (bind, connect, send, close)        |
| `NetStreamEvtV1`   | stream              | downstream events (accepted, data, closed, error)     |
| `NetDatagramTxV1`  | datagram            | outbound datagrams with explicit destination          |
| `NetDatagramRxV1`  | datagram            | inbound datagrams with explicit source                |
| `NetPacketV1`      | packet              | packet-preserving envelope with ingress metadata      |
| `NetMuxCmdV1`      | multiplexed session | session / stream open / close / send                  |
| `NetMuxEvtV1`      | multiplexed session | session / stream events and readiness                 |
| `SessionCtrlV1`    | any                 | control sideband between anchor, worker, directory    |

Concrete Rust types land in `modules/sdk/contracts/net/`:

- `net_proto.rs` — Stream Surface v1, opcodes `0x01..0x13`. Users:
  HTTP, MQTT, TLS. Stream only; UDP has been retired from this contract
  (Phase 2d).
- `datagram.rs` — Datagram Surface v1, opcodes `0x20..0x43`. Users:
  DNS, RTP, log_net, VoIP. IPv4 addresses BE, ports LE, source always
  carried on RX.
- `packet.rs` — Packet Surface v1, opcodes `0x50..0x63`. Envelope
  reserved; first consumer = Phase 6 QUIC.
- `session_ctrl.rs` — SessionCtrlV1, opcodes `0x70..0x9F`. Envelope
  reserved; first consumers = Phase 5 anchor / worker deployments.
  Carries `session_id` (16 BE) + `anchor_id` / `worker_id` (8 BE) +
  `session_epoch` (4 LE) across ATTACH / DETACH / DRAIN / EXPORT /
  IMPORT / RESUME / EPOCH_BUMP / RELOCATE flows.
- `mux.rs` — Multiplexed Session Surface, opcodes `0xB0..0xCF`.
  Envelope reserved; first consumer = Phase 6 QUIC. Carries
  `session_id` (u32 LE, transport association) + `stream_id` (u32 LE,
  per-session) on every stream-scoped message. Bidi / unidirectional
  / urgent flags on stream open; per-stream and per-session errors;
  flow-control via `STREAM_READY` / `STREAM_ACK` credit messages.
- `stream.rs` — planned, would formalise the Stream Surface v1
  opcodes as a dedicated file once the naming history of `net_proto.rs`
  becomes a burden; low priority while the legacy filename still reads
  clearly.

All four landed files share the 3-byte `[msg_type][len_lo][len_hi]`
TLV header so the existing `net_read_frame` / `net_write_frame` helpers
in `modules/sdk/runtime.rs` work unchanged. Opcode ranges are disjoint
across the files so misconfigured channels fail loudly rather than
silently misparsing.

### Datagram Envelope

The datagram envelope carries:

- local endpoint handle
- source address / port on RX
- destination address / port on TX when not connected-default
- payload length
- metadata flags

### Packet Envelope

The packet envelope carries:

- payload span
- ingress source / lane
- timestamp
- traffic markings (ECN, DSCP, class)
- checksum / offload status
- optional flow hint / connection ID hint

This is the minimum needed for QUIC, WebRTC-class stacks, packet policy
modules, and portability-aware routing.

### SessionCtrlV1

The control-plane sideband between anchors, workers, and directories
carries events for:

- attach (`CMD_SC_ATTACH` / `MSG_SC_ATTACHED`)
- detach (`CMD_SC_DETACH` / `MSG_SC_DETACHED`)
- pause / drain (`CMD_SC_DRAIN` / `MSG_SC_DRAINED`)
- opaque state export / import with chunked transfer and CRC32
  integrity (`CMD_SC_EXPORT_BEGIN` / `CMD_SC_EXPORT_CHUNK` /
  `CMD_SC_EXPORT_END` / `MSG_SC_IMPORT_BEGIN` / `MSG_SC_IMPORT_CHUNK` /
  `MSG_SC_IMPORT_END`)
- resume (`CMD_SC_RESUME` / `MSG_SC_RESUMED`)
- generation change (`CMD_SC_EPOCH_BUMP` / `MSG_SC_EPOCH_CONFIRMED`)
- worker relocation (`CMD_SC_RELOCATE` / `MSG_SC_RELOCATED`)
- role discovery handshake (`CMD_SC_HELLO` / `MSG_SC_HELLO_ACK`)

`SessionCtrlV1` is a module-level contract, not a kernel interface. The
landed envelope lives at `modules/sdk/contracts/net/session_ctrl.rs`.
Identity byte order is **big-endian** for `session_id` / `anchor_id` /
`worker_id` so raw byte comparison matches the cluster's canonical
identity representation; `session_epoch` and status / length fields
remain little-endian for consistency with the other net contracts.

Stale-epoch rejection is an ordering invariant, not just a convention:
receivers reject any message whose epoch is less than the last
authoritative epoch for `session_id` and reply with
`MSG_SC_ERROR` (or implicit drop, per peer policy).

## Observability

Continuity transitions are observable through Fluxor's existing monitor
and log path. Anchors, workers, and directories emit `MON_SESSION`
lines at every `SessionCtrlV1` transition so operators can see attach,
rebind, epoch bump, drain timeout, and stale-generation rejection on
the same telemetry channel already used for other per-module
visibility.

The `MON_SESSION` line format is specified in `monitor-protocol.md`:
one line per transition, `session=` rendered as 32 hex chars big-
endian so a single grep follows a session across all emitters.

No module emits `MON_SESSION` today — the format is reserved and will
become load-bearing when Phase 5 anchor / worker deployments wire up
telemetry. The echo demo (`examples/linux/echo_edge.yaml`) is a
candidate first emitter.

## Module Stack Patterns

### Stateless DNS / Short HTTP (`reroutable` / `drain_only`)

```text
driver(frame.ethernet) -> ip(transport.datagram.udp) -> dns
driver(frame.ethernet) -> ip(transport.stream.tcp)   -> tls -> http
```

VIPs, anycast, and drain are typically sufficient.

### Large Quantum Cluster (`edge_anchored`)

```text
client
  -> quantum_edge_anchor(transport.anchor.stream.secure, mqtt wire session)
  -> remote/local channels
  -> quantum_session_core(session.worker)
  -> topic_router / fanout / persistence
  -> lattice-backed session.directory
```

The split:

- the **edge anchor** keeps the TCP/TLS/MQTT client attachment stable
- the **session core** and downstream broker logic may move
- the **session directory** tracks where the session core lives

For MQTT specifically, the recommended first split is:

- the anchor owns TCP/TLS attachment, MQTT parser/serializer,
  CONNECT/CONNACK attachment state, keepalive timers, negotiated
  capability limits, and the bounded ingress/egress buffers needed to
  survive short worker rebinding
- the worker owns subscriptions, retained session state, shard routing,
  delivery queues, and the durable QoS inflight ledger keyed by packet
  ID and `session_epoch`

The size and overflow policy of the temporary rebinding buffers must be
declared explicitly in the anchor manifest or session contract rather
than emerging implicitly from implementation defaults.

Worker replacement sequence:

1. the anchor enters rebinding mode for `session_id`
2. it temporarily stops issuing new outbound deliveries while continuing
   to service wire-liveness traffic such as keepalive exchange
3. the old worker exports subscription state, delivery cursor, and QoS
   inflight ledger
4. the directory advances `session_epoch` and binds the session to the
   new worker
5. the new worker imports the snapshot, reclaims ownership of the
   inflight ledger, and resumes delivery from the exported cursor
6. the anchor reopens normal forwarding once the new worker declares
   ready for that epoch

MQTT shared-subscription semantics such as `$share/*` cut across
individual session boundaries and are a later Quantum-specific
extension to this split, not part of the first anchor/worker baseline.

### Push Notification Front Door (`edge_anchored`)

```text
device
  -> push_edge_anchor(transport.anchor.stream.secure)
  -> delivery_worker(session.worker)
  -> fanout / queue / backend
```

Same pattern as Quantum, optimized for enormous numbers of mostly idle
long-lived sessions.

### Lattice Watches / Chronicle Control Channels (`resumable` or `edge_anchored`)

```text
client/agent
  -> edge_anchor
  -> watch_or_control_worker
  -> replicated state / orchestration backend
```

### Clustor Internal Replication (`resumable`)

```text
replicator
  -> transport.stream or transport.mux
  -> peer replicator
```

Both endpoints are under platform control and the protocol already has
indices, terms, and retry logic, so `resumable` is usually enough.

### QUIC / HTTP/3 (`transport_migratable`)

```text
driver(frame.ethernet)
  -> ip(transport.datagram.udp)
  -> quic(transport.mux.quic, session continuity support)
  -> http3 / broker / remote-channel transport
```

QUIC is the natural candidate for `transport_migratable` because its
connection model is already designed for path movement.

### WebRTC-Class Stack

```text
driver
  -> ip(transport.datagram)
  -> ice / stun / turn
  -> dtls
  -> srtp / data transport
  -> media / data consumers
```

Benefits from the packet surface and continuity model, but is not the
place to start full transport portability.

## Handoff and Reconfigure Integration

Drain-first reconfigure is necessary but not sufficient for continuity
classes above `drain_only`.

### Handoff Requirements

For `resumable`, `edge_anchored`, and `transport_migratable`, protocol
modules need:

- graceful drain
- opaque state export / import
- optional session export / import
- generation / epoch coordination
- preserved anchor behaviour where applicable
- ready signaling so a replacement path is not made live too early

### Architectural Rule

Handoff remains module-owned and opaque. The kernel may preserve:

- channels
- module identity mapping
- module lifecycle hooks
- opaque exported state blobs

It must not interpret TCP control blocks, QUIC packet spaces, TLS
secrets, MQTT subscription state, RTP jitter buffers, or watch cursors.

### Anchor-Preserved Maintenance

For `edge_anchored` continuity:

- the anchor survives
- the worker drains / exports
- the new worker imports and attaches
- the client transport stays alive

The initial target is **planned** maintenance and controlled relocation.
If the anchor itself crashes unexpectedly, client-visible continuity is
only as strong as the protocol's resume story or a separate anchor-HA
mechanism. This document does not claim that a single anchor failure
becomes invisible; solving unplanned anchor loss requires paired
anchors, replicated anchor state, or stronger transport semantics such
as QUIC-class migration.

### Handoff via `graph_slot`

Fluxor already has machinery that fits anchor/worker replacement:

- staged graph bundles via `graph_slot`
- activation by epoch change
- deferred readiness via `module_deferred_ready` so a module can delay
  live participation until import and attach are complete

On targets using A/B graph slots, the reference local handoff is:

1. stage the replacement worker stack in the inactive slot
2. activate the new slot or generation without dropping the surviving
   anchor
3. let the new worker import exported state while still held behind
   deferred ready
4. flip the anchor's forwarding target to the new worker generation
5. drain and retire the old worker path

On targets or workloads where worker placement is quorum-durable rather
than single-node atomic, an equivalent staging mechanism such as a
cluster-consensus-coordinated epoch transition serves the same
architectural role. The architecture requires staged, fenced handoff
with explicit ready and epoch semantics; it does not require that the
staging primitive be local.

If current `graph_slot` activation remains whole-graph rather than
partial or per-subgraph, then anchor-preserved worker swap requires
either a `graph_slot` extension or an equivalent staging mechanism, and
is tracked as an explicit implementation dependency in the RFC.

## Remote Channels and Placement

Remote channels are the natural fabric between anchors and movable
workers. When the anchor is stable and the worker moves, the boundary
between them is often naturally a channel boundary. Remote channels let
that boundary cross nodes without rewriting the module model.

When an anchor terminates TLS, DTLS, or QUIC crypto and forwards
post-decrypt traffic to a worker on another node, the remote-channel
hop becomes the new trust boundary. In that case the remote-channel
transport **must** provide mutual authentication, integrity protection,
and encryption in line with `.context/future/rfc_remote_channels.md`.

The architecture should explicitly support different continuity
expectations per edge:

- internal cluster streams may be `resumable`
- external client sessions may be `edge_anchored`
- QUIC-based services may become `transport_migratable`

## Packaging and Reuse

Reusable protocol code lives in shared cores and helpers such as
`tcp_core`, `udp_core`, `tls_record_core`, `quic_recovery_core`,
`protocol_timer_core`, `stream_surface_core`, `datagram_surface_core`,
`mux_surface_core`, `session_anchor_core`, `session_directory_core`,
`session_handoff_core`.

These are architectural reuse units, not necessarily separate `.fmod`s.
Whether a target bundles monolithic `ip`, `ip` plus `quic`, a combined
secure ingress stack, or individual modules is a packaging decision made
per target. Whichever packaging is chosen must expose the same surfaces,
continuity classes, and capabilities, so loose coupling and reuse do
not depend on packaging shape.

## Target-Class Fit

Not every role belongs on every target.

- transport anchors are primarily for server-class or edge-class targets
- constrained devices typically act as clients, session workers,
  resumable peers, or protocol consumers
- the same surfaces and continuity vocabulary apply everywhere

This keeps the model honest across RP-class devices, Pi-class systems,
and larger clustered deployments.

## Reference Implementation

A minimal end-to-end demonstration of the anchor / worker split lives
in the tree:

- `modules/app/echo_anchor/` — transport anchor. Binds a TCP port via
  Stream Surface v1, accepts one client at a time, mints a
  `session_id`, and attaches the worker via
  `CMD_SC_ATTACH` (continuity class `edge_anchored`).
- `modules/app/echo_worker/` — session worker. Handles
  `CMD_SC_ATTACH` / `CMD_SC_DRAIN` / `CMD_SC_DETACH`, uppercases each
  byte in the data plane, returns `MSG_SC_ATTACHED` / `MSG_SC_DRAINED`
  / `MSG_SC_DETACHED` back to the anchor.
- `examples/linux/echo_edge.yaml` — graph wiring the two modules
  against `linux_net` on port 9000. Runs with
  `fluxor run examples/linux/echo_edge.yaml` and is exercised over
  plain TCP (`nc 127.0.0.1 9000`).

The demo validates the `SessionCtrlV1` envelope end-to-end: HELLO is
skipped (optional), `ATTACH` / `ATTACHED` open the session, raw bytes
flow bidirectionally over the data plane, and `DETACH` / `DETACHED`
close it. Multiple sequential client sessions recycle cleanly through
`ATTACH → ACTIVE → DETACH → LISTENING`.

Live worker handoff (anchor-preserved worker swap) is deliberately
out of scope for this demo — it needs `graph_slot` per-subgraph
activation or an equivalent staging mechanism (see
`architecture/protocol_surfaces.md` §Handoff and Reconfigure
Integration).

## Buildability — VoIP-as-anchor and QUIC

The five contract files (`net_proto`, `datagram`, `packet`, `mux`,
`session_ctrl`) plus the `transport.*` / `session.*` capability
vocabulary in `capability_surface.md` plus the `MON_SESSION` line
format in `monitor-protocol.md` together cover every operation the
RFC's six phases require. Two specific future deployments are
buildable from what's landed today:

### VoIP edge-anchored

A VoIP front door split into `voip_edge_anchor` (owns SIP/RTP client
attachment) + `voip_session_worker` (owns dialog state, fanout,
durable interaction with backend) is buildable with **no new
contracts**:

| Need | Provided by |
|------|-------------|
| SIP signalling | `datagram.rs` (SIP runs on UDP today; `voip` already migrated in Phase 2c) |
| RTP media | `datagram.rs` for RX, jitter buffer in worker |
| ATTACH / DETACH on call setup / teardown | `session_ctrl.rs` CMD_SC_ATTACH / DETACH |
| Worker handoff during a live call | `session_ctrl.rs` CMD_SC_DRAIN / EXPORT / IMPORT / RESUME / RELOCATE |
| Session epochs to reject stale RTP after rebind | `session_ctrl.rs` `session_epoch` |
| Operator visibility | `monitor-protocol.md` `MON_SESSION` |

What's still needed to ship: split the existing `voip` module's
state into `voip_edge_anchor` + `voip_session_worker` along the
SIP-state vs media-state boundary, wire SessionCtrlV1 between them.
Pattern proven by `echo_anchor` + `echo_worker`. No architectural
gaps.

### QUIC + HTTP/3

A `quic` foundation module providing `transport.mux.quic` with
`transport_migratable` continuity is buildable with the contracts
landed today:

| Need | Provided by |
|------|-------------|
| Underlying UDP transport with src/dst metadata | `datagram.rs` |
| Packet-preserving fast path with timestamp / ECN / flow_hint / lane | `packet.rs` |
| Multiplexed-session surface (one transport, many streams) | `mux.rs` |
| Per-session migration (path change without reconnect) | `session_ctrl.rs` `CMD_SC_EPOCH_BUMP` / `CMD_SC_RELOCATE` |
| `transport.mux.quic` capability | `capability_surface.md` |
| `transport_migratable` continuity class | This document §Continuity Classes |

What's still needed to ship: the `quic` module itself (substantial
engineering), an HTTP/3 layer that consumes `transport.mux`, and
config-tool validation for `transport_migratable` graphs. The
contract envelopes are reserved in advance precisely so this work
has a stable target.

### What's NOT in this document

The following are explicitly **out of scope** of the RFC's protocol
substrate but are tracked separately:

- `graph_slot` per-subgraph activation (RFC §13.4 dependency) — needed
  for fully-atomic anchor-preserved worker swap. Tracked in repo
  memory as a separate workstream.
- Reusable protocol cores (`tcp_core`, `quic_recovery_core`,
  `session_handoff_core`, etc., RFC §15.1) — code-sharing units
  extracted from real implementations once two consumers exist.
- Live `MON_SESSION` emission in modules — needs a module-index
  syscall or a dedicated monitor module that tails SessionCtrlV1
  channels.

These are engineering follow-ups, not architectural gaps. The
five-contract substrate and the role / capability / continuity-class
vocabulary are complete.

## Related Documentation

- `architecture/network.md` — current `net_proto` / Stream Surface v1
  wire format, driver layering, TLS as channel transformer
- `architecture/capability_surface.md` — capability matching, content
  types, hardware-domain expansion; hosts the `transport.*` and
  `session.*` capability names
- `architecture/reconfigure.md` — drain / migrate phases, module_drain
  export, staged reconfigure
- `architecture/pipeline.md` — channel mechanics, mailbox mode,
  deferred ready
- `architecture/monitor-protocol.md` — MON_* telemetry families;
  `MON_SESSION` lands here
- `.context/rfc_protocols.md` — the source RFC for this document
- `.context/future/rfc_remote_channels.md` — remote-channel fabric
  between anchors and remote workers
