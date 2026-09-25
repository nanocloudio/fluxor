# Capability Surface Architecture

This document is the reference for Fluxor's capability vocabulary: the
content types that type every channel, the capability and provider-contract
registries that module manifests declare against, and the build-time
validation the config tool applies to those declarations. It also describes
platform stack expansion, the mechanism that turns a board-independent
application config into a concrete driver-and-foundation module graph.

## Scope

This architecture defines:

- the four declaration fields in a module's `manifest.toml`
- port content types and the on-wire content-type byte table
- the capability registry (`capabilities = [...]`)
- the provider-contract and provider-surface registries
  (`requires_contract`, `provides = [...]`)
- service and continuity validation in the config tool
- platform stack expansion (`platform:` in graph YAML)

## The Problem

A static HTTP file server needs a byte-stream transport. The transport needs
an IP stack. The IP stack needs Ethernet frames. Frames need a hardware
driver. The chain between "I need a stream" and the physical hardware varies
by board:

| Hardware | Module chain | Count |
|----------|-------------|-------|
| cyw43 (WiFi, raw frames) | cyw43 + wifi + ip | 3 |
| enc28j60 (Ethernet, raw frames) | enc28j60 + ip | 2 |
| rp1_gem (Pi 5 Ethernet) | rp1_gem + conn_guard + ip | 3 |

The application module is identical in every case: it speaks the `NetProto`
framing over a channel and never touches frames or drivers. What changes per
board is the substrate stack, and that is exactly what platform stack
expansion injects (see §Platform Stack Expansion).

The same substitution property holds in other domains. A module that
consumes `file.data` can be served by `fat32` over a local block device or
by the host filesystem on Linux; a module that emits `AudioSample` can feed
an I2S sink or a host audio device. The channel abstraction makes the bytes
identical either way; the capability vocabulary makes the substitution
declarable and checkable.

## Manifest Declarations

Source: `tools/src/manifest.rs`, `contracts/src/vocabulary.rs`.

A module's `manifest.toml` separates four concerns into four fields:

- top-level `provides = [...]` — services or storage surfaces this module
  offers to consumers. Validated against `PROVIDER_CONTRACTS` plus
  `PROVIDER_SURFACES`; an unknown name fails the build with a
  did-you-mean hint.
- top-level `capabilities = [...]` — role and surface capabilities the
  module carries (presentation, audio, transport, continuity roles).
  Validated against `CAPABILITY_NAMES` and canonicalised to lowercase.
- `[[resources]].requires_contract = "..."` — kernel or provider contracts
  the module needs at runtime (GPIO, SPI, PIO, channel, FS, timer,
  platform DMA, and the rest of `PROVIDER_CONTRACTS`), with an `access`
  mode of `read`, `write`, `exclusive`, or `chain`.
- `[requires]` — target CPU features. A module that declares
  `requires.fpu = true` is rejected at build time from a target without
  hardware floating point.
- `[[requires_when]]` — a target-provided capability (see
  [Target-Provided Capabilities](#target-provided-capabilities)) the module
  needs only under one of its own parameter values: `param`, `equals`,
  `capability`. The composer resolves the parameter from the graph (or the
  schema default) and refuses placement on a target that cannot provide the
  capability when the value matches.

Examples from shipped manifests:

```toml
# modules/drivers/cyw43/manifest.toml
[[resources]]
requires_contract = "pio"
access = "exclusive"

[[resources]]
requires_contract = "gpio"
access = "write"

# modules/drivers/i2s_pio/manifest.toml
capabilities = ["audio.sample", "presentation.clock"]

[[resources]]
requires_contract = "pio"
access = "exclusive"

# modules/foundation/fat32/manifest.toml
provides = ["file.data"]
```

Modules without these fields participate only in explicit wiring and in
platform stack expansion.

## Port Content Types

Every port in `manifest.toml` declares a `content_type` naming the data
format that flows through it:

```toml
[[ports]]
name = "audio"
direction = "input"
content_type = "AudioSample"
required = true
```

The config tool validates each wired edge against the content types and
directions of the two ports it connects; a content-type name not in the
registry fails manifest parsing with a did-you-mean hint.

Content-type identifiers are `UpperCamelCase` and resolve to a positional
wire byte (`contracts/src/lib.rs::CONTENT_TYPES`). Tooling writes the byte
index into the compiled manifest; the kernel routes by byte, never by name.
The table is append-only: reordering or removing an entry is a wire-format
break for every existing compiled config.

The dotted lowercase storage names (`storage.block`, `file.data`,
`storage.namespace`, `storage.object`) are not content types. They are
semantic surfaces declared through `provides` / `requires_contract`; their
byte streams ride `OctetStream` on the wire.

### Content Type Registry

Source: `contracts/src/lib.rs`.

| Byte | Content type | Carries |
|-----:|--------------|---------|
| 0 | `OctetStream` | Untyped byte stream: block I/O, file data, project-local protocols |
| 1 | `Cbor` | CBOR-encoded structured data |
| 2 | `Json` | JSON structured data |
| 3 | `AudioSample` | Decoded sample-domain audio (PCM) |
| 4 | `TextPlain` | Plain text |
| 5 | `TextHtml` | HTML text |
| 6 | `VideoRaster` | Pixel-domain frames |
| 7 | `MeshEvent` | Mesh event payloads |
| 8 | `MeshCommand` | Mesh command payloads |
| 9 | `MeshState` | Mesh state payloads |
| 10 | `MeshHandle` | Mesh handle payloads |
| 11 | `InputEvent` | Generic input event record; new graphs wire the per-class input types below |
| 12 | `GestureMatch` | Matched gesture identifiers |
| 13 | `FmpMessage` | FMP control messages (next / prev / toggle) |
| 14 | `EthernetFrame` | Raw Ethernet frames |
| 15 | `HciMessage` | Bluetooth HCI messages |
| 16 | `AudioEncoded` | Codec-domain audio access units; codec identity travels in-band, never as a content-type fork |
| 17 | `VideoEncoded` | Codec-domain video access units |
| 18 | `VideoDraw` | Retained / replayable draw lists |
| 19 | `VideoScanout` | Present-ready output to a paced display sink |
| 20 | `MediaMuxed` | Combined AV / timing / container streams |
| 21 | `WsFrame` | WebSocket frame surface: `{conn_id u32, opcode u8, fin u8, payload_len u16}` + payload |
| 22 | `InputBinaryState` | Labelled binary state set (see `input_capability_surface.md`) |
| 23 | `EventTimelineVideo` | Frame-aligned event stream, video flavour |
| 24 | `EventTimelineAudio` | Frame-aligned event stream, audio flavour |
| 25 | `NetProto` | Net protocol framing `[msg_type:u8][len:u16 LE][payload]`, delivered atomically on a byte-stream channel |
| 26 | `PointerEvents` | Packed pointer event records (`modules/sdk/contracts/input/`) |
| 27 | `KeyEvents` | Packed key event records |
| 28 | `GamepadEvents` | Packed gamepad event records |
| 29 | `MidiEvents` | Fixed 4-byte MIDI channel-voice events (`modules/sdk/contracts/input/midi.rs`) |
| 30 | `Telemetry` | Fixed-layout `TelemetryRecord` (`modules/sdk/contracts/telemetry.rs`) |
| 31 | `SurfaceTraits` | Fixed 24-byte environment-plane descriptor (`modules/sdk/contracts/input/surface_traits.rs`) |
| 32 | `PresentationLayout` | Resolved presentation-layout records (`tools/src/presentation_resolver.rs`) |
| 33 | `HttpRequest` | HTTP fan-out request half: `{conn_id u16, stream_id u16, method u8, flags u8, path_len u16, hdr_len u16, body_len u16}` + bytes |
| 34 | `HttpResponse` | HTTP fan-out response half, matched to its request by `(conn_id, stream_id)` |
| 35 | `NamespaceChange` | Control-plane store change surface, one record per key mutation: `{revision u64, kind u8, key_len u16, val_len u32}` + key and value bytes, inside a mesh Event envelope |
| 36 | `GpuCommand` | Generic GPU work — the request stream of `modules/sdk/wire/gpu_wire.rs` (query, resource, program, transfer, submission, fence, control, surface) |
| 37 | `GpuOutcome` | Generic GPU outcomes — the reply half: acceptance, handles, capabilities, readback bytes, surface leases, and exactly one terminal outcome per accepted request |
| 38 | `SensorSample` | A measured physical quantity, one fixed 24-byte reading per record (`modules/sdk/contracts/sensor.rs`). The quantity and its unit are capability facts on the producing port, not bytes in the record |
| 39 | `MeasurementStream` | A block of samples per acquisition — a radar chirp set, a microphone window, an IMU burst (`modules/sdk/contracts/measurement.rs`). Fixed 16-byte header then the block; the sample encoding, channel count and samples per channel are capability facts, while `block_len` is per-frame because a final or drained block is legitimately short |

Codec identity is deliberately not part of this table. Encoded surfaces are
generic (`AudioEncoded` / `VideoEncoded`): a content type names a
substitution surface, not an implementation enumeration. Encoded access
units and container formats are self-describing, so codec identity travels
in-band or as a fact on the wiring edge. Whole encoded images ride
`OctetStream` (magic-byte self-describing). The admission test for new
vocabulary is in `abi_layers.md`.

External modules use the same schema and the same registries as first-party
modules; a new content type is added by appending to `CONTENT_TYPES`, not by
inventing a project-local string.

### Rate classes

Source: `contracts/src/lib.rs` (`RateClass`, `CONTENT_RATE_CLASS`).

Every content type carries a default rate class — `control`, `audio`,
`video`, `bulk`, or `transaction` — describing the sustained-throughput
demand of a stream. A wiring edge can override the default with a `rate:`
key. The config compiler validates each edge's granted ring against its
class floor at build time, and the kernel derives per-step pump budgets
from the class.

## Capability Registry

Source: `contracts/src/vocabulary.rs` (`CAPABILITY_NAMES`).

The registry accepted in a manifest's `capabilities = [...]` list has two
tiers sharing one namespace: hardware-facing roles (the role a module plays)
and service-level surfaces (the substitutable data a producer or consumer
carries). Grammar is domain-leading lowercase dotted, with the role noun
before any refinement (`display.scanout.protected`). Quantities and limits
are capability facts, not name segments.

Hardware-facing roles:

| Capability | Meaning |
|------------|---------|
| `display.scanout` | Paced display output |
| `display.multihead` | Multiple simultaneous scanout heads |
| `display.capture` | Produces frames of a display that exists elsewhere — a shared screen, window or tab — as opposed to *being* a display or being a camera. Declared as a role rather than left to convention, because a viewer that cannot tell a shared screen from a camera cannot tell a person what is being shared |
| `display.scanout.protected` | Protected-content scanout path |
| `video.decode` | Hardware video decode |
| `video.encode` | Hardware video encode |
| `video.decode.protected` | Protected-content decode path |
| `audio.output.protected` | Protected audio output path |
| `audio.output.rate_trim` | Output clock rate trimming |
| `gpu.render` | GPU render capability |
| `gpu.compute` | GPU compute capability |
| `presentation.clock` | Sink-authored presentation clock |

Service-level surfaces (mirroring the content-type surface family):

| Capability | Meaning |
|------------|---------|
| `audio.sample` | Decoded sample-domain audio |
| `audio.encoded` | Codec-domain audio |
| `video.encoded` | Codec-domain video |
| `video.draw` | Draw-list video |
| `video.raster` | Pixel-domain video |
| `video.scanout` | Present-ready scanout stream |
| `media.muxed` | Container-muxed media |
| `media.path.protected` | End-to-end protected media path |
| `presentation.group` | Synchronised presentation group membership |

Input and MIDI:

| Capability | Meaning |
|------------|---------|
| `input.mapper` | Translates raw input into application actions |
| `input.gamepad` | Gamepad input source |
| `input.virtual` | Virtual (software-defined) input source |
| `input.remote` | Remote input source |
| `midi.input` | MIDI input (Web MIDI on wasm, ALSA seq on Linux, USB-MIDI host on rp2350 / bcm2712) |
| `midi.output` | MIDI output |

Transport surfaces:

| Capability | Meaning |
|------------|---------|
| `transport.stream` | Byte-stream transport endpoint |
| `transport.stream.tcp` | TCP byte-stream transport |
| `transport.stream.secure` | Secured byte-stream transport (post-TLS) |
| `transport.datagram` | Datagram transport endpoint |
| `transport.datagram.udp` | UDP datagram transport |
| `transport.datagram.secure` | Secured datagram transport (post-DTLS) |
| `transport.mux` | Multiplexed session transport |
| `transport.mux.quic` | QUIC transport |
| `transport.packet` | Packet-preserving network surface |
| `security.tls13.stream` | TLS 1.3 stream security layer |
| `security.dtls13.datagram` | DTLS 1.3 datagram security layer |

Continuity roles (see `protocol_surfaces.md` for the session-continuity
model these support):

| Capability | Meaning |
|------------|---------|
| `transport.anchor.stream` | Stable stream-facing transport anchor |
| `transport.anchor.stream.secure` | Stable secure stream-facing anchor. tls declares `aead = "implicit_counter"` with `horizon = "exact"` |
| `transport.anchor.datagram` | Stable datagram-facing anchor |
| `transport.anchor.mux` | Stable multiplexed-session anchor. quic declares `aead = "on_wire_sequence"` |
| `session.worker` | Movable session / application worker |
| `session.directory` | Placement and continuity metadata service |
| `session.resume` | Resumable session state support. Facts `scope` (`local`: the ticket names state only the minting host holds; `fleet`: the ticket is the state, sealed under a vault key any admitted host with that generation opens) and `early_data` (`off`, or `local_single_use` against the minting host's single-use record). quic declares `local` / `local_single_use` |
| `session.handoff` | Opaque export / import handoff support |
| `session.reservation` | Durable, quorum-committed reservation of nonce / sequence blocks, so a taken-over sender never reuses AEAD nonces |
| `security.key_wrap` | Session-key custody wrapped under a KEK the storage layer cannot read |
| `fence.enforceable` | Emission fence for a local address: after the fence answers, nothing sourced from the address is handed onward, and ARP for it is not answered. Fact `cutoff`: `ring_handoff` (the ip module's boundary — frames already in the driver ring may still leave) or `wire` (the driver drained on request and reported its completed transmit count). Provided by `ip` over the `net::identity` `ADDR_FENCE` verb with a per-install token minted from the CSPRNG and the boot incarnation; the manifest declares `ring_handoff` and the composer raises it to `wire` on a target whose NIC driver answers the `tx_drain` query (bcm2712). An out-of-band fence agent — a member placed on another node whose cut is power or the fabric port, `modules/fixtures/fence_agent/` being the reference — answers the same verbs and declares `wire` for itself |
| `durable.rpo_zero` | Synchronous quorum-durable-before-acknowledge write path for security-relevant session state |

The anchor roles share one fact schema, declared on the
`transport.anchor` parent they descend from rather than repeated on each.
`aead` states what protects the records the peer is shown, and so whether a
taken-over sender may skip its counter forward: `on_wire_sequence`, where
the peer reads each record's sequence from the record itself and a skip is
legal; `implicit_counter`, where both peers count in lockstep and a skip
fails the peer's decrypt; or `unencrypted`, where there is no counter to
protect. `horizon` is what an implicit-counter anchor must state to reach
replicated-anchor continuity at all: `exact`, where nothing is shown to the
peer until the standby has confirmed it holds that transition, so a
takeover resumes on the counter the peer is actually at; or `cut`, where
only the checkpoint cut is exact and the mirror runs behind it.

Target-provided:

| Capability | Meaning |
|------------|---------|
| `time.wall` | Calendar time (seconds since the Unix epoch) the platform can vouch for, as `timer::TRUSTED_UNIX` reports it. Fact `source`: `rtc`, `network_sync` or `signed_authority` — the strongest class the HAL reports `TRUSTED` for |
| `trust.system` | Whether the platform will verify a certificate chain and answer for it — the `trust` contract (class `0x001D`). Carries no facts: a verifier either answers or it does not. True of the TARGET, not of the machine — a linux host whose root bundle is missing still answers, by refusing every chain |

Replication and streaming:

| Capability | Meaning |
|------------|---------|
| `replication.state_machine` | Replicated commit-and-apply surface: per-entry committed stream, accepted-into-WAL index echo, quorum-durability notice, snapshot install / export, apply-pipeline reset |
| `stream.ordered_ack` | Ordered-publish surface answering durable acks and link-state signals; the parent a consumer requires when it only publishes, satisfied by either role below. Wire contract: `modules/sdk/contracts/exchange.rs` |
| `stream.ordered_ack.sink` | A provider that accepts records and does not answer with data: an MQTT topic, a Kafka partition, an INSERT |
| `stream.ordered_ack.exchange` | A provider that additionally answers each publish with data on the same correlation: an HTTP GET, a SELECT |
| `stream.line` | Line- or byte-delimited text stream: one command's output feeding the next command's input, unidirectional, backpressured by the channel, with no correlation and no acks |
| `stream.publish` | Substitutable fire-and-collect publish surface — what a pipeline stage or a program binds. Generalises `stream.ordered_ack`, which additionally promises the durable-ack session protocol |
| `stream.subscribe` | Substitutable subscribe surface: records delivered to a stage, with the delivery guarantee and replay support declared as facts |
| `request.http` | Substitutable HTTP request surface |
| `request.record` | Substitutable record-query surface (a table, a key-value store) |
| `sensor.sample` | Produces `SensorSample` records. What a consumer requires to bind a thermometer, a light sensor, a replay module or a simulator alike; the quantity, cadence and payload ceiling are facts the composer checks against what the consumer asked for |
| `measurement.stream` | Produces `MeasurementStream` records: a block per acquisition, from a producer whose individual readings are not separately meaningful. The block's shape — encoding, channels, samples per channel — are facts, so the composer refuses a consumer that would de-interleave it wrongly |

The last four are application-EFFECT surfaces: what a graph binds when a
stage publishes, subscribes, or calls out, as opposed to the transport it
rides. Profile differences between providers are capability FACTS, never
name forks — `stream.publish` with `broadcast = "fanout"` is Kafka's genuine
multi-partition ack, and with `broadcast = "degenerate"` is MQTT's single
ordering unit. The admitted facts and their values are
`CAPABILITY_FACTS` in `contracts/src/vocabulary.rs`; unknown names and
unadmitted values are rejected at manifest parse.

`replication.state_machine` sits one layer above the storage
read / write / durability surfaces: its index echo, snapshot callbacks, and
reset signal have no equivalent in the `storage.namespace` + `event.log`
pattern (see `storage_capability_surface.md` §4), which stays at the storage
layer. The full contract lives with whichever module provides it; only the
surface name is canonical here, so a manifest can declare it typo-checked.

### What consumes the registry

Declared capabilities are validated vocabulary consumed by the config-block
validators — the `presentation_groups` blocks described in
[av_capability_surface.md](av_capability_surface.md) and the
`continuity` blocks described below. There is no generic string-matched requires→provides resolver:
graphs wire a surface's ports explicitly, and substrate stacks are injected
by platform stack expansion. Continuity roles do not consume bits in the
`required_caps` device-class mask; they live in the manifest vocabulary
alongside `audio.sample`.

### Target-Provided Capabilities

Source: `contracts/src/vocabulary.rs` (`TARGET_CAPABILITIES`),
`tools/src/target_facts.rs`.

A few capabilities are properties of the platform rather than of any
module: no manifest declares them, no graph wires them, and the kernel's
HAL is what answers them at runtime. The composer answers them per target
from the target-facts table, which also carries the vault's suite set and
custody-tier ceiling for the same reason — the vault is a kernel contract
class, per target, not a module.

Two capabilities are answered this way: `time.wall` and `trust.system`.
At runtime the kernel's
`timer::TRUSTED_UNIX` record says whether a reading is `TRUSTED` (backed by
synchronisation evidence), which epoch it belongs to, and whether the clock
is suspected of having rolled back; a consumer making a validity decision
reads that record and refuses on an untrusted reading. At compose time the
same fact is admissible: a module that fails closed without a trusted clock
under some configuration binds that configuration with `[[requires_when]]`,
so a graph that would only ever refuse handshakes is refused before it is
built. The `tls` module does this for `clock_policy = require`:

```toml
[[requires_when]]
param      = "clock_policy"
equals     = "require"
capability = "time.wall"
```

Which targets provide `time.wall` follows the HAL: a hosted Linux runtime
queries `adjtimex(2)` and reports `network_sync`; the bare-metal and
browser platforms have no synchronisation evidence and provide nothing. A
target that gains a time source gains the row, and the table states the
same facts as the platform HALs it describes.

### Execution envelope

Source: `tools/src/manifest.rs` (`ExecutionEnvelope`),
`tools/src/target_facts.rs` (`admit_execution_profile`,
`TargetFacts::step_budget_us`), `tools/src/config/validate.rs`.

Cooperative budgets say what a step MAY take; they are not evidence of
what it DOES take. A module states that evidence in its manifest as two
facts and the profile they hold under:

```toml
[execution]
max_step_us     = 120   # exclusive CPU time of one module_step
max_dispatch_us = 40    # bounded cost of one synchronous provider dispatch
profile         = "measured_envelope"
evidence        = "observed maxima under mixed TCP / ARP / UDP load"
```

`max_step_us` is the step's own CPU time; the synchronous provider calls it
makes are charged separately through `max_dispatch_us` and their bounded
count, so a provider shared by several callers is counted once. There are
two profiles and they are not interchangeable:

- `analytical_bound` — the numbers rest on a reviewed derivation over
  bounded code paths, named by `evidence` (required). Only bare metal can
  honour a bound claim.
- `measured_envelope` — the numbers are observed maxima under a stated
  workload on a stated host, with a safety factor over the observation. A
  percentile, not a guarantee. Linux and wasm publish this profile only:
  a hosted runtime's latency tail belongs to the host scheduler.

The manifest parser checks that both facts are present and positive, that
the profile is one of the two, that an analytical bound names its
evidence, and that `max_step_us` fits the step budget of every silicon in
`hardware_targets` — one default scheduler pass, taken from the
target-facts table, which carries the kernel's own budget for that silicon.

A graph claims a profile for itself at compose:

```yaml
execution:
  profile: measured_envelope   # or analytical_bound
```

A graph that names none claims nothing. With a claim, admission is per
instantiated module and names every offender: `analytical_bound` needs
every member to declare `analytical_bound` and the target to be bare
metal; `measured_envelope` needs every member to declare `[execution]` at
all, since a module with no facts cannot be part of a measured claim.

What passes here is the presence and kind of each member's evidence. The
graph arithmetic — summing admitted quanta and dispatch costs into a
scheduler round, composing a service curve with an arrival envelope,
checking each edge's backlog and deadline — is not part of the claim, and
an admitted graph holds no derived end-to-end latency bound. `ip` is the
measured module: its envelope is the maximum step time observed under a
mixed TCP / ARP / UDP load, times the safety factor recorded beside the
number.

## Provider Contracts and Surfaces

Source: `contracts/src/vocabulary.rs`, `tools/src/config/generate.rs`,
`tools/src/config/validate.rs`.

`PROVIDER_CONTRACTS` names the privileged operation families accepted in
`[[resources]].requires_contract` and, for service providers, in
`provides`:

```
gpio  spi  i2c  pio  channel  timer  platform_nic_ring  platform_dma
fs  buffer  event  uart  adc  pwm  platform_dma_fd  pcie_device
storage.namespace  storage.object  usb_host
```

Naming is lowercase `snake_case`, with the two storage contracts in their
dotted spelling because they mirror the public semantic storage surfaces.
The numeric dispatch IDs live in `fluxor-tools`
(`manifest::contract_id_from_name`).

`PROVIDER_SURFACES` extends the `provides` vocabulary with the storage
surface family that providers advertise but that is not class-byte
dispatched: `storage.block` and `file.data`.

Validation applied by the config tool:

- **Services.** A graph's `services:` section maps a service name to a
  provider module. The tool checks the provider exists in the graph and
  that its manifest declares `provides` for that service.
- **Single provider per surface.** Two modules providing the same
  contract surface with the same instance selector is a build error: the
  later registration would silently shadow the earlier one at runtime.
  Multiple providers of one surface are allowed only with distinct
  `volume:` selectors routed by a `mount` module. See
  `storage_capability_surface.md` §1 for the full mechanism.
- **Exclusive-access conflicts.** Two modules claiming `exclusive` access
  to the same device class and instance is a build error.

## Storage Capability Surfaces

The storage capability is decomposed into four canonical surfaces plus one
orthogonal axis. The full architecture, including opcodes, providers, and
the leased-handle contract, is in `storage_capability_surface.md`; the
names belong in this taxonomy:

```
storage.block       — raw block I/O. Drivers (sd, nvme, flash_rp)
                      provide; filesystems consume.
file.data           — byte-stream file access (open, read, seek, stat,
                      write, fsync). fat32 and the mount router provide;
                      the Linux host serves it as a platform provider.
storage.namespace   — name-keyed directory surface (lookup, stat, list,
                      rename, delete, bind, subscribe).
storage.object      — whole-blob byte-addressed surface (put, get, head,
                      range_get, delete).
```

The orthogonal axis is `abi::fence::Fence`: every storage op that completes
successfully returns the strongest fence it actually achieved —
`Volatile`, `LocalDurable`, `ReplicatedDurable`, `ContentHashed`,
`RevisionMonotone`, or `ViewConsistent`. Providers may share a surface name
and differ in fence strength; the fence is what makes substitution honest.
`storage_capability_surface.md` §2 carries the full rationale and the
partial order.

The `event.log` content-type pattern (not a surface) reuses these
primitives: a `storage.namespace` entry resolves to an Event stream with
monotone per-source sequence and the appropriate fence. Local WALs,
replicated commit logs, and generic append logs all reduce to this pattern
without a separate capability surface.

## Continuity Validation

Source: `tools/src/config/validate.rs`, `tools/src/config/manifest.rs`.

A graph config may declare `continuity` blocks classifying its sessions
into one of five classes: `reroutable`, `drain_only`, `resumable`,
`edge_anchored`, or `transport_migratable` (the classes themselves are
defined in `protocol_surfaces.md`). The validator checks each declaration
as graph structure:

- `resumable` — at least one declared member (`anchor` or `workers`) must
  carry `session.resume`.
- `edge_anchored` — the `anchor` module must carry a `transport.anchor.*`
  capability; every worker must carry `session.worker`; with more than one
  worker (an anchor-preserved swap target), every worker must also carry
  `session.handoff`.
- `transport_migratable` with mechanism `native_primitive` — some module
  in the graph must provide a `transport.mux.*` transport, since the wire
  protocol itself carries the migration.
- `transport_migratable` with mechanism `platform_replicated_state` — the
  declaration must name an `anchor` carrying `transport.anchor.datagram`,
  `transport.anchor.stream.secure` or `transport.anchor.mux` and a
  `directory` carrying `session.directory`, declare its AEAD class and a
  failover budget, and the graph must resolve providers for all four of
  `session.reservation`, `security.key_wrap`, `fence.enforceable`, and
  `durable.rpo_zero`. A stream or mux anchor is admitted only on a target
  where Fluxor owns the transport (`TargetFacts::owns_transport`: the
  bare-metal silicons, never `linux` or `wasm`). The fence is checked in
  two halves: the ip module's `fence.enforceable` must reach
  `cutoff = "wire"` on the target (`TargetFacts::nic_tx_drain`), and an
  out-of-band `fence.enforceable` provider must declare
  `[capability_facts."fence.enforceable"] cutoff = "wire"` for itself
  and be a member placed on another node (`modules[].node`,
  `protocol_surfaces.md` §Remote Channels and Placement) — a local
  cutoff alone never confirms a hung host quiet, and a module on this
  node declaring `wire` is refused by name. The anchor is never a placed
  member. The declared `aead` must equal the anchor's own
  `transport.anchor` `aead` fact — the declaration names the anchor's
  AEAD class, it does not choose it, and an anchor stating none is
  refused. `implicit_counter` is admitted only through an anchor
  declaring `horizon = "exact"`: an implicit-contiguous AEAD counter
  cannot skip forward on takeover, so without a mirror that holds each
  record before the peer is shown it, that transport's honest ceiling
  is `resumable`.

These checks establish the presence of a capability, not its correctness
under fault. Mechanism and AEAD fields are only valid on
`transport_migratable`; declaring them on a weaker class is an error.

Security is orthogonal to transport: `transport.stream` is not equivalent
to `transport.stream.secure`. `tls` upgrades plain stream to secure stream;
`dtls` upgrades plain datagram to secure datagram. Secure anchors may be
expressed as composed stacks (`tls` in front of `transport.anchor.stream`)
or as the explicit `transport.anchor.stream.secure` capability where that
makes graph validation clearer. Continuity behaviour is policy: nothing
inserts TLS / DTLS silently, invents anchors, or promotes `resumable` to
`edge_anchored`.

## Platform Stack Expansion

Source: `tools/src/stack_expand.rs`, `stacks/*.toml`,
`tools/src/target.rs`.

Stack expansion is how a board-independent application config acquires its
hardware substrate. A graph YAML declares a `platform:` section naming the
stacks it wants (`net`, `audio`, `display`, `storage`, `pointer`,
`keyboard`, `gamepad`, `midi`, `debug`, `cli`); each stack is a profile
file under `stacks/` containing two kinds of injection block:

- `[[variant]]` — exclusive. Exactly one is selected by a
  specificity-scored match against board and target metadata (board name,
  phy, NIC). This answers "which driver / phy shape does this board use?".
- `[[overlay]]` — additive. Every overlay whose match predicate holds is
  applied on top of the variant (debug netconsole, pcap sink, and similar
  optional layers).

A selected variant injects concrete modules, wiring, params, and services
into the config before the ordinary generation pipeline runs. The `net`
stack, for example, injects `virtio_net + ip` on qemu-virt,
`cyw43 + wifi + ip` on pico2w, and `rp1_gem + conn_guard + ip` on pi5 —
three different substrate stacks under one unchanged application graph.
Board defaults (e.g. `net → {phy: wifi, nic: cyw43}`) come from the target
descriptor, so most configs need only name the stack.

Module params inside a stack resolve through chained sources: `env:VAR`
(environment), `user:KEY` (merged user platform fields), `host:PATH`
(`~/.config/fluxor/host.toml`), or a literal. The first source that
resolves wins; a trailing `|required` turns "nothing resolved" into a
build-time error so safety-critical params cannot fall back silently.

Separately, a config's `hardware:` section declares pin-level board wiring
(`hardware.spi`, `hardware.i2c`, `hardware.gpio` entries), which
`tools/src/board.rs` validates against the target: bus existence, pin
ranges, reserved pins, and pin conflicts.

## Design Target: Capability Resolution

Status: design target, not wired.

The declared vocabulary is intended to eventually drive a generic
requires→provides resolver in the config tool, analogous to a package
manager resolving dependencies:

- A requirement names a capability; the resolver finds a provider chain
  through service modules down to the hardware substrate, auto-adding
  intermediate modules.
- Matching is by exact name or by prefix: a requirement of `net.frame`
  would match any `net.frame.*` provider, while the reverse would not hold
  (a `net.frame.wifi`-specific module cannot run on a generic frame
  provider).
- Unambiguous content-type matches (exactly one unconnected producer and
  one unconnected consumer of a type) would be auto-wired; ambiguity would
  be an error naming the candidates; explicit wiring would always win.
- Quantitative constraints would be expressed as capability facts (for
  example a `max_refresh_hz` fact on `display.scanout`, letting a motion
  consumer reject an e-paper panel at build time) rather than as name
  forks.

None of this resolver exists. Today, substrate stacks are injected by
platform stack expansion, application wiring is explicit, and the
vocabulary is enforced as validated names on manifests plus the
service / continuity / single-provider checks described above.

## Relationship to Other Documents

- `network.md` — the frame-provider vs transport-provider distinction the
  `net` stack variants implement; the `NetProto` TLV framing.
- `protocol_surfaces.md` — the four protocol surfaces, the five session
  continuity classes, and the anchor / worker / directory roles that the
  `transport.*` and `session.*` capabilities here support.
- `storage_capability_surface.md` — the storage surface family, the
  `Fence` axis, and multi-volume provider routing.
- `av_capability_surface.md` and `input_capability_surface.md` — the AV
  and input tiers of the capability registry.
- `mesh.md` — mesh events carry the same content-type identifiers as
  on-device channels, so intra-device ports and inter-device mesh bindings
  share one type vocabulary.
- `hal_architecture.md` — the kernel-level primitives (GPIO, SPI, PIO,
  I2C) behind the `requires_contract` names.
- `pipeline.md` — the runtime execution substrate. Stack expansion adds
  modules and wiring before the runner sees the graph; injected modules
  are indistinguishable from user-declared ones at runtime.

The machine-readable rename map for this vocabulary (old spelling to
canonical spelling) is generated into `contracts/vocabulary_map.toml`
from `contracts/src/vocabulary.rs` (`RENAME_MAP`); sibling projects
consume the generated file rather than hand-copying constant lists.
