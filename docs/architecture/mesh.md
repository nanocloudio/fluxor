# Fluxor Mesh Architecture

*It's a way to stop caring which computer something is on.*

This document is the normative reference for the Fluxor mesh surface:
the irreducible primitives, the wire formats they ride on, and how
they compose with the local pipeline runtime. Field tables and byte
layouts here are specification-grade; the prose explains intent.

## Overview

A mesh surface is a distributed object substrate where state, events, and commands are addressable without assuming where they run, and where locality is handled by placement rather than by interface.

A Pico 2 W running fluxor participates in the mesh as a first-class citizen.

```
+--------------- Pico Device -----------------+
|                                             |
|  +-------------+      +-------------+       |
|  |  Object A   |      |  Object B   |       |
|  |  (speaker)  |      |  (sensor)   |       |
|  |             |      |             |       |
|  | accepts:    |      | emits:      |       |
|  |  audio/pcm  |      |  app/cbor   |       |
|  |             |      |             |       |
|  | [pipeline]  |      | [pipeline]  |       |
|  |  v          |      |  v          |       |
|  | i2s sink    |      | spi source  |       |
|  +-------------+      +-------------+       |
|        ^                    v               |
|     Events IN          Events OUT           |
+--------+--------------------+---------------+
         |                    |
   ------+--------------------+----------
         |       MESH         |
```

## The 8 Irreducible Primitives

### 1. Object Identity

**What it is:** A stable, location-independent identifier for something that exists.

**Shape:** 128-bit opaque identifier. Compared bytewise, rendered as a canonical UUID string for diagnostics. Object identity is independent of the device hosting the object, the transport carrying its events, and any address it currently binds to. Two endpoints can compare object IDs without coordinating.

### 2. Authority as Capability

**What it is:** Unforgeable, transferable rights to observe or affect an object.

**Permission bits** (rendered as a 16-bit field):

| Bit | Permission   | Allows |
|-----|--------------|--------|
| 0   | ReadState    | Read object state snapshots |
| 1   | Subscribe    | Receive event streams from the object |
| 2   | SendCommand  | Issue commands to the object |
| 3   | Configure    | Change object parameters |
| 4   | Admin        | Manage object lifecycle |
| 5   | Delegate     | Hand off a subset of these rights to another holder |

**Capability composition (96 bytes, fixed layout):**

| Field          | Size  | Description |
|----------------|-------|-------------|
| object_id      | 16 B  | Object this grant applies to (full ObjectId, no truncation) |
| permissions    | 2 B   | Bitfield from the table above |
| flags          | 2 B   | Reserved — future use (delegation depth, contextual caveats) |
| not_before     | 4 B   | Earliest validity, seconds since epoch — anti-replay |
| not_after      | 4 B   | Expiry, seconds since epoch — lease bound |
| issuer_key_id  | 4 B   | First 4 bytes of `SHA-256(issuer_pubkey)` — resolves to a slot in the device trust store |
| signature      | 64 B  | Ed25519 over the preceding 32 bytes |

The capability is a self-contained signed assertion. Everything needed to verify it travels in the 96 bytes — there is no "go ask a server" step. Verification is described in §Security Model; the wire layout in §Capability Token matches this composition exactly.

### 3. Handle

**What it is:** A concrete reference combining identity, authority, and (optionally) where to find the object now.

**Composition:**

| Field      | Description |
|------------|-------------|
| object     | Object ID — who you're addressing |
| capability | Capability token — what you're permitted to do |
| hint       | Location hint — where to find it; an optimisation, never authoritative |

Handles are the only way to touch the mesh. Holding a handle conveys both reference and authority; no other interface bypasses this.

### 4. Object

**What it is:** The universal unit of meaning — something that may have state, events, and commands.

**Operations every Object exposes:**

- `id()` — return the Object ID
- `get_state(snapshot)` — produce a current state snapshot
- `emit_event(event)` — emit a typed event to subscribers
- `handle_command(cmd, capability)` — evaluate a command under the supplied capability and return a result

Objects collapse files, processes, services, and devices into one semantic unit. A speaker, a sensor, a file, a controller — all are Objects.

### 5. Event

**What it is:** Append-only, ordered facts — the only way change is represented over time.

**Composition:**

| Field         | Description |
|---------------|-------------|
| source        | Object ID of the emitter |
| sequence      | Monotonic counter, per source |
| timestamp_us  | Microsecond timestamp at the source |
| content_type  | MIME-style identifier naming the payload format |
| payload       | Opaque bytes interpreted per `content_type` |

Wire layout: see §Event Header below.

### 6. Deterministic State Derivation

**What it is:** State is always a projection of events.

Objects derive their state from their event history. On constrained targets the implementation is typically emit-and-forget — there is no local persistence — but the principle holds: state can always be reconstructed from events.

### 7. Execution (Agent)

**What it is:** A place where commands are evaluated and events are emitted.

A device acts as an agent when it responds to commands and interacts with other objects. Passive sensors that only emit events are not agents.

### 8. Time-boundedness (Lease)

**What it is:** All authority and resource claims are finite unless renewed.

Capabilities carry a `not_after` timestamp. Handles expire and must be renewed. Nothing in the mesh is held open indefinitely without an explicit lease.

## Content Types

Events carry typed data identified by MIME-like content types:

| ID | Type | Description |
|----|------|-------------|
| 0 | `application/octet-stream` | Raw bytes |
| 1 | `application/cbor` | Structured data |
| 2 | `application/json` | JSON (larger) |
| 3 | `audio/pcm` | PCM audio |
| 4 | `audio/opus` | Opus audio |
| ... | ... | ... |

The full registry lives alongside the kernel's `CONTENT_TYPES` table and is the same set used by typed channels — see [`capability_surface.md`](capability_surface.md#content-type-registry) for the canonical list.

## Pipeline Integration

Fluxor's existing pipeline system (Source -> Transformer -> Sink) integrates with mesh objects:

- **Pipelines are internal:** They process data within an object
- **Events cross boundaries:** Objects communicate via events

A **mesh bridge** is an Object that wraps one or more local pipelines: it surfaces pipeline output as outbound events, routes inbound commands into the pipeline as control input, and presents the pipeline's status as queryable state. The bridge is where the local execution model and the mesh surface meet — the pipeline contract is unchanged on one side, the Object contract is unchanged on the other.

### Example: Audio Player Object

```json
{
  "device_uuid": "11111111-1111-1111-1111-111111111111",
  "device_name": "pico-living-room",
  "sources": [
    {"type": "Playlist", "id": 0, "content_type": "AudioSample",
     "directory": "/audio", "mode": 2, "auto_start": true}
  ],
  "sinks": [
    {"type": "I2sOutput", "id": 0, "content_type": "AudioSample",
     "data_pin": 9, "clock_pin_base": 10, "bits": 16, "sample_rate": 44100}
  ],
  "pipelines": [
    {"source_id": 0, "sink_id": 0, "transformers": [], "enabled": true}
  ],
  "objects": [
    {
      "uuid": "550e8400-e29b-41d4-a716-446655440000",
      "name": "speaker",
      "accepts": [{"content_type": "AudioSample", "pipeline_id": 0}],
      "emits": [{"content_type": "MeshState", "pipeline_id": 0}],
      "enabled": true
    }
  ]
}
```

### Example: Sensor Object

```json
{
  "device_name": "pico-radar",
  "sources": [
    {"type": "SpiRead", "id": 0, "content_type": "OctetStream",
     "spi_id": 0, "cs_pin": 17}
  ],
  "sinks": [
    {"type": "MqttPublish", "id": 0, "content_type": "OctetStream",
     "topic": "sensors/radar/frames", "qos": 0}
  ],
  "pipelines": [
    {"source_id": 0, "sink_id": 0, "transformers": [], "enabled": true}
  ],
  "objects": [
    {
      "uuid": "660e8400-e29b-41d4-a716-446655440001",
      "name": "radar-sensor",
      "emits": [{"content_type": "OctetStream", "pipeline_id": 0}],
      "accepts": [],
      "enabled": true
    }
  ]
}
```

## Wire Format

### Event Header (32 bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                      Source ObjectId                          |
|                        (16 bytes)                             |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Sequence                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                      Timestamp (us)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| ContentType |    Flags    |            Length                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Payload...                            |
```

### Command Payload (12 bytes + args)

Commands are transported as Events with `content_type: MeshCommand`. The payload uses this format:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Request ID                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Action             |    Flags    |    Reserved     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Args Length                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Args (CBOR)...                          |
```

| Field | Size | Description |
|-------|------|-------------|
| Request ID | 4 bytes | Correlation ID for response (0 = no response expected) |
| Action | 2 bytes | Operation code (see `action::` namespace) |
| Flags | 1 byte | `ResponseRequired`, `HighPriority`, `Idempotent`, `Encrypted` |
| Args Length | 4 bytes | Length of arguments data |
| Args | variable | CBOR-encoded arguments |

**Routing:** The target object is determined by the transport layer (MQTT topic, Handle routing), not embedded in the command payload. The Event header's `source` field identifies who sent the command.

### Response Payload (8 bytes + data)

Responses to commands use Events with `content_type: MeshState` or a dedicated response topic:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Request ID                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Result     |    Flags    |          Data Length            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Data (CBOR)...                          |
```

| Result Code | Value | Description |
|-------------|-------|-------------|
| Ok | 0 | Success |
| Accepted | 1 | Processing asynchronously |
| Error | 2 | Generic error |
| NotFound | 3 | Target object not found |
| NotSupported | 4 | Action not supported |
| Unauthorized | 5 | Insufficient capability |
| InvalidArgs | 6 | Arguments invalid |
| Timeout | 7 | Operation timed out |
| Busy | 8 | Resource busy, retry later |

### Standard Action Codes

| Range | Purpose |
|-------|---------|
| 0x0000-0x00FF | Mesh core (Ping, GetState, Subscribe, Configure, Start, Stop) |
| 0x0100-0x01FF | Audio (Play, Pause, Next, Previous, SetVolume) |
| 0x0200-0x02FF | GPIO (SetPin, GetPin, TogglePin) |
| 0x1000+ | Application-specific |

### Capability Token (96 bytes)

The on-wire capability is byte-for-byte equal to the composition in
§2. All fields are big-endian. Verification rules are in §Security
Model.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                      Object ID                                |
|                       (16 bytes)                              |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Permissions         |            Flags               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Not Before                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Not After                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Issuer Key ID                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                                                               |
|                       Signature                               |
|                       (64 bytes)                              |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field          | Offset | Size  | Type / encoding |
|----------------|--------|-------|-----------------|
| object_id      | 0      | 16 B  | Opaque bytes |
| permissions    | 16     | 2 B   | u16, bitfield |
| flags          | 18     | 2 B   | u16, reserved (must be 0) |
| not_before     | 20     | 4 B   | u32 seconds since epoch |
| not_after      | 24     | 4 B   | u32 seconds since epoch |
| issuer_key_id  | 28     | 4 B   | First 4 bytes of `SHA-256(issuer_pubkey)` |
| signature      | 32     | 64 B  | Ed25519 over bytes 0..32 |

A *capability chain* — used to verify a token whose issuer is a
delegated subkey rather than the root — is a contiguous sequence of
these 96-byte records ordered leaf → … → root-signed. Each record's
`object_id` for non-leaf links is the SHA-256 of the next link's
signing key; each record's `permissions` for non-leaf links must
include the `Delegate` bit and must be a superset of the next link's
permissions. The transport carries `<u16 chain_len><96 B record>×N`.

## Security Model

The mesh uses the same trust primitives as the rest of Fluxor:
Ed25519 signatures, root public keys, and KEY_VAULT-resident key
material. There is no X.509, no certificate authority, no name
binding — capabilities are bearer assertions, not certificates.

### Trust root

Each device carries a root Ed25519 public key in KEY_VAULT (slot 0
by convention). The root key is established at provisioning and is
the only key whose authority is assumed; every other signing key
must be reachable from it by a verifiable chain.

### Per-command verification

On receipt of a command bearing a capability (token + optional
chain), the receiver executes the following checks. Every check is
local — no remote lookup is consulted.

1. **Structural decode.** Confirm the token is 96 bytes and any
   accompanying chain is well-formed (`<u16 chain_len><96 B>×N`).
2. **Signature.** Verify `signature` against the issuer public key
   identified by `issuer_key_id`. The issuer key must resolve to
   either the local KEY_VAULT root or the leaf-key of an attached
   chain whose head verifies to the root under the same rules.
3. **Chain coherence** (when a chain is present). For each
   non-leaf link L and its child C: L's `permissions` must include
   `Delegate`; C's `permissions` must be a subset of L's; L's
   `object_id` must equal `SHA-256(issuer_pubkey_of(C))` (i.e. L
   binds the subkey that signs C); the lease window of every link
   must contain `now`.
4. **Validity window.** Check `not_before ≤ now ≤ not_after` on the
   capability itself.
5. **Permission match.** Check that the operation being attempted
   is permitted by the bitfield.

Any failure aborts the command. A holder is never expected to renew
a capability mid-operation — leases are checked once at admission;
in-flight commands continue under the lease they entered with.

### Key custody

Issuer private keys never leave KEY_VAULT. A holder that exercises
`Delegate` does so via a KEY_VAULT signing primitive that takes the
delegated capability bytes as input and emits the signature — the
private key bytes are not exposed to module code. This is the same
discipline used by every other Fluxor consumer of KEY_VAULT
(see `security.md`).

## Memory Considerations

The mesh implementation is designed for embedded systems:

| Resource | Limit |
|----------|-------|
| Objects per device | 16 |
| Handles per device | 32 |
| Pipelines per object | 4 |
| Event inline data | 4096 bytes |
| Command inline data | 256 bytes |

## Design Decisions

This section documents key architectural decisions that define the mesh surface.

### Device vs Object Identity

**Decision:** Device identity and object identity are separate concepts.

```
Device: Physical hardware identity
+-- device_uuid: identifies the physical Pico (or other MCU)
+-- device_name: human-readable hardware name ("pico-living-room")

Objects: Logical capabilities hosted on the device
+-- object.uuid: identifies a logical service/capability
+-- object.name: human-readable service name ("speaker", "motion-sensor")
```

**Rationale:** A single device can host multiple logical objects. A Pico running fluxor might expose:
- A speaker object (accepts audio/pcm)
- A button object (emits mesh events)
- A temperature sensor object (emits sensor readings)

Each object has its own identity for addressing and capability management. Device identity answers "where is the code running?" while object identity answers "what capability am I talking to?"

**In config:** `device_uuid`/`device_name` are in the header. `objects[]` is a separate array of logical objects with their own UUIDs.

### Event (Primitive) vs Content Types (MeshEvent, MeshCommand)

**Decision:** `Event` is the transport envelope. `MeshEvent`, `MeshCommand`, etc. are content types describing the payload format.

```
+---------------------------------------------+
| Event (32-byte header + payload)            |  <- Transport primitive
| +-- source: ObjectId                        |
| +-- sequence: uint32                        |
| +-- timestamp: uint64                       |
| +-- content_type: MeshCommand  -------------|--+
| +-- payload: [command data]                 |  |
+---------------------------------------------+  |
                                                 |
    ContentTypeId describes payload format <------+
```

**Rationale:** Events are the universal transport mechanism. The `content_type` field describes how to interpret the payload bytes. `MeshCommand` means "this payload is a command to be executed." `MeshEvent` means "this payload is a mesh-native event notification."

This separation allows:
- Audio data to flow as Events with `content_type: AudioSample`
- Commands to flow as Events with `content_type: MeshCommand`
- Same transport, different semantics

### Content Bindings Map to Pipelines

**Decision:** Object emit/accept bindings pair a content type with a pipeline id.

| Field        | Description |
|--------------|-------------|
| content_type | What kind of data this binding carries |
| pipeline_id  | Which local pipeline produces or consumes it |

**Rationale:** This bridges the mesh abstraction to fluxor's hardware pipeline system. When an object "accepts audio/pcm", it means:
1. Incoming Events with `content_type: AudioSample` are valid
2. The data is routed to `pipeline_id` for processing
3. That pipeline connects to hardware (I2S sink, etc.)

This keeps objects declarative while pipelines handle the hardware details.

## Module Layout

The mesh module lives at `modules/foundation/mesh/`. Shared wire
types and primitive structs are currently consolidated in
`modules/foundation/mesh/mesh_types.rs` alongside `mod.rs`. As the
surface grows, the file will split along the lines below.

**Planned decomposition** (a single planned split, not separate
crates):

| Submodule       | Purpose |
|-----------------|---------|
| `identity`      | Object ID generation, parsing, and canonical string form |
| `content_type`  | Content-type registry shared with the kernel `CONTENT_TYPES` table |
| `event`         | Event structure and 32-byte header codec |
| `command`       | Command and response payload formats, action-code registry |
| `capability`    | Permission flags, capability token codec, chain verification against KEY_VAULT root |
| `handle`        | Handle composition, location hints, holder-side registry |
| `object`        | Object trait, local object registry, dispatch |
| `mesh_bridge`   | Object surfacing of local pipelines (events out, commands in) |
