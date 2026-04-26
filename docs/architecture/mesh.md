# Fluxor Mesh Architecture

*It's a way to stop caring which computer something is on.*

> **Note:** This document describes the mesh architecture model. The implementation
> is in Rust, not C++. Code examples are pseudocode illustrating the concepts.
> See the source code in `src/` for implementation details.

Fluxor is a mesh-native firmware framework for embedded systems. This document describes the mesh primitives and how they integrate with the fluxor pipeline system.

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

**Implementation:** `ObjectId` - 128-bit UUID stored in `identity.hpp`

```cpp
struct ObjectId {
    uint8_t bytes[16];

    bool is_null() const;
    bool operator==(const ObjectId& other) const;
    int to_string(char* buffer, size_t capacity) const;
    static bool from_string(const char* str, ObjectId& out);
};
```

### 2. Authority as Capability

**What it is:** Unforgeable, transferable rights to observe or affect an object.

**Implementation:** `Permission` flags and `Capability` struct in `capability.hpp`

```cpp
enum class Permission : uint16_t {
    ReadState   = 1 << 0,
    Subscribe   = 1 << 1,
    SendCommand = 1 << 2,
    Configure   = 1 << 3,
    Admin       = 1 << 4,
    Delegate    = 1 << 5,
    // ...
};

struct Capability {
    ObjectId object_id;
    Permission permissions;
    uint32_t not_after;     // Lease expiry
    uint8_t signature[64];  // Ed25519 signature
};
```

Capabilities are validated against a CA certificate stored in device flash.

### 3. Handle

**What it is:** A concrete thing you hold that combines object identity, capability, and optional location hints.

**Implementation:** `Handle` struct in `handle.hpp`

```cpp
struct Handle {
    ObjectId object;            // Who you're talking to
    CapabilityToken capability; // What you can do
    LocationHint hint;          // Where to find it
};
```

Handles are the only way to touch the mesh. They encapsulate both reference and authority.

### 4. Object

**What it is:** The universal unit of meaning - something that may have state, events, and commands.

**Implementation:** `Object` interface in `object.hpp`

```cpp
class Object {
public:
    virtual const ObjectId& id() const = 0;
    virtual bool get_state(StateSnapshot& state) const = 0;
    virtual bool emit_event(const Event& event) = 0;
    virtual CommandResult handle_command(const Command& cmd,
                                         const Capability& auth) = 0;
};
```

Objects collapse files, processes, services, and devices into one semantic unit.

### 5. Event

**What it is:** Append-only, ordered facts - the only way change is represented over time.

**Implementation:** `Event` struct in `event.hpp`

```cpp
struct Event {
    ObjectId source;        // Who emitted this
    uint32_t sequence;      // Monotonic per-source
    uint64_t timestamp_us;  // When
    ContentTypeId content_type;  // What kind
    uint8_t* data;
    uint16_t length;
};
```

Events have a content type (MIME-like) that describes how to interpret the payload.

### 6. Deterministic State Derivation

**What it is:** State is always a projection of events.

**Implementation:** Objects derive their state from their event history. On embedded, we typically emit-and-forget (no local persistence), but the principle holds: state can always be reconstructed from events.

### 7. Execution (Agent)

**What it is:** A place where commands are evaluated and events are emitted.

**Implementation:** The device itself is an agent when it responds to commands and interacts with other objects. Passive sensors that only emit events are not agents.

### 8. Time-boundedness (Lease)

**What it is:** All authority and resource claims are finite unless renewed.

**Implementation:** Capabilities have `not_after` timestamps. Handles expire and must be renewed.

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

See `content_type.hpp` for the full list.

## Pipeline Integration

Fluxor's existing pipeline system (Source -> Transformer -> Sink) integrates with mesh objects:

- **Pipelines are internal:** They process data within an object
- **Events cross boundaries:** Objects communicate via events

`MeshBridge` bridges the two:

```cpp
class MeshBridge : public Object {
    // Wraps pipelines
    // Converts pipeline output to events
    // Injects commands into pipelines
};
```

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

### Capability Token (20 bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Object Hash                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Permissions         |          Not Before             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Not After          |        Issuer Hash              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Issuer Hash (cont)       |         Signature               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Signature (cont)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Security Model

All operations are authorized by capabilities validated against a CA:

1. Device has its keypair + CA certificate in flash
2. Handles contain capability tokens
3. On command receipt:
   - Check capability signature chains to CA
   - Verify `not_after` hasn't passed
   - Verify required permissions are granted
   - Execute if valid

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

**Decision:** Object emit/accept bindings specify `{content_type, pipeline_id}`.

```cpp
struct ContentBinding {
    ContentTypeId content_type;  // What kind of data
    uint8_t pipeline_id;         // Which pipeline handles it
};
```

**Rationale:** This bridges the mesh abstraction to fluxor's hardware pipeline system. When an object "accepts audio/pcm", it means:
1. Incoming Events with `content_type: AudioSample` are valid
2. The data is routed to `pipeline_id` for processing
3. That pipeline connects to hardware (I2S sink, etc.)

This keeps objects declarative while pipelines handle the hardware details.

## Conceptual Module Structure

The mesh implementation would be organized as:

| Module | Purpose |
|--------|---------|
| `identity` | ObjectId generation and parsing |
| `content_type` | ContentType registry and MIME mappings |
| `event` | Event structure with 32-byte header |
| `command` | CommandPayload, ResponsePayload, action codes |
| `capability` | Permission flags, Capability tokens |
| `handle` | Handle, LocationHint, HandleRegistry |
| `object` | Object trait, ObjectRegistry |
| `mesh_bridge` | Bridge between mesh objects and pipelines |
