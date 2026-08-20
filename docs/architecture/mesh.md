# Mesh Architecture

The mesh is Fluxor's model for systems that span more than one
device: a distributed object substrate in which state, events, and
commands are addressable without assuming where they run. Locality is
handled by placement, not by interface — moving an object between
devices changes routing, never the code that talks to it.

The shift it makes is the same one the rest of Fluxor makes locally,
extended across the network: the unit of architecture is not the
device but the capability-bearing object. A Pico on a shelf is not
"a device with an API"; it is a host for a speaker object, a button
object, and a temperature object, each independently addressable,
each governed by its own authority. Every participant, down to the
smallest microcontroller, is a first-class citizen of the same
substrate.

The architecture rests on eight primitives. Everything else in this
document is their elaboration; a closing note records how far the
runtime has adopted them.

## The Eight Primitives

**1. Object identity.** A stable, location-independent identifier
for something that exists. Identity is independent of the device
hosting the object, the transport carrying its events, and any
address it currently binds to. Two endpoints can compare object
identities without coordinating.

**2. Authority as capability.** Unforgeable, transferable,
time-bounded rights to observe or affect an object. Authority is a
thing you hold and present, not a row in someone else's access list.

**3. Handle.** A concrete reference combining identity, authority,
and optionally a hint about where the object is now. Handles are the
only way to touch the mesh: holding one conveys both reference and
permission, and no other interface bypasses that.

**4. Object.** The universal unit of meaning — something that may
have state, events, and commands. Objects collapse files, processes,
services, and devices into one semantic unit: a speaker, a sensor, a
file, and a controller are all objects.

**5. Event.** Append-only, ordered facts; the only way change is
represented over time.

**6. Deterministic state derivation.** State is a projection of
events. On constrained targets the implementation is typically
emit-and-forget, with no local persistence, but the principle holds:
state can always be reconstructed from the event history.

**7. Execution (agent).** A place where commands are evaluated and
events are emitted. A passive sensor that only emits events is not an
agent; anything that responds to commands is.

**8. Time-boundedness (lease).** All authority and resource claims
are finite unless renewed. Capabilities expire, handles expire,
nothing is held open indefinitely without an explicit lease.

## Identity

An `ObjectId` is a 128-bit opaque identifier, compared bytewise and
rendered as a canonical UUID string for diagnostics. It names a
logical object, never a piece of hardware.

Device identity and object identity are deliberately separate
concepts. A device — one board, one uuid, one human-readable name —
hosts multiple logical objects, each with its own identity. Device
identity answers "where is the code running"; object identity
answers "what capability am I talking to". Addressing and authority
always target object identity, which is what lets an object relocate
between devices without invalidating the handles held against it.

## Events

Events travel with a fixed 32-byte header followed by the payload.
Multi-byte fields are little-endian.

| Offset | Field | Type |
|--------|-------|------|
| 0 | `source` | `[u8; 16]` — ObjectId of the emitter |
| 16 | `sequence` | `u32` — monotonic per source |
| 20 | `timestamp_us` | `u64` — microseconds at the source |
| 28 | `content_type` | `u8` — index into the content-type registry |
| 29 | `flags` | `u8` |
| 30 | `length` | `u16` — payload byte count |
| 32 | payload | `length` bytes |

The event is the universal transport envelope; the `content_type`
byte says how to interpret the payload. Audio flows as events
carrying `AudioSample`, structured data as `Cbor`, commands as
events carrying `MeshCommand`, state notifications as `MeshState` —
same transport, different semantics. The per-source monotone
`sequence` gives every consumer a total order per emitter without
global coordination.

Content types come from the same one-byte registry that types
on-device channels (`MeshEvent`, `MeshCommand`, `MeshState`, and
`MeshHandle` are the mesh-specific entries); the canonical list and
its admission rules are in
[`capability_surface.md`](capability_surface.md#content-type-registry).
An intra-device port and a cross-device event binding therefore agree
about payload meaning by construction.

## Authority

Authority over an object is rendered as a 16-bit permission field:

| Bit | Permission   | Allows |
|-----|--------------|--------|
| 0   | ReadState    | Read object state snapshots |
| 1   | Subscribe    | Receive event streams from the object |
| 2   | SendCommand  | Issue commands to the object |
| 3   | Configure    | Change object parameters |
| 4   | Admin        | Manage object lifecycle |
| 5   | Delegate     | Hand off a subset of these rights to another holder |

### The capability token

A capability is a self-contained signed assertion of authority:
96 bytes carrying everything needed to verify it, with no
"go ask a server" step. Fields are big-endian on the wire.

| Field          | Offset | Size  | Encoding |
|----------------|--------|-------|----------|
| object_id      | 0      | 16 B  | The object this grant applies to (full ObjectId, no truncation) |
| permissions    | 16     | 2 B   | u16 bitfield from the table above |
| flags          | 18     | 2 B   | u16, reserved, must be 0 (future: delegation depth, contextual caveats) |
| not_before     | 20     | 4 B   | u32 seconds since epoch — earliest validity, anti-replay |
| not_after      | 24     | 4 B   | u32 seconds since epoch — expiry, the lease bound |
| issuer_key_id  | 28     | 4 B   | First 4 bytes of `SHA-256(issuer_pubkey)`, resolving to a slot in the device trust store |
| signature      | 32     | 64 B  | Ed25519 over bytes 0..32 |

### Delegation chains

A capability whose issuer is a delegated subkey rather than the root
travels with a *chain*: a contiguous sequence of the same 96-byte
records, ordered leaf → … → root-signed, carried as
`<u16 chain_len><96 B record>×N`. For each non-leaf link, its
`object_id` is the SHA-256 of the next link's signing key (binding
the subkey it authorises), its `permissions` must include `Delegate`
and be a superset of the next link's, and its validity window must
contain `now`. Authority can only narrow link by link; no delegation
ever widens what the root granted.

### Security model

The mesh uses the same trust primitives as the rest of Fluxor:
Ed25519 signatures, root public keys, and KEY_VAULT-resident key
material (see [`security.md`](security.md)). There is no X.509, no
certificate authority, no name binding — capabilities are bearer
assertions, not certificates.

Each device carries a root Ed25519 public key in KEY_VAULT (slot 0
by convention), established at provisioning. It is the only key
whose authority is assumed; every other signing key must be
reachable from it by a verifiable chain.

On receipt of a command bearing a capability, the receiver checks,
entirely locally:

1. **Structural decode** — the token is 96 bytes and any chain is
   well-formed.
2. **Signature** — verified against the issuer key, which must
   resolve to the local root or to the leaf of an attached chain
   whose head verifies to the root.
3. **Chain coherence** — the narrowing, key-binding, and lease rules
   above hold for every link.
4. **Validity window** — `not_before ≤ now ≤ not_after`.
5. **Permission match** — the attempted operation is allowed by the
   bitfield.

Any failure aborts the command. Leases are checked once at
admission: in-flight commands complete under the lease they entered
with, and a holder is never expected to renew mid-operation.

Issuer private keys never leave KEY_VAULT. A holder exercising
`Delegate` does so through a KEY_VAULT signing primitive that takes
the delegated capability bytes and emits the signature; private key
bytes are never exposed to module code.

## Handles

A handle combines the three things needed to use an object:

| Field      | Role |
|------------|------|
| object     | ObjectId — who you are addressing |
| capability | Capability token — what you are permitted to do |
| hint       | Location hint — where to find it now; an optimisation, never authoritative |

The hint is the load-bearing subtlety: because it is advisory, an
object can move and a stale hint costs a lookup, not a broken
reference. Identity and authority stay valid across relocation.

## Commands and Responses

Commands travel as events with `content_type: MeshCommand`. The
target object is determined by handle routing at the transport
layer, not embedded in the payload; the event header's `source`
identifies the sender.

Command payload (12 bytes + arguments):

| Field | Size | Description |
|-------|------|-------------|
| request_id | 4 B | Correlation id for the response (0 = no response expected) |
| action | 2 B | Operation code (ranges below) |
| flags | 1 B | `ResponseRequired`, `HighPriority`, `Idempotent`, `Encrypted` |
| reserved | 1 B | Must be 0 |
| args_length | 4 B | Length of the argument data |
| args | variable | CBOR-encoded arguments |

Responses travel as events with `content_type: MeshState` (8 bytes +
data): `request_id` (4 B), `result` (1 B), `flags` (1 B),
`data_length` (2 B), then CBOR data. Result codes: Ok (0), Accepted
(1, processing asynchronously), Error (2), NotFound (3),
NotSupported (4), Unauthorized (5), InvalidArgs (6), Timeout (7),
Busy (8).

Action codes are namespaced by range: 0x0000–0x00FF mesh core (Ping,
GetState, Subscribe, Configure, Start, Stop); 0x0100–0x01FF audio
(Play, Pause, Next, Previous, SetVolume); 0x0200–0x02FF GPIO
(SetPin, GetPin, TogglePin); 0x1000 and above application-specific.

## Objects, the Registry, and the Bridge

Every object exposes the same four operations: `id()` returns its
ObjectId; `get_state(snapshot)` produces a current state snapshot;
`emit_event(event)` emits a typed event to subscribers; and
`handle_command(cmd, capability)` evaluates a command under the
presented capability and returns a result. A per-device object
registry owns dispatch from inbound events to the objects it hosts.

The **mesh bridge** is where the substrate meets Fluxor's local
execution model. A bridge is an object wrapping one or more local
processing graphs: it surfaces graph output as outbound events,
routes inbound commands in as control input, and presents graph
status as queryable state. The graph contract is unchanged on one
side, the object contract on the other. An object's emit/accept
bindings each pair a content type with the local graph that produces
or consumes it: "accepts `AudioSample`" means incoming events of
that type are valid and flow into the bound graph, which connects to
the hardware. Objects stay declarative; graphs handle the hardware.

## Embedded Memory Budgets

The substrate is sized to run on constrained targets:

| Resource | Limit |
|----------|------|
| Objects per device | 16 |
| Handles per device | 32 |
| Graphs per object | 4 |
| Event inline data | 4096 bytes |
| Command inline data | 256 bytes |

## Transport

The mesh does not define its own fabric. Cross-node transport is
carried by remote channels (`modules/foundation/remote_channel/`),
which multiplex logical channels over one byte transport; mesh
events and commands ride the same fabric as every other cross-node
channel.

## Adoption Status

The runtime adopts the mesh incrementally. In the tree today: the
128-bit `ObjectId` and the 32-byte event header are implemented and
carry the storage namespace change feed; the content-type registry
is shared with on-device channels; and the storage contract's
handles realise the handle/permission/lease shape with a narrower
permission set (Read / Write / Subscribe / Delegate) and monotonic
nanosecond lease bounds. The substrate proper — the capability token
codec, chain verification, the object registry, and the bridge — is
a design target, not yet wired; when built it decomposes into
identity, content_type, event, command, capability, handle, object,
and mesh_bridge submodules of a single module.
