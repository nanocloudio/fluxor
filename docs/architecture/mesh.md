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
| flags          | 18     | 2 B   | u16, reserved, must be 0; a token with any flag set is refused |
| not_before     | 20     | 4 B   | u32 seconds since epoch — earliest validity |
| not_after      | 24     | 4 B   | u32 seconds since epoch — expiry, the lease bound |
| issuer_key_id  | 28     | 4 B   | First 4 bytes of `SHA-256(issuer_pubkey)`, naming the key carried with the link (see below) |
| signature      | 32     | 64 B  | Ed25519 over the 16-byte domain tag `fluxor.mesh.cap\0` followed by bytes 0..32 |

The domain tag separates token signatures from every other signature a
key makes: a module's signing envelope is also 32 bytes, and without the
tag a signature over one would be a valid token. Bytes 0..32 are every
field but the signature, so no field steers a grant unsigned. A token is
a bearer assertion: whoever holds the bytes inside the window can present
them, which is why a session must be authenticated before it may present
one (see Presenting a capability).

### Delegation chains

A capability whose issuer is a delegated subkey rather than the root
travels with a *chain*. The chain is carried as `<u16 link_count BE>`
followed by that many 128-byte links, ordered leaf → … → root-signed.
Each link is a 96-byte token followed by the 32-byte Ed25519 public key
that signed it. A delegate's key cannot be looked up anywhere, which is
the point of a chain, so it travels with the link it signed, and the
link's `issuer_key_id` must name it.

For each delegation link (every link but the leaf):

- its `object_id` is the first 16 bytes of SHA-256 of the key that
  signed the link before it, binding the subkey it authorises;
- its `permissions` include `Delegate` and are a superset of the
  previous link's;
- its validity window contains the previous link's.

The last link's signer must be a root the verifier holds. Authority can
only narrow link by link, in rights and in time; no delegation ever
widens what the root granted in rights or time. Objects do not narrow: a
delegation names a key, not an object, so a delegate may grant its
permissions on any object, and a root that delegates to a key trusts that
key with every object. A chain holds at most `MAX_CHAIN_LINKS`
(8) links, so one presentation costs a verifier at most eight signature
checks.

The codec, the chain rules and the verifier are one source,
`modules/sdk/contracts/mesh/capability.rs`. It ships in the SDK source
artefact (`fluxor-abi`), so any PIC module or host tool links the same
bytes. It takes SHA-256 and Ed25519 verification from its caller
(`CapCrypto`), so the contract carries no crypto of its own. Golden
vectors in `capability_vectors.rs` beside it cover valid tokens and
chains and one vector per refusal class, and a consumer runs them to
prove it wired the verifier as the contract means.

### Security model

The mesh uses the same trust primitives as the rest of Fluxor: Ed25519
signatures, root public keys, and KEY_VAULT-resident private keys (see
[`security.md`](security.md)). There is no X.509, no certificate
authority, no name binding: capabilities are bearer assertions, not
certificates.

A verifier holds the deployment's mesh root public key, and during a
rotation its successor as well (`MAX_ROOTS`, 2). The root is a trust
anchor of the same kind as a TLS `trust` bundle: it is configuration the
deployment states, given to the verifying module as a parameter, and
covered by the composition the graph attests. It is not a KEY_VAULT slot.
The vault holds private keys, owned by the module that made them and
named by labels in that module's own namespace, so no slot is shared and
none is public. Every other signing key must be reachable from a root by
a verifiable chain.

On receipt of a chain, the receiver checks, entirely locally and before
any signature:

1. **Structure.** The link count is 1–8 and the bytes hold exactly that
   many links.
2. **Reserved bits.** `flags` is zero and no permission bit outside the
   six above is set. A caveat a verifier cannot name is refused, never
   ignored.
3. **Keys.** Every link's `issuer_key_id` names the key it carries, and
   the last link's key is a root.
4. **Chain coherence.** The key-binding, `Delegate`, permission-narrowing
   and window-narrowing rules above hold for every delegation.
5. **Validity window.** `not_before ≤ now − u` and `now + u ≤ not_after`
   for every link, where `now` and `u` are the `TRUSTED_UNIX`
   observation and its uncertainty. A reading the platform does not mark
   trusted, or one flagged as having gone backwards, is no clock, and the
   chain is refused rather than checked against a guess.
6. **Object and permission.** The leaf names the object the operation
   targets and carries every permission it needs.

Only then are the signatures verified, one per call
(`ChainCheck::step`), leaf first. A stream of forged chains therefore
costs a verifier no signature work, and a long chain fits a
microcontroller's step budget. Any failure refuses the operation with
one of sixteen named refusals. Leases are checked at admission:
in-flight commands complete under the lease they entered with, and a
holder is never expected to renew mid-operation.

Private keys are never exposed to module code. An operator's issuing
keys are seeds held as module-signing keys are. A module that delegates
at run time signs `Token::signed_bytes` with `KEY_VAULT::SIGN` on an Ed25519 slot it
owns.

### Issuing

Operators issue with the `fluxor` CLI, alongside module signing. A key
is the 32-byte Ed25519 seed `fluxor modules keygen` makes, and the public
key it prints is what a root's verifiers are configured with.

- `fluxor modules cap mint` grants permissions on an object.
- `fluxor modules cap delegate` authorises another key to grant within a
  narrower set.
- `fluxor modules cap verify` checks a chain for one operation.
- `fluxor modules cap inspect` prints a chain's links.

`mint` and `delegate` sign a new link and put it in front of the chain
that authorises the signing key, or start a chain when that key is the
root. Before signing, they refuse a link that does not narrow the link
that delegated to its key, so the CLI never issues a chain a verifier
would refuse on those grounds.

The CLI links the contract's own codec and chain rules and signs with
its own RFC 8032 Ed25519. Its verifier is as strict as a device's: it
refuses a scalar not below the group order, a non-canonical key or `R`,
and a small-order key or `R`. The golden vectors hold it to the
contract, and it reissues their root-signed links byte for byte. A chain
it issues is therefore what every verifier accepts. `verify` checks against the host's clock with no
uncertainty; a device decides against its own trusted clock.

### Presenting a capability

Mutual TLS (or QUIC) authenticates the channel; the capability
authorises the operation. A client presents a chain once per session
with `MSG_CAP_PRESENT` (`0xD0`). The server verifies it and answers
`MSG_CAP_ANSWER` (`0xD1`) with the grant or the refusal, and records the
grant against the session. Each later command names its object and is
admitted against the grants that session holds, at the time the command
arrives (`SessionGrants::authorise`). A session holds at most
`MAX_SESSION_GRANTS` (8) grants. A ninth presentation is refused until
one is withdrawn (`MSG_CAP_WITHDRAW`, `0xD2`), and nothing is evicted.
Grants die with the session.

A server refuses a presentation on a session whose `peer_identity` does
not bind an identity. A bearer token on an anonymous channel is a token
anyone who saw it can replay.

Request-scoped protocols carry the chain in the `fluxor-capability`
header as `fxcap1.` + unpadded base64url and verify it per request, or
cache it per connection. The frames use the TLV header the net contracts
share, in a range disjoint from all of them, so a protocol's own channel
can carry them beside its own frames.

Storage names the same permission bits. `StorageAccess` maps each storage
operation class to one bit (read → `ReadState`, write → `SendCommand`,
subscribe → `Subscribe`, delegate → `Delegate`), `StorageHandle::allows`
checks a handle's bits against it, and `lease_bound_ns` bounds a handle's
lease by its grant's expiry.

A module calling a store through `provider_call` has no session to present
on, so `storage.object` presents through an op of its own. `PRESENT` names
a scope (a key prefix such as `photos/`) and carries a chain whose leaf
names that scope's object. The store verifies the chain and answers a grant
handle, and every later op passes that grant as its handle. Each op is
admitted only inside the scope, with the bit its access class needs, while
the grant's window is open, and only for the module that presented it. The
Linux store enforces this whenever it is configured with roots (see
[presenting a grant to a store](storage_capability_surface.md#31-presenting-a-grant-to-a-store)).

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

The object registry is designed to run on constrained targets, within
these limits:

| Resource | Limit |
|----------|------|
| Objects per device | 16 |
| Handles per device | 32 |
| Graphs per object | 4 |
| Event inline data | 4096 bytes |
| Command inline data | 256 bytes |

## Transport

The mesh does not define its own fabric. Cross-node transport is carried
by remote channels (`modules/foundation/remote_channel/`), which
multiplex up to eight local channels over one authenticated session.

- **Records preserved.** Each channel declares a content type, a local
  record framing and a maximum record. Both ends exchange these tables
  when a session opens and refuse the session on any difference. A
  record up to the maximum is fragmented and reassembled whole before
  delivery. A record over it is refused and counted, never truncated.
- **Per-channel credit.** Every channel has its own credit, so a large
  or stalled record holds up only its own channel, and nothing is
  dropped under backpressure.
- **Authenticated transport.** The transport authenticates and the
  channel module does not. Remote channels ride the clear side of
  mutual TLS, with the session used only once a `peer_identity` record
  naming that session binds, or ride QUIC, where each channel is its own
  stream so one channel's loss recovery never blocks another's.

Mesh events and commands ride this fabric like every other cross-node
channel.

## Adoption Status

What the tree implements:

- the 128-bit `ObjectId` and the 32-byte event header, carrying the
  storage namespace change feed;
- the content-type registry shared with on-device channels;
- the capability token and chain codec, local verification against
  trusted time, the session presentation wire and per-session grants
  (`contracts/mesh/capability.rs`), with their golden vectors;
- issuance and checking in the `fluxor` CLI (`fluxor modules cap`);
- capability grants on `storage.object` (`PRESENT`): scope, permission
  and expiry enforced per op by the Linux store when it holds roots;
- the remote-channel fabric.

The object registry and the mesh bridge are not built. When built they
complete a single module of identity, event, command, handle, object
and mesh_bridge submodules over the capability contract above.
