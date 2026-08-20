# Storage Capability Surface

Fluxor's storage architecture rests on three layered concepts:

1. a **surface family** — four canonical surfaces the graph carries:
   `storage.block`, `file.data`, `storage.namespace`, `storage.object`;
2. a **per-op fence advertisement** — `abi::fence::Fence`, the orthogonal
   axis that lets two providers share a surface name while differing
   honestly in durability and ordering;
3. a **leased mesh-Handle contract** — every opened namespace, object, or
   stream is a `StorageHandle` carrying `not_after` and revocation
   semantics, built on the mesh `Handle` (mesh primitive #3) and `Lease`
   (mesh primitive #8).

This document is the storage peer of `av_capability_surface.md` (AV),
`input_capability_surface.md` (input), `endpoint_capability_surface.md`
(external hosts), and `protocol_surfaces.md` (net).

---

## 1. Canonical surface family

Source: `modules/sdk/contracts/storage/`, `contracts/src/vocabulary.rs`.

Storage pipelines move data on channels typed by `content_type` and
exchange leased handles through the mesh Handle primitive. Four surfaces
compose the family; every provider declares one or more.

| Surface             | Domain                                                          | Providers / consumers                                        |
|---------------------|-----------------------------------------------------------------|--------------------------------------------------------------|
| `storage.block`     | Raw block I/O                                                   | sd, nvme, flash_rp provide; fat32 consumes                   |
| `file.data`         | Byte-stream file access (open, read, seek, stat, write, fsync)  | fat32 and the mount router provide; player / viewer modules consume |
| `storage.namespace` | Name-keyed directory surface (lookup, stat, list, rename, delete, bind, subscribe) | host platform providers (§5); scanners and stores consume |
| `storage.object`    | Whole-blob byte-addressed surface (put, get, head, range_get, delete) | host platform providers (§5); object_bank consumes     |

Multipart object upload is deliberately not part of `storage.object`.
Large writes compose via the `event.log` pattern in §4 and finalise with
the four-opcode streamed sequence (`PUT_STREAMED_OPEN` / `_WRITE` /
`_COMMIT` / `_ABORT`). Object-store adapters can synthesise
provider-specific multipart uploads on top of this surface; the surface
itself stays narrow so substitutability holds.

Append-log behaviour is deliberately not a new surface: it is an
Event-stream content-type pattern over the mesh Event primitive (§4).

Page-backing for arenas is deliberately not a public surface: it is an
internal cache concern of `storage.block` / `file.data` providers (see
`modules/sdk/contracts/storage/paged_arena.rs`).

### Where this is enforced

- `provides` in `manifest.toml` is validated against the provider
  vocabulary in `contracts/src/vocabulary.rs` (`PROVIDER_CONTRACTS` plus
  `PROVIDER_SURFACES`); an unknown name fails manifest parsing.
  Consumers reach a provider through `[[resources]].requires_contract`
  (by contract, substitutable) or by naming the provider's ports directly
  in graph YAML (by name, not substitutable — prefer the former, and
  route multi-volume graphs through `mount`).
- The four surfaces appear in `capability_surface.md`'s canonical
  taxonomy.
- The opcode constants live in `modules/sdk/contracts/storage/`
  (`fs.rs`, `namespace.rs`, `object.rs`, plus the kernel-private
  `graph_slot.rs`, `paged_arena.rs`, `runtime_params.rs`).

### Declared providers and consumers

Loadable modules carrying `provides = [...]` in their `manifest.toml`:

| Surface             | Declared by (`provides`)                            |
|---------------------|-----------------------------------------------------|
| `storage.block`     | `foundation/sd`, `drivers/nvme`, `drivers/flash_rp` |
| `file.data`         | `foundation/fat32`, `foundation/mount`              |
| `storage.namespace` | no loadable module                                  |
| `storage.object`    | no loadable module                                  |

The hosts carry no `provides` rows: on Linux and wasm these surfaces are
served by platform dispatchers inside the runtime (§5) rather than by
modules with manifests, so they register directly and never advertise a
surface.

Consumers by contract (substitutable): `foundation/fs_bank` and
`foundation/fs_tap` name `requires_contract = "fs"`;
`foundation/object_bank` names `requires_contract = "storage.namespace"`
and `"storage.object"`.

### Multiple volumes: instance-keyed providers + the `mount` module

Source: `tools/src/config/validate.rs` (`validate_single_provider`),
`src/kernel/module/syscalls.rs`, `modules/foundation/mount/mod.rs`.

Contract providers are auto-registered by the loader after each module
reaches Ready, in module-index order. The class-byte dispatch path
(`handle == -1`, e.g. `FS_OPEN`) routes to the top-most **unkeyed**
(selector 0) provider layer. A second unkeyed provider of the same
surface would shadow the first silently, leaving its drive unreachable,
so `validate_single_provider` rejects two unkeyed providers of one
surface at build time, naming both.

Two volumes coexist by declaring distinct **instance selectors**. A
provider module (a `fat32`) sets a `volume:` param; it exports
`module_provider_selector`, and the loader registers it as an
instance-keyed layer rather than the default. The kernel exposes one
syscall for reaching a keyed layer:

- `provider_call_sel(sel, sel_len, op_handle, op, …)` hashes the selector
  name, finds the layer carrying it, and dispatches, with the contract
  taken from the opcode's class byte exactly as the `handle == -1` path
  does. The caller names the target volume inline on every op; there is
  no bound token to cache. Resolving by selector per call is what keeps
  it sound under live graph mutation: a freed-then-reused module index
  cannot alias a stale binding.

The **`mount` module** (`modules/foundation/mount/`) is the policy layer.
It registers as the default (unkeyed) FS provider and carries a
`mounts: "/boot=sd0;/data=nvme0"` table. On `FS_OPEN(path)` it
longest-prefix-matches the path to a volume, forwards the prefix-stripped
path to that volume via `provider_call_sel`, and remaps the returned
handle so later handle-bound ops (`FS_READ` / `FS_CLOSE` / …) route back
to the owning volume. Path policy stays in the module; the kernel never
parses paths. `validate_single_provider` therefore allows several
providers of one surface as long as each `volume:` selector is distinct
(two same-volume or two unkeyed providers still error), and separately
rejects a graph in which every provider of a surface is keyed with no
default router to reach them.

A contract may additionally opt out of single-provider validation via
the chain-aware allowlist (`CHAIN_AWARE_PROVIDES` in
`tools/src/config/validate.rs`): a contract on that list tolerates
multiple providers in one graph because its callers fan through the
providers via the `CHAIN_NEXT` flag rather than letting the last
registration win. Nothing declares chain-awareness today, so the list is
empty and every duplicate provider is an error.

Multi-volume routing covers the `fs` contract (`file.data`) only: the
`mount` module routes `fs` opcodes, and nothing routes
`storage.namespace` or `storage.object` opcodes across volumes.

**Hotplug / removable media.** The `mount` module carries an optional
control channel (`ctl`, in[0]) mirroring the IP `addr_ctl` port: the
platform backend that detects an insert or remove writes one command per
record (`[cmd][prefix_len][prefix][volume_len][volume]`), and
`module_step` drains and applies them. A remove revokes every open handle
on that volume: the next op fails `ENODEV` and frees the slot, the
storage handle lease / revocation contract enforced at the handle
authority (this module, which owns every consumer-facing FS handle). An
add installs a mount whose backend binds lazily on first use. Media
detection is platform-specific and outside the module's scope; the module
only consumes the control messages.

### Where instance-keying applies — and where it does not

Instance-keying (`provider_call_sel` plus a policy router like `mount`)
is for logical, contract-dispatched service surfaces: the storage
surfaces (`file.data`, and, when routed, `storage.namespace` /
`storage.object`), tenant-scoped stores, and similar. It is deliberately
not applied to physical hardware channels:

- Block devices (`storage.block` on sd / nvme / flash_rp) and NIC frames
  are `OctetStream` / `EthernetFrame` channels wired by name, not
  provider-call dispatch. A physical device's identity is its graph
  position ("the NVMe on `m2_primary`", "the NIC at this slot"); there is
  no logical abstraction to route the way a mount prefix routes to a
  volume.
- The multi-instance cases people reach for — WAL + data volumes,
  multiple NVMe namespaces, multiple NICs — are handled at the logical
  layer: `mount` routes several FS volumes (each still backed by a
  by-name block channel), and net multi-homing lives in `ip`'s address
  table.

The boundary: physical hardware stays channel-wired by name;
instance-keying applies only to logical service surfaces. This keeps the
kernel mechanism minimal and the graph honest.

### Opcode class allocation

Source: `src/kernel/module/provider.rs`, `src/kernel/module/syscalls.rs`.

Class-byte routing in the kernel uses `(op >> 8) & 0xFF` to pick the
contract id, so every dispatched surface needs its own class byte:

| Class byte | Contract id (`kernel::provider::contract`) | Opcode range |
|-----------:|---------------------------------------------|--------------|
| `0x09`     | `FS`                                        | `0x0900..0x09FF` — random-access file I/O (`fs.rs`) |
| `0x13`     | `STORAGE_NAMESPACE`                         | `0x1300..0x13FF` — directory-like name-keyed surface (`namespace.rs`) |
| `0x14`     | `STORAGE_OBJECT`                            | `0x1400..0x14FF` — whole-blob byte-addressed surface (`object.rs`) |

`storage.block` is exposed through block-IO requests on driver channels
(sd, nvme, …) rather than a single class byte; per-driver request formats
are documented alongside those modules. Class byte `0x0A` is `BUFFER`,
not a storage surface — namespace and object opcodes sit in their own
class bytes to avoid the collision.

---

## 2. Fence — the orthogonal axis

Source: `modules/sdk/fence.rs` (exposed as `abi::fence`).

Two providers may both satisfy `storage.object` and yet differ wildly in
what `PUT` means:

- A local POSIX file write returns "ok" once the kernel page cache holds
  the bytes — no durability until the next sync.
- A FAT32 driver returns "ok" for a write once the bytes are staged, and
  only an fsync commits them through the device cache.
- A replicated put returns "ok" once a quorum has accepted a particular
  log position — durability against a configured cluster.
- A content-addressed put returns "ok" with the digest of the bytes it
  stored — durability is the hash itself.

"Ok / errno" cannot express any of that. The fence does. Every storage op
that completes successfully returns the strongest `Fence` it actually
achieved.

```rust
// modules/sdk/fence.rs
pub enum Fence {
    Volatile,
    LocalDurable      { device_id: DeviceId },
    ReplicatedDurable {
        source: ObjectId, commit_index: u64,
        epoch: u32, quorum: u8, witness: Witness,
    },
    ContentHashed     { algorithm: HashAlg, digest: Digest32 },
    RevisionMonotone  { source: ObjectId, revision: u64 },
    ViewConsistent    { source: ObjectId, revision: u64 },
}
```

Three variants carry an explicit `source: ObjectId`. Without it, revision
10 of namespace A would falsely dominate revision 5 of namespace B. The
source identifies the log, namespace, or state machine the fence refers
to; `dominates` requires same-source for any same-dimension comparison.

`ReplicatedDurable` carries enough fields to make the partial order
correct:

- `commit_index` is the monotone log position within an epoch. Refinement
  is by `commit_index`: at the same `(source, epoch)`, `commit_index=10`
  dominates `commit_index=5`. Indices are not monotone across epochs (a
  reconfiguration may have rewound the log), so `dominates` refuses to
  order two fences with different epochs.
- `epoch` is the membership / reconfiguration generation of the
  replicating group.
- `quorum` is informational — a tighter accepting set is reassuring but
  does not refute a same-index commitment.
- `witness` is the opaque commitment. Same `(source, epoch,
  commit_index)` with mismatched witness signals a fork; `dominates`
  returns false rather than ordering divergent histories. Equal witnesses
  on the same `(source, epoch, commit_index)` are the only equivalence
  case.

The fence has a partial order (`Fence::dominates`): `LocalDurable` on
device A does not dominate `LocalDurable` on device B; two
`ReplicatedDurable` fences against different sources do not dominate each
other regardless of epoch, quorum, or index; `ContentHashed` is
orthogonal to `LocalDurable` — both are meaningful, neither dominates the
other. Consumers that need guarantees along multiple dimensions
accumulate fences rather than comparing them.

### Why this is load-bearing

Strip the fence and "the storage surface" is a type assertion with no
behavioural contract behind it. With the fence, providers and consumers
can:

- substitute providers without ABI churn — they wire on the surface name
  and the required fence dominance;
- record the achieved fence alongside the value so a follow-up reader
  refuses to proceed unless the recorded fence still dominates what it
  needs;
- gossip witnesses across the mesh — replicated providers populate
  `ReplicatedDurable.witness`; everyone else treats it as bytes to
  forward.

### Wire encoding and retrieval

`Fence` has a stable prefix-tagged byte encoding so providers return one
fence value per op without a side-channel. The encoding lives in
`abi::fence::Fence::{encode, decode}` and the upper bound is
`WIRE_MAX_LEN = 62` bytes:

| Tag                       | Payload                                                                            | Total |
|--------------------------:|------------------------------------------------------------------------------------|------:|
| `TAG_VOLATILE`            | (none)                                                                             | 1     |
| `TAG_LOCAL_DURABLE`       | `device_id: u64 LE`                                                                | 9     |
| `TAG_REPLICATED_DURABLE`  | `source[16]`, `commit_index: u64 LE`, `epoch: u32 LE`, `quorum: u8`, `witness[32]` | 62    |
| `TAG_CONTENT_HASHED`      | `algorithm: u8`, `digest[32]`                                                      | 34    |
| `TAG_REVISION_MONOTONE`   | `source[16]`, `revision: u64 LE`                                                   | 25    |
| `TAG_VIEW_CONSISTENT`     | `source[16]`, `revision: u64 LE`                                                   | 25    |

Two retrieval paths, one per op shape:

**1. Handle-bound and open-returning ops** (e.g. `fs::READ`, `fs::FSYNC`,
`object::GET`, `object::RANGE_GET`, `namespace::LOOKUP`,
`namespace::SUBSCRIBE`, `object::PUT_STREAMED_OPEN`) advertise the
per-handle fence via:

```
let mut buf = [0u8; abi::fence::WIRE_MAX_LEN];
let n = provider_query(handle,
                       abi::kernel_abi::query_key::LAST_FENCE,
                       buf.as_mut_ptr(),
                       buf.len());
if n > 0 {
    let (fence, _) = Fence::decode(&buf[..n as usize])?;
    // refuse to proceed unless `fence.dominates(my_required_fence)`
}
```

`query_key::LAST_FENCE = 8` is a cross-class common key. The kernel
forwards it as `provider::provider_call(handle, QUERY_OP, out, out_len)`
so the contract's vtable resolves from the handle's FD tag and strips the
tag before re-entering the provider. Both kernel-internal providers and
PIC module providers handle `QUERY_OP` through their existing dispatch
function; there is no separate query-callback ABI.

**2. Handle=-1 one-shot ops** (e.g. `object::PUT`, `object::HEAD`,
`object::DELETE`, `namespace::LIST`, `namespace::RENAME`,
`namespace::DELETE`, `namespace::BIND`, `object::PUT_STREAMED_COMMIT`)
carry a `[fence_out_ptr: u64 LE, fence_out_cap: u16 LE]` pair at the end
of their arg layout. The provider writes the encoded fence (up to
`WIRE_MAX_LEN` bytes) into that buffer atomically with returning the op's
i32 result; callers decode via `Fence::decode`. The fence travels in band
with the result so a crash between return and query cannot lose it.

`Fence::decode` returns `None` for an unknown tag. Consumers MUST treat
decode failure as "no recognised fence" and refuse to proceed; promoting
the unknown tag to `Volatile` would silently weaken substitution.

### Provider behaviour

The Linux host (`src/platform/linux/providers.rs::linux_fs_dispatch`)
records a per-handle `Fence` on every successful op: durability-achieving
ops (`FSYNC`, durable `PREALLOCATE`) record
`Fence::LocalDurable { device_id: LINUX_FS_DEVICE_ID }`; every other op
(`READ` / `WRITE` / `SEEK` / `STAT` / `OPEN` / `OPENDIR` / `READDIR`)
records `Fence::Volatile`. Volatile-recording overwrites any prior
`LocalDurable` so a slot's fence never reports stale durability. The
slot's fence is exposed to in-process callers via `slot_fence(handle)`
and over the syscall ABI via `abi::fence::QUERY_OP`.

The bare-metal FAT32 provider (`modules/foundation/fat32/mod.rs`) answers
`QUERY_OP` the same way: a handle reports `LocalDurable` only after a
writable handle's bytes have been committed through the device cache by a
successful fsync; every other live handle, including any read-only
handle, reports `Volatile`. The wasm fetch provider
(`src/platform/wasm/fs.rs`) answers `Volatile` for every successful op.

---

## 3. Leased mesh Handles

Source: `modules/sdk/contracts/storage/handle.rs`.

Opening a namespace prefix, an object, or an event stream produces a
*handle*: the value the caller subsequently uses to read, watch, or
close. Storage handles compose the mesh primitives (`mesh.md`):

```rust
// modules/sdk/contracts/storage/handle.rs
pub struct StorageHandle {
    pub object: ObjectId,        // mesh primitive #1
    pub kind: HandleKind,        // Object | Namespace | Stream
    pub permissions: u16,        // OR-combined StoragePerm
    pub slot: u16,               // provider-local FD; crosses the syscall boundary
    pub not_after: u64,          // mesh primitive #8 (Lease)
    pub hint: LocationHintBlob,  // mesh LocationHint, opaque blob
    pub revoked: bool,           // revoked by issuer or provider on unmount, reconfigure
}
```

Lifecycle rules:

- Providers map `(ObjectId, Capability, LocationHint)` to a small integer
  slot index. The integer is what crosses the syscall boundary;
  `StorageHandle` is the typed Rust view inside the provider and any
  host-side caller that has the slot mapping.
- `not_after` is an absolute monotonic timestamp (kernel `time_ns`).
  Providers refuse ops with `now >= not_after` and free the slot.
- Revocation is provider-driven: an unmount, a replicated store
  reconfiguration, or an explicit revoke from the issuer flips `revoked`
  and frees the slot. The next op against a revoked handle fails with
  `EACCES` or `ENODEV`.
- Richer per-slot state extends `StorageHandle`; new permissions extend
  `StoragePerm`. Storage providers compose this primitive rather than
  parallel handle / FD types.

`HandleKind::Stream` is the kind issued for either `file.data` reads or
for an `event.log` subscription (§4).

---

## 4. The `event.log` content-type pattern

`event.log` is not a new surface: it is an Event-stream content-type
pattern built on the mesh Event primitive (the event model in
`mesh.md`):

- The wire shape is the mesh Event header plus a per-source monotone
  sequence.
- The provider advertises `Fence::ReplicatedDurable { source,
  commit_index, epoch, quorum, witness }` once a commit succeeds against
  a cluster, or `Fence::LocalDurable { device_id }` once a single-node
  WAL has been flushed. `source` identifies the log; `commit_index` is
  the position on it; `witness` distinguishes forked histories at the
  same `(source, commit_index, epoch)`.
- Subscribers consume the stream by opening a `storage.namespace` entry
  of `HandleKind::Stream`, or by subscribing under a prefix via
  `namespace::SUBSCRIBE`.

Three otherwise unrelated provider classes reduce to this pattern:

- **Local WAL** — per-store write-ahead log; `RevisionMonotone` per
  commit, `LocalDurable` per fsync.
- **Replicated commit log** — replicated state-machine log;
  `ReplicatedDurable` per accepted entry.
- **Generic append logs** — any "name resolves to an Event stream with
  monotone sequence" use case.

Because `event.log` is a content type and not a surface, providers do not
declare a new capability to participate: they advertise
`storage.namespace` (so consumers can `SUBSCRIBE` to a prefix) and ship a
stream-kind handle whose Events carry the `event.log` content type.

### Large-blob writes via event.log

`object::PUT` is single-shot — the body fits in a single arg pointer.
Larger writes compose through four `storage.object` opcodes
(`modules/sdk/contracts/storage/object.rs`):

```
PUT_STREAMED_OPEN   (handle = -1)  →  stream handle
PUT_STREAMED_WRITE  (handle = sh)  →  one chunk appended as one Event
…
PUT_STREAMED_COMMIT (handle = sh)  →  atomic promotion + fence_out
PUT_STREAMED_ABORT  (handle = sh)  →  discard staged events
```

A provider maps this onto whatever shape its backing store prefers:

- a replicated object store opens an `event.log` stream at
  `_staging/<key>`, appends one Event per `PUT_STREAMED_WRITE`, and on
  `PUT_STREAMED_COMMIT` atomically links the finalised event sequence
  under `<key>`, advertising `ReplicatedDurable`;
- a local object store writes chunks to an append-only WAL and
  fsync+renames on commit, advertising `LocalDurable { device_id }`;
- an object-store adapter maps the open / write / commit sequence to its
  upstream's native multipart or staged-upload API, passing through the
  fence the upstream advertised (typically `ReplicatedDurable` or
  `ContentHashed`).

The handle's per-handle fence is `Volatile` during WRITE and upgrades to
the strongest fence COMMIT achieves; the same encoded fence is also
written into `fence_out_ptr` on COMMIT so the caller records it in band
with the success return. `PUT_STREAMED_ABORT` releases the staging
events; subsequent reads of `<key>` see no trace of the partial sequence.

There is no separate "multipart" surface, and `object::PUT` is not
stretched into a streaming op: `PUT` stays a small-blob single-shot, and
large bodies compose through the four streaming opcodes above.

---

## 5. Platform providers

The host platforms serve the storage surfaces through dispatchers built
into the runtime rather than loadable modules:

- **Linux `file.data`** — `src/platform/linux/providers.rs`
  (`linux_fs_dispatch`), libc-backed random-access file I/O with the
  per-handle fence recording described in §2.
- **Linux `storage.namespace`** — `src/platform/linux/namespace.rs`,
  directory enumeration (`LIST` / `STAT`) over the host filesystem via
  `std::fs`. Namespace keys are raw filesystem paths, byte-identical to
  what `linux_fs_dispatch` opens, so a consumer can `LIST` here and fetch
  each hit through the FS contract on the same key. The per-handle fence
  is `Volatile` (a live, mutable host filesystem).
- **Linux `storage.object`** — `src/platform/linux/object.rs`, HTTP/1.1
  `Range:` reads (`HEAD` / `GET` / `RANGE_GET` / `CLOSE`) so a
  Linux-hosted graph can demand-page immutable assets by byte range.
- **wasm peers** — `src/platform/wasm/fs.rs`, `namespace.rs`, and
  `object.rs` serve the same three contracts in the browser host.

On bare metal, `foundation/fat32` provides `file.data` over a
`storage.block` channel: random-access reads through the FS contract,
writes emitted as block-write requests on its `block_writes` output port
(typically wired to `nvme.requests`), and directory listing served
through the FS contract's `OPENDIR` / `READDIR`. It does not implement
the `storage.namespace` contract.

These are one adapter family; content-addressed, replicated, and
object-store adapters can use the same surface vocabulary. Providers
interoperate when they share the four surfaces and the fence contract.

---

## 6. Scope

This page covers:

- the four canonical storage surfaces and their opcodes;
- the `Fence` enum, its rationale, and its partial order;
- the leased `StorageHandle` contract built on mesh primitives;
- the `event.log` content-type pattern.

Out of scope (deliberately):

- Wire-level paired `(value, Fence)` envelopes on the existing `fs`
  opcodes. The syscall ABI returns `i32`; the per-handle fence is fetched
  via a follow-up `provider_query(handle, query_key::LAST_FENCE, …)` and
  decoded via `Fence::decode`.
- `storage.append_log` as a public surface — covered by the `event.log`
  pattern.
- `storage.page_backing` as a public surface — internal cache concern of
  `storage.block` / `file.data` providers; lives in
  `modules/sdk/contracts/storage/paged_arena.rs`.
- Cross-provider rename / delete. `RENAME` is atomic within one provider;
  moving an entry between providers is a higher-level orchestration
  concern.
