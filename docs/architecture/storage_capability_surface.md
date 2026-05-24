# Storage Capability Surface

Fluxor's storage architecture rests on three layered concepts:

1. a **surface family** — four canonical surfaces the graph
   carries: `storage.block`, `file.data`, `storage.namespace`,
   `storage.object`;
2. a **per-op fence advertisement** — `contracts::fence::Fence`, the
   orthogonal axis that lets two providers share a surface name
   while differing honestly in durability and ordering;
3. a **leased mesh-Handle contract** — every opened namespace,
   object, or stream is a `StorageHandle` carrying `not_after` and
   revocation semantics, built on the mesh `Handle` (mesh primitive
   #3) and `Lease` (mesh primitive #8).

This document is the in-tree reference. It is the storage peer of
`av_capability_surface.md` (AV), `input_capability_surface.md`
(input), `endpoint_capability_surface.md` (external hosts), and
`protocol_surfaces.md` (net).

---

## 1. Canonical surface family

Storage pipelines move data on channels typed by `content_type` and
exchange leased handles through the mesh Handle primitive. Four
surfaces compose the family; every provider declares one or more.

| Surface             | Domain                                                          | Typical providers / consumers                                |
|---------------------|-----------------------------------------------------------------|--------------------------------------------------------------|
| `storage.block`     | Raw 512-byte block I/O                                          | sd, flash, nvme; fat32, littlefs consume                     |
| `file.data`         | Byte-stream file access (open, read, seek, stat, write, fsync)  | fat32, linux_fs, http-as-fs; player / viewer modules consume |
| `storage.namespace` | Name-keyed directory surface (lookup, list, rename, …)          | fat32 (readonly), linux_fs, replicated namespace adapters    |
| `storage.object`    | Whole-blob byte-addressed surface (put, get, head, range_get)   | content-addressed stores, replicated object stores, HTTP-backed adapters |

Multipart object upload is deliberately not part of `storage.object`.
Large writes compose via the `event.log` pattern in §4 and finalise
with `object::PUT_STREAMED_COMMIT` — the concrete four-opcode
sequence (`PUT_STREAMED_OPEN` / `_WRITE` / `_COMMIT` / `_ABORT`).
Object-store adapters can synthesize provider-specific multipart
uploads on top of this surface; the surface itself stays narrow so
substitutability holds.

Append-log behaviour is deliberately not a new surface — it is an
Event-stream content-type pattern over the mesh Event primitive
(§4).

Page-backing for arenas is deliberately not a public surface —
it's an internal cache concern of `storage.block` / `file.data`
providers (see `contracts/storage/paged_arena.rs`).

### Where this is enforced

- `provides` / `requires` in `manifest.toml` reference the surface
  names above; the manifest parser accepts them as free-form
  capability strings, and the config tool resolves consumer →
  provider chains at build time via the rules in
  `capability_surface.md`.
- The four surfaces appear in `capability_surface.md`'s canonical
  taxonomy.
- The opcode constants live in `modules/sdk/contracts/storage/`
  (`fs.rs`, `namespace.rs`, `object.rs`, plus the kernel-private
  `graph_slot.rs`, `paged_arena.rs`, `runtime_params.rs`).

### Opcode class allocation

Class-byte routing in the kernel (`provider::provider_call` /
`syscalls.rs`) uses `(op >> 8) & 0xFF` to pick the contract id, so
every surface needs its own class byte:

| Class byte | Contract id (`kernel::provider::contract`) | Opcode range |
|-----------:|---------------------------------------------|--------------|
| `0x09`     | `FS`                                        | `0x0900..0x09FF` — random-access file I/O (`fs.rs`) |
| `0x13`     | `STORAGE_NAMESPACE`                         | `0x1300..0x13FF` — directory-like name-keyed surface (`namespace.rs`) |
| `0x14`     | `STORAGE_OBJECT`                            | `0x1400..0x14FF` — whole-blob byte-addressed surface (`object.rs`) |

`storage.block` is exposed through block-IO ioctls on driver
channels (sd, nvme, …) rather than a single class byte; per-driver
opcodes are documented alongside those modules. Class byte `0x0A`
is `BUFFER`, not a storage surface — namespace and object opcodes
sit in their own class bytes to avoid the collision.

---

## 2. Fence — the orthogonal axis

Two providers may both satisfy `storage.object` and yet differ
wildly in what `PUT` means:

- A local POSIX file write returns "ok" once the kernel page cache
  holds the bytes — no durability until the next sync.
- A FAT32 driver over SD returns "ok" once the FAT block has been
  flushed — local durability against a specific device.
- A replicated put returns "ok" once a quorum has accepted
  a particular log position — durability against a configured
  cluster.
- A content-addressed put returns "ok" with the digest of the
  bytes it stored — durability is the hash itself.

"Ok / errno" cannot express any of that. The fence does. Every
storage op that completes successfully returns the strongest
`Fence` it actually achieved.

```rust
// modules/sdk/contracts/fence.rs
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

Three variants carry an explicit `source: ObjectId`. Without it,
revision 10 of namespace A would falsely dominate revision 5 of
namespace B. The source identifies the log, namespace, or state
machine the fence refers to; `dominates` requires same-source for
any same-dimension comparison.

`ReplicatedDurable` carries enough fields to make the partial order
correct:

- `commit_index` is the monotone log position within an epoch.
  Refinement is by `commit_index`: at the same `(source, epoch)`,
  `commit_index=10` dominates `commit_index=5`. Indices are not
  monotone across epochs (a reconfiguration may have rewound the
  log), so `dominates` refuses to order two fences with different
  epochs.
- `epoch` is the membership / reconfiguration generation of the
  replicating group. `dominates` requires same epoch; cross-epoch
  comparisons are not expressible through this fence alone.
- `quorum` is informational — a tighter accepting set is
  reassuring but does not refute a same-index commitment.
- `witness` is the opaque commitment. Same `(source, epoch,
  commit_index)` with mismatched witness signals a fork;
  `dominates` returns false rather than ordering divergent
  histories. Equal witnesses on the same `(source, epoch,
  commit_index)` are the only equivalence case.

The fence has a partial order (`Fence::dominates`): `LocalDurable`
on device A does not dominate `LocalDurable` on device B; two
`ReplicatedDurable` fences against different `source`s do not
dominate each other regardless of epoch / quorum / index;
`ContentHashed` is orthogonal to `LocalDurable` — both are
meaningful, neither dominates the other. Consumers that need
guarantees along multiple dimensions accumulate fences rather than
comparing them.

### Why this is load-bearing

Strip the fence and "the storage surface" is a type assertion with
no behavioural contract behind it. With the fence, Fluxor providers
and consumers can:

- substitute providers without anticipating ABI churn — they wire
  on the surface name and the required fence dominance;
- record the achieved fence alongside the value so a follow-up
  reader refuses to proceed unless the recorded fence still
  dominates what it needs;
- gossip witnesses across the mesh — replicated providers populate
  `ReplicatedDurable.witness`; everyone else treats it as bytes to
  forward.

### Wire encoding and retrieval

`Fence` has a stable prefix-tagged byte encoding so providers
return one fence value per op without a side-channel. The encoding
lives in `contracts::fence::Fence::{encode, decode}` and the upper
bound is `WIRE_MAX_LEN = 62` bytes:

| Tag                       | Payload                                                                                              | Total |
|--------------------------:|------------------------------------------------------------------------------------------------------|------:|
| `TAG_VOLATILE`            | (none)                                                                                               | 1     |
| `TAG_LOCAL_DURABLE`       | `device_id: u64 LE`                                                                                  | 9     |
| `TAG_REPLICATED_DURABLE`  | `source[16]`, `commit_index: u64 LE`, `epoch: u32 LE`, `quorum: u8`, `witness[32]`                   | 62    |
| `TAG_CONTENT_HASHED`      | `algorithm: u8`, `digest[32]`                                                                        | 34    |
| `TAG_REVISION_MONOTONE`   | `source[16]`, `revision: u64 LE`                                                                     | 25    |
| `TAG_VIEW_CONSISTENT`     | `source[16]`, `revision: u64 LE`                                                                     | 25    |

Two retrieval paths, one per op shape:

**1. Handle-bound and open-returning ops** (e.g. `fs::READ`,
`fs::FSYNC`, `object::GET`, `object::RANGE_GET`,
`namespace::LOOKUP`, `namespace::SUBSCRIBE`,
`object::PUT_STREAMED_OPEN`) advertise the per-handle fence via:

```
let mut buf = [0u8; abi::contracts::fence::WIRE_MAX_LEN];
let n = provider_query(handle,
                       abi::kernel_abi::query_key::LAST_FENCE,
                       buf.as_mut_ptr(),
                       buf.len());
if n > 0 {
    let (fence, _) = Fence::decode(&buf[..n as usize])?;
    // refuse to proceed unless `fence.dominates(my_required_fence)`
}
```

`query_key::LAST_FENCE = 8` is a cross-class common key. The
kernel forwards it as `provider::provider_call(handle, QUERY_OP,
out, out_len)` so the contract's vtable resolves from the handle's
FD tag and strips the tag before re-entering the provider. Both
kernel-internal providers and PIC module providers handle
`QUERY_OP` through their existing dispatch function — there is no
separate query-callback ABI.

**2. Handle=-1 one-shot ops** (e.g. `object::PUT`, `object::HEAD`,
`object::DELETE`, `namespace::LIST`, `namespace::RENAME`,
`namespace::DELETE`, `object::PUT_STREAMED_COMMIT`) carry a
`[fence_out_ptr: u64 LE, fence_out_cap: u16 LE]` pair at the end of
their arg layout. The provider writes the encoded fence (up to
`fence::WIRE_MAX_LEN` bytes) into that buffer atomically with
returning the op's i32 result; callers decode via `Fence::decode`.
The fence travels in band with the result so a crash between
return and query cannot lose it.

`Fence::decode` returns `None` for an unknown tag. Consumers MUST
treat decode failure as "no recognised fence" and refuse to
proceed; promoting the unknown tag to `Volatile` would silently
weaken substitution.

### Provider behaviour

The Linux host (`src/platform/linux/providers.rs::linux_fs_dispatch`)
records a per-handle `Fence` on every successful op:

- `FSYNC` → `Fence::LocalDurable { device_id: LINUX_FS_DEVICE_ID }`
- `READ` / `WRITE` / `SEEK` / `STAT` / `READDIR` / `OPEN` /
  `OPENDIR` → `Fence::Volatile`

Volatile-recording overwrites any prior `LocalDurable` so a slot's
fence never reports stale durability. The slot's fence is exposed
to in-process callers via `slot_fence(handle)` and over the
syscall ABI via `contracts::fence::QUERY_OP`. The bare-metal FAT32
provider (`modules/foundation/fat32/mod.rs`) is read-only and
answers `QUERY_OP` with `Fence::Volatile` for live slots; the wasm
fetch provider (`src/platform/wasm/fs.rs`) does the same.

---

## 3. Leased mesh Handles

Opening a namespace prefix, an object, or an event stream produces
a *handle* — the value the caller subsequently uses to read,
watch, or close. Storage handles compose the mesh primitives
(`docs/architecture/mesh.md`):

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

- Providers map `(ObjectId, Capability, LocationHint)` to a small
  integer slot index. The integer is what crosses the syscall
  boundary; `StorageHandle` is the typed Rust view inside the
  provider and any host-side caller that has the slot mapping.
- `not_after` is an absolute monotonic timestamp (kernel
  `time_ns`). Providers refuse ops with `now_ns >= not_after` and
  free the slot.
- Revocation is provider-driven: a FAT32 unmount, a replicated store
  reconfiguration, or an explicit revoke from the issuer flips
  `revoked` and frees the slot. The next op against a revoked
  handle fails with `EACCES` or `ENODEV`.
- Richer per-slot state extends `StorageHandle`; new permissions
  extend `StoragePerm` — storage providers compose this primitive
  rather than parallel handle / FD types.

`HandleKind::Stream` is the kind issued for either `file.data`
reads or for an `event.log` subscription (§4).

---

## 4. The `event.log` content-type pattern

`event.log` is not a new surface — it is an Event-stream
content-type pattern built on the mesh Event primitive (mesh.md
§5):

- The wire shape is the mesh Event header plus a per-source
  monotone sequence (mesh primitive #5).
- The provider advertises `Fence::ReplicatedDurable { source,
  commit_index, epoch, quorum, witness }` once a commit succeeds
  against a cluster, or `Fence::LocalDurable { device_id }` once a
  single-node WAL has been flushed. `source` identifies the log;
  `commit_index` is the position on it; `witness` distinguishes
  forked histories at the same `(source, commit_index, epoch)`.
- Subscribers consume the stream by opening a `storage.namespace`
  entry of `HandleKind::Stream` (or by subscribing under a prefix
  via `namespace::SUBSCRIBE`).

Three otherwise unrelated provider classes reduce to this pattern:

- **Local WAL** — per-store write-ahead log; `RevisionMonotone` per
  commit, `LocalDurable` per fsync.
- **Replicated commit log** — replicated state-machine log;
  `ReplicatedDurable` per accepted entry.
- **Generic append logs** — any "name resolves to an Event stream
  with monotone sequence" use case, including foundation/log_net's
  ring drain wrapped as a namespace entry.

Because `event.log` is a content type and not a surface, providers
do not declare a new capability to participate — they advertise
`storage.namespace` (so consumers can `SUBSCRIBE` to a prefix) and
ship a stream-kind handle whose Events carry the `event.log`
content type.

### Large-blob writes via event.log

`object::PUT` is single-shot — the body fits in a single arg
pointer. Cloud-scale writes compose through four `storage.object`
opcodes:

```
PUT_STREAMED_OPEN   (handle = -1)  →  stream handle
PUT_STREAMED_WRITE  (handle = sh)  →  one chunk appended as one Event
…
PUT_STREAMED_COMMIT (handle = sh)  →  atomic promotion + fence_out
PUT_STREAMED_ABORT  (handle = sh)  →  discard staged events
```

Providers map this onto whatever shape their backing store
prefers:

- **Replicated object store** opens an `event.log` stream at
  `_staging/<key>`; each `PUT_STREAMED_WRITE` appends one Event;
  `PUT_STREAMED_COMMIT` atomically links the finalised event
  sequence under `<key>` and advertises `ReplicatedDurable
  { source, commit_index, epoch, quorum, witness }`.
- **Local object store** writes chunks to an append-only WAL;
  `PUT_STREAMED_COMMIT` fsync+renames and advertises
  `LocalDurable { device_id }`.
- **Object-store adapter** maps the streamed open/write/commit
  sequence to the provider's native multipart or staged-upload API.
  The fence on COMMIT is whatever the upstream advertised (typically
  `ReplicatedDurable` or `ContentHashed`).

The handle's per-handle fence is `Volatile` during WRITE and
upgrades to the strongest fence COMMIT achieves; the same encoded
fence is also written into `fence_out_ptr` on COMMIT so the caller
records it in band with the success return. `PUT_STREAMED_ABORT`
releases the staging events; subsequent reads of `<key>` see no
trace of the partial sequence.

Large object providers can satisfy this contract. There is no
separate "multipart" surface, and `object::PUT` is not stretched
into a streaming op — `PUT` stays a small-blob single-shot; large
bodies compose through the four streaming opcodes above.

---

## 5. Adapter compatibility

The local POSIX adapter at `src/platform/linux/providers.rs`
(`linux_fs_dispatch`) and the bare-metal adapter at
`modules/foundation/fat32/mod.rs` are one provider each of:

- `file.data` — byte-stream access. Linux advertises
  `Fence::LocalDurable { device_id }` on successful `FSYNC` and
  `Fence::Volatile` for unflushed writes and plain reads; FAT32 is
  read-only and advertises `Fence::Volatile`. Per-handle recording
  ensures `query_key::LAST_FENCE` always reflects the latest op on
  the queried handle.
- `storage.namespace` (readonly for FAT32; full read/write for
  linux_fs once `RENAME` / `DELETE` lands) — `OPENDIR` / `READDIR`
  surface the listing operations.

`fs.rs` is one adapter family; content-addressed, replicated, and
object-store adapters can use the same surface vocabulary. They
interoperate when they share the four surfaces and the fence contract.

---

## 6. Scope

This page covers:

- the four canonical storage surfaces and their opcodes;
- the `Fence` enum, its rationale, and its partial order;
- the leased `StorageHandle` contract built on mesh primitives;
- the `event.log` content-type pattern.

Out of scope (deliberately):

- A per-capability conformance test suite. Cases should stabilise
  after the surfaces do and after two independent providers exercise
  the same contract.
- Wire-level paired `(value, Fence)` envelopes on the existing
  `fs` opcodes. The syscall ABI returns `i32`; the per-handle
  fence is fetched via a follow-up `provider_query(handle,
  query_key::LAST_FENCE, …)` and decoded via `Fence::decode`. A
  paired return envelope is a later evolution once a consumer
  needs in-band delivery.
- `storage.append_log` as a public surface — covered by the
  `event.log` pattern.
- `storage.page_backing` as a public surface — internal cache
  concern of `storage.block` / `file.data` providers; lives in
  `contracts/storage/paged_arena.rs`.
- Cross-provider rename / delete. `RENAME` is atomic within one
  provider; moving an entry between providers is a higher-level
  orchestration concern.
