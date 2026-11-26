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

Source: `crates/fluxor-abi/src/contracts/storage/`, `contracts/src/vocabulary.rs`.

Storage pipelines move data on channels typed by `content_type` and
exchange leased handles through the mesh Handle primitive. Four surfaces
compose the family; every provider declares one or more.

| Surface             | Carries                                                         | Providers / consumers                                        |
|---------------------|-----------------------------------------------------------------|--------------------------------------------------------------|
| `storage.block`     | Raw block I/O                                                   | nvme, sd, flash_rp (data store), file_block, crypt_block provide; fat32, crypt_block, nbd_serve and key_vault consume |
| `file.data`         | Byte-stream file access (open, read, seek, stat, write, fsync)  | fat32 and the mount router provide; player / viewer modules consume |
| `storage.namespace` | Name-keyed directory surface (lookup, stat, list, rename, delete, bind, subscribe) | host platform providers and fs_object (§5); scanners and stores consume |
| `storage.object`    | Whole-blob byte-addressed surface (put, get, head, range_get, delete, list) | host platform providers and fs_object (§5); object_bank consumes |
| `storage.custody`   | Custody of a keyed volume's key (seal, open, custodian, split, drill) | a keyed volume provides it beside its data surface; consumers select it by the volume's name |

`storage.custody` is not a data surface: it is how a consumer uses a keyed
volume's key without holding it. The vault scopes key labels by module type,
so only the volume's own module reaches its key; what another module needs
of that key (a backup sealed under it, the volume's recovery custodians,
recovery shares, a drill that the shares still rebuild it) it asks the volume
for, by the volume's name. Every argument is in place
(`crates/fluxor-abi/src/contracts/storage/custody.rs`); shares use key_vault's
v1 share format.

Multipart object upload is deliberately not part of `storage.object`.
Large writes compose via the `event.log` pattern in §4 and finalise with
the four-opcode streamed sequence (`PUT_STREAMED_OPEN` / `_WRITE` /
`_COMMIT` / `_ABORT`). Object-store adapters can synthesise
provider-specific multipart uploads on top of this surface; the surface
itself stays narrow so substitutability holds.

Append-log behaviour is deliberately not a new surface: it is an
Event-stream content-type pattern over the mesh Event primitive (§4).

### Where this is enforced

- `provides` in `manifest.toml` is validated against the provider
  vocabulary (the ABI registry's manifest-nameable contracts plus
  `PROVIDER_SURFACES`); an unknown name fails manifest parsing.
  Consumers reach a provider through `[[resources]].requires_contract`
  (by contract, substitutable) or by naming the provider's ports directly
  in graph YAML (by name, not substitutable — prefer the former, and
  route multi-volume graphs through `mount`).
- The four surfaces appear in `capability_surface.md`'s canonical
  taxonomy.
- The opcode constants live in `crates/fluxor-abi/src/contracts/storage/`
  (`fs.rs`, `namespace.rs`, `object.rs`, `block.rs`, `custody.rs`, the
  shared `handle.rs`, plus the kernel-private `graph_slot.rs` and
  `runtime_params.rs`).

### Declared providers and consumers

Loadable modules carrying `provides = [...]` in their `manifest.toml`:

| Surface             | Declared by (`provides`)                            |
|---------------------|-----------------------------------------------------|
| `storage.block`     | `modules/drivers/nvme`, `modules/foundation/sd`, `modules/foundation/file_block`, `modules/foundation/crypt_block` |
| `file.data`         | `modules/foundation/fat32`, `modules/foundation/mount`              |
| `storage.namespace` | `modules/foundation/fs_object`, `modules/foundation/fs_namespace`, `modules/fixtures/mem_ns` (a RAM test fixture) |
| `storage.object`    | `modules/foundation/fs_object`, `modules/foundation/file_object` (read only) |

The hosts carry no `provides` rows: on Linux and wasm these surfaces are
served by platform dispatchers inside the runtime (§5) rather than by
modules with manifests, so they register directly and never advertise a
surface.

The `fs` contract's bulk ops carry their bytes in the call's `data` span
and take no `arg`: `READ` and `READDIR` fill it and answer the count
written, `WRITE` and `WRITE_ASYNC` take from it and answer the count taken.
Every other `fs` op carries at most one bounded `arg` record (a path, an
offset, a `STAT` record) and no `data`.

Consumers by contract (substitutable): `modules/foundation/fs_bank` and
`modules/foundation/fs_tap` name `requires_contract = "fs"`;
`modules/foundation/object_bank` names `requires_contract = "storage.namespace"`
and `"storage.object"`.

### Multiple volumes: instance-keyed providers + the `mount` module

Source: `tools/src/config/validate.rs` (`validate_single_provider`),
`src/kernel/module/provider.rs`, `src/kernel/module/syscalls.rs`,
`modules/foundation/mount/mod.rs`.

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
instance-keyed layer rather than the default. A consumer reaches a keyed
layer by binding to it once:

- `provider_open(contract, kernel::BIND, [NAME][len u8][name])` hashes the
  selector name, finds the layer carrying it, and returns a bound handle.
  Every op through that handle reaches that layer (a NAME bind delivers
  `handle = -1` to the provider), and a handle an op through it mints is
  routed to the same provider. `provider_close` drops the binding without
  asking the provider anything. A bind to a name no layer carries is
  `ENODEV`. The bound handle is a route, so it carries a generation: once
  its layer goes (a live removal), the handle names nothing (`EBADF`) and a
  freed-then-reused module index never aliases it.

The selector name `platform` is reserved: a bind to `platform` reaches
the platform's own (kernel-registered) provider of the contract, beneath
every module layer — the host filesystem on
Linux, even when the graph carries a `fat32` of its own as the default.
No module may register it: the loader's registration is refused
(`EACCES`) and `validate_single_provider` rejects `volume: platform` on
a provider first. `file_block`'s `volume: platform` is how an image file
on the host sits under a graph-local filesystem built on it.

Every handle an `fs` provider answers is wrapped by the kernel in a route
(`abi_layers.md`, Handles): the provider answers its own index, the module is
given a handle naming the route, and every later op on the handle reaches
that provider with its index, whatever the default layer is. A value no
route names — a descriptor field never opened (0), a bare slot number, a
handle kept past its close — is refused `EBADF` before it reaches a
provider, rather than landing on whichever file holds that slot now. A
route answers only its minter's owner; it dies with its provider's layer, a
departing consumer's routes are closed at their providers, and a graph reset
forgets them all. A handle minted through a bound handle (a keyed volume,
or `platform` beneath a graph-local default) is routed to the same provider,
so a subscription to a keyed store rings and reads exactly as one to the
default store does.

The **`mount` module** (`modules/foundation/mount/`) is the policy layer.
It registers as the default (unkeyed) FS provider and carries a
`mounts: "/boot=sd0;/data=nvme0"` table. On `FS_OPEN(path)` it
longest-prefix-matches the path to a volume, forwards the prefix-stripped
path to that volume through the handle it bound to that volume's name,
keeps the routed handle it
gets back, and hands the consumer a handle of its own, so later
handle-bound ops (`FS_READ` / `FS_CLOSE` / …) come back to it (which is
what lets an unmount revoke them) and are forwarded to the owning
volume with the caller's `data` span. A mount may name `platform` as its volume. Path policy stays in
the module; the kernel never parses paths. `validate_single_provider` therefore allows several
providers of one surface as long as each `volume:` selector is distinct;
two providers with one `volume:`, or two unkeyed providers, are refused.

**Which volume a consumer reaches.** A consumer declares it on its
claim, the `[[resources]]` row in its `manifest.toml`, with at most one of
four keys. They are read from `manifest.toml` by `pack` and the composer
and are not written to the module's binary manifest.

- `selector = "<name>"`: the claim reaches that one volume.
- `selector_param = "<param>"`: the instance's value of that param names
  the volume, read as the packer reads it (a bare key on the entry over one
  under `params:`). Empty or absent, the claim reaches the default
  provider. `file_block` declares `selector_param = "volume"`.
- `selector_table = "<param>"`: the param holds `;`-separated
  `prefix=volume` entries, and the claim reaches every volume they name.
  `mount` declares `selector_table = "mounts"` on its own `fs` claim: the
  kernel checks the grant of the module that binds and calls the volume, and
  a provider's dispatch runs as the provider, so the check is on `mount`'s
  claim, not on the consumer whose op it forwards. A volume `mount`'s
  hotplug channel adds as it runs is not checked.
- `selector_runtime = true`: the module chooses the name as it runs, so
  the composer cannot check it.

A claim the module uses only under some configuration says so with
`active_when_params = ["<param>", …]`, beside any of the keys above: the
claim counts for the composer's checks only for an instance that sets at
least one of those params non-empty (read as `selector_param` is), and an
instance that sets none of them never makes the call, so the claim reaches
no provider and feeds none. `http` declares
`active_when_params = ["routes_prefix", "listeners_prefix",
"sessions_prefix"]` on its `storage.namespace` claim: without a table
configured it never touches the store, so an `http` that feeds the graph's
default store (an api plane's) is not refused for a call it never makes.
Like the selector keys it is read from `manifest.toml` and never written to
the binary manifest; a binary manifest's claims are always counted.

`pack` refuses a `selector_param`, `selector_table` or
`active_when_params` entry that is not one of the module's own `str`
params, and `active_when_params = []`, an empty name or a repeated one.
With none of the selector keys, the claim reaches
the contract's default: the top-most
unkeyed module provider, else the platform's own provider, else `ENOSYS`.
The platform's own `fs` provider is the host's filesystem on Linux and
wasm; on bcm2712 it serves workloads only, each inside a root of its own
on the node's volume, and answers the node's own modules `ENOSYS`; the RP
targets have none.

The composer checks every claim the instance exercises against the
providers of the graph the module runs in (a workload's against the workload's own: a workload
reaches only providers of its own and the platform), and refuses, naming
the module, its claim and the fix:

- a claim that names no volume in a graph whose module providers of the
  contract are all keyed: none of them would answer it;
- a claim that names no volume and reaches the graph's default provider
  while feeding it through the wiring (a `file_block` under the `fat32`
  that is the graph's filesystem): the provider cannot answer the module
  until the module has served it, so neither comes up. A path counts only
  when its last edge enters an input of the provider that gates its
  readiness — `gates_readiness` on the `[[ports]]` entry, `true` unless
  declared `false`, and assumed for an endpoint that names no port or a
  port the manifest lacks. `fat32`'s `blocks` gates (it mounts from what
  arrives there); a store fed commands by a request pipeline (lattice's
  `kv_state_worker_store`, whose `commands` input carries routed commands
  it applies, not what it needs before it answers) declares `false`, so a
  claimant upstream of that pipeline is admitted. A path that passes
  through another provider of the same contract, entering it through one
  of its gating inputs, counts whichever input of the default provider it
  then enters: what the composer cannot see through it treats as a
  dependency. `gates_readiness` is tools-side only, never serialised, and
  refused on an output port;
- a claim that names a volume no provider in the graph declares: at
  runtime it would answer `ENODEV`;
- a claim that names `platform` where the target's platform does not
  answer the contract for that graph's modules;
- a `selector_table` entry that is not `prefix=volume`, which the module
  would skip;
- a provider that names the volume it reaches with its own `volume`
  param, which names the volume it provides.

A graph with keyed providers and no consumer, or only `selector_runtime`
consumers, passes. A provider's claim on its own contract that names no
volume is its use of the layers below it and is not checked.

The kernel's readiness gate (`gate_contract_consumers`) holds a module
that claims a contract until the contract's default module provider is
Ready, when that provider is deferred-ready; a module that is
deferred-ready itself is not held. A keyed provider is never waited for.
The loader registers a provider when its `module_new` returns, so a keyed
`fat32` is reachable before its volume is mounted and answers `EAGAIN`
until it is; a bind answers `ENODEV` for a name no layer carries, and the
caller retries. `file_block` is deferred-ready and
reports Ready only once its open has succeeded, which is how a
filesystem built on it waits.

Every duplicate unkeyed provider of a contract in one graph is an error.

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
add installs a mount; like every mount, its volume is reached by name on
each call through a binding made when the mount is installed. Media
detection is platform-specific and outside the module's scope; the module
only consumes the control messages.

### Where instance-keying applies — and where it does not

Instance-keying (a NAME bind plus a policy router like `mount`)
is for logical, contract-dispatched service surfaces: the storage
surfaces (`file.data`, and, when routed, `storage.namespace` /
`storage.object`), owner-scoped stores, and similar. It is deliberately
not applied to physical hardware channels:

- Block devices (`storage.block` on nvme / sd / file_block) and NIC frames
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
| `0x0D`     | `FS`                                        | `0x0D00..0x0DFF` — random-access file I/O (`fs.rs`) |
| `0x0E`     | `STORAGE_NAMESPACE`                         | `0x0E00..0x0EFF` — directory-like name-keyed surface (`namespace.rs`) |
| `0x0F`     | `STORAGE_OBJECT`                            | `0x0F00..0x0FFF` — whole-blob byte-addressed surface (`object.rs`) |
| `0x28`     | `storage_custody::ID`                       | `0x2800..0x28FF` — custody of a keyed volume's key (`custody.rs`) |

`storage.block` (`0x2A`) is an edge contract: it has no default provider
and is never reached by class byte. A consumer binds it through its
`blocks` port (§1.1) and every op goes to the source at the other end of
that edge.

### 1.1 `storage.block` v1

Source: `crates/fluxor-abi/src/contracts/storage/block.rs`; consumer client:
`crates/fluxor-rt/src/block.rs`.

A block source is the module wired to a consumer's `blocks` input. A
consumer port that declares `requires_capability = "storage.block"` must be
wired from exactly one module that provides it. The consumer binds once —
`provider_open(storage.block, kernel::BIND, [PORT][in][index])` — and
calls every op through the bound handle; the source is handed its own port
ref on the edge as the handle. Every request is one fixed record:

| Op | Argument | Result |
| --- | --- | --- |
| `DESCRIBE` `0x2A00` | description record (40 B, written) | 0, or `EAGAIN` before attach |
| `SUBMIT` `0x2A01` | request (40 B) | 0, `EAGAIN` when full, or a refusal |
| `REAP` `0x2A02` | completion (80 B, written) | 1 when one was written, 0 when none |
| `EXEC` `0x2A03` | request + completion (written) | the completion's status |
| `READ_STREAM` `0x2A04` | request, op `READ` | data streamed on the channel |

The description's `F_*` flags are the contract's capability bits. They
qualify the geometry beside them and exist only once the device has
attached, so they travel in that one record and the contract has no separate
`CAPS`.

- **Ops:** `READ`, `WRITE`, `FLUSH`, `DISCARD`.
- **Flags:** `FUA` makes a write durable before it completes. `PREFLUSH`
  flushes every write reaped before the request was submitted, then runs it.
- **Units:** every count and address is in logical blocks of the size
  `DESCRIBE` reports; addresses are 64-bit.
- **Ordering:** requests in flight are unordered. A `FLUSH` covers writes
  whose completions were reaped before it was submitted.
- **Lengths:** every op's `arg` is one flat record whose bound the registry
  declares; the kernel holds every caller, gated or not, to it before a
  source runs.
- **Buffers:** a request names no address. The consumer opens one `lend`
  over its block cache on the bound handle (`lend::OPEN`, a cookie of its
  choosing) and each request names `[cookie][offset][buf_len]` inside it.
  The source resolves the span (`lend::RESOLVE`, grant `lend.borrow`),
  bounds-checks it, moves the data and returns the borrow (`lend::RETURN`)
  before the completion becomes reapable — at `SUBMIT` for a write on a
  source reporting `F_WRITE_COPIES`. `EXEC` carries its buffer as the call's
  `data` span instead. A consumer torn down while a span is still borrowed
  has the memory under it **quarantined** until the borrow returns, so a
  source that never completes keeps the memory it was lent, which is a leak
  and not a corruption.
- **Stream:** `READ_STREAM` restarts the source's stream on the edge at the
  request's LBA; the blocks arrive on the `blocks` channel. A consumer
  flushes its input (`channel::FLUSH`) before it, so nothing of the
  abandoned stream is read as the new one.
- **Fences:** each successful completion carries the strongest `Fence` the
  source achieved (§2): `LocalDurable` for a flush, a FUA write, or any write
  on a device with no volatile cache; `Volatile` for other writes; none for a
  read. A transform such as `crypt_block` passes the fence of the source
  below it through as reported, never strengthened.
- **Capabilities:** block size and count, per-request and atomic block
  limits, queue depth, device id, and whether the source writes, flushes,
  honours FUA natively, discards (and reads back zeros), pipelines, streams,
  or copies write data at submit.
- **Gated callers:** the gateway checks each op's `arg` against the
  registry's shape and the caller's own memory, and a lend's span against
  the caller's memory when it is opened (`module_isolation.md`).

| Source | Serves |
| --- | --- |
| `nvme` | everything; 8 requests in flight on I/O queue 0 |
| `sd` | one-block `SUBMIT`/`REAP` reads and writes (queue depth 1, writes copied at submit and on the card when they complete, `EXEC` answers `ENOSYS`), and `READ_STREAM` to restart the sector stream beside them at an LBA |
| `flash_rp` (`store`) | the RP flash's 16 KiB data store in 4 KiB erase-sector blocks: reads, and writes that complete `LocalDurable` (queue depth 1, `EXEC` answers `ENOSYS`) |
| `file_block` | everything over one file reached through `fs` |
| `crypt_block` | everything, as authenticated encryption over the source wired to its `lower` input |

Every source that runs on a host is checked against one conformance corpus
of these rules.

#### Publishing a source to Linux

`nbd_serve` consumes the source on its `blocks` input and serves it over NBD
(fixed newstyle, simple replies) on a `net_proto` stream transport, so
`nbd-client` attaches it as `/dev/nbdN`. It drives the source with
`SUBMIT`/`REAP` when the source reports `F_ASYNC` and `EXEC` otherwise,
answers `FLUSH` only after the source's `FLUSH` completes, and honours `FUA`
natively or as write-then-flush. Transmission flags, size and block size come
from `DESCRIBE`. One client at a time; see its README.

---

## 2. Fence — the orthogonal axis

Source: `crates/fluxor-abi/src/fence.rs` (exposed as `abi::fence`).

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
// crates/fluxor-abi/src/fence.rs
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
`object::PUT_STREAMED_OPEN`) advertise the per-handle fence via:

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
forwards it to the provider that minted the handle as the common opcode
`QUERY_OP` (`0x00FE`), with the output buffer as the call's `arg`: the
contract is resolved from the handle, not from the opcode's class byte.
Both kernel-internal providers and PIC module providers answer `QUERY_OP`
through their ordinary dispatch function; there is no separate
query-callback ABI.

**2. Handle=-1 one-shot ops** (e.g. `object::PUT`, `object::HEAD`,
`object::DELETE`, `object::LIST`, `object::RETAIN`, `namespace::LIST`,
`namespace::RENAME`,
`namespace::DELETE`, `namespace::BIND`, `object::PUT_STREAMED_COMMIT`)
end their `arg` with the fence trailer (`abi::fence::trailer`): the last
`trailer::LEN` (64) bytes of the record, which the provider writes as
`[fence_len u16][Fence::encode bytes]` atomically with returning the op's
result; callers decode via `Fence::decode`. The fence travels in band
with the result so a crash between return and query cannot lose it, and
an answer whose fence cannot be delivered is not an answer.

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

### Byte durability and name durability are separate fences

A file's bytes can be durable while the directory entry that finds them is
not. The `file.data` / `fs` contract therefore fences the two separately,
and a consumer building a crash-recoverable artefact needs both:

| Fence | Opcodes | Proves |
|---|---|---|
| Byte durability | `FSYNC`, or `FSYNC_SUBMIT` + `FSYNC_POLL` | The file's contents and its own recorded size are on non-volatile media |
| Name durability | `FSYNC_NAME`, or `RENAME` | The parent-directory entry that resolves the path is on non-volatile media |

File `fsync` is not name publication on any provider. The two supported
publication recipes are:

1. `OPEN_CREATE`(final) → `WRITE` → `FSYNC` → `FSYNC_NAME`(final). Crash
   leaves the name absent, or present over a prefix of the bytes — correct
   for self-describing artefacts (a WAL segment with an in-band
   terminator).
2. `OPEN_CREATE`(temp) → `WRITE` → `FSYNC` → `CLOSE` → `RENAME`(temp →
   final). Crash leaves the old name or the new complete artefact —
   correct for all-or-nothing artefacts (snapshots, pointer records,
   content-addressed bodies).

Both are optional capabilities (`caps::FSYNC_NAME`, `caps::RENAME`). A
consumer that needs crash-safe publication queries `CAPS` and fails closed
when the bit it needs is clear.

### The object-model surface

`STAT` answers one 32-byte record, `[size u64][mtime u64][ino u64][nlink
u32][0 u32]`; `ino` is 0 where the volume has no stable file identity and
`nlink` 0 where names are not counted. `LINK` and `SYMLINK` cover what an
inode-based filesystem carries and FAT32 does not: a second name for a file,
and symbolic links. A provider answers only what its format holds and clears
the bit otherwise — FAT32 clears both and reports `ino` 0, `nlink` 1, which
is honest rather than degraded. The host provider serves `RMDIR`, `LINK` and
`SYMLINK` and a real `ino` to the node because `fstat`, `link(2)` and
`readlink(2)` already answer them. `SEEK` takes exactly `[offset u64]` and
answers 0.

The contract carries no permission model: no user, group or mode bits. Who
may reach a file is decided by which owner's root the provider resolves it in
(§5, "What a workload reaches"), never by credentials stored on the file. A
format's own permission fields stay inside its provider.

`ino = 0` is defined as "this volume has no stable file identity", not as a
valid identity, and nothing may infer identity from anything else — a start
cluster is not an inode number, because FAT32 reuses freed clusters and two
files that never coexisted share one.

Ownership is *reported*, and enforcement of a per-owner policy is a separate
question answered by `query_key::CALLER_OWNER`: the owner of the module that
invoked the current provider frame. It is a query rather than an argument on
`provider_call` because the kernel already holds the fact, and a field every
call carried could only restate it.

Publication lives on the byte surface rather than moving to
`storage.namespace` because `OPEN_CREATE` and `MKDIR` are already the
fused `BIND` + open forms (see `namespace.rs::BIND`); `FSYNC_NAME` and
`RENAME` complete that fusion. A filesystem provider whose directory
entries live inside the byte surface publishes names here; a split provider
(an index without bytes) publishes them through `storage.namespace`. The
two remain equivalent operations achieving the same fence.

### Provider semantics in that vocabulary

**Linux.** Byte durability is `fsync(2)` on the file descriptor. Name
durability is `fsync(2)` on the parent directory (`FSYNC_NAME`) or, for
`RENAME`, `rename(2)` followed by an fsync of the destination parent and,
when it differs, the source parent. `RENAME` replaces an existing
destination atomically. Achieved fence: `LocalDurable`.

**FAT32.** Byte durability is the block source's Flush after the data
sectors and the file's own directory-entry size. The async surface
(`WRITE_ASYNC` + `FSYNC_SUBMIT`/`FSYNC_POLL`) runs a two-stage
data-then-metadata state machine: each ticket snapshots the file's size
and first cluster at submit, waits for the device fence over the data,
then submits that snapshotted directory entry through the same ring
behind a second fence. A successful poll therefore proves data *and*
size metadata durable, and never publishes a frontier newer than the
ticket it belongs to. The entry is only rewritten when a ticket's
frontier exceeds what has already been submitted, so out-of-order polls
cannot move the on-media size backwards. A preallocated fixed-capacity
file has no metadata to publish and skips the second stage entirely.

Name durability on FAT32 is `FSYNC_NAME`: every name-minting op
(`OPEN_CREATE`, `MKDIR`, `UNLINK`, `RMDIR`) already writes its directory
sector synchronously, so the opcode resolves the parent and issues the device
Flush that commits it.

A name that does not fit 8.3 is carried as a long-name companion set written
*in front of* the entry it names, with a synthesised `BASE~N.EXT` alias in
the 8.3 field the format indexes by. The companions land before the entry and
are retired after it, so a crash can only leave companions naming nothing —
which every reader ignores. Lookup matches whichever form the name is in: the
alias depends on what else is in the directory, so it cannot be re-derived
from the caller's name, and a provider that generated aliases without also
matching on the companion run would let a caller write a file it could never
open again.

`RENAME` has no single-sector form when the two entries fall in different
sectors, so it is ordered to be recoverable instead. An intent record in
an unused reserved sector — a region no FAT32 reader interprets — names
both entries together with the exact images they are expected to hold.
The sequence is: arm the record, publish the destination entry, retire
the source entry, disarm; every step commits through the device Flush.
Mounting the volume replays the record ahead of the first operation,
comparing the on-media entries against those images: destination
published with the source still live completes the retirement,
destination untouched rolls back, and anything else leaves the directory
alone. No interruption leaves the artefact reachable by no name.

Two consequences follow. Between publication and retirement both names
exist, each naming the same cluster chain, so a volume read by another
FAT32 implementation after a power cut and before this provider replays
the record shows the source a completed rename would have removed. And
the capability bit reads the mounted volume's geometry: it stays clear on
a volume whose reserved region cannot hold the record, and a consumer
that needs all-or-nothing publication there must use recipe 1 over a
self-describing artefact, or refuse to run on that volume.

---

## 3. Leased mesh Handles

Source: `crates/fluxor-abi/src/contracts/storage/handle.rs`.

Opening a namespace prefix, an object, or an event stream produces a
*handle*: the value the caller subsequently uses to read, watch, or
close. Storage handles compose the mesh primitives (`mesh.md`):

```rust
// crates/fluxor-abi/src/contracts/storage/handle.rs
pub struct StorageHandle {
    pub object: ObjectId,        // mesh primitive #1
    pub kind: HandleKind,        // Object | Namespace | Stream
    pub permissions: u16,        // mesh permission bits of the grant (mesh primitive #2)
    pub slot: u16,               // provider-local FD; crosses the syscall boundary
    pub not_after: u64,          // mesh primitive #8 (Lease)
    pub hint: LocationHintBlob,  // mesh LocationHint, opaque blob
    pub revoked: bool,           // revoked by issuer or provider on unmount, reconfigure
}
```

Lifecycle rules:

- A provider hands out a small integer slot index. The integer is what
  crosses the syscall boundary; `StorageHandle` is the typed Rust view for a
  provider or host-side caller that keeps the slot's authority and lease.
- The kernel gateway refuses a gated module any provider handle it was not
  minted, and releases the handle on `CLOSE` (`module_isolation.md`).
- The Linux key store, configured with mesh roots, binds every op to a
  verified grant (§3.1). Without roots it, the bcm2712 store and the HTTP and
  wasm object providers issue plain slot indices: a slot carries no
  capability, lease or revocation state, and their only handle limit is the
  slot table (a full table answers `ENOMEM`).
- A provider that binds a handle to a verified mesh grant
  (`crates/fluxor-abi/src/contracts/mesh/capability.rs`, [`mesh.md`](mesh.md#authority)) uses
  the vocabulary in `handle.rs`. Storage has no permission vocabulary of
  its own: the handle carries the grant's mesh permission bits, and each
  operation class needs one — `StorageAccess::Read` (`GET`, `HEAD`,
  `RANGE_GET`, `LIST`, `LOOKUP`, `STAT`) needs `ReadState`, `Write`
  (`PUT`, the streamed put, `DELETE`, `RETAIN`, `RENAME`, `BIND`) needs
  `SendCommand`, `Subscribe` (`SUBSCRIBE`, `CHANGES`) needs `Subscribe`,
  and `Delegate` needs `Delegate`. `StorageHandle::allows` is the check.
- `not_after` is an absolute monotonic timestamp (kernel `time_ns`). Such a
  provider refuses ops with `now >= not_after` and frees the slot, and
  takes the earlier of its own lease and the grant's expiry
  (`lease_bound_ns`), so the handle never outlives its authority.
- Revocation by such a provider (an unmount, a replicated store
  reconfiguration, an explicit revoke from the issuer) flips `revoked` and
  frees the slot; the next op against it fails with `EACCES` or `ENODEV`.

### 3.1 Presenting a grant to a store

Source: `crates/fluxor-abi/src/contracts/storage/object.rs` (`PRESENT`, `grant`),
`modules/foundation/store`.

A module reaches a guarded store through `provider_call`, which has no
session for the mesh's `MSG_CAP_PRESENT` to ride. So `storage.object` has
its own presentation op:

1. `PRESENT` (`0x0F2B`) names a scope in its `arg` and carries a
   capability chain as its `data` span. A scope is a key prefix ending `/`
   (`photos/`). The chain's leaf names the
   scope's object, `grant::scope_object`: SHA-256 over a domain tag and the
   scope, truncated to an `ObjectId`. `fluxor modules cap mint --scope
   photos/` issues one.
2. The store verifies the chain against its roots and its trusted clock
   and answers a grant handle. A refused chain answers `EACCES`, with its
   `Refusal` written into the request's first byte. The chain rides the
   `data` span, so a chain of any length is presented without growing the
   record.
3. Every later op passes the grant as its `handle`: `PUT`, `GET`, `HEAD`,
   `DELETE`, `LIST`, `RETAIN` and `PUT_STREAMED_OPEN`, which otherwise take
   `-1`. The
   store admits an op only when all of these hold:
   - its key, or `LIST`'s prefix, lies inside the scope;
   - the grant carries the bit its `StorageAccess` class needs;
   - the grant's window is still open by the trusted clock.
4. A read handle opened under a grant dies with it, and `CLOSE` on the grant
   ends both.

Anything else is `EACCES`:

- an op on `-1`;
- a key outside the scope, or a missing permission;
- an expired grant, or no trusted clock;
- a grant presented by another module, or by an earlier occupancy of the
  caller's scheduler slot.

The store's namespace surface cannot carry a grant, so a guarded store
refuses it entirely rather than list what a scope hides.

Roots are the `store` instance's `roots` param, up to two 64-hex Ed25519
public keys, the second for a rotation: a store with roots is guarded. Roots
that do not parse fail the instance, rather than open it unguarded, and a
guarded instance requires `time.wall` (its trusted clock, `[[requires_when]]
active_when_params = ["roots"]`), so a target without one refuses the graph.
Without `roots` the store is an unguarded local
store: `PRESENT` answers `ENOSYS` and an op with `handle = -1` is served
without a grant. The chain is verified in the module, with the SDK's
SHA-256 and Ed25519; the kernel holds no roots.

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
  of `HandleKind::Stream`, or watch a prefix with `namespace::SUBSCRIBE`
  and read what changed with `CHANGES` (§5, Subscriptions).

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

`object::PUT` is single-shot — the body is the call's `data` span, one
in-memory blob. Larger writes compose through four `storage.object` opcodes
(`crates/fluxor-abi/src/contracts/storage/object.rs`):

```
PUT_STREAMED_OPEN   (handle = -1)  →  stream handle
PUT_STREAMED_WRITE  (handle = sh)  →  one chunk appended as one Event
…
PUT_STREAMED_COMMIT (handle = sh)  →  atomic promotion + fence trailer
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
written into COMMIT's fence trailer (its whole `arg`) so the caller records
it in band with the success return. `PUT_STREAMED_ABORT` releases the staging
events; subsequent reads of `<key>` see no trace of the partial sequence.

There is no separate "multipart" surface, and `object::PUT` is not
stretched into a streaming op: `PUT` stays a small-blob single-shot, and
large bodies compose through the four streaming opcodes above.

### Key reference, retention and legal hold

`object::PUT` and `object::PUT_STREAMED_OPEN` carry, and the `object::HEAD`
record reports, one block (`object::Kept`):

```
[key_ref_len: u8][key_ref][retain_until_ms: u64 LE][legal_hold: u8]
```

`key_ref` names the key that sealed the object, at most `KEY_REF_MAX` (64)
bytes; the store keeps and returns it and never interprets it.
`retain_until_ms`, 0 for none, is judged on the store's clock. While an object
is retained or held, a `DELETE` of it and a `PUT` or `PUT_STREAMED_COMMIT` over
it are refused `ERETAINED`, decided at the write's linearization point.

`object::RETAIN` (`0x0F2C`) changes a live object's retention and hold in the
same log order as writes: retention only extends, and a hold can be set and
cleared. A grant authorizes it with the write permission.

A provider that cannot keep these refuses a non-empty `key_ref`, a non-zero
`retain_until_ms`, a `legal_hold` and `RETAIN` with `ENOSYS`, never ignoring
one, and reports none in `HEAD`. Every provider in this tree refuses them. A
store that keeps them is one whose writes are durable and logged.

---

## 5. Platform providers

The host platforms serve the storage surfaces the node itself reaches
through dispatchers built into the runtime:

- **Linux `file.data`** — `src/platform/linux/providers.rs`
  (`linux_fs_dispatch`), libc-backed random-access file I/O with the
  per-handle fence recording described in §2. It is registered node-only
  (`provider::register_node_only`): a caller acting with an authority of
  its own is answered `EACCES` however it reaches it — by class byte or
  a `platform` bind.
- **wasm peers** — `src/platform/wasm/fs.rs`, `namespace.rs`, and
  `object.rs` serve the same three contracts in the browser host. The
  wasm `storage.object` answers `LIST` with `ENOSYS`: its reads fall
  through to `fetch()` against the page origin, which cannot be
  enumerated, and a listing of the written layer alone would omit objects
  `GET` serves.

Every other storage surface is a module a graph composes: the versioned
store (`modules/foundation/store`), a directory listing over `fs`
(`modules/foundation/fs_namespace`, LIST/STAT under a `root` param, over
`fat32` or the Linux host fs alike), the files under such a directory read
as objects (`modules/foundation/file_object`, HEAD/GET/RANGE_GET under the
same `root`, composed beside `fs_namespace`), a store over a filesystem
(`fs_object`), and a workload's rooted `fs` (`modules/foundation/owner_fs`).
No target answers `storage.object` or `storage.namespace` as a platform
fact: a graph that requires one without composing a provider is refused at
compose, not answered `ENOSYS` at its first call.

### What a workload reaches

A workload runs for an owner other than the node owner. A provider layer is
owner-scoped or workload-scoped (`provider_scope`):

- an **owner-scoped** layer serves the owner whose module registered it,
  and owners acting with that owner's authority. The node's provider
  modules (its `fat32`, its `fs_object`, its `mount`, its `store`) are
  invisible to a workload, and a workload's own provider modules serve that
  workload alone;
- a **workload-scoped** layer serves every caller acting with an authority
  of its own, and no caller acting with the node's. Only a node-owned
  module registers one (`EACCES` otherwise), and only for a contract the
  registry marks `workload_served` (`fs`). It is how a workload reaches what
  the node holds: rooted, and charged to its own owner.

An owner admitted to act with the node's authority (`ADD_FLAG_CREATOR_AUTHORITY`,
see [reconfigure.md](reconfigure.md#adding-a-subgraph-with-the-nodes-authority))
is not a workload here. It reaches the node's layers and the node-only
platform providers as the node does (host paths on Linux), holds no storage
line and is never rooted. Its own layers still serve it alone. Every handle a
provider hands it is stamped with its own owner, answers that owner alone and
is closed when it is released.

**The workload layer.** A node graph that admits workloads with storage
composes `owner_fs` above its own `fs` (`fat32`, or the Linux host fs):

```yaml
  - name: owner_fs
    root: /owners          # Linux: a host directory such as /var/lib/nanocloud.io/owners
```

`owner_fs` resolves a workload's paths beneath `<root>/<owner uid hex>/files/`,
refusing `..`, a backslash or a NUL; a leading `/` is the root. It reaches
the layer beneath with an ordinary call in its own frame: its own layer is
invisible to the node, so the call lands on the node's `fs`. Every handle is
a slot of its own table, stamped with its opener (`EBADF` to anyone else),
at most `max_open_per_owner` (32) per owner. `LINK`, `SYMLINK` and
`READLINK` are `ENOSYS` and absent from its caps, so nothing inside a root
is ever a link it made; a symlink the host plants is not followed out by
any path `owner_fs` builds, and lexical confinement plus the absence of link
ops is the whole confinement on every target. Nothing in the layer waits:
making, charging and removing a root are bounded jobs across steps, and a
call that finds its root not ready is `EAGAIN`.

**Storage lines.** The kernel knows a cap and a count per owner, nothing
about what a byte of storage is. A `CREATE` installs the owner's storage
line from its header (`storage` byte: `STORAGE_OWN_ROOT` installs it,
capped at `storage_bytes`, 0 uncapped; `STORAGE_NONE` installs none); a
live add holds an uncapped one, an owner acting with the node's authority
none. `owner_fs` charges with `resource::LEDGER_CHARGE` /
`LEDGER_RELEASE`, which take no owner: the kernel charges the frame's
caller, so a provider charges only an owner it is serving, and only a
module holding a workload layer may charge at all. An owner with no line is
refused its first charge, so it never gets a root. The costs are the
layer's, one rule on every file system: a file costs its size plus 4096
bytes, a directory or any other name 4096. A `WRITE` that would grow a
file, a `PREALLOCATE`, an `OPEN_CREATE` or `MKDIR` of a new name past the
cap is `ENOSPC`; an unlink, a truncate or a rmdir gives the bytes back. What
an existing root already holds is charged when the owner first reaches it,
past its cap if need be (`LEDGER_HELD`): over its cap it can shrink but not
grow.

**Release.** A root is made when an owner first touches storage and removed
when the owner is released (a `DESTROY`, a `KILL`, a rolled-back
admission): the kernel's `OWNER_RELEASED` record carries the owner's uid, so
`owner_fs` removes a root the owner never touched this boot. The removal is
tombstoned before its first unlink, so a root half removed by a power cut is
finished rather than reused. Nothing else removes a root, so it survives a
restart, and an owner admitted again under the same identity finds what it
held, charged to it again. Data that must outlive the owner belongs to a
volume.

**Volumes.** A graph workload's volumes are the workload layer's to lend, not
its `CREATE`'s (the graph backend answers a required `workload::volume`
entry `ENOSYS`). The node agent writes records to `owner_fs`'s `ctl` input
before the workload is created: `ADD{uid, dst, volume, path, ro}` /
`REMOVE`, an `ADD` idempotent per `(uid, dst)`. `volume` names a keyed `fs`
backend (bound by name) or `platform` (the Linux host path `path`); a
workload path at or under `dst` (longest match) is served there, uncharged.
A read-only volume refuses every change `EROFS`; the volume's own name is
`EBUSY` to `UNLINK`, `RMDIR` and `RENAME`; a `RENAME` between a volume and
anything else is `EXDEV`; a `REMOVE` revokes the handles open on it.
`owner_fs` drains its `ctl` at the top of every call and step, so a record
written before the `CREATE` is applied before the workload's first call.

**A workload's own store.** A workload that wants watchable keys composes
`store` in its own subgraph over its rooted `fs` (`dir` inside its root).
The store's log is files in the owner's root, so it is charged to the owner
and goes with it.

**Admission.** A workload whose modules claim a contract that nothing
serves it — not its own subgraph, not a workload layer, not a platform
provider that serves workloads — is refused at `CREATE` (`ENOSYS`), not
answered at its first call. The composer leaves a workload's claim of a
`workload_served` contract to that check: what serves it is the node's, not
the workload's graph.

### The versioned watchable key store

Some consumers do not want a filesystem or a byte range; they want keys they
can watch. The `store` module (`modules/foundation/store`) serves
`storage.object` and `storage.namespace` over one keyspace with one revision
clock, on Linux, bcm2712, UEFI and RP2350 alike, and a graph selects it by
composing it:

```yaml
  - name: store
    dir: /store            # its log directory on the `fs` beneath
    durable: on            # off: RAM only
```

Its tables come from its heap, sized by the composer from its params
(`objects`, `value_bytes`, `history`, `reads`, `writes`, `grants`,
`stage_max`) and from the graph's declared `store_subs` demand. A node
composes one over its own volume; nothing in the environment names or moves
it.

- **Durable** (`durable: on`, `requires_contract = "fs"`): an append log
  `<dir>/store.log` of records `[rev u64][op u8][key_len u16][val_len u32][key][val]`,
  written through `fs` and fenced (`FSYNC`) before the write is acknowledged;
  a `PUT` answers `EINPROGRESS` until its record is fenced, and the same
  request asked again collects the outcome. One write is in flight at a
  time; another is `EBUSY`. The log is never reopened for appending: the
  store replays it, copies its valid records to `store.cpy`, publishes that
  as `store.bak`, rewrites `store.log` from it and removes the backup, so a
  crash at any point leaves the old log or a complete backup, and a torn
  tail is cut. A complete record that cannot be applied is corruption, and
  the open is refused rather than dropping the records behind it. An
  acknowledged write reports `LocalDurable` on the `fs`'s device.
- **RAM** (`durable: off`): no `fs`, and `Fence::RevisionMonotone`, never
  `LocalDurable`, because under-reporting durability is the safe direction
  and a caller must not conclude a write outlived a power cut.

A full object table is `ENOMEM`, an exhausted value arena `ENOSPC`; neither
evicts a live key, since a consumer reads a missing key as a deletion and
would tear down whatever that key named.

The store refuses (`EINVAL`) a `PUT` of the empty key, which is the
end-of-listing cursor on `LIST`, of
a key that is not UTF-8, and of a key longer than `STORAGE_KEY_MAX` (255
bytes, `handle.rs`), the longest name either listing carries. A
precondition kind it does not know, or an `ETAG` without a whole revision,
is `EINVAL` rather than an unconditional write. `HEAD` into a buffer too
small for its record answers `ENOMEM`. A `PUT`, `HEAD` or `DELETE` whose
`arg` cannot hold its fence trailer is `EINVAL`, refused before the op acts,
as the contract states for every op that carries a fence trailer.

It keeps a monotone revision clock, uses a key's revision as the CAS
token, pages `namespace::LIST` and `object::LIST` with a cursor, and serve
`CHANGES` from a bounded change history (`history`) — a read from before that window
is answered `LOST` and the watcher relists, rather than being handed a gap
(see Subscriptions below). A page that cannot
hold one entry is `ENOMEM` on both listings, never an empty page that
returns the cursor it was given. Both cursors are the last name the page
returned, so a write behind the cursor never shifts the page after it.

### Subscriptions

Source: `crates/fluxor-abi/src/contracts/storage/namespace.rs` (`SUBSCRIBE`,
`CHANGES` and their codecs), `crates/fluxor-sdk/src/cores/table_consumer.rs`
(the consumer every table follows), `modules/fixtures/mem_ns` (a provider
small enough to read whole).

A subscription is a doorbell, not a stream. The store never writes a
consumer's channel: no key, value or record is pushed anywhere, and a
consumer needs no self-wired port to receive one. It learns that something
under its prefix changed, and reads what it needs, in bounded pages.

- **A signalling handle.** `SUBSCRIBE` (`[prefix][flags]`) mints a
  subscription handle that signals (`abi_layers.md`, Handles): the store
  answers its own index, and the kernel hands it the subscription's doorbell
  (`kernel::BIND_DOORBELL`). A refusal is `ENOMEM`, and the `store`
  module counts it against the `store_subs` pool (`LEDGER_DENY`) and names
  it in the log; `mem_ns` also holds each owner to
  a quota of its table. Each `SUBSCRIBE` is its own subscription.
- **A ring per change.** A change under the prefix rings the subscription's
  doorbell — the `store` module and `mem_ns` alike, with
  `kernel::DOORBELL_RING` — and a burst of rings before the consumer polls
  costs one wake. The handle is its minter's alone: the kernel refuses it to
  any other owner, and its `LAST_FENCE` is `ENOSYS` — a subscription is a
  doorbell, not a view, and each read carries its own fence. A subscription
  ends with its handle: closing it, or releasing its minter, closes the
  store's index and frees the doorbell, so a ring after it rings nothing.
- **The consumer's step**: `HANDLE_POLL` on each subscription (`POLL_IN` once
  per ring: the poll takes it), marking each that rang *pending*; then a
  `CHANGES` read of each pending one, through its handle. *Pending* is
  cleared only by a page whose `more` is clear. Whatever the interleaving, a
  change is followed by a completed read that observes it: the ring follows
  the change, and the read follows the poll that took the ring.
- **What the consumer owes.** A read that fails leaves the consumer pending,
  with its token where it was, so it reads again rather than waiting for a
  change that may never come.

`CHANGES` answers one bounded page per call. Where it resumes is a token:

- **empty** — a relist: every current entry under the prefix, `Added`, with
  its value, paged by key. The first page pins the revision the walk
  answers for, an entry changed after it is left to the read that resumes
  from it, and the last page hands that revision back.
- **8 bytes** — a bare revision `since` (`changes::revision_token`): the
  changes after it.
- **anything else** — the provider's continuation (up to
  `changes::TOKEN_MAX` bytes, never exactly 8), echoed back verbatim. One the
  provider did not issue or no longer recognises is `EINVAL` or `LOST`, and
  the consumer relists.

A page whose `more` is clear always carries an 8-byte revision token; that is
what a consumer keeps at rest and resumes from. Records are read at the
store's current state, one per changed key: present → `Added` or `Modified`
with its current value and `mod_rev`, absent → `Deleted`. A key created and
deleted inside the window is reported `Deleted`, never omitted, and applying
by key is idempotent, so intermediate versions collapse and a consumer
converges on what the store holds. A page may cut inside a revision (one
write can touch several keys: a `mem_ns` `RENAME` touches two); a key whose
last change lies past the page's cut is left to the page that holds it, so no
`mod_rev` a consumer sees runs ahead of the read. `safe_rev` is the highest
revision the read has delivered whole: a consumer that hands resume points to
its own clients stamps them at most this. The page's fence is
`ViewConsistent` at the store's revision from the key stores, `Volatile`
from `mem_ns`.

A `since` older than the store can answer is `LOST` — the 410 of a watch —
and the consumer relists; so is a `since` past anything the store has issued
(a store that restarted empty). `EAGAIN` means "not now" (a busy device, a
spent walk budget); a read through its subscription is rung again when the
store can answer, so a consumer woken only by its subscriptions never stalls
on a wait. The key stores and `mem_ns` answer every read inside the call and
never answer `EAGAIN`.

| Provider | Change history | Walk per call |
| --- | --- | --- |
| Linux node store | 65536 revisions (`NODE_STORE_HISTORY`) | 4096 entries or keys (`CHANGES_SCAN_BUDGET`) |
| Linux workload store | 4096 revisions (`OWNER_STORE_HISTORY`) | as the node store |
| bcm2712 store | 128 revisions (`HISTORY`) | the retained history; a relist page, one pass of the object table per record |
| `mem_ns` | 32 entries (`LOG_CAP`) | 16 entries or bindings (`SCAN_BUDGET`) |

`table_consumer` is that protocol for a table: subscribe, poll, read pages
from the token and apply them by key, and on a cold start or `LOST` relist
into a shadow table that is swapped in only when the last page lands — a
table swapped in place is a torn table for any reader mid-scan. A module with
several tables steps each; each polls its own subscription. A refused `SUBSCRIBE` other than `EAGAIN` is asked again after
a backoff, so a full table is not asked, and refused, on every step. Every
store op goes to the store the consumer is given: the contract's default, or
by selector a keyed volume or `platform`; a module names it by a `str` param
it declares as its `storage.namespace` claim's `selector_param`.

### Listing names

One bound serves both listings' names: `STORAGE_KEY_MAX` (255 bytes,
`handle.rs`) is the longest key, entry name and cursor, and the longest
`object::LIST` prefix. It is the width of the `namespace::LIST` `name_len`
and trailing `cursor_len` (a `u8`), and the kernel gateway's argument copy
is sized to carry an `object::LIST` prefix and cursor of that length, so a
gated module can resume a listing at any key a provider holds. A
`namespace::LIST` prefix is a path, not a name, bounded by
`namespace::PATH_MAX` (1024): a filesystem provider's prefix is a host
directory at any depth.

`object::LIST` enumerates the keys under a prefix in ascending bytewise
order, one bounded page per call. A page carries at most `max_keys`
entries (`1..=LIST_PAGE_MAX`, 1000), each with the key, size, mtime and
etag `HEAD` would report, and ends with a cursor; an empty cursor ends the
listing. `namespace::LIST` pages the same way, each entry carrying a name
and a kind. The provider fills whole entries while keeping room for the
trailer that resumes after the last one (the cursor is that entry's key),
and refuses with `ENOMEM` when not even one entry fits, so every page but
the last makes progress (`list::min_out_cap`).

The cursor is the last name the page returned, and the next page resumes
strictly after it in name order; it is not a snapshot. A key written or
deleted between pages is seen or not according to whether it sorts after
the cursor, a write behind the cursor never shifts, skips or repeats an
entry, and a key present for the whole listing is seen exactly once. Each
page carries its own fence: `ViewConsistent` from the key stores,
`Volatile` from the filesystem, wasm and `mem_ns` namespaces. A key longer
than `STORAGE_KEY_MAX` cannot be carried by a cursor, so a provider that
meets one in range refuses with `EOVERFLOW` rather than skip it.

`namespace::LIST` names come in two shapes, and a provider states its
shape in `CAPS` with `caps::CHILD_NAMES`. A key-shaped provider (the key
stores, `mem_ns`; the bit clear) lists
whole keys under the prefix, so its cursor starts with the prefix. A
directory-shaped provider (the filesystem and wasm namespaces; the bit set)
lists the prefix's immediate children by name, so its cursor is a child
name and never holds `/`, and a consumer joins prefix and name with one `/`
to make the entry's key. A cursor of the wrong shape, or not UTF-8, was not
issued by the provider: `EINVAL`. An `object::LIST` entry's key is the key `GET`,
`HEAD` and `DELETE` take, and listing returns no handle. The request, page
and cursor codec is `object::list` and `namespace::list`; providers and
consumers share it.

| Provider | `object::LIST` | `namespace::LIST` |
| --- | --- | --- |
| Linux key store (`store.rs`) | served, over its ordered map | served, same map |
| bcm2712 key store (`store.rs`) | served, by ordered selection over its fixed table | served, same selection |
| Linux HTTP range provider (`object.rs`) | `ENOSYS` | — |
| Linux filesystem provider (`namespace.rs`) | — | served, immediate children of a directory in name order; a name that is not UTF-8 is not listed |
| wasm (`object.rs`, `namespace.rs`) | `ENOSYS` | served by the host index, in UTF-8 byte order |
| `mem_ns` fixture | — | served, over its binding table |
| `fs_object` | served, by a scan of its directory | served, same scan |
| `fs_namespace` | — | served, immediate children of a directory in name order; a name that is not UTF-8 is not listed |
| `file_object` | `ENOSYS`: its directory is `fs_namespace`'s to list | — |

On bare metal, `modules/foundation/fat32` provides `file.data` over a
`storage.block` channel: random-access reads through the FS contract,
reads and writes both riding `storage.block` requests on its `blocks` input
port (typically wired from `nvme.blocks`), and directory listing served
through the FS contract's `OPENDIR` / `READDIR`. It does not implement
the `storage.namespace` contract. Every directory or FAT walk is bounded
per call, by sectors read (`DIR_SCAN_BUDGET_SECTORS`,
`FAT_SCAN_BUDGET_SECTORS`) and by time (`CALL_BUDGET_US`), and answers
`EAGAIN` with its position saved, so a caller asks again with the same
arguments; the directories a path passes through are remembered between
calls, so one operation's paths under a long directory resolve together.
Once mounted, it settles the volume a step at a time — the free-cluster
summary, the clean bit, then the rename replay — and an operation that
arrives first settles the rest before it runs.

### A store over a filesystem: `fs_object`

`modules/foundation/fs_object` gives a board a store without a storage cluster:
it provides `storage.object` and a key-shaped `storage.namespace` (`LIST`
and `CAPS` only) over whatever serves the `fs` contract — `fat32` on bare
metal, the host directory on Linux. Each object is one file under its
`root` directory (default `/objects`), named by an 8.3 name drawn from 50
bits of SHA-256 of the key, with the key, content type and etag (SHA-256
of the body) in a header in front of the body. The name only finds the
file; the header says whose it is, so two keys that collide are told apart
and the second is refused `EEXIST`.

| Property | Behaviour |
| --- | --- |
| Keys | 1..=255 bytes of UTF-8 (`STORAGE_KEY_MAX`); any other key is `EINVAL` |
| Writes | `PUT` writes a temporary, fsyncs it and renames it over the object, answering `LocalDurable`; it needs `OPEN_CREATE`, `WRITE`, `FSYNC`, `UNLINK` and `RENAME` from the filesystem and is `ENOSYS` without them. `DELETE` unlinks and, with `FSYNC_NAME`, fences the removal |
| Preconditions | `ANY` and `ABSENT`; `ETAG` is `ENOSYS` |
| Crash | the old object or the new one, never a torn one; at worst a leftover temporary, which nothing reads and the next `PUT` of that key removes |
| Pacing | a write answers `EINPROGRESS` and is asked again with the same bytes; each ask does at most one filesystem operation that walks or writes. Reads and listings answer `EAGAIN` while the filesystem does |
| Concurrency | one write in flight (another is refused `EBUSY`) and one listing scan (another is answered `EAGAIN`); a request whose caller stops asking is superseded after `SUPERSEDE_AFTER` refusals |
| Listing | a page of at most `PAGE_KEYS` keys in key order, resumed after a cursor, each page a `Volatile` fence; a page opens every object in the store, so it suits tens or hundreds of keys |
| Not offered | grants (`PRESENT` is `ENOSYS`), streamed puts, change subscription, namespace `LOOKUP` / `STAT` |

### Files read as objects: `file_object` beside `fs_namespace`

`modules/foundation/fs_namespace` and `modules/foundation/file_object` read a
directory tree the `fs` contract serves — a music library, a set of covers —
without moving it into a store. Each provides one surface, so a graph
composes both; given the same `root`, they key a file the same way, by its
path beneath `root`, and a consumer LISTs through one and opens through the
other by that key.

| Property | Behaviour |
| --- | --- |
| Keys | the path beneath `root`, joined as `fs_namespace` joins a prefix: unset, `root` is `/` and the key is the path `fs` opens; set, a leading `/` stays beneath it. A component that climbs (`..`) or a NUL byte is `EACCES`; the confinement is lexical, as `fs` itself is |
| `root` | at most 96 bytes; a longer one fails `module_new` with a log line, in both modules, rather than being cut or ignored (which would serve `/`) |
| Reads | `GET` holds the file open as the handle (8 at once, `EBUSY` past them), `RANGE_GET` reads from any offset (a short count at the tail, 0 past it), `HEAD` answers size, mtime, no content type and the 8-byte etag `fs_namespace`'s `STAT` gives the same file; every read is `Volatile`, and the file system's `EAGAIN` is passed on |
| Absent | a key naming nothing, or a directory, is `ENOENT` from `GET` and `ENXIO` from `HEAD` |
| Writes | none: `PUT`, `DELETE`, `RETAIN` and the streamed puts are `EROFS`, and `CAPS` sets neither `WRITE` nor `LIST`. A consumer that also caches what it computes (a scan) composes a store for that |
| Owners | node-owned and owner-scoped, like `fs_namespace`: a handle answers its opener alone and goes with it on `OWNER_RELEASED` |

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
- Cross-provider rename / delete. `RENAME` is atomic within one provider;
  moving an entry between providers is a higher-level orchestration
  concern.
