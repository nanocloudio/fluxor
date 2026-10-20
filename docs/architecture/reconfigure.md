# Live Graph Reconfigure

Source: `src/kernel/exec/scheduler/live_reconfig.rs`,
`src/kernel/exec/scheduler/setup.rs`, `src/kernel/exec/scheduler/live.rs`,
`src/kernel/workload/owner.rs`, `tools/src/reconfigure.rs`

## Overview

Live graph reconfigure updates a running Fluxor graph by gracefully draining
admitted work before reset, subject to a bounded timeout. The scheduler
transitions through phases:

```
RUNNING -> DRAINING -> MIGRATING -> RUNNING
```

## Configuration

```yaml
reconfigure:
  mode: live              # "live" or "atomic" (default: atomic)
  drain_timeout_ms: 5000  # max drain wait (default: 5000)

modules:
  - name: web
    type: http_server
    drain:
      timeout: 3000      # per-module override
      policy: graceful   # "graceful" (default) or "immediate"
```

## Module Classification

Each module is classified as one of:

| Status    | Criteria | During DRAINING | Across MIGRATING |
|-----------|----------|-----------------|------------------|
| Survive   | Same binary + config + wiring | Normal stepping | Unchanged graph membership, re-instantiated state |
| Drain     | Changed, exports `module_drain` | drain() called, then normal stepping until Done | Replaced by the new definition, re-instantiated state |
| Terminate | Changed, no drain | Continues stepping, force-stopped in MIGRATING | Replaced by the new definition, re-instantiated state |

`Survive` names a property of the transition plan, not of the module
instance. A surviving module is one whose three identity hashes are
unchanged, so it appears in the new graph with the same binary,
parameters, and wiring, is not asked to drain, and is not force-stopped.
Its RAM state does not carry across: `prepare_graph` resets the state
arena, the channel and buffer registries, and the name arena for every
module in the graph, drops every provider layer a module registered, then
re-instantiates each one through `module_new` (which registers its
provider layers afresh).
The status therefore predicts what the new graph looks like, not what
the running instance keeps.

Module identity is defined by three hashes:
- **Binary identity**: module name hash (resolves to the same `.fmod`)
- **Config identity**: FNV-1a of serialised params (detects config-only changes)
- **Wiring identity**: FNV-1a of connected edges (detects topology changes)

## Adding Drain Support to a Module

Export `module_drain` from your module:

```rust
#[no_mangle]
#[link_section = ".text.module_drain"]
pub extern "C" fn module_drain(state: *mut u8) -> i32 {
    let s = unsafe { &mut *(state as *mut MyState) };
    s.draining = 1;  // Stop accepting new work
    0
}
```

The pack tool detects this export and sets header flag bit 3 (`drain_capable`).
During DRAINING, the scheduler calls `module_drain()` once (in reverse
topological order), then continues calling `module_step()` normally. When
your module has no more in-flight work, return `StepOutcome::Done` (1)
from `module_step()`.

## Releasing an Owner's Resources

A provider that holds resources on a consumer's behalf — scratch objects, open
files, staged writes — is told when that consumer's owner is torn down, so it
can reclaim them instead of holding them until the next reset.

Subscribe by exporting a marker:

```rust
#[no_mangle]
#[link_section = ".text.module_observes_owner_release"]
pub extern "C" fn module_observes_owner_release() -> u32 {
    1
}
```

The loader reads the marker after provider registration succeeds; a module that
registers no contract has no dispatch to call and is refused. A module that does
not export it is never notified, so a provider holding nothing per consumer pays
nothing.

The kernel then calls `module_provider_dispatch` with opcode `OWNER_RELEASED`
(`0x0C22`) and an 8-byte argument:

```
[slot: u16 LE][reserved: u16 = 0][generation: u32 LE]
```

Those are the same bytes `query_key::CALLER_OWNER` answers, so a provider
compares an owner it stamped against the one being released without
reformatting either. Compare BOTH fields: slots are reused, and matching on the
slot alone closes the live resources of whoever replaced the dead owner.

The notification runs before any teardown, on the scheduler thread, inside a
provider frame — the owner handle still resolves, the provider's state is still
live, and a handler may make syscalls exactly as it would in a normal step. It
is delivered from owner teardown itself rather than from the drain driver, so
the paths that never reach the drain driver (the `KILL` and `DESTROY` workload
verbs, and admission rollback) are covered by the same edge.

Each subscriber is called once per released owner, whatever number of contracts
it serves. The return value is ignored: a provider with nothing to release may
answer `-ENOSYS`.

After the subscribers, the platform's own hook runs with the same handle. On
Linux it closes every file the owner holds open, drops its store with the
reads, writes and watches on it, and removes its storage root. On bcm2712
it closes the handles the owner holds through its root and queues the root
for removal. The kernel keeps no table of storage handles: each platform
provider records which owner opened each handle and refuses it to any other,
so the hook alone is enough for nothing a workload opened to outlive it.

An owner acting with the node's authority (below) has no root, and the hook
removes nothing from the node's storage for it. It closes what the owner
opened: on Linux its host files, host processes, host namespace and HTTP
object handles, and its handles on the node's store; on bcm2712 its handles
on the node's store.

## Adding a Subgraph with the Node's Authority

Every live add is an owner of its own: it is freed, paused, charged and
released as one. Its modules run as that owner from their first
instruction: the add stamps each slot it takes before any module
instantiates, so what a module's `module_new` allocates, opens and registers
(its provider layers among them) is its owner's. While the add is
instantiating, the owner is `Reserved`: its own modules admit work for
themselves, nothing else admits work on its behalf until it is `Active`, and
only the add frees it (`FREE_OWNER` answers `-3`) by rolling itself back. A
slot a staged add holds is not free to another add, even before its module
is in.

By default an added owner is a workload: walled from the node's provider
layers, its storage rooted. A node component that places subgraphs to act on
its own behalf (an operator shell running a user's commands) sets
`ADD_FLAG_CREATOR_AUTHORITY` (`0x0001`) in the `AddSubgraph` header's `flags`
(bytes 6..8, big-endian). The owner then acts with the node's authority: it
reaches the node's provider layers and the platform's storage as the node
does and, on Linux, spawns host processes and binds ports as the node does,
outside the lease plan, while everything it opens is still stamped with its
own owner and goes with it.
It gains nothing an add cannot carry: node param tags are refused on every
add, this one included.

The rule, enforced by the decoder and the add:

- Only `APPLY_ADD` from a module honours the flag; the calling module is the
  add's creator. The creator must itself act with the node's authority (a
  node module, or a module of an owner admitted this way); a workload creator
  is refused `EACCES` before anything is allocated, so a workload can neither
  pass on what it does not hold nor gain it through an add of its own.
- Every other path that decodes an `AddSubgraph` names no creator and refuses
  the flag `EINVAL`: a workload `CREATE` (whose blob comes from off the node)
  and a boot graph's resident workloads.
- Every undefined flag bit is refused `EINVAL` on every path.

The owner holds no storage grant (no root is ever made for it), and its
authority is recorded on the owner table entry (`Authority::Node`), read
through `OwnerTable::authority_of` and `scheduler::caller_authority()`. What a
call reaches is decided by the caller's authority; what it holds is stamped
with `scheduler::caller_owner()`. `CALLER_OWNER` answers the owner, so a
provider scoping per consumer (scratch space) still scopes per subgraph.

## Modules for Workloads Staged at Runtime

A subgraph staged after boot names its modules by type, and a type resolves
only against the module table packed into the image. List the types a node's
workloads may be staged with under `workload_modules:`; they are packed
without being instantiated:

```yaml
workload_modules:
  - fat32
  - crypt_block
  - nbd_serve
```

An entry is a type name, or `{ type: <name>, variant: <variant> }` to pick a
build. Resident workloads' types are packed the same way. One image carries one
build of a type, so a variant must agree with the base graph's and every
workload's.

## Drain-Then-Reset Model

Reconfigure drains, then resets:

1. **DRAINING**: Modules with `module_drain` get a graceful shutdown period.
   In-flight requests complete. The drain has a bounded timeout.

2. **MIGRATING**: After drain completes (or times out), the scheduler performs
   a full destructive reconfigure through the same `prepare_graph()` path used
   at boot. All arenas are reset and all modules are re-instantiated.

The full reset avoids moving surviving module state blocks: modules may hold
absolute pointers into their own state, and relocating state would break
self-referential pointers without a state export/import contract. The drain
phase already provides the main value — in-flight work completes gracefully.

What this model delivers:

- **Zero in-flight request loss** for drain-capable modules (e.g., http_server)
- **Bounded drain timeout** prevents hung modules from blocking deployment
- **A/B fallback** on migration failure (full destructive reconfigure from the
  old config)
- **Build-time transition plan preview** via
  `fluxor inspect new.yaml --against old.yaml`

What reconfigure does not do:

- Preserve state for surviving modules (all state is reset)
- Preserve channels between surviving modules
- Compact arenas (selective module replacement without a full reset)
- Hand sockets off to new module instances

None of these is needed for drain-then-reset semantics; preserving state
across a reconfigure would be a different mechanism.

## CLI: Transition Plan Preview

```bash
$ fluxor inspect new_config.yaml --against old_config.yaml

Reconfigure mode: live
Drain timeout: 5000ms

ID    Module            Action        Drain
----  ----------------  ------------  --------
0     cyw43             survive       n/a
1     ip                survive       n/a
2     tcp_listen        survive       n/a
3     http_server       drain         3000ms
4     my_handler        terminate     none

Summary: 3 survive, 1 drain, 1 terminate, 0 add, 0 remove
```

## Drain Ordering

1. **Stop-intake** (reverse topological): `module_drain()` called on downstream
   consumers first, then upstream producers.

2. **Drain-completion** (forward topological): Upstream modules finish draining
   first, then downstream. A module cannot reach Drained state until all
   upstream draining modules are Drained.

## Timeout and Forced Termination

If the drain deadline is exceeded, all still-draining modules are
force-terminated. Their in-flight work is lost — the same outcome those
modules would see under an atomic reconfigure.

## Header Flag Layout (module header `reserved[0]`)

| Bit | Name | Description |
|-----|------|-------------|
| 0 | mailbox_safe | Can consume from mailbox channels |
| 1 | in_place_writer | Uses buffer_acquire_inplace |
| 2 | deferred_ready | Needs init time before downstream runs |
| 3 | drain_capable | Exports module_drain for live reconfigure |
| 4 | isr_module | Exports module_isr_init / module_isr_entry (Tier 2) |
| 5 | wasm_payload | Module body is a wasm payload (set by `pack_fmod_wasm`, read by `src/platform/wasm.rs`) |
| 6-7 | reserved | Must be 0 |
