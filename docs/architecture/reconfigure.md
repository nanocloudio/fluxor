# Live Graph Reconfigure

Source: `src/kernel/exec/scheduler/live_reconfig.rs`,
`src/kernel/exec/scheduler/setup.rs`, `tools/src/reconfigure.rs`

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
module in the graph, then re-instantiates each one through `module_new`.
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

## Drain-Then-Reset Model

The implemented reconfigure model is drain-then-reset:

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

Out of scope for the current reconfigure path:

- State preservation for surviving modules (all state is reset)
- Channel preservation between surviving modules
- Arena compaction (selective module replacement without full reset)
- Socket handoff to new module instances

None of these are needed for the supported reconfigure semantics; a
preservation-aware reconfigure path would be a separate design.

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
