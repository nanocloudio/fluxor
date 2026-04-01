# Live Graph Reconfigure

## Overview

Live graph reconfigure allows updating a running Fluxor graph without dropping
in-flight work. The scheduler transitions through four phases:

```
RUNNING -> DRAINING -> MIGRATING -> RUNNING
```

## Configuration

```yaml
reconfigure:
  mode: live           # "live" or "atomic" (default: atomic)
  drain_timeout_ms: 5000  # max drain wait (100-30000ms, default: 5000)

modules:
  - id: 1
    type: http_server
    drain:
      timeout: 3000     # per-module override (must be <= global)
      policy: graceful   # "graceful" (default) or "immediate"
```

## Module Classification

Each module is classified as one of:

| Status    | Criteria | During DRAINING |
|-----------|----------|-----------------|
| Survive   | Same binary + config + wiring | Normal stepping |
| Drain     | Changed, exports `module_drain` | drain() called, then normal stepping until Done |
| Terminate | Changed, no drain | Continues stepping, force-stopped in MIGRATING |

Module identity is defined by three hashes:
- **Binary identity**: module name hash (resolves to same .fmod)
- **Config identity**: FNV-1a of serialized params (detects config-only changes)
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

## V1 Implementation (Current)

The v1 implementation provides **drain-then-reset**:

1. **DRAINING**: Modules with `module_drain` get a graceful shutdown period.
   In-flight requests complete. The drain has a bounded timeout.

2. **MIGRATING**: After drain completes (or times out), performs a **full
   destructive reconfigure** — same as the existing `prepare_graph()` path.
   All arenas are reset, all modules re-instantiated.

### Why V1 Uses Full Reset

Arena compaction (moving surviving module state blocks) is deferred to v2:

- Many existing modules may use absolute pointers in state (not audited)
- Moving state breaks self-referential pointers without `module_state_export/import`
- The drain phase already provides the key value: in-flight work completes gracefully
- Full reset is safe, simple, and matches the existing well-tested behavior

### What V1 Delivers

- **Zero in-flight request loss** for drain-capable modules (e.g., http_server)
- **Bounded drain timeout** prevents hung modules from blocking deployment
- **A/B fallback** on migration failure (full destructive reconfigure from old config)
- **Build-time transition plan preview** via `fluxor diff old.yaml new.yaml`

### What V1 Does NOT Deliver

- State preservation for surviving modules (all state is reset)
- Channel preservation between surviving modules
- Arena compaction (selective module replacement without full reset)
- Socket handoff to new module instances

These are planned for v2.

## CLI: Transition Plan Preview

```bash
$ fluxor diff old_config.yaml new_config.yaml

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

If the drain deadline is exceeded, all still-draining modules are force-terminated.
Their in-flight work is lost — equivalent to the current atomic reconfigure for
those specific modules.

## Header Flag Layout (ABI v2 reserved[0])

| Bit | Name | Description |
|-----|------|-------------|
| 0 | mailbox_safe | Can consume from mailbox channels |
| 1 | in_place_writer | Uses buffer_acquire_inplace |
| 2 | deferred_ready | Needs init time before downstream runs |
| 3 | drain_capable | Exports module_drain for live reconfigure |
| 4-7 | reserved | Must be 0 |
