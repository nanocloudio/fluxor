# Kernel Concurrency Model

The kernel ships on four platforms with different concurrency profiles:

| Platform | Cores | Domains | Pump shape |
|---|---|---|---|
| RP2040 / RP2350 | 1 (effective) | 1 | single synchronous loop on core 0 |
| BCM2712 (Pi 5) | 4 | up to 4 (`MAX_DOMAINS = 4`) | one bare-metal pump per core, each runs its assigned domain's modules |
| Linux | 1 (cooperative) | 1 | std thread on the main process |
| WASM | 1 (single-threaded) | 1 | host calls `kernel_step()` on its event loop |

This document classifies every `static mut` in `src/kernel/` by access
pattern. Each kernel file's top-of-file comment summarises the relevant
access pattern and points back here.

## Three access classes

Every shared mutable state in the kernel falls into one of three access
classes; the safety story is different for each.

### Boot-only — written before the graph runs

Everything from `kernel::boot()` through the final `instantiate_one_module`
runs on core 0 only. Secondary cores spin in the trampoline waiting
for `INIT_COMPLETE.store(1, Release)` (see
`src/platform/bcm2712.rs`). Statics written exclusively in that window
need no synchronisation:

- `src/kernel/module/loader.rs`: `STATE_ARENA`, `STATE_ARENA_OFFSET`,
  `FREE_LIST`, `FREE_COUNT`, `PIC_IRQ_DISABLED_COUNT`
- `src/kernel/boot/config.rs`: `CONFIG_ARENA`, `ARENA_OFFSET`
- `src/kernel/ipc/buffer_pool.rs`: `BUFFER_ARENA`, `BUFFER_ARENA_OFFSET`
- `src/kernel/exec/scheduler/`: `STATIC_CONFIG`, `STATIC_LOADER`,
  `PARAM_BUFFER`, `NAME_STORAGE`, `NEXT_NAME_SLOT`,
  `INSTANTIATION_STATE`, `INSTANTIATION_IDX`, `MODULE_STATE_PTR`
- `src/kernel/module/syscalls.rs`: `SYSCALL_TABLE`, `HARDWARE_CONTEXT`,
  `SYSTEM_EXTENSION`, `DEV_QUERY_EXTENSION`
- `src/kernel/sys/hal.rs`: `HAL_OPS`

After init these are read-only. All four platforms publish
`INIT_COMPLETE` (or its equivalent; for RP/Linux/WASM there is no
secondary core to release) before any code reads them. Writes during
reconfigure happen on core 0 with all secondaries parked, restoring
boot-only semantics for the duration of the rebuild.

### Per-core-sliced — steady state, no byte shared

Some state is touched on every step but is sliced by core or by module
so two cores never touch the same byte:

- `MODULE_HEAPS[i]` (`src/kernel/mem/heap.rs`) — module *i*'s heap.
  Module *i* only steps on its assigned core, so each heap sees a
  single writer.
- `FAN_BUFS[d]` (`src/kernel/exec/scheduler/module_types.rs`) —
  per-domain scratch for tee / merge. Tee and merge inherit their fan
  group's `domain_id`; a domain runs on exactly one core, so
  per-domain indexing keeps each core on its own buffer.
- `CURRENT_MODULE_PER_CORE[c]` (`src/kernel/exec/scheduler/merge.rs`)
  — `AtomicU32` array indexed by `hal::core_id()`.

Per-module / per-core arrays in this category are not annotated as
`static mut` blanket — each entry is independent and the indexing rule
must be visible at every use site.

### Cross-core-shared — steady state, true sharing

A handful of statics are shared across cores in steady state. Every one
must be an atomic or guarded by a lock:

- `CHANNELS[i]` (`src/kernel/ipc/channel.rs`) — each `ChannelSlot`
  uses `AtomicI8`/`AtomicU8`/`AtomicU32`/`AtomicPtr`/`AtomicBool` for
  state + buffer + ioctl handler fields, plus an internal spin-wait
  `lock` for the FIFO critical section. Cross-core safe.
- `BUFFER_REGISTRY[i]` (`src/kernel/ipc/buffer_pool.rs`) — each
  `BufferRegistrySlot` is fully atomic. Cross-core safe.
- Event queues (`src/kernel/ipc/event.rs`) — atomic ring per event
  handle.

Rule of thumb for new code: any state visible to PIC modules via
syscall traffic is cross-core-shared by default; any state populated by
`populate_static_state` / `prepare_graph` is boot-only; anything else,
justify in a comment.

## Function-local `static mut`

Two function-local `static mut`s exist in
`src/kernel/module/syscalls.rs` (`LOGGED` in the EAGAIN logger
throttle, `LOGGED_NULL_STATE` in the null-state logger). Both can race
across cores; the worst case is a duplicate log line per process
lifetime. Acceptable.

## What this document is not

It is not a SAFETY proof — Rust still requires `unsafe` for every raw
access to these statics. It is the contract readers should hold
against the call graph when auditing one of those `unsafe` blocks. If
the classification above is ever wrong for a static, the fix is to
update both the comment and this document.
