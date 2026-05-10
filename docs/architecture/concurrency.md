# Kernel Concurrency Model

The kernel ships on four platforms with different concurrency profiles:

| Platform | Cores | Domains | Pump shape |
|---|---|---|---|
| RP2040 / RP2350 | 1 (effective) | 1 | embassy executor on core 0 |
| BCM2712 (Pi 5 / CM5) | 4 | up to 4 (`MAX_DOMAINS = 4`) | one bare-metal pump per core, each runs its assigned domain's modules |
| Linux | 1 (cooperative) | 1 | std thread on the main process |
| WASM | 1 (single-threaded) | 1 | host calls `kernel_step()` on its event loop |

This document classifies every `static mut` in `src/kernel/` by access
pattern. Each kernel file's top-of-file comment summarises the relevant
phase and points back here.

## Three lifecycle phases

Every shared mutable state in the kernel falls into one of three phases;
the safety story is different for each.

### Phase 1 — single-threaded boot

Everything from `kernel::boot()` through the final `instantiate_one_module`
runs on **core 0 only**. Secondary cores spin in the trampoline waiting
for `INIT_COMPLETE.store(1, Release)` (see
[bcm2712.rs](../../src/platform/bcm2712.rs)). Statics written exclusively
in this phase need no synchronisation:

- `kernel::loader`: `STATE_ARENA`, `STATE_ARENA_OFFSET`, `FREE_LIST`,
  `FREE_COUNT`, `PIC_IRQ_DISABLED_COUNT`
- `kernel::config`: `CONFIG_ARENA`, `ARENA_OFFSET`
- `kernel::buffer_pool`: `BUFFER_ARENA`, `BUFFER_ARENA_OFFSET`
- `kernel::scheduler`: `STATIC_CONFIG`, `STATIC_LOADER`, `PARAM_BUFFER`,
  `NAME_STORAGE`, `NEXT_NAME_SLOT`, `INSTANTIATION_STATE`,
  `INSTANTIATION_IDX`, `MODULE_STATE_PTR`
- `kernel::syscalls`: `SYSCALL_TABLE`, `HARDWARE_CONTEXT`,
  `SYSTEM_EXTENSION`, `DEV_QUERY_EXTENSION`
- `kernel::hal`: `HAL_OPS`

After init these are read-only. All four platforms publish
`INIT_COMPLETE` (or its equivalent — for RP/Linux/WASM there's no
secondary core to release) before any code reads them. Writes during
reconfigure happen on core 0 with all secondaries parked, restoring
phase-1 semantics for the duration of the rebuild.

### Phase 2 — steady-state, per-core isolation

Some state is touched on every step but is sliced by core or by module
so two cores never touch the same byte:

- `MODULE_HEAPS[i]` (`kernel::heap`) — module *i*'s heap. Module *i*
  only steps on its assigned core, so each heap sees a single writer.
- `FAN_BUFS[d]` (`kernel::scheduler::module_types`) — per-domain
  scratch for tee / merge. Tee and merge inherit their fan group's
  `domain_id`; a domain runs on exactly one core, so per-domain
  indexing keeps each core on its own buffer.
- `CURRENT_MODULE_PER_CORE[c]` (`kernel::scheduler`) — `AtomicU32`
  array indexed by `hal::core_id()`.

Per-module / per-core arrays in this category are not annotated as
`static mut` blanket — each entry is independent and the indexing rule
must be visible at every use site.

### Phase 3 — steady-state, true sharing

A handful of statics are shared across cores in steady state. Every one
must be an atomic or guarded by a lock:

- `kernel::channel::CHANNELS[i]` — each `ChannelSlot` uses
  `AtomicI8`/`AtomicU8`/`AtomicU32`/`AtomicPtr`/`AtomicBool` for state +
  buffer + ioctl handler fields, plus an internal spin-wait `lock` for
  the FIFO critical section. Cross-core safe.
- `kernel::buffer_pool::BUFFER_REGISTRY[i]` — each `BufferRegistrySlot`
  is fully atomic. Cross-core safe.
- `kernel::event::*` event queues — atomic ring per event handle.

Rule of thumb for new code: any state visible to PIC modules via
syscall traffic is phase 3 by default; any state populated by
`populate_static_state` / `prepare_graph` is phase 1; anything else,
justify in a comment.

## Function-local `static mut`

Two function-local `static mut`s exist in `kernel::syscalls` (`LOGGED`
in the EAGAIN logger throttle, `LOGGED_NULL_STATE` in the null-state
logger). Both can race across cores; the worst case is a duplicate log
line per process lifetime. Acceptable.

## What this document is not

It's not a SAFETY proof — Rust still requires `unsafe` for every raw
access to these statics. It's the *contract* readers should hold
against the call graph when auditing one of those `unsafe` blocks. If
the classification above is ever wrong for a static, the fix is to
update both the comment and this document.
