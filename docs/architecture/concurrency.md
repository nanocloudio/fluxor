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
- `src/kernel/exec/scheduler/`: `STATIC_CONFIG`, `STATIC_LOADER`,
  `NAME_STORAGE`, `NEXT_NAME_SLOT`,
  `INSTANTIATION_STATE`, `INSTANTIATION_IDX`, `MODULE_STATE_PTR`
- `src/kernel/module/syscalls.rs`: `SYSCALL_TABLE`, `HARDWARE_CONTEXT`,
  `SYSTEM_EXTENSION`, `DEV_QUERY_EXTENSION`
- `src/kernel/sys/hal.rs`: `HAL_OPS`

After init these are read-only. All four platforms publish
`INIT_COMPLETE` (or its equivalent; for RP/Linux/WASM there is no
secondary core to release) before any code reads them. Writes during
reconfigure happen on core 0 with all secondaries parked, restoring
boot-only semantics for the duration of the rebuild. The parsed config's
module entries borrow their params from the resident config blob in place
(only an instance with stored runtime overrides is handed a merged copy, made
on core 0 as it instantiates), so the blob stays mapped for as long as the
config does. The state arena allocator is also written after init: on core 0
for live graph changes (peer cores quiesced) and the block-lend ledger
releasing a quarantined module's memory, and from any core when an elastic
module heap grows (`kernel::mem::heap`). Its bookkeeping (`STATE_ARENA_OFFSET`,
`FREE_LIST`, `FREE_COUNT`) is therefore serialised by `STATE_LOCK`, held only
over the bounded bookkeeping and never while the carved bytes are zeroed.

### Per-core-sliced — steady state, no byte shared

Some state is touched on every step but is sliced by core or by module
so two cores never touch the same byte:

- `MODULE_HEAPS[i]` (`src/kernel/mem/heap.rs`) — module *i*'s heap.
  Module *i* only steps on its assigned core, so each heap sees a
  single writer. Growing it carves from the shared state arena under
  `STATE_LOCK`.
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
- The buffer arena allocator (`src/kernel/ipc/buffer_pool.rs`) —
  channels open and close at graph build, on live graph changes, when
  the block-lend ledger closes a channel (core 0, peers running), and
  from a module's own `channel::OPEN` / `CLOSE` on any core. The free
  list and high-water mark change only under `ARENA_LOCK`; the mark is
  an `AtomicUsize` so occupancy reads need no lock. A channel detaches
  its buffer under its own FIFO lock before returning it, so a reader
  or writer on another core finishes with the buffer first or finds
  none.
- The network-disciplined wall clock (`src/kernel/sys/time_sync.rs`) —
  any core reads the anchor; any core's module may install one through
  `timer::DISCIPLINE`. A sequence lock (writers claim it even-to-odd by
  compare-exchange) keeps a reader from pairing two anchors' fields.
- Event queues (`src/kernel/ipc/event.rs`) — atomic ring per event
  handle.
- The bcm2712 state arena's zeroed frontier (`src/kernel/module/loader.rs`)
  — every domain zeroes the arena in its slack. One claim at a time
  (`CLAIM`, taken under `STATE_LOCK` with a try-lock, so a domain never
  waits to donate slack): the frontier chunk above the bump offset, or the
  head of a freed region on the in-zeroing list. The zeroing runs outside
  the lock. A frontier claim completes with two release stores and no lock,
  so an allocation that needs memory under it may wait for it while holding
  `STATE_LOCK`; an in-zeroing claim completes under the lock, and a reset
  waits for it outside the lock. The arena's top is shared with the kernel's
  table carves (`src/kernel/mem/carve.rs`) without a common lock: a carve
  lowers `ARENA_CAP` then reads `ARENA_HIGH`, an allocation raises
  `ARENA_HIGH` then reads `ARENA_CAP`, both sequentially consistent, so of
  any two racing at least one sees the other and backs off.

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
