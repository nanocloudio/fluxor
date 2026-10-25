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

The boot-sized kernel tables (`src/kernel/mem/table.rs`) move to a larger
block only while a graph is prepared, and the block a table moves out of is
freed at once: on bcm2712 to the carve zone, for the next carve, and on Linux
to the host's allocator. The move copies the table, publishes the new block
with a release store, and then frees the old one, so the argument that no
reader can still hold the old block is made per platform.

On bcm2712 every move runs on core 0, in `prepare_graph`, which core 0 enters
from its pump loop between steps, holding no slice of any table (a slice
lives only within the call that reads it). At boot no other core has left
its wait for `INIT_COMPLETE`. For a rebuild the other domains are quiesced
first: each parks at its tick boundary, outside any step, and resumes only
after the rebuild, when its acquire load of the quiesce flag, paired with the
release store that ends the quiesce, makes the new block visible to its next
read. Interrupts are covered by three facts:

- Core 0 masks its own interrupts from the copy to the free. Every interrupt
  that reaches a table from handler context is delivered there: an event
  binding (which signals its event slot) and the PCIe MSI multiplexer are
  bound to core 0, and `gic::irq_bind` refuses to bind an SGI or PPI, which
  is taken on whichever core raises it, to an event.
- A Tier 1b or Tier 2 handler may run on another core: a Tier 2 IRQ is
  delivered to its domain's core, which the quiesce parks but does not mask.
  `prepare_graph` closes ISR-tier dispatch before it sizes a table
  (`isr_tier::close_dispatch`). A handler raises an in-flight count and then
  reads the gate; the close stores the gate and then waits for the count to
  reach zero; all four accesses are sequentially consistent, so either the
  handler sees the gate closed and steps nothing, or the close sees the
  handler and waits for it to return. Dispatch reopens only when the new
  graph registers an ISR-tier module, after every table is sized.
- The timer tick handler on each core touches atomics only.

A table its own lock guards (the net-attach lane tables) may move on a step,
on any core, under that lock, which every reader of it holds.

On Linux the hosted runtime reads its tables from one thread. The scheduler,
every module step and every call a module makes run on the main thread,
which takes a rebuild between passes, when no pass holds a slice. The
runtime's other threads (the process executor's and the CLI's pipe pumps, the
`host_mount` workers, the resolver, GPU and display threads, the `net_route`
prober and announcer, the audio callback) exchange with the scheduler through
bridges, channels and their own locked state, never a kernel table. Their log
records reach the owner-attribution tee, which reads the module owner table
only on the scheduler thread. The stop-signal handler stores atomics, or
restores the terminal and re-raises.

RP keeps a moved block until the next plan, which replans the whole pool with
interrupts masked (`carve::begin_plan`).

### Per-core-sliced — steady state, no byte shared

Some state is touched on every step but is sliced by core or by module
so two cores never touch the same byte:

- `MODULE_HEAPS[i]` (`src/kernel/mem/heap.rs`) — module *i*'s heap.
  Module *i* only steps on its assigned core, so each heap sees a
  single writer. Growing it carves from the shared state arena under
  `STATE_LOCK`. The table itself is a per-module boot-sized table:
  each record sits in a cell, so every access borrows the table shared,
  and the table moves only while a graph is prepared.
- `GRAPH_PACERS` and `RESIDENT_GRAPHS`
  (`src/kernel/exec/scheduler/merge.rs`, `multigraph.rs`) — the multi-graph
  runner's per-owner tables, one entry per owner slot and execution domain.
  An entry's pass state is read and written only by the runner of its own
  domain; of another domain's resident-graph entry a runner reads only the
  domain it names, which changes only when the index is rebuilt, with the
  other domains parked.
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
- Event slots (`src/kernel/ipc/event.rs`) — each `EventSlot` is atomic
  (allocated, signalled, owner), and the wake-pending mask a module's
  signal latches is an array of atomic words.
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
