# Kernel Concurrency Model

The kernel ships on five platforms with different concurrency profiles.
Every platform admits up to `MAX_DOMAINS` (4) execution domains; what
differs is which core each domain runs on. A target maps each domain index
to a core (`[smp] domain_cores` in its TOML), and one domain loop runs per
core that has a domain:

| Platform | Cores | Domains | Domain loop |
|---|---|---|---|
| RP2040 | 1 | up to 4, all on one thread | one loop on core 0 passes over every domain in index order |
| RP2350 | 2 | up to 4: domain 1 on core 1, domains 0, 2, 3 on core 0 | one loop per core over its domains; core 1 parks whenever XIP is detached |
| BCM2712 (Pi 5) | 4 | up to 4, domain d on core d | one bare-metal domain loop per core, each running its own domain's modules |
| uefi | up to 4 used | up to 4, domain d on core d | as BCM2712: the boot core runs domain 0, secondary n runs domain n |
| Linux | 1 (cooperative) | up to 4, all on one thread | the main thread of the process runs a pass of every domain in index order (`pass::tick_all`) |
| WASM | 1 (single-threaded) | up to 4, all on one thread | the browser host calls `kernel_step()` on its event loop, which runs a pass of every domain in index order |

This document classifies every `static mut` in `src/kernel/` by access
pattern. Each kernel file's top-of-file comment summarises the relevant
access pattern and points back here.

## Three access classes

Every shared mutable state in the kernel falls into one of three access
classes; the safety story is different for each.

### Boot-only — written before the graph runs

Everything from `kernel::boot()` through `scheduler::instantiate_graph`
publishing the node's graph runs on core 0 only. Secondary cores wait for `domains::release()`
(`src/kernel/exec/domains/mod.rs`) before entering their loops. Statics
written exclusively in that window need no synchronisation:

- `src/kernel/module/loader.rs`: `STATE_ARENA`, `STATE_ARENA_OFFSET`,
  `FREE_LIST`, `FREE_COUNT`, `PIC_IRQ_DISABLED_COUNT` (the arena's
  bookkeeping is also written after init, under `STATE_LOCK`, below)
- `src/kernel/exec/scheduler/`: `STATIC_CONFIG`, `STATIC_LOADER`,
  `INSTANTIATION_STATE`, `INSTANTIATION_IDX`
- `src/kernel/module/syscalls.rs`: `SYSCALL_TABLE`, `HARDWARE_CONTEXT`,
  `SYSTEM_EXTENSION`, `DEV_QUERY_EXTENSION`
- `src/kernel/sys/hal.rs`: `HAL_OPS`

After init these are read-only. The multi-core platforms (bcm2712, uefi)
publish them to their secondaries with the release store `domains::release()`
makes, which each secondary's acquire load pairs with before it reads them;
the RP2350 lets core 1 leave its wait in RAM after the same release; RP2040,
Linux and WASM have no secondary core to release. Writes during
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
freed at once: on bcm2712 and uefi to the carve zone, for the next carve,
and on Linux to the host's allocator. The move copies the table, publishes the new block
with a release store, and then frees the old one, so the argument that no
reader can still hold the old block is made per platform.

On bcm2712 and uefi every move runs on core 0, in `prepare_graph`, which
core 0 enters from its domain loop between steps, holding no slice of any table
(a slice lives only within the call that reads it). At boot no other core has
left its wait for `domains::release()`. For a rebuild the other domains are
quiesced first: each parks at its pass boundary, outside any step, and resumes
only after the rebuild, when its acquire load of the quiesce generation,
paired with the store that ends the quiesce, makes the new block visible to
its next read. Interrupts are covered by three facts:

- Core 0 masks its own interrupts from the copy to the free. Every interrupt
  that reaches a table from handler context is delivered there: an event
  binding (which signals its event slot) and the PCIe MSI multiplexer are
  bound to core 0, and `gic::irq_bind` refuses to bind an SGI or PPI, which
  is taken on whichever core raises it, to an event.
- A `timer` or `irq` handler may run on another core: an `irq` module's
  IRQ is delivered to its domain's core, which the quiesce parks but does
  not mask. `prepare_graph` closes interrupt-mode dispatch before it sizes
  a table (`interrupt::close_dispatch`). A handler raises an in-flight count and then
  reads the gate; the close stores the gate and then waits for the count to
  reach zero; all four accesses are sequentially consistent, so either the
  handler sees the gate closed and steps nothing, or the close sees the
  handler and waits for it to return. Dispatch reopens only when the new
  graph registers an interrupt-mode module, after every table is sized.
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
  (`src/kernel/exec/scheduler/pacer.rs`, `multigraph.rs`) — the pass
  engine's per-owner tables, one entry per owner slot and execution domain.
  An entry's pass state is read and written only by the domain loop of its
  own domain; of another domain's resident-graph entry a domain loop reads
  only the
  domain it names, which changes only when the index is rebuilt, with the
  other domains parked.
- `CURRENT_MODULE_PER_CORE[c]` (`src/kernel/exec/scheduler/state.rs`)
  — `AtomicU32` array indexed by `hal::core_id()`.

Per-module / per-core arrays in this category are not annotated as
`static mut` blanket — each entry is independent and the indexing rule
must be visible at every use site.

### Cross-core-shared — steady state, true sharing

A handful of statics are shared across cores in steady state. Every one
must be an atomic or guarded by a lock:

- `CHANNELS[i]` (`src/kernel/ipc/channel.rs`) — each `ChannelSlot`
  uses atomics for its state, generation, ends, stream flags and buffer
  slot, plus an internal spin-wait `lock` for the FIFO critical section.
  Cross-core safe.
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

## RP2350: two cores and one flash

The RP2350 runs domain 1 on its second Cortex-M33 and domains 0, 2 and 3 on
the first (`targets/silicon/rp2350.toml`, `[smp] domain_cores`). The kernel
state the two cores share falls into the classes above; what the platform
adds (`src/platform/rp/`) is classified here.

**Each core's own.** The step guard's alarm, armed deadline and stray count
(`rp/step_guard.rs`; core 0 on the monotonic timer instance, core 1 on its
own instance); the armed, timed-out and protection-fault flags
(`kernel/exec/step_guard.rs`, indexed by core); the gated-module control
block and the MPU, which each core programs for the module it steps
(`rp/protection.rs`); the stack fence and the measured entry depth
(`rp/boot.rs`; core 1 steps on its own stack in SRAM8 and SRAM9); the
module-timer alarm and the `timer` slots tagged with the core
(`kernel/exec/timer.rs`); the NVIC. Each core's NVIC can be written by that
core alone, so a line bound for core 1 is recorded in a line set
(`rp/core1.rs`) that core 1 applies when it enters its loop, after every
park and at a pass boundary where the set changed.

**Shared under the cores' lock.** `portable_atomic`'s 64-bit atomics (the
monotonic and ledger counters, the log and telemetry rings) go through the
critical section (`arch/critical_section_impl.rs`), which masks the local
core's interrupts and then takes one lock word with the exclusive accesses
(`arch/core_lock.rs`); a nested section takes the lock once. The platform
providers (`gpio`, `platform_dma`, `platform_dma_fd`, the raw register
bridges) run each call inside the same section while core 1 runs a domain
(`rp_providers::exclusive`). Every lock word and every atomic is a static in
main SRAM, the only memory where the two cores' exclusive accesses are
arbitrated.

**Core 0 only.** USB, the console, the watchdog, flash, and every quiesce
request. Core 0 feeds the watchdog only while core 1's heartbeat moves, core
1 is parked for core 0, or core 1 runs no domain.

**Bridged.** An edge between a domain on core 0 and one on core 1 is split
into two channels joined by a lock-free ring (`domains/cross.rs`); an edge
between two domains of core 0 is a plain channel, since one loop steps both
ends.

**XIP detach.** Both cores execute from flash. A sector erase, a page
program and the BOOTSEL read take execute-in-place away, so every one of
them goes through `with_xip_detached` (`rp/flash.rs`), on core 0 only: core
1 parks between two of its module steps in a loop that lies in RAM and runs
with its interrupts masked, records from inside that loop that it has
parked, and returns only once core 0 has restored XIP. Core 0 waits no
longer than the deadline of the step core 1 is in plus a millisecond, and
answers `EBUSY` past it. Core 1 is started for the first graph that places a
module on it, waits in the same RAM loop until that graph is released, and
parks there for a structural quiesce. A flash op issued on core 1 answers
`ENOTSUP`. The time a core is held for a detach (core 0 with its interrupts
masked, core 1 parked) is not the stepping module's: its deadline moves past
it and the scheduler leaves it out of the step's time. An erase or a program
also empties the cache both cores fetch through, so each core's steps may
run over their deadlines by one refill of that cache in the passes that
follow (`rp/step_charge.rs`). Before an erase or a program every DMA scan
list's armed entries return to fill.

**Core 1's stack.** Core 1 steps on a stack of its own, 8 KiB
(`[smp] secondary_stack` in the target file). A gated module runs on the
stack in its private region; a module that is not gated runs on core 1's,
and the composer admits it against the stack less `reserve_kb`, the kernel's
own share under it: its frames where it calls the module, the deepest call
the module can make back (through the provider table to a handler and the
logger), and one interrupt on top. The firmware build measures that sum in
the linked image (`tools/img/kernel_stack_bound.py`) and refuses an image
that needs more than the reserve. Three kinds of call run frames deeper than
core 1's whole stack (a signature check, the loader): the `reconfigure`
contract, the signing root and the key vault answer `ENOTSUP` on core 1, as
flash does.

**Faults.** A module's fault on core 1 is taken by its policy like any
other, and the work of the policy is core 0's: on every kernel that runs
domains on more than one core, a core other than the primary posts a
module's timeout, error, protection fault or completion on the module's own
fault record and stops stepping it, and the primary's next pass finalizes,
restarts or terminates it with the other cores parked
(`scheduler/fault.rs`). A kernel fault or a panic on core 1 is the node's:
core 1 gives up the lock between the cores, leaves what happened for core 0
and waits in RAM; core 0 logs it, keeps it as the crash record the next boot
reports, and resets the whole node through the bootrom. Whenever core 0
itself stops running the graph (its own fault report, a halted graph, a
reset) it first returns core 1 to the bootrom, so nothing runs beside it.

## Function-local statics

A static declared inside a function is an atomic, never a `static mut`:
the gateway's refusal-log throttle (`LOGGED`, `src/kernel/module/gateway.rs`),
the key vault's once-only warning (`WARNED`), the host page size read once
(`PAGE`, Linux), and the gateway's minted-handle table (`MINTED`). The
throttles and once-flags tolerate a race with at worst a duplicate log
line; the handle table is updated by compare-exchange.

## What this document is not

It is not a SAFETY proof — Rust still requires `unsafe` for every raw
access to these statics. It is the contract readers should hold
against the call graph when auditing one of those `unsafe` blocks. If
the classification above is ever wrong for a static, the fix is to
update both the comment and this document.
