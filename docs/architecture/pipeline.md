# Graph Runner Architecture

The graph runner is the heart of Fluxor. It loads PIC modules into a runtime
graph, opens channels between them, and steps them cooperatively in
topological order. This document describes the runtime model, the channel
mechanics, the execution loop, and the lifecycle of modules and graphs.

## Design Goals

- Compose modules into arbitrary graphs via configuration, not firmware code
- Keep the kernel small and protocol-agnostic
- Make all I/O non-blocking with structural backpressure
- Support live reconfiguration without dropping in-flight work
- Run identical module binaries across silicon families

## Runtime Model

```
Config (flash or boot image)              Runtime
-----------------------------             -------
modules[]   ───────────────────►  ModuleSlot[] (state, hints, caps)
edges[]     ───────────────────►  Edge[] with channel handles
domains[]   ───────────────────►  Per-domain tick budget
            ───────────────────►  setup() → setup_graph() → run_main_loop()
```

A graph is a set of module instances and a set of directed edges that
connect them. Each module is a `.fmod` artifact loaded from flash. Each
edge becomes a kernel-allocated channel ring buffer. The runner steps
all instantiated modules each iteration, in topological order, until
the graph reaches a terminal state, encounters a fault, or is asked to
reconfigure.

## Graph Configuration Model

Graphs are declared in config as module instances plus explicit wiring
edges, with an optional hardware section that the config tool resolves
into driver modules and infrastructure wiring (see
[capability_surface.md](capability_surface.md)).

### Top-Level Shape

- `target` — silicon/board identifier (e.g. `pico2w`, `cm5`, `qemu-virt`)
- `hardware` — physical hardware declarations (network, audio, display, storage)
- `modules` — application module instances and their parameters
- `wiring` — directed edges between module ports
- `data` — optional inline assets referenced by modules
- `execution` — optional per-domain tick periods and core assignments
- `reconfigure` — optional drain timeout and policy

### Wiring

Each wiring entry connects one source port to one destination port:

```yaml
wiring:
  - from: source.stream
    to: decode.data
  - from: decode.pixels
    to: display.pixels
```

Port names are manifest-defined contracts. The config tool resolves names
to channel bindings and validates direction and content compatibility
against the source and destination modules' manifests.

### Topology Rules

- Graph execution order is topological (producers before consumers)
- Fan-out and fan-in are represented as runtime helpers (tee/merge)
- Cycles require explicit buffering and are an advanced pattern

### Inline Data Assets

The optional `data` section stores small assets directly in the config
payload. This is suited for embedded presets, sequences, and test
fixtures where external storage is not required.

### Validation

The config tool enforces:

- module existence and parameter shape against the manifest
- valid port references on both ends of every wire
- content-type compatibility on each edge
- bounded resource usage (channels, buffers, module slots, arena fits)
- pin and bus conflicts against the silicon's hardware capabilities
- capability satisfaction (every `requires` met by some `provides`)

## Module Execution

Modules implement four required exports:

```rust
#[no_mangle] pub extern "C" fn module_state_size() -> u32 { ... }
#[no_mangle] pub extern "C" fn module_init(syscalls: *const c_void) { ... }
#[no_mangle] pub extern "C" fn module_new(in_chan: i32, out_chan: i32, ctrl_chan: i32,
                                          params: *const u8, params_len: usize,
                                          state: *mut u8, state_size: usize,
                                          syscalls: *const c_void) -> i32 { ... }
#[no_mangle] pub extern "C" fn module_step(state: *mut u8) -> i32 { ... }
```

Optional exports surface additional capabilities:

| Export | Purpose |
|--------|--------|
| `module_arena_size` | Request a per-module heap (see [heap.md](heap.md)) |
| `module_channel_hints` | Request specific channel buffer sizes per port |
| `module_drain` | Support graceful drain during live reconfigure |
| `module_deferred_ready` | Gate downstream modules until init completes |
| `module_mailbox_safe` | Declare safe consumption from mailbox channels |
| `module_in_place_safe` | Declare safe in-place mailbox transformation |

### Step Outcome

`module_step` returns a small integer:

| Value | Meaning |
|-------|--------|
| `0` | Continue — yield, more work possible later |
| `1` | Done — module reached terminal completion |
| `2` | Burst — re-step immediately, more work this tick |
| `3` | Ready — initialization complete, downstream may run |
| `<0` | Error (errno-style negative codes) |

`Burst` is a scheduling hint, not a license for unbounded work. The
scheduler re-steps a bursting module up to `MAX_BURST_STEPS` (4)
additional times in the same tick. Each burst step still has to satisfy
the bounded-time contract.

`Ready` participates in the deferred-ready chain: a module that exports
`module_deferred_ready` is gated by the scheduler so that its downstream
consumers do not run until it has returned `Ready` from a step. The
gating is transitive — if A is gated on B and B is gated on C, then A's
consumers wait until C reports ready, then B reports ready.

### Async I/O Pattern

Hardware-facing operations use start/poll sequencing:

1. Begin an operation (`*_start`)
2. Return / yield while pending
3. Poll for completion (`*_poll`) on a subsequent step

This pattern keeps every module cooperative and predictable. There is
no blocking syscall in the table — even DMA-backed transfers are
expressed as start/poll pairs.

## The Main Loop

The kernel main loop on every target is the same shape:

```
loop {
    poll_hardware_edges();           // GPIO/IRQ → event signals
    step_modules(modules, count);    // topological walk
    if let wake = take_wake_pending() {
        step_woken_modules(wake);    // intra-tick wake from events
    }
    sleep_until_tick_or_event();
    if let wake = take_wake_pending() {
        step_woken_modules(wake);    // post-sleep wake from ISR
    }
}
```

The "sleep until tick or event" step differs by target:

| Target | Sleep mechanism |
|--------|----------------|
| RP2040, RP2350 | Embassy `select(Timer::after(tick), SCHEDULER_WAKE.wait()).await` |
| BCM2712, CM5 | Synchronous wait on the chip's monotonic timer with interrupt unmasking |

In both cases, an event signal from an ISR or another module wakes the
loop early — the sleep is bounded above by the configured tick period
but can return immediately when there is work to do. See
[events.md](events.md) for the event/wake contract.

## Channel-Based IPC

Modules communicate exclusively through channels, allocated by the
kernel and addressed by handle:

```rust
let ready = (sys.channel_poll)(in_chan, POLL_IN);
if ready & POLL_IN != 0 {
    let n = (sys.channel_read)(in_chan, buf.as_mut_ptr(), buf.len());
    // process n bytes
    (sys.channel_write)(out_chan, output.as_ptr(), output.len());
}
```

A channel is a ring buffer between exactly one producer and one
consumer. Fan-out and fan-in are handled by tee/merge helper modules
inserted by the runner when wiring requires them. The kernel allocates
channel buffers from a dedicated buffer arena, separate from module
state, so that channel sizing does not compete with module memory.

### Channel Buffer Sizing

Before opening channels, the scheduler queries each module's optional
`module_channel_hints` export to determine per-port buffer sizes.
Channel buffers are allocated from the **buffer arena**. Both the state
arena and the buffer arena are reset on graph reconfigure.

| Workload class | Typical channel size |
|---------------|---------------------|
| Audio data (PCM frames) | 2048 bytes |
| Control / FMP commands | 256 bytes |
| Network frames (Ethernet MTU) | 4096–8192 bytes |
| Mailbox video frames | up to 65535 bytes |

Modules without channel hints get the default 2048 bytes per port. The
config tool validates that the sum of all channel buffers fits within
the buffer arena for the target silicon.

### FIFO Mode

The default channel mode is FIFO with copy semantics. `channel_write`
copies bytes into the ring buffer; `channel_read` copies bytes out.
This is the right mode for byte-stream producers that build their
output incrementally — a decoder emitting partial frames, a sensor
emitting timestamped readings, a network driver pushing variable-size
packets.

### Mailbox Mode (Zero-Copy)

For workloads where a producer can fill a complete buffer in one step
and the consumer can process it without copying, channels support
**mailbox mode**. Producer and consumer exchange ownership of the same
underlying buffer through `buffer_acquire_*` / `buffer_release_*`
syscalls. No copy occurs — the buffer stays in place and the consumer
reads it directly.

```
  FIFO copy        mailbox (zero-copy alias chain)
 ──────────      ──────────────────────────────────
 Source ──copy──► Producer ──alias──► InPlace ──alias──► Sink
         ch A      (group=1)  ch B    (group=1)  ch B    (DMA)
```

Mailbox mode is enabled per edge by setting a `buffer_group` value in
the wiring. All edges in the same group share one underlying buffer.

#### State machine

A mailbox buffer cycles through four states:

1. **STREAMING** — initial state; the producer is filling the buffer
2. **READY** — producer has released the buffer; consumer can read it
3. **READY_PROCESSED** — an in-place writer has transformed the buffer
4. (back to STREAMING when the final consumer releases)

#### Capability flags

Each module participating in a mailbox chain declares its capabilities
via header flags (`reserved[0]`):

| Bit | Name | Meaning |
|-----|------|--------|
| 0 | `mailbox_safe` | Module can consume from a mailbox channel |
| 1 | `in_place_writer` | Module uses `buffer_acquire_inplace` to transform the buffer |
| 2 | `deferred_ready` | Module needs init time before downstream may run |
| 3 | `drain_capable` | Module exports `module_drain` for live reconfigure |

The pack tool detects the corresponding `module_*` export and sets the
flag automatically. The loader uses these flags to validate that the
config's mailbox chains are consistent — a module without
`mailbox_safe` cannot appear in a `buffer_group` chain.

#### Constraints

- At most one in-place transform per alias chain (the `READY_PROCESSED`
  state prevents double-processing)
- `buffer_group` is incompatible with tee/merge helpers; the runner
  clears `buffer_group` on inserted fan edges
- Buffer sizing for grouped edges is the maximum of all port hints
  across the group, so the channel is large enough for the most
  demanding consumer

### FIFO → Mailbox Boundary Rule

When a transformer reads from a FIFO input and writes to a mailbox
output, it must check the mailbox output is acquirable **before**
consuming the FIFO input:

```c
// Correct: reserve the output buffer first
u32 cap = 0;
u8 *buf = buffer_acquire_write(out_chan, &cap);
if (!buf) return 0;          // do not read input — output not ready
int read = channel_read(in_chan, buf, cap);
if (read > 0) buffer_release_write(out_chan, read);
```

FIFO reads are destructive. If the module reads input but then cannot
acquire the mailbox output, the data is lost — there is no recovery
path because the FIFO has already advanced. Reserving the output first
guarantees that any byte taken off the FIFO has a place to land.

### Backpressure

Backpressure is structural: a producer that cannot write its output
(because the channel buffer is full or the mailbox is busy) does not
advance its internal state. Time, frame counters, and read positions
only move when the corresponding output has been committed. This is
the same rule whether the producer is generating audio samples,
emitting Ethernet frames, or fanning out a Raft proposal — see
[module_architecture.md](module_architecture.md) for the principles.

## Tee and Merge

When the wiring connects one output to multiple inputs, or multiple
outputs to one input, the runner inserts a helper module:

```
Config:                Runtime:
A → B                  A → B
A → C                  A → [tee] → B
                              → C

A → C                  A → [merge] → C
B → C                  B →
```

Tee and merge use a shared static fan buffer. They are not visible in
the config and do not count against module slot limits. They are
incompatible with mailbox `buffer_group` aliasing — fan helpers always
copy.

## Module Instantiation

PIC modules go through this sequence during `setup_graph`:

1. **Find** — locate the module in flash by name hash
2. **Validate** — check magic bytes, ABI version, code bounds
3. **Size query** — call `module_state_size()` for the state buffer size
4. **Allocate** — reserve state from the state arena
5. **Heap query** — call `module_arena_size()` if exported, reserve heap
6. **Init** — call `module_init(syscalls)` once
7. **New** — call `module_new(in, out, ctrl, params, params_len, state, state_size, syscalls)`
8. **Channel hints** — call `module_channel_hints()` if exported
9. **Wait for ready** — if `deferred_ready` flag is set, gate downstream until first `Ready` outcome

State memory is zeroed by `alloc_state()` before `module_new` is
called, so modules do not need to re-zero their state struct.
Instantiation is sequential — a module that returns a transient error
from `module_new` is retried in a bounded loop before the next module
proceeds.

### Per-Module Heap

Modules that need dynamic allocation export `module_arena_size()`. The
kernel allocates a per-module heap arena alongside the state buffer
during instantiation and the SDK helpers `heap_alloc`, `heap_free`,
`heap_realloc` allocate within that arena. Modules that do not export
the function get no heap and pay zero cost. See [heap.md](heap.md).

### Per-Module Sandboxing

Modules can declare a protection level:

| Level | Name | Mechanism |
|-------|------|----------|
| 0 | None | Direct call, no isolation |
| 1 | Guarded | Step guard timer detects timeouts |
| 2 | Isolated | Hardware memory protection (MPU on RP2350, MMU on CM5) per step |

Isolated modules execute with their state, code, and channel buffers
mapped via the MPU/MMU and everything else excluded. A wild pointer
write outside their permitted regions raises a fault that the scheduler
catches, classifies, and handles via a per-module fault policy
(`Skip`, `Restart`, or `RestartGraph`). The same step guard catches
modules that exceed their per-step time budget. See
[reconfigure.md](reconfigure.md) for the recovery state machine.

## Live Graph Reconfigure

The scheduler supports updating a running graph through four phases:

```
RUNNING → DRAINING → MIGRATING → RUNNING
```

In `DRAINING`, modules with the `drain_capable` flag have `module_drain`
called in reverse topological order. They stop accepting new work but
keep stepping until in-flight work completes (or the drain timeout
expires). In `MIGRATING`, the new graph's modules are instantiated and
the scheduler swaps over. Surviving modules — same binary, same config,
same wiring — are preserved across the swap.

This is what makes live config updates possible: an HTTP server can
finish responding to in-flight requests, then the new HTTP server
instance takes over without dropping connections. See
[reconfigure.md](reconfigure.md) for the full state machine and the
drain protocol.

## Demand-Paged Arenas

On targets with an MMU (BCM2712, CM5), modules can request demand-paged
arenas larger than physical RAM. The kernel allocates virtual address
space backed by a page pool with clock eviction and a backing store
(NVMe or RAM disk). The module sees a flat large arena and accesses
pages directly; the kernel handles faults transparently. This is how
data-heavy workloads — large lookup tables, decoded image caches,
streaming buffers — run on the same scheduler that drives microsecond-
scale audio modules.

## Static Memory

The runner consolidates per-module arrays into a single
`SchedulerState` struct (`static mut SCHED`) to avoid async state
machine bloat:

```rust
static mut SCHED: SchedulerState; // edges, modules, ports, caps, arenas, hints, drain state, ...
```

Limits are configurable per target via constants in `scheduler.rs`:

| Resource | Configurable via | Typical defaults |
|----------|-----------------|-----------------|
| Modules | `MAX_MODULES` | 8 (RP2040), 64 (RP2350), 256 (BCM2712) |
| Channel edges | `MAX_GRAPH_EDGES` | 16 (RP2040), 128 (RP2350), 1024 (BCM2712) |
| Event slots | `MAX_EVENTS` | 32 |
| State arena | `STATE_ARENA_SIZE` | 64 KB (RP2040), 256 KB (RP2350), 1 MB+ (BCM2712) |
| Buffer arena | `BUFFER_ARENA_SIZE` | 16 KB (RP2040), 32 KB (RP2350), 256 KB+ (BCM2712) |
| Buffer slots | `MAX_BUFFER_SLOTS` | 20 |
| Module name | `MAX_MODULE_NAME` | 16 bytes |
| Burst steps | `MAX_BURST_STEPS` | 4 per module per tick |

These are sized per silicon — small embedded targets have tight
budgets, server-class targets have headroom for larger graphs. The
config tool validates that the requested resources fit within the
target's limits.

## Async Runtime Guardrails

The runtime enforces cooperative async behavior across all graph
workloads:

- Hardware-facing operations use non-blocking start/poll patterns
- Backpressure flows through channel/buffer readiness, never sleep loops
- Periodic async tasks include explicit yield points and avoid tight loops
- Long critical sections in hot paths are avoided to protect scheduler latency
- Stream interfaces return promptly when data or capacity is unavailable

These rules apply to kernel HAL code (Embassy tasks on RP, polled DMA
on aarch64) and to PIC modules. They are the contract that makes the
"single 1 ms tick" model work at all.

## Loader Architecture

The loader (`src/kernel/loader/`) is split into focused submodules:

| Submodule | Purpose |
|-----------|--------|
| `error.rs` | Typed `LoaderError` enum |
| `flash.rs` | Safe wrappers around flash reads (XIP-aware) |
| `ffi.rs` | FFI call wrappers for module exports |
| `loader.rs` | State arena allocation and channel hint queries |
| `validation.rs` | Function pointer validation, magic checks |
| `table.rs` | Module table parsing and lookup |
| `dynamic.rs` | `DynamicModule` wrapper implementing the `Module` trait |

The loader resolves required exports via FNV-1a name hashing — there is
no symbol table in the `.fmod` file beyond a list of exported function
hashes and offsets. This keeps the binary format compact and the
loader fast.

## Related Documentation

- [module_architecture.md](module_architecture.md) — module step contract, principles, ABI
- [device_classes.md](device_classes.md) — `dev_call` opcodes and provider dispatch
- [hal_architecture.md](hal_architecture.md) — bus primitives, syscall table, per-silicon HAL
- [events.md](events.md) — event signals, IRQ binding, intra-tick wake
- [heap.md](heap.md) — per-module heap allocation
- [reconfigure.md](reconfigure.md) — live graph reconfigure phases and drain protocol
- [timing.md](timing.md) — stream clock vs wall clock, StreamTime, producer scheduling
- [capability_surface.md](capability_surface.md) — hardware section, capability resolution, auto-wiring
