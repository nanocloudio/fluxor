# Graph Pipeline Architecture

The kernel loads modules into a runtime graph, opens channels
between them, and its domain loops step them cooperatively in the
composer's order (producers before consumers). This
document describes the runtime model, the channel mechanics, the
execution loop, and the lifecycle of modules and graphs.

## Design Goals

- Compose modules into arbitrary graphs via configuration, not firmware code
- Keep the kernel small and protocol-agnostic
- Make all I/O non-blocking with structural backpressure
- Support live reconfiguration that drains admitted work before
  reset, subject to a bounded timeout
- Run identical module binaries across silicon families

## Runtime Model

Source: `src/kernel/exec/scheduler/mod.rs`

```
Config (flash or firmware image)          Runtime
--------------------------------          -------
modules[]   ───────────────────►  ModuleSlot[] (state, hints, caps)
edges[]     ───────────────────►  Edge[] with channel handles
domains[]   ───────────────────►  Per-domain exec mode, cadence, budget
            ───────────────────►  setup() → graph instantiation → domain loop
```

A graph is a set of module instances and a set of directed edges that
connect them. Each module is a `.fmod` artefact loaded from flash. Each
edge becomes a kernel-allocated channel ring buffer. Each domain loop
steps its domain's instantiated modules each pass, in the composer's order, until
the graph reaches a terminal state, encounters a fault, or is asked to
reconfigure.

## Graph Configuration Model

Source: `tools/src/config/generate.rs`

Graphs are declared in config as module instances plus explicit wiring
edges, with an optional pin-level `hardware:` section validated against
the board and a `platform:` section the config tool expands into driver
stacks (see [capability_surface.md](capability_surface.md)).

### Top-Level Shape

- `target` — silicon/board identifier (e.g. `pico2w`, `pi5`, `qemu-virt`)
- `hardware` — physical hardware declarations (network, audio, display, storage)
- `modules` — application module instances and their parameters
- `wiring` — directed edges between module ports
- `data` — optional inline assets referenced by modules
- `execution` — optional domains: each one's exec mode and cadence (see [scheduler.md](scheduler.md#where-the-execution-mode-is-declared))
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

- The stepping order is the composer's breadth-first topological order
  over the edges (producers before consumers), projected onto each domain
- Fan-out and fan-in become `tee` and `merge` modules the composer inserts
  (see [Tee and Merge](#tee-and-merge))
- A cycle refuses the graph unless the config sets
  `scheduler.accept_cycles`; then its members step after the rest, in index
  order

### Inline Data Assets

The optional `data` section stores small assets directly in the config
payload. This is suited to embedded presets and sequences where
external storage is not required.

### Validation

The config tool enforces:

- module existence and parameter shape against the manifest
- valid port references on both ends of every wire
- content-type compatibility on each edge
- bounded resource usage (channels, buffers, module slots, arena fits)
- pin and bus conflicts against the silicon's hardware capabilities
- capability satisfaction (every `requires` met by some `provides`)

## Module Execution

Source: `src/kernel/module/loader.rs`,
`src/kernel/exec/scheduler/slot.rs`

A module states its facts once, at the crate root, and implements its
entry points:

```rust
fluxor_rt::module_facts! { state: ModuleState }
#[no_mangle] pub extern "C" fn module_init(syscalls: *const c_void) { ... }
#[no_mangle] pub extern "C" fn module_new(in_chan: i32, out_chan: i32, ctrl_chan: i32,
                                          params: *const u8, params_len: usize,
                                          state: *mut u8, state_size: usize,
                                          syscalls: *const c_void) -> i32 { ... }
#[no_mangle] pub extern "C" fn module_step(state: *mut u8) -> StepReturn { ... }
```

Further capabilities are manifest facts or optional entry points:

| Fact / entry point | Purpose |
|--------|--------|
| `module_facts!`'s `arena:` | Request a per-module heap (see [heap.md](heap.md)) |
| `module_drain` | Support graceful drain during live reconfigure |
| `deferred_ready = true` | Gate downstream modules until init completes |
| `mailbox_safe = true` | Declare safe consumption from mailbox channels |
| `in_place_writer = true` | Declare safe in-place mailbox transformation |
| `module_pipeline_refill` | Bounded input-refill hook called between steps |
| `module_post_tick_flush` | TX-only flush hook called after the module pass |
| `module_isr_entry` | `irq`-mode interrupt entry (see [scheduler.md](scheduler.md)) |
| `provider_contracts` + `module_provider_dispatch` / `module_provider_selector` | Provider contract surface (see [abi_layers.md](abi_layers.md)) |

### Step Outcome

`module_step` returns a small integer:

| Value | Meaning |
|-------|--------|
| `0` | Continue — yield, more work possible later |
| `1` | Done — module reached terminal completion |
| `2` | Burst — re-step immediately, more work this tick |
| `3` | Ready — initialisation complete, downstream may run |
| `<0` | Error (errno-style negative codes) |

`Burst` is a scheduling hint, not a licence for unbounded work. The
scheduler re-steps a bursting module under a burst deadline: either the
module's manifest-declared burst deadline, or the per-step deadline
multiplied by a fixed burst multiplier. Between burst iterations the
scheduler also checks the domain budget, so a single bursting module
cannot consume the whole tick. `MAX_BURST_STEPS` (16384) in
`src/kernel/exec/scheduler/pass.rs` bounds the iteration count as a
final safety valve.

`Ready` participates in the deferred-ready chain: a module that exports
`deferred_ready = true` is gated by the scheduler so that its downstream
consumers do not run until it has returned `Ready` from a step. The
gating is transitive: if A is gated on B and B is gated on C, then A's
consumers wait until C reports ready, then B reports ready.

The same gate covers a dependency no edge shows. A module that requires a
contract (`requires_contract` in its manifest) whose default provider is
a deferred-ready module waits for that provider's `Ready` exactly as a
module downstream of it on an edge would: the consumer reaches the
provider through `provider_call`, not a channel, but a store whose disk
mounts only once the graph steps answers `EAGAIN` until then, and a
consumer that subscribes or reads once at its first step would take that
for a refusal. Deferred-ready consumers are left ungated, so providers
that require each other's contracts still step to readiness. The gate is
set once instantiation is complete, at boot and after a rebuild alike.

The gate holds a module silently, so the kernel watches it: once a second it
looks for modules the gate is holding, and one held for a whole 30-second
window is logged once, naming a deferred module upstream that has not
reported Ready (`[ready] <module> not stepped for at least 30s: waiting on
<upstream> ...`), and flagged `readiness_starved` in its `ModuleStateSnapshot`.
When the hold ends the record clears, and a later hold is reported afresh.

### Async I/O Pattern

Hardware-facing operations use start/poll sequencing:

1. Begin an operation (`*_start`)
2. Return / yield while pending
3. Poll for completion (`*_poll`) on a subsequent step

This pattern keeps every module cooperative and predictable. There is
no blocking syscall in the table; even DMA-backed transfers are
expressed as start/poll pairs.

## The Domain Loop

Source: `src/kernel/exec/scheduler/pass.rs`, `src/platform/rp.rs`,
`src/kernel/exec/domains/mod.rs`

Every target's loop drives the one pass engine; [scheduler.md](scheduler.md#passes)
describes the passes and [events.md](events.md#scheduler-wake-integration)
the loop around them. A single-core loop (RP, Linux, wasm) runs a tick
pass over every domain, then a wake pass for what the tick latched, then
sleeps until the pass's deadline or a wake, then runs a wake pass again; a
domain loop on its own core (bcm2712, uefi) does the same for its one
domain.

The sleep differs by target:

| Target | Sleep mechanism |
|--------|----------------|
| RP2040, RP2350 | Deadline alarm against the scheduler wake (WFE, woken by SEV) via `wait_for_wake` |
| BCM2712, UEFI | Each domain loop arms its core's timer at the pass's deadline and waits in WFI for it or another interrupt |

In every case an event signal from an ISR or another module wakes the
loop early: the sleep is bounded above by the deadline the tick pass
returned (the graphs' pacers, bounded by the domain's armed timers) but
returns at once when there is work to do.

## Channel-Based IPC

Source: `src/kernel/ipc/channel.rs`, `src/kernel/ipc/buffer_pool.rs`

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
consumer. Fan-out and fan-in are handled by `tee`/`merge` modules
the composer inserts when wiring requires them: at build time for a
node graph, and when a workload's graph is composed for the ports of that
graph's own modules, by the same rules. The kernel allocates
channel buffers from a dedicated buffer arena, separate from module
state, so that channel sizing does not compete with module memory.

### Channel Buffer Sizing

Before opening channels, the scheduler reads each module's per-port
`buffer_size` and `max_record` from the port-capacity section of its
signed manifest. No module code runs, and every declared port is
honoured.
Channel buffers are allocated from the buffer arena. Both the state
arena and the buffer arena are reset on graph reconfigure. Between
reconfigures, a channel closed by a live graph change returns its buffer:
the region merges with free neighbours and either lowers the arena's
high-water mark or joins a free list that later channels take from (best
fit), so a node that admits and reaps workloads indefinitely holds the
arena at a fixed point. Every buffer is aligned to a 64-byte cache line.
A mailbox buffer still lent to a producer or consumer when its channel
closes is not returned — the holder may still touch it — and stays spent
until the next reconfigure.

An edge's ring is the largest of its producer port's `buffer_size`, its
consumer port's and the wiring entry's `buffer_bytes`, rounded up to a
power of two (64 bytes at least); an edge that none of the three sizes
gets the default 8192 bytes, and a request over 4 MiB is refused rather
than clamped. A producer port whose `max_record` does not fit its ring
is refused too: a write larger than the ring could never succeed. On a
ring (any edge outside a mailbox group) a record costs its length plus a
two-byte length prefix per 65535 bytes (`ring_size::record_bytes`), so
`max_record` is measured with its prefixes; a mailbox's record is the
whole buffer. A
mailbox group's ring is its largest member's, opened once and aliased by
every member whose consumer is mailbox-safe; a member whose consumer is
not opens a ring of its own at the group's size. The tee or merge on a
fanned port adds the edge joining it to the port, sized by that port, and
each fanned edge beyond it is sized by its other end and its
`buffer_bytes`. On bcm2712 every edge between two domains, or of class
`cross_core`, adds a default consumer-side ring.

`contracts/src/ring_size.rs` states this rule once: the scheduler opens
rings by it, `channel_open` bounds them by it, and `fluxor build` (and
`--check`) replays graph preparation by it over the compiled config. It
prints the largest rings beside the total, the share of the target's
buffer arena and the slack, and refuses a graph whose rings do not fit,
naming the edges that take the most. The limit is the kernel profile's
arena, or the graph's `capacity: { buffer_arena }` envelope where that is
lower; every ring also takes a channel slot, counted against the
profile's channel table or `capacity: { channels }`. The arena a booted
graph uses and the channels it opens equal that replay. Typical hint choices: a few
hundred bytes for control channels, 2048 bytes for PCM audio, several KiB
for network frames, and tens of KiB for mailbox video frames — a ring
sized to the records its edge carries.

### Ends

Every channel has one producer and one consumer, bound by the kernel from
the edge it carries when the graph is wired (`channel_bind_edge`); a
channel a module opens itself (`channel::OPEN`) has the opener at both
ends, and a tap's channel is written by the kernel alone. Every op checks
the caller's end:

| Side | Ops |
|------|-----|
| Consumer | `channel_read`, `channel_peek`, `channel_discard`, `RECORD_LEN`, `ACQUIRE_READ`, `RELEASE_READ`, `ACQUIRE_INPLACE` |
| Producer | `channel_write`, `SET_HUP`, `WRITABLE`, `ACQUIRE_WRITE` |
| Either | `channel_poll`, `FLUSH`, `CLOSE`, `RELEASE_WRITE` (its lend's holder only) |

Anyone else gets `EBADF`. In a mailbox alias chain the in-place module
between producer and consumer is the chain's relay and acts from the
consumer side. The kernel's own code acts from every end.

### FIFO Mode

The default channel mode is FIFO with copy semantics. `channel_write`
copies one record into the ring, whole or not at all (`EAGAIN` when it
does not fit now); `channel_read` copies bytes out. This is the right
mode for byte-stream producers that build their output incrementally: a
decoder emitting partial frames, a sensor emitting timestamped readings,
a network driver pushing variable-size packets.

#### Record boundaries

The ring keeps every write's boundary: each write is stored as
`[len u16 LE][payload]`, and a write over 65535 bytes is stored as
several records. Reads, peeks and discards are a byte stream over the
payload that consume prefixes as they cross them, so a consumer that
frames by its own headers reads exactly what the producer wrote. A
consumer that frames by records asks `channel::RECORD_LEN`: the unread
bytes of the record at the head (`EAGAIN` when nothing is buffered). The
prefix costs ring space — a ring of N bytes takes a write of at most
N − 2, and a write of the ring's whole capacity is refused —
and `WRITABLE` answers the largest single write that fits now. The
cross-domain pump moves a producer's channel record by record, so the
consumer's channel keeps the same boundaries.

### Mailbox Mode (Zero-Copy)

For workloads where a producer can fill a complete buffer in one step
and the consumer can process it without copying, channels support
mailbox mode: the channel holds one record, lent rather than copied
through the channel ops `ACQUIRE_WRITE` / `RELEASE_WRITE` /
`ACQUIRE_READ` / `RELEASE_READ` / `ACQUIRE_INPLACE` (SDK helpers
`dev_buffer_*`). No copy occurs; the buffer stays in place and the
consumer reads it directly. `channel_read` / `channel_write` work on a
mailbox too, copying.

```
  FIFO copy        mailbox (zero-copy alias chain)
 ──────────      ──────────────────────────────────
 Source ──copy──► Producer ──alias──► InPlace ──alias──► Sink
         ch A      (group=1)  ch B    (group=1)  ch B    (DMA)
```

Mailbox mode is enabled per edge by setting a `buffer_group` value in
the wiring. All edges in the same group share one underlying buffer.

#### The record machine

The record moves through four states (`src/kernel/ipc/buffer_pool.rs`):

```
            acquire_write              publish(len>0)             acquire_read
   IDLE ─────────────────► WRITING ─────────────────► READY ─────────────────► READING
    ▲  ◄── cancel_write ──────┘ ▲                       │ ▲                      │
    │     (len == 0)            │ acquire_inplace       │ └──── cancel_read ─────┤
    │                           └─ (READY && !processed)┘     (bit untouched)    │
    │◄────────────────────────── release_read ──────────────────────────────────┘
    │◄── FLUSH (READY only; processed = 0)       FLUSH on WRITING/READING = EBUSY
```

- A lend (WRITING or READING) names its **holder**, and ends only with
  it: the holder's release or cancel, the holder's retirement (its write
  lend is cancelled, its read lend returned unconsumed), or the channel's
  close, which abandons the memory rather than hand it to the next
  channel. Another module's release answers `EBUSY`.
- `FLUSH` never ends a lend: on a WRITING or READING record it answers
  `EBUSY` and changes nothing. On a READY record it drops the record.
- The `processed` bit is set when a WRITING that began as an in-place
  acquire publishes, and cleared when the record leaves READY for IDLE.
  `ACQUIRE_INPLACE` takes only a READY record that is not processed, so
  at most one in-place transform runs per record. A peek of a mailbox is
  an acquire and a cancel, so it never races an in-place writer on
  another core and never clears the bit.

#### One commit path

Every successful write — copied or lent, ring or mailbox, its reader
gone or not — commits through one step: the channel's WROTE is set, its
tap gets a copy, the record becomes visible, and the consumer's wake is
latched. A lent write's only exit from WRITING is that publish. A
channel whose reader has retired commits every write and keeps none of
it (a mailbox record left READY when the reader retires is dropped).

#### Lengths

- A write of 0 bytes publishes nothing and returns 0; `RELEASE_WRITE(0)`
  cancels the lend (WRITING → IDLE) and returns 0. `RELEASE_WRITE(n)`
  returns `n`; a length past the buffer's capacity is `EINVAL`, the lend
  kept.
- A read that fits no byte (`len == 0`, or nothing buffered) returns
  `EAGAIN`.
- A mailbox read needs room for the whole record: a shorter buffer is
  `EINVAL` and the record stays READY. A copied write larger than the
  buffer is `EINVAL`, its lend given back.
- A mailbox discard drops whole records: `n` at least the record's
  length releases it and returns the length, `0 < n < record` is
  `EINVAL`, `n == 0` returns 0.

#### Capability flags

A module in a mailbox chain declares what it can do there in its manifest
(`mailbox_safe`, `in_place_writer`), carried as header flag bits (see
[Header flags](module_architecture.md#header-flags)). A group's ring is
aliased only into an edge whose consumer is `mailbox_safe`; any other
member opens a mailbox of its own at the group's size, which later members
alias. A reader needs `mailbox_safe`; a module that modifies the record in
place needs both, and setup refuses a group with more than one
`in_place_writer`.

#### Constraints

- At most one in-place transform per alias chain (the `processed` bit
  prevents double-processing)
- No alias chain passes through a `tee` or `merge`. Over a port whose
  content type is `Framed` (or a port declared `framed = true`) the composer
  gives every edge around the fan a `buffer_group` of its own, so each
  is a mailbox and the fan moves one record per transfer; over any
  other port it clears `buffer_group` and the edges are FIFOs
- Buffer sizing for grouped edges is the maximum of all port hints
  across the group, so the channel is large enough for the most
  demanding consumer

### Stream state: HUP, ERR, WROTE, FLUSH

A channel has one source of HUP: the producer's `SET_HUP` (end of
stream), or the producer's retirement (`producer_gone`, set by the
scheduler for every output of a module it retires, with ERR beside it
when the module failed). `channel_poll` reports HUP for either, ERR when
the producer failed, and WROTE once anything was written since the last
flush. `FLUSH`, from either end, starts the stream over: it drops what
is buffered, the owed discard and WROTE, and the stated HUP; HUP from a
retired producer and ERR stay. A mailbox polls OUT while its record is
IDLE or its reader is gone.

### Signals between a pair

The kernel carries no sideband word beside a channel. What a pair of
modules tells each other travels in the contract the pair speaks:

- **A consumer selecting what its producer streams** (a seek, a file or
  blob index): the `stream_select` edge contract. The consumer binds once
  — `provider_open(stream_select, kernel::BIND, [PORT][in][index])` — and
  calls `SELECT` with `[position u64]` through the bound handle; the
  producer at the other end of that port serves it, restarts its stream at
  the position and ends the item with `SET_HUP`. The consumer flushes its
  input first. A block source is selected through `storage.block`'s
  `READ_STREAM` instead, which carries the LBA.
- **A producer stating its stream's format** (a sample rate): an in-band
  record on the data edge. On an `AudioSample` edge a record of exactly
  six bytes, `[0xA5F0 u16][sample_rate u32]`
  (`contracts::audio_sample::format`), states the rate of the frames
  after it; sample records are whole 4-byte frames, so no sample record
  is ever six bytes. The consumer reads record by record
  (`RECORD_LEN`, or one mailbox record at a time), and a stage between
  producer and sink forwards the format record as it arrives.

### FIFO → Mailbox Boundary Rule

When a transformer reads from a FIFO input and writes to a mailbox
output, it must check the mailbox output is acquirable before
consuming the FIFO input:

```c
// Correct: reserve the output buffer first
if (!(channel_poll(in_chan, POLL_IN) & POLL_IN)) return 0;  // nothing to move
u32 cap = 0;
u8 *buf = dev_buffer_acquire_write(out_chan, &cap);
if (!buf) return 0;          // do not read input — output not ready
int read = channel_read(in_chan, buf, cap);
dev_buffer_release_write(out_chan, read > 0 ? read : 0);
```

A release of zero bytes cancels the lend and publishes nothing, so a
transformer that read nothing gives its output back unused.

FIFO reads are destructive. If the module reads input but then cannot
acquire the mailbox output, the data is lost; there is no recovery
path because the FIFO has already advanced. Reserving the output first
guarantees that any byte taken off the FIFO has a place to land.

### Backpressure

Backpressure is structural: a producer that cannot write its output
(because the channel buffer is full or the mailbox is busy) does not
advance its internal state. Time, frame counters, and read positions
only move when the corresponding output has been committed. This is
the same rule whether the producer is generating audio samples,
emitting Ethernet frames, or fanning out an application event; see
[module_architecture.md](module_architecture.md) for the principles.

## Tee and Merge

Source: `contracts/src/graph/plan.rs`, `modules/foundation/tee`,
`modules/foundation/merge`

When the wiring connects one output to multiple inputs, or multiple
outputs to one input, the composer inserts a fan module:

```
Config:                Runtime:
A → B                  A → B
A → C                  A → [tee] → B
                              → C

A → C                  A → [merge] → C
B → C                  B →
```

Tee and merge are foundation modules (`tee`, `merge`) the composer
adds to the composed graph and to the image's module table; each takes
scratch from its own heap, sized to the largest ring beside it. Two fans
are left out: a module with several inbound edges keeps its data inputs
unmerged, and an output whose consumers are exactly the modules feeding
the producer stays unteed. Fans are not visible in the config, but the
inserted instances do occupy module slots, so a heavily fanned graph
consumes more of the module table than its config lists.

A fan always copies, and what it copies per transfer is set by the
fanned port's content type. Over a byte stream it moves whatever is
waiting. Over a length-prefixed type (`EthernetFrame`, `NetProto`) or a
self-sizing one (`Telemetry`) it peeks the header and moves one whole
frame, once every output has room for it. Over a `Framed` type, or a
port declared `framed = true`, every edge around the fan is a mailbox
of its own and the fan moves one record per transfer, taking it from
the input only once every output is free; a record larger than the
fan scratch is a topology error the fan reports rather than retries.
No alias chain passes through a fan: the mailboxes a record fan uses
are never shared, and over every other type `buffer_group` is cleared.

## Module Instantiation

Source: `src/kernel/exec/scheduler/instantiation.rs`,
`src/kernel/module/loader.rs`

PIC modules go through this sequence during graph setup:

1. **Find** — locate the module in flash by name hash
2. **Validate** — check magic bytes, ABI version, code bounds
3. **Size** — the manifest's state size; a module whose manifest states none
   is refused
4. **Allocate** — reserve state from the state arena
5. **Heap** — the cap is the graph's per-instance `heap.arena_bytes`, else the
   type's declared arena (the manifest's); a committed heap is carved whole
   now, an elastic one commits its declared heap now and the room the graph
   grants above it as the module allocates
6. **Init** — call `module_init(syscalls)` once
7. **New** — call `module_new(in, out, ctrl, params, params_len, state, state_size, syscalls)`.
   `params` points into the resident config blob itself (or a live add's
   request): the kernel borrows module params in place rather than copying
   them, so it sets no ceiling on a module's params or on the config; the
   mapped blob is the only bound. Only an instance the platform stores
   runtime overrides for is handed a merged copy.
8. **Wait for ready** — if `deferred_ready` flag is set, gate downstream until first `Ready` outcome

State memory is zeroed by `alloc_state()` before `module_new` is
called, so modules do not need to re-zero their state struct.
Instantiation is sequential: a module whose `module_new` answers pending
is polled in a bounded loop until it is ready, or refused, before the next
module proceeds.

### Per-Module Heap

Modules that need dynamic allocation declare an arena (`module_facts!`'s
`arena:`, written into the manifest), which the graph may resize per instance with
`heap.arena_bytes`. The SDK helpers `heap_alloc`, `heap_free`,
`heap_realloc` allocate within that cap; on linux, bcm2712 and uefi the heap
commits the declared arena at instantiation and the room a larger graph cap
grants as it is used, elsewhere the cap is carved at instantiation. Modules with no
arena get no heap and pay zero cost. See [heap.md](heap.md).

### Protection and fault policy

Source: `contracts/src/isolation.rs`, `src/kernel/exec/step_guard.rs`

Every module runs under the step guard at one protection level
(`protection:`, config tag `0xF5`):

| Wire | Level | Mechanism |
|------|-------|----------|
| 0 | `privileged` | Direct call; the step guard detects overruns |
| 1 | `contained` | Unprivileged: its own RAM and all of XIP flash (MPU targets) |
| 2 | `isolated` | Unprivileged: its own RAM and its own code (MPU on RP, MMU on bcm2712) |

A gated (contained or isolated) module reaches the kernel only through the
gateway, which checks every pointer, channel and handle it is handed; see
[module_isolation.md](module_isolation.md). An access outside its regions
raises a fault that the scheduler catches, classifies, and handles by the
module's fault policy (`skip`, `restart` or `tolerate`; see
[module_architecture.md](module_architecture.md#fault-recovery)). The same
step guard catches modules that exceed their per-step time budget; see
[scheduler.md](scheduler.md#deadline-enforcement).

## Live Graph Reconfigure

The scheduler updates a running graph by draining it and rebuilding it:

```
RUNNING → DRAINING → RUNNING (rebuild)
```

In `Draining`, modules with the `drain_capable` flag have `module_drain`
called in reverse order. They stop accepting new work but keep stepping
until in-flight work completes (or the drain timeout expires). The graph is
then rebuilt through the same `prepare_graph` path as at boot: every arena
is reset and every module re-instantiated, so no module's state carries
across.

This is what lets an HTTP server finish responding to in-flight requests
before the new graph's server takes over. See
[reconfigure.md](reconfigure.md) for the state machine and the drain
protocol.

## Static Memory

Source: `src/kernel/exec/scheduler/state.rs`, `src/kernel/config.rs`

The scheduler consolidates per-module arrays into a single
`SchedulerState` struct held in a `static mut SCHED`: edges, module
slots, ports, channel hints, arenas, capability classes, permissions,
and drain state all live in one struct with a single `reset()`.

Kernel capacity — modules, edges, events, the state and buffer arenas —
is stated in one place, `src/kernel/config.rs`, one profile per kernel
platform (linux, bcm2712, uefi, wasm, RP); on RP the arena sizes come from
the per-silicon TOML files under `targets/silicon/`. Where a plan sizes a
table at boot, the profile states its bound. None of it is part of the
module ABI. [limit_register.md](limit_register.md) holds every figure, and
the config tool refuses a graph that does not fit the target's.

## Async Runtime Guardrails

The runtime relies on cooperative async behaviour across all graph
workloads:

- Hardware-facing operations use non-blocking start/poll patterns
- Backpressure flows through channel/buffer readiness, never sleep loops
- Periodic async tasks include explicit yield points and avoid tight loops
- Long critical sections in hot paths are avoided to protect scheduler latency
- Stream interfaces return promptly when data or capacity is unavailable

These rules apply to kernel HAL code and to PIC modules alike, whatever
the underlying wait mechanism. They are the contract that makes the
single-tick execution model work.

## Loader

Source: `src/kernel/module/loader.rs`

The loader parses the FXMT module table, validates each `.fmod`
payload (magic bytes, ABI version, function-pointer bounds), allocates
state from the state arena, and wraps loaded modules in a
`DynamicModule` that implements the kernel's `Module` trait. Related
concerns live alongside it in `src/kernel/module/`: `syscalls.rs`
(the syscall table handed to modules), `provider.rs` (provider
contract dispatch), `gateway.rs` (the gated modules' syscall gateway), and
`ota_stage.rs` (over-the-air staging).

The loader resolves exports via FNV-1a name hashing; there is no
symbol table in the `.fmod` file beyond a list of exported function
hashes and offsets. This keeps the binary format compact and the
loader fast.

## Related Documentation

- [module_architecture.md](module_architecture.md) — module step contract, principles, ABI
- [abi_layers.md](abi_layers.md) — ABI layers, contract inventory, provider dispatch
- [hal_architecture.md](hal_architecture.md) — bus primitives, syscall table, per-silicon HAL
- [events.md](events.md) — event signals, IRQ binding, intra-tick wake
- [heap.md](heap.md) — per-module heap allocation
- [reconfigure.md](reconfigure.md) — live graph reconfigure phases and drain protocol
- [timing.md](timing.md) — stream clock vs wall clock, StreamTime, producer scheduling
- [capability_surface.md](capability_surface.md) — capability vocabulary, content types, platform stack expansion
