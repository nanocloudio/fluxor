# Fluxor Module Architecture

Core architecture and runtime principles for the module graph.

## Table of Contents

1. [Principles](#principles)
2. [Module Interface Contract](#module-interface-contract)
3. [Ports and Content Contracts](#ports-and-content-contracts)
4. [Runtime and Memory Safety Invariants](#runtime-and-memory-safety-invariants)
5. [Operational Conventions](#operational-conventions)
6. [Runtime Graph Model](#runtime-graph-model)

---

## Principles

These principles codify the runtime contracts that keep the async, poll-based
graph stable under backpressure and real-time constraints.

### 1) Progress is defined by successful external effects

**Rule:** A module must only advance its internal timeline/state when it has
successfully committed the corresponding output (or consumed the corresponding
input).

- Sources (sequencer): time advances only when the current value has been
  delivered.
- Sinks (I2S): audio time advances only when a buffer has been accepted/pushed.

**Rationale:** Prevents drift when channels backpressure or DMA is busy.

**Pattern:** Keep an explicit `delivered_*` marker and gate all "advance" logic
on it.

---

### 2) Output messages must be atomic at the channel layer

**Rule:** Every edge has a declared message unit (frame size). Modules must
never rely on multi-call assembly of one message unless the channel guarantees
atomicity.

- Control edges should use fixed-size messages (prefer 32-bit or 64-bit).
- Audio edges should use fixed-size frames (typically 4 bytes per stereo sample).

**Rationale:** Partial writes/reads introduce variable delivery time which
becomes timing jitter.

**Do:**
- Use 4-byte control messages (`u32`) instead of 2-byte (`u16`) if the channel
  implementation is word-based.
- If partials are possible, implement a full message reassembly buffer and do
  not advance time while assembling.

**Don't:**
- Send 2 bytes and "hope" they arrive together.

---

### 3) Timebase selection: control-rate timing must not depend on call frequency

**Rule:** Any module that schedules events must compute time deltas from a
monotonic clock, not from "number of steps" or "assumed poll rate".

**Rationale:** Step frequency varies with load and logging.

**Preferred:**
- `micros()` monotonic if available.
- Otherwise `millis()` with careful quantisation handling and jitter mitigation.

**Design note:** If you only have `millis()`, treat 1 ms as your minimum
scheduling quantum and avoid patterns that amplify that jitter (partial message
delivery, heavy logging).

---

### 4) Timer start is anchored to event commitment

**Rule:** If an event’s duration is defined as “N ms after value X is delivered”,
the timer must be initialized at the moment X is delivered—not at module
creation and not at the next `module_step`.

**Rationale:** Prevents "first event too long" and start-up skew.

**Pattern:** On first successful write, set `timing_init = 1`, set `last_tick =
now`, clear accumulators.

---

### 5) Explicit backpressure contract

**Rule:** Every module must define and obey its backpressure policy:
- Source modules: must not generate faster than downstream can accept.
- Transform modules: must not consume input unless they can eventually emit
  output (or they must buffer internally).
- Sink modules: must handle starvation deterministically (e.g., write silence)
  and record it.

**Rationale:** Prevents hidden buffering, drift, and audio artefacts.

**Examples:**
- Sequencer: if output is blocked, do not advance note time.
- Oscillator: if output is blocked, do not advance phase (or restore and
  advance only for frames actually written).

---

### 6) "Audio time" and "control time" must be decoupled

**Rule:** Control updates must not be delivered via the same mechanisms that can
be delayed by audio streaming pressure unless you explicitly accept jitter.

**Rationale:** If control messages share a congested channel with audio frames,
note changes will wobble.

**Recommendation:**
- Separate control and audio channels.
- Keep control messages small and atomic.
- Prefer latest-wins semantics for control (see next rule).

---

### 7) Control edges should be latest-wins, not queue-accurate

**Rule:** Frequency/parameter controls should generally be treated as state
(latest value), not events (every value must be processed).

**Rationale:** If control changes queue up, you get delayed parameter jumps.

**Implementation options:**
- Channel overwrites (single-slot mailbox).
- Drain loop: read all available control messages each step, keep only the most
  recent.

**Control contract (no mailbox channels):**
- Controls flow over normal pipe channels.
- Each control consumer must drain all pending control messages each step and
  apply only the most recent value.
- Producers should emit atomic-sized control messages (prefer `u32`) to avoid
  partial delivery and reassembly.

---

### 8) Logging must be treated as a real-time hazard

**Rule:** Logging inside `module_step` must be rate-limited and never on the hot
path for audio/control scheduling.

**Rationale:** Logging changes timing, increases contention, and creates jitter
that looks like "mysterious audio bugs".

**Policy:**
- Compile-time feature gate, or
- Throttle to ≥100 ms, or
- Log only transitions (starve events, partial writes, state changes).

---

### 9) Memory ordering around DMA and shared buffers is mandatory

**Rule:** If the producer writes a buffer and then signals/pushes it to DMA via
syscalls, it must issue the appropriate fence before the syscall that makes the
buffer visible to DMA.

**Rationale:** Prevents "identical but distorted" style bugs from stale cache or
reordering.

**Pattern:** `compiler_fence(SeqCst)` (or stronger platform fence if needed)
immediately before push.

---

### 10) Define module "step semantics" precisely

**Rule:** `module_step` must satisfy:
- Non-blocking: bounded work per call.
- Deterministic: no unbounded loops over variable input unless capped.
- Idempotent under retry: if an output write partially succeeds, the retry must
  produce identical remaining bytes and correct timeline progression.

**Rationale:** Makes composition safe and prevents phase/time corruption.

**Burst stepping:** Returning `2` (Burst) requests immediate re-step within the
same tick, up to `MAX_BURST_STEPS` (4) additional steps. Each individual burst
step must still satisfy all the rules above — Burst does not relax the bounded
work contract. It is a scheduling hint for compute-heavy modules that can
productively do multiple chunks per tick (see `guides/compute_heavy_modules.md`).

---

### 11) Observability is part of the module contract

**Rule:** Modules must expose enough runtime signal to diagnose flow and timing
issues without intrusive debug changes.

**Minimum expectation:**
- initialization and error transitions are visible
- drop/starvation/backpressure counters are available where relevant
- periodic status reporting is optional but supported

**Rationale:** Async pipeline failures are often timing-sensitive and require
low-overhead operational visibility.

---

### 12) Capability boundaries must remain explicit

**Rule:** Foundation modules remain hardware-agnostic; driver modules may
use bus primitives, but both must keep syscall and port contracts explicit.

**Rationale:** This preserves portability of the foundation layer while
allowing hardware-specific driver modules to remain isolated and composable.

---

## Module Interface Contract

Modules are isolated runtime units with a stable kernel boundary.

### Lifecycle Shape

Each dynamic module follows this lifecycle:

1. `module_state_size()` declares state memory requirements.
2. `module_init(syscalls)` receives the syscall table.
3. `module_new(...)` binds channels, parses params, and initializes module state.
4. `module_step(state)` advances the state machine cooperatively.
5. Module teardown occurs by graph reset/reconfigure and arena reset.

This contract keeps modules loadable, relocatable, and independent of board-specific firmware code.

### Binary and Loader Contract

The runtime loader enforces a concrete module binary contract:

- Table magic: `FXMT`; module magic: `FXMD`
- Module ABI version must match loader expectation
- Required exports are FNV-1a hash resolved: `module_state_size`,
  `module_init`, `module_new`, `module_step`
- Optional exports: `module_channel_hints`, `module_arena_size`,
  `module_drain`, `module_deferred_ready`, `module_mailbox_safe`,
  `module_in_place_safe`
- The header carries schema/manifest section sizes, capability flag
  byte (`reserved[0]`), and required capability bits
- Parameter schema and manifest payloads are embedded in the `.fmod` image

Module sources include three SDK files via the standard pattern:

```rust
#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");
```

`modules/sdk/abi.rs` is the stable kernel ABI definition. `runtime.rs`
contains compiler intrinsics and helper functions every PIC module
needs. `params.rs` provides the `define_params!` macro and parameter
schema encoding. Modules outside the fluxor tree (such as the Clustor
project's modules) include the same files via a relative path through
their git submodule.

See `src/kernel/loader.rs`, `modules/module.ld`, and `tools/src/modules.rs`
for the loader, linker script, and pack tool.

### Step Outcome Contract

`module_step` uses a compact result model:

- `0`: Continue (yield, no terminal state)
- `1`: Done (module reached terminal completion)
- `2`: Burst (request immediate re-step in the same scheduler cycle)
- `3`: Ready (initialization complete, downstream may run)
- `<0`: Error (errno-style failure)

`Burst` is a scheduling hint, not a license for unbounded work. Each step
call remains bounded and non-blocking.

`Ready` participates in the deferred-ready chain. A module that exports
`module_deferred_ready` (header flag bit 2) gates its downstream consumers
until it returns `Ready` from a step. This is how drivers like cyw43 and
the IP module signal "I am initialized" without the kernel needing to
know what initialization means for any specific device.

### Drain Contract (Live Reconfigure)

Modules that export `module_drain` participate in graceful shutdown
during a live graph reconfigure. The pack tool sets header flag bit 3
(`drain_capable`) when the export is present. During the `DRAINING`
phase, the scheduler calls `module_drain(state)` once on the module
(in reverse topological order) to signal "stop accepting new work."
The module then continues stepping normally until in-flight work is
complete and it returns `Done` (1) from `module_step`. After all
drain-capable modules have completed, the scheduler transitions to
`MIGRATING` and instantiates the new graph.

See `architecture/reconfigure.md` for the full state machine.

### Fault Recovery

Modules can be assigned a protection level at config time:

- **Level 0 (None)** — direct call, no isolation. Same as historical behavior.
- **Level 1 (Guarded)** — step guard timer detects timeouts. A module
  that overruns its step deadline is marked as faulted.
- **Level 2 (Isolated)** — hardware memory protection (MPU on RP2350,
  MMU on CM5). The kernel maps only the module's state, code, channel
  buffers, and heap; any other memory access raises a fault.

Faulted modules transition through `Running → Faulted → Recovering`
according to a per-module fault policy:

| Policy | Behavior |
|--------|----------|
| `Skip` | Log the fault and skip this module on subsequent ticks |
| `Restart` | Re-allocate state, call `module_new` again, re-enter the graph |
| `RestartGraph` | Trigger a full graph reconfigure (last resort) |

Recovery is bounded by a per-module restart count and exponential
backoff. The kernel records `FaultStats` per module accessible via
`dev_query` for telemetry.

### Async I/O Pattern

Hardware-facing operations use start/poll sequencing:

1. Start an operation (`*_start`).
2. Return/yield while pending.
3. Poll for completion (`*_poll`) in subsequent steps.

This pattern keeps every module cooperative and preserves predictable scheduler latency under load.

## Ports and Content Contracts

Modules exchange data through named ports declared in each module manifest.

### Port Roles

- Input ports consume upstream data streams.
- Output ports produce downstream data streams.
- Control ports carry command/state updates with atomic message boundaries.

### Content Contracts

Port `content_type` is the semantic contract for graph wiring and validation.
Examples include `OctetStream`, `AudioPcm`, `ImageRaw`, and `FmpMessage`.

The runtime transports bytes, while config-time validation enforces type compatibility.

### Backpressure Contract

- Sources do not advance production time without successful downstream commit.
- Transforms either emit or retain enough state to retry safely.
- Sinks behave deterministically under starvation (for example silence insertion or hold-last-value policies).

## Runtime and Memory Safety Invariants

### Layout and ABI Boundaries

- Cross-boundary structs use stable C layout (`repr(C)`).
- State and buffer ownership remains explicit at module boundaries.
- Module state sizing is declarative and kernel-managed through arenas.

### Alignment and DMA Safety

- DMA-visible buffers use natural word alignment.
- Memory ordering is explicit at producer-to-DMA handoff boundaries.
- Zero-copy paths preserve ownership and sequencing invariants before release signals.

### Determinism Rules

- No unbounded loops over dynamic input in one step call.
- Retry behavior is idempotent for partial progress cases.
- Time is derived from monotonic clocks or committed stream progression, never assumed call frequency.

## Operational Conventions

### A) Edge metadata

In config/graph, record for each edge:
- frame size (bytes)
- semantics: stream vs control (latest-wins)
- atomicity requirement
- backpressure behaviour

Then modules can validate at runtime (or loader-time) that they are connected to
compatible edges.

### B) A short "module author checklist"

A one-page checklist is more likely to be read than long docs. Example items:
- Does my output message have a fixed size?
- Can the channel partially write it? If yes, is reassembly safe and does time
  only advance on commit?
- Am I using `millis()`/`micros()` deltas rather than step count?
- Is logging disabled or throttled?
- If DMA involved: did I fence correctly?

### C) Provide reference implementations

Keep "golden" modules that demonstrate the contracts:
- `audio_source` (phase pacing + partial write correctness)
- `sequencer` (timer anchored to commit)
- `control_consumer` (drain-loop latest-wins pattern)

## Runtime Graph Model

The kernel uses a graph-based execution model. Modules are connected via
channels, and the runner steps all modules each iteration.

```
+-------------------------------------------------------------+
|                      MODULE GRAPH                            |
+-------------------------------------------------------------+
|                                                              |
|  +--------+         +--------+         +--------+          |
|  | Source |--chan--->| Trans  |--chan--->|  Sink  |          |
|  | (sd)   |         |(digest)|         |(logger)|          |
|  +--------+         +--------+         +--------+          |
|                                                              |
|  Module roles (from header):                                |
|  - Source (1): Produces data, requires output channel       |
|  - Transformer (2): Processes data, requires both channels  |
|  - Sink (3): Consumes data, requires input channel          |
|                                                              |
|  Each module implements step() and uses channel syscalls    |
+-------------------------------------------------------------+
|                      LOADER                                  |
|  PIC modules loaded from flash -> DynamicModule wrapper      |
|  module_state_size() -> module_init() -> module_new()         |
|  State in kernel RAM, code executes from flash (XIP)        |
+-------------------------------------------------------------+
|                      RUNNER                                  |
|  setup() -> setup_graph() -> run_main_loop()                  |
|  Automatic tee/merge insertion for fan-out/fan-in           |
+-------------------------------------------------------------+
```


For asset banks, selectors, and control bindings, see:
- `../guides/asset_banks.md`
- `../guides/input_system.md`
- `../guides/input_gestures.md`
