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

**Rule:** If an event's duration is defined as "N ms after value X is delivered",
the timer must be initialised at the moment X is delivered, not at module
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
same tick. The scheduler bounds the burst by a time deadline (the module's
declared burst deadline, or the step deadline times a fixed multiplier) and by
the domain budget, so each individual burst step must still satisfy all the
rules above; Burst does not relax the bounded work contract. It is a scheduling
hint for compute-heavy modules that can productively do multiple chunks per
tick (see [../guides/compute_heavy_modules.md](../guides/compute_heavy_modules.md)).

---

### 11) Observability is part of the module contract

**Rule:** Modules must expose enough runtime signal to diagnose flow and timing
issues without intrusive debug changes.

**Minimum expectation:**
- initialisation and error transitions are visible
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

Source: `src/kernel/module/loader.rs`, `tools/src/modules.rs`

Modules are isolated runtime units with a stable kernel boundary.

### Lifecycle Shape

Each dynamic module follows this lifecycle:

1. `module_state_size()` declares state memory requirements.
2. `module_init(syscalls)` receives the syscall table.
3. `module_new(...)` binds channels, parses params, and initialises module state.
4. `module_step(state)` advances the state machine cooperatively.
5. Module teardown occurs by graph reset/reconfigure and arena reset.

This contract keeps modules loadable, relocatable, and independent of
board-specific firmware code.

### Binary and Loader Contract

The runtime loader enforces a concrete module binary contract:

- Table magic: `FXMT`; module magic: `FXMD`
- Module ABI version must match loader expectation
- Required exports are FNV-1a hash resolved: `module_state_size`,
  `module_init`, `module_new`, `module_step`
- Optional exports: `module_arena_size`,
  `module_drain`, `module_deferred_ready`, `module_mailbox_safe`,
  `module_in_place_safe`, `module_pipeline_refill`,
  `module_post_tick_flush`, `module_isr_init` / `module_isr_entry`,
  and the provider-contract exports (`module_provider_dispatch`,
  `module_provides_contract`, `module_provider_selector`)
- The header carries schema/manifest section sizes, capability flag
  byte (`reserved[0]`), and required capability bits
- Parameter schema and manifest payloads are embedded in the `.fmod` image
- The manifest section (`FXMF`) carries a SHA-256 integrity hash over
  code+data, an Ed25519 signature over that hash, and the signer's
  public-key fingerprint. The loader recomputes the hash at admission
  time and rejects any module whose bytes drift from the manifest
  (`IntegrityMismatch`); with the `enforce_signatures` feature set,
  unsigned modules and bad signatures are rejected
  (`SignatureInvalid`). `fluxor modules sign` produces signed manifests; see
  [security.md](security.md) for the trust chain and
  [network_boot.md](network_boot.md) for the deployment-time use of the
  same signing key.

#### Position-independent data

A module image is placed at a load-time address and the loader applies
no relocations, so the image may contain no absolute address. Scalar
data is safe: a `static` or `const` table of integers or bytes lives in
`.rodata` and is reached PC-relative (`adrp` plus page offset on
aarch64, a PC-relative literal on thumb, a fixed linear-memory offset
on wasm32). The packer keeps every module's code page-aligned so the
`adrp` pair resolves at any load address. What is not safe is data
that *contains* an address: a `const` array of `&[u8]` or function
pointers, and a `static` holding a reference — including a single `&str`.
Each reads a wrong address at run time, on every target.

A `match` that returns literals differs by machine. On 32-bit Arm (both RP
dies) LLVM lowers it to a switch lookup table of absolute pointers, so it
has the same defect. On aarch64 LLVM emits a table of PC-relative offsets
instead, which needs no relocation — so the same source is correct on
bcm2712 and wrong on an RP die, and a module that targets both has to be
written for the RP case.

Hold names in a `name_table!` (`runtime/names.rs`): the strings are one run
of bytes with integer end offsets, built at compile time, so the only
address in play is the table's own. Otherwise act in each arm rather than
returning the literal from it.

`fluxor modules build` enforces this. It refuses (under `--strict`, as
`fluxor ci` builds; warns otherwise) an object carrying an absolute
relocation, naming the section. Two shapes are exempt, recognised from the
object's structure rather than from a name, so neither can hide a table
that code reads:

- a data section nothing in the object references — a retention static,
  kept alive by the linker script and never loaded by code;
- a section that is exactly one `core::panic::Location` — one pointer at
  offset 0 to a `.rs` path of the length the next word states, then the
  line and column. Code passes it to the panic call, but its pointer is read
  only by a panic already under way.

A table code reads is reached by a relocation from that code and is never
exactly one `Location`, whatever it is named and whatever its strings end
in.

#### What a module cannot link

A module links against the SDK's runtime (`runtime/intrinsics.rs`) and no
other: no `core` panic machinery, no soft-float library, no
`compiler_builtins`. The runtime provides `memcpy`, `memmove`, `memset`,
`memcmp`; on 32-bit Arm the `__aeabi_*` integer division, 64-bit shift and
multiply, and `__clzsi2`; on AArch64 the 128-bit division helpers
(`__udivti3`, `__umodti3`, `__divti3`, `__modti3`); and a trap for a slice
index out of bounds. Anything else the compiler reaches for is an undefined
symbol, and the module does not link.

| Construct | rp2040 | rp2350 | bcm2712 | Write instead |
|---|---|---|---|---|
| `f32` arithmetic | does not link (soft-float) | **links, then faults the whole node** — see below | native | scaled integers (fixed-point) |
| `f64` arithmetic | does not link | does not link | native | scaled integers (fixed-point) |
| `a / b`, `a % b` on any integer type, divisor not provably non-zero | does not link | does not link | does not link | a `NonZero*` divisor, or `checked_div` / `checked_rem` |
| signed `a / b`, `a % b` with zero ruled out | does not link | does not link | does not link | `checked_div` / `checked_rem`, or divide the magnitudes unsigned and restore the sign |
| `copy_from_slice` with lengths it cannot prove equal | does not link | does not link | does not link | a length the compiler can see, or a `zip` loop |
| `split_at` (and other panics that format a message) | does not link | does not link | does not link | `split_at_checked`, `get(..)` |
| slice index it cannot prove in bounds | links; a miss **hangs** | links; a miss **hangs** | links; a miss **hangs** | `get(..)`, handling the miss |

`u128` and `i128` arithmetic — multiply, divide, remainder — links on every
target: 32-bit Arm expands it inline, AArch64 calls the runtime helpers. The
divide-by-zero rule above still applies to it.

Division is refused at link, and indexing is not, deliberately. Every integer
`/` and `%` carries a divide-by-zero panic (and signed division a `MIN / -1`
overflow panic) whose absence stops the build, so an author learns about the
case at the desk. A slice index is too common to refuse, so the runtime
answers its panic with a trap that spins: an out-of-bounds index does not
fault, the step simply never returns. Use `get(..)` wherever the index is not
provably in range.

On rp2350 `f32` is a trap of a different kind, and a worse one. The target
is `thumbv8m.main-none-eabihf`, so the compiler lowers `f32` to VFP
instructions rather than calls, and the module links. The RP kernel does not
grant the coprocessor, so the first such instruction is a NOCP UsageFault
(CFSR bit 19); the fault handler reports it and parks the node. One `f32` operation in any module stops every module on the board,
not just its own. The FPU stays off by design: enabling it means lazy FP
context stacking on every exception (72 more bytes on the kernel stack each
time) and scrubbing the FP registers between modules, for no module that
needs it. A rig scenario holds this on the silicon.

The build holds this table true: a check builds one module per construct
for each die and fails the moment any row stops matching, so a toolchain
upgrade that moves a row is caught the day it lands.

#### Stack depth

A module steps on a stack it did not size — the kernel's on an RP part, where
every ungated module steps in turn on one stack; a stack in its own private
region when it is gated — so the composer admits its depth before a device
runs it. `fluxor modules build` measures it: the compile emits the assembly
beside the object, and the build walks the call graph from every `module_*`
entry point, summing each function's frame along the deepest path. The
`.fmod` manifest carries the figure, and `fluxor modules build -v` prints it
with the path that sets it.

| What the walk reads | How |
|---|---|
| Frames | 32-bit Arm: the `.save`/`.vsave`/`.pad` unwind directives, exactly. aarch64: the stack-pointer decrements |
| Calls, tail calls | A call stacks the callee on the caller's frame; a tail call replaces it |
| Indirect calls | Charged the deepest function whose address the module takes, one level deep; a taken function is also an entry point, since it is usually a callback the kernel calls. The rest of an indirect call's reach is the kernel, whose frames are the stack's reserve |
| No bound | Recursion, a frame sized at run time, a call outside the module: no figure is recorded |

Where the walk has no bound, or reaches less than the author knows the module
needs — a provider it calls that calls back, inline assembly that moves the
stack pointer — the module declares it:

```rust
declare_module_stack_bytes!(if cfg!(fluxor_silicon = "bcm2712") { 16 * 1024 } else { 5 * 1024 });
```

A declaration is a floor: the manifest records the larger of it and the
measurement, and a declaration below the measurement fails the build. The
composer refuses a graph on an RP target whose deepest module does not fit
the stack (see [The RP stack](hal_architecture.md#the-rp-stack)), or that
carries a module with no figure; it sizes a gated module's private region for
its depth, and on an MMU target refuses an isolated module deeper than
`[isolation] isolated_stack_kb`. The scheduler fences each
step at the admitted depth on the device — 128 painted bytes below it — and
faults a module whose frames write into the fence, which is what catches the
paths the walk does not follow.

Large locals are the usual cause of a deep path, and the compiler names them:
`rustc -C remark=stack-frame-layout -C debuginfo=2` lists every stack slot
with the variables it holds (`-C llvm-args=-no-stack-coloring` separates
slots that share storage). A value built by `new()` and assigned into state is
staged on the stack first; assigning from a `const` copies it in place.

Module sources include the SDK via the standard pattern:

```rust
#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");
```

`modules/sdk/abi.rs` is the assembler for the layered ABI. The
actual content lives under `modules/sdk/abi/kernel_abi.rs` (core
primitives), `modules/sdk/contracts/` (portable domain contracts such
as `hal/`, `net/`, `storage/`, `key_vault.rs`),
`modules/sdk/internal/` (kernel-private orchestration), and
`modules/sdk/platform/` (chip-specific raw register bridges). The
assembler composes them into the `abi` namespace; every opcode lives
in exactly one layer file and consumers import it by its real path.
[abi_layers.md](abi_layers.md) is the public reference for the
layering rules.

`runtime.rs` contains compiler intrinsics and helper functions every
PIC module needs. `runtime/params.rs` provides the `define_params!`
macro and parameter schema encoding. External modules can include the
same SDK files via a relative path through their checked-out Fluxor
SDK.

**Built-in modules** (`builtin = true` in their `manifest.toml`) are
compiled directly into the kernel binary rather than shipped as
`.fmod` images. Since there is no `.fmod` to embed a `define_params!`
schema into, built-ins declare their parameter schema in the manifest
TOML under a `[[params]]` section: the same wire format (TLV) as PIC
modules, but the schema is read off disk at config-build time.

Built-in manifests live under `modules/platform/<platform>/<name>/`,
with `linux/` for Linux-host APIs and `host/` for host-OS-agnostic
pure-Rust modules. The Rust implementation sits in
`src/platform/<platform>/<name>.rs`. Built-in vs PIC is a
deployment distinction (linked-in vs loaded-at-runtime), not a
selection one: `stacks/*.toml` route logical surfaces to either kind
transparently.

See [abi_layers.md](abi_layers.md) for the schema, validation rules
(unknown-key/range/required), the runtime-feature cross-check, and
the full module-categories layout. The kernel itself sees only the
resulting TLV bytes; built-in vs PIC is invisible at the wire layer.

See `src/kernel/module/loader.rs`, `modules/sdk/module.ld`, and
`tools/src/modules.rs` for the loader, linker script, and pack tool.

### Step Outcome Contract

`module_step` uses a compact result model:

- `0`: Continue (yield, no terminal state)
- `1`: Done (module reached terminal completion)
- `2`: Burst (request immediate re-step in the same scheduler cycle)
- `3`: Ready (initialisation complete, downstream may run)
- `<0`: Error (errno-style failure)

`Burst` is a scheduling hint, not a licence for unbounded work. Each step
call remains bounded and non-blocking.

`Ready` participates in the deferred-ready chain. A module that exports
`module_deferred_ready` (header flag bit 2) gates its downstream consumers
until it returns `Ready` from a step. This is how drivers like cyw43 and
the IP module signal "I am initialised" without the kernel needing to
know what initialisation means for any specific device.

### Drain Contract (Live Reconfigure)

Modules that export `module_drain` participate in graceful shutdown
during a live graph reconfigure. The pack tool sets header flag bit 3
(`drain_capable`) when the export is present. During the `Draining`
phase, the scheduler calls `module_drain(state)` once on the module
(in reverse topological order) to signal "stop accepting new work".
The module then continues stepping normally until in-flight work is
complete and it returns `Done` (1) from `module_step`. After all
drain-capable modules have completed, the scheduler transitions to
`Migrating` and instantiates the new graph.

See [reconfigure.md](reconfigure.md) for the full state machine.

Stopping the hosted runtime (SIGTERM or SIGINT) drains the same way. The
runtime calls `module_drain` once on every drain-capable module, in
reverse execution order, and keeps the whole graph stepping. A module
that answers 0 has work in flight (staged writes to commit, a lease to
release) and is waited for until it returns `Done`. Any other answer
means there is nothing to wait for. The process exits once every module
it waits for has finished, or when the drain deadline passes
(`FLUXOR_DRAIN_MS`, default 10 s). It then ends by the signal it was
sent, and a second signal from the same sender stops it at once. `fluxor
run` and `fluxor exec` pass the signal to the runtime rather than ending
it.

### Fault Recovery

Source: `src/kernel/exec/step_guard.rs`

Modules can be assigned a protection level at config time:

- **Level 0 (None)** — direct call, no isolation.
- **Level 1 (Guarded)** — step guard timer detects timeouts. A module
  that overruns its step deadline is marked as faulted.
- **Level 2 (Contained)** and **Level 3 (Isolated)** — the gated levels.
  The module runs unprivileged, reaching only its own private region
  (stack, state, heap) and its code — all of flash when contained — and
  the kernel only through the gateway; any other access raises a fault.
  Implemented on rp2040 and rp2350 (MPU) and on the Pi 5 (EL0 under a
  per-module page table, isolated only). A request is a floor: the target
  provides the weakest level it implements at or above it, and refuses one
  above everything it implements. See
  [module_isolation.md](module_isolation.md).

Faulted modules transition through `Running → Faulted → Recovering`
(or `Terminated`) according to a per-module fault policy:

| Policy | Behaviour |
|--------|----------|
| `Skip` | Terminate the module; the graph continues without it |
| `Restart` | Flush the module's channels and resume stepping. State is not zeroed and `module_new` is not re-called, so this is safe only for stateless or idempotent modules; stateful modules should use `Skip` and rely on the operator to drain and reload |
| `RestartGraph` | Trigger a full graph reconfigure (last resort) |
| `Tolerate` | Record step-deadline overruns (fault counter, log, fault ring) without faulting the module; step errors still fault normally. For modules whose synchronous device operations have a legitimate heavy tail |

Recovery is bounded by a per-module restart count and exponential
backoff. The kernel records `FaultStats` per module, exposed as a
snapshot through the provider query surface for telemetry.

### Async I/O Pattern

Hardware-facing operations use start/poll sequencing:

1. Start an operation (`*_start`).
2. Return/yield while pending.
3. Poll for completion (`*_poll`) in subsequent steps.

This pattern keeps every module cooperative and preserves predictable
scheduler latency under load.

## Ports and Content Contracts

Source: `tools/src/manifest.rs`

Modules exchange data through named ports declared in each module manifest.

### Port Roles

- Input ports consume upstream data streams.
- Output ports produce downstream data streams.
- Control ports carry command/state updates with atomic message boundaries.

### Content Contracts

Port `content_type` is the semantic contract for graph wiring and validation.
Examples include `OctetStream`, `AudioSample`, `VideoRaster`, and `FmpMessage`.
The full list is the `CONTENT_TYPES` table in the contracts crate.

The runtime transports bytes, while config-time validation enforces type
compatibility.

### Backpressure Contract

- Sources do not advance production time without successful downstream commit.
- Transforms either emit or retain enough state to retry safely.
- Sinks behave deterministically under starvation (for example silence
  insertion or hold-last-value policies).

## Runtime and Memory Safety Invariants

### Layout and ABI Boundaries

- Cross-boundary structs use stable C layout (`repr(C)`).
- State and buffer ownership remains explicit at module boundaries.
- Module state sizing is declarative and kernel-managed through arenas.

### Alignment and DMA Safety

- DMA-visible buffers use natural word alignment.
- Memory ordering is explicit at producer-to-DMA handoff boundaries.
- Zero-copy paths preserve ownership and sequencing invariants before release
  signals.

### Determinism Rules

- No unbounded loops over dynamic input in one step call.
- Retry behaviour is idempotent for partial progress cases.
- Time is derived from monotonic clocks or committed stream progression, never
  assumed call frequency.

## Operational Conventions

### Edge metadata

In config/graph, record for each edge:
- frame size (bytes)
- semantics: stream vs control (latest-wins)
- atomicity requirement
- backpressure behaviour

Modules can then validate at runtime (or loader-time) that they are connected
to compatible edges.

### Module author checklist

- Does my output message have a fixed size?
- Can the channel partially write it? If yes, is reassembly safe and does time
  only advance on commit?
- Am I using `millis()`/`micros()` deltas rather than step count?
- Is logging disabled or throttled?
- If DMA is involved: did I fence correctly?

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
|  setup() -> graph instantiation -> main loop                 |
|  Automatic tee/merge insertion for fan-out/fan-in           |
+-------------------------------------------------------------+
```

For asset banks, selectors, and control bindings, see:
- [../guides/asset_banks.md](../guides/asset_banks.md)
- [../guides/input_system.md](../guides/input_system.md)
- [../guides/input_gestures.md](../guides/input_gestures.md)
