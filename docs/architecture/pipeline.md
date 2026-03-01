# Graph Runner Architecture

## Design Goals

- Compose modules into arbitrary graphs via config, not firmware changes.
- Keep core logic domain-agnostic and expose a small syscall surface.
- Make all I/O non-blocking with clear backpressure handling via channels.

## Runtime Model

```
Config (flash)             Runtime
--------------             -------
modules[]     -------->  ModuleSlot (Dynamic, Tee, Merge)
edges[]       -------->  Edge[] with channel handles
              -------->  run_main_loop()
```

Each PIC module is loaded via the loader and wrapped in a `DynamicModule`.
The graph runner steps all modules in order, and modules communicate via
kernel-managed channels.

## Graph Configuration Model

Graphs are declared in config as module instances plus explicit wiring edges.

### Top-Level Shape

- `modules`: module instances and parameterization
- `wiring`: directed edges between module ports
- `data` (optional): inline assets referenced by modules

### Wiring Semantics

Each wiring entry connects one source port to one destination port:

```yaml
wiring:
  - from: source.stream
    to: decode.data
  - from: decode.pixels
    to: display.pixels
```

Port names are manifest-defined contracts. The runner resolves names to channel
bindings and validates direction and content compatibility.

### Topology Rules

- Graph execution order is topological.
- Fan-out and fan-in are represented as explicit runtime helpers (tee/merge).
- Cycles require explicit buffering/control semantics and are treated as advanced patterns.

### Inline Data Assets

The optional `data` section stores small assets directly in config payloads.
This is suited for embedded presets, sequences, and test fixtures where external
storage is not required.

### Validation Model

Configuration validation enforces:

- module existence and parameter shape
- valid port references
- content-type compatibility
- bounded resource usage (channels, buffers, module slots)

## Module Execution

Modules implement the `Module` trait with a single entry point:

```rust
pub enum StepOutcome { Continue, Done, Burst }

pub trait Module {
    /// Advance the module by one step.
    ///
    /// Returns:
    /// - `Ok(Continue)` - More work possible on later ticks
    /// - `Ok(Done)`     - Module completed its task
    /// - `Ok(Burst)`    - Re-step immediately (has more work this tick)
    /// - `Err(())`      - Error occurred
    fn step(&mut self) -> Result<StepOutcome, ()>;
}
```

The runner calls `step()` on all modules each iteration. When a module returns
`Burst`, the scheduler re-steps it up to `MAX_BURST_STEPS` (4) additional times
within the same tick, enabling compute-heavy modules to do multiple chunks of
work per tick while remaining cooperative. Modules use channel syscalls to read
inputs and write outputs.

## Graph Runner

The runner in `src/kernel/scheduler.rs` uses a three-stage initialization sequence:

```rust
// Stage 1: Initialize loader and config
if !setup(&runner_config) {
    panic!("Setup failed");
}

// Stage 2: Build graph, open channels, instantiate modules
let count = setup_graph(&runner_config);
if count < 0 {
    panic!("Graph setup failed");
}

// Stage 3: Run the main loop
run_main_loop(count as usize).await;
```

### Main Loop

The main loop uses Embassy's `select()` to sleep efficiently. When an event fires (GPIO edge, module-to-module signal, or ISR source), the scheduler wakes immediately instead of waiting for the next 1ms tick.

```rust
pub async fn run_main_loop(module_count: usize) -> ! {
    loop {
        // 1. Poll GPIO edges (signals events for pins with bindings)
        gpio::poll_gpio_edges();

        // 2. Step all modules in topological order
        match step_modules(modules, module_count) {
            StepResult::Continue => {}
            StepResult::Done => break,
            StepResult::Error(i) => { log::error!("Step failed: {}", i); break; }
        }

        // 3. Intra-tick wake: events fired during step (module A signals module B)
        let wake = event::take_wake_pending();
        if wake != 0 {
            step_woken_modules(modules, module_count, wake);
        }

        // 4. Sleep until 1ms tick OR event signal
        event::SCHEDULER_WAKE.reset();
        select(Timer::after(1ms), event::SCHEDULER_WAKE.wait()).await;

        // 5. Post-sleep wake: events from ISR during sleep
        let wake = event::take_wake_pending();
        if wake != 0 {
            step_woken_modules(modules, module_count, wake);
        }
    }
}
```

`step_woken_modules()` is a lightweight variant that only steps modules whose bit is set in the wake bitmask, bypassing frequency gating. See `architecture/events.md` for the full event system design.

## Channel-Based IPC

Modules communicate through channels, not direct buffer passing:

```rust
// In module step():
let ready = syscalls::channel_poll(self.in_chan, POLL_IN);
if ready & POLL_IN != 0 {
    let n = syscalls::channel_read(self.in_chan, buf.as_mut_ptr(), buf.len());
    // Process data...
    syscalls::channel_write(self.out_chan, output.as_ptr(), output.len());
}
```

### Channel Types

| Type | Value | Description |
|------|-------|-------------|
| `Pipe` | 3 | In-memory ring buffer between modules |
| `Tcp` | 1 | TCP stream socket |
| `Udp` | 2 | UDP datagram socket |

## Module Roles

Modules declare their role in the header, which determines channel requirements:

| Role | Value | Inputs | Outputs |
|------|-------|--------|---------|
| Source | 1 | None | Required |
| Transformer | 2 | Required | Required |
| Sink | 3 | Required | None |

## Fan-Out and Fan-In

The runner automatically inserts helper modules for complex topologies:

- **Tee Module**: Inserted when one output feeds multiple inputs
- **Merge Module**: Inserted when multiple outputs feed one input

```
Config:                    Runtime:
A -> B                      A -> B
A -> C                      A -> [tee] -> B
                                   -> C
```

## Module Instantiation

PIC modules go through this sequence:

1. **Load**: Find module in flash by name hash
2. **Validate**: Check magic, ABI version, code bounds
3. **Size Query**: Call `module_state_size()` to get buffer size
4. **Allocate**: Get state buffer from state arena
5. **Init**: Call `module_init(syscalls)` for one-time setup
6. **Create**: Call `module_new(params, len, state, syscalls)`

### Channel Buffer Allocation

Before opening channels, the scheduler queries each module's optional `module_channel_hints` export to determine per-port buffer sizes. Channel buffers are allocated from a **dedicated buffer arena** (32 KB, separate from the module state arena). Both arenas are reset on graph reconfigure.

Audio data channels use the default 2048 bytes. Control and event channels typically request 256 bytes via hints. Bulk data channels (e.g. video framebuffers for mailbox mode) can request larger sizes (up to 65535 bytes via the `u16` hint field). Channel buffer allocation does not compete with module state memory.

### FIFO→Mailbox Chaining

Channels support two buffer modes: **FIFO** (copy via `channel_write`/`channel_read`)
and **mailbox** (zero-copy via `buffer_acquire_write`/`release`/`acquire_read`/`release`).
The two modes serve different roles in a pipeline and can coexist:

**When to use FIFO:**
A producer that builds output incrementally (partial writes, byte-at-a-time) must
write into a FIFO channel. Copy semantics are required because the producer cannot
fill a whole buffer in a single step.

**When to use mailbox:**
A module that can produce (or transform) a complete buffer in one step should use
mailbox mode. The buffer stays in place — no copy — and downstream modules consume
or transform it directly.

**The chaining pattern:**

```
  FIFO copy        mailbox (zero-copy alias chain)
 ──────────      ──────────────────────────────────
 Source ──copy──► Producer ──alias──► InPlace ──alias──► Sink
         ch A      (group=1)  ch B    (group=1)  ch B    (DMA)
```

1. Use a **FIFO channel** for any producer that cannot write whole buffers in place
   (e.g., a byte-stream source, a decoder that emits partial frames).

2. A **mailbox chain** begins at the first module that can produce full buffers and
   wants zero-copy handoff. All edges in the chain share the same `buffer_group`
   value in config. The scheduler aliases them to the same underlying buffer in
   `open_channels`.

3. An **in-place transform** within a mailbox chain acquires the buffer via
   `buffer_acquire_inplace` (READY → PRODUCER), modifies it, and releases via
   `buffer_release_write` (→ READY_PROCESSED). The module must set both
   `mailbox_safe` (header flags bit 0) and `in_place_writer` (bit 1).

4. **Read-only consumers** (sinks) at the end of a mailbox chain only need
   `mailbox_safe` (bit 0). They consume via `buffer_acquire_read` or
   transparent `channel_read`. Example: I2S reads mailbox data without
   modifying it.

5. At most **one in-place transform** is supported per alias chain (the
   READY_PROCESSED state prevents double-processing, and `validate_buffer_groups`
   rejects configs with multiple `in_place_writer` modules per group). For
   multiple transforms, insert a FIFO copy step between them.

**Capability flags** (header `reserved[0]`):
- `mailbox_safe` (bit 0): module can safely consume from mailbox channels.
  Required for any module in a `buffer_group` chain.
- `in_place_writer` (bit 1): module uses `buffer_acquire_inplace` to modify
  the buffer. Only for chain-interior modules.
- `module_in_place_safe` export: sets both bits (backward compatible).
- `module_mailbox_safe` export: sets bit 0 only (read-only consumers).

**Buffer sizing:** For grouped edges, the scheduler computes the buffer size
as the maximum of all port hints across all edges in the group. This ensures
the channel is large enough for the most demanding consumer.

**Constraints:**
- `buffer_group` aliasing is incompatible with tee/merge. `insert_fan` clears
  `buffer_group` on fan edges and logs an error.
- Any edge with `buffer_group != 0` enables mailbox mode on its channel,
  even if it is the only edge in the group.

See `channel.rs` module docs for mailbox size semantics and `buffer_pool.rs` for
the full state machine.

### FIFO→Mailbox Backpressure

When a transformer module reads from a FIFO input and writes to a mailbox
output (the FIFO→mailbox boundary), it must follow a strict ordering rule:

**Rule: Check mailbox output acquirability BEFORE consuming FIFO input.**

FIFO reads are destructive — `channel_read` dequeues data from the ring
buffer. If the module reads FIFO data but then cannot acquire the mailbox
output buffer (because the downstream consumer has not released it), the
read data is lost. Unlike a FIFO output where partial writes leave data
in the ring buffer, a failed mailbox acquire has no recovery path.

**Correct pattern:**
```c
// 1. Check mailbox output is available
u32 cap = 0;
u8 *buf = buffer_acquire_write(out_chan, &cap);
if (!buf) return 0; // DO NOT read input — output not ready
// 2. Now safe to read FIFO input (output buffer is reserved)
int read = channel_read(in_chan, buf, cap);
if (read > 0) buffer_release_write(out_chan, read);
```

**Alternative:** use `channel_write` for transparent handling. The module
still must check `channel_poll(out_chan, POLL_OUT)` before reading input.

Modules at the FIFO→mailbox boundary are those with a FIFO input channel
(no `buffer_group` on incoming edge) and a mailbox output channel
(`buffer_group` set on outgoing edge).

## Loader Architecture

The loader (`src/kernel/loader/`) is split into focused submodules:

- `error.rs` - Typed error enum (`LoaderError`)
- `flash.rs` - Safe wrappers for flash memory reads
- `ffi.rs` - FFI call wrappers for module functions
- `loader.rs` - State arena allocation and channel hint queries
- `validation.rs` - Function pointer and module validation
- `table.rs` - Module table parsing and lookup
- `dynamic.rs` - `DynamicModule` wrapper (implements `Module` trait)

## Non-Blocking Contract

All module operations must be non-blocking:

- `step()` must return immediately
- Use `channel_poll()` before reads/writes
- Backpressure is signaled by channel fullness (POLL_OUT == 0)

## Async Runtime Guardrails

The runtime enforces cooperative async behavior across all graph workloads:

- Hardware-facing operations use non-blocking start/poll patterns, not blocking waits.
- Backpressure is signaled through channel/buffer readiness, never by sleep-based retries.
- Periodic async tasks include explicit delay/yield points and avoid tight loops.
- Long critical sections in hot paths are avoided to protect scheduler latency.
- Stream interfaces return promptly when data or capacity is unavailable.

## Static Memory

The runner consolidates all per-module arrays into a single `SchedulerState`
struct (`static mut SCHED`) to avoid async state machine bloat:

```rust
static mut SCHED: SchedulerState;  // edges, modules, ports, caps, arenas, hints, …
```

## Limits

| Resource | Limit | Notes |
|----------|-------|-------|
| Modules | 8 | `MAX_MODULES` in scheduler.rs |
| Channels/Edges | 15 | `MAX_GRAPH_EDGES` in config.rs |
| Events | 32 | |
| State arena | 256 KB | Module state + module arenas (configurable via `STATE_ARENA_SIZE`) |
| Buffer arena | 32 KB | Channel buffers only (configurable via `BUFFER_ARENA_SIZE`) |
| Buffer slots | 20 | `MAX_BUFFER_SLOTS` in buffer_pool.rs |
| Module name | 16 bytes | |
| Burst steps | 4 | `MAX_BURST_STEPS` per module per tick |
