# Compute-Heavy Modules

This guide defines architecture patterns for modules that perform substantial
CPU work per unit of data (for example emulation, decoding, rendering, or large
state transforms).

Source: `modules/mod.rs` (the step contract), with scheduler and memory
background in [../architecture/scheduler.md](../architecture/scheduler.md)
and [../architecture/heap.md](../architecture/heap.md).

## Design goal

Keep heavy modules composable inside Fluxor's cooperative scheduler without
breaking latency or starving neighbouring modules.

## Execution contract

Heavy modules preserve the same step contract as all modules:

- bounded work per `step()` call
- non-blocking behaviour
- deterministic retry behaviour under partial progress

A module may return `StepOutcome::Burst` when it can productively continue
work in the same tick, but each burst step is still bounded.

## Memory model

Use memory by role:

- the module's heap arena (sized by `module_arena_size`, allocated from
  `STATE_ARENA`) for persistent module state
- channels and shared buffers for frame transport

Large transient payloads flow through buffers and channels rather than being
copied into long-lived state.

## Data transport patterns

Choose transport to match the workload:

- FIFO channels for stream-like sequential payloads
- mailbox and zero-copy buffers for large frame handoff

Mailbox mode is preferred for framebuffer-scale or similarly large payloads
where copy amplification dominates runtime cost.

## Scheduling guidance

- Use burst stepping only when more useful work is immediately available.
- Avoid unbounded inner loops in a single step.
- Prioritise forward progress and responsiveness over single-module throughput.

If a module can generate output faster than consumers accept it, throttle at the
module boundary rather than accumulating unbounded internal work.

## Multi-stage heavy pipelines

For complex compute chains, split responsibilities across modules:

- producer/acquisition
- heavy transform stage(s)
- presentation/output stage

This keeps each module contract narrow and makes bottlenecks observable in the
graph.

## Reliability checklist

- bounded CPU per step under worst-case input
- explicit behaviour under backpressure
- no hidden timeline drift from dropped or partial output
- clear recovery behaviour on reset and end-of-stream

## Related documentation

- [../architecture/module_architecture.md](../architecture/module_architecture.md)
- [../architecture/pipeline.md](../architecture/pipeline.md)
- [../architecture/timing.md](../architecture/timing.md)
