# Compute-Heavy Modules

This guide defines architecture patterns for modules that perform substantial
CPU work per unit of data (for example emulation, decoding, rendering, or large
state transforms).

## Design Goal

Keep heavy modules composable inside Fluxor's cooperative scheduler without
breaking latency or starving neighboring modules.

## Execution Contract

Heavy modules must preserve the same step contract as all modules:

- bounded work per `step()` call
- non-blocking behavior
- deterministic retry behavior under partial progress

A module may return `Burst` when it can productively continue work in the same
tick, but each burst step is still bounded.

## Memory Model

Use memory by role:

- **state arena** for persistent module state
- **channel/buffer arena** for frame transport and shared buffers

Large transient payloads should flow through buffers/channels rather than being
copied into long-lived state.

## Data Transport Patterns

Choose transport to match workload:

- FIFO channels for stream-like sequential payloads
- mailbox/zero-copy buffers for large frame handoff

Mailbox mode is preferred for framebuffer-scale or similarly large payloads
where copy amplification dominates runtime cost.

## Scheduling Guidance

- Use burst stepping only when more useful work is immediately available.
- Avoid unbounded inner loops in a single step.
- Prioritize forward progress and responsiveness over single-module throughput.

If a module can generate output faster than consumers accept it, throttle at the
module boundary rather than accumulating unbounded internal work.

## Multi-Stage Heavy Pipelines

For complex compute chains, split responsibilities across modules:

- producer/acquisition
- heavy transform stage(s)
- presentation/output stage

This keeps each module contract narrow and makes bottlenecks observable in the
graph.

## Reliability Checklist

- bounded CPU per step under worst-case input
- explicit behavior under backpressure
- no hidden timeline drift from dropped or partial output
- clear recovery behavior on reset/end-of-stream

## Related Documentation

- `docs/architecture/module_architecture.md`
- `docs/architecture/pipeline.md`
- `docs/architecture/timing.md`
