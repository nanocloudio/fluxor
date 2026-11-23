# Compute-Heavy Modules

This guide defines architecture patterns for modules that perform substantial
CPU work per unit of data (for example emulation, decoding, rendering, or large
state transforms).

Source: `fluxor_rt::StepReturn` and `src/kernel/exec/step.rs` (the step
contract), with scheduler and memory
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

A module may return `StepReturn::Burst` when it can productively continue
work in the same tick, but each burst step is still bounded.

## The step budget

Source: `src/kernel/exec/scheduler/pass.rs`, `live.rs`, `fault.rs`,
`src/kernel/exec/step_guard.rs`, `tools/src/config/builder.rs`. The kernel's
side of the same mechanism is in
[../architecture/scheduler.md](../architecture/scheduler.md#deadline-enforcement).

Three bounds apply to a cooperative (`tick` or `poll`) module's step, from
the inside out:

| Bound | Figure | Declared by | Past it |
|---|---|---|---|
| Step deadline | `step_deadline_us`; undeclared, `DEFAULT_STEP_DEADLINE_US`: 2000 µs on silicon, 20000 µs on the QEMU builds of bcm2712 and uefi | the module's entry in the graph | a timeout fault |
| Burst deadline | `step_deadline_burst_us`; undeclared, the step deadline × `BURST_MULTIPLIER` (8): 16000 µs at the default | the module's entry in the graph | a timeout fault |
| Domain pass budget | the domain's `tick_us`; undeclared, the graph's tick, else `DEFAULT_TICK_US` (1000 µs) | the graph | the burst ends early; the pass is logged, not faulted |

A graph declares the first two on the module's entry, with what an overrun
does:

```yaml
modules:
  - name: decoder
    type: frame_decoder
    step_deadline_us: 4000
    step_deadline_burst_us: 12000
    fault_policy: skip
```

### One step

The scheduler arms the step guard with the step deadline before
`module_step` and reads it when the step returns. A step that returns
`Continue` after its deadline has passed is a timeout fault. The deadline is
a fault threshold: it is not the time a step is expected to take, and it
does not stop the step. An ungated module that runs on is not interrupted
on any target, and the Linux and wasm hosts do not observe the overrun at
all; a gated (`contained` or `isolated`) module is forced out at its
deadline. The table in
[scheduler.md](../architecture/scheduler.md#deadline-enforcement) says how
each target notices.

Well below the deadline, a step is already visible: one whose wall clock,
burst re-steps included, is over 50 µs logs `MON_HEAVY_STEP` with the
module's index and the elapsed time (each `MON_` line at most once per
2 s per domain, with a count of the ones suppressed).

### A burst

A step that returns `Burst` is stepped again at once, and again while it
keeps returning `Burst`, up to `MAX_BURST_STEPS` (16384) re-steps. The guard
is re-armed once, with the burst deadline, for the whole run of re-steps:
the burst deadline bounds their sum, not each one. The loop tests the guard
before every re-step, so a burst that has passed its deadline faults there
instead of stepping again.

The burst also ends, without a fault, when the domain runs out of pass
budget. Before every re-step the scheduler adds what the domain has
consumed this pass to what this module has used so far, and stops the burst
(`MON_BURST_BUDGET_ABORT`) when the sum is over the domain's budget. So a
burst gets what is left of the domain's tick after the modules ahead of it
in the pass — at the default tick, less than 1000 µs — and the 16000 µs
default burst deadline is reached only in a domain with a longer tick.
The module is stepped again on the next pass and picks its work up there.

### The hard cap

A declared deadline is bounded twice, and the build refuses a graph past
either bound instead of clamping it:

- The effective burst deadline (declared, else 8 × the step deadline) may
  not exceed 16 × the domain's tick; on a domain with adaptive cadence,
  16 × its `tick_min_us`.
- It may not exceed 100000 µs (`STEP_BUDGET_HARD_CAP_US` in the kernel,
  `HARD_BURST_CAP_US` in the build) whatever the tick.

With no burst deadline declared, that puts the largest step deadline at
twice the domain's tick (16 ÷ 8), and at 12500 µs however long the tick is.
At the default 1000 µs tick the ceiling is 16000 µs, which the default
deadline's burst (2000 × 8) meets exactly. Declaring `step_deadline_burst_us`
lets the step deadline rise towards the ceiling without the multiplier
carrying the burst past it. For a module of a workload the kernel applies
the same two bounds, to the step deadline as well as the burst, against
the node's own ticks when the workload is admitted, and refuses the
workload with `ERANGE`. A module that declares neither deadline runs on
the defaults and is not measured against the cap.

The build also warns when the step deadlines declared in one domain sum to
more than 4 × its tick.

A module's manifest makes a separate claim, `[execution] max_step_us`: the
CPU time one step takes, as the author measured or bounded it. The build
refuses a manifest whose `max_step_us` is over 1000 µs, one pass at the
default tick, on any target the module names.

### What an overrun does

A timeout fault is recorded (the module's fault counter, a
`[guard] module <index> (<type>) step timeout (fault #<n>)` warning, a
record in the fault ring) and then the module's `fault_policy` applies:

- `skip`, the default: the module is terminated with `-110` and the graph
  runs on without it. A workload's modules may declare no other policy.
- `restart`: the module is held out of the pass for its backoff
  (`restart_backoff_ms`, 100 ms unless declared, doubled for each restart
  already taken) and then stepped again with its state as it was, up to
  `max_restarts` (3 unless declared); after that it is terminated.
- `tolerate`: the overrun is recorded and nothing else happens. For a module
  whose late steps are a device's doing, not its own.

A pass that overruns the domain's budget is not a fault of any module. The
pass finishes, so the modules after the heavy one still step; the domain
logs `MON_BUDGET_OVERRUN` naming the three modules that used the most of
the pass, takes no further sub-pass this tick, and starts the next pass
one module further round its order. At 10 × the budget the pass stops
where it is and the remaining modules wait for the next one.

### Splitting long work

Work that cannot finish inside the step deadline is done a slice at a time,
with the position kept in module state:

1. Size a slice from the budget, not from the data: a number of blocks,
   rows, instructions or bytes whose worst case sits well inside the step
   deadline on the slowest target the module names, and inside the
   manifest's `max_step_us`.
2. Keep a cursor in state (the next block, the phase of a multi-phase
   operation, the partial result) so that a step resumes exactly where the
   last one stopped, and so that stopping between any two slices leaves
   state consistent. A burst can end after any slice.
3. Return `Burst` after a slice only when the next slice can run now: its
   input is present and its output has room. The re-step happens in the
   same pass, within the burst deadline and the domain's remaining budget.
4. Return `Continue` when the next slice has to wait, for input, for output
   room or for a device. The module is stepped again on a later pass;
   nothing is lost by yielding.
5. Do not loop over slices inside one step to save re-steps. The guard
   measures the step, and a step that is long only sometimes is the one
   that faults in the field.

A slice that cannot be made small enough — a single indivisible operation
longer than the ceiling allows — does not belong in a cooperative step on
that target. Give the module a domain of its own with a tick that fits it,
so that the pass budget it draws on is not its neighbours' (where the
target runs that domain on a core of its own the work leaves their core as
well; where domains share a core a long step still delays the rest), or
move the operation behind a device or provider that completes
asynchronously.

## Memory model

Use memory by role:

- the module's heap (capped by its declared arena or the instance's
  `heap.arena_bytes`, committed from `STATE_ARENA`) for persistent module
  state
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
