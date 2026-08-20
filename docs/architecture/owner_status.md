# Owner Live-Status Surface (`owner_status.json`)

Fluxor aggregates per-module lifecycle state into **per-owner** live status and
publishes it as a file. A host orchestrator reads that file to learn whether
each workload is activating, running, or dead, and why — pull-based, file plus
CLI only, no sockets and no signals.

Everything below the last hop is owner-space: the kernel, the runtime and the
file speak `owner`, the same vocabulary as the rest of the graph runtime. The
translation into an orchestrator's own nouns happens once, at the CLI boundary,
and is described in [Pod projection](#pod-projection) at the end.

## Why the kernel has to aggregate

A fault is a per-module event, but a workload is a set of modules. Only the
kernel knows which modules an owner's plan slot expanded into — the owner plan
stamps a slot→module-range mapping at admission — so only the kernel can fold
"module 7 hard-faulted" into "this owner is dead". Exporting the mapping
instead would make every consumer re-derive the aggregate and would leak module
indices into orchestration.

That is the whole reason this surface exists rather than consumers reading
the monitor record stream: monitor speaks modules, this speaks owners.

## Data flow

Source: `src/kernel/exec/scheduler/ownership.rs`,
`src/platform/linux/owner_status.rs`, `tools/src/node_agent.rs`.

```
kernel: scheduler::owner_live_snapshot()
    per-MODULE fault/finish state folded into per-OWNER records via the
    owner plan's slot→module-range stamping
        │
        ▼
node runtime (fluxor-linux, FLUXOR_PLAN mode): OwnerStatusWriter
    latches lifecycle transitions per owner UID (activation time, terminal
    reason, aggregate restart count) and atomically replaces
    owner_status.json next to the plan file — on change, at the plan-watch
    cadence (100 ms), and synchronously after every graph rebuild
        │
        ▼
fluxor agent status --store <dir> --json
    locates owner_status.json via the publish.path record the commit/remove
    verbs write into the store, strict-parses it, gates on the writer being
    alive, and joins by owner UID + slot + owner generation
```

The runtime consumes its plan by file-and-mtime watch and publishes status the
same way. The symmetry is deliberate: one directory carries the whole exchange,
so a crashed orchestrator or a crashed runtime leaves a coherent on-disk state
rather than a half-open connection.

## File shape

The file carries a small envelope plus one entry per resident workload:

```json
{
  "version": 1,
  "pid": 4242,
  "pid_start_ticks": 12345678,
  "plan_generation": 7,
  "written_at": "<rfc3339>",
  "workloads": [
    {
      "owner_uid_hex": "…",
      "slot": 0,
      "owner_generation": 3,
      "runtime": {
        "phase": "Activating | Running | Terminated",
        "ready": true,
        "started": true,
        "restart_count": 0,
        "started_at": "<rfc3339>",
        "terminated": {
          "reason": "Completed | GraphNodeFault | ExternalProcessExited | LivenessFailure | Evicted | FluxorReservationInvalid",
          "exit_code": 0,
          "signal": null,
          "finished_at": "<rfc3339>"
        },
        "waiting_reason": "FluxorReserving | ActivationBackOff"
      }
    }
  ]
}
```

`terminated` is present only when `phase == "Terminated"`; `waiting_reason`
only when `phase == "Activating"`; `started_at` only once the owner has
started. Two additive groups appear conditionally and are omitted otherwise,
so their absence keeps older output byte-identical:

- `bound_endpoints`: the owner's bound network ports, as
  `[{"protocol": "tcp" | "udp", "port": N}, …]`.
- Drain state: `"owner_state": "Draining"` plus, when a deadline is set,
  `drain_deadline_unix` and `drain_remaining_secs`. A draining owner also
  reports `ready: false`.

The two reason lists are **closed vocabularies**. The reader
(`tools/src/node_agent.rs`) deserialises them into Rust enums, so a value
outside the set cannot reach a consumer — a writer/reader version skew fails
the parse instead of propagating a string nothing downstream understands.

Reasons the Linux runtime emits:

| Reason | Meaning |
|---|---|
| `GraphNodeFault` | An owned module was permanently terminated by the fault state machine — step error, hard/MPU fault, or drain timeout. `exit_code` is the step-guard fault kind, non-zero. |
| `LivenessFailure` | A step-deadline `TIMEOUT` fault: the runtime's liveness enforcement caught a non-responsive module. |
| `Completed` | Every owned module returned `Done`. `exit_code` 0. |
| `ActivationBackOff` | *(waiting)* Some but not all of the owner's planned modules instantiated. A per-module instantiate failure holds the owner out of `Running` rather than presenting a partially-built graph as healthy. |

`ExternalProcessExited`, `Evicted`, `FluxorReservationInvalid` and the
waiting reason `FluxorReserving` are reserved for the paths that can produce
them — the external-process bridge, eviction, and reservation handling — and
are in the vocabulary so those paths can land without a format change.

## Semantics

- **Aggregation is fluxor's job.** Module indices, per-module fault counts and
  histograms stay in the monitor record stream (`MON_FAULT` / `MON_HIST` / `MON_STATE`);
  this surface speaks only per-owner aggregates. A consumer never needs the
  slot→module mapping.
- **`restart_count` counts aggregate re-activations only**: an owner observed
  Terminated — or superseded by a higher owner generation, or resuming under a
  new runtime process — that runs again. An internal module retry (step-guard
  `Restart` policy) is module telemetry; it surfaces as a transient
  `ready: false`, never as a restart.
- **Co-resident attribution.** With several owners in one runtime, a fault in a
  module owned by A terminates A's aggregate only; other owners' records are
  untouched.
- **Freshness is by writer liveness, not timestamps.** The file carries the
  runtime's `pid` and `pid_start_ticks` (process start time, field 22 of
  `/proc/<pid>/stat`); the reader drops the join when that exact process is
  gone. A crashed runtime, a recycled PID, or a zombie can never present stale
  state as live. A timestamp would only say when the file was written, which is
  a different question from whether anyone is still maintaining it.
- **Generation scoping.** The file carries the `plan_generation` its state was
  derived under, and the writer rewrites on generation change even when the
  derived states are identical. The reader joins only when that matches the
  committed generation *and* the entry's slot and owner generation match the
  committed assignment — so after a new commit, old live state is never
  attached to new durable records.
- **Durability** mirrors the plan publish: temp write, fsync, atomic rename,
  parent-dir fsync. A reader never observes a half-written file.

## Pod projection

`fluxor agent status --json` is where owner-space meets orchestrator-space. It
joins each `owner_status.json` record onto the durable record for that owner
and emits it as `pods[].runtime`, using the field names above unchanged.

Two properties matter to a consumer:

- `runtime` is **absent** when the node runtime isn't up — no file, unreadable
  file, out-of-vocabulary value, or a dead writer. Absence means "unknown", not
  "not running"; a consumer must not read it as a negative assertion.
- The key is additive. Everything else in `agent status --json` is unchanged,
  so a consumer that ignores `runtime` sees exactly what it saw before.

`pod` is the orchestrator's noun, not fluxor's — the kernel and runtime carry
no Kubernetes vocabulary, and this projection is the single point where the two
naming systems meet. Downstream, nanocloud maps `pods[].runtime` onto
`containerStatuses`; that mapping and the Kubernetes status schema are
nanocloud's concern, specified in its own Pod API rather than here.
