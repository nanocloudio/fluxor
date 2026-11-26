# Owner Facts (`workload::OWNERS`)

The kernel folds per-module lifecycle state into **per-owner** facts and
answers them through one read of the `workload` contract, `OWNERS`. A node
agent reads them to learn whether each workload is activating, running or
gone, and why. The read is the same on every target; what a node agent makes
of the facts — phases, reasons, restart counts, how long a gone owner is
remembered, the file it writes for an orchestrator — is the agent's.

## Why the kernel has to aggregate

A fault is a per-module event, but a workload is a set of modules. Only the
kernel knows which modules an owner's plan slot expanded into — the owner plan
stamps a slot→module-range mapping at admission — so only the kernel can fold
"module 7 hard-faulted" into "this owner has a terminated module". Exporting
the mapping instead would make every consumer re-derive the aggregate and
would leak module indices into orchestration. Module indices, per-module fault
counts and histograms stay in the monitor record stream (`MON_FAULT` /
`MON_HIST` / `MON_STATE`); this surface speaks only owners.

## The read

`OWNERS` takes no handle and no `arg`; the answer lands in `data`. It is the
node's to read: a caller acting with an authority of its own is answered
`EACCES`. The layout is `abi::contracts::workload::owners`, little-endian:

```text
head (48 B): [count:u16][record_len:u16][_:u32][plan_generation:u64][plan_digest:32]
record (record_len B, 64 today):
  uid[16] slot:u16 state:u8 fault_kind:u8 generation:u32
  modules:u16 loaded:u16 finished:u16 terminated:u16 recovering:u16
  drain:u8 _:u8 activations:u32 fault_ms:u64 drain_deadline:u64 drained_at:u64
```

A reader takes `record_len` from the head, so a record that grows keeps its
front. `plan_generation` and `plan_digest` name the owner plan the kernel last
applied (the digest is the one it verified, over the plan's header and every
section; all zero before the first). The
[agent protocol](agent_protocol.md#what-the-activation-digest-proves) holds it to
the committed plan's before it reports an activation.

One record per owner slot, in slot order:

- **A live owner** (`state` ACTIVE, DRAINING or PAUSED): `modules` its plan
  stamps, `loaded` of them instantiated, `finished` ended cleanly,
  `terminated` ended by the fault policy, `recovering` faulted and being
  retried; `fault_kind` and `fault_ms` of its most recent terminated module
  (kinds `owners::FAULT_*`; 0 for none); `activations`, how many times this
  kernel instantiated its modules (one more for each rebuild that does so
  again); `drain_deadline`, the unix second its plan revocation states while it
  drains.
- **A gone owner** (`state` GONE): an owner freed after its plan revoked it,
  listed while the applied plan still lists the revocation. `drain` says how
  its drain ended — `QUIESCED` (every module ended and its edges ran dry),
  `DEADLINE_PASSED` (freed still running), or `FORFEITED` (a rebuild dropped
  it mid-drain, or this kernel started after it was revoked) — and
  `drained_at` when the kernel freed it, on the clock the platform drives
  drains with (0 when it did not).

## Drains

A revocation in the owner plan carries the drain's deadline. Applying it
closes the owner's admission (`begin_drain`); `owner_plan::drain_tick(now)`,
which the platform calls with its wall clock (the kernel keeps none), frees
each draining owner at the earlier of quiescence and its deadline
(`scheduler::free_owner`: drain hooks, stop, unsplice, close edges, reclaim,
revoke) and records how on its slot. A plan may drop a revocation only once
its owner is freed. Retention is the node agent's: a gone owner stays readable
exactly as long as the agent's plan keeps listing its revocation.

## On a Linux node

In node-agent mode (`FLUXOR_PLAN` set) `fluxor-linux` drives `drain_tick` at
the plan-watch cadence (100 ms) and writes the `OWNERS` answer verbatim beside
the plan (`abi::platform::linux::owner_facts`): the file `owner_records`, a
16-byte head `["FXOW"][pid:u32][pid_start_ticks:u64]`, then the answer —
atomically replaced (temp write, fsync, rename, parent fsync) whenever the
answer changes, after every graph rebuild before the rebuilt modules step, and
at a stop. The start ticks (field 22 of `/proc/<pid>/stat`) let a reader tell
the writer from a process that reused its pid: a crashed runtime, a recycled
pid or a zombie never presents stale facts as live. The runtime derives no
phase, counts no restart and keeps nothing past the kernel's records.

### Bound endpoints

Which endpoints an owner holds is not an owner fact: the node's sockets are
the network provider's (`fluxor-provider-net`, the graph's `linux_net`). In
node-agent mode the runtime names the facts directory to the provider as
`FLUXOR_FACTS_DIR`, and the provider writes `bound_endpoints` there
(`abi::platform::linux::bound_endpoints`), atomically replaced (temp write,
rename) whenever the set changes:

```text
head (24 B): ["FXBE"][pid:u32][pid_start_ticks:u64][count:u16][record_len:u16][_:u32]
record (record_len B, 12 today): owner_slot:u16 port:u16 owner_generation:u32 protocol:u8 _:3
```

One record per live listener or datagram endpoint, the node's own (owner slot
0, generation 0) included; `protocol` is the IP protocol number. The head names
the provider process the same way the facts file names the runtime, so a report
whose provider is gone (a crash, a graph rebuild between two providers) says
nothing.

## `fluxor agent status`

`fluxor agent status --json` is where owner facts meet the agent's durable
records. It locates the facts file through the `publish.path` record the
commit and remove verbs write into the store, drops it when its writer is not
the live process that wrote it or when it was read under another plan
generation, joins each record onto the committed workload by owner uid, slot
and owner generation, and renders it as `workloads[].runtime`
(`node_agent::render_runtime`):

| Facts | `runtime` |
|---|---|
| GONE, drain QUIESCED | `Terminated`, `Completed`, exit 0, `drain` detail |
| GONE, otherwise | `Terminated`, `GraphNodeFault`, exit = the drain-timeout fault kind; `drain.timed_out`, and `drain.forfeited` for FORFEITED |
| a terminated module | `Terminated`, `LivenessFailure` for a step-deadline fault, else `GraphNodeFault`; exit = the fault kind |
| every module ended cleanly | `Terminated`, `Completed`, exit 0 |
| every module instantiated | `Running`; `ready` while none is being retried and the owner is not draining |
| some module not instantiated | `Activating`, waiting `ActivationBackOff` when it stamps modules |

`restart_count` is `activations − 1`: each time the runtime instantiated the
owner's modules again. An internal module retry (step-guard `Restart` policy)
is module telemetry; it surfaces as a transient `ready: false`, never as a
restart. A draining owner carries `owner_state: "Draining"`, its
`drain_deadline_unix` and the `drain_remaining_secs` left at the read; a paused
one `owner_state: "Paused"`. `finished_at` is present when the facts carry a
wall-clock time for the end (a drain the runtime ran).

The reason lists are **closed vocabularies**, Rust enums in
`tools/src/node_agent.rs`: `Completed`, `GraphNodeFault`, `LivenessFailure`
from these facts; `ExternalProcessExited`, `Evicted`, `FluxorReservationInvalid`
and the waiting reason `FluxorReserving` belong to the external-process bridge,
eviction and reservation handling.

`workloads[].endpoints` joins the provider's report onto each placed workload
by the committed plan's owner slot and owner generation: one entry per export
the workload declared (`bound` when the provider holds it) and one per bind it
holds but never declared (`declared: false`) — reported, not policed. It is
absent while no live provider reports.

`runtime` is **absent** when no live runtime's facts join — absence means
"unknown", not "not running". A record with no durable row left (its revocation
aged out of the agent's plan while the runtime still lists it) is reported as a
runtime-only row, `committed: false`. Fluxor's nouns end here: an orchestrator
that presents workloads under names of its own maps `workloads[].runtime` onto
its schema itself.
