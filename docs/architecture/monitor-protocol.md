# Monitor Protocol

The monitor protocol is a stream of newline-framed text records that a
running Fluxor device emits on its normal log/telemetry transport (USB CDC
on RP targets, UART on Pi 5). A host-side parser tails those lines,
aggregates them into per-module rows, and renders an ANSI table.

Source: `tools/src/monitor.rs` (host parser), `src/kernel/exec/step_guard.rs`
(fault emission), `crates/fluxor-rt/src/telemetry.rs` (session emission).

## Transport

Any serial device that delivers the kernel's `log::info!` stream. The host
opens the device as a file and reads line-by-line — baud and termios
configuration is the caller's responsibility (for example:
`stty -F /dev/ttyACM0 115200 raw -echo`).

## Line formats

All lines are space-separated `key=value` pairs following a tag. Unknown
tags are ignored, and unknown keys within a known tag are ignored — the
protocol is forward-compatible so new fields can be added without breaking
older monitor builds.

### `MON_FAULT`

Emitted unconditionally from `step_guard::push_fault` whenever a module
faults. No on-device configuration required.

```
MON_FAULT mod=<idx> kind=<k> fault_count=<n> restart_count=<n> caused_by=<idx> tick=<t>
```

| Field           | Meaning                                                                 |
|-----------------|-------------------------------------------------------------------------|
| `mod`           | Module index (0..MAX_MODULES-1).                                        |
| `kind`          | Fault type (`step_guard::fault_type`): `1` timeout, `2` step error, `4` protection (MPU or MMU abort, stack bound, stack fence), `5` drain timeout. |
| `fault_count`   | Cumulative fault count for this module after this event.                |
| `restart_count` | Cumulative restart count after this event.                              |
| `caused_by`     | The upstream module whose fault within the cascade window this one followed; `65535` (`NO_MODULE`) for an independent fault. |
| `tick`          | Kernel tick at which the fault was recorded.                            |

### `MON_HIST`

Snapshot of a module's step-time histogram (eight log2-spaced buckets).
Not emitted by the kernel directly: the on-device `monitor` module
(`modules/foundation/monitor`) calls `STEP_HISTOGRAM_QUERY` on a slow
cadence and prints the line.

```
MON_HIST mod=<idx> b0=<n> b1=<n> b2=<n> b3=<n> b4=<n> b5=<n> b6=<n> b7=<n>
```

Buckets, in microseconds: `<2`, `<4`, `<8`, `<16`, `<32`, `<64`, `<256`,
`>=256` (`step_bucket` in `src/kernel/exec/scheduler/multigraph.rs`).

Every step is counted, whatever it returned — `Continue`, `Ready`,
`Burst`, `Done` or an error — and each iteration of a burst counts as the
step it is. So the total across a module's buckets is the number of times
the scheduler stepped it, and a module absent from the histogram is a
module that is not being stepped.

That distinction is the point of the field. Counting only one outcome
would make a starved module and a busy module returning something else
produce the same record — none — and the reading that matters most here
is exactly the one between those two.

The ladder is weighted below the tick budget on purpose: it exists to
attribute a healthy graph's tick budget per module, so most of its
resolution sits where healthy steps land. The heavy tail is reported
exactly, per module, by `MON_HEAVY_STEP` (`elapsed_us` verbatim) and in
aggregate by `MON_BUDGET_OVERRUN`; `b6`/`b7` retain enough of the top end
to spot a heavy module without reading the fault stream.

### `MON_STATE`

A module's scheduler-visible state. Like `MON_HIST`, emitted by the
on-device monitor module, which calls `MODULE_STATE_QUERY` per module.
Slots the scheduler holds empty are skipped, so every line is a real
module.

```
MON_STATE mod=<idx> name=<s> state=<s> ready=<0|1> finished=<0|1> restarts=<n> domain=<d> period=<n> inactive=<n> gen=<n> prot=<s>
```

- `name` — the module's type name. Omitted when the caller's buffer had
  no room for it, which the query reports rather than truncating.
- `state` — `running`, `faulted`, `recovering`, or `terminated`.
- `ready` — the module has signalled `StepOutcome::Ready`.
- `finished` — it has finalised, by `Done` or by termination.
- `period` — ticks between steps; `0` means every tick.
- `inactive` — consecutive ticks the readiness gate has blocked this
  module from stepping. Zero after any successful step, so a climbing
  value is a dead upstream edge and is the field that answers "why is
  this module not running".
- `gen` — per-slot generation, bumped on reset, restart and replacement.
  Pair it across two reads: a change means the slot was reused and the
  earlier line describes a different module.
- `prot` — the protection level the kernel enforces on the module:
  `privileged`, `contained` or `isolated` (see
  [module_isolation.md](module_isolation.md)). This is what the target
  provides, which can be stronger than what the graph asked for.

Trust class is not reported: the scheduler does not keep it per module, so
there is nothing to report it from. A field synthesised at the emitter would
be a reading nobody could trust, which is worse than an absent column.

### `MON_HEAVY_STEP`

Emitted (rate-limited) by the scheduler when a single module step exceeds
the heavy-step threshold (`src/kernel/exec/scheduler/pass.rs`):

```
MON_HEAVY_STEP module=<idx> domain=<d> elapsed_us=<n> tick=<t> suppressed=<n>
```

### `MON_BUDGET_OVERRUN`

Emitted (rate-limited) by the scheduler when an execution domain exhausts
its per-pass step budget (`src/kernel/exec/scheduler/pass.rs`):

```
MON_BUDGET_OVERRUN domain=<d> consumed_us=<n> limit_us=<n> last_mod=<idx> top=<idx>:<us>/<steps>,<idx>:<us>/<steps>,<idx>:<us>/<steps> overrun_count=<n> tick=<t> suppressed=<n>
```

`last_mod` is the module whose step closed the pass over budget; `top` lists
the three modules of the domain that consumed the most of that pass, each
with its microseconds and the number of times it was stepped (a bursting
module is stepped many times in one pass). Unused slots read `0:0/0`.

In both lines `tick` is the domain's pass count (`pass_count(domain)`): the
number of tick passes that domain has run.

### `MON_SESSION`

Session-continuity observability. Emitted by anchors, workers, and session
directories at every `SessionCtrlV1` state transition (see
[protocol_surfaces.md](protocol_surfaces.md)) so operators can see attach,
rebind, drain, epoch bump, relocation, and stale-generation rejection on
the same telemetry channel as the rest of monitor output. The emission
helpers live in `crates/fluxor-rt/src/telemetry.rs`; `echo_anchor` and
`echo_worker` are the in-tree emitters.

```
MON_SESSION mod=<idx> event=<e> session=<32-hex> epoch=<n> [anchor=<16-hex>] [worker=<16-hex>] [reason=<r>] [status=<s>]
```

| Field     | Meaning                                                              |
|-----------|----------------------------------------------------------------------|
| `mod`     | Module index of the emitter (anchor, worker, or directory).          |
| `event`   | Transition label; see event table below.                             |
| `session` | `session_id` (16 bytes) rendered as 32 lowercase hex chars, no sep.  |
| `epoch`   | `session_epoch` as decimal u32.                                      |
| `anchor`  | `anchor_id` (8 bytes) as 16 hex chars. Omit if emitter is anchor.    |
| `worker`  | `worker_id` (8 bytes) as 16 hex chars. Omit on anchor-only events.   |
| `reason`  | Detach reason name. Present only on `event=detached`.                |
| `status`  | Status code name. Optional; present when the emitter supplies one (conventionally on `attached` / `imported` / `relocated`). |

`session_id` rendering uses the canonical cluster byte order (big-endian)
with no `-` separators, so `MON_SESSION` lines grep cleanly for a given
session across emitters.

#### Events

| Event        | Emitter(s)            | When                                                                |
|--------------|-----------------------|---------------------------------------------------------------------|
| `attached`   | worker                | `MSG_SC_ATTACHED(STATUS_OK)` sent. `status=ok`.                     |
| `attach_failed` | worker             | `MSG_SC_ATTACHED(status != OK)`. `status=<code>`.                   |
| `drained`    | worker                | `MSG_SC_DRAINED` sent.                                              |
| `exported`   | worker                | `CMD_SC_EXPORT_END` sent; CRC32 committed.                          |
| `imported`   | worker                | `MSG_SC_IMPORT_END` emitted. `status=ok` or `corrupt`.              |
| `resumed`    | worker                | `MSG_SC_RESUMED` emitted for the new epoch.                         |
| `detached`   | worker                | `MSG_SC_DETACHED` sent. `reason=<name>`.                            |
| `epoch_bump` | directory / anchor    | `MSG_SC_EPOCH_CONFIRMED` emitted. `epoch` is the NEW epoch.         |
| `relocated`  | directory             | `MSG_SC_RELOCATED` emitted. `status=<code>`, `worker=<new>`.        |
| `attach_req` | anchor                | `CMD_SC_ATTACH` sent. (Informational.)                              |
| `detach_req` | anchor                | `CMD_SC_DETACH` sent. `reason=<name>`.                              |
| `export_req` | anchor                | Export requested from the worker. (Informational.)                  |
| `resume_req` | anchor                | Resume requested for the new epoch. (Informational.)                |
| `rejected`   | any                   | Stale epoch / unknown session rejected inbound. `reason=stale_epoch` or `unknown_session`. |
| `error`      | any                   | `MSG_SC_ERROR` emitted. `status=<code>`.                            |

Reasons (from the `DETACH_*` constants in
`crates/fluxor-abi/src/contracts/net/session_ctrl.rs`): `normal`, `drain_timeout`,
`stale_epoch`, `error`, `client_gone`.

Status codes (from the `STATUS_*` constants): `ok`, `stale_epoch`,
`unknown_session`, `no_capacity`, `corrupt`, `not_ready`.

#### Failover records (`transport_migratable` sessions)

The SDK defines these events (`MON_EV_FENCE_INITIATED` through
`MON_EV_CLASS_REPORT` in `crates/fluxor-rt/src/telemetry.rs`) and formats
them; no module in this repository emits them. For sessions declared `transport_migratable` with platform-replicated
state, the record set above is extended so an unplanned failover is
visible in telemetry rather than inferred after the fact. Same line
format; additional events:

| Event                        | Emitter(s)          | When                                                                    |
|------------------------------|---------------------|-------------------------------------------------------------------------|
| `fence_initiated`            | directory / takeover| Enforceable emission fence (STONITH / fabric cutoff) fired at the old anchor. |
| `fence_confirmed`            | directory / takeover| Fence confirmed dead. Distinct from `fence_initiated`: the client-facing VIP must not move before this record. |
| `vip_moved`                  | takeover anchor     | Client-facing VIP now attracts datagrams to the takeover host.          |
| `reservation_granted`        | anchor              | A fresh egress counter/sequence block was quorum-committed. `status=ok`. |
| `reservation_exhausted_stall`| anchor              | Emit path stalled waiting on a reservation grant.                       |
| `rpo_loss`                   | takeover worker     | Un-checkpointed application tail lost at failover. `reason=<bound>` states what was lost (e.g. `reason=1_tick`). |
| `unsafe_recovery_epoch_void` | directory           | Forced/unsafe quorum recovery voided all outstanding reservation blocks and forced an epoch bump. |
| `class_report`               | anchor              | Per-session declared vs achieved continuity class (see below).          |

`class_report` carries two extra keys:

```
MON_SESSION mod=<idx> event=class_report session=<32-hex> epoch=<n> declared_class=<c> achieved_class=<c>
```

Class names: `reroutable`, `drain_only`, `resumable`, `edge_anchored`,
`transport_migratable` (the `CC_*` constants in `session_ctrl.rs`).
A session running below its declared class — budget miss, missing fence,
encrypted implicit-counter AEAD — surfaces the degradation here
(`achieved_class` below `declared_class`), so a silent fall-back from
`transport_migratable` to `resumable` is visible in production rather
than inferred.

#### Example

```
MON_SESSION mod=3 event=attached session=44454d4f2d413031000000000000000a epoch=1 worker=44454d4f2d573031 status=ok
MON_SESSION mod=4 event=attached session=44454d4f2d413031000000000000000a epoch=1 anchor=44454d4f2d413031 status=ok
MON_SESSION mod=4 event=drained session=44454d4f2d413031000000000000000a epoch=1 anchor=44454d4f2d413031
MON_SESSION mod=4 event=detached session=44454d4f2d413031000000000000000a epoch=1 anchor=44454d4f2d413031 reason=client_gone
```

Operators grep `MON_SESSION ... session=44454d4f2d413031000000000000000a`
to follow one session's lifecycle across anchor / worker / directory
emitters.

## Kernel support

Source: `crates/fluxor-abi/src/internal/monitor.rs`.

- `FAULT_MONITOR_SUBSCRIBE` (`0x2152`) — bind an event handle that the
  kernel signals on every fault.
- `FAULT_MONITOR_POP` (`0x2153`) — pop the oldest fault record (16 bytes,
  module and cause as u16; see `step_guard::FaultRecord`).
- `FAULT_STATS_QUERY` (`0x2154`) — fetch the current `FaultStats` for a
  module index.
- `STEP_HISTOGRAM_QUERY` (`0x2155`) — fetch the 8-bucket histogram for a
  module (or the global histogram with `handle=-1`).
- `MODULE_STATE_QUERY` (`0x2157`) — fetch a module's scheduler-visible
  state, the fields of `MON_STATE`.

The `monitor` module reads these calls on a slow cadence and prints the
corresponding `MON_*` lines. The parser in `tools/src/monitor.rs` accepts
whatever arrives — any subset is acceptable.
