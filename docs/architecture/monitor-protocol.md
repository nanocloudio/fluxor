# Monitor Protocol

The monitor protocol is a stream of newline-framed text records that a
running Fluxor device emits on its normal log/telemetry transport (USB CDC
on RP targets, UART on Pi 5). A host-side parser tails those lines,
aggregates them into per-module rows, and renders an ANSI table.

Source: `tools/src/monitor.rs` (host parser), `src/kernel/exec/step_guard.rs`
(fault emission), `modules/sdk/runtime/telemetry.rs` (session emission).

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
MON_FAULT mod=<idx> kind=<k> fault_count=<n> restart_count=<n> tick=<t>
```

| Field           | Meaning                                                                 |
|-----------------|-------------------------------------------------------------------------|
| `mod`           | Module index (0..MAX_MODULES-1).                                        |
| `kind`          | Fault type: `1` timeout, `2` step error, `3` hard fault, `4` MPU/MMU.   |
| `fault_count`   | Cumulative fault count for this module after this event.                |
| `restart_count` | Cumulative restart count after this event.                              |
| `tick`          | Kernel tick at which the fault was recorded.                            |

### `MON_HIST`

Snapshot of a module's step-time histogram (eight log2-spaced buckets).
Not emitted by the kernel directly — requires an on-device monitor module
that periodically calls `STEP_HISTOGRAM_QUERY` and prints the line.

```
MON_HIST mod=<idx> b0=<n> b1=<n> b2=<n> b3=<n> b4=<n> b5=<n> b6=<n> b7=<n>
```

Buckets, in microseconds: `<2`, `<4`, `<8`, `<16`, `<32`, `<64`, `<256`,
`>=256` (`step_bucket` in `src/kernel/exec/scheduler/multigraph.rs`).

The ladder is weighted below the tick budget on purpose: it exists to
attribute a healthy graph's tick budget per module, so most of its
resolution sits where healthy steps land. The heavy tail is reported
exactly, per module, by `MON_HEAVY_STEP` (`elapsed_us` verbatim) and in
aggregate by `MON_BUDGET_OVERRUN`; `b6`/`b7` retain enough of the top end
to spot a heavy module without reading the fault stream.

### `MON_HEAVY_STEP`

Emitted (rate-limited) by the scheduler when a single module step exceeds
the heavy-step threshold (`src/kernel/exec/scheduler/domain_budget.rs`):

```
MON_HEAVY_STEP module=<idx> domain=<d> elapsed_us=<n> tick=<t> suppressed=<n>
```

### `MON_BUDGET_OVERRUN`

Emitted (rate-limited) by the scheduler when an execution domain exhausts
its per-tick step budget (`src/kernel/exec/scheduler/domain_budget.rs`):

```
MON_BUDGET_OVERRUN domain=<d> consumed_us=<n> limit_us=<n> last_mod=<idx> overrun_count=<n> tick=<t> suppressed=<n>
```

### `MON_STATE`

One line per module at startup and on protection-level changes. Also
requires a monitor module; the kernel does not emit it on its own.

```
MON_STATE mod=<idx> name=<s> prot=<p> tier=<t> state=<s>
```

| Field   | Meaning                                                                |
|---------|------------------------------------------------------------------------|
| `name`  | Module name (truncated to 16 chars by the host view).                  |
| `prot`  | `none`, `guarded`, or `isolated`.                                      |
| `tier`  | `platform`, `verified`, `community`, or `unsigned`.                    |
| `state` | `running`, `faulted`, `recovering`, or `terminated`.                   |

### `MON_SESSION`

Session-continuity observability. Emitted by anchors, workers, and session
directories at every `SessionCtrlV1` state transition (see
[protocol_surfaces.md](protocol_surfaces.md)) so operators can see attach,
rebind, drain, epoch bump, relocation, and stale-generation rejection on
the same telemetry channel as the rest of monitor output. The emission
helpers live in `modules/sdk/runtime/telemetry.rs`; `echo_anchor` and
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
`modules/sdk/contracts/net/session_ctrl.rs`): `normal`, `drain_timeout`,
`stale_epoch`, `error`, `client_gone`.

Status codes (from the `STATUS_*` constants): `ok`, `stale_epoch`,
`unknown_session`, `no_capacity`, `corrupt`, `not_ready`.

#### Failover records (`transport_migratable` sessions)

Status: design target, not wired — no module emits these lines yet.

For sessions declared `transport_migratable` with platform-replicated
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

### `MON_PRESENTATION`

Status: design target, not wired — no module emits these lines yet.

AV presentation-group observability, defined by
[av_capability_surface.md](av_capability_surface.md). Clock authorities,
presentation anchors, and group coordinators emit one line per state
change so operators can trace lip-sync drift, sink join / leave, anchor
rebind, and missed present / audio boundaries on the same telemetry
channel as session continuity.

```
MON_PRESENTATION mod=<idx> event=<e> group=<id> [member=<name>] [authority=<name>] [latency_ms=<n>] [skew_us=<n>] [epoch=<n>] [reason=<r>] [status=<s>]
```

| Field        | Meaning                                                                       |
|--------------|-------------------------------------------------------------------------------|
| `mod`        | Module index of the emitter (clock authority, anchor, or coordinator).        |
| `event`      | Transition label; see event table below.                                      |
| `group`      | `presentation_group.id` from YAML config (e.g. `living_room`).                |
| `member`     | Module name of the member the event applies to. Omit for whole-group events.  |
| `authority`  | Module name of the current clock authority. Present on `epoch_advance`.       |
| `latency_ms` | Group latency budget consumed; reported on `latency_report`.                  |
| `skew_us`    | Inter-member skew in microseconds; reported on `skew_report`.                 |
| `epoch`      | Presentation epoch as decimal u32. Bumps on cutover.                          |
| `reason`     | Cause; e.g. `cutover`, `clock_loss`, `member_drop`, `degraded_mode`.          |
| `status`     | Status code; e.g. `ok`, `underflow`, `overflow`, `missed_present`.            |

#### Events

| Event             | Emitter(s)         | When                                                                       |
|-------------------|--------------------|----------------------------------------------------------------------------|
| `group_active`    | coordinator/anchor | Group reached steady state. `authority=<name>`.                            |
| `member_joined`   | coordinator        | Sink admitted into group. `member=<name>`.                                 |
| `member_left`     | coordinator        | Sink departed (planned or fault). `member=<name> reason=<r>`.              |
| `epoch_advance`   | clock authority    | Presentation epoch bumped at a media boundary. `epoch=<n> reason=cutover`. |
| `anchor_rebind`   | anchor             | Stable sink attachment moved (anchor-preserved continuity).                |
| `clock_lost`      | clock authority    | Authority lost timing reference. `reason=clock_loss`.                      |
| `clock_recovered` | clock authority    | Authority regained timing.                                                 |
| `latency_report`  | any                | Periodic latency report; `latency_ms=<n>`.                                 |
| `skew_report`     | coordinator        | Periodic inter-member skew report; `skew_us=<n>`.                          |
| `underflow`       | sink               | Sink starved at the boundary. `status=underflow`.                          |
| `overflow`        | sink               | Sink dropped frames/samples. `status=overflow`.                            |
| `missed_present`  | scanout sink       | Frame missed its target vsync. `status=missed_present`.                    |
| `degraded_mode`   | coordinator        | Group entered/left degraded mode. `reason=<r> status=<s>`.                 |

Reasons: `cutover`, `clock_loss`, `member_drop`, `degraded_mode`,
`member_recovered`, `protected_required`, `format_change`.

Status codes: `ok`, `underflow`, `overflow`, `missed_present`,
`drift_corrected`, `protected_denied`.

## Kernel support

Source: `modules/sdk/internal/monitor.rs`.

- `FAULT_MONITOR_SUBSCRIBE` (`0x0C52`) — bind an event handle that the
  kernel signals on every fault.
- `FAULT_MONITOR_POP` (`0x0C53`) — pop the oldest fault record (12 bytes,
  see `step_guard::FaultRecord`).
- `FAULT_STATS_QUERY` (`0x0C54`) — fetch the current `FaultStats` for a
  module index.
- `STEP_HISTOGRAM_QUERY` (`0x0C55`) — fetch the 8-bucket histogram for a
  module (or the global histogram with `handle=-1`).

A monitor module reads these syscalls on a slow cadence and prints the
corresponding `MON_*` lines. The parser in `tools/src/monitor.rs` accepts
whatever arrives — any subset is acceptable.
