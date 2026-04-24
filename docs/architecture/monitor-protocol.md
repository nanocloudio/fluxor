# Monitor Protocol

`fluxor monitor` displays a live per-module dashboard for a running Fluxor
device. The device emits newline-framed text lines on its normal log
transport (USB CDC on RP targets, UART on Pi 5); the host tool tails those
lines, aggregates them into per-module rows, and renders an ANSI table.

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

Buckets, in microseconds: `<64`, `<128`, `<256`, `<512`, `<1024`, `<2048`,
`<4096`, `>=4096`.

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

Reserved for session-continuity observability. Emitted by anchors,
workers, and session directories (see
`architecture/protocol_surfaces.md`) at every
`SessionCtrlV1` state transition so operators can see attach, rebind,
drain, epoch bump, relocation, and stale-generation rejection on the
same telemetry channel as the rest of monitor output.

The line format is part of the public observability surface defined
by `architecture/protocol_surfaces.md`. Anchor / worker / directory
modules (`echo_anchor` and `echo_worker` today) emit one line per
state transition.

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
| `status`  | Status code name. Present only on `event=attached` / `imported` / `relocated`. |

`session_id` rendering uses the canonical cluster byte order (big-
endian) with no `-` separators, so `MON_SESSION` lines grep cleanly
for a given session across emitters.

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
| `rejected`   | any                   | Stale epoch / unknown session rejected inbound. `reason=stale_epoch` or `unknown_session`. |
| `error`      | any                   | `MSG_SC_ERROR` emitted. `status=<code>`.                            |

Reasons (from `DETACH_*` constants in `session_ctrl.rs`): `normal`,
`drain_timeout`, `stale_epoch`, `error`, `client_gone`.

Status codes (from `STATUS_*` constants): `ok`, `stale_epoch`,
`unknown_session`, `no_capacity`, `corrupt`, `not_ready`.

#### Example

```
MON_SESSION mod=3 event=attach_req session=44454d4f2d413031000000000000000a epoch=1 worker=44454d4f2d573031 status=ok
MON_SESSION mod=4 event=attached session=44454d4f2d413031000000000000000a epoch=1 anchor=44454d4f2d413031 status=ok
MON_SESSION mod=4 event=drained session=44454d4f2d413031000000000000000a epoch=1 anchor=44454d4f2d413031
MON_SESSION mod=4 event=detached session=44454d4f2d413031000000000000000a epoch=1 anchor=44454d4f2d413031 reason=client_gone
```

Operators grep `MON_SESSION ... session=44454d4f2d413031000000000000000a`
to follow one session's lifecycle across anchor / worker / directory
emitters.

## Kernel support

- `FAULT_MONITOR_SUBSCRIBE` (`0x0C52`) — bind an event handle that the
  kernel signals on every fault.
- `FAULT_MONITOR_POP` (`0x0C53`) — pop the oldest fault record (12 bytes,
  see `step_guard::FaultRecord`).
- `FAULT_STATS_QUERY` (`0x0C54`) — fetch the current `FaultStats` for a
  module index.
- `STEP_HISTOGRAM_QUERY` (`0x0C55`) — fetch the 8-bucket histogram for a
  module (or the global histogram with `handle=-1`).

A monitor module reads these syscalls on a slow cadence and prints the
corresponding `MON_*` lines. The CLI scaffold in `tools/src/monitor.rs`
parses whatever arrives — any subset is acceptable.
