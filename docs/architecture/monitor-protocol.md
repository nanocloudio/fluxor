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
