# Rig Backend Protocol

Normative specification for the subprocess contract between
`fluxor rig …` (the orchestrator) and an individual hardware-rig backend.

The orchestrator knows only the capability vocabulary and the run
lifecycle. It knows nothing about any specific mechanism (smart-plug
model, netboot protocol, serial tty setup, …). Every concrete mechanism
is an external executable that speaks the protocol on this page.

See also:

- [`tools/src/rig/vocab.rs`](../../tools/src/rig/vocab.rs) — the closed
  capability vocabulary boards declare and scenarios require.
- [../guides/rig.md](../guides/rig.md) — running scenarios on a rig.

---

## 1. Roles

- **Orchestrator** — `fluxor rig …`. Selects backends, spawns them, feeds
  them config on stdin, consumes their stdout, and enforces lifecycle
  ordering.
- **Backend** — any executable on the search path whose name matches
  `<surface>-<name>`. A backend may implement one or more **verbs** for
  its surface.

Backends can be written in any language: the contract is JSON over
stdio and an exit code.

## 2. Discovery

### 2.1 Executable naming

A backend is an executable whose filename is `<surface>-<name>`, where
`surface` is one of:

`power`, `deploy`, `console`, `telemetry`, `observe`

…and `name` is the second half of the capability identifier, or for
power the profile's `backend = "…"` field. Examples:

| Profile section / field                 | Executable              |
|-----------------------------------------|-------------------------|
| `[power] backend = "<name>"`            | `power-<name>`          |
| `[deploy.netboot_tftp]`                 | `deploy-netboot_tftp`   |
| `[console.serial]`                      | `console-serial`        |
| `[telemetry.monitor_udp]`               | `telemetry-monitor_udp` |
| `[observe.udp_capture]`                 | `observe-udp_capture`   |

A binding that says `relay = "<name>"` is run through `relay-<name>`,
found the same way (§4.5).

### 2.2 Search path

Lookup order (first match wins):

1. `$FLUXOR_BACKEND_PATH`, colon-separated, `$PATH`-style
2. `$XDG_DATA_HOME/fluxor/backends/`
   (falls back to `$HOME/.local/share/fluxor/backends/` when unset)
3. For each entry of `$XDG_DATA_DIRS` (defaulting to
   `/usr/local/share:/usr/share`): `<entry>/fluxor/backends/`

A file must be a regular file with at least one execute bit set to
qualify.

### 2.3 Missing backend

If no matching executable is found, the run fails before it builds or
touches the rig, with an error naming every searched path and pointing
operators at `$FLUXOR_BACKEND_PATH`. Nothing is silently degraded.

## 3. Invocation forms

The orchestrator spawns a backend as:

```
<executable> <verb> [--additional-args…]
```

Two invocation shapes exist:

- **Actuator** (one-shot). Used for capability verbs that complete in
  bounded time: `power cycle|on|off|diagnose|hold|sweep`, `deploy
  stage|unstage`. The orchestrator writes one JSON object to stdin,
  closes stdin, waits for exit.
- **Transport** (streaming). Used for capability verbs that produce
  observable activity over the life of the run: `console attach`,
  `telemetry attach`, `observe attach`, `deploy watch`. The orchestrator
  writes one JSON object to stdin, closes stdin, then reads
  newline-delimited JSON events from stdout until the backend exits or
  the run ends.

A single backend executable may implement multiple verbs of both kinds.
For example, `deploy-netboot_tftp` is expected to implement both `stage`
(actuator) and `watch` (transport).

### 3.1 Verbs by surface

| Surface     | Actuator verbs                                   | Transport verbs |
|-------------|--------------------------------------------------|-----------------|
| `power`     | `on`, `off`, `cycle`, `diagnose`, `hold`, `sweep` | —              |
| `deploy`    | `stage`, `unstage`                               | `watch`         |
| `console`   | —                                                | `attach`        |
| `telemetry` | —                                                | `attach`        |
| `observe`   | —                                                | `attach`        |

Every run attaches its deploy backend's `watch` (a deploy mechanism with
nothing to watch exits 64 at once), the consoles and the telemetry
transport the plan selected, and every observe transport the scenario
names.

The switching verbs (`on`, `off`, `cycle`) and `stage` are the run; the
board contract (`[rig].power`) says which switching verbs a target has.
The rest are the teardown and its helpers, and every backend may offer
them:

| Verb       | When the orchestrator calls it | What it does |
|------------|--------------------------------|--------------|
| `diagnose` | after a failed or timed-out run (an aborted one too, with `--diagnose`), before `off` | gathers what the mechanism can see of the machine's last state (a cloud console log, a bootrom state, a plug's power reading) into `run_dir`; reports it in `detail`. |
| `off`      | at the end of every run, whatever the verdict | makes the machine stop. A mechanism with nothing to switch (a USB-powered board) reports `ok` with an `info` beginning `no-op:` and the run record says so. A `detail.residue` with any non-empty list means the machine is not down, whatever the exit code. |
| `unstage`  | after `off` | removes what `stage` put in place (a TFTP root entry, an uploaded image). |
| `hold`     | before a `--hold` wait on a run that did not pass (never one a signal ended) | `args.minutes` says how long the operator wants the machine kept; the backend may refuse (exit nonzero) when it cannot promise that — the hold is then skipped and the teardown runs at once. `info` is where to say how to reach the machine. |
| `sweep`    | by `fluxor rig teardown --all`, once per distinct power binding | finds and stops everything of this lab's that is still running anywhere the mechanism can see, and reports what it found under `detail.residue`. |

A backend that does not implement a verb **exits 64** (§5.2) rather
than guessing. For `diagnose`, `unstage`, `hold` and `sweep` that is
the normal case and is tolerated; for a switching verb or `stage` it
fails the step — an `off` at teardown included, since a backend with
nothing to switch says so with a `no-op:`.

A teardown is clean when `off` came out `ok` (or the profile binds no
power backend at all), `unstage` came out `ok` or unsupported, and
nothing reported residue; a failed `diagnose` is recorded but does not
keep the rig marked. A rig left marked is torn down again before
anything else touches it.

## 4. Stdin

Every invocation receives one JSON object on stdin, terminated by a
newline. The orchestrator closes stdin immediately afterwards.

A `deploy-netboot_tftp stage`:

```json
{
  "binding": {
    "root": "/srv/tftp",
    "client_ip": "192.0.2.47"
  },
  "context": {
    "rig_id": "pi5-a",
    "lab": "default",
    "run_id": "1776928391-123456789-pi5-a",
    "run_dir": "/home/operator/.local/state/fluxor/labs/default/rigs/pi5-a/runs/1776928391-123456789-pi5-a",
    "scenario_name": "pi5_boot_banner",
    "board": "pi5",
    "effective_timeout_ms": 30000,
    "phase": "run",
    "state_dir": "/home/operator/.local/state/fluxor/labs/default/rigs/pi5-a/state"
  },
  "artifact": {
    "kind": "file",
    "path": "/home/operator/src/fluxor/target/pi5/kernel8.img"
  }
}
```

`artifact`, `args` and `relay` are present only when they apply.

### 4.1 `binding`

A flat map of string → scalar copied from the rig profile section that
selected this backend (e.g. `[power]` for a power backend,
`[deploy.netboot_tftp]` for `deploy-netboot_tftp`). Values are
strings, 64-bit integers, finite floats, or booleans.

Two keys mean something to the orchestrator as well: `actuator_timeout_s`
(§5.3) and `shutdown_grace_s` (§5.3, §6.2). `relay` names a relay
(§4.5).

**Secrets.** Values that originated as `${env:…}` or `${file:…}`
indirections in the profile are resolved to plaintext before being
placed in the `binding`. Backends never see indirection syntax.
Backends **must not** log or surface these values in human-readable
output beyond what the run fundamentally requires (e.g. the TCP request
body for a smart-plug command).

### 4.2 `context`

Identity of the run. Backends can include relevant fields in side-channel
logs so per-backend output is correlatable to the run manifest. The
`run_dir` exists and is writable; backends may write what they gather
into it (a capture, the command line they ran, a console log). Outside
a scenario — a teardown, an ad-hoc power verb, a sweep — the invocation
still gets a `run_id` and a `run_dir` of its own. `effective_timeout_ms`
is the run's match timeout, or the verb's bound outside a run.

`phase` says why the backend is being called: `run` for the lifecycle
of a scenario, `teardown` for the steps that put the rig back (also
`fluxor rig teardown`), `adhoc` for `fluxor rig power …`. A backend
that behaves differently in a teardown (no retries, no waiting for a
console) keys on it; most ignore it. Absent means `run`.

`state_dir` is the rig's own directory (`0700`), kept across runs and
serialised by the rig lock: where this rig's backends leave what a
later step needs — the image a deploy registered, the machine a power
step started, for the console to find. Files in it are written
atomically (write to a name ending `.tmp`, then rename) and carry
`"schema": 1`, `run_id` and `rig`. A deploy's `unstage` and a power
backend's `off` and `sweep` clean up what their counterparts left: a
`state_dir` holding anything but temporary files means something of an
earlier run may still be up, and `fluxor rig power off` on such a rig
runs the full teardown. The orchestrator keeps its own teardown marker
there too. `run_dir` is one run's record; `state_dir` is the rig's
memory.

### 4.3 `artifact`

Populated only for `deploy stage`. `kind` is `file` (single artifact)
or `bundle` (directory tree). `path` is absolute.

### 4.4 `args`

Verb-specific input, absent for a verb that takes none. `hold` receives
`{"minutes": N}`. A verb with arguments carries them here rather than in
top-level fields.

### 4.5 `relay`

A binding may say `relay = "<name>"`, naming a `[relay.<name>]` table
of the same profile: the backend then runs somewhere else — a bench
host beside the device under test — and the orchestrator spawns
`relay-<name> <surface>-<backend> <verb>` in its place, with this
field set to the relay's table. The relay carries the backend's stdio
through and returns its exit code, so a backend needs no change to be
relayed; a relay that copies `run_dir` back on shutdown gets the
binding's `shutdown_grace_s` to do it in. The protocol is stdio-only
for exactly this reason. Absent when the backend runs directly.

## 5. Actuator protocol

### 5.1 Stdout

On success, the backend writes one JSON object to stdout:

```json
{"ok": true, "info": "cycled the outlet at 192.0.2.26"}
```

Fields:

| Field   | Required? | Meaning                                         |
|---------|-----------|-------------------------------------------------|
| `ok`    | optional  | boolean; defaults to `true`. `false` fails the step even on exit 0; `true` does not rescue a nonzero exit. |
| `info`  | optional  | short human string; surfaced in the run log.   |
| `detail`| optional  | arbitrary JSON; copied verbatim into the run manifest. |

Empty stdout is equivalent to `{"ok": true}`. Stdout that is not one
JSON object is a failure of the step.

`ok: false` with exit 0 is a failure: the report is believed.

### 5.2 Exit code

- `0` = success (unless the report says `ok: false`).
- `64` = the backend does not implement this verb. Tolerated for the
  optional verbs (§3.1), a failure for the rest.
- any other nonzero = failure. The orchestrator keeps the tail of
  stderr in the error message and in the run record. During a run a
  failed `stage` or switching verb aborts it, and the teardown follows;
  a refused `hold` skips the hold; during a teardown the failure is
  recorded and the remaining steps still run.

### 5.3 Timeout and process group

Every actuator invocation has a timeout: the binding's
`actuator_timeout_s`, else the orchestrator's default of 60 s. An
actuator that has not exited by then is sent SIGTERM, then SIGKILL
after the binding's `shutdown_grace_s` (default 2 s). Both go to the
backend's process group, so helpers it spawned die with it. Stdout and
stderr are drained concurrently, so a chatty backend never blocks on a
full pipe. Once the backend exits, the orchestrator waits at most the
grace period for its pipes to close: a process it left running that
still holds them (a daemon launched without redirecting its stdio) does
not hold up the run. A helper the backend means to outlive it — a
machine it started — belongs in its own session with its own stdio.
Well-behaved actuators finish in seconds; the timeout is for the ones
that do not.

## 6. Transport protocol

### 6.1 Stdout — newline-delimited JSON events

Each line on stdout is a single JSON object with a `kind` discriminator.
Non-JSON lines are logged to stderr by the orchestrator and skipped;
they do not abort the run.

```json
{"kind": "ready"}
{"kind": "bytes", "data": "aGVsbG8K"}
{"kind": "fetch", "filename": "fluxor/kernel8.img", "client_ip": "192.0.2.47"}
{"kind": "dhcp"}
{"kind": "note", "message": "switched to secondary PHY"}
{"kind": "error", "message": "tftp: client timeout"}
```

Event kinds:

| `kind`  | Fields                                     | Meaning |
|---------|---------------------------------------------|---------|
| `ready` | —                                           | Setup finished; observation is live. The orchestrator does not stage or power the rig until every attached transport has sent it (or closed its stdout), up to 10 s; a backend that never sends it costs that wait. Anything reported about the open itself (a `boot` found on opening) goes before it. |
| `bytes` | `data` (base64 string)                      | Raw transport bytes. Base64 keeps the line `cat`-safe. |
| `boot`  | —                                           | The machine behind this transport started again: a USB tty that enumerated anew, a serial log the power step started afresh, a cloud instance that entered `running`. **Never on the first open** — the machine may have been running for hours. The orchestrator uses it to tell the new image's output from the old one's. |
| `fetch` | `filename` (string), `client_ip` (optional string) | A deploy-adjacent fetch event (e.g. TFTP served a file). An `observe.netboot_fetch` rule matches on `filename`. |
| `dhcp`  | —                                           | Informational DHCP activity. Purely diagnostic. |
| `error` | `message` (string)                          | Non-fatal backend-surfaced error. An `observe.netboot_fetch` fail rule whose regex matches `message` fails the run. |
| `note`  | `message` (string)                          | Free-form human-readable diagnostic. |

Bytes from every byte-stream transport — console, telemetry, an observe
probe reporting its results — go to `<run_dir>/<capability>.log` and to
the rules that name that capability. Bytes that arrive before the run's
power step are the previous image talking: they are logged but never
matched, unless the transport reported a `boot` after the power step
began.

A line whose `kind` the orchestrator does not recognise is logged to
stderr and skipped, like any other line it cannot decode.

### 6.2 Shutdown

The orchestrator signals shutdown by sending **SIGTERM** to the backend's
process group. Backends **should**:

- catch SIGTERM,
- flush any pending event to stdout,
- exit cleanly (exit code 0).

When the backend exits, or after the binding's `shutdown_grace_s`
(default 2 s) if it has not, the orchestrator sends **SIGKILL** to the
process group — not just the backend process: anything the backend
spawned (a `journalctl -f`, a helper that ignores SIGTERM) dies with it.
It then waits at most the grace period again for the backend's stdout
to close.

A transport that exits on its own, or with 64 for a verb it does not
have, closes with its reason in the run log, and the run goes on
without it: a rule that read from it is then decided by what it said
before it closed, its silence (`max_silence_s`), or the timeout.

Backends are spawned in their own process group, so a single
`kill(-pgid, …)` reaches the whole subtree, and a terminal's Ctrl-C
reaches the orchestrator — which tears down — rather than the backend.

### 6.3 No stdin after setup

The orchestrator closes stdin immediately after sending the invocation
JSON. Backends should not expect further input.

## 7. Stderr

Stderr is kept beside the run as
`<run_dir>/<surface>-<name>-<verb>.stderr.log` (`….teardown.stderr.log`
for a teardown step). An actuator's stderr is captured whole and its
tail surfaced in the error and the run record when it fails; a
transport's is also copied live to the operator's terminal. Backends
should use stderr for human-readable diagnostics and errors. **Never put
secret values on stderr.**

## 8. Example backends

### 8.1 Minimal `power-manual` (actuator)

```sh
#!/bin/sh
# power-manual: asks the operator to switch the DUT by hand. The
# invocation on stdin is read and ignored; the operator answers on the
# terminal, since stdin carries the invocation and is closed after it.
read _invocation

ask() {
  printf '[power-manual] %s, then press Enter ' "$1" >/dev/tty
  read _ </dev/tty
}

case "$1" in
  cycle) ask "Unplug the DUT"; ask "Plug the DUT back in"
         printf '{"ok":true,"info":"cycled by hand"}\n' ;;
  on)    ask "Plug the DUT in";  printf '{"ok":true}\n' ;;
  off)   ask "Unplug the DUT";   printf '{"ok":true}\n' ;;
  *)     printf 'power-manual: no verb %s\n' "$1" >&2
         exit 64 ;;
esac
```

### 8.2 Minimal `console-stub` (transport, for tests)

```sh
#!/bin/sh
# console-stub: emits one pre-canned bytes event, then waits for SIGTERM.
read _invocation_json
trap 'exit 0' TERM

# "hello\n" base64-encoded
printf '{"kind":"ready"}\n'
printf '{"kind":"bytes","data":"aGVsbG8K"}\n'

while :; do sleep 1; done
```

## 9. Stability

There is one protocol, this one. A backend ignores invocation fields it
does not know, and the orchestrator skips event lines it cannot decode,
so either side tolerates fields the other does not use.
