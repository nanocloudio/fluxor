# Rig Backend Protocol

Normative specification for the subprocess contract between
`fluxor rig …` (the orchestrator) and an individual hardware-rig backend.

The orchestrator knows only the capability vocabulary and the run
lifecycle. It knows nothing about any specific mechanism (smart-plug
model, netboot protocol, serial tty setup, …). Every concrete mechanism
is an external executable that speaks the protocol on this page.

See also:

- [capability_surface.md](capability_surface.md) — the public vocabulary.
- [../guides/rig.md](../guides/rig.md) — running scenarios on a rig.

---

## 1. Roles

- **Orchestrator** — `fluxor rig …`. Selects backends, spawns them, feeds
  them config on stdin, consumes their stdout, and enforces lifecycle
  ordering.
- **Backend** — any executable on the search path whose name matches
  `<surface>-<name>`. A backend may implement one or more **verbs** for
  its surface.

Backends can be written in any language. Reference backends in the
sibling `fluxor-rig-backends` tree are Python scripts.

## 2. Discovery

### 2.1 Executable naming

A backend is an executable whose filename is `<surface>-<name>`, where
`surface` is one of:

`power`, `deploy`, `console`, `telemetry`, `observe`

…and `name` is the second half of the capability identifier or the
profile's `backend = "…"` field. Examples:

| Profile section / field                 | Executable            |
|-----------------------------------------|------------------------|
| `[power] backend = "kasa_local"`        | `power-kasa_local`     |
| `[power] backend = "manual"`            | `power-manual`         |
| `[deploy.netboot_tftp]`                 | `deploy-netboot_tftp`  |
| `[console.serial]`                      | `console-serial`       |
| `[telemetry.monitor_udp]`               | `telemetry-monitor_udp`|

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

If no matching executable is found, the orchestrator fails at plan/run
time with an error naming every searched path and pointing operators at
`$FLUXOR_BACKEND_PATH`. Nothing is silently degraded.

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
  `telemetry attach`, `deploy watch`. The orchestrator writes one JSON
  object to stdin, closes stdin, then reads newline-delimited JSON
  events from stdout until the backend exits.

A single backend executable may implement multiple verbs of both kinds.
For example, `deploy-netboot_tftp` is expected to implement both `stage`
(actuator) and `watch` (transport).

### 3.1 Verbs by surface

| Surface     | Actuator verbs                                   | Transport verbs |
|-------------|--------------------------------------------------|-----------------|
| `power`     | `on`, `off`, `cycle`, `diagnose`, `hold`, `sweep` | —              |
| `deploy`    | `stage`, `unstage`                               | `watch`         |
| `console`   | —                                                | `attach`        |
| `observe`   | —                                                | `attach`        |

The switching verbs (`on`, `off`, `cycle`) and `stage` are the run; the
board contract (`[rig].power`) says which switching verbs a target has.
The rest are the teardown and its helpers, and every backend may offer
them:

| Verb       | When the orchestrator calls it | What it does |
|------------|--------------------------------|--------------|
| `diagnose` | after a failed or timed-out run, before `off` | gathers what the mechanism can see of the machine's last state (a cloud console log, a bootrom state, a plug's power reading) into `run_dir`; reports it in `detail`. |
| `off`      | at the end of every run, whatever the verdict | makes the machine stop. A mechanism with nothing to switch (a USB-powered board) reports `ok` with an `info` beginning `no-op:` and the run record says so. |
| `unstage`  | after `off` | removes what `stage` put in place (a TFTP root entry, an uploaded image). |
| `hold`     | before a `--hold` wait on a failed run | `args.minutes` says how long the operator wants the machine kept; the backend may refuse (exit nonzero) when it cannot promise that — the hold is then skipped and the teardown runs at once. `info` is where to say how to reach the machine. |
| `sweep`    | by `fluxor rig teardown --all`, once per distinct power binding | finds and stops everything of this lab's that is still running anywhere the mechanism can see, and reports what it found under `detail.residue`. |

A backend that does not implement a verb **exits 64** (§5.2) rather
than guessing. For `diagnose`, `unstage`, `hold` and `sweep` that is
the normal case and is tolerated; for a switching verb or `stage` it
fails the step.

## 4. Stdin

Every invocation receives one JSON object on stdin, terminated by a
newline. The orchestrator closes stdin immediately afterwards.

```json
{
  "binding": {
    "backend": "kasa_local",
    "host": "192.0.2.26",
    "password": "already-resolved-plaintext"
  },
  "context": {
    "rig_id": "pi5-a",
    "lab": "default",
    "run_id": "1776928391-pi5-a",
    "run_dir": "/home/operator/.local/state/fluxor/labs/default/rigs/pi5-a/runs/1776928391-pi5-a",
    "scenario_name": "pi5_boot_banner",
    "board": "pi5",
    "effective_timeout_ms": 30000,
    "phase": "run",
    "state_dir": "/home/operator/.local/state/fluxor/labs/default/rigs/pi5-a/state"
  },
  "artifact": {
    "kind": "bundle",
    "path": "/home/operator/src/fluxor/target/bcm2712"
  },
  "args": null,
  "relay": null
}
```

### 4.1 `binding`

A flat map of string → scalar copied from the rig profile section that
selected this backend (e.g. `[power]` for a power backend,
`[deploy.netboot_tftp]` for `deploy-netboot_tftp`). Values are
strings, 64-bit integers, or booleans.

**Secrets.** Values that originated as `${env:…}`, `${file:…}`, or
`${keychain:…}` indirections in the profile are resolved to plaintext
before being placed in the `binding`. Backends never see indirection
syntax. Backends **must not** log or surface these values in
human-readable output beyond what the run fundamentally requires (e.g.
the TCP request body for a smart-plug command).

### 4.2 `context`

Identity of the run. Backends can include relevant fields in side-channel
logs so per-backend output is correlatable to the run manifest. The
`run_dir` exists and is writable; backends may write auxiliary logs into
it (e.g. `deploy-netboot_tftp/stage.log`).

`phase` says why the backend is being called: `run` for the lifecycle
of a scenario, `teardown` for the steps that put the rig back (also
`fluxor rig teardown`), `adhoc` for `fluxor rig power …`. A backend
that behaves differently in a teardown (no retries, no waiting for a
console) keys on it; most ignore it. Absent means `run`.

`state_dir` is the rig's own directory (`0700`), kept across runs and
serialised by the rig lock: where this rig's backends leave what a
later step needs — the image a deploy registered, the machine a power
step started, for the console to find. Files in it are written
atomically (write to a temporary name, then rename) and carry
`"schema": 1`, `run_id` and `rig`. A deploy's `unstage` and a power
backend's `off` and `sweep` clean up what their counterparts left.
`run_dir` is one run's record; `state_dir` is the rig's memory.

### 4.3 `artifact`

Populated only for `deploy stage`. `kind` is `file` (single artifact)
or `bundle` (directory tree). `path` is absolute.

### 4.4 `args`

Verb-specific input, `null` for most verbs. `hold` receives
`{"minutes": N}`. New verbs add their own keys here rather than new
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
for exactly this reason. `null` when the backend runs directly.

## 5. Actuator protocol

### 5.1 Stdout

On success, the backend writes one JSON object to stdout:

```json
{"ok": true, "info": "cycled via kasa_local at 192.0.2.26"}
```

Fields:

| Field   | Required? | Meaning                                         |
|---------|-----------|-------------------------------------------------|
| `ok`    | optional  | boolean; defaults to `true`. Advisory only — the orchestrator uses exit code as the authoritative success signal. |
| `info`  | optional  | short human string; surfaced in the run log.   |
| `detail`| optional  | arbitrary JSON; copied verbatim into the run manifest. |

Empty stdout is equivalent to `{"ok": true}`.

`ok: false` with exit 0 is a failure: the report is believed.

### 5.2 Exit code

- `0` = success (unless the report says `ok: false`).
- `64` = the backend does not implement this verb. Tolerated for the
  optional verbs (§3.1), a failure for the rest.
- any other nonzero = failure. The orchestrator keeps the tail of
  stderr in the error message and in the run record. During a run the
  failure aborts it, and the teardown follows; during a teardown the
  failure is recorded and the remaining steps still run.

### 5.3 Timeout and process group

Every actuator invocation has a timeout: the binding's
`actuator_timeout_s`, else the orchestrator's default of 60 s. An
actuator that has not exited by then is sent SIGTERM, then SIGKILL
after the binding's `shutdown_grace_s` (default 2 s). Both go to the
backend's process group, so helpers it spawned die with it. Stdout and
stderr are drained concurrently, so a chatty backend never blocks on a
full pipe. Well-behaved actuators finish in seconds; the timeout is for
the ones that do not.

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
| `ready` | —                                           | Setup finished; observation is live. The orchestrator does not stage or power the rig until every attached transport has sent it (or exited), up to 10 s; a backend that never sends it costs that wait. Anything reported about the open itself (a `boot` found on opening) goes before it. |
| `bytes` | `data` (base64 string)                      | Raw transport bytes. Base64 keeps the line `cat`-safe. |
| `boot`  | —                                           | The machine behind this transport started again: a tty that enumerated anew, a serial console whose DTR dropped, a cloud instance that entered `running`. **Never on the first open** — the machine may have been running for hours. The orchestrator uses it to tell the new image's output from the old one's. |
| `fetch` | `filename` (string), `client_ip` (optional string) | A deploy-adjacent fetch event (e.g. TFTP served a file). |
| `dhcp`  | —                                           | Informational DHCP activity. Purely diagnostic. |
| `error` | `message` (string)                          | Non-fatal backend-surfaced error. |
| `note`  | `message` (string)                          | Free-form human-readable diagnostic. |

Event kinds the orchestrator does not recognise are ignored. Future
kinds can be added without breaking older backends.

### 6.2 Shutdown

The orchestrator signals shutdown by sending **SIGTERM** to the backend's
process group. Backends **should**:

- catch SIGTERM,
- flush any pending event to stdout,
- exit cleanly (exit code 0).

If the backend has not exited after the binding's `shutdown_grace_s`
(default 2 s) the orchestrator sends **SIGKILL** to the process group
(not just the backend process — any grandchildren the backend spawned,
such as a `journalctl -f` subprocess, die with it).

A transport that exits on its own, or with 64 for a verb it does not
have, closes with its reason in the run log; the run goes on without
it unless a rule read from it.

Backends are spawned in their own process group, so a single
`kill(-pgid, …)` reaches the whole subtree.

### 6.3 No stdin after setup

The orchestrator closes stdin immediately after sending the invocation
JSON. Backends should not expect further input.

## 7. Stderr

Stderr is captured to `<run_dir>/<surface>-<verb>.stderr.log` (phase
prefixed outside the run) and its tail is surfaced to the operator when
the backend fails. Backends should use stderr for human-readable
diagnostics and errors. **Never put secret values on stderr.**

## 8. Example backends

### 8.1 Minimal `power-manual` (actuator)

```sh
#!/bin/sh
# power-manual: prompts the operator to unplug and re-plug the DUT.
# Reads invocation on stdin (ignored) and returns a success report.

case "$1" in
  cycle)
    printf '[power-manual] Unplug the DUT, then press Enter ' >&2
    read _
    printf '[power-manual] Plug the DUT back in, then press Enter ' >&2
    read _
    printf '{"ok":true,"info":"cycled manually"}\n'
    ;;
  on|off)
    printf '{"ok":true}\n'
    ;;
  *)
    printf 'power-manual: unknown verb %s\n' "$1" >&2
    exit 2
    ;;
esac
```

### 8.2 Minimal `console-stub` (transport, for tests)

```sh
#!/bin/sh
# console-stub: emits one pre-canned bytes event, then waits for SIGTERM.
read _invocation_json

# "hello\n" base64-encoded
printf '{"kind":"ready"}\n'
printf '{"kind":"bytes","data":"aGVsbG8K"}\n'

trap 'exit 0' TERM
while :; do sleep 60; done
```

## 9. Version and stability

There is one protocol, this one. Fields and event kinds are added
additively; a backend that ignores what it does not know keeps
working, and the orchestrator ignores event kinds it does not know.
