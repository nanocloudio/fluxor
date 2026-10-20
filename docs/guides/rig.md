# Hardware rigs

A rig is a board on a bench that `fluxor rig` can flash, reboot and read
without anyone present. A scenario says what to run and what the console
must show; a rig profile outside the tree says which board is attached and
how it is reached; backends — small executables on the discovery path — do
the reaching. A backend is invoked with a verb, reads its inventory as
JSON on stdin, and reports as JSON on stdout, so adding a way to flash or
power a board is a new executable rather than a change here
([the protocol](../architecture/rig-backend-protocol.md)).

```
fluxor rig test --scenario <scenario>.toml --rig <rig>
```

builds the scenario's config into an image, attaches the console, deploys
the image, cycles power, and reports a verdict from the pass/fail rules.
Then, whatever the verdict, it tears the rig down: power off, the staged
image removed, every observer stopped. Every run is recorded under
`~/.local/state/fluxor/labs/<lab>/rigs/<rig>/runs/`, console capture
and the teardown's outcome included.

A board that cannot be switched off — a Pico on USB — reports the power
off as a no-op, and the record says so. A teardown that does not complete
(the plug did not answer, a cloud machine is still running) leaves the
rig marked; the next `fluxor rig test` on it finishes the teardown before
doing anything else, and `fluxor rig teardown --rig <rig>` does it by
hand. `fluxor rig teardown --all` goes through every rig in the lab and
then asks each power backend — once per distinct binding, whatever the
rigs' own teardowns came to — to sweep for anything of the lab's it can
still see running.

A failed run can be kept for inspection: `--hold <minutes>` leaves the
rig as the run left it until the time is up, Enter is pressed or Ctrl-C
arrives, then tears down. A run that a signal ended is torn down at
once. A board whose images leave the host (a cloud machine) needs
`--hold` on `fluxor rig power on` and `cycle` too, because an `on` with
no end would leave a machine running somewhere.

## Pico 2 W over USB

A Pico 2 W needs no debug probe and no switched supply. Every RP
image carries what picotool needs to control it: the pico-sdk USB identity
(`2e8a:000a`), the chip's unique ID as the USB serial, and the reset
interface picotool drives. With those, `picotool load -f image.uf2` takes
a *running* board into BOOTSEL, flashes it and reboots it — one command,
no button, no drive.

Host setup, once:

```
# picotool needs to open the device without root.
echo 'SUBSYSTEM=="usb", ATTRS{idVendor}=="2e8a", MODE="0666", TAG+="uaccess"' \
  | sudo tee /etc/udev/rules.d/99-picotool.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

The deploy, power and console backends for the board go on the discovery
path — `$FLUXOR_BACKEND_PATH`, or `~/.local/share/fluxor/backends/`;
`make install` links the ones a checkout carries.

Which board is attached, and how it is reached, is a rig profile — held
outside any repository, under `~/.config/fluxor/labs/<lab>/rigs/<rig>.toml`.
That is where every bench-specific value belongs; nothing in the tree
names a particular board. Substitute your own id and serial:

```toml
[rig]
id = "<rig>"
board = "pico2w"
tags = ["wifi", "usb"]

# The board's USB serial is the chip's unique ID — `picotool info -d`
# prints it as `chipid` on RP2350 and as `flash id` on RP2040. It selects
# the board when several are attached. The RP2350 bootrom reports the same
# serial in BOOTSEL; the RP2040 bootrom reports one fixed serial for every
# RP2040, so the backend follows a Pico W across the reboot by its USB
# port instead.
[deploy.picotool]
serial = "<chip-id>"

# "Power" on a USB-powered board is a reboot through the reset interface,
# done by the `power-<name>` backend this names. The other keys are that
# backend's own.
[power]
backend = "<name>"
serial = "<chip-id>"
boot_delay_ms = 3000

# The CDC console. The backend reopens it across every reboot the run
# causes, so a reboot shows up as a reboot rather than as silence.
[console.usb_cdc]
serial = "<chip-id>"

# Facts the BUILD needs that the repo cannot carry. A Pico 2 W cannot be
# built for without the SSID of the network in this room, and no
# checked-in graph can name it. Keys are environment variable names, used
# verbatim, and reach the scenario's build command and nothing else.
#
# Values take the same indirections as any other profile field, so a
# password need not be written here at all — and a value that came from
# an indirection is redacted in plan output, run records and profile
# hashes.
[build_env]
WIFI_SSID = "<your-ssid>"
WIFI_PASSWORD = "${env:WIFI_PASSWORD}"
# WIFI_PASSWORD = "${file:/home/me/.config/fluxor/secrets/wifi.psk}"
```

The project recipe (`~/.config/fluxor/projects/fluxor/rig.toml`) must
produce the *combined* image — kernel, trailer, modules and config — with
`fluxor build <config> --emit=combined --firmware <kernel.uf2>`. A
kernel-only UF2 boots and then has nothing to load, which reads like a
dead board.

Wifi credentials reach the build through `[build_env]` above. They can
still come from the environment of the `fluxor rig` invocation, and a
graph can name them directly, but the profile is where they belong: a
run that depends on what the operator happened to have exported
reproduces only in the shell that set it up. The board says which names
it needs (`build_env_required`) and which are secrets
(`build_env_secret`); a profile missing a required name is refused at
plan time.

A profile may also carry `[host]`: facts the build reads from your
`host.toml` (`host:…` in a graph), overridden for this rig — a cloud
rig's telemetry collector is not the address the bench next to you uses.
The merged file is written into the run's directory and the build is
pointed at it, so the run record holds exactly what the build saw. And a
binding may say `relay = "<name>"` with a matching `[relay.<name>]` table
to run its backend on another machine, for observers that must sit
beside a device no cable reaches.

A secret is never written in a profile. A key whose name says secret —
`password`, `token`, `psk`, `passphrase`, `secret`, alone or as a
suffix — and anything under `[secrets]` must be a `${file:…}` or
`${env:…}` reference; a plain value is refused. The file behind
`${file:…}` must belong to the user running `fluxor` and be mode 0600,
and a profile that resolves any secret must be 0600 itself. The
resolved value reaches the backend and the build and nothing else: plan
output, run records and profile hashes show it redacted.

Omitting the SSID is legal — the wifi module then scans instead of
associating, which is a real mode — but the build warns, naming every
source it tried, and the module says the same thing on its own console.
The consequence otherwise shows up far from the cause: cyw43 never
reaches link up, never announces its MAC, and `ip` sits at `[ip] waiting
for mac` for the life of the board, with every line in that chain
individually unalarming.

What you cannot do over USB alone: cut power, or see the LED. A scenario
that needs the LED observed needs a person, or a camera.

## Pi 5 over the network

The Pi 5 rig netboots: the image is staged into a TFTP root, a switched
supply cycles power, and the console is a UART adapter. The board
declares that shape in `targets/boards/pi5.toml` as capabilities —
`deploy.netboot_tftp`, `power.cycle`, `console.serial` — and the bench
supplies a backend executable for each. The profile again carries the
bench's own values — the board's address, the TFTP root, the serial port,
the power backend's credentials — and again lives outside the tree.

## A machine that is a process

A rig need not be a board. The `qemu-uefi-arm64` board is a QEMU machine
with UEFI firmware: `deploy.qemu_disk` lays a per-run overlay on the built
disk image, `power.cycle` launches QEMU (the command it ran is kept in
the run's directory), `console.qemu_serial` reads the serial console from
its first byte, and `telemetry.qemu_virtio` carries the telemetry ring
over a virtio-serial port. Power off is a QMP `quit`; a failed run's
`diagnose` freezes the machine and keeps its registers, PCI tree and
status, and `--hold` leaves it frozen with a `gdb` line to attach to. The
same scenario shape, the same record, the same teardown — a virtual rig
is just a rig whose backends talk to a process.

## Writing a scenario

A scenario names its board, its config, what it requires of the rig, and
regexes over the console it must (`[[pass]]`) and must not (`[[fail]]`)
see. The console attaches because the rules read from it; only deploy
and power need naming in `requires`. Keep the fail rules for things the
kernel says when it has given up — `[fault] pc=`, `[cyw43] halt phase=`,
`[fluxor] boot:` — so a failed run says why in the verdict.

A `[[pass]]` that never arrives fails only when the whole timeout runs
out, and the verdict then says nothing about where the boot stopped.
`[[expect]]` rules put deadlines on the way: `within_s` says a line must
appear that soon after the power step (or after the source reports a
fresh boot, if that is later), `max_silence_s` says the source, once it
has spoken, must not go quiet for longer than that, and a missed
expectation fails the run at once, naming the rule.

```toml
[[expect]]
source = "console.usb_cdc"
regex = "\\[boot\\] ready modules="
within_s = 10
```

Only output after the run's own power step counts. What the board was
printing before — the previous image, still running while the new one
is staged — is captured but never matched, so a stale pass line cannot
pass a run.
