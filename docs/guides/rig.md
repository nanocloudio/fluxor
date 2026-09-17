# Hardware rigs

A rig is a board on a bench that `fluxor rig` can flash, reboot and read
without anyone present. A scenario says what to run and what the console
must show; a rig profile outside the tree says which board is attached and
how it is reached; backends — small executables on the discovery path — do
the reaching. A backend is invoked with a verb,
reads its inventory as JSON on stdin, and reports as JSON on stdout, so
adding a way to flash or power a board is a new executable rather than a
change here.

```
fluxor rig test --scenario <scenario>.toml --rig <rig>
```

builds the scenario's config into an image, attaches the console, deploys
the image, cycles power, and reports a verdict from the pass/fail rules.
Every run is recorded under
`~/.local/state/fluxor/labs/<lab>/rigs/<rig>/runs/`, console capture
included.

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
make install     # puts the backends on the discovery path
```

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
# prints it as `chipid`. It selects the board when several are attached,
# and it is what picotool tracks across the reboot it asks for.
[deploy.picotool]
serial = "<chip-id>"

# "Power" on a USB-powered board is a reboot through the reset interface.
[power]
backend = "picotool"
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
# WIFI_PASSWORD = "${file:/etc/fluxor/wifi.psk}"
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
reproduces only in the shell that set it up.

Omitting the SSID is legal — the wifi module then scans instead of
associating, which is a real mode — but the build warns, naming every
source it tried, and the module says the same thing on its own console.
Without that, the consequence surfaced far from the cause: cyw43 never
reaches link up, never announces its MAC, and `ip` sits at `[ip] waiting
for mac` for the life of the board, with every line in that chain
individually unalarming.

What you cannot do over USB alone: cut power, or see the LED. A scenario
that needs the LED observed needs a person, or a camera.

## Pi 5 over the network

The Pi 5 rig netboots: the image is staged into a TFTP root, a switched
supply cycles power, and the console is a UART adapter. The board
declares that shape in `targets/boards/pi5.toml`, and the
`deploy-netboot_tftp`, `power-kasa_local` and `console-serial` backends
supply it. The profile again carries the bench's own values — the board's
address, the TFTP root, the serial port, the power backend's credentials
— and again lives outside the tree.

## Writing a scenario

A scenario names its board, its config, what it requires of the rig, and
regexes over the console it must (`[[pass]]`) and must not (`[[fail]]`)
see. The console attaches because the rules read from it; only deploy
and power need naming in `requires`. Keep the fail rules for things the
kernel says when it has given up — `[fault] pc=`, `[cyw43] halt phase=`,
`[fluxor] boot:` — so a failed run says why in the verdict.
