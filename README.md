# Fluxor

**Composable firmware runtime for microcontrollers.**

Fluxor is not a monolithic embedded stack. It is a graph runtime where hardware-facing drivers and portable services are composed at runtime through configuration, with modules loaded as position-independent binaries.

On RP2040 and RP2350-class devices, this enables systems that feel closer to a software platform than a fixed firmware image.

## Why Fluxor

- **Graph-native execution model**: Systems are built as module graphs (`modules` + `wiring`) instead of hard-coded control loops.
- **Loadable PIC modules**: Processing logic ships as `.fmod` artifacts, validated and loaded by the runtime.
- **Strict kernel boundary**: A stable syscall ABI isolates modules from board-specific implementation details.
- **Event-driven scheduling**: Modules step cooperatively with intra-tick wakeups, reducing latency and wasted polling.
- **Hardware + service layering**: Driver modules touch buses; service modules remain portable across boards.
- **Single platform, broad workloads**: Audio pipelines, displays, touch input, storage, networking, and protocol stacks can coexist in one runtime.

## What Makes It Different

Most embedded projects force an early trade-off: either hard-code everything for speed, or build a generic framework that is too heavy for the target.

Fluxor takes a third path:

- Keep the kernel compact and deterministic.
- Push domain logic into modules.
- Keep module contracts explicit (ports, types, params, ABI).
- Reconfigure behavior by changing graph config and module set, not by rewriting firmware.

That makes Fluxor practical for products that iterate quickly but still need low-level control.

## Architecture Snapshot

```text
                    +-------------------------------+
                    |           Fluxor Core         |
                    | scheduler | channels | loader |
                    | events    | syscalls | ABI    |
                    +-------------------------------+
                               ^
                               | stable syscall boundary
                               v
+----------------------------------------------------------------+
|                       Loadable PIC Modules                     |
|  drivers: sd, st7701s, gt911, button, i2s, cyw43, enc28j60...  |
|  services: fat32, ip, mqtt, decoder, img_decode, bank, synth...|
+----------------------------------------------------------------+
```

## Core Capabilities

- **Module graph runtime** with topological execution and explicit wiring
- **Dynamic fan-out/fan-in support** via runtime tee/merge helpers
- **Channel IPC** with FIFO and mailbox modes for stream and frame workflows
- **Event objects** with scheduler wake integration and IRQ binding model
- **Device-class dispatch** via `dev_call` / `dev_query` for ABI stability
- **Portable service stack** patterns for network, filesystem, and media flows
- **Tooling pipeline** to build firmware, pack modules, and compose UF2 images from YAML

The repository currently includes **38 modules** across audio, display, storage, networking, and control domains.

## Supported Targets

Fluxor targets Raspberry Pi microcontroller families through board definitions and silicon-aware packaging.

- **RP2350** (`thumbv8m.main-none-eabihf`)
- **RP2040** (`thumbv6m-none-eabi`)

Board definitions live in `targets/boards/` (for example: `pico2w`, `picow`, `waveshare-lcd4`).

## Quick Start

### 1. Prerequisites

- Rust toolchain
- `arm-none-eabi-objcopy`
- `arm-none-eabi-ld`

Install Rust targets:

```bash
rustup target add thumbv8m.main-none-eabihf
rustup target add thumbv6m-none-eabi
rustup target add aarch64-unknown-linux-gnu
```

### 2. Build firmware, tools, and modules

```bash
make build
```

### 3. Package a UF2 from an example config

```bash
make package NAME=fat32_player
```

List all example names:

```bash
find examples -name '*.yaml' | sort
```

### 4. Build all example artifacts

```bash
make examples
```

`make examples` builds all shipped example artifacts:

- RP examples as UF2s
- QEMU virt examples as `kernel8.img` images under `target/bcm2712/images/qemu-virt/`
- CM5 examples as `kernel8.img` images under `target/cm5/images/cm5/`

For every target, packaging is driven by the YAML config and prebuilt `.fmod` modules. QEMU virt and CM5 `kernel8.img` files are assembled as raw boot images with a layout trailer, module table, and config blob appended after the fixed kernel binary.

If you want only one class of outputs:

```bash
make examples-rp
make examples-vm
make examples-cm5
```

## CLI Workflow

The host tool is built as `fluxor` and provides package and inspection commands:

```bash
# Compose firmware + YAML config into UF2
fluxor combine <firmware.bin> <config.yaml> -o <out.uf2>

# Compose firmware.bin + YAML config into a raw boot image
fluxor pack-image <firmware.bin> <config.yaml> --modules-dir <dir> -o <kernel8.img>

# Pack module ELF into .fmod
fluxor pack <module.elf> -o <module.fmod> -n <name> -t <module_type>

# Inspect/verify packaged artifacts
fluxor info <file.uf2>
fluxor decode <file.uf2>
```

## Repository Layout

```text
fluxor/
├── src/         # Kernel, scheduler, syscalls, HAL surfaces, runtime
├── modules/     # PIC modules (drivers + services)
├── tools/       # Host CLI and packaging utilities
├── examples/    # Graph YAML examples per board
├── docs/        # Architecture and guides
└── targets/     # Board and silicon definitions
```

## Documentation

Start with [docs/overview.md](docs/overview.md).

Recommended reading path:

1. `docs/architecture/pipeline.md`
2. `docs/architecture/module_architecture.md`
3. `docs/architecture/device_classes.md`
4. `docs/architecture/events.md`
5. `docs/guides/audio.md` and `docs/guides/music_player.md`

## Contributing

Issues and PRs are welcome. If you are adding a module, keep the contract explicit:

- clear manifest and port definitions
- deterministic `step()` behavior
- documented params and wiring assumptions

## License

Apache-2.0
