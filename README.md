# Fluxor

**Deterministic systems software, from interrupt to internet, expressed as a graph and validated before deployment.**

Fluxor is a runtime that replaces threads, processes, and ad-hoc event loops with an explicit graph of position-independent modules connected by typed channels. The graph is described in a YAML config, validated against a target's hardware capabilities at build time, and executed cooperatively at runtime. The same model spans hardware-timer-driven control loops, microcontroller firmware, embedded Linux services, browser-hosted WASM bundles, and server-class workloads — without changing the abstraction.

```text
+-------------------------------+
|          Fluxor Core          |
| scheduler | channels | events |
| loader    | syscalls | ABI    |
+-------------------------------+
              ^ stable syscall ABI
              v
+----------------------------------------------------------------+
|                    Position-Independent Modules                |
|  drivers     foundation     app                                |
|  cyw43       ip             http     synth      sequencer      |
|  enc28j60    fat32          mqtt     codec      mixer          |
|  e810        tls            dns      voip       rtp            |
|  st7701s     wifi           quic     drum       echo_anchor    |
|  ...         ...            ...      ...                       |
+----------------------------------------------------------------+
```

The kernel knows how to step modules, move bytes between them, and expose low-level platform contracts. It does not know what TCP is, what a filesystem is, what audio sounds like, or what an HTTP request means. Everything else lives in modules.

## Why Fluxor

Existing systems software forces a choice. Embedded RTOSes give you predictable timing but no composition story above bare metal. Server-class runtimes give you composition but introduce GC pauses, kernel preemption, async work-stealing, and mutex contention that destroy tail latency. Linux real-time patches narrow the gap on one end; bare-metal frameworks narrow it on the other. Neither side gives you a single model that survives the transition from a 1µs ISR to a 10 GbE network stack.

Fluxor takes a different approach:

- **One model from interrupt to internet.** Hardware-timer ISR work, cooperative microsecond-scale modules, network protocol stacks, distributed consensus, demand-paged compute, and browser-hosted bundles all use the same graph primitive — modules connected by channels, executed in topological order. There is no separate "real-time" tier and "service" tier with different APIs.

- **Validation is the trust root.** Every config is checked against a target descriptor: pin assignments, bus configurations, capability requirements, channel typing, resource budgets, peripheral counts. A config that violates an invariant fails at build time, not in production. The kernel enforces the validated grant — modules cannot give themselves permissions.

- **Determinism is structural, not aspirational.** No GC. No work-stealing scheduler. No mutex contention (each domain is single-threaded). No surprise allocations. Backpressure flows through channel fullness, not credit counters in application code. Modules are bounded in time per step and in memory per arena, by contract.

- **Composition is the unit of reuse.** A module compiled once runs unchanged across silicon families with matching architecture. A music player on a Pico W and a music player streaming over network use the same MP3 decoder module, the same I2S driver module, with different wiring. A consensus node on bare-metal aarch64 reuses the same WAL, commit-tracker, and apply-pipeline modules whether the network underneath is virtio or PCIe Ethernet. A retro-computer emulator runs as the same Z80 core on a Pico 2 W, on a CM5 bare-metal stack, and as a WASM bundle in the browser — only the providers underneath change.

- **The kernel is small and stays small.** Adding support for a new chip means writing a driver module, not modifying the kernel. Adding a new protocol means writing a foundation module, not modifying the kernel. Nothing in the kernel grows with the number of supported devices or protocols.

## What People Build With It

The same primitives carry workloads that normally live in entirely different software ecosystems:

- **Audio products.** Music players, synthesizers with effects chains, MIDI sequencers, MP3 decoders, I2S drivers, microphone capture pipelines.
- **Display and input.** ST7701S panel output, GT911 touch, buttons, keyboard/pointer/gamepad surfaces, gestures, browser canvas sinks, and split deployments where a browser hosts the presentation surface for a bare-metal back end.
- **Storage and filesystems.** SD-card drivers, FAT32, flash blob serving, runtime parameter stores, NVMe with poll-mode completion approaching Linux line-rate at QD=1.
- **Networking.** CYW43 Wi-Fi, ENC28J60, RP1 GEM, Intel E810, virtio-net, full TCP/UDP/IPv4 with ARP/ICMP/DHCP, HTTP/1.1 with Range, DNS, MQTT, VoIP/RTP, TLS 1.3 (pure Rust, no C dependency), DTLS, and an HTTP/3 path through the same module set.
- **Real-time control.** Hardware-timer ISR-tier modules for motor control, sensor fusion, FOC current loops, drone PID stacks, PLC scan cycles, EtherCAT-style cyclic I/O — admitted into Tier 1b/2 domains alongside cooperative modules in the same graph.
- **Distributed systems.** Raft consensus, write-ahead logging, group fsync batching, replication pipelines, and snapshot transport built as ordinary Fluxor module sets sharing the same scheduler and channel ABI as everything else.
- **Edge data services.** Object and namespace surfaces, replicated key-value caches, message brokers, API gateways — every request phase as a module, deterministic P99, no OS tax between cycles.
- **Fleet-deployable graph bundles.** Container-style packaging where the unit of deployment is a signed, validated graph rather than an OCI image. Bundles boot in milliseconds, deploy atomically with A/B rollback, and accept live reconfigure. Trust derives from signing rather than namespace isolation.
- **Demand-paged compute.** Workloads with datasets larger than physical RAM, transparently paged from NVMe or other backing stores. KV stores, indexes, model weights, and decoded asset caches sit behind the same pager.
- **AI inference pipelines.** Sensor → preprocess → inference → postprocess → action expressed as one graph. The pipeline structure stays identical from a quantized TinyML classifier on a Pico to an NPU-accelerated model on an aarch64 board to a poll-mode throughput pipeline on a server-class node — only the inference module differs.
- **Retro emulators.** Z80 / 6502 / m68k cores, video, and audio subsystems are structurally isomorphic to a Fluxor pipeline; burst stepping handles compute-heavy CPU steps and StreamTime synchronises frames with audio. The same emulator graph runs on microcontroller, bare-metal aarch64, and browser targets.
- **Industrial systems.** Hardware-timed execution tiers provide temporal enforcement for safety-relevant functions while non-safety logic runs cooperatively in the same graph. The model targets safety profiles with structural arguments rather than retrofitted analysis.

These are not separate Fluxor variants. They are graphs in the same runtime, validated by the same tool, loaded by the same loader, scheduled by the same kernel.

## Architecture Snapshot

```text
+----------------------------------------------------------------+
|                       App Modules                                |
|        synth, mixer, voip, sequencer, codec, rtp, drum, ...       |
+----------------------------------------------------------------+
|                    Foundation Modules                           |
|     ip, fat32, http, dns, mqtt, tls, wifi, mesh, ...            |
+----------------------------------------------------------------+
|                      Driver Modules                              |
|     cyw43, enc28j60, virtio_net, sd, st7701s, gt911, i2s, ...    |
+----------------------------------------------------------------+
             Stable Syscall ABI (kernel_abi + HAL contracts)
+----------------------------------------------------------------+
|                          Kernel                                  |
|     scheduler  •  channels  •  events  •  loader  •  HAL        |
+----------------------------------------------------------------+
|                          Silicon                                 |
|             RP2040  •  RP2350  •  BCM2712  •  CM5               |
+----------------------------------------------------------------+
```

Modules are organized into three categories by directory:

- **Drivers** (`modules/drivers/`) — touch hardware. Allowed to be platform-specific and to use bus syscalls (SPI, PIO, I2C, GPIO, MMIO).
- **Foundation** (`modules/foundation/`) — portable building blocks. Filesystems, network protocols, transport layers. No direct hardware access; everything goes through channels and the syscall ABI.
- **App** (`modules/app/`) — application-level modules. Audio synthesis, codecs, sequencers, distributed-systems components, anything that composes drivers and foundation modules into a workload.

Every box above the syscall ABI is a position-independent module. On RP targets, modules execute in place from flash via XIP. On aarch64 targets, they are loaded from the boot image's module table into RAM. The same `.fmod` artifact works across every kernel build that exposes the same ABI version on that architecture.

## Core Capabilities

- **Module graph runtime** with topological execution and explicit YAML wiring
- **Cooperative scheduler** with intra-tick event-driven wake (sub-millisecond response to interrupts)
- **Channel IPC** in FIFO mode (copy semantics) and mailbox mode (zero-copy buffer aliasing)
- **Event objects** with IRQ binding, scheduler wake integration, and ISR-safe signalling
- **Per-module heap** with bounded arenas, observable via `dev_query`
- **Per-module sandboxing** at three protection levels (None / Guarded / Isolated) with MPU enforcement on RP2350 and MMU enforcement on aarch64
- **Live graph reconfigure** with four-phase drain protocol and `module_drain` hook for in-flight work completion
- **Demand-paged arenas** for compute workloads larger than physical RAM (aarch64 targets)
- **Capability resolution** at build time: declare what hardware you have, the tool resolves driver chains and auto-wires infrastructure
- **Hardware-timer ISR tier** for hard real-time control with cycle-accurate observability, admitted into the same scheduler as cooperative modules
- **Stream clock vs wall clock separation** via `StreamTime`, enabling sample-accurate A/V sync without GC jitter
- **Validation before deployment**: pin conflicts, bus assignments, content type compatibility, resource budgets — all checked at config compile time

## Supported Targets

Fluxor separates **silicon** (the chip — its peripherals, register layout, and CPU architecture) from **boards** (a chip plus a specific PCB layout, pin assignments, and on-board peripherals). One silicon definition can back many boards.

### Silicon

| Silicon | Architecture | Notes |
|---------|--------------|-------|
| **RP2040** | thumbv6m-none-eabi (Cortex-M0+) | XIP execution, current RP runtime uses Embassy |
| **RP2350A / RP2350B** | thumbv8m.main-none-eabihf (Cortex-M33) | XIP execution, current RP runtime uses Embassy, larger RAM than RP2040 |
| **BCM2712** | aarch64-unknown-none (Cortex-A76) | DRAM-resident, synchronous polling, MMU + page tables |
| **ESP32-S3** | xtensa-esp32s3-none-elf | Validation-only (no kernel build yet) |
| **Linux host** | aarch64-unknown-linux-gnu / x86_64-unknown-linux-gnu | Host-side simulation and tooling |

### Boards

| Board | Silicon | Notes |
|-------|---------|-------|
| **Pico**, **Pico W** | RP2040 | Standard Raspberry Pi Pico boards |
| **Pico 2**, **Pico 2 W** | RP2350A | Standard Raspberry Pi Pico 2 boards |
| **Waveshare LCD modules** | RP2350A/B | RP2350-based boards with on-board displays and touch |
| **QEMU virt** | BCM2712 | Synthetic aarch64 target for development under QEMU |
| **CM5** | BCM2712 | Raspberry Pi Compute Module 5 (bare metal) |
| **Linux** | Linux host | Host-side runtime for embedded Linux services and simulation |

Silicon definitions live in `targets/silicon/*.toml`. Board definitions live in `targets/boards/*.toml` and layer board-specific pin assignments and on-board peripherals on top of the chosen silicon.

## Quick Start

### 1. Prerequisites

- Rust toolchain (stable)
- For RP targets: `arm-none-eabi-objcopy`, `arm-none-eabi-ld`
- For aarch64 targets: `rust-objcopy` (via `cargo install cargo-binutils`)

Install Rust targets you plan to build:

```bash
rustup target add thumbv8m.main-none-eabihf   # RP2350
rustup target add thumbv6m-none-eabi          # RP2040
rustup target add aarch64-unknown-none        # BCM2712 / CM5
rustup target add aarch64-unknown-linux-gnu   # host tools
```

### 2. Build the host tools

```bash
make build
```

This builds the host CLI and its tests from `tools/`. The release CLI used by the Makefile is built with:

```bash
make tools
```

### 3. Build firmware and modules

The Makefile target selector is `TARGET`:

To target a different silicon:

```bash
make firmware TARGET=rp2040
make firmware TARGET=rp2350
make firmware TARGET=bcm2712
make firmware TARGET=cm5
make firmware-all
```

Build PIC modules for the target layout consumed by `fluxor build`, `combine`, and `run`:

```bash
make modules TARGET=rp2350
make modules TARGET=bcm2712
make modules-all
```

### 4. Build or run an example

Linux-hosted examples run directly:

```bash
make run CONFIG=examples/hello/linux.yaml
```

Hardware targets build an artifact and then flash:

```bash
make flash CONFIG=examples/static_server/pico2w.yaml
make flash CONFIG=examples/hello/cm5.yaml
```

You can also build a single packaged artifact without flashing:

```bash
target/aarch64-unknown-linux-gnu/release/fluxor build examples/static_server/pico2w.yaml
```

For each target, packaging is driven by the YAML config and the prebuilt `.fmod` modules. The kernel binary, the module table, and the validated config blob are assembled into the target's output format.

## CLI Workflow

The host tool is built as `fluxor` and provides packaging and inspection commands:

```bash
# List all configured targets
fluxor targets

# Validate a config without packaging
fluxor validate examples/audio_player/pico2w.yaml

# Build one YAML config into the target-specific artifact
fluxor build examples/audio_player/pico2w.yaml

# Pack a module ELF into .fmod
fluxor pack <module.elf> -o <module.fmod> -n <name> -t <module_type>

# Inspect a built artifact
fluxor info <file.uf2>
fluxor decode <file.uf2>

# Show what changes between two configs (used for live reconfigure planning)
fluxor diff <old.yaml> <new.yaml>
```

## Repository Layout

```text
fluxor/
├── src/                # Kernel: scheduler, syscalls, channels, events, loader, HAL
│   ├── kernel/         # Cooperative scheduler, IPC, loader, fault recovery
│   └── platform/       # Per-target runtime and HAL backends
├── modules/            # Position-independent modules
│   ├── sdk/            # Shared SDK: abi.rs, runtime.rs, params.rs
│   ├── drivers/        # Hardware drivers (cyw43, enc28j60, sd, st7701s, ...)
│   ├── foundation/     # Portable services (ip, fat32, http, mqtt, dns, tls, ...)
│   └── app/            # Application modules (synth, codec, mixer, voip, ...)
├── tools/              # Host CLI: validate, build, run, flash, pack, sign, inspect
├── examples/           # Example YAML configs grouped by capability
├── docs/               # Architecture references and guides
└── targets/            # Silicon and board definitions
```

### Where media lives

Fluxor doesn't keep a central asset pool. Each consumer owns its media:

- **Example media** lives next to the example that uses it:
  `examples/<capability>/assets/<file>`. The wasm asset bank,
  `host_asset_source`, and similar loaders resolve paths from there.
- **Module media** lives next to the module that ships with it:
  `modules/<area>/<module>/assets/<file>`.
- **Browser-runtime code** (`runtime.html`, `host_shims.js`,
  `endpoint_runtime.js`) lives at `src/platform/wasm/host/`.

Anything that doesn't fit one of these homes shouldn't grow into a
flat shared `assets/` directory; give it a real home beside the
consumer that owns it.

## Documentation

Start with [docs/overview.md](docs/overview.md) for the documentation index.

Recommended reading path:

1. [docs/architecture/pipeline.md](docs/architecture/pipeline.md) — graph runner, channels, scheduler, mailbox mode
2. [docs/architecture/module_architecture.md](docs/architecture/module_architecture.md) — module contract, lifecycle, fault recovery
3. [docs/architecture/hal_architecture.md](docs/architecture/hal_architecture.md) — kernel/module split and per-silicon HAL
4. [docs/architecture/abi_layers.md](docs/architecture/abi_layers.md) — ABI layers, contract inventory, provider dispatch
5. [docs/architecture/network.md](docs/architecture/network.md) — channel-based networking and net_proto
6. [docs/architecture/capability_surface.md](docs/architecture/capability_surface.md) — hardware section and capability vocabulary
7. [docs/guides/examples.md](docs/guides/examples.md) — current end-to-end example families
8. [docs/vision.md](docs/vision.md) — the broader capability-centric argument

## Contributing

Issues and PRs are welcome. If you are adding a module, keep the contract explicit:

- A clear `manifest.toml` with port definitions, content types, and capability declarations
- Deterministic `module_step` behavior — bounded time, no blocking, no unbounded allocation
- Documented parameters and wiring assumptions
- Capability flag declarations (`mailbox_safe`, `in_place_writer`, `deferred_ready`, `drain_capable`) where appropriate

If you are adding silicon support, you will need a TOML in `targets/silicon/` describing the chip's peripherals and a platform backend in `src/platform/`. The kernel itself should remain mostly cfg-free; per-silicon constants are generated into `chip_generated.rs` and included by the selected platform chip module.

## License

Apache-2.0
