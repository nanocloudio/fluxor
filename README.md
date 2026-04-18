# Fluxor

**Deterministic systems software, from interrupt to internet, expressed as a graph and validated before deployment.**

Fluxor is a runtime that replaces threads, processes, and ad-hoc event loops with an explicit graph of position-independent modules connected by typed channels. The graph is described in a YAML config, validated against a target's hardware capabilities at build time, and executed cooperatively at runtime. The same model spans hardware-timer-driven control loops, microcontroller firmware, embedded Linux services, and server-class workloads — without changing the abstraction.

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
|  cyw43       ip             http     synth     raft_engine     |
|  enc28j60    fat32          mqtt     sequencer  wal            |
|  e810        tls            dns      mp3        commit_tracker |
|  st7701s     wifi           voip     mixer     ...             |
|  ...         ...            ...      ...                       |
+----------------------------------------------------------------+
```

The kernel knows how to step modules, move bytes between them, and touch buses. It does not know what TCP is, what a filesystem is, what audio sounds like, or what a Raft log entry looks like. Everything else lives in modules.

## Why Fluxor

Existing systems software forces a choice. Embedded RTOSes give you predictable timing but no composition story above bare metal. Server-class runtimes give you composition but introduce GC pauses, kernel preemption, async work-stealing, and mutex contention that destroy tail latency. Linux real-time patches narrow the gap on one end; bare-metal frameworks narrow it on the other. Neither side gives you a single model that survives the transition from a 1µs ISR to a 10 GbE network stack.

Fluxor takes a different approach:

- **One model from interrupt to internet.** Hardware-timer ISR work, cooperative microsecond-scale modules, network protocol stacks, distributed consensus, and demand-paged compute workloads all use the same graph primitive — modules connected by channels, executed in topological order. There is no separate "real-time" tier and "service" tier with different APIs.

- **Validation is the trust root.** Every config is checked against a target descriptor: pin assignments, bus configurations, capability requirements, channel typing, resource budgets, peripheral counts. A config that violates an invariant fails at build time, not in production. The kernel enforces the validated grant — modules cannot give themselves permissions.

- **Determinism is structural, not aspirational.** No GC. No work-stealing scheduler. No mutex contention (each domain is single-threaded). No surprise allocations. Backpressure flows through channel fullness, not credit counters in application code. Modules are bounded in time per step and in memory per arena, by contract.

- **Composition is the unit of reuse.** A module compiled once runs unchanged across silicon families. A music player on a Pico W and a music player streaming over network use the same `mp3` decoder module, the same `i2s` driver module, with different wiring. A consensus node on bare-metal aarch64 reuses the same `wal`, `commit_tracker`, and `apply_pipeline` modules whether the network underneath is virtio or PCIe Ethernet.

- **The kernel is small and stays small.** Adding support for a new chip means writing a driver module, not modifying the kernel. Adding a new protocol means writing a foundation module, not modifying the kernel. The minimum kernel for a Pico is around 256 KB compiled. Nothing in the kernel grows with the number of supported devices or protocols.

## What People Build With It

The same primitives carry workloads that normally live in entirely different software ecosystems:

- **Audio products.** Music players, synthesizers with effects chains, MIDI sequencers, MP3 decoders, I2S drivers, microphone capture pipelines.
- **Display and input.** TFT LCD drivers, e-paper renderers, touch controllers, gesture recognition, ST7701S panels, Waveshare LCD modules.
- **Storage and filesystems.** SD card drivers, FAT32 filesystems, flash blob serving, runtime parameter stores.
- **Networking.** WiFi drivers (cyw43, esp_wifi), Ethernet PHYs (enc28j60, e810, virtio_net), full TCP/UDP/IP stack, HTTP servers and clients, DNS, MQTT, VoIP/RTP, TLS 1.3 (pure Rust, no C dependency).
- **Real-time control.** Hardware-timer ISR modules for motor control, sensor fusion, FOC current loops, drone PID stacks, PLC scan cycles, EtherCAT-style cyclic I/O.
- **Distributed systems.** Raft consensus, write-ahead logging, group fsync batching, replication pipelines, snapshot transport. The Clustor project is a 21-module Raft replication substrate built on Fluxor primitives.
- **Edge data services.** S3-compatible object storage, EBS-style block storage, KV caches, message brokers, API gateways — every request phase as a module, deterministic P99, zero OS tax. Competitive with Linux storage targets at extreme IOPS using poll-mode NVMe completion.
- **Fleet-deployable graph bundles.** Container-style packaging where the unit of deployment is a signed, validated graph rather than an OCI image. Bundles are 50–500 KB, boot in milliseconds, and deploy atomically with A/B rollback and live reconfigure. Trust derives from signing rather than namespace isolation.
- **Demand-paged compute.** Workloads with datasets larger than physical RAM, transparently paged from NVMe or other backing stores. KV stores, indexes, model weights, and decoded asset caches all sit behind the same pager.
- **AI inference pipelines.** Sensor → preprocess → inference → postprocess → action expressed as one graph. Hailo NPUs and other accelerators map to the start/poll pattern. The pipeline structure stays identical across devices — only the inference module differs between a TinyML quantised classifier on a Pico, a Hailo-accelerated model on a CM5, and a server-class throughput pipeline.
- **Native build toolchains.** Compilers as natural graph pipelines — lex, parse, type-check, lower, optimise, codegen — each phase a module with bounded memory and observable timing. Self-hosting via a Cranelift-native backend or via the POSIX shim that lets LLVM/rustc/lld run on the same kernel.
- **Game consoles and 3D rendering.** GPU rendering (V3D, VideoCore VII) as start/poll modules. The entire console — from USB gamepad through physics through GPU shaders to HDMI output and I2S audio — is one declared graph with deterministic frame timing and no OS overhead between cycles.
- **Retro emulators.** CPU emulation, video, and audio subsystems are structurally isomorphic to a Fluxor pipeline; burst stepping handles compute-heavy CPU steps and StreamTime synchronises frames with audio.
- **Industrial and safety-critical systems.** Hardware-timed execution tiers provide temporal enforcement for safety functions while non-safety logic runs cooperatively in the same graph. The model targets IEC 62304 Class C, IEC 61508 SIL 3, and ISO 26262 ASIL C with structural arguments rather than retrofitted analysis.
- **Web rendering platforms.** HTML, CSS, Canvas 2D, WebAssembly, WebGL, and Web Workers map onto the graph model — each platform feature is a module, Workers are compute domains, rendering is a deterministic pipeline. Untrusted-content isolation is the genuine boundary; everything else composes naturally.

These are not separate Fluxor variants. They are graphs in the same runtime, validated by the same tool, loaded by the same loader, scheduled by the same kernel.

## Architecture Snapshot

```text
+----------------------------------------------------------------+
|                       App Modules                                |
|        synth, mixer, voip, sequencer, codec, raft_engine, ...    |
+----------------------------------------------------------------+
|                    Foundation Modules                           |
|     ip, fat32, http, dns, mqtt, tls, wifi, mesh, ...            |
+----------------------------------------------------------------+
|                      Driver Modules                              |
|     cyw43, enc28j60, virtio_net, sd, st7701s, gt911, i2s, ...    |
+----------------------------------------------------------------+
                Stable Syscall ABI (dev_call)
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
- **Hardware-timer ISR tier** for hard real-time control with cycle-accurate observability
- **Stream clock vs wall clock separation** via `StreamTime`, enabling sample-accurate A/V sync without GC jitter
- **Validation before deployment**: pin conflicts, bus assignments, content type compatibility, resource budgets — all checked at config compile time

## Supported Targets

Fluxor separates **silicon** (the chip — its peripherals, register layout, and CPU architecture) from **boards** (a chip plus a specific PCB layout, pin assignments, and on-board peripherals). One silicon definition can back many boards.

### Silicon

| Silicon | Architecture | Notes |
|---------|--------------|-------|
| **RP2040** | thumbv6m-none-eabi (Cortex-M0+) | XIP execution, Embassy async runtime |
| **RP2350A / RP2350B** | thumbv8m.main-none-eabihf (Cortex-M33) | XIP execution, Embassy async runtime, larger RAM than RP2040 |
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

### 2. Build firmware, tools, and modules

```bash
make build
```

This builds the kernel for the default target (RP2350), the host CLI tool, and all PIC modules.

To target a different silicon:

```bash
make firmware TARGET_ID=rp2040
make firmware TARGET_ID=bcm2712
make firmware TARGET_ID=cm5
make firmware-all
```

### 3. Build all example artifacts

```bash
make examples
```

This builds every example config under `examples/` for its declared target:

- RP examples → UF2 images
- BCM2712 examples → `kernel8.img` boot images for QEMU virt
- CM5 examples → `kernel8.img` boot images for the Compute Module 5

For each target, packaging is driven entirely by the YAML config and the prebuilt `.fmod` modules. The kernel binary, the module table, and the validated config blob are assembled into a single image.

If you only want one class of outputs:

```bash
make examples-rp
make examples-vm
make examples-cm5
```

### 4. Run an example

For QEMU virt (BCM2712):

```bash
make run CONFIG=examples/qemu-virt/hello.yaml
```

For RP boards, flash the UF2 produced by `make examples` to your device.

## CLI Workflow

The host tool is built as `fluxor` and provides packaging and inspection commands:

```bash
# List all configured targets
fluxor targets

# Validate a config without packaging
fluxor validate examples/pico2w/music_player.yaml

# Compose firmware + YAML config + modules into a bootable image.
#   RP targets -> UF2; aarch64 targets -> raw binary (kernel8.img)
fluxor combine <firmware.bin> <config.yaml> -o <out.{uf2,img}>

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
│   ├── platform/       # Per-silicon HAL (rp.rs, bcm2712.rs)
│   └── io/             # Bus primitives (gpio, spi, pio, i2c, uart)
├── modules/            # Position-independent modules
│   ├── sdk/            # Shared SDK: abi.rs, runtime.rs, params.rs
│   ├── drivers/        # Hardware drivers (cyw43, enc28j60, sd, st7701s, ...)
│   ├── foundation/     # Portable services (ip, fat32, http, mqtt, dns, tls, ...)
│   └── app/            # Application modules (synth, codec, mixer, voip, ...)
├── tools/              # Host CLI: validate, combine, pack, build, diff
├── examples/           # Example YAML configs per target board
├── docs/               # Architecture references and guides
└── targets/            # Silicon and board definitions
```

## Documentation

Start with [docs/overview.md](docs/overview.md) for the documentation index.

Recommended reading path:

1. [docs/architecture/pipeline.md](docs/architecture/pipeline.md) — graph runner, channels, scheduler, mailbox mode
2. [docs/architecture/module_architecture.md](docs/architecture/module_architecture.md) — module contract, lifecycle, fault recovery
3. [docs/architecture/hal_architecture.md](docs/architecture/hal_architecture.md) — kernel/module split and per-silicon HAL
4. [docs/architecture/device_classes.md](docs/architecture/device_classes.md) — `dev_call` opcode namespace
5. [docs/architecture/network.md](docs/architecture/network.md) — channel-based networking and net_proto
6. [docs/architecture/capability_surface.md](docs/architecture/capability_surface.md) — hardware section and auto-wiring
7. [docs/vision.md](docs/vision.md) — the longer mesh-native computing argument

## Contributing

Issues and PRs are welcome. If you are adding a module, keep the contract explicit:

- A clear `manifest.toml` with port definitions, content types, and capability declarations
- Deterministic `module_step` behavior — bounded time, no blocking, no unbounded allocation
- Documented parameters and wiring assumptions
- Capability flag declarations (`mailbox_safe`, `in_place_writer`, `deferred_ready`, `drain_capable`) where appropriate

If you are adding silicon support, you will need a TOML in `targets/silicon/` describing the chip's peripherals and a HAL backend in `src/platform/`. The kernel itself should remain mostly cfg-free — per-silicon constants come from the generated `chip_generated.rs`.

## License

Apache-2.0
