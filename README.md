# Fluxor

Fluxor is a runtime for deterministic systems software. It replaces
threads, processes, and ad-hoc event loops with an explicit graph of
position-independent modules connected by typed channels. The graph is
described in a YAML config, validated against a target's hardware
capabilities at build time, and executed cooperatively at runtime. The
same model spans hardware-timer-driven control loops, microcontroller
firmware, embedded Linux services, browser-hosted WASM bundles, and
server-class workloads.

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
|  drivers        foundation      app (sibling repos)            |
|  cyw43          ip              consensus                      |
|  enc28j60       fat32           codecs                         |
|  e810           tls             synthesis                      |
|  st7701s        dns             emulation                      |
|  nvme           quic            ...                            |
+----------------------------------------------------------------+
```

The kernel knows how to step modules, move bytes between them, and
expose low-level platform contracts. It does not know what TCP is, what
a filesystem is, what audio sounds like, or what an HTTP request means.
Everything else lives in modules.

## Why Fluxor

Embedded RTOSes give you predictable timing but no composition story
above bare metal. Server-class runtimes give you composition but
introduce GC pauses, kernel preemption, and scheduler contention that
dominate tail latency. Neither side offers a single model that survives
the transition from a microsecond ISR to a network stack.

Fluxor's approach:

- **One model from interrupt to internet.** Hardware-timer ISR work,
  cooperative microsecond-scale modules, network protocol stacks, and
  browser-hosted bundles use the same graph primitive: modules connected
  by channels, executed in topological order. There is no separate
  real-time tier with a different API.
- **Validation is the trust root.** Every config is checked against a
  target descriptor: pin assignments, bus configurations, capability
  requirements, channel typing, resource budgets. A config that violates
  an invariant fails at build time, not in production. The kernel
  enforces the validated grant; modules cannot give themselves
  permissions.
- **Determinism is structural.** No GC, no work-stealing scheduler, no
  cross-thread locking (each execution domain is single-threaded).
  Backpressure flows through channel fullness. Modules are bounded in
  time per step and in memory per arena, by contract.
- **Composition is the unit of reuse.** A module compiled once runs
  unchanged across silicon families with matching architecture; only the
  wiring and the provider chain underneath change between targets.
- **The kernel stays small.** New chip support is a driver module, not a
  kernel change. A new protocol is a foundation module, not a kernel
  change.

The broader capability-centric argument, and where the model is headed,
is in [docs/vision.md](docs/vision.md).

## Architecture Snapshot

```text
+----------------------------------------------------------------+
|                       App Modules                              |
|   consensus, codecs, synthesis, emulation (sibling repos)      |
+----------------------------------------------------------------+
|                    Foundation Modules                          |
|     ip, fat32, dns, tls, quic, wifi, kv_store, sd, ...         |
+----------------------------------------------------------------+
|                      Driver Modules                            |
|     cyw43, enc28j60, virtio_net, nvme, st7701s, gt911, ...     |
+----------------------------------------------------------------+
             Stable Syscall ABI (kernel_abi + HAL contracts)
+----------------------------------------------------------------+
|                          Kernel                                |
|     scheduler  •  channels  •  events  •  loader  •  HAL       |
+----------------------------------------------------------------+
|                          Silicon                               |
|               RP2040  •  RP2350  •  BCM2712                    |
+----------------------------------------------------------------+
```

Modules are organised into three layers:

- **Drivers** (`modules/drivers/`) touch hardware. They may be
  platform-specific and use bus syscalls (SPI, PIO, I2C, GPIO, MMIO).
- **Foundation** (`modules/foundation/`) holds portable building
  blocks: filesystems, network protocols, transport layers. No direct
  hardware access; everything goes through channels and the syscall ABI.
- **App** modules compose drivers and foundation modules into a
  workload. They live in sibling repositories, are built against the
  Fluxor SDK, and load like any other PIC module.

Every box above the syscall ABI is a position-independent module. On RP
targets, modules execute in place from flash via XIP. On aarch64
targets, they are loaded from the boot image's module table into RAM.
The same `.fmod` artefact works across every kernel build that exposes
the same ABI surface on that architecture.

## Core Capabilities

- Module graph runtime with topological execution and explicit YAML
  wiring
- Cooperative scheduler with intra-tick event-driven wake
- Channel IPC in FIFO mode (copy semantics) and mailbox mode (zero-copy
  buffer aliasing)
- Event objects with IRQ binding, scheduler wake integration, and
  ISR-safe signalling
- Per-module heap with bounded arenas, observable via the provider
  query surface
- Per-module sandboxing at three protection levels (None / Guarded /
  Isolated), MPU-enforced on RP2350 and MMU-enforced on aarch64
- Live graph reconfigure with a four-phase drain protocol
- Demand-paged arenas for workloads larger than physical RAM (aarch64
  targets)
- Platform stack expansion at build time: a config's `platform:`
  section expands into the board-appropriate driver chain
- Hardware-timer ISR tier for hard real-time control, admitted into the
  same scheduler as cooperative modules
- Stream clock vs wall clock separation via `StreamTime` for
  sample-accurate A/V sync
- Validation before deployment: pin conflicts, bus assignments, content
  type compatibility, and resource budgets are checked at config compile
  time

## Supported Targets

Fluxor separates **silicon** (the chip: peripherals, register layout,
CPU architecture) from **boards** (a chip plus a specific PCB layout,
pin assignments, and on-board peripherals). One silicon definition can
back many boards. **Host** targets run the graph inside an existing OS
process.

### Silicon

| Silicon | Architecture | Notes |
|---------|--------------|-------|
| **RP2040** | thumbv6m-none-eabi (Cortex-M0+) | XIP execution |
| **RP2350** | thumbv8m.main-none-eabihf (Cortex-M33) | XIP execution |
| **BCM2712** | aarch64-unknown-none (Cortex-A76) | DRAM-resident, MMU + page tables |
| **ESP32-S3** | xtensa-esp32s3-none-elf | Validation only (no kernel build) |

### Boards and hosts

| Target | Silicon | Notes |
|--------|---------|-------|
| **pico**, **picow** | RP2040 | Raspberry Pi Pico / Pico W |
| **pico2w** | RP2350 | Raspberry Pi Pico 2 W |
| **waveshare-lcd4** | RP2350 | Waveshare board with on-board display and touch |
| **qemu-virt** | BCM2712 | Synthetic aarch64 target for development under QEMU |
| **pi5** | BCM2712 | Raspberry Pi 5, bare metal |
| **linux** | host | Linux userspace runtime for embedded Linux services and simulation |
| **wasm** | host | Browser-instantiated WASM bundle |

Silicon definitions live in `targets/silicon/*.toml`, board definitions
in `targets/boards/*.toml`, and host definitions in
`targets/host/*.toml`. `fluxor inspect` lists every target the checkout
knows about.

## Quick Start

### 1. Prerequisites

- Rust toolchain (stable)
- For RP targets: `arm-none-eabi-objcopy`, `arm-none-eabi-ld`
- For aarch64 targets: `rust-objcopy` (via `cargo install cargo-binutils`)

Install the Rust targets you plan to build:

```bash
rustup target add thumbv8m.main-none-eabihf   # RP2350
rustup target add thumbv6m-none-eabi          # RP2040
rustup target add aarch64-unknown-none        # BCM2712 (pi5 / qemu-virt)
rustup target add aarch64-unknown-linux-gnu   # host tools
```

### 2. Build everything

```bash
make build
```

This builds the `fluxor` CLI, the kernel for every target, every module
palette, and the `fluxor-linux` runtime binary. It is the default goal,
so a bare `make` does the same.

### 3. Build one piece at a time

A single board's kernel image (the Makefile selector is `TARGET`, and it
takes a **board** id — firmware is built per board, modules per silicon):

```bash
make firmware TARGET=pico2w    # boards: pico | picow | pico2w | waveshare-lcd4 | qemu-virt | pi5
make firmware TARGET=wasm      # hosts:  linux | wasm
```

An RP image resolves no third-party runtime crate; the firmware build checks
the dependency closure before the image is written out.

PIC modules, in the target layout consumed by `fluxor build` and
`fluxor run`:

```bash
fluxor modules build --target rp2350
fluxor modules build --all
```

### 4. Run a graph

Linux-hosted configs run directly; the config can be a file or piped
in on stdin:

```bash
fluxor run - <<'EOF'
<a minimal graph — embedded in docs/guides/running.md>
EOF
```

[docs/guides/running.md](docs/guides/running.md) carries the full
embedded config plus bring-up, smoke checks, and shutdown.

Hardware targets build an artefact and flash it, and a packaged
artefact can be built without flashing:

```bash
fluxor flash <config.yaml>
fluxor build <config.yaml>
```

For each target, packaging is driven by the YAML config and the
prebuilt `.fmod` modules: the kernel binary, the module table, and the
validated config blob are assembled into the target's output format.

## CLI Workflow

The host tool is built as `fluxor` and provides packaging and
inspection commands:

```bash
# Project info: root, available targets, stacks
fluxor inspect

# Validate a config against its target, writing nothing
fluxor build --check <config.yaml>

# Build one YAML config into the target-specific artefact
fluxor build <config.yaml>

# Build the PIC modules a config names, then pack an ELF by hand
fluxor modules build --target bcm2712
fluxor modules pack <module.elf> -o <module.fmod> -n <name> -t <module_type>

# Inspect a built artefact (or a store reference)
fluxor inspect <file.uf2>
fluxor inspect <file.uf2> --emit-config

# Show what changes between two configs (live-reconfigure planning)
fluxor inspect <new.yaml> --against <old.yaml>
```

Publishing artefacts into the local OCI store, and consuming them from
a downstream project, is covered in
[docs/guides/publishing.md](docs/guides/publishing.md).

## Repository Layout

```text
fluxor/
├── src/                # Kernel: scheduler, syscalls, channels, events, loader, HAL
│   ├── kernel/         # Cooperative scheduler, IPC, loader, fault recovery
│   └── platform/       # Per-target runtime and HAL backends
├── modules/            # Position-independent modules
│   ├── sdk/            # Shared SDK: ABI, runtime, params
│   ├── drivers/        # Hardware drivers (cyw43, enc28j60, nvme, st7701s, ...)
│   ├── foundation/     # Portable services (ip, fat32, dns, tls, quic, ...)
│   ├── platform/       # Dual-context platform tables shared with the kernel
│   └── fixtures/       # Probe and demo modules for protocol surfaces
├── crates/             # Host-side crates: fluxor-abi, fluxor-sdk, fluxor-launcher
├── contracts/          # Capability contract definitions
├── tools/              # Host CLI: validate, build, run, flash, pack, sign, inspect
├── stacks/             # Reusable stack fragments referenced by configs
├── targets/            # Silicon, board, and host definitions
├── firmware/           # Vendored peripheral firmware blobs (CYW43)
└── docs/               # Architecture references and guides
```

Media assets live beside the module that consumes them
(`modules/<area>/<module>/assets/`); there is no central asset pool.
Browser-runtime code (`runtime.html`, `host_shims.js`,
`endpoint_runtime.js`) lives at `src/platform/wasm/host/`.

## Documentation

Start with [docs/overview.md](docs/overview.md) for the documentation
index.

Recommended reading path:

1. [docs/guides/running.md](docs/guides/running.md) — bring a graph up on the Linux host
2. [docs/architecture/pipeline.md](docs/architecture/pipeline.md) — graph runner, channels, scheduler, mailbox mode
3. [docs/architecture/module_architecture.md](docs/architecture/module_architecture.md) — module contract, lifecycle, fault recovery
4. [docs/architecture/hal_architecture.md](docs/architecture/hal_architecture.md) — kernel/module split and per-silicon HAL
5. [docs/architecture/abi_layers.md](docs/architecture/abi_layers.md) — ABI layers, contract inventory, provider dispatch
6. [docs/architecture/network.md](docs/architecture/network.md) — channel-based networking and net_proto
7. [docs/architecture/capability_surface.md](docs/architecture/capability_surface.md) — capability vocabulary and resolution
8. [docs/vision.md](docs/vision.md) — the capability-centric argument

## License

Apache-2.0
