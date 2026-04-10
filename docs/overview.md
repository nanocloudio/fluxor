# Fluxor Documentation

Fluxor is a composable runtime that replaces threads and processes with
a deterministic module graph. Systems are assembled as explicitly wired
position-independent modules connected by typed channels and executed in
topological order by a cooperative scheduler. The runtime distinguishes
wall-clock time from stream-clock time, enabling predictable pipelines
for audio, display, control, networking, storage, consensus, and compute
workloads — across microcontrollers, application processors, and
server-class hardware.

Fluxor is one half of a larger vision. The mesh surface provides the
distributed object model — stable, capability-bearing objects addressable
without assuming where they run. Fluxor provides the deterministic local
execution. Together they point toward a computing model in which physical
device boundaries become implementation details rather than architectural
constraints.

## Start Here

- [vision.md](vision.md) — the mesh-native computing model and why it matters
- [architecture/pipeline.md](architecture/pipeline.md) — graph runner, channels, and execution model
- [architecture/module_architecture.md](architecture/module_architecture.md) — module contract, step semantics, composition rules
- [architecture/hal_architecture.md](architecture/hal_architecture.md) — kernel/module split, syscall ABI, per-silicon HAL

## Architecture

How the system works. These are the authoritative references.

- [architecture/pipeline.md](architecture/pipeline.md) — graph runner, channels, FIFO and mailbox IPC, execution model
- [architecture/module_architecture.md](architecture/module_architecture.md) — module lifecycle, step contract, fault recovery, drain protocol
- [architecture/timing.md](architecture/timing.md) — stream clock vs wall clock, StreamTime, producer scheduling
- [architecture/hal_architecture.md](architecture/hal_architecture.md) — HAL boundaries, syscall table, kernel/module split, per-silicon HAL
- [architecture/device_classes.md](architecture/device_classes.md) — device class system, opcode namespaces, `dev_call`/`dev_query`
- [architecture/events.md](architecture/events.md) — event objects, IRQ binding, scheduler wake, ISR safety contract
- [architecture/capability_surface.md](architecture/capability_surface.md) — capability resolution, auto-wiring, hardware abstraction
- [architecture/network.md](architecture/network.md) — channel-based networking, net_proto, drivers, IP module, TLS
- [architecture/heap.md](architecture/heap.md) — per-module heap allocation
- [architecture/reconfigure.md](architecture/reconfigure.md) — live graph reconfigure, drain protocol
- [architecture/mesh.md](architecture/mesh.md) — mesh architecture: identity, authority, discovery, events, binding
- [architecture/network_boot.md](architecture/network_boot.md) — stateless network boot, fleet deployment, trust model
- [architecture/pin_allocation.md](architecture/pin_allocation.md) — GPIO allocation, pin validation, peripheral assignments

## Guides

How to build things with the system. Domain-specific patterns and recipes.

- [guides/audio.md](guides/audio.md) — audio pipeline architecture and format handling
- [guides/music_player.md](guides/music_player.md) — music-player pipeline and track control model
- [guides/input_system.md](guides/input_system.md) — input actions, controls, and dispatch
- [guides/input_gestures.md](guides/input_gestures.md) — gesture recognition and command bindings
- [guides/asset_banks.md](guides/asset_banks.md) — banks, cursors, and control mapping
- [guides/midi.md](guides/midi.md) — MIDI event handling and synthesis composition
- [guides/displays.md](guides/displays.md) — display/touch configuration and pixel pipeline
- [guides/foundation.md](guides/foundation.md) — foundation layer, driver/foundation boundary, contract patterns
- [guides/compute_heavy_modules.md](guides/compute_heavy_modules.md) — patterns for emulators, codecs, and compute-intensive workloads

## Modules

Module documentation is colocated with each module implementation under
[modules/](../modules/). Each module's `mod.rs` is the authoritative
source for its parameters, channel hints, and capability flags. Modules
with non-trivial state machines or substantial protocol logic include
explanatory comments at the top of their source.
