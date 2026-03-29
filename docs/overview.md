# Fluxor Documentation

Fluxor is a composable firmware runtime that replaces threads and processes with
a deterministic module graph. Systems are assembled as explicitly wired modules
connected by typed channels, executed in topological order by a cooperative
scheduler. The runtime distinguishes wall-clock time from stream-clock time,
enabling predictable pipelines for audio, display, control, networking, and
compute workloads — from microcontrollers to application processors.

Fluxor is one half of a larger vision. The mesh surface provides the distributed
object model — stable, capability-bearing objects addressable without assuming
where they run. Fluxor provides the deterministic local execution. Together they
point toward a computing model in which physical device boundaries become
implementation details rather than architectural constraints.

## Start Here

- `vision.md` — the mesh-native computing model and why it matters
- `architecture/mesh.md` — the eight irreducible mesh primitives
- `architecture/pipeline.md` — graph runner, channels, and execution model
- `architecture/module_architecture.md` — module contract, step semantics, composition rules

## Architecture

How the system works. These are the authoritative references.

- `architecture/pipeline.md` — graph runner, channels, FIFO and mailbox IPC, execution model
- `architecture/module_architecture.md` — module lifecycle, step contract, backpressure, timing rules
- `architecture/timing.md` — stream clock vs wall clock, StreamTime, producer scheduling
- `architecture/hal_architecture.md` — HAL boundaries, syscall table, kernel/module split
- `architecture/device_classes.md` — device class system, opcode namespaces, dev_call/dev_query
- `architecture/events.md` — event objects, IRQ binding, scheduler wake, ISR safety contract
- `architecture/capability_surface.md` — capability resolution, auto-wiring, hardware abstraction
- `architecture/network.md` — networking: WiFi HAL, TCP/UDP (smoltcp), netif registry
- `architecture/mesh.md` — mesh architecture: identity, authority, discovery, events, binding
- `architecture/network_boot.md` — stateless network boot, fleet deployment, trust model
- `architecture/pin_allocation.md` — GPIO allocation, pin validation, peripheral assignments

## Guides

How to build things with the system. Domain-specific patterns and recipes.

- `guides/audio.md` — audio pipeline architecture and format handling
- `guides/music_player.md` — music-player pipeline and track control model
- `guides/input_system.md` — input actions, controls, and dispatch
- `guides/input_gestures.md` — gesture recognition and command bindings
- `guides/asset_banks.md` — banks, cursors, and control mapping
- `guides/midi.md` — MIDI event handling and synthesis composition
- `guides/displays.md` — display/touch configuration and pixel pipeline
- `guides/services.md` — service-layer architecture and driver/service boundary
- `guides/compute_heavy_modules.md` — patterns for emulators, codecs, and compute-intensive workloads

## Modules

Module documentation is colocated with each module implementation:

- `modules/*/README.md` — module summary, manifest interface, parameters, and file map
- `modules/sd/DESIGN.md` — SD state machine deep dive
- `modules/effects/DESIGN.md` — effects taxonomy and presets
