# Fluxor Documentation

Fluxor is a composable runtime that replaces threads and processes with
a deterministic module graph. Systems are assembled as explicitly wired
position-independent modules connected by typed channels and executed
in topological order by a cooperative scheduler. The runtime
distinguishes wall-clock time from stream-clock time, giving
predictable pipelines for audio, display, control, networking, storage,
consensus, and compute workloads across microcontrollers, application
processors, Linux-hosted runs, and browser-hosted WASM bundles.

## Start Here

- [guides/running.md](guides/running.md) — bring a graph up on the Linux host, config included
- [architecture/pipeline.md](architecture/pipeline.md) — graph runner, channels, and execution model
- [architecture/module_architecture.md](architecture/module_architecture.md) — module contract, step semantics, composition rules
- [vision.md](vision.md) — the capability-centric argument and where the model is headed

## Architecture

How the system works. These are the authoritative references.

- [architecture/pipeline.md](architecture/pipeline.md) — graph runner, channels, FIFO and mailbox IPC, burst stepping, capacity profiles
- [architecture/module_architecture.md](architecture/module_architecture.md) — module lifecycle, step contract, fault recovery, drain protocol
- [architecture/scheduler.md](architecture/scheduler.md) — execution tiers, ISR-tier admission and I/O contract, domain loops
- [architecture/concurrency.md](architecture/concurrency.md) — what is shared, what is domain-local, and why it is safe
- [architecture/timing.md](architecture/timing.md) — stream clock vs wall clock, StreamTime, producer scheduling
- [architecture/events.md](architecture/events.md) — event objects, IRQ binding, scheduler wake, ISR safety contract
- [architecture/heap.md](architecture/heap.md) — per-module heap allocation and observability
- [architecture/reconfigure.md](architecture/reconfigure.md) — live graph reconfigure and the drain-then-reset model
- [architecture/hal_architecture.md](architecture/hal_architecture.md) — kernel/module split, syscall table, per-silicon HAL
- [architecture/abi_layers.md](architecture/abi_layers.md) — ABI layers, contract inventory, provider dispatch, permissions
- [architecture/abi_surface.md](architecture/abi_surface.md) — the ABI-surface digest, artefact provenance digests, and how a surface change propagates
- [architecture/limit_register.md](architecture/limit_register.md) — the register of hard capacity ceilings and their defining constants
- [architecture/capability_surface.md](architecture/capability_surface.md) — capability vocabulary, content-type registry, platform stack expansion, validation
- [architecture/storage_capability_surface.md](architecture/storage_capability_surface.md) — block, file, namespace, and object surfaces; fences; multi-volume routing
- [architecture/endpoint_capability_surface.md](architecture/endpoint_capability_surface.md) — remote presentation endpoints and the browser endpoint runtime
- [architecture/input_capability_surface.md](architecture/input_capability_surface.md) — input surfaces, payload contracts, mapper discipline
- [architecture/av_capability_surface.md](architecture/av_capability_surface.md) — audio/video surfaces, presentation groups, clock authority
- [architecture/browser_capability_surface.md](architecture/browser_capability_surface.md) — the browser as a capability provider
- [architecture/wasm_platform.md](architecture/wasm_platform.md) — the WASM target: bundle format, entry points, host imports
- [architecture/wasm_browser_host.md](architecture/wasm_browser_host.md) — the browser host runtime and its built-in modules
- [architecture/network.md](architecture/network.md) — channel-based networking, net_proto, drivers, IP module, TLS
- [architecture/datagram_secure_transports.md](architecture/datagram_secure_transports.md) — DTLS 1.3 and QUIC v1 on the datagram surface
- [architecture/protocol_surfaces.md](architecture/protocol_surfaces.md) — datagram, packet, mux, and session-control contracts; continuity classes
- [architecture/network_boot.md](architecture/network_boot.md) — OTA graph delivery: graph images, registry pull, staging, activation
- [architecture/mesh.md](architecture/mesh.md) — the mesh architecture: distributed objects, capability-based authority, events, leases
- [architecture/security.md](architecture/security.md) — trust root, module signing, KEY_VAULT, network hardening
- [architecture/pin_allocation.md](architecture/pin_allocation.md) — GPIO allocation, pin validation, peripheral assignments
- [architecture/owner_status.md](architecture/owner_status.md) — per-owner live status and `owner_status.json`
- [architecture/monitor-protocol.md](architecture/monitor-protocol.md) — the monitor record stream and its vocabularies

## Guides

How to build and run things with the system.

- [guides/running.md](guides/running.md) — the simplest validated bring-up, config embedded
- [guides/publishing.md](guides/publishing.md) — publishing artefacts into the local OCI store, consuming them downstream, and keeping the store itself (pins, quarantine, collection)
- [guides/foundation.md](guides/foundation.md) — foundation layer, driver/foundation boundary, contract patterns
- [guides/audio.md](guides/audio.md) — audio pipeline architecture and format handling
- [guides/music_player.md](guides/music_player.md) — music-player pipeline and track control model
- [guides/asset_banks.md](guides/asset_banks.md) — banks, cursors, and control mapping
- [guides/input_system.md](guides/input_system.md) — input actions, controls, and dispatch
- [guides/input_gestures.md](guides/input_gestures.md) — gesture recognition and command bindings
- [guides/displays.md](guides/displays.md) — display/touch configuration and pixel pipeline
- [guides/midi.md](guides/midi.md) — the MIDI transport surface and synthesis composition
- [guides/compute_heavy_modules.md](guides/compute_heavy_modules.md) — patterns for emulators, codecs, and compute-intensive workloads

## Modules

Module documentation is colocated with each module implementation under
[modules/](../modules/). Each module's `mod.rs` is the authoritative
source for its parameters, channel hints, and capability flags.
