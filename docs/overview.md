# Fluxor Documentation (v1)

Start here. This overview provides a clean map of the docs as they exist today,
organized for quick onboarding and realistic implementation alignment.

## Architecture

- `architecture/pipeline.md` — graph runner, channels, and execution model
- `architecture/module_architecture.md` — module roles, composition, and control principles
- `architecture/timing.md` — stream clock vs wall clock timing rules
- `architecture/hal_architecture.md` — HAL boundaries and syscall surface
- `architecture/device_classes.md` — device class system, opcode namespaces, dev_call/dev_query
- `architecture/events.md` — event objects, IRQ binding, scheduler wake (drivers outside kernel)
- `architecture/network.md` — networking: WiFi HAL, TCP/UDP (smoltcp), netif registry
- `architecture/mesh.md` — mesh architecture model
- `architecture/pin_allocation.md` — GPIO / pin usage

## Reference Maps

- `specs/module_spec.md` — index to module architecture references
- `specs/module_invariants.md` — index to invariants references
- `specs/graph_config.md` — index to graph configuration references

## Guides

- `guides/audio.md` — audio building blocks and formats
- `guides/music_player.md` — music-player pipeline and control model
- `guides/input_system.md` — input actions, controls, and dispatch
- `guides/input_gestures.md` — gesture recognition and bindings
- `guides/asset_banks.md` — banks, cursors, and control mapping
- `guides/midi.md` — MIDI support and asset integration
- `guides/displays.md` — display/touch configuration and events
- `guides/services.md` — service abstraction boundaries
- `guides/compute_heavy_modules.md` — patterns for emulators, codecs, and compute-intensive workloads

## Formats

- `formats/led_subtitle_format.md` — LED subtitle file format
- `formats/spi_device_streaming.md` — SPI streaming format notes

## Modules

- Module documentation is now colocated with each module implementation:
  - `modules/*/README.md` — module summary, manifest interface, parameters, and file map
  - `modules/sd/DESIGN.md` — SD state machine deep dive
  - `modules/effects/DESIGN.md` — effects taxonomy and presets

## Legacy / proposals

These are retained for reference but are not the canonical v1 docs:
- `legacy/generic_pipeline_refactor.md`
- `legacy/input_system_refactor.md`
- `legacy/module_architecture_future.md`
- `legacy/module_manifest_design.md`
- `legacy/modular_network_architecture.md`
- `legacy/network_architecture.md`
- `legacy/dynamic_linking.md`
- `legacy/pin_allocation_migration.md`
