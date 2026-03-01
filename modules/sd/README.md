# sd Module

SD Card PIC Module

Detailed design notes are in [DESIGN.md](./DESIGN.md).

## Files

- `manifest.toml`
- `mod.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "blocks"
direction = "output"
content_type = "OctetStream"
required = true

[[resources]]
device_class = "spi"
access = "exclusive"

[[resources]]
device_class = "gpio"
access = "write"

[[resources]]
device_class = "timer"
access = "write"
```

## Parameters

- `block_count`
- `cs_pin`
- `spi_bus`
- `start_block`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
