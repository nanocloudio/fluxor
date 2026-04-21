# enc28j60 Module

ENC28J60 Ethernet Frame Provider PIC Module

## Files

- `manifest.toml`
- `mod.rs`
- `constants.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "frames_tx"
direction = "input"
content_type = "EthernetFrame"

[[ports]]
name = "frames_rx"
direction = "output"
content_type = "EthernetFrame"
required = true

[[resources]]
requires_contract = "spi"
access = "exclusive"

[[resources]]
requires_contract = "gpio"
access = "write"
```

## Parameters

- `cs_pin`
- `int_pin`
- `spi_bus`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
