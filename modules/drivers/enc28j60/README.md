# enc28j60 Module

ENC28J60 Ethernet Frame Provider PIC Module

## Files

- `manifest.toml`
- `mod.rs`
- `constants.rs`

## Interface

| Port | Direction | Content type | |
|---|---|---|---|
| `frames_tx` | input | `EthernetFrame` |  |
| `frames_rx` | output | `EthernetFrame` | required |

Builds for: `rp2040`, `rp2350`. [manifest.toml](manifest.toml) is the declaration.

## Parameters

- `cs_pin`
- `int_pin`
- `spi_bus`
