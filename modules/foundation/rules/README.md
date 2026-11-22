# rules Module

Rules Engine PIC Module

## Files

- `manifest.toml`
- `mod.rs`

## Interface

| Port | Direction | Content type | |
|---|---|---|---|
| `sensor` | input | `OctetStream` |  |
| `alarm` | output | `OctetStream` |  |

Builds for: `rp2350`. [manifest.toml](manifest.toml) is the declaration.

## Parameters

- `high_threshold`
- `low_threshold`
- `topic`
