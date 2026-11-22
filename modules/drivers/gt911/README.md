# gt911 Module

GT911 Capacitive Touch Controller PIC Module

## Files

- `manifest.toml`
- `mod.rs`

## Interface

| Port | Direction | Content type | |
|---|---|---|---|
| `touch` | output | `InputEvent` | required |

Builds for: `rp2350`. [manifest.toml](manifest.toml) is the declaration.

## Parameters

- `addr`
- `i2c_bus`
- `int_pin`
- `rst_pin`
