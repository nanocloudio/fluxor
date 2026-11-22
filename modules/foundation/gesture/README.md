# gesture Module

Gesture PIC Module

## Files

- `manifest.toml`
- `mod.rs`

## Interface

| Port | Direction | Content type | |
|---|---|---|---|
| `raw` | input | `OctetStream` | required |
| `commands` | output | `FmpMessage` | required |

Builds for: `rp2350`, `bcm2712`, `wasm`, `linux`, `rp2040`. [manifest.toml](manifest.toml) is the declaration.

## Parameters

- `click`
- `double_click`
- `long_press`
- `long_press_ms`
- `mode`
- `multi_click_ms`
- `triple_click`
