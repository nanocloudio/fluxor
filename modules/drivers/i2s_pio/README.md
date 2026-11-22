# i2s Module

I2S PIC Module

## Files

- `manifest.toml`
- `mod.rs`
- `params_def.rs`
- `pio.rs`

## Interface

| Port | Direction | Content type | |
|---|---|---|---|
| `audio` | input | `AudioSample` | required |

Builds for: `rp2350`. [manifest.toml](manifest.toml) is the declaration.

## Parameters

- `clock_base`
- `data_pin`
- `sample_rate`
