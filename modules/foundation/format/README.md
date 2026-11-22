# format Module

Format PIC Module

## Files

- `manifest.toml`
- `mod.rs`

## Interface

| Port | Direction | Content type | |
|---|---|---|---|
| `raw_audio` | input | `OctetStream` | required |
| `audio` | output | `AudioSample` | required |

Builds for: `rp2350`. [manifest.toml](manifest.toml) is the declaration.

## Parameters

- `dither`
- `input_bits`
- `input_channels`
- `input_rate`
- `output_rate`
