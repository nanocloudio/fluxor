# mic_source Module

Microphone Source PIC Module (I2S RX via PIO)

## Files

- `manifest.toml`
- `mod.rs`
- `pio.rs`

## Interface

| Port | Direction | Content type | |
|---|---|---|---|
| `audio` | output | `AudioSample` |  |

Builds for: `rp2350`. [manifest.toml](manifest.toml) is the declaration.

## Parameters

- `clock_base`
- `in_pin`
- `sample_rate`
