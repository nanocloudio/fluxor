# i2s Module

I2S PIC Module

## Files

- `manifest.toml`
- `mod.rs`
- `params_def.rs`
- `pio.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "audio"
direction = "input"
content_type = "AudioPcm"
required = true

[[resources]]
requires_contract = "pio"
access = "exclusive"
instance = 0

[[resources]]
requires_contract = "gpio"
access = "write"
```

## Parameters

- `clock_base`
- `data_pin`
- `sample_rate`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
