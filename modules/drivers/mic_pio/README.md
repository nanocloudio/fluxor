# mic_source Module

Microphone Source PIC Module (I2S RX via PIO)

## Files

- `manifest.toml`
- `mod.rs`
- `pio.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "audio"
direction = "output"
content_type = "AudioPcm"

[[resources]]
requires_contract = "pio"
access = "read"
instance = 0
```

## Parameters

- `clock_base`
- `in_pin`
- `sample_rate`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
