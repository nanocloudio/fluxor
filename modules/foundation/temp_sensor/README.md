# temp_sensor Module

Temperature Sensor PIC Module

## Files

- `manifest.toml`
- `mod.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "reading"
direction = "output"
content_type = "OctetStream"

[[resources]]
requires_contract = "adc"
access = "read"
```

## Parameters

- `interval_ms`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
