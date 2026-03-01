# rules Module

Rules Engine PIC Module

## Files

- `manifest.toml`
- `mod.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "sensor"
direction = "input"
content_type = "OctetStream"

[[ports]]
name = "alarm"
direction = "output"
content_type = "OctetStream"
```

## Parameters

- `high_threshold`
- `low_threshold`
- `topic`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
