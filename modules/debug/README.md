# debug Module

Debug PIC Module

## Files

- `manifest.toml`
- `mod.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "data"
direction = "input"
content_type = "OctetStream"
required = true
```

## Parameters

- `log_level`
- `mode`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
