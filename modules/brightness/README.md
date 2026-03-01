# brightness Module

Brightness PIC Module

## Files

- `manifest.toml`
- `mod.rs`
- `params_def.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "source"
direction = "input"
content_type = "OctetStream"
required = true

[[ports]]
name = "level"
direction = "output"
content_type = "OctetStream"
required = true
```

## Parameters

- `attack`
- `curve`
- `mode`
- `output_divider`
- `release`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
