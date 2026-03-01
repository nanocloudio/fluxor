# gesture Module

Gesture PIC Module

## Files

- `manifest.toml`
- `mod.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "raw"
direction = "input"
content_type = "OctetStream"
required = true

[[ports]]
name = "commands"
direction = "output"
content_type = "FmpMessage"
required = true

[commands]
emits = ["next", "prev", "toggle", "select", "long_press", "on", "off"]
```

## Parameters

- `click`
- `double_click`
- `long_press`
- `long_press_ms`
- `mode`
- `multi_click_ms`
- `triple_click`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
