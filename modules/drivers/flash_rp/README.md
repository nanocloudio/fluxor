# flash Module

Flash Module — BOOTSEL Button + Blob Serving + Runtime Parameter Store

## Files

- `manifest.toml`
- `mod.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]
permissions = ["flash_raw", "backing_provider"]

[[ports]]
name = "events"
direction = "output"
content_type = "FmpMessage"

[[ports]]
name = "stream"
index = 1
direction = "output"
content_type = "OctetStream"

[commands]
emits = ["toggle", "next", "prev", "long_press", "on", "off"]
```

## Parameters

- `click`
- `debounce_ms`
- `double_click`
- `item_count`
- `long_press_cmd`
- `long_press_ms`
- `mode`
- `multi_click_ms`
- `presets`
- `triple_click`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
