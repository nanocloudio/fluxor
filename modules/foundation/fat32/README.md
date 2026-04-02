# fat32 Module

FAT32 PIC Module

## Files

- `manifest.toml`
- `mod.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "blocks"
direction = "input"
content_type = "OctetStream"
required = true

[[ports]]
name = "files"
direction = "output"
content_type = "OctetStream"
required = true

[[ports]]
name = "seek"
direction = "ctrl_input"
content_type = "OctetStream"
```

## Parameters

- `path`
- `pattern`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
