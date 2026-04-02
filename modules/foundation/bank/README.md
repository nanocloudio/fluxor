# bank Module

Asset Bank PIC Module (Seekable Version)

## Files

- `manifest.toml`
- `mod.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "files"
direction = "input"
content_type = "OctetStream"
required = true

[[ports]]
name = "stream"
direction = "output"
content_type = "OctetStream"
required = true

[[ports]]
name = "notify"
index = 1
direction = "output"
content_type = "FmpMessage"

[[ports]]
name = "commands"
direction = "ctrl_input"
content_type = "FmpMessage"

[commands]
accepts = ["next", "prev", "toggle", "select"]
emits = ["status"]
```

## Parameters

- `auto_advance`
- `file_count`
- `initial_index`
- `mode`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
