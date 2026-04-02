# mesh Module

Module documentation for mesh.

## Files

- `manifest.toml`
- `mod.rs`
- `mesh_types.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "mqtt_rx"
direction = "input"
content_type = "OctetStream"
required = true

[[ports]]
name = "notify"
index = 1
direction = "input"
content_type = "FmpMessage"

[[ports]]
name = "mqtt_tx"
direction = "output"
content_type = "OctetStream"
required = true

[[ports]]
name = "commands"
direction = "ctrl_output"
content_type = "FmpMessage"

[commands]
accepts = ["status"]
emits = ["next", "prev", "toggle", "select"]
```

## Parameters

- No TLV parameter tags detected in module source.

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
