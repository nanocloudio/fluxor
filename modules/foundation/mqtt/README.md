# mqtt Module

Module documentation for mqtt.

## Files

- `manifest.toml`
- `mod.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "mesh_rx"
direction = "input"
content_type = "OctetStream"

[[ports]]
name = "mesh_tx"
direction = "output"
content_type = "OctetStream"

# Network transport: wired to the IP / transport stack via NetProto.
[[ports]]
name = "net_in"
direction = "input"
content_type = "NetProto"

[[ports]]
name = "net_out"
direction = "output"
content_type = "NetProto"
```

## Parameters

- `broker_ip`
- `broker_port`
- `client_id`
- `keepalive_s`
- `publish_topic`
- `subscribe_topic`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
