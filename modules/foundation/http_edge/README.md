# http Module

HTTP Source PIC Module

## Files

- `manifest.toml`
- `mod.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "data"
direction = "output"
content_type = "OctetStream"
required = true

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

- `host_ip`
- `path`
- `port`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
