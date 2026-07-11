# dns Module

DNS Server PIC Module

## Files

- `manifest.toml`
- `mod.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

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

- `host`
- `port`
- `ttl`
- `upstream`
- `upstream_port` (destination port for forwarded queries, default 53 —
  lets a delegation listener on a non-standard port be the upstream)

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
