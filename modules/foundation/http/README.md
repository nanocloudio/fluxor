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

[[resources]]
requires_contract = "socket"
access = "write"
```

## Parameters

- `host_ip`
- `path`
- `port`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
