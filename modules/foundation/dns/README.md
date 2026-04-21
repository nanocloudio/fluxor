# dns Module

DNS Server PIC Module

## Files

- `manifest.toml`
- `mod.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[resources]]
requires_contract = "socket"
access = "write"
```

## Parameters

- `host`
- `port`
- `ttl`
- `upstream`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
