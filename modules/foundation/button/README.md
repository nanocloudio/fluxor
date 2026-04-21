# button Module

Button PIC Module

## Files

- `manifest.toml`
- `mod.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "raw"
direction = "output"
content_type = "OctetStream"

[[resources]]
requires_contract = "gpio"
access = "read"
```

## Parameters

- `active_low`
- `control_id`
- `pin`
- `pull`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
