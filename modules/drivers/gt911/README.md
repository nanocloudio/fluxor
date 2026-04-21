# gt911 Module

GT911 Capacitive Touch Controller PIC Module

## Files

- `manifest.toml`
- `mod.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "touch"
direction = "output"
content_type = "InputEvent"
required = true

[[resources]]
requires_contract = "i2c"
access = "exclusive"

[[resources]]
requires_contract = "gpio"
access = "write"

[[resources]]
requires_contract = "event"
access = "write"

[[resources]]
requires_contract = "timer"
access = "write"
```

## Parameters

- `addr`
- `i2c_bus`
- `int_pin`
- `rst_pin`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
