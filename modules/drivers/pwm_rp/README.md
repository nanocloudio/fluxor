# pwm Module

PWM Provider PIC Module

## Files

- `manifest.toml`
- `mod.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[resources]]
device_class = "gpio"
access = "exclusive"

[[resources]]
device_class = "system"
access = "exclusive"

[[resources]]
device_class = "pwm"
access = "exclusive"
```

## Parameters

- No TLV parameter tags detected in module source.

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
