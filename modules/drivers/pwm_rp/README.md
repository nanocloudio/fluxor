# pwm Module

PWM Provider PIC Module

## Files

- `manifest.toml`
- `mod.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]
permissions = ["platform_raw"]

[[resources]]
requires_contract = "gpio"
access = "exclusive"

[[resources]]
requires_contract = "pwm"
access = "exclusive"
```

## Parameters

- No TLV parameter tags detected in module source.

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
