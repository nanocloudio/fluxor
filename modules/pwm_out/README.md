# pwm_out Module

PWM Output PIC Module

## Files

- `manifest.toml`
- `mod.rs`
- `params_def.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "brightness"
direction = "input"
content_type = "OctetStream"
required = true

[[resources]]
device_class = "pwm"
access = "exclusive"
```

## Parameters

- `pin`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
