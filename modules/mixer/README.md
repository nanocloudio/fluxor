# mixer Module

Mixer Channel Strip PIC Module

## Files

- `manifest.toml`
- `mod.rs`
- `eq.rs`
- `params.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "audio"
direction = "input"
content_type = "AudioPcm"
required = true

[[ports]]
name = "mixed"
direction = "output"
content_type = "AudioPcm"
required = true

[[ports]]
name = "control"
direction = "ctrl_input"
content_type = "InputEvent"
```

## Parameters

- `eq_high_freq`
- `eq_high_gain`
- `eq_low_freq`
- `eq_low_gain`
- `eq_mid_freq`
- `eq_mid_gain`
- `eq_mid_q`
- `gain_in`
- `gain_out`
- `pan`
- `sample_rate`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
