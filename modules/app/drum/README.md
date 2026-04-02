# drum Module

Drum PIC Module

## Files

- `manifest.toml`
- `mod.rs`
- `params_def.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "pattern"
direction = "input"
content_type = "OctetStream"

[[ports]]
name = "audio"
direction = "output"
content_type = "AudioPcm"
required = true
```

## Parameters

- `hat_decay`
- `kick_decay`
- `kick_pitch`
- `level`
- `sample_rate`
- `snare_decay`
- `snare_tone`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
