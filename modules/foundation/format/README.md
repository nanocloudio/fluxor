# format Module

Format PIC Module

## Files

- `manifest.toml`
- `mod.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "raw_audio"
direction = "input"
content_type = "OctetStream"
required = true

[[ports]]
name = "audio"
direction = "output"
content_type = "AudioSample"
required = true
```

## Parameters

- `dither`
- `input_bits`
- `input_channels`
- `input_rate`
- `output_rate`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
