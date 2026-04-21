# file_source Module

File Source Module - Stream audio from file

## Files

- `manifest.toml`
- `mod.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "audio"
direction = "output"
content_type = "AudioPcm"
required = true

[[resources]]
requires_contract = "fs"
access = "read"
```

## Parameters

- `bits`
- `channels`
- `loop_mode`
- `sample_rate`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
