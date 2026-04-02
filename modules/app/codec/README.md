# decoder Module

Unified Audio Decoder PIC Module

## Files

- `manifest.toml`
- `mod.rs`
- `aac_codec.rs`
- `mp3_codec.rs`
- `wav_codec.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "encoded"
direction = "input"
content_type = "OctetStream"
required = true

[[ports]]
name = "audio"
direction = "output"
content_type = "AudioPcm"
required = true
```

## Parameters

- No TLV parameter tags detected in module source.

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
