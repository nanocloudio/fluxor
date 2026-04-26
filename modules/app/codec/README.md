# codec Module

Unified essence decoder for the rp2350 target. Dispatches at runtime
between audio-essence sub-codecs (`wav_codec`, `mp3_codec`, `aac_codec`)
and image-essence (`image_codec`) by sniffing the encoded payload's
container/magic.

## Surface contract

The output ports follow the canonical AV surface family:

- `audio` — `AudioSample` (decoded sample-domain audio)
- `pixels` — `VideoRaster` (decoded pixel-domain frames)

The input port is `OctetStream` because format detection happens inside
the module; per-essence wrapper splits are an implementation detail of
the runtime dispatcher in `mod.rs`. A graph that only needs one output
side simply leaves the other unwired.

## Files

- `manifest.toml`
- `mod.rs` — entry, format sniff, sub-codec dispatch
- `aac_codec.rs` — AudioSample producer (AAC)
- `mp3_codec.rs` — AudioSample producer (MP3)
- `wav_codec.rs` — AudioSample producer (WAV / PCM)
- `image_codec.rs` — VideoRaster producer (JPEG / PNG)

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
content_type = "AudioSample"

[[ports]]
name = "pixels"
direction = "output"
content_type = "VideoRaster"
```

## Parameters

- No TLV parameter tags detected in module source.

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
