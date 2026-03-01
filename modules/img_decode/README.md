# img_decode Module

Image Decoder PIC Module

## Files

- `manifest.toml`
- `mod.rs`
- `bmp_codec.rs`
- `jpeg_codec.rs`
- `scale.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "data"
direction = "input"
content_type = "OctetStream"
required = true

[[ports]]
name = "pixels"
direction = "output"
content_type = "ImageRaw"
required = true
```

## Parameters

- `bg_color`
- `decode_scale`
- `height`
- `scale_mode`
- `width`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
