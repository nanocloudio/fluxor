# st7701s Module

ST7701S Display Driver PIC Module

## Files

- `manifest.toml`
- `mod.rs`
- `init_seq.rs`
- `pio_programs.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "pixels"
direction = "input"
content_type = "VideoRaster"
required = false

[[resources]]
requires_contract = "gpio"
access = "write"

[[resources]]
requires_contract = "pio"
access = "exclusive"

[[resources]]
requires_contract = "timer"
access = "write"
```

## Parameters

- `bl_pin`
- `cs_pin`
- `data0_pin`
- `de_pin`
- `height`
- `hsync_pin`
- `mirror_x`
- `pclk_pin`
- `pio_data`
- `pio_sync`
- `rst_pin`
- `sck_pin`
- `sda_pin`
- `source_rows`
- `vsync_pin`
- `width`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
