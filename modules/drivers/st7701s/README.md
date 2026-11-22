# st7701s Module

ST7701S Display Driver PIC Module

## Files

- `manifest.toml`
- `mod.rs`
- `init_seq.rs`
- `pio_programs.rs`

## Interface

| Port | Direction | Content type | |
|---|---|---|---|
| `pixels` | input | `VideoRaster` |  |

Builds for: `rp2350`. [manifest.toml](manifest.toml) is the declaration.

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
