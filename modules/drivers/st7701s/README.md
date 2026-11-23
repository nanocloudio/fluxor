# st7701s Module

ST7701S RGB-parallel panel, drawn from a draw list and scanned out a band at a time

## Files

- `manifest.toml`
- `mod.rs`
- `init_seq.rs`
- `pio_programs.rs`

## Interface

| Port | Direction | Content type | |
|---|---|---|---|
| `draw` | input | `VideoDraw` | retained and drawn again every refresh |
| `surface0` | input | `VideoRaster` | placed by SURFACE records; shown scaled when `draw` is not wired |

Builds for: `rp2350`. [manifest.toml](manifest.toml) is the declaration.

## Parameters

- `band_rows`
- `bl_pin`
- `cs_pin`
- `data0_pin`
- `de_pin`
- `frame_bytes`
- `height`
- `hsync_pin`
- `mirror_x`
- `pack0`
- `pack1`
- `pack2`
- `pack3`
- `pclk_max_khz`
- `pclk_pin`
- `pio_data`
- `pio_sync`
- `record_bytes`
- `refresh_mhz`
- `resource_bytes`
- `ring_rows`
- `rst_pin`
- `sck_pin`
- `sda_pin`
- `status_s`
- `surface_bytes`
- `underrun_rgb565`
- `vsync_pin`
- `width`

## Telemetry

`refreshes`, `underruns` (bands sent as the fill colour after a renderer
could have armed them, a flash write's among them), `late_frames` (committed frames that waited more
than one refresh), `render_us_per_band` (the mean over the last refresh)
and `refresh_mhz` (the rate the sync divider gives).
