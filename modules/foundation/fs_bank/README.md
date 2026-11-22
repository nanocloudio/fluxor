# fs_bank Module

FS-backed Asset Bank PIC Module (Seekable Version)

## Files

- `manifest.toml`
- `mod.rs`

## Interface

| Port | Direction | Content type | |
|---|---|---|---|
| `stream` | output | `OctetStream` | required |
| `notify` | output | `FmpMessage` |  |
| `commands` | ctrl_input | `FmpMessage` |  |

Builds for: `rp2350`, `bcm2712`, `wasm`, `linux`. [manifest.toml](manifest.toml) is the declaration.

## Parameters

- `auto_advance`
- `file_count`
- `initial_index`
- `mode`
