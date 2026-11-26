# flash_rp Module

Flash Module — BOOTSEL Button + Blob Serving + Runtime Parameter Store + Data Store

## Files

- `manifest.toml`
- `mod.rs`

## Interface

| Port | Direction | Content type | |
|---|---|---|---|
| `raw` | output | `OctetStream` |  |
| `stream` | output | `OctetStream` | serves `stream_select` |
| `store` | output | `OctetStream` | serves `storage.block` |

Builds for: `rp2350`, `rp2040`. [manifest.toml](manifest.toml) is the declaration.

## Data store (`store`, out[2])

A `storage.block` source over the flash's data region: the
`flash_layout::DATA_STORE_SIZE` (16 KiB) directly below the parameter store,
at the top of the flash, so a UF2 reflash (which writes only the addresses it
carries, none past graph slot B) leaves it as it is. `picotool erase` does not.

- `CAPS`: blocks of one erase sector (`flash_layout::FLASH_SECTOR`, 4 KiB, which
  the board's `flash_erase_size` must equal), 4 blocks, one per request, queue
  depth 1, `F_WRITE | F_FUA | F_ASYNC`. `EAGAIN` until the first step has read
  the partition (`FLASH_LAYOUT`).
- A read is an XIP copy, answered at `SUBMIT`. A write erases its sector in one
  step and programs it four pages a step after; its buffer stays lent until
  reaped. Every write completes `LocalDurable`: the flash keeps no volatile
  cache, so `FUA` and `FLUSH` cost nothing.
- `EXEC` answers `ENOSYS`: an erase takes as long as the flash takes.

A `key_vault` keeps its record image's two A/B slots here (`image` bytes
each, two of them within the 16 KiB).

## Parameters

- `debounce_ms` (u16, default 50): BOOTSEL debounce window.
- `presets` (blob): inline blobs served on `stream`, up to 8 blobs and 4 KiB
  in all.

`raw` carries one byte per debounced BOOTSEL transition (`0x01` pressed,
`0x00` released), the `input::button` shape `gesture` consumes. `stream`
sends the blob its consumer selects by index (`stream_select`) in 512-byte
records, then `SET_HUP`.
