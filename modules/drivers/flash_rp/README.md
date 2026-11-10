# flash Module

Flash Module — BOOTSEL Button + Blob Serving + Runtime Parameter Store + Data Store

## Files

- `manifest.toml`
- `mod.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]
permissions = ["flash_raw"]

[[ports]]
name = "events"
direction = "output"
content_type = "FmpMessage"

[[ports]]
name = "stream"
index = 1
direction = "output"
content_type = "OctetStream"

[commands]
emits = ["toggle", "next", "prev", "long_press", "on", "off"]
```

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

`vault_store` keeps the key vault's two image slots here: 8 KiB each on an
RP2350, 4 KiB on an RP2040.

## Parameters

- `click`
- `debounce_ms`
- `double_click`
- `item_count`
- `long_press_cmd`
- `long_press_ms`
- `mode`
- `multi_click_ms`
- `presets`
- `triple_click`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
