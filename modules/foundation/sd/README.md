# sd Module

SD Card PIC Module

Detailed design notes are in [DESIGN.md](./DESIGN.md).

## Files

- `manifest.toml`
- `mod.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "blocks"
direction = "output"
content_type = "OctetStream"
required = true

[[resources]]
requires_contract = "spi"
access = "exclusive"

[[resources]]
requires_contract = "gpio"
access = "write"

[[resources]]
requires_contract = "timer"
access = "write"
```

## Parameters

- `block_count`
- `cs_pin`
- `spi_bus`
- `start_block`

## Addressing ceiling

Block addresses here are 32-bit, and that is the SD specification's own
limit rather than an implementation shortcut: SDHC/SDXC cards are addressed
by 512-byte block number in a 32-bit argument, which tops out at 2 TiB — the
same place SDXC itself stops. The block contract's ioctls carry a 64-bit LBA
because NVMe devices go further; a consumer that hands this driver an address
past 32 bits gets a refusal, never a wrapped one that lands somewhere else.

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
