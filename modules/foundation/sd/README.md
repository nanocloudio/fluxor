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

## Block source

`blocks` carries two things:

- a sector stream from `start_block`, repositioned by `IOCTL_NOTIFY` seeks;
- `storage.block` as a read-only source: `CAPS` and one-block `READ`
  requests through `SUBMIT` / `REAP`. Capacity and the device id come from
  the card's CSD register.

`CAPS` reports `F_ASYNC`, queue depth 1, `max_blocks` 1 and no `F_WRITE`.
`SUBMIT` answers `EAGAIN` while the card is attaching or the one slot is
taken, and `EINVAL` for a refused request (a write, a range past the card, a
buffer that does not cover the block, or a block the card cannot address).
A queued read runs on the stream's own read machine as soon as the stream's
block in flight finishes, ahead of the stream's next block, and advances one
bounded poll per step. The block is copied to the caller's buffer only when
it arrives whole; a failed read completes with `EIO`.

`EXEC` is not served and answers `ENOSYS`. It must finish inside the call,
and a card transfer takes as long as the card takes, so serving it would hold
a scheduler step for that long; the contract gives `EXEC` no retryable
answer. A consumer reads this source through `SUBMIT` / `REAP`.

When the stream has read its `block_count` blocks (non-zero), `blocks`
reports end-of-stream (`POLL_HUP`) and the module keeps running, so `CAPS`,
`SUBMIT` and `REAP` are still served. A seek after the end is not honoured.

## Addressing

The card's read command takes a 32-bit argument: a block number on a
block-addressed card (SDHC/SDXC, 2 TiB at most) and a byte offset on a
byte-addressed one (SDSC, 2 GiB at most). The address is computed in 64 bits
and a request whose argument would not fit in 32 is refused with `EINVAL`
rather than wrapped onto another block; the stream stops with a read error
at such a block. `CAPS` reports the card's real block count, so a request
past it is refused before it reaches the card.

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
