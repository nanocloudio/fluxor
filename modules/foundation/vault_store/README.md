# vault_store — the key vault's durable store

The key vault keeps the node's persisted keys (labelled keys opened with
`PERSIST`) as one image in kernel RAM. `vault_store` carries that image to and
from a `storage.block` source, so where the keys live is the graph's choice and
one implementation serves every board. The wire contract is
`abi::internal::vault_store`; the kernel side is `kernel::security::vault_store`.

## Parameters

| Tag | Name | Default | Meaning |
| --- | --- | --- | --- |
| 1 | `image` | 8192 | Image size in bytes: a multiple of 512 and of the source's block size, 1024..=4096 on an RP2040 (a Pico W graph says `image: 4096`), ..=8192 on an RP2350, ..=16384 on bcm2712 and Linux |
| 2 | `seal` | `hardware` | `hardware`: records sealed under the platform's key; `none`: kept readable |
| 3 | `start_sector` | 0 | Where slot A starts, in 512-byte sectors |
| 4 | `sector_count` | 0 | The window in 512-byte sectors; 0 is the rest of the source |

Slot A is `[start, start + image)`, slot B follows it; the window must hold
both. Sectors are 512 bytes whatever the source's block size, so a window is
named the same on every medium. The source must queue writes (`F_ASYNC`,
`F_WRITE`) with blocks of 512 B to 4 KiB; anything else stops the module with
one log line.

## Behaviour

- **Load.** Both slots are read and digested (`SCAN`), then the newer valid
  image is read again into the kernel (`FILL`): one image of RAM. Neither valid
  is an empty store. A slot that changes between the passes starts the load
  over at once; a read the source fails starts it over a second later. Until
  the load finishes, every labelled vault open answers `EAGAIN`, from before
  any module in the graph runs.
- **Writes.** A key made with `PERSIST` changes the image. The module writes
  the new image to the slot not holding the durable one, a block at a time,
  then fences it (`FLUSH` on a source with a volatile cache); only then does it
  report the image durable. Until then the open that made the key, and every
  open of it, answers `EAGAIN`; asked again, the same key is answered once it
  is on the medium. An image changed during a write is started again from its
  first block in the same slot; the durable slot is never written. A write the
  medium refuses is reported (`[vault] store write failed`), the opens waiting
  on it answer `ERROR`, and the module retries a second later.
- **One per graph.** The kernel answers the first instance and refuses the
  rest (`EBUSY`); the composer refuses a graph with two.

## Sealing

- `hardware`: each record is sealed under the platform's key (`HalOps::seal`),
  which the medium never holds: the bcm2712 OTP device key, the RP2350 OTP seal
  key once provisioned. A board without one persists nothing — keys work for
  the boot that made them — and logs `[vault] store is seal: hardware and this
  board has no sealing key` once.
- `none`: each record is the key itself, under its own record magic (`FXVC`,
  `FXVR`). Whoever holds the medium holds the keys. `DESCRIBE` reports such a
  key `persisted::CLEAR` with tier `SOFTWARE`, and `TIER` reports `SOFTWARE`,
  so a consumer that requires protection at rest refuses it. A sealed store
  never reads a readable record: one found there is treated as absent.

The production recommendation is `hardware`; `none` is for boards without a
sealing key, and for development.

## Wiring

Pico 2 W, the flash data region (`flash_rp`'s `store` output, 16 KiB below the
parameter store, so a UF2 reflash never reaches it):

```yaml
- name: flash_rp
- name: vault_store
  params: { image: 8192, seal: none }
wiring:
  - from: flash_rp.store
    to: vault_store.blocks
```

An SD card, recommended: a file on the card's FAT, so the card stays readable
on a PC and needs no partitioning:

```yaml
- name: sd
  params: { spi_bus: 0, cs_pin: 17 }
- name: fat32
  params: { volume: sd0 }
- name: file_block
  params: { path: /fluxor/vault.img, blocks: 32, volume: sd0 }
- name: vault_store
  params: { image: 8192, seal: none }
wiring:
  - { from: sd.blocks, to: fat32.blocks }
  - { from: file_block.blocks, to: vault_store.blocks }
```

A block source answers the one consumer its channel reaches, so `vault_store`
needs a source no other module reads: the composer refuses a second edge from
the same output, since a tee carries the stream but not the requests and a
vault behind one would never load. No module splits one source into windows,
so on a device a filesystem already holds, the vault is a file on that
filesystem.

An SD card, raw: a window of the card, e.g. sectors 2048..2080, in a graph
where nothing else reads `sd.blocks`:

```yaml
- name: vault_store
  params: { image: 8192, seal: none, start_sector: 2048, sector_count: 32 }
wiring:
  - { from: sd.blocks, to: vault_store.blocks }
```

Pi 5, recommended: a file on the board's FAT32, beside whatever else the
volume holds (32 KiB, two 16 KiB slots):

```yaml
- name: fat32
- name: file_block
  params: { path: /vault.img, blocks: 64 }
- name: vault_store
  params: { image: 16384, seal: hardware }
wiring:
  - { from: nvme.blocks, to: fat32.blocks }
  - { from: file_block.blocks, to: vault_store.blocks }
```

Pi 5, raw NVMe, in a graph where nothing else reads `nvme.blocks`: the first
32 KiB of the drive's External backing space, which no paging arena is carved
from (LBA `0x200000` of a 512-byte namespace), as two 16 KiB slots:

```yaml
- name: vault_store
  params: { image: 16384, seal: hardware, start_sector: 2097152, sector_count: 64 }
wiring:
  - { from: nvme.blocks, to: vault_store.blocks }
```
