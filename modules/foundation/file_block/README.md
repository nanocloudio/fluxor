# file_block — a `storage.block` source over one file

`file_block` serves `storage.block` v1 from a file it reaches through the
`fs` contract. Over `fat32` it is a loop device; on a Linux host it is a disk
image. It is the source a graph wires under a block consumer when no real
device is wanted, and the host test source for block transforms.

## Parameters

| Tag | Name | Default | Meaning |
| --- | --- | --- | --- |
| 1 | `path` | — | Image file, created when absent; at most 96 bytes, a longer path is refused at open (`EINVAL`), never clipped |
| 2 | `block_size` | 512 | Logical block size: a power of two from 512 |
| 3 | `blocks` | 0 | Minimum image size in blocks; a shorter file is extended |
| 4 | `volume` | — | The `fs` provider the image is reached through: absent = the default provider, a keyed volume's name, or `platform` |

## Where the image lives

Without `volume`, the image is opened through the default `fs` provider, the
one `provider_call(-1, OPEN_CREATE, …)` reaches. A graph that also carries a
filesystem of its own — a `fat32` over an encrypted device built on this very
source — makes that filesystem the default, and the image would be looked for
inside the volume it backs. `volume` names the provider explicitly, through
`provider_call_sel`:

- `platform` — the platform's own provider: the host filesystem on Linux.
  Reserved; no module can register under it.
- any other name — a keyed volume (a `fat32` with that `volume:`).

The open and every op on the handle it returns go to that provider. A name
longer than 16 bytes is refused at open (`EINVAL`), never clipped.

```yaml
- name: file_block
  params: { path: disk.img, blocks: 196608, volume: platform }
```

## Behaviour

- `CAPS`: write, flush, discard (reads back zeros), pipelined, copies write
  data at `SUBMIT`; up to 64 blocks per request; queue depth 8.
- Every request runs inside the call that carries it. `SUBMIT` queues the
  completion for `REAP`.
- Writes complete `Volatile`; `FLUSH` and `FUA` run the file's `FSYNC` and
  complete `LocalDurable`, naming a device id hashed from the path (and the
  `volume`, when one is named).
- `module_deferred_ready`: consumers wait until the image is open.
