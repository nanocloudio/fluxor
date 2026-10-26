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
source — makes that filesystem the default, and the image's open would go to
the filesystem it backs, which cannot answer until the image serves it.
`volume` names the provider explicitly, through `provider_call_sel`:

- `platform` — the platform's own provider: the host filesystem on Linux
  and wasm. On bcm2712 it serves workloads only, and the RP targets have
  none.
  Reserved; no module can register under it.
- any other name — a keyed volume (a `fat32` with that `volume:`).

The open and every op on the handle it returns go to that provider. A name
longer than 16 bytes is refused at open (`EINVAL`), never clipped.

The `fs` claim in the manifest names this param (`selector_param =
"volume"`), so the composer checks the provider each instance reaches and
refuses a graph where it reaches none: a `volume` no `fat32` in the graph
declares, `platform` on a target whose platform does not answer the graph's
`fs` calls, or no `volume` in a graph whose `fs` providers are all keyed.
It also refuses an image with no `volume` under a graph whose filesystem is
built on it: that filesystem is the default provider, and it cannot open
the image it mounts.

```yaml
- name: file_block
  params: { path: disk.img, blocks: 196608, volume: platform }
```

## Behaviour

- `CAPS`: write, flush, discard (reads back zeros), pipelined; up to 64
  blocks per request; queue depth 8. No `F_WRITE_COPIES`: a queued write's
  buffer is read when its turn comes, so it stays lent until reaped.
- The `fs` contract never waits on the device inside a call, so a request
  is a resumable job. `SUBMIT` queues it; the queue runs in submission
  order, advanced inside `SUBMIT`/`REAP` and by the module's own step. A
  job parked on `EAGAIN` (nothing moved) or `EINPROGRESS` (a taken `FSYNC`,
  re-asked identically) resumes where it stopped; short counts advance by
  what moved. `REAP` answers 0 until the job is decided.
- `EXEC` runs the same job inside the call and answers `EAGAIN` while it is
  undecided, or while queued requests hold the job. Re-asking the
  identical request resumes it; a different request starts over (block
  requests are idempotent, so a parked job left behind is harmless).
- Opening is a step machine too: `OPEN_CREATE`, `STAT`, the extending
  write and its `FSYNC` each resume across steps.
- Writes complete `Volatile`; `FLUSH` and `FUA` run the file's `FSYNC` and
  complete `LocalDurable`, naming a device id hashed from the path (and the
  `volume`, when one is named).
- `module_deferred_ready`: consumers wait until the image is open.
