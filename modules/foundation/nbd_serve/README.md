# nbd_serve — a `storage.block` source published over NBD

`nbd_serve` consumes the `storage.block` v1 source wired to its `blocks`
input and serves it to a Linux NBD client over a `net_proto` stream
transport: `linux_net` on a Linux host, `ip` on bare metal. `nbd-client`
attaches the export as `/dev/nbdN`, so a kernel filesystem, `fsck` or SQLite
runs on the source unchanged. Stacked over `crypt_block` it publishes the
decrypted device; over a Loam volume provider, the remote volume.

```yaml
target: linux

platform:
  net: {}

modules:
  - name: disk
    type: file_block
    params:
      path: /var/lib/fluxor/disk.img
      blocks: 262144
  - name: nbd
    type: nbd_serve
    params:
      port: 10809

wiring:
  - from: disk.blocks
    to: nbd.blocks
```

The `platform.net` stack wires `nbd.net_in` / `nbd.net_out` to the transport.
Then, as root on the client host:

```sh
nbd-client -N '' -b 512 <host> 10809 /dev/nbd0
```

`-b` must be the source's logical block size (the handshake reports it to a
client that asks with `NBD_INFO_BLOCK_SIZE`).

## Parameters

| Tag | Name | Default | Meaning |
| --- | --- | --- | --- |
| 1 | `port` | 10809 | TCP port. The address is the transport's: `linux_net` listens on every interface, `ip` on its own |
| 2 | `export` | empty | Export name a client must ask for; empty accepts any name |
| 3 | `read_only` | 0 | 1 publishes the export read-only whatever the source supports |
| 4 | `queue_depth` | 8 | Chunks in flight to a pipelining source, at most `MAX_SLOTS` (8) and the source's own depth |
| 5 | `max_request` | 32 MiB | Largest read or write accepted, rounded down to the block size |

## Ports

| Port | Direction | Carries |
| --- | --- | --- |
| `blocks` | input | the `storage.block` source (channel ioctls) |
| `net_in` | input | `net_proto` events from the transport |
| `net_out` | output | `net_proto` commands to the transport |

## Handshake

Fixed newstyle, `NO_ZEROES` offered. Options: `EXPORT_NAME`, `GO`, `INFO`,
`LIST`, `ABORT`; anything else is answered `ERR_UNSUP` and haggling
continues. `GO`/`INFO` answer `NBD_INFO_EXPORT` and, when asked,
`NBD_INFO_BLOCK_SIZE` (minimum = the source's logical block size, preferred
4 KiB or the block size, maximum = `max_request`). Replies are simple replies;
structured replies are not offered.

The export's size is `CAPS` block count × logical block size. The module
does not listen until `CAPS` answers. Transmission flags follow the source:

| Flag | When |
| --- | --- |
| `READ_ONLY` | `read_only` is set, or the source lacks `F_WRITE` |
| `SEND_FLUSH` | the source has a volatile cache (`F_FLUSH`) |
| `SEND_FUA` | writable, and the source has `F_FUA` or `F_FLUSH` |
| `SEND_TRIM` | writable, and the source has `F_DISCARD` |

## Transmission

- `READ`, `WRITE`, `TRIM` become `READ`, `WRITE`, `DISCARD` requests of at
  most one slot (16 KiB, or the source's `max_blocks` if smaller; `TRIM`
  chunks are `max_blocks`, up to 1 GiB). A larger request streams through the pool.
- The source is driven with `SUBMIT`/`REAP` when it reports `F_ASYNC`, up to
  the queue depth, and with `EXEC` otherwise. `EAGAIN` from either is
  retried on a later step.
- Replies leave in the order requests finish, each with its handle.
- `FLUSH` is answered after the source's `FLUSH` completes. It covers every
  write already answered, which is what NBD asks.
- `FUA` passes through as `F_FUA` when the source has it. Otherwise the
  write is followed by a `FLUSH` submitted after the write was reaped, and
  answered after that. A source without a volatile cache needs neither.
- A read is answered once all its chunks are in, with the source's error if
  one failed. A read larger than the free pool streams instead, and a chunk
  that fails after its header went out closes the connection — a simple
  reply cannot retract a success.
- Errors: `EPERM`/`EACCES`/`EROFS` → `EPERM`; `ENOMEM`, `EINVAL`, `ENOSPC` →
  the same NBD code; `EFBIG`/`EOVERFLOW` → `EOVERFLOW`; `ENOSYS`/`ENOTSUP` →
  `ENOTSUP`; everything else, `EIO` and `EBADMSG` included → `EIO`.
  Unaligned or zero-length requests, reads past the end, requests above
  `max_request`, `TRIM` without discard and unknown commands → `EINVAL`;
  writes or trims past the end → `ENOSPC`; writes and trims on a read-only
  export → `EPERM`. A refused write's payload is drained, never buffered.
- `DISC`: requests already received are answered, then the connection
  closes.

## Connections

One client at a time: a second connection is closed as it arrives, so the
export has one writer. When the client goes, or the stream becomes unusable,
nothing more is sent; the module reaps every request still with the source —
which holds the module's buffers until then — and only then closes the
connection and accepts the next client.

## NBD and ublk

ublk is the intended Linux frontend and NBD the fallback and bring-up
oracle. On the reference Pi 5 host the ublk gate is closed: kernel
6.18.33+rpt-rpi-2712 is built without `CONFIG_BLK_DEV_UBLK` (no `ublk_drv`,
no `/dev/ublk-control`), while `nbd.ko` is available and io_uring is enabled.
A ublk frontend would consume the same `storage.block` records and replace
only the transport.

Attaching a real `/dev/nbdN` needs root, so the host tests
(`tests/harness/tests/nbd_serve.rs`) play the NBD client byte for byte over a
modelled transport instead.

## Limits

Registered in `docs/architecture/limit_register.md`: `MAX_SLOTS` (8),
`SLOT_SIZE` (16 KiB), `MAX_REQUESTS` (16), `MAX_REQUEST_BYTES` (32 MiB),
`EXPORT_NAME_CAP`, `OPT_BUF_SIZE`, `OUT_DATA_MAX`, and the per-step frame
and reap budgets. The pool and frame buffers are module state (about 140 KiB),
admitted at compose time.
