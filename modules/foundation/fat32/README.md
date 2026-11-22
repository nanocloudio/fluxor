# fat32

A FAT32 filesystem provider for the `fs` contract
(`crates/fluxor-abi/src/contracts/storage/fs.rs`).

## What it is for

FAT32 is the format a Linux host can mount, `fsck`, and copy files onto with
no tooling of ours involved. That is the whole reason this provider exists:
it is the interchange filesystem, the one a person can read on a laptop after
pulling the card. Everything below follows from taking that seriously — a
volume this provider has written must be a volume any other FAT32
implementation accepts, not merely one this provider can read back.

## Files

- `mod.rs` — the FS-contract provider, the mount, and the parameter surface.
- `manifest.toml` — ports, provided surfaces, observability.

## Ports

| Port | Direction | Purpose |
|---|---|---|
| `blocks` | input | Block source (`nvme`, `sd`, `crypt_block`, `file_block`). Reads and writes ride its `storage.block` requests; a mount over a streaming source reads through `READ_STREAM`. |

## Capabilities

`CAPS` (0x0DFF) reports what this provider serves. Two things about it are
load-bearing for consumers:

- **It returns `EAGAIN` until the volume is mounted.** `RENAME` is derived
  from the *volume's* reserved-sector geometry, not from the provider, so
  there is no honest answer before the boot sector is read. A consumer that
  probes during graph bring-up and latches a bitmap it never successfully
  read will run its degraded surface forever.
- **`RENAME` tracks the volume.** A volume formatted with fewer than ten
  reserved sectors cannot carry the rename intent record, so the bit stays
  clear and the opcode returns `ENOSYS`. This is not a failure; it is the
  capability surface working.

Served: `OPEN`, `OPENDIR`, `OPEN_CREATE`, `WRITE`, `FSYNC`, `UNLINK`,
`TRUNCATE`, `MKDIR`, `RMDIR`, `PREALLOCATE`, `FSYNC_ASYNC`, `FSYNC_NAME`,
and `RENAME` where the volume permits.

Not served, and the bits stay clear: `LINK` and `SYMLINK`. FAT32 has no
inode and no second name for a file, so `STAT` answers `ino` 0 ("this volume
has no stable file identity") and `nlink` 1. In particular a start cluster
is **not** an inode number: this provider reuses freed clusters, so two files
that never coexisted share one.

## Names

Both forms are carried. A name that fits 8.3 takes the path it always took
and mints no companion entries, so a volume this provider writes stays as
plain as the caller's names allow. A name that does not gets a long-name
companion set and a synthesised `BASE~N.EXT` alias in the 8.3 field the
format itself indexes by.

- **Lookup matches the form the name is in.** A generated alias depends on
  what else is in the directory, so it cannot be re-derived from the name the
  caller asked for; a long name is therefore found by reconstructing the
  companion run in front of each entry and comparing that. The two cannot be
  unified, and a provider that generated aliases without matching on them
  would let a caller write a file it can never open again.
- **The alias is unique in its directory.** Four numeric tails are probed,
  then a hashed one — probing indefinitely would make a directory of similar
  long names quadratic in device reads inside a budgeted dispatch, and the
  fifth attempt is as likely to be unique as the thousandth.
- **Re-using an entry keeps its existing alias.** The companions carry a
  checksum of the 8.3 name behind them; minting a fresh alias over a name
  that already exists would leave them naming a checksum that no longer
  matches, which `fsck.vfat` reports and declines to repair.
- **Companions are written before the entry they name**, and retired after
  it. A crash between the two leaves companions naming nothing, which every
  reader ignores and the next claim of the slot retires — the reverse order
  would leave a live file under its `~N` alias with the caller's name nowhere
  on the volume.

**Names that are still refused, not clipped.** ASCII only, at most
`LFN_MAX_CHARS`, none of the characters the format reserves for its own
structure, and no trailing dot or space — no FAT implementation preserves
one, so accepting it would hand back a file under a name nobody asked for.
Long names *written elsewhere* that exceed those bounds are still preserved
and still retired with their entries: preservation walks the companion run
without decoding it, so only matching and generation are bounded.

## Durability

The vocabulary is the contract's — byte durability and name durability are
separate, and file `FSYNC` does not publish a name. See
[storage_capability_surface.md](../../../docs/architecture/storage_capability_surface.md#byte-durability-and-name-durability-are-separate-fences)
and `crates/fluxor-abi/src/contracts/storage/fs.rs`.

- **Names** are published by `FSYNC_NAME`, or atomically by `RENAME`.
- **`RENAME`** has no atomic primitive in the format: the new entry and the
  cleared old one are in different sectors. It is made recoverable instead,
  with an intent record in the last reserved sector — a region no FAT32
  reader interprets — and a four-phase arm → publish → retire → disarm
  sequence replayed at the next mount. The record is bound to the volume's
  serial number, so a record left by an earlier filesystem on the same
  device is ignored rather than replayed into a live directory.
  - **Stated cost:** between publish and retire, both names exist over one
    chain. A foreign reader that mounts the volume before this provider
    replays sees the source entry a completed rename would have removed.
- **A single-sector write is assumed failure-atomic.** Every directory
  entry, FAT entry and the intent record sits inside one sector for exactly
  that reason. The assumption is not left implicit: the NVMe driver reads
  the controller's `AWUPF` and reports it. Consumers building two-slot
  recovery on top inherit the same dependency — and note that **two entries
  in one directory sector share a failure unit**, so two names are not
  independent unless something has placed them in different sectors.

## Space

Every path that stops referencing storage hands it back:

- `UNLINK` and create-over-existing queue the chain for background
  reclamation, and **refuse with `EAGAIN` when the queue is full** rather
  than stranding it. Reclamation is deferred out of the operation because
  walking an N-cluster chain inside one `provider_call` would hold the
  caller's step for as long as the chain is long.
- `OPEN_CREATE` reserves nothing. The chain starts at the first byte
  written, so a create that is abandoned leaves nothing behind.
- Appends link **one cluster at a time**. FAT32 describes a file's extent
  with nothing but its chain and its size, so a reserved-but-unwritten
  cluster is indistinguishable from a wrong size field, and `fsck` reports
  it. `PREALLOCATE` is where a caller asks for capacity, and there the
  reservation *is* the size.
- The FSINFO free-cluster count is maintained incrementally and written as
  the format's "unknown" whenever the volume is being mutated. A count is a
  claim about a volume that is not being written; freezing a stale one into
  a crash is what makes every checker report an error.
- FAT[1]'s ClnShutBit is cleared on the first mutation of a mount and set
  again when the volume falls quiet. A volume that came back from a power
  cut claiming to be clean is the thing this prevents.

## Timestamps

Filled from `timer::UNIX_MILLIS` when the platform has a real-time clock,
and **left unset when it does not**. A board with no RTC does not know what
time it is; stamping every file with 1980-01-01 produces timestamps that
look like data and are not.

## Bounded work

No operation waits on the device inside a `provider_call` (the `fs`
contract's rule). Three mechanisms make that hold:

- **A sector cache.** Every metadata sector — FAT, directory, FSINFO, the
  rename intent record — lives in a cache slot (`CACHE_SLOTS`: 128 on
  aarch64, 24 on a microcontroller). A read of a sector the cache does not
  hold submits a `storage.block` read and the operation answers `EAGAIN`; a
  later ask finds it. A write only changes the slot and marks it dirty.
- **Epochs.** A dirty slot carries the epoch it was written in. The engine,
  run at every dispatch and every step, writes one epoch and starts the
  next only once every write of it has completed — and, where the boundary
  was declared durable, once a `FLUSH` submitted after them has completed.
  An operation states its ordering as boundaries ("zero the cluster,
  durable boundary, link it") and the engine puts them on the media in that
  order over as many steps as the device takes. A sector written again in a
  later epoch gets a new slot, so the older image reaches the device first.
- **Transactions.** An operation's cache writes are tentative and the state
  it may change is saved. If a sector it needed was not cached, or the
  cache or epoch window was momentarily full, it aborts: tentative slots are
  dropped, the state is put back, and it answers `EAGAIN` with nothing
  consumed. Once everything it touches is cached, the whole operation runs
  against memory inside one call and commits.

What an operation promises to have made durable — `FSYNC`, `RENAME`,
`TRUNCATE`, `PREALLOCATE`, `FSYNC_NAME` — is decided by its last durable
boundary reaching the device; until then it answers `EINPROGRESS`, and the
caller asks again with the same request.

Scans are bounded by CPU and cache pins rather than device waits:

- A directory walk reads at most `DIR_SCAN_BUDGET_SECTORS` sectors (32 on
  aarch64, 6 on a microcontroller), then returns `EAGAIN` with its position
  saved. A directory large enough to matter is not exotic.
- A free-cluster scan reads at most `FAT_SCAN_BUDGET_SECTORS` (32) FAT
  sectors, then returns `EAGAIN` with its cursor saved, so a retry converges
  rather than restarts. A scan that has been all the way round *stays*
  answered until something is freed, so a full volume costs one `ENOSPC`
  rather than a full-FAT read per request. `ENOSPC` tells a consumer to
  stop, `EAGAIN` to ask again; collapsing either into the other either spins
  forever or fails a write that would have succeeded.

A directory entry is what *references* clusters, so the FAT sectors holding
its chain's links are ordered ahead of the directory sector that publishes
it. A crash can then only lose links nothing refers to yet — the
allocation-before-publish window under Limits — and never leave a size
claiming bytes the chain cannot reach.

## Seeding a volume

Putting a known file on a device at bring-up is not this module's job. The
`fat32_seed` fixture (`modules/fixtures/fat32_seed/`) does it as an ordinary
`fs` consumer — `OPEN_CREATE`, `WRITE`, `FSYNC`, `FSYNC_NAME` — so a
scenario needs nothing placed on the volume beforehand and this provider
carries no second implementation of its own write path.

## Mounting and formatting

A writable `storage.block` source with no read stream (`crypt_block`,
`file_block`, `sd`) is mounted through its requests; a source that offers
`F_READ_STREAM` (`nvme` on a 512-byte format), or is not writable, through
its stream. A transform such as `crypt_block` has no stream at all, which is
why the choice follows the source rather than a parameter.

`format: 1` lays a FAT32 volume across the whole source when its first sector
is entirely zero: a blank device, such as a fresh `crypt_block` container.
A first sector with any content — a FAT32 volume, a partition table, another
filesystem's data — is never overwritten, and without `format` nothing is
written at all. The layout is `mkfs.vfat -F 32`'s:
32 reserved sectors (boot sector, FSINFO, backups at 6 and 7), two FATs, the
root in cluster 2, cluster size from the specification's table, a serial from
the clock and the device. A source too small for 65 525 clusters is refused:
below that the specification types a volume as FAT16 whatever it says.

The reserved region, both FATs and the root cluster are zeroed at most 64
requests per step (discard runs, 8-sector pipelined writes or single sectors,
by what the source offers), then the metadata is written behind a flush and
the boot sector last, behind another. `format_cluster_sectors` overrides the
cluster size (a power of two up to 128 sectors). A format cut short leaves the first sector unsigned, and the
next mount formats from the start. Log: `[fat32] formatting`, `[fat32]
formatted`, then the ordinary `[fat32] boot ok`.

## Parameters

| Param | Purpose |
|---|---|
| `path`, `pattern` | Directory and glob for the enumeration surface. |
| `volume` | Instance selector for multi-volume routing (`mount` binds by name). `platform` is reserved: the build and the kernel refuse it. |
| `format` | 1 = lay a fresh volume on a source that holds none (see Mounting and formatting). |
| `format_cluster_sectors` | Sectors per cluster for `format`; 0 (default) = the specification's table. |
| `namespace` | NVMe namespace id the block requests carry (default 1; 0 = the source's own default). |
| `expect_volume_id` | Volume serial this graph expects. Refuses every operation on a mismatch, and **gates the destructive parameters below**. |
| `max_open_per_owner` | Handles one owner may hold at once. 0 = provider-wide table only. |
| `init_free_hint` | Cluster the free-cluster scan starts from, also written as FSINFO's next-free hint. Clusters from it on must be free. |
| `clean_root` | **Destructive.** Truncates the root directory. Requires `expect_volume_id`. |
| `clear_free_region` | **Destructive.** Zeroes a FAT span. Requires `clean_root`. |

The destructive parameters refuse to act unless the graph has named the
volume by serial. "Whatever is on the blocks channel" is not a specific
enough answer to the question of which volume to wipe.

The serial to put in `expect_volume_id` is reported by the module itself,
as `vol=` on its heartbeat:

```
[fat32] hb init=12 files=003 fds=2 clean=0 vol=1A2B-3C4D
```

It is printed in the `XXXX-XXXX` form `blkid` and `fatlabel -i` use, so a
serial read off a running graph and one read off a host tool compare
without conversion. `expect_volume_id` takes the same digits as a number
(`0x1A2B3C4D`). Both refusals name the serial too: a graph that asks to
wipe a volume it has not named reports the one it found, and a serial
mismatch reports what is on the device against what was expected.

## Limits, stated rather than discovered

- **4 GiB files, 2 TiB volumes.** The format's own ceilings. `SEEK` and
  `TRUNCATE` accept 64-bit values and refuse what the format cannot address,
  rather than wrapping; `STAT` answers in whichever width the caller's
  buffer selects. The *volume* is capped there; where it sits is not — the
  partition base is 64-bit and every sector number in this provider is an
  offset within the volume, so a FAT32 partition beyond 2 TiB on a large
  device is ordinary.
- **512-byte device blocks only.** The provider asks the block source for
  its logical block size and refuses to mount when it is not 512. Every
  failure-atomicity claim here is a claim about a 512-byte sector; on a 4Kn
  namespace a sector write becomes a read-modify-write of the enclosing
  4 KiB block, silently merging eight sectors into one failure unit and
  taking with it the independence two directory entries in different sectors
  are supposed to have. Refusing is the honest answer.
- **Long names are ASCII-only.** Decoding UTF-8 into the UTF-16 the format
  stores means surrogate handling in a module that cannot afford to get it
  subtly wrong, and a mangled name is worse than a refused one.
- **`UNLINK` does not remove directories**; `RMDIR` does, and only an empty
  one. Recursive removal is not offered: walking an unbounded tree inside one
  `provider_call` is the shape every other operation here is bounded to
  avoid, and a caller that wants it can drive the walk and see each step.
- **Per-owner handle quotas** come from `query_key::CALLER_OWNER`, which the
  kernel publishes across the dispatch frame — `provider_call` carries no
  owner argument and should not gain one. `max_open_per_owner` refuses the
  owner that is over its share while the table still has room, so the failure
  lands on the workload at fault rather than on whoever asks next. The
  generation is held with the slot: a reused owner slot is a different owner.
  Without a ceiling the tables are still provider-wide, and a diagnostic
  names the holders when one fills.
- **No object model.** FAT32 has no inode and no hard links: `STAT`
  answers `ino` 0 and `nlink` 1, and `LINK` and `SYMLINK` stay clear.
  Nothing here fabricates an identity — in particular a start cluster is not
  an inode number, because this provider reuses freed clusters.
- **A crash can still leak storage**, in two bounded windows: between
  linking a cluster and publishing the entry that references it, and between
  a `TRUNCATE` detaching its tail and the background drain releasing it.
  Neither is silent — the volume-dirty bit and the retracted free count are
  how a crash announces itself — and neither loses data. Reclaiming them
  needs a full mark-and-sweep, which `fsck.vfat` already does correctly and
  which is not worth reimplementing inside a provider that has deliberately
  bounded every operation's device work.
- **`TRUNCATE` publishes its new size before releasing the storage behind
  it.** A crash in between therefore leaves a correct, shorter file with
  storage still attached, which `fsck` reports and repairs. The reverse
  order would leave a size claiming bytes the chain cannot reach, so this is
  the direction to fail in.

## If you are adding ext2/3/4

Two questions must be answered before ext code exists, because a provider
written against the current stack would answer them by accident and the
accident would then be the seam:

- **Block geometry.** The filesystem block, the device logical block and the
  staging buffer are three different sizes. Decide which layer owns each
  conversion before any of them is hard-coded: this provider only ever
  refuses a device whose logical block is not 512, which is a legitimate
  answer for FAT and not one ext can reuse.
- **Object model.** Settle what the `fs` contract says about ownership, hard
  links, symlinks and inode identity — concepts FAT has no representation for
  and therefore never forced the contract to name. If ext answers them
  privately it grows a side channel and stops being comparable to this
  provider.

What is worth reusing from here is the *lower* half — the sector cache and
its write chokepoints, the bounded resumable-scan shape, the fence and
ticket machinery, and the errno taxonomy. What is not worth reusing is
anything above that:
FAT's path resolution, its directory format and its allocation model have
nothing in common with an inode-and-extent filesystem, and a shared
abstraction over both would be shaped by whichever came first.

The seam has deliberately not been extracted into a shared crate here. There
is one consumer, and an interface designed against one consumer is a guess.
