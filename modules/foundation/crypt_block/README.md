# crypt_block — authenticated encryption for a block source

`crypt_block` sits between a block consumer and a block source. It serves
`storage.block` v1 on `blocks` and keeps an encrypted container on the source
wired to `lower`. Every authentication unit is sealed with an AEAD under a
volume data key held behind a KEY_VAULT handle, derived from a volume
master key the module owns. The key bytes never enter the module.

## Where the master comes from

| Mode | Master |
| --- | --- |
| Local (`key`) | A persisted `KDF_KEY` under the `key` label, in this module's namespace |
| Attach (`attach = 1`) | Reconstructed from two recovery-share envelopes, never persisted |

In attach mode the module takes these steps:
1. It generates a fresh P-256 recipient key and writes `"FXRK"` and the
   public key (69 bytes) to its `recipient` output.
2. It waits for the attachment bundle on its `bundle` control input: `"FXSB"`,
   the count 2 and three zero bytes, then two share envelopes (528 bytes).
   The envelopes are two custodians' shares, re-wrapped to that recipient.
3. It reconstructs the master with `SHARE_COMBINE`, bound to the volume id
   and epoch the container's superblock names. The superblock MAC is then
   verified under the reconstructed key.
4. It destroys the recipient key, whatever the outcome.

A bundle for another recipient or another volume fails the attach with
`EACCES`. A device with no container is formatted with the bundle's volume
id and epoch only when `format` is 1. A new attach is a new instance with a
new recipient key; a bundle is never reusable.

## Parameters

| Tag | Name | Default | Meaning |
| --- | --- | --- | --- |
| 1 | `key` | — | Vault label of the volume master key (`KDF_KEY`), in this module's namespace; at most 64 bytes, and epoch N's `key#N` must fit too |
| 2 | `format` | 0 | 1: lay a new container over a lower device with no superblock in either slot; a device whose superblocks do not verify holds a container, and the mount fails `ENODEV` |
| 3 | `block_size` | 512 | Upper logical block size: a power of two from 512 to the unit size |
| 4 | `unit_size` | 4096 | Authentication unit: a power of two from 512 to 4096, at least the lower block size |
| 5 | `journal_units` | 64 | Write-ahead journal size in units: even, 2 to 128; a record takes two, a header and its ciphertext |
| 6 | `attach` | 0 | 1: take the master from an attachment bundle on `bundle` |

## Ports

| Port | Direction | Carries |
| --- | --- | --- |
| `lower` | input | The block source the container lives on |
| `blocks` | output | The decrypted `storage.block` device |
| `recipient` | output | Attach mode: the recipient key's announcement |
| `status` | output | Optional: the status record, written when it changes |
| `bundle` | control input | The attachment bundle (attach mode); then control records, and a rotation's bundles |

## Data-key rotation

A `"FXRT"` record (then four zero bytes) on the control input rotates the
volume to a new epoch and master while it stays mounted. The superblock
carries the rotation, so a crash at any point resumes where it was:

| State | What holds |
| --- | --- |
| Prepared | The next epoch's master is held; nothing uses it |
| Active | New writes seal under the new epoch; each read takes its unit's epoch key |
| Migrating | Each step re-seals up to 8 old-epoch units, then commits the cursor once they are home and durable |
| Retiring | A scan proves no unit needs the old epoch |
| Steady | Committed first; only then is the old master destroyed |

Each step runs at most one phase.

### Local volumes

The next master is generated and persisted before the prepared superblock
is committed. Epoch 1's master is filed under `key`, and epoch N's under
`key#N`. Retirement destroys the old epoch's label.

### Attached volumes

The next master comes from the custodians, as a bundle for the next epoch:
1. The `"FXRT"` record makes a fresh recipient key and announces it on
   `recipient` (`"FXRK"`, as at attach). Nothing is written yet. The
   announcement does not name an epoch: the pipeline that sent the record
   asked for the next one. A second record while it waits changes nothing.
2. The pipeline answers with the next epoch's bundle (`"FXSB"`, 528 bytes)
   on the control input: a new split of the new key, which two custodians
   re-wrap to that recipient.
3. The module reconstructs it with `SHARE_COMBINE`, bound to the volume id
   and the next epoch, and destroys the recipient key. Only then is the
   prepared superblock committed.
4. The rotation runs as on a local volume, with both epochs' masters held as
   handles. Retirement destroys the old epoch's handles; nothing was ever
   filed under a label.

A bundle that is refused leaves the volume steady and serving at its
epoch, with the device untouched. A bundle is refused when it is for
another epoch, for another volume, or for a spent recipient. A fresh
recipient is then announced for the next try. A bundle that arrives with
no rotation waiting for it is refused `EINVAL`.

Attached masters are never persisted, so a restart during a rotation needs
both epochs' bundles again. The mount then works as follows:
- It reads the superblock and knows what it needs: the superblock's epoch,
  and while a rotation is under way the other one. That is the next epoch
  while prepared, and the previous epoch after.
- It announces one recipient at a time. It takes a bundle for either epoch
  it still needs, in whichever order they come, going by the epoch the
  envelopes name.
- A bundle for an epoch it does not need is refused, and a fresh recipient
  is announced. So a pipeline that knows only that a rotation from N to
  N+1 is under way can offer N and N+1 in turn.
- It mounts once it holds every master it needs, and the rotation resumes
  where the superblock left it.

A bundle for a needed epoch that does not open fails the mount (`EACCES`,
`EINVAL`), as at attach.

## Crypto-erase

An `"FXER"` record (then four zero bytes) on the control input erases the
volume:
1. Every master it has is destroyed: the current and previous epochs', and
   a prepared next one. A recipient awaiting a rotation's bundle goes too.
2. Both superblocks are zeroed and flushed.
3. The device goes offline (`ENODEV`).

The keys go first, so a crash part-way has already left nothing readable.
On an attached volume the master was never persisted here; erasing its
recovery shares is the custodians' part.

## Status

The optional `status` output lets the pipeline that sends rotation, erase
and bundle records follow the volume. It carries one 40-byte record,
little-endian, written whenever a field changes, and so once at ready:

| Off | Len | Field |
| --- | --- | --- |
| 0 | 4 | `"FXST"` |
| 4 | 1 | State: 0 opening, 1 awaiting bundle, 2 ready, 3 rotating, 4 failed, 5 erased |
| 5 | 1 | The superblock's rotation state: 0 steady, 1 prepared, 2 active, 3 migrating, 4 retiring |
| 6 | 2 | Reserved, zero |
| 8 | 4 | Epoch |
| 12 | 4 | Previous epoch |
| 16 | 4 | Awaited epoch: the epoch a bundle is awaited for, 0 for none (or a blank device, which takes the bundle's) |
| 20 | 4 | Errno: the mount's or erase's failure, or the last background step's result (a refused bundle is `EACCES`) |
| 24 | 16 | Volume id |

What the states mean for a pipeline:
- **Awaiting bundle:** a recipient has been announced for the awaited
  epoch. A mount under a rotation awaits the superblock's epoch first, then
  the other epoch the rotation holds. A refused bundle leaves it awaiting,
  with the refusal in the errno.
- **Rotating:** a rotation is under way, in the state the record names.
- **Ready** with rotation 0 at epoch N after a rotation: it is steady, and
  the old epoch's master is already destroyed. Epoch N-1's custody may
  retire.
- **Erased:** reported once the erase has finished; a failed erase reports
  failed.

While an attach is opening, the epochs and volume id are the superblock's,
read before it is verified; a local mount reports them as zero until
ready. A full channel never holds the module up. A
record not yet started is replaced by the latest one, and a record partly
written is finished first. A slow reader therefore loses intermediate
states and never the latest.

## Container

On the lower device, in whole units, there are four regions:
- **Superblocks:** two copies, A and B, each authenticated with HMAC-SHA256
  under a key derived from the master.
- **Journal:** write-ahead records.
- **Metadata table:** 48 bytes per unit, holding the generation, epoch,
  flags, nonce and tag.
- **Data units:** these are what the upper device addresses.

The AEAD suite is AES-256-GCM where the vault runs AES in constant time, and
ChaCha20-Poly1305 otherwise; it is fixed when the container is formatted. A
nonce is a random per-epoch prefix and a monotone sequence. Sequence ranges
are reserved in a superblock before any nonce in them is used, so a restart
never reuses one.

## Behaviour

- **Writes:** a write seals the unit and appends a journal record. It
  completes `Volatile`.
- **Flush:** `FLUSH` (or `FUA`) makes the journal durable, writes the pending
  units home, and flushes again. It completes with the fence the lower
  source reported for that last flush (for its last write, on a source
  with no volatile cache): `LocalDurable` from a disk, `RevisionMonotone`
  from a Loam volume. The fence is passed through, never strengthened.
- **Crash recovery:** a crash leaves every unit old or new. A restart replays
  every journal record that opens and is newer than its unit's home.
- **Reads:** a read that does not authenticate fails `EIO`. A discarded or
  never-written unit reads zeros.
- **Rollback:** on a raw lower device the generations share the data's
  rollback domain. They make crash recovery exact, and do not detect a
  hostile restore of the whole device.
- **Readiness:** `module_deferred_ready` holds consumers until the container
  mounts.

## Lower and upper I/O

`crypt_block` keeps one lower request in flight. On a source with `F_ASYNC`
it submits the request and reaps the completion in the same step or a later
one; on any other source it issues `EXEC` and, while that answers `EAGAIN`,
asks again after a step. Every operation, from the mount to a rotation
phase, waits there and resumes where it left off. A mount over a slow
source therefore commits one superblock generation, however long it waits.
One pump of the engine is bounded by `STEP_BUDGET` lower requests and
resumptions.

Upper requests complete when their lower work does:

| Call | Completes |
| --- | --- |
| `SUBMIT` | Queued; `REAP` returns the completion once its lower work is done. The buffer is lent until then: no `F_WRITE_COPIES` |
| `EXEC` | Inside the call when its lower work completes inside the call, as over a source that answers inline. Otherwise `EAGAIN`: the request carries on in later steps, and the next `EXEC` of the same request (same bytes, same tag) completes it |

The buffer of an `EXEC` is read and written only inside `EXEC` calls. An
`EXEC` of a different request, or a `SUBMIT`, drops an `EXEC` whose caller
stopped asking; its units written so far stay written, as after any write
that did not complete.
