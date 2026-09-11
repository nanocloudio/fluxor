// Contract: fs — filesystem dispatch.
//
// Layer: contracts/storage (public, stable).
//
// The kernel only routes; a provider module (`fat32` on bare metal,
// `linux_fs_dispatch` on the host) implements the opcodes. For
// streaming workloads, channel-based file transport (producer
// publishes bytes, consumer reads; seek/eof via channel IOCTL
// sideband) is usually the better shape — this contract is for
// random-access file I/O (seek+read, stat-then-read, etc.) where
// channels would require expensive out-of-band coordination.
//
// STAT's output buffer selects its own shape by width — 8, 16 or 48
// bytes. See `STAT`.
//
// ## Handle identity
//
// `OPEN` and `OPENDIR` return a tagged FD: providers encode the
// returned slot via `kernel_abi::fd::tag_fd(FD_TAG_FS, slot)`. The
// kernel's FS vtable wrapper strips the tag before re-entering the
// provider, so inbound ops see a raw slot. The tag is what lets
// `provider_call` and `provider_query` (including `LAST_FENCE`)
// resolve the contract from the handle through `fd_tag_contract`.
//
// ## Durability vocabulary
//
// Two independent things can be durable, and this contract keeps them
// separate because a consumer's recovery depends on both:
//
//   - **Byte durability** — the file's contents, plus the size metadata
//     of its own entry. Fenced by `FSYNC` (blocking) or by
//     `FSYNC_SUBMIT`/`FSYNC_POLL` (pipelined). `WRITE` and `WRITE_ASYNC`
//     are both submission only: bytes are volatile until a fence.
//   - **Name durability** — the entry in the parent directory that lets
//     a later mount *find* the file. Fenced by `FSYNC_NAME`, or achieved
//     as part of `RENAME`.
//
// File `FSYNC` is not name publication on any provider. A consumer that
// creates a recovery artefact and fsyncs only its FD can crash into a
// state where durable bytes have no discoverable name. Durable
// publication is one of two shapes:
//
//   1. `OPEN_CREATE`(final) → `WRITE` → `FSYNC` → `FSYNC_NAME`(final).
//      Crash-visible outcomes: name absent, or name present with a
//      prefix of the bytes. Use when the artefact is self-describing
//      (a WAL segment with an in-band terminator, a checksummed record
//      stream) so a truncated tail is recoverable.
//   2. `OPEN_CREATE`(temp) → `WRITE` → `FSYNC` → `CLOSE` →
//      `RENAME`(temp → final). Crash-visible outcomes: the old name, or
//      the new complete artefact. Use when the artefact must be
//      all-or-nothing (a snapshot, a pointer record, a content-addressed
//      body).
//
// Each achieves `Fence::LocalDurable { device_id }` at its final step,
// and nothing weaker at the steps before it. `MKDIR` and `UNLINK`
// likewise publish a name only once `FSYNC_NAME` covers the path.
//
// Both `FSYNC_NAME` and `RENAME` are optional capabilities. A consumer
// that needs crash-safe publication MUST query `CAPS` and fail closed
// when the bit it needs is clear, rather than proceeding on file
// `FSYNC` alone.
//
// ### Why these live here and not only on `storage.namespace`
//
// `storage.namespace` (0x13__) is the canonical naming surface, and
// `OPEN_CREATE`/`MKDIR` are already documented as fused `BIND` + open
// forms — see `namespace.rs::BIND`. `FSYNC_NAME` and `RENAME` complete
// that fusion rather than competing with it: a filesystem provider whose
// directory entries live inside the byte tier publishes names through
// this surface, and a split provider (an index without bytes) publishes
// them through `storage.namespace`. Requiring every consumer to hold a
// second namespace-provider handle to fence a name it minted through
// this contract would make the two surfaces mandatory in pairs, which
// the split-provider design exists to avoid. The equivalence still
// binds: `FSYNC_NAME` after `OPEN_CREATE`, and `RENAME` here, achieve
// the same fence as `BIND` and `RENAME` there.

pub const OPEN: u32 = 0x0900;
pub const READ: u32 = 0x0901;
/// Set the absolute read/write offset. `handle=file`.
///
/// `arg` is `[offset: u32 LE]`, or `[offset: u64 LE]` when `arg_len >= 8`.
/// Providers MUST accept both widths and select on `arg_len`; callers with
/// an offset that fits in 32 bits may keep sending the narrow form.
///
/// Returns negative errno on failure; any non-negative value is success.
/// Consumers must not require a particular success value — a provider may
/// return 0 or the resulting absolute offset. A provider whose backing
/// format cannot address the requested offset returns `EINVAL`; `fat32`
/// does so past 4 GiB, which is the format's own file-size ceiling.
pub const SEEK: u32 = 0x0902;
pub const CLOSE: u32 = 0x0903;

/// Report a handle's size and modification time.
///
/// `arg` points at an output buffer. Its width selects the shape:
///
///   - `arg_len >= 48` → `[size: u64 LE, mtime: u64 LE, ino: u64 LE,
///     nlink: u32 LE, mode: u32 LE, uid: u32 LE, gid: u32 LE]`
///   - `arg_len >= 16` → `[size: u64 LE, mtime: u64 LE]`
///   - `arg_len >= 8` → `[size: u32 LE, mtime: u32 LE]`
///
/// Providers MUST serve the first two and return the number of bytes
/// written, so a consumer learns the width it actually got rather than
/// assuming the one it asked for.
///
/// The wide form exists because 32 bits is a property of FAT32, not of
/// filesystems: `ext4` addresses files past 4 GiB and stores timestamps that
/// pass 2038. Making the width a function of the buffer the caller supplies
/// means a consumer moves to 64-bit when it needs to, against a provider
/// that already answers, instead of every consumer and provider changing on
/// the same day. A provider whose true size exceeds what the narrow form can
/// carry returns `EOVERFLOW` (`-75`) rather than a truncated number.
///
/// # The object-model fields
///
/// The 48-byte form carries what an inode-based filesystem has and FAT32
/// does not. A provider serves it only with [`caps::STAT_OBJECT`] set; the
/// rules for what it may put there are not optional:
///
///   - **`ino` is opaque, and 0 means "this volume has no stable file
///     identity"** — not a valid identity that could collide with a real
///     one. Nothing may infer identity from anything else; in particular a
///     start cluster is NOT an inode number, because FAT32 reuses freed
///     clusters and two files that never coexisted share one. A consumer
///     caching by it returns the wrong file.
///   - **`uid`/`gid`/`mode` are reported, not enforced.** A provider whose
///     format has no permission model reports the mount's declared defaults
///     and clears [`caps::OWNERSHIP`]; it does NOT report 0, which reads as
///     root. Enforcement needs an owner identity on the dispatch, which
///     `provider_call` does not carry.
///   - **`nlink` is the number of names.** [`UNLINK`] removes a name and
///     queues storage for reclamation when the last one goes. A provider
///     without hard links reports 1, which is true.
pub const STAT: u32 = 0x0904;
/// Blocking byte-durability fence: commit this file's contents and its
/// own recorded size past the device's volatile cache. `handle=file`.
/// Returns 0 or negative errno; the achieved fence is
/// `LocalDurable { device_id }`.
///
/// It does NOT publish the name that finds the file — see [`FSYNC_NAME`]
/// and the durability vocabulary at the top of this file.
pub const FSYNC: u32 = 0x0905;
/// Write data. handle=file, arg=data, arg_len=data_len. Returns bytes written.
pub const WRITE: u32 = 0x0906;

/// Open a directory for enumeration.
///
/// `handle = -1`; `arg` points at the directory path (UTF-8, no null
/// terminator), `arg_len` is the path length. Returns a directory FD
/// (non-negative) that shares the same handle pool as files — so
/// `CLOSE` works uniformly on both — or a negative errno
/// (`-2 ENOENT`, `-20 ENOTDIR`, `-23 ENFILE` etc.).
///
/// The directory is positioned at its first entry; successive
/// `READDIR` calls advance through the chain.
pub const OPENDIR: u32 = 0x0907;

/// Read the next batch of directory entries from a `OPENDIR` handle.
///
/// `handle` is the dir FD; `arg` is `*mut u8` output buffer,
/// `arg_len` its capacity. The provider fills as many whole entries
/// as fit, advances its internal cursor, and returns the number of
/// bytes written (positive) or `0` once the directory is fully
/// drained. The caller iterates by calling `READDIR` until it gets
/// `0`, then calls `CLOSE`.
///
/// Output buffer layout (all little-endian):
///
/// ```text
///   [count: u16 LE]                        — entries in this batch
///   per entry, repeated `count` times:
///     [name_len: u8]                       — 1..=255
///     [entry_type: u8]                     — 0 = file, 1 = directory
///     [name: name_len bytes UTF-8]         — no null terminator
/// ```
///
/// Hidden / system / volume-label entries (anything where the FAT
/// attribute byte has bits 0x02..0x08 set, or LFN companion entries)
/// are skipped at the provider layer; `.` and `..` are skipped too —
/// callers don't see them.
///
/// If the buffer is too small to hold even one entry, the provider
/// returns `-7 E2BIG` without advancing the cursor so the caller can
/// retry with a larger buffer.
pub const READDIR: u32 = 0x0908;

/// Open a file with create-on-missing semantics. Same arg layout as
/// `OPEN` — `handle = -1`, `arg` is the UTF-8 path, `arg_len` is
/// its length — but providers create the file with O_RDWR|O_CREAT
/// when it doesn't exist. Returns a tagged FD or a negative errno.
///
/// Distinct from `OPEN` so the existing "no auto-create" policy on
/// `OPEN` stays loud about typo'd paths (`OPEN /api/nope.png`
/// should 404, not 200-create-empty). Callers that legitimately
/// need to create a file on first boot (a per-PIC write-ahead log,
/// content-addressed body files) opt into `OPEN_CREATE` explicitly.
///
/// # Capability discovery — query `CAPS` first
///
/// `OPEN_CREATE` is part of the FS contract's *write tier*. Not
/// every storage backend implements write — bare-metal FAT32
/// would need a cluster allocator + FAT-table writeback +
/// directory-entry emit that's not in v1, and the wasm provider
/// maps to browser storage primitives whose create semantics
/// vary by host. Callers MUST query `CAPS` (see below) and
/// branch on `caps::OPEN_CREATE` before invoking this opcode if
/// they want a portable result.
///
/// Providers without write support return `ENOSYS` (`-38`) here,
/// so callers that skip the `CAPS` check still get a clean error
/// — they just won't know up-front whether the call would
/// succeed.
///
/// Normatively `storage.namespace::BIND(kind=object)` +
/// `file.data::OPEN` fused into one round trip — see
/// `namespace.rs::BIND` for the fused/split equivalence.
pub const OPEN_CREATE: u32 = 0x0909;

/// Remove a filesystem entry by path.
///
/// `handle = -1`; `arg` points at the UTF-8 path without a NUL terminator and
/// `arg_len` is its byte length. Returns `0` on success or a negative errno.
/// Providers that do not support mutation return `ENOSYS` and leave
/// [`caps::UNLINK`] clear.
pub const UNLINK: u32 = 0x090A;

/// Create a single directory by path. The parent must already exist (this is
/// `mkdir`, not `mkdir -p`); a missing parent returns `ENOENT`. An existing
/// directory at the path is success, so callers that create each level
/// top-down (e.g. `scp -r`, which sends one `D` per level) can re-issue safely.
/// Normatively `storage.namespace::BIND(kind=namespace)` — see
/// `namespace.rs::BIND` for the fused/split equivalence.
///
/// `handle = -1`; `arg` points at the UTF-8 path without a NUL terminator and
/// `arg_len` is its byte length. Returns `0` on success or a negative errno.
/// Providers that do not support mutation return `ENOSYS` and leave
/// [`caps::MKDIR`] clear.
pub const MKDIR: u32 = 0x090B;

/// Reserve a fixed-capacity file through an existing writable FD.
///
/// `arg` is `[capacity: u32 LE]`. Providers allocate enough physical storage
/// for `capacity`, persist the file's directory/inode size once, and leave the
/// descriptor positioned at offset 0. Subsequent writes within that capacity
/// do not change file size, allowing append logs to use an in-band terminator
/// without rewriting size metadata at every durability fence.
///
/// Returns `0` on success or a negative errno. The operation is deliberately
/// distinct from sparse truncate: success promises that the capacity is
/// physically backed and crash-visible. Providers without that guarantee
/// return `ENOSYS` and leave [`caps::PREALLOCATE`] clear.
pub const PREALLOCATE: u32 = 0x090E;

/// Shrink an existing file to `len` bytes, releasing the storage past the
/// new end.
///
/// `handle = -1`; `arg` is `[len: u64 LE][path]` — eight length bytes
/// followed by the UTF-8 path, with `arg_len` covering both.
///
/// Shrink only. A `len` greater than the current size returns `EINVAL`:
/// growing a file by moving its size field would publish storage the file
/// never wrote as its contents, which on a recycled volume is whatever used
/// to live there. A caller that wants capacity asks for [`PREALLOCATE`],
/// which allocates it.
///
/// The new size is durable when the call returns; releasing the storage
/// behind it may be deferred, so a crash can leave a correct shorter file
/// with storage still attached. Returns `EBUSY` when a writable handle is
/// open on the file, `EISDIR` for a directory. Providers that do not
/// support it return `ENOSYS` and leave [`caps::TRUNCATE`] clear.
pub const TRUNCATE: u32 = 0x090C;

/// Write data through an FD that submits now and proves durability
/// later — the provider hands the sectors to the block source's async
/// ring (multiple in flight) and returns. Like plain [`WRITE`], the
/// bytes are submitted but volatile; the caller establishes durability
/// with [`FSYNC_SUBMIT`] / [`FSYNC_POLL`] instead of the blocking
/// [`FSYNC`]. Same arg shape as [`WRITE`] (`handle=file`, `arg=data`,
/// `arg_len=len`). Lets a durable append log (the WAL) pipeline its
/// writes instead of spin-polling each, the single biggest write-
/// throughput lever. Providers without the async tier return `ENOSYS`
/// and leave [`caps::FSYNC_ASYNC`] clear; callers fall back to `WRITE`.
///
/// A short return is backpressure, not an error: the provider accepted
/// the returned prefix and the caller rewinds and retries the rest.
pub const WRITE_ASYNC: u32 = 0x090F;

/// Open a non-blocking durability fence over every write issued on this
/// FD so far. `handle=file`; `arg` is a ≥8-byte output buffer that
/// receives an opaque `u64` LE ticket. Returns 0, or `EAGAIN` when the
/// provider has no free fence slot (bounded pipelining depth — retry the
/// submit on a later step). The caller polls the ticket with
/// [`FSYNC_POLL`] until it reports durable. Any pending deferred sector
/// is submitted first so the fence covers it.
///
/// ## The ticket snapshots a frontier
///
/// A ticket is answerable for the file extent that existed at submit —
/// its byte range **and** its file-size metadata. Callers may keep
/// writing, growing the file, while the ticket is outstanding; those
/// later bytes are not attributed to it. Tickets may be polled in any
/// order and several may be outstanding on one FD.
///
/// The provider, not the caller, owns the directory/inode metadata that
/// records the frontier. A caller never publishes size itself, and no
/// provider may publish a frontier newer than the polled ticket's.
///
/// The ticket is opaque and provider-scoped: it is valid only on the FD
/// that produced it, and only until that FD is closed. Presenting it on
/// another FD, or after `CLOSE`, returns `EINVAL` — never a false
/// durable.
pub const FSYNC_SUBMIT: u32 = 0x0910;

/// Non-blocking poll of a fence ticket from [`FSYNC_SUBMIT`].
/// `handle=file`; `arg` holds the `u64` LE ticket. Returns 0 = durable,
/// 1 = pending, or a negative errno if a fenced write failed or the
/// ticket is not live on this FD. The caller (WAL) must withhold its
/// durable acknowledgement until this returns 0.
///
/// ## Exact meaning of a successful poll
///
/// A 0 return proves that every byte written to this FD before the
/// ticket's [`FSYNC_SUBMIT`], and file-size metadata recording at least
/// that frontier, are on non-volatile media — the device write cache
/// included. Data reaches media before the metadata that describes it,
/// so a crash can never expose a size pointing past durable bytes.
///
/// It is a **lower bound**. Writes issued after the submit may also have
/// reached media, and the recorded size may be larger than the ticket's
/// frontier. Neither makes the result invalid; a consumer must not
/// require a fence to stop exactly at its frontier.
///
/// ## Failure and backpressure
///
/// A negative return latches: the covered writes are unprovable, the FD
/// does not become `LocalDurable`, and the caller must treat the fence
/// as failed and recover through checked [`WRITE`] + [`FSYNC`]. A `1`
/// return may mean either "device writes outstanding" or "metadata
/// publication is queued behind a full ring"; both clear by polling
/// again on a later step, and neither consumes the ticket.
///
/// ## Name publication is a different fence
///
/// This fence covers an existing entry's contents and size frontier. It
/// says nothing about whether the *name* that finds the file is durable
/// in its parent directory — see [`FSYNC_NAME`].
pub const FSYNC_POLL: u32 = 0x0911;

/// Durably publish the parent-directory entry naming `path`.
///
/// `handle = -1`; `arg` points at the UTF-8 path (no NUL terminator),
/// `arg_len` is its length. Returns `0` on success or a negative errno.
///
/// ## Why the byte tier needs this opcode
///
/// [`FSYNC`] and [`FSYNC_POLL`] fence a file's *bytes and its own size
/// metadata* through an open FD. Neither publishes the directory entry
/// that lets a later mount find the file by name. A consumer that
/// creates a recovery artefact with [`OPEN_CREATE`], writes it, and
/// fsyncs the FD has durable bytes reachable by no durable name: after
/// a power cut the file may be absent, or present with its old contents.
/// `FSYNC_NAME` is the fence that closes that gap for the operations
/// this contract already mints names with — [`OPEN_CREATE`], [`MKDIR`],
/// and [`UNLINK`].
///
/// ## Ordering contract
///
/// The caller issues the naming operation, makes the file's bytes
/// durable, then calls `FSYNC_NAME` on the path. On success the entry —
/// creation, directory creation, or removal, whichever the caller last
/// performed on that path — is on non-volatile media, and the achieved
/// fence is `LocalDurable { device_id }`. Publishing a name before the
/// bytes is legal but pointless: the fence proves only what its own
/// call covers.
///
/// Providers without durable name publication return `ENOSYS` and leave
/// [`caps::FSYNC_NAME`] clear. A consumer that needs crash-safe
/// publication MUST check the bit and fail closed when it is absent
/// rather than treating file [`FSYNC`] as name publication — it is not.
pub const FSYNC_NAME: u32 = 0x0912;

/// Remove an empty directory by path.
///
/// `handle = -1`; `arg` is the path. Returns `0`, or `ENOTDIR` when the path
/// is not a directory, `ENOTEMPTY` when it still holds entries, `EBUSY`
/// while an FD references it, `ENOENT`, or `ENOSYS` where [`caps::RMDIR`]
/// is clear.
///
/// Emptiness is the provider's check, not the caller's: a caller that
/// enumerated the directory and found it empty has a fact that was true when
/// it looked. Recursive removal is deliberately not offered — a provider
/// walking an unbounded tree inside one `provider_call` is exactly the
/// unbounded-work shape this contract's `EAGAIN` rule exists to prevent, and
/// a caller that wants it can drive the walk and see each step's outcome.
///
/// As with [`UNLINK`], the removal is minted here and published by
/// [`FSYNC_NAME`] on the path.
pub const RMDIR: u32 = 0x0915;

/// Add a second name for an existing file.
///
/// `handle = -1`; `arg` is the same two-path encoding [`RENAME`] uses:
///
/// ```text
///   [existing_len: u16 LE]
///   [existing: existing_len bytes UTF-8]
///   [new_len: u16 LE]
///   [new: new_len bytes UTF-8]
/// ```
///
/// Returns `0`, or a negative errno: `EEXIST` if the new name is taken,
/// `ENOENT` if the existing one is not there, `EISDIR` if it is a directory,
/// `EXDEV` if the two paths are on different volumes, `ENOSYS` where
/// [`caps::LINK`] is clear.
///
/// The name is minted, not fenced. As with [`OPEN_CREATE`], durable
/// publication is [`FSYNC_NAME`] on the new path — a link that survives the
/// call but not the power cut is the same failure this contract separates
/// byte durability from name durability to prevent.
///
/// A provider whose format has no second-name concept leaves the bit clear
/// and returns `ENOSYS`. It does NOT emulate one by copying: two names for
/// one file and two files with equal contents differ under mutation, and a
/// consumer that asked for the first would silently get the second.
pub const LINK: u32 = 0x0913;

/// Read a symbolic link's target without following it.
///
/// `handle = -1`; `arg` carries the path in and the target out:
///
/// ```text
///   [path_len: u16 LE][path: path_len bytes UTF-8]
/// ```
///
/// `arg_len` is the size of the WRITABLE buffer, not the path's length —
/// they are different numbers and a single `arg_len` cannot be both. On
/// success the target is written at offset 0 and its byte length returned;
/// `E2BIG` when the buffer cannot hold it (retry with a larger one),
/// `EINVAL` when the path is not a symlink, `ENOSYS` where
/// [`caps::SYMLINK`] is clear.
///
/// Resolution stays with the caller, and that is the point of having this
/// opcode at all rather than a "follow links" mode on [`OPEN`]. A provider
/// that silently follows makes `O_NOFOLLOW` inexpressible, and on a system
/// where a path is often the whole of an authority check that turns a
/// symlink into a confused-deputy primitive: the caller names one thing, the
/// provider opens another, and nothing in the return value says so.
pub const READLINK: u32 = 0x0914;

/// Rename an entry, publishing the new name durably.
///
/// `handle = -1`; `arg` is:
///
/// ```text
///   [src_len: u16 LE]
///   [src: src_len bytes UTF-8]
///   [dst_len: u16 LE]
///   [dst: dst_len bytes UTF-8]
/// ```
///
/// Returns `0` on success or a negative errno. Normatively
/// `storage.namespace::RENAME` fused into the byte tier — see
/// `namespace.rs::RENAME`.
///
/// ## Guarantee
///
/// Success means a later mount observes either the old name or the new
/// name, never a state where the bytes exist under no name. Both parent
/// directories are durable on return, so the achieved fence is
/// `LocalDurable { device_id }` and no follow-up [`FSYNC_NAME`] is
/// required.
///
/// The provider does **not** fence the source file's bytes. Durable
/// publication of a newly written artefact is: [`OPEN_CREATE`] a
/// temporary path, [`WRITE`], [`FSYNC`] (or the async fence), [`CLOSE`],
/// then `RENAME` onto the final path. Renaming a file whose bytes are
/// still volatile publishes a name over indeterminate contents.
///
/// An existing destination is replaced atomically where the backend
/// supports it. Providers that cannot offer atomic replacement return
/// `ENOSYS` and leave [`caps::RENAME`] clear — a consumer must then use
/// [`OPEN_CREATE`] + [`FSYNC_NAME`] and tolerate a partially written
/// final name, or refuse to run on that backend.
///
/// ## What the guarantee costs on a backend without an atomic primitive
///
/// A backend whose directory mutation is not itself all-or-nothing may
/// still meet the guarantee by ordering its writes so that every
/// interruption is distinguishable, and settling the outcome when the
/// volume is next mounted. Two consequences follow for a consumer:
///
///   - Between the interruption and that settlement, a reader outside
///     this provider may observe BOTH names, each naming the artefact.
///     Reading the volume with another implementation of the same
///     filesystem after a power cut, before mounting it here, can
///     therefore see the source that a completed rename would have
///     removed — and a repair tool run at that moment may act on it.
///   - The source name is not guaranteed gone until the volume has been
///     mounted through this contract once. A consumer that treats the
///     absence of the source as proof of publication must obtain it from
///     a fresh lookup after mount, not from the rename's return.
///
/// Both are absent on a backend whose rename is a single atomic
/// operation. Neither weakens the guarantee above: the artefact is never
/// reachable by no name, and the destination is authoritative from the
/// moment `RENAME` returns.
pub const RENAME: u32 = 0x090D;

/// FS provider capability bitmap. `provider_call(handle, CAPS,
/// out, out_len)` writes a `u32` (little-endian, 4 bytes) into
/// `out`.
///
/// # Scope: what the bitmap covers (and what it doesn't)
///
/// The bitmap describes **handle-acquisition + write-tier**
/// capabilities — the entry-point opcodes a caller invokes with
/// `handle = -1` to obtain a new FD, plus the future mutation
/// opcodes (`WRITE`, `FSYNC`, …) that target an FD.
///
/// Per-FD read-side ops (`READ`, `STAT`, `SEEK`, `CLOSE`,
/// `READDIR`) are NOT in the bitmap. Those aren't separable
/// capabilities — they're the per-FD operation surface a
/// provider necessarily implements as the consequence of
/// returning a usable FD from `OPEN` / `OPENDIR`. A provider
/// that returns a `READDIR`-incompatible handle from `OPENDIR`
/// is broken; we don't define a bit for "does the FD this
/// `OPENDIR` just gave me actually support `READDIR`".
///
/// Concretely, a provider declares a capability surface like:
///   - `OPEN` set → "you can open existing files by path."
///   - `OPENDIR` set → "you can iterate directories."
///   - `OPEN_CREATE` set → "open-or-create works on this backend."
///   - Future write bits set → "this backend supports mutation."
///
/// A provider with `OPEN` set but `OPENDIR` clear (e.g. wasm
/// against a URL backend that doesn't expose directory listing)
/// is well-formed; callers wanting directory iteration check the
/// bit first.
///
/// # Wire shape
///
///   - `arg`/`out` is a `*mut u8` pointing at a 4-byte buffer.
///   - `arg_len` MUST be `>= 4`.
///   - Return value: `4` on success (bytes written), or a
///     negative errno on error.
///
/// # Provider obligation
///
/// All FS providers MUST implement `CAPS`. Bits not listed in
/// [`caps`] are reserved and MUST be returned as 0.
///
/// # `EAGAIN` and the probe rule
///
/// A capability can depend on the backing volume, not only on the
/// provider: `fat32` derives [`RENAME`] from the mounted volume's
/// reserved-sector geometry. A provider whose backing store has not
/// finished attaching therefore has no answer to give, and MUST return
/// `EAGAIN` rather than a pessimistic bitmap.
///
/// Consumers accordingly MUST treat `EAGAIN` as "ask again", never as
/// "capability absent", and MUST NOT latch a bitmap they have not
/// successfully read. The failure this prevents is silent and
/// permanent: a consumer probing during boot latches a clear bit,
/// runs its degraded tier for the lifetime of the process, and is
/// indistinguishable from one running on a volume that genuinely
/// cannot support the capability.
pub const CAPS: u32 = 0x09FF;

/// # Errno taxonomy
///
/// Three failure classes are distinguished across EVERY opcode in this
/// contract, because a consumer's correct response differs for each and
/// collapsing them silently downgrades durability:
///
///   - **`ENOSYS` — the provider does not implement this opcode.** A
///     permanent, structural answer about the provider, and the ONLY
///     errno that permits a consumer to select a compatibility
///     fallback. Always accompanied by a clear [`CAPS`] bit, so a
///     consumer that probes CAPS should never see it.
///   - **`EAGAIN` — not yet, ask again.** Transient: the mount has not
///     resolved, a bounded internal resource (fence slots, submission
///     ring) is momentarily exhausted, or the device is busy. Retry on
///     a later step. Never a fallback trigger and never an error to
///     report upward.
///   - **Everything else (`EIO`, `ENODEV`, `ENOSPC`, `ENOENT`,
///     `EBUSY`, …) — a real failure of this call.** In particular
///     `ENODEV` means the provider or its device is *gone*, which is a
///     failure, NOT permission to proceed in a weaker mode. A consumer
///     that treats `ENODEV` like `ENOSYS` converts a dead device into
///     a silent durability downgrade.
///
/// The distinction is load-bearing on [`PREALLOCATE`] specifically,
/// where all three are reachable: `ENOSYS` selects a dynamically
/// growing file, `EAGAIN` means retry, and `ENODEV`/`ENOSPC`/`EIO`
/// MUST fail whatever admission the preallocation was gating.
pub mod errno_classes {
    /// Opcode not implemented by this provider. The only fallback trigger.
    pub const UNSUPPORTED: i32 = -38;
    /// Not yet — retry on a later step. Never a fallback trigger.
    pub const TRANSIENT: i32 = -11;

    /// True when `rc` permits a consumer to select a compatibility
    /// fallback for the opcode that returned it. Deliberately narrow:
    /// every other negative rc is a failure of this call.
    #[must_use]
    pub const fn permits_fallback(rc: i32) -> bool {
        rc == UNSUPPORTED
    }

    /// True when `rc` means the call should simply be retried.
    #[must_use]
    pub const fn is_transient(rc: i32) -> bool {
        rc == TRANSIENT
    }
}

/// Capability bits returned by the [`CAPS`] opcode. A provider
/// sets bit B iff calling the corresponding entry-point or
/// mutation opcode would succeed for valid input (rather than
/// returning `ENOSYS`).
///
/// Adding a new write opcode is a two-step ABI change:
///   1. Reserve the next bit here and document it as
///      "implemented by no provider yet, providers MUST return 0".
///   2. Implement the opcode in linux + fat32 + wasm, flipping
///      the bit on for each backend that supports it.
///
/// Bit positions are stable forever — never renumber.
pub mod caps {
    // ── Handle-acquisition tier ─────────────────────────────
    // Opcodes called with handle = -1 that return a new FD.
    /// [`OPEN`] (0x0900) — read-only file open by path.
    pub const OPEN: u32 = 1 << 0;
    /// [`OPENDIR`] (0x0907) — open a directory for iteration.
    /// Implies the returned FD supports `READDIR`.
    pub const OPENDIR: u32 = 1 << 1;
    /// [`OPEN_CREATE`] (0x0909) — open with O_CREAT semantics.
    pub const OPEN_CREATE: u32 = 1 << 2;

    // ── Write tier (mutate state through an existing FD) ────
    /// [`WRITE`] (0x0906) — write bytes through an FD. The
    /// opcode predates `CAPS`; advertising the bit lets callers
    /// distinguish read-only providers (e.g. FAT32 v1, wasm
    /// fetch) from writable ones (linux) without trial-and-
    /// error.
    pub const WRITE: u32 = 1 << 3;
    /// [`FSYNC`] (0x0905) — durability fence on an FD. As with
    /// `WRITE`, the opcode predates the capability bitmap and
    /// the bit is the discovery channel.
    pub const FSYNC: u32 = 1 << 4;

    // Unimplemented capability bits remain clear until their opcode and
    // provider implementations land in lockstep.
    /// [`UNLINK`] (0x090A) — remove a file by path.
    pub const UNLINK: u32 = 1 << 5;
    /// [`TRUNCATE`] (0x090C) — shrink a file, releasing the storage past
    /// the new end.
    pub const TRUNCATE: u32 = 1 << 6;
    /// [`MKDIR`] (0x090B) — create one directory by path.
    pub const MKDIR: u32 = 1 << 7;
    /// [`RENAME`] (0x090D) — atomic, durably published rename.
    pub const RENAME: u32 = 1 << 8;
    /// [`PREALLOCATE`] (0x090E) — physically reserve fixed file capacity and
    /// leave its descriptor positioned at byte zero.
    pub const PREALLOCATE: u32 = 1 << 9;
    /// [`WRITE_ASYNC`] (0x090F) + [`FSYNC_SUBMIT`]/[`FSYNC_POLL`]
    /// (0x0910/0x0911) — the pipelined async durable-write tier. Set iff
    /// the provider (and its block source) implement submit-now /
    /// fence-later durability; callers fall back to `WRITE`+`FSYNC` when
    /// clear.
    pub const FSYNC_ASYNC: u32 = 1 << 10;
    /// [`FSYNC_NAME`] (0x0912) — durable publication of a parent-directory
    /// entry. Set iff the provider can prove a name reaches non-volatile
    /// media independently of the file's own bytes.
    pub const FSYNC_NAME: u32 = 1 << 11;

    // ── Object-model tier ───────────────────────────────────
    // What an inode-based filesystem carries and FAT32 does not. A provider
    // whose format has no answer clears the bit rather than fabricating one.
    /// [`STAT`]'s 48-byte form is served — `ino`, `nlink`, `mode`, `uid`,
    /// `gid` in addition to size and mtime.
    pub const STAT_OBJECT: u32 = 1 << 12;
    /// `uid`/`gid`/`mode` describe a real permission model rather than the
    /// mount's declared defaults. Reporting only; enforcement needs an owner
    /// identity on the dispatch, which `provider_call` does not carry.
    pub const OWNERSHIP: u32 = 1 << 13;
    /// A name can be added to an existing file, and `nlink` counts names.
    pub const LINK: u32 = 1 << 14;
    /// [`RMDIR`] (0x0915) — remove an empty directory by path.
    pub const RMDIR: u32 = 1 << 16;
    /// Symbolic links exist on this volume and `READLINK` resolves one.
    /// Resolution stays in the consumer: a provider that silently follows
    /// links makes `O_NOFOLLOW` inexpressible and turns a symlink into a
    /// confused-deputy primitive on a system where a path is often the whole
    /// of an authority check.
    pub const SYMLINK: u32 = 1 << 15;
}
