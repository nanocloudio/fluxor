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
// STAT output buffer layout (8 bytes): `[size: u32 LE, mtime: u32 LE]`.
// Both `fat32` and `linux_fs_dispatch` populate it per this shape.
//
// ## Handle identity
//
// `OPEN` and `OPENDIR` return a tagged FD: providers encode the
// returned slot via `kernel_abi::fd::tag_fd(FD_TAG_FS, slot)`. The
// kernel's FS vtable wrapper strips the tag before re-entering the
// provider, so inbound ops see a raw slot. The tag is what lets
// `provider_call` and `provider_query` (including `LAST_FENCE`)
// resolve the contract from the handle through `fd_tag_contract`.

pub const OPEN: u32 = 0x0900;
pub const READ: u32 = 0x0901;
pub const SEEK: u32 = 0x0902;
pub const CLOSE: u32 = 0x0903;
pub const STAT: u32 = 0x0904;
/// Sync file data to disk. handle=file. Returns 0 or negative errno.
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
/// need to create a file on first boot (e.g. Loam's per-PIC WAL,
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
pub const OPEN_CREATE: u32 = 0x0909;

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
pub const CAPS: u32 = 0x09FF;

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
    pub const OPEN:           u32 = 1 << 0;
    /// [`OPENDIR`] (0x0907) — open a directory for iteration.
    /// Implies the returned FD supports `READDIR`.
    pub const OPENDIR:        u32 = 1 << 1;
    /// [`OPEN_CREATE`] (0x0909) — open with O_CREAT semantics.
    pub const OPEN_CREATE:    u32 = 1 << 2;

    // ── Write tier (mutate state through an existing FD) ────
    /// [`WRITE`] (0x0906) — write bytes through an FD. The
    /// opcode predates `CAPS`; advertising the bit lets callers
    /// distinguish read-only providers (e.g. FAT32 v1, wasm
    /// fetch) from writable ones (linux) without trial-and-
    /// error.
    pub const WRITE:          u32 = 1 << 3;
    /// [`FSYNC`] (0x0905) — durability fence on an FD. As with
    /// `WRITE`, the opcode predates the capability bitmap and
    /// the bit is the discovery channel.
    pub const FSYNC:          u32 = 1 << 4;

    // Reserved — no opcodes assigned yet; providers MUST return
    // 0 until a future revision lands both the opcode and the
    // implementation in lockstep across the listed providers.
    /// Reserved for `UNLINK` (planned 0x090A).
    pub const UNLINK:         u32 = 1 << 5;
    /// Reserved for `TRUNCATE` (planned 0x090B).
    pub const TRUNCATE:       u32 = 1 << 6;
    /// Reserved for `MKDIR` (planned 0x090C).
    pub const MKDIR:          u32 = 1 << 7;
    /// Reserved for `RENAME` (planned 0x090D).
    pub const RENAME:         u32 = 1 << 8;
}
