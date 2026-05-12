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
