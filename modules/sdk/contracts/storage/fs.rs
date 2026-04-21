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
