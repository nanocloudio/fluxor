// Platform: linux host mounts (contract class 0x1F).
//
// Layer: platform/linux (host-specific). A node that publishes block devices
// to its own kernel (an NBD export of an encrypted volume) must mount the
// filesystem on them for its workloads. Mounting is a host-kernel mechanic,
// not a Fluxor one, so it lives in a host-scoped class, registered only by the
// linux platform; an unregistered class answers `ENOSYS`.
//
// The platform holds the policy, not the caller:
// - every mount point lies under one mount root the operator configures
//   (`FLUXOR_MOUNT_ROOT`); a caller names a directory relative to it, and a
//   path that climbs out (`..`, absolute) is refused;
// - the source must be a block device;
// - every mount is `nodev` and `nosuid`;
// - the answer is the kernel's errno, so a missing privilege is `EPERM`
//   rather than a mount(8) exit status that looks like any other failure;
// - a symlink inside the mount root is never followed: a directory path
//   through one is refused with `EINVAL`.
//
// MOUNT and UMOUNT wait on the device's I/O, and the device may be one this
// node serves itself, so neither blocks the caller: the first call starts
// the work and answers `EAGAIN`, and the caller asks again with the same
// argument (a later step) until the answer is the result. The platform bounds
// the work it holds: a caller has a few jobs in flight at once (a further
// request answers `EAGAIN` until one finishes), and an answer nobody collects
// is dropped after a time. Both operations are idempotent against the host's
// mount table, so a caller whose answer was dropped asks again and gets the
// answer the lost one carried.
//
// PROJECT, REMOVE_TREE, GROUP_TREE and MKDIR_MODE work on directories under
// the same root, with the same symlink refusal, off the caller's thread the
// same way. They give a host-process workload's files and directories a mode
// and a group and swap them atomically — the permission model the portable
// `fs` contract deliberately lacks — so no caller spawns a mode or removal
// tool for it.
//
// Gated by `requires_contract = "host_mount"` AND `platform_raw`. Making a
// filesystem and checking one are userland tools; run them through the
// process executor (`host_process::PROC_CLASS`).

/// Provider contract class for host mounts.
pub const CLASS: u16 = 0x001F;

/// The privileges this runtime holds for these ops, as a bit set:
/// [`PRIV_SYS_ADMIN`] (it may mount: `MOUNT`, `UMOUNT`, a memory-backed
/// `PROJECT`) and [`PRIV_CHOWN`] (it may give a file any group: `PROJECT`
/// and `GROUP_TREE` with a group the runtime is not a member of).
/// `handle = -1`, no argument.
pub const PRIV: u32 = 0x1F00;
/// [`PRIV`] bit: `CAP_SYS_ADMIN` is held.
pub const PRIV_SYS_ADMIN: i32 = 1 << 0;
/// [`PRIV`] bit: `CAP_CHOWN` is held.
pub const PRIV_CHOWN: i32 = 1 << 1;
/// Mount a block device. `arg = [dev_len:u16 LE][dir_len:u16 LE][fs_len:u8]
/// [flags:u8][dev][dir][fs]`: `dev` an absolute block-device path, `dir`
/// relative to the mount root (created when absent, parents included; the
/// directory itself is set to mode 0700), `fs` the filesystem type. Returns
/// 0, or a negative errno: `EPERM` without the privilege, `ENOTBLK` for a
/// source that is no block device, `EINVAL` for a directory outside the root
/// (or reached through a symlink), `EBUSY` for one holding a different mount;
/// `EAGAIN` while the mount runs or while the caller's jobs are all running.
/// A directory that already holds this device with the same access answers 0.
pub const MOUNT: u32 = 0x1F01;
/// Unmount. `arg = [dir]`, relative to the mount root. Returns 1 when it
/// unmounted, 0 when nothing was mounted there (also the answer to an
/// unmount whose earlier answer was dropped), or a negative errno (`EBUSY`,
/// `EPERM`, `EINVAL` for a path through a symlink) when it could not; `EAGAIN`
/// while the unmount runs or while the caller's jobs are all running.
///
/// What is unmounted is identified, not looked up: the directory's parent
/// is opened by the same walk as `MOUNT`'s and held; the mount at `dir` is
/// named by its mount id, read through that descriptor without following a
/// symlink; it must be mounted at exactly `dir` and be a mount `MOUNT` makes
/// — a block device's filesystem, `nodev` and `nosuid` — or the answer is
/// `EBUSY` (a projection's memory filesystem is `REMOVE_TREE`'s); and the
/// unmount names `dir` through the held parent, refusing a symlink. A
/// kernel that reports no mount id answers `ENOSYS`.
pub const UMOUNT: u32 = 0x1F02;
/// The mount root, written into `arg`. Returns its length, or `ENOSPC` when
/// `arg` is too short.
pub const ROOT: u32 = 0x1F03;

/// Project files into a directory under the mount root, replacing what an
/// earlier projection there put, atomically for a reader. `arg =
/// [dir_len:u16][dir][group:u32][flags:u8][count:u16][entry]×count`, then
/// `[size:u64]` with [`P_SIZE`] only; entry
/// `[path_len:u16][path][mode:u16][data_len:u32][data]`, little-endian.
///
/// - `dir` is relative to the mount root, created when absent (mode 0755).
/// - `path` is relative to `dir`, `/`-separated, no empty, `.` or `..`
///   component, its first component not starting with `..`; two entries may
///   not name the same path.
/// - Layout: every entry is written into a fresh `..<timestamp>` directory;
///   a temporary link to it is renamed over `..data`; each top-level name
///   is a link `name → ..data/name`, made when new and removed when no entry
///   carries it any more; the previous timestamp directory is removed. A
///   reader that resolves `..data` once (opens it, then the files beneath)
///   sees one projection whole, never a mix of two.
/// - A file's `mode` is masked to `0o777`: no setuid, setgid or sticky bit
///   is ever written to one. Directories are `0o755`. With a `group` other
///   than [`NO_GROUP`], every file and directory is group-owned by it, group
///   read is added to each file, and each directory gets the setgid bit
///   (`0o2755`); with [`P_READ_ONLY`], `0o440` is added to every file's
///   mode.
/// - [`P_MEMORY`] mounts a memory filesystem (`nosuid,nodev`) at `dir` the
///   first time; later projections write into it. A different mount already
///   at `dir` is `EBUSY`. The filesystem is bounded: it holds at most
///   `size` bytes ([`P_SIZE`]; less than the entries need is `ENOSPC`), or
///   without one 64 MiB or what the entries need when that is more — at
///   most 1 GiB either way (`E2BIG`) — and as many files as the entries
///   need plus one per page of room. While a later projection swaps in, the
///   bound is what the filesystem holds plus the new one's, and the new
///   one's again once the swap is done. Its pages are charged by the
///   kernel's memory accounting to whoever writes them: what `PROJECT`
///   writes to the runtime's cgroup, what a workload writes into a writable
///   projection to the workload's. An orchestrator that bounds a
///   projection by a workload's memory quota states it as `size`.
/// - [`P_SIZE`] (with [`P_MEMORY`] only, else `EINVAL`): `[size:u64]`
///   follows the last entry.
///
/// Returns 0, or a negative errno: `EINVAL` (malformed, a path that climbs
/// out, a symlink on the way to `dir`), `EEXIST` (a top-level name already
/// in `dir` that is not the projection's own `..data` link), `EPERM` (a group the
/// runtime may not give, a memory mount without `CAP_SYS_ADMIN`); `EAGAIN`
/// while it runs, as `MOUNT`.
pub const PROJECT: u32 = 0x1F04;
/// Remove a directory tree under the mount root. `arg = [dir]`, relative to
/// the root. The walk never follows a symlink (a link is removed, not what
/// it names) and never crosses into another mount: a memory filesystem a
/// `PROJECT` mounted inside (or at) `dir` is unmounted first, and any other
/// mount point inside answers `EBUSY` with nothing removed — a mounted
/// volume is never deleted through this op. Each projection mount is
/// unmounted as [`UMOUNT`] unmounts a volume: by its mount id, read through
/// the held parent directory, and only while that id is a projection's
/// memory filesystem at exactly that directory (else `EBUSY`). Returns 0
/// once the tree is gone (also when there was none), or a negative errno
/// (`EBUSY`, `EINVAL` for a path through a symlink, `EPERM`); `EAGAIN` while
/// it runs, as `MOUNT`.
pub const REMOVE_TREE: u32 = 0x1F05;
/// Give a directory tree under the mount root to a group. `arg =
/// [dir_len:u16][dir][group:u32][policy:u8]`: every file, directory and
/// link inside `dir` (and `dir` itself) is group-owned by `group`; files get
/// group read and write, directories group read, write and search and the
/// setgid bit, so what the workload creates later inherits the group. A
/// mount point inside `dir` is left alone (its own volume); symlinks are
/// never followed. `dir` itself may be a mount point — the volume being
/// prepared. `policy` [`GT_ALWAYS`] walks the whole tree;
/// [`GT_ON_ROOT_MISMATCH`] does nothing when `dir` already has the group,
/// the setgid bit and group read, write and search. Returns 0, or a
/// negative errno (`ENOENT`, `EINVAL`, `EPERM`); `EAGAIN` while it runs, as
/// `MOUNT`.
pub const GROUP_TREE: u32 = 0x1F06;

/// Make a directory under the mount root with an exact mode. `arg =
/// [dir_len:u16][dir][mode:u16]`, little-endian: `dir` relative to the mount
/// root, created when absent (missing parents mode 0755), every component
/// reached without following a symlink; an existing directory is kept and
/// given the mode. `mode` is permission bits only (`0o000..=0o777`), set
/// exactly — the runtime's umask does not apply — on the directory just
/// opened, never by a path looked up again; its owner and group are left as
/// they are. Returns 0, or a negative errno: `EINVAL` (malformed, a mode with
/// a setuid, setgid or sticky bit or any bit above them, a path that climbs
/// out, a symlink on the way to or at `dir`), `ENOTDIR` (a component that is
/// not a directory), `EPERM` (a directory the runtime may not change);
/// `EAGAIN` while it runs, as `MOUNT`.
pub const MKDIR_MODE: u32 = 0x1F07;

/// `MOUNT` flag: mount read-only.
pub const F_RDONLY: u8 = 1 << 0;
/// `PROJECT` group meaning none: ownership is left as created.
pub const NO_GROUP: u32 = 0xFFFF_FFFF;
/// `PROJECT` flag: back `dir` with a memory filesystem.
pub const P_MEMORY: u8 = 1 << 0;
/// `PROJECT` flag: the projection is read-only (`0o440` added to modes).
pub const P_READ_ONLY: u8 = 1 << 1;
/// `PROJECT` flag: a `[size:u64]` bound on the memory filesystem follows the
/// entries (with [`P_MEMORY`] only).
pub const P_SIZE: u8 = 1 << 2;
/// `GROUP_TREE` policy: always walk the whole tree.
pub const GT_ALWAYS: u8 = 0;
/// `GROUP_TREE` policy: walk only when `dir` itself does not already match.
pub const GT_ON_ROOT_MISMATCH: u8 = 1;
