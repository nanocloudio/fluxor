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
// Gated by `requires_contract = "host_mount"` AND `platform_raw`. Making a
// filesystem and checking one are userland tools; run them through the
// process executor (`host_process::PROC_CLASS`).

/// Provider contract class for host mounts.
pub const CLASS: u16 = 0x001F;

/// Whether this runtime may mount: 1 when it holds `CAP_SYS_ADMIN`, 0 when it
/// does not. `handle = -1`, no argument.
pub const PRIV: u32 = 0x1F00;
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
pub const UMOUNT: u32 = 0x1F02;
/// The mount root, written into `arg`. Returns its length, or `ENOSPC` when
/// `arg` is too short.
pub const ROOT: u32 = 0x1F03;

/// `MOUNT` flag: mount read-only.
pub const F_RDONLY: u8 = 1 << 0;
