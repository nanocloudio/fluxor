// ============================================================================
// Linux FS Provider — real file I/O via libc
// ============================================================================

use super::builtin_params::instance_state;
use crate::abi::fence::{DeviceId, Fence};
use crate::kernel::ipc::channel;

/// Stable device id for the Linux host's local filesystem. One
/// logical backing store from Fluxor's point of view, so a single
/// constant suffices.
const LINUX_FS_DEVICE_ID: DeviceId = 0x6c69_6e75_785f_6673; // "linux_fs"

/// File handle table mapping Fluxor handles to host file descriptors (for
/// files) or directory streams (for OPENDIR'd directories). Slot index is
/// the Fluxor handle the caller passes back through subsequent FS_READ /
/// FS_READDIR / FS_CLOSE calls.
///
/// This table is a hard ceiling on concurrent opens for the whole node,
/// not a per-consumer one, and exhausting it surfaces far from its cause:
/// the open fails, and whatever the caller could not open becomes a
/// failure in that caller's own terms. Sizing it generously is worth more
/// than the memory it saves.
///
/// A replicated-state consumer is the demanding shape — it holds a write-
/// ahead log open per group plus a couple of metadata slots, so roughly
/// three handles per group — and 256 leaves room for sixty-odd groups
/// alongside everything else a node has open. The cost is the static
/// table below: 256 `LinuxFileSlot`s at 96 bytes each, 24 KiB of BSS on
/// a platform that already maps a 96 MiB state arena.
const MAX_OPEN_FILES: usize = 256;

struct LinuxFileSlot {
    fd: i32,
    /// `*mut libc::DIR` cast to a usize so the static can be initialized
    /// in `const` context (raw pointers aren't const-defaultable). 0
    /// when the slot is a file slot; non-zero when it's a dir slot
    /// opened via FS_OPENDIR. CLOSE picks the right libc tear-down by
    /// inspecting this field.
    dir_ptr: usize,
    in_use: bool,
    /// Strongest `Fence` the most recent successful op on this slot
    /// achieved. Each dispatcher arm writes this before returning
    /// success; `provider_query(handle, query_key::LAST_FENCE, …)`
    /// reads it back and encodes it on the wire.
    last_fence: Fence,
    /// Who opened the slot. Only that owner reaches it: a handle names a
    /// slot, and a slot answers its opener alone.
    owner: crate::kernel::workload::owner::OwnerHandle,
    /// Bumped each time the slot is claimed and carried in the handle, so a
    /// handle kept past its close names no slot (`slot_index`), never the
    /// file that took the slot next — another module's, as often as not.
    generation: u32,
}

/// Bits of a handle that name the slot; the rest above them, up to the
/// tag, carry the slot's generation.
const SLOT_BITS: u32 = 8;
const _: () = assert!(MAX_OPEN_FILES <= 1 << SLOT_BITS);
const GEN_MASK: u32 = (crate::abi::kernel_abi::fd::SLOT_MASK as u32) >> SLOT_BITS;

/// The handle for slot `idx` at its current generation.
fn slot_handle(idx: usize, generation: u32) -> i32 {
    use crate::kernel::ipc::fd::{tag_fd, FD_TAG_FS};
    tag_fd(FD_TAG_FS, ((generation << SLOT_BITS) | idx as u32) as i32)
}

/// The slot a handle names, while it is the slot's current occupancy; an
/// index past the table otherwise, which every arm refuses.
fn slot_index(handle: i32) -> usize {
    if handle < 0 {
        return usize::MAX;
    }
    let inner = crate::kernel::ipc::fd::slot_of(handle) as u32;
    let idx = (inner & ((1 << SLOT_BITS) - 1)) as usize;
    let generation = inner >> SLOT_BITS;
    // SAFETY: single-threaded platform dispatch; `idx` is bounds-checked.
    let current = unsafe {
        (*core::ptr::addr_of!(LINUX_FILES))
            .get(idx)
            .map(|s| s.generation)
    };
    if current == Some(generation) {
        idx
    } else {
        usize::MAX
    }
}

/// The next generation of slot `idx`: never 0, so no handle is ever 0.
unsafe fn next_generation(files: &[LinuxFileSlot], idx: usize) -> u32 {
    let g = (files[idx].generation.wrapping_add(1)) & GEN_MASK;
    if g == 0 {
        1
    } else {
        g
    }
}

static mut LINUX_FILES: [LinuxFileSlot; MAX_OPEN_FILES] = {
    const EMPTY: LinuxFileSlot = LinuxFileSlot {
        fd: -1,
        dir_ptr: 0,
        in_use: false,
        last_fence: Fence::Volatile,
        owner: crate::kernel::workload::owner::OWNER_SYSTEM,
        generation: 0,
    };
    [EMPTY; MAX_OPEN_FILES]
};

/// Whether `slot` is open and its caller's: the opener alone reaches a slot.
fn owned(slot: &LinuxFileSlot) -> bool {
    slot.in_use && slot.owner == crate::kernel::exec::scheduler::caller_owner()
}

/// A free slot `owner` may take: any, for the system; within its quota, for
/// a workload.
fn free_slot_for(
    files: &[LinuxFileSlot],
    owner: crate::kernel::workload::owner::OwnerHandle,
) -> Option<usize> {
    if !owner.is_system()
        && files
            .iter()
            .filter(|s| s.in_use && s.owner == owner)
            .count()
            >= crate::kernel::workload::storage::OWNER_MAX_OPEN_FILES
    {
        return None;
    }
    files.iter().position(|s| !s.in_use)
}

/// Claim a file slot for `fd` on behalf of `owner`. The tagged handle, or
/// `ENOMEM` with `fd` closed when the table, or the owner's share of it, is
/// full.
unsafe fn claim_file_slot(fd: i32, owner: crate::kernel::workload::owner::OwnerHandle) -> i32 {
    use crate::kernel::sys::errno;
    let files = &mut *core::ptr::addr_of_mut!(LINUX_FILES);
    let Some(slot_idx) = free_slot_for(files, owner) else {
        libc::close(fd);
        return errno::ENOMEM;
    };
    let generation = next_generation(files, slot_idx);
    files[slot_idx] = LinuxFileSlot {
        fd,
        dir_ptr: 0,
        in_use: true,
        last_fence: Fence::Volatile,
        owner,
        generation,
    };
    slot_handle(slot_idx, generation)
}

/// Claim a directory slot for `dir` on behalf of `owner`.
unsafe fn claim_dir_slot(
    dir: *mut libc::DIR,
    owner: crate::kernel::workload::owner::OwnerHandle,
) -> i32 {
    use crate::kernel::sys::errno;
    let files = &mut *core::ptr::addr_of_mut!(LINUX_FILES);
    let Some(slot_idx) = free_slot_for(files, owner) else {
        libc::closedir(dir);
        return errno::ENOMEM;
    };
    let generation = next_generation(files, slot_idx);
    files[slot_idx] = LinuxFileSlot {
        fd: -1,
        dir_ptr: dir as usize,
        in_use: true,
        last_fence: Fence::Volatile,
        owner,
        generation,
    };
    slot_handle(slot_idx, generation)
}

/// The path-taking `fs` ops for a workload: each resolves beneath the
/// owner's files root (`owner_root`), so the owner reaches what it owns and
/// nothing else, and each keeps the owner's per-inode charge in step with
/// the inodes it creates, changes and removes. A hard link is not offered:
/// one inode under two names would be charged once and could be released
/// twice. `None` for an op that works on a handle, which the shared arms
/// serve for every owner.
///
/// # Safety
/// As `linux_fs_dispatch`.
unsafe fn tenant_fs_path_op(
    owner: crate::kernel::workload::owner::OwnerHandle,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> Option<i32> {
    use crate::abi::contracts::storage::fs as dev_fs;
    use crate::kernel::sys::errno;
    use crate::platform::linux::owner_root as root;

    let path_arg = |ptr: *const u8, len: usize| -> Result<&[u8], i32> {
        if ptr.is_null() || len == 0 {
            return Err(errno::EINVAL);
        }
        if len > LINUX_FS_PATH_MAX {
            return Err(errno::E2BIG);
        }
        Ok(core::slice::from_raw_parts(ptr, len))
    };
    Some(match opcode {
        dev_fs::OPEN => {
            let path = match path_arg(arg, arg_len) {
                Ok(p) => p,
                Err(e) => return Some(e),
            };
            // As the host's OPEN: read-write on an existing file, never a
            // create; read-only when the file cannot be written.
            let mut fd = root::open_beneath(owner, path, libc::O_RDWR, 0);
            if fd < 0 {
                fd = root::open_beneath(owner, path, libc::O_RDONLY, 0);
                if fd < 0 {
                    return Some(fd);
                }
            }
            claim_file_slot(fd, owner)
        }
        dev_fs::OPEN_CREATE => {
            let path = match path_arg(arg, arg_len) {
                Ok(p) => p,
                Err(e) => return Some(e),
            };
            let fd = root::open_beneath(owner, path, libc::O_RDWR, 0);
            if fd >= 0 {
                return Some(claim_file_slot(fd, owner));
            }
            if fd != errno::ENOENT {
                return Some(fd);
            }
            // A new name: its entry is charged before it exists.
            if !root::reserve(owner, crate::kernel::workload::storage::ENTRY_COST) {
                return Some(errno::ENOSPC);
            }
            let fd = root::open_beneath(
                owner,
                path,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                0o600,
            );
            root::unreserve(owner, crate::kernel::workload::storage::ENTRY_COST);
            if fd < 0 {
                return Some(fd);
            }
            if let Some(st) = root::stat_fd(fd) {
                root::charge_inode(owner, st.st_ino, root::inode_cost(&st), false);
            }
            claim_file_slot(fd, owner)
        }
        dev_fs::OPENDIR => {
            let path = match path_arg(arg, arg_len) {
                Ok(p) => p,
                Err(e) => return Some(e),
            };
            let fd = root::open_beneath(owner, path, libc::O_RDONLY | libc::O_DIRECTORY, 0);
            if fd < 0 {
                return Some(fd);
            }
            let dir = libc::fdopendir(fd);
            if dir.is_null() {
                libc::close(fd);
                return Some(errno::ENODEV);
            }
            claim_dir_slot(dir, owner)
        }
        dev_fs::UNLINK => {
            let path = match path_arg(arg, arg_len) {
                Ok(p) => p,
                Err(e) => return Some(e),
            };
            let (dirfd, name) = match root::parent_beneath(owner, path) {
                Ok(v) => v,
                Err(e) => return Some(e),
            };
            let st = root::stat_at(dirfd, &name);
            let rc = libc::unlinkat(dirfd, name.as_ptr() as *const libc::c_char, 0);
            let err = *libc::__errno_location();
            libc::close(dirfd);
            if rc < 0 {
                return Some(-err);
            }
            // The name is gone. An inode a handle still holds keeps its
            // charge until that handle closes.
            if let Some(st) = st {
                if !open_by(owner, st.st_ino) {
                    root::charge_inode(owner, st.st_ino, 0, false);
                }
            }
            errno::OK
        }
        dev_fs::MKDIR => {
            let path = match path_arg(arg, arg_len) {
                Ok(p) => p,
                Err(e) => return Some(e),
            };
            let (dirfd, name) = match root::parent_beneath(owner, path) {
                Ok(v) => v,
                Err(e) => return Some(e),
            };
            if !root::reserve(owner, crate::kernel::workload::storage::ENTRY_COST) {
                libc::close(dirfd);
                return Some(errno::ENOSPC);
            }
            let rc = libc::mkdirat(dirfd, name.as_ptr() as *const libc::c_char, 0o755);
            let err = *libc::__errno_location();
            root::unreserve(owner, crate::kernel::workload::storage::ENTRY_COST);
            let made = (rc == 0).then(|| root::stat_at(dirfd, &name)).flatten();
            libc::close(dirfd);
            if let Some(st) = made {
                root::charge_inode(
                    owner,
                    st.st_ino,
                    crate::kernel::workload::storage::ENTRY_COST,
                    false,
                );
            }
            // Idempotent, as the host's MKDIR.
            if rc < 0 && err != libc::EEXIST {
                -err
            } else {
                errno::OK
            }
        }
        dev_fs::RMDIR => {
            let path = match path_arg(arg, arg_len) {
                Ok(p) => p,
                Err(e) => return Some(e),
            };
            let (dirfd, name) = match root::parent_beneath(owner, path) {
                Ok(v) => v,
                Err(e) => return Some(e),
            };
            let st = root::stat_at(dirfd, &name);
            let rc = libc::unlinkat(
                dirfd,
                name.as_ptr() as *const libc::c_char,
                libc::AT_REMOVEDIR,
            );
            let err = *libc::__errno_location();
            let out = if rc < 0 {
                -err
            } else {
                if let Some(st) = st {
                    root::charge_inode(owner, st.st_ino, 0, false);
                }
                if libc::fsync(dirfd) < 0 {
                    -*libc::__errno_location()
                } else {
                    errno::OK
                }
            };
            libc::close(dirfd);
            out
        }
        dev_fs::LINK => errno::ENOSYS,
        dev_fs::READLINK => {
            if arg.is_null() || arg_len < 2 {
                return Some(errno::EINVAL);
            }
            let path_len = usize::from(u16::from_le_bytes([*arg, *arg.add(1)]));
            if path_len == 0 || arg_len < 2 + path_len {
                return Some(errno::EINVAL);
            }
            let path = match path_arg(arg.add(2), path_len) {
                Ok(p) => p,
                Err(e) => return Some(e),
            };
            let fd = root::open_beneath(owner, path, libc::O_PATH | libc::O_NOFOLLOW, 0);
            if fd < 0 {
                return Some(fd);
            }
            let mut target = [0u8; 512];
            let n = libc::readlinkat(
                fd,
                c"".as_ptr(),
                target.as_mut_ptr() as *mut libc::c_char,
                target.len(),
            );
            let err = *libc::__errno_location();
            libc::close(fd);
            if n < 0 {
                return Some(-err);
            }
            let n = n as usize;
            if n == target.len() || n > arg_len {
                return Some(errno::E2BIG);
            }
            core::ptr::copy_nonoverlapping(target.as_ptr(), arg, n);
            n as i32
        }
        dev_fs::TRUNCATE => {
            if arg.is_null() || arg_len < 9 {
                return Some(errno::EINVAL);
            }
            let a = core::slice::from_raw_parts(arg, arg_len);
            let len = u64::from_le_bytes([a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]]);
            if len > i64::MAX as u64 {
                return Some(errno::EINVAL);
            }
            let path = match path_arg(arg.add(8), arg_len - 8) {
                Ok(p) => p,
                Err(e) => return Some(e),
            };
            let fd = root::open_beneath(owner, path, libc::O_WRONLY, 0);
            if fd < 0 {
                return Some(fd);
            }
            let out = match root::stat_fd(fd) {
                None => -*libc::__errno_location(),
                Some(st) if st.st_mode & libc::S_IFMT == libc::S_IFDIR => -libc::EISDIR,
                // Shrink only, as the host's TRUNCATE.
                Some(st) if len > st.st_size as u64 => errno::EINVAL,
                Some(st) => {
                    if libc::ftruncate(fd, len as i64) < 0 {
                        -*libc::__errno_location()
                    } else {
                        settle_inode(owner, fd, st.st_ino);
                        errno::OK
                    }
                }
            };
            libc::close(fd);
            out
        }
        dev_fs::FSYNC_NAME => {
            let path = match path_arg(arg, arg_len) {
                Ok(p) => p,
                Err(e) => return Some(e),
            };
            let (dirfd, _) = match root::parent_beneath(owner, path) {
                Ok(v) => v,
                Err(e) => return Some(e),
            };
            let out = if libc::fsync(dirfd) < 0 {
                -*libc::__errno_location()
            } else {
                errno::OK
            };
            libc::close(dirfd);
            out
        }
        dev_fs::RENAME => {
            let Some((src, src_len, dst, dst_len)) = two_paths(arg, arg_len) else {
                return Some(errno::EINVAL);
            };
            let (d1, n1) = match root::parent_beneath(owner, &src[..src_len]) {
                Ok(v) => v,
                Err(e) => return Some(e),
            };
            let (d2, n2) = match root::parent_beneath(owner, &dst[..dst_len]) {
                Ok(v) => v,
                Err(e) => {
                    libc::close(d1);
                    return Some(e);
                }
            };
            let moved = root::stat_at(d1, &n1);
            let replaced = root::stat_at(d2, &n2);
            // Atomic against a reader, durable once both parents are synced,
            // the destination first.
            let out = if libc::renameat(
                d1,
                n1.as_ptr() as *const libc::c_char,
                d2,
                n2.as_ptr() as *const libc::c_char,
            ) < 0
            {
                -*libc::__errno_location()
            } else {
                // The entry the destination named, if any, is gone with its
                // charge.
                if let (Some(m), Some(r)) = (moved, replaced) {
                    if m.st_ino != r.st_ino && !open_by(owner, r.st_ino) {
                        root::charge_inode(owner, r.st_ino, 0, false);
                    }
                }
                if libc::fsync(d2) < 0 || libc::fsync(d1) < 0 {
                    -*libc::__errno_location()
                } else {
                    errno::OK
                }
            };
            libc::close(d1);
            libc::close(d2);
            out
        }
        _ => return None,
    })
}

/// Close a file slot's descriptor. A workload's inode whose last name went
/// while the slot held it open gives its charge back now.
unsafe fn close_file_slot(slot: &mut LinuxFileSlot) {
    use crate::platform::linux::owner_root as root;
    if root::rooted(slot.owner) {
        if let Some(st) = root::stat_fd(slot.fd) {
            if st.st_nlink == 0 {
                root::charge_inode(slot.owner, st.st_ino, 0, false);
            }
        }
    }
    libc::close(slot.fd);
    slot.fd = -1;
}

/// Close every slot `owner` holds. Part of the platform's owner-release
/// hook: what a workload opened goes with it.
///
/// # Safety
/// Single-threaded platform dispatch only.
pub unsafe fn release_owner_files(owner: crate::kernel::workload::owner::OwnerHandle) {
    let files = &mut *core::ptr::addr_of_mut!(LINUX_FILES);
    for slot in files.iter_mut().filter(|s| s.in_use && s.owner == owner) {
        if slot.dir_ptr != 0 {
            libc::closedir(slot.dir_ptr as *mut libc::DIR);
            slot.dir_ptr = 0;
        } else if slot.fd >= 0 {
            libc::close(slot.fd);
            slot.fd = -1;
        }
        slot.in_use = false;
        slot.last_fence = Fence::Volatile;
    }
}

/// Whether a slot `owner` holds is open on inode `ino`.
unsafe fn open_by(owner: crate::kernel::workload::owner::OwnerHandle, ino: u64) -> bool {
    let files = &*core::ptr::addr_of!(LINUX_FILES);
    files.iter().any(|s| {
        s.in_use
            && s.owner == owner
            && s.fd >= 0
            && crate::platform::linux::owner_root::stat_fd(s.fd).is_some_and(|st| st.st_ino == ino)
    })
}

/// Charge `owner` what the inode `fd` is open on holds now, whatever it was
/// charged before.
unsafe fn settle_inode(owner: crate::kernel::workload::owner::OwnerHandle, fd: i32, ino: u64) {
    use crate::platform::linux::owner_root as root;
    if let Some(st) = root::stat_fd(fd) {
        root::charge_inode(owner, ino, root::inode_cost(&st), false);
    }
}

/// Record the strongest `Fence` the provider just achieved for
/// `slot`. The dispatcher's i32 return carries errno / count; the
/// fence is surfaced per-handle and read back via
/// `provider_query(handle, query_key::LAST_FENCE, …)`. Every op
/// writes its fence on success — `Volatile` reads overwrite a prior
/// `LocalDurable` so the slot never reports a stale durability
/// claim.
unsafe fn record_slot_fence(slot: usize, fence: Fence) {
    if slot >= MAX_OPEN_FILES {
        return;
    }
    let files = &mut *core::ptr::addr_of_mut!(LINUX_FILES);
    files[slot].last_fence = fence;
}

/// Read back the fence advertised for `slot`'s most recent
/// successful op. Returns `None` for unbound slots; the kernel
/// introspection path treats that as `E_NOSYS`.
pub fn slot_fence(handle: i32) -> Option<Fence> {
    let slot = slot_index(handle);
    if slot >= MAX_OPEN_FILES {
        return None;
    }
    // SAFETY: `slot` is bounds-checked above; `LINUX_FILES` is a static
    // array of plain-old-data `OpenFile` entries owned by this module.
    unsafe {
        let files = &*core::ptr::addr_of!(LINUX_FILES);
        if !owned(&files[slot]) {
            return None;
        }
        Some(files[slot].last_fence)
    }
}

/// Maximum FS path length the linux provider accepts. One byte
/// reserved for the trailing NUL so libc's path-arg primitives
/// can be called directly. Callers passing a longer path get
/// `E2BIG` rather than a silently truncated open.
const LINUX_FS_PATH_MAX: usize = 255;

/// Decode the two-path argument `LINK`, `RENAME` and friends share:
/// `[a_len: u16 LE][a][b_len: u16 LE][b]`, validating both as filesystem
/// paths and returning them NUL-terminated.
///
/// One decoder, because two copies of these offsets is two chances to
/// validate one path and not the other — and the unvalidated one is the
/// interesting half to an attacker.
///
/// # Safety
/// `arg` must point at `arg_len` readable bytes.
unsafe fn two_paths(
    arg: *const u8,
    arg_len: usize,
) -> Option<([u8; 256], usize, [u8; 256], usize)> {
    if arg.is_null() || arg_len < 4 {
        return None;
    }
    let bytes = core::slice::from_raw_parts(arg, arg_len);
    let a_len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
    if arg_len < 2 + a_len + 2 {
        return None;
    }
    let b_off = 2 + a_len + 2;
    let b_len = u16::from_le_bytes([bytes[2 + a_len], bytes[3 + a_len]]) as usize;
    if arg_len < b_off + b_len {
        return None;
    }
    let mut a = [0u8; 256];
    let mut b = [0u8; 256];
    validate_fs_path(arg.add(2), a_len, &mut a).ok()?;
    validate_fs_path(arg.add(b_off), b_len, &mut b).ok()?;
    Some((a, a_len, b, b_len))
}

/// Validate + copy a UTF-8 path argument from a contract caller
/// into `out` and NUL-terminate it for libc.
///
/// Returns the path length in bytes (NOT counting the NUL) on
/// success, or a negative errno:
///
///   - `EINVAL` if the buffer is null, empty, or contains an
///     interior NUL byte (interior NULs let an attacker submit
///     `evil\0../etc/passwd` and have libc see `evil` while a
///     downstream policy check saw the longer string),
///   - `E2BIG` if the path length exceeds `LINUX_FS_PATH_MAX`.
///
/// Centralised so OPEN, OPEN_CREATE, and OPENDIR get identical path
/// validation. Per-arm length handling is how one of them ends up
/// truncating an overlong path where the others reject it, which turns a
/// caller's mistake into a silently different file.
///
/// # Safety
/// `arg` must point at `arg_len` readable bytes.
unsafe fn validate_fs_path(
    arg: *const u8,
    arg_len: usize,
    out: &mut [u8; 256],
) -> Result<usize, i32> {
    use crate::kernel::sys::errno;
    if arg.is_null() || arg_len == 0 {
        return Err(errno::EINVAL);
    }
    if arg_len > LINUX_FS_PATH_MAX {
        return Err(errno::E2BIG);
    }
    let bytes = core::slice::from_raw_parts(arg, arg_len);
    let mut i = 0;
    while i < arg_len {
        if bytes[i] == 0 {
            // Interior NUL — refuse rather than passing a
            // truncated path to libc. POSIX paths can't contain
            // NULs, so an interior NUL is always either a bug
            // or a path-splicing attack.
            return Err(errno::EINVAL);
        }
        i += 1;
    }
    out[..arg_len].copy_from_slice(bytes);
    out[arg_len] = 0;
    Ok(arg_len)
}

/// The directory component of `path` as a NUL-terminated buffer, or `"."`
/// when the path has no separator. Trailing separators are ignored so
/// `"a/b/"` and `"a/b"` share a parent.
fn parent_of(path: &[u8]) -> [u8; 256] {
    let mut out = [0u8; 256];
    let mut end = path.len();
    while end > 1 && path[end - 1] == b'/' {
        end -= 1;
    }
    let mut cut = None;
    let mut i = end;
    while i > 0 {
        i -= 1;
        if path[i] == b'/' {
            cut = Some(i);
            break;
        }
    }
    match cut {
        // A leading-slash path's parent is the root itself.
        Some(0) => {
            out[0] = b'/';
        }
        Some(n) => out[..n].copy_from_slice(&path[..n]),
        None => out[0] = b'.',
    }
    out
}

/// `fsync(2)` the directory holding `path`, making the entry that names it
/// durable. This is what turns a created, removed, or renamed name into a
/// name a later mount can find; file `fsync` never does. Returns
/// `errno::OK` or a negative errno.
///
/// # Safety
/// Calls libc directly; `path` must be a valid slice with no interior NUL
/// (guaranteed by `validate_fs_path`).
unsafe fn fsync_parent_dir(path: &[u8]) -> i32 {
    use crate::kernel::sys::errno;
    let dir = parent_of(path);
    let fd = libc::open(
        dir.as_ptr() as *const libc::c_char,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
    );
    if fd < 0 {
        return -*libc::__errno_location();
    }
    let rc = libc::fsync(fd);
    let err = if rc < 0 {
        -*libc::__errno_location()
    } else {
        errno::OK
    };
    libc::close(fd);
    err
}

/// FS provider dispatch.
///
/// `OPEN` and `OPENDIR` self-tag their returns with `FD_TAG_FS` so
/// the kernel resolves the contract from the handle via
/// `fd_tag_contract`. Inbound ops arrive with the tag stripped by
/// the FS vtable wrapper, so `handle` here is the raw slot index.
/// # Safety
/// Single-threaded platform dispatch only: touches `static mut` provider
/// state without synchronization. `arg` must be null or valid for reads
/// and writes of `arg_len` bytes for the duration of the call.
pub unsafe fn linux_fs_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::contracts::storage::fs as dev_fs;
    use crate::abi::fence as dev_fence;
    use crate::kernel::sys::errno;

    // Cross-cutting fence-introspection opcode. Public surface:
    // `provider_query(handle, query_key::LAST_FENCE, …)`. The
    // kernel forwards it as `provider_call(handle, QUERY_OP, …)`
    // so the FS vtable wrapper strips the FD tag before this
    // dispatcher sees the slot.
    if opcode == dev_fence::QUERY_OP {
        if arg.is_null() || arg_len < dev_fence::WIRE_MAX_LEN {
            return errno::EINVAL;
        }
        let Some(fence) = slot_fence(handle) else {
            return errno::ENOSYS;
        };
        let buf = core::slice::from_raw_parts_mut(arg, arg_len);
        return match fence.encode(buf) {
            Some(n) => n as i32,
            None => errno::EINVAL,
        };
    }

    // A workload names paths inside a root of its own; the host's paths are
    // the node's, and those of an owner acting with the node's authority.
    // Slots are stamped with the caller's own owner either way: what it
    // opened goes with it.
    let owner = crate::kernel::exec::scheduler::caller_owner();
    let rooted = crate::platform::linux::owner_root::rooted(owner);

    // FS capability bitmap (modules/sdk/contracts/storage/fs.rs::CAPS).
    // Linux implements the full read-tier, the write-tier, both
    // name-publication ops (RENAME 0x090D, FSYNC_NAME 0x0912) and TRUNCATE.
    // FSYNC_ASYNC stays clear: this provider fences with a blocking
    // `fsync(2)`. A workload's root offers no hard links.
    if opcode == dev_fs::CAPS {
        if arg.is_null() || arg_len < 4 {
            return errno::EINVAL;
        }
        let caps: u32 = dev_fs::caps::OPEN
            | dev_fs::caps::OPENDIR
            | dev_fs::caps::OPEN_CREATE
            | dev_fs::caps::WRITE
            | dev_fs::caps::FSYNC
            | dev_fs::caps::UNLINK
            | dev_fs::caps::MKDIR
            | dev_fs::caps::PREALLOCATE
            | dev_fs::caps::RENAME
            | dev_fs::caps::TRUNCATE
            | dev_fs::caps::FSYNC_NAME
            // The host filesystem has a real object model and `fstat`
            // answers all of it, plus `rmdir(2)`, `link(2)` and
            // `readlink(2)`.
            | dev_fs::caps::STAT_OBJECT
            | dev_fs::caps::RMDIR
            | dev_fs::caps::LINK
            | dev_fs::caps::SYMLINK;
        let caps = if rooted {
            caps & !dev_fs::caps::LINK
        } else {
            caps
        };
        let bytes = caps.to_le_bytes();
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), arg, 4);
        return 4;
    }

    // Handle ops below serve both, each slot its opener alone.
    if rooted {
        if let Some(rc) = tenant_fs_path_op(owner, opcode, arg, arg_len) {
            return rc;
        }
    }

    match opcode {
        dev_fs::OPEN => {
            if arg.is_null() || arg_len == 0 {
                return errno::EINVAL;
            }
            let files = &mut *core::ptr::addr_of_mut!(LINUX_FILES);
            let slot_idx = files.iter().position(|s| !s.in_use);
            let slot_idx = match slot_idx {
                Some(i) => i,
                None => return errno::ENOMEM,
            };

            let mut path_buf = [0u8; 256];
            if let Err(e) = validate_fs_path(arg, arg_len, &mut path_buf) {
                return e;
            }

            // Open policy: read-write on existing files, never auto-
            // create. `FS_OPEN` carries no flags, so the caller cannot
            // say "I need to write" versus "I'm just reading". Creating
            // on open would answer a missing file with an empty one
            // persisted on disk (a typo'd `GET /api/list/nope.png` would
            // 200), so a missing file is ENOENT and the http handler
            // emits 404.
            let fd_raw = libc::open(
                path_buf.as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_CLOEXEC,
                0,
            );
            if fd_raw < 0 {
                // Fall back to read-only (covers files we can read
                // but not write, e.g. read-only-mounted assets).
                let fd_raw = libc::open(
                    path_buf.as_ptr() as *const libc::c_char,
                    libc::O_RDONLY | libc::O_CLOEXEC,
                    0,
                );
                if fd_raw < 0 {
                    // Preserve absence versus permission/I/O failure: storage consumers
                    // must not initialise a new world after a failed existing-file read.
                    return -*libc::__errno_location();
                }
                let _ = slot_idx;
                // FS handles carry their contract in the tag; the
                // vtable wrapper strips it on re-entry.
                return claim_file_slot(fd_raw, owner);
            }
            let _ = slot_idx;
            claim_file_slot(fd_raw, owner)
        }
        dev_fs::OPEN_CREATE => {
            let mut path_buf = [0u8; 256];
            if let Err(e) = validate_fs_path(arg, arg_len, &mut path_buf) {
                return e;
            }
            let files = &mut *core::ptr::addr_of_mut!(LINUX_FILES);
            let slot_idx = files.iter().position(|s| !s.in_use);
            let slot_idx = match slot_idx {
                Some(i) => i,
                None => return errno::ENOMEM,
            };
            // O_RDWR|O_CREAT, mode 0600. Distinct opcode from
            // OPEN — callers opt in to the create-on-missing
            // behaviour so OPEN keeps its "loud on missing"
            // policy (see comment on the OPEN arm above).
            let fd_raw = libc::open(
                path_buf.as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC,
                0o600,
            );
            if fd_raw < 0 {
                return errno::ENODEV;
            }
            let _ = slot_idx;
            claim_file_slot(fd_raw, owner)
        }
        dev_fs::UNLINK => {
            let mut path_buf = [0u8; 256];
            if let Err(e) = validate_fs_path(arg, arg_len, &mut path_buf) {
                return e;
            }
            let rc = libc::unlink(path_buf.as_ptr() as *const libc::c_char);
            if rc < 0 {
                -*libc::__errno_location()
            } else {
                errno::OK
            }
        }
        dev_fs::MKDIR => {
            let mut path_buf = [0u8; 256];
            if let Err(e) = validate_fs_path(arg, arg_len, &mut path_buf) {
                return e;
            }
            // Idempotent: an existing directory is success (scp -r sends a `D` per
            // level and may re-create; callers can `mkdir` the same path twice).
            let rc = libc::mkdir(path_buf.as_ptr() as *const libc::c_char, 0o755);
            if rc < 0 {
                let raw = *libc::__errno_location();
                if raw == libc::EEXIST {
                    errno::OK
                } else {
                    -raw
                }
            } else {
                errno::OK
            }
        }
        dev_fs::RMDIR => {
            let mut path_buf = [0u8; 256];
            if let Err(e) = validate_fs_path(arg, arg_len, &mut path_buf) {
                return e;
            }
            // Not idempotent, unlike MKDIR above: "the directory is gone" and
            // "the directory was never there" are the same end state, but a
            // caller removing a path it believes it created wants to hear
            // that it was not there.
            if libc::rmdir(path_buf.as_ptr() as *const libc::c_char) < 0 {
                return -*libc::__errno_location();
            }
            // The removal is a change to the PARENT's directory entry, so
            // that is what has to reach media for the name to stay gone.
            fsync_parent_dir(&path_buf[..arg_len])
        }
        dev_fs::LINK => {
            let Some((existing, existing_len, new, new_len)) = two_paths(arg, arg_len) else {
                return errno::EINVAL;
            };
            // A directory hard link is refused by the kernel too, but saying
            // so here means the caller gets the contract's errno rather than
            // whatever the platform happens to raise.
            let mut st: libc::stat = core::mem::zeroed();
            if libc::stat(existing.as_ptr() as *const libc::c_char, &mut st) == 0
                && st.st_mode & libc::S_IFMT == libc::S_IFDIR
            {
                return errno::EISDIR;
            }
            if libc::link(
                existing.as_ptr() as *const libc::c_char,
                new.as_ptr() as *const libc::c_char,
            ) < 0
            {
                return -*libc::__errno_location();
            }
            let _ = existing_len;
            // Minted, not fenced — the contract's own rule. The caller
            // publishes with FSYNC_NAME on the new path.
            let _ = new_len;
            errno::OK
        }
        dev_fs::READLINK => {
            // `[path_len: u16][path]`, with `arg_len` sizing the OUTPUT
            // buffer. The two are different numbers: a caller reading a long
            // target through a short path would otherwise be told its own
            // path length is the limit.
            if arg.is_null() || arg_len < 2 {
                return errno::EINVAL;
            }
            let path_len = usize::from(u16::from_le_bytes([*arg, *arg.add(1)]));
            if path_len == 0 || arg_len < 2 + path_len {
                return errno::EINVAL;
            }
            let mut path_buf = [0u8; 256];
            if let Err(e) = validate_fs_path(arg.add(2), path_len, &mut path_buf) {
                return e;
            }
            let mut target = [0u8; 512];
            let n = libc::readlink(
                path_buf.as_ptr() as *const libc::c_char,
                target.as_mut_ptr() as *mut libc::c_char,
                target.len(),
            );
            if n < 0 {
                return -*libc::__errno_location();
            }
            let n = n as usize;
            // `readlink(2)` truncates silently when the buffer is short, and
            // a truncated path is a different path. Refuse rather than hand
            // back a name that resolves somewhere else.
            if n == target.len() {
                return errno::E2BIG;
            }
            if n > arg_len {
                return errno::E2BIG;
            }
            core::ptr::copy_nonoverlapping(target.as_ptr(), arg, n);
            n as i32
        }
        dev_fs::TRUNCATE => {
            // `[len: u64 LE][path]`.
            if arg.is_null() || arg_len < 9 {
                return errno::EINVAL;
            }
            let a = core::slice::from_raw_parts(arg, arg_len);
            let len = u64::from_le_bytes([a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]]);
            if len > i64::MAX as u64 {
                return errno::EINVAL;
            }
            let mut path_buf = [0u8; 256];
            if let Err(e) = validate_fs_path(arg.add(8), arg_len - 8, &mut path_buf) {
                return e;
            }
            // Shrink only, matching the contract. `truncate(2)` would happily
            // grow the file into a sparse tail, which is exactly the
            // behaviour the contract excludes: it publishes storage the file
            // never wrote as its contents.
            let mut st: libc::stat = core::mem::zeroed();
            if libc::stat(path_buf.as_ptr() as *const libc::c_char, &mut st) < 0 {
                return -*libc::__errno_location();
            }
            if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
                return -libc::EISDIR;
            }
            if len > st.st_size as u64 {
                return errno::EINVAL;
            }
            if libc::truncate(path_buf.as_ptr() as *const libc::c_char, len as i64) < 0 {
                return -*libc::__errno_location();
            }
            errno::OK
        }
        dev_fs::FSYNC_NAME => {
            let mut path_buf = [0u8; 256];
            let len = match validate_fs_path(arg, arg_len, &mut path_buf) {
                Ok(n) => n,
                Err(e) => return e,
            };
            fsync_parent_dir(&path_buf[..len])
        }
        dev_fs::RENAME => {
            let Some((src_buf, src_len, dst_buf, dst_len)) = two_paths(arg, arg_len) else {
                return errno::EINVAL;
            };
            // `rename(2)` is atomic against a concurrent reader: the
            // destination name resolves to the old inode or the new one,
            // never to neither. It is NOT durable on return, so both
            // parents are fsynced before the fence is advertised — the
            // destination first, since that is the name a recovering
            // consumer looks for.
            if libc::rename(
                src_buf.as_ptr() as *const libc::c_char,
                dst_buf.as_ptr() as *const libc::c_char,
            ) < 0
            {
                return -*libc::__errno_location();
            }
            let rc = fsync_parent_dir(&dst_buf[..dst_len]);
            if rc != errno::OK {
                return rc;
            }
            let src_parent = parent_of(&src_buf[..src_len]);
            let dst_parent = parent_of(&dst_buf[..dst_len]);
            if src_parent != dst_parent {
                let rc = fsync_parent_dir(&src_buf[..src_len]);
                if rc != errno::OK {
                    return rc;
                }
            }
            errno::OK
        }
        dev_fs::PREALLOCATE => {
            let slot_idx = slot_index(handle);
            let files = &*core::ptr::addr_of!(LINUX_FILES);
            if slot_idx >= MAX_OPEN_FILES || !owned(&files[slot_idx]) {
                return errno::EINVAL;
            }
            if arg.is_null() || arg_len < 4 {
                return errno::EINVAL;
            }
            let capacity = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            if capacity == 0 {
                return errno::EINVAL;
            }
            let fd = files[slot_idx].fd;
            let slot_owner = files[slot_idx].owner;
            let Some(st) = crate::platform::linux::owner_root::stat_fd(fd) else {
                return -*libc::__errno_location();
            };
            // Reserving never shrinks: a file already past the capacity keeps
            // its bytes.
            let size = (st.st_size as u64).max(u64::from(capacity));
            // A workload is charged for the capacity before it is reserved.
            if crate::platform::linux::owner_root::rooted(slot_owner)
                && !crate::platform::linux::owner_root::charge_inode(
                    slot_owner,
                    st.st_ino,
                    crate::kernel::workload::storage::file_cost(size),
                    true,
                )
            {
                return errno::ENOSPC;
            }
            let rc = libc::posix_fallocate(fd, 0, capacity as libc::off_t);
            let grew = rc == 0 && libc::ftruncate(fd, size as libc::off_t) == 0;
            let err = if rc != 0 {
                -rc
            } else {
                -*libc::__errno_location()
            };
            if crate::platform::linux::owner_root::rooted(slot_owner) {
                settle_inode(slot_owner, fd, st.st_ino);
            }
            if !grew {
                return err;
            }
            if libc::lseek(fd, 0, libc::SEEK_SET) < 0 {
                return -*libc::__errno_location();
            }
            // PREALLOCATE promises the capacity is physically backed and
            // crash-visible on success (see the contract in
            // `sdk::contracts::storage::fs`). fallocate + ftruncate reserve the
            // blocks and set the size, but neither is durable until the inode
            // metadata is flushed — fsync it so the fence matches fat32's
            // durable PREALLOCATE rather than reporting a false `Volatile`.
            if libc::fsync(fd) < 0 {
                return -*libc::__errno_location();
            }
            record_slot_fence(
                slot_idx,
                Fence::LocalDurable {
                    device_id: LINUX_FS_DEVICE_ID,
                },
            );
            errno::OK
        }
        dev_fs::READ => {
            let slot_idx = slot_index(handle);
            let files = &*core::ptr::addr_of!(LINUX_FILES);
            if slot_idx >= MAX_OPEN_FILES || !owned(&files[slot_idx]) {
                return errno::EINVAL;
            }
            if arg.is_null() || arg_len == 0 {
                return errno::EINVAL;
            }
            let n = libc::read(files[slot_idx].fd, arg as *mut libc::c_void, arg_len);
            if n < 0 {
                errno::ERROR
            } else {
                // Reads reflect the kernel page cache; no
                // durability claim. Recording overwrites any prior
                // `LocalDurable` so the slot's fence stays honest.
                record_slot_fence(slot_idx, Fence::Volatile);
                n as i32
            }
        }
        dev_fs::WRITE => {
            let slot_idx = slot_index(handle);
            let files = &mut *core::ptr::addr_of_mut!(LINUX_FILES);
            if slot_idx >= MAX_OPEN_FILES || !owned(&files[slot_idx]) {
                return errno::EINVAL;
            }
            if arg.is_null() || arg_len == 0 {
                return errno::EINVAL;
            }
            let fd = files[slot_idx].fd;
            let slot_owner = files[slot_idx].owner;
            // A workload is charged for what the write can make the inode
            // hold before it runs; a write its storage cap refuses lands
            // nothing. What the inode holds afterwards is what it keeps.
            let mut ino = None;
            if crate::platform::linux::owner_root::rooted(slot_owner) {
                use crate::platform::linux::owner_root as root;
                let Some(st) = root::stat_fd(fd) else {
                    return errno::ERROR;
                };
                let pos = libc::lseek(fd, 0, libc::SEEK_CUR).max(0) as u64;
                let end = (st.st_size as u64).max(pos.saturating_add(arg_len as u64));
                if !root::charge_inode(
                    slot_owner,
                    st.st_ino,
                    crate::kernel::workload::storage::ENTRY_COST + end,
                    true,
                ) {
                    return errno::ENOSPC;
                }
                ino = Some(st.st_ino);
            }
            let n = libc::write(fd, arg as *const libc::c_void, arg_len);
            if let Some(ino) = ino {
                settle_inode(slot_owner, fd, ino);
            }
            if n < 0 {
                errno::ERROR
            } else {
                // Page-cache hand-off; not durable until FSYNC.
                record_slot_fence(slot_idx, Fence::Volatile);
                n as i32
            }
        }
        dev_fs::SEEK => {
            let slot_idx = slot_index(handle);
            let files = &*core::ptr::addr_of!(LINUX_FILES);
            if slot_idx >= MAX_OPEN_FILES || !owned(&files[slot_idx]) {
                return errno::EINVAL;
            }
            if arg.is_null() || arg_len < 4 {
                return errno::EINVAL;
            }
            // 32-bit or 64-bit offset, selected by the buffer width the
            // caller supplied. This backend has no 4 GiB ceiling, so the
            // wide form is honoured as given.
            let offset: i64 = if arg_len >= 8 {
                let a = core::slice::from_raw_parts(arg, 8);
                let v = u64::from_le_bytes([a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]]);
                if v > i64::MAX as u64 {
                    return errno::EINVAL;
                }
                v as i64
            } else {
                let v = i32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
                if v < 0 {
                    return errno::EINVAL;
                }
                i64::from(v)
            };
            let pos = libc::lseek(files[slot_idx].fd, offset, libc::SEEK_SET);
            if pos < 0 {
                errno::ERROR
            } else {
                // Seek doesn't change durability, but it's a
                // successful op on this handle — record Volatile so
                // the slot fence describes the latest op.
                record_slot_fence(slot_idx, Fence::Volatile);
                // Any non-negative value is success; an offset past what an
                // `i32` carries is reported as 0 rather than as an errno.
                i32::try_from(pos).unwrap_or(0)
            }
        }
        dev_fs::CLOSE => {
            let slot_idx = slot_index(handle);
            let files = &mut *core::ptr::addr_of_mut!(LINUX_FILES);
            if slot_idx >= MAX_OPEN_FILES || !owned(&files[slot_idx]) {
                // The fs contract's CLOSE answers 0 or EBADF.
                return -9; // EBADF
            }
            // Dispatch on whether this slot is a file (fd >= 0) or a
            // directory (dir_ptr != 0). They share the slot table so
            // a single CLOSE op works for both.
            if files[slot_idx].dir_ptr != 0 {
                libc::closedir(files[slot_idx].dir_ptr as *mut libc::DIR);
                files[slot_idx].dir_ptr = 0;
            } else if files[slot_idx].fd >= 0 {
                close_file_slot(&mut files[slot_idx]);
            }
            files[slot_idx].in_use = false;
            files[slot_idx].last_fence = Fence::Volatile;
            errno::OK
        }
        dev_fs::STAT => {
            let slot_idx = slot_index(handle);
            let files = &*core::ptr::addr_of!(LINUX_FILES);
            if slot_idx >= MAX_OPEN_FILES || !owned(&files[slot_idx]) {
                return errno::EINVAL;
            }
            if arg.is_null() || arg_len < 8 {
                return errno::EINVAL;
            }
            let mut stat: libc::stat = core::mem::zeroed();
            let ret = libc::fstat(files[slot_idx].fd, &mut stat);
            if ret < 0 {
                return errno::ERROR;
            }
            let size = stat.st_size as u64;
            let mtime = stat.st_mtime as u64;
            // Metadata read; no durability claim.
            record_slot_fence(slot_idx, Fence::Volatile);
            if arg_len >= 32 {
                // This backend is the one that genuinely has an object model
                // to report: `fstat` already answered every field. A provider
                // that has the answer and returns the short form instead
                // makes the wide form untestable.
                let out = core::slice::from_raw_parts_mut(arg, 32);
                out[..8].copy_from_slice(&size.to_le_bytes());
                out[8..16].copy_from_slice(&mtime.to_le_bytes());
                out[16..24].copy_from_slice(&(stat.st_ino as u64).to_le_bytes());
                out[24..28].copy_from_slice(&(stat.st_nlink as u32).to_le_bytes());
                out[28..32].copy_from_slice(&0u32.to_le_bytes());
                return 32;
            }
            if arg_len >= 16 {
                let out = core::slice::from_raw_parts_mut(arg, 16);
                out[..8].copy_from_slice(&size.to_le_bytes());
                out[8..].copy_from_slice(&mtime.to_le_bytes());
                return 16;
            }
            // The narrow form cannot carry this file. Saying so is the whole
            // point of having two widths: clamping to `u32::MAX` would hand
            // the caller a number that is not the size, with no way to tell
            // it apart from a file that really is that long.
            if size > u64::from(u32::MAX) {
                return errno::EOVERFLOW;
            }
            let out = core::slice::from_raw_parts_mut(arg, 8);
            out[..4].copy_from_slice(&(size as u32).to_le_bytes());
            out[4..].copy_from_slice(&(mtime as u32).to_le_bytes());
            8
        }
        dev_fs::FSYNC => {
            let slot_idx = slot_index(handle);
            let files = &*core::ptr::addr_of!(LINUX_FILES);
            if slot_idx >= MAX_OPEN_FILES || !owned(&files[slot_idx]) {
                return errno::EINVAL;
            }
            let ret = libc::fsync(files[slot_idx].fd);
            if ret < 0 {
                errno::ERROR
            } else {
                // `fsync(2)` has flushed bytes + metadata to the
                // host device, so the strongest honest fence is
                // `LocalDurable` against the FS device id.
                // Cross-host durability needs a replicating
                // provider layered on top.
                record_slot_fence(
                    slot_idx,
                    Fence::LocalDurable {
                        device_id: LINUX_FS_DEVICE_ID,
                    },
                );
                errno::OK
            }
        }
        dev_fs::OPENDIR => {
            let mut path_buf = [0u8; 256];
            if let Err(e) = validate_fs_path(arg, arg_len, &mut path_buf) {
                return e;
            }
            let files = &mut *core::ptr::addr_of_mut!(LINUX_FILES);
            let slot_idx = match files.iter().position(|s| !s.in_use) {
                Some(i) => i,
                None => return errno::ENOMEM,
            };
            let dir = libc::opendir(path_buf.as_ptr() as *const libc::c_char);
            if dir.is_null() {
                return errno::ENODEV;
            }
            let _ = slot_idx;
            claim_dir_slot(dir, owner)
        }
        dev_fs::READDIR => {
            let slot_idx = slot_index(handle);
            let files = &*core::ptr::addr_of!(LINUX_FILES);
            if slot_idx >= MAX_OPEN_FILES
                || !owned(&files[slot_idx])
                || files[slot_idx].dir_ptr == 0
            {
                return errno::EINVAL;
            }
            if arg.is_null() || arg_len < 2 {
                return errno::EINVAL;
            }
            let dir = files[slot_idx].dir_ptr as *mut libc::DIR;

            // Reserve 2 bytes for the count header.
            let mut out_pos: usize = 2;
            let mut count: u16 = 0;
            loop {
                // Where this entry starts, so an entry that does not fit
                // the caller's buffer is put back for the next call.
                let before = libc::telldir(dir);
                // libc::readdir returns NULL on end-of-dir OR error.
                // We don't distinguish — caller sees this as `0` for
                // "directory drained" either way.
                let ent = libc::readdir(dir);
                if ent.is_null() {
                    break;
                }
                let ent = &*ent;
                // Name length: find first NUL within d_name. `d_name` is
                // `[c_char; 256]`, and `c_char` is `i8` on x86_64 but `u8`
                // on aarch64 — `.cast::<u8>()` normalises both without
                // tripping clippy::unnecessary_cast on the arch where the
                // `as` form would be a no-op.
                let name_ptr: *const u8 = ent.d_name.as_ptr().cast();
                let mut nlen = 0usize;
                while nlen < 255 && *name_ptr.add(nlen) != 0 {
                    nlen += 1;
                }
                if nlen == 0 {
                    continue;
                }
                // Skip "." and ".." pseudo-entries.
                if nlen == 1 && *name_ptr == b'.' {
                    continue;
                }
                if nlen == 2 && *name_ptr == b'.' && *name_ptr.add(1) == b'.' {
                    continue;
                }
                let is_dir = ent.d_type == libc::DT_DIR;
                let need = 2 + nlen;
                if out_pos + need > arg_len {
                    // Buffer full: put the entry back rather than drop it, so
                    // it opens the next batch. Unconditionally — `E2BIG` tells
                    // the caller to retry with a larger buffer, and an entry
                    // consumed on the way out is one the retry never sees.
                    libc::seekdir(dir, before);
                    if count == 0 {
                        return errno::E2BIG;
                    }
                    break;
                }
                *arg.add(out_pos) = nlen as u8;
                *arg.add(out_pos + 1) = if is_dir { 1 } else { 0 };
                let mut i = 0usize;
                while i < nlen {
                    *arg.add(out_pos + 2 + i) = *name_ptr.add(i);
                    i += 1;
                }
                out_pos += need;
                count += 1;
            }
            // Contract: return 0 once the directory is drained so the
            // caller can break the readdir loop on a single sentinel
            // instead of having to inspect the count header.
            if count == 0 {
                record_slot_fence(slot_idx, Fence::Volatile);
                0
            } else {
                let cnt_le = count.to_le_bytes();
                *arg = cnt_le[0];
                *arg.add(1) = cnt_le[1];
                record_slot_fence(slot_idx, Fence::Volatile);
                out_pos as i32
            }
        }
        _ => errno::ENOSYS,
    }
}

// ============================================================================
// Linux PROC Provider — the impure boundary (host process executor, class 0x16)
// ============================================================================
//
// `do <cmd>` (sector) calls this via provider_call, gated by
// `requires_contract="proc"`. SPAWN (handle=-1) allocates a slot, spawns the
// command through `ProcExecutor` (background reader thread → non-blocking
// `poll_stdout`), and returns a `FD_TAG_PROC`-tagged handle.
// READ/STATUS/CLOSE carry that handle back. Completion is the real process exit
// (STATUS=0 once exited AND drained) — never a quiescence guess.
//
// GRANT: an executable allowlist, working directory, environment allowlist
// and timeout the operator sets at launch (`proc_grant`). The allowlist is
// hygiene + accident-prevention, NOT a sandbox (any dev tool is
// RCE-equivalent — the node is the boundary); no OS sandbox is applied.
//
// OWNERS: a spawn acts with the node's authority, so only the node and an
// owner acting with it spawn (a workload is refused EACCES). A child is its
// spawner's: only that owner reads, polls or closes it, and the owner-release
// hook shuts it down with the owner.

use crate::abi::platform::linux::host_process::{PROC_CLOSE, PROC_READ, PROC_SPAWN, PROC_STATUS};

const MAX_PROCS: usize = 8;

struct LinuxProcSlot {
    exec: Option<crate::platform::proc_executor::ProcExecutor>,
    in_use: bool,
    deadline: Option<std::time::Instant>,
    /// Stdout is a byte stream carried in frames: a frame larger than a
    /// caller's `PROC_READ` buffer is staged here and served across calls, so
    /// no read size loses bytes.
    staged: [u8; crate::platform::proc_executor::READ_CHUNK],
    staged_len: usize,
    staged_off: usize,
    /// The owner that spawned the child: the slot is its alone, and the
    /// child goes with it.
    owner: crate::kernel::workload::owner::OwnerHandle,
}

static mut LINUX_PROCS: [LinuxProcSlot; MAX_PROCS] = [const {
    LinuxProcSlot {
        exec: None,
        in_use: false,
        deadline: None,
        staged: [0; crate::platform::proc_executor::READ_CHUNK],
        staged_len: 0,
        staged_off: 0,
        owner: crate::kernel::workload::owner::OWNER_SYSTEM,
    }
}; MAX_PROCS];

/// Whether `slot` is a live child of the calling owner's: the spawner alone
/// reaches it.
fn proc_owned(slot: &LinuxProcSlot) -> bool {
    slot.in_use && slot.owner == crate::kernel::exec::scheduler::caller_owner()
}

/// Close a child's slot: the child is shut down and the slot's per-run state
/// cleared rather than left for whoever spawns into it next.
fn close_proc_slot(slot: &mut LinuxProcSlot, grace: std::time::Duration) {
    if let Some(mut e) = slot.exec.take() {
        e.shutdown(grace);
    }
    slot.in_use = false;
    slot.deadline = None;
    slot.staged_len = 0;
    slot.staged_off = 0;
    slot.owner = crate::kernel::workload::owner::OWNER_SYSTEM;
}

/// Shut down every child `owner` spawned. Part of the platform's
/// owner-release hook: a host process never outlives the owner that
/// spawned it.
///
/// # Safety
/// Single-threaded platform dispatch only.
pub unsafe fn release_owner_procs(owner: crate::kernel::workload::owner::OwnerHandle) {
    let procs = &mut *core::ptr::addr_of_mut!(LINUX_PROCS);
    for slot in procs.iter_mut().filter(|s| s.in_use && s.owner == owner) {
        close_proc_slot(slot, std::time::Duration::from_millis(100));
    }
}

/// The node's `proc` grant — WHAT `do` may run and how, sourced from the
/// environment so the operator declares it at launch (`SECTOR_PROC_ALLOW`,
/// `_ROOT`, `_ENV`, `_TIMEOUT_MS`), with safe defaults. The allowlist is
/// accident-prevention, NOT confinement (any dev tool is RCE-equivalent — the
/// node is the boundary);
/// `root`/`env`/`timeout` are hygiene + blast-radius bounds.
struct ProcGrant {
    root: Option<std::path::PathBuf>,
    allow: std::vec::Vec<String>,
    env_allow: std::vec::Vec<String>,
    timeout_ms: u64,
}

fn proc_grant() -> &'static ProcGrant {
    static GRANT: std::sync::OnceLock<ProcGrant> = std::sync::OnceLock::new();
    GRANT.get_or_init(|| {
        let split = |v: String| {
            v.split([',', ' ', ':'])
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect::<std::vec::Vec<_>>()
        };
        let default_allow = || {
            [
                "echo", "ls", "cat", "pwd", "uname", "date", "whoami", "env", "true", "false",
                "wc", "head", "tail", "grep", "find", "rg", "git", "cargo", "rustc", "make",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect::<std::vec::Vec<_>>()
        };
        let default_env = || {
            [
                "PATH",
                "HOME",
                "USER",
                "LANG",
                "LC_ALL",
                "TERM",
                "CARGO_HOME",
                "RUSTUP_HOME",
                "SSH_AUTH_SOCK",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect::<std::vec::Vec<_>>()
        };
        ProcGrant {
            root: std::env::var("SECTOR_PROC_ROOT")
                .ok()
                .map(std::path::PathBuf::from),
            allow: std::env::var("SECTOR_PROC_ALLOW")
                .ok()
                .map(split)
                .unwrap_or_else(default_allow),
            env_allow: std::env::var("SECTOR_PROC_ENV")
                .ok()
                .map(split)
                .unwrap_or_else(default_env),
            timeout_ms: std::env::var("SECTOR_PROC_TIMEOUT_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(120_000),
        }
    })
}

/// Process-executor provider dispatch.
///
/// # Safety
/// Single-threaded platform dispatch only: touches `static mut` provider
/// state without synchronization. `arg` must be null or valid for reads
/// and writes of `arg_len` bytes for the duration of the call.
pub unsafe fn linux_proc_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::abi::platform::linux::host_process::FD_TAG_PROC;
    use crate::kernel::ipc::fd::{slot_of, tag_fd};
    use crate::kernel::sys::errno;
    use crate::kernel::workload::extbridge::OverloadPolicy;
    use crate::platform::proc_executor::{ProcExecutor, SpawnPolicy};

    let procs = &mut *core::ptr::addr_of_mut!(LINUX_PROCS);
    match opcode {
        PROC_SPAWN => {
            if arg.is_null() || arg_len == 0 {
                return errno::EINVAL;
            }
            // A host process acts with the node's authority: the node and an
            // owner acting with it spawn one, a workload never does. The
            // child is the spawning owner's, and goes with it.
            let owner = crate::kernel::exec::scheduler::caller_owner();
            if !crate::kernel::exec::scheduler::caller_authority().is_system() {
                return errno::EACCES;
            }
            let bytes = core::slice::from_raw_parts(arg, arg_len);
            let line = match core::str::from_utf8(bytes) {
                Ok(s) => s.trim(),
                Err(_) => return errno::EINVAL,
            };
            let mut parts = line.split_whitespace();
            let cmd = match parts.next() {
                Some(c) => c,
                None => return errno::EINVAL,
            };
            let grant = proc_grant();
            if !grant.allow.iter().any(|a| a == cmd) {
                return errno::EACCES; // not in the node's allowlist
            }
            let args: std::vec::Vec<&str> = parts.collect();
            let slot = match procs.iter().position(|s| !s.in_use) {
                Some(i) => i,
                None => return errno::ENOMEM,
            };
            // Scoped cwd + a declared (non-ambient) environment; Block policy →
            // true end-to-end backpressure (a slow consumer throttles the child).
            let policy = SpawnPolicy {
                cwd: grant.root.clone(),
                env_allow: grant.env_allow.clone(),
            };
            match ProcExecutor::spawn(owner, cmd, &args, OverloadPolicy::Block, &policy) {
                Ok(exec) => {
                    procs[slot].exec = Some(exec);
                    procs[slot].in_use = true;
                    procs[slot].owner = owner;
                    procs[slot].staged_len = 0;
                    procs[slot].staged_off = 0;
                    procs[slot].deadline = Some(
                        std::time::Instant::now()
                            + std::time::Duration::from_millis(grant.timeout_ms),
                    );
                    tag_fd(FD_TAG_PROC, slot as i32)
                }
                Err(_) => errno::ERROR,
            }
        }
        PROC_READ => {
            let slot = slot_of(handle) as usize;
            if slot >= MAX_PROCS || !proc_owned(&procs[slot]) || arg.is_null() || arg_len == 0 {
                return errno::EINVAL;
            }
            let out = core::slice::from_raw_parts_mut(arg, arg_len);
            let p = &mut procs[slot];
            if p.staged_off >= p.staged_len {
                // A whole frame into the stage, whatever the caller's size.
                match p.exec.as_ref().and_then(|e| e.poll_stdout(&mut p.staged)) {
                    Some(n) => {
                        p.staged_len = n;
                        p.staged_off = 0;
                    }
                    None => return 0, // nothing ready this step
                }
            }
            let n = (p.staged_len - p.staged_off).min(out.len());
            out[..n].copy_from_slice(&p.staged[p.staged_off..p.staged_off + n]);
            p.staged_off += n;
            n as i32
        }
        PROC_STATUS => {
            let slot = slot_of(handle) as usize;
            if slot >= MAX_PROCS || !proc_owned(&procs[slot]) {
                return errno::EINVAL;
            }
            // Past the deadline, kill the child — a runaway build can't wedge
            // the pipe (bounds the blast radius). The kill is reported through
            // the same completion answer as a natural exit, so the code below
            // carries `128 + SIGKILL` rather than a success a caller would act
            // on.
            let timed_out = procs[slot]
                .deadline
                .is_some_and(|dl| std::time::Instant::now() >= dl);
            let staged = procs[slot].staged_off < procs[slot].staged_len;
            let e = match procs[slot].exec.as_mut() {
                Some(e) => e,
                None => return errno::EINVAL,
            };
            if timed_out {
                e.shutdown(std::time::Duration::from_millis(50));
            }
            // Done only when the child has exited AND both reader threads finished
            // AND the inbound bridge and the read stage are drained — otherwise a
            // final in-flight chunk would be lost. 1 = more may come; 0 = truly done.
            let running = !timed_out
                && (e.alive() || !e.reader_finished() || e.stdout_pending() > 0 || staged);
            // Every answer that says done carries how the command ended:
            // `arg` (LE i32) is its exit code, `128 + signal` when a signal
            // ended it, and -1 when the status could not be read at all. A
            // caller acting on the command's success — a fence agent on a
            // power cut — reads it; one that only waits ignores it.
            if !running && !arg.is_null() && arg_len >= 4 {
                let code = e.exit_code().unwrap_or(-1);
                core::ptr::copy_nonoverlapping(code.to_le_bytes().as_ptr(), arg, 4);
            }
            i32::from(running)
        }
        PROC_CLOSE => {
            let slot = slot_of(handle) as usize;
            if slot < MAX_PROCS && proc_owned(&procs[slot]) {
                close_proc_slot(&mut procs[slot], std::time::Duration::from_millis(100));
            }
            0
        }
        _ => errno::ENOSYS,
    }
}

// ============================================================================
// linux_net built-in module — channel-based net_proto framing via libc sockets
// ============================================================================

/// FNV-1a hash of "linux_net"
pub const LINUX_NET_HASH: u32 = 0xFBCC7DC9;

// Net protocol message types (downstream: linux_net → consumer)
const MSG_ACCEPTED: u8 = 0x01;
const MSG_DATA: u8 = 0x02;
const MSG_CLOSED: u8 = 0x03;
/// net_proto `CLOSED_ID_GRACE_MS`: how long a closed connection's id stays the
/// consumer's after MSG_CLOSED. Mirrored by value here because this file
/// carries its own copy of the opcode table; the contract module is the
/// authority.
const CLOSED_ID_GRACE_MS: u32 = 5_000;
/// How long a deferred `CMD_CLOSE` waits for the connection's queued bytes to
/// reach the wire before closing anyway.
///
/// The wait exists so a close does not discard what the consumer already
/// handed over (RFC 793 §3.5). It is bounded because a peer that has stopped
/// reading would otherwise hold the slot and its descriptor for good: past
/// this the remainder is dropped, loudly, which is a reported loss rather than
/// a silent one.
const CLOSE_DRAIN_MAX_MS: u64 = 10_000;
const MSG_BOUND: u8 = 0x04;
const MSG_CONNECTED: u8 = 0x05;
const MSG_ERROR: u8 = 0x06;
/// Bind refusal / failure: `[port: u16 LE][errno: u8]`. The port is the
/// routing key (consumers sharing net_out already filter by local_port).
/// Emitted on a bind syscall failure and on an owner-gate refusal, so a
/// requester never hangs waiting for MSG_BOUND on a failed bind.
const MSG_BIND_REFUSED: u8 = 0x07;

// Net protocol command types (upstream: consumer → linux_net)
const CMD_BIND: u8 = 0x10;
const CMD_SEND: u8 = 0x11;
const CMD_CLOSE: u8 = 0x12;
/// Reserved dial (`[sock_type][ip u32 LE][port][tag u16 LE?]`), unsupported. Answered with
/// `MSG_ERROR ENOSYS` on its tag so a stale emitter fails on its first dial
/// rather than dialling the address its bytes would decode to under the
/// live shape.
const CMD_CONNECT: u8 = 0x13;
/// The dial: `[sock_type][af][port u16 LE][addr…][tag u16 LE?]`, decoded by the
/// contract's `read_connect_to`. A name is resolved here — the provider is
/// the resolver on every platform — through `getaddrinfo(3)` on a thread,
/// so `/etc/hosts`, `resolv.conf`, nsswitch and systemd-resolved all apply
/// and the scheduler never blocks on a lookup.
const CMD_CONNECT_TO: u8 = 0x14;

// Datagram surface (modules/sdk/contracts/net/datagram.rs, opcodes
// 0x20..0x43). Disjoint from net_proto so the same channel can carry
// both contracts.
const DG_CMD_BIND: u8 = 0x20;
const DG_CMD_SEND_TO: u8 = 0x21;
const DG_CMD_CLOSE: u8 = 0x22;
const DG_MSG_BOUND: u8 = 0x40;
const DG_MSG_RX_FROM: u8 = 0x41;
const DG_MSG_CLOSED: u8 = 0x42;
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
const DG_MSG_ERROR: u8 = 0x43;
const DG_AF_INET: u8 = 4;
/// Datagram destination given as a DNS name (`[len][name]`), resolved by
/// this provider exactly as a stream dial is. A name not yet in the cache
/// starts a lookup and the datagram is DROPPED: a datagram sender
/// retransmits, and the next send after the answer lands goes out.
const DG_AF_NAME: u8 = 1;
/// Marker introducing the owner tag on `DG_CMD_SEND_TO` / `DG_CMD_CLOSE`. It
/// sits at the offset that otherwise carries `af`, and is distinct from every
/// defined address family, so the tagged and untagged shapes separate at a
/// fixed offset rather than by a length rule over variable-length data.
const DG_OWNER_TAG_MARK: u8 = 0xFF;
/// Bytes the owner-tag field occupies: `[MARK][owner_tag: u16 LE]`.
const DG_OWNER_TAG_FIELD: usize = 3;

const CONN_TYPE_UDP_BOUND: u8 = 2;

/// Connection slots (listeners + clients) when the graph does not set
/// `max_conns`. The table is a heap `Vec` sized once at instantiation
/// from the built-in's `max_conns` param, capped at
/// `LINUX_NET_MAX_CONNS_CAP` because net_proto carries the slot index
/// as `u16 LE`. A slot holds no buffer until a send backs up, so a large
/// table of idle connections costs only the fixed per-slot fields.
pub const LINUX_NET_MAX_CONNS_DEFAULT: usize = 128;
/// Hard ceiling on `max_conns`: the wire id is a `u16`. A configured value
/// outside `LINUX_NET_MAX_CONNS_MIN..=LINUX_NET_MAX_CONNS_CAP` is refused at
/// instantiation, never adjusted.
pub const LINUX_NET_MAX_CONNS_CAP: usize = 65535;
/// Floor on `max_conns`: one listener and one connection.
pub const LINUX_NET_MAX_CONNS_MIN: usize = 2;
/// Ready-event batch drained from the epoll set per step. Level
/// triggered, so a socket left out of one batch is served next step.
const LINUX_NET_READY_BATCH: usize = 1024;
/// Max distinct inbound command channels (priority lanes).
pub const LINUX_NET_MAX_INBOUND: usize = 8;
/// Lanes a workload staged at runtime may attach (`net_attach`). Attached
/// lane `j` is lane index `LINUX_NET_MAX_INBOUND + j`, after every boot lane.
pub const LINUX_NET_MAX_ATTACHED: usize = 32;
/// Control frames held for one destination channel while it is full. At the
/// cap the sources that would add to it pause: the lane's commands are left
/// in its command channel and its listeners' pending connections in the
/// kernel's accept queue, so a wedged consumer back-pressures its producer.
/// No queued frame is ever evicted. What can still arrive while paused is
/// bounded by the slots the lane already holds (each emits at most a
/// connect result, a peer report and a close), so the queue never passes
/// [`LinuxNetState::pending_ctrl_ceiling`]; a frame refused there is
/// counted and logged.
pub const PENDING_CTRL_CAP: usize = 256;
/// Per-connection write backlog cap when the graph does not set
/// `write_buf_kib`. 128 KiB holds a full Spectrum video frame's worth of
/// WS fragments (~98 KB) so a slow peer can absorb one frame's
/// transmission pause without the producer overflowing the backlog
/// (which closes the connection). The buffer is allocated the first
/// time a send backs up and released with the slot, so the cap is a
/// per-connection worst case, not a resident cost.
pub const LINUX_NET_WRITE_BUF_DEFAULT: usize = 128 * 1024;
/// The largest command frame payload read (the command scratch). A larger
/// frame is drained to stay frame-aligned and answered `EMSGSIZE` in the
/// shape its command's requester waits on.
pub const LINUX_NET_CMD_MAX: usize = 49152;
/// Listen backlog when the graph does not set `listen_backlog`. The
/// kernel's SYN queue must absorb a whole connect burst; at 8 a
/// 32-client burst dropped SYNs 9..=32.
pub const LINUX_NET_LISTEN_BACKLOG_DEFAULT: i32 = 128;

// Intentionally NOT Copy: `write_buf` owns a heap allocation.
// References / field-access only.
#[allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]
struct LinuxNetConn {
    fd: i32,
    conn_type: u8,
    state: u8,
    /// For TCP listeners (`conn_type == 1, state == 3`): the port the
    /// listener is bound to. Used by `linux_net_cmd_bind` to recognise
    /// re-binds on the same port. Zero for non-listener slots.
    port: u16,
    /// `CMD_CLOSE` arrived while `write_buf` still held unsent bytes. The
    /// close waits for them: RFC 793 §3.5 has CLOSE transmit everything
    /// already queued, and `close(2)` over a live backlog drops it — the peer
    /// then reads a clean FIN on a response short by exactly that much, with
    /// no error anywhere to say so. The bare-metal `ip` module defers its FIN
    /// for the same reason.
    close_when_drained: bool,
    /// When the deferred close gives up and closes regardless.
    close_deadline: Option<std::time::Instant>,
    /// Bytes already drained from `write_buf`.
    write_offset: u32,
    /// Total valid bytes in `write_buf` (drained slice is `[offset..len]`).
    write_len: u32,
    /// Requester tag from `CMD_CONNECT_TO`, echoed in `MSG_CONNECTED` /
    /// connect-failure `MSG_ERROR` so a fanned net_out routes the event back.
    connect_tag: crate::abi::contracts::net::net_proto::RequesterTag,
    /// `state == 5` (resolving, no fd yet): the lookup this slot is waiting
    /// on. A result whose id does not match is stale — the slot was revoked
    /// and possibly retaken while the lookup ran — and is dropped.
    resolve_id: u32,
    /// `state == 5`: when the lookup was handed to the resolver thread, so a
    /// resolver that never answers cannot pin the slot.
    resolve_started: Option<std::time::Instant>,
    /// The COMMANDING owner — the owner of the module whose lane issued the
    /// bind/connect that created this slot (/// attribution is carried via the lane, never inferred from the executing
    /// module, which may be system-owned). Immutable for the life of the slot.
    owner: crate::kernel::workload::owner::OwnerHandle,
    /// The lane whose command created this slot (an accepted connection
    /// takes its listener's). Every event about the slot goes to that
    /// lane's events channel, and an attached lane may act only on the
    /// slots it created. Immutable for the life of the slot.
    lane: u16,
    /// Datagram endpoints only: the `owner_tag` the consumer stamped on
    /// `DG_CMD_BIND`. `DG_CMD_SEND_TO` / `DG_CMD_CLOSE` must present the same
    /// value or the command is refused with `EPERM`. Zero is the host
    /// wildcard, reachable by the untagged shape.
    dg_owner_tag: u16,
    /// Unsent bytes. Empty until a send backs up; then grown as the backlog
    /// does (to the instance's `write_buf_max`) and kept until the slot is
    /// released.
    write_buf: Vec<u8>,
    /// `state == 4` (closed, id held): when the id is released if the
    /// consumer has not sent CMD_CLOSE by then. net_proto's release rule —
    /// after MSG_CLOSED the id stays the consumer's for
    /// `CLOSED_ID_GRACE_MS`, so its CMD_CLOSE can never land on a newcomer
    /// that took the same index, and a consumer that never closes cannot
    /// pin the slot either.
    release_at: Option<std::time::Instant>,
    /// `state == 1` (connecting): the addresses this name resolved to that
    /// have not been tried yet, in the host's order. A refused or
    /// unreachable connect moves to the next before it is reported, so a
    /// name whose first address is dead — `localhost` on a dual-stack box
    /// answering `::1` ahead of `127.0.0.1` — still reaches a service
    /// listening on the other one.
    alts: Vec<Resolved>,
    /// `state == 1`: when the attempt now in `fd` was started, so a family
    /// that is black-holed rather than refusing does not hold the dial for
    /// the whole connect timeout (RFC 8305 §5).
    attempt_started: Option<std::time::Instant>,
    /// `state == 1`: attempts started BEFORE the one in `fd` and still in
    /// flight. The first of any of them to connect wins and the rest are
    /// closed; a consumer never learns a race happened.
    racing: Vec<i32>,
    /// Datagram endpoints only: for each peer heard from, the local address
    /// its last datagram arrived at, `(peer addr, peer port, local addr)`
    /// with addresses as `s_addr`. A send to that peer leaves from that
    /// address, so an endpoint bound to every address answers from the one
    /// it was asked at — not from whichever source the route prefers, which
    /// the asker (and connection tracking, for a translated service) would
    /// not take for the answer. At most [`DG_REPLY_FROM_MAX`] peers, the
    /// longest unheard replaced first.
    dg_reply_from: Vec<(u32, u16, u32)>,
    /// Datagram endpoints only: arrivals not delivered to the consumer — its
    /// channel was full or held control frames, or the datagram was larger
    /// than one frame carries.
    dg_rx_dropped: u64,
}

/// Peers a datagram endpoint remembers the arrival address of.
const DG_REPLY_FROM_MAX: usize = 64;

impl LinuxNetConn {
    fn empty() -> Self {
        Self {
            fd: -1,
            conn_type: 0,
            state: 0,
            port: 0,
            close_when_drained: false,
            close_deadline: None,
            write_offset: 0,
            write_len: 0,
            connect_tag: 0,
            resolve_id: 0,
            resolve_started: None,
            release_at: None,
            owner: crate::kernel::workload::owner::OWNER_SYSTEM,
            lane: 0,
            dg_owner_tag: 0,
            write_buf: Vec::new(),
            alts: Vec::new(),
            attempt_started: None,
            racing: Vec::new(),
            dg_reply_from: Vec::new(),
            dg_rx_dropped: 0,
        }
    }
}

/// Largest control frame a lane queue holds: a stream's peer report
/// (`MSG_PEER`, `[type][len: u16][conn_id: u16][family][addr: 16][port: u16]`),
/// queued with the accept it follows. Every control frame fits it, which
/// `linux_net_send_msg` checks at compile time; data (`MSG_DATA`,
/// `DG_MSG_RX_FROM`) is never queued.
const CTRL_FRAME_MAX: usize = 3 + crate::abi::contracts::net::net_proto::PEER_LEN;

/// Control frames waiting for room on one destination channel, in order.
type PendingCtrl = std::collections::VecDeque<([u8; CTRL_FRAME_MAX], usize)>;

/// A lane a runtime-staged workload attached (`net_attach`): its own
/// command channel, read like a boot lane, and its own events channel,
/// which every event for a slot the lane created goes to and nothing else
/// does.
struct AttachedLane {
    owner: crate::kernel::workload::owner::OwnerHandle,
    key: u8,
    commands: i32,
    events: i32,
    /// Control frames `events` had no room for. Per lane, so one consumer
    /// that falls behind holds up only its own terminal results.
    pending: PendingCtrl,
}

/// linux_net keeps per-instance state in a `Box<LinuxNetState>` like
/// every other host built-in. Two `linux_net` modules in one graph
/// would each get their own connection table and channel handles —
/// but they would still race for OS-level listen ports and fds. That's
/// a config-time concern (don't bind two listeners on port 9000), not
/// a state-aliasing one. Per-instance ownership matches the rest of
/// the host built-in family and makes the dispatch path uniform.
pub struct LinuxNetState {
    /// Inbound command channels, drained in INDEX ORDER each step —
    /// index = the edge's position among `to: linux_net.net_in` lines
    /// in the graph wiring, so earlier edges are higher priority.
    /// Each producer gets its OWN channel: frame atomicity is
    /// per-channel, the drain order is an explicit priority lane, and
    /// a bulk flood on one lane (a web stream) cannot serialise ahead
    /// of latency-critical traffic on another (Raft heartbeats racing
    /// an election timeout).
    net_ins: [i32; LINUX_NET_MAX_INBOUND],
    /// Owner of each lane's producer module, resolved at instantiation from
    /// the wired edge (`channel_producer_owner`) and refreshed on every
    /// rebuild — the carried-attribution source for bind stamps.
    lane_owners: [crate::kernel::workload::owner::OwnerHandle; LINUX_NET_MAX_INBOUND],
    /// Event channels, one per `from: linux_net.net_out` edge when the graph
    /// pairs each with a lane's producer, else the one (teed) `net_out`.
    net_outs: [i32; LINUX_NET_MAX_INBOUND],
    /// The `net_outs` index each boot lane's events go to: the channel its
    /// producer reads, so a consumer that falls behind holds up only the
    /// connections it opened.
    lane_out: [u8; LINUX_NET_MAX_INBOUND],
    /// Connection table, `max_conns` slots; the slot index is the
    /// net_proto conn id.
    conns: Vec<LinuxNetConn>,
    /// Per-connection write backlog cap (`write_buf_kib` param).
    write_buf_max: usize,
    /// `listen()` backlog for every listener this instance binds.
    listen_backlog: i32,
    /// epoll set holding every live fd, `data.u64` = slot index. Level
    /// triggered: readiness is re-reported every step until consumed,
    /// so a socket skipped for channel back-pressure is not lost.
    epfd: i32,
    /// Scratch for one `epoll_wait` batch.
    ready: Vec<libc::epoll_event>,
    ready_len: usize,
    /// One command frame's payload, `LINUX_NET_CMD_MAX` (48 KiB) bytes:
    /// several times net_proto's `MAX_CMD_DATA` (8 KiB of `CMD_SEND` data
    /// plus its conn id), so every conforming command fits. A frame whose
    /// payload is larger is drained and answered `EMSGSIZE`, never read in
    /// part.
    cmd_buf: [u8; LINUX_NET_CMD_MAX],
    msg_buf: [u8; 16384],
    recv_buf: [u8; 16384],
    /// The part of `recv_buf` a full channel left un-forwarded, and the
    /// slot it came from. A frame write is all-or-nothing, so a short
    /// write leaves bytes read from the socket but not yet delivered;
    /// they are already out of the kernel's buffer, so the only place
    /// they can be re-offered from is here. While a tail is held no
    /// socket is read, because `recv_buf` is the one place to read into
    /// and overwriting it is how those bytes would be lost.
    hold_slot: i32,
    hold_off: usize,
    hold_len: usize,
    /// The lane the held tail is owed to, fixed when the hold is taken: the
    /// slot may be closed while its tail waits, and its bytes still belong
    /// to the lane that was reading it.
    hold_lane: usize,
    /// Next slot to consider when allocating a connection. Used to
    /// allocate round-robin instead of "first free", so a slot freed
    /// in step T isn't immediately reused in step T+1 — that race lets
    /// stale `CMD_SEND` bytes from the previous session land on the
    /// fresh connection's fd, scrambling its response stream.
    next_alloc: usize,
    /// Control-frame (MSG_CONNECTED / CLOSED / ERROR / BOUND) retry queues,
    /// one per `net_outs` channel. The consumer channel is all-or-nothing;
    /// when it's momentarily full a tiny control frame would otherwise be
    /// DROPPED, stranding a waiter. Queue it and flush before each step.
    /// At `PENDING_CTRL_CAP` the lane's sources pause; nothing queued is
    /// evicted. Attached lanes queue on their own.
    pending_ctrl: [PendingCtrl; LINUX_NET_MAX_INBOUND],
    /// Control frames refused at `pending_ctrl_ceiling`. The pause at
    /// `PENDING_CTRL_CAP` keeps a queue below the ceiling, so this staying
    /// zero is the design holding.
    ctrl_refused: u64,
    /// Datagrams received and not delivered, over every endpoint.
    dg_rx_dropped: u64,
    /// Runtime-attached lanes; entry `j` is lane `LINUX_NET_MAX_INBOUND + j`.
    /// A detached entry is `None` and its index may be reused, which is safe
    /// because detaching closes every slot the lane created.
    attached: Vec<Option<AttachedLane>>,
    /// The resolver thread's queues, started on the first name this
    /// instance is asked to dial. Everything crossing the thread boundary
    /// is owned: a job carries its own copy of the name.
    resolver: Option<Resolver>,
    /// Ids handed to lookups, so a result can be matched to the slot that
    /// is still waiting for it and no other.
    resolve_seq: u32,
    /// Slots in `resolving`, so a step with none pays nothing for the
    /// guard sweep.
    resolving: usize,
    /// Names a cache-warming lookup (a named datagram destination) is in
    /// flight for. A datagram sender retransmits while it waits, and
    /// without this every retransmit would queue another identical job.
    warming: Vec<String>,
    /// Positive cache, consulted BEFORE a slot is taken: `getaddrinfo` has
    /// no TTL to report, so entries live `DNS_CACHE_TTL`. It is what keeps
    /// the common case out of the resolver thread — and out of tls's single
    /// in-flight connect window, which a lookup would otherwise stretch to
    /// a DNS round-trip.
    dns_cache: Vec<DnsCacheEntry>,
}

/// One address a name resolved to, in network order as the socket wants it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Resolved {
    V4([u8; 4]),
    V6([u8; 16]),
}

struct DnsCacheEntry {
    name: String,
    /// Every candidate the host gave, in its order. Cached whole so a name
    /// answered from cache falls back exactly as a freshly resolved one does.
    addrs: Vec<Resolved>,
    expires: std::time::Instant,
}

/// How many addresses one name may be dialled at. A name that resolves to
/// more than this is not worth a longer ladder: the connect timeout bounds
/// each rung, and a host with four dead addresses is down, not slow. The cut
/// is taken after the families are interleaved ([`dial_candidates`]), so
/// both families are dialled whenever the host answered both.
pub const MAX_DIAL_CANDIDATES: usize = 4;

/// Cache entries per instance; one slot per distinct name the graph dials.
const DNS_CACHE_SLOTS: usize = 32;
/// How long a positive answer is reused. `getaddrinfo` returns no TTL, so
/// the contract's fallback applies.
const DNS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60);
/// A resolving slot older than this is failed `ENOENT`: glibc's own retry
/// ladder is shorter, so this only fires if the resolver thread is gone.
const RESOLVE_GUARD: std::time::Duration = std::time::Duration::from_secs(30);

struct ResolveJob {
    id: u32,
    /// The stream slot waiting on this lookup; `None` for a datagram
    /// destination, which only warms the cache.
    slot: Option<usize>,
    name: String,
    /// Datagram sockets here are `AF_INET`, so their lookups ask for v4.
    v4_only: bool,
}

struct ResolveDone {
    id: u32,
    slot: Option<usize>,
    name: String,
    result: Result<Vec<Resolved>, i32>,
}

struct Resolver {
    jobs: std::sync::mpsc::Sender<ResolveJob>,
    done: std::sync::mpsc::Receiver<ResolveDone>,
}

impl Resolver {
    fn start() -> Option<Self> {
        let (jobs, job_rx) = std::sync::mpsc::channel::<ResolveJob>();
        let (done_tx, done) = std::sync::mpsc::channel::<ResolveDone>();
        let spawned = std::thread::Builder::new()
            .name("fluxor-resolver".into())
            .spawn(move || {
                while let Ok(job) = job_rx.recv() {
                    let result = resolve_blocking(&job.name, job.v4_only);
                    let reply = ResolveDone {
                        id: job.id,
                        slot: job.slot,
                        name: job.name,
                        result,
                    };
                    if done_tx.send(reply).is_err() {
                        break;
                    }
                }
            });
        match spawned {
            Ok(_) => Some(Self { jobs, done }),
            Err(e) => {
                log::error!("[linux_net] cannot start the resolver thread: {e}");
                None
            }
        }
    }
}

/// `getaddrinfo(3)` with `AI_ADDRCONFIG`: the host's resolver, hosts file
/// and nsswitch order, which is the order the candidates are returned in.
/// Every address is returned; the caller picks the ones it dials with
/// [`dial_candidates`]. Runs on the resolver thread only.
fn resolve_blocking(name: &str, v4_only: bool) -> Result<Vec<Resolved>, i32> {
    let cname = match std::ffi::CString::new(name) {
        Ok(c) => c,
        Err(_) => return Err(libc::EINVAL),
    };
    // SAFETY: `hints` is zeroed then filled; `cname` outlives the call; the
    // result list is walked while owned and released with `freeaddrinfo`.
    unsafe {
        let mut hints: libc::addrinfo = core::mem::zeroed();
        hints.ai_family = if v4_only {
            libc::AF_INET
        } else {
            libc::AF_UNSPEC
        };
        hints.ai_socktype = libc::SOCK_STREAM;
        hints.ai_flags = libc::AI_ADDRCONFIG;
        let mut res: *mut libc::addrinfo = core::ptr::null_mut();
        let rc = libc::getaddrinfo(cname.as_ptr(), core::ptr::null(), &hints, &mut res);
        if rc != 0 {
            let why = std::ffi::CStr::from_ptr(libc::gai_strerror(rc)).to_string_lossy();
            log::warn!("[linux_net] resolve {name}: {why}");
            return Err(libc::ENOENT);
        }
        let mut found: Vec<Resolved> = Vec::new();
        let mut cur = res;
        while !cur.is_null() {
            let ai = &*cur;
            if ai.ai_family == libc::AF_INET && !ai.ai_addr.is_null() {
                let sa = &*(ai.ai_addr as *const libc::sockaddr_in);
                found.push(Resolved::V4(sa.sin_addr.s_addr.to_ne_bytes()));
            } else if ai.ai_family == libc::AF_INET6 && !ai.ai_addr.is_null() && !v4_only {
                let sa = &*(ai.ai_addr as *const libc::sockaddr_in6);
                found.push(Resolved::V6(sa.sin6_addr.s6_addr));
            }
            cur = ai.ai_next;
        }
        libc::freeaddrinfo(res);
        if found.is_empty() {
            Err(libc::ENOENT)
        } else {
            Ok(found)
        }
    }
}

impl LinuxNetState {
    /// A cached, unexpired answer for `name`.
    fn dns_cache_get(&self, name: &[u8]) -> Option<Vec<Resolved>> {
        let now = std::time::Instant::now();
        self.dns_cache
            .iter()
            .find(|e| e.name.as_bytes() == name && e.expires > now)
            .map(|e| e.addrs.clone())
    }

    fn dns_cache_put(&mut self, name: String, addrs: Vec<Resolved>) {
        let now = std::time::Instant::now();
        let expires = now + DNS_CACHE_TTL;
        if let Some(e) = self.dns_cache.iter_mut().find(|e| e.name == name) {
            e.addrs = addrs;
            e.expires = expires;
            return;
        }
        if self.dns_cache.len() >= DNS_CACHE_SLOTS {
            // Evict an expired entry if any, else the soonest to expire.
            let victim = self
                .dns_cache
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.expires)
                .map(|(i, _)| i)
                .unwrap_or(0);
            self.dns_cache.swap_remove(victim);
        }
        self.dns_cache.push(DnsCacheEntry {
            name,
            addrs,
            expires,
        });
    }

    /// Hand `name` to the resolver thread. `false` when the thread cannot
    /// be started or has gone away, which the caller reports as `ENOENT`.
    fn resolve_async(&mut self, name: &[u8], slot: Option<usize>, v4_only: bool) -> Option<u32> {
        if slot.is_none() && self.warming.iter().any(|n| n.as_bytes() == name) {
            return None; // already looking this one up
        }
        if self.resolver.is_none() {
            self.resolver = Resolver::start();
        }
        let resolver = self.resolver.as_ref()?;
        self.resolve_seq = self.resolve_seq.wrapping_add(1).max(1);
        let id = self.resolve_seq;
        let job = ResolveJob {
            id,
            slot,
            name: String::from_utf8_lossy(name).into_owned(),
            v4_only,
        };
        if resolver.jobs.send(job).is_err() {
            log::error!("[linux_net] resolver thread is gone");
            self.resolver = None;
            // Nothing is in flight any more: the answers those names were
            // waiting for died with the thread.
            self.warming.clear();
            return None;
        }
        if slot.is_none() {
            self.warming
                .push(String::from_utf8_lossy(name).into_owned());
        }
        Some(id)
    }

    /// Build the per-instance state on the heap. The connection table is
    /// a `Vec` of small slot records; write backlogs are allocated per
    /// connection on first use, so the size of this struct does not
    /// scale with `max_conns * write_buf_max`. A `max_conns` outside
    /// `LINUX_NET_MAX_CONNS_MIN..=LINUX_NET_MAX_CONNS_CAP` is refused with
    /// the reason, never adjusted to fit.
    pub fn new(
        net_ins: [i32; LINUX_NET_MAX_INBOUND],
        lane_owners: [crate::kernel::workload::owner::OwnerHandle; LINUX_NET_MAX_INBOUND],
        net_outs: [i32; LINUX_NET_MAX_INBOUND],
        lane_out: [u8; LINUX_NET_MAX_INBOUND],
        max_conns: usize,
        write_buf_max: usize,
        listen_backlog: i32,
    ) -> Result<Box<Self>, String> {
        if !(LINUX_NET_MAX_CONNS_MIN..=LINUX_NET_MAX_CONNS_CAP).contains(&max_conns) {
            return Err(format!(
                "max_conns {max_conns} is outside [{LINUX_NET_MAX_CONNS_MIN}, \
                 {LINUX_NET_MAX_CONNS_CAP}] (the conn id is a u16 and the table needs a \
                 listener and a connection)"
            ));
        }
        let mut conns = Vec::with_capacity(max_conns);
        for _ in 0..max_conns {
            conns.push(LinuxNetConn::empty());
        }
        // SAFETY: plain libc call with no pointer arguments.
        let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epfd < 0 {
            log::error!("[linux_net] epoll_create1 failed; sockets will never report ready");
        }
        let mut ready = Vec::with_capacity(LINUX_NET_READY_BATCH);
        for _ in 0..LINUX_NET_READY_BATCH {
            ready.push(libc::epoll_event { events: 0, u64: 0 });
        }
        Ok(Box::new(Self {
            net_ins,
            lane_owners,
            net_outs,
            lane_out: lane_out.map(|j| j.min(LINUX_NET_MAX_INBOUND as u8 - 1)),
            conns,
            write_buf_max: write_buf_max.max(1),
            listen_backlog: listen_backlog.max(1),
            epfd,
            ready,
            ready_len: 0,
            cmd_buf: [0u8; LINUX_NET_CMD_MAX],
            msg_buf: [0u8; 16384],
            recv_buf: [0u8; 16384],
            hold_slot: -1,
            hold_off: 0,
            hold_len: 0,
            hold_lane: 0,
            // Skip slot 0 in initial rotation — it's almost always the
            // TCP listener bound by the first CMD_BIND.
            next_alloc: 1,
            pending_ctrl: core::array::from_fn(|_| PendingCtrl::new()),
            attached: (0..LINUX_NET_MAX_ATTACHED).map(|_| None).collect(),
            resolver: None,
            resolve_seq: 0,
            warming: Vec::new(),
            resolving: 0,
            dns_cache: Vec::new(),
            ctrl_refused: 0,
            dg_rx_dropped: 0,
        }))
    }

    /// Control frames refused because a destination's queue stood at
    /// [`Self::pending_ctrl_ceiling`].
    pub fn ctrl_refused(&self) -> u64 {
        self.ctrl_refused
    }

    /// Datagrams received and not delivered, over every endpoint.
    pub fn dg_rx_dropped(&self) -> u64 {
        self.dg_rx_dropped
    }

    /// Datagrams endpoint `ep` received and did not deliver.
    pub fn dg_endpoint_rx_dropped(&self, ep: usize) -> u64 {
        self.conns.get(ep).map_or(0, |c| c.dg_rx_dropped)
    }

    /// Control frames waiting for `lane`'s events channel.
    pub fn pending_ctrl_len(&self, lane: usize) -> usize {
        if lane < LINUX_NET_MAX_INBOUND {
            return self.pending_ctrl[self.lane_out[lane] as usize].len();
        }
        self.attached
            .get(lane - LINUX_NET_MAX_INBOUND)
            .and_then(|a| a.as_ref())
            .map_or(0, |a| a.pending.len())
    }

    /// Whether `lane`'s control queue is at [`PENDING_CTRL_CAP`]: its
    /// commands and accepts wait until the consumer reads.
    fn lane_paused(&self, lane: usize) -> bool {
        self.pending_ctrl_len(lane) >= PENDING_CTRL_CAP
    }

    /// The most frames one destination's queue can hold. A paused lane
    /// creates no slot, so past [`PENDING_CTRL_CAP`] the queue grows only
    /// by what the slots that exist still owe — at most three frames each
    /// (`MSG_CONNECTED`, `MSG_PEER`, `MSG_CLOSED`) — plus the two frames one
    /// command or accept emits before the pause is seen.
    pub fn pending_ctrl_ceiling(&self) -> usize {
        PENDING_CTRL_CAP + 2 + 3 * self.conns.len()
    }

    /// Register `fd` (held by slot `slot`) for `events` in the epoll set.
    /// Closing the fd removes it again, so slots are never explicitly
    /// deregistered.
    unsafe fn watch(&self, fd: i32, slot: usize, events: u32) {
        if self.epfd < 0 {
            return;
        }
        let mut ev = libc::epoll_event {
            events,
            u64: slot as u64,
        };
        if libc::epoll_ctl(self.epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) < 0 {
            let err = *libc::__errno_location();
            log::warn!("[linux_net] epoll add failed for slot {slot} (errno {err})");
        }
    }

    /// Change the events watched for `fd`.
    unsafe fn rewatch(&self, fd: i32, slot: usize, events: u32) {
        if self.epfd < 0 {
            return;
        }
        let mut ev = libc::epoll_event {
            events,
            u64: slot as u64,
        };
        libc::epoll_ctl(self.epfd, libc::EPOLL_CTL_MOD, fd, &mut ev);
    }

    /// Fill `ready` with the slots whose fds report readiness. Zero
    /// timeout: this runs inside a scheduler step.
    unsafe fn poll_ready(&mut self) {
        self.ready_len = 0;
        if self.epfd < 0 {
            return;
        }
        let n = libc::epoll_wait(
            self.epfd,
            self.ready.as_mut_ptr(),
            self.ready.len() as i32,
            0,
        );
        if n > 0 {
            self.ready_len = n as usize;
        }
    }

    /// Slot index carried by ready event `k`, or `None` if it no longer
    /// names a slot.
    fn ready_slot(&self, k: usize) -> Option<usize> {
        let slot = self.ready[k].u64 as usize;
        if slot < self.conns.len() {
            Some(slot)
        } else {
            None
        }
    }

    /// The control-frame queue for `lane`'s destination: its `net_outs`
    /// channel's for a boot lane, the lane's own for an attached one. `None`
    /// for an attached index with no lane.
    fn lane_queue(&mut self, lane: usize) -> Option<&mut PendingCtrl> {
        if lane < LINUX_NET_MAX_INBOUND {
            return Some(&mut self.pending_ctrl[self.lane_out[lane] as usize]);
        }
        self.attached
            .get_mut(lane - LINUX_NET_MAX_INBOUND)
            .and_then(|a| a.as_mut())
            .map(|a| &mut a.pending)
    }

    /// Flush `lane`'s queued control frames; stops at the first one its
    /// channel can't take so ordering is preserved. Returns true if the
    /// queue is now empty.
    unsafe fn flush_lane(&mut self, lane: usize) -> bool {
        let ch = lane_events(self, lane);
        let Some(q) = self.lane_queue(lane) else {
            return true;
        };
        while let Some((frame, len)) = q.front() {
            if ch < 0 {
                return false;
            }
            if channel::channel_write(ch, frame.as_ptr(), *len) < *len as i32 {
                return false;
            }
            q.pop_front();
        }
        true
    }

    /// Flush every destination's queued control frames, each on its own so
    /// a full channel holds up only its own. Returns true if all are empty.
    unsafe fn flush_pending_ctrl(&mut self) -> bool {
        let mut all_empty = true;
        for lane in 0..LINUX_NET_MAX_INBOUND {
            all_empty &= self.flush_lane(lane);
        }
        for j in 0..self.attached.len() {
            if self.attached[j].is_some() {
                all_empty &= self.flush_lane(LINUX_NET_MAX_INBOUND + j);
            }
        }
        all_empty
    }
}

/// The owner a lane's commands run as: the boot lane's producer, or the
/// workload that attached the lane.
fn lane_owner(st: &LinuxNetState, lane: usize) -> crate::kernel::workload::owner::OwnerHandle {
    if lane < LINUX_NET_MAX_INBOUND {
        return st.lane_owners[lane];
    }
    st.attached
        .get(lane - LINUX_NET_MAX_INBOUND)
        .and_then(|a| a.as_ref())
        .map_or(crate::kernel::workload::owner::OWNER_SYSTEM, |a| a.owner)
}

/// The channel a lane's commands are read from, or -1.
fn lane_commands(st: &LinuxNetState, lane: usize) -> i32 {
    if lane < LINUX_NET_MAX_INBOUND {
        return st.net_ins[lane];
    }
    st.attached
        .get(lane - LINUX_NET_MAX_INBOUND)
        .and_then(|a| a.as_ref())
        .map_or(-1, |a| a.commands)
}

/// The channel a lane's events go to: the `net_outs` channel its producer
/// reads for a boot lane, the lane's own for an attached one, or -1 for an
/// attached index with no lane.
fn lane_events(st: &LinuxNetState, lane: usize) -> i32 {
    if lane < LINUX_NET_MAX_INBOUND {
        return st.net_outs[st.lane_out[lane] as usize];
    }
    st.attached
        .get(lane - LINUX_NET_MAX_INBOUND)
        .and_then(|a| a.as_ref())
        .map_or(-1, |a| a.events)
}

/// Whether a command on `lane` may act on slot `idx`. An attached lane
/// reaches only the slots it created, and no other lane reaches those. Boot
/// lanes share the table among themselves.
fn lane_may_touch(st: &LinuxNetState, lane: usize, idx: usize) -> bool {
    let Some(c) = st.conns.get(idx) else {
        return true; // no such slot: the handler ignores it
    };
    if c.state == 0 {
        return true;
    }
    let owner_lane = c.lane as usize;
    owner_lane == lane || (owner_lane < LINUX_NET_MAX_INBOUND && lane < LINUX_NET_MAX_INBOUND)
}

/// Close every slot `lane` created, without a word to the lane: it is being
/// detached, and its events channel closes with it. Drops a recv tail held
/// for it, whose bytes have nowhere left to go.
unsafe fn close_lane_conns(st: &mut LinuxNetState, lane: usize) {
    let mut resolving_freed = 0usize;
    for (i, conn) in st.conns.iter_mut().enumerate() {
        if conn.state == 0 || conn.lane as usize != lane {
            continue;
        }
        if conn.state == 5 {
            resolving_freed += 1;
        }
        if conn.fd >= 0 {
            libc::close(conn.fd);
        }
        for &fd in &conn.racing {
            libc::close(fd);
        }
        log::info!("[linux_net] closed slot {i} (lane {lane} detached)");
        *conn = LinuxNetConn::empty();
    }
    st.resolving = st.resolving.saturating_sub(resolving_freed);
    if st.hold_slot >= 0 && st.hold_lane == lane {
        st.hold_slot = -1;
        st.hold_off = 0;
        st.hold_len = 0;
    }
}

unsafe fn set_nonblocking(fd: i32) {
    let flags = libc::fcntl(fd, libc::F_GETFL);
    if flags >= 0 {
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

// ----------------------------------------------------------------------
// linux_net instance registry
//
// The platform needs to reach every linux_net instance's connection table
// from OUTSIDE its step — for the owner teardown hook (drain/free), the
// rebuild fd close-out, and the bound-endpoint report. Instances register
// their state pointer at instantiation; the registry is swept-and-cleared
// at the top of every graph (re)build, before the old state is torn down.
// All access is on the single platform/scheduler thread.
// ----------------------------------------------------------------------

static mut LINUX_NET_REGISTRY: Vec<*mut LinuxNetState> = Vec::new();

/// Register a freshly-instantiated linux_net state. Platform thread only.
pub fn linux_net_register_state(ptr: *mut LinuxNetState) {
    // SAFETY: single-threaded platform instantiation path; the registry is
    // reached through a raw pointer, never forming a `&mut STATIC`.
    unsafe {
        let reg = &raw mut LINUX_NET_REGISTRY;
        (*reg).push(ptr);
    }
}

/// Close every fd in every registered instance and clear the registry.
/// Called at the top of every graph (re)build, BEFORE the destructive graph
/// reset drops the old module state — otherwise the old listener fds leak,
/// still holding their ports, and the re-issued CMD_BINDs after the rebuild
/// die on EADDRINUSE.
pub fn linux_net_close_all_and_clear_registry() {
    // SAFETY: single-threaded; pointers registered this graph generation are
    // still valid until prepare_graph tears the old graph down (called after).
    unsafe {
        let reg = &raw mut LINUX_NET_REGISTRY;
        for &st_ptr in (*reg).iter() {
            let st = &mut *st_ptr;
            for conn in st.conns.iter_mut() {
                if conn.fd >= 0 {
                    libc::close(conn.fd);
                }
                *conn = LinuxNetConn::empty();
            }
            st.resolving = 0;
            // Attached lanes' channels die with the graph they were opened in.
            for a in st.attached.iter_mut() {
                *a = None;
            }
            st.hold_slot = -1;
        }
        (*reg).clear();
    }
    // The provider is the instance the rebuild is about to register again.
    crate::kernel::workload::net_attach::unregister();
}

/// The instance that serves attached lanes: the first registered one.
///
/// # Safety
/// Platform thread; the pointer is valid until the next rebuild clears the
/// registry.
unsafe fn linux_net_provider_state() -> Option<&'static mut LinuxNetState> {
    let reg = &raw const LINUX_NET_REGISTRY;
    (*reg).first().map(|&p| &mut *p)
}

/// `net_attach` hook: take `(commands, events)` as a lane of `owner`'s.
/// EINVAL for a missing or shared channel, ENODEV with no instance, EEXIST
/// for an `(owner, key)` already attached, ENOSPC when every lane is taken.
///
/// # Safety
/// Scheduler thread; both channels are open for `owner`'s edges.
pub unsafe fn linux_net_attach(
    owner: crate::kernel::workload::owner::OwnerHandle,
    key: u8,
    commands: i32,
    events: i32,
) -> i32 {
    use crate::kernel::sys::errno;
    if commands < 0 || events < 0 || commands == events {
        return errno::EINVAL;
    }
    let Some(st) = linux_net_provider_state() else {
        return errno::ENODEV;
    };
    if st
        .attached
        .iter()
        .flatten()
        .any(|a| a.owner == owner && a.key == key)
    {
        return errno::EEXIST;
    }
    let Some(j) = st.attached.iter().position(|a| a.is_none()) else {
        log::warn!(
            "[linux_net] owner slot {} lane {key} refused: all {LINUX_NET_MAX_ATTACHED} attached lanes taken",
            owner.slot
        );
        return errno::ENOSPC;
    };
    st.attached[j] = Some(AttachedLane {
        owner,
        key,
        commands,
        events,
        pending: PendingCtrl::new(),
    });
    log::info!(
        "[linux_net] owner slot {} lane {key} attached as lane {} (commands {commands}, events {events})",
        owner.slot,
        LINUX_NET_MAX_INBOUND + j
    );
    0
}

/// `net_attach` hook: detach every lane of `owner`, drop what was queued
/// for them, and close every slot they created. A no-op for an owner with
/// no lanes.
///
/// # Safety
/// Scheduler thread, before `owner`'s channels close.
pub unsafe fn linux_net_detach(owner: crate::kernel::workload::owner::OwnerHandle) {
    let Some(st) = linux_net_provider_state() else {
        return;
    };
    for j in 0..st.attached.len() {
        if st.attached[j].as_ref().is_some_and(|a| a.owner == owner) {
            st.attached[j] = None;
            close_lane_conns(st, LINUX_NET_MAX_INBOUND + j);
            log::info!(
                "[linux_net] owner slot {} lane {} detached",
                owner.slot,
                LINUX_NET_MAX_INBOUND + j
            );
        }
    }
}

/// Close every connection slot stamped with `owner`, across all instances.
/// The drain driver calls this BEFORE `free_owner`, so an observer never sees
/// the owner's terminal record while its port is still accepting. Platform
/// thread only.
pub fn linux_net_close_owner_conns(owner: crate::kernel::workload::owner::OwnerHandle) {
    // SAFETY: single-threaded platform access to registered live instances,
    // reached through a raw pointer.
    unsafe {
        let reg = &raw const LINUX_NET_REGISTRY;
        for &st_ptr in (*reg).iter() {
            let st = &mut *st_ptr;
            let mut resolving_freed = 0usize;
            for (i, conn) in st.conns.iter_mut().enumerate() {
                if conn.state != 0 && conn.owner == owner {
                    if conn.state == 5 {
                        resolving_freed += 1;
                    }
                    if conn.fd >= 0 {
                        libc::close(conn.fd);
                        log::info!(
                            "[linux_net] closed slot {i} (owner slot {} revoked)",
                            owner.slot
                        );
                    }
                    *conn = LinuxNetConn::empty();
                }
            }
            st.resolving = st.resolving.saturating_sub(resolving_freed);
        }
    }
}

/// Snapshot the bound endpoints per owner: `(owner, protocol, port)` for every
/// live listener / UDP socket. Protocol: 1 = tcp, 2 = udp (matching
/// CONN_TYPE_UDP_BOUND mnemonically). The runtime's raw report — declarations
/// are the agent's business. Platform thread only.
pub fn linux_net_bound_endpoints() -> Vec<(crate::kernel::workload::owner::OwnerHandle, u8, u16)> {
    let mut out = Vec::new();
    // SAFETY: single-threaded platform access to registered live instances,
    // reached through a raw pointer.
    unsafe {
        let reg = &raw const LINUX_NET_REGISTRY;
        for &st_ptr in (*reg).iter() {
            let st = &*st_ptr;
            for conn in st.conns.iter() {
                if conn.state == 3 && conn.fd >= 0 && conn.port != 0 {
                    let proto = match conn.conn_type {
                        1 => 1u8,                   // tcp listener
                        CONN_TYPE_UDP_BOUND => 2u8, // udp socket
                        _ => continue,              // data conns: not endpoints
                    };
                    out.push((conn.owner, proto, conn.port));
                }
            }
        }
    }
    out
}

fn linux_net_alloc_conn(st: &mut LinuxNetState) -> i32 {
    // Round-robin from `next_alloc`. After allocating slot N, advance
    // `next_alloc` to N+1 so the same slot isn't picked again until the
    // table has cycled — by that time any stale CMD_SEND bytes for the
    // previous occupant have been drained and harmlessly dropped (they
    // hit `state == 0` and exit early).
    let n = st.conns.len();
    let start = st.next_alloc % n;
    for off in 0..n {
        let i = (start + off) % n;
        if st.conns[i].state == 0 {
            st.next_alloc = (i + 1) % n;
            return i as i32;
        }
    }
    -1
}

/// Emit one control frame, `[type][payload]`, to `lane`'s events channel:
/// the lane a slot's events belong to, or the lane whose command a
/// slot-less result answers. Every control frame fits a queue slot, checked
/// at compile time, so none can be too large to build. Ordering is per
/// destination: a frame that cannot be written now, or that would overtake
/// one already queued, is queued behind it. Nothing queued is evicted; the
/// lane's sources pause at [`PENDING_CTRL_CAP`] instead, and a frame that
/// finds the queue at [`LinuxNetState::pending_ctrl_ceiling`] is counted and
/// logged.
unsafe fn linux_net_send_msg<const N: usize>(st: &mut LinuxNetState, lane: usize, data: &[u8; N]) {
    const {
        assert!(
            N >= 1 && N + 2 <= CTRL_FRAME_MAX,
            "a control frame must fit a queue slot"
        );
    }
    let events = lane_events(st, lane);
    if events < 0 {
        return;
    }
    let payload_len = (N - 1) as u16;
    let total = N + 2;
    let mut frame = [0u8; CTRL_FRAME_MAX];
    frame[0] = data[0];
    frame[1] = payload_len as u8;
    frame[2] = (payload_len >> 8) as u8;
    frame[3..total].copy_from_slice(&data[1..]);
    let queued_empty = st.flush_lane(lane);
    if queued_empty && channel::channel_write(events, frame.as_ptr(), total) == total as i32 {
        return;
    }
    let ceiling = st.pending_ctrl_ceiling();
    let queued = match st.lane_queue(lane) {
        Some(q) if q.len() < ceiling => {
            q.push_back((frame, total));
            true
        }
        _ => false,
    };
    if !queued {
        st.ctrl_refused += 1;
        log::error!(
            "[linux_net] lane {lane}: control frame 0x{:02x} refused, its queue is at its \
             ceiling of {ceiling} ({} refused)",
            data[0],
            st.ctrl_refused
        );
    }
}

/// `MSG_ERROR [conn_id: u16 LE][errno][requester_tag: u16 LE]`: the tagged
/// terminal result of a failed dial.
fn connect_error_frame(
    conn_id: u16,
    errno: u8,
    tag: crate::abi::contracts::net::net_proto::RequesterTag,
) -> [u8; 6] {
    let c = conn_id.to_le_bytes();
    let t = tag.to_le_bytes();
    [MSG_ERROR, c[0], c[1], errno, t[0], t[1]]
}

/// Report stream `conn_id`'s peer (`MSG_PEER`), the socket's remote end,
/// queued after the `MSG_ACCEPTED` / `MSG_CONNECTED` it follows and ahead of
/// the stream's data.
unsafe fn linux_net_send_peer(st: &mut LinuxNetState, lane: usize, conn_id: usize, fd: i32) {
    use crate::abi::contracts::net::net_proto as np;
    let mut ss: libc::sockaddr_storage = core::mem::zeroed();
    let mut len = core::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    if libc::getpeername(fd, &mut ss as *mut _ as *mut libc::sockaddr, &mut len) != 0 {
        return;
    }
    let mut addr = [0u8; 16];
    let (family, port) = match ss.ss_family as i32 {
        libc::AF_INET => {
            let a = &*(&ss as *const _ as *const libc::sockaddr_in);
            addr[..4].copy_from_slice(&a.sin_addr.s_addr.to_ne_bytes());
            (np::AF_INET, u16::from_be(a.sin_port))
        }
        libc::AF_INET6 => {
            let a = &*(&ss as *const _ as *const libc::sockaddr_in6);
            addr = a.sin6_addr.s6_addr;
            (np::AF_INET6, u16::from_be(a.sin6_port))
        }
        _ => return,
    };
    let mut frame = [0u8; 3 + np::PEER_LEN];
    if np::write_peer(&mut frame, conn_id as u16, family, &addr, port).is_none() {
        return;
    }
    // `linux_net_send_msg` takes `[type][payload]` and frames it.
    let mut msg = [0u8; 1 + np::PEER_LEN];
    msg[0] = np::MSG_PEER;
    msg[1..].copy_from_slice(&frame[3..]);
    linux_net_send_msg(st, lane, &msg);
}

/// `MSG_CONNECTED [conn_id: u16 LE][requester_tag: u16 LE]`.
fn connected_frame(
    conn_id: [u8; 2],
    tag: crate::abi::contracts::net::net_proto::RequesterTag,
) -> [u8; 5] {
    let t = tag.to_le_bytes();
    [MSG_CONNECTED, conn_id[0], conn_id[1], t[0], t[1]]
}

/// Emit `MSG_BIND_REFUSED [port:2 LE][errno:1]` so a bind failure/refusal is
/// surfaced to the requester rather than leaving it waiting for MSG_BOUND.
unsafe fn linux_net_send_bind_refused(st: &mut LinuxNetState, lane: usize, port: u16, errno: u8) {
    let pb = port.to_le_bytes();
    let msg = [MSG_BIND_REFUSED, pb[0], pb[1], errno];
    linux_net_send_msg(st, lane, &msg);
}

/// Emit the datagram contract's `DG_MSG_ERROR [ep_id][errno]` for a failed
/// `DG_CMD_BIND`, alongside `MSG_BIND_REFUSED`: datagram-contract modules
/// (dns et al.) parse only `DG_MSG_*` opcodes in their WaitBound states, so
/// without this frame a refused UDP bind parks them forever instead of
/// faulting. `ep_id` 0xFF = no endpoint was
/// allocated. Emitting both frames is additive-safe: each surface's
/// listeners match only their own opcode.
unsafe fn linux_net_send_dg_error(st: &mut LinuxNetState, lane: usize, errno: u8) {
    linux_net_send_dg_ep_error(st, lane, 0xFF, errno);
}

/// `DG_MSG_ERROR [ep_id][errno]` for endpoint `ep` (0xFF: none).
unsafe fn linux_net_send_dg_ep_error(st: &mut LinuxNetState, lane: usize, ep: u8, errno: u8) {
    let msg = [DG_MSG_ERROR, ep, errno];
    linux_net_send_msg(st, lane, &msg);
}

/// The Part B bind gate for a NEW bind by `commander`: admission must be open
/// (a Draining owner binds nothing new — same-owner re-binds of held ports
/// never reach this, they take the use-class fast path), and when the
/// committed plan is lease-aware the (protocol, port) must be granted.
/// System-owned commanders are ungated, as everywhere; one acting with the
/// node's authority binds as the node does once its own admission is open.
/// Returns the refusal errno, or None to proceed.
fn linux_net_new_bind_refusal(
    commander: crate::kernel::workload::owner::OwnerHandle,
    protocol: u8,
    port: u16,
) -> Option<u8> {
    if commander.is_system() {
        return None;
    }
    if !crate::kernel::exec::scheduler::owners_mut().authorize_admit(commander) {
        log::warn!(
            "[linux_net] bind port {port} refused: owner slot {} draining/revoked",
            commander.slot
        );
        return Some(1); // EPERM
    }
    if crate::kernel::exec::scheduler::owners()
        .authority_of(commander)
        .is_system()
    {
        return None;
    }
    match crate::kernel::workload::owner_plan::lease_gate(
        commander.slot,
        commander.generation,
        protocol,
        port,
    ) {
        crate::kernel::workload::owner_plan::LeaseGate::Refused => {
            log::warn!(
                "[linux_net] bind port {port} refused: no lease granted to owner slot {}",
                commander.slot
            );
            Some(13) // EACCES
        }
        _ => None,
    }
}

unsafe fn linux_net_cmd_bind(st: &mut LinuxNetState, port: u16, lane: usize) {
    let commander = lane_owner(st, lane);
    // Embedded IP modules close their listener after each accepted
    // connection; their TCP/IP servers re-issue CMD_BIND between
    // requests. On Linux the listening fd persists, so a re-bind on the
    // same port would fail with EADDRINUSE. Acknowledge the re-bind with
    // MSG_BOUND immediately when an existing listener is alive *for the
    // same port* — but ONLY for the same commanding owner: the fast path
    // was owner-blind and would silently hand one owner's listener to
    // another. Same-owner re-bind is use-class (allowed even while
    // Draining — the accept-loop case); a cross-owner claim on a live
    // listener is refused. So is a claim across an attached lane: the
    // listener's accepts go to the lane that bound it, never to another.
    for (li, c) in st.conns.iter().enumerate() {
        if c.state == 3 && c.conn_type == 1 && c.fd >= 0 && c.port == port {
            if c.owner == commander && lane_may_touch(st, lane, li) {
                // MSG_BOUND payload: [conn_id:2 LE][local_port:2 LE]
                let pb = port.to_le_bytes();
                let cb = (li as u16).to_le_bytes();
                let msg = [MSG_BOUND, cb[0], cb[1], pb[0], pb[1]];
                linux_net_send_msg(st, lane, &msg);
            } else {
                log::warn!(
                    "[linux_net] bind port {port} refused: held by owner slot {} \
                     (requester owner slot {})",
                    c.owner.slot,
                    commander.slot
                );
                linux_net_send_bind_refused(st, lane, port, 98); // EADDRINUSE
            }
            return;
        }
    }

    if let Some(errno) = linux_net_new_bind_refusal(commander, 1, port) {
        linux_net_send_bind_refused(st, lane, port, errno);
        return;
    }

    let slot = linux_net_alloc_conn(st);
    if slot < 0 {
        log::error!("[linux_net] no free slots for listener");
        linux_net_send_bind_refused(st, lane, port, 105); // ENOBUFS
        return;
    }

    let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
    if fd < 0 {
        log::error!("[linux_net] socket() failed");
        linux_net_send_bind_refused(st, lane, port, 23); // ENFILE
        return;
    }

    let opt: i32 = 1;
    libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_REUSEADDR,
        &opt as *const i32 as *const libc::c_void,
        4,
    );

    let mut addr: libc::sockaddr_in = core::mem::zeroed();
    addr.sin_family = libc::AF_INET as u16;
    addr.sin_port = port.to_be();
    addr.sin_addr.s_addr = 0;

    if libc::bind(
        fd,
        &addr as *const libc::sockaddr_in as *const libc::sockaddr,
        core::mem::size_of::<libc::sockaddr_in>() as u32,
    ) < 0
    {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        log::error!("[linux_net] bind() failed on port {port} (errno {errno})");
        libc::close(fd);
        linux_net_send_bind_refused(st, lane, port, errno.clamp(0, 255) as u8);
        return;
    }

    // Backlog 128: the kernel's SYN queue must absorb the entire
    // burst of a high-concurrency connect (clients ramp up
    // simultaneously in benchmarks). At backlog=8 a 32-client burst
    // dropped SYNs 9..=32 — clients saw ConnectionReset on connect.
    if libc::listen(fd, st.listen_backlog) < 0 {
        log::error!("[linux_net] listen() failed");
        libc::close(fd);
        linux_net_send_bind_refused(st, lane, port, 95); // EOPNOTSUPP
        return;
    }

    set_nonblocking(fd);
    let idx = slot as usize;
    st.conns[idx] = LinuxNetConn {
        fd,
        conn_type: 1,
        state: 3,
        port,
        owner: commander,
        lane: lane as u16,
        ..LinuxNetConn::empty()
    };
    st.watch(fd, idx, libc::EPOLLIN as u32);
    // The scenario runner uses this stderr line as its readiness signal. Keep it
    // visible at the default warning log level; an info-only signal makes
    // `fluxor run` kill a healthy, already-listening host after five seconds.
    log::warn!("[linux_net] listening on port {port} (slot {idx})");

    // MSG_BOUND payload: `[conn_id:2 LE][local_port:2 LE]`. Consumers sharing
    // net_out filter by local_port; without it a second anchor's BIND races on
    // the same channel and steals server_conn_id.
    //
    // This file has two bind paths — this one and the owner-gated one above —
    // and both must emit this exact shape. A short frame does not fail loudly:
    // the consumer skips the port it cannot read, never latches an accept port,
    // and falls back to claiming every accept, which is indistinguishable from
    // working multi-anchor filtering until a second anchor exists.
    let pb = port.to_le_bytes();
    let cb = (idx as u16).to_le_bytes();
    let msg = [MSG_BOUND, cb[0], cb[1], pb[0], pb[1]];
    linux_net_send_msg(st, lane, &msg);
}

// ----------------------------------------------------------------------
// Datagram surface — UDP bind / send_to / recvfrom on the same channel
// ----------------------------------------------------------------------

/// Decode the optional owner tag at the head of a `DG_CMD_SEND_TO` /
/// `DG_CMD_CLOSE` payload. Returns `(claimed_tag, offset_of_next_field)` —
/// the offset is `1` for the untagged shape, so an untagged command decodes
/// exactly as it did before the tag existed. An absent tag reads as 0.
fn dg_claimed_owner_tag(payload: &[u8]) -> (u16, usize) {
    if payload.len() > DG_OWNER_TAG_FIELD && payload[1] == DG_OWNER_TAG_MARK {
        (
            u16::from_le_bytes([payload[2], payload[3]]),
            1 + DG_OWNER_TAG_FIELD,
        )
    } else {
        (0, 1)
    }
}

unsafe fn linux_net_dg_cmd_bind(st: &mut LinuxNetState, port: u16, owner_tag: u16, lane: usize) {
    let commander = lane_owner(st, lane);
    if let Some(errno) = linux_net_new_bind_refusal(commander, 2, port) {
        linux_net_send_bind_refused(st, lane, port, errno);
        linux_net_send_dg_error(st, lane, errno);
        return;
    }
    let slot = linux_net_alloc_conn(st);
    if slot < 0 {
        log::error!("[linux_net] no free slots for UDP bind");
        linux_net_send_bind_refused(st, lane, port, 105); // ENOBUFS
        linux_net_send_dg_error(st, lane, 105);
        return;
    }

    let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
    if fd < 0 {
        log::error!("[linux_net] UDP socket() failed");
        linux_net_send_bind_refused(st, lane, port, 23); // ENFILE
        linux_net_send_dg_error(st, lane, 23);
        return;
    }
    let opt: i32 = 1;
    libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_REUSEADDR,
        &opt as *const i32 as *const libc::c_void,
        4,
    );
    // Each datagram's arrival address, so its answer leaves from it.
    libc::setsockopt(
        fd,
        libc::IPPROTO_IP,
        libc::IP_PKTINFO,
        &opt as *const i32 as *const libc::c_void,
        4,
    );

    let mut addr: libc::sockaddr_in = core::mem::zeroed();
    addr.sin_family = libc::AF_INET as u16;
    addr.sin_port = port.to_be();
    addr.sin_addr.s_addr = 0;

    if libc::bind(
        fd,
        &addr as *const libc::sockaddr_in as *const libc::sockaddr,
        core::mem::size_of::<libc::sockaddr_in>() as u32,
    ) < 0
    {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        log::error!("[linux_net] UDP bind() failed on port {port} (errno {errno})");
        libc::close(fd);
        linux_net_send_bind_refused(st, lane, port, errno.clamp(0, 255) as u8);
        linux_net_send_dg_error(st, lane, errno.clamp(0, 255) as u8);
        return;
    }
    set_nonblocking(fd);
    let idx = slot as usize;
    // `port` is recorded: the endpoint report and the bind gate both need it.
    st.conns[idx] = LinuxNetConn {
        fd,
        conn_type: CONN_TYPE_UDP_BOUND,
        state: 3,
        port,
        owner: commander,
        lane: lane as u16,
        dg_owner_tag: owner_tag,
        ..LinuxNetConn::empty()
    };
    st.watch(fd, idx, libc::EPOLLIN as u32);
    log::info!("[linux_net] UDP bound port {port} (slot {idx})");

    // MSG_DG_BOUND payload (datagram contract):
    //   [ep_id: u8] [local_port: u16 LE].
    let mut msg = [0u8; 1 + 3];
    msg[0] = DG_MSG_BOUND;
    msg[1] = idx as u8;
    msg[2] = (port & 0xFF) as u8;
    msg[3] = (port >> 8) as u8;
    linux_net_send_msg(st, lane, &msg);
}

/// Whether the consumer claiming `claimed_tag` may send on endpoint `ep`:
/// the slot holds a live bound datagram endpoint and the tag recorded at
/// bind is the one claimed. Answers `EPERM` on a live endpoint reached by
/// a consumer that does not hold it, and nothing at all on a slot that
/// holds no endpoint. Asked BEFORE the destination is read, so an
/// unowned endpoint buys neither a datagram nor a name lookup.
unsafe fn dg_endpoint_admits(
    st: &mut LinuxNetState,
    lane: usize,
    ep: i16,
    claimed_tag: u16,
) -> bool {
    if ep < 0 || (ep as usize) >= st.conns.len() {
        return false;
    }
    let c = &st.conns[ep as usize];
    if c.state != 3 || c.conn_type != CONN_TYPE_UDP_BOUND || c.fd < 0 {
        return false;
    }
    if c.dg_owner_tag != claimed_tag {
        linux_net_send_dg_error(st, lane, 1); // EPERM
        return false;
    }
    true
}

unsafe fn linux_net_dg_cmd_send_to(
    st: &mut LinuxNetState,
    lane: usize,
    ep: i16,
    claimed_tag: u16,
    ip: [u8; 4],
    port: u16,
    data: &[u8],
) {
    if ep < 0 || (ep as usize) >= st.conns.len() {
        return;
    }
    let idx = ep as usize;
    let (state, conn_type, fd, bound_tag) = {
        let c = &st.conns[idx];
        (c.state, c.conn_type, c.fd, c.dg_owner_tag)
    };
    if state != 3 || conn_type != CONN_TYPE_UDP_BOUND || fd < 0 {
        return;
    }
    // `ep` is an index, not an authority: the command channel merges every
    // producer into one stream and carries no producer identity. The tag
    // recorded at bind is what says who holds the endpoint.
    if bound_tag != claimed_tag {
        linux_net_send_dg_error(st, lane, 1); // EPERM
        return;
    }
    let mut addr: libc::sockaddr_in = core::mem::zeroed();
    addr.sin_family = libc::AF_INET as u16;
    addr.sin_port = port.to_be();
    addr.sin_addr.s_addr = u32::from_le_bytes([ip[0], ip[1], ip[2], ip[3]]);
    let from = st.conns[idx]
        .dg_reply_from
        .iter()
        .find(|(a, p, _)| *a == addr.sin_addr.s_addr && *p == port)
        .map(|e| e.2);
    dg_send_from(fd, &addr, from, data);
}

/// Send `data` to `to` on `fd`, from local address `from` (`s_addr`) when
/// given — an answer leaves from the address its question arrived at — and
/// from the route's preferred source otherwise.
unsafe fn dg_send_from(fd: i32, to: &libc::sockaddr_in, from: Option<u32>, data: &[u8]) {
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    // Room for one `in_pktinfo` control message, aligned as cmsg requires.
    let mut cbuf = [0u64; 8];
    let mut msg: libc::msghdr = core::mem::zeroed();
    msg.msg_name = to as *const libc::sockaddr_in as *mut libc::c_void;
    msg.msg_namelen = core::mem::size_of::<libc::sockaddr_in>() as u32;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if let Some(src) = from {
        let space = libc::CMSG_SPACE(core::mem::size_of::<libc::in_pktinfo>() as u32) as usize;
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space.min(core::mem::size_of_val(&cbuf)) as _;
        let c = libc::CMSG_FIRSTHDR(&msg);
        if !c.is_null() {
            (*c).cmsg_level = libc::IPPROTO_IP;
            (*c).cmsg_type = libc::IP_PKTINFO;
            (*c).cmsg_len = libc::CMSG_LEN(core::mem::size_of::<libc::in_pktinfo>() as u32) as _;
            let info = libc::in_pktinfo {
                ipi_ifindex: 0,
                ipi_spec_dst: libc::in_addr { s_addr: src },
                ipi_addr: libc::in_addr { s_addr: 0 },
            };
            core::ptr::write_unaligned(libc::CMSG_DATA(c) as *mut libc::in_pktinfo, info);
        }
    }
    libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL);
}

/// The local address a datagram arrived at, from its `IP_PKTINFO`: the
/// header's destination when it is a unicast one, else the address the host
/// would answer a broadcast or multicast from.
unsafe fn dg_arrival_addr(msg: &libc::msghdr) -> Option<u32> {
    let mut c = libc::CMSG_FIRSTHDR(msg);
    while !c.is_null() {
        if (*c).cmsg_level == libc::IPPROTO_IP && (*c).cmsg_type == libc::IP_PKTINFO {
            let info = core::ptr::read_unaligned(libc::CMSG_DATA(c) as *const libc::in_pktinfo);
            let dst = info.ipi_addr.s_addr;
            let first = dst.to_le_bytes()[0];
            let unicast = dst != 0 && dst != u32::MAX && !(224..=239).contains(&first);
            let a = if unicast {
                dst
            } else {
                info.ipi_spec_dst.s_addr
            };
            return (a != 0).then_some(a);
        }
        c = libc::CMSG_NXTHDR(msg, c);
    }
    None
}

/// Remember that `peer` reached `conn` at local address `local`.
fn dg_note_arrival(conn: &mut LinuxNetConn, peer: (u32, u16), local: u32) {
    let v = &mut conn.dg_reply_from;
    if let Some(at) = v.iter().position(|(a, p, _)| (*a, *p) == peer) {
        v.remove(at);
    } else if v.len() >= DG_REPLY_FROM_MAX {
        v.remove(0);
    }
    v.push((peer.0, peer.1, local));
}

unsafe fn linux_net_dg_cmd_close(st: &mut LinuxNetState, lane: usize, ep: i16, claimed_tag: u16) {
    if ep < 0 || (ep as usize) >= st.conns.len() {
        return;
    }
    let idx = ep as usize;
    // Close is the destructive half of the same authority question as send.
    if st.conns[idx].conn_type == CONN_TYPE_UDP_BOUND && st.conns[idx].dg_owner_tag != claimed_tag {
        linux_net_send_dg_error(st, lane, 1); // EPERM
        return;
    }
    if st.conns[idx].fd >= 0 && st.conns[idx].conn_type == CONN_TYPE_UDP_BOUND {
        libc::close(st.conns[idx].fd);
    }
    st.conns[idx] = LinuxNetConn::empty();

    let mut msg = [0u8; 3];
    msg[0] = DG_MSG_CLOSED;
    let ep_b = ep.to_le_bytes();
    msg[1] = ep_b[0];
    msg[2] = ep_b[1];
    linux_net_send_msg(st, lane, &msg);
}

unsafe fn linux_net_dg_poll_recv(st: &mut LinuxNetState) -> bool {
    // `DG_MSG_RX_FROM [ep_id][af = 4][src_addr: 4 BE][src_port: u16 LE][data]`,
    // built whole in `msg_buf`: the datagram is received straight after its
    // header, so the largest one delivered is what one frame there carries.
    const HDR: usize = 3 + 1 + 1 + 4 + 2;
    let mut had_work = false;
    let mut k = 0;
    while k < st.ready_len {
        let Some(i) = st.ready_slot(k) else {
            k += 1;
            continue;
        };
        if st.conns[i].conn_type == CONN_TYPE_UDP_BOUND
            && st.conns[i].state == 3
            && st.conns[i].fd >= 0
        {
            let mut from: libc::sockaddr_in = core::mem::zeroed();
            let mut iov = libc::iovec {
                iov_base: st.msg_buf.as_mut_ptr().add(HDR) as *mut libc::c_void,
                iov_len: st.msg_buf.len() - HDR,
            };
            let mut cbuf = [0u64; 8];
            let mut mh: libc::msghdr = core::mem::zeroed();
            mh.msg_name = &mut from as *mut libc::sockaddr_in as *mut libc::c_void;
            mh.msg_namelen = core::mem::size_of::<libc::sockaddr_in>() as u32;
            mh.msg_iov = &mut iov;
            mh.msg_iovlen = 1;
            mh.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
            mh.msg_controllen = core::mem::size_of_val(&cbuf) as _;
            let n = libc::recvmsg(st.conns[i].fd, &mut mh, 0);
            if n > 0 {
                let n = n as usize;
                let port = u16::from_be(from.sin_port);
                if let Some(local) = dg_arrival_addr(&mh) {
                    dg_note_arrival(&mut st.conns[i], (from.sin_addr.s_addr, port), local);
                }
                let lane = st.conns[i].lane as usize;
                let total = HDR + n;
                let delivered = if mh.msg_flags & libc::MSG_TRUNC != 0 {
                    // Larger than a frame carries: a cut datagram is never
                    // delivered as if it were whole.
                    false
                } else {
                    let payload_len = (total - 3) as u16;
                    let ip_b = from.sin_addr.s_addr.to_le_bytes();
                    let pb = port.to_le_bytes();
                    st.msg_buf[..HDR].copy_from_slice(&[
                        DG_MSG_RX_FROM,
                        payload_len as u8,
                        (payload_len >> 8) as u8,
                        i as u8,
                        DG_AF_INET,
                        ip_b[0],
                        ip_b[1],
                        ip_b[2],
                        ip_b[3],
                        pb[0],
                        pb[1],
                    ]);
                    let events = lane_events(st, lane);
                    // A datagram never overtakes a queued control frame (the
                    // endpoint's own DG_MSG_BOUND among them).
                    events >= 0
                        && st.flush_lane(lane)
                        && channel::channel_write(events, st.msg_buf.as_ptr(), total)
                            == total as i32
                };
                if !delivered {
                    // UDP may drop; it is never dropped uncounted.
                    st.conns[i].dg_rx_dropped += 1;
                    st.dg_rx_dropped += 1;
                    if st.dg_rx_dropped.is_power_of_two() {
                        log::warn!(
                            "[linux_net] datagram endpoint {i}: {} arrival(s) not delivered \
                             ({} over every endpoint; the latest {n} B{})",
                            st.conns[i].dg_rx_dropped,
                            st.dg_rx_dropped,
                            if mh.msg_flags & libc::MSG_TRUNC != 0 {
                                ", larger than a frame"
                            } else {
                                ", its consumer's channel full"
                            }
                        );
                    }
                }
                had_work = true;
            }
        }
        k += 1;
    }
    had_work
}

/// The dial. Literals dial at once; a name is served from the cache or
/// parked in a `resolving` slot (state 5, no fd) until the resolver thread
/// answers, at which point it takes the same path a literal does.
unsafe fn linux_net_cmd_connect_to(
    st: &mut LinuxNetState,
    sock_type: u8,
    port: u16,
    target: crate::abi::contracts::net::net_proto::Target<'_>,
    tag: crate::abi::contracts::net::net_proto::RequesterTag,
    lane: usize,
) {
    use crate::abi::contracts::net::net_proto::Target;
    // STREAM-only surface (the net_proto stream surface). Datagram traffic uses
    // the datagram surface (CMD_DG_BIND / CMD_DG_SEND_TO), so a non-stream
    // sock_type is rejected with EINVAL — matching the bare-metal IP module
    // and the public contract.
    const SOCK_TYPE_STREAM: u8 = 1;
    if sock_type != SOCK_TYPE_STREAM {
        let msg = connect_error_frame(0, 22u8, tag); // EINVAL, no slot allocated (conn 0, u16 LE)
        linux_net_send_msg(st, lane, &msg);
        return;
    }
    let addrs = match target {
        Target::V4(a) => Some(vec![Resolved::V4(a)]),
        Target::V6(a) => Some(vec![Resolved::V6(a)]),
        Target::Name(name) => st.dns_cache_get(name),
    };
    let slot = linux_net_alloc_conn(st);
    if slot < 0 {
        log::error!("[linux_net] no free connection slots");
        // Tagged terminal result (ENOMEM) so the requester completes.
        let msg = connect_error_frame(0, 12u8, tag);
        linux_net_send_msg(st, lane, &msg);
        return;
    }
    let idx = slot as usize;
    let owner = lane_owner(st, lane);
    match addrs {
        Some(addrs) if !addrs.is_empty() => {
            let mut addrs = dial_candidates(addrs);
            let first = addrs.remove(0);
            let dial = Dial {
                sock_type,
                alts: addrs,
                port,
                tag,
                owner,
                lane: lane as u16,
                racing: Vec::new(),
            };
            linux_net_dial(st, idx, first, dial);
        }
        _ => {
            let Target::Name(name) = target else {
                unreachable!("a literal always has an address");
            };
            match st.resolve_async(name, Some(idx), false) {
                Some(id) => {
                    st.resolving += 1;
                    st.conns[idx] = LinuxNetConn {
                        fd: -1,
                        conn_type: sock_type,
                        state: 5,
                        port,
                        connect_tag: tag,
                        resolve_id: id,
                        resolve_started: Some(std::time::Instant::now()),
                        owner,
                        lane: lane as u16,
                        ..LinuxNetConn::empty()
                    };
                }
                None => {
                    st.conns[idx] = LinuxNetConn::empty();
                    let msg = connect_error_frame(0, 2u8, tag); // ENOENT
                    linux_net_send_msg(st, lane, &msg);
                }
            }
        }
    }
}

/// One posted result, or `None` when the queue is empty — or the thread is
/// gone, in which case the queue is dropped with it.
fn take_resolved(st: &mut LinuxNetState) -> Option<ResolveDone> {
    match st.resolver.as_ref()?.done.try_recv() {
        Ok(d) => Some(d),
        Err(std::sync::mpsc::TryRecvError::Empty) => None,
        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
            st.resolver = None;
            st.warming.clear();
            None
        }
    }
}

/// Take the results the resolver thread has posted since the last step.
/// A stream result lands in the slot that is still waiting on it (matched
/// by id, so a revoked-and-retaken slot never receives someone else's
/// address); a datagram result only warms the cache.
unsafe fn linux_net_drain_resolved(st: &mut LinuxNetState) -> bool {
    let mut had_work = false;
    while let Some(done) = take_resolved(st) {
        had_work = true;
        if done.slot.is_none() {
            st.warming.retain(|n| *n != done.name);
        }
        // The candidates are chosen once, and the cache holds exactly them,
        // so a name answered from cache dials as a fresh one does.
        let result = done.result.map(dial_candidates);
        if let Ok(addrs) = &result {
            st.dns_cache_put(done.name.clone(), addrs.clone());
        }
        let Some(idx) = done.slot else {
            continue;
        };
        if idx >= st.conns.len() || st.conns[idx].state != 5 || st.conns[idx].resolve_id != done.id
        {
            continue; // stale: the slot was revoked while the lookup ran
        }
        st.resolving = st.resolving.saturating_sub(1);
        let (sock_type, port, tag, owner, lane) = {
            let c = &st.conns[idx];
            (c.conn_type, c.port, c.connect_tag, c.owner, c.lane)
        };
        match result {
            Ok(addrs) if !addrs.is_empty() => {
                let mut addrs = addrs;
                let first = addrs.remove(0);
                let dial = Dial {
                    sock_type,
                    alts: addrs,
                    port,
                    tag,
                    owner,
                    lane,
                    racing: Vec::new(),
                };
                linux_net_dial(st, idx, first, dial);
            }
            Ok(_) => {
                st.conns[idx] = LinuxNetConn::empty();
                let msg = connect_error_frame(0, libc::ENOENT as u8, tag);
                linux_net_send_msg(st, lane as usize, &msg);
            }
            Err(errno) => {
                st.conns[idx] = LinuxNetConn::empty();
                let msg = connect_error_frame(0, errno as u8, tag);
                linux_net_send_msg(st, lane as usize, &msg);
            }
        }
    }
    // A slot the resolver never answered for: fail it rather than pin it.
    if st.resolving == 0 {
        return had_work;
    }
    let now = std::time::Instant::now();
    for i in 0..st.conns.len() {
        if st.conns[i].state != 5 {
            continue;
        }
        let Some(started) = st.conns[i].resolve_started else {
            continue;
        };
        if now.duration_since(started) > RESOLVE_GUARD {
            let tag = st.conns[i].connect_tag;
            let lane = st.conns[i].lane as usize;
            st.conns[i] = LinuxNetConn::empty();
            st.resolving = st.resolving.saturating_sub(1);
            let msg = connect_error_frame(0, 2u8, tag); // ENOENT
            linux_net_send_msg(st, lane, &msg);
            had_work = true;
        }
    }
    had_work
}

/// Interleave the resolved addresses by family, first of each in turn
/// (RFC 8305 §4).
///
/// `getaddrinfo` groups by family, so a host that answers with four IPv6
/// addresses and one IPv4 would have the ladder spend all its patience on
/// IPv6 before ever reaching the address that works. Alternating means the
/// second rung is always the other family, which is where the answer is when
/// a family is the thing that is broken.
///
/// The host's ordering WITHIN a family is preserved: that part encodes
/// policy this provider has no better view of.
pub fn interleave_families(addrs: Vec<Resolved>) -> Vec<Resolved> {
    let mut first: Vec<Resolved> = Vec::with_capacity(addrs.len());
    let mut second: Vec<Resolved> = Vec::new();
    // Whichever family the host put first keeps the lead: its preference
    // ordering is the one signal available about which is likelier to work.
    let lead_is_v6 = matches!(addrs.first(), Some(Resolved::V6(_)));
    for a in addrs {
        let is_v6 = matches!(a, Resolved::V6(_));
        if is_v6 == lead_is_v6 {
            first.push(a);
        } else {
            second.push(a);
        }
    }
    let mut out = Vec::with_capacity(first.len() + second.len());
    let mut a = first.into_iter();
    let mut b = second.into_iter();
    loop {
        match (a.next(), b.next()) {
            (None, None) => break,
            (x, y) => {
                if let Some(v) = x {
                    out.push(v);
                }
                if let Some(v) = y {
                    out.push(v);
                }
            }
        }
    }
    out
}

/// The addresses a name is dialled at, in dial order: every address the host
/// answered, families interleaved, then cut to [`MAX_DIAL_CANDIDATES`]. The
/// cut comes after the interleave, so a host that answers several addresses
/// of one family ahead of the other is still dialled over both.
pub fn dial_candidates(addrs: Vec<Resolved>) -> Vec<Resolved> {
    let mut out = interleave_families(addrs);
    out.truncate(MAX_DIAL_CANDIDATES);
    out
}

/// One outbound connect as this provider carries it: what the consumer
/// asked for, who to answer, and the addresses the name resolved to that
/// have not been tried yet. Passed whole down the dial ladder so a rung
/// hands the next one everything it needs and nothing it does not.
struct Dial {
    sock_type: u8,
    /// Addresses left to try after the one being dialled now.
    alts: Vec<Resolved>,
    port: u16,
    /// The requester's tag, echoed on the single terminal result.
    tag: crate::abi::contracts::net::net_proto::RequesterTag,
    owner: crate::kernel::workload::owner::OwnerHandle,
    /// The lane that asked, which every result of the dial answers.
    lane: u16,
    /// Attempts already in flight, carried down the ladder so a rung
    /// started on the attempt delay does not abandon the one before it.
    racing: Vec<i32>,
}

/// How long one attempt is given before the next address is tried
/// ALONGSIDE it rather than after it (RFC 8305 §5 calls this the Connection
/// Attempt Delay and recommends 250 ms).
///
/// The sequential ladder alone handles an address that refuses, which is
/// immediate. It does nothing for one that is black-holed — no RST, just
/// silence — where the dial would wait out the whole connect timeout before
/// trying the address that works. That is the case this exists for, and it
/// is the common shape of a broken IPv6 path.
const ATTEMPT_DELAY: std::time::Duration = std::time::Duration::from_millis(250);

/// Open a socket and start a non-blocking connect to `addr`, answering the
/// fd or `None` when even that could not be done.
///
/// No slot is touched: this is the part the dial ladder and the attempt-delay
/// race both need, and the race needs it WITHOUT the slot bookkeeping because
/// it is adding a second attempt to a slot that already has one.
unsafe fn start_connect(addr: Resolved, port: u16) -> Option<i32> {
    let family = match addr {
        Resolved::V4(_) => libc::AF_INET,
        Resolved::V6(_) => libc::AF_INET6,
    };
    let fd = libc::socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
    if fd < 0 {
        return None;
    }
    set_nonblocking(fd);
    tune_stream(fd);
    let mut sa4: libc::sockaddr_in = core::mem::zeroed();
    let mut sa6: libc::sockaddr_in6 = core::mem::zeroed();
    let (sa_ptr, sa_len): (*const libc::sockaddr, u32) = match addr {
        Resolved::V4(a) => {
            sa4.sin_family = libc::AF_INET as u16;
            sa4.sin_port = port.to_be();
            sa4.sin_addr.s_addr = u32::from_ne_bytes(a);
            (
                &sa4 as *const libc::sockaddr_in as *const libc::sockaddr,
                core::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        }
        Resolved::V6(a) => {
            sa6.sin6_family = libc::AF_INET6 as u16;
            sa6.sin6_port = port.to_be();
            sa6.sin6_addr.s6_addr = a;
            (
                &sa6 as *const libc::sockaddr_in6 as *const libc::sockaddr,
                core::mem::size_of::<libc::sockaddr_in6>() as u32,
            )
        }
    };
    let ret = libc::connect(fd, sa_ptr, sa_len);
    if ret < 0 && *libc::__errno_location() != libc::EINPROGRESS {
        libc::close(fd);
        return None;
    }
    Some(fd)
}

/// Open the socket for `addr` and start the non-blocking connect into slot
/// `idx`, which the caller has reserved.
///
/// A failure here is not yet the connect's answer: `linux_net_dial_failed`
/// takes the next candidate and only reports `MSG_ERROR` once none is left,
/// so the requester sees one terminal result however many rungs were tried.
unsafe fn linux_net_dial(st: &mut LinuxNetState, idx: usize, addr: Resolved, dial: Dial) {
    let family = match addr {
        Resolved::V4(_) => libc::AF_INET,
        Resolved::V6(_) => libc::AF_INET6,
    };
    let fd = libc::socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
    if fd < 0 {
        log::error!("[linux_net] socket() failed for connect");
        let errno = *libc::__errno_location();
        linux_net_dial_failed(st, idx, dial, errno);
        return;
    }

    set_nonblocking(fd);
    tune_stream(fd);

    let mut sa4: libc::sockaddr_in = core::mem::zeroed();
    let mut sa6: libc::sockaddr_in6 = core::mem::zeroed();
    let (sa_ptr, sa_len): (*const libc::sockaddr, u32) = match addr {
        Resolved::V4(a) => {
            sa4.sin_family = libc::AF_INET as u16;
            sa4.sin_port = dial.port.to_be();
            sa4.sin_addr.s_addr = u32::from_ne_bytes(a);
            (
                &sa4 as *const libc::sockaddr_in as *const libc::sockaddr,
                core::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        }
        Resolved::V6(a) => {
            sa6.sin6_family = libc::AF_INET6 as u16;
            sa6.sin6_port = dial.port.to_be();
            sa6.sin6_addr.s6_addr = a;
            (
                &sa6 as *const libc::sockaddr_in6 as *const libc::sockaddr,
                core::mem::size_of::<libc::sockaddr_in6>() as u32,
            )
        }
    };
    let ret = libc::connect(fd, sa_ptr, sa_len);

    if ret < 0 {
        let errno = *libc::__errno_location();
        if errno != libc::EINPROGRESS {
            libc::close(fd);
            linux_net_dial_failed(st, idx, dial, errno);
            return;
        }
        st.conns[idx] = LinuxNetConn {
            fd,
            conn_type: dial.sock_type,
            state: 1,
            port: dial.port,
            connect_tag: dial.tag,
            alts: dial.alts,
            attempt_started: Some(std::time::Instant::now()),
            racing: dial.racing,
            // Stamp the commanding owner so this outbound data conn is torn
            // down with its owner on drain/revoke; otherwise it stays
            // OWNER_SYSTEM and outlives revocation.
            owner: dial.owner,
            lane: dial.lane,
            ..LinuxNetConn::empty()
        };
        st.watch(fd, idx, (libc::EPOLLOUT | libc::EPOLLIN) as u32);
    } else {
        st.conns[idx] = LinuxNetConn {
            fd,
            conn_type: dial.sock_type,
            state: 2,
            port: dial.port,
            connect_tag: dial.tag,
            owner: dial.owner,
            lane: dial.lane,
            ..LinuxNetConn::empty()
        };
        st.watch(fd, idx, libc::EPOLLIN as u32);
        let cb = (idx as u16).to_le_bytes();
        let msg = connected_frame(cb, dial.tag);
        linux_net_send_msg(st, dial.lane as usize, &msg);
        linux_net_send_peer(st, dial.lane as usize, idx, fd);
    }
}

/// One rung of the dial ladder failed. Take the next candidate if there is
/// one; otherwise release the slot and give the requester the single
/// terminal `MSG_ERROR` it is owed, carrying the errno of the last address
/// tried. A ladder is invisible to the consumer: it asked for a name, not
/// for an address, and what it gets back is whether the name was reached.
unsafe fn linux_net_dial_failed(st: &mut LinuxNetState, idx: usize, mut dial: Dial, errno: i32) {
    if !dial.alts.is_empty() {
        let next = dial.alts.remove(0);
        log::debug!(
            "[linux_net] connect failed errno={errno}; {} candidate(s) left",
            dial.alts.len()
        );
        linux_net_dial(st, idx, next, dial);
        return;
    }
    log::error!("[linux_net] connect() failed errno={errno}");
    st.conns[idx] = LinuxNetConn::empty();
    let msg = connect_error_frame(idx as u16, errno as u8, dial.tag);
    linux_net_send_msg(st, dial.lane as usize, &msg);
}

/// Send `data` on `conn_id`. The fd is non-blocking, so libc::send may
/// return short or EAGAIN when the kernel buffer is full — anything that
/// doesn't go out immediately gets stashed in the per-connection
/// `write_buf` and drained by `linux_net_drain_writes` on subsequent
/// steps. Caller (linux_net_step) gates further channel reads while any
/// connection still has pending bytes, propagating back-pressure to the
/// upstream channel buffer instead of dropping data.
unsafe fn linux_net_cmd_send(st: &mut LinuxNetState, conn_id: u16, data: &[u8]) {
    let idx = conn_id as usize;
    if idx >= st.conns.len() || st.conns[idx].state < 2 {
        return;
    }
    let conn = &mut st.conns[idx];
    if conn.fd < 0 {
        return;
    }

    let mut sent_now: usize = 0;
    if conn.write_len == conn.write_offset {
        // No backlog: try a direct send. If it goes out fully, no
        // buffering is needed — common case on fast networks / loopback.
        let n = libc::send(
            conn.fd,
            data.as_ptr() as *const libc::c_void,
            data.len(),
            libc::MSG_NOSIGNAL,
        );
        if n > 0 {
            sent_now = n as usize;
        } else if n < 0 {
            // Hard send error → peer is gone (EPIPE, ECONNRESET, …).
            // Don't buffer bytes for a dead socket; drop the conn so
            // `linux_net_drain_writes` doesn't sit on it forever and
            // gate the channel reader.
            let err = *libc::__errno_location();
            if err != libc::EAGAIN && err != libc::EWOULDBLOCK && err != libc::EINTR {
                // Said out loud: a connection dropped on a send error is
                // indistinguishable, from the peer, from a crash or a
                // firewall.
                log::warn!("[linux_net] dropping conn {conn_id} on send error (errno {err})");
                let fd = conn.fd;
                let lane = conn.lane as usize;
                st.conns[idx] = LinuxNetConn::empty();
                libc::close(fd);
                let cb = conn_id.to_le_bytes();
                let msg = [MSG_CLOSED, cb[0], cb[1]];
                linux_net_send_msg(st, lane, &msg);
                return;
            }
        }
    }

    let remaining = data.len().saturating_sub(sent_now);
    if remaining == 0 {
        return;
    }

    // Compact any drained prefix so the new tail starts at offset 0.
    let already = (conn.write_len - conn.write_offset) as usize;
    if conn.write_offset > 0 && already > 0 {
        conn.write_buf
            .copy_within(conn.write_offset as usize..conn.write_len as usize, 0);
    }
    conn.write_len = already as u32;
    conn.write_offset = 0;

    let write_buf_max = st.write_buf_max;
    let conn = &mut st.conns[idx];
    if already + remaining > write_buf_max {
        // Backlog overflow: upstream produced data faster than our
        // sized backlog can absorb. Drop the connection cleanly so
        // the peer fails fast rather than waiting on a stalled stream.
        log::warn!(
            "[linux_net] write backlog overflow on conn {conn_id} ({already} pending + {remaining} new > {write_buf_max})"
        );
        let fd = conn.fd;
        let lane = conn.lane as usize;
        st.conns[idx] = LinuxNetConn::empty();
        libc::close(fd);
        let cb = conn_id.to_le_bytes();
        let msg = [MSG_CLOSED, cb[0], cb[1]];
        linux_net_send_msg(st, lane, &msg);
        return;
    }

    // Grown as needed (doubling, to `write_buf_max`) rather than sized to the
    // maximum on the first short send: a large maximum is for the peer that
    // falls far behind, not a cost every briefly-backlogged connection pays.
    let need = already + remaining;
    if conn.write_buf.len() < need {
        let mut cap = conn.write_buf.len().max(64 * 1024);
        while cap < need {
            cap = cap.saturating_mul(2);
        }
        conn.write_buf.resize(cap.min(write_buf_max), 0);
    }
    let dst = &mut conn.write_buf[already..already + remaining];
    dst.copy_from_slice(&data[sent_now..]);
    conn.write_len = (already + remaining) as u32;
}

/// Try to drain any per-connection write backlog. Returns true if any
/// connection's backlog is FULL after the pass — it could not take one more
/// command frame (`backlog_full`) — and the caller defers further command
/// reads so the upstream channel applies back-pressure. Only then: the
/// channel is shared by every connection, so gating on a backlog that is
/// merely large holds up every other connection's commands behind one peer
/// that is slow to read (a watch client busy elsewhere stalled the whole API
/// server's answers that way). A large backlog is buffered instead, up to
/// `write_buf_max`.
///
/// Connections whose `libc::send` returns a hard error (EPIPE,
/// ECONNRESET, EBADF, …) — i.e. the peer is gone — are torn down here
/// rather than left pending forever. Without this the gating signal
/// would stay true, blocking every subsequent channel read and making
/// the server unable to handle a second connection.
/// A backlog of `pending` bytes that could not take one more command frame
/// (`LINUX_NET_CMD_MAX`) without passing `write_buf_max`. While one exists no
/// command is read, so a frame that is read always fits and the overflow
/// close in `linux_net_cmd_send` is reached only when `write_buf_max` itself
/// is smaller than a frame.
fn backlog_full(write_buf_max: usize, pending: usize) -> bool {
    pending > 0 && pending + LINUX_NET_CMD_MAX > write_buf_max
}

unsafe fn linux_net_drain_writes(st: &mut LinuxNetState) -> bool {
    let mut heavy_pending = false;
    for i in 0..st.conns.len() {
        let c = &mut st.conns[i];
        if c.fd < 0 || c.write_len == c.write_offset {
            continue;
        }
        let to_send = (c.write_len - c.write_offset) as usize;
        let p = c.write_buf.as_ptr().add(c.write_offset as usize);
        let n = libc::send(c.fd, p as *const libc::c_void, to_send, libc::MSG_NOSIGNAL);
        if n > 0 {
            c.write_offset = c.write_offset.saturating_add(n as u32);
        } else if n < 0 {
            // EAGAIN / EWOULDBLOCK = "kernel buffer full, retry". Any
            // other errno is a dead socket — drop it now so the slot
            // can be reused and `heavy_pending` clears.
            let err = *libc::__errno_location();
            if err != libc::EAGAIN && err != libc::EWOULDBLOCK && err != libc::EINTR {
                log::warn!("[linux_net] dropping conn {i} on drain-write error (errno {err})");
                let fd = c.fd;
                let lane = c.lane as usize;
                let cb = (i as u16).to_le_bytes();
                st.conns[i] = LinuxNetConn::empty();
                libc::close(fd);
                let msg = [MSG_CLOSED, cb[0], cb[1]];
                linux_net_send_msg(st, lane, &msg);
                continue;
            }
        }
        let still_pending = (c.write_len - c.write_offset) as usize;
        if backlog_full(st.write_buf_max, still_pending) {
            heavy_pending = true;
        }
        if c.close_when_drained
            && c.close_deadline
                .is_some_and(|t| std::time::Instant::now() >= t)
        {
            log::warn!(
                "[linux_net] conn {i}: closing with {still_pending} bytes undelivered \u{2014} the \
                 peer stopped reading for {CLOSE_DRAIN_MAX_MS}ms"
            );
            let fd = c.fd;
            let lane = c.lane as usize;
            let cb = (i as u16).to_le_bytes();
            st.conns[i] = LinuxNetConn::empty();
            if fd >= 0 {
                libc::close(fd);
            }
            let msg = [MSG_CLOSED, cb[0], cb[1]];
            linux_net_send_msg(st, lane, &msg);
            continue;
        }
        if c.write_offset >= c.write_len {
            c.write_offset = 0;
            c.write_len = 0;
            if c.close_when_drained {
                // Everything queued is on the wire: the deferred close runs
                // now, and reports as any other close does.
                let fd = c.fd;
                let lane = c.lane as usize;
                let cb = (i as u16).to_le_bytes();
                st.conns[i] = LinuxNetConn::empty();
                if fd >= 0 {
                    libc::close(fd);
                }
                let msg = [MSG_CLOSED, cb[0], cb[1]];
                linux_net_send_msg(st, lane, &msg);
                continue;
            }
        }
    }
    heavy_pending
}

/// The socket is gone (peer FIN or a dead socket). Close the fd, report
/// MSG_CLOSED, and HOLD the slot (`state = 4`) rather than freeing it, so the
/// id is not handed to the next accept until the consumer has answered with
/// CMD_CLOSE or the contract's grace interval has passed. Freeing on the
/// spot would let a consumer's CMD_CLOSE close a newcomer that had already
/// taken the index.
unsafe fn hold_closed_slot(st: &mut LinuxNetState, i: usize) {
    if st.conns[i].fd >= 0 {
        libc::close(st.conns[i].fd);
    }
    let owner = st.conns[i].owner;
    let lane = st.conns[i].lane;
    st.conns[i] = LinuxNetConn::empty();
    st.conns[i].owner = owner;
    st.conns[i].lane = lane;
    st.conns[i].state = 4;
    st.conns[i].release_at = Some(
        std::time::Instant::now() + std::time::Duration::from_millis(u64::from(CLOSED_ID_GRACE_MS)),
    );
    let cb = (i as u16).to_le_bytes();
    let msg = [MSG_CLOSED, cb[0], cb[1]];
    linux_net_send_msg(st, lane as usize, &msg);
}

/// Release held ids whose grace interval has passed.
unsafe fn sweep_held_slots(st: &mut LinuxNetState) {
    let now = std::time::Instant::now();
    for i in 0..st.conns.len() {
        if st.conns[i].state == 4 && st.conns[i].release_at.is_some_and(|t| now >= t) {
            st.conns[i] = LinuxNetConn::empty();
        }
    }
}

unsafe fn linux_net_cmd_close(st: &mut LinuxNetState, conn_id: u16) {
    let idx = conn_id as usize;
    if idx >= st.conns.len() || st.conns[idx].state == 0 {
        return;
    }
    if st.conns[idx].state == 4 {
        // The consumer answered MSG_CLOSED within the grace interval: the id
        // is released now, and MSG_CLOSED is not repeated.
        st.conns[idx] = LinuxNetConn::empty();
        return;
    }
    if st.conns[idx].fd >= 0 && st.conns[idx].write_len > st.conns[idx].write_offset {
        // Queued bytes first. The drain sweep finishes the close once they
        // are on the wire; until then the slot stays live so nothing reuses
        // the id, and the consumer is answered `MSG_CLOSED` only when the
        // close has actually happened.
        st.conns[idx].close_when_drained = true;
        st.conns[idx].close_deadline =
            Some(std::time::Instant::now() + std::time::Duration::from_millis(CLOSE_DRAIN_MAX_MS));
        return;
    }
    if st.conns[idx].fd >= 0 {
        libc::close(st.conns[idx].fd);
    }
    if st.conns[idx].state == 5 {
        st.resolving = st.resolving.saturating_sub(1);
    }
    let lane = st.conns[idx].lane as usize;
    st.conns[idx] = LinuxNetConn::empty();
    let cb = conn_id.to_le_bytes();
    let msg = [MSG_CLOSED, cb[0], cb[1]];
    linux_net_send_msg(st, lane, &msg);
}

unsafe fn linux_net_poll_accept(st: &mut LinuxNetState) -> bool {
    let mut had_work = false;

    // Per-listener accept budget: pending connections drained per
    // listener per tick. The number binds in both directions. Accept one
    // per tick and a 32-client connect burst needs 32 ticks (32 ms at the
    // default 1 ms scheduler tick) before the last client is accepted,
    // which outlasts a client's initial HTTP/2 handshake timeout. Accept
    // without a bound and one burst owns the tick. 32 clears a full burst
    // in a single pass while keeping the worst-case per-tick cost bounded
    // (~32 × per-socket setsockopt overhead ≈ a few hundred µs).
    const PER_TICK_ACCEPT_BUDGET: u32 = 32;

    for k in 0..st.ready_len {
        let Some(li) = st.ready_slot(k) else {
            continue;
        };
        if st.conns[li].state != 3 || st.conns[li].conn_type != 1 || st.conns[li].fd < 0 {
            continue;
        }

        let listener_fd = st.conns[li].fd;
        let listener_port = st.conns[li].port;
        // The accepted client inherits the listener's owner so it is torn down
        // with the owner on drain/revoke.
        let listener_owner = st.conns[li].owner;
        // ... and the listener's lane, so its accepts and their data go to
        // the lane that bound it.
        let listener_lane = st.conns[li].lane;
        let mut accepted_on_this_listener: u32 = 0;
        while accepted_on_this_listener < PER_TICK_ACCEPT_BUDGET {
            // A lane whose control queue is full takes no new connection:
            // it would owe an accept the lane cannot yet be told about. The
            // kernel's accept queue holds it until the consumer reads.
            if st.lane_paused(listener_lane as usize) {
                had_work = true;
                break;
            }
            let mut addr: libc::sockaddr_in = core::mem::zeroed();
            let mut addr_len: libc::socklen_t = core::mem::size_of::<libc::sockaddr_in>() as u32;

            let client_fd = libc::accept4(
                listener_fd,
                &mut addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
                &mut addr_len,
                libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            );
            if client_fd < 0 {
                break; // EAGAIN / EWOULDBLOCK — queue drained
            }
            accepted_on_this_listener += 1;
            accept_one_client(st, client_fd, listener_port, listener_owner, listener_lane);
            had_work = true;
        }
    }
    had_work
}

/// The options every TCP stream this provider carries is given, accepted or
/// dialled alike.
unsafe fn tune_stream(fd: i32) {
    // Enable application-friendly TCP keepalive so a silently-dead
    // peer (laptop suspended, NAT timeout without RST) is detected
    // within ~30 s instead of the kernel default ~2 h. Without
    // this, a paused-emulator/idle stream wouldn't trigger the
    // outbound-write cleanup path (no data → no EPIPE) and the
    // slot would stay live until OS keepalive fired.
    let one: i32 = 1;
    libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_KEEPALIVE,
        &one as *const i32 as *const libc::c_void,
        4,
    );

    // TCP_NODELAY disables Nagle's algorithm, which would otherwise
    // hold small sends until either the kernel ACKs the previous
    // outbound packet or a 200 ms timer fires. Fluxor already does
    // its own segmentation/coalescing per `CMD_SEND`, so Nagle only
    // adds latency. With NODELAY the throughput ceiling is set by
    // `SO_SNDBUF` instead.
    libc::setsockopt(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_NODELAY,
        &one as *const i32 as *const libc::c_void,
        4,
    );
    let buf_bytes: i32 = 1 << 20; // 1 MiB
    libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_SNDBUF,
        &buf_bytes as *const i32 as *const libc::c_void,
        4,
    );
    libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_RCVBUF,
        &buf_bytes as *const i32 as *const libc::c_void,
        4,
    );
    let idle_secs: i32 = 15;
    libc::setsockopt(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_KEEPIDLE,
        &idle_secs as *const i32 as *const libc::c_void,
        4,
    );
    let intvl_secs: i32 = 5;
    libc::setsockopt(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_KEEPINTVL,
        &intvl_secs as *const i32 as *const libc::c_void,
        4,
    );
    let probes: i32 = 3;
    libc::setsockopt(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_KEEPCNT,
        &probes as *const i32 as *const libc::c_void,
        4,
    );
}

/// Per-accepted-connection setsockopt + slot allocation + MSG_ACCEPTED
/// delivery. Split out of `linux_net_poll_accept` so the drain loop
/// stays readable.
///
/// `listener_port` is included in the MSG_ACCEPTED payload so
/// consumers that share `net_out` with other anchors (multi-anchor
/// graphs binding distinct ports) can filter on it and only claim
/// their own connections — the broadcast surface would otherwise
/// double-allocate the conn_id across every consumer.
unsafe fn accept_one_client(
    st: &mut LinuxNetState,
    client_fd: i32,
    listener_port: u16,
    owner: crate::kernel::workload::owner::OwnerHandle,
    lane: u16,
) {
    tune_stream(client_fd);

    let slot = linux_net_alloc_conn(st);
    if slot < 0 {
        // A connection dropped without a word.
        //
        // This is what a client sees as "peer closed connection" mid-TLS
        // handshake with no alert and no server-side error — the socket is
        // accepted and immediately closed, so from the outside it is
        // indistinguishable from a crash, a firewall, or a protocol bug.
        // Debugging it from the client end is close to impossible, which is
        // how one instance of this went unexplained across an entire
        // programme of work.
        //
        // At `warn`, because a full connection table is not routine: it
        // means the deployment is at its ceiling and refusing work.
        log::warn!(
            "[linux_net] connection table full ({} slots) — \
             refusing an accepted connection on port {listener_port}; the peer \
             will see a close with no alert",
            st.conns.len()
        );
        libc::close(client_fd);
        return;
    }
    let idx = slot as usize;
    st.conns[idx] = LinuxNetConn {
        fd: client_fd,
        conn_type: 1,
        state: 2,
        owner,
        lane,
        ..LinuxNetConn::empty()
    };
    st.watch(client_fd, idx, libc::EPOLLIN as u32);

    // MSG_ACCEPTED payload: [conn_id:2 LE][listener_port:2 LE]
    let pb = listener_port.to_le_bytes();
    let cb = (idx as u16).to_le_bytes();
    let msg = [MSG_ACCEPTED, cb[0], cb[1], pb[0], pb[1]];
    linux_net_send_msg(st, lane as usize, &msg);
    linux_net_send_peer(st, lane as usize, idx, client_fd);
    log::info!("[linux_net] accepted conn_id={idx}");
}

/// Write `recv_buf[from..total]` to `lane`'s events channel as MSG_DATA
/// frames, returning where it got to.
///
/// A frame write is all-or-nothing, so this stops at the first one that does
/// not fit rather than splitting it. What it returns is the caller's business:
/// the bytes past it have left the kernel's buffer and exist nowhere else.
unsafe fn forward_chunks(
    st: &mut LinuxNetState,
    lane: usize,
    slot: usize,
    from: usize,
    total: usize,
) -> usize {
    const MAX_DATA_FRAGMENT: usize = 1460; // mirrors net_proto::MAX_DATA_FRAGMENT
    let events = lane_events(st, lane);
    // Data never overtakes a queued control frame (an accept and its peer
    // report): it waits, as for a full channel.
    if !st.flush_lane(lane) {
        return from;
    }
    let mut off = from;
    while off < total {
        let chunk = (total - off).min(MAX_DATA_FRAGMENT);
        let payload_len = 2 + chunk;
        let frame_len = 3 + payload_len;
        if frame_len > st.msg_buf.len() {
            break;
        }
        st.msg_buf[0] = MSG_DATA;
        st.msg_buf[1] = payload_len as u8;
        st.msg_buf[2] = (payload_len >> 8) as u8;
        let cb = (slot as u16).to_le_bytes();
        st.msg_buf[3] = cb[0];
        st.msg_buf[4] = cb[1];
        core::ptr::copy_nonoverlapping(
            st.recv_buf.as_ptr().add(off),
            st.msg_buf.as_mut_ptr().add(5),
            chunk,
        );
        let wrote = channel::channel_write(events, st.msg_buf.as_ptr(), frame_len);
        if wrote < frame_len as i32 {
            break;
        }
        off += chunk;
    }
    off
}

unsafe fn linux_net_poll_recv(st: &mut LinuxNetState) -> bool {
    let mut had_work = false;

    // A tail held from a previous step goes first, and nothing is read until
    // it has gone: `recv_buf` is the only place a read lands, so reading over
    // a tail is how those bytes would be lost. This is the case the whole
    // hold exists for -- a consumer that fell behind, which is every consumer
    // eventually.
    if st.hold_slot >= 0 {
        let slot = st.hold_slot as usize;
        let off = forward_chunks(st, st.hold_lane, slot, st.hold_off, st.hold_len);
        if off < st.hold_len {
            st.hold_off = off;
            return true; // still blocked — keep getting scheduled
        }
        st.hold_slot = -1;
        st.hold_off = 0;
        st.hold_len = 0;
        had_work = true;
    }

    for k in 0..st.ready_len {
        let Some(i) = st.ready_slot(k) else {
            continue;
        };
        if st.conns[i].state != 2 && st.conns[i].state != 1 {
            continue;
        }
        if st.conns[i].fd < 0 {
            continue;
        }

        if st.conns[i].state != 2 {
            if st.conns[i].state == 1 {
                // Every attempt in flight for this slot: the current one and
                // any started earlier on the attempt delay. The first to
                // connect wins and the others are closed, so what the
                // consumer sees is one connect that either worked or did not.
                let mut fds: Vec<i32> = Vec::with_capacity(1 + st.conns[i].racing.len());
                fds.push(st.conns[i].fd);
                fds.extend_from_slice(&st.conns[i].racing);
                let mut polls: Vec<libc::pollfd> = fds
                    .iter()
                    .map(|&fd| libc::pollfd {
                        fd,
                        events: libc::POLLOUT,
                        revents: 0,
                    })
                    .collect();
                let ready = libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, 0);
                let mut winner: Option<i32> = None;
                let mut last_err = 0i32;
                let mut dead: Vec<i32> = Vec::new();
                if ready > 0 {
                    for p in &polls {
                        if p.revents & (libc::POLLOUT | libc::POLLERR | libc::POLLHUP) == 0 {
                            continue;
                        }
                        let mut err: i32 = 0;
                        let mut errlen: libc::socklen_t = 4;
                        libc::getsockopt(
                            p.fd,
                            libc::SOL_SOCKET,
                            libc::SO_ERROR,
                            &mut err as *mut i32 as *mut libc::c_void,
                            &mut errlen,
                        );
                        if err == 0 && winner.is_none() {
                            winner = Some(p.fd);
                        } else if err != 0 {
                            last_err = err;
                            dead.push(p.fd);
                        }
                    }
                }
                let tag = st.conns[i].connect_tag;
                if let Some(fd) = winner {
                    // Close every attempt that did not win, the current one
                    // included when an earlier rung answered first.
                    for &other in &fds {
                        if other != fd {
                            libc::close(other);
                        }
                    }
                    let c = &mut st.conns[i];
                    c.fd = fd;
                    c.state = 2;
                    c.alts.clear();
                    c.racing.clear();
                    c.attempt_started = None;
                    st.rewatch(fd, i, libc::EPOLLIN as u32);
                    let cb = (i as u16).to_le_bytes();
                    let msg = connected_frame(cb, tag);
                    let lane = st.conns[i].lane as usize;
                    linux_net_send_msg(st, lane, &msg);
                    linux_net_send_peer(st, lane, i, fd);
                    had_work = true;
                } else if !dead.is_empty() {
                    // Drop the attempts that failed. The slot only falls to
                    // the ladder when nothing is left in flight.
                    for &fd in &dead {
                        libc::close(fd);
                    }
                    let alive: Vec<i32> =
                        fds.iter().copied().filter(|f| !dead.contains(f)).collect();
                    if alive.is_empty() {
                        let dial = {
                            let c = &mut st.conns[i];
                            Dial {
                                sock_type: c.conn_type,
                                alts: core::mem::take(&mut c.alts),
                                port: c.port,
                                tag,
                                owner: c.owner,
                                lane: c.lane,
                                racing: Vec::new(),
                            }
                        };
                        st.conns[i] = LinuxNetConn::empty();
                        linux_net_dial_failed(st, i, dial, last_err);
                    } else {
                        let c = &mut st.conns[i];
                        c.fd = alive[0];
                        c.racing = alive[1..].to_vec();
                    }
                    had_work = true;
                } else if st.conns[i]
                    .attempt_started
                    .is_some_and(|t| t.elapsed() >= ATTEMPT_DELAY)
                    && !st.conns[i].alts.is_empty()
                {
                    // Nothing has answered and the delay has passed: try the
                    // next address ALONGSIDE, rather than waiting out a path
                    // that may never answer at all.
                    let next = st.conns[i].alts.remove(0);
                    match start_connect(next, st.conns[i].port) {
                        Some(fd) => {
                            let c = &mut st.conns[i];
                            c.racing.push(c.fd);
                            c.fd = fd;
                            c.attempt_started = Some(std::time::Instant::now());
                            st.watch(fd, i, (libc::EPOLLOUT | libc::EPOLLIN) as u32);
                            had_work = true;
                        }
                        None => {
                            // Could not even open the socket; the attempt
                            // already running is still the live one.
                            st.conns[i].attempt_started = Some(std::time::Instant::now());
                        }
                    }
                }
            }
            continue;
        }

        // BACKPRESSURE: kernel channel writes are all-or-nothing, so read from
        // the socket only as many bytes as the consumer channel can accept right
        // now — leaving the rest in the socket so TCP windows the peer down.
        // Reading more and dropping the overflow would silently corrupt the
        // stream. Bound the recv to the writable space minus chunk-framing
        // overhead (≤5 B per ≤MSS fragment). The space is the connection's own
        // lane's, so a full attached lane windows down only its own sockets.
        let lane = st.conns[i].lane as usize;
        let events = lane_events(st, lane);
        let room = if events >= 0 {
            channel::channel_writable_bytes(events)
        } else {
            0
        };
        // Each fragment adds 5 B (hdr + u16 conn_id); 64 B covers the worst
        // case for a full recv_buf (≤12 fragments → ≤60 B).
        let cap = st.recv_buf.len().min(room.saturating_sub(64));
        if cap == 0 {
            // Channel full — don't read; let TCP backpressure the peer. But
            // this is work pending, not work finished: the socket is readable
            // and stays readable, and nothing wakes this module when the
            // consumer drains the channel, because a module is scheduled by
            // its inputs and the room here appears on an output. Reporting
            // idle would end the transfer wherever the consumer first fell
            // behind — the bytes already sent arrive, and the rest never do.
            had_work = true; // still blocked — keep getting scheduled
            continue;
        }
        let n = libc::recv(
            st.conns[i].fd,
            st.recv_buf.as_mut_ptr() as *mut libc::c_void,
            cap,
            0,
        );
        if n > 0 {
            // CHUNK the read into ≤MAX_DATA_FRAGMENT frames. The recv was
            // bounded by the room, so every chunk should fit; a short write
            // anyway leaves a tail to re-offer rather than bytes to drop.
            let total = n as usize;
            let off = forward_chunks(st, lane, i, 0, total);
            if off < total {
                st.hold_slot = i as i32;
                st.hold_lane = lane;
                st.hold_off = off;
                st.hold_len = total;
                // Every connection shares `recv_buf`, so no other one may be
                // read while a tail is held in it.
                return true;
            }
            had_work = true;
        } else if n == 0 {
            hold_closed_slot(st, i);
            had_work = true;
        } else {
            // n < 0. EAGAIN / EWOULDBLOCK / EINTR is "no data right
            // now"; everything else (ECONNRESET, EPIPE, EBADF, …) is a
            // dead socket. Treat it like a peer-FIN: free the slot and
            // emit MSG_CLOSED. Without this, an RST'd connection
            // (browser tab closed, force-close, route flap) leaks its
            // slot forever and the 24-slot table eventually fills up,
            // after which all new accepts queue and the server appears
            // to "fall over after one connection".
            let err = *libc::__errno_location();
            if err != libc::EAGAIN && err != libc::EWOULDBLOCK && err != libc::EINTR {
                hold_closed_slot(st, i);
                had_work = true;
            }
        }
    }
    had_work
}

/// Leading payload bytes kept from an oversized command: enough for the
/// retired `CMD_CONNECT`'s tag at bytes 7..9.
const OVERSIZED_HEAD: usize = 9;

/// Answer a command frame larger than `LINUX_NET_CMD_MAX` with `EMSGSIZE`,
/// in the shape its requester waits on: a dial's `MSG_ERROR` on its tag
/// (`CMD_CONNECT_TO`'s last two bytes, the retired `CMD_CONNECT`'s 7..9), a
/// bind's `MSG_BIND_REFUSED` (with `DG_MSG_ERROR` for a datagram bind), a
/// datagram send's or close's `DG_MSG_ERROR` on its endpoint, and a stream
/// command's `MSG_ERROR` on its connection. An oversized `CMD_SEND` has lost
/// bytes from the middle of the stream, so the connection is closed after
/// the error (`MSG_CLOSED`): the peer must not read a stream with a hole in
/// it as whole. A connection or endpoint the lane may not act on is not
/// touched and its id is not echoed. An opcode with no requester shape is
/// logged.
unsafe fn linux_net_refuse_oversized(
    st: &mut LinuxNetState,
    lane: usize,
    msg_type: u8,
    payload_len: usize,
    head: &[u8; OVERSIZED_HEAD],
    tail: [u8; 2],
) {
    use crate::abi::contracts::net::net_proto as np;
    const EMSGSIZE: u8 = libc::EMSGSIZE as u8;
    log::warn!(
        "[linux_net] lane {lane}: command 0x{msg_type:02x} of {payload_len} B is larger than \
         {LINUX_NET_CMD_MAX} B; refused EMSGSIZE"
    );
    match msg_type {
        CMD_CONNECT_TO => {
            let msg = connect_error_frame(0, EMSGSIZE, u16::from_le_bytes(tail));
            linux_net_send_msg(st, lane, &msg);
        }
        CMD_CONNECT => {
            let msg = connect_error_frame(0, EMSGSIZE, np::retired_connect_tag(head));
            linux_net_send_msg(st, lane, &msg);
        }
        CMD_SEND | CMD_CLOSE => {
            let conn_id = u16::from_le_bytes([head[0], head[1]]);
            let idx = conn_id as usize;
            let live = st.conns.get(idx).is_some_and(|c| c.state != 0);
            if !live || !lane_may_touch(st, lane, idx) {
                return;
            }
            let cb = conn_id.to_le_bytes();
            let msg = [MSG_ERROR, cb[0], cb[1], EMSGSIZE];
            linux_net_send_msg(st, lane, &msg);
            if msg_type == CMD_SEND && st.conns[idx].state == 2 {
                hold_closed_slot(st, idx);
            }
        }
        CMD_BIND => {
            linux_net_send_bind_refused(st, lane, u16::from_le_bytes([head[0], head[1]]), EMSGSIZE);
        }
        DG_CMD_BIND => {
            linux_net_send_bind_refused(st, lane, u16::from_le_bytes([head[0], head[1]]), EMSGSIZE);
            linux_net_send_dg_error(st, lane, EMSGSIZE);
        }
        DG_CMD_SEND_TO | DG_CMD_CLOSE => {
            let ep = head[0];
            let named = st
                .conns
                .get(ep as usize)
                .is_some_and(|c| c.state != 0 && c.conn_type == CONN_TYPE_UDP_BOUND)
                && lane_may_touch(st, lane, ep as usize);
            linux_net_send_dg_ep_error(st, lane, if named { ep } else { 0xFF }, EMSGSIZE);
        }
        _ => {}
    }
}

pub fn linux_net_step(state: *mut u8) -> i32 {
    // SAFETY: `state` is the kernel-owned per-instance arena sized
    // for `LinuxNetState` by the loader.
    unsafe {
        let st = instance_state::<LinuxNetState>(state);

        let mut had_work = false;

        // Retry any control frames a back-pressured consumer dropped earlier, so
        // terminal results (MSG_CONNECTED / CLOSED / ERROR) are never lost.
        if !st.flush_pending_ctrl() {
            had_work = true; // still draining — keep getting scheduled
        }

        // Drain per-connection write backlogs first. If any connection
        // is sitting on more than half a buffer of unsent bytes, defer
        // pulling new commands off the channel — the upstream channel
        // buffer is the back-pressure point for `CMD_SEND`. Lighter
        // backlogs don't gate, so parallel `CMD_CLOSE` etc. still flow.
        sweep_held_slots(st);
        if linux_net_drain_resolved(st) {
            had_work = true;
        }
        let heavy_pending = linux_net_drain_writes(st);
        if heavy_pending {
            had_work = true;
        }

        if !heavy_pending {
            let mut gated = false;
            // Boot lanes in wiring order, then every attached lane: a lane a
            // workload attached at runtime ranks below the node's own.
            for lane in 0..LINUX_NET_MAX_INBOUND + LINUX_NET_MAX_ATTACHED {
                if gated {
                    break;
                }
                let lane_ch = lane_commands(st, lane);
                if lane_ch < 0 {
                    continue;
                }
                loop {
                    // Every command may owe the lane a control frame; at
                    // the queue's cap the rest wait in the command channel
                    // until the consumer reads its events.
                    if st.lane_paused(lane) {
                        had_work = true;
                        break;
                    }
                    let mut hdr = [0u8; 3];
                    let n = channel::channel_read(lane_ch, hdr.as_mut_ptr(), 3);
                    if n < 3 {
                        break;
                    }
                    let msg_type = hdr[0];
                    let payload_len = (hdr[1] as u16 | ((hdr[2] as u16) << 8)) as usize;
                    if payload_len > st.cmd_buf.len() {
                        // Oversized command (a consumer exceeding MAX_CMD_DATA). The
                        // body would NOT fit our scratch; DRAIN it from the FIFO so
                        // the next read starts on a real header, keeping the bytes
                        // its requester is named by (a conn id or endpoint at the
                        // front, a dial's tag at the end), and answer it.
                        let mut left = payload_len;
                        let mut scratch = [0u8; 1024];
                        let mut head = [0u8; OVERSIZED_HEAD];
                        let mut tail = [0u8; 2];
                        let mut at = 0usize;
                        while left > 0 {
                            let take = left.min(scratch.len());
                            let got = channel::channel_read(lane_ch, scratch.as_mut_ptr(), take);
                            if got <= 0 {
                                break;
                            }
                            let got = got as usize;
                            for &b in &scratch[..got] {
                                if at < OVERSIZED_HEAD {
                                    head[at] = b;
                                }
                                tail = [tail[1], b];
                                at += 1;
                            }
                            left -= got;
                        }
                        linux_net_refuse_oversized(st, lane, msg_type, payload_len, &head, tail);
                        had_work = true;
                        continue;
                    }
                    if payload_len > 0 {
                        let n2 =
                            channel::channel_read(lane_ch, st.cmd_buf.as_mut_ptr(), payload_len);
                        if n2 < payload_len as i32 {
                            break;
                        }
                    }

                    match msg_type {
                        CMD_BIND if payload_len >= 2 => {
                            let port = u16::from_le_bytes([st.cmd_buf[0], st.cmd_buf[1]]);
                            linux_net_cmd_bind(st, port, lane);
                            had_work = true;
                        }
                        CMD_CONNECT => {
                            // Unsupported. Fail the emitter loudly on its tag rather
                            // than dial whatever its address bytes decode to.
                            let tag = crate::abi::contracts::net::net_proto::retired_connect_tag(
                                &st.cmd_buf[..payload_len],
                            );
                            log::warn!(
                                "[linux_net] CMD_CONNECT (0x13) is unsupported; dial with CMD_CONNECT_TO (0x14) [tag {tag}]"
                            );
                            let msg = connect_error_frame(0, 38u8, tag); // ENOSYS
                            linux_net_send_msg(st, lane, &msg);
                            had_work = true;
                        }
                        CMD_CONNECT_TO => {
                            use crate::abi::contracts::net::net_proto::read_connect_to;
                            // Decode against a copy so the record's borrowed name does
                            // not hold `cmd_buf` while the state is mutated.
                            let mut rec =
                                [0u8; crate::abi::contracts::net::net_proto::CONNECT_TO_MAX];
                            let n = payload_len.min(rec.len());
                            rec[..n].copy_from_slice(&st.cmd_buf[..n]);
                            match read_connect_to(&rec[..n]) {
                                Some((sock_type, port, target, tag)) if n == payload_len => {
                                    let tag = tag.unwrap_or(0);
                                    linux_net_cmd_connect_to(
                                        st, sock_type, port, target, tag, lane,
                                    );
                                }
                                _ => {
                                    // Malformed: a name past 253 bytes, an unknown family,
                                    // a truncated address. EINVAL goes to the tag the
                                    // record's last two bytes spell, as `read_connect_to`
                                    // states.
                                    let tag = crate::abi::contracts::net::net_proto::malformed_connect_to_tag(
                                        &st.cmd_buf[..payload_len],
                                    );
                                    log::warn!(
                                        "[linux_net] malformed CMD_CONNECT_TO ({payload_len} B)"
                                    );
                                    let msg = connect_error_frame(0, 22u8, tag);
                                    linux_net_send_msg(st, lane, &msg);
                                }
                            }
                            had_work = true;
                        }
                        CMD_SEND if payload_len >= 3 => {
                            let conn_id = u16::from_le_bytes([st.cmd_buf[0], st.cmd_buf[1]]);
                            if !lane_may_touch(st, lane, conn_id as usize) {
                                log::warn!(
                                    "[linux_net] lane {lane} CMD_SEND on conn {conn_id} refused: \
                                     opened by lane {}",
                                    st.conns[conn_id as usize].lane
                                );
                                had_work = true;
                                continue;
                            }
                            let data_len = payload_len - 2;
                            let data_slice =
                                core::slice::from_raw_parts(st.cmd_buf.as_ptr().add(2), data_len);
                            linux_net_cmd_send(st, conn_id, data_slice);
                            had_work = true;
                            // This connection's backlog can take no further
                            // frame: stop reading until it drains, as the
                            // pass above would have.
                            if let Some(c) = st.conns.get(conn_id as usize) {
                                let pending = (c.write_len - c.write_offset) as usize;
                                if backlog_full(st.write_buf_max, pending) {
                                    gated = true;
                                    break;
                                }
                            }
                        }
                        CMD_CLOSE if payload_len >= 2 => {
                            let conn_id = u16::from_le_bytes([st.cmd_buf[0], st.cmd_buf[1]]);
                            if !lane_may_touch(st, lane, conn_id as usize) {
                                log::warn!(
                                    "[linux_net] lane {lane} CMD_CLOSE on conn {conn_id} refused: \
                                     opened by lane {}",
                                    st.conns[conn_id as usize].lane
                                );
                                had_work = true;
                                continue;
                            }
                            linux_net_cmd_close(st, conn_id);
                            had_work = true;
                        }
                        DG_CMD_BIND | DG_CMD_SEND_TO | DG_CMD_CLOSE
                            if lane >= LINUX_NET_MAX_INBOUND =>
                        {
                            // The datagram surface is served on boot lanes
                            // only. Its endpoint ids are a byte and its
                            // authority is a consumer-stamped tag, not the
                            // lane; routing and isolating it per lane is a
                            // surface of its own. Refused in the surface's
                            // own error shape so the sender faults rather
                            // than waits.
                            log::warn!(
                                "[linux_net] lane {lane}: datagram command 0x{msg_type:02x} refused \
                                 on an attached lane"
                            );
                            if msg_type == DG_CMD_BIND && payload_len >= 2 {
                                let port = u16::from_le_bytes([st.cmd_buf[0], st.cmd_buf[1]]);
                                linux_net_send_bind_refused(st, lane, port, 95);
                                // EOPNOTSUPP
                            }
                            linux_net_send_dg_error(st, lane, 95); // EOPNOTSUPP
                            had_work = true;
                        }
                        DG_CMD_BIND if payload_len >= 3 => {
                            // Payload (modules/sdk/contracts/net/datagram.rs):
                            //   [port: u16 LE] [flags: u8] [owner_tag: u16 LE]?
                            // A bind that omits the tag records tag 0.
                            let port = u16::from_le_bytes([st.cmd_buf[0], st.cmd_buf[1]]);
                            let owner_tag = if payload_len >= 5 {
                                u16::from_le_bytes([st.cmd_buf[3], st.cmd_buf[4]])
                            } else {
                                0
                            };
                            linux_net_dg_cmd_bind(st, port, owner_tag, lane);
                            had_work = true;
                        }
                        DG_CMD_SEND_TO if payload_len >= 4 => {
                            // Datagram contract:
                            //   [ep_id:1][af:1=4][addr:4 BE][port:2 LE][data...]
                            //   [ep_id:1][af:1=1][len:1][name…][port:2 LE][data...]
                            // The owner-tagged form inserts [MARK][owner_tag:2 LE]
                            // between `ep_id` and `af`.
                            let (claimed_tag, dest_off) =
                                dg_claimed_owner_tag(&st.cmd_buf[..payload_len]);
                            let ep = st.cmd_buf[0] as i16;
                            if !dg_endpoint_admits(st, lane, ep, claimed_tag) {
                                had_work = true;
                                continue;
                            }
                            let af = if dest_off < payload_len {
                                st.cmd_buf[dest_off]
                            } else {
                                0
                            };
                            let ap = dest_off + 1;
                            let (ip, port_at) = match af {
                                DG_AF_INET if payload_len >= ap + 6 => (
                                    [
                                        st.cmd_buf[ap],
                                        st.cmd_buf[ap + 1],
                                        st.cmd_buf[ap + 2],
                                        st.cmd_buf[ap + 3],
                                    ],
                                    ap + 4,
                                ),
                                DG_AF_NAME if payload_len > ap => {
                                    let len = st.cmd_buf[ap] as usize;
                                    let name_end = ap + 1 + len;
                                    if len == 0 || payload_len < name_end + 2 {
                                        had_work = true;
                                        continue;
                                    }
                                    let name = &st.cmd_buf[ap + 1..name_end];
                                    match st.dns_cache_get(name).and_then(|addrs| {
                                        addrs.into_iter().find_map(|a| match a {
                                            Resolved::V4(v4) => Some(v4),
                                            Resolved::V6(_) => None,
                                        })
                                    }) {
                                        Some(a) => (a, name_end),
                                        _ => {
                                            // Not in hand: start the lookup and drop this
                                            // datagram; the sender's retransmit finds the
                                            // answer in the cache.
                                            let name = name.to_vec();
                                            let _ = st.resolve_async(&name, None, true);
                                            had_work = true;
                                            continue;
                                        }
                                    }
                                }
                                _ => {
                                    linux_net_send_dg_error(st, lane, 97); // EAFNOSUPPORT
                                    had_work = true;
                                    continue;
                                }
                            };
                            let port =
                                u16::from_le_bytes([st.cmd_buf[port_at], st.cmd_buf[port_at + 1]]);
                            let data_off = port_at + 2;
                            let data_len = payload_len - data_off;
                            let data = core::slice::from_raw_parts(
                                st.cmd_buf.as_ptr().add(data_off),
                                data_len,
                            );
                            linux_net_dg_cmd_send_to(st, lane, ep, claimed_tag, ip, port, data);
                            had_work = true;
                        }
                        DG_CMD_CLOSE if payload_len >= 1 => {
                            // Payload: [ep_id: u8], or the owner-tagged form
                            // [ep_id: u8][MARK][owner_tag: u16 LE].
                            let (claimed_tag, _) = dg_claimed_owner_tag(&st.cmd_buf[..payload_len]);
                            let ep = st.cmd_buf[0] as i16;
                            // A boot lane's datagram close must not free a
                            // slot an attached lane opened.
                            if !lane_may_touch(st, lane, ep as usize) {
                                log::warn!(
                                    "[linux_net] lane {lane} DG_CMD_CLOSE on slot {ep} refused: \
                                     opened by lane {}",
                                    st.conns[ep as usize].lane
                                );
                                had_work = true;
                                continue;
                            }
                            linux_net_dg_cmd_close(st, lane, ep, claimed_tag);
                            had_work = true;
                        }
                        _ => {
                            log::warn!("[linux_net] unknown cmd 0x{msg_type:02x} pl={payload_len}");
                        }
                    }
                }
            }
        }

        st.poll_ready();
        if linux_net_poll_accept(st) {
            had_work = true;
        }
        if linux_net_poll_recv(st) {
            had_work = true;
        }
        if linux_net_dg_poll_recv(st) {
            had_work = true;
        }

        if had_work {
            2
        } else {
            0
        }
    }
}
