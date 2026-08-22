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

/// File handle table mapping Fluxor handles to libc fds (for files) or
/// libc DIR* (for OPENDIR'd directories). Slot index is the Fluxor
/// handle the caller passes back through subsequent FS_READ /
/// FS_READDIR / FS_CLOSE calls.
const MAX_OPEN_FILES: usize = 16;

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
}

static mut LINUX_FILES: [LinuxFileSlot; MAX_OPEN_FILES] = {
    const EMPTY: LinuxFileSlot = LinuxFileSlot {
        fd: -1,
        dir_ptr: 0,
        in_use: false,
        last_fence: Fence::Volatile,
    };
    [EMPTY; MAX_OPEN_FILES]
};

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
pub fn slot_fence(slot: i32) -> Option<Fence> {
    if slot < 0 || (slot as usize) >= MAX_OPEN_FILES {
        return None;
    }
    // SAFETY: `slot` is bounds-checked above; `LINUX_FILES` is a static
    // array of plain-old-data `OpenFile` entries owned by this module.
    unsafe {
        let files = &*core::ptr::addr_of!(LINUX_FILES);
        if !files[slot as usize].in_use {
            return None;
        }
        Some(files[slot as usize].last_fence)
    }
}

/// Maximum FS path length the linux provider accepts. One byte
/// reserved for the trailing NUL so libc's path-arg primitives
/// can be called directly. Callers passing a longer path get
/// `E2BIG` rather than a silently truncated open.
const LINUX_FS_PATH_MAX: usize = 255;

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
/// Centralised so OPEN, OPEN_CREATE, and OPENDIR get identical
/// path validation — previously each arm rolled its own
/// `arg_len.min(255)` and OPENDIR silently truncated where the

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

/// other two now reject overlong paths.
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
        libc::O_RDONLY | libc::O_DIRECTORY,
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
    use crate::kernel::ipc::fd::{tag_fd, FD_TAG_FS};
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

    // FS capability bitmap (modules/sdk/contracts/storage/fs.rs::CAPS).
    // Linux implements the full read-tier, the write-tier, and both
    // name-publication ops (RENAME 0x090D, FSYNC_NAME 0x0912). TRUNCATE
    // stays 0 — that opcode isn't assigned yet. FSYNC_ASYNC stays 0:
    // this provider fences with a blocking `fsync(2)`.
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
            | dev_fs::caps::OWNERSHIP
            | dev_fs::caps::RMDIR
            | dev_fs::caps::LINK
            | dev_fs::caps::SYMLINK;
        let bytes = caps.to_le_bytes();
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), arg, 4);
        return 4;
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
            // create. The kernel's `FS_OPEN` opcode has no flags
            // argument today — there's no way for the caller to
            // signal "I need to write" vs "I'm just reading". A
            // previous rev tried `O_RDWR|O_CREAT` first to support
            // write-side callers, but that silently 200-OK'd missing
            // files (a typo'd `GET /api/list/nope.png` would create
            // an empty file and persist it on disk). Now: if the
            // file doesn't exist, return ENODEV → the http handler
            // emits 404 cleanly. Future write-side callers can use
            // a new `FS_OPEN_CREATE` opcode or pass flags in the
            // path-extension slot once the ABI grows that knob.
            let fd_raw = libc::open(path_buf.as_ptr() as *const libc::c_char, libc::O_RDWR, 0);
            if fd_raw < 0 {
                // Fall back to read-only (covers files we can read
                // but not write, e.g. read-only-mounted assets).
                let fd_raw =
                    libc::open(path_buf.as_ptr() as *const libc::c_char, libc::O_RDONLY, 0);
                if fd_raw < 0 {
                    return errno::ENODEV;
                }
                files[slot_idx].fd = fd_raw;
                files[slot_idx].in_use = true;
                files[slot_idx].last_fence = Fence::Volatile;
                // FS handles carry their contract in the tag; the
                // vtable wrapper strips it on re-entry.
                return tag_fd(FD_TAG_FS, slot_idx as i32);
            }
            files[slot_idx].fd = fd_raw;
            files[slot_idx].in_use = true;
            files[slot_idx].last_fence = Fence::Volatile;
            tag_fd(FD_TAG_FS, slot_idx as i32)
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
                libc::O_RDWR | libc::O_CREAT,
                0o600,
            );
            if fd_raw < 0 {
                return errno::ENODEV;
            }
            files[slot_idx].fd = fd_raw;
            files[slot_idx].in_use = true;
            files[slot_idx].last_fence = Fence::Volatile;
            tag_fd(FD_TAG_FS, slot_idx as i32)
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
            let slot_idx = handle as usize;
            let files = &*core::ptr::addr_of!(LINUX_FILES);
            if slot_idx >= MAX_OPEN_FILES || !files[slot_idx].in_use {
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
            let rc = libc::posix_fallocate(fd, 0, capacity as libc::off_t);
            if rc != 0 {
                return -rc;
            }
            if libc::ftruncate(fd, capacity as libc::off_t) != 0 {
                return -*libc::__errno_location();
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
            let slot_idx = handle as usize;
            let files = &*core::ptr::addr_of!(LINUX_FILES);
            if slot_idx >= MAX_OPEN_FILES || !files[slot_idx].in_use {
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
            let slot_idx = handle as usize;
            let files = &*core::ptr::addr_of!(LINUX_FILES);
            if slot_idx >= MAX_OPEN_FILES || !files[slot_idx].in_use {
                return errno::EINVAL;
            }
            if arg.is_null() || arg_len == 0 {
                return errno::EINVAL;
            }
            let n = libc::write(files[slot_idx].fd, arg as *const libc::c_void, arg_len);
            if n < 0 {
                errno::ERROR
            } else {
                // Page-cache hand-off; not durable until FSYNC.
                record_slot_fence(slot_idx, Fence::Volatile);
                n as i32
            }
        }
        dev_fs::SEEK => {
            let slot_idx = handle as usize;
            let files = &*core::ptr::addr_of!(LINUX_FILES);
            if slot_idx >= MAX_OPEN_FILES || !files[slot_idx].in_use {
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
                pos as i32
            }
        }
        dev_fs::CLOSE => {
            let slot_idx = handle as usize;
            let files = &mut *core::ptr::addr_of_mut!(LINUX_FILES);
            if slot_idx >= MAX_OPEN_FILES || !files[slot_idx].in_use {
                return errno::EINVAL;
            }
            // Dispatch on whether this slot is a file (fd >= 0) or a
            // directory (dir_ptr != 0). They share the slot table so
            // a single CLOSE op works for both.
            if files[slot_idx].dir_ptr != 0 {
                libc::closedir(files[slot_idx].dir_ptr as *mut libc::DIR);
                files[slot_idx].dir_ptr = 0;
            } else if files[slot_idx].fd >= 0 {
                libc::close(files[slot_idx].fd);
                files[slot_idx].fd = -1;
            }
            files[slot_idx].in_use = false;
            files[slot_idx].last_fence = Fence::Volatile;
            errno::OK
        }
        dev_fs::STAT => {
            let slot_idx = handle as usize;
            let files = &*core::ptr::addr_of!(LINUX_FILES);
            if slot_idx >= MAX_OPEN_FILES || !files[slot_idx].in_use {
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
            if arg_len >= 48 {
                // This backend is the one that genuinely has an object model
                // to report: `fstat` already answered every field. A provider
                // that has the answer and returns the short form instead
                // makes the wide form untestable.
                let out = core::slice::from_raw_parts_mut(arg, 48);
                out[..8].copy_from_slice(&size.to_le_bytes());
                out[8..16].copy_from_slice(&mtime.to_le_bytes());
                out[16..24].copy_from_slice(&(stat.st_ino as u64).to_le_bytes());
                out[24..28].copy_from_slice(&(stat.st_nlink as u32).to_le_bytes());
                out[28..32].copy_from_slice(&(stat.st_mode as u32).to_le_bytes());
                out[32..36].copy_from_slice(&(stat.st_uid as u32).to_le_bytes());
                out[36..40].copy_from_slice(&(stat.st_gid as u32).to_le_bytes());
                out[40..48].copy_from_slice(&0u64.to_le_bytes());
                return 48;
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
            let slot_idx = handle as usize;
            let files = &*core::ptr::addr_of!(LINUX_FILES);
            if slot_idx >= MAX_OPEN_FILES || !files[slot_idx].in_use {
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
            files[slot_idx].fd = -1;
            files[slot_idx].dir_ptr = dir as usize;
            files[slot_idx].in_use = true;
            files[slot_idx].last_fence = Fence::Volatile;
            tag_fd(FD_TAG_FS, slot_idx as i32)
        }
        dev_fs::READDIR => {
            let slot_idx = handle as usize;
            let files = &*core::ptr::addr_of!(LINUX_FILES);
            if slot_idx >= MAX_OPEN_FILES || !files[slot_idx].in_use || files[slot_idx].dir_ptr == 0
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
                    // Buffer full. libc::readdir has already advanced
                    // past this entry, so we have to spill it forward —
                    // simplest correct behaviour is to rewind by seeking
                    // back one entry. Portable POSIX doesn't expose a
                    // "putback" so we use telldir/seekdir.
                    // Note: linux harness use case is small directories
                    // (audio/image asset folders) where one READDIR call
                    // drains everything; this branch is the rare edge.
                    if count == 0 {
                        return errno::E2BIG;
                    }
                    // We can't easily un-read the entry — best effort
                    // is to truncate here and let the caller realise
                    // one entry was dropped via a smaller-than-expected
                    // total. For the bank scan use case this is fine
                    // (16 paths max anyway). For pathological inputs
                    // the caller should retry with a larger buffer.
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
// command through the pre-existing `ProcExecutor` (background reader thread →
// non-blocking `poll_stdout`), and returns a `FD_TAG_PROC`-tagged handle.
// READ/STATUS/CLOSE carry that handle back. Completion is the real process exit
// (STATUS=0 once exited AND drained) — never a quiescence guess.
//
// GRANT (MVP): a hardcoded executable allowlist. The allowlist is hygiene +
// accident-prevention, NOT a sandbox (any dev tool is RCE-equivalent — the node
// is the boundary). Config-driven root/env/timeout scoping + OS sandboxing are
// the documented hardening follow-ups (sector architecture §5).

const PROC_SPAWN: u32 = 0x1600;
const PROC_READ: u32 = 0x1601;
const PROC_STATUS: u32 = 0x1602;
const PROC_CLOSE: u32 = 0x1603;

const MAX_PROCS: usize = 8;

struct LinuxProcSlot {
    exec: Option<crate::platform::proc_executor::ProcExecutor>,
    in_use: bool,
    deadline: Option<std::time::Instant>,
}

static mut LINUX_PROCS: [LinuxProcSlot; MAX_PROCS] = [const {
    LinuxProcSlot {
        exec: None,
        in_use: false,
        deadline: None,
    }
}; MAX_PROCS];

/// The node's `proc` grant — WHAT `do` may run and how, sourced from the environment
/// so the operator declares it at launch (`SECTOR_PROC_ALLOW`, `_ROOT`, `_ENV`,
/// `_TIMEOUT_MS`), with safe defaults. The allowlist is accident-prevention + the
/// migration-frontier surface, NOT confinement (any dev tool is RCE-equivalent — the
/// node is the boundary, §5); `root`/`env`/`timeout` are hygiene + blast-radius bounds.
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
    use crate::kernel::workload::owner::OWNER_SYSTEM;
    use crate::platform::proc_executor::{ProcExecutor, SpawnPolicy};

    let procs = &mut *core::ptr::addr_of_mut!(LINUX_PROCS);
    match opcode {
        PROC_SPAWN => {
            if arg.is_null() || arg_len == 0 {
                return errno::EINVAL;
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
            match ProcExecutor::spawn(OWNER_SYSTEM, cmd, &args, OverloadPolicy::Block, &policy) {
                Ok(exec) => {
                    procs[slot].exec = Some(exec);
                    procs[slot].in_use = true;
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
            if slot >= MAX_PROCS || !procs[slot].in_use || arg.is_null() || arg_len == 0 {
                return errno::EINVAL;
            }
            let out = core::slice::from_raw_parts_mut(arg, arg_len);
            match procs[slot].exec.as_ref().and_then(|e| e.poll_stdout(out)) {
                Some(n) => n as i32,
                None => 0, // nothing ready this step
            }
        }
        PROC_STATUS => {
            let slot = slot_of(handle) as usize;
            if slot >= MAX_PROCS || !procs[slot].in_use {
                return errno::EINVAL;
            }
            // Timeout: past the deadline, kill the child and report done — a runaway
            // build can't wedge the pipe (bounds the blast radius, §5).
            let timed_out = procs[slot]
                .deadline
                .is_some_and(|dl| std::time::Instant::now() >= dl);
            if timed_out {
                if let Some(e) = procs[slot].exec.as_mut() {
                    e.shutdown(std::time::Duration::from_millis(50));
                }
                return 0;
            }
            let e = match procs[slot].exec.as_mut() {
                Some(e) => e,
                None => return errno::EINVAL,
            };
            // Done only when the child has exited AND both reader threads finished
            // AND the inbound bridge is drained — otherwise a final in-flight chunk
            // would be lost. 1 = more may come; 0 = truly done.
            let running = e.alive() || !e.reader_finished() || e.stdout_pending() > 0;
            i32::from(running)
        }
        PROC_CLOSE => {
            let slot = slot_of(handle) as usize;
            if slot < MAX_PROCS && procs[slot].in_use {
                if let Some(mut e) = procs[slot].exec.take() {
                    e.shutdown(std::time::Duration::from_millis(100));
                }
                procs[slot].in_use = false;
                procs[slot].deadline = None;
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
const MSG_BOUND: u8 = 0x04;
const MSG_CONNECTED: u8 = 0x05;
const MSG_ERROR: u8 = 0x06;
/// Bind refusal / failure: `[port: u16 LE][errno: u8]`. The port is the routing
/// key (consumers sharing net_out already filter by local_port). Emitted on a
/// bind syscall failure and on an owner-gate refusal (rfc_endpoint_lease.md
/// §5.3), so a requester never hangs waiting for MSG_BOUND on a failed bind.
const MSG_BIND_REFUSED: u8 = 0x07;

// Net protocol command types (upstream: consumer → linux_net)
const CMD_BIND: u8 = 0x10;
const CMD_SEND: u8 = 0x11;
const CMD_CLOSE: u8 = 0x12;
const CMD_CONNECT: u8 = 0x13;

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
/// Marker introducing the owner tag on `DG_CMD_SEND_TO` / `DG_CMD_CLOSE`. It
/// sits at the offset that otherwise carries `af`, and is distinct from every
/// defined address family, so the tagged and untagged shapes separate at a
/// fixed offset rather than by a length rule over variable-length data.
const DG_OWNER_TAG_MARK: u8 = 0xFF;
/// Bytes the owner-tag field occupies: `[MARK][owner_tag: u16 LE]`.
const DG_OWNER_TAG_FIELD: usize = 3;

const CONN_TYPE_UDP_BOUND: u8 = 2;

/// Total connection slots (listeners + clients). Bumped from 24 to
/// 128 so apps that benchmark with high-concurrency connect bursts
/// (Lattice's 32-/64-client etcd + redis loadtests) don't hit the
/// platform's slot cap before the app's own anchor MAX_CONNS.
///
/// `LinuxNetState` is built directly on the heap (`LinuxNetState::new`
/// returns `Box<Self>` via `Box::new_uninit`), so `LINUX_NET_MAX_CONNS *
/// LINUX_NET_WRITE_BUF` (here 128 × 128 KiB = 16 MiB) is NOT bounded by
/// the process stack — there is no stack-resident temporary of the full
/// struct.
const LINUX_NET_MAX_CONNS: usize = 128;
/// Max distinct inbound command channels (priority lanes).
pub const LINUX_NET_MAX_INBOUND: usize = 8;
/// Per-connection write backlog. Sized to hold a full Spectrum video
/// frame's worth of WS fragments (~98 KB) so a slow peer can absorb one
/// frame's transmission pause without the producer overflowing the
/// backlog (which closes the connection). Kept at 128 KiB — the heap
/// construction (see `LINUX_NET_MAX_CONNS`) lifts the prior stack-size
/// constraint that had forced this down to 32 KiB.
const LINUX_NET_WRITE_BUF: usize = 128 * 1024;

// Intentionally NOT Copy: this struct holds a 128 KiB inline buffer.
// Implicit copies (`let conn = st.conns[idx];`) would push that whole
// buffer onto the stack on every read. References / field-access only.
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
    /// Bytes already drained from `write_buf`.
    write_offset: u32,
    /// Total valid bytes in `write_buf` (drained slice is `[offset..len]`).
    write_len: u32,
    /// Requester tag from `CMD_CONNECT`, echoed in `MSG_CONNECTED` /
    /// connect-failure `MSG_ERROR` so a fanned net_out routes the event back.
    connect_tag: u8,
    /// The COMMANDING owner — the owner of the module whose lane issued the
    /// bind/connect that created this slot (rfc_endpoint_lease.md §4.1:
    /// attribution is carried via the lane, never inferred from the executing
    /// module, which may be system-owned). Immutable for the life of the slot.
    owner: crate::kernel::workload::owner::OwnerHandle,
    /// Datagram endpoints only: the `owner_tag` the consumer stamped on
    /// `DG_CMD_BIND`. `DG_CMD_SEND_TO` / `DG_CMD_CLOSE` must present the same
    /// value or the command is refused with `EPERM`. Zero is the host
    /// wildcard, reachable by the untagged shape.
    dg_owner_tag: u16,
    write_buf: [u8; LINUX_NET_WRITE_BUF],
}

impl LinuxNetConn {
    const EMPTY: Self = Self {
        fd: -1,
        conn_type: 0,
        state: 0,
        port: 0,
        write_offset: 0,
        write_len: 0,
        connect_tag: 0,
        owner: crate::kernel::workload::owner::OWNER_SYSTEM,
        dg_owner_tag: 0,
        write_buf: [0u8; LINUX_NET_WRITE_BUF],
    };
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
    /// rebuild — the carried-attribution source for bind stamps
    /// (rfc_endpoint_lease.md §4.1).
    lane_owners: [crate::kernel::workload::owner::OwnerHandle; LINUX_NET_MAX_INBOUND],
    net_out: i32,
    conns: [LinuxNetConn; LINUX_NET_MAX_CONNS],
    /// Sized to absorb a full multi-MSS `CMD_SEND` payload. The
    /// upstream HTTP module stages up to `NET_BUF_SIZE` bytes per
    /// call (8 KiB on aarch64); a smaller cmd_buf would silently
    /// truncate the second `channel_read` and corrupt the next
    /// frame's header parse. Sized at 16 KiB to leave headroom for
    /// any future raise in `NET_BUF_SIZE` without re-sync.
    cmd_buf: [u8; 49152],
    msg_buf: [u8; 16384],
    recv_buf: [u8; 16384],
    /// Next slot to consider when allocating a connection. Used to
    /// allocate round-robin instead of "first free", so a slot freed
    /// in step T isn't immediately reused in step T+1 — that race lets
    /// stale `CMD_SEND` bytes from the previous session land on the
    /// fresh connection's fd, scrambling its response stream.
    next_alloc: u8,
    /// Control-frame (MSG_CONNECTED / CLOSED / ERROR / BOUND) retry queue. The
    /// consumer channel is all-or-nothing; when it's momentarily full a tiny
    /// control frame would otherwise be DROPPED, stranding a waiter. Queue it and
    /// flush before each step. Bounded so a wedged consumer can't grow it without
    /// limit (oldest dropped past the cap).
    pending_ctrl: std::collections::VecDeque<([u8; 8], usize)>,
}

impl LinuxNetState {
    /// Allocate the per-instance state DIRECTLY on the heap. At
    /// `LINUX_NET_MAX_CONNS = 128` × `LINUX_NET_WRITE_BUF = 128 KiB` the
    /// struct is ~16 MiB; building it by value (`Self { … }`) would
    /// materialise that whole array as a stack temporary before the
    /// `Box` move and overflow the 8 MiB default stack. Allocating with
    /// `Box::new_uninit` and initialising fields in place never puts the
    /// full struct on the stack (each `LinuxNetConn::EMPTY` write is one
    /// slot at a time).
    pub fn new(
        net_ins: [i32; LINUX_NET_MAX_INBOUND],
        lane_owners: [crate::kernel::workload::owner::OwnerHandle; LINUX_NET_MAX_INBOUND],
        net_out: i32,
    ) -> Box<Self> {
        let mut b: Box<core::mem::MaybeUninit<Self>> = Box::new_uninit();
        let p = b.as_mut_ptr();
        // SAFETY: `p` points at the freshly-allocated, uninitialised Box
        // contents; every field is written exactly once below before
        // `assume_init`, and the pointer is valid + aligned for `Self`.
        unsafe {
            use core::ptr::addr_of_mut;
            addr_of_mut!((*p).net_ins).write(net_ins);
            addr_of_mut!((*p).lane_owners).write(lane_owners);
            addr_of_mut!((*p).net_out).write(net_out);
            let conns = addr_of_mut!((*p).conns) as *mut LinuxNetConn;
            for i in 0..LINUX_NET_MAX_CONNS {
                conns.add(i).write(LinuxNetConn::EMPTY);
            }
            addr_of_mut!((*p).cmd_buf).write([0u8; 49152]);
            addr_of_mut!((*p).msg_buf).write([0u8; 16384]);
            addr_of_mut!((*p).recv_buf).write([0u8; 16384]);
            // Skip slot 0 in initial rotation — it's almost always the
            // TCP listener bound by the first CMD_BIND.
            addr_of_mut!((*p).next_alloc).write(1);
            addr_of_mut!((*p).pending_ctrl).write(std::collections::VecDeque::new());
            b.assume_init()
        }
    }

    /// Flush queued control frames; stops at the first one the channel can't
    /// take so ordering is preserved. Returns true if the queue is now empty.
    unsafe fn flush_pending_ctrl(&mut self) -> bool {
        while let Some((frame, len)) = self.pending_ctrl.front() {
            if self.net_out < 0 {
                return false;
            }
            if channel::channel_write(self.net_out, frame.as_ptr(), *len) < *len as i32 {
                return false;
            }
            self.pending_ctrl.pop_front();
        }
        true
    }
}

unsafe fn set_nonblocking(fd: i32) {
    let flags = libc::fcntl(fd, libc::F_GETFL);
    if flags >= 0 {
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

// ----------------------------------------------------------------------
// linux_net instance registry (rfc_endpoint_lease.md §4.3–§4.5)
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
/// die on EADDRINUSE (rfc_endpoint_lease.md §4.5).
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
                *conn = LinuxNetConn::EMPTY;
            }
        }
        (*reg).clear();
    }
}

/// Close every connection slot stamped with `owner`, across all instances.
/// The drain driver calls this BEFORE `free_owner`, so an observer never sees
/// the owner's terminal record while its port is still accepting
/// (rfc_endpoint_lease.md §4.4). Platform thread only.
pub fn linux_net_close_owner_conns(owner: crate::kernel::workload::owner::OwnerHandle) {
    // SAFETY: single-threaded platform access to registered live instances,
    // reached through a raw pointer.
    unsafe {
        let reg = &raw const LINUX_NET_REGISTRY;
        for &st_ptr in (*reg).iter() {
            let st = &mut *st_ptr;
            for (i, conn) in st.conns.iter_mut().enumerate() {
                if conn.state != 0 && conn.owner == owner {
                    if conn.fd >= 0 {
                        libc::close(conn.fd);
                        log::info!(
                            "[linux_net] closed slot {i} (owner slot {} revoked)",
                            owner.slot
                        );
                    }
                    *conn = LinuxNetConn::EMPTY;
                }
            }
        }
    }
}

/// Snapshot the bound endpoints per owner: `(owner, protocol, port)` for every
/// live listener / UDP socket. Protocol: 1 = tcp, 2 = udp (matching
/// CONN_TYPE_UDP_BOUND mnemonically). The runtime's raw report — declarations
/// are the agent's business (rfc_endpoint_lease.md §4.3). Platform thread only.
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
    let start = st.next_alloc as usize;
    for off in 0..LINUX_NET_MAX_CONNS {
        let i = (start + off) % LINUX_NET_MAX_CONNS;
        if st.conns[i].state == 0 {
            st.next_alloc = ((i + 1) % LINUX_NET_MAX_CONNS) as u8;
            return i as i32;
        }
    }
    -1
}

unsafe fn linux_net_send_msg(st: &mut LinuxNetState, data: &[u8]) {
    if st.net_out < 0 || data.is_empty() {
        return;
    }
    let msg_type = data[0];
    let payload = &data[1..];
    let payload_len = payload.len() as u16;
    // Sized to fit a max-payload UDP datagram (1500 MTU) + the
    // datagram-surface header overhead (1 op + 2 len + 9 ep/AF/port/ip).
    let mut frame = [0u8; 1600];
    if 3 + payload.len() > frame.len() {
        return;
    }
    frame[0] = msg_type;
    frame[1] = payload_len as u8;
    frame[2] = (payload_len >> 8) as u8;
    if !payload.is_empty() {
        frame[3..3 + payload.len()].copy_from_slice(payload);
    }
    let total = 3 + payload.len();
    // Preserve ordering: if anything is already queued, OR this write doesn't
    // fully land, enqueue for retry rather than dropping the terminal result.
    // Small control frames (≤8 B) fit the queue slot; larger frames (datagram
    // RX) fall back to best-effort (they're not terminal results).
    let queued_empty = st.flush_pending_ctrl();
    if queued_empty && channel::channel_write(st.net_out, frame.as_ptr(), total) == total as i32 {
        return;
    }
    if total <= 8 {
        const PENDING_CTRL_CAP: usize = 256;
        if st.pending_ctrl.len() >= PENDING_CTRL_CAP {
            st.pending_ctrl.pop_front(); // bounded — drop oldest under sustained wedge
        }
        let mut slot = [0u8; 8];
        slot[..total].copy_from_slice(&frame[..total]);
        st.pending_ctrl.push_back((slot, total));
    }
}

/// Emit `MSG_BIND_REFUSED [port:2 LE][errno:1]` so a bind failure/refusal is
/// surfaced to the requester rather than leaving it waiting for MSG_BOUND.
unsafe fn linux_net_send_bind_refused(st: &mut LinuxNetState, port: u16, errno: u8) {
    let pb = port.to_le_bytes();
    let msg = [MSG_BIND_REFUSED, pb[0], pb[1], errno];
    linux_net_send_msg(st, &msg);
}

/// Emit the datagram contract's `DG_MSG_ERROR [ep_id][errno]` for a failed
/// `DG_CMD_BIND`, alongside `MSG_BIND_REFUSED`: datagram-contract modules
/// (dns et al.) parse only `DG_MSG_*` opcodes in their WaitBound states, so
/// without this frame a refused UDP bind parks them forever instead of
/// faulting (rfc_system_services.md §7 Q1). `ep_id` 0xFF = no endpoint was
/// allocated. Emitting both frames is additive-safe: each surface's
/// listeners match only their own opcode.
unsafe fn linux_net_send_dg_error(st: &mut LinuxNetState, errno: u8) {
    let msg = [DG_MSG_ERROR, 0xFF, errno];
    linux_net_send_msg(st, &msg);
}

/// The Part B bind gate (rfc_endpoint_lease.md §5.3) for a NEW bind by
/// `commander`: admission must be open (a Draining owner binds nothing new —
/// same-owner re-binds of held ports never reach this, they take the use-class
/// fast path), and when the committed plan is lease-aware the (protocol, port)
/// must be granted. System-owned commanders are ungated, as everywhere.
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
    let commander = st.lane_owners[lane];
    // Embedded IP modules close their listener after each accepted
    // connection; their TCP/IP servers re-issue CMD_BIND between
    // requests. On Linux the listening fd persists, so a re-bind on
    // the same port would fail with EADDRINUSE. Acknowledge the
    // re-bind with MSG_BOUND immediately when an existing listener
    // is alive *for the same port* — but ONLY for the same commanding
    // owner (rfc_endpoint_lease.md §4.2): the fast path was owner-blind
    // and would silently hand one owner's listener to another. Same-owner
    // re-bind is use-class (allowed even while Draining — the accept-loop
    // case); a cross-owner claim on a live listener is refused.
    for (li, c) in st.conns.iter().enumerate() {
        if c.state == 3 && c.conn_type == 1 && c.fd >= 0 && c.port == port {
            if c.owner == commander {
                // MSG_BOUND payload: [conn_id:2 LE][local_port:2 LE]
                let pb = port.to_le_bytes();
                let cb = (li as u16).to_le_bytes();
                let msg = [MSG_BOUND, cb[0], cb[1], pb[0], pb[1]];
                linux_net_send_msg(st, &msg);
            } else {
                log::warn!(
                    "[linux_net] bind port {port} refused: held by owner slot {} \
                     (requester owner slot {})",
                    c.owner.slot,
                    commander.slot
                );
                linux_net_send_bind_refused(st, port, 98); // EADDRINUSE
            }
            return;
        }
    }

    if let Some(errno) = linux_net_new_bind_refusal(commander, 1, port) {
        linux_net_send_bind_refused(st, port, errno);
        return;
    }

    let slot = linux_net_alloc_conn(st);
    if slot < 0 {
        log::error!("[linux_net] no free slots for listener");
        linux_net_send_bind_refused(st, port, 105); // ENOBUFS
        return;
    }

    let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    if fd < 0 {
        log::error!("[linux_net] socket() failed");
        linux_net_send_bind_refused(st, port, 23); // ENFILE
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
        linux_net_send_bind_refused(st, port, errno.clamp(0, 255) as u8);
        return;
    }

    // Backlog 128: the kernel's SYN queue must absorb the entire
    // burst of a high-concurrency connect (clients ramp up
    // simultaneously in benchmarks). At backlog=8 a 32-client burst
    // dropped SYNs 9..=32 — clients saw ConnectionReset on connect.
    if libc::listen(fd, 128) < 0 {
        log::error!("[linux_net] listen() failed");
        libc::close(fd);
        linux_net_send_bind_refused(st, port, 95); // EOPNOTSUPP
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
        ..LinuxNetConn::EMPTY
    };
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
    linux_net_send_msg(st, &msg);
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
    let commander = st.lane_owners[lane];
    if let Some(errno) = linux_net_new_bind_refusal(commander, 2, port) {
        linux_net_send_bind_refused(st, port, errno);
        linux_net_send_dg_error(st, errno);
        return;
    }
    let slot = linux_net_alloc_conn(st);
    if slot < 0 {
        log::error!("[linux_net] no free slots for UDP bind");
        linux_net_send_bind_refused(st, port, 105); // ENOBUFS
        linux_net_send_dg_error(st, 105);
        return;
    }

    let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
    if fd < 0 {
        log::error!("[linux_net] UDP socket() failed");
        linux_net_send_bind_refused(st, port, 23); // ENFILE
        linux_net_send_dg_error(st, 23);
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
        log::error!("[linux_net] UDP bind() failed on port {port} (errno {errno})");
        libc::close(fd);
        linux_net_send_bind_refused(st, port, errno.clamp(0, 255) as u8);
        linux_net_send_dg_error(st, errno.clamp(0, 255) as u8);
        return;
    }
    set_nonblocking(fd);
    let idx = slot as usize;
    // `port` is recorded: the endpoint report and the bind gate both need it
    // (rfc_endpoint_lease.md §1.1).
    st.conns[idx] = LinuxNetConn {
        fd,
        conn_type: CONN_TYPE_UDP_BOUND,
        state: 3,
        port,
        owner: commander,
        dg_owner_tag: owner_tag,
        ..LinuxNetConn::EMPTY
    };
    log::info!("[linux_net] UDP bound port {port} (slot {idx})");

    // MSG_DG_BOUND payload (datagram contract):
    //   [ep_id: u8] [local_port: u16 LE].
    let mut msg = [0u8; 1 + 3];
    msg[0] = DG_MSG_BOUND;
    msg[1] = idx as u8;
    msg[2] = (port & 0xFF) as u8;
    msg[3] = (port >> 8) as u8;
    linux_net_send_msg(st, &msg);
}

unsafe fn linux_net_dg_cmd_send_to(
    st: &mut LinuxNetState,
    ep: i16,
    claimed_tag: u16,
    ip: [u8; 4],
    port: u16,
    data: &[u8],
) {
    if ep < 0 || (ep as usize) >= LINUX_NET_MAX_CONNS {
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
        linux_net_send_dg_error(st, 1); // EPERM
        return;
    }
    let mut addr: libc::sockaddr_in = core::mem::zeroed();
    addr.sin_family = libc::AF_INET as u16;
    addr.sin_port = port.to_be();
    addr.sin_addr.s_addr = u32::from_le_bytes([ip[0], ip[1], ip[2], ip[3]]);
    libc::sendto(
        fd,
        data.as_ptr() as *const libc::c_void,
        data.len(),
        libc::MSG_NOSIGNAL,
        &addr as *const libc::sockaddr_in as *const libc::sockaddr,
        core::mem::size_of::<libc::sockaddr_in>() as u32,
    );
}

unsafe fn linux_net_dg_cmd_close(st: &mut LinuxNetState, ep: i16, claimed_tag: u16) {
    if ep < 0 || (ep as usize) >= LINUX_NET_MAX_CONNS {
        return;
    }
    let idx = ep as usize;
    // Close is the destructive half of the same authority question as send.
    if st.conns[idx].conn_type == CONN_TYPE_UDP_BOUND && st.conns[idx].dg_owner_tag != claimed_tag {
        linux_net_send_dg_error(st, 1); // EPERM
        return;
    }
    if st.conns[idx].fd >= 0 && st.conns[idx].conn_type == CONN_TYPE_UDP_BOUND {
        libc::close(st.conns[idx].fd);
    }
    st.conns[idx] = LinuxNetConn::EMPTY;

    let mut msg = [0u8; 3];
    msg[0] = DG_MSG_CLOSED;
    let ep_b = ep.to_le_bytes();
    msg[1] = ep_b[0];
    msg[2] = ep_b[1];
    linux_net_send_msg(st, &msg);
}

unsafe fn linux_net_dg_poll_recv(st: &mut LinuxNetState) -> bool {
    let mut had_work = false;
    let mut i = 0;
    while i < LINUX_NET_MAX_CONNS {
        if st.conns[i].conn_type == CONN_TYPE_UDP_BOUND
            && st.conns[i].state == 3
            && st.conns[i].fd >= 0
        {
            let mut from: libc::sockaddr_in = core::mem::zeroed();
            let mut from_len: libc::socklen_t = core::mem::size_of::<libc::sockaddr_in>() as u32;
            let n = libc::recvfrom(
                st.conns[i].fd,
                st.recv_buf.as_mut_ptr() as *mut libc::c_void,
                st.recv_buf.len(),
                0,
                &mut from as *mut libc::sockaddr_in as *mut libc::sockaddr,
                &mut from_len,
            );
            if n > 0 {
                let n = n as usize;
                let port = u16::from_be(from.sin_port);
                let ip_b = from.sin_addr.s_addr.to_le_bytes();
                // MSG_DG_RX_FROM IPv4 payload (datagram contract):
                //   [ep_id:1][af:1=4][src_addr:4 BE][src_port:2 LE][data...].
                let payload_len = 1 + 1 + 4 + 2 + n;
                if 1 + payload_len > st.msg_buf.len() {
                    i += 1;
                    continue;
                }
                st.msg_buf[0] = DG_MSG_RX_FROM;
                st.msg_buf[1] = i as u8;
                st.msg_buf[2] = DG_AF_INET;
                st.msg_buf[3] = ip_b[0];
                st.msg_buf[4] = ip_b[1];
                st.msg_buf[5] = ip_b[2];
                st.msg_buf[6] = ip_b[3];
                st.msg_buf[7] = (port & 0xFF) as u8;
                st.msg_buf[8] = (port >> 8) as u8;
                core::ptr::copy_nonoverlapping(
                    st.recv_buf.as_ptr(),
                    st.msg_buf.as_mut_ptr().add(9),
                    n,
                );
                // Copy out so `st` is free to borrow mutably in the send (the
                // datagram RX frame lives in `st.msg_buf`).
                let msg = st.msg_buf[..1 + payload_len].to_vec();
                linux_net_send_msg(st, &msg);
                had_work = true;
            }
        }
        i += 1;
    }
    had_work
}

unsafe fn linux_net_cmd_connect(
    st: &mut LinuxNetState,
    sock_type: u8,
    ip: u32,
    port: u16,
    tag: u8,
    lane: usize,
) {
    // STREAM-only surface (net_proto Stream Surface v1). Datagram traffic uses
    // the datagram surface (CMD_DG_BIND / CMD_DG_SEND_TO), not CMD_CONNECT, so a
    // non-stream sock_type is rejected with EINVAL — matching the bare-metal IP
    // module and the public contract.
    const SOCK_TYPE_STREAM: u8 = 1;
    if sock_type != SOCK_TYPE_STREAM {
        let msg = [MSG_ERROR, 0u8, 0u8, 22u8, tag]; // EINVAL, no slot allocated (conn 0, u16 LE)
        linux_net_send_msg(st, &msg);
        return;
    }
    let slot = linux_net_alloc_conn(st);
    if slot < 0 {
        log::error!("[linux_net] no free connection slots");
        // Tagged terminal result (ENOMEM) so the requester completes.
        let msg = [MSG_ERROR, 0u8, 0u8, 12u8, tag];
        linux_net_send_msg(st, &msg);
        return;
    }
    let idx = slot as usize;

    let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    if fd < 0 {
        log::error!("[linux_net] socket() failed for connect");
        st.conns[idx] = LinuxNetConn::EMPTY; // release the slot we reserved
        let errno = *libc::__errno_location();
        let cb = (idx as u16).to_le_bytes();
        let msg = [MSG_ERROR, cb[0], cb[1], errno as u8, tag];
        linux_net_send_msg(st, &msg);
        return;
    }

    set_nonblocking(fd);

    let mut addr: libc::sockaddr_in = core::mem::zeroed();
    addr.sin_family = libc::AF_INET as u16;
    addr.sin_port = port.to_be();
    addr.sin_addr.s_addr = ip.to_be();

    let ret = libc::connect(
        fd,
        &addr as *const libc::sockaddr_in as *const libc::sockaddr,
        core::mem::size_of::<libc::sockaddr_in>() as u32,
    );

    if ret < 0 {
        let errno = *libc::__errno_location();
        if errno != libc::EINPROGRESS {
            log::error!("[linux_net] connect() failed errno={errno}");
            libc::close(fd);
            let cb = (idx as u16).to_le_bytes();
            let msg = [MSG_ERROR, cb[0], cb[1], errno as u8, tag];
            linux_net_send_msg(st, &msg);
            return;
        }
        st.conns[idx] = LinuxNetConn {
            fd,
            conn_type: sock_type,
            state: 1,
            connect_tag: tag,
            // Stamp the commanding owner so this outbound data conn is torn
            // down with its owner on drain/revoke (rfc_endpoint_lease.md §4.4);
            // otherwise it stays OWNER_SYSTEM and outlives revocation.
            owner: st.lane_owners[lane],
            ..LinuxNetConn::EMPTY
        };
    } else {
        st.conns[idx] = LinuxNetConn {
            fd,
            conn_type: sock_type,
            state: 2,
            connect_tag: tag,
            owner: st.lane_owners[lane],
            ..LinuxNetConn::EMPTY
        };
        let cb = (idx as u16).to_le_bytes();
        let msg = [MSG_CONNECTED, cb[0], cb[1], tag];
        linux_net_send_msg(st, &msg);
    }
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
    if idx >= LINUX_NET_MAX_CONNS || st.conns[idx].state < 2 {
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
                let fd = conn.fd;
                st.conns[idx] = LinuxNetConn::EMPTY;
                libc::close(fd);
                let cb = conn_id.to_le_bytes();
                let msg = [MSG_CLOSED, cb[0], cb[1]];
                linux_net_send_msg(st, &msg);
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

    if already + remaining > conn.write_buf.len() {
        // Backlog overflow: upstream produced data faster than our
        // sized backlog can absorb. Drop the connection cleanly so
        // the peer fails fast rather than waiting on a stalled stream.
        log::warn!(
            "[linux_net] write backlog overflow on conn {} ({} pending + {} new > {})",
            conn_id,
            already,
            remaining,
            conn.write_buf.len()
        );
        let fd = conn.fd;
        st.conns[idx] = LinuxNetConn::EMPTY;
        libc::close(fd);
        let cb = conn_id.to_le_bytes();
        let msg = [MSG_CLOSED, cb[0], cb[1]];
        linux_net_send_msg(st, &msg);
        return;
    }

    let dst = &mut conn.write_buf[already..already + remaining];
    dst.copy_from_slice(&data[sent_now..]);
    conn.write_len = (already + remaining) as u32;
}

/// Try to drain any per-connection write backlog. Returns true if any
/// connection still has *substantial* pending bytes after the pass
/// (more than half its `write_buf`) — the caller uses this as a soft
/// hint to defer further `CMD_SEND` consumption so the upstream channel
/// applies back-pressure. Lighter backlogs don't gate, so commands like
/// `CMD_CLOSE` for parallel/orphan connections still flow through.
///
/// Connections whose `libc::send` returns a hard error (EPIPE,
/// ECONNRESET, EBADF, …) — i.e. the peer is gone — are torn down here
/// rather than left pending forever. Without this the gating signal
/// would stay true, blocking every subsequent channel read and making
/// the server unable to handle a second connection.
unsafe fn linux_net_drain_writes(st: &mut LinuxNetState) -> bool {
    let mut heavy_pending = false;
    let threshold = LINUX_NET_WRITE_BUF / 2;
    for i in 0..LINUX_NET_MAX_CONNS {
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
                let fd = c.fd;
                let cb = (i as u16).to_le_bytes();
                st.conns[i] = LinuxNetConn::EMPTY;
                libc::close(fd);
                let msg = [MSG_CLOSED, cb[0], cb[1]];
                linux_net_send_msg(st, &msg);
                continue;
            }
        }
        let still_pending = (c.write_len - c.write_offset) as usize;
        if still_pending > threshold {
            heavy_pending = true;
        }
        if c.write_offset >= c.write_len {
            c.write_offset = 0;
            c.write_len = 0;
        }
    }
    heavy_pending
}

unsafe fn linux_net_cmd_close(st: &mut LinuxNetState, conn_id: u16) {
    let idx = conn_id as usize;
    if idx >= LINUX_NET_MAX_CONNS || st.conns[idx].state == 0 {
        return;
    }
    if st.conns[idx].fd >= 0 {
        libc::close(st.conns[idx].fd);
    }
    st.conns[idx] = LinuxNetConn::EMPTY;
    let cb = conn_id.to_le_bytes();
    let msg = [MSG_CLOSED, cb[0], cb[1]];
    linux_net_send_msg(st, &msg);
}

unsafe fn linux_net_poll_accept(st: &mut LinuxNetState) -> bool {
    let mut had_work = false;

    // Per-listener accept budget. Drain up to N pending connections
    // per listener per tick rather than the historical 1/tick — at
    // 1/tick a 32-client connect burst took 32 ticks (32 ms at the
    // default 1 ms scheduler tick) to fully accept, and clients
    // timed out their initial HTTP/2 handshake. 32 keeps the worst-
    // case per-tick cost bounded (~32 × per-socket setsockopt
    // overhead ≈ a few hundred µs).
    const PER_TICK_ACCEPT_BUDGET: u32 = 32;

    for li in 0..LINUX_NET_MAX_CONNS {
        if st.conns[li].state != 3 || st.conns[li].fd < 0 {
            continue;
        }

        let listener_fd = st.conns[li].fd;
        let listener_port = st.conns[li].port;
        // The accepted client inherits the listener's owner so it is torn down
        // with the owner on drain/revoke (rfc_endpoint_lease.md §4.4).
        let listener_owner = st.conns[li].owner;
        let mut accepted_on_this_listener: u32 = 0;
        while accepted_on_this_listener < PER_TICK_ACCEPT_BUDGET {
            let mut addr: libc::sockaddr_in = core::mem::zeroed();
            let mut addr_len: libc::socklen_t = core::mem::size_of::<libc::sockaddr_in>() as u32;

            let client_fd = libc::accept4(
                listener_fd,
                &mut addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
                &mut addr_len,
                libc::SOCK_NONBLOCK,
            );
            if client_fd < 0 {
                break; // EAGAIN / EWOULDBLOCK — queue drained
            }
            accepted_on_this_listener += 1;
            accept_one_client(st, client_fd, listener_port, listener_owner);
            had_work = true;
        }
    }
    had_work
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
) {
    // Enable application-friendly TCP keepalive so a silently-dead
    // peer (laptop suspended, NAT timeout without RST) is detected
    // within ~30 s instead of the kernel default ~2 h. Without
    // this, a paused-emulator/idle stream wouldn't trigger the
    // outbound-write cleanup path (no data → no EPIPE) and the
    // slot would stay live until OS keepalive fired.
    let one: i32 = 1;
    libc::setsockopt(
        client_fd,
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
        client_fd,
        libc::IPPROTO_TCP,
        libc::TCP_NODELAY,
        &one as *const i32 as *const libc::c_void,
        4,
    );
    let buf_bytes: i32 = 1 << 20; // 1 MiB
    libc::setsockopt(
        client_fd,
        libc::SOL_SOCKET,
        libc::SO_SNDBUF,
        &buf_bytes as *const i32 as *const libc::c_void,
        4,
    );
    libc::setsockopt(
        client_fd,
        libc::SOL_SOCKET,
        libc::SO_RCVBUF,
        &buf_bytes as *const i32 as *const libc::c_void,
        4,
    );
    let idle_secs: i32 = 15;
    libc::setsockopt(
        client_fd,
        libc::IPPROTO_TCP,
        libc::TCP_KEEPIDLE,
        &idle_secs as *const i32 as *const libc::c_void,
        4,
    );
    let intvl_secs: i32 = 5;
    libc::setsockopt(
        client_fd,
        libc::IPPROTO_TCP,
        libc::TCP_KEEPINTVL,
        &intvl_secs as *const i32 as *const libc::c_void,
        4,
    );
    let probes: i32 = 3;
    libc::setsockopt(
        client_fd,
        libc::IPPROTO_TCP,
        libc::TCP_KEEPCNT,
        &probes as *const i32 as *const libc::c_void,
        4,
    );

    let slot = linux_net_alloc_conn(st);
    if slot < 0 {
        libc::close(client_fd);
        return;
    }
    let idx = slot as usize;
    st.conns[idx] = LinuxNetConn {
        fd: client_fd,
        conn_type: 1,
        state: 2,
        owner,
        ..LinuxNetConn::EMPTY
    };

    // MSG_ACCEPTED payload: [conn_id:2 LE][listener_port:2 LE]
    let pb = listener_port.to_le_bytes();
    let cb = (idx as u16).to_le_bytes();
    let msg = [MSG_ACCEPTED, cb[0], cb[1], pb[0], pb[1]];
    linux_net_send_msg(st, &msg);
    log::info!("[linux_net] accepted conn_id={idx}");
}

unsafe fn linux_net_poll_recv(st: &mut LinuxNetState) -> bool {
    let mut had_work = false;

    for i in 0..LINUX_NET_MAX_CONNS {
        if st.conns[i].state != 2 && st.conns[i].state != 1 {
            continue;
        }
        if st.conns[i].fd < 0 {
            continue;
        }

        if st.conns[i].state != 2 {
            if st.conns[i].state == 1 {
                let mut pfd = libc::pollfd {
                    fd: st.conns[i].fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                if libc::poll(&mut pfd, 1, 0) > 0 && pfd.revents & libc::POLLOUT != 0 {
                    let mut err: i32 = 0;
                    let mut errlen: libc::socklen_t = 4;
                    libc::getsockopt(
                        st.conns[i].fd,
                        libc::SOL_SOCKET,
                        libc::SO_ERROR,
                        &mut err as *mut i32 as *mut libc::c_void,
                        &mut errlen,
                    );
                    let tag = st.conns[i].connect_tag;
                    if err == 0 {
                        st.conns[i].state = 2;
                        let cb = (i as u16).to_le_bytes();
                        let msg = [MSG_CONNECTED, cb[0], cb[1], tag];
                        linux_net_send_msg(st, &msg);
                        had_work = true;
                    } else {
                        libc::close(st.conns[i].fd);
                        st.conns[i] = LinuxNetConn::EMPTY;
                        let cb = (i as u16).to_le_bytes();
                        let msg = [MSG_ERROR, cb[0], cb[1], err as u8, tag];
                        linux_net_send_msg(st, &msg);
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
        // overhead (≤5 B per ≤MSS fragment).
        const MAX_DATA_FRAGMENT: usize = 1460; // mirrors net_proto::MAX_DATA_FRAGMENT
        let room = if st.net_out >= 0 {
            channel::channel_writable_bytes(st.net_out)
        } else {
            0
        };
        // Each fragment adds 5 B (hdr + u16 conn_id); 64 B covers the worst
        // case for a full recv_buf (≤12 fragments → ≤60 B).
        let cap = st.recv_buf.len().min(room.saturating_sub(64));
        if cap == 0 {
            continue; // channel full — don't read; let TCP backpressure the peer.
        }
        let n = libc::recv(
            st.conns[i].fd,
            st.recv_buf.as_mut_ptr() as *mut libc::c_void,
            cap,
            0,
        );
        if n > 0 {
            // CHUNK the read into ≤MAX_DATA_FRAGMENT frames (the recv was bounded
            // so every chunk is guaranteed to fit the channel — no drops).
            let total = n as usize;
            let mut off = 0usize;
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
                let cb = (i as u16).to_le_bytes();
                st.msg_buf[3] = cb[0];
                st.msg_buf[4] = cb[1];
                core::ptr::copy_nonoverlapping(
                    st.recv_buf.as_ptr().add(off),
                    st.msg_buf.as_mut_ptr().add(5),
                    chunk,
                );
                let wrote = channel::channel_write(st.net_out, st.msg_buf.as_ptr(), frame_len);
                if wrote < frame_len as i32 {
                    // Shouldn't happen (recv was bounded) — but never advance past
                    // an unwritten chunk; stop and retry next step.
                    break;
                }
                off += chunk;
            }
            had_work = true;
        } else if n == 0 {
            libc::close(st.conns[i].fd);
            st.conns[i] = LinuxNetConn::EMPTY;
            let cb = (i as u16).to_le_bytes();
            let msg = [MSG_CLOSED, cb[0], cb[1]];
            linux_net_send_msg(st, &msg);
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
                libc::close(st.conns[i].fd);
                st.conns[i] = LinuxNetConn::EMPTY;
                let cb = (i as u16).to_le_bytes();
                let msg = [MSG_CLOSED, cb[0], cb[1]];
                linux_net_send_msg(st, &msg);
                had_work = true;
            }
        }
    }
    had_work
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
        let heavy_pending = linux_net_drain_writes(st);
        if heavy_pending {
            had_work = true;
        }

        if !heavy_pending {
            for lane in 0..LINUX_NET_MAX_INBOUND {
                let lane_ch = st.net_ins[lane];
                if lane_ch < 0 {
                    continue;
                }
                loop {
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
                        // the next read starts on a real header, then skip the frame
                        // rather than parsing stale cmd_buf bytes mid-stream.
                        let mut left = payload_len;
                        let mut scratch = [0u8; 1024];
                        while left > 0 {
                            let take = left.min(scratch.len());
                            let got = channel::channel_read(lane_ch, scratch.as_mut_ptr(), take);
                            if got <= 0 {
                                break;
                            }
                            left -= got as usize;
                        }
                        log::warn!("[linux_net] oversized command frame ({payload_len} B) dropped");
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
                        CMD_CONNECT if payload_len >= 7 => {
                            let sock_type = st.cmd_buf[0];
                            let ip = u32::from_le_bytes([
                                st.cmd_buf[1],
                                st.cmd_buf[2],
                                st.cmd_buf[3],
                                st.cmd_buf[4],
                            ]);
                            let port = u16::from_le_bytes([st.cmd_buf[5], st.cmd_buf[6]]);
                            // Optional trailing requester tag (8-byte form), echoed in
                            // MSG_CONNECTED / MSG_ERROR for fanned-net_out routing.
                            let tag = if payload_len >= 8 { st.cmd_buf[7] } else { 0 };
                            linux_net_cmd_connect(st, sock_type, ip, port, tag, lane);
                            had_work = true;
                        }
                        CMD_SEND if payload_len >= 3 => {
                            let conn_id = u16::from_le_bytes([st.cmd_buf[0], st.cmd_buf[1]]);
                            let data_len = payload_len - 2;
                            let data_slice =
                                core::slice::from_raw_parts(st.cmd_buf.as_ptr().add(2), data_len);
                            linux_net_cmd_send(st, conn_id, data_slice);
                            had_work = true;
                        }
                        CMD_CLOSE if payload_len >= 2 => {
                            let conn_id = u16::from_le_bytes([st.cmd_buf[0], st.cmd_buf[1]]);
                            linux_net_cmd_close(st, conn_id);
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
                        DG_CMD_SEND_TO if payload_len >= 8 => {
                            // IPv4 payload (datagram contract):
                            //   [ep_id:1][af:1=4][addr:4 BE][port:2 LE][data...]
                            // The owner-tagged form inserts [MARK][owner_tag:2 LE]
                            // between `ep_id` and `af`.
                            let (claimed_tag, dest_off) =
                                dg_claimed_owner_tag(&st.cmd_buf[..payload_len]);
                            if payload_len < dest_off + 7 {
                                had_work = true;
                                continue;
                            }
                            let ep = st.cmd_buf[0] as i16;
                            let ap = dest_off + 1;
                            let ip = [
                                st.cmd_buf[ap],
                                st.cmd_buf[ap + 1],
                                st.cmd_buf[ap + 2],
                                st.cmd_buf[ap + 3],
                            ];
                            let port = u16::from_le_bytes([st.cmd_buf[ap + 4], st.cmd_buf[ap + 5]]);
                            let data_off = dest_off + 7;
                            let data_len = payload_len - data_off;
                            let data = core::slice::from_raw_parts(
                                st.cmd_buf.as_ptr().add(data_off),
                                data_len,
                            );
                            linux_net_dg_cmd_send_to(st, ep, claimed_tag, ip, port, data);
                            had_work = true;
                        }
                        DG_CMD_CLOSE if payload_len >= 1 => {
                            // Payload: [ep_id: u8], or the owner-tagged form
                            // [ep_id: u8][MARK][owner_tag: u16 LE].
                            let (claimed_tag, _) = dg_claimed_owner_tag(&st.cmd_buf[..payload_len]);
                            let ep = st.cmd_buf[0] as i16;
                            linux_net_dg_cmd_close(st, ep, claimed_tag);
                            had_work = true;
                        }
                        _ => {
                            log::warn!("[linux_net] unknown cmd 0x{msg_type:02x} pl={payload_len}");
                        }
                    }
                }
            }
        }

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
