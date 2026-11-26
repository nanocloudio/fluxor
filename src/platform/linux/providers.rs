// ============================================================================
// Linux FS Provider — real file I/O via libc
// ============================================================================

use crate::abi::fence::{DeviceId, Fence};
use crate::kernel::module::user_span::UserSpan;

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

/// How many handles the library's own provider tables can hand modules at
/// once: the part of the `handles` pool the boot plan derives. Files, spawned
/// processes and host workloads.
pub fn handle_slots() -> usize {
    use crate::abi::contracts::resource as res;
    use crate::kernel::sys::resource_ledger::ceiling;
    let pool = |p: u16| ceiling(p) as usize;
    let workloads = pool(res::POOL_OWNERS).saturating_sub(1);
    MAX_OPEN_FILES + MAX_PROCS + pool(res::POOL_SANDBOXES) + workloads
}

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
}

/// The slot an index names; an index past the table otherwise, which every
/// arm refuses. The index is the provider's own: the kernel's handle around
/// it carries the generation that keeps a closed handle from naming the
/// slot's next file.
fn slot_index(handle: i32) -> usize {
    usize::try_from(handle).unwrap_or(usize::MAX)
}

static mut LINUX_FILES: [LinuxFileSlot; MAX_OPEN_FILES] = {
    const EMPTY: LinuxFileSlot = LinuxFileSlot {
        fd: -1,
        dir_ptr: 0,
        in_use: false,
        last_fence: Fence::Volatile,
        owner: crate::kernel::workload::owner::OWNER_NODE,
    };
    [EMPTY; MAX_OPEN_FILES]
};

/// Whether `slot` is open and its caller's: the opener alone reaches a slot.
fn owned(slot: &LinuxFileSlot) -> bool {
    slot.in_use && slot.owner == crate::kernel::exec::scheduler::caller_owner()
}

/// Claim a file slot for `fd` on behalf of `owner`. The slot's index, or
/// `ENOMEM` with `fd` closed when the table is full.
unsafe fn claim_file_slot(fd: i32, owner: crate::kernel::workload::owner::OwnerHandle) -> i32 {
    use crate::kernel::sys::errno;
    let files = &mut *core::ptr::addr_of_mut!(LINUX_FILES);
    let Some(slot_idx) = files.iter().position(|s| !s.in_use) else {
        libc::close(fd);
        return errno::ENOMEM;
    };
    files[slot_idx] = LinuxFileSlot {
        fd,
        dir_ptr: 0,
        in_use: true,
        last_fence: Fence::Volatile,
        owner,
    };
    slot_idx as i32
}

/// Claim a directory slot for `dir` on behalf of `owner`.
unsafe fn claim_dir_slot(
    dir: *mut libc::DIR,
    owner: crate::kernel::workload::owner::OwnerHandle,
) -> i32 {
    use crate::kernel::sys::errno;
    let files = &mut *core::ptr::addr_of_mut!(LINUX_FILES);
    let Some(slot_idx) = files.iter().position(|s| !s.in_use) else {
        libc::closedir(dir);
        return errno::ENOMEM;
    };
    files[slot_idx] = LinuxFileSlot {
        fd: -1,
        dir_ptr: dir as usize,
        in_use: true,
        last_fence: Fence::Volatile,
        owner,
    };
    slot_idx as i32
}

/// Close a file slot's descriptor.
unsafe fn close_file_slot(slot: &mut LinuxFileSlot) {
    libc::close(slot.fd);
    slot.fd = -1;
}

/// Close every slot `owner` holds: what an owner acting with the node's
/// authority opened goes with it (`owner_release`).
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
pub(crate) const LINUX_FS_PATH_MAX: usize = 255;

/// Decode the two-path argument `LINK`, `RENAME` and friends share:
/// `[a_len: u16 LE][a][b_len: u16 LE][b]`, validating both as filesystem
/// paths and returning them NUL-terminated.
///
/// One decoder, because two copies of these offsets is two chances to
/// validate one path and not the other — and the unvalidated one is the
/// interesting half to an attacker.
///
fn two_paths(bytes: &[u8]) -> Option<([u8; 256], usize, [u8; 256], usize)> {
    let arg_len = bytes.len();
    if arg_len < 4 {
        return None;
    }
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
    validate_fs_path(&bytes[2..2 + a_len], &mut a).ok()?;
    validate_fs_path(&bytes[b_off..b_off + b_len], &mut b).ok()?;
    Some((a, a_len, b, b_len))
}

/// Validate + copy a UTF-8 path argument from a contract caller
/// into `out` and NUL-terminate it for libc.
///
/// Returns the path length in bytes (NOT counting the NUL) on
/// success, or a negative errno:
///
///   - `EINVAL` if the path is empty or contains an
///     interior NUL byte (interior NULs let an attacker submit
///     `evil\0../etc/passwd` and have libc see `evil` while a
///     downstream policy check saw the longer string),
///   - `E2BIG` if the path length exceeds `LINUX_FS_PATH_MAX`.
///
/// Centralised so OPEN, OPEN_CREATE, and OPENDIR get identical path
/// validation. Per-arm length handling is how one of them ends up
/// truncating an overlong path where the others reject it, which turns a
/// caller's mistake into a silently different file.
fn validate_fs_path(bytes: &[u8], out: &mut [u8; 256]) -> Result<usize, i32> {
    use crate::kernel::sys::errno;
    let arg_len = bytes.len();
    if arg_len == 0 {
        return Err(errno::EINVAL);
    }
    if arg_len > LINUX_FS_PATH_MAX {
        return Err(errno::E2BIG);
    }
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
/// `OPEN` and `OPENDIR` answer the slot's index, which the kernel wraps in
/// a handle; every op on that handle arrives here with the index.
pub fn linux_fs_dispatch(handle: i32, opcode: u32, arg: &mut [u8], mut data: UserSpan<'_>) -> i32 {
    // SAFETY: provider dispatch runs on the scheduler thread, the only
    // thread touching the file-slot table.
    unsafe { fs_dispatch_on_thread(handle, opcode, arg, data.as_mut()) }
}

/// [`linux_fs_dispatch`]'s body.
///
/// # Safety
/// Scheduler thread only: touches `static mut` provider state without
/// synchronization.
unsafe fn fs_dispatch_on_thread(handle: i32, opcode: u32, arg: &mut [u8], data: &mut [u8]) -> i32 {
    use crate::abi::contracts::storage::fs as dev_fs;
    use crate::abi::fence as dev_fence;
    use crate::kernel::sys::errno;

    let arg_len = arg.len();

    // Cross-cutting fence-introspection opcode. Public surface:
    // `provider_query(handle, query_key::LAST_FENCE, …)`. The
    // kernel forwards it as `provider_call(handle, QUERY_OP, …)`
    // over the handle's route, so this dispatcher sees the slot's index.
    if opcode == dev_fence::QUERY_OP {
        if arg_len < dev_fence::WIRE_MAX_LEN {
            return errno::EINVAL;
        }
        let Some(fence) = slot_fence(handle) else {
            return errno::ENOSYS;
        };
        let buf = &mut arg[..];
        return match fence.encode(buf) {
            Some(n) => n as i32,
            None => errno::EINVAL,
        };
    }

    // The host's paths are the node's (the provider is node-only), served to
    // the node and to owners acting with its authority. Slots are stamped
    // with the caller's own owner: what it opened goes with it.
    let owner = crate::kernel::exec::scheduler::caller_owner();

    // FS capability bitmap (crates/fluxor-abi/src/contracts/storage/fs.rs::CAPS).
    // Linux implements the full read surface, the write surface, both
    // name-publication ops (RENAME, FSYNC_NAME) and TRUNCATE.
    // FSYNC_ASYNC stays clear: this provider fences with a blocking
    // `fsync(2)`.
    if opcode == dev_fs::CAPS {
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
            // The host filesystem has `rmdir(2)`, `link(2)` and
            // `readlink(2)`.
            | dev_fs::caps::RMDIR
            | dev_fs::caps::LINK
            | dev_fs::caps::SYMLINK;
        return crate::abi::kernel_abi::caps_word::answer(arg, caps);
    }

    match opcode {
        dev_fs::OPEN => {
            if arg_len == 0 {
                return errno::EINVAL;
            }
            let files = &mut *core::ptr::addr_of_mut!(LINUX_FILES);
            let slot_idx = files.iter().position(|s| !s.in_use);
            let slot_idx = match slot_idx {
                Some(i) => i,
                None => return errno::ENOMEM,
            };

            let mut path_buf = [0u8; 256];
            if let Err(e) = validate_fs_path(arg, &mut path_buf) {
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
            if let Err(e) = validate_fs_path(arg, &mut path_buf) {
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
            if let Err(e) = validate_fs_path(arg, &mut path_buf) {
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
            if let Err(e) = validate_fs_path(arg, &mut path_buf) {
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
            if let Err(e) = validate_fs_path(arg, &mut path_buf) {
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
            let Some((existing, existing_len, new, new_len)) = two_paths(arg) else {
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
            if arg_len < 2 {
                return errno::EINVAL;
            }
            let path_len = usize::from(u16::from_le_bytes([arg[0], arg[1]]));
            if path_len == 0 || arg_len < 2 + path_len {
                return errno::EINVAL;
            }
            let mut path_buf = [0u8; 256];
            if let Err(e) = validate_fs_path(&arg[2..2 + path_len], &mut path_buf) {
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
            arg[..n].copy_from_slice(&target[..n]);
            n as i32
        }
        dev_fs::TRUNCATE => {
            // `[len: u64 LE][path]`.
            if arg_len < 9 {
                return errno::EINVAL;
            }
            let a = &arg[..];
            let len = u64::from_le_bytes([a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]]);
            if len > i64::MAX as u64 {
                return errno::EINVAL;
            }
            let mut path_buf = [0u8; 256];
            if let Err(e) = validate_fs_path(&arg[8..], &mut path_buf) {
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
            let len = match validate_fs_path(arg, &mut path_buf) {
                Ok(n) => n,
                Err(e) => return e,
            };
            fsync_parent_dir(&path_buf[..len])
        }
        dev_fs::RENAME => {
            let Some((src_buf, src_len, dst_buf, dst_len)) = two_paths(arg) else {
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
            if arg_len < 4 {
                return errno::EINVAL;
            }
            let capacity = u32::from_le_bytes([arg[0], arg[1], arg[2], arg[3]]);
            if capacity == 0 {
                return errno::EINVAL;
            }
            let fd = files[slot_idx].fd;
            let mut st = core::mem::zeroed::<libc::stat>();
            if libc::fstat(fd, &mut st) != 0 {
                return -*libc::__errno_location();
            }
            // Reserving never shrinks: a file already past the capacity keeps
            // its bytes.
            let size = (st.st_size as u64).max(u64::from(capacity));
            let rc = libc::posix_fallocate(fd, 0, capacity as libc::off_t);
            let grew = rc == 0 && libc::ftruncate(fd, size as libc::off_t) == 0;
            let err = if rc != 0 {
                -rc
            } else {
                -*libc::__errno_location()
            };
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
            if data.is_empty() {
                return errno::EINVAL;
            }
            let n = libc::read(
                files[slot_idx].fd,
                data.as_mut_ptr() as *mut libc::c_void,
                data.len(),
            );
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
            if data.is_empty() {
                return errno::EINVAL;
            }
            let fd = files[slot_idx].fd;
            let n = libc::write(fd, data.as_ptr() as *const libc::c_void, data.len());
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
            let Some(offset) = dev_fs::seek::parse(arg).and_then(|v| i64::try_from(v).ok()) else {
                return errno::EINVAL;
            };
            let pos = libc::lseek(files[slot_idx].fd, offset, libc::SEEK_SET);
            if pos < 0 {
                errno::ERROR
            } else {
                // Seek doesn't change durability, but it's a
                // successful op on this handle — record Volatile so
                // the slot fence describes the latest op.
                record_slot_fence(slot_idx, Fence::Volatile);
                errno::OK
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
            if arg_len != dev_fs::stat::LEN {
                return errno::EINVAL;
            }
            let mut stat: libc::stat = core::mem::zeroed();
            let ret = libc::fstat(files[slot_idx].fd, &mut stat);
            if ret < 0 {
                return errno::ERROR;
            }
            // Metadata read; no durability claim.
            record_slot_fence(slot_idx, Fence::Volatile);
            dev_fs::Stat {
                size: stat.st_size as u64,
                mtime: stat.st_mtime as u64,
                ino: stat.st_ino as u64,
                nlink: stat.st_nlink as u32,
            }
            .answer(arg)
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
            if let Err(e) = validate_fs_path(arg, &mut path_buf) {
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
            if data.len() < 2 {
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
                let name: &[u8] =
                    core::slice::from_raw_parts(ent.d_name.as_ptr().cast(), ent.d_name.len());
                let nlen = name.iter().take(255).position(|&b| b == 0).unwrap_or(255);
                if nlen == 0 {
                    continue;
                }
                // Skip "." and ".." pseudo-entries.
                if &name[..nlen] == b"." || &name[..nlen] == b".." {
                    continue;
                }
                let is_dir = ent.d_type == libc::DT_DIR;
                let need = 2 + nlen;
                if out_pos + need > data.len() {
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
                data[out_pos] = nlen as u8;
                data[out_pos + 1] = if is_dir { 1 } else { 0 };
                data[out_pos + 2..out_pos + 2 + nlen].copy_from_slice(&name[..nlen]);
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
                data[..2].copy_from_slice(&count.to_le_bytes());
                record_slot_fence(slot_idx, Fence::Volatile);
                out_pos as i32
            }
        }
        _ => errno::ENOSYS,
    }
}

// ============================================================================
// Commands the node runs itself (`host_process::PROC_*`)
// ============================================================================
//
// The `host_process` provider (`workload::host_process_dispatch`) hands these
// ops here. PROC_SPAWN (handle = -1) allocates a slot, spawns the command
// through `ProcExecutor` (background reader thread → non-blocking
// `poll_stdout`), and answers the slot's index, which the kernel mints a
// `host_process` handle around. READ/STATUS/CLOSE arrive with that index.
// Completion is the real process exit (STATUS=0 once exited AND drained) —
// never a quiescence guess.
//
// GRANT: an executable allowlist, working directory, environment allowlist
// and timeout the operator configures for the runtime (`proc_grant`). The
// allowlist is hygiene + accident-prevention, NOT a sandbox (any tool is
// RCE-equivalent — the node is the boundary); no OS sandbox is applied.
//
// OWNERS: a spawn acts with the node's authority, so only the node and an
// owner acting with it spawn (a workload is refused EACCES). A child is its
// spawner's: only that owner reads, polls or closes it, and the owner-release
// hook shuts it down with the owner.

use crate::abi::platform::linux::host_process::{PROC_CLOSE, PROC_READ, PROC_SPAWN, PROC_STATUS};

/// Commands the node runs at once: their `host_process` indexes are
/// `0..MAX_PROCS`, below the terminal sessions'.
pub const MAX_PROCS: usize = 8;
const _: () = assert!(
    (MAX_PROCS as i32) <= super::host_backend::TTY_HANDLE_BASE,
    "a command's index stays below the terminal sessions'"
);

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
        owner: crate::kernel::workload::owner::OWNER_NODE,
    }
}; MAX_PROCS];

/// Whether `slot` is a live child of the calling owner's: the spawner alone
/// reaches it.
fn proc_owned(slot: &LinuxProcSlot) -> bool {
    slot.in_use && slot.owner == crate::kernel::exec::scheduler::caller_owner()
}

/// Close child slot `idx`: the child is shut down, the slot's per-run state
/// cleared rather than left for whoever spawns into it next, and every
/// handle naming it retired.
fn close_proc_slot(procs: &mut [LinuxProcSlot; MAX_PROCS], idx: usize, grace: std::time::Duration) {
    let slot = &mut procs[idx];
    if let Some(mut e) = slot.exec.take() {
        e.shutdown(grace);
    }
    slot.in_use = false;
    slot.deadline = None;
    slot.staged_len = 0;
    slot.staged_off = 0;
    slot.owner = crate::kernel::workload::owner::OWNER_NODE;
    crate::kernel::module::provider::retire_routes_naming(
        crate::abi::registry::host_process::ID,
        idx as i32,
    );
}

/// Shut down every child `owner` spawned. Part of the platform's
/// owner-release hook: a host process never outlives the owner that
/// spawned it.
///
/// # Safety
/// Single-threaded platform dispatch only.
pub unsafe fn release_owner_procs(owner: crate::kernel::workload::owner::OwnerHandle) {
    let procs = &mut *core::ptr::addr_of_mut!(LINUX_PROCS);
    for idx in 0..MAX_PROCS {
        if procs[idx].in_use && procs[idx].owner == owner {
            close_proc_slot(procs, idx, std::time::Duration::from_millis(100));
        }
    }
}

/// The node's command grant — WHAT `PROC_SPAWN` may run and how, configured
/// for the runtime by the operator at launch: `FLUXOR_PROC_ALLOW` (the
/// executables, separated by `,`, `:` or spaces; unset = none, so nothing
/// runs), `FLUXOR_PROC_ROOT` (the working directory; unset = the runtime's
/// own), `FLUXOR_PROC_ENV` (the environment names passed through; unset =
/// `PATH HOME USER LANG LC_ALL TERM`) and `FLUXOR_PROC_TIMEOUT_MS` (unset =
/// 120000). The allowlist is accident-prevention, NOT confinement (any tool
/// is RCE-equivalent — the node is the boundary); `root`/`env`/`timeout` are
/// hygiene + blast-radius bounds.
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
        let default_env = || {
            ["PATH", "HOME", "USER", "LANG", "LC_ALL", "TERM"]
                .iter()
                .map(|s| s.to_string())
                .collect::<std::vec::Vec<_>>()
        };
        ProcGrant {
            root: std::env::var("FLUXOR_PROC_ROOT")
                .ok()
                .map(std::path::PathBuf::from),
            allow: std::env::var("FLUXOR_PROC_ALLOW")
                .ok()
                .map(split)
                .unwrap_or_default(),
            env_allow: std::env::var("FLUXOR_PROC_ENV")
                .ok()
                .map(split)
                .unwrap_or_else(default_env),
            timeout_ms: std::env::var("FLUXOR_PROC_TIMEOUT_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(120_000),
        }
    })
}

/// The node's commands (`host_process::PROC_*`), handed here by the
/// `host_process` provider. SPAWN's command line is `data` in; READ answers
/// into `arg`; the others take the index SPAWN answered.
pub(crate) fn proc_dispatch(handle: i32, opcode: u32, arg: &mut [u8], data: UserSpan<'_>) -> i32 {
    use crate::kernel::sys::errno;
    use crate::kernel::workload::extbridge::OverloadPolicy;
    use crate::platform::proc_executor::{ProcExecutor, SpawnPolicy};

    // SAFETY: provider dispatch runs on the scheduler thread, the only
    // thread touching the process-slot table.
    let procs = unsafe { &mut *core::ptr::addr_of_mut!(LINUX_PROCS) };
    match opcode {
        PROC_SPAWN => {
            let line = data.as_slice();
            if line.is_empty() {
                return errno::EINVAL;
            }
            // A host process acts with the node's authority: the node and an
            // owner acting with it spawn one, a workload never does. The
            // child is the spawning owner's, and goes with it.
            let owner = crate::kernel::exec::scheduler::caller_owner();
            if !crate::kernel::exec::scheduler::caller_authority().is_node() {
                return errno::EACCES;
            }
            let line = match core::str::from_utf8(line) {
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
                    slot as i32
                }
                Err(_) => errno::ERROR,
            }
        }
        PROC_READ => {
            let slot = usize::try_from(handle).unwrap_or(usize::MAX);
            if slot >= MAX_PROCS || !proc_owned(&procs[slot]) || arg.is_empty() {
                return errno::EINVAL;
            }
            let out = arg;
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
            let slot = usize::try_from(handle).unwrap_or(usize::MAX);
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
            if let (false, Some(out)) = (running, arg.get_mut(..4)) {
                out.copy_from_slice(&e.exit_code().unwrap_or(-1).to_le_bytes());
            }
            i32::from(running)
        }
        PROC_CLOSE => {
            let slot = usize::try_from(handle).unwrap_or(usize::MAX);
            if slot < MAX_PROCS && proc_owned(&procs[slot]) {
                close_proc_slot(procs, slot, std::time::Duration::from_millis(100));
            }
            0
        }
        _ => errno::ENOSYS,
    }
}
