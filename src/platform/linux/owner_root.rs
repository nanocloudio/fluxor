//! Owner-scoped storage on Linux.
//!
//! A workload is a tenant of the node. What it reaches through the platform's
//! storage contracts is a root of its own, never the host filesystem, the
//! HTTP origin or the node's control-plane store:
//!
//! - `fs` resolves inside `<base>/<owner uid>/files/`, through `openat2` with
//!   `RESOLVE_BENEATH`, so no path, symlink or magic link leads out of it;
//! - `storage.object` and `storage.namespace` reach a versioned store of the
//!   owner's own, under `<base>/<owner uid>/store/`;
//! - every byte it holds is charged to the owner's storage ledger against the
//!   `storage_bytes` its `CREATE` admitted.
//!
//! The base is `$FLUXOR_OWNER_ROOT`, default `/var/lib/fluxor/owners`. A root
//! is made when the owner first touches storage and removed when the owner is
//! released. Nothing else removes it: a root survives a runtime restart, and
//! an owner admitted again under the same identity finds what it held. Data
//! that must outlive the owner itself belongs to a volume.

use std::path::{Path, PathBuf};

use crate::kernel::exec::scheduler;
use crate::kernel::sys::errno;
use crate::kernel::workload::owner::OwnerHandle;
use crate::platform::linux::store::Store;

/// Where owner roots live when `FLUXOR_OWNER_ROOT` is unset.
const DEFAULT_BASE: &str = "/var/lib/fluxor/owners";
/// Change history an owner's store retains for its watchers.
const OWNER_STORE_HISTORY: usize = 4096;
/// Changes one of an owner's watchers may fall behind by.
const OWNER_STORE_RING: usize = 1024;
/// Longest path an owner names, matching the `fs` provider's own bound.
const PATH_MAX: usize = 255;

/// One owner's root: its files directory, held open, and its store, opened
/// on first use.
struct Root {
    owner: OwnerHandle,
    dir: PathBuf,
    files_fd: i32,
    store: Option<Store>,
}

static mut ROOTS: Vec<Root> = Vec::new();

fn base_dir() -> PathBuf {
    std::env::var_os("FLUXOR_OWNER_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_BASE))
}

fn hex(uid: &[u8; 16]) -> String {
    uid.iter().map(|b| format!("{b:02x}")).collect()
}

/// Bytes a directory tree holds in regular files.
fn tree_bytes(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut total = 0u64;
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.is_dir() {
            total += tree_bytes(&entry.path());
        } else if meta.is_file() {
            total += meta.len();
        }
    }
    total
}

/// The owner's root, made on first use. `None` for the system owner (which
/// has no root: the host is its own), an owner that no longer resolves, or a
/// root that cannot be made.
///
/// # Safety
/// Single-threaded platform dispatch only: touches the `static mut` table.
unsafe fn root_for(owner: OwnerHandle) -> Option<&'static mut Root> {
    if owner.is_system() {
        return None;
    }
    let roots = &mut *core::ptr::addr_of_mut!(ROOTS);
    if let Some(i) = roots.iter().position(|r| r.owner == owner) {
        return roots.get_mut(i);
    }
    let uid = scheduler::owners().lookup(owner)?.owner_uid;
    let dir = base_dir().join(hex(&uid));
    let files = dir.join("files");
    if std::fs::create_dir_all(&files).is_err()
        || std::fs::create_dir_all(dir.join("store")).is_err()
    {
        log::error!(
            "[owner_root] owner slot {} has no storage root: {} cannot be made",
            owner.slot,
            dir.display()
        );
        return None;
    }
    let c = std::ffi::CString::new(files.as_os_str().as_encoded_bytes()).ok()?;
    let files_fd = libc::open(
        c.as_ptr(),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
    );
    if files_fd < 0 {
        return None;
    }
    // What the root already holds is the owner's to carry: an owner
    // re-admitted under the same identity finds its scratch charged.
    let held = tree_bytes(&dir);
    if held > 0 {
        let _ = scheduler::owners_mut().charge_storage(owner, held);
    }
    roots.push(Root {
        owner,
        dir,
        files_fd,
        store: None,
    });
    roots.last_mut()
}

/// The owner's own versioned store, opened on first use.
///
/// # Safety
/// As [`root_for`].
pub unsafe fn store_for(owner: OwnerHandle) -> Option<&'static mut Store> {
    let root = root_for(owner)?;
    if root.store.is_none() {
        match Store::open(
            &root.dir.join("store"),
            OWNER_STORE_HISTORY,
            OWNER_STORE_RING,
        ) {
            Ok(s) => root.store = Some(s),
            Err(e) => {
                log::error!(
                    "[owner_root] owner slot {} store would not open: {e}",
                    owner.slot
                );
                return None;
            }
        }
    }
    root.store.as_mut()
}

/// The platform's owner-release hook: close the owner's store and files
/// directory and remove its root. Registered with the kernel at init.
pub fn release(owner: OwnerHandle) {
    // SAFETY: owner release runs on the scheduler thread, as every dispatch.
    unsafe {
        let roots = &mut *core::ptr::addr_of_mut!(ROOTS);
        let Some(i) = roots.iter().position(|r| r.owner == owner) else {
            return;
        };
        let root = roots.swap_remove(i);
        drop(root.store);
        libc::close(root.files_fd);
        if let Err(e) = std::fs::remove_dir_all(&root.dir) {
            log::warn!(
                "[owner_root] owner slot {} root {} not removed: {e}",
                owner.slot,
                root.dir.display()
            );
        }
    }
}

/// Charge `bytes` of storage to `owner`; `false` when its cap refuses.
pub fn charge(owner: OwnerHandle, bytes: u64) -> bool {
    scheduler::owners_mut().charge_storage(owner, bytes).is_ok()
}

/// Give `bytes` of storage back to `owner`.
pub fn release_bytes(owner: OwnerHandle, bytes: u64) {
    scheduler::owners_mut().release_storage(owner, bytes);
}

/// A path as the owner names it, relative to its root: a leading `/` is the
/// root, and an empty path is the root itself. NUL-terminated for libc.
fn relative(path: &[u8]) -> Result<[u8; 256], i32> {
    if path.len() > PATH_MAX || path.contains(&0) {
        return Err(errno::EINVAL);
    }
    let mut p = path;
    while let Some(rest) = p.strip_prefix(b"/") {
        p = rest;
    }
    let mut out = [0u8; 256];
    if p.is_empty() {
        out[0] = b'.';
    } else {
        out[..p.len()].copy_from_slice(p);
    }
    Ok(out)
}

/// The errno for a path that `openat2` would not resolve beneath the root:
/// the owner asked for something outside what it owns.
fn confined(raw: i32) -> i32 {
    match raw {
        libc::EXDEV | libc::ELOOP => errno::EACCES,
        e => -e,
    }
}

/// Open `path` beneath the owner's files root. The fd, or a negative errno.
///
/// # Safety
/// As [`root_for`].
pub unsafe fn open_beneath(owner: OwnerHandle, path: &[u8], flags: i32, mode: u32) -> i32 {
    let Some(root) = root_for(owner) else {
        return errno::EACCES;
    };
    let rel = match relative(path) {
        Ok(r) => r,
        Err(e) => return e,
    };
    openat2_beneath(root.files_fd, &rel, flags, mode)
}

/// `struct open_how` as `openat2(2)` reads it.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

unsafe fn openat2_beneath(dirfd: i32, rel: &[u8; 256], flags: i32, mode: u32) -> i32 {
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: mode as u64,
        resolve: libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
    };
    let fd = libc::syscall(
        libc::SYS_openat2,
        dirfd,
        rel.as_ptr() as *const libc::c_char,
        &how as *const OpenHow,
        core::mem::size_of::<OpenHow>(),
    );
    if fd < 0 {
        return confined(*libc::__errno_location());
    }
    fd as i32
}

/// The directory holding `path`, opened beneath the owner's root, and the
/// name inside it: `(dirfd, name)`, the fd the caller's to close. A name
/// that is empty, `.` or `..` names no entry and is `EINVAL`.
///
/// # Safety
/// As [`root_for`].
pub unsafe fn parent_beneath(owner: OwnerHandle, path: &[u8]) -> Result<(i32, [u8; 256]), i32> {
    let Some(root) = root_for(owner) else {
        return Err(errno::EACCES);
    };
    let rel = relative(path)?;
    let len = rel.iter().position(|&b| b == 0).unwrap_or(0);
    let mut end = len;
    while end > 0 && rel[end - 1] == b'/' {
        end -= 1;
    }
    let cut = rel[..end].iter().rposition(|&b| b == b'/');
    let (dir_part, name_part): (&[u8], &[u8]) = match cut {
        Some(c) => (&rel[..c.max(1)], &rel[c + 1..end]),
        None => (b".", &rel[..end]),
    };
    if name_part.is_empty() || name_part == b"." || name_part == b".." {
        return Err(errno::EINVAL);
    }
    let mut dir = [0u8; 256];
    if dir_part.is_empty() {
        dir[0] = b'.';
    } else {
        dir[..dir_part.len()].copy_from_slice(dir_part);
    }
    let dirfd = openat2_beneath(root.files_fd, &dir, libc::O_RDONLY | libc::O_DIRECTORY, 0);
    if dirfd < 0 {
        return Err(dirfd);
    }
    let mut name = [0u8; 256];
    name[..name_part.len()].copy_from_slice(name_part);
    Ok((dirfd, name))
}

/// Size of the regular file `name` in `dirfd`, 0 for anything else.
///
/// # Safety
/// `dirfd` open; `name` NUL-terminated.
pub unsafe fn file_size_at(dirfd: i32, name: &[u8; 256]) -> u64 {
    let mut st: libc::stat = core::mem::zeroed();
    if libc::fstatat(
        dirfd,
        name.as_ptr() as *const libc::c_char,
        &mut st,
        libc::AT_SYMLINK_NOFOLLOW,
    ) != 0
        || st.st_mode & libc::S_IFMT != libc::S_IFREG
    {
        return 0;
    }
    st.st_size as u64
}
