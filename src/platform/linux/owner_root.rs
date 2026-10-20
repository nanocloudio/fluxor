//! Owner-scoped storage on Linux.
//!
//! A workload is a tenant of the node. What it reaches through the platform's
//! storage contracts is a root of its own, never the host filesystem, the
//! HTTP origin or the node's control-plane store:
//!
//! - `fs` resolves inside `<base>/<owner uid>/files/`, through `openat2` with
//!   `RESOLVE_BENEATH`, so no path, symlink or magic link leads out of it;
//! - `storage.object` and `storage.namespace` reach a versioned store of the
//!   owner's own, under `<base>/<owner uid>/store/`, with handle tables of its
//!   own;
//! - what it holds is charged to the owner's storage ledger against the
//!   `storage_bytes` its `CREATE` admitted: each file its size plus
//!   [`ENTRY_COST`], each directory [`ENTRY_COST`], and each store entry its
//!   key, its value and a record overhead.
//!
//! A file's charge is kept per inode and read from the inode itself, so it
//! follows the file whichever handle or path changes it.
//!
//! An owner reaches a root only by its grant
//! (`kernel::workload::storage::StorageGrant`): one whose `CREATE` granted no
//! node storage is answered `EACCES`, and the costs it is charged are the
//! ones every platform charges.
//!
//! The base is `$FLUXOR_OWNER_ROOT`, default `/var/lib/fluxor/owners`. A root
//! is made when an owner granted one first touches storage, and removed when
//! the owner is released. Nothing else removes it: a root survives a runtime
//! restart, and an owner admitted again under the same identity finds what it
//! held, charged to its ledger again. A root for an identity the node agent
//! will not admit again is the agent's to remove. Data that must outlive the
//! owner itself belongs to a volume.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::kernel::exec::scheduler;
use crate::kernel::sys::errno;
use crate::kernel::workload::owner::OwnerHandle;
use crate::kernel::workload::storage::{file_cost, may_hold_storage, ENTRY_COST};
use crate::platform::linux::store::{Served, Store};

/// Where owner roots live when `FLUXOR_OWNER_ROOT` is unset.
const DEFAULT_BASE: &str = "/var/lib/fluxor/owners";
/// Change history an owner's store retains for its watchers.
const OWNER_STORE_HISTORY: usize = 4096;
/// Changes one of an owner's watchers may fall behind by.
const OWNER_STORE_RING: usize = 1024;
/// Longest path an owner names, matching the `fs` provider's own bound.
const PATH_MAX: usize = 255;

/// One owner's root: its files directory, held open, its store with the
/// handles on it, opened on first use, and what each inode is charged.
struct Root {
    owner: OwnerHandle,
    dir: PathBuf,
    files_fd: i32,
    store: Option<Served>,
    inodes: BTreeMap<u64, u64>,
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

/// What an inode costs its owner: a regular file its size plus
/// [`ENTRY_COST`], anything else [`ENTRY_COST`].
pub fn inode_cost(st: &libc::stat) -> u64 {
    if st.st_mode & libc::S_IFMT == libc::S_IFREG {
        file_cost(st.st_size as u64)
    } else {
        ENTRY_COST
    }
}

/// Every inode under `dir`, with its cost, by `lstat`: a symlink is charged
/// as a name and never followed.
fn walk_inodes(dir: &Path, into: &mut BTreeMap<u64, u64>) {
    use std::os::unix::fs::MetadataExt;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        let cost = if meta.is_file() {
            file_cost(meta.len())
        } else {
            ENTRY_COST
        };
        into.insert(meta.ino(), cost);
        if meta.is_dir() {
            walk_inodes(&entry.path(), into);
        }
    }
}

pub use crate::kernel::workload::storage::rooted;

/// The owner's root, made on first use. `None` for the system owner (which
/// has no root: the host is its own), an owner that no longer resolves or is
/// on its way out, or a root that cannot be made.
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
    if !may_hold_storage(owner) {
        return None;
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
    // What the root already holds is the owner's to carry: an owner admitted
    // again under the same identity is charged for it, past its cap if need
    // be, so it can shrink but not grow until it is back under.
    let mut inodes = BTreeMap::new();
    walk_inodes(&files, &mut inodes);
    scheduler::owners_mut().charge_storage_held(owner, inodes.values().sum());
    roots.push(Root {
        owner,
        dir,
        files_fd,
        store: None,
        inodes,
    });
    roots.last_mut()
}

/// The owner's own versioned store with its handle tables, opened on first
/// use and charged for what it already holds.
///
/// # Safety
/// As [`root_for`].
pub unsafe fn store_for(owner: OwnerHandle) -> Option<&'static mut Served> {
    let root = root_for(owner)?;
    if root.store.is_none() {
        match Store::open(
            &root.dir.join("store"),
            OWNER_STORE_HISTORY,
            OWNER_STORE_RING,
        ) {
            Ok(s) => {
                let served = Served::owner(s);
                scheduler::owners_mut().charge_storage_held(owner, served.held_bytes());
                root.store = Some(served);
            }
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

/// The owner-release half this library holds: close the files the owner
/// holds open, drop its store and the handles on it, close its files
/// directory and remove its root. A root the owner never opened in this run,
/// one a previous run left, is removed all the same. An owner that acted
/// with the node's authority has no root: the files, host processes and
/// node-store handles it opened are closed, and nothing on the host is
/// removed. The runtime's owner-release hook calls it, while the owner still
/// resolves, beside the host namespace and HTTP object providers' own.
pub fn release(owner: OwnerHandle) {
    if owner.is_system() {
        return;
    }
    if !rooted(owner) {
        // SAFETY: owner release runs on the scheduler thread, as every dispatch.
        unsafe {
            crate::platform::linux::providers::release_owner_files(owner);
            crate::platform::linux::providers::release_owner_procs(owner);
            crate::platform::linux::store::release_opener(owner);
        }
        return;
    }
    // SAFETY: owner release runs on the scheduler thread, as every dispatch.
    let dir = unsafe {
        let roots = &mut *core::ptr::addr_of_mut!(ROOTS);
        match roots.iter().position(|r| r.owner == owner) {
            Some(i) => {
                let root = roots.swap_remove(i);
                crate::platform::linux::providers::release_owner_files(owner);
                drop(root.store);
                libc::close(root.files_fd);
                root.dir
            }
            None => match scheduler::owners().lookup(owner) {
                Some(e) => base_dir().join(hex(&e.owner_uid)),
                None => return,
            },
        }
    };
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => log::warn!(
            "[owner_root] owner slot {} root {} not removed: {e}",
            owner.slot,
            dir.display()
        ),
    }
}

/// Set what inode `ino` is charged to `owner` to `cost`, charging or giving
/// back the difference. A growth is refused (`false`, nothing changed) when
/// `within_cap` and the owner's cap would be passed; settling what an inode
/// already holds (`within_cap` false) is never refused. A cost of 0 forgets
/// the inode.
///
/// # Safety
/// As [`root_for`].
pub unsafe fn charge_inode(owner: OwnerHandle, ino: u64, cost: u64, within_cap: bool) -> bool {
    let Some(root) = root_for(owner) else {
        return !within_cap;
    };
    let had = root.inodes.get(&ino).copied().unwrap_or(0);
    if cost > had {
        let grow = cost - had;
        if within_cap {
            if scheduler::owners_mut().charge_storage(owner, grow).is_err() {
                return false;
            }
        } else {
            scheduler::owners_mut().charge_storage_held(owner, grow);
        }
    } else if had > cost {
        scheduler::owners_mut().release_storage(owner, had - cost);
    }
    if cost == 0 {
        root.inodes.remove(&ino);
    } else {
        root.inodes.insert(ino, cost);
    }
    true
}

/// What inode `ino` is charged to `owner`.
///
/// # Safety
/// As [`root_for`].
pub unsafe fn inode_charge(owner: OwnerHandle, ino: u64) -> u64 {
    root_for(owner)
        .and_then(|r| r.inodes.get(&ino).copied())
        .unwrap_or(0)
}

/// Charge `bytes` to `owner` ahead of creating something, within its cap.
pub fn reserve(owner: OwnerHandle, bytes: u64) -> bool {
    scheduler::owners_mut().charge_storage(owner, bytes).is_ok()
}

/// Give back `bytes` reserved and not used.
pub fn unreserve(owner: OwnerHandle, bytes: u64) {
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

/// `lstat` of `name` in `dirfd`.
///
/// # Safety
/// `dirfd` open; `name` NUL-terminated.
pub unsafe fn stat_at(dirfd: i32, name: &[u8; 256]) -> Option<libc::stat> {
    let mut st: libc::stat = core::mem::zeroed();
    (libc::fstatat(
        dirfd,
        name.as_ptr() as *const libc::c_char,
        &mut st,
        libc::AT_SYMLINK_NOFOLLOW,
    ) == 0)
        .then_some(st)
}

/// `fstat` of an open descriptor.
///
/// # Safety
/// `fd` is a descriptor this provider holds.
pub unsafe fn stat_fd(fd: i32) -> Option<libc::stat> {
    let mut st: libc::stat = core::mem::zeroed();
    (libc::fstat(fd, &mut st) == 0).then_some(st)
}
