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
//!
//! A volume is a host directory lent to a workload at its `CREATE`
//! (`abi::contracts::workload::volume`, [`lend`]): the workload's `fs` paths
//! at or under the volume's path resolve beneath that directory, through
//! the same `openat2` `RESOLVE_BENEATH`, whatever its storage grant. A
//! symlink in a volume resolves when its target stays beneath the volume's
//! directory, so a directory laid out by the Kubernetes AtomicWriter
//! (`key -> ..data/key`, `..data -> ..<timestamp>`) reads, and a swap of
//! `..data` is seen by the next open; a link that leads out of it, by an
//! absolute target or a `..` past its top, and every magic link, is refused
//! (`EACCES`). The owner's own root follows no symlink at all: nothing the
//! owner can make there is one. A path op that names an entry (`UNLINK`,
//! `RENAME`, `RMDIR`, `READLINK`, the `lstat` charging reads) acts on a link
//! itself, never its target; only the directories leading to it are
//! followed. A listing reports a link as an entry of its own (type 0), not
//! as what it points at. A read-only volume takes no change (`EACCES`),
//! whatever a link in it names. What a volume holds is the
//! node's, not the owner's: nothing in it is charged to the owner's ledger,
//! and the owner's release closes the volume and leaves its directory as it
//! was.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::kernel::exec::scheduler;
use crate::kernel::sys::errno;
use crate::kernel::workload::owner::OwnerHandle;
use crate::kernel::workload::storage::{file_cost, may_hold_storage, ENTRY_COST};
use crate::platform::linux::providers::LINUX_FS_PATH_MAX;
use crate::platform::linux::store::{Served, Store};

/// Where owner roots live when `FLUXOR_OWNER_ROOT` is unset.
const DEFAULT_BASE: &str = "/var/lib/fluxor/owners";
/// Change history an owner's store retains: how far back its watchers'
/// `CHANGES` reads reach before they relist.
const OWNER_STORE_HISTORY: usize = 4096;

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

/// A host directory lent to an owner: held open (`O_PATH`), named by `dst`
/// — the owner's path for it, its components joined by `/`, no leading one.
struct Volume {
    owner: OwnerHandle,
    dst: Vec<u8>,
    fd: i32,
    ro: bool,
}

static mut VOLUMES: Vec<Volume> = Vec::new();

/// A workload's own vault (`workload::vault`): the directory its labelled
/// keys are kept in, held open, and the key its owner supplied that they
/// are sealed under.
struct Vault {
    owner: OwnerHandle,
    dir_fd: i32,
    key: [u8; crate::abi::contracts::workload::vault::SEAL_KEY_LEN],
}

static mut VAULTS: Vec<Vault> = Vec::new();

/// Give `owner` its own vault: the directory `dir` (a path the owner names,
/// in one of the volumes lent to it, made when absent) and the key its
/// records are sealed under. `EINVAL` for a `dir` in no lent volume or a
/// second vault; `EACCES` for a read-only volume; the error making or
/// opening the directory otherwise.
///
/// # Safety
/// As [`lend`].
pub unsafe fn set_vault(
    owner: OwnerHandle,
    dir: &[u8],
    key: [u8; crate::abi::contracts::workload::vault::SEAL_KEY_LEN],
) -> Result<(), i32> {
    let vaults = &mut *core::ptr::addr_of_mut!(VAULTS);
    if owner.is_system() || vaults.iter().any(|v| v.owner == owner) {
        return Err(errno::EINVAL);
    }
    let rel = relative(dir)?;
    let Some((v, _)) = volume_of(owner, &rel) else {
        return Err(errno::EINVAL);
    };
    if v.ro {
        return Err(errno::EACCES);
    }
    let mut fd = open_beneath(owner, dir, libc::O_RDONLY | libc::O_DIRECTORY, 0);
    if fd == errno::ENOENT {
        let (parent, name) = parent_beneath(owner, dir)?;
        let made = libc::mkdirat(parent, name.as_ptr() as *const libc::c_char, 0o700);
        let err = *libc::__errno_location();
        libc::close(parent);
        if made != 0 && err != libc::EEXIST {
            return Err(-err);
        }
        fd = open_beneath(owner, dir, libc::O_RDONLY | libc::O_DIRECTORY, 0);
    }
    if fd < 0 {
        return Err(fd);
    }
    vaults.push(Vault {
        owner,
        dir_fd: fd,
        key,
    });
    Ok(())
}

/// Forget `owner`'s vault: its directory closed and left as it is, its key
/// wiped.
///
/// # Safety
/// As [`lend`].
unsafe fn close_vault(owner: OwnerHandle) {
    let vaults = &mut *core::ptr::addr_of_mut!(VAULTS);
    vaults.retain_mut(|v| {
        if v.owner != owner {
            return true;
        }
        for b in v.key.iter_mut() {
            core::ptr::write_volatile(b, 0);
        }
        libc::close(v.dir_fd);
        false
    });
}

unsafe fn vault_of(owner: OwnerHandle) -> Option<&'static Vault> {
    let vaults = &*core::ptr::addr_of!(VAULTS);
    vaults.iter().find(|v| v.owner == owner)
}

/// Whether `owner` brought a vault of its own.
///
/// # Safety
/// As [`lend`].
pub unsafe fn vault_present(owner: OwnerHandle) -> bool {
    vault_of(owner).is_some()
}

/// The key `owner`'s vault records are sealed under; the caller wipes it.
///
/// # Safety
/// As [`lend`].
pub unsafe fn vault_key(
    owner: OwnerHandle,
) -> Option<[u8; crate::abi::contracts::workload::vault::SEAL_KEY_LEN]> {
    vault_of(owner).map(|v| v.key)
}

/// A record's file name in a vault: its name, hex-encoded (a name is any
/// bytes; a file name is not), NUL-terminated.
fn vault_file(name: &[u8], tmp: bool) -> Option<std::ffi::CString> {
    let mut s = String::with_capacity(name.len() * 2 + 4);
    for b in name {
        use core::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    if tmp {
        s.push_str(".tmp");
    }
    std::ffi::CString::new(s).ok()
}

/// Read the record `name` from `owner`'s vault into `out`: its length, or
/// `None` when there is none (or it does not fit).
///
/// # Safety
/// As [`lend`].
pub unsafe fn vault_read(owner: OwnerHandle, name: &[u8], out: &mut [u8]) -> Option<usize> {
    let v = vault_of(owner)?;
    let file = vault_file(name, false)?;
    let fd = libc::openat(
        v.dir_fd,
        file.as_ptr(),
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    );
    if fd < 0 {
        return None;
    }
    let mut at = 0usize;
    let mut whole = false;
    loop {
        if at == out.len() {
            // One byte more than fits says the record is not one of ours.
            let mut extra = [0u8; 1];
            whole = libc::read(fd, extra.as_mut_ptr().cast(), 1) == 0;
            break;
        }
        let n = libc::read(fd, out[at..].as_mut_ptr().cast(), out.len() - at);
        if n < 0 {
            break;
        }
        if n == 0 {
            whole = true;
            break;
        }
        at += n as usize;
    }
    libc::close(fd);
    whole.then_some(at)
}

/// Store `blob` as the record `name` in `owner`'s vault so it outlives the
/// process: written to a temporary, flushed, renamed over the old record and
/// the directory flushed, so `true` means it would survive a power cut and a
/// crash at any point leaves the old record whole.
///
/// # Safety
/// As [`lend`].
pub unsafe fn vault_write(owner: OwnerHandle, name: &[u8], blob: &[u8]) -> bool {
    let Some(v) = vault_of(owner) else {
        return false;
    };
    let (Some(file), Some(tmp)) = (vault_file(name, false), vault_file(name, true)) else {
        return false;
    };
    let fd = libc::openat(
        v.dir_fd,
        tmp.as_ptr(),
        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    );
    if fd < 0 {
        return false;
    }
    let mut at = 0usize;
    while at < blob.len() {
        let n = libc::write(fd, blob[at..].as_ptr().cast(), blob.len() - at);
        if n <= 0 {
            break;
        }
        at += n as usize;
    }
    let ok = at == blob.len() && libc::fsync(fd) == 0;
    libc::close(fd);
    if !ok || libc::renameat(v.dir_fd, tmp.as_ptr(), v.dir_fd, file.as_ptr()) != 0 {
        libc::unlinkat(v.dir_fd, tmp.as_ptr(), 0);
        return false;
    }
    libc::fsync(v.dir_fd) == 0
}

/// Remove the record `name` from `owner`'s vault; whether none remains.
///
/// # Safety
/// As [`lend`].
pub unsafe fn vault_delete(owner: OwnerHandle, name: &[u8]) -> bool {
    let Some(v) = vault_of(owner) else {
        return false;
    };
    let Some(file) = vault_file(name, false) else {
        return false;
    };
    if libc::unlinkat(v.dir_fd, file.as_ptr(), 0) != 0 && *libc::__errno_location() != libc::ENOENT
    {
        return false;
    }
    libc::fsync(v.dir_fd) == 0
}

/// Lend `owner` the host directory `src` (absolute) at its path `dst`,
/// read-only when `ro`. `EINVAL` for a `dst` that is empty, climbs (`.`/`..`)
/// or is lent already; `E2BIG` past `workload::volume::MAX` volumes; the
/// error opening `src` (`ENOENT`, `ENOTDIR`, ...).
///
/// # Safety
/// Single-threaded platform dispatch only: touches the `static mut` table.
pub unsafe fn lend(owner: OwnerHandle, src: &[u8], dst: &[u8], ro: bool) -> Result<(), i32> {
    if owner.is_system() || !src.starts_with(b"/") || src.contains(&0) {
        return Err(errno::EINVAL);
    }
    let mut norm = Vec::new();
    for part in dst.split(|&b| b == b'/').filter(|p| !p.is_empty()) {
        if part == b"." || part == b".." || part.contains(&0) {
            return Err(errno::EINVAL);
        }
        if !norm.is_empty() {
            norm.push(b'/');
        }
        norm.extend_from_slice(part);
    }
    if norm.is_empty() || norm.len() > LINUX_FS_PATH_MAX {
        return Err(errno::EINVAL);
    }
    let vols = &mut *core::ptr::addr_of_mut!(VOLUMES);
    let held = vols.iter().filter(|v| v.owner == owner);
    if held.clone().any(|v| v.dst == norm) {
        return Err(errno::EINVAL);
    }
    if held.count() >= crate::abi::contracts::workload::volume::MAX {
        return Err(errno::E2BIG);
    }
    let c = std::ffi::CString::new(src).map_err(|_| errno::EINVAL)?;
    let fd = libc::open(
        c.as_ptr(),
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
    );
    if fd < 0 {
        return Err(-*libc::__errno_location());
    }
    vols.push(Volume {
        owner,
        dst: norm,
        fd,
        ro,
    });
    Ok(())
}

/// Close every volume lent to `owner`. Its directories stay as they are.
///
/// # Safety
/// As [`lend`].
unsafe fn close_volumes(owner: OwnerHandle) {
    let vols = &mut *core::ptr::addr_of_mut!(VOLUMES);
    vols.retain(|v| {
        if v.owner == owner {
            libc::close(v.fd);
            false
        } else {
            true
        }
    });
}

/// The volume a root-relative path (as [`relative`] makes it) lies in, the
/// longest `dst` that is the path or a parent of it, and the rest of the
/// path beneath it (`.` for the volume itself).
///
/// # Safety
/// As [`lend`].
unsafe fn volume_of(owner: OwnerHandle, rel: &[u8; 256]) -> Option<(&'static Volume, [u8; 256])> {
    let len = rel.iter().position(|&b| b == 0).unwrap_or(rel.len());
    let path = &rel[..len];
    let vols = &*core::ptr::addr_of!(VOLUMES);
    let v = vols
        .iter()
        .filter(|v| {
            v.owner == owner
                && path.starts_with(&v.dst)
                && (path.len() == v.dst.len() || path[v.dst.len()] == b'/')
        })
        .max_by_key(|v| v.dst.len())?;
    let mut rest = &path[v.dst.len()..];
    while let Some(r) = rest.strip_prefix(b"/") {
        rest = r;
    }
    let mut out = [0u8; 256];
    if rest.is_empty() {
        out[0] = b'.';
    } else {
        out[..rest.len()].copy_from_slice(rest);
    }
    Some((v, out))
}

/// Which volume `path` (as the owner names it) lies in: an index stable for
/// the call, or `None` for the owner's own root. What lies in a volume is
/// not charged to the owner.
///
/// # Safety
/// As [`lend`].
pub unsafe fn volume_index(owner: OwnerHandle, path: &[u8]) -> Option<usize> {
    let rel = relative(path).ok()?;
    let (v, _) = volume_of(owner, &rel)?;
    let vols = &*core::ptr::addr_of!(VOLUMES);
    vols.iter().position(|x| core::ptr::eq(x, v))
}

/// Whether `path` lies in a volume lent to `owner`.
///
/// # Safety
/// As [`lend`].
pub unsafe fn lent(owner: OwnerHandle, path: &[u8]) -> bool {
    volume_index(owner, path).is_some()
}

/// Whether `open(2)` flags ask to change what they open.
fn writes(flags: i32) -> bool {
    flags & (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) != 0
}

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
        match Store::open(&root.dir.join("store"), OWNER_STORE_HISTORY) {
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
    // Lent, not owned: closed, and left as they are; the vault's key wiped.
    // SAFETY: owner release runs on the scheduler thread, as every dispatch.
    unsafe {
        close_vault(owner);
        close_volumes(owner);
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
/// root, and an empty path is the root itself. At most the `fs` provider's
/// `LINUX_FS_PATH_MAX`, so it is NUL-terminated for libc within 256 bytes.
fn relative(path: &[u8]) -> Result<[u8; 256], i32> {
    if path.len() > LINUX_FS_PATH_MAX || path.contains(&0) {
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
    let rel = match relative(path) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if let Some((v, rest)) = volume_of(owner, &rel) {
        if v.ro && writes(flags) {
            return errno::EACCES;
        }
        return openat2_beneath(v.fd, &rest, flags, mode, Links::Beneath);
    }
    let Some(root) = root_for(owner) else {
        return errno::EACCES;
    };
    openat2_beneath(root.files_fd, &rel, flags, mode, Links::None)
}

/// `struct open_how` as `openat2(2)` reads it.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// Which symlinks a resolution beneath a directory follows.
#[derive(Clone, Copy)]
enum Links {
    /// None: the owner's own root, where nothing the owner makes is a link.
    None,
    /// Those whose target stays beneath the directory: a lent volume. A
    /// link leading out (absolute, or `..` past the top) is `EXDEV` from
    /// `RESOLVE_BENEATH`, a magic link `ELOOP`; both answer `EACCES`.
    Beneath,
}

unsafe fn openat2_beneath(dirfd: i32, rel: &[u8; 256], flags: i32, mode: u32, links: Links) -> i32 {
    let resolve = match links {
        Links::None => {
            libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS
        }
        Links::Beneath => libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS,
    };
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: mode as u64,
        resolve,
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
    let rel = relative(path)?;
    // In a volume, beneath its directory: a read-only one takes no change,
    // and the volume itself is no entry the owner can change.
    let (base_fd, rel, links) = match volume_of(owner, &rel) {
        Some((v, _)) if v.ro => return Err(errno::EACCES),
        Some((_, rest)) if rest[0] == b'.' && rest[1] == 0 => return Err(errno::EBUSY),
        Some((v, rest)) => (v.fd, rest, Links::Beneath),
        None => match root_for(owner) {
            Some(root) => (root.files_fd, rel, Links::None),
            None => return Err(errno::EACCES),
        },
    };
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
    // The directories leading to the name follow what `links` allows; the
    // name itself is the caller's to act on, a link as a link.
    let dirfd = openat2_beneath(base_fd, &dir, libc::O_RDONLY | libc::O_DIRECTORY, 0, links);
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
