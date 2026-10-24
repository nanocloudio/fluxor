//! Linux host mounts (contract class 0x1F, `abi::platform::linux::host_mount`).
//!
//! Mounts a block device onto a directory under the operator's mount root,
//! and unmounts it. The platform holds the policy: every mount point lies
//! under the root (`FLUXOR_MOUNT_ROOT`, default `/var/lib/fluxor/mounts`), the
//! source must be a block device, and every mount is `nodev,nosuid`. Answers
//! are the kernel's errno, so a caller tells a missing privilege (`EPERM`)
//! from a device that will not mount.
//!
//! mount(2) and umount2(2) never run on the scheduler thread. Both wait on
//! the device's I/O, and the device may be one this node serves itself (an
//! NBD export of an encrypted volume): a blocking call there would stop the
//! very modules that must answer it. Each runs on a thread of its own; the
//! caller is answered `EAGAIN` and asks again with the same argument, and
//! the call that finds the thread finished takes its answer.
//!
//! # Job table
//!
//! A job is keyed by (calling module, opcode, exact request), so a module
//! only ever collects its own answers. The table is bounded:
//!
//! - a caller holds at most `MAX_JOBS_PER_CALLER` jobs, and the table at most
//!   `MAX_JOBS`; a request beyond either is answered `EAGAIN` without starting
//!   while the jobs holding the room are still running (back-pressure);
//! - an answer nobody collects expires `RESULT_TTL` after the job finished;
//! - when a caller is at its quota or the table is full, the caller's own
//!   oldest finished job is dropped to make room. A running job is never
//!   dropped, and one caller's abandoned answers never cost another caller
//!   its room beyond their `RESULT_TTL`.
//!
//! A dropped or expired answer is recoverable because both operations are
//! idempotent against the host's mount table (`/proc/self/mountinfo`): a
//! `MOUNT` of the device already mounted at that target with the same access
//! answers 0, and an `UMOUNT` of a target with nothing mounted answers 0.
//! The retry therefore reaches the state the lost answer described. The one
//! difference is `UMOUNT`: a lost 1 ("unmounted") is re-answered 0 ("nothing
//! mounted"), both meaning the target is free.
//!
//! # Path handling
//!
//! The root is operator-owned and trusted. Beneath it, every component of a
//! caller's directory is opened with `O_NOFOLLOW` from the descriptor of its
//! parent, so a symlink planted under the root is refused (`EINVAL`) rather
//! than followed out of it, and a mount lands on the descriptor just opened
//! (`/proc/self/fd`), not on a path that could be swapped after the check.
//! An unmount holds the walked parent and identifies the mount at the leaf
//! by its id (`statx` through the parent, no symlink followed); the mount
//! with that id must sit at exactly that directory and be one `MOUNT` makes
//! (a block device's filesystem, `nodev`, `nosuid`). The id is read again
//! and the unmount names the leaf through the held parent
//! (`/proc/self/fd/<parent>/<leaf>`, `UMOUNT_NOFOLLOW`), so no directory
//! above it can be swapped. The kernel has no unmount by descriptor or id:
//! a party able to rename entries inside the parent directory between the
//! second read and the call could still put another mount of the same
//! kind there, which is why the root must not be writable by untrusted
//! users.
//!
//! # Projections, removal, group ownership and directory modes
//!
//! `PROJECT` writes a set of files into a directory under the root with the
//! timestamped-directory swap: the files land in a fresh `..<timestamp>`
//! directory, a temporary link to it is renamed over `..data` (one atomic
//! rename), each top-level name is a link through `..data`, and what the
//! previous projection left is removed after the swap. A file's requested
//! mode is masked to the permission bits, so no setuid, setgid or sticky bit
//! is ever written to one; a directory is 0755, with a group 2755 (setgid,
//! so what is made inside inherits the group).
//! A memory-backed projection mounts a `tmpfs` there once, named
//! [`PROJECTION_SOURCE`] in the mount table so it is known again after a
//! restart, and bounded: the size the request states, or
//! [`PROJECTION_MEMORY_DEFAULT`] (what the entries need when that is more),
//! at most [`PROJECTION_MEMORY_MAX`], and a file count to match. A later
//! projection grows the bound by its own for the swap and sets it back to
//! its own after.
//!
//! `MKDIR_MODE` makes a directory by the same walk and gives it an exact
//! mode through the descriptor the walk opened, whatever the umask.
//!
//! `REMOVE_TREE` and `GROUP_TREE` walk below the target with `openat2`
//! (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV`), or, on a
//! kernel without it, `O_NOFOLLOW` opens with a device compare; either way a
//! symlink is never followed and a mount is never entered. The mount table
//! is read first as well, since a bind mount from the same filesystem shares
//! its device number: `REMOVE_TREE` refuses (`EBUSY`) any mount inside that
//! a projection did not make, before removing anything, and `GROUP_TREE`
//! leaves every inner mount alone. `REMOVE_TREE` then unmounts each
//! projection mount as `UMOUNT` unmounts a volume: reached from the held
//! parent through no symlink, identified by its mount id, and removed only
//! while that id is a projection's memory filesystem at exactly that path.

use crate::abi::platform::linux::host_mount as hm;
use crate::kernel::sys::errno;
use std::collections::HashSet;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

const DEFAULT_ROOT: &str = "/var/lib/fluxor/mounts";
/// Bit of `CAP_SYS_ADMIN` in a capability set.
const CAP_SYS_ADMIN: u32 = 21;
/// Bit of `CAP_CHOWN` in a capability set.
const CAP_CHOWN: u32 = 0;
/// The source a projection's memory filesystem carries in the mount table:
/// how `PROJECT` knows its own mount again and `REMOVE_TREE` tells it from a
/// volume.
pub const PROJECTION_SOURCE: &str = "fluxor-projection";
/// The `..data` link of a projection and the temporary name it is made
/// under before the rename.
const DATA_LINK: &str = "..data";
const DATA_TMP: &str = "..data_tmp";
/// Mounts and unmounts running or answered and not yet collected, over all
/// callers.
pub const MAX_JOBS: usize = 16;
/// The share of the table one caller may hold.
pub const MAX_JOBS_PER_CALLER: usize = 4;
/// How long a finished job's answer waits to be collected.
pub const RESULT_TTL: Duration = Duration::from_secs(30);
/// The bytes a memory-backed projection's filesystem may hold when the
/// request states no size (`P_SIZE`), or what its entries need when that is
/// more.
pub const PROJECTION_MEMORY_DEFAULT: u64 = 64 << 20;
/// The most a memory-backed projection's filesystem may hold, stated or
/// needed: a larger one is `E2BIG`.
pub const PROJECTION_MEMORY_MAX: u64 = 1 << 30;

/// Work started off the scheduler thread; its value is the answer.
pub type Work = Box<dyn FnOnce() -> i32 + Send>;

/// The answer of a job, and when it was produced.
struct Slot {
    done: OnceLock<(i32, Instant)>,
}

/// A mount or unmount started off the scheduler thread.
struct Job {
    caller: u64,
    op: u32,
    arg: Vec<u8>,
    slot: Arc<Slot>,
}

impl Job {
    fn finished_at(&self) -> Option<Instant> {
        self.slot.done.get().map(|&(_, t)| t)
    }
}

/// Bounded table of off-thread jobs. Jobs are kept in start order.
#[doc(hidden)]
pub struct JobTable {
    jobs: Mutex<Vec<Job>>,
    max_jobs: usize,
    per_caller: usize,
    ttl: Duration,
}

impl JobTable {
    pub const fn new(max_jobs: usize, per_caller: usize, ttl: Duration) -> Self {
        Self {
            jobs: Mutex::new(Vec::new()),
            max_jobs,
            per_caller,
            ttl,
        }
    }

    /// Jobs held, running or answered.
    pub fn len(&self) -> usize {
        self.jobs.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Jobs held whose answer is ready.
    pub fn finished(&self) -> usize {
        let jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        jobs.iter().filter(|j| j.finished_at().is_some()).count()
    }

    /// Answer `op(arg)` for `caller` from its job: the result once the job
    /// has finished (collecting it), `EAGAIN` while it runs. With no job yet,
    /// `check` runs here; its `Err` is the answer at once, and its `Ok` work
    /// is started on a thread of its own when the caller and the table have
    /// room for it. `now` is the monotonic time of the call.
    pub fn run(
        &self,
        caller: u64,
        op: u32,
        arg: &[u8],
        now: Instant,
        check: impl FnOnce() -> Result<Work, i32>,
    ) -> i32 {
        let mut jobs = self.jobs.lock().unwrap_or_else(|p| p.into_inner());
        let ttl = self.ttl;
        jobs.retain(|j| {
            j.finished_at()
                .is_none_or(|t| now.saturating_duration_since(t) < ttl)
        });
        if let Some(i) = jobs
            .iter()
            .position(|j| j.caller == caller && j.op == op && j.arg == arg)
        {
            return match jobs[i].slot.done.get() {
                Some(&(rc, _)) => {
                    jobs.remove(i);
                    rc
                }
                None => -libc::EAGAIN,
            };
        }
        let work = match check() {
            Ok(w) => w,
            Err(e) => return e,
        };
        let held = jobs.iter().filter(|j| j.caller == caller).count();
        if held >= self.per_caller || jobs.len() >= self.max_jobs {
            // Make room from the caller's own finished answers, oldest
            // first; running jobs are never dropped.
            let oldest = jobs
                .iter()
                .enumerate()
                .filter(|(_, j)| j.caller == caller)
                .filter_map(|(i, j)| j.finished_at().map(|t| (t, i)))
                .min();
            match oldest {
                Some((_, i)) => {
                    jobs.remove(i);
                }
                None => return -libc::EAGAIN,
            }
            if jobs.len() >= self.max_jobs {
                return -libc::EAGAIN;
            }
        }
        let slot = Arc::new(Slot {
            done: OnceLock::new(),
        });
        let done = slot.clone();
        let spawned = std::thread::Builder::new()
            .name("host_mount".into())
            .spawn(move || {
                let rc = work();
                let _ = done.done.set((rc, Instant::now()));
            });
        if spawned.is_err() {
            return -libc::EAGAIN;
        }
        jobs.push(Job {
            caller,
            op,
            arg: arg.to_vec(),
            slot,
        });
        -libc::EAGAIN
    }
}

static TABLE: JobTable = JobTable::new(MAX_JOBS, MAX_JOBS_PER_CALLER, RESULT_TTL);

/// Identity of the calling module, stable across its retries: the module
/// slot together with the owner generation, so a module slot reused by a
/// later tenant does not inherit its predecessor's jobs.
fn caller_key() -> u64 {
    use crate::kernel::exec::scheduler;
    let owner = scheduler::caller_owner();
    ((scheduler::current_module_index() as u64) << 48)
        | (u64::from(owner.slot) << 32)
        | u64::from(owner.generation)
}

fn run_off_thread(op: u32, arg: &[u8], check: impl FnOnce() -> Result<Work, i32>) -> i32 {
    TABLE.run(caller_key(), op, arg, Instant::now(), check)
}

/// The mount root (`FLUXOR_MOUNT_ROOT`, default `/var/lib/fluxor/mounts`):
/// where every mount, projection and volume tree of this provider lies, and
/// so where workloads write.
pub fn mount_root() -> &'static Path {
    root()
}

fn root() -> &'static Path {
    static ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        std::env::var_os("FLUXOR_MOUNT_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_ROOT))
    })
}

/// `rel` as a path relative to the mount root, or `EINVAL` for one that is
/// empty, absolute or climbs out.
fn resolve(rel: &[u8]) -> Result<PathBuf, i32> {
    let rel = core::str::from_utf8(rel).map_err(|_| errno::EINVAL)?;
    let rel = Path::new(rel);
    if rel.as_os_str().is_empty() {
        return Err(errno::EINVAL);
    }
    let mut out = PathBuf::new();
    for c in rel.components() {
        match c {
            Component::Normal(p) => out.push(p),
            _ => return Err(errno::EINVAL),
        }
    }
    Ok(out)
}

fn last_errno() -> i32 {
    -std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

/// Whether this process holds capability `bit` in its effective set.
fn holds_cap(bit: u32) -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
        .is_some_and(|caps| caps & (1u64 << bit) != 0)
}

/// The `PRIV` answer: the privilege bits this runtime holds.
fn privileges() -> i32 {
    let mut p = 0;
    if holds_cap(CAP_SYS_ADMIN) {
        p |= hm::PRIV_SYS_ADMIN;
    }
    if holds_cap(CAP_CHOWN) {
        p |= hm::PRIV_CHOWN;
    }
    p
}

/// What `/proc/self/mountinfo` says of the topmost mount at a directory.
#[doc(hidden)]
#[derive(Debug, PartialEq, Eq)]
pub struct MountEntry {
    /// Device number of the mounted filesystem, `(major, minor)`.
    pub dev: (u32, u32),
    /// Whether the mount is read-only.
    pub ro: bool,
}

/// The topmost mount whose mount point is exactly `dir` in `info` (the text
/// of `/proc/self/mountinfo`), or `None` when nothing is mounted there.
#[doc(hidden)]
pub fn mount_entry(info: &str, dir: &Path) -> Option<MountEntry> {
    let want = dir.as_os_str().as_bytes();
    info.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            if f.len() < 7 || unescape(f[4]).as_slice() != want {
                return None;
            }
            let (maj, min) = f[2].split_once(':')?;
            Some(MountEntry {
                dev: (maj.parse().ok()?, min.parse().ok()?),
                ro: f[5].split(',').any(|o| o == "ro"),
            })
        })
        .next_back()
}

/// A mount point as `/proc/self/mountinfo` lists it.
#[doc(hidden)]
#[derive(Debug, PartialEq, Eq)]
pub struct MountPoint {
    pub path: PathBuf,
    pub fstype: String,
    pub source: String,
}

impl MountPoint {
    /// Whether `PROJECT` made this mount.
    pub fn is_projection(&self) -> bool {
        self.fstype == "tmpfs" && self.source == PROJECTION_SOURCE
    }
}

/// Every mount in `info` whose mount point is `dir` or lies beneath it, in
/// the table's order (a mount stacked over another comes after it).
#[doc(hidden)]
pub fn mounts_under(info: &str, dir: &Path) -> Vec<MountPoint> {
    info.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            if f.len() < 7 {
                return None;
            }
            let path = PathBuf::from(std::ffi::OsString::from_vec(unescape(f[4])));
            if !path.starts_with(dir) {
                return None;
            }
            let sep = f.iter().skip(6).position(|t| *t == "-")? + 6;
            Some(MountPoint {
                path,
                fstype: f.get(sep + 1)?.to_string(),
                source: String::from_utf8_lossy(&unescape(f.get(sep + 2)?)).into_owned(),
            })
        })
        .collect()
}

/// [`mounts_under`] against the host's table now.
fn host_mounts_under(dir: &Path) -> Result<Vec<MountPoint>, i32> {
    let info = std::fs::read_to_string("/proc/self/mountinfo").map_err(|e| os_errno(&e))?;
    Ok(mounts_under(&info, dir))
}

/// The mount at `dir` as the host lists it now.
fn mounted_at(dir: &Path) -> Option<MountEntry> {
    let info = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    mount_entry(&info, dir)
}

/// Undo mountinfo's octal escapes (`\040` for a space, and so on).
fn unescape(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 4 <= b.len() {
            let digits = core::str::from_utf8(&b[i + 1..i + 4]).unwrap_or("");
            if let Ok(v) = u8::from_str_radix(digits, 8) {
                out.push(v);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn cstr(p: &Path) -> Result<CString, i32> {
    CString::new(p.as_os_str().as_bytes()).map_err(|_| errno::EINVAL)
}

/// Targets with a mount or unmount in flight; one worker at a time per
/// target keeps "is it mounted, then mount it" from racing itself.
fn in_flight() -> &'static Mutex<HashSet<PathBuf>> {
    static SET: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    SET.get_or_init(|| Mutex::new(HashSet::new()))
}

struct TargetClaim(PathBuf);

impl TargetClaim {
    fn take(target: &Path) -> Option<Self> {
        let mut set = in_flight().lock().unwrap_or_else(|p| p.into_inner());
        set.insert(target.to_path_buf())
            .then(|| Self(target.to_path_buf()))
    }
}

impl Drop for TargetClaim {
    fn drop(&mut self) {
        in_flight()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.0);
    }
}

fn os_errno(e: &std::io::Error) -> i32 {
    -e.raw_os_error().unwrap_or(libc::EIO)
}

/// Open `path` below `parent` as a directory without following a symlink at
/// that name. A symlink is `EINVAL` (it would redirect out of the root);
/// `Ok(None)` is a name that does not exist.
fn open_dir_at(parent: libc::c_int, name: &CString) -> Result<Option<OwnedFd>, i32> {
    // SAFETY: `name` is NUL-terminated; `parent` is an open descriptor.
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd >= 0 {
        // SAFETY: a descriptor just returned by openat, owned by nobody else.
        return Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) }));
    }
    let err = last_errno();
    if err == -libc::ENOENT {
        return Ok(None);
    }
    // O_NOFOLLOW on a symlink reports ENOTDIR (with O_DIRECTORY) or ELOOP.
    let mut st = core::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: as above; `st` is written on success.
    let is_link = unsafe {
        libc::fstatat(
            parent,
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        ) == 0
            && (st.assume_init().st_mode & libc::S_IFMT) == libc::S_IFLNK
    };
    Err(if is_link { errno::EINVAL } else { err })
}

/// The directory `rel` below the mount root, every component opened
/// `O_NOFOLLOW` from its parent. With `create`, missing components are made
/// (mode 0755, `leaf_mode` for the last, both under the umask). `Ok(None)` is
/// a component that does not exist.
fn walk(rel: &[std::ffi::OsString], create: bool, leaf_mode: u32) -> Result<Option<OwnedFd>, i32> {
    if create {
        std::fs::create_dir_all(root()).map_err(|e| os_errno(&e))?;
    }
    let base = cstr(root())?;
    // SAFETY: a NUL-terminated path.
    let fd = unsafe {
        libc::open(
            base.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let err = last_errno();
        return if err == -libc::ENOENT {
            Ok(None)
        } else {
            Err(err)
        };
    }
    // SAFETY: a descriptor just returned by open, owned by nobody else.
    let mut cur = unsafe { OwnedFd::from_raw_fd(fd) };
    for (i, name) in rel.iter().enumerate() {
        let name = CString::new(name.as_bytes()).map_err(|_| errno::EINVAL)?;
        if create {
            let mode = if i + 1 == rel.len() { leaf_mode } else { 0o755 };
            // SAFETY: `cur` is open; `name` is NUL-terminated.
            let rc = unsafe { libc::mkdirat(cur.as_raw_fd(), name.as_ptr(), mode as libc::mode_t) };
            if rc != 0 && last_errno() != -libc::EEXIST {
                return Err(last_errno());
            }
        }
        match open_dir_at(cur.as_raw_fd(), &name)? {
            Some(next) => cur = next,
            None => return Ok(None),
        }
    }
    Ok(Some(cur))
}

fn components(rel: &Path) -> Vec<std::ffi::OsString> {
    rel.iter().map(|c| c.to_os_string()).collect()
}

/// The path of an open descriptor, as the kernel resolves it.
fn fd_target(fd: &OwnedFd) -> Result<PathBuf, i32> {
    std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).map_err(|e| os_errno(&e))
}

/// Check a `MOUNT` request against the policy; `Ok` is the mount itself.
///
/// The directory is made and verified by the work, not here: a target that
/// already holds this very mount is answered 0 without touching it, and any
/// other mount there is `EBUSY`.
fn check_mount(arg: &[u8]) -> Result<Work, i32> {
    if arg.len() < 6 {
        return Err(errno::EINVAL);
    }
    let dev_len = u16::from_le_bytes([arg[0], arg[1]]) as usize;
    let dir_len = u16::from_le_bytes([arg[2], arg[3]]) as usize;
    let fs_len = arg[4] as usize;
    let flags = arg[5];
    let body = &arg[6..];
    if body.len() < dev_len + dir_len + fs_len || fs_len == 0 || dev_len == 0 {
        return Err(errno::EINVAL);
    }
    let dev = Path::new(std::ffi::OsStr::from_bytes(&body[..dev_len]));
    let fs = &body[dev_len + dir_len..dev_len + dir_len + fs_len];
    let rel = components(&resolve(&body[dev_len..dev_len + dir_len])?);
    if !dev.is_absolute() {
        return Err(errno::EINVAL);
    }
    let rdev = match std::fs::metadata(dev) {
        Ok(m) => {
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            if !m.file_type().is_block_device() {
                return Err(-libc::ENOTBLK);
            }
            m.rdev()
        }
        Err(e) => return Err(-e.raw_os_error().unwrap_or(libc::ENOENT)),
    };
    let want = (libc::major(rdev), libc::minor(rdev));
    let (Ok(src), Ok(fstype)) = (cstr(dev), CString::new(fs)) else {
        return Err(errno::EINVAL);
    };
    let ro = flags & hm::F_RDONLY != 0;
    let mut mflags = libc::MS_NODEV | libc::MS_NOSUID;
    if ro {
        mflags |= libc::MS_RDONLY;
    }
    Ok(Box::new(move || {
        let fd = match walk(&rel, true, 0o700) {
            Ok(Some(fd)) => fd,
            Ok(None) => return -libc::ENOENT,
            Err(e) => return e,
        };
        let target = match fd_target(&fd) {
            Ok(t) => t,
            Err(e) => return e,
        };
        let Some(_claim) = TargetClaim::take(&target) else {
            return -libc::EBUSY;
        };
        if let Some(m) = mounted_at(&target) {
            return if m == (MountEntry { dev: want, ro }) {
                0
            } else {
                -libc::EBUSY
            };
        }
        // SAFETY: `fd` is an open directory.
        unsafe { libc::fchmod(fd.as_raw_fd(), 0o700) };
        let Ok(dst) = CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())) else {
            return errno::EINVAL;
        };
        // SAFETY: three NUL-terminated strings owned by this closure.
        let rc = unsafe {
            libc::mount(
                src.as_ptr(),
                dst.as_ptr(),
                fstype.as_ptr(),
                mflags,
                core::ptr::null(),
            )
        };
        if rc != 0 {
            last_errno()
        } else {
            0
        }
    }))
}

/// What `statx` says of `name` in `dir` (of `dir` itself for `None`) —
/// its type and the id of the mount it is on — without following a symlink
/// or triggering an automount. `None` when there is nothing by that name;
/// `ENOSYS` on a kernel that reports no mount id (before 5.8).
fn statx_at(dir: &OwnedFd, name: Option<&CString>) -> Result<Option<libc::statx>, i32> {
    let mut stx = core::mem::MaybeUninit::<libc::statx>::zeroed();
    let (path, flags) = match name {
        Some(n) => (
            n.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT,
        ),
        None => (c"".as_ptr(), libc::AT_EMPTY_PATH | libc::AT_NO_AUTOMOUNT),
    };
    // SAFETY: `dir` is open, `path` NUL-terminated, `stx` written on success.
    let rc = unsafe {
        libc::statx(
            dir.as_raw_fd(),
            path,
            flags,
            libc::STATX_TYPE | libc::STATX_MNT_ID,
            stx.as_mut_ptr(),
        )
    };
    if rc != 0 {
        let e = last_errno();
        return if e == -libc::ENOENT { Ok(None) } else { Err(e) };
    }
    // SAFETY: written by the successful call above.
    let stx = unsafe { stx.assume_init() };
    if stx.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(errno::ENOSYS);
    }
    Ok(Some(stx))
}

/// A mount as `/proc/self/mountinfo` lists it by its id.
#[doc(hidden)]
#[derive(Debug, PartialEq, Eq)]
pub struct MountRow {
    pub path: PathBuf,
    /// Device number of the mounted filesystem, `(major, minor)`.
    pub dev: (u32, u32),
    /// The per-mount options carry both `nodev` and `nosuid`.
    pub nodev_nosuid: bool,
    pub fstype: String,
    pub source: String,
}

impl MountRow {
    /// Whether `MOUNT` makes a mount like this one: a filesystem on a block
    /// device (a memory filesystem has major 0), `nodev` and `nosuid`.
    pub fn is_volume(&self) -> bool {
        self.dev.0 != 0 && self.nodev_nosuid
    }

    /// Whether `PROJECT` makes a mount like this one: its memory
    /// filesystem, named [`PROJECTION_SOURCE`], `nodev` and `nosuid`.
    pub fn is_projection(&self) -> bool {
        self.fstype == "tmpfs" && self.source == PROJECTION_SOURCE && self.nodev_nosuid
    }
}

/// The mount whose id is `id` in `info` (the text of
/// `/proc/self/mountinfo`), the id `statx` reports as `stx_mnt_id`.
#[doc(hidden)]
pub fn mount_with_id(info: &str, id: u64) -> Option<MountRow> {
    info.lines().find_map(|l| {
        let f: Vec<&str> = l.split(' ').collect();
        if f.len() < 7 || f[0].parse::<u64>().ok()? != id {
            return None;
        }
        let (maj, min) = f[2].split_once(':')?;
        let opts: Vec<&str> = f[5].split(',').collect();
        let sep = f.iter().skip(6).position(|t| *t == "-")? + 6;
        Some(MountRow {
            path: PathBuf::from(std::ffi::OsString::from_vec(unescape(f[4]))),
            dev: (maj.parse().ok()?, min.parse().ok()?),
            nodev_nosuid: opts.contains(&"nodev") && opts.contains(&"nosuid"),
            fstype: f.get(sep + 1)?.to_string(),
            source: String::from_utf8_lossy(&unescape(f.get(sep + 2)?)).into_owned(),
        })
    })
}

/// Unmount the mount at `leaf` in the held directory `parent`, whose path is
/// `target`, if `accept` says it is one this provider may remove. What is
/// mounted there is identified, not looked up: its mount id is read through
/// `parent` (`statx`, no symlink followed); the mount with that id must sit
/// at exactly `target` and pass `accept`, else `EBUSY`; the id is read
/// again; and the unmount names the leaf through the held parent
/// (`/proc/self/fd/<parent>/<leaf>`, `UMOUNT_NOFOLLOW`). `Ok(true)` when it
/// unmounted, `Ok(false)` when nothing is mounted there; `EINVAL` for a
/// symlink leaf, `ENOTDIR` for one that is no directory.
fn umount_verified(
    parent: &OwnedFd,
    leaf: &CString,
    target: &Path,
    accept: fn(&MountRow) -> bool,
) -> Result<bool, i32> {
    let mounted = || -> Result<Option<u64>, i32> {
        let Some(at) = statx_at(parent, Some(leaf))? else {
            return Ok(None);
        };
        match u32::from(at.stx_mode) & libc::S_IFMT {
            libc::S_IFLNK => return Err(errno::EINVAL),
            libc::S_IFDIR => {}
            _ => return Err(-libc::ENOTDIR),
        }
        let own = statx_at(parent, None)?.ok_or(-libc::ENOENT)?;
        Ok((at.stx_mnt_id != own.stx_mnt_id).then_some(at.stx_mnt_id))
    };
    let Some(id) = mounted()? else {
        return Ok(false);
    };
    let info = std::fs::read_to_string("/proc/self/mountinfo").map_err(|e| os_errno(&e))?;
    match mount_with_id(&info, id) {
        Some(row) if row.path == target && accept(&row) => {}
        Some(_) => return Err(-libc::EBUSY),
        None => return Ok(false),
    }
    let dst = CString::new(format!(
        "/proc/self/fd/{}/{}",
        parent.as_raw_fd(),
        leaf.to_string_lossy()
    ))
    .map_err(|_| errno::EINVAL)?;
    match mounted()? {
        Some(again) if again == id => {}
        None => return Ok(false),
        Some(_) => return Err(-libc::EBUSY),
    }
    // SAFETY: a NUL-terminated string owned here.
    if unsafe { libc::umount2(dst.as_ptr(), libc::UMOUNT_NOFOLLOW) } != 0 {
        return Err(last_errno());
    }
    Ok(true)
}

/// Check an `UMOUNT` request; `Ok` is the unmount itself. Nothing mounted
/// there (or no such directory) is the answer 0.
///
/// The target is never looked up by its path from the root: its parent is
/// walked and held (the parent, not the target: a descriptor on the mounted
/// filesystem would itself make the unmount `EBUSY`), and the mount is
/// removed by [`umount_verified`] only when it is one `MOUNT` makes (a block
/// device's filesystem, `nodev`, `nosuid`).
fn check_umount(arg: &[u8]) -> Result<Work, i32> {
    let mut rel = components(&resolve(arg)?);
    let leaf = rel.pop().ok_or(errno::EINVAL)?;
    let leaf = CString::new(leaf.as_bytes()).map_err(|_| errno::EINVAL)?;
    Ok(Box::new(move || {
        let parent = match walk(&rel, false, 0) {
            Ok(Some(fd)) => fd,
            Ok(None) => return 0,
            Err(e) => return e,
        };
        let target = match fd_target(&parent) {
            Ok(p) => p.join(std::ffi::OsStr::from_bytes(leaf.as_bytes())),
            Err(e) => return e,
        };
        let Some(_claim) = TargetClaim::take(&target) else {
            return -libc::EBUSY;
        };
        match umount_verified(&parent, &leaf, &target, MountRow::is_volume) {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(e) => e,
        }
    }))
}

/// Provider dispatch for `host_mount`. `handle = -1` for every op.
///
/// # Safety
/// `arg` must be null or valid for reads and writes of `arg_len` bytes.
pub unsafe fn host_mount_dispatch(_handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    let bytes = if arg.is_null() {
        &mut [][..]
    } else {
        core::slice::from_raw_parts_mut(arg, arg_len)
    };
    match opcode {
        hm::PRIV => privileges(),
        hm::MOUNT => run_off_thread(hm::MOUNT, bytes, || check_mount(bytes)),
        hm::UMOUNT => run_off_thread(hm::UMOUNT, bytes, || check_umount(bytes)),
        hm::PROJECT => run_off_thread(hm::PROJECT, bytes, || check_project(bytes)),
        hm::REMOVE_TREE => run_off_thread(hm::REMOVE_TREE, bytes, || check_remove_tree(bytes)),
        hm::GROUP_TREE => run_off_thread(hm::GROUP_TREE, bytes, || check_group_tree(bytes)),
        hm::MKDIR_MODE => run_off_thread(hm::MKDIR_MODE, bytes, || check_mkdir_mode(bytes)),
        hm::ROOT => {
            let r = root().as_os_str().as_bytes();
            if bytes.len() < r.len() {
                return -libc::ENOSPC;
            }
            bytes[..r.len()].copy_from_slice(r);
            r.len() as i32
        }
        _ => errno::ENOSYS,
    }
}

// ─── PROJECT / REMOVE_TREE / GROUP_TREE ───────────────────────────────────

/// One projected file: its path below the projection, its mode, its bytes.
struct Entry {
    path: Vec<Vec<u8>>,
    mode: u32,
    data: Vec<u8>,
}

/// A little-endian reader over a request.
struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], i32> {
        let end = self.p.checked_add(n).ok_or(errno::EINVAL)?;
        let v = self.b.get(self.p..end).ok_or(errno::EINVAL)?;
        self.p = end;
        Ok(v)
    }
    fn u8(&mut self) -> Result<u8, i32> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, i32> {
        let v = self.take(2)?;
        Ok(u16::from_le_bytes([v[0], v[1]]))
    }
    fn u32(&mut self) -> Result<u32, i32> {
        let v = self.take(4)?;
        Ok(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
    }
    fn done(&self) -> bool {
        self.p == self.b.len()
    }
}

/// A projected path: `/`-separated, no empty, `.` or `..` component, no NUL,
/// the first component not starting with `..` (those names are the
/// projection's own).
fn entry_path(p: &[u8]) -> Result<Vec<Vec<u8>>, i32> {
    if p.is_empty() || p.starts_with(b"..") || p.contains(&0) {
        return Err(errno::EINVAL);
    }
    let comps: Vec<Vec<u8>> = p.split(|&b| b == b'/').map(<[u8]>::to_vec).collect();
    if comps
        .iter()
        .any(|c| c.is_empty() || c.as_slice() == b"." || c.as_slice() == b"..")
    {
        return Err(errno::EINVAL);
    }
    Ok(comps)
}

fn c_name(b: &[u8]) -> Result<CString, i32> {
    CString::new(b).map_err(|_| errno::EINVAL)
}

/// The timestamp directory name for a projection made now.
fn stamp_name(n: u32) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    // Civil date from days since 1970-01-01 (proleptic Gregorian).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "..{y:04}_{m:02}_{d:02}_{:02}_{:02}_{:02}.{:09}{}",
        tod / 3600,
        (tod / 60) % 60,
        tod % 60,
        now.subsec_nanos(),
        if n == 0 {
            String::new()
        } else {
            format!("_{n}")
        }
    )
}

/// What a `fstatat` without following says of `name` in `dir`; `None` when
/// there is nothing by that name.
fn lstat_at(dir: &OwnedFd, name: &CString) -> Result<Option<libc::stat>, i32> {
    let mut st = core::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `dir` is open, `name` NUL-terminated; `st` written on success.
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 {
        // SAFETY: fstatat succeeded.
        return Ok(Some(unsafe { st.assume_init() }));
    }
    match last_errno() {
        e if e == -libc::ENOENT => Ok(None),
        e => Err(e),
    }
}

fn fstat(fd: &OwnedFd) -> Result<libc::stat, i32> {
    let mut st = core::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `fd` is open; `st` written on success.
    if unsafe { libc::fstat(fd.as_raw_fd(), st.as_mut_ptr()) } != 0 {
        return Err(last_errno());
    }
    // SAFETY: fstat succeeded.
    Ok(unsafe { st.assume_init() })
}

fn is_dir(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

fn is_link(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFLNK
}

/// The target of the link `name` in `dir`; `None` when there is no such
/// name, `EINVAL` when it is not a link.
fn readlink_at(dir: &OwnedFd, name: &CString) -> Result<Option<Vec<u8>>, i32> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: `buf` is writable for its length.
    let n = unsafe {
        libc::readlinkat(
            dir.as_raw_fd(),
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if n < 0 {
        return match last_errno() {
            e if e == -libc::ENOENT => Ok(None),
            e => Err(e),
        };
    }
    buf.truncate(n as usize);
    Ok(Some(buf))
}

fn unlink_at(dir: &OwnedFd, name: &CString, flags: libc::c_int) -> Result<(), i32> {
    // SAFETY: `dir` is open, `name` NUL-terminated.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), flags) } != 0 {
        let e = last_errno();
        if e != -libc::ENOENT {
            return Err(e);
        }
    }
    Ok(())
}

fn symlink_at(target: &[u8], dir: &OwnedFd, name: &CString) -> Result<(), i32> {
    let t = c_name(target)?;
    // SAFETY: both NUL-terminated; `dir` is open.
    if unsafe { libc::symlinkat(t.as_ptr(), dir.as_raw_fd(), name.as_ptr()) } != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// The names in a directory, `.` and `..` left out.
fn entries(dir: &OwnedFd) -> Result<Vec<CString>, i32> {
    // SAFETY: duplicating an open descriptor; the copy is the stream's.
    let dup = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        return Err(last_errno());
    }
    // SAFETY: `dup` is an open directory descriptor, owned by the stream.
    let d = unsafe { libc::fdopendir(dup) };
    if d.is_null() {
        let e = last_errno();
        // SAFETY: the stream did not take it.
        unsafe { libc::close(dup) };
        return Err(e);
    }
    // SAFETY: the stream starts where the shared offset is; rewind it.
    unsafe { libc::rewinddir(d) };
    let mut out = Vec::new();
    loop {
        // SAFETY: `d` is an open stream.
        let ent = unsafe { libc::readdir(d) };
        if ent.is_null() {
            break;
        }
        // SAFETY: readdir returns an entry whose name is NUL-terminated.
        let name = unsafe { core::ffi::CStr::from_ptr((*ent).d_name.as_ptr()) };
        let b = name.to_bytes();
        if b != b"." && b != b".." {
            out.push(name.to_owned());
        }
    }
    // SAFETY: closes the stream and `dup`.
    unsafe { libc::closedir(d) };
    Ok(out)
}

/// Open the directory `name` below `dir` without following a symlink and
/// without entering another mount. `Ok(None)`: nothing by that name;
/// `EXDEV`: a mount point; `ELOOP`/`ENOTDIR`: a link or not a directory.
fn open_beneath(dir: &OwnedFd, name: &CString) -> Result<Option<OwnedFd>, i32> {
    // SAFETY: open_how is plain integers; all-zero is its empty value.
    let mut how: libc::open_how = unsafe { core::mem::zeroed() };
    how.flags = (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_XDEV;
    // SAFETY: `how` is a live open_how of the size passed; `name` is
    // NUL-terminated; `dir` is open.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_raw_fd(),
            name.as_ptr(),
            &how as *const libc::open_how,
            core::mem::size_of::<libc::open_how>(),
        )
    };
    if fd >= 0 {
        // SAFETY: a descriptor just returned by openat2, owned by nobody else.
        return Ok(Some(unsafe { OwnedFd::from_raw_fd(fd as i32) }));
    }
    let e = last_errno();
    if e == -libc::ENOENT {
        return Ok(None);
    }
    if e != -libc::ENOSYS {
        return Err(e);
    }
    // No openat2: O_NOFOLLOW, then the device compared with the parent's.
    // SAFETY: as above.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return match last_errno() {
            e if e == -libc::ENOENT => Ok(None),
            e => Err(e),
        };
    }
    // SAFETY: a descriptor just returned by openat, owned by nobody else.
    let sub = unsafe { OwnedFd::from_raw_fd(fd) };
    if fstat(&sub)?.st_dev != fstat(dir)?.st_dev {
        return Err(-libc::EXDEV);
    }
    Ok(Some(sub))
}

/// Remove everything inside `dir`, never following a link or entering a
/// mount (`EBUSY` if one is met).
fn remove_contents(dir: &OwnedFd) -> Result<(), i32> {
    for name in entries(dir)? {
        let Some(st) = lstat_at(dir, &name)? else {
            continue;
        };
        if is_dir(&st) {
            match open_beneath(dir, &name) {
                Ok(Some(sub)) => remove_contents(&sub)?,
                Ok(None) => continue,
                Err(e) if e == -libc::EXDEV => return Err(-libc::EBUSY),
                Err(e) => return Err(e),
            }
            unlink_at(dir, &name, libc::AT_REMOVEDIR)?;
        } else {
            unlink_at(dir, &name, 0)?;
        }
    }
    Ok(())
}

/// Remove the directory `name` in `parent` and everything inside it.
fn remove_dir_at(parent: &OwnedFd, name: &CString) -> Result<(), i32> {
    match open_beneath(parent, name) {
        Ok(Some(sub)) => remove_contents(&sub)?,
        Ok(None) => return Ok(()),
        Err(e) if e == -libc::EXDEV => return Err(-libc::EBUSY),
        Err(e) => return Err(e),
    }
    unlink_at(parent, name, libc::AT_REMOVEDIR)
}

fn fchown_group(fd: &OwnedFd, group: u32) -> Result<(), i32> {
    // SAFETY: `fd` is open; uid -1 leaves the owner as it is.
    if unsafe { libc::fchown(fd.as_raw_fd(), u32::MAX, group) } != 0 {
        return Err(last_errno());
    }
    Ok(())
}

fn fchmod(fd: &OwnedFd, mode: u32) -> Result<(), i32> {
    // SAFETY: `fd` is open.
    if unsafe { libc::fchmod(fd.as_raw_fd(), mode as libc::mode_t) } != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// A projection directory's group and mode: `0o755`, and with a group the
/// group and setgid (group read and search are already in `0o755`).
fn set_dir(fd: &OwnedFd, group: Option<u32>) -> Result<(), i32> {
    if let Some(g) = group {
        fchown_group(fd, g)?;
        fchmod(fd, 0o2755)
    } else {
        fchmod(fd, 0o755)
    }
}

/// A projection request, checked.
struct Projection {
    rel: Vec<std::ffi::OsString>,
    group: Option<u32>,
    memory: bool,
    read_only: bool,
    entries: Vec<Entry>,
    /// The bytes and files its memory filesystem holds ([`memory_bound`]).
    bound: (u64, u64),
}

fn parse_project(arg: &[u8]) -> Result<Projection, i32> {
    let mut r = Rd { b: arg, p: 0 };
    let dir_len = r.u16()? as usize;
    let rel = components(&resolve(r.take(dir_len)?)?);
    let group = match r.u32()? {
        hm::NO_GROUP => None,
        g => Some(g),
    };
    let flags = r.u8()?;
    if flags & !(hm::P_MEMORY | hm::P_READ_ONLY | hm::P_SIZE) != 0
        || (flags & hm::P_SIZE != 0 && flags & hm::P_MEMORY == 0)
    {
        return Err(errno::EINVAL);
    }
    let count = r.u16()? as usize;
    let mut entries: Vec<Entry> = Vec::with_capacity(count);
    for _ in 0..count {
        let path_len = r.u16()? as usize;
        let path = entry_path(r.take(path_len)?)?;
        let mode = u32::from(r.u16()?);
        let data_len = r.u32()? as usize;
        let data = r.take(data_len)?.to_vec();
        if entries.iter().any(|e| e.path == path) {
            return Err(errno::EINVAL);
        }
        entries.push(Entry { path, mode, data });
    }
    let size = if flags & hm::P_SIZE != 0 {
        let b: [u8; 8] = r.take(8)?.try_into().map_err(|_| errno::EINVAL)?;
        Some(u64::from_le_bytes(b))
    } else {
        None
    };
    if !r.done() {
        return Err(errno::EINVAL);
    }
    let memory = flags & hm::P_MEMORY != 0;
    let bound = if memory {
        memory_bound(&entries, size)?
    } else {
        (0, 0)
    };
    Ok(Projection {
        rel,
        group,
        memory,
        read_only: flags & hm::P_READ_ONLY != 0,
        entries,
        bound,
    })
}

/// The page size every memory filesystem counts in.
fn page() -> u64 {
    // SAFETY: a query with no side effect.
    let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if p > 0 {
        p as u64
    } else {
        4096
    }
}

/// What a memory-backed projection's filesystem needs to hold `entries`:
/// `(bytes, files)` — every file's bytes in whole pages, a page for each
/// entry and for the projection's own names (a long link takes one), and a
/// file for each entry, each directory, each top-level link and the
/// projection's own names.
#[doc(hidden)]
pub fn memory_need(entries: &[(Vec<Vec<u8>>, u64)]) -> (u64, u64) {
    let page = page();
    let mut bytes = page * (entries.len() as u64 + 4);
    let mut dirs: HashSet<Vec<Vec<u8>>> = HashSet::new();
    let mut tops: HashSet<&[u8]> = HashSet::new();
    for (path, len) in entries {
        bytes += len.div_ceil(page) * page;
        for k in 1..path.len() {
            dirs.insert(path[..k].to_vec());
        }
        if let Some(t) = path.first() {
            tops.insert(t);
        }
    }
    let files = entries.len() as u64 + dirs.len() as u64 + tops.len() as u64 + 4;
    (bytes, files)
}

/// The bound of a memory-backed projection's filesystem: `(bytes, files)`.
/// `size` when stated (`ENOSPC` when the entries need more), else
/// [`PROJECTION_MEMORY_DEFAULT`] or what the entries need when that is more;
/// either way at most [`PROJECTION_MEMORY_MAX`] (`E2BIG`). The files are what
/// the entries need and one per page of room.
fn memory_bound(entries: &[Entry], size: Option<u64>) -> Result<(u64, u64), i32> {
    let listed: Vec<(Vec<Vec<u8>>, u64)> = entries
        .iter()
        .map(|e| (e.path.clone(), e.data.len() as u64))
        .collect();
    let (need, files) = memory_need(&listed);
    let bytes = match size {
        Some(s) if s > PROJECTION_MEMORY_MAX => return Err(-libc::E2BIG),
        Some(s) if s < need => return Err(-libc::ENOSPC),
        Some(s) => s,
        None => need.max(PROJECTION_MEMORY_DEFAULT),
    };
    if bytes > PROJECTION_MEMORY_MAX {
        return Err(-libc::E2BIG);
    }
    Ok((bytes, files + bytes / page()))
}

/// What the memory filesystem at `dir` holds now: `(bytes, files)`.
fn memory_used(dir: &OwnedFd) -> Result<(u64, u64), i32> {
    let mut st = core::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `dir` is open; `st` is written on success.
    if unsafe { libc::fstatvfs(dir.as_raw_fd(), st.as_mut_ptr()) } != 0 {
        return Err(last_errno());
    }
    // SAFETY: written by the successful call above.
    let st = unsafe { st.assume_init() };
    let bytes = st.f_blocks.saturating_sub(st.f_bfree) * st.f_frsize;
    let files = st.f_files.saturating_sub(st.f_ffree);
    Ok((bytes, files))
}

/// Set the bound of the memory filesystem whose root is `dir`, in place.
fn memory_resize(dir: &OwnedFd, (bytes, files): (u64, u64)) -> Result<(), i32> {
    let at =
        CString::new(format!("/proc/self/fd/{}", dir.as_raw_fd())).map_err(|_| errno::EINVAL)?;
    let opts =
        CString::new(format!("size={bytes},nr_inodes={files}")).map_err(|_| errno::EINVAL)?;
    // SAFETY: NUL-terminated strings owned here.
    let rc = unsafe {
        libc::mount(
            core::ptr::null(),
            at.as_ptr(),
            core::ptr::null(),
            libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV,
            opts.as_ptr().cast(),
        )
    };
    if rc != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// Check a `PROJECT` request; `Ok` is the projection itself.
fn check_project(arg: &[u8]) -> Result<Work, i32> {
    let p = parse_project(arg)?;
    Ok(Box::new(move || match project(&p) {
        Ok(()) => 0,
        Err(e) => e,
    }))
}

fn project(p: &Projection) -> Result<(), i32> {
    let mut dir = walk(&p.rel, true, 0o755)?.ok_or(-libc::ENOENT)?;
    let target = fd_target(&dir)?;
    let Some(_claim) = TargetClaim::take(&target) else {
        return Err(-libc::EBUSY);
    };
    if p.memory {
        let here = host_mounts_under(&target)?
            .into_iter()
            .rfind(|m| m.path == target);
        match here {
            // Room for the one it holds and the new one while the swap
            // runs; cut back to the new one's bound once it is done.
            Some(m) if m.is_projection() => {
                let (b, f) = memory_used(&dir)?;
                memory_resize(&dir, (b + p.bound.0, f + p.bound.1))?;
            }
            Some(_) => return Err(-libc::EBUSY),
            None => {
                let dst = CString::new(format!("/proc/self/fd/{}", dir.as_raw_fd()))
                    .map_err(|_| errno::EINVAL)?;
                let src = c_name(PROJECTION_SOURCE.as_bytes())?;
                let opts = CString::new(format!(
                    "mode=0755,size={},nr_inodes={}",
                    p.bound.0, p.bound.1
                ))
                .map_err(|_| errno::EINVAL)?;
                // SAFETY: NUL-terminated strings owned here.
                let rc = unsafe {
                    libc::mount(
                        src.as_ptr(),
                        dst.as_ptr(),
                        c"tmpfs".as_ptr(),
                        libc::MS_NOSUID | libc::MS_NODEV,
                        opts.as_ptr().cast(),
                    )
                };
                if rc != 0 {
                    return Err(last_errno());
                }
                // The descriptor names the directory beneath the new mount.
                dir = walk(&p.rel, false, 0)?.ok_or(-libc::ENOENT)?;
            }
        }
    }
    set_dir(&dir, p.group)?;

    // The top-level names, each a link through `..data`; a name already
    // there as anything but the projection's own link to it (`..data/<name>`)
    // is not the projection's to replace.
    let mut tops: Vec<CString> = Vec::new();
    for e in &p.entries {
        let t = c_name(&e.path[0])?;
        if !tops.contains(&t) {
            tops.push(t);
        }
    }
    for t in &tops {
        if lstat_at(&dir, t)?.is_some()
            && readlink_at(&dir, t).ok().flatten() != Some(data_link_to(t))
        {
            return Err(-libc::EEXIST);
        }
    }

    // A fresh timestamp directory holding every entry.
    let mut n = 0u32;
    let stamp = loop {
        let name = c_name(stamp_name(n).as_bytes())?;
        // SAFETY: `dir` is open, `name` NUL-terminated.
        if unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) } == 0 {
            break name;
        }
        let e = last_errno();
        if e != -libc::EEXIST || n > 1000 {
            return Err(e);
        }
        n += 1;
    };
    if let Err(e) = fill(&dir, &stamp, p) {
        let _ = remove_dir_at(&dir, &stamp);
        return Err(e);
    }

    // The swap: one rename makes the new set what `..data` names.
    let tmp = c_name(DATA_TMP.as_bytes())?;
    let data = c_name(DATA_LINK.as_bytes())?;
    unlink_at(&dir, &tmp, 0)?;
    symlink_at(stamp.as_bytes(), &dir, &tmp)?;
    // SAFETY: `dir` is open; both names NUL-terminated.
    if unsafe {
        libc::renameat(
            dir.as_raw_fd(),
            tmp.as_ptr(),
            dir.as_raw_fd(),
            data.as_ptr(),
        )
    } != 0
    {
        let e = last_errno();
        let _ = unlink_at(&dir, &tmp, 0);
        let _ = remove_dir_at(&dir, &stamp);
        return Err(e);
    }

    // Links for the names the projection carries.
    for t in &tops {
        let want = data_link_to(t);
        match readlink_at(&dir, t)? {
            Some(have) if have == want => {}
            Some(_) => {
                unlink_at(&dir, t, 0)?;
                symlink_at(&want, &dir, t)?;
            }
            None => symlink_at(&want, &dir, t)?,
        }
    }
    // What the previous projection left: links to names no entry carries
    // any more, and every timestamp directory but the new one.
    for name in entries(&dir)? {
        let b = name.as_bytes();
        if b == DATA_LINK.as_bytes() || b == stamp.as_bytes() {
            continue;
        }
        let Some(st) = lstat_at(&dir, &name)? else {
            continue;
        };
        if is_link(&st) && !b.starts_with(b"..") && !tops.contains(&name) {
            if let Some(t) = readlink_at(&dir, &name)? {
                if t.starts_with(b"..data/") {
                    unlink_at(&dir, &name, 0)?;
                }
            }
        } else if is_dir(&st) && b.starts_with(b"..") {
            remove_dir_at(&dir, &name)?;
        }
    }
    // The bound is the new projection's again. What a workload wrote into a
    // writable projection past it keeps the room the swap had.
    if p.memory {
        let _ = memory_resize(&dir, p.bound);
    }
    Ok(())
}

/// What the projection's link for the top-level name `t` holds.
fn data_link_to(t: &CString) -> Vec<u8> {
    [DATA_LINK.as_bytes(), b"/", t.as_bytes()].concat()
}

/// Write every entry of `p` into the timestamp directory `stamp` in `dir`.
fn fill(dir: &OwnedFd, stamp: &CString, p: &Projection) -> Result<(), i32> {
    let root = open_beneath(dir, stamp)?.ok_or(-libc::ENOENT)?;
    set_dir(&root, p.group)?;
    for e in &p.entries {
        let Some((leaf, parents)) = e.path.split_last() else {
            return Err(errno::EINVAL);
        };
        let mut cur = open_beneath(dir, stamp)?.ok_or(-libc::ENOENT)?;
        for c in parents {
            let name = c_name(c)?;
            // SAFETY: `cur` is open, `name` NUL-terminated.
            let made = unsafe { libc::mkdirat(cur.as_raw_fd(), name.as_ptr(), 0o700) } == 0;
            if !made && last_errno() != -libc::EEXIST {
                return Err(last_errno());
            }
            let next = open_beneath(&cur, &name)?.ok_or(-libc::ENOENT)?;
            if made {
                set_dir(&next, p.group)?;
            }
            cur = next;
        }
        let name = c_name(leaf)?;
        // SAFETY: `cur` is open, `name` NUL-terminated.
        let fd = unsafe {
            libc::openat(
                cur.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(last_errno());
        }
        // SAFETY: a descriptor just returned by openat, owned by nobody else.
        let f = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut off = 0;
        while off < e.data.len() {
            // SAFETY: the slice is live for its length.
            let w = unsafe {
                libc::write(
                    f.as_raw_fd(),
                    e.data[off..].as_ptr().cast(),
                    e.data.len() - off,
                )
            };
            if w < 0 {
                let err = last_errno();
                if err == -libc::EINTR {
                    continue;
                }
                return Err(err);
            }
            off += w as usize;
        }
        // The group first: a change of owner clears set-id bits, and the
        // mode below is the last word.
        let mut mode = e.mode & 0o777;
        if let Some(g) = p.group {
            fchown_group(&f, g)?;
            mode |= 0o040;
        }
        if p.read_only {
            mode |= 0o440;
        }
        fchmod(&f, mode)?;
    }
    Ok(())
}

/// Check a `REMOVE_TREE` request; `Ok` is the removal itself.
fn check_remove_tree(arg: &[u8]) -> Result<Work, i32> {
    let mut rel = components(&resolve(arg)?);
    let leaf = rel.pop().ok_or(errno::EINVAL)?;
    let leaf = CString::new(leaf.as_bytes()).map_err(|_| errno::EINVAL)?;
    Ok(Box::new(move || match remove_tree(&rel, &leaf) {
        Ok(()) => 0,
        Err(e) => e,
    }))
}

fn remove_tree(rel: &[std::ffi::OsString], leaf: &CString) -> Result<(), i32> {
    let Some(parent) = walk(rel, false, 0)? else {
        return Ok(());
    };
    let Some(st) = lstat_at(&parent, leaf)? else {
        return Ok(());
    };
    if is_link(&st) {
        return Err(errno::EINVAL);
    }
    if !is_dir(&st) {
        return unlink_at(&parent, leaf, 0);
    }
    let target = fd_target(&parent)?.join(std::ffi::OsStr::from_bytes(leaf.as_bytes()));
    let Some(_claim) = TargetClaim::take(&target) else {
        return Err(-libc::EBUSY);
    };
    // Every mount inside is checked before anything is removed: one that
    // is not a projection's is a volume, and the tree stays whole.
    let mut mounts = host_mounts_under(&target)?;
    if mounts.iter().any(|m| !m.is_projection()) {
        return Err(-libc::EBUSY);
    }
    // Deepest first, the later of two stacked mounts first. Each is reached
    // from the held parent through no symlink and removed by its id, as
    // UMOUNT removes a volume, and only while it is a projection's.
    mounts.reverse();
    mounts.sort_by_key(|m| core::cmp::Reverse(m.path.components().count()));
    for m in &mounts {
        let inside = components(m.path.strip_prefix(&target).map_err(|_| errno::EINVAL)?);
        let Some((last, between)) = inside.split_last() else {
            umount_verified(&parent, leaf, &m.path, MountRow::is_projection)?;
            continue;
        };
        let Some(mut dir) = open_dir_at(parent.as_raw_fd(), leaf)? else {
            return Ok(());
        };
        let mut gone = false;
        for c in between {
            let name = CString::new(c.as_bytes()).map_err(|_| errno::EINVAL)?;
            match open_dir_at(dir.as_raw_fd(), &name)? {
                Some(next) => dir = next,
                None => {
                    gone = true;
                    break;
                }
            }
        }
        if !gone {
            let name = CString::new(last.as_bytes()).map_err(|_| errno::EINVAL)?;
            umount_verified(&dir, &name, &m.path, MountRow::is_projection)?;
        }
    }
    let dir = match open_dir_at(parent.as_raw_fd(), leaf)? {
        Some(d) => d,
        None => return Ok(()),
    };
    remove_contents(&dir)?;
    drop(dir);
    unlink_at(&parent, leaf, libc::AT_REMOVEDIR)
}

/// Check a `MKDIR_MODE` request; `Ok` is the work itself. The mode is the
/// permission bits alone: a setuid, setgid or sticky bit, or anything above
/// them, is `EINVAL`.
fn check_mkdir_mode(arg: &[u8]) -> Result<Work, i32> {
    let mut r = Rd { b: arg, p: 0 };
    let dir_len = r.u16()? as usize;
    let rel = components(&resolve(r.take(dir_len)?)?);
    let mode = u32::from(r.u16()?);
    if !r.done() || mode & !0o777 != 0 {
        return Err(errno::EINVAL);
    }
    Ok(Box::new(move || match mkdir_mode(&rel, mode) {
        Ok(()) => 0,
        Err(e) => e,
    }))
}

/// Make the directory `rel` below the mount root (its missing parents
/// 0755, the directory itself 0700 until it is given its mode) and set its
/// mode to exactly `mode` through the descriptor the walk opened — so the
/// umask plays no part, and no path is looked up again between the walk
/// and the change.
fn mkdir_mode(rel: &[std::ffi::OsString], mode: u32) -> Result<(), i32> {
    let dir = walk(rel, true, 0o700)?.ok_or(-libc::ENOENT)?;
    let target = fd_target(&dir)?;
    let Some(_claim) = TargetClaim::take(&target) else {
        return Err(-libc::EBUSY);
    };
    fchmod(&dir, mode)
}

/// A `GROUP_TREE` request, checked.
struct GroupTree {
    rel: Vec<std::ffi::OsString>,
    group: u32,
    on_mismatch: bool,
}

fn parse_group_tree(arg: &[u8]) -> Result<GroupTree, i32> {
    let mut r = Rd { b: arg, p: 0 };
    let dir_len = r.u16()? as usize;
    let rel = components(&resolve(r.take(dir_len)?)?);
    let group = r.u32()?;
    let policy = r.u8()?;
    if !r.done() || group == hm::NO_GROUP {
        return Err(errno::EINVAL);
    }
    let on_mismatch = match policy {
        hm::GT_ALWAYS => false,
        hm::GT_ON_ROOT_MISMATCH => true,
        _ => return Err(errno::EINVAL),
    };
    Ok(GroupTree {
        rel,
        group,
        on_mismatch,
    })
}

/// Check a `GROUP_TREE` request; `Ok` is the walk itself.
fn check_group_tree(arg: &[u8]) -> Result<Work, i32> {
    let g = parse_group_tree(arg)?;
    Ok(Box::new(move || match group_tree(&g) {
        Ok(()) => 0,
        Err(e) => e,
    }))
}

/// The bits `GROUP_TREE` adds: a directory's group read, write, search and
/// setgid; a file's group read and write.
const GT_DIR_BITS: u32 = 0o2070;
const GT_FILE_BITS: u32 = 0o060;

fn group_tree(g: &GroupTree) -> Result<(), i32> {
    let dir = walk(&g.rel, false, 0)?.ok_or(-libc::ENOENT)?;
    let target = fd_target(&dir)?;
    let Some(_claim) = TargetClaim::take(&target) else {
        return Err(-libc::EBUSY);
    };
    let st = fstat(&dir)?;
    if g.on_mismatch && st.st_gid == g.group && st.st_mode & GT_DIR_BITS == GT_DIR_BITS {
        return Ok(());
    }
    // Mounts inside are other volumes: left alone, bind mounts from this
    // very filesystem included (the device compare cannot see those).
    let inner: Vec<PathBuf> = host_mounts_under(&target)?
        .into_iter()
        .map(|m| m.path)
        .filter(|p| *p != target)
        .collect();
    fchown_group(&dir, g.group)?;
    fchmod(&dir, (st.st_mode & 0o7777) | GT_DIR_BITS)?;
    group_contents(&dir, &target, g.group, &inner)
}

fn group_contents(dir: &OwnedFd, at: &Path, group: u32, inner: &[PathBuf]) -> Result<(), i32> {
    for name in entries(dir)? {
        let path = at.join(std::ffi::OsStr::from_bytes(name.as_bytes()));
        if inner.contains(&path) {
            continue;
        }
        let Some(st) = lstat_at(dir, &name)? else {
            continue;
        };
        if is_link(&st) {
            // The link itself, never what it names.
            // SAFETY: `dir` is open, `name` NUL-terminated.
            let rc = unsafe {
                libc::fchownat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    u32::MAX,
                    group,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if rc != 0 {
                return Err(last_errno());
            }
        } else if is_dir(&st) {
            let sub = match open_beneath(dir, &name) {
                Ok(Some(sub)) => sub,
                Ok(None) => continue,
                // A mount point the table did not list by this path.
                Err(e) if e == -libc::EXDEV => continue,
                Err(e) => return Err(e),
            };
            let st = fstat(&sub)?;
            fchown_group(&sub, group)?;
            fchmod(&sub, (st.st_mode & 0o7777) | GT_DIR_BITS)?;
            group_contents(&sub, &path, group, inner)?;
        } else {
            // A path descriptor: nothing is opened for reading, a fifo
            // never blocks, and the file is the one just looked at.
            // SAFETY: `dir` is open, `name` NUL-terminated.
            let fd = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                let e = last_errno();
                if e == -libc::ENOENT {
                    continue;
                }
                return Err(e);
            }
            // SAFETY: a descriptor just returned by openat, owned by nobody else.
            let f = unsafe { OwnedFd::from_raw_fd(fd) };
            let st = fstat(&f)?;
            if st.st_dev != fstat(dir)?.st_dev {
                continue;
            }
            // SAFETY: an empty path with AT_EMPTY_PATH names `f` itself.
            if unsafe {
                libc::fchownat(
                    f.as_raw_fd(),
                    c"".as_ptr(),
                    u32::MAX,
                    group,
                    libc::AT_EMPTY_PATH,
                )
            } != 0
            {
                return Err(last_errno());
            }
            if st.st_mode & libc::S_IFMT == libc::S_IFREG {
                // A change of group clears set-id bits; re-read the mode.
                let st = fstat(&f)?;
                let p = CString::new(format!("/proc/self/fd/{}", f.as_raw_fd()))
                    .map_err(|_| errno::EINVAL)?;
                // SAFETY: a NUL-terminated path naming `f`'s file.
                let rc = unsafe {
                    libc::chmod(
                        p.as_ptr(),
                        ((st.st_mode & 0o7777) | GT_FILE_BITS) as libc::mode_t,
                    )
                };
                if rc != 0 {
                    return Err(last_errno());
                }
            }
        }
    }
    Ok(())
}
