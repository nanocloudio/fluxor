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
//! An unmount verifies the same walk, then unmounts the resolved path with
//! `UMOUNT_NOFOLLOW`; a party able to rewrite directories inside the root
//! between that walk and the call can still race it, which is why the root
//! must not be writable by untrusted users.

use crate::abi::platform::linux::host_mount as hm;
use crate::kernel::sys::errno;
use std::collections::HashSet;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

const DEFAULT_ROOT: &str = "/var/lib/fluxor/mounts";
/// Bit of `CAP_SYS_ADMIN` in a capability set.
const CAP_SYS_ADMIN: u32 = 21;
/// Mounts and unmounts running or answered and not yet collected, over all
/// callers.
pub const MAX_JOBS: usize = 16;
/// The share of the table one caller may hold.
pub const MAX_JOBS_PER_CALLER: usize = 4;
/// How long a finished job's answer waits to be collected.
pub const RESULT_TTL: Duration = Duration::from_secs(30);

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

/// Whether this process holds `CAP_SYS_ADMIN` in its effective set.
fn may_mount() -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
        .is_some_and(|caps| caps & (1u64 << CAP_SYS_ADMIN) != 0)
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
/// (mode 0777 under the umask; `leaf_mode` for the last). `Ok(None)` is a
/// component that does not exist.
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
            let mode = if i + 1 == rel.len() { leaf_mode } else { 0o777 };
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

/// Check an `UMOUNT` request; `Ok` is the unmount itself. Nothing mounted
/// there (or no such directory) is the answer 0.
fn check_umount(arg: &[u8]) -> Result<Work, i32> {
    let mut rel = components(&resolve(arg)?);
    let leaf = rel.pop().ok_or(errno::EINVAL)?;
    let leaf = CString::new(leaf.as_bytes()).map_err(|_| errno::EINVAL)?;
    Ok(Box::new(move || {
        // The parent is held open, not the target: an open descriptor on the
        // mounted filesystem would itself make the unmount `EBUSY`.
        let parent = match walk(&rel, false, 0) {
            Ok(Some(fd)) => fd,
            Ok(None) => return 0,
            Err(e) => return e,
        };
        // Refuses a symlink leaf; releases the descriptor at once.
        match open_dir_at(parent.as_raw_fd(), &leaf) {
            Ok(Some(_)) => {}
            Ok(None) => return 0,
            Err(e) => return e,
        }
        let target = match fd_target(&parent) {
            Ok(p) => p.join(std::ffi::OsStr::from_bytes(leaf.as_bytes())),
            Err(e) => return e,
        };
        let Some(_claim) = TargetClaim::take(&target) else {
            return -libc::EBUSY;
        };
        if mounted_at(&target).is_none() {
            return 0;
        }
        let Ok(dst) = cstr(&target) else {
            return errno::EINVAL;
        };
        // SAFETY: a NUL-terminated string owned by this closure.
        if unsafe { libc::umount2(dst.as_ptr(), libc::UMOUNT_NOFOLLOW) } != 0 {
            last_errno()
        } else {
            1
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
        hm::PRIV => i32::from(may_mount()),
        hm::MOUNT => run_off_thread(hm::MOUNT, bytes, || check_mount(bytes)),
        hm::UMOUNT => run_off_thread(hm::UMOUNT, bytes, || check_umount(bytes)),
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
