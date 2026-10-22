// ============================================================================
// Linux host-process backend for the `workload` contract (class 0x1A)
// ============================================================================
//
// The namespace/cgroup isolation MECHANISM behind the `workload` host-process
// backend — not a consumer-facing surface. The `workload` provider
// (`workload.rs`) admits and owner/lease-binds a workload, then drives the
// primitives here: `hp_spawn` (fork + staged unshare, `/` made private, rootfs
// bind-onto-self, pivot_root with MS_MOVE fallback, a create/start barrier, and
// a non-blocking stdout/stderr drain), and `hp_start` / `hp_read` /
// `hp_signal` / `hp_wait` / `hp_destroy`. This backend is owner-agnostic; the
// owner↔handle↔slot mapping lives in the provider.
//
// Namespaces: MOUNT+UTS+IPC via a single unshare in the forked child, plus a
// PID-ns double-fork so the container is PID 1. A **null sandbox** (the caller's
// `isolate` param is false) skips unshare entirely — PROC semantics, the
// unprivileged path; a namespaced spawn needs CAP_SYS_ADMIN, and one the host
// refuses fails CREATE with the kernel's errno. No seccomp filter or
// capability bound is applied, which is why the provider advertises
// SHARED/ISOLATED but not HARDENED (fail-closed).
//
// Network: when the workload spec asks for its own network domain
// (`NET_ISO_OWN` on any endpoint), NEWNET joins the unshare set (orthogonal to
// `isolate` — a null sandbox can have its own netns too), and the sibling
// `net_identity` module realizes the Tier-1 network fields (lo up; veth +
// identity address when one is assigned) before START releases the barrier.
//
// Spawn inputs are EXPLICIT parameters, never an on-disk bundle/OCI format —
// this backend is a generic isolation primitive. `build_plan` takes:
//   argv     command + args (required, non-empty)
//   rootfs   container root to pivot into (optional)
//   isolate  unshare MOUNT|UTS|IPC|PID (needs CAP_SYS_ADMIN)
// and [`ProcessParams`] the process itself (`plan_process`):
//   env      the WHOLE environment, `NAME=VALUE` each. Nothing of the
//            runtime's own environment reaches a workload: the runtime holds
//            secrets in its (a node's seal key), and a workload is not it.
//            `HOME` is added when absent, as OCI runtimes do: the user's home
//            in the root's /etc/passwd, else `/`. A bare argv[0] is looked up
//            on the env's own `PATH` (or a default search path when it has
//            none — never the runtime's), in the root the process runs in
//   cwd      where it starts, absolute, in its own view of the filesystem
//            (`/` when empty); created inside an isolated rootfs, as an OCI
//            runtime creates a missing working directory
//   user     who it runs as, the OCI spelling: `uid[:gid]`, or a name (and
//            group) resolved in the root's /etc/passwd and /etc/group — the
//            only files this backend reads, and only the workload's own: each
//            is opened beneath the root (a symlink in it resolves inside the
//            root, never out to the host's) and read only when it is a
//            regular file. A name the root does not have refuses the spawn
//            (ENOENT); the id 4294967295 (the kernel's "unchanged") is EINVAL.
//            Applied in the child with setgroups/setresgid/setresuid before
//            exec. Changing the uid needs CAP_SETUID and changing the gid or
//            the groups CAP_SETGID: a runtime without them REFUSES (EACCES)
//            an identity it cannot assume rather than run the workload as
//            itself — the same fail-closed rule as `isolate`
//   groups   numeric supplementary groups added to the user's; `strict`
//            keeps only the primary and these (no /etc/group membership).
//            Without CAP_SETGID they run only when the runtime already holds
//            them (strict: exactly that set) — refused (EACCES) otherwise
//   root_read_only  with `isolate`: the root mount is remounted read-only
//            in the child LAST — after the volumes, the fresh /proc and the
//            working directory — non-recursively, so every volume keeps its
//            own access
// Volumes ([`VolumeBind`], an isolated sandbox with a rootfs only) are bound
// in the child before the pivot, from descriptors: the source is opened
// without following a symlink at its last component (and below the mount
// root, `FLUXOR_MOUNT_ROOT`, where workloads write, through no symlink at
// all); the mount point is resolved inside the rootfs (`RESOLVE_IN_ROOT`, so
// an image's symlink can never point it at the host), each missing
// directory made there; the tree is cloned (`open_tree`), made read-only
// recursively when asked (`mount_setattr`), and moved onto the mount point
// (`move_mount`). Every mount lands in the sandbox's own private mount
// namespace and goes with it.
// Descriptors: every pipe is created close-on-exec, and each child (the
// workload, an EXEC, a TTY session) closes everything but the handful it
// needs (stdio, the start barrier, the pid relay) before exec, so a workload
// starts holding only what it was granted — never a runtime listener, store
// file or device. Its stdin is the host's `/dev/null`, opened before the
// pivot. Each child also starts from default signal dispositions and an
// empty signal mask, whatever the runtime's are.
// cgroup.v2 limits come from the portable `ResourceEnvelope` (mapped in
// `hp_spawn`), not from any file. The orchestrator owns the mapping from its
// container/OCI world to these parameters.
//
// A library module (`fluxor::platform::linux::host_backend`); the `workload`
// provider in the sibling module composes it, and the host test harness
// exercises it.

use std::ffi::CString;

// Terminal-state byte reported by `hp_wait`.
const HP_STATE_RUNNING: u8 = 0;
const HP_STATE_EXITED: u8 = 1;
const HP_STATE_SIGNALLED: u8 = 2;
// Live, not terminal: frozen via PAUSE.
const HP_STATE_PAUSED: u8 = 3;

/// The sandbox-index DOMAIN, not a table size. The table holds a sandbox
/// for every workload of the host-process backend, a finished one included
/// until it is destroyed: an orchestrator keeps a terminated workload's exit
/// status and logs for as long as the workload it belongs to exists. Each is
/// a workload with an owner of its own, so the table is sized at boot to the
/// plan's `sandboxes` ceiling, whose derived part is the owner table's
/// workload slots (`size_kernel_tables`): every workload owner has a sandbox
/// slot, and the reserve on top seats finished sandboxes, by default only as
/// far as this domain leaves room. What this bounds is what an index may be at all: the
/// workload provider's slot space below the graph backend's
/// (`workload::GRAPH_SLOT_BASE`), and the `fx<stem>w<idx>` link name, which
/// must fit IFNAMSIZ. A plan past it is refused at boot naming `sandboxes`.
pub const MAX_SANDBOXES: usize = 4096;
const _: () = assert!(
    MAX_SANDBOXES >= crate::kernel::workload::owner::MAX_OWNERS,
    "the sandbox domain must seat every owner"
);
// `fx` + stem + `w` + the largest index's digits fit a link name's 15.
const _: () = assert!(
    2 + super::instance::STEM_MAX + 1 + digits(MAX_SANDBOXES - 1) <= 15,
    "fx<stem>w<idx> must fit IFNAMSIZ for every sandbox index"
);

/// Decimal digits of `n`.
const fn digits(mut n: usize) -> usize {
    let mut d = 1;
    while n >= 10 {
        n /= 10;
        d += 1;
    }
    d
}

struct HpSlot {
    in_use: bool,
    /// The pid to waitpid for exit. In an isolated sandbox this is the
    /// intermediate (the PID-ns parent), whose exit relays the container init's
    /// status; in a null sandbox it is the container process itself.
    pid: i32,
    /// The container init's host pid — what SIGNAL/DESTROY target. Equals `pid`
    /// for a null sandbox; the grandchild (PID 1 in the new pid ns) when
    /// isolated. Signalling `pid` (the intermediate, blocked in waitpid) would
    /// not reach the container.
    container_pid: i32,
    /// Write end of the start-barrier pipe; the init blocks reading the read
    /// end until `HP_START` writes here. -1 once started.
    start_w: i32,
    /// Read end of the merged stdout/stderr pipe.
    out_r: i32,
    started: bool,
    /// Cached exit once WAIT observed it (so repeat WAITs are stable).
    reaped: bool,
    /// Whether CREATE unshared namespaces — HP_EXEC setns-joins them only then.
    isolated: bool,
    /// Whether CREATE created a cgroup for this sandbox — DESTROY rmdir's it.
    cgrouped: bool,
    /// Whether the container was actually moved into that cgroup — the PAUSE
    /// gate. `cgrouped` alone is not enough: an unprivileged run can create
    /// the dir yet fail the `cgroup.procs` move (the cgroup2 common-ancestor
    /// rule), and freezing an EMPTY cgroup would report success while the
    /// workload kept running — a lying PAUSE.
    contained: bool,
    /// Frozen via PAUSE (`cgroup.freeze` = 1). Live, not terminal; WAIT
    /// reports [`HP_STATE_PAUSED`] while set and the child has not exited.
    paused: bool,
    exit_state: u8,
    exit_code: i32,
    /// What a process of this workload is — its environment, where it
    /// starts, who it runs as: the spawn's, so an EXEC or a TTY session runs
    /// as the workload does and never as the runtime.
    proc: ProcCtx,
}

const HP_EMPTY: HpSlot = HpSlot {
    in_use: false,
    pid: -1,
    container_pid: -1,
    start_w: -1,
    out_r: -1,
    started: false,
    reaped: false,
    isolated: false,
    cgrouped: false,
    contained: false,
    paused: false,
    exit_state: HP_STATE_RUNNING,
    exit_code: 0,
    proc: PROC_EMPTY,
};

static mut LINUX_SANDBOXES: crate::kernel::mem::table::Table<HpSlot, MAX_SANDBOXES> = crate::boot_table!(
    MAX_SANDBOXES,
    HP_EMPTY,
    crate::abi::contracts::resource::POOL_SANDBOXES
);

/// Reserve the sandbox table's ceiling, `n` slots; slots are committed a
/// segment at a time as spawns need them.
///
/// # Safety
/// Graph-preparation context: no reference into the table is live.
pub unsafe fn size_sandboxes(n: usize) -> Result<(), crate::kernel::mem::table::TableError> {
    if n > MAX_SANDBOXES {
        return Err(crate::kernel::mem::table::TableError::Ceiling);
    }
    (*core::ptr::addr_of!(LINUX_SANDBOXES)).reserve(n)
}

/// Sandboxes the table may hold: its ceiling.
pub fn sandbox_capacity() -> usize {
    // SAFETY: a read of the table's bounds.
    unsafe { (*core::ptr::addr_of!(LINUX_SANDBOXES)).ceiling() }
}

/// Sandboxes held, finished ones awaiting destroy included.
pub fn sandboxes_in_use() -> usize {
    // SAFETY: platform-thread read.
    unsafe {
        (*core::ptr::addr_of!(LINUX_SANDBOXES))
            .iter()
            .filter(|s| s.in_use)
            .count()
    }
}

/// The first free slot of `table`, committing another segment when every
/// committed one is taken. `None` past the ceiling, counted against `pool`.
fn free_slot<T, const N: usize>(
    table: &crate::kernel::mem::table::Table<T, N>,
    in_use: impl Fn(&T) -> bool,
    pool: u16,
) -> Option<usize> {
    if let Some(i) = table.iter().position(|s| !in_use(s)) {
        return Some(i);
    }
    let next = table.len();
    if table.grow(next + 1).is_err() {
        crate::kernel::sys::resource_ledger::deny(pool);
        return None;
    }
    Some(next)
}

/// The prepared, fork-safe spawn plan — everything the post-fork child needs,
/// built entirely in the parent (no allocation happens in the child).
pub struct SpawnPlan {
    /// Owns the CStrings that `argv_ptrs` points into — must outlive the fork.
    /// Never read by name; kept alive so the raw pointers stay valid.
    #[allow(dead_code, reason = "owns the CStrings argv_ptrs points into")]
    argv: Vec<CString>,
    argv_ptrs: Vec<*const libc::c_char>,
    rootfs: Option<CString>,
    isolate: bool,
    /// Remount the root read-only, last, before the identity change.
    root_read_only: bool,
    /// Unshare NEWNET so the workload gets its own network domain
    /// (`workload` Tier-1 `NET_ISO_OWN`). Set by the caller from the spec;
    /// network isolation is contract intent.
    own_netns: bool,
    /// cgroup.v2 resource limits from the portable `ResourceEnvelope`, applied
    /// best-effort by the parent after the container pid is known. Verbatim
    /// interface-file values: bytes for `memory.max`, a count for `pids.max`,
    /// `"quota period"` for `cpu.max`. Absent → that controller is left
    /// unlimited.
    mem_max: Option<String>,
    pids_max: Option<String>,
    cpu_max: Option<String>,
    /// Bind mounts, resolved against the rootfs BEFORE the fork: the child
    /// only issues syscalls, it never allocates.
    binds: Vec<PlannedBind>,
    /// The process: its environment, cwd and credentials ([`plan_process`]).
    /// Empty until planned — a plan nobody gave an environment runs with
    /// none, never with the runtime's.
    proc: ProcCtx,
    /// `proc.envp` as the NULL-terminated pointer array execve takes.
    envp_ptrs: Vec<*const libc::c_char>,
}

/// The process of a workload, as it will be exec'd: built before the fork
/// (the child only reads it) and kept on the slot for EXEC and TTY sessions.
pub struct ProcCtx {
    /// The whole environment, `NAME=VALUE` each.
    envp: Vec<CString>,
    /// Where a bare argv[0] is looked up: the env's `PATH`, else
    /// [`DEFAULT_SEARCH_PATH`]. None until planned.
    search: Option<CString>,
    /// Where the process starts, as the child sees the filesystem.
    cwd: Option<CString>,
    /// The directories to create, outermost first, when `cwd` is missing
    /// inside an isolated rootfs (the workload's own; never on the host).
    cwd_dirs: Vec<CString>,
    /// Who it runs as; None = the runtime's own identity.
    cred: Option<Cred>,
}

const PROC_EMPTY: ProcCtx = ProcCtx {
    envp: Vec::new(),
    search: None,
    cwd: None,
    cwd_dirs: Vec::new(),
    cred: None,
};

impl ProcCtx {
    /// The environment as the NULL-terminated array execve takes; it borrows
    /// `envp`, so it is valid while this context is.
    fn envp_ptrs(&self) -> Vec<*const libc::c_char> {
        let mut v: Vec<*const libc::c_char> = self.envp.iter().map(|c| c.as_ptr()).collect();
        v.push(core::ptr::null());
        v
    }
}

/// The search path a bare argv[0] is looked up on when the workload's
/// environment names no `PATH` — the one container runtimes default to.
pub const DEFAULT_SEARCH_PATH: &str =
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// A workload's identity: the uid and gid it runs as, and its supplementary
/// groups (the primary first).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cred {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
}

/// The supplementary groups this process holds now.
fn held_groups() -> Vec<u32> {
    // SAFETY: a size query, then a buffer of that size.
    unsafe {
        let n = libc::getgroups(0, core::ptr::null_mut());
        if n <= 0 {
            return Vec::new();
        }
        let mut v = vec![0 as libc::gid_t; n as usize];
        let got = libc::getgroups(n, v.as_mut_ptr());
        v.truncate(got.max(0) as usize);
        v
    }
}

/// Capability bits (`capabilities(7)`).
const CAP_SETGID: u32 = 6;
const CAP_SETUID: u32 = 7;
const CAP_SYS_ADMIN: u32 = 21;

/// Whether this process holds capability `bit` in its effective set.
fn holds_cap(bit: u32) -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("CapEff:"))
                .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
        })
        .is_some_and(|caps| caps & (1u64 << bit) != 0)
}

/// host_process `CAPS`: what this runtime realizes of the source. A
/// read-only root needs the mount privilege (it is realized only in an
/// isolated sandbox, which needs it too); groups need the privilege to set
/// them.
pub fn hp_caps() -> u32 {
    use crate::abi::platform::linux::host_process::caps;
    let mut c = 0;
    if holds_cap(CAP_SYS_ADMIN) {
        c |= caps::ROOT_READ_ONLY;
    }
    if holds_cap(CAP_SETGID) {
        c |= caps::GROUPS | caps::GROUPS_STRICT;
    }
    c
}

/// The process half of a spawn (see the module header): the environment,
/// the working directory and the user, each as the orchestrator states it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcessParams {
    /// `NAME=VALUE` entries — the whole environment.
    pub env: Vec<String>,
    /// Absolute; empty is `/`.
    pub cwd: String,
    /// `uid[:gid]` or `name[:group]`; empty is the runtime's own identity.
    pub user: String,
    /// Numeric supplementary groups, added to the user's.
    pub groups: Vec<u32>,
    /// The primary gid and `groups` only: none from the root's group file
    /// (nor, for the runtime's own identity, the runtime's own).
    pub groups_strict: bool,
    /// The root is read-only (an isolated sandbox only).
    pub root_read_only: bool,
}

/// A user resolved against a root: who to run as (None = the runtime's own
/// identity, unchanged), and that user's home.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedUser {
    pub cred: Option<Cred>,
    pub home: String,
}

/// The largest user database this backend parses. A larger one is refused
/// whole (`E2BIG`), never read in part: a cut drops every entry past it and
/// can shorten the member list it falls in, so `alice` reads as `ali`.
pub const USER_DB_MAX: u64 = 4 << 20;

/// The bytes of `rel` (`etc/passwd`, `etc/group`) in the workload's root,
/// resolved inside it: `openat2` with `RESOLVE_IN_ROOT`, so `..` and an
/// absolute symlink stop at the root and the host's own file is never read
/// for the workload's. Only a regular file is read (a FIFO would block, a
/// device has no user database). Empty when there is none; `E2BIG` when it
/// holds more than [`USER_DB_MAX`] bytes and `EIO` when it cannot be read to
/// its end (the read's own errno), each with a log line, so resolution never rests on part of it.
fn read_in_root(root: &str, rel: &core::ffi::CStr) -> Result<Vec<u8>, i32> {
    use std::io::Read as _;
    use std::os::fd::{FromRawFd, OwnedFd};
    let Ok(root_c) = CString::new(root) else {
        return Ok(Vec::new());
    };
    // SAFETY: a NUL-terminated path; the descriptor is owned below.
    let rfd = unsafe {
        libc::open(
            root_c.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if rfd < 0 {
        return Ok(Vec::new());
    }
    // SAFETY: a descriptor just returned by open, owned by nobody else.
    let rfd = unsafe { OwnedFd::from_raw_fd(rfd) };
    let fd = openat2_raw(
        std::os::fd::AsRawFd::as_raw_fd(&rfd),
        rel.as_ptr(),
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC,
        libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_MAGICLINKS,
    );
    if fd < 0 {
        return Ok(Vec::new());
    }
    // SAFETY: a descriptor just returned by openat2, owned by nobody else.
    let file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    if !file.metadata().is_ok_and(|m| m.is_file()) {
        return Ok(Vec::new());
    }
    let what = rel.to_string_lossy();
    // One byte past the cap tells a database at the cap from one beyond it,
    // whatever its size claimed when it was opened.
    let mut bytes = Vec::new();
    if let Err(e) = file.take(USER_DB_MAX + 1).read_to_end(&mut bytes) {
        log::warn!("[host_process] {root}/{what} cannot be read ({e}); user resolution refused");
        return Err(-e.raw_os_error().unwrap_or(libc::EIO));
    }
    if bytes.len() as u64 > USER_DB_MAX {
        log::warn!(
            "[host_process] {root}/{what} is larger than {USER_DB_MAX} bytes; user resolution \
             refused rather than read in part"
        );
        return Err(crate::kernel::sys::errno::E2BIG);
    }
    Ok(bytes)
}

/// The lines of a user database that are UTF-8, split on `\n`. A line that
/// is not is skipped and counted, so one bad entry cannot empty the whole
/// database; the count is logged.
fn user_db_lines<'a>(root: &str, what: &str, bytes: &'a [u8]) -> Vec<&'a str> {
    let mut skipped = 0usize;
    let lines = bytes
        .split(|&b| b == b'\n')
        .filter_map(|l| match core::str::from_utf8(l) {
            Ok(s) => Some(s.strip_suffix('\r').unwrap_or(s)),
            Err(_) => {
                skipped += 1;
                None
            }
        })
        .collect();
    if skipped > 0 {
        log::warn!("[host_process] {root}/{what}: {skipped} line(s) that are not UTF-8 skipped");
    }
    lines
}

/// `openat2(dirfd, path, how)` with `flags` and `resolve`: the descriptor,
/// or the negative errno. The descriptor is always close-on-exec, whatever
/// `flags` says: nothing this runtime opens may reach a child it spawns.
/// Async-signal-safe (one system call on a stack `open_how`), so a forked
/// child may use it.
fn openat2_raw(dirfd: i32, path: *const libc::c_char, flags: i32, resolve: u64) -> i32 {
    // SAFETY: open_how is plain integers; all-zero is its empty value.
    let mut how: libc::open_how = unsafe { core::mem::zeroed() };
    how.flags = (flags | libc::O_CLOEXEC) as u64;
    how.resolve = resolve;
    // SAFETY: `how` is a live open_how of the size passed; the caller passes
    // a NUL-terminated path and an open (or AT_FDCWD) directory.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            path,
            &how as *const libc::open_how,
            core::mem::size_of::<libc::open_how>(),
        )
    };
    if rc < 0 {
        // SAFETY: errno of the call just made.
        -unsafe { *libc::__errno_location() }
    } else {
        rc as i32
    }
}

/// One `/etc/passwd` entry: name, uid, gid, home.
fn passwd_entries(root: &str) -> Result<Vec<(String, u32, u32, String)>, i32> {
    let bytes = read_in_root(root, c"etc/passwd")?;
    Ok(user_db_lines(root, "etc/passwd", &bytes)
        .into_iter()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 7 || l.starts_with('#') {
                return None;
            }
            Some((
                f[0].to_string(),
                f[2].parse().ok()?,
                f[3].parse().ok()?,
                f[5].to_string(),
            ))
        })
        .collect())
}

/// One `/etc/group` entry: name, gid, members.
fn group_entries(root: &str) -> Result<Vec<(String, u32, Vec<String>)>, i32> {
    let bytes = read_in_root(root, c"etc/group")?;
    Ok(user_db_lines(root, "etc/group", &bytes)
        .into_iter()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 4 || l.starts_with('#') {
                return None;
            }
            let members = f[3]
                .split(',')
                .filter(|m| !m.is_empty())
                .map(str::to_string)
                .collect();
            Some((f[0].to_string(), f[2].parse().ok()?, members))
        })
        .collect())
}

/// The id `setresuid`/`setresgid` read as "leave this one unchanged" (and
/// `setgroups` refuses): never an identity a workload can be given.
const UNCHANGED_ID: u32 = u32::MAX;

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Resolve an OCI user string against `root` (the workload's root: its
/// rootfs, or `/` for a workload without one). `uid` alone takes the gid of
/// that uid's passwd entry, or 0 when it has none (as OCI runtimes do); a
/// name must be in the root's passwd (`root` is uid 0 even without one), a
/// group name in its group file (ENOENT otherwise); a malformed one is
/// EINVAL, and so is the id 4294967295, which the id-setting calls read as
/// "leave unchanged" (from the string or from the root's databases).
/// Supplementary groups are the primary plus every group the user's name is
/// a member of. An empty user is the runtime's own identity (`cred: None`),
/// its home looked up by the runtime's uid. A user database larger than
/// [`USER_DB_MAX`] is E2BIG and one that cannot be read is the read's errno:
/// no identity is resolved from part of one.
pub fn resolve_user(user: &str, root: &str) -> Result<ResolvedUser, i32> {
    use crate::kernel::sys::errno;
    let pw = passwd_entries(root)?;
    if user.is_empty() {
        // SAFETY: geteuid has no preconditions.
        let me = unsafe { libc::geteuid() };
        let home = pw
            .iter()
            .find(|e| e.1 == me)
            .map(|e| e.3.clone())
            .unwrap_or_else(|| "/".into());
        return Ok(ResolvedUser { cred: None, home });
    }
    let (u, g) = match user.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (user, None),
    };
    if u.is_empty() || g.is_some_and(str::is_empty) {
        return Err(errno::EINVAL);
    }
    let entry = if all_digits(u) {
        let uid: u32 = u.parse().map_err(|_| errno::EINVAL)?;
        pw.iter()
            .find(|e| e.1 == uid)
            .cloned()
            .unwrap_or((String::new(), uid, 0, "/".into()))
    } else {
        match pw.iter().find(|e| e.0 == u) {
            Some(e) => e.clone(),
            // `root` is uid 0 in any root, with a user database or without
            // (a `FROM scratch` image saying `USER root`).
            None if u == "root" => ("root".into(), 0, 0, "/root".into()),
            None => return Err(errno::ENOENT),
        }
    };
    let groups_db = group_entries(root)?;
    let gid = match g {
        None => entry.2,
        Some(g) if all_digits(g) => g.parse().map_err(|_| errno::EINVAL)?,
        Some(g) => groups_db
            .iter()
            .find(|e| e.0 == g)
            .map(|e| e.1)
            .ok_or(errno::ENOENT)?,
    };
    if entry.1 == UNCHANGED_ID || gid == UNCHANGED_ID {
        return Err(errno::EINVAL);
    }
    let mut groups = vec![gid];
    if !entry.0.is_empty() {
        for (_, id, members) in groups_db.iter().filter(|e| e.1 != UNCHANGED_ID) {
            if members.contains(&entry.0) && !groups.contains(id) {
                groups.push(*id);
            }
        }
    }
    let home = if entry.3.is_empty() {
        "/".into()
    } else {
        entry.3.clone()
    };
    Ok(ResolvedUser {
        cred: Some(Cred {
            uid: entry.1,
            gid,
            groups,
        }),
        home,
    })
}

/// Plan the process half of a spawn into `plan`: the environment (with
/// `HOME` when it has none), the search path, the working directory as the
/// child will see it, and the identity. EINVAL for an entry that is not
/// `NAME=VALUE`, a relative cwd, one that could leave a non-isolated rootfs,
/// or the id 4294967295; ENOENT for a user the root does not have; E2BIG for
/// a user database larger than [`USER_DB_MAX`]; EACCES for an identity the
/// runtime cannot assume — another uid without CAP_SETUID, another gid or
/// other groups without CAP_SETGID.
pub fn plan_process(plan: &mut SpawnPlan, p: &ProcessParams) -> Result<(), i32> {
    use crate::kernel::sys::errno;
    let rootfs = plan
        .rootfs
        .as_ref()
        .map(|c| c.to_string_lossy().into_owned())
        .filter(|r| !r.is_empty());
    let root = rootfs.as_deref().unwrap_or("/");
    if p.root_read_only && !plan.isolate {
        return Err(errno::EINVAL);
    }
    plan.root_read_only = p.root_read_only;
    let resolved = resolve_user(&p.user, root)?;
    let mut cred = resolved.cred;
    // SAFETY: the id getters have no preconditions.
    let (euid, egid) = unsafe { (libc::geteuid(), libc::getegid()) };
    let explicit = !p.groups.is_empty() || p.groups_strict;
    if p.groups.contains(&UNCHANGED_ID) {
        return Err(errno::EINVAL);
    }
    if explicit {
        let mut c = cred.take().unwrap_or_else(|| Cred {
            uid: euid,
            gid: egid,
            groups: core::iter::once(egid).chain(held_groups()).collect(),
        });
        if p.groups_strict {
            c.groups = vec![c.gid];
        }
        for g in &p.groups {
            if !c.groups.contains(g) {
                c.groups.push(*g);
            }
        }
        cred = Some(c);
    }
    if let Some(c) = &cred {
        if c.uid != euid && !holds_cap(CAP_SETUID) {
            return Err(errno::EACCES);
        }
        if !holds_cap(CAP_SETGID) {
            // It cannot change its gid or its groups, so it runs as itself
            // or not at all: the gid must be its own and the groups it asks
            // for ones it already holds (strict: exactly those). Without any
            // asked for it keeps its own. A uid it could change with its
            // own groups kept would carry the runtime's groups: refused.
            let held: Vec<u32> = core::iter::once(egid).chain(held_groups()).collect();
            let ok = c.uid == euid
                && c.gid == egid
                && (!explicit
                    || if p.groups_strict {
                        held.iter().all(|g| c.groups.contains(g))
                            && c.groups.iter().all(|g| held.contains(g))
                    } else {
                        p.groups.iter().all(|g| held.contains(g))
                    });
            if !ok {
                return Err(errno::EACCES);
            }
            cred = None;
        }
    }
    let mut envp = Vec::with_capacity(p.env.len() + 1);
    let mut path = None;
    let mut has_home = false;
    for e in &p.env {
        let Some((name, value)) = e.split_once('=') else {
            return Err(errno::EINVAL);
        };
        if name.is_empty() {
            return Err(errno::EINVAL);
        }
        if name == "PATH" {
            path = Some(value.to_string());
        }
        has_home |= name == "HOME";
        envp.push(CString::new(e.as_str()).map_err(|_| errno::EINVAL)?);
    }
    if !has_home {
        envp.push(CString::new(format!("HOME={}", resolved.home)).map_err(|_| errno::EINVAL)?);
    }
    let search = path.unwrap_or_else(|| DEFAULT_SEARCH_PATH.to_string());
    let cwd = if p.cwd.is_empty() {
        "/"
    } else {
        p.cwd.as_str()
    };
    if !cwd.starts_with('/') {
        return Err(errno::EINVAL);
    }
    let mut cwd_dirs = Vec::new();
    let child_cwd = match (rootfs.as_deref(), plan.isolate) {
        // Pivoted: the path is the workload's own, created when missing.
        (Some(_), true) => {
            let mut acc = String::new();
            for seg in cwd.split('/').filter(|s| !s.is_empty()) {
                acc.push('/');
                acc.push_str(seg);
                cwd_dirs.push(CString::new(acc.clone()).map_err(|_| errno::EINVAL)?);
            }
            cwd.to_string()
        }
        // Not pivoted: the rootfs is only a directory, so the path is
        // joined under it and may not climb out of it.
        (Some(r), false) => {
            if cwd.split('/').any(|s| s == "..") {
                return Err(errno::EINVAL);
            }
            format!(
                "{}{}",
                r.trim_end_matches('/'),
                if cwd == "/" { "" } else { cwd }
            )
        }
        (None, _) => cwd.to_string(),
    };
    plan.proc = ProcCtx {
        envp,
        search: Some(CString::new(search).map_err(|_| errno::EINVAL)?),
        cwd: Some(CString::new(child_cwd).map_err(|_| errno::EINVAL)?),
        cwd_dirs,
        cred,
    };
    plan.envp_ptrs = plan.proc.envp_ptrs();
    Ok(())
}

/// A volume the workload sees at `dst` inside its root: the host path `src`
/// bind-mounted there (`workload` Tier-2 option `mount`/`bind`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VolumeBind {
    pub src: String,
    pub dst: String,
    pub ro: bool,
}

/// A bind, ready for the child, which only issues system calls with it: the
/// source as the child opens it, and the mount point below the rootfs.
pub struct PlannedBind {
    /// The host path of the source.
    src: CString,
    /// Set when the source lies below the mount root: the root, and the path
    /// beneath it, resolved through no symlink at all (workloads write
    /// there, and could plant one).
    src_beneath: Option<(CString, CString)>,
    /// One step per component of the mount point below the rootfs: the
    /// directory holding it (`.` for the rootfs itself) and its name.
    steps: Vec<(CString, CString)>,
    /// The mount point, relative to the rootfs.
    target: CString,
    /// The source is not a directory: the mount point is a file.
    file: bool,
    ro: bool,
}

/// Resolve `binds` against `rootfs`, with the source policy of the mount
/// root the host-mount provider serves ([`plan_binds_in`]).
pub fn plan_binds(rootfs: Option<&str>, binds: &[VolumeBind]) -> Result<Vec<PlannedBind>, i32> {
    plan_binds_in(rootfs, binds, super::host_mount::mount_root())
}

/// Resolve `binds` against `rootfs`. Refuses (EINVAL) a relative path, a `..`
/// segment, a mount point of `/`, or a bind without a rootfs to bind into — a
/// volume that would land somewhere other than inside the workload's own root
/// is not a volume. The source is opened as the child will open it, so a
/// source the child would refuse fails here with its errno: ENOENT when it is
/// missing, EINVAL when its last component is a symlink or, below
/// `mount_root`, any component is.
pub fn plan_binds_in(
    rootfs: Option<&str>,
    binds: &[VolumeBind],
    mount_root: &std::path::Path,
) -> Result<Vec<PlannedBind>, i32> {
    use crate::kernel::sys::errno;
    use std::os::unix::ffi::OsStrExt;
    if binds.is_empty() {
        return Ok(Vec::new());
    }
    if rootfs.is_none_or(str::is_empty) {
        return Err(errno::EINVAL);
    }
    let clean = |p: &str| p.starts_with('/') && !p.split('/').any(|s| s == "..");
    let cstr = |b: &[u8]| CString::new(b).map_err(|_| errno::EINVAL);
    let mut out = Vec::new();
    for b in binds {
        let segs: Vec<&str> = b
            .dst
            .split('/')
            .filter(|s| !s.is_empty() && *s != ".")
            .collect();
        if !clean(&b.src) || !clean(&b.dst) || segs.is_empty() {
            return Err(errno::EINVAL);
        }
        let src_beneath = match std::path::Path::new(&b.src).strip_prefix(mount_root) {
            Ok(rel) if !mount_root.as_os_str().is_empty() => {
                let rel = rel.as_os_str().as_bytes();
                Some((
                    cstr(mount_root.as_os_str().as_bytes())?,
                    cstr(if rel.is_empty() { b"." } else { rel })?,
                ))
            }
            _ => None,
        };
        let src = cstr(b.src.as_bytes())?;
        // SAFETY: NUL-terminated strings owned here.
        let fd = unsafe { open_bind_source(&src, src_beneath.as_ref()) };
        if fd < 0 {
            return Err(fd);
        }
        // SAFETY: a descriptor just opened, closed once read.
        let file = unsafe {
            let mut st: libc::stat = core::mem::zeroed();
            let ok = libc::fstat(fd, &mut st) == 0;
            libc::close(fd);
            if !ok {
                return Err(errno::ERROR);
            }
            st.st_mode & libc::S_IFMT != libc::S_IFDIR
        };
        let mut steps = Vec::with_capacity(segs.len());
        let mut parent = String::from(".");
        for s in &segs {
            steps.push((cstr(parent.as_bytes())?, cstr(s.as_bytes())?));
            parent.push('/');
            parent.push_str(s);
        }
        out.push(PlannedBind {
            src,
            src_beneath,
            steps,
            target: cstr(parent.as_bytes())?,
            file,
            ro: b.ro,
        });
    }
    Ok(out)
}

/// Open a bind's source as an `O_PATH` descriptor: below the mount root
/// through no symlink at all (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`),
/// elsewhere without following a symlink at the last component. Returns the
/// descriptor, or a negative errno (ENOENT; EINVAL for a symlink).
/// Async-signal-safe.
///
/// # Safety
/// The strings are NUL-terminated.
unsafe fn open_bind_source(src: &core::ffi::CStr, beneath: Option<&(CString, CString)>) -> i32 {
    use crate::kernel::sys::errno;
    let flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let fd = match beneath {
        Some((root, rel)) => {
            let rfd = libc::open(
                root.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            );
            if rfd < 0 {
                return -*libc::__errno_location();
            }
            let fd = openat2_raw(
                rfd,
                rel.as_ptr(),
                flags,
                libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS,
            );
            libc::close(rfd);
            fd
        }
        None => openat2_raw(
            libc::AT_FDCWD,
            src.as_ptr(),
            flags,
            libc::RESOLVE_NO_MAGICLINKS,
        ),
    };
    if fd == -libc::ELOOP {
        return errno::EINVAL;
    }
    if fd < 0 {
        return fd;
    }
    // `O_PATH | O_NOFOLLOW` opens a symlink itself rather than failing.
    let mut st: libc::stat = core::mem::zeroed();
    if libc::fstat(fd, &mut st) == 0 && st.st_mode & libc::S_IFMT != libc::S_IFLNK {
        return fd;
    }
    libc::close(fd);
    errno::EINVAL
}

/// Build the fork-safe plan from explicit spawn parameters. The caller (the
/// `workload` provider) supplies argv, an optional rootfs path, and the isolate
/// flag directly — this backend is a generic isolation primitive and does not
/// know any bundle/OCI on-disk format. cgroup limits arrive separately via the
/// `ResourceEnvelope` and are filled in by [`hp_spawn`].
pub fn build_plan(
    argv_tokens: &[&str],
    rootfs: Option<&str>,
    isolate: bool,
) -> Result<SpawnPlan, i32> {
    let mut argv: Vec<CString> = Vec::new();
    for tok in argv_tokens {
        argv.push(CString::new(*tok).map_err(|_| crate::kernel::sys::errno::EINVAL)?);
    }
    if argv.is_empty() {
        return Err(crate::kernel::sys::errno::EINVAL);
    }
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(core::ptr::null());

    let rootfs = rootfs
        .filter(|p| !p.is_empty())
        .map(|p| CString::new(p).map_err(|_| crate::kernel::sys::errno::EINVAL))
        .transpose()?;

    Ok(SpawnPlan {
        argv,
        argv_ptrs,
        rootfs,
        isolate,
        root_read_only: false,
        own_netns: false,
        binds: Vec::new(),
        mem_max: None,
        pids_max: None,
        cpu_max: None,
        proc: PROC_EMPTY,
        envp_ptrs: vec![core::ptr::null()],
    })
}

/// The cgroup.v2 interface-file writes for a sandbox's resource limits. Pure
/// (no I/O) so the limit→file mapping is unit-testable without root or a
/// cgroup mount. Only present limits produce a write.
pub fn cgroup_writes(plan: &SpawnPlan) -> Vec<(&'static str, &str)> {
    let mut w = Vec::new();
    if let Some(m) = plan.mem_max.as_deref() {
        w.push(("memory.max", m));
    }
    if let Some(p) = plan.pids_max.as_deref() {
        w.push(("pids.max", p));
    }
    if let Some(c) = plan.cpu_max.as_deref() {
        w.push(("cpu.max", c));
    }
    w
}

/// Portable Tier-1 resource intents from the `workload` header (0 = unset).
/// Named for the intent, never the cgroup file — the mapping to cgroup.v2 lives
/// in `envelope_cgroup_values`.
#[derive(Clone, Copy)]
pub struct ResourceEnvelope {
    /// Milli core-equivalents (500 = half a core). Maps to `cpu.max`.
    pub compute_milli: u32,
    /// Memory quota in bytes. Maps to `memory.max`.
    pub memory_bytes: u64,
    /// Max concurrent tasks. Maps to `pids.max`.
    pub max_tasks: u32,
}

impl ResourceEnvelope {
    /// No limits — every field 0. The `workload` provider always builds a real
    /// envelope from the spec header; this one is for direct callers.
    pub const UNSET: ResourceEnvelope = ResourceEnvelope {
        compute_milli: 0,
        memory_bytes: 0,
        max_tasks: 0,
    };
}

/// Map the portable envelope to cgroup.v2 interface-file values
/// `(memory.max, pids.max, cpu.max)`; `None` where the intent is unset. Pure so
/// the intent→file translation is unit-testable without root. `cpu.max` uses a
/// fixed 100 ms period: quota = compute_milli * period / 1000 = compute_milli *
/// 100, so 1000 milli (one core) → `"100000 100000"`.
pub fn envelope_cgroup_values(
    env: &ResourceEnvelope,
) -> (Option<String>, Option<String>, Option<String>) {
    let mem = (env.memory_bytes > 0).then(|| env.memory_bytes.to_string());
    let pids = (env.max_tasks > 0).then(|| env.max_tasks.to_string());
    let cpu = (env.compute_milli > 0).then(|| format!("{} 100000", env.compute_milli as u64 * 100));
    (mem, pids, cpu)
}

/// The base cgroup directory under which per-sandbox cgroups are created:
/// `FLUXOR_HOST_CGROUP_ROOT` if set, else the runtime's own cgroup (from
/// `/proc/self/cgroup`) beneath the cgroup2 mount. None if it can't be resolved.
pub fn cgroup_base() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("FLUXOR_HOST_CGROUP_ROOT") {
        return Some(std::path::PathBuf::from(p));
    }
    let content = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    // Unified hierarchy line: "0::/user.slice/...".
    let rel = content.lines().find_map(|l| l.strip_prefix("0::"))?;
    Some(std::path::PathBuf::from("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
}

/// Best-effort: create the sandbox's cgroup, enable the controllers, write the
/// limits, and move the container into it. Returns `(created, contained)`:
/// `created` iff the cgroup dir was created (so DESTROY should rmdir it),
/// `contained` iff the container was actually moved into it (the freezer
/// gate — see `HpSlot::contained`). NEVER fatal — a container runs
/// unlimited if the cgroup fs is unavailable/undelegated (every step ignores
/// its error). Enforcement therefore depends on the runtime's cgroup being
/// delegated with the cpu/memory/pids controllers available.
fn hp_apply_cgroup(idx: usize, container_pid: i32, plan: &SpawnPlan) -> (bool, bool) {
    let writes = cgroup_writes(plan);
    if writes.is_empty() {
        return (false, false);
    }
    let Some(base) = cgroup_base() else {
        return (false, false);
    };
    // Make the controllers available to child cgroups. Enable each ONE AT A
    // TIME: a single `"+memory +pids +cpu"` write is rejected atomically when
    // any one controller is unavailable (e.g. the memory controller is off by
    // default on Raspberry Pi OS), which would silently drop the cpu/pids
    // limits too. Per-controller writes degrade gracefully — an unavailable
    // controller's limit is skipped, the others still apply. (Best-effort;
    // also fails with EBUSY on an internal-process parent.)
    let subtree = base.join("cgroup.subtree_control");
    for ctl in ["+memory", "+pids", "+cpu"] {
        let _ = std::fs::write(&subtree, ctl.as_bytes());
    }
    let dir = base.join(format!("fluxor.hostproc.{idx}"));
    if std::fs::create_dir_all(&dir).is_err() {
        return (false, false);
    }
    for (file, value) in writes {
        let _ = std::fs::write(dir.join(file), value.as_bytes());
    }
    // Move the container into the cgroup (host pid; cgroups are orthogonal to
    // the pid namespace). This is the step an unprivileged run typically
    // fails (cgroup2 requires write access on the source/destination COMMON
    // ANCESTOR's cgroup.procs) — track it so PAUSE never freezes an empty
    // cgroup.
    let procs = dir.join("cgroup.procs");
    let pid_bytes = container_pid.to_string();
    let mut contained = std::fs::write(&procs, pid_bytes.as_bytes()).is_ok();
    if !contained {
        // Under a THREADED ROOT base (one of its children was made threaded),
        // a fresh child is "domain invalid" and refuses processes (EOPNOTSUPP).
        // Switching the child to threaded makes it a valid member; threaded
        // cgroups still freeze (cgroup.freeze is core surface), only domain
        // controllers (memory) stop applying — consistent with best-effort.
        if std::fs::write(dir.join("cgroup.type"), b"threaded").is_ok() {
            contained = std::fs::write(&procs, pid_bytes.as_bytes()).is_ok();
        }
    }
    (true, contained)
}

/// Write a sandbox cgroup's `cgroup.freeze` ("1" freeze / "0" thaw). True on
/// success. The freezer is core cgroup2 surface (present on every v2 cgroup
/// since Linux 5.2), not a controller — no subtree_control dance needed.
fn hp_freeze_write(idx: usize, freeze: bool) -> bool {
    let Some(base) = cgroup_base() else {
        return false;
    };
    std::fs::write(
        base.join(format!("fluxor.hostproc.{idx}"))
            .join("cgroup.freeze"),
        if freeze { b"1".as_slice() } else { b"0" },
    )
    .is_ok()
}

/// Remove a sandbox's cgroup (once the container has exited so cgroup.procs is
/// empty and rmdir can succeed). Best-effort.
fn hp_remove_cgroup(idx: usize) {
    if let Some(base) = cgroup_base() {
        let _ = std::fs::remove_dir(base.join(format!("fluxor.hostproc.{idx}")));
    }
}

/// Write `-errno` (the calling child's last error) up the pid relay, so the
/// parent answers CREATE with it, then exit with `code`. Async-signal-safe.
unsafe fn relay_errno_and_exit(pid_w: i32, code: i32) -> ! {
    let e = -*libc::__errno_location();
    let b = e.to_ne_bytes();
    libc::write(pid_w, b.as_ptr() as *const libc::c_void, 4);
    libc::_exit(code);
}

/// The intermediate child — runs after the provider's fork. MUST be
/// async-signal-safe: only libc calls against pointers prepared in the parent,
/// no allocation. For an isolated sandbox it unshares the namespaces (NEWPID
/// affects its children, so the grandchild it forks is PID 1 in the new pid ns),
/// forks the container init, relays that init's host pid up `pid_w`, and relays
/// its exit status as its own exit code. For a null sandbox it *is* the
/// container and execs directly, closing `pid_w` once its own network domain
/// (if any) is in place. A namespace the host refuses is relayed up `pid_w`
/// as `-errno`, and CREATE answers it; any later failure `_exit`s a distinct
/// code so the parent's WAIT surfaces it.
unsafe fn hp_child(plan: &SpawnPlan, start_r: i32, out_w: i32, pid_w: i32) -> ! {
    // Everything the runtime holds goes, but what this child needs: stdio
    // (replaced below), the barrier, the out pipe and the pid relay.
    close_all_but(&[
        libc::STDIN_FILENO,
        libc::STDOUT_FILENO,
        libc::STDERR_FILENO,
        start_r,
        out_w,
        pid_w,
    ]);
    if !plan.isolate {
        // Null sandbox: this process is the container, and the provider
        // already knows its pid. Own-netns is orthogonal to isolate: unshare
        // just the network domain when the spec asks.
        if plan.own_netns && libc::unshare(libc::CLONE_NEWNET) != 0 {
            relay_errno_and_exit(pid_w, 121);
        }
        libc::close(pid_w);
        hp_container_body(plan, start_r, out_w);
    }

    // The intermediate lives exactly as long as the container init, whose
    // status it relays: a stop request meant for the runtime (a terminal's
    // Ctrl-C reaches its whole process group) is not one for it.
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
        libc::signal(sig, libc::SIG_IGN);
    }
    // Isolated sandbox (privileged). Unshare PID + MOUNT|UTS|IPC (+ NET when
    // the spec asks for an own network domain). NEWPID takes effect for our
    // children, so the grandchild we fork becomes PID 1 in the new pid
    // namespace; MOUNT|UTS|IPC (and the netns) apply to us and are inherited
    // by it.
    let mut ns_mask =
        libc::CLONE_NEWPID | libc::CLONE_NEWNS | libc::CLONE_NEWUTS | libc::CLONE_NEWIPC;
    if plan.own_netns {
        ns_mask |= libc::CLONE_NEWNET;
    }
    if libc::unshare(ns_mask) != 0 {
        relay_errno_and_exit(pid_w, 125);
    }
    let init = libc::fork();
    if init < 0 {
        relay_errno_and_exit(pid_w, 120);
    }
    if init == 0 {
        // Grandchild = container init (PID 1). It does the mount surgery (so
        // /proc reflects the new pid namespace) and execs.
        libc::close(pid_w);
        hp_container_body(plan, start_r, out_w);
    }
    // Intermediate: relay the container init's host pid up to the provider, then
    // relay its exit status as our own exit code.
    let pb = init.to_ne_bytes();
    libc::write(pid_w, pb.as_ptr() as *const libc::c_void, 4);
    libc::close(pid_w);
    libc::close(start_r); // the grandchild holds its own copy for the barrier
    libc::close(out_w); // only the grandchild should hold the stdout write end
    let mut status: libc::c_int = 0;
    loop {
        let r = libc::waitpid(init, &mut status, 0);
        if r == init {
            break;
        }
        if r < 0 && *libc::__errno_location() == libc::EINTR {
            continue;
        }
        libc::_exit(119);
    }
    if libc::WIFEXITED(status) {
        libc::_exit(libc::WEXITSTATUS(status));
    }
    if libc::WIFSIGNALED(status) {
        libc::_exit(128 + libc::WTERMSIG(status));
    }
    libc::_exit(118);
}

/// Every signal back to its default disposition and none blocked: a child
/// starts from what a fresh process has, not from the runtime's state (it
/// ignores SIGPIPE, and an ignored signal stays ignored across exec).
/// Async-signal-safe.
unsafe fn reset_signals() {
    let mut sa: libc::sigaction = core::mem::zeroed();
    sa.sa_sigaction = libc::SIG_DFL;
    libc::sigemptyset(&mut sa.sa_mask);
    // Linux numbers signals 1..=64 (SIGKILL and SIGSTOP refuse; harmless).
    for sig in 1..=64 {
        libc::sigaction(sig, &sa, core::ptr::null_mut());
    }
    let mut none: libc::sigset_t = core::mem::zeroed();
    libc::sigemptyset(&mut none);
    libc::sigprocmask(libc::SIG_SETMASK, &none, core::ptr::null_mut());
}

/// Point stdin at the host's `/dev/null` and stdout and stderr at `out_w`
/// (closed after). False when `/dev/null` cannot be opened: the child must
/// then not run, since its stdin would still be the runtime's.
/// Async-signal-safe.
unsafe fn wire_stdio(out_w: i32) -> bool {
    let nfd = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
    if nfd < 0 || libc::dup2(nfd, libc::STDIN_FILENO) < 0 {
        return false;
    }
    if nfd > 2 {
        libc::close(nfd);
    }
    if libc::dup2(out_w, libc::STDOUT_FILENO) < 0 || libc::dup2(out_w, libc::STDERR_FILENO) < 0 {
        return false;
    }
    if out_w > 2 {
        libc::close(out_w);
    }
    true
}

/// The container-process body — stdio, mounts (isolated), the create/start
/// barrier, the working directory, the identity, then exec. Runs as the
/// container init (grandchild) in an isolated sandbox, or as the direct child
/// in a null sandbox; its namespaces are already unshared by the caller in
/// the isolated case.
unsafe fn hp_container_body(plan: &SpawnPlan, start_r: i32, out_w: i32) -> ! {
    // Become a process-group leader so SIGNAL/DESTROY can deliver to the
    // whole group (`kill(-pgid)`) and children of the container init hear a
    // SIGTERM too. Fork inherits the parent's pgid, so the double-fork alone
    // does not make one. No controlling terminal to detach here (stdio is the
    // out pipe), so setpgid suffices; the TTY session path does its own
    // setsid.
    libc::setpgid(0, 0);
    reset_signals();
    // stdio first, while `/dev/null` is still the host's: a rootfs need not
    // have one, and one it has is the image's.
    if !wire_stdio(out_w) {
        libc::_exit(113);
    }
    if plan.isolate {
        // Make `/` a private recursive mount so our mount changes don't
        // propagate to the host — the first step, before any mount.
        let slash = c"/".as_ptr();
        let none = c"none".as_ptr();
        if libc::mount(
            none,
            slash,
            core::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            core::ptr::null(),
        ) != 0
        {
            libc::_exit(124);
        }
        if let Some(rootfs) = plan.rootfs.as_ref() {
            // Volumes, before the pivot: the host paths are only reachable
            // from here. The mount namespace is already private, so none of
            // this propagates back to the host.
            if !bind_volumes(rootfs, &plan.binds) {
                libc::_exit(121);
            }
            if hp_pivot_into(rootfs.as_ptr()) != 0 {
                libc::_exit(123);
            }
            // A fresh /proc — mounted here (in the new pid namespace) so it
            // reflects the container's pid view, with the init as PID 1.
            let proc_src = c"proc".as_ptr();
            let proc_dst = c"/proc".as_ptr();
            let proc_ty = c"proc".as_ptr();
            libc::mount(
                proc_src,
                proc_dst,
                proc_ty,
                libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV,
                core::ptr::null(),
            );
        }
    }
    // A null sandbox with a rootfs is not rooted in it (no mount namespace to
    // pivot in): it only STARTS there — `proc.cwd` is joined under it.

    // The create/start barrier: block until HP_START releases us.
    let mut b = [0u8; 1];
    loop {
        let n = libc::read(start_r, b.as_mut_ptr() as *mut libc::c_void, 1);
        if n == 1 {
            break;
        }
        if n < 0 && *libc::__errno_location() == libc::EINTR {
            continue;
        }
        // Parent closed the pipe without releasing (create aborted) → exit.
        libc::_exit(122);
    }
    libc::close(start_r);

    // Where it starts: missing inside an isolated rootfs, it is created
    // there (the workload's own filesystem) and entered again.
    let cwd = plan.proc.cwd.as_ref().map_or(c"/".as_ptr(), |c| c.as_ptr());
    if libc::chdir(cwd) != 0 {
        for d in &plan.proc.cwd_dirs {
            libc::mkdir(d.as_ptr(), 0o755);
        }
        if libc::chdir(cwd) != 0 {
            libc::_exit(116);
        }
    }
    // The root read-only, after everything that writes to it (the volume
    // mount points, /proc, the working directory) and before the identity
    // change takes the privilege.
    if plan.root_read_only && !remount_read_only(c"/") {
        libc::_exit(114);
    }
    // Who it runs as, last: the mounts and the cwd above may need the
    // runtime's privilege.
    if let Some(c) = plan.proc.cred.as_ref() {
        if !apply_cred(c) {
            libc::_exit(115);
        }
    }
    exec_with(&plan.argv_ptrs, &plan.envp_ptrs, &plan.proc);
}

/// `RESOLVE_*` for a path inside a workload's rootfs: `..` and absolute
/// symlinks stop at the root, and no `/proc` magic link leads out of it.
const IN_ROOT: u64 = libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_MAGICLINKS;

/// `move_mount(2)` flags (`<linux/mount.h>`): the source and the target are
/// the descriptors themselves.
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x0000_0004;
const MOVE_MOUNT_T_EMPTY_PATH: libc::c_uint = 0x0000_0040;

/// Bind every planned volume into `rootfs` (see the module header). False
/// on the first one that cannot be bound. Async-signal-safe.
unsafe fn bind_volumes(rootfs: &core::ffi::CStr, binds: &[PlannedBind]) -> bool {
    if binds.is_empty() {
        return true;
    }
    let rfd = libc::open(
        rootfs.as_ptr(),
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
    );
    if rfd < 0 {
        return false;
    }
    let ok = binds.iter().all(|b| bind_volume(rfd, b));
    libc::close(rfd);
    ok
}

/// Bind one volume: its source opened as planning opened it (and of the same
/// kind), its mount point made and resolved inside the rootfs `rfd`, the
/// source's tree cloned, made read-only when asked, and moved there.
/// Async-signal-safe.
unsafe fn bind_volume(rfd: i32, b: &PlannedBind) -> bool {
    let src = open_bind_source(&b.src, b.src_beneath.as_ref());
    if src < 0 {
        return false;
    }
    let mut st: libc::stat = core::mem::zeroed();
    let same_kind =
        libc::fstat(src, &mut st) == 0 && (st.st_mode & libc::S_IFMT == libc::S_IFDIR) != b.file;
    let dst = if same_kind { mount_point(rfd, b) } else { -1 };
    let ok = dst >= 0 && attach(src, dst, rfd, b);
    if dst >= 0 {
        libc::close(dst);
    }
    libc::close(src);
    ok
}

/// Make `b`'s mount point inside the rootfs `rfd` — every missing directory
/// on the way (mode 0755) and, for a file, an empty file — each step's
/// directory resolved inside the root, so no symlink of the image's places
/// any of it on the host. Returns an `O_PATH` descriptor of the mount point
/// (of the source's kind), or -1. Async-signal-safe.
unsafe fn mount_point(rfd: i32, b: &PlannedBind) -> i32 {
    let last = b.steps.len().saturating_sub(1);
    for (i, (parent, name)) in b.steps.iter().enumerate() {
        let pfd = openat2_raw(
            rfd,
            parent.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            IN_ROOT,
        );
        if pfd < 0 {
            return -1;
        }
        // Either call fails harmlessly on a name that exists (a symlink
        // included: neither follows one); the resolution below decides.
        if i < last || !b.file {
            libc::mkdirat(pfd, name.as_ptr(), 0o755);
        } else {
            let fd = libc::openat(
                pfd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o644,
            );
            if fd >= 0 {
                libc::close(fd);
            }
        }
        libc::close(pfd);
    }
    let dir = if b.file { 0 } else { libc::O_DIRECTORY };
    let dfd = openat2_raw(
        rfd,
        b.target.as_ptr(),
        libc::O_PATH | libc::O_CLOEXEC | dir,
        IN_ROOT,
    );
    if dfd < 0 {
        return -1;
    }
    let mut st: libc::stat = core::mem::zeroed();
    if b.file && (libc::fstat(dfd, &mut st) != 0 || st.st_mode & libc::S_IFMT == libc::S_IFDIR) {
        libc::close(dfd);
        return -1;
    }
    dfd
}

/// Clone the tree at `src` (recursively, as a bind does), make it read-only
/// throughout when `b.ro`, and move it onto the mount point `dst`.
/// Async-signal-safe.
unsafe fn attach(src: i32, dst: i32, rfd: i32, b: &PlannedBind) -> bool {
    let tree = libc::syscall(
        libc::SYS_open_tree,
        src,
        c"".as_ptr(),
        libc::OPEN_TREE_CLONE
            | libc::OPEN_TREE_CLOEXEC
            | libc::AT_RECURSIVE as libc::c_uint
            | libc::AT_EMPTY_PATH as libc::c_uint,
    ) as i32;
    if tree < 0 {
        return false;
    }
    // Read-only before it is reachable: every mount of the clone, so a
    // volume with mounts inside is read-only all the way down. A kernel
    // without `mount_setattr` (before 5.12) remounts the top mount once it
    // is in place instead.
    let mut remount = false;
    if b.ro {
        let attr = libc::mount_attr {
            attr_set: libc::MOUNT_ATTR_RDONLY,
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        };
        if libc::syscall(
            libc::SYS_mount_setattr,
            tree,
            c"".as_ptr(),
            (libc::AT_EMPTY_PATH | libc::AT_RECURSIVE) as libc::c_uint,
            &attr as *const libc::mount_attr,
            core::mem::size_of::<libc::mount_attr>(),
        ) != 0
        {
            if *libc::__errno_location() != libc::ENOSYS {
                libc::close(tree);
                return false;
            }
            remount = true;
        }
    }
    let moved = libc::syscall(
        libc::SYS_move_mount,
        tree,
        c"".as_ptr(),
        dst,
        c"".as_ptr(),
        MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
    ) == 0;
    libc::close(tree);
    if !moved {
        return false;
    }
    if !remount {
        return true;
    }
    // The mount point resolved again is the bound tree's top mount.
    let top = openat2_raw(
        rfd,
        b.target.as_ptr(),
        libc::O_PATH | libc::O_CLOEXEC,
        IN_ROOT,
    );
    if top < 0 {
        return false;
    }
    let mut path = [0u8; 32];
    let ok = fd_path(top, &mut path)
        && remount_read_only(core::ffi::CStr::from_ptr(path.as_ptr().cast()));
    libc::close(top);
    ok
}

/// `/proc/self/fd/<fd>` into `buf`, NUL-terminated. Async-signal-safe.
fn fd_path(fd: i32, buf: &mut [u8; 32]) -> bool {
    const PREFIX: &[u8] = b"/proc/self/fd/";
    if fd < 0 {
        return false;
    }
    buf[..PREFIX.len()].copy_from_slice(PREFIX);
    let mut digits = [0u8; 10];
    let mut n = fd as u32;
    let mut len = 0;
    loop {
        digits[len] = b'0' + (n % 10) as u8;
        len += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    for i in 0..len {
        buf[PREFIX.len() + i] = digits[len - 1 - i];
    }
    buf[PREFIX.len() + len] = 0;
    true
}

/// Remount the mount at `path` read-only: that mount alone (a bind remount
/// never recurses), so mounts beneath it keep their own access. A bind
/// remount replaces the mount's per-mount flags, so the ones it already
/// carries (`nosuid`, `nodev`, `noexec`, the atime policy) are read first
/// and kept — the remount only ever takes access away. Async-signal-safe.
unsafe fn remount_read_only(path: &core::ffi::CStr) -> bool {
    let Some(have) = mount_flags(path) else {
        return false;
    };
    let mut keep: libc::c_ulong = 0;
    for (st_bit, ms_bit) in [
        (libc::ST_NOSUID, libc::MS_NOSUID),
        (libc::ST_NODEV, libc::MS_NODEV),
        (libc::ST_NOEXEC, libc::MS_NOEXEC),
        (libc::ST_NOATIME, libc::MS_NOATIME),
        (libc::ST_NODIRATIME, libc::MS_NODIRATIME),
        (libc::ST_RELATIME, libc::MS_RELATIME),
    ] {
        if have & st_bit != 0 {
            keep |= ms_bit;
        }
    }
    libc::mount(
        core::ptr::null(),
        path.as_ptr(),
        core::ptr::null(),
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | keep,
        core::ptr::null(),
    ) == 0
}

/// The `ST_*` flags of the mount at `path`, by the raw `statfs` syscall (the
/// libc wrappers either hide the field or may fall back to reading the mount
/// table). On 64-bit Linux the kernel's `struct statfs` is fifteen 8-byte
/// words — type, bsize, blocks, bfree, bavail, files, ffree, fsid, namelen,
/// frsize, flags, four spare — so `flags` is word 10. Async-signal-safe.
#[cfg(target_pointer_width = "64")]
unsafe fn mount_flags(path: &core::ffi::CStr) -> Option<libc::c_ulong> {
    let mut w = [0u64; 15];
    if libc::syscall(libc::SYS_statfs, path.as_ptr(), w.as_mut_ptr()) != 0 {
        return None;
    }
    Some(w[10] as libc::c_ulong)
}

/// As above on a 32-bit host, through `statvfs` (a kernel that reports the
/// flags itself — every one since 2.6.36 — spares glibc reading any file).
#[cfg(not(target_pointer_width = "64"))]
unsafe fn mount_flags(path: &core::ffi::CStr) -> Option<libc::c_ulong> {
    let mut st: libc::statvfs = core::mem::zeroed();
    if libc::statvfs(path.as_ptr(), &mut st) != 0 {
        return None;
    }
    Some(st.f_flag as libc::c_ulong)
}

/// Close every descriptor of this process except `keep` (at most eight;
/// negatives ignored). For a forked child before exec: async-signal-safe —
/// the keep-set is sorted on the stack, the gaps between its members are
/// closed with `close_range`, and a kernel without it gets a raw `close`
/// loop up to the descriptor limit. Nothing is allocated and /proc is not
/// read.
unsafe fn close_all_but(keep: &[i32]) {
    let mut k = [0u32; 8];
    let mut n = 0;
    for &fd in keep {
        if fd >= 0 && n < k.len() {
            k[n] = fd as u32;
            n += 1;
        }
    }
    let mut i = 1;
    while i < n {
        let mut j = i;
        while j > 0 && k[j - 1] > k[j] {
            k.swap(j - 1, j);
            j -= 1;
        }
        i += 1;
    }
    let mut lo: u32 = 0;
    for &fd in k.iter().take(n) {
        if fd > lo {
            close_span(lo, fd - 1);
        }
        lo = lo.max(fd.saturating_add(1));
    }
    close_span(lo, u32::MAX);
}

/// Close descriptors `lo..=hi`: `close_range`, else a `close` loop bounded by
/// `RLIMIT_NOFILE` (a descriptor is always below the limit it was opened
/// under). Async-signal-safe.
unsafe fn close_span(lo: u32, hi: u32) {
    if libc::syscall(libc::SYS_close_range, lo, hi, 0u32) == 0 {
        return;
    }
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let limit = if libc::syscall(
        libc::SYS_prlimit64,
        0,
        libc::RLIMIT_NOFILE,
        core::ptr::null::<libc::rlimit>(),
        &mut rl as *mut libc::rlimit,
    ) == 0
    {
        // The kernel's own ceiling on any process's table (`fs.nr_open`'s
        // maximum) bounds an unlimited soft limit.
        rl.rlim_cur.min(1 << 30)
    } else {
        1 << 20
    };
    let end = (u64::from(hi) + 1).min(limit);
    let mut fd = u64::from(lo);
    while fd < end {
        libc::syscall(libc::SYS_close, fd as libc::c_long);
        fd += 1;
    }
}

/// Become `c`: supplementary groups, then gid, then uid (all three ids of
/// each, so nothing can be regained). Raw syscalls: they change this thread
/// only, which in a forked child is the process — glibc's wrappers would
/// try to broadcast to threads the child does not have. False on any
/// refusal.
unsafe fn apply_cred(c: &Cred) -> bool {
    libc::syscall(libc::SYS_setgroups, c.groups.len(), c.groups.as_ptr()) == 0
        && libc::syscall(libc::SYS_setresgid, c.gid, c.gid, c.gid) == 0
        && libc::syscall(libc::SYS_setresuid, c.uid, c.uid, c.uid) == 0
}

/// A process joining a live workload (EXEC, TTY): into its cwd (it stays at
/// the root it entered when that is gone), then its identity — a refused one
/// exits 115 rather than run as the runtime.
unsafe fn enter_as_workload(proc: &ProcCtx) {
    if let Some(c) = proc.cwd.as_ref() {
        libc::chdir(c.as_ptr());
    }
    if let Some(c) = proc.cred.as_ref() {
        if !apply_cred(c) {
            libc::_exit(115);
        }
    }
}

/// execve `argv` with exactly `envp` — never the runtime's environment. A
/// bare argv[0] is looked up on the workload's own search path, in its own
/// root, by execvp's rules (an empty entry is the cwd; a hit that is not
/// executable is remembered, the search goes on). Exits 127 when nothing
/// was found, 126 when something was but could not be run. Async-signal-
/// safe: the candidate path is built on the stack.
unsafe fn exec_with(
    argv: &[*const libc::c_char],
    envp: &[*const libc::c_char],
    proc: &ProcCtx,
) -> ! {
    let file = argv[0];
    let flen = libc::strlen(file);
    if flen == 0 {
        libc::_exit(127);
    }
    if !libc::strchr(file, b'/' as libc::c_int).is_null() {
        libc::execve(file, argv.as_ptr(), envp.as_ptr());
        let e = *libc::__errno_location();
        libc::_exit(if e == libc::ENOENT || e == libc::ENOTDIR {
            127
        } else {
            126
        });
    }
    // A plan given no environment still searches the default path, never
    // the runtime's.
    const DEFAULT: &core::ffi::CStr =
        c"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    let search = proc
        .search
        .as_deref()
        .unwrap_or(DEFAULT)
        .as_ptr()
        .cast::<u8>();
    let mut buf = [0u8; 4096];
    let mut found = false;
    let mut p = search;
    loop {
        let mut q = p;
        while *q != 0 && *q != b':' {
            q = q.add(1);
        }
        let seg = q.offset_from(p) as usize;
        let (dir, dlen) = if seg == 0 {
            (b".".as_ptr(), 1)
        } else {
            (p, seg)
        };
        if dlen + 1 + flen < buf.len() {
            core::ptr::copy_nonoverlapping(dir, buf.as_mut_ptr(), dlen);
            buf[dlen] = b'/';
            core::ptr::copy_nonoverlapping(file.cast::<u8>(), buf.as_mut_ptr().add(dlen + 1), flen);
            buf[dlen + 1 + flen] = 0;
            libc::execve(
                buf.as_ptr() as *const libc::c_char,
                argv.as_ptr(),
                envp.as_ptr(),
            );
            let e = *libc::__errno_location();
            if e != libc::ENOENT
                && e != libc::ENOTDIR
                && e != libc::ESTALE
                && e != libc::ELOOP
                && e != libc::ENAMETOOLONG
            {
                found = true;
            }
        }
        if *q == 0 {
            break;
        }
        p = q.add(1);
    }
    libc::_exit(if found { 126 } else { 127 });
}

/// pivot_root into `new_root` (a mount point): bind rootfs onto itself,
/// pivot, detach the old root, with an MS_MOVE fallback on EINVAL/EXDEV.
/// Returns 0 on success, -1 on failure.
unsafe fn hp_pivot_into(new_root: *const libc::c_char) -> i32 {
    let bind_flags = libc::MS_BIND | libc::MS_REC;
    if libc::mount(
        new_root,
        new_root,
        core::ptr::null(),
        bind_flags,
        core::ptr::null(),
    ) != 0
    {
        return -1;
    }
    if libc::chdir(new_root) != 0 {
        return -1;
    }
    // put_old = "." (the new root's cwd); pivot_root(".", ".") then detach.
    let dot = c".".as_ptr();
    let pivot_rc = libc::syscall(libc::SYS_pivot_root, dot, dot);
    if pivot_rc == 0 {
        // Detach the old root now stacked at "/".
        let slash = c"/".as_ptr();
        libc::umount2(slash, libc::MNT_DETACH);
        return 0;
    }
    // Fallback, for a root pivot_root refuses (one on the initial ramfs):
    // MS_MOVE the new root onto "/" then chroot into it.
    let slash = c"/".as_ptr();
    if libc::mount(
        dot,
        slash,
        core::ptr::null(),
        libc::MS_MOVE,
        core::ptr::null(),
    ) != 0
    {
        return -1;
    }
    if libc::chroot(dot) != 0 {
        return -1;
    }
    if libc::chdir(slash) != 0 {
        return -1;
    }
    0
}

/// Spawn a sandbox from explicit params (`argv`, optional `rootfs`, `isolate`):
/// fork the container onto the start barrier, apply cgroup limits, realize the
/// network domain, and record the slot. Returns the slot index (>= 0) or a
/// negative errno. The core of the `workload` host-process backend;
/// owner-binding is the caller's concern (the `workload` provider records it).
/// `env` carries the portable resource intents from a `workload` spec — the
/// sole source of cgroup limits (this backend reads no files). `own_netns` +
/// `ident` carry the Tier-1 network fields: with `own_netns` the container
/// gets its own netns (lo up); with `ident` also a veth pair carrying the
/// identity address (see `net_identity`). A network-realization failure fails
/// the spawn — Tier-1 fields are never silently dropped.
/// # Safety
/// Single-threaded platform dispatch only: mutates the process-global
/// sandbox slot table without synchronization, and forks — no other
/// thread may touch the table (or hold locks the child would inherit).
pub unsafe fn hp_spawn(
    argv_tokens: &[&str],
    rootfs: Option<&str>,
    isolate: bool,
    env: &ResourceEnvelope,
    own_netns: bool,
    ident: Option<&super::net_identity::NetIdentity>,
) -> i32 {
    hp_spawn_with_binds(
        argv_tokens,
        rootfs,
        isolate,
        env,
        own_netns,
        ident,
        &[],
        &ProcessParams::default(),
    )
}

/// [`hp_spawn`] with volumes and the process: each [`VolumeBind`] is
/// bind-mounted into the rootfs before the pivot, and the workload runs with
/// exactly `proc`'s environment, in its cwd, as its user ([`plan_process`]).
/// A bind needs an isolated sandbox with a rootfs (EINVAL otherwise) —
/// without its own mount namespace the mount would land on the host.
///
/// # Safety
/// As [`hp_spawn`].
#[allow(
    clippy::too_many_arguments,
    reason = "one spawn: the plan's parts as the provider parsed them"
)]
pub unsafe fn hp_spawn_with_binds(
    argv_tokens: &[&str],
    rootfs: Option<&str>,
    isolate: bool,
    env: &ResourceEnvelope,
    own_netns: bool,
    ident: Option<&super::net_identity::NetIdentity>,
    binds: &[VolumeBind],
    proc: &ProcessParams,
) -> i32 {
    use crate::kernel::sys::errno;

    let mut plan = match build_plan(argv_tokens, rootfs, isolate) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if let Err(e) = plan_process(&mut plan, proc) {
        return e;
    }
    if !binds.is_empty() && !isolate {
        return errno::EINVAL;
    }
    plan.binds = match plan_binds(rootfs, binds) {
        Ok(b) => b,
        Err(e) => return e,
    };
    plan.own_netns = own_netns;
    // cgroup limits come solely from the portable resource envelope (the
    // orchestrator's intent); this backend has no on-disk bundle to read.
    let (mem, pids, cpu) = envelope_cgroup_values(env);
    plan.mem_max = mem;
    plan.pids_max = pids;
    plan.cpu_max = cpu;

    let slots = &mut *core::ptr::addr_of_mut!(LINUX_SANDBOXES);
    let idx = match free_slot(
        slots,
        |s| s.in_use,
        crate::abi::contracts::resource::POOL_SANDBOXES,
    ) {
        Some(i) => i,
        None => return errno::ENOMEM,
    };

    // Pipes: out (child→parent stdio), start (parent→child barrier), pid
    // (child→parent relay of the container init's host pid — used when the
    // isolated double-fork makes the container a grandchild).
    let mut out_fds = [0i32; 2];
    let mut start_fds = [0i32; 2];
    let mut pid_fds = [0i32; 2];
    // Close-on-exec from creation: another thread's fork+exec never inherits
    // them. The child's own uses are all before its exec (or are the stdio
    // `dup2`, which clears the flag on the copy).
    if libc::pipe2(out_fds.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
        return errno::ERROR;
    }
    if libc::pipe2(start_fds.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
        libc::close(out_fds[0]);
        libc::close(out_fds[1]);
        return errno::ERROR;
    }
    if libc::pipe2(pid_fds.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
        for fd in [out_fds[0], out_fds[1], start_fds[0], start_fds[1]] {
            libc::close(fd);
        }
        return errno::ERROR;
    }
    let (out_r, out_w) = (out_fds[0], out_fds[1]);
    let (start_r, start_w) = (start_fds[0], start_fds[1]);
    let (pid_r, pid_w) = (pid_fds[0], pid_fds[1]);

    let pid = libc::fork();
    if pid < 0 {
        libc::close(out_r);
        libc::close(out_w);
        libc::close(start_r);
        libc::close(start_w);
        libc::close(pid_r);
        libc::close(pid_w);
        return errno::ERROR;
    }
    if pid == 0 {
        // Child: keep out_w + start_r + pid_w; close the parent ends.
        libc::close(out_r);
        libc::close(start_w);
        libc::close(pid_r);
        hp_child(&plan, start_r, out_w, pid_w);
        // unreachable
    }
    // Parent: keep out_r + start_w; close the child ends. Make out_r
    // non-blocking so HP_READ never blocks the scheduler.
    libc::close(out_w);
    libc::close(start_r);
    libc::close(pid_w);
    // out_r/start_w live in the slot table across calls; they are close-on-
    // exec (pipe2 above), so later fork+exec children (other containers,
    // exec probes, TTY sessions) never hold the out pipe open past this
    // container's exit nor defeat the closed-start_w abort signal — and those
    // children sweep their descriptors besides.
    let fl = libc::fcntl(out_r, libc::F_GETFL);
    libc::fcntl(out_r, libc::F_SETFL, fl | libc::O_NONBLOCK);

    // The container init's pid. For an isolated sandbox the intermediate writes
    // the grandchild's host pid up the pid pipe; a null sandbox's container IS
    // `pid`, and it closes the pipe once its network domain is in place. A
    // namespace the host refused arrives as `-errno` instead: the child is
    // reaped and CREATE answers it, so a workload that asked for isolation
    // never appears to run without it.
    let mut container_pid = pid;
    let mut pb = [0u8; 4];
    let got = loop {
        let n = libc::read(pid_r, pb.as_mut_ptr() as *mut libc::c_void, 4);
        if n < 0 && *libc::__errno_location() == libc::EINTR {
            continue;
        }
        break n;
    };
    libc::close(pid_r);
    let relayed = (got == 4).then(|| i32::from_ne_bytes(pb));
    let refused = match relayed {
        Some(v) if v <= 0 => Some(if v < 0 { v } else { errno::ERROR }),
        Some(v) if plan.isolate => {
            container_pid = v;
            None
        }
        Some(_) => Some(errno::ERROR),
        // The intermediate died before relaying the init's pid.
        None if plan.isolate => Some(errno::ERROR),
        None => None,
    };
    if let Some(e) = refused {
        libc::close(out_r);
        libc::close(start_w);
        let mut status = 0;
        while libc::waitpid(pid, &mut status, 0) < 0 && *libc::__errno_location() == libc::EINTR {}
        return e;
    }

    let slot = &mut slots[idx];
    slot.in_use = true;
    slot.pid = pid;
    slot.container_pid = container_pid;
    slot.start_w = start_w;
    slot.out_r = out_r;
    slot.started = false;
    slot.reaped = false;
    slot.isolated = plan.isolate;
    slot.paused = false;
    slot.exit_state = HP_STATE_RUNNING;
    slot.exit_code = 0;
    // The child has its copy; the slot keeps the process for EXEC and TTY.
    slot.proc = core::mem::replace(&mut plan.proc, PROC_EMPTY);
    // Apply resource limits before START releases the container (best-effort).
    let (cgrouped, contained) = hp_apply_cgroup(idx, container_pid, &plan);
    slot.cgrouped = cgrouped;
    slot.contained = contained;
    // Realize the network domain before START releases the container. Unlike
    // cgroups this is NOT best-effort: the network fields are Tier-1 spec, so
    // a failure fails the spawn rather than running with weaker networking.
    if own_netns {
        let rc = super::net_identity::realize(idx, container_pid, ident);
        if rc != 0 {
            hp_destroy(idx as i32);
            return rc;
        }
    }
    idx as i32
}

unsafe fn slot_for(raw: i32) -> Option<&'static mut HpSlot> {
    let idx = raw as usize;
    let slots = &mut *core::ptr::addr_of_mut!(LINUX_SANDBOXES);
    slots.get_mut(idx).filter(|s| s.in_use)
}

/// HP_START: release the init from the start barrier.
/// # Safety
/// Single-threaded platform dispatch only: mutates the process-global
/// sandbox slot table without synchronization.
pub unsafe fn hp_start(raw: i32) -> i32 {
    use crate::kernel::sys::errno;
    let Some(slot) = slot_for(raw) else {
        return errno::EINVAL;
    };
    if slot.started {
        return errno::OK;
    }
    let one = [1u8; 1];
    libc::write(slot.start_w, one.as_ptr() as *const libc::c_void, 1);
    libc::close(slot.start_w);
    slot.start_w = -1;
    slot.started = true;
    errno::OK
}

/// HP_READ: drain one chunk of merged stdout/stderr; 0 when nothing ready.
/// # Safety
/// Single-threaded platform dispatch only (process-global slot table).
/// `out` must be valid for writes of `out_len` bytes.
pub unsafe fn hp_read(raw: i32, out: *mut u8, out_len: usize) -> i32 {
    use crate::kernel::sys::errno;
    if out.is_null() || out_len == 0 {
        return errno::EINVAL;
    }
    let Some(slot) = slot_for(raw) else {
        return errno::EINVAL;
    };
    let n = libc::read(slot.out_r, out as *mut libc::c_void, out_len);
    if n >= 0 {
        return n as i32;
    }
    let e = *libc::__errno_location();
    if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
        return 0; // nothing ready this step
    }
    errno::ERROR
}

// ─── Interactive PTY sessions ─────────────────────────────────────────────
//
// A one-shot `hp_exec` captures output and returns; an interactive session
// keeps a pseudo-terminal open across scheduler steps so a shell can be driven
// bidirectionally. The master fd + child pid live in a process-global session
// table; `hp_tty_step` pumps one step of it (write stdin, drain output, poll
// liveness), and the caller relays those bytes.

/// The session-id DOMAIN, not a table size: the table is sized at boot to
/// the plan's `tty_sessions` ceiling (`size_kernel_tables`) — interactive
/// terminals (an interactive exec, an attach) open at once across every
/// sandbox, each a pseudo-terminal and a child pumped every step; a one-shot
/// `EXEC` takes none. A plan past it is refused at boot naming the pool.
pub const MAX_TTY_SESSIONS: usize = 4096;

struct TtySession {
    in_use: bool,
    /// PTY master (host side); the child holds the slave as its controlling tty.
    master: i32,
    pid: i32,
    reaped: bool,
    exit_code: i32,
}

const TTY_EMPTY: TtySession = TtySession {
    in_use: false,
    master: -1,
    pid: -1,
    reaped: false,
    exit_code: 0,
};

static mut LINUX_TTYS: crate::kernel::mem::table::Table<TtySession, MAX_TTY_SESSIONS> = crate::boot_table!(
    MAX_TTY_SESSIONS,
    TTY_EMPTY,
    crate::abi::contracts::resource::POOL_TTY_SESSIONS
);

/// Reserve the session table's ceiling, `n` sessions.
///
/// # Safety
/// Graph-preparation context: no reference into the table is live.
pub unsafe fn size_tty_sessions(n: usize) -> Result<(), crate::kernel::mem::table::TableError> {
    if n > MAX_TTY_SESSIONS {
        return Err(crate::kernel::mem::table::TableError::Ceiling);
    }
    (*core::ptr::addr_of!(LINUX_TTYS)).reserve(n)
}

/// Sessions the table may hold: its ceiling.
pub fn tty_capacity() -> usize {
    // SAFETY: a read of the table's bounds.
    unsafe { (*core::ptr::addr_of!(LINUX_TTYS)).ceiling() }
}

/// HP_TTY_OPEN: start an interactive PTY session running `argv` inside the
/// sandbox. Allocates a pseudo-terminal, sets its window size, forks a session
/// leader whose controlling tty is the PTY slave (setns-joining the container's
/// namespaces when isolated), and execs. Returns a session id (>= 0) for the
/// step/resize/close ops, or a negative errno.
///
/// `arg` = `[rows:u16 LE][cols:u16 LE][command line…]`.
///
/// # Safety
/// Single-threaded platform dispatch only. `arg` valid for `arg_len` reads.
pub unsafe fn hp_tty_open(raw: i32, arg: *const u8, arg_len: usize) -> i32 {
    use crate::kernel::sys::errno;
    if arg.is_null() || arg_len < 4 {
        return errno::EINVAL;
    }
    let a = core::slice::from_raw_parts(arg, arg_len);
    let rows = u16::from_le_bytes([a[0], a[1]]);
    let cols = u16::from_le_bytes([a[2], a[3]]);
    let cmd_end = a[4..]
        .iter()
        .position(|&b| b == 0)
        .map(|i| 4 + i)
        .unwrap_or(arg_len);
    let cmdline = match core::str::from_utf8(&a[4..cmd_end]) {
        Ok(s) => s.trim(),
        Err(_) => return errno::EINVAL,
    };
    if cmdline.is_empty() {
        return errno::EINVAL;
    }
    let mut cargs: Vec<CString> = Vec::new();
    for tok in cmdline.split_whitespace() {
        match CString::new(tok) {
            Ok(c) => cargs.push(c),
            Err(_) => return errno::EINVAL,
        }
    }
    let mut argv_ptrs: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(core::ptr::null());

    let Some(slot) = slot_for(raw) else {
        return errno::EINVAL;
    };
    // The session joins the workload: its namespaces, its cgroup, and it
    // runs as the workload does — its environment, its cwd, its user.
    let join = match prepare_join(raw, slot) {
        Ok(j) => j,
        Err(e) => return e,
    };
    let proc = &slot.proc;
    let envp = proc.envp_ptrs();

    let sessions = &mut *core::ptr::addr_of_mut!(LINUX_TTYS);
    let sid = match free_slot(
        sessions,
        |s| s.in_use,
        crate::abi::contracts::resource::POOL_TTY_SESSIONS,
    ) {
        Some(i) => i,
        None => {
            join.close();
            return errno::ENOMEM;
        }
    };

    // Allocate the PTY (host side) and open the slave.
    // The master outlives this call (session table) — close-on-exec from
    // creation, so later fork+exec children (other sessions, HP_EXEC, sandbox
    // spawns) never inherit a copy that would keep this PTY from hanging up.
    let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
    if master < 0 {
        join.close();
        return errno::ERROR;
    }
    if libc::grantpt(master) != 0 || libc::unlockpt(master) != 0 {
        libc::close(master);
        join.close();
        return errno::ERROR;
    }
    let mut pts = [0 as libc::c_char; 128];
    if libc::ptsname_r(master, pts.as_mut_ptr(), pts.len()) != 0 {
        libc::close(master);
        join.close();
        return errno::ERROR;
    }
    let slave = libc::open(
        pts.as_ptr(),
        libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
    );
    if slave < 0 {
        libc::close(master);
        join.close();
        return errno::ERROR;
    }
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    libc::ioctl(master, libc::TIOCSWINSZ, &ws);

    let pid = libc::fork();
    if pid < 0 {
        libc::close(master);
        libc::close(slave);
        join.close();
        return errno::ERROR;
    }
    if pid == 0 {
        // Child: join the workload, become a session leader on the PTY
        // slave, exec.
        reset_signals();
        libc::close(master);
        if !join.enter() {
            libc::_exit(125);
        }
        libc::setsid();
        libc::ioctl(slave, libc::TIOCSCTTY, 0);
        libc::dup2(slave, libc::STDIN_FILENO);
        libc::dup2(slave, libc::STDOUT_FILENO);
        libc::dup2(slave, libc::STDERR_FILENO);
        if slave > 2 {
            libc::close(slave);
        }
        close_all_but(&[libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO]);
        enter_as_workload(proc);
        exec_with(&argv_ptrs, &envp, proc);
    }
    // Parent: keep the master (non-blocking), drop the slave + ns fds.
    libc::close(slave);
    join.close();
    let fl = libc::fcntl(master, libc::F_GETFL);
    libc::fcntl(master, libc::F_SETFL, fl | libc::O_NONBLOCK);
    sessions[sid] = TtySession {
        in_use: true,
        master,
        pid,
        reaped: false,
        exit_code: 0,
    };
    sid as i32
}

/// HP_TTY_STEP: one pump step of a session — write pending stdin to the PTY,
/// drain its output, and poll the child's liveness. `arg` in =
/// `[sid:u32 LE][wlen:u32 LE][stdin bytes: wlen]`; `arg` out =
/// `[rlen:u32 LE][state:u8][code:i32 LE][output: rlen]` (state 0 = running,
/// 1 = exited). Returns 0, or a negative errno for a bad session id.
///
/// # Safety
/// Single-threaded platform dispatch only. `arg` valid for `arg_len` r/w.
pub unsafe fn hp_tty_step(arg: *mut u8, arg_len: usize) -> i32 {
    use crate::kernel::sys::errno;
    if arg.is_null() || arg_len < 9 {
        return errno::EINVAL;
    }
    let sid = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]) as usize;
    let wlen = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]) as usize;

    let sessions = &mut *core::ptr::addr_of_mut!(LINUX_TTYS);
    if sid >= sessions.len() || !sessions[sid].in_use {
        return errno::EINVAL;
    }
    let master = sessions[sid].master;
    // Write the stdin bytes straight from `arg` — the output drain below only
    // touches `arg` after this. Partial writes and EINTR are retried; a full
    // PTY buffer (EAGAIN on the non-blocking master) drops the remainder: the
    // wire format carries no consumed-count, and interactive input stays far
    // below the kernel's PTY buffer.
    let wn = wlen.min(arg_len - 8);
    let mut woff = 0usize;
    while woff < wn {
        let w = libc::write(master, arg.add(8 + woff) as *const libc::c_void, wn - woff);
        if w > 0 {
            woff += w as usize;
        } else if w < 0 && *libc::__errno_location() == libc::EINTR {
            continue;
        } else {
            break;
        }
    }
    // Drain the PTY output into arg[9..].
    let hdr = 9usize;
    let cap = arg_len - hdr;
    let mut rn = 0usize;
    if cap > 0 {
        loop {
            let n = libc::read(master, arg.add(hdr) as *mut libc::c_void, cap);
            if n > 0 {
                rn = n as usize;
            } else if n < 0 && *libc::__errno_location() == libc::EINTR {
                continue;
            }
            break;
        }
    }
    // Poll liveness (non-blocking reap).
    let (state, code) = if sessions[sid].reaped {
        (1u8, sessions[sid].exit_code)
    } else {
        let mut st: libc::c_int = 0;
        let r = libc::waitpid(sessions[sid].pid, &mut st, libc::WNOHANG);
        if r == sessions[sid].pid {
            let code = if libc::WIFEXITED(st) {
                libc::WEXITSTATUS(st)
            } else if libc::WIFSIGNALED(st) {
                128 + libc::WTERMSIG(st)
            } else {
                0
            };
            sessions[sid].reaped = true;
            sessions[sid].exit_code = code;
            (1u8, code)
        } else {
            (0u8, 0)
        }
    };
    core::ptr::copy_nonoverlapping((rn as u32).to_le_bytes().as_ptr(), arg, 4);
    *arg.add(4) = state;
    core::ptr::copy_nonoverlapping(code.to_le_bytes().as_ptr(), arg.add(5), 4);
    0
}

/// HP_TTY_RESIZE: set a session's window size. `arg` =
/// `[sid:u32 LE][rows:u16 LE][cols:u16 LE]`.
/// # Safety
/// Single-threaded platform dispatch only. `arg` valid for `arg_len` reads.
pub unsafe fn hp_tty_resize(arg: *const u8, arg_len: usize) -> i32 {
    use crate::kernel::sys::errno;
    if arg.is_null() || arg_len < 8 {
        return errno::EINVAL;
    }
    let sid = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]) as usize;
    let rows = u16::from_le_bytes([*arg.add(4), *arg.add(5)]);
    let cols = u16::from_le_bytes([*arg.add(6), *arg.add(7)]);
    let sessions = &*core::ptr::addr_of!(LINUX_TTYS);
    if sid >= sessions.len() || !sessions[sid].in_use {
        return errno::EINVAL;
    }
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    libc::ioctl(sessions[sid].master, libc::TIOCSWINSZ, &ws);
    0
}

/// HP_TTY_CLOSE: kill (if still running) + reap the session, close the master,
/// free the slot. `arg` = `[sid:u32 LE]`. Returns the child's exit code.
/// # Safety
/// Single-threaded platform dispatch only. `arg` valid for `arg_len` reads.
pub unsafe fn hp_tty_close(arg: *const u8, arg_len: usize) -> i32 {
    use crate::kernel::sys::errno;
    if arg.is_null() || arg_len < 4 {
        return errno::EINVAL;
    }
    let sid = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]) as usize;
    let sessions = &mut *core::ptr::addr_of_mut!(LINUX_TTYS);
    if sid >= sessions.len() || !sessions[sid].in_use {
        return errno::EINVAL;
    }
    if !sessions[sid].reaped {
        libc::kill(sessions[sid].pid, libc::SIGKILL);
        let mut st: libc::c_int = 0;
        let mut code = 128 + libc::SIGKILL;
        loop {
            let r = libc::waitpid(sessions[sid].pid, &mut st, 0);
            if r == sessions[sid].pid {
                if libc::WIFEXITED(st) {
                    code = libc::WEXITSTATUS(st);
                } else if libc::WIFSIGNALED(st) {
                    code = 128 + libc::WTERMSIG(st);
                }
                break;
            }
            if r < 0 && *libc::__errno_location() == libc::EINTR {
                continue;
            }
            break;
        }
        sessions[sid].reaped = true;
        sessions[sid].exit_code = code;
    }
    let code = sessions[sid].exit_code;
    if sessions[sid].master >= 0 {
        libc::close(sessions[sid].master);
    }
    sessions[sid] = TTY_EMPTY;
    code
}

/// What a process joining a live workload (EXEC, a TTY session) needs,
/// prepared in the parent so the child only issues system calls: the
/// container's namespaces (isolated only, in `setns` order — ipc, uts, net,
/// pid, mnt; mnt last, as it changes what `/proc/<pid>/ns` resolves to), the
/// `cgroup.procs` of the workload's cgroup when the workload is contained in
/// one, and whether it pivoted.
struct Join {
    ns: [i32; 5],
    procs: Option<CString>,
    isolated: bool,
}

/// Prepare to join `slot` (sandbox `raw`): EINVAL before START or while
/// PAUSEd (a process joining a frozen cgroup would freeze with it), ESRCH
/// when an isolated container's namespaces are gone. A join is all or
/// nothing: a process that could not enter every namespace would run on the
/// host.
unsafe fn prepare_join(raw: i32, slot: &HpSlot) -> Result<Join, i32> {
    use crate::kernel::sys::errno;
    if !slot.started || slot.paused {
        return Err(errno::EINVAL);
    }
    let mut join = Join {
        ns: [-1; 5],
        procs: None,
        isolated: slot.isolated,
    };
    if slot.contained {
        join.procs = cgroup_base().and_then(|b| {
            let p = b
                .join(format!("fluxor.hostproc.{raw}"))
                .join("cgroup.procs");
            CString::new(p.into_os_string().into_encoded_bytes()).ok()
        });
        if join.procs.is_none() {
            return Err(errno::ERROR);
        }
    }
    if slot.isolated {
        for (i, ns) in ["ipc", "uts", "net", "pid", "mnt"].iter().enumerate() {
            let fd = CString::new(format!("/proc/{}/ns/{ns}", slot.container_pid))
                .map_or(-1, |p| {
                    libc::open(p.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC)
                });
            if fd < 0 {
                join.close();
                return Err(errno::ESRCH);
            }
            join.ns[i] = fd;
        }
    }
    Ok(join)
}

impl Join {
    /// In the forked child: into the workload's cgroup (while its path is
    /// still the host's), then its namespaces, then its root. False on any
    /// refusal; the child must then exit. Async-signal-safe.
    unsafe fn enter(&self) -> bool {
        if let Some(p) = self.procs.as_ref() {
            // "0" moves the writer itself (cgroup-v2 `cgroup.procs`).
            let fd = libc::open(p.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
            let moved = fd >= 0 && libc::write(fd, b"0".as_ptr().cast(), 1) == 1;
            if fd >= 0 {
                libc::close(fd);
            }
            if !moved {
                return false;
            }
        }
        for &fd in &self.ns {
            if fd >= 0 {
                if libc::setns(fd, 0) != 0 {
                    return false;
                }
                libc::close(fd);
            }
        }
        !self.isolated || libc::chdir(c"/".as_ptr()) == 0
    }

    /// The parent's copies, once the child has its own.
    unsafe fn close(&self) {
        for &fd in &self.ns {
            if fd >= 0 {
                libc::close(fd);
            }
        }
    }
}

/// HP_EXEC: run a one-shot command *inside* an existing sandbox and capture its
/// merged stdout/stderr — the primitive behind an orchestrator's exec. For an
/// isolated sandbox the child joins the container's namespaces (all of them,
/// or it does not run), and in either kind it joins the workload's cgroup
/// when the workload has one, so it counts against the workload's limits;
/// it runs with the workload's environment, cwd and user. Synchronous:
/// forks, drains the child's output until the child has exited and nothing
/// is left to read, and reaps it — so it blocks the scheduler step for the
/// command's own lifetime (fine for probes; interactive/streaming exec is the
/// PTY session ops above). A process the command left behind holding its
/// output open does not hold the step.
///
/// `arg` on input holds the whitespace-split command line (NUL- or length-
/// bounded). On return `arg` holds `[out_len:u32 LE][output…]` with the captured
/// bytes truncated to fit `arg_len`; the return value is the child's exit code
/// (0–255), `128+signo` if signalled, or a negative errno on a setup failure
/// (EINVAL before START or while PAUSEd, ESRCH when the container is gone).
///
/// # Safety
/// Single-threaded platform dispatch only (process-global slot table). `arg`
/// must be valid for reads and writes of `arg_len` bytes.
pub unsafe fn hp_exec(raw: i32, arg: *mut u8, arg_len: usize) -> i32 {
    use crate::kernel::sys::errno;
    if arg.is_null() || arg_len < 4 {
        return errno::EINVAL;
    }
    // Read the command line out of `arg` before we reuse it for the output.
    let cmd_bytes = core::slice::from_raw_parts(arg, arg_len);
    let cmd_end = cmd_bytes.iter().position(|&b| b == 0).unwrap_or(arg_len);
    let cmdline = match core::str::from_utf8(&cmd_bytes[..cmd_end]) {
        Ok(s) => s.trim(),
        Err(_) => return errno::EINVAL,
    };
    if cmdline.is_empty() {
        return errno::EINVAL;
    }
    let mut cargs: Vec<CString> = Vec::new();
    for tok in cmdline.split_whitespace() {
        match CString::new(tok) {
            Ok(c) => cargs.push(c),
            Err(_) => return errno::EINVAL,
        }
    }
    let mut argv_ptrs: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(core::ptr::null());

    let Some(slot) = slot_for(raw) else {
        return errno::EINVAL;
    };
    let join = match prepare_join(raw, slot) {
        Ok(j) => j,
        Err(e) => return e,
    };
    let proc = &slot.proc;
    let envp = proc.envp_ptrs();

    let mut fds = [0i32; 2];
    if libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
        join.close();
        return errno::ERROR;
    }
    let (r, w) = (fds[0], fds[1]);
    let pid = libc::fork();
    if pid < 0 {
        libc::close(r);
        libc::close(w);
        join.close();
        return errno::ERROR;
    }
    if pid == 0 {
        // Child: stdio while `/dev/null` is the host's, then into the
        // workload, then exec. No allocation past this point.
        reset_signals();
        libc::close(r);
        if !wire_stdio(w) {
            libc::_exit(113);
        }
        if !join.enter() {
            libc::_exit(125);
        }
        close_all_but(&[libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO]);
        enter_as_workload(proc);
        exec_with(&argv_ptrs, &envp, proc);
    }

    // Parent: close the write end + the ns fds, drain the pipe into arg[4..]
    // (truncating on overflow but still draining so the child never blocks)
    // until the child has exited and nothing is ready, then reap.
    libc::close(w);
    join.close();
    let cap = arg_len - 4;
    let mut written = 0usize;
    let mut scratch = [0u8; 4096];
    let mut status: libc::c_int = 0;
    let mut reaped = false;
    loop {
        let mut pfd = libc::pollfd {
            fd: r,
            events: libc::POLLIN,
            revents: 0,
        };
        // Once the child is gone, only what is already in the pipe is read.
        let ready = libc::poll(&mut pfd, 1, if reaped { 0 } else { 20 });
        if ready < 0 {
            if *libc::__errno_location() == libc::EINTR {
                continue;
            }
            break;
        }
        if ready > 0 {
            let n = libc::read(r, scratch.as_mut_ptr() as *mut libc::c_void, scratch.len());
            if n > 0 {
                let n = n as usize;
                if written < cap {
                    let take = n.min(cap - written);
                    core::ptr::copy_nonoverlapping(scratch.as_ptr(), arg.add(4 + written), take);
                    written += take;
                }
                continue;
            }
            if n < 0 && *libc::__errno_location() == libc::EINTR {
                continue;
            }
            break; // EOF: every writer is gone
        }
        if reaped {
            break;
        }
        reaped = libc::waitpid(pid, &mut status, libc::WNOHANG) == pid;
    }
    libc::close(r);
    while !reaped {
        let rc = libc::waitpid(pid, &mut status, 0);
        reaped = rc == pid || (rc < 0 && *libc::__errno_location() != libc::EINTR);
    }
    let out_len = (written as u32).to_le_bytes();
    core::ptr::copy_nonoverlapping(out_len.as_ptr(), arg, 4);
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        126
    }
}

/// HP_SIGNAL: deliver a signal to the container process.
/// # Safety
/// Single-threaded platform dispatch only (process-global slot table).
/// `arg` must be valid for reads of `arg_len` bytes.
pub unsafe fn hp_signal(raw: i32, arg: *const u8, arg_len: usize) -> i32 {
    use crate::kernel::sys::errno;
    if arg.is_null() || arg_len < 1 {
        return errno::EINVAL;
    }
    let signo = *arg as i32;
    let Some(slot) = slot_for(raw) else {
        return errno::EINVAL;
    };
    // Reap first: once the process this slot waits for has exited, the
    // container's pid is free for the host to reuse, and a signal sent to it
    // could reach a stranger.
    hp_poll_reap(raw, slot);
    if slot.reaped {
        return errno::OK; // already gone
    }
    // Thaw-then-signal: a frozen cgroup queues signals and handlers cannot
    // run — SIG_KILL and SIG_TERM alike thaw first so grace semantics stay
    // uniform.
    if slot.paused {
        hp_freeze_write(raw as usize, false);
        slot.paused = false;
    }
    // Target the container init's process group, not the intermediate (which
    // is blocked in waitpid and would not forward the signal).
    if kill_container_group(slot.container_pid, signo) != 0 {
        return errno::ERROR;
    }
    errno::OK
}

/// Deliver `signo` to the container's process group — the container body
/// makes itself a group leader (`setpgid(0,0)`) before exec, so `-pgid` is
/// `-container_pid` (children of the init must
/// hear the signal too, or grace semantics are meaningless). Falls back to
/// single-pid delivery when the group kill fails with ESRCH — the one
/// legitimate gap is a container signalled before its body reached setpgid.
/// Returns 0 on success, -1 on failure (kill semantics).
unsafe fn kill_container_group(container_pid: i32, signo: i32) -> i32 {
    if libc::kill(-container_pid, signo) == 0 {
        return 0;
    }
    if *libc::__errno_location() == libc::ESRCH {
        return libc::kill(container_pid, signo);
    }
    -1
}

/// Non-blocking reap poll: latch the terminal state once the child is gone.
/// Shared by WAIT (state reporting) and PAUSE (a terminal workload must be
/// refused, so PAUSE needs the same freshness as WAIT). A workload that
/// exited on its own releases its address here, as DESTROY would.
unsafe fn hp_poll_reap(raw: i32, slot: &mut HpSlot) {
    if slot.reaped {
        return;
    }
    let mut status: libc::c_int = 0;
    let r = libc::waitpid(slot.pid, &mut status, libc::WNOHANG);
    if r == slot.pid {
        slot.reaped = true;
        super::net_identity::released(raw as usize);
        if libc::WIFEXITED(status) {
            slot.exit_state = HP_STATE_EXITED;
            slot.exit_code = libc::WEXITSTATUS(status);
        } else if libc::WIFSIGNALED(status) {
            slot.exit_state = HP_STATE_SIGNALLED;
            slot.exit_code = libc::WTERMSIG(status);
        }
    }
    // r == 0 → still running; r < 0 → already reaped elsewhere (leave running/unknown).
}

/// HP_WAIT: non-blocking; returns [state:u8][code:i32 LE]. Caches the result.
/// # Safety
/// Single-threaded platform dispatch only (process-global slot table).
/// `out` must be valid for writes of `out_len` bytes.
pub unsafe fn hp_wait(raw: i32, out: *mut u8, out_len: usize) -> i32 {
    use crate::kernel::sys::errno;
    if out.is_null() || out_len < 5 {
        return errno::EINVAL;
    }
    let Some(slot) = slot_for(raw) else {
        return errno::EINVAL;
    };
    hp_poll_reap(raw, slot);
    let buf = core::slice::from_raw_parts_mut(out, out_len);
    if !slot.reaped && slot.paused {
        // Frozen and not exited → PAUSED, live, not terminal.
        // A workload that died BEFORE the freeze latched terminal in the
        // poll above and reports that; a frozen one cannot exit, so the two
        // never race. RESUME clears `paused`, so the next poll reflects
        // RUNNING.
        buf[0] = HP_STATE_PAUSED;
        buf[1..5].copy_from_slice(&0i32.to_le_bytes());
        return 5;
    }
    buf[0] = slot.exit_state;
    buf[1..5].copy_from_slice(&slot.exit_code.to_le_bytes());
    5
}

/// HP_PAUSE: freeze the sandbox via its cgroup's `cgroup.freeze`. Gated on
/// the container actually living in the per-sandbox cgroup (`cgrouped &&
/// contained`) — a workload whose best-effort cgroup setup failed gets
/// ENOSYS, and there is never a SIGSTOP fallback (a stopped process is
/// observable and thaw-able by its own children; the freezer is not).
/// Idempotent: PAUSE on paused returns 0. PAUSE on a terminal workload is a
/// state error — EINVAL, the backend's wrong-lifecycle-state convention (cf.
/// EXEC/TTY_OPEN before START).
///
/// # Safety
/// Single-threaded platform dispatch only (process-global slot table).
pub unsafe fn hp_pause(raw: i32) -> i32 {
    use crate::kernel::sys::errno;
    let Some(slot) = slot_for(raw) else {
        return errno::EINVAL;
    };
    hp_poll_reap(raw, slot);
    if slot.reaped {
        return errno::EINVAL; // terminal — ESTATE-class refusal
    }
    if !(slot.cgrouped && slot.contained) {
        return errno::ENOSYS; // this workload has no working freezer
    }
    if slot.paused {
        return errno::OK;
    }
    if !hp_freeze_write(raw as usize, true) {
        return errno::ERROR;
    }
    slot.paused = true;
    errno::OK
}

/// HP_RESUME: thaw a paused sandbox (`cgroup.freeze` = 0). Idempotent:
/// RESUME on a running workload returns 0; a terminal workload is also 0
/// (it is by definition not paused — thawing a corpse is a no-op).
/// # Safety
/// Single-threaded platform dispatch only (process-global slot table).
pub unsafe fn hp_resume(raw: i32) -> i32 {
    use crate::kernel::sys::errno;
    let Some(slot) = slot_for(raw) else {
        return errno::EINVAL;
    };
    if !(slot.cgrouped && slot.contained) {
        return errno::ENOSYS; // same per-workload gate as PAUSE
    }
    if !slot.paused {
        return errno::OK;
    }
    if !hp_freeze_write(raw as usize, false) {
        return errno::ERROR;
    }
    slot.paused = false;
    errno::OK
}

/// HP_DESTROY: kill (SIGTERM → brief grace → SIGKILL), reap, free the slot.
/// The container's mounts live in its own mount namespace and vanish with it,
/// so there is nothing to unmount on the host.
/// # Safety
/// Single-threaded platform dispatch only: mutates the process-global
/// sandbox slot table without synchronization.
pub unsafe fn hp_destroy(raw: i32) -> i32 {
    use crate::kernel::sys::errno;
    let Some(slot) = slot_for(raw) else {
        return errno::EINVAL;
    };
    if slot.start_w >= 0 {
        libc::close(slot.start_w);
        slot.start_w = -1;
    }
    // Thaw-then-destroy: frozen, the init could never run a TERM handler
    // and the graceful window below would always escalate to SIGKILL —
    // thaw first so DESTROY-on-paused keeps the same grace semantics as
    // DESTROY-on-running.
    if slot.paused {
        hp_freeze_write(raw as usize, false);
        slot.paused = false;
    }
    // As for SIGNAL: a container whose relay already exited is not signalled.
    hp_poll_reap(raw, slot);
    if !slot.reaped && slot.pid > 0 {
        // Signal the container init's process group (SIGKILL to PID 1 of a
        // pid ns tears the whole namespace down; the group delivery also
        // reaches a null sandbox's children); reap the
        // intermediate/child via `pid`. A handler-less init ignores SIGTERM
        // from our ancestor ns, so the grace simply elapses and SIGKILL
        // settles it.
        kill_container_group(slot.container_pid, libc::SIGTERM);
        let mut status: libc::c_int = 0;
        let mut gone = false;
        for _ in 0..50 {
            if libc::waitpid(slot.pid, &mut status, libc::WNOHANG) == slot.pid {
                gone = true;
                break;
            }
            libc::usleep(2000); // 2ms × 50 = 100ms grace
        }
        if !gone {
            kill_container_group(slot.container_pid, libc::SIGKILL);
            libc::waitpid(slot.pid, &mut status, 0);
        }
    }
    // Its address leaves the node: flows discarded, attachment unguarded.
    super::net_identity::released(raw as usize);
    if slot.out_r >= 0 {
        libc::close(slot.out_r);
    }
    let had_cgroup = slot.cgrouped;
    *slot = HP_EMPTY;
    // The container is reaped now, so its cgroup.procs is empty and rmdir works.
    if had_cgroup {
        hp_remove_cgroup(raw as usize);
    }
    errno::OK
}
