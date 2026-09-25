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
// unprivileged path; a namespaced spawn needs CAP_SYS_ADMIN. Seccomp/caps are
// not applied yet, which is why the provider advertises SHARED/ISOLATED but not
// HARDENED (fail-closed).
//
// Network: when the workload spec asks for its own network domain
// (`NET_ISO_OWN` on any endpoint), NEWNET joins the unshare set (orthogonal to
// `isolate` — a null sandbox can still get its own netns), and the sibling
// `net_identity` module realizes the Tier-1 network fields (lo up; veth +
// identity address when one is assigned) before START releases the barrier.
//
// Spawn inputs are EXPLICIT parameters, never an on-disk bundle/OCI format —
// this backend is a generic isolation primitive. `build_plan` takes:
//   argv     command + args (required, non-empty)
//   rootfs   container root to pivot into (optional)
//   isolate  unshare MOUNT|UTS|IPC|PID (needs CAP_SYS_ADMIN)
// cgroup.v2 limits come from the portable `ResourceEnvelope` (mapped in
// `hp_spawn`), not from any file. The orchestrator (nanocloud) owns the
// mapping from its container/OCI world to these parameters.
//
// A library module (`fluxor::platform::linux::host_backend`); the `workload` provider in
// the sibling module composes it, and the host test harness exercises it.

use std::ffi::CString;

// Terminal-state byte reported by `hp_wait`.
const HP_STATE_RUNNING: u8 = 0;
const HP_STATE_EXITED: u8 = 1;
const HP_STATE_SIGNALLED: u8 = 2;
// Live, not terminal: frozen via PAUSE.
const HP_STATE_PAUSED: u8 = 3;

pub const MAX_SANDBOXES: usize = 16;

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
};

static mut LINUX_SANDBOXES: [HpSlot; MAX_SANDBOXES] = [HP_EMPTY; MAX_SANDBOXES];

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
}

/// A volume the workload sees at `dst` inside its root: the host path `src`
/// bind-mounted there (`workload` Tier-2 option `mount`/`bind`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VolumeBind {
    pub src: String,
    pub dst: String,
    pub ro: bool,
}

/// A bind, ready for the child: the directories to create under the rootfs
/// (outermost first), the mount target, and whether the target is a file.
pub struct PlannedBind {
    src: CString,
    target: CString,
    dirs: Vec<CString>,
    file: bool,
    ro: bool,
}

/// Resolve `binds` against `rootfs`. Refuses (EINVAL) a relative path, a `..`
/// segment, or a bind without a rootfs to bind into — a volume that would land
/// somewhere other than inside the workload's own root is not a volume.
pub fn plan_binds(rootfs: Option<&str>, binds: &[VolumeBind]) -> Result<Vec<PlannedBind>, i32> {
    use crate::kernel::sys::errno;
    if binds.is_empty() {
        return Ok(Vec::new());
    }
    let Some(root) = rootfs.filter(|r| !r.is_empty()) else {
        return Err(errno::EINVAL);
    };
    let clean = |p: &str| p.starts_with('/') && !p.split('/').any(|s| s == "..");
    let mut out = Vec::new();
    for b in binds {
        if !clean(&b.src) || !clean(&b.dst) || b.dst == "/" {
            return Err(errno::EINVAL);
        }
        let file = std::fs::metadata(&b.src)
            .map(|m| m.is_file())
            .map_err(|_| errno::ENOENT)?;
        let root = root.trim_end_matches('/');
        let target = format!("{root}{}", b.dst);
        // Every directory from the rootfs down to the target (or its parent,
        // for a file), created in order by the child.
        let mut dirs = Vec::new();
        let mut acc = root.to_string();
        let segs: Vec<&str> = b.dst.split('/').filter(|s| !s.is_empty()).collect();
        let upto = if file {
            segs.len().saturating_sub(1)
        } else {
            segs.len()
        };
        for s in &segs[..upto] {
            acc.push('/');
            acc.push_str(s);
            dirs.push(CString::new(acc.clone()).map_err(|_| errno::EINVAL)?);
        }
        out.push(PlannedBind {
            src: CString::new(b.src.clone()).map_err(|_| errno::EINVAL)?,
            target: CString::new(target).map_err(|_| errno::EINVAL)?,
            dirs,
            file,
            ro: b.ro,
        });
    }
    Ok(out)
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
        own_netns: false,
        binds: Vec::new(),
        mem_max: None,
        pids_max: None,
        cpu_max: None,
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
    /// envelope from the spec header, so this sentinel is currently only
    /// constructed by tests.
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

/// The intermediate child — runs after the provider's fork. MUST be
/// async-signal-safe: only libc calls against pointers prepared in the parent,
/// no allocation. For an isolated sandbox it unshares the namespaces (NEWPID
/// affects its children, so the grandchild it forks is PID 1 in the new pid ns),
/// forks the container init, relays that init's host pid up `pid_w`, and relays
/// its exit status as its own exit code. For a null sandbox it *is* the
/// container and execs directly. On any failure it `_exit`s a distinct code so
/// the parent's WAIT surfaces it.
unsafe fn hp_child(plan: &SpawnPlan, start_r: i32, out_w: i32, pid_w: i32) -> ! {
    if !plan.isolate {
        // Null sandbox: this process is the container. No pid relay needed —
        // the provider already knows this pid. Own-netns is orthogonal to
        // isolate: unshare just the network domain when the spec asks.
        libc::close(pid_w);
        if plan.own_netns && libc::unshare(libc::CLONE_NEWNET) != 0 {
            libc::_exit(121);
        }
        hp_container_body(plan, start_r, out_w);
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
        libc::_exit(125);
    }
    let init = libc::fork();
    if init < 0 {
        libc::_exit(120);
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

/// The container-process body — mounts (isolated) / chdir (null), stdio, the
/// create/start barrier, then exec. Runs as the container init (grandchild) in
/// an isolated sandbox, or as the direct child in a null sandbox; its
/// namespaces are already unshared by the caller in the isolated case.
unsafe fn hp_container_body(plan: &SpawnPlan, start_r: i32, out_w: i32) -> ! {
    // Become a process-group leader so SIGNAL/DESTROY can deliver to the
    // whole group (`kill(-pgid)`) and children of the container init hear a
    // SIGTERM too. NB: the double-fork did NOT already do this — fork
    // inherits the parent's pgid — so this call is load-bearing, not
    // belt-and-braces. No controlling terminal to detach here (stdio is the
    // out pipe), so setpgid suffices; the TTY session path does its own
    // setsid.
    libc::setpgid(0, 0);
    if plan.isolate {
        // Make `/` a private recursive mount so our mount changes don't
        // propagate to the host (nanocloud runtime.rs:876 — the first, load-
        // bearing step).
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
            for b in &plan.binds {
                for d in &b.dirs {
                    libc::mkdir(d.as_ptr(), 0o755);
                }
                if b.file {
                    let fd = libc::open(b.target.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o644);
                    if fd >= 0 {
                        libc::close(fd);
                    }
                }
                if libc::mount(
                    b.src.as_ptr(),
                    b.target.as_ptr(),
                    core::ptr::null(),
                    libc::MS_BIND | libc::MS_REC,
                    core::ptr::null(),
                ) != 0
                {
                    libc::_exit(121);
                }
                if b.ro
                    && libc::mount(
                        core::ptr::null(),
                        b.target.as_ptr(),
                        core::ptr::null(),
                        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_REC,
                        core::ptr::null(),
                    ) != 0
                {
                    libc::_exit(121);
                }
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
    } else if let Some(rootfs) = plan.rootfs.as_ref() {
        // Null sandbox with a rootfs: chroot only (no mount ns). chdir first.
        libc::chdir(rootfs.as_ptr());
    }

    // stdio → the out pipe; stdin from /dev/null.
    libc::dup2(out_w, libc::STDOUT_FILENO);
    libc::dup2(out_w, libc::STDERR_FILENO);
    let devnull = c"/dev/null".as_ptr();
    let nfd = libc::open(devnull, libc::O_RDONLY);
    if nfd >= 0 {
        libc::dup2(nfd, libc::STDIN_FILENO);
        if nfd > 2 {
            libc::close(nfd);
        }
    }
    if out_w > 2 {
        libc::close(out_w);
    }

    // The create/start barrier: block until HP_START releases us
    // (nanocloud runtime.rs:991 — the init waits on the start pipe).
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

    libc::execvp(plan.argv_ptrs[0], plan.argv_ptrs.as_ptr());
    // execvp only returns on failure.
    libc::_exit(127);
}

/// pivot_root into `new_root` (a mount point). Mirrors nanocloud
/// runtime.rs:2913: bind rootfs onto itself, pivot, detach the old root, with
/// an MS_MOVE fallback on EINVAL/EXDEV. Returns 0 on success, -1 on failure.
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
    // Fallback: MS_MOVE the new root to "/" then chroot (nanocloud
    // fallback_move_root, runtime.rs:2990).
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
    hp_spawn_with_binds(argv_tokens, rootfs, isolate, env, own_netns, ident, &[])
}

/// [`hp_spawn`] with volumes: each [`VolumeBind`] is bind-mounted into the
/// rootfs before the pivot. A bind needs an isolated sandbox with a rootfs
/// (EINVAL otherwise) — without its own mount namespace the mount would land
/// on the host.
///
/// # Safety
/// As [`hp_spawn`].
pub unsafe fn hp_spawn_with_binds(
    argv_tokens: &[&str],
    rootfs: Option<&str>,
    isolate: bool,
    env: &ResourceEnvelope,
    own_netns: bool,
    ident: Option<&super::net_identity::NetIdentity>,
    binds: &[VolumeBind],
) -> i32 {
    use crate::kernel::sys::errno;

    let mut plan = match build_plan(argv_tokens, rootfs, isolate) {
        Ok(p) => p,
        Err(e) => return e,
    };
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
    let idx = match slots.iter().position(|s| !s.in_use) {
        Some(i) => i,
        None => return errno::ENOMEM,
    };

    // Pipes: out (child→parent stdio), start (parent→child barrier), pid
    // (child→parent relay of the container init's host pid — used when the
    // isolated double-fork makes the container a grandchild).
    let mut out_fds = [0i32; 2];
    let mut start_fds = [0i32; 2];
    let mut pid_fds = [0i32; 2];
    if libc::pipe(out_fds.as_mut_ptr()) != 0
        || libc::pipe(start_fds.as_mut_ptr()) != 0
        || libc::pipe(pid_fds.as_mut_ptr()) != 0
    {
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
    // out_r/start_w live in the slot table across calls — mark them CLOEXEC so
    // later fork+exec children (other containers, exec probes, TTY sessions)
    // don't inherit copies that would hold the out pipe open past this
    // container's exit (no EOF on out_r) or defeat the closed-start_w abort
    // signal. Safe for THIS container: it uses its own ends pre-exec only
    // (barrier read, pid relay) or dup2'd onto stdio, and these parent copies
    // are closed in its fork branch above.
    libc::fcntl(out_r, libc::F_SETFD, libc::FD_CLOEXEC);
    libc::fcntl(start_w, libc::F_SETFD, libc::FD_CLOEXEC);
    let fl = libc::fcntl(out_r, libc::F_GETFL);
    libc::fcntl(out_r, libc::F_SETFL, fl | libc::O_NONBLOCK);

    // The container init's pid. For an isolated sandbox the intermediate writes
    // the grandchild's host pid up the pid pipe; a null sandbox's container IS
    // `pid`. If the relay never arrives (intermediate died early — e.g. unshare
    // EPERM without root), fall back to `pid`; WAIT then surfaces its exit.
    let mut container_pid = pid;
    if plan.isolate {
        let mut pb = [0u8; 4];
        if libc::read(pid_r, pb.as_mut_ptr() as *mut libc::c_void, 4) == 4 {
            container_pid = i32::from_ne_bytes(pb);
        }
    }
    libc::close(pid_r);

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
    if idx >= MAX_SANDBOXES || !slots[idx].in_use {
        return None;
    }
    Some(&mut slots[idx])
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

// ─── Interactive PTY exec sessions (kubectl exec -it) ─────────────────────
//
// A one-shot `hp_exec` captures output and returns; an interactive session
// keeps a pseudo-terminal open across scheduler steps so a shell can be driven
// bidirectionally. The master fd + child pid live in a process-global session
// table; `hp_tty_step` pumps one step of it (write stdin, drain output, poll
// liveness) and the provider relays those bytes over the store seam.

pub const MAX_TTY_SESSIONS: usize = 8;

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

static mut LINUX_TTYS: [TtySession; MAX_TTY_SESSIONS] = [TTY_EMPTY; MAX_TTY_SESSIONS];

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

    let (container_pid, isolated, started) = {
        let Some(slot) = slot_for(raw) else {
            return errno::EINVAL;
        };
        (slot.container_pid, slot.isolated, slot.started)
    };
    if !started {
        return errno::EINVAL;
    }

    let sessions = &mut *core::ptr::addr_of_mut!(LINUX_TTYS);
    let sid = match sessions.iter().position(|s| !s.in_use) {
        Some(i) => i,
        None => return errno::ENOMEM,
    };

    // Allocate the PTY (host side) and open the slave.
    let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
    if master < 0 {
        return errno::ERROR;
    }
    // The master outlives this call (session table) — mark it CLOEXEC so later
    // fork+exec children (other sessions, HP_EXEC, sandbox spawns) don't
    // inherit a copy that would keep this PTY from ever hanging up.
    libc::fcntl(master, libc::F_SETFD, libc::FD_CLOEXEC);
    if libc::grantpt(master) != 0 || libc::unlockpt(master) != 0 {
        libc::close(master);
        return errno::ERROR;
    }
    let mut pts = [0 as libc::c_char; 128];
    if libc::ptsname_r(master, pts.as_mut_ptr(), pts.len()) != 0 {
        libc::close(master);
        return errno::ERROR;
    }
    let slave = libc::open(pts.as_ptr(), libc::O_RDWR);
    if slave < 0 {
        libc::close(master);
        return errno::ERROR;
    }
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    libc::ioctl(master, libc::TIOCSWINSZ, &ws);

    // Pre-open the container's namespace fds (parent side; no post-fork malloc).
    let mut ns_fds = [-1i32; 5];
    if isolated {
        for (i, ns) in ["ipc", "uts", "net", "pid", "mnt"].iter().enumerate() {
            if let Ok(p) = CString::new(format!("/proc/{container_pid}/ns/{ns}")) {
                ns_fds[i] = libc::open(p.as_ptr(), libc::O_RDONLY);
            }
        }
    }

    let pid = libc::fork();
    if pid < 0 {
        libc::close(master);
        libc::close(slave);
        for &fd in &ns_fds {
            if fd >= 0 {
                libc::close(fd);
            }
        }
        return errno::ERROR;
    }
    if pid == 0 {
        // Child: join namespaces, become a session leader on the PTY slave, exec.
        libc::close(master);
        for &fd in &ns_fds {
            if fd >= 0 {
                libc::setns(fd, 0);
                libc::close(fd);
            }
        }
        if isolated {
            libc::chdir(c"/".as_ptr());
        }
        libc::setsid();
        libc::ioctl(slave, libc::TIOCSCTTY, 0);
        libc::dup2(slave, libc::STDIN_FILENO);
        libc::dup2(slave, libc::STDOUT_FILENO);
        libc::dup2(slave, libc::STDERR_FILENO);
        if slave > 2 {
            libc::close(slave);
        }
        libc::execvp(argv_ptrs[0], argv_ptrs.as_ptr());
        libc::_exit(127);
    }
    // Parent: keep the master (non-blocking), drop the slave + ns fds.
    libc::close(slave);
    for &fd in &ns_fds {
        if fd >= 0 {
            libc::close(fd);
        }
    }
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
    if sid >= MAX_TTY_SESSIONS || !sessions[sid].in_use {
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
    if sid >= MAX_TTY_SESSIONS || !sessions[sid].in_use {
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
    if sid >= MAX_TTY_SESSIONS || !sessions[sid].in_use {
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

/// HP_EXEC: run a one-shot command *inside* an existing sandbox and capture its
/// merged stdout/stderr — the `kubectl exec workload -- cmd` primitive. For an
/// isolated sandbox the child setns-joins the container's namespaces (nsenter);
/// a null sandbox shares the host's, so it execs directly. Synchronous: forks,
/// drains the child's output to EOF, and reaps it — so it briefly blocks the
/// scheduler step (fine for probes; interactive/streaming exec is the PTY
/// session ops above).
///
/// `arg` on input holds the whitespace-split command line (NUL- or length-
/// bounded). On return `arg` holds `[out_len:u32 LE][output…]` with the captured
/// bytes truncated to fit `arg_len`; the return value is the child's exit code
/// (0–255), `128+signo` if signalled, or a negative errno on a setup failure.
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

    let (container_pid, isolated, started) = {
        let Some(slot) = slot_for(raw) else {
            return errno::EINVAL;
        };
        (slot.container_pid, slot.isolated, slot.started)
    };
    if !started {
        return errno::EINVAL; // nothing to exec into until the container runs
    }

    // Pre-open the container's namespace fds on the PARENT side — malloc is safe
    // here, but the post-fork child must not allocate. setns order: ipc, uts,
    // net, pid, mnt (mnt last, as it changes /proc/<pid>/ns visibility). pid
    // takes effect for children only; without a re-fork the exec'd process keeps
    // the host pid view — acceptable for a filesystem/exec probe.
    let mut ns_fds = [-1i32; 5];
    if isolated {
        for (i, ns) in ["ipc", "uts", "net", "pid", "mnt"].iter().enumerate() {
            if let Ok(p) = CString::new(format!("/proc/{container_pid}/ns/{ns}")) {
                ns_fds[i] = libc::open(p.as_ptr(), libc::O_RDONLY);
            }
        }
    }

    let mut fds = [0i32; 2];
    if libc::pipe(fds.as_mut_ptr()) != 0 {
        for &fd in &ns_fds {
            if fd >= 0 {
                libc::close(fd);
            }
        }
        return errno::ERROR;
    }
    let (r, w) = (fds[0], fds[1]);
    let pid = libc::fork();
    if pid < 0 {
        libc::close(r);
        libc::close(w);
        for &fd in &ns_fds {
            if fd >= 0 {
                libc::close(fd);
            }
        }
        return errno::ERROR;
    }
    if pid == 0 {
        // Child: join namespaces (best-effort), wire stdio to the pipe, exec.
        // No allocation past this point.
        libc::close(r);
        for &fd in &ns_fds {
            if fd >= 0 {
                libc::setns(fd, 0);
                libc::close(fd);
            }
        }
        if isolated {
            libc::chdir(c"/".as_ptr());
        }
        libc::dup2(w, libc::STDOUT_FILENO);
        libc::dup2(w, libc::STDERR_FILENO);
        let nfd = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
        if nfd >= 0 {
            libc::dup2(nfd, libc::STDIN_FILENO);
            if nfd > 2 {
                libc::close(nfd);
            }
        }
        if w > 2 {
            libc::close(w);
        }
        libc::execvp(argv_ptrs[0], argv_ptrs.as_ptr());
        libc::_exit(127); // execvp only returns on failure
    }

    // Parent: close the write end + the ns fds, drain the pipe into arg[4..]
    // (truncating on overflow but still draining so the child never blocks),
    // then reap.
    libc::close(w);
    for &fd in &ns_fds {
        if fd >= 0 {
            libc::close(fd);
        }
    }
    let cap = arg_len - 4;
    let mut written = 0usize;
    let mut scratch = [0u8; 4096];
    loop {
        let n = libc::read(r, scratch.as_mut_ptr() as *mut libc::c_void, scratch.len());
        if n > 0 {
            let n = n as usize;
            if written < cap {
                let take = n.min(cap - written);
                core::ptr::copy_nonoverlapping(scratch.as_ptr(), arg.add(4 + written), take);
                written += take;
            }
        } else if n == 0 {
            break;
        } else if *libc::__errno_location() == libc::EINTR {
            continue;
        } else {
            break;
        }
    }
    libc::close(r);
    let mut status: libc::c_int = 0;
    loop {
        let rc = libc::waitpid(pid, &mut status, 0);
        if rc == pid {
            break;
        }
        if rc < 0 && *libc::__errno_location() == libc::EINTR {
            continue;
        }
        break;
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
/// refused, so PAUSE needs the same freshness as WAIT).
unsafe fn hp_poll_reap(slot: &mut HpSlot) {
    if slot.reaped {
        return;
    }
    let mut status: libc::c_int = 0;
    let r = libc::waitpid(slot.pid, &mut status, libc::WNOHANG);
    if r == slot.pid {
        slot.reaped = true;
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
    hp_poll_reap(slot);
    let buf = core::slice::from_raw_parts_mut(out, out_len);
    if !slot.reaped && slot.paused {
        // Frozen and not exited → PAUSED, live, not terminal.
        // A workload that died BEFORE the
        // freeze latched terminal in the poll above and reports it as today;
        // a frozen one cannot exit, so the two never race. RESUME clears
        // `paused`, so the next poll reflects RUNNING (§3.3).
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
    hp_poll_reap(slot);
    if slot.reaped {
        return errno::EINVAL; // terminal — ESTATE-class refusal (§2.2)
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
/// The container's mounts live in its own mount namespace and vanish with it —
/// no host-side unmount (nanocloud tears down host-side mounts because it binds
/// on the host; v1 pivots inside the child's ns).
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
    if !slot.reaped && slot.pid > 0 {
        // Signal the container init's process group (SIGKILL to PID 1 of a
        // pid ns tears the whole namespace down; the group delivery also
        // reaches a null sandbox's children — §3.1); reap the
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
