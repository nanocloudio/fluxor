// ============================================================================
// The privilege and system-call surface of a Linux host-process workload
// ============================================================================
//
// Mechanism behind the host-process backend's confinement — not a
// consumer-facing surface. Every process of a workload (its container init,
// an EXEC, a TTY session) is confined before it execs, in this order:
//
//   1. `no_new_privs` (`PR_SET_NO_NEW_PRIVS`): no exec ever grants a
//      privilege the process does not already hold — a setuid or setgid
//      binary runs with the caller's ids, file capabilities are not raised,
//      and a uid-0 exec's permitted set never grows past what it was.
//   2. The capability bounding set is cut to the granted set: the OCI
//      runtime defaults ([`DEFAULT_CAPS`]: CHOWN, DAC_OVERRIDE, FSETID,
//      FOWNER, MKNOD, NET_RAW, SETGID, SETUID, SETFCAP, SETPCAP,
//      NET_BIND_SERVICE, SYS_CHROOT, KILL, AUDIT_WRITE) plus what the
//      orchestrator added. Cutting it needs `CAP_SETPCAP`; a runtime without
//      it leaves the bounding set as it is, which under `no_new_privs`
//      grants nothing (an exec's permitted set is bounded by the one before
//      it, and that one is cut in step 4).
//   3. `PR_SET_KEEPCAPS`, so the identity change keeps the permitted set
//      for step 4 to cut rather than clear; then the identity itself.
//   4. The sets the workload runs with (`capset`, ambient): uid 0 holds the
//      granted set as effective and permitted, inheritable and ambient
//      empty; any other uid holds only the added capabilities, in every set
//      including ambient, so they survive its exec. The defaults are not
//      given to a non-root user: it holds none unless the orchestrator
//      added them — the semantics of the OCI default for a non-root user.
//      Only capabilities the runtime itself holds can be granted.
//   5. The system-call filter (seccomp, `SECCOMP_SET_MODE_FILTER`), last,
//      immediately before the exec: an allowlist modelled on the OCI default
//      profile. The architecture is checked first (a foreign one — a
//      32-bit compat entry — kills the process, since its numbers name
//      other calls); a call off the list answers `EPERM`. `clone` and
//      `unshare` are allowed only without namespace flags, `clone3`
//      answers `ENOSYS` (so a C library falls back to `clone`, whose flags
//      the filter can read), `personality` only for the plain Linux
//      personalities, `socket` for every family but `AF_VSOCK`; the calls
//      the default profile ties to a capability (mount and namespace
//      creation to `CAP_SYS_ADMIN`, `ptrace` relatives to
//      `CAP_SYS_PTRACE`, the clock to `CAP_SYS_TIME`, and so on) are allowed
//      when that capability is granted.
//
// The filter is built in the parent, before the fork; the child only hands
// the finished program to the kernel. Everything the child runs here is a
// raw system call on memory prepared before the fork — no allocation.
//
// The filter table is aarch64's. On another architecture no filter is
// built ([`filter_available`] is false), the rest of the confinement still
// applies, and the backend does not offer the hardened posture.

use crate::kernel::sys::errno;

/// Capability numbers (`capabilities(7)`).
pub mod cap {
    pub const CHOWN: u32 = 0;
    pub const DAC_OVERRIDE: u32 = 1;
    pub const DAC_READ_SEARCH: u32 = 2;
    pub const FOWNER: u32 = 3;
    pub const FSETID: u32 = 4;
    pub const KILL: u32 = 5;
    pub const SETGID: u32 = 6;
    pub const SETUID: u32 = 7;
    pub const SETPCAP: u32 = 8;
    pub const NET_BIND_SERVICE: u32 = 10;
    pub const NET_RAW: u32 = 13;
    pub const SYS_MODULE: u32 = 16;
    pub const SYS_RAWIO: u32 = 17;
    pub const SYS_CHROOT: u32 = 18;
    pub const SYS_PTRACE: u32 = 19;
    pub const SYS_PACCT: u32 = 20;
    pub const SYS_ADMIN: u32 = 21;
    pub const SYS_BOOT: u32 = 22;
    pub const SYS_NICE: u32 = 23;
    pub const SYS_TIME: u32 = 25;
    pub const SYS_TTY_CONFIG: u32 = 26;
    pub const MKNOD: u32 = 27;
    pub const AUDIT_WRITE: u32 = 29;
    pub const SETFCAP: u32 = 31;
    pub const SYSLOG: u32 = 34;
    pub const PERFMON: u32 = 38;
    pub const BPF: u32 = 39;
}

/// `1 << c` for a capability number.
const fn bit(c: u32) -> u64 {
    1u64 << c
}

/// The capabilities a workload is granted when the orchestrator adds none:
/// the OCI runtime defaults.
pub const DEFAULT_CAPS: u64 = bit(cap::CHOWN)
    | bit(cap::DAC_OVERRIDE)
    | bit(cap::FSETID)
    | bit(cap::FOWNER)
    | bit(cap::MKNOD)
    | bit(cap::NET_RAW)
    | bit(cap::SETGID)
    | bit(cap::SETUID)
    | bit(cap::SETFCAP)
    | bit(cap::SETPCAP)
    | bit(cap::NET_BIND_SERVICE)
    | bit(cap::SYS_CHROOT)
    | bit(cap::KILL)
    | bit(cap::AUDIT_WRITE);

/// The capability sets of a process, one bit per capability.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapSets {
    pub bounding: u64,
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
    pub ambient: u64,
}

/// The sets `/proc/<pid>/status` text states (`CapInh`, `CapPrm`, `CapEff`,
/// `CapBnd`, `CapAmb`); a field it lacks reads as empty.
pub fn sets_in_status(status: &str) -> CapSets {
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
            .unwrap_or(0)
    };
    CapSets {
        bounding: field("CapBnd:"),
        effective: field("CapEff:"),
        permitted: field("CapPrm:"),
        inheritable: field("CapInh:"),
        ambient: field("CapAmb:"),
    }
}

/// The sets this runtime holds now.
pub fn runtime_sets() -> CapSets {
    std::fs::read_to_string("/proc/self/status")
        .map(|s| sets_in_status(&s))
        .unwrap_or_default()
}

/// The highest capability number this kernel knows
/// (`/proc/sys/kernel/cap_last_cap`); 63 when it cannot be read, every
/// number past the real last one then answering `EINVAL` harmlessly.
pub fn last_cap() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&n| n < 64)
        .unwrap_or(63)
}

/// What the orchestrator asked of a workload's confinement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Request {
    /// Capabilities granted beyond [`DEFAULT_CAPS`], one bit per number.
    pub cap_add: u64,
    /// No system-call filter.
    pub no_syscall_filter: bool,
    /// The hardened posture: no addition, a filter, the bounding set cut.
    pub hardened: bool,
}

/// The sets a workload runs with, given what the runtime holds (`held`),
/// the highest capability number (`last`) and whether it runs as uid 0
/// ([`plan`] and the module header). `EINVAL` for an added number past
/// `last`; `EACCES` for an added capability the runtime does not hold in
/// both its permitted and its bounding set, since it cannot grant one it
/// lacks.
pub fn plan_sets(cap_add: u64, held: CapSets, last: u32, root: bool) -> Result<CapSets, i32> {
    let valid = if last >= 63 {
        u64::MAX
    } else {
        (1u64 << (last + 1)) - 1
    };
    if cap_add & !valid != 0 {
        return Err(errno::EINVAL);
    }
    if cap_add & !(held.permitted & held.bounding) != 0 {
        return Err(errno::EACCES);
    }
    let granted = (DEFAULT_CAPS | cap_add) & valid;
    let holdable = held.permitted & held.bounding;
    Ok(if root {
        let have = granted & holdable;
        CapSets {
            bounding: granted,
            effective: have,
            permitted: have,
            inheritable: 0,
            ambient: 0,
        }
    } else {
        CapSets {
            bounding: granted,
            effective: cap_add,
            permitted: cap_add,
            inheritable: cap_add,
            ambient: cap_add,
        }
    })
}

/// A workload's confinement, prepared before the fork: the child only
/// issues system calls with it.
pub struct Confine {
    /// False for a confinement nobody planned: the child refuses to exec.
    planned: bool,
    sets: CapSets,
    last_cap: u32,
    /// The runtime holds `CAP_SETPCAP`, so the bounding set is cut.
    drop_bounding: bool,
    /// The system-call filter; empty for none.
    filter: Vec<libc::sock_filter>,
}

impl Confine {
    /// The confinement of a process nobody planned: the child refuses to
    /// exec under it.
    pub const UNPLANNED: Confine = Confine {
        planned: false,
        sets: CapSets {
            bounding: 0,
            effective: 0,
            permitted: 0,
            inheritable: 0,
            ambient: 0,
        },
        last_cap: 0,
        drop_bounding: false,
        filter: Vec::new(),
    };

    /// The sets the workload runs with.
    pub fn sets(&self) -> CapSets {
        self.sets
    }

    /// Whether a system-call filter is installed.
    pub fn filtered(&self) -> bool {
        !self.filter.is_empty()
    }

    /// Whether the bounding set is cut.
    pub fn bounds(&self) -> bool {
        self.drop_bounding
    }

    /// Before the identity change: `no_new_privs`, the bounding set cut,
    /// the permitted set kept across the change. False on a refusal; the
    /// child must then not exec. Async-signal-safe.
    ///
    /// # Safety
    /// A forked child before exec.
    pub unsafe fn enter(&self) -> bool {
        if !self.planned {
            return false;
        }
        if prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0) != 0 {
            return false;
        }
        if self.drop_bounding {
            for c in 0..=self.last_cap {
                if self.sets.bounding & bit(c) != 0 {
                    continue;
                }
                if prctl(libc::PR_CAPBSET_DROP, c.into(), 0) != 0
                    && *libc::__errno_location() != libc::EINVAL
                {
                    return false;
                }
            }
        }
        // Locked by a securebit the runtime set for itself, it stays as it
        // is; the sets below are then what the identity change left.
        prctl(libc::PR_SET_KEEPCAPS, 1, 0);
        true
    }

    /// After the identity change: the effective, permitted and inheritable
    /// sets, then ambient. False on a refusal. Async-signal-safe.
    ///
    /// # Safety
    /// A forked child before exec, after [`Confine::enter`].
    pub unsafe fn settle(&self) -> bool {
        #[repr(C)]
        struct Header {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct Data {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        // `_LINUX_CAPABILITY_VERSION_3`: two 32-bit words per set.
        let hdr = Header {
            version: 0x2008_0522,
            pid: 0,
        };
        let s = self.sets;
        let data = [
            Data {
                effective: s.effective as u32,
                permitted: s.permitted as u32,
                inheritable: s.inheritable as u32,
            },
            Data {
                effective: (s.effective >> 32) as u32,
                permitted: (s.permitted >> 32) as u32,
                inheritable: (s.inheritable >> 32) as u32,
            },
        ];
        if libc::syscall(libc::SYS_capset, &hdr as *const Header, data.as_ptr()) != 0 {
            return false;
        }
        if prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0,
        ) != 0
            && (s.ambient != 0 || *libc::__errno_location() != libc::EINVAL)
        {
            return false;
        }
        for c in 0..64u32 {
            if s.ambient & bit(c) != 0
                && prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_RAISE as libc::c_ulong,
                    c.into(),
                ) != 0
            {
                return false;
            }
        }
        prctl(libc::PR_SET_KEEPCAPS, 0, 0);
        true
    }

    /// Last, immediately before the exec: the system-call filter. False
    /// when the kernel refuses it. Async-signal-safe.
    ///
    /// # Safety
    /// A forked child, after [`Confine::enter`] (`no_new_privs` is what
    /// lets an unprivileged process install one).
    pub unsafe fn seal(&self) -> bool {
        if self.filter.is_empty() {
            return true;
        }
        let prog = libc::sock_fprog {
            len: self.filter.len() as libc::c_ushort,
            filter: self.filter.as_ptr() as *mut libc::sock_filter,
        };
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER as libc::c_ulong,
            0 as libc::c_ulong,
            &prog as *const libc::sock_fprog,
        ) == 0
    }
}

/// Plan a workload's confinement from the orchestrator's request, for a
/// workload that runs as uid 0 (`root`) or not. `EINVAL` and `EACCES` as
/// [`plan_sets`]; for the hardened posture also `EINVAL` for an addition or
/// a filter opt-out, `ENOSYS` when no filter can be built here, and `EPERM`
/// when the runtime cannot cut the bounding set (it lacks `CAP_SETPCAP`).
pub fn plan(req: &Request, root: bool) -> Result<Confine, i32> {
    let held = runtime_sets();
    let last = last_cap();
    let drop_bounding = held.effective & bit(cap::SETPCAP) != 0;
    if req.hardened {
        if req.cap_add != 0 || req.no_syscall_filter {
            return Err(errno::EINVAL);
        }
        if !filter_available() {
            return Err(errno::ENOSYS);
        }
        if !drop_bounding {
            return Err(-libc::EPERM);
        }
    }
    let sets = plan_sets(req.cap_add, held, last, root)?;
    let filter = if req.no_syscall_filter || !filter_available() {
        Vec::new()
    } else {
        default_filter(DEFAULT_CAPS | req.cap_add)
    };
    Ok(Confine {
        planned: true,
        sets,
        last_cap: last,
        drop_bounding,
        filter,
    })
}

/// `prctl(op, a, b, 0, 0)` with every argument a full machine word: the
/// variadic C call would leave the upper half of a narrower one undefined,
/// and the options here refuse (`EINVAL`) any unused argument that is not
/// zero. Async-signal-safe.
///
/// # Safety
/// As the option requires.
unsafe fn prctl(op: libc::c_int, a: libc::c_ulong, b: libc::c_ulong) -> libc::c_int {
    libc::prctl(op, a, b, 0 as libc::c_ulong, 0 as libc::c_ulong)
}

/// Whether this runtime installs a system-call filter: an architecture
/// with a table, on a kernel with seccomp filters. Probed once.
pub fn filter_available() -> bool {
    static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        // SAFETY: a query with no side effect.
        cfg!(target_arch = "aarch64") && unsafe { prctl(libc::PR_GET_SECCOMP, 0, 0) } >= 0
    })
}

// ─── The filter program ────────────────────────────────────────────────────

/// `seccomp_data` offsets: the call number, the architecture, the low word
/// of the first argument (little-endian).
const DATA_NR: u32 = 0;
const DATA_ARCH: u32 = 4;
const DATA_ARG0_LO: u32 = 16;
/// `AUDIT_ARCH_AARCH64` (`EM_AARCH64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE`).
pub const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
/// The longest program the kernel loads (`BPF_MAXINSNS`).
const MAX_INSNS: usize = 4096;

const LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
const JEQ_K: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
const JSET_K: u16 = (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16;
const RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;

/// The namespace flags of `clone` (`CLONE_NEWNS`, `NEWCGROUP`, `NEWUTS`,
/// `NEWIPC`, `NEWUSER`, `NEWPID`, `NEWNET`): the default profile's mask.
pub const CLONE_NS_MASK: u32 = 0x7E02_0000;
/// The same for `unshare`, which also takes `CLONE_NEWTIME`.
pub const UNSHARE_NS_MASK: u32 = CLONE_NS_MASK | 0x80;
/// `AF_VSOCK`, the one socket family the default profile refuses.
const AF_VSOCK: u32 = 40;
/// The personalities a workload may select: `PER_LINUX`, `PER_LINUX32`,
/// `UNAME26`, both, and the query.
const PERSONALITIES: [u32; 5] = [0x0, 0x8, 0x2_0000, 0x2_0008, 0xFFFF_FFFF];

const RET_ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
const RET_KILL: u32 = libc::SECCOMP_RET_KILL_PROCESS;
const RET_EPERM: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
const RET_ENOSYS: u32 = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// The default system-call filter for a workload granted `caps` (see the
/// module header). Pure: the program the kernel is handed.
pub fn default_filter(caps: u64) -> Vec<libc::sock_filter> {
    let table = table::allowed(caps);
    let mut p = Vec::with_capacity(8 + 2 * table.len() + 32);
    p.push(stmt(LD_W_ABS, DATA_ARCH));
    p.push(jump(JEQ_K, table::ARCH, 1, 0));
    p.push(stmt(RET_K, RET_KILL));
    p.push(stmt(LD_W_ABS, DATA_NR));
    for &nr in &table {
        p.push(jump(JEQ_K, nr, 0, 1));
        p.push(stmt(RET_K, RET_ALLOW));
    }
    let admin = caps & bit(cap::SYS_ADMIN) != 0;
    if !admin {
        // Without namespace flags only; `clone3` hides its flags in memory
        // the filter cannot read, so it is answered as absent.
        for (nr, mask) in [
            (table::CLONE, CLONE_NS_MASK),
            (table::UNSHARE, UNSHARE_NS_MASK),
        ] {
            p.push(jump(JEQ_K, nr, 0, 4));
            p.push(stmt(LD_W_ABS, DATA_ARG0_LO));
            p.push(jump(JSET_K, mask, 1, 0));
            p.push(stmt(RET_K, RET_ALLOW));
            p.push(stmt(RET_K, RET_EPERM));
        }
        p.push(jump(JEQ_K, table::CLONE3, 0, 1));
        p.push(stmt(RET_K, RET_ENOSYS));
    }
    // `personality` for the listed values only.
    let n = PERSONALITIES.len() as u8;
    p.push(jump(JEQ_K, table::PERSONALITY, 0, n + 3));
    p.push(stmt(LD_W_ABS, DATA_ARG0_LO));
    for (i, v) in PERSONALITIES.iter().enumerate() {
        p.push(jump(JEQ_K, *v, n - i as u8, 0));
    }
    p.push(stmt(RET_K, RET_EPERM));
    p.push(stmt(RET_K, RET_ALLOW));
    // `socket` for every family but `AF_VSOCK`.
    p.push(jump(JEQ_K, table::SOCKET, 0, 4));
    p.push(stmt(LD_W_ABS, DATA_ARG0_LO));
    p.push(jump(JEQ_K, AF_VSOCK, 1, 0));
    p.push(stmt(RET_K, RET_ALLOW));
    p.push(stmt(RET_K, RET_EPERM));
    p.push(stmt(RET_K, RET_EPERM));
    assert!(p.len() <= MAX_INSNS, "the filter fits BPF_MAXINSNS");
    p
}

/// The call numbers of the allowlist, per architecture.
#[cfg(target_arch = "aarch64")]
mod table {
    use super::{bit, cap};

    pub const ARCH: u32 = super::AUDIT_ARCH_AARCH64;
    pub const CLONE: u32 = 220;
    pub const CLONE3: u32 = 435;
    pub const UNSHARE: u32 = 97;
    pub const PERSONALITY: u32 = 92;
    pub const SOCKET: u32 = 198;
    const _: () = assert!(
        CLONE == libc::SYS_clone as u32
            && CLONE3 == libc::SYS_clone3 as u32
            && UNSHARE == libc::SYS_unshare as u32
            && PERSONALITY == libc::SYS_personality as u32
            && SOCKET == libc::SYS_socket as u32,
        "the argument-checked calls are aarch64's numbers"
    );

    /// Allowed whatever the capabilities (the default profile's
    /// unconditional list, as aarch64 numbers it).
    const ALWAYS: &[u32] = &[
        0,   // io_setup
        1,   // io_destroy
        2,   // io_submit
        3,   // io_cancel
        4,   // io_getevents
        5,   // setxattr
        6,   // lsetxattr
        7,   // fsetxattr
        8,   // getxattr
        9,   // lgetxattr
        10,  // fgetxattr
        11,  // listxattr
        12,  // llistxattr
        13,  // flistxattr
        14,  // removexattr
        15,  // lremovexattr
        16,  // fremovexattr
        17,  // getcwd
        19,  // eventfd2
        20,  // epoll_create1
        21,  // epoll_ctl
        22,  // epoll_pwait
        23,  // dup
        24,  // dup3
        25,  // fcntl
        26,  // inotify_init1
        27,  // inotify_add_watch
        28,  // inotify_rm_watch
        29,  // ioctl
        30,  // ioprio_set
        31,  // ioprio_get
        32,  // flock
        33,  // mknodat
        34,  // mkdirat
        35,  // unlinkat
        36,  // symlinkat
        37,  // linkat
        43,  // statfs
        44,  // fstatfs
        45,  // truncate
        46,  // ftruncate
        47,  // fallocate
        48,  // faccessat
        49,  // chdir
        50,  // fchdir
        52,  // fchmod
        53,  // fchmodat
        54,  // fchownat
        55,  // fchown
        56,  // openat
        57,  // close
        59,  // pipe2
        61,  // getdents64
        62,  // lseek
        63,  // read
        64,  // write
        65,  // readv
        66,  // writev
        67,  // pread64
        68,  // pwrite64
        69,  // preadv
        70,  // pwritev
        71,  // sendfile
        72,  // pselect6
        73,  // ppoll
        74,  // signalfd4
        75,  // vmsplice
        76,  // splice
        77,  // tee
        78,  // readlinkat
        79,  // newfstatat
        80,  // fstat
        81,  // sync
        82,  // fsync
        83,  // fdatasync
        84,  // sync_file_range
        85,  // timerfd_create
        86,  // timerfd_settime
        87,  // timerfd_gettime
        88,  // utimensat
        90,  // capget
        91,  // capset
        93,  // exit
        94,  // exit_group
        95,  // waitid
        96,  // set_tid_address
        98,  // futex
        99,  // set_robust_list
        100, // get_robust_list
        101, // nanosleep
        102, // getitimer
        103, // setitimer
        107, // timer_create
        108, // timer_gettime
        109, // timer_getoverrun
        110, // timer_settime
        111, // timer_delete
        113, // clock_gettime
        114, // clock_getres
        115, // clock_nanosleep
        118, // sched_setparam
        119, // sched_setscheduler
        120, // sched_getscheduler
        121, // sched_getparam
        122, // sched_setaffinity
        123, // sched_getaffinity
        124, // sched_yield
        125, // sched_get_priority_max
        126, // sched_get_priority_min
        127, // sched_rr_get_interval
        128, // restart_syscall
        129, // kill
        130, // tkill
        131, // tgkill
        132, // sigaltstack
        133, // rt_sigsuspend
        134, // rt_sigaction
        135, // rt_sigprocmask
        136, // rt_sigpending
        137, // rt_sigtimedwait
        138, // rt_sigqueueinfo
        139, // rt_sigreturn
        140, // setpriority
        141, // getpriority
        143, // setregid
        144, // setgid
        145, // setreuid
        146, // setuid
        147, // setresuid
        148, // getresuid
        149, // setresgid
        150, // getresgid
        151, // setfsuid
        152, // setfsgid
        153, // times
        154, // setpgid
        155, // getpgid
        156, // getsid
        157, // setsid
        158, // getgroups
        159, // setgroups
        160, // uname
        163, // getrlimit
        164, // setrlimit
        165, // getrusage
        166, // umask
        167, // prctl
        168, // getcpu
        169, // gettimeofday
        171, // adjtimex
        172, // getpid
        173, // getppid
        174, // getuid
        175, // geteuid
        176, // getgid
        177, // getegid
        178, // gettid
        179, // sysinfo
        180, // mq_open
        181, // mq_unlink
        182, // mq_timedsend
        183, // mq_timedreceive
        184, // mq_notify
        185, // mq_getsetattr
        186, // msgget
        187, // msgctl
        188, // msgrcv
        189, // msgsnd
        190, // semget
        191, // semctl
        192, // semtimedop
        193, // semop
        194, // shmget
        195, // shmctl
        196, // shmat
        197, // shmdt
        199, // socketpair
        200, // bind
        201, // listen
        202, // accept
        203, // connect
        204, // getsockname
        205, // getpeername
        206, // sendto
        207, // recvfrom
        208, // setsockopt
        209, // getsockopt
        210, // shutdown
        211, // sendmsg
        212, // recvmsg
        213, // readahead
        214, // brk
        215, // munmap
        216, // mremap
        221, // execve
        222, // mmap
        223, // fadvise64
        226, // mprotect
        227, // msync
        228, // mlock
        229, // munlock
        230, // mlockall
        231, // munlockall
        232, // mincore
        233, // madvise
        234, // remap_file_pages
        240, // rt_tgsigqueueinfo
        242, // accept4
        243, // recvmmsg
        260, // wait4
        261, // prlimit64
        263, // fanotify_mark
        264, // name_to_handle_at
        266, // clock_adjtime
        267, // syncfs
        269, // sendmmsg
        274, // sched_setattr
        275, // sched_getattr
        276, // renameat2
        277, // seccomp
        278, // getrandom
        279, // memfd_create
        281, // execveat
        283, // membarrier
        284, // mlock2
        285, // copy_file_range
        286, // preadv2
        287, // pwritev2
        288, // pkey_mprotect
        289, // pkey_alloc
        290, // pkey_free
        291, // statx
        292, // io_pgetevents
        293, // rseq
        424, // pidfd_send_signal
        434, // pidfd_open
        436, // close_range
        437, // openat2
        439, // faccessat2
        441, // epoll_pwait2
        444, // landlock_create_ruleset
        445, // landlock_add_rule
        446, // landlock_restrict_self
        447, // memfd_secret
        448, // process_mrelease
        449, // futex_waitv
        451, // cachestat
        452, // fchmodat2
        453, // map_shadow_stack
        454, // futex_wake
        455, // futex_wait
        456, // futex_requeue
        // `ptrace` and its relatives: the default profile allows these on
        // every kernel the backend runs on.
        117, // ptrace
        270, // process_vm_readv
        271, // process_vm_writev
    ];

    /// Allowed when the capability is granted.
    const BY_CAP: &[(u32, &[u32])] = &[
        (cap::DAC_READ_SEARCH, &[265]), // open_by_handle_at
        (
            cap::SYS_ADMIN,
            &[
                280, // bpf
                220, // clone, any flags
                435, // clone3
                262, // fanotify_init
                431, // fsconfig
                432, // fsmount
                430, // fsopen
                433, // fspick
                18,  // lookup_dcookie
                40,  // mount
                442, // mount_setattr
                429, // move_mount
                428, // open_tree
                241, // perf_event_open
                60,  // quotactl
                443, // quotactl_fd
                162, // setdomainname
                161, // sethostname
                268, // setns
                116, // syslog
                39,  // umount2
                97,  // unshare, any flags
            ],
        ),
        (cap::SYS_BOOT, &[142]),                // reboot
        (cap::SYS_CHROOT, &[51]),               // chroot
        (cap::SYS_MODULE, &[105, 106, 273]),    // init_module, delete_module, finit_module
        (cap::SYS_PACCT, &[89]),                // acct
        (cap::SYS_PTRACE, &[272, 438, 440]),    // kcmp, pidfd_getfd, process_madvise
        (cap::SYS_TIME, &[170, 112]),           // settimeofday, clock_settime
        (cap::SYS_TTY_CONFIG, &[58]),           // vhangup
        (cap::SYS_NICE, &[235, 236, 237, 450]), // mbind, get_mempolicy, set_mempolicy, _home_node
        (cap::SYSLOG, &[116]),                  // syslog
        (cap::BPF, &[280]),                     // bpf
        (cap::PERFMON, &[241]),                 // perf_event_open
    ];

    /// The numbers allowed outright for a workload granted `caps`, each
    /// once, ascending.
    pub fn allowed(caps: u64) -> Vec<u32> {
        let mut v: Vec<u32> = ALWAYS.to_vec();
        for (c, nrs) in BY_CAP {
            if caps & bit(*c) != 0 {
                v.extend_from_slice(nrs);
            }
        }
        v.sort_unstable();
        v.dedup();
        v
    }
}

/// No table on this architecture: [`filter_available`] is false, so no
/// program is ever built from it.
#[cfg(not(target_arch = "aarch64"))]
mod table {
    pub const ARCH: u32 = 0;
    pub const CLONE: u32 = u32::MAX;
    pub const CLONE3: u32 = u32::MAX;
    pub const UNSHARE: u32 = u32::MAX;
    pub const PERSONALITY: u32 = u32::MAX;
    pub const SOCKET: u32 = u32::MAX;
    pub fn allowed(_caps: u64) -> Vec<u32> {
        Vec::new()
    }
}

/// The allowlist's call numbers for a workload granted `caps` (the calls the
/// filter allows without looking at an argument).
pub fn allowed_calls(caps: u64) -> Vec<u32> {
    table::allowed(caps)
}

// ─── Parent death ──────────────────────────────────────────────────────────

/// Bind the calling child to its parent: `SIGKILL` when the thread that
/// forked it exits, then a check that it has not already — a parent gone
/// before the bind was made would never send it. `parent` is the pid the
/// child must still see as its parent. The identity change clears the
/// binding, so a child binds again after it. Exits (code 110) when the
/// parent is gone. Async-signal-safe.
///
/// # Safety
/// A forked child.
pub unsafe fn bind_to_parent(parent: i32) {
    if prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong, 0) != 0
        || libc::getppid() != parent
    {
        libc::_exit(110);
    }
}

/// [`bind_to_parent`] for a child whose parent is outside its pid namespace
/// (`getppid` reads 0 there): the parent's liveness is a pipe whose only
/// write end the parent holds, and its end of file is the parent gone.
/// Async-signal-safe.
///
/// # Safety
/// A forked child; `lifeline` is the read end of that pipe.
pub unsafe fn bind_to_parent_by(lifeline: i32) {
    if prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong, 0) != 0 {
        libc::_exit(110);
    }
    let mut pfd = libc::pollfd {
        fd: lifeline,
        events: libc::POLLIN,
        revents: 0,
    };
    if libc::poll(&mut pfd, 1, 0) != 0 {
        libc::_exit(110);
    }
}
