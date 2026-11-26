// Platform: linux host-process operations (contract class `host_process`).
//
// Layer: platform/linux (host-specific, unstable). Host-PROCESS mechanics —
// command execution, PTY sessions, output drains, commands the node runs
// itself, the host-process source (root, argv, environment, identity) — are
// one backend's implementation vocabulary, not native Fluxor workload
// semantics, so they live here rather than in the stable `workload`
// contract. The native surface is
// CREATE/START/WAIT/SIGNAL/DESTROY/PAUSE/RESUME/CAPS/OPTIONS.
//
// Calling convention: every op names what it acts on in the handle slot.
// An op on a workload ([`READ`], [`EXEC`], [`TTY_OPEN`]) takes the caller's
// `workload` handle (the contract accepts that contract's handles, so the
// kernel resolves it for the handle's owner); a terminal session and a
// spawned command are handles this contract mints ([`TTY_OPEN`],
// [`PROC_SPAWN`]) and the ops on them take. [`PROC_SPAWN`] and [`CAPS`] take
// `-1`. Command lines, stdin and output travel in `data`. All fields
// little-endian. The class is present only where the linux host platform
// registered it — an unregistered class returns `ENOSYS`, which IS the
// discovery. Every op needs the `host_process.exec` grant, which a gated
// module never holds.

/// Provider contract class for host-process ops.
pub const CLASS: u16 = super::super::super::registry::host_process::ID;

/// One-shot command in a running workload, through its handle. `arg` in =
/// `[cmd_len:u32]`, out = `[out_len:u32]` ([`EXEC_ARG_LEN`]); `data` in =
/// the command line (UTF-8, words split on whitespace, NUL-bounded) in its
/// first `cmd_len` bytes, out = the merged stdout/stderr in its first
/// `out_len`, truncated to fit `data`. Returns the command's exit code
/// (0–255, `128 + signal` when a signal ended it) or a negative errno.
/// Synchronous: the call returns once the command has exited and its output
/// was drained. The command
/// joins the workload — its namespaces (every one, or it does not run), its
/// cgroup, its environment, cwd and user, its capabilities, `no_new_privs`
/// and system-call filter (see [`SOURCE_HOST_PROCESS`]) — and holds no
/// descriptor of the runtime's. `EINVAL` before START or while the workload
/// is PAUSEd or for a workload that is not a host process, `ESRCH` when its
/// container is gone.
pub use super::super::super::registry::host_process::EXEC;
/// Drain a workload's merged stdout/stderr, through its handle. No `arg`;
/// `data` out = the output. Returns the bytes written into `data` (0 = none
/// pending).
pub use super::super::super::registry::host_process::READ;
/// Kill, reap and free a session, through its handle; the handle closes.
/// No `arg`. Returns its exit code.
pub use super::super::super::registry::host_process::TTY_CLOSE;
/// Open an interactive PTY session in a workload, through its handle. `arg`
/// = `[rows:u16][cols:u16]` ([`TTY_OPEN_ARG_LEN`]); `data` in = the command
/// line (UTF-8, words split on whitespace, NUL-bounded). Returns the
/// session's handle. The session joins the workload as [`EXEC`] does, with
/// the same refusals.
/// The session belongs to whoever opened it — the calling module, under its
/// owner: [`TTY_STEP`], [`TTY_RESIZE`] and [`TTY_CLOSE`] from any other
/// module or owner answer `EACCES`. The session is closed (its process
/// killed and reaped, its handle retired) when the opener's owner is
/// released, and when the workload it joined is destroyed.
pub use super::super::super::registry::host_process::TTY_OPEN;
/// Resize a session's window, through its handle. `arg` =
/// `[rows:u16][cols:u16]` ([`TTY_RESIZE_ARG_LEN`]).
pub use super::super::super::registry::host_process::TTY_RESIZE;
/// Pump a session, through its handle: write stdin, drain output, poll for
/// exit. `arg` in = `[wlen:u32]`, out = `[rlen:u32][state:u8][code:i32]`
/// ([`TTY_STEP_ARG_LEN`]; `state` [`TTY_RUNNING`] or [`TTY_EXITED`], `code`
/// the exit code once exited); `data` in = stdin in its first `wlen` bytes,
/// out = the output in its first `rlen`. Returns 0.
pub use super::super::super::registry::host_process::TTY_STEP;

/// [`EXEC`]'s `arg` length, in and out.
pub const EXEC_ARG_LEN: usize = 4;
/// [`TTY_OPEN`]'s `arg` length.
pub const TTY_OPEN_ARG_LEN: usize = 4;
/// [`TTY_STEP`]'s `arg` length: the answer's (the request is its first 4).
pub const TTY_STEP_ARG_LEN: usize = 9;
/// [`TTY_RESIZE`]'s `arg` length.
pub const TTY_RESIZE_ARG_LEN: usize = 4;
/// [`TTY_STEP`] `state`: the session's process runs.
pub const TTY_RUNNING: u8 = 0;
/// [`TTY_STEP`] `state`: it exited; `code` holds how.
pub const TTY_EXITED: u8 = 1;

/// Host-only `source_kind` for the workload CREATE header: the source-ref
/// carries explicit host-process spawn params, realized by the linux
/// host-process backend. Little-endian, every part length-prefixed and
/// present, nothing after the last:
/// ```text
///   [flags:u8]                    SRC_ISOLATED: own namespaces (needs
///                                 privilege) — set exactly when the
///                                 header's posture is ISOLATED or
///                                 HARDENED, else EINVAL;
///                                 SRC_ROOT_READ_ONLY: the root is
///                                 read-only once the process starts
///                                 (needs SRC_ISOLATED, else EINVAL);
///                                 SRC_CAP_ADD: the cap_add part follows
///                                 the groups part; SRC_NO_SYSCALL_FILTER:
///                                 no system-call filter;
///                                 SRC_OWN_NETWORK: a network namespace of
///                                 its own (needs SRC_ISOLATED, else
///                                 EINVAL). Any other bit is EINVAL
///   [rootfs_len:u16][rootfs]      the root to pivot into; empty = none
///   [argv_len:u16][argv]          NUL-separated tokens, at least one
///   [env_len:u16][env]            NUL-separated `NAME=VALUE`: the WHOLE
///                                 environment — nothing of the runtime's
///                                 own reaches the process (`HOME` is added
///                                 when absent); a bare argv[0] is looked up
///                                 on this `PATH`
///   [cwd_len:u16][cwd]            absolute; empty = `/`
///   [user_len:u16][user]          `uid[:gid]` | `name[:group]` (resolved in
///                                 the root's /etc/passwd, /etc/group, read
///                                 inside the root); empty = the runtime's
///                                 own identity. The id 4294967295 is
///                                 EINVAL. A runtime without CAP_SETUID
///                                 refuses (`EACCES`) another uid, and one
///                                 without CAP_SETGID another gid
///   [groups_len:u16]              1 + 4n
///     [groups_flags:u8]           GROUPS_STRICT: the process holds the
///                                 primary gid and the listed ones only;
///                                 clear: also every group the root's
///                                 /etc/group names the user a member of.
///                                 Any other bit is EINVAL
///     [gid:u32 × n]               numeric supplementary groups, added to
///                                 the user's. A runtime without CAP_SETGID
///                                 runs them only when it already holds
///                                 them (strict: exactly that set;
///                                 `EACCES` otherwise)
///   [cap_add_len:u16]             8; present only with SRC_CAP_ADD
///     [cap_add:u64]               capabilities granted beyond the
///                                 defaults, bit n = capability n
///                                 (capabilities(7) numbering). A number
///                                 past the host's last is EINVAL; one the
///                                 runtime does not hold in both its
///                                 permitted and bounding sets, EACCES
/// ```
/// Confinement: every process of the workload — its own, an [`EXEC`], a
/// [`TTY_OPEN`] session — execs with `no_new_privs`, with these
/// capabilities, and under the system-call filter:
/// - The bounding set is cut to the granted set: the OCI default
///   capabilities (CHOWN, DAC_OVERRIDE, FSETID, FOWNER, MKNOD, NET_RAW,
///   SETGID, SETUID, SETFCAP, SETPCAP, NET_BIND_SERVICE, SYS_CHROOT, KILL,
///   AUDIT_WRITE) and `cap_add`. A runtime without CAP_SETPCAP cannot cut it
///   and leaves it whole; under `no_new_privs` that grants nothing beyond
///   the sets below.
/// - Running as uid 0, the process holds the granted set (as far as the
///   runtime holds it) effective and permitted, nothing inheritable or
///   ambient. Running as any other uid it holds `cap_add` only, in every
///   set including ambient, so the added capabilities survive its exec;
///   with no addition it holds none.
/// - The system-call filter is an allowlist modelled on the Docker default
///   seccomp profile: the architecture is checked first (a foreign one,
///   32-bit compat included, kills the process); a call off the list
///   answers `EPERM`; `clone` and `unshare`
///   are allowed without namespace flags only, `clone3` answers `ENOSYS`,
///   `personality` takes the plain Linux personalities only, `socket` every
///   family but `AF_VSOCK`; calls the profile ties to a capability (mount
///   and namespace creation to SYS_ADMIN, `ptrace` relatives to SYS_PTRACE,
///   the clock to SYS_TIME, and the rest) are allowed when it is granted.
///   SRC_NO_SYSCALL_FILTER runs the workload without it. Where [`CAPS`]
///   lacks [`caps::SYSCALL_FILTER`] no filter is installed.
/// - At posture HARDENED, SRC_CAP_ADD with a non-zero `cap_add`, and
///   SRC_NO_SYSCALL_FILTER, are EINVAL; a runtime that cannot cut the
///   bounding set answers EPERM.
///
/// Lifetime: a workload does not outlive the runtime process (a thread of
/// it ending is not the runtime ending). Each workload has an intermediate
/// process between the runtime and its init, which relays the init's status
/// exactly (an exit code as itself, a terminating signal as that signal).
/// When the runtime is gone the intermediate kills the init. SIGNAL and
/// DESTROY reach the init's process group through the intermediate, the one
/// process that reaps the init, so a signal never reaches a process that
/// took the init's pid after it ended. With ISOLATED
/// the init is PID 1 of the workload's pid namespace, so every process in
/// it ends with it. With SHARED the intermediate is a child subreaper: when
/// the init ends — by itself, by SIGNAL or DESTROY, or with the runtime —
/// every process the workload started that is still running is killed and
/// reaped, whatever process group or session it moved to. An EXEC and a
/// TTY session of an ISOLATED workload run inside its pid namespace, behind
/// an intermediate of their own that relays their status the same way; both
/// end with the runtime's dispatch thread.
///
/// Workload naming: READ, EXEC and TTY_OPEN take a `workload` handle under
/// that contract's rule — a handle is its minting module's owner's, and a
/// workload another owner's module created answers `EACCES`, unless the
/// caller acts with the node's authority (which names it by `LOOKUP`).
///
/// Devices (SRC_ISOLATED with a rootfs): the root and every volume are
/// `nodev`, and `/dev` is the workload's own memory filesystem (mode 0755,
/// nosuid, noexec, nodev) holding the host's null, zero, full, random,
/// urandom and tty bound in, `pts` (a new devpts instance, ptmxmode 0666),
/// `shm` (a memory filesystem of at most 64 MiB, or the workload's memory
/// quota when that is smaller), and the links fd, stdin, stdout, stderr and
/// ptmx. `/proc` is a new instance (nosuid, noexec, nodev) showing the
/// workload's pid namespace, with `sys`, `sysrq-trigger`, `irq`, `bus` and
/// `fs` read-only and `acpi`, `asound`, `kcore`, `keys`, `latency_stats`,
/// `sched_debug`, `scsi`, `timer_list` and `timer_stats` masked (the Docker
/// defaults). An EXEC or a TTY session joins the namespaces of the init
/// itself, through a pid descriptor: once the init has ended it is `ESRCH`.
/// The root is entered with `pivot_root(2)`: a host whose own root is the
/// initial ramfs, where that is refused, runs no isolated workload with a
/// rootfs (the init exits 123). An isolated workload needs Linux 5.12
/// (`mount_setattr`) and pid-descriptor `setns` (5.8); a kernel without them
/// fails it rather than isolate it less. An isolated workload without a
/// rootfs shares the host's filesystem and `/proc`.
/// Read-only root: the root mount alone is made read-only, last — after
/// the volumes, the fresh `/proc` and the working directory are in place —
/// so a volume keeps its own access and a missing working directory is
/// created all the same.
///
/// Isolation the host refuses (namespaces without the privilege) answers
/// CREATE with the kernel's errno (`EPERM`): a workload that asked for it
/// never runs without it.
///
/// NOT a workload package or OCI format: the backend reads no files but the user
/// databases of the workload's own root; the orchestrator composes the
/// params. Malformed → `EINVAL`. The native contract defines only
/// `SOURCE_FMOD_GRAPH = 0`; nonzero kinds are backend-defined.
pub const SOURCE_HOST_PROCESS: u8 = 1;

/// Source `flags` bit: the workload gets namespaces of its own.
pub const SRC_ISOLATED: u8 = 1 << 0;
/// Source `flags` bit: the workload's root is read-only (with
/// [`SRC_ISOLATED`] only).
pub const SRC_ROOT_READ_ONLY: u8 = 1 << 1;
/// Source `flags` bit: a `cap_add` part follows the groups part.
pub const SRC_CAP_ADD: u8 = 1 << 2;
/// Source `flags` bit: the workload runs without a system-call filter.
pub const SRC_NO_SYSCALL_FILTER: u8 = 1 << 3;
/// Source `flags` bit: the workload gets a network namespace of its own,
/// with only `lo` up (with [`SRC_ISOLATED`] only). Its address, the name
/// service it asks and the endpoints it may bind are the node's net
/// provider's to give it, from the node agent (`net::identity` on the
/// provider's `addr_ctl`, the owner plan's grants); without the bit it
/// shares the host's network.
pub const SRC_OWN_NETWORK: u8 = 1 << 4;
/// Source `groups_flags` bit: the listed groups and the primary only.
pub const GROUPS_STRICT: u8 = 1 << 0;

/// What this host realizes of the source above. `handle = -1`; `arg` out is
/// exactly 4 bytes, the `u32` LE [`caps`] word; no `data`. Returns 0. A bit
/// is set only when the runtime holds the privilege the feature needs, so a
/// writer that reads it never sends a request the host would refuse.
pub use super::super::super::registry::host_process::CAPS;

/// [`CAPS`] bits.
pub mod caps {
    /// [`super::SRC_ROOT_READ_ONLY`] is honoured.
    pub const ROOT_READ_ONLY: u32 = 1 << 0;
    /// Numeric supplementary groups are applied.
    pub const GROUPS: u32 = 1 << 1;
    /// [`super::GROUPS_STRICT`] is honoured.
    pub const GROUPS_STRICT: u32 = 1 << 2;
    /// [`super::SRC_CAP_ADD`] is honoured: the runtime holds CAP_SETPCAP,
    /// so it also cuts a workload's bounding set to the granted set. An
    /// added capability the runtime itself lacks is still `EACCES`.
    pub const CAP_ADD: u32 = 1 << 3;
    /// A workload runs under the default system-call filter, and
    /// [`super::SRC_NO_SYSCALL_FILTER`] runs one without it.
    pub const SYSCALL_FILTER: u32 = 1 << 4;
}

/// Kill the command if still running, reap it, and free its slot, through
/// its handle; the handle closes. No `arg`. Returns 0.
pub use super::super::super::registry::host_process::PROC_CLOSE;
/// Read the command's merged stdout and stderr, through its handle. `arg`
/// out = the output, at most [`PROC_READ_MAX`] bytes; returns the bytes
/// written, 0 when nothing is ready this step.
pub use super::super::super::registry::host_process::PROC_READ;
/// Run a command on the node itself (not in a workload): `handle = -1`, no
/// `arg`; `data` in = the command line (UTF-8, words split on whitespace).
/// A command runs with the node's authority, so a caller acting with an
/// authority of its own is refused `EACCES`. The executable must be on the
/// node's allowlist, which the operator configures for the host runtime
/// (empty unless configured: nothing runs); it starts in the configured
/// working directory with only the configured environment names. Returns
/// the command's handle, `EACCES` for a command off the allowlist, `ENOMEM`
/// with every slot in use. The command is its spawner's owner's, and is
/// killed when that owner is released.
pub use super::super::super::registry::host_process::PROC_SPAWN;
/// Whether the command has finished, through its handle: 1 while it runs
/// or output is still to be read, 0 once it has exited and every byte was
/// read. On 0, `arg` out `[code:i32]` ([`PROC_STATUS_ARG_LEN`]) receives its
/// exit code (i32 LE): `128 + signal` when a signal ended it, -1 when it
/// could not be read. A command past the configured timeout is killed and
/// reported so.
pub use super::super::super::registry::host_process::PROC_STATUS;

/// Most bytes one [`PROC_READ`] answers (its `arg` bound).
pub const PROC_READ_MAX: usize = 1024;
/// [`PROC_STATUS`]'s `arg` length.
pub const PROC_STATUS_ARG_LEN: usize = 4;

/// `workload` `CAPS` source-kind bit for [`SOURCE_HOST_PROCESS`], the linux
/// backend's own kind.
pub const CAPS_SOURCE_HOST_PROCESS: u32 =
    super::super::super::contracts::workload::caps::source_kind(SOURCE_HOST_PROCESS);
