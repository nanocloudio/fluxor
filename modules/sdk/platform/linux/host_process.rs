// Platform: linux host-process operations (contract class 0x1B).
//
// Layer: platform/linux (host-specific, unstable). Host-PROCESS mechanics —
// command execution, PTY sessions, stdout/stderr drains, the host-process
// source (root, argv, environment, identity) — are one backend's
// implementation vocabulary, not native Fluxor workload semantics, so they
// live here rather than in the stable `workload` (0x1A) contract. The native surface is
// CREATE/START/WAIT/SIGNAL/DESTROY/PAUSE/RESUME/CAPS.
//
// Calling convention: every op is a `handle = -1` call (the kernel routes
// handle-tagged calls by tag→class, and workload handles route to 0x1A), so
// ops that target a workload carry its tagged fd in the leading 4 bytes of
// `arg` (little-endian i32); TTY session ops carry the session id.
// The class is present only where the linux host platform registered it — an
// unregistered class returns `ENOSYS`, which IS the discovery.

/// Provider contract class for host-process ops.
pub const CLASS: u16 = 0x001B;

/// Drain merged stdout/stderr. `arg = [workload_fd: i32 LE][out …]`; returns
/// bytes written into `out` after the fd prefix (0 = none pending).
pub const READ: u32 = 0x1B01;
/// One-shot command in a running workload. `arg = [workload_fd: i32 LE]
/// [payload …]` (payload wire per the linux backend docs). The command
/// joins the workload — its namespaces (every one, or it does not run), its
/// cgroup, its environment, cwd and user — and holds no descriptor of the
/// runtime's. `EINVAL` before START or while the workload is PAUSEd, `ESRCH`
/// when its container is gone.
pub const EXEC: u32 = 0x1B02;
/// Open an interactive PTY session. `arg = [workload_fd: i32 LE][params …]`.
/// The session joins the workload as [`EXEC`] does, with the same refusals.
pub const TTY_OPEN: u32 = 0x1B03;
/// Pump a session (stdin/out/exit). Session id in `arg` (unchanged framing).
pub const TTY_STEP: u32 = 0x1B04;
/// Resize a session's window. Session id in `arg`.
pub const TTY_RESIZE: u32 = 0x1B05;
/// Kill+reap+free a session. Session id in `arg`.
pub const TTY_CLOSE: u32 = 0x1B06;

/// Host-only `source_kind` for the workload CREATE header: the source-ref
/// carries explicit host-process spawn params, realized by the linux
/// host-process backend. Little-endian, every part length-prefixed and
/// present, nothing after the last:
/// ```text
///   [flags:u8]                    SRC_ISOLATED: own namespaces (needs
///                                 privilege); SRC_ROOT_READ_ONLY: the root
///                                 is read-only once the process starts
///                                 (needs SRC_ISOLATED, else EINVAL); any
///                                 other bit is EINVAL
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
/// ```
/// Read-only root: the root mount alone is made read-only, last — after
/// the volumes, the fresh `/proc` and the working directory are in place —
/// so a volume keeps its own access and a missing working directory is
/// created all the same.
///
/// Isolation the host refuses (namespaces without the privilege) answers
/// CREATE with the kernel's errno (`EPERM`): a workload that asked for it
/// never runs without it.
///
/// NOT a bundle/OCI format: the backend reads no files but the user
/// databases of the workload's own root; the orchestrator composes the
/// params. Malformed → `EINVAL`. The native contract defines only
/// `SOURCE_FMOD_GRAPH = 0`; nonzero kinds are backend-defined.
pub const SOURCE_HOST_PROCESS: u8 = 1;

/// Source `flags` bit: the workload gets namespaces of its own.
pub const SRC_ISOLATED: u8 = 1 << 0;
/// Source `flags` bit: the workload's root is read-only (with
/// [`SRC_ISOLATED`] only).
pub const SRC_ROOT_READ_ONLY: u8 = 1 << 1;
/// Source `groups_flags` bit: the listed groups and the primary only.
pub const GROUPS_STRICT: u8 = 1 << 0;

/// What this host realizes of the source above. `handle = -1`, no
/// argument, no workload fd; returns the [`caps`] bit set. A bit is set only
/// when the runtime holds the privilege the feature needs, so a writer that
/// reads it never sends a request the host would refuse.
pub const CAPS: u32 = 0x1B00;

/// [`CAPS`] bits.
pub mod caps {
    /// [`super::SRC_ROOT_READ_ONLY`] is honoured.
    pub const ROOT_READ_ONLY: u32 = 1 << 0;
    /// Numeric supplementary groups are applied.
    pub const GROUPS: u32 = 1 << 1;
    /// [`super::GROUPS_STRICT`] is honoured.
    pub const GROUPS_STRICT: u32 = 1 << 2;
}

/// Host process-executor provider class (opcode class 0x16xx): a host-side
/// provider spawns a command and streams its output. Registered only by the
/// linux platform; the kernel routes its fd tag via the dynamic tag-route
/// registration, keeping the generic kernel free of host vocabulary.
pub const PROC_CLASS: u16 = 0x0016;

/// Spawn a command. `handle = -1`, `arg` = the command line (UTF-8, words
/// split on whitespace). The executable must be on the node's allowlist
/// (`SECTOR_PROC_ALLOW`); it starts in the granted root with only the
/// granted environment. Returns a [`FD_TAG_PROC`]-tagged handle, `EACCES`
/// for a command off the allowlist, `ENOMEM` with every slot in use.
pub const PROC_SPAWN: u32 = 0x1600;
/// Read merged stdout and stderr. `arg` = the output buffer; returns the
/// bytes written, 0 when nothing is ready this step.
pub const PROC_READ: u32 = 0x1601;
/// Whether the command has finished: 1 while it runs or output is still to
/// be read, 0 once it has exited and every byte was read. On 0, an `arg` of
/// at least 4 bytes receives its exit code (i32 LE): `128 + signal` when a
/// signal ended it, -1 when it could not be read. A command past the grant's
/// timeout is killed and reported so.
pub const PROC_STATUS: u32 = 0x1602;
/// Kill if still running, reap, and free the slot.
pub const PROC_CLOSE: u32 = 0x1603;

/// `workload` CAPS `source_kinds` bit for [`SOURCE_HOST_PROCESS`] (bit 1 — the
/// stable contract defines only bit 0, `SOURCE_FMOD_GRAPH`; higher bits are
/// backend-defined and this is the linux backend's).
pub const CAPS_SOURCE_HOST_PROCESS: u8 = 1 << 1;

/// Host process-executor handle tag (class [`PROC_CLASS`], 0x0016) —
/// the proc-executor's spawned-process handles. Numeric value is a kernel
/// fd-tag registry reservation; the semantic constant lives here.
pub const FD_TAG_PROC: i32 = 25;
