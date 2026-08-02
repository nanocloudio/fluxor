// Platform: linux host-process operations (contract class 0x1B).
//
// Layer: platform/linux (host-specific, unstable). Host-PROCESS mechanics —
// command execution, PTY sessions, stdout/stderr drains, rootfs bundles — are
// one backend's implementation vocabulary, not native Fluxor workload
// semantics, so they live here rather than in the stable `workload` (0x1A)
// contract (docs/architecture/abi_layers.md D-WORKLOAD-ABI). The
// native surface stays CREATE/START/WAIT/SIGNAL/DESTROY/PAUSE/RESUME/CAPS.
//
// Calling convention: every op is a `handle = -1` call (the kernel routes
// handle-tagged calls by tag→class, and workload handles route to 0x1A), so
// ops that target a workload carry its tagged fd in the leading 4 bytes of
// `arg` (little-endian i32); TTY session ops carry the session id as before.
// The class is present only where the linux host platform registered it — an
// unregistered class returns `ENOSYS`, which IS the discovery.

/// Provider contract class for host-process ops.
pub const CLASS: u16 = 0x001B;

/// Drain merged stdout/stderr. `arg = [workload_fd: i32 LE][out …]`; returns
/// bytes written into `out` after the fd prefix (0 = none pending).
pub const READ: u32 = 0x1B01;
/// One-shot command in a running workload. `arg = [workload_fd: i32 LE]
/// [payload …]` (payload wire per the linux backend docs).
pub const EXEC: u32 = 0x1B02;
/// Open an interactive PTY session. `arg = [workload_fd: i32 LE][params …]`.
pub const TTY_OPEN: u32 = 0x1B03;
/// Pump a session (stdin/out/exit). Session id in `arg` (unchanged framing).
pub const TTY_STEP: u32 = 0x1B04;
/// Resize a session's window. Session id in `arg`.
pub const TTY_RESIZE: u32 = 0x1B05;
/// Kill+reap+free a session. Session id in `arg`.
pub const TTY_CLOSE: u32 = 0x1B06;

/// Host-only `source_kind` for the workload CREATE header: the source-ref
/// carries explicit host-process spawn params (argv, optional rootfs path,
/// isolate flag — see `workload.rs`), realized by the linux host-process
/// backend. NOT a bundle/OCI format: the backend reads no files; the
/// orchestrator composes the params. The native contract defines only
/// `SOURCE_FMOD_GRAPH = 0`; nonzero kinds are backend-defined.
pub const SOURCE_HOST_PROCESS: u8 = 1;

/// Host process-executor provider class (opcode class 0x16xx): a host-side
/// provider spawns a command and streams its output. Registered only by the
/// linux platform; the kernel routes its fd tag via the dynamic tag-route
/// registration, keeping the generic kernel free of host vocabulary.
pub const PROC_CLASS: u16 = 0x0016;

/// `workload` CAPS `source_kinds` bit for [`SOURCE_HOST_PROCESS`] (bit 1 — the
/// stable contract defines only bit 0, `SOURCE_FMOD_GRAPH`; higher bits are
/// backend-defined and this is the linux backend's).
pub const CAPS_SOURCE_HOST_PROCESS: u8 = 1 << 1;

/// Host process-executor handle tag (class [`PROC_CLASS`], 0x0016) —
/// the proc-executor's spawned-process handles. Numeric value is a kernel
/// fd-tag registry reservation; the semantic constant lives here.
pub const FD_TAG_PROC: i32 = 25;
