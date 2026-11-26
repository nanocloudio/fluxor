// ============================================================================
// Linux `workload` provider (contract class `workload`) — the consumer-facing
// isolated-workload surface.
// ============================================================================
//
// This provider is the platform-neutral front for isolated workloads. It parses
// the spec header, resolves the identity to a plan-allocated owner,
// lease-gates admission, enforces the options envelope FAIL-CLOSED
// against the resolved backend's advertised capabilities, then delegates to the
// backend. On Linux the only backend is the host-process backend — the
// owner-bound `host_backend.rs` mechanism (namespaces/cgroups); an fmod-graph source has
// no Linux realization and is refused (it resolves to the MPU/EL0 backend on a
// metal node, by placement).
//
// Composes the host-process backend in the sibling `host_backend` module.

use super::host_backend::{
    hp_destroy, hp_exec, hp_pause, hp_read, hp_resume, hp_signal, hp_spawn_with_binds, hp_start,
    hp_tty_close, hp_tty_open, hp_tty_resize, hp_tty_step, hp_wait, ResourceEnvelope,
    MAX_SANDBOXES,
};
use crate::abi::contracts::workload as wl;
use crate::abi::platform::linux::host_process as hp;
use crate::kernel::module::user_span::UserSpan;
use crate::kernel::workload::owner::OwnerHandle;

// Host-process ops (class `host_process`, `abi::platform::linux::host_process`
// has the wire formats) arrive at [`host_process_dispatch`] with what the
// handle names, as this provider calls it: an op on a workload with the
// workload's index (its `workload` handle, which the contract accepts), a
// session op with the session's index, a node command op with the
// command's.

/// The workload-index range: one workload per sandbox. The table is sized
/// at boot with the sandbox table ([`size_workloads`]).
const MAX_WORKLOADS: usize = MAX_SANDBOXES;
const _: () = assert!(
    crate::kernel::workload::owner::MAX_OWNERS <= HOST_SLOT_BASE as usize,
    "the graph backend's workload slots must stay below the host-process backend's"
);

/// One admitted workload: its owner and the host-process backend slot it maps
/// to (the host-process backend's; its handle index is its slot above
/// [`HOST_SLOT_BASE`], a graph workload's is the graph backend's own slot).
#[derive(Clone, Copy)]
struct WorkloadSlot {
    in_use: bool,
    owner: OwnerHandle,
    backend_idx: i32,
    /// This backend allocated the owner at CREATE (its identity named no
    /// owner the plan holds), so its DESTROY frees it.
    allocated: bool,
    /// The owner of the module that created it: only that owner, or a
    /// caller acting with the node's authority, acts on it ([`may_use`]).
    holder: OwnerHandle,
}

const WORKLOAD_EMPTY: WorkloadSlot = WorkloadSlot {
    in_use: false,
    owner: crate::kernel::workload::owner::OWNER_NODE,
    backend_idx: -1,
    allocated: false,
    holder: crate::kernel::workload::owner::OWNER_NODE,
};

/// Whether the calling module may act on a workload `slot` holds: its
/// owner created it, or it acts with the node's authority (the node agent).
fn may_use(slot: &WorkloadSlot) -> bool {
    use crate::kernel::exec::scheduler;
    scheduler::caller_authority() == crate::kernel::workload::owner::OWNER_NODE
        || scheduler::caller_owner() == slot.holder
}

/// End the slot's workload: its sandbox goes, and an owner this backend
/// allocated is freed with its storage root, as the graph backend frees one
/// at DESTROY. Returns the sandbox's answer.
unsafe fn release_slot(idx: usize) -> i32 {
    let slots = &mut *core::ptr::addr_of_mut!(LINUX_WORKLOADS);
    let slot = slots[idx];
    let rc = hp_destroy(slot.backend_idx);
    super::host_lane::owner_facts::ended(slot.owner);
    slots[idx] = WORKLOAD_EMPTY;
    retire_handles(idx);
    if slot.allocated {
        free_allocated_owner(slot.owner);
    }
    rc
}

/// Free an owner this backend allocated. It holds no modules and no net
/// lanes (those are the graph backend's), so its release is the providers'
/// edge — open files closed, its store dropped, its storage root removed —
/// then the slot.
unsafe fn free_allocated_owner(owner: OwnerHandle) {
    crate::kernel::module::provider::notify_owner_released(owner);
    crate::kernel::exec::scheduler::owners_mut().free(owner);
}

static mut LINUX_WORKLOADS: crate::kernel::mem::table::Table<WorkloadSlot, MAX_WORKLOADS> = crate::boot_table!(
    MAX_WORKLOADS,
    WORKLOAD_EMPTY,
    crate::abi::contracts::resource::POOL_SANDBOXES
);

/// Size the workload table to the sandbox table's `n` slots, all committed.
///
/// # Safety
/// Graph-preparation context: no reference into the table is live.
pub unsafe fn size_workloads(n: usize) -> Result<(), crate::kernel::mem::table::TableError> {
    if n > MAX_WORKLOADS {
        return Err(crate::kernel::mem::table::TableError::Ceiling);
    }
    let t = &*core::ptr::addr_of!(LINUX_WORKLOADS);
    t.reserve(n)?;
    t.grow(n)
}

#[inline]
fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// The postures the host-process backend realizes. `SHARED` is a null
/// sandbox and `ISOLATED` namespaces of the workload's own with its cgroup;
/// every workload, at either, is confined (`confine.rs`: the OCI default
/// capabilities, `no_new_privs`, the default system-call filter) unless its
/// source opts out. `HARDENED` is `ISOLATED` with that confinement whole —
/// no capability added, no opt-out, the bounding set cut — and is realized
/// only where the system-call filter is (`confine::filter_available`). A
/// posture it does not realize, or a required option entry it does not
/// list, fails admission (`ENOSYS`) rather than running under-hardened.
fn host_backend_honors_posture(posture: u8) -> bool {
    match posture {
        wl::POSTURE_SHARED | wl::POSTURE_ISOLATED => true,
        wl::POSTURE_HARDENED => super::confine::filter_available(),
        _ => false,
    }
}

/// The postures [`CAPS`](wl::CAPS) advertises: those
/// [`host_backend_honors_posture`] realizes.
fn host_backend_postures() -> u32 {
    let mut p = wl::caps::POSTURE_SHARED | wl::caps::POSTURE_ISOLATED;
    if host_backend_honors_posture(wl::POSTURE_HARDENED) {
        p |= wl::caps::POSTURE_HARDENED;
    }
    p
}
/// Options entries this backend realizes. `mount`/`bind` is a volume
/// (`wl::volume`): the value is `<host path>\0<path in the workload>\0<ro:
/// 1|0>`, bind-mounted into the rootfs before the pivot
/// (`host_backend::hp_spawn_with_binds`). `env`/`var` (`wl::env`) is one
/// `NAME=VALUE` of the process's environment, over the source's own.
fn host_backend_honors_option(ns: &[u8], key: &[u8]) -> bool {
    (ns == wl::volume::NS && key == wl::volume::KEY) || (ns == wl::env::NS && key == wl::env::KEY)
}

/// The options directory [`OPTIONS`](wl::OPTIONS) lists: what the
/// host-process backend realizes. The graph backend realizes none: a graph
/// workload's environment is bound into its params by its creator, and its
/// volumes are lent by the node's workload `fs` layer.
const LINUX_OPTIONS: &[(&[u8], &[&[u8]])] = &[
    (wl::volume::NS, &[wl::volume::KEY]),
    (wl::env::NS, &[wl::env::KEY]),
];

/// Put the CREATE's `env`/`var` entries into a process's environment, in
/// order, each replacing any entry of its name. `EINVAL` for an entry with
/// no name or one that is not UTF-8.
fn apply_env_options(opts: &[u8], env: &mut std::vec::Vec<std::string::String>) -> Result<(), i32> {
    use crate::kernel::sys::errno;
    for o in wl::opt::iter(opts) {
        let o = o.map_err(|()| errno::EINVAL)?;
        if o.ns != wl::env::NS || o.key != wl::env::KEY {
            continue;
        }
        let entry = core::str::from_utf8(o.val).map_err(|_| errno::EINVAL)?;
        let Some(eq) = entry.find('=').filter(|&eq| eq > 0) else {
            return Err(errno::EINVAL);
        };
        let prefix = &entry[..=eq];
        env.retain(|e| !e.starts_with(prefix));
        env.push(entry.into());
    }
    Ok(())
}

/// A `mount`/`bind` value: `<src>\0<dst>[\0<ro>]`, `ro` `1` (read-only) or
/// `0`. Anything else — another `ro` spelling, a fourth part — is malformed,
/// never read as writable.
fn parse_bind(val: &[u8]) -> Option<super::host_backend::VolumeBind> {
    let mut parts = val.split(|b| *b == 0);
    let src = core::str::from_utf8(parts.next()?).ok()?;
    let dst = core::str::from_utf8(parts.next()?).ok()?;
    let ro = match parts.next() {
        None | Some(b"0") => false,
        Some(b"1") => true,
        Some(_) => return None,
    };
    if src.is_empty() || dst.is_empty() || parts.next().is_some() {
        return None;
    }
    Some(super::host_backend::VolumeBind {
        src: src.into(),
        dst: dst.into(),
        ro,
    })
}
/// Whether this host can freeze at all: cgroup2 is mounted (`cgroup.freeze`
/// is core cgroup2 surface, present on every v2 cgroup since Linux 5.2 — not
/// a controller) and a base cgroup for per-sandbox dirs resolves — the same
/// preconditions `hp_apply_cgroup` relies on. Probed once per process; the
/// per-workload gate still applies: a workload whose best-effort cgroup setup
/// failed gets ENOSYS from PAUSE.
fn host_backend_can_freeze() -> bool {
    static CAN_FREEZE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CAN_FREEZE.get_or_init(|| {
        std::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers").is_ok()
            && super::host_backend::cgroup_base().is_some()
    })
}

/// Validate the TLV options envelope. Advisory entries a backend does not
/// understand are ignored; a REQUIRED entry it does not advertise fails
/// admission. Returns `Ok(())` or a negative errno.
fn validate_options(
    opts: &[u8],
    binds: &mut std::vec::Vec<super::host_backend::VolumeBind>,
) -> Result<(), i32> {
    use crate::kernel::sys::errno;
    for o in wl::opt::iter(opts) {
        let o = o.map_err(|()| errno::EINVAL)?;
        if o.ns == wl::volume::NS && o.key == wl::volume::KEY {
            match parse_bind(o.val) {
                Some(b) => binds.push(b),
                None => return Err(errno::EINVAL),
            }
        }
        // Fail-closed: a required entry the backend cannot honor blocks admission.
        if o.required() && !host_backend_honors_option(o.ns, o.key) {
            return Err(errno::ENOSYS);
        }
    }
    Ok(())
}

/// The host-process source section (`SOURCE_HOST_PROCESS`), little-endian,
/// every part length-prefixed and present, in this order:
/// ```text
///   [flags:u8]                         SRC_ISOLATED | SRC_ROOT_READ_ONLY |
///                                      SRC_CAP_ADD | SRC_NO_SYSCALL_FILTER |
///                                      SRC_OWN_NETWORK
///   [rootfs_len:u16][rootfs]           the root to pivot into; empty = none
///   [argv_len:u16][argv]               NUL-separated tokens, at least one
///   [env_len:u16][env]                 NUL-separated `NAME=VALUE` — the WHOLE
///                                      environment; empty = none at all
///   [cwd_len:u16][cwd]                 absolute; empty = `/`
///   [user_len:u16][user]               `uid[:gid]` | `name[:group]`; empty =
///                                      the runtime's own identity
///   [groups_len:u16][groups_flags:u8][gid:u32 × n]
///                                      groups_len = 1 + 4n; GROUPS_STRICT
///   [cap_add_len:u16 = 8][cap_add:u64] with SRC_CAP_ADD only: capabilities
///                                      granted beyond the defaults
/// ```
/// Nothing may follow the last part. A read-only root without isolation is
/// EINVAL (there is no mount namespace of its own to make read-only), and so
/// is any flag bit this backend does not define. The backend's rules for
/// each part are `host_backend`'s (`plan_process`).
pub struct HostSource<'a> {
    pub isolate: bool,
    /// A network namespace of its own (`SRC_OWN_NETWORK`).
    pub own_network: bool,
    pub rootfs: Option<&'a str>,
    pub argv: std::vec::Vec<&'a str>,
    pub process: super::host_backend::ProcessParams,
}

/// Parse a host-process source section; EINVAL for anything malformed —
/// a part that overruns, bytes past the last part, text that is not UTF-8,
/// a groups part that is not `1 + 4n` long, an undefined flag bit, or no
/// argv.
pub fn parse_host_source(src: &[u8]) -> Result<HostSource<'_>, i32> {
    fn text(b: &[u8]) -> Result<&str, i32> {
        core::str::from_utf8(b).map_err(|_| crate::kernel::sys::errno::EINVAL)
    }
    use crate::kernel::sys::errno;
    let mut p = 1usize;
    let flags = *src.first().ok_or(errno::EINVAL)?;
    if flags
        & !(hp::SRC_ISOLATED
            | hp::SRC_ROOT_READ_ONLY
            | hp::SRC_CAP_ADD
            | hp::SRC_NO_SYSCALL_FILTER
            | hp::SRC_OWN_NETWORK)
        != 0
    {
        return Err(errno::EINVAL);
    }
    let isolate = flags & hp::SRC_ISOLATED != 0;
    let root_read_only = flags & hp::SRC_ROOT_READ_ONLY != 0;
    let own_network = flags & hp::SRC_OWN_NETWORK != 0;
    if (root_read_only || own_network) && !isolate {
        return Err(errno::EINVAL);
    }
    let mut part = || -> Result<&[u8], i32> {
        let n = src
            .get(p..p + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
            .ok_or(errno::EINVAL)?;
        let v = src.get(p + 2..p + 2 + n).ok_or(errno::EINVAL)?;
        p += 2 + n;
        Ok(v)
    };
    let rootfs = part()?;
    let argv = part()?;
    let env = part()?;
    let cwd = part()?;
    let user = part()?;
    let groups = part()?;
    let cap_add = if flags & hp::SRC_CAP_ADD != 0 {
        let b: [u8; 8] = part()?.try_into().map_err(|_| errno::EINVAL)?;
        u64::from_le_bytes(b)
    } else {
        0
    };
    if p != src.len() {
        return Err(errno::EINVAL);
    }
    let Some((&gflags, gids)) = groups.split_first() else {
        return Err(errno::EINVAL);
    };
    if gflags & !hp::GROUPS_STRICT != 0 || gids.len() % 4 != 0 {
        return Err(errno::EINVAL);
    }
    let rootfs = Some(text(rootfs)?).filter(|r| !r.is_empty());
    let mut args = std::vec::Vec::new();
    for tok in argv.split(|b| *b == 0).filter(|t| !t.is_empty()) {
        args.push(text(tok)?);
    }
    if args.is_empty() {
        return Err(errno::EINVAL);
    }
    let mut vars = std::vec::Vec::new();
    for e in env.split(|b| *b == 0).filter(|t| !t.is_empty()) {
        vars.push(text(e)?.to_string());
    }
    Ok(HostSource {
        isolate,
        own_network,
        rootfs,
        argv: args,
        process: super::host_backend::ProcessParams {
            env: vars,
            cwd: text(cwd)?.to_string(),
            user: text(user)?.to_string(),
            groups: gids
                .chunks_exact(4)
                .map(|g| u32::from_le_bytes([g[0], g[1], g[2], g[3]]))
                .collect(),
            groups_strict: gflags & hp::GROUPS_STRICT != 0,
            root_read_only,
            cap_add,
            no_syscall_filter: flags & hp::SRC_NO_SYSCALL_FILTER != 0,
            hardened: false,
        },
    })
}

/// `CREATE` on the host-process backend: admit + instantiate a workload from
/// the header + the variable-length source-ref / endpoint / options
/// sections. Returns the workload slot's index or a negative errno.
/// An owner this call allocates is freed again when the call refuses, so a
/// refused CREATE leaves nothing.
unsafe fn workload_create(arg: &[u8]) -> i32 {
    let mut allocated: Option<OwnerHandle> = None;
    let rc = workload_create_as(arg, &mut allocated);
    if rc < 0 {
        if let Some(owner) = allocated {
            free_allocated_owner(owner);
        }
    }
    rc
}

unsafe fn workload_create_as(buf: &[u8], allocated: &mut Option<OwnerHandle>) -> i32 {
    use crate::kernel::sys::errno;

    let Some((h, src_range, opt_range)) = wl::CreateHeader::parse(buf) else {
        return errno::EINVAL;
    };
    let identity = h.identity;
    let posture = h.posture;
    let source_kind = h.source_kind;
    let storage_line = match h.storage {
        wl::STORAGE_OWN_ROOT => true,
        wl::STORAGE_NONE => false,
        _ => return errno::EINVAL,
    };
    let envelope = ResourceEnvelope {
        compute_milli: h.compute_milli,
        memory_bytes: h.memory_bytes,
        max_tasks: h.max_tasks,
    };

    // An fmod graph went to the module-graph backend in the dispatch; any
    // other kind this backend does not run.
    if source_kind != hp::SOURCE_HOST_PROCESS {
        return errno::ENOSYS;
    }
    if !host_backend_honors_posture(posture) {
        return errno::ENOSYS; // a posture this host cannot realize
    }

    // Identity → owner. A workload names who it is: the null identity names
    // no one, and everything keyed on an owner would see every such workload
    // as one, so it is refused. An identity the plan allocated runs as that
    // owner. Any other is given an owner of its own here, the same rule the
    // graph backend allocates by (lowest free slot, monotonic generation),
    // and that owner lives as long as the workload: DESTROY frees it with
    // its storage root. One identity is one workload, whichever backend runs
    // it.
    if identity == [0u8; 16] {
        return errno::EINVAL;
    }
    if crate::kernel::workload::workload_graph::holds_identity(&identity) {
        return errno::EEXIST;
    }
    let owner = match crate::kernel::exec::scheduler::owners().find_by_uid(identity) {
        Some(h) => {
            let slots = &*core::ptr::addr_of!(LINUX_WORKLOADS);
            if slots.iter().any(|s| s.in_use && s.owner == h) {
                return errno::EEXIST;
            }
            h
        }
        None => match crate::kernel::exec::scheduler::owners_mut().alloc(identity) {
            Some(h) => {
                // Admitted in this one call, so active at once; a refusal
                // below frees it (`workload_create`).
                crate::kernel::exec::scheduler::owners_mut()
                    .set_state(h, crate::kernel::workload::owner::OwnerState::Active);
                *allocated = Some(h);
                h
            }
            None => return errno::ENOMEM, // every owner slot is taken
        },
    };
    if !crate::kernel::exec::scheduler::owners().authorize_admit(owner) {
        return errno::EACCES; // draining/revoked owner cannot admit new work
    }
    // The owner's storage line, as the header names it.
    let storage_bytes = h.storage_bytes;
    {
        use crate::abi::contracts::resource::OWNER_LINE_STORAGE;
        let owners = crate::kernel::exec::scheduler::owners_mut();
        if storage_line {
            owners.set_line(owner, OWNER_LINE_STORAGE, storage_bytes);
        } else {
            owners.remove_line(owner, OWNER_LINE_STORAGE);
        }
    }

    // Options: fail-closed against the backend's advertised capabilities.
    let mut binds = std::vec::Vec::new();
    if let Err(e) = validate_options(&buf[opt_range.clone()], &mut binds) {
        return e;
    }

    // Spawn on the host-process backend, bound to the owner. The source section
    // carries EXPLICIT spawn params (the orchestrator composes them from its own
    // bundle/OCI format — this backend has no bundle knowledge), see
    // `parse_host_source`.
    let mut src = match parse_host_source(&buf[src_range]) {
        Ok(s) => s,
        Err(e) => return e,
    };
    if let Err(e) = apply_env_options(&buf[opt_range], &mut src.process.env) {
        return e;
    }
    // The posture is the isolation: namespaces of its own at ISOLATED and
    // above, none at SHARED, and the source's flag must say the same. A
    // hardened workload takes no addition and no opt-out.
    if src.isolate != (posture >= wl::POSTURE_ISOLATED) {
        return errno::EINVAL;
    }
    if posture == wl::POSTURE_HARDENED {
        if src.process.cap_add != 0 || src.process.no_syscall_filter {
            return errno::EINVAL;
        }
        src.process.hardened = true;
    }
    let backend_idx = hp_spawn_with_binds(
        &src.argv,
        src.rootfs,
        src.isolate,
        &envelope,
        src.own_network,
        &binds,
        &src.process,
    );
    // What the owner may hold, beside what it was asked to run: the line an
    // operator reads to see a workload's envelope arrive.
    if backend_idx >= 0 {
        log::info!(
            "[workload] host workload {}.{}: compute_milli={} memory_bytes={} max_tasks={} storage_bytes={}",
            owner.slot,
            owner.generation,
            envelope.compute_milli,
            envelope.memory_bytes,
            envelope.max_tasks,
            storage_bytes
        );
    }
    if backend_idx < 0 {
        return backend_idx;
    }

    let slots = &mut *core::ptr::addr_of_mut!(LINUX_WORKLOADS);
    let widx = match slots.iter().position(|s| !s.in_use) {
        Some(i) => i,
        None => {
            crate::kernel::sys::resource_ledger::deny(
                crate::abi::contracts::resource::POOL_SANDBOXES,
            );
            // No workload slot: don't leak the backend sandbox.
            hp_destroy(backend_idx);
            return errno::ENOMEM;
        }
    };
    slots[widx] = WorkloadSlot {
        in_use: true,
        owner,
        backend_idx,
        allocated: allocated.is_some(),
        holder: crate::kernel::exec::scheduler::caller_owner(),
    };
    // Host providers that take owner facts learn the owner's process.
    if let Some(pid) = super::host_backend::hp_container_pid(backend_idx) {
        super::host_lane::owner_facts::started(owner, pid);
    }
    widx as i32
}

/// The sandbox behind workload slot `raw`, for the calling module: `EINVAL`
/// for no such workload, `EACCES` for one it may not act on ([`may_use`]).
unsafe fn workload_backend_idx(raw: i32) -> Result<i32, i32> {
    use crate::kernel::sys::errno;
    let slots = &*core::ptr::addr_of!(LINUX_WORKLOADS);
    match usize::try_from(raw).ok().and_then(|i| slots.get(i)) {
        Some(s) if s.in_use && may_use(s) => Ok(s.backend_idx),
        Some(s) if s.in_use => Err(errno::EACCES),
        _ => Err(errno::EINVAL),
    }
}

/// Map the portable SIGNAL subset to the host signal number.
fn portable_signo(signo: u32) -> Option<u8> {
    match signo {
        wl::SIG_TERM => Some(libc::SIGTERM as u8),
        wl::SIG_KILL => Some(libc::SIGKILL as u8),
        _ => None,
    }
}

/// The host-process workload slot whose owner carries `identity`.
unsafe fn slot_by_identity(identity: &[u8]) -> Option<usize> {
    let slots = &*core::ptr::addr_of!(LINUX_WORKLOADS);
    let owners = crate::kernel::exec::scheduler::owners();
    (0..slots.len()).find(|&i| {
        slots[i].in_use
            && owners
                .lookup(slots[i].owner)
                .is_some_and(|e| e.owner_uid[..] == *identity)
    })
}

/// First handle index of the host-process backend's workloads. A workload
/// whose source is an fmod graph is staged into this runtime's own live graph
/// by the kernel's module-graph backend, the one bare metal runs, and its
/// handle index is that backend's slot, as on metal (the backend retires the
/// handles naming a slot as it frees it); host-process slots are offset here
/// so they never collide with it.
const HOST_SLOT_BASE: i32 = 0x1000;

/// Retire every handle naming host-process slot `idx`, freed.
fn retire_handles(idx: usize) {
    crate::kernel::module::provider::retire_routes_naming(
        crate::abi::registry::workload::ID,
        HOST_SLOT_BASE + idx as i32,
    );
}

/// `workload` provider dispatch. CREATE is `handle = -1`; lifecycle ops are
/// handed the workload's index (what its handle's route carries).
///
/// Two backends answer, chosen by the CREATE's source kind: a host-process
/// bundle runs as an isolated host process, and an fmod graph is staged into
/// the live graph by `kernel::workload::workload_graph`. Single-threaded
/// platform dispatch: the `static mut` provider state is touched only on the
/// scheduler thread.
pub fn linux_workload_dispatch(
    handle: i32,
    opcode: u32,
    arg: &mut [u8],
    data: UserSpan<'_>,
) -> i32 {
    // The kernel's release notice (`provider::observe_owner_release`): what
    // the owner holds of the host goes with it.
    if opcode == crate::abi::internal::reconfigure::OWNER_RELEASED {
        let Some(rec) = arg.get(..8) else {
            return crate::kernel::sys::errno::EINVAL;
        };
        let owner = OwnerHandle {
            slot: u16::from_le_bytes([rec[0], rec[1]]),
            generation: u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]),
        };
        super::owner_release::release_owner(owner);
        return 0;
    }
    // SAFETY: provider dispatch runs on the scheduler thread, the only
    // thread touching the workload and backend tables.
    unsafe { workload_dispatch_on_thread(handle, opcode, arg, data) }
}

/// [`linux_workload_dispatch`]'s body.
///
/// # Safety
/// Scheduler thread only: touches `static mut` provider state without
/// synchronization.
unsafe fn workload_dispatch_on_thread(
    handle: i32,
    opcode: u32,
    arg: &mut [u8],
    mut data: UserSpan<'_>,
) -> i32 {
    use crate::kernel::sys::errno;

    use crate::kernel::workload::workload_graph;

    if opcode == wl::CREATE {
        // An fmod graph, and a graph bringing its own modules, are the
        // graph backend's; everything else is a host process.
        if matches!(
            arg.get(17),
            Some(&wl::SOURCE_FMOD_GRAPH) | Some(&wl::SOURCE_FMOD_PACK)
        ) {
            return workload_graph::workload_dispatch(-1, opcode, arg, data.reborrow());
        }
        let rc = workload_create(arg);
        return if rc < 0 { rc } else { HOST_SLOT_BASE + rc };
    }
    if opcode == wl::CAPS {
        return crate::abi::kernel_abi::caps_word::answer(arg, workload_caps());
    }
    if opcode == wl::OPTIONS {
        return workload_options(data.as_mut());
    }
    // The owner facts are the kernel's, the same read on every target.
    if opcode == wl::OWNERS {
        return workload_graph::workload_dispatch(-1, opcode, arg, data.reborrow());
    }
    // What the node's own image holds, for pinning a pack against it.
    // By identity: the graph backend first (a staged CREATE, or a graph
    // workload), then the host-process slots.
    if opcode == wl::LOOKUP || (opcode == wl::DESTROY && handle < 0) {
        let rc = workload_graph::workload_dispatch(-1, opcode, arg, data.reborrow());
        if rc != errno::ENOENT {
            return rc;
        }
        let Some(id) = arg.get(..16) else {
            return errno::EINVAL;
        };
        let Some(idx) = slot_by_identity(id) else {
            return errno::ENOENT;
        };
        let slots = &*core::ptr::addr_of!(LINUX_WORKLOADS);
        if !may_use(&slots[idx]) {
            return errno::EACCES;
        }
        if opcode == wl::LOOKUP {
            let owner = slots[idx].owner;
            let out = &mut arg[..6];
            out[0..2].copy_from_slice(&owner.slot.to_le_bytes());
            out[2..6].copy_from_slice(&owner.generation.to_le_bytes());
            return HOST_SLOT_BASE + idx as i32;
        }
        return release_slot(idx);
    }

    if (0..HOST_SLOT_BASE).contains(&handle) {
        return workload_graph::workload_dispatch(handle, opcode, arg, data.reborrow());
    }
    let raw = handle.saturating_sub(HOST_SLOT_BASE);
    let bidx = match workload_backend_idx(raw) {
        Ok(b) => b,
        Err(e) => return e,
    };
    match opcode {
        wl::START => hp_start(bidx),
        wl::PAUSE => hp_pause(bidx),
        wl::RESUME => hp_resume(bidx),
        wl::WAIT => hp_wait(bidx, arg),
        wl::SIGNAL => {
            if arg.len() < 4 {
                return errno::EINVAL;
            }
            let signo = rd_u32(arg, 0);
            let Some(hostsig) = portable_signo(signo) else {
                return errno::EINVAL;
            };
            hp_signal(bidx, &[hostsig])
        }
        wl::DESTROY => release_slot(raw as usize),
        _ => errno::ENOSYS,
    }
}

/// `CAPS`: the linux backend's capability word.
fn workload_caps() -> u32 {
    // Both backends: a host-process bundle, and an fmod graph staged into
    // the live graph — with its own modules where the kernel has code space
    // for packs. Each refuses at CREATE what it cannot honour.
    let sources = hp::CAPS_SOURCE_HOST_PROCESS
        | wl::caps::SOURCE_FMOD_GRAPH
        | if crate::kernel::workload::code_pack::POOL_SIZE > 0 {
            wl::caps::SOURCE_FMOD_PACK
        } else {
            0
        };
    // Optional ops: SIGNAL by real signal delivery (to the process group),
    // LOOKUP, and PAUSE iff the host can freeze at all (cgroup2 present) — a
    // workload whose own cgroup setup failed gets ENOSYS from it.
    let mut ops = wl::caps::SIGNAL | wl::caps::LOOKUP;
    if host_backend_can_freeze() {
        ops |= wl::caps::PAUSE;
    }
    host_backend_postures() | sources | ops
}

/// `OPTIONS`: the namespace directory ([`LINUX_OPTIONS`]): `mount`/`bind` (a
/// volume) and `env`/`var` (the environment).
fn workload_options(out: &mut [u8]) -> i32 {
    match crate::kernel::workload::workload_graph::write_option_directory(out, LINUX_OPTIONS) {
        0 => crate::kernel::sys::errno::ERANGE,
        n => n as i32,
    }
}

/// Destroy every workload belonging to an owner being freed. Called from the
/// platform's owner release (`owner_release`) on every `free_owner`, which
/// frees the owner itself, so the slot is only cleared here.
pub fn linux_workload_close_owner(owner: OwnerHandle) {
    // SAFETY: platform-thread single-writer access to the workload table and the
    // backend slots it owns.
    unsafe {
        let slots = &mut *core::ptr::addr_of_mut!(LINUX_WORKLOADS);
        for (idx, slot) in slots.iter_mut().enumerate() {
            if slot.in_use && slot.owner == owner {
                hp_destroy(slot.backend_idx);
                *slot = WORKLOAD_EMPTY;
                retire_handles(idx);
            }
        }
    }
}

/// Host-process provider dispatch — the linux host mechanics that sit
/// beside the stable `workload` surface. `handle` is the provider's index of
/// what the op acts on: READ, EXEC and TTY_OPEN a workload's (the index its
/// `workload` handle carries), the TTY ops a session's, the PROC ops a node
/// command's; PROC_SPAWN and CAPS take none.
pub fn host_process_dispatch(
    handle: i32,
    opcode: u32,
    arg: &mut [u8],
    mut data: UserSpan<'_>,
) -> i32 {
    use crate::kernel::sys::errno;

    // What this host realizes of the source.
    if opcode == hp::CAPS {
        return crate::abi::kernel_abi::caps_word::answer(arg, super::host_backend::hp_caps());
    }
    // The node's own commands.
    if matches!(
        opcode,
        hp::PROC_SPAWN | hp::PROC_READ | hp::PROC_STATUS | hp::PROC_CLOSE
    ) {
        return super::providers::proc_dispatch(handle, opcode, arg, data);
    }
    // SAFETY (each block below): provider dispatch runs on the scheduler
    // thread, the only thread touching the backend's slot and session tables.
    match opcode {
        // SAFETY: as above.
        hp::TTY_STEP => return unsafe { hp_tty_step(handle, arg, data.as_mut()) },
        // SAFETY: as above.
        hp::TTY_RESIZE => return unsafe { hp_tty_resize(handle, arg) },
        // SAFETY: as above.
        hp::TTY_CLOSE => return unsafe { hp_tty_close(handle) },
        hp::READ | hp::EXEC | hp::TTY_OPEN => {}
        _ => return errno::ENOSYS,
    }

    // Workload ops: a graph workload's index runs no host process.
    if handle < HOST_SLOT_BASE {
        return errno::EINVAL;
    }
    // SAFETY: as above.
    let bidx = match unsafe { workload_backend_idx(handle - HOST_SLOT_BASE) } {
        Ok(b) => b,
        Err(e) => return e,
    };
    // SAFETY: as above.
    unsafe {
        match opcode {
            hp::READ => hp_read(bidx, data.as_mut()),
            hp::EXEC => hp_exec(bidx, arg, data.as_mut()),
            _ => hp_tty_open(bidx, arg, data.as_slice()),
        }
    }
}
