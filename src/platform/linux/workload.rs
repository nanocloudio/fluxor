// ============================================================================
// Linux `workload` provider (contract class 0x1A) — the consumer-facing
// isolated-workload surface.
// ============================================================================
//
// This provider is the platform-neutral front for isolated workloads. It parses
// the Tier-1 spec header, resolves the identity to a plan-allocated owner,
// lease-gates admission, enforces the Tier-2 options envelope FAIL-CLOSED
// against the resolved backend's advertised capabilities, then delegates to the
// backend. On Linux the only backend is the host-process backend — the
// owner-bound `host_backend.rs` mechanism (namespaces/cgroups); an fmod-graph source has
// no Linux realization and is refused (it resolves to the MPU/EL0 backend on a
// metal node, by placement).
//
// Composes the host-process backend in the sibling `host_backend` module.

use super::host_backend::{
    hp_destroy, hp_exec, hp_pause, hp_read, hp_resume, hp_signal, hp_spawn, hp_start, hp_tty_close,
    hp_tty_open, hp_tty_resize, hp_tty_step, hp_wait, ResourceEnvelope, MAX_SANDBOXES,
};
use crate::abi::contracts::workload as wl;
use crate::abi::platform::linux::host_process as hp;
use crate::kernel::workload::owner::OwnerHandle;

// Host-process opcodes (`hp::EXEC`/`hp::TTY_*`, class 0x1B): the host class
// numbers them and owns the consts. Only their arg/out wire formats — backend
// detail, not contract surface — are documented here:
//
// Workload-scoped ops carry `[workload_fd: i32 LE]` before the payloads below
// (handle = -1 calls; the kernel routes handle-tagged calls by tag→class).
//
// * `EXEC` (0x1B02) — one-shot: run a command inside a workload and capture
//   its output. Payload in = command line; out = `[out_len:u32][output…]`;
//   return = exit code.
// * `TTY_OPEN` (0x1B03) — start an interactive PTY session. Payload =
//   `[rows:u16][cols:u16][cmd…]`; return = session id.
// * `TTY_STEP` (0x1B04) — pump a session: write stdin, drain output, poll
//   exit. `arg` in = `[sid:u32][wlen:u32][stdin…]`; out =
//   `[rlen:u32][state:u8][code:i32][out…]`.
// * `TTY_RESIZE` (0x1B05) — `arg` = `[sid:u32][rows:u16][cols:u16]`.
// * `TTY_CLOSE` (0x1B06) — kill+reap+free a session. `arg` = `[sid:u32]`;
//   return = exit code.

const MAX_WORKLOADS: usize = MAX_SANDBOXES;

/// One admitted workload: its owner and the host-process backend slot it maps
/// to. (Only the host-process backend exists on Linux; a `kind` field is added
/// when a second Linux backend does.)
#[derive(Clone, Copy)]
struct WorkloadSlot {
    in_use: bool,
    owner: OwnerHandle,
    backend_idx: i32,
}

const WORKLOAD_EMPTY: WorkloadSlot = WorkloadSlot {
    in_use: false,
    owner: crate::kernel::workload::owner::OWNER_SYSTEM,
    backend_idx: -1,
};

static mut LINUX_WORKLOADS: [WorkloadSlot; MAX_WORKLOADS] = [WORKLOAD_EMPTY; MAX_WORKLOADS];

#[inline]
fn rd_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
#[inline]
fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// The host-process backend's honest capability set. `host_backend.rs` provides
/// namespace + cgroup isolation but not seccomp/caps/SELinux, so it advertises
/// `SHARED`/`ISOLATED` only — never `HARDENED` — and zero `linux.*` option
/// keys. A `HARDENED` request, or a required option entry, therefore fails
/// admission rather than running silently under-hardened (the §5.2/§5.3 rule).
/// Extending `host_backend.rs` to apply a hardening knob is what adds its key here.
fn host_backend_honors_posture(posture: u8) -> bool {
    matches!(posture, wl::POSTURE_SHARED | wl::POSTURE_ISOLATED)
}
fn host_backend_honors_option(_ns: &[u8], _key: &[u8]) -> bool {
    false // no hardening options implemented yet
}
/// Network fields the backend realizes (`net_identity.rs`): own netns and an
/// IPv4 identity. IPv6 identity is not implemented yet, so it fails admission
/// (`ENOSYS`) per the same fail-closed rule — never a silently-unaddressed
/// workload.
fn host_backend_net_caps() -> u8 {
    wl::caps::NET_ISO_OWN | wl::caps::NET_IDENTITY
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

/// Validate the Tier-2 TLV options envelope. Advisory entries a backend does not
/// understand are ignored; a REQUIRED entry it does not advertise fails
/// admission. Returns `Ok(())` or a negative errno. TLV entry:
/// `[ns_len:u8][ns][key_len:u8][key][flags:u8][val_len:u16 LE][val]`.
unsafe fn validate_options(opts: &[u8]) -> Result<(), i32> {
    use crate::kernel::sys::errno;
    let mut p = 0usize;
    while p < opts.len() {
        if p + 1 > opts.len() {
            return Err(errno::EINVAL);
        }
        let ns_len = opts[p] as usize;
        p += 1;
        if p + ns_len + 1 > opts.len() {
            return Err(errno::EINVAL);
        }
        let ns = &opts[p..p + ns_len];
        p += ns_len;
        let key_len = opts[p] as usize;
        p += 1;
        if p + key_len + 3 > opts.len() {
            return Err(errno::EINVAL);
        }
        let key = &opts[p..p + key_len];
        p += key_len;
        let flags = opts[p];
        p += 1;
        let val_len = rd_u16(opts, p) as usize;
        p += 2;
        if p + val_len > opts.len() {
            return Err(errno::EINVAL);
        }
        p += val_len;
        // Fail-closed: a required entry the backend cannot honor blocks admission.
        if (flags & wl::opt::OPT_REQUIRED) != 0 && !host_backend_honors_option(ns, key) {
            return Err(errno::ENOSYS);
        }
    }
    Ok(())
}

/// WORKLOAD_CREATE: admit + instantiate a workload from the Tier-1 header + the
/// variable-length source-ref / endpoint / options sections. Returns a tagged
/// `FD_TAG_WORKLOAD` handle or a negative errno.
unsafe fn workload_create(arg: *const u8, arg_len: usize) -> i32 {
    use crate::kernel::ipc::fd::{tag_fd, FD_TAG_WORKLOAD};
    use crate::kernel::sys::errno;

    if arg.is_null() || arg_len < wl::CREATE_HEADER_SIZE {
        return errno::EINVAL;
    }
    let buf = core::slice::from_raw_parts(arg, arg_len);

    let mut identity = [0u8; 16];
    identity.copy_from_slice(&buf[0..16]);
    let posture = buf[16];
    let source_kind = buf[17];
    let net_iso = buf[18];
    if net_iso > wl::NET_ISO_OWN {
        return errno::EINVAL;
    }
    let envelope = ResourceEnvelope {
        compute_milli: rd_u32(buf, 20),
        memory_bytes: u64::from_le_bytes([
            buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
        ]),
        max_tasks: rd_u32(buf, 32),
    };
    let source_ref_len = rd_u16(buf, 40) as usize;
    let endpoint_count = rd_u16(buf, 42) as usize;
    let options_len = rd_u32(buf, 44) as usize;
    // Tier-1 network identity: an input computed by the
    // orchestrator's address policy; the backend realizes it.
    let net_family = buf[48];
    let net_prefix_len = buf[49];
    let net_segment = rd_u16(buf, 50);
    let mut net_addr = [0u8; 16];
    net_addr.copy_from_slice(&buf[52..68]);
    // This backend has no segment/lane mechanism (that is metal lane
    // addressing); a non-default segment must refuse admission, never run on
    // the default segment as if it were the requested one.
    if net_segment != 0 {
        return errno::ENOSYS;
    }

    // Section bounds.
    let src_start = wl::CREATE_HEADER_SIZE;
    let ep_start = src_start + source_ref_len;
    let opt_start = ep_start + endpoint_count * wl::NET_ENDPOINT_SIZE;
    let opt_end = opt_start + options_len;
    if opt_end > arg_len {
        return errno::EINVAL;
    }

    // Backend selection is by source kind (placement routes fmod-graph to a
    // metal node; a bundle to a Linux node). Only the host-process backend
    // exists here.
    if source_kind != hp::SOURCE_HOST_PROCESS {
        return errno::ENOSYS; // fmod-graph → MPU/EL0 backend, not on Linux
    }
    if !host_backend_honors_posture(posture) {
        return errno::ENOSYS; // e.g. HARDENED before seccomp/caps land
    }

    // Identity → owner. The null uid is the single-tenant / system workload:
    // a single-tenant device runs entirely as owner 0, and
    // when MAX_OWNERS == 1 there are no workload slots to admit into, so the
    // system owner (slot 0, permanently Active) is the only owner. A non-null
    // uid must resolve to a plan-allocated owner — the provider references it, it
    // does not allocate (the plan is authoritative for owners).
    let owner = if identity == [0u8; 16] {
        crate::kernel::workload::owner::OWNER_SYSTEM
    } else {
        match crate::kernel::exec::scheduler::owners().find_by_uid(identity) {
            Some(h) => h,
            None => return errno::EACCES, // no admitted workload for this uid
        }
    };
    if !crate::kernel::exec::scheduler::owners().authorize_admit(owner) {
        return errno::EACCES; // draining/revoked owner cannot admit new work
    }

    // Lease-gate each declared endpoint against the owner's lease before any
    // mechanism runs. A refusal blocks admission. The workload-level net_iso
    // field — or any endpoint asking for its own network domain — puts the
    // whole workload in its own netns.
    let mut own_netns = net_iso == wl::NET_ISO_OWN;
    for i in 0..endpoint_count {
        let e = ep_start + i * wl::NET_ENDPOINT_SIZE;
        let proto = buf[e];
        // Unknown net_iso values must not degrade to SHARED — same rule as
        // the workload-level field above.
        if buf[e + 1] > wl::NET_ISO_OWN {
            return errno::EINVAL;
        }
        if buf[e + 1] == wl::NET_ISO_OWN {
            own_netns = true;
        }
        let port = rd_u16(buf, e + 2);
        let gate = crate::kernel::workload::owner_plan::lease_gate(
            owner.slot,
            owner.generation,
            proto,
            port,
        );
        if matches!(
            gate,
            crate::kernel::workload::owner_plan::LeaseGate::Refused
        ) {
            return errno::EACCES;
        }
    }

    // Network identity: fail-closed validation against the backend's honest
    // net capabilities (never silently weaker networking). An identity only
    // makes sense in an own network domain — assigning a workload address in
    // the shared host domain is routing policy, not workload mechanism.
    let net_ident = match net_family {
        wl::NET_FAM_NONE => None,
        wl::NET_FAM_IPV4 => {
            if (host_backend_net_caps() & wl::caps::NET_IDENTITY) == 0 {
                return errno::ENOSYS;
            }
            if !own_netns || net_prefix_len == 0 || net_prefix_len > 32 {
                return errno::EINVAL;
            }
            // Contract: IPv4 lives in bytes 0..4, rest zero. Trailing garbage
            // means a malformed header (or a v6 address under a v4 family) —
            // refuse rather than guess.
            if net_addr[4..].iter().any(|&b| b != 0) {
                return errno::EINVAL;
            }
            let mut v4 = [0u8; 4];
            v4.copy_from_slice(&net_addr[..4]);
            Some(super::net_identity::NetIdentity {
                addr_v4: v4,
                prefix_len: net_prefix_len,
            })
        }
        // IPv6 identity is not realized by this backend yet (net_identity.rs
        // is ioctl/IPv4; v6 needs the netlink addr path).
        wl::NET_FAM_IPV6 => return errno::ENOSYS,
        _ => return errno::EINVAL,
    };
    if own_netns && (host_backend_net_caps() & wl::caps::NET_ISO_OWN) == 0 {
        return errno::ENOSYS;
    }

    // Tier-2 options: fail-closed against the backend's advertised capabilities.
    if let Err(e) = validate_options(&buf[opt_start..opt_end]) {
        return e;
    }

    // Spawn on the host-process backend, bound to the owner. The source section
    // carries EXPLICIT spawn params (the orchestrator composes them from its own
    // bundle/OCI format — this backend has no bundle knowledge):
    //   [isolate:u8][rootfs_len:u16 LE][rootfs bytes][argv: rest, NUL-separated]
    let src = &buf[src_start..ep_start];
    if src.len() < 3 {
        return errno::EINVAL;
    }
    let isolate = src[0] == 1;
    let rootfs_len = u16::from_le_bytes([src[1], src[2]]) as usize;
    let rootfs_end = 3 + rootfs_len;
    if rootfs_end > src.len() {
        return errno::EINVAL;
    }
    let rootfs = match core::str::from_utf8(&src[3..rootfs_end]) {
        Ok(s) if !s.is_empty() => Some(s),
        Ok(_) => None,
        Err(_) => return errno::EINVAL,
    };
    let argv_bytes = &src[rootfs_end..];
    let mut argv: std::vec::Vec<&str> = std::vec::Vec::new();
    for tok in argv_bytes.split(|b| *b == 0) {
        if tok.is_empty() {
            continue;
        }
        match core::str::from_utf8(tok) {
            Ok(s) => argv.push(s),
            Err(_) => return errno::EINVAL,
        }
    }
    let backend_idx = hp_spawn(
        &argv,
        rootfs,
        isolate,
        &envelope,
        own_netns,
        net_ident.as_ref(),
    );
    if backend_idx < 0 {
        return backend_idx;
    }

    let slots = &mut *core::ptr::addr_of_mut!(LINUX_WORKLOADS);
    let widx = match slots.iter().position(|s| !s.in_use) {
        Some(i) => i,
        None => {
            // No workload slot: don't leak the backend sandbox.
            hp_destroy(backend_idx);
            return errno::ENOMEM;
        }
    };
    slots[widx] = WorkloadSlot {
        in_use: true,
        owner,
        backend_idx,
    };
    tag_fd(FD_TAG_WORKLOAD, widx as i32)
}

unsafe fn workload_backend_idx(raw: i32) -> Option<i32> {
    let idx = raw as usize;
    let slots = &*core::ptr::addr_of!(LINUX_WORKLOADS);
    if idx >= MAX_WORKLOADS || !slots[idx].in_use {
        return None;
    }
    Some(slots[idx].backend_idx)
}

/// Map the portable SIGNAL subset to the host signal number.
fn portable_signo(signo: u32) -> Option<u8> {
    match signo {
        wl::SIG_TERM => Some(libc::SIGTERM as u8),
        wl::SIG_KILL => Some(libc::SIGKILL as u8),
        _ => None,
    }
}

/// `workload` provider dispatch. CREATE is `handle = -1`; lifecycle ops carry
/// the `FD_TAG_WORKLOAD` handle (stripped to a slot by `slot_of`).
/// # Safety
/// Single-threaded platform dispatch only: touches `static mut` provider
/// state without synchronization. `arg` must be null or valid for reads
/// and writes of `arg_len` bytes for the duration of the call.
pub unsafe fn linux_workload_dispatch(
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    use crate::kernel::ipc::fd::slot_of;
    use crate::kernel::sys::errno;

    if opcode == wl::CREATE {
        return workload_create(arg as *const u8, arg_len);
    }
    if opcode == wl::CAPS {
        return workload_caps(arg, arg_len);
    }

    let raw = slot_of(handle);
    let Some(bidx) = workload_backend_idx(raw) else {
        return errno::EINVAL;
    };
    match opcode {
        wl::START => hp_start(bidx),
        wl::PAUSE => hp_pause(bidx),
        wl::RESUME => hp_resume(bidx),
        wl::WAIT => hp_wait(bidx, arg, arg_len),
        wl::SIGNAL => {
            if arg.is_null() || arg_len < 4 {
                return errno::EINVAL;
            }
            let signo = rd_u32(core::slice::from_raw_parts(arg, arg_len), 0);
            let Some(hostsig) = portable_signo(signo) else {
                return errno::EINVAL;
            };
            let s = [hostsig];
            hp_signal(bidx, s.as_ptr(), 1)
        }
        wl::DESTROY => {
            let rc = hp_destroy(bidx);
            let slots = &mut *core::ptr::addr_of_mut!(LINUX_WORKLOADS);
            slots[raw as usize] = WORKLOAD_EMPTY;
            rc
        }
        _ => errno::ENOSYS,
    }
}

/// WORKLOAD_CAPS: write the backend discovery structure (see the contract's
/// `CAPS` doc). Prefix `[postures:u8][source_kinds:u8][ops:u16 LE][net:u8]`
/// then an empty namespace directory `[ns_count:u16 = 0]` (no `linux.*` keys
/// defined).
unsafe fn workload_caps(arg: *mut u8, arg_len: usize) -> i32 {
    use crate::kernel::sys::errno;
    if arg.is_null() || arg_len < 7 {
        return errno::EINVAL;
    }
    let out = core::slice::from_raw_parts_mut(arg, arg_len);
    out[0] = wl::caps::POSTURE_SHARED | wl::caps::POSTURE_ISOLATED;
    out[1] = hp::CAPS_SOURCE_HOST_PROCESS;
    // Implemented optional ops: READ + EXEC + the TTY set + real-signal SIGNAL
    // delivery (process-group). PAUSE is
    // advertised iff the host can freeze at all (cgroup2 present); a workload
    // whose own cgroup setup failed still gets per-workload ENOSYS.
    // READ/EXEC/TTY retired to the 0x1B host-process class (D-WORKLOAD-ABI).
    let mut ops = wl::caps::SIGNAL;
    if host_backend_can_freeze() {
        ops |= wl::caps::PAUSE;
    }
    out[2..4].copy_from_slice(&ops.to_le_bytes());
    out[4] = host_backend_net_caps();
    out[5..7].copy_from_slice(&0u16.to_le_bytes()); // ns_count
    7
}

/// Drain/revocation hook: destroy every workload belonging to a revoked owner.
/// Mirrors `linux_net_close_owner_conns`; called from the owner-drain path.
pub fn linux_workload_close_owner(owner: OwnerHandle) {
    // SAFETY: platform-thread single-writer access to the workload table and the
    // backend slots it owns; mirrors `linux_net_close_owner_conns`.
    unsafe {
        let slots = &mut *core::ptr::addr_of_mut!(LINUX_WORKLOADS);
        for slot in slots.iter_mut() {
            if slot.in_use && slot.owner == owner {
                hp_destroy(slot.backend_idx);
                *slot = WORKLOAD_EMPTY;
            }
        }
    }
}

/// Host-process (0x1B) provider dispatch — the linux host mechanics evicted
/// from the stable 0x1A surface (D-WORKLOAD-ABI). Every op is a `handle = -1`
/// call; workload-targeting ops carry the tagged workload fd in the leading
/// 4 bytes of `arg` (LE), TTY session ops carry the session id as before.
///
/// # Safety
/// Scheduler-thread dispatch only; `arg` null or valid for `arg_len` bytes.
pub unsafe fn host_process_dispatch(
    _handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    use crate::kernel::ipc::fd::slot_of;
    use crate::kernel::sys::errno;

    // Session-scoped ops (no workload fd prefix).
    if opcode == hp::TTY_STEP {
        return hp_tty_step(arg, arg_len);
    }
    if opcode == hp::TTY_RESIZE {
        return hp_tty_resize(arg as *const u8, arg_len);
    }
    if opcode == hp::TTY_CLOSE {
        return hp_tty_close(arg as *const u8, arg_len);
    }

    // Workload-scoped ops: `[workload_fd: i32 LE]` prefix.
    if arg.is_null() || arg_len < 4 {
        return errno::EINVAL;
    }
    let a = core::slice::from_raw_parts(arg, 4);
    let wfd = i32::from_le_bytes([a[0], a[1], a[2], a[3]]);
    let Some(bidx) = workload_backend_idx(slot_of(wfd)) else {
        return errno::EINVAL;
    };
    let body = arg.add(4);
    let body_len = arg_len - 4;
    match opcode {
        hp::READ => hp_read(bidx, body, body_len),
        hp::EXEC => hp_exec(bidx, body, body_len),
        hp::TTY_OPEN => hp_tty_open(bidx, body as *const u8, body_len),
        _ => errno::ENOSYS,
    }
}
