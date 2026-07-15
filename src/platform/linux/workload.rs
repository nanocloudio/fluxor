// ============================================================================
// Linux `workload` provider (contract class 0x1A) — the consumer-facing
// isolated-workload surface. See `.context/fluxor_nanocloud.md`.
// ============================================================================
//
// This provider is the platform-neutral front for isolated workloads. It parses
// the Tier-1 spec header, resolves the identity to a plan-allocated owner,
// lease-gates admission, enforces the Tier-2 options envelope FAIL-CLOSED
// against the resolved backend's advertised capabilities, then delegates to the
// backend. On Linux the only backend is the host-process backend — the
// owner-bound `oci.rs` mechanism (namespaces/cgroups); an fmod-graph source has
// no Linux realization and is refused (it resolves to the MPU/EL0 backend on a
// metal node, by placement).
//
// Composes the host-process backend in the sibling `oci` module.

use super::oci::{
    oci_destroy, oci_read, oci_signal, oci_spawn, oci_start, oci_wait, ResourceEnvelope,
    MAX_SANDBOXES,
};
use crate::abi::contracts::workload as wl;
use crate::kernel::owner::OwnerHandle;

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
    owner: crate::kernel::owner::OWNER_SYSTEM,
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

/// The host-process backend's honest capability set. `oci.rs` provides
/// namespace + cgroup isolation but not seccomp/caps/SELinux, so it advertises
/// `SHARED`/`ISOLATED` only — never `HARDENED` — and zero `linux.*` option
/// keys. A `HARDENED` request, or a required option entry, therefore fails
/// admission rather than running silently under-hardened (the §5.2/§5.3 rule).
/// Extending `oci.rs` to apply a hardening knob is what adds its key here.
fn host_backend_honors_posture(posture: u8) -> bool {
    matches!(posture, wl::POSTURE_SHARED | wl::POSTURE_ISOLATED)
}
fn host_backend_honors_option(_ns: &[u8], _key: &[u8]) -> bool {
    false // no hardening options implemented yet
}

/// Validate the Tier-2 TLV options envelope. Advisory entries a backend does not
/// understand are ignored; a REQUIRED entry it does not advertise fails
/// admission. Returns `Ok(())` or a negative errno. TLV entry:
/// `[ns_len:u8][ns][key_len:u8][key][flags:u8][val_len:u16 LE][val]`.
unsafe fn validate_options(opts: &[u8]) -> Result<(), i32> {
    use crate::kernel::errno;
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
    use crate::kernel::errno;
    use crate::kernel::fd::{tag_fd, FD_TAG_WORKLOAD};

    if arg.is_null() || arg_len < wl::CREATE_HEADER_SIZE {
        return errno::EINVAL;
    }
    let buf = core::slice::from_raw_parts(arg, arg_len);

    let mut identity = [0u8; 16];
    identity.copy_from_slice(&buf[0..16]);
    let posture = buf[16];
    let source_kind = buf[17];
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
    if source_kind != wl::SOURCE_BUNDLE {
        return errno::ENOSYS; // fmod-graph → MPU/EL0 backend, not on Linux
    }
    if !host_backend_honors_posture(posture) {
        return errno::ENOSYS; // e.g. HARDENED before seccomp/caps land
    }

    // Identity → owner. The null uid is the single-tenant / system workload:
    // rfc_k8s.md §14 — "a single-tenant device runs entirely as owner 0", and
    // when MAX_OWNERS == 1 there are no workload slots to admit into, so the
    // system owner (slot 0, permanently Active) is the only owner. A non-null
    // uid must resolve to a plan-allocated owner — the provider references it, it
    // does not allocate (rfc_k8s: the plan is authoritative for owners).
    let owner = if identity == [0u8; 16] {
        crate::kernel::owner::OWNER_SYSTEM
    } else {
        match crate::kernel::scheduler::owners().find_by_uid(identity) {
            Some(h) => h,
            None => return errno::EACCES, // no admitted pod for this uid
        }
    };
    if !crate::kernel::scheduler::owners().authorize_admit(owner) {
        return errno::EACCES; // draining/revoked owner cannot admit new work
    }

    // Lease-gate each declared endpoint against the owner's lease before any
    // mechanism runs (rfc_endpoint_lease). A refusal blocks admission.
    for i in 0..endpoint_count {
        let e = ep_start + i * wl::NET_ENDPOINT_SIZE;
        let proto = buf[e];
        let port = rd_u16(buf, e + 2);
        let gate = crate::kernel::owner_plan::lease_gate(owner.slot, owner.generation, proto, port);
        if matches!(gate, crate::kernel::owner_plan::LeaseGate::Refused) {
            return errno::EACCES;
        }
    }

    // Tier-2 options: fail-closed against the backend's advertised capabilities.
    if let Err(e) = validate_options(&buf[opt_start..opt_end]) {
        return e;
    }

    // Spawn on the host-process backend, bound to the owner.
    let bundle = match core::str::from_utf8(&buf[src_start..ep_start]) {
        Ok(s) => s.trim(),
        Err(_) => return errno::EINVAL,
    };
    let backend_idx = oci_spawn(bundle, &envelope);
    if backend_idx < 0 {
        return backend_idx;
    }

    let slots = &mut *core::ptr::addr_of_mut!(LINUX_WORKLOADS);
    let widx = match slots.iter().position(|s| !s.in_use) {
        Some(i) => i,
        None => {
            // No workload slot: don't leak the backend sandbox.
            oci_destroy(backend_idx);
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
    use crate::kernel::errno;
    use crate::kernel::fd::slot_of;

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
        wl::START => oci_start(bidx),
        wl::READ => oci_read(bidx, arg, arg_len),
        wl::WAIT => oci_wait(bidx, arg, arg_len),
        wl::SIGNAL => {
            if arg.is_null() || arg_len < 4 {
                return errno::EINVAL;
            }
            let signo = rd_u32(core::slice::from_raw_parts(arg, arg_len), 0);
            let Some(hostsig) = portable_signo(signo) else {
                return errno::EINVAL;
            };
            let s = [hostsig];
            oci_signal(bidx, s.as_ptr(), 1)
        }
        wl::DESTROY => {
            let rc = oci_destroy(bidx);
            let slots = &mut *core::ptr::addr_of_mut!(LINUX_WORKLOADS);
            slots[raw as usize] = WORKLOAD_EMPTY;
            rc
        }
        _ => errno::ENOSYS,
    }
}

/// WORKLOAD_CAPS: write the backend discovery structure (see the contract's
/// `CAPS` doc). Prefix `[postures:u8][source_kinds:u8][ops:u16 LE]` then an
/// empty namespace directory `[ns_count:u16 = 0]` (no `linux.*` keys defined).
unsafe fn workload_caps(arg: *mut u8, arg_len: usize) -> i32 {
    use crate::kernel::errno;
    if arg.is_null() || arg_len < 6 {
        return errno::EINVAL;
    }
    let out = core::slice::from_raw_parts_mut(arg, arg_len);
    out[0] = wl::caps::POSTURE_SHARED | wl::caps::POSTURE_ISOLATED;
    out[1] = wl::caps::SOURCE_BUNDLE;
    out[2..4].copy_from_slice(&wl::caps::READ.to_le_bytes());
    out[4..6].copy_from_slice(&0u16.to_le_bytes()); // ns_count
    6
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
                oci_destroy(slot.backend_idx);
                *slot = WORKLOAD_EMPTY;
            }
        }
    }
}
