// ============================================================================
// Metal module-graph `workload` backend (contract class 0x1A).
// ============================================================================
//
// The bare-metal realization of the `workload` contract: a workload is an owned
// module subgraph, staged onto the live graph via the already-built owner /
// lease / live-graph primitives.
// This is the metal twin of `platform::linux::workload` (the host-process
// backend). It lives in `src/kernel` — not `src/platform/bcm2712` — because the
// logic is kernel-generic multitenant: `apply_add`/`free_owner`/`owner_pause`
// reach the run loop on **host-linux** too, so the harness drives this dispatch
// end-to-end there (the metal registration in `bcm2712::bcm_init_providers` is a
// thin wrapper that installs `workload_dispatch` as the 0x1A provider).
//
// Per-op mapping:
//   CREATE  — decode the `source_ref` FLXA subgraph → `apply_add`; stage paused
//             (the START barrier); lease-gate the header endpoints; allocate a
//             `WorkloadSlot`; return `tag_fd(FD_TAG_WORKLOAD, idx)`.
//   START   — `owner_resume` (release the create-time pause).
//   WAIT    — map the owner's live status → `[state:u8][code:i32 LE]`.
//   SIGNAL  — TERM → `begin_drain`, KILL → `free_owner`.
//   DESTROY — `free_owner` + clear the slot (idempotent).
//   PAUSE / RESUME — `owner_pause` / `owner_resume` (direct).
//   CAPS    — the metal bitmap: SHARED posture, FMOD_GRAPH source, PAUSE
//             op, own-address net identity.
//
// **Dispatch context invariant:** runtime `apply_add`/ `free_owner` must run
// on the primary domain / core 0 — `request_quiesce` (the peer-core quiesce
// built into `apply_add`/`free_owner`) is primary-only. The
// `workload` provider dispatches on the system graph, which lives on domain 0,
// so this holds naturally; there is no secondary-core path into this backend.

use crate::abi::contracts::workload as wl;
use crate::kernel::exec::scheduler::live;
use crate::kernel::exec::scheduler::{self, OwnerLiveStatus, OWNER_STATE_PAUSED};
use crate::kernel::exec::step_guard::fault_type;
use crate::kernel::ipc::channel::channel_write;
use crate::kernel::ipc::fd::{slot_of, tag_fd, FD_TAG_WORKLOAD};
use crate::kernel::sys::errno;
use crate::kernel::workload::code_pack;
use crate::kernel::workload::owner::{OwnerHandle, MAX_OWNERS, OWNER_SYSTEM};
use crate::kernel::workload::owner_plan::{lease_gate, LeaseGate};
use crate::kernel::workload::storage::StorageGrant;

// ── Metal net identity install ───────────────────────────────────
//
// On CREATE of a `net=own` workload the backend installs the workload's
// address into the node's shared net-identity provider by writing an
// `ADDR_ADD` control frame to the provider's `addr_ctl` port; DESTROY/KILL
// writes `ADDR_DEL`. The backend does NOT know which module the provider is,
// what it is named, or how it stores addresses — the provider SELF-REGISTERS
// at init via the `NET_IDENT_PROVIDER` syscall, declaring its module slot and
// its control/ingress port indices, and the backend speaks the shared
// `net::identity` contract (opcodes, framing, payload layout) to whatever
// registered. Any base-graph module implementing the contract's `addr_ctl`
// receiver is a valid provider; the foundation `ip` module is one.

use crate::abi::contracts::net::identity as netid;
use portable_atomic::{AtomicU32, Ordering};

/// Registered net-identity provider, packed as
/// `[slot: u16][addr_ctl_port: u8][net_in_port: u8]` (little-endian view), or
/// [`NO_PROVIDER`] when none has registered. One atomic so a reader never sees
/// a torn slot/port pair.
static NET_IDENT_PROVIDER_REG: AtomicU32 = AtomicU32::new(NO_PROVIDER);
const NO_PROVIDER: u32 = u32::MAX;

/// Register `slot` as the node's net-identity provider with its declared
/// control (`addr_ctl_port`) and ingress (`net_in_port`) input-port indices.
/// First-wins: a second registration returns `EBUSY`. The syscall path gates
/// callers to base-graph (system-owned) modules; tests register directly.
pub fn register_net_identity_provider(slot: u16, addr_ctl_port: u8, net_in_port: u8) -> i32 {
    let packed = (slot as u32) | ((addr_ctl_port as u32) << 16) | ((net_in_port as u32) << 24);
    match NET_IDENT_PROVIDER_REG.compare_exchange(
        NO_PROVIDER,
        packed,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => 0,
        // Same registration repeated (module re-init) is a benign no-op.
        Err(cur) if cur == packed => 0,
        Err(_) => errno::EBUSY,
    }
}

/// Clear the registration (test isolation only — production providers live for
/// the boot lifetime).
#[cfg(feature = "host-linux")]
pub fn reset_net_identity_provider() {
    NET_IDENT_PROVIDER_REG.store(NO_PROVIDER, Ordering::Release);
}

/// The registered provider as `(slot, addr_ctl_port, net_in_port)`, or `None`.
fn net_identity_provider() -> Option<(usize, u8, u8)> {
    let packed = NET_IDENT_PROVIDER_REG.load(Ordering::Acquire);
    if packed == NO_PROVIDER {
        return None;
    }
    Some((
        (packed & 0xFFFF) as usize,
        ((packed >> 16) & 0xFF) as u8,
        ((packed >> 24) & 0xFF) as u8,
    ))
}

/// One admitted metal workload: its owner subgraph. Mirrors the Linux
/// `WorkloadSlot`, minus the host-process backend index (the subgraph *is* the
/// backend). Bounded by the owner table — at most one workload per owner slot.
#[derive(Clone, Copy)]
struct WorkloadSlot {
    in_use: bool,
    owner: OwnerHandle,
    /// The workload's installed IPv4 identity (16-byte address, IPv4 in bytes
    /// 0..4 network order), or all-zero for a host-shared workload that never
    /// took one. Retained at CREATE so DESTROY/KILL can emit the matching
    /// `ADDR_DEL`.
    net_addr: [u8; 16],
    /// The creating module's lanes into the subgraph (`wl::LANES`).
    lanes: [CallerLane; wl::MAX_CALLER_LANES],
    lane_count: u8,
}

/// One key of the creator's lanes: the channel it reads (the subgraph's edge
/// into it) and the one it writes (its edge into the subgraph), -1 if absent.
#[derive(Clone, Copy)]
struct CallerLane {
    key: u8,
    to_caller: i32,
    from_caller: i32,
}

const NO_LANE: CallerLane = CallerLane {
    key: 0,
    to_caller: -1,
    from_caller: -1,
};

const WL_EMPTY: WorkloadSlot = WorkloadSlot {
    in_use: false,
    owner: OWNER_SYSTEM,
    net_addr: [0u8; 16],
    lanes: [NO_LANE; wl::MAX_CALLER_LANES],
    lane_count: 0,
};

const MAX_WORKLOADS: usize = MAX_OWNERS;

static mut FMOD_WORKLOADS: [WorkloadSlot; MAX_WORKLOADS] = [WL_EMPTY; MAX_WORKLOADS];

/// A `CREATE` whose subgraph is being instantiated a batch per call. The
/// backend owns everything the add reads between calls: its own copy of the
/// subgraph (the modules' params are read from it as they instantiate), and
/// the pack its names resolve in. One is pending at a time.
struct PendingCreate {
    identity: [u8; 16],
    /// SHA-256 of the spec as the caller sent it: a continuation sends the
    /// same bytes.
    spec: [u8; 32],
    staged: live::StagedAdd,
    pack: Option<code_pack::Staged>,
    caller_edges: [live::CallerEdge; wl::MAX_CALLER_LANES * 2],
    caller_edge_count: usize,
}

static mut PENDING: Option<PendingCreate> = None;

/// The pending `CREATE`'s copy of its subgraph. An FLXA source is at most a
/// `u16` long (the header's `source_ref_len`).
static mut PENDING_BLOB: [u8; u16::MAX as usize] = [0; u16::MAX as usize];

/// Modules a `CREATE` instantiates per call. A subgraph with more answers
/// `EINPROGRESS` between batches, so no call holds the scheduler for longer
/// than a few module loads.
pub const CREATE_MODULES_PER_CALL: usize = 4;

/// Forget the pending `CREATE` without rolling it back: a rebuild has
/// already dropped every workload, the half-added one with them, and freed
/// the code pool its pack lived in.
pub fn reset_pending() {
    // SAFETY: rebuild path, scheduler thread.
    unsafe { *core::ptr::addr_of_mut!(PENDING) = None };
}

/// Roll the pending `CREATE` back: its add, and the pack it brought.
unsafe fn abandon_pending() {
    if let Some(p) = (*core::ptr::addr_of_mut!(PENDING)).take() {
        live::abandon_staged(p.staged);
        if let Some(s) = p.pack {
            code_pack::release(s);
        }
    }
}

/// Whether a workload of this backend carries `identity`: a live one, or
/// the `CREATE` being staged. Another backend asks before it admits one.
pub fn holds_identity(identity: &[u8; 16]) -> bool {
    // SAFETY: scheduler thread.
    pending_identity() == Some(*identity) || unsafe { slot_by_identity(identity) }.is_some()
}

/// The identity of the pending `CREATE`, if any.
fn pending_identity() -> Option<[u8; 16]> {
    // SAFETY: scheduler thread.
    unsafe { (*core::ptr::addr_of!(PENDING)).as_ref().map(|p| p.identity) }
}

/// SHA-256 of a `CREATE` spec.
fn spec_digest(spec: &[u8]) -> [u8; 32] {
    let mut h = crate::kernel::security::crypto::sha256::Sha256::new();
    h.update(spec);
    h.finalize()
}

#[inline]
fn rd_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
#[inline]
fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

// FLXA subgraph blob layout (big-endian, `scheduler::live` codec): magic(4) +
// version(2) + reserved(2) + owner_uid(16) + state_cap(4) + buffer_cap(4) +
// module_count(1) + edge_count(1) then the module/edge records.
const FLXA_OWNER_UID_OFF: usize = 8;
const FLXA_STATE_CAP_OFF: usize = 24;
const FLXA_BUFFER_CAP_OFF: usize = 28;
/// Minimum bytes for a well-formed FLXA header (through the two count bytes).
const FLXA_MIN_LEN: usize = 34;

/// Clamp a blob cap field to the envelope memory ceiling, in place. `mem_ceil`
/// is `None` for an unlimited envelope; a blob cap of 0 is also "unlimited", so
/// the ceiling wins; otherwise the tighter of the two holds (caps, never a
/// new meter).
#[inline]
fn clamp_cap_be(buf: &mut [u8], off: usize, mem_ceil: Option<u32>) {
    let existing = u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
    let clamped = match mem_ceil {
        None => existing,
        Some(m) if existing == 0 => m,
        Some(m) => existing.min(m),
    };
    buf[off..off + 4].copy_from_slice(&clamped.to_be_bytes());
}

/// Resolve the net-identity provider's `addr_ctl` channel from the
/// registration, or `-1` when no provider has registered (a node with
/// no network stack).
fn addr_ctl_channel() -> i32 {
    match net_identity_provider() {
        Some((slot, addr_ctl_port, _)) => {
            scheduler::get_module_port(slot, 0 /* PORT_IN */, addr_ctl_port)
        }
        None => -1,
    }
}

/// Resolve the next FREE spare lane of the boot merge feeding the registered
/// net-identity provider's declared ingress port. This is the
/// channel a `net=own` workload's net-facing producer edges into so its egress
/// reaches the shared provider through the merge. Returns the lane channel id,
/// or `-1` when no provider registered, there is no boot merge on the
/// provider's ingress (a node whose base graph provisioned no spare-lane
/// merge), or every spare lane is already taken (exhaustion). A `-1` with a
/// sentinel edge present makes CREATE fail `ENOMEM` cleanly (nothing
/// allocated).
fn provider_net_in_spare_lane() -> i32 {
    let Some((slot, _, net_in_port)) = net_identity_provider() else {
        return -1;
    };
    let ingress = scheduler::get_module_port(slot, 0 /* PORT_IN */, net_in_port);
    let merge = scheduler::find_spare_lane_merge_for_channel(ingress);
    if merge < 0 {
        return -1;
    }
    scheduler::merge_next_free_lane(merge as usize)
}

/// Single-writer gate: the backend is the *sole* writer of `addr_ctl`, so
/// the base graph must leave the channel producer-less (no module edged into
/// it). `channel_producer_owner` returns `OWNER_SYSTEM` for a producer-less (or
/// benign system-anchored) channel; a non-system producer means a mis-wired base
/// graph — `channel_write` on an SPSC FIFO with a second producer violates the
/// invariant, so we refuse rather than double-write.
fn addr_ctl_writable(ch: i32) -> bool {
    scheduler::channel_producer_owner(ch).is_system()
}

/// Write one `net::identity`-framed `addr_ctl` control frame: `[msg_type:u8]
/// [payload_len:u16 LE][payload]` (the shared net-contract TLV framing). Returns
/// true iff the whole frame was accepted (the provider reads header+body
/// atomically; a short write would desync the ring).
///
/// # Safety
/// Scheduler-thread only (writes an SPSC channel by id). `ch` must be a valid
/// channel and `payload.len() <= netid::MAX_PAYLOAD`.
unsafe fn write_addr_ctl_frame(ch: i32, msg_type: u8, payload: &[u8]) -> bool {
    let mut frame = [0u8; netid::FRAME_HDR + netid::MAX_PAYLOAD];
    frame[0] = msg_type;
    frame[1..3].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    frame[netid::FRAME_HDR..netid::FRAME_HDR + payload.len()].copy_from_slice(payload);
    let total = netid::FRAME_HDR + payload.len();
    channel_write(ch, frame.as_ptr(), total) == total as i32
}

/// Install a `net=own` workload's IPv4 identity into the net-identity provider
///: resolve the `addr_ctl` channel, assert single-writer, and write
/// `ADDR_ADD [addr:16][prefix_len:1][owner_tag:2 LE]` with
/// `owner_tag = owner_slot`. The address is live before START releases the
/// workload. Returns 0, or a negative errno:
///   * `ENODEV` — no provider / addr_ctl in the base graph (a `net=own` CREATE
///     on a node with no network stack fails cleanly — never silently
///     dropped),
///   * `EBUSY`  — the base graph wired a producer into addr_ctl (mis-wire),
///   * `EAGAIN` — the low-rate control ring rejected the frame.
///
/// # Safety
/// Scheduler-thread only. `addr16.len() == 16`.
unsafe fn install_identity(addr16: &[u8], prefix_len: u8, owner_slot: u16) -> i32 {
    let ch = addr_ctl_channel();
    if ch < 0 {
        return errno::ENODEV;
    }
    if !addr_ctl_writable(ch) {
        return errno::EBUSY;
    }
    let mut payload = [0u8; netid::MAX_PAYLOAD];
    payload[0..16].copy_from_slice(addr16);
    payload[netid::ADD_PREFIX_LEN_OFF] = prefix_len;
    payload[netid::ADD_OWNER_TAG_OFF..netid::ADD_OWNER_TAG_OFF + 2]
        .copy_from_slice(&owner_slot.to_le_bytes());
    if write_addr_ctl_frame(ch, netid::ADDR_ADD, &payload[..netid::ADDR_ADD_PAYLOAD_LEN]) {
        0
    } else {
        errno::EAGAIN
    }
}

/// Emit `ADDR_DEL [addr:16]` for a torn-down workload's address.
/// Best-effort: a zero address (host-shared workload, never installed) is a
/// no-op, and if the provider / addr_ctl is gone or the ring is momentarily
/// full the address ages out with the freed owner anyway.
///
/// # Safety
/// Scheduler-thread only.
unsafe fn remove_identity(addr16: &[u8; 16]) {
    if addr16.iter().all(|&b| b == 0) {
        return;
    }
    let ch = addr_ctl_channel();
    if ch < 0 || !addr_ctl_writable(ch) {
        return;
    }
    let _ = write_addr_ctl_frame(ch, netid::ADDR_DEL, addr16);
}

/// Admit a new `CREATE` and stage its subgraph as the pending one: stage and
/// admit its pack, refuse a module holding a node privilege, copy the
/// subgraph into the backend's own memory (carrying the header's identity
/// and the memory ceiling there, never into the caller's spec), and reserve
/// its owner with the storage the header admits. 0, or a negative errno with
/// nothing left staged.
///
/// # Safety
/// Scheduler thread; `buf` is the caller's whole spec.
#[allow(
    clippy::too_many_arguments,
    reason = "the parsed header fields CREATE admits by; a struct would restate the header under a second name"
)]
unsafe fn begin_create(
    buf: &[u8],
    flxa_off: usize,
    flxa_len: usize,
    pack: Option<(usize, usize, usize)>,
    src_start: usize,
    memory_bytes: u64,
    storage_bytes: u64,
    storage_grant: StorageGrant,
    wants_identity: bool,
    identity: [u8; 16],
    spec: [u8; 32],
) -> i32 {
    // ── A pack: the workload's own modules, staged as its code. Each must be
    //    the module asked for — its bytes match a pin — or one the node's
    //    signing root signed; then the region is made executable, and the
    //    subgraph's names resolve in it first while the add instantiates.
    let staged = match pack {
        Some((ptr, len, pins)) => {
            let bytes = core::slice::from_raw_parts(ptr as *const u8, len);
            let staged = match code_pack::stage(bytes) {
                Ok(s) => s,
                Err(e) => return e,
            };
            let pin_bytes = &buf[src_start + wl::pack_ref::SIZE
                ..src_start + wl::pack_ref::SIZE + pins * wl::pack_ref::PIN_SIZE];
            let mut ok = true;
            let ldr = code_pack::loader(staged);
            code_pack::for_each_module(staged, |hash, fmod| {
                let pinned = |p: &[u8; 32]| -> bool { pin_matches(pin_bytes, p) };
                let module = ldr.find_by_name_hash(hash);
                ok &= match module {
                    Ok(m) => code_pack::admitted_with(fmod, &m, pinned),
                    Err(_) => false,
                };
            });
            if !ok {
                code_pack::release(staged);
                return errno::EACCES;
            }
            if !code_pack::seal(staged) {
                code_pack::release(staged);
                return errno::EFAULT;
            }
            Some(staged)
        }
        None => None,
    };
    let unstage = |staged: Option<code_pack::Staged>| {
        code_pack::end_staging();
        if let Some(s) = staged {
            code_pack::release(s);
        }
    };
    if let Some(s) = staged {
        code_pack::begin_staging(s);
    }
    let flxa = &buf[flxa_off..flxa_off + flxa_len];
    // A workload is a tenant of the node, not part of it: none of its
    // modules may hold a node privilege. `platform_raw` reads any register
    // (the seal key's OTP rows among them), `dma` and `pcie_device` reach
    // memory behind the kernel, `reconfigure`/`monitor`/`bridge`/`flash_raw`/
    // `backing_provider`/`usb_host` act on the node itself. Only `observe` —
    // a read-only telemetry drain — is admitted. Checked before any owner is
    // allocated, against the modules the node would instantiate.
    let Some(perms) = live::module_permissions(flxa) else {
        unstage(staged);
        return errno::EINVAL;
    };
    if perms & !crate::kernel::module::syscalls::permission::OBSERVE != 0 {
        unstage(staged);
        return errno::EACCES;
    }
    // The creator's own lanes (FLXA `Caller` edges): each lands at the add's
    // first edge plus its position.
    let mut caller_edges = [live::CallerEdge::default(); wl::MAX_CALLER_LANES * 2];
    let Some(caller_edge_count) = live::caller_edges(flxa, &mut caller_edges) else {
        unstage(staged);
        return errno::EINVAL;
    };

    // ── The backend's own copy of the subgraph, carrying the header's
    //    identity (what `apply_add` allocates the owner by) and the memory
    //    ceiling clamped onto the subgraph's caps.
    let blob = &mut (&mut *core::ptr::addr_of_mut!(PENDING_BLOB))[..flxa_len];
    blob.copy_from_slice(flxa);
    blob[FLXA_OWNER_UID_OFF..FLXA_OWNER_UID_OFF + 16].copy_from_slice(&identity);
    let mem_ceil = if memory_bytes == 0 {
        None
    } else {
        Some(memory_bytes.min(u32::MAX as u64) as u32)
    };
    clamp_cap_be(blob, FLXA_STATE_CAP_OFF, mem_ceil);
    clamp_cap_be(blob, FLXA_BUFFER_CAP_OFF, mem_ceil);

    // ── Stage the subgraph: decode it, reserve the owner, assign slots and
    //    open its channels. A `net=own` workload's net-facing producer names
    //    `SPARE_LANE_SENTINEL` (the workload manager cannot name a kernel
    //    channel off-node); it is wired into the boot merge's next free spare
    //    lane on the net provider's ingress, and with no free lane the
    //    CREATE is refused `ENOMEM` before anything is allocated.
    live::set_caller(Some(scheduler::current_module_index()));
    let spare_lane = wants_identity.then(provider_net_in_spare_lane);
    let begun = live::begin_add_encoded(blob, spare_lane);
    live::set_caller(None);
    code_pack::end_staging();
    let staged_add = match begun {
        Ok(st) => st,
        Err(e) => {
            if let Some(s) = staged {
                code_pack::release(s);
            }
            return e;
        }
    };
    // What the owner may hold in the node's storage, set before any of its
    // modules runs.
    scheduler::owners_mut().set_storage_cap(staged_add.handle(), storage_bytes);
    scheduler::owners_mut().set_storage_grant(staged_add.handle(), storage_grant);
    log::info!(
        "[workload] graph workload {}.{}: storage_bytes={}",
        staged_add.handle().slot,
        staged_add.handle().generation,
        storage_bytes
    );
    *core::ptr::addr_of_mut!(PENDING) = Some(PendingCreate {
        identity,
        spec,
        staged: staged_add,
        pack: staged,
        caller_edges,
        caller_edge_count,
    });
    0
}

/// WORKLOAD_CREATE: stage a fmod-graph workload as a new owner subgraph. Returns
/// a tagged `FD_TAG_WORKLOAD` handle, or a negative errno.
///
/// # Safety
/// `arg` must be null or valid for reads and writes of `arg_len` bytes for the
/// call. The `source_ref` (FLXA) region is mutated in place (identity + caps
/// override) and `apply_add_encoded`'s handle write-back overwrites its first 6
/// bytes — the caller's buffer is scratch after CREATE.
unsafe fn workload_create(arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < wl::CREATE_HEADER_SIZE {
        return errno::EINVAL;
    }
    let buf = core::slice::from_raw_parts(arg, arg_len);

    let posture = buf[16];
    let source_kind = buf[17];
    let net_iso = buf[18];
    let memory_bytes = u64::from_le_bytes([
        buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
    ]);
    let storage_bytes = u64::from_le_bytes([
        buf[68], buf[69], buf[70], buf[71], buf[72], buf[73], buf[74], buf[75],
    ]);
    let Some(storage_grant) = StorageGrant::from_wire(buf[19]) else {
        return errno::EINVAL;
    };
    let source_ref_len = rd_u16(buf, 40) as usize;
    let endpoint_count = rd_u16(buf, 42) as usize;
    let options_len = rd_u32(buf, 44) as usize;
    let net_family = buf[48];
    let net_prefix_len = buf[49];
    let net_segment = rd_u16(buf, 50);
    // net_addr @52..68 (16 bytes; IPv4 in bytes 0..4, network order) — matches
    // the `net::identity` ADDR_ADD address-slot layout, so it copies straight
    // into the payload with no re-order.
    let mut net_addr = [0u8; 16];
    net_addr.copy_from_slice(&buf[52..68]);

    // Section bounds.
    let src_start = wl::CREATE_HEADER_SIZE;
    let ep_start = src_start + source_ref_len;
    let opt_start = ep_start + endpoint_count * wl::NET_ENDPOINT_SIZE;
    let opt_end = opt_start + options_len;
    if opt_end > arg_len {
        return errno::EINVAL;
    }

    // ── Header validation (cheap, before any owner is allocated). Honest,
    //    fail-closed: this backend realizes only what CAPS advertises.
    // Backend selection is by source kind: only the fmod-graph source resolves
    // to the metal backend (a bundle → the Linux host-process backend).
    if source_kind != wl::SOURCE_FMOD_GRAPH && source_kind != wl::SOURCE_FMOD_PACK {
        return errno::ENOSYS;
    }
    // Only POSTURE_SHARED is realized; this backend gives a workload no
    // protection domain of its own, so ISOLATED and HARDENED are refused.
    if posture != wl::POSTURE_SHARED {
        return errno::ENOSYS;
    }
    // Net identity admission. The realized identity is IPv4 own-domain —
    // `net_iso == OWN` together with `net_family == IPV4`. A bare
    // host-shared workload (`SHARED` + `NONE`) installs nothing.
    // Anything in between is fail-closed:
    //   * net_iso beyond OWN is malformed,
    //   * own-iso XOR a family (one without the other) is a half-specified
    //     identity — not realized,
    //   * IPv6 and non-default segments are not realized (ENOSYS).
    if net_iso > wl::NET_ISO_OWN {
        return errno::EINVAL;
    }
    let wants_identity = net_iso == wl::NET_ISO_OWN || net_family != wl::NET_FAM_NONE;
    if wants_identity
        && (net_iso != wl::NET_ISO_OWN || net_family != wl::NET_FAM_IPV4 || net_segment != 0)
    {
        return errno::ENOSYS;
    }
    for i in 0..endpoint_count {
        let e = ep_start + i * wl::NET_ENDPOINT_SIZE;
        let ep_iso = buf[e + 1];
        if ep_iso > wl::NET_ISO_OWN {
            return errno::EINVAL;
        }
        if ep_iso == wl::NET_ISO_OWN {
            return errno::ENOSYS; // own-domain endpoint is not realized here
        }
    }

    // Where the FLXA subgraph lies in the source section: all of it for a
    // graph; past the pack reference and its pins for a pack.
    let (flxa_off, flxa_len, pack) = if source_kind == wl::SOURCE_FMOD_PACK {
        use wl::pack_ref;
        if source_ref_len < pack_ref::SIZE {
            return errno::EINVAL;
        }
        let r = &buf[src_start..src_start + pack_ref::SIZE];
        let ptr = u64::from_le_bytes([r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]]) as usize;
        let len = rd_u32(r, pack_ref::LEN) as usize;
        let pins = rd_u16(r, pack_ref::PIN_COUNT) as usize;
        let head = pack_ref::SIZE + pins * pack_ref::PIN_SIZE;
        if ptr == 0 || len == 0 || source_ref_len < head {
            return errno::EINVAL;
        }
        (
            src_start + head,
            source_ref_len - head,
            Some((ptr, len, pins)),
        )
    } else {
        (src_start, source_ref_len, None)
    };
    if flxa_len < FLXA_MIN_LEN {
        return errno::EINVAL; // not a well-formed FLXA subgraph
    }

    // ── Who the workload is, and what it may hold.
    //
    // The identity is what the owner is allocated by, and what an owner's
    // resources key on (storage scoped by `mount`, a volume's grant). The
    // null identity names no one — every workload created with it would be
    // the same owner to anything keyed on it — so it is refused.
    if buf[..16].iter().all(|&b| b == 0) {
        return errno::EINVAL;
    }
    let mut identity = [0u8; 16];
    identity.copy_from_slice(&buf[..16]);
    let spec = spec_digest(&buf[..opt_end]);

    // A CREATE being staged is continued by its own identity with the same
    // spec; anything else waits until it is published or abandoned.
    if let Some(id) = pending_identity() {
        let same = id == identity
            && (*core::ptr::addr_of!(PENDING))
                .as_ref()
                .is_some_and(|p| p.spec == spec);
        if !same {
            return errno::EBUSY;
        }
    } else {
        // One identity is one workload.
        if scheduler::owners().find_by_uid(identity).is_some() {
            return errno::EEXIST;
        }
        let rc = begin_create(
            buf,
            flxa_off,
            flxa_len,
            pack,
            src_start,
            memory_bytes,
            storage_bytes,
            storage_grant,
            wants_identity,
            identity,
            spec,
        );
        if rc != 0 {
            return rc;
        }
    }

    // ── One batch of the pending add; the rest of CREATE once its last
    //    module is in.
    let p = (*core::ptr::addr_of_mut!(PENDING))
        .as_mut()
        .expect("pending CREATE");
    if let Some(s) = p.pack {
        code_pack::begin_staging(s);
    }
    let batch = live::instantiate_batch(&mut p.staged, CREATE_MODULES_PER_CALL);
    code_pack::end_staging();
    match batch {
        Ok(false) => return errno::EINPROGRESS,
        Ok(true) => {}
        Err(e) => {
            // The add rolled itself back; its pack goes with it.
            if let Some(p) = (*core::ptr::addr_of_mut!(PENDING)).take() {
                if let Some(s) = p.pack {
                    code_pack::release(s);
                }
            }
            return e.code();
        }
    }
    let Some(p) = (*core::ptr::addr_of_mut!(PENDING)).take() else {
        return errno::EINVAL;
    };
    let edge_base = p.staged.edge_base();
    let caller_edges = p.caller_edges;
    let caller_edge_count = p.caller_edge_count;
    let owner = match live::finish_staged(p.staged) {
        Ok(owner) => owner,
        Err(e) => {
            if let Some(s) = p.pack {
                code_pack::release(s);
            }
            return e.code();
        }
    };
    // The pack is the owner's now: freed with it (`live::free_owner`), so
    // every later failure's `free_owner` takes the code too.
    if let Some(s) = p.pack {
        code_pack::bind(s, owner.slot);
    }

    // ── Lease-gate each declared endpoint against the owner's retained plan
    //    (as `linux/workload.rs` does). A refusal fails CREATE
    //    here — not silently at bind — so roll the staged owner back.
    for i in 0..endpoint_count {
        let e = ep_start + i * wl::NET_ENDPOINT_SIZE;
        let proto = buf[e];
        let port = rd_u16(buf, e + 2);
        if matches!(
            lease_gate(owner.slot, owner.generation, proto, port),
            LeaseGate::Refused
        ) {
            let _ = live::free_owner(owner);
            return errno::EACCES;
        }
    }

    // ── Net-identity install. Install the workload's address into the
    //    net-identity provider BEFORE the START barrier — the address is
    //    live/ARP-answered before the workload ever runs (the provider makes it
    //    "live before any bind"). owner_tag = the just-allocated
    //    owner slot. A resolve/write failure fails CREATE and rolls the owner
    //    back — a `net=own` workload never runs without its identity.
    if wants_identity {
        let rc = install_identity(&net_addr, net_prefix_len, owner.slot);
        if rc != 0 {
            let _ = live::free_owner(owner);
            return rc;
        }
    }

    // ── START barrier: stage paused. `apply_add` set the owner Active;
    //    pause it now so it does not run until START resumes it.
    if live::owner_pause(owner).is_err() {
        remove_identity(&net_addr);
        let _ = live::free_owner(owner);
        return errno::EINVAL;
    }

    // ── Allocate the workload slot.
    let slots = &mut *core::ptr::addr_of_mut!(FMOD_WORKLOADS);
    let widx = match slots.iter().position(|s| !s.in_use) {
        Some(i) => i,
        None => {
            remove_identity(&net_addr);
            let _ = live::free_owner(owner); // don't leak the staged owner
            return errno::ENOMEM;
        }
    };
    let mut lanes = [NO_LANE; wl::MAX_CALLER_LANES];
    let mut lane_count = 0usize;
    for ce in caller_edges.iter().take(caller_edge_count) {
        let ch = scheduler::sched_mut().edges[edge_base + ce.index].channel;
        let at = match lanes[..lane_count].iter().position(|l| l.key == ce.key) {
            Some(at) => at,
            None if lane_count < wl::MAX_CALLER_LANES => {
                lanes[lane_count].key = ce.key;
                lane_count += 1;
                lane_count - 1
            }
            None => {
                remove_identity(&net_addr);
                let _ = live::free_owner(owner);
                return errno::ENOMEM;
            }
        };
        if ce.into_caller {
            lanes[at].to_caller = ch;
        } else {
            lanes[at].from_caller = ch;
        }
    }
    slots[widx] = WorkloadSlot {
        in_use: true,
        owner,
        // Only an installed identity is remembered for the DESTROY-time
        // ADDR_DEL; a host-shared workload stores a zero address (no-op DEL).
        net_addr: if wants_identity { net_addr } else { [0u8; 16] },
        lanes,
        lane_count: lane_count as u8,
    };
    tag_fd(FD_TAG_WORKLOAD, widx as i32)
}

/// Resolve a stripped workload slot index to its owner, or `None` if the slot
/// is out of range or free.
unsafe fn slot_owner(raw: i32) -> Option<OwnerHandle> {
    let idx = raw as usize;
    let slots = &*core::ptr::addr_of!(FMOD_WORKLOADS);
    if idx >= MAX_WORKLOADS || !slots[idx].in_use {
        return None;
    }
    Some(slots[idx].owner)
}

/// Map an owner's live status to the WAIT `(state, code)` pair, defined for
/// the fmod model — a graph runs forever, so there is no process-shaped
/// "exit code":
///   * no record (owner freed / torn down) → `(STATE_EXITED, 0)` — the only
///     EXITED path,
///   * any module faulted (`last_fault_kind != NONE` or `modules_terminated`)
///     → `(STATE_SIGNALLED, last_fault_kind)` — the fmod analogue of a kill,
///   * owner paused → `(STATE_PAUSED, 0)`,
///   * otherwise (Active, no fault; Draining still serves) → `(STATE_RUNNING, 0)`.
///
/// A pure function of the snapshot, so the fault→SIGNALLED mapping is
/// unit-testable against a synthetic `OwnerLiveStatus` (a real in-harness module
/// fault is impractical to induce for the metal path).
pub fn wait_state_map(rec: Option<&OwnerLiveStatus>) -> (u8, i32) {
    match rec {
        None => (wl::STATE_EXITED, 0),
        Some(s) => {
            if s.last_fault_kind != fault_type::NONE || s.modules_terminated > 0 {
                (wl::STATE_SIGNALLED, s.last_fault_kind as i32)
            } else if s.owner_state == OWNER_STATE_PAUSED {
                (wl::STATE_PAUSED, 0)
            } else {
                (wl::STATE_RUNNING, 0)
            }
        }
    }
}

/// WORKLOAD_WAIT: snapshot the owner's live status and write
/// `[state:u8][code:i32 LE]` into `out`. Non-blocking.
///
/// `owner` is `None` when the workload slot was already reaped (DESTROY/KILL):
/// a torn-down handle reads as EXITED — the terminal state a status loop polls
/// after teardown — never an error.
///
/// # Safety
/// `arg` must be valid for writes of `arg_len` (>= 5) bytes.
unsafe fn workload_wait(owner: Option<OwnerHandle>, arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 5 {
        return errno::EINVAL;
    }
    let mut snap = [OwnerLiveStatus::EMPTY; MAX_OWNERS];
    let n = scheduler::owner_live_snapshot(&mut snap);
    let rec = owner.and_then(|o| {
        snap[..n]
            .iter()
            .find(|r| r.slot == o.slot && r.generation == o.generation)
    });
    let (state, code) = wait_state_map(rec);
    let out = core::slice::from_raw_parts_mut(arg, arg_len);
    out[0] = state;
    out[1..5].copy_from_slice(&code.to_le_bytes());
    5
}

/// WORKLOAD_CAPS: write the metal backend's honest capability set. Same
/// prefix shape as the Linux backend: `[postures:u8][source_kinds:u8]
/// [ops:u16 LE][net:u8]` then an empty namespace directory `[ns_count:u16 = 0]`.
///
/// # Safety
/// `arg` must be valid for writes of `arg_len` (>= 7) bytes.
unsafe fn workload_caps(arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 7 {
        return errno::EINVAL;
    }
    let out = core::slice::from_raw_parts_mut(arg, arg_len);
    // Postures: SHARED only. ISOLATED/HARDENED need EL0-per-workload.
    out[0] = wl::caps::POSTURE_SHARED;
    // Source kinds: an fmod graph, and a graph bringing its own modules where
    // the node has code space for packs. Never a host bundle: metal has no
    // rootfs to unpack one into.
    out[1] = wl::caps::SOURCE_FMOD_GRAPH
        | if code_pack::POOL_SIZE > 0 {
            wl::caps::SOURCE_FMOD_PACK
        } else {
            0
        };
    // Ops: PAUSE only. READ (no metal owner-log tee), EXEC/TTY (no process to
    // exec into) stay clear; the SIGNAL bit asserts real process-group signal
    // delivery this backend does not provide (TERM→drain, KILL→free).
    out[2..4].copy_from_slice(&(wl::caps::PAUSE | wl::caps::LOOKUP).to_le_bytes());
    // Net: NET_ISO_OWN | NET_IDENTITY — a `net=own` workload's own IPv4
    // address is installed into the net-identity provider and ARP-answered.
    // Owner-scoped *binds* to that address are not resolved here (the
    // workload's binds run host-wildcard), but the address itself is live,
    // so both bits are honestly set.
    out[4] = wl::caps::NET_ISO_OWN | wl::caps::NET_IDENTITY;
    out[5..7].copy_from_slice(&0u16.to_le_bytes()); // ns_count
    7
}

/// The metal `workload` (0x1A) provider dispatch. CREATE/CAPS are the `handle
/// = -1` globals; lifecycle ops carry the `FD_TAG_WORKLOAD` handle, stripped
/// to a slot by `slot_of`. Matches `provider::ProviderDispatch` and the Linux
/// `linux_workload_dispatch` signature.
///
/// # Safety
/// Scheduler-thread dispatch only: touches `static mut` provider state and the
/// live graph without synchronization, and must run on the primary domain
/// (core 0) — see the module header. `arg` must be null or valid for reads and
/// writes of `arg_len` bytes for the call.
pub unsafe fn workload_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    let timed = matches!(opcode, wl::CREATE | wl::DESTROY);
    let t0 = if timed {
        crate::kernel::sys::hal::now_micros()
    } else {
        0
    };
    let rc = dispatch_op(handle, opcode, arg, arg_len);
    if timed {
        live_stats_record(
            opcode,
            rc,
            crate::kernel::sys::hal::now_micros().saturating_sub(t0),
        );
    }
    rc
}

// ── Live-churn telemetry ─────────────────────────────────────────
//
// A node that admits and reaps workloads for its whole life must not leak
// what each one takes. These counters make that a reading rather than a
// guess: every `LIVE_STATS_EVERY` DESTROY calls (and on any refused CREATE)
// one `[live]` line reports the graph's population beside both arenas'
// high-water marks and free lists, so a rig run shows whether churn returns
// to a fixed point. The worst CREATE/DESTROY wall time bounds how long one
// live change held the scheduler thread; the peer cores are quiesced for the
// graph edit inside it.

struct LiveStats {
    creates: u32,
    create_fails: u32,
    destroys: u32,
    create_max_us: u32,
    destroy_max_us: u32,
}

static mut LIVE_STATS: LiveStats = LiveStats {
    creates: 0,
    create_fails: 0,
    destroys: 0,
    create_max_us: 0,
    destroy_max_us: 0,
};

const LIVE_STATS_EVERY: u32 = 25;

/// Fold one timed op into the counters and report when due. Scheduler thread.
unsafe fn live_stats_record(opcode: u32, rc: i32, us: u64) {
    let st = &mut *core::ptr::addr_of_mut!(LIVE_STATS);
    let us = us.min(u32::MAX as u64) as u32;
    let due = if opcode == wl::CREATE {
        if rc == errno::EINPROGRESS {
            false
        } else if rc < 0 {
            st.create_fails = st.create_fails.wrapping_add(1);
            true
        } else {
            st.creates = st.creates.wrapping_add(1);
            st.create_max_us = st.create_max_us.max(us);
            false
        }
    } else {
        st.destroys = st.destroys.wrapping_add(1);
        st.destroy_max_us = st.destroy_max_us.max(us);
        st.destroys.checked_rem(LIVE_STATS_EVERY) == Some(0)
    };
    if !due {
        return;
    }
    let s = scheduler::sched_mut();
    let (state_used, state_cap) = crate::kernel::module::loader::arena_usage();
    let (holes, hole_bytes) = crate::kernel::module::loader::state_free_list_usage();
    let (buf_used, buf_cap) = crate::kernel::ipc::buffer_pool::arena_usage();
    let (bholes, bhole_bytes, bleaked) = crate::kernel::ipc::buffer_pool::buffer_free_list_usage();
    log::info!(
        "[live] c={} cf={} d={} rc={} mods={} edges={} owners={} state={}/{} holes={}/{} buf={}/{} bholes={}/{} bleak={} cmax_us={} dmax_us={}",
        st.creates,
        st.create_fails,
        st.destroys,
        rc,
        s.active_module_count,
        s.edge_count,
        scheduler::owners_mut().active_workload_count(),
        state_used,
        state_cap,
        holes,
        hole_bytes,
        buf_used,
        buf_cap,
        bholes,
        bhole_bytes,
        bleaked,
        st.create_max_us,
        st.destroy_max_us,
    );
}

unsafe fn dispatch_op(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    if opcode == wl::CREATE {
        return workload_create(arg, arg_len);
    }
    if opcode == wl::MODULE_DIGESTS {
        if arg.is_null() {
            return errno::EINVAL;
        }
        let out = core::slice::from_raw_parts_mut(arg, arg_len);
        return code_pack::node_digests(scheduler::static_loader(), out);
    }
    if opcode == wl::CAPS {
        return workload_caps(arg, arg_len);
    }
    // A net provider that is a module (the bare-metal `ip`): it claims the
    // role, takes the lanes staged workloads attach, and asks whether a
    // lane's owner may bind (see `net_attach`).
    if opcode == wl::NET_PROVIDE {
        return crate::kernel::workload::net_attach::provide_queued(
            scheduler::current_module_index(),
        );
    }
    if opcode == wl::NET_LANE_TAKE || opcode == wl::NET_LANE_ADMIT {
        if arg.is_null() {
            return errno::EINVAL;
        }
        let slot = scheduler::current_module_index();
        let buf = core::slice::from_raw_parts_mut(arg, arg_len);
        return if opcode == wl::NET_LANE_TAKE {
            crate::kernel::workload::net_attach::take_queued(slot, buf)
        } else {
            crate::kernel::workload::net_attach::admit_queued(slot, buf)
        };
    }

    if opcode == wl::LOOKUP {
        if arg.is_null() || arg_len < 16 {
            return errno::EINVAL;
        }
        let out = core::slice::from_raw_parts_mut(arg, arg_len);
        let mut identity = [0u8; 16];
        identity.copy_from_slice(&out[..16]);
        if pending_identity() == Some(identity) {
            return errno::EINPROGRESS;
        }
        let Some(widx) = slot_by_identity(&identity) else {
            return errno::ENOENT;
        };
        let owner = (*core::ptr::addr_of!(FMOD_WORKLOADS))[widx].owner;
        out[0..2].copy_from_slice(&owner.slot.to_le_bytes());
        out[2..6].copy_from_slice(&owner.generation.to_le_bytes());
        return tag_fd(FD_TAG_WORKLOAD, widx as i32);
    }
    if opcode == wl::DESTROY && handle < 0 {
        if arg.is_null() || arg_len < 16 {
            return errno::EINVAL;
        }
        let mut identity = [0u8; 16];
        identity.copy_from_slice(core::slice::from_raw_parts(arg, 16));
        if pending_identity() == Some(identity) {
            // Abandon the staged CREATE: its add rolls back and its pack goes.
            abandon_pending();
            return 0;
        }
        return match slot_by_identity(&identity) {
            Some(widx) => destroy_slot(widx),
            None => errno::ENOENT,
        };
    }

    let raw = slot_of(handle);
    let owner_opt = slot_owner(raw);
    // WAIT tolerates a reaped slot → EXITED: a status loop keeps polling
    // after DESTROY/KILL and must see the terminal state, not an error.
    if opcode == wl::WAIT {
        return workload_wait(owner_opt, arg, arg_len);
    }
    let Some(owner) = owner_opt else {
        return errno::EINVAL;
    };
    match opcode {
        // START releases the create-time pause. Idempotent (resume of an
        // already-Active owner is a no-op).
        wl::START => match live::owner_resume(owner) {
            Ok(()) => 0,
            Err(_) => errno::EINVAL,
        },
        wl::PAUSE => match live::owner_pause(owner) {
            Ok(()) => 0,
            Err(_) => errno::EINVAL,
        },
        wl::RESUME => match live::owner_resume(owner) {
            Ok(()) => 0,
            Err(_) => errno::EINVAL,
        },
        wl::SIGNAL => {
            if arg.is_null() || arg_len < 4 {
                return errno::EINVAL;
            }
            let signo = rd_u32(core::slice::from_raw_parts(arg, arg_len), 0);
            match signo {
                // Graceful: move the owner to Draining (its graphs run dry).
                wl::SIG_TERM => {
                    scheduler::owners_mut().begin_drain(owner);
                    0
                }
                // Immediate: tear the owner down. The slot is left in place so a
                // subsequent WAIT resolves the handle and reports EXITED; DESTROY
                // reaps the slot. Remove the net identity and clear the
                // stored address so DESTROY does not re-emit ADDR_DEL.
                wl::SIG_KILL => {
                    let slots = &mut *core::ptr::addr_of_mut!(FMOD_WORKLOADS);
                    remove_identity(&slots[raw as usize].net_addr);
                    slots[raw as usize].net_addr = [0u8; 16];
                    // The lanes' channels close with the owner; the ids must
                    // not outlive them, or LANES would name channels another
                    // owner may be given.
                    slots[raw as usize].lanes = [NO_LANE; wl::MAX_CALLER_LANES];
                    slots[raw as usize].lane_count = 0;
                    let _ = live::free_owner(owner);
                    0
                }
                _ => errno::ENOSYS, // portable subset only
            }
        }
        wl::LANES => {
            // An owner that has gone (drained out, torn down elsewhere) took
            // its channels with it.
            if scheduler::owners_mut().lookup(owner).is_none() {
                return errno::EINVAL;
            }
            let slot = &(*core::ptr::addr_of!(FMOD_WORKLOADS))[raw as usize];
            let n = slot.lane_count as usize;
            let need = 1 + n * 9;
            if arg.is_null() || arg_len < need {
                return errno::EINVAL;
            }
            let out = core::slice::from_raw_parts_mut(arg, need);
            out[0] = n as u8;
            for (i, l) in slot.lanes.iter().take(n).enumerate() {
                let o = 1 + i * 9;
                out[o] = l.key;
                out[o + 1..o + 5].copy_from_slice(&l.to_caller.to_le_bytes());
                out[o + 5..o + 9].copy_from_slice(&l.from_caller.to_le_bytes());
            }
            need as i32
        }
        wl::DESTROY => destroy_slot(raw as usize),
        _ => errno::ENOSYS,
    }
}

/// Tear workload slot `widx` down: remove its net identity (ADDR_DEL) before
/// freeing the owner (a zero or cleared address is a no-op: host-shared, or
/// already removed by SIG_KILL), then free the slot.
unsafe fn destroy_slot(widx: usize) -> i32 {
    let slots = &mut *core::ptr::addr_of_mut!(FMOD_WORKLOADS);
    remove_identity(&slots[widx].net_addr);
    let _ = live::free_owner(slots[widx].owner); // idempotent — stale handle is fine
    slots[widx] = WL_EMPTY;
    0
}

/// The live workload slot whose owner carries `identity`.
unsafe fn slot_by_identity(identity: &[u8; 16]) -> Option<usize> {
    let slots = &*core::ptr::addr_of!(FMOD_WORKLOADS);
    let owners = scheduler::owners();
    (0..MAX_WORKLOADS).find(|&i| {
        slots[i].in_use
            && owners
                .lookup(slots[i].owner)
                .is_some_and(|e| e.owner_uid == *identity)
    })
}

/// Does `pins` (32-byte SHA-256 pins, back to back) hold `digest`?
fn pin_matches(pins: &[u8], digest: &[u8; 32]) -> bool {
    pins.chunks_exact(32).any(|p| p == digest)
}
