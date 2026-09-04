// ============================================================================
// Metal module-graph `workload` backend (contract class 0x1A).
// ============================================================================
//
// The bare-metal realization of the `workload` contract: a workload is an owned
// module subgraph, staged onto the live graph via the already-built owner /
// lease / live-graph primitives (the "facade" of `fluxor_nanocloud.md` §4.1).
// This is the metal twin of `platform::linux::workload` (the host-process
// backend). It lives in `src/kernel` — not `src/platform/bcm2712` — because the
// logic is kernel-generic multitenant: `apply_add`/`free_owner`/`owner_pause`
// reach the run loop on **host-linux** too, so the harness drives this dispatch
// end-to-end there (the metal registration in `bcm2712::bcm_init_providers` is a
// thin wrapper that installs `workload_dispatch` as the 0x1A provider).
//
// Per-op mapping:
//   CREATE  — decode the `source_ref` FLXA subgraph → `apply_add`; stage paused
//             (§4.1 START barrier); lease-gate the header endpoints; allocate a
//             `WorkloadSlot`; return `tag_fd(FD_TAG_WORKLOAD, idx)`.
//   START   — `owner_resume` (release the create-time pause).
//   WAIT    — map the owner's live status → `[state:u8][code:i32 LE]` (§4.2).
//   SIGNAL  — TERM → `begin_drain`, KILL → `free_owner` (§4.3).
//   DESTROY — `free_owner` + clear the slot (idempotent).
//   PAUSE / RESUME — `owner_pause` / `owner_resume` (direct).
//   CAPS    — the metal bitmap (§4.4): SHARED posture, FMOD_GRAPH source, PAUSE
//             op, no net identity.
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
use crate::kernel::workload::owner::{OwnerHandle, MAX_OWNERS, OWNER_SYSTEM};
use crate::kernel::workload::owner_plan::{lease_gate, LeaseGate};

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
// receiver is a valid provider; the foundation `ip` module is today's.

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
    /// `ADDR_DEL` (§3.3).
    net_addr: [u8; 16],
}

const WL_EMPTY: WorkloadSlot = WorkloadSlot {
    in_use: false,
    owner: OWNER_SYSTEM,
    net_addr: [0u8; 16],
};

const MAX_WORKLOADS: usize = MAX_OWNERS;

static mut FMOD_WORKLOADS: [WorkloadSlot; MAX_WORKLOADS] = [WL_EMPTY; MAX_WORKLOADS];

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
/// the ceiling wins; otherwise the tighter of the two holds (§3.1 step 3 —
/// caps, never a new meter).
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
/// registration (§3.3), or `-1` when no provider has registered (a node with
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

/// Single-writer gate (§3.3): the backend is the *sole* writer of `addr_ctl`, so
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
/// (§3.3): resolve the `addr_ctl` channel, assert single-writer, and write
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

/// Emit `ADDR_DEL [addr:16]` for a torn-down workload's address (§3.3).
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
    let buf = core::slice::from_raw_parts_mut(arg, arg_len);

    let posture = buf[16];
    let source_kind = buf[17];
    let net_iso = buf[18];
    let memory_bytes = u64::from_le_bytes([
        buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
    ]);
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
    if source_kind != wl::SOURCE_FMOD_GRAPH {
        return errno::ENOSYS;
    }
    // Only POSTURE_SHARED is realized; ISOLATED/HARDENED need EL0 wiring.
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
    //   * IPv6 and non-default segments are deferred with net_identity (ENOSYS).
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

    if source_ref_len < FLXA_MIN_LEN {
        return errno::EINVAL; // not a well-formed FLXA subgraph
    }

    // ── Bridge the durable workload identity into the FLXA blob so `apply_add`'s
    //    `owners.alloc(owner_uid)` / `find_by_uid` carries the header identity
    //    (§3.1 step 2), and clamp the FLXA caps to the envelope memory ceiling
    //    (§3.1 step 3 — caps, never a new meter). Both edits are in place within
    //    the `source_ref` region, which we validated is >= FLXA_MIN_LEN long.
    buf.copy_within(0..16, src_start + FLXA_OWNER_UID_OFF);
    let mem_ceil = if memory_bytes == 0 {
        None
    } else {
        Some(memory_bytes.min(u32::MAX as u64) as u32)
    };
    clamp_cap_be(buf, src_start + FLXA_STATE_CAP_OFF, mem_ceil);
    clamp_cap_be(buf, src_start + FLXA_BUFFER_CAP_OFF, mem_ceil);

    // ── Stage the subgraph. `apply_add_encoded` decodes the FLXA blob (PIC
    //    modules, edges, caps), allocates the owner, instantiates + splices —
    //    the complete admission gate (name_hash resolvable in flash, bounds,
    //    atomic rollback). On metal this is the first runtime `apply_add`, which
    //    drives the per-domain splice + multicore quiesce. On success
    //    it writes `[slot:u16 LE][generation:u32 LE]` into the blob's first 6
    //    bytes; we read the owner handle back from there.
    //
    //    Spare-lane injection seam. A `net=own`
    //    workload composes its net-facing producer edge with a
    //    `SPARE_LANE_SENTINEL` `to` (the workload manager cannot name a kernel runtime
    //    channel off-node). Resolve the boot merge's next free spare lane on
    //    the provider's `net_in` and hand it to the decode→inject→apply variant, which
    //    rewrites the sentinel to `ExistingChannel(lane)` so the producer edges
    //    straight into the merge. A free lane read is side-effect-free (the
    //    attach commits inside `apply_add`), so a `-1` (no merge / exhausted)
    //    with a sentinel present fails `ENOMEM` before anything is allocated.
    //    A host-shared workload carries no sentinel and takes the plain path,
    //    byte-identical.
    let src_ptr = arg.add(src_start);
    let rc = if wants_identity {
        let spare_lane = provider_net_in_spare_lane();
        live::apply_add_encoded_spare_lane(src_ptr, source_ref_len, spare_lane)
    } else {
        live::apply_add_encoded(src_ptr, source_ref_len)
    };
    if rc != 0 {
        return rc; // negative AddError::code, -ENOMEM (no spare lane), or -EINVAL
    }
    let hb = core::slice::from_raw_parts(src_ptr, 6);
    let owner = OwnerHandle {
        slot: u16::from_le_bytes([hb[0], hb[1]]),
        generation: u32::from_le_bytes([hb[2], hb[3], hb[4], hb[5]]),
    };

    // ── Lease-gate each declared endpoint against the owner's retained plan
    //    (§3.1 step 5, identical to `linux/workload.rs`). A refusal fails CREATE
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

    // ── START barrier (§4.1): stage paused. `apply_add` set the owner Active;
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
    slots[widx] = WorkloadSlot {
        in_use: true,
        owner,
        // Only an installed identity is remembered for the DESTROY-time
        // ADDR_DEL; a host-shared workload stores a zero address (no-op DEL).
        net_addr: if wants_identity { net_addr } else { [0u8; 16] },
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

/// Map an owner's live status to the WAIT `(state, code)` pair (§4.2, redefined
/// for the fmod model — a graph runs forever, so there is no process-shaped
/// "exit code"):
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
/// `[state:u8][code:i32 LE]` into `out` (§4.2). Non-blocking.
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

/// WORKLOAD_CAPS: write the metal backend's honest capability set (§4.4). Same
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
    // Postures: SHARED only. ISOLATED/HARDENED need EL0-per-workload (§5).
    out[0] = wl::caps::POSTURE_SHARED;
    // Source kinds: fmod-graph (metal has no rootfs bundle transport).
    out[1] = wl::caps::SOURCE_FMOD_GRAPH;
    // Ops: PAUSE only. READ (no metal owner-log tee), EXEC/TTY (no process to
    // exec into) stay clear; the SIGNAL bit asserts real process-group signal
    // delivery this backend does not provide (TERM→drain, KILL→free).
    out[2..4].copy_from_slice(&wl::caps::PAUSE.to_le_bytes());
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
    if opcode == wl::CREATE {
        return workload_create(arg, arg_len);
    }
    if opcode == wl::CAPS {
        return workload_caps(arg, arg_len);
    }

    let raw = slot_of(handle);
    let owner_opt = slot_owner(raw);
    // WAIT tolerates a reaped slot → EXITED (§4.2): a status loop keeps polling
    // after DESTROY/KILL and must see the terminal state, not an error.
    if opcode == wl::WAIT {
        return workload_wait(owner_opt, arg, arg_len);
    }
    let Some(owner) = owner_opt else {
        return errno::EINVAL;
    };
    match opcode {
        // START releases the create-time pause (§4.1). Idempotent (resume of an
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
                // reaps the slot. Remove the net identity (§3.3) and clear the
                // stored address so DESTROY does not re-emit ADDR_DEL.
                wl::SIG_KILL => {
                    let slots = &mut *core::ptr::addr_of_mut!(FMOD_WORKLOADS);
                    remove_identity(&slots[raw as usize].net_addr);
                    slots[raw as usize].net_addr = [0u8; 16];
                    let _ = live::free_owner(owner);
                    0
                }
                _ => errno::ENOSYS, // portable subset only
            }
        }
        wl::DESTROY => {
            // Remove the net identity (§3.3 — ADDR_DEL) before freeing the
            // owner; a zero/cleared address is a no-op (host-shared, or already
            // removed by SIG_KILL).
            let slots = &mut *core::ptr::addr_of_mut!(FMOD_WORKLOADS);
            remove_identity(&slots[raw as usize].net_addr);
            let _ = live::free_owner(owner); // idempotent — stale handle is fine
            slots[raw as usize] = WL_EMPTY;
            0
        }
        _ => errno::ENOSYS,
    }
}
