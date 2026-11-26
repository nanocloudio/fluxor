// ============================================================================
// Metal module-graph `workload` backend (contract class `workload`).
// ============================================================================
//
// The bare-metal realization of the `workload` contract: a workload is an owned
// module subgraph, staged onto the live graph via the already-built owner /
// live-graph primitives.
// This is the metal twin of `platform::linux::workload` (the host-process
// backend). It lives in `src/kernel` — not `src/platform/bcm2712` — because the
// logic is kernel-generic: splice/`free_owner`/`owner_pause`
// reach the run loop on **host-linux** too, so the harness drives this dispatch
// end-to-end there (the metal registration in `bcm2712::bcm_init_providers` is a
// thin wrapper that installs `workload_dispatch` as the 0x1A provider).
//
// Per-op mapping:
//   CREATE  — decode the `source_ref` composed graph → the splice; stage paused
//             (the START barrier); allocate a `WorkloadSlot`; return its index
//             (the kernel wraps it in a handle).
//   START   — `owner_resume` (release the create-time pause).
//   WAIT    — map the owner's live status → `[state:u8][code:i32 LE]`.
//   SIGNAL  — TERM → `begin_drain`, KILL → `free_owner`.
//   DESTROY — `free_owner` + clear the slot (idempotent).
//   PAUSE / RESUME — `owner_pause` / `owner_resume` (direct).
//   CAPS    — the posture the node realizes, the source kinds, PAUSE and
//             LOOKUP.
//
// The backend knows little of a workload's network: its address and name
// service are the node agent's to give the node's net provider before START
// (`net::identity` on the provider's `addr_ctl`); the endpoints it may
// listen on are the `CREATE`'s `net`/`endpoint` options, which only a
// creator acting with the node's authority gives (`endpoints::admit`); and
// its lanes are kernel facts with no content
// (`kernel::workload::lanes`).
//
// **Dispatch context invariant:** runtime splice/`free_owner` must run
// on the primary domain / core 0 — `request_quiesce` (the peer-core quiesce
// built into splice/`free_owner`) is primary-only. The
// `workload` provider dispatches on the node graph, which lives on domain 0,
// so this holds naturally; there is no secondary-core path into this backend.

use crate::abi::contracts::workload as wl;
use crate::kernel::exec::scheduler::{self, OwnerLiveStatus, OWNER_STATE_PAUSED};
use crate::kernel::exec::scheduler::{live, splice};
use crate::kernel::exec::step_guard::fault_type;
use crate::kernel::module::user_span::UserSpan;
use crate::kernel::sys::errno;
use crate::kernel::workload::code_pack;
use crate::kernel::workload::owner::{OwnerHandle, OWNER_NODE, OWNER_TABLE_SLOTS};

/// One admitted metal workload: its owner subgraph. Mirrors the Linux
/// `WorkloadSlot`, minus the host-process backend index (the subgraph *is* the
/// backend). Bounded by the owner table — at most one workload per owner slot.
#[derive(Clone, Copy)]
struct WorkloadSlot {
    in_use: bool,
    owner: OwnerHandle,
    /// The creating module's lanes into the subgraph (`wl::LANE`).
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
    owner: OWNER_NODE,
    lanes: [NO_LANE; wl::MAX_CALLER_LANES],
    lane_count: 0,
};

/// One workload slot per owner slot: the static profile's compiled size.
/// Where tables are sized at boot it is sized to the owner table ([`size`]).
const MAX_WORKLOADS: usize = OWNER_TABLE_SLOTS;

static mut FMOD_WORKLOADS: crate::kernel::mem::table::Table<WorkloadSlot, MAX_WORKLOADS> = crate::boot_table!(
    MAX_WORKLOADS,
    WL_EMPTY,
    crate::abi::contracts::resource::POOL_OWNERS
);

/// Who holds each workload slot's handle: the owner of the module that
/// created it. Only that owner, or a caller acting with the node's
/// authority, acts on the workload ([`may_act_on`]).
static mut FMOD_HOLDERS: crate::kernel::mem::table::Table<OwnerHandle, MAX_WORKLOADS> =
    crate::boot_table!(MAX_WORKLOADS, OWNER_NODE);

/// Size the workload slots to the owner table's `owners` slots.
///
/// # Safety
/// Graph-preparation context: no reference into the table is live.
pub unsafe fn size(owners: usize) -> Result<(), crate::kernel::mem::table::TableError> {
    let t = &*core::ptr::addr_of!(FMOD_WORKLOADS);
    t.reserve(owners)?;
    t.grow(owners)?;
    let h = &*core::ptr::addr_of!(FMOD_HOLDERS);
    h.reserve(owners)?;
    h.grow(owners)?;
    let staging_slots = staging_for(splice::workspaces_for(owners));
    let st = &*core::ptr::addr_of!(STAGING);
    st.reserve(staging_slots)?;
    st.grow(staging_slots)?;
    let b = &*core::ptr::addr_of!(PENDING_BLOB);
    b.reserve(staging_slots * BLOB_BYTES)?;
    b.grow(staging_slots * BLOB_BYTES)
}

/// Whether the calling module may act on the workload in slot `widx`: its
/// owner is the one that created it (began its `CREATE`), or it acts with
/// the node's authority (the node agent). Every handle op, `LOOKUP` and
/// `DESTROY` by identity answer anyone else `EACCES`.
unsafe fn may_act_on(widx: usize) -> bool {
    let holders = &*core::ptr::addr_of!(FMOD_HOLDERS);
    may_act_as(holders.get(widx).copied().unwrap_or(OWNER_NODE))
}

/// Whether the caller is `holder`, or acts with the node's authority.
fn may_act_as(holder: OwnerHandle) -> bool {
    scheduler::caller_authority() == OWNER_NODE || scheduler::caller_owner() == holder
}

/// The owner staging the pending `CREATE`: only it (or a caller with the
/// node's authority) continues it, finds it with `LOOKUP` or abandons it.
static mut PENDING_HOLDER: Option<OwnerHandle> = None;

/// A `CREATE` whose subgraph is being instantiated a batch per call. The
/// backend owns everything the add reads between calls: its own copy of the
/// subgraph (the modules' params are read from it as they instantiate), and
/// the pack its names resolve in. One is pending at a time.
struct PendingCreate {
    identity: [u8; 16],
    /// SHA-256 of the spec as the caller sent it: a continuation sends the
    /// same bytes.
    spec: [u8; 32],
    staged: splice::StagedAdd,
    pack: Option<code_pack::Staged>,
    caller_edges: [splice::CallerEdge; wl::MAX_CALLER_LANES * 2],
    caller_edge_count: usize,
}

/// What a `CREATE` holds from its first call to its last: the add it stages.
struct Staging {
    pending: Option<PendingCreate>,
}

impl Staging {
    const EMPTY: Staging = Staging { pending: None };
}

/// A graph source is at most a `u16` long (the header's `source_ref_len`).
const BLOB_BYTES: usize = u16::MAX as usize;

/// Staging slots on a node that stages `adds` adds at once: one `CREATE` at
/// a time, none where it stages none.
const fn staging_for(adds: usize) -> usize {
    if adds > 0 {
        1
    } else {
        0
    }
}

/// The profile's compiled staging slots, for a static-table profile (wasm).
const STAGING_SLOTS: usize = if OWNER_TABLE_SLOTS > 1 { 1 } else { 0 };

/// The staging slot, sized from the plan ([`size`]).
static mut STAGING: crate::kernel::mem::table::Table<Staging, STAGING_SLOTS> = {
    #[cfg(any(feature = "host-linux", feature = "aarch64-metal", feature = "rp"))]
    {
        crate::kernel::mem::table::Table::new_planned(
            |_| Staging::EMPTY,
            || staging_for(splice::add_capacity()),
        )
    }
    #[cfg(not(any(feature = "host-linux", feature = "aarch64-metal", feature = "rp")))]
    {
        crate::kernel::mem::table::Table::from_array([const { Staging::EMPTY }; STAGING_SLOTS])
    }
};

/// The pending `CREATE`'s copy of its subgraph, sized with the staging slot.
static mut PENDING_BLOB: crate::kernel::mem::table::Table<u8, { STAGING_SLOTS * BLOB_BYTES }> = {
    #[cfg(any(feature = "host-linux", feature = "aarch64-metal", feature = "rp"))]
    {
        crate::kernel::mem::table::Table::new_planned(
            |_| 0,
            || staging_for(splice::add_capacity()) * BLOB_BYTES,
        )
    }
    #[cfg(not(any(feature = "host-linux", feature = "aarch64-metal", feature = "rp")))]
    {
        crate::kernel::mem::table::Table::from_array([0; STAGING_SLOTS * BLOB_BYTES])
    }
};

/// The staging slot, if the node holds one. Scheduler thread.
fn staging() -> Option<&'static mut Staging> {
    // SAFETY: scheduler-thread state; callers hold no other borrow of it.
    let t = unsafe { &mut *core::ptr::addr_of_mut!(STAGING) };
    t.get_mut(0)
}

/// The pending `CREATE`'s blob buffer, if the node holds one. Scheduler
/// thread.
fn pending_blob() -> Option<&'static mut [u8]> {
    // SAFETY: scheduler-thread state; callers hold no other borrow of it.
    let t = unsafe { &mut *core::ptr::addr_of_mut!(PENDING_BLOB) };
    (t.len() >= BLOB_BYTES).then(|| &mut t[..BLOB_BYTES])
}

/// Modules a `CREATE` instantiates per call. A subgraph with more answers
/// `EINPROGRESS` between batches, so no call holds the scheduler for longer
/// than a few module loads.
pub const CREATE_MODULES_PER_CALL: usize = 4;

/// Forget the pending `CREATE` without rolling it back: a rebuild has
/// already dropped every workload, the half-added one with them, and freed
/// the code pool its pack lived in.
pub fn reset_pending() {
    if let Some(st) = staging() {
        st.pending = None;
    }
}

/// Roll the pending `CREATE` back: its add, and the pack it brought.
unsafe fn abandon_pending() {
    if let Some(p) = staging().and_then(|st| st.pending.take()) {
        splice::abandon(p.staged);
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
    staging().and_then(|st| st.pending.as_ref().map(|p| p.identity))
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

// Composed-graph header fields (`fluxor_contracts::graph`, little-endian).
const GRAPH_OWNER_UID_OFF: usize = 12;
const GRAPH_STATE_CAP_OFF: usize = 28;
const GRAPH_BUFFER_CAP_OFF: usize = 32;

/// Clamp a blob cap field to the envelope memory ceiling, in place. `mem_ceil`
/// is `None` for an unlimited envelope; a blob cap of 0 is also "unlimited", so
/// the ceiling wins; otherwise the tighter of the two holds (caps, never a
/// new meter).
#[inline]
fn clamp_cap(buf: &mut [u8], off: usize, mem_ceil: Option<u32>) {
    let existing = rd_u32(buf, off);
    let clamped = match mem_ceil {
        None => existing,
        Some(m) if existing == 0 => m,
        Some(m) => existing.min(m),
    };
    buf[off..off + 4].copy_from_slice(&clamped.to_le_bytes());
}

/// Admit a new `CREATE` and stage its subgraph as the pending one: stage and
/// admit its pack, refuse a module holding a node privilege, copy the
/// subgraph into the backend's own memory (carrying the header's identity
/// and the memory ceiling there, never into the caller's spec), and reserve
/// its owner with the storage the header admits. 0, or a negative errno with
/// nothing left staged.
///
/// Each step is its own frame, so the splice's admission runs under this
/// one's few locals alone.
///
/// # Safety
/// Scheduler thread; `buf` is the caller's whole spec.
unsafe fn begin_create(buf: &[u8], req: &CreateSpec<'_>) -> i32 {
    let staged = match stage_pack(buf, req) {
        Ok(s) => s,
        Err(e) => return e,
    };
    if let Some(s) = staged {
        code_pack::begin_staging(s);
    }
    let blob = match own_subgraph(buf, req) {
        Ok(b) => b,
        Err(e) => {
            code_pack::end_staging();
            if let Some(s) = staged {
                code_pack::release(s);
            }
            return e;
        }
    };

    // ── Stage the subgraph: decode it, reserve the owner, assign slots and
    //    open its channels. A workload's traffic reaches the node's network
    //    over its own lanes (`Endpoint::Lane`).
    live::set_caller(Some(scheduler::current_module_index()));
    let begun = splice::begin_encoded(blob);
    live::set_caller(None);
    code_pack::end_staging();
    match begun {
        Ok(st) => seat_pending(buf, req, staged, st),
        Err(e) => {
            if let Some(s) = staged {
                code_pack::release(s);
            }
            e
        }
    }
}

/// A pack: the workload's own modules, staged as its code. Each must be the
/// module asked for — its bytes match a pin — or one the node's signing
/// root signed; then the region is made executable, and the subgraph's
/// names resolve in it first while the add instantiates.
///
/// # Safety
/// Scheduler thread.
#[inline(never)]
unsafe fn stage_pack(buf: &[u8], req: &CreateSpec<'_>) -> Result<Option<code_pack::Staged>, i32> {
    let Some((bytes, pins)) = req.pack else {
        return Ok(None);
    };
    let staged = code_pack::stage(bytes)?;
    let pin_bytes = &buf[req.src_start + wl::pack_ref::SIZE
        ..req.src_start + wl::pack_ref::SIZE + pins * wl::pack_ref::PIN_SIZE];
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
        // ENOEXEC, not EACCES: the staged bytes are not the module they
        // claim to be — nothing is being denied, the payload is wrong. A
        // caller told this can fetch the code again, which is the only
        // refusal here that fetching can mend.
        return Err(errno::ENOEXEC);
    }
    if !code_pack::seal(staged) {
        code_pack::release(staged);
        return Err(errno::EFAULT);
    }
    Ok(Some(staged))
}

/// The backend's own copy of the subgraph: its modules' grants checked,
/// carrying the header's identity (what the splice allocates the owner by)
/// and the memory ceiling clamped onto the subgraph's caps.
///
/// # Safety
/// Scheduler thread; the pack the subgraph names is staged.
#[inline(never)]
unsafe fn own_subgraph(buf: &[u8], req: &CreateSpec<'_>) -> Result<&'static mut [u8], i32> {
    let src_graph = &buf[req.graph_off..req.graph_off + req.graph_len];
    // A workload runs on the node for its owner and is not part of it: none of its
    // modules may hold a grant that reaches past the gateway, the ones that
    // act on the node itself (registers, DMA, PCIe, reconfiguration, other
    // workloads, the host). Checked before any owner is allocated, against
    // the modules the node would instantiate.
    let grants = splice::module_grants(src_graph).ok_or(errno::EINVAL)?;
    if grants[0] & crate::abi::registry::CONTRACT_REACH_KERNEL != 0
        || grants[1] & crate::abi::registry::grant::REACH_KERNEL != 0
    {
        // EACCES is this refusal's alone: of everything that can refuse a
        // create, this is the only one that is a permission. It is also the
        // only one nothing can mend — the pack would have to be built with
        // different grants — so a caller told EACCES should stop, where
        // ENOEXEC invites fetching the code again and EBUSY invites
        // waiting. They shared this code once, and a caller that could not
        // tell them apart re-fetched a correct image for as long as it was
        // retried.
        return Err(errno::EACCES);
    }
    // Every contract a module's claims require as configured is served to
    // the new owner: by a module of its own subgraph, a workload layer of
    // the node's or a platform provider that serves workloads. Refused here
    // rather than answered at the first call; an optional claim, and a
    // conditional one its params do not exercise, require nothing.
    let provided = splice::module_provides(src_graph).ok_or(errno::EINVAL)?;
    let required = splice::module_required_claims(src_graph).ok_or(errno::EINVAL)?;
    for c in 0..64u16 {
        if required & (1u64 << c) != 0
            && provided & (1u64 << c) == 0
            && !crate::kernel::module::provider::served_to_workload(c)
        {
            log::warn!(
                "[workload] create refused: a module claims contract 0x{c:02x}, which no \
                 provider serves to a workload here and the workload does not compose"
            );
            return Err(errno::ENOSYS);
        }
    }
    let pending = pending_blob().ok_or(errno::ENOSPC)?;
    let blob = pending.get_mut(..src_graph.len()).ok_or(errno::E2BIG)?;
    blob.copy_from_slice(src_graph);
    blob[GRAPH_OWNER_UID_OFF..GRAPH_OWNER_UID_OFF + 16].copy_from_slice(&req.identity);
    let mem_ceil = if req.memory_bytes == 0 {
        None
    } else {
        Some(req.memory_bytes.min(u32::MAX as u64) as u32)
    };
    clamp_cap(blob, GRAPH_STATE_CAP_OFF, mem_ceil);
    clamp_cap(blob, GRAPH_BUFFER_CAP_OFF, mem_ceil);
    Ok(blob)
}

/// The owner's storage line as the header names it: installed and capped
/// at `storage_bytes`, or none.
///
/// # Safety
/// Scheduler thread.
#[inline(never)]
unsafe fn install_storage_line(owner: OwnerHandle, req: &CreateSpec<'_>) -> Result<(), i32> {
    use crate::abi::contracts::resource::OWNER_LINE_STORAGE;
    let owners = scheduler::owners_mut();
    let ok = if req.storage_line {
        owners.set_line(owner, OWNER_LINE_STORAGE, req.storage_bytes)
    } else {
        owners.remove_line(owner, OWNER_LINE_STORAGE)
    };
    if ok {
        Ok(())
    } else {
        Err(errno::ESRCH)
    }
}

/// The staged add as the pending CREATE: its storage line installed before
/// any of its modules runs, and the creator's own lanes (`Caller` edges)
/// noted, each landing at the add's first edge plus its position. 0, or the
/// negative errno with the add abandoned.
///
/// # Safety
/// Scheduler thread.
#[inline(never)]
unsafe fn seat_pending(
    buf: &[u8],
    req: &CreateSpec<'_>,
    staged: Option<code_pack::Staged>,
    staged_add: splice::StagedAdd,
) -> i32 {
    let abandon = |staged_add: splice::StagedAdd, e: i32| {
        splice::abandon(staged_add);
        if let Some(s) = staged {
            code_pack::release(s);
        }
        e
    };
    if let Err(e) = install_storage_line(staged_add.handle(), req) {
        return abandon(staged_add, e);
    }
    // The endpoints its options grant, checked whole by `parse_create`.
    let opts = wl::CreateHeader::parse(buf).map_or(0..0, |(_, _, o)| o);
    let endpoints = wl::opt::iter(&buf[opts])
        .filter_map(Result::ok)
        .filter(is_endpoint)
        .flat_map(|o| crate::kernel::workload::endpoints::listed(o.val));
    if let Err(e) = crate::kernel::workload::endpoints::admit(staged_add.handle(), endpoints) {
        return abandon(staged_add, e);
    }
    let src_graph = &buf[req.graph_off..req.graph_off + req.graph_len];
    let mut caller_edges = [splice::CallerEdge::default(); wl::MAX_CALLER_LANES * 2];
    let Some(caller_edge_count) = splice::caller_edges(src_graph, &mut caller_edges) else {
        return abandon(staged_add, errno::EINVAL);
    };
    log::info!(
        "[workload] graph workload {}.{}: storage_bytes={}",
        staged_add.handle().slot,
        staged_add.handle().generation,
        req.storage_bytes
    );
    let Some(st) = staging() else {
        return abandon(staged_add, errno::ENOSPC);
    };
    st.pending = Some(PendingCreate {
        identity: req.identity,
        spec: req.spec,
        staged: staged_add,
        pack: staged,
        caller_edges,
        caller_edge_count,
    });
    0
}

/// A CREATE's spec: its sections located and its header checked against
/// what this backend realizes.
#[derive(Clone, Copy)]
struct CreateSpec<'a> {
    graph_off: usize,
    graph_len: usize,
    pack: Option<(&'a [u8], usize)>,
    src_start: usize,
    memory_bytes: u64,
    storage_bytes: u64,
    /// The header's `storage` byte: whether the owner holds a storage line.
    storage_line: bool,
    identity: [u8; 16],
    spec: [u8; 32],
}

/// WORKLOAD_CREATE: stage a fmod-graph workload as a new owner subgraph from
/// the spec in `buf` and, for a pack source, the module table in `pack`.
/// Returns the workload slot's index, or a negative errno.
///
/// Three phases, each its own frame so none is on the stack under another's
/// deepest call: the spec read, the add begun, the add advanced and
/// published.
///
/// # Safety
/// Scheduler thread.
unsafe fn workload_create(buf: &[u8], pack_bytes: &[u8]) -> i32 {
    let req = match parse_create(buf, pack_bytes) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let rc = open_create(buf, &req);
    if rc != 0 {
        return rc;
    }
    advance_create()
}

/// The CREATE's spec read and checked, before anything is staged.
///
/// # Safety
/// Scheduler thread.
#[inline(never)]
unsafe fn parse_create<'a>(buf: &'a [u8], pack_bytes: &'a [u8]) -> Result<CreateSpec<'a>, i32> {
    let (h, src, opts) = wl::CreateHeader::parse(buf).ok_or(errno::EINVAL)?;
    let storage_line = match h.storage {
        wl::STORAGE_OWN_ROOT => true,
        wl::STORAGE_NONE => false,
        _ => return Err(errno::EINVAL),
    };

    // ── Header validation (cheap, before any owner is allocated). Honest,
    //    fail-closed: this backend realizes only what CAPS advertises.
    // Backend selection is by source kind: only the fmod-graph source resolves
    // to the metal backend (a host-process source → the Linux host-process backend).
    if h.source_kind != wl::SOURCE_FMOD_GRAPH && h.source_kind != wl::SOURCE_FMOD_PACK {
        return Err(errno::ENOSYS);
    }
    // The posture is a floor: a node realizes the one posture its CAPS
    // names, and a request at or below it is realized there. HARDENED is
    // realized nowhere; a node with no protection backend runs no workload.
    match realized_posture() {
        Some(p) if h.posture <= p => {}
        _ => return Err(errno::ENOSYS),
    }

    // Where the composed graph lies in the source section: all of it for a
    // graph; past the pack reference and its pins for a pack.
    let src_start = src.start;
    let source_ref_len = src.len();
    let (graph_off, graph_len, pack) = if h.source_kind == wl::SOURCE_FMOD_PACK {
        use wl::pack_ref;
        if source_ref_len < pack_ref::SIZE {
            return Err(errno::EINVAL);
        }
        let r = &buf[src_start..src_start + pack_ref::SIZE];
        let pins = rd_u16(r, pack_ref::PIN_COUNT) as usize;
        let head = pack_ref::SIZE + pins * pack_ref::PIN_SIZE;
        if pack_bytes.is_empty() || source_ref_len < head {
            return Err(errno::EINVAL);
        }
        (
            src_start + head,
            source_ref_len - head,
            Some((pack_bytes, pins)),
        )
    } else {
        (src_start, source_ref_len, None)
    };
    if graph_len < fluxor_contracts::graph::HEADER_LEN {
        return Err(errno::EINVAL); // not a composed graph
    }
    // The options: the endpoints the creator grants the owner, required or
    // not (a grant is never dropped); any other entry this backend does not
    // realize, so a required one is refused before anything is staged and an
    // advisory one is ignored.
    // They are admitted with the owner (`seat_pending`).
    for o in wl::opt::iter(&buf[opts.clone()]) {
        let o = o.map_err(|()| errno::EINVAL)?;
        if is_endpoint(&o) {
            // Granting the node's endpoints is the node's to do.
            if scheduler::caller_authority() != OWNER_NODE {
                return Err(errno::EACCES);
            }
            if o.val.len() != wl::endpoint::LEN {
                return Err(errno::EINVAL);
            }
        } else if o.required() {
            return Err(errno::ENOSYS);
        }
    }

    // ── Who the workload is, and what it may hold.
    //
    // The identity is what the owner is allocated by, and what an owner's
    // resources key on (storage scoped by `mount`, a volume's grant). The
    // null identity names no one — every workload created with it would be
    // the same owner to anything keyed on it — so it is refused.
    if h.identity.iter().all(|&b| b == 0) {
        return Err(errno::EINVAL);
    }
    let spec = spec_digest(buf);

    Ok(CreateSpec {
        graph_off,
        graph_len,
        pack,
        src_start,
        memory_bytes: h.memory_bytes,
        storage_bytes: h.storage_bytes,
        storage_line,
        identity: h.identity,
        spec,
    })
}

/// Whether `o` is a `net`/`endpoint` option.
fn is_endpoint(o: &wl::opt::Entry<'_>) -> bool {
    o.ns == wl::endpoint::NS && o.key == wl::endpoint::KEY
}

/// Begin the CREATE's add, or check a continuation names the one being
/// staged. 0, or the negative errno.
///
/// # Safety
/// Scheduler thread.
#[inline(never)]
unsafe fn open_create(buf: &[u8], req: &CreateSpec<'_>) -> i32 {
    let CreateSpec { identity, spec, .. } = *req;
    // A node whose plan seats no workload owner stages no CREATE.
    if staging().is_none() {
        return errno::ENOSPC;
    }
    // A CREATE being staged is continued by its own identity with the same
    // spec; anything else waits until it is published or abandoned.
    if let Some(id) = pending_identity() {
        let same = id == identity
            && staging()
                .and_then(|st| st.pending.as_ref())
                .is_some_and(|p| p.spec == spec);
        if !same {
            return errno::EBUSY;
        }
    } else {
        // One identity is one workload.
        if scheduler::owners().find_by_uid(identity).is_some() {
            return errno::EEXIST;
        }
        let rc = begin_create(buf, req);
        if rc != 0 {
            return rc;
        }
    }

    0
}

/// One batch of the pending add; once its last module is in, the add
/// published ([`publish_create`]).
///
/// # Safety
/// Scheduler thread.
#[inline(never)]
unsafe fn advance_create() -> i32 {
    // ── One batch of the pending add; the rest of CREATE once its last
    //    module is in.
    let Some(p) = staging().and_then(|st| st.pending.as_mut()) else {
        return errno::EINVAL;
    };
    if let Some(s) = p.pack {
        code_pack::begin_staging(s);
    }
    let batch = splice::instantiate_batch(&mut p.staged, CREATE_MODULES_PER_CALL);
    code_pack::end_staging();
    match batch {
        Ok(false) => return errno::EINPROGRESS,
        Ok(true) => {}
        Err(e) => {
            // The add rolled itself back; its pack goes with it.
            if let Some(p) = staging().and_then(|st| st.pending.take()) {
                if let Some(s) = p.pack {
                    code_pack::release(s);
                }
            }
            return e.code();
        }
    }
    publish_create()
}

/// The pending add, every module in, published: the owner activated, paused
/// for START and its workload slot allocated. The slot's index, or the
/// negative errno with the owner rolled back.
///
/// # Safety
/// Scheduler thread.
#[inline(never)]
unsafe fn publish_create() -> i32 {
    let Some(p) = staging().and_then(|st| st.pending.take()) else {
        return errno::EINVAL;
    };
    let edge_base = p.staged.edge_base();
    let caller_edges = p.caller_edges;
    let caller_edge_count = p.caller_edge_count;
    let owner = match splice::finish(p.staged) {
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

    // ── START barrier: stage paused. the splice set the owner Active;
    //    pause it now so it does not run until START resumes it.
    if live::owner_pause(owner).is_err() {
        let _ = live::free_owner(owner);
        return errno::EINVAL;
    }

    // ── Allocate the workload slot.
    let slots = &mut *core::ptr::addr_of_mut!(FMOD_WORKLOADS);
    let widx = match slots.iter().position(|s| !s.in_use) {
        Some(i) => i,
        None => {
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
        lanes,
        lane_count: lane_count as u8,
    };
    widx as i32
}

/// Resolve a stripped workload slot index to its owner, or `None` if the slot
/// is out of range or free.
unsafe fn slot_owner(raw: i32) -> Option<OwnerHandle> {
    let idx = raw as usize;
    let slots = &*core::ptr::addr_of!(FMOD_WORKLOADS);
    match slots.get(idx) {
        Some(s) if s.in_use => Some(s.owner),
        _ => None,
    }
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
fn workload_wait(owner: Option<OwnerHandle>, out: &mut [u8]) -> i32 {
    if out.len() < 5 {
        return errno::EINVAL;
    }
    let rec = owner.and_then(scheduler::owner_live_status);
    let (state, code) = wait_state_map(rec.as_ref());
    out[0] = state;
    out[1..5].copy_from_slice(&code.to_le_bytes());
    5
}

/// The one posture this node realizes for a graph workload: a metal node
/// with a protection backend runs every module a workload brings
/// unprivileged (`POSTURE_ISOLATED`, the admission in `splice`), the Linux
/// runtime in its own process (`POSTURE_SHARED`), a node with no backend
/// none.
fn realized_posture() -> Option<u8> {
    crate::kernel::exec::scheduler::splice::node_workload_gate().posture()
}

/// `CAPS`: the metal backend's honest capability word.
fn workload_caps() -> u32 {
    // Postures: the one realized (a request below it is realized there).
    let postures = realized_posture().map_or(0, wl::caps::posture);
    // Source kinds: an fmod graph, and a graph bringing its own modules where
    // the node has code space for packs. Never a host bundle: metal has no
    // rootfs to unpack one into.
    let sources = wl::caps::SOURCE_FMOD_GRAPH
        | if code_pack::POOL_SIZE != 0 {
            wl::caps::SOURCE_FMOD_PACK
        } else {
            0
        };
    // Ops: PAUSE and LOOKUP. The SIGNAL bit asserts real process-group
    // signal delivery this backend does not provide (TERM→drain, KILL→free).
    let ops = wl::caps::PAUSE | wl::caps::LOOKUP;
    postures | sources | ops
}

/// `OPTIONS`: the options entries the graph backend realizes: the endpoints
/// a creator grants the owner (`net`/`endpoint`). A graph workload's
/// environment is bound into its params by its creator, and the rest of its
/// network is the node's net provider's.
fn workload_options(out: &mut [u8]) -> i32 {
    match write_option_directory(out, &[(wl::endpoint::NS, &[wl::endpoint::KEY])]) {
        0 => errno::ERANGE,
        n => n as i32,
    }
}

/// Write an `OPTIONS` namespace directory `[ns_count:u16] then ns_count ×
/// ([ns_len:u8][ns][key_count:u16] then key_count × ([key_len:u8][key]))`
/// into `out`; its length, or 0 when `out` is too short for it.
pub fn write_option_directory(out: &mut [u8], dir: &[(&[u8], &[&[u8]])]) -> usize {
    let need = 2 + dir
        .iter()
        .map(|(ns, keys)| 1 + ns.len() + 2 + keys.iter().map(|k| 1 + k.len()).sum::<usize>())
        .sum::<usize>();
    if out.len() < need {
        return 0;
    }
    out[0..2].copy_from_slice(&(dir.len() as u16).to_le_bytes());
    let mut at = 2;
    for (ns, keys) in dir {
        out[at] = ns.len() as u8;
        out[at + 1..at + 1 + ns.len()].copy_from_slice(ns);
        at += 1 + ns.len();
        out[at..at + 2].copy_from_slice(&(keys.len() as u16).to_le_bytes());
        at += 2;
        for k in *keys {
            out[at] = k.len() as u8;
            out[at + 1..at + 1 + k.len()].copy_from_slice(k);
            at += 1 + k.len();
        }
    }
    at
}

/// The metal `workload` (0x1A) provider dispatch. CREATE/CAPS/OPTIONS are the
/// `handle = -1` globals; lifecycle ops are handed the workload slot's index
/// (what a workload handle's route carries). Matches `provider::ProviderDispatch` and the Linux
/// `linux_workload_dispatch` signature.
///
/// # Safety
/// Scheduler-thread dispatch only: touches `static mut` provider state and the
/// live graph without synchronization, and must run on the primary domain
/// (core 0) — see the module header.
pub unsafe fn workload_dispatch(
    handle: i32,
    opcode: u32,
    arg: &mut [u8],
    data: UserSpan<'_>,
) -> i32 {
    let timed = matches!(opcode, wl::CREATE | wl::DESTROY);
    let t0 = if timed {
        crate::kernel::sys::hal::now_micros()
    } else {
        0
    };
    // CREATE runs under this frame alone: its admission is the deepest path
    // a live add takes.
    let rc = if opcode == wl::CREATE {
        create_op(arg, data.as_slice())
    } else {
        dispatch_op(handle, opcode, arg, data)
    };
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
    // What gated workload modules hold: isolated pages (state, heap, EL0
    // stacks), isolation slots and minted gateway handles, each back to its
    // fixed point when churn reaps cleanly.
    #[cfg(feature = "chip-bcm2712")]
    {
        let (pages, pages_cap) = crate::kernel::module::loader::isolated_pages_in_use();
        log::info!(
            "[live] iso pages={}/{} slots={} free={} gate_handles={}",
            pages,
            pages_cap,
            crate::arch::aarch64::isolation::slots_in_use(),
            crate::arch::aarch64::isolation::free_slots(),
            crate::kernel::module::gateway::minted_in_use(),
        );
    }
}

/// `CREATE`: `arg` the spec, `data` a pack source's module table. The owner
/// that began a staged CREATE holds the workload it ends in.
///
/// # Safety
/// Scheduler thread.
#[inline(never)]
unsafe fn create_op(arg: &mut [u8], data: &[u8]) -> i32 {
    let pending_holder = &mut *core::ptr::addr_of_mut!(PENDING_HOLDER);
    let pending = pending_identity();
    if pending.is_none() {
        *pending_holder = None;
    }
    if let Some(h) = *pending_holder {
        if !may_act_as(h) {
            // Another owner's staged CREATE: continuing it is refused;
            // any other spec waits for it, as the holder's own would.
            let names_it = arg
                .get(..16)
                .is_some_and(|a| pending.is_some_and(|id| a == id));
            return if names_it {
                errno::EACCES
            } else {
                errno::EBUSY
            };
        }
    }
    // The owner that began a staged CREATE holds the workload it ends
    // in, whoever sends the call that finishes it.
    let holder = pending_holder.unwrap_or_else(scheduler::caller_owner);
    // `arg` = the spec; `data` = a pack source's module table.
    let rc = workload_create(arg, data);
    if rc == errno::EINPROGRESS {
        *pending_holder = Some(holder);
    } else {
        *pending_holder = None;
    }
    if rc >= 0 {
        let holders = &mut *core::ptr::addr_of_mut!(FMOD_HOLDERS);
        if let Some(h) = holders.get_mut(rc as usize) {
            *h = holder;
        }
    }
    rc
}

unsafe fn dispatch_op(handle: i32, opcode: u32, arg: &mut [u8], mut data: UserSpan<'_>) -> i32 {
    if opcode == wl::CAPS {
        return crate::abi::kernel_abi::caps_word::answer(arg, workload_caps());
    }
    if opcode == wl::OPTIONS {
        return workload_options(data.as_mut());
    }
    if opcode == wl::OWNERS {
        // Every owner's facts: the node's to read, as it alone composes them.
        if !scheduler::caller_authority().is_node() {
            return errno::EACCES;
        }
        return crate::kernel::workload::owner_plan::owners_answer(data.as_mut());
    }
    if opcode == wl::LOOKUP {
        if arg.len() < 16 {
            return errno::EINVAL;
        }
        let out = arg;
        let mut identity = [0u8; 16];
        identity.copy_from_slice(&out[..16]);
        if pending_identity() == Some(identity) {
            let pending_holder = *core::ptr::addr_of!(PENDING_HOLDER);
            return if pending_holder.is_none_or(may_act_as) {
                errno::EINPROGRESS
            } else {
                errno::EACCES
            };
        }
        let Some(widx) = slot_by_identity(&identity) else {
            return errno::ENOENT;
        };
        if !may_act_on(widx) {
            return errno::EACCES;
        }
        let owner = (&*core::ptr::addr_of!(FMOD_WORKLOADS))[widx].owner;
        out[0..2].copy_from_slice(&owner.slot.to_le_bytes());
        out[2..6].copy_from_slice(&owner.generation.to_le_bytes());
        return widx as i32;
    }
    if opcode == wl::DESTROY && handle < 0 {
        if arg.len() < 16 {
            return errno::EINVAL;
        }
        let mut identity = [0u8; 16];
        identity.copy_from_slice(&arg[..16]);
        if pending_identity() == Some(identity) {
            let pending_holder = &mut *core::ptr::addr_of_mut!(PENDING_HOLDER);
            if !pending_holder.is_none_or(may_act_as) {
                return errno::EACCES;
            }
            // Abandon the staged CREATE: its add rolls back and its pack goes.
            abandon_pending();
            *pending_holder = None;
            return 0;
        }
        return match slot_by_identity(&identity) {
            Some(widx) if !may_act_on(widx) => errno::EACCES,
            Some(widx) => destroy_slot(widx),
            None => errno::ENOENT,
        };
    }

    let raw = handle;
    let owner_opt = slot_owner(raw);
    if raw >= 0 && !may_act_on(raw as usize) {
        return errno::EACCES;
    }
    // WAIT tolerates a reaped slot → EXITED: a status loop keeps polling
    // after DESTROY/KILL and must see the terminal state, not an error.
    if opcode == wl::WAIT {
        return workload_wait(owner_opt, arg);
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
            if arg.len() < 4 {
                return errno::EINVAL;
            }
            let signo = rd_u32(arg, 0);
            match signo {
                // Graceful: move the owner to Draining (its graphs run dry).
                wl::SIG_TERM => {
                    scheduler::owners_mut().begin_drain(owner);
                    0
                }
                // Immediate: tear the owner down. The slot is left in place so a
                // subsequent WAIT resolves the handle and reports EXITED; DESTROY
                // reaps the slot.
                wl::SIG_KILL => {
                    let slots = &mut *core::ptr::addr_of_mut!(FMOD_WORKLOADS);
                    // The lanes' channels close with the owner; their handles
                    // go with them.
                    slots[raw as usize].lanes = [NO_LANE; wl::MAX_CALLER_LANES];
                    slots[raw as usize].lane_count = 0;
                    let _ = live::free_owner(owner);
                    0
                }
                _ => errno::ENOSYS, // portable subset only
            }
        }
        // `arg = [key u8][dir u8]`: the channel of one of the caller's lanes.
        wl::LANE => {
            // An owner that has gone (drained out, torn down elsewhere) took
            // its channels with it.
            if scheduler::owners_mut().lookup(owner).is_none() {
                return errno::EINVAL;
            }
            let (Some(&key), Some(&dir)) = (arg.first(), arg.get(1)) else {
                return errno::EINVAL;
            };
            let slot = &(&*core::ptr::addr_of!(FMOD_WORKLOADS))[raw as usize];
            let Some(l) = slot
                .lanes
                .iter()
                .take(slot.lane_count as usize)
                .find(|l| l.key == key)
            else {
                return errno::ENOENT;
            };
            let ch = match dir {
                wl::lane::TO_CALLER => l.to_caller,
                wl::lane::FROM_CALLER => l.from_caller,
                _ => return errno::EINVAL,
            };
            if ch < 0 {
                errno::ENOENT
            } else {
                ch
            }
        }
        wl::DESTROY => destroy_slot(raw as usize),
        _ => errno::ENOSYS,
    }
}

/// Tear workload slot `widx` down: free the owner, then the slot and every
/// handle naming it. A slot's index is the handle index the platform's provider answers
/// for it on every platform.
unsafe fn destroy_slot(widx: usize) -> i32 {
    let slots = &mut *core::ptr::addr_of_mut!(FMOD_WORKLOADS);
    let _ = live::free_owner(slots[widx].owner); // idempotent — stale handle is fine
    slots[widx] = WL_EMPTY;
    crate::kernel::module::provider::retire_routes_naming(
        crate::abi::registry::workload::ID,
        widx as i32,
    );
    0
}

/// The live workload slot whose owner carries `identity`.
unsafe fn slot_by_identity(identity: &[u8; 16]) -> Option<usize> {
    let slots = &*core::ptr::addr_of!(FMOD_WORKLOADS);
    let owners = scheduler::owners();
    (0..slots.len()).find(|&i| {
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
