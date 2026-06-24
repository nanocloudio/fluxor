//! WS-D-min: minimal live graph mutation — add and tear down a self-contained
//! subgraph owner on a *running* graph, without a destructive rebuild.
//!
//! This is the keystone primitive behind OTA, k8s-style pods, and REPL
//! subgraph-exec (the same mechanism under different lifecycle policies); the
//! cheapest caller — an ephemeral REPL subgraph — is built first to force
//! exactly the core. It narrows `k8s_plan.md` WS-D.1/D.2 to **add + teardown**
//! and pulls in the slice of WS-C (per-owner reclaim) teardown needs. See the
//! design note `.context/ws_d_min.md` for the full rationale.
//!
//! Two operations, both synchronous and owner-scoped:
//!   * [`apply_add`]  — allocate an owner, instantiate its modules, open its
//!     edges, and *append* it to the execution order. No existing owner is
//!     paused, reset, or re-ordered; the phase stays `Running` throughout.
//!   * [`free_owner`] — stop the owner's modules (one-shot drain then
//!     terminate), close its edges, reclaim its state, and revoke the handle
//!     (the generation guard in [`crate::kernel::owner`] rejects it thereafter).
//!
//! Splice, not re-topo: `exec_order` is a flat `[u8; MAX_MODULES]` consumed via
//! `exec_order_count`, so a new owner's (internally topo-sorted) modules are
//! appended at the tail and the freed owner's entries are compacted out — the
//! whole-graph topological sort is never re-run, so existing modules keep their
//! slot, state, and schedule position. A NEW producer → EXISTING consumer edge
//! costs one tick of (buffered, lossless) latency; existing modules are never
//! gated on a new owner (their `upstream_mask` is never touched), so a buggy
//! ephemeral owner can't stall the system.
//!
//! Linux-first. The bcm2712/rp `domain_exec_order` splice + multicore quiesce,
//! async PIC load, owner-tagged allocator (WS-C), and partial replacement
//! (WS-D.4) are documented follow-ups, not built here. Gated on `multitenant`
//! (host-linux + bcm2712 enable it; bare-metal rp compiles it out at zero cost).

use super::{
    BuiltInModule, Edge, InstantiateResult, ModulePorts, ModuleSlot, SchedulerState, MAX_CHANNELS,
    MAX_MODULES, SCHED,
};
use crate::kernel::config::ModuleEntry;
use crate::kernel::owner::{OwnerHandle, OwnerState, OWNER_SYSTEM};

/// Largest subgraph one `apply_add` admits. Bounded, stack-only working set.
pub const MAX_ADD_MODULES: usize = 16;
/// Largest edge count one `apply_add` admits.
pub const MAX_ADD_EDGES: usize = 32;

/// How a new module is instantiated.
pub enum ModuleSource {
    /// A PIC `.fmod` resolved by `name_hash`, instantiated via the loader.
    /// Must complete synchronously (`InstantiateResult::Done`); an async
    /// (`Pending`) load yields [`AddError::WouldBlock`] — the async path is a
    /// follow-up, not part of the keystone core.
    Pic(ModuleEntry),
    /// A statically-linked built-in (host shims, REPL/test emitters). The
    /// module resolves its channels from its port table (populated before
    /// instantiation) — see the proof test.
    Builtin(BuiltInModule),
}

/// One new module in the added subgraph. Consumed by [`apply_add`] (the source
/// is moved out), so the caller's slice is left holding placeholders.
pub struct AddModule {
    pub source: ModuleSource,
    pub domain_id: u8,
}

/// An endpoint of an [`AddEdge`]: a new module (subgraph-local index) or a
/// module already live in the running graph (global slot index).
#[derive(Clone, Copy)]
pub enum Endpoint {
    New(u8),
    Existing(u16),
}

/// One edge of the added subgraph. `from`/`to` are subgraph-local for new
/// modules and global for existing ones.
#[derive(Clone, Copy)]
pub struct AddEdge {
    pub from: Endpoint,
    pub from_port_index: u8,
    pub to: Endpoint,
    pub to_port_index: u8,
    /// Per-edge ring-buffer byte hint (0 = derive from module hints).
    pub buffer_bytes: u32,
}

/// A new owner's subgraph. `modules` is `&mut` because the sources are moved
/// out during instantiation; the caller's array is consumed.
pub struct AddSubgraph<'a> {
    pub pod_uid: [u8; 16],
    pub modules: &'a mut [AddModule],
    pub edges: &'a [AddEdge],
    /// Admitted hard caps from the resource profile; 0 = unlimited (the
    /// REPL/ephemeral default). Stored on the owner; fine-grained byte
    /// enforcement is deferred to the owner-tagged allocator (WS-C).
    pub state_cap: u32,
    pub buffer_cap: u32,
}

/// Why `apply_add` failed. A failure leaves the running graph bit-identical.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddError {
    TooManyModules,
    TooManyEdges,
    OwnerSlotsExhausted,
    PlanMismatch,
    NoFreeSlot,
    BadEndpoint,
    ChannelOpenFailed,
    Instantiate,
    /// PIC instantiation returned `Pending` (async load) — out of scope here.
    WouldBlock,
}

impl AddError {
    /// Negative errno-style code for the syscall surface.
    pub fn code(self) -> i32 {
        match self {
            AddError::TooManyModules => -1,
            AddError::TooManyEdges => -2,
            AddError::OwnerSlotsExhausted => -3,
            AddError::PlanMismatch => -4,
            AddError::NoFreeSlot => -5,
            AddError::BadEndpoint => -6,
            AddError::ChannelOpenFailed => -7,
            AddError::Instantiate => -8,
            AddError::WouldBlock => -11, // -EAGAIN
        }
    }
}

/// Why `free_owner` failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FreeError {
    /// The handle names the system owner, which cannot be freed.
    NotWorkload,
    /// The handle is unknown or its generation no longer matches (already
    /// freed / reused) — the fail-closed path.
    StaleHandle,
}

impl FreeError {
    pub fn code(self) -> i32 {
        match self {
            FreeError::NotWorkload => -1,
            FreeError::StaleHandle => -2,
        }
    }
}

/// Borrow the scheduler state. Single-threaded scheduler context; callers must
/// not hold the returned reference across a call that re-derives `SCHED`.
#[inline]
fn sched() -> &'static mut SchedulerState {
    // SAFETY: scheduler-thread-exclusive; mirrors `sched_mut()`.
    unsafe { &mut *core::ptr::addr_of_mut!(SCHED) }
}

// ============================================================================
// apply_add
// ============================================================================

/// Add `sub` as a new owner to the running graph. On success returns the new
/// [`OwnerHandle`]. `assignment`, when `Some((slot, generation))`, asserts the
/// kernel-allocated owner matches the placement a host-side composer chose
/// (determinism contract, `k8s_plan §11`); pass `None` for a standalone caller.
///
/// Atomic: the execution-order splice is the last mutation, so any earlier
/// failure rolls back to a bit-identical graph and the scheduler never observes
/// a half-built owner.
pub fn apply_add(
    sub: AddSubgraph<'_>,
    assignment: Option<(u16, u32)>,
) -> Result<OwnerHandle, AddError> {
    let n = sub.modules.len();
    let e = sub.edges.len();
    if n > MAX_ADD_MODULES {
        return Err(AddError::TooManyModules);
    }
    if e > MAX_ADD_EDGES {
        return Err(AddError::TooManyEdges);
    }

    // 1. Reserve the owner (lowest-free slot + monotonic generation — the same
    //    rule the host composer uses, so kernel-side allocation matches a plan).
    let handle = match sched().owners.alloc(sub.pod_uid) {
        Some(h) => h,
        None => return Err(AddError::OwnerSlotsExhausted),
    };
    if let Some((slot, generation)) = assignment {
        if handle.slot != slot || handle.generation != generation {
            sched().owners.free(handle);
            return Err(AddError::PlanMismatch);
        }
    }
    sched()
        .owners
        .set_caps(handle, sub.state_cap, sub.buffer_cap);

    // 2. Assign each new module the lowest-free `Empty` slot. NOT a watermark:
    //    freeing a non-last owner leaves holes, so we scan.
    let mut local_to_global = [0usize; MAX_ADD_MODULES];
    {
        let s = sched();
        let mut scan = 0usize;
        for (local, g) in local_to_global.iter_mut().take(n).enumerate() {
            let slot = loop {
                if scan >= MAX_MODULES {
                    // No free slot: undo the owner reservation and bail.
                    s.owners.free(handle);
                    let _ = local;
                    return Err(AddError::NoFreeSlot);
                }
                let candidate = scan;
                scan += 1;
                if matches!(s.modules[candidate], ModuleSlot::Empty) {
                    break candidate;
                }
            };
            *g = slot;
        }
    }

    // Resolve an endpoint to a global module index.
    let resolve = |ep: Endpoint| -> Option<usize> {
        match ep {
            Endpoint::New(l) => local_to_global.get(l as usize).copied(),
            Endpoint::Existing(g) => {
                let g = g as usize;
                if g < MAX_MODULES && !matches!(sched().modules[g], ModuleSlot::Empty) {
                    Some(g)
                } else {
                    None
                }
            }
        }
    };

    // 3. Append the new edges to `sched.edges[edge_base..]`.
    let edge_base = sched().edge_count;
    if edge_base + e > MAX_CHANNELS {
        sched().owners.free(handle);
        return Err(AddError::TooManyEdges);
    }
    for (i, ae) in sub.edges.iter().enumerate() {
        let from = match resolve(ae.from) {
            Some(g) => g,
            None => {
                sched().owners.free(handle);
                return Err(AddError::BadEndpoint);
            }
        };
        let to = match resolve(ae.to) {
            Some(g) => g,
            None => {
                sched().owners.free(handle);
                return Err(AddError::BadEndpoint);
            }
        };
        let mut edge =
            Edge::new_indexed(from, "out", ae.from_port_index, to, "in", ae.to_port_index);
        edge.buffer_bytes = ae.buffer_bytes;
        sched().edges[edge_base + i] = edge;
    }

    // 4. Open only the new edges' channels. On failure, close whatever opened
    //    and roll back (the appended edges are not yet committed to edge_count).
    if e > 0 {
        let rc = super::open_channels(&mut sched().edges[edge_base..edge_base + e]);
        if rc < 0 {
            super::close_channels(&sched().edges[edge_base..edge_base + e]);
            clear_edge_range(edge_base, e);
            sched().owners.free(handle);
            return Err(AddError::ChannelOpenFailed);
        }
    }
    sched().edge_count = edge_base + e;

    // 5. Populate the new modules' port tables from the freshly opened edges so
    //    instantiation / lazy channel lookup sees them. Existing modules' port
    //    tables are NOT touched.
    for &slot in local_to_global.iter().take(n) {
        super::populate_module_ports_from_edges(slot, slot);
    }

    // 6. Instantiate each module synchronously and stamp it with the owner.
    for (local, m) in sub.modules.iter_mut().enumerate().take(n) {
        let slot = local_to_global[local];
        let source = core::mem::replace(&mut m.source, ModuleSource::Pic(ModuleEntry::default()));
        let res = match source {
            ModuleSource::Builtin(b) => {
                super::store_builtin_module(slot, b);
                Ok(())
            }
            ModuleSource::Pic(entry) => instantiate_pic(slot, &entry),
        };
        if let Err(err) = res {
            // Roll back: free this and any earlier instantiated slots, close
            // the new channels, drop the appended edges, revoke the owner.
            rollback_add(handle, &local_to_global[..n], edge_base, e);
            return Err(err);
        }
        super::set_module_owner(slot, handle);
        let s = sched();
        s.ready[slot] = true;
        s.finished[slot] = false;
        s.domain_id[slot] = m.domain_id;
        // Ready-gate only on NEW upstream modules — never gate on existing ones,
        // and never modify an existing module's mask (isolation).
        s.upstream_mask[slot].clear_all();
    }
    // Fill new modules' upstream masks from intra-owner edges (after all slots
    // are known) for deterministic ready-gating among the added modules.
    for ae in sub.edges.iter() {
        if let (Endpoint::New(_), Endpoint::New(_)) = (ae.from, ae.to) {
            if let (Some(from), Some(to)) = (resolve(ae.from), resolve(ae.to)) {
                sched().upstream_mask[to].set(from);
            }
        }
    }

    // 7. Splice into the execution order: topo-sort the new modules over their
    //    internal edges, then append. Existing entries are untouched.
    let order = topo_order_new(&local_to_global[..n], sub.edges);
    {
        let s = sched();
        for &slot in order.iter().take(n) {
            let pos = s.exec_order_count;
            s.exec_order[pos] = slot as u8;
            s.exec_order_count = pos + 1;
        }
        s.active_module_count += n;
    }

    // 8. Activate.
    sched().owners.set_state(handle, OwnerState::Active);
    Ok(handle)
}

/// Instantiate a PIC module into `slot`. Synchronous only: an async
/// (`Pending`) load is aborted and reported as [`AddError::WouldBlock`].
fn instantiate_pic(slot: usize, entry: &ModuleEntry) -> Result<(), AddError> {
    // SAFETY: scheduler-thread graph-mutation context; mirrors the Linux boot
    // instantiation path (disjoint sub-borrows of SCHED passed in).
    let loader = unsafe { super::static_loader() };
    let s = sched();
    match super::instantiate_one_module(
        loader,
        entry,
        slot,
        slot,
        &mut s.edges,
        &mut s.modules,
        &mut s.ports,
    ) {
        InstantiateResult::Done => Ok(()),
        // Async/streaming load is a documented follow-up; abort the pending
        // handle so no half-built slot lingers.
        InstantiateResult::Pending(pending) => {
            // SAFETY: `pending` is the loader handle just returned for `slot`.
            unsafe { pending.abort() };
            Err(AddError::WouldBlock)
        }
        InstantiateResult::Error(_) => Err(AddError::Instantiate),
    }
}

/// Roll back a partially-applied add. The exec-order splice has not happened
/// yet, so only instantiated slots, opened channels, and appended edges need
/// undoing, then the owner is revoked.
fn rollback_add(handle: OwnerHandle, slots: &[usize], edge_base: usize, e: usize) {
    let s = sched();
    for &slot in slots {
        let taken = core::mem::replace(&mut s.modules[slot], ModuleSlot::Empty);
        if let ModuleSlot::Dynamic(dm) = taken {
            // SAFETY: the slot is being torn down and will not be stepped.
            unsafe { dm.free() };
        }
        s.ports[slot] = ModulePorts::empty();
        s.upstream_mask[slot].clear_all();
        s.ready[slot] = true;
        s.finished[slot] = false;
        super::set_module_owner(slot, OWNER_SYSTEM);
    }
    if e > 0 {
        super::close_channels(&s.edges[edge_base..edge_base + e]);
    }
    clear_edge_range(edge_base, e);
    // `edge_count` was only advanced after a successful open; if we reach here
    // post-open, retract it.
    if s.edge_count == edge_base + e {
        s.edge_count = edge_base;
    }
    s.owners.free(handle);
}

/// Topologically order the new modules over their subgraph-internal edges so
/// producers precede consumers within the owner. Falls back to declaration
/// order on a cycle (the running graph already rejects cycles elsewhere; an
/// added subgraph is expected acyclic).
fn topo_order_new(slots: &[usize], edges: &[AddEdge]) -> [usize; MAX_ADD_MODULES] {
    let n = slots.len();
    let mut indeg = [0u8; MAX_ADD_MODULES];
    for ae in edges {
        if let (Endpoint::New(_), Endpoint::New(t)) = (ae.from, ae.to) {
            let t = t as usize;
            if t < n {
                indeg[t] += 1;
            }
        }
    }
    let mut out = [0usize; MAX_ADD_MODULES];
    let mut visited = [false; MAX_ADD_MODULES];
    let mut w = 0usize;
    // Kahn over local indices; O(n^2) is fine for n <= MAX_ADD_MODULES.
    while w < n {
        let mut progressed = false;
        for local in 0..n {
            if !visited[local] && indeg[local] == 0 {
                visited[local] = true;
                out[w] = slots[local];
                w += 1;
                for ae in edges {
                    if let (Endpoint::New(f), Endpoint::New(t)) = (ae.from, ae.to) {
                        if f as usize == local {
                            let t = t as usize;
                            if t < n && indeg[t] > 0 {
                                indeg[t] -= 1;
                            }
                        }
                    }
                }
                progressed = true;
            }
        }
        if !progressed {
            // Cycle: append remaining in declaration order.
            for local in 0..n {
                if !visited[local] {
                    out[w] = slots[local];
                    w += 1;
                }
            }
            break;
        }
    }
    out
}

/// Reset `edges[base..base+count]` to the empty default (channel = -1).
fn clear_edge_range(base: usize, count: usize) {
    let s = sched();
    for i in base..base + count {
        s.edges[i] = Edge::simple(0, 0);
    }
}

// ============================================================================
// free_owner
// ============================================================================

/// Free `handle`: stop its modules, close its edges, reclaim its state, and
/// revoke the handle. Synchronous and idempotent against a stale handle.
///
/// One-shot drain only: `module_drain` is invoked once (a best-effort
/// stop-intake/flush) and the module is then terminated. Multi-tick graceful
/// drain is the reconfigure module's cross-tick policy, layered on top by
/// driving the owner's modules to `Done` *before* calling `free_owner`.
pub fn free_owner(handle: OwnerHandle) -> Result<(), FreeError> {
    if handle.is_system() {
        return Err(FreeError::NotWorkload);
    }
    if sched().owners.lookup(handle).is_none() {
        return Err(FreeError::StaleHandle);
    }
    sched().owners.begin_drain(handle);

    // Which module slots belong to this owner.
    let mut owned = [false; MAX_MODULES];
    let mut owned_count = 0usize;
    for (i, slot_owned) in owned.iter_mut().enumerate() {
        if matches!(sched().modules[i], ModuleSlot::Empty) {
            continue;
        }
        if super::module_owner(i) == handle {
            *slot_owned = true;
            owned_count += 1;
        }
    }

    // 1. Stop modules: one-shot drain (if exported), then mark finished so the
    //    scheduler skips them immediately.
    {
        let s = sched();
        for (i, &is_owned) in owned.iter().enumerate() {
            if !is_owned {
                continue;
            }
            if let ModuleSlot::Dynamic(ref m) = s.modules[i] {
                // SAFETY: module is live and about to be torn down; drain runs
                // on its owning (scheduler) core.
                unsafe {
                    super::set_current_module(i);
                    let _ = m.call_drain();
                }
            }
            s.finished[i] = true;
        }
    }

    // 2. Unsplice from the execution order BEFORE freeing state, so a racing
    //    step can never reach a freed slot. Stable compaction.
    {
        let s = sched();
        let mut w = 0usize;
        for r in 0..s.exec_order_count {
            let idx = s.exec_order[r] as usize;
            if idx < MAX_MODULES && owned[idx] {
                continue;
            }
            s.exec_order[w] = s.exec_order[r];
            w += 1;
        }
        s.exec_order_count = w;
    }

    // 3. Close the owner's edges and compact the edges array. Nothing
    //    references edges by array index, and channel handles are unchanged by
    //    the shift, so surviving owners are untouched.
    {
        let s = sched();
        let mut w = 0usize;
        for r in 0..s.edge_count {
            let edge = s.edges[r];
            let from_owned = edge.from_module < MAX_MODULES && owned[edge.from_module];
            let to_owned = edge.to_module < MAX_MODULES && owned[edge.to_module];
            if from_owned || to_owned {
                if edge.channel >= 0 {
                    crate::kernel::syscalls::channel_close(edge.channel);
                }
                continue;
            }
            if w != r {
                s.edges[w] = s.edges[r];
            }
            w += 1;
        }
        for i in w..s.edge_count {
            s.edges[i] = Edge::simple(0, 0);
        }
        s.edge_count = w;
    }

    // 4. Free state and clear each owned slot.
    {
        let s = sched();
        for (i, &is_owned) in owned.iter().enumerate() {
            if !is_owned {
                continue;
            }
            let taken = core::mem::replace(&mut s.modules[i], ModuleSlot::Empty);
            if let ModuleSlot::Dynamic(dm) = taken {
                // SAFETY: slot unspliced and finished; never stepped again.
                unsafe { dm.free() };
            }
            s.ports[i] = ModulePorts::empty();
            s.upstream_mask[i].clear_all();
            s.ready[i] = true;
            s.finished[i] = false;
            s.slot_generation[i] = s.slot_generation[i].wrapping_add(1);
            super::set_module_owner(i, OWNER_SYSTEM);
        }
        s.active_module_count = s.active_module_count.saturating_sub(owned_count);
    }

    // 5. Revoke the handle. The generation guard now rejects it.
    sched().owners.free(handle);
    Ok(())
}

// ============================================================================
// Syscall codec (APPLY_ADD / FREE_OWNER)
// ============================================================================
//
// Bounded binary `AddSubgraph` for the on-device caller (REPL / node agent).
// Big-endian, fixed-width — same discipline as the composed-plan codec in
// `tools/src/compose.rs`. PIC modules only (a built-in has no serialisable
// form); a target with asynchronous PIC load returns `WouldBlock` until the
// async follow-up. Integrity/signature verification of the blob is the signing
// layer's job (WS-H) and the channel is authenticated (k8s node-agent), so this
// decoder validates structure and bounds, not a content digest.

/// Wire magic: "FLXA".
const ADD_MAGIC: u32 = 0x464C_5841;
/// Wire version.
const ADD_VERSION: u16 = 1;

/// Minimal big-endian reading cursor over the encoded blob.
struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Self {
        Cur { b, p: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.p.checked_add(n)?;
        if end > self.b.len() {
            return None;
        }
        let s = &self.b[self.p..end];
        self.p = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
}

fn decode_endpoint(kind: u8, idx: u16) -> Option<Endpoint> {
    match kind {
        0 => Some(Endpoint::New(idx as u8)),
        1 => Some(Endpoint::Existing(idx)),
        _ => None,
    }
}

/// Decode a bounded binary `AddSubgraph` and apply it. On success writes the
/// 6-byte `OwnerHandle` (`slot:u16 LE, generation:u32 LE`) into `arg[0..6]` and
/// returns 0; otherwise a negative error (`-EINVAL` for a malformed blob, or
/// the negative [`AddError::code`]).
///
/// # Safety
/// `arg` must be a writable buffer of at least `arg_len` bytes, valid for the
/// duration of the call (module params are borrowed from it in place).
pub unsafe fn apply_add_encoded(arg: *mut u8, arg_len: usize) -> i32 {
    const EINVAL: i32 = -22;
    if arg.is_null() {
        return EINVAL;
    }
    // SAFETY: caller guarantees `arg`/`arg_len` describe a valid buffer.
    let bytes = unsafe { core::slice::from_raw_parts(arg, arg_len) };
    let mut c = Cur::new(bytes);

    if c.u32() != Some(ADD_MAGIC) || c.u16() != Some(ADD_VERSION) || c.u16().is_none() {
        return EINVAL;
    }
    let pod_uid: [u8; 16] = match c.take(16) {
        Some(s) => s.try_into().unwrap(),
        None => return EINVAL,
    };
    let (state_cap, buffer_cap) = match (c.u32(), c.u32()) {
        (Some(s), Some(b)) => (s, b),
        _ => return EINVAL,
    };
    let mc = match c.u8() {
        Some(n) if (n as usize) <= MAX_ADD_MODULES => n as usize,
        _ => return EINVAL,
    };
    let ec = match c.u8() {
        Some(n) if (n as usize) <= MAX_ADD_EDGES => n as usize,
        _ => return EINVAL,
    };

    let mut mods: [AddModule; MAX_ADD_MODULES] = core::array::from_fn(|_| AddModule {
        source: ModuleSource::Pic(ModuleEntry::default()),
        domain_id: 0,
    });
    for m in mods.iter_mut().take(mc) {
        let name_hash = match c.u32() {
            Some(v) => v,
            None => return EINVAL,
        };
        let domain_id = match c.u8() {
            Some(v) => v,
            None => return EINVAL,
        };
        let plen = match c.u16() {
            Some(v) => v as usize,
            None => return EINVAL,
        };
        let params = match c.take(plen) {
            Some(s) => s,
            None => return EINVAL,
        };
        let entry = ModuleEntry {
            name_hash,
            domain_id,
            params_ptr: if plen == 0 {
                core::ptr::null()
            } else {
                params.as_ptr()
            },
            params_len: plen,
            ..ModuleEntry::default()
        };
        m.source = ModuleSource::Pic(entry);
        m.domain_id = domain_id;
    }

    let mut edges = [AddEdge {
        from: Endpoint::New(0),
        from_port_index: 0,
        to: Endpoint::New(0),
        to_port_index: 0,
        buffer_bytes: 0,
    }; MAX_ADD_EDGES];
    for edge in edges.iter_mut().take(ec) {
        let from_kind = c.u8();
        let from_idx = c.u16();
        let from_port = c.u8();
        let to_kind = c.u8();
        let to_idx = c.u16();
        let to_port = c.u8();
        let buffer_bytes = c.u32();
        let (Some(fk), Some(fi), Some(fp), Some(tk), Some(ti), Some(tp), Some(bb)) = (
            from_kind,
            from_idx,
            from_port,
            to_kind,
            to_idx,
            to_port,
            buffer_bytes,
        ) else {
            return EINVAL;
        };
        let (Some(from), Some(to)) = (decode_endpoint(fk, fi), decode_endpoint(tk, ti)) else {
            return EINVAL;
        };
        edge.from = from;
        edge.from_port_index = fp;
        edge.to = to;
        edge.to_port_index = tp;
        edge.buffer_bytes = bb;
    }

    let sub = AddSubgraph {
        pod_uid,
        modules: &mut mods[..mc],
        edges: &edges[..ec],
        state_cap,
        buffer_cap,
    };
    match apply_add(sub, None) {
        Ok(handle) => {
            if arg_len < 6 {
                // Applied, but no room to report the handle — caller can still
                // free by pod_uid via a future op; treat as success.
                return 0;
            }
            // SAFETY: arg has >= 6 writable bytes (checked).
            unsafe {
                let slot = handle.slot.to_le_bytes();
                let gen = handle.generation.to_le_bytes();
                *arg = slot[0];
                *arg.add(1) = slot[1];
                *arg.add(2) = gen[0];
                *arg.add(3) = gen[1];
                *arg.add(4) = gen[2];
                *arg.add(5) = gen[3];
            }
            0
        }
        Err(e) => e.code(),
    }
}

/// Decode `[slot:u16 LE, generation:u32 LE]` and free that owner.
///
/// # Safety
/// `arg` must point to at least `arg_len` readable bytes.
pub unsafe fn free_owner_encoded(arg: *const u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 6 {
        return -22;
    }
    // SAFETY: caller guarantees >= 6 readable bytes.
    let bytes = unsafe { core::slice::from_raw_parts(arg, 6) };
    let slot = u16::from_le_bytes([bytes[0], bytes[1]]);
    let generation = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
    match free_owner(OwnerHandle { slot, generation }) {
        Ok(()) => 0,
        Err(e) => e.code(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::channel;
    use crate::kernel::hal::{self, HalOps};

    const SENTINEL: u32 = 0xA5A5_A5A5;

    // ── Minimal HAL fixture ──────────────────────────────────────────────
    // Channel ops and `step_modules` wrap critical sections / timers via the
    // HAL, which a unit test must install (boot is never run). Everything is a
    // no-op; `now_millis` returns 0 so the per-boot crash-check is skipped.
    fn z32() -> u32 {
        0
    }
    fn z64() -> u64 {
        0
    }
    fn zusize() -> usize {
        0
    }
    fn di() -> u32 {
        0
    }
    fn ri(_: u32) {}
    fn unit0() {}
    fn id_usize(x: usize) -> usize {
        x
    }
    fn yes_fn(_: usize) -> bool {
        true
    }
    fn yes_base(_: usize) -> bool {
        true
    }
    fn yes_code(_: usize, _: usize, _: u32) -> bool {
        true
    }
    fn yes_integrity(_: &[u8], _: &[u8]) -> bool {
        true
    }
    fn arm(_: u32) {}
    fn isr_start(_: u32) {}
    fn rel_handles(_: u8) {}
    fn merge_over(_: u16, _: *mut u8, len: usize, _: usize) -> usize {
        len
    }
    fn init_gpio_stub(_: &[Option<crate::kernel::config::GpioConfig>]) -> usize {
        0
    }
    fn csprng_stub(_: *mut u8, _: usize) -> i32 {
        0
    }
    fn irq_bind_stub(_: u32, _: i32, _: usize) -> i32 {
        0
    }

    static TEST_HAL: HalOps = HalOps {
        disable_interrupts: di,
        restore_interrupts: ri,
        wake_scheduler: unit0,
        now_millis: z64,
        now_micros: z64,
        tick_count: z32,
        flash_base: zusize,
        flash_end: zusize,
        apply_code_bit: id_usize,
        validate_fn_addr: yes_fn,
        validate_module_base: yes_base,
        validate_fn_in_code: yes_code,
        verify_integrity: yes_integrity,
        pic_barrier: unit0,
        step_guard_init: unit0,
        step_guard_arm: arm,
        step_guard_disarm: unit0,
        step_guard_post_check: unit0,
        read_cycle_count: z32,
        isr_tier_init: unit0,
        isr_tier_start: isr_start,
        isr_tier_stop: unit0,
        isr_tier_poll: unit0,
        init_providers: unit0,
        release_module_handles: rel_handles,
        boot_scan: unit0,
        merge_runtime_overrides: merge_over,
        init_gpio: init_gpio_stub,
        csprng_fill: csprng_stub,
        core_id: zusize,
        irq_bind: irq_bind_stub,
    };

    // ── Test module step fns (channel handle cached in state[0..4]) ───────
    // Layout: [0..4]=channel i32 LE, [4..8]=step counter u32, [8..12]=last
    // value read, [12]=emit-once flag.
    fn base_step(state: *mut u8) -> i32 {
        // SAFETY: BuiltInModule state is a 64-byte buffer.
        let s = unsafe { core::slice::from_raw_parts_mut(state, 64) };
        let ch = i32::from_le_bytes([s[0], s[1], s[2], s[3]]);
        let c = u32::from_le_bytes([s[4], s[5], s[6], s[7]]).wrapping_add(1);
        s[4..8].copy_from_slice(&c.to_le_bytes());
        if ch >= 0 {
            let mut buf = [0u8; 4];
            // SAFETY: valid handle, 4-byte read into a 4-byte buffer.
            let rc = unsafe { channel::channel_read(ch, buf.as_mut_ptr(), 4) };
            if rc == 4 {
                s[8..12].copy_from_slice(&buf);
            }
        }
        0
    }
    fn emit_step(state: *mut u8) -> i32 {
        // SAFETY: as above.
        let s = unsafe { core::slice::from_raw_parts_mut(state, 64) };
        let ch = i32::from_le_bytes([s[0], s[1], s[2], s[3]]);
        if s[12] == 0 && ch >= 0 {
            let v = SENTINEL.to_le_bytes();
            // SAFETY: valid handle, 4-byte write from a 4-byte buffer.
            let rc = unsafe { channel::channel_write(ch, v.as_ptr(), 4) };
            if rc == 4 {
                s[12] = 1;
            }
        }
        0
    }

    fn set_state_ch(slot: usize, ch: i32) {
        if let ModuleSlot::BuiltIn(ref mut m) = sched().modules[slot] {
            m.state[0..4].copy_from_slice(&ch.to_le_bytes());
        }
    }
    fn base_counter() -> u32 {
        if let ModuleSlot::BuiltIn(ref m) = sched().modules[0] {
            u32::from_le_bytes(m.state[4..8].try_into().unwrap())
        } else {
            0
        }
    }
    fn base_lastval() -> u32 {
        if let ModuleSlot::BuiltIn(ref m) = sched().modules[0] {
            u32::from_le_bytes(m.state[8..12].try_into().unwrap())
        } else {
            0
        }
    }
    fn emit_done() -> bool {
        if let ModuleSlot::BuiltIn(ref m) = sched().modules[1] {
            m.state[12] == 1
        } else {
            false
        }
    }
    fn step(n: usize) {
        for _ in 0..n {
            // SAFETY: scheduler-thread; mirrors the platform main loop.
            super::super::step_modules(unsafe { super::super::sched_modules() }, 4);
        }
    }

    /// The keystone proof: add a one-module owner to a running graph, observe
    /// the existing module keep stepping and the new module emit a sentinel,
    /// then free the owner and assert full reclamation + a dead handle.
    #[test]
    fn add_then_free_owner_on_live_graph() {
        hal::init(&TEST_HAL);

        // ── Build a clean one-module base graph: a counter built-in in slot 0.
        {
            let s = sched();
            for i in 0..4 {
                s.modules[i] = ModuleSlot::Empty;
                s.finished[i] = false;
                s.ready[i] = true;
                s.ports[i] = ModulePorts::empty();
                s.upstream_mask[i].clear_all();
                s.domain_id[i] = 0;
            }
            s.edge_count = 0;
            s.exec_order_count = 0;
            s.active_module_count = 0;
            s.domain_count = 0;
        }
        super::super::store_builtin_module(0, BuiltInModule::new("test_base", base_step));
        set_state_ch(0, -1); // no input yet
        {
            let s = sched();
            s.exec_order[0] = 0;
            s.exec_order_count = 1;
            s.active_module_count = 1;
        }

        // Base is running before any mutation.
        step(3);
        let count_before_add = base_counter();
        assert_eq!(count_before_add, 3, "base must step on the bare graph");
        let arena_before = crate::kernel::loader::arena_usage().0;
        let edges_before = sched().edge_count;

        // ── apply_add: a one-module emitter owner wired into the existing base.
        let mut mods = [AddModule {
            source: ModuleSource::Builtin(BuiltInModule::new("test_emit", emit_step)),
            domain_id: 0,
        }];
        let edges = [AddEdge {
            from: Endpoint::New(0),
            from_port_index: 0,
            to: Endpoint::Existing(0),
            to_port_index: 0,
            buffer_bytes: 0,
        }];
        let sub = AddSubgraph {
            pod_uid: [7u8; 16],
            modules: &mut mods,
            edges: &edges,
            state_cap: 0,
            buffer_cap: 0,
        };
        let handle = apply_add(sub, None).expect("apply_add must succeed");

        // The splice landed: counts grew by exactly one, emitter in slot 1.
        assert_eq!(sched().active_module_count, 2);
        assert_eq!(sched().exec_order_count, 2);
        assert!(matches!(sched().modules[1], ModuleSlot::BuiltIn(_)));
        assert!(sched().owners.authorize(handle), "owner must be Active");
        // Existing base was untouched by the splice: same slot, same counter.
        assert_eq!(
            base_counter(),
            count_before_add,
            "apply_add must not step base"
        );
        assert_eq!(sched().exec_order[0], 0, "base keeps its schedule position");

        // Wire the shared channel handle into both module states.
        let ch = super::super::get_module_port(1, 1, 0);
        assert!(ch >= 0, "emitter output channel must be open");
        set_state_ch(1, ch);
        set_state_ch(0, ch);

        // ── Step the live graph: base keeps stepping AND receives the sentinel.
        step(4);
        assert!(emit_done(), "emitter must have written the sentinel");
        assert_eq!(
            base_lastval(),
            SENTINEL,
            "base must receive the emitted value"
        );
        assert!(
            base_counter() > count_before_add,
            "base must keep stepping across the add (no pause/reset)"
        );
        let count_before_free = base_counter();

        // ── free_owner: reclaim everything, revoke the handle.
        set_state_ch(0, -1); // detach base from the soon-closed channel
        free_owner(handle).expect("free_owner must succeed");

        // Handle is dead (generation guard).
        assert!(
            sched().owners.lookup(handle).is_none(),
            "handle must be revoked"
        );
        assert!(!sched().owners.authorize(handle));
        // Slot, ports, exec order, counts, edges, and arena are all reclaimed.
        assert!(
            matches!(sched().modules[1], ModuleSlot::Empty),
            "module slot freed"
        );
        assert_eq!(super::super::get_module_port(1, 1, 0), -1, "ports reset");
        assert_eq!(sched().exec_order_count, 1, "exec order unspliced");
        assert_eq!(sched().active_module_count, 1);
        assert_eq!(sched().edge_count, edges_before, "edge reclaimed");
        assert_eq!(
            crate::kernel::loader::arena_usage().0,
            arena_before,
            "no state-arena leak"
        );
        // The owner's channel is closed: reading it no longer yields data.
        let mut buf = [0u8; 4];
        // SAFETY: handle was valid; reading a closed handle returns an error.
        let rc = unsafe { channel::channel_read(ch, buf.as_mut_ptr(), 4) };
        assert_ne!(rc, 4, "closed channel must not deliver data");

        // Base survives teardown and keeps stepping.
        step(2);
        assert!(
            base_counter() > count_before_free,
            "base must keep stepping after free_owner"
        );

        // ── Binary codec surface: encode a 0-module owner, apply + free it via
        // the syscall entry points (exercises the decoder without PIC load).
        let mut blob = [0u8; 34];
        blob[0..4].copy_from_slice(&ADD_MAGIC.to_be_bytes());
        blob[4..6].copy_from_slice(&ADD_VERSION.to_be_bytes());
        // reserved, pod_uid, caps, and both counts are left zero.
        // SAFETY: `blob` is a 34-byte writable buffer, > the 6 bytes the handle
        // write-back needs.
        let rc = unsafe { apply_add_encoded(blob.as_mut_ptr(), blob.len()) };
        assert_eq!(rc, 0, "encoded 0-module add must succeed");
        let h = OwnerHandle {
            slot: u16::from_le_bytes([blob[0], blob[1]]),
            generation: u32::from_le_bytes([blob[2], blob[3], blob[4], blob[5]]),
        };
        assert!(sched().owners.authorize(h), "decoded handle must be live");
        let mut hbuf = [0u8; 6];
        hbuf[0..2].copy_from_slice(&h.slot.to_le_bytes());
        hbuf[2..6].copy_from_slice(&h.generation.to_le_bytes());
        // SAFETY: 6-byte readable handle record.
        assert_eq!(unsafe { free_owner_encoded(hbuf.as_ptr(), hbuf.len()) }, 0);
        assert!(
            sched().owners.lookup(h).is_none(),
            "encoded free revokes handle"
        );

        // A malformed blob (bad magic) fails closed.
        let bad = [0u8; 34];
        // SAFETY: 34-byte readable/writable buffer.
        let rc_bad = unsafe { apply_add_encoded(bad.as_ptr() as *mut u8, bad.len()) };
        assert_eq!(rc_bad, -22);
    }
}
