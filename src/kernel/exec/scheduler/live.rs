//! Minimal live graph mutation — add and tear down a self-contained
//! subgraph owner on a *running* graph, without a destructive rebuild.
//!
//! This is the keystone primitive behind OTA, orchestrated workloads, and
//! REPL subgraph-exec: the same mechanism under different lifecycle
//! policies. The surface is deliberately just add and teardown, plus the
//! per-owner reclaim teardown needs — enough for the cheapest caller, an
//! ephemeral REPL subgraph, which is what keeps it to the core.
//!
//! Two operations, both synchronous and owner-scoped:
//!   * [`apply_add`]  — allocate an owner, instantiate its modules, open its
//!     edges, and *append* it to the execution order. No existing owner is
//!     paused, reset, or re-ordered; the phase stays `Running` throughout.
//!   * [`free_owner`] — stop the owner's modules (one-shot drain then
//!     terminate), close its edges, reclaim its state, and revoke the handle
//!     (the generation guard in [`crate::kernel::workload::owner`] rejects it thereafter).
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
//! async PIC load, owner-tagged allocator, and partial replacement
//! are documented follow-ups, not built here. Gated on `multitenant`
//! (host-linux + bcm2712 enable it; bare-metal rp compiles it out at zero cost).

use super::{
    BuiltInModule, Edge, InstantiateResult, ModulePorts, ModuleSlot, SchedulerState, MAX_CHANNELS,
    MAX_MODULES, SCHED,
};
use crate::kernel::boot::config::ModuleEntry;
use crate::kernel::workload::owner::{OwnerHandle, OwnerState, OWNER_SYSTEM};

/// Largest subgraph one `apply_add` admits. Bounded, stack-only working set.
pub const MAX_ADD_MODULES: usize = 16;
/// Largest edge count one `apply_add` admits.
pub const MAX_ADD_EDGES: usize = 32;

/// Reserved `Endpoint::Existing` global index marking a **net-facing
/// spare-lane edge** in a FLXA blob ( option A). The workload manager composes
/// a `net=own` workload's FLXA off-node and CANNOT express
/// `Endpoint::ExistingChannel` — the FLXA v1 wire has no channel-endpoint
/// kind, and the spare-lane channel id is a kernel runtime value unknowable
/// off-node. So a `net=own` template emits its net-facing producer edge with
/// `to = Existing(SPARE_LANE_SENTINEL)`; the metal backend
/// (`workload_graph.rs`), between decode and apply, resolves the boot merge's
/// next free spare lane and rewrites the edge to `ExistingChannel(lane)` (via
/// [`apply_add_encoded_spare_lane`]). `0xFFFF` is never a real live module
/// slot (`MAX_MODULES` ≪ `0xFFFF`), so the marker is unambiguous and rides the
/// EXISTING FLXA v1 wire with NO codec/ABI change (`decode_endpoint(1,
/// 0xFFFF)` round-trips to `Existing(0xFFFF)`).
pub const SPARE_LANE_SENTINEL: u16 = 0xFFFF;

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
    /// A pre-existing **shared channel** by id — an attachable-lane merge's
    /// spare input lane. Only valid as an edge `to`: the producer (`from`, a
    /// `New` module) is wired to write into this exact channel — which a boot
    /// merge already reads — instead of `apply_add` opening a fresh ring. This
    /// is how a runtime `net=own` workload reaches the node's one shared `ip`
    /// through the merge without any runtime merge-state mutation.
    /// Direct-API only: the FLXA v1 wire has no channel-endpoint kind,
    /// mirroring `AddEdge::wake_on_write`'s direct-only status.
    ExistingChannel(i32),
    /// A **tap** on a live module's output port (global slot index), valid
    /// only as an edge `from`. The edge gets a fresh channel that the kernel
    /// fills with a copy of every write to that port's channel — lossy, never
    /// back-pressuring the producer — and the tapped module's own wiring is
    /// untouched. FLXA endpoint kind 2. One tap per channel.
    Tap(u16),
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
    /// Wake-on-write: a successful write on this edge latches the
    /// consumer's event-wake bit and rings the scheduler doorbell — same
    /// semantics as `wake: true` on a base-graph wiring entry, bound with
    /// the same rules as `prepare_graph`'s wiring pass (same-domain
    /// direct edges only). NOT expressible through the FLXA wire codec:
    /// the v1 per-edge record has no reserved space, so
    /// `apply_add_encoded` always decodes it as `false`; only direct
    /// [`apply_add`] callers can set it.
    pub wake_on_write: bool,
}

/// A new owner's subgraph. `modules` is `&mut` because the sources are moved
/// out during instantiation; the caller's array is consumed.
pub struct AddSubgraph<'a> {
    pub owner_uid: [u8; 16],
    pub modules: &'a mut [AddModule],
    pub edges: &'a [AddEdge],
    /// Admitted hard caps from the resource profile; 0 = unlimited (the
    /// REPL/ephemeral default). Stored on the owner; fine-grained byte
    /// enforcement is deferred to the owner-tagged allocator.
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
    /// The owner's admitted `state_cap` would be exceeded by this subgraph's
    /// module state. Refused at admission rather than allowed to draw down the
    /// shared state arena at its neighbours' expense.
    StateCapExceeded,
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
            AddError::StateCapExceeded => -9,
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

/// Why `owner_pause` / `owner_resume` failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PauseError {
    /// The handle names the system owner, which can never be paused.
    NotWorkload,
    /// Unknown handle or stale generation (already freed / reused).
    StaleHandle,
    /// The owner is in a state the verb does not apply to (`Reserved`,
    /// `Draining`, `Revoked`) — pause is Active↔Paused only; a draining
    /// owner is past the point of reversibility.
    BadState,
}

impl PauseError {
    pub fn code(self) -> i32 {
        match self {
            PauseError::NotWorkload => -1,
            PauseError::StaleHandle => -2,
            PauseError::BadState => -3,
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
// Live-splice: multicore quiesce + per-domain dispatch-table splice
//
// ============================================================================
//
// bcm2712 cores step the PER-DOMAIN `domain_exec_order` (via
// `step_domain_modules` / `..._poll`), which only the boot-only
// `finalize_resident_graphs` populates — so a *runtime* `apply_add`/`free_owner`
// that mutates only the flat `exec_order` stages a subgraph the domain runners
// never step. The per-domain splice closes that: after the exec_order
// mutation, on bcm2712, splice
// the affected domains' `domain_exec_order` incrementally
// (`scheduler::recompute_domain_orders`, byte-identical to a full recompute for
// those domains) while every peer domain core is parked.
//
// Single-domain / non-bcm builds (host-linux, host-wasm, qemu-virt single-core)
// step the flat `exec_order` directly and never read `domain_exec_order`, so the
// splice is compiled out there and `apply_add`/`free_owner` stay byte-identical.

/// Bit `d` set ⇒ a module in the mutation touches domain `d`. Bounded by
/// `multicore::MAX_DOMAINS` (≤ 32, so a `u32` mask is always sufficient).
#[cfg(feature = "smp")]
#[inline]
fn domain_bit(domain_id: u8) -> u32 {
    1u32 << (domain_id as usize).min(crate::kernel::sys::hal::smp_max_domains() - 1)
}

/// Park every peer domain core for a live schedule mutation, returning `true`
/// iff a quiesce was actually taken (so the caller must release it). At runtime
/// on bcm2712 this is the `request_quiesce`/`wait_parked` park-all-secondaries
/// pattern (`bcm2712/multicore.rs`); at boot (pre-SMP, `!smp_online`) and on
/// single-domain hosts it is a no-op — the mutation runs single-threaded.
///
/// **Invariant:** primary-core-only. `request_quiesce` is defined for domain 0;
/// the runtime callers (`apply_add`/`free_owner`) must run on the primary
/// domain's scheduler context (the metal `workload` provider dispatches on the
/// system graph, which lives on domain 0).
#[inline]
fn quiesce_peers() -> bool {
    crate::kernel::sys::hal::smp_quiesce_peers()
}

/// Release a quiesce taken by [`quiesce_peers`]. No-op when `parked` is false.
#[inline]
fn release_peers(parked: bool) {
    if parked {
        crate::kernel::sys::hal::smp_release_peers();
    }
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
    let handle = match sched().owners.alloc(sub.owner_uid) {
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
            Endpoint::Existing(g) | Endpoint::Tap(g) => {
                let g = g as usize;
                if g < MAX_MODULES && !matches!(sched().modules[g], ModuleSlot::Empty) {
                    Some(g)
                } else {
                    None
                }
            }
            // A raw channel id resolves to no module — attach edges are handled
            // out of band in the edge-build loop below.
            Endpoint::ExistingChannel(_) => None,
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
        // Attachable-lane merge: `to` names a
        // pre-existing shared spare-lane channel a boot merge already caches.
        // Wire the producer to write into THAT channel — no fresh ring — so its
        // frame reaches the shared consumer (metal `ip`) through the merge with
        // zero merge-state mutation. The lane must be a real, currently-FREE
        // lane of some live merge (producer-less ⇒ system-owned); anything else
        // is a bad endpoint.
        if let Endpoint::ExistingChannel(ch) = ae.to {
            let merge = match super::merge_owning_lane(ch) {
                Some(m) => m,
                None => {
                    sched().owners.free(handle);
                    return Err(AddError::BadEndpoint);
                }
            };
            if !super::channel_producer_owner(ch).is_system() {
                // Lane already carries a producer — refuse rather than create a
                // second producer on one SPSC lane.
                sched().owners.free(handle);
                return Err(AddError::BadEndpoint);
            }
            let mut edge = Edge::new_indexed(from, "out", ae.from_port_index, merge, "in", 0);
            edge.channel = ch;
            edge.shared_channel = true;
            edge.buffer_bytes = ae.buffer_bytes;
            edge.wake_on_write = ae.wake_on_write;
            sched().edges[edge_base + i] = edge;
            continue;
        }
        let to = match resolve(ae.to) {
            Some(g) => g,
            None => {
                sched().owners.free(handle);
                return Err(AddError::BadEndpoint);
            }
        };
        let tap_source = if let Endpoint::Tap(_) = ae.from {
            // The tapped port must be one the module already writes.
            let ports = &sched().ports[from];
            let p = ae.from_port_index as usize;
            let ch = if p < ports.out_count as usize {
                ports.out_chans[p]
            } else {
                -1
            };
            if ch < 0 || matches!(ae.to, Endpoint::Tap(_)) {
                sched().owners.free(handle);
                return Err(AddError::BadEndpoint);
            }
            ch
        } else {
            -1
        };
        let mut edge =
            Edge::new_indexed(from, "out", ae.from_port_index, to, "in", ae.to_port_index);
        edge.tap = tap_source >= 0;
        edge.tap_source = tap_source;
        edge.buffer_bytes = ae.buffer_bytes;
        edge.wake_on_write = ae.wake_on_write;
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
    // Attach each tap: its fresh channel becomes the mirror of the tapped
    // port's channel. A channel already tapped refuses the add (one mirror
    // per channel); nothing is committed yet, so the rollback is local.
    for i in edge_base..edge_base + e {
        let edge = sched().edges[i];
        if edge.tap
            && !crate::kernel::ipc::channel::channel_set_mirror(edge.tap_source, edge.channel)
        {
            detach_taps(edge_base, i - edge_base);
            super::close_channels(&sched().edges[edge_base..edge_base + e]);
            clear_edge_range(edge_base, e);
            sched().owners.free(handle);
            return Err(AddError::BadEndpoint);
        }
    }
    sched().edge_count = edge_base + e;

    // 5. Populate the new modules' port tables from the freshly opened edges so
    //    instantiation / lazy channel lookup sees them.
    for &slot in local_to_global.iter().take(n) {
        super::populate_module_ports_from_edges(slot, slot);
    }
    // Also (re)populate any EXISTING module that a new edge attaches to, so its
    // port table gains the freshly-opened data channels — e.g. an ssh module's
    // data_rx/data_tx ports bridging to a spawned `run` pipeline. This rebuilds the
    // module's channel lookup table from ALL committed edges; because
    // collect_channels places each channel at its edge's declared port index,
    // existing ports (net_in/net_out at index 0) are preserved and the new bridge
    // ports (index 1) are added. Only the channel table is touched — the module's
    // ready-gate mask is left alone (isolation).
    for ae in sub.edges.iter() {
        if let Endpoint::Existing(g) = ae.from {
            super::populate_module_ports_from_edges(g as usize, g as usize);
        }
        if let Endpoint::Existing(g) = ae.to {
            super::populate_module_ports_from_edges(g as usize, g as usize);
        }
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
        // Charge this module's state-arena draw against the owner's admitted
        // `state_cap` (cap 0 = unlimited). The allocation has already happened
        // — the loader is the only half that knows the size — so exceeding the
        // cap rolls the whole add back rather than trimming it: a subgraph is
        // admitted entire or not at all, and a half-admitted one would be a
        // graph nobody described.
        let footprint = super::module_state_footprint(slot);
        if sched().owners.charge_state(handle, footprint).is_err() {
            let (charged, _) = sched().owners.charged_bytes(handle);
            log::warn!(
                "[live] owner slot {} refused: module state {} + {} exceeds its admitted \
                 state_cap; raise the workload's cap or shrink the graph",
                handle.slot,
                charged,
                footprint,
            );
            rollback_add(handle, &local_to_global[..=local], edge_base, e);
            return Err(AddError::StateCapExceeded);
        }
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

    // 7. Publish the subgraph into the live schedule. On bcm2712 every peer
    //    domain core is parked first: the exec_order splice,
    //    the per-domain dispatch-table splice, and the resident-graph reindex are
    //    the mutations a concurrently-stepping peer core must never observe half
    //    applied. No-op wrapper on single-domain hosts and at boot (both run
    //    single-threaded), so those paths stay byte-identical.
    let parked = quiesce_peers();

    //    Splice into the execution order: topo-sort the new modules over their
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

    // Per-domain splice (bcm2712 only): reproject the affected
    // domains' `domain_exec_order` from the freshly-spliced flat order so the
    // per-domain runners (`step_domain_modules`) step the new modules — not just
    // the flat-order path. Infallible (a bounded reprojection mirroring the boot
    // compute) and it runs AFTER the last fallible step (instantiation, step 6),
    // so `apply_add`'s atomic-rollback contract is preserved: any earlier failure
    // aborts before the exec_order/domain mutation and leaves the graph
    // bit-identical; once here the add is committed and cannot fail. Byte-
    // identical to a full recompute for the affected domains.
    #[cfg(feature = "smp")]
    {
        let mut affected: u32 = 0;
        for &slot in local_to_global.iter().take(n) {
            affected |= domain_bit(sched().domain_id[slot]);
        }
        super::recompute_domain_orders(affected);
    }

    // Wake-on-write wiring for the live-added edges — the same pass, with
    // the same skip set, that `prepare_graph` runs for base-graph edges:
    // bind `wake: true` edges' channels to their consumer so a successful
    // write latches the consumer's event-wake bit and rings the scheduler
    // doorbell. Same-domain direct edges only; anything the platform would
    // split across the SPSC pump (different domains, or
    // `EdgeClass::CrossCore`) must bind at consumer-side pump delivery
    // instead — a producer-side binding is the guaranteed-spurious
    // write-time wake — and the live path does no cross-domain bridging
    // (Linux-first, see the module header), so such edges stay unbound and
    // degrade to readable-channel-scan/backstop service. Runs after
    // instantiation (the last fallible step, and the point where the new
    // modules' `domain_id` is stamped), so a rollback never leaves a
    // binding behind.
    {
        let s = sched();
        for edge in s.edges[edge_base..edge_base + e].iter() {
            if !edge.wake_on_write
                || edge.channel < 0
                || edge.bridge_slot >= 0
                || edge.consumer_channel >= 0
                || edge.edge_class == crate::kernel::boot::config::EdgeClass::CrossCore
                || s.domain_id[edge.from_module] != s.domain_id[edge.to_module]
            {
                continue;
            }
            crate::kernel::ipc::channel::channel_set_wake_module(
                edge.channel,
                edge.to_module as i32,
            );
            log::info!(
                "[wake] live edge {}→{} chan={} wake-on-write bound",
                edge.from_module,
                edge.to_module,
                edge.channel
            );
        }
    }

    // 8. Activate.
    sched().owners.set_state(handle, OwnerState::Active);
    // Refresh the multi-graph runner's bounded resident-graph index so the new
    // owner is multiplexed (and its §7 pacer instance gets primed) on the next
    // pass. Bounded one-shot, off the hot path.
    super::rebuild_resident_graph_index();
    // Publication complete — release the parked peer cores (no-op if none).
    release_peers(parked);
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
    // An add that failed part-way still ran `module_new` for the slots that did
    // instantiate, and those may already have asked a provider for resources.
    // Same edge, same ordering as `free_owner`: notify before anything is torn
    // down and while the handle still resolves.
    crate::kernel::module::provider::notify_owner_released(handle);
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
        detach_taps(edge_base, e);
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

/// Stop mirroring into every tap edge in `edges[base..base+count]`.
fn detach_taps(base: usize, count: usize) {
    let s = sched();
    for i in base..base + count {
        let edge = s.edges[i];
        if edge.tap && edge.tap_source >= 0 {
            crate::kernel::ipc::channel::channel_set_mirror(edge.tap_source, -1);
        }
    }
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
    let state = match sched().owners.lookup(handle) {
        Some(e) => e.state,
        None => return Err(FreeError::StaleHandle),
    };
    // Tell subscribed providers first, while the owner handle still resolves
    // and every provider module is still live and steppable. A provider that
    // holds resources on this owner's behalf (scratch objects, open files)
    // reclaims them here; after this point the handle's generation moves and
    // a provider belonging to this owner's own graph is torn down below.
    // Delivered from here rather than from the platform drain driver so the
    // paths that bypass it — the workload verbs (KILL/DESTROY) and admission
    // rollback — are covered by the same edge.
    crate::kernel::module::provider::notify_owner_released(handle);
    // Which module slots belong to this owner, and which domains they occupy —
    // captured up front (pure reads) BEFORE any mutation, because the metal
    // per-domain unsplice below needs the freed owner's domain set, and
    // step 4 clears each module's `domain_id`. `affected` (bit d ⇒ domain d) is
    // used only on bcm2712.
    let mut owned = [false; MAX_MODULES];
    let mut owned_count = 0usize;
    #[cfg(feature = "smp")]
    let mut affected: u32 = 0;
    for (i, slot_owned) in owned.iter_mut().enumerate() {
        if matches!(sched().modules[i], ModuleSlot::Empty) {
            continue;
        }
        if super::module_owner(i) == handle {
            *slot_owned = true;
            owned_count += 1;
            #[cfg(feature = "smp")]
            {
                affected |= domain_bit(sched().domain_id[i]);
            }
        }
    }

    // Park every peer domain core for the teardown: the drain,
    // exec_order compaction, edge close, state free, per-domain unsplice, and
    // reindex are the mutations a concurrently-stepping peer core must never
    // observe half applied. No-op wrapper on single-domain hosts and at boot.
    let parked = quiesce_peers();

    if state == OwnerState::Paused {
        // Freeing a paused owner: drop its wake masking first so the
        // paused-owner count and mask bits can't outlive the owner. The
        // deferred wakes are discarded — the modules are being torn down.
        let mask = owned_module_mask(handle);
        let _ = crate::kernel::ipc::event::unpause_mask_modules(&mask);
    }
    sched().owners.begin_drain(handle);

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
    //    the shift, so surviving owners are untouched. `channel_close` resets
    //    the slot, which also clears any wake-on-write `wake_module` binding —
    //    a reused channel slot can never latch wakes for a freed module index.
    {
        let s = sched();
        let mut w = 0usize;
        for r in 0..s.edge_count {
            let edge = s.edges[r];
            let from_owned = edge.from_module < MAX_MODULES && owned[edge.from_module];
            let to_owned = edge.to_module < MAX_MODULES && owned[edge.to_module];
            if edge.tap && edge.tap_source >= 0 && (from_owned || to_owned) {
                // Either end going stops the mirror.
                crate::kernel::ipc::channel::channel_set_mirror(edge.tap_source, -1);
            }
            if edge.tap && from_owned && !to_owned {
                // The TAPPED module went; its observer lives on. End the tap's
                // stream (the observer completes by EOF) and keep the edge —
                // and its channel, which the observer still reads — until the
                // observer's own owner is freed.
                crate::kernel::ipc::channel::channel_mark_hup(edge.channel);
                let mut kept = edge;
                kept.tap_source = -1;
                s.edges[w] = kept;
                w += 1;
                continue;
            }
            if from_owned || to_owned {
                // A shared spare-lane edge (attachable-lane merge) is
                // removed with the owner but its channel is NEVER closed — the
                // boot merge caches it. Dropping the edge alone frees the lane
                // (`channel_producer_owner` reverts to system on the next scan).
                if edge.channel >= 0 && !edge.shared_channel {
                    crate::kernel::module::syscalls::channel_close(edge.channel);
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
            // A live-added module may have auto-registered as a contract
            // provider (e.g. a mounted volume backend). Compact its layer out
            // of the provider table before its state is freed, or a later
            // dispatch would call into freed code. Boot modules reach this via
            // `release_module_handles` on finish; the live-splice teardown must
            // do it explicitly.
            crate::kernel::module::provider::release_module_providers(i as u8);
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

    // Per-domain unsplice (bcm2712 only): reproject the affected
    // domains' `domain_exec_order` from the now-compacted flat order. The freed
    // modules are already gone from `exec_order` (step 2) and their slots are
    // `Empty` (step 4), so the reprojection naturally drops them and compacts —
    // byte-identical to a full recompute for those domains. Runs after the state
    // free so the rebuilt per-domain wake masks reflect only survivors.
    #[cfg(feature = "smp")]
    super::recompute_domain_orders(affected);

    // 5. Revoke the handle. The generation guard now rejects it.
    sched().owners.free(handle);
    // Drop the freed owner from the resident-graph index. A later slot reuse
    // bumps the generation, so its §7 pacer instance resets (§7.1) and the
    // re-added entry is re-primed.
    super::rebuild_resident_graph_index();
    // Teardown complete — release the parked peer cores (no-op if none).
    release_peers(parked);
    Ok(())
}

// ============================================================================
// owner_pause / owner_resume
// ============================================================================
//
// The metal PAUSE verb: a reversible quiesce built from exactly the two
// primitives the drain RFC specifies — §3.5 admission close (the
// `authorize_admit` gate, closed by the `Paused` owner state) and §3.6
// per-owner wake masking (`event::pause_mask_modules`) — plus the re-latch
// path `owner_resume` owns. Deliberately weaker than drain: no
// `module_drain`, no channel-empty requirement, no deadline. In-flight
// steps complete naturally (pause runs on the scheduler thread between
// steps — there is no preemption to suppress); from the next runner pass
// the §6.5 predicate treats the owner's graphs as not-runnable regardless
// of readable inbound data, and inbound writes simply buffer in the
// owner's channels (deferred, not refused — divergence from §3.5's
// refuse-or-defer choice, documented here: channel rings are lossless and
// bounded, so buffering IS the deferral; producers see normal
// backpressure when the ring fills).

/// The owner's stamped module set. Bounded scan; scheduler-thread only.
fn owned_module_mask(handle: OwnerHandle) -> crate::kernel::workload::bitmask::ModuleMask {
    let s = sched();
    let mut mask = crate::kernel::workload::bitmask::ModuleMask::new();
    for i in 0..MAX_MODULES {
        if !matches!(s.modules[i], ModuleSlot::Empty) && super::module_owner(i) == handle {
            mask.set(i);
        }
    }
    mask
}

/// Pause `handle`: close admission and mask its wake sources so its graphs
/// stop being stepped. Idempotent (pause of a paused owner is a no-op).
/// The system owner is refused. Scheduler-thread only (same access class
/// as `apply_add` / `free_owner`).
pub fn owner_pause(handle: OwnerHandle) -> Result<(), PauseError> {
    if handle.is_system() {
        return Err(PauseError::NotWorkload);
    }
    let state = match sched().owners.lookup(handle) {
        Some(e) => e.state,
        None => return Err(PauseError::StaleHandle),
    };
    match state {
        OwnerState::Paused => return Ok(()), // idempotent
        OwnerState::Active => {}
        _ => return Err(PauseError::BadState),
    }
    let mask = owned_module_mask(handle);
    // Mask-then-check (lost-wakeup discipline): divert NEW wakes first,
    // then sweep bits that latched before the mask was visible. A signal
    // racing the sweep lands in EVENT_WAKE_PENDING and is deferred by the
    // runner's per-pass straggler sweep / the woken-step guard.
    crate::kernel::ipc::event::pause_mask_modules(&mask);
    let latched = crate::kernel::ipc::event::take_wake_in_mask(&mask);
    crate::kernel::ipc::event::defer_masked_wakes(&latched);
    // State last: the runner skips on `Paused`, admission closes via
    // `authorize_admit` (the same gate, reversible).
    sched().owners.set_state(handle, OwnerState::Paused);
    Ok(())
}

/// Resume `handle`: reopen admission and re-latch every wake that arrived
/// while paused, so deferred producers/timers are serviced on the next
/// pass — a module with masked-arrived data steps exactly once with
/// `event_wake = true`, as if the wake had just fired. Idempotent (resume
/// of an Active owner is a no-op).
pub fn owner_resume(handle: OwnerHandle) -> Result<(), PauseError> {
    if handle.is_system() {
        return Err(PauseError::NotWorkload);
    }
    let state = match sched().owners.lookup(handle) {
        Some(e) => e.state,
        None => return Err(PauseError::StaleHandle),
    };
    match state {
        OwnerState::Active => return Ok(()), // idempotent
        OwnerState::Paused => {}
        _ => return Err(PauseError::BadState),
    }
    sched().owners.set_state(handle, OwnerState::Active);
    let mask = owned_module_mask(handle);
    // Unmask-then-drain: after the mask clears, new wakes latch normally;
    // the returned set is everything that was diverted while masked. Both
    // orders of a racing signal deliver — none are lost, a duplicate
    // event-wake step is benign (level-triggered semantics).
    let deferred = crate::kernel::ipc::event::unpause_mask_modules(&mask);
    if !deferred.is_empty() {
        for idx in deferred.iter_set() {
            crate::kernel::ipc::event::relatch_module_wake(idx);
        }
        crate::kernel::sys::hal::wake_scheduler();
    }
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
// layer's job and the channel is authenticated (k8s node-agent), so this
// decoder validates structure and bounds, not a content digest.

/// Wire magic: "FLXA".
pub const ADD_MAGIC: u32 = 0x464C_5841;
/// Wire version.
pub const ADD_VERSION: u16 = 1;

/// Minimal big-endian reading cursor over the encoded blob.
struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Cur<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
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
        2 => Some(Endpoint::Tap(idx)),
        _ => None,
    }
}

/// Decode a bounded binary `AddSubgraph` and apply it. On success writes the
/// 6-byte `OwnerHandle` (`slot:u16 LE, generation:u32 LE`) into `arg[0..6]` and
/// returns 0; otherwise a negative error (`-EINVAL` for a malformed blob, or
/// the negative [`AddError::code`]).
///
/// A [`SPARE_LANE_SENTINEL`] `to` endpoint is **not** rewritten here: it decodes
/// to `Existing(0xFFFF)`, which resolves to no live module and fails
/// [`AddError::BadEndpoint`] — a plain FLXA apply never carries the metal
/// net-facing sentinel. The metal backend uses [`apply_add_encoded_spare_lane`]
/// instead.
///
/// # Safety
/// `arg` must be a writable buffer of at least `arg_len` bytes, valid for the
/// duration of the call (module params are borrowed from it in place).
pub unsafe fn apply_add_encoded(arg: *mut u8, arg_len: usize) -> i32 {
    // SAFETY: forwarded contract; `None` = no spare-lane rewrite (the sentinel,
    // if present, falls through to `BadEndpoint`).
    unsafe { apply_add_encoded_inner(arg, arg_len, None) }
}

/// The metal `net=own` variant of [`apply_add_encoded`] — the
/// decode→inject→apply seam. Identical to
/// `apply_add_encoded`, except a net-facing [`SPARE_LANE_SENTINEL`] `to`
/// endpoint is rewritten to `Endpoint::ExistingChannel(spare_lane)` before
/// apply, wiring the workload's producer into the boot merge's pre-cached spare
/// lane so its egress reaches the node's shared `ip`.
///
/// `spare_lane` is the caller-resolved free lane channel
/// (`merge_next_free_lane(find_spare_lane_merge_for_channel(ingress))`, resolved from the registered net-identity provider):
///   * `>= 0` — a sentinel edge is rewritten to `ExistingChannel(spare_lane)`,
///   * `< 0`  — a sentinel edge means the caller found NO free lane, so the
///     apply is refused `ENOMEM` (spare-lane exhaustion / no boot merge) with
///     nothing allocated — a clean fail-closed rollback.
///
/// A blob with **no** sentinel edge ignores `spare_lane` and is byte-identical
/// to `apply_add_encoded` (the host-shared path).
///
/// # Safety
/// As [`apply_add_encoded`].
pub unsafe fn apply_add_encoded_spare_lane(arg: *mut u8, arg_len: usize, spare_lane: i32) -> i32 {
    // SAFETY: forwarded contract.
    unsafe { apply_add_encoded_inner(arg, arg_len, Some(spare_lane)) }
}

/// Shared decode+apply body for [`apply_add_encoded`] /
/// [`apply_add_encoded_spare_lane`]. `spare_lane`:
///   * `None`         — no metal rewrite (sentinel → `BadEndpoint`),
///   * `Some(l)` l>=0 — rewrite a sentinel `to` to `ExistingChannel(l)`,
///   * `Some(l)` l<0  — a sentinel with no resolved lane → `-ENOMEM`.
///
/// # Safety
/// As [`apply_add_encoded`].
unsafe fn apply_add_encoded_inner(arg: *mut u8, arg_len: usize, spare_lane: Option<i32>) -> i32 {
    const EINVAL: i32 = -22;
    const ENOMEM: i32 = -12;
    if arg.is_null() {
        return EINVAL;
    }
    // SAFETY: caller guarantees `arg`/`arg_len` describe a valid buffer.
    let bytes = unsafe { core::slice::from_raw_parts(arg, arg_len) };
    let mut c = Cur::new(bytes);

    if c.u32() != Some(ADD_MAGIC) || c.u16() != Some(ADD_VERSION) || c.u16().is_none() {
        return EINVAL;
    }
    let owner_uid: [u8; 16] = match c.take(16) {
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
        // The v1 per-edge wire record (kind/idx/port ×2 + buffer_bytes) has
        // no reserved space to carry the wake flag; encoded edges are never
        // wake-flagged. See the field doc on `AddEdge::wake_on_write`.
        wake_on_write: false,
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
        let (Some(from), Some(mut to)) = (decode_endpoint(fk, fi), decode_endpoint(tk, ti)) else {
            return EINVAL;
        };
        // Net-facing spare-lane sentinel: the composer marks the
        // net-facing producer's `to` as `Existing(SPARE_LANE_SENTINEL)` because
        // it cannot name a kernel runtime channel off-node. Rewrite it to the
        // caller-resolved boot-merge spare lane (`ExistingChannel`) so the
        // producer edges straight into the merge.
        if matches!(to, Endpoint::Existing(SPARE_LANE_SENTINEL)) {
            match spare_lane {
                Some(l) if l >= 0 => to = Endpoint::ExistingChannel(l),
                // net=own with no free spare lane / no boot merge — fail closed
                // before anything is allocated (clean, no rollback needed).
                Some(_) => return ENOMEM,
                // Plain apply (host-shared): leave the sentinel; it resolves to
                // no module and `apply_add` rejects it (BadEndpoint), unchanged.
                None => {}
            }
        }
        edge.from = from;
        edge.from_port_index = fp;
        edge.to = to;
        edge.to_port_index = tp;
        edge.buffer_bytes = bb;
    }

    let sub = AddSubgraph {
        owner_uid,
        modules: &mut mods[..mc],
        edges: &edges[..ec],
        state_cap,
        buffer_cap,
    };
    match apply_add(sub, None) {
        Ok(handle) => {
            if arg_len < 6 {
                // Applied, but no room to report the handle — caller can still
                // free by owner_uid via a future op; treat as success.
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

/// Decode `[slot:u16 LE, generation:u32 LE]` and pause that owner
/// (`OWNER_PAUSE = 0x0C49`). Same handle record as `FREE_OWNER`.
///
/// # Safety
/// `arg` must point to at least `arg_len` readable bytes.
pub unsafe fn owner_pause_encoded(arg: *const u8, arg_len: usize) -> i32 {
    match decode_owner_handle(arg, arg_len) {
        Some(h) => match owner_pause(h) {
            Ok(()) => 0,
            Err(e) => e.code(),
        },
        None => -22,
    }
}

/// Decode `[slot:u16 LE, generation:u32 LE]` and resume that owner
/// (`OWNER_RESUME = 0x0C4A`).
///
/// # Safety
/// `arg` must point to at least `arg_len` readable bytes.
pub unsafe fn owner_resume_encoded(arg: *const u8, arg_len: usize) -> i32 {
    match decode_owner_handle(arg, arg_len) {
        Some(h) => match owner_resume(h) {
            Ok(()) => 0,
            Err(e) => e.code(),
        },
        None => -22,
    }
}

/// Shared `[slot:u16 LE, generation:u32 LE]` handle decode.
fn decode_owner_handle(arg: *const u8, arg_len: usize) -> Option<OwnerHandle> {
    if arg.is_null() || arg_len < 6 {
        return None;
    }
    // SAFETY: non-null with >= 6 readable bytes, checked above; callers
    // guarantee validity for the call duration.
    let bytes = unsafe { core::slice::from_raw_parts(arg, 6) };
    Some(OwnerHandle {
        slot: u16::from_le_bytes([bytes[0], bytes[1]]),
        generation: u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
    })
}
