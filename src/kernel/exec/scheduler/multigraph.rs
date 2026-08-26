//! Scheduler responsibility module (real module boundary; parent statics and
//! helpers reach us via `super`).
#![allow(
    unused_imports,
    reason = "the flat scheduler namespace is glob-imported; each module uses a subset"
)]
use super::*;

// ===========================================================================
// Multi-graph runtime (RFC adaptive_tick_extra §7 — the resident-graph runner)
// ===========================================================================
//
// The §7 graph-local pacer surface above is keyed by `(graph_slot, generation,
// domain)` and was built single-graph-degenerate. This section is the runtime
// that admits and concurrently runs MORE THAN ONE resident graph, so the pacer
// surface becomes live: each resident graph is an `owner::OwnerHandle{slot,
// generation}` (the system graph is `OWNER_SYSTEM`, slot 0; workload graphs are
// admitted as owners 1..N via `live::apply_add`). On a shared cooperative runner
// the runner steps each owner's modules independently, skips an idle owner
// (§6.5/§7.2), and arms the physical sleep as the §7.2 deadline-merge minimum.
//
// Static-bounded (§7.5): the resident-graph index is a bounded table built at
// admission/finalize time, NOT scanned per pass (§7.6). The graph→domain→pacer
// keys are resolved into `RESIDENT_GRAPHS` once; a live pass only reads it.

/// One resident `(graph, domain)` the runner multiplexes. `mask` is the cached
/// set of module slots this graph owns *in this domain* (built at finalize so
/// `take_wake_in_mask` is an `EVENT_WAKE ∩ mask` intersection, never a scan).
/// `primed` forces the first pass after (re)build to step the graph at least
/// once so the steady-state §6.5 predicate has prior-pass signals to read.
#[cfg(feature = "multitenant")]
#[derive(Clone, Copy)]
struct ResidentGraph {
    slot: u16,
    generation: u32,
    domain: u8,
    mask: ModuleMask,
    primed: bool,
    /// Last logged runnable state — drives the transition-only `MON_GRAPH_PACER`
    /// line (§12: per-pass logs must be rate-limited / transition-only).
    last_runnable: bool,
    /// Modules with `step_period > 1`. Each carries its OWN absolute next-due in
    /// `SchedulerState::module_next_due_us` and its own period
    /// (`step_period × NOMINAL tick`), so distinct periods AND phase offsets are
    /// preserved — the runner fires only the individually-due members (via
    /// `event_wake`), never the whole set at the shortest period.
    periodic_mask: ModuleMask,
    /// True iff EVERY owned module is idle-safe attested — the precondition for
    /// fully parking the graph when idle (§6.5). When false the graph is
    /// fail-closed: never parked, only relaxed to the `tick_max` backstop.
    idle_safe: bool,
    /// Absolute wall-clock deadline (µs) for the next backstop liveness step of a
    /// NON-idle-safe graph (advanced by `tick_max` each backstop step). Unused
    /// when `idle_safe` (the graph may park outright).
    backstop_next_due_us: u64,
}

#[cfg(feature = "multitenant")]
impl ResidentGraph {
    const EMPTY: ResidentGraph = ResidentGraph {
        slot: 0,
        generation: 0,
        domain: 0,
        mask: ModuleMask::EMPTY,
        primed: false,
        last_runnable: true,
        periodic_mask: ModuleMask::EMPTY,
        idle_safe: false,
        backstop_next_due_us: 0,
    };
}

#[cfg(feature = "multitenant")]
static mut RESIDENT_GRAPHS: [ResidentGraph; MAX_GRAPH_PACERS] =
    [ResidentGraph::EMPTY; MAX_GRAPH_PACERS];
#[cfg(feature = "multitenant")]
static mut RESIDENT_GRAPH_COUNT: usize = 0;

/// Rebuild the bounded resident-graph index from the live module set. Called at
/// boot after all admission `apply_add`s and on every reconfigure / `free_owner`
/// (§7.1: a reused slot is a *new* generation, so its pacer is reset and its
/// `primed` flag re-armed). One bounded pass over module slots — never on the
/// hot path. No-op (single-graph degenerate) on non-multitenant builds.
pub fn rebuild_resident_graph_index() {
    #[cfg(feature = "multitenant")]
    {
        // SAFETY: scheduler-thread-exclusive; runs at boot finalize / reconfigure,
        // never concurrently with a stepping pass. Mutable: re-anchors each
        // periodic module's `module_next_due_us`.
        let sched = unsafe { &mut *core::ptr::addr_of_mut!(SCHED) };
        // SAFETY: same single-mutator context as `sched` above.
        let table = unsafe { &mut *core::ptr::addr_of_mut!(RESIDENT_GRAPHS) };
        let mut count = 0usize;
        for entry in table.iter_mut() {
            *entry = ResidentGraph::EMPTY;
        }
        for idx in 0..MAX_MODULES {
            if matches!(sched.modules[idx], ModuleSlot::Empty) {
                continue;
            }
            let owner = sched.module_owner[idx];
            let domain = (sched.domain_id[idx] as usize).min(MAX_DOMAINS - 1) as u8;
            // Find or append the (owner.slot, owner.generation, domain) entry.
            let mut found = None;
            for (i, e) in table.iter().take(count).enumerate() {
                if e.slot == owner.slot && e.generation == owner.generation && e.domain == domain {
                    found = Some(i);
                    break;
                }
            }
            let i = match found {
                Some(i) => i,
                None => {
                    if count >= MAX_GRAPH_PACERS {
                        // Build-time admission (`MAX_PACER_INSTANCES`) rejects
                        // configs that need more; this is the fail-closed runtime
                        // backstop — extra graphs simply aren't multiplexed.
                        log::error!(
                            "[multigraph] resident-graph index full ({MAX_GRAPH_PACERS}); \
                             module {idx} owner slot={} not indexed",
                            owner.slot
                        );
                        continue;
                    }
                    let i = count;
                    table[i].slot = owner.slot;
                    table[i].generation = owner.generation;
                    table[i].domain = domain;
                    table[i].mask = ModuleMask::EMPTY;
                    table[i].primed = false;
                    table[i].periodic_mask = ModuleMask::EMPTY;
                    // Fresh entry: assume idle-safe and AND each owned module's
                    // attestation in below (an empty graph stays the EMPTY default).
                    table[i].idle_safe = true;
                    table[i].backstop_next_due_us = 0;
                    count += 1;
                    i
                }
            };
            table[i].mask.set(idx);
            // Each multi-tick period-gated module keeps its OWN absolute schedule
            // (per-module `module_next_due_us`), preserving distinct periods and
            // phases. Reset its next-due so it (re)primes on the next pass.
            if sched.step_period[idx] > 1 {
                table[i].periodic_mask.set(idx);
                sched.module_next_due_us[idx] = 0;
            }
            // A graph is idle-safe only if EVERY owned module attests it.
            if !sched.module_idle_safe[idx] {
                table[i].idle_safe = false;
            }
        }
        // Reconcile the §7 pacer table (`GRAPH_PACERS`) against the rebuilt
        // resident keys. A pacer whose (slot, generation, domain) no longer
        // appears belongs to a freed / reconfigured owner; left active it keeps
        // occupying a slot, so repeated owner churn across domains would exhaust
        // the bounded 16-slot table despite few LIVE graphs. Bounded (16×16) and
        // rebuild-time only — never on the hot path. (§7.1: a reused slot is a new
        // generation, so a stale-generation pacer is also released here.)
        // SAFETY: same single-mutator (scheduler-thread-exclusive) context.
        let pacers = unsafe { &mut *core::ptr::addr_of_mut!(GRAPH_PACERS) };
        for p in pacers.iter_mut() {
            if !p.active {
                continue;
            }
            let live = table.iter().take(count).any(|e| {
                e.slot == p.graph_slot && e.generation == p.generation && e.domain == p.domain
            });
            if !live {
                *p = GraphPacer::new();
            }
        }
        // SAFETY: scheduler-thread-exclusive write.
        unsafe {
            RESIDENT_GRAPH_COUNT = count;
        }
    }
}

/// Finalize the domain dispatch tables over the *current* live module set, then
/// rebuild the resident-graph index. Call ONCE after all boot-time `apply_add`
/// admissions, before the per-domain run loops start: `live::apply_add` splices
/// only the flat `exec_order` (the `domain_exec_order` splice is a deliberate
/// follow-up needing a multicore quiesce), so a per-domain cooperative runner
/// (BCM2712) would otherwise never see a boot-admitted module. Rebuilds
/// `domain_module_mask`, `domain_count`, and `domain_exec_order` from the flat
/// order, exactly as `prepare_graph` does for the base graph.
///
/// Boot-time only (cores not yet stepping) or single-threaded host — NOT safe to
/// call while a BCM domain loop is mid-pass over `domain_exec_order`. No-op on
/// non-multitenant builds.
pub fn finalize_resident_graphs() {
    #[cfg(feature = "multitenant")]
    {
        // SAFETY: scheduler-thread-exclusive; boot finalize / single-threaded host.
        let sched = unsafe { &mut *core::ptr::addr_of_mut!(SCHED) };
        for m in sched.domain_module_mask.iter_mut() {
            *m = ModuleMask::EMPTY;
        }
        let mut max_domain: u8 = 0;
        for i in 0..MAX_MODULES {
            if matches!(sched.modules[i], ModuleSlot::Empty) {
                continue;
            }
            let did = sched.domain_id[i];
            let d = (did as usize).min(MAX_DOMAINS - 1);
            sched.domain_module_mask[d].set(i);
            if did > max_domain {
                max_domain = did;
            }
        }
        let want_count = (max_domain as usize + 1).min(MAX_DOMAINS) as u8;
        if want_count > sched.domain_count {
            sched.domain_count = want_count;
        }
        let mc = sched.active_module_count;
        compute_domain_exec_orders_static(mc);
    }
    rebuild_resident_graph_index();
}

/// Boot path: admit every resident workload declared in the config's `[FXPD]`
/// post-body section (RFC adaptive_tick_extra §7 — the `combine <two-graph.yaml>`
/// / `workloads:` mechanism) as a workload owner via `apply_add`, then finalize the
/// domain dispatch tables. Call ONCE after `prepare_graph` + instantiation and
/// BEFORE the per-domain run loops start (same constraint as
/// `finalize_resident_graphs`). No-op when there is no workload section (single-graph
/// config, byte-identical boot) or on non-multitenant builds.
pub fn admit_resident_workloads_from_config() {
    #[cfg(feature = "multitenant")]
    {
        // SAFETY: boot context — single-threaded, sole reader of STATIC_CONFIG.
        let cfg = unsafe { static_config() };
        let ptr = cfg.resident_workload_section;
        let len = cfg.resident_workload_section_len;
        // Header: magic(4)+section_len(4)+crc16(2)+count(2) = 12 bytes. The whole
        // section's length+CRC were already validated in `read_config_from_slice`
        // (it only records the section when bounds AND CRC pass), so by here the
        // bytes are integral; the per-workload bounds below are belt-and-braces.
        if ptr.is_null() || len < 12 {
            return;
        }
        // SAFETY: `read_config_from_slice` validated `ptr`/`len` lie within the
        // mapped config blob, `len <= MAX_WORKLOAD_SECTION_BYTES`, and the CRC matched.
        let section = unsafe { core::slice::from_raw_parts(ptr, len) };
        let magic = u32::from_le_bytes([section[0], section[1], section[2], section[3]]);
        if magic != crate::kernel::boot::config::WORKLOAD_SECTION_MAGIC {
            return;
        }
        let count = u16::from_le_bytes([section[10], section[11]]) as usize;
        // Bounded scratch: `apply_add_encoded` needs a writable buffer (it writes
        // the 6-byte handle back) and borrows params in place during instantiate;
        // copying each blob leaves the read-only config image unmutated.
        const SCRATCH_LEN: usize = crate::kernel::boot::config::MAX_WORKLOAD_SECTION_BYTES;
        static mut WORKLOAD_SCRATCH: [u8; SCRATCH_LEN] = [0u8; SCRATCH_LEN];
        // Atomic admission: a partial admit (some workloads live, others rejected)
        // would contradict the "all workloads" contract and leave the runtime in a
        // half-built state. Record each admitted owner's handle; if ANY workload fails,
        // roll back every handle admitted in this pass via `free_owner` and admit
        // ZERO — the runtime stays single-graph rather than partially multiplexed.
        let mut handles = [crate::kernel::workload::owner::OwnerHandle {
            slot: 0,
            generation: 0,
        }; MAX_GRAPH_PACERS];
        let mut idle_flags = [false; MAX_GRAPH_PACERS];
        let mut admitted = 0usize;
        let mut failed = false;
        let mut off = 12usize;
        for _ in 0..count {
            // Per-workload frame: blob_len(4) + flags(1) + blob. flags bit0 = idle-safe
            // attestation (the operator/tooling asserts the workload is demand-driven).
            if off + 5 > len {
                log::error!("[multigraph] workload section truncated mid-frame; rolling back");
                failed = true;
                break;
            }
            let blob_len = u32::from_le_bytes([
                section[off],
                section[off + 1],
                section[off + 2],
                section[off + 3],
            ]) as usize;
            off += 4;
            let workload_flags = section[off];
            off += 1;
            let workload_idle_safe = (workload_flags & 0x01) != 0;
            if blob_len == 0 || off + blob_len > len || blob_len > SCRATCH_LEN {
                log::error!("[multigraph] workload blob len {blob_len} out of range; rolling back");
                failed = true;
                break;
            }
            // SAFETY: scheduler-thread-exclusive boot context; bounded copy.
            let scratch = unsafe { &mut *core::ptr::addr_of_mut!(WORKLOAD_SCRATCH) };
            scratch[..blob_len].copy_from_slice(&section[off..off + blob_len]);
            off += blob_len;
            // SAFETY: `scratch` is writable and >= `blob_len`; `apply_add_encoded`
            // validates the FLXA blob structure/bounds and writes the 6-byte handle
            // (slot u16 LE, generation u32 LE) back into `scratch[0..6]` on success.
            let rc = unsafe { live::apply_add_encoded(scratch.as_mut_ptr(), blob_len) };
            if rc >= 0 {
                if admitted < MAX_GRAPH_PACERS {
                    handles[admitted] = crate::kernel::workload::owner::OwnerHandle {
                        slot: u16::from_le_bytes([scratch[0], scratch[1]]),
                        generation: u32::from_le_bytes([
                            scratch[2], scratch[3], scratch[4], scratch[5],
                        ]),
                    };
                    idle_flags[admitted] = workload_idle_safe;
                }
                admitted += 1;
            } else {
                log::error!("[multigraph] resident workload admit failed rc={rc}; rolling back");
                failed = true;
                break;
            }
        }
        if failed {
            for h in handles.iter().take(admitted.min(MAX_GRAPH_PACERS)) {
                let _ = live::free_owner(*h);
            }
            log::error!(
                "[multigraph] resident workload admission aborted; rolled back {admitted} workload(s) — \
                 none active (single-graph boot)"
            );
            return;
        }
        if admitted > 0 {
            // Apply each workload's idle-safe attestation to its admitted modules
            // BEFORE finalize (which rebuilds the per-graph `idle_safe` from the
            // module flags). Unattested workloads stay fail-closed (backstop cadence).
            for i in 0..admitted.min(MAX_GRAPH_PACERS) {
                set_owner_idle_safe(handles[i], idle_flags[i]);
            }
            log::info!("[multigraph] admitted {admitted} resident workload(s) from config");
            finalize_resident_graphs();
        }
    }
}

/// Number of distinct resident `(graph, domain)` instances the runner is
/// multiplexing. `<= 1` selects the single-graph fast path (today's behaviour).
/// Always `0`/`1`-equivalent on non-multitenant builds (one resident graph).
pub fn resident_graph_count() -> usize {
    #[cfg(feature = "multitenant")]
    {
        // SAFETY: scheduler-thread read of a bounded counter.
        unsafe { RESIDENT_GRAPH_COUNT }
    }
    #[cfg(not(feature = "multitenant"))]
    {
        1
    }
}

/// Count resident `(graph, domain)` instances whose domain is `domain`.
#[cfg(feature = "multitenant")]
fn resident_graph_count_in_domain(domain: usize) -> usize {
    // SAFETY: scheduler-thread read of the bounded resident-graph table/counter.
    let table = unsafe { &*core::ptr::addr_of!(RESIDENT_GRAPHS) };
    // SAFETY: scheduler-thread read of a bounded counter.
    let count = unsafe { RESIDENT_GRAPH_COUNT };
    table
        .iter()
        .take(count)
        .filter(|e| e.domain as usize == domain)
        .count()
}

/// Step exactly ONE resident graph's modules in `domain` for this tick, reusing
/// the shared `step_one_module` body and the bounded burst multi-pass. Only
/// modules whose owner matches `(slot, generation)` run; siblings are skipped so
/// a hot graph's burst loop cannot run an idle graph's modules. Returns this
/// graph's per-sub-pass `(work, burst)` signals, read back from the per-domain
/// `PACER_WORK_TICK` / `PACER_BURST_TICK` accumulators (reset here, so they
/// reflect only this graph's modules — every module in `domain` for this owner).
#[cfg(feature = "multitenant")]
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors step_one_module's threaded (modules, sched, not_ready, \
              active_count) plus the owner key and the shared overrun latch; \
              bundling them into a struct would obscure the step call site"
)]
fn step_graph_owner(
    modules: &mut [ModuleSlot; MAX_MODULES],
    sched: &mut SchedulerState,
    slot: u16,
    generation: u32,
    domain: usize,
    not_ready: &ModuleMask,
    active_count: &mut usize,
    overrun_logged_this_pass: &mut bool,
    woken: &ModuleMask,
    periodic: &ModuleMask,
) -> (bool, bool) {
    use crate::kernel::workload::owner::OwnerHandle;
    let want = OwnerHandle { slot, generation };
    // Reset this graph's signal accumulators so the read-back is owner-scoped.
    PACER_BURST_TICK[domain].store(false, Ordering::Relaxed);
    PACER_WORK_TICK[domain].store(false, Ordering::Relaxed);

    let count = sched.active_module_count;
    // Iterate the FLAT topological `exec_order` (the universal module list —
    // `live::apply_add` splices it, whereas `domain_exec_order` is only rebuilt
    // at boot finalize), filtering to this graph's modules IN this domain. That
    // makes per-owner stepping correct whether the owner was admitted at boot or
    // live, on any platform.
    let n = sched.exec_order_count;
    // Apply the cyclic-shift fairness rotation: a hard budget overrun bumps
    // `domain_exec_order_offset[domain]` (below), and starting each pass at that
    // offset gives every position equal exposure across passes — otherwise the
    // modules after a repeat-overrunner would be deterministically starved.
    // Computed once per pass (the increment takes effect next tick), mirroring
    // `step_domain_modules`.
    let dom_offset = if n > 0 {
        (sched.domain_exec_order_offset[domain] as usize) % n
    } else {
        0
    };
    let mut tick_pass = 0u32;
    let mut hard_break = false;
    loop {
        BURST_SEEN_THIS_PASS[domain].store(false, Ordering::Relaxed);
        for i in 0..n {
            let pos = if n > 0 { (i + dom_offset) % n } else { i };
            let module_idx = sched.exec_order[pos] as usize;
            if module_idx >= count {
                continue;
            }
            // Domain + owner filter — the heart of cross-graph isolation: a
            // graph's pass only ever steps its own modules in its own domain.
            if (sched.domain_id[module_idx] as usize) != domain {
                continue;
            }
            if sched.module_owner[module_idx] != want {
                continue;
            }
            // Skip Tier-1c pre-tick-drain modules: the flat `exec_order` includes
            // them, but they are run exactly once per tick by `step_domain_pre_tick`
            // (the runner calls it once, domain-global). Stepping them again here
            // would double-execute RX drains and break the run-exactly-once
            // contract (the same reason `step_domain_modules` iterates
            // `domain_exec_order`, which excludes them, not the flat order).
            if sched.pre_tick_drain[module_idx] {
                continue;
            }
            // §6.5 event-wake: a module woken this pass steps with `event_wake =
            // true`, which bypasses step-period gating (the wake overrides the
            // period) exactly as `step_woken_modules` does — so a targeted wake is
            // honoured even when the module's period is not due this tick.
            let event_wake = woken.test(module_idx);
            // §7 absolute periodic scheduling: a period-gated module fires ONLY on
            // its own next-due (signalled via `woken`/`event_wake` by the runner)
            // or a direct event wake. Otherwise it is SUPPRESSED here — not run and
            // its tick counter NOT advanced — so a pass triggered by a sibling's
            // work/wake cannot advance its counter and fire it before its absolute
            // deadline. (The tick-counter path in `step_one_module` stays the
            // single-graph behaviour; this confines absolute scheduling to the
            // multi-graph runner.)
            if periodic.test(module_idx) && !event_wake {
                continue;
            }
            step_one_module(
                modules,
                sched,
                module_idx,
                not_ready,
                active_count,
                event_wake,
            );

            let soft = domain_budget_exhausted(sched, domain);
            let hard = soft && domain_budget_hard_overrun(sched, domain);
            if soft && !*overrun_logged_this_pass {
                record_domain_budget_overrun(sched, domain, module_idx);
                sched.domain_exec_order_offset[domain] =
                    sched.domain_exec_order_offset[domain].wrapping_add(1);
                *overrun_logged_this_pass = true;
            }
            if hard {
                hard_break = true;
                break;
            }
        }
        tick_pass += 1;
        if hard_break || tick_pass >= MAX_PIPELINE_PASSES {
            break;
        }
        if domain_budget_exhausted(sched, domain) {
            break;
        }
        // Device input may have arrived while this graph pass ran. Refill only
        // for the system owner; other resident owners consume the resulting
        // system-graph output through their normal scheduled pass.
        let refilled =
            slot == 0 && step_domain_pipeline_refill(modules, sched, domain, active_count);
        // Same forced-pass override as the single-graph loop in
        // domain_budget.rs, via the shared predicate.
        if !BURST_SEEN_THIS_PASS[domain].load(Ordering::Relaxed)
            && !refilled
            && !super::stepping::forced_pass_pending(tick_pass)
        {
            break;
        }
    }
    let work = PACER_WORK_TICK[domain].load(Ordering::Relaxed);
    let burst = PACER_BURST_TICK[domain].load(Ordering::Relaxed);
    (work, burst)
}

/// §6.5 timer-due predicate for a resident graph. v1: wall-clock timers signal
/// through the event path, so a due timer surfaces as a targeted wake
/// (`owner_wake_pending`); this returns `false` and the wake carries it. A
/// future per-owner timer wheel can make this precise; until then a graph with
/// no targeted wake and no prior-pass work is treated idle (the AC1/AC2 case).
#[cfg(feature = "multitenant")]
#[inline]
fn owner_timer_due(_slot: u16, _generation: u32, _domain: usize) -> bool {
    false
}

/// §3.2 pause predicate for a resident graph: true iff the owning slot is
/// `Paused` at this generation. Callers MUST short-circuit behind
/// `event::paused_owners_present()` so the unused path stays a single
/// relaxed load (default-off discipline).
#[cfg(feature = "multitenant")]
#[inline]
fn owner_graph_paused(sched: &SchedulerState, slot: u16, generation: u32) -> bool {
    slot != 0
        && sched.owners.entry_at(slot as usize).is_some_and(|e| {
            e.generation == generation
                && matches!(e.state, crate::kernel::workload::owner::OwnerState::Paused)
        })
}

/// True iff any resident graph in `domain` belongs to a paused owner. Used
/// by `step_resident_graphs_domain` to route a single-paused-graph domain
/// through the multi-graph runner (whose §3.2 skip is the only paused-aware
/// stepping path) instead of the pause-blind fast path. Bounded scan of the
/// resident-graph index; callers short-circuit behind
/// `event::paused_owners_present()`.
#[cfg(feature = "multitenant")]
fn domain_has_paused_graph(domain: usize) -> bool {
    // SAFETY: scheduler-thread read; the table is only mutated at rebuild.
    let table = unsafe { &*core::ptr::addr_of!(RESIDENT_GRAPHS) };
    // SAFETY: scheduler-thread read of a bounded counter.
    let rc = unsafe { RESIDENT_GRAPH_COUNT };
    // SAFETY: scheduler-thread read of the owner table.
    let sched = unsafe { &*core::ptr::addr_of!(SCHED) };
    table
        .iter()
        .take(rc)
        .any(|e| e.domain as usize == domain && owner_graph_paused(sched, e.slot, e.generation))
}

/// §6.5 readable-channel term (RFC idle_skip_wake §4): does any edge whose
/// CONSUMER belongs to this graph — and whose PRODUCER does not — hold
/// readable bytes? Without this term, data written into a skipped graph's
/// inbound channel (a cross-owner `apply_add` edge, or a system-graph
/// producer) waits for the graph's backstop cadence: under demand-driven
/// idle that is `tick_max_us` per hop, which is exactly the multi-workload
/// latency term the RFC exists to remove. The check adds a wake REASON
/// evaluated at the runner's existing cadence — not a wake source — so
/// there is no storm surface and no ordering change.
///
/// Cost: O(edges) per otherwise-idle graph per pass, one lock-guarded
/// `channel_poll` per cross-graph edge (POLL_IN covers both FIFO fill and
/// mailbox READY). Callers short-circuit it behind every cheaper runnable
/// term. If graph counts ever make the scan measurable, the RFC's O1
/// refinement is a per-graph dirty bit set inside `channel_write` — decide
/// from density-scenario profiling, not up front.
///
/// Intra-graph edges are deliberately excluded: data on them can only have
/// been produced by this graph's own modules, whose step already reported
/// work/burst to the pacer — including them would keep a graph busy on
/// bytes it is itself draining at its own pace.
///
/// Fills `out` with the CONSUMER modules that have readable inbound data;
/// the runner adds them to the woken set so they step with
/// `event_wake = true` (bypassing step-period gating) — cross-graph
/// channel data thereby carries exactly the semantics of a targeted
/// `event_signal`, which is what RFC adaptive_tick mechanism (a) named for
/// "channel write" wakes all along. Returns `true` if any were found.
#[cfg(feature = "multitenant")]
fn graph_inbound_readable(sched: &SchedulerState, mask: &ModuleMask, out: &mut ModuleMask) -> bool {
    let mut any = false;
    for e in sched.edges.iter().take(sched.edge_count) {
        if !mask.test(e.to_module) || mask.test(e.from_module) {
            continue;
        }
        // Consumer-side handle: the bridged override when present (the
        // consumer can only read what the pump already delivered), else
        // the shared channel.
        let ch = if e.consumer_channel >= 0 {
            e.consumer_channel
        } else {
            e.channel
        };
        if ch < 0 {
            continue;
        }
        let ready =
            crate::kernel::ipc::channel::channel_poll(ch, crate::kernel::ipc::channel::POLL_IN);
        if ready > 0 && (ready as u32 & crate::kernel::ipc::channel::POLL_IN) != 0 {
            out.set(e.to_module);
            any = true;
        }
    }
    any
}

/// The shared-cooperative-runner core (RFC adaptive_tick_extra §7.2). Steps
/// every resident graph in `domain` independently, skips idle graphs (§6.5),
/// and returns the merged physical-sleep deadline (µs). Mirrors the once-per-tick
/// housekeeping of `step_domain_modules` (tick advance, drain timeout, budget
/// reset, worst-step decay, Tier-1c pre-tick, ISR-bridge pump) but runs the
/// exec-order rotation once PER resident graph so each graph's burst/budget
/// fairness and pacer state stay independent.
#[cfg(feature = "multitenant")]
fn multi_graph_runner(modules: &mut [ModuleSlot; MAX_MODULES], domain: usize) -> (StepResult, u32) {
    // SAFETY: scheduler-thread context — sole stepper for this domain (mirrors
    // `step_domain_modules`).
    let sched = unsafe { &mut *core::ptr::addr_of_mut!(SCHED) };
    if sched.prepare_in_progress {
        return (StepResult::Done, domain_tick_max_us(domain));
    }
    // Canonical tick advance — domain 0 only (BCM convention; see
    // `step_domain_modules`).
    if domain == 0 {
        // SAFETY: domain 0 is the canonical tick advancer.
        unsafe {
            DBG_TICK = DBG_TICK.wrapping_add(1);
        }
    }
    let count = sched.active_module_count;
    if enforce_drain_timeout(sched, modules, count) {
        return (StepResult::Done, domain_tick_max_us(domain));
    }

    let mut active_count: usize = 0;
    for i in 0..count {
        if !sched.finished[i] {
            active_count += 1;
        }
    }
    let mut not_ready = ModuleMask::new();
    // §6.5 fail-closed "must tick" set: modules that MUST be stepped regardless of
    // work/wake or the idle predicate, because skipping them stalls forward
    // progress — a deferred-ready module still initialising (never reaches Ready)
    // or a faulting/recovering module whose restart backoff only decrements when
    // stepped. A graph owning any such module is not idle-skip eligible until it
    // clears. Built once per pass (same bounded 0..count walk as `not_ready`),
    // never a per-graph scan of all modules.
    let mut must_tick_mask = ModuleMask::new();
    for i in 0..count {
        if !sched.ready[i] {
            not_ready.set(i);
        }
        if sched.finished[i] {
            continue;
        }
        let initialising = sched.deferred_ready[i] && !sched.ready[i];
        let recovering = matches!(
            sched.fault_info[i].state,
            FaultState::Faulted | FaultState::Recovering
        );
        if initialising || recovering {
            must_tick_mask.set(i);
        }
    }
    // Once-per-tick budget reset + §5.3 worst-step decay for this domain.
    sched.domain_budget_us_consumed[domain] = 0;
    let w = sched.domain_worst_step_us[domain];
    if w > 0 {
        sched.domain_worst_step_us[domain] = w - (w >> WORST_STEP_DECAY_SHIFT).max(1);
    }
    let mut overrun_logged_this_pass = false;

    // Tier-1c pre-tick drain — domain-global, runs once (not per graph).
    step_domain_pre_tick(modules, sched, domain, &not_ready, &mut active_count);

    let flags = domain_adaptive_flags(domain);
    let adaptive = flags != 0;
    // Idle-skip (§6.5) is gated SPECIFICALLY on mechanism (a). A cadence-only or
    // thermal domain (e.g. `ADAPTIVE_FLAG_CADENCE` without `ADAPTIVE_FLAG_IDLE`)
    // adjusts the tick RATE but must still step every resident graph every pass —
    // skipping there would freeze a workload's period-gated step counters and
    // park it permanently. Only mechanism (a) makes a workload skip-idle eligible.
    let idle_skip = (flags & ADAPTIVE_FLAG_IDLE) != 0;
    let tmin = domain_tick_min_us(domain);
    let tmax = domain_tick_max_us(domain);
    let floor = pacer_domain_floor_us(domain);
    let now = crate::kernel::sys::hal::now_micros();

    // SAFETY: scheduler-thread read of a bounded counter.
    let rc = unsafe { RESIDENT_GRAPH_COUNT };
    // §7.2 deadline merge, computed INLINE (no `keys` array) so the runner's
    // stack frame stays small — it runs on top of the deepest module-step call
    // chain (the system net stack) on a bounded bare-metal per-core stack.
    let mut min_runnable = u32::MAX;
    let mut min_backstop = u32::MAX;
    let mut any_runnable = false;

    let nominal = domain_tick_us(domain);
    for gi in 0..rc {
        // Snapshot the entry's static fields before borrowing `sched` mutably in
        // the step pass (the table is not mutated by stepping).
        let (slot, generation, gdomain, mask, primed, periodic_mask, idle_safe, snap_backstop);
        {
            // SAFETY: scheduler-thread read; the table is not mutated by stepping.
            let table = unsafe { &*core::ptr::addr_of!(RESIDENT_GRAPHS) };
            let e = &table[gi];
            slot = e.slot;
            generation = e.generation;
            gdomain = e.domain as usize;
            mask = e.mask;
            primed = e.primed;
            periodic_mask = e.periodic_mask;
            idle_safe = e.idle_safe;
            snap_backstop = e.backstop_next_due_us;
        }
        if gdomain != domain {
            continue;
        }
        // §3.2 pause skip (rfc_workload_lifecycle.md, P4): a paused owner's
        // graph is not-runnable REGARDLESS of wakes, due periodic modules,
        // backstop, must-tick, or readable inbound — evaluated before every
        // §6.5 term so none of them can step it. Wake bits that latched
        // before the pause mask became visible (the mask-then-check race)
        // are swept into the deferred store here, pass by pass, so a paused
        // owner's stragglers can't keep `domain_wake_pending` asserted and
        // pin the domain out of idle sleep. Guarded by the default-off
        // paused-owner count: with no owner paused this is one relaxed load
        // per graph per pass, and stepping proceeds as the pause-free path.
        if crate::kernel::ipc::event::paused_owners_present()
            && owner_graph_paused(sched, slot, generation)
        {
            let stragglers = crate::kernel::ipc::event::take_wake_in_mask(&mask);
            crate::kernel::ipc::event::defer_masked_wakes(&stragglers);
            continue;
        }
        // Atomically read-and-clear this owner's wake bits. The returned snapshot
        // (a) gives `wake` for the runnable/deadline decision, and (b) is threaded
        // into `step_graph_owner` so the *specifically woken* modules step with
        // `event_wake = true` (bypassing step-period gating) before the bit is
        // gone — preserving normal event-wake semantics. Taking (not peeking) also
        // makes the wake one-shot, so it can't stay sticky (bcm2712's domain loop
        // has no global `take_wake_pending` drain); a later wake re-latches.
        let woken = crate::kernel::ipc::event::take_wake_in_mask(&mask);
        let wake = !woken.is_empty();
        let timer_due = owner_timer_due(slot, generation, domain);
        let is_system = slot == 0;

        // §7 PER-MODULE absolute schedule: each period-gated module fires exactly
        // when wall-clock reaches ITS OWN `module_next_due_us`, so distinct periods
        // and phase offsets are preserved and a sibling's pass rate never advances
        // it. Build the individually-due set and track the soonest pending due (for
        // the deadline merge). Bounded by the periodic module count, not all
        // modules (§7.6).
        let mut due_mask = ModuleMask::new();
        let mut min_due_us = u32::MAX;
        for idx in periodic_mask.iter_set() {
            let nd = sched.module_next_due_us[idx];
            if nd == 0 || now >= nd {
                due_mask.set(idx);
            } else {
                min_due_us = min_due_us.min(nd.saturating_sub(now).min(tmax as u64) as u32);
            }
        }
        let any_due = !due_mask.is_empty();

        // §6.5 runnable predicate. The SYSTEM graph (slot 0) is NEVER skipped (it
        // owns polled device I/O + telemetry — "platform maintenance work assigned
        // to that graph"). `any_due` is the per-module periodic schedule; `wake` a
        // targeted event; `must_tick` the fail-closed init/fault-recovery term;
        // `backstop_due` the fail-closed liveness for a NON-idle-safe workload
        // (never parked, only relaxed to `tick_max`). Idle-skip is gated on
        // mechanism (a) via `idle_skip`, so cadence-only/thermal domains never
        // skip. A graph is fully parkable only when it is idle_safe-attested.
        let prior_runnable = graph_pacer_instance_runnable(slot, generation, domain as u8);
        let must_tick = mask.intersects(&must_tick_mask);
        let backstop_due = !is_system && !idle_safe && (snap_backstop == 0 || now >= snap_backstop);
        let base_runnable = is_system
            || !idle_skip
            || !primed
            || prior_runnable
            || wake
            || timer_due
            || any_due
            || must_tick
            || backstop_due;
        // Readable-channel term (RFC idle_skip_wake §4): an otherwise-idle
        // graph with readable bytes on a cross-graph inbound edge is
        // runnable NOW — not at its
        // backstop. Evaluated last so the edge scan runs only for graphs
        // every cheaper term already declared idle. The consumers found
        // join the woken set below, stepping with `event_wake = true` so a
        // period-gated consumer cannot leave the data sitting (which would
        // re-fire this term every pass). In the normal case this fires once
        // per arrival episode: the consuming step reports work to the
        // pacer, so `prior_runnable` short-circuits the scan afterwards.
        let mut inbound_mask = ModuleMask::new();
        let inbound_ready =
            !base_runnable && graph_inbound_readable(sched, &mask, &mut inbound_mask);
        if inbound_ready {
            // Once per arrival episode in the consuming case (see above);
            // a repeat indicates a consumer sitting on readable data —
            // visibility wanted, but debug-level so a wedged consumer
            // can't flood the log ring at pass rate.
            log::debug!("MON_GRAPH_INBOUND slot={slot} gen={generation} domain={domain}");
        }
        let runnable = base_runnable || inbound_ready;

        // Fire ONLY the individually-due periodic modules (plus genuine wakes
        // and inbound-data consumers); `step_graph_owner` suppresses every
        // other periodic module so the per-pass tick counter can't fire one
        // early.
        let mut eff_woken = woken;
        eff_woken.or_assign(&due_mask);
        eff_woken.or_assign(&inbound_mask);

        let mut eff_backstop = snap_backstop;
        let (work, burst) = if runnable {
            let r = step_graph_owner(
                modules,
                sched,
                slot,
                generation,
                domain,
                &not_ready,
                &mut active_count,
                &mut overrun_logged_this_pass,
                &eff_woken,
                &periodic_mask,
            );
            // SAFETY: scheduler-thread-exclusive write of a bounded entry.
            let table = unsafe { &mut *core::ptr::addr_of_mut!(RESIDENT_GRAPHS) };
            table[gi].primed = true;
            // Advance each fired module's OWN absolute schedule by its OWN period
            // (`step_period × nominal tick`). Bounded catch-up, then resync if it
            // fell many periods behind (avoid a catch-up storm after a long stall).
            for idx in due_mask.iter_set() {
                let period = (sched.step_period[idx] as u64)
                    .saturating_mul(nominal as u64)
                    .max(1);
                let prev = sched.module_next_due_us[idx];
                let mut nd = if prev == 0 { now } else { prev };
                let mut guard = 0u32;
                loop {
                    nd = nd.wrapping_add(period);
                    guard += 1;
                    if nd > now || guard >= 64 {
                        break;
                    }
                }
                if nd <= now {
                    nd = now.wrapping_add(period);
                }
                sched.module_next_due_us[idx] = nd;
                min_due_us = min_due_us.min(nd.saturating_sub(now).min(tmax as u64) as u32);
            }
            // Re-arm the non-idle-safe backstop one `tmax` out.
            if !is_system && !idle_safe {
                eff_backstop = now.wrapping_add(tmax as u64);
                table[gi].backstop_next_due_us = eff_backstop;
            }
            r
        } else {
            (false, false)
        };

        // Feed the §7 pacer instance: this drives both next-tick runnability and
        // the deadline-merge below.
        graph_pacer_set_signals(slot, generation, domain as u8, work, burst, wake, timer_due);

        // §12 observability: transition-only `MON_GRAPH_PACER` so a per-graph
        // idle↔busy change is visible (per-pass logging would defeat the
        // efficiency gain). `busy` here is the post-step pacer signal.
        let busy = work || burst || wake || timer_due;
        if busy != primed_was_runnable(gi) {
            // SAFETY: DBG_TICK aligned u32 read.
            let tick = unsafe { DBG_TICK };
            log::info!(
                "MON_GRAPH_PACER slot={slot} gen={generation} domain={domain} \
                 state={} stepped={} tick={tick}",
                if busy { "busy" } else { "idle" },
                runnable as u8
            );
            set_last_runnable(gi, busy);
        }

        // §7.2 merge, inline: an idle instance still bounds the wait via its
        // relaxed deadline if nothing is runnable, but only runnable instances
        // tighten it.
        let d = graph_pacer_deadline(slot, generation, domain as u8, tmin, tmax, floor, now);
        min_backstop = min_backstop.min(d);
        if busy {
            any_runnable = true;
            min_runnable = min_runnable.min(d);
        }
        // A periodic module tightens the runner's wake to ITS OWN soonest next-due
        // (clamped to `tmax`). This decouples cadence from sibling load: an idle
        // sibling can't relax past the due time, and a busy sibling waking early
        // won't STEP the module until due — it fires on its absolute schedule.
        if min_due_us != u32::MAX {
            any_runnable = true;
            min_runnable = min_runnable.min(min_due_us);
        }
        // A must-tick graph (init / fault recovery) keeps the runner on the
        // nominal cadence until it clears, so progress isn't stalled at `tmax`.
        if must_tick {
            any_runnable = true;
            min_runnable = min_runnable.min(nominal);
        }
        // A non-idle-safe workload runs at least every `tmax` (fail-closed).
        if !is_system && !idle_safe {
            any_runnable = true;
            min_runnable =
                min_runnable.min(eff_backstop.saturating_sub(now).min(tmax as u64) as u32);
        }
    }

    // Output-only flush — domain-global, once after all resident graphs.
    step_domain_post_tick_flush(modules, sched, domain, &mut active_count);

    // ISR-bridge drain — domain-global, once per tick.
    pump_isr_bridges();

    let result = if active_count == 0 {
        StepResult::Done
    } else {
        StepResult::Continue
    };
    if !adaptive {
        // Fixed-tick multi-graph: isolation by per-owner stepping, no idle-skip.
        return (result, domain_tick_us(domain));
    }
    let deadline = if any_runnable {
        min_runnable
    } else if min_backstop == u32::MAX {
        domain_tick_us(domain)
    } else {
        min_backstop
    };
    (result, deadline)
}

/// Last logged runnable state for resident-graph entry `gi` (for the
/// transition-only `MON_GRAPH_PACER` line).
#[cfg(feature = "multitenant")]
fn primed_was_runnable(gi: usize) -> bool {
    // SAFETY: scheduler-thread read of a bounded entry.
    let table = unsafe { &*core::ptr::addr_of!(RESIDENT_GRAPHS) };
    table[gi].last_runnable
}

/// Record the last logged runnable state for resident-graph entry `gi`.
#[cfg(feature = "multitenant")]
fn set_last_runnable(gi: usize, v: bool) {
    // SAFETY: scheduler-thread-exclusive write of a bounded entry.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(RESIDENT_GRAPHS) };
    table[gi].last_runnable = v;
}

/// Read a §7 pacer instance's stored §6.5 runnability without mutating it (the
/// merge/deadline path re-reads it; this is the pre-step "did the prior pass
/// leave it runnable?" query).
#[cfg(feature = "multitenant")]
fn graph_pacer_instance_runnable(graph_slot: u16, generation: u32, domain: u8) -> bool {
    let Some(idx) = graph_pacer_index(graph_slot, generation, domain) else {
        return true; // fail-closed: no instance yet ⇒ run it
    };
    let gp = &raw const GRAPH_PACERS;
    // SAFETY: scheduler-thread-exclusive read; idx in bounds.
    let p = unsafe { &(*gp)[idx] };
    graph_pacer_runnable(p)
}

/// Multi-graph entry point for a FLAT single-domain cooperative runner (Linux /
/// wasm): step all resident graphs in domain 0 and return the next pacing
/// deadline (µs). Single-graph fast path (`resident_graph_count() <= 1`) is the
/// existing `step_modules` + `pacer_next_deadline_us(0)` — byte-identical to
/// today. On non-multitenant builds always the fast path.
pub fn step_resident_graphs_flat(
    modules: &mut [ModuleSlot; MAX_MODULES],
    count: usize,
) -> (StepResult, u32) {
    #[cfg(feature = "multitenant")]
    {
        if resident_graph_count() > 1 {
            return multi_graph_runner(modules, 0);
        }
    }
    let result = step_modules(modules, count);
    (result, pacer_next_deadline_us(0))
}

/// Multi-graph entry point for a PER-DOMAIN cooperative runner (BCM2712 core
/// loops): step all resident graphs that live in `domain` and return that
/// domain's next pacing deadline (µs). Single-graph-in-domain fast path is the
/// existing `step_domain_modules(domain)` + `pacer_next_deadline_us(domain)`.
pub fn step_resident_graphs_domain(
    modules: &mut [ModuleSlot; MAX_MODULES],
    domain: usize,
) -> (StepResult, u32) {
    #[cfg(feature = "multitenant")]
    {
        // A domain whose ONLY resident graph belongs to a paused owner must
        // also take the runner path: the fast path below is pause-blind and
        // would keep stepping the paused modules. Default-off — with no owner
        // paused the second term is never evaluated and the predicate reduces
        // to the `> 1` rule.
        if resident_graph_count_in_domain(domain) > 1
            || (crate::kernel::ipc::event::paused_owners_present()
                && domain_has_paused_graph(domain))
        {
            return multi_graph_runner(modules, domain);
        }
    }
    let result = step_domain_modules(modules, domain);
    // Event-wake drain for the single-graph domain path. Every consumer
    // of latched wake bits must sit on some drain: the rp/linux platform
    // loops drain `EVENT_WAKE_PENDING` around their sleeps, the >1-graph
    // runner consumes wakes via `take_wake_in_mask`, and this path (the
    // bcm2712 per-domain loop with one resident graph) drains here —
    // otherwise a latched software wake (`event_signal`, wake-on-write)
    // never reaches a period-gated module and the module waits out its
    // full period with the bit stranded. Domain-scoped take so one
    // domain's drain can't consume a sibling domain's wakes;
    // `step_woken_modules` applies the woken-path budget bound
    // (RFC idle_skip_wake §5). The WFI-latency caveat is unchanged: a
    // software wake is serviced on the next timer pass (§5.4 clamp), not
    // mid-sleep — this drain is what performs that service.
    {
        // SAFETY: scheduler-thread context — sole stepper for this domain.
        let sched = unsafe { &*core::ptr::addr_of!(SCHED) };
        let count = sched.active_module_count;
        let mut dmask = ModuleMask::new();
        for i in 0..count {
            if !sched.finished[i] && (sched.domain_id[i] as usize) == domain {
                dmask.set(i);
            }
        }
        let woken = crate::kernel::ipc::event::take_wake_in_mask(&dmask);
        if !woken.is_empty() {
            step_woken_modules(modules, count, &woken);
        }
    }
    (result, pacer_next_deadline_us(domain))
}

/// Domain execution-mode wire byte values.
///
/// These bytes appear in the config blob's domain-metadata section
/// (`tools/src/config.rs` writes them via `parse_domain_tier_to_exec_mode`)
/// and are read back by `prepare_graph` into `SCHED.domain_exec_mode`.
/// **Values are wire-stable** — older `.cfg.bin` blobs read by newer
/// kernels (and vice versa) must agree on the byte-to-tier mapping.
/// The mapping is asymmetric (Tier 1b → 2, Tier 2 → 4) because Tier
/// 1a/3 were allocated first; reshuffling would break already-built
/// configs. See `.context/rfc_isr_tier_surface.md` §D5.
pub mod exec_mode {
    /// Tier 0 — cooperative, main scheduler loop.
    pub const COOPERATIVE: u8 = 0;
    /// Tier 1a — high-rate periodic cooperative (sub-ms tick).
    pub const TIER_1A: u8 = 1;
    /// Tier 1b — shared timer-ISR. ISR-tier (requires `isr_safe` + bridge).
    pub const TIER_1B: u8 = 2;
    /// Tier 3 — poll-mode, continuous stepping with WFE on idle.
    pub const TIER_3: u8 = 3;
    /// Tier 2 — IRQ-owned. ISR-tier (requires `isr_safe` + bridge).
    pub const TIER_2: u8 = 4;
    /// Tier 1c — pre-pass cooperative drain. Per-module flag, *not* a
    /// per-domain exec_mode: a Tier 1c module sits inside a Tier 0
    /// or Tier 1a domain and runs at the start of every scheduler
    /// pass before any `domain_exec_order` modules. The byte value
    /// here is reserved for telemetry/logging only — the kernel reads
    /// the bit per-module from `ModuleEntry::pre_tick_drain`, not from
    /// the domain's exec_mode. See `.context/rfc_isr_tier_surface.md`
    /// §D8.
    pub const TIER_1C: u8 = 5;
}

/// Return the execution mode for a domain. See [`exec_mode`] for the
/// stable byte→tier mapping.
pub fn domain_exec_mode(domain_id: usize) -> u8 {
    if domain_id < MAX_DOMAINS {
        // SAFETY: scheduler-thread-only read; domain_id bounded.
        unsafe { SCHED.domain_exec_mode[domain_id] }
    } else {
        0
    }
}

/// `true` if `exec_mode` denotes an ISR-tier domain (Tier 1b or
/// Tier 2). Cooperative tiers (0, 1a, 3) do not require bridge-only
/// channels or the `isr_safe` attestation. The byte values come from
/// [`exec_mode`]; checked here against the named constants so a
/// future reshuffle has to update both sides together.
#[inline]
pub fn is_isr_tier_exec_mode(mode: u8) -> bool {
    mode == exec_mode::TIER_1B || mode == exec_mode::TIER_2
}

/// `true` if `module_idx`'s assigned domain is an ISR-tier
/// (Tier 1b or Tier 2) domain. The cooperative scheduler skips
/// stepping ISR-tier modules because they run from a timer/IRQ
/// handler, not from `step_modules`. See
/// `.context/rfc_isr_tier_surface.md` §D6.
#[inline]
pub fn module_is_isr_tier(module_idx: usize) -> bool {
    if module_idx >= MAX_MODULES {
        return false;
    }
    // SAFETY: scheduler-thread-only read; module_idx bounded.
    let d = unsafe { SCHED.domain_id[module_idx] } as usize;
    if d >= MAX_DOMAINS {
        return false;
    }
    // SAFETY: as above; d bounded by the check just above.
    let m = unsafe { SCHED.domain_exec_mode[d] };
    is_isr_tier_exec_mode(m)
}

/// Reject syscall `op` when the calling module sits in an ISR-tier
/// (Tier 1b or Tier 2) domain. Emits a single `MON_PERM_DENIED` log
/// line per rejection and returns `true` so the caller can bail with
/// the standard `errno::EACCES`. Cooperative callers (Tier 0/1a/1c)
/// and out-of-bounds `module_idx` return `false`.
///
/// The runtime gate is defense in depth — the build-time validator
/// (`tools/src/config.rs::validate_isr_tier_admission`) already
/// rejects malformed graphs; this catches hand-rolled binaries that
/// bypass the tools pipeline. See
/// `.context/rfc_isr_tier_surface.md` §D6.
#[inline]
pub fn deny_isr_tier_syscall(op: &'static str) -> bool {
    let module_idx = current_module_index();
    if module_idx >= MAX_MODULES {
        return false;
    }
    if !module_is_isr_tier(module_idx) {
        return false;
    }
    // SAFETY: scheduler-thread read; module_idx already bounded.
    let domain = unsafe { SCHED.domain_id[module_idx] };
    log::warn!(
        "MON_PERM_DENIED domain={domain} mod={module_idx} op={op} tick={tick}",
        // SAFETY: DBG_TICK is an aligned u32 read.
        tick = unsafe { DBG_TICK },
    );
    true
}

/// Test-facing setter — assigns `domain` to module `module_idx`.
/// Production paths route the assignment through `prepare_graph`,
/// which reads it off the config blob; this helper exists so
/// scheduler-conformance tests can plant a module's domain without
/// going through a full graph build.
pub fn set_module_domain(module_idx: usize, domain: u8) {
    if module_idx >= MAX_MODULES {
        return;
    }
    // SAFETY: scheduler-thread mutation; module_idx bounded.
    unsafe {
        SCHED.domain_id[module_idx] = domain;
    }
}

/// Test-facing setter — assigns `exec_mode` to `domain_id`. Used by
/// conformance tests that exercise the cooperative-skip behaviour
/// without going through a full `prepare_graph` cycle. Production
/// callers should source `exec_mode` from `prepare_graph` reading
/// the config blob.
pub fn set_domain_exec_mode(domain_id: usize, exec_mode: u8) {
    if domain_id >= MAX_DOMAINS {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; domain_id bounded.
    unsafe {
        SCHED.domain_exec_mode[domain_id] = exec_mode;
    }
}

/// Return the number of configured domains.
pub fn domain_count() -> usize {
    // SAFETY: scheduler-thread-only read.
    let c = unsafe { SCHED.domain_count } as usize;
    if c == 0 {
        1
    } else {
        c
    }
}

/// Return the module count for a specific domain.
pub fn domain_module_count(domain_id: usize) -> usize {
    if domain_id < MAX_DOMAINS {
        // SAFETY: scheduler-thread-only read; domain_id bounded.
        unsafe { SCHED.domain_module_count[domain_id] as usize }
    } else {
        0
    }
}

/// Return the global module index at position `i` in `domain_id`'s
/// topologically-sorted execution order, or `None` if out of range.
/// Per-core pump loops walk this to drive every module — user modules
/// and any `_tee` / `_merge` — that lives in their domain.
pub fn domain_exec_order_at(domain_id: usize, i: usize) -> Option<usize> {
    if domain_id >= MAX_DOMAINS {
        return None;
    }
    // SAFETY: domain_id bounded above.
    let count = unsafe { SCHED.domain_module_count[domain_id] as usize };
    if i >= count {
        return None;
    }
    // SAFETY: `i < count <= MAX_MODULES`; domain_id bounded.
    Some(unsafe { SCHED.domain_exec_order[domain_id][i] as usize })
}

/// Return the domain id assigned to a module, or `0` (the default
/// domain) for out-of-range indices.
pub fn module_domain_id(module_idx: usize) -> u8 {
    if module_idx >= MAX_MODULES {
        return 0;
    }
    // SAFETY: module_idx bounded above.
    unsafe { SCHED.domain_id[module_idx] }
}

/// Report a module's processing latency in frames.
/// Called by modules during init via the REPORT_LATENCY kernel primitive.
pub fn report_module_latency(module_idx: usize, frames: u32) {
    if module_idx < MAX_MODULES {
        // SAFETY: scheduler-thread-only mutation; idx bounded.
        unsafe {
            SCHED.module_latency[module_idx] = frames;
        }
    }
}

/// Get the downstream latency for a module (computed after all modules init).
pub fn downstream_latency(module_idx: usize) -> u32 {
    if module_idx < MAX_MODULES {
        // SAFETY: module_idx bounded above.
        unsafe { SCHED.downstream_latency[module_idx] }
    } else {
        0
    }
}

/// Bucket index for a step elapsed time in microseconds.
/// 0: <2, 1: <4, 2: <8, 3: <16, 4: <32, 5: <64, 6: <256, 7: >=256
///
/// The ladder is deliberately weighted BELOW the tick budget. Edges that
/// start at `<64` and double to `>=4096` put every step of a healthy
/// `tick_us: 100` graph into `b0` — a histogram that cannot separate a 1 µs
/// module from a 50 µs one, and from which no per-module share of the tick
/// budget can be computed at all.
///
/// The tail such edges would resolve is already reported exactly, and per
/// module, by `MON_HEAVY_STEP` (`elapsed_us` verbatim) and in aggregate by
/// `MON_BUDGET_OVERRUN` (`consumed_us` vs `limit_us`). Spending resolution
/// there costs the only range where attribution is still possible. `b6`/`b7`
/// keep enough of the top end to spot a heavy module without reading the
/// fault stream.
#[inline]
fn step_bucket(elapsed_us: u32) -> usize {
    if elapsed_us < 2 {
        0
    } else if elapsed_us < 4 {
        1
    } else if elapsed_us < 8 {
        2
    } else if elapsed_us < 16 {
        3
    } else if elapsed_us < 32 {
        4
    } else if elapsed_us < 64 {
        5
    } else if elapsed_us < 256 {
        6
    } else {
        7
    }
}

/// Record a step's elapsed time into per-module and global histograms.
pub fn record_step_time(module_idx: usize, elapsed_us: u32) {
    if module_idx >= MAX_MODULES {
        return;
    }
    let b = step_bucket(elapsed_us);
    // SAFETY: scheduler-thread-only mutation; module_idx bounded above.
    unsafe {
        SCHED.step_hist[module_idx][b] = SCHED.step_hist[module_idx][b].saturating_add(1);
        SCHED.step_hist_global[b] = SCHED.step_hist_global[b].saturating_add(1);
    }
}

/// Query step histogram. `module_idx == usize::MAX` returns the global
/// histogram; otherwise a per-module histogram. Writes 8 u32 LE to `out_buf`.
///
/// # Safety
/// `out_buf` must be valid for writes of at least 32 bytes
/// (8 × u32 LE). The function does not read from `out_buf`. Aliasing
/// is fine since each call writes a fixed-size, fixed-offset record.
pub unsafe fn query_step_histogram(module_idx: usize, out_buf: *mut u8) -> i32 {
    let hist_ptr: *const [u32; 8] = if module_idx == usize::MAX {
        &raw const SCHED.step_hist_global
    } else if module_idx < MAX_MODULES {
        // SAFETY: module_idx < MAX_MODULES bounds the offset; `step_hist`
        // is `[[u32; 8]; MAX_MODULES]` so the cast + `add` is in-bounds.
        unsafe {
            (&raw const SCHED.step_hist)
                .cast::<[u32; 8]>()
                .add(module_idx)
        }
    } else {
        return crate::kernel::sys::errno::EINVAL;
    };
    for i in 0..8 {
        // SAFETY: hist_ptr is one of the two valid pointers selected above.
        let v = unsafe { (*hist_ptr)[i] };
        let bytes = v.to_le_bytes();
        // SAFETY: caller's `# Safety` contract: `out_buf` covers 32 bytes;
        // i*4 ranges in 0..28 → +4 reads stay in-bounds.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf.add(i * 4), 4);
        }
    }
    0
}

/// Get fault statistics for a module (for `provider_query` FAULT_STATS).
pub fn get_fault_stats(module_idx: usize) -> FaultStats {
    if module_idx >= MAX_MODULES {
        return FaultStats::default();
    }
    // SAFETY: scheduler-thread-only read; module_idx bounded above.
    unsafe {
        let tick = DBG_TICK;
        SCHED.fault_info[module_idx].to_stats(tick)
    }
}

/// Get mutable fault info for a module (for config-time setup).
pub fn set_module_fault_policy(
    module_idx: usize,
    policy: FaultPolicy,
    max_restarts: u16,
    backoff_ms: u16,
) {
    if module_idx >= MAX_MODULES {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; module_idx bounded.
    unsafe {
        let fi = &mut SCHED.fault_info[module_idx];
        fi.policy = policy;
        fi.max_restarts = max_restarts;
        fi.restart_backoff_ms = backoff_ms;
    }
}

/// Set per-module step deadline (from config).
pub fn set_module_step_deadline(module_idx: usize, deadline_us: u32) {
    if module_idx >= MAX_MODULES {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; module_idx bounded.
    unsafe {
        SCHED.fault_info[module_idx].step_deadline_us = deadline_us;
    }
}

/// Set the per-module burst-deadline override in microseconds.
/// `0` disables the override and falls back to the implicit
/// `step_deadline_us * BURST_MULTIPLIER` ceiling used by
/// `step_one_module`. Sourced from the module manifest's
/// `step_deadline_burst_us` setting.
pub fn set_module_step_deadline_burst(module_idx: usize, deadline_us: u32) {
    if module_idx >= MAX_MODULES {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; module_idx bounded.
    unsafe {
        SCHED.fault_info[module_idx].step_deadline_burst_us = deadline_us;
    }
}

/// Declare a quarantine partner for `module_idx`. When this module
/// faults AND the partner has faulted within `QUARANTINE_WINDOW_MS`,
/// both transition to `Terminated`. Pass `0xFF` to clear the pairing.
/// Sourced from the module manifest's `quarantine_partner` setting;
/// the kernel does not infer pairings from channel wiring.
pub fn set_module_quarantine_partner(module_idx: usize, partner: u8) {
    if module_idx >= MAX_MODULES {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; module_idx bounded.
    unsafe {
        SCHED.fault_info[module_idx].quarantine_partner = partner;
    }
}

/// Set the module's step-period phase offset. The phase is applied
/// to the step counter as `step_counter[idx] = phase %
/// step_period[idx]`, so the module's first eligible tick happens at
/// `period - phase` ticks rather than `period`. Lets graph authors
/// stagger coarse-period modules so they don't all fire on the same
/// tick (convoy mitigation). Mirrors what `instantiate_one_module`
/// does from the manifest's `ModuleHeader::step_phase()` byte.
pub fn set_module_step_phase(module_idx: usize, phase: u8) {
    if module_idx >= MAX_MODULES {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; module_idx bounded.
    unsafe {
        let period = SCHED.step_period[module_idx];
        SCHED.step_counter[module_idx] = if period > 0 { phase % period } else { 0 };
    }
}

/// Set per-module step period (every N ticks). `0` = step every tick.
/// Used by the loader's manifest-driven setup and by conformance tests
/// that exercise the period-gating path in `step_one_module`.
pub fn set_module_step_period(module_idx: usize, period: u8) {
    if module_idx >= MAX_MODULES {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; module_idx bounded.
    unsafe {
        SCHED.step_period[module_idx] = period;
        // Resetting the counter keeps period semantics predictable: the
        // next tick is the first measured tick of the new period.
        SCHED.step_counter[module_idx] = 0;
    }
}

/// Read the current fault state of a module. Test-facing query so
/// scheduler conformance tests can assert fault transitions without
/// reaching into `SCHED` directly.
pub fn module_fault_state(module_idx: usize) -> FaultState {
    if module_idx >= MAX_MODULES {
        return FaultState::Running;
    }
    // SAFETY: scheduler-thread-only read; module_idx bounded.
    unsafe { SCHED.fault_info[module_idx].state }
}

/// Read `finished[module_idx]`. Test-facing query for terminate /
/// done assertions.
pub fn module_finished(module_idx: usize) -> bool {
    if module_idx >= MAX_MODULES {
        return false;
    }
    // SAFETY: scheduler-thread-only read; module_idx bounded.
    unsafe { SCHED.finished[module_idx] }
}

/// Mark a module as "deferred-ready". Deferred-ready modules step
/// freely even when their upstream peers haven't signaled `Ready` yet
/// — they need to run to reach Ready themselves (typical for
/// infrastructure like `linux_net` that sets `Ready` only after the
/// network is up).
pub fn set_module_deferred_ready(module_idx: usize, deferred: bool) {
    if module_idx >= MAX_MODULES {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; module_idx bounded.
    unsafe {
        SCHED.deferred_ready[module_idx] = deferred;
    }
}

/// Set the upstream-readiness mask for a module. Each bit i in `mask`
/// means "this module depends on module i being Ready before it can
/// step". Used by loader manifest plumbing and by conformance tests
/// that exercise ready-signal gating without a real graph.
pub fn set_module_upstream_mask(module_idx: usize, mask: u64) {
    if module_idx >= MAX_MODULES {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; module_idx bounded.
    // Loader manifest plumbing and conformance tests pass a u64 (≤64 modules);
    // the full-width path is built by `compute_upstream_mask`.
    unsafe {
        SCHED.upstream_mask[module_idx] = ModuleMask::from_u64(mask);
    }
}

/// Full-width variant of [`set_module_upstream_mask`]: set individual
/// upstream bits, including indices ≥ 64. Test-facing (like
/// `clear_module_ready`) — production masks come from
/// `compute_upstream_mask`.
pub fn set_module_upstream_bits(module_idx: usize, bits: &[usize]) {
    if module_idx >= MAX_MODULES {
        return;
    }
    let mut mask = ModuleMask::new();
    for &b in bits {
        if b < MAX_MODULES {
            mask.set(b);
        }
    }
    // SAFETY: scheduler-thread-only mutation; module_idx bounded.
    unsafe {
        SCHED.upstream_mask[module_idx] = mask;
    }
}

/// Clear the per-module ready bit. Test-facing helper so a fresh
/// graph can be wired into a state where downstream modules are
/// gated waiting on a not-yet-Ready upstream.
pub fn clear_module_ready(module_idx: usize) {
    if module_idx >= MAX_MODULES {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; module_idx bounded.
    unsafe {
        SCHED.ready[module_idx] = false;
    }
}

/// Read the per-module ready bit.
pub fn module_is_ready(module_idx: usize) -> bool {
    if module_idx >= MAX_MODULES {
        return false;
    }
    // SAFETY: scheduler-thread-only read; module_idx bounded.
    unsafe { SCHED.ready[module_idx] }
}

/// Snapshot of a single module's scheduler-visible state. Used by
/// diagnostics
/// and by operator-facing introspection.
#[derive(Debug, Clone, Copy)]
pub struct ModuleStateSnapshot {
    /// Module slot index in the scheduler's `modules` array.
    pub idx: u8,
    /// `true` if the module's slot is non-empty in the scheduler.
    pub present: bool,
    /// Whether the module has signaled `StepOutcome::Ready`.
    pub ready: bool,
    /// Whether the module has finalised (`Done` / terminated).
    pub finished: bool,
    /// Capability tier (Driver/Service/Protocol — see scheduler docs).
    pub cap_class: u8,
    /// Permission bitmap (per `syscalls::permission` bits).
    pub permissions: u16,
    /// Per-module fault state machine state.
    pub fault_state: FaultState,
    /// Step-period gate in scheduler ticks (0 = every tick, N = every
    /// N ticks). Wall-clock period is `step_period * domain_tick_us`.
    pub step_period: u8,
    /// Restart count to date.
    pub restart_count: u16,
    /// Domain the module is assigned to (0 = default).
    pub domain_id: u8,
    /// Consecutive ticks the readiness gate has been blocking this
    /// module from stepping. `0` after every successful step; non-zero
    /// indicates a dead upstream edge.
    pub inactive_for_ticks: u32,
    /// Per-slot generation. Bumped on graph reset, restart, and
    /// module replacement. Async consumers that snapshot telemetry
    /// must pair this with a later read of the same module — a
    /// mismatch means the slot was reused and the prior snapshot is
    /// stale.
    pub slot_generation: u32,
}

/// Build a `ModuleStateSnapshot` for `module_idx`. Returns a
/// `present: false` placeholder if the slot is empty or out of range
/// so callers can iterate `0..MAX_MODULES` uniformly.
pub fn module_state_snapshot(module_idx: usize) -> ModuleStateSnapshot {
    if module_idx >= MAX_MODULES {
        return ModuleStateSnapshot {
            idx: 0,
            present: false,
            ready: false,
            finished: false,
            cap_class: 0,
            permissions: 0,
            fault_state: FaultState::Running,
            step_period: 0,
            restart_count: 0,
            domain_id: 0,
            inactive_for_ticks: 0,
            slot_generation: 0,
        };
    }
    // SAFETY: scheduler-thread-only read; module_idx bounded above.
    let sched = unsafe {
        let p = &raw const SCHED;
        &*p
    };
    let present = !matches!(sched.modules[module_idx], ModuleSlot::Empty);
    ModuleStateSnapshot {
        idx: module_idx as u8,
        present,
        ready: sched.ready[module_idx],
        finished: sched.finished[module_idx],
        cap_class: sched.cap_class[module_idx],
        permissions: sched.permissions[module_idx],
        fault_state: sched.fault_info[module_idx].state,
        step_period: sched.step_period[module_idx],
        restart_count: sched.fault_info[module_idx].restart_count,
        domain_id: sched.domain_id[module_idx],
        inactive_for_ticks: sched.inactive_for_ticks[module_idx],
        slot_generation: sched.slot_generation[module_idx],
    }
}

/// Lookup a channel port for the currently-executing module.
/// Called from the channel_port syscall implementation.
pub fn channel_port_lookup(port_type: u8, index: u8) -> i32 {
    let idx = index as usize;
    let cm = current_module_index();
    // Guard the "no module" sentinel (== MAX_MODULES): a live-added module can reach
    // a port lookup before CURRENT_MODULE_PER_CORE is set to its slot. Return -1
    // (port not resolvable yet) rather than index a fixed [_; MAX_MODULES] array OOB.
    if cm >= MAX_MODULES {
        return -1;
    }
    // SAFETY: cm bounded above; scheduler-thread-only read.
    let ports = unsafe { &SCHED.ports[cm] };
    match port_type {
        0 => {
            if idx < ports.in_count as usize {
                ports.in_chans[idx]
            } else {
                -1
            }
        }
        1 => {
            if idx < ports.out_count as usize {
                ports.out_chans[idx]
            } else {
                -1
            }
        }
        2 => {
            if idx < ports.ctrl_count as usize {
                ports.ctrl_chans[idx]
            } else {
                -1
            }
        }
        _ => -1,
    }
}

/// Syscall: get the calling module's arena allocation.
/// Returns null if no arena was allocated.
///
/// # Safety
/// `size_out` must either be null or a valid `*mut u32`. The returned
/// `*mut u8` (if non-null) points at the calling module's arena
/// region; lifetime is bounded by the module's existence in the
/// scheduler. Cross-module aliasing is prevented by the per-module
/// arena layout, but the caller must not retain the pointer past
/// module teardown.
pub unsafe extern "C" fn syscall_arena_get(size_out: *mut u32) -> *mut u8 {
    let cm = current_module_index();
    let arena = &SCHED.arenas[cm];
    if !size_out.is_null() {
        *size_out = arena.size;
    }
    arena.ptr
}
