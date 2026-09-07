//! Scheduler responsibility module (real module boundary; parent statics and
//! helpers reach us via `super`). Execution-order + domain-order computation and domain validation.
#![allow(
    unused_imports,
    reason = "the flat scheduler namespace is glob-imported; each module uses a subset"
)]
use super::*;

/// Precompute upstream dependency bitmask for ready-signal gating.
///
/// For each module, `upstream_mask[i]` has one bit set per module that feeds
/// `i` over a **forward** edge — an edge whose source precedes its destination
/// in the topological execution order (`exec_order`). Used with `ready[]` to
/// skip a module while any of its forward upstreams has not yet signaled
/// `StepOutcome::Ready`.
///
/// **Back-edges are excluded.** A back-edge is a cycle-closing edge that only
/// exists when the graph declares `scheduler: accept_cycles: true`; under the
/// topological sort, a cycle's members are ordered linearly and the edge that
/// runs "backward" (a later member → an earlier one) is the back-edge. Counting
/// such an edge toward `upstream_mask` would make a feedback cycle's members
/// each wait on the other's `Ready` forever — a mutual deadlock that leaves the
/// whole feedback cycle dark. Excluding back-edges lets cycle members step from
/// the first tick and converge to `Ready`.
///
/// MUST be called after `compute_exec_order` (which appends cycle members under
/// `accept_cycles`) so the position map reflects the final ordering.
pub(crate) fn compute_upstream_mask(edges: &[Edge], edge_count: usize) {
    // SAFETY: scheduler-thread (prepare_graph) context.
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };
    for slot in sched.upstream_mask.iter_mut() {
        *slot = ModuleMask::EMPTY;
    }
    for slot in sched.completion_mask.iter_mut() {
        *slot = ModuleMask::EMPTY;
    }

    // Build a module→position map from the topological execution order.
    // `NO_POS` marks a module absent from exec_order; we can't prove an edge
    // touching it is forward, so we conservatively exclude that edge from the
    // gate rather than index out of range.
    const NO_POS: u16 = u16::MAX;
    let mut pos = [NO_POS; MAX_MODULES];
    for (order_pos, &m) in sched
        .exec_order
        .iter()
        .take(sched.exec_order_count)
        .enumerate()
    {
        let midx = m as usize;
        if midx < MAX_MODULES {
            pos[midx] = order_pos as u16;
        }
    }

    for edge in edges.iter().take(edge_count) {
        let from = edge.from_module;
        let to = edge.to_module;
        if from >= MAX_MODULES || to >= MAX_MODULES {
            continue;
        }
        // Completion tracks EVERY real edge — a sink downstream of a feedback
        // cycle must wait on producers reachable through a back-edge too.
        sched.completion_mask[to].set(from);
        let (pf, pt) = (pos[from], pos[to]);
        // Forward edge only: both endpoints ordered and source strictly
        // precedes destination. `pf >= pt` (including either unordered) is a
        // back-edge or unprovable — excluded so feedback cycles don't deadlock.
        if pf != NO_POS && pt != NO_POS && pf < pt {
            sched.upstream_mask[to].set(from);
        }
    }
}

/// After this, EXEC_ORDER contains module indices in dependency order:
/// sources first, sinks last. This ensures that within a single scheduler pass,
/// data flows through an entire chain (e.g. sequencer → synth → effects → i2s)
/// rather than propagating one hop per tick.
///
/// Modules with no incoming edges (sources and isolated modules) are picked
/// up by the BFS start; modules that remain unordered after BFS imply a
/// graph cycle.
///
/// **Cycle policy**:
/// v1 has no typed feedback-edge concept, so cycles are appended at the end
/// in index order AND a loud `log::error!` line is emitted so the cycle is
/// visible in operator output. The fail-load path is owned by
/// `prepare_graph` (which checks the returned `cycle_count`); silently
/// shipping the post-cycle order would propagate non-deterministic stepping
/// behaviour, and crashing the kernel on a valid-but-cyclic example graph
/// loses the diagnostic. Returns the number of modules that could NOT be
/// topologically ordered (0 = no cycles).
pub(crate) fn compute_exec_order(edges: &[Edge], edge_count: usize, module_count: usize) -> usize {
    // SAFETY: prepare_graph context — single mutator.
    let exec_order = unsafe {
        let p = &raw mut SCHED;
        &mut (*p).exec_order
    };

    // Compute in-degree for each module
    let mut in_degree = [0u8; MAX_MODULES];
    for e in edges.iter().take(edge_count) {
        if e.channel >= 0 && e.to_module < module_count {
            in_degree[e.to_module] = in_degree[e.to_module].saturating_add(1);
        }
    }

    // BFS queue: start with modules that have no incoming edges (sources)
    let mut queue = [0u8; MAX_MODULES];
    let mut qhead: usize = 0;
    let mut qtail: usize = 0;
    for (i, &deg) in in_degree.iter().take(module_count).enumerate() {
        if deg == 0 {
            queue[qtail] = i as u8;
            qtail += 1;
        }
    }

    let mut count = 0;
    while qhead < qtail {
        let m = queue[qhead] as usize;
        qhead += 1;
        exec_order[count] = m as u8;
        count += 1;

        // Decrement in-degree of all successors
        for e in edges.iter().take(edge_count) {
            if e.channel >= 0 && e.from_module == m && e.to_module < module_count {
                in_degree[e.to_module] -= 1;
                if in_degree[e.to_module] == 0 {
                    queue[qtail] = e.to_module as u8;
                    qtail += 1;
                }
            }
        }
    }

    // Cycle handling. Any module still unordered after BFS is in a cycle.
    // The non-zero return value is what `prepare_graph` decides on — it logs
    // the rejection as an error or the acceptance as a warning — so this
    // line is a trace of the ordering, not a second verdict. Isolated
    // modules never reach this branch — their `in_degree == 0` makes them
    // BFS roots.
    let cycle_count = module_count - count;
    if cycle_count > 0 {
        let mut first_unordered: i32 = -1;
        for i in 0..module_count {
            let mut found = false;
            for &m in exec_order.iter().take(count) {
                if m == i as u8 {
                    found = true;
                    break;
                }
            }
            if !found {
                if first_unordered < 0 {
                    first_unordered = i as i32;
                }
                exec_order[count] = i as u8;
                count += 1;
            }
        }
        log::debug!(
            "[scheduler] graph has {cycle_count} module(s) in a cycle (first unordered idx={first_unordered}); \
             v1 has no typed feedback edges — cycles are appended at the end in \
             declaration order, and `prepare_graph` decides whether to accept or \
             reject the resulting graph based on `graph_flags.ACCEPT_CYCLES`",
        );
    }

    // SAFETY: prepare_graph context — single mutator.
    unsafe {
        SCHED.exec_order_count = count;
    }
    cycle_count
}

/// Partition the global exec_order into per-domain execution orders (E4-S4).
///
/// Each domain gets its own ordered list of modules. On single-core, all domains
/// execute sequentially in the same tick (no behavior change). The data structures
/// are ready for Epic 6 multi-core where each domain maps to a core.
/// Accesses SCHED global directly to avoid borrow conflicts.
pub(crate) fn compute_domain_exec_orders_static(_module_count: usize) {
    // SAFETY: prepare_graph context — single mutator.
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };

    // Clear domain module counts (both the regular exec_order list and
    // the Tier 1c pre-tick list).
    for d in 0..MAX_DOMAINS {
        sched.domain_module_count[d] = 0;
        sched.domain_pre_tick_count[d] = 0;
    }

    // Walk exec_order (already topologically sorted) and partition by
    // domain. Modules flagged `pre_tick_drain` go into
    // `domain_pre_tick_order` instead of `domain_exec_order` so
    // `step_domain_modules` can drain them before the regular rotation.
    for order_pos in 0..sched.exec_order_count {
        let module_idx = sched.exec_order[order_pos] as usize;
        let domain = sched.domain_id[module_idx] as usize;
        let domain = if domain < MAX_DOMAINS { domain } else { 0 };

        if sched.pre_tick_drain[module_idx] {
            let pcount = sched.domain_pre_tick_count[domain] as usize;
            if pcount < MAX_PRE_TICK_PER_DOMAIN {
                sched.domain_pre_tick_order[domain][pcount] = module_idx as u8;
                sched.domain_pre_tick_count[domain] = (pcount + 1) as u8;
            } else {
                log::error!(
                    "[domain] {domain} dropping pre_tick_drain module {module_idx} \
                     — capacity {MAX_PRE_TICK_PER_DOMAIN} exceeded"
                );
            }
            continue;
        }

        let count = sched.domain_module_count[domain] as usize;
        if count < MAX_MODULES {
            sched.domain_exec_order[domain][count] = module_idx as u8;
            sched.domain_module_count[domain] = (count + 1) as u8;
        }
    }

    // Log domain composition (regular + pre-tick).
    let effective_domains = if sched.domain_count > 0 {
        sched.domain_count as usize
    } else {
        1
    };
    for d in 0..effective_domains {
        let count = sched.domain_module_count[d];
        let pcount = sched.domain_pre_tick_count[d];
        if count > 0 || pcount > 0 || d == 0 {
            let tick = if sched.domain_tick_us[d] > 0 {
                sched.domain_tick_us[d]
            } else {
                sched.tick_us
            };
            if pcount > 0 {
                log::info!("[domain] {d} modules={count} pre_tick={pcount} tick_us={tick}");
            } else {
                log::info!("[domain] {d} modules={count} tick_us={tick}");
            }
        }
    }
}

/// Targeted, incremental counterpart to [`compute_domain_exec_orders_static`] +
/// the `finalize_resident_graphs` mask loop: recompute the per-domain dispatch
/// tables (`domain_exec_order`, `domain_module_count`, `domain_pre_tick_order`,
/// `domain_pre_tick_count`, `domain_module_mask`) for ONLY the domains whose bit
/// is set in `affected_mask` (bit `d` ⇒ domain `d`), from the current flat
/// `exec_order`, and grow `domain_count` to cover any newly-occupied domain
/// (never shrink — matches `finalize_resident_graphs`).
///
/// This is the live-splice: `live::apply_add`/`free_owner` call it
/// — under a multicore peer quiesce on bcm2712 — so a *runtime*
/// CREATE/DESTROY's modules reach the per-domain runners that step
/// `domain_exec_order` (`step_domain_modules`, `step_domain_modules_poll`),
/// not only the flat `exec_order`. Boot-time domain wiring stays with
/// `finalize_resident_graphs`; this never calls it.
///
/// Byte-identical, per affected domain, to a full `finalize_resident_graphs`
/// recompute — the flat `exec_order` is the single source of truth both walk,
/// existing modules keep their relative order (a live add only appends to the
/// tail; a free compacts, preserving order), so a per-domain reprojection
/// reproduces exactly what the whole-graph walk would. Proven in the
/// `live_graph_mutation` harness (`domain_splice_matches_full_recompute`).
///
/// Safe to call ONLY single-threaded (boot / host) or with every peer domain
/// core parked (`multicore::request_quiesce` + `wait_parked`). Never on the hot
/// path — a bounded scan invoked once per CREATE/DESTROY.
#[cfg(feature = "multitenant")]
pub fn recompute_domain_orders(affected_mask: u32) {
    // SAFETY: scheduler-thread-exclusive; caller guarantees peers are quiesced
    // (or single-threaded boot/host) — same access class as
    // `compute_domain_exec_orders_static`.
    let sched = unsafe { &mut *core::ptr::addr_of_mut!(SCHED) };

    let is_affected = |d: usize| d < MAX_DOMAINS && (affected_mask & (1u32 << d)) != 0;

    // Clear the affected domains' regular + Tier-1c counts and wake masks.
    for d in 0..MAX_DOMAINS {
        if !is_affected(d) {
            continue;
        }
        sched.domain_module_count[d] = 0;
        sched.domain_pre_tick_count[d] = 0;
        sched.domain_module_mask[d] = ModuleMask::EMPTY;
    }

    // Rebuild the affected domains' wake masks over ALL resident modules —
    // mirrors the `finalize_resident_graphs` mask loop exactly, restricted to
    // the affected domains.
    for i in 0..MAX_MODULES {
        if matches!(sched.modules[i], ModuleSlot::Empty) {
            continue;
        }
        let d = (sched.domain_id[i] as usize).min(MAX_DOMAINS - 1);
        if is_affected(d) {
            sched.domain_module_mask[d].set(i);
        }
    }

    // Reproject the flat `exec_order` into the affected domains' execution /
    // pre-tick orders — mirrors `compute_domain_exec_orders_static`, restricted
    // to the affected domains.
    for order_pos in 0..sched.exec_order_count {
        let module_idx = sched.exec_order[order_pos] as usize;
        if module_idx >= MAX_MODULES {
            continue;
        }
        let domain = (sched.domain_id[module_idx] as usize).min(MAX_DOMAINS - 1);
        if !is_affected(domain) {
            continue;
        }
        if sched.pre_tick_drain[module_idx] {
            let pcount = sched.domain_pre_tick_count[domain] as usize;
            if pcount < MAX_PRE_TICK_PER_DOMAIN {
                sched.domain_pre_tick_order[domain][pcount] = module_idx as u8;
                sched.domain_pre_tick_count[domain] = (pcount + 1) as u8;
            }
        } else {
            let count = sched.domain_module_count[domain] as usize;
            if count < MAX_MODULES {
                sched.domain_exec_order[domain][count] = module_idx as u8;
                sched.domain_module_count[domain] = (count + 1) as u8;
            }
        }
    }

    // Grow `domain_count` to cover any newly-occupied domain (never shrink —
    // matches `finalize_resident_graphs`).
    let mut max_domain: u8 = 0;
    for i in 0..MAX_MODULES {
        if matches!(sched.modules[i], ModuleSlot::Empty) {
            continue;
        }
        let did = sched.domain_id[i];
        if did > max_domain {
            max_domain = did;
        }
    }
    let want_count = ((max_domain as usize + 1).min(MAX_DOMAINS)) as u8;
    if want_count > sched.domain_count {
        sched.domain_count = want_count;
    }
}

/// Validate domain configuration (E4-S5).
///
/// Accesses SCHED global directly to avoid borrow conflicts with edges.
/// Checks:
/// - Warn on empty domains
/// - Warn on modules without domain assignment when domains are configured
/// - Validate cross_core edges connect modules in different domains
///
/// Log every edge tagged `EdgeClass::DmaOwned` at graph-prepare time.
///
/// Pure observability: confirms that the YAML-level annotation reached the
/// scheduler edge table. The scheduler does not issue cache maintenance on
/// DmaOwned handoffs — that belongs with zero-copy mailbox edges, where the
/// payload buffer is actually shared
/// between producer and consumer. Streaming-arena buffers live inside
/// the module (see nvme `write_bufs[]`) and do their own DC CVAC via
/// the `DMA_FLUSH` syscall before device submission.
pub fn log_dma_owned_edges(edge_count: usize) {
    // SAFETY: scheduler-thread-only read.
    let sched = unsafe {
        let p = &raw const SCHED;
        &*p
    };
    let mut n = 0usize;
    for i in 0..edge_count {
        if i >= MAX_CHANNELS {
            break;
        }
        let e = &sched.edges[i];
        if let crate::kernel::boot::config::EdgeClass::DmaOwned = e.edge_class {
            log::info!(
                "[sched] DmaOwned edge {}→{} (group={})",
                e.from_module,
                e.to_module,
                e.buffer_group,
            );
            n += 1;
        }
    }
    if n > 0 {
        log::info!("[sched] {n} DmaOwned edges declared (maintenance deferred)");
    }
}

/// Same intent as `log_dma_owned_edges`, but walks the config's edge
/// table directly. Used by the bcm2712 graph setup path, which owns
/// module/edge instantiation itself and never populates `sched.edges`.
pub fn log_dma_owned_edges_from_config(edges: &[Option<crate::kernel::boot::config::GraphEdge>]) {
    let mut n = 0usize;
    for edge in edges.iter().flatten() {
        if let crate::kernel::boot::config::EdgeClass::DmaOwned = edge.edge_class {
            log::info!(
                "[sched] DmaOwned edge {}→{} (group={})",
                edge.from_id,
                edge.to_id,
                edge.buffer_group,
            );
            n += 1;
        }
    }
    if n > 0 {
        log::info!("[sched] {n} DmaOwned edges declared (maintenance deferred)");
    }
}

pub(crate) fn validate_domains_static(module_count: usize, edge_count: usize) {
    // SAFETY: prepare_graph context — single reader on the scheduler thread.
    let sched = unsafe {
        let p = &raw const SCHED;
        &*p
    };

    if sched.domain_count <= 1 {
        return; // Single domain — nothing to validate
    }

    let effective_domains = sched.domain_count as usize;

    // Warn on empty domains
    for d in 0..effective_domains {
        if sched.domain_module_count[d] == 0 {
            log::warn!("[domain] domain {d} is empty (no modules assigned)");
        }
    }

    // Check for modules assigned to out-of-range domains
    for i in 0..module_count {
        let domain = sched.domain_id[i] as usize;
        if domain >= effective_domains && domain != 0 {
            log::warn!(
                "[domain] module {} assigned to domain {} (max {}), using domain 0",
                i,
                domain,
                effective_domains - 1
            );
        }
    }

    // Validate cross_core edges connect modules in different domains
    for i in 0..edge_count {
        let e = &sched.edges[i];
        if let crate::kernel::boot::config::EdgeClass::CrossCore = e.edge_class {
            let from_domain = if e.from_module < MAX_MODULES {
                sched.domain_id[e.from_module]
            } else {
                0
            };
            let to_domain = if e.to_module < MAX_MODULES {
                sched.domain_id[e.to_module]
            } else {
                0
            };
            if from_domain == to_domain {
                log::warn!(
                    "[domain] cross_core edge {}→{} but both in domain {}",
                    e.from_module,
                    e.to_module,
                    from_domain
                );
            }
        }
    }

    // Estimate tick budget: warn if module count exceeds rough budget
    for d in 0..effective_domains {
        let count = sched.domain_module_count[d] as usize;
        let domain_tick = if sched.domain_tick_us[d] > 0 {
            sched.domain_tick_us[d]
        } else {
            sched.tick_us
        };
        if domain_tick < 500 && count > 8 {
            log::warn!(
                "[domain] domain {d} has {count} modules with tick_us={domain_tick} — may exceed tick budget"
            );
        }
    }
}

/// Compute downstream latency for each module.
///
/// Walk graph in reverse execution order (sinks→sources). For each module M,
/// find all successors N via edges. downstream_latency[M] = max over all N of
/// (module_latency[N] + downstream_latency[N]).
pub fn compute_downstream_latency(sched: &mut SchedulerState, module_count: usize) {
    let _edge_count = sched.exec_order_count;

    // Walk in reverse exec order: sinks have downstream_latency=0, then work backwards
    for rev_i in 0..sched.exec_order_count {
        let m = sched.exec_order[sched.exec_order_count - 1 - rev_i] as usize;
        if m >= module_count {
            continue;
        }

        let mut max_downstream: u32 = 0;
        // Find all outgoing edges from m
        for e_i in 0..MAX_CHANNELS {
            let e = &sched.edges[e_i];
            if e.channel >= 0 && e.from_module == m && e.to_module < module_count {
                let n = e.to_module;
                let total = sched.module_latency[n].saturating_add(sched.downstream_latency[n]);
                if total > max_downstream {
                    max_downstream = total;
                }
            }
        }
        sched.downstream_latency[m] = max_downstream;
    }
}
