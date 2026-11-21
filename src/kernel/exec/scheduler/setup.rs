//! Scheduler responsibility module (real module boundary; parent statics and
//! helpers reach us via `super`).
use super::*;

// ============================================================================
// Setup Functions
// ============================================================================

/// Size every boot-sized kernel table from the plan `config` derives
/// (`resource_ledger::plan`): the scheduler's per-module and per-edge tables,
/// the channel slots, events, timers, owners, tracked handles, the
/// state-arena free list, the `net.policy` store and, on Linux and bcm2712,
/// the control-plane store's tables. On a static profile it checks that each
/// table already holds its plan. `Err` has logged the refusal, naming the
/// pool.
///
/// # Safety
/// Graph preparation: no module runs and nothing holds a reference into any
/// of these tables.
pub unsafe fn size_kernel_tables(
    config: &Config,
) -> Result<(), crate::kernel::sys::resource_ledger::Refused> {
    // The platform frames the plan: it may plan its own memory around the
    // kernel's tables, and it sizes the tables it keeps after them.
    // SAFETY: the caller's contract, forwarded to both.
    unsafe { crate::platform::chip::plan_tables(|| size_tables(config)) }
}

/// The kernel's own tables, from the plan `config` derives.
///
/// # Safety
/// As [`size_kernel_tables`].
unsafe fn size_tables(config: &Config) -> Result<(), crate::kernel::sys::resource_ledger::Refused> {
    use crate::abi::contracts::resource as res;
    use crate::kernel::sys::resource_ledger as ledger;
    ledger::plan(config);
    let refused = ledger::refuse_table;
    for pool in 1..=res::KERNEL_POOL_COUNT as u16 {
        ledger::check_static(pool)?;
    }
    let (module_derived, _) = ledger::plan_parts(res::POOL_MODULE_SLOTS);
    let modules = ledger::ceiling(res::POOL_MODULE_SLOTS) as usize;
    if modules > MAX_MODULES {
        ledger::refuse(
            res::POOL_MODULE_SLOTS,
            "past the module-index range (12-bit config ids, ModuleMask width)",
        );
        return Err(ledger::Refused);
    }
    let (edge_derived, _) = ledger::plan_parts(res::POOL_CHANNELS);
    let edges = ledger::ceiling(res::POOL_CHANNELS) as usize;
    if edges > MAX_CHANNELS {
        ledger::refuse(res::POOL_CHANNELS, "past the channel-id range");
        return Err(ledger::Refused);
    }
    // SAFETY: graph preparation is SCHED's single mutator.
    let sched = unsafe { &mut *core::ptr::addr_of_mut!(SCHED) };
    sched
        .size_module_tables(modules, module_derived as usize)
        .map_err(|e| refused(res::POOL_MODULE_SLOTS, e))?;
    sched
        .size_edge_tables(edges, edge_derived as usize)
        .map_err(|e| refused(res::POOL_CHANNELS, e))?;
    crate::kernel::ipc::channel::size(edges, edge_derived as usize)
        .map_err(|e| refused(res::POOL_CHANNELS, e))?;
    let whole = |pool: u16| ledger::ceiling(pool) as usize;
    // Event, timer and routed handles name their slot in the handle's index
    // field: a table past it would hand out handles that alias. The routes'
    // derived part is what the platform's own provider tables can hand out.
    ledger::set_derived(
        res::POOL_HANDLES,
        crate::kernel::module::provider::platform_handle_slots() as u32,
    );
    let index_limit = crate::abi::kernel_abi::handle::INDEX_LIMIT;
    for pool in [res::POOL_EVENTS, res::POOL_TIMERS, res::POOL_HANDLES] {
        if whole(pool) > index_limit {
            ledger::refuse(pool, "past the handle index range");
            return Err(ledger::Refused);
        }
    }
    crate::kernel::ipc::event::size(whole(res::POOL_EVENTS))
        .map_err(|e| refused(res::POOL_EVENTS, e))?;
    crate::kernel::ipc::timer::size_timers(whole(res::POOL_TIMERS))
        .map_err(|e| refused(res::POOL_TIMERS, e))?;
    let owners = whole(res::POOL_OWNERS);
    sched
        .owners
        .size(owners)
        .map_err(|e| refused(res::POOL_OWNERS, e))?;
    // Every per-owner table is the owner table's size: one log ring, one
    // code-pack region (and one being staged), one graph-workload slot per
    // owner slot; the graph-local pacers and the resident-graph index hold
    // one entry per owner slot and execution domain.
    super::pacer::size_graph_pacers(owners).map_err(|e| refused(res::POOL_OWNERS, e))?;
    super::multigraph::size_resident_graphs(owners).map_err(|e| refused(res::POOL_OWNERS, e))?;
    #[cfg(feature = "host-linux")]
    crate::kernel::workload::owner_log::size(owners).map_err(|e| refused(res::POOL_OWNERS, e))?;
    crate::kernel::workload::code_pack::size(owners).map_err(|e| refused(res::POOL_OWNERS, e))?;
    crate::kernel::workload::workload_graph::size(owners)
        .map_err(|e| refused(res::POOL_OWNERS, e))?;
    crate::kernel::module::provider::size_routes(whole(res::POOL_HANDLES))
        .map_err(|e| refused(res::POOL_HANDLES, e))?;
    crate::kernel::ipc::lend::size(whole(res::POOL_LENDS))
        .map_err(|e| refused(res::POOL_LENDS, e))?;
    crate::kernel::module::loader::size_free_list(whole(res::POOL_STATE_FREE_LIST))
        .map_err(|e| refused(res::POOL_STATE_FREE_LIST, e))?;
    crate::kernel::net_policy::size(
        whole(res::POOL_NET_POLICY_TABLES),
        whole(res::POOL_NET_POLICY_TABLE_BYTES),
    )
    .map_err(|e| refused(res::POOL_NET_POLICY_TABLES, e))?;
    crate::kernel::net_route::size(
        whole(res::POOL_NET_ROUTE_SEGMENTS),
        whole(res::POOL_NET_ROUTE_PEERS),
        whole(res::POOL_NET_ROUTE_HELD),
    )
    .map_err(|e| refused(res::POOL_NET_ROUTE_SEGMENTS, e))?;
    // A ring per edge with an interrupt-mode end; past the profile's rings
    // an edge loses its routing, logged when it is wired.
    // SAFETY: the caller's contract, forwarded.
    unsafe {
        crate::kernel::ipc::isr_ring::size(
            isr_edges(config).min(crate::kernel::ipc::isr_ring::MAX_RINGS),
        )
    }
    .map_err(|e| refused(res::POOL_CHANNELS, e))?;
    Ok(())
}

/// Edges of the node graph with an end in an interrupt-mode domain.
fn isr_edges(config: &Config) -> usize {
    let isr = |id: ModuleId| {
        config
            .modules
            .get(usize::from(id))
            .copied()
            .flatten()
            .and_then(|m| {
                config
                    .domain_exec_mode
                    .get(usize::from(m.domain_id))
                    .copied()
            })
            .is_some_and(ExecMode::is_interrupt)
    };
    config
        .graph_edges
        .iter()
        .take(config.edge_count as usize)
        .flatten()
        .filter(|e| isr(e.from_id) || isr(e.to_id))
        .count()
}

/// Boot setup: the module loader, the configuration, the runtime parameter
/// store and the step guard. `false` has logged what failed.
pub fn setup() -> bool {
    // SAFETY: setup runs once at boot; no concurrent reader yet.
    let loader = unsafe {
        let p = &raw mut STATIC_LOADER;
        &mut *p
    };
    // SAFETY: as above.
    let config = unsafe {
        let p = &raw mut STATIC_CONFIG;
        &mut *p
    };

    // Initialize PIC module loader
    if let Err(e) = loader.init() {
        e.log("loader");
        return false;
    }

    if !read_config_into(config) {
        log::error!("[config] not found");
        return false;
    }
    // Scan runtime parameter store (flash sector with persistent overrides)
    hal::boot_scan();

    // Initialize step guard timer hardware
    step_guard::init();

    true
}

/// Whether the module `name_hash` names declares what the `vault_store`
/// contract asks of whoever calls it: the graph's store for the vault's
/// records, by its manifest rather than by its name.
fn keeps_vault_records(loader: &ModuleLoader, name_hash: u32) -> bool {
    use crate::abi::registry::{contract_grant, vault_store, OpGrant};
    let Ok(m) = loader.find_by_name_hash(name_hash) else {
        return false;
    };
    let held = m.manifest_grants();
    match contract_grant(vault_store::ID) {
        Some(OpGrant::Contract(c)) => held[0] & (1u64 << c) != 0,
        Some(OpGrant::Grant(g)) => held[1] & (1u64 << g) != 0,
        Some(OpGrant::Free) | None => false,
    }
}

/// Prepare the node's graph: release the previous graph, reset the kernel's
/// tables to the plan the installed config derives, and stage the config's
/// composed graph through the splice under the node owner
/// (`splice::admit_boot`): checked as any add is, its edges wired and their
/// channels opened, every slot stamped. The caller applies what must hold
/// before any module runs (an owner plan, cross-domain bridging), then
/// [`instantiate_graph`] instantiates and publishes it.
///
/// The negative errno on refusal; the graph is then idle until the next
/// preparation succeeds.
pub fn prepare_graph() -> Result<super::splice::StagedAdd, i32> {
    // SAFETY: prepare_graph runs single-threaded during graph bring-up.
    let config: &'static Config = unsafe { &*core::ptr::addr_of!(STATIC_CONFIG) };
    let Some(composed) = config.composed() else {
        log::error!("[graph] no composed graph");
        return Err(crate::kernel::sys::errno::EINVAL);
    };
    let module_count = usize::from(composed.module_count());
    let edge_count = usize::from(composed.edge_count());
    if module_count == 0 {
        log::error!("[graph] no modules");
        return Err(crate::kernel::sys::errno::EINVAL);
    }
    if module_count > MAX_MODULES || edge_count > MAX_CHANNELS {
        log::error!("[graph] {module_count} modules / {edge_count} edges past the kernel's domain");
        return Err(crate::kernel::sys::errno::E2BIG);
    }

    // A graph that keeps the vault's records through a store module says so
    // before any module runs: until that store loads, the vault answers
    // `EAGAIN` rather than read the platform's store, or none, as its own
    // and mint a key over one already kept.
    // SAFETY: graph preparation, the loader's single reader.
    let loader = unsafe { static_loader() };
    crate::kernel::security::vault_store::expect(
        composed
            .modules()
            .any(|m| keeps_vault_records(loader, m.name_hash)),
    );

    log::info!("[graph] modules={module_count} edges={edge_count}");

    // SAFETY: prepare_graph is the single mutator of SCHED until
    // graph stepping resumes; this `&mut` is exclusive.
    let sched = unsafe { &mut *core::ptr::addr_of_mut!(SCHED) };

    // Transaction marker, latched before any destructive reset: while it
    // is set, `pass::run` reports the graph `StepResult::Done` (cleanly
    // idle) instead of stepping a half-prepared one. The splice clears it
    // once the new graph is published; a failed preparation leaves it set,
    // so a domain that resumes after the quiesce steps nothing until the
    // next preparation succeeds.
    sched.prepare_in_progress = true;

    // No module is current while the graph is built: kernel-internal
    // channel calls are never mistaken for a stale interrupt-mode slot's.
    set_current_module(MAX_MODULES);

    // No interrupt-mode module may run while the tables move: one dispatched
    // on another core reads the module tables in a syscall's admission
    // check. Its registration reopens dispatch once the new graph has
    // instantiated it.
    crate::kernel::exec::interrupt::close_dispatch();

    // The previous graph's instances go first, while the arena their state
    // was drawn from is intact: a native module releases what it built.
    for i in 0..sched.modules.len() {
        let _ = sched.modules[i].take_state_range();
    }

    // Size every boot-sized table to the plan this config derives, before
    // anything below walks one. A plan the platform cannot hold fails the
    // graph here, naming the pool.
    // SAFETY: graph preparation — no module runs and nothing holds a
    // reference into a kernel table: the cooperative domains are parked or
    // not yet started, and interrupt-mode dispatch is closed above.
    if unsafe { size_kernel_tables(config) }.is_err() {
        return Err(crate::kernel::sys::errno::ENOSPC);
    }

    // Reset all scheduler state, state arena, and name arena. Channel
    // slots and buffer registry slots are wiped too, so a prior graph's
    // claims don't accumulate: resetting the arenas alone would leave slot
    // metadata `Allocated` across rebuilds, and `try_allocate` would skip
    // those slots until `MAX_CHANNELS` / `MAX_BUFFER_SLOTS` ran out even on
    // otherwise well-sized graphs. Module provider layers go with the
    // modules that registered them (`reset_module_layers`).
    reset_state_arena();
    // A rebuild drops every workload, and with them the code packs they
    // brought.
    crate::kernel::workload::workload_graph::reset_pending();
    crate::kernel::workload::code_pack::reset();
    // Drop any EL0-isolation page tables from a previous graph so a
    // reconfigure rebuilds them from the new graph's regions. No-op on
    // non-BCM2712 platforms.
    crate::kernel::sys::hal::protection_reset();
    crate::kernel::ipc::channel::reset_all();
    crate::kernel::ipc::buffer_pool::reset_all();
    crate::kernel::ipc::buffer_pool::reset_buffer_arena();
    crate::kernel::module::provider::reset_handle_tracking();
    crate::kernel::module::provider::reset_module_layers();
    // The old graph's slots no longer name net.route writers; the tables stay.
    crate::kernel::net_route::reset_bindings();
    // A module net provider and the lanes queued for it belong to the old
    // graph; a native one registers again as the new graph instantiates.
    crate::kernel::workload::net_attach::reset_queued();
    // The previous graph's interrupt-mode registrations and bridge slots go
    // before the new graph registers its own.
    crate::kernel::exec::interrupt::reset_all();
    crate::kernel::ipc::isr_ring::reset_all();
    sched.reset();
    // A resident owner's state is charged again as the new graph
    // instantiates its modules; what the previous graph charged goes.
    sched.owners.clear_state_charges();
    // The pacer statics live outside `SCHED`: a rebuilt graph starts from a
    // clean cadence rather than the prior graph's.
    pacer_reset_all();
    // Owner-pause wake masking also lives outside `SCHED`; pause is a
    // runtime posture, not desired state, and does not survive a rebuild.
    crate::kernel::ipc::event::reset_pause_masking();

    // Store graph-level sample rate from config header
    sched.graph_sample_rate = config.header.graph_sample_rate;
    if sched.graph_sample_rate != 0 {
        log::info!("[graph] sample_rate={}", sched.graph_sample_rate);
    }

    // Store tick_us from config header (0 = default 1000us)
    let raw_tick_us = config.header.tick_us as u32;
    sched.tick_us = if raw_tick_us == 0 {
        DEFAULT_TICK_US
    } else {
        raw_tick_us
    };
    if raw_tick_us != 0 {
        log::info!("[graph] tick_us={}", sched.tick_us);
    }

    // The node runs every domain its graph declares, occupied or not (a
    // workload may be placed in one later), and every domain a module
    // occupies; a single domain counts as none.
    let max_domain = composed.modules().map(|m| m.domain).max().unwrap_or(0);
    let occupied = if max_domain > 0 {
        (max_domain + 1).min(MAX_DOMAINS as u8)
    } else {
        0
    };
    let declared = config.domain_count.min(MAX_DOMAINS as u8);
    sched.domain_count = if declared > 1 {
        declared.max(occupied)
    } else {
        occupied
    };

    // Per-domain tick_us, exec_mode, and budget limit from config. The
    // budget limit *is* the tick: a domain that exceeds its tick_us within a
    // single pass is over-subscribed by definition. Per-domain `tick_us == 0`
    // means "inherit the graph-level tick".
    for d in 0..MAX_DOMAINS {
        sched.domains[d].tick_us = config.domain_tick_us[d] as u32;
        sched.domains[d].exec_mode = config.domain_exec_mode[d];
        // Adaptive-tick per-domain config. The config parser already
        // default-filled tick_min/tick_max to the domain's effective tick
        // when unset, so for an unmodified config tick_min == tick_max ==
        // tick and adaptive_flags == 0 ⇒ no-op.
        sched.domains[d].adaptive_flags = config.domain_adaptive_flags[d];
        sched.domains[d].tick_min_us = config.domain_tick_min_us[d] as u32;
        sched.domains[d].tick_max_us = config.domain_tick_max_us[d] as u32;
        let dtick = sched.domains[d].tick_us;
        sched.domains[d].budget_limit_us = if dtick > 0 {
            dtick
        } else if sched.tick_us > 0 {
            sched.tick_us
        } else {
            // Last resort: matches the platform main-loop default
            // (`tick_period_us = 1000` when nothing is configured).
            1000
        };
    }

    super::splice::admit_boot(composed, usize::from(config.domain_count)).map_err(|why| {
        log::error!("[graph] node graph refused: {}", why.name());
        why.code()
    })
}

/// Instantiate the node's graph [`prepare_graph`] staged and publish it
/// (`splice::instantiate_batch`, `splice::finish`, as a live add): a module
/// at a time, `each(slot)` after each one; `wait()` between polls of a load
/// that completes later, within the shared poll budget. The module count,
/// or the negative errno that refused the graph, which is then idle.
pub fn instantiate_graph(
    mut st: super::splice::StagedAdd,
    wait: &mut dyn FnMut(),
    each: &mut dyn FnMut(usize),
) -> Result<usize, i32> {
    use crate::kernel::exec::graph_build::GraphWalk;
    let n = st.module_count();
    let mut walk = GraphWalk::new(n);
    while !walk.is_finished() {
        match super::splice::instantiate_batch(&mut st, 1) {
            Ok(_) if st.loading() => {
                if !walk.record_poll() {
                    log::error!(
                        "[inst] module {} still loading after {} polls",
                        walk.next_entry(),
                        walk.polls()
                    );
                    super::splice::abandon(st);
                    return Err(crate::kernel::sys::errno::ETIMEDOUT);
                }
                wait();
            }
            Ok(_) => {
                each(st.slot(walk.next_entry()));
                walk.advance_instantiated();
            }
            Err(why) => {
                log::error!(
                    "[inst] module {} refused the graph: {}",
                    walk.next_entry(),
                    why.name()
                );
                return Err(why.code());
            }
        }
    }
    super::splice::finish(st).map_err(|why| {
        log::error!("[graph] node graph not published: {}", why.name());
        why.code()
    })?;
    Ok(n)
}

/// [`prepare_graph`] and [`instantiate_graph`] with nothing between them, no
/// wait between polls and no per-module step: the node's graph where the
/// platform applies nothing before its modules run.
pub fn build_graph() -> Result<usize, i32> {
    let st = prepare_graph()?;
    instantiate_graph(st, &mut || {}, &mut |_| {})
}

/// Default cycle budget of an interrupt-mode module when the graph gives
/// none (YAML `isr_budget_cycles`, params tag 0xFB): the chip's, in its own
/// cycle counter.
pub const DEFAULT_ISR_BUDGET_CYCLES: u32 = crate::platform::chip::DEFAULT_ISR_BUDGET_CYCLES;

/// Read the resolved IRQ for `module_idx`, or `None` when unset.
pub fn module_irq(module_idx: usize) -> Option<u16> {
    if module_idx >= module_slots() {
        return None;
    }
    // SAFETY: scheduler-thread read; module_idx bounded.
    let v = unsafe { (&*core::ptr::addr_of!(SCHED)).irq[module_idx] };
    if v == u16::MAX {
        None
    } else {
        Some(v)
    }
}

/// Assign an `irq` IRQ number to a module. Production path is
/// `parse_protection_config`'s TLV-tag 0xFC handler at module
/// instantiation; conformance tests call this directly to plant an
/// IRQ on a slot without going through a YAML/TLV cycle. `u16::MAX`
/// clears the override (the same sentinel `module_irq` uses to mean
/// "unset").
pub fn set_module_irq(module_idx: usize, irq: u16) {
    if module_idx >= module_slots() {
        return;
    }
    // SAFETY: scheduler-thread mutation; module_idx bounded.
    unsafe {
        (&mut *core::ptr::addr_of_mut!(SCHED)).irq[module_idx] = irq;
    }
}

/// Set the `timer` cycle budget override for a module. `0` clears
/// the override so the kernel falls back to
/// `DEFAULT_ISR_BUDGET_CYCLES`. Production path is
/// `parse_protection_config`'s TLV-tag 0xFB handler at module
/// instantiation; conformance tests call this directly.
pub fn set_module_isr_budget_cycles(module_idx: usize, budget_cycles: u32) {
    if module_idx >= module_slots() {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; module_idx bounded.
    unsafe {
        (&mut *core::ptr::addr_of_mut!(SCHED)).isr_budget_cycles[module_idx] = budget_cycles;
    }
}

/// Public accessor for the resolved per-module `timer`/`irq` ISR budget
/// (override if set, else `DEFAULT_ISR_BUDGET_CYCLES`). Lets conformance
/// tests observe the result of the TLV-tag-0xFB parse → `set_*` round trip
/// without exposing the private override array.
pub fn module_isr_budget_cycles(module_idx: usize) -> u32 {
    resolved_isr_budget_cycles(module_idx)
}

/// Read the resolved `timer` budget for a module: the per-module
/// override if non-zero, otherwise `DEFAULT_ISR_BUDGET_CYCLES`.
fn resolved_isr_budget_cycles(module_idx: usize) -> u32 {
    if module_idx >= module_slots() {
        return DEFAULT_ISR_BUDGET_CYCLES;
    }
    // SAFETY: scheduler-thread read; module_idx bounded.
    let ov = unsafe { (&*core::ptr::addr_of!(SCHED)).isr_budget_cycles[module_idx] };
    if ov == 0 {
        DEFAULT_ISR_BUDGET_CYCLES
    } else {
        ov
    }
}

/// Element size of every interrupt-mode ring: the ring's whole element, so
/// a payload fits in one; chunked payloads need a protocol of their own.
const ISR_BRIDGE_ELEM_SIZE: usize = crate::kernel::ipc::isr_ring::MAX_ELEM;

/// Walk every edge with at least one endpoint in an interrupt-mode
/// (`timer`/`irq`) domain and wire an `IsrRing` to it, recording the
/// slot index in `edge.bridge_slot`. The bridge is the *only*
/// channel interrupt-mode modules read/write through — the cooperative
/// side keeps its PIPE channel, and `pump_isr_bridges` shuttles
/// bytes between the two at every scheduler tick. Edges with both
/// endpoints in cooperative modes are skipped.
///
/// The rings are the boot plan's: one per edge of the node graph with an
/// interrupt-mode end, at most `MAX_RINGS`. An edge past them loses its
/// ISR routing, logged; the cooperative scheduler's runtime gate still
/// rejects channel I/O from the ISR side, so the graph is dead rather than
/// corrupt. The build-time validator catches the over-budget case.
pub(crate) fn wire_isr_bridges(edges: &mut [Edge]) {
    // SAFETY: prepare_graph runs single-threaded; SCHED writers are
    // serialised, so a shared read of `domain_id`/`domain_exec_mode`
    // is consistent here.
    let sched = unsafe {
        let p = &raw const SCHED;
        &*p
    };
    let mut wired: u16 = 0;
    for edge in edges.iter_mut() {
        if edge.bridge_slot >= 0 {
            continue;
        }
        let from_d = sched.domain_id[edge.from_module] as usize;
        let to_d = sched.domain_id[edge.to_module] as usize;
        let from_isr = from_d < MAX_DOMAINS && sched.domains[from_d].exec_mode.is_interrupt();
        let to_isr = to_d < MAX_DOMAINS && sched.domains[to_d].exec_mode.is_interrupt();
        if !from_isr && !to_isr {
            continue;
        }
        let Some(slot_idx) = crate::kernel::ipc::isr_ring::alloc(
            ISR_BRIDGE_ELEM_SIZE,
            edge.from_module as ModuleId,
            edge.to_module as ModuleId,
        ) else {
            log::error!(
                "[isr] no ring left for edge {}->{}: the boot plan sized none for it",
                edge.from_module,
                edge.to_module,
            );
            continue;
        };
        edge.bridge_slot = slot_idx as i8;
        wired += 1;
        log::info!(
            "[isr] bridge slot {slot_idx} wired for edge {}->{} (from_isr={from_isr} to_isr={to_isr})",
            edge.from_module,
            edge.to_module,
        );
    }
    // SAFETY: as above; a scalar the pass reads to skip the pump when no
    // bridge is wired.
    unsafe {
        let count = &mut (*core::ptr::addr_of_mut!(SCHED)).bridge_count;
        *count = count.saturating_add(wired);
    }
}

/// Drain bytes between the PIPE channels and their associated ISR
/// bridge slots. Runs once per tick pass, after the graphs
/// (cooperative path) and from the BCM2712 `tick` arm. Direction is
/// inferred from each edge's endpoint modes:
///
/// * from cooperative to `timer`/`irq` → drain bytes from
///   `edge.channel` (PIPE) into `bridge_slot` (Ring push). ISR
///   consumes from bridge on its next fire.
/// * from `timer`/`irq` to cooperative → pop from `bridge_slot`
///   and write into `edge.channel` (PIPE). Cooperative consumer
///   reads from the channel via the regular `channel_read` path.
/// * Both endpoints interrupt-mode is rare but works: the
///   bridge becomes the only conduit; the helper drains it back
///   into the consumer's PIPE handle so downstream port resolution
///   keeps working.
///
/// The drain is bounded — at most `MAX_DRAINS_PER_TICK` slots per
/// direction per tick — so a hot edge can't monopolise the pump.
pub fn pump_isr_bridges() {
    const MAX_DRAINS_PER_TICK: usize = 8;

    // SAFETY: scheduler-thread access during the scheduler tick.
    let sched = unsafe {
        let p = &raw const SCHED;
        &*p
    };
    let edge_count = sched.edge_count;
    let mut buf = [0u8; ISR_BRIDGE_ELEM_SIZE];

    for i in 0..edge_count {
        if i >= MAX_CHANNELS {
            break;
        }
        let edge = &sched.edges[i];
        if edge.bridge_slot < 0 {
            continue;
        }
        let from_d = sched.domain_id[edge.from_module] as usize;
        let to_d = sched.domain_id[edge.to_module] as usize;
        let from_isr = from_d < MAX_DOMAINS && sched.domains[from_d].exec_mode.is_interrupt();
        let to_isr = to_d < MAX_DOMAINS && sched.domains[to_d].exec_mode.is_interrupt();
        let slot_idx = edge.bridge_slot as usize;
        let Some(ring) = crate::kernel::ipc::isr_ring::get(slot_idx) else {
            continue;
        };

        // Cooperative → ISR: drain PIPE → bridge push.
        //
        // **Backpressure contract:** check that the ring has room
        // BEFORE reading the channel. `channel_read` consumes on
        // success, so a read-then-push pattern would drop the
        // payload when `ring.push` fails. Stopping at the source
        // keeps the bytes in the PIPE for the next pump pass.
        if !from_isr && to_isr && edge.channel >= 0 {
            for _ in 0..MAX_DRAINS_PER_TICK {
                if ring.is_full() {
                    break;
                }
                // SAFETY: buf is a stack array, len matches.
                let n = unsafe {
                    crate::kernel::ipc::channel::channel_read(
                        edge.channel,
                        buf.as_mut_ptr(),
                        ISR_BRIDGE_ELEM_SIZE,
                    )
                };
                if n <= 0 {
                    break;
                }
                let len = n as usize;
                if !ring.push(&buf[..len]) {
                    // Should be unreachable given the `is_full`
                    // check above (kernel runs the pump from the
                    // scheduler thread; no concurrent producer
                    // races here in single-core builds). Log if it
                    // ever happens.
                    log::warn!(
                        "[isr] bridge ring overflow on edge {}->{} after is_full check; \
                         {} bytes lost",
                        edge.from_module,
                        edge.to_module,
                        len,
                    );
                    break;
                }
            }
        }
        // ISR → cooperative: peek bridge → PIPE write → commit pop.
        //
        // **Backpressure contract:** popping before writing would
        // discard the element on `channel_write` backpressure.
        // Peek-then-commit holds the element in the ring head until
        // the PIPE accepts the write; on EAGAIN the element stays
        // put for the next pump pass.
        if from_isr && !to_isr && edge.channel >= 0 {
            for _ in 0..MAX_DRAINS_PER_TICK {
                let len = ring.peek_one(&mut buf);
                if len == 0 {
                    break;
                }
                // SAFETY: buf alive for the call.
                let written = unsafe {
                    crate::kernel::ipc::channel::channel_write(edge.channel, buf.as_ptr(), len)
                };
                if written <= 0 {
                    // PIPE back-pressured — leave the element in
                    // the ring (`peek_one` didn't advance tail).
                    // Next pump pass retries.
                    break;
                }
                // Confirmed write: commit the pop. `dst` slot is
                // discarded — we already wrote the peeked copy.
                let mut sink = [0u8; ISR_BRIDGE_ELEM_SIZE];
                let _ = ring.pop(&mut sink);
            }
        }
    }
}

/// Collect the bridge slots whose interrupt-mode endpoint is `module_idx`,
/// partitioning into (`in_bridges`, `out_bridges`) for the
/// `interrupt::register_*` calls. Each return slice carries at most 4
/// entries (matching `interrupt::MODULE_MAX_BRIDGES`).
fn collect_isr_bridges_for_module(
    sched: &SchedulerState,
    module_idx: usize,
) -> ([i8; 4], usize, [i8; 4], usize) {
    let mut in_bridges = [-1i8; 4];
    let mut in_count = 0usize;
    let mut out_bridges = [-1i8; 4];
    let mut out_count = 0usize;
    let edge_count = sched.edge_count;
    for i in 0..edge_count.min(MAX_CHANNELS) {
        let edge = &sched.edges[i];
        if edge.bridge_slot < 0 {
            continue;
        }
        if edge.to_module == module_idx && in_count < in_bridges.len() {
            in_bridges[in_count] = edge.bridge_slot;
            in_count += 1;
        } else if edge.from_module == module_idx && out_count < out_bridges.len() {
            out_bridges[out_count] = edge.bridge_slot;
            out_count += 1;
        }
    }
    (in_bridges, in_count, out_bridges, out_count)
}

/// How [`register_isr_module`] registered a module.
pub(crate) enum IsrRegistration {
    /// a `timer` slot, stepped by the timer of this period.
    Timer { period_us: u32 },
    /// an `irq` slot, its IRQ bound to the domain's core.
    Irq,
}

/// Hand one interrupt-mode module to its dispatcher: a timer slot for a
/// `timer` domain, an interrupt slot for an `irq` domain, its line bound to
/// the domain's core when `bind` (at graph bring-up) and unmasked otherwise
/// (a restart: the binding stayed, the line was masked when the module's
/// outcome latched). `None` for a module of a cooperative domain, or when
/// registration fails (logged). The one registration path, at graph
/// bring-up and when a faulted module restarts; the timer dispatcher is
/// started by the splice at bring-up only.
///
/// An `irq` module is dispatched through its interrupt entry (a PIC
/// module's `module_isr_entry` export, a native module's `isr_entry`),
/// never its cooperative step; one without it is refused here, behind the
/// splice's admission check.
pub(crate) fn register_isr_module(
    sched: &SchedulerState,
    modules: &[ModuleSlot],
    module_idx: usize,
    bind: bool,
) -> Option<IsrRegistration> {
    use crate::kernel::exec::{irq, timer};
    let domain = sched.domain_id[module_idx] as usize;
    if domain >= MAX_DOMAINS {
        return None;
    }
    let exec_mode = sched.domains[domain].exec_mode;
    if !exec_mode.is_interrupt() {
        return None;
    }
    let (in_arr, in_n, out_arr, out_n) = collect_isr_bridges_for_module(sched, module_idx);
    let in_bridges = &in_arr[..in_n];
    let out_bridges = &out_arr[..out_n];
    let budget = resolved_isr_budget_cycles(module_idx);

    if exec_mode == ExecMode::Irq {
        let Some(irq) = module_irq(module_idx) else {
            log::error!("[isr] irq-domain module {module_idx} has no IRQ assigned — skipping");
            return None;
        };
        let entry = match &modules[module_idx] {
            ModuleSlot::Dynamic(m) => m.isr_entry_fn().map(|e| (e, m.state_ptr())),
            ModuleSlot::Native(m) => m.vtable().isr_entry.map(|e| (e, m.state_ptr())),
            ModuleSlot::Empty => return None,
        };
        let Some((isr_entry, state_ptr)) = entry else {
            log::error!(
                "[isr] irq-domain module {module_idx} has no interrupt entry — refusing to \
                 dispatch its cooperative step from IRQ context"
            );
            return None;
        };
        let rc = irq::register_module(irq::IrqRegistration {
            isr_entry,
            state_ptr,
            irq_number: irq,
            module_index: module_idx as ModuleId,
            budget_cycles: budget,
            in_bridges,
            out_bridges,
        });
        if rc < 0 {
            log::error!("[isr] failed to register irq-domain module {module_idx}");
            return None;
        }
        if !bind {
            crate::kernel::sys::hal::irq_mask(irq as u32, false);
            return Some(IsrRegistration::Irq);
        }
        // The IRQ goes to the core that runs this domain's loop (domain id
        // == core id on the multi-core platform); single-core and no-IRQ
        // platforms ignore the target, and a HAL without an interrupt
        // controller binds nothing.
        let bind_rc = crate::kernel::sys::hal::irq_bind(
            irq as u32,
            irq::IRQ_MODULE_EVENT,
            crate::kernel::sys::hal::IrqAck::None,
            domain as u8,
        );
        if bind_rc < 0 {
            log::warn!(
                "[isr] hal::irq_bind(irq={irq}) returned {bind_rc} — interrupt dispatch may \
                 not fire on this platform"
            );
        }
        return Some(IsrRegistration::Irq);
    }

    // The period: the domain's tick, else the graph's, else the default.
    let dtick = sched.domains[domain].tick_us;
    let period_us = if dtick > 0 {
        dtick
    } else if sched.tick_us > 0 {
        sched.tick_us
    } else {
        DEFAULT_TICK_US
    };
    let (step_fn, state_ptr): (crate::kernel::module::loader::ModuleStepFn, *mut u8) =
        match &modules[module_idx] {
            ModuleSlot::Dynamic(m) => (m.step_fn(), m.state_ptr()),
            ModuleSlot::Native(m) => (m.vtable().step, m.state_ptr()),
            ModuleSlot::Empty => return None,
        };
    let rc = timer::register_module(
        step_fn,
        state_ptr,
        module_idx as ModuleId,
        budget,
        in_bridges,
        out_bridges,
    );
    if rc < 0 {
        log::error!("[isr] failed to register timer-domain module {module_idx} (domain {domain})");
        return None;
    }
    Some(IsrRegistration::Timer { period_us })
}

/// Log the arenas the node's graph and its workloads drew: the one-line
/// `[arena]` summary each platform writes once its graph is up.
pub fn log_arena_usage() {
    let (state_used, state_cap) = crate::kernel::module::loader::arena_usage();
    let (cfg_used, cfg_cap) = crate::kernel::boot::config::config_params_usage();
    let (buf_used, buf_cap) = crate::kernel::ipc::buffer_pool::arena_usage();
    // `cfg` is the params the graph borrows in place against its blob's
    // length; `heap` is what module heaps have committed against their caps
    // (an elastic heap commits as it allocates).
    let (heaps, heap_committed, heap_cap, _) = crate::kernel::mem::heap::heaps_usage();
    log::info!(
        "[arena] state={state_used}/{state_cap} cfg={cfg_used}/{cfg_cap} buf={buf_used}/{buf_cap} \
         heap={heap_committed}/{heap_cap} heaps={heaps}"
    );
}
