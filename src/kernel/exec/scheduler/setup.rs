//! Scheduler responsibility module (real module boundary; parent statics and
//! helpers reach us via `super`).
use super::*;

// ============================================================================
// Setup Functions
// ============================================================================

/// Synchronous setup - returns true if ready to run, false on error
///
/// Call this first, then call run_main_loop() if it returns true.
pub fn setup(runner_config: &RunnerConfig) -> bool {
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

    // Validate hardware requirements
    if !validate_hardware_requirements(runner_config) {
        log::error!("[boot] hardware validation failed");
        return false;
    }

    true
}

/// Common graph preparation: validate config, wire edges, insert fan modules,
/// open channels, and compute execution order.
///
/// Returns (module_list, module_count) on success, or -1 on error.
/// After this call, edges/modules/module_ports/finished/exec_order are initialized.
pub fn prepare_graph() -> Result<([Option<ModuleEntry>; MAX_MODULES], usize), i32> {
    // SAFETY: prepare_graph runs single-threaded during graph bring-up.
    let config = unsafe {
        let p = &raw const STATIC_CONFIG;
        &*p
    };
    // SAFETY: as above.
    let loader = unsafe {
        let p = &raw const STATIC_LOADER;
        &*p
    };
    let edge_count = config.edge_count as usize;
    let declared_modules = config.module_count as usize;

    if declared_modules == 0 {
        log::error!("[graph] no modules");
        return Err(-1);
    }
    if declared_modules > MAX_MODULES {
        log::error!("[graph] too many modules");
        return Err(-1);
    }
    if edge_count > MAX_CHANNELS {
        log::error!("[graph] too many edges");
        return Err(-1);
    }

    let (mut module_list, mut module_count, id_to_slot) = build_module_list(config)?;
    if module_count == 0 {
        log::error!("[graph] no usable modules");
        return Err(-1);
    }

    log::info!("[graph] modules={declared_modules} edges={edge_count}");

    // SAFETY: prepare_graph is the single mutator of SCHED until
    // graph stepping resumes; this `&mut` is exclusive.
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };

    // Transaction marker: latch BEFORE any destructive reset so a
    // racing `step_modules` on another core observes a half-prepared
    // graph as `StepResult::Done` (cleanly idle) rather than iterating
    // stale pointers. Cleared at the successful return path below; on
    // an early-return failure the marker is intentionally left set so
    // the SCHED is fail-safe until the next `prepare_graph` re-latches
    // it.
    sched.prepare_in_progress = true;

    // Clear `current_module` so the runtime EACCES gate
    // (`deny_isr_tier_syscall`) doesn't fire for kernel-internal
    // `channel_open` / `channel_read` / `channel_write` calls that
    // happen during graph build. The stale value from the previous
    // graph could point at a slot whose *new* domain is Tier 1b — a
    // classic teardown race that would surface as "open_channels
    // returns EACCES" inside the very call that's *populating* the
    // new graph. Reset is bounded by MAX_MODULES so the gate's
    // `caller >= MAX_MODULES` short-circuit kicks in.
    set_current_module(MAX_MODULES);

    // Reset all scheduler state, state arena, and name arena. Channel
    // slots and buffer registry slots also need to be wiped so a prior
    // graph's claims don't accumulate — bump-allocator-only resets
    // leave slot metadata in `Allocated` state across reconfigures,
    // and `try_allocate` would then skip those slots until
    // `MAX_CHANNELS` / `MAX_BUFFER_SLOTS` are exhausted even on
    // otherwise well-sized graphs.
    reset_state_arena();
    // Drop any EL0-isolation page tables from a previous graph so a
    // reconfigure rebuilds them from the new graph's regions. No-op on
    // non-BCM2712 platforms.
    crate::kernel::sys::hal::protection_reset();
    crate::kernel::ipc::channel::reset_all();
    crate::kernel::ipc::buffer_pool::reset_all();
    crate::kernel::ipc::buffer_pool::reset_buffer_arena();
    NameArena::reset();
    crate::kernel::backing_provider::unregister();
    crate::kernel::module::provider::reset_handle_tracking();
    // Tear down any prior graph's ISR-tier registrations and bridge
    // slots before walking the new module table. Without this, the
    // post-instantiation `register_isr_tier_modules_from_graph`
    // helper would append on top of stale entries from the previous
    // graph, and `wire_isr_bridges` would over-allocate bridge slots.
    crate::kernel::exec::isr_tier::reset_all();
    crate::kernel::bridge::bridge_reset_all();
    sched.reset();
    // The mechanism-(a)/(b) pacer statics live outside `Sched`, so reset them
    // here too — a rebuilt graph must start from a clean cadence (level/dwell/
    // deadband/idle-latch/burst) rather than inheriting the prior graph's.
    pacer_reset_all();
    // Owner-pause wake masking also lives outside `Sched`; the rebuild clears
    // every module's owner stamp (below) and plan re-apply reinstalls owners
    // Active, so stale mask bits would suppress wakes for reused module slots
    // (pause is a runtime posture, not
    // desired state; it does not survive a rebuild).
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

    // Store per-module domain assignments and infer domain count.
    // Mirror the per-module `pre_tick_drain` flag into SCHED at the
    // same time so the post-instantiation ISR-tier admission helper
    // reads it without re-touching the config blob.
    let mut max_domain: u8 = 0;
    // Rebuild the per-domain module bitmap from scratch (prepare_graph re-runs
    // on live reconfigure). The pacer intersects it with EVENT_WAKE_PENDING
    // for a per-domain idle decision.
    for m in sched.domain_module_mask.iter_mut() {
        *m = ModuleMask::EMPTY;
    }
    for entry in config.modules.iter().flatten() {
        let id = entry.id as usize;
        if id < MAX_MODULES {
            sched.domain_id[id] = entry.domain_id;
            sched.pre_tick_drain[id] = entry.pre_tick_drain;
            let d = entry.domain_id as usize;
            if d < MAX_DOMAINS {
                sched.domain_module_mask[d].set(id);
            }
            if entry.domain_id > max_domain {
                max_domain = entry.domain_id;
            }
        }
    }
    sched.domain_count = if max_domain > 0 {
        (max_domain + 1).min(MAX_DOMAINS as u8)
    } else {
        0
    };

    // Populate per-domain tick_us, exec_mode, and budget limit from
    // config. The budget limit *is* the tick: a domain that exceeds
    // its tick_us within a single pass is over-subscribed by
    // definition. Per-domain `tick_us == 0` means "inherit the
    // graph-level tick"; that fallback is what the budget guards
    // against — the cooperative path doesn't gate inter-module
    // execution by anything else.
    for d in 0..MAX_DOMAINS {
        sched.domain_tick_us[d] = config.domain_tick_us[d] as u32;
        sched.domain_exec_mode[d] = config.domain_exec_mode[d];
        // Adaptive-tick per-domain config. The config parser already
        // default-filled tick_min/tick_max to the domain's effective tick
        // when unset, so for an unmodified config tick_min == tick_max ==
        // tick and adaptive_flags == 0 ⇒ no-op.
        sched.domain_adaptive_flags[d] = config.domain_adaptive_flags[d];
        sched.domain_tick_min_us[d] = config.domain_tick_min_us[d] as u32;
        sched.domain_tick_max_us[d] = config.domain_tick_max_us[d] as u32;
        let dtick = sched.domain_tick_us[d];
        sched.domain_budget_us_limit[d] = if dtick > 0 {
            dtick
        } else if sched.tick_us > 0 {
            sched.tick_us
        } else {
            // Last resort: matches the platform main-loop default
            // (`tick_period_us = 1000` when nothing is configured).
            1000
        };
    }

    let edges = &mut sched.edges;

    // Wire edges from config
    for (i, edge_opt) in config.graph_edges.iter().take(edge_count).enumerate() {
        if let Some(edge) = *edge_opt {
            let from_slot = id_to_slot.get(edge.from_id as usize).copied().unwrap_or(-1);
            let to_slot = id_to_slot.get(edge.to_id as usize).copied().unwrap_or(-1);

            if from_slot < 0 || to_slot < 0 {
                log::error!(
                    "[graph] edge {} unknown module {}→{}",
                    i,
                    edge.from_id,
                    edge.to_id
                );
                return Err(-1);
            }

            let to_port_name = if edge.to_port == 1 { "ctrl" } else { "in" };
            let mut e = Edge::new_indexed(
                from_slot as usize,
                "out",
                edge.from_port_index,
                to_slot as usize,
                to_port_name,
                edge.to_port_index,
            );
            e.buffer_group = edge.buffer_group;
            e.edge_class = edge.edge_class;
            e.buffer_bytes = edge.buffer_bytes;
            e.rate_class = edge.rate_class;
            e.wake_on_write = edge.wake_on_write;
            edges[i] = e;
        } else {
            log::error!("[graph] edge {i} missing");
            return Err(-1);
        }
    }

    // Insert fan-out (tee) and fan-in (merge) modules
    let mut runtime_edge_count = edge_count;
    if !insert_fan_out(
        edges,
        &mut runtime_edge_count,
        &mut module_list,
        &mut module_count,
        loader,
    ) {
        return Err(-1);
    }
    if !insert_fan_in(
        edges,
        &mut runtime_edge_count,
        &mut module_list,
        &mut module_count,
        loader,
    ) {
        return Err(-1);
    }

    // EL0-isolation pre-pass: mark which modules requested `protection:
    // isolated` from their config params BEFORE channels are opened. The full
    // protection TLV is parsed later, at instantiation (`parse_protection_config`,
    // which runs after this in the platform flow), but `open_channels` →
    // `alloc_streaming_for_module` and the channel-region pass below both need
    // `module_is_isolated` to already be true so an isolated producer's channel
    // buffers are page-aligned + page-padded (otherwise the EL0 channel mapping
    // would round into a peer's buffer, and `build_table` would refuse the
    // non-page-clean region → the module would fail closed). Cheap, idempotent
    // with the later full parse.
    mark_isolated_from_params(&module_list, module_count);

    // Query channel hints and open channels
    collect_module_hints(loader, &module_list, module_count);
    if open_channels(&mut edges[..runtime_edge_count]) < 0 {
        log::error!("[graph] channel open failed");
        return Err(-1);
    }

    // Allocate ISR-tier bridge slots for any edge with at least one
    // endpoint in a Tier 1b/2 domain. The producer continues to
    // write the regular PIPE channel; `pump_isr_bridges` drains it
    // into the bridge ring each scheduler tick (and vice versa for
    // ISR→cooperative direction).
    wire_isr_bridges(&mut edges[..runtime_edge_count]);

    // Wake-on-write wiring: bind `wake: true` edges' channels to their
    // consumer module so a successful write latches the consumer's
    // event-wake bit and rings the scheduler doorbell. Same-domain
    // direct edges only here: bridged (ISR-tier) endpoints have no PIPE
    // writes to hook, and any edge the platform will split across the
    // SPSC pump (different domains, or `EdgeClass::CrossCore`) must
    // wake at consumer-side pump DELIVERY — a write-time wake on the
    // producer-side channel is guaranteed-spurious because the
    // consumer's domain steps before it pumps inbound, and the bytes
    // aren't readable through the consumer's handle until the pump
    // moves them. The cross-domain binding happens where the knowledge
    // lives: the platform's cross-edge bridging binds the
    // consumer-local channel (see bcm2712 `bridge_cross_domain_edges`),
    // so the pump's delivery write into it triggers the same wake hook
    // at the first moment the consumer could actually read the bytes.
    for e in edges[..runtime_edge_count].iter() {
        if !e.wake_on_write || e.channel < 0 || e.bridge_slot >= 0 || e.consumer_channel >= 0 {
            continue;
        }
        if e.edge_class == crate::kernel::boot::config::EdgeClass::CrossCore {
            // Bridged regardless of domain assignment — the consumer
            // reads the pump-delivered consumer-local channel, so the
            // wake binds there (platform bridging), not on the
            // producer-side channel.
            continue;
        }
        // SAFETY: scheduler-thread context during graph prep.
        let same_domain = unsafe {
            let p = core::ptr::addr_of!(SCHED);
            (*p).domain_id[e.from_module] == (*p).domain_id[e.to_module]
        };
        if !same_domain {
            continue; // bound at platform bridging, delivery side
        }
        crate::kernel::ipc::channel::channel_set_wake_module(e.channel, e.to_module as i32);
        log::info!(
            "[wake] edge {}→{} chan={} wake-on-write bound",
            e.from_module,
            e.to_module,
            e.channel
        );
    }

    // Validate buffer-group constraints uniformly across every
    // platform. Runs after `collect_module_hints` (which populates
    // `in_place_writer`) and `open_channels` (which sets
    // `edge.channel >= 0` for the live edges); two in-place writers
    // pinned into the same buffer group is undefined producer
    // ownership and must be rejected before the graph can step.
    if !validate_buffer_groups(&edges[..runtime_edge_count]) {
        log::error!("[graph] buffer group validation failed");
        return Err(crate::kernel::sys::errno::EINVAL);
    }

    // Register each module's channel-buffer range with the MPU/MMU so an
    // isolated module sees only its own buffers through region 6.
    for i in 0..module_count {
        let (base, size) = crate::kernel::ipc::buffer_pool::compute_module_buffer_range(i as u8);
        if size > 0 {
            // Platform protection policy (page rounding, fail-closed
            // interleave checks) lives behind the HAL seam.
            crate::kernel::sys::hal::protection_set_channel_region(i, base, size);
        }
    }

    // EL0-isolation page tables are built LAZILY on a module's first EL0 entry
    // (`mmu::enter_el0` → `build_table`), not here: module instantiation (which
    // registers the code/state/heap regions via `register_module`) runs in the
    // platform flow AFTER `prepare_graph` returns, so the regions aren't known
    // yet at this point. `register_module` preserves the channel region set by
    // the pass above, so the lazy build sees code/state/heap plus the
    // page-aligned channel range together. A failed lazy build fails the module
    // closed (never stepped at EL1) — see `enter_el0`.

    // Compute topological execution order. A graph with cycles is
    // rejected by default: silently running the topological prefix
    // plus the cyclic remainder produces a *different* graph than
    // the author declared. Typed feedback edges with explicit
    // buffering will get their own ABI shape; until then a cycle is
    // malformed and must be regenerated.
    //
    // Opt-in escape hatch (`graph_flags & ACCEPT_CYCLES`): the
    // config blob's graph-section flags byte can carry an explicit
    // author attestation that any cycles are bidirectional feedback
    // pairs (canonically `http <-> linux_net` in any linux http
    // example). When the flag is set, cycle members are appended to
    // exec_order in declaration order and a loud `log::warn!` line
    // is emitted so the choice is visible in operator output.
    let cycle_count = compute_exec_order(edges, runtime_edge_count, module_count);
    if cycle_count > 0 {
        let accept =
            (config.graph_flags & crate::kernel::boot::config::GRAPH_FLAG_ACCEPT_CYCLES) != 0;
        if !accept {
            log::error!(
                "[graph] {cycle_count} module(s) involved in cycles — graph rejected. \
                 Set `scheduler: {{ accept_cycles: true }}` in the graph YAML \
                 if these cycles are bidirectional feedback pairs."
            );
            return Err(crate::kernel::sys::errno::EINVAL);
        }
        log::warn!(
            "[graph] accepting {cycle_count} cycle module(s) under graph_flags.ACCEPT_CYCLES \
             — stepping order within the cycle is best-effort, declaration order."
        );
    }

    // Compute upstream dependency masks for ready-signal gating
    compute_upstream_mask(edges, runtime_edge_count);

    // Partition modules by domain and validate the partitioning.
    // These use the global SCHED directly to avoid borrow conflicts with `edges`.
    compute_domain_exec_orders_static(module_count);
    validate_domains_static(module_count, runtime_edge_count);

    // Log DmaOwned edges so operators can confirm the graph declares them.
    // Today DmaOwned is a metadata annotation — the scheduler doesn't issue
    // DC CVAC / DC IVAC at edge handoff because channels are copy-FIFO and
    // the consumer module (nvme) owns its own streaming buffers. Zero-copy
    // mailbox edges (buffer_group != 0) are where the scheduler will start
    // driving cache maintenance automatically; this log line pre-stages
    // the observability.
    log_dma_owned_edges(runtime_edge_count);

    sched.active_module_count = module_count;
    sched.edge_count = runtime_edge_count;

    // Populate every module's port table from the compiled edges so
    // `get_module_port` resolves correctly before any module is
    // instantiated. Built-ins that bypass `instantiate_one_module` and
    // post-processors (e.g. cross-domain bridging) can read the wired
    // handles immediately on return.
    for module_idx in 0..module_count {
        if !populate_module_ports_from_edges(module_idx, module_idx) {
            log::error!("[graph] port limit exceeded for module {module_idx}");
            return Err(-1);
        }
    }

    // Graph is fully wired — clear the in-progress marker so the
    // scheduler can step. Earlier early-returns leave it set, which is
    // the safe state (no module slots may be valid).
    sched.prepare_in_progress = false;

    Ok((module_list, module_count))
}

/// Default cycle budget for Tier 1b modules when no per-module
/// override is configured. ~2 µs on a Cortex-A76 at 2 GHz; tuned to
/// stay quiet on rp1_gem-class workloads while still catching a
/// runaway ISR body. Per-module overrides via the YAML `scheduler:
/// { isr_budget_cycles: N }` per-module block override this default;
/// see `prepare_graph` for the plumbing.
pub const DEFAULT_ISR_BUDGET_CYCLES: u32 = 2000;

/// Per-module ISR cycle budget override populated from the
/// `isr_budget_cycles:` YAML field via the kernel TLV tag 0xFB at
/// instantiation time. `0` means "fall back to
/// `DEFAULT_ISR_BUDGET_CYCLES`". Indexed by module slot.
static mut MODULE_ISR_BUDGET_OVERRIDE: [u32; MAX_MODULES] = [0; MAX_MODULES];

/// Per-module hardware IRQ number for Tier 2 admission. Populated
/// from the `irq:` YAML field via TLV tag 0xFC at instantiation
/// time. `u16::MAX` (the default) means "unset" — non-Tier-2 modules
/// keep the sentinel and the admission helper skips them.
static mut MODULE_IRQ_NUMBER: [u16; MAX_MODULES] = [u16::MAX; MAX_MODULES];

/// Read the resolved IRQ for `module_idx`, or `None` when unset.
pub fn module_irq(module_idx: usize) -> Option<u16> {
    if module_idx >= MAX_MODULES {
        return None;
    }
    // SAFETY: scheduler-thread read; module_idx bounded.
    let v = unsafe { MODULE_IRQ_NUMBER[module_idx] };
    if v == u16::MAX {
        None
    } else {
        Some(v)
    }
}

/// Assign a Tier 2 IRQ number to a module. Production path is
/// `parse_protection_config`'s TLV-tag 0xFC handler at module
/// instantiation; conformance tests call this directly to plant an
/// IRQ on a slot without going through a YAML/TLV cycle. `u16::MAX`
/// clears the override (the same sentinel `module_irq` uses to mean
/// "unset").
pub fn set_module_irq(module_idx: usize, irq: u16) {
    if module_idx >= MAX_MODULES {
        return;
    }
    // SAFETY: scheduler-thread mutation; module_idx bounded.
    unsafe {
        MODULE_IRQ_NUMBER[module_idx] = irq;
    }
}

/// Set the Tier 1b cycle budget override for a module. `0` clears
/// the override so the kernel falls back to
/// `DEFAULT_ISR_BUDGET_CYCLES`. Production path is
/// `parse_protection_config`'s TLV-tag 0xFB handler at module
/// instantiation; conformance tests call this directly.
pub fn set_module_isr_budget_cycles(module_idx: usize, budget_cycles: u32) {
    if module_idx >= MAX_MODULES {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; module_idx bounded.
    unsafe {
        MODULE_ISR_BUDGET_OVERRIDE[module_idx] = budget_cycles;
    }
}

/// Public accessor for the resolved per-module Tier 1b/2 ISR budget
/// (override if set, else `DEFAULT_ISR_BUDGET_CYCLES`). Lets conformance
/// tests observe the result of the TLV-tag-0xFB parse → `set_*` round trip
/// without exposing the private override array.
pub fn module_isr_budget_cycles(module_idx: usize) -> u32 {
    resolved_isr_budget_cycles(module_idx)
}

/// Read the resolved Tier 1b budget for a module: the per-module
/// override if non-zero, otherwise `DEFAULT_ISR_BUDGET_CYCLES`.
fn resolved_isr_budget_cycles(module_idx: usize) -> u32 {
    if module_idx >= MAX_MODULES {
        return DEFAULT_ISR_BUDGET_CYCLES;
    }
    // SAFETY: scheduler-thread read; module_idx bounded.
    let ov = unsafe { MODULE_ISR_BUDGET_OVERRIDE[module_idx] };
    if ov == 0 {
        DEFAULT_ISR_BUDGET_CYCLES
    } else {
        ov
    }
}

/// Element size advertised by every kernel-allocated ISR bridge ring.
/// Sized to the bridge crate's `MAX_BRIDGE_DATA` so the entire payload
/// fits in one slot; chunked payloads need their own bridge protocol.
const ISR_BRIDGE_ELEM_SIZE: usize = 56;

/// Walk every edge with at least one endpoint in an ISR-tier
/// (Tier 1b/2) domain and allocate a `RingBridge` slot, recording the
/// slot index in `edge.bridge_slot`. The bridge is the *only*
/// channel ISR-tier modules read/write through — the cooperative
/// side keeps its PIPE channel, and `pump_isr_bridges` shuttles
/// bytes between the two at every scheduler tick. Edges with both
/// endpoints in cooperative tiers are skipped.
///
/// `MAX_BRIDGES` caps the total bridges. Exceeding it returns
/// without crashing — the affected edges lose their ISR routing,
/// the cooperative scheduler's runtime gate still rejects any
/// channel I/O attempts from the ISR side, so the graph is dead
/// rather than corrupt. The build-time validator catches the
/// over-budget case in practice.
fn wire_isr_bridges(edges: &mut [Edge]) {
    // SAFETY: prepare_graph runs single-threaded; SCHED writers are
    // serialised, so a shared read of `domain_id`/`domain_exec_mode`
    // is consistent here.
    let sched = unsafe {
        let p = &raw const SCHED;
        &*p
    };
    for edge in edges.iter_mut() {
        if edge.bridge_slot >= 0 {
            continue; // already assigned (rerun safety)
        }
        let from_d = sched.domain_id[edge.from_module] as usize;
        let to_d = sched.domain_id[edge.to_module] as usize;
        let from_isr =
            from_d < MAX_DOMAINS && is_isr_tier_exec_mode(sched.domain_exec_mode[from_d]);
        let to_isr = to_d < MAX_DOMAINS && is_isr_tier_exec_mode(sched.domain_exec_mode[to_d]);
        if !from_isr && !to_isr {
            continue;
        }
        let slot = crate::kernel::bridge::bridge_alloc();
        if slot < 0 {
            log::error!(
                "[isr] bridge alloc exhausted at edge {}->{} (MAX_BRIDGES={MAX_ISR_BRIDGES_PER_GRAPH})",
                edge.from_module,
                edge.to_module,
            );
            continue;
        }
        let slot_idx = slot as usize;
        if let Some(bs) = crate::kernel::bridge::bridge_slot_mut(slot_idx) {
            bs.init_ring(
                ISR_BRIDGE_ELEM_SIZE,
                edge.from_module as u8,
                edge.to_module as u8,
            );
        }
        edge.bridge_slot = slot as i8;
        log::info!(
            "[isr] bridge slot {slot_idx} wired for edge {}->{} (from_isr={from_isr} to_isr={to_isr})",
            edge.from_module,
            edge.to_module,
        );
    }
}

/// Public alias for the `MAX_BRIDGES` ceiling visible from the
/// scheduler. Re-exported so logging + diagnostics that originate
/// here name the same constant as the bridge implementation.
const MAX_ISR_BRIDGES_PER_GRAPH: usize = crate::kernel::bridge::MAX_BRIDGES;

/// Drain bytes between the PIPE channels and their associated ISR
/// bridge slots. Runs once per scheduler tick after `step_modules`
/// (cooperative path) and from the BCM2712 Tier 0 arm. Direction is
/// inferred from each edge's endpoint tiers:
///
/// * `from = cooperative, to = Tier 1b/2` → drain bytes from
///   `edge.channel` (PIPE) into `bridge_slot` (Ring push). ISR
///   consumes from bridge on its next fire.
/// * `from = Tier 1b/2, to = cooperative` → pop from `bridge_slot`
///   and write into `edge.channel` (PIPE). Cooperative consumer
///   reads from the channel via the regular `channel_read` path.
/// * Same-tier (both endpoints ISR-tier) is rare but works: the
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
        let from_isr =
            from_d < MAX_DOMAINS && is_isr_tier_exec_mode(sched.domain_exec_mode[from_d]);
        let to_isr = to_d < MAX_DOMAINS && is_isr_tier_exec_mode(sched.domain_exec_mode[to_d]);
        let slot_idx = edge.bridge_slot as usize;
        let bridge = match crate::kernel::bridge::bridge_get(slot_idx) {
            Some(b) => b,
            None => continue,
        };
        let ring = match bridge.as_ring() {
            Some(r) => r,
            None => continue,
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

/// Collect the bridge slots whose ISR-tier endpoint is `module_idx`,
/// partitioning into (`in_bridges`, `out_bridges`) for the
/// `isr_tier::register_*` calls. Each return slice carries at most 4
/// entries (matching `MAX_ISR_BRIDGES` in `src/kernel/isr_tier.rs`).
fn collect_isr_bridges_for_module(module_idx: usize) -> ([i8; 4], usize, [i8; 4], usize) {
    let mut in_bridges = [-1i8; 4];
    let mut in_count = 0usize;
    let mut out_bridges = [-1i8; 4];
    let mut out_count = 0usize;
    // SAFETY: scheduler-thread access during the post-instantiation
    // admission helper.
    let sched = unsafe {
        let p = &raw const SCHED;
        &*p
    };
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

/// Tier 1b BCM admission trampoline state — exposes the BuiltInModule's
/// step pointer + state buffer via the slot index encoded in the
/// `state_ptr` argument. The `isr_tier1b_handler` invokes step_fn
/// with this index, the trampoline resolves the slot and dispatches
/// to the inner BuiltInModule step function.
unsafe extern "C" fn builtin_tier1b_trampoline(state: *mut u8) -> i32 {
    // `state` is the module index encoded as an integer pointer (see
    // `register_isr_tier_modules_from_graph` below). The encoding
    // round-trips through `usize` because the scheduler's module
    // slots are stable for the graph's lifetime.
    let module_idx = state as usize;
    // SAFETY: ISR-tier dispatch on BCM is polled from the scheduler
    // thread (the platform's `bcm_isr_tier_poll` invocation), so
    // there's no preemption against the cooperative writer; we
    // observe a coherent slot.
    let sched = unsafe { sched_ref() };
    if module_idx >= MAX_MODULES {
        return 0;
    }
    if let crate::kernel::exec::scheduler::module_types::ModuleSlot::BuiltIn(m) =
        &sched.modules[module_idx]
    {
        // Cast away the const — BuiltInModule::step_fn writes to the
        // state buffer in-place. The state buffer is owned by the slot
        // and not shared with anyone else this tick.
        let state_ptr = m.state.as_ptr() as *mut u8;
        return (m.step_fn())(state_ptr);
    }
    0
}

/// Walk the prepared graph and hand every Tier 1b module to the ISR-
/// tier dispatcher. For each ISR-tier-domain module, the helper picks
/// the appropriate `(step_fn, state_ptr)` pair from its slot and
/// invokes `isr_tier::register_tier1b_module`. After all modules are
/// registered, the helper computes the minimum tick interval across
/// all Tier 1b domains and arms the platform's Tier 1b timer via
/// `isr_tier::start_tier1b`.
///
/// Returns the number of modules registered. A return of `0` means
/// no Tier 1b modules are present and the timer was not started.
///
/// Bridge-channel wiring from YAML edges is **partially wired**:
///   * `wire_isr_bridges` allocates a `RingBridge` slot for every
///     edge with at least one ISR-tier endpoint; the slot index
///     lands in `Edge::bridge_slot`.
///   * `collect_isr_bridges_for_module` (called below) populates
///     the per-module `in_bridges` / `out_bridges` arrays passed to
///     `register_tier1b_module` from those slots.
///   * `pump_isr_bridges` drains PIPE↔ring each scheduler tick
///     using the `is_full` + `peek_one` peek-then-commit pattern
///     so backpressure is non-lossy.
///
/// **Module-facing gap:** PIC modules have no documented SDK
/// surface to read/write their bridge slots from inside
/// `module_step`. The SDK's `bridge_dispatch` helper rides
/// `provider_call`, which the syscall gate denies for
/// ISR-tier callers. The build-time validator rejects any
/// YAML edge touching an ISR-tier endpoint to prevent silently-
/// broken admission; production Tier 1b step bodies do
/// private-state work only. See
/// `docs/architecture/scheduler.md` §"ISR-tier I/O contract".
pub fn register_isr_tier_modules_from_graph() -> usize {
    // SAFETY: caller runs on the scheduler thread during graph bring-
    // up; no concurrent observers of SCHED/ISR_SLOTS yet.
    let sched = unsafe { sched_ref() };
    let count = sched.active_module_count;
    let mut registered: usize = 0;
    let mut min_period_us: u32 = u32::MAX;

    for module_idx in 0..count {
        let domain = sched.domain_id[module_idx] as usize;
        if domain >= MAX_DOMAINS {
            continue;
        }
        let exec_mode = sched.domain_exec_mode[domain];

        // Tier 2: per-IRQ-owned.
        //
        // A dynamically-loaded Tier 2 module is dispatched from IRQ
        // context through its dedicated `module_isr_entry` export
        // (resolved by `loader::lookup_exports` into
        // `DynamicModule::isr_entry_fn()`), never the cooperative
        // `module_step`. A Dynamic module with no ISR entry is a hard
        // registration failure here — the build-time validator requires
        // the export, and this is the runtime backstop. `BuiltInModule`
        // fixtures (whose Rust step function is trivially ISR-safe) take
        // the trampoline arm below.
        if exec_mode == exec_mode::TIER_2 {
            let irq = match module_irq(module_idx) {
                Some(n) => n,
                None => {
                    log::error!("[isr] Tier 2 module {module_idx} has no IRQ assigned — skipping");
                    continue;
                }
            };
            let (in_arr, in_n, out_arr, out_n) = collect_isr_bridges_for_module(module_idx);
            let budget = resolved_isr_budget_cycles(module_idx);
            let rc = match &sched.modules[module_idx] {
                crate::kernel::exec::scheduler::module_types::ModuleSlot::Dynamic(m) => {
                    match m.isr_entry_fn() {
                        Some(isr_entry) => crate::kernel::exec::isr_tier::register_tier2_module(
                            crate::kernel::exec::isr_tier::Tier2Registration {
                                isr_entry,
                                state_ptr: m.state_ptr(),
                                irq_number: irq,
                                module_index: module_idx as u8,
                                budget_cycles: budget,
                                uses_fpu: false,
                                in_bridges: &in_arr[..in_n],
                                out_bridges: &out_arr[..out_n],
                            },
                        ),
                        None => {
                            log::error!(
                                "[isr] Tier 2 module {module_idx} exports no \
                                 module_isr_entry — refusing to dispatch its \
                                 cooperative module_step from IRQ context"
                            );
                            -1
                        }
                    }
                }
                crate::kernel::exec::scheduler::module_types::ModuleSlot::BuiltIn(_) => {
                    crate::kernel::exec::isr_tier::register_tier2_module(
                        crate::kernel::exec::isr_tier::Tier2Registration {
                            isr_entry: builtin_tier1b_trampoline,
                            state_ptr: module_idx as *mut u8,
                            irq_number: irq,
                            module_index: module_idx as u8,
                            budget_cycles: budget,
                            uses_fpu: false,
                            in_bridges: &in_arr[..in_n],
                            out_bridges: &out_arr[..out_n],
                        },
                    )
                }
                _ => -1,
            };
            if rc < 0 {
                log::error!("[isr] failed to register Tier 2 module {module_idx}");
                continue;
            }
            // Bind the IRQ vector to the trampoline. The HAL hook is
            // a no-op on platforms without a real interrupt
            // controller (e.g. the host harness); production platforms
            // wire the IRQ-controller register here.
            // Deliver the IRQ to the core that runs this Tier-2 domain's
            // `exec_mode==4` park loop (domain id == core id on the multi-core
            // platform), not core 0 — otherwise the GIC dispatches
            // `module_isr_entry` on the wrong core. Single-core / no-IRQ
            // platforms ignore the target.
            let bind_rc = crate::kernel::sys::hal::irq_bind(
                irq as u32,
                crate::kernel::exec::isr_tier::ISR_TIER2_EVENT,
                crate::kernel::exec::isr_tier::isr_tier2_trampoline as usize,
                domain as u8,
            );
            if bind_rc < 0 {
                log::warn!(
                    "[isr] hal::irq_bind(irq={irq}) returned {bind_rc} — Tier 2 \
                     dispatch may not fire on this platform"
                );
            }
            registered += 1;
            continue;
        }

        if exec_mode != exec_mode::TIER_1B {
            continue;
        }
        // Find the period for this domain (fall back to graph-level
        // tick_us, then DEFAULT_TICK_US for fully un-configured cases).
        let dtick = sched.domain_tick_us[domain];
        let period_us = if dtick > 0 {
            dtick
        } else if sched.tick_us > 0 {
            sched.tick_us
        } else {
            DEFAULT_TICK_US
        };
        if period_us < min_period_us {
            min_period_us = period_us;
        }

        // Resolve in/out bridge slots for this module from the edge
        // table populated by `wire_isr_bridges`.
        let (in_arr, in_n, out_arr, out_n) = collect_isr_bridges_for_module(module_idx);
        let in_slice = &in_arr[..in_n];
        let out_slice = &out_arr[..out_n];
        let budget = resolved_isr_budget_cycles(module_idx);

        // Resolve the step_fn + state_ptr pair based on the slot kind.
        let rc = match &sched.modules[module_idx] {
            crate::kernel::exec::scheduler::module_types::ModuleSlot::Dynamic(m) => {
                crate::kernel::exec::isr_tier::register_tier1b_module(
                    m.step_fn(),
                    m.state_ptr(),
                    module_idx as u8,
                    budget,
                    in_slice,
                    out_slice,
                )
            }
            crate::kernel::exec::scheduler::module_types::ModuleSlot::BuiltIn(_) => {
                // BuiltInModule has Rust ABI; route through the
                // `builtin_tier1b_trampoline` which decodes the slot
                // index from `state_ptr`.
                crate::kernel::exec::isr_tier::register_tier1b_module(
                    builtin_tier1b_trampoline,
                    module_idx as *mut u8,
                    module_idx as u8,
                    budget,
                    in_slice,
                    out_slice,
                )
            }
            _ => -1,
        };
        if rc < 0 {
            log::error!("[isr] failed to register Tier 1b module {module_idx} (domain {domain})");
            continue;
        }
        registered += 1;
    }

    if registered > 0 && min_period_us < u32::MAX {
        log::info!(
            "[isr] starting Tier 1b timer period={min_period_us}us with {registered} modules"
        );
        crate::kernel::exec::isr_tier::start_tier1b(min_period_us);
    }
    registered
}

/// Fold per-owner state accounting for the modules a boot/rebuild pass
/// instantiated, then emit the one-line `[arena]` summary.
///
/// Each platform calls this once after its instantiation loop completes, so
/// STATE_ARENA reflects every `alloc_state` call (BUFFER and CONFIG arenas are
/// filled earlier, by `open_channels` and `populate_static_state`
/// respectively).
///
/// The accounting half runs here rather than per module because the resident
/// path stamps owners from the composed plan BEFORE instantiation (so
/// `module_new` sees tenant ownership), which means no single module's
/// instantiation is the point at which its owner becomes known — the pass is.
/// Unlike the live-admission path, a resident owner over its cap is reported
/// rather than refused: the graph it describes is the node's own boot
/// composition, and failing it closed would leave the node with no graph at
/// all rather than with a cap to raise.
pub fn finalize_instantiation_accounting() {
    charge_resident_owner_state();
    let (state_used, state_cap) = crate::kernel::module::loader::state_arena_usage();
    let (cfg_used, cfg_cap) = crate::kernel::boot::config::config_arena_usage();
    let (buf_used, buf_cap) = crate::kernel::ipc::buffer_pool::buffer_arena_usage();
    log::info!(
        "[arena] state={state_used}/{state_cap} cfg={cfg_used}/{cfg_cap} buf={buf_used}/{buf_cap}"
    );
}

/// Charge every instantiated module's state-arena draw to the owner stamped on
/// its slot. Idempotent against a rebuild: each pass zeroes the workload
/// owners' charges before re-folding them, so a reconfigure that reuses a slot
/// does not double-count it.
fn charge_resident_owner_state() {
    // SAFETY: post-instantiation, scheduler thread, single-threaded at this
    // point on every platform (each calls this once after its instantiation
    // loop, before the runner starts).
    let s = unsafe { crate::kernel::exec::scheduler::sched_mut() };
    s.owners.clear_state_charges();
    for idx in 0..crate::kernel::boot::config::MAX_MODULES {
        let owner = crate::kernel::exec::scheduler::module_owner(idx);
        if owner.is_system() {
            continue;
        }
        let bytes = crate::kernel::exec::scheduler::module_state_footprint(idx);
        if bytes == 0 {
            continue;
        }
        if s.owners.charge_state(owner, bytes).is_err() {
            let (charged, cap) = s.owners.charged_state(owner);
            log::warn!(
                "[arena] owner slot {} over its admitted state_cap: {charged} charged against \
                 {cap} (module {idx} adds {bytes}); the graph runs, the cap is the thing to fix",
                owner.slot,
            );
        }
    }
}

// Async graph setup (setup_graph_async) and run_main_loop are in
// src/platform/rp.rs.
// Sync variants (setup_graph_sync, run_main_loop_sync) are in
// src/platform/bcm2712.rs.
