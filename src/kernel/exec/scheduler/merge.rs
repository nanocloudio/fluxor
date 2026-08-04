//! Scheduler responsibility module (real module boundary; parent statics and
//! helpers reach us via `super`).
#![allow(
    unused_imports,
    reason = "the flat scheduler namespace is glob-imported; each module uses a subset"
)]
use super::*;

// ============================================================================
// Attachable-lane merge (rfc_workload_backend_metal.md §7 P4)
// ============================================================================
//
// The keystone that unblocks the metal `net=own` path. The one shared `ip`
// module caches its `net_in` channel at init and never re-resolves, so a runtime
// producer can only reach `ip` through a channel `ip` cached at boot — i.e.
// through a `_merge` whose OUTPUT is that cached channel. A boot `_merge` with
// SPARE input lanes (pre-opened, producer-less channels) is provisioned here;
// a runtime `apply_add` then wires a workload's net-facing producer to write
// into a free spare lane (`Endpoint::ExistingChannel`, `live.rs`). Because the
// merge's lanes are cached at boot and never mutated at runtime, attaching needs
// NO merge-state mutation — the round-robin `MergeModule::step` reads an empty
// spare lane as a benign no-op until a producer arrives. This subsumes the P3b
// runtime fan-in: no `add_input_lane`, no under-quiesce merge restructure.

/// Provision an attachable-lane `_merge` on a base-graph consumer's input port
/// at boot, with `spare_count` pre-opened producer-less spare lanes. The merge's
/// output becomes the consumer's input-port channel (so `ip`'s init-time
/// `net_in` cache picks up the merge — this MUST run before the consumer caches,
/// i.e. during graph prep / boot), and each spare lane is a distinct SPSC channel
/// a future workload producer attaches to. Returns the merge's module slot, or
/// `-1` on failure (bad slot, no free module/channel, out-of-range count).
///
/// Boot / pre-SMP only: it appends the merge to `exec_order` (and the affected
/// domain's order on bcm2712) with no quiesce — there is no live loop yet. A
/// graph that never calls this is byte-identical.
pub fn provision_spare_lane_merge(
    consumer_slot: usize,
    to_port_index: u8,
    spare_count: usize,
    frame_kind: u8,
) -> i32 {
    if consumer_slot >= MAX_MODULES || spare_count == 0 || spare_count > MAX_PORTS {
        return -1;
    }
    // SAFETY: boot / graph-prep context — single mutator, pre-SMP.
    let sched = unsafe { &mut *core::ptr::addr_of_mut!(SCHED) };
    if matches!(sched.modules[consumer_slot], ModuleSlot::Empty) {
        return -1;
    }
    let mut merge_slot = MAX_MODULES;
    for (i, slot) in sched.modules.iter().enumerate() {
        if matches!(slot, ModuleSlot::Empty) {
            merge_slot = i;
            break;
        }
    }
    if merge_slot >= MAX_MODULES {
        return -1;
    }
    if sched.edge_count >= MAX_CHANNELS {
        return -1;
    }
    // The merge's sole output — the channel the consumer caches and reads — plus
    // `spare_count` producer-less spare input lanes.
    let out_chan = crate::kernel::ipc::channel::channel_open(
        crate::kernel::ipc::channel::CHANNEL_TYPE_PIPE,
        null(),
        0,
    );
    if out_chan < 0 {
        return -1;
    }
    let mut lanes = [-1i32; MAX_CHANNELS];
    for lane in lanes.iter_mut().take(spare_count) {
        let ch = crate::kernel::ipc::channel::channel_open(
            crate::kernel::ipc::channel::CHANNEL_TYPE_PIPE,
            null(),
            0,
        );
        if ch < 0 {
            return -1;
        }
        *lane = ch;
    }
    let domain = sched.domain_id[consumer_slot];
    let dom = (domain as usize).min(MAX_DOMAINS - 1) as u8;
    sched.modules[merge_slot] = ModuleSlot::Merge(MergeModule::new(
        &lanes,
        spare_count,
        out_chan,
        dom,
        frame_kind,
    ));
    sched.ready[merge_slot] = true;
    sched.finished[merge_slot] = false;
    sched.domain_id[merge_slot] = domain;
    sched.slot_generation[merge_slot] = sched.slot_generation[merge_slot].wrapping_add(1);
    set_module_owner(merge_slot, crate::kernel::workload::owner::OWNER_SYSTEM);

    // The consumer reads the merge's output: set its input port so its init-time
    // cache picks up the merge, and record the merge→consumer edge for graph
    // consistency (so `channel_producer_owner`/teardown see it).
    set_module_port(consumer_slot, 0 /* PORT_IN */, to_port_index, out_chan);
    let mut e = Edge::new_indexed(merge_slot, "out", 0, consumer_slot, "in", to_port_index);
    e.channel = out_chan;
    sched.edges[sched.edge_count] = e;
    sched.edge_count += 1;

    // Splice the merge into the execution order (append; workload producers
    // attach at the tail later). Boot / pre-SMP, so no quiesce.
    let pos = sched.exec_order_count;
    if pos < MAX_MODULES {
        sched.exec_order[pos] = merge_slot as u8;
        sched.exec_order_count = pos + 1;
        sched.active_module_count += 1;
    }
    let d = domain as usize;
    if d < MAX_DOMAINS {
        sched.domain_module_mask[d].set(merge_slot);
    }
    #[cfg(feature = "smp")]
    recompute_domain_orders(1u32 << (d.min(crate::kernel::sys::hal::smp_max_domains() - 1)));
    merge_slot as i32
}

/// Discover the attachable-lane merge feeding a named base-graph consumer's
/// input port. Name-anchored: resolves the consumer's input channel and
/// returns the live merge whose output is that channel, or `-1`.
pub fn find_spare_lane_merge(consumer_name_hash: u32, to_port_index: u8) -> i32 {
    find_spare_lane_merge_for_channel(resolve_module_input_channel(
        consumer_name_hash,
        to_port_index,
    ))
}

/// Discover the attachable-lane merge whose output IS the given channel — the
/// channel a consumer caches as its input. Channel-anchored (no name
/// convention; the workload backend resolves the channel from the registered
/// net-identity provider's declared ingress port). Returns the merge's module
/// slot, or `-1`.
pub fn find_spare_lane_merge_for_channel(merge_out: i32) -> i32 {
    if merge_out < 0 {
        return -1;
    }
    // SAFETY: scheduler-thread read.
    let sched = unsafe { &*core::ptr::addr_of!(SCHED) };
    for (i, slot) in sched.modules.iter().enumerate() {
        if let ModuleSlot::Merge(m) = slot {
            if m.out_chan() == merge_out {
                return i as i32;
            }
        }
    }
    -1
}

/// Next FREE spare lane on a merge — a cached input channel with no producer
/// yet (`channel_producer_owner` still system). The attaching workload's
/// producer is wired to write into this channel id. Returns `-1` if the slot is
/// not a merge or every lane is taken.
pub fn merge_next_free_lane(merge_slot: usize) -> i32 {
    if merge_slot >= MAX_MODULES {
        return -1;
    }
    // SAFETY: scheduler-thread read.
    let sched = unsafe { &*core::ptr::addr_of!(SCHED) };
    if let ModuleSlot::Merge(m) = &sched.modules[merge_slot] {
        for &ch in m.input_lanes() {
            if ch >= 0 && channel_producer_owner(ch).is_system() {
                return ch;
            }
        }
    }
    -1
}

/// The merge slot that caches `ch` as one of its input lanes, if any. Lets
/// `apply_add` set an attach edge's `to` to the real consumer of the spare lane.
pub fn merge_owning_lane(ch: i32) -> Option<usize> {
    if ch < 0 {
        return None;
    }
    // SAFETY: scheduler-thread read.
    let sched = unsafe { &*core::ptr::addr_of!(SCHED) };
    for (i, slot) in sched.modules.iter().enumerate() {
        if let ModuleSlot::Merge(m) = slot {
            if m.input_lanes().contains(&ch) {
                return Some(i);
            }
        }
    }
    None
}

/// Read a port channel handle for a module. Mirror of `set_module_port`.
/// Returns -1 if unset or out of range.
pub fn get_module_port(module_idx: usize, port_type: u8, port_index: u8) -> i32 {
    if module_idx >= MAX_MODULES {
        return -1;
    }
    // SAFETY: SCHED scheduler-thread owned; module_idx bounded above.
    let ports = unsafe { &SCHED.ports[module_idx] };
    let idx = port_index as usize;
    match port_type {
        0 => {
            if idx < MAX_PORTS {
                ports.in_chans[idx]
            } else {
                -1
            }
        }
        1 => {
            if idx < MAX_PORTS {
                ports.out_chans[idx]
            } else {
                -1
            }
        }
        2 => {
            if idx < MAX_PORTS {
                ports.ctrl_chans[idx]
            } else {
                -1
            }
        }
        _ => -1,
    }
}

/// Set a port channel handle for a module. Used by BCM2712 platform
/// which doesn't go through the RP-side instantiate_one_module path.
/// port_type: 0=in, 1=out, 2=ctrl
pub fn set_module_port(module_idx: usize, port_type: u8, port_index: u8, channel: i32) {
    if module_idx >= MAX_MODULES {
        return;
    }
    // SAFETY: SCHED scheduler-thread owned; module_idx bounded above.
    let ports = unsafe { &mut SCHED.ports[module_idx] };
    let idx = port_index as usize;
    match port_type {
        0 => {
            if idx < MAX_PORTS {
                ports.in_chans[idx] = channel;
                if idx as u8 >= ports.in_count {
                    ports.in_count = idx as u8 + 1;
                }
            }
        }
        1 => {
            if idx < MAX_PORTS {
                ports.out_chans[idx] = channel;
                if idx as u8 >= ports.out_count {
                    ports.out_count = idx as u8 + 1;
                }
            }
        }
        2 => {
            if idx < MAX_PORTS {
                ports.ctrl_chans[idx] = channel;
                if idx as u8 >= ports.ctrl_count {
                    ports.ctrl_count = idx as u8 + 1;
                }
            }
        }
        _ => {}
    }
}

/// Maximum hints per module
const MAX_HINTS_PER_MODULE: usize = 8;

/// Per-module channel hints (buffer size requests)
#[derive(Clone, Copy)]
pub(crate) struct ModuleHints {
    pub(crate) hints: [ChannelHint; MAX_HINTS_PER_MODULE],
    pub(crate) count: usize,
}

impl ModuleHints {
    pub(crate) const fn empty() -> Self {
        Self {
            hints: [ChannelHint {
                port_type: 0,
                port_index: 0,
                buffer_size: 0,
                max_record: 0,
            }; MAX_HINTS_PER_MODULE],
            count: 0,
        }
    }
}

/// Per-module arena info: (ptr, size). Null if module has no arena.
#[derive(Copy, Clone)]
pub(crate) struct ArenaInfo {
    pub(crate) ptr: *mut u8,
    pub(crate) size: u32,
}

impl ArenaInfo {
    pub(crate) const fn empty() -> Self {
        Self {
            ptr: core::ptr::null_mut(),
            size: 0,
        }
    }
}

/// All scheduler runtime state in a single struct.
///
/// Replaces 14 scattered `static mut` arrays. A single `reset()` method
/// replaces the multi-line reset block in `prepare_graph()`.
pub struct SchedulerState {
    /// Graph edge wiring
    pub edges: [Edge; MAX_CHANNELS],
    /// Flow-stall sampler state: last sampled ring fill +
    /// consecutive-unchanged count per classed edge.
    pub(crate) flow_last_fill: [u32; MAX_CHANNELS],
    pub(crate) flow_stalls: [u8; MAX_CHANNELS],
    /// Number of populated entries in `edges` (post fan insertion).
    pub edge_count: usize,
    /// Instantiated module slots
    pub modules: [ModuleSlot; MAX_MODULES],
    /// Per-module port assignments
    pub ports: [ModulePorts; MAX_MODULES],
    /// Per-module channel hints (buffer size requests)
    pub(crate) hints: [ModuleHints; MAX_MODULES],
    /// Per-module finished flags (done or errored)
    pub(crate) finished: [bool; MAX_MODULES],
    /// Per-module arena allocations
    pub(crate) arenas: [ArenaInfo; MAX_MODULES],
    /// Per-module capability class (checked on provider dispatch)
    pub(crate) cap_class: [u8; MAX_MODULES],
    /// Per-module required_caps bitmask from manifest — public contract bits only
    pub(crate) required_caps: [u32; MAX_MODULES],
    /// Per-module fine-grained permissions bitmap (from manifest binary
    /// byte 15). Gates privileged 0x0Cxx opcodes by category — see the
    /// `permission` module in `syscalls.rs`. Separate from `required_caps`
    /// so non-contract permissions don't overload the contract bitmask.
    pub(crate) permissions: [u16; MAX_MODULES],
    /// Per-module instance-params blob pointer + length. Populated
    /// by platform loaders that have access to the source bytes —
    /// the wasm loader uses this so modules can fetch their own
    /// params via the `MODULE_INSTANCE_PARAMS` provider_query opcode
    /// across the kernel/module memory split. Native PIC loaders pass
    /// params directly to `module_new` and leave these null.
    pub(crate) module_params_ptr: [*const u8; MAX_MODULES],
    pub(crate) module_params_len: [usize; MAX_MODULES],
    /// Per-module mailbox_safe flag (header flags bit 0): can consume from mailbox
    pub(crate) mailbox_safe: [bool; MAX_MODULES],
    /// Per-module in_place_writer flag (header flags bit 1): uses acquire_inplace
    pub(crate) in_place_writer: [bool; MAX_MODULES],
    /// Per-module deferred ready flag (header flags bit 2)
    pub(crate) deferred_ready: [bool; MAX_MODULES],
    /// Per-module EL0-isolation request (set from the `protection: isolated`
    /// TLV tag 0xF5 == 2). Gates whether the module is routed through the
    /// EL0 protected step; `none`/`guarded` modules keep the direct EL1 path.
    pub(crate) isolated: [bool; MAX_MODULES],
    /// Per-module ready flag (true = outputs meaningful, false = still initializing)
    pub(crate) ready: [bool; MAX_MODULES],
    /// Per-module upstream dependency bitmask (precomputed from edges).
    /// FORWARD edges only — used for the readiness gate, where counting a
    /// cycle back-edge would deadlock the feedback pair.
    pub(crate) upstream_mask: [ModuleMask; MAX_MODULES],
    /// Per-module predecessor bitmask over ALL edges — forward AND cycle
    /// back-edges. Used ONLY for sink-completion (`cli_out`): a sink must not
    /// declare itself done while a producer that can still feed it — including
    /// one reached through a feedback cycle — is alive. Separate from
    /// `upstream_mask` because the readiness gate needs the forward-only set.
    pub(crate) completion_mask: [ModuleMask; MAX_MODULES],
    /// Per-module step period in scheduler ticks (0 = every tick, N =
    /// step every N ticks). Wall-clock period is
    /// `step_period * domain_tick_us` — units are ticks, NOT
    /// milliseconds. Sourced from the module header's
    /// `step_period_ticks` byte.
    pub(crate) step_period: [u8; MAX_MODULES],
    /// Per-module step counter (counts ticks toward period)
    pub(crate) step_counter: [u8; MAX_MODULES],
    /// Per-module ABSOLUTE next-due wall-clock (µs) for the multi-graph runner's
    /// graph-local periodic schedule (RFC adaptive_tick_extra §7). A module with
    /// `step_period > 1` in a resident workload graph fires when `now >=
    /// module_next_due_us[i]`, then this advances by its own
    /// `step_period × NOMINAL tick` — so each module keeps its OWN period and
    /// phase, independent of sibling load and of other periodic modules in the
    /// same graph. `0` ⇒ not yet anchored (primes on first encounter). Unused by
    /// the single-graph fast path.
    #[cfg_attr(
        not(feature = "multitenant"),
        allow(dead_code, reason = "read only by the multi-graph runner")
    )]
    pub(crate) module_next_due_us: [u64; MAX_MODULES],
    /// Per-module idle-safe attestation: the module owner asserts it is
    /// demand-driven (woken by events / its own periodic schedule) and may be
    /// idle-skipped. DEFAULT false = fail-closed: an unattested workload graph is
    /// never fully parked, only relaxed to the backstop (`tick_max`) cadence.
    /// Set from the workload's FXPD attestation flag at admission.
    #[cfg_attr(
        not(feature = "multitenant"),
        allow(dead_code, reason = "read only by the multi-graph runner")
    )]
    pub(crate) module_idle_safe: [bool; MAX_MODULES],
    /// Per-module count of consecutive ticks the module was considered
    /// by the scheduler but never reached `m.step()` — readiness gate
    /// vetoed every time. Reset to 0 on any actual step (Continue,
    /// Burst, Ready, Done). A graph author seeing a non-zero value
    /// here on a long-running module has either a dead edge or a
    /// permanently-unsatisfied upstream dependency. Surfaced via
    /// `ModuleStateSnapshot::inactive_for_ticks`.
    pub(crate) inactive_for_ticks: [u32; MAX_MODULES],
    /// Per-slot generation counter. Bumped on every event that
    /// invalidates an outstanding reference into the slot's state
    /// region — graph reset, module replacement (`store_builtin_module`,
    /// `store_dynamic_module`), partial restart. Callers that snapshot
    /// telemetry asynchronously can pair the snapshot's
    /// `slot_generation` with a later read; a generation mismatch means
    /// the slot was reused under them and the stale read must be
    /// discarded. Closes the use-after-free window between a fault
    /// telemetry dispatch and the read of the (possibly-replaced)
    /// module state.
    pub(crate) slot_generation: [u32; MAX_MODULES],
    /// Wall-clock time (ms, `hal::now_millis()`) at which the current
    /// `Draining` phase started. Captured by
    /// `set_reconfigure_phase(Draining)`; consulted by `step_modules`
    /// to enforce the `MAX_DRAIN_MS` ceiling. `u64::MAX` means "no
    /// drain in progress" — distinguishes the not-set sentinel from a
    /// legitimate `now == 0` start.
    pub(crate) drain_started_ms: u64,
    /// Starting offset into the topological `exec_order` for the
    /// flat-path next pass. Incremented after every `MON_BUDGET_OVERRUN`
    /// so modules that are exec-order-behind the overrunning one don't
    /// permanently lose every pass to the same upstream burster.
    /// Pass order stays deterministic — same cyclic permutation per
    /// non-overrunning pass.
    pub(crate) exec_order_offset: u8,
    /// Per-domain counterpart to `exec_order_offset` for the
    /// domain-stepped path. `step_domain_modules` rotates the start
    /// of `domain_exec_order[domain_id]` by this offset; it
    /// increments on every per-domain budget overrun. Without this,
    /// BCM multi-domain graphs with one overrunning module per
    /// domain would permanently starve every later position in that
    /// domain's exec_order.
    pub(crate) domain_exec_order_offset: [u8; MAX_DOMAINS],
    /// Topological execution order (Kahn's algorithm output)
    pub(crate) exec_order: [u8; MAX_MODULES],
    /// Number of entries in exec_order
    pub(crate) exec_order_count: usize,
    /// Graph-level sample rate from config (0 = not set)
    pub(crate) graph_sample_rate: u32,
    /// Tick period in microseconds (0 = default 1000us)
    pub(crate) tick_us: u32,
    /// Per-module self-reported latency in frames
    pub(crate) module_latency: [u32; MAX_MODULES],
    /// Per-module accumulated downstream latency in frames
    pub(crate) downstream_latency: [u32; MAX_MODULES],
    /// Per-module fault bookkeeping (state, policy, counters)
    pub(crate) fault_info: [ModuleFaultInfo; MAX_MODULES],
    /// Per-module domain assignment (0 = default domain)
    pub(crate) domain_id: [u8; MAX_MODULES],
    /// Per-module Tier 1c opt-in. Mirrors
    /// `ModuleEntry::pre_tick_drain` so `compute_domain_exec_orders_static`
    /// can partition pre-tick modules into `domain_pre_tick_order`
    /// without re-reading the config blob.
    pub(crate) pre_tick_drain: [bool; MAX_MODULES],
    /// Per-domain topological execution order
    pub(crate) domain_exec_order: [[u8; MAX_MODULES]; MAX_DOMAINS],
    /// Number of modules in each domain's execution order
    pub(crate) domain_module_count: [u8; MAX_DOMAINS],
    /// Number of domains configured (0 or 1 = single default domain)
    pub(crate) domain_count: u8,
    /// Per-domain tick_us (0 = use global tick_us). Index 0 = default domain.
    pub(crate) domain_tick_us: [u32; MAX_DOMAINS],
    /// Per-domain execution mode (0=cooperative/Tier 0, 1=high-rate/Tier 1a, 3=poll/Tier 3).
    pub(crate) domain_exec_mode: [u8; MAX_DOMAINS],

    // ── Adaptive-tick per-domain config (RFC adaptive_tick §8) ──────────
    /// Per-domain adaptive enable flags: bit 0 = (a) demand-driven idle,
    /// bit 1 = (b) adaptive cadence. `0` (the default for every unmodified
    /// config) ⇒ adaptive tick is fully off and pacing is byte-identical.
    pub(crate) domain_adaptive_flags: [u8; MAX_DOMAINS],
    /// Per-domain latency-floor target the pacer drives toward under load
    /// (mechanism (b)), µs. Default-filled to the domain's tick at parse.
    pub(crate) domain_tick_min_us: [u32; MAX_DOMAINS],
    /// Per-domain relaxed/idle backstop cadence the pacer relaxes toward
    /// (mechanisms (a)/(b)), µs. Default-filled to the domain's tick at parse.
    pub(crate) domain_tick_max_us: [u32; MAX_DOMAINS],

    // ── Per-domain step budget accumulator ──────────────────────────
    /// Per-domain budget limit in microseconds. Sourced from
    /// `domain_tick_us[d]` at `prepare_graph` time. `0` disables the
    /// budget check (no limit configured).
    ///
    /// Rationale: the cooperative scheduler can only enforce step
    /// budgets *between* modules (aarch64 step_guard is advisory; see
    /// [`step_guard.rs`](../step_guard.rs)). Tier 3 (poll-mode)
    /// especially needs total domain budget accounting because there
    /// is no per-tick boundary to fall back on — without this the
    /// poll loop will run an over-budget module indefinitely.
    ///
    /// The limit *is* the tick. There is intentionally no overrun
    /// "factor" multiplier — slack belongs in `tick_us`, not in a
    /// hidden tunable that has to be tracked separately. See
    /// [[scheduler-priority1-pass]] memory note for the decision.
    pub(crate) domain_budget_us_limit: [u32; MAX_DOMAINS],
    /// Per-domain microseconds consumed in the *current* step pass.
    /// Reset at the top of `step_modules` / `step_domain_modules` /
    /// `step_domain_modules_poll`; accumulated after every
    /// `step_one_module` return regardless of `StepOutcome`.
    pub(crate) domain_budget_us_consumed: [u64; MAX_DOMAINS],
    /// Cumulative count of times the domain's pass was cut short
    /// because `consumed > limit`. Surfaced via `monitor` so operators
    /// see chronically over-subscribed domains without needing to
    /// instrument modules individually.
    pub(crate) domain_budget_overruns: [u32; MAX_DOMAINS],
    /// Per-domain worst-recent single-step time, microseconds. This is the
    /// adaptive-tick **floor input** (RFC adaptive_tick §5.3 / P0b): the pacer
    /// must never drive the tick below `worst_step × margin` or it re-creates
    /// the `tick_us=500` budget overrun (evidence #5). It is a **decaying
    /// peak-hold**, NOT a monotonic max: `step_one_module` raises it to the
    /// live worst, and the per-pass budget reset decays it by `>>
    /// WORST_STEP_DECAY_SHIFT`, so a one-off (thermal) spike ages out and the
    /// floor relaxes on cool-down (AC7). A monotonic max would pin the floor
    /// high forever. Portable / measured on every tier + platform — the only
    /// pre-existing worst-step (`DomainMetrics.worst_step_ticks`, bcm2712) is
    /// Tier-1a-only, in cycles, and monotonic, so it cannot serve here.
    pub(crate) domain_worst_step_us: [u32; MAX_DOMAINS],

    /// Per-domain module bitmap — bit `m` set iff module `m` belongs to this
    /// domain. Built once in `prepare_graph` from `domain_id`. The adaptive-tick
    /// pacer intersects it with `EVENT_WAKE_PENDING` so one domain's idle
    /// decision is not coupled to a sibling domain's wake (RFC adaptive_tick
    /// §5.1). On a single-domain target every module lands in domain 0, so the
    /// intersection degenerates exactly to the global `wake_pending_nonzero()`.
    pub(crate) domain_module_mask: [ModuleMask; MAX_DOMAINS],

    // ── Tier 1c pre-pass drain slot ─────────────────────────────────
    /// Per-domain module indices that opt into the Tier 1c pre-tick
    /// slot. Each tick, `step_domain_modules` (and its `_poll`
    /// variant) walks this list before the regular `domain_exec_order`
    /// rotation, calling `step_one_module` for each entry. The
    /// indices are populated by `prepare_graph` from
    /// `ModuleEntry::pre_tick_drain` (which mirrors the manifest
    /// flag). See `.context/rfc_isr_tier_surface.md` §D8.
    pub(crate) domain_pre_tick_order: [[u8; MAX_PRE_TICK_PER_DOMAIN]; MAX_DOMAINS],
    /// Number of pre-tick modules in each domain.
    pub(crate) domain_pre_tick_count: [u8; MAX_DOMAINS],
    /// Cumulative count of times the per-domain pre-tick combined
    /// budget (`MAX_PRE_TICK_BUDGET_US`) was exceeded, causing the
    /// remaining pre-tick modules in the list to skip the current
    /// pass. Surfaced via monitor telemetry.
    pub(crate) domain_pre_tick_overruns: [u32; MAX_DOMAINS],

    // ── Live Reconfigure State ──────────────────────────────────────
    /// Current reconfigure phase, queryable via `reconfigure_phase()`.
    pub(crate) reconfigure_phase: ReconfigurePhase,
    /// Number of modules in the current graph, set by `prepare_graph`.
    pub(crate) active_module_count: usize,
    /// Pending rebuild request (config_ptr, len). Set by `request_rebuild`,
    /// consumed by the per-platform main loop, which performs a destructive
    /// reset + reload.
    pub(crate) rebuild_request: Option<(*const u8, usize)>,
    /// Transaction marker for `prepare_graph`. Set true at the *start* of
    /// graph preparation (before any destructive `reset_*` call) and
    /// cleared once the new graph is fully wired. While set, `step_modules`
    /// short-circuits to `StepResult::Done` so a partially-built graph
    /// can't be observed by a racing scheduler tick.
    ///
    /// Stays set across an early-return failure path so a half-prepared
    /// SCHED is fail-safe until the *next* `prepare_graph` (which
    /// re-sets the marker before resetting state again).
    pub(crate) prepare_in_progress: bool,

    // ── Per-module export table info (for resolve_export_for_module) ──
    /// Code base address per module (for resolving export offsets)
    pub(crate) module_code_base: [usize; MAX_MODULES],
    /// Code size per module (for provider pointer validation)
    pub(crate) module_code_size: [u32; MAX_MODULES],
    /// Export table pointer per module
    pub(crate) module_export_table: [*const u8; MAX_MODULES],
    /// Export count per module
    pub(crate) module_export_count: [u16; MAX_MODULES],

    // ── Step timing histogram (8 log2 buckets) ─────────────────────
    /// Per-module bucket counts: <64us, <128, <256, <512, <1024, <2048, <4096, >=4096
    pub(crate) step_hist: [[u32; 8]; MAX_MODULES],
    /// Global bucket counts across all modules.
    pub(crate) step_hist_global: [u32; 8],
    /// Workload owner table (rfc_k8s.md §6.2, §10, §14).
    /// Slot 0 is the system owner. Size-1 (system only) on single-tenant
    /// builds, so it costs nothing meaningful when `multitenant` is off.
    pub owners: OwnerTable,
    /// Per-module owner handle. Present only on multi-tenant builds — bare
    /// metal carries no per-module ownership state (rfc_k8s.md §6.4, §19.2).
    #[cfg(feature = "multitenant")]
    pub(crate) module_owner: [OwnerHandle; MAX_MODULES],
}

impl SchedulerState {
    const fn new() -> Self {
        Self {
            edges: [Edge::simple(0, 0); MAX_CHANNELS],
            edge_count: 0,
            flow_last_fill: [0; MAX_CHANNELS],
            flow_stalls: [0; MAX_CHANNELS],
            modules: [const { ModuleSlot::Empty }; MAX_MODULES],
            ports: [ModulePorts::empty(); MAX_MODULES],
            hints: [ModuleHints::empty(); MAX_MODULES],
            finished: [false; MAX_MODULES],
            arenas: [const { ArenaInfo::empty() }; MAX_MODULES],
            cap_class: [0; MAX_MODULES],
            required_caps: [0; MAX_MODULES],
            permissions: [0; MAX_MODULES],
            module_params_ptr: [core::ptr::null(); MAX_MODULES],
            module_params_len: [0; MAX_MODULES],
            mailbox_safe: [false; MAX_MODULES],
            in_place_writer: [false; MAX_MODULES],
            deferred_ready: [false; MAX_MODULES],
            isolated: [false; MAX_MODULES],
            ready: [true; MAX_MODULES],
            upstream_mask: [ModuleMask::EMPTY; MAX_MODULES],
            completion_mask: [ModuleMask::EMPTY; MAX_MODULES],
            step_period: [0; MAX_MODULES],
            step_counter: [0; MAX_MODULES],
            module_next_due_us: [0; MAX_MODULES],
            module_idle_safe: [false; MAX_MODULES],
            inactive_for_ticks: [0; MAX_MODULES],
            slot_generation: [0; MAX_MODULES],
            drain_started_ms: u64::MAX,
            exec_order_offset: 0,
            domain_exec_order_offset: [0; MAX_DOMAINS],
            exec_order: [0; MAX_MODULES],
            exec_order_count: 0,
            graph_sample_rate: 0,
            tick_us: 0,
            module_latency: [0; MAX_MODULES],
            downstream_latency: [0; MAX_MODULES],
            fault_info: [ModuleFaultInfo::new(); MAX_MODULES],
            domain_id: [0; MAX_MODULES],
            pre_tick_drain: [false; MAX_MODULES],
            domain_exec_order: [[0; MAX_MODULES]; MAX_DOMAINS],
            domain_module_count: [0; MAX_DOMAINS],
            domain_count: 0,
            domain_tick_us: [0; MAX_DOMAINS],
            domain_exec_mode: [0; MAX_DOMAINS],
            domain_adaptive_flags: [0; MAX_DOMAINS],
            domain_tick_min_us: [0; MAX_DOMAINS],
            domain_tick_max_us: [0; MAX_DOMAINS],
            domain_budget_us_limit: [0; MAX_DOMAINS],
            domain_budget_us_consumed: [0; MAX_DOMAINS],
            domain_budget_overruns: [0; MAX_DOMAINS],
            domain_worst_step_us: [0; MAX_DOMAINS],
            domain_module_mask: [ModuleMask::EMPTY; MAX_DOMAINS],
            domain_pre_tick_order: [[0; MAX_PRE_TICK_PER_DOMAIN]; MAX_DOMAINS],
            domain_pre_tick_count: [0; MAX_DOMAINS],
            domain_pre_tick_overruns: [0; MAX_DOMAINS],
            reconfigure_phase: ReconfigurePhase::Running,
            active_module_count: 0,
            rebuild_request: None,
            prepare_in_progress: false,
            module_code_base: [0; MAX_MODULES],
            module_code_size: [0; MAX_MODULES],
            module_export_table: [core::ptr::null(); MAX_MODULES],
            module_export_count: [0; MAX_MODULES],
            step_hist: [[0; 8]; MAX_MODULES],
            step_hist_global: [0; 8],
            owners: OwnerTable::new(),
            #[cfg(feature = "multitenant")]
            module_owner: [OWNER_SYSTEM; MAX_MODULES],
        }
    }

    /// Reset all runtime state for a new graph setup.
    /// Does NOT reset state arena or name arena (separate concerns).
    pub(crate) fn reset(&mut self) {
        for i in 0..MAX_CHANNELS {
            self.edges[i] = Edge::simple(0, 0);
        }
        self.edge_count = 0;
        for i in 0..MAX_MODULES {
            self.modules[i] = ModuleSlot::Empty;
            self.ports[i] = ModulePorts::empty();
            self.hints[i] = ModuleHints::empty();
            self.finished[i] = false;
            self.arenas[i] = ArenaInfo::empty();
            self.cap_class[i] = 0;
            self.required_caps[i] = 0;
            self.permissions[i] = 0;
            self.mailbox_safe[i] = false;
            self.in_place_writer[i] = false;
            self.deferred_ready[i] = false;
            self.isolated[i] = false;
            self.ready[i] = true;
            self.upstream_mask[i] = ModuleMask::EMPTY;
            self.completion_mask[i] = ModuleMask::EMPTY;
            // Clear the per-module owner stamp; workload owner lifecycle in the
            // owner table is managed by the transition path, not here.
            #[cfg(feature = "multitenant")]
            {
                self.module_owner[i] = OWNER_SYSTEM;
            }
            self.step_period[i] = 0;
            self.step_counter[i] = 0;
            self.inactive_for_ticks[i] = 0;
            // Bump the generation on graph reset — every outstanding
            // snapshot of the previous graph's slot is now stale.
            // Wrapping ensures we keep producing fresh tokens across
            // many reconfigures without overflowing.
            self.slot_generation[i] = self.slot_generation[i].wrapping_add(1);
            self.module_latency[i] = 0;
            self.downstream_latency[i] = 0;
            self.fault_info[i] = ModuleFaultInfo::new();
            self.module_code_base[i] = 0;
            self.module_code_size[i] = 0;
            self.module_export_table[i] = core::ptr::null();
            self.module_export_count[i] = 0;
            self.step_hist[i] = [0; 8];
            self.pre_tick_drain[i] = false;
        }
        self.step_hist_global = [0; 8];
        self.exec_order_count = 0;
        self.graph_sample_rate = 0;
        self.tick_us = 0;
        self.domain_count = 0;
        for d in 0..MAX_DOMAINS {
            self.domain_module_count[d] = 0;
            self.domain_tick_us[d] = 0;
            self.domain_adaptive_flags[d] = 0;
            self.domain_tick_min_us[d] = 0;
            self.domain_tick_max_us[d] = 0;
            self.domain_budget_us_limit[d] = 0;
            self.domain_budget_us_consumed[d] = 0;
            self.domain_budget_overruns[d] = 0;
            self.domain_worst_step_us[d] = 0;
            self.domain_module_mask[d] = ModuleMask::EMPTY;
            self.domain_exec_order_offset[d] = 0;
            self.domain_pre_tick_count[d] = 0;
            self.domain_pre_tick_overruns[d] = 0;
            for i in 0..MAX_PRE_TICK_PER_DOMAIN {
                self.domain_pre_tick_order[d][i] = 0;
            }
        }
        self.reconfigure_phase = ReconfigurePhase::Running;
        self.active_module_count = 0;
        self.rebuild_request = None;
        self.drain_started_ms = u64::MAX;
        self.exec_order_offset = 0;
        // `prepare_in_progress` is intentionally NOT cleared here. The
        // marker is owned by `prepare_graph`, which sets it *before*
        // calling `reset()` and clears it once preparation completes.
        // Resetting here would race the marker the caller just set.
    }
}

pub(crate) static mut SCHED: SchedulerState = SchedulerState::new();

/// Get a mutable reference to the scheduler state.
///
/// # Safety
/// Caller must ensure exclusive access.
pub unsafe fn sched_mut() -> &'static mut SchedulerState {
    let p = &raw mut SCHED;
    &mut *p
}

/// Get an immutable reference to the scheduler state.
///
/// # Safety
/// Returns a `&'static` aliasing `SCHED`. Caller must not hold a
/// concurrent `sched_mut()` borrow; in practice the kernel calls this
/// only from the single owning core's main loop / step path.
pub unsafe fn sched_ref() -> &'static SchedulerState {
    let p = &raw const SCHED;
    &*p
}

/// Get a mutable reference to the modules array.
///
/// # Safety
/// Returns an exclusive `&mut` to `SCHED.modules`. Caller must hold no
/// other reference (mutable or shared) to `SCHED` for the returned
/// reference's lifetime. Use only from the single boot/owning core
/// during reconfigure or platform-init paths.
pub unsafe fn sched_modules() -> &'static mut [ModuleSlot; MAX_MODULES] {
    let p = &raw mut SCHED;
    &mut (*p).modules
}

/// Get a mutable reference to the static param buffer.
///
/// # Safety
/// Returns an exclusive `&mut` to the static `PARAM_BUFFER`. Caller
/// must ensure single-threaded access — used during config-time param
/// staging before modules are stepped.
pub unsafe fn param_buffer_mut() -> &'static mut ParamBuffer {
    &mut *core::ptr::addr_of_mut!(PARAM_BUFFER)
}

/// Per-core current module index (supports multi-core BCM2712).
/// On single-core platforms, only index 0 is used. Avoids data races
/// when multiple cores step modules concurrently.
static CURRENT_MODULE_PER_CORE: [portable_atomic::AtomicU32; MAX_DOMAINS] =
    [const { portable_atomic::AtomicU32::new(0) }; MAX_DOMAINS];

/// Return the index of the module currently being stepped.
/// Used by event::event_create() to set event ownership.
pub fn current_module_index() -> usize {
    let core = crate::kernel::sys::hal::core_id();
    CURRENT_MODULE_PER_CORE[core].load(portable_atomic::Ordering::Relaxed) as usize
}

/// Return the module index a specific core is currently stepping. Lets a
/// sibling core (e.g. core 0) identify which module another core is stuck in
/// when that core's tick count has frozen — a cross-core hang diagnostic.
pub fn module_index_on_core(core: usize) -> usize {
    if core >= MAX_DOMAINS {
        return 0;
    }
    CURRENT_MODULE_PER_CORE[core].load(portable_atomic::Ordering::Relaxed) as usize
}

/// Set the current module index. Used by provider dispatch for context switching.
pub fn set_current_module(idx: usize) {
    let core = crate::kernel::sys::hal::core_id();
    CURRENT_MODULE_PER_CORE[core].store(idx as u32, portable_atomic::Ordering::Relaxed);
}

/// Get the state pointer for a module by index.
/// Returns null if the slot is empty or not a dynamic module.
/// State pointer for the module currently being instantiated (set during module_new).
/// Lets syscalls made from inside `module_new()` find the module by
/// index → state pointer (e.g. heap ops, provider registration).
static mut INSTANTIATION_STATE: *mut u8 = core::ptr::null_mut();
static mut INSTANTIATION_IDX: usize = usize::MAX;

/// Set the instantiation state pointer (called before module_new).
pub fn set_instantiation_state(idx: usize, state: *mut u8) {
    // SAFETY: scheduler-thread-only mutation; set/clear bracket each module_new.
    unsafe {
        INSTANTIATION_STATE = state;
        INSTANTIATION_IDX = idx;
    }
}

/// Clear the instantiation state pointer (called after module_new).
pub fn clear_instantiation_state() {
    // SAFETY: scheduler-thread-only mutation.
    unsafe {
        INSTANTIATION_STATE = core::ptr::null_mut();
        INSTANTIATION_IDX = usize::MAX;
    }
}

/// Persistent per-module state-pointer shadow. The RP path populates
/// `SCHED.modules` directly, but the bcm2712 domain-instantiator keeps
/// modules in `DOMAIN_MODULES` and leaves `SCHED.modules` empty — so a
/// late-bound registration syscall (e.g. `BACKING_PROVIDER_ENABLE` in
/// `step_ready`, long after `module_new`) can't find the state through
/// `SCHED.modules`. This shadow is set by both paths and read as the
/// second-choice source in `get_module_state`.
static mut MODULE_STATE_PTR: [*mut u8; MAX_MODULES] = [core::ptr::null_mut(); MAX_MODULES];

/// Publish a module's state pointer for later syscall lookups. Callable
/// from any platform after a module's state has been allocated.
pub fn set_module_state_ptr(idx: usize, state: *mut u8) {
    if idx >= MAX_MODULES {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; idx bounded.
    unsafe {
        MODULE_STATE_PTR[idx] = state;
    }
}

pub fn get_module_state(idx: usize) -> *mut u8 {
    if idx >= MAX_MODULES {
        return core::ptr::null_mut();
    }
    // SAFETY: scheduler-thread-only access; idx bounded; the SCHED.modules
    // entry / MODULE_STATE_PTR shadow / INSTANTIATION_STATE union covers
    // every platform's lifecycle stage.
    unsafe {
        // During module_new, the module isn't stored in SCHED yet
        if idx == INSTANTIATION_IDX && !INSTANTIATION_STATE.is_null() {
            return INSTANTIATION_STATE;
        }
        match &SCHED.modules[idx] {
            ModuleSlot::Dynamic(m) => m.state_ptr(),
            _ => {
                // Fall back to the shadow array populated by platforms
                // that don't store modules in SCHED.modules (bcm2712).
                MODULE_STATE_PTR[idx]
            }
        }
    }
}

/// Return the capability class of the module currently being stepped.
/// Used by `check_contract_grant` to gate `provider_*` dispatch.
pub fn current_module_cap_class() -> u8 {
    let idx = current_module_index();
    // Guard the sentinel/out-of-range index: a live-added module can make a
    // provider_call before CURRENT_MODULE_PER_CORE is set to its slot, leaving idx
    // at the "no module" sentinel (== MAX_MODULES). Fall back to class 0 rather than
    // index a fixed [_; MAX_MODULES] array out of bounds.
    if idx >= MAX_MODULES {
        return 0;
    }
    // SAFETY: idx bounded above; scheduler-thread-only read.
    unsafe { SCHED.cap_class[idx] }
}

/// Return the required_caps bitmask of the module currently being stepped.
/// Bit N set = module declared it needs contract id N in its manifest.
/// Contract bits only — internal-orchestration permission is in
/// `current_module_internal_permission`.
pub fn current_module_required_caps() -> u32 {
    let idx = current_module_index();
    // Same sentinel guard as current_module_cap_class (a live-added module's early
    // provider_call can read the "no module" sentinel index).
    if idx >= MAX_MODULES {
        return 0;
    }
    // SAFETY: idx bounded above; scheduler-thread-only read.
    unsafe { SCHED.required_caps[idx] }
}

/// Return the fine-grained permission bitmap of the module currently
/// being stepped. Each bit corresponds to a privileged-opcode category
/// — see the `permission` module in `syscalls.rs`.
pub fn current_module_permissions() -> u16 {
    let idx = current_module_index();
    // SAFETY: scheduler-thread-only read.
    unsafe { SCHED.permissions[idx] }
}

/// Return the export table info for a module by index.
/// Used by loader::resolve_export_for_module to resolve export hashes.
pub fn get_module_exports(idx: usize) -> (usize, *const u8, u16) {
    if idx >= MAX_MODULES {
        return (0, core::ptr::null(), 0);
    }
    // SAFETY: scheduler-thread-only read; idx bounded.
    unsafe {
        (
            SCHED.module_code_base[idx],
            SCHED.module_export_table[idx],
            SCHED.module_export_count[idx],
        )
    }
}

/// Set the export table info for a module (used by Linux platform loader).
pub fn set_module_exports(
    idx: usize,
    code_base: usize,
    export_table: *const u8,
    export_count: u16,
) {
    if idx >= MAX_MODULES {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; idx bounded.
    unsafe {
        SCHED.module_code_base[idx] = code_base;
        SCHED.module_export_table[idx] = export_table;
        SCHED.module_export_count[idx] = export_count;
    }
}

/// Get the code region (base, size) for a module, used for provider pointer validation.
pub fn module_code_region(idx: usize) -> (usize, u32) {
    if idx >= MAX_MODULES {
        return (0, 0);
    }
    // SAFETY: scheduler-thread-only read; idx bounded.
    unsafe { (SCHED.module_code_base[idx], SCHED.module_code_size[idx]) }
}

/// Set the capability class, required_caps, and permissions bitmap for
/// a module (used by the Linux / bcm2712 platform loaders when they
/// stage modules from their embedded images).
pub fn set_module_caps(idx: usize, cap_class: u8, required_caps: u32, permissions: u16) {
    if idx >= MAX_MODULES {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; idx bounded.
    unsafe {
        SCHED.cap_class[idx] = cap_class;
        SCHED.required_caps[idx] = required_caps;
        SCHED.permissions[idx] = permissions;
    }
}

/// Register a module's per-instance params blob so the
/// `MODULE_INSTANCE_PARAMS` provider_query opcode can return it.
///
/// The pointer must remain valid for the life of the graph — for
/// native loaders this means the params live in the mmap'd / flashed
/// modules image, for wasm it means the embedded config blob in the
/// kernel `.wasm`. Both are stable.
///
/// # Safety
/// `ptr` must point at `len` readable bytes that outlive the module's
/// scheduler entry.
pub unsafe fn set_module_params(idx: usize, ptr: *const u8, len: usize) {
    if idx >= MAX_MODULES {
        return;
    }
    SCHED.module_params_ptr[idx] = ptr;
    SCHED.module_params_len[idx] = len;
}

/// Look up the params blob registered via `set_module_params`. Returns
/// `(ptr, len)` — `(null, 0)` if the loader didn't register any.
pub fn module_params(idx: usize) -> (*const u8, usize) {
    if idx >= MAX_MODULES {
        return (core::ptr::null(), 0);
    }
    // SAFETY: scheduler-thread-only read; idx bounded.
    unsafe { (SCHED.module_params_ptr[idx], SCHED.module_params_len[idx]) }
}

/// Store a BuiltInModule in the scheduler's module table (used by Linux platform).
pub fn store_builtin_module(idx: usize, m: BuiltInModule) {
    if idx >= MAX_MODULES {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; idx bounded.
    unsafe {
        SCHED.modules[idx] = ModuleSlot::BuiltIn(m);
        SCHED.ready[idx] = true;
        // Bump the slot generation on replacement so async consumers
        // can detect a slot reuse.
        SCHED.slot_generation[idx] = SCHED.slot_generation[idx].wrapping_add(1);
    }
}

/// Install an internal fan module (`_tee` / `_merge`) at `idx`,
/// collecting its channels from the prepared `sched.edges`.
///
/// The Linux / bare-metal path instantiates tee/merge inside
/// [`instantiate_one_module`]; the wasm platform runs its own
/// per-module bring-up loop (`src/platform/wasm.rs`) that dispatches
/// host built-ins by name and otherwise host-instantiates PIC modules —
/// it has no PIC `.fmod` for the kernel-internal fan modules, so without
/// this the inserted `_merge`/`_tee` is never given a `ModuleSlot` and
/// silently forwards nothing (fan-in into a consumer port delivers no
/// data). This is the wasm equivalent of that instantiation; returns
/// `false` if the port shape is invalid.
pub fn install_fan_module(idx: usize, is_merge: bool, domain_id: u8, frame_kind: u8) -> bool {
    if idx >= MAX_MODULES {
        return false;
    }
    // SAFETY: graph-prep / bring-up context — single mutator, idx bounded.
    let sched = unsafe { &mut *core::ptr::addr_of_mut!(SCHED) };
    let mut in_chans = [-1i32; MAX_CHANNELS];
    let mut out_chans = [-1i32; MAX_CHANNELS];
    let in_count = collect_input_channels(&sched.edges, idx, &mut in_chans);
    let out_count = collect_output_channels(&sched.edges, idx, &mut out_chans);
    let domain = (domain_id as usize).min(MAX_DOMAINS - 1) as u8;
    if is_merge {
        if out_count != 1 || in_count == 0 {
            log::error!("[inst] wasm merge idx={idx} invalid ports in={in_count} out={out_count}");
            return false;
        }
        sched.modules[idx] = ModuleSlot::Merge(MergeModule::new(
            &in_chans,
            in_count,
            out_chans[0],
            domain,
            frame_kind,
        ));
    } else {
        if in_count != 1 || out_count == 0 {
            log::error!("[inst] wasm tee idx={idx} invalid ports in={in_count} out={out_count}");
            return false;
        }
        sched.modules[idx] = ModuleSlot::Tee(TeeModule::new(
            in_chans[0],
            &out_chans,
            out_count,
            domain,
            frame_kind,
        ));
    }
    sched.ready[idx] = true;
    sched.slot_generation[idx] = sched.slot_generation[idx].wrapping_add(1);
    true
}

/// Store a DynamicModule in the scheduler's module table (used by Linux platform).
pub fn store_dynamic_module(idx: usize, dm: DynamicModule) {
    if idx >= MAX_MODULES {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; idx bounded.
    unsafe {
        SCHED.modules[idx] = ModuleSlot::Dynamic(dm);
        // See store_builtin_module — same rationale.
        SCHED.slot_generation[idx] = SCHED.slot_generation[idx].wrapping_add(1);
    }
}

/// Return the graph-level sample rate (0 = not configured).
pub fn graph_sample_rate() -> u32 {
    // SAFETY: scheduler-thread-only read.
    unsafe { SCHED.graph_sample_rate }
}

/// Snapshot of the currently-loaded graph's top-level identity. Used by
/// diagnostics and
/// by tools that need to fingerprint a running configuration without
/// re-reading the binary blob (e.g. to skip a reconfigure when the
/// proposed graph hash matches what's already loaded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphSnapshot {
    /// CRC16-CCITT over the binary config body — same value the loader
    /// validates against `header.checksum`. `0` means the producer
    /// didn't include a checksum.
    pub config_checksum: u16,
    /// Active module count in the compiled graph.
    pub module_count: u8,
    /// Compiled edge count.
    pub edge_count: u8,
    /// Tick interval in microseconds (`0` = default `DEFAULT_TICK_US`).
    pub tick_us: u32,
    /// Graph-level sample rate (`0` = not configured).
    pub sample_rate: u32,
    /// Number of modules in `exec_order` (post-topological-sort length).
    pub exec_order_count: usize,
}

/// Build a `GraphSnapshot` from the current `STATIC_CONFIG` and `SCHED`.
/// Safe to call after `populate_static_state` + `prepare_graph` have run;
/// before that returns a zero-filled snapshot (every field 0).
pub fn graph_snapshot() -> GraphSnapshot {
    // SAFETY: scheduler-thread-only read; static_config/SCHED stable
    // after populate_static_state + prepare_graph.
    let cfg = unsafe {
        let p = &raw const STATIC_CONFIG;
        &*p
    };
    // SAFETY: as above.
    let sched = unsafe {
        let p = &raw const SCHED;
        &*p
    };
    GraphSnapshot {
        config_checksum: cfg.header.checksum,
        module_count: cfg.header.module_count,
        edge_count: cfg.header.edge_count,
        tick_us: cfg.header.tick_us as u32,
        sample_rate: sched.graph_sample_rate,
        exec_order_count: sched.exec_order_count,
    }
}

/// Set the graph-level sample rate (called from config parsing).
pub fn set_graph_sample_rate(rate: u32) {
    // SAFETY: scheduler-thread-only mutation; called from config parse.
    unsafe {
        SCHED.graph_sample_rate = rate;
    }
}

/// Return the configured tick period in microseconds.
pub fn tick_us() -> u32 {
    // SAFETY: scheduler-thread-only read.
    let t = unsafe { SCHED.tick_us };
    if t == 0 {
        DEFAULT_TICK_US
    } else {
        t
    }
}

/// MODULE_FLOW_BUDGET: per-step byte grant for one of the calling module's
/// ports, derived from the wired edge's rate class and the
/// module's domain cadence.
///
/// Grant rates are PACING targets, deliberately above the validation
/// floors (floor = minimum acceptable provisioning; grant = what a
/// healthy stream is paced at):
///   control → 0 (no grant — modules keep their own unit-per-step
///   pacing; a derived control grant could only regress them),
///   audio → 4 MB/s, video → 24 MB/s, bulk → 96 MB/s,
///   transaction → 4 MB/s.
///
/// Per-step grant = rate × domain tick period, clamped to
/// [1 KiB, 256 KiB] so one step can neither starve nor monopolise.
/// Uses the period currently selected by the adaptive-tick pacer, falling
/// back to the configured cadence before the first pacing decision.
/// Semantic priority of a rate class, independent of its wire discriminant.
/// `Transaction` (discriminant 4) is latency-sensitive request/response traffic
/// that sits just above `control`, NOT above the media classes — so raw
/// discriminant order (`control 0 < audio 1 < video 2 < bulk 3 < transaction 4`)
/// must not be used to pick the governing class on a port. Mirrors the build-time
/// ordering in `tools/src/config.rs::validate_wiring_capacity`.
fn rate_class_rank(class: u8) -> u8 {
    match class {
        0 => 0, // control
        4 => 1, // transaction
        1 => 2, // audio
        2 => 3, // video
        3 => 4, // bulk
        _ => 0,
    }
}

fn flow_budget_for_class(class: u8, domain: usize) -> i32 {
    let rate_bytes_per_sec: u64 = match class {
        1 => 4 * 1024 * 1024,
        2 => 24 * 1024 * 1024,
        3 => 96 * 1024 * 1024,
        4 => 4 * 1024 * 1024,
        _ => return 0,
    };
    let tick_us = pacer_current_period_us(domain.min(MAX_DOMAINS - 1)).max(1) as u64;
    let grant = rate_bytes_per_sec * tick_us / 1_000_000;
    grant.clamp(1024, 256 * 1024) as i32
}

pub fn syscall_flow_budget(port_index: u8) -> i32 {
    let idx = current_module_index();
    if idx >= MAX_MODULES {
        return 0;
    }
    // SAFETY: scheduler-thread read of SCHED edge/domain tables.
    let (class, domain) = unsafe {
        let p = &raw const SCHED;
        let sched = &*p;
        let mut class = 0u8;
        for e in sched.edges.iter().take(sched.edge_count) {
            if e.from_module == idx
                && e.from_port_index == port_index
                && rate_class_rank(e.rate_class) > rate_class_rank(class)
            {
                class = e.rate_class;
            }
        }
        (class, sched.domain_id[idx] as usize)
    };
    flow_budget_for_class(class, domain)
}

/// Input-port consumption budget. The logical port index is the stable graph
/// contract. The channel descriptor is payload data (never a provider handle)
/// and resolves runtime bridge/repacking aliases when necessary.
pub fn syscall_input_flow_budget(port_index: u8, channel: i32) -> i32 {
    let idx = current_module_index();
    if idx >= MAX_MODULES {
        return 0;
    }
    // SAFETY: scheduler-thread single accessor of SCHED, read through a raw pointer.
    let (class, domain) = unsafe {
        let p = &raw const SCHED;
        let sched = &*p;
        let mut class = 0u8;
        let mut sole_classed = 0u8;
        let mut classed_inputs = 0u8;
        for e in sched.edges.iter().take(sched.edge_count) {
            if e.to_module == idx && e.rate_class != 0 {
                classed_inputs = classed_inputs.saturating_add(1);
                sole_classed = e.rate_class;
            }
            let owns_port = e.to_module == idx && e.to_port_index == port_index;
            let owns_channel = channel >= 0
                && e.to_module == idx
                && (e.channel == channel || e.consumer_channel == channel);
            if (owns_port || owns_channel) && rate_class_rank(e.rate_class) > rate_class_rank(class)
            {
                class = e.rate_class;
            }
        }
        // Fall back only when the module has exactly one classed input, making
        // the association unambiguous. Multiple classed inputs must identify
        // their graph port or fail closed.
        if class == 0 && classed_inputs == 1 {
            class = sole_classed;
        }
        (class, sched.domain_id[idx] as usize)
    };
    flow_budget_for_class(class, domain)
}

pub fn domain_tick_us(domain_id: usize) -> u32 {
    if domain_id < MAX_DOMAINS {
        // SAFETY: scheduler-thread-only read; domain_id bounded.
        let t = unsafe { SCHED.domain_tick_us[domain_id] };
        if t > 0 {
            return t;
        }
    }
    tick_us()
}

/// Return the per-domain worst-recent single-step time in microseconds — the
/// §5.3 adaptive-tick floor input (decaying peak-hold, NOT a monotonic max).
/// The pacer clamps `tick_min_us` up by `worst × margin` so a shortened tick
/// never shrinks the per-domain budget below one heavy step (evidence #5).
/// `0` until the domain has stepped at least once.
pub fn domain_worst_step_us(domain_id: usize) -> u32 {
    if domain_id < MAX_DOMAINS {
        // SAFETY: scheduler-thread-only read; domain_id bounded.
        unsafe { SCHED.domain_worst_step_us[domain_id] }
    } else {
        0
    }
}

/// True iff any module belonging to `domain_id` has a pending event
/// (non-consuming peek). The per-domain wake signal for the adaptive-tick pacer
/// (RFC adaptive_tick §5.1): a domain only counts its own
/// modules' wakes, so a busy sibling domain can't keep this domain from
/// relaxing/idling on multicore. If the domain's module mask is empty
/// (unconfigured/degenerate domain) it falls back to the global wake signal, so
/// a missing mask can never produce a false "idle" (which would over-relax the
/// tick and risk a missed wake).
pub fn domain_wake_pending(domain_id: usize) -> bool {
    let d = domain_id.min(MAX_DOMAINS - 1);
    // SAFETY: scheduler-thread-only read; `ModuleMask` is `Copy`.
    let mask = unsafe { SCHED.domain_module_mask[d] };
    if mask.is_empty() {
        return crate::kernel::ipc::event::wake_pending_nonzero();
    }
    crate::kernel::ipc::event::wake_pending_in_mask(&mask)
}

/// Adaptive-tick enable flags for a domain (RFC adaptive_tick §8): bit 0 =
/// (a) demand-driven idle, bit 1 = (b) adaptive cadence. `0` ⇒ adaptive off.
pub fn domain_adaptive_flags(domain_id: usize) -> u8 {
    if domain_id < MAX_DOMAINS {
        // SAFETY: scheduler-thread-only read; domain_id bounded.
        unsafe { SCHED.domain_adaptive_flags[domain_id] }
    } else {
        0
    }
}

/// Per-domain adaptive latency-floor target (µs). Default-filled to the
/// domain's tick when unconfigured, so it is a safe lower bound for the pacer.
pub fn domain_tick_min_us(domain_id: usize) -> u32 {
    if domain_id < MAX_DOMAINS {
        // SAFETY: scheduler-thread-only read; domain_id bounded.
        let v = unsafe { SCHED.domain_tick_min_us[domain_id] };
        if v > 0 {
            return v;
        }
    }
    domain_tick_us(domain_id)
}

/// Per-domain adaptive relaxed/idle backstop cadence (µs). Default-filled to
/// the domain's tick when unconfigured (so an un-opted domain never relaxes).
pub fn domain_tick_max_us(domain_id: usize) -> u32 {
    if domain_id < MAX_DOMAINS {
        // SAFETY: scheduler-thread-only read; domain_id bounded.
        let v = unsafe { SCHED.domain_tick_max_us[domain_id] };
        if v > 0 {
            return v;
        }
    }
    domain_tick_us(domain_id)
}

/// Test-only: plant a domain's adaptive config (flags + tick_min/max µs)
/// without a full `install_static_config`. Production sets these from the
/// config blob in `prepare_graph`; conformance tests use this to exercise the
/// pacer / hot-start paths directly.
pub fn set_domain_adaptive_for_test(
    domain_id: usize,
    flags: u8,
    tick_min_us: u32,
    tick_max_us: u32,
) {
    if domain_id >= MAX_DOMAINS {
        return;
    }
    // SAFETY: scheduler-thread-exclusive mutation; domain_id bounded.
    unsafe {
        SCHED.domain_adaptive_flags[domain_id] = flags;
        SCHED.domain_tick_min_us[domain_id] = tick_min_us;
        SCHED.domain_tick_max_us[domain_id] = tick_max_us;
    }
}

/// Test-only: set a module slot's tick-counted step period. Production sets this
/// from the config/manifest in `prepare_graph` / `apply_add`; conformance tests
/// use it to exercise the period-gated runnable path (a multi-tick module must
/// keep its owning graph on the cooperative cadence — never idle-skipped).
pub fn set_step_period_for_test(slot: usize, period: u8) {
    if slot < MAX_MODULES {
        // SAFETY: scheduler-thread-exclusive mutation; slot bounded.
        unsafe {
            SCHED.step_period[slot] = period;
        }
    }
}

/// Test-only: put a module slot into (or out of) the "deferred-ready, still
/// initialising" state the §6.5 fail-closed `must_tick` predicate keys on — a
/// deferred-ready module that has not reached Ready must keep stepping even when
/// the graph is otherwise idle, or it could never finish initialising.
pub fn set_module_init_state_for_test(slot: usize, initialising: bool) {
    if slot < MAX_MODULES {
        // SAFETY: scheduler-thread-exclusive mutation; slot bounded.
        unsafe {
            SCHED.deferred_ready[slot] = initialising;
            SCHED.ready[slot] = !initialising;
        }
    }
}

/// Test-only: set a module slot's idle-safe attestation (production sets it from
/// the workload's FXPD flag at admission). Only an all-idle-safe graph may be fully
/// parked; an unattested workload is fail-closed to the `tick_max` backstop.
pub fn set_module_idle_safe_for_test(slot: usize, idle_safe: bool) {
    if slot < MAX_MODULES {
        // SAFETY: scheduler-thread-exclusive mutation; slot bounded.
        unsafe {
            SCHED.module_idle_safe[slot] = idle_safe;
        }
    }
}

/// Mark every module currently owned by `owner` as idle-safe (or not) — the
/// admission-time application of a workload's FXPD idle-safe attestation. Bounded
/// boot-time pass; the resident-graph index's per-graph `idle_safe` is recomputed
/// by the following `rebuild_resident_graph_index`. No-op on non-multitenant.
#[cfg(feature = "multitenant")]
pub fn set_owner_idle_safe(owner: crate::kernel::workload::owner::OwnerHandle, idle_safe: bool) {
    // SAFETY: scheduler-thread-exclusive boot context.
    let sched = unsafe { &mut *core::ptr::addr_of_mut!(SCHED) };
    for i in 0..MAX_MODULES {
        if matches!(sched.modules[i], ModuleSlot::Empty) {
            continue;
        }
        if sched.module_owner[i] == owner {
            sched.module_idle_safe[i] = idle_safe;
        }
    }
}

/// Bit 0 of `domain_adaptive_flags` — mechanism (a) demand-driven idle enabled.
pub const ADAPTIVE_FLAG_IDLE: u8 = 0x01;
/// Bit 1 of `domain_adaptive_flags` — mechanism (b) adaptive cadence enabled.
pub const ADAPTIVE_FLAG_CADENCE: u8 = 0x02;

// ── Mechanism (b) AIMD cadence tunables (RFC adaptive_tick §5.2/§5.3) ────────
// These are PLACEHOLDER defaults — OQ1 marks the exact values as rig-tuned on
// the cooled Pi 5. The locked design constraints they must respect: AIMD is
// asymmetric (fast multiplicative decrease on busy, slow additive increase on
// idle); the minimum dwell must be ≥ the workload's burst inter-arrival or the
// cadence sawtooths (§5.2); levels are discrete to bound step-counted rescaling
// and keep diagnostics legible.
/// Floor margin: the pacer never drives the tick below `worst_step ×
/// FLOOR_MARGIN` (so the per-domain budget always fits one heavy step —
/// evidence #5). 2× leaves headroom for the rest of the pass.
const FLOOR_MARGIN: u32 = 2;
/// Consecutive busy passes required before stepping the cadence DOWN (faster).
const PACER_BUSY_RUN_N: u16 = 2;
/// Consecutive idle passes required before stepping the cadence UP (relax).
const PACER_IDLE_RUN_M: u16 = 4;
/// Minimum wall-clock dwell between cadence-level changes, µs. MUST be ≥ the
/// expected burst inter-arrival for the workload (§5.2) — placeholder, rig-tuned.
const PACER_MIN_DWELL_US: u64 = 2_000;
/// Max discrete level index (deadline = `tick_max >> idx`, clamped to floor).
/// Caps the geometric ladder depth; the floor clamp usually bites first.
const PACER_MAX_LEVEL: u8 = 12;

/// Cadence deadband. Hold the previously-applied deadline unless a new candidate
/// differs by more than `last >> PACER_DEADBAND_SHIFT` (≈6.25%), floored at
/// `PACER_DEADBAND_MIN_US`. This suppresses sub-µs floor jitter from
/// `domain_worst_step_us` measurement noise (e.g. 750↔752 → floor 1500↔1504),
/// which would otherwise dither the cadence and spam `MON_PACER_LEVEL` (AC6).
/// Real ladder steps (≥2×) and load/thermal floor moves always clear the band.
const PACER_DEADBAND_SHIFT: u32 = 4;
const PACER_DEADBAND_MIN_US: u32 = 16;

/// Per-domain mechanism-(b) pacer state. Touched only by the domain's own
/// scheduler pass (single-threaded on Linux/rp; per-core-exclusive on
/// bcm2712, like `DOMAIN_METRICS`), so a plain `static mut` is sound.
#[derive(Clone, Copy)]
pub(crate) struct PacerState {
    /// Discrete level index: 0 = `tick_max` (relaxed); higher = faster.
    level_idx: u8,
    busy_run: u16,
    idle_run: u16,
    /// `now_micros()` of the last level change (dwell gate).
    last_change_us: u64,
    /// Last reported deadline, so MON_PACER_LEVEL only logs real changes.
    last_reported_us: u32,
    init: bool,
}
impl PacerState {
    const fn new() -> Self {
        Self {
            level_idx: 0,
            busy_run: 0,
            idle_run: 0,
            last_change_us: 0,
            last_reported_us: 0,
            init: false,
        }
    }
}
static mut PACER: [PacerState; MAX_DOMAINS] = [PacerState::new(); MAX_DOMAINS];

/// Per-domain "currently in demand-driven idle" latch, so MON_PACER_IDLE_SLEEP
/// logs once per busy→idle transition (low-rate) rather than every idle pass.
static PACER_IDLE_REPORTED: [AtomicBool; MAX_DOMAINS] =
    [const { AtomicBool::new(false) }; MAX_DOMAINS];

/// Per-domain "was the previous pass idle" latch, for the §6.6 hot-start
/// transition detector (RFC adaptive_tick_extra). An idle→busy edge arms the
/// hot-start window.
static PACER_WAS_IDLE: [AtomicBool; MAX_DOMAINS] = [const { AtomicBool::new(false) }; MAX_DOMAINS];

/// Per-domain hot-start passes remaining (§6.6). After a wake-from-idle the
/// pacer runs this many busy passes at the §5.3 floor (the tightest safe
/// cadence) instead of slowly ramping down from the relaxed `tick_max`, so a
/// request-response pipeline's return hops don't each wait a full `tick_max`
/// gap. Bounded window; never bypasses Burst/budget/floor guards.
static PACER_HOTSTART: [portable_atomic::AtomicU8; MAX_DOMAINS] =
    [const { portable_atomic::AtomicU8::new(0) }; MAX_DOMAINS];

/// Period most recently selected for each domain's next scheduler pass.
/// A zero value means no pacing decision has occurred since graph prepare;
/// callers then fall back to the configured nominal cadence.
static PACER_CURRENT_PERIOD_US: [AtomicU32; MAX_DOMAINS] =
    [const { AtomicU32::new(0) }; MAX_DOMAINS];

fn record_pacer_period_us(domain_id: usize, period_us: u32) -> u32 {
    PACER_CURRENT_PERIOD_US[domain_id.min(MAX_DOMAINS - 1)]
        .store(period_us.max(1), Ordering::Relaxed);
    period_us.max(1)
}

/// Period currently governing per-step flow budgets for a domain.
pub fn pacer_current_period_us(domain_id: usize) -> u32 {
    let period = PACER_CURRENT_PERIOD_US[domain_id.min(MAX_DOMAINS - 1)].load(Ordering::Relaxed);
    if period == 0 {
        domain_tick_us(domain_id)
    } else {
        period
    }
}

/// Hot-start window length in passes (§6.6). Matched to the bounded pipeline
/// hop budget so the first request after idle converges at the floor rather
/// than the relaxed tick.
const PACER_HOTSTART_PASSES: u8 = MAX_PIPELINE_PASSES as u8;

/// Compute the §5.3 per-domain floor (µs): never below `tick_min_us`, raised by
/// the live decaying worst-step so a shortened tick can't shrink the budget
/// below one heavy step. Clamped not to exceed `tick_max_us`.
fn pacer_floor_us(domain_id: usize, tick_max: u32) -> u32 {
    let tick_min = domain_tick_min_us(domain_id);
    let worst = domain_worst_step_us(domain_id);
    tick_min
        .max(worst.saturating_mul(FLOOR_MARGIN))
        .min(tick_max)
}

/// Public accessor: the live §5.3 effective floor (µs) for `domain_id` right now
/// — `max(tick_min_us, worst_step × FLOOR_MARGIN)`, clamped to `tick_max_us`.
/// `pacer_next_deadline_us` never returns below this. A platform that further
/// clamps the armed deadline (e.g. bcm2712's software-wake latency clamp) MUST
/// NOT arm below it: doing so would run a heavy domain faster than its
/// worst-step budget admits, breaking the budget/floor contract. Reconcile as
/// `raw.min(clamp.max(pacer_domain_floor_us(d)))`.
pub fn pacer_domain_floor_us(domain_id: usize) -> u32 {
    let tick_max = domain_tick_max_us(domain_id);
    pacer_floor_us(domain_id, tick_max)
}

/// Reset all mechanism-(a)/(b) pacer state to boot defaults. The pacer statics
/// (`PACER`, `PACER_IDLE_REPORTED`, `PACER_BURST_TICK`) live OUTSIDE `Sched`, so
/// `Sched::reset()` does not touch them. `prepare_graph` calls this on every
/// (re)configuration: without it a rebuilt graph would inherit the prior graph's
/// `level_idx`, dwell timestamps, deadband (`last_reported_us`), idle-report
/// latch, and burst accumulator — making the new graph's first cadence decision
/// a function of the OLD config/load instead of purely the new one. Runs
/// single-threaded during reconfigure, before any domain pump steps the new
/// graph, so there is no concurrent pacer access.
pub(crate) fn pacer_reset_all() {
    for d in 0..MAX_DOMAINS {
        // SAFETY: single-threaded reconfigure (no concurrent pacer pass);
        // `&raw mut` forms a pointer to the static-mut element without a
        // reference (avoids static_mut_refs), mirroring `pacer_apply_cadence`.
        let slot = unsafe { &raw mut PACER[d] };
        // SAFETY: exclusive write of the Copy state during reconfigure.
        unsafe { *slot = PacerState::new() };
        PACER_IDLE_REPORTED[d].store(false, Ordering::Relaxed);
        PACER_BURST_TICK[d].store(false, Ordering::Relaxed);
        PACER_WORK_TICK[d].store(false, Ordering::Relaxed);
        PACER_WAS_IDLE[d].store(false, Ordering::Relaxed);
        PACER_HOTSTART[d].store(0, Ordering::Relaxed);
        PACER_CURRENT_PERIOD_US[d].store(0, Ordering::Relaxed);
    }
    // §7 graph-local pacer table — same reconfigure reset (a reused graph slot
    // must not inherit the prior graph's heat).
    graph_pacer_reset_all();
}

/// Drive the mechanism-(b) pacer to its fully-relaxed level (`tick_max`). Called
/// on the mechanism-(a) demand-idle path: (a) returns `tick_max` directly WITHOUT
/// running the (b) AIMD ladder, so without this the (b) `level_idx` /
/// `last_reported_us` stay frozen at the pre-idle busy level — and the first busy
/// pass after a long idle would jump straight back to the busy cadence,
/// bypassing the intended AIMD cooldown + dwell (RFC adaptive_tick §5.3). Forcing
/// level 0 makes the post-idle resume start from the relaxed cadence and ramp
/// back down under sustained load. Per-domain-exclusive access (same invariant as
/// `pacer_apply_cadence`).
fn pacer_force_relaxed(domain_id: usize, tick_max: u32) {
    let d = domain_id.min(MAX_DOMAINS - 1);
    let now = crate::kernel::sys::hal::now_micros();
    // SAFETY: per-domain-exclusive; `&raw mut` avoids a static_mut reference.
    let slot = unsafe { &raw mut PACER[d] };
    // SAFETY: per-domain-exclusive read/write of the Copy state.
    let mut ps = unsafe { *slot };
    // Mark the busy→relaxed transition for the dwell gate only on a real change
    // (or first use), so repeated idle passes don't keep pushing the dwell window.
    if ps.level_idx != 0 || !ps.init {
        ps.last_change_us = now;
    }
    ps.init = true;
    ps.level_idx = 0;
    ps.busy_run = 0;
    ps.last_reported_us = tick_max;
    // SAFETY: per-domain-exclusive write-back.
    unsafe { *slot = ps };
}

/// Mechanism (b): AIMD cadence between the floor and `tick_max`, with run-length
/// hysteresis + a minimum dwell, on a discrete geometric level ladder
/// (`tick_max >> level_idx`, clamped to the floor). Busy passes step the level
/// DOWN fast (toward the floor = lower latency); idle passes step it UP slowly
/// (toward `tick_max`). Emits MON_PACER_LEVEL on a real change and
/// MON_PACER_FLOOR when the live floor has raised the effective minimum above
/// `tick_min_us` (the load-shed / thermal signal).
fn pacer_apply_cadence(domain_id: usize, idle: bool, tick_max: u32) -> u32 {
    let d = domain_id.min(MAX_DOMAINS - 1);
    let floor = pacer_floor_us(domain_id, tick_max);
    let now = crate::kernel::sys::hal::now_micros();
    // PACER[d] is touched only by domain d's own scheduler pass (single-threaded
    // on Linux/rp; per-core-exclusive on bcm2712). `PacerState` is `Copy`, so we
    // read-modify-write through a raw pointer — no reference to the `static mut`
    // (avoids both static_mut_refs and deref_addrof).
    // SAFETY: per-domain-exclusive access as documented above; `&raw mut`
    // forms a pointer to the static-mut element without a reference to it.
    let slot = unsafe { &raw mut PACER[d] };
    // SAFETY: per-domain-exclusive read of the Copy state.
    let mut ps = unsafe { *slot };
    if !ps.init {
        ps.init = true;
        ps.level_idx = 0;
        ps.last_change_us = now;
    }
    if idle {
        ps.idle_run = ps.idle_run.saturating_add(1);
        ps.busy_run = 0;
    } else {
        ps.busy_run = ps.busy_run.saturating_add(1);
        ps.idle_run = 0;
    }
    let dwell_ok = now.wrapping_sub(ps.last_change_us) >= PACER_MIN_DWELL_US;
    let old_idx = ps.level_idx;
    if !idle && ps.busy_run >= PACER_BUSY_RUN_N && dwell_ok {
        // Multiplicative decrease (one halving) — fast to get faster.
        ps.level_idx = (ps.level_idx + 1).min(PACER_MAX_LEVEL);
        ps.busy_run = 0;
    } else if idle && ps.idle_run >= PACER_IDLE_RUN_M && dwell_ok {
        // Additive increase (one level) — slow to relax.
        ps.level_idx = ps.level_idx.saturating_sub(1);
        ps.idle_run = 0;
    }
    if ps.level_idx != old_idx {
        ps.last_change_us = now;
    }
    let raw_deadline = (tick_max >> ps.level_idx.min(31)).max(floor).min(tick_max);
    // Deadband: hold the previously-applied deadline unless the change is
    // significant. Worst_step measurement jitter (±a few µs) would otherwise
    // dither the floor (and thus the cadence) and spam MON_PACER_LEVEL (AC6);
    // ladder steps and real floor moves clear the band.
    let last = ps.last_reported_us;
    let band = (last >> PACER_DEADBAND_SHIFT).max(PACER_DEADBAND_MIN_US);
    let deadline = if last != 0 && raw_deadline.abs_diff(last) <= band {
        last
    } else {
        raw_deadline
    };
    if deadline != ps.last_reported_us {
        ps.last_reported_us = deadline;
        let reason = if idle { "cooldown" } else { "busy" };
        // SAFETY: DBG_TICK aligned u32 read.
        let tick = unsafe { DBG_TICK };
        log::info!("MON_PACER_LEVEL domain={d} tick_us={deadline} reason={reason} tick={tick}");
        if floor > domain_tick_min_us(domain_id) {
            log::info!(
                "MON_PACER_FLOOR domain={d} floor_us={floor} worst_step_us={} tick={tick}",
                domain_worst_step_us(domain_id)
            );
        }
    }
    // SAFETY: per-domain-exclusive write-back of the updated state.
    unsafe {
        *slot = ps;
    }
    deadline
}

/// Select the next pacing deadline (µs) for `domain_id` from existing kernel
/// signals — the single adaptive-tick decision "how long until the next pass?"
/// (RFC adaptive_tick §5.1). Call it at the platform pacing tail, AFTER the
/// pass + its pre-sleep wake drain, so the busy/idle signal reflects the pass
/// just finished.
///
/// **Mechanism (a) demand-driven idle** (bit 0): when (a) is enabled and the
/// pass was idle (no pending wake, no burst), relax the next sleep to
/// `tick_max_us` — the platform sleeps in an event-interruptible posture, so a
/// wake returns immediately; the backstop bounds worst-case re-evaluation and
/// keeps step-counted timers advancing (always-armed-backstop invariant, D7).
/// **Mechanism (b) adaptive cadence** (bit 1): AIMD toward `tick_min_us` on a
/// busy pass / back off toward `tick_max_us` on an idle one, with hysteresis
/// (deadband) and the §5.3 floor = `max(tick_min_us, worst_step × FLOOR_MARGIN)`
/// so the chosen cadence never undershoots the live worst-step cost.
///
/// When no adaptive flag is set this returns `domain_tick_us` exactly, so an
/// unconfigured domain is byte-identical in pacing to today.
///
/// Idle is decided per-domain via `domain_wake_pending(domain_id)` (the
/// `EVENT_WAKE_PENDING ∩ domain_module_mask` intersection), so on
/// multicore a busy sibling domain can't block this domain from relaxing. On a
/// single-domain target (Linux/rp) every module is in domain 0, so it
/// degenerates exactly to the global `wake_pending_nonzero()`.
pub fn pacer_next_deadline_us(domain_id: usize) -> u32 {
    let flags = domain_adaptive_flags(domain_id);
    if flags == 0 {
        return record_pacer_period_us(domain_id, domain_tick_us(domain_id));
    }
    // Use the outer-tick accumulator, NOT BURST_SEEN_THIS_PASS (which is reset
    // per pipeline sub-pass and reads false after a flush-then-drain tick).
    let burst = PACER_BURST_TICK
        .get(domain_id.min(MAX_DOMAINS - 1))
        .map(|b| b.load(Ordering::Relaxed))
        .unwrap_or(false);
    // §6 work signal (RFC adaptive_tick_extra): a module that did useful work
    // this tick (WorkDone/RunnableBacklog/Burst, via REPORT_STEP_EFFECT) keeps
    // the pacer hot even if it returned `Continue` for fairness (the IP/NIC
    // case). Heat-only — re-step is still Burst-gated.
    let work = PACER_WORK_TICK
        .get(domain_id.min(MAX_DOMAINS - 1))
        .map(|b| b.load(Ordering::Relaxed))
        .unwrap_or(false);
    let idle = !burst && !work && !domain_wake_pending(domain_id);
    let tick_max = domain_tick_max_us(domain_id);
    // §6.6 hot-start transition tracking: record idle→busy edges. On idle the
    // hot-start window resets; the edge (was_idle && now busy) arms it below.
    let hs_di = domain_id.min(MAX_DOMAINS - 1);
    let was_idle = PACER_WAS_IDLE[hs_di].swap(idle, Ordering::Relaxed);
    if idle {
        PACER_HOTSTART[hs_di].store(0, Ordering::Relaxed);
    }
    // MON_PACER_IDLE_SLEEP on the busy→idle transition only (low-rate), when
    // demand-driven idle is the active relaxation for this domain.
    if (flags & ADAPTIVE_FLAG_IDLE) != 0 {
        let di = domain_id.min(MAX_DOMAINS - 1);
        let was = PACER_IDLE_REPORTED[di].swap(idle, Ordering::Relaxed);
        if idle && !was {
            // SAFETY: DBG_TICK aligned u32 read.
            let tick = unsafe { DBG_TICK };
            log::info!("MON_PACER_IDLE_SLEEP domain={di} backstop_us={tick_max} tick={tick}");
        }
    }
    if (flags & ADAPTIVE_FLAG_IDLE) != 0 && idle {
        // (a) demand-driven idle: relax straight to the backstop. The platform
        // sleeps event-interruptibly so a wake returns immediately. When (b) is
        // ALSO enabled, (a) bypasses its AIMD ladder — so explicitly drive the
        // (b) pacer to its relaxed level here. Otherwise level_idx/last_reported_us
        // stay frozen at the pre-idle busy level and the first busy pass after a
        // long idle jumps straight back to the busy cadence, skipping the AIMD
        // cooldown/dwell. With this, the post-idle resume starts relaxed and ramps
        // back down under load (the intended hysteresis).
        if (flags & ADAPTIVE_FLAG_CADENCE) != 0 {
            pacer_force_relaxed(domain_id, tick_max);
        }
        return record_pacer_period_us(domain_id, tick_max);
    }
    // §6.6 hot-start (busy pass): on the idle→busy edge, arm a bounded window of
    // `PACER_HOTSTART_PASSES` and return the §5.3 floor — the tightest safe
    // cadence, which never undershoots the live worst-step — so a
    // request-response pipeline's return hops after idle don't each wait out
    // (b)'s slow AIMD ramp down from `tick_max`. The floor still respects
    // budgets/guaranteed admission, and Burst guards apply unchanged.
    //
    // Hot-start modulates the busy-pass deadline below the nominal tick, so it
    // is part of mechanism (b) and runs only when (b) cadence is enabled. In
    // idle-only mode (bit 0 without bit 1) a busy pass returns the nominal
    // `domain_tick_us`: idle-only never changes the busy cadence, keeping the
    // worst-step bound intact. The `was_idle` latch above is maintained either
    // way.
    if (flags & ADAPTIVE_FLAG_CADENCE) != 0 {
        let mut hot = PACER_HOTSTART[hs_di].load(Ordering::Relaxed);
        if was_idle {
            hot = PACER_HOTSTART_PASSES;
        }
        if hot > 0 {
            PACER_HOTSTART[hs_di].store(hot - 1, Ordering::Relaxed);
            let floor = pacer_floor_us(domain_id, tick_max);
            if hot == PACER_HOTSTART_PASSES {
                // A cooperative pipeline can alternate idle/work at every
                // boundary, making hot-start a normal high-frequency event.
                // Keep the monitor observable without turning log transport
                // into work on every hot-path transition.
                // SAFETY: mon_throttle takes raw pointers to the monitor throttle
                // statics; scheduler-thread only.
                if let Some(sup) = unsafe {
                    mon_throttle(
                        core::ptr::addr_of_mut!(MON_HOTSTART_LAST),
                        core::ptr::addr_of_mut!(MON_HOTSTART_SUP),
                    )
                } {
                    // SAFETY: DBG_TICK aligned u32 read.
                    let tick = unsafe { DBG_TICK };
                    log::info!(
                        "MON_PACER_HOTSTART domain={hs_di} deadline_us={floor} passes={PACER_HOTSTART_PASSES} tick={tick} suppressed={sup}"
                    );
                }
            }
            // Drive (b)'s ladder toward the floor so cadence stays tight when
            // the window ends.
            let _ = pacer_apply_cadence(domain_id, false, tick_max);
            return record_pacer_period_us(domain_id, floor);
        }
        // (b) AIMD cadence between the §5.3 floor and tick_max.
        let period = pacer_apply_cadence(domain_id, idle, tick_max);
        return record_pacer_period_us(domain_id, period);
    }
    // (a) enabled but this pass was busy, (b) disabled → nominal tick.
    record_pacer_period_us(domain_id, domain_tick_us(domain_id))
}

// ===========================================================================
// §7 graph-local pacing (RFC adaptive_tick_extra)
// ===========================================================================
//
// Per-`(graph_instance, domain)` pacer state, so a hot graph cannot pin an idle
// graph's cadence and an idle graph cannot delay a hot one. Graph identity is
// `owner::OwnerHandle{slot, generation}`. A multi-graph runner drives this
// surface: the §7.2 shared-runner deadline-merge, the §6.5 skip-idle runnable
// predicate, and §7.1 generation-reset on slot reuse. A single resident graph
// reduces to the per-domain `pacer_next_deadline_us` path above. Bounded (§7.5),
// no hot-path alloc (§7.6).
//
// Each instance carries its own AIMD `PacerState` and reuses the same ladder
// constants as `pacer_apply_cadence`.

/// Declared bounded graph/domain pacer-instance table size (§7.5). Sized for a
/// handful of resident graphs across the domains; admission rejects configs
/// that would need more (the tools `MAX_PACER_INSTANCES` gate).
pub const MAX_GRAPH_PACERS: usize = 16;

#[derive(Clone, Copy)]
pub(crate) struct GraphPacer {
    pub(crate) active: bool,
    pub(crate) graph_slot: u16,
    pub(crate) generation: u32,
    pub(crate) domain: u8,
    pub(crate) state: PacerState,
    /// Per-instance pass signals, set by the multi-graph runner before asking
    /// for a deadline: work (WorkDone/RunnableBacklog/Burst seen), burst, a
    /// targeted wake, and a due timer/liveness deadline.
    pub(crate) work: bool,
    pub(crate) burst: bool,
    pub(crate) wake: bool,
    pub(crate) timer_due: bool,
    pub(crate) was_idle: bool,
    pub(crate) hotstart: u8,
}

impl GraphPacer {
    pub(crate) const fn new() -> Self {
        Self {
            active: false,
            graph_slot: 0,
            generation: 0,
            domain: 0,
            state: PacerState::new(),
            work: false,
            burst: false,
            wake: false,
            timer_due: false,
            was_idle: false,
            hotstart: 0,
        }
    }
}

pub(crate) static mut GRAPH_PACERS: [GraphPacer; MAX_GRAPH_PACERS] =
    [GraphPacer::new(); MAX_GRAPH_PACERS];

/// Resolve the bounded-table index for `(graph_slot, domain)`, allocating a
/// free slot on first use. A generation mismatch (the owner slot was reused by
/// a new graph) RESETS the instance so the new graph cannot inherit the old
/// graph's heat/floor/dwell (§7.1). Returns `None` if the table is full
/// (the build-time admission gate prevents this for valid configs). Not a
/// hot-path scan in steady state — the runner caches the index at prepare time.
pub(crate) fn graph_pacer_index(graph_slot: u16, generation: u32, domain: u8) -> Option<usize> {
    let gp = &raw mut GRAPH_PACERS;
    // SAFETY: scheduler-thread-exclusive access to the table.
    let t = unsafe { &mut *gp };
    // Existing instance for this key?
    for (i, p) in t.iter_mut().enumerate() {
        if p.active && p.graph_slot == graph_slot && p.domain == domain {
            if p.generation != generation {
                // Slot reused by a new graph — reset (§7.1 generation guard).
                *p = GraphPacer::new();
                p.active = true;
                p.graph_slot = graph_slot;
                p.generation = generation;
                p.domain = domain;
            }
            return Some(i);
        }
    }
    // Allocate a free slot.
    for (i, p) in t.iter_mut().enumerate() {
        if !p.active {
            *p = GraphPacer::new();
            p.active = true;
            p.graph_slot = graph_slot;
            p.generation = generation;
            p.domain = domain;
            return Some(i);
        }
    }
    None // table full — admission should have rejected this config
}

/// AIMD ladder step for a graph-local instance (mirrors `pacer_apply_cadence`'s
/// math on the instance's own `PacerState`, using the same constants). Returns
/// the chosen deadline in µs, clamped to `[floor, tick_max]`.
fn graph_pacer_ladder(ps: &mut PacerState, idle: bool, tick_max: u32, floor: u32, now: u64) -> u32 {
    if !ps.init {
        ps.init = true;
        ps.level_idx = 0;
        ps.last_change_us = now;
    }
    if idle {
        ps.idle_run = ps.idle_run.saturating_add(1);
        ps.busy_run = 0;
    } else {
        ps.busy_run = ps.busy_run.saturating_add(1);
        ps.idle_run = 0;
    }
    let dwell_ok = now.wrapping_sub(ps.last_change_us) >= PACER_MIN_DWELL_US;
    let old = ps.level_idx;
    if !idle && ps.busy_run >= PACER_BUSY_RUN_N && dwell_ok {
        ps.level_idx = (ps.level_idx + 1).min(PACER_MAX_LEVEL);
        ps.busy_run = 0;
    } else if idle && ps.idle_run >= PACER_IDLE_RUN_M && dwell_ok {
        ps.level_idx = ps.level_idx.saturating_sub(1);
        ps.idle_run = 0;
    }
    if ps.level_idx != old {
        ps.last_change_us = now;
    }
    let raw = (tick_max >> ps.level_idx.min(31)).max(floor).min(tick_max);
    ps.last_reported_us = raw;
    raw
}

/// §6.5 runnable predicate: is this graph/domain instance runnable this pass
/// (must be stepped), or may it be skipped on a shared runner? Runnable iff any
/// of: prior-pass work/burst, a targeted wake, or a due timer/liveness
/// deadline. Conservative — when in doubt the runner passes `timer_due=true`
/// (fail-closed to the backstop).
pub(crate) fn graph_pacer_runnable(p: &GraphPacer) -> bool {
    p.work || p.burst || p.wake || p.timer_due
}

/// Set this instance's per-pass signals (called by the multi-graph runner
/// before computing deadlines). Resolves/allocates the instance.
#[allow(
    clippy::fn_params_excessive_bools,
    reason = "the four signals (work/burst/wake/timer_due) are the distinct \
              §6.3 pacer busy inputs; a bitfield would obscure them at the \
              call site for no safety gain"
)]
pub fn graph_pacer_set_signals(
    graph_slot: u16,
    generation: u32,
    domain: u8,
    work: bool,
    burst: bool,
    wake: bool,
    timer_due: bool,
) -> bool {
    let Some(idx) = graph_pacer_index(graph_slot, generation, domain) else {
        return false;
    };
    let gp = &raw mut GRAPH_PACERS;
    // SAFETY: scheduler-thread-exclusive; idx in bounds.
    let p = unsafe { &mut (*gp)[idx] };
    p.work = work;
    p.burst = burst;
    p.wake = wake;
    p.timer_due = timer_due;
    true
}

/// §7.2 graph-local next deadline for one `(graph_slot, domain)` instance.
/// Independent of every other instance: an idle instance relaxes to `tick_max`
/// and a busy instance tightens toward `floor`, with the §6.6 hot-start jump on
/// the idle→busy edge. `floor`/`tick_min`/`tick_max` are the domain's bounds.
pub fn graph_pacer_deadline(
    graph_slot: u16,
    generation: u32,
    domain: u8,
    tick_min_us: u32,
    tick_max_us: u32,
    floor_us: u32,
    now_us: u64,
) -> u32 {
    let Some(idx) = graph_pacer_index(graph_slot, generation, domain) else {
        return tick_max_us;
    };
    let gp = &raw mut GRAPH_PACERS;
    // SAFETY: scheduler-thread-exclusive; idx in bounds.
    let p = unsafe { &mut (*gp)[idx] };
    let floor = floor_us.max(tick_min_us).min(tick_max_us);
    // Must mirror `graph_pacer_runnable` exactly: a graph runnable only because
    // a timer/liveness deadline is due is NOT idle, or it would be relaxed to
    // tick_max and miss its due deadline.
    let idle = !graph_pacer_runnable(p);
    let was_idle = p.was_idle;
    p.was_idle = idle;
    if idle {
        p.hotstart = 0;
        // Drive the ladder toward relaxed so the resume ramps (hysteresis).
        let _ = graph_pacer_ladder(&mut p.state, true, tick_max_us, floor, now_us);
        return tick_max_us;
    }
    // Busy: §6.6 hot-start on the idle→busy edge.
    if was_idle {
        p.hotstart = PACER_HOTSTART_PASSES;
    }
    if p.hotstart > 0 {
        p.hotstart -= 1;
        let _ = graph_pacer_ladder(&mut p.state, false, tick_max_us, floor, now_us);
        return floor;
    }
    graph_pacer_ladder(&mut p.state, false, tick_max_us, floor, now_us)
}

/// §7.2 shared-runner deadline merge: the physical wait is the minimum deadline
/// across the RUNNABLE instances in `keys` (each `(graph_slot, generation,
/// domain, tick_min, tick_max, floor)`); idle instances are skipped (not
/// stepped) but still bound the wait via their relaxed deadline if nothing is
/// runnable. Returns `(min_deadline_us, any_runnable)`. This is how a hot graph
/// keeps the runner tight without an idle sibling forcing it slow, and an idle
/// sibling relaxes without delaying the hot graph.
pub fn graph_pacer_shared_runner_deadline(
    keys: &[(u16, u32, u8, u32, u32, u32)],
    now_us: u64,
) -> (u32, bool) {
    let mut min_runnable = u32::MAX;
    let mut min_backstop = u32::MAX;
    let mut any_runnable = false;
    for &(slot, gen_, domain, tmin, tmax, floor) in keys {
        let d = graph_pacer_deadline(slot, gen_, domain, tmin, tmax, floor, now_us);
        min_backstop = min_backstop.min(d);
        // Re-read runnability from the instance the call resolved.
        if let Some(idx) = graph_pacer_index(slot, gen_, domain) {
            let gp = &raw const GRAPH_PACERS;
            // SAFETY: scheduler-thread-exclusive read.
            let p = unsafe { &(*gp)[idx] };
            if graph_pacer_runnable(p) {
                any_runnable = true;
                min_runnable = min_runnable.min(d);
            }
        }
    }
    if any_runnable {
        (min_runnable, true)
    } else {
        (
            if min_backstop == u32::MAX {
                0
            } else {
                min_backstop
            },
            false,
        )
    }
}

/// Reset the entire graph-local pacer table (reconfigure / test teardown).
pub fn graph_pacer_reset_all() {
    let gp = &raw mut GRAPH_PACERS;
    // SAFETY: scheduler-thread-exclusive; called at reconfigure or in tests.
    let t = unsafe { &mut *gp };
    for p in t.iter_mut() {
        *p = GraphPacer::new();
    }
}
