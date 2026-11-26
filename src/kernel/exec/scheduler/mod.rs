//! Module scheduler - graph management and execution.
//!
//! This module provides:
//! - Graph data structures (Edge, StepResult) for describing module connections
//! - Channel management for inter-module communication
//! - Config-driven module instantiation from flash
//! - Main execution loop that steps all modules
//!
//! The scheduler reads configuration, instantiates PIC modules dynamically,
//! wires them together via channels, and runs the processing graph.
//!
//! ## Concurrency
//!
//! Most `static mut` storage here (`STATIC_CONFIG`, `STATIC_LOADER`,
//! `SCHED`, `INSTANTIATION_*`) is populated on core 0 during graph compile,
//! then treated as read-only across all cores during step.
//! `CURRENT_MODULE_PER_CORE[c]` is an atomic array indexed by
//! `hal::core_id()`. See `docs/architecture/concurrency.md`.

use portable_atomic::{AtomicBool, AtomicU32, Ordering};

use crate::kernel::boot::config::{
    read_config_into, Config, ModuleEntry, MAX_GRAPH_EDGES, MAX_MODULES as CONFIG_MAX_MODULES,
};
use crate::kernel::exec::step::StepOutcome;
use crate::kernel::exec::step_guard::{
    self, fault_type, FaultPolicy, FaultRecord, FaultState, FaultStats, ModuleFaultInfo,
};
use crate::kernel::ipc::channel;
use crate::kernel::ipc::channel::{
    channel_producer_gone, channel_set_mailbox, channel_set_reader_gone,
};
use crate::kernel::module::loader::{
    reset_state_arena, DynamicModule, ModuleLoader, PortCapacities, StartNewResult,
};
use crate::kernel::module::syscalls;
use crate::kernel::module::syscalls::get_syscall_table;
use crate::kernel::sys::hal;
use crate::kernel::workload::bitmask::ModuleMask;
use crate::kernel::workload::owner::{OwnerHandle, OwnerTable, OWNER_NODE};
use fluxor_contracts::boot_config::ExecMode;
use fluxor_contracts::ring_size as rings;

// ============================================================================
// Graph Constants and Types
// ============================================================================

/// Maximum number of modules in a graph.
pub const MAX_MODULES: usize = CONFIG_MAX_MODULES;

/// A module's index in the graph. Every table, owner field and wire field
/// that names a module carries one of these.
pub type ModuleId = u16;

/// No module: the sentinel an owner field holds when nothing owns it, and
/// what a fault with no upstream cause names.
pub const NO_MODULE: ModuleId = ModuleId::MAX;

// Readiness, upstream, event-wake and domain-step bitmaps are
// `ModuleMask`-backed and scale with the ceiling; every index is a
// `ModuleId`, whose top value is reserved as `NO_MODULE`.
const _: () = assert!(
    MAX_MODULES < NO_MODULE as usize,
    "MAX_MODULES must leave NO_MODULE outside the module-index range"
);

/// The `buffer_group` values the tables keyed by group span
/// (`ring_size::buffer_groups`): the whole byte on the host profile's graph,
/// half of it on the small parts, where these tables are on the stack.
pub(crate) const BUFFER_GROUPS: usize = rings::buffer_groups(MAX_GRAPH_EDGES);

/// The edge-index range: the config format's bound on a channel id. The
/// edge tables are sized at boot within it (see [`edge_slots`]); on the
/// static profiles it is the compiled channel count.
pub const MAX_CHANNELS: usize = MAX_GRAPH_EDGES;

/// A scheduler table with one slot per module: boot-sized on Linux, aarch64
/// bare metal and RP, the profile's static array on wasm
/// (`kernel::mem::table`).
pub type ModTable<T> = crate::kernel::mem::table::Table<T, MAX_MODULES>;
/// A scheduler table with one slot per edge.
pub type EdgeTable<T> = crate::kernel::mem::table::Table<T, MAX_CHANNELS>;

/// Module slots live now: what the boot plan committed, grown by live adds.
/// Every walk over modules runs to this, never to `MAX_MODULES`. On the
/// static profiles it is the compiled table size.
#[inline]
pub fn module_slots() -> usize {
    #[cfg(any(feature = "host-linux", feature = "aarch64-metal", feature = "rp"))]
    {
        // SAFETY: a length read of the scheduler's module table; it changes
        // only while a graph is prepared or a subgraph is added, on the
        // scheduler thread.
        unsafe { (&*core::ptr::addr_of!(SCHED)).modules.len() }
    }
    #[cfg(not(any(feature = "host-linux", feature = "aarch64-metal", feature = "rp")))]
    {
        MAX_MODULES
    }
}

/// [`module_slots`] without sizing the table, for interrupt context and the
/// wake latch it reaches: a table no plan has sized holds no module, so every
/// index reads as out of range.
#[inline]
pub fn committed_module_slots() -> usize {
    #[cfg(any(feature = "host-linux", feature = "aarch64-metal", feature = "rp"))]
    {
        // SAFETY: as `module_slots`.
        unsafe { (&*core::ptr::addr_of!(SCHED)).modules.committed().len() }
    }
    #[cfg(not(any(feature = "host-linux", feature = "aarch64-metal", feature = "rp")))]
    {
        MAX_MODULES
    }
}

/// Edge slots live now (see [`module_slots`]).
#[inline]
pub fn edge_slots() -> usize {
    #[cfg(any(feature = "host-linux", feature = "aarch64-metal", feature = "rp"))]
    {
        // SAFETY: as `module_slots`.
        unsafe { (&*core::ptr::addr_of!(SCHED)).edges.len() }
    }
    #[cfg(not(any(feature = "host-linux", feature = "aarch64-metal", feature = "rp")))]
    {
        MAX_CHANNELS
    }
}

/// Result of stepping all modules in a graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepResult {
    /// All modules ran successfully, continue running.
    Continue,
    /// A module signaled completion.
    Done,
    /// A module encountered an error (index provided).
    Error(usize),
}

// ============================================================================
// Live Reconfigure Types
// ============================================================================

/// Reconfigure phase: whether the graph is draining for a rebuild.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReconfigurePhase {
    /// Normal operation — no reconfigure in progress.
    Running = 0,
    /// Drain-capable modules are completing in-flight work.
    Draining = 1,
}

/// Maximum number of execution domains.
pub const MAX_DOMAINS: usize = 4;

/// Default tick period in microseconds (1ms).
pub const DEFAULT_TICK_US: u32 = 1000;

/// Per-pass exponential-decay shift for `domain_worst_step_us`, the input to
/// the adaptive-tick per-domain floor. Each pass removes `1/2^SHIFT` of the
/// retained peak, so a one-off spike ages out in ~`SHIFT × ln(spike/steady)`
/// passes (~0.4 s at a 1 ms tick for SHIFT=8) and the floor relaxes on
/// cool-down. The exact value is rig-tuned; the decay couples weakly to pass
/// rate under variable tick (a second-order effect — relaxation
/// speed, not correctness). The per-step peak-hold re-raises it to the live
/// worst, so steady-state tracks the current worst and only stale spikes decay.
pub const WORST_STEP_DECAY_SHIFT: u32 = 8;

/// Maximum number of pre-pass drain modules per domain.
/// Sized for NIC RX + ARP cache drain + headroom — enough for the
/// canonical use case (single NIC driver per domain) without
/// bloating `SchedulerState` (each domain costs
/// `MAX_PRE_PASS_PER_DOMAIN` bytes in `domain_pre_pass_order`).
pub const MAX_PRE_PASS_PER_DOMAIN: usize = 4;

/// The share of its domain's tick the pre-pass slot may take, as a
/// divisor: the slot's modules together run for at most `tick_us / 20`
/// (5 µs of a 100 µs tick, 50 µs of a 1 ms one) before the cooperative
/// pass, so pre-pass work cannot starve it at any cadence.
pub const PRE_PASS_BUDGET_SHARE: u32 = 20;

/// Describes a connection between two module ports.
#[derive(Debug, Clone, Copy)]
pub struct Edge {
    /// Source module index
    pub from_module: usize,
    /// Source port name
    pub from_port: &'static str,
    /// Destination module index
    pub to_module: usize,
    /// Destination port name
    pub to_port: &'static str,
    /// Channel handle the producer writes into (assigned by `open_channels`).
    pub channel: i32,
    /// Optional override for the consumer-side handle. When `>= 0`, the
    /// destination module's port table is filled with this channel
    /// instead of `channel`, and a platform-specific bridge moves bytes
    /// from `channel` into `consumer_channel` (e.g. the BCM2712
    /// cross-domain SPSC pump). `-1` means the consumer reads `channel`
    /// directly — every same-domain edge.
    pub consumer_channel: i32,
    /// Source output port index (0 = primary)
    pub from_port_index: u8,
    /// Destination input/ctrl port index (0 = primary)
    pub to_port_index: u8,
    /// Buffer group ID for aliasing. 0 = no aliasing.
    /// Edges with the same non-zero group share the same channel buffer.
    pub buffer_group: u8,
    /// Edge class metadata (Local, DmaOwned, CrossCore). Pure metadata on single-core.
    pub edge_class: crate::kernel::boot::config::EdgeClass,
    /// Per-edge ring-buffer size override in bytes (from
    /// `wiring[i].buffer_bytes` in the YAML config). `0` defers to the
    /// manifest port capacities; non-zero is combined with them
    /// via `max(...)` in `open_channels`. See
    /// `kernel::boot::config::GraphEdge::buffer_bytes`.
    pub buffer_bytes: u32,
    /// Bridge slot index when at least one endpoint is in an interrupt-mode
    /// domain (`timer`/`irq`). `-1` means no bridge — an edge between
    /// cooperative domains continues to use the regular PIPE channel exclusively. Set by
    /// `wire_isr_bridges` after `open_channels`. The
    /// `pump_isr_bridges` routine drains PIPE↔bridge in whichever
    /// direction the interrupt-mode endpoint sits.
    pub bridge_slot: i8,
    /// Rate class: 0=control, 1=audio, 2=video, 3=bulk, 4=transaction.
    /// Drives MODULE_FLOW_BUDGET grants.
    pub rate_class: u8,
    /// `wake: true` on the wiring entry: a successful write on this
    /// edge latches the consumer's event-wake bit and rings the
    /// scheduler doorbell. Wired into the channel slot's
    /// `wake_module` by `prepare_graph` for same-domain direct edges;
    /// cross-domain edges are bound to the consumer-local delivery
    /// channel by the platform's cross-domain bridging instead
    /// (delivery-side wake).
    pub wake_on_write: bool,
    /// The consumer port declares `retains_send` (`GraphEdge::retains_send`).
    /// A fan's bridge edge out of the fanned producer carries it only when
    /// every fanned edge does, so `channel::FACTS` on the producer's channel
    /// answers for every consumer it reaches.
    pub retains_send: bool,
    /// A **tap** (live mirror) edge: `channel` receives a copy of every write
    /// to `tap_source`, the output channel of `from_module`'s port. The
    /// tapped module does not write it — so it is never collected as that
    /// module's output — and the copy is lossy (see `channel_set_mirror`).
    /// `tap_source` is -1 once the tapped side has gone.
    pub tap: bool,
    pub tap_source: i32,
    /// Whose buffer ledger the edge's ring is charged to: the owner of the
    /// module at that end, which the add that opened the ring placed.
    /// Only the edge that opened a ring carries its charge.
    pub charge: EdgeCharge,
    /// Which end, if either, is a lane (`Endpoint::Lane`): the module at
    /// that end is the lane's target, which takes the channel with
    /// `LANE_TAKE` and never as a port, so the edge is never collected into
    /// its port table nor split across cores. Until a node graph's lane
    /// resolves (`splice::finish`) that end's module is [`LANE_PENDING`].
    pub lane: LaneEnd,
}

/// The end of an edge that is a lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneEnd {
    None,
    /// The producer end: the edge carries the lane's events.
    From,
    /// The consumer end: the edge carries the lane's commands.
    To,
}

/// The module index of a lane end whose target has not declared yet: past
/// every slot, so no port table, wake or channel end names it.
pub const LANE_PENDING: usize = usize::MAX;

/// The end of an edge whose module's owner was charged the edge's ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeCharge {
    None,
    Producer,
    Consumer,
}

impl Edge {
    /// Create a new edge with unassigned channel.
    pub const fn new(
        from_module: usize,
        from_port: &'static str,
        to_module: usize,
        to_port: &'static str,
    ) -> Self {
        Self {
            from_module,
            from_port,
            to_module,
            to_port,
            channel: -1,
            consumer_channel: -1,
            from_port_index: 0,
            to_port_index: 0,
            buffer_group: 0,
            edge_class: crate::kernel::boot::config::EdgeClass::Local,
            buffer_bytes: 0,
            rate_class: 0,
            bridge_slot: -1,
            wake_on_write: false,
            retains_send: false,
            tap: false,
            tap_source: -1,
            charge: EdgeCharge::None,
            lane: LaneEnd::None,
        }
    }

    /// Create a new edge with port indices and optional buffer group.
    pub const fn new_indexed(
        from_module: usize,
        from_port: &'static str,
        from_port_index: u8,
        to_module: usize,
        to_port: &'static str,
        to_port_index: u8,
    ) -> Self {
        Self {
            from_module,
            from_port,
            to_module,
            to_port,
            channel: -1,
            consumer_channel: -1,
            from_port_index,
            to_port_index,
            buffer_group: 0,
            edge_class: crate::kernel::boot::config::EdgeClass::Local,
            buffer_bytes: 0,
            rate_class: 0,
            bridge_slot: -1,
            wake_on_write: false,
            retains_send: false,
            tap: false,
            tap_source: -1,
            charge: EdgeCharge::None,
            lane: LaneEnd::None,
        }
    }

    /// Create a simple edge using default port names (out -> in).
    pub const fn simple(from_module: usize, to_module: usize) -> Self {
        Self::new(from_module, "out", to_module, "in")
    }

    /// Create a control edge (out -> ctrl).
    pub const fn ctrl(from_module: usize, to_module: usize) -> Self {
        Self::new(from_module, "out", to_module, "ctrl")
    }

    /// Check if this is a control edge (destination is ctrl port).
    pub fn is_ctrl(&self) -> bool {
        self.to_port == "ctrl"
    }
}

// ============================================================================
// Channel Management
// ============================================================================

/// Open channels for all edges in the graph.
///
/// Each ring is sized by `fluxor_contracts::ring_size`: the largest of the
/// producer and consumer ports' declared capacities and the edge's
/// `buffer_bytes`, rounded up to a power of two (64 bytes at least), and the
/// default ring (`CHANNEL_BUFFER_SIZE`) where nothing sizes the edge. The
/// composer replays graph preparation over the same rule
/// (`fluxor_contracts::graph::plan`) and refuses at build a graph whose rings do not
/// fit the target's buffer arena; the harness test `ring_demand` pins the
/// two together.
///
/// ## Mailbox (zero-copy) aliasing
///
/// `buffer_group` in graph edges is the *only* way to enable mailbox mode.
/// Any edge with a non-zero `buffer_group` enables mailbox on its channel.
/// When two or more edges share the same group, a later edge reuses the
/// group's ring (aliasing).
///
/// The downstream module must set `mailbox_safe` (header flags bit 0) or the
/// alias is skipped and the edge opens a ring of its own at the group's size,
/// still a mailbox, which later members of the group then alias. Modules
/// that only read mailbox data (e.g. I2S sink via `buffer_acquire_read`) need
/// `mailbox_safe` but not `in_place_writer`. Modules that modify the buffer
/// in place (e.g. effects via `buffer_acquire_inplace`) need both.
///
/// At most one `in_place_writer` module per buffer_group is allowed (enforced
/// at setup by `validate_buffer_groups`).
///
/// No aliased chain passes through a fan (tee/merge): in-place modification
/// through a shared buffer would reach every party in the fan at once. The
/// composer decides by what the fanned port carries
/// (`fluxor_contracts::graph::plan`): around a record fan every edge has a
/// group of its own, so each is a mailbox and the fan moves one record per
/// transfer; around any other fan the edges are FIFOs.
///
/// ## Buffer sizing for groups
///
/// A group's ring is its largest member's request — port capacities and
/// `buffer_bytes` alike — so the shared ring holds the most demanding
/// member's records (e.g. an I2S sink requiring 2048 bytes).
///
/// ## FIFO→Mailbox chaining
///
/// Use FIFO for any producer that writes incrementally (partial frames). A
/// mailbox chain begins at the first module that produces whole buffers; edges
/// in the chain share the same `buffer_group`. At most one in-place transform
/// is supported per chain; `docs/architecture/pipeline.md` (FIFO → Mailbox
/// Boundary Rule) has the rule.
///
/// Returns the number of channels opened, or -1 on error.
pub fn open_channels(edges: &mut [Edge]) -> i32 {
    // SAFETY: SCHED is scheduler-thread owned; read-only access via
    // `&raw const`. open_channels runs during graph prep.
    let port_caps = unsafe {
        let p = &raw const SCHED;
        &(*p).port_caps
    };

    // The per-edge request (`ring_size::edge_request`): the largest of the
    // producer/consumer manifest port capacities and the wiring's
    // `buffer_bytes` — a port capacity is a per-port-type minimum, the
    // wiring field a per-edge one, so the larger wins.
    // A lane end has no port: what it carries is sized by its peer's port
    // and the edge's `buffer_bytes`.
    let edge_min_size = |edge: &Edge| -> u32 {
        let from_size = match port_caps.get(edge.from_module) {
            Some(c) if edge.lane != LaneEnd::From => c.lookup(1, edge.from_port_index).0,
            _ => 0,
        };
        let to_port_type = if edge.is_ctrl() { 2 } else { 0 };
        let to_size = match port_caps.get(edge.to_module) {
            Some(c) if edge.lane != LaneEnd::To => c.lookup(to_port_type, edge.to_port_index).0,
            _ => 0,
        };
        rings::edge_request(from_size, to_size, edge.buffer_bytes)
    };

    // A group's ring is its largest member's request; a member aliases the
    // ring the group's latest member before it took. Both are found among
    // the edges themselves, so no table spans the group domain on the stack.
    let group_max_size = |edges: &[Edge], group: u8| -> u32 {
        edges
            .iter()
            .filter(|e| e.buffer_group == group)
            .map(&edge_min_size)
            .max()
            .unwrap_or(0)
    };
    let mut count = 0;
    for i in 0..edges.len() {
        let group_channel = if edges[i].buffer_group > 0 {
            edges[..i]
                .iter()
                .rfind(|e| e.buffer_group == edges[i].buffer_group && e.channel >= 0)
                .map_or(-1, |e| e.channel)
        } else {
            -1
        };
        let group_size = if edges[i].buffer_group > 0 {
            group_max_size(edges, edges[i].buffer_group)
        } else {
            0
        };
        let edge = &mut edges[i];
        // Check for buffer group aliasing
        let group = edge.buffer_group as usize;
        if group > 0 && group_channel >= 0 {
            // Verify destination module can safely consume from mailbox
            // SAFETY: SCHED is scheduler-thread owned; `edge.to_module` is
            // bounded by the slot check (a pending lane end is past every
            // slot).
            let safe =
                edge.to_module < module_slots() && unsafe { SCHED.mailbox_safe[edge.to_module] };
            if safe {
                // Alias: reuse existing channel for this group
                edge.channel = group_channel;
                bind_edge_ends(edge);
                continue;
            } else {
                // skip alias — module not mailbox_safe
                // Fall through to create separate channel
            }
        }

        // Determine buffer size: grouped edges use pre-computed max,
        // ungrouped edges use the same combined signal directly.
        let buf_size = if group > 0 && group_size > 0 {
            group_size
        } else {
            edge_min_size(edge)
        };

        // ── Load-time capacity enforcement ──
        // The ring this edge is granted (`rings::ring_for`): a request
        // above the ceiling is refused rather than clamped — a clamped
        // producer believes it has headroom it does not, and would find
        // out as a wedge under load rather than as a config error at graph
        // build. channel_write is all-or-nothing, so a producer whose
        // declared max_record exceeds the ring is a permanent wedge by
        // construction, refused here with its numbers.
        let Some(granted) = rings::ring_for(buf_size) else {
            log::error!(
                "[graph] edge {}→{}: requested buffer {} exceeds the \
                 channel ceiling {} — lower the request or split the stream.",
                edge.from_module,
                edge.to_module,
                buf_size,
                rings::MAX_RING_BYTES,
            );
            return -1;
        };
        // A ring keeps each record's length beside it; a mailbox's record is
        // the whole buffer.
        let max_record = match port_caps.get(edge.from_module) {
            Some(c) if edge.lane != LaneEnd::From => c.lookup(1, edge.from_port_index).1,
            _ => 0,
        };
        let footprint = if group > 0 {
            u64::from(max_record)
        } else {
            rings::record_bytes(max_record)
        };
        if footprint > u64::from(granted) {
            log::error!(
                "[graph] edge {}→{}: producer port {} declares max_record={} \
                 ({} bytes of ring with its length prefixes) but the ring grants \
                 {} bytes (requested {}); an all-or-nothing write larger than the \
                 ring can never succeed. Raise the edge's buffer_bytes / the \
                 port's buffer_size, or lower max_record.",
                edge.from_module,
                edge.to_module,
                edge.from_port_index,
                max_record,
                footprint,
                granted,
                buf_size,
            );
            return -1;
        }

        // An unsized edge opens with no config and takes the kernel's
        // default ring; a sized one passes its granted ring, which
        // `channel_open` accepts only as a power of two in range.
        let chan = if buf_size > 0 {
            channel::channel_open(&granted.to_le_bytes())
        } else {
            channel::channel_open(&[])
        };

        if chan < 0 {
            return -1;
        }
        edge.channel = chan;
        bind_edge_ends(edge);
        count += 1;

        // Record channel handle and enable mailbox mode for grouped edges.
        // buffer_group != 0 means the config tool determined this edge should
        // use zero-copy semantics, even for a single edge in the group.
        if group > 0 {
            channel_set_mailbox(chan);
        }
    }
    count
}

/// Bind `edge`'s ends on its channel: its producer writes it, its consumer
/// reads it. A tap's channel is written by the kernel's mirror alone.
fn bind_edge_ends(edge: &Edge) {
    let end = |m: usize| {
        if m < module_slots() {
            m as ModuleId
        } else {
            NO_MODULE
        }
    };
    let producer = if edge.tap {
        NO_MODULE
    } else {
        end(edge.from_module)
    };
    channel::channel_bind_edge(edge.channel, producer, end(edge.to_module));
}

/// Validate buffer group constraints after module instantiation.
///
/// Rules:
/// - At most one `in_place_writer` module per buffer_group. Multiple in-place
///   writers cause runtime stalls (READY_PROCESSED rejection by buffer_pool).
///
/// Returns true if valid, false if constraints violated.
pub fn validate_buffer_groups(edges: &[Edge]) -> bool {
    // SAFETY: SCHED is scheduler-thread owned; read-only access.
    let sched = unsafe {
        let p = &raw const SCHED;
        &*p
    };
    let mut group_writers = [0u8; BUFFER_GROUPS];
    let mut valid = true;

    for edge in edges.iter() {
        if edge.channel < 0 {
            continue;
        }
        let group = edge.buffer_group as usize;
        if group == 0 {
            continue;
        }
        if edge.is_ctrl() {
            continue;
        }

        let to_mod = edge.to_module;
        if to_mod < module_slots() && sched.in_place_writer[to_mod] {
            group_writers[group] += 1;
            if group_writers[group] > 1 {
                log::error!(
                    "[graph] buffer_group={group} duplicate in_place_writer module={to_mod}"
                );
                valid = false;
            }
        }
    }

    valid
}

/// Close all channels in the edge list.
pub fn close_channels(edges: &[Edge]) {
    for edge in edges {
        if edge.channel >= 0 {
            syscalls::channel_close(edge.channel);
        }
    }
}

// ============================================================================
// Module Slots
// ============================================================================

pub mod slot;
pub use slot::ModuleSlot;

/// Owner lifecycle on a running graph (free, pause, resume) and step budgets.
pub mod live;
pub use live::{free_owner, FreeError, StepBudget, STEP_BUDGET_HARD_CAP_US};

/// Native modules: the platform's own, found by name hash.
pub mod native;
pub use native::{NativeInit, NativeModule, NativeVtable};

/// Composed graphs spliced into the schedule, boot and live.
pub mod splice;
pub use splice::{AddAuthority, AddError, StagedAdd};

// ── Scheduler body: responsibility modules ──────────────────────────────────
// Each names what it gives the rest of the kernel below, explicitly.
pub mod attest;
pub mod exec_order;
/// The module fault machine.
pub mod fault;
pub mod instantiation;
pub mod live_reconfig;
pub mod multigraph;
pub mod ownership;
/// The adaptive pacer.
pub mod pacer;
/// The pass engine.
pub mod pass;
pub mod setup;
pub mod state;
pub mod static_storage;
pub mod wiring;
pub use exec_order::log_dma_owned_edges;
pub(crate) use exec_order::{
    gate_contract_consumers, refresh_domains, splice_into_order, unsplice_from_orders,
};
pub(crate) use instantiation::{collect_one_module_hints, finalize_module};
pub use instantiation::{
    is_node_param_tag, maybe_emit_alive, module_device_window, module_level,
    module_step_deadline_us, params_carry_tag, params_heap_arena_bytes, params_level,
    params_node_tag, params_raw_arena, params_u8, parse_protection_config, sample_flow_stalls,
    sample_pstatus, set_pstatus_interval_ms, DBG_STEP_MODULE, HEAP_ARENA_TAG, HEAP_RAW_ARENA_TAG,
};
pub use live_reconfig::{
    active_module_count, begin_stop_drain, call_module_drain, hold_idle, mark_module_finished,
    module_completion_predecessors_finished, module_info_flags, module_upstream_words,
    prepare_in_progress, raise_module_fault, reconfigure_phase, set_reconfigure_phase,
    stop_drain_settled,
};
pub use multigraph::{
    admit_resident_workloads_from_config, arena_get, channel_caller, channel_port_lookup,
    clear_module_ready, deny_interrupt_mode_syscall, domain_count, domain_exec_mode,
    domain_exec_order_at, domain_module_count, downstream_latency, get_fault_stats,
    module_domain_id, module_fault_info, module_fault_state, module_finished,
    module_is_interrupt_mode, module_is_ready, module_state_snapshot, query_module_state,
    query_step_histogram, rebuild_resident_graph_index, record_step_time, report_module_latency,
    resident_graph_count, set_domain_exec_mode, set_module_deferred_ready, set_module_domain,
    set_module_fault_policy, set_module_quarantine_partner, set_module_step_deadline,
    set_module_step_deadline_burst, set_module_step_period, set_module_step_phase,
    set_module_upstream_bits, set_module_upstream_mask, ModuleStateSnapshot, PacerLine,
    PACER_LOG_INTERVAL_US,
};
pub(crate) use multigraph::{
    graph_inbound_readable, log_pacer_line, mark_graph_stepped, owner_graph_paused, resident_graph,
    slot_resident, ResidentGraph,
};
pub use ownership::{
    authorize_module_access, caller_authority, caller_owner, channel_facts, channel_producer_owner,
    free_module_state, module_is_finished, module_owner, module_owner_attribution,
    owner_live_status, owner_modules_quiescent, owners, owners_mut, request_rebuild,
    set_module_owner, take_rebuild_request, OwnerLiveStatus, OWNER_STATE_ACTIVE,
    OWNER_STATE_DRAINING, OWNER_STATE_PAUSED,
};
pub use pacer::{
    graph_pacer_deadline, graph_pacer_reset_all, graph_pacer_set_signals, pacer_bounds,
    pacer_current_period_us, pacer_domain_floor_us, DeadlineMerge, PacerBounds,
    ADAPTIVE_FLAG_CADENCE, ADAPTIVE_FLAG_IDLE,
};
pub(crate) use pacer::{
    graph_pacer_retain, graph_pacer_runnable, pacer_reset_all, settle_deadline,
};
pub(crate) use pass::MAX_PIPELINE_PASSES;
pub use pass::{
    domain_budget_overruns, domain_budget_us_consumed, domain_pacer_work_pending,
    domain_pre_pass_at, domain_pre_pass_count, domain_pre_pass_overruns, pass_count,
    report_step_effect, run, set_domain_budget_us_limit, set_forced_pipeline_passes, step_effect,
    take_domain_wakes, tick_all, wake_all, PassKind, PassResult,
};
pub use setup::{
    build_graph, instantiate_graph, log_arena_usage, module_irq, module_isr_budget_cycles,
    prepare_graph, pump_isr_bridges, set_module_irq, set_module_isr_budget_cycles, setup,
    size_kernel_tables, DEFAULT_ISR_BUDGET_CYCLES,
};
pub(crate) use setup::{register_isr_module, wire_isr_bridges, IsrRegistration};
pub(crate) use state::{as_module_step, ArenaInfo, MonLine, SCHED};
pub use state::{
    caller_module_index, clear_instantiation_state, copy_module_params, current_module_grants,
    current_module_id, current_module_index, domain_adaptive_flags, domain_tick_max_us,
    domain_tick_min_us, domain_tick_us, domain_worst_step_us, edge_peer, get_module_port,
    graph_sample_rate, graph_snapshot, in_module_step, module_code_region, module_index_on_core,
    module_params, module_port, module_program, module_program_region, module_slot_generation,
    module_state_footprint, module_type_hash, sched_mut, set_caller_module, set_current_module,
    set_graph_sample_rate, set_instantiation_state, set_module_arena, set_module_grants,
    set_module_params, set_module_type_hash, set_owner_idle_safe, store_dynamic_module,
    store_native_module, syscall_flow_budget, syscall_input_flow_budget, take_module_arena,
    tick_us, with_module_context, GraphSnapshot, SchedulerState,
};
use static_storage::MAX_PORTS;
pub use static_storage::{
    install_static_config, populate_static_state, populate_static_state_with_len, static_config,
    static_config_mut, static_loader, static_loader_mut, ModulePorts,
};
pub(crate) use static_storage::{STATIC_CONFIG, STATIC_LOADER};
pub use wiring::{instantiate_one_module, populate_module_ports_from_edges, InstantiateResult};
