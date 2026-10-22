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
//! `SCHED`, `NAME_STORAGE`, `INSTANTIATION_*`,
//! `MODULE_STATE_PTR`) is populated on core 0 during graph compile,
//! then treated as read-only across all cores during step.
//! `FAN_BUFS[d]` is per-domain scratch indexed by tee/merge `domain_id`
//! so concurrent fan modules on different cores don't share a buffer.
//! `CURRENT_MODULE_PER_CORE[c]` is an atomic array indexed by
//! `hal::core_id()`. See `docs/architecture/concurrency.md`.

use core::ptr::null;

use portable_atomic::{AtomicBool, AtomicU32, Ordering};

use crate::kernel::boot::config::{
    read_config_into, Config, ModuleEntry, ModuleList, MAX_GRAPH_EDGES,
    MAX_MODULES as CONFIG_MAX_MODULES,
};
use crate::kernel::exec::step_guard::{
    self, fault_type, FaultPolicy, FaultRecord, FaultState, FaultStats, ModuleFaultInfo,
};
use crate::kernel::ipc::channel;
use crate::kernel::ipc::channel::{
    channel_set_flags, channel_set_mailbox, channel_set_reader_gone, POLL_ERR, POLL_HUP,
};
use crate::kernel::ipc::ring_size as rings;
use crate::kernel::module::loader::{
    reset_state_arena, DynamicModule, ModuleLoader, PortCapacities, StartNewResult,
};
use crate::kernel::module::syscalls;
use crate::kernel::module::syscalls::{get_table_for_module_type, is_spi_initialized};
use crate::kernel::sys::hal;
use crate::kernel::workload::bitmask::ModuleMask;
use crate::kernel::workload::owner::{OwnerHandle, OwnerTable, MAX_OWNERS, OWNER_SYSTEM};
use crate::modules::StepOutcome;

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
    "MAX_MODULES must leave NO_MODULE outside the module-index domain"
);

/// The `buffer_group` values the tables keyed by group span
/// (`ring_size::buffer_groups`): the whole byte on the host profile's graph,
/// half of it on the small parts, where these tables are on the stack.
pub(crate) const BUFFER_GROUPS: usize = rings::buffer_groups(MAX_GRAPH_EDGES);

/// The edge-index domain: the config format's bound on a channel id. The
/// edge tables are sized at boot within it (see [`edge_slots`]); on the
/// static profiles it is the compiled channel count.
pub const MAX_CHANNELS: usize = MAX_GRAPH_EDGES;

/// A scheduler table with one slot per module: boot-sized on Linux, bcm2712
/// and RP, the profile's static array on wasm (`kernel::mem::table`).
pub type ModTable<T> = crate::kernel::mem::table::Table<T, MAX_MODULES>;
/// A scheduler table with one slot per edge.
pub type EdgeTable<T> = crate::kernel::mem::table::Table<T, MAX_CHANNELS>;

/// Module slots live now: what the boot plan committed, grown by live adds.
/// Every walk over modules runs to this, never to `MAX_MODULES`. On the
/// static profiles it is the compiled table size.
#[inline]
pub fn module_slots() -> usize {
    #[cfg(any(feature = "host-linux", feature = "chip-bcm2712", feature = "rp"))]
    {
        // SAFETY: a length read of the scheduler's module table; it changes
        // only while a graph is prepared or a subgraph is added, on the
        // scheduler thread.
        unsafe { (&*core::ptr::addr_of!(SCHED)).modules.len() }
    }
    #[cfg(not(any(feature = "host-linux", feature = "chip-bcm2712", feature = "rp")))]
    {
        MAX_MODULES
    }
}

/// Edge slots live now (see [`module_slots`]).
#[inline]
pub fn edge_slots() -> usize {
    #[cfg(any(feature = "host-linux", feature = "chip-bcm2712", feature = "rp"))]
    {
        // SAFETY: as `module_slots`.
        unsafe { (&*core::ptr::addr_of!(SCHED)).edges.len() }
    }
    #[cfg(not(any(feature = "host-linux", feature = "chip-bcm2712", feature = "rp")))]
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

/// Reconfigure phase state machine.
///
/// The scheduler manages live reconfigure as a four-phase transition:
/// RUNNING -> DRAINING -> MIGRATING -> RUNNING
///
/// During RUNNING, the phase check in step_modules() is a single
/// branch-not-taken with zero overhead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReconfigurePhase {
    /// Normal operation — no reconfigure in progress.
    Running = 0,
    /// Drain-capable modules are completing in-flight work.
    Draining = 1,
    /// Modules being replaced/removed, new modules instantiated.
    Migrating = 2,
}

/// Maximum number of burst re-steps per module per tick.
/// When step() returns StepOutcome::Burst, the scheduler re-steps the module
/// up to this many additional times, stopping early if the module returns
/// Continue (no more work), Done, or Error.
/// This enables compute-heavy modules to do multiple chunks of work per tick
/// while remaining cooperative (each individual step is still bounded).
const MAX_BURST_STEPS: usize = 16384;

/// Wall-clock window (in milliseconds) within which a paired-module
/// fault co-incidence triggers quarantine. If module A faults and its
/// declared `quarantine_partner` B has also faulted within this many
/// milliseconds, both transition to `Terminated` regardless of their
/// individual `FaultPolicy`. 100 ms is comfortable for the "two halves
/// of a TLS handshake go wrong at the same time" case, tight enough
/// that unrelated faults don't mistakenly cross-trigger.
///
/// Measured against `hal::now_millis()` (via `last_fault_ms`) rather
/// than a tick count: a fixed tick window silently shrinks/grows the
/// real coincidence window the moment mechanism (b) varies the tick
/// period, and stalls entirely under mechanism (a) idle-sleep — either
/// way the safety decision would be made on a wrong window.
const QUARANTINE_WINDOW_MS: u64 = 100;

/// Hard kernel ceiling on `Draining` phase duration, in scheduler
/// ticks. The reconfigure PIC module owns the drain orchestration and
/// decides when each module has finished its in-flight work — but a
/// buggy or hung module-drain can hold the graph indefinitely. After
/// this many ticks in `Draining`, the kernel force-finalises every
/// non-finished module with `FaultState::Terminated`, logs
/// `MON_DRAIN_FORCED`, and snaps the phase back to `Running` so the
/// next reconfigure attempt can proceed.
///
/// 30 000 ms = 30 s. Long enough that well-behaved drains never hit
/// it; short enough that operators don't wait minutes on a hung
/// migration.
///
/// Measured against `hal::now_millis()` (via `drain_started_ms`)
/// rather than a tick count: under mechanism (b) the tick period
/// varies, so a 30 000-tick ceiling would not map to 30 s, and under
/// mechanism (a) the tick stops advancing while a hung module holds
/// the graph — the ceiling would never fire.
const MAX_DRAIN_MS: u64 = 30_000;

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

/// Maximum number of Tier 1c pre-tick drain modules per domain.
/// Sized for NIC RX + ARP cache drain + headroom — enough for the
/// canonical use case (single NIC driver per domain) without
/// bloating `SchedulerState` (each domain costs
/// `MAX_PRE_TICK_PER_DOMAIN` bytes in `domain_pre_tick_order`).
pub const MAX_PRE_TICK_PER_DOMAIN: usize = 4;

/// Combined cycle budget for *all* Tier 1c pre-tick modules in a
/// single domain pass, in microseconds. Pre-tick modules run before
/// the regular `domain_exec_order` rotation; this cap prevents
/// cumulative pre-tick work from starving the cooperative loop.
/// At `tick_us = 100`, 5 µs leaves >99 µs for Tier 0/1a modules.
pub const MAX_PRE_TICK_BUDGET_US: u32 = 5;

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
    /// Bridge slot index when at least one endpoint is in an ISR-tier
    /// domain (Tier 1b/2). `-1` means no bridge — same-tier edges
    /// continue to use the regular PIPE channel exclusively. Set by
    /// `wire_isr_bridges` after `open_channels`. The
    /// `pump_isr_bridges` routine drains PIPE↔bridge in whichever
    /// direction the ISR-tier endpoint sits.
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
    /// This edge references a **pre-existing shared channel** it neither
    /// opened nor owns — an attachable-lane merge's spare input lane.
    /// `channel` is pre-assigned to that spare-lane id;
    /// `open_channels`/`close_channels` skip it (they must not open a fresh
    /// ring, nor close a channel a boot merge caches) and `free_owner` never
    /// closes it, so tearing the attaching workload down just frees the lane
    /// (edge removed ⇒ `channel_producer_owner` reverts to system) without
    /// disturbing the merge. `false` for every normal edge, so the whole graph
    /// is byte-identical when no lane is attached.
    pub shared_channel: bool,
    /// A **tap** (live mirror) edge: `channel` receives a copy of every write
    /// to `tap_source`, the output channel of `from_module`'s port. The
    /// tapped module does not write it — so it is never collected as that
    /// module's output — and the copy is lossy (see `channel_set_mirror`).
    /// `tap_source` is -1 once the tapped side has gone.
    pub tap: bool,
    pub tap_source: i32,
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
            shared_channel: false,
            tap: false,
            tap_source: -1,
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
            shared_channel: false,
            tap: false,
            tap_source: -1,
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
/// Each ring is sized by `kernel::ipc::ring_size`: the largest of the
/// producer and consumer ports' declared capacities and the edge's
/// `buffer_bytes`, rounded up to a power of two (64 bytes at least), and the
/// default ring (`CHANNEL_BUFFER_SIZE`) where nothing sizes the edge. The
/// composer replays graph preparation over the same file
/// (`tools/src/ring_plan.rs`) and refuses at build a graph whose rings do not
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
/// through a shared buffer would reach every party in the fan at once.
/// `insert_fan` decides by what the fanned port carries. Over a record-
/// carrying port (`FRAME_KIND_RECORD`) it gives every edge around the fan a
/// `buffer_group` of its own, above the config's range, so each edge is a
/// mailbox and the fan moves one record per transfer; over any other port it
/// clears `buffer_group` and the edges are FIFOs.
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
    let edge_min_size = |edge: &Edge| -> u32 {
        let (from_size, _) = port_caps[edge.from_module].lookup(1, edge.from_port_index);
        let to_port_type = if edge.is_ctrl() { 2 } else { 0 };
        let (to_size, _) = port_caps[edge.to_module].lookup(to_port_type, edge.to_port_index);
        rings::edge_request(from_size, to_size, edge.buffer_bytes)
    };

    // Pre-scan: each group's largest member request, the size of the ring
    // the group shares.
    let mut group_max_size = [0u32; BUFFER_GROUPS];
    for edge in edges.iter() {
        let group = edge.buffer_group as usize;
        if group == 0 {
            continue;
        }
        let edge_max = edge_min_size(edge);
        if edge_max > group_max_size[group] {
            group_max_size[group] = edge_max;
        }
    }

    // Map buffer_group -> channel handle for aliasing
    let mut group_channels = [-1i32; BUFFER_GROUPS];
    let mut count = 0;
    for edge in edges.iter_mut() {
        // Attachable-lane edge: `channel` is a pre-existing shared spare lane
        // (an attachable-lane merge cached it at boot). Never open a fresh
        // ring for it — the producer must write into the lane the merge
        // already reads. No boot edge sets this.
        if edge.shared_channel {
            continue;
        }
        // Check for buffer group aliasing
        let group = edge.buffer_group as usize;
        if group > 0 && group_channels[group] >= 0 {
            // Verify destination module can safely consume from mailbox
            // SAFETY: SCHED is scheduler-thread owned; `edge.to_module`
            // is bounded against MAX_MODULES by config validation.
            let safe = unsafe { SCHED.mailbox_safe[edge.to_module] };
            if safe {
                // Alias: reuse existing channel for this group
                edge.channel = group_channels[group];
                // aliased to existing group channel
                continue;
            } else {
                // skip alias — module not mailbox_safe
                // Fall through to create separate channel
            }
        }

        // Determine buffer size: grouped edges use pre-computed max,
        // ungrouped edges use the same combined signal directly.
        let buf_size = if group > 0 && group_max_size[group] > 0 {
            group_max_size[group]
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
        let (_, max_record) = port_caps[edge.from_module].lookup(1, edge.from_port_index);
        if max_record > granted {
            log::error!(
                "[graph] edge {}→{}: producer port {} declares max_record={} \
                 but the ring grants {} bytes (requested {}); an all-or-nothing \
                 write larger than the ring can never succeed. Raise the edge's \
                 buffer_bytes / the port's buffer_size, or lower max_record.",
                edge.from_module,
                edge.to_module,
                edge.from_port_index,
                max_record,
                granted,
                buf_size,
            );
            return -1;
        }

        // An unsized edge opens with no config and takes the kernel's
        // default ring; a sized one passes its granted ring, which
        // `channel_open` accepts only as a power of two in range.
        let producer_mod = edge.from_module as ModuleId;
        let chan = if buf_size > 0 {
            let config = granted.to_le_bytes();
            channel::channel_open_for_module(
                channel::CHANNEL_TYPE_PIPE,
                config.as_ptr(),
                4,
                producer_mod,
            )
        } else {
            channel::channel_open_for_module(channel::CHANNEL_TYPE_PIPE, null(), 0, producer_mod)
        };

        if chan < 0 {
            return -1;
        }
        edge.channel = chan;
        count += 1;

        // Record channel handle and enable mailbox mode for grouped edges.
        // buffer_group != 0 means the config tool determined this edge should
        // use zero-copy semantics, even for a single edge in the group.
        if group > 0 {
            group_channels[group] = chan;
            channel_set_mailbox(chan);
        }
    }
    count
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
        // Never close a pre-existing shared spare lane — an attachable-lane
        // merge caches it; closing it would strand the merge on a dead
        // handle. Detaching a workload just drops the edge, reverting the
        // lane to producer-less/free.
        if edge.shared_channel {
            continue;
        }
        if edge.channel >= 0 {
            syscalls::channel_close(edge.channel);
        }
    }
}

// ============================================================================
// Name Arena (static string interning)
// ============================================================================

/// Maximum name length (including null terminator space)
const MAX_NAME_LEN: usize = 32;

/// Maximum number of interned names. One per DISTINCT module name — `intern`
/// returns the existing slot for a repeat — so a graph of many instances of a
/// few engines (a params control plane is mostly `decision`, `store_source`
/// and `store_effect`) uses a handful. Sized to MAX_MODULES so even a graph of
/// all-distinct modules cannot run out.
const MAX_NAMES: usize = MAX_MODULES;

/// Static storage for interned names
static mut NAME_STORAGE: [[u8; MAX_NAME_LEN]; MAX_NAMES] = [[0; MAX_NAME_LEN]; MAX_NAMES];

/// Next available slot index
static mut NEXT_NAME_SLOT: usize = 0;

/// Arena for interning module names as static strings.
///
/// Each slot is stable for the lifetime of the graph — no wrap-around,
/// so returned `&'static str` pointers remain valid until `reset()`.
struct NameArena;

impl NameArena {
    /// Intern a name, returning a &'static str.
    /// Returns "?" if the arena is exhausted — not reachable while MAX_NAMES
    /// is MAX_MODULES, since a graph cannot hold more distinct names.
    fn intern(name: &str) -> &'static str {
        // SAFETY: NameArena is scheduler-thread owned; static name buffers
        // are accessed only from prepare_graph / instantiate paths.
        unsafe {
            // A name already interned is returned as-is: the arena holds
            // distinct names, not one per instance.
            let want = &name.as_bytes()[..name.len().min(MAX_NAME_LEN - 1)];
            let storage = &raw const NAME_STORAGE;
            for buf in (*storage).iter().take(NEXT_NAME_SLOT) {
                let len = buf.iter().position(|&b| b == 0).unwrap_or(MAX_NAME_LEN);
                if &buf[..len] == want {
                    return core::str::from_utf8_unchecked(&buf[..len]);
                }
            }
            if NEXT_NAME_SLOT >= MAX_NAMES {
                log::warn!("NameArena: exhausted ({MAX_NAMES} slots), cannot intern '{name}'");
                return "?";
            }

            let slot = NEXT_NAME_SLOT;
            NEXT_NAME_SLOT += 1;

            let buf = &mut NAME_STORAGE[slot];
            let len = name.len().min(MAX_NAME_LEN - 1);
            if name.len() > MAX_NAME_LEN - 1 {
                log::warn!(
                    "NameArena: '{}' truncated to {} bytes",
                    name,
                    MAX_NAME_LEN - 1
                );
            }
            buf[..len].copy_from_slice(&name.as_bytes()[..len]);
            buf[len] = 0;

            core::str::from_utf8_unchecked(&buf[..len])
        }
    }

    /// Reset the arena (call when tearing down the graph).
    fn reset() {
        // SAFETY: scheduler-thread reset between graph rebuilds.
        unsafe {
            NEXT_NAME_SLOT = 0;
        }
    }
}

// ============================================================================
// Module Slots
// ============================================================================

pub mod module_types;
pub use module_types::{
    BuiltInModule, DummyModule, MergeModule, ModuleSlot, TeeModule, FAN_FRAMES_PER_STEP,
    FRAME_KIND_NET, FRAME_KIND_RECORD,
};

/// Live graph mutation (add owner / free owner). Multi-tenant only —
/// bare-metal single-tenant targets compile it out at zero cost.
#[cfg(feature = "multitenant")]
pub mod live;
#[cfg(feature = "multitenant")]
pub use live::{
    apply_add, free_owner, AddEdge, AddError, AddModule, AddSubgraph, Endpoint, FreeError,
    ModuleSource, StepBudget,
};

// ============================================================================
// Runner Configuration
// ============================================================================

/// Runtime configuration for the scheduler
pub struct RunnerConfig {
    /// SPI bus number (0 or 1)
    pub spi_bus: u8,
    /// GPIO pin number for CS
    pub cs_pin: u8,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            spi_bus: 0,
            cs_pin: 17,
        }
    }
}

// ── Scheduler body: real responsibility modules ──────────────────────────────
// Each is a genuine module boundary (its own namespace + explicit visibility),
// re-exported flat so existing `scheduler::X` call sites are unchanged.
pub mod attest;
pub mod built_in;
pub mod domain_budget;
pub mod exec_order;
pub mod instantiation;
pub mod live_reconfig;
pub mod merge;
pub mod multigraph;
pub mod ownership;
pub mod setup;
pub mod static_storage;
pub mod stepping;
pub mod wiring;
pub use built_in::*;
pub use domain_budget::*;
pub use exec_order::*;
pub use instantiation::*;
pub use live_reconfig::*;
pub use merge::*;
pub use multigraph::*;
pub use ownership::*;
pub use setup::*;
pub use static_storage::*;
pub use stepping::set_forced_pipeline_passes;
pub use stepping::*;
pub use wiring::*;
