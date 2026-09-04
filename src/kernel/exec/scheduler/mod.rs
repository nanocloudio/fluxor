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
//! `SCHED`, `PARAM_BUFFER`, `NAME_STORAGE`, `INSTANTIATION_*`,
//! `MODULE_STATE_PTR`) is populated on core 0 during graph compile,
//! then treated as read-only across all cores during step.
//! `FAN_BUFS[d]` is per-domain scratch indexed by tee/merge `domain_id`
//! so concurrent fan modules on different cores don't share a buffer.
//! `CURRENT_MODULE_PER_CORE[c]` is an atomic array indexed by
//! `hal::core_id()`. See `docs/architecture/concurrency.md`.

use core::ptr::null;

use portable_atomic::{AtomicBool, AtomicU32, Ordering};

use crate::kernel::boot::config::{
    read_config_into, Config, ModuleEntry, MAX_GRAPH_EDGES, MAX_MODULES as CONFIG_MAX_MODULES,
};
use crate::kernel::exec::step_guard::{
    self, fault_type, FaultPolicy, FaultRecord, FaultState, FaultStats, ModuleFaultInfo,
};
use crate::kernel::ipc::channel;
use crate::kernel::ipc::channel::{channel_set_flags, channel_set_mailbox, POLL_ERR, POLL_HUP};
use crate::kernel::module::loader::{
    find_hint_for_port, reset_state_arena, ChannelHint, DynamicModule, ModuleLoader, StartNewResult,
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

// Compile-time gate: readiness, upstream, event-wake, and domain-step bitmaps
// are `ModuleMask`-backed, so they scale past 64.
// The residual ceiling is fault-cascade attribution (`detect_caused_by` keeps
// the caused-by module id in a `u8`) and the u16 module-index domain; 256 is
// the validated multi-workload profile (Pi 5). Raising it further requires widening
// those id fields.
const _: () = assert!(
    MAX_MODULES <= 256,
    "MAX_MODULES > 256 requires widening fault-attribution module ids past u8."
);

/// Maximum number of channels (edges) in a graph.
/// Matches MAX_GRAPH_EDGES from config to support fan-in/out expansion.
pub const MAX_CHANNELS: usize = MAX_GRAPH_EDGES;

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
/// period, and stalls entirely under mechanism (a) idle-sleep — a
/// correctness regression for this safety decision.
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

/// Per-pass exponential-decay shift for `domain_worst_step_us` (the §5.3
/// adaptive-tick floor input). Each pass removes `1/2^SHIFT` of the retained
/// peak, so a one-off spike ages out in ~`SHIFT × ln(spike/steady)` passes
/// (~0.4 s at a 1 ms tick for SHIFT=8) and the floor relaxes on cool-down
/// (AC7). Exact value is rig-tuned (OQ1); the decay couples weakly to pass
/// rate under variable tick (a documented second-order effect — relaxation
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
    /// `wiring[i].buffer_bytes` in the YAML config). `0` defers to
    /// `module_channel_hints`; non-zero is combined with module hints
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
/// Uses per-module channel hints to right-size each channel buffer.
/// The source module's output port hint determines the buffer size.
/// Falls back to the default 2048 bytes if no hint is available.
///
/// ## Mailbox (zero-copy) aliasing
///
/// `buffer_group` in graph edges is the *only* way to enable mailbox mode.
/// Any edge with a non-zero `buffer_group` enables mailbox on its channel.
/// When two or more edges share the same group, subsequent edges reuse the
/// channel opened for the first edge (aliasing).
///
/// The downstream module must set `mailbox_safe` (header flags bit 0) or the
/// alias is skipped and a separate FIFO channel is created instead. Modules
/// that only read mailbox data (e.g. I2S sink via `buffer_acquire_read`) need
/// `mailbox_safe` but not `in_place_writer`. Modules that modify the buffer
/// in place (e.g. effects via `buffer_acquire_inplace`) need both.
///
/// At most one `in_place_writer` module per buffer_group is allowed (enforced
/// at setup by `validate_buffer_groups`).
///
/// Aliased mailbox chains are incompatible with fan-out/fan-in (tee/merge).
/// `insert_fan` explicitly clears `buffer_group` on edges that require a tee
/// or merge, because in-place modification through an aliased buffer would
/// corrupt data for other consumers in the fan.
///
/// ## Buffer sizing for groups
///
/// For grouped edges, the buffer is sized to the maximum of all port hints
/// across all edges in the group. This ensures the channel is large enough
/// for the most demanding consumer (e.g. I2S requiring 2048 bytes).
///
/// ## FIFO→Mailbox chaining
///
/// Use FIFO for any producer that writes incrementally (partial frames). A
/// mailbox chain begins at the first module that produces whole buffers; edges
/// in the chain share the same `buffer_group`. At most one in-place transform
/// is supported per chain. See `docs/architecture/pipeline.md` §FIFO→Mailbox.
///
/// Returns the number of channels opened, or -1 on error.
pub fn open_channels(edges: &mut [Edge]) -> i32 {
    // SAFETY: SCHED is scheduler-thread owned; read-only access via
    // `&raw const`. open_channels runs during graph prep.
    let module_hints = unsafe {
        let p = &raw const SCHED;
        &(*p).hints
    };

    // Resolve the per-edge buffer-size signal. Combines the
    // producer/consumer `module_channel_hints` with the YAML
    // `buffer_bytes` override via `max(...)` — module hints express
    // a per-port-type minimum, the YAML field expresses a graph-
    // level bandwidth requirement, so the larger always wins.
    let edge_min_size = |edge: &Edge| -> u32 {
        let from_hints = &module_hints[edge.from_module];
        let from_size = find_hint_for_port(
            &from_hints.hints[..from_hints.count],
            1, // port_type = out
            edge.from_port_index,
        );
        let to_hints = &module_hints[edge.to_module];
        let to_port_type = if edge.is_ctrl() { 2 } else { 0 };
        let to_size = find_hint_for_port(
            &to_hints.hints[..to_hints.count],
            to_port_type,
            edge.to_port_index,
        );
        from_size.max(to_size).max(edge.buffer_bytes)
    };

    // Pre-scan: compute max buffer size per group across all edges.
    // This ensures the shared channel is large enough for the most
    // demanding consumer (e.g. I2S requiring exactly 2048 bytes) and
    // for any sized YAML override on a member edge.
    let mut group_max_size: [u32; 128] = [0; 128];
    for edge in edges.iter() {
        let group = edge.buffer_group as usize;
        if group == 0 || group >= 128 {
            continue;
        }
        let edge_max = edge_min_size(edge);
        if edge_max > group_max_size[group] {
            group_max_size[group] = edge_max;
        }
    }

    // Map buffer_group -> channel handle for aliasing
    let mut group_channels: [i32; 128] = [-1; 128];
    let mut count = 0;
    for edge in edges.iter_mut() {
        // Attachable-lane edge: `channel` is a pre-existing shared spare lane
        // (an attachable-lane merge cached it at boot). Never open a fresh
        // ring for it — the producer must write into the lane the merge
        // already reads. No boot edge sets this, so the base-graph path is
        // byte-identical.
        if edge.shared_channel {
            continue;
        }
        // Check for buffer group aliasing
        let group = edge.buffer_group as usize;
        if group > 0 && group < 128 && group_channels[group] >= 0 {
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
        let buf_size = if group > 0 && group < 128 && group_max_size[group] > 0 {
            group_max_size[group]
        } else {
            edge_min_size(edge)
        };

        // ── Load-time capacity enforcement ──
        // channel_write is all-or-nothing: a record larger than the
        // ring can NEVER succeed, so a producer whose declared
        // max_record exceeds what this ring will grant is a
        // permanent-wedge-by-construction — refuse the graph now,
        // with numbers, instead of freezing at runtime.
        {
            let from_hints = &module_hints[edge.from_module];
            let max_record = crate::kernel::module::loader::find_max_record_for_port(
                &from_hints.hints[..from_hints.count],
                1, // port_type = out
                edge.from_port_index,
            );
            {
                const MAX_CHAN_BYTES: u32 = 4 * 1024 * 1024;
                if buf_size > MAX_CHAN_BYTES {
                    // A request above the channel ceiling used to be
                    // silently clamped — the producer then believed it
                    // had headroom it didn't. Loud beats wedged.
                    log::error!(
                        "[graph] edge {}→{}: requested buffer {} exceeds the \
                         channel ceiling {} — lower the request or split the stream.",
                        edge.from_module,
                        edge.to_module,
                        buf_size,
                        MAX_CHAN_BYTES,
                    );
                    return -1;
                }
            }
            if max_record > 0 {
                const MIN_CHAN_BYTES: u32 = 64;
                const MAX_CHAN_BYTES: u32 = 4 * 1024 * 1024;
                // Model the grant the open below will actually make:
                // sized requests are normalised (clamp + pow2); an
                // unsized edge (buf_size == 0) takes the kernel's
                // default ring, NOT 64 bytes — modelling it as 64
                // would fail every max_record-only port spuriously.
                let granted = if buf_size == 0 {
                    crate::abi::CHANNEL_BUFFER_SIZE as u32
                } else {
                    buf_size
                        .clamp(MIN_CHAN_BYTES, MAX_CHAN_BYTES)
                        .next_power_of_two()
                };
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
            }
        }

        let producer_mod = edge.from_module as u8;
        let chan = if buf_size > 0 {
            // `channel_open` accepts only an exact 4-byte LE u32 that
            // is already a power of two and in `[64, 256 KiB]`. Module
            // hints and YAML overrides arrive as arbitrary `u32`s, so
            // the scheduler is the place that normalises before the
            // syscall sees them.
            const MIN_CHAN_BYTES: u32 = 64;
            // 256 KiB silently clamped large producers: app GPU/video frames run
            // past 1 MiB, so they could not transit in one ring fill and the
            // display gated/froze. The wasm buffer arena is 8 MiB, so a single
            // 4 MiB channel is safe (only channels that REQUEST more grow, and the
            // other channels together stay well under the remaining 4 MiB) — chunk's
            // GPU command ring wants a chunk mesh + far-terrain LOD ring in one step.
            const MAX_CHAN_BYTES: u32 = 4 * 1024 * 1024;
            let normalised = buf_size
                .clamp(MIN_CHAN_BYTES, MAX_CHAN_BYTES)
                .next_power_of_two();
            let config = normalised.to_le_bytes();
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
        if group > 0 && group < 128 {
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
    let mut group_writers: [u8; 128] = [0; 128];
    let mut valid = true;

    for edge in edges.iter() {
        if edge.channel < 0 {
            continue;
        }
        let group = edge.buffer_group as usize;
        if group == 0 || group >= 128 {
            continue;
        }
        if edge.is_ctrl() {
            continue;
        }

        let to_mod = edge.to_module;
        if to_mod < MAX_MODULES && sched.in_place_writer[to_mod] {
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
// Parameter Buffer
// ============================================================================

/// Maximum module-specific config size — from silicon TOML [kernel] section.
const MAX_MODULE_CONFIG_SIZE: usize = crate::kernel::config::MAX_MODULE_CONFIG_SIZE;

/// Buffer for module params.
///
/// Params are purely module-specific config from YAML.
/// Channels are passed as direct arguments to module_new.
///
/// IMPORTANT: This is statically allocated to avoid inflating the async
/// future size (16KB+ buffer would cause stack overflow when embedded
/// in the async state machine).
#[repr(C, align(4))]
pub struct ParamBuffer {
    data: [u8; MAX_MODULE_CONFIG_SIZE],
    len: usize,
}

/// Static param buffer — only used during sequential module instantiation.
static mut PARAM_BUFFER: ParamBuffer = ParamBuffer {
    data: [0; MAX_MODULE_CONFIG_SIZE],
    len: 0,
};

impl ParamBuffer {
    fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }

    fn len(&self) -> usize {
        self.len
    }

    fn set_len(&mut self, len: usize) {
        self.len = len;
    }

    /// Copy module-specific config bytes.
    fn write(&mut self, config: &[u8]) {
        let copy_len = config.len().min(MAX_MODULE_CONFIG_SIZE);
        self.data[..copy_len].copy_from_slice(&config[..copy_len]);
        self.len = copy_len;
    }
}

// ============================================================================
// Name Arena (static string interning)
// ============================================================================

/// Maximum name length (including null terminator space)
const MAX_NAME_LEN: usize = 32;

/// Maximum number of interned names
const MAX_NAMES: usize = 64;

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
    /// Returns "?" if arena is exhausted (should not happen with MAX_NAMES == MAX_MODULES).
    fn intern(name: &str) -> &'static str {
        // SAFETY: NameArena is scheduler-thread owned; static name buffers
        // are accessed only from prepare_graph / instantiate paths.
        unsafe {
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
pub use module_types::{BuiltInModule, DummyModule, MergeModule, ModuleSlot, TeeModule};

/// Live graph mutation (add owner / free owner). Multi-tenant only —
/// bare-metal single-tenant targets compile it out at zero cost.
#[cfg(feature = "multitenant")]
pub mod live;
#[cfg(feature = "multitenant")]
pub use live::{
    apply_add, free_owner, AddEdge, AddError, AddModule, AddSubgraph, Endpoint, FreeError,
    ModuleSource,
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
