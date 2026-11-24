//! Scheduler responsibility module (real module boundary; parent statics and
//! helpers reach us via `super`).
use super::*;

/// The module at the other end of `module_idx`'s port `index` of
/// `port_type` (0 in, 1 out, 2 ctrl), with that module's own port on the
/// edge as `(port_type, index)`. `None` when the port is not wired, or when
/// it is an output wired to more than one consumer: a port that reaches
/// several modules names none of them.
pub fn edge_peer(module_idx: usize, port_type: u8, index: u8) -> Option<(usize, u8, u8)> {
    // SAFETY: SCHED scheduler-thread owned; edges are written at graph setup
    // and live add, both on the scheduler thread.
    let sched = unsafe { &*core::ptr::addr_of!(SCHED) };
    let edges = &sched.edges[..sched.edge_count];
    match port_type {
        0 | 2 => edges
            .iter()
            .find(|e| {
                !e.tap
                    && e.to_module == module_idx
                    && e.to_port_index == index
                    && e.is_ctrl() == (port_type == 2)
            })
            .map(|e| (e.from_module, 1, e.from_port_index)),
        1 => {
            let mut it = edges
                .iter()
                .filter(|e| !e.tap && e.from_module == module_idx && e.from_port_index == index);
            let e = it.next()?;
            if it.next().is_some() {
                return None;
            }
            Some((
                e.to_module,
                if e.is_ctrl() { 2 } else { 0 },
                e.to_port_index,
            ))
        }
        _ => None,
    }
}

/// Read a port channel handle for a module. Mirror of `set_module_port`.
/// Returns -1 if unset or out of range.
pub fn get_module_port(module_idx: usize, port_type: u8, port_index: u8) -> i32 {
    if module_idx >= module_slots() {
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

/// Read a port channel handle for a module by its manifest-declared
/// binding, `(port_type, port_index)` as `abi::platform::native` states it.
/// A native module names the port it wants and the table says where the packer
/// wired it, so no platform restates a port's number by hand.
pub fn module_port(module_idx: usize, port: (u8, u8)) -> i32 {
    get_module_port(module_idx, port.0, port.1)
}

/// Set a port channel handle for a module. Used by BCM2712 platform
/// which doesn't go through the RP-side instantiate_one_module path.
/// port_type: 0=in, 1=out, 2=ctrl
pub fn set_module_port(module_idx: usize, port_type: u8, port_index: u8, channel: i32) {
    if module_idx >= module_slots() {
        return;
    }
    // SAFETY: SCHED scheduler-thread owned; module_idx bounded above.
    let ports = unsafe { &mut SCHED.ports[module_idx] };
    let idx = port_index as usize;
    // The module is that end of the channel, unless an edge already named it.
    let end = if port_type == 1 {
        crate::kernel::ipc::channel::End::Producer
    } else {
        crate::kernel::ipc::channel::End::Consumer
    };
    crate::kernel::ipc::channel::channel_bind_end(channel, end, module_idx as ModuleId);
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

/// The pool the per-module tables are sized from.
const MODULE_POOL: u16 = crate::abi::contracts::resource::POOL_MODULE_SLOTS;
/// The pool the per-edge tables are sized from.
const EDGE_POOL: u16 = crate::abi::contracts::resource::POOL_CHANNELS;

/// Declares [`SchedulerState`] from one list of its parts, and derives from
/// that list everything that must name each of them: construction, the
/// reservation and growth of the per-module and per-edge tables, and the
/// return to a graph-less state. A column added to the list is reserved,
/// grown and reset with the rest; nothing else names it.
///
/// - `module_columns`: one slot per module, reserved and grown together,
///   each slot returned to its initial value by `reset`.
/// - `edge_columns`: one slot per edge, likewise.
/// - `graph`: per-graph values, returned to their initial value by `reset`.
/// - `kept`: values `reset` leaves alone, each for the reason its doc gives.
///
/// The module table itself (`modules`), the slot generation, the per-domain
/// orders and the per-domain records are not in the lists: each is handled
/// by name below for the reason its doc gives.
macro_rules! scheduler_state {
    (
        module_columns { $( $(#[$mm:meta])* $mv:vis $m:ident : $mt:ty = $mi:expr ),* $(,)? }
        edge_columns { $( $(#[$em:meta])* $ev:vis $e:ident : $et:ty = $ei:expr ),* $(,)? }
        graph { $( $(#[$gm:meta])* $gv:vis $g:ident : $gt:ty = $gi:expr ),* $(,)? }
        kept { $( $(#[$km:meta])* $kv:vis $k:ident : $kt:ty = $ki:expr ),* $(,)? }
    ) => {
        /// All scheduler runtime state, returned to its graph-less state by
        /// one `reset()` derived from the declaration (`scheduler_state!`).
        pub struct SchedulerState {
            /// Instantiated module slots. Reserved and committed after every
            /// other per-module table: its committed count is
            /// `module_slots()`, the bound the others are indexed by, so a
            /// reservation refused part-way leaves it no longer than any
            /// other.
            pub modules: ModTable<ModuleSlot>,
            /// Per-slot generation. Bumped, never cleared, on every event
            /// that ends an occupancy (graph reset, a slot vacated, a module
            /// replaced or restarted), so a pair (slot, generation) names one
            /// occupancy and an outstanding snapshot of a reused slot reads
            /// as stale.
            pub(crate) slot_generation: ModTable<u32>,
            /// Each domain's projection of the composer's order: the order
            /// its pass walks. Per-module tables, reserved with them; kept
            /// apart from [`DomainState`] because a table's storage is not
            /// reset by assignment.
            pub(crate) domain_exec_order: [ModTable<ModuleId>; MAX_DOMAINS],
            /// Per-domain state (see [`DomainState`]).
            pub(crate) domains: [DomainState; MAX_DOMAINS],
            $( $(#[$mm])* $mv $m: ModTable<$mt>, )*
            $( $(#[$em])* $ev $e: EdgeTable<$et>, )*
            $( $(#[$gm])* $gv $g: $gt, )*
            $( $(#[$km])* $kv $k: $kt, )*
        }

        impl SchedulerState {
            const fn new() -> Self {
                Self {
                    modules: crate::boot_table!(MAX_MODULES, ModuleSlot::Empty, MODULE_POOL),
                    slot_generation: crate::boot_table!(MAX_MODULES, 0, MODULE_POOL),
                    domain_exec_order: [const { crate::boot_table!(MAX_MODULES, 0, MODULE_POOL) };
                        MAX_DOMAINS],
                    domains: [const { DomainState::new() }; MAX_DOMAINS],
                    $( $m: crate::boot_table!(MAX_MODULES, $mi, MODULE_POOL), )*
                    $( $e: crate::boot_table!(MAX_CHANNELS, $ei, EDGE_POOL), )*
                    $( $g: $gi, )*
                    $( $k: $ki, )*
                }
            }

            /// Reserve every per-module table for `ceiling` slots, the module
            /// table last.
            ///
            /// # Safety
            /// As [`size_module_tables`](Self::size_module_tables).
            unsafe fn reserve_module_tables(
                &mut self,
                ceiling: usize,
            ) -> Result<(), crate::kernel::mem::table::TableError> {
                $( self.$m.reserve(ceiling)?; )*
                self.slot_generation.reserve(ceiling)?;
                for t in self.domain_exec_order.iter() {
                    t.reserve(ceiling)?;
                }
                // SAFETY: the caller's contract covers the heap table too: it
                // is a per-module table, reserved with the rest.
                unsafe { crate::kernel::mem::heap::reserve_heaps(ceiling)? };
                self.modules.reserve(ceiling)
            }

            /// The most slots any per-module table holds committed. A table
            /// touched before its plan sized it keeps the slots its first use
            /// committed, so the tables of one graph can arrive at sizing
            /// with different counts.
            fn module_tables_committed(&self) -> usize {
                let mut m = self.modules.len().max(self.slot_generation.len());
                $( m = m.max(self.$m.len()); )*
                for t in self.domain_exec_order.iter() {
                    m = m.max(t.len());
                }
                m.max(crate::kernel::mem::heap::heap_slots())
            }

            /// Commit per-module slots until `n` are live, within the
            /// reserved ceiling: a segment at a time, at boot and when a live
            /// add needs a slot. The module table commits last.
            pub(crate) fn grow_module_tables(
                &mut self,
                n: usize,
            ) -> Result<(), crate::kernel::mem::table::TableError> {
                $( self.$m.grow(n)?; )*
                self.slot_generation.grow(n)?;
                for t in self.domain_exec_order.iter() {
                    t.grow(n)?;
                }
                crate::kernel::mem::heap::grow_heaps(n)?;
                self.modules.grow(n)
            }

            /// Reserve the per-edge tables for `ceiling` edges and commit
            /// `live`; they share an index, so they commit one count and hold
            /// what any of them already holds.
            ///
            /// # Safety
            /// As [`size_module_tables`](Self::size_module_tables).
            pub(crate) unsafe fn size_edge_tables(
                &mut self,
                ceiling: usize,
                live: usize,
            ) -> Result<(), crate::kernel::mem::table::TableError> {
                let mut ceiling = ceiling;
                loop {
                    $( self.$e.reserve(ceiling)?; )*
                    let mut held = 0usize;
                    $( held = held.max(self.$e.len()); )*
                    if held <= ceiling {
                        return self.grow_edge_tables(live.max(held));
                    }
                    ceiling = held;
                }
            }

            /// Commit per-edge slots until `n` are live.
            pub(crate) fn grow_edge_tables(
                &mut self,
                n: usize,
            ) -> Result<(), crate::kernel::mem::table::TableError> {
                $( self.$e.grow(n)?; )*
                Ok(())
            }

            /// Return slot `i`'s per-module columns to their initial values.
            /// The module table, the generation and the gateway are the
            /// caller's.
            fn reset_module_columns(&mut self, i: usize) {
                $( self.$m[i] = $mi; )*
            }

            /// Return the per-edge columns of edge `i` to their initial values.
            fn reset_edge_columns(&mut self, i: usize) {
                $( self.$e[i] = $ei; )*
            }

            /// Return the per-graph values to their initial values.
            fn reset_graph_values(&mut self) {
                $( self.$g = $gi; )*
            }
        }
    };
}

scheduler_state! {
    module_columns {
        /// Per-module port assignments
        pub ports: ModulePorts = ModulePorts::empty(),
        /// Per-module declared port capacities (buffer size requests)
        pub(crate) port_caps: PortCapacities = PortCapacities::NONE,
        /// Per-module finished flags (done or errored)
        pub(crate) finished: bool = false,
        /// Per-module arena allocations
        pub(crate) arenas: ArenaInfo = ArenaInfo::empty(),
        /// Per-module grants: word 0 holds a bit per contract id, word 1 a bit
        /// per op-level grant (`registry::grant`). The module may call an op
        /// only when it holds the op's grant.
        pub(crate) grants: [u64; 2] = [0; 2],
        /// Per-module type: the config entry's `name_hash`, the FNV-1a of the
        /// module's type name. Stable across boots and graph edits, so it names
        /// what a module is where the slot index names only where it sits.
        pub(crate) type_hash: u32 = 0,
        /// Per-module instance-params blob pointer + length, recorded by
        /// platform loaders that hold the source bytes (the wasm loader) so a
        /// module can fetch its params through `MODULE_INSTANCE_PARAMS`.
        pub(crate) module_params_ptr: *const u8 = core::ptr::null(),
        pub(crate) module_params_len: usize = 0,
        /// The module's interrupt-mode cycle budget (params tag 0xFB); `0`
        /// is `DEFAULT_ISR_BUDGET_CYCLES`.
        pub(crate) isr_budget_cycles: u32 = 0,
        /// The hardware line an `irq`-domain module owns (params tag 0xFC);
        /// `u16::MAX` when unset.
        pub(crate) irq: u16 = u16::MAX,
        /// What the module's signature established, as admission validated
        /// it (`loader::validate_module`): instantiation reads it rather
        /// than validating the same bytes again.
        pub(crate) module_signing: crate::kernel::module::loader::Signing =
            crate::kernel::module::loader::Signing::Unverified,
        /// Per-module mailbox_safe flag (header flags bit 0): can consume from mailbox
        pub(crate) mailbox_safe: bool = false,
        /// Per-module in_place_writer flag (header flags bit 1): uses acquire_inplace
        pub(crate) in_place_writer: bool = false,
        /// Per-module deferred ready flag (header flags bit 2)
        pub(crate) deferred_ready: bool = false,
        /// Per-module protection level (tag 0xF5). A gated level routes the
        /// module through the protected entry; a privileged one keeps the direct
        /// call.
        pub(crate) protection: fluxor_contracts::isolation::Level =
            fluxor_contracts::isolation::Level::Privileged,
        /// Per-module device window (base, size) from tag 0xFD; size 0 = none.
        pub(crate) device_window: (u64, u32) = (0, 0),
        /// Per-module ready flag (true = outputs meaningful, false = still initializing)
        pub(crate) ready: bool = true,
        /// Per-module upstream dependency bitmask (precomputed from edges).
        /// FORWARD edges only — used for the readiness gate, where counting a
        /// cycle back-edge would deadlock the feedback pair.
        pub(crate) upstream_mask: ModuleMask = ModuleMask::EMPTY,
        /// Per-module predecessor bitmask over ALL edges — forward AND cycle
        /// back-edges. Used ONLY for sink-completion (`cli_out`): a sink must not
        /// declare itself done while a producer that can still feed it — including
        /// one reached through a feedback cycle — is alive.
        pub(crate) completion_mask: ModuleMask = ModuleMask::EMPTY,
        /// Per-module step period in nominal ticks of its domain (0 or 1 =
        /// every pass). The module steps when the wall clock reaches
        /// `module_next_due_us`, which then advances by
        /// `step_period × domain_tick_us`.
        pub(crate) step_period: u8 = 0,
        /// Per-module phase within its period (header `step_phase`, `< period`):
        /// the first due falls `period - phase - 1` nominal ticks after the
        /// module's first pass, so coarse-period modules can be staggered.
        pub(crate) step_phase: u8 = 0,
        /// Per-module absolute next-due wall clock (µs) of a periodic module.
        /// `0` = not yet anchored (anchored on its first pass).
        pub(crate) module_next_due_us: u64 = 0,
        /// Per-module idle-safe attestation: the module owner asserts it is
        /// demand-driven (woken by events / its own periodic schedule) and may be
        /// idle-skipped. Default false = fail-closed: an unattested workload graph
        /// is never fully parked, only relaxed to the backstop (`tick_max`).
        pub(crate) module_idle_safe: bool = false,
        /// Per-module count of consecutive passes the readiness gate vetoed the
        /// module's step; reset to 0 on any actual step. Surfaced via
        /// `ModuleStateSnapshot::inactive_for_ticks`.
        pub(crate) inactive_for_ticks: u32 = 0,
        /// Per-module self-reported latency in frames
        pub(crate) module_latency: u32 = 0,
        /// Per-module accumulated downstream latency in frames
        pub(crate) downstream_latency: u32 = 0,
        /// Per-module fault bookkeeping (state, policy, counters)
        pub(crate) fault_info: ModuleFaultInfo = ModuleFaultInfo::new(),
        /// Per-module domain assignment (0 = default domain)
        pub(crate) domain_id: u8 = 0,
        /// Per-module pre-pass opt-in (`ModuleEntry::pre_pass`): the
        /// module runs in its domain's pre-pass slot, not its order.
        pub(crate) pre_pass: bool = false,
        /// Wall-clock each module consumed in the current pass, and how many
        /// times it was stepped, so a budget overrun can name what actually
        /// spent the budget rather than whichever module finished last.
        pub(crate) pass_module_us: u32 = 0,
        pub(crate) pass_module_steps: u16 = 0,
        /// Code base address per module (for resolving export offsets)
        pub(crate) module_code_base: usize = 0,
        /// Code size per module (for provider pointer validation)
        pub(crate) module_code_size: u32 = 0,
        /// Per-module step-time bucket counts (see `step_bucket`).
        pub(crate) step_hist: [u32; 8] = [0; 8],
        /// Per-module owner handle. Workload owner lifecycle in the owner
        /// table is managed by the transition path; a reset slot is the
        /// node owner's.
        pub(crate) module_owner: OwnerHandle = OWNER_NODE,
    }
    edge_columns {
        /// Flow-stall sampler state: last sampled ring fill +
        /// consecutive-unchanged count per classed edge.
        pub(crate) flow_last_fill: u32 = 0,
        pub(crate) flow_stalls: u8 = 0,
        /// Graph edge wiring. Last: its committed count bounds the others.
        pub edges: Edge = Edge::simple(0, 0),
    }
    graph {
        /// Number of populated entries in `edges`.
        pub edge_count: usize = 0,
        /// Wall-clock time (ms, `hal::now_millis()`) at which the current
        /// `Draining` phase started; `u64::MAX` when no drain is in progress.
        pub(crate) drain_started_ms: u64 = u64::MAX,
        /// Graph-level sample rate from config (0 = not set)
        pub(crate) graph_sample_rate: u32 = 0,
        /// Tick period in microseconds (0 = default 1000us)
        pub(crate) tick_us: u32 = 0,
        /// Number of domains configured (0 or 1 = single default domain)
        pub(crate) domain_count: u8 = 0,
        /// Readiness-gate starvation sweep (`readiness_starvation_sweep`), in
        /// order: the modules held when the current window opened and at every
        /// sweep since, the held modules already reported for their current
        /// hold, when the sweep last ran, and when the current window opened.
        pub(crate) starvation_suspect: ModuleMask = ModuleMask::EMPTY,
        pub(crate) starvation_reported: ModuleMask = ModuleMask::EMPTY,
        pub(crate) starvation_sweep_ms: u64 = 0,
        pub(crate) starvation_window_ms: u64 = 0,
        /// Edges with a cooperative⇄interrupt-mode bridge (`wire_isr_bridges`);
        /// the pump runs only when there is one.
        pub(crate) bridge_count: u16 = 0,
        /// Current reconfigure phase, queryable via `reconfigure_phase()`.
        pub(crate) reconfigure_phase: ReconfigurePhase = ReconfigurePhase::Running,
        /// Number of modules in the current graph, set by `prepare_graph`.
        pub(crate) active_module_count: usize = 0,
        /// A rebuild is pending. Set by `request_rebuild`, consumed by the
        /// per-platform domain loop, which performs a destructive reset + reload.
        pub(crate) rebuild_request: bool = false,
        /// Global step-time bucket counts across all modules.
        pub(crate) step_hist_global: [u32; 8] = [0; 8],
    }
    kept {
        /// Transaction marker for `prepare_graph`, owned by it: set at the
        /// start of preparation (before `reset`) and cleared once the new
        /// graph is wired, so a pass never sees a half-built graph. A failed
        /// preparation leaves it set until the next one.
        pub(crate) prepare_in_progress: bool = false,
        /// Workload owner table. Slot 0 is the node owner; sized at boot
        /// from the plan's `owners` ceiling, and kept across a graph reset
        /// (owner lifecycle belongs to the transition path).
        pub owners: OwnerTable = OwnerTable::kernel(),
    }
}

/// The kinds of monitor line a domain throttles (`DomainState::mon_throttle`).
#[derive(Clone, Copy)]
#[repr(u8)]
pub(crate) enum MonLine {
    HeavyStep = 0,
    BudgetOverrun = 1,
    BurstAbort = 2,
    WakeDefer = 3,
    Hotstart = 4,
}
const MON_LINES: usize = 5;

/// The least time between two lines of one monitor kind in one domain (ms).
/// On a coarse-timer host (the browser's `now_micros` floor is ~1–2 ms) every
/// step trips the per-step monitors; one line per window, carrying how many
/// were suppressed, still surfaces a rare native overrun.
const MON_LOG_THROTTLE_MS: u64 = 2_000;

/// One monitor line's throttle: when it last logged and how many were
/// suppressed since.
#[derive(Clone, Copy)]
pub(crate) struct Throttle {
    last_ms: u64,
    suppressed: u32,
    primed: bool,
}

impl Throttle {
    const NEW: Throttle = Throttle {
        last_ms: 0,
        suppressed: 0,
        primed: false,
    };
}

/// What one execution domain's pass engine owns. Touched by that domain's
/// loop only (its own core on bcm2712), except the atomics, which other
/// cores and the step-effect syscall read or set.
pub(crate) struct DomainState {
    /// The domain's nominal tick (0 = the graph's `tick_us`).
    pub(crate) tick_us: u32,
    /// The domain's execution mode.
    pub(crate) exec_mode: ExecMode,
    /// Adaptive enable flags: bit 0 (a) demand-driven idle, bit 1 (b)
    /// adaptive cadence. `0` = adaptive off, pacing on the nominal tick.
    pub(crate) adaptive_flags: u8,
    /// Latency-floor target the pacer drives toward under load, µs.
    pub(crate) tick_min_us: u32,
    /// Relaxed/idle backstop cadence the pacer relaxes toward, µs.
    pub(crate) tick_max_us: u32,
    /// Budget per pass, µs: the tick. `0` = no budget.
    pub(crate) budget_limit_us: u32,
    /// µs consumed in the current pass, every step charged whatever it
    /// returned.
    pub(crate) budget_consumed_us: u64,
    /// Passes whose consumption crossed the limit.
    pub(crate) budget_overruns: u32,
    /// Decaying peak-hold of the worst single step, µs: the adaptive floor's
    /// input. Raised by every step, decayed once per pass.
    pub(crate) worst_step_us: u32,
    /// The domain's modules (`take_wake_in_mask`, the idle decision).
    pub(crate) module_mask: ModuleMask,
    /// Entries in `domain_exec_order[d]`.
    pub(crate) module_count: ModuleId,
    /// Where the pass starts in the order; advanced on every budget overrun
    /// so the modules after an overrunner are not starved.
    pub(crate) exec_offset: ModuleId,
    /// The pre-pass slot: modules drained once before the order each tick.
    pub(crate) pre_pass_order: [ModuleId; MAX_PRE_PASS_PER_DOMAIN],
    pub(crate) pre_pass_count: u8,
    /// Passes whose pre-pass slot crossed its budget
    /// ([`SchedulerState::pre_pass_budget_us`]).
    pub(crate) pre_pass_overruns: u32,
    /// Tick passes run; the domain's clock for fault records and monitor
    /// lines. Kept across a graph reset.
    pub(crate) pass_count: AtomicU32,
    /// A module burst in the current sub-pass (re-pass signal).
    pub(crate) burst_seen: AtomicBool,
    /// A module burst during the current graph's walk (pacer busy signal).
    pub(crate) pacer_burst: AtomicBool,
    /// A module reported useful work during the current graph's walk
    /// (`REPORT_STEP_EFFECT`; pacer busy signal).
    pub(crate) pacer_work: AtomicBool,
    /// Monitor-line throttles (`MonLine`).
    mon: [Throttle; MON_LINES],
}

impl DomainState {
    pub(crate) const fn new() -> Self {
        Self {
            tick_us: 0,
            exec_mode: ExecMode::Tick,
            adaptive_flags: 0,
            tick_min_us: 0,
            tick_max_us: 0,
            budget_limit_us: 0,
            budget_consumed_us: 0,
            budget_overruns: 0,
            worst_step_us: 0,
            module_mask: ModuleMask::EMPTY,
            module_count: 0,
            exec_offset: 0,
            pre_pass_order: [0; MAX_PRE_PASS_PER_DOMAIN],
            pre_pass_count: 0,
            pre_pass_overruns: 0,
            pass_count: AtomicU32::new(0),
            burst_seen: AtomicBool::new(false),
            pacer_burst: AtomicBool::new(false),
            pacer_work: AtomicBool::new(false),
            mon: [Throttle::NEW; MON_LINES],
        }
    }

    /// Return to the graph-less state, keeping the pass count.
    fn reset(&mut self) {
        let passes = self.pass_count.load(Ordering::Relaxed);
        *self = Self::new();
        self.pass_count = AtomicU32::new(passes);
    }

    /// Tick passes this domain has run.
    #[inline]
    pub(crate) fn passes(&self) -> u32 {
        self.pass_count.load(Ordering::Relaxed)
    }

    /// `Some(suppressed since the last line)` when a `line` may log now
    /// (opening a new window), else `None`, counting it suppressed.
    pub(crate) fn mon_throttle(&mut self, line: MonLine) -> Option<u32> {
        let now = crate::kernel::sys::hal::now_millis();
        let t = &mut self.mon[line as usize];
        if !t.primed || now.wrapping_sub(t.last_ms) >= MON_LOG_THROTTLE_MS {
            let n = t.suppressed;
            *t = Throttle {
                last_ms: now,
                suppressed: 0,
                primed: true,
            };
            Some(n)
        } else {
            t.suppressed = t.suppressed.wrapping_add(1);
            None
        }
    }
}

impl SchedulerState {
    /// What domain `d`'s pre-pass slot may take of one pass, µs: its share
    /// ([`PRE_PASS_BUDGET_SHARE`]) of the domain's tick (the graph's when
    /// the domain declares none), at least 1.
    pub(crate) fn pre_pass_budget_us(&self, d: usize) -> u64 {
        let tick = match self.domains[d].tick_us {
            0 => self.tick_us,
            t => t,
        };
        u64::from((tick / PRE_PASS_BUDGET_SHARE).max(1))
    }

    /// Reserve the per-module tables for `ceiling` slots and commit `live`
    /// of them. Graph-preparation context: no reference into a table is held.
    ///
    /// # Safety
    /// No reference into any per-module table may be live (`Table::reserve`).
    pub(crate) unsafe fn size_module_tables(
        &mut self,
        ceiling: usize,
        live: usize,
    ) -> Result<(), crate::kernel::mem::table::TableError> {
        // SAFETY: the caller's contract.
        unsafe { self.reserve_module_tables(ceiling)? };
        // Every per-module table is indexed by the same slot, so all of them
        // commit the same count: what the graph needs, or what any of them
        // already holds, whichever is more. A table touched before its plan
        // sized it holds its first use's slots, which may be past the plan's
        // ceiling; the whole group is then reserved to hold them too, or the
        // tables the plan reached first could not grow to that count.
        let held = self.module_tables_committed();
        if held > ceiling {
            // SAFETY: the caller's contract.
            unsafe { self.reserve_module_tables(held)? };
        }
        self.grow_module_tables(live.max(held))
    }

    /// Reset all runtime state for a new graph setup. Leaves the state and
    /// name arenas (separate concerns) and the `kept` values.
    pub(crate) fn reset(&mut self) {
        for i in 0..self.edges.len() {
            self.reset_edge_columns(i);
        }
        for i in 0..self.modules.len() {
            self.modules[i] = ModuleSlot::Empty;
            if crate::kernel::module::gateway::is_registered(i) {
                crate::kernel::module::gateway::release(i);
            }
            self.reset_module_columns(i);
            // Every outstanding snapshot of the previous graph's slot is now
            // stale.
            self.slot_generation[i] = self.slot_generation[i].wrapping_add(1);
        }
        self.reset_graph_values();
        for d in self.domains.iter_mut() {
            d.reset();
        }
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

/// Per-core current module index (supports multi-core BCM2712).
/// On single-core platforms, only index 0 is used. Avoids data races
/// when multiple cores step modules concurrently.
static CURRENT_MODULE_PER_CORE: [portable_atomic::AtomicU32; MAX_DOMAINS] =
    [const { portable_atomic::AtomicU32::new(0) }; MAX_DOMAINS];

/// Per core: a module's `step` is on the stack. Instantiation, teardown and
/// the scheduler's own work run with it clear, so what a step costs the
/// kernel (`heap::note_zeroed`) can be told from what the graph's lifecycle
/// costs.
static STEP_ACTIVE: [AtomicBool; MAX_DOMAINS] = [const { AtomicBool::new(false) }; MAX_DOMAINS];

/// Whether a module's step is running on this core.
#[inline]
pub fn in_module_step() -> bool {
    let core = crate::kernel::sys::hal::core_id();
    STEP_ACTIVE
        .get(core)
        .is_some_and(|f| f.load(Ordering::Relaxed))
}

/// Run a module's `step` with [`in_module_step`] set on this core.
#[inline]
pub(crate) fn as_module_step<R>(f: impl FnOnce() -> R) -> R {
    let core = crate::kernel::sys::hal::core_id();
    let flag = STEP_ACTIVE.get(core);
    if let Some(flag) = flag {
        flag.store(true, Ordering::Relaxed);
    }
    let r = f();
    if let Some(flag) = flag {
        flag.store(false, Ordering::Relaxed);
    }
    r
}

/// Return the index of the module currently being stepped.
/// Used by event::event_create() to set event ownership.
pub fn current_module_index() -> usize {
    let core = crate::kernel::sys::hal::core_id();
    CURRENT_MODULE_PER_CORE.get(core).map_or(MAX_MODULES, |c| {
        c.load(portable_atomic::Ordering::Relaxed) as usize
    })
}

/// The module currently being stepped on this core, as the id an owner
/// field records: `NO_MODULE` in kernel context (between steps the index is
/// parked at `MAX_MODULES`), so what the kernel allocates for itself is
/// owned by no module rather than by whichever slot the parked value aliases.
pub fn current_module_id() -> ModuleId {
    let idx = current_module_index();
    if idx < module_slots() {
        idx as ModuleId
    } else {
        NO_MODULE
    }
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

/// Record the arena the loader allocated for `idx`, so `arena_get` hands
/// the module the same region its `heap_alloc` draws from and teardown has
/// one range to reclaim. The loader is the allocator because it is the half
/// that knows whether the module asked for isolation, and an isolated
/// module's arena has to come from the page-aligned region.
///
/// # Safety
/// Scheduler-thread context during instantiation; `ptr`/`size` must be the
/// range `loader::alloc_state` returned for this module.
pub unsafe fn set_module_arena(idx: usize, ptr: *mut u8, size: u32) {
    // A raw pointer taken first, then dereferenced: a `&mut SCHED` would be a
    // reference to a `static mut`, which is what the raw form exists to avoid.
    let p = &raw mut SCHED;
    let sched = &mut *p;
    if idx < sched.arenas.len() {
        sched.arenas[idx] = ArenaInfo { ptr, size };
    }
}

/// Take back the arena recorded for `idx` (`set_module_arena`), leaving
/// none: the loader releasing a construction that did not finish.
///
/// # Safety
/// Scheduler-thread context during instantiation.
pub unsafe fn take_module_arena(idx: usize) -> (*mut u8, usize) {
    let p = &raw mut SCHED;
    let sched = &mut *p;
    match sched.arenas.get_mut(idx) {
        Some(a) => {
            let taken = core::mem::replace(a, ArenaInfo::empty());
            (taken.ptr, taken.size as usize)
        }
        None => (core::ptr::null_mut(), 0),
    }
}

/// State-arena bytes charged to whoever owns module `idx`: its state buffer
/// plus its heap's cap. An elastic heap commits only what the module uses,
/// but its owner is admitted for the most it may grow to, so a workload's
/// `state_cap` bounds its worst case rather than a snapshot.
///
/// A PIC module and a native one alike draw their state from the arena; an
/// empty slot reports 0. The figure is what the owner drew from the shared
/// arena, not how much memory exists on its behalf.
pub fn module_state_footprint(idx: usize) -> u32 {
    // SAFETY: scheduler-thread read of the module table and arena table.
    unsafe {
        let p = &raw const SCHED;
        let sched = &*p;
        if idx >= sched.modules.len() {
            return 0;
        }
        let state = sched.modules[idx].state().map_or(0, |(_, size)| size);
        let arena = if idx < sched.arenas.len() {
            sched.arenas[idx].size
        } else {
            0
        };
        state.saturating_add(arena)
    }
}

/// Set the current module index. Used by provider dispatch for context switching.
pub fn set_current_module(idx: usize) {
    let core = crate::kernel::sys::hal::core_id();
    if let Some(c) = CURRENT_MODULE_PER_CORE.get(core) {
        c.store(idx as u32, portable_atomic::Ordering::Relaxed);
    }
}

/// Run `f` as module `idx`, then return to whichever context was current.
///
/// A module's entry points (`module_new`, `module_drain`) can be reached from
/// inside another module's syscall — a subgraph staged by a workload CREATE,
/// a drain asked through reconfigure — and that caller's next syscall is
/// gated on its own identity. At boot the context around the call is no
/// module, and that is what comes back.
pub fn with_module_context<R>(idx: usize, f: impl FnOnce() -> R) -> R {
    let caller = current_module_index();
    set_current_module(idx);
    let r = f();
    set_current_module(caller);
    r
}

/// Per-core module index of whoever *asked* for the provider frame currently
/// running, published for the duration of that frame.
///
/// `provider_call` carries no owner argument and should not gain one:
/// widening it is a positional-ABI flag day across every module in the fleet,
/// for a fact the kernel already holds. Publishing the caller instead costs
/// one relaxed store per dispatch and lets a provider ask.
static CALLER_MODULE_PER_CORE: [portable_atomic::AtomicU32; MAX_DOMAINS] =
    [const { portable_atomic::AtomicU32::new(MAX_MODULES as u32) }; MAX_DOMAINS];

/// Module index that invoked the provider frame currently running, or
/// [`MAX_MODULES`] when nothing is on the stack (a module stepping normally
/// rather than serving somebody's request).
pub fn caller_module_index() -> usize {
    let core = crate::kernel::sys::hal::core_id();
    CALLER_MODULE_PER_CORE[core].load(portable_atomic::Ordering::Relaxed) as usize
}

/// Publish the caller for a provider frame. Each frame saves and restores its
/// own predecessor, so nesting is exact: a provider that calls another
/// provider is that one's caller, not the original requester.
pub fn set_caller_module(idx: usize) {
    let core = crate::kernel::sys::hal::core_id();
    CALLER_MODULE_PER_CORE[core].store(idx as u32, portable_atomic::Ordering::Relaxed);
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

/// The grants of the module currently being stepped: word 0 a bit per
/// contract id, word 1 a bit per op-level grant.
///
/// None outside a module's step: a live-added module can make a
/// `provider_call` before its slot is current, leaving the "no module"
/// sentinel, and that call holds nothing.
pub fn current_module_grants() -> [u64; 2] {
    let idx = current_module_index();
    if idx >= module_slots() {
        return [0; 2];
    }
    // SAFETY: idx bounded above; scheduler-thread-only read.
    unsafe { SCHED.grants[idx] }
}

/// Get the code region (base, size) for a module, used for provider pointer validation.
pub fn module_code_region(idx: usize) -> (usize, u32) {
    if idx >= module_slots() {
        return (0, 0);
    }
    // SAFETY: scheduler-thread-only read; idx bounded.
    unsafe { (SCHED.module_code_base[idx], SCHED.module_code_size[idx]) }
}

/// Set a module's grants (the platform loaders that stage modules from
/// their own images).
pub fn set_module_grants(idx: usize, grants: [u64; 2]) {
    if idx >= module_slots() {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; idx bounded.
    unsafe {
        SCHED.grants[idx] = grants;
    }
}

/// Record the type of the module in slot `idx`.
pub fn set_module_type_hash(idx: usize, type_hash: u32) {
    if idx >= module_slots() {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; idx bounded.
    unsafe {
        SCHED.type_hash[idx] = type_hash;
    }
}

/// The type of the module in slot `idx`, or 0 when the slot holds none.
pub fn module_type_hash(idx: usize) -> u32 {
    if idx >= module_slots() {
        return 0;
    }
    // SAFETY: scheduler-thread-only read; idx bounded.
    unsafe { SCHED.type_hash[idx] }
}

/// The owner the node image's program section names the module in slot `idx`
/// by: its type and its ordinal among the modules of that type in lower
/// slots, which is the order the packer counts instances in
/// (`tools/src/modules.rs::collect_programs`). `None` for an empty slot.
fn program_owner(idx: usize) -> Option<(u32, u8)> {
    if idx >= module_slots() {
        return None;
    }
    let ty = module_type_hash(idx);
    if ty == 0 {
        return None;
    }
    let mut ordinal = 0u8;
    for j in 0..idx {
        if module_type_hash(j) == ty {
            ordinal = ordinal.checked_add(1)?;
        }
    }
    Some((ty, ordinal))
}

/// The program in `slot` that the node image carries for the module in slot
/// `idx`.
pub fn module_program(idx: usize, slot: u8) -> Option<crate::kernel::module::loader::ProgramRef> {
    let (ty, ordinal) = program_owner(idx)?;
    // SAFETY: scheduler-thread read of the loader, which is set at boot.
    unsafe { static_storage::static_loader() }.find_program(ty, ordinal, slot)
}

/// The region holding every program the node image carries for the module in
/// slot `idx`, as (base, length): what the module is granted when isolated.
pub fn module_program_region(idx: usize) -> Option<(*const u8, usize)> {
    let (ty, ordinal) = program_owner(idx)?;
    // SAFETY: scheduler-thread read of the loader, which is set at boot.
    unsafe { static_storage::static_loader() }.program_region(ty, ordinal)
}

/// The generation of slot `idx`: bumped whenever the slot is reset,
/// restarted or given another module, so a pair (slot, generation) names
/// one module occupancy.
pub fn module_slot_generation(idx: usize) -> u32 {
    if idx >= module_slots() {
        return 0;
    }
    // SAFETY: scheduler-thread-only read; idx bounded.
    unsafe { SCHED.slot_generation[idx] }
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
    if idx >= module_slots() {
        return;
    }
    SCHED.module_params_ptr[idx] = ptr;
    SCHED.module_params_len[idx] = len;
}

/// Look up the params blob registered via `set_module_params`. Returns
/// `(ptr, len)` — `(null, 0)` if the loader didn't register any.
pub fn module_params(idx: usize) -> (*const u8, usize) {
    if idx >= module_slots() {
        return (core::ptr::null(), 0);
    }
    // SAFETY: scheduler-thread-only read; idx bounded.
    unsafe { (SCHED.module_params_ptr[idx], SCHED.module_params_len[idx]) }
}

/// Copy module `idx`'s instance params into `out`, as many as fit; answers
/// their whole length (0 for a module with none).
pub fn copy_module_params(idx: usize, out: &mut [u8]) -> usize {
    let (src, len) = module_params(idx);
    if src.is_null() || len == 0 {
        return 0;
    }
    // SAFETY: the params the loader recorded for a live module stay mapped
    // and unchanged while it is loaded, and the read ends here.
    let params = unsafe { core::slice::from_raw_parts(src, len) };
    let n = len.min(out.len());
    out[..n].copy_from_slice(&params[..n]);
    len
}

/// Replace the instance in slot `idx` with a fresh one of `vt`, built with
/// `params`: the previous instance is released and its state returned to
/// the arena. A graph's modules take the splice's path instead.
pub fn store_native_module(
    idx: usize,
    vt: &'static super::native::NativeVtable,
    params: &[u8],
) -> Result<(), i32> {
    if idx >= module_slots() {
        return Err(crate::kernel::sys::errno::EINVAL);
    }
    // SAFETY: scheduler-thread-only mutation; idx bounded.
    let sched = unsafe { &mut *core::ptr::addr_of_mut!(SCHED) };
    let (ptr, size) = sched.modules[idx].take_state_range();
    if !ptr.is_null() {
        // SAFETY: the range the vacated instance held; it is released.
        unsafe { crate::kernel::module::loader::free_state_range(ptr, size) };
    }
    let init = super::native::NativeInit {
        slot: idx,
        params,
        code: None,
    };
    let m = with_module_context(idx, || super::native::NativeModule::new(vt, &init))?;
    sched.modules[idx] = ModuleSlot::Native(m);
    sched.ready[idx] = true;
    // A replaced occupancy: outstanding snapshots of the slot are stale.
    sched.slot_generation[idx] = sched.slot_generation[idx].wrapping_add(1);
    Ok(())
}

/// Store a DynamicModule in the scheduler's module table (used by Linux platform).
pub fn store_dynamic_module(idx: usize, dm: DynamicModule) {
    if idx >= module_slots() {
        return;
    }
    // SAFETY: scheduler-thread-only mutation; idx bounded.
    unsafe {
        // No generation bump here, unlike `store_native_module`: this stores
        // a module whose `module_new` has already run (the pending load path,
        // `try_complete`), and anything it opened there was stamped with the
        // slot's current generation — bumping now would make its own
        // occupancy look stale (`query_key::MODULE_LIVE`). The slot's previous
        // occupant already moved the generation when it vacated (owner free,
        // rollback, restart, graph reset), as on the synchronous load path,
        // which stores the module without a bump too.
        let sched = &mut *core::ptr::addr_of_mut!(SCHED);
        let (ptr, size) = sched.modules[idx].take_state_range();
        if !ptr.is_null() {
            // The range the vacated instance held; it is released.
            crate::kernel::module::loader::free_state_range(ptr, size);
        }
        sched.modules[idx] = ModuleSlot::Dynamic(dm);
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
    /// The config blob's CRC-32, as the parser verified it.
    pub config_checksum: u32,
    /// Module count in the compiled graph.
    pub module_count: u16,
    /// Compiled edge count (past 255 on the host profile).
    pub edge_count: u16,
    /// Tick interval in microseconds (`0` = default `DEFAULT_TICK_US`).
    pub tick_us: u32,
    /// Graph-level sample rate (`0` = not configured).
    pub sample_rate: u32,
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
        module_count: cfg.module_count,
        edge_count: cfg.edge_count,
        tick_us: cfg.header.tick_us as u32,
        sample_rate: sched.graph_sample_rate,
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
    if idx >= module_slots() {
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
/// contract; the channel the calling module reads that port through (which a
/// bridge or a repacking stage may have substituted for the edge's own)
/// resolves the edge when the index alone does not.
pub fn syscall_input_flow_budget(port_index: u8) -> i32 {
    let idx = current_module_index();
    if idx >= module_slots() {
        return 0;
    }
    let channel = get_module_port(idx, 0, port_index);
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
        let t = unsafe { SCHED.domains[domain_id].tick_us };
        if t > 0 {
            return t;
        }
    }
    tick_us()
}

/// Return the per-domain worst-recent single-step time in microseconds — the
/// adaptive-tick floor input (decaying peak-hold, NOT a monotonic max).
/// The pacer clamps `tick_min_us` up by `worst × margin` so a shortened tick
/// never shrinks the per-domain budget below one heavy step.
/// `0` until the domain has stepped at least once.
pub fn domain_worst_step_us(domain_id: usize) -> u32 {
    if domain_id < MAX_DOMAINS {
        // SAFETY: scheduler-thread-only read; domain_id bounded.
        unsafe { SCHED.domains[domain_id].worst_step_us }
    } else {
        0
    }
}

/// Adaptive-tick enable flags for a domain: bit 0 = (a) demand-driven idle,
/// bit 1 = (b) adaptive cadence. `0` ⇒ adaptive off.
pub fn domain_adaptive_flags(domain_id: usize) -> u8 {
    if domain_id < MAX_DOMAINS {
        // SAFETY: scheduler-thread-only read; domain_id bounded.
        unsafe { SCHED.domains[domain_id].adaptive_flags }
    } else {
        0
    }
}

/// Per-domain adaptive latency-floor target (µs). Default-filled to the
/// domain's tick when unconfigured, so it is a safe lower bound for the pacer.
pub fn domain_tick_min_us(domain_id: usize) -> u32 {
    if domain_id < MAX_DOMAINS {
        // SAFETY: scheduler-thread-only read; domain_id bounded.
        let v = unsafe { SCHED.domains[domain_id].tick_min_us };
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
        let v = unsafe { SCHED.domains[domain_id].tick_max_us };
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
        SCHED.domains[domain_id].adaptive_flags = flags;
        SCHED.domains[domain_id].tick_min_us = tick_min_us;
        SCHED.domains[domain_id].tick_max_us = tick_max_us;
    }
}

/// Test-only: set a module slot's tick-counted step period. Production sets this
/// from the config/manifest in `prepare_graph` / the splice; conformance tests
/// use it to exercise the period-gated runnable path (a multi-tick module must
/// keep its owning graph on the cooperative cadence — never idle-skipped).
pub fn set_step_period_for_test(slot: usize, period: u8) {
    if slot < module_slots() {
        // SAFETY: scheduler-thread-exclusive mutation; slot bounded.
        unsafe {
            SCHED.step_period[slot] = period;
            SCHED.module_next_due_us[slot] = 0;
        }
    }
}

/// Test-only: put a module slot into (or out of) the "deferred-ready, still
/// initialising" state the fail-closed `must_tick` predicate keys on — a
/// deferred-ready module that has not reached Ready must keep stepping even when
/// the graph is otherwise idle, or it could never finish initialising.
pub fn set_module_init_state_for_test(slot: usize, initialising: bool) {
    if slot < module_slots() {
        // SAFETY: scheduler-thread-exclusive mutation; slot bounded.
        unsafe {
            SCHED.deferred_ready[slot] = initialising;
            SCHED.ready[slot] = !initialising;
        }
    }
}

/// Test-only: set a module slot's idle-safe attestation (production sets it from
/// the workload's `WKLD` idle-safe flag at admission). Only an all-idle-safe graph may be fully
/// parked; an unattested workload is fail-closed to the `tick_max` backstop.
pub fn set_module_idle_safe_for_test(slot: usize, idle_safe: bool) {
    if slot < module_slots() {
        // SAFETY: scheduler-thread-exclusive mutation; slot bounded.
        unsafe {
            SCHED.module_idle_safe[slot] = idle_safe;
        }
    }
}

/// Mark every module currently owned by `owner` as idle-safe (or not) — the
/// admission-time application of a workload's idle-safe attestation. Bounded
/// boot-time pass; the resident-graph index's per-graph `idle_safe` is recomputed
/// by the following `rebuild_resident_graph_index`.
pub fn set_owner_idle_safe(owner: crate::kernel::workload::owner::OwnerHandle, idle_safe: bool) {
    // SAFETY: scheduler-thread-exclusive boot context.
    let sched = unsafe { &mut *core::ptr::addr_of_mut!(SCHED) };
    for i in 0..module_slots() {
        if matches!(sched.modules[i], ModuleSlot::Empty) {
            continue;
        }
        if sched.module_owner[i] == owner {
            sched.module_idle_safe[i] = idle_safe;
        }
    }
}
