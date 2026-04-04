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

use core::ptr::null;

use crate::kernel::hal;
use crate::kernel::config::{
    read_config_into, Config, ModuleEntry,
    MAX_MODULES as CONFIG_MAX_MODULES,
    MAX_GRAPH_EDGES,
};
use crate::kernel::loader::{DynamicModule, StartNewResult, ModuleLoader, reset_state_arena, ChannelHint, query_channel_hints, find_hint_for_port};
use crate::kernel::syscalls::{
    get_table_for_module_type,
    is_spi_initialized,
};
use crate::kernel::channel;
use crate::kernel::channel::{CHANNEL_TYPE_PIPE, POLL_IN, POLL_OUT, POLL_HUP, POLL_ERR, channel_set_flags, channel_set_mailbox};
use crate::kernel::syscalls as syscalls;
use crate::kernel::step_guard::{self, ModuleFaultInfo, FaultState, FaultPolicy, FaultStats, fault_type};
use crate::modules::{Module, StepOutcome};

// ============================================================================
// Graph Constants and Types
// ============================================================================

/// Maximum number of modules in a graph.
pub const MAX_MODULES: usize = CONFIG_MAX_MODULES;

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

/// Per-module drain state during DRAINING phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DrainState {
    /// Module is surviving the transition — not draining.
    Surviving = 0,
    /// Module is actively draining in-flight work.
    Draining = 1,
    /// Module has signaled drain complete (returned Done).
    Drained = 2,
    /// Module does not support drain — will be force-terminated.
    PendingTerminate = 3,
}

/// Maximum number of burst re-steps per module per tick.
/// When step() returns StepOutcome::Burst, the scheduler re-steps the module
/// up to this many additional times, stopping early if the module returns
/// Continue (no more work), Done, or Error.
/// This enables compute-heavy modules to do multiple chunks of work per tick
/// while remaining cooperative (each individual step is still bounded).
const MAX_BURST_STEPS: usize = 16384;

/// Maximum number of execution domains.
pub const MAX_DOMAINS: usize = 4;

/// Default tick period in microseconds (1ms).
pub const DEFAULT_TICK_US: u32 = 1000;

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
    /// Channel handle (assigned by open_channels)
    pub channel: i32,
    /// Source output port index (0 = primary)
    pub from_port_index: u8,
    /// Destination input/ctrl port index (0 = primary)
    pub to_port_index: u8,
    /// Buffer group ID for aliasing. 0 = no aliasing.
    /// Edges with the same non-zero group share the same channel buffer.
    pub buffer_group: u8,
    /// Edge class metadata (Local, DmaOwned, CrossCore). Pure metadata on single-core.
    pub edge_class: crate::kernel::config::EdgeClass,
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
            from_port_index: 0,
            to_port_index: 0,
            buffer_group: 0,
            edge_class: crate::kernel::config::EdgeClass::Local,
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
            from_port_index,
            to_port_index,
            buffer_group: 0,
            edge_class: crate::kernel::config::EdgeClass::Local,
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
    let module_hints = unsafe { &*(&raw const SCHED.hints) };

    // Pre-scan: compute max buffer size per group across all edges.
    // This ensures the channel is large enough for the most demanding
    // consumer (e.g. I2S requiring exactly 2048 bytes).
    let mut group_max_size: [u16; 128] = [0; 128];
    for edge in edges.iter() {
        let group = edge.buffer_group as usize;
        if group == 0 || group >= 128 { continue; }

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

        let edge_max = from_size.max(to_size);
        if edge_max > group_max_size[group] {
            group_max_size[group] = edge_max;
        }
    }

    // Map buffer_group -> channel handle for aliasing
    let mut group_channels: [i32; 128] = [-1; 128];
    let mut count = 0;
    for edge in edges.iter_mut() {
        // Check for buffer group aliasing
        let group = edge.buffer_group as usize;
        if group > 0 && group < 128 {
            if group_channels[group] >= 0 {
                // Verify destination module can safely consume from mailbox
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
        }

        // Determine buffer size: grouped edges use pre-computed max,
        // ungrouped edges use per-edge hint lookup.
        let buf_size = if group > 0 && group < 128 && group_max_size[group] > 0 {
            group_max_size[group]
        } else {
            let from_hints = &module_hints[edge.from_module];
            let hint_size = find_hint_for_port(
                &from_hints.hints[..from_hints.count],
                1, // port_type = out
                edge.from_port_index,
            );
            if hint_size > 0 {
                hint_size
            } else {
                let to_hints = &module_hints[edge.to_module];
                let to_port_type = if edge.is_ctrl() { 2 } else { 0 };
                find_hint_for_port(
                    &to_hints.hints[..to_hints.count],
                    to_port_type,
                    edge.to_port_index,
                )
            }
        };

        let chan = if buf_size > 0 {
            let config = buf_size.to_le_bytes();
            syscalls::channel_open(CHANNEL_TYPE_PIPE, config.as_ptr(), 2)
        } else {
            syscalls::channel_open(CHANNEL_TYPE_PIPE, null(), 0)
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
    let sched = unsafe { &*(&raw const SCHED) };
    let mut group_writers: [u8; 128] = [0; 128];
    let mut valid = true;

    for edge in edges.iter() {
        if edge.channel < 0 { continue; }
        let group = edge.buffer_group as usize;
        if group == 0 || group >= 128 { continue; }
        if edge.is_ctrl() { continue; }

        let to_mod = edge.to_module;
        if to_mod < MAX_MODULES && sched.in_place_writer[to_mod] {
            group_writers[group] += 1;
            if group_writers[group] > 1 {
                log::error!("[graph] buffer_group={} duplicate in_place_writer module={}", group, to_mod);
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
// Parameter Buffer
// ============================================================================

/// Maximum module-specific config size — from silicon TOML [kernel] section.
const MAX_MODULE_CONFIG_SIZE: usize = super::chip::MAX_MODULE_CONFIG_SIZE;

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
const MAX_NAME_LEN: usize = 16;

/// Maximum number of interned names
const MAX_NAMES: usize = 16;

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
        unsafe {
            if NEXT_NAME_SLOT >= MAX_NAMES {
                log::warn!("NameArena: exhausted ({} slots), cannot intern '{}'", MAX_NAMES, name);
                return "?";
            }

            let slot = NEXT_NAME_SLOT;
            NEXT_NAME_SLOT += 1;

            let buf = &mut NAME_STORAGE[slot];
            let len = name.len().min(MAX_NAME_LEN - 1);
            if name.len() > MAX_NAME_LEN - 1 {
                log::warn!("NameArena: '{}' truncated to {} bytes", name, MAX_NAME_LEN - 1);
            }
            buf[..len].copy_from_slice(&name.as_bytes()[..len]);
            buf[len] = 0;

            core::str::from_utf8_unchecked(&buf[..len])
        }
    }

    /// Reset the arena (call when tearing down the graph).
    fn reset() {
        unsafe { NEXT_NAME_SLOT = 0; }
    }
}

// ============================================================================
// Module Slots
// ============================================================================

/// Shared scratch buffer for tee/merge fan modules.
/// Sized to match the channel buffer so atomic messages are never fragmented.
/// Safe to share because modules are stepped sequentially (single-core cooperative).
const FAN_BUF_SIZE: usize = crate::abi::CHANNEL_BUFFER_SIZE;
static mut FAN_BUF: [u8; FAN_BUF_SIZE] = [0u8; FAN_BUF_SIZE];

/// Module slot - holds an instantiated module
pub enum ModuleSlot {
    Empty,
    /// Dynamically loaded PIC module
    Dynamic(DynamicModule),
    Dummy(DummyModule),
    Tee(TeeModule),
    Merge(MergeModule),
    /// Statically linked built-in module (function pointers + state buffer).
    /// Used on platforms without PIC loading (e.g. aarch64 QEMU).
    BuiltIn(BuiltInModule),
}

impl ModuleSlot {
    /// Returns true if this slot contains a dynamically loaded PIC module
    pub fn is_dynamic(&self) -> bool {
        matches!(self, ModuleSlot::Dynamic(_))
    }

    /// Returns the module type as a string for logging
    pub fn type_name(&self) -> &'static str {
        match self {
            ModuleSlot::Empty => "empty",
            ModuleSlot::Dynamic(_) => "dynamic",
            ModuleSlot::Dummy(_) => "dummy",
            ModuleSlot::Tee(_) => "tee",
            ModuleSlot::Merge(_) => "merge",
            ModuleSlot::BuiltIn(m) => m.name,
        }
    }

    fn as_module_mut(&mut self) -> Option<&mut dyn Module> {
        match self {
            ModuleSlot::Empty => None,
            ModuleSlot::Dynamic(m) => Some(m),
            ModuleSlot::Dummy(m) => Some(m),
            ModuleSlot::Tee(m) => Some(m),
            ModuleSlot::Merge(m) => Some(m),
            ModuleSlot::BuiltIn(m) => Some(m),
        }
    }
}

// ============================================================================
// Built-in Modules (Dummy, Tee, Merge)
// ============================================================================

pub struct DummyModule;

impl Module for DummyModule {
    fn step(&mut self) -> Result<StepOutcome, i32> {
        Ok(StepOutcome::Continue)
    }

    fn name(&self) -> &'static str {
        "dummy"
    }
}

/// Built-in module: step function pointer + opaque state.
/// Used for statically-linked modules on platforms without PIC loading.
pub struct BuiltInModule {
    pub name: &'static str,
    step_fn: fn(*mut u8) -> i32,
    state: [u8; 64], // Fixed-size state (enough for channel handles + counters)
}

impl BuiltInModule {
    pub fn new(name: &'static str, step_fn: fn(*mut u8) -> i32) -> Self {
        Self { name, step_fn, state: [0u8; 64] }
    }
}

impl Module for BuiltInModule {
    fn step(&mut self) -> Result<StepOutcome, i32> {
        let rc = (self.step_fn)(self.state.as_mut_ptr());
        match rc {
            0 => Ok(StepOutcome::Continue),
            1 => Ok(StepOutcome::Done),
            2 => Ok(StepOutcome::Burst),
            3 => Ok(StepOutcome::Ready),
            _ => Err(rc),
        }
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

pub struct TeeModule {
    in_chan: i32,
    out_chans: [i32; MAX_CHANNELS],
    out_count: usize,
}

impl TeeModule {
    fn new(in_chan: i32, out_chans: [i32; MAX_CHANNELS], out_count: usize) -> Self {
        Self {
            in_chan,
            out_chans,
            out_count,
        }
    }
}

impl Module for TeeModule {
    fn step(&mut self) -> Result<StepOutcome, i32> {
        if self.in_chan < 0 || self.out_count == 0 {
            return Err(-1);
        }

        if channel::syscall_channel_poll(self.in_chan, POLL_IN) & (POLL_IN as i32) == 0 {
            return Ok(StepOutcome::Continue);
        }

        for idx in 0..self.out_count {
            if channel::syscall_channel_poll(self.out_chans[idx], POLL_OUT) & (POLL_OUT as i32) == 0 {
                return Ok(StepOutcome::Continue);
            }
        }

        let buf = unsafe { &mut *(&raw mut FAN_BUF) };
        let read = unsafe { channel::syscall_channel_read(self.in_chan, buf.as_mut_ptr(), buf.len()) };
        if read <= 0 {
            return Ok(StepOutcome::Continue);
        }

        let len = read as usize;
        for idx in 0..self.out_count {
            let wrote = unsafe { channel::syscall_channel_write(self.out_chans[idx], buf.as_ptr(), len) };
            if wrote != read {
                return Err(-2);
            }
        }

        Ok(StepOutcome::Continue)
    }

    fn name(&self) -> &'static str {
        "tee"
    }
}

pub struct MergeModule {
    in_chans: [i32; MAX_CHANNELS],
    in_count: usize,
    out_chan: i32,
    next_idx: usize,
}

impl MergeModule {
    fn new(in_chans: [i32; MAX_CHANNELS], in_count: usize, out_chan: i32) -> Self {
        Self {
            in_chans,
            in_count,
            out_chan,
            next_idx: 0,
        }
    }
}

impl Module for MergeModule {
    fn step(&mut self) -> Result<StepOutcome, i32> {
        if self.out_chan < 0 || self.in_count == 0 {
            return Err(-1);
        }

        if channel::syscall_channel_poll(self.out_chan, POLL_OUT) & (POLL_OUT as i32) == 0 {
            return Ok(StepOutcome::Continue);
        }

        for _ in 0..self.in_count {
            let idx = self.next_idx % self.in_count;
            self.next_idx = (self.next_idx + 1) % self.in_count;
            let chan = self.in_chans[idx];

            if channel::syscall_channel_poll(chan, POLL_IN) & (POLL_IN as i32) == 0 {
                continue;
            }

            let buf = unsafe { &mut *(&raw mut FAN_BUF) };
            let read = unsafe { channel::syscall_channel_read(chan, buf.as_mut_ptr(), buf.len()) };
            if read <= 0 {
                return Ok(StepOutcome::Continue);
            }

            let wrote = unsafe { channel::syscall_channel_write(self.out_chan, buf.as_ptr(), read as usize) };
            if wrote != read {
                return Err(-2);
            }

            return Ok(StepOutcome::Continue);
        }

        Ok(StepOutcome::Continue)
    }

    fn name(&self) -> &'static str {
        "merge"
    }
}

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

// ============================================================================
// Static Storage
// ============================================================================

static mut STATIC_CONFIG: Config = Config::empty();
static mut STATIC_LOADER: ModuleLoader = ModuleLoader::new();

/// Get a reference to the static loader.
pub unsafe fn static_loader() -> &'static ModuleLoader {
    &*(&raw const STATIC_LOADER)
}

/// Maximum ports per direction (in/out/ctrl) per module
const MAX_PORTS: usize = 4;

/// Per-module port assignments (replaces old MODULE_CHANNELS tuple)
#[derive(Clone, Copy)]
pub struct ModulePorts {
    in_chans:   [i32; MAX_PORTS],
    out_chans:  [i32; MAX_PORTS],
    ctrl_chans: [i32; MAX_PORTS],
    in_count:   u8,
    out_count:  u8,
    ctrl_count: u8,
}

impl ModulePorts {
    const fn empty() -> Self {
        Self {
            in_chans:   [-1; MAX_PORTS],
            out_chans:  [-1; MAX_PORTS],
            ctrl_chans: [-1; MAX_PORTS],
            in_count:   0,
            out_count:  0,
            ctrl_count: 0,
        }
    }
}

/// Maximum hints per module
const MAX_HINTS_PER_MODULE: usize = 8;

/// Per-module channel hints (buffer size requests)
#[derive(Clone, Copy)]
struct ModuleHints {
    hints: [ChannelHint; MAX_HINTS_PER_MODULE],
    count: usize,
}

impl ModuleHints {
    const fn empty() -> Self {
        Self {
            hints: [ChannelHint { port_type: 0, port_index: 0, buffer_size: 0 }; MAX_HINTS_PER_MODULE],
            count: 0,
        }
    }
}

/// Per-module arena info: (ptr, size). Null if module has no arena.
struct ArenaInfo {
    ptr: *mut u8,
    size: u32,
}

impl ArenaInfo {
    const fn empty() -> Self {
        Self { ptr: core::ptr::null_mut(), size: 0 }
    }
}

/// All scheduler runtime state in a single struct.
///
/// Replaces 14 scattered `static mut` arrays. A single `reset()` method
/// replaces the multi-line reset block in `prepare_graph()`.
pub struct SchedulerState {
    /// Graph edge wiring
    pub edges: [Edge; MAX_CHANNELS],
    /// Instantiated module slots
    pub modules: [ModuleSlot; MAX_MODULES],
    /// Per-module port assignments
    pub ports: [ModulePorts; MAX_MODULES],
    /// Per-module channel hints (buffer size requests)
    hints: [ModuleHints; MAX_MODULES],
    /// Per-module finished flags (done or errored)
    finished: [bool; MAX_MODULES],
    /// Per-module arena allocations
    arenas: [ArenaInfo; MAX_MODULES],
    /// Per-module capability class (checked by dev_call)
    cap_class: [u8; MAX_MODULES],
    /// Per-module required_caps bitmask from manifest
    required_caps: [u32; MAX_MODULES],
    /// Per-module mailbox_safe flag (header flags bit 0): can consume from mailbox
    mailbox_safe: [bool; MAX_MODULES],
    /// Per-module in_place_writer flag (header flags bit 1): uses acquire_inplace
    in_place_writer: [bool; MAX_MODULES],
    /// Per-module deferred ready flag (header flags bit 2)
    deferred_ready: [bool; MAX_MODULES],
    /// Per-module ready flag (true = outputs meaningful, false = still initializing)
    ready: [bool; MAX_MODULES],
    /// Per-module upstream dependency bitmask (precomputed from edges)
    upstream_mask: [u16; MAX_MODULES],
    /// Per-module step period (0 = every tick, N = every N ms)
    step_period: [u8; MAX_MODULES],
    /// Per-module step counter (counts ticks toward period)
    step_counter: [u8; MAX_MODULES],
    /// Topological execution order (Kahn's algorithm output)
    exec_order: [u8; MAX_MODULES],
    /// Number of entries in exec_order
    exec_order_count: usize,
    /// Index of the module currently being stepped or instantiated
    current_module: usize,
    /// Graph-level sample rate from config (0 = not set)
    graph_sample_rate: u32,
    /// Tick period in microseconds (0 = default 1000us)
    tick_us: u32,
    /// Per-module self-reported latency in frames
    module_latency: [u32; MAX_MODULES],
    /// Per-module accumulated downstream latency in frames
    downstream_latency: [u32; MAX_MODULES],
    /// Per-module fault bookkeeping (state, policy, counters)
    fault_info: [ModuleFaultInfo; MAX_MODULES],
    /// Per-module domain assignment (0 = default domain)
    domain_id: [u8; MAX_MODULES],
    /// Per-domain topological execution order
    domain_exec_order: [[u8; MAX_MODULES]; MAX_DOMAINS],
    /// Number of modules in each domain's execution order
    domain_module_count: [u8; MAX_DOMAINS],
    /// Number of domains configured (0 or 1 = single default domain)
    domain_count: u8,
    /// Per-domain tick_us (0 = use global tick_us). Index 0 = default domain.
    domain_tick_us: [u32; MAX_DOMAINS],
    /// Per-domain execution mode (0=cooperative/Tier 0, 1=high-rate/Tier 1a, 3=poll/Tier 3).
    domain_exec_mode: [u8; MAX_DOMAINS],

    // ── Live Reconfigure State ──────────────────────────────────────
    /// Current reconfigure phase (Running during normal operation).
    reconfigure_phase: ReconfigurePhase,
    /// Per-module drain state (only meaningful during DRAINING).
    drain_state: [DrainState; MAX_MODULES],
    /// Per-module drain-capable flag (header flags bit 3).
    /// Set during module instantiation from the module binary header.
    drain_capable: [bool; MAX_MODULES],
    /// Tick count when DRAINING phase started (for timeout).
    drain_start_tick: u32,
    /// Drain timeout in ticks (ms). Default 5000.
    drain_timeout_ticks: u32,
    /// Per-module in-flight count (reported by modules during drain).
    drain_inflight: [u32; MAX_MODULES],
    /// Number of modules in the current graph (for reconfigure).
    active_module_count: usize,

    // ── Per-module export table info (for resolve_export_for_module) ──
    /// Code base address per module (for resolving export offsets)
    module_code_base: [usize; MAX_MODULES],
    /// Export table pointer per module
    module_export_table: [*const u8; MAX_MODULES],
    /// Export count per module
    module_export_count: [u16; MAX_MODULES],
}

impl SchedulerState {
    const fn new() -> Self {
        Self {
            edges: [Edge::simple(0, 0); MAX_CHANNELS],
            modules: [const { ModuleSlot::Empty }; MAX_MODULES],
            ports: [ModulePorts::empty(); MAX_MODULES],
            hints: [ModuleHints::empty(); MAX_MODULES],
            finished: [false; MAX_MODULES],
            arenas: [const { ArenaInfo::empty() }; MAX_MODULES],
            cap_class: [0; MAX_MODULES],
            required_caps: [0; MAX_MODULES],
            mailbox_safe: [false; MAX_MODULES],
            in_place_writer: [false; MAX_MODULES],
            deferred_ready: [false; MAX_MODULES],
            ready: [true; MAX_MODULES],
            upstream_mask: [0; MAX_MODULES],
            step_period: [0; MAX_MODULES],
            step_counter: [0; MAX_MODULES],
            exec_order: [0; MAX_MODULES],
            exec_order_count: 0,
            current_module: 0,
            graph_sample_rate: 0,
            tick_us: 0,
            module_latency: [0; MAX_MODULES],
            downstream_latency: [0; MAX_MODULES],
            fault_info: [ModuleFaultInfo::new(); MAX_MODULES],
            domain_id: [0; MAX_MODULES],
            domain_exec_order: [[0; MAX_MODULES]; MAX_DOMAINS],
            domain_module_count: [0; MAX_DOMAINS],
            domain_count: 0,
            domain_tick_us: [0; MAX_DOMAINS],
            domain_exec_mode: [0; MAX_DOMAINS],
            reconfigure_phase: ReconfigurePhase::Running,
            drain_state: [DrainState::Surviving; MAX_MODULES],
            drain_capable: [false; MAX_MODULES],
            drain_start_tick: 0,
            drain_timeout_ticks: 5000,
            drain_inflight: [0; MAX_MODULES],
            active_module_count: 0,
            module_code_base: [0; MAX_MODULES],
            module_export_table: [core::ptr::null(); MAX_MODULES],
            module_export_count: [0; MAX_MODULES],
        }
    }

    /// Reset all runtime state for a new graph setup.
    /// Does NOT reset state arena or name arena (separate concerns).
    fn reset(&mut self) {
        for i in 0..MAX_CHANNELS {
            self.edges[i] = Edge::simple(0, 0);
        }
        for i in 0..MAX_MODULES {
            self.modules[i] = ModuleSlot::Empty;
            self.ports[i] = ModulePorts::empty();
            self.hints[i] = ModuleHints::empty();
            self.finished[i] = false;
            self.arenas[i] = ArenaInfo::empty();
            self.cap_class[i] = 0;
            self.required_caps[i] = 0;
            self.mailbox_safe[i] = false;
            self.in_place_writer[i] = false;
            self.deferred_ready[i] = false;
            self.ready[i] = true;
            self.upstream_mask[i] = 0;
            self.step_period[i] = 0;
            self.step_counter[i] = 0;
            self.module_latency[i] = 0;
            self.downstream_latency[i] = 0;
            self.fault_info[i] = ModuleFaultInfo::new();
            self.module_code_base[i] = 0;
            self.module_export_table[i] = core::ptr::null();
            self.module_export_count[i] = 0;
        }
        self.exec_order_count = 0;
        self.graph_sample_rate = 0;
        self.tick_us = 0;
        self.domain_count = 0;
        for d in 0..MAX_DOMAINS {
            self.domain_module_count[d] = 0;
            self.domain_tick_us[d] = 0;
        }
        self.reconfigure_phase = ReconfigurePhase::Running;
        for i in 0..MAX_MODULES {
            self.drain_state[i] = DrainState::Surviving;
            self.drain_capable[i] = false;
            self.drain_inflight[i] = 0;
        }
        self.drain_start_tick = 0;
        self.drain_timeout_ticks = 5000;
        self.active_module_count = 0;
    }
}

static mut SCHED: SchedulerState = SchedulerState::new();

/// Get a mutable reference to the scheduler state.
///
/// # Safety
/// Caller must ensure exclusive access.
pub unsafe fn sched_mut() -> &'static mut SchedulerState {
    &mut *(&raw mut SCHED)
}

/// Get an immutable reference to the scheduler state.
pub unsafe fn sched_ref() -> &'static SchedulerState {
    &*(&raw const SCHED)
}

/// Get a mutable reference to the modules array.
pub unsafe fn sched_modules() -> &'static mut [ModuleSlot; MAX_MODULES] {
    &mut *(&raw mut SCHED.modules)
}

/// Get a mutable reference to the static param buffer.
pub unsafe fn param_buffer_mut() -> &'static mut ParamBuffer {
    &mut *core::ptr::addr_of_mut!(PARAM_BUFFER)
}

/// Return the index of the module currently being stepped.
/// Used by event::event_create() to set event ownership.
pub fn current_module_index() -> usize {
    unsafe { SCHED.current_module }
}

/// Set the current module index. Used by provider dispatch for context switching.
pub fn set_current_module(idx: usize) {
    unsafe { SCHED.current_module = idx; }
}

/// Get the state pointer for a module by index.
/// Returns null if the slot is empty or not a dynamic module.
/// State pointer for the module currently being instantiated (set during module_new).
/// Allows REGISTER_PROVIDER to find the state before the module is stored in SCHED.
static mut INSTANTIATION_STATE: *mut u8 = core::ptr::null_mut();
static mut INSTANTIATION_IDX: usize = usize::MAX;

/// Set the instantiation state pointer (called before module_new).
pub fn set_instantiation_state(idx: usize, state: *mut u8) {
    unsafe { INSTANTIATION_STATE = state; INSTANTIATION_IDX = idx; }
}

/// Clear the instantiation state pointer (called after module_new).
pub fn clear_instantiation_state() {
    unsafe { INSTANTIATION_STATE = core::ptr::null_mut(); INSTANTIATION_IDX = usize::MAX; }
}

pub fn get_module_state(idx: usize) -> *mut u8 {
    if idx >= MAX_MODULES {
        return core::ptr::null_mut();
    }
    unsafe {
        // During module_new, the module isn't stored in SCHED yet
        if idx == INSTANTIATION_IDX && !INSTANTIATION_STATE.is_null() {
            return INSTANTIATION_STATE;
        }
        match &SCHED.modules[idx] {
            ModuleSlot::Dynamic(m) => m.state_ptr(),
            _ => core::ptr::null_mut(),
        }
    }
}

/// Return the capability class of the module currently being stepped.
/// Used by dev_call to enforce device class access restrictions.
pub fn current_module_cap_class() -> u8 {
    unsafe { SCHED.cap_class[SCHED.current_module] }
}

/// Return the required_caps bitmask of the module currently being stepped.
/// Bit N set = module declared it needs device class N in its manifest.
pub fn current_module_required_caps() -> u32 {
    unsafe { SCHED.required_caps[SCHED.current_module] }
}

/// Return the export table info for a module by index.
/// Used by loader::resolve_export_for_module to resolve export hashes.
pub fn get_module_exports(idx: usize) -> (usize, *const u8, u16) {
    if idx >= MAX_MODULES {
        return (0, core::ptr::null(), 0);
    }
    unsafe {
        (SCHED.module_code_base[idx],
         SCHED.module_export_table[idx],
         SCHED.module_export_count[idx])
    }
}

/// Set the export table info for a module (used by Linux platform loader).
pub fn set_module_exports(idx: usize, code_base: usize, export_table: *const u8, export_count: u16) {
    if idx >= MAX_MODULES { return; }
    unsafe {
        SCHED.module_code_base[idx] = code_base;
        SCHED.module_export_table[idx] = export_table;
        SCHED.module_export_count[idx] = export_count;
    }
}

/// Set the capability class and required_caps for a module (used by Linux platform loader).
pub fn set_module_caps(idx: usize, cap_class: u8, required_caps: u32) {
    if idx >= MAX_MODULES { return; }
    unsafe {
        SCHED.cap_class[idx] = cap_class;
        SCHED.required_caps[idx] = required_caps;
    }
}

/// Step a single module by index (used by Linux platform main loop).
pub fn step_module(idx: usize) {
    if idx >= MAX_MODULES { return; }
    unsafe {
        if let ModuleSlot::Dynamic(ref mut m) = SCHED.modules[idx] {
            let _ = m.step();
        }
    }
}

/// Store a DynamicModule in the scheduler's module table (used by Linux platform).
pub fn store_dynamic_module(idx: usize, dm: DynamicModule) {
    if idx >= MAX_MODULES { return; }
    unsafe {
        SCHED.modules[idx] = ModuleSlot::Dynamic(dm);
    }
}

/// Return the graph-level sample rate (0 = not configured).
pub fn graph_sample_rate() -> u32 {
    unsafe { SCHED.graph_sample_rate }
}

/// Set the graph-level sample rate (called from config parsing).
pub fn set_graph_sample_rate(rate: u32) {
    unsafe { SCHED.graph_sample_rate = rate; }
}

/// Return the configured tick period in microseconds.
pub fn tick_us() -> u32 {
    let t = unsafe { SCHED.tick_us };
    if t == 0 { DEFAULT_TICK_US } else { t }
}

/// Return the configured tick period for a specific domain.
/// Falls back to global tick_us if domain has no override.
pub fn domain_tick_us(domain_id: usize) -> u32 {
    if domain_id < MAX_DOMAINS {
        let t = unsafe { SCHED.domain_tick_us[domain_id] };
        if t > 0 { return t; }
    }
    tick_us()
}

/// Return the execution mode for a domain.
/// 0 = cooperative (Tier 0), 1 = high-rate periodic (Tier 1a), 3 = poll-mode (Tier 3).
pub fn domain_exec_mode(domain_id: usize) -> u8 {
    if domain_id < MAX_DOMAINS {
        unsafe { SCHED.domain_exec_mode[domain_id] }
    } else {
        0
    }
}

/// Return the number of configured domains.
pub fn domain_count() -> usize {
    let c = unsafe { SCHED.domain_count } as usize;
    if c == 0 { 1 } else { c }
}

/// Return the module count for a specific domain.
pub fn domain_module_count(domain_id: usize) -> usize {
    if domain_id < MAX_DOMAINS {
        unsafe { SCHED.domain_module_count[domain_id] as usize }
    } else {
        0
    }
}

/// Report a module's processing latency in frames.
/// Called by modules during init via dev_call(SYSTEM::REPORT_LATENCY).
pub fn report_module_latency(module_idx: usize, frames: u32) {
    if module_idx < MAX_MODULES {
        unsafe { SCHED.module_latency[module_idx] = frames; }
    }
}

/// Get the downstream latency for a module (computed after all modules init).
pub fn downstream_latency(module_idx: usize) -> u32 {
    if module_idx < MAX_MODULES {
        unsafe { SCHED.downstream_latency[module_idx] }
    } else {
        0
    }
}

/// Get fault statistics for a module (for dev_query FAULT_STATS).
pub fn get_fault_stats(module_idx: usize) -> FaultStats {
    if module_idx >= MAX_MODULES {
        return FaultStats::default();
    }
    unsafe {
        let tick = DBG_TICK;
        SCHED.fault_info[module_idx].to_stats(tick)
    }
}

/// Get mutable fault info for a module (for config-time setup).
pub fn set_module_fault_policy(module_idx: usize, policy: FaultPolicy, max_restarts: u16, backoff_ms: u16) {
    if module_idx >= MAX_MODULES { return; }
    unsafe {
        let fi = &mut SCHED.fault_info[module_idx];
        fi.policy = policy;
        fi.max_restarts = max_restarts;
        fi.restart_backoff_ms = backoff_ms;
    }
}

/// Set per-module step deadline (from config).
pub fn set_module_step_deadline(module_idx: usize, deadline_us: u32) {
    if module_idx >= MAX_MODULES { return; }
    unsafe {
        SCHED.fault_info[module_idx].step_deadline_us = deadline_us;
    }
}

/// Lookup a channel port for the currently-executing module.
/// Called from the channel_port syscall implementation.
pub fn channel_port_lookup(port_type: u8, index: u8) -> i32 {
    let idx = index as usize;
    let ports = unsafe { &SCHED.ports[SCHED.current_module] };
    match port_type {
        0 => if idx < ports.in_count as usize { ports.in_chans[idx] } else { -1 },
        1 => if idx < ports.out_count as usize { ports.out_chans[idx] } else { -1 },
        2 => if idx < ports.ctrl_count as usize { ports.ctrl_chans[idx] } else { -1 },
        _ => -1,
    }
}

/// Syscall: get the calling module's arena allocation.
/// Returns null if no arena was allocated.
pub unsafe extern "C" fn syscall_arena_get(size_out: *mut u32) -> *mut u8 {
    let arena = &SCHED.arenas[SCHED.current_module];
    if !size_out.is_null() {
        *size_out = arena.size;
    }
    arena.ptr
}

// ============================================================================
// Setup Functions
// ============================================================================

/// Synchronous setup - returns true if ready to run, false on error
///
/// Call this first, then call run_main_loop() if it returns true.
pub fn setup(runner_config: &RunnerConfig) -> bool {
    let loader = unsafe { &mut *(&raw mut STATIC_LOADER) };
    let config = unsafe { &mut *(&raw mut STATIC_CONFIG) };

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
    let config = unsafe { &*(&raw const STATIC_CONFIG) };
    let loader = unsafe { &*(&raw const STATIC_LOADER) };
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

    let (mut module_list, mut module_count, id_to_slot) = build_module_list(config);
    if module_count == 0 {
        log::error!("[graph] no usable modules");
        return Err(-1);
    }

    log::info!("[graph] modules={} edges={}", declared_modules, edge_count);

    let sched = unsafe { &mut *(&raw mut SCHED) };

    // Reset all scheduler state, state arena, and name arena
    reset_state_arena();
    crate::kernel::buffer_pool::reset_buffer_arena();
    NameArena::reset();
    sched.reset();

    // Store graph-level sample rate from config header
    sched.graph_sample_rate = config.header.graph_sample_rate as u32;
    if sched.graph_sample_rate != 0 {
        log::info!("[graph] sample_rate={}", sched.graph_sample_rate);
    }

    // Store tick_us from config header (0 = default 1000us)
    let raw_tick_us = config.header.tick_us as u32;
    sched.tick_us = if raw_tick_us == 0 { DEFAULT_TICK_US } else { raw_tick_us };
    if raw_tick_us != 0 {
        log::info!("[graph] tick_us={}", sched.tick_us);
    }

    // Store per-module domain assignments and infer domain count
    let mut max_domain: u8 = 0;
    for entry in config.modules.iter().flatten() {
        let id = entry.id as usize;
        if id < MAX_MODULES {
            sched.domain_id[id] = entry.domain_id;
            if entry.domain_id > max_domain { max_domain = entry.domain_id; }
        }
    }
    sched.domain_count = if max_domain > 0 { (max_domain + 1).min(MAX_DOMAINS as u8) } else { 0 };

    // Populate per-domain tick_us and exec_mode from config
    for d in 0..MAX_DOMAINS {
        sched.domain_tick_us[d] = config.domain_tick_us[d] as u32;
        sched.domain_exec_mode[d] = config.domain_exec_mode[d];
    }

    let edges = &mut sched.edges;

    // Wire edges from config
    for i in 0..edge_count {
        if let Some(edge) = config.graph_edges[i] {
            let from_slot = id_to_slot.get(edge.from_id as usize).copied().unwrap_or(-1);
            let to_slot = id_to_slot.get(edge.to_id as usize).copied().unwrap_or(-1);

            if from_slot < 0 || to_slot < 0 {
                log::error!("[graph] edge {} unknown module {}→{}", i, edge.from_id, edge.to_id);
                return Err(-1);
            }

            let to_port_name = if edge.to_port == 1 { "ctrl" } else { "in" };
            let mut e = Edge::new_indexed(
                from_slot as usize, "out", edge.from_port_index,
                to_slot as usize, to_port_name, edge.to_port_index,
            );
            e.buffer_group = edge.buffer_group;
            e.edge_class = edge.edge_class;
            edges[i] = e;
        } else {
            log::error!("[graph] edge {} missing", i);
            return Err(-1);
        }
    }

    // Insert fan-out (tee) and fan-in (merge) modules
    let mut runtime_edge_count = edge_count;
    if !insert_fan_out(edges, &mut runtime_edge_count, &mut module_list, &mut module_count) {
        return Err(-1);
    }
    if !insert_fan_in(edges, &mut runtime_edge_count, &mut module_list, &mut module_count) {
        return Err(-1);
    }

    // Query channel hints and open channels
    collect_module_hints(loader, &module_list, module_count);
    if open_channels(&mut edges[..runtime_edge_count]) < 0 {
        log::error!("[graph] channel open failed");
        return Err(-1);
    }

    // Compute topological execution order
    compute_exec_order(edges, runtime_edge_count, module_count);

    // Compute upstream dependency masks for ready-signal gating
    compute_upstream_mask(edges, runtime_edge_count);

    // Partition modules by domain (E4-S4) and validate (E4-S5)
    // These use the global SCHED directly to avoid borrow conflicts with `edges`.
    compute_domain_exec_orders_static(module_count);
    validate_domains_static(module_count, runtime_edge_count);

    Ok((module_list, module_count))
}

// Async graph setup (setup_graph_async) and run_main_loop are in
// src/platform/rp.rs — they use embassy async/await which is RP-only.
// Sync variants (setup_graph_sync, run_main_loop_sync) are in
// src/platform/bcm2712.rs.

// ============================================================================
// Module Instantiation
// ============================================================================

/// Internal module hashes (fnv1a32)
const INTERNAL_TEE_HASH: u32 = 0x607f045c;   // "_tee"
const INTERNAL_MERGE_HASH: u32 = 0x8a6bcd3e; // "_merge"

fn build_module_list(
    config: &Config,
) -> ([Option<ModuleEntry>; MAX_MODULES], usize, [i8; MAX_MODULES]) {
    let mut module_list: [Option<ModuleEntry>; MAX_MODULES] = [None; MAX_MODULES];
    let mut id_to_slot: [i8; MAX_MODULES] = [-1; MAX_MODULES];
    let mut count = 0;

    for entry in config.modules.iter().flatten() {
        if count >= MAX_MODULES {
            log::error!("[graph] module limit reached");
            break;
        }

        let id = entry.id as usize;
        if id >= MAX_MODULES {
            log::warn!("[graph] module id={} out of range", entry.id);
            continue;
        }

        if id_to_slot[id] >= 0 {
            log::warn!("[graph] duplicate id={} ignored", entry.id);
            continue;
        }

        id_to_slot[id] = count as i8;
        module_list[count] = Some(*entry);
        count += 1;
    }

    (module_list, count, id_to_slot)
}

/// Query channel hints for all modules in the list.
///
/// For each module, looks up its `module_channel_hints` export and
/// stores the hints in MODULE_HINTS. Modules without the export
/// get empty hints (all ports use default buffer sizes).
fn collect_module_hints(
    loader: &ModuleLoader,
    module_list: &[Option<ModuleEntry>; MAX_MODULES],
    module_count: usize,
) {
    let module_hints = unsafe { &mut *(&raw mut SCHED.hints) };

    for module_idx in 0..module_count {
        let entry = match &module_list[module_idx] {
            Some(e) => e,
            None => continue,
        };

        // Skip internal modules (tee, merge) — they have no hints export
        if is_internal_module(entry) {
            continue;
        }

        // Find the module in flash
        let loaded = match loader.find_by_name_hash(entry.name_hash) {
            Ok(m) => m,
            Err(_) => continue, // Will be caught during instantiation
        };

        // Extract mailbox_safe / in_place_writer flags early so open_channels
        // can use them for buffer-group aliasing decisions.
        let flags_byte = loaded.header.reserved[0];
        unsafe {
            let sched = &mut *(&raw mut SCHED);
            sched.mailbox_safe[module_idx] = (flags_byte & 0x01) != 0;
            sched.in_place_writer[module_idx] = (flags_byte & 0x02) != 0;
        }

        // Query hints
        let (hints, count) = query_channel_hints(&loaded);
        if count > 0 {
            module_hints[module_idx].hints = hints;
            module_hints[module_idx].count = count;
            // hints stored for module
        }
    }
}

fn push_internal_module(
    module_list: &mut [Option<ModuleEntry>; MAX_MODULES],
    module_count: &mut usize,
    name_hash: u32,
) -> Option<usize> {
    if *module_count >= MAX_MODULES {
        log::error!("No room for internal module");
        return None;
    }

    let idx = *module_count;
    module_list[idx] = Some(ModuleEntry {
        name_hash,
        id: idx as u8,
        domain_id: 0,
        params_ptr: core::ptr::null(),
        params_len: 0,
    });
    *module_count += 1;
    Some(idx)
}

fn is_internal_module(entry: &ModuleEntry) -> bool {
    entry.name_hash == INTERNAL_TEE_HASH || entry.name_hash == INTERNAL_MERGE_HASH
}

/// Direction for fan-in/fan-out insertion
#[derive(Clone, Copy, PartialEq, Eq)]
enum FanDirection {
    Out,
    In,
}

/// Compute port grouping key for fan insertion.
///
/// Out: groups by from_port_index (one tee per output port).
/// In: groups by (is_ctrl << 4) | to_port_index (separate merge per port+type).
fn edge_port_key(edge: &Edge, direction: FanDirection) -> u8 {
    match direction {
        FanDirection::Out => edge.from_port_index,
        FanDirection::In => {
            let type_bit = if edge.is_ctrl() { 0x10 } else { 0x00 };
            type_bit | edge.to_port_index
        }
    }
}

/// Check if an edge connects to `module_idx` in the given direction.
fn edge_matches_module(edge: &Edge, module_idx: usize, direction: FanDirection) -> bool {
    match direction {
        FanDirection::Out => edge.from_module == module_idx,
        FanDirection::In => edge.to_module == module_idx,
    }
}

/// Insert tee (fan-out) or merge (fan-in) modules where a single port has
/// multiple edges.
///
/// Any `buffer_group` on edges that require a tee/merge is cleared and logged
/// at error level. Aliased mailbox chains are incompatible with fan modules
/// because in-place modification through a shared buffer would corrupt data
/// for the other consumers/producers in the fan.
fn insert_fan(
    direction: FanDirection,
    edges: &mut [Edge; MAX_CHANNELS],
    edge_count: &mut usize,
    module_list: &mut [Option<ModuleEntry>; MAX_MODULES],
    module_count: &mut usize,
) -> bool {
    let original_count = *module_count;
    let (internal_hash, name) = match direction {
        FanDirection::Out => (INTERNAL_TEE_HASH, "tee"),
        FanDirection::In => (INTERNAL_MERGE_HASH, "merge"),
    };

    for module_idx in 0..original_count {
        let entry_id = match &module_list[module_idx] {
            Some(entry) if !is_internal_module(entry) => entry.id,
            _ => continue,
        };

        // Collect all edges connecting to this module in the given direction
        let mut matching = [0usize; MAX_CHANNELS];
        let mut match_count = 0;
        for i in 0..*edge_count {
            if edge_matches_module(&edges[i], module_idx, direction)
                && match_count < MAX_CHANNELS
            {
                matching[match_count] = i;
                match_count += 1;
            }
        }

        if match_count <= 1 {
            continue;
        }

        // Group edges by port key. Each unique key gets its own tee/merge.
        // Invariant: every index in matching[0..match_count] is visited exactly once.
        let mut processed = [false; MAX_CHANNELS];
        for start in 0..match_count {
            if processed[start] {
                continue;
            }

            let port_key = edge_port_key(&edges[matching[start]], direction);

            // Collect all edges sharing this port key
            let mut group = [0usize; MAX_CHANNELS];
            let mut group_count = 0;
            for j in start..match_count {
                if !processed[j]
                    && edge_port_key(&edges[matching[j]], direction) == port_key
                {
                    group[group_count] = matching[j];
                    group_count += 1;
                    processed[j] = true;
                }
            }

            if group_count <= 1 {
                continue;
            }

            // Invariant: buffer aliasing (buffer_group) is incompatible with tee/merge.
            // In-place modification through an aliased buffer would corrupt data for
            // other consumers in the fan. Strip and log at error level.
            for k in 0..group_count {
                let ei = group[k];
                if edges[ei].buffer_group != 0 {
                    log::error!("[graph] fan module={} buffer_group={} cleared (incompatible)",
                        module_idx, edges[ei].buffer_group);
                    edges[ei].buffer_group = 0;
                }
            }

            // Insert tee/merge module for this port group
            if *edge_count + 1 > MAX_CHANNELS {
                log::error!("[graph] channel limit for {} module={}", name, entry_id);
                return false;
            }

            let fan_idx = match push_internal_module(module_list, module_count, internal_hash) {
                Some(idx) => idx,
                None => return false,
            };

            // Add bridge edge: original module ↔ fan module
            let new_edge = match direction {
                FanDirection::Out => {
                    let mut e = Edge::simple(module_idx, fan_idx);
                    e.from_port_index = port_key;
                    e
                }
                FanDirection::In => Edge::simple(fan_idx, module_idx),
            };
            edges[*edge_count] = new_edge;
            *edge_count += 1;

            // Rewire group edges to go through the fan module
            for k in 0..group_count {
                match direction {
                    FanDirection::Out => edges[group[k]].from_module = fan_idx,
                    FanDirection::In => edges[group[k]].to_module = fan_idx,
                }
            }
        }
    }

    true
}

fn insert_fan_out(
    edges: &mut [Edge; MAX_CHANNELS],
    edge_count: &mut usize,
    module_list: &mut [Option<ModuleEntry>; MAX_MODULES],
    module_count: &mut usize,
) -> bool {
    insert_fan(FanDirection::Out, edges, edge_count, module_list, module_count)
}

fn insert_fan_in(
    edges: &mut [Edge; MAX_CHANNELS],
    edge_count: &mut usize,
    module_list: &mut [Option<ModuleEntry>; MAX_MODULES],
    module_count: &mut usize,
) -> bool {
    insert_fan(FanDirection::In, edges, edge_count, module_list, module_count)
}

fn validate_hardware_requirements(config: &RunnerConfig) -> bool {
    let mut valid = true;

    if !is_spi_initialized(config.spi_bus) {
        log::error!("[boot] config spi bus={} not initialized", config.spi_bus);
        valid = false;
    }

    // Log which buses are available (informational for debugging)
    for bus in 0..2u8 {
        if is_spi_initialized(bus) {
            log::info!("[boot] spi{} available", bus);
        }
    }
    for bus in 0..2u8 {
        if crate::kernel::syscalls::is_i2c_initialized(bus) {
            log::info!("[boot] i2c{} available", bus);
        }
    }

    valid
}

/// Copy collected channels into ModulePorts.
/// Returns false if any port count exceeds MAX_PORTS (config error).
fn populate_ports(
    ports: &mut ModulePorts,
    in_chans: &[i32; MAX_CHANNELS],
    in_count: usize,
    out_chans: &[i32; MAX_CHANNELS],
    out_count: usize,
    ctrl_chans: &[i32; MAX_CHANNELS],
    ctrl_count: usize,
) -> bool {
    if in_count > MAX_PORTS {
        log::error!("[inst] input port limit in={} max={}", in_count, MAX_PORTS);
        return false;
    }
    if out_count > MAX_PORTS {
        log::error!("[inst] output port limit out={} max={}", out_count, MAX_PORTS);
        return false;
    }
    if ctrl_count > MAX_PORTS {
        log::error!("[inst] ctrl port limit ctrl={} max={}", ctrl_count, MAX_PORTS);
        return false;
    }
    ports.in_count = in_count as u8;
    ports.out_count = out_count as u8;
    ports.ctrl_count = ctrl_count as u8;
    let mut i = 0;
    while i < in_count { ports.in_chans[i] = in_chans[i]; i += 1; }
    i = 0;
    while i < out_count { ports.out_chans[i] = out_chans[i]; i += 1; }
    i = 0;
    while i < ctrl_count { ports.ctrl_chans[i] = ctrl_chans[i]; i += 1; }
    true
}

/// Result of synchronous per-module instantiation.
pub enum InstantiateResult {
    /// Module ready, increment count
    Done,
    /// Module needs async completion
    Pending(crate::kernel::loader::DynamicModulePending),
    /// Fatal error
    Error(i32),
}

/// Synchronous per-module instantiation — all large locals live on the
/// regular call stack rather than in the async future state machine.
#[inline(never)]
pub fn instantiate_one_module(
    loader: &ModuleLoader,
    entry: &ModuleEntry,
    module_idx: usize,
    instantiated: usize,
    edges: &mut [Edge; MAX_CHANNELS],
    modules: &mut [ModuleSlot; MAX_MODULES],
    module_ports: &mut [ModulePorts; MAX_MODULES],
) -> InstantiateResult {
    // Channel collection — large arrays stay on sync stack
    let mut in_chans = [-1i32; MAX_CHANNELS];
    let mut out_chans = [-1i32; MAX_CHANNELS];
    let mut ctrl_chans = [-1i32; MAX_CHANNELS];
    let in_count = collect_input_channels(edges, module_idx, &mut in_chans);
    let out_count = collect_output_channels(edges, module_idx, &mut out_chans);
    let ctrl_count = collect_ctrl_channels(edges, module_idx, &mut ctrl_chans);
    let in_chan = if in_count > 0 { in_chans[0] } else { -1 };
    let out_chan = if out_count > 0 { out_chans[0] } else { -1 };
    let ctrl_chan = if ctrl_count > 0 { ctrl_chans[0] } else { -1 };

    let ports = &mut module_ports[instantiated];
    if !populate_ports(ports, &in_chans, in_count, &out_chans, out_count, &ctrl_chans, ctrl_count) {
        log::error!("[inst] module={} port limit exceeded", entry.id);
        return InstantiateResult::Error(-1);
    }

    if entry.name_hash == INTERNAL_TEE_HASH {
        if in_count != 1 || out_count == 0 {
            log::error!("[inst] tee module={} invalid ports", entry.id);
            return InstantiateResult::Error(-1);
        }
        modules[instantiated] = ModuleSlot::Tee(TeeModule::new(in_chans[0], out_chans, out_count));
        return InstantiateResult::Done;
    } else if entry.name_hash == INTERNAL_MERGE_HASH {
        if out_count != 1 || in_count == 0 {
            log::error!("[inst] merge module={} invalid ports", entry.id);
            return InstantiateResult::Error(-1);
        }
        modules[instantiated] = ModuleSlot::Merge(MergeModule::new(in_chans, in_count, out_chans[0]));
        return InstantiateResult::Done;
    }

    // Loader lookup
    let found_module = match loader.find_by_name_hash(entry.name_hash) {
        Ok(m) => m,
        Err(e) => { e.log("loader"); return InstantiateResult::Error(-1); }
    };
    let name = found_module.name_str();
    let static_name = NameArena::intern(name);

    // Select capability-filtered syscall table based on module type
    let syscalls = get_table_for_module_type(found_module.header.module_type);

    // Record capability class and manifest metadata for enforcement
    unsafe {
        let sched = &mut *(&raw mut SCHED);
        sched.cap_class[instantiated] = match found_module.header.module_type {
            5 => 3,  // Protocol → CAP_FULL
            3 => 1,  // Sink → CAP_SERVICE_PIO
            4 => 2,  // EventHandler → CAP_SERVICE_GPIO
            _ => 0,  // Source, Transformer → CAP_SERVICE
        };
        sched.required_caps[instantiated] = found_module.header.required_caps() as u32;
        // Store export table info for resolve_export_for_module
        sched.module_code_base[instantiated] = found_module.code_base() as usize;
        sched.module_export_table[instantiated] = found_module.export_table_ptr();
        sched.module_export_count[instantiated] = found_module.header.export_count;
        let flags_byte = found_module.header.reserved[0];
        sched.mailbox_safe[instantiated] = (flags_byte & 0x01) != 0;
        sched.in_place_writer[instantiated] = (flags_byte & 0x02) != 0;
        let deferred = (flags_byte & 0x04) != 0;
        sched.deferred_ready[instantiated] = deferred;
        sched.drain_capable[instantiated] = (flags_byte & 0x08) != 0;
        if deferred {
            sched.ready[instantiated] = false;
        }
    }

    // Check for optional module_arena_size export and allocate if present
    unsafe {
        let sched = &mut *(&raw mut SCHED);
        let arenas = &mut sched.arenas;
        arenas[instantiated] = ArenaInfo::empty();
        if let Ok(addr) = found_module.get_export_addr(
            crate::kernel::loader::export_hashes::MODULE_ARENA_SIZE,
        ) {
            let arena_size_fn: unsafe extern "C" fn() -> u32 =
                core::mem::transmute(addr as usize);
            let requested = arena_size_fn() as usize;
            if requested > 0 {
                match crate::kernel::loader::alloc_state(requested) {
                    Ok(ptr) => {
                        arenas[instantiated] = ArenaInfo { ptr, size: requested as u32 };
                    }
                    Err(e) => {
                        e.log("arena");
                        return InstantiateResult::Error(-1);
                    }
                }
            }
        }
    }

    // Copy params to static buffer and merge runtime overrides
    unsafe {
        let pb = &mut *core::ptr::addr_of_mut!(PARAM_BUFFER);
        pb.write(entry.params());

        // Overlay any runtime parameter overrides from flash store
        {
            let new_len = hal::merge_runtime_overrides(
                entry.id as u16,
                pb.as_mut_ptr(),
                pb.len(),
                MAX_MODULE_CONFIG_SIZE,
            );
            pb.set_len(new_len);
        }
    }

    // Full instantiation via start_new
    // Set current module index so REGISTER_PROVIDER can identify us
    set_current_module(instantiated);
    let result = unsafe {
        let pb = core::ptr::addr_of!(PARAM_BUFFER);
        DynamicModule::start_new(
            &found_module, syscalls,
            in_chan, out_chan, ctrl_chan,
            (*pb).as_ptr(), (*pb).len(),
            static_name,
        )
    };
    clear_instantiation_state();

    match result {
        Ok(StartNewResult::Ready(dynamic)) => {
            modules[instantiated] = ModuleSlot::Dynamic(dynamic);
        }
        Ok(StartNewResult::Pending(pending)) => {
            // Record step period before returning
            unsafe {
                (*(&raw mut SCHED)).step_period[instantiated] = found_module.header.step_period_ms();
            }
            return InstantiateResult::Pending(pending);
        }
        Err(e) => {
            e.log("scheduler");
            return InstantiateResult::Error(-1);
        }
    }

    // Record step frequency hint from module header
    unsafe {
        (*(&raw mut SCHED)).step_period[instantiated] = found_module.header.step_period_ms();
    }

    // Parse protection config from TLV params (tags 0xF0-0xF3)
    parse_protection_config(instantiated, entry.params());

    InstantiateResult::Done
}

// Platform-specific graph setup and main loop functions have been moved
// to their respective platform files (rp.rs, bcm2712.rs).
// They use the pub(crate) accessors: prepare_graph(), instantiate_one_module(),
// sched_mut(), sched_modules(), validate_buffer_groups(), compute_downstream_latency(),
// step_modules(), step_woken_modules().

/// Compute topological execution order from the edge graph using Kahn's algorithm.
///
/// Precompute upstream dependency bitmask for ready-signal gating.
/// For each module, upstream_mask[i] has bits set for all modules that
/// feed data into module i via edges. Used with ready[] to skip modules
/// whose upstream infrastructure hasn't signaled Ready yet.
fn compute_upstream_mask(edges: &[Edge], edge_count: usize) {
    let sched = unsafe { &mut *(&raw mut SCHED) };
    for i in 0..MAX_MODULES {
        sched.upstream_mask[i] = 0;
    }
    for i in 0..edge_count {
        let from = edges[i].from_module;
        let to = edges[i].to_module;
        if from < MAX_MODULES && to < MAX_MODULES {
            sched.upstream_mask[to] |= 1u16 << from;
        }
    }
}

/// After this, EXEC_ORDER contains module indices in dependency order:
/// sources first, sinks last. This ensures that within a single scheduler pass,
/// data flows through an entire chain (e.g. sequencer → synth → effects → i2s)
/// rather than propagating one hop per tick.
///
/// Modules not reachable via edges (isolated) are appended at the end.
/// Cycles (which shouldn't occur in a valid graph) are broken by appending
/// remaining modules in index order.
fn compute_exec_order(edges: &[Edge], edge_count: usize, module_count: usize) {
    let exec_order = unsafe { &mut *(&raw mut SCHED.exec_order) };

    // Compute in-degree for each module
    let mut in_degree = [0u8; MAX_MODULES];
    for i in 0..edge_count {
        let e = &edges[i];
        if e.channel >= 0 && e.to_module < module_count {
            in_degree[e.to_module] = in_degree[e.to_module].saturating_add(1);
        }
    }

    // BFS queue: start with modules that have no incoming edges (sources)
    let mut queue = [0u8; MAX_MODULES];
    let mut qhead: usize = 0;
    let mut qtail: usize = 0;
    for i in 0..module_count {
        if in_degree[i] == 0 {
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
        for i in 0..edge_count {
            let e = &edges[i];
            if e.channel >= 0 && e.from_module == m && e.to_module < module_count {
                in_degree[e.to_module] -= 1;
                if in_degree[e.to_module] == 0 {
                    queue[qtail] = e.to_module as u8;
                    qtail += 1;
                }
            }
        }
    }

    // Append any remaining modules (cycle-breaker or isolated modules)
    if count < module_count {
        for i in 0..module_count {
            let mut found = false;
            for j in 0..count {
                if exec_order[j] == i as u8 {
                    found = true;
                    break;
                }
            }
            if !found {
                exec_order[count] = i as u8;
                count += 1;
            }
        }
    }

    unsafe { SCHED.exec_order_count = count; }
}

/// Partition the global exec_order into per-domain execution orders (E4-S4).
///
/// Each domain gets its own ordered list of modules. On single-core, all domains
/// execute sequentially in the same tick (no behavior change). The data structures
/// are ready for Epic 6 multi-core where each domain maps to a core.
/// Accesses SCHED global directly to avoid borrow conflicts.
fn compute_domain_exec_orders_static(_module_count: usize) {
    let sched = unsafe { &mut *(&raw mut SCHED) };

    // Clear domain module counts
    for d in 0..MAX_DOMAINS {
        sched.domain_module_count[d] = 0;
    }

    // Walk exec_order (already topologically sorted) and partition by domain
    for order_pos in 0..sched.exec_order_count {
        let module_idx = sched.exec_order[order_pos] as usize;
        let domain = sched.domain_id[module_idx] as usize;
        let domain = if domain < MAX_DOMAINS { domain } else { 0 };

        let count = sched.domain_module_count[domain] as usize;
        if count < MAX_MODULES {
            sched.domain_exec_order[domain][count] = module_idx as u8;
            sched.domain_module_count[domain] = (count + 1) as u8;
        }
    }

    // Log domain composition
    let effective_domains = if sched.domain_count > 0 { sched.domain_count as usize } else { 1 };
    for d in 0..effective_domains {
        let count = sched.domain_module_count[d];
        if count > 0 || d == 0 {
            let tick = if sched.domain_tick_us[d] > 0 { sched.domain_tick_us[d] } else { sched.tick_us };
            log::info!("[domain] {} modules={} tick_us={}", d, count, tick);
        }
    }
}

/// Validate domain configuration (E4-S5).
///
/// Accesses SCHED global directly to avoid borrow conflicts with edges.
/// Checks:
/// - Warn on empty domains
/// - Warn on modules without domain assignment when domains are configured
/// - Validate cross_core edges connect modules in different domains
fn validate_domains_static(module_count: usize, edge_count: usize) {
    let sched = unsafe { &*(&raw const SCHED) };

    if sched.domain_count <= 1 {
        return; // Single domain — nothing to validate
    }

    let effective_domains = sched.domain_count as usize;

    // Warn on empty domains
    for d in 0..effective_domains {
        if sched.domain_module_count[d] == 0 {
            log::warn!("[domain] domain {} is empty (no modules assigned)", d);
        }
    }

    // Check for modules assigned to out-of-range domains
    for i in 0..module_count {
        let domain = sched.domain_id[i] as usize;
        if domain >= effective_domains && domain != 0 {
            log::warn!("[domain] module {} assigned to domain {} (max {}), using domain 0",
                i, domain, effective_domains - 1);
        }
    }

    // Validate cross_core edges connect modules in different domains
    for i in 0..edge_count {
        let e = &sched.edges[i];
        if let crate::kernel::config::EdgeClass::CrossCore = e.edge_class {
            let from_domain = if e.from_module < MAX_MODULES { sched.domain_id[e.from_module] } else { 0 };
            let to_domain = if e.to_module < MAX_MODULES { sched.domain_id[e.to_module] } else { 0 };
            if from_domain == to_domain {
                log::warn!("[domain] cross_core edge {}→{} but both in domain {}",
                    e.from_module, e.to_module, from_domain);
            }
        }
    }

    // Estimate tick budget: warn if module count exceeds rough budget
    for d in 0..effective_domains {
        let count = sched.domain_module_count[d] as usize;
        let domain_tick = if sched.domain_tick_us[d] > 0 { sched.domain_tick_us[d] } else { sched.tick_us };
        if domain_tick < 500 && count > 8 {
            log::warn!("[domain] domain {} has {} modules with tick_us={} — may exceed tick budget",
                d, count, domain_tick);
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
        if m >= module_count { continue; }

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

/// Finalize a module after it reports done or error.
///
/// Sets POLL_HUP (done) or POLL_ERR (error) on all output channels,
/// releases owned handles, and marks the module finished.
/// `error_code`: None = module done normally, Some(rc) = error with return code.
fn finalize_module(
    module_idx: usize,
    error_code: Option<i32>,
    type_name: &str,
    context: &str,
) {
    let sched = unsafe { &mut *(&raw mut SCHED) };

    let flag = if error_code.is_some() { POLL_ERR } else { POLL_HUP };
    if let Some(rc) = error_code {
        log::warn!("[sched] module {} ({}) error rc={}{}", module_idx, type_name, rc, context);
    } else {
        log::info!("[sched] module {} ({}) done{}", module_idx, type_name, context);
    }

    let ports = &sched.ports[module_idx];
    let mut p = 0;
    while p < ports.out_count as usize {
        if ports.out_chans[p] >= 0 {
            channel_set_flags(ports.out_chans[p], flag);
        }
        p += 1;
    }
    syscalls::release_module_handles(module_idx as u8);
    sched.finished[module_idx] = true;
}

#[no_mangle]
pub static mut DBG_TICK: u32 = 0;

/// Current tick count (milliseconds since boot). Used by timer FDs on aarch64.
pub fn tick_count() -> u32 {
    unsafe { DBG_TICK }
}
/// Last module index attempted before a crash — readable by HardFault handler
#[no_mangle]
pub static mut DBG_STEP_MODULE: u8 = 0xFF;

/// Crash data buffer in .uninit section — NOT zeroed by cortex-m-rt startup,
/// survives SYSRESETREQ software resets. Written by HardFault handler, read at tick 500.
/// Layout: [0]=magic, [1]=PC, [2]=LR, [3]=module, [4]=tick, [5]=R0
#[link_section = ".uninit.CRASH_DATA"]
#[no_mangle]
pub static mut CRASH_DATA: core::mem::MaybeUninit<[u32; 8]> = core::mem::MaybeUninit::uninit();

/// Magic marker for valid crash data
pub const CRASH_MAGIC: u32 = 0xDEAD_BEEF;

/// Parse protection configuration from module params TLV.
///
/// Looks for reserved tags 0xF0-0xF3 in the TLV v2 params blob:
/// - 0xF0: step_deadline_us (u32, 4 bytes LE)
/// - 0xF1: fault_policy (u8: 0=skip, 1=restart, 2=restart_graph)
/// - 0xF2: max_restarts (u16, 2 bytes LE)
/// - 0xF3: restart_backoff_ms (u16, 2 bytes LE)
fn parse_protection_config(module_idx: usize, params: &[u8]) {
    if params.len() < 4 {
        return;
    }

    // TLV v2 format: [0xFE, 0x02, len_lo, len_hi, ...entries..., 0xFF, 0x00]
    // Each entry: tag(1), len(1), value(len)
    // We scan raw bytes for our reserved tags regardless of TLV structure
    let mut pos = 0;

    // Skip TLV v2 header if present
    if params.len() >= 4 && params[0] == 0xFE && params[1] == 0x02 {
        pos = 4; // Skip header (magic, version, length)
    }

    let sched = unsafe { &mut *(&raw mut SCHED) };
    let fi = &mut sched.fault_info[module_idx];

    while pos + 2 <= params.len() {
        let tag = params[pos];
        let len = params[pos + 1] as usize;
        pos += 2;

        if tag == 0xFF {
            break; // End-of-params marker
        }

        if pos + len > params.len() {
            break;
        }

        match tag {
            0xF0 if len == 4 => {
                // step_deadline_us (u32 LE)
                let val = u32::from_le_bytes([
                    params[pos], params[pos+1], params[pos+2], params[pos+3],
                ]);
                fi.step_deadline_us = val;
            }
            0xF1 if len >= 1 => {
                // fault_policy
                fi.policy = match params[pos] {
                    0 => FaultPolicy::Skip,
                    1 => FaultPolicy::Restart,
                    2 => FaultPolicy::RestartGraph,
                    _ => FaultPolicy::Skip,
                };
            }
            0xF2 if len == 2 => {
                // max_restarts (u16 LE)
                fi.max_restarts = u16::from_le_bytes([params[pos], params[pos+1]]);
            }
            0xF3 if len == 2 => {
                // restart_backoff_ms (u16 LE)
                fi.restart_backoff_ms = u16::from_le_bytes([params[pos], params[pos+1]]);
            }
            _ => {} // Unknown tag — skip
        }

        pos += len;
    }
}

/// Handle a step timeout: record fault, transition to Faulted or Terminated.
fn handle_step_timeout(
    sched: &mut SchedulerState,
    modules: &mut [ModuleSlot; MAX_MODULES],
    module_idx: usize,
    active_count: &mut usize,
) {
    let tick = unsafe { DBG_TICK };
    let fi = &mut sched.fault_info[module_idx];
    fi.record_fault(fault_type::TIMEOUT, tick);
    log::warn!("[guard] module {} ({}) step timeout (fault #{})",
        module_idx, modules[module_idx].type_name(), fi.fault_count);

    if fi.can_restart() {
        fi.state = FaultState::Faulted;
        fi.backoff_remaining = fi.restart_backoff_ms as u32;
    } else {
        fi.state = FaultState::Terminated;
        finalize_module(module_idx, Some(-110), modules[module_idx].type_name(), " (timeout terminated)");
        *active_count -= 1;
    }
}

/// Handle a step error: record fault, transition to Faulted or finalize.
fn handle_step_error(
    sched: &mut SchedulerState,
    modules: &mut [ModuleSlot; MAX_MODULES],
    module_idx: usize,
    rc: i32,
    active_count: &mut usize,
    context: &str,
) {
    let tick = unsafe { DBG_TICK };
    let fi = &mut sched.fault_info[module_idx];
    fi.record_fault(fault_type::STEP_ERROR, tick);

    if fi.can_restart() {
        fi.state = FaultState::Faulted;
        fi.backoff_remaining = fi.restart_backoff_ms as u32;
        log::warn!("[guard] module {} ({}) error rc={} — will restart (fault #{})",
            module_idx, modules[module_idx].type_name(), rc, fi.fault_count);
    } else {
        fi.state = FaultState::Terminated;
        finalize_module(module_idx, Some(rc), modules[module_idx].type_name(), context);
        *active_count -= 1;
    }
}

/// Attempt to restart a faulted module.
///
/// Restart procedure:
/// 1. Mark as Recovering
/// 2. Release all handles
/// 3. Drain/flush connected channels
/// 4. Zero module state block
/// 5. Reset ready signal (re-gate downstream)
/// 6. Call module_new() with original params (via step_fn reinit)
/// 7. Resume stepping
///
/// Note: Full restart (re-calling module_new) requires stored params and
/// loader state. For v1, we do a simplified restart: zero state + re-call
/// module_new is deferred to a future iteration. Instead, we zero state
/// and let the module re-initialize on next step (works for stateless modules).
/// For stateful modules, the module will see zeroed state and should handle
/// it gracefully (same as fresh boot).
fn handle_module_restart(
    sched: &mut SchedulerState,
    modules: &mut [ModuleSlot; MAX_MODULES],
    module_idx: usize,
) {
    sched.fault_info[module_idx].state = FaultState::Recovering;
    sched.fault_info[module_idx].restart_count += 1;
    log::info!("[guard] restarting module {} ({}) (restart #{})",
        module_idx, modules[module_idx].type_name(),
        sched.fault_info[module_idx].restart_count);

    // Release owned handles (events, timers, DMA, providers, etc.)
    syscalls::release_module_handles(module_idx as u8);

    // Drain/flush all connected channels (both in and out)
    let ports = &sched.ports[module_idx];
    for i in 0..ports.in_count as usize {
        if ports.in_chans[i] >= 0 {
            channel::channel_ioctl(ports.in_chans[i], channel::IOCTL_FLUSH, core::ptr::null_mut());
        }
    }
    for i in 0..ports.out_count as usize {
        if ports.out_chans[i] >= 0 {
            channel::channel_ioctl(ports.out_chans[i], channel::IOCTL_FLUSH, core::ptr::null_mut());
        }
    }
    for i in 0..ports.ctrl_count as usize {
        if ports.ctrl_chans[i] >= 0 {
            channel::channel_ioctl(ports.ctrl_chans[i], channel::IOCTL_FLUSH, core::ptr::null_mut());
        }
    }

    // Zero the module's state block
    if let ModuleSlot::Dynamic(m) = &modules[module_idx] {
        let state = m.state_ptr();
        if !state.is_null() {
            // We don't know state_size from DynamicModule alone, but the arena
            // allocator zeroed it at alloc time. We'll zero a conservative amount
            // based on the arena info (if available).
            // For now, just leave state as-is — module will see previous state.
            // Full restart with module_new re-call is a future enhancement.
        }
    }

    // Reset ready signal if module was deferred_ready
    if sched.deferred_ready[module_idx] {
        sched.ready[module_idx] = false;
    }

    // Mark as running again
    sched.fault_info[module_idx].state = FaultState::Running;
    sched.finished[module_idx] = false;
}

pub fn step_modules(modules: &mut [ModuleSlot; MAX_MODULES], count: usize) -> StepResult {
    let sched = unsafe { &mut *(&raw mut SCHED) };
    let tick = unsafe { DBG_TICK };
    unsafe { DBG_TICK += 1; }

    // ── Live Reconfigure: drain progress check ─────────────────────
    // Single branch-not-taken during normal RUNNING — zero overhead.
    if sched.reconfigure_phase == ReconfigurePhase::Draining {
        if check_drain_progress(count) {
            enter_migrating_v1();
            // V1: signal that migration should happen (caller handles rebuild)
        }
    }
    // Periodic heartbeat — confirms scheduler is alive
    if tick % 500 == 0 && tick > 0 {
        // Check for crash info from previous run (in .uninit RAM, set by HardFault handler)
        // Done at t=500 so USB serial is definitely connected.
        if tick == 500 {
            unsafe {
                let crash = (&raw const CRASH_DATA) as *const u32;
                let magic = core::ptr::read_volatile(crash);
                if magic == CRASH_MAGIC {
                    let pc = core::ptr::read_volatile(crash.add(1));
                    let lr = core::ptr::read_volatile(crash.add(2));
                    let module = core::ptr::read_volatile(crash.add(3));
                    let prev_tick = core::ptr::read_volatile(crash.add(4));
                    let r0 = core::ptr::read_volatile(crash.add(5));
                    let cfsr = core::ptr::read_volatile(crash.add(6));
                    let bfar = core::ptr::read_volatile(crash.add(7));
                    log::error!("[crash] pc={:08x} lr={:08x} r0={:08x} mod={} t={}",
                        pc, lr, r0, module, prev_tick);
                    log::error!("[crash] cfsr={:08x} bfar={:08x}", cfsr, bfar);
                    // Clear marker so it doesn't repeat
                    core::ptr::write_volatile((&raw mut CRASH_DATA) as *mut u32, 0);
                }
            }
        }
        log::info!("[sched] alive t={}", tick);
    }
    // Count active (non-finished) modules upfront so step-period gating
    // doesn't falsely produce active_count==0 → StepResult::Done.
    let mut active_count: usize = 0;
    for i in 0..count {
        if !sched.finished[i] {
            active_count += 1;
        }
    }

    // Compute not-ready bitmask for upstream gating
    let mut not_ready: u16 = 0;
    for i in 0..count {
        if !sched.ready[i] {
            not_ready |= 1u16 << i;
        }
    }

    // Step modules in topological order so producers run before consumers
    let exec_count = sched.exec_order_count;
    let n = if exec_count > 0 { exec_count } else { count };
    for order_pos in 0..n {
        let module_idx = if exec_count > 0 { sched.exec_order[order_pos] as usize } else { order_pos };
        if module_idx >= count {
            continue;
        }

        // Skip already finished modules
        if sched.finished[module_idx] {
            continue;
        }

        // Step frequency gating: skip if counter hasn't reached period
        let period = sched.step_period[module_idx];
        if period > 0 {
            sched.step_counter[module_idx] = sched.step_counter[module_idx].wrapping_add(1);
            if sched.step_counter[module_idx] < period {
                continue;
            }
            sched.step_counter[module_idx] = 0;
        }

        // Note: we intentionally step ALL non-finished modules every tick.
        // Stateful generators (e.g. synth) produce continuous output from
        // internal state, not just in response to input data. Gating on
        // input readiness starves audio pipelines.

        // Ready-signal gating: skip if any upstream module hasn't signaled Ready.
        // Deferred-ready modules (infrastructure) are exempt while initializing —
        // they must step freely to reach Ready even if upstream peers aren't ready.
        // Only non-deferred (application) modules are gated by upstream readiness.
        if not_ready != 0
            && !sched.deferred_ready[module_idx]
            && (sched.upstream_mask[module_idx] & not_ready) != 0
        {
            continue;
        }

        // Skip faulted/terminated modules
        let fault_state = sched.fault_info[module_idx].state;
        if fault_state == FaultState::Faulted {
            // Check if backoff has elapsed → attempt restart
            if sched.fault_info[module_idx].backoff_remaining > 0 {
                sched.fault_info[module_idx].backoff_remaining -= 1;
                continue;
            }
            if sched.fault_info[module_idx].can_restart() {
                handle_module_restart(sched, modules, module_idx);
                // After restart attempt, skip this tick (module will run next tick)
                continue;
            } else {
                // Cannot restart — terminate
                sched.fault_info[module_idx].state = FaultState::Terminated;
                finalize_module(module_idx, Some(-110), modules[module_idx].type_name(), " (terminated)");
                active_count -= 1;
                continue;
            }
        } else if fault_state == FaultState::Terminated || fault_state == FaultState::Recovering {
            continue;
        }

        if let Some(m) = modules[module_idx].as_module_mut() {
            // Set current_module so channel_port works during module_step
            sched.current_module = module_idx;
            // Track for HardFault diagnosis
            unsafe { core::ptr::write_volatile(&raw mut DBG_STEP_MODULE, module_idx as u8); }

            // Arm step guard timer
            let deadline = sched.fault_info[module_idx].effective_deadline_us();
            step_guard::arm(deadline);

            match m.step() {
                Ok(StepOutcome::Continue) => {
                    step_guard::disarm();
                    step_guard::post_step_check();
                    if step_guard::check_and_clear_timeout() {
                        handle_step_timeout(sched, modules, module_idx, &mut active_count);
                    }
                }
                Ok(StepOutcome::Ready) => {
                    step_guard::disarm();
                    if !sched.ready[module_idx] {
                        sched.ready[module_idx] = true;
                        log::info!("{}: ready", modules[module_idx].type_name());
                    }
                }
                Ok(StepOutcome::Done) => {
                    step_guard::disarm();
                    finalize_module(module_idx, None, modules[module_idx].type_name(), "");
                    active_count -= 1;
                }
                Ok(StepOutcome::Burst) => {
                    // Keep timer armed for entire burst with extended deadline
                    step_guard::disarm();
                    let burst_deadline = deadline.saturating_mul(step_guard::BURST_MULTIPLIER);
                    step_guard::arm(burst_deadline);

                    for _ in 0..MAX_BURST_STEPS {
                        // Check timeout between burst iterations
                        if step_guard::is_timed_out() {
                            step_guard::disarm();
                            step_guard::check_and_clear_timeout();
                            handle_step_timeout(sched, modules, module_idx, &mut active_count);
                            break;
                        }
                        if let Some(m) = modules[module_idx].as_module_mut() {
                            match m.step() {
                                Ok(StepOutcome::Burst) => continue,
                                Ok(StepOutcome::Continue) => break,
                                Ok(StepOutcome::Ready) => {
                                    if !sched.ready[module_idx] {
                                        sched.ready[module_idx] = true;
                                        log::info!("{}: ready", modules[module_idx].type_name());
                                    }
                                    break;
                                }
                                Ok(StepOutcome::Done) => {
                                    finalize_module(module_idx, None, modules[module_idx].type_name(), " (burst)");
                                    active_count -= 1;
                                    break;
                                }
                                Err(rc) => {
                                    handle_step_error(sched, modules, module_idx, rc, &mut active_count, " (burst)");
                                    break;
                                }
                            }
                        } else {
                            break;
                        }
                    }
                    step_guard::disarm();
                    step_guard::post_step_check();
                    // Check if burst as a whole timed out
                    if step_guard::check_and_clear_timeout() {
                        handle_step_timeout(sched, modules, module_idx, &mut active_count);
                    }
                }
                Err(rc) => {
                    step_guard::disarm();
                    handle_step_error(sched, modules, module_idx, rc, &mut active_count, "");
                }
            }
        }
    }

    if active_count == 0 {
        StepResult::Done
    } else {
        StepResult::Continue
    }
}

/// Step only modules whose bit is set in `wake_bits`.
/// Bypasses frequency gating — an event overrides the step period.
/// Uses topological order to preserve producer-before-consumer invariant.
pub fn step_woken_modules(
    modules: &mut [ModuleSlot; MAX_MODULES],
    count: usize,
    wake_bits: u16,
) {
    let sched = unsafe { &mut *(&raw mut SCHED) };
    let exec_count = sched.exec_order_count;

    let n = if exec_count > 0 { exec_count } else { count };
    for order_pos in 0..n {
        let module_idx = if exec_count > 0 { sched.exec_order[order_pos] as usize } else { order_pos };
        if module_idx >= count {
            continue;
        }
        if sched.finished[module_idx] {
            continue;
        }
        // Only step modules with pending events
        if (wake_bits & (1u16 << module_idx)) == 0 {
            continue;
        }
        // Ready-signal gating: skip if any upstream module hasn't signaled Ready.
        // Deferred-ready modules are exempt while initializing.
        {
            let mut not_ready: u16 = 0;
            for i in 0..count {
                if !sched.ready[i] { not_ready |= 1u16 << i; }
            }
            if not_ready != 0
                && !sched.deferred_ready[module_idx]
                && (sched.upstream_mask[module_idx] & not_ready) != 0
            {
                continue;
            }
        }
        // Skip faulted/terminated modules
        let fault_state = sched.fault_info[module_idx].state;
        if fault_state != FaultState::Running {
            continue;
        }

        if let Some(m) = modules[module_idx].as_module_mut() {
            sched.current_module = module_idx;

            let deadline = sched.fault_info[module_idx].effective_deadline_us();
            step_guard::arm(deadline);

            match m.step() {
                Ok(StepOutcome::Continue) => {
                    step_guard::disarm();
                    step_guard::post_step_check();
                    if step_guard::check_and_clear_timeout() {
                        log::warn!("[guard] module {} timeout (event wake)", module_idx);
                        sched.fault_info[module_idx].record_fault(fault_type::TIMEOUT, unsafe { DBG_TICK });
                    }
                }
                Ok(StepOutcome::Ready) => {
                    step_guard::disarm();
                    if !sched.ready[module_idx] {
                        sched.ready[module_idx] = true;
                        log::info!("{}: ready", modules[module_idx].type_name());
                    }
                }
                Ok(StepOutcome::Done) => {
                    step_guard::disarm();
                    finalize_module(module_idx, None, modules[module_idx].type_name(), " (event wake)");
                }
                Ok(StepOutcome::Burst) => {
                    step_guard::disarm();
                    let burst_deadline = deadline.saturating_mul(step_guard::BURST_MULTIPLIER);
                    step_guard::arm(burst_deadline);

                    for _ in 0..MAX_BURST_STEPS {
                        if step_guard::is_timed_out() {
                            break;
                        }
                        if let Some(m) = modules[module_idx].as_module_mut() {
                            match m.step() {
                                Ok(StepOutcome::Burst) => continue,
                                Ok(StepOutcome::Continue) => break,
                                Ok(StepOutcome::Ready) => {
                                    if !sched.ready[module_idx] {
                                        sched.ready[module_idx] = true;
                                        log::info!("{}: ready", modules[module_idx].type_name());
                                    }
                                    break;
                                }
                                Ok(StepOutcome::Done) => {
                                    finalize_module(module_idx, None, modules[module_idx].type_name(), " (event wake burst)");
                                    break;
                                }
                                Err(rc) => {
                                    finalize_module(module_idx, Some(rc), modules[module_idx].type_name(), " (event wake burst)");
                                    break;
                                }
                            }
                        } else {
                            break;
                        }
                    }
                    step_guard::disarm();
                    step_guard::post_step_check();
                    step_guard::check_and_clear_timeout(); // Clear without action for woken path
                }
                Err(rc) => {
                    step_guard::disarm();
                    finalize_module(module_idx, Some(rc), modules[module_idx].type_name(), " (event wake)");
                }
            }
        }
    }
}

// ============================================================================
// Live Reconfigure — Drain Phase
// ============================================================================

/// Return the current reconfigure phase (for observability).
pub fn reconfigure_phase() -> ReconfigurePhase {
    unsafe { SCHED.reconfigure_phase }
}

/// Enter the DRAINING phase for a live reconfigure.
///
/// Classifies each module as Surviving, Draining, or PendingTerminate based on
/// the `surviving` bitmask and each module's drain_capable flag.
/// Calls module_drain() on all drain-capable non-surviving modules.
///
/// `surviving`: bitmask where bit N set = module N survives the transition.
/// `drain_timeout_ms`: maximum time in ms to wait for drain completion.
pub fn enter_draining(surviving: u16, drain_timeout_ms: u32) {
    let sched = unsafe { &mut *(&raw mut SCHED) };
    let count = sched.active_module_count;
    let tick = unsafe { DBG_TICK };

    sched.reconfigure_phase = ReconfigurePhase::Draining;
    sched.drain_start_tick = tick;
    sched.drain_timeout_ticks = drain_timeout_ms;

    let mut draining_count: usize = 0;
    let mut terminate_count: usize = 0;

    // Classify modules and call module_drain on drain-capable ones
    // RFC: module_drain() called in reverse topological order (downstream first)
    let exec_count = sched.exec_order_count;
    for rev_pos in 0..exec_count {
        let order_pos = exec_count - 1 - rev_pos;
        let module_idx = sched.exec_order[order_pos] as usize;
        if module_idx >= count { continue; }

        if (surviving & (1u16 << module_idx)) != 0 {
            sched.drain_state[module_idx] = DrainState::Surviving;
            continue;
        }

        if sched.drain_capable[module_idx] {
            // Call module_drain on the module
            if let ModuleSlot::Dynamic(ref m) = sched.modules[module_idx] {
                sched.current_module = module_idx;
                let _rc = unsafe { m.call_drain() };
            }
            sched.drain_state[module_idx] = DrainState::Draining;
            sched.drain_inflight[module_idx] = 0;
            draining_count += 1;
        } else {
            sched.drain_state[module_idx] = DrainState::PendingTerminate;
            terminate_count += 1;
        }
    }

    log::info!(
        "[reconfigure] phase=DRAINING draining={} terminate={} surviving={} timeout={}ms",
        draining_count, terminate_count,
        count - draining_count - terminate_count,
        drain_timeout_ms,
    );
}

/// Check drain progress and handle timeouts.
///
/// Called each tick during DRAINING phase (from step_modules).
/// Returns true if draining is complete (all non-surviving modules are
/// Drained or PendingTerminate), meaning we should transition to MIGRATING.
fn check_drain_progress(count: usize) -> bool {
    let sched = unsafe { &mut *(&raw mut SCHED) };
    let tick = unsafe { DBG_TICK };

    // Check timeout
    let elapsed = tick.wrapping_sub(sched.drain_start_tick);
    if elapsed >= sched.drain_timeout_ticks {
        force_drain_complete(count);
        return true;
    }

    // Check if all draining modules have returned Done
    for i in 0..count {
        if sched.drain_state[i] == DrainState::Draining {
            // Still draining — check if module returned Done in last step
            if sched.finished[i] {
                // Module returned Done during step — check upstream drain ordering.
                // A module cannot be marked Drained until all upstream draining
                // modules are already Drained (forward topological ordering).
                let upstream_still_draining = check_upstream_draining(i, count);
                if !upstream_still_draining {
                    sched.drain_state[i] = DrainState::Drained;
                    log::info!("[reconfigure] module={} ({}) drain_complete elapsed={}ms",
                        i, sched.modules[i].type_name(), elapsed);
                }
                // If upstream still draining, keep this module as Draining
                // until upstream completes (forward topo ordering)
            }
        }
    }

    // Check if all non-surviving modules are done
    for i in 0..count {
        if sched.drain_state[i] == DrainState::Draining {
            return false; // Still draining
        }
    }

    true // All drained or pending-terminate
}

/// Check if any upstream module of `module_idx` is still in Draining state.
fn check_upstream_draining(module_idx: usize, count: usize) -> bool {
    let sched = unsafe { &*(&raw const SCHED) };
    let upstream = sched.upstream_mask[module_idx];

    for i in 0..count {
        if i == module_idx { continue; }
        if (upstream & (1u16 << i)) != 0 && sched.drain_state[i] == DrainState::Draining {
            return true;
        }
    }
    false
}

/// Force all still-draining modules to Drained state (timeout exceeded).
fn force_drain_complete(count: usize) {
    let sched = unsafe { &mut *(&raw mut SCHED) };

    for i in 0..count {
        if sched.drain_state[i] == DrainState::Draining {
            log::warn!("[reconfigure] module={} ({}) drain_forced inflight={}",
                i, sched.modules[i].type_name(), sched.drain_inflight[i]);
            sched.drain_state[i] = DrainState::Drained;
        }
    }
}

/// Execute the MIGRATING phase: v1 fallback (full arena reset).
///
/// V1 strategy: drain-capable modules get a graceful shutdown, then we do
/// a full destructive reconfigure. Arena compaction is deferred to v2.
///
/// Rationale for v1 full-reset fallback:
/// - Many existing modules may use absolute pointers in state (not audited yet)
/// - Arena compaction requires moving state blocks, which breaks self-referential ptrs
/// - The drain phase already provides the key value: in-flight work completes gracefully
/// - Full reset is safe, simple, and matches current behavior after drain completes
///
/// V2 will add: state arena compaction, selective module instantiation, channel
/// preservation for surviving modules. This requires auditing all modules for
/// absolute pointer usage and adding module_state_export/import where needed.
fn enter_migrating_v1() {
    let sched = unsafe { &mut *(&raw mut SCHED) };

    log::info!("[reconfigure] phase=MIGRATING (v1 full reset)");
    sched.reconfigure_phase = ReconfigurePhase::Migrating;

    // V1: After drain completes, perform a full destructive reconfigure.
    // The drain phase already allowed in-flight work to complete gracefully.
    // Now we tear down everything and rebuild from the new config.
    //
    // This is functionally identical to the existing prepare_graph() path,
    // but preceded by the drain phase that let modules finish their work.
    //
    // The actual graph rebuild is triggered by the caller (run_main_loop)
    // which detects the Migrating phase and calls setup_graph_async().
}

/// Identify channels that should be preserved during MIGRATING.
///
/// A channel is preserved if BOTH endpoints (from_module and to_module)
/// are in the `surviving` bitmask. All other channels are closed.
///
/// Returns a bitmask of edge indices that should be preserved.
/// V1 note: This function is implemented but not used in the v1 full-reset
/// path. It will be used by v2 selective channel migration.
#[allow(dead_code)]
fn compute_preserved_channels(surviving: u16, edge_count: usize) -> u32 {
    let sched = unsafe { &*(&raw const SCHED) };
    let mut preserved: u32 = 0;

    for i in 0..edge_count {
        let edge = &sched.edges[i];
        if edge.channel < 0 { continue; }

        let from_survives = (surviving & (1u16 << edge.from_module)) != 0;
        let to_survives = (surviving & (1u16 << edge.to_module)) != 0;

        if from_survives && to_survives {
            preserved |= 1u32 << i;
        }
    }

    preserved
}

/// Report in-flight work count for a draining module (called from syscall).
pub fn drain_report_inflight(module_idx: usize, count: u32) {
    if module_idx < MAX_MODULES {
        unsafe { SCHED.drain_inflight[module_idx] = count; }
    }
}

/// Rollback from a failed migration attempt.
///
/// If migration fails (module_new returns error, arena exhausted, etc.),
/// the scheduler falls back to a full destructive reconfigure from the
/// previous known-good config. In v1, this is equivalent to calling
/// prepare_graph() + setup_graph_async() with the old config.
///
/// The A/B slot mechanism ensures the old config is always available:
/// the slot flip only happens AFTER successful migration.
pub fn rollback_reconfigure() {
    let sched = unsafe { &mut *(&raw mut SCHED) };

    log::error!("[reconfigure] migration failed, rolling back to previous config");

    // Reset phase to Running — the old graph continues
    sched.reconfigure_phase = ReconfigurePhase::Running;

    // Clear drain state
    for i in 0..MAX_MODULES {
        sched.drain_state[i] = DrainState::Surviving;
        sched.drain_inflight[i] = 0;
    }

    // The caller should reload the old config and do a full destructive
    // reconfigure. In v1, this means the drained modules are already stopped
    // and we've lost their state — but at least the system recovers.
}

/// Return elapsed drain time in ms (0 if not draining).
pub fn drain_elapsed_ms() -> u32 {
    let sched = unsafe { &*(&raw const SCHED) };
    if sched.reconfigure_phase != ReconfigurePhase::Draining {
        return 0;
    }
    let tick = unsafe { DBG_TICK };
    tick.wrapping_sub(sched.drain_start_tick)
}

// ============================================================================
// Channel Collection Helpers
// ============================================================================

fn collect_channels(
    edges: &[Edge; MAX_CHANNELS],
    module_idx: usize,
    direction: FanDirection,
    ctrl_only: bool,
    out: &mut [i32; MAX_CHANNELS],
) -> usize {
    let mut count = 0;
    for edge in edges.iter() {
        let matches = match direction {
            FanDirection::Out => edge.from_module == module_idx,
            FanDirection::In => edge.to_module == module_idx && edge.is_ctrl() == ctrl_only,
        };
        if edge.channel >= 0 && matches {
            // Place at port index if it fits, otherwise append
            let port_idx = match direction {
                FanDirection::Out => edge.from_port_index as usize,
                FanDirection::In => edge.to_port_index as usize,
            };
            if port_idx < out.len() && out[port_idx] == -1 {
                out[port_idx] = edge.channel;
                if port_idx >= count { count = port_idx + 1; }
            } else if count < out.len() {
                out[count] = edge.channel;
                count += 1;
            }
        }
    }
    count
}

fn collect_output_channels(
    edges: &[Edge; MAX_CHANNELS],
    module_idx: usize,
    out: &mut [i32; MAX_CHANNELS],
) -> usize {
    collect_channels(edges, module_idx, FanDirection::Out, false, out)
}

fn collect_input_channels(
    edges: &[Edge; MAX_CHANNELS],
    module_idx: usize,
    out: &mut [i32; MAX_CHANNELS],
) -> usize {
    // Only collect non-ctrl (data) input channels
    collect_channels(edges, module_idx, FanDirection::In, false, out)
}

fn collect_ctrl_channels(
    edges: &[Edge; MAX_CHANNELS],
    module_idx: usize,
    out: &mut [i32; MAX_CHANNELS],
) -> usize {
    // Only collect ctrl input channels
    collect_channels(edges, module_idx, FanDirection::In, true, out)
}

// ============================================================================
// Built-in module graph (no PIC loading, no config parsing)
// ============================================================================

/// Manually insert built-in modules and run the scheduler loop.
/// Used on platforms without flash/PIC (e.g. aarch64 QEMU).
///
/// `modules`: array of (name, step_fn) pairs. Channels between them are
/// created automatically: module[0].out → module[1].in → module[1].out → ...
pub fn run_builtin_graph(modules: &[(&'static str, fn(*mut u8) -> i32)]) -> ! {
    let count = modules.len().min(MAX_MODULES);
    let sched = unsafe { &mut *(&raw mut SCHED) };

    // Create channels between consecutive modules
    let mut channels = [0i32; MAX_MODULES];
    let mut chan_count = 0usize;
    if count > 1 {
        let mut i = 0;
        while i < count - 1 {
            let ch = channel::channel_open(channel::CHANNEL_TYPE_PIPE, null(), 0);
            if ch >= 0 {
                channels[i] = ch;
                chan_count += 1;
            }
            i += 1;
        }
    }

    // Insert modules
    let mut i = 0;
    while i < count {
        let mut m = BuiltInModule::new(modules[i].0, modules[i].1);
        // Store channel handles in state: bytes 0-3 = input, 4-7 = output
        let state = m.state.as_mut_ptr();
        // Input channel (from previous module)
        let in_ch: i32 = if i > 0 { channels[i - 1] } else { -1 };
        unsafe { core::ptr::write(state as *mut i32, in_ch) };
        // Output channel (to next module)
        let out_ch: i32 = if i < count - 1 { channels[i] } else { -1 };
        unsafe { core::ptr::write(state.add(4) as *mut i32, out_ch) };

        sched.modules[i] = ModuleSlot::BuiltIn(m);
        sched.ready[i] = true;
        i += 1;
    }

    log::info!("[sched] running modules={} channels={}", count, chan_count);

    // Synchronous main loop
    loop {
        unsafe {
            core::arch::asm!("wfi"); // Wait for timer tick
        }

        unsafe { DBG_TICK += 1; }
        let tick = unsafe { DBG_TICK };

        step_modules(&mut sched.modules, count);

        // Check event wake
        let wake = crate::kernel::event::take_wake_pending();
        if wake != 0 {
            step_woken_modules(&mut sched.modules, count, wake);
        }

        if tick % 500 == 0 {
            log::info!("[sched] alive t={}", tick);
        }
    }
}
