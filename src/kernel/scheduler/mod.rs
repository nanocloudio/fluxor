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

use portable_atomic::{AtomicBool, Ordering};

use crate::kernel::channel;
use crate::kernel::channel::{channel_set_flags, channel_set_mailbox, POLL_ERR, POLL_HUP};
use crate::kernel::config::{
    read_config_into, Config, ModuleEntry, MAX_GRAPH_EDGES, MAX_MODULES as CONFIG_MAX_MODULES,
};
use crate::kernel::hal;
use crate::kernel::loader::{
    find_hint_for_port, query_channel_hints, reset_state_arena, ChannelHint, DynamicModule,
    ModuleLoader, StartNewResult,
};
use crate::kernel::step_guard::{
    self, fault_type, FaultPolicy, FaultRecord, FaultState, FaultStats, ModuleFaultInfo,
};
use crate::kernel::syscalls;
use crate::kernel::syscalls::{get_table_for_module_type, is_spi_initialized};
use crate::modules::StepOutcome;

// ============================================================================
// Graph Constants and Types
// ============================================================================

/// Maximum number of modules in a graph.
pub const MAX_MODULES: usize = CONFIG_MAX_MODULES;

// Compile-time gate: readiness, upstream, event-wake, and domain-step
// bitmaps in this module store one bit per module in a `u64`. Widening
// `MAX_MODULES` past 64 must come with a matching bitmap rewrite — until
// then this assert blocks the configuration drift that would let
// `1u64 << module_idx` overflow at runtime.
const _: () = assert!(
    MAX_MODULES <= 64,
    "MAX_MODULES > 64 requires widening every scheduler bitmap (upstream_mask, \
     not_ready, wake_bits, event-wake) past u64."
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
    pub edge_class: crate::kernel::config::EdgeClass,
    /// Per-edge ring-buffer size override in bytes (from
    /// `wiring[i].buffer_bytes` in the YAML config). `0` defers to
    /// `module_channel_hints`; non-zero is combined with module hints
    /// via `max(...)` in `open_channels`. See
    /// `kernel::config::GraphEdge::buffer_bytes`.
    pub buffer_bytes: u32,
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
            edge_class: crate::kernel::config::EdgeClass::Local,
            buffer_bytes: 0,
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
            edge_class: crate::kernel::config::EdgeClass::Local,
            buffer_bytes: 0,
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
        // Check for buffer group aliasing
        let group = edge.buffer_group as usize;
        if group > 0 && group < 128 && group_channels[group] >= 0 {
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

        // Determine buffer size: grouped edges use pre-computed max,
        // ungrouped edges use the same combined signal directly.
        let buf_size = if group > 0 && group < 128 && group_max_size[group] > 0 {
            group_max_size[group]
        } else {
            edge_min_size(edge)
        };

        let producer_mod = edge.from_module as u8;
        let chan = if buf_size > 0 {
            // `channel_open` accepts only an exact 4-byte LE u32 that
            // is already a power of two and in `[64, 256 KiB]`. Module
            // hints and YAML overrides arrive as arbitrary `u32`s, so
            // the scheduler is the place that normalises before the
            // syscall sees them.
            const MIN_CHAN_BYTES: u32 = 64;
            const MAX_CHAN_BYTES: u32 = 256 * 1024;
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
                    "[graph] buffer_group={} duplicate in_place_writer module={}",
                    group,
                    to_mod
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
        unsafe {
            if NEXT_NAME_SLOT >= MAX_NAMES {
                log::warn!(
                    "NameArena: exhausted ({} slots), cannot intern '{}'",
                    MAX_NAMES,
                    name
                );
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
///
/// # Safety
/// Returns a `&'static ModuleLoader` aliasing the static `STATIC_LOADER`.
/// Caller must not hold a `static_loader_mut()` borrow concurrently.
pub unsafe fn static_loader() -> &'static ModuleLoader {
    let p = &raw const STATIC_LOADER;
    &*p
}

/// Mutable access to the static loader for platforms that initialize
/// it themselves (e.g. CM5 scans flash via the trailer).
///
/// # Safety
/// Returns an exclusive `&mut` to `STATIC_LOADER`. Only sound during
/// platform init before any module is stepped, or from the
/// reconfigure code path which is single-threaded by the
/// `reconfigure_phase` state machine.
pub unsafe fn static_loader_mut() -> &'static mut ModuleLoader {
    let p = &raw mut STATIC_LOADER;
    &mut *p
}

/// Mutable access to the static config, paired with `static_loader_mut`.
///
/// # Safety
/// Returns an exclusive `&mut` to `STATIC_CONFIG`. Same constraints as
/// `static_loader_mut`: init-time or single-threaded reconfigure only.
pub unsafe fn static_config_mut() -> &'static mut Config {
    let p = &raw mut STATIC_CONFIG;
    &mut *p
}

/// Get a reference to the static config. Returns the parsed FXWR header
/// + module list + edge list that `prepare_graph` consumes.
///
/// # Safety
/// Returns a `&'static Config` aliasing `STATIC_CONFIG`. Caller must not
/// hold a `static_config_mut()` borrow concurrently.
pub unsafe fn static_config() -> &'static Config {
    let p = &raw const STATIC_CONFIG;
    &*p
}

/// Install a fully-formed `Config` directly into the static slot. Used
/// by integration tests that drive `prepare_graph` against a synthetic
/// graph without round-tripping through the binary serializer.
///
/// # Safety
/// Overwrites `STATIC_CONFIG`. Caller must ensure no other reference to
/// `STATIC_CONFIG` is live (no module is mid-step, no other thread is
/// reading config). Test-only on hosted; reconfigure-time on bare metal.
pub unsafe fn install_static_config(cfg: Config) {
    let dst = unsafe {
        let p = &raw mut STATIC_CONFIG;
        &mut *p
    };
    *dst = cfg;
}

/// Populate the static config + loader from in-memory blobs.
///
/// `config_ptr` points to an FXWR-format config blob; `modules_ptr` to a
/// module-table blob. The caller must keep both memory ranges mapped
/// until module instantiation completes. After this returns `Ok`,
/// `prepare_graph()` is the next step.
///
/// **Length-aware variant**: callers that know the config blob length
/// (hosted targets reading from a file, wasm reading from a static
/// `[u8; N]` blob) should prefer [`populate_static_state_with_len`] so
/// the parser can reject sections that would extend past the mapped
/// range. The pointer-only entry continues to delegate to a strict
/// path internally with a 32 KiB upper bound — the historical
/// `MAX_CONFIG_SIZE`.
///
/// # Safety
/// `config_ptr` and `modules_ptr` must each point at a valid blob whose
/// internal length fields stay within the mapped range. Both ranges
/// must remain mapped for the lifetime of `STATIC_CONFIG` / loader use
/// (typically the entire kernel run on bare-metal targets). Mutates
/// the static config + loader; not safe to call after the scheduler
/// has started stepping modules.
pub unsafe fn populate_static_state(
    config_ptr: *const u8,
    config_len: usize,
    modules_ptr: *const u8,
) -> Result<(), &'static str> {
    // `config_len` is the platform's declared upper bound on the
    // config blob's mapped region. QEMU virt passes the gap between
    // QEMU_CONFIG_BLOB_ADDR and QEMU_MODULES_BLOB_ADDR; other
    // bare-metal paths use the slot size from their flash trailer.
    let loader = unsafe {
        let p = &raw mut STATIC_LOADER;
        &mut *p
    };
    let config = unsafe {
        let p = &raw mut STATIC_CONFIG;
        &mut *p
    };
    loader
        .init_from_blob(modules_ptr)
        .map_err(|_| "loader init failed")?;
    if !unsafe {
        crate::kernel::config::read_config_from_ptr_with_len(config_ptr, config_len, config)
    } {
        return Err("config parse failed");
    }
    Ok(())
}

/// Length-aware counterpart to `populate_static_state`.
///
/// `config_blob` is the entire config region as a byte slice; its length
/// is the hard upper bound the parser uses when validating section
/// offsets. Hosted targets (Linux: `Vec<u8>` from disk; WASM: a static
/// `[u8; CONFIG_BLOB_CAPACITY]`) call this variant so a malformed
/// header that claims a body larger than the actual blob fails
/// deterministically rather than wandering past the mapping.
///
/// # Safety
/// `modules_ptr` must point at a valid module-table blob whose internal
/// length fields stay within the mapped range. `config_blob` may be
/// any slice the caller has a valid reference for. Mutates the static
/// config + loader; not safe to call after the scheduler has started
/// stepping modules.
pub unsafe fn populate_static_state_with_len(
    config_blob: &[u8],
    modules_ptr: *const u8,
) -> Result<(), &'static str> {
    let loader = unsafe {
        let p = &raw mut STATIC_LOADER;
        &mut *p
    };
    let config = unsafe {
        let p = &raw mut STATIC_CONFIG;
        &mut *p
    };
    loader
        .init_from_blob(modules_ptr)
        .map_err(|_| "loader init failed")?;
    if !crate::kernel::config::read_config_from_slice(config_blob, config) {
        return Err("config parse failed");
    }
    Ok(())
}

/// Maximum ports per direction (in/out/ctrl) per module. Sized for
/// Quantum's session_processor, which multiplexes 7 logical input
/// streams across 7 ports with fan-in expansion. `pub(super)` so
/// `module_types` can size its `TeeModule::out_chans` /
/// `MergeModule::in_chans` arrays from the same constant.
pub(super) const MAX_PORTS: usize = 16;

/// Per-module port assignments (replaces old MODULE_CHANNELS tuple)
#[derive(Clone, Copy)]
pub struct ModulePorts {
    in_chans: [i32; MAX_PORTS],
    out_chans: [i32; MAX_PORTS],
    ctrl_chans: [i32; MAX_PORTS],
    in_count: u8,
    out_count: u8,
    ctrl_count: u8,
}

impl ModulePorts {
    const fn empty() -> Self {
        Self {
            in_chans: [-1; MAX_PORTS],
            out_chans: [-1; MAX_PORTS],
            ctrl_chans: [-1; MAX_PORTS],
            in_count: 0,
            out_count: 0,
            ctrl_count: 0,
        }
    }
}

/// Read a port channel handle for a module. Mirror of `set_module_port`.
/// Returns -1 if unset or out of range.
pub fn get_module_port(module_idx: usize, port_type: u8, port_index: u8) -> i32 {
    if module_idx >= MAX_MODULES {
        return -1;
    }
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
struct ModuleHints {
    hints: [ChannelHint; MAX_HINTS_PER_MODULE],
    count: usize,
}

impl ModuleHints {
    const fn empty() -> Self {
        Self {
            hints: [ChannelHint {
                port_type: 0,
                port_index: 0,
                buffer_size: 0,
            }; MAX_HINTS_PER_MODULE],
            count: 0,
        }
    }
}

/// Per-module arena info: (ptr, size). Null if module has no arena.
#[derive(Copy, Clone)]
struct ArenaInfo {
    ptr: *mut u8,
    size: u32,
}

impl ArenaInfo {
    const fn empty() -> Self {
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
    /// Number of populated entries in `edges` (post fan insertion).
    pub edge_count: usize,
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
    /// Per-module capability class (checked on provider dispatch)
    cap_class: [u8; MAX_MODULES],
    /// Per-module required_caps bitmask from manifest — public contract bits only
    required_caps: [u32; MAX_MODULES],
    /// Per-module fine-grained permissions bitmap (from manifest binary
    /// byte 15). Gates privileged 0x0Cxx opcodes by category — see the
    /// `permission` module in `syscalls.rs`. Separate from `required_caps`
    /// so non-contract permissions don't overload the contract bitmask.
    permissions: [u8; MAX_MODULES],
    /// Per-module instance-params blob pointer + length. Populated
    /// by platform loaders that have access to the source bytes —
    /// the wasm loader uses this so modules can fetch their own
    /// params via the `MODULE_INSTANCE_PARAMS` provider_query opcode
    /// across the kernel/module memory split. Native PIC loaders pass
    /// params directly to `module_new` and leave these null.
    module_params_ptr: [*const u8; MAX_MODULES],
    module_params_len: [usize; MAX_MODULES],
    /// Per-module mailbox_safe flag (header flags bit 0): can consume from mailbox
    mailbox_safe: [bool; MAX_MODULES],
    /// Per-module in_place_writer flag (header flags bit 1): uses acquire_inplace
    in_place_writer: [bool; MAX_MODULES],
    /// Per-module deferred ready flag (header flags bit 2)
    deferred_ready: [bool; MAX_MODULES],
    /// Per-module ready flag (true = outputs meaningful, false = still initializing)
    ready: [bool; MAX_MODULES],
    /// Per-module upstream dependency bitmask (precomputed from edges)
    upstream_mask: [u64; MAX_MODULES],
    /// Per-module step period in scheduler ticks (0 = every tick, N =
    /// step every N ticks). Wall-clock period is
    /// `step_period * domain_tick_us` — units are ticks, NOT
    /// milliseconds. Sourced from the module header's
    /// `step_period_ticks` byte.
    step_period: [u8; MAX_MODULES],
    /// Per-module step counter (counts ticks toward period)
    step_counter: [u8; MAX_MODULES],
    /// Topological execution order (Kahn's algorithm output)
    exec_order: [u8; MAX_MODULES],
    /// Number of entries in exec_order
    exec_order_count: usize,
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
    domain_budget_us_limit: [u32; MAX_DOMAINS],
    /// Per-domain microseconds consumed in the *current* step pass.
    /// Reset at the top of `step_modules` / `step_domain_modules` /
    /// `step_domain_modules_poll`; accumulated after every
    /// `step_one_module` return regardless of `StepOutcome`.
    domain_budget_us_consumed: [u64; MAX_DOMAINS],
    /// Cumulative count of times the domain's pass was cut short
    /// because `consumed > limit`. Surfaced via `monitor` so operators
    /// see chronically over-subscribed domains without needing to
    /// instrument modules individually.
    domain_budget_overruns: [u32; MAX_DOMAINS],

    // ── Live Reconfigure State ──────────────────────────────────────
    /// Current reconfigure phase, queryable via `reconfigure_phase()`.
    reconfigure_phase: ReconfigurePhase,
    /// Number of modules in the current graph, set by `prepare_graph`.
    active_module_count: usize,
    /// Pending rebuild request (config_ptr, len). Set by `request_rebuild`,
    /// consumed by the per-platform main loop, which performs a destructive
    /// reset + reload.
    rebuild_request: Option<(*const u8, usize)>,

    // ── Per-module export table info (for resolve_export_for_module) ──
    /// Code base address per module (for resolving export offsets)
    module_code_base: [usize; MAX_MODULES],
    /// Code size per module (for provider pointer validation)
    module_code_size: [u32; MAX_MODULES],
    /// Export table pointer per module
    module_export_table: [*const u8; MAX_MODULES],
    /// Export count per module
    module_export_count: [u16; MAX_MODULES],

    // ── Step timing histogram (8 log2 buckets) ─────────────────────
    /// Per-module bucket counts: <64us, <128, <256, <512, <1024, <2048, <4096, >=4096
    step_hist: [[u32; 8]; MAX_MODULES],
    /// Global bucket counts across all modules.
    step_hist_global: [u32; 8],
}

impl SchedulerState {
    const fn new() -> Self {
        Self {
            edges: [Edge::simple(0, 0); MAX_CHANNELS],
            edge_count: 0,
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
            ready: [true; MAX_MODULES],
            upstream_mask: [0; MAX_MODULES],
            step_period: [0; MAX_MODULES],
            step_counter: [0; MAX_MODULES],
            exec_order: [0; MAX_MODULES],
            exec_order_count: 0,
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
            domain_budget_us_limit: [0; MAX_DOMAINS],
            domain_budget_us_consumed: [0; MAX_DOMAINS],
            domain_budget_overruns: [0; MAX_DOMAINS],
            reconfigure_phase: ReconfigurePhase::Running,
            active_module_count: 0,
            rebuild_request: None,
            module_code_base: [0; MAX_MODULES],
            module_code_size: [0; MAX_MODULES],
            module_export_table: [core::ptr::null(); MAX_MODULES],
            module_export_count: [0; MAX_MODULES],
            step_hist: [[0; 8]; MAX_MODULES],
            step_hist_global: [0; 8],
        }
    }

    /// Reset all runtime state for a new graph setup.
    /// Does NOT reset state arena or name arena (separate concerns).
    fn reset(&mut self) {
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
            self.ready[i] = true;
            self.upstream_mask[i] = 0;
            self.step_period[i] = 0;
            self.step_counter[i] = 0;
            self.module_latency[i] = 0;
            self.downstream_latency[i] = 0;
            self.fault_info[i] = ModuleFaultInfo::new();
            self.module_code_base[i] = 0;
            self.module_code_size[i] = 0;
            self.module_export_table[i] = core::ptr::null();
            self.module_export_count[i] = 0;
            self.step_hist[i] = [0; 8];
        }
        self.step_hist_global = [0; 8];
        self.exec_order_count = 0;
        self.graph_sample_rate = 0;
        self.tick_us = 0;
        self.domain_count = 0;
        for d in 0..MAX_DOMAINS {
            self.domain_module_count[d] = 0;
            self.domain_tick_us[d] = 0;
            self.domain_budget_us_limit[d] = 0;
            self.domain_budget_us_consumed[d] = 0;
            self.domain_budget_overruns[d] = 0;
        }
        self.reconfigure_phase = ReconfigurePhase::Running;
        self.active_module_count = 0;
        self.rebuild_request = None;
    }
}

static mut SCHED: SchedulerState = SchedulerState::new();

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
    let core = crate::kernel::hal::core_id();
    CURRENT_MODULE_PER_CORE[core].load(portable_atomic::Ordering::Relaxed) as usize
}

/// Set the current module index. Used by provider dispatch for context switching.
pub fn set_current_module(idx: usize) {
    let core = crate::kernel::hal::core_id();
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
    unsafe {
        INSTANTIATION_STATE = state;
        INSTANTIATION_IDX = idx;
    }
}

/// Clear the instantiation state pointer (called after module_new).
pub fn clear_instantiation_state() {
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
    unsafe {
        MODULE_STATE_PTR[idx] = state;
    }
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
    unsafe { SCHED.cap_class[idx] }
}

/// Return the required_caps bitmask of the module currently being stepped.
/// Bit N set = module declared it needs contract id N in its manifest.
/// Contract bits only — internal-orchestration permission is in
/// `current_module_internal_permission`.
pub fn current_module_required_caps() -> u32 {
    let idx = current_module_index();
    unsafe { SCHED.required_caps[idx] }
}

/// Return the fine-grained permission bitmap of the module currently
/// being stepped. Each bit corresponds to a privileged-opcode category
/// — see the `permission` module in `syscalls.rs`.
pub fn current_module_permissions() -> u8 {
    let idx = current_module_index();
    unsafe { SCHED.permissions[idx] }
}

/// Return the export table info for a module by index.
/// Used by loader::resolve_export_for_module to resolve export hashes.
pub fn get_module_exports(idx: usize) -> (usize, *const u8, u16) {
    if idx >= MAX_MODULES {
        return (0, core::ptr::null(), 0);
    }
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
    unsafe { (SCHED.module_code_base[idx], SCHED.module_code_size[idx]) }
}

/// Set the capability class, required_caps, and permissions bitmap for
/// a module (used by the Linux / bcm2712 platform loaders when they
/// stage modules from their embedded images).
pub fn set_module_caps(idx: usize, cap_class: u8, required_caps: u32, permissions: u8) {
    if idx >= MAX_MODULES {
        return;
    }
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
    unsafe { (SCHED.module_params_ptr[idx], SCHED.module_params_len[idx]) }
}

/// Store a BuiltInModule in the scheduler's module table (used by Linux platform).
pub fn store_builtin_module(idx: usize, m: BuiltInModule) {
    if idx >= MAX_MODULES {
        return;
    }
    unsafe {
        SCHED.modules[idx] = ModuleSlot::BuiltIn(m);
        SCHED.ready[idx] = true;
    }
}

/// Store a DynamicModule in the scheduler's module table (used by Linux platform).
pub fn store_dynamic_module(idx: usize, dm: DynamicModule) {
    if idx >= MAX_MODULES {
        return;
    }
    unsafe {
        SCHED.modules[idx] = ModuleSlot::Dynamic(dm);
    }
}

/// Return the graph-level sample rate (0 = not configured).
pub fn graph_sample_rate() -> u32 {
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
    let cfg = unsafe {
        let p = &raw const STATIC_CONFIG;
        &*p
    };
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
    unsafe {
        SCHED.graph_sample_rate = rate;
    }
}

/// Return the configured tick period in microseconds.
pub fn tick_us() -> u32 {
    let t = unsafe { SCHED.tick_us };
    if t == 0 {
        DEFAULT_TICK_US
    } else {
        t
    }
}

/// Return the configured tick period for a specific domain.
/// Falls back to global tick_us if domain has no override.
pub fn domain_tick_us(domain_id: usize) -> u32 {
    if domain_id < MAX_DOMAINS {
        let t = unsafe { SCHED.domain_tick_us[domain_id] };
        if t > 0 {
            return t;
        }
    }
    tick_us()
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
}

/// Return the execution mode for a domain. See [`exec_mode`] for the
/// stable byte→tier mapping.
pub fn domain_exec_mode(domain_id: usize) -> u8 {
    if domain_id < MAX_DOMAINS {
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
    let d = unsafe { SCHED.domain_id[module_idx] } as usize;
    if d >= MAX_DOMAINS {
        return false;
    }
    let m = unsafe { SCHED.domain_exec_mode[d] };
    is_isr_tier_exec_mode(m)
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
    unsafe {
        SCHED.domain_exec_mode[domain_id] = exec_mode;
    }
}

/// Return the number of configured domains.
pub fn domain_count() -> usize {
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
    let count = unsafe { SCHED.domain_module_count[domain_id] as usize };
    if i >= count {
        return None;
    }
    Some(unsafe { SCHED.domain_exec_order[domain_id][i] as usize })
}

/// Return the domain id assigned to a module, or `0` (the default
/// domain) for out-of-range indices.
pub fn module_domain_id(module_idx: usize) -> u8 {
    if module_idx >= MAX_MODULES {
        return 0;
    }
    unsafe { SCHED.domain_id[module_idx] }
}

/// Report a module's processing latency in frames.
/// Called by modules during init via the REPORT_LATENCY kernel primitive.
pub fn report_module_latency(module_idx: usize, frames: u32) {
    if module_idx < MAX_MODULES {
        unsafe {
            SCHED.module_latency[module_idx] = frames;
        }
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

/// Bucket index for a step elapsed time in microseconds.
/// 0: <64, 1: <128, 2: <256, 3: <512, 4: <1024, 5: <2048, 6: <4096, 7: >=4096
#[inline]
fn step_bucket(elapsed_us: u32) -> usize {
    if elapsed_us < 64 {
        0
    } else if elapsed_us < 128 {
        1
    } else if elapsed_us < 256 {
        2
    } else if elapsed_us < 512 {
        3
    } else if elapsed_us < 1024 {
        4
    } else if elapsed_us < 2048 {
        5
    } else if elapsed_us < 4096 {
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
        unsafe {
            (&raw const SCHED.step_hist)
                .cast::<[u32; 8]>()
                .add(module_idx)
        }
    } else {
        return crate::kernel::errno::EINVAL;
    };
    for i in 0..8 {
        let v = unsafe { (*hist_ptr)[i] };
        let bytes = v.to_le_bytes();
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
    unsafe {
        SCHED.fault_info[module_idx].step_deadline_us = deadline_us;
    }
}

/// Set per-module step period (every N ticks). `0` = step every tick.
/// Used by the loader's manifest-driven setup and by conformance tests
/// that exercise the period-gating path in `step_one_module`.
pub fn set_module_step_period(module_idx: usize, period: u8) {
    if module_idx >= MAX_MODULES {
        return;
    }
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
    unsafe { SCHED.fault_info[module_idx].state }
}

/// Read `finished[module_idx]`. Test-facing query for terminate /
/// done assertions.
pub fn module_finished(module_idx: usize) -> bool {
    if module_idx >= MAX_MODULES {
        return false;
    }
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
    unsafe {
        SCHED.ready[module_idx] = false;
    }
}

/// Read the per-module ready bit.
pub fn module_is_ready(module_idx: usize) -> bool {
    if module_idx >= MAX_MODULES {
        return false;
    }
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
    pub permissions: u8,
    /// Per-module fault state machine state.
    pub fault_state: FaultState,
    /// Step-period gate in scheduler ticks (0 = every tick, N = every
    /// N ticks). Wall-clock period is `step_period * domain_tick_us`.
    pub step_period: u8,
    /// Restart count to date.
    pub restart_count: u16,
    /// Domain the module is assigned to (0 = default).
    pub domain_id: u8,
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
        };
    }
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
    }
}

/// Lookup a channel port for the currently-executing module.
/// Called from the channel_port syscall implementation.
pub fn channel_port_lookup(port_type: u8, index: u8) -> i32 {
    let idx = index as usize;
    let cm = current_module_index();
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

// ============================================================================
// Setup Functions
// ============================================================================

/// Synchronous setup - returns true if ready to run, false on error
///
/// Call this first, then call run_main_loop() if it returns true.
pub fn setup(runner_config: &RunnerConfig) -> bool {
    let loader = unsafe {
        let p = &raw mut STATIC_LOADER;
        &mut *p
    };
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
    let config = unsafe {
        let p = &raw const STATIC_CONFIG;
        &*p
    };
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

    log::info!("[graph] modules={} edges={}", declared_modules, edge_count);

    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };

    // Reset all scheduler state, state arena, and name arena.
    //
    // also wipe channel slots and buffer registry slots
    // so a previous graph's claims don't accumulate. Before this, the
    // bump-allocator-only `reset_buffer_arena` and per-channel
    // `channel_close` left slot metadata in `Allocated` state across
    // reconfigures — each reconfigure ate slots that `try_allocate`
    // then skipped, eventually exhausting `MAX_CHANNELS` / `MAX_BUFFER_SLOTS`
    // even with otherwise well-sized graphs.
    reset_state_arena();
    crate::kernel::channel::reset_all();
    crate::kernel::buffer_pool::reset_all();
    crate::kernel::buffer_pool::reset_buffer_arena();
    NameArena::reset();
    crate::kernel::backing_provider::unregister();
    crate::kernel::provider::reset_handle_tracking();
    sched.reset();

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

    // Store per-module domain assignments and infer domain count
    let mut max_domain: u8 = 0;
    for entry in config.modules.iter().flatten() {
        let id = entry.id as usize;
        if id < MAX_MODULES {
            sched.domain_id[id] = entry.domain_id;
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
            edges[i] = e;
        } else {
            log::error!("[graph] edge {} missing", i);
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

    // Query channel hints and open channels
    collect_module_hints(loader, &module_list, module_count);
    if open_channels(&mut edges[..runtime_edge_count]) < 0 {
        log::error!("[graph] channel open failed");
        return Err(-1);
    }

    // validate buffer-group constraints
    // uniformly across every platform. Previously this was wired only
    // from `src/platform/rp.rs`; Linux / WASM / BCM platforms skipped
    // the check, so graphs that pinned two in-place writers into the
    // same buffer group ran with undefined producer ownership on
    // those platforms. The function runs after `collect_module_hints`
    // (which populates `in_place_writer`) and `open_channels` (which
    // sets `edge.channel >= 0` for the live edges).
    if !validate_buffer_groups(&edges[..runtime_edge_count]) {
        log::error!("[graph] buffer group validation failed");
        return Err(crate::kernel::errno::EINVAL);
    }

    // Register each module's channel-buffer range with the MPU/MMU so an
    // isolated module sees only its own buffers through region 6.
    for i in 0..module_count {
        let (base, size) = crate::kernel::buffer_pool::compute_module_buffer_range(i as u8);
        if size > 0 {
            crate::kernel::mpu::set_channel_region(i, base as u32, size as u32);
            #[cfg(feature = "chip-bcm2712")]
            crate::kernel::mmu::set_channel_region(i, base as u64, size as u64);
        }
    }

    // Compute topological execution order.
    //
    // A graph with cycles is normally rejected here: previously
    // `prepare_graph` discarded the cycle count via `_cycle_count`
    // and ran the best-effort topological prefix plus the cyclic
    // remainder, which produced a *different* graph than the
    // author declared. Typed feedback edges with explicit buffering
    // will get their own ABI shape; until then a cycle is malformed
    // by default and must be regenerated.
    //
    // **Opt-in escape hatch** (`graph_flags & ACCEPT_CYCLES`): the
    // config blob's graph-section flags byte can carry an explicit
    // author attestation that any cycles are bidirectional feedback
    // pairs (canonically `http <-> linux_net` in any linux http
    // example). When the flag is set, cycle members are appended to
    // exec_order in declaration order — the same best-effort
    // behaviour the old code had — and a loud `log::warn!` line is
    // emitted so the choice is visible in operator output.
    //
    // See `.context/rfc_deployment_scenarios.md` §13 "Known issue
    // blocking PR 3 end-to-end" for the design discussion.
    let cycle_count = compute_exec_order(edges, runtime_edge_count, module_count);
    if cycle_count > 0 {
        let accept = (config.graph_flags
            & crate::kernel::config::GRAPH_FLAG_ACCEPT_CYCLES)
            != 0;
        if !accept {
            log::error!(
                "[graph] {} module(s) involved in cycles — graph rejected. \
                 Set `scheduler: {{ accept_cycles: true }}` in the graph YAML \
                 if these cycles are bidirectional feedback pairs.",
                cycle_count
            );
            return Err(crate::kernel::errno::EINVAL);
        }
        log::warn!(
            "[graph] accepting {} cycle module(s) under graph_flags.ACCEPT_CYCLES \
             — stepping order within the cycle is best-effort, declaration order.",
            cycle_count
        );
    }

    // Compute upstream dependency masks for ready-signal gating
    compute_upstream_mask(edges, runtime_edge_count);

    // Partition modules by domain (E4-S4) and validate (E4-S5)
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
            log::error!("[graph] port limit exceeded for module {}", module_idx);
            return Err(-1);
        }
    }

    Ok((module_list, module_count))
}

/// Emit a one-line `[arena]` summary covering each kernel arena's
/// used/cap byte counts. Each platform calls this once after its
/// instantiation loop completes, so STATE_ARENA reflects every
/// `alloc_state` call (BUFFER and CONFIG arenas are filled earlier,
/// by `open_channels` and `populate_static_state` respectively).
pub fn log_arena_summary() {
    let (state_used, state_cap) = crate::kernel::loader::state_arena_usage();
    let (cfg_used, cfg_cap) = crate::kernel::config::config_arena_usage();
    let (buf_used, buf_cap) = crate::kernel::buffer_pool::buffer_arena_usage();
    log::info!(
        "[arena] state={}/{} cfg={}/{} buf={}/{}",
        state_used,
        state_cap,
        cfg_used,
        cfg_cap,
        buf_used,
        buf_cap
    );
}

// Async graph setup (setup_graph_async) and run_main_loop are in
// src/platform/rp.rs — they use embassy async/await which is RP-only.
// Sync variants (setup_graph_sync, run_main_loop_sync) are in
// src/platform/bcm2712.rs.

// ============================================================================
// Module Instantiation
// ============================================================================

/// Internal module hashes (fnv1a32)
pub const INTERNAL_TEE_HASH: u32 = 0x607f045c; // "_tee"
pub const INTERNAL_MERGE_HASH: u32 = 0x8a6bcd3e; // "_merge"

/// Build the dense module list from the validated config.
///
/// Fail-closed on every malformation:
///   * Modules with `id >= MAX_MODULES` → `Err(EINVAL)`.
///   * Duplicate ids → `Err(EINVAL)`.
///   * Modules exceeding the per-graph `MAX_MODULES` ceiling →
///     `Err(EINVAL)`.
///
/// The error code is the bare `i32` negative-errno that
/// `prepare_graph` already propagates.
type ModuleList = ([Option<ModuleEntry>; MAX_MODULES], usize, [i8; MAX_MODULES]);

fn build_module_list(config: &Config) -> Result<ModuleList, i32> {
    let mut module_list: [Option<ModuleEntry>; MAX_MODULES] = [None; MAX_MODULES];
    let mut id_to_slot: [i8; MAX_MODULES] = [-1; MAX_MODULES];
    let mut count = 0;

    for entry in config.modules.iter().flatten() {
        if count >= MAX_MODULES {
            log::error!(
                "[graph] module count exceeds MAX_MODULES={} — graph rejected",
                MAX_MODULES
            );
            return Err(crate::kernel::errno::EINVAL);
        }

        let id = entry.id as usize;
        if id >= MAX_MODULES {
            log::error!(
                "[graph] module id={} out of range (MAX_MODULES={}) — graph rejected",
                entry.id,
                MAX_MODULES
            );
            return Err(crate::kernel::errno::EINVAL);
        }

        if id_to_slot[id] >= 0 {
            log::error!(
                "[graph] duplicate module id={} — graph rejected",
                entry.id
            );
            return Err(crate::kernel::errno::EINVAL);
        }

        id_to_slot[id] = count as i8;
        module_list[count] = Some(*entry);
        count += 1;
    }

    Ok((module_list, count, id_to_slot))
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
    let module_hints = unsafe {
        let p = &raw mut SCHED;
        &mut (*p).hints
    };

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
            let p = &raw mut SCHED;
            let sched = &mut *p;
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
    domain_id: u8,
    frame_kind: u8,
) -> Option<usize> {
    if *module_count >= MAX_MODULES {
        log::error!("No room for internal module");
        return None;
    }

    let idx = *module_count;
    module_list[idx] = Some(ModuleEntry {
        name_hash,
        id: idx as u8,
        domain_id,
        frame_kind,
        params_ptr: core::ptr::null(),
        params_len: 0,
    });
    // Mirror the domain assignment into SCHED so the per-domain
    // exec-order partitioner sees the inserted slot.
    if idx < MAX_MODULES {
        let sched = unsafe {
            let p = &raw mut SCHED;
            &mut *p
        };
        sched.domain_id[idx] = domain_id;
    }
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

/// Map a port's manifest `content_type` byte to a `FRAME_KIND_*`
/// discriminant. Auto-inserted tee/merge fans must not split frames
/// mid-payload — the consumer parser would read the body tail as a
/// bogus header — so when this returns a non-NONE kind the fan
/// switches to frame-aware transfer (peek length, drain full frame,
/// write atomically to all outputs).
pub fn port_frame_kind_from_content_type(content_type: u8) -> u8 {
    use module_types::{
        CONTENT_TYPE_ETHERNET_FRAME, CONTENT_TYPE_NET_PROTO, FRAME_KIND_ETH, FRAME_KIND_NET,
        FRAME_KIND_NONE,
    };
    match content_type {
        CONTENT_TYPE_ETHERNET_FRAME => FRAME_KIND_ETH,
        CONTENT_TYPE_NET_PROTO => FRAME_KIND_NET,
        _ => FRAME_KIND_NONE,
    }
}

/// Convert a `FanDirection` + ctrl bit into the manifest direction
/// byte (0=input, 1=output, 2=ctrl_input). Mirrors the encoding
/// produced by the manifest packer in `tools/src/manifest.rs`.
fn manifest_direction_byte(dir: FanDirection, port_key: u8) -> u8 {
    match dir {
        FanDirection::Out => 1,
        FanDirection::In => {
            if (port_key & 0x10) != 0 {
                2
            } else {
                0
            }
        }
    }
}

/// Look up a module's port content_type by its `name_hash`. Returns
/// `FRAME_KIND_NONE` when the module isn't in the loader table (host
/// built-in without a packed manifest) or the manifest doesn't
/// describe a port at the requested direction+index.
fn fanned_port_frame_kind(
    loader: &ModuleLoader,
    name_hash: u32,
    dir: FanDirection,
    port_key: u8,
) -> u8 {
    use module_types::FRAME_KIND_NONE;
    let direction_byte = manifest_direction_byte(dir, port_key);
    let index = port_key & 0x0F;
    if let Ok(module) = loader.find_by_name_hash(name_hash) {
        if let Some(ct) = module.port_content_type(direction_byte, index) {
            return port_frame_kind_from_content_type(ct);
        }
    }
    FRAME_KIND_NONE
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
    loader: &ModuleLoader,
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
        for (i, edge) in edges.iter().take(*edge_count).enumerate() {
            if edge_matches_module(edge, module_idx, direction) && match_count < MAX_CHANNELS {
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
                if !processed[j] && edge_port_key(&edges[matching[j]], direction) == port_key {
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
            for &ei in group.iter().take(group_count) {
                if edges[ei].buffer_group != 0 {
                    log::error!(
                        "[graph] fan module={} buffer_group={} cleared (incompatible)",
                        module_idx,
                        edges[ei].buffer_group
                    );
                    edges[ei].buffer_group = 0;
                }
            }

            // Insert tee/merge module for this port group
            if *edge_count + 1 > MAX_CHANNELS {
                log::error!("[graph] channel limit for {} module={}", name, entry_id);
                return false;
            }

            // The tee/merge inherits the fanned-on module's domain so
            // it runs in the same pump as the fan group it serves.
            let (fan_domain, fan_name_hash) = match &module_list[module_idx] {
                Some(e) => (e.domain_id, e.name_hash),
                None => (0, 0),
            };
            // Detect the fanned port's wire format from the module's
            // manifest content_type. If the fanned module is a host
            // built-in (no manifest), fall back to checking any peer's
            // manifest across the fan — both ends of an edge must
            // declare a compatible content_type, so peer-side gives
            // the same answer.
            let mut fan_kind = fanned_port_frame_kind(loader, fan_name_hash, direction, port_key);
            if fan_kind == module_types::FRAME_KIND_NONE {
                for k in 0..group_count {
                    let edge = &edges[group[k]];
                    let (peer_idx, peer_dir, peer_port_key) = match direction {
                        FanDirection::Out => (
                            edge.to_module,
                            FanDirection::In,
                            if edge.is_ctrl() { 0x10 } else { 0x00 } | edge.to_port_index,
                        ),
                        FanDirection::In => {
                            (edge.from_module, FanDirection::Out, edge.from_port_index)
                        }
                    };
                    let peer_hash = match &module_list[peer_idx] {
                        Some(e) => e.name_hash,
                        None => continue,
                    };
                    let peer_kind =
                        fanned_port_frame_kind(loader, peer_hash, peer_dir, peer_port_key);
                    if peer_kind != module_types::FRAME_KIND_NONE {
                        fan_kind = peer_kind;
                        break;
                    }
                }
            }
            let fan_idx = match push_internal_module(
                module_list,
                module_count,
                internal_hash,
                fan_domain,
                fan_kind,
            ) {
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
                FanDirection::In => {
                    let mut e = Edge::simple(fan_idx, module_idx);
                    e.to_port_index = port_key;
                    e
                }
            };
            edges[*edge_count] = new_edge;
            *edge_count += 1;

            // Rewire group edges to go through the fan module. The
            // port indices on the rewritten edges must repack from 0
            // (one slot per fanned consumer/producer) because the
            // tee/merge module has only a single logical input/output
            // port — `collect_channels` places channels at
            // `from_port_index` / `to_port_index`, and if the original
            // edges all carried the same source-side port index (e.g.
            // every fan-out edge inheriting peer_router.raft_rpc's
            // index 3) they would land in the same slot and overwrite,
            // leaving the tee/merge with `out_chans[0..k] = -1` so its
            // poll loop bails before it does any work.
            for k in 0..group_count {
                match direction {
                    FanDirection::Out => {
                        edges[group[k]].from_module = fan_idx;
                        edges[group[k]].from_port_index = k as u8;
                    }
                    FanDirection::In => {
                        edges[group[k]].to_module = fan_idx;
                        edges[group[k]].to_port_index = k as u8;
                    }
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
    loader: &ModuleLoader,
) -> bool {
    insert_fan(
        FanDirection::Out,
        edges,
        edge_count,
        module_list,
        module_count,
        loader,
    )
}

fn insert_fan_in(
    edges: &mut [Edge; MAX_CHANNELS],
    edge_count: &mut usize,
    module_list: &mut [Option<ModuleEntry>; MAX_MODULES],
    module_count: &mut usize,
    loader: &ModuleLoader,
) -> bool {
    insert_fan(
        FanDirection::In,
        edges,
        edge_count,
        module_list,
        module_count,
        loader,
    )
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

/// Populate a module's port table from the compiled `sched.edges`.
///
/// Reads every edge touching `module_idx` and writes the resulting
/// in/out/ctrl channel handles into `sched.ports[instantiated]`.
/// Returns `false` if the module has more than `MAX_PORTS` channels in
/// any direction (a config error).
///
/// Used by platform setup paths that don't go through
/// `instantiate_one_module` — e.g. hosted built-ins that aren't in the
/// loader.
pub fn populate_module_ports_from_edges(module_idx: usize, instantiated: usize) -> bool {
    if module_idx >= MAX_MODULES || instantiated >= MAX_MODULES {
        return false;
    }
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };
    let mut in_chans = [-1i32; MAX_CHANNELS];
    let mut out_chans = [-1i32; MAX_CHANNELS];
    let mut ctrl_chans = [-1i32; MAX_CHANNELS];
    let in_count = collect_input_channels(&sched.edges, module_idx, &mut in_chans);
    let out_count = collect_output_channels(&sched.edges, module_idx, &mut out_chans);
    let ctrl_count = collect_ctrl_channels(&sched.edges, module_idx, &mut ctrl_chans);
    populate_ports(
        &mut sched.ports[instantiated],
        &in_chans,
        in_count,
        &out_chans,
        out_count,
        &ctrl_chans,
        ctrl_count,
    )
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
        log::error!(
            "[inst] output port limit out={} max={}",
            out_count,
            MAX_PORTS
        );
        return false;
    }
    if ctrl_count > MAX_PORTS {
        log::error!(
            "[inst] ctrl port limit ctrl={} max={}",
            ctrl_count,
            MAX_PORTS
        );
        return false;
    }
    ports.in_count = in_count as u8;
    ports.out_count = out_count as u8;
    ports.ctrl_count = ctrl_count as u8;
    let mut i = 0;
    while i < in_count {
        ports.in_chans[i] = in_chans[i];
        i += 1;
    }
    i = 0;
    while i < out_count {
        ports.out_chans[i] = out_chans[i];
        i += 1;
    }
    i = 0;
    while i < ctrl_count {
        ports.ctrl_chans[i] = ctrl_chans[i];
        i += 1;
    }
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
    if !populate_ports(
        ports,
        &in_chans,
        in_count,
        &out_chans,
        out_count,
        &ctrl_chans,
        ctrl_count,
    ) {
        log::error!("[inst] module={} port limit exceeded", entry.id);
        return InstantiateResult::Error(-1);
    }

    if entry.name_hash == INTERNAL_TEE_HASH {
        if in_count != 1 || out_count == 0 {
            log::error!("[inst] tee module={} invalid ports", entry.id);
            return InstantiateResult::Error(-1);
        }
        // Clamp to keep the index within `FAN_BUFS` even if an
        // out-of-range `domain_id` slips past
        // `compute_domain_exec_orders_static`.
        let domain = (entry.domain_id as usize).min(MAX_DOMAINS - 1) as u8;
        modules[instantiated] = ModuleSlot::Tee(TeeModule::new(
            in_chans[0],
            &out_chans,
            out_count,
            domain,
            entry.frame_kind,
        ));
        return InstantiateResult::Done;
    } else if entry.name_hash == INTERNAL_MERGE_HASH {
        if out_count != 1 || in_count == 0 {
            log::error!("[inst] merge module={} invalid ports", entry.id);
            return InstantiateResult::Error(-1);
        }
        let domain = (entry.domain_id as usize).min(MAX_DOMAINS - 1) as u8;
        modules[instantiated] = ModuleSlot::Merge(MergeModule::new(
            &in_chans,
            in_count,
            out_chans[0],
            domain,
            entry.frame_kind,
        ));
        return InstantiateResult::Done;
    }

    // Loader lookup
    let found_module = match loader.find_by_name_hash(entry.name_hash) {
        Ok(m) => m,
        Err(e) => {
            e.log("loader");
            return InstantiateResult::Error(-1);
        }
    };
    let name = found_module.name_str();
    let static_name = NameArena::intern(name);

    // Select capability-filtered syscall table based on module type
    let syscalls = get_table_for_module_type(found_module.header.module_type);

    // Record capability class and manifest metadata for enforcement
    unsafe {
        let p = &raw mut SCHED;
        let sched = &mut *p;
        sched.cap_class[instantiated] = match found_module.header.module_type {
            5 => 3, // Protocol → CAP_FULL
            3 => 1, // Sink → CAP_SERVICE_PIO
            4 => 2, // EventHandler → CAP_SERVICE_GPIO
            _ => 0, // Source, Transformer → CAP_SERVICE
        };
        sched.required_caps[instantiated] = found_module.header.required_caps();
        sched.permissions[instantiated] = found_module.manifest_permissions();
        // Store export table info for resolve_export_for_module
        sched.module_code_base[instantiated] = found_module.code_base() as usize;
        sched.module_code_size[instantiated] = found_module.header.code_size;
        sched.module_export_table[instantiated] = found_module.export_table_ptr();
        sched.module_export_count[instantiated] = found_module.header.export_count;
        let flags_byte = found_module.header.reserved[0];
        sched.mailbox_safe[instantiated] = (flags_byte & 0x01) != 0;
        sched.in_place_writer[instantiated] = (flags_byte & 0x02) != 0;
        let deferred = (flags_byte & 0x04) != 0;
        sched.deferred_ready[instantiated] = deferred;
        if deferred {
            sched.ready[instantiated] = false;
        }
    }

    // Check for optional module_arena_size export and allocate if present
    unsafe {
        let p = &raw mut SCHED;
        let sched = &mut *p;
        let arenas = &mut sched.arenas;
        arenas[instantiated] = ArenaInfo::empty();
        if let Ok(addr) =
            found_module.get_export_addr(crate::kernel::loader::export_hashes::MODULE_ARENA_SIZE)
        {
            let arena_size_fn: unsafe extern "C" fn() -> u32 = core::mem::transmute(addr);
            let requested = arena_size_fn() as usize;
            if requested > 0 {
                match crate::kernel::loader::alloc_state(requested) {
                    Ok(ptr) => {
                        arenas[instantiated] = ArenaInfo {
                            ptr,
                            size: requested as u32,
                        };
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

    // Full instantiation via start_new.
    // Set current module index so any syscall made from inside
    // module_new() can identify the calling module (state pointer,
    // heap, required_caps, loader-driven provider registration).
    set_current_module(instantiated);
    let result = unsafe {
        let pb = core::ptr::addr_of!(PARAM_BUFFER);
        DynamicModule::start_new(
            &found_module,
            syscalls,
            crate::kernel::loader::ChannelHandles {
                in_chan,
                out_chan,
                ctrl_chan,
            },
            crate::kernel::loader::ParamSlice {
                ptr: (*pb).as_ptr(),
                len: (*pb).len(),
            },
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
                SCHED.step_period[instantiated] = found_module.header.step_period_ticks();
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
        SCHED.step_period[instantiated] = found_module.header.step_period_ticks();
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
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };
    for slot in sched.upstream_mask.iter_mut() {
        *slot = 0;
    }
    for edge in edges.iter().take(edge_count) {
        let from = edge.from_module;
        let to = edge.to_module;
        if from < MAX_MODULES && to < MAX_MODULES {
            sched.upstream_mask[to] |= 1u64 << from;
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
fn compute_exec_order(edges: &[Edge], edge_count: usize, module_count: usize) -> usize {
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
    // Surface the cycle through both a loud log line (so it shows up in any
    // host runtime's output) and a non-zero return value (so `prepare_graph`
    // can decide between reject / accept-with-warning). Isolated modules
    // never reach this branch — their `in_degree == 0` makes them BFS roots.
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
        log::error!(
            "[scheduler] graph has {} module(s) in a cycle (first unordered idx={}); \
             v1 has no typed feedback edges — cycles are appended at the end in \
             declaration order, and `prepare_graph` decides whether to accept or \
             reject the resulting graph based on `graph_flags.ACCEPT_CYCLES`",
            cycle_count,
            first_unordered,
        );
    }

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
fn compute_domain_exec_orders_static(_module_count: usize) {
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };

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
    let effective_domains = if sched.domain_count > 0 {
        sched.domain_count as usize
    } else {
        1
    };
    for d in 0..effective_domains {
        let count = sched.domain_module_count[d];
        if count > 0 || d == 0 {
            let tick = if sched.domain_tick_us[d] > 0 {
                sched.domain_tick_us[d]
            } else {
                sched.tick_us
            };
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
///
/// Log every edge tagged `EdgeClass::DmaOwned` at graph-prepare time.
///
/// Pure observability for now: confirms that the YAML-level annotation
/// reached the scheduler edge table. The scheduler does NOT yet issue
/// cache maintenance on DmaOwned handoffs — that work lands with zero-
/// copy mailbox edges, where the payload buffer is actually shared
/// between producer and consumer. Streaming-arena buffers live inside
/// the module (see nvme `write_bufs[]`) and do their own DC CVAC via
/// the `DMA_FLUSH` syscall before device submission.
pub fn log_dma_owned_edges(edge_count: usize) {
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
        if let crate::kernel::config::EdgeClass::DmaOwned = e.edge_class {
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
        log::info!(
            "[sched] {} DmaOwned edges declared (maintenance deferred)",
            n
        );
    }
}

/// Same intent as `log_dma_owned_edges`, but walks the config's edge
/// table directly. Used by the bcm2712 graph setup path, which owns
/// module/edge instantiation itself and never populates `sched.edges`.
pub fn log_dma_owned_edges_from_config(edges: &[Option<crate::kernel::config::GraphEdge>]) {
    let mut n = 0usize;
    for edge in edges.iter().flatten() {
        if let crate::kernel::config::EdgeClass::DmaOwned = edge.edge_class {
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
        log::info!(
            "[sched] {} DmaOwned edges declared (maintenance deferred)",
            n
        );
    }
}

fn validate_domains_static(module_count: usize, edge_count: usize) {
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
            log::warn!("[domain] domain {} is empty (no modules assigned)", d);
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
        if let crate::kernel::config::EdgeClass::CrossCore = e.edge_class {
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
                "[domain] domain {} has {} modules with tick_us={} — may exceed tick budget",
                d,
                count,
                domain_tick
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

/// Finalize a module after it reports done or error.
///
/// Sets POLL_HUP (done) or POLL_ERR (error) on all output channels,
/// releases owned handles, and marks the module finished.
/// `error_code`: None = module done normally, Some(rc) = error with return code.
fn finalize_module(module_idx: usize, error_code: Option<i32>, type_name: &str, context: &str) {
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };

    let flag = if error_code.is_some() {
        POLL_ERR as u8
    } else {
        POLL_HUP as u8
    }; // u8: sticky_events is AtomicU8
    if let Some(rc) = error_code {
        log::warn!(
            "[sched] module {} ({}) error rc={}{}",
            module_idx,
            type_name,
            rc,
            context
        );
    } else {
        log::info!(
            "[sched] module {} ({}) done{}",
            module_idx,
            type_name,
            context
        );
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

/// Wallclock-paced scheduler heartbeat. Platforms call this once per
/// tick from their outer loop; this is the single canonical emit
/// point for `[sched] alive` across linux / wasm / rp / bcm — the
/// per-platform and step_modules-internal copies that used to live
/// here have all been collapsed into this function.
///
/// Cadence: every 30 wallclock seconds at the active `tick_us` for
/// the given domain (or the global `tick_us` for the default domain
/// / single-domain platforms). `hal::now_millis()` provides the
/// `elapsed_ms` suffix — every supported platform's HAL implements
/// it.
///
/// `domain_id == None` is the flat / single-domain case (linux,
/// wasm, rp, qemu): no `domain=` field is emitted. `Some(d)` is the
/// multi-domain case (bcm2712): the field is appended so per-core
/// logs are distinguishable.
pub fn maybe_emit_alive(tick: u64, domain_id: Option<usize>) {
    if tick == 0 {
        return;
    }
    let d = domain_id.unwrap_or(0);
    let tick_us = domain_tick_us(d).max(1) as u64;
    let period = (30_000_000u64 / tick_us).max(1);
    if !tick.is_multiple_of(period) {
        return;
    }
    let ms = crate::kernel::hal::now_millis();
    match domain_id {
        Some(d) => log::info!("[sched] alive t={} elapsed_ms={} domain={}", tick, ms, d),
        None => log::info!("[sched] alive t={} elapsed_ms={}", tick, ms),
    }
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

    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };
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
                    params[pos],
                    params[pos + 1],
                    params[pos + 2],
                    params[pos + 3],
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
                fi.max_restarts = u16::from_le_bytes([params[pos], params[pos + 1]]);
            }
            0xF3 if len == 2 => {
                // restart_backoff_ms (u16 LE)
                fi.restart_backoff_ms = u16::from_le_bytes([params[pos], params[pos + 1]]);
            }
            0xF4 if len == 1 => {
                // trust_tier: 0=platform, 1=verified, 2=community, 3=unsigned.
                // Signature verification happens in the loader; this tag only
                // surfaces the outcome for telemetry.
                if params[pos] == 3 {
                    log::warn!("[trust] module {} is unsigned", module_idx);
                }
            }
            0xF5 if len == 1 => {
                // protection: 0=none, 1=guarded, 2=isolated.
                // An isolated module opts the whole graph into MPU isolation;
                // per-module MPU regions are registered during instantiation.
                if params[pos] >= 2 {
                    crate::kernel::mpu::set_enabled(true);
                }
            }
            _ => {}
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
    log::warn!(
        "[guard] module {} ({}) step timeout (fault #{})",
        module_idx,
        modules[module_idx].type_name(),
        fi.fault_count
    );
    step_guard::push_fault(FaultRecord {
        module_idx: module_idx as u8,
        fault_kind: fault_type::TIMEOUT,
        _reserved: 0,
        tick,
        fault_count: fi.fault_count,
        restart_count: fi.restart_count,
    });

    if fi.can_restart() {
        fi.state = FaultState::Faulted;
        fi.backoff_remaining = fi.restart_backoff_ms as u32;
    } else {
        fi.state = FaultState::Terminated;
        finalize_module(
            module_idx,
            Some(-110),
            modules[module_idx].type_name(),
            " (timeout terminated)",
        );
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
    step_guard::push_fault(FaultRecord {
        module_idx: module_idx as u8,
        fault_kind: fault_type::STEP_ERROR,
        _reserved: 0,
        tick,
        fault_count: fi.fault_count,
        restart_count: fi.restart_count,
    });

    if fi.can_restart() {
        fi.state = FaultState::Faulted;
        fi.backoff_remaining = fi.restart_backoff_ms as u32;
        log::warn!(
            "[guard] module {} ({}) error rc={} — will restart (fault #{})",
            module_idx,
            modules[module_idx].type_name(),
            rc,
            fi.fault_count
        );
    } else {
        fi.state = FaultState::Terminated;
        finalize_module(
            module_idx,
            Some(rc),
            modules[module_idx].type_name(),
            context,
        );
        *active_count -= 1;
    }
}

/// Handle an MPU/MMU protection fault: record, emit event, transition state.
fn handle_mpu_fault(
    sched: &mut SchedulerState,
    modules: &mut [ModuleSlot; MAX_MODULES],
    module_idx: usize,
    active_count: &mut usize,
) {
    let tick = unsafe { DBG_TICK };
    let fi = &mut sched.fault_info[module_idx];
    fi.record_fault(fault_type::MPU_FAULT, tick);
    log::warn!(
        "[mpu] module {} ({}) protection fault (fault #{})",
        module_idx,
        modules[module_idx].type_name(),
        fi.fault_count
    );
    step_guard::push_fault(FaultRecord {
        module_idx: module_idx as u8,
        fault_kind: fault_type::MPU_FAULT,
        _reserved: 0,
        tick,
        fault_count: fi.fault_count,
        restart_count: fi.restart_count,
    });

    if fi.can_restart() {
        fi.state = FaultState::Faulted;
        fi.backoff_remaining = fi.restart_backoff_ms as u32;
    } else {
        fi.state = FaultState::Terminated;
        finalize_module(
            module_idx,
            Some(-14),
            modules[module_idx].type_name(),
            " (mpu terminated)",
        );
        *active_count -= 1;
    }
}

/// Attempt to restart a faulted module.
///
/// **v1 partial-restart contract**:
///
/// 1. `syscalls::release_module_handles` releases events, timers, DMA, and
///    tracked provider handles owned by the module.
/// 2. Every connected channel (in / out / ctrl) is `IOCTL_FLUSH`'d.
/// 3. If the module was `deferred_ready`, its ready bit is reset.
/// 4. Fault state moves back to `Running`; `finished[idx]` is cleared.
///
/// What is **not** done in v1, and would be needed for a full restart:
///   - State memory is **not** zeroed — the module observes whatever state
///     it had when it faulted. Safe for stateless / idempotent modules.
///   - `module_new()` is **not** re-called. Stored params + loader state to
///     drive a fresh init aren't plumbed through the restart path yet.
///   - Channel ioctl handlers registered by the module are **not** cleared.
///     Today this matches behaviour (no `module_new` re-call means no
///     re-register), but a full restart implementation must clear them
///     before re-init to avoid stale handler pointers.
///
/// Modules whose invariants do not survive "saw faulted state and got
/// re-stepped" should use `FaultPolicy::Skip` and rely on the operator to
/// drain+reload via the reconfigure module
/// (`.context/rfc_graph_reconfigure.md`).
fn handle_module_restart(
    sched: &mut SchedulerState,
    modules: &mut [ModuleSlot; MAX_MODULES],
    module_idx: usize,
) {
    sched.fault_info[module_idx].state = FaultState::Recovering;
    sched.fault_info[module_idx].restart_count += 1;
    log::info!(
        "[guard] restarting module {} ({}) (restart #{})",
        module_idx,
        modules[module_idx].type_name(),
        sched.fault_info[module_idx].restart_count
    );

    // Release owned handles (events, timers, DMA, providers, etc.)
    syscalls::release_module_handles(module_idx as u8);

    // Drain/flush all connected channels (both in and out)
    let ports = &sched.ports[module_idx];
    for i in 0..ports.in_count as usize {
        if ports.in_chans[i] >= 0 {
            channel::channel_ioctl(
                ports.in_chans[i],
                channel::IOCTL_FLUSH,
                core::ptr::null_mut(),
            );
        }
    }
    for i in 0..ports.out_count as usize {
        if ports.out_chans[i] >= 0 {
            channel::channel_ioctl(
                ports.out_chans[i],
                channel::IOCTL_FLUSH,
                core::ptr::null_mut(),
            );
        }
    }
    for i in 0..ports.ctrl_count as usize {
        if ports.ctrl_chans[i] >= 0 {
            channel::channel_ioctl(
                ports.ctrl_chans[i],
                channel::IOCTL_FLUSH,
                core::ptr::null_mut(),
            );
        }
    }

    // **v1 partial-restart**: state is intentionally NOT zeroed — the
    // `DynamicModule` doesn't carry its `state_size`, and zeroing a
    // conservative range could overrun adjacent module state in the
    // shared arena. The module will see whatever state it had at fault
    // time; this matches the docstring above. Full restart (state zero
    // + `module_new` re-call) needs stored params and loader state
    // plumbed through this path. Modules that can't safely
    // resume from faulted state must opt out of `Restart` (use `Skip`).
    let _ = &modules[module_idx];

    // Reset ready signal if module was deferred_ready
    if sched.deferred_ready[module_idx] {
        sched.ready[module_idx] = false;
    }

    // Mark as running again
    sched.fault_info[module_idx].state = FaultState::Running;
    sched.finished[module_idx] = false;
}

pub fn step_modules(modules: &mut [ModuleSlot; MAX_MODULES], count: usize) -> StepResult {
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };
    let tick = unsafe { DBG_TICK };
    unsafe {
        DBG_TICK += 1;
    }

    // Crash-info one-shot: at first opportunity after boot, check the
    // .uninit CRASH_DATA RAM that a HardFault handler may have left
    // behind from the previous run, and clear the marker so it
    // doesn't repeat. Tick threshold chosen so USB serial is
    // definitely connected (≈ first scheduler-heartbeat slot at the
    // active tick rate). The `[sched] alive` log itself is emitted
    // by the platform's outer loop via `maybe_emit_alive`.
    let crash_check_tick = (30_000_000u32 / sched.tick_us.max(1)).max(1);
    if tick == crash_check_tick {
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
                log::error!(
                    "[crash] pc={:08x} lr={:08x} r0={:08x} mod={} t={}",
                    pc,
                    lr,
                    r0,
                    module,
                    prev_tick
                );
                log::error!("[crash] cfsr={:08x} bfar={:08x}", cfsr, bfar);
                core::ptr::write_volatile((&raw mut CRASH_DATA) as *mut u32, 0);
            }
        }
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
    let mut not_ready: u64 = 0;
    for i in 0..count {
        if !sched.ready[i] {
            not_ready |= 1u64 << i;
        }
    }

    // Reset the per-pass budget accumulator for **every** domain
    // before this pass starts. The flat path used to reset only
    // `domain_budget_us_consumed[0]` and check only domain 0
    // after each module — but `step_one_module` charges elapsed
    // time to the module's *actual* `domain_id`, so modules
    // assigned to non-default domains (multi-domain configs on a
    // flat target — currently rare but architecturally legal)
    // had their step-time accumulating into a bucket nobody
    // checked. Resetting every domain + checking the stepped
    // module's own domain closes the gap.
    for d in 0..MAX_DOMAINS {
        sched.domain_budget_us_consumed[d] = 0;
    }

    // Step modules in topological order so producers run before consumers.
    // The per-module step body is in `step_one_module` so the upcoming
    // domain-scoped `step_domain_modules` reuses the exact
    // same semantics — see `.context/scheduler_domain_api.md`.
    let exec_count = sched.exec_order_count;
    let n = if exec_count > 0 { exec_count } else { count };
    for order_pos in 0..n {
        let module_idx = if exec_count > 0 {
            sched.exec_order[order_pos] as usize
        } else {
            order_pos
        };
        if module_idx >= count {
            continue;
        }
        step_one_module(modules, sched, module_idx, not_ready, &mut active_count, false);

        // Check the budget of the domain the *just-stepped*
        // module belongs to — not always domain 0. Two reasons to
        // break the iteration on overrun: (1) any further work
        // this pass is past-budget by definition, (2) the loop is
        // single-threaded; we can't keep stepping other domains
        // while breaking just one. Operators see one overrun per
        // pass on the offending domain — same UX as the
        // domain-scoped step path.
        let stepped_domain = sched.domain_id[module_idx] as usize;
        if stepped_domain < MAX_DOMAINS && domain_budget_exhausted(sched, stepped_domain) {
            record_domain_budget_overrun(sched, stepped_domain, module_idx);
            break;
        }
    }

    if active_count == 0 {
        StepResult::Done
    } else {
        StepResult::Continue
    }
}

/// Step every module assigned to `domain_id` in the per-domain
/// topological order. Multi-domain counterpart to [`step_modules`];
/// both share the same per-module body (`step_one_module`) so semantics
/// match exactly — step-period gating, ready-signal gating, fault
/// transitions, `StepOutcome::{Continue, Ready, Done, Burst}`,
/// step-guard arm/disarm, step-time recording.
///
/// Returns `StepResult::Done` when every active module across the
/// whole graph is finalised (the active_count is global to v1; see
/// `.context/scheduler_domain_api.md` §4). Sibling domains can keep
/// stepping independently; callers should decide global shutdown
/// based on every domain returning `Done`.
///
/// `domain_id` >= `MAX_DOMAINS` returns `StepResult::Done` immediately
/// (no-op, no error). The caller should guarantee this never happens —
/// `multicore::MAX_DOMAINS` already caps assignment.
///
/// Set inside `step_one_module` whenever a module returns `Burst` from
/// `m.step()`, and read by the Tier 3 poll-mode wrapper
/// (`step_domain_modules_poll`) to decide whether the domain has more
/// work pending or can WFE. Each `step_domain_modules_poll` call
/// clears the flag before the pass.
static BURST_SEEN_THIS_PASS: AtomicBool = AtomicBool::new(false);

/// Variant of [`step_domain_modules`] for platforms running a
/// continuous-poll execution tier (e.g. BCM2712 Tier 3): runs one full
/// pass through the domain's modules via the shared `step_one_module`
/// body, then returns `(StepResult, burst_seen)` where `burst_seen`
/// indicates whether any module returned `StepOutcome::Burst` during
/// the pass. Poll-mode callers use that bit to decide whether to spin
/// (more work pending) or WFE (idle).
pub fn step_domain_modules_poll(
    modules: &mut [ModuleSlot; MAX_MODULES],
    domain_id: usize,
) -> (StepResult, bool) {
    BURST_SEEN_THIS_PASS.store(false, Ordering::Relaxed);
    let result = step_domain_modules(modules, domain_id);
    let burst = BURST_SEEN_THIS_PASS.swap(false, Ordering::Relaxed);
    (result, burst)
}

/// Has the given domain consumed more than its tick budget in the
/// current pass? Called between modules in `step_modules` /
/// `step_domain_modules` to enforce the per-domain budget; returns
/// `true` once the cumulative `m.step()` wall-clock for this pass
/// exceeds `domain_budget_us_limit`. A `limit == 0` disables the
/// check (no budget configured — e.g. host-test or pre-`prepare_graph`
/// callers).
#[inline]
fn domain_budget_exhausted(sched: &SchedulerState, domain_id: usize) -> bool {
    if domain_id >= MAX_DOMAINS {
        return false;
    }
    let limit = sched.domain_budget_us_limit[domain_id] as u64;
    if limit == 0 {
        return false;
    }
    sched.domain_budget_us_consumed[domain_id] > limit
}

/// Record a per-domain budget-overrun event: increment the counter
/// and emit a `MON_BUDGET_OVERRUN` log line over the same monitor
/// transport the fault ring uses. Reusing the existing transport
/// means operators see budget overruns alongside faults without a
/// second pipe to subscribe to. `last_module_idx` names the module
/// whose step closed the pass over budget, for triage — it isn't
/// faulted (its `StepOutcome` was honoured), it's just the last
/// observable step before the overrun fired.
fn record_domain_budget_overrun(
    sched: &mut SchedulerState,
    domain_id: usize,
    last_module_idx: usize,
) {
    sched.domain_budget_overruns[domain_id] =
        sched.domain_budget_overruns[domain_id].saturating_add(1);
    log::warn!(
        "MON_BUDGET_OVERRUN domain={} consumed_us={} limit_us={} \
         last_mod={} overrun_count={} tick={}",
        domain_id,
        sched.domain_budget_us_consumed[domain_id],
        sched.domain_budget_us_limit[domain_id],
        last_module_idx,
        sched.domain_budget_overruns[domain_id],
        unsafe { DBG_TICK },
    );
}

/// Diagnostic accessor — total budget-overrun count for `domain_id`
/// since boot. Returns 0 for invalid `domain_id`.
pub fn domain_budget_overruns(domain_id: usize) -> u32 {
    if domain_id >= MAX_DOMAINS {
        return 0;
    }
    unsafe { SCHED.domain_budget_overruns[domain_id] }
}

/// Diagnostic accessor — microseconds consumed by `domain_id` in the
/// most recent pass. Reset at the top of every pass; reading after
/// the pass returns the cumulative time. Returns 0 for invalid
/// `domain_id`.
pub fn domain_budget_us_consumed(domain_id: usize) -> u64 {
    if domain_id >= MAX_DOMAINS {
        return 0;
    }
    unsafe { SCHED.domain_budget_us_consumed[domain_id] }
}

/// Test-facing setter — overrides the budget limit for a domain
/// without going through `prepare_graph`. Conformance tests use this
/// to plant a tight budget against a controllable workload. Passing
/// `limit_us == 0` disables enforcement.
pub fn set_domain_budget_us_limit(domain_id: usize, limit_us: u32) {
    if domain_id >= MAX_DOMAINS {
        return;
    }
    unsafe {
        SCHED.domain_budget_us_limit[domain_id] = limit_us;
    }
}

pub fn step_domain_modules(
    modules: &mut [ModuleSlot; MAX_MODULES],
    domain_id: usize,
) -> StepResult {
    if domain_id >= MAX_DOMAINS {
        return StepResult::Done;
    }
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };

    // Recompute active_count and not_ready once per tick (cheap; same
    // as `step_modules`). active_count is global; a domain-only count
    // would need per-domain `finished[]` tracking// per the design memo.
    let count = sched.active_module_count;
    let mut active_count: usize = 0;
    for i in 0..count {
        if !sched.finished[i] {
            active_count += 1;
        }
    }
    let mut not_ready: u64 = 0;
    for i in 0..count {
        if !sched.ready[i] {
            not_ready |= 1u64 << i;
        }
    }

    // Reset the per-pass budget accumulator before stepping any
    // modules. `step_one_module` adds elapsed wall-clock here; the
    // loop below cuts off if the domain overshoots its tick.
    sched.domain_budget_us_consumed[domain_id] = 0;

    let n = sched.domain_module_count[domain_id] as usize;
    for pos in 0..n {
        let module_idx = sched.domain_exec_order[domain_id][pos] as usize;
        if module_idx >= count {
            continue;
        }
        step_one_module(modules, sched, module_idx, not_ready, &mut active_count, false);

        // Per-domain budget enforcement: if cumulative step time has
        // exceeded the domain's tick budget, log + count + skip the
        // remaining modules this pass. They'll get their turn on the
        // next pass when the accumulator resets. This is what keeps
        // a misconfigured Tier 3 domain (or a sibling-starving
        // burst) from monopolising a core indefinitely on aarch64
        // where the step guard is advisory.
        if domain_budget_exhausted(sched, domain_id) {
            record_domain_budget_overrun(sched, domain_id, module_idx);
            break;
        }
    }

    if active_count == 0 {
        StepResult::Done
    } else {
        StepResult::Continue
    }
}

/// Per-module step body shared between `step_modules` (flat,
/// single-domain), `step_domain_modules` (per-domain), and
/// `step_woken_modules` (event wake). Encapsulates the full
/// `StepOutcome` handling — period gating, ready gating, fault state
/// machine, burst loop, finalisation — so every caller gets identical
/// semantics. See `.context/scheduler_domain_api.md` for the full
/// design.
///
/// `event_wake = true` bypasses step-period gating (an event overrides
/// the per-module period) but keeps every other invariant: upstream-
/// ready gating, fault transitions, step-time recording, step-guard
/// arm/disarm, stack-canary check, and burst MPU-fault handling all
/// fire identically. `active_count` is decremented on finalisation.
///
/// Caller passes its current `active_count`; this function decrements
/// it when a module finalises (Done / terminate / fault-without-restart).
#[inline]
fn step_one_module(
    modules: &mut [ModuleSlot; MAX_MODULES],
    sched: &mut SchedulerState,
    module_idx: usize,
    not_ready: u64,
    active_count: &mut usize,
    event_wake: bool,
) {
    // Skip already finished modules
    if sched.finished[module_idx] {
        return;
    }

    // Skip ISR-tier modules. Tier 1b (`exec_mode == 2`) and Tier 2
    // (`exec_mode == 4`) modules run from a timer-ISR or hardware IRQ
    // handler — not from the cooperative `step_modules` loop. Stepping
    // them here would double-execute their work (once cooperatively
    // and once from the ISR) and would also break the ISR-only
    // assumption that no `provider_call`/heap-allocation is on the
    // call stack at module entry. The build-time validator in
    // `tools/src/config.rs::validate_isr_tier_admission` already
    // rejects ISR-tier modules without the `isr_safe` flag; the
    // runtime skip here is defense in depth for hand-rolled binaries.
    let domain = sched.domain_id[module_idx] as usize;
    if domain < MAX_DOMAINS && is_isr_tier_exec_mode(sched.domain_exec_mode[domain]) {
        return;
    }

    // Step frequency gating: skip if counter hasn't reached period.
    // `step_period` is measured in scheduler ticks (NOT milliseconds);
    // wall-clock cadence is `step_period * domain_tick_us`.
    // Event-wake bypasses the period — the event is the trigger.
    if !event_wake {
        let period = sched.step_period[module_idx];
        if period > 0 {
            sched.step_counter[module_idx] = sched.step_counter[module_idx].wrapping_add(1);
            if sched.step_counter[module_idx] < period {
                return;
            }
            sched.step_counter[module_idx] = 0;
        }
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
        return;
    }

    // Skip faulted/terminated modules
    let fault_state = sched.fault_info[module_idx].state;
    if fault_state == FaultState::Faulted {
        // Check if backoff has elapsed → attempt restart
        if sched.fault_info[module_idx].backoff_remaining > 0 {
            sched.fault_info[module_idx].backoff_remaining -= 1;
            return;
        }
        if sched.fault_info[module_idx].can_restart() {
            handle_module_restart(sched, modules, module_idx);
            // After restart attempt, skip this tick (module will run next tick)
            return;
        } else {
            // Cannot restart — terminate
            sched.fault_info[module_idx].state = FaultState::Terminated;
            finalize_module(
                module_idx,
                Some(-110),
                modules[module_idx].type_name(),
                " (terminated)",
            );
            *active_count -= 1;
            return;
        }
    } else if fault_state == FaultState::Terminated || fault_state == FaultState::Recovering {
        return;
    }

    if let Some(m) = modules[module_idx].as_module_mut() {
        // Set current_module so channel_port works during module_step
        set_current_module(module_idx);
        // Track for HardFault diagnosis
        unsafe {
            core::ptr::write_volatile(&raw mut DBG_STEP_MODULE, module_idx as u8);
        }

        // Arm step guard timer
        let deadline = sched.fault_info[module_idx].effective_deadline_us();
        step_guard::arm(deadline);
        let step_t0 = crate::kernel::hal::now_micros();
        // `module_t0` is the *whole-step* wall-clock anchor for the
        // per-domain budget accumulator. Distinct from `step_t0`
        // (which the Continue arm uses to record per-module step
        // time) because Burst's re-step loop should count toward the
        // domain budget too — every iteration of the loop is real
        // wall-clock the domain owes.
        let module_t0 = step_t0;

        match m.step() {
            Ok(StepOutcome::Continue) => {
                step_guard::disarm();
                let elapsed = (crate::kernel::hal::now_micros() - step_t0) as u32;
                record_step_time(module_idx, elapsed);
                step_guard::post_step_check();
                if step_guard::check_and_clear_timeout() {
                    handle_step_timeout(sched, modules, module_idx, active_count);
                }
                if step_guard::check_and_clear_mpu_fault() {
                    handle_mpu_fault(sched, modules, module_idx, active_count);
                }
                // PSP stack overflow detection: the canary word at the
                // bottom of the module stack is clobbered by an overflow.
                // Re-arm it so the next module starts with a clean band.
                if !crate::kernel::mpu::check_stack_canary() {
                    log::error!("[mpu] module {} stack canary violated", module_idx);
                    crate::kernel::mpu::reinit_stack_canary();
                    handle_mpu_fault(sched, modules, module_idx, active_count);
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
                *active_count -= 1;
            }
            Ok(StepOutcome::Burst) => {
                // Record that this pass saw a Burst — poll-mode callers
                // (`step_domain_modules_poll`) read this to decide
                // whether to spin or WFE.
                BURST_SEEN_THIS_PASS.store(true, Ordering::Relaxed);
                // Keep timer armed for entire burst with extended deadline
                step_guard::disarm();
                let burst_deadline = deadline.saturating_mul(step_guard::BURST_MULTIPLIER);
                step_guard::arm(burst_deadline);

                for _ in 0..MAX_BURST_STEPS {
                    // Check timeout between burst iterations
                    if step_guard::is_timed_out() {
                        step_guard::disarm();
                        step_guard::check_and_clear_timeout();
                        handle_step_timeout(sched, modules, module_idx, active_count);
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
                                finalize_module(
                                    module_idx,
                                    None,
                                    modules[module_idx].type_name(),
                                    " (burst)",
                                );
                                *active_count -= 1;
                                break;
                            }
                            Err(rc) => {
                                handle_step_error(
                                    sched,
                                    modules,
                                    module_idx,
                                    rc,
                                    active_count,
                                    " (burst)",
                                );
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
                    handle_step_timeout(sched, modules, module_idx, active_count);
                }
                if step_guard::check_and_clear_mpu_fault() {
                    handle_mpu_fault(sched, modules, module_idx, active_count);
                }
            }
            Err(rc) => {
                step_guard::disarm();
                handle_step_error(sched, modules, module_idx, rc, active_count, "");
                if step_guard::check_and_clear_mpu_fault() {
                    handle_mpu_fault(sched, modules, module_idx, active_count);
                }
            }
        }

        // Accumulate wall-clock spent on this module (any outcome,
        // including Burst loops and faults) into the owning domain's
        // budget. The accumulator is reset by the caller at the top
        // of each pass; the per-domain pass loop checks the limit
        // after this function returns and breaks the iteration if
        // exceeded. now_micros uses the same monotonic source as
        // step_t0, so wraparound matches step-time recording.
        let elapsed = crate::kernel::hal::now_micros().wrapping_sub(module_t0);
        let d = sched.domain_id[module_idx] as usize;
        if d < MAX_DOMAINS {
            sched.domain_budget_us_consumed[d] =
                sched.domain_budget_us_consumed[d].saturating_add(elapsed);
        }
    }
}

/// Step only modules whose bit is set in `wake_bits`. Walks the
/// topological execution order so producer modules still run before
/// their consumers within a single wake pass, then delegates each
/// per-module step to `step_one_module` with `event_wake = true`.
/// Event-wake bypasses step-period gating but inherits every other
/// scheduler invariant — upstream-ready gating, fault state machine,
/// step-time recording, step-guard arm/disarm, stack-canary check,
/// burst MPU-fault handling — from the shared body.
pub fn step_woken_modules(modules: &mut [ModuleSlot; MAX_MODULES], count: usize, wake_bits: u64) {
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };

    // Compute current readiness mask once per wake pass, matching the
    // flat/domain stepping paths.
    let mut not_ready: u64 = 0;
    for i in 0..count {
        if !sched.ready[i] {
            not_ready |= 1u64 << i;
        }
    }
    let mut active_count: usize = 0;
    for i in 0..count {
        if !sched.finished[i] {
            active_count += 1;
        }
    }

    let exec_count = sched.exec_order_count;
    let n = if exec_count > 0 { exec_count } else { count };
    for order_pos in 0..n {
        let module_idx = if exec_count > 0 {
            sched.exec_order[order_pos] as usize
        } else {
            order_pos
        };
        if module_idx >= count {
            continue;
        }
        if (wake_bits & (1u64 << module_idx)) == 0 {
            continue;
        }
        step_one_module(modules, sched, module_idx, not_ready, &mut active_count, true);
    }
}

// ============================================================================
// Live Reconfigure — Kernel Primitives
// ============================================================================
//
// Raw primitives exposed to the `modules/reconfigure` PIC module via the
// `dev_system` reconfigure opcodes (0x0C67–0x0C6F).

/// Return the current reconfigure phase.
pub fn reconfigure_phase() -> ReconfigurePhase {
    unsafe { SCHED.reconfigure_phase }
}

/// Set the current reconfigure phase.
pub fn set_reconfigure_phase(phase: ReconfigurePhase) {
    unsafe {
        SCHED.reconfigure_phase = phase;
    }
}

/// Return the number of active modules in the current graph.
pub fn active_module_count() -> usize {
    unsafe { SCHED.active_module_count }
}

/// Return the number of modules currently in `exec_order` (the
/// topologically-sorted list `step_modules` iterates). Exposed so tests
/// and diagnostics can confirm `prepare_graph` populated it. Equals
/// `active_module_count` after a clean graph prepare; >0 once any module
/// has been ordered.
pub fn exec_order_count() -> usize {
    unsafe { SCHED.exec_order_count }
}

/// Platform hook: set the active module count. Called by platforms whose
/// graph-setup path doesn't go through `prepare_graph` (e.g. the bcm2712
/// domain-based instantiator) but which still want queries like
/// `RECONFIGURE_MODULE_COUNT` to report the right value.
pub fn set_active_module_count(n: usize) {
    unsafe {
        SCHED.active_module_count = n;
    }
}

/// Invoke `module_drain()` on module N. Returns the module's return code,
/// or -1 if the module is not drain-capable or the index is invalid.
pub fn call_module_drain(module_idx: usize) -> i32 {
    if module_idx >= MAX_MODULES {
        return -1;
    }
    let sched = unsafe {
        let p = &raw const SCHED;
        &*p
    };
    if let ModuleSlot::Dynamic(ref m) = sched.modules[module_idx] {
        set_current_module(module_idx);
        unsafe { m.call_drain() }
    } else {
        -1
    }
}

/// Mark a module as finished so the scheduler skips it in future ticks.
pub fn mark_module_finished(module_idx: usize) {
    if module_idx < MAX_MODULES {
        unsafe {
            let p = &raw mut SCHED;
            (*p).finished[module_idx] = true;
        }
    }
}

/// Raise a fault against module `idx` with the given `fault_kind`
/// (see `step_guard::fault_type`). Updates the module's fault bookkeeping
/// and pushes a record to the global fault ring so subscribers (monitor
/// CLI, metrics sinks) observe it uniformly with step-guard / MPU faults.
pub fn raise_module_fault(module_idx: usize, fault_kind: u8) {
    if module_idx >= MAX_MODULES {
        return;
    }
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };
    let tick = unsafe { DBG_TICK };
    sched.fault_info[module_idx].record_fault(fault_kind, tick);
    let fi = &sched.fault_info[module_idx];
    step_guard::push_fault(FaultRecord {
        module_idx: module_idx as u8,
        fault_kind,
        _reserved: 0,
        tick,
        fault_count: fi.fault_count,
        restart_count: fi.restart_count,
    });
}

/// Module capability flag bitmask:
///   bit 0: drain_capable (module exports module_drain)
///   bit 1: deferred_ready
///   bit 2: mailbox_safe
///   bit 3: in_place_writer
pub fn module_info_flags(module_idx: usize) -> u32 {
    if module_idx >= MAX_MODULES {
        return 0;
    }
    let sched = unsafe {
        let p = &raw const SCHED;
        &*p
    };
    let mut flags: u32 = 0;
    if let ModuleSlot::Dynamic(ref m) = sched.modules[module_idx] {
        if m.has_drain() {
            flags |= 0x01;
        }
    }
    if sched.deferred_ready[module_idx] {
        flags |= 0x02;
    }
    if sched.mailbox_safe[module_idx] {
        flags |= 0x04;
    }
    if sched.in_place_writer[module_idx] {
        flags |= 0x08;
    }
    flags
}

/// Upstream-module bitmask for module N.
pub fn module_upstream_mask(module_idx: usize) -> u64 {
    if module_idx >= MAX_MODULES {
        return 0;
    }
    unsafe { SCHED.upstream_mask[module_idx] }
}

/// Whether module N has returned StepOutcome::Done.
pub fn module_is_finished(module_idx: usize) -> bool {
    if module_idx >= MAX_MODULES {
        return false;
    }
    unsafe { SCHED.finished[module_idx] }
}

/// Request a graph rebuild. The per-platform main loop consumes the request
/// after `step_modules` returns.
///
/// # Safety
/// The caller must ensure `config_ptr..config_ptr+config_len` remains valid
/// until the main loop consumes the request. A null pointer with zero length
/// signals "reload current STATIC_CONFIG".
pub unsafe fn request_rebuild(config_ptr: *const u8, config_len: usize) {
    unsafe {
        let p = &raw mut SCHED;
        (*p).rebuild_request = Some((config_ptr, config_len));
    }
}

/// Consume the pending rebuild request, if any.
pub fn take_rebuild_request() -> Option<(*const u8, usize)> {
    unsafe {
        let p = &raw mut SCHED;
        (*p).rebuild_request.take()
    }
}

/// Tear down a single module: release its module heap arena, then its
/// state buffer, back to the loader pool. Clears the slot, port
/// assignments, hints, drain flags, and finished state so the slot can
/// be reused.
///
/// Intended for use by the graph-rebuild path when only some modules
/// need to be replaced. Not called by the atomic reconfigure path,
/// which uses `reset_state_arena` to drop everything at once.
pub fn free_module_state(module_idx: usize) {
    if module_idx >= MAX_MODULES {
        return;
    }
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };

    // Heap arena (from module_arena_size export, if any).
    let arena = sched.arenas[module_idx];
    if !arena.ptr.is_null() && arena.size > 0 {
        unsafe {
            crate::kernel::loader::free_state_range(arena.ptr, arena.size as usize);
        }
    }
    sched.arenas[module_idx] = ArenaInfo::empty();

    // State buffer lives inside the DynamicModule; consume the slot.
    let slot = core::mem::replace(&mut sched.modules[module_idx], ModuleSlot::Empty);
    if let ModuleSlot::Dynamic(m) = slot {
        unsafe {
            m.free();
        }
    }

    // Reset per-module scheduler bookkeeping so reuse is clean.
    sched.ports[module_idx] = ModulePorts::empty();
    sched.hints[module_idx] = ModuleHints::empty();
    sched.finished[module_idx] = false;
    sched.ready[module_idx] = true;
    sched.deferred_ready[module_idx] = false;
    sched.mailbox_safe[module_idx] = false;
    sched.in_place_writer[module_idx] = false;
    sched.upstream_mask[module_idx] = 0;
    sched.step_period[module_idx] = 0;
    sched.step_counter[module_idx] = 0;
    sched.module_code_base[module_idx] = 0;
    sched.module_code_size[module_idx] = 0;
    sched.module_export_table[module_idx] = core::ptr::null();
    sched.module_export_count[module_idx] = 0;
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
        // Producer reads `channel`; consumer reads `consumer_channel`
        // when a platform bridge has split the edge, otherwise `channel`.
        let chan_for_side = match direction {
            FanDirection::Out => edge.channel,
            FanDirection::In => {
                if edge.consumer_channel >= 0 {
                    edge.consumer_channel
                } else {
                    edge.channel
                }
            }
        };
        if chan_for_side >= 0 && matches {
            // Place at port index if it fits, otherwise append
            let port_idx = match direction {
                FanDirection::Out => edge.from_port_index as usize,
                FanDirection::In => edge.to_port_index as usize,
            };
            if port_idx < out.len() && out[port_idx] == -1 {
                out[port_idx] = chan_for_side;
                if port_idx >= count {
                    count = port_idx + 1;
                }
            } else if count < out.len() {
                out[count] = chan_for_side;
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

/// Pair of (module name, step function) for `run_builtin_graph`.
pub type BuiltinModuleEntry = (&'static str, fn(*mut u8) -> i32);

/// Manually insert built-in modules and run the scheduler loop.
/// Used on platforms without flash/PIC (e.g. aarch64 QEMU).
///
/// `modules`: array of (name, step_fn) pairs. Channels between them are
/// created automatically: module[0].out → module[1].in → module[1].out → ...
pub fn run_builtin_graph(modules: &[BuiltinModuleEntry]) -> ! {
    let count = modules.len().min(MAX_MODULES);
    let sched = unsafe {
        let p = &raw mut SCHED;
        &mut *p
    };

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
        // `wfi` halts the core until an interrupt; only valid on Arm
        // bare-metal targets. On wasm32 the host drives ticks
        // externally via `kernel_step()`, so this loop is unreachable
        // there — gate the asm so wasm32 compiles cleanly.
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        unsafe {
            core::arch::asm!("wfi"); // Wait for timer tick
        }
        #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
        core::hint::spin_loop();

        unsafe {
            DBG_TICK += 1;
        }
        let tick = unsafe { DBG_TICK };

        step_modules(&mut sched.modules, count);

        // Check event wake
        let wake = crate::kernel::event::take_wake_pending();
        if wake != 0 {
            step_woken_modules(&mut sched.modules, count, wake);
        }

        // Built-in-graph platforms (qemu / rp) don't have a separate
        // outer-loop heartbeat module; emit through the canonical
        // helper so cadence + message shape matches every other
        // platform.
        maybe_emit_alive(tick as u64, None);
    }
}
