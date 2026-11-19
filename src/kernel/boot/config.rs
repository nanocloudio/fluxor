//! The boot configuration: where the platform maps it, and the `Config` the
//! kernel fills from it.
//!
//! The blob's format and its one codec are `fluxor_contracts::boot_config`
//! (FXCF): a checksummed header and tagged sections, decoded without
//! allocating. This module locates the blob in the window the platform maps,
//! hands it to the codec, bounds what the codec returns by this kernel's
//! capacity profile, and fills `Config`. A blob the codec refuses, or one
//! that asks for more than the profile holds, is refused whole: nothing of it
//! is applied.
//!
//! ## Concurrency
//!
//! The parsed `Config` is written by `populate_static_state` on core 0 at
//! boot (and at a rebuild, with every other core parked), then read by every
//! core. Module params and resident workloads are not copied out of the blob:
//! each `ModuleEntry` borrows its params in place, and `Config::workloads`
//! reads the blob's `WKLD` section where it lies, so the config blob stays
//! mapped for as long as the `Config` that points into it (every platform
//! keeps it mapped for the life of the kernel). See
//! `docs/architecture/concurrency.md`.
//!
//! ## Graph image
//!
//! The graph a kernel boots is a graph image (`abi::wire::graph_image`): a
//! 256-byte header, the module table and the config, admitted by
//! `boot::graph_image::admit` before anything in it is read. A firmware image
//! carries one after the kernel, its header on the first 256-byte boundary
//! past the kernel's file-backed end:
//!
//! ```text
//! [kernel]
//! [graph image header, 256 bytes]
//! [module table, 4 KiB aligned]
//! [config, 256-byte aligned]
//! ```
//!
//! An RP board boots the graph of one of its flash A/B slots when it has an
//! admissible one (`platform::planner::choose_slot`). A Linux runtime is handed
//! its image as a file and admits it itself; wasm embeds its blobs.

use fluxor_contracts::boot_config::{self, BootConfig, Workloads};

// ============================================================================
// GPIO pin configuration (the HAL's `init_gpio` input)
// ============================================================================

/// GPIO direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GpioDirection {
    Input = 0,
    Output = 1,
}

/// GPIO initial level (for outputs)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GpioLevel {
    Low = 0,
    High = 1,
}

/// GPIO pull configuration (for inputs)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GpioPull {
    None = 0,
    Up = 1,
    Down = 2,
}

/// GPIO pin configuration
#[derive(Debug, Clone, Copy)]
pub struct GpioConfig {
    /// Pin number
    pub pin: u8,
    /// Direction (input or output)
    pub direction: GpioDirection,
    /// Pull configuration (for inputs)
    pub pull: GpioPull,
    /// Initial level (for outputs)
    pub initial: GpioLevel,
    /// Owner module index (`NO_MODULE` = kernel-owned). Set by config;
    /// the kernel grants the pin to the module at instantiation.
    pub owner_module_id: ModuleId,
}

/// Maximum number of SPI buses
pub const MAX_SPI_BUSES: usize = 2;
/// Maximum number of I2C buses
pub const MAX_I2C_BUSES: usize = 2;

// ============================================================================
// Hardware Context - Runtime State
// ============================================================================

/// Hardware context - tracks which bus resources have been initialized.
///
/// Tracks which hardware buses have been configured at boot.
/// Used by the scheduler to validate hardware requirements.
pub struct HardwareContext {
    spi_initialized: [bool; MAX_SPI_BUSES],
    i2c_initialized: [bool; MAX_I2C_BUSES],
}

impl Default for HardwareContext {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareContext {
    pub const fn new() -> Self {
        Self {
            spi_initialized: [false; MAX_SPI_BUSES],
            i2c_initialized: [false; MAX_I2C_BUSES],
        }
    }

    pub fn is_spi_initialized(&self, bus: u8) -> bool {
        if (bus as usize) < MAX_SPI_BUSES {
            self.spi_initialized[bus as usize]
        } else {
            false
        }
    }

    pub fn mark_spi_initialized(&mut self, bus: u8) {
        if (bus as usize) < MAX_SPI_BUSES {
            self.spi_initialized[bus as usize] = true;
        }
    }

    pub fn is_i2c_initialized(&self, bus: u8) -> bool {
        if (bus as usize) < MAX_I2C_BUSES {
            self.i2c_initialized[bus as usize]
        } else {
            false
        }
    }

    pub fn mark_i2c_initialized(&mut self, bus: u8) {
        if (bus as usize) < MAX_I2C_BUSES {
            self.i2c_initialized[bus as usize] = true;
        }
    }
}

// ============================================================================
// Graph image layout
// ============================================================================

extern "C" {
    #[cfg(feature = "rp")]
    static __end_block_addr: u8;
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    static __end_data_addr: u8;
    /// First byte `_start` zeroes on a RAM-loaded aarch64 image: the end of
    /// the window the graph image after the kernel lies in.
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    static __bss_start: u8;
}

/// Where the admitted graph image's regions lie in memory.
#[derive(Debug, Clone, Copy)]
pub struct FlashLayout {
    /// Address of the module table.
    pub modules_addr: u32,
    /// Bytes of the module table, as the image header states it: the
    /// loader's bound on the table.
    pub modules_size: u32,
    /// Address of the config.
    pub config_addr: u32,
    /// Bytes of the config, as the image header states it: the parser's
    /// only bound.
    pub config_size: u32,
}

impl FlashLayout {
    /// The regions of an admitted image whose header lies at `base`.
    pub fn of(base: u32, header: &crate::abi::wire::graph_image::Header) -> FlashLayout {
        FlashLayout {
            modules_addr: base + header.modules_offset,
            modules_size: header.modules_size,
            config_addr: base + header.config_offset,
            config_size: header.config_size,
        }
    }
}

/// Where the graph image a firmware image carries lies: the first 256-byte
/// boundary past the kernel's file-backed end. On RP that end is
/// `__end_block_addr`, past everything the flash holds for the kernel; on a
/// RAM-loaded aarch64 image it is `__end_data_addr`, before `.bss`, which
/// `_start` zeroes in RAM.
#[cfg(any(feature = "rp", all(target_arch = "aarch64", target_os = "none")))]
fn firmware_image_addr() -> u32 {
    #[cfg(feature = "rp")]
    // SAFETY: a linker symbol; only its address is taken.
    let end = unsafe { &__end_block_addr as *const u8 as u32 };
    #[cfg(not(feature = "rp"))]
    // SAFETY: a linker symbol; only its address is taken.
    let end = unsafe { &__end_data_addr as *const u8 as u32 };
    end.div_ceil(256) * 256
}

/// Bytes from `at` the firmware image's graph image may occupy: what lies
/// between it and the next thing the platform owns.
///
/// - A RAM-loaded aarch64 image (Pi 5, CM5, a uefi image) carries it between
///   the end of its file-backed sections and `.bss`, which `_start` zeroes
///   before `main`: the window ends at `__bss_start` (`linker/memory-bcm2712.x`,
///   `linker/memory-uefi.x`).
/// - An RP image executes in place from flash, and the platform states the
///   window below its graph slots (`platform::planner::firmware_image_window`).
#[cfg(any(feature = "rp", all(target_arch = "aarch64", target_os = "none")))]
fn firmware_image_window(at: u32) -> u32 {
    #[cfg(feature = "rp")]
    {
        crate::platform::planner::firmware_image_window(at)
    }
    #[cfg(not(feature = "rp"))]
    {
        // SAFETY: a linker symbol; only its address is taken.
        let end = unsafe { &__bss_start as *const u8 as usize };
        (end as u32).saturating_sub(at)
    }
}

/// The graph image after the kernel, admitted, or `None` (said why).
#[cfg(any(feature = "rp", all(target_arch = "aarch64", target_os = "none")))]
fn firmware_image_layout(own_pin: &[u8; 32]) -> Option<FlashLayout> {
    let at = firmware_image_addr();
    let window = firmware_image_window(at);
    if window == 0 {
        log::error!("[config] no room for a graph image at 0x{at:08x}");
        return None;
    }
    // SAFETY: `[at, at + window)` is mapped for the life of the kernel: it
    // is the flash below the graph slots on RP, and the part of a RAM-loaded
    // image's load before `.bss` on aarch64 (`firmware_image_window`).
    let image = unsafe { core::slice::from_raw_parts(at as usize as *const u8, window as usize) };
    match super::graph_image::admit(image, own_pin) {
        Ok(header) => Some(FlashLayout::of(at, &header)),
        Err(why) => {
            log::error!(
                "[config] graph image at 0x{at:08x} refused: {}",
                why.reason()
            );
            None
        }
    }
}

/// The layout chosen this boot, held so the image is admitted (and its
/// payload hashed) once: boot asks for it more than once. 0 = not yet
/// chosen, 1 = chosen.
static LAYOUT_CHOSEN: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
static mut LAYOUT: Option<FlashLayout> = None;

/// The graph image this kernel boots: on RP the admitted flash slot with the
/// higher epoch, else (and on a RAM-loaded aarch64 image) the image after the
/// kernel. `None` where no image is admitted, and on targets whose graph is
/// handed over another way (Linux, wasm).
pub fn read_layout() -> Option<FlashLayout> {
    use core::sync::atomic::Ordering;
    if LAYOUT_CHOSEN.load(Ordering::Acquire) == 1 {
        // SAFETY: written once below before the flag is released, and never
        // again; the Acquire load orders this read after that write.
        return unsafe { *core::ptr::addr_of!(LAYOUT) };
    }
    let layout = choose_layout();
    // SAFETY: the first read of the layout is boot's, on core 0 before any
    // other core or module runs, so nothing reads or writes this concurrently.
    unsafe { *core::ptr::addr_of_mut!(LAYOUT) = layout };
    LAYOUT_CHOSEN.store(1, Ordering::Release);
    layout
}

fn choose_layout() -> Option<FlashLayout> {
    #[cfg(any(feature = "rp", all(target_arch = "aarch64", target_os = "none")))]
    {
        let own_pin = super::graph_image::own_abi_pin();
        #[cfg(feature = "rp")]
        if let Some(layout) = crate::platform::planner::choose_slot(&own_pin) {
            return Some(layout);
        }
        firmware_image_layout(&own_pin)
    }
    #[cfg(not(any(feature = "rp", all(target_arch = "aarch64", target_os = "none"))))]
    {
        None
    }
}

/// The config of the graph image this kernel boots: the bytes
/// `read_config_into` decodes. `None` with no admitted image.
pub fn layout_config_window() -> Option<&'static [u8]> {
    let layout = read_layout()?;
    // SAFETY: the image was admitted inside memory mapped for the life of
    // the kernel (a flash slot, or the window after the kernel), and the
    // header's config region lies inside it.
    Some(unsafe {
        core::slice::from_raw_parts(
            layout.config_addr as usize as *const u8,
            layout.config_size as usize,
        )
    })
}

/// Maximum counts.
///
/// `MAX_MODULES` is the kernel platform's module-index domain, stated in
/// `kernel::config` (4096 on Linux, 1024 on bcm2712 and uefi, 48 on wasm, 32
/// on RP); the per-module tables are sized from the boot plan within it. It
/// is kernel capacity, not ABI: modules read the live slot count at runtime
/// (`internal::reconfigure::SLOT_CAPACITY`). Every per-module set — the
/// event-wake bitmap, owner and upstream masks — is a `ModuleMask` of
/// `MODULE_MASK_WORDS` u64 words sized from it, so a profile value needs no
/// bitmap widened by hand; the limit that does bind is the `0xFFFF`
/// no-module sentinel in the config blob's u16 module id.
pub use crate::kernel::config::MAX_MODULES;
use crate::kernel::exec::scheduler::{ModuleId, MAX_DOMAINS, NO_MODULE};

const _: () = assert!(
    MAX_MODULES <= NO_MODULE as usize,
    "module ids are u16 in the config blob and 0xFFFF names no module"
);

/// The edge-id domain: the most edges a graph may carry and so the channel-id
/// domain. On the static profiles it is the profile's compiled count
/// (`kernel::config::GRAPH_EDGES`); on Linux and aarch64 bare metal the edge
/// table is sized from the graph and this bounds it.
#[cfg(any(feature = "host-linux", feature = "aarch64-metal"))]
pub const MAX_GRAPH_EDGES: usize = 255 * 128;
#[cfg(not(any(feature = "host-linux", feature = "aarch64-metal")))]
pub const MAX_GRAPH_EDGES: usize = crate::kernel::config::GRAPH_EDGES;
/// The edge-id domain of the small (static) profiles, named so the tools'
/// capacity mirror can pin it against this source text.
pub const SMALL_GRAPH_EDGES: usize = 128;
#[cfg(not(any(feature = "host-linux", feature = "aarch64-metal")))]
const _: () = assert!(
    MAX_GRAPH_EDGES == SMALL_GRAPH_EDGES,
    "a static profile's edge domain is the named small-profile count"
);

// There is no fixed ceiling on the config blob. The parser is handed the
// blob as a slice whose length is what the platform mapped, and that length
// is the only bound: a blob whose `total_len` runs past it is refused by the
// codec. Wherever a graph image carries the blob, that length is the config
// region its admitted header states; QEMU virt passes the gap to the module
// blob it side-loads, and wasm the embedded blob's used length. The CLI
// refuses an image whose payload would not fit the window it is packed into.

// ============================================================================
// Graph Config
// ============================================================================

/// Bytes of module params the parsed config borrows from its blob, and the
/// blob's length: `(params_bytes, blob_len)`. Written by the parser, read by
/// `finalize_instantiation_accounting` and the resource ledger
/// (`POOL_CONFIG_ARENA`). Params are not copied anywhere, so the pair is an
/// observation of the graph, not a pool that can run out.
static CONFIG_PARAMS_BYTES: portable_atomic::AtomicUsize = portable_atomic::AtomicUsize::new(0);
static CONFIG_BLOB_LEN: portable_atomic::AtomicUsize = portable_atomic::AtomicUsize::new(0);

/// `(params_bytes, blob_len)` of the config last parsed: the module params
/// borrowed in place from the blob, against the blob's length.
pub fn config_params_usage() -> (usize, usize) {
    use portable_atomic::Ordering;
    (
        CONFIG_PARAMS_BYTES.load(Ordering::Relaxed),
        CONFIG_BLOB_LEN.load(Ordering::Relaxed),
    )
}

/// One module of the graph, filled from the blob's module record
/// (`boot_config::ModuleRecord`), its params borrowed in place.
#[derive(Debug, Clone, Copy)]
pub struct ModuleEntry {
    pub name_hash: u32,
    pub id: ModuleId,
    /// Execution domain ID (0 = default domain)
    pub domain_id: u8,
    /// Module opts into the Tier 1c pre-pass drain slot. Set by the
    /// tools-side build pipeline from the module manifest's
    /// `pre_tick_drain` field. Read by `prepare_graph` to populate
    /// `domain_pre_tick_order` and exclude the module from
    /// `domain_exec_order`.
    pub pre_tick_drain: bool,
    /// Tee/merge framing mode (`FRAME_KIND_*` from `module_types`).
    /// `FRAME_KIND_NONE` (0) is best-effort byte-stream forwarding;
    /// `FRAME_KIND_ETH` (1) parses `[len:u16][payload]`;
    /// `FRAME_KIND_NET` (2) parses `[msg_type:u8][len:u16][payload]`;
    /// `FRAME_KIND_TELEMETRY` (3) sizes a `TelemetryRecord` from its
    /// `signal`+`kind` prefix.
    /// Set by `insert_fan` for ports that carry framed protocols;
    /// ignored for any other module type.
    pub frame_kind: u8,
    /// Pointer to the params inside the config blob, borrowed in place. Valid
    /// for as long as the blob stays mapped, which every platform guarantees
    /// for the life of the `Config` that holds this entry.
    pub params_ptr: *const u8,
    /// Length of params
    pub params_len: usize,
}

impl ModuleEntry {
    /// Get params as slice
    pub fn params(&self) -> &[u8] {
        if self.params_ptr.is_null() || self.params_len == 0 {
            &[]
        } else {
            // SAFETY: `params_ptr` is non-null + non-zero len; the parser
            // pointed it into the config blob after the codec bounded the
            // record inside it, and the blob stays mapped for the life of the
            // config (see the module header).
            unsafe { core::slice::from_raw_parts(self.params_ptr, self.params_len) }
        }
    }
}

impl Default for ModuleEntry {
    fn default() -> Self {
        Self {
            name_hash: 0,
            id: 0,
            domain_id: 0,
            pre_tick_drain: false,
            frame_kind: 0,
            params_ptr: core::ptr::null(),
            params_len: 0,
        }
    }
}

impl ModuleEntry {
    /// Check if this is an empty/invalid entry
    pub fn is_empty(&self) -> bool {
        self.name_hash == 0
    }
}

/// What an edge's ring is, for placement: same domain, DMA-owned, cross-core
/// or a NIC descriptor ring.
pub use fluxor_contracts::boot_config::EdgeClass;

/// Graph edge connecting two modules
#[derive(Debug, Clone, Copy)]
pub struct GraphEdge {
    pub from_id: ModuleId,
    pub to_id: ModuleId,
    /// Destination port type: 0 = in (data), 1 = ctrl (control)
    pub to_port: u8,
    /// Source port index, 0..=15. 0 = primary output.
    pub from_port_index: u8,
    /// Destination port index, 0..=15. 0 = primary input/ctrl.
    pub to_port_index: u8,
    /// Buffer group ID for aliasing. 0 = no aliasing (each edge gets its own buffer).
    /// Any edge with a non-zero group ID enables mailbox (zero-copy) mode on its
    /// channel. When multiple edges share the same group, they alias to the same
    /// channel buffer. Aliasing requires the downstream module to have `mailbox_safe`
    /// (header flags bit 0) set. Incompatible with tee/merge — `insert_fan` clears
    /// `buffer_group` on fan edges. 0..=31.
    pub buffer_group: u8,
    /// Edge class metadata (Local, DmaOwned, CrossCore, NicRing). Pure
    /// metadata on single-core; no runtime cost.
    pub edge_class: EdgeClass,
    /// Per-edge ring-buffer size in bytes. `0` defers to the
    /// producer/consumer manifest port capacities and the default ring
    /// (`BUFFER_SIZE`). Non-zero requests at least this many bytes: the
    /// scheduler takes the largest of it and the two port capacities,
    /// rounds that up to a power of two of at least 64 bytes, and refuses
    /// the graph when it is over the 4 MiB ceiling (`fluxor_contracts::ring_size`).
    pub buffer_bytes: u32,
    /// Rate class of this edge: 0=control, 1=audio, 2=video,
    /// 3=bulk, 4=transaction (contracts `RateClass`). Feeds
    /// MODULE_FLOW_BUDGET grants and the wake-on-write class gate.
    pub rate_class: u8,
    /// `wake: true` on the wiring entry: a successful
    /// `channel_write` on this edge latches the consumer's
    /// event-wake bit and rings the scheduler doorbell so an idle
    /// sleep is cut short.
    pub wake_on_write: bool,
    /// The consumer port declares `retains_send`: it keeps its own copy of
    /// what it sends until the provider reports it acknowledged. Set by the
    /// composer; read back through `channel::FACTS`.
    pub retains_send: bool,
}

impl From<boot_config::EdgeRecord> for GraphEdge {
    fn from(e: boot_config::EdgeRecord) -> Self {
        Self {
            from_id: e.from,
            to_id: e.to,
            to_port: u8::from(e.to_ctrl),
            from_port_index: e.from_port,
            to_port_index: e.to_port,
            buffer_group: e.buffer_group,
            edge_class: e.class,
            buffer_bytes: e.buffer_bytes,
            rate_class: e.rate_class,
            wake_on_write: e.wake_on_write,
            retains_send: e.retains_send,
        }
    }
}

// ============================================================================
// Config and its reader
// ============================================================================

/// The blob-level facts of a parsed config.
#[derive(Debug, Clone, Copy)]
pub struct ConfigHeader {
    /// The blob's CRC-32, as the codec verified it.
    pub checksum: u32,
    /// Tick period in microseconds. 0 = default 1000us.
    pub tick_us: u16,
    /// Graph-level sample rate. 0 = not set.
    pub graph_sample_rate: u32,
}

/// Module entries indexed by module id (or, for `prepare_graph`'s staged
/// list, by scheduler slot).
pub type ModuleList = crate::kernel::mem::table::ParseTable<Option<ModuleEntry>, MAX_MODULES>;

/// Parsed configuration
pub struct Config {
    pub header: ConfigHeader,
    /// Module entries by id: an array of the profile's module count on the
    /// static profiles; on Linux and aarch64 bare metal a list as long as the
    /// largest id parsed.
    pub modules: ModuleList,
    /// Graph edges in blob order.
    pub graph_edges: crate::kernel::mem::table::ParseTable<Option<GraphEdge>, MAX_GRAPH_EDGES>,
    pub module_count: u16,
    pub edge_count: u16,
    /// Per-domain tick_us. 0 = use global.
    pub domain_tick_us: [u16; MAX_DOMAINS],
    /// Per-domain execution mode, the `ExecMode` byte (`scheduler::exec_mode`).
    pub domain_exec_mode: [u8; MAX_DOMAINS],
    /// Per-domain adaptive-tick enable flags. `0` = adaptive off.
    ///   bit 0: enable mechanism (a) demand-driven idle.
    ///   bit 1: enable mechanism (b) adaptive cadence.
    pub domain_adaptive_flags: [u8; MAX_DOMAINS],
    /// Per-domain adaptive-tick latency floor target, µs (mechanism (b)). The
    /// pacer never drives the tick below `max(tick_min_us, worst_step×margin)`.
    /// A blob value of 0, and every domain the blob declares no record for,
    /// takes that domain's effective tick (so an unconfigured domain has no
    /// adaptive headroom — a no-op).
    pub domain_tick_min_us: [u16; MAX_DOMAINS],
    /// Per-domain adaptive-tick relaxed/idle backstop cadence, µs. The idle
    /// sleep (a) and the cooldown ceiling (b) relax toward this. 0 takes the
    /// domain's effective tick, as for `domain_tick_min_us`.
    pub domain_tick_max_us: [u16; MAX_DOMAINS],
    /// Graph-level flags (`GRAPH_FLAG_*`).
    pub graph_flags: u8,
    /// The blob's resident workloads (`WKLD`), read where they lie in the
    /// config image. `scheduler::admit_resident_workloads_from_config` admits
    /// each at boot; the resource ledger plans for them. `None` on a config
    /// with no workloads.
    workloads: Option<Workloads<'static>>,
}

/// `graph_flags` bit 0: accept cycles in the dataflow graph. The
/// canonical use case is bidirectional `http <-> linux_net` feedback
/// pairs in linux http examples. The flag is graph-wide: an edge carries
/// no feedback marking, so every cycle's members are stepped after the
/// ordered modules, in declaration order (`compute_exec_order`).
pub const GRAPH_FLAG_ACCEPT_CYCLES: u8 = boot_config::GRAPH_FLAG_ACCEPT_CYCLES;

impl Config {
    /// Create an empty config
    pub const fn empty() -> Self {
        Self {
            header: ConfigHeader {
                checksum: 0,
                tick_us: 0,
                graph_sample_rate: 0,
            },
            modules: ModuleList::new(None),
            graph_edges: crate::kernel::mem::table::ParseTable::new(None),
            module_count: 0,
            edge_count: 0,
            domain_tick_us: [0; MAX_DOMAINS],
            domain_exec_mode: [0; MAX_DOMAINS],
            domain_adaptive_flags: [0; MAX_DOMAINS],
            domain_tick_min_us: [0; MAX_DOMAINS],
            domain_tick_max_us: [0; MAX_DOMAINS],
            graph_flags: 0,
            workloads: None,
        }
    }

    /// The resident workloads the blob declares, `None` if it declares none.
    pub fn workloads(&self) -> Option<Workloads<'_>> {
        self.workloads
    }
}

/// Read the config the flash layout points at directly into `dest`, bounded
/// by the window the layout says is mapped there.
///
/// Returns true if config was read successfully, false otherwise.
/// This avoids allocating a large Config struct on the stack.
pub fn read_config_into(dest: &mut Config) -> bool {
    match layout_config_window() {
        Some(blob) => read_config_from_slice(blob, dest),
        None => {
            log::error!("[config] no config window in the flash layout");
            false
        }
    }
}

/// Read config from a raw pointer plus caller-supplied length. The
/// caller (a platform boot path) must pass the
/// mapped region size; the slice is constructed with
/// `from_raw_parts(ptr, len)`, and that length is the parser's only bound.
/// `len = 0` is rejected.
///
/// # Safety
/// `flash_ptr..flash_ptr.add(len)` must be a valid, contiguous, readable
/// memory region that stays mapped and unchanged for as long as the parsed
/// `config` is in use: its module entries and workloads borrow from it.
pub unsafe fn read_config_from_ptr_with_len(
    flash_ptr: *const u8,
    len: usize,
    config: &mut Config,
) -> bool {
    if flash_ptr.is_null() || len == 0 {
        log::error!("[config] null pointer or zero length");
        return false;
    }
    // SAFETY: caller's `# Safety` contract — `flash_ptr` covers `len`
    // contiguous readable bytes for as long as the parsed config is used
    // (its module params are borrowed from them). `len > 0` checked above.
    let blob = unsafe { core::slice::from_raw_parts(flash_ptr, len) };
    read_config_from_slice(blob, config)
}

/// Why a decoded blob does not fit this kernel: the count and the limit it
/// passes, named in the boot log.
enum Refusal {
    Codec(boot_config::DecodeError),
    Over {
        what: &'static str,
        count: usize,
        limit: &'static str,
        max: usize,
    },
    RepeatedModule(ModuleId),
    Hardware(&'static str),
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Codec(e) => {
                let (a, b) = e.detail();
                write!(f, "{} ({a:#010x}, {b})", e.kind())
            }
            Self::Over {
                what,
                count,
                limit,
                max,
            } => write!(f, "{what}={count} exceeds {limit}={max}"),
            Self::RepeatedModule(id) => write!(f, "module id {id} repeated"),
            Self::Hardware(why) => write!(f, "hardware section: {why}"),
        }
    }
}

fn bounded(
    what: &'static str,
    count: usize,
    limit: &'static str,
    max: usize,
) -> Result<(), Refusal> {
    if count > max {
        Err(Refusal::Over {
            what,
            count,
            limit,
            max,
        })
    } else {
        Ok(())
    }
}

/// Read config from a caller-provided byte slice into `config`. The slice's
/// length is the hard upper bound: a blob whose `total_len` runs past it is
/// refused. The codec refuses an unknown, repeated or truncated section and a
/// checksum mismatch; counts past this kernel's profile (`MAX_MODULES`,
/// `MAX_GRAPH_EDGES`, `MAX_DOMAINS`, `MAX_OWNERS`) are refused naming the
/// limit, never clamped. A refused blob leaves `config` empty and applies
/// nothing (the capacity envelope included).
///
/// The parsed module entries and workloads BORROW from `blob` (nothing is
/// copied), so the caller keeps `blob` mapped and unchanged for as long as
/// `config` is used — every platform passes its resident config blob, which
/// lives as long as the kernel does.
pub fn read_config_from_slice(blob: &[u8], config: &mut Config) -> bool {
    *config = Config::empty();
    CONFIG_PARAMS_BYTES.store(0, portable_atomic::Ordering::Relaxed);
    CONFIG_BLOB_LEN.store(0, portable_atomic::Ordering::Relaxed);
    // SAFETY: the caller keeps `blob` mapped and unchanged for as long as
    // `config` is used (this function's contract, as for every module's
    // borrowed params); the views `config` keeps into it live no longer.
    let blob: &'static [u8] = unsafe { core::slice::from_raw_parts(blob.as_ptr(), blob.len()) };
    match fill(blob, config) {
        Ok(()) => true,
        Err(why) => {
            log::error!("[config] refused: {why}");
            *config = Config::empty();
            false
        }
    }
}

fn fill(blob: &'static [u8], config: &mut Config) -> Result<(), Refusal> {
    use crate::kernel::sys::resource_ledger;
    let bc = boot_config::decode(blob).map_err(Refusal::Codec)?;
    let graph = bc.graph();
    bounded(
        "module_count",
        usize::from(graph.module_count()),
        "MAX_MODULES",
        MAX_MODULES,
    )?;
    bounded(
        "edge_count",
        usize::from(graph.edge_count()),
        "MAX_GRAPH_EDGES",
        MAX_GRAPH_EDGES,
    )?;
    bounded(
        "domain_count",
        usize::from(graph.domain_count()),
        "MAX_DOMAINS",
        MAX_DOMAINS,
    )?;
    if let Some(w) = bc.workloads() {
        // Slot 0 is the system owner; each workload takes one of the rest.
        bounded(
            "workload_count",
            usize::from(w.count()),
            "MAX_OWNERS - 1",
            crate::kernel::workload::owner::MAX_OWNERS - 1,
        )?;
    }
    check_hardware(&bc)?;

    config.header = ConfigHeader {
        checksum: bc.checksum(),
        tick_us: graph.tick_us,
        graph_sample_rate: graph.graph_sample_rate,
    };
    config.graph_flags = graph.graph_flags;
    config.module_count = graph.module_count();
    config.edge_count = graph.edge_count();

    for m in graph.modules() {
        bounded(
            "module id",
            usize::from(m.id),
            "MAX_MODULES - 1",
            MAX_MODULES - 1,
        )?;
        bounded(
            "module domain",
            usize::from(m.domain),
            "MAX_DOMAINS - 1",
            MAX_DOMAINS - 1,
        )?;
        let slot = &mut config.modules[usize::from(m.id)];
        if slot.is_some() {
            return Err(Refusal::RepeatedModule(m.id));
        }
        *slot = Some(ModuleEntry {
            name_hash: m.name_hash,
            id: m.id,
            domain_id: m.domain,
            pre_tick_drain: m.pre_pass,
            frame_kind: 0,
            params_ptr: if m.params.is_empty() {
                core::ptr::null()
            } else {
                m.params.as_ptr()
            },
            params_len: m.params.len(),
        });
    }

    config
        .graph_edges
        .reserve_entries(usize::from(graph.edge_count()));
    for (i, e) in graph.edges().enumerate() {
        config.graph_edges[i] = Some(GraphEdge::from(e));
    }

    let global_tick = if graph.tick_us > 0 {
        graph.tick_us
    } else {
        1000
    };
    let mut domains = graph.domains();
    for d in 0..MAX_DOMAINS {
        let rec = domains.next().unwrap_or_default();
        let eff = if rec.tick_us > 0 {
            rec.tick_us
        } else {
            global_tick
        };
        config.domain_tick_us[d] = rec.tick_us;
        config.domain_exec_mode[d] = rec.exec_mode as u8;
        config.domain_adaptive_flags[d] = rec.adaptive_flags;
        config.domain_tick_min_us[d] = if rec.tick_min_us > 0 {
            rec.tick_min_us
        } else {
            eff
        };
        config.domain_tick_max_us[d] = if rec.tick_max_us > 0 {
            rec.tick_max_us
        } else {
            eff
        };
    }

    config.workloads = bc.workloads();

    // Everything is checked: the envelope and the declared demand are the
    // pools' live-add reserves and declared asks, installed whole. Absent
    // sections leave a pool at its derived size plus the profile's default
    // reserve.
    resource_ledger::reset_envelope();
    for e in bc.envelope().iter().flat_map(|p| p.iter()) {
        resource_ledger::set_reserve(e.pool, e.n);
    }
    for e in bc.demand().iter().flat_map(|p| p.iter()) {
        resource_ledger::set_declared(e.pool, e.n);
    }

    CONFIG_PARAMS_BYTES.store(graph.params_bytes(), portable_atomic::Ordering::Relaxed);
    CONFIG_BLOB_LEN.store(bc.total_len(), portable_atomic::Ordering::Relaxed);
    Ok(())
}

/// The platform's hardware section: a platform that declares one (RP) decodes
/// and checks it, and refuses a blob without it; every other platform refuses
/// a blob that carries one.
fn check_hardware(bc: &BootConfig<'_>) -> Result<(), Refusal> {
    #[cfg(feature = "rp")]
    {
        let hw = bc
            .hardware()
            .ok_or(Refusal::Hardware("this platform needs one"))?;
        crate::platform::planner::decode_hardware(hw)
            .map(|_| ())
            .map_err(Refusal::Hardware)
    }
    #[cfg(not(feature = "rp"))]
    {
        if bc.hardware().is_some() {
            return Err(Refusal::Hardware("this platform has none"));
        }
        Ok(())
    }
}
