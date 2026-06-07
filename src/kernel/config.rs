//! Configuration and hardware structures.
//!
//! This module provides:
//! - Binary configuration reader for FXWR format config from flash
//! - Hardware configuration structures for SPI, I2C, and GPIO
//! - Runtime hardware context tracking
//! - Hardware manager for initialization
//!
//! ## Concurrency
//!
//! `CONFIG_ARENA` and `ARENA_OFFSET` are boot-only: written by
//! `populate_static_state` on core 0, then read by every core via the
//! parsed `Config`. See `docs/architecture/concurrency.md`.
//!
//! ## Flash Layout
//!
//! The flash layout is dynamic, controlled by a 16-byte trailer placed
//! immediately after the firmware code (256-byte aligned).
//!
//! ```text
//! 0x10000000: [firmware]
//!             [trailer - 16 bytes, 256-byte aligned after firmware]
//!             [modules - optional, any size]
//!             [config - any size]
//! ```

// ============================================================================
// Hardware Configuration Structures
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

/// SPI bus configuration
#[derive(Debug, Clone, Copy)]
pub struct SpiConfig {
    /// SPI bus number (0 or 1)
    pub bus: u8,
    /// MISO pin number
    pub miso: u8,
    /// MOSI pin number
    pub mosi: u8,
    /// SCK pin number
    pub sck: u8,
    /// Initial frequency in Hz
    pub freq_hz: u32,
}

/// I2C bus configuration
#[derive(Debug, Clone, Copy)]
pub struct I2cConfig {
    /// I2C bus number (0 or 1)
    pub bus: u8,
    /// SDA pin number
    pub sda: u8,
    /// SCL pin number
    pub scl: u8,
    /// Frequency in Hz
    pub freq_hz: u32,
}

/// UART bus configuration
#[derive(Debug, Clone, Copy)]
pub struct UartConfig {
    /// UART bus number (0 or 1)
    pub bus: u8,
    /// TX pin number
    pub tx_pin: u8,
    /// RX pin number
    pub rx_pin: u8,
    /// Baud rate
    pub baudrate: u32,
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
    /// Owner module index (0xFF = kernel-owned, 0-7 = module index)
    /// Set by config; kernel grants pin to module at instantiation.
    pub owner_module_id: u8,
}

/// PIO instance configuration
///
/// Each PIO config describes one PIO instance's pin wiring.
/// - For cmd mode (bidirectional gSPI): data_pin=DIO, clk_pin=CLK, extra_pin=0xFF
/// - For stream mode (I2S): data_pin=DOUT, clk_pin=BCLK, extra_pin=LRCLK
#[derive(Debug, Clone, Copy)]
pub struct PioConfig {
    /// PIO block index (0, 1, or 2 on RP2350B)
    pub pio_idx: u8,
    /// Primary data pin
    pub data_pin: u8,
    /// Clock / sideset-base pin
    pub clk_pin: u8,
    /// Extra pin (LRCLK for I2S, 0xFF if unused)
    pub extra_pin: u8,
}

/// Maximum number of SPI buses
pub const MAX_SPI_BUSES: usize = 2;
/// Maximum number of I2C buses
pub const MAX_I2C_BUSES: usize = 2;
/// Maximum number of PIO instances (RP2350B has 3 PIO blocks)
pub const MAX_PIO_CONFIGS: usize = 3;
/// Maximum number of UART buses
pub const MAX_UART_BUSES: usize = 2;
/// Maximum number of GPIO pins that can be configured
pub const MAX_GPIO_CONFIGS: usize = 8;

/// Hardware configuration - describes all hardware resources
#[derive(Debug, Clone)]
pub struct HardwareConfig {
    /// SPI bus configurations
    pub spi: [Option<SpiConfig>; MAX_SPI_BUSES],
    /// I2C bus configurations
    pub i2c: [Option<I2cConfig>; MAX_I2C_BUSES],
    /// UART bus configurations
    pub uart: [Option<UartConfig>; MAX_UART_BUSES],
    /// PIO instance configurations (index 0 = cmd, index 1 = stream)
    pub pio: [Option<PioConfig>; MAX_PIO_CONFIGS],
    /// GPIO pin configurations
    pub gpio: [Option<GpioConfig>; MAX_GPIO_CONFIGS],
    /// Maximum GPIO pin count from target (e.g. 30 for RP2350A, 48 for RP2350B)
    pub max_gpio: u8,
}

impl Default for HardwareConfig {
    fn default() -> Self {
        Self {
            spi: [None; MAX_SPI_BUSES],
            i2c: [None; MAX_I2C_BUSES],
            uart: [None; MAX_UART_BUSES],
            pio: [None; MAX_PIO_CONFIGS],
            gpio: [None; MAX_GPIO_CONFIGS],
            max_gpio: 30,
        }
    }
}

impl HardwareConfig {
    /// Create an empty hardware configuration
    pub const fn new() -> Self {
        Self {
            spi: [None; MAX_SPI_BUSES],
            i2c: [None; MAX_I2C_BUSES],
            uart: [None; MAX_UART_BUSES],
            pio: [None; MAX_PIO_CONFIGS],
            gpio: [None; MAX_GPIO_CONFIGS],
            max_gpio: 30,
        }
    }
}

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
// Flash Layout
// ============================================================================

extern "C" {
    static __end_block_addr: u8;
    #[cfg(target_arch = "aarch64")]
    static __end_data_addr: u8;
}

/// Trailer magic: "FXLT" (Fluxor Layout Trailer)
pub const TRAILER_MAGIC: u32 = 0x544C5846;

/// Current trailer version
pub const TRAILER_VERSION: u8 = 1;

/// Config magic
pub const MAGIC_CONFIG: u32 = 0x52575846; // "FXWR"

// ============================================================================
// Flash Layout Trailer
// ============================================================================

/// Flash layout information read from trailer
#[derive(Debug, Clone, Copy)]
pub struct FlashLayout {
    /// Address of module table (0 = no modules)
    pub modules_addr: u32,
    /// Known byte length of the module-table region, or 0 if the layout
    /// source doesn't carry one. Flash A/B graph slots record it (and
    /// bound-check it against the slot aperture); the legacy firmware
    /// trailer has no length field, so it reports 0 and the loader falls
    /// back to the hard `MAX_MODULES_BLOB_SIZE` cap. Preserved so the
    /// loader can give the shared table validator a real mapping bound
    /// instead of trusting the table's self-declared `total_size` alone.
    pub modules_size: u32,
    /// Address of config
    pub config_addr: u32,
}

/// Compute trailer address from linker symbol.
///
/// On RP (flash/XIP): trailer is after `__end_block_addr` (includes BSS in flash).
/// On aarch64 (RAM-loaded): trailer is after `__end_data_addr` (end of loadable
/// sections, before BSS), because the VPU loads the image contiguously and BSS
/// is zeroed separately in RAM.
fn get_trailer_addr() -> u32 {
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: `__end_data_addr` is a linker symbol; only its address
        // is taken, never the value at that address.
        let end_data = unsafe { &__end_data_addr as *const u8 as u32 };
        (end_data + 255) & !255
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        // SAFETY: as above; `__end_block_addr` is a linker symbol.
        let end_block = unsafe { &__end_block_addr as *const u8 as u32 };
        (end_block + 255) & !255
    }
}

/// Read flash layout. On targets that expose A/B graph slots, the slot
/// with a valid header and the higher epoch wins; otherwise the
/// layout trailer at the end of the firmware is used.
pub fn read_layout() -> Option<FlashLayout> {
    #[cfg(feature = "rp")]
    if let Some(layout) = read_layout_from_slots() {
        return Some(layout);
    }
    read_layout_from_trailer()
}

#[cfg(feature = "rp")]
fn read_layout_from_slots() -> Option<FlashLayout> {
    use crate::abi::platform::rp::flash_layout;
    let slot_a = (flash_layout::XIP_BASE + flash_layout::GRAPH_SLOT_A_OFFSET) as *const u8;
    let slot_b = (flash_layout::XIP_BASE + flash_layout::GRAPH_SLOT_B_OFFSET) as *const u8;

    // SAFETY: slot_a and slot_b point into the XIP-mapped flash region;
    // `decode_slot_header` reads 256 bytes per slot, which fits within
    // the GRAPH_SLOT_*_OFFSET aperture sizing defined by flash_layout.
    let a = unsafe { decode_slot_header(slot_a) };
    // SAFETY: as above; slot_b is the secondary slot at a fixed offset.
    let b = unsafe { decode_slot_header(slot_b) };
    let (base, hdr) = match (a, b) {
        (Some(ha), Some(hb)) => {
            if ha.epoch >= hb.epoch {
                (slot_a, ha)
            } else {
                (slot_b, hb)
            }
        }
        (Some(ha), None) => (slot_a, ha),
        (None, Some(hb)) => (slot_b, hb),
        (None, None) => return None,
    };
    let slot_base = base as u32;
    Some(FlashLayout {
        modules_addr: slot_base + hdr.modules_offset,
        modules_size: hdr.modules_size,
        config_addr: slot_base + hdr.config_offset,
    })
}

#[cfg(feature = "rp")]
struct SlotHeader {
    epoch: u64,
    modules_offset: u32,
    modules_size: u32,
    config_offset: u32,
}

#[cfg(feature = "rp")]
unsafe fn decode_slot_header(base: *const u8) -> Option<SlotHeader> {
    use crate::abi::platform::rp::flash_layout;
    let magic = read_u32(base);
    if magic != flash_layout::GRAPH_SLOT_MAGIC {
        return None;
    }
    let version = *base.add(4);
    if version != flash_layout::GRAPH_SLOT_VERSION {
        return None;
    }
    let epoch = read_u64(base.add(8));
    let modules_offset = read_u32(base.add(16));
    let modules_size = read_u32(base.add(20));
    let config_offset = read_u32(base.add(24));
    let config_size = read_u32(base.add(28));

    // An A/B slot always carries a real module-table length written by the
    // packer; the smallest possible table is its 16-byte header. A
    // `modules_size` below that is a torn/corrupt slot — reject it rather than
    // letting `init()` treat 0 as the trailer's "legacy unknown length"
    // sentinel and fall back to the MAX_MODULES_BLOB_SIZE bound, which would
    // let a corrupt table escape the slot aperture. (The legacy trailer, which
    // has no length field, keeps 0 = unknown — see read_layout_from_trailer.)
    if modules_size < 16 {
        return None;
    }
    // Both regions must fit inside the slot.
    if (modules_offset as u64) + (modules_size as u64) > flash_layout::GRAPH_SLOT_SIZE as u64 {
        return None;
    }
    if (config_offset as u64) + (config_size as u64) > flash_layout::GRAPH_SLOT_SIZE as u64 {
        return None;
    }

    Some(SlotHeader {
        epoch,
        modules_offset,
        modules_size,
        config_offset,
    })
}

#[cfg(feature = "rp")]
unsafe fn read_u64(p: *const u8) -> u64 {
    let lo = read_u32(p) as u64;
    let hi = read_u32(p.add(4)) as u64;
    lo | (hi << 32)
}

/// Read flash layout from the firmware trailer.
fn read_layout_from_trailer() -> Option<FlashLayout> {
    let trailer_addr = get_trailer_addr();
    let trailer_ptr = trailer_addr as *const u8;

    // SAFETY: `trailer_addr` is the linker-computed address of the
    // firmware trailer; the magic check below rejects a bad address.
    unsafe {
        let magic = read_u32(trailer_ptr);

        if magic != TRAILER_MAGIC {
            log::error!("[config] bad trailer magic=0x{magic:08x} addr=0x{trailer_addr:08x}");
            return None;
        }

        let version = *trailer_ptr.add(4);
        if version != TRAILER_VERSION {
            log::error!("[config] unsupported trailer version={version}");
            return None;
        }

        let expected_crc = read_u16(trailer_ptr.add(6));
        let modules_addr = read_u32(trailer_ptr.add(8));
        let config_addr = read_u32(trailer_ptr.add(12));

        // Trailer CRC (bytes 6-7) reserved for future use.
        // Config integrity is validated by the config header's own CRC-16 checksum.
        let _ = expected_crc;

        Some(FlashLayout {
            modules_addr,
            // The legacy trailer has no module-table length field; 0 tells
            // the loader to fall back to the MAX_MODULES_BLOB_SIZE cap and
            // validate internal consistency against the table's own
            // total_size.
            modules_size: 0,
            config_addr,
        })
    }
}

/// Maximum counts.
///
/// `MAX_MODULES` is re-exported from `abi::config::kernel` (per-target
/// profile in `modules/sdk/config.rs`) so kernel-side static arrays match
/// what the SDK promises modules. Bumping it on aarch64-host accommodates
/// graphs like Quantum (42 modules); the wasm/embedded profiles run with
/// 32. The event-wake bitmap in `kernel/event.rs` is u64, so any profile
/// value up to 64 is safe; >64 needs the bitmap widened first.
pub use crate::abi::config::kernel::MAX_MODULES;

// The event-wake bitmap in `kernel/event.rs` is u64, so MAX_MODULES > 64
// would silently lose wake notifications for the higher-numbered modules.
// Catch any future profile bump that would violate this at compile time.
const _: () = assert!(
    MAX_MODULES <= 64,
    "MAX_MODULES > 64 requires widening kernel/event.rs wake_bits beyond u64"
);

pub const MAX_GRAPH_EDGES: usize = 128;

/// Hard ceiling on the on-disk config blob size. Per-platform:
/// - Embedded targets (rp/bcm) cap at 32 KiB — fits in their
///   statically-sized flash regions; bumping requires re-validating
///   the mapped config region + trailer's `config_size` field.
/// - Host targets (linux/wasm) cap at 256 KiB — the synthesised
///   wasm-scenario host inlines the canonical browser shell
///   (runtime.html + host_shims.js, now ~110 KiB combined and growing
///   with player-mode UX + the OPFS object tier) plus scenario.json as
///   `body:` routes so the orchestrator stays self-contained per the
///   shared-infra-in-orchestrator partition principle. Host targets have
///   GiBs of RAM, so the cap is a sanity bound, not a memory constraint.
#[cfg(any(target_os = "linux", target_arch = "wasm32"))]
pub const MAX_CONFIG_SIZE: usize = 256 * 1024;
#[cfg(not(any(target_os = "linux", target_arch = "wasm32")))]
pub const MAX_CONFIG_SIZE: usize = 32 * 1024;

/// Hardware section binary format sizes
pub const SPI_CONFIG_BIN_SIZE: usize = 8;
pub const I2C_CONFIG_BIN_SIZE: usize = 8;
pub const UART_CONFIG_BIN_SIZE: usize = 8;
pub const GPIO_CONFIG_BIN_SIZE: usize = 5;
pub const PIO_CONFIG_BIN_SIZE: usize = 4;

/// Graph section binary format sizes.
///
/// Edge layout (8 bytes):
///   byte 0:    from_id
///   byte 1:    to_id
///   byte 2:    bit 7    = to_port (0 = data, 1 = ctrl)
///              bits 6:5 = edge_class
///              bits 4:0 = buffer_group
///   byte 3:    bits 7:4 = from_port_index
///              bits 3:0 = to_port_index
///   bytes 4-7: buffer_bytes (u32 LE) — explicit ring-buffer size.
///              `0` falls back to module hints / `BUFFER_SIZE`.
///              Otherwise `max(module_hint, buffer_bytes)` is the
///              size requested from `channel_open_for_module`.
pub const GRAPH_EDGE_SIZE: usize = 8;
pub const GRAPH_SECTION_SIZE: usize = 4 + MAX_GRAPH_EDGES * GRAPH_EDGE_SIZE + 16; // header + edges + domain metadata

// ============================================================================
// Graph Config (Version 1: Variable-Length Module Entries)
// ============================================================================

/// Config arena size for storing variable-length module params across
/// all modules in the loaded graph. Sized per chip so embedded targets
/// don't carry a host-class arena in `.bss`. See each platform's
/// `chip` module.
pub const CONFIG_ARENA_SIZE: usize = super::chip::CONFIG_ARENA_SIZE;

/// Static arena for module params storage
static mut CONFIG_ARENA: [u8; CONFIG_ARENA_SIZE] = [0; CONFIG_ARENA_SIZE];
static mut ARENA_OFFSET: usize = 0;

/// Allocate bytes from config arena (bump allocator)
/// Returns None if arena is exhausted
fn arena_alloc(size: usize) -> Option<&'static mut [u8]> {
    // SAFETY: CONFIG_ARENA / ARENA_OFFSET are scheduler-thread owned;
    // `offset + size <= CONFIG_ARENA_SIZE` is checked before slicing.
    unsafe {
        let offset = ARENA_OFFSET;
        if offset + size > CONFIG_ARENA_SIZE {
            return None;
        }
        ARENA_OFFSET = offset + size;
        Some(&mut CONFIG_ARENA[offset..offset + size])
    }
}

/// Reset arena (call before parsing new config)
fn arena_reset() {
    // SAFETY: called between graph rebuilds; no live arena slice.
    unsafe {
        ARENA_OFFSET = 0;
    }
}

/// Current config-arena occupancy: `(used_bytes, total_bytes)`. Read
/// by `scheduler::log_arena_summary` so silicon-TOML sizing decisions
/// can be validated against real workloads.
pub fn config_arena_usage() -> (usize, usize) {
    // SAFETY: word-sized read of static usize.
    unsafe { (ARENA_OFFSET, CONFIG_ARENA_SIZE) }
}

/// Parsed module entry with variable-length params
///
/// Binary format (variable length):
/// - Bytes 0-1: entry_length (u16) - total entry size including header
/// - Bytes 2-5: name_hash (fnv1a32)
/// - Byte 6: id
/// - Byte 7: bit-packed metadata —
///   bits 0-2 = domain_id (0..7, 0 = default domain),
///   bit  4   = pre_tick_drain (Tier 1c opt-in),
///   bits 3, 5-7 reserved.
/// - Bytes 8+: params (entry_length - 8 bytes)
#[derive(Debug, Clone, Copy)]
pub struct ModuleEntry {
    pub name_hash: u32,
    pub id: u8,
    /// Execution domain ID (0 = default domain)
    pub domain_id: u8,
    /// Module opts into the Tier 1c pre-pass drain slot. Set by the
    /// tools-side build pipeline from the module manifest's
    /// `pre_tick_drain` field. Read by `prepare_graph` to populate
    /// `domain_pre_tick_order` and exclude the module from
    /// `domain_exec_order`. See `.context/rfc_isr_tier_surface.md` §D8.
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
    /// Pointer to params in arena (stable for lifetime of config)
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
            // SAFETY: `params_ptr` is non-null + non-zero len; the loader
            // wrote it from the config arena so the slice lives as long
            // as the config blob (whole boot lifetime in practice).
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

/// Edge class for channels — metadata for future multi-core scheduling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EdgeClass {
    /// Local: same domain, default
    Local = 0,
    /// DMA-owned: buffer managed by DMA controller
    DmaOwned = 1,
    /// Cross-core: connects modules in different execution domains
    CrossCore = 2,
    /// NIC ring: zero-copy packet buffer via NicRing DMA descriptors
    NicRing = 3,
}

/// Graph edge connecting two modules
#[derive(Debug, Clone, Copy)]
pub struct GraphEdge {
    pub from_id: u8,
    pub to_id: u8,
    /// Destination port type: 0 = in (data), 1 = ctrl (control)
    pub to_port: u8,
    /// Source port index (high nibble of byte 3). 0 = primary output.
    pub from_port_index: u8,
    /// Destination port index (low nibble of byte 3). 0 = primary input/ctrl.
    pub to_port_index: u8,
    /// Buffer group ID for aliasing. 0 = no aliasing (each edge gets its own buffer).
    /// Any edge with a non-zero group ID enables mailbox (zero-copy) mode on its
    /// channel. When multiple edges share the same group, they alias to the same
    /// channel buffer. Aliasing requires the downstream module to have `mailbox_safe`
    /// (header flags bit 0) set. Incompatible with tee/merge — `insert_fan` clears
    /// `buffer_group` on fan edges.
    ///
    /// Binary encoding: 5 bits (0..31) in byte 2 bits [4:0] of the graph edge.
    /// See `parse_graph_edge`.
    pub buffer_group: u8,
    /// Edge class metadata (Local, DmaOwned, CrossCore, NicRing).
    /// Encoded in bits [6:5] of byte 2 of the on-wire edge record (see
    /// `parse_graph_edge` for the full byte layout). Pure metadata on
    /// single-core; no runtime cost.
    pub edge_class: EdgeClass,
    /// Per-edge ring-buffer size override in bytes. `0` defers to the
    /// producer/consumer module hints (`module_channel_hints`) and the
    /// global `BUFFER_SIZE` fallback. Non-zero requests at least this
    /// many bytes; the scheduler combines it with module hints via
    /// `max(module_hint, buffer_bytes)` and `channel_open_for_module`
    /// clamps to `MAX_CHAN_BYTES = 256 KiB` and rounds up to a power
    /// of two. Encoded as a u32 LE in bytes 4-7 of the edge record.
    pub buffer_bytes: u32,
}

// ============================================================================
// Config Header and Reader
// ============================================================================

/// Config header
#[derive(Debug, Clone, Copy)]
pub struct ConfigHeader {
    pub magic: u32,
    pub version: u16,
    pub checksum: u16,
    pub module_count: u8,
    pub edge_count: u8,
    /// Tick period in microseconds (bytes 10-11). 0 = default 1000us.
    /// Valid range: 100-50000.
    pub tick_us: u16,
    /// Graph-level sample rate (bytes 12-15). 0 = not set.
    pub graph_sample_rate: u32,
}

/// Parsed configuration
pub struct Config {
    pub header: ConfigHeader,
    pub modules: [Option<ModuleEntry>; MAX_MODULES],
    pub graph_edges: [Option<GraphEdge>; MAX_GRAPH_EDGES],
    pub module_count: u8,
    pub edge_count: u8,
    pub hardware: HardwareConfig,
    /// Per-domain tick_us (from graph section domain metadata). 0 = use global.
    pub domain_tick_us: [u16; 4],
    /// Per-domain execution mode: 0=cooperative, 1=high_rate/Tier1a, 3=poll/Tier3.
    pub domain_exec_mode: [u8; 4],
    /// Graph-level flags byte (graph section header byte 1).
    ///   bit 0: ACCEPT_CYCLES — author has explicitly attested that
    ///          any cycles in the graph are bidirectional feedback
    ///          pairs (e.g. `http <-> linux_net`) and safe to step
    ///          in best-effort declaration order. Without this bit,
    ///          `prepare_graph` rejects cycles (v1 strict invariant).
    /// bits 1-7: reserved (must be 0).
    ///
    /// See `.context/rfc_deployment_scenarios.md` §13 ("Known issue
    /// blocking PR 3 end-to-end") for the design rationale.
    pub graph_flags: u8,
}

/// `graph_flags` bit 0: accept cycles in the dataflow graph. The
/// canonical use case is bidirectional `http <-> linux_net` feedback
/// pairs in linux http examples. Typed feedback edges are the
/// long-term answer (see scheduler comment near `compute_exec_order`);
/// this flag is the transitional accommodation.
pub const GRAPH_FLAG_ACCEPT_CYCLES: u8 = 0x01;

impl Config {
    /// Create an empty config
    pub const fn empty() -> Self {
        Self {
            header: ConfigHeader {
                magic: 0,
                version: 0,
                checksum: 0,
                module_count: 0,
                edge_count: 0,
                tick_us: 0,
                graph_sample_rate: 0,
            },
            modules: [None; MAX_MODULES],
            graph_edges: [None; MAX_GRAPH_EDGES],
            module_count: 0,
            edge_count: 0,
            hardware: HardwareConfig::new(),
            domain_tick_us: [0; 4],
            domain_exec_mode: [0; 4],
            graph_flags: 0,
        }
    }
}

/// Read config from flash
///
/// Returns None if config is invalid or not present
pub fn read_config() -> Option<Config> {
    let layout = read_layout()?;
    read_config_at(layout.config_addr)
}

/// Read config from flash directly into provided destination
///
/// Returns true if config was read successfully, false otherwise.
/// This avoids allocating a large Config struct on the stack.
pub fn read_config_into(dest: &mut Config) -> bool {
    let layout = match read_layout() {
        Some(l) => l,
        None => return false,
    };
    read_config_at_into(layout.config_addr, dest)
}

/// Read config from a specific flash address
///
/// Returns None if config is invalid or not present
pub fn read_config_at(config_addr: u32) -> Option<Config> {
    let mut config = Config::empty();
    if read_config_at_into(config_addr, &mut config) {
        Some(config)
    } else {
        None
    }
}

/// Read config from a specific flash address directly into provided destination
///
/// Returns true if config was read successfully, false otherwise.
/// This avoids allocating a large Config struct on the stack.
pub fn read_config_at_into(config_addr: u32, config: &mut Config) -> bool {
    // Bare-metal flash-trailer path: the trailer reader already
    // validates `config_offset + config_size <= GRAPH_SLOT_SIZE` in
    // `read_slot_header`, so passing the parser's `MAX_CONFIG_SIZE`
    // cap here is safe — the underlying flash region is guaranteed
    // by the slot layout (`flash_layout::GRAPH_SLOT_SIZE` is 64 KiB
    // on RP, well above the 32 KiB cap).
    // SAFETY: the trailer reader guarantees `[config_addr, config_addr +
    // MAX_CONFIG_SIZE)` lies inside the flash slot.
    unsafe { read_config_from_ptr_with_len(config_addr as *const u8, MAX_CONFIG_SIZE, config) }
}

/// Read config from a raw pointer plus caller-supplied length. The
/// caller (platform boot path / flash trailer reader) must pass the
/// mapped region size; the slice is constructed with
/// `from_raw_parts(ptr, len)`. `len = 0` is rejected; `len`
/// exceeding `MAX_CONFIG_SIZE` is rejected outright rather than
/// silently narrowed — a source that promises more than the parser's
/// logical maximum is either a tooling bug or a malformed blob.
///
/// # Safety
/// `flash_ptr..flash_ptr.add(len)` must be a valid, contiguous,
/// readable memory region for the duration of the call.
pub unsafe fn read_config_from_ptr_with_len(
    flash_ptr: *const u8,
    len: usize,
    config: &mut Config,
) -> bool {
    if flash_ptr.is_null() || len == 0 {
        log::error!("[config] null pointer or zero length");
        return false;
    }
    if len > MAX_CONFIG_SIZE {
        log::error!("[config] source len={len} exceeds MAX_CONFIG_SIZE={MAX_CONFIG_SIZE}");
        return false;
    }
    // SAFETY: caller's `# Safety` contract — `flash_ptr` covers `len`
    // contiguous readable bytes for the duration of the call. `len > 0`
    // and `len <= MAX_CONFIG_SIZE` already checked above.
    let blob = unsafe { core::slice::from_raw_parts(flash_ptr, len) };
    read_config_from_slice(blob, config)
}

/// Read config from a caller-provided byte slice into `config`. The slice's
/// length is the hard upper bound: any section that would extend past
/// `blob.len()` causes a deterministic rejection with a logged error, no
/// silent truncation. Module / edge counts exceeding `MAX_MODULES` /
/// `MAX_GRAPH_EDGES` are rejected, not clamped.
pub fn read_config_from_slice(blob: &[u8], config: &mut Config) -> bool {
    let flash_ptr = blob.as_ptr();
    let blob_len = blob.len();

    // Header must fit before we even consider parsing.
    const HEADER_SIZE: usize = 16;
    if blob_len < HEADER_SIZE {
        log::error!("[config] blob too short: {blob_len} < {HEADER_SIZE}");
        return false;
    }
    // Read header (16 bytes)
    // SAFETY: `blob_len >= HEADER_SIZE` (= 16) checked above, so reads at
    // offsets 0..16 stay inside `blob`.
    let header = unsafe {
        let magic = read_u32(flash_ptr);
        if magic != MAGIC_CONFIG {
            log::warn!("[config] bad magic=0x{magic:08x}");
            return false;
        }

        let version = read_u16(flash_ptr.add(4));
        let checksum = read_u16(flash_ptr.add(6));
        let module_count = *flash_ptr.add(8);
        let edge_count = *flash_ptr.add(9);
        let tick_us = read_u16(flash_ptr.add(10));
        let graph_sample_rate = read_u32(flash_ptr.add(12));

        ConfigHeader {
            magic,
            version,
            checksum,
            module_count,
            edge_count,
            tick_us,
            graph_sample_rate,
        }
    };

    // Reset config to empty state and arena
    *config = Config::empty();
    config.header = header;
    arena_reset();

    // Kernel and tools always ship together, so any mismatch is an
    // upgrade-skipped or toolchain-mismatch bug rather than a
    // graceful path.
    if header.version != 1 {
        log::error!("[config] unsupported version={}", header.version);
        return false;
    }

    // Reject oversized counts deterministically instead of clamping. A
    // header that promises more modules/edges than the kernel can hold is
    // either a tool-version mismatch or a malformed blob — either way the
    // right answer is to refuse the load with a clear log line.
    if header.module_count as usize > MAX_MODULES {
        log::error!(
            "[config] module_count={} exceeds MAX_MODULES={}",
            header.module_count,
            MAX_MODULES
        );
        return false;
    }
    if header.edge_count as usize > MAX_GRAPH_EDGES {
        log::error!(
            "[config] edge_count={} exceeds MAX_GRAPH_EDGES={}",
            header.edge_count,
            MAX_GRAPH_EDGES
        );
        return false;
    }
    config.module_count = header.module_count;
    config.edge_count = header.edge_count;

    // Parse modules - variable-length entries
    // SAFETY: `blob_len >= HEADER_SIZE + 6` checked below; `flash_ptr.add(16)`
    // points past the header inside the blob.
    let modules_base = unsafe { flash_ptr.add(16) };

    // Module section header: module_count (u8), reserved (u8),
    // section_size (u32). u32 lets multi-component scenarios (split
    // deployments where producer + viewer/player both embed the
    // canonical wasm shell as http body routes) clear 64 KiB without
    // overflowing the section size; embedded targets (rp/bcm) still
    // fit in the low 16 bits in practice.
    if blob_len < HEADER_SIZE + 6 {
        log::error!(
            "[config] blob too short for module section header: {} < {}",
            blob_len,
            HEADER_SIZE + 6
        );
        return false;
    }
    // SAFETY: `blob_len >= HEADER_SIZE + 6` (checked above); section_size
    // u32 lives at offset 16+2 inside `blob`.
    let section_size = unsafe { read_u32(modules_base.add(2)) } as usize;

    // Validate CRC16-CCITT checksum over body (bytes 8 onwards).
    // Body = header tail (8) + module section (6+section_size) + graph (64) + hw (variable).
    // We read hw counts to compute total size.
    let body_before_hw = 8 + (6 + section_size) + GRAPH_SECTION_SIZE;

    // Hardware section header (6 bytes: spi/i2c/gpio/pio/_/uart) must fit
    // inside the blob too. `body_before_hw` is measured from `flash_ptr+8`,
    // so the absolute offset of the hw header is `8 + body_before_hw`.
    let hw_header_offset = 8 + body_before_hw;
    if blob_len < hw_header_offset + 6 {
        log::error!(
            "[config] section_size={} pushes hw header past blob_len={} (need {})",
            section_size,
            blob_len,
            hw_header_offset + 6
        );
        return false;
    }
    // SAFETY: `blob_len >= hw_header_offset + 6` checked above; the hw
    // header lies at `modules_base + 6 + section_size + GRAPH_SECTION_SIZE`.
    let hw_header_ptr = unsafe { modules_base.add(6 + section_size + GRAPH_SECTION_SIZE) };
    // SAFETY: 6 bytes at hw_header_ptr verified by the bounds check above.
    let (spi_n, i2c_n, gpio_n, pio_n, uart_n) = unsafe {
        (
            (*hw_header_ptr) as usize,
            (*hw_header_ptr.add(1)) as usize,
            (*hw_header_ptr.add(2)) as usize,
            (*hw_header_ptr.add(3)) as usize,
            (*hw_header_ptr.add(5)) as usize,
        )
    };
    let hw_size = 6
        + spi_n * SPI_CONFIG_BIN_SIZE
        + i2c_n * I2C_CONFIG_BIN_SIZE
        + uart_n * UART_CONFIG_BIN_SIZE
        + gpio_n * GPIO_CONFIG_BIN_SIZE
        + pio_n * PIO_CONFIG_BIN_SIZE;
    let body_size = body_before_hw + hw_size;

    // Sanity-check total config size against (a) the existing hard MAX
    // and (b) the caller-provided slice length. The caller's length is the
    // physical upper bound — exceeding it would read past the mapped blob.
    let total_size = 8 + body_size;
    if total_size > MAX_CONFIG_SIZE {
        log::error!("[config] too large size={total_size} max={MAX_CONFIG_SIZE}");
        return false;
    }
    if total_size > blob_len {
        log::error!("[config] body size={total_size} exceeds caller blob length={blob_len}");
        return false;
    }

    if header.checksum != 0 {
        // SAFETY: `total_size = 8 + body_size <= blob_len` checked above.
        let body = unsafe { core::slice::from_raw_parts(flash_ptr.add(8), body_size) };
        let computed = crc16_ccitt(body);
        if computed != header.checksum {
            log::warn!(
                "[config] checksum mismatch stored=0x{:04x} computed=0x{:04x}",
                header.checksum,
                computed
            );
            return false;
        }
    }
    // Bounds-check: module section size should be reasonable.
    // Linux/wasm get a larger ceiling so the wasm-scenario synth
    // host can carry the inlined browser shell (~140 KiB of
    // runtime.html + host_shims.js + scenario.json as http route
    // bodies) — same partition principle as `MAX_CONFIG_SIZE` above,
    // kept in lockstep with it and the CLI's MAX_MODULE_PARAMS_SIZE.
    #[cfg(any(target_os = "linux", target_arch = "wasm32"))]
    const MAX_MODULE_SECTION: usize = 256 * 1024;
    #[cfg(not(any(target_os = "linux", target_arch = "wasm32")))]
    const MAX_MODULE_SECTION: usize = 32 * 1024;
    if section_size > MAX_MODULE_SECTION {
        log::error!(
            "[config] module section too large size={section_size} max={MAX_MODULE_SECTION}"
        );
        return false;
    }

    // Parse variable-length entries. A malformed module section
    // (truncation, undersized entry length, out-of-bounds extent,
    // out-of-range id, arena-alloc failure) rejects the whole config
    // — partial graphs are never accepted.
    let mut offset = 6usize; // Skip 6-byte section header (count, reserved, section_size u32)
    for i in 0..config.module_count as usize {
        // Every entry's 32-bit length prefix must fit inside the
        // declared section.
        if offset + 4 > section_size + 6 {
            log::error!(
                "[config] module entry {i} length prefix past section end (offset={offset}, section_size={section_size})"
            );
            return false;
        }

        // SAFETY: `offset + 4 <= section_size + 6 <= blob_len` per the
        // checks above and the section-size bounds-check on read.
        let entry_ptr = unsafe { modules_base.add(offset) };
        // SAFETY: 4-byte read at entry_ptr is in-bounds (same proof).
        let entry_len = unsafe { read_u32(entry_ptr) } as usize;

        if entry_len < 10 {
            log::error!("[config] module entry {i} bad length={entry_len}");
            return false;
        }

        // The whole entry payload must also fit inside the section.
        if offset + entry_len > section_size + 6 {
            log::error!(
                "[config] module entry {i} extends past section end (offset={offset}, entry_len={entry_len}, section_size={section_size})"
            );
            return false;
        }

        let entry = match parse_module_entry(entry_ptr, entry_len) {
            Some(e) => e,
            None => {
                log::error!("[config] module entry {i} parse failed (arena allocation exhausted)");
                return false;
            }
        };
        if (entry.id as usize) >= MAX_MODULES {
            log::error!(
                "[config] module entry {} id={} out of range (MAX_MODULES={})",
                i,
                entry.id,
                MAX_MODULES
            );
            return false;
        }
        config.modules[entry.id as usize] = Some(entry);

        offset += entry_len;
    }

    // Section base is after module section (6-byte header + entries)
    // SAFETY: `modules_base + 6 + section_size` lies inside the blob
    // (`6 + section_size + GRAPH_SECTION_SIZE` already validated above).
    let section_base = unsafe { modules_base.add(6 + section_size) };

    let edge_count = config.edge_count as usize;

    // Graph section header layout (4 bytes, see tools/src/config.rs):
    //   byte 0: edge_count (redundant with config.edge_count above;
    //           tools writes both so we read the authoritative one
    //           from the counts block)
    //   byte 1: graph_flags — see `GRAPH_FLAG_*` constants
    //   bytes 2-3: reserved (must be 0; future use)
    // SAFETY: graph section is `GRAPH_SECTION_SIZE` bytes from section_base;
    // 4-byte header fits.
    config.graph_flags = unsafe { *section_base.add(1) };

    // Edges start at offset 4 within graph section
    // SAFETY: `section_base + 4` is the start of the edge array.
    let edges_base = unsafe { section_base.add(4) };
    for i in 0..edge_count {
        // SAFETY: `edge_count <= MAX_GRAPH_EDGES` (checked above); each
        // entry is `GRAPH_EDGE_SIZE` bytes, all within the graph section.
        let entry_ptr = unsafe { edges_base.add(i * GRAPH_EDGE_SIZE) };
        config.graph_edges[i] = Some(parse_graph_edge(entry_ptr));
    }

    // Parse domain metadata (16 bytes after edge entries)
    // SAFETY: section_base + 4 + MAX_GRAPH_EDGES * GRAPH_EDGE_SIZE points
    // at the domain meta section within GRAPH_SECTION_SIZE.
    let domain_meta_base = unsafe { section_base.add(4 + MAX_GRAPH_EDGES * GRAPH_EDGE_SIZE) };
    for d in 0..4usize {
        // SAFETY: `d < 4`; 16 bytes of domain meta = 4 × 4-byte entries.
        unsafe {
            let base = domain_meta_base.add(d * 4);
            config.domain_tick_us[d] = read_u16(base);
            config.domain_exec_mode[d] = *base.add(2);
        }
    }

    // Hardware section starts after graph section (80 bytes). Any
    // oversized hardware count (spi/i2c/gpio/pio/uart) causes the
    // whole config to be rejected rather than silently truncating.
    // SAFETY: hw section follows the graph section; `hw_size` already
    // validated against `body_size <= blob_len`.
    let hw_base = unsafe { section_base.add(GRAPH_SECTION_SIZE) };
    config.hardware = match parse_hardware_section(hw_base) {
        Some(hw) => hw,
        None => {
            log::error!("[config] hardware section rejected (oversized counts)");
            return false;
        }
    };

    true
}

// ============================================================================
// Entry Parsers
// ============================================================================

/// Parse variable-length module entry
///
/// Format (10-byte header — entry_length widened to u32 to allow
/// per-module params >64 KiB, needed by the synth host's http
/// module when both halves of a split scenario inline their wasm
/// shells as body routes):
/// - Bytes 0-3: entry_length (u32)
/// - Bytes 4-7: name_hash (u32)
/// - Byte 8: id
/// - Byte 9: reserved/domain_id
/// - Bytes 10+: params
fn parse_module_entry(ptr: *const u8, entry_len: usize) -> Option<ModuleEntry> {
    // SAFETY: caller validated `entry_len >= 10` and that `ptr..ptr+entry_len`
    // lies inside the config blob. All inner reads are bounded by `entry_len`.
    unsafe {
        let name_hash = read_u32(ptr.add(4));
        let id = *ptr.add(8);
        // Byte 9 is multiplexed (see ModuleEntry docs): bits 0-2 carry
        // domain_id (0..7), bit 4 carries pre_tick_drain.
        let byte9 = *ptr.add(9);
        let domain_id = byte9 & 0x07;
        let pre_tick_drain = (byte9 & 0x10) != 0;

        let params_len = entry_len.saturating_sub(10);
        if params_len == 0 {
            return Some(ModuleEntry {
                name_hash,
                id,
                domain_id,
                pre_tick_drain,
                frame_kind: 0,
                params_ptr: core::ptr::null(),
                params_len: 0,
            });
        }

        // Allocate space in arena and copy params
        let arena_buf = arena_alloc(params_len)?;
        core::ptr::copy_nonoverlapping(ptr.add(10), arena_buf.as_mut_ptr(), params_len);

        Some(ModuleEntry {
            name_hash,
            id,
            domain_id,
            pre_tick_drain,
            frame_kind: 0,
            params_ptr: arena_buf.as_ptr(),
            params_len,
        })
    }
}

/// Parse graph edge from binary
///
/// Format (8 bytes):
/// - byte 0:    from_id (u8)
/// - byte 1:    to_id (u8)
/// - byte 2:    bit 7      = to_port (0=in, 1=ctrl)
///   bits [6:5] = edge_class (2-bit)
///   bits [4:0] = buffer_group (5-bit, 0..31)
/// - byte 3:    bits [7:4] = from_port_index (4-bit, 0..15)
///   bits [3:0] = to_port_index   (4-bit, 0..15)
/// - bytes 4-7: buffer_bytes (u32 LE, 0 = no override)
///
/// Both port indices are 4 bits; the runtime caps both at
/// `MAX_PORTS = 16` (scheduler.rs). `buffer_group` is 5 bits — group 0
/// means no aliasing, ids 1..31 mark in-place chains. The tool's
/// `assign_buffer_groups` enforces the 31 ceiling.
fn parse_graph_edge(ptr: *const u8) -> GraphEdge {
    // SAFETY: `ptr..ptr+GRAPH_EDGE_SIZE (= 8)` is in-bounds (caller is
    // the edge-loop which bounds-checked `edge_count * GRAPH_EDGE_SIZE`).
    unsafe {
        let from_id = *ptr;
        let to_id = *ptr.add(1);
        let byte2 = *ptr.add(2);
        let to_port = (byte2 >> 7) & 1;
        let edge_class_raw = (byte2 >> 5) & 0x03;
        let buffer_group = byte2 & 0x1F;
        let port_byte = *ptr.add(3);
        let from_port_index = (port_byte >> 4) & 0x0F;
        let to_port_index = port_byte & 0x0F;
        let buffer_bytes = u32::from_le_bytes([*ptr.add(4), *ptr.add(5), *ptr.add(6), *ptr.add(7)]);
        let edge_class = match edge_class_raw {
            1 => EdgeClass::DmaOwned,
            2 => EdgeClass::CrossCore,
            3 => EdgeClass::NicRing,
            _ => EdgeClass::Local,
        };
        GraphEdge {
            from_id,
            to_id,
            to_port,
            from_port_index,
            to_port_index,
            buffer_group,
            edge_class,
            buffer_bytes,
        }
    }
}

/// Parse hardware section from binary config
///
/// Binary format:
/// ```text
/// Offset 0: spi_count (u8)
/// Offset 1: i2c_count (u8)
/// Offset 2: gpio_count (u8)
/// Offset 3: pio_count (u8)
/// Offset 4: max_gpio (u8)
/// Offset 5: uart_count (u8)
/// Offset 6: spi_configs[spi_count] (8 bytes each)
///           - bus (u8), miso (u8), mosi (u8), sck (u8), freq_hz (u32)
/// Then: i2c_configs[i2c_count] (8 bytes each)
///           - bus (u8), sda (u8), scl (u8), reserved (u8), freq_hz (u32)
/// Then: uart_configs[uart_count] (8 bytes each)
///           - bus (u8), tx_pin (u8), rx_pin (u8), reserved (u8), baudrate (u32)
/// Then: gpio_configs[gpio_count] (5 bytes each)
///           - pin (u8), flags (u8), initial (u8), owner_module_id (u8), reserved (u8)
///           - flags: bit0 = direction (0=in, 1=out), bit1-2 = pull (0=none, 1=up, 2=down)
///           - owner_module_id: 0xFF = kernel-owned, 0-7 = module index to grant to
/// Then: pio_configs[pio_count] (4 bytes each)
///           - pio_idx (u8), data_pin (u8), clk_pin (u8), extra_pin (u8)
///           - extra_pin: 0xFF = unused
/// ```
/// Hardware-count fields are rejected, not clamped: any `*_count`
/// value exceeding the corresponding `MAX_*` constant returns `None`
/// so the enclosing parser fails the whole graph. Silent truncation
/// would let a config asking for 10 SPI buses on a 2-bus platform
/// parse 2 and drop the other 8 without surfacing the mismatch.
fn parse_hardware_section(ptr: *const u8) -> Option<HardwareConfig> {
    let mut hw = HardwareConfig::default();

    // SAFETY: caller (`read_config_from_slice`) bounds-checked `hw_size`
    // against `blob_len`; this body validates counts against MAX_* before
    // offsetting through the per-section arrays.
    unsafe {
        let spi_count_raw = *ptr;
        let i2c_count_raw = *ptr.add(1);
        let gpio_count_raw = *ptr.add(2);
        let pio_count_raw = *ptr.add(3);
        let max_gpio = *ptr.add(4);
        let uart_count_raw = *ptr.add(5);

        if spi_count_raw as usize > MAX_SPI_BUSES {
            log::error!("[config] spi_count={spi_count_raw} exceeds MAX_SPI_BUSES={MAX_SPI_BUSES}");
            return None;
        }
        if i2c_count_raw as usize > MAX_I2C_BUSES {
            log::error!("[config] i2c_count={i2c_count_raw} exceeds MAX_I2C_BUSES={MAX_I2C_BUSES}");
            return None;
        }
        if gpio_count_raw as usize > MAX_GPIO_CONFIGS {
            log::error!(
                "[config] gpio_count={gpio_count_raw} exceeds MAX_GPIO_CONFIGS={MAX_GPIO_CONFIGS}"
            );
            return None;
        }
        if pio_count_raw as usize > MAX_PIO_CONFIGS {
            log::error!(
                "[config] pio_count={pio_count_raw} exceeds MAX_PIO_CONFIGS={MAX_PIO_CONFIGS}"
            );
            return None;
        }
        if uart_count_raw as usize > MAX_UART_BUSES {
            log::error!(
                "[config] uart_count={uart_count_raw} exceeds MAX_UART_BUSES={MAX_UART_BUSES}"
            );
            return None;
        }

        let spi_count = spi_count_raw as usize;
        let i2c_count = i2c_count_raw as usize;
        let gpio_count = gpio_count_raw as usize;
        let pio_count = pio_count_raw as usize;
        let uart_count = uart_count_raw as usize;
        if max_gpio > 0 {
            hw.max_gpio = max_gpio;
        }

        // Parse SPI configs (starting at offset 6)
        let mut offset = 6usize;
        for i in 0..spi_count {
            let entry = ptr.add(offset);
            hw.spi[i] = Some(SpiConfig {
                bus: *entry,
                miso: *entry.add(1),
                mosi: *entry.add(2),
                sck: *entry.add(3),
                freq_hz: read_u32(entry.add(4)),
            });
            offset += SPI_CONFIG_BIN_SIZE;
        }

        // Parse I2C configs
        for i in 0..i2c_count {
            let entry = ptr.add(offset);
            hw.i2c[i] = Some(I2cConfig {
                bus: *entry,
                sda: *entry.add(1),
                scl: *entry.add(2),
                // byte 3 is reserved
                freq_hz: read_u32(entry.add(4)),
            });
            offset += I2C_CONFIG_BIN_SIZE;
        }

        // Parse UART configs (8 bytes each): bus, tx_pin, rx_pin, reserved, baudrate(u32)
        for i in 0..uart_count {
            let entry = ptr.add(offset);
            hw.uart[i] = Some(UartConfig {
                bus: *entry,
                tx_pin: *entry.add(1),
                rx_pin: *entry.add(2),
                // byte 3 is reserved
                baudrate: read_u32(entry.add(4)),
            });
            offset += UART_CONFIG_BIN_SIZE;
        }

        // Parse GPIO configs (5 bytes each):
        // byte 0: pin, byte 1: flags, byte 2: initial, byte 3: owner_module_id, byte 4: reserved
        for i in 0..gpio_count {
            let entry = ptr.add(offset);
            let pin = *entry;
            let flags = *entry.add(1);
            let initial = *entry.add(2);
            let owner_module_id = *entry.add(3);

            let direction = if flags & 0x01 != 0 {
                GpioDirection::Output
            } else {
                GpioDirection::Input
            };

            let pull = match (flags >> 1) & 0x03 {
                1 => GpioPull::Up,
                2 => GpioPull::Down,
                _ => GpioPull::None,
            };

            let level = if initial != 0 {
                GpioLevel::High
            } else {
                GpioLevel::Low
            };

            hw.gpio[i] = Some(GpioConfig {
                pin,
                direction,
                pull,
                initial: level,
                owner_module_id,
            });
            offset += GPIO_CONFIG_BIN_SIZE;
        }

        // Parse PIO configs (4 bytes each): pio_idx, data_pin, clk_pin, extra_pin
        for i in 0..pio_count {
            let entry = ptr.add(offset);
            hw.pio[i] = Some(PioConfig {
                pio_idx: *entry,
                data_pin: *entry.add(1),
                clk_pin: *entry.add(2),
                extra_pin: *entry.add(3),
            });
            offset += PIO_CONFIG_BIN_SIZE;
        }
    }

    Some(hw)
}

// ============================================================================
// Helpers
// ============================================================================

#[inline]
unsafe fn read_u16(ptr: *const u8) -> u16 {
    u16::from_le_bytes([
        core::ptr::read_volatile(ptr),
        core::ptr::read_volatile(ptr.add(1)),
    ])
}

#[inline]
unsafe fn read_u32(ptr: *const u8) -> u32 {
    u32::from_le_bytes([
        core::ptr::read_volatile(ptr),
        core::ptr::read_volatile(ptr.add(1)),
        core::ptr::read_volatile(ptr.add(2)),
        core::ptr::read_volatile(ptr.add(3)),
    ])
}

/// CRC16-CCITT checksum (matches tools/src/config.rs)
fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}
