//! Configuration and hardware structures.
//!
//! This module provides:
//! - Binary configuration reader for FXWR format config from flash
//! - Hardware configuration structures for SPI, I2C, and GPIO
//! - Runtime hardware context tracking
//! - Hardware manager for initialization
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
        let end_data = unsafe { &__end_data_addr as *const u8 as u32 };
        (end_data + 255) & !255
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
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

    let a = unsafe { decode_slot_header(slot_a) };
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
        config_addr: slot_base + hdr.config_offset,
    })
}

#[cfg(feature = "rp")]
struct SlotHeader {
    epoch: u64,
    modules_offset: u32,
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

    unsafe {
        let magic = read_u32(trailer_ptr);

        if magic != TRAILER_MAGIC {
            log::error!(
                "[config] bad trailer magic=0x{:08x} addr=0x{:08x}",
                magic,
                trailer_addr
            );
            return None;
        }

        let version = *trailer_ptr.add(4);
        if version != TRAILER_VERSION {
            log::error!("[config] unsupported trailer version={}", version);
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
            config_addr,
        })
    }
}

/// Maximum counts.
///
/// MAX_MODULES=64 accommodates graphs like Quantum (42 modules). The event
/// wake bitmap in `kernel/event.rs` is u64 to match.
pub const MAX_MODULES: usize = 64;
pub const MAX_GRAPH_EDGES: usize = 128;

/// Hardware section binary format sizes
pub const SPI_CONFIG_BIN_SIZE: usize = 8;
pub const I2C_CONFIG_BIN_SIZE: usize = 8;
pub const UART_CONFIG_BIN_SIZE: usize = 8;
pub const GPIO_CONFIG_BIN_SIZE: usize = 5;
pub const PIO_CONFIG_BIN_SIZE: usize = 4;

/// Graph section binary format sizes
pub const GRAPH_EDGE_SIZE: usize = 4;
pub const GRAPH_SECTION_SIZE: usize = 4 + MAX_GRAPH_EDGES * GRAPH_EDGE_SIZE + 16; // header + edges + domain metadata

// ============================================================================
// Graph Config (Version 1: Variable-Length Module Entries)
// ============================================================================

/// Config arena size for storing variable-length module params across all
/// modules in the loaded graph. Per-chip so embedded targets don't carry a
/// host-class arena in `.bss`. See each platform's `chip` module.
pub const CONFIG_ARENA_SIZE: usize = super::chip::CONFIG_ARENA_SIZE;

/// Static arena for module params storage
static mut CONFIG_ARENA: [u8; CONFIG_ARENA_SIZE] = [0; CONFIG_ARENA_SIZE];
static mut ARENA_OFFSET: usize = 0;

/// Allocate bytes from config arena (bump allocator)
/// Returns None if arena is exhausted
fn arena_alloc(size: usize) -> Option<&'static mut [u8]> {
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
    unsafe {
        ARENA_OFFSET = 0;
    }
}

/// Parsed module entry with variable-length params
///
/// Binary format (variable length):
/// - Bytes 0-1: entry_length (u16) - total entry size including header
/// - Bytes 2-5: name_hash (fnv1a32)
/// - Byte 6: id
/// - Byte 7: domain_id (0 = default domain)
/// - Bytes 8+: params (entry_length - 8 bytes)
#[derive(Debug, Clone, Copy)]
pub struct ModuleEntry {
    pub name_hash: u32,
    pub id: u8,
    /// Execution domain ID (0 = default domain)
    pub domain_id: u8,
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
    /// Binary encoding: 7 bits (0..127) in byte 2 bits [6:0] of the graph edge
    /// (bit 7 of byte 2 is `to_port`). See `parse_graph_edge`.
    pub buffer_group: u8,
    /// Edge class metadata (Local, DmaOwned, CrossCore).
    /// Encoded in bits [5:4] of byte 3. Pure metadata on single-core; no runtime cost.
    pub edge_class: EdgeClass,
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
}

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
    read_config_from_ptr(config_addr as *const u8, config)
}

/// Read config from a memory pointer directly into provided destination.
///
/// Works with any memory-mapped config blob (flash on RP, embedded blob on aarch64).
pub fn read_config_from_ptr(flash_ptr: *const u8, config: &mut Config) -> bool {
    // Read header (16 bytes)
    let header = unsafe {
        let magic = read_u32(flash_ptr);
        if magic != MAGIC_CONFIG {
            log::warn!("[config] bad magic=0x{:08x}", magic);
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

    if header.version != 1 {
        log::error!("[config] unsupported version={}", header.version);
        return false;
    }

    config.module_count = header.module_count.min(MAX_MODULES as u8);
    config.edge_count = header.edge_count.min(MAX_GRAPH_EDGES as u8);

    // Parse modules - variable-length entries
    let modules_base = unsafe { flash_ptr.add(16) };

    // Module section header: module_count (u8), reserved (u8), section_size (u16)
    let section_size = unsafe { read_u16(modules_base.add(2)) } as usize;

    // Validate CRC16-CCITT checksum over body (bytes 8 onwards).
    // Body = header tail (8) + module section (4+section_size) + graph (64) + hw (variable).
    // We read hw counts to compute total size.
    let body_before_hw = 8 + (4 + section_size) + GRAPH_SECTION_SIZE;
    let hw_header_ptr = unsafe { modules_base.add(4 + section_size + GRAPH_SECTION_SIZE) };
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

    // Sanity-check total config size against flash bounds
    let total_size = 8 + body_size;
    const MAX_CONFIG_SIZE: usize = 32 * 1024;
    if total_size > MAX_CONFIG_SIZE {
        log::error!(
            "[config] too large size={} max={}",
            total_size,
            MAX_CONFIG_SIZE
        );
        return false;
    }

    if header.checksum != 0 {
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
    // Bounds-check: module section size should be reasonable
    const MAX_MODULE_SECTION: usize = 32 * 1024;
    if section_size > MAX_MODULE_SECTION {
        log::error!(
            "[config] module section too large size={} max={}",
            section_size,
            MAX_MODULE_SECTION
        );
        return false;
    }

    // Parse variable-length entries
    let mut offset = 4usize; // Skip section header
    for _ in 0..config.module_count as usize {
        if offset >= section_size + 4 {
            log::warn!("[config] module section truncated");
            break;
        }

        let entry_ptr = unsafe { modules_base.add(offset) };
        let entry_len = unsafe { read_u16(entry_ptr) } as usize;

        if entry_len < 8 {
            log::warn!("[config] bad entry length={}", entry_len);
            break;
        }

        let entry = parse_module_entry(entry_ptr, entry_len);
        if let Some(e) = entry {
            if e.id < MAX_MODULES as u8 {
                config.modules[e.id as usize] = Some(e);
            } else {
                log::warn!("[config] module id={} out of range", e.id);
            }
        }

        offset += entry_len;
    }

    // Section base is after module section (header + entries)
    let section_base = unsafe { modules_base.add(4 + section_size) };

    let edge_count = config.edge_count as usize;

    // Edges start at offset 4 within graph section
    let edges_base = unsafe { section_base.add(4) };
    for i in 0..edge_count {
        let entry_ptr = unsafe { edges_base.add(i * GRAPH_EDGE_SIZE) };
        config.graph_edges[i] = Some(parse_graph_edge(entry_ptr));
    }

    // Parse domain metadata (16 bytes after edge entries)
    let domain_meta_base = unsafe { section_base.add(4 + MAX_GRAPH_EDGES * GRAPH_EDGE_SIZE) };
    for d in 0..4usize {
        unsafe {
            let base = domain_meta_base.add(d * 4);
            config.domain_tick_us[d] = read_u16(base);
            config.domain_exec_mode[d] = *base.add(2);
        }
    }

    // Hardware section starts after graph section (80 bytes)
    let hw_base = unsafe { section_base.add(GRAPH_SECTION_SIZE) };
    config.hardware = parse_hardware_section(hw_base);

    true
}

// ============================================================================
// Entry Parsers
// ============================================================================

/// Parse variable-length module entry
///
/// Format:
/// - Bytes 0-1: entry_length (u16)
/// - Bytes 2-5: name_hash (u32)
/// - Byte 6: id
/// - Byte 7: reserved
/// - Bytes 8+: params
fn parse_module_entry(ptr: *const u8, entry_len: usize) -> Option<ModuleEntry> {
    unsafe {
        let name_hash = read_u32(ptr.add(2));
        let id = *ptr.add(6);
        let domain_id = *ptr.add(7);

        let params_len = entry_len.saturating_sub(8);
        if params_len == 0 {
            return Some(ModuleEntry {
                name_hash,
                id,
                domain_id,
                params_ptr: core::ptr::null(),
                params_len: 0,
            });
        }

        // Allocate space in arena and copy params
        let arena_buf = arena_alloc(params_len)?;
        core::ptr::copy_nonoverlapping(ptr.add(8), arena_buf.as_mut_ptr(), params_len);

        Some(ModuleEntry {
            name_hash,
            id,
            domain_id,
            params_ptr: arena_buf.as_ptr(),
            params_len,
        })
    }
}

/// Parse graph edge from binary
///
/// Format (4 bytes):
/// - byte 0: from_id (u8)
/// - byte 1: to_id (u8)
/// - byte 2: bit 7      = to_port (0=in, 1=ctrl)
///   bits [6:5] = edge_class (2-bit)
///   bits [4:0] = buffer_group (5-bit, 0..31)
/// - byte 3: bits [7:4] = from_port_index (4-bit, 0..15)
///   bits [3:0] = to_port_index   (4-bit, 0..15)
///
/// Both port indices are 4 bits; the runtime caps both at
/// `MAX_PORTS = 16` (scheduler.rs). `buffer_group` is 5 bits — group 0
/// means no aliasing, ids 1..31 mark in-place chains. The tool's
/// `assign_buffer_groups` enforces the 31 ceiling.
fn parse_graph_edge(ptr: *const u8) -> GraphEdge {
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
fn parse_hardware_section(ptr: *const u8) -> HardwareConfig {
    let mut hw = HardwareConfig::default();

    unsafe {
        let spi_count = (*ptr).min(MAX_SPI_BUSES as u8) as usize;
        let i2c_count = (*ptr.add(1)).min(MAX_I2C_BUSES as u8) as usize;
        let gpio_count = (*ptr.add(2)).min(MAX_GPIO_CONFIGS as u8) as usize;
        let pio_count = (*ptr.add(3)).min(MAX_PIO_CONFIGS as u8) as usize;
        let max_gpio = *ptr.add(4);
        let uart_count = (*ptr.add(5)).min(MAX_UART_BUSES as u8) as usize;
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

    hw
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

// ============================================================================
// Hardware Manager
// ============================================================================

/// Default SPI configuration (Pico 2 W SD card pins)
const DEFAULT_SPI: SpiConfig = SpiConfig {
    bus: 0,
    miso: 16,
    mosi: 19,
    sck: 18,
    freq_hz: 400_000,
};

/// Default I2C configuration (Pico 2 W: I2C0 on GPIO 20/21)
const DEFAULT_I2C: I2cConfig = I2cConfig {
    bus: 0,
    sda: 20,
    scl: 21,
    freq_hz: 400_000,
};

/// Default PIO cmd configuration (Pico 2 W: PIO1, cyw43 gSPI DIO=24, CLK=29)
const DEFAULT_PIO_CMD: PioConfig = PioConfig {
    pio_idx: 1,
    data_pin: 24,
    clk_pin: 29,
    extra_pin: 0xFF,
};

/// Default PIO stream configuration (Pico 2 W: PIO0, I2S data=28, bclk=26, lrclk=27)
const DEFAULT_PIO_STREAM: PioConfig = PioConfig {
    pio_idx: 0,
    data_pin: 28,
    clk_pin: 26,
    extra_pin: 27,
};

/// Hardware manager - reads config and provides initialization helpers
pub struct Hardware {
    config: HardwareConfig,
}

impl Hardware {
    /// Create hardware manager, reading config from flash or using defaults
    pub fn new() -> Self {
        let config = match read_config() {
            Some(c) => {
                let mut hw = c.hardware.clone();
                if hw.spi[0].is_none() && hw.spi[1].is_none() {
                    hw.spi[0] = Some(DEFAULT_SPI);
                }
                hw
            }
            None => {
                // No config blob — bare firmware boot (Pico 2 W defaults)
                let mut hw = HardwareConfig::new();
                hw.spi[0] = Some(DEFAULT_SPI);
                hw.pio[0] = Some(DEFAULT_PIO_CMD);
                hw.pio[1] = Some(DEFAULT_PIO_STREAM);
                hw
            }
        };
        Self { config }
    }

    /// Get SPI configuration
    pub fn spi(&self) -> SpiConfig {
        self.config.spi[0]
            .or(self.config.spi[1])
            .unwrap_or(DEFAULT_SPI)
    }

    /// Get SPI bus number
    pub fn spi_bus(&self) -> u8 {
        self.spi().bus
    }

    /// Get CS pin number (first output GPIO)
    pub fn cs_pin(&self) -> u8 {
        self.config
            .gpio
            .iter()
            .flatten()
            .find(|g| g.direction == GpioDirection::Output)
            .map(|g| g.pin)
            .unwrap_or(17)
    }

    /// Get I2C configuration (first configured bus or default)
    pub fn i2c(&self) -> I2cConfig {
        self.config.i2c[0]
            .or(self.config.i2c[1])
            .unwrap_or(DEFAULT_I2C)
    }

    /// Get PIO cmd configuration (slot 0: bidirectional gSPI for cyw43)
    pub fn pio_cmd(&self) -> PioConfig {
        self.config.pio[0].unwrap_or(DEFAULT_PIO_CMD)
    }

    /// Get PIO stream configuration (slot 1: I2S output)
    pub fn pio_stream(&self) -> PioConfig {
        self.config.pio[1].unwrap_or(DEFAULT_PIO_STREAM)
    }

    /// Get GPIO config for a specific pin
    pub fn gpio(&self, pin: u8) -> Option<&GpioConfig> {
        self.config.gpio.iter().flatten().find(|g| g.pin == pin)
    }

    /// Get raw GPIO configs
    pub fn gpio_configs(&self) -> &[Option<GpioConfig>; MAX_GPIO_CONFIGS] {
        &self.config.gpio
    }

    /// Get raw hardware config for the planner
    pub fn raw_config(&self) -> &HardwareConfig {
        &self.config
    }

    /// Initialize all GPIO pins from config
    pub fn init_gpio(&self) -> usize {
        (crate::kernel::hal::init_gpio)(&self.config.gpio)
    }
}

impl Default for Hardware {
    fn default() -> Self {
        Self::new()
    }
}
