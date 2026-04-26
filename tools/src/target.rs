//! Target configuration loader.
//!
//! Loads silicon and board TOML definitions from the `targets/` directory
//! and provides a unified `TargetDescriptor` for validation and build.
//!
//! Resolution: `load_target("pico2w")` checks `targets/boards/pico2w.toml` first
//! (which references silicon "rp2350a"), then falls back to `targets/silicon/pico2w.toml`.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

use crate::error::{Error, Result};

// ── TOML deserialization structs ────────────────────────────────────────────

#[derive(Deserialize)]
struct TomlSiliconFile {
    target: TomlTargetMeta,
    build: Option<TomlBuildConfig>,
    gpio: TomlGpioConfig,
    peripherals: TomlPeripherals,
    memory: Option<TomlMemoryConfig>,
    kernel: Option<TomlKernelConfig>,
    isolation: Option<TomlIsolationConfig>,
}

#[derive(Deserialize, Default)]
struct TomlKernelConfig {
    state_arena_kb: Option<u32>,
}

#[derive(Deserialize, Default)]
struct TomlIsolationConfig {
    mpu_regions: Option<u8>,
    has_mmu: Option<bool>,
}

#[derive(Deserialize)]
struct TomlTargetMeta {
    id: String,
    family: String,
    description: String,
}

#[derive(Deserialize)]
struct TomlBuildConfig {
    rust_target: String,
    cargo_features: Vec<String>,
    uf2_family_id: String,
    module_target: String,
}

#[derive(Deserialize)]
struct TomlGpioConfig {
    max_pin: Option<u8>,
    reserved_pins: Option<Vec<u8>>,
    reserved_reasons: Option<HashMap<String, String>>,
}

#[derive(Deserialize)]
struct TomlPeripherals {
    spi_count: u8,
    i2c_count: u8,
    uart_count: u8,
    adc_channels: u8,
    pwm_slices: u8,
    pio_count: u8,
    pio_state_machines: u8,
    dma_channels: u8,
    spi0: Option<TomlPinTableEntry>,
    spi1: Option<TomlPinTableEntry>,
    spi2: Option<TomlPinTableEntry>,
    i2c0: Option<TomlPinTableEntry>,
    i2c1: Option<TomlPinTableEntry>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TomlPinTableEntry {
    Any { valid_pins: TomlPinTableKind },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TomlPinTableKind {
    Any(String),
    Explicit(Vec<Vec<u8>>),
}

#[derive(Deserialize)]
struct TomlMemoryConfig {
    flash_base: String,
    flash_size: String,
    ram_base: String,
    ram_size: String,
}

#[derive(Deserialize)]
struct TomlBoardFile {
    board: TomlBoardMeta,
    build: Option<TomlBoardBuild>,
    gpio: Option<TomlGpioConfig>,
    hardware: Option<TomlBoardHardware>,
    /// Platform stack defaults (e.g. [platform.net] phy="wifi", driver="cyw43")
    platform: Option<std::collections::HashMap<String, std::collections::HashMap<String, String>>>,
}

/// Board-level build overrides. Only present for boards that need cargo
/// features beyond the silicon defaults (e.g. `board-cm5` selects Pi 5
/// RAM origin and RP1 init). Unspecified fields inherit from silicon.
#[derive(Deserialize)]
struct TomlBoardBuild {
    rust_target: Option<String>,
    module_target: Option<String>,
    /// Cargo features to add on top of silicon's features.
    cargo_features: Option<Vec<String>>,
}

#[derive(Deserialize, Clone)]
struct TomlBoardHardware {
    spi: Option<Vec<toml::Value>>,
    pio: Option<Vec<toml::Value>>,
}

#[derive(Deserialize)]
struct TomlBoardMeta {
    id: String,
    silicon: String,
    description: String,
}

// ── Public types ────────────────────────────────────────────────────────────

/// Resolved target descriptor combining silicon + optional board info.
#[derive(Debug, Clone)]
pub struct TargetDescriptor {
    /// Silicon target id (e.g. "rp2350a")
    pub id: String,
    /// Silicon family (e.g. "rp2", "esp32")
    pub family: String,
    /// Human description of the silicon
    pub description: String,
    /// Board id, if loaded via board file (e.g. "pico2w")
    pub board_id: Option<String>,
    /// Board description, if loaded via board file
    pub board_description: Option<String>,
    /// Build configuration (None for validation-only targets)
    pub build: Option<BuildConfig>,
    /// Maximum GPIO pin number (inclusive)
    pub max_pin: u8,
    /// Reserved pins on this board
    pub reserved_pins: Vec<u8>,
    /// Reason string for each reserved pin
    pub reserved_reasons: HashMap<u8, String>,
    /// Peripheral counts
    pub spi_count: u8,
    pub i2c_count: u8,
    pub uart_count: u8,
    pub adc_channels: u8,
    pub pwm_slices: u8,
    pub pio_count: u8,
    pub pio_state_machines: u8,
    pub dma_channels: u8,
    /// Valid SPI pin tables (indexed by bus number)
    pub spi_pins: Vec<PinTable>,
    /// Valid I2C pin tables (indexed by bus number)
    pub i2c_pins: Vec<PinTable>,
    /// Memory layout
    pub memory: Option<MemoryConfig>,
    /// Board-level hardware defaults (merged when YAML omits a section)
    pub hardware_defaults: Option<serde_json::Value>,
    /// Platform stack defaults from board TOML (e.g. net → {phy: wifi, driver: cyw43})
    pub platform_defaults:
        std::collections::HashMap<String, std::collections::HashMap<String, String>>,
    /// State arena size in KB (from [kernel] section, default 256)
    pub state_arena_kb: u32,
    /// Number of MPU regions available (0 = no MPU, e.g. Cortex-M0+)
    pub mpu_regions: u8,
    /// Whether the target has an MMU (for full page-table isolation)
    pub has_mmu: bool,
}

/// Build configuration for targets that support kernel compilation.
#[derive(Debug, Clone)]
pub struct BuildConfig {
    pub rust_target: String,
    pub cargo_features: Vec<String>,
    pub uf2_family_id: u32,
    pub module_target: String,
}

/// Pin assignment table for a peripheral bus.
#[derive(Debug, Clone)]
pub enum PinTable {
    /// Explicit list of valid pin combinations
    Explicit(Vec<Vec<u8>>),
    /// Any GPIO pin is valid (e.g. ESP32 GPIO matrix)
    Any,
    /// No pin table defined
    None,
}

/// Memory region layout.
#[derive(Debug, Clone)]
pub struct MemoryConfig {
    pub flash_base: u32,
    pub flash_size: u32,
    pub ram_base: u32,
    pub ram_size: u32,
}

// ── Implementation ──────────────────────────────────────────────────────────

impl TargetDescriptor {
    /// Check if an SPI pin combination is valid for the given bus.
    pub fn is_valid_spi_pins(&self, bus: u8, miso: u8, mosi: u8, sck: u8) -> bool {
        let table = self.spi_pins.get(bus as usize).unwrap_or(&PinTable::None);
        match table {
            PinTable::Any => true,
            PinTable::None => false,
            PinTable::Explicit(combos) => combos
                .iter()
                .any(|c| c.len() >= 3 && c[0] == miso && c[1] == mosi && c[2] == sck),
        }
    }

    /// Check if an I2C pin combination is valid for the given bus.
    pub fn is_valid_i2c_pins(&self, bus: u8, sda: u8, scl: u8) -> bool {
        let table = self.i2c_pins.get(bus as usize).unwrap_or(&PinTable::None);
        match table {
            PinTable::Any => true,
            PinTable::None => false,
            PinTable::Explicit(combos) => combos
                .iter()
                .any(|c| c.len() >= 2 && c[0] == sda && c[1] == scl),
        }
    }

    /// Check if a pin is reserved on this board. Returns reason if reserved.
    pub fn is_reserved_pin(&self, pin: u8) -> Option<&str> {
        if self.reserved_pins.contains(&pin) {
            self.reserved_reasons
                .get(&pin)
                .map(|s| s.as_str())
                .or(Some("reserved"))
        } else {
            None
        }
    }

    /// Build id used for firmware + packed-image output paths.
    /// Equals the board id when loaded as a board, otherwise the silicon id.
    /// Modules live under the silicon id (`self.id`) regardless.
    pub fn build_id(&self) -> &str {
        self.board_id.as_deref().unwrap_or(&self.id)
    }

    /// Display name: "pico2w (RP2350A)" or just "rp2350a (RP2350A)"
    pub fn display_name(&self) -> String {
        if let Some(ref board) = self.board_id {
            format!("{} ({})", board, self.description)
        } else {
            format!("{} ({})", self.id, self.description)
        }
    }
}

/// Load and resolve a target by name.
///
/// Resolution order:
/// 1. Check `targets/boards/{name}.toml` — if found, load board + referenced silicon
/// 2. Check `targets/silicon/{name}.toml` — if found, load silicon directly
/// 3. Error: unknown target
pub fn load_target(name: &str, project_root: &Path) -> Result<TargetDescriptor> {
    let targets_dir = project_root.join("targets");

    // Try board first
    let board_path = targets_dir.join("boards").join(format!("{}.toml", name));
    if board_path.exists() {
        return load_board_target(&board_path, &targets_dir);
    }

    // Try silicon
    let silicon_path = targets_dir.join("silicon").join(format!("{}.toml", name));
    if silicon_path.exists() {
        return load_silicon_target(&silicon_path);
    }

    // List available targets for error message
    let available = list_targets(project_root);
    Err(Error::Config(format!(
        "Unknown target '{}'. Available: {}",
        name,
        if available.is_empty() {
            "none (missing targets/ directory?)".to_string()
        } else {
            available.join(", ")
        }
    )))
}

/// List all available target names (boards + silicon).
pub fn list_targets(project_root: &Path) -> Vec<String> {
    let targets_dir = project_root.join("targets");
    let mut names = Vec::new();

    // Boards first (more user-friendly)
    if let Ok(entries) = std::fs::read_dir(targets_dir.join("boards")) {
        for entry in entries.flatten() {
            if let Some(name) = entry
                .path()
                .file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.to_string())
            {
                names.push(name);
            }
        }
    }

    // Then silicon
    if let Ok(entries) = std::fs::read_dir(targets_dir.join("silicon")) {
        for entry in entries.flatten() {
            if let Some(name) = entry
                .path()
                .file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.to_string())
            {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
    }

    names.sort();
    names
}

// ── Internal loading ────────────────────────────────────────────────────────

fn load_silicon_target(path: &Path) -> Result<TargetDescriptor> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("Failed to read {}: {}", path.display(), e)))?;
    let silicon: TomlSiliconFile = toml::from_str(&content)
        .map_err(|e| Error::Config(format!("Failed to parse {}: {}", path.display(), e)))?;

    let build = silicon.build.map(|b| {
        let uf2_id = parse_hex_u32(&b.uf2_family_id).unwrap_or(0);
        BuildConfig {
            rust_target: b.rust_target,
            cargo_features: b.cargo_features,
            uf2_family_id: uf2_id,
            module_target: b.module_target,
        }
    });

    let memory = silicon.memory.map(|m| MemoryConfig {
        flash_base: parse_hex_u32(&m.flash_base).unwrap_or(0),
        flash_size: parse_hex_u32(&m.flash_size).unwrap_or(0),
        ram_base: parse_hex_u32(&m.ram_base).unwrap_or(0),
        ram_size: parse_hex_u32(&m.ram_size).unwrap_or(0),
    });

    let p = &silicon.peripherals;

    Ok(TargetDescriptor {
        id: silicon.target.id,
        family: silicon.target.family,
        description: silicon.target.description,
        board_id: None,
        board_description: None,
        build,
        max_pin: silicon.gpio.max_pin.unwrap_or(29),
        reserved_pins: Vec::new(),
        reserved_reasons: HashMap::new(),
        spi_count: p.spi_count,
        i2c_count: p.i2c_count,
        uart_count: p.uart_count,
        adc_channels: p.adc_channels,
        pwm_slices: p.pwm_slices,
        pio_count: p.pio_count,
        pio_state_machines: p.pio_state_machines,
        dma_channels: p.dma_channels,
        spi_pins: build_spi_tables(p),
        i2c_pins: build_i2c_tables(p),
        memory,
        hardware_defaults: None,
        platform_defaults: std::collections::HashMap::new(),
        state_arena_kb: silicon
            .kernel
            .as_ref()
            .and_then(|k| k.state_arena_kb)
            .unwrap_or(256),
        mpu_regions: silicon
            .isolation
            .as_ref()
            .and_then(|i| i.mpu_regions)
            .unwrap_or(0),
        has_mmu: silicon
            .isolation
            .as_ref()
            .and_then(|i| i.has_mmu)
            .unwrap_or(false),
    })
}

fn load_board_target(board_path: &Path, targets_dir: &Path) -> Result<TargetDescriptor> {
    let content = std::fs::read_to_string(board_path)
        .map_err(|e| Error::Config(format!("Failed to read {}: {}", board_path.display(), e)))?;
    let board: TomlBoardFile = toml::from_str(&content)
        .map_err(|e| Error::Config(format!("Failed to parse {}: {}", board_path.display(), e)))?;

    // Load referenced silicon target
    let silicon_path = targets_dir
        .join("silicon")
        .join(format!("{}.toml", board.board.silicon));
    if !silicon_path.exists() {
        return Err(Error::Config(format!(
            "Board '{}' references silicon '{}', but {} not found",
            board.board.id,
            board.board.silicon,
            silicon_path.display()
        )));
    }

    let mut desc = load_silicon_target(&silicon_path)?;

    // Overlay board info
    desc.board_id = Some(board.board.id);
    desc.board_description = Some(board.board.description);

    // Overlay GPIO reservations from board
    if let Some(gpio) = board.gpio {
        if let Some(pins) = gpio.reserved_pins {
            desc.reserved_pins = pins;
        }
        if let Some(reasons) = gpio.reserved_reasons {
            desc.reserved_reasons = reasons
                .into_iter()
                .filter_map(|(k, v)| k.parse::<u8>().ok().map(|pin| (pin, v)))
                .collect();
        }
    }

    // Convert board hardware defaults to JSON for config merging
    if let Some(hw) = board.hardware {
        let mut map = serde_json::Map::new();
        if let Some(spi) = hw.spi {
            let arr: Vec<serde_json::Value> = spi
                .iter()
                .filter_map(|v| serde_json::to_value(v).ok())
                .collect();
            map.insert("spi".into(), serde_json::Value::Array(arr));
        }
        if let Some(pio) = hw.pio {
            let arr: Vec<serde_json::Value> = pio
                .iter()
                .filter_map(|v| serde_json::to_value(v).ok())
                .collect();
            map.insert("pio".into(), serde_json::Value::Array(arr));
        }
        if !map.is_empty() {
            desc.hardware_defaults = Some(serde_json::Value::Object(map));
        }
    }

    // Platform stack defaults (e.g. [platform.net] phy="wifi")
    if let Some(platform) = board.platform {
        desc.platform_defaults = platform;
    }

    // Merge board-level build overrides onto silicon's build config. Only
    // used by boards that need extra cargo features (cm5 adds `board-cm5`).
    if let Some(bb) = board.build {
        if let Some(ref mut build) = desc.build {
            if let Some(rt) = bb.rust_target {
                build.rust_target = rt;
            }
            if let Some(mt) = bb.module_target {
                build.module_target = mt;
            }
            if let Some(features) = bb.cargo_features {
                for f in features {
                    if !build.cargo_features.contains(&f) {
                        build.cargo_features.push(f);
                    }
                }
            }
        }
    }

    Ok(desc)
}

fn build_spi_tables(p: &TomlPeripherals) -> Vec<PinTable> {
    vec![
        convert_pin_table(&p.spi0),
        convert_pin_table(&p.spi1),
        convert_pin_table(&p.spi2),
    ]
}

fn build_i2c_tables(p: &TomlPeripherals) -> Vec<PinTable> {
    vec![convert_pin_table(&p.i2c0), convert_pin_table(&p.i2c1)]
}

fn convert_pin_table(entry: &Option<TomlPinTableEntry>) -> PinTable {
    match entry {
        None => PinTable::None,
        Some(TomlPinTableEntry::Any { valid_pins }) => match valid_pins {
            TomlPinTableKind::Any(s) if s == "any" => PinTable::Any,
            TomlPinTableKind::Any(_) => PinTable::None,
            TomlPinTableKind::Explicit(combos) => PinTable::Explicit(combos.clone()),
        },
    }
}

fn parse_hex_u32(s: &str) -> Option<u32> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u32>().ok()
    }
}
