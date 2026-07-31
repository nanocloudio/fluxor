//! Target configuration loader.
//!
//! Loads silicon, board, and host TOML definitions from the `targets/`
//! directory and provides a unified `TargetDescriptor` for validation and
//! build.
//!
//! Resolution: `load_target("pico2w")` checks `targets/boards/pico2w.toml`
//! first (which references silicon "rp2350"), then `targets/host/`, then
//! `targets/silicon/`. The registry is the ONLY board→silicon mapping —
//! tooling must not carry alias tables (standards/target_consolidation.md §3).

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
    /// Platform stack defaults — used by host descriptors (e.g.
    /// `[platform.net] provider = "host"`); silicon files omit it. Values are
    /// `toml::Value` so structured sections (e.g. `[platform.pcie] aliases`,
    /// consumed by `build.rs`) parse; only string entries flow to stack facts.
    platform:
        Option<std::collections::HashMap<String, std::collections::HashMap<String, toml::Value>>>,
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
    /// Silicon whose PIC modules this target loads, when it differs from
    /// the target's own id (the linux host runs the aarch64 `bcm2712`
    /// modules). Absent means "my own silicon".
    module_silicon: Option<String>,
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
    /// Board/emulator memory map. Silicon files describe the die, not where a
    /// particular board or emulator places RAM/flash — so the concrete map is a
    /// board-level fact and overrides any silicon default when present. (e.g.
    /// `qemu-virt` carries the QEMU virt RAM map; a real board's RAM origin is
    /// selected by its `board-*` cargo feature at link time.)
    memory: Option<TomlMemoryConfig>,
    /// Platform stack defaults (e.g. [platform.net] phy="wifi", nic="cyw43").
    /// `toml::Value` values so structured sections parse (see SiliconToml).
    platform:
        Option<std::collections::HashMap<String, std::collections::HashMap<String, toml::Value>>>,
}

/// Board-level build overrides. Only present for boards that need cargo
/// features beyond the silicon defaults (e.g. `board-pi5` selects Pi 5
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

/// Which registry tier a target name resolved through. Boards deploy,
/// hosts run fluxor as a process, silicon keys module artifacts. See
/// standards/target_consolidation.md §2 for where each may appear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Silicon,
    Board,
    Host,
}

/// Resolved target descriptor combining silicon + optional board info.
#[derive(Debug, Clone)]
pub struct TargetDescriptor {
    /// Registry tier the name resolved through.
    pub kind: TargetKind,
    /// Silicon target id (e.g. "rp2350")
    pub id: String,
    /// Silicon family (e.g. "rp2", "esp32")
    pub family: String,
    /// Human description of the silicon
    pub description: String,
    /// Board id, if loaded via board file (e.g. "pico2w")
    pub board_id: Option<String>,
    /// `[target].module_silicon` from the descriptor TOML — set only when
    /// the target's PIC modules come from another silicon. Read through
    /// `module_silicon()`, which falls back to this target's own silicon.
    pub module_silicon_override: Option<String>,
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

    /// Silicon whose PIC modules (`.fmod`s) and OCI pins this target uses.
    ///
    /// Single source for "where do my modules come from": both the
    /// `target/fluxor/<silicon>/modules` directory and the silicon tag on
    /// `fluxor.lock` pins key off this. Most targets answer with their own
    /// silicon; the linux host answers `bcm2712` because it loads the same
    /// aarch64 PIC modules. Declare the exception in the target TOML
    /// (`[target].module_silicon`) so a new host family never has to touch
    /// this code. There are no alias tables: boards resolve through their
    /// `[board].silicon` field, so `self.id` IS the silicon id here.
    pub fn module_silicon(&self) -> &str {
        match self.module_silicon_override {
            Some(ref s) => s,
            None => &self.id,
        }
    }

    /// True for host-level targets (`linux`, `wasm`) — fluxor as a
    /// process on an OS/runtime rather than a board or bare silicon.
    pub fn is_host(&self) -> bool {
        self.kind == TargetKind::Host
    }

    /// Manifest `hardware_targets` strings this target accepts: its
    /// module silicon, plus its own token when it is a host (host-capable
    /// modules declare `linux`/`wasm` directly). Boards never appear —
    /// a board id in `hardware_targets` is a validation error.
    pub fn accepted_hardware_targets(&self) -> Vec<String> {
        let mut v = vec![self.module_silicon().to_string()];
        if self.is_host() {
            let own = self.build_id().to_string();
            if !v.contains(&own) {
                v.push(own);
            }
        }
        v
    }

    /// Display name: "pico2w (RP2350 (dual Cortex-M33))" or "rp2350 (...)"
    pub fn display_name(&self) -> String {
        if let Some(ref board) = self.board_id {
            format!("{} ({})", board, self.description)
        } else {
            format!("{} ({})", self.id, self.description)
        }
    }
}

/// Reduce raw `[platform.*]` tables to the string-only facts stack expansion
/// consumes (phy/nic/sink/provider). Structured sections such as
/// `[platform.pcie] aliases` (an array of tables read by `build.rs` to generate
/// the kernel alias table) carry non-string values; those entries are not stack
/// facts and are dropped here.
fn platform_string_defaults(
    platform: Option<
        std::collections::HashMap<String, std::collections::HashMap<String, toml::Value>>,
    >,
) -> std::collections::HashMap<String, std::collections::HashMap<String, String>> {
    platform
        .unwrap_or_default()
        .into_iter()
        .map(|(section, kv)| {
            let strings = kv
                .into_iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
                .collect();
            (section, strings)
        })
        .collect()
}

/// Load and resolve a target by name.
///
/// Resolution order:
/// 1. Check `<project_root>/targets/boards/{name}.toml` — board first.
/// 2. Check `<project_root>/targets/host/{name}.toml` — host tier.
/// 3. Check `<project_root>/targets/silicon/{name}.toml`.
/// 4. **Fall back to the install root** (when discovered — see
///    `project::install_root`) and repeat 1+2 against it. Lets an
///    external user project reuse bundled targets without copying
///    them.
/// 4. Error: unknown target.
pub fn load_target(name: &str, project_root: &Path) -> Result<TargetDescriptor> {
    // Try project root first.
    if let Some(desc) = try_load_target_under(name, project_root)? {
        return Ok(desc);
    }
    // Then install root, if discovered.
    if let Some(install) = crate::project::install_root() {
        if install.path != project_root {
            if let Some(desc) = try_load_target_under(name, &install.path)? {
                return Ok(desc);
            }
        }
    }

    let available = list_targets(project_root);
    let main = if available.is_empty() {
        "none (missing targets/ directory?)".to_string()
    } else {
        available.join(", ")
    };
    // "Did you mean …?" hint — small Levenshtein with a cheap
    // threshold. Most typos are 1-2 character distance from the
    // intended name (`pic2w` → `pico2w`, `pi` → `pi5`, …). Cap at
    // distance 3 to avoid suggesting wildly unrelated targets.
    let suggestion = closest_match(name, &available, 3);
    let did_you_mean = match suggestion {
        Some(s) => format!(" Did you mean '{s}'?"),
        None => String::new(),
    };
    Err(Error::Config(format!(
        "Unknown target '{name}'.{did_you_mean} Available: {main}"
    )))
}

// Levenshtein-distance helpers moved to
// `tools/src/text_distance.rs` so the library-side `manifest.rs`
// can use the same lookup for "did you mean" hints on content_type
// typos. Re-exported here for binary-tree callers (stack_expand,
// config, this file) that adopted them via
// `crate::target::closest_match` before the move.
pub(crate) use crate::text_distance::closest_match;

/// Try to resolve `name` under a single root. Returns `Ok(None)`
/// when neither the board nor silicon file exists — distinct from
/// `Ok(Some(desc))` (found) and `Err(...)` (file present but
/// malformed). The two-stage return lets `load_target` walk
/// multiple roots without conflating "not here" with "broken".
fn try_load_target_under(name: &str, root: &Path) -> Result<Option<TargetDescriptor>> {
    let targets_dir = root.join("targets");
    let board_path = targets_dir.join("boards").join(format!("{name}.toml"));
    if board_path.exists() {
        return load_board_target(&board_path, &targets_dir).map(Some);
    }
    let host_path = targets_dir.join("host").join(format!("{name}.toml"));
    if host_path.exists() {
        return load_silicon_target(&host_path, TargetKind::Host).map(Some);
    }
    let silicon_path = targets_dir.join("silicon").join(format!("{name}.toml"));
    if silicon_path.exists() {
        return load_silicon_target(&silicon_path, TargetKind::Silicon).map(Some);
    }
    Ok(None)
}

/// List all available target names (boards + silicon).
///
/// Merges entries from `project_root/targets/` AND from the install
/// root (when discovered via `project::install_root`). The project
/// root wins on duplicate names — a user override silently masks
/// the bundled descriptor, which is the intended behaviour.
pub fn list_targets(project_root: &Path) -> Vec<String> {
    let mut names = Vec::new();
    collect_target_names_under(project_root, &mut names);

    // Merge install-root entries that aren't already present.
    if let Some(install) = crate::project::install_root() {
        if install.path != project_root {
            collect_target_names_under(&install.path, &mut names);
        }
    }

    names.sort();
    names
}

/// List target names under a single root. Used by `fluxor inspect`
/// to render a merged "what's available where" view with source
/// annotations (project root vs install root). Distinct from
/// `list_targets` which deduplicates across roots — this returns
/// only what `root` itself carries, so the caller can compute
/// merge/shadow semantics for display.
pub fn list_targets_under(root: &Path) -> Vec<String> {
    let mut names = Vec::new();
    collect_target_names_under(root, &mut names);
    names.sort();
    names
}

/// Walk a single root's `targets/{boards,silicon}/` and append
/// every `*.toml` file stem to `names` that isn't already present.
/// Project-root entries win on duplicate names because the project
/// root is walked first.
fn collect_target_names_under(root: &Path, names: &mut Vec<String>) {
    let targets_dir = root.join("targets");
    for subdir in ["boards", "host", "silicon"] {
        if let Ok(entries) = std::fs::read_dir(targets_dir.join(subdir)) {
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
    }
}

// ── Internal loading ────────────────────────────────────────────────────────

fn load_silicon_target(path: &Path, kind: TargetKind) -> Result<TargetDescriptor> {
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
        kind,
        id: silicon.target.id,
        family: silicon.target.family,
        description: silicon.target.description,
        board_id: None,
        board_description: None,
        module_silicon_override: silicon.target.module_silicon,
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
        platform_defaults: platform_string_defaults(silicon.platform),
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

    let mut desc = load_silicon_target(&silicon_path, TargetKind::Silicon)?;
    desc.kind = TargetKind::Board;

    // Overlay board info
    desc.board_id = Some(board.board.id);
    desc.board_description = Some(board.board.description);

    // Board memory map overrides the silicon default (silicon describes the die,
    // the board/emulator places RAM/flash). A board without its own [memory]
    // keeps whatever the silicon declared (typically none).
    if let Some(m) = board.memory {
        desc.memory = Some(MemoryConfig {
            flash_base: parse_hex_u32(&m.flash_base).unwrap_or(0),
            flash_size: parse_hex_u32(&m.flash_size).unwrap_or(0),
            ram_base: parse_hex_u32(&m.ram_base).unwrap_or(0),
            ram_size: parse_hex_u32(&m.ram_size).unwrap_or(0),
        });
    }

    // Overlay GPIO reservations from board
    if let Some(gpio) = board.gpio {
        // Package/pin-count narrowing: silicon pin data covers the full
        // die pin-out; a board on a smaller package caps `max_pin` and
        // the peripheral pin tables shrink to combos it can wire
        // (pico2w = RP2350 QFN-60 → max_pin 29).
        if let Some(max) = gpio.max_pin {
            desc.max_pin = max;
            let cap = |tables: &mut Vec<PinTable>| {
                for t in tables.iter_mut() {
                    if let PinTable::Explicit(combos) = t {
                        combos.retain(|c| c.iter().all(|&pin| pin <= max));
                    }
                }
            };
            cap(&mut desc.spi_pins);
            cap(&mut desc.i2c_pins);
        }
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

    // Platform stack defaults (e.g. [platform.net] phy="wifi"). Only string
    // entries are stack facts; structured sections (pcie aliases) are read from
    // the raw board TOML by build.rs, not here.
    desc.platform_defaults = platform_string_defaults(board.platform);

    // Merge board-level build overrides onto silicon's build config. Only
    // used by boards that need extra cargo features (pi5 adds `board-pi5`).
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

// Inline tests for `closest_match` / `levenshtein` live in
// `tools/src/text_distance.rs` alongside the implementation.

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    fn repo_root() -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p
    }

    /// Pins the "where do my modules come from" answer for every shipped
    /// target. A new target that gets this wrong loads `.fmod`s from a
    /// directory nothing writes, and resolves `fluxor.lock` pins tagged
    /// with a silicon nothing publishes.
    #[test]
    fn module_silicon_pins_shipped_targets() {
        let root = repo_root();
        for (target, want) in [
            ("linux", "bcm2712"),
            ("pi5", "bcm2712"),
            ("bcm2712", "bcm2712"),
            ("qemu-virt", "bcm2712"),
            ("rp2350", "rp2350"),
            ("pico2w", "rp2350"),
            ("waveshare-lcd4", "rp2350"),
            ("rp2040", "rp2040"),
            ("pico", "rp2040"),
            ("picow", "rp2040"),
            ("wasm", "wasm"),
        ] {
            let desc = super::load_target(target, &root).expect("target loads");
            assert_eq!(
                desc.module_silicon(),
                want,
                "target `{target}` must load modules built for `{want}`"
            );
        }
    }

    /// Only the linux host declares an override; every other descriptor
    /// answers with its own silicon, so the mapping stays data-driven
    /// rather than a family match in code.
    #[test]
    fn module_silicon_override_is_declared_in_toml() {
        let root = repo_root();
        let linux = super::load_target("linux", &root).expect("linux target loads");
        assert_eq!(linux.module_silicon_override.as_deref(), Some("bcm2712"));
        let bcm = super::load_target("bcm2712", &root).expect("bcm2712 target loads");
        assert_eq!(bcm.module_silicon_override, None);
    }
}
