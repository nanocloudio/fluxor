//! Target configuration loader.
//!
//! Loads silicon, board, and host TOML definitions from the `targets/`
//! directory and provides a unified `TargetDescriptor` for validation and
//! build.
//!
//! Resolution: `load_target("pico2w")` checks `targets/boards/pico2w.toml`
//! first (which references silicon "rp2350"), then `targets/host/`, then
//! `targets/silicon/`. The registry is the ONLY board→silicon mapping —
//! tooling must not carry alias tables.

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
    buffer_arena_kb: Option<u32>,
    module_code_kb: Option<u32>,
    ram_static_max_kb: Option<u32>,
    kernel_stack_reserve_kb: Option<u32>,
    kernel_stack_kb: Option<u32>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct TomlIsolationConfig {
    levels: Option<Vec<String>>,
    region_model: Option<String>,
    regions: Option<u32>,
    stack_bound: Option<String>,
    device_windows: Option<bool>,
    device_ranges: Option<Vec<TomlDeviceRange>>,
    #[serde(rename = "peripheral_gate")]
    _peripheral_gate: Option<TomlPeripheralGate>,
    isolated_stack_kb: Option<u32>,
    isolated_slots: Option<u32>,
    exception_frame_bytes: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlDeviceRange {
    name: String,
    base: String,
    size: String,
    /// The block's peripheral-gate register (kernel fact; the composer
    /// needs only the range).
    #[serde(rename = "gate")]
    _gate: Option<String>,
}

/// The peripheral access-control block the kernel locks at boot (kernel
/// fact; parsed so the section stays closed to typos).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlPeripheralGate {
    #[serde(rename = "base")]
    _base: String,
    #[serde(rename = "first")]
    _first: String,
    #[serde(rename = "last")]
    _last: String,
}

/// How a target's protection unit draws a region — the planner's model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionModel {
    /// No protection unit the kernel drives.
    None,
    /// ARMv8-M PMSAv8: base/limit, 32-byte granularity.
    Pmsav8,
    /// ARMv6-M/ARMv7-M PMSAv7: power-of-two size, size-aligned, 8 subregions.
    Pmsav7,
    /// An MMU with 4 KiB pages.
    Pages,
}

impl RegionModel {
    fn parse(s: &str) -> Option<RegionModel> {
        match s {
            "none" => Some(RegionModel::None),
            "pmsav8" => Some(RegionModel::Pmsav8),
            "pmsav7" => Some(RegionModel::Pmsav7),
            "pages" => Some(RegionModel::Pages),
            _ => None,
        }
    }
}

/// What bounds a gated module's stack in hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackBound {
    None,
    LimitRegister,
    GuardRegion,
    GuardPage,
}

impl StackBound {
    fn parse(s: &str) -> Option<StackBound> {
        match s {
            "none" => Some(StackBound::None),
            "limit-register" => Some(StackBound::LimitRegister),
            "guard-region" => Some(StackBound::GuardRegion),
            "guard-page" => Some(StackBound::GuardPage),
            _ => None,
        }
    }
}

/// A target's isolation facts (`[isolation]`). Published by the target and
/// admitted against by the composer; chip identity is never consulted. The
/// default is a target with no protection unit and no gated level.
#[derive(Debug, Clone)]
pub struct IsolationFacts {
    /// The gated levels the kernel implements here (`contained`,
    /// `isolated`). `none` and `guarded` are implemented everywhere.
    pub levels: Vec<crate::protection::Level>,
    pub region_model: RegionModel,
    /// Protection regions per core.
    pub regions: u32,
    pub stack_bound: StackBound,
    /// Whether an isolated module can be given a device window.
    pub device_windows: bool,
    /// The peripheral blocks a gated driver may be granted as its device
    /// window, by name: (name, base, size).
    pub device_ranges: Vec<(String, u64, u32)>,
    /// How many modules can be isolated at once.
    pub isolated_slots: u32,
    /// Bytes an exception frame takes on a gated module's stack.
    pub exception_frame_bytes: u32,
}

impl Default for IsolationFacts {
    fn default() -> IsolationFacts {
        IsolationFacts {
            levels: Vec::new(),
            region_model: RegionModel::None,
            regions: 0,
            stack_bound: StackBound::None,
            device_windows: false,
            device_ranges: Vec::new(),
            isolated_slots: 0,
            exception_frame_bytes: 0,
        }
    }
}

impl IsolationFacts {
    /// The region planner's model for these facts, or `None` where no
    /// protection unit is driven.
    pub fn planner_model(&self) -> Option<fluxor_contracts::isolation::RegionModel> {
        use fluxor_contracts::isolation::RegionModel as P;
        let regions = self.regions as u8;
        match self.region_model {
            RegionModel::Pmsav8 => Some(P::Pmsav8 { regions }),
            RegionModel::Pmsav7 => Some(P::Pmsav7 { regions }),
            RegionModel::Pages => Some(P::Pages),
            RegionModel::None => None,
        }
    }

    fn from_toml(t: Option<&TomlIsolationConfig>, id: &str) -> Result<IsolationFacts> {
        let Some(t) = t else {
            return Ok(Self::default());
        };
        let bad = |what: &str, v: &str| {
            Error::Config(format!(
                "targets/{id}: [isolation] {what} '{v}' is not recognised"
            ))
        };
        let mut levels = Vec::new();
        for l in t.levels.iter().flatten() {
            let level = crate::protection::Level::parse(l).ok_or_else(|| bad("level", l))?;
            if !level.is_gated() {
                return Err(Error::Config(format!(
                    "targets/{id}: [isolation] levels lists '{l}', which every target \
                     implements; list only gated levels (contained, isolated)"
                )));
            }
            levels.push(level);
        }
        let region_model = match &t.region_model {
            Some(m) => RegionModel::parse(m).ok_or_else(|| bad("region_model", m))?,
            None => RegionModel::None,
        };
        let stack_bound = match &t.stack_bound {
            Some(b) => StackBound::parse(b).ok_or_else(|| bad("stack_bound", b))?,
            None => StackBound::None,
        };
        let mut device_ranges = Vec::new();
        for r in t.device_ranges.iter().flatten() {
            let num = |v: &str| {
                let h = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X"));
                h.and_then(|h| u64::from_str_radix(&h.replace('_', ""), 16).ok())
                    .ok_or_else(|| bad("device_ranges address", v))
            };
            let size =
                u32::try_from(num(&r.size)?).map_err(|_| bad("device_ranges size", &r.size))?;
            device_ranges.push((r.name.clone(), num(&r.base)?, size));
        }
        Ok(IsolationFacts {
            levels,
            region_model,
            regions: t.regions.unwrap_or(0),
            stack_bound,
            device_windows: t.device_windows.unwrap_or(false),
            device_ranges,
            isolated_slots: t.isolated_slots.unwrap_or(0),
            exception_frame_bytes: t.exception_frame_bytes.unwrap_or(0),
        })
    }
}

#[derive(Deserialize)]
struct TomlTargetMeta {
    id: String,
    family: String,
    description: String,
    /// The runtime this target is (`crate::runtime_abi::RUNTIMES`).
    runtime: String,
    /// The module ABI it loads: its artefact shelf, store tag and pin.
    module_abi: String,
}

#[derive(Deserialize)]
struct TomlBuildConfig {
    rust_target: String,
    cargo_features: Vec<String>,
    uf2_family_id: String,
    module_target: String,
    /// The boot loader's own triple, for a target booted through one.
    loader_target: Option<String>,
    /// Where the firmware looks for that loader on the boot volume.
    loader_path: Option<String>,
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
    /// Flash the kernel keeps at the bottom (RP), which the graph-slot
    /// partition leaves it.
    kernel_flash_reserve: Option<String>,
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
    flash: Option<TomlBoardFlash>,
}

/// `[hardware.flash]`: the flash the board fits, which overrides the
/// silicon's default.
#[derive(Deserialize, Clone)]
struct TomlBoardFlash {
    size: String,
}

#[derive(Deserialize)]
struct TomlBoardMeta {
    id: String,
    /// The die under the board. Exactly one of `silicon` and `host`.
    silicon: Option<String>,
    /// The host target the board runs on, for a board that is a machine
    /// with an operating system (a cloud instance running the hosted
    /// runtime): it resolves through `targets/host/<host>.toml`.
    host: Option<String>,
    description: String,
}

// ── Public types ────────────────────────────────────────────────────────────

/// Which registry tier a target name resolved through. Boards deploy,
/// hosts run fluxor as a process, silicon keys module artifacts.
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
    /// `[target].runtime`: where modules run, which decides the contracts
    /// they may reach and the modules that may be placed here.
    pub runtime: String,
    /// `[target].module_abi`: the bytes this target loads — its artefact
    /// shelf (`target/fluxor/<abi>/modules`), store tag and pin.
    pub module_abi: String,
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
    /// Channel buffer arena in KiB (`[kernel] buffer_arena_kb`), where the
    /// silicon states it — the RP parts, whose kernel takes the figure from
    /// this file. The host-class kernels state theirs in
    /// `src/kernel/config.rs` (`capacity::kernel_buffer_arena`).
    pub buffer_arena_kb: Option<u32>,
    /// The loader's ceiling on one module's code, in KiB (`[kernel]
    /// module_code_kb`); `None` where the silicon states none.
    pub module_code_kb: Option<u32>,
    /// Ceiling on the kernel image's static RAM — `.data` + `.bss` +
    /// `.uninit` — in KiB (`[kernel] ram_static_max_kb`). `None` where the
    /// silicon declares none, which is every target whose image is not
    /// linked against a fixed RAM region.
    pub ram_static_max_kb: Option<u32>,
    /// The kernel's own frames at a module call on a target whose modules
    /// step on the kernel stack, in KiB (`[kernel] kernel_stack_reserve_kb`).
    pub kernel_stack_reserve_kb: Option<u32>,
    /// Whether the target has an MMU — derived from the isolation facts'
    /// region model, so paged arenas and isolation agree about it.
    pub has_mmu: bool,
    /// The target's isolation facts.
    pub isolation: IsolationFacts,
    /// The EL1 kernel stack each core runs on, in KiB (`[kernel]
    /// kernel_stack_kb`), on a target whose kernel stack is not what its RAM
    /// region leaves over.
    pub kernel_stack_kb: Option<u32>,
    /// The stack an isolated module runs on, in KiB
    /// (`[isolation] isolated_stack_kb`). Pinned to the kernel's
    /// `ISOLATED_STACK_BYTES`.
    pub isolated_stack_kb: Option<u32>,
}

/// Build configuration for targets that support kernel compilation.
#[derive(Debug, Clone)]
pub struct BuildConfig {
    pub rust_target: String,
    pub cargo_features: Vec<String>,
    pub uf2_family_id: u32,
    pub module_target: String,
    /// For a target the firmware boots through a loader (UEFI): the
    /// loader's triple (`aarch64-unknown-uefi`) and its path on the boot
    /// volume (`EFI/BOOT/BOOTAA64.EFI`, the firmware's default).
    pub loader_target: Option<String>,
    pub loader_path: Option<String>,
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
    /// Flash the kernel keeps at the bottom (RP); 0 where none is declared.
    pub kernel_flash_reserve: u32,
}

// ── Implementation ──────────────────────────────────────────────────────────

impl TargetDescriptor {
    /// How an RP board's flash is partitioned: where the firmware region
    /// ends, the two graph slots, the parameter store. The kernel built for
    /// this board computes the same (`flash_layout::graph_flash`, from the
    /// board's flash size and the silicon's kernel reserve). `None` for a
    /// target with no XIP flash to partition.
    pub fn graph_flash(&self) -> Option<crate::modules::sdk_layout::flash_layout::GraphFlash> {
        if !matches!(self.id.as_str(), "rp2040" | "rp2350") {
            return None;
        }
        let m = self.memory.as_ref()?;
        Some(crate::modules::sdk_layout::flash_layout::graph_flash(
            m.flash_size,
            m.kernel_flash_reserve,
        ))
    }

    /// The stack a module at `level` steps on, in bytes, and what it is. An
    /// isolated module on an MMU target has its own fixed stack; every other
    /// module — and on an MPU target a gated one too, whose process stack is
    /// the module part of the kernel stack — steps on the kernel stack. `None`
    /// where the target states neither (a host, where the OS owns the stack).
    pub fn module_stack_limit(
        &self,
        level: crate::protection::Level,
    ) -> Option<(u64, &'static str)> {
        if self.has_mmu && level == crate::protection::Level::Isolated {
            return self
                .isolated_stack_kb
                .map(|kb| (u64::from(kb) * 1024, "the isolated module stack"));
        }
        self.kernel_stack_limit()
    }

    /// What the kernel stack leaves a module that steps on it: the stack less
    /// the kernel's own reserve. The stack is `[kernel] kernel_stack_kb` where
    /// the target states it (an MMU target, whose stacks are linker
    /// reservations), otherwise what the RAM region leaves above the static
    /// ceiling.
    pub fn kernel_stack_limit(&self) -> Option<(u64, &'static str)> {
        let reserve = u64::from(self.kernel_stack_reserve_kb?) * 1024;
        let stack = match self.kernel_stack_kb {
            Some(kb) => u64::from(kb) * 1024,
            None => {
                let ram = self.memory.as_ref()?.ram_size as u64;
                let statics = u64::from(self.ram_static_max_kb?) * 1024;
                ram.checked_sub(statics)?
            }
        };
        Some((
            stack.checked_sub(reserve)?,
            "the kernel stack less its reserve",
        ))
    }

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

    /// The module ABI this target loads (`crate::runtime_abi::ABIS`).
    pub fn module_abi(&self) -> &str {
        &self.module_abi
    }

    /// The runtime this target is (`crate::runtime_abi::RUNTIMES`).
    pub fn runtime(&self) -> &str {
        &self.runtime
    }

    /// True for host-level targets (`linux`, `wasm`) — fluxor as a
    /// process on an OS/runtime rather than a board or bare silicon.
    pub fn is_host(&self) -> bool {
        self.kind == TargetKind::Host
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

// The "did you mean" lookup lives in `tools/src/text_distance.rs`, shared
// with the library-side `manifest.rs`; the binary-tree callers
// (stack_expand, config, this file) reach it through this re-export.
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
            loader_target: b.loader_target,
            loader_path: b.loader_path,
        }
    });

    let memory = silicon.memory.map(|m| MemoryConfig {
        flash_base: parse_hex_u32(&m.flash_base).unwrap_or(0),
        flash_size: parse_hex_u32(&m.flash_size).unwrap_or(0),
        ram_base: parse_hex_u32(&m.ram_base).unwrap_or(0),
        ram_size: parse_hex_u32(&m.ram_size).unwrap_or(0),
        kernel_flash_reserve: m
            .kernel_flash_reserve
            .as_deref()
            .and_then(parse_hex_u32)
            .unwrap_or(0),
    });

    let p = &silicon.peripherals;
    let isolation = IsolationFacts::from_toml(silicon.isolation.as_ref(), &silicon.target.id)?;
    // A target names a runtime from the table and an ABI that runtime
    // loads; anything else would send its modules to a shelf nothing
    // builds and admit modules that cannot run there.
    let Some(rt) = crate::runtime_abi::runtime(&silicon.target.runtime) else {
        return Err(Error::Config(format!(
            "{}: `runtime = \"{}\"` is not a runtime (known: {})",
            path.display(),
            silicon.target.runtime,
            crate::runtime_abi::RUNTIMES
                .iter()
                .map(|r| r.id)
                .collect::<Vec<_>>()
                .join(", ")
        )));
    };
    if !rt.abis.contains(&silicon.target.module_abi.as_str()) {
        return Err(Error::Config(format!(
            "{}: runtime `{}` does not load module ABI `{}` (it loads {})",
            path.display(),
            rt.id,
            silicon.target.module_abi,
            rt.abis.join(", ")
        )));
    }

    Ok(TargetDescriptor {
        kind,
        id: silicon.target.id,
        family: silicon.target.family,
        description: silicon.target.description,
        board_id: None,
        board_description: None,
        runtime: silicon.target.runtime,
        module_abi: silicon.target.module_abi,
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
        buffer_arena_kb: silicon.kernel.as_ref().and_then(|k| k.buffer_arena_kb),
        module_code_kb: silicon.kernel.as_ref().and_then(|k| k.module_code_kb),
        ram_static_max_kb: silicon.kernel.as_ref().and_then(|k| k.ram_static_max_kb),
        kernel_stack_reserve_kb: silicon
            .kernel
            .as_ref()
            .and_then(|k| k.kernel_stack_reserve_kb),
        has_mmu: isolation.region_model == RegionModel::Pages,
        isolation,
        kernel_stack_kb: silicon.kernel.as_ref().and_then(|k| k.kernel_stack_kb),
        isolated_stack_kb: silicon.isolation.as_ref().and_then(|i| i.isolated_stack_kb),
    })
}

fn load_board_target(board_path: &Path, targets_dir: &Path) -> Result<TargetDescriptor> {
    let content = std::fs::read_to_string(board_path)
        .map_err(|e| Error::Config(format!("Failed to read {}: {}", board_path.display(), e)))?;
    let board: TomlBoardFile = toml::from_str(&content)
        .map_err(|e| Error::Config(format!("Failed to parse {}: {}", board_path.display(), e)))?;

    // Load the referenced silicon target — or, for a hosted board, the
    // host target it runs on.
    let (base_path, base_kind) = match (&board.board.silicon, &board.board.host) {
        (Some(silicon), None) => (
            targets_dir.join("silicon").join(format!("{silicon}.toml")),
            TargetKind::Silicon,
        ),
        (None, Some(host)) => (
            targets_dir.join("host").join(format!("{host}.toml")),
            TargetKind::Host,
        ),
        (Some(_), Some(_)) => {
            return Err(Error::Config(format!(
                "Board '{}' names both a silicon and a host; a board stands on one",
                board.board.id
            )))
        }
        (None, None) => {
            return Err(Error::Config(format!(
                "Board '{}' names neither a silicon nor a host",
                board.board.id
            )))
        }
    };
    if !base_path.exists() {
        return Err(Error::Config(format!(
            "Board '{}' references {} '{}', but {} not found",
            board.board.id,
            match base_kind {
                TargetKind::Host => "host",
                _ => "silicon",
            },
            board
                .board
                .silicon
                .as_deref()
                .or(board.board.host.as_deref())
                .unwrap_or(""),
            base_path.display()
        )));
    }

    let mut desc = load_silicon_target(&base_path, base_kind)?;
    desc.kind = TargetKind::Board;

    // Overlay board info
    desc.board_id = Some(board.board.id);
    desc.board_description = Some(board.board.description);

    // Board memory map overrides the silicon default (silicon describes the die,
    // the board/emulator places RAM/flash). A board without its own [memory]
    // keeps whatever the silicon declared (typically none).
    if let Some(m) = board.memory {
        let reserve = desc.memory.as_ref().map_or(0, |m| m.kernel_flash_reserve);
        desc.memory = Some(MemoryConfig {
            flash_base: parse_hex_u32(&m.flash_base).unwrap_or(0),
            flash_size: parse_hex_u32(&m.flash_size).unwrap_or(0),
            ram_base: parse_hex_u32(&m.ram_base).unwrap_or(0),
            ram_size: parse_hex_u32(&m.ram_size).unwrap_or(0),
            kernel_flash_reserve: m
                .kernel_flash_reserve
                .as_deref()
                .and_then(parse_hex_u32)
                .unwrap_or(reserve),
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

    // The flash the board fits overrides the silicon's default, as the
    // kernel build takes it (build.rs): both partition the same flash.
    if let Some(size) = board
        .hardware
        .as_ref()
        .and_then(|hw| hw.flash.as_ref())
        .and_then(|f| parse_hex_u32(&f.size))
    {
        if let Some(m) = desc.memory.as_mut() {
            m.flash_size = size;
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

    /// Pins every shipped target's runtime and module ABI. A target that
    /// gets the ABI wrong loads `.fmod`s from a shelf nothing writes and
    /// resolves pins tagged with an ABI nothing publishes; one that gets the
    /// runtime wrong admits modules that cannot run there.
    #[test]
    fn shipped_targets_declare_their_runtime_and_abi() {
        let root = repo_root();
        for (target, runtime, abi) in [
            ("linux", "linux", "aarch64"),
            ("pi5", "bcm2712", "aarch64"),
            ("bcm2712", "bcm2712", "aarch64"),
            ("qemu-virt", "bcm2712", "aarch64"),
            ("rp2350", "rp2350", "thumbv8m"),
            ("pico2w", "rp2350", "thumbv8m"),
            ("waveshare-lcd4", "rp2350", "thumbv8m"),
            ("rp2040", "rp2040", "thumbv6m"),
            ("pico", "rp2040", "thumbv6m"),
            ("picow", "rp2040", "thumbv6m"),
            ("wasm", "wasm", "wasm32"),
            ("esp32", "esp32", "xtensa-lx6"),
            ("uefi", "uefi", "aarch64"),
            ("qemu-uefi-arm64", "uefi", "aarch64"),
        ] {
            let desc = super::load_target(target, &root).expect("target loads");
            assert_eq!(desc.runtime(), runtime, "target `{target}` runtime");
            assert_eq!(desc.module_abi(), abi, "target `{target}` module ABI");
        }
    }

    /// The flash each RP board is partitioned from is the board's own, and
    /// the partition is the one the kernel built for it computes: a Pico W's
    /// 2 MB is not a Pico 2 W's 4 MB, and neither puts a slot past its end.
    /// Targets with no XIP flash have no partition.
    #[test]
    fn rp_boards_partition_their_own_flash() {
        let root = repo_root();
        for (target, flash, slot_a, slot_size) in [
            ("pico2w", 0x40_0000u32, 0x1C_1000u32, 0x11_F000u32),
            ("rp2350", 0x40_0000, 0x1C_1000, 0x11_F000),
            ("picow", 0x20_0000, 0x10_1000, 0x7_F000),
            ("pico", 0x20_0000, 0x10_1000, 0x7_F000),
        ] {
            let g = super::load_target(target, &root)
                .expect("target loads")
                .graph_flash()
                .unwrap_or_else(|| panic!("`{target}` has a partition"));
            assert_eq!(g.flash_size, flash, "`{target}` flash");
            assert_eq!(g.slot_a, slot_a, "`{target}` slot A");
            assert_eq!(g.slot_size, slot_size, "`{target}` slot size");
            assert_eq!(g.param_store + 4096, flash, "`{target}` parameter store");
        }
        for target in ["linux", "pi5", "wasm"] {
            let desc = super::load_target(target, &root).expect("target loads");
            assert!(desc.graph_flash().is_none(), "`{target}` has no XIP flash");
        }
    }

    /// A board that stands on a host (`[board] host = "linux"`) resolves
    /// through `targets/host/`, builds as that host, and is still a board.
    #[test]
    fn a_hosted_board_resolves_through_its_host() {
        let root = repo_root();
        let desc = super::load_target("ec2-linux-arm64", &root).expect("hosted board loads");
        let host = super::load_target("linux", &root).expect("host loads");
        assert_eq!(desc.kind, super::TargetKind::Board);
        assert_eq!(desc.board_id.as_deref(), Some("ec2-linux-arm64"));
        assert_eq!(desc.runtime(), host.runtime());
        assert_eq!(desc.module_abi(), host.module_abi());
        assert_eq!(
            desc.build.as_ref().map(|b| b.rust_target.clone()),
            host.build.as_ref().map(|b| b.rust_target.clone())
        );
    }

    /// Every target names a runtime and ABI the table knows, and the
    /// runtime loads that ABI.
    #[test]
    fn every_target_agrees_with_the_runtime_table() {
        let root = repo_root();
        for name in super::list_targets(&root) {
            let desc = super::load_target(&name, &root).expect("target loads");
            let rt = crate::runtime_abi::runtime(desc.runtime())
                .unwrap_or_else(|| panic!("`{name}` names unknown runtime `{}`", desc.runtime()));
            assert!(
                rt.abis.contains(&desc.module_abi()),
                "`{name}`: runtime `{}` does not load ABI `{}`",
                rt.id,
                desc.module_abi()
            );
        }
    }

    /// A target file naming a runtime the table does not know, or an ABI
    /// its runtime does not load, is refused when it loads.
    #[test]
    fn a_target_naming_an_unknown_runtime_or_a_foreign_abi_is_refused() {
        let scratch = tempfile::tempdir().unwrap();
        let silicon = scratch.path().join("targets/silicon");
        std::fs::create_dir_all(&silicon).unwrap();
        let base =
            std::fs::read_to_string(repo_root().join("targets/silicon/rp2350.toml")).unwrap();
        let write = |runtime: &str, abi: &str| {
            std::fs::write(
                silicon.join("rp2350.toml"),
                base.replace("runtime = \"rp2350\"", &format!("runtime = \"{runtime}\""))
                    .replace(
                        "module_abi = \"thumbv8m\"",
                        &format!("module_abi = \"{abi}\""),
                    ),
            )
            .unwrap();
            super::load_target("rp2350", scratch.path())
        };
        assert!(write("rp2350", "thumbv8m").is_ok());
        let err = write("rp2350b", "thumbv8m").unwrap_err().to_string();
        assert!(err.contains("not a runtime"), "{err}");
        let err = write("rp2350", "aarch64").unwrap_err().to_string();
        assert!(err.contains("does not load module ABI `aarch64`"), "{err}");
    }
}
