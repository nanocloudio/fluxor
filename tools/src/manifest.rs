//! Module manifest: structured metadata for composition, validation, and integrity.
//!
//! The manifest is a required section in every `.fmod` file (ABI v2+).
//! It describes ports, resource claims, dependencies, and an optional integrity hash.

#![allow(
    dead_code,
    reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
)]

use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::hash::fnv1a_hash;

/// Manifest section magic: "FXMF"
pub const MANIFEST_MAGIC: u32 = 0x464D5846;

/// Manifest format version. Kept at v1 by policy — the kernel and
/// tools always ship together, so additive wire-format extensions
/// ride within v1 rather than bumping the integer. The current
/// layout is:
///
/// - 16-byte header (magic, version, port/resource/dependency
///   counts, module_version, hardware_targets, state_size_hint,
///   flags, fine-grained permissions byte).
/// - Port records (4 bytes each): `[direction, content_type, flags,
///   index]`. Byte 3 is the resolved per-direction `PortSpec.index`,
///   matching what the config compiler wires against.
/// - Resource records (4 bytes each).
/// - Dependency records (8 bytes each).
/// - Optional 32-byte SHA-256 integrity hash (flags bit 0).
/// - Optional `[ed25519_signature: 64B][signer_pubkey_fingerprint:
///   32B]` block (flags bit 1). The signature covers the integrity
///   hash, not the full module bytes.
pub const MANIFEST_VERSION: u8 = 1;

/// Manifest header size (fixed portion before variable sections)
pub const MANIFEST_HEADER_SIZE: usize = 16;

/// Signature block size (ed25519 signature + signer fingerprint).
pub const SIGNATURE_BLOCK_SIZE: usize = 96;

// Content-type wire-byte table lives in `fluxor-contracts` so sibling
// projects authoring module manifests can depend on it without pulling
// in the rest of the host-side tooling. Re-exported here to preserve
// the long-standing `tools::manifest::CONTENT_TYPES` import path.
pub use fluxor_contracts::CONTENT_TYPES;

fn content_type_from_str(s: &str) -> Result<u8> {
    if let Some(idx) = CONTENT_TYPES
        .iter()
        .position(|&t| t.eq_ignore_ascii_case(s))
    {
        return Ok(idx as u8);
    }
    // Levenshtein "did you mean" hint — content_type typos in port
    // declarations are common (e.g. `content_type: "AudioMP3"` vs
    // `"AudioMp3"`). Case-insensitive match would have caught the
    // capitalisation difference; the closest_match catches actual
    // misspellings (`"AudioSamle"` → `"AudioSample"`). The helper
    // lives in `crate::text_distance` so it's reachable from both
    // the binary and library compilation contexts of this file.
    let candidates: Vec<String> = CONTENT_TYPES.iter().map(|s| s.to_string()).collect();
    let suggestion = crate::text_distance::closest_match(s, &candidates, 3);
    Err(Error::Module(match suggestion {
        Some(hint) => format!("unknown content type: '{s}'. Did you mean '{hint}'?"),
        None => format!("unknown content type: '{s}'"),
    }))
}

// ── Contract name → u8 mapping (matches provider::contract constants) ───────
//
// The manifest's `requires_contract` field names a contract by its layer
// name. Module-facing names mirror the layer boundaries documented in
// `docs/architecture/abi_layers.md`:
//   - HAL hardware contracts: "gpio", "spi", "i2c", "pio", "uart", "adc", "pwm"
//   - Stable module contracts: "fs" (plus kernel-provided channel/timer/buffer/event, implicit)
//   - Platform transport contracts: "platform_nic_ring", "platform_dma",
//     "platform_dma_fd", "pcie_device" (raw register-level surfaces gated
//     by `platform_raw`)
//
// Permission names ("internal", "flash_raw", "platform_raw", etc.) are not
// contracts and belong in the top-level `permissions = [...]` list — they
// are rejected here with a schema-error pointing at the correct section.

/// Parse a contract name from `[[resources]].requires_contract`. Only
/// public contract names are accepted here — `"internal"` and specific
/// permission names like `"flash_raw"` or `"platform_raw"` are **not**
/// contracts and must be declared under the top-level `permissions = [...]`
/// list instead.
pub fn contract_id_from_name(s: &str) -> Result<u8> {
    match s.to_ascii_lowercase().as_str() {
        "gpio" => Ok(0x01),
        "spi" => Ok(0x02),
        "i2c" => Ok(0x03),
        "pio" => Ok(0x04),
        "channel" => Ok(0x05),
        "timer" => Ok(0x06),
        "platform_nic_ring" => Ok(0x07),
        "platform_dma" => Ok(0x08),
        "fs" => Ok(0x09),
        "buffer" => Ok(0x0A),
        "event" => Ok(0x0B),
        "uart" => Ok(0x0D),
        "adc" => Ok(0x0E),
        "pwm" => Ok(0x0F),
        "platform_dma_fd" => Ok(0x11),
        "pcie_device" => Ok(0x12),
        // Storage capability surfaces (see
        // docs/architecture/storage_capability_surface.md). Both are
        // module-providable contracts; class bytes match the kernel
        // `provider::contract::STORAGE_*` constants.
        "storage.namespace" | "namespace" => Ok(0x13),
        "storage.object" | "object" => Ok(0x14),
        // USB host controller binding (scaffold). Allocated so
        // foundation modules can name the contract today; the kernel
        // vtable is not yet implemented and `provider_open` against
        // it returns ENOSYS until a host-controller driver lands.
        "usb_host" => Ok(0x15),
        // Anything that looks like a permission name is a manifest
        // schema error — those go in `permissions = [...]`, not
        // `[[resources]]`.
        "internal" | "system" | "reconfigure" | "flash_raw" | "backing_provider"
        | "platform_raw" | "monitor" | "bridge" => Err(Error::Module(format!(
            "`{s}` is a permission, not a contract. Declare it in the \
                 top-level `permissions = [\"{s}\", ...]` list, not under \
                 `[[resources]]`. See docs/architecture/abi_layers.md."
        ))),
        _ => Err(Error::Module(format!(
            "unknown contract name: {s} — expected one of: gpio, spi, i2c, pio, \
             uart, adc, pwm, fs, storage.namespace, storage.object, usb_host, \
             platform_nic_ring, platform_dma, platform_dma_fd, \
             pcie_device (see docs/architecture/abi_layers.md)"
        ))),
    }
}

pub fn contract_name_to_str(class: u8) -> &'static str {
    // Must round-trip with `contract_id_from_name`: every id that
    // `_from_name` accepts MUST be present here, and the returned
    // name MUST be one that `_from_name` round-trips back to the
    // same id. The drift-guard test in
    // `tools/tests/contract_id_round_trip.rs` enforces both
    // directions.
    match class {
        0x01 => "gpio",
        0x02 => "spi",
        0x03 => "i2c",
        0x04 => "pio",
        0x05 => "channel",
        0x06 => "timer",
        0x07 => "platform_nic_ring",
        0x08 => "platform_dma",
        0x09 => "fs",
        0x0A => "buffer",
        0x0B => "event",
        0x0C => "internal",
        0x0D => "uart",
        0x0E => "adc",
        0x0F => "pwm",
        0x11 => "platform_dma_fd",
        0x12 => "pcie_device",
        // Storage capability surfaces — kept in sync with
        // `provider::contract::STORAGE_{NAMESPACE,OBJECT}` (kernel)
        // and `contract_id_from_name` (this file). Missing these
        // pre-2026-05-19 caused error messages quoting bit 0x13/0x14
        // of a required-caps mask to render the byte as "unknown".
        0x13 => "storage.namespace",
        0x14 => "storage.object",
        0x15 => "usb_host",
        _ => "unknown",
    }
}

/// Whitelist of AV / presentation / input capability names accepted in
/// a manifest's top-level `capabilities = [...]` list. Two tiers:
/// hardware-facing (the role the module plays — paced scanout, group
/// clock, protected output, mapper) and service-level (the surface a
/// producer or consumer carries). Unknown names are rejected at parse
/// time so `display.scaneout` and friends fail the build rather than
/// silently dropping out.
///
/// AV names are documented in `docs/architecture/av_capability_surface.md`.
/// Input names are documented in `docs/architecture/input_capability_surface.md`
/// and added one at a time as a real module declares them.
const AV_CAPABILITY_NAMES: &[&str] = &[
    // Hardware-facing
    "display.scanout",
    "display.multihead",
    "display.protected_scanout",
    "video.decode",
    "video.encode",
    "video.protected_decode",
    "audio.protected_out",
    "audio.rate_trim",
    "gpu.render",
    "presentation.clock",
    // Service-level (mirror the canonical content-type surface family)
    "audio.sample",
    "audio.encoded",
    "video.encoded",
    "video.draw",
    "video.raster",
    "video.scanout",
    "media.muxed",
    "media.protected_path",
    "presentation.group",
    // Input (added as modules declare them; see input_capability_surface.md §5)
    "input.mapper",
    "input.gamepad",
    "input.virtual",
    "input.remote",
    // MIDI surface — paired with the `input::midi` contract and the
    // `MidiEvents` content type. Declared by the per-platform MIDI
    // drivers (Web MIDI on wasm, ALSA seq on linux, class-compliant
    // USB-MIDI on rp2350 / cm5).
    "midi.input",
    "midi.output",
];

/// Validate capability names against the whitelist and canonicalize each
/// entry to its lowercase form in place. Downstream consumers — the
/// presentation-group validator, telemetry, doc dumps — can then use
/// exact string comparison instead of paying for case-insensitive
/// matching at every callsite.
fn validate_capability_names(caps: &mut [String]) -> Result<()> {
    for c in caps {
        match AV_CAPABILITY_NAMES
            .iter()
            .find(|n| n.eq_ignore_ascii_case(c))
        {
            Some(canonical) => {
                if c.as_str() != *canonical {
                    *c = canonical.to_string();
                }
            }
            None => {
                let candidates: Vec<String> =
                    AV_CAPABILITY_NAMES.iter().map(|s| s.to_string()).collect();
                let did_you_mean = crate::text_distance::closest_match(c, &candidates, 3)
                    .map(|s| format!(" Did you mean `{s}`?"))
                    .unwrap_or_default();
                return Err(Error::Module(format!(
                    "unknown capability `{c}`.{did_you_mean} Expected one of: {}.",
                    AV_CAPABILITY_NAMES.join(", "),
                )));
            }
        }
    }
    Ok(())
}

fn access_mode_from_str(s: &str) -> Result<u8> {
    match s.to_ascii_lowercase().as_str() {
        "read" => Ok(0),
        "write" => Ok(1),
        "exclusive" => Ok(2),
        "chain" => Ok(3),
        _ => {
            let valid = ["read", "write", "exclusive", "chain"]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>();
            let did_you_mean = crate::text_distance::closest_match(s, &valid, 3)
                .map(|h| format!(" Did you mean '{h}'?"))
                .unwrap_or_default();
            Err(Error::Module(format!(
                "unknown access mode: '{s}'.{did_you_mean} Expected: read, write, exclusive, chain."
            )))
        }
    }
}

fn access_mode_to_str(mode: u8) -> &'static str {
    match mode {
        0 => "read",
        1 => "write",
        2 => "exclusive",
        3 => "chain",
        _ => "unknown",
    }
}

fn direction_from_str(s: &str) -> Result<u8> {
    match s.to_ascii_lowercase().as_str() {
        "input" | "in" => Ok(0),
        "output" | "out" => Ok(1),
        "ctrl" | "ctrl_input" => Ok(2),
        "ctrl_output" => Ok(3),
        _ => {
            let valid = ["input", "output", "ctrl", "ctrl_output"]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>();
            let did_you_mean = crate::text_distance::closest_match(s, &valid, 3)
                .map(|h| format!(" Did you mean '{h}'?"))
                .unwrap_or_default();
            Err(Error::Module(format!(
                "unknown port direction: '{s}'.{did_you_mean} Expected: input, output, ctrl, ctrl_output."
            )))
        }
    }
}

pub fn direction_to_str(d: u8) -> &'static str {
    match d {
        0 => "input",
        1 => "output",
        2 => "ctrl",
        3 => "ctrl_output",
        _ => "unknown",
    }
}

pub fn content_type_to_str(ct: u8) -> &'static str {
    CONTENT_TYPES.get(ct as usize).copied().unwrap_or("Unknown")
}

// ── Semver encoding ─────────────────────────────────────────────────────────

/// Encode semver (major, minor, patch) into a u16: major<<10 | minor<<5 | patch.
/// Supports major 0-63, minor 0-31, patch 0-31.
pub fn encode_semver(major: u8, minor: u8, patch: u8) -> u16 {
    ((major as u16 & 0x3F) << 10) | ((minor as u16 & 0x1F) << 5) | (patch as u16 & 0x1F)
}

/// Decode u16 semver back to (major, minor, patch).
pub fn decode_semver(v: u16) -> (u8, u8, u8) {
    let major = ((v >> 10) & 0x3F) as u8;
    let minor = ((v >> 5) & 0x1F) as u8;
    let patch = (v & 0x1F) as u8;
    (major, minor, patch)
}

fn parse_semver(s: &str) -> Result<(u8, u8, u8)> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::Module(format!("invalid semver: {s}")));
    }
    let major: u8 = parts[0]
        .parse()
        .map_err(|_| Error::Module(format!("invalid semver major: {s}")))?;
    let minor: u8 = parts[1]
        .parse()
        .map_err(|_| Error::Module(format!("invalid semver minor: {s}")))?;
    let patch: u8 = parts[2]
        .parse()
        .map_err(|_| Error::Module(format!("invalid semver patch: {s}")))?;
    Ok((major, minor, patch))
}

// ── Hardware target mapping ─────────────────────────────────────────────────

fn hardware_targets_from_list(targets: &[String]) -> u16 {
    let mut mask = 0u16;
    for t in targets {
        match t.to_ascii_lowercase().as_str() {
            "rp2350" => mask |= 0x01,
            "rp2040" => mask |= 0x02,
            _ => {} // ignore unknown targets
        }
    }
    mask
}

// ── Core types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PortSpec {
    pub direction: u8,
    pub content_type: u8,
    pub flags: u8,
    /// Human-readable port name (tooling-only, not serialized to binary).
    pub name: Option<String>,
    /// Explicit port index within its direction group (default: sequential).
    pub index: u8,
}

#[derive(Debug, Clone)]
pub struct ResourceClaim {
    pub device_class: u8,
    pub access_mode: u8,
    /// Hardware instance index (0xFF = any/unspecified).
    /// Used to distinguish e.g. PIO0 vs PIO1 for conflict checks.
    pub instance: u8,
}

#[derive(Debug, Clone)]
pub struct Dependency {
    pub name_hash: u32,
    pub min_version: u16,
}

/// FMP command vocabulary: what messages a module accepts and/or emits.
/// Used by the config tool for wiring validation (not serialized to binary).
#[derive(Debug, Clone, Default)]
pub struct CommandVocabulary {
    pub accepts: Vec<String>,
    pub emits: Vec<String>,
}

/// Fine-grained module permissions. Each category gates a specific
/// subset of 0x0Cxx orchestration / platform opcodes; a module that
/// needs only one surface does not implicitly get the others.
///
/// Serialised as a u8 bitmap into the manifest binary (reserved byte
/// at offset 15). Not part of the module header's flags byte — so
/// that adding a permission does not require a module-header ABI bump.
#[derive(Debug, Clone, Copy, Default)]
pub struct ManifestPermissions {
    pub bits: u8,
}

/// Permission category bits. Keep in sync with the kernel's
/// `permission` module in `src/kernel/syscalls.rs`.
pub mod permission {
    pub const RECONFIGURE: u8 = 1 << 0; // graph slot commit, boot counter, FMP routing
    pub const FLASH_RAW: u8 = 1 << 1; // flash ERASE / PROGRAM
    pub const BACKING_PROVIDER: u8 = 1 << 2; // paged-arena / backing-provider registration
    pub const PLATFORM_RAW: u8 = 1 << 3; // MMIO/DMA/PCIe/SMMU/NIC, raw peripheral register bridges
    pub const MONITOR: u8 = 1 << 4; // fault monitor BIND/WAIT/ACK/REPORT/RAISE
    pub const BRIDGE: u8 = 1 << 5; // cross-domain / cross-core dispatch

    pub fn from_name(s: &str) -> Option<u8> {
        match s {
            "reconfigure" => Some(RECONFIGURE),
            "flash_raw" => Some(FLASH_RAW),
            "backing_provider" => Some(BACKING_PROVIDER),
            "platform_raw" => Some(PLATFORM_RAW),
            "monitor" => Some(MONITOR),
            "bridge" => Some(BRIDGE),
            _ => None,
        }
    }

    pub fn names(bits: u8) -> Vec<&'static str> {
        let mut out = Vec::new();
        if bits & RECONFIGURE != 0 {
            out.push("reconfigure");
        }
        if bits & FLASH_RAW != 0 {
            out.push("flash_raw");
        }
        if bits & BACKING_PROVIDER != 0 {
            out.push("backing_provider");
        }
        if bits & PLATFORM_RAW != 0 {
            out.push("platform_raw");
        }
        if bits & MONITOR != 0 {
            out.push("monitor");
        }
        if bits & BRIDGE != 0 {
            out.push("bridge");
        }
        out
    }
}

/// Param type categories declared in `[[params]]`. Matches the wire
/// types used by the runtime TLV packer in `tools/src/schema.rs`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ManifestParamType {
    U8,
    U16,
    U32,
    Str,
    Enum,
}

/// A single `[[params]]` entry from a built-in's `manifest.toml`. The
/// tag is auto-assigned in declaration order (10..) so manifest authors
/// don't have to. Defaults are stored as 32-bit unsigned integers when
/// numeric, or as a string for `str`/`enum`.
#[derive(Debug, Clone)]
pub struct ManifestParam {
    /// TLV tag (auto-assigned: first param = 10, second = 11, ...).
    /// Tags 0xF0..0xFF are reserved for protection/policy metadata; we
    /// stay well below.
    pub tag: u8,
    pub name: String,
    pub ptype: ManifestParamType,
    /// Numeric default for U8/U16/U32; ignored for Str/Enum.
    pub default_num: u32,
    /// String default for Str; enum-name default for Enum.
    pub default_str: String,
    /// Enum: list of (name, value) mappings. Values are u8.
    pub enum_values: Vec<(String, u8)>,
    /// Optional inclusive range for numeric params: [min, max].
    pub range: Option<(u32, u32)>,
    /// When true, the YAML must specify this param — build fails if
    /// missing. Equivalent to "no safe default exists." Set on params
    /// like `host_asset_source.path` where falling back to a default
    /// would silently misconfigure the graph.
    pub required: bool,
}

#[derive(Debug, Clone)]
pub struct Manifest {
    pub module_version: u16,
    pub hardware_targets: u16,
    pub state_size_hint: u16,
    pub ports: Vec<PortSpec>,
    pub resources: Vec<ResourceClaim>,
    pub permissions: ManifestPermissions,
    pub dependencies: Vec<Dependency>,
    pub integrity_hash: Option<[u8; 32]>,
    /// Ed25519 signature over the integrity hash. Set by the `fluxor sign`
    /// subcommand; absent on unsigned (v1) manifests.
    pub signature: Option<[u8; 64]>,
    /// SHA-256 fingerprint of the signer's Ed25519 public key. Loader
    /// matches this against OTP/provisioned pubkey to accept/reject.
    pub signer_fp: Option<[u8; 32]>,
    /// FMP command vocabulary (parsed from TOML, not in binary format)
    pub commands: CommandVocabulary,
    /// Services this module provides to others (parsed from TOML, not in
    /// binary format). Used by the config resolver to wire dependencies by
    /// service name (e.g. `pwm_rp` provides `"pwm"`).
    pub provides: Vec<String>,
    /// AV / presentation capabilities this module declares (parsed from
    /// TOML, not serialized to the binary `.fmod`). The whitelist lives
    /// in `AV_CAPABILITY_NAMES`; the config validator consults this
    /// field to enforce presentation-group rules. See
    /// `docs/architecture/av_capability_surface.md`.
    pub capabilities: Vec<String>,
    /// Module is built into the kernel (no .fmod file needed).
    /// Used by platform-specific modules like linux_net.
    pub builtin: bool,
    /// Module attests that its `module_step` / `module_isr_init` /
    /// `module_isr_entry` exports are safe to invoke from an ISR
    /// context: no heap allocation, no `provider_call`, no
    /// `channel_read`/`channel_write`, bounded execution within the
    /// declared `isr_budget_cycles`. The author owns this claim; the
    /// tool does not statically verify it. The flag is mandatory for
    /// admission into a Tier 1b (`domain_exec_mode == 2`) or Tier 2
    /// (`domain_exec_mode == 4`) domain — modules without it are
    /// rejected at build time. See
    /// `.context/rfc_isr_tier_surface.md` §D7 for the contract this
    /// flag attests to and §Step-3 for the validator that enforces it.
    pub isr_safe: bool,
    /// Module opts into the **Tier 1c pre-pass drain slot**. Pre-tick
    /// modules run cooperatively at the *start* of every scheduler
    /// pass for their domain, before the regular `domain_exec_order`
    /// rotation. Use for latency-critical drains that need to run
    /// every tick regardless of `exec_order` position (canonical
    /// case: NIC RX/TX). The module retains the full cooperative API
    /// (heap + `provider_call` + `channel_read`/`write`); the only
    /// new contract is a shared combined cycle budget across all
    /// pre-tick modules in a domain (kernel default
    /// `MAX_PRE_TICK_BUDGET_US = 5`). See
    /// `.context/rfc_isr_tier_surface.md` §D8 for the contract and
    /// motivating measurement.
    pub pre_tick_drain: bool,
    /// Hardware-feature requirements declared by the module.
    /// Validated against the resolved target's silicon capability
    /// matrix at config time by `check_target_capabilities`. Default
    /// `TomlRequires::default()` (all-false) means "no specific
    /// requirements," which satisfies every silicon.
    pub requires: TomlRequires,
    /// Built-in parameter declarations from `[[params]]` (toml-only).
    /// `.fmod` modules carry their schema embedded in the binary; built-ins
    /// declare it here so the config tool can validate YAML and pack TLV.
    pub params: Vec<ManifestParam>,
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            module_version: encode_semver(0, 1, 0),
            hardware_targets: 0x01, // RP2350 by default
            state_size_hint: 0,
            ports: Vec::new(),
            resources: Vec::new(),
            permissions: ManifestPermissions::default(),
            dependencies: Vec::new(),
            integrity_hash: None,
            signature: None,
            signer_fp: None,
            commands: CommandVocabulary::default(),
            provides: Vec::new(),
            capabilities: Vec::new(),
            builtin: false,
            isr_safe: false,
            pre_tick_drain: false,
            requires: TomlRequires::default(),
            params: Vec::new(),
        }
    }
}

/// NEON / aarch64 intrinsic substrings that signal an
/// ISR-unsafe import. A Tier 1b/Tier 2 module (`isr_safe = true`,
/// `domain_exec_mode == 2 or 4`) hard-preempts the cooperative tier,
/// and the ISR is documented as scalar-only. If a module accidentally
/// pulls in a NEON intrinsic, restoring its NEON state on ISR
/// completion is the caller's job — and nothing in the runtime saves
/// the NEON file. A Tier 1b ISR that clobbers NEON would corrupt the
/// preempted cooperative thread's vector regs.
///
/// The substrings below cover the canonical NEON paths in `core::arch`:
///   * `core::arch::aarch64` — the `arm_neon` module re-exports
///   * `arm_neon::` — direct import of the intrinsic module
///   * `vqaddq_`, `vld1q_`, `vst1q_`, `vmlaq_`, etc. — common intrinsic
///     prefixes (`v[name][q]_[type]`). The `vld1q_`/`vst1q_` plus
///     `vqaddq_` triplet covers ~95% of real NEON use without a wide
///     false-positive surface.
const NEON_IMPORT_MARKERS: &[&str] = &[
    "core::arch::aarch64",
    "arm_neon::",
    "::vld1q_",
    "::vst1q_",
    "::vqaddq_",
    "::vaddq_",
    "::vmulq_",
    "::vmlaq_",
];

/// Scan a module source tree for NEON / aarch64 SIMD imports.
/// Returns `Ok(())` if no markers found, `Err` listing the offending
/// files otherwise. Designed to be called from the build path when
/// `manifest.isr_safe == true` so a module that claims ISR safety
/// can't quietly pull in NEON intrinsics.
///
/// The check is **substring-based and source-static** — it parses
/// `.rs` files under `src_root` and looks for the marker strings
/// in `NEON_IMPORT_MARKERS`. Inside a string literal or comment that
/// happens to mention the marker, the check will false-positive;
/// fix the source comment or split the literal in those cases. The
/// alternative (full Rust parsing) costs ~100× more for the same
/// signal.
pub fn check_isr_safe_no_neon(src_root: &Path) -> Result<()> {
    if !src_root.exists() {
        return Ok(());
    }
    let mut offenders: Vec<String> = Vec::new();
    walk_rs(src_root, &mut |path, source| {
        for marker in NEON_IMPORT_MARKERS {
            if source.contains(marker) {
                offenders.push(format!(
                    "{}: contains `{}` (NEON-marker substring)",
                    path.display(),
                    marker,
                ));
                break;
            }
        }
    });
    if offenders.is_empty() {
        Ok(())
    } else {
        Err(Error::Module(format!(
            "ISR-tier module declares `isr_safe = true` but its source imports NEON / \
             aarch64 SIMD intrinsics. Tier 1b/Tier 2 ISRs are scalar-only by contract \
             — NEON registers are not preserved across an ISR. Offending files:\n  {}",
            offenders.join("\n  "),
        )))
    }
}

/// Walk `.rs` files under `root`, invoking `f(path, source)` for each.
/// Best-effort; unreadable files are skipped silently. Pure
/// directory traversal — no Cargo metadata, no symlink chasing.
fn walk_rs<F: FnMut(&Path, &str)>(root: &Path, f: &mut F) {
    let entries = match std::fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_rs(&path, f);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            if let Ok(source) = std::fs::read_to_string(&path) {
                f(&path, &source);
            }
        }
    }
}

impl Manifest {
    /// Compute the required_caps bitmask from resource claims. Each
    /// declared contract id sets the corresponding bit in a u32; contract
    /// ids must fall in 0..31 to be expressible. Non-contract permissions
    /// live in `self.permissions` and are serialised separately into
    /// manifest binary byte 15.
    pub fn required_caps_mask(&self) -> Result<u32> {
        let mut mask = 0u32;
        for r in &self.resources {
            if r.device_class < 32 {
                mask |= 1u32 << r.device_class;
            } else {
                return Err(Error::Module(format!(
                    "requires_contract {} (0x{:02x}) is outside the required_caps u32 range (bits 0..31).",
                    contract_name_to_str(r.device_class),
                    r.device_class,
                )));
            }
        }
        Ok(mask)
    }

    /// Look up a port by name. Returns (direction, index, content_type).
    pub fn find_port_by_name(&self, name: &str) -> Option<(u8, u8, u8)> {
        self.ports.iter().find_map(|p| {
            p.name
                .as_deref()
                .filter(|n| *n == name)
                .map(|_| (p.direction, p.index, p.content_type))
        })
    }

    /// Look up a port by direction and index. Returns content_type if found.
    pub fn find_port(&self, direction: u8, index: u8) -> Option<u8> {
        self.ports.iter().find_map(|p| {
            if p.direction == direction && p.index == index {
                Some(p.content_type)
            } else {
                None
            }
        })
    }

    /// Look up a module's source-tree manifest by type name. Returns
    /// `Ok(None)` if nothing matches; `Err` only on a parse failure of
    /// an existing file. Results are cached for the lifetime of the
    /// process — each module type is parsed at most once per
    /// invocation, including negative lookups.
    ///
    /// Search paths cover both PIC modules (one of `drivers/`,
    /// `foundation/`, `app/`, or the catch-all `modules/`) and
    /// kernel-resident built-ins (under
    /// `modules/builtin/<platform>/<name>/`). See
    /// `docs/architecture/abi_layers.md` for what each tree is for.
    pub fn from_source_tree(module_type: &str) -> Result<Option<Self>> {
        static CACHE: std::sync::OnceLock<
            std::sync::Mutex<std::collections::HashMap<String, Option<Manifest>>>,
        > = std::sync::OnceLock::new();
        let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
        if let Some(hit) = cache.lock().unwrap().get(module_type) {
            return Ok(hit.clone());
        }
        const SOURCE_DIRS: &[&str] = &[
            "modules/drivers",
            "modules/foundation",
            "modules/app",
            "modules/builtin/linux",
            "modules/builtin/host",
            "modules/builtin/wasm",
            "modules/builtin/qemu",
            "modules",
        ];
        let mut found: Option<Manifest> = None;
        for dir in SOURCE_DIRS {
            let p = std::path::Path::new(dir)
                .join(module_type)
                .join("manifest.toml");
            if p.exists() {
                let m = Manifest::from_toml(&p)?;
                found = Some(m);
                break;
            }
        }
        cache
            .lock()
            .unwrap()
            .insert(module_type.to_string(), found.clone());
        Ok(found)
    }

    /// Parse manifest from a TOML file.
    pub fn from_toml(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| Error::Module(format!("cannot read {}: {}", path.display(), e)))?;
        let toml_val: TomlManifest = toml::from_str(&content)
            .map_err(|e| Error::Module(format!("invalid manifest TOML: {e}")))?;

        let (major, minor, patch) = parse_semver(&toml_val.version)?;
        let module_version = encode_semver(major, minor, patch);

        let hardware_targets = toml_val
            .hardware_targets
            .map(|t| hardware_targets_from_list(&t))
            .unwrap_or(0x01);

        let state_size_hint = toml_val.state_size_hint.unwrap_or(0);

        let mut ports = Vec::new();
        let mut port_names: std::collections::HashSet<String> = std::collections::HashSet::new();
        // Track next auto-index per direction: [input, output, ctrl]
        let mut next_index = [0u8; 4];
        for p in toml_val.ports.unwrap_or_default() {
            let direction = direction_from_str(&p.direction)?;
            let content_type = content_type_from_str(&p.content_type)?;
            let mut flags = 0u8;
            if p.required.unwrap_or(false) {
                flags |= 0x01;
            }

            // Validate port name
            if let Some(ref name) = p.name {
                if name == "in" || name == "out" || name == "ctrl" {
                    return Err(Error::Module(format!(
                        "port name '{name}' is a reserved word"
                    )));
                }
                if !port_names.insert(name.clone()) {
                    return Err(Error::Module(format!("duplicate port name '{name}'")));
                }
            }

            // Resolve port index
            let dir_idx = direction as usize;
            let index = if let Some(idx) = p.index {
                // Explicit index — advance auto-index past it
                if idx >= next_index[dir_idx] {
                    next_index[dir_idx] = idx + 1;
                }
                idx
            } else {
                let idx = next_index[dir_idx];
                next_index[dir_idx] = idx + 1;
                idx
            };

            ports.push(PortSpec {
                direction,
                content_type,
                flags,
                name: p.name,
                index,
            });
        }

        let mut resources = Vec::new();
        for r in toml_val.resources.unwrap_or_default() {
            let cid = contract_id_from_name(&r.device_class)?;
            let access_mode = access_mode_from_str(&r.access)?;
            let instance = r.instance.unwrap_or(0xFF);
            resources.push(ResourceClaim {
                device_class: cid,
                access_mode,
                instance,
            });
        }

        let mut permissions = ManifestPermissions::default();
        for name in toml_val.permissions.unwrap_or_default() {
            match permission::from_name(&name) {
                Some(bit) => permissions.bits |= bit,
                None => {
                    return Err(Error::Module(format!(
                        "unknown permission: {name} — expected one of: reconfigure, \
                         flash_raw, backing_provider, platform_raw, monitor, bridge \
                         (see docs/architecture/abi_layers.md)",
                    )));
                }
            }
        }

        let mut dependencies = Vec::new();
        for d in toml_val.dependencies.unwrap_or_default() {
            let name_hash = fnv1a_hash(d.name.as_bytes());
            let min_version = if let Some(v) = d.min_version {
                let (maj, min, pat) = parse_semver(&v)?;
                encode_semver(maj, min, pat)
            } else {
                0
            };
            dependencies.push(Dependency {
                name_hash,
                min_version,
            });
        }

        let commands = if let Some(cmds) = toml_val.commands {
            CommandVocabulary {
                accepts: cmds.accepts.unwrap_or_default(),
                emits: cmds.emits.unwrap_or_default(),
            }
        } else {
            CommandVocabulary::default()
        };

        let provides = toml_val.provides.unwrap_or_default();
        let mut capabilities = toml_val.capabilities.unwrap_or_default();
        validate_capability_names(&mut capabilities)?;

        let builtin = toml_val.builtin.unwrap_or(false);

        let raw_params = toml_val.params.unwrap_or_default();
        // `[[params]]` belongs to built-ins. PIC (`.fmod`) modules carry
        // their schema in the binary via the `define_params!` macro;
        // declaring it again in the manifest would create two sources
        // of truth for the same wire layout.
        if !builtin && !raw_params.is_empty() {
            return Err(Error::Module(format!(
                "[[params]] is only valid on built-in modules (`builtin = true`). \
                 PIC modules embed their schema via `define_params!`. \
                 Got {} param(s) on a non-builtin manifest.",
                raw_params.len(),
            )));
        }

        let mut params: Vec<ManifestParam> = Vec::new();
        for (i, p) in raw_params.into_iter().enumerate() {
            let tag = 10u8
                .checked_add(i as u8)
                .ok_or_else(|| Error::Module("too many [[params]] entries (max 245)".into()))?;
            let ptype = match p.ptype.as_str() {
                "u8" => ManifestParamType::U8,
                "u16" => ManifestParamType::U16,
                "u32" => ManifestParamType::U32,
                "str" | "string" => ManifestParamType::Str,
                "enum" => ManifestParamType::Enum,
                other => {
                    return Err(Error::Module(format!(
                        "param '{}': unknown type '{}' (expected: u8, u16, u32, str, enum)",
                        p.name, other,
                    )));
                }
            };

            // Enum: values list is required; each name maps to its index.
            let mut enum_values: Vec<(String, u8)> = Vec::new();
            if ptype == ManifestParamType::Enum {
                let vals = p.values.as_ref().ok_or_else(|| {
                    Error::Module(format!(
                        "param '{}': enum requires `values = [...]`",
                        p.name
                    ))
                })?;
                if vals.is_empty() || vals.len() > 256 {
                    return Err(Error::Module(format!(
                        "param '{}': enum needs 1..=256 values",
                        p.name
                    )));
                }
                for (j, v) in vals.iter().enumerate() {
                    enum_values.push((v.clone(), j as u8));
                }
            } else if p.values.is_some() {
                return Err(Error::Module(format!(
                    "param '{}': `values` only applies to type='enum'",
                    p.name
                )));
            }

            // Resolve default. Numeric types accept integers; str/enum
            // accept strings (enum default must be one of `values`).
            let mut default_num: u32 = 0;
            let mut default_str = String::new();
            match (&ptype, p.default.as_ref()) {
                (
                    ManifestParamType::U8 | ManifestParamType::U16 | ManifestParamType::U32,
                    Some(v),
                ) => {
                    let n = v.as_integer().ok_or_else(|| {
                        Error::Module(format!("param '{}': default must be an integer", p.name))
                    })?;
                    if n < 0 {
                        return Err(Error::Module(format!(
                            "param '{}': default must be non-negative",
                            p.name
                        )));
                    }
                    default_num = n as u32;
                }
                (ManifestParamType::Str, Some(v)) => {
                    let s = v.as_str().ok_or_else(|| {
                        Error::Module(format!("param '{}': default must be a string", p.name))
                    })?;
                    default_str = s.to_string();
                }
                (ManifestParamType::Enum, Some(v)) => {
                    let s = v.as_str().ok_or_else(|| {
                        Error::Module(format!(
                            "param '{}': default must be one of {:?}",
                            p.name,
                            enum_values.iter().map(|(n, _)| n).collect::<Vec<_>>(),
                        ))
                    })?;
                    let (_, val) = enum_values.iter().find(|(n, _)| n == s).ok_or_else(|| {
                        Error::Module(format!(
                            "param '{}': default '{}' is not in values {:?}",
                            p.name,
                            s,
                            enum_values.iter().map(|(n, _)| n).collect::<Vec<_>>(),
                        ))
                    })?;
                    default_num = *val as u32;
                    default_str = s.to_string();
                }
                (_, None) => {} // no default — zero / empty
            }

            // Validate range bounds.
            let range = if let Some([min, max]) = p.range {
                if matches!(ptype, ManifestParamType::Str | ManifestParamType::Enum) {
                    return Err(Error::Module(format!(
                        "param '{}': `range` only applies to numeric types",
                        p.name
                    )));
                }
                if min > max {
                    return Err(Error::Module(format!(
                        "param '{}': range min ({}) > max ({})",
                        p.name, min, max
                    )));
                }
                Some((min, max))
            } else {
                None
            };

            // A `required` param must not also carry a `default` — that
            // would be contradictory. Catch the schema error early.
            if p.required && p.default.is_some() {
                return Err(Error::Module(format!(
                    "param '{}': `required = true` and `default` are mutually exclusive",
                    p.name
                )));
            }

            params.push(ManifestParam {
                tag,
                name: p.name,
                ptype,
                default_num,
                default_str,
                enum_values,
                range,
                required: p.required,
            });
        }

        Ok(Manifest {
            module_version,
            hardware_targets,
            state_size_hint,
            ports,
            resources,
            permissions,
            dependencies,
            integrity_hash: None, // set later by caller
            signature: None,
            signer_fp: None,
            commands,
            provides,
            capabilities,
            builtin,
            isr_safe: toml_val.isr_safe,
            pre_tick_drain: toml_val.pre_tick_drain,
            requires: toml_val.requires,
            params,
        })
    }

    /// Serialize manifest to binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let has_integrity = self.integrity_hash.is_some();
        let has_signature = self.signature.is_some() && self.signer_fp.is_some();
        // Signature requires integrity (signature is over the hash).
        let has_signature = has_signature && has_integrity;
        let var_size = self.ports.len() * 4
            + self.resources.len() * 4
            + self.dependencies.len() * 8
            + if has_integrity { 32 } else { 0 }
            + if has_signature {
                SIGNATURE_BLOCK_SIZE
            } else {
                0
            };
        let total = MANIFEST_HEADER_SIZE + var_size;
        let mut buf = Vec::with_capacity(total);

        // Header (16 bytes). Signed and unsigned manifests share the
        // same port-record layout; signature presence is signalled by
        // flag bit 1 (byte 14), not by a version split.
        buf.extend_from_slice(&MANIFEST_MAGIC.to_le_bytes());
        buf.push(MANIFEST_VERSION);
        buf.push(self.ports.len() as u8);
        buf.push(self.resources.len() as u8);
        buf.push(self.dependencies.len() as u8);
        buf.extend_from_slice(&self.module_version.to_le_bytes());
        buf.extend_from_slice(&self.hardware_targets.to_le_bytes());
        buf.extend_from_slice(&self.state_size_hint.to_le_bytes());
        // byte 14: bit 0 = has_integrity, bit 1 = has_signature,
        //          bit 2 = isr_safe (author attestation; the
        //                  **build-time** `validate_isr_tier_admission`
        //                  in `tools/src/config.rs` is the live gate
        //                  for this flag. Tier 1b admission is live;
        //                  Tier 2 is still hard-rejected at build
        //                  time pending the PIC-loader
        //                  `module_isr_entry` lift. The kernel-side
        //                  `Manifest::from_bytes` round-trips the
        //                  bit through `LoadedModule.manifest`, but
        //                  the loader does NOT currently re-check it
        //                  at instantiation — the runtime gate today
        //                  is the §D7 EACCES check on every gated
        //                  syscall (`scheduler::deny_isr_tier_syscall`).
        //                  A loader-side defense-in-depth check that
        //                  mirrors the build-time one would still be
        //                  worth adding for hand-rolled binaries.
        //          bit 3 = pre_tick_drain (Tier 1c opt-in; see
        //                  `.context/rfc_isr_tier_surface.md` §D8).
        //                  Read by `prepare_graph` to populate
        //                  `domain_pre_tick_order` and exclude the
        //                  module from `domain_exec_order`.
        //          bits 4-7: reserved (0).
        let flags = (if has_integrity { 1 } else { 0 })
            | (if has_signature { 2 } else { 0 })
            | (if self.isr_safe { 4 } else { 0 })
            | (if self.pre_tick_drain { 8 } else { 0 });
        buf.push(flags);
        // byte 15: fine-grained permissions bitmap (see `permission::*`).
        // The kernel reads this byte directly at module instantiation.
        buf.push(self.permissions.bits);

        // Ports (4 bytes each: direction, content_type, flags, index).
        // Byte 3 is the per-direction port index (0..15) the TOML
        // resolver computed in `parse_toml` — manifests may pin
        // explicit indices via `index = N`, so the binary must carry
        // the resolved value rather than re-derive it from source
        // order on the read side.
        for p in &self.ports {
            buf.push(p.direction);
            buf.push(p.content_type);
            buf.push(p.flags);
            buf.push(p.index);
        }

        // Resources (4 bytes each)
        for r in &self.resources {
            buf.push(r.device_class);
            buf.push(r.access_mode);
            buf.push(r.instance);
            buf.push(0);
        }

        // Dependencies (8 bytes each)
        for d in &self.dependencies {
            buf.extend_from_slice(&d.name_hash.to_le_bytes());
            buf.extend_from_slice(&d.min_version.to_le_bytes());
            buf.push(0);
            buf.push(0);
        }

        // Integrity hash (32 bytes)
        if let Some(hash) = &self.integrity_hash {
            buf.extend_from_slice(hash);
        }

        // Signature block (64 B sig + 32 B signer fingerprint). Only emitted
        // when both present *and* the integrity hash is set (signature is
        // over that hash).
        if has_signature {
            buf.extend_from_slice(self.signature.as_ref().unwrap());
            buf.extend_from_slice(self.signer_fp.as_ref().unwrap());
        }

        debug_assert_eq!(buf.len(), total);
        buf
    }

    /// Deserialize manifest from binary.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < MANIFEST_HEADER_SIZE {
            return Err(Error::Module(format!(
                "manifest too small: {} bytes",
                data.len()
            )));
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != MANIFEST_MAGIC {
            return Err(Error::Module(format!(
                "invalid manifest magic: 0x{magic:08x}"
            )));
        }

        let version = data[4];
        if version != MANIFEST_VERSION {
            return Err(Error::Module(format!(
                "unsupported manifest version: {version}"
            )));
        }

        let port_count = data[5] as usize;
        let resource_count = data[6] as usize;
        let dependency_count = data[7] as usize;
        let module_version = u16::from_le_bytes([data[8], data[9]]);
        let hardware_targets = u16::from_le_bytes([data[10], data[11]]);
        let state_size_hint = u16::from_le_bytes([data[12], data[13]]);
        let flags = data[14];
        let has_integrity = (flags & 0x01) != 0;
        let has_signature = (flags & 0x02) != 0;
        let isr_safe = (flags & 0x04) != 0;
        let pre_tick_drain = (flags & 0x08) != 0;
        let permissions_bits = data[15]; // fine-grained permissions bitmap

        let expected_size = MANIFEST_HEADER_SIZE
            + port_count * 4
            + resource_count * 4
            + dependency_count * 8
            + if has_integrity { 32 } else { 0 }
            + if has_signature {
                SIGNATURE_BLOCK_SIZE
            } else {
                0
            };

        if data.len() < expected_size {
            return Err(Error::Module(format!(
                "manifest truncated: {} bytes, expected {}",
                data.len(),
                expected_size
            )));
        }

        let mut offset = MANIFEST_HEADER_SIZE;

        let mut ports = Vec::with_capacity(port_count);
        for _ in 0..port_count {
            ports.push(PortSpec {
                direction: data[offset],
                content_type: data[offset + 1],
                flags: data[offset + 2],
                name: None,
                index: data[offset + 3],
            });
            offset += 4;
        }

        let mut resources = Vec::with_capacity(resource_count);
        for _ in 0..resource_count {
            resources.push(ResourceClaim {
                device_class: data[offset],
                access_mode: data[offset + 1],
                instance: data[offset + 2],
            });
            offset += 4;
        }

        let mut dependencies = Vec::with_capacity(dependency_count);
        for _ in 0..dependency_count {
            let name_hash = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            let min_version = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
            dependencies.push(Dependency {
                name_hash,
                min_version,
            });
            offset += 8;
        }

        let integrity_hash = if has_integrity {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;
            Some(hash)
        } else {
            None
        };

        let (signature, signer_fp) = if has_signature {
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&data[offset..offset + 64]);
            offset += 64;
            let mut fp = [0u8; 32];
            fp.copy_from_slice(&data[offset..offset + 32]);
            (Some(sig), Some(fp))
        } else {
            (None, None)
        };

        Ok(Manifest {
            module_version,
            hardware_targets,
            state_size_hint,
            ports,
            resources,
            permissions: ManifestPermissions {
                bits: permissions_bits,
            },
            dependencies,
            integrity_hash,
            signature,
            signer_fp,
            commands: CommandVocabulary::default(),
            provides: Vec::new(),     // not serialized in binary format
            capabilities: Vec::new(), // not serialized in binary format
            builtin: false,
            isr_safe,
            pre_tick_drain,
            // `requires` is a TOML-only field — modules carry their
            // binary manifest stripped of the requires block (it's a
            // build-time concern, not a runtime one). Round-tripping
            // through the binary loses it; that's intentional.
            requires: TomlRequires::default(),
            params: Vec::new(), // toml-only, not serialized
        })
    }

    /// Display manifest contents for info/debug output.
    pub fn display(&self) -> String {
        let (major, minor, patch) = decode_semver(self.module_version);
        let mut lines = vec![
            format!("  version: {}.{}.{}", major, minor, patch),
            format!("  hardware_targets: 0x{:04x}", self.hardware_targets),
            match self.required_caps_mask() {
                Ok(m) => format!("  required_caps: 0x{m:08x}"),
                Err(e) => format!("  required_caps: <error: {e}>"),
            },
        ];
        if self.state_size_hint > 0 {
            lines.push(format!("  state_size_hint: {} bytes", self.state_size_hint));
        }
        if !self.ports.is_empty() {
            lines.push("  ports:".into());
            for p in &self.ports {
                let req = if p.flags & 0x01 != 0 {
                    " (required)"
                } else {
                    ""
                };
                let name_str = p.name.as_deref().unwrap_or("-");
                lines.push(format!(
                    "    {}[{}] {} ({}){}",
                    direction_to_str(p.direction),
                    p.index,
                    name_str,
                    content_type_to_str(p.content_type),
                    req,
                ));
            }
        }
        if !self.resources.is_empty() {
            lines.push("  resources:".into());
            for r in &self.resources {
                if r.instance != 0xFF {
                    lines.push(format!(
                        "    {}[{}] ({})",
                        contract_name_to_str(r.device_class),
                        r.instance,
                        access_mode_to_str(r.access_mode),
                    ));
                } else {
                    lines.push(format!(
                        "    {} ({})",
                        contract_name_to_str(r.device_class),
                        access_mode_to_str(r.access_mode),
                    ));
                }
            }
        }
        if self.permissions.bits != 0 {
            lines.push(format!(
                "  permissions: [{}]",
                permission::names(self.permissions.bits).join(", ")
            ));
        }
        if !self.dependencies.is_empty() {
            lines.push("  dependencies:".into());
            for d in &self.dependencies {
                let (maj, min, pat) = decode_semver(d.min_version);
                lines.push(format!(
                    "    hash=0x{:08x} min={}.{}.{}",
                    d.name_hash, maj, min, pat,
                ));
            }
        }
        if !self.commands.accepts.is_empty() || !self.commands.emits.is_empty() {
            lines.push("  commands:".into());
            if !self.commands.accepts.is_empty() {
                lines.push(format!(
                    "    accepts: [{}]",
                    self.commands.accepts.join(", ")
                ));
            }
            if !self.commands.emits.is_empty() {
                lines.push(format!("    emits: [{}]", self.commands.emits.join(", ")));
            }
        }
        if let Some(hash) = &self.integrity_hash {
            let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
            lines.push(format!("  integrity: sha256:{hex}"));
        }
        lines.join("\n")
    }
}

/// Compute SHA-256 integrity hash over code and data sections.
pub fn compute_integrity(code: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(code);
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

// ── TOML deserialization structs ────────────────────────────────────────────

#[derive(Deserialize)]
struct TomlManifest {
    version: String,
    hardware_targets: Option<Vec<String>>,
    state_size_hint: Option<u16>,
    ports: Option<Vec<TomlPort>>,
    resources: Option<Vec<TomlResource>>,
    /// Top-level `permissions = ["reconfigure", "flash_raw", …]` list —
    /// fine-grained non-contract permission categories. Distinct from
    /// `[[resources]]` (which is for public contract access).
    permissions: Option<Vec<String>>,
    dependencies: Option<Vec<TomlDependency>>,
    commands: Option<TomlCommands>,
    provides: Option<Vec<String>>,
    /// AV / presentation capability strings. Whitelisted by
    /// `AV_CAPABILITY_NAMES`; validated and canonicalized at parse time.
    capabilities: Option<Vec<String>>,
    /// Module is built into the kernel (no .fmod file needed).
    builtin: Option<bool>,
    /// Author attests ISR-safety. Required for Tier 1b/2 admission.
    /// See `Manifest::isr_safe` for the contract.
    #[serde(default)]
    isr_safe: bool,
    /// Author opts the module into the Tier 1c pre-pass drain slot.
    /// See `Manifest::pre_tick_drain` for the contract.
    #[serde(default)]
    pre_tick_drain: bool,
    /// Hardware-feature requirements. Validated at config time
    /// against the resolved target's capability matrix. A module that
    /// declares `requires.fpu = true` is rejected from a target without
    /// FPU support (RP2040). Default-all-false means "no specific
    /// requirements," which satisfies every silicon.
    #[serde(default)]
    requires: TomlRequires,
    /// `[[params]]` declarations — built-in modules only. PIC modules
    /// embed schema in their .fmod and these are ignored.
    params: Option<Vec<TomlParam>>,
}

/// Hardware-feature requirements declared by a module in its
/// `[requires]` TOML section. Used by `check_target_capabilities` to
/// reject the module at config time if the resolved target lacks
/// the requested capability — catches a class of "module pulls in
/// soft-float on a target without FPU and silently runs 100× slower"
/// bugs before they ship.
#[derive(Deserialize, Default, Clone, Copy, Debug)]
#[serde(default)]
pub struct TomlRequires {
    /// Hardware floating-point unit. Modules using `f32`/`f64` math
    /// on a target without FPU fall back to soft-float helpers in
    /// `compiler-builtins`, which are 50–100× slower than scalar
    /// integer ops. Declare `requires.fpu = true` to be rejected
    /// from such targets at build time.
    pub fpu: bool,
    /// Advanced SIMD (NEON on aarch64). Modules that use
    /// `core::arch::aarch64` intrinsics must declare this; the build
    /// then rejects placement on Cortex-M / WASM targets where the
    /// intrinsics simply don't exist (link error or panic at runtime).
    pub neon: bool,
    /// Memory-management unit with page-table isolation. Modules that
    /// rely on `rfc_virtual_memory` paged arenas declare this; the
    /// build rejects placement on Cortex-M / Cortex-A targets without
    /// an MMU (RP2350 has an MPU but not an MMU).
    pub mmu: bool,
}

/// Target hardware-capability matrix used by
/// `check_target_capabilities`. Constructed from a target's silicon
/// id; tracks the three boolean caps that modules can demand. Built
/// here rather than read from `TargetDescriptor` to keep this lint
/// portable across the tools crate's internal types (avoids a
/// circular dependency in tools/src/config.rs).
#[derive(Clone, Copy, Debug)]
pub struct TargetCapabilities {
    pub fpu: bool,
    pub neon: bool,
    pub mmu: bool,
}

impl TargetCapabilities {
    /// Resolve capabilities for a silicon id OR a board id.
    /// Conservative — unknown names return all-false so a manifest's
    /// `requires.fpu = true` will reject placement until the name
    /// is added here.
    ///
    /// Real YAML configs commonly use board ids (`cm5`, `pico2w`,
    /// `linux`) rather than the silicon id (`bcm2712`, `rp2350a`).
    /// The first arm of `match` normalises board ids to the matching
    /// silicon entry; callers that already pass a silicon id pass
    /// through unchanged. The board → silicon map mirrors
    /// `targets/boards/<board>.toml`'s `board.silicon` field —
    /// adding a board requires both the TOML descriptor AND a row
    /// here.
    pub fn for_silicon(name: &str) -> Self {
        // Board → silicon normalisation. Mirrors
        // `targets/boards/<board>.toml::[board].silicon`.
        let silicon = match name {
            "cm5" => "bcm2712",
            "qemu-virt" => "bcm2712",
            "pico2w" => "rp2350a",
            "waveshare-lcd4" => "rp2350b",
            "pico" | "picow" => "rp2040",
            "linux-host" => "linux",
            other => other,
        };
        match silicon {
            // Cortex-M0+, no FPU, no SIMD, no MMU.
            "rp2040" => Self {
                fpu: false,
                neon: false,
                mmu: false,
            },
            // Cortex-M33 with FPv5-SP single-precision FPU, no SIMD,
            // MPU but not MMU.
            s if s.starts_with("rp2350") => Self {
                fpu: true,
                neon: false,
                mmu: false,
            },
            // Cortex-A76 quad-core, full FP/NEON, full MMU.
            "bcm2712" => Self {
                fpu: true,
                neon: true,
                mmu: true,
            },
            // Hosted: always all-yes (running on the dev machine).
            "linux" => Self {
                fpu: true,
                neon: true,
                mmu: true,
            },
            // WASM: no NEON in the portable target; FPU yes via
            // wasm-mvp; no MMU (linear memory only).
            "wasm" | "wasm32" => Self {
                fpu: true,
                neon: false,
                mmu: false,
            },
            // Unknown — fail closed.
            _ => Self {
                fpu: false,
                neon: false,
                mmu: false,
            },
        }
    }
}

/// Confirm that the module's declared hardware-feature
/// requirements are satisfied by the target's capabilities. Returns
/// `Ok(())` if compatible, `Err` listing every mismatched capability
/// otherwise.
///
/// Designed to be called from the config-validation path against the
/// resolved per-module target after `parse_modules_from_config`. The
/// resulting error message is operator-facing (cites silicon id and
/// the missing caps).
pub fn check_target_capabilities(manifest_requires: TomlRequires, silicon: &str) -> Result<()> {
    let caps = TargetCapabilities::for_silicon(silicon);
    let mut missing: Vec<&str> = Vec::new();
    if manifest_requires.fpu && !caps.fpu {
        missing.push("fpu");
    }
    if manifest_requires.neon && !caps.neon {
        missing.push("neon");
    }
    if manifest_requires.mmu && !caps.mmu {
        missing.push("mmu");
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(Error::Module(format!(
            "module's `[requires]` declares {} but silicon `{}` does not provide them. \
             Either place this module on a target with those caps, or drop the requirement \
             if it's no longer needed.",
            missing.join(", "),
            silicon,
        )))
    }
}

#[derive(Deserialize)]
struct TomlParam {
    name: String,
    /// One of: u8, u16, u32, str, enum
    #[serde(rename = "type")]
    ptype: String,
    /// TOML may parse the default as int, string, or enum-name; capture
    /// raw and resolve in `Manifest::from_toml`.
    default: Option<toml::Value>,
    /// Required for `type = "enum"`: list of legal value names. Each maps
    /// to its index (0..len-1) on the wire.
    values: Option<Vec<String>>,
    /// Optional inclusive `[min, max]` for numeric types.
    range: Option<[u32; 2]>,
    /// `required = true` makes YAML omission a build error. Implies no
    /// safe default exists for this param — falling back would
    /// silently misconfigure the graph.
    #[serde(default)]
    required: bool,
}

#[derive(Deserialize)]
struct TomlPort {
    direction: String,
    content_type: String,
    required: Option<bool>,
    name: Option<String>,
    index: Option<u8>,
}

#[derive(Deserialize)]
struct TomlResource {
    /// Public contract this module needs access to. Values: one of
    /// gpio, spi, i2c, pio, uart, adc, pwm, fs. Non-contract
    /// permissions go in the top-level `permissions = [...]` list.
    #[serde(rename = "requires_contract")]
    device_class: String,
    access: String,
    instance: Option<u8>,
}

#[derive(Deserialize)]
struct TomlDependency {
    name: String,
    min_version: Option<String>,
}

#[derive(Deserialize)]
struct TomlCommands {
    accepts: Option<Vec<String>>,
    emits: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_roundtrip() {
        let v = encode_semver(1, 2, 3);
        assert_eq!(decode_semver(v), (1, 2, 3));
    }

    #[test]
    fn empty_manifest_roundtrip() {
        let m = Manifest::default();
        let bytes = m.to_bytes();
        assert_eq!(bytes.len(), MANIFEST_HEADER_SIZE);
        let m2 = Manifest::from_bytes(&bytes).unwrap();
        assert_eq!(m2.module_version, m.module_version);
        assert!(m2.ports.is_empty());
        assert!(m2.resources.is_empty());
        assert!(m2.dependencies.is_empty());
        assert!(m2.integrity_hash.is_none());
    }

    #[test]
    fn manifest_with_integrity_roundtrip() {
        let mut m = Manifest::default();
        m.ports.push(PortSpec {
            direction: 0,
            content_type: 3,
            flags: 1,
            name: None,
            index: 0,
        });
        m.resources.push(ResourceClaim {
            device_class: 0x04,
            access_mode: 2,
            instance: 0xFF,
        });
        m.dependencies.push(Dependency {
            name_hash: 0x12345678,
            min_version: encode_semver(1, 0, 0),
        });
        m.integrity_hash = Some([0xAB; 32]);

        let bytes = m.to_bytes();
        let m2 = Manifest::from_bytes(&bytes).unwrap();
        assert_eq!(m2.ports.len(), 1);
        assert_eq!(m2.ports[0].content_type, 3);
        assert_eq!(m2.resources.len(), 1);
        assert_eq!(m2.resources[0].device_class, 0x04);
        assert_eq!(m2.dependencies.len(), 1);
        assert_eq!(m2.dependencies[0].name_hash, 0x12345678);
        assert_eq!(m2.integrity_hash.unwrap(), [0xAB; 32]);
    }

    #[test]
    fn required_caps_mask() {
        let mut m = Manifest::default();
        m.resources.push(ResourceClaim {
            device_class: 0x01,
            access_mode: 0,
            instance: 0xFF,
        }); // GPIO
        m.resources.push(ResourceClaim {
            device_class: 0x04,
            access_mode: 2,
            instance: 0xFF,
        }); // PIO
        assert_eq!(m.required_caps_mask().unwrap(), (1 << 1) | (1 << 4));
    }

    fn parse_toml(src: &str) -> Result<Manifest> {
        // RAII scratch dir; cleaned when this function returns. The
        // path passed to `from_toml` is only borrowed during the
        // synchronous parse, so the TempDir can drop right after.
        let tmp = tempfile::Builder::new()
            .prefix("fluxor-manifest-test-")
            .tempdir()
            .unwrap();
        let path = tmp.path().join("manifest.toml");
        std::fs::write(&path, src).unwrap();
        Manifest::from_toml(&path)
    }

    #[test]
    fn rejects_params_on_non_builtin_manifest() {
        let src = r#"
version = "1.0.0"
hardware_targets = ["linux"]

[[ports]]
name = "stream"
direction = "output"
content_type = "OctetStream"

[[params]]
name = "x"
type = "u32"
default = 1
"#;
        let err = parse_toml(src).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("[[params]] is only valid on built-in modules"),
            "unexpected message: {msg}",
        );
    }

    #[test]
    fn accepts_params_on_builtin_manifest() {
        let src = r#"
version = "1.0.0"
hardware_targets = ["linux"]
builtin = true

[[ports]]
name = "stream"
direction = "output"
content_type = "OctetStream"

[[params]]
name = "width"
type = "u32"
default = 480
range = [1, 4096]

[[params]]
name = "scale_mode"
type = "enum"
values = ["fit", "stretch"]
default = "fit"

[[params]]
name = "path"
type = "str"
required = true
"#;
        let m = parse_toml(src).expect("parse");
        assert!(m.builtin);
        assert_eq!(m.params.len(), 3);
        // Tag auto-assignment starts at 10 in declaration order.
        assert_eq!(m.params[0].tag, 10);
        assert_eq!(m.params[1].tag, 11);
        assert_eq!(m.params[2].tag, 12);
        // Range honored.
        assert_eq!(m.params[0].range, Some((1, 4096)));
        // Enum value table.
        assert_eq!(m.params[1].enum_values.len(), 2);
        assert_eq!(m.params[1].enum_values[0].1, 0); // fit -> 0
        assert_eq!(m.params[1].enum_values[1].1, 1); // stretch -> 1
        assert_eq!(m.params[1].default_num, 0); // fit
                                                // required honored.
        assert!(m.params[2].required);
        assert!(!m.params[0].required);
    }

    #[test]
    fn rejects_required_with_default() {
        let src = r#"
version = "1.0.0"
builtin = true

[[params]]
name = "path"
type = "str"
default = "/tmp/foo"
required = true
"#;
        let err = parse_toml(src).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("mutually exclusive"), "unexpected: {msg}");
    }
}
