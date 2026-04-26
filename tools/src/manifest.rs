//! Module manifest: structured metadata for composition, validation, and integrity.
//!
//! The manifest is a required section in every `.fmod` file (ABI v2+).
//! It describes ports, resource claims, dependencies, and an optional integrity hash.

#![allow(dead_code)]

use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::hash::fnv1a_hash;

/// Manifest section magic: "FXMF"
pub const MANIFEST_MAGIC: u32 = 0x464D5846;

/// Current manifest format version. v1 = unsigned (integrity hash optional).
/// v2 adds an optional Ed25519 signature block after the integrity hash:
///   [ed25519_signature: 64B][signer_pubkey_fingerprint: 32B]
/// The signature covers the 32-byte SHA-256 integrity hash (not the full
/// module bytes directly) — integrity hash is still the anchor; the
/// signature authenticates it.
pub const MANIFEST_VERSION: u8 = 2;

/// Manifest header size (fixed portion before variable sections)
pub const MANIFEST_HEADER_SIZE: usize = 16;

/// Signature block size (ed25519 signature + signer fingerprint).
pub const SIGNATURE_BLOCK_SIZE: usize = 96;

// ── Content type string→u8 mapping (matches config.rs CONTENT_TYPES) ────────
//
// Position in this table is the on-wire content_type byte; appending is
// always safe, reordering is not. Manifest authors reference these names
// in `[[ports]].content_type`.
//
// AV surface family:
//   - AudioSample  — decoded sample-domain audio
//   - AudioEncoded — codec-domain audio access units (Opus/MP3/AAC/G.711/...)
//   - VideoEncoded — codec-domain video access units (H.264/H.265/AV1/...)
//   - VideoDraw    — retained/replayable draw lists (UI, browser, dashboards)
//   - VideoRaster  — pixel-domain frames
//   - VideoScanout — present-ready output to a paced display sink
//   - MediaMuxed   — deliberate combined AV/timing/container streams
//
// AudioOpus / AudioMp3 / AudioAac / ImageJpeg / ImagePng are codec-tagged
// variants kept distinct from the generic AudioEncoded / VideoEncoded
// surfaces so `content_type` can carry codec identity without sideband.

const CONTENT_TYPES: &[&str] = &[
    "OctetStream",
    "Cbor",
    "Json",
    "AudioSample",
    "AudioOpus",
    "AudioMp3",
    "AudioAac",
    "TextPlain",
    "TextHtml",
    "VideoRaster",
    "ImageJpeg",
    "ImagePng",
    "MeshEvent",
    "MeshCommand",
    "MeshState",
    "MeshHandle",
    "InputEvent",
    "GestureMatch",
    "FmpMessage",
    "EthernetFrame",
    "HciMessage",
    "AudioEncoded",
    "VideoEncoded",
    "VideoDraw",
    "VideoScanout",
    "MediaMuxed",
];

fn content_type_from_str(s: &str) -> Result<u8> {
    CONTENT_TYPES
        .iter()
        .position(|&t| t.eq_ignore_ascii_case(s))
        .map(|i| i as u8)
        .ok_or_else(|| Error::Module(format!("unknown content type: {}", s)))
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
fn contract_id_from_name(s: &str) -> Result<u8> {
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
        // Anything that looks like a permission name is a manifest
        // schema error — those go in `permissions = [...]`, not
        // `[[resources]]`.
        "internal" | "system" | "reconfigure" | "flash_raw" | "backing_provider"
        | "platform_raw" | "monitor" | "bridge" => Err(Error::Module(format!(
            "`{}` is a permission, not a contract. Declare it in the \
                 top-level `permissions = [\"{}\", ...]` list, not under \
                 `[[resources]]`. See docs/architecture/abi_layers.md.",
            s, s
        ))),
        _ => Err(Error::Module(format!(
            "unknown contract name: {} — expected one of: gpio, spi, i2c, pio, \
             uart, adc, pwm, fs, platform_nic_ring, platform_dma, platform_dma_fd, \
             pcie_device (see docs/architecture/abi_layers.md)",
            s
        ))),
    }
}

fn contract_name_to_str(class: u8) -> &'static str {
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
        _ => "unknown",
    }
}

/// Whitelist of AV / presentation capability names accepted in a
/// manifest's top-level `capabilities = [...]` list. Two tiers:
/// hardware-facing (the role the module plays — paced scanout, group
/// clock, protected output) and service-level (the surface a producer
/// or consumer carries). Unknown names are rejected at parse time so
/// `display.scaneout` and friends fail the build rather than silently
/// dropping out.
///
/// Documented in `docs/architecture/av_capability_surface.md`.
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
                return Err(Error::Module(format!(
                    "unknown capability `{}`. Expected one of: {}.",
                    c,
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
        _ => Err(Error::Module(format!("unknown access mode: {}", s))),
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
        _ => Err(Error::Module(format!("unknown port direction: {}", s))),
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
        return Err(Error::Module(format!("invalid semver: {}", s)));
    }
    let major: u8 = parts[0]
        .parse()
        .map_err(|_| Error::Module(format!("invalid semver major: {}", s)))?;
    let minor: u8 = parts[1]
        .parse()
        .map_err(|_| Error::Module(format!("invalid semver minor: {}", s)))?;
    let patch: u8 = parts[2]
        .parse()
        .map_err(|_| Error::Module(format!("invalid semver patch: {}", s)))?;
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
            params: Vec::new(),
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
            .map_err(|e| Error::Module(format!("invalid manifest TOML: {}", e)))?;

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
                        "port name '{}' is a reserved word",
                        name
                    )));
                }
                if !port_names.insert(name.clone()) {
                    return Err(Error::Module(format!("duplicate port name '{}'", name)));
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
                        "unknown permission: {} — expected one of: reconfigure, \
                         flash_raw, backing_provider, platform_raw, monitor, bridge \
                         (see docs/architecture/abi_layers.md)",
                        name,
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

        // Header (16 bytes). Emit v2 only when a signature block is
        // actually present; unsigned manifests stay at v1.
        let version = if has_signature { MANIFEST_VERSION } else { 1 };
        buf.extend_from_slice(&MANIFEST_MAGIC.to_le_bytes());
        buf.push(version);
        buf.push(self.ports.len() as u8);
        buf.push(self.resources.len() as u8);
        buf.push(self.dependencies.len() as u8);
        buf.extend_from_slice(&self.module_version.to_le_bytes());
        buf.extend_from_slice(&self.hardware_targets.to_le_bytes());
        buf.extend_from_slice(&self.state_size_hint.to_le_bytes());
        // byte 14: bit 0 = has_integrity, bit 1 = has_signature.
        let flags = (if has_integrity { 1 } else { 0 }) | (if has_signature { 2 } else { 0 });
        buf.push(flags);
        // byte 15: fine-grained permissions bitmap (see `permission::*`).
        // The kernel reads this byte directly at module instantiation.
        buf.push(self.permissions.bits);

        // Ports (4 bytes each)
        for p in &self.ports {
            buf.push(p.direction);
            buf.push(p.content_type);
            buf.push(p.flags);
            buf.push(0); // reserved
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
                "invalid manifest magic: 0x{:08x}",
                magic
            )));
        }

        let version = data[4];
        if version != 1 && version != 2 {
            return Err(Error::Module(format!(
                "unsupported manifest version: {}",
                version
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
        let has_signature = version >= 2 && (flags & 0x02) != 0;
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
        let mut next_index = [0u8; 4];
        for _ in 0..port_count {
            let direction = data[offset];
            let dir_idx = (direction as usize).min(3);
            let index = next_index[dir_idx];
            next_index[dir_idx] = index + 1;
            ports.push(PortSpec {
                direction,
                content_type: data[offset + 1],
                flags: data[offset + 2],
                name: None,
                index,
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
            provides: Vec::new(), // not serialized in binary format
            capabilities: Vec::new(), // not serialized in binary format
            builtin: false,
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
                Ok(m) => format!("  required_caps: 0x{:08x}", m),
                Err(e) => format!("  required_caps: <error: {}>", e),
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
            let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
            lines.push(format!("  integrity: sha256:{}", hex));
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
    /// `[[params]]` declarations — built-in modules only. PIC modules
    /// embed schema in their .fmod and these are ignored.
    params: Option<Vec<TomlParam>>,
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
        // Use a unique scratch path per call so parallel tests don't
        // race on the same file.
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "fluxor-manifest-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("manifest.toml");
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
        let msg = format!("{}", err);
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
        let msg = format!("{}", err);
        assert!(msg.contains("mutually exclusive"), "unexpected: {msg}");
    }
}
