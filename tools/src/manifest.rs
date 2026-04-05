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

/// Current manifest format version
pub const MANIFEST_VERSION: u8 = 1;

/// Manifest header size (fixed portion before variable sections)
pub const MANIFEST_HEADER_SIZE: usize = 16;

// ── Content type string→u8 mapping (matches config.rs CONTENT_TYPES) ────────

const CONTENT_TYPES: &[&str] = &[
    "OctetStream", "Cbor", "Json", "AudioPcm", "AudioOpus", "AudioMp3", "AudioAac",
    "TextPlain", "TextHtml", "ImageRaw", "ImageJpeg", "ImagePng",
    "MeshEvent", "MeshCommand", "MeshState", "MeshHandle", "InputEvent", "GestureMatch",
    "FmpMessage", "EthernetFrame", "HciMessage",
];

fn content_type_from_str(s: &str) -> Result<u8> {
    CONTENT_TYPES
        .iter()
        .position(|&t| t.eq_ignore_ascii_case(s))
        .map(|i| i as u8)
        .ok_or_else(|| Error::Module(format!("unknown content type: {}", s)))
}

// ── Device class string→u8 mapping (matches dev_class constants) ────────────

fn device_class_from_str(s: &str) -> Result<u8> {
    match s.to_ascii_lowercase().as_str() {
        "gpio" => Ok(0x01),
        "spi" => Ok(0x02),
        "i2c" => Ok(0x03),
        "pio" => Ok(0x04),
        "channel" => Ok(0x05),
        "timer" => Ok(0x06),
        "netif" => Ok(0x07),
        "socket" => Ok(0x08),
        "fs" => Ok(0x09),
        "buffer" => Ok(0x0A),
        "event" => Ok(0x0B),
        "system" => Ok(0x0C),
        "uart" => Ok(0x0D),
        "adc" => Ok(0x0E),
        "pwm" => Ok(0x0F),
        _ => Err(Error::Module(format!("unknown device class: {}", s))),
    }
}

fn device_class_to_str(class: u8) -> &'static str {
    match class {
        0x01 => "gpio",
        0x02 => "spi",
        0x03 => "i2c",
        0x04 => "pio",
        0x05 => "channel",
        0x06 => "timer",
        0x07 => "netif",
        0x08 => "socket",
        0x09 => "fs",
        0x0A => "buffer",
        0x0B => "event",
        0x0C => "system",
        0x0D => "uart",
        0x0E => "adc",
        0x0F => "pwm",
        _ => "unknown",
    }
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
    let major: u8 = parts[0].parse().map_err(|_| Error::Module(format!("invalid semver major: {}", s)))?;
    let minor: u8 = parts[1].parse().map_err(|_| Error::Module(format!("invalid semver minor: {}", s)))?;
    let patch: u8 = parts[2].parse().map_err(|_| Error::Module(format!("invalid semver patch: {}", s)))?;
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

#[derive(Debug, Clone)]
pub struct Manifest {
    pub module_version: u16,
    pub hardware_targets: u16,
    pub state_size_hint: u16,
    pub ports: Vec<PortSpec>,
    pub resources: Vec<ResourceClaim>,
    pub dependencies: Vec<Dependency>,
    pub integrity_hash: Option<[u8; 32]>,
    /// FMP command vocabulary (parsed from TOML, not in binary format)
    pub commands: CommandVocabulary,
    /// Services this module provides to others (parsed from TOML, not in binary format).
    /// e.g. ip provides "socket", pwm provides "pwm"
    pub provides: Vec<String>,
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            module_version: encode_semver(0, 1, 0),
            hardware_targets: 0x01, // RP2350 by default
            state_size_hint: 0,
            ports: Vec::new(),
            resources: Vec::new(),
            dependencies: Vec::new(),
            integrity_hash: None,
            commands: CommandVocabulary::default(),
            provides: Vec::new(),
        }
    }
}

impl Manifest {
    /// Compute the required_caps bitmask from resource claims.
    /// Bit N = device class N is required.
    pub fn required_caps_mask(&self) -> u16 {
        let mut mask = 0u16;
        for r in &self.resources {
            if r.device_class < 16 {
                mask |= 1 << r.device_class;
            }
        }
        mask
    }

    /// Look up a port by name. Returns (direction, index, content_type).
    pub fn find_port_by_name(&self, name: &str) -> Option<(u8, u8, u8)> {
        self.ports.iter().find_map(|p| {
            p.name.as_deref().filter(|n| *n == name).map(|_| (p.direction, p.index, p.content_type))
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

    /// Parse manifest from a TOML file.
    pub fn from_toml(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| Error::Module(format!("cannot read {}: {}", path.display(), e)))?;
        let toml_val: TomlManifest = toml::from_str(&content)
            .map_err(|e| Error::Module(format!("invalid manifest TOML: {}", e)))?;

        let (major, minor, patch) = parse_semver(&toml_val.version)?;
        let module_version = encode_semver(major, minor, patch);

        let hardware_targets = toml_val.hardware_targets
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
                        "port name '{}' is a reserved word", name
                    )));
                }
                if !port_names.insert(name.clone()) {
                    return Err(Error::Module(format!(
                        "duplicate port name '{}'", name
                    )));
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

            ports.push(PortSpec { direction, content_type, flags, name: p.name, index });
        }

        let mut resources = Vec::new();
        for r in toml_val.resources.unwrap_or_default() {
            let device_class = device_class_from_str(&r.device_class)?;
            let access_mode = access_mode_from_str(&r.access)?;
            let instance = r.instance.unwrap_or(0xFF);
            resources.push(ResourceClaim { device_class, access_mode, instance });
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
            dependencies.push(Dependency { name_hash, min_version });
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

        Ok(Manifest {
            module_version,
            hardware_targets,
            state_size_hint,
            ports,
            resources,
            dependencies,
            integrity_hash: None, // set later by caller
            commands,
            provides,
        })
    }

    /// Serialize manifest to binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let has_integrity = self.integrity_hash.is_some();
        let var_size = self.ports.len() * 4
            + self.resources.len() * 4
            + self.dependencies.len() * 8
            + if has_integrity { 32 } else { 0 };
        let total = MANIFEST_HEADER_SIZE + var_size;
        let mut buf = Vec::with_capacity(total);

        // Header (16 bytes)
        buf.extend_from_slice(&MANIFEST_MAGIC.to_le_bytes());
        buf.push(MANIFEST_VERSION);
        buf.push(self.ports.len() as u8);
        buf.push(self.resources.len() as u8);
        buf.push(self.dependencies.len() as u8);
        buf.extend_from_slice(&self.module_version.to_le_bytes());
        buf.extend_from_slice(&self.hardware_targets.to_le_bytes());
        buf.extend_from_slice(&self.state_size_hint.to_le_bytes());
        buf.push(if has_integrity { 1 } else { 0 });
        buf.push(0); // reserved

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

        debug_assert_eq!(buf.len(), total);
        buf
    }

    /// Deserialize manifest from binary.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < MANIFEST_HEADER_SIZE {
            return Err(Error::Module(format!(
                "manifest too small: {} bytes", data.len()
            )));
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != MANIFEST_MAGIC {
            return Err(Error::Module(format!(
                "invalid manifest magic: 0x{:08x}", magic
            )));
        }

        let version = data[4];
        if version != MANIFEST_VERSION {
            return Err(Error::Module(format!(
                "unsupported manifest version: {}", version
            )));
        }

        let port_count = data[5] as usize;
        let resource_count = data[6] as usize;
        let dependency_count = data[7] as usize;
        let module_version = u16::from_le_bytes([data[8], data[9]]);
        let hardware_targets = u16::from_le_bytes([data[10], data[11]]);
        let state_size_hint = u16::from_le_bytes([data[12], data[13]]);
        let has_integrity = data[14] != 0;

        let expected_size = MANIFEST_HEADER_SIZE
            + port_count * 4
            + resource_count * 4
            + dependency_count * 8
            + if has_integrity { 32 } else { 0 };

        if data.len() < expected_size {
            return Err(Error::Module(format!(
                "manifest truncated: {} bytes, expected {}", data.len(), expected_size
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
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            ]);
            let min_version = u16::from_le_bytes([data[offset + 4], data[offset + 5]]);
            dependencies.push(Dependency { name_hash, min_version });
            offset += 8;
        }

        let integrity_hash = if has_integrity {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[offset..offset + 32]);
            Some(hash)
        } else {
            None
        };

        Ok(Manifest {
            module_version,
            hardware_targets,
            state_size_hint,
            ports,
            resources,
            dependencies,
            integrity_hash,
            commands: CommandVocabulary::default(),
            provides: Vec::new(), // not serialized in binary format
        })
    }

    /// Display manifest contents for info/debug output.
    pub fn display(&self) -> String {
        let (major, minor, patch) = decode_semver(self.module_version);
        let mut lines = vec![
            format!("  version: {}.{}.{}", major, minor, patch),
            format!("  hardware_targets: 0x{:04x}", self.hardware_targets),
            format!("  required_caps: 0x{:04x}", self.required_caps_mask()),
        ];
        if self.state_size_hint > 0 {
            lines.push(format!("  state_size_hint: {} bytes", self.state_size_hint));
        }
        if !self.ports.is_empty() {
            lines.push("  ports:".into());
            for p in &self.ports {
                let req = if p.flags & 0x01 != 0 { " (required)" } else { "" };
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
                        device_class_to_str(r.device_class),
                        r.instance,
                        access_mode_to_str(r.access_mode),
                    ));
                } else {
                    lines.push(format!(
                        "    {} ({})",
                        device_class_to_str(r.device_class),
                        access_mode_to_str(r.access_mode),
                    ));
                }
            }
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
                lines.push(format!("    accepts: [{}]", self.commands.accepts.join(", ")));
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
    dependencies: Option<Vec<TomlDependency>>,
    commands: Option<TomlCommands>,
    provides: Option<Vec<String>>,
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
        m.ports.push(PortSpec { direction: 0, content_type: 3, flags: 1, name: None, index: 0 });
        m.resources.push(ResourceClaim { device_class: 0x04, access_mode: 2, instance: 0xFF });
        m.dependencies.push(Dependency { name_hash: 0x12345678, min_version: encode_semver(1, 0, 0) });
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
        m.resources.push(ResourceClaim { device_class: 0x01, access_mode: 0, instance: 0xFF }); // GPIO
        m.resources.push(ResourceClaim { device_class: 0x04, access_mode: 2, instance: 0xFF }); // PIO
        assert_eq!(m.required_caps_mask(), (1 << 1) | (1 << 4));
    }
}
