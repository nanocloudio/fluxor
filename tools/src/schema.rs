//! Parameter schema reader and generic TLV packer.
//!
//! Reads schema from .fmod files and packs YAML config into TLV format.
//! No module-specific knowledge — everything is driven by the schema.

use std::collections::HashMap;
use std::path::Path;

use serde_json::Value;

use crate::modules::ModuleInfo;

/// Schema magic bytes: "SP"
const SCHEMA_MAGIC: [u8; 2] = [0x53, 0x50];

/// TLV header: magic + version
const TLV_MAGIC: u8 = 0xFE;
const TLV_VERSION: u8 = 0x01;
const TLV_END: u8 = 0xFF;

/// Parameter types (must match module-side param_macro.rs)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ParamType {
    U8 = 0,
    U16 = 1,
    U32 = 2,
    Str = 3,
    U16Array = 4,
    Blob = 5,
}

impl ParamType {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::U8),
            1 => Some(Self::U16),
            2 => Some(Self::U32),
            3 => Some(Self::Str),
            4 => Some(Self::U16Array),
            5 => Some(Self::Blob),
            _ => None,
        }
    }

    #[allow(dead_code)]
    fn wire_size(&self) -> Option<usize> {
        match self {
            Self::U8 => Some(1),
            Self::U16 => Some(2),
            Self::U32 => Some(4),
            _ => None, // variable length
        }
    }
}

/// A single parameter definition from the schema.
#[derive(Debug, Clone)]
pub struct SchemaParam {
    pub tag: u8,
    pub ptype: ParamType,
    pub name: String,
    pub default: u32,
    /// Enum mappings: name → value (e.g., "sine" → 5)
    pub enums: HashMap<String, u8>,
}

/// Parsed parameter schema for a module.
#[derive(Debug, Clone)]
pub struct ParamSchema {
    pub params: Vec<SchemaParam>,
    /// Lookup by param name (including dotted names for nested YAML)
    name_map: HashMap<String, usize>,
}

impl ParamSchema {
    /// Parse schema from raw bytes (as embedded in .fmod).
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        if data[0] != SCHEMA_MAGIC[0] || data[1] != SCHEMA_MAGIC[1] {
            return None;
        }
        let _version = data[2];
        let count = data[3] as usize;

        let mut params = Vec::with_capacity(count);
        let mut pos = 4usize;

        for _ in 0..count {
            if pos + 6 > data.len() {
                break;
            }

            let tag = data[pos];
            pos += 1;
            let ptype = ParamType::from_u8(data[pos])?;
            pos += 1;

            // Default (4 bytes LE)
            if pos + 4 > data.len() {
                break;
            }
            let default =
                u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            pos += 4;

            // Name
            if pos >= data.len() {
                break;
            }
            let name_len = data[pos] as usize;
            pos += 1;
            if pos + name_len > data.len() {
                break;
            }
            let name = String::from_utf8_lossy(&data[pos..pos + name_len]).to_string();
            pos += name_len;

            // Enums
            if pos >= data.len() {
                break;
            }
            let enum_count = data[pos] as usize;
            pos += 1;
            let mut enums = HashMap::new();
            for _ in 0..enum_count {
                if pos >= data.len() {
                    break;
                }
                let val = data[pos];
                pos += 1;
                if pos >= data.len() {
                    break;
                }
                let ename_len = data[pos] as usize;
                pos += 1;
                if pos + ename_len > data.len() {
                    break;
                }
                let ename = String::from_utf8_lossy(&data[pos..pos + ename_len]).to_string();
                pos += ename_len;
                enums.insert(ename, val);
            }

            params.push(SchemaParam {
                tag,
                ptype,
                name,
                default,
                enums,
            });
        }

        let mut name_map = HashMap::new();
        for (i, p) in params.iter().enumerate() {
            name_map.insert(p.name.clone(), i);
        }

        Some(ParamSchema { params, name_map })
    }

    /// Parse schema from an .fmod file's ModuleInfo.
    pub fn from_module_info(info: &ModuleInfo) -> Option<Self> {
        info.schema.as_ref().and_then(|data| Self::from_bytes(data))
    }

    /// Build a schema from a built-in module's `manifest.toml` `[[params]]`
    /// section. This lets the same TLV packer used for `.fmod` modules
    /// produce per-instance params for kernel built-ins (which have no
    /// `.fmod` to embed schema bytes into).
    pub fn from_manifest(m: &crate::manifest::Manifest) -> Option<Self> {
        if m.params.is_empty() {
            return None;
        }
        let mut params = Vec::with_capacity(m.params.len());
        for mp in &m.params {
            let ptype = match mp.ptype {
                crate::manifest::ManifestParamType::U8 => ParamType::U8,
                crate::manifest::ManifestParamType::U16 => ParamType::U16,
                crate::manifest::ManifestParamType::U32 => ParamType::U32,
                crate::manifest::ManifestParamType::Str => ParamType::Str,
                // Enum maps to U8 on the wire — the manifest's value table
                // resolves YAML strings to indexed bytes before pack time.
                crate::manifest::ManifestParamType::Enum => ParamType::U8,
            };
            let mut enums = HashMap::new();
            for (name, val) in &mp.enum_values {
                enums.insert(name.clone(), *val);
            }
            params.push(SchemaParam {
                tag: mp.tag,
                ptype,
                name: mp.name.clone(),
                default: mp.default_num,
                enums,
            });
        }
        let mut name_map = HashMap::new();
        for (i, p) in params.iter().enumerate() {
            name_map.insert(p.name.clone(), i);
        }
        Some(ParamSchema { params, name_map })
    }

    /// Look up a param by name.
    /// Supports dotted YAML names matching underscored schema names:
    /// e.g., "eq.low_freq" matches schema param "eq_low_freq".
    pub fn find(&self, name: &str) -> Option<&SchemaParam> {
        if let Some(&i) = self.name_map.get(name) {
            return Some(&self.params[i]);
        }
        // Try replacing dots with underscores (YAML nested → schema flat)
        if name.contains('.') {
            let underscored = name.replace('.', "_");
            if let Some(&i) = self.name_map.get(&underscored) {
                return Some(&self.params[i]);
            }
        }
        None
    }
}

/// YAML keys that are structural metadata, not module params.
/// Module-specific keys (pin, data_pin, etc.) are NOT listed here —
/// the schema itself determines which YAML keys are valid params.
/// Unknown keys are silently skipped by pack_param().
pub(crate) const SKIP_KEYS: &[&str] = &[
    "name",
    "type",
    "wiring",
    "preset",
    "presets",
    "voices",
    "routes",
    "step_deadline_us",
    "fault_policy",
    "max_restarts",
    "restart_backoff_ms",
];

/// Grouping suffixes that YAML nesting may introduce in outer keys
/// but that don't appear in schema param names. When the outer key
/// ends with one of these, a stripped form is also inserted into the
/// key/value map so that e.g. `filter_envelope.attack_ms` matches
/// schema param `filter_attack_ms`.
pub(crate) const GROUPING_SUFFIXES: &[&str] = &["_envelope", "_config", "_settings", "_params"];

/// Pack YAML module config into TLV format using schema.
///
/// Returns the number of bytes written to `entry` starting at `base_offset`.
/// Returns Err if a preset reference cannot be resolved.
pub fn build_params_from_schema(
    module: &Value,
    schema: &ParamSchema,
    entry: &mut [u8],
    base_offset: usize,
    data_section: Option<&Value>,
    module_name: &str,
) -> Result<usize, String> {
    let mut kv: HashMap<String, Value> = HashMap::new();
    let mut presets: Option<Vec<Value>> = None;
    let mut voices: Option<Vec<Value>> = None;

    // Expand `routes:` array into flat route_N_* keys before general flattening.
    if let Some(obj) = module.as_object() {
        if let Some(routes_val) = obj.get("routes") {
            if let Some(routes_arr) = routes_val.as_array() {
                expand_routes(routes_arr, &mut kv, data_section);
            }
        }
    }

    // Flatten YAML into a flat key/value map, preserving dotted and underscored forms.
    if let Some(obj) = module.as_object() {
        for (key, value) in obj {
            if key == "presets" {
                presets = value.as_array().map(|a| a.to_vec());
                continue;
            }
            if key == "preset" {
                // Singular form: treat as a single preset entry
                presets = Some(vec![value.clone()]);
                continue;
            }
            if key == "voices" {
                voices = value.as_array().map(|a| a.to_vec());
                continue;
            }

            if SKIP_KEYS.contains(&key.as_str()) {
                continue;
            }

            if value.is_object() {
                if let Some(inner_obj) = value.as_object() {
                    // `params: { ... }` is a transparent wrapper — its
                    // inner keys map directly to schema params with no
                    // prefix. Idiomatic YAML grouping, used by several
                    // examples to separate config from wiring metadata.
                    let transparent = key == "params";
                    for (inner_key, inner_value) in inner_obj {
                        if transparent {
                            kv.insert(inner_key.clone(), inner_value.clone());
                            if inner_key.contains('.') {
                                kv.insert(
                                    inner_key.replace('.', "_"),
                                    inner_value.clone(),
                                );
                            }
                            continue;
                        }
                        let dotted = format!("{}.{}", key, inner_key);
                        let underscored = dotted.replace('.', "_");
                        kv.insert(dotted, inner_value.clone());
                        kv.insert(underscored.clone(), inner_value.clone());
                        // Also insert suffix-stripped form so that e.g.
                        // filter_envelope.attack_ms → filter_attack_ms
                        for suffix in GROUPING_SUFFIXES {
                            if key.ends_with(suffix) {
                                let prefix = &key[..key.len() - suffix.len()];
                                let stripped = format!("{}_{}", prefix, inner_key);
                                kv.insert(stripped, inner_value.clone());
                            }
                        }
                    }
                }
                continue;
            }

            kv.insert(key.clone(), value.clone());
            if key.contains('.') {
                kv.insert(key.replace('.', "_"), value.clone());
            }
        }
    }

    let mut pos = base_offset;

    // TLV header
    entry[pos] = TLV_MAGIC;
    pos += 1;
    entry[pos] = TLV_VERSION;
    pos += 1;
    let len_pos = pos; // payload length placeholder
    pos += 2;

    let payload_start = pos;

    // Pack params in schema order to respect dependency constraints.
    for param in &schema.params {
        if param.ptype == ParamType::U16Array {
            if let Some(arr) = presets.as_ref() {
                for preset_ref in arr {
                    let values = resolve_preset_values(preset_ref, data_section)
                        .map_err(|e| format!("module '{}': {}", module_name, e))?;
                    if !values.is_empty() {
                        let val_len = values.len() * 2;
                        if pos + 2 + val_len < entry.len() {
                            entry[pos] = param.tag;
                            pos += 1;
                            entry[pos] = val_len as u8;
                            pos += 1;
                            for v in &values {
                                let bytes = v.to_le_bytes();
                                entry[pos] = bytes[0];
                                pos += 1;
                                entry[pos] = bytes[1];
                                pos += 1;
                            }
                        }
                    }
                }
            }
            continue;
        }

        if param.ptype == ParamType::Blob {
            if let Some(arr) = presets.as_ref() {
                for preset_ref in arr.iter() {
                    let blob = resolve_preset_blob(preset_ref, data_section)
                        .map_err(|e| format!("module '{}': {}", module_name, e))?;
                    if blob.is_empty() {
                        continue;
                    }
                    // Self-delimiting blob: first chunk carries 2-byte LE total
                    // length header. Module uses this to know when one blob ends
                    // and the next begins, without needing a separate boundary tag.
                    let total_len = blob.len() as u16;
                    let header = total_len.to_le_bytes();
                    let mut off = 0;
                    let mut first = true;
                    while off < blob.len() {
                        let extra = if first { 2 } else { 0 };
                        let max_data = 255 - extra;
                        let chunk = std::cmp::min(max_data, blob.len() - off);
                        if pos + 2 + extra + chunk >= entry.len() {
                            break;
                        }
                        entry[pos] = param.tag;
                        pos += 1;
                        entry[pos] = (extra + chunk) as u8;
                        pos += 1;
                        if first {
                            entry[pos] = header[0];
                            pos += 1;
                            entry[pos] = header[1];
                            pos += 1;
                            first = false;
                        }
                        for i in 0..chunk {
                            entry[pos] = blob[off + i];
                            pos += 1;
                        }
                        off += chunk;
                    }
                }
            }
            continue;
        }

        if let Some(value) = kv.get(&param.name) {
            pos = pack_param(schema, &param.name, value, entry, pos, data_section);
        }
    }

    // Pack voice preset blobs (tag 0xFD, each containing a complete inner TLV blob)
    if let Some(voice_refs) = voices.as_ref() {
        for voice_ref in voice_refs {
            if let Some(voice_params) = resolve_voice_params(voice_ref, data_section, module_name) {
                let mut inner = [0u8; 256];
                let inner_len = pack_voice_inner(&voice_params, schema, &mut inner);
                if inner_len > 0 && pos + 2 + inner_len < entry.len() {
                    entry[pos] = 0xFD;
                    pos += 1;
                    entry[pos] = inner_len as u8;
                    pos += 1;
                    entry[pos..pos + inner_len].copy_from_slice(&inner[..inner_len]);
                    pos += inner_len;
                }
            }
        }
    }

    // End marker
    entry[pos] = TLV_END;
    pos += 1;
    entry[pos] = 0x00;
    pos += 1;

    // Patch payload length
    let payload_len = (pos - payload_start) as u16;
    entry[len_pos..len_pos + 2].copy_from_slice(&payload_len.to_le_bytes());

    Ok(pos - base_offset)
}

/// Pack a single param value into the TLV buffer.
fn pack_param(
    schema: &ParamSchema,
    key: &str,
    value: &Value,
    entry: &mut [u8],
    mut pos: usize,
    data_section: Option<&Value>,
) -> usize {
    let param = match schema.find(key) {
        Some(p) => p,
        None => return pos, // unknown key, skip silently
    };

    match param.ptype {
        ParamType::U8 => {
            let val = resolve_u8(value, param);
            if pos + 3 < entry.len() {
                entry[pos] = param.tag;
                pos += 1;
                entry[pos] = 1;
                pos += 1;
                entry[pos] = val;
                pos += 1;
            }
        }
        ParamType::U16 => {
            let val = resolve_u16(value, param);
            if pos + 4 < entry.len() {
                entry[pos] = param.tag;
                pos += 1;
                entry[pos] = 2;
                pos += 1;
                let bytes = val.to_le_bytes();
                entry[pos] = bytes[0];
                pos += 1;
                entry[pos] = bytes[1];
                pos += 1;
            }
        }
        ParamType::U32 => {
            let val = resolve_u32(value, param);
            if pos + 6 < entry.len() {
                entry[pos] = param.tag;
                pos += 1;
                entry[pos] = 4;
                pos += 1;
                let bytes = val.to_le_bytes();
                entry[pos] = bytes[0];
                pos += 1;
                entry[pos] = bytes[1];
                pos += 1;
                entry[pos] = bytes[2];
                pos += 1;
                entry[pos] = bytes[3];
                pos += 1;
            }
        }
        ParamType::Str => {
            if let Some(s) = value.as_str() {
                let resolved = resolve_str_content(s, data_section);
                let bytes = resolved.as_bytes();
                // Split into chunks of up to 255 bytes (same tag for each).
                // Modules that expect large content (e.g. http body)
                // append in their dispatch handler.
                let mut offset = 0;
                loop {
                    let remaining = bytes.len() - offset;
                    if remaining == 0 {
                        break;
                    }
                    let chunk_len = remaining.min(255);
                    if pos + 2 + chunk_len >= entry.len() {
                        break;
                    }
                    entry[pos] = param.tag;
                    pos += 1;
                    entry[pos] = chunk_len as u8;
                    pos += 1;
                    entry[pos..pos + chunk_len].copy_from_slice(&bytes[offset..offset + chunk_len]);
                    pos += chunk_len;
                    offset += chunk_len;
                }
            } else if let Some(arr) = value.as_array() {
                // String array: emit one TLV entry per list item (same tag)
                for item in arr {
                    if let Some(s) = item.as_str() {
                        let bytes = s.as_bytes();
                        let len = bytes.len().min(255);
                        if pos + 2 + len < entry.len() {
                            entry[pos] = param.tag;
                            pos += 1;
                            entry[pos] = len as u8;
                            pos += 1;
                            entry[pos..pos + len].copy_from_slice(&bytes[..len]);
                            pos += len;
                        }
                    }
                }
            }
        }
        ParamType::U16Array | ParamType::Blob => {
            // Handled separately via presets logic above
        }
    }

    pos
}

/// Resolve a value to u8, checking enum mappings first.
fn resolve_u8(value: &Value, param: &SchemaParam) -> u8 {
    // Check enum mapping (string → numeric)
    if let Some(s) = value.as_str() {
        if let Some(&v) = param.enums.get(s) {
            return v;
        }
        // Also try lowercase
        let lower = s.to_lowercase();
        if let Some(&v) = param.enums.get(&lower) {
            return v;
        }
        // Try parsing as number
        if let Ok(n) = s.parse::<u8>() {
            return n;
        }
        // Boolean strings
        return match s {
            "true" | "on" | "yes" => 1,
            "false" | "off" | "no" => 0,
            _ => param.default as u8,
        };
    }
    if let Some(n) = value.as_u64() {
        return n as u8;
    }
    if let Some(b) = value.as_bool() {
        return if b { 1 } else { 0 };
    }
    param.default as u8
}

/// Resolve a value to u16.
fn resolve_u16(value: &Value, param: &SchemaParam) -> u16 {
    if let Some(s) = value.as_str() {
        if let Some(&v) = param.enums.get(s) {
            return v as u16;
        }
        if let Ok(n) = s.parse::<u16>() {
            return n;
        }
        return param.default as u16;
    }
    if let Some(n) = value.as_u64() {
        return n as u16;
    }
    param.default as u16
}

/// Resolve a value to u32.
/// Unresolvable strings are hashed via FNV-1a, enabling FMP message type
/// names to be written as readable strings in YAML (e.g., `click: toggle`).
fn resolve_u32(value: &Value, param: &SchemaParam) -> u32 {
    if let Some(s) = value.as_str() {
        if let Some(&v) = param.enums.get(s) {
            return v as u32;
        }
        if let Ok(n) = s.parse::<u32>() {
            return n;
        }
        // Try dotted-decimal IPv4 (e.g. "192.168.1.1" → network byte order u32)
        if s.contains('.') {
            if let Some(ip) = parse_ipv4(s) {
                return ip;
            }
        }
        // Hash as FNV-1a — enables FMP message type names in config YAML
        return crate::hash::fnv1a_hash(s.as_bytes());
    }
    if let Some(n) = value.as_u64() {
        return n as u32;
    }
    param.default
}

/// Parse dotted-decimal IPv4 to u32 in network byte order.
fn parse_ipv4(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let a = parts[0].parse::<u8>().ok()?;
    let b = parts[1].parse::<u8>().ok()?;
    let c = parts[2].parse::<u8>().ok()?;
    let d = parts[3].parse::<u8>().ok()?;
    Some(u32::from_be_bytes([a, b, c, d]))
}

/// Resolve a str param value through the data section.
///
/// If `value` matches a key in `data_section` that has a `content` field,
/// returns the content string. Otherwise returns the original value.
fn resolve_str_content<'a>(value: &'a str, data_section: Option<&'a Value>) -> &'a str {
    if let Some(data) = data_section {
        if let Some(entry) = data.get(value) {
            if let Some(content) = entry.get("content") {
                if let Some(s) = content.as_str() {
                    return s;
                }
            }
        }
    }
    value
}

/// Built-in preset names resolved at compile time.
/// These are first-class features, not fallbacks — unknown names produce errors.
fn builtin_preset(name: &str) -> Option<Vec<u16>> {
    match name {
        "c_major" | "major" => Some(vec![262, 294, 330, 349, 392, 440, 494, 523]),
        "c_minor" | "minor" => Some(vec![262, 294, 311, 349, 392, 415, 466, 523]),
        "pentatonic" => Some(vec![262, 294, 330, 392, 440]),
        "blues" => Some(vec![262, 311, 349, 370, 392, 466]),
        "chromatic" => Some(vec![
            262, 277, 294, 311, 330, 349, 370, 392, 415, 440, 466, 494,
        ]),
        "bass" => Some(vec![65, 73, 82, 98, 110]),
        _ => None,
    }
}

/// Resolve preset values from a data section reference, built-in name, or inline array.
///
/// Returns Ok(values) on success, Err(message) if a string name cannot be resolved.
fn resolve_preset_values(
    preset_ref: &Value,
    data_section: Option<&Value>,
) -> Result<Vec<u16>, String> {
    // Direct array of numbers
    if let Some(arr) = preset_ref.as_array() {
        return Ok(arr
            .iter()
            .filter_map(|v| v.as_u64().map(|n| n as u16))
            .collect());
    }

    // String reference: try data section first, then built-in names
    if let Some(name) = preset_ref.as_str() {
        if let Some(data) = data_section {
            if let Some(entry) = data.get(name) {
                if let Some(values) = entry.get("values") {
                    if let Some(arr) = values.as_array() {
                        return Ok(arr
                            .iter()
                            .filter_map(|v| v.as_u64().map(|n| n as u16))
                            .collect());
                    }
                }
            }
        }

        if let Some(values) = builtin_preset(name) {
            return Ok(values);
        }

        return Err(format!(
            "preset '{}' not found (not in data section or built-in presets: \
             c_major, c_minor, pentatonic, blues, chromatic, bass)",
            name
        ));
    }

    Err("preset must be a string name or array of numbers".into())
}

/// Resolve a preset reference as raw binary bytes.
///
/// Supports:
/// - Inline array of byte values: `[0x42, 0x4D, ...]`
/// - String reference to data section entry with `hex:` field (hex string)
/// - String reference to data section entry with `bytes:` field (byte array)
fn resolve_preset_blob(
    preset_ref: &Value,
    data_section: Option<&Value>,
) -> Result<Vec<u8>, String> {
    // Direct array of numbers (interpreted as bytes)
    if let Some(arr) = preset_ref.as_array() {
        return Ok(arr
            .iter()
            .filter_map(|v| v.as_u64().map(|n| n as u8))
            .collect());
    }

    // String reference: look up in data section
    if let Some(name) = preset_ref.as_str() {
        if let Some(data) = data_section {
            if let Some(entry) = data.get(name) {
                // Try hex string first
                if let Some(hex_str) = entry.get("hex").and_then(|v| v.as_str()) {
                    return decode_hex(hex_str).map_err(|e| format!("blob '{}': {}", name, e));
                }
                // Try bytes array
                if let Some(bytes_arr) = entry.get("bytes").and_then(|v| v.as_array()) {
                    return Ok(bytes_arr
                        .iter()
                        .filter_map(|v| v.as_u64().map(|n| n as u8))
                        .collect());
                }
                return Err(format!(
                    "blob '{}' in data section has no 'hex' or 'bytes' field",
                    name
                ));
            }
        }
        return Err(format!("blob '{}' not found in data section", name));
    }

    Err("blob preset must be a string name or array of byte values".into())
}

/// Decode a hex string (with optional spaces) into bytes.
fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let hex: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if hex.len() % 2 != 0 {
        return Err("hex string must have even number of characters".into());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut i = 0;
    while i < hex.len() {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|_| format!("invalid hex at position {}", i))?;
        bytes.push(byte);
        i += 2;
    }
    Ok(bytes)
}

/// Resolve voice params from a data section reference.
///
/// Looks up `voice_ref` (a string name) in `data_section`, then extracts
/// the sub-object for `module_name` (e.g., "synth" or "effects").
/// Falls back to the voice object itself if no module-specific sub-object.
fn resolve_voice_params(
    voice_ref: &Value,
    data_section: Option<&Value>,
    module_name: &str,
) -> Option<Value> {
    let name = voice_ref.as_str()?;
    let data = data_section?;
    let voice_entry = data.get(name)?;

    // Extract module-specific sub-object (e.g., data.acid_bass.synth)
    if let Some(module_params) = voice_entry.get(module_name) {
        if module_params.is_object() {
            return Some(module_params.clone());
        }
    }

    // Fallback: use the voice object itself (flat format, minus "type" key)
    if voice_entry.is_object() {
        return Some(voice_entry.clone());
    }

    None
}

/// Pack voice params into a complete inner TLV blob.
///
/// Produces `[0xFE, 0x02, len_lo, len_hi, ...tag-len-value entries..., 0xFF, 0x00]`.
/// This is stored inside the outer `0xFD` tag. When the module switches voices,
/// it copies this blob into `params` and calls `apply_params`.
fn pack_voice_inner(voice_params: &Value, schema: &ParamSchema, buf: &mut [u8; 256]) -> usize {
    let mut kv: HashMap<String, Value> = HashMap::new();

    // Flatten voice params into kv map (same logic as build_params_from_schema)
    if let Some(obj) = voice_params.as_object() {
        for (key, value) in obj {
            if SKIP_KEYS.contains(&key.as_str()) {
                continue;
            }

            if value.is_object() {
                if let Some(inner_obj) = value.as_object() {
                    for (inner_key, inner_value) in inner_obj {
                        let dotted = format!("{}.{}", key, inner_key);
                        let underscored = dotted.replace('.', "_");
                        kv.insert(dotted, inner_value.clone());
                        kv.insert(underscored.clone(), inner_value.clone());
                        for suffix in GROUPING_SUFFIXES {
                            if key.ends_with(suffix) {
                                let prefix = &key[..key.len() - suffix.len()];
                                let stripped = format!("{}_{}", prefix, inner_key);
                                kv.insert(stripped, inner_value.clone());
                            }
                        }
                    }
                }
                continue;
            }

            kv.insert(key.clone(), value.clone());
            if key.contains('.') {
                kv.insert(key.replace('.', "_"), value.clone());
            }
        }
    }

    // TLV header
    let mut pos = 0usize;
    buf[pos] = TLV_MAGIC;
    pos += 1;
    buf[pos] = TLV_VERSION;
    pos += 1;
    let len_pos = pos;
    pos += 2; // payload length placeholder

    let payload_start = pos;

    // Pack matching params in schema order
    for param in &schema.params {
        if param.ptype == ParamType::U16Array || param.ptype == ParamType::Blob {
            continue; // voices don't contain presets or blobs
        }
        if let Some(value) = kv.get(&param.name) {
            pos = pack_param(schema, &param.name, value, buf, pos, None);
        }
    }

    // End marker
    buf[pos] = TLV_END;
    pos += 1;
    buf[pos] = 0x00;
    pos += 1;

    // Patch payload length
    let payload_len = (pos - payload_start) as u16;
    buf[len_pos..len_pos + 2].copy_from_slice(&payload_len.to_le_bytes());

    pos
}

/// Load schema for a module type from the .fmod files directory.
pub fn load_schema_for_module(module_type: &str, modules_dir: &Path) -> Option<ParamSchema> {
    let fmod_path = modules_dir.join(format!("{}.fmod", module_type));
    if !fmod_path.exists() {
        return None;
    }
    let info = ModuleInfo::from_file(&fmod_path).ok()?;
    ParamSchema::from_module_info(&info)
}

/// Expand a `routes:` YAML array into flat `route_N_*` keys in the kv map.
///
/// Each route object may contain:
///   - `path`: URL prefix (string)
///   - `body`: inline body or data section reference (string)
///   - `source`: "files" for fat32 file serving
///   - `proxy`: "ip:port" for forward proxy
///
/// Handler type is auto-detected:
///   - `body` with `{{ }}` → template (1)
///   - `body` without → static (0)
///   - `source: files` → file (2)
///   - `proxy:` → proxy (3)
fn expand_routes(routes: &[Value], kv: &mut HashMap<String, Value>, data_section: Option<&Value>) {
    for (i, route) in routes.iter().enumerate() {
        if i >= 4 {
            break;
        } // MAX_ROUTES = 4
        let _base = i * 10 + 10; // tags: 10, 20, 30, 40
        let obj = match route.as_object() {
            Some(o) => o,
            None => continue,
        };

        // Path
        if let Some(path) = obj.get("path") {
            kv.insert(format!("route_{}_path", i), path.clone());
        }

        // Determine handler type and body
        let mut handler: u8 = 0;

        if let Some(proxy_val) = obj.get("proxy") {
            // Proxy handler
            handler = 3;
            if let Some(proxy_str) = proxy_val.as_str() {
                if let Some((ip_str, port_str)) = proxy_str.rsplit_once(':') {
                    kv.insert(
                        format!("route_{}_proxy_ip", i),
                        Value::String(ip_str.to_string()),
                    );
                    kv.insert(
                        format!("route_{}_proxy_port", i),
                        Value::String(port_str.to_string()),
                    );
                } else {
                    // No port — use IP as-is, default port
                    kv.insert(format!("route_{}_proxy_ip", i), proxy_val.clone());
                }
            }
        } else if obj.get("source").is_some() {
            // File handler
            handler = 2;
        } else if let Some(body_val) = obj.get("body") {
            // Static or template handler — resolve body through data section
            let body_str = if let Some(s) = body_val.as_str() {
                let resolved = resolve_str_content(s, data_section);
                resolved.to_string()
            } else {
                String::new()
            };

            // Auto-detect template if body contains {{ }}
            if body_str.contains("{{") {
                handler = 1; // template
            } else {
                handler = 0; // static
            }

            kv.insert(format!("route_{}_body", i), Value::String(body_str));
        }

        kv.insert(
            format!("route_{}_handler", i),
            Value::Number(serde_json::Number::from(handler)),
        );
    }
}
