//! Parameter schema reader and generic TLV packer.
//!
//! Reads schema from .fmod files and packs YAML config into TLV format.
//! No module-specific knowledge — everything is driven by the schema.

use std::collections::HashMap;
use std::path::Path;

use serde_json::Value;

use crate::modules::ModuleInfo;

/// Route `handler` ids, from the SDK that the serving module also compiles
/// against. Deriving the byte here and switching on it there are two halves
/// of one wire value; reading both from `fluxor_abi` is what makes them
/// checkable rather than merely intended to agree.
use fluxor_abi::config::route_handler as handler_id;

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
    /// A string param whose module ACCUMULATES the chunks it is sent.
    ///
    /// The packer splits a value longer than one TLV entry into several
    /// entries under the same tag. That only produces the whole value
    /// when the module's handler appends; a handler that assigns keeps
    /// the LAST chunk and silently drops the rest, which is why plain
    /// [`Str`] is refused past one entry rather than chunked. A module
    /// declaring this type is asserting that its handler appends.
    StrChunked = 6,
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
            6 => Some(Self::StrChunked),
            _ => None,
        }
    }

    #[allow(
        dead_code,
        reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
    )]
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
    // `[[variant]]` selection — resolution input, never a wire param.
    "variant",
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
/// The value `param` takes for this module entry: what the YAML sets —
/// under the name directly or inside a `params:` wrapper — or the schema
/// default when unset. `None` when the schema has no such parameter.
///
/// Numeric parameters resolve to their number; an enum resolves to its
/// wire value, so a caller comparing against an enum NAME maps the name
/// through the schema first. This is the same resolution `pack_param`
/// applies, exposed for a compose-time check that has to know a value
/// before anything is packed.
pub fn effective_param_value(module: &Value, schema: &ParamSchema, param: &str) -> Option<u32> {
    let def = schema.find(param)?;
    let set = module
        .get(param)
        .or_else(|| module.get("params").and_then(|p| p.get(param)));
    Some(match set {
        Some(v) => match def.ptype {
            ParamType::U8 => u32::from(resolve_u8(v, def)),
            ParamType::U16 => u32::from(resolve_u16(v, def)),
            _ => resolve_u32(v, def),
        },
        None => def.default,
    })
}

/// Whether `param` on this module entry is one of `wanted` — enum names or
/// numbers as a `[[requires_when]]` writes them. `None` when the schema has
/// no such parameter or a wanted value names neither an enum value nor a
/// number.
pub fn param_is_one_of(
    module: &Value,
    schema: &ParamSchema,
    param: &str,
    wanted: &[String],
) -> Option<bool> {
    let def = schema.find(param)?;
    let value = effective_param_value(module, schema, param)?;
    let mut hit = false;
    for w in wanted {
        let target = match def
            .enums
            .get(w)
            .or_else(|| def.enums.get(&w.to_lowercase()))
        {
            Some(&v) => u32::from(v),
            None => w.parse::<u32>().ok()?,
        };
        hit |= value == target;
    }
    Some(hit)
}

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
                expand_routes(routes_arr, &mut kv, data_section)?;
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
                                kv.insert(inner_key.replace('.', "_"), inner_value.clone());
                            }
                            continue;
                        }
                        let dotted = format!("{key}.{inner_key}");
                        let underscored = dotted.replace('.', "_");
                        kv.insert(dotted, inner_value.clone());
                        kv.insert(underscored.clone(), inner_value.clone());
                        // Also insert suffix-stripped form so that e.g.
                        // filter_envelope.attack_ms → filter_attack_ms
                        for suffix in GROUPING_SUFFIXES {
                            if key.ends_with(suffix) {
                                let prefix = &key[..key.len() - suffix.len()];
                                let stripped = format!("{prefix}_{inner_key}");
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
                        .map_err(|e| format!("module '{module_name}': {e}"))?;
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
                        .map_err(|e| format!("module '{module_name}': {e}"))?;
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
            check_param_value_len(param, &param.name, value, data_section, module_name)?;
            check_param_value_dotted(module_name, &param.name, value, param)?;
            check_param_value_enum(module_name, &param.name, value, param)?;
            pos = pack_param(schema, &param.name, value, entry, pos, data_section);
        }
    }

    // Pack voice preset blobs (tag 0xFD, each containing a complete inner TLV blob)
    if let Some(voice_refs) = voices.as_ref() {
        for voice_ref in voice_refs {
            if let Some(voice_params) = resolve_voice_params(voice_ref, data_section, module_name) {
                let mut inner = [0u8; 256];
                let inner_len = pack_voice_inner(&voice_params, schema, &mut inner, module_name)?;
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
/// Maximum bytes a single TLV entry's value can carry — the entry's
/// length is one byte (`[tag][len][value]`), so this is what fits.
pub const MAX_TLV_VALUE_LEN: usize = u8::MAX as usize;

/// Refuse a parameter value the module cannot receive intact.
///
/// A TLV entry's length is a single byte, so a longer value can only
/// travel as several entries under one tag. That reassembles if and only
/// if the module's handler APPENDS each chunk; a handler that assigns
/// keeps the last one and drops the rest, leaving the module holding a
/// truncated value with nothing to indicate it.
///
/// Such a truncation surfaces far from its cause — a fragment of a
/// source file reaching a compiler, which refuses it, which empties a
/// closure, which makes an isolate answer nothing, several modules from
/// the graph line that was too long.
///
/// A plain `str` is therefore refused here, where the module and the
/// field can still be named. A module whose handler does accumulate
/// declares the param `str_chunked` and keeps the split.
fn check_param_value_len(
    param: &SchemaParam,
    key: &str,
    value: &Value,
    data_section: Option<&Value>,
    module_name: &str,
) -> Result<(), String> {
    if param.ptype != ParamType::Str {
        return Ok(());
    }
    let Some(s) = value.as_str() else {
        return Ok(());
    };
    let len = resolve_str_content(s, data_section).len();
    if len <= MAX_TLV_VALUE_LEN {
        return Ok(());
    }
    Err(format!(
        "module '{module_name}': parameter '{key}' is {len} bytes, over the \
         {MAX_TLV_VALUE_LEN}-byte limit for a single parameter entry — the \
         module would receive only the tail of it. Shorten the value, move it \
         to a file the module opens at runtime, or (only if the module's \
         handler appends each chunk) declare the parameter `str_chunked`."
    ))
}

/// A `u32` parameter takes a number, a hex literal or an IPv4 literal. A
/// string with a dot that is not a dotted quad is a host name that landed
/// on an address parameter; `resolve_u32` would hash it and the module
/// would dial nonsense, so it is refused here, where the module and the
/// field can still be named. A dotless string is left to `resolve_u32`,
/// where an FMP message-type name is hashed by design.
/// A parameter that declares named values takes one of them, a number, or
/// a boolean word. Anything else is a name that means nothing here: the
/// resolver would fall back to the default (`u8`) or hash the string
/// (`u32`), and the module would run a policy the graph never asked for.
/// Refused where the module, the key and the valid names can all be said.
fn check_param_value_enum(
    module_name: &str,
    key: &str,
    value: &Value,
    param: &SchemaParam,
) -> Result<(), String> {
    if param.enums.is_empty() {
        return Ok(());
    }
    let Some(s) = value.as_str() else {
        return Ok(());
    };
    let lower = s.to_lowercase();
    if param.enums.contains_key(s)
        || param.enums.contains_key(&lower)
        || s.parse::<u64>().is_ok()
        || matches!(
            lower.as_str(),
            "true" | "on" | "yes" | "false" | "off" | "no"
        )
    {
        return Ok(());
    }
    let mut names: Vec<&str> = param.enums.keys().map(String::as_str).collect();
    names.sort_unstable();
    Err(format!(
        "module '{module_name}': parameter '{key}' is '{s}', which is not one of \
         its values: {}",
        names.join(", ")
    ))
}

fn check_param_value_dotted(
    module_name: &str,
    key: &str,
    value: &Value,
    param: &SchemaParam,
) -> Result<(), String> {
    if param.ptype != ParamType::U32 {
        return Ok(());
    }
    let Some(s) = value.as_str() else {
        return Ok(());
    };
    if !s.contains('.') || param.enums.contains_key(s) || parse_ipv4(s).is_some() {
        return Ok(());
    }
    Err(format!(
        "module '{module_name}': parameter '{key}' is '{s}', which contains a dot \
         but is not a dotted quad; a u32 parameter takes a number, a hex literal \
         or an IPv4 literal — a host name belongs in `authority`"
    ))
}

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
        ParamType::Str | ParamType::StrChunked => {
            if let Some(s) = value.as_str() {
                let resolved = resolve_str_content(s, data_section);
                let bytes = resolved.as_bytes();
                // A TLV entry carries its length in ONE byte. A longer
                // value is split across several entries under the same
                // tag, which reassembles only if the module's handler
                // appends — so only `str_chunked` is split. A plain
                // `str` is refused above, by `check_param_value_len`,
                // where the graph and field can still be named.
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
                // Two array shapes are supported here:
                //   - String array: one item per list entry, each
                //     emits its own TLV entry with the same tag.
                //     Used by params with multiple textual values.
                //   - Byte array: every item is a `Value::Number`
                //     in `0..=255`. Concatenate into a single byte
                //     buffer and emit as TLV-chunked binary, same as
                //     the UTF-8 string path above. Used for binary
                //     `body_file` payloads (`.wasm`, images, ...) so
                //     the bytes never round-trip through a Rust
                //     `String` (which would require valid UTF-8).
                let all_bytes = arr
                    .iter()
                    .all(|v| v.as_u64().map(|n| n <= 255).unwrap_or(false));
                if all_bytes && !arr.is_empty() {
                    let bytes: Vec<u8> = arr.iter().map(|v| v.as_u64().unwrap() as u8).collect();
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
                        entry[pos..pos + chunk_len]
                            .copy_from_slice(&bytes[offset..offset + chunk_len]);
                        pos += chunk_len;
                        offset += chunk_len;
                    }
                } else {
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
        // Hex literal ("0xC0A8010A"); a number, never a name to hash.
        if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            if let Ok(n) = u32::from_str_radix(h, 16) {
                return n;
            }
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
/// Decode a base64-encoded body payload. Returns None on any
/// invalid input; callers fall back to an empty body. Standard
/// alphabet, accepts and ignores padding, rejects whitespace.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn lookup(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in bytes {
        if c == b'=' {
            break;
        }
        let v = lookup(c)?;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

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
            "preset '{name}' not found (not in data section or built-in presets: \
             c_major, c_minor, pentatonic, blues, chromatic, bass)"
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
                    return decode_hex(hex_str).map_err(|e| format!("blob '{name}': {e}"));
                }
                // Try bytes array
                if let Some(bytes_arr) = entry.get("bytes").and_then(|v| v.as_array()) {
                    return Ok(bytes_arr
                        .iter()
                        .filter_map(|v| v.as_u64().map(|n| n as u8))
                        .collect());
                }
                return Err(format!(
                    "blob '{name}' in data section has no 'hex' or 'bytes' field"
                ));
            }
        }
        return Err(format!("blob '{name}' not found in data section"));
    }

    Err("blob preset must be a string name or array of byte values".into())
}

/// Decode a hex string (with optional spaces) into bytes.
fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let hex: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !hex.len().is_multiple_of(2) {
        return Err("hex string must have even number of characters".into());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut i = 0;
    while i < hex.len() {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|_| format!("invalid hex at position {i}"))?;
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
fn pack_voice_inner(
    voice_params: &Value,
    schema: &ParamSchema,
    buf: &mut [u8; 256],
    module_name: &str,
) -> Result<usize, String> {
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
                        let dotted = format!("{key}.{inner_key}");
                        let underscored = dotted.replace('.', "_");
                        kv.insert(dotted, inner_value.clone());
                        kv.insert(underscored.clone(), inner_value.clone());
                        for suffix in GROUPING_SUFFIXES {
                            if key.ends_with(suffix) {
                                let prefix = &key[..key.len() - suffix.len()];
                                let stripped = format!("{prefix}_{inner_key}");
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
            check_param_value_dotted(module_name, &param.name, value, param)?;
            check_param_value_enum(module_name, &param.name, value, param)?;
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

    Ok(pos)
}

/// Load the param schema for a module type from its `.fmod`.
///
/// The schema is generated at build time from the module's `define_params!`
/// and lives ONLY in the `.fmod` (not the manifest), so config generation must
/// read the actual artifact to encode a module's params. When the `.fmod` is
/// absent from `modules_dir` the module may be a store-pinned provider composed
/// in from a sibling project: resolve it from the OCI store exactly as the
/// module TABLE builder (`parse_modules_from_config_multi`) does, else the
/// provider's params (e.g. a connector `endpoint`) silently drop and the module
/// runs unconfigured. `modules_dir` is already resolved to the build's silicon
/// — the same answer `TargetDescriptor::module_silicon()` gives, which is also
/// the silicon tag on the `fluxor.lock` pins consulted below.
///
/// Three outcomes, deliberately distinguishable:
///   - `Ok(Some(schema))` — a schema was read.
///   - `Ok(None)` — this module legitimately has no `.fmod`-borne schema: a
///     built-in (schema lives in its `manifest.toml`), a module declaring no
///     params, or an unpinned module whose `.fmod` simply isn't built (the
///     module-table builder reports that one separately).
///   - `Err` — the module IS pinned in `fluxor.lock` but its pinned artifact
///     could not be resolved. Failing closed here mirrors
///     `config::assert_pinned_manifests_resolvable` on the manifest half of the
///     same pin: a pinned module that hard-fails port validation must not
///     silently build with its params dropped.
pub fn load_schema_for_module(
    module_type: &str,
    modules_dir: &Path,
) -> crate::Result<Option<ParamSchema>> {
    let fmod_path = modules_dir.join(format!("{module_type}.fmod"));
    let info = if fmod_path.exists() {
        match ModuleInfo::from_file(&fmod_path) {
            Ok(i) => i,
            Err(_) => return Ok(None),
        }
    } else {
        let Some(pinned) = resolve_pinned_fmod(module_type, modules_dir)? else {
            return Ok(None);
        };
        ModuleInfo::from_file(&pinned.path)
            .map_err(|e| pinned_schema_error(module_type, &format!("{}: {e}", pinned.pin_label)))?
    };
    Ok(ParamSchema::from_module_info(&info))
}

/// A pin that resolved to real bytes, carrying the label the error path
/// quotes when those bytes turn out to be unreadable.
struct PinnedFmod {
    path: std::path::PathBuf,
    pin_label: String,
}

/// `pin <reference> (<digest>)` for the `[[artifact]]` module entry
/// covering `module_type` on `silicon` — the same label the
/// manifest-side resolver quotes, so a broken artifact reports one
/// identity from both halves. Degrades to the silicon alone when the
/// lockfile can't be re-read.
fn pin_label(project_root: &Path, module_type: &str, silicon: &str) -> String {
    let pin = fluxor_tools::store_resolve::read_store_lock(project_root)
        .ok()
        .flatten()
        .and_then(|l| {
            l.artifacts.into_iter().find(|a| {
                a.kind == "module" && a.name == module_type && a.target.as_deref() == Some(silicon)
            })
        });
    match pin {
        Some(p) => format!("pin {} ({})", p.reference, p.digest),
        None => format!("pin target '{silicon}'"),
    }
}

/// Sibling wording of `assert_pinned_manifests_resolvable`'s error so the two
/// halves of a broken pin — manifest and params — read as one failure class.
fn pinned_schema_error(module_type: &str, why: &str) -> crate::Error {
    crate::Error::Config(format!(
        "module '{module_type}' is pinned in fluxor.lock but its param schema could not be \
         resolved from the OCI store: {why}"
    ))
}

/// Resolve a module's `.fmod` path from the project's `[[artifact]]` module pins when
/// it is absent on disk. The pin silicon is `modules_dir`'s own parent, which
/// holds in both artifact layouts (`target/fluxor/<silicon>/modules` and the
/// `--out target` form `target/<silicon>/modules`). The project root comes from
/// the marker walk rather than a fixed ancestor depth: those two layouts differ
/// by one level, so a fixed depth reads a foreign `fluxor.lock` under one of
/// them and the pin silently fails to resolve.
///
/// `Ok(None)` means no pin covers this name; `Err` means one does and it is
/// unresolvable (missing/corrupt blob, integrity failure, unreadable store or
/// lockfile), which is a hard error rather than a silent drop to "no params".
fn resolve_pinned_fmod(module_type: &str, modules_dir: &Path) -> crate::Result<Option<PinnedFmod>> {
    let silicon = match modules_dir.parent().and_then(|p| p.file_name()) {
        Some(s) => s.to_string_lossy().into_owned(),
        None => return Ok(None),
    };
    // Anchor a relative dir to the cwd so the walk has a real path to climb.
    let anchored = if modules_dir.is_absolute() {
        modules_dir.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(modules_dir),
            Err(_) => return Ok(None),
        }
    };
    let project_root = crate::project::discover_from(&anchored)
        .map(|r| r.path)
        .unwrap_or_else(crate::project::root);
    let Some(resolver) = crate::store_cli::lock_store_resolver(&project_root, &silicon, None)
    else {
        return Ok(None);
    };
    match resolver(module_type) {
        crate::modules::StorePin::Resolved(path) => Ok(Some(PinnedFmod {
            path,
            pin_label: pin_label(&project_root, module_type, &silicon),
        })),
        crate::modules::StorePin::NotPinned => Ok(None),
        crate::modules::StorePin::Failed(why) => Err(pinned_schema_error(
            module_type,
            &format!("{}: {why}", pin_label(&project_root, module_type, &silicon)),
        )),
    }
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
fn expand_routes(
    routes: &[Value],
    kv: &mut HashMap<String, Value>,
    data_section: Option<&Value>,
) -> Result<(), String> {
    // The http module's TLV table (`define_params!`, host profile
    // `http::MAX_ROUTES` in `modules/sdk/abi/config.rs`) carries 8 routes
    // (tags 10..89). A route past that has no TLV tag and would vanish
    // silently at runtime — so overflow is a compile error here, not
    // headroom. Raising the ceiling means extending the module-side TLV
    // table first; `tools/tests/http_route_tlv_coverage.rs` locks the pair.
    const TOOL_MAX_ROUTES: usize = 8;
    if routes.len() > TOOL_MAX_ROUTES {
        return Err(format!(
            "routes: {} declared, but the http module's TLV table carries {} — \
             routes {}.. would be silently dropped at runtime. Split the routes \
             across http module instances or extend the module-side table.",
            routes.len(),
            TOOL_MAX_ROUTES,
            TOOL_MAX_ROUTES
        ));
    }
    for (i, route) in routes.iter().enumerate() {
        let _base = i * 10 + 10; // tags: 10, 20, 30, 40
        let obj = match route.as_object() {
            Some(o) => o,
            None => continue,
        };

        // Path
        if let Some(path) = obj.get("path") {
            kv.insert(format!("route_{i}_path"), path.clone());
        }

        // Determine handler type and body.
        //
        // The handler id is DERIVED from the boolean route keys below and
        // never read from the yaml: a raw `handler: 11` compiles to
        // `STATIC` and serves an empty static body (pinned by
        // `a_raw_handler_number_is_ignored_not_honoured`). A graph naming a
        // number directly would make every renumbering a breaking config
        // change, and would let a config assert a handler the serving module
        // does not have.
        let mut handler: u8 = handler_id::STATIC;

        if obj
            .get("websocket_fanout")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            // WebSocket handler with external fan-out — accepts the
            // Upgrade then routes inbound frames to the http module's
            // ws_out port and reads outbound frames from ws_in.
            // `retain_replay: false` selects the session variant
            // (handler 9): same wiring, but a new connection never
            // receives retained envelopes from a previous session —
            // required for session protocols (e.g. the sector surface
            // auth gate), where replaying one connection's frames to
            // the next is a correctness/security failure.
            // `admit: true` hands the upgrade decision to the application:
            // the request is reported on `ws_admit_out` and the 101 is
            // composed only once `ws_admit_in` answers accept. It implies
            // session semantics — an admission-gated route is exactly the
            // place replaying a previous connection's frames to a fresh,
            // not-yet-admitted subscriber would be wrong — so it is checked
            // before `retain_replay` rather than combined with it.
            handler = if obj.get("admit").and_then(|v| v.as_bool()).unwrap_or(false) {
                handler_id::WS_FANOUT_ADMIT
            } else if obj
                .get("retain_replay")
                .and_then(|v| v.as_bool())
                .unwrap_or(true)
            {
                handler_id::WS_FANOUT_RETAIN
            } else {
                handler_id::WS_FANOUT
            };
        } else if obj
            .get("websocket")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            // WebSocket handler — accepts the Upgrade and echoes frames.
            handler = handler_id::WEBSOCKET;
        } else if obj.get("grpc").and_then(|v| v.as_bool()).unwrap_or(false) {
            // gRPC unary handler (HANDLER_GRPC) — answers with a canned
            // length-prefixed message and a `grpc-status: 0` trailer.
            //
            // The route path should be the gRPC SERVICE prefix
            // (`/pkg.Service/`), because a method path is `/<service>/<Method>`
            // and http matches a trailing `/` as a prefix.
            handler = handler_id::GRPC;
        } else if obj.get("app").and_then(|v| v.as_bool()).unwrap_or(false) {
            // Application fan-out (HANDLER_APP) — the request goes out on the
            // http module's `req_out` port as an `HttpRequest` envelope and the
            // answer comes back on `resp_in`, so a downstream graph node
            // decides what the request MEANS while http keeps owning HTTP.
            //
            // The route path is normally a prefix ending in `/`, since an API
            // mounted at `/v2/` must receive everything beneath it. A bare `/`
            // is also a prefix for this handler alone.
            handler = handler_id::APP;
        } else if let Some(proxy_val) = obj.get("proxy") {
            // Proxy handler
            handler = handler_id::PROXY;
            if let Some(proxy_str) = proxy_val.as_str() {
                if let Some((ip_str, port_str)) = proxy_str.rsplit_once(':') {
                    kv.insert(
                        format!("route_{i}_proxy_ip"),
                        Value::String(ip_str.to_string()),
                    );
                    kv.insert(
                        format!("route_{i}_proxy_port"),
                        Value::String(port_str.to_string()),
                    );
                } else {
                    // No port — use IP as-is, default port
                    kv.insert(format!("route_{i}_proxy_ip"), proxy_val.clone());
                }
            }
        } else if let Some(fs_path_val) = obj.get("fs_path") {
            // FS_CONTRACT-served file: `fs_path: "/web/INDEX.HTM"`.
            // The http module opens the file via `provider_call(-1,
            // FS_OPEN, ...)` against whichever module registered as
            // the FS provider (`fat32` on bare-metal, `linux_fs_dispatch`
            // on the host).
            handler = handler_id::FS_FILE;
            kv.insert(format!("route_{i}_fs_path"), fs_path_val.clone());
        } else if let Some(fs_list_val) = obj.get("fs_list") {
            // FS_CONTRACT-served directory listing as JSON. The http
            // module calls `FS_OPENDIR` + `FS_READDIR` against the
            // configured directory each request and emits
            // `{"items":["a","b",…]}`. Optional `fs_filter:` (case-
            // insensitive comma-separated extension list) narrows the
            // result. Used by the browser image_viewer / audio_player
            // launchers to enumerate the asset bank.
            handler = handler_id::FS_LIST;
            kv.insert(format!("route_{i}_fs_list"), fs_list_val.clone());
            if let Some(fs_filter_val) = obj.get("fs_filter") {
                kv.insert(format!("route_{i}_fs_filter"), fs_filter_val.clone());
            }
        } else if obj.get("source").is_some() {
            // The `source` value is informational (typically the
            // upstream port name); the actual wiring is declared in
            // the `wiring:` block.
            //
            //  - `source:` alone → HANDLER_FILE: URL-derived index
            //    (fat32-style `/file/<N>` picks the N-th file).
            //  - `source:` + `source_index:` → HANDLER_STATIC with
            //    `source_index >= 0`: a fixed-index fetch through
            //    `http.file_data` that caches as a static body. Used
            //    for indexed asset banks like `host_asset_index` where
            //    each route serves one specific asset.
            //  - `source:` + `source_index:` + `stream: true` →
            //    HANDLER_STREAM: same fixed-index fetch but the
            //    bytes pipe straight from `file_chan` into the
            //    socket without staging in `body_pool`. Use for
            //    multi-MiB payloads that exceed the body-pool cap
            //    (WASM bundles, large media).
            let stream = obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);
            if let Some(idx_val) = obj.get("source_index") {
                if let Some(idx) = idx_val.as_u64() {
                    handler = if stream {
                        handler_id::STREAM
                    } else {
                        handler_id::STATIC
                    };
                    kv.insert(
                        format!("route_{i}_source"),
                        Value::Number(serde_json::Number::from(idx)),
                    );
                }
            } else {
                handler = handler_id::FILE;
            }
        } else if let Some(body_val) = obj.get("body") {
            // Static or template handler — resolve body through data section.
            //
            // Bodies starting with the `base64:` sentinel are binary
            // payloads inlined from a `body_file` whose bytes weren't
            // valid UTF-8 (e.g. `.wasm`, images). Decode to bytes and
            // store as `Value::Array` of `Value::Number(u8)` so the
            // bytes flow through `pack_param`'s `Str` arm without
            // ever passing through a Rust `String` — `String::from_utf8_unchecked`
            // on arbitrary binary is undefined behaviour. UTF-8 text
            // bodies stay as `Value::String`.
            let body_value: Value = if let Some(s) = body_val.as_str() {
                let resolved = resolve_str_content(s, data_section);
                if let Some(payload) = resolved.strip_prefix("base64:") {
                    match base64_decode(payload) {
                        Some(bytes) => Value::Array(
                            bytes.into_iter().map(|b| Value::Number(b.into())).collect(),
                        ),
                        None => {
                            // Decode failure is unrecoverable; emit
                            // empty so the build doesn't silently
                            // ship a corrupted payload, but don't
                            // halt the whole pipeline.
                            Value::String(String::new())
                        }
                    }
                } else {
                    Value::String(resolved.to_string())
                }
            } else {
                Value::String(String::new())
            };

            // Auto-detect template if body contains {{ }} (text bodies
            // only — binary byte arrays can't be templated).
            handler = match &body_value {
                Value::String(s) if s.contains("{{") => handler_id::TEMPLATE,
                _ => handler_id::STATIC,
            };

            kv.insert(format!("route_{i}_body"), body_value);
        }

        kv.insert(
            format!("route_{i}_handler"),
            Value::Number(serde_json::Number::from(handler)),
        );

        // Per-route Content-Type (optional). Common values: text/html
        // (default), application/wasm, application/json,
        // application/octet-stream. The http module clamps to
        // MAX_CONTENT_TYPE bytes; longer values are truncated.
        if let Some(ct_val) = obj.get("content_type").and_then(|v| v.as_str()) {
            kv.insert(
                format!("route_{i}_content_type"),
                Value::String(ct_val.to_string()),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Derive the handler byte a `routes:` entry compiles to.
    fn handler_of(route: serde_json::Value) -> Option<u64> {
        let mut kv: HashMap<String, Value> = HashMap::new();
        expand_routes(&[route], &mut kv, None).expect("within route ceiling");
        kv.get("route_0_handler").and_then(|v| v.as_u64())
    }

    /// Each boolean route key selects its handler.
    ///
    /// The ids come from `fluxor_abi::config::route_handler`, which
    /// the serving module compiles against too — so this asserts the mapping
    /// from route KEY to handler, not the numbers themselves. A silent
    /// disagreement about a number would be invisible in a config dump (the
    /// route simply serves the wrong thing), which is why there is one
    /// definition rather than two that are checked against each other.
    #[test]
    fn boolean_route_keys_select_their_handlers() {
        for (route, want) in [
            (
                serde_json::json!({"path": "/ws", "websocket": true}),
                handler_id::WEBSOCKET,
            ),
            (
                serde_json::json!({"path": "/pkg.Svc/", "grpc": true}),
                handler_id::GRPC,
            ),
            (
                serde_json::json!({"path": "/app/", "app": true}),
                handler_id::APP,
            ),
            (
                serde_json::json!({"path": "/sub", "websocket_fanout": true}),
                handler_id::WS_FANOUT_RETAIN,
            ),
            (
                serde_json::json!({"path": "/sub", "websocket_fanout": true, "retain_replay": false}),
                handler_id::WS_FANOUT,
            ),
            (
                serde_json::json!({"path": "/sub", "websocket_fanout": true, "admit": true}),
                handler_id::WS_FANOUT_ADMIT,
            ),
            (
                serde_json::json!({"path": "/p", "proxy": "10.0.0.1:80"}),
                handler_id::PROXY,
            ),
            (
                serde_json::json!({"path": "/t", "body": "hi {{name}}"}),
                handler_id::TEMPLATE,
            ),
            (
                serde_json::json!({"path": "/s", "body": "hi"}),
                handler_id::STATIC,
            ),
        ] {
            assert_eq!(
                handler_of(route.clone()),
                Some(u64::from(want)),
                "route {route} selected the wrong handler"
            );
        }
    }

    /// The websocket fan-out family: retention, session isolation, and
    /// admission are three different routes to three different handlers.
    ///
    /// `admit` is the one with a security consequence. A graph that meant to
    /// gate its upgrade and silently compiled to handler 5 would accept every
    /// connection and never report one on `ws_admit_out` — an unguarded
    /// control socket that looks exactly like a guarded one in a config dump.
    #[test]
    fn websocket_fanout_variants_select_their_handlers() {
        assert_eq!(
            handler_of(serde_json::json!({"path": "/ws", "websocket_fanout": true})),
            Some(5),
            "retention on by default"
        );
        assert_eq!(
            handler_of(serde_json::json!({
                "path": "/ws", "websocket_fanout": true, "retain_replay": false
            })),
            Some(9),
            "no replay across sessions"
        );
        assert_eq!(
            handler_of(serde_json::json!({
                "path": "/ws", "websocket_fanout": true, "admit": true
            })),
            Some(12),
            "the application grants the upgrade"
        );
        // Admission implies session semantics, so it wins over an explicit
        // `retain_replay` either way rather than combining into a fourth id.
        assert_eq!(
            handler_of(serde_json::json!({
                "path": "/ws", "websocket_fanout": true, "admit": true, "retain_replay": true
            })),
            Some(12)
        );
        // And it is opt-in: absent or false leaves the ungated handler.
        assert_eq!(
            handler_of(serde_json::json!({
                "path": "/ws", "websocket_fanout": true, "admit": false
            })),
            Some(5)
        );
    }

    /// **The trap this test exists for.** `handler` is DERIVED from the
    /// boolean keys and never read from the yaml, so a raw `handler: 11`
    /// compiles to handler 0 — a static route with no body, which answers
    /// `200 OK` with `Content-Length: 0` — a misconfigured route that reads
    /// as a working server.
    ///
    /// Pinned so the silence is a decision rather than a surprise. If raw
    /// handler numbers are ever accepted, this test is where that changes.
    #[test]
    fn a_raw_handler_number_is_ignored_not_honoured() {
        assert_eq!(
            handler_of(serde_json::json!({"path": "/app/", "handler": 11})),
            Some(0),
            "a raw `handler:` number must not select a handler — use the \
             boolean key (`app: true`) instead"
        );
    }

    /// A route with none of the boolean keys is a static body route.
    #[test]
    fn a_plain_route_is_static() {
        assert_eq!(
            handler_of(serde_json::json!({"path": "/", "body": "hi"})),
            Some(0)
        );
    }

    /// Build a throwaway project root holding a `fluxor.lock` that pins
    /// `pinned_conn` to a digest no store contains, plus an empty store the
    /// resolver is pointed at. Returns (project, store, modules_dir).
    fn pinned_but_missing_fixture() -> (tempfile::TempDir, tempfile::TempDir, std::path::PathBuf) {
        let project = tempfile::tempdir().expect("tempdir-project");
        let store = tempfile::tempdir().expect("tempdir-store");
        std::fs::write(project.path().join(".fluxor"), b"").expect("project marker");
        std::fs::write(
            project.path().join("fluxor.lock"),
            "[[artifact]]\n\
             kind = \"module\"\n\
             name = \"pinned_conn\"\n\
             project = \"local\"\n\
             target = \"bcm2712\"\n\
             digest = \"sha256:\
             0000000000000000000000000000000000000000000000000000000000000000\"\n\
             reference = \"local/pinned_conn:1\"\n",
        )
        .expect("write lockfile");
        let modules_dir = project
            .path()
            .join("target")
            .join("fluxor")
            .join("bcm2712")
            .join("modules");
        std::fs::create_dir_all(&modules_dir).expect("modules dir");
        (project, store, modules_dir)
    }

    /// A module pinned in `fluxor.lock` whose artifact the store cannot
    /// produce must ABORT the build naming module, pin and cause — never
    /// collapse to "this module has no params" and pack an empty TLV
    /// section, which ships the module unconfigured (a connector with no
    /// `endpoint`). Sibling of `config::assert_pinned_manifests_resolvable`,
    /// which already fails closed on the manifest half of the same pin.
    #[test]
    fn pinned_module_with_unresolvable_store_is_a_hard_error() {
        let (_project, store, modules_dir) = pinned_but_missing_fixture();
        let _env = crate::config::test_env::EnvGuard::set(&[("FLUXOR_STORE", store.path())]);

        let err = load_schema_for_module("pinned_conn", &modules_dir)
            .expect_err("pinned module with no store artifact must fail closed");
        let msg = err.to_string();
        assert!(msg.contains("pinned_conn"), "names the module: {msg}");
        assert!(msg.contains("fluxor.lock"), "names the lockfile: {msg}");
        assert!(
            msg.contains("pin local/pinned_conn:1") && msg.contains("sha256:0000"),
            "names the pin reference and digest: {msg}"
        );
        assert!(
            msg.contains("could not be resolved from the OCI store"),
            "reads as a sibling of the manifest failure: {msg}"
        );
    }

    /// The other two outcomes stay `Ok(None)`: a module the pins don't cover
    /// and whose `.fmod` isn't on disk is "no schema here" — the built-in
    /// lookup and the module-table builder handle that case, so turning it
    /// into an error would break every built-in module.
    #[test]
    fn unpinned_module_without_fmod_reports_no_schema() {
        let (_project, store, modules_dir) = pinned_but_missing_fixture();
        let _env = crate::config::test_env::EnvGuard::set(&[("FLUXOR_STORE", store.path())]);

        let schema =
            load_schema_for_module("not_pinned_anywhere", &modules_dir).expect("not a hard error");
        assert!(schema.is_none(), "no pin, no .fmod → no schema");
    }
}

#[cfg(test)]
mod requires_when_resolution {
    use super::*;
    use crate::manifest::{Manifest, ManifestParam, ManifestParamType};

    /// A schema shaped like tls's: `clock_policy` enum, `require = 0` default.
    fn clock_schema() -> ParamSchema {
        let m = Manifest {
            params: vec![ManifestParam {
                tag: 12,
                name: "clock_policy".into(),
                ptype: ManifestParamType::Enum,
                default_num: 0,
                default_str: "require".into(),
                enum_values: vec![("require".into(), 0), ("unchecked".into(), 1)],
                range: None,
                required: false,
            }],
            ..Manifest::default()
        };
        ParamSchema::from_manifest(&m).expect("schema")
    }

    fn yaml(s: &str) -> Value {
        serde_yaml::from_str(s).expect("yaml")
    }

    fn one_of(m: &Value, s: &ParamSchema, p: &str, w: &[&str]) -> Option<bool> {
        let w: Vec<String> = w.iter().map(|x| x.to_string()).collect();
        param_is_one_of(m, s, p, &w)
    }

    #[test]
    fn unset_resolves_to_the_schema_default() {
        let s = clock_schema();
        let m = yaml("type: tls\n");
        assert_eq!(effective_param_value(&m, &s, "clock_policy"), Some(0));
        assert_eq!(one_of(&m, &s, "clock_policy", &["require"]), Some(true));
        assert_eq!(one_of(&m, &s, "clock_policy", &["unchecked"]), Some(false));
        assert_eq!(
            one_of(&m, &s, "clock_policy", &["unchecked", "require"]),
            Some(true)
        );
    }

    #[test]
    fn set_by_name_number_or_under_params_resolves_alike() {
        let s = clock_schema();
        for m in [
            yaml("type: tls\nclock_policy: unchecked\n"),
            yaml("type: tls\nparams:\n  clock_policy: unchecked\n"),
            yaml("type: tls\nclock_policy: 1\n"),
        ] {
            assert_eq!(one_of(&m, &s, "clock_policy", &["unchecked"]), Some(true));
            assert_eq!(one_of(&m, &s, "clock_policy", &["0"]), Some(false));
        }
    }

    #[test]
    fn undeclared_parameter_or_value_is_none() {
        let s = clock_schema();
        let m = yaml("type: tls\n");
        assert_eq!(one_of(&m, &s, "no_such", &["require"]), None);
        assert_eq!(one_of(&m, &s, "clock_policy", &["sometimes"]), None);
        assert_eq!(
            one_of(&m, &s, "clock_policy", &["require", "sometimes"]),
            None
        );
    }
}

#[cfg(test)]
mod resolve_u32_forms {
    use super::*;

    fn param() -> SchemaParam {
        SchemaParam {
            tag: 0,
            ptype: ParamType::U32,
            name: String::from("dst_ip"),
            default: 0,
            enums: HashMap::new(),
        }
    }

    /// A hex literal is a number, not a name to hash.
    #[test]
    fn hex_is_parsed_not_hashed() {
        let v = serde_json::json!("0xC0A8010A");
        assert_eq!(resolve_u32(&v, &param()), 0xC0A8_010A);
    }

    /// Dotted quad and decimal remain the readable forms.
    #[test]
    fn dotted_quad_and_decimal_agree() {
        let p = param();
        let a = resolve_u32(&serde_json::json!("192.168.1.10"), &p);
        let b = resolve_u32(&serde_json::json!("3232235786"), &p);
        let c = resolve_u32(&serde_json::json!(3232235786u64), &p);
        assert_eq!(a, 0xC0A8_010A);
        assert_eq!(a, b);
        assert_eq!(a, c);
    }
}
