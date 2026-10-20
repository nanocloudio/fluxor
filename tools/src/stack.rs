//! Published stacks: a parameterised piece of graph, included by name.
//!
//! A stack is a set of modules and the wiring between them that a graph
//! takes in whole. Platform stacks (`stacks/*.toml`, expanded by the CLI's
//! `stack_expand`) are fluxor's own, injected by matching the target. A
//! published stack is a reusable subsystem — a storage node, a store
//! replica, a peer-link — that any project owns and other projects' graphs
//! include explicitly. This module is the published form.
//!
//! The owner owns the composition's SHAPE: its modules, their
//! types, the wiring between them, which knobs exist and which ports the
//! outside may reach. The includer owns the INSTANCE: the name it is known
//! by, the values of its knobs, where it is placed and what its exports are
//! wired to. Neither edits the other's text.
//!
//! The document (`docs/architecture/stacks.md` has the full surface):
//!
//! ```yaml
//! stack: sealed_volume           # name; marks the file as a stack
//! version: 0.1.0                 # the published version
//! params:                        # the one params schema graphs declare
//!   image: { type: string, required: true, example: volume.img }
//!   block_size: { type: integer, default: 512, min: 512, max: 4096 }
//! exports:                       # the only ports an includer may wire
//!   blocks: seal.blocks
//!   status: seal.status
//! modules:
//!   - name: disk
//!     type: file_block
//!     path: ${param:image}
//!     block_size: ${param:block_size}
//!   - name: seal
//!     type: crypt_block
//! wiring:
//!   - from: disk.blocks
//!     to: seal.lower
//! ```
//!
//! and a graph includes it:
//!
//! ```yaml
//! include:
//!   - stack: sealed_volume        # a stack name, or a file path
//!     as: data                    # modules become data_disk, data_seal
//!     params: { image: data.img }
//! wiring:
//!   - from: data.blocks           # an export, never an internal port
//!     to: fs.blocks
//! ```
//!
//! Expansion runs on the parsed graph before every other pass — ahead of
//! platform stack expansion and placement — so everything downstream sees
//! an ordinary graph: the stack's modules under prefixed names, its internal edges,
//! and the includer's export edges rewritten onto the internal ports they
//! name. Content types, port directions, params and capacity are then held
//! to the same validation as any hand-written edge.
//!
//! Parameters are the one model graphs use ([`crate::params`]): the same
//! declaration, the same `${param:<name>}` placeholder and the same
//! parsed-tree substitution, so a value is data and can never add a module or
//! an edge. A graph may forward its own `${param:x}` into an include's param
//! when the two are declared with the same type.
//!
//! A published stack carries its module references the way a bundle
//! carries its modules: as the exact module artifacts, per target, it was
//! composed against — resolved at publish time through the publishing
//! project's own published modules and its `fluxor.lock`. A stack name a
//! graph includes is a reference: `fluxor update` pins the stack, and the
//! module references it carries, from the dependency that publishes it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::oci_store::{OciStore, MT_FLUXOR_STACK, MT_FLUXOR_STACK_MODULES};
use crate::params::{self, ParamSpec, ParamType, ParamValue};
use crate::store_resolve::{self, Artifact};

/// The lockfile kind, the store `io.fluxor.kind` annotation and the
/// document's marker key.
pub const KIND: &str = "stack";

/// The tag namespace stacks publish under: `stack/<name>:<version>`.
pub const TAG_PREFIX: &str = "stack/";

/// The graph key that includes stacks.
pub const INCLUDE_KEY: &str = "include";

/// Every key a stack document may carry. A target, a platform, a
/// scheduler, services, execution domains: each belongs to the graph that
/// includes the stack, never to the stack.
const DOC_KEYS: &[&str] = &[
    "stack",
    "version",
    "description",
    "params",
    "exports",
    "modules",
    "wiring",
];

/// Every key one `include:` entry may carry.
const INCLUDE_ENTRY_KEYS: &[&str] = &["stack", "as", "params", "node"];

/// Keys of a stack module entry that are its identity, owned by the
/// stack and never parameterised.
const IDENTITY_KEYS: &[&str] = &["name", "type", "variant"];

/// The keys a placed member keeps (`config::placement`): its identity and
/// its node. Its parameters and its wiring belong to the graph that
/// instantiates it on that node.
const PLACED_KEYS: &[&str] = &["name", "type", "variant", "node"];

/// Longest stack name, in bytes.
const MAX_NAME_BYTES: usize = 64;

/// Longest version, in bytes: the OCI tag bound.
const MAX_VERSION_BYTES: usize = 128;

/// The tag every publish also moves, and so never a version.
const LATEST: &str = "latest";

/// Highest buffer group: an edge entry carries its group in 5 bits, and 0
/// is no group.
const BUFFER_GROUP_MAX: u64 = 31;

/// Placeholder opener, as [`crate::params`] spells it.
const PLACEHOLDER: &str = "${param:";

// ============================================================================
// The document
// ============================================================================

/// A parsed and checked stack document.
#[derive(Clone, Debug)]
pub struct Stack {
    /// The stack's name (`stack:`).
    pub name: String,
    /// The published version (`version:`); required to publish.
    pub version: Option<String>,
    /// The typed parameter schema.
    pub params: BTreeMap<String, ParamSpec>,
    /// Export name → the internal endpoint(s) it stands for. More than one
    /// endpoint fans the export out: every edge the includer draws to it
    /// becomes one edge per endpoint.
    pub exports: BTreeMap<String, Vec<String>>,
    /// Module entries, placeholders unrendered.
    modules: Vec<serde_yaml::Value>,
    /// Edge entries, placeholders unrendered.
    wiring: Vec<serde_yaml::Value>,
}

/// Is `name` a stack name: `[a-z][a-z0-9_-]*`, at most
/// [`MAX_NAME_BYTES`]. It is a store tag component, so it carries no `/`
/// and no `:`.
pub fn is_stack_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && name.len() <= MAX_NAME_BYTES
        && bytes.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}

/// Is `version` a publishable version: an OCI tag
/// (`[A-Za-z0-9_][A-Za-z0-9._-]*`, at most [`MAX_VERSION_BYTES`]) other than
/// `latest`, which every publish moves to the version it publishes.
pub fn is_version(version: &str) -> bool {
    let mut bytes = version.bytes();
    matches!(bytes.next(), Some(b) if b.is_ascii_alphanumeric() || b == b'_')
        && version.len() <= MAX_VERSION_BYTES
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && version != LATEST
}

/// Is `alias` an include instance name: `[a-z][a-z0-9_]*`. It prefixes
/// module names and stands as the module part of an export endpoint, so it
/// is held to the module-name alphabet.
fn is_alias(alias: &str) -> bool {
    params::is_param_name(alias)
}

/// Does a parsed YAML document declare itself a stack?
pub fn is_stack_document(doc: &serde_yaml::Value) -> bool {
    doc.as_mapping()
        .is_some_and(|m| m.contains_key(serde_yaml::Value::String(KIND.into())))
}

fn yaml_kind(v: &serde_yaml::Value) -> &'static str {
    match v {
        serde_yaml::Value::Null => "null",
        serde_yaml::Value::Bool(_) => "a boolean",
        serde_yaml::Value::Number(n) if n.is_i64() || n.is_u64() => "an integer",
        serde_yaml::Value::Number(_) => "a float",
        serde_yaml::Value::String(_) => "a string",
        serde_yaml::Value::Sequence(_) => "a list",
        serde_yaml::Value::Mapping(_) => "a mapping",
        serde_yaml::Value::Tagged(_) => "a tagged value",
    }
}

fn has_placeholder(s: &str) -> bool {
    s.contains(PLACEHOLDER)
}

/// `module.port` → `(module, port)`.
fn split_endpoint(spec: &str) -> Option<(&str, &str)> {
    let (m, p) = spec.split_once('.')?;
    (!m.is_empty() && !p.is_empty()).then_some((m, p))
}

impl Stack {
    /// Parse and check a stack document. Every violation is reported
    /// together, one per line.
    pub fn parse(text: &str) -> std::result::Result<Stack, String> {
        let doc: serde_yaml::Value =
            serde_yaml::from_str(text).map_err(|e| format!("parse stack: {e}"))?;
        Self::from_document(&doc)
    }

    /// [`Stack::parse`] over an already-parsed document.
    pub fn from_document(doc: &serde_yaml::Value) -> std::result::Result<Stack, String> {
        let map = doc
            .as_mapping()
            .ok_or_else(|| "a stack is a mapping".to_string())?;
        let mut errors: Vec<String> = Vec::new();
        // What a stack means cannot depend on the environment of whoever
        // builds it: a value the includer's caller has is the includer's
        // own param, which it forwards.
        if let Err(e) = params::refuse_environment(doc, "stack") {
            errors.push(e);
        }

        for key in map.keys() {
            match key.as_str() {
                Some(k) if DOC_KEYS.contains(&k) => {}
                Some(k) => errors.push(format!(
                    "unknown key `{k}`: a stack carries {} — a target, platform, \
                     scheduler or any other graph-wide setting belongs to the graph that \
                     includes it",
                    DOC_KEYS.join(", ")
                )),
                None => errors.push(format!("non-string key {key:?}")),
            }
        }
        let get = |k: &str| map.get(serde_yaml::Value::String(k.into()));

        let name = match get("stack") {
            Some(serde_yaml::Value::String(n)) if is_stack_name(n) => n.clone(),
            Some(serde_yaml::Value::String(n)) => {
                errors.push(format!(
                    "stack name '{n}' is not [a-z][a-z0-9_-]* of at most {MAX_NAME_BYTES} \
                     bytes"
                ));
                n.clone()
            }
            Some(other) => {
                errors.push(format!(
                    "`stack:` names the stack and must be a string, got {}",
                    yaml_kind(other)
                ));
                String::new()
            }
            None => {
                errors.push("`stack: <name>` is required".into());
                String::new()
            }
        };

        let version = match get("version") {
            None => None,
            Some(serde_yaml::Value::String(v)) if is_version(v) => Some(v.clone()),
            Some(serde_yaml::Value::String(v)) => {
                errors.push(format!(
                    "`version: {v}` is not a store tag: [A-Za-z0-9_][A-Za-z0-9._-]* of at most \
                     {MAX_VERSION_BYTES} bytes, and not `{LATEST}`"
                ));
                None
            }
            Some(other) => {
                errors.push(format!(
                    "`version:` must be a string (quote a numeric version), got {}",
                    yaml_kind(other)
                ));
                None
            }
        };

        if let Some(d) = get("description") {
            if !d.is_string() {
                errors.push(format!(
                    "`description:` must be a string, got {}",
                    yaml_kind(d)
                ));
            }
        }

        let params = match get("params").map_or(Ok(BTreeMap::new()), params::parse_params) {
            Ok(p) => {
                errors.extend(params::validate_schema(&p));
                p
            }
            Err(e) => {
                errors.push(e);
                BTreeMap::new()
            }
        };

        let modules: Vec<serde_yaml::Value> = match get("modules") {
            None | Some(serde_yaml::Value::Null) => {
                errors.push("`modules:` is required: a stack is at least one module".into());
                Vec::new()
            }
            Some(serde_yaml::Value::Sequence(seq)) => seq
                .iter()
                .map(|m| match m {
                    // A bare name is shorthand for `{ name: <name> }`.
                    serde_yaml::Value::String(n) => {
                        let mut entry = serde_yaml::Mapping::new();
                        entry.insert("name".into(), serde_yaml::Value::String(n.clone()));
                        serde_yaml::Value::Mapping(entry)
                    }
                    other => other.clone(),
                })
                .collect(),
            Some(other) => {
                errors.push(format!(
                    "`modules:` must be a list, got {}",
                    yaml_kind(other)
                ));
                Vec::new()
            }
        };

        let wiring: Vec<serde_yaml::Value> = match get("wiring") {
            None | Some(serde_yaml::Value::Null) => Vec::new(),
            Some(serde_yaml::Value::Sequence(seq)) => seq.clone(),
            Some(other) => {
                errors.push(format!(
                    "`wiring:` must be a list, got {}",
                    yaml_kind(other)
                ));
                Vec::new()
            }
        };

        // Modules: a unique, literal name each; placement is the includer's.
        let mut names: BTreeSet<String> = BTreeSet::new();
        for (i, m) in modules.iter().enumerate() {
            let Some(entry) = m.as_mapping() else {
                errors.push(format!(
                    "modules[{i}] must be a mapping or a name, got {}",
                    yaml_kind(m)
                ));
                continue;
            };
            let name = match entry.get("name") {
                Some(serde_yaml::Value::String(n)) => n.clone(),
                _ => {
                    errors.push(format!("modules[{i}] needs a string `name`"));
                    continue;
                }
            };
            for key in IDENTITY_KEYS {
                match entry.get(*key) {
                    None => {}
                    Some(serde_yaml::Value::String(s)) if has_placeholder(s) => {
                        errors.push(format!(
                            "module '{name}': `{key}` is parameterised; a module's identity \
                             is the stack's shape and only its values take parameters"
                        ));
                    }
                    Some(serde_yaml::Value::String(_)) => {}
                    Some(other) => errors.push(format!(
                        "module '{name}': `{key}` must be a string, got {}",
                        yaml_kind(other)
                    )),
                }
            }
            if name.is_empty() || name.contains('.') || name.chars().any(char::is_whitespace) {
                errors.push(format!(
                    "module name '{name}' must be non-empty with no `.` or whitespace"
                ));
            }
            if entry.contains_key("node") {
                errors.push(format!(
                    "module '{name}' carries `node:`; where a stack runs is the includer's \
                     decision (`node:` on the include)"
                ));
            }
            if !names.insert(name.clone()) {
                errors.push(format!("module '{name}' is declared twice"));
            }
        }

        // Wiring: object form, internal endpoints only.
        let endpoint_ok = |spec: &str, what: &str, errors: &mut Vec<String>| {
            if has_placeholder(spec) {
                errors.push(format!(
                    "{what} '{spec}' is parameterised; the stack's wiring is its shape"
                ));
                return;
            }
            match split_endpoint(spec) {
                Some((m, _)) if names.contains(m) => {}
                Some((m, _)) => errors.push(format!(
                    "{what} '{spec}' names '{m}', which is not a module of this stack — a \
                     stack wires only its own modules; expose the port as an export and let \
                     the includer wire it"
                )),
                None => errors.push(format!("{what} '{spec}' is not `module.port`")),
            }
        };
        for (i, w) in wiring.iter().enumerate() {
            let Some(edge) = w.as_mapping() else {
                errors.push(format!(
                    "wiring[{i}] must be a mapping with `from` and `to`, got {}",
                    yaml_kind(w)
                ));
                continue;
            };
            for end in ["from", "to"] {
                match edge.get(end) {
                    Some(serde_yaml::Value::String(s)) => {
                        endpoint_ok(s, &format!("wiring[{i}].{end}"), &mut errors)
                    }
                    _ => errors.push(format!("wiring[{i}] needs a string `{end}`")),
                }
            }
        }

        // Exports: names for internal endpoints.
        let mut exports: BTreeMap<String, Vec<String>> = BTreeMap::new();
        match get("exports") {
            None | Some(serde_yaml::Value::Null) => {}
            Some(serde_yaml::Value::Mapping(m)) => {
                for (k, v) in m {
                    let Some(export) = k.as_str() else {
                        errors.push(format!("export name {k:?} must be a string"));
                        continue;
                    };
                    if !is_alias(export) {
                        errors.push(format!("export name '{export}' is not [a-z][a-z0-9_]*"));
                    }
                    let targets: Vec<String> = match v {
                        serde_yaml::Value::String(s) => vec![s.clone()],
                        serde_yaml::Value::Sequence(seq) if !seq.is_empty() => seq
                            .iter()
                            .map(|e| e.as_str().map(str::to_string).unwrap_or_default())
                            .collect(),
                        other => {
                            errors.push(format!(
                                "export '{export}' must name `module.port` or a non-empty list \
                                 of them, got {}",
                                yaml_kind(other)
                            ));
                            continue;
                        }
                    };
                    for t in &targets {
                        endpoint_ok(t, &format!("export '{export}'"), &mut errors);
                    }
                    exports.insert(export.to_string(), targets);
                }
            }
            Some(other) => errors.push(format!(
                "`exports:` must be a mapping of export name to `module.port`, got {}",
                yaml_kind(other)
            )),
        }

        // Every placeholder declared, every declared param used.
        let mut used = BTreeSet::new();
        for v in modules.iter().chain(wiring.iter()) {
            match params::placeholders(v) {
                Ok(p) => used.extend(p),
                Err(e) => errors.push(e),
            }
        }
        errors.extend(params::check_references(&params, &used, "stack"));

        if errors.is_empty() {
            Ok(Stack {
                name,
                version,
                params,
                exports,
                modules,
                wiring,
            })
        } else {
            Err(errors.join("\n"))
        }
    }

    /// The stack's module names, in declaration order.
    pub fn module_names(&self) -> Vec<String> {
        self.modules
            .iter()
            .filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(str::to_string))
            .collect()
    }

    /// Each module's effective type (`type:`, else its name), deduplicated.
    pub fn module_types(&self) -> BTreeSet<String> {
        self.modules
            .iter()
            .filter_map(|m| {
                m.get("type")
                    .and_then(|t| t.as_str())
                    .or_else(|| m.get("name").and_then(|n| n.as_str()))
                    .map(str::to_string)
            })
            .collect()
    }

    /// Render the stack with its defaults and examples, the values a
    /// check without a consumer uses. A file example names a sample
    /// relative to `dir`, the stack's own directory.
    pub fn check_render(&self, dir: &Path) -> std::result::Result<(), String> {
        let values = params::check_values(&self.params, dir)?;
        self.render(&values).map(|_| ())
    }

    /// Modules and wiring with `values` substituted, as JSON.
    fn render(
        &self,
        values: &BTreeMap<String, ParamValue>,
    ) -> std::result::Result<(Vec<Value>, Vec<Value>), String> {
        let to_json = |v: serde_yaml::Value| -> std::result::Result<Value, String> {
            serde_json::to_value(v).map_err(|e| format!("render: {e}"))
        };
        let mut modules = Vec::with_capacity(self.modules.len());
        for m in &self.modules {
            modules.push(to_json(params::render(m, values)?)?);
        }
        let mut wiring = Vec::with_capacity(self.wiring.len());
        for w in &self.wiring {
            wiring.push(to_json(params::render(w, values)?)?);
        }
        Ok((modules, wiring))
    }
}

// ============================================================================
// Include values
// ============================================================================

/// A JSON scalar as the TOML value [`params`] types and checks.
fn json_scalar(v: &Value) -> Option<toml::Value> {
    match v {
        Value::Bool(b) => Some(toml::Value::Boolean(*b)),
        Value::Number(n) => n.as_i64().map(toml::Value::Integer),
        Value::String(s) => Some(toml::Value::String(s.clone())),
        _ => None,
    }
}

fn json_kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "an integer",
        Value::Number(_) => "a float",
        Value::String(_) => "a string",
        Value::Array(_) => "a list",
        Value::Object(_) => "a mapping",
    }
}

/// The `${param:<name>}` a whole include value forwards, if that is what it
/// is.
fn forwarded(v: &Value) -> Option<&str> {
    let s = v.as_str()?;
    let name = s.strip_prefix(PLACEHOLDER)?.strip_suffix('}')?;
    params::is_param_name(name).then_some(name)
}

/// May the includer's `from` be forwarded into the stack's `to`? The types
/// match, and an integer's declared range lies inside the stack's, so every
/// value the includer accepts the stack accepts too.
fn forwardable(name: &str, from: &ParamSpec, to: &ParamSpec) -> std::result::Result<(), String> {
    if from.ty != to.ty {
        return Err(format!(
            "param '{name}' is {}, and the graph forwards a param declared {}",
            to.ty.label(),
            from.ty.label()
        ));
    }
    let below = |bound: Option<i64>, of: Option<i64>| match (bound, of) {
        (Some(b), Some(o)) => o < b,
        (Some(_), None) => true,
        (None, _) => false,
    };
    if below(to.min, from.min) || to.max.is_some_and(|m| from.max.is_none_or(|f| f > m)) {
        return Err(format!(
            "param '{name}' takes {}..={}, and the graph forwards a param declared {}..={}; \
             declare the forwarded param within the stack's bounds",
            to.min.map_or("".into(), |v| v.to_string()),
            to.max.map_or("".into(), |v| v.to_string()),
            from.min.map_or("".into(), |v| v.to_string()),
            from.max.map_or("".into(), |v| v.to_string()),
        ));
    }
    Ok(())
}

/// The values one include instantiates its stack with: what the include
/// supplies, typed and bounded against the declaration, with defaults for
/// the rest. A value that is exactly `${param:<x>}` forwards the including
/// graph's own param `x`, declared in `includer`: it is accepted when the
/// two declarations match ([`forwardable`]) and stays a placeholder the
/// graph's own values render. A value with placeholders inside other text
/// is a string. Every refusal — an unknown name, a type or range error, a
/// missing required value, a file that is not there, a forward of another
/// type — is reported together. A `file` value is taken relative to
/// `base_dir`, the including graph's directory, and becomes the file's
/// absolute path.
pub fn resolve_values(
    params: &BTreeMap<String, ParamSpec>,
    supplied: &Map<String, Value>,
    base_dir: &Path,
    includer: &BTreeMap<String, ParamSpec>,
) -> std::result::Result<BTreeMap<String, ParamValue>, String> {
    let declared = if params.is_empty() {
        "none".to_string()
    } else {
        params
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut errors = Vec::new();
    let mut values = BTreeMap::new();
    for (name, v) in supplied {
        let Some(spec) = params.get(name) else {
            errors.push(format!("unknown param '{name}' (declared: {declared})"));
            continue;
        };
        if let Some(x) = forwarded(v) {
            match includer.get(x) {
                None => errors.push(format!(
                    "param '{name}' forwards `{PLACEHOLDER}{x}}}`, which the graph's `params:` \
                     does not declare"
                )),
                Some(from) => match forwardable(name, from, spec) {
                    Ok(()) => {
                        values.insert(
                            name.clone(),
                            ParamValue::String(format!("{PLACEHOLDER}{x}}}")),
                        );
                    }
                    Err(e) => errors.push(e),
                },
            }
            continue;
        }
        if v.as_str().is_some_and(has_placeholder) {
            if spec.ty == ParamType::String {
                values.insert(
                    name.clone(),
                    ParamValue::String(v.as_str().unwrap_or_default().into()),
                );
            } else {
                errors.push(format!(
                    "param '{name}' is {}, and text around a placeholder makes a string",
                    spec.ty.label()
                ));
            }
            continue;
        }
        let Some(tv) = json_scalar(v) else {
            errors.push(format!(
                "param '{name}' is {}, got {}",
                spec.ty.label(),
                json_kind(v)
            ));
            continue;
        };
        let typed = params::typed_toml(&format!("param '{name}'"), spec.ty, &tv)
            .and_then(|pv| params::check_value(name, spec, &pv).map(|()| pv));
        match typed {
            Ok(ParamValue::String(p)) if spec.ty == ParamType::File => {
                match params::existing_file(name, &base_dir.join(&p)) {
                    Ok(abs) => {
                        values.insert(name.clone(), ParamValue::String(abs));
                    }
                    Err(e) => errors.push(e),
                }
            }
            Ok(pv) => {
                values.insert(name.clone(), pv);
            }
            Err(e) => errors.push(e),
        }
    }
    for (name, spec) in params {
        if values.contains_key(name) || supplied.contains_key(name) {
            continue;
        }
        match &spec.default {
            Some(d) => {
                values.insert(name.clone(), d.clone());
            }
            None => errors.push(format!(
                "missing required param '{name}'{}",
                spec.description
                    .as_deref()
                    .map(|d| format!(" ({d})"))
                    .unwrap_or_default()
            )),
        }
    }
    if errors.is_empty() {
        Ok(values)
    } else {
        Err(errors.join("; "))
    }
}

// ============================================================================
// Expansion
// ============================================================================

/// Where includes resolve from.
pub struct IncludeContext<'a> {
    /// The including graph's directory: a local stack path and a `file`
    /// param value are relative to it.
    pub graph_dir: &'a Path,
    /// The project a stack name resolves through: its own
    /// `packaging/stack/<name>.yaml`, else the stack its `fluxor.lock` pins.
    pub project_root: &'a Path,
    /// The store pinned stacks are read from; `None` is the default
    /// store (`$FLUXOR_STORE`, else the XDG data directory).
    pub store_root: Option<&'a Path>,
    /// The including graph's own params: an include may forward one of
    /// them, `${param:<name>}`, as a value.
    pub params: &'a BTreeMap<String, ParamSpec>,
}

/// Is an include's `stack:` value a file path rather than a store name?
/// A stack name has no `/` and no extension, so either marks a path.
fn is_path_reference(r: &str) -> bool {
    r.contains('/') || r.ends_with(".yaml") || r.ends_with(".yml")
}

/// One expanded include.
struct Instance {
    alias: String,
    node: Option<String>,
    /// Export → internal endpoints, already prefixed.
    exports: BTreeMap<String, Vec<String>>,
}

fn module_entry_name(entry: &Value) -> Option<&str> {
    entry
        .as_str()
        .or_else(|| entry.get("name").and_then(|n| n.as_str()))
}

/// Expand every `include:` entry of `config` in place, then drop the key.
///
/// Each include's stack is loaded (from a file, or by name: the project's
/// own packaged stack, else the stack its lock pins), its params resolved and
/// substituted, its
/// modules added under `<as>_<name>` and its internal wiring added with
/// them, each explicit buffer group renumbered to one of the include's own
/// ([`renumber_groups`]); the graph's own edges that name `<as>.<export>`
/// are rewritten onto the internal endpoints the export stands for. An edge
/// that names a stack's internal port, an unknown export, or an export of
/// an include placed on another node is refused, as is any module-name
/// collision, and an include whose groups outnumber the free ones. The
/// expansion is a pure function of the graph, the stacks and the pins:
/// includes expand in list order, a stack's modules and edges keep its
/// declaration order, and they follow the graph's own.
pub fn expand_includes(
    config: &mut Value,
    ctx: &IncludeContext<'_>,
) -> std::result::Result<(), String> {
    let Some(obj) = config.as_object_mut() else {
        return Ok(());
    };
    let Some(includes) = obj.remove(INCLUDE_KEY) else {
        return Ok(());
    };
    let list = match includes {
        Value::Null => return Ok(()),
        Value::Array(a) => a,
        other => {
            return Err(format!(
                "`include:` must be a list of stack includes, got {}",
                json_kind(&other)
            ))
        }
    };

    let mut taken: BTreeSet<String> = obj
        .get("modules")
        .and_then(|m| m.as_array())
        .map(|a| {
            a.iter()
                .filter_map(module_entry_name)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    // Buffer groups already held: the graph's own explicit groups, then each
    // include's as it is given fresh ones.
    let mut groups_held: BTreeSet<u64> = obj
        .get("wiring")
        .and_then(|w| w.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|w| w.get("buffer_group").and_then(Value::as_u64))
                .filter(|g| (1..=BUFFER_GROUP_MAX).contains(g))
                .collect()
        })
        .unwrap_or_default();
    let mut instances: Vec<Instance> = Vec::new();
    // Prefixed module name → the alias that owns it.
    let mut internal: BTreeMap<String, String> = BTreeMap::new();
    let mut added_modules: Vec<Value> = Vec::new();
    let mut added_wiring: Vec<Value> = Vec::new();

    for (i, inc) in list.iter().enumerate() {
        let Some(entry) = inc.as_object() else {
            return Err(format!(
                "include[{i}] must be a mapping (`stack`, `as`, `params`, `node`), got {}",
                json_kind(inc)
            ));
        };
        if let Some(k) = entry
            .keys()
            .find(|k| !INCLUDE_ENTRY_KEYS.contains(&k.as_str()))
        {
            return Err(format!(
                "include[{i}]: unknown key `{k}` (an include carries {})",
                INCLUDE_ENTRY_KEYS.join(", ")
            ));
        }
        let reference = entry.get("stack").and_then(|f| f.as_str()).ok_or_else(|| {
            format!("include[{i}] needs `stack:` — a pinned stack name or a file path")
        })?;
        let alias = entry.get("as").and_then(|a| a.as_str()).ok_or_else(|| {
            format!(
                "include[{i}] (`{reference}`) needs `as:` — the instance name its modules are \
                 prefixed with and its exports are wired through"
            )
        })?;
        let at = format!("include '{alias}' (`{reference}`)");
        if !is_alias(alias) {
            return Err(format!("{at}: `as` must be [a-z][a-z0-9_]*"));
        }
        if instances.iter().any(|x| x.alias == alias) {
            return Err(format!("{at}: `as: {alias}` is used by an earlier include"));
        }
        if taken.contains(alias) {
            return Err(format!(
                "{at}: `as: {alias}` is also a module name; an edge to `{alias}.<port>` would \
                 be ambiguous"
            ));
        }
        let node = match entry.get("node") {
            None | Some(Value::Null) => None,
            Some(Value::String(n)) if !n.is_empty() => Some(n.clone()),
            Some(other) => {
                return Err(format!(
                    "{at}: `node` names the node the include is placed on and must be a \
                     non-empty string, got {}",
                    json_kind(other)
                ))
            }
        };
        let supplied = match entry.get("params") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(m)) => m.clone(),
            Some(other) => {
                return Err(format!(
                    "{at}: `params` must be a mapping, got {}",
                    json_kind(other)
                ))
            }
        };

        let stack = load(reference, ctx).map_err(|e| format!("{at}: {e}"))?;
        let values = resolve_values(&stack.params, &supplied, ctx.graph_dir, ctx.params)
            .map_err(|e| format!("{at}: {e}"))?;
        let (modules, wiring) = stack.render(&values).map_err(|e| format!("{at}: {e}"))?;

        let rename: BTreeMap<String, String> = stack
            .module_names()
            .into_iter()
            .map(|n| {
                let prefixed = format!("{alias}_{n}");
                (n, prefixed)
            })
            .collect();
        let prefix_endpoint = |spec: &str| -> String {
            match split_endpoint(spec) {
                Some((m, p)) => format!("{}.{p}", rename.get(m).map_or(m, String::as_str)),
                None => spec.to_string(),
            }
        };

        for mut m in modules {
            let Some(entry) = m.as_object_mut() else {
                continue;
            };
            let name = entry
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or_default()
                .to_string();
            let prefixed = rename.get(&name).cloned().unwrap_or_else(|| name.clone());
            if !taken.insert(prefixed.clone()) {
                return Err(format!(
                    "{at}: module '{name}' becomes '{prefixed}', which the graph already names \
                     — rename the include or the colliding module"
                ));
            }
            entry
                .entry("type".to_string())
                .or_insert_with(|| Value::String(name.clone()));
            entry.insert("name".into(), Value::String(prefixed.clone()));
            // A partner named by a stack-internal name moves with it.
            if let Some(Value::String(p)) = entry.get_mut("quarantine_partner") {
                if let Some(r) = rename.get(p.as_str()) {
                    *p = r.clone();
                }
            }
            if let Some(n) = &node {
                entry.retain(|k, _| PLACED_KEYS.contains(&k.as_str()));
                entry.insert("node".into(), Value::String(n.clone()));
            }
            internal.insert(prefixed, alias.to_string());
            added_modules.push(m);
        }

        // A placed include's members are instantiated by the graph on that
        // node, edges included; here they are declared only.
        if node.is_none() {
            let wiring =
                renumber_groups(wiring, &mut groups_held).map_err(|e| format!("{at}: {e}"))?;
            for mut w in wiring {
                if let Some(edge) = w.as_object_mut() {
                    for end in ["from", "to"] {
                        if let Some(Value::String(s)) = edge.get_mut(end) {
                            *s = prefix_endpoint(s);
                        }
                    }
                }
                added_wiring.push(w);
            }
        }

        let exports = stack
            .exports
            .iter()
            .map(|(k, v)| (k.clone(), v.iter().map(|e| prefix_endpoint(e)).collect()))
            .collect();
        instances.push(Instance {
            alias: alias.to_string(),
            node,
            exports,
        });
    }

    // The graph's own edges: an endpoint naming an include resolves through
    // its exports; one naming a stack's internal module is refused.
    let own_wiring = match obj.get("wiring") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(a)) => a.clone(),
        Some(_) => return Err("wiring must be a list".into()),
    };
    let resolve_end = |spec: &str, i: usize| -> std::result::Result<Vec<String>, String> {
        let Some((m, port)) = split_endpoint(spec) else {
            return Ok(vec![spec.to_string()]);
        };
        if let Some(inst) = instances.iter().find(|x| x.alias == m) {
            if let Some(n) = &inst.node {
                return Err(format!(
                    "wiring[{i}] '{spec}': include '{m}' is placed on node '{n}' — its \
                     members run there and are reached over a remote channel, so its exports \
                     cannot be wired in this graph"
                ));
            }
            return inst.exports.get(port).cloned().ok_or_else(|| {
                format!(
                    "wiring[{i}] '{spec}': '{port}' is not an export of include '{m}' \
                     (exports: {})",
                    if inst.exports.is_empty() {
                        "none".to_string()
                    } else {
                        inst.exports.keys().cloned().collect::<Vec<_>>().join(", ")
                    }
                )
            });
        }
        if let Some(owner) = internal.get(m) {
            return Err(format!(
                "wiring[{i}] '{spec}': '{m}' is internal to include '{owner}'; wire it \
                 through one of that include's exports (`{owner}.<export>`)"
            ));
        }
        Ok(vec![spec.to_string()])
    };
    let mut wiring_out: Vec<Value> = Vec::with_capacity(own_wiring.len() + added_wiring.len());
    for (i, w) in own_wiring.iter().enumerate() {
        let (Some(from), Some(to)) = (
            w.get("from").and_then(|f| f.as_str()),
            w.get("to").and_then(|t| t.as_str()),
        ) else {
            wiring_out.push(w.clone());
            continue;
        };
        let froms = resolve_end(from, i)?;
        let tos = resolve_end(to, i)?;
        for f in &froms {
            for t in &tos {
                let mut edge = w.clone();
                edge["from"] = Value::String(f.clone());
                edge["to"] = Value::String(t.clone());
                wiring_out.push(edge);
            }
        }
    }
    wiring_out.extend(added_wiring);

    let modules = obj
        .entry("modules".to_string())
        .or_insert_with(|| Value::Array(Vec::new()));
    match modules {
        Value::Array(a) => a.extend(added_modules),
        Value::Null => *modules = Value::Array(added_modules),
        _ => return Err("modules must be a list".into()),
    }
    obj.insert("wiring".into(), Value::Array(wiring_out));
    Ok(())
}

/// Give one include's explicit buffer groups numbers of their own.
///
/// A stack numbers its groups for itself, so its numbers mean nothing
/// in the graph that includes it: they would join the includer's own
/// groups, or a second include of the same stack. Each distinct group
/// the stack's wiring names is renumbered to a group no one else in the
/// graph holds, edges that shared a group still sharing one. A group whose
/// own number is free keeps it; the rest, in ascending order, take the
/// highest free groups in ascending order. A single include whose numbers
/// are free therefore keeps them, and moved groups stay at the top of the
/// 5-bit range, away from the in-place chains the build numbers up from 1
/// (the framed edges it numbers down from 31 skip every group the wiring
/// names). Too few free groups is refused, never clamped.
fn renumber_groups(
    mut wiring: Vec<Value>,
    held: &mut BTreeSet<u64>,
) -> std::result::Result<Vec<Value>, String> {
    let mut own: BTreeSet<u64> = BTreeSet::new();
    for (i, w) in wiring.iter().enumerate() {
        match w.get("buffer_group") {
            None | Some(Value::Null) => {}
            Some(v) => match v.as_u64() {
                Some(0) => {}
                Some(g) if g <= BUFFER_GROUP_MAX => {
                    own.insert(g);
                }
                _ => {
                    return Err(format!(
                        "stack wiring[{i}]: buffer_group must be an integer 0 to \
                         {BUFFER_GROUP_MAX}, got {v}"
                    ))
                }
            },
        }
    }
    if own.is_empty() {
        return Ok(wiring);
    }
    let free: Vec<u64> = (1..=BUFFER_GROUP_MAX)
        .filter(|g| !held.contains(g))
        .collect();
    if free.len() < own.len() {
        return Err(format!(
            "its wiring names {} buffer groups ({}) and only {} of the graph's \
             {BUFFER_GROUP_MAX} are free: the graph's own wiring and the includes before this \
             one hold {}",
            own.len(),
            own.iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            free.len(),
            held.iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let (kept, moved): (Vec<u64>, Vec<u64>) = own.iter().partition(|g| !held.contains(g));
    let open: Vec<u64> = free.into_iter().filter(|g| !kept.contains(g)).collect();
    let fresh = &open[open.len() - moved.len()..];
    let map: BTreeMap<u64, u64> = kept
        .iter()
        .map(|&g| (g, g))
        .chain(moved.iter().copied().zip(fresh.iter().copied()))
        .collect();
    held.extend(map.values());
    for w in &mut wiring {
        if let Some(edge) = w.as_object_mut() {
            if let Some(g) = edge.get("buffer_group").and_then(Value::as_u64) {
                if let Some(&to) = map.get(&g) {
                    edge.insert("buffer_group".into(), Value::from(to));
                }
            }
        }
    }
    Ok(wiring)
}

/// Load the stack an include names: a file relative to the graph; or, by
/// name, the project's own `packaging/stack/<name>.yaml`, else the store
/// stack its `fluxor.lock` pins under that name.
fn load(reference: &str, ctx: &IncludeContext<'_>) -> std::result::Result<Stack, String> {
    let read_file = |path: &Path| {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("read stack {}: {e}", path.display()))?;
        Stack::parse(&text).map_err(|e| format!("{}:\n{e}", path.display()))
    };
    if is_path_reference(reference) {
        return read_file(&ctx.graph_dir.join(reference));
    }
    if !is_stack_name(reference) {
        return Err(format!(
            "'{reference}' is neither a stack name nor a file path (a path contains `/` or \
             ends in .yaml or .yml)"
        ));
    }
    let own = crate::packaging::stack_path(ctx.project_root, reference);
    if own.is_file() {
        return read_file(&own);
    }
    let lock = store_resolve::read_store_lock(ctx.project_root)
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let pinned: Vec<&Artifact> = lock.artifacts.iter().filter(|a| a.kind == KIND).collect();
    let Some(entry) = pinned.iter().find(|a| a.name == reference) else {
        return Err(format!(
            "stack '{reference}' is neither this project's own ({}) nor pinned in {} \
             (pinned stacks: {}) — `fluxor update` pins every stack a graph includes by name \
             from the dependency that publishes it",
            own.display(),
            store_resolve::lockfile_path(ctx.project_root).display(),
            if pinned.is_empty() {
                "none".to_string()
            } else {
                pinned
                    .iter()
                    .map(|a| a.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ));
    };
    let store = open_store(ctx.store_root).map_err(|e| e.to_string())?;
    let p = read_pinned(&store, entry).map_err(|e| e.to_string())?;

    // The stack's modules resolve through the module pins its own pin
    // added; a reference that is not pinned here would leave the build to
    // whatever module happens to be on disk.
    let me = crate::project::project_identity(ctx.project_root)
        .ok()
        .flatten()
        .map(|i| i.name);
    let missing: Vec<String> = p
        .modules
        .iter()
        .filter(|r| Some(&r.project) != me.as_ref())
        .filter(|r| {
            !lock
                .artifacts
                .iter()
                .any(|a| a.kind == "module" && a.name == r.name && a.target == r.target)
        })
        .map(|r| {
            format!(
                "{} ({})",
                r.name,
                r.target.as_deref().unwrap_or("any target")
            )
        })
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "stack '{reference}' composes modules this project does not pin: {} — run \
             `fluxor update` to pin them with the stack",
            missing.join(", ")
        ));
    }
    let stack = Stack::parse(&p.text).map_err(|e| format!("pinned stack '{reference}':\n{e}"))?;
    if stack.name != reference {
        return Err(format!(
            "pinned stack '{reference}' ({}) names itself '{}'",
            entry.digest, stack.name
        ));
    }
    Ok(stack)
}

// ============================================================================
// Reading a graph
// ============================================================================

/// A graph file as everything downstream reads it, its placeholders not yet
/// rendered: parsed and checked ([`params::parse_graph`]), its includes
/// expanded against its own directory and `project_root`, forwarding its
/// own params. Returns the expanded document, without `params:`, and the
/// graph's params.
pub fn read_expanded(
    path: &Path,
    project_root: &Path,
    store_root: Option<&Path>,
) -> std::result::Result<(Value, BTreeMap<String, ParamSpec>), String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let graph = params::parse_graph(&text)?;
    let mut doc: Value =
        serde_json::to_value(&graph.doc).map_err(|e| format!("parse graph: {e}"))?;
    expand_includes(
        &mut doc,
        &IncludeContext {
            graph_dir: graph_dir(path),
            project_root,
            store_root,
            params: &graph.params,
        },
    )?;
    Ok((doc, graph.params))
}

/// A graph file read for a build or a run: [`read_expanded`], then
/// rendered with the values this process renders graphs with
/// ([`params::values_for`]).
pub fn load_graph(path: &Path, project_root: &Path) -> std::result::Result<Value, String> {
    let (doc, declared) = read_expanded(path, project_root, None)?;
    if declared.is_empty() {
        return Ok(doc);
    }
    let values = params::values_for(&declared, graph_dir(path))?;
    let yaml = serde_yaml::to_value(&doc).map_err(|e| format!("render graph: {e}"))?;
    serde_json::to_value(params::render(&yaml, &values)?).map_err(|e| format!("render graph: {e}"))
}

/// The directory a graph's relative references resolve against.
pub fn graph_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn open_store(root: Option<&Path>) -> Result<OciStore> {
    match root {
        Some(r) => OciStore::open(r.to_path_buf()),
        None => OciStore::open(crate::oci_store::store_root()?),
    }
}

// ============================================================================
// The store side
// ============================================================================

/// A pinned stack as the store holds it.
pub struct PinnedStack {
    /// The stack document.
    pub text: String,
    /// Its module references.
    pub modules: Vec<Artifact>,
}

/// Read a pinned stack's document and module references, each layer
/// digest-verified.
pub fn read_pinned(store: &OciStore, e: &Artifact) -> Result<PinnedStack> {
    let manifest = store_resolve::read_pinned_manifest(store, e)?;
    let layer = |mt: &str| -> Result<Vec<u8>> {
        let l = manifest
            .layers
            .iter()
            .find(|l| l.media_type == mt)
            .ok_or_else(|| {
                Error::Config(format!(
                    "stack '{}' ({}) has no {mt} layer — corrupt manifest",
                    e.name, e.digest
                ))
            })?;
        store_resolve::read_manifest_layer_blob(store, &e.name, &e.digest, &l.digest)
    };
    let text = String::from_utf8(layer(MT_FLUXOR_STACK)?).map_err(|err| {
        Error::Config(format!("stack '{}': document is not UTF-8: {err}", e.name))
    })?;
    let modules: Vec<Artifact> = serde_json::from_slice(&layer(MT_FLUXOR_STACK_MODULES)?)
        .map_err(|err| Error::Config(format!("stack '{}': modules.json: {err}", e.name)))?;
    Ok(PinnedStack { text, modules })
}

/// The module artifacts a stack composes, per target, resolved through
/// the publishing project: its own published modules first, then the
/// module pins of its `fluxor.lock`. A kernel built-in has no artifact and
/// is carried by every runtime. A module that resolves neither way is
/// refused: the stack would name a module no consumer could find.
pub fn module_references(
    stack: &Stack,
    project_root: &Path,
    project: &str,
    store: &OciStore,
) -> Result<Vec<Artifact>> {
    let own: Vec<Artifact> = store_resolve::resolve_dependency(store, project, None)
        .unwrap_or_default()
        .into_iter()
        .filter(|a| a.kind == "module")
        .collect();
    let pins: Vec<Artifact> = store_resolve::read_store_lock(project_root)?
        .map(|l| l.artifacts)
        .unwrap_or_default()
        .into_iter()
        .filter(|a| a.kind == "module")
        .collect();
    let mut out = Vec::new();
    let mut missing = Vec::new();
    for ty in stack.module_types() {
        let mine: Vec<&Artifact> = own.iter().filter(|a| a.name == ty).collect();
        let found: Vec<&Artifact> = if mine.is_empty() {
            pins.iter().filter(|a| a.name == ty).collect()
        } else {
            mine
        };
        if found.is_empty() {
            if !crate::modules::is_builtin_module(&ty) {
                missing.push(ty);
            }
            continue;
        }
        out.extend(found.into_iter().cloned());
    }
    if !missing.is_empty() {
        return Err(Error::Config(format!(
            "stack '{}' composes {} — neither published by project '{project}' nor pinned \
             in its fluxor.lock. Publish the project's modules (`fluxor publish fmod`) or pin \
             the module, then publish the stack",
            stack.name,
            missing.join(", ")
        )));
    }
    store_resolve::sort_entries(&mut out);
    Ok(out)
}

/// The entries a stack reference pins: the stack and every module
/// reference it carries, except the consumer's own modules (it builds those
/// itself). A module the consumer already pins for the same target keeps
/// the consumer's pin — it chose that module, and one image carries one
/// build of a type; each such case is returned as a note.
fn merge_stack_pins(
    entries: &mut Vec<Artifact>,
    stack: &Artifact,
    modules: &[Artifact],
    me: Option<&str>,
) -> Vec<String> {
    let mut notes = Vec::new();
    entries.retain(|e| !(e.kind == KIND && e.name == stack.name));
    entries.push(stack.clone());
    for m in modules {
        if Some(m.project.as_str()) == me {
            continue;
        }
        let held = entries
            .iter()
            .find(|e| e.kind == "module" && e.name == m.name && e.target == m.target);
        match held {
            Some(h) if h.digest == m.digest => {}
            Some(h) => notes.push(format!(
                "note: module {} ({}) stays at this project's pin {} ({}); stack '{}' \
                 was published against {}",
                m.name,
                m.target.as_deref().unwrap_or("any target"),
                h.reference,
                h.digest,
                stack.name,
                m.digest
            )),
            None => entries.push(m.clone()),
        }
    }
    notes
}

/// The lock entries one stack reference pins: the stack, and the module
/// references it carries.
pub fn derived_pins(
    store: &OciStore,
    stack: &Artifact,
    out: &mut Vec<Artifact>,
    me: Option<&str>,
) -> Result<()> {
    let pinned = read_pinned(store, stack)?;
    let doc = Stack::parse(&pinned.text).map_err(|e| {
        Error::Config(format!(
            "stack '{}' ({}) does not parse:\n{e}",
            stack.name, stack.digest
        ))
    })?;
    if doc.name != stack.name {
        return Err(Error::Config(format!(
            "'{}' ({}) holds stack '{}', not '{}'",
            stack.reference, stack.digest, doc.name, stack.name
        )));
    }
    let mut stack = stack.clone();
    let mut modules = pinned.modules;
    store_resolve::fill_content(store, std::slice::from_mut(&mut stack));
    store_resolve::fill_content(store, &mut modules);
    for note in merge_stack_pins(out, &stack, &modules, me) {
        eprintln!("{note}");
    }
    Ok(())
}

/// The reference a stack publishes under: `stack/<name>:<version>`,
/// or `tag` when one is given. A given tag names the same stack —
/// `stack/<name>:<t>` with `t` a version — because the tag is how a
/// consumer pins, includes and advances it: a stack published under
/// another name, or outside `stack/`, could be pinned but never
/// advanced, and `latest` is the tag every publish moves.
pub fn publish_ref(stack: &Stack, tag: Option<&str>) -> Result<String> {
    let body = format!("{TAG_PREFIX}{}", stack.name);
    let Some(tag) = tag else {
        let version = stack.version.as_deref().ok_or_else(|| {
            Error::Config(format!("stack '{}' declares no `version:`", stack.name))
        })?;
        return Ok(format!("{body}:{version}"));
    };
    match tag.split_once(':') {
        Some((b, t)) if b == body && is_version(t) => Ok(tag.to_string()),
        _ => Err(Error::Config(format!(
            "--tag '{tag}' must be `{body}:<version>`: a stack is tagged under its own \
             name, and the version is a store tag other than `{LATEST}`"
        ))),
    }
}

/// The document a stack publish stages, checked: it parses, names a
/// version, and renders with its defaults and examples.
pub fn read_for_publish(path: &Path) -> Result<(Stack, Vec<u8>)> {
    let bytes = std::fs::read(path)
        .map_err(|e| Error::Config(format!("read stack {}: {e}", path.display())))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|e| Error::Config(format!("{}: not UTF-8: {e}", path.display())))?;
    let stack =
        Stack::parse(text).map_err(|e| Error::Config(format!("{}:\n{e}", path.display())))?;
    if stack.version.is_none() {
        return Err(Error::Config(format!(
            "{}: a published stack declares `version:`",
            path.display()
        )));
    }
    let dir = path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    stack.check_render(&dir).map_err(|e| {
        Error::Config(format!(
            "{} rendered with defaults and examples: {e}",
            path.display()
        ))
    })?;
    Ok((stack, bytes))
}

/// What a publish sweep checks of a stack before it writes anything: the
/// document, as [`read_for_publish`] checks it, and that every module type
/// it composes will have a reference to record — a kernel built-in, a
/// module of the publishing project (which the same sweep publishes first),
/// or a module its `fluxor.lock` pins. Returns the reference the stack
/// publishes under.
pub fn check_publishable(path: &Path, project_root: &Path) -> Result<String> {
    let (stack, _) = read_for_publish(path)?;
    let at = crate::packaging::stack_path(project_root, &stack.name);
    if std::path::absolute(path).ok() != std::path::absolute(&at).ok() {
        return Err(Error::Config(format!(
            "{}: stack '{}' publishes from {} — a project's published stacks are \
             `packaging/stack/<name>.yaml`, named for the stack",
            path.display(),
            stack.name,
            at.display()
        )));
    }
    let own: BTreeSet<String> = crate::modules_build::list(project_root)?
        .into_iter()
        .map(|m| m.name)
        .collect();
    let pinned: BTreeSet<String> = store_resolve::read_store_lock(project_root)?
        .map(|l| l.artifacts)
        .unwrap_or_default()
        .into_iter()
        .filter(|a| a.kind == "module")
        .map(|a| a.name)
        .collect();
    let missing: Vec<String> = stack
        .module_types()
        .into_iter()
        .filter(|t| !own.contains(t) && !pinned.contains(t))
        .filter(|t| !crate::modules::is_builtin_module(t))
        .collect();
    if !missing.is_empty() {
        return Err(Error::Config(format!(
            "{}: stack '{}' composes {} — neither a module of this project, nor a kernel \
             built-in, nor pinned from a dependency in its fluxor.lock, so the stack would name \
             a module no consumer could find. Declare the dependency that publishes it and run \
             `fluxor update`, then publish",
            path.display(),
            stack.name,
            missing.join(", ")
        )));
    }
    publish_ref(&stack, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A two-module stack with every param kind the checks exercise.
    const VOLUME: &str = r#"
stack: volume
version: 0.1.0
params:
  image:
    type: string
    required: true
    example: v.img
  block_size:
    type: integer
    default: 512
    min: 512
    max: 4096
  verbose:
    type: boolean
    default: false
exports:
  blocks: seal.blocks
  status: seal.status
  lower: [disk.blocks, seal.lower]
modules:
  - name: disk
    type: file_block
    path: ${param:image}
    block_size: ${param:block_size}
  - name: seal
    type: crypt_block
    label: "vol-${param:block_size}"
    trace: ${param:verbose}
wiring:
  - from: disk.blocks
    to: seal.lower
    buffer_bytes: 4096
"#;

    struct Sandbox {
        dir: tempfile::TempDir,
    }

    impl Sandbox {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            std::fs::write(dir.path().join("volume.yaml"), VOLUME).unwrap();
            Sandbox { dir }
        }
        fn path(&self) -> &Path {
            self.dir.path()
        }
        fn expand(&self, mut graph: Value) -> std::result::Result<Value, String> {
            self.expand_with_store(&mut graph, None)?;
            Ok(graph)
        }
        fn expand_with_store(
            &self,
            graph: &mut Value,
            store: Option<&Path>,
        ) -> std::result::Result<(), String> {
            self.expand_forwarding(graph, store, &BTreeMap::new())
        }
        fn expand_forwarding(
            &self,
            graph: &mut Value,
            store: Option<&Path>,
            params: &BTreeMap<String, ParamSpec>,
        ) -> std::result::Result<(), String> {
            expand_includes(
                graph,
                &IncludeContext {
                    graph_dir: self.path(),
                    project_root: self.path(),
                    store_root: store,
                    params,
                },
            )
        }
    }

    /// Pin `artifact` as `fluxor update` pins a referenced stack: the stack
    /// and the module references it carries.
    fn pin(root: &Path, store: &OciStore, artifact: &Artifact) -> Result<()> {
        let mut entries = store_resolve::read_store_lock(root)?
            .map(|l| l.artifacts)
            .unwrap_or_default();
        derived_pins(store, artifact, &mut entries, None)?;
        store_resolve::write_store_lock(root, &entries)?;
        Ok(())
    }

    fn module<'a>(g: &'a Value, name: &str) -> &'a Value {
        g["modules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["name"] == name)
            .unwrap_or_else(|| panic!("no module {name} in {g:#}"))
    }

    fn edges(g: &Value) -> Vec<(String, String)> {
        g["wiring"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| {
                (
                    w["from"].as_str().unwrap().to_string(),
                    w["to"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }

    fn one_volume(params: Value) -> Value {
        json!({
            "target": "linux",
            "include": [{"stack": "volume.yaml", "as": "data", "params": params}],
            "modules": [{"name": "fs", "type": "fat32"}],
            "wiring": [{"from": "data.blocks", "to": "fs.blocks"}],
        })
    }

    // ── params ──────────────────────────────────────────────────────────

    #[test]
    fn defaults_fill_what_the_include_omits_and_values_stay_typed() {
        let sb = Sandbox::new();
        let g = sb.expand(one_volume(json!({"image": "d.img"}))).unwrap();
        let disk = module(&g, "data_disk");
        assert_eq!(disk["path"], "d.img");
        assert_eq!(
            disk["block_size"], 512,
            "a whole-value placeholder keeps its type"
        );
        let seal = module(&g, "data_seal");
        assert_eq!(
            seal["label"], "vol-512",
            "an embedded placeholder interpolates"
        );
        assert_eq!(seal["trace"], false);
        assert!(g.get("include").is_none(), "the include key is consumed");
    }

    #[test]
    fn a_supplied_value_overrides_the_default() {
        let sb = Sandbox::new();
        let g = sb
            .expand(one_volume(
                json!({"image": "d.img", "block_size": 4096, "verbose": true}),
            ))
            .unwrap();
        assert_eq!(module(&g, "data_disk")["block_size"], 4096);
        assert_eq!(module(&g, "data_seal")["trace"], true);
    }

    #[test]
    fn a_missing_required_param_is_refused() {
        let sb = Sandbox::new();
        let e = sb.expand(one_volume(json!({}))).unwrap_err();
        assert!(e.contains("missing required param 'image'"), "{e}");
    }

    #[test]
    fn bounds_are_enforced() {
        let sb = Sandbox::new();
        let e = sb
            .expand(one_volume(json!({"image": "d.img", "block_size": 8192})))
            .unwrap_err();
        assert!(e.contains("above its maximum 4096"), "{e}");
        let e = sb
            .expand(one_volume(json!({"image": "d.img", "block_size": 128})))
            .unwrap_err();
        assert!(e.contains("below its minimum 512"), "{e}");
    }

    #[test]
    fn type_errors_and_unknown_params_are_refused_together() {
        let sb = Sandbox::new();
        let e = sb
            .expand(one_volume(json!({
                "image": 7,
                "block_size": "big",
                "verbose": 1.5,
                "colour": "red",
            })))
            .unwrap_err();
        assert!(
            e.contains("param 'image' must be a string, got an integer"),
            "{e}"
        );
        assert!(
            e.contains("param 'block_size' must be an integer, got a string"),
            "{e}"
        );
        assert!(
            e.contains("param 'verbose' is a boolean, got a float"),
            "{e}"
        );
        assert!(e.contains("unknown param 'colour'"), "{e}");
        assert!(
            !e.contains("missing required param 'image'"),
            "a value given with the wrong type is not also missing: {e}"
        );
    }

    #[test]
    fn a_file_param_resolves_against_the_graph_and_must_exist() {
        let sb = Sandbox::new();
        std::fs::write(
            sb.path().join("certstack.yaml"),
            "stack: certstack\nparams:\n  ca:\n    type: file\n    required: true\n    \
             example: ca.der\nmodules:\n  - name: tls\n    trust: ${param:ca}\n",
        )
        .unwrap();
        let graph = |ca: &str| json!({"include": [{"stack": "certstack.yaml", "as": "peer", "params": {"ca": ca}}]});
        let e = sb.expand(graph("ca.der")).unwrap_err();
        assert!(e.contains("param 'ca'"), "{e}");
        std::fs::write(sb.path().join("ca.der"), b"der").unwrap();
        let g = sb.expand(graph("ca.der")).unwrap();
        let trust = module(&g, "peer_tls")["trust"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            Path::new(&trust).is_absolute() && trust.ends_with("ca.der"),
            "{trust}"
        );
    }

    // ── exports, prefixing, instances ──────────────────────────────────

    #[test]
    fn modules_are_prefixed_typed_and_internal_wiring_follows_them() {
        let sb = Sandbox::new();
        let g = sb.expand(one_volume(json!({"image": "d.img"}))).unwrap();
        assert_eq!(module(&g, "data_disk")["type"], "file_block");
        let names: Vec<&str> = g["modules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["fs", "data_disk", "data_seal"]);
        assert_eq!(
            edges(&g),
            [
                ("data_seal.blocks".to_string(), "fs.blocks".to_string()),
                (
                    "data_disk.blocks".to_string(),
                    "data_seal.lower".to_string()
                ),
            ]
        );
        assert_eq!(g["wiring"][1]["buffer_bytes"], 4096, "edge fields survive");
    }

    #[test]
    fn an_untyped_module_keeps_its_name_as_its_type() {
        let sb = Sandbox::new();
        std::fs::write(
            sb.path().join("bare.yaml"),
            "stack: bare\nmodules: [debug]\nexports:\n  data: debug.data\n",
        )
        .unwrap();
        let g = sb
            .expand(json!({"include": [{"stack": "bare.yaml", "as": "tap"}]}))
            .unwrap();
        assert_eq!(module(&g, "tap_debug")["type"], "debug");
    }

    #[test]
    fn wiring_to_a_port_the_stack_does_not_export_is_refused() {
        let sb = Sandbox::new();
        let mut graph = one_volume(json!({"image": "d.img"}));
        graph["wiring"] = json!([{"from": "fs.out", "to": "data.bundle"}]);
        let e = sb.expand(graph).unwrap_err();
        assert!(
            e.contains(
                "'bundle' is not an export of include 'data' (exports: blocks, lower, status)"
            ),
            "{e}"
        );
    }

    #[test]
    fn wiring_to_a_stack_internal_module_is_refused() {
        let sb = Sandbox::new();
        let mut graph = one_volume(json!({"image": "d.img"}));
        graph["wiring"] = json!([{"from": "data_disk.blocks", "to": "fs.blocks"}]);
        let e = sb.expand(graph).unwrap_err();
        assert!(
            e.contains("'data_disk' is internal to include 'data'"),
            "{e}"
        );
    }

    #[test]
    fn a_fanned_export_draws_one_edge_per_internal_endpoint() {
        let sb = Sandbox::new();
        let mut graph = one_volume(json!({"image": "d.img"}));
        graph["wiring"] = json!([{"from": "fs.out", "to": "data.lower", "rate": "bulk"}]);
        let g = sb.expand(graph).unwrap();
        let e = edges(&g);
        assert!(
            e.contains(&("fs.out".into(), "data_disk.blocks".into())),
            "{e:?}"
        );
        assert!(
            e.contains(&("fs.out".into(), "data_seal.lower".into())),
            "{e:?}"
        );
        assert_eq!(g["wiring"][1]["rate"], "bulk");
    }

    #[test]
    fn two_instances_of_one_stack_never_collide() {
        let sb = Sandbox::new();
        let g = sb
            .expand(json!({
                "include": [
                    {"stack": "volume.yaml", "as": "data", "params": {"image": "a.img"}},
                    {"stack": "volume.yaml", "as": "scratch",
                     "params": {"image": "b.img", "block_size": 4096}},
                ],
                "modules": [{"name": "log", "type": "debug"}],
                "wiring": [
                    {"from": "data.status", "to": "log.data"},
                    {"from": "scratch.status", "to": "log.data"},
                ],
            }))
            .unwrap();
        assert_eq!(module(&g, "data_disk")["path"], "a.img");
        assert_eq!(module(&g, "scratch_disk")["path"], "b.img");
        assert_eq!(module(&g, "scratch_disk")["block_size"], 4096);
        let e = edges(&g);
        assert!(e.contains(&("data_seal.status".into(), "log.data".into())));
        assert!(e.contains(&("scratch_seal.status".into(), "log.data".into())));
        assert!(e.contains(&("scratch_disk.blocks".into(), "scratch_seal.lower".into())));
    }

    /// A stack whose two internal edges hold three groups between them:
    /// one edge alone in 26, a chain of two in 30.
    const GROUPED: &str = r#"
stack: grouped
modules:
  - name: a
    type: file_block
    path: a.img
  - name: b
    type: crypt_block
  - name: c
    type: crypt_block
exports:
  out: c.blocks
wiring:
  - { from: a.blocks, to: b.lower, buffer_group: 26 }
  - { from: b.blocks, to: c.lower, buffer_group: 30 }
  - { from: b.status, to: c.lower, buffer_group: 30 }
  - { from: a.blocks, to: c.lower }
"#;

    fn groups_of(g: &Value, prefix: &str) -> Vec<Option<u64>> {
        g["wiring"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|w| w["from"].as_str().unwrap().starts_with(prefix) && w["to"] != "fs.blocks")
            .map(|w| w.get("buffer_group").and_then(Value::as_u64))
            .collect()
    }

    #[test]
    fn a_single_include_keeps_its_free_groups() {
        let sb = Sandbox::new();
        std::fs::write(sb.path().join("grouped.yaml"), GROUPED).unwrap();
        let g = sb
            .expand(json!({
                "include": [{"stack": "grouped.yaml", "as": "x"}],
                "wiring": [],
            }))
            .unwrap();
        assert_eq!(
            groups_of(&g, "x_"),
            vec![Some(26), Some(30), Some(30), None]
        );
    }

    #[test]
    fn two_includes_of_one_stack_get_distinct_groups() {
        let sb = Sandbox::new();
        std::fs::write(sb.path().join("grouped.yaml"), GROUPED).unwrap();
        let g = sb
            .expand(json!({
                "include": [
                    {"stack": "grouped.yaml", "as": "x"},
                    {"stack": "grouped.yaml", "as": "y"},
                ],
                "modules": [{"name": "fs", "type": "fat32"}],
                // The graph's own group 31, and 30 written by hand.
                "wiring": [
                    {"from": "x.out", "to": "fs.blocks", "buffer_group": 31},
                    {"from": "y.out", "to": "fs.blocks", "buffer_group": 29},
                ],
            }))
            .unwrap();
        let x = groups_of(&g, "x_");
        let y = groups_of(&g, "y_");
        // The graph holds 29 and 31; x keeps 26 and 30, which are free; y
        // finds both held and takes the highest two still free. A chain
        // stays a chain; an ungrouped edge stays ungrouped.
        assert_eq!(x, vec![Some(26), Some(30), Some(30), None]);
        assert_eq!(y, vec![Some(27), Some(28), Some(28), None]);
        // The graph's own groups are its own.
        let own: Vec<Option<u64>> = g["wiring"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|w| w["to"] == "fs.blocks")
            .map(|w| w["buffer_group"].as_u64())
            .collect();
        assert_eq!(own, vec![Some(31), Some(29)]);
    }

    #[test]
    fn running_out_of_groups_is_refused() {
        let sb = Sandbox::new();
        std::fs::write(sb.path().join("grouped.yaml"), GROUPED).unwrap();
        // The graph holds 1..=30: one group free, and the stack needs two.
        let own: Vec<Value> = (1..=30)
            .map(|n| json!({"from": format!("m{n}.out"), "to": "fs.blocks", "buffer_group": n}))
            .collect();
        let e = sb
            .expand(json!({
                "include": [{"stack": "grouped.yaml", "as": "x"}],
                "wiring": own,
            }))
            .unwrap_err();
        assert!(
            e.contains("include 'x'")
                && e.contains("names 2 buffer groups (26, 30)")
                && e.contains("only 1 of the graph's 31 are free"),
            "{e}"
        );
        // A group outside the 5-bit field is refused, not clamped.
        std::fs::write(
            sb.path().join("wide.yaml"),
            GROUPED.replace("buffer_group: 26", "buffer_group: 40"),
        )
        .unwrap();
        let e = sb
            .expand(json!({"include": [{"stack": "wide.yaml", "as": "w"}]}))
            .unwrap_err();
        assert!(
            e.contains("buffer_group must be an integer 0 to 31, got 40"),
            "{e}"
        );
    }

    #[test]
    fn instance_names_and_module_names_are_checked_for_collisions() {
        let sb = Sandbox::new();
        let twice = json!({"include": [
            {"stack": "volume.yaml", "as": "data", "params": {"image": "a"}},
            {"stack": "volume.yaml", "as": "data", "params": {"image": "b"}},
        ]});
        let e = sb.expand(twice).unwrap_err();
        assert!(e.contains("used by an earlier include"), "{e}");

        let clash = json!({
            "include": [{"stack": "volume.yaml", "as": "data", "params": {"image": "a"}}],
            "modules": [{"name": "data_disk", "type": "debug"}],
        });
        let e = sb.expand(clash).unwrap_err();
        assert!(
            e.contains("becomes 'data_disk', which the graph already names"),
            "{e}"
        );

        let alias_is_module = json!({
            "include": [{"stack": "volume.yaml", "as": "fs", "params": {"image": "a"}}],
            "modules": [{"name": "fs", "type": "fat32"}],
        });
        let e = sb.expand(alias_is_module).unwrap_err();
        assert!(e.contains("is also a module name"), "{e}");
    }

    #[test]
    fn expansion_is_deterministic() {
        let sb = Sandbox::new();
        let graph = json!({
            "include": [
                {"stack": "volume.yaml", "as": "b", "params": {"image": "b.img"}},
                {"stack": "volume.yaml", "as": "a", "params": {"image": "a.img"}},
            ],
            "wiring": [{"from": "a.status", "to": "b.lower"}],
        });
        let one = serde_json::to_string(&sb.expand(graph.clone()).unwrap()).unwrap();
        let two = serde_json::to_string(&sb.expand(graph).unwrap()).unwrap();
        assert_eq!(one, two);
    }

    #[test]
    fn a_graph_without_includes_is_untouched() {
        let sb = Sandbox::new();
        let graph = json!({"modules": [{"name": "x"}], "wiring": []});
        assert_eq!(sb.expand(graph.clone()).unwrap(), graph);
    }

    // ── forwarding the includer's params ───────────────────────────────

    fn declared(yaml: &str) -> BTreeMap<String, ParamSpec> {
        params::parse_params(&serde_yaml::from_str(yaml).unwrap()).unwrap()
    }

    #[test]
    fn a_param_forwards_into_an_include_of_the_same_type() {
        let sb = Sandbox::new();
        let own = declared(
            "img: {type: string, required: true, example: x.img}\n\
             size: {type: integer, default: 1024, min: 512, max: 4096}\n",
        );
        let mut g = one_volume(json!({"image": "${param:img}", "block_size": "${param:size}"}));
        sb.expand_forwarding(&mut g, None, &own).unwrap();
        // The placeholders ride into the stack's modules, an integer in an
        // integer's place and inside the stack's own text, for the graph's
        // values to render.
        let disk = module(&g, "data_disk");
        assert_eq!(disk["path"], "${param:img}");
        assert_eq!(disk["block_size"], "${param:size}");
        assert_eq!(module(&g, "data_seal")["label"], "vol-${param:size}");
        let values: BTreeMap<String, ParamValue> = [
            ("img".to_string(), ParamValue::String("d.img".into())),
            ("size".to_string(), ParamValue::Integer(2048)),
        ]
        .into();
        let rendered = params::render(&serde_yaml::to_value(&g).unwrap(), &values).unwrap();
        let disk = &rendered["modules"][1];
        assert_eq!(disk["block_size"], serde_yaml::Value::Number(2048.into()));
        assert_eq!(disk["path"].as_str(), Some("d.img"));
    }

    #[test]
    fn a_forward_of_another_type_or_wider_bounds_is_refused() {
        let sb = Sandbox::new();
        let own = declared(
            "name: {type: string, default: a}\n\
             wide: {type: integer, default: 1024}\n\
             img: {type: string, default: x.img}\n",
        );
        let e = sb
            .expand_forwarding(
                &mut one_volume(json!({"image": "${param:img}", "block_size": "${param:name}"})),
                None,
                &own,
            )
            .unwrap_err();
        assert!(
            e.contains("param 'block_size' is an integer, and the graph forwards a param declared a string"),
            "{e}"
        );
        let e = sb
            .expand_forwarding(
                &mut one_volume(json!({"image": "${param:img}", "block_size": "${param:wide}"})),
                None,
                &own,
            )
            .unwrap_err();
        assert!(e.contains("within the stack's bounds"), "{e}");
        let e = sb
            .expand_forwarding(
                &mut one_volume(json!({"image": "${param:ghost}"})),
                None,
                &own,
            )
            .unwrap_err();
        assert!(e.contains("does not declare"), "{e}");
        let e = sb
            .expand_forwarding(
                &mut one_volume(json!({"image": "${param:img}", "block_size": "1${param:wide}"})),
                None,
                &own,
            )
            .unwrap_err();
        assert!(
            e.contains("text around a placeholder makes a string"),
            "{e}"
        );
        // Text around a string placeholder is a string value.
        let mut g = one_volume(json!({"image": "/srv/${param:img}"}));
        sb.expand_forwarding(&mut g, None, &own).unwrap();
        assert_eq!(module(&g, "data_disk")["path"], "/srv/${param:img}");
    }

    #[test]
    fn a_graph_read_renders_its_params_through_its_includes() {
        let sb = Sandbox::new();
        let graph = sb.path().join("g.yaml");
        std::fs::write(
            &graph,
            "target: linux\nparams:\n  size: {type: integer, default: 1024, min: 512, max: \
             2048}\ninclude:\n  - stack: volume.yaml\n    as: data\n    params:\n      image: \
             d.img\n      block_size: ${param:size}\nmodules: []\n",
        )
        .unwrap();
        let (doc, declared) = read_expanded(&graph, sb.path(), None).unwrap();
        assert_eq!(declared["size"].ty, ParamType::Integer);
        assert!(doc.get("params").is_none() && doc.get(INCLUDE_KEY).is_none());
        // Unset, a process renders with the given values: here, none, so
        // the default.
        let g = load_graph(&graph, sb.path()).unwrap();
        assert_eq!(module(&g, "data_disk")["block_size"], 1024);
    }

    // ── placement ──────────────────────────────────────────────────────

    #[test]
    fn a_placed_include_declares_its_members_on_that_node() {
        let sb = Sandbox::new();
        let g = sb
            .expand(json!({
                "include": [{"stack": "volume.yaml", "as": "data", "node": "storage-1",
                             "params": {"image": "d.img"}}],
                "modules": [{"name": "fs", "type": "fat32"}],
                "wiring": [],
            }))
            .unwrap();
        for name in ["data_disk", "data_seal"] {
            let m = module(&g, name).as_object().unwrap();
            assert_eq!(m["node"], "storage-1");
            let keys: BTreeSet<&str> = m.keys().map(String::as_str).collect();
            assert!(
                keys.iter().all(|k| PLACED_KEYS.contains(k)),
                "a placed member carries identity and node only: {keys:?}"
            );
        }
        assert!(
            edges(&g).is_empty(),
            "a placed include's internal edges belong to the node that runs it"
        );
        // Params are still checked: the instance is the includer's either way.
        let e = sb
            .expand(json!({"include": [{"stack": "volume.yaml", "as": "data",
                                        "node": "storage-1"}]}))
            .unwrap_err();
        assert!(e.contains("missing required param 'image'"), "{e}");
    }

    #[test]
    fn a_placed_include_cannot_be_wired_locally() {
        let sb = Sandbox::new();
        let e = sb
            .expand(json!({
                "include": [{"stack": "volume.yaml", "as": "data", "node": "storage-1",
                             "params": {"image": "d.img"}}],
                "modules": [{"name": "fs", "type": "fat32"}],
                "wiring": [{"from": "data.blocks", "to": "fs.blocks"}],
            }))
            .unwrap_err();
        assert!(e.contains("is placed on node 'storage-1'"), "{e}");
    }

    // ── the document ────────────────────────────────────────────────────

    #[test]
    fn a_stack_carries_no_graph_wide_settings() {
        let e = Stack::parse("stack: s\ntarget: linux\nplatform: {net: {}}\nmodules: [a]\n")
            .unwrap_err();
        assert!(e.contains("unknown key `target`"), "{e}");
        assert!(e.contains("unknown key `platform`"), "{e}");
    }

    #[test]
    fn a_stack_never_reads_the_environment() {
        for text in [
            "stack: s\nmodules:\n  - name: m\n    path: \"${HOME}/v.img\"\n",
            "stack: s\nmodules: [a, b]\nwiring:\n  - from: a.out\n    to: b.in\n    \
             depth: \"${DEPTH:-4}\"\n",
        ] {
            let e = Stack::parse(text).unwrap_err();
            assert!(
                e.contains("reads the environment, and a stack is never substituted")
                    && e.contains("the including graph binds it"),
                "{text}: {e}"
            );
        }
        // A param placeholder and a file source spec are not environment
        // references.
        Stack::parse(
            "stack: s\nparams:\n  p: {type: string, default: a}\nmodules:\n  - name: m\n    \
             a: ${param:p}\n    trust: \"${file:ca.pem}\"\n",
        )
        .unwrap();
    }

    #[test]
    fn a_stack_owns_its_shape_and_wires_only_its_own_modules() {
        let e = Stack::parse(
            "stack: s\nparams:\n  t: {type: string, default: x}\n  unused: {type: integer, \
             default: 1}\nexports:\n  out: ghost.out\nmodules:\n  - name: a\n    type: \
             ${param:t}\n  - name: b\n    node: elsewhere\nwiring:\n  - from: linux_net.net_out\n    \
             to: a.in\n  - from: a.out\n    to: b.${param:t}\n  - from: a.x\n    to: b.y\n    \
             depth: ${param:nope}\n",
        )
        .unwrap_err();
        assert!(e.contains("module 'a': `type` is parameterised"), "{e}");
        assert!(e.contains("module 'b' carries `node:`"), "{e}");
        assert!(
            e.contains("names 'linux_net', which is not a module of this stack"),
            "{e}"
        );
        assert!(e.contains("'b.${param:t}' is parameterised"), "{e}");
        assert!(e.contains("export 'out' 'ghost.out' names 'ghost'"), "{e}");
        assert!(
            e.contains("the stack references `${param:nope}` but `params:` declares no 'nope'"),
            "{e}"
        );
        assert!(
            e.contains("param 'unused' is declared but the stack never references"),
            "{e}"
        );
    }

    #[test]
    fn a_stack_schema_is_held_to_the_bundle_rules() {
        let e = Stack::parse(
            "stack: s\nparams:\n  a: {type: integer, default: \"x\"}\n  b: {type: string, \
             required: true}\n  c: {type: string, min: 1, default: y}\nmodules:\n  - name: m\n    \
             p: ${param:a}\n    q: ${param:b}\n    r: ${param:c}\n",
        )
        .unwrap_err();
        assert!(e.contains("params.a.default must be an integer"), "{e}");
        let e = Stack::parse(
            "stack: s\nparams:\n  b: {type: string, required: true}\n  c: {type: string, \
             min: 1, default: y}\nmodules:\n  - name: m\n    q: ${param:b}\n    r: ${param:c}\n",
        )
        .unwrap_err();
        assert!(
            e.contains("param 'b' is required but declares no example"),
            "{e}"
        );
        assert!(e.contains("bounds apply to integers only"), "{e}");
    }

    #[test]
    fn a_version_is_a_store_tag() {
        for ok in ["0.1.0", "1", "v2_rc-1", "2026.10.21"] {
            assert!(is_version(ok), "{ok}");
        }
        for bad in [
            "",
            "latest",
            "1.0 beta",
            "1.0+build",
            "-1",
            ".1",
            "a/b",
            "1:2",
        ] {
            assert!(!is_version(bad), "{bad}");
        }
        assert!(!is_version(&"9".repeat(MAX_VERSION_BYTES + 1)));
        let e = Stack::parse("stack: s\nversion: latest\nmodules: [a]\n").unwrap_err();
        assert!(e.contains("`version: latest` is not a store tag"), "{e}");
        let e = Stack::parse("stack: s\nversion: 1.5\nmodules: [a]\n").unwrap_err();
        assert!(e.contains("quote a numeric version"), "{e}");
    }

    #[test]
    fn a_publish_is_tagged_under_the_stacks_own_name() {
        let s = Stack::parse(VOLUME).unwrap();
        assert_eq!(publish_ref(&s, None).unwrap(), "stack/volume:0.1.0");
        assert_eq!(
            publish_ref(&s, Some("stack/volume:0.1.0-rc1")).unwrap(),
            "stack/volume:0.1.0-rc1"
        );
        for bad in [
            "stack/other:1",
            "volume:1",
            "acme/volume:1",
            "stack/volume:latest",
            "stack/volume",
            "stack/volume:",
        ] {
            let e = publish_ref(&s, Some(bad)).unwrap_err().to_string();
            assert!(e.contains("must be `stack/volume:<version>`"), "{bad}: {e}");
        }
        let unversioned = Stack::parse("stack: s\nmodules: [a]\n").unwrap();
        assert!(publish_ref(&unversioned, None).is_err());
    }

    /// The stack `docs/architecture/stacks.md` shows is one the
    /// composer takes as written.
    #[test]
    fn the_documented_stack_parses_and_renders() {
        let doc = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/architecture/stacks.md"),
        )
        .unwrap();
        let block = doc
            .split("```yaml\n")
            .skip(1)
            .filter_map(|b| b.split_once("```").map(|(y, _)| y))
            .find(|y| y.starts_with("stack:"))
            .expect("the document shows a stack");
        let s = Stack::parse(block).unwrap();
        assert_eq!(s.name, "sealed_volume");
        s.check_render(Path::new(".")).unwrap();
        assert_eq!(
            s.exports.keys().map(String::as_str).collect::<Vec<_>>(),
            ["blocks", "status"]
        );
    }

    /// The include `docs/architecture/stacks.md` shows expands as the
    /// document describes: one instance by file path, one by name through
    /// the project's own `packaging/stack/`, each prefixed and wired through
    /// its exports.
    #[test]
    fn the_documented_include_expands() {
        let doc = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/architecture/stacks.md"),
        )
        .unwrap();
        let blocks: Vec<&str> = doc
            .split("```yaml\n")
            .skip(1)
            .filter_map(|b| b.split_once("```").map(|(y, _)| y))
            .collect();
        let stack = blocks
            .iter()
            .find(|y| y.starts_with("stack:"))
            .expect("the document shows a stack");
        let graph = blocks
            .iter()
            .find(|y| y.contains("\ninclude:"))
            .expect("the document shows an include");
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("sealed_volume.yaml"), stack).unwrap();
        let own = crate::packaging::stack_path(tmp.path(), "sealed_volume");
        std::fs::create_dir_all(own.parent().unwrap()).unwrap();
        std::fs::write(&own, stack).unwrap();

        let mut g: Value =
            serde_json::to_value(serde_yaml::from_str::<serde_yaml::Value>(graph).unwrap())
                .unwrap();
        expand_includes(
            &mut g,
            &IncludeContext {
                graph_dir: tmp.path(),
                project_root: tmp.path(),
                store_root: None,
                params: &BTreeMap::new(),
            },
        )
        .unwrap();
        let names: Vec<&str> = g["modules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "fs",
                "log",
                "data_disk",
                "data_seal",
                "scratch_disk",
                "scratch_seal"
            ]
        );
        assert_eq!(module(&g, "scratch_disk")["block_size"], 4096);
        assert_eq!(module(&g, "data_seal")["block_size"], 512);
        let e = edges(&g);
        for (from, to) in [
            ("data_seal.blocks", "fs.blocks"),
            ("data_seal.status", "log.data"),
            ("scratch_seal.status", "log.data"),
            ("data_disk.blocks", "data_seal.lower"),
            ("scratch_disk.blocks", "scratch_seal.lower"),
        ] {
            assert!(
                e.contains(&(from.into(), to.into())),
                "{from} -> {to}: {e:?}"
            );
        }
    }

    #[test]
    fn the_check_render_uses_defaults_and_examples() {
        let s = Stack::parse(VOLUME).unwrap();
        s.check_render(Path::new(".")).unwrap();
        assert_eq!(
            s.module_types().into_iter().collect::<Vec<_>>(),
            ["crypt_block", "file_block"]
        );
    }

    // ── store-pinned includes ──────────────────────────────────────────

    /// Publish `text` as stack `name` (with `modules` as its module
    /// references) from project `owner` into `store`.
    fn publish_stack(store: &OciStore, owner: &str, text: &str, modules: &[Artifact]) {
        let s = Stack::parse(text).unwrap();
        let ref_name = format!("{TAG_PREFIX}{}:{}", s.name, s.version.as_deref().unwrap());
        let modules_json = serde_json::to_vec(modules).unwrap();
        let meta = crate::oci_store::ArtifactMeta {
            project: owner,
            provenance: crate::oci_store::PROVENANCE_LOCAL,
            source_rev: None,
            abi_surface_hex: "00",
            input_digest_hex: None,
            ci_digest_hex: None,
        };
        let txn = store.begin_publish().unwrap();
        let prepared = vec![store
            .prepare_stack(
                &crate::oci_store::StackArtifact {
                    stack_yaml: text.as_bytes(),
                    modules_json: &modules_json,
                    ref_name: &ref_name,
                },
                &meta,
            )
            .unwrap()];
        let index = store.read_index().unwrap();
        let plan = store
            .plan_publish(&index, owner, "0.1.0", &prepared, None, &[])
            .unwrap();
        store.commit_plan(&txn, plan, prepared, None).unwrap();
    }

    fn module_ref(store: &OciStore, name: &str, project: &str) -> Artifact {
        let desc = crate::oci_store::publish_module(
            store,
            &crate::oci_store::ModulePublish {
                name,
                target: "aarch64",
                fmod_bytes: name.as_bytes(),
                manifest_toml: Some("version = \"1.0.0\"\n"),
                provenance: crate::oci_store::PROVENANCE_LOCAL,
                source_rev: None,
                ref_name: &format!("aarch64/{name}:0.1.0"),
            },
        )
        .unwrap();
        Artifact {
            kind: "module".into(),
            name: name.into(),
            project: project.into(),
            target: Some("aarch64".into()),
            digest: desc.digest,
            reference: format!("aarch64/{name}:0.1.0"),
            content: None,
        }
    }

    #[test]
    fn a_pinned_store_stack_is_included_by_name() {
        let sb = Sandbox::new();
        let store_root = sb.path().join("store");
        let store = OciStore::open(store_root.clone()).unwrap();
        let disk = module_ref(&store, "file_block", "storage");
        let seal = module_ref(&store, "crypt_block", "storage");
        publish_stack(&store, "storage", VOLUME, &[disk.clone(), seal.clone()]);

        // Unpinned: the include says how to pin it.
        let mut graph = json!({
            "include": [{"stack": "volume", "as": "data", "params": {"image": "d.img"}}],
            "modules": [{"name": "fs", "type": "fat32"}],
            "wiring": [{"from": "data.blocks", "to": "fs.blocks"}],
        });
        let e = sb
            .expand_with_store(&mut graph.clone(), Some(&store_root))
            .unwrap_err();
        assert!(e.contains("`fluxor update` pins every stack"), "{e}");

        // Pinned: the stack and its module references land in the lock.
        let desc = store.resolve("stack/volume:0.1.0").unwrap();
        let artifact = store_resolve::artifact_from_descriptor(&desc)
            .unwrap()
            .unwrap();
        assert_eq!(
            (artifact.kind.as_str(), artifact.name.as_str()),
            ("stack", "volume")
        );
        pin(sb.path(), &store, &artifact).unwrap();
        let lock = store_resolve::read_store_lock(sb.path()).unwrap().unwrap();
        for want in [&disk, &seal] {
            assert!(
                lock.artifacts
                    .iter()
                    .any(|a| a.kind == "module" && a.name == want.name && a.digest == want.digest),
                "module pin {} missing from {:?}",
                want.name,
                lock.artifacts
            );
        }
        sb.expand_with_store(&mut graph, Some(&store_root)).unwrap();
        assert_eq!(module(&graph, "data_disk")["path"], "d.img");
        assert!(edges(&graph).contains(&("data_seal.blocks".into(), "fs.blocks".into())));
    }

    #[test]
    fn a_stack_name_another_project_publishes_is_refused() {
        let sb = Sandbox::new();
        let store = OciStore::open(sb.path().join("store")).unwrap();
        publish_stack(&store, "storage", VOLUME, &[]);
        let meta = crate::oci_store::ArtifactMeta {
            project: "other",
            provenance: crate::oci_store::PROVENANCE_LOCAL,
            source_rev: None,
            abi_surface_hex: "00",
            input_digest_hex: None,
            ci_digest_hex: None,
        };
        let artifact = crate::oci_store::StackArtifact {
            stack_yaml: VOLUME.as_bytes(),
            modules_json: b"[]",
            ref_name: "stack/volume:0.2.0",
        };
        let e = store
            .prepare_stack(&artifact, &meta)
            .err()
            .expect("a second publisher is refused")
            .to_string();
        assert!(
            e.contains("stack 'volume' is already published by project 'storage'"),
            "{e}"
        );
        // The owner publishes its next version.
        let meta = crate::oci_store::ArtifactMeta {
            project: "storage",
            ..meta
        };
        store.prepare_stack(&artifact, &meta).unwrap();
    }

    #[test]
    fn a_pin_whose_document_names_another_stack_is_refused() {
        let sb = Sandbox::new();
        let store_root = sb.path().join("store");
        let store = OciStore::open(store_root.clone()).unwrap();
        publish_stack(&store, "storage", VOLUME, &[]);
        let desc = store.resolve("stack/volume:0.1.0").unwrap();
        let mut artifact = store_resolve::artifact_from_descriptor(&desc)
            .unwrap()
            .unwrap();
        artifact.name = "disk".into();
        let e = pin(sb.path(), &store, &artifact).unwrap_err().to_string();
        assert!(e.contains("holds stack 'volume', not 'disk'"), "{e}");
        assert!(
            store_resolve::read_store_lock(sb.path()).unwrap().is_none(),
            "nothing was pinned"
        );
    }

    #[test]
    fn a_store_stack_whose_module_pins_are_gone_is_refused() {
        let sb = Sandbox::new();
        let store_root = sb.path().join("store");
        let store = OciStore::open(store_root.clone()).unwrap();
        let disk = module_ref(&store, "file_block", "storage");
        publish_stack(&store, "storage", VOLUME, &[disk]);
        let desc = store.resolve("stack/volume:latest").unwrap();
        let artifact = store_resolve::artifact_from_descriptor(&desc)
            .unwrap()
            .unwrap();
        pin(sb.path(), &store, &artifact).unwrap();
        let mut lock = store_resolve::read_store_lock(sb.path()).unwrap().unwrap();
        lock.artifacts.retain(|a| a.kind != "module");
        store_resolve::write_store_lock(sb.path(), &lock.artifacts).unwrap();
        let mut graph = json!({
            "include": [{"stack": "volume", "as": "data", "params": {"image": "d.img"}}],
        });
        let e = sb
            .expand_with_store(&mut graph, Some(&store_root))
            .unwrap_err();
        assert!(
            e.contains("composes modules this project does not pin: file_block"),
            "{e}"
        );
    }

    #[test]
    fn a_consumer_keeps_its_own_module_pin() {
        let mut entries = vec![Artifact {
            kind: "module".into(),
            name: "tls".into(),
            project: "fluxor".into(),
            target: Some("aarch64".into()),
            digest: "sha256:mine".into(),
            reference: "aarch64/tls:0.0.2".into(),
            content: None,
        }];
        let stack = Artifact {
            kind: KIND.into(),
            name: "peer".into(),
            project: "control".into(),
            target: None,
            digest: "sha256:stack".into(),
            reference: "stack/peer:0.1.0".into(),
            content: None,
        };
        let theirs = Artifact {
            digest: "sha256:theirs".into(),
            ..entries[0].clone()
        };
        let own = Artifact {
            name: "router".into(),
            project: "me".into(),
            ..entries[0].clone()
        };
        let notes = merge_stack_pins(&mut entries, &stack, &[theirs, own], Some("me"));
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(
            notes[0].contains("stays at this project's pin"),
            "{notes:?}"
        );
        assert_eq!(
            entries.len(),
            2,
            "the consumer's own module is not pinned: {entries:?}"
        );
        assert!(entries.iter().any(|e| e.digest == "sha256:mine"));
        assert!(entries.iter().any(|e| e.kind == KIND));
    }
}
