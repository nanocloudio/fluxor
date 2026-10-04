//! Service-bundle parameters.
//!
//! A `role = "service"` workload publishes a graph TEMPLATE plus a typed
//! parameter schema (`[params.<name>]` in its source manifest, carried into
//! `workload.json`). The graph names a parameter as `${param:<name>}`; a
//! consumer supplies values at `fluxor run` time and never edits the graph.
//!
//! Substitution works on the PARSED graph, never on its text. A scalar that
//! is exactly one placeholder becomes a typed node (integer, boolean or
//! string); a string scalar with placeholders inside other text is
//! interpolated, and only string and integer parameters may appear there.
//! Text substitution is refused by construction because a value is data: a
//! value spliced into YAML text could open a mapping, close a quote or add a
//! module, and a parsed-tree substitution has no syntax for a value to reach.
//!
//! The environment pass ([`crate::env_subst`]) runs first, exactly as on
//! every graph read; it leaves `${param:...}` untouched because `param:<name>`
//! is not a POSIX variable name. The rendered graph is then escaped so the
//! environment pass the build runs on it again is an identity: a substituted
//! value is never read as an environment reference either.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Most parameters one service may declare. A service with more knobs than
/// this is configuring its internals through the run surface, which is what
/// the graph is for; the ceiling also bounds every per-run check below.
pub const MAX_PARAMS: usize = 64;

/// Longest string value, in bytes, a parameter accepts — from a default, an
/// example, `--param` or a `--params` file. Values are paths, hosts and
/// identifiers; a multi-kilobyte value is a file's contents, and a file is
/// passed by path, as a `file` parameter.
pub const MAX_PARAM_STRING_BYTES: usize = 4096;

/// Longest parameter name, in bytes.
pub const MAX_PARAM_NAME_BYTES: usize = 64;

/// The placeholder opener: `${param:<name>}`.
const PLACEHOLDER: &str = "${param:";

// ============================================================================
// Schema
// ============================================================================

/// A declared parameter's type.
///
/// A `file` is a path to a file the consumer supplies at run time — a CA
/// bundle, a certificate, a key — that the graph names where a module takes
/// a path (`cert_file: ${param:cert}`, `trust: "${file:${param:ca}}"`). Its
/// value renders as the file's absolute path, and a run is refused before
/// anything is built when the file is not there. It has no default: the
/// file is the consumer's, not the bundle's. Its example names a sample
/// relative to the source manifest, which the checks build with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParamType {
    String,
    Integer,
    Boolean,
    File,
}

impl ParamType {
    fn label(self) -> &'static str {
        match self {
            ParamType::String => "a string",
            ParamType::Integer => "an integer",
            ParamType::Boolean => "a boolean",
            ParamType::File => "a file path",
        }
    }
}

/// One parameter value, typed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ParamValue {
    Boolean(bool),
    Integer(i64),
    String(String),
}

impl ParamValue {
    pub fn ty(&self) -> ParamType {
        match self {
            ParamValue::Boolean(_) => ParamType::Boolean,
            ParamValue::Integer(_) => ParamType::Integer,
            ParamValue::String(_) => ParamType::String,
        }
    }

    /// Whether this value can be a `ty`: a file is carried as its path.
    fn is(&self, ty: ParamType) -> bool {
        self.ty() == ty || (ty == ParamType::File && self.ty() == ParamType::String)
    }

    fn to_yaml(&self) -> serde_yaml::Value {
        match self {
            ParamValue::Boolean(b) => serde_yaml::Value::Bool(*b),
            ParamValue::Integer(i) => serde_yaml::Value::Number((*i).into()),
            ParamValue::String(s) => serde_yaml::Value::String(s.clone()),
        }
    }
}

/// One declared parameter, as `workload.json` carries it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParamSpec {
    #[serde(rename = "type")]
    pub ty: ParamType,
    #[serde(default)]
    pub required: bool,
    /// The value an optional parameter takes when none is given. Required
    /// for an optional parameter, refused on a required one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<ParamValue>,
    /// Integer bounds, inclusive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// A representative value. Required for a required parameter: the ci
    /// gate renders the graph with defaults and examples and holds it to
    /// the build's own validation, so a required parameter without one would
    /// leave a graph nothing can check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<ParamValue>,
}

/// `[params.<name>]` as written in a source manifest. Values stay TOML until
/// they are checked against the declared type, so a wrong type is reported
/// as exactly that rather than as an untagged-enum mismatch.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParamSource {
    #[serde(rename = "type")]
    ty: ParamType,
    #[serde(default)]
    required: bool,
    default: Option<toml::Value>,
    min: Option<i64>,
    max: Option<i64>,
    description: Option<String>,
    example: Option<toml::Value>,
}

/// Is `name` a parameter name: `[a-z][a-z0-9_]*`, at most
/// [`MAX_PARAM_NAME_BYTES`].
pub fn is_param_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && name.len() <= MAX_PARAM_NAME_BYTES
        && bytes.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

fn toml_type_word(v: &toml::Value) -> &'static str {
    match v {
        toml::Value::String(_) => "a string",
        toml::Value::Integer(_) => "an integer",
        toml::Value::Float(_) => "a float",
        toml::Value::Boolean(_) => "a boolean",
        toml::Value::Datetime(_) => "a datetime",
        toml::Value::Array(_) => "an array",
        toml::Value::Table(_) => "a table",
    }
}

/// A TOML value as the declared type, or an error naming both.
fn typed_toml(what: &str, ty: ParamType, v: &toml::Value) -> Result<ParamValue, String> {
    match (ty, v) {
        (ParamType::String | ParamType::File, toml::Value::String(s)) => {
            Ok(ParamValue::String(s.clone()))
        }
        (ParamType::Integer, toml::Value::Integer(i)) => Ok(ParamValue::Integer(*i)),
        (ParamType::Boolean, toml::Value::Boolean(b)) => Ok(ParamValue::Boolean(*b)),
        _ => Err(format!(
            "{what} must be {}, got {}",
            ty.label(),
            toml_type_word(v)
        )),
    }
}

/// Parse a source manifest's `[params]` table. Shape errors (an unknown key,
/// an unknown type, a value of the wrong type) are reported here; the
/// cross-field rules are [`validate_schema`]'s.
pub fn parse_source_params(table: &toml::Table) -> Result<BTreeMap<String, ParamSpec>, String> {
    let mut out = BTreeMap::new();
    for (name, value) in table {
        let src: ParamSource = value
            .clone()
            .try_into()
            .map_err(|e| format!("[params.{name}]: {e}"))?;
        let typed = |field: &str, v: &Option<toml::Value>| -> Result<Option<ParamValue>, String> {
            v.as_ref()
                .map(|v| typed_toml(&format!("[params.{name}] {field}"), src.ty, v))
                .transpose()
        };
        out.insert(
            name.clone(),
            ParamSpec {
                ty: src.ty,
                required: src.required,
                default: typed("default", &src.default)?,
                min: src.min,
                max: src.max,
                description: src.description.clone(),
                example: typed("example", &src.example)?,
            },
        );
    }
    Ok(out)
}

/// A value against its parameter's declaration: type, integer bounds,
/// string length, and no NUL byte in a string.
fn check_value(name: &str, spec: &ParamSpec, v: &ParamValue) -> Result<(), String> {
    if !v.is(spec.ty) {
        return Err(format!(
            "param '{name}' is {}, got {}",
            spec.ty.label(),
            v.ty().label()
        ));
    }
    match v {
        ParamValue::Integer(i) => {
            if let Some(min) = spec.min.filter(|min| i < min) {
                return Err(format!("param '{name}' = {i} is below its minimum {min}"));
            }
            if let Some(max) = spec.max.filter(|max| i > max) {
                return Err(format!("param '{name}' = {i} is above its maximum {max}"));
            }
        }
        ParamValue::String(s) if s.contains('\0') => {
            return Err(format!("param '{name}' contains a NUL byte"));
        }
        ParamValue::String(s) if s.len() > MAX_PARAM_STRING_BYTES => {
            return Err(format!(
                "param '{name}' is {} bytes long; a parameter string holds at most \
                 {MAX_PARAM_STRING_BYTES} (MAX_PARAM_STRING_BYTES)",
                s.len()
            ));
        }
        _ => {}
    }
    Ok(())
}

/// The schema's own rules. Returns every violation, each naming its param.
pub fn validate_schema(params: &BTreeMap<String, ParamSpec>) -> Vec<String> {
    let mut errors = Vec::new();
    if params.len() > MAX_PARAMS {
        errors.push(format!(
            "{} params declared; a service declares at most {MAX_PARAMS} (MAX_PARAMS)",
            params.len()
        ));
    }
    for (name, spec) in params {
        if !is_param_name(name) {
            errors.push(format!(
                "param name '{name}' is not [a-z][a-z0-9_]* of at most {MAX_PARAM_NAME_BYTES} bytes"
            ));
        }
        if spec.required && spec.default.is_some() {
            errors.push(format!(
                "param '{name}' is required and also declares a default; a required value has none"
            ));
        }
        if !spec.required && spec.default.is_none() {
            errors.push(format!(
                "param '{name}' is optional but declares no default; an omitted value must still render"
            ));
        }
        if spec.ty == ParamType::File && spec.default.is_some() {
            errors.push(format!(
                "param '{name}' is a file and declares a default; the file is the consumer's — \
                 declare it required, with an example"
            ));
        }
        if spec.required && spec.example.is_none() {
            errors.push(format!(
                "param '{name}' is required but declares no example; the ci gate renders the graph \
                 with one"
            ));
        }
        if spec.ty != ParamType::Integer && (spec.min.is_some() || spec.max.is_some()) {
            errors.push(format!(
                "param '{name}' declares min/max but is {}; bounds apply to integers only",
                spec.ty.label()
            ));
        }
        if let (Some(min), Some(max)) = (spec.min, spec.max) {
            if min > max {
                errors.push(format!("param '{name}' has min {min} above max {max}"));
            }
        }
        for (field, v) in [("default", &spec.default), ("example", &spec.example)] {
            if let Some(v) = v {
                if let Err(e) = check_value(name, spec, v) {
                    errors.push(format!("{field}: {e}"));
                }
            }
        }
    }
    errors
}

/// The value every parameter takes when the graph is checked without a
/// consumer: its default, else its example. A file example names a sample
/// relative to `source_dir`, the source manifest's directory, and is
/// refused when the sample is not there.
pub fn check_values(
    params: &BTreeMap<String, ParamSpec>,
    source_dir: &Path,
) -> Result<BTreeMap<String, ParamValue>, String> {
    let mut out = BTreeMap::new();
    let mut errors = Vec::new();
    for (name, spec) in params {
        let Some(v) = spec.default.clone().or_else(|| spec.example.clone()) else {
            continue;
        };
        let v = match (spec.ty, v) {
            (ParamType::File, ParamValue::String(p)) => {
                match existing_file(name, &source_dir.join(&p)) {
                    Ok(abs) => ParamValue::String(abs),
                    Err(e) => {
                        errors.push(format!("example: {e}"));
                        continue;
                    }
                }
            }
            (_, v) => v,
        };
        out.insert(name.clone(), v);
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors.join("; "))
    }
}

/// `path` as an absolute path to a file that can be read, or an error
/// naming parameter `name`.
fn existing_file(name: &str, path: &Path) -> Result<String, String> {
    let abs = std::path::absolute(path)
        .map_err(|e| format!("param '{name}': {}: {e}", path.display()))?;
    std::fs::File::open(&abs)
        .and_then(|f| f.metadata())
        .map_err(|e| format!("param '{name}': {}: {e}", abs.display()))
        .and_then(|m| {
            if m.is_file() {
                Ok(())
            } else {
                Err(format!("param '{name}': {} is not a file", abs.display()))
            }
        })?;
    abs.into_os_string()
        .into_string()
        .map_err(|_| format!("param '{name}': {} is not UTF-8", path.display()))
}

// ============================================================================
// Placeholders
// ============================================================================

enum Piece<'a> {
    Text(&'a str),
    Param(&'a str),
}

/// Split a string scalar into literal text and `${param:<name>}` pieces.
fn split(s: &str) -> Result<Vec<Piece<'_>>, String> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(pos) = rest.find(PLACEHOLDER) {
        if pos > 0 {
            out.push(Piece::Text(&rest[..pos]));
        }
        let after = &rest[pos + PLACEHOLDER.len()..];
        let end = after
            .find('}')
            .ok_or_else(|| format!("unclosed `{PLACEHOLDER}` in {s:?}"))?;
        let name = &after[..end];
        if !is_param_name(name) {
            return Err(format!(
                "`{PLACEHOLDER}{name}}}` in {s:?}: '{name}' is not a parameter name \
                 ([a-z][a-z0-9_]*)"
            ));
        }
        out.push(Piece::Param(name));
        rest = &after[end + 1..];
    }
    if !rest.is_empty() {
        out.push(Piece::Text(rest));
    }
    Ok(out)
}

/// Every parameter a parsed graph references. A placeholder in a mapping
/// KEY is refused: only values are parameterised, so the graph's shape is
/// the publisher's alone.
pub fn placeholders(doc: &serde_yaml::Value) -> Result<BTreeSet<String>, String> {
    fn walk(v: &serde_yaml::Value, out: &mut BTreeSet<String>) -> Result<(), String> {
        match v {
            serde_yaml::Value::String(s) => {
                for p in split(s)? {
                    if let Piece::Param(n) = p {
                        out.insert(n.to_string());
                    }
                }
            }
            serde_yaml::Value::Sequence(seq) => {
                for item in seq {
                    walk(item, out)?;
                }
            }
            serde_yaml::Value::Mapping(map) => {
                for (k, item) in map {
                    if let Some(key) = k.as_str().filter(|key| key.contains(PLACEHOLDER)) {
                        return Err(format!(
                            "placeholder in mapping key {key:?}: only values may be parameterised"
                        ));
                    }
                    walk(item, out)?;
                }
            }
            serde_yaml::Value::Tagged(t) => walk(&t.value, out)?,
            _ => {}
        }
        Ok(())
    }
    let mut out = BTreeSet::new();
    walk(doc, &mut out)?;
    Ok(out)
}

/// Every placeholder declared, every declared param referenced.
pub fn check_references(
    params: &BTreeMap<String, ParamSpec>,
    used: &BTreeSet<String>,
) -> Vec<String> {
    let mut errors = Vec::new();
    let declared: Vec<&str> = params.keys().map(String::as_str).collect();
    for name in used {
        if !params.contains_key(name) {
            errors.push(format!(
                "the graph references `{PLACEHOLDER}{name}}}` but no [params.{name}] is declared \
                 (declared: {})",
                if declared.is_empty() {
                    "none".to_string()
                } else {
                    declared.join(", ")
                }
            ));
        }
    }
    for name in params.keys() {
        if !used.contains(name) {
            errors.push(format!(
                "param '{name}' is declared but no graph references `{PLACEHOLDER}{name}}}`"
            ));
        }
    }
    errors
}

/// Substitute `values` into a parsed graph.
pub fn render(
    doc: &serde_yaml::Value,
    values: &BTreeMap<String, ParamValue>,
) -> Result<serde_yaml::Value, String> {
    let value_of = |name: &str| {
        values
            .get(name)
            .ok_or_else(|| format!("no value for `{PLACEHOLDER}{name}}}`"))
    };
    Ok(match doc {
        serde_yaml::Value::String(s) => {
            let pieces = split(s)?;
            match pieces.as_slice() {
                [Piece::Param(name)] => value_of(name)?.to_yaml(),
                _ if pieces.iter().any(|p| matches!(p, Piece::Param(_))) => {
                    let mut text = String::with_capacity(s.len());
                    for p in &pieces {
                        match p {
                            Piece::Text(t) => text.push_str(t),
                            Piece::Param(name) => match value_of(name)? {
                                ParamValue::String(v) => text.push_str(v),
                                ParamValue::Integer(i) => text.push_str(&i.to_string()),
                                ParamValue::Boolean(_) => {
                                    return Err(format!(
                                        "`{PLACEHOLDER}{name}}}` is a boolean inside other text in \
                                         {s:?}; a boolean may only stand alone as a whole value"
                                    ));
                                }
                            },
                        }
                    }
                    serde_yaml::Value::String(text)
                }
                _ => doc.clone(),
            }
        }
        serde_yaml::Value::Sequence(seq) => serde_yaml::Value::Sequence(
            seq.iter()
                .map(|v| render(v, values))
                .collect::<Result<_, _>>()?,
        ),
        serde_yaml::Value::Mapping(map) => {
            let mut out = serde_yaml::Mapping::with_capacity(map.len());
            for (k, v) in map {
                out.insert(k.clone(), render(v, values)?);
            }
            serde_yaml::Value::Mapping(out)
        }
        serde_yaml::Value::Tagged(t) => {
            serde_yaml::Value::Tagged(Box::new(serde_yaml::value::TaggedValue {
                tag: t.tag.clone(),
                value: render(&t.value, values)?,
            }))
        }
        other => other.clone(),
    })
}

/// Parse graph text after its environment pass.
pub fn parse_graph(template: &str) -> Result<serde_yaml::Value, String> {
    let text = crate::env_subst::substitute(template)?;
    serde_yaml::from_str(&text).map_err(|e| format!("parse graph: {e}"))
}

/// Template text → the graph one run builds: environment pass, parse,
/// parameter substitution, serialise, and escape so the build's own
/// environment pass leaves the result as rendered.
pub fn render_graph_text(
    template: &str,
    values: &BTreeMap<String, ParamValue>,
) -> Result<String, String> {
    let doc = parse_graph(template)?;
    let rendered = render(&doc, values)?;
    let text = serde_yaml::to_string(&rendered).map_err(|e| format!("serialise graph: {e}"))?;
    Ok(crate::env_subst::escape(&text))
}

// ============================================================================
// Run-time values
// ============================================================================

/// One `--param name=value`.
pub fn parse_flag(raw: &str) -> Result<(String, String), String> {
    let (name, value) = raw
        .split_once('=')
        .ok_or_else(|| format!("--param {raw:?}: expected NAME=VALUE"))?;
    Ok((name.to_string(), value.to_string()))
}

/// A `--params` values file: one flat TOML table of `name = value`.
pub fn read_values_file(path: &Path) -> Result<BTreeMap<String, toml::Value>, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("--params {}: {e}", path.display()))?;
    let table: toml::Table =
        toml::from_str(&text).map_err(|e| format!("--params {}: {e}", path.display()))?;
    let mut out = BTreeMap::new();
    for (k, v) in table {
        if matches!(v, toml::Value::Table(_) | toml::Value::Array(_)) {
            return Err(format!(
                "--params {}: '{k}' is {}; a values file is one flat table of name = value",
                path.display(),
                toml_type_word(&v)
            ));
        }
        out.insert(k, v);
    }
    Ok(out)
}

/// A `--param` string as the declared type.
fn typed_flag(name: &str, ty: ParamType, raw: &str) -> Result<ParamValue, String> {
    match ty {
        ParamType::String | ParamType::File => Ok(ParamValue::String(raw.to_string())),
        ParamType::Integer => raw.parse::<i64>().map(ParamValue::Integer).map_err(|_| {
            format!("--param {name}={raw}: '{name}' is an integer, and {raw:?} is not one")
        }),
        ParamType::Boolean => match raw {
            "true" => Ok(ParamValue::Boolean(true)),
            "false" => Ok(ParamValue::Boolean(false)),
            _ => Err(format!(
                "--param {name}={raw}: '{name}' is a boolean (true or false)"
            )),
        },
    }
}

/// The values one run uses: the `--params` file, overridden by `--param`
/// flags, with defaults for the rest. Every refusal — an unknown name, a
/// missing required value, a type or range error, a file that is not there,
/// values given to a bundle that declares no parameters — is collected and
/// reported together. A file value becomes the file's absolute path; a
/// relative one is taken from the working directory (the caller makes a
/// values file's paths relative to that file first).
pub fn resolve_values(
    params: &BTreeMap<String, ParamSpec>,
    file: &BTreeMap<String, toml::Value>,
    flags: &[(String, String)],
) -> Result<BTreeMap<String, ParamValue>, String> {
    if params.is_empty() {
        if file.is_empty() && flags.is_empty() {
            return Ok(BTreeMap::new());
        }
        return Err(
            "this bundle declares no parameters; --param and --params do not apply to it".into(),
        );
    }
    let declared = params
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let mut errors = Vec::new();
    let mut values: BTreeMap<String, ParamValue> = BTreeMap::new();

    for (name, v) in file {
        let Some(spec) = params.get(name) else {
            errors.push(format!(
                "unknown param '{name}' in --params (declared: {declared})"
            ));
            continue;
        };
        match typed_toml(&format!("--params '{name}'"), spec.ty, v)
            .and_then(|pv| check_value(name, spec, &pv).map(|()| pv))
        {
            Ok(pv) => {
                values.insert(name.clone(), pv);
            }
            Err(e) => errors.push(e),
        }
    }

    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (name, raw) in flags {
        if !seen.insert(name) {
            errors.push(format!("--param {name} is given more than once"));
            continue;
        }
        let Some(spec) = params.get(name) else {
            errors.push(format!("unknown param '{name}' (declared: {declared})"));
            continue;
        };
        match typed_flag(name, spec.ty, raw)
            .and_then(|pv| check_value(name, spec, &pv).map(|()| pv))
        {
            Ok(pv) => {
                values.insert(name.clone(), pv);
            }
            Err(e) => errors.push(e),
        }
    }

    for (name, spec) in params {
        if spec.ty == ParamType::File {
            if let Some(ParamValue::String(p)) = values.get(name) {
                match existing_file(name, Path::new(p)) {
                    Ok(abs) => {
                        values.insert(name.clone(), ParamValue::String(abs));
                    }
                    Err(e) => errors.push(e),
                }
            }
        }
        if values.contains_key(name) {
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
        Err(errors.join("\n"))
    }
}

// ============================================================================
// Source manifests (discovery + the ci check)
// ============================================================================

/// The fields of a workload source manifest the service checks read.
pub struct ServiceSource {
    pub name: String,
    pub role: String,
    /// `(target, graph path)` per `[[implementation]]`, the path resolved
    /// against the manifest's directory.
    pub implementations: Vec<(String, PathBuf)>,
    pub params: BTreeMap<String, ParamSpec>,
}

/// Read the service-relevant fields of a source manifest.
pub fn read_source(path: &Path) -> Result<ServiceSource, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let doc: toml::Table = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let workload = doc
        .get("workload")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| format!("{}: no [workload] table", path.display()))?;
    let name = workload
        .get("name")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| format!("{}: [workload] needs a string `name`", path.display()))?
        .to_string();
    let role = match workload.get("role") {
        None => "service".to_string(),
        Some(toml::Value::String(r)) if r == "service" || r == "cli" => r.clone(),
        Some(_) => {
            return Err(format!(
                "{}: workload.role must be 'service' or 'cli'",
                path.display()
            ));
        }
    };
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut implementations = Vec::new();
    match doc.get("implementation") {
        None => {}
        Some(toml::Value::Array(imps)) => {
            for (i, imp) in imps.iter().enumerate() {
                let field = |key: &str| {
                    imp.get(key).and_then(toml::Value::as_str).ok_or_else(|| {
                        format!(
                            "{}: [[implementation]] #{} needs a string `{key}`",
                            path.display(),
                            i + 1
                        )
                    })
                };
                implementations.push((field("target")?.to_string(), dir.join(field("graph")?)));
            }
        }
        Some(_) => {
            return Err(format!(
                "{}: `implementation` must be an array of tables",
                path.display()
            ));
        }
    }
    let params = match doc.get("params") {
        None => BTreeMap::new(),
        Some(toml::Value::Table(t)) => {
            parse_source_params(t).map_err(|e| format!("{}: {e}", path.display()))?
        }
        Some(_) => return Err(format!("{}: `params` must be a table", path.display())),
    };
    Ok(ServiceSource {
        name,
        role,
        implementations,
        params,
    })
}

/// The project's service source manifests, by the discovery rule:
/// `packaging/service/workload.toml`, `packaging/service/<name>/workload.toml`
/// and `examples/<name>/workload.toml`, each counted when its role is
/// `service` (the default). Sorted.
pub fn service_manifests(project_root: &Path) -> Vec<PathBuf> {
    let mut candidates = vec![project_root.join("packaging/service/workload.toml")];
    for parent in ["packaging/service", "examples"] {
        if let Ok(entries) = std::fs::read_dir(project_root.join(parent)) {
            candidates.extend(
                entries
                    .flatten()
                    .map(|e| e.path().join("workload.toml"))
                    .filter(|p| p.is_file()),
            );
        }
    }
    let mut out: Vec<PathBuf> = candidates
        .into_iter()
        .filter(|p| p.is_file())
        .filter(|p| read_source(p).map(|s| s.role == "service").unwrap_or(true))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// A service source manifest checked: its schema well-formed, every
/// placeholder in its linux graphs declared and every declared param
/// referenced, and each linux graph rendered with defaults and examples.
/// Returns `(graph path, rendered text)` per linux implementation.
pub fn check_source(path: &Path) -> Result<Vec<(PathBuf, String)>, String> {
    let src = read_source(path)?;
    if src.role != "service" && !src.params.is_empty() {
        return Err(format!(
            "{}: role '{}' declares [params]; parameters belong to services (an applet takes argv)",
            path.display(),
            src.role
        ));
    }
    let mut errors = validate_schema(&src.params);
    if !crate::workload::is_workload_name(&src.name) {
        errors.push(format!(
            "workload name '{}' is not a workload name",
            src.name
        ));
    }
    let mut used = BTreeSet::new();
    let mut graphs = Vec::new();
    for (target, graph) in &src.implementations {
        if target != "linux" {
            continue;
        }
        let template = match std::fs::read_to_string(graph) {
            Ok(t) => t,
            Err(e) => {
                errors.push(format!("{}: {e}", graph.display()));
                continue;
            }
        };
        match parse_graph(&template).and_then(|doc| placeholders(&doc)) {
            Ok(names) => used.extend(names),
            Err(e) => errors.push(format!("{}: {e}", graph.display())),
        }
        graphs.push((graph.clone(), template));
    }
    errors.extend(check_references(&src.params, &used));
    if !errors.is_empty() {
        return Err(format!("{}: {}", path.display(), errors.join("; ")));
    }
    let values = check_values(&src.params, path.parent().unwrap_or(Path::new(".")))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    graphs
        .into_iter()
        .map(|(graph, template)| {
            render_graph_text(&template, &values)
                .map(|text| (graph.clone(), text))
                .map_err(|e| format!("{}: {e}", graph.display()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema(toml_text: &str) -> Result<BTreeMap<String, ParamSpec>, String> {
        let t: toml::Table = toml::from_str(toml_text).unwrap();
        let params = parse_source_params(t["params"].as_table().unwrap())?;
        let errors = validate_schema(&params);
        if errors.is_empty() {
            Ok(params)
        } else {
            Err(errors.join("; "))
        }
    }

    const GOOD: &str = r#"
[params.port]
type = "integer"
default = 9100
min = 1
max = 65535
description = "TCP port"

[params.wal_dir]
type = "string"
required = true
example = "/var/lib/wal"

[params.verbose]
type = "boolean"
default = false
"#;

    #[test]
    fn a_well_formed_schema_parses() {
        let p = schema(GOOD).unwrap();
        assert_eq!(p["port"].default, Some(ParamValue::Integer(9100)));
        assert!(p["wal_dir"].required);
        assert_eq!(p["verbose"].ty, ParamType::Boolean);
    }

    #[test]
    fn schema_refusals_are_precise() {
        let cases: &[(&str, &str)] = &[
            (
                "[params.p]\ntype = \"integer\"\nrequired = true\ndefault = 1\nexample = 1\n",
                "required and also declares a default",
            ),
            (
                "[params.p]\ntype = \"integer\"\ndefault = \"x\"\n",
                "default must be an integer, got a string",
            ),
            (
                "[params.p]\ntype = \"integer\"\ndefault = 0\nmin = 1\n",
                "below its minimum 1",
            ),
            (
                "[params.p]\ntype = \"integer\"\ndefault = 5\nmin = 9\nmax = 2\n",
                "min 9 above max 2",
            ),
            (
                "[params.p]\ntype = \"string\"\ndefault = \"a\"\nmin = 1\n",
                "integers only",
            ),
            (
                "[params.P]\ntype = \"string\"\ndefault = \"a\"\n",
                "not [a-z]",
            ),
            (
                "[params.p]\ntype = \"string\"\ndefault = \"a\"\nbogus = 1\n",
                "unknown field `bogus`",
            ),
            (
                "[params.p]\ntype = \"float\"\ndefault = 1.0\n",
                "unknown variant",
            ),
            ("[params.p]\ntype = \"string\"\n", "declares no default"),
            (
                "[params.p]\ntype = \"string\"\nrequired = true\n",
                "declares no example",
            ),
        ];
        for (text, want) in cases {
            let e = schema(text).unwrap_err();
            assert!(e.contains(want), "{text}\n→ {e}\n(wanted {want:?})");
        }
    }

    #[test]
    fn the_param_ceiling_and_string_ceiling_refuse() {
        let mut text = String::new();
        for i in 0..=MAX_PARAMS {
            text.push_str(&format!("[params.p{i}]\ntype = \"integer\"\ndefault = 1\n"));
        }
        assert!(schema(&text).unwrap_err().contains("MAX_PARAMS"));
        let long = "x".repeat(MAX_PARAM_STRING_BYTES + 1);
        let e = schema(&format!(
            "[params.s]\ntype = \"string\"\ndefault = \"{long}\"\n"
        ))
        .unwrap_err();
        assert!(e.contains("MAX_PARAM_STRING_BYTES"), "{e}");
    }

    #[test]
    fn exact_placeholders_become_typed_nodes_and_embedded_ones_interpolate() {
        let doc = parse_graph(
            "modules:\n  - name: m\n    port: ${param:port}\n    on: ${param:verbose}\n    \
             path: \"${param:wal_dir}/seg-${param:port}\"\n    keep: ${FLUXOR_SURELY_UNSET:-7}\n",
        )
        .unwrap();
        let names = placeholders(&doc).unwrap();
        assert_eq!(
            names.into_iter().collect::<Vec<_>>(),
            vec!["port", "verbose", "wal_dir"]
        );
        let values: BTreeMap<String, ParamValue> = [
            ("port".to_string(), ParamValue::Integer(9200)),
            ("verbose".to_string(), ParamValue::Boolean(true)),
            ("wal_dir".to_string(), ParamValue::String("/w".into())),
        ]
        .into();
        let out = render(&doc, &values).unwrap();
        let m = &out["modules"][0];
        assert_eq!(m["port"], serde_yaml::Value::Number(9200.into()));
        assert_eq!(m["on"], serde_yaml::Value::Bool(true));
        assert_eq!(m["path"], serde_yaml::Value::String("/w/seg-9200".into()));
        assert_eq!(m["keep"], serde_yaml::Value::Number(7.into()));
    }

    #[test]
    fn a_value_cannot_inject_yaml_or_an_environment_reference() {
        let template = "modules:\n  - name: m\n    path: ${param:p}\n    label: \"x-${param:p}\"\n";
        let evil = "a\n  - name: injected\n    path: ${HOME}";
        let values: BTreeMap<String, ParamValue> =
            [("p".to_string(), ParamValue::String(evil.into()))].into();
        let text = render_graph_text(template, &values).unwrap();
        // The build re-runs the environment pass; the value must survive it
        // byte-for-byte and stay one scalar.
        let reread: serde_yaml::Value =
            serde_yaml::from_str(&crate::env_subst::substitute(&text).unwrap()).unwrap();
        let modules = reread["modules"].as_sequence().unwrap();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0]["path"].as_str(), Some(evil));
        assert_eq!(
            modules[0]["label"].as_str().map(str::to_string),
            Some(format!("x-{evil}"))
        );
    }

    #[test]
    fn booleans_cannot_sit_inside_text_and_keys_cannot_be_placeholders() {
        let doc = parse_graph("a: \"x${param:b}\"\n").unwrap();
        let values: BTreeMap<String, ParamValue> =
            [("b".to_string(), ParamValue::Boolean(true))].into();
        assert!(render(&doc, &values).unwrap_err().contains("boolean"));
        let doc = parse_graph("\"${param:k}\": 1\n").unwrap();
        assert!(placeholders(&doc).unwrap_err().contains("mapping key"));
        let doc = parse_graph("a: \"${param:Bad}\"\n").unwrap();
        assert!(placeholders(&doc)
            .unwrap_err()
            .contains("not a parameter name"));
        // The environment pass refuses an unclosed `${` first; the
        // placeholder scan refuses it on its own as well.
        assert!(parse_graph("a: \"${param:open\"\n").is_err());
        let doc: serde_yaml::Value = serde_yaml::from_str("a: \"${param:open\"\n").unwrap();
        assert!(placeholders(&doc).unwrap_err().contains("unclosed"));
    }

    #[test]
    fn references_must_match_declarations_both_ways() {
        let p = schema(GOOD).unwrap();
        let used: BTreeSet<String> = ["port", "wal_dir", "ghost"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let errors = check_references(&p, &used).join("; ");
        assert!(
            errors.contains("`${param:ghost}` but no [params.ghost]"),
            "{errors}"
        );
        assert!(
            errors.contains("param 'verbose' is declared but no graph"),
            "{errors}"
        );
    }

    #[test]
    fn run_values_resolve_and_refuse() {
        let p = schema(GOOD).unwrap();
        let flag = |s: &str| parse_flag(s).unwrap();

        let v = resolve_values(&p, &BTreeMap::new(), &[flag("wal_dir=/w")]).unwrap();
        assert_eq!(v["port"], ParamValue::Integer(9100));
        assert_eq!(v["verbose"], ParamValue::Boolean(false));

        // The flag overrides the file.
        let file: BTreeMap<String, toml::Value> = [
            ("port".to_string(), toml::Value::Integer(1000)),
            ("wal_dir".to_string(), toml::Value::String("/f".into())),
        ]
        .into();
        let v = resolve_values(&p, &file, &[flag("port=2000")]).unwrap();
        assert_eq!(v["port"], ParamValue::Integer(2000));
        assert_eq!(v["wal_dir"], ParamValue::String("/f".into()));

        let e = resolve_values(&p, &BTreeMap::new(), &[flag("bogus=1")]).unwrap_err();
        assert!(
            e.contains("unknown param 'bogus' (declared: port, verbose, wal_dir)"),
            "{e}"
        );
        assert!(e.contains("missing required param 'wal_dir'"), "{e}");
        let e = resolve_values(
            &p,
            &BTreeMap::new(),
            &[flag("wal_dir=/w"), flag("port=abc")],
        )
        .unwrap_err();
        assert!(e.contains("'port' is an integer"), "{e}");
        let e = resolve_values(
            &p,
            &BTreeMap::new(),
            &[flag("wal_dir=/w"), flag("port=70000")],
        )
        .unwrap_err();
        assert!(e.contains("above its maximum 65535"), "{e}");
        let e = resolve_values(
            &p,
            &BTreeMap::new(),
            &[flag("wal_dir=/w"), flag("verbose=yes")],
        )
        .unwrap_err();
        assert!(e.contains("boolean"), "{e}");
        let file: BTreeMap<String, toml::Value> =
            [("port".to_string(), toml::Value::String("1".into()))].into();
        let e = resolve_values(&p, &file, &[flag("wal_dir=/w")]).unwrap_err();
        assert!(e.contains("must be an integer, got a string"), "{e}");
        let e = resolve_values(
            &p,
            &BTreeMap::new(),
            &[flag("wal_dir=/a"), flag("wal_dir=/b")],
        )
        .unwrap_err();
        assert!(e.contains("more than once"), "{e}");

        let e = resolve_values(&BTreeMap::new(), &BTreeMap::new(), &[flag("port=1")]).unwrap_err();
        assert!(e.contains("declares no parameters"), "{e}");
        assert!(resolve_values(&BTreeMap::new(), &BTreeMap::new(), &[]).is_ok());
    }

    /// A scratch directory holding `ca.pem`, unique to this test.
    fn scratch_with_ca(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fluxor-file-param-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("testdata")).unwrap();
        std::fs::write(dir.join("testdata/ca.pem"), "pem").unwrap();
        dir
    }

    const FILE_SCHEMA: &str = r#"
[params.ca]
type = "file"
required = true
example = "testdata/ca.pem"
description = "CA bundle"
"#;

    #[test]
    fn a_file_param_is_required_and_has_no_default() {
        assert!(schema(FILE_SCHEMA).is_ok());
        let e = schema("[params.ca]\ntype = \"file\"\ndefault = \"/etc/ca.pem\"\n").unwrap_err();
        assert!(e.contains("is a file and declares a default"), "{e}");
        let e = schema("[params.ca]\ntype = \"file\"\nrequired = true\nexample = 3\n").unwrap_err();
        assert!(e.contains("must be a file path, got an integer"), "{e}");
    }

    #[test]
    fn a_file_value_is_its_absolute_path_and_must_be_there() {
        let flag = |s: &str| parse_flag(s).unwrap();
        let dir = scratch_with_ca("run");
        let p = schema(FILE_SCHEMA).unwrap();
        let ca = dir.join("testdata/ca.pem");
        let v = resolve_values(
            &p,
            &BTreeMap::new(),
            &[flag(&format!("ca={}", ca.display()))],
        )
        .unwrap();
        assert_eq!(v["ca"], ParamValue::String(ca.display().to_string()));

        let missing = dir.join("nope.pem");
        let e = resolve_values(
            &p,
            &BTreeMap::new(),
            &[flag(&format!("ca={}", missing.display()))],
        )
        .unwrap_err();
        assert!(e.contains("param 'ca'") && e.contains("nope.pem"), "{e}");
        let e = resolve_values(
            &p,
            &BTreeMap::new(),
            &[flag(&format!("ca={}", dir.display()))],
        )
        .unwrap_err();
        assert!(e.contains("is not a file"), "{e}");

        // The graph names it where a module takes a path, alone or inside a
        // `${file:..}` source spec, and the build's environment pass leaves
        // both as rendered.
        let template = "modules:\n  - name: tls\n    trust: \"${file:${param:ca}}\"\n    \
                        cert_file: ${param:ca}\n";
        let text = render_graph_text(template, &v).unwrap();
        let reread: serde_yaml::Value =
            serde_yaml::from_str(&crate::env_subst::substitute(&text).unwrap()).unwrap();
        let m = &reread["modules"][0];
        assert_eq!(
            m["trust"],
            serde_yaml::Value::String(format!("${{file:{}}}", ca.display()))
        );
        assert_eq!(
            m["cert_file"],
            serde_yaml::Value::String(ca.display().to_string())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_example_is_a_sample_beside_the_source_manifest() {
        let dir = scratch_with_ca("check");
        let p = schema(FILE_SCHEMA).unwrap();
        let v = check_values(&p, &dir).unwrap();
        assert_eq!(
            v["ca"],
            ParamValue::String(dir.join("testdata/ca.pem").display().to_string())
        );
        let e = check_values(&p, &dir.join("elsewhere")).unwrap_err();
        assert!(e.contains("example: param 'ca'"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn workload_json_round_trips_the_schema() {
        let p = schema(GOOD).unwrap();
        let json = serde_json::to_string(&p).unwrap();
        let back: BTreeMap<String, ParamSpec> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
        assert!(serde_json::from_str::<ParamSpec>(r#"{"type":"string","extra":1}"#).is_err());
    }
}
