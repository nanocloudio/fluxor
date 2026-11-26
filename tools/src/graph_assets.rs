//! A graph's `assets:`: the files it declares, the ones it builds at build
//! time through a bound stack, and the `${asset:<name>}` placeholder its
//! module params name one by.
//!
//! An entry is a path (`- some/file.png`, or `{ path: …, name: … }`), or a
//! build step: `{ name: <n>, build: "@<bound>", from: <path>, params: {…} }`.
//! A build step composes a Linux graph around the stack the project binds to
//! `<bound>` ([`build_step_graph`]), runs it on the project's host runtime
//! with `input` set to the absolute path of `from` and its `params` beside
//! it (a `${asset:<name>}` there names an asset declared earlier, and
//! resolves to its file), and keeps what it writes
//! to `output` as the asset's file, `target/assets/<n>` under the project.
//! From there a built asset is a file like any other: a wasm bundle bakes it
//! into its `fluxor.assets` section.
//!
//! `${asset:<name>}` resolves by the graph's target family: `asset://<name>`
//! on wasm, the asset file's absolute path on linux, and on a family whose
//! node image carries programs (rp2, bcm, uefi) a program of the module
//! instance whose param names it, `program:<slot>`. Resolving it never runs
//! a build step, so a check renders the path a build would write.
//!
//! The interface a build-step stack meets is documented in
//! `docs/architecture/stacks.md` (Build-time assets).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use serde_json::{json, Value};

use crate::error::{Error, Result};

/// The graph key that declares assets.
pub const ASSETS_KEY: &str = "assets";

/// The placeholder a value names an asset by: `${asset:<name>}`.
const PLACEHOLDER: &str = "${asset:";

/// The alias a build step's stack is included as in its graph.
const STEP_ALIAS: &str = "build";

/// Where a declared asset's bytes come from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// A file, absolute.
    File(PathBuf),
    /// Built at build time by the stack bound to `binding`, from `from`
    /// (absolute; a file or a directory), given `params` beside `input`.
    Build {
        binding: String,
        from: PathBuf,
        params: BTreeMap<String, Value>,
    },
}

/// One `assets:` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asset {
    pub name: String,
    pub source: Source,
}

/// What builds an asset, as a key: a digest of the bound stack, `from:`, and
/// its params with every `${asset:}` resolved to the file it names. Two
/// graphs that build one name from different inputs have different keys, so
/// each keeps its own bytes; the same inputs share one output.
fn inputs_key(binding: &str, from: &Path, params: &BTreeMap<String, Value>) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(binding.as_bytes());
    h.update([0]);
    h.update(from.display().to_string().as_bytes());
    h.update([0]);
    // A BTreeMap serialises in key order: one text per params set.
    h.update(serde_json::to_string(params).unwrap_or_default().as_bytes());
    h.finalize()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Where a built asset's bytes land: `target/assets/<key>/<name>`, `<key>`
/// its [`inputs_key`].
pub fn output_path(project_root: &Path, key: &str, name: &str) -> PathBuf {
    project_root.join("target/assets").join(key).join(name)
}

/// Where a built asset's build-step graph and its image are written:
/// `target/assets/.build/<key>/<name>/`, beside the outputs and never one of
/// them.
pub fn work_dir(project_root: &Path, key: &str, name: &str) -> PathBuf {
    project_root
        .join("target/assets/.build")
        .join(key)
        .join(name)
}

/// A build step's params with each `${asset:<name>}` resolved through
/// `file`.
fn step_params(
    params: &BTreeMap<String, Value>,
    file: &dyn Fn(&str) -> Option<PathBuf>,
) -> BTreeMap<String, Value> {
    params
        .iter()
        .map(|(k, v)| (k.clone(), substitute(v, file)))
        .collect()
}

/// The file that holds each asset's bytes, in declaration order: a path
/// entry's own file, a built one's [`output_path`]. A build step's params
/// name only assets declared before it ([`parse`] holds them to that), so
/// their files are known when its key is taken.
pub fn asset_files(assets: &[Asset], project_root: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = Vec::with_capacity(assets.len());
    for asset in assets {
        let file = match &asset.source {
            Source::File(p) => p.clone(),
            Source::Build {
                binding,
                from,
                params,
            } => {
                let earlier = |name: &str| {
                    assets
                        .iter()
                        .zip(&files)
                        .find(|(a, _)| a.name == name)
                        .map(|(_, f)| f.clone())
                };
                let params = step_params(params, &earlier);
                output_path(
                    project_root,
                    &inputs_key(binding, from, &params),
                    &asset.name,
                )
            }
        };
        files.push(file);
    }
    files
}

/// `p` made absolute against the working directory, `.` and `..` removed
/// lexically, so a check and a build name the same path for it.
fn absolute(p: &Path) -> PathBuf {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    };
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// An asset name is one path segment: it is a file under `target/assets/`
/// and the key a bundle serves it at.
fn check_name(name: &str) -> std::result::Result<(), String> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.starts_with('.')
        || name.contains(['/', '\\', '}', '\0'])
    {
        return Err(format!(
            "'{name}' is not an asset name — one path segment, not starting with `.`, with no \
             `/`, `\\` or `}}`"
        ));
    }
    Ok(())
}

/// The assets `config` (the graph read from `graph`) declares. A relative
/// `path:` or `from:` is relative to the graph's directory.
pub fn parse(config: &Value, graph: &Path) -> Result<Vec<Asset>> {
    let Some(entries) = config.get(ASSETS_KEY) else {
        return Ok(Vec::new());
    };
    let entries = entries.as_array().ok_or_else(|| {
        Error::Config(format!(
            "graph `{}`: `assets:` must be a list",
            graph.display()
        ))
    })?;
    let base = absolute(crate::stack::graph_dir(graph));
    let mut out: Vec<Asset> = Vec::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        let at =
            |why: String| Error::Config(format!("graph `{}`: assets[{i}]: {why}", graph.display()));
        let asset = parse_entry(entry, &base).map_err(at)?;
        check_name(&asset.name).map_err(at)?;
        if out.iter().any(|a| a.name == asset.name) {
            return Err(at(format!("asset '{}' is declared twice", asset.name)));
        }
        if let Source::Build { params, .. } = &asset.source {
            for value in params.values() {
                for name in placeholders(value).map_err(at)? {
                    if !out.iter().any(|a| a.name == name) {
                        return Err(at(format!(
                            "`params:` names `{PLACEHOLDER}{name}}}`, which is not an asset \
                             declared before '{}' — a build step's params name assets \
                             declared earlier in `assets:`, which build first",
                            asset.name
                        )));
                    }
                }
            }
        }
        out.push(asset);
    }
    Ok(out)
}

/// The basename a path entry is named by when it gives no `name:`.
fn basename(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
        .to_string()
}

/// One `assets:` entry, its paths made absolute against `base`.
fn parse_entry(entry: &Value, base: &Path) -> std::result::Result<Asset, String> {
    let m = match entry {
        Value::String(path) => {
            return Ok(Asset {
                name: basename(path),
                source: Source::File(absolute(&base.join(path))),
            })
        }
        Value::Object(m) => m,
        _ => return Err("must be a path, or a map with `path:` or `build:` and `from:`".into()),
    };
    if let Some(k) = m
        .keys()
        .find(|k| !matches!(k.as_str(), "name" | "path" | "build" | "from" | "params"))
    {
        return Err(format!(
            "unknown key `{k}` (an entry takes name, and path or build + from + params)"
        ));
    }
    let params = match m.get("params") {
        None => BTreeMap::new(),
        Some(Value::Object(p)) => {
            let mut out = BTreeMap::new();
            for (k, v) in p {
                if k == "input" {
                    return Err(
                        "`params:` cannot set `input` — the build step's `input` is \
                                `from:`"
                            .into(),
                    );
                }
                if !matches!(v, Value::String(_) | Value::Number(_) | Value::Bool(_)) {
                    return Err(format!(
                        "`params: {k}` must be a string, a number or a boolean"
                    ));
                }
                out.insert(k.clone(), v.clone());
            }
            out
        }
        Some(_) => return Err("`params:` must be a map of the build step's params".into()),
    };
    if !params.is_empty() && m.get("build").is_none() {
        return Err("`params:` belongs to a build step (`build: \"@<name>\"`)".into());
    }
    let text = |key: &str| match m.get(key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(_) => Err(format!("`{key}:` must be a string")),
    };
    let name = text("name")?;
    match (text("path")?, text("build")?, text("from")?) {
        (Some(_), Some(_), _) => Err(
            "takes `path:` or `build:`, not both — a path names a file; a build makes one".into(),
        ),
        (Some(_), None, Some(_)) => Err("`from:` belongs to a build step (`build: \"@<name>\"`); \
                                         a path entry names its file with `path:`"
            .into()),
        (Some(path), None, None) => Ok(Asset {
            name: name.map_or_else(|| basename(path), str::to_string),
            source: Source::File(absolute(&base.join(path))),
        }),
        (None, Some(build), from) => {
            let binding = crate::stack::bound_name(build).ok_or_else(|| {
                format!(
                    "`build: {build:?}` must name a bound stack, `@<name>`, that \
                     [uses.stacks] in fluxor.toml binds"
                )
            })?;
            let name =
                name.ok_or_else(|| format!("a build step (`build: {build:?}`) needs a `name:`"))?;
            let from = from.ok_or_else(|| {
                format!(
                    "a build step (`build: {build:?}`) needs `from:`, the file or directory it \
                     builds from, relative to the graph"
                )
            })?;
            Ok(Asset {
                name: name.to_string(),
                source: Source::Build {
                    binding: binding.to_string(),
                    from: absolute(&base.join(from)),
                    params,
                },
            })
        }
        (None, None, _) => {
            Err("names no file: give `path:`, or `build: \"@<name>\"` with `from:`".into())
        }
    }
}

/// `(name, file)` for every asset, as a bundle bakes them.
pub fn files(config: &Value, graph: &Path, project_root: &Path) -> Result<Vec<(String, PathBuf)>> {
    let assets = parse(config, graph)?;
    let files = asset_files(&assets, project_root);
    Ok(assets.into_iter().map(|a| a.name).zip(files).collect())
}

// ============================================================================
// `${asset:<name>}`
// ============================================================================

/// The asset names a value's `${asset:<name>}` placeholders name.
fn placeholders(v: &Value) -> std::result::Result<Vec<String>, String> {
    let Value::String(s) = v else {
        return Ok(Vec::new());
    };
    let mut names = Vec::new();
    let mut rest = s.as_str();
    while let Some(pos) = rest.find(PLACEHOLDER) {
        let after = &rest[pos + PLACEHOLDER.len()..];
        let end = after
            .find('}')
            .ok_or_else(|| format!("unclosed `{PLACEHOLDER}` in {s:?}"))?;
        names.push(after[..end].to_string());
        rest = &after[end + 1..];
    }
    Ok(names)
}

/// `v` with each `${asset:<name>}` replaced by `file(name)`.
fn substitute(v: &Value, file: &dyn Fn(&str) -> Option<PathBuf>) -> Value {
    let Value::String(s) = v else {
        return v.clone();
    };
    let mut text = String::with_capacity(s.len());
    let mut rest = s.as_str();
    while let Some(pos) = rest.find(PLACEHOLDER) {
        text.push_str(&rest[..pos]);
        let after = &rest[pos + PLACEHOLDER.len()..];
        let Some(end) = after.find('}') else {
            break;
        };
        match file(&after[..end]) {
            Some(p) => text.push_str(&p.display().to_string()),
            None => text.push_str(&rest[pos..pos + PLACEHOLDER.len() + end + 1]),
        }
        rest = &after[end + 1..];
    }
    text.push_str(rest);
    Value::String(text)
}

/// Does any value of the graph `config`, outside its `assets:` declarations,
/// name an asset?
pub fn names_an_asset(config: &Value) -> bool {
    fn any(v: &Value) -> bool {
        match v {
            Value::String(s) => s.contains(PLACEHOLDER),
            Value::Array(a) => a.iter().any(any),
            Value::Object(m) => m.values().any(any),
            _ => false,
        }
    }
    match config {
        Value::Object(m) => m.iter().any(|(k, v)| k != ASSETS_KEY && any(v)),
        other => any(other),
    }
}

/// The module-entry key the resolver records the params it resolved under,
/// for the composer to hold against the module's manifest
/// (`[[params]] asset = true`). Never written by hand and never a wire
/// param.
pub const ASSET_PARAMS_KEY: &str = "asset_params";

/// Programs one node image holds (`modules::build_program_section`).
const MAX_GRAPH_PROGRAMS: usize = 255;

/// Programs one module instance owns: a slot is a byte.
const MAX_INSTANCE_PROGRAMS: usize = 256;

/// How a target family hands a module an asset.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mechanism {
    /// `asset://<name>`, out of the bundle's asset section.
    BundleUrl,
    /// The asset file's absolute path.
    File,
    /// A program of the module instance, named `program:<slot>`.
    Program,
}

fn mechanism(family: &str) -> Option<Mechanism> {
    match family {
        "wasm" => Some(Mechanism::BundleUrl),
        "linux" => Some(Mechanism::File),
        "rp2" | "bcm" | "uefi" => Some(Mechanism::Program),
        _ => None,
    }
}

/// Refuse a graph whose module entry carries [`ASSET_PARAMS_KEY`] as
/// written: the key is the resolver's record, and one written by hand would
/// claim a param names an asset the resolver never saw.
pub fn refuse_written_asset_params(config: &Value, graph: &Path) -> Result<()> {
    for entry in module_entries(config) {
        if entry.get(ASSET_PARAMS_KEY).is_some() {
            let name = entry.get("name").and_then(Value::as_str).unwrap_or("?");
            return Err(Error::Config(format!(
                "graph `{}`: module '{name}': `{ASSET_PARAMS_KEY}` is recorded by the build \
                 for each param that names an asset (`{PLACEHOLDER}<name>}}`); it is not \
                 written in a graph",
                graph.display()
            )));
        }
    }
    Ok(())
}

/// Every module entry of `config`: the node graph's and each workload's.
fn module_entries(config: &Value) -> Vec<&Value> {
    fn list(v: Option<&Value>) -> Vec<&Value> {
        v.and_then(Value::as_array)
            .map(|a| a.iter().collect())
            .unwrap_or_default()
    }
    let mut out = list(config.get("modules"));
    for w in list(config.get("workloads")) {
        out.extend(list(w.get("modules")));
    }
    out
}

/// The one asset a value names when it is `${asset:<name>}` and nothing
/// else.
fn whole_placeholder(v: &Value) -> Option<&str> {
    let s = v.as_str()?;
    let name = s.strip_prefix(PLACEHOLDER)?.strip_suffix('}')?;
    (!name.contains('}') && !name.contains(PLACEHOLDER)).then_some(name)
}

/// Whether `v` holds a placeholder at any depth.
fn holds_placeholder(v: &Value) -> bool {
    match v {
        Value::String(s) => s.contains(PLACEHOLDER),
        Value::Array(a) => a.iter().any(holds_placeholder),
        Value::Object(m) => m.values().any(holds_placeholder),
        _ => false,
    }
}

/// Replace every placeholder in `v`, at any depth, by `value_of(name)`.
fn substitute_all(
    v: &mut Value,
    value_of: &dyn Fn(&str) -> std::result::Result<String, String>,
) -> std::result::Result<(), String> {
    match v {
        Value::String(s) if s.contains(PLACEHOLDER) => {
            let mut text = String::with_capacity(s.len());
            let mut rest = s.as_str();
            while let Some(pos) = rest.find(PLACEHOLDER) {
                text.push_str(&rest[..pos]);
                let after = &rest[pos + PLACEHOLDER.len()..];
                let end = after
                    .find('}')
                    .ok_or_else(|| format!("unclosed `{PLACEHOLDER}` in {s:?}"))?;
                text.push_str(&value_of(&after[..end])?);
                rest = &after[end + 1..];
            }
            text.push_str(rest);
            *s = text;
        }
        Value::Array(a) => {
            for item in a {
                substitute_all(item, value_of)?;
            }
        }
        Value::Object(m) => {
            for item in m.values_mut() {
                substitute_all(item, value_of)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// The programs a module entry names, as a list: `programs:`, or its one
/// `program:` as the first of one.
fn program_count(entry: &Value) -> usize {
    match (entry.get("program"), entry.get("programs")) {
        (_, Some(Value::Array(list))) => list.len(),
        (Some(_), _) => 1,
        _ => 0,
    }
}

/// Resolve every `${asset:<name>}` in `config`'s values by the graph's
/// target `family`, and record on each module entry the params that named
/// one ([`ASSET_PARAMS_KEY`]).
///
/// On `wasm` a placeholder becomes `asset://<name>` and on `linux` the asset
/// file's absolute path, as a whole value or inside a longer one. On a
/// family whose node image carries programs (`rp2`, `bcm`, `uefi`) a module
/// param whose whole value is the placeholder makes the asset a program of
/// that instance: an entry `{ file, kind: <name> }` appended to the entry's
/// `programs:` (its one `program:` becoming the first of the list), in the
/// order of the param names that name it, and the param's value becomes
/// `program:<slot>`. Two params of one instance naming one asset share the
/// slot; each instance has its own copy. There a placeholder anywhere else
/// is refused: inside a longer value, outside a module's params, or in a
/// workload's module, whose image carries no programs.
///
/// Substitution is on the parsed tree, never on text. Nothing is built here.
pub fn resolve_placeholders(
    config: &mut Value,
    graph: &Path,
    family: &str,
    project_root: &Path,
) -> Result<()> {
    if !names_an_asset(config) {
        return Ok(());
    }
    let assets: BTreeMap<String, PathBuf> =
        files(config, graph, project_root)?.into_iter().collect();
    let file_of = |name: &str| -> std::result::Result<PathBuf, String> {
        assets.get(name).cloned().ok_or_else(|| {
            let declared = if assets.is_empty() {
                "none".to_string()
            } else {
                assets.keys().cloned().collect::<Vec<_>>().join(", ")
            };
            format!("`{PLACEHOLDER}{name}}}` names no asset — `assets:` declares: {declared}")
        })
    };
    let fail = |e: String| Error::Config(format!("graph `{}`: {e}", graph.display()));
    let first = || {
        fn find(v: &Value) -> Option<String> {
            match v {
                Value::String(_) => placeholders(v).ok()?.into_iter().next(),
                Value::Array(a) => a.iter().find_map(find),
                Value::Object(m) => m.values().find_map(find),
                _ => None,
            }
        }
        config
            .as_object()
            .and_then(|m| {
                m.iter()
                    .filter(|(k, _)| k.as_str() != ASSETS_KEY)
                    .find_map(|(_, v)| find(v))
            })
            .unwrap_or_default()
    };
    let Some(mechanism) = mechanism(family) else {
        return Err(fail(format!(
            "`{PLACEHOLDER}{}}}`: target family '{family}' gives a module no asset — \
             `${{asset:}}` resolves on wasm (to `asset://<name>`), on linux (to the asset \
             file's absolute path) and on rp2, bcm and uefi (to a program of the module \
             instance, `program:<slot>`)",
            first()
        )));
    };
    let value_of = |name: &str| -> std::result::Result<String, String> {
        let file = file_of(name)?;
        Ok(match mechanism {
            Mechanism::BundleUrl => format!("asset://{name}"),
            Mechanism::File | Mechanism::Program => file.display().to_string(),
        })
    };
    // Outside a module's params a placeholder is text to substitute, or on a
    // program family nothing a module could read.
    let elsewhere = |v: &mut Value, at: &str| -> std::result::Result<(), String> {
        if !holds_placeholder(v) {
            return Ok(());
        }
        if mechanism == Mechanism::Program {
            return Err(format!(
                "{at} names an asset, but on {family} an asset is a program of the module \
                 instance whose param names it: write `{PLACEHOLDER}<name>}}` as the whole \
                 value of a module param"
            ));
        }
        substitute_all(v, &value_of)
    };

    let mut graph_programs: usize = config
        .get("modules")
        .and_then(Value::as_array)
        .map_or(0, |ms| ms.iter().map(program_count).sum());
    let Some(top) = config.as_object_mut() else {
        return Ok(());
    };
    for (key, value) in top.iter_mut() {
        match key.as_str() {
            ASSETS_KEY => {}
            "modules" => {
                for entry in value.as_array_mut().into_iter().flatten() {
                    resolve_module(
                        entry,
                        true,
                        family,
                        mechanism,
                        &file_of,
                        &value_of,
                        &mut graph_programs,
                    )
                    .map_err(&fail)?;
                }
            }
            "workloads" => {
                for workload in value.as_array_mut().into_iter().flatten() {
                    let Some(w) = workload.as_object_mut() else {
                        elsewhere(workload, "`workloads`").map_err(&fail)?;
                        continue;
                    };
                    for (wkey, wvalue) in w.iter_mut() {
                        if wkey == "modules" {
                            for entry in wvalue.as_array_mut().into_iter().flatten() {
                                resolve_module(
                                    entry,
                                    false,
                                    family,
                                    mechanism,
                                    &file_of,
                                    &value_of,
                                    &mut graph_programs,
                                )
                                .map_err(&fail)?;
                            }
                        } else {
                            elsewhere(wvalue, &format!("`workloads` `{wkey}`")).map_err(&fail)?;
                        }
                    }
                }
            }
            other => elsewhere(value, &format!("`{other}`")).map_err(&fail)?,
        }
    }
    Ok(())
}

/// Resolve the placeholders of one module entry and record the params that
/// held one. `node` is a module of the node graph, which owns programs; a
/// workload's module does not.
fn resolve_module(
    entry: &mut Value,
    node: bool,
    family: &str,
    mechanism: Mechanism,
    file_of: &dyn Fn(&str) -> std::result::Result<PathBuf, String>,
    value_of: &dyn Fn(&str) -> std::result::Result<String, String>,
    graph_programs: &mut usize,
) -> std::result::Result<(), String> {
    if !holds_placeholder(entry) {
        return Ok(());
    }
    let name = entry
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_string();
    let own_programs = program_count(entry);
    let Some(map) = entry.as_object_mut() else {
        return Ok(());
    };
    // The params that name an asset, sorted by name: a key of the entry, or
    // of its `params:` wrapper.
    let mut params: BTreeSet<(String, bool)> = BTreeSet::new();
    for (key, value) in map.iter() {
        if key == "params" {
            if let Some(inner) = value.as_object() {
                for (k, v) in inner {
                    if holds_placeholder(v) {
                        params.insert((k.clone(), true));
                    }
                }
                continue;
            }
        }
        if holds_placeholder(value) {
            params.insert((key.clone(), false));
        }
    }
    let at = |param: &str| format!("module '{name}': `{param}`");
    // Programs this entry gains, by asset name.
    let mut slots: BTreeMap<String, usize> = BTreeMap::new();
    let mut appended: Vec<Value> = Vec::new();
    for (param, wrapped) in &params {
        let value = if *wrapped {
            map.get_mut("params").and_then(|p| p.get_mut(param))
        } else {
            map.get_mut(param)
        };
        let Some(value) = value else {
            continue;
        };
        if mechanism != Mechanism::Program {
            substitute_all(value, value_of).map_err(|e| format!("{}: {e}", at(param)))?;
            continue;
        }
        if !node {
            return Err(format!(
                "{}: names an asset, but a workload's modules own no programs: on {family} \
                 an asset is a program in the node image, and the kernel finds programs only \
                 for the node graph's own modules",
                at(param)
            ));
        }
        if matches!(param.as_str(), "program" | "programs") {
            return Err(format!(
                "{}: a program is a file; an asset becomes one through the param that names \
                 it (`<param>: {PLACEHOLDER}<name>}}`)",
                at(param)
            ));
        }
        let Some(asset) = whole_placeholder(value).map(str::to_string) else {
            return Err(format!(
                "{}: {value} embeds an asset in a longer value, but on {family} an asset is \
                 a program of the instance, named `program:<slot>`, not a path to extend: \
                 give the param the placeholder as its whole value",
                at(param)
            ));
        };
        let slot = match slots.get(&asset) {
            Some(&slot) => slot,
            None => {
                let file = file_of(&asset).map_err(|e| format!("{}: {e}", at(param)))?;
                let slot = own_programs + appended.len();
                if slot >= MAX_INSTANCE_PROGRAMS {
                    return Err(format!(
                        "{}: asset '{asset}' would be program {slot} of the instance; an \
                         instance owns at most {MAX_INSTANCE_PROGRAMS}",
                        at(param)
                    ));
                }
                *graph_programs += 1;
                if *graph_programs > MAX_GRAPH_PROGRAMS {
                    return Err(format!(
                        "{}: asset '{asset}' is program {} of the graph; a node image holds \
                         at most {MAX_GRAPH_PROGRAMS}",
                        at(param),
                        *graph_programs
                    ));
                }
                appended.push(json!({ "file": file.display().to_string(), "kind": asset }));
                slots.insert(asset, slot);
                slot
            }
        };
        *value = Value::String(format!("program:{slot}"));
    }
    if !appended.is_empty() {
        let mut list = match (map.remove("program"), map.remove("programs")) {
            (Some(_), Some(_)) => {
                return Err(format!(
                    "module '{name}': name its programs with `program` or `programs`, not both"
                ))
            }
            (Some(one), None) => vec![one],
            (None, Some(Value::Array(list))) => list,
            (None, Some(_)) => return Err(format!("module '{name}': `programs` is a list")),
            (None, None) => Vec::new(),
        };
        list.extend(appended);
        map.insert("programs".to_string(), Value::Array(list));
    }
    map.insert(
        ASSET_PARAMS_KEY.to_string(),
        Value::Array(
            params
                .iter()
                .map(|(p, _)| p.clone())
                .collect::<BTreeSet<String>>()
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    );
    Ok(())
}

/// Make each relative `path:` and `from:` in `config`'s `assets:` absolute
/// against `base`, the directory of the graph they were written in, so the
/// graph still names the same files once written elsewhere (a scenario's
/// work directory). A value carrying a placeholder is left as written.
pub fn anchor(config: &mut Value, base: &Path) {
    let Some(entries) = config.get_mut(ASSETS_KEY).and_then(Value::as_array_mut) else {
        return;
    };
    let fix = |v: &mut Value| {
        if let Value::String(s) = v {
            if !s.contains("${") && Path::new(s.as_str()).is_relative() {
                *s = absolute(&base.join(s.as_str())).display().to_string();
            }
        }
    };
    for entry in entries {
        match entry {
            Value::String(_) => fix(entry),
            Value::Object(m) => {
                for key in ["path", "from"] {
                    if let Some(v) = m.get_mut(key) {
                        fix(v);
                    }
                }
            }
            _ => {}
        }
    }
}

// ============================================================================
// Build steps
// ============================================================================

/// The Linux graph that builds one asset: the stack bound to `binding`,
/// given `input`, writing its `output` to stdout and, where the stack
/// exports them, its `diagnostics` to stderr and its `exit` code to the
/// process's.
pub fn build_step_graph(
    binding: &str,
    input: &Path,
    params: &BTreeMap<String, Value>,
    exports: &BTreeSet<String>,
) -> Value {
    let mut p = serde_json::Map::new();
    p.insert("input".into(), Value::String(input.display().to_string()));
    for (k, v) in params {
        p.insert(k.clone(), v.clone());
    }
    let mut wiring =
        vec![json!({ "from": format!("{STEP_ALIAS}.output"), "to": "cli_out.bytes_in" })];
    if exports.contains("diagnostics") {
        wiring.push(json!({ "from": format!("{STEP_ALIAS}.diagnostics"), "to": "cli_out.err_in" }));
    }
    if exports.contains("exit") {
        wiring.push(json!({ "from": format!("{STEP_ALIAS}.exit"), "to": "cli_out.exit_in" }));
    }
    json!({
        "target": "linux",
        "platform": { "cli": {} },
        "include": [{
            "stack": format!("@{binding}"),
            "as": STEP_ALIAS,
            "params": p,
        }],
        "wiring": wiring,
    })
}

/// Is `line` one of the runtime's own log records (`[<time> <LEVEL> …] …`)
/// rather than a line the build step wrote to its diagnostics?
fn is_runtime_log(line: &str) -> bool {
    let Some(rest) = line.strip_prefix('[') else {
        return false;
    };
    let mut words = rest.split_whitespace();
    let _time = words.next();
    matches!(
        words.next(),
        Some("ERROR" | "WARN" | "INFO" | "DEBUG" | "TRACE")
    )
}

/// The build step's own diagnostics: its stderr without the runtime's log.
fn diagnostics(stderr: &str) -> Vec<&str> {
    stderr
        .lines()
        .filter(|l| !l.trim().is_empty() && !is_runtime_log(l))
        .collect()
}

/// Build every asset `config` (the graph read from `graph`) declares with
/// `build:`, writing each to [`output_path`]. A failed step fails the build,
/// naming the asset, the binding and the stack, with the step's
/// diagnostics.
pub fn build_all(config: &Value, graph: &Path, verbose: bool) -> Result<()> {
    let assets = parse(config, graph)?;
    if !assets
        .iter()
        .any(|a| matches!(a.source, Source::Build { .. }))
    {
        return Ok(());
    }
    let project_root = crate::project::root_for_config(graph);
    // Every step's binding names a stack before any step builds.
    for asset in &assets {
        if let Source::Build { binding, .. } = &asset.source {
            crate::stack::resolve_binding(binding, &project_root).map_err(|e| {
                Error::Config(format!("{}: {e}", step_label(graph, &asset.name, binding)))
            })?;
        }
    }
    let files = asset_files(&assets, &project_root);
    for asset in &assets {
        let Source::Build {
            binding,
            from,
            params,
        } = &asset.source
        else {
            continue;
        };
        // `parse` held every placeholder to an asset declared earlier, which
        // has built by now; it resolves to that asset's file.
        let file = |name: &str| {
            assets
                .iter()
                .zip(&files)
                .find(|(a, _)| a.name == name)
                .map(|(_, f)| f.clone())
        };
        let params = step_params(params, &file);
        let key = inputs_key(binding, from, &params);
        build_one_asset(
            &BuildStep {
                name: &asset.name,
                binding,
                from,
                params: &params,
                output: &output_path(&project_root, &key, &asset.name),
                work_dir: &work_dir(&project_root, &key, &asset.name),
            },
            graph,
            &project_root,
            verbose,
        )?;
    }
    Ok(())
}

/// How a refusal names one build step.
fn step_label(graph: &Path, name: &str, binding: &str) -> String {
    format!(
        "graph `{}`: asset '{name}' (`build: \"@{binding}\"`)",
        graph.display()
    )
}

/// One build step, its inputs resolved.
struct BuildStep<'a> {
    name: &'a str,
    binding: &'a str,
    from: &'a Path,
    params: &'a BTreeMap<String, Value>,
    /// Where its bytes land ([`output_path`]).
    output: &'a Path,
    /// Where its build-step graph and image are written ([`work_dir`]).
    work_dir: &'a Path,
}

fn build_one_asset(
    step: &BuildStep<'_>,
    graph: &Path,
    project_root: &Path,
    verbose: bool,
) -> Result<()> {
    let BuildStep {
        name,
        binding,
        from,
        params,
        output: target,
        work_dir: dir,
    } = *step;
    let what = step_label(graph, name, binding);
    if !from.exists() {
        return Err(Error::Config(format!(
            "{what}: `from:` {} does not exist",
            from.display()
        )));
    }
    std::fs::create_dir_all(dir)?;
    let stack = crate::stack::load_bound(
        binding,
        &crate::stack::IncludeContext {
            graph_dir: dir,
            project_root,
            store_root: None,
            params: &BTreeMap::new(),
        },
    )
    .map_err(|e| Error::Config(format!("{what}: {e}")))?;
    let what = format!("{what}, stack '{}'", stack.name);
    let exports: BTreeSet<String> = stack.exports.keys().cloned().collect();
    if !exports.contains("output") {
        return Err(Error::Config(format!(
            "{what}: the stack exports no `output` — a build step exports `output` \
             (OctetStream, the asset's bytes); it exports: {}",
            exports.iter().cloned().collect::<Vec<_>>().join(", ")
        )));
    }

    let step = build_step_graph(binding, from, params, &exports);
    let yaml = serde_yaml::to_string(&step)
        .map_err(|e| Error::Config(format!("{what}: serialise build-step graph: {e}")))?;
    let step_path = dir.join("build.yaml");
    std::fs::write(
        &step_path,
        format!(
            "# Auto-generated by `fluxor build {}` for asset '{name}'.\n\
             # DO NOT EDIT — overwritten on every build.\n{yaml}",
            graph.display()
        ),
    )?;
    // The step's image runs here, so it pins this node's providers even
    // inside a check.
    let built = crate::config::compose_to_run(|| {
        crate::build_one_from(&step_path, Some(&dir.join("node.img")), None, verbose)
    })
    .map_err(|e| Error::Config(format!("{what}: building its build-step graph: {e}")))?;

    let runtime = crate::project::linux_runtime(project_root);
    if !runtime.is_file() {
        return Err(Error::Config(format!(
            "{what}: no host runtime at {} to run the build step — run `fluxor sync`",
            runtime.display()
        )));
    }
    let output = std::process::Command::new(&runtime)
        .arg("--image")
        .arg(&built.output_path)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| Error::Config(format!("{what}: running {}: {e}", runtime.display())))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if verbose {
        eprint!("{stderr}");
    }
    let failure = if !output.status.success() {
        Some(match output.status.code() {
            Some(code) => format!("exited with status {code}"),
            None => format!("was stopped ({})", output.status),
        })
    } else if output.stdout.is_empty() {
        Some("produced no output".to_string())
    } else {
        None
    };
    if let Some(failure) = failure {
        // A stale asset from an earlier build must not stand in for this one.
        let _ = std::fs::remove_file(target);
        let lines = diagnostics(&stderr);
        let detail = if lines.is_empty() {
            "\n  (the build step wrote no diagnostics; `fluxor build -v` shows the runtime's log)"
                .to_string()
        } else {
            lines.iter().map(|l| format!("\n  {l}")).collect()
        };
        return Err(Error::Config(format!(
            "{what}: building from {} {failure}:{detail}",
            from.display()
        )));
    }
    crate::store_sync::write_file_atomic(target, &output.stdout, false)
        .map_err(|e| Error::Config(format!("{what}: {e}")))?;
    eprintln!(
        "  asset '{name}': {} bytes built by @{binding} (stack '{}') → {}",
        output.stdout.len(),
        stack.name,
        target.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph(yaml: &str) -> Value {
        serde_yaml::from_str(yaml).unwrap()
    }

    const DECLARED: &str = "target: linux\nassets:\n  - { name: page.doc, build: \"@compiler\", \
                            from: ../docs/page.html }\n  - { path: art/logo.png, name: logo }\n  \
                            - art/font.bin\nmodules:\n  - name: m\n    document: \
                            ${asset:page.doc}\n    logo: \"logo at ${asset:logo}\"\n    font: \
                            ${asset:font.bin}\n";

    #[test]
    fn entries_parse_with_paths_relative_to_the_graph() {
        let g = Path::new("/p/examples/probe/g.yaml");
        let assets = parse(&graph(DECLARED), g).unwrap();
        assert_eq!(
            assets,
            vec![
                Asset {
                    name: "page.doc".into(),
                    source: Source::Build {
                        binding: "compiler".into(),
                        from: "/p/examples/docs/page.html".into(),
                        params: BTreeMap::new(),
                    },
                },
                Asset {
                    name: "logo".into(),
                    source: Source::File("/p/examples/probe/art/logo.png".into()),
                },
                Asset {
                    name: "font.bin".into(),
                    source: Source::File("/p/examples/probe/art/font.bin".into()),
                },
            ]
        );
        let key = inputs_key(
            "compiler",
            Path::new("/p/examples/docs/page.html"),
            &BTreeMap::new(),
        );
        assert_eq!(
            asset_files(&assets, Path::new("/p")),
            [
                PathBuf::from(format!("/p/target/assets/{key}/page.doc")),
                PathBuf::from("/p/examples/probe/art/logo.png"),
                PathBuf::from("/p/examples/probe/art/font.bin"),
            ]
        );
    }

    #[test]
    fn malformed_entries_are_refused_naming_the_entry() {
        let g = Path::new("/p/g.yaml");
        let refuse = |entry: &str| {
            parse(&graph(&format!("assets:\n  - {entry}\n")), g)
                .unwrap_err()
                .to_string()
        };
        for (entry, want) in [
            (
                "{ name: a, path: x, build: \"@c\", from: y }",
                "takes `path:` or `build:`, not both",
            ),
            ("{ name: a, build: \"@c\" }", "needs `from:`"),
            ("{ build: \"@c\", from: y }", "needs a `name:`"),
            (
                "{ name: a, build: compiler, from: y }",
                "must name a bound stack, `@<name>`",
            ),
            (
                "{ name: a, path: x, from: y }",
                "`from:` belongs to a build step",
            ),
            ("{ name: a }", "names no file"),
            ("{ name: a, path: x, size: 3 }", "unknown key `size`"),
            (
                "{ name: a, path: x, params: { k: v } }",
                "`params:` belongs to a build step",
            ),
            (
                "{ name: a, build: \"@c\", from: y, params: [1] }",
                "`params:` must be a map",
            ),
            (
                "{ name: a, build: \"@c\", from: y, params: { input: z } }",
                "cannot set `input`",
            ),
            (
                "{ name: a, build: \"@c\", from: y, params: { k: [1] } }",
                "`params: k` must be a string, a number or a boolean",
            ),
            (
                "{ name: a, build: \"@c\", from: y, params: { k: \"${asset:b}\" } }",
                "names `${asset:b}`, which is not an asset declared before 'a'",
            ),
            ("{ name: a/b, path: x }", "'a/b' is not an asset name"),
            (
                "{ name: a, build: 3, from: y }",
                "`build:` must be a string",
            ),
            ("7", "must be a path, or a map"),
        ] {
            let e = refuse(entry);
            assert!(e.contains("graph `/p/g.yaml`: assets[0]: "), "{entry}: {e}");
            assert!(e.contains(want), "{entry}: {e}");
        }
        let e = parse(&graph("assets:\n  - { name: a, path: x }\n  - y/a\n"), g)
            .unwrap_err()
            .to_string();
        assert!(e.contains("assets[1]: asset 'a' is declared twice"), "{e}");
    }

    #[test]
    fn a_placeholder_is_a_bundle_url_on_wasm() {
        let mut g = graph(DECLARED);
        resolve_placeholders(
            &mut g,
            Path::new("/p/examples/probe/g.yaml"),
            "wasm",
            Path::new("/p"),
        )
        .unwrap();
        let m = &g["modules"][0];
        assert_eq!(m["document"], "asset://page.doc");
        assert_eq!(m["logo"], "logo at asset://logo");
        assert_eq!(m["font"], "asset://font.bin");
        // The declarations themselves are left as written.
        assert_eq!(g["assets"], graph(DECLARED)["assets"]);
    }

    #[test]
    fn a_placeholder_is_the_file_on_linux_built_or_not() {
        let mut g = graph(DECLARED);
        resolve_placeholders(
            &mut g,
            Path::new("/p/examples/probe/g.yaml"),
            "linux",
            Path::new("/p"),
        )
        .unwrap();
        let m = &g["modules"][0];
        let key = inputs_key(
            "compiler",
            Path::new("/p/examples/docs/page.html"),
            &BTreeMap::new(),
        );
        assert_eq!(m["document"], format!("/p/target/assets/{key}/page.doc"));
        assert_eq!(m["logo"], "logo at /p/examples/probe/art/logo.png");
        assert_eq!(m["font"], "/p/examples/probe/art/font.bin");
    }

    #[test]
    fn a_placeholder_is_refused_on_a_family_without_assets_and_when_unknown() {
        let g = Path::new("/p/examples/g.yaml");
        let e = resolve_placeholders(&mut graph(DECLARED), g, "esp32", Path::new("/p"))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("graph `/p/examples/g.yaml`: `${asset:page.doc}`: target family 'esp32' gives a module no asset")
                && e.contains("wasm")
                && e.contains("linux")
                && e.contains("rp2, bcm and uefi"),
            "{e}"
        );
        let mut unknown = graph(
            "target: wasm\nassets: [a.bin]\nmodules:\n  - { name: m, f: \"${asset:b.bin}\" }\n",
        );
        let e = resolve_placeholders(&mut unknown, g, "wasm", Path::new("/p"))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("graph `/p/examples/g.yaml`: module 'm': `f`: `${asset:b.bin}` names no asset — `assets:` declares: a.bin"),
            "{e}"
        );
        let mut none = graph("modules:\n  - { name: m, f: \"${asset:b.bin}\" }\n");
        let e = resolve_placeholders(&mut none, g, "linux", Path::new("/p"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("declares: none"), "{e}");
        // A graph naming no asset is untouched, whatever its target.
        let mut plain = graph("assets: [{ name: x, build: nope }]\nmodules: [{ name: m }]\n");
        resolve_placeholders(&mut plain, g, "esp32", Path::new("/p")).unwrap();
        assert_eq!(plain["modules"][0].get(ASSET_PARAMS_KEY), None);
    }

    /// A graph of two instances of one type and one of another, each naming
    /// assets by whole-value params.
    const PROGRAMS: &str =
        "assets:\n  - { path: art/fonts.gpk, name: fonts }\n  - art/page.doc\n  \
                            - art/rom.bin\nmodules:\n  - name: view_a\n    type: view\n    \
                            fonts: ${asset:fonts}\n    document: ${asset:page.doc}\n    \
                            backup: ${asset:fonts}\n  - name: view_b\n    type: view\n    \
                            params: { document: \"${asset:page.doc}\" }\n  - name: plain\n    \
                            speed: 3\n";

    fn resolved(yaml: &str, family: &str) -> Value {
        let mut g = graph(yaml);
        resolve_placeholders(
            &mut g,
            Path::new("/p/examples/probe/g.yaml"),
            family,
            Path::new("/p"),
        )
        .unwrap();
        g
    }

    fn refused(yaml: &str, family: &str) -> String {
        resolve_placeholders(
            &mut graph(yaml),
            Path::new("/p/examples/probe/g.yaml"),
            family,
            Path::new("/p"),
        )
        .unwrap_err()
        .to_string()
    }

    /// On a family whose node image carries programs, an asset is a program
    /// of the instance: appended to its `programs:` in the order of the
    /// param names, the param holding its slot. Two params of one instance
    /// naming one asset share the slot; each instance has its own copy.
    #[test]
    fn a_whole_value_placeholder_is_a_program_of_the_instance() {
        for family in ["rp2", "bcm", "uefi"] {
            let g = resolved(PROGRAMS, family);
            let a = &g["modules"][0];
            // Params sorted: backup, document, fonts.
            assert_eq!(a["backup"], "program:0", "{family}");
            assert_eq!(a["document"], "program:1");
            assert_eq!(a["fonts"], "program:0");
            assert_eq!(
                a["programs"],
                json!([
                    { "file": "/p/examples/probe/art/fonts.gpk", "kind": "fonts" },
                    { "file": "/p/examples/probe/art/page.doc", "kind": "page.doc" },
                ])
            );
            assert_eq!(a[ASSET_PARAMS_KEY], json!(["backup", "document", "fonts"]));
            let b = &g["modules"][1];
            assert_eq!(b["params"]["document"], "program:0");
            assert_eq!(
                b["programs"],
                json!([{ "file": "/p/examples/probe/art/page.doc", "kind": "page.doc" }])
            );
            assert_eq!(b[ASSET_PARAMS_KEY], json!(["document"]));
            // A module that names no asset is left as written.
            assert_eq!(g["modules"][2], graph(PROGRAMS)["modules"][2]);
        }
    }

    /// The instance's own programs keep their slots; assets follow them. A
    /// single `program:` becomes the first entry of `programs:`.
    #[test]
    fn asset_slots_follow_the_instances_declared_programs() {
        let one =
            "assets: [art/rom.bin]\nmodules:\n  - name: m\n    program: \"${file:boot.bin}\"\n    \
                   rom: ${asset:rom.bin}\n";
        let g = resolved(one, "rp2");
        let m = &g["modules"][0];
        assert_eq!(m.get("program"), None);
        assert_eq!(
            m["programs"],
            json!([
                "${file:boot.bin}",
                { "file": "/p/examples/probe/art/rom.bin", "kind": "rom.bin" },
            ])
        );
        assert_eq!(m["rom"], "program:1");

        let list = "assets: [art/rom.bin]\nmodules:\n  - name: m\n    programs: [a.bin, { file: b.bin, kind: b }]\n    \
                    rom: ${asset:rom.bin}\n";
        let g = resolved(list, "bcm");
        assert_eq!(g["modules"][0]["rom"], "program:2");
        assert_eq!(g["modules"][0]["programs"].as_array().unwrap().len(), 3);

        let both = "assets: [art/rom.bin]\nmodules:\n  - name: m\n    program: a.bin\n    programs: [b.bin]\n    \
                    rom: ${asset:rom.bin}\n";
        assert!(refused(both, "rp2").contains("`program` or `programs`, not both"));
    }

    /// The packed section a resolved graph yields names each instance as
    /// the owner of its own copy, by asset name.
    #[test]
    fn the_resolved_graph_packs_a_program_per_instance() {
        let dir = tempfile::tempdir().unwrap();
        let art = dir.path().join("art");
        std::fs::create_dir_all(&art).unwrap();
        std::fs::write(art.join("fonts.gpk"), b"FONTS-FONTS").unwrap();
        std::fs::write(art.join("page.doc"), [7u8; 5000]).unwrap();
        std::fs::write(art.join("rom.bin"), b"rom").unwrap();
        let mut g = graph(PROGRAMS);
        resolve_placeholders(&mut g, &dir.path().join("g.yaml"), "rp2", dir.path()).unwrap();
        let programs = crate::modules::collect_programs(&g).unwrap();
        let view = crate::hash::fnv1a_hash(b"view");
        let seen: Vec<(u32, u8, u8, u32, usize, &str, &str)> = programs
            .iter()
            .map(|p| {
                (
                    p.type_hash,
                    p.ordinal,
                    p.slot,
                    p.kind,
                    p.bytes.len(),
                    p.owner.as_str(),
                    p.label.as_str(),
                )
            })
            .collect();
        let fonts = crate::hash::fnv1a_hash(b"fonts");
        let page = crate::hash::fnv1a_hash(b"page.doc");
        assert_eq!(
            seen,
            [
                (view, 0, 0, fonts, 11, "view_a", "fonts"),
                (view, 0, 1, page, 5000, "view_a", "page.doc"),
                (view, 1, 0, page, 5000, "view_b", "page.doc"),
            ]
        );
        assert!(programs.iter().all(|p| p.format == [0u8; 32]));

        // The section, read back by the layout `kernel_abi::program` states.
        use fluxor_abi::kernel_abi::program as pg;
        let section = crate::modules::build_program_section(&programs).unwrap();
        let u32_at = |at: usize| u32::from_le_bytes(section[at..at + 4].try_into().unwrap());
        assert_eq!(u32_at(0), pg::SECTION_MAGIC);
        assert_eq!(section[5], 3);
        assert_eq!(u32_at(8) as usize, section.len());
        let mut regions = Vec::new();
        for (n, p) in programs.iter().enumerate().take(3) {
            let e = pg::HEADER_LEN + n * pg::ENTRY_LEN;
            assert_eq!(
                (u32_at(e), section[e + 4], section[e + 5]),
                (p.type_hash, p.ordinal, p.slot)
            );
            assert_eq!(u32_at(e + 8), p.kind);
            let (at, len) = (u32_at(e + 12) as usize, u32_at(e + 16) as usize);
            assert_eq!(&section[at..at + len], &p.bytes[..]);
            assert_eq!(at % pg::PROGRAM_ALIGN, 0);
            assert_eq!(&section[e + 32..e + 64], &[0u8; 32]);
            regions.push((u32_at(e + 20) as usize, u32_at(e + 24) as usize));
        }
        // One region an owner, on a page of its own, disjoint from the other's.
        assert_eq!(regions[0], regions[1]);
        assert_ne!(regions[0], regions[2]);
        assert!(regions.iter().all(|r| r.0 % pg::OWNER_ALIGN == 0));
        assert!(regions[0].0 + regions[0].1 <= regions[2].0);
        assert_eq!(
            crate::modules::program_regions(&programs).unwrap(),
            [
                crate::modules::ProgramRegion {
                    owner: "view_a".into(),
                    offset: regions[0].0,
                    len: regions[0].1
                },
                crate::modules::ProgramRegion {
                    owner: "view_b".into(),
                    offset: regions[2].0,
                    len: regions[2].1
                },
            ]
        );
    }

    /// Every family records the params that named an asset, whole value or
    /// embedded, and the values on wasm and linux are what a module opens
    /// through the `fs` contract.
    #[test]
    fn the_params_that_name_an_asset_are_recorded_on_every_family() {
        let wasm = resolved(DECLARED, "wasm");
        assert_eq!(
            wasm["modules"][0][ASSET_PARAMS_KEY],
            json!(["document", "font", "logo"])
        );
        let linux = resolved(DECLARED, "linux");
        assert_eq!(
            linux["modules"][0][ASSET_PARAMS_KEY],
            json!(["document", "font", "logo"])
        );
        let rp = resolved(PROGRAMS, "rp2");
        assert_eq!(
            rp["modules"][0][ASSET_PARAMS_KEY],
            json!(["backup", "document", "fonts"])
        );
        // Under `params:`, in a workload's module and inside a list.
        let nested = "target: linux\nassets: [a.bin]\nmodules:\n  - name: m\n    params: { f: \"${asset:a.bin}\" }\n    \
                      list: [x, \"${asset:a.bin}\"]\nworkloads:\n  - name: w\n    modules:\n      - { name: wm, g: \"${asset:a.bin}\" }\n\
                      data:\n  note: { content: \"${asset:a.bin}\" }\n";
        let g = resolved(nested, "linux");
        let file = "/p/examples/probe/a.bin";
        assert_eq!(g["modules"][0]["params"]["f"], file);
        assert_eq!(g["modules"][0]["list"][1], file);
        assert_eq!(g["modules"][0][ASSET_PARAMS_KEY], json!(["f", "list"]));
        assert_eq!(g["workloads"][0]["modules"][0]["g"], file);
        assert_eq!(
            g["workloads"][0]["modules"][0][ASSET_PARAMS_KEY],
            json!(["g"])
        );
        assert_eq!(g["data"]["note"]["content"], file);
    }

    /// A program reference is not a path to extend, and only a node
    /// module's param owns one.
    #[test]
    fn a_program_family_refuses_an_asset_that_is_not_a_whole_param_value() {
        let e = refused(DECLARED, "rp2");
        assert!(
            e.contains("module 'm': `logo`")
                && e.contains("\"logo at ${asset:logo}\"")
                && e.contains("embeds an asset in a longer value")
                && e.contains("program:<slot>"),
            "{e}"
        );
        let list = "assets: [a.bin]\nmodules:\n  - { name: m, list: [\"${asset:a.bin}\"] }\n";
        assert!(refused(list, "bcm").contains("module 'm': `list`"));
        let program = "assets: [a.bin]\nmodules:\n  - { name: m, program: \"${asset:a.bin}\" }\n";
        assert!(refused(program, "rp2").contains("a program is a file"));
        let elsewhere = "assets: [a.bin]\nmodules: [{ name: m }]\ndata:\n  note: { content: \"${asset:a.bin}\" }\n";
        let e = refused(elsewhere, "uefi");
        assert!(
            e.contains("`data` names an asset") && e.contains("whole"),
            "{e}"
        );
    }

    /// A workload image carries no program section: on a program family an
    /// asset in a workload's module is refused, naming it and the reason.
    #[test]
    fn a_program_family_refuses_an_asset_in_a_workloads_module() {
        let w = "assets: [a.bin]\nmodules: [{ name: node }]\nworkloads:\n  - name: w\n    modules:\n      - { name: wm, rom: \"${asset:a.bin}\" }\n";
        let e = refused(w, "bcm");
        assert!(
            e.contains("module 'wm': `rom`")
                && e.contains("a workload's modules own no programs")
                && e.contains("node image"),
            "{e}"
        );
        // The same graph on linux reads the file.
        assert_eq!(
            resolved(w, "linux")["workloads"][0]["modules"][0]["rom"],
            "/p/examples/probe/a.bin"
        );
    }

    /// The limits a section holds count assets, and the refusal names the
    /// one that crossed.
    #[test]
    fn the_asset_that_crosses_a_program_limit_is_named() {
        // 255 programs a graph: 254 declared, then two assets.
        let mut y = String::from("assets: [a.bin, b.bin]\nmodules:\n");
        for i in 0..254 {
            y.push_str(&format!("  - {{ name: m{i}, program: p.bin }}\n"));
        }
        y.push_str("  - { name: last, x: \"${asset:a.bin}\", y: \"${asset:b.bin}\" }\n");
        let e = refused(&y, "rp2");
        assert!(
            e.contains("module 'last': `y`")
                && e.contains("asset 'b.bin' is program 256 of the graph")
                && e.contains("at most 255"),
            "{e}"
        );
        // 256 programs an instance.
        let own: Vec<String> = (0..256).map(|i| format!("p{i}.bin")).collect();
        let y = format!(
            "assets: [a.bin]\nmodules:\n  - {{ name: m, programs: [{}], x: \"${{asset:a.bin}}\" }}\n",
            own.join(", ")
        );
        let e = refused(&y, "rp2");
        assert!(
            e.contains("asset 'a.bin' would be program 256 of the instance")
                && e.contains("at most 256"),
            "{e}"
        );
    }

    /// The key is the build's record, never written in a graph.
    #[test]
    fn a_written_asset_params_key_is_refused() {
        let g = Path::new("/p/g.yaml");
        for y in [
            "modules:\n  - { name: m, asset_params: [f], f: /some/file }\n",
            "modules: [{ name: n }]\nworkloads:\n  - name: w\n    modules:\n      - { name: m, asset_params: [] }\n",
        ] {
            let e = refuse_written_asset_params(&graph(y), g)
                .unwrap_err()
                .to_string();
            assert!(
                e.contains("graph `/p/g.yaml`: module 'm': `asset_params`")
                    && e.contains("not written in a graph"),
                "{e}"
            );
        }
        refuse_written_asset_params(&graph(DECLARED), g).unwrap();
    }

    #[test]
    fn the_build_step_graph_wires_what_the_stack_exports() {
        let all: BTreeSet<String> = ["output", "diagnostics", "exit"]
            .into_iter()
            .map(String::from)
            .collect();
        let g = build_step_graph(
            "compiler",
            Path::new("/p/docs/page.html"),
            &BTreeMap::new(),
            &all,
        );
        assert_eq!(
            g,
            json!({
                "target": "linux",
                "platform": { "cli": {} },
                "include": [{
                    "stack": "@compiler",
                    "as": "build",
                    "params": { "input": "/p/docs/page.html" },
                }],
                "wiring": [
                    { "from": "build.output", "to": "cli_out.bytes_in" },
                    { "from": "build.diagnostics", "to": "cli_out.err_in" },
                    { "from": "build.exit", "to": "cli_out.exit_in" },
                ],
            })
        );
        let only: BTreeSet<String> = ["output".to_string()].into();
        let params: BTreeMap<String, Value> = [
            ("fonts".to_string(), json!("/p/target/assets/a.gpk")),
            ("sizes".to_string(), json!(16)),
        ]
        .into();
        let g = build_step_graph("compiler", Path::new("/in"), &params, &only);
        assert_eq!(
            g["include"][0]["params"],
            json!({ "input": "/in", "fonts": "/p/target/assets/a.gpk", "sizes": 16 })
        );
        assert_eq!(
            g["wiring"],
            json!([{ "from": "build.output", "to": "cli_out.bytes_in" }])
        );
    }

    #[test]
    fn build_params_name_earlier_assets_by_their_files() {
        let g = Path::new("/p/examples/g.yaml");
        let config = graph(
            "assets:\n  - { name: a.gpk, build: \"@baker\", from: ../f.ttf, params: { sizes: \
             \"16,24\" } }\n  - { name: d, build: \"@c\", from: ../d.html, params: { fonts: \
             \"${asset:a.gpk},${asset:a.gpk}\" } }\n",
        );
        let assets = parse(&config, g).unwrap();
        let Source::Build { params, .. } = &assets[1].source else {
            panic!("a build step");
        };
        let files = asset_files(&assets, Path::new("/p"));
        let file = |name: &str| {
            assets
                .iter()
                .zip(&files)
                .find(|(a, _)| a.name == name)
                .map(|(_, f)| f.clone())
        };
        let a = files[0].display().to_string();
        assert_eq!(
            substitute(&params["fonts"], &file),
            json!(format!("{a},{a}"))
        );
        // The second step's key covers the file the first resolves to.
        let resolved = step_params(params, &file);
        assert_eq!(
            files[1],
            output_path(
                Path::new("/p"),
                &inputs_key("c", Path::new("/p/d.html"), &resolved),
                "d"
            )
        );
        // Declared after the step that names it: refused.
        let late = graph(
            "assets:\n  - { name: d, build: \"@c\", from: x, params: { f: \"${asset:a}\" } }\n  \
             - { name: a, path: y }\n",
        );
        let e = parse(&late, g).unwrap_err().to_string();
        assert!(e.contains("assets[0]: `params:` names `${asset:a}`"), "{e}");
    }

    /// Two graphs that build one asset name from different params keep
    /// their own bytes; the same inputs name the same file.
    #[test]
    fn one_name_built_from_different_inputs_lands_in_different_files() {
        let g = Path::new("/p/examples/g.yaml");
        let bake = |sizes: &str| {
            let config = graph(&format!(
                "assets:\n  - {{ name: mono.gpk, build: \"@baker\", from: ../f.ttf, params: \
                 {{ sizes: \"{sizes}\" }} }}\n"
            ));
            asset_files(&parse(&config, g).unwrap(), Path::new("/p")).remove(0)
        };
        let (a, b) = (bake("16"), bake("24"));
        assert_ne!(a, b, "different params, different files");
        assert_eq!(a, bake("16"), "the same inputs, the same file");
        for f in [&a, &b] {
            assert_eq!(f.file_name().and_then(|n| n.to_str()), Some("mono.gpk"));
            assert!(f.starts_with("/p/target/assets"));
        }
        // From another source or through another stack: another file too.
        let other = graph(
            "assets:\n  - { name: mono.gpk, build: \"@baker\", from: ../g.ttf, params: { sizes: \
             \"16\" } }\n",
        );
        assert_ne!(
            asset_files(&parse(&other, g).unwrap(), Path::new("/p"))[0],
            a
        );
    }

    #[test]
    fn diagnostics_drop_the_runtime_log() {
        let stderr = "[2026-11-08T10:00:00Z INFO  fluxor_linux] loading config\n\
                      page.html:3:7: error: unknown property `colour`\n\
                      [1762596000000 WARN  fluxor::kernel] slow step\n\n\
                      page.css:9:1: error: unclosed block\n";
        assert_eq!(
            diagnostics(stderr),
            [
                "page.html:3:7: error: unknown property `colour`",
                "page.css:9:1: error: unclosed block"
            ]
        );
    }

    #[test]
    fn relative_asset_paths_anchor_to_the_graph() {
        let mut g = graph(
            "assets:\n  - a/b.png\n  - { name: d, build: \"@c\", from: ../d.html }\n  \
             - { path: \"${param:rom}\", name: rom }\n  - /abs/x\n",
        );
        anchor(&mut g, Path::new("/p/examples"));
        assert_eq!(
            g["assets"],
            json!([
                "/p/examples/a/b.png",
                { "name": "d", "build": "@c", "from": "/p/d.html" },
                { "path": "${param:rom}", "name": "rom" },
                "/abs/x",
            ])
        );
    }

    /// A build step through a name the project does not bind is refused
    /// before anything is built, naming the asset and the line to add.
    #[test]
    fn an_unbound_build_step_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("fluxor.toml"),
            "[project]\nname = \"p\"\nversion = \"0.0.1\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("examples")).unwrap();
        std::fs::write(root.join("page.html"), "<p>").unwrap();
        let g = root.join("examples/g.yaml");
        let config =
            graph("assets:\n  - { name: page.doc, build: \"@compiler\", from: ../page.html }\n");
        let e = build_all(&config, &g, false).unwrap_err().to_string();
        assert!(
            e.contains(
                "asset 'page.doc' (`build: \"@compiler\"`): `compiler` is not bound — add \
                        `compiler = \"<stack>\"` under [uses.stacks]"
            ),
            "{e}"
        );
        assert!(!root.join("target/assets").exists());
    }
}
