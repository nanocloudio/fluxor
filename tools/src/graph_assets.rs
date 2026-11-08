//! A graph's `assets:`: the files it declares, the ones it builds at build
//! time through a bound stack, and the `${asset:<name>}` placeholder its
//! module params name one by.
//!
//! An entry is a path (`- some/file.png`, or `{ path: …, name: … }`), or a
//! build step: `{ name: <n>, build: "@<bound>", from: <path> }`. A build
//! step composes a Linux graph around the stack the project binds to
//! `<bound>` ([`build_step_graph`]), runs it on the project's host runtime
//! with `input` set to the absolute path of `from`, and keeps what it writes
//! to `output` as the asset's file, `target/assets/<n>` under the project.
//! From there a built asset is a file like any other: a wasm bundle bakes it
//! into its `fluxor.assets` section.
//!
//! `${asset:<name>}` resolves by the graph's target family: `asset://<name>`
//! on wasm, the asset file's absolute path on linux. Resolving it never runs
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
    /// (absolute; a file or a directory).
    Build { binding: String, from: PathBuf },
}

/// One `assets:` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asset {
    pub name: String,
    pub source: Source,
}

impl Asset {
    /// The file that holds the asset's bytes: a path entry's own file, a
    /// built one's output under the project.
    pub fn file(&self, project_root: &Path) -> PathBuf {
        match &self.source {
            Source::File(p) => p.clone(),
            Source::Build { .. } => output_path(project_root, &self.name),
        }
    }
}

/// Where a built asset's bytes land: `target/assets/<name>`.
pub fn output_path(project_root: &Path, name: &str) -> PathBuf {
    project_root.join("target/assets").join(name)
}

/// Where a built asset's build-step graph and its config are written:
/// `target/assets/.build/<name>/`, beside the outputs and never one of them.
pub fn work_dir(project_root: &Path, name: &str) -> PathBuf {
    project_root.join("target/assets/.build").join(name)
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
        .find(|k| !matches!(k.as_str(), "name" | "path" | "build" | "from"))
    {
        return Err(format!(
            "unknown key `{k}` (an entry takes name, and path or build + from)"
        ));
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
    Ok(parse(config, graph)?
        .into_iter()
        .map(|a| {
            let file = a.file(project_root);
            (a.name, file)
        })
        .collect())
}

// ============================================================================
// `${asset:<name>}`
// ============================================================================

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

/// Resolve every `${asset:<name>}` in `config`'s values: to `asset://<name>`
/// when `family` is `wasm`, to the asset file's absolute path when it is
/// `linux`. Substitution is on the parsed tree, never on text; a whole value
/// and a value embedding one both resolve. Nothing is built here.
pub fn resolve_placeholders(
    config: &mut Value,
    graph: &Path,
    family: &str,
    project_root: &Path,
) -> Result<()> {
    if !names_an_asset(config) {
        return Ok(());
    }
    let assets: BTreeMap<String, PathBuf> = parse(config, graph)?
        .into_iter()
        .map(|a| {
            let file = a.file(project_root);
            (a.name, file)
        })
        .collect();
    let value_of = |name: &str| -> std::result::Result<String, String> {
        let Some(file) = assets.get(name) else {
            let declared = if assets.is_empty() {
                "none".to_string()
            } else {
                assets.keys().cloned().collect::<Vec<_>>().join(", ")
            };
            return Err(format!(
                "`{PLACEHOLDER}{name}}}` names no asset — `assets:` declares: {declared}"
            ));
        };
        match family {
            "wasm" => Ok(format!("asset://{name}")),
            "linux" => Ok(file.display().to_string()),
            other => Err(format!(
                "`{PLACEHOLDER}{name}}}`: target family '{other}' has no asset area a module \
                 could open an asset from by name — `${{asset:}}` resolves on wasm (to `asset://<name>`) and on \
                 linux (to the asset file's absolute path)"
            )),
        }
    };
    fn walk(
        v: &mut Value,
        top: bool,
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
                    walk(item, false, value_of)?;
                }
            }
            Value::Object(m) => {
                for (k, item) in m.iter_mut() {
                    if !(top && k == ASSETS_KEY) {
                        walk(item, false, value_of)?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
    walk(config, true, &value_of)
        .map_err(|e| Error::Config(format!("graph `{}`: {e}", graph.display())))
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
pub fn build_step_graph(binding: &str, input: &Path, exports: &BTreeSet<String>) -> Value {
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
            "params": { "input": input.display().to_string() },
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
    for asset in &assets {
        let Source::Build { binding, from } = &asset.source else {
            continue;
        };
        build_one_asset(&asset.name, binding, from, graph, &project_root, verbose)?;
    }
    Ok(())
}

fn build_one_asset(
    name: &str,
    binding: &str,
    from: &Path,
    graph: &Path,
    project_root: &Path,
    verbose: bool,
) -> Result<()> {
    let what = format!(
        "graph `{}`: asset '{name}' (`build: \"@{binding}\"`)",
        graph.display()
    );
    if !from.exists() {
        return Err(Error::Config(format!(
            "{what}: `from:` {} does not exist",
            from.display()
        )));
    }
    let dir = work_dir(project_root, name);
    std::fs::create_dir_all(&dir)?;
    let stack = crate::stack::load_bound(
        binding,
        &crate::stack::IncludeContext {
            graph_dir: &dir,
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

    let step = build_step_graph(binding, from, &exports);
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
    let built = crate::build_one_from(&step_path, Some(&dir.join("config.bin")), None, verbose)
        .map_err(|e| Error::Config(format!("{what}: building its build-step graph: {e}")))?;
    let out_dir = built.output_path.parent().unwrap_or(&dir).to_path_buf();

    let runtime = crate::project::linux_runtime(project_root);
    if !runtime.is_file() {
        return Err(Error::Config(format!(
            "{what}: no host runtime at {} to run the build step — run `fluxor sync`",
            runtime.display()
        )));
    }
    let output = std::process::Command::new(&runtime)
        .arg("--config")
        .arg(out_dir.join("config.bin"))
        .arg("--modules")
        .arg(out_dir.join("modules.bin"))
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| Error::Config(format!("{what}: running {}: {e}", runtime.display())))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if verbose {
        eprint!("{stderr}");
    }
    let target = output_path(project_root, name);
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
        let _ = std::fs::remove_file(&target);
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
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&target, &output.stdout)?;
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
        assert_eq!(
            assets[0].file(Path::new("/p")),
            PathBuf::from("/p/target/assets/page.doc")
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
        assert_eq!(m["document"], "/p/target/assets/page.doc");
        assert_eq!(m["logo"], "logo at /p/examples/probe/art/logo.png");
        assert_eq!(m["font"], "/p/examples/probe/art/font.bin");
    }

    #[test]
    fn a_placeholder_is_refused_elsewhere_and_when_unknown() {
        let g = Path::new("/p/examples/g.yaml");
        let e = resolve_placeholders(&mut graph(DECLARED), g, "rp2", Path::new("/p"))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("graph `/p/examples/g.yaml`: `${asset:page.doc}`: target family 'rp2' has no asset area"),
            "{e}"
        );
        let mut unknown = graph(
            "target: wasm\nassets: [a.bin]\nmodules:\n  - { name: m, f: \"${asset:b.bin}\" }\n",
        );
        let e = resolve_placeholders(&mut unknown, g, "wasm", Path::new("/p"))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("graph `/p/examples/g.yaml`: `${asset:b.bin}` names no asset — `assets:` declares: a.bin"),
            "{e}"
        );
        let mut none = graph("modules:\n  - { name: m, f: \"${asset:b.bin}\" }\n");
        let e = resolve_placeholders(&mut none, g, "linux", Path::new("/p"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("declares: none"), "{e}");
        // A graph naming no asset is untouched, whatever its target.
        let mut plain = graph("assets: [{ name: x, build: nope }]\nmodules: [{ name: m }]\n");
        resolve_placeholders(&mut plain, g, "rp2", Path::new("/p")).unwrap();
    }

    #[test]
    fn the_build_step_graph_wires_what_the_stack_exports() {
        let all: BTreeSet<String> = ["output", "diagnostics", "exit"]
            .into_iter()
            .map(String::from)
            .collect();
        let g = build_step_graph("compiler", Path::new("/p/docs/page.html"), &all);
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
        let g = build_step_graph("compiler", Path::new("/in"), &only);
        assert_eq!(
            g["wiring"],
            json!([{ "from": "build.output", "to": "cli_out.bytes_in" }])
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
        assert!(!output_path(root, "page.doc").exists());
    }
}
