//! Cargo git-registry index management.
//!
//! Cargo expects a custom registry to look like a git repo with:
//!
//! - `config.json` at the root, declaring the download-URL template
//! - Per-crate metadata files, one JSON line per version, organised
//!   by name-prefix (`<aa>/<bb>/<full-name>` for 4+ char names)
//! - A `.git/` directory so cargo can `git fetch` to discover updates
//!
//! This module owns: the index-path computation, the per-version
//! JSON shape, the git commit invocation, and `config.json`
//! generation. Called from `publish.rs` on canonical publish (locals
//! never enter the index) and from `registry init` to bootstrap the
//! tree.
//!
//! Spec: https://doc.rust-lang.org/cargo/reference/registry-index.html

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

use crate::error::{Error, Result};
use crate::hash::file_sha256_full;

const REGISTRY_NAME: &str = "fluxor";

pub fn index_root(registry_root: &Path) -> PathBuf {
    registry_root.join("index")
}

/// Cargo's prefix-grouped path for a crate name. Mirrors the
/// rust-lang/crates.io-index convention so cargo can locate entries
/// without scanning. Returns `Err` for an empty name — cargo itself
/// rejects empty package names, but bare-string callers should get a
/// surfacable error rather than a panic.
pub fn index_path_for(name: &str) -> Result<PathBuf> {
    let lower = name.to_ascii_lowercase();
    let path = match lower.len() {
        0 => return Err(Error::Config("empty crate name".into())),
        1 => PathBuf::from("1").join(&lower),
        2 => PathBuf::from("2").join(&lower),
        3 => PathBuf::from("3").join(&lower[..1]).join(&lower),
        _ => PathBuf::from(&lower[..2]).join(&lower[2..4]).join(&lower),
    };
    Ok(path)
}

// ── config.json ───────────────────────────────────────────────────────

#[derive(Serialize)]
struct ConfigJson<'a> {
    /// Download URL template — cargo substitutes `{crate}` and
    /// `{version}` at fetch time. Points at the local cargo/ shelf
    /// where the `.crate` tarballs live.
    dl: String,
    /// API endpoint — `null` because publish goes through the
    /// `fluxor` CLI, not `cargo publish`.
    api: Option<&'a str>,
    /// Allowed registry names for transitive deps that reference
    /// other registries. Empty is fine for our use.
    #[serde(rename = "allowed-registries")]
    allowed_registries: &'a [&'a str],
}

pub fn write_config_json(index_root: &Path, registry_root: &Path) -> Result<()> {
    let cargo_dir = registry_root.join("cargo");
    let dl_template = format!("file://{}/{{crate}}-{{version}}.crate", cargo_dir.display());
    let cfg = ConfigJson {
        dl: dl_template,
        api: None,
        allowed_registries: &[],
    };
    let body = serde_json::to_string_pretty(&cfg)
        .map_err(|e| Error::Config(format!("serialise config.json: {e}")))?;
    fs::write(index_root.join("config.json"), body)?;
    Ok(())
}

// ── git wrapping ──────────────────────────────────────────────────────

fn run_git(dir: &Path, args: &[&str]) -> Result<()> {
    let status = Command::new("git")
        .args(args)
        .current_dir(dir)
        .status()
        .map_err(|e| Error::Config(format!("spawn git {args:?}: {e}")))?;
    if !status.success() {
        return Err(Error::Config(format!("git {args:?} failed: {status}")));
    }
    Ok(())
}

fn run_git_quiet(dir: &Path, args: &[&str]) -> Result<()> {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .map_err(|e| Error::Config(format!("spawn git {args:?}: {e}")))?;
    if !output.status.success() {
        return Err(Error::Config(format!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Verify `git` is on PATH. The registry index is a real git repo
/// (cargo expects to be able to fetch from it), so every code path
/// that touches the index depends on git being available. A clearer
/// up-front message beats `spawn git: No such file or directory`
/// emerging from deep inside an `ensure_initialised` chain.
fn require_git() -> Result<()> {
    let probe = Command::new("git").arg("--version").output();
    match probe {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(Error::Config(format!(
            "`git --version` failed (exit {}): {}",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        ))),
        Err(_) => Err(Error::Config(
            "`git` not found on PATH — install git to use `fluxor registry init` / `publish`"
                .into(),
        )),
    }
}

/// Initialise the index directory as a git repo + write
/// `config.json` + commit the initial state. Idempotent: a second
/// invocation against an already-initialised index re-writes
/// `config.json` (preserving the path template) and commits if it
/// changed.
pub fn ensure_initialised(registry_root: &Path) -> Result<PathBuf> {
    require_git()?;
    let root = index_root(registry_root);
    fs::create_dir_all(&root)?;
    let git_dir = root.join(".git");
    if !git_dir.exists() {
        run_git(&root, &["init", "--quiet", "--initial-branch=master"])?;
        // Local user identity for the registry's own commits. Avoids
        // depending on the developer's global git config.
        run_git_quiet(&root, &["config", "user.name", "fluxor"])?;
        run_git_quiet(&root, &["config", "user.email", "registry@fluxor.local"])?;
    }
    write_config_json(&root, registry_root)?;
    // Stage + commit if there are changes.
    run_git_quiet(&root, &["add", "config.json"])?;
    let diff = Command::new("git")
        .args(["diff", "--cached", "--quiet"])
        .current_dir(&root)
        .status()
        .ok();
    let has_staged = !matches!(diff.and_then(|s| s.code()), Some(0));
    if has_staged {
        run_git_quiet(
            &root,
            &["commit", "--quiet", "-m", "registry: bootstrap config.json"],
        )?;
    }
    Ok(root)
}

// ── Per-version entry ─────────────────────────────────────────────────

#[derive(Serialize, Debug)]
pub struct IndexEntry<'a> {
    pub name: &'a str,
    pub vers: &'a str,
    pub deps: Vec<IndexDep>,
    /// SHA-256 of the .crate tarball, hex.
    pub cksum: String,
    /// Feature → list of conditional deps. Empty maps fine.
    pub features: serde_json::Map<String, serde_json::Value>,
    pub yanked: bool,
}

#[derive(Serialize, Debug, Clone)]
pub struct IndexDep {
    pub name: String,
    pub req: String,
    pub features: Vec<String>,
    pub optional: bool,
    #[serde(rename = "default_features")]
    pub default_features: bool,
    pub target: Option<String>,
    pub kind: String,
    pub registry: Option<String>,
    pub package: Option<String>,
}

/// SHA-256 of a file, lowercase hex — the cksum form cargo's
/// per-version index lines record.
pub fn sha256_hex(path: &Path) -> Result<String> {
    file_sha256_full(path)
}

/// Append a JSON-per-line entry to the per-crate index file under
/// `index_root`. Creates the per-crate file if absent, otherwise
/// appends a new line. Refuses to add a version already present.
/// Stages + commits the change.
pub fn append_entry(registry_root: &Path, entry: &IndexEntry<'_>) -> Result<PathBuf> {
    let root = ensure_initialised(registry_root)?;
    let rel = index_path_for(entry.name)?;
    let abs = root.join(&rel);
    if let Some(parent) = abs.parent() {
        fs::create_dir_all(parent)?;
    }

    // Read existing entries (if any) and check for duplicate version.
    let existing = fs::read_to_string(&abs).unwrap_or_default();
    for line in existing.lines() {
        if line.trim().is_empty() {
            continue;
        }
        // Cheap version-extraction by parsing the line; avoid a full
        // schema dance — every entry is one JSON object with a
        // `vers` field at the top level.
        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if value
            .get("vers")
            .and_then(|v| v.as_str())
            .map(|v| v == entry.vers)
            .unwrap_or(false)
        {
            return Err(Error::Config(format!(
                "index already records {} {} — bump the crate's [package].version or yank the existing entry",
                entry.name, entry.vers
            )));
        }
    }

    let line = serde_json::to_string(entry)
        .map_err(|e| Error::Config(format!("serialise index entry: {e}")))?;
    let mut new_text = existing;
    if !new_text.is_empty() && !new_text.ends_with('\n') {
        new_text.push('\n');
    }
    new_text.push_str(&line);
    new_text.push('\n');
    fs::write(&abs, new_text)?;

    // Stage + commit. The relative path is always ASCII because
    // cargo enforces ASCII crate names; if a non-UTF-8 entry ever
    // does slip in, lossy conversion still produces a valid path
    // for `git add` (it just lowercases the diagnostic).
    let rel_str = rel.to_string_lossy();
    run_git_quiet(&root, &["add", rel_str.as_ref()])?;
    let commit_msg = format!("publish {} {}", entry.name, entry.vers);
    run_git_quiet(&root, &["commit", "--quiet", "-m", &commit_msg])?;

    Ok(abs)
}

// ── Cargo dep extraction ──────────────────────────────────────────────

/// Read a crate's `Cargo.toml` and convert its `[dependencies]` to
/// the cargo-index dep shape. Only the fields cargo cares about for
/// resolution are emitted. Workspace inheritance (`{ workspace = true
/// }`) is rejected loudly — `cargo package` should have rewritten it,
/// but if we ever pass the raw manifest we'd lose information.
pub fn extract_deps(crate_manifest_path: &Path) -> Result<Vec<IndexDep>> {
    let text = fs::read_to_string(crate_manifest_path)
        .map_err(|e| Error::Config(format!("read {}: {e}", crate_manifest_path.display())))?;
    let parsed: toml::Value = toml::from_str(&text)
        .map_err(|e| Error::Config(format!("parse {}: {e}", crate_manifest_path.display())))?;

    let mut out: Vec<IndexDep> = Vec::new();
    for (kind_label, table_name) in [
        ("normal", "dependencies"),
        ("build", "build-dependencies"),
        ("dev", "dev-dependencies"),
    ] {
        let Some(deps) = parsed.get(table_name).and_then(|v| v.as_table()) else {
            continue;
        };
        for (name, value) in deps {
            let dep = one_dep(name, value, kind_label)?;
            out.push(dep);
        }
    }
    // Target-conditional deps live under `[target."cfg(...)".dependencies]`.
    if let Some(target_table) = parsed.get("target").and_then(|v| v.as_table()) {
        for (target_pred, sub) in target_table {
            for (kind_label, table_name) in [
                ("normal", "dependencies"),
                ("build", "build-dependencies"),
                ("dev", "dev-dependencies"),
            ] {
                let Some(deps) = sub.get(table_name).and_then(|v| v.as_table()) else {
                    continue;
                };
                for (name, value) in deps {
                    let mut dep = one_dep(name, value, kind_label)?;
                    dep.target = Some(target_pred.clone());
                    out.push(dep);
                }
            }
        }
    }

    Ok(out)
}

fn one_dep(name: &str, value: &toml::Value, kind: &str) -> Result<IndexDep> {
    // Two wire forms: bare version string (`serde = "1"`) or table.
    if let Some(req) = value.as_str() {
        return Ok(IndexDep {
            name: name.to_string(),
            req: req.to_string(),
            features: Vec::new(),
            optional: false,
            default_features: true,
            target: None,
            kind: kind.to_string(),
            registry: None,
            package: None,
        });
    }
    let Some(table) = value.as_table() else {
        return Err(Error::Config(format!(
            "dependency `{name}` has unexpected shape: {value:?}"
        )));
    };
    // Reject workspace inheritance in any form. `cargo package`
    // normalises every workspace reference into a concrete value
    // before writing the bundled Cargo.toml; an indexer that ever
    // sees an un-normalised manifest must refuse rather than emit
    // a misleading dep entry.
    if table.get("workspace").and_then(|v| v.as_bool()) == Some(true) {
        return Err(Error::Config(format!(
            "dependency `{name}` uses `workspace = true` — \
             `cargo package` should have rewritten it; refusing to index a raw workspace dep"
        )));
    }
    for field in [
        "version",
        "features",
        "default-features",
        "registry",
        "optional",
    ] {
        if matches!(
            table
                .get(field)
                .and_then(|v| v.as_table())
                .and_then(|t| t.get("workspace"))
                .and_then(|v| v.as_bool()),
            Some(true)
        ) {
            return Err(Error::Config(format!(
                "dependency `{name}` uses `{field}.workspace = true` — \
                 `cargo package` should have rewritten it; refusing to index a partially-inherited workspace dep"
            )));
        }
    }
    let req = table
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("*")
        .to_string();
    let features = table
        .get("features")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let optional = table
        .get("optional")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let default_features = table
        .get("default-features")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let registry = table
        .get("registry")
        .and_then(|v| v.as_str())
        .map(String::from);
    let package = table
        .get("package")
        .and_then(|v| v.as_str())
        .map(String::from);
    Ok(IndexDep {
        name: name.to_string(),
        req,
        features,
        optional,
        default_features,
        target: None,
        kind: kind.to_string(),
        registry,
        package,
    })
}

// ── CLI ───────────────────────────────────────────────────────────────

pub fn cmd_registry_init() -> Result<()> {
    let root = crate::registry::registry_root()?;
    crate::registry::ensure_layout(&root)?;
    let index = ensure_initialised(&root)?;
    println!("initialised registry index: {}", index.display());
    println!(
        "download template: file://{}/cargo/{{crate}}-{{version}}.crate",
        root.display()
    );
    println!();
    println!("next step: run `fluxor registry setup-cargo` to add the");
    println!("`[registries.{REGISTRY_NAME}]` alias to ~/.cargo/config.toml,");
    println!("then in a downstream project declare:");
    println!();
    println!("    [dependencies]");
    println!("    fluxor-abi = {{ version = \"0.1\", registry = \"{REGISTRY_NAME}\" }}");
    Ok(())
}

pub fn cmd_registry_setup_cargo() -> Result<()> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| Error::Config("cannot resolve cargo config: $HOME is not set".into()))?;
    let cargo_dir = PathBuf::from(home).join(".cargo");
    fs::create_dir_all(&cargo_dir)?;
    let config_path = cargo_dir.join("config.toml");

    let registry_root = crate::registry::registry_root()?;
    let index_url = format!("file://{}", index_root(&registry_root).display());

    // Read existing content (if any) and rewrite the
    // [registries.fluxor] block between sentinels.
    let existing = fs::read_to_string(&config_path).unwrap_or_default();
    let new_text = upsert_registry_block(&existing, &index_url);
    fs::write(&config_path, new_text)?;
    println!(
        "updated {} with [registries.{REGISTRY_NAME}] alias",
        config_path.display()
    );
    println!("index URL: {index_url}");
    Ok(())
}

const SENTINEL_BEGIN: &str = "# >>> BEGIN fluxor-managed registry alias >>>";
const SENTINEL_END: &str = "# <<< END fluxor-managed registry alias <<<";

fn upsert_registry_block(existing: &str, index_url: &str) -> String {
    let block = format!(
        "{SENTINEL_BEGIN}\n\
         [registries.{REGISTRY_NAME}]\n\
         index = \"{index_url}\"\n\
         {SENTINEL_END}\n"
    );

    // If sentinels are present, replace the block between them.
    if let (Some(start), Some(end)) = (existing.find(SENTINEL_BEGIN), existing.find(SENTINEL_END)) {
        let end_line_end = existing[end..]
            .find('\n')
            .map(|n| end + n + 1)
            .unwrap_or(existing.len());
        let mut out = String::with_capacity(existing.len() + block.len());
        out.push_str(&existing[..start]);
        out.push_str(&block);
        out.push_str(&existing[end_line_end..]);
        return out;
    }

    // Otherwise append (with a separator newline if needed).
    let mut out = existing.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(&block);
    out
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_path_for_one_char() {
        assert_eq!(index_path_for("a").unwrap(), PathBuf::from("1").join("a"));
    }

    #[test]
    fn index_path_for_two_chars() {
        assert_eq!(index_path_for("ab").unwrap(), PathBuf::from("2").join("ab"));
    }

    #[test]
    fn index_path_for_three_chars() {
        assert_eq!(
            index_path_for("abc").unwrap(),
            PathBuf::from("3").join("a").join("abc")
        );
    }

    #[test]
    fn index_path_for_long_name() {
        assert_eq!(
            index_path_for("fluxor-abi").unwrap(),
            PathBuf::from("fl").join("ux").join("fluxor-abi")
        );
    }

    #[test]
    fn index_path_for_empty_errors() {
        assert!(index_path_for("").is_err());
    }

    #[test]
    fn upsert_registry_block_inserts_when_absent() {
        let original = "[other]\nkey = \"value\"\n";
        let out = upsert_registry_block(original, "file:///x");
        assert!(out.contains("[other]"));
        assert!(out.contains("[registries.fluxor]"));
        assert!(out.contains("file:///x"));
    }

    #[test]
    fn upsert_registry_block_replaces_when_present() {
        let original = format!(
            "[other]\nkey = \"v\"\n\n{SENTINEL_BEGIN}\n\
             [registries.fluxor]\n\
             index = \"file:///old\"\n\
             {SENTINEL_END}\n\
             [more]\nx = 1\n"
        );
        let out = upsert_registry_block(&original, "file:///new");
        assert!(out.contains("file:///new"));
        assert!(!out.contains("file:///old"));
        assert!(out.contains("[other]"));
        assert!(out.contains("[more]"));
    }

    #[test]
    fn extract_deps_parses_bare_version_string() {
        let toml_str = r#"
            [package]
            name = "x"
            version = "0.1.0"
            [dependencies]
            serde = "1"
        "#;
        let tmp = std::env::temp_dir().join(format!(
            "fluxor_cargo_index_test_{}.toml",
            std::process::id()
        ));
        std::fs::write(&tmp, toml_str).unwrap();
        let deps = extract_deps(&tmp).unwrap();
        std::fs::remove_file(&tmp).ok();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "serde");
        assert_eq!(deps[0].req, "1");
        assert_eq!(deps[0].kind, "normal");
    }
}
