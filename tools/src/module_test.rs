//! `fluxor modules test` — unit-test a module's `include!`d cores on the host.
//!
//! A `.fmod` core is `no_std`, no-alloc source that is `include!`d rather than
//! linked, so `cargo test` cannot reach it: there is no crate to test. Today
//! every project works around that by hand-writing a crate whose only job is to
//! mount the cores (chronicle's `chronicle-bytecode` is 237 lines of exactly
//! that). This runs the tests without the crate.
//!
//! WHY THE MODULE DECLARES ITS HARNESS. Mounting cannot be derived: the include
//! order is load-bearing (ed25519 needs the SHA-512 in sha384.rs), some cores
//! need a `SyscallTable` in scope, and some reference items from others. Only
//! the module knows its own set. So the manifest names a harness file, the
//! harness does the mounting exactly as the module does, and fluxor owns the
//! part that is mechanical: generating a crate around it and running it.
//!
//!   # modules/app/thing/manifest.toml
//!   [test]
//!   harness = "tests/harness.rs"
//!
//! The harness file is mounted into the generated crate as a `#[path]`
//! module, so it may open with inner doc comments and use
//! `#[path = "../mod.rs"] mod x;` to mount its module's root — the
//! generated crate enables the `host-test` feature, disarming the
//! module sources' `no_std`/`no_mangle` gates.
//!
//! The generated crate is disposable and lives under the project's target dir,
//! so it never pollutes the source tree and is rebuilt from scratch when the
//! harness changes.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Error, Result};

/// A module that declares a test harness.
struct Harness {
    module: String,
    /// Absolute path to the harness source.
    path: PathBuf,
    /// The module's DEFAULT variant feature set (RFC module_variants), so the
    /// harness tests the same cfg surface the unsuffixed `.fmod` ships with.
    /// Empty for variant-less modules. Without this, a harness would compile
    /// every gated feature OUT and its tests would silently not exercise what
    /// the default artifact actually carries.
    features: Vec<String>,
}

/// Harnesses that resolve to a file on disk — what the phase would run,
/// and the condition for the lifecycle `test` verb to run it at all.
pub fn resolved_harness_count(project_root: &Path) -> usize {
    discover(project_root).len()
}

/// Manifests that *declare* `[test] harness`, whether or not the file
/// they name exists. The gap between this and
/// [`resolved_harness_count`] is a phase that would run nothing while
/// the project says it has tests, so `fluxor ci` compares the two
/// rather than silently omitting the phase.
pub fn declared_harness_count(project_root: &Path) -> usize {
    let mut n = 0;
    for d in crate::manifest::MODULE_TIERS {
        let Ok(entries) = fs::read_dir(project_root.join(d)) else {
            continue;
        };
        for e in entries.flatten() {
            let text = fs::read_to_string(e.path().join("manifest.toml")).unwrap_or_default();
            if toml::from_str::<toml::Value>(&text)
                .ok()
                .and_then(|d| harness_path(&d))
                .is_some()
            {
                n += 1;
            }
        }
    }
    n
}

fn discover(project_root: &Path) -> Vec<Harness> {
    // The one tier list, so a `[test]` harness is run wherever the
    // module lives — fixtures and platform tiers included.
    let mut out = Vec::new();
    for d in crate::manifest::MODULE_TIERS {
        let root = project_root.join(d);
        let Ok(entries) = fs::read_dir(&root) else {
            continue;
        };
        for e in entries.flatten() {
            let dir = e.path();
            let manifest = dir.join("manifest.toml");
            let Ok(text) = fs::read_to_string(&manifest) else {
                continue;
            };
            let Ok(doc) = toml::from_str::<toml::Value>(&text) else {
                continue;
            };
            let Some(rel) = harness_path(&doc) else {
                continue;
            };
            let path = dir.join(&rel);
            if path.is_file() {
                out.push(Harness {
                    module: dir
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    path,
                    features: default_variant_features(&doc),
                });
            }
        }
    }
    out.sort_by(|a, b| a.module.cmp(&b.module));
    out
}

/// `[test] harness = "..."`, relative to the manifest's directory.
fn harness_path(manifest: &toml::Value) -> Option<String> {
    manifest
        .get("test")?
        .get("harness")?
        .as_str()
        .map(str::to_string)
}

/// The `features` of the `default = true` `[[variant]]`, empty when the
/// module declares no variants (the common case).
///
/// Read through the TOML parser rather than by hand: a `features` array
/// split across lines is legal and a line reader returns empty for it,
/// which is silently the wrong answer — the harness would then compile
/// every gated feature out, the exact miss this field exists to close.
fn default_variant_features(manifest: &toml::Value) -> Vec<String> {
    manifest
        .get("variant")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .find(|v| v.get("default").and_then(toml::Value::as_bool) == Some(true))
        .and_then(|v| v.get("features"))
        .and_then(toml::Value::as_array)
        .map(|fs| {
            fs.iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Generate a throwaway crate that mounts `h` and run `cargo test` in it.
fn run_one(h: &Harness, out_root: &Path, verbose: bool) -> Result<bool> {
    let dir = out_root.join(format!("moduletest-{}", h.module));
    fs::create_dir_all(dir.join("src")).map_err(Error::Io)?;

    // The default-variant features are declared AND defaulted, so the harness
    // compiles the exact cfg surface the unsuffixed `.fmod` ships with.
    let mut feat_decl = String::new();
    let mut feat_default = String::from("\"host-test\"");
    for f in &h.features {
        feat_decl.push_str(&format!("{f:?} = []\n"));
        feat_default.push_str(&format!(", {f:?}"));
    }
    fs::write(
        dir.join("Cargo.toml"),
        format!(
            "[package]\nname = \"moduletest_{}\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
             [lib]\npath = \"src/lib.rs\"\n[workspace]\n\
             [features]\ndefault = [{feat_default}]\nhost-test = []\n{feat_decl}",
            h.module.replace('-', "_")
        ),
    )
    .map_err(Error::Io)?;

    // `#[path]`, not `include!`: a mounted module file may open with
    // inner doc comments and `#![cfg_attr(...)]` attributes, which
    // rustc rejects when macro-spliced but accepts in a real module
    // file. Relative `include!`/`#[path]` inside the harness resolve
    // against the harness file's own directory either way, so the
    // harness keeps writing `include!("../../common/x.rs")` /
    // `#[path = "../mod.rs"]` exactly as the module does.
    //
    // `pub`: the mounted cores are only *used* by their inline tests,
    // so in the non-test compile of this crate every item would be
    // dead code. Public reachability (here and via `pub mod` mounts
    // inside the harness) is what marks them as exported API instead
    // of warning noise.
    fs::write(
        dir.join("src/lib.rs"),
        format!("#[path = r\"{}\"]\npub mod harness;\n", h.path.display()),
    )
    .map_err(Error::Io)?;

    let mut cmd = Command::new("cargo");
    cmd.arg("test").current_dir(&dir);
    // Pin the HOST triple explicitly: the generated crate lives inside
    // the project tree, so a bare `cargo test` inherits the repo's
    // `.cargo/config` default target — a bare-metal triple in module
    // projects, which has no std and no test runner.
    cmd.args(["--target", host_triple()]);
    if !verbose {
        cmd.arg("--quiet");
    }
    let status = cmd.status().map_err(Error::Io)?;
    Ok(status.success())
}

/// The triple this tool was built for — by construction the host that
/// is running it, and therefore the right `--target` for host tests.
fn host_triple() -> &'static str {
    env!("FLUXOR_HOST_TRIPLE")
}

/// `fluxor modules test [--module NAME]`.
pub fn cmd_test(project_root: Option<&Path>, module: Option<&str>, verbose: bool) -> Result<()> {
    let root = match project_root {
        Some(p) => p.to_path_buf(),
        None => std::env::current_dir().map_err(Error::Io)?,
    };
    let mut harnesses = discover(&root);
    if let Some(name) = module {
        harnesses.retain(|h| h.module == name);
        if harnesses.is_empty() {
            return Err(Error::Config(format!(
                "no module `{name}` declares a [test] harness"
            )));
        }
    }
    if harnesses.is_empty() {
        println!(
            "no module declares a [test] harness — add one to a module manifest:\n\
             \n  [test]\n  harness = \"tests/harness.rs\"\n"
        );
        return Ok(());
    }

    let out_root = root.join("target/fluxor/moduletests");
    let mut failed = Vec::new();
    for h in &harnesses {
        println!("test {} ({})", h.module, h.path.display());
        match run_one(h, &out_root, verbose) {
            Ok(true) => {}
            Ok(false) => failed.push(h.module.clone()),
            Err(e) => {
                eprintln!("  error: {e}");
                failed.push(h.module.clone());
            }
        }
    }
    println!(
        "\nModule tests: {} passed, {} failed",
        harnesses.len() - failed.len(),
        failed.len()
    );
    if failed.is_empty() {
        Ok(())
    } else {
        Err(Error::Config(format!("failed: {}", failed.join(", "))))
    }
}

#[cfg(test)]
mod tests {
    use super::{default_variant_features, harness_path};

    fn doc(src: &str) -> toml::Value {
        toml::from_str(src).expect("fixture parses")
    }

    #[test]
    fn a_default_variant_yields_its_feature_set() {
        let m = doc(r#"
version = "1.0.0"
[[variant]]
name = "web"
features = ["h1", "ws"]
[[variant]]
name = "full"
features = ["h1", "h2", "ws"]
default = true
"#);
        assert_eq!(default_variant_features(&m), vec!["h1", "h2", "ws"]);
    }

    #[test]
    fn a_variantless_manifest_yields_no_features() {
        assert!(default_variant_features(&doc("version = \"1.0.0\"\n")).is_empty());
    }

    /// A multi-line array is legal TOML, and the hand-rolled line reader
    /// this replaced returned empty for it — silently compiling the
    /// harness without the features it is meant to pin.
    #[test]
    fn a_features_array_split_across_lines_is_read_whole() {
        let m = doc(r#"
[[variant]]
name = "full"
default = true
features = [
    "h1",
    "h2",
]
"#);
        assert_eq!(default_variant_features(&m), vec!["h1", "h2"]);
    }

    #[test]
    fn harness_path_reads_the_test_table() {
        let m = doc("[test]\nharness = \"tests/x.rs\"\n");
        assert_eq!(harness_path(&m).as_deref(), Some("tests/x.rs"));
        assert!(harness_path(&doc("version = \"1\"\n")).is_none());
    }
}
