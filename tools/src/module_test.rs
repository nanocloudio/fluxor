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
}

/// Discover every module under `modules/**` whose manifest declares `[test]`.
/// True when any module manifest declares a `[test] harness` — the
/// condition for `fluxor ci` to run the module-test phase at all.
pub fn has_harnesses(project_root: &Path) -> bool {
    !discover(project_root).is_empty()
}

fn discover(project_root: &Path) -> Vec<Harness> {
    // Flat `modules/*` covers consumer projects (zedex-style layout);
    // the tier dirs cover fluxor's own tree. A tier dir has no
    // manifest.toml of its own, so scanning `modules` flat can't
    // double-count its children.
    const DIRS: [&str; 4] = [
        "modules",
        "modules/drivers",
        "modules/foundation",
        "modules/app",
    ];
    let mut out = Vec::new();
    for d in DIRS {
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
            let Some(rel) = harness_path(&text) else {
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
                });
            }
        }
    }
    out.sort_by(|a, b| a.module.cmp(&b.module));
    out
}

/// Read `[test] harness = "..."` without pulling in a TOML dependency for one
/// key: the manifests are small and this keeps the reader obvious.
fn harness_path(manifest: &str) -> Option<String> {
    let mut in_test = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_test = t == "[test]";
            continue;
        }
        if !in_test {
            continue;
        }
        let Some((k, v)) = t.split_once('=') else {
            continue;
        };
        if k.trim() != "harness" {
            continue;
        }
        return Some(v.trim().trim_matches('"').to_string());
    }
    None
}

/// Generate a throwaway crate that mounts `h` and run `cargo test` in it.
fn run_one(h: &Harness, out_root: &Path, verbose: bool) -> Result<bool> {
    let dir = out_root.join(format!("moduletest-{}", h.module));
    fs::create_dir_all(dir.join("src")).map_err(Error::Io)?;

    fs::write(
        dir.join("Cargo.toml"),
        format!(
            "[package]\nname = \"moduletest_{}\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
             [lib]\npath = \"src/lib.rs\"\n[workspace]\n\
             [features]\ndefault = [\"host-test\"]\nhost-test = []\n",
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
