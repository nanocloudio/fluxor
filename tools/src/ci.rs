//! `fluxor ci` — orchestrate the full CI gate.
//!
//! Phases run in sequence; **every phase runs even when an earlier
//! one fails**, so a single CI run surfaces every problem rather than
//! the first one. The final exit code is the OR of every phase's
//! exit code.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::error::{Error, Result};
use crate::hygiene;
use crate::modules_build;

/// Per-phase result.
#[derive(Debug, Clone)]
pub struct PhaseResult {
    pub name: &'static str,
    pub status: PhaseStatus,
    pub elapsed_ms: u128,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseStatus {
    Ok,
    Failed,
    Skipped,
}

impl PhaseStatus {
    pub fn label(self) -> &'static str {
        match self {
            PhaseStatus::Ok => "ok",
            PhaseStatus::Failed => "FAILED",
            PhaseStatus::Skipped => "skipped",
        }
    }
}

/// Skip flags for local iteration; production CI rejects all skips.
#[derive(Debug, Default, Clone)]
pub struct SkipSet {
    pub cargo: bool,
    pub modules: bool,
    pub lint: bool,
    pub hygiene: bool,
    pub templates: bool,
}

impl SkipSet {
    pub fn from_strs(skip: &[String]) -> std::result::Result<Self, String> {
        let mut s = Self::default();
        for raw in skip {
            for v in raw.split(',') {
                match v.trim() {
                    "" => {}
                    "cargo" => s.cargo = true,
                    "modules" => s.modules = true,
                    "lint" => s.lint = true,
                    "hygiene" => s.hygiene = true,
                    "templates" => s.templates = true,
                    other => return Err(format!("unknown --skip phase: {other}")),
                }
            }
        }
        Ok(s)
    }
}

/// Drive the full pipeline. Returns the phase results in order plus
/// the aggregate exit status (`ok()` is true iff every non-skipped
/// phase passed).
pub fn run(project_root: &Path, skip: &SkipSet, verbose: bool) -> Result<Vec<PhaseResult>> {
    let in_ci = std::env::var_os("CI").is_some();
    if in_ci && (skip.cargo || skip.modules || skip.lint || skip.hygiene || skip.templates) {
        return Err(Error::Config(
            "`--skip` is rejected when $CI is set; CI must run the full pipeline".to_string(),
        ));
    }
    let mut results = Vec::new();

    // ───── Phase 1.1: fmt-check ─────────────────────────────────────
    results.push(if skip.lint {
        skipped("fmt-check")
    } else {
        run_step("fmt-check", verbose, || {
            cargo_in(project_root, &["fmt", "--all", "--", "--check"])
        })
    });

    // ───── Phase 1.2: clippy ────────────────────────────────────────
    // The fluxor workspace mixes a host CLI with no_std embedded
    // crates that don't compile under the workspace's default-feature
    // path, so clippy runs per-target like the kernel build matrix.
    // Downstream consumers (whose `Cargo.toml` doesn't declare the
    // kernel features) run the single-invocation form instead.
    let kernel_workspace = is_fluxor_kernel_workspace(project_root);
    let clippy_label = if kernel_workspace {
        "clippy (kernel matrix + tools)"
    } else {
        "clippy"
    };
    results.push(if skip.lint {
        skipped(clippy_label)
    } else {
        run_step(clippy_label, verbose, || {
            if kernel_workspace {
                clippy_matrix(project_root)
            } else {
                clippy_downstream(project_root)
            }
        })
    });

    // ───── Phase 1.3: workspace [lints] opt-in audit ────────────────
    results.push(if skip.lint {
        skipped("workspace-lint-opt-in")
    } else {
        run_step("workspace-lint-opt-in", verbose, || {
            check_workspace_lint_optin(project_root)
        })
    });

    // ───── Phase 1.4: hygiene ───────────────────────────────────────
    results.push(if skip.hygiene {
        skipped("hygiene")
    } else {
        run_step("hygiene", verbose, || run_hygiene(project_root))
    });

    // ───── Phase 1.45: observability instrumentation contract ───────
    //
    // Enforce standards/observability.md §6: every data-moving module
    // either declares `[observability]` metrics/spans or carries an
    // `exempt` reason. Strict (a gap is an error, not a warning), so a
    // new byte-moving module can't land uninstrumented and unexplained.
    results.push(if skip.hygiene {
        skipped("observability")
    } else {
        run_step("observability", verbose, || run_observability(project_root))
    });

    // ───── Phase 1.46: presentation placement ───────────────────────
    //
    // Enforce rfc_adaptive_presentation.md §9: run the placement resolver
    // over every config's `presentation.shell` against the surface it
    // targets, and fail on any `essential` control that can't be surfaced
    // there (no plane + no `bind_physical`). Stops a control going silently
    // dead on a constrained device (e.g. a screenless rp2350 + I2S speaker).
    results.push(if skip.lint {
        skipped("presentation")
    } else {
        run_step("presentation", verbose, || run_presentation(project_root))
    });

    // ───── Phase 1.5: template render ───────────────────────────────
    results.push(if skip.templates {
        skipped("template-render")
    } else {
        run_step("template-render", verbose, || check_templates(project_root))
    });

    // ───── Phase 1.6: version-skew ──────────────────────────────────
    results.push(run_step("version-skew", verbose, || {
        check_version_skew(project_root)
    }));

    // ───── Phase 1.7: lockfile consistency ──────────────────────────
    //
    // When the project declares `[dependencies]`, the committed
    // `fluxor.lock` must match what the resolver would produce today
    // against the local registry. Projects without `[dependencies]`
    // skip cleanly — no lockfile is expected.
    results.push(run_step("lockfile-consistency", verbose, || {
        check_lockfile_consistency(project_root)
    }));

    // ───── Phase 2: cargo unit + library tests ──────────────────────
    //
    // For fluxor itself, run from `tools/` rather than workspace
    // root: the kernel's default features pull in embedded crates
    // that don't compile on the host. The Makefile's `make test`
    // follows the same pattern (cd tools && cargo test --all-targets
    // --all-features). Downstreams may declare their own host-tools
    // sub-crate via `[ci.cargo] host_tools_crate = "tools"`; absent
    // that, this phase is skipped with a clear reason rather than
    // failing on a missing directory.
    let host_tools_crate = load_host_tools_crate(project_root);
    let tools_path = host_tools_crate.as_ref().map(|c| project_root.join(c));
    results.push(if skip.cargo {
        skipped("cargo-test (tools)")
    } else {
        match tools_path.as_ref() {
            Some(p) if p.is_dir() => run_step("cargo-test (tools)", verbose, || {
                cargo_in(p, &["test", "--all-targets", "--all-features"])
            }),
            Some(p) => PhaseResult {
                name: "cargo-test (tools)",
                status: PhaseStatus::Skipped,
                elapsed_ms: 0,
                message: format!("no host-tools crate at {}", p.display()),
            },
            None => PhaseResult {
                name: "cargo-test (tools)",
                status: PhaseStatus::Skipped,
                elapsed_ms: 0,
                message: "no host-tools crate (set `[ci.cargo] host_tools_crate` to enable)"
                    .to_string(),
            },
        }
    });

    // ───── Phase 3: modules build ───────────────────────────────────
    results.push(if skip.modules {
        skipped("modules-build (strict)")
    } else {
        run_step("modules-build (strict)", verbose, || {
            run_modules_build_strict(project_root, verbose)
        })
    });

    // ───── Phase 4: cargo integration / harness tests ───────────────
    //
    // The harness is a sub-workspace at `tests/harness/`. Downstream
    // projects that vendor fluxor without the harness see this phase
    // marked skipped rather than failed.
    let harness_path = project_root.join("tests/harness");
    results.push(if skip.cargo {
        skipped("cargo-test (harness)")
    } else if !harness_path.exists() {
        PhaseResult {
            name: "cargo-test (harness)",
            status: PhaseStatus::Skipped,
            elapsed_ms: 0,
            message: "tests/harness not present".to_string(),
        }
    } else {
        run_step("cargo-test (harness)", verbose, || {
            cargo_in(
                &harness_path,
                &[
                    "test",
                    "--target",
                    "aarch64-unknown-linux-gnu",
                    "--no-fail-fast",
                ],
            )
        })
    });

    // tls crypto KATs live in the modules/foundation/tls crate which
    // defaults to `#![no_std]` / `#![no_main]`. `cargo test -p` from
    // workspace root with `--features host-test` toggles those off.
    let tls_path = project_root.join("modules/foundation/tls");
    results.push(if skip.cargo {
        skipped("cargo-test (tls KATs)")
    } else if !tls_path.exists() {
        PhaseResult {
            name: "cargo-test (tls KATs)",
            status: PhaseStatus::Skipped,
            elapsed_ms: 0,
            message: "tls module not present".to_string(),
        }
    } else {
        run_step("cargo-test (tls KATs)", verbose, || {
            cargo_in(
                project_root,
                &[
                    "test",
                    "-p",
                    "fluxor-mod-tls",
                    "--features",
                    "host-test",
                    "--target",
                    "aarch64-unknown-linux-gnu",
                    "--no-fail-fast",
                ],
            )
        })
    });

    Ok(results)
}

fn run_step<F>(name: &'static str, verbose: bool, f: F) -> PhaseResult
where
    F: FnOnce() -> std::result::Result<(), String>,
{
    if verbose {
        eprintln!("[ci] running phase: {name}");
    }
    let start = Instant::now();
    let outcome = f();
    let elapsed_ms = start.elapsed().as_millis();
    match outcome {
        Ok(()) => PhaseResult {
            name,
            status: PhaseStatus::Ok,
            elapsed_ms,
            message: String::new(),
        },
        Err(msg) => PhaseResult {
            name,
            status: PhaseStatus::Failed,
            elapsed_ms,
            message: msg,
        },
    }
}

fn skipped(name: &'static str) -> PhaseResult {
    PhaseResult {
        name,
        status: PhaseStatus::Skipped,
        elapsed_ms: 0,
        message: String::new(),
    }
}

fn cargo_in(dir: &Path, args: &[&str]) -> std::result::Result<(), String> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(dir).args(args);
    let status = cmd
        .status()
        .map_err(|e| format!("cargo: spawn failed: {e}"))?;
    if !status.success() {
        return Err(format!(
            "cargo {} exited {}",
            args.join(" "),
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

/// Single-invocation clippy for downstream projects whose workspace
/// builds end-to-end under default features.
fn clippy_downstream(project_root: &Path) -> std::result::Result<(), String> {
    cargo_in(
        project_root,
        &[
            "clippy",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
    )
}

/// Run clippy across every kernel target/feature pair fluxor ships
/// for, plus the host tools sub-crate. The fluxor workspace can't be
/// linted in a single `cargo clippy --workspace` invocation because
/// the kernel's default features pull embedded-only deps that don't
/// compile on the host; each entry below is one self-consistent
/// build configuration matching `Makefile :: lint`.
fn clippy_matrix(project_root: &Path) -> std::result::Result<(), String> {
    let matrix: &[ClippyJob<'_>] = &[
        // Host tools — all features enabled.
        ClippyJob {
            label: "tools",
            cwd: "tools",
            args: &[
                "clippy",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
            feature_gate: None,
            package_gate: None,
        },
        // Linux host kernel binary.
        ClippyJob {
            label: "kernel host-linux",
            cwd: "",
            args: &[
                "clippy",
                "--release",
                "--target",
                "aarch64-unknown-linux-gnu",
                "--bin",
                "fluxor-linux",
                "--no-default-features",
                "--features",
                "host-linux",
                "--",
                "-D",
                "warnings",
            ],
            feature_gate: Some("host-linux"),
            package_gate: None,
        },
        // RP2350B firmware.
        ClippyJob {
            label: "kernel rp2350b",
            cwd: "",
            args: &[
                "clippy",
                "--release",
                "--target",
                "thumbv8m.main-none-eabihf",
                "--no-default-features",
                "--features",
                "chip-rp2350b",
                "--",
                "-D",
                "warnings",
            ],
            feature_gate: Some("chip-rp2350b"),
            package_gate: None,
        },
        // RP2040 firmware.
        ClippyJob {
            label: "kernel rp2040",
            cwd: "",
            args: &[
                "clippy",
                "--release",
                "--target",
                "thumbv6m-none-eabi",
                "--no-default-features",
                "--features",
                "chip-rp2040",
                "--",
                "-D",
                "warnings",
            ],
            feature_gate: Some("chip-rp2040"),
            package_gate: None,
        },
        // BCM2712 firmware.
        ClippyJob {
            label: "kernel bcm2712",
            cwd: "",
            args: &[
                "clippy",
                "--release",
                "--target",
                "aarch64-unknown-none",
                "--no-default-features",
                "--features",
                "chip-bcm2712",
                "--",
                "-D",
                "warnings",
            ],
            feature_gate: Some("chip-bcm2712"),
            package_gate: None,
        },
        // CM5 (BCM2712 with board overlay).
        ClippyJob {
            label: "kernel board-cm5",
            cwd: "",
            args: &[
                "clippy",
                "--release",
                "--target",
                "aarch64-unknown-none",
                "--no-default-features",
                "--features",
                "board-cm5",
                "--",
                "-D",
                "warnings",
            ],
            feature_gate: Some("board-cm5"),
            package_gate: None,
        },
        // wasm.
        ClippyJob {
            label: "kernel wasm",
            cwd: "",
            args: &[
                "clippy",
                "--release",
                "--target",
                "wasm32-unknown-unknown",
                "--no-default-features",
                "--features",
                "host-wasm",
                "--",
                "-D",
                "warnings",
            ],
            feature_gate: Some("host-wasm"),
            package_gate: None,
        },
        // Foundation PIC modules under the host-test feature, exercising
        // the same code that ships as `.fmod` blobs on hardware. Catches
        // workspace-clippy issues the per-target embedded matrix can't
        // see (those targets exclude the `host-test` cfg branches).
        ClippyJob {
            label: "mod ip (host-test)",
            cwd: "",
            args: &[
                "clippy",
                "--all-targets",
                "-p",
                "fluxor-mod-ip",
                "--features",
                "host-test",
                "--target",
                "aarch64-unknown-linux-gnu",
                "--",
                "-D",
                "warnings",
            ],
            feature_gate: None,
            package_gate: Some("fluxor-mod-ip"),
        },
        ClippyJob {
            label: "mod http (host-test)",
            cwd: "",
            args: &[
                "clippy",
                "--all-targets",
                "-p",
                "fluxor-mod-http",
                "--features",
                "host-test",
                "--target",
                "aarch64-unknown-linux-gnu",
                "--",
                "-D",
                "warnings",
            ],
            feature_gate: None,
            package_gate: Some("fluxor-mod-http"),
        },
        ClippyJob {
            label: "mod ws_stream (host-test)",
            cwd: "",
            args: &[
                "clippy",
                "--all-targets",
                "-p",
                "fluxor-mod-ws-stream",
                "--features",
                "host-test",
                "--target",
                "aarch64-unknown-linux-gnu",
                "--",
                "-D",
                "warnings",
            ],
            feature_gate: None,
            package_gate: Some("fluxor-mod-ws-stream"),
        },
        ClippyJob {
            label: "mod tls (host-test)",
            cwd: "",
            args: &[
                "clippy",
                "--all-targets",
                "-p",
                "fluxor-mod-tls",
                "--features",
                "host-test",
                "--target",
                "aarch64-unknown-linux-gnu",
                "--",
                "-D",
                "warnings",
            ],
            feature_gate: None,
            package_gate: Some("fluxor-mod-tls"),
        },
    ];
    // Each kernel job is keyed by the feature it builds with; the
    // foundation jobs are keyed by package name. Either gate failing
    // means the job doesn't apply to this workspace (e.g., a slim
    // downstream that vendors only some of fluxor's modules), so
    // skip rather than fail.
    let workspace_features = workspace_feature_set(project_root);
    let workspace_packages = workspace_package_set(project_root);

    let mut failures = Vec::new();
    for job in matrix {
        if let Some(feat) = job.feature_gate {
            if !workspace_features.contains(feat) {
                continue;
            }
        }
        if let Some(pkg) = job.package_gate {
            if !workspace_packages.contains(pkg) {
                continue;
            }
        }
        let cwd = if job.cwd.is_empty() {
            project_root.to_path_buf()
        } else {
            project_root.join(job.cwd)
        };
        if !cwd.is_dir() {
            // Job cwd missing — skip silently. Downstream projects
            // without `tools/` route through `clippy_downstream`, so
            // reaching here means detection drifted; defend in depth.
            continue;
        }
        // Each clippy invocation in this matrix touches src/lib.rs to
        // invalidate the incremental cache — otherwise sibling-target
        // runs see "no source changed since last lint" and skip,
        // hiding any cross-feature regressions.
        let _ = std::fs::OpenOptions::new()
            .append(true)
            .open(project_root.join("src/lib.rs"))
            .and_then(|f| f.set_len(f.metadata()?.len()));

        if let Err(e) = cargo_in(&cwd, job.args) {
            failures.push(format!("{}: {e}", job.label));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

/// Union of all features declared by any workspace member. Used to
/// detect whether the project is shaped like the fluxor kernel
/// (declares the chip / board features) or like a downstream
/// consumer (doesn't).
fn workspace_feature_set(project_root: &Path) -> std::collections::HashSet<String> {
    let output = Command::new("cargo")
        .arg("metadata")
        .args(["--format-version", "1", "--no-deps"])
        .current_dir(project_root)
        .output();
    let Ok(out) = output else {
        return std::collections::HashSet::new();
    };
    if !out.status.success() {
        return std::collections::HashSet::new();
    }
    let parsed: serde_json::Value = match serde_json::from_slice(&out.stdout) {
        Ok(v) => v,
        Err(_) => return std::collections::HashSet::new(),
    };
    let mut feats = std::collections::HashSet::new();
    if let Some(pkgs) = parsed.get("packages").and_then(|v| v.as_array()) {
        for pkg in pkgs {
            if let Some(map) = pkg.get("features").and_then(|v| v.as_object()) {
                for k in map.keys() {
                    feats.insert(k.clone());
                }
            }
        }
    }
    feats
}

struct ClippyJob<'a> {
    label: &'a str,
    /// Subdirectory relative to project root. Empty string = project root.
    cwd: &'a str,
    args: &'a [&'a str],
    /// If `Some(feature)`, only run this job when the workspace declares
    /// that feature. Lets downstream consumers omit the kernel matrix
    /// without having to fork ci.rs.
    feature_gate: Option<&'a str>,
    /// If `Some(name)`, only run this job when the workspace contains
    /// a package with that name. Used by the foundation-module jobs
    /// (`-p fluxor-mod-…`) which silently no-op if the package isn't
    /// part of this workspace.
    package_gate: Option<&'a str>,
}

/// Returns the set of workspace package names visible to `cargo
/// metadata --no-deps`. Used to gate `-p <pkg>` clippy jobs so a
/// downstream that vendors only some of fluxor's modules doesn't
/// trip on `error: package … not found`.
fn workspace_package_set(project_root: &Path) -> std::collections::HashSet<String> {
    let output = Command::new("cargo")
        .arg("metadata")
        .args(["--format-version", "1", "--no-deps"])
        .current_dir(project_root)
        .output();
    let Ok(out) = output else {
        return std::collections::HashSet::new();
    };
    if !out.status.success() {
        return std::collections::HashSet::new();
    }
    let parsed: serde_json::Value = match serde_json::from_slice(&out.stdout) {
        Ok(v) => v,
        Err(_) => return std::collections::HashSet::new(),
    };
    let mut names = std::collections::HashSet::new();
    if let Some(pkgs) = parsed.get("packages").and_then(|v| v.as_array()) {
        for pkg in pkgs {
            if let Some(name) = pkg.get("name").and_then(|v| v.as_str()) {
                names.insert(name.to_string());
            }
        }
    }
    names
}

/// Detect whether the project at `project_root` is fluxor itself
/// (kernel + tools + foundation modules) rather than a downstream
/// consumer. The discriminator is the workspace including the
/// `fluxor-tools` package — that name is unique to fluxor's source
/// tree. Downstream consumers like clustor/quantum vendor fluxor
/// via `deps/fluxor` but don't list `fluxor-tools` in their
/// workspace members.
fn is_fluxor_kernel_workspace(project_root: &Path) -> bool {
    let pkgs = workspace_package_set(project_root);
    pkgs.contains("fluxor-tools")
}

/// Resolve the host-tools cargo crate path relative to the project
/// root. Order: explicit `[ci.cargo] host_tools_crate` in
/// `fluxor.toml` → conventional `tools/` if present → `None`. The
/// `cargo-test (tools)` phase reports "skipped" when this returns
/// `None` instead of producing a spawn-failed error.
fn load_host_tools_crate(project_root: &Path) -> Option<String> {
    let fp = project_root.join("fluxor.toml");
    if fp.exists() {
        #[derive(serde::Deserialize)]
        struct Top {
            ci: Option<Ci>,
        }
        #[derive(serde::Deserialize)]
        struct Ci {
            cargo: Option<Cargo>,
        }
        #[derive(serde::Deserialize)]
        struct Cargo {
            host_tools_crate: Option<String>,
        }
        if let Ok(raw) = std::fs::read_to_string(&fp) {
            if let Ok(top) = toml::from_str::<Top>(&raw) {
                if let Some(s) = top
                    .ci
                    .and_then(|c| c.cargo)
                    .and_then(|c| c.host_tools_crate)
                {
                    return Some(s);
                }
            }
        }
    }
    let conventional = project_root.join("tools");
    if conventional.is_dir() && conventional.join("Cargo.toml").is_file() {
        return Some("tools".to_string());
    }
    None
}

/// Hygiene phase wraps the scanner and reports any violation or stale
/// exemption as a phase failure with a brief summary.
fn run_hygiene(project_root: &Path) -> std::result::Result<(), String> {
    let config =
        hygiene::Config::load(project_root).map_err(|e| format!("loading fluxor.toml: {e}"))?;
    let report = hygiene::scan(project_root, &config).map_err(|e| e.to_string())?;
    if report.ok() {
        return Ok(());
    }
    Err(format!(
        "{} violation(s), {} stale exemption(s); run `fluxor lint hygiene` for details",
        report.violations.len(),
        report.stale_exemptions.len()
    ))
}

/// Observability instrumentation-contract phase. Mirrors `fluxor lint
/// observability --strict`: a data-moving module with neither `[observability]`
/// instruments nor an `exempt` reason fails, as does a malformed instrument
/// name. See `standards/observability.md` §6.
fn run_observability(project_root: &Path) -> std::result::Result<(), String> {
    let toml_exempt = crate::observability::load_toml_exemptions(project_root);
    let report =
        crate::observability::lint_with_exemptions(&project_root.join("modules"), &toml_exempt);
    if report.invalid_names.is_empty() && report.uninstrumented.is_empty() {
        return Ok(());
    }
    let mut msg = String::new();
    if !report.invalid_names.is_empty() {
        msg.push_str(&format!(
            "{} malformed instrument name(s); ",
            report.invalid_names.len()
        ));
    }
    if !report.uninstrumented.is_empty() {
        msg.push_str(&format!(
            "{} data-moving module(s) with no `[observability]` metrics/spans or `exempt` reason ({}); ",
            report.uninstrumented.len(),
            report.uninstrumented.join(", ")
        ));
    }
    msg.push_str("run `fluxor lint observability --strict` for details");
    Err(msg)
}

/// Run the placement-resolver lint over every config's `presentation.shell`
/// (rfc_adaptive_presentation.md §9). Mirrors `fluxor lint presentation`.
fn run_presentation(project_root: &Path) -> std::result::Result<(), String> {
    let mut violations: Vec<String> = Vec::new();
    for entry in walkdir::WalkDir::new(project_root)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() || path.components().any(|c| c.as_os_str() == "target") {
            continue;
        }
        match path.extension().and_then(|e| e.to_str()) {
            Some("yaml") | Some("yml") => {}
            _ => continue,
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        // Not every .yaml is a Fluxor config; skip anything that doesn't parse.
        let Ok(cfg) = serde_yaml::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        let rel = path.strip_prefix(project_root).unwrap_or(path).display();
        for msg in crate::presentation_resolver::lint_config(&cfg) {
            violations.push(format!("{rel}: {msg}"));
        }
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} unplaceable essential control(s): {}; run `fluxor lint presentation` for details",
            violations.len(),
            violations.join("; ")
        ))
    }
}

/// Walk every workspace member and confirm it declares
/// `[lints] workspace = true` (or appears in
/// `fluxor.toml::[[ci.lints.exemption]]`). New `cargo new` crates
/// don't inherit workspace lints by default; this check catches that
/// drift.
fn check_workspace_lint_optin(project_root: &Path) -> std::result::Result<(), String> {
    // Read workspace Cargo.toml to enumerate members.
    let manifest_path = project_root.join("Cargo.toml");
    let raw = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("reading {}: {e}", manifest_path.display()))?;
    let parsed: toml::Value =
        toml::from_str(&raw).map_err(|e| format!("parsing Cargo.toml: {e}"))?;
    let members: Vec<String> = parsed
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(toml::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    // Read fluxor.toml for exemptions.
    let exempt: std::collections::HashSet<String> = {
        let fp = project_root.join("fluxor.toml");
        if fp.exists() {
            #[derive(serde::Deserialize)]
            struct Top {
                ci: Option<Ci>,
            }
            #[derive(serde::Deserialize)]
            struct Ci {
                lints: Option<LintCfg>,
            }
            #[derive(serde::Deserialize)]
            struct LintCfg {
                #[serde(default)]
                exemption: Vec<Exemption>,
            }
            #[derive(serde::Deserialize)]
            struct Exemption {
                crate_: Option<String>,
                #[serde(rename = "crate")]
                crate_field: Option<String>,
            }
            let raw = std::fs::read_to_string(&fp).map_err(|e| e.to_string())?;
            let top: Top = toml::from_str(&raw).map_err(|e| e.to_string())?;
            top.ci
                .and_then(|c| c.lints)
                .map(|l| {
                    l.exemption
                        .into_iter()
                        .filter_map(|e| e.crate_field.or(e.crate_))
                        .collect()
                })
                .unwrap_or_default()
        } else {
            std::collections::HashSet::new()
        }
    };

    let mut bad = Vec::new();
    for member in &members {
        if exempt.contains(member) {
            continue;
        }
        let path = project_root.join(member).join("Cargo.toml");
        if !path.exists() {
            continue;
        }
        let raw = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        // Cheap text check — full TOML parse is overkill for this gate.
        if !raw.contains("workspace = true") {
            bad.push(member.clone());
        }
    }
    if bad.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "workspace members missing `[lints] workspace = true`: {}",
            bad.join(", ")
        ))
    }
}

/// Render every config under `[ci.templates].dir` through
/// `render_template::render`. Substitution vars come from the
/// `[ci.templates] vars = { … }` map in `fluxor.toml`, with optional
/// per-file overrides in `[[ci.templates.template]]` blocks. A leftover
/// `__KEY__` after substitution names the missing key and points the
/// operator at the fluxor.toml field to fix.
fn check_templates(project_root: &Path) -> std::result::Result<(), String> {
    let cfg = match load_templates_config(project_root) {
        Ok(Some(c)) => c,
        Ok(None) => return Ok(()),
        Err(e) => return Err(e),
    };
    let Some(dir) = cfg.dir.as_deref() else {
        return Ok(());
    };
    let path = project_root.join(dir);
    if !path.is_dir() {
        return Ok(());
    }
    let base_vars: Vec<(String, String)> = cfg
        .vars
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let mut bad = Vec::new();
    for entry in walkdir::WalkDir::new(&path)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        let ext = p.extension().and_then(|s| s.to_str());
        if !matches!(ext, Some("yaml" | "yml")) {
            continue;
        }
        let content = match std::fs::read_to_string(p) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Per-template overrides: match by suffix against the
        // declared `file = "…"` field so callers can write paths
        // relative to project root, the templates dir, or just the
        // basename.
        let rel = p.strip_prefix(project_root).unwrap_or(p);
        let mut vars: Vec<(String, String)> = base_vars.clone();
        for tpl in &cfg.template {
            if path_matches(rel, &tpl.file) {
                for (k, v) in &tpl.vars {
                    if let Some(slot) = vars.iter_mut().find(|(kk, _)| kk == k) {
                        slot.1 = v.clone();
                    } else {
                        vars.push((k.clone(), v.clone()));
                    }
                }
            }
        }

        match crate::render_template::render(&content, &vars) {
            Ok(rendered) => {
                if let Some(missing) = first_unresolved_key(&rendered) {
                    bad.push(format!(
                        "{}: unresolved placeholder `__{missing}__` — set `[ci.templates] vars.{missing} = \"…\"` (or a per-template override) in fluxor.toml",
                        rel.display()
                    ));
                }
            }
            Err(e) => {
                let msg = e.to_string();
                // render() failed on a leftover placeholder. Extract
                // the key from the error and surface the fluxor.toml
                // hint rather than the raw internal error.
                if let Some(missing) = extract_missing_key_from_err(&msg) {
                    bad.push(format!(
                        "{}: unresolved placeholder `__{missing}__` — set `[ci.templates] vars.{missing} = \"…\"` (or a per-template override) in fluxor.toml",
                        rel.display()
                    ));
                } else {
                    bad.push(format!("{}: {msg}", rel.display()));
                }
            }
        }
    }
    if bad.is_empty() {
        Ok(())
    } else {
        Err(bad.join("; "))
    }
}

#[derive(serde::Deserialize, Default)]
struct TemplatesCfg {
    dir: Option<String>,
    #[serde(default)]
    vars: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    template: Vec<TemplateOverride>,
}

#[derive(serde::Deserialize)]
struct TemplateOverride {
    file: String,
    #[serde(default)]
    vars: std::collections::BTreeMap<String, String>,
}

fn load_templates_config(project_root: &Path) -> std::result::Result<Option<TemplatesCfg>, String> {
    let fp = project_root.join("fluxor.toml");
    if !fp.exists() {
        return Ok(None);
    }
    #[derive(serde::Deserialize)]
    struct Top {
        ci: Option<Ci>,
    }
    #[derive(serde::Deserialize)]
    struct Ci {
        templates: Option<TemplatesCfg>,
    }
    let raw = std::fs::read_to_string(&fp).map_err(|e| e.to_string())?;
    let top: Top = toml::from_str(&raw).map_err(|e| format!("parsing fluxor.toml: {e}"))?;
    Ok(top.ci.and_then(|c| c.templates))
}

/// Suffix-match a config file path against an override's `file` entry.
/// Accepts the override expressed relative to project root, relative
/// to the templates dir, or as a bare basename.
fn path_matches(actual: &Path, declared: &str) -> bool {
    let actual_str = actual.to_string_lossy().replace('\\', "/");
    let declared_norm = declared.replace('\\', "/");
    actual_str == declared_norm
        || actual_str.ends_with(&format!("/{declared_norm}"))
        || actual
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == declared_norm)
}

fn first_unresolved_key(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 4 < bytes.len() {
        if bytes[i] == b'_' && bytes[i + 1] == b'_' {
            let start = i + 2;
            let mut end = start;
            while end < bytes.len() {
                let b = bytes[end];
                if b == b'_' && end + 1 < bytes.len() && bytes[end + 1] == b'_' {
                    let body = &s[start..end];
                    if !body.is_empty()
                        && body
                            .bytes()
                            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
                    {
                        return Some(body.to_string());
                    }
                    break;
                }
                if !b.is_ascii_uppercase() && !b.is_ascii_digit() && b != b'_' {
                    break;
                }
                end += 1;
            }
            i = end;
        } else {
            i += 1;
        }
    }
    None
}

/// Pull the key name out of a `render_template::render` error like
/// "Config error: unresolved placeholder `__SELF_ID__` after substitution".
fn extract_missing_key_from_err(msg: &str) -> Option<String> {
    let open = msg.find("`__")?;
    let after = &msg[open + 3..];
    let close = after.find("__`")?;
    Some(after[..close].to_string())
}

/// Lockfile-consistency phase. Skips cleanly when:
///
/// - the project has no `[dependencies]` table (no lockfile expected); or
/// - live workspace mode is active for this project root (live members
///   bypass the lockfile and an advisory is printed at sync time; CI
///   should treat drift as informational, not fatal).
///
/// Otherwise demands a present, parseable, drift-free `fluxor.lock`.
fn check_lockfile_consistency(project_root: &Path) -> std::result::Result<(), String> {
    let deps = crate::project::dependencies(project_root)?;
    if deps.is_empty() {
        return Ok(());
    }
    // Live-mode advisory: workspace mode is per-developer, gitignored,
    // and intentionally bypasses lockfile pinning. CI shouldn't reject
    // a build just because the developer happens to have the project
    // listed in `~/.fluxor/workspace.toml`.
    if let Ok(Some(ws)) = crate::workspace::load_workspace() {
        if crate::workspace::current_member(&ws, project_root).is_some() {
            eprintln!(
                "note: live workspace mode active for this project root — \
                 lockfile-consistency check skipped. Run `make update` after \
                 leaving workspace mode to refresh fluxor.lock against the registry."
            );
            return Ok(());
        }
    }
    crate::lockfile::check_consistent(project_root).map_err(|e| e.to_string())
}

/// Version-skew check.
///
/// Preferred form: `fluxor.toml::[required].fluxor.abi = N` — the
/// installed CLI's compiled-in [`crate::wire::ABI_VERSION`] (the
/// byte stamped into every module header) must equal `N`. The pin
/// bumps only when the wire ABI changes, so consumers re-pin at
/// most once per breaking-change cycle.
///
/// Legacy form: `fluxor.toml::[required].fluxor.rev = "<sha>"` —
/// installed-CLI source SHA must match. Honoured for projects that
/// need hermetic vendoring. If both fields are set, `abi` wins.
fn check_version_skew(project_root: &Path) -> std::result::Result<(), String> {
    let fp = project_root.join("fluxor.toml");
    if !fp.exists() {
        return Ok(()); // not configured
    }
    #[derive(serde::Deserialize)]
    struct Top {
        required: Option<Req>,
    }
    #[derive(serde::Deserialize)]
    struct Req {
        fluxor: Option<FluxorPin>,
    }
    #[derive(serde::Deserialize)]
    struct FluxorPin {
        abi: Option<u32>,
        rev: Option<String>,
    }
    let raw = std::fs::read_to_string(&fp).map_err(|e| e.to_string())?;
    let top: Top = toml::from_str(&raw).map_err(|e| e.to_string())?;
    let pin = top.required.and_then(|r| r.fluxor);
    let Some(pin) = pin else {
        return Ok(());
    };

    if let Some(required_abi) = pin.abi {
        let actual_abi = u32::from(crate::wire::ABI_VERSION);
        if required_abi == actual_abi {
            return Ok(());
        }
        return Err(format!(
            "fluxor.toml [required].fluxor.abi = {required_abi} but installed CLI implements abi = {actual_abi}; \
             install a CLI matching abi {required_abi} (or bump the pin once the modules in this project are rebuilt against abi {actual_abi})"
        ));
    }

    let Some(required_rev) = pin.rev else {
        return Ok(());
    };
    // Legacy rev pin. Read current HEAD of the *fluxor source
    // checkout*. On a downstream project that's `deps/fluxor/`; on
    // fluxor itself there is no deps/fluxor, so fall back to the
    // project root's git SHA. Crucially: never fall back to
    // `git -C project_root` from a downstream — that would read
    // the consumer's HEAD, not fluxor's.
    let fluxor_dir = project_root.join("deps/fluxor");
    let (sha_source, source_label) = if fluxor_dir.exists() {
        (fluxor_dir, "deps/fluxor".to_string())
    } else {
        (project_root.to_path_buf(), "<project root>".to_string())
    };
    let current_rev = match git_short_sha(&sha_source) {
        Some(s) => s,
        None => return Ok(()), // no git — skip the check
    };
    if current_rev.starts_with(&required_rev) || required_rev.starts_with(&current_rev) {
        return Ok(());
    }
    Err(format!(
        "fluxor.toml [required].fluxor.rev = {required_rev:?} but {source_label} HEAD is {current_rev:?}; \
         bump the pin (or update {source_label}) so they match, then run `make setup` to refresh the installed CLI. \
         Consider switching to the preferred `abi = N` form — it only changes when the wire ABI breaks."
    ))
}

fn git_short_sha(dir: &Path) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "--short=7", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8(output.stdout).ok()?;
    Some(s.trim().to_string())
}

fn run_modules_build_strict(project_root: &Path, verbose: bool) -> std::result::Result<(), String> {
    let opts = modules_build::BuildOpts {
        project_root: project_root.to_path_buf(),
        selector: modules_build::TargetSelector::All,
        // Per the standard's §2 path, ci writes to `target/fluxor/`.
        out_root: project_root.join("target/fluxor"),
        strict: true,
        verbose,
    };
    let report = modules_build::run(&opts).map_err(|e| e.to_string())?;
    let mut failed = Vec::new();
    for tr in &report.per_target {
        if !tr.failed.is_empty() {
            failed.push(format!("{}: {} failed", tr.target, tr.failed.len()));
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed.join("; "))
    }
}

/// Format the summary block printed at end-of-run.
pub fn format_summary(results: &[PhaseResult]) -> String {
    let mut out = String::new();
    out.push_str("\n=================== ci summary ===================\n");
    for r in results {
        out.push_str(&format!(
            "{label:>7}  {name:30}  {ms:>5} ms\n",
            label = r.status.label(),
            name = r.name,
            ms = r.elapsed_ms,
        ));
        if r.status == PhaseStatus::Failed && !r.message.is_empty() {
            for line in r.message.lines() {
                out.push_str(&format!("          {line}\n"));
            }
        }
    }
    out.push_str("==================================================\n");
    out
}

pub fn all_ok(results: &[PhaseResult]) -> bool {
    results.iter().all(|r| r.status != PhaseStatus::Failed)
}

// `PathBuf` is referenced in the public signature above; keep the
// import live even when no other path operations land in this file.
#[allow(dead_code, reason = "imported for the public signature of `run`")]
type _PathBufRef = PathBuf;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skipset_parses_comma_separated_phases() {
        let s = SkipSet::from_strs(&["cargo,modules".into(), "lint".into()]).unwrap();
        assert!(s.cargo);
        assert!(s.modules);
        assert!(s.lint);
        assert!(!s.hygiene);
        assert!(!s.templates);
    }

    #[test]
    fn skipset_rejects_unknown_phase() {
        let err = SkipSet::from_strs(&["bogus".into()]).unwrap_err();
        assert!(err.contains("bogus"));
    }

    #[test]
    fn first_unresolved_key_returns_first_match() {
        assert_eq!(
            first_unresolved_key("self=__SELF_ID__ port=__LISTEN_PORT__"),
            Some("SELF_ID".to_string())
        );
        assert_eq!(first_unresolved_key("no placeholders here"), None);
        assert_eq!(first_unresolved_key("__a_b__ first lowercase"), None);
    }

    #[test]
    fn extract_missing_key_parses_render_err() {
        let err = "Config error: unresolved placeholder `__SELF_ID__` after substitution";
        assert_eq!(
            extract_missing_key_from_err(err),
            Some("SELF_ID".to_string())
        );
    }

    #[test]
    fn abi_version_constant_is_in_range() {
        // The pinned `[required].fluxor.abi` value in every shipped
        // fluxor.toml today is 1; if `wire::ABI_VERSION` ever bumps,
        // the corresponding fluxor.toml files must bump in lockstep
        // (and this assertion becomes a reminder to do so).
        assert_eq!(u32::from(crate::wire::ABI_VERSION), 1);
    }

    #[test]
    fn path_matches_suffix_and_basename() {
        let p = Path::new("configs/multi-3node.yaml");
        assert!(path_matches(p, "configs/multi-3node.yaml"));
        assert!(path_matches(p, "multi-3node.yaml"));
        assert!(!path_matches(p, "configs/other.yaml"));
        // Nested form still matches via the `/` suffix rule.
        let nested = Path::new("modules/cluster/configs/x.yaml");
        assert!(path_matches(nested, "cluster/configs/x.yaml"));
    }
}
