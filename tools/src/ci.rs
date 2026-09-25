//! `fluxor ci` — orchestrate the full CI gate.
//!
//! Phases run in sequence; **every phase runs even when an earlier
//! one fails**, so a single CI run surfaces every problem rather than
//! the first one. The final exit code is the OR of every phase's
//! exit code.

use std::collections::BTreeSet;
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
    /// Ran, found something worth saying, and did not fail the run. For
    /// a condition that is real but is not this project's to fix.
    Warned,
    Skipped,
}

impl PhaseStatus {
    pub fn label(self) -> &'static str {
        match self {
            PhaseStatus::Ok => "ok",
            PhaseStatus::Failed => "FAILED",
            PhaseStatus::Warned => "warn",
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
    pub kernel: bool,
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
                    "kernel" => s.kernel = true,
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
    if in_ci
        && (skip.cargo
            || skip.modules
            || skip.lint
            || skip.hygiene
            || skip.templates
            || skip.kernel)
    {
        return Err(Error::Config(
            "`--skip` is rejected when $CI is set; CI must run the full pipeline".to_string(),
        ));
    }
    let mut results = Vec::new();

    // A fmod-only project (all PIC modules, no host crate) has no `Cargo.toml`,
    // so `cargo fmt` / `cargo clippy` have nothing to drive. Rather than skip
    // the lint gate there, clippy runs directly on the PIC module sources
    // (clippy-driver with the strict-build target flags).
    let has_cargo = project_root.join("Cargo.toml").is_file();
    let has_modules = project_root.join("modules").is_dir();

    // ───── fmt-check ─────────────────────────────────────────────────────
    // Two phases, because they cover disjoint trees: `cargo fmt --all`
    // reaches the workspace's members, and PIC module sources are not
    // members of it. A project with both gets both, or the modules are
    // the half nothing formats.
    results.push(if skip.lint {
        skipped("fmt-check")
    } else if has_cargo {
        run_step("fmt-check", verbose, || {
            cargo_in(project_root, &["fmt", "--all", "--", "--check"])
        })
    } else if has_modules {
        run_step("fmt-check (modules)", verbose, || {
            modules_fmt_check(project_root, verbose)
        })
    } else {
        skipped("fmt-check")
    });
    if has_cargo && has_modules {
        results.push(if skip.lint {
            skipped("fmt-check (modules)")
        } else {
            run_step("fmt-check (modules)", verbose, || {
                modules_fmt_check(project_root, verbose)
            })
        });
    }

    // ───── clippy ────────────────────────────────────────────────────────
    // The fluxor workspace mixes a host CLI with no_std embedded
    // crates that don't compile under the workspace's default-feature
    // path, so clippy runs per-target like the kernel build matrix.
    // Downstream consumers (whose `Cargo.toml` doesn't declare the
    // kernel features) run the single-invocation form instead. A
    // fmod-only project (no host crate) clippies its PIC sources
    // directly via clippy-driver.
    let kernel_workspace = is_fluxor_kernel_workspace(project_root);
    let clippy_label = if kernel_workspace {
        "clippy (kernel matrix + tools)"
    } else {
        "clippy"
    };
    results.push(if skip.lint {
        skipped(clippy_label)
    } else if !has_cargo {
        if has_modules {
            run_step("clippy (modules)", verbose, || {
                modules_clippy_check(project_root, verbose)
            })
        } else {
            skipped(clippy_label)
        }
    } else {
        run_step(clippy_label, verbose, || {
            if kernel_workspace {
                clippy_matrix(project_root)
            } else {
                clippy_downstream(project_root)
            }
        })
    });

    // ───── workspace [lints] opt-in audit ────────────────────────────────
    // Audits the workspace `Cargo.toml` for `[lints] workspace = true`;
    // a crate-less fmod-only project has no such manifest, so the phase
    // is not part of its pipeline (omitted rather than listed skipped).
    if has_cargo {
        results.push(if skip.lint {
            skipped("workspace-lint-opt-in")
        } else {
            run_step("workspace-lint-opt-in", verbose, || {
                check_workspace_lint_optin(project_root)
            })
        });
    }

    // ───── hygiene ───────────────────────────────────────────────────────
    results.push(if skip.hygiene {
        skipped("hygiene")
    } else {
        run_step("hygiene", verbose, || run_hygiene(project_root))
    });

    // ───── observability instrumentation contract ────────────────────────
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

    // ───── presentation placement ────────────────────────────────────────
    //
    // Run the placement resolver
    // over every config's `presentation.shell` against the surface it
    // targets, and fail on any `essential` control that can't be surfaced
    // there (no plane + no `bind_physical`). Stops a control going silently
    // dead on a constrained device (e.g. a screenless rp2350 + I2S speaker).
    results.push(if skip.lint {
        skipped("presentation")
    } else {
        run_step("presentation", verbose, || run_presentation(project_root))
    });

    // ───── Makefile standard ─────────────────────────────────────────────
    //
    // Holds this project's Makefile to `standards/make.md`. A CLI verb that
    // moves strands the help text and the scripts naming it across every
    // checkout, and each one is then found by hand. This phase reads the live
    // CLI, so the standard is enforced where it is violated.
    results.push(if skip.lint {
        skipped("makefile")
    } else {
        run_step("makefile", verbose, || run_makefile(project_root))
    });

    // ───── fluxor.toml schema ────────────────────────────────────────────
    //
    // The config every other phase reads is itself checked: a key
    // naming a directory that does not exist, or a table at a placement
    // nothing reads, is an error here. Runs unconditionally: it is a
    // file read, and a project whose config is wrong cannot trust the
    // phases configured by it.
    if project_root.join("fluxor.toml").is_file() {
        results.push(run_step("fluxor-toml-schema", verbose, || {
            crate::ci_schema::check(project_root)
        }));
    }

    // ───── template render ───────────────────────────────────────────────
    results.push(if skip.templates {
        skipped("template-render")
    } else {
        run_step("template-render", verbose, || check_templates(project_root))
    });

    // ───── version-skew ──────────────────────────────────────────────────
    results.push(run_step("version-skew", verbose, || {
        check_version_skew(project_root)
    }));

    // ───── lockfile consistency ──────────────────────────────────────────
    //
    // When the project declares `[dependencies]`, the committed
    // `fluxor.lock` must be present, parse in the uniform
    // `[[artifact]]` shape, and pin every declared dependency.
    // Projects without `[dependencies]` skip cleanly — no lockfile is
    // expected.
    results.push(run_step("lockfile-consistency", verbose, || {
        check_lockfile_consistency(project_root)
    }));

    // ───── catalog drift ─────────────────────────────────────────────────
    //
    // `stacks/` and `targets/` are the one build input nothing pinned.
    // They are read live from the fluxor checkout while the modules they
    // configure come from digests in `fluxor.lock`, so a stack edited in
    // a sibling checkout changes every downstream build at once — no
    // publish, no `update`, and until now no record that anything moved.
    // `fluxor update` stamps the catalog it resolved against; this
    // reports when the live one has drifted from that stamp.
    //
    // Warns rather than fails, for the same reason live-staleness does:
    // a catalog that has moved on is an ordinary state, not a defect.
    // What was missing was any way to SEE it, which is what turned a
    // one-line skew into an afternoon.
    {
        if verbose {
            eprintln!("[ci] running phase: catalog-drift");
        }
        let start = Instant::now();
        let outcome = check_catalog_drift(project_root);
        let elapsed_ms = start.elapsed().as_millis();
        results.push(match outcome {
            Ok(()) => PhaseResult {
                name: "catalog-drift",
                status: PhaseStatus::Ok,
                elapsed_ms,
                message: String::new(),
            },
            // Warned, not Failed: a catalog that has moved on is an
            // ordinary state. Failing here would make the phase
            // something people route around, and the value of this
            // signal is entirely that it gets read.
            Err(msg) => PhaseResult {
                name: "catalog-drift",
                status: PhaseStatus::Warned,
                elapsed_ms,
                message: msg,
            },
        });
    }

    // ───── SDK materialisation ───────────────────────────────────────────
    //
    // The lockfile NAMES the SDK revision a project compiles against, but
    // the compiler reads the materialised tree under `target/fluxor/`, and
    // nothing downstream of the extraction consults the lockfile again. So
    // the pin is worth something only while the tree on disk is that pin,
    // which is what this asserts.
    //
    // Hard-fails rather than warns: unlike live-staleness, which reports a
    // defensible state (you build what you pinned, upstream moved on),
    // there is no reading under which a tree that disagrees with its own
    // stamp is intended.
    {
        if verbose {
            eprintln!("[ci] running phase: sdk-materialisation");
        }
        let start = Instant::now();
        let outcome = crate::store_sync::materialisation_report(project_root);
        let elapsed_ms = start.elapsed().as_millis();
        results.push(match outcome {
            Ok(None) => skipped("sdk-materialisation"),
            Ok(Some(r)) if r.is_clean() => PhaseResult {
                name: "sdk-materialisation",
                status: PhaseStatus::Ok,
                elapsed_ms,
                message: "every materialised source tree holds the bytes its pin names".to_string(),
            },
            Ok(Some(r)) => {
                let status = if r.drift.is_empty() {
                    PhaseStatus::Warned
                } else {
                    PhaseStatus::Failed
                };
                let mut parts = r.drift;
                parts.extend(r.unverifiable);
                PhaseResult {
                    name: "sdk-materialisation",
                    status,
                    elapsed_ms,
                    message: parts.join("; "),
                }
            }
            Err(e) => PhaseResult {
                name: "sdk-materialisation",
                status: PhaseStatus::Failed,
                elapsed_ms,
                message: e.to_string(),
            },
        });
    }

    // ───── live staleness ────────────────────────────────────────────────
    //
    // Reports when a workspace-member DEPENDENCY has work it has not
    // published, so a reader knows the pinned artefacts this build
    // resolved are not the latest that checkout holds. Informational by
    // default (`[ci] live_staleness`); a release gate sets `fail`.
    //
    // The project's own publish state is not checked: nothing builds
    // against its own published artefacts. Skips cleanly when there is
    // no workspace file or no member dependency to compare.
    {
        if verbose {
            eprintln!("[ci] running phase: live-staleness");
        }
        let start = Instant::now();
        let scope = live_staleness_scope(project_root);
        let outcome = crate::store_sync::live_staleness_report(project_root);
        let elapsed_ms = start.elapsed().as_millis();
        results.push(match outcome {
            Ok(None) => skipped("live-staleness"),
            Ok(Some(findings)) => {
                let (status, message) = classify_staleness(&findings, scope);
                PhaseResult {
                    name: "live-staleness",
                    status,
                    elapsed_ms,
                    message,
                }
            }
            Err(e) => PhaseResult {
                name: "live-staleness",
                status: PhaseStatus::Failed,
                elapsed_ms,
                message: e.to_string(),
            },
        });
    }

    // ───── limit register ────────────────────────────────────────────────
    //
    // The register of deliberate ceilings, checked against the source it
    // describes. Fluxor's register states "an id-shaped ceiling found in
    // source but absent here is a bug" — a rule that is true only while
    // something checks it, which is what this phase is.
    //
    // Omitted entirely for a project with no register: not yet having
    // written one is not a failure of the gate over it.
    {
        let register_rel = limit_register_path(project_root);
        let coverage_fails = limit_register_coverage_fails(project_root);
        if verbose {
            eprintln!("[ci] running phase: limit-register");
        }
        let start = Instant::now();
        let outcome = crate::limit_register::check(project_root, &register_rel);
        let elapsed_ms = start.elapsed().as_millis();
        results.push(match outcome {
            Ok(None) => skipped("limit-register"),
            Ok(Some(r)) => {
                let uncovered = r.uncovered.len();
                let (status, message) = if !r.failures.is_empty() {
                    (PhaseStatus::Failed, r.failures.join("; "))
                } else if uncovered > 0 && coverage_fails {
                    (
                        PhaseStatus::Failed,
                        format!(
                            "{} ceiling(s) over {} row(s) match their source, but {uncovered} \
                             ceiling-shaped const(s) in register-named files are neither \
                             registered nor exempt: {}",
                            r.checked,
                            r.rows,
                            preview(&r.uncovered)
                        ),
                    )
                } else if uncovered > 0 {
                    (
                        PhaseStatus::Warned,
                        format!(
                            "{} ceiling(s) over {} row(s) match their source; {uncovered} \
                             ceiling-shaped const(s) in register-named files are unregistered \
                             ({}) — register or exempt them, or set \
                             `[ci] limit_register_coverage = \"fail\"` once the list is empty",
                            r.checked,
                            r.rows,
                            preview(&r.uncovered)
                        ),
                    )
                } else {
                    (
                        PhaseStatus::Ok,
                        format!(
                            "{} ceiling(s) over {} row(s) match their source; {} coupling(s) \
                             enforced; no unregistered ceiling in a register-named file",
                            r.checked, r.rows, r.constraints
                        ),
                    )
                };
                PhaseResult {
                    name: "limit-register",
                    status,
                    elapsed_ms,
                    message,
                }
            }
            Err(e) => PhaseResult {
                name: "limit-register",
                status: PhaseStatus::Failed,
                elapsed_ms,
                message: e.to_string(),
            },
        });
    }

    // ───── ABI-surface pin ───────────────────────────────────────────────
    //
    // The checked-in ABI-surface pin (source hash + digest, mirrored in
    // three files) must match what the current `modules/sdk` sources
    // produce. A stale pin means built modules embed a wrong surface digest
    // and generations pin to a surface that no longer exists. Only the
    // fluxor kernel tree carries these sources; downstream projects skip.
    if crate::abi_pin::has_abi_surface(project_root) {
        results.push(run_step("abi-surface-pin", verbose, || {
            check_abi_pin(project_root)
        }));
    }

    // ───── cargo unit + library tests ────────────────────────────────────
    //
    // For fluxor itself, run from `tools/` rather than workspace
    // root: the kernel's default features pull in embedded crates
    // that don't compile on the host. The Makefile's `make test`
    // follows the same pattern (cd tools && cargo test --all-targets
    // --all-features). Downstreams may declare their own host-tools
    // sub-crate via `[ci.cargo] host_tools_crate = "tools"`; absent
    // that, a host-buildable workspace runs the standard's phase-2
    // command at the workspace root instead (see below).
    // `cargo test` needs a cargo project. A crate-less fmod-only project
    // (no root `Cargo.toml`) with no host-tools crate has nothing here, so
    // the phase is omitted rather than perpetually listed as skipped.
    // Resolved by `cargo_unit_site`, the same call `fluxor test` makes, so
    // the gate and the verb cannot run different commands over one tree.
    let unit_site = cargo_unit_site(project_root);
    let unit_label = if cargo_host_tools_dir(project_root).is_some() {
        "cargo-test (tools)"
    } else {
        "cargo-test (unit)"
    };
    if let Some((dir, args)) = unit_site {
        results.push(if skip.cargo {
            skipped(unit_label)
        } else {
            run_step(unit_label, verbose, || {
                let argv: Vec<&str> = args.clone();
                cargo_test_phase(&dir, &argv)
            })
        });
    }

    // ───── wasm host-shim behaviour (node) ───────────────────────────────
    //
    // The browser host's import shims are JavaScript, so the only thing
    // cargo can hold about them is that every extern has one (the parity
    // guard in `tools/tests`). What they DO is held by `tests/host/*.test.js`
    // on a fake linear memory, with `node` as the engine. A kernel
    // workspace without `node` on the path reports the phase skipped
    // rather than omitted, so the absence of the runtime is visible.
    if kernel_workspace {
        results.push(if skip.cargo {
            skipped("wasm-host-shims (node)")
        } else {
            run_node_tests(project_root, verbose)
        });
    }

    // ───── modules build ─────────────────────────────────────────────────
    results.push(if skip.modules {
        skipped("modules-build (strict)")
    } else {
        run_step("modules-build (strict)", verbose, || {
            run_modules_build_strict(project_root, verbose)
        })
    });

    // ───── tracked examples build-check ──────────────────────────────────
    //
    // `examples/` is the front door, and a graph naming a module the repo does
    // not contain still *reads* fine — it only fails when someone runs it.
    // Every module extraction and every domain/tier rule change can strand one
    // silently. Build-check each tracked example so that lands here, on the
    // day, rather than in a downstream clone.
    //
    // Tracked only: the working tree carries local scratch graphs that
    // legitimately name sibling-repo modules.
    //
    // AFTER the module build, because a build-check resolves each graph
    // against the `.fmod` artefacts and reads their parameter schemas out of
    // them. Run before, it checks whatever a previous build happened to leave
    // in `target/fluxor` — passing on a warm tree and failing on a cold one,
    // which is a gate that reports the bench rather than the commit.
    results.push(if skip.lint {
        skipped("examples")
    } else {
        run_step("examples", verbose, || run_examples(project_root))
    });

    // ───── kernel link + static-RAM budget ───────────────────────────────
    //
    // Clippy type-checks the rp kernels but stops before the linker, and
    // a static-RAM overflow is invisible to a type-check. So this links
    // the real image rather than checking the crate: a target whose only
    // coverage is a type-check is a target whose image nothing builds.
    //
    // It also holds each image under the static-RAM ceiling its silicon
    // declares (`[kernel] ram_static_max_kb`). The linker already refuses
    // an image that cannot fit at all; the budget binds earlier, so a few
    // KiB of creep per month fails here with a number attached instead of
    // arriving one day as a link error at the cliff.
    results.push(
        if skip.kernel || !is_fluxor_kernel_workspace(project_root) {
            skipped("kernel-link (rp)")
        } else {
            run_step("kernel-link (rp)", verbose, || {
                run_kernel_link_budget(project_root, verbose)
            })
        },
    );

    // ───── project test scripts (E2E gate) ───────────────────────────────
    //
    // A fmod-only project has no cargo tests — its behaviour is proven by
    // graph E2Es that boot the built `.fmod` artefacts. `[ci.test] scripts
    // = [...]` (globs) declares them; each runs here, after the strict
    // module build that produces the artefacts they load. This is the
    // in-`ci` home for a project's runtime gate, so `make ci` proves
    // behaviour and not just lint/build. Omitted when unconfigured; a
    // failing script names itself (and dumps a log tail) in the phase
    // message. `--skip cargo` (the test skip) bypasses it.
    match load_test_scripts(project_root) {
        Ok(test_scripts) if test_scripts.is_empty() => {}
        Ok(test_scripts) => results.push(if skip.cargo {
            skipped("project-e2e")
        } else {
            run_step("project-e2e", verbose, || {
                run_test_scripts(project_root, &test_scripts, verbose)
            })
        }),
        Err(e) => results.push(run_step("project-e2e", verbose, move || Err(e))),
    }

    // ───── cargo integration tests ───────────────────────────────────────
    //
    // Two sites, either of which may be absent: the `tests/harness/`
    // sub-workspace, and the root package's own `tests/`. A project with
    // neither omits the phase entirely (its runtime gate is `[ci.test]`
    // scripts, run by the project-e2e phase) rather than carrying a perpetual
    // skip line that reads as an unmet obligation.
    //
    // The root site matters because the unit-test phase selects target kinds
    // (`--lib --bins`), and naming any target kind turns cargo's default
    // selection off — so integration tests are excluded there by
    // construction. Without this sweep a root `tests/*.rs` is run by
    // `fluxor test` and by nothing in the gate.
    //
    // `cargo_integration_sites` is the same call `fluxor test` makes.
    if !skip.cargo && is_fluxor_kernel_workspace(project_root) {
        ensure_host_binary(project_root, verbose);
    }
    for (label, dir, args) in cargo_integration_sites(project_root) {
        results.push(if skip.cargo {
            skipped(label)
        } else {
            run_step(label, verbose, || {
                let argv: Vec<&str> = args.clone();
                cargo_test_in(&dir, &argv)
            })
        });
    }

    Ok(results)
}

/// Phases completed so far, for the live `[n]` index.
static PHASE_INDEX: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A phase that has produced no output of its own for this long is reported
/// as still running, so a long quiet stretch reads as work rather than as a
/// hang. The module phases can run for minutes without a line of their own.
const HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(30);

/// Render a duration the way an operator reads it.
fn dur(ms: u128) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{}m{:02}s", ms / 60_000, (ms % 60_000) / 1000)
    }
}

/// Announce a phase, run it, and report the outcome as soon as it lands.
///
/// The elapsed time was always measured and then held back until the summary,
/// so an operator who cancelled at minute twenty learned nothing. The index
/// carries no total: the phase list is built by the conditionals in `run()`,
/// and a second count of them would be a second source of truth that drifts
/// from the first the moment either changes.
fn run_step<F>(name: &'static str, verbose: bool, f: F) -> PhaseResult
where
    F: FnOnce() -> std::result::Result<(), String>,
{
    let n = PHASE_INDEX.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    eprintln!("[{n:>2}] {name} ...");
    if verbose {
        eprintln!("[ci] running phase: {name}");
    }
    let start = Instant::now();

    // Heartbeat. Parked on a channel rather than sleeping in a loop, so the
    // thread ends the moment the phase does instead of outliving it.
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let beat = std::thread::spawn(move || {
        let t0 = Instant::now();
        // Only a TIMEOUT means "still going". `recv_timeout` also returns
        // Err on Disconnected, which is precisely the signal that the phase
        // has finished — treating the two alike spins the thread forever.
        while matches!(
            done_rx.recv_timeout(HEARTBEAT),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ) {
            eprintln!("     … still running ({})", dur(t0.elapsed().as_millis()));
        }
    });

    let outcome = f();
    let elapsed_ms = start.elapsed().as_millis();
    drop(done_tx);
    let _ = beat.join();

    let (status, message) = match outcome {
        Ok(()) => (PhaseStatus::Ok, String::new()),
        Err(msg) => (PhaseStatus::Failed, msg),
    };
    eprintln!("[{n:>2}] {name} {} ({})", status.label(), dur(elapsed_ms));
    PhaseResult {
        name,
        status,
        elapsed_ms,
        message,
    }
}

/// Run every `tests/host/*.test.js` under `node`. Skipped, with the reason
/// in the message, when there is no `node` to run them or nothing to run.
fn run_node_tests(project_root: &Path, verbose: bool) -> PhaseResult {
    const NAME: &str = "wasm-host-shims (node)";
    let mut tests = Vec::new();
    expand_glob(project_root, "tests/host/*.test.js", &mut tests);
    tests.sort();
    if tests.is_empty() {
        return PhaseResult {
            name: NAME,
            status: PhaseStatus::Skipped,
            elapsed_ms: 0,
            message: "no tests/host/*.test.js".to_string(),
        };
    }
    let node_present = Command::new("node")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !node_present {
        return PhaseResult {
            name: NAME,
            status: PhaseStatus::Skipped,
            elapsed_ms: 0,
            message: format!("node not on PATH; {} test file(s) not run", tests.len()),
        };
    }
    run_step(NAME, verbose, || {
        let mut failed = Vec::new();
        for test in &tests {
            let name = test
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("?")
                .to_string();
            if verbose {
                eprintln!("[ci] {NAME}: {name}");
            }
            let out = Command::new("node")
                .arg(test)
                .current_dir(project_root)
                .output()
                .map_err(|e| format!("node: spawn failed: {e}"))?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let tail: Vec<&str> = stderr.lines().rev().take(12).collect();
                let tail: Vec<&str> = tail.into_iter().rev().collect();
                failed.push(format!("{name}:\n    {}", tail.join("\n    ")));
            }
        }
        if failed.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "{} of {} node test file(s) failed:\n  {}",
                failed.len(),
                tests.len(),
                failed.join("\n  ")
            ))
        }
    })
}

fn skipped(name: &'static str) -> PhaseResult {
    PhaseResult {
        name,
        status: PhaseStatus::Skipped,
        elapsed_ms: 0,
        message: String::new(),
    }
}

pub(crate) fn cargo_in(dir: &Path, args: &[&str]) -> std::result::Result<(), String> {
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
        // Rig observer backends. A crate of their own because they carry an
        // async runtime the CLI does not (see `tools/rig-observers/`), which
        // also puts them outside the `tools` job above: a cargo invocation in
        // `tools/` selects the package rooted there and nothing beside it.
        // These are shipped binaries, so they are linted like any other.
        ClippyJob {
            label: "rig-observers",
            cwd: "tools/rig-observers",
            args: &[
                "clippy",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
            feature_gate: None,
            package_gate: Some("fluxor-rig-observers"),
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
                "-C",
                "target-feature=+aes,+sha2,+neon",
            ],
            feature_gate: Some("host-linux"),
            package_gate: None,
        },
        // RP firmware, once per silicon.
        //
        // A chip feature alone names silicon, not a firmware: it selects
        // register bases and nothing that boots, so each job builds the
        // binary that carries the reset vector and panic handler with it.
        // Both RP chips are covered, so a construct that is fine on ARMv8-M
        // and not on ARMv6-M is caught here rather than on a board.
        //
        // Neither job sets `FLUXOR_BOARD`, so both are silicon-level: board
        // facts (console pins, crystal) are absent and the code that reads
        // them must be gated accordingly. That is the point of the pass, not
        // an omission.
        ClippyJob {
            label: "kernel rp2350",
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
                "-C",
                "target-feature=+aes,+sha2,+neon",
            ],
            feature_gate: Some("chip-bcm2712"),
            package_gate: None,
        },
        // Pi 5 (BCM2712 with board overlay).
        ClippyJob {
            label: "kernel board-pi5",
            cwd: "",
            args: &[
                "clippy",
                "--release",
                "--target",
                "aarch64-unknown-none",
                "--no-default-features",
                "--features",
                "board-pi5",
                "--",
                "-D",
                "warnings",
                "-C",
                "target-feature=+aes,+sha2,+neon",
            ],
            feature_gate: Some("board-pi5"),
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
        // The harness sub-workspace `#[path]`-mounts every foundation
        // module core under the host-test feature, exercising the same
        // code that ships as `.fmod` blobs on hardware. One clippy pass
        // there covers all mounted cores' host-test cfg branches, which
        // no per-crate job could: module directories carry no crates
        // (standards/fluxor-modules.md §0).
        // Skipped naturally when `tests/harness/` doesn't exist.
        ClippyJob {
            label: "harness (module cores, host-test)",
            cwd: "tests/harness",
            args: &[
                "clippy",
                "--all-targets",
                "--target",
                "aarch64-unknown-linux-gnu",
                "--",
                "-D",
                "warnings",
            ],
            feature_gate: None,
            package_gate: None,
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
        // Nothing here invalidates the tree between jobs, and nothing should.
        //
        // Each job names a distinct package, `--target` or `--features`, so
        // each is a separate cargo unit with its own fingerprint: no job can
        // be satisfied by another's cache. The one case cargo skips is an
        // unchanged tree, where skipping is correct — it replays the cached
        // diagnostics with the outcome preserved, so a failure still fails.
        //
        // Forcing a rebuild here would not be free. `tests/harness` reaches
        // this crate by path, so touching it makes the integration-test phase
        // rebuild the kernel and relink every integration-test binary.
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
/// tree. A downstream consumer vendors fluxor via `deps/fluxor` but
/// does not list `fluxor-tools` in its workspace members.
fn is_fluxor_kernel_workspace(project_root: &Path) -> bool {
    let pkgs = workspace_package_set(project_root);
    pkgs.contains("fluxor-tools")
}

/// Decide the live-staleness phase outcome.
///
/// Findings are about workspace-member dependencies; the default reports
/// them and the run continues, because a pinned build resolving what an
/// upstream published is correct behaviour, not a defect. `fail` is for
/// a release gate that needs the whole member set current.
fn classify_staleness(
    findings: &[String],
    scope: crate::store_sync::StalenessScope,
) -> (PhaseStatus, String) {
    if findings.is_empty() {
        return (PhaseStatus::Ok, String::new());
    }
    let message = findings.join("; ");
    match scope {
        crate::store_sync::StalenessScope::Fail => (PhaseStatus::Failed, message),
        crate::store_sync::StalenessScope::Report => (PhaseStatus::Warned, message),
    }
}

/// How far the live-staleness phase acts, from `[ci] live_staleness`.
///
/// Defaults to `report`. Set `fail` for a release gate that requires
/// every member dependency to be current. An unrecognised value falls
/// back to the default; the `fluxor-toml-schema` phase reports the typo.
pub(crate) fn live_staleness_scope(project_root: &Path) -> crate::store_sync::StalenessScope {
    #[derive(serde::Deserialize)]
    struct Top {
        ci: Option<Ci>,
    }
    #[derive(serde::Deserialize)]
    struct Ci {
        live_staleness: Option<String>,
    }
    std::fs::read_to_string(project_root.join("fluxor.toml"))
        .ok()
        .and_then(|raw| toml::from_str::<Top>(&raw).ok())
        .and_then(|top| top.ci)
        .and_then(|ci| ci.live_staleness)
        .and_then(|v| crate::store_sync::StalenessScope::parse(&v))
        .unwrap_or_default()
}

/// Resolve the host-tools cargo crate path relative to the project
/// root. Order: explicit `[ci.cargo] host_tools_crate` in
/// `fluxor.toml` → conventional `tools/` if present → `None`. The
/// `cargo-test (tools)` phase reports "skipped" when this returns
/// `None` instead of producing a spawn-failed error.
pub(crate) fn load_host_tools_crate(project_root: &Path) -> Option<String> {
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

/// Where cargo runs for this project, resolved once.
///
/// `None` when the project has no cargo tree. `Some(dir)` is the directory
/// cargo is invoked in, and the flag says whether that directory is the root
/// of a workspace — a host-tools SUB-crate is one package and takes neither
/// `--workspace` nor the root's integration sweep.
///
/// A `host_tools_crate` naming the root itself resolves to `None` here rather
/// than to a second, subtly different root site: pointing the key at `.` says
/// "the root is the host-tools crate", which is what not declaring it already
/// means. Collapsing the two is what stops one command running at the root
/// under `fluxor test` and a different one under `fluxor ci`.
pub(crate) fn cargo_host_tools_dir(project_root: &Path) -> Option<PathBuf> {
    let dir = project_root.join(load_host_tools_crate(project_root)?);
    let dir = dir.canonicalize().unwrap_or(dir);
    let root = project_root
        .canonicalize()
        .unwrap_or(project_root.to_path_buf());
    (dir != root && dir.join("Cargo.toml").is_file()).then_some(dir)
}

/// The triple the Tier-2 harness suites are built and run for. One spelling,
/// because the phase that runs them and the step that provides their binary
/// have to agree: a binary under another triple is a binary those tests skip.
const HARNESS_TARGET: &str = "aarch64-unknown-linux-gnu";

/// Build `fluxor-linux` so the Tier-2 integration tests have the binary they
/// drive.
///
/// Those tests boot the production binary and observe it as a user would. When
/// it is absent each one prints a skip line and RETURNS — which libtest records
/// as a pass, so the phase reports green over suites that never ran. `make ci`
/// is `fluxor ci` alone and does not depend on `make install`, so nothing else
/// in the gate guarantees the binary exists.
///
/// Only when it is missing: a present binary is left alone, because rebuilding
/// it here would overwrite whatever the developer is testing against.
fn ensure_host_binary(project_root: &Path, verbose: bool) {
    let bin = project_root
        .join("target")
        .join(HARNESS_TARGET)
        .join("release")
        .join("fluxor-linux");
    if bin.is_file() {
        return;
    }
    if verbose {
        println!("  building fluxor-linux for the integration tests");
    }
    let _ = cargo_in(
        project_root,
        &[
            "build",
            "--release",
            "--bin",
            "fluxor-linux",
            "--no-default-features",
            "--features",
            "host-linux,host-playback,host-hsm",
            "--target",
            HARNESS_TARGET,
        ],
    );
}

/// The UNIT-test invocation: `(directory, args)`, or `None` with no cargo tree.
///
/// One definition, read by `fluxor ci`'s unit-test phase and by the `fluxor test`
/// verb, so the gate and the verb cannot drift into running different
/// commands over the same tree.
/// Taking the facts as arguments rather than reading them keeps the rule
/// testable against a layout that is described rather than built on disk, and
/// lets a caller that has already resolved its shape pass what it knows.
pub(crate) fn unit_site_for(
    root: &Path,
    host_tools: Option<&Path>,
    has_cargo: bool,
) -> Option<(PathBuf, Vec<&'static str>)> {
    if let Some(dir) = host_tools {
        // One package, every target kind: a host-tools crate exists because
        // the workspace around it cannot build on the host, so there is no
        // workspace sweep to do from here.
        return Some((
            dir.to_path_buf(),
            vec!["test", "--all-targets", "--all-features"],
        ));
    }
    has_cargo.then(|| {
        (
            root.to_path_buf(),
            vec!["test", "--workspace", "--lib", "--bins"],
        )
    })
}

/// [`unit_site_for`] with the facts read off disk — `fluxor ci`'s entry.
pub(crate) fn cargo_unit_site(project_root: &Path) -> Option<(PathBuf, Vec<&'static str>)> {
    unit_site_for(
        project_root,
        cargo_host_tools_dir(project_root).as_deref(),
        project_root.join("Cargo.toml").is_file(),
    )
}

/// The INTEGRATION-test invocations, in the order they should run.
///
/// Two sites, either of which may be absent: the `tests/harness/`
/// sub-workspace, and the root package's own `tests/`. The second exists
/// because the unit site is deliberately `--lib --bins`, which selects target
/// kinds and so excludes integration tests entirely — without a sweep for
/// them, a root `tests/*.rs` is compiled by nothing the gate runs and its
/// assertions are never executed.
///
/// The root sweep is skipped when a host-tools crate took the unit site: that
/// crate exists precisely because the root cannot build on the host, and a
/// sweep there would fail for that reason rather than for a test's.
pub(crate) fn integration_sites_for(
    root: &Path,
    host_tools: Option<&Path>,
    has_cargo: bool,
    has_harness: bool,
    has_root_tests: bool,
) -> Vec<(&'static str, PathBuf, Vec<&'static str>)> {
    let mut out = Vec::new();
    if has_harness {
        out.push((
            "cargo-test (harness)",
            root.join("tests/harness"),
            vec!["test", "--target", HARNESS_TARGET, "--no-fail-fast"],
        ));
    }
    if host_tools.is_none() && has_cargo && has_root_tests {
        out.push((
            "cargo-test (integration)",
            root.to_path_buf(),
            vec!["test", "--workspace", "--tests"],
        ));
    }
    out
}

/// [`integration_sites_for`] with the facts read off disk — `fluxor ci`'s entry.
pub(crate) fn cargo_integration_sites(
    project_root: &Path,
) -> Vec<(&'static str, PathBuf, Vec<&'static str>)> {
    integration_sites_for(
        project_root,
        cargo_host_tools_dir(project_root).as_deref(),
        project_root.join("Cargo.toml").is_file(),
        project_root.join("tests/harness").exists(),
        project_root.join("tests").is_dir(),
    )
}

/// Hygiene phase wraps the scanner and reports any violation or stale
/// exemption as a phase failure with a brief summary.
pub(crate) fn run_hygiene(project_root: &Path) -> std::result::Result<(), String> {
    let config =
        hygiene::Config::load(project_root).map_err(|e| format!("loading fluxor.toml: {e}"))?;
    let report = hygiene::scan(project_root, &config).map_err(|e| e.to_string())?;
    if report.ok() {
        return Ok(());
    }
    Err(format!(
        "{} violation(s); run `fluxor lint hygiene` for details",
        report.violations.len()
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
    if report.invalid_names.is_empty()
        && report.invalid_attr_keys.is_empty()
        && report.uninstrumented.is_empty()
    {
        return Ok(());
    }
    let mut msg = String::new();
    if !report.invalid_names.is_empty() {
        msg.push_str(&format!(
            "{} malformed instrument name(s); ",
            report.invalid_names.len()
        ));
    }
    if !report.invalid_attr_keys.is_empty() {
        msg.push_str(&format!(
            "{} dimension key(s) outside the standards/observability.md §5              vocabulary ({}); ",
            report.invalid_attr_keys.len(),
            report
                .invalid_attr_keys
                .iter()
                .map(|(m, k)| format!("{m}: {k}"))
                .collect::<Vec<_>>()
                .join(", ")
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

/// Run the placement-resolver lint over every config's
/// `presentation.shell`. Mirrors `fluxor lint presentation`. A `Command`
/// that re-invokes this CLI binary as `fluxor`. The launcher `fexecve`s a
/// digest-named store blob, so `current_exe()` is `blobs/sha256/<hex>` —
/// spawning it bare puts the hex digest in the child's argv[0] and the
/// busybox applet dispatch fires instead of the subcommand parse. Pin
/// argv[0].
fn self_invoke() -> Command {
    let exe = std::env::current_exe().unwrap_or_else(|_| "fluxor".into());
    // A concurrent `cargo build` replaces the running binary by rename,
    // after which `current_exe()` names a deleted inode and spawning it
    // fails ENOENT. `/proc/self/exe` still execs the original image, so
    // the run stays self-consistent instead of failing every spawn.
    #[cfg(target_os = "linux")]
    let exe = if exe.exists() {
        exe
    } else {
        std::path::PathBuf::from("/proc/self/exe")
    };
    let mut cmd = Command::new(exe);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        cmd.arg0("fluxor");
    }
    cmd
}

/// Build-check every git-tracked config under `examples/`.
///
/// Uses `git ls-files` rather than a directory walk so untracked local
/// experiments — which may legitimately name sibling-repo modules — are not
/// gated on. A repo without git, or without tracked examples, passes trivially.
fn run_examples(project_root: &Path) -> std::result::Result<(), String> {
    // Versioned examples, from BOTH repos: a project may keep its
    // examples in the primary repo, shadow-track them
    // (standards/test-tracking.md), or be mid-move between the two.
    // Enumerating one repo silently gates a subset: the graphs tracked in
    // the other repo are on disk and never checked.
    let mut listing: BTreeSet<String> = BTreeSet::new();
    for git_dir in [None, Some(project_root.join(".git-shadow"))] {
        let mut cmd = Command::new("git");
        if let Some(d) = &git_dir {
            if !d.is_dir() {
                continue;
            }
            cmd.arg("--git-dir")
                .arg(d)
                .arg("--work-tree")
                .arg(project_root);
        }
        cmd.args(["ls-files", "examples/*.yaml", "examples/**/*.yaml"])
            .current_dir(project_root);
        if let Ok(out) = cmd.output() {
            listing.extend(
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .map(str::to_string),
            );
        }
    }
    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for rel in &listing {
        let rel = rel.as_str();
        // Not examples: the harness tree is fixtures and probes, and a
        // `bundle/` holds packaged OUTPUT (`workload.json` beside a
        // rendered `graph.yaml`) whose source graph is checked already.
        if rel.contains("test_harness/") || rel.contains("/bundle/") {
            continue;
        }
        // Tracked in an index but absent from disk. Build-checking it
        // yields a bare ENOENT that names no cause, so say the cause:
        // an index (commonly the shadow one) still lists a file a
        // deletion removed. Distinguishing this from a broken graph is
        // the difference between "fix your config" and "fix your index".
        if !project_root.join(rel).exists() {
            failures.push(format!(
                "{rel}: tracked but not on disk — a git index still lists it after \
                 the file was deleted; drop the entry (`git rm --cached`) in \
                 whichever index tracks it"
            ));
            continue;
        }
        checked += 1;
        let st = self_invoke()
            .args(["build", "--check", rel])
            .current_dir(project_root)
            .output();
        match st {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                // The specific diagnostic goes to stdout; stderr carries only
                // the "Validation failed" summary. Reporting the summary alone
                // would make this phase say a config is broken without saying
                // why — search both, and prefer the detailed line.
                let combined = format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                );
                let detail = combined
                    .lines()
                    .map(str::trim)
                    .find(|l| l.contains("ERROR"))
                    .or_else(|| {
                        combined
                            .lines()
                            .map(str::trim)
                            .find(|l| l.contains("error") && !l.contains("Validation failed"))
                    })
                    .unwrap_or("build --check failed")
                    .to_string();
                failures.push(format!("{rel}: {detail}"));
            }
            Err(e) => failures.push(format!("{rel}: could not run build --check: {e}")),
        }
    }
    if failures.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{} of {checked} tracked example(s) fail `fluxor build --check`:\n  {}",
        failures.len(),
        failures.join("\n  ")
    ))
}

/// Enforce `standards/make.md` against this project's Makefile.
///
/// The rules themselves — preamble, target set, canonical recipe
/// bodies, §3 recipe complexity — live in [`crate::makefile_lint`],
/// which is pure text and unit-tested as such. What this wrapper adds
/// is the live CLI: every `fluxor <verb>` the Makefile names is
/// resolved against *this binary's* command set, so a verb that is
/// renamed or retired fails here on the day it moves rather than in a
/// sibling repo weeks later. Nothing about the check needs updating
/// when the CLI changes — it asks the binary.
fn run_makefile(project_root: &Path) -> std::result::Result<(), String> {
    let path = project_root.join("Makefile");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(()); // fmod-only projects ship no Makefile
    };
    let verbs = cli_verbs();
    let mut problems: Vec<String> = crate::makefile_lint::check(&text, &verbs)
        .iter()
        .map(|v| v.render("Makefile"))
        .collect();

    // The scripts §3 sends complexity into are part of the same surface:
    // a Makefile one line long that calls a script naming a retired verb
    // is drift the Makefile check cannot see.
    for script in shell_scripts(project_root) {
        let Ok(body) = std::fs::read_to_string(project_root.join(&script)) else {
            continue;
        };
        problems.extend(
            crate::makefile_lint::check_script(&body, &verbs)
                .iter()
                .map(|v| v.render(&script)),
        );
    }

    if problems.is_empty() {
        return Ok(());
    }
    Err(format!(
        "deviates from standards/make.md:\n  {}",
        problems.join("\n  ")
    ))
}

/// Tracked `*.sh` under `tools/` and `scripts/` — the two directories
/// §3 sanctions for recipe complexity and `fluxor help --make` walks.
/// Tracked only, so an untracked local experiment is not gated.
fn shell_scripts(project_root: &Path) -> Vec<String> {
    let Ok(out) = Command::new("git")
        .args(["ls-files", "tools/*.sh", "scripts/*.sh"])
        .current_dir(project_root)
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect()
}

/// Top-level subcommand names, read from this binary's own `--help`
/// so the set is whatever the CLI actually offers. An unreadable help
/// output yields an empty set, which disables the verb check rather
/// than failing the phase on a broken probe.
fn cli_verbs() -> BTreeSet<String> {
    let Ok(out) = self_invoke().arg("--help").output() else {
        return BTreeSet::new();
    };
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .skip_while(|l| !l.starts_with("Commands:"))
        .skip(1)
        .take_while(|l| l.starts_with("  ") || l.trim().is_empty())
        .filter_map(|l| l.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

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
///
/// An exemption names a **crate name**, never a member path — the one
/// semantic the schema phase enforces (`ci_schema`), applied here by
/// resolving each member's `[package] name` before the comparison.
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
                        .filter_map(|e| e.crate_field)
                        .collect()
                })
                .unwrap_or_default()
        } else {
            std::collections::HashSet::new()
        }
    };

    // Member path → package name, so an exemption written as a name
    // (the one semantic) matches the member it names.
    let names: std::collections::HashMap<String, String> =
        crate::ci_schema::workspace_members(project_root)
            .into_iter()
            .collect();

    let mut bad = Vec::new();
    for member in &members {
        if names.get(member).is_some_and(|n| exempt.contains(n)) {
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

/// Gate: the checked-in ABI-surface pin must match the current sources. Uses
/// the same computation as `fluxor abi-regen` (read-only here); a mismatch is
/// fixed by running that command.
fn check_abi_pin(project_root: &Path) -> std::result::Result<(), String> {
    let plan = crate::abi_pin::compute(project_root).map_err(|e| e.to_string())?;
    let stale = plan.stale_sites().map_err(|e| e.to_string())?;
    if stale.is_empty() {
        Ok(())
    } else {
        let names: Vec<String> = stale.iter().map(|p| p.display().to_string()).collect();
        Err(format!(
            "ABI-surface pin stale — run `fluxor abi-regen`. Out-of-date: {}",
            names.join(", ")
        ))
    }
}

/// Lockfile-consistency phase over the uniform `[[artifact]]` lockfile.
///
/// Cheap by design: the lockfile must be present (when `[dependencies]`
/// exist), parse in the uniform shape, and carry at least one pin for
/// every declared dependency. There is no live-mode skip — sync
/// write-through-resolves workspace members through the same lockfile,
/// so the file is authoritative for everyone. Digest/epoch
/// verification against the store happens at sync/materialise time,
/// not here.
/// Report when the live catalog differs from the one `fluxor update`
/// resolved these pins against.
///
/// Skips cleanly with no lockfile, no stamp (a lock written before the
/// stamp existed), or no resolvable install root — none of those are a
/// drift, and failing on them would only teach people to ignore this.
/// Whether a catalog digest that differs from its stamp is worth reporting.
///
/// A skew needs two sides. The hazard is that a module resolved from a pinned
/// digest meets a stack file read live, so a graph expands onto a parameter or
/// an edge that pinned module does not have. With nothing pinned there is no
/// second side: the live catalog is the only catalog, and a project in that
/// state is either the catalog's owner or has resolved nothing yet.
///
/// Reporting it anyway warns the owner of a catalog on every edit to it, and a
/// signal that fires on correct work is one people learn to scroll past.
fn catalog_drift_matters(pinned: usize, stamped: &str, live: &str) -> bool {
    pinned > 0 && stamped != live
}

fn check_catalog_drift(project_root: &Path) -> std::result::Result<(), String> {
    let lock = match crate::store_resolve::read_store_lock(project_root) {
        Ok(Some(l)) => l,
        Ok(None) => return Ok(()),
        Err(e) => return Err(e.to_string()),
    };
    let Some(stamped) = lock.catalog else {
        return Ok(());
    };
    let Some(root) = crate::project::install_root() else {
        return Ok(());
    };
    let Some(live) = crate::store_resolve::catalog_digest(&root.path) else {
        return Ok(());
    };
    if !catalog_drift_matters(lock.artifacts.len(), &stamped.digest, &live) {
        return Ok(());
    }
    Err(format!(
        "the catalog (stacks/ + targets/) at {} has changed since these pins were \
         resolved: lock stamps {}, live is {}. Stack expansion reads the live files \
         while modules come from the pinned digests, so a graph can expand to a \
         parameter or an edge the pinned module does not have. Re-run `fluxor \
         update`, or rebuild this target's modules if you own the catalog.",
        root.path.display(),
        &stamped.digest[..stamped.digest.len().min(19)],
        &live[..live.len().min(19)],
    ))
}

fn check_lockfile_consistency(project_root: &Path) -> std::result::Result<(), String> {
    let deps = crate::project::dependencies(project_root)?;
    if deps.is_empty() {
        return Ok(());
    }
    let lock = crate::store_resolve::read_store_lock(project_root).map_err(|e| e.to_string())?;
    let Some(lock) = lock else {
        return Err("fluxor.lock missing — run `fluxor sync`".to_string());
    };
    for dep in &deps {
        if !lock.artifacts.iter().any(|a| a.project == dep.name) {
            return Err(format!(
                "dependency '{}' has no [[artifact]] entry in fluxor.lock — run `fluxor sync`",
                dep.name
            ));
        }
    }
    Ok(())
}

/// Version-skew check.
///
/// Preferred form: `fluxor.toml::[required].fluxor.abi = N` — the
/// installed CLI's compiled-in [`crate::wire::ABI_VERSION`] (the
/// byte stamped into every module header) must equal `N`. The pin
/// bumps only when the wire ABI changes, so consumers re-pin at
/// most once per breaking-change cycle.
///
/// Exact form: `fluxor.toml::[required].fluxor.rev = "<sha>"` — the
/// installed CLI's source SHA must match. For projects that vendor
/// hermetically and want the whole tree pinned, not just the wire
/// ABI. If both fields are set, `abi` wins.
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
    // A `rev` pin. Read current HEAD of the *fluxor source
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
         bump the pin (or update {source_label}) so they match, then run \
         `cargo install --locked --path tools` to refresh the installed CLI. \
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

/// fmt-check phase for PIC module sources: `rustfmt --check` each one.
/// They are not cargo workspace members, so `cargo fmt --all` never
/// reaches them whether or not the project also has a host crate.
fn modules_fmt_check(project_root: &Path, verbose: bool) -> std::result::Result<(), String> {
    let report =
        modules_build::fmt_check_modules(project_root, verbose).map_err(|e| e.to_string())?;
    if report.ok() {
        // A 7 ms sweep must not read as a sweep that did not run.
        eprintln!(
            "     {} source(s): {} checked, {} unchanged since last pass",
            report.checked,
            report.checked - report.cached,
            report.cached
        );
        Ok(())
    } else {
        Err(format!(
            "{} of {} module sources need formatting (run `rustfmt` on them): {}",
            report.failed.len(),
            report.checked,
            report.failed_summary()
        ))
    }
}

/// clippy phase for fmod-only projects: run `clippy-driver` over every
/// module source with the strict-build target flags.
fn modules_clippy_check(project_root: &Path, verbose: bool) -> std::result::Result<(), String> {
    let report =
        modules_build::clippy_check_modules(project_root, verbose).map_err(|e| e.to_string())?;
    if report.ok() {
        eprintln!(
            "     {} module(s): {} linted, {} unchanged since last pass",
            report.checked,
            report.checked - report.cached,
            report.cached
        );
        Ok(())
    } else {
        Err(format!(
            "clippy failed on {} of {} modules: {}",
            report.failed.len(),
            report.checked,
            report.failed_summary()
        ))
    }
}

/// Read `[ci.test] scripts` from `fluxor.toml` — the globs of shell
/// scripts that make up a project's runtime (E2E) test gate. Empty when
/// unconfigured, which omits the phase entirely. A fluxor.toml that
/// exists but can't be read or parsed is an error — a broken config must
/// fail the phase, never silently omit it.
pub(crate) fn load_test_scripts(project_root: &Path) -> std::result::Result<Vec<String>, String> {
    let fp = project_root.join("fluxor.toml");
    if !fp.exists() {
        return Ok(Vec::new());
    }
    #[derive(serde::Deserialize)]
    struct Top {
        ci: Option<Ci>,
    }
    #[derive(serde::Deserialize)]
    struct Ci {
        test: Option<Test>,
    }
    #[derive(serde::Deserialize)]
    struct Test {
        scripts: Option<Vec<String>>,
    }
    let raw = std::fs::read_to_string(&fp).map_err(|e| format!("{}: {e}", fp.display()))?;
    let top: Top = toml::from_str(&raw).map_err(|e| format!("parsing fluxor.toml: {e}"))?;
    Ok(top
        .ci
        .and_then(|c| c.test)
        .and_then(|t| t.scripts)
        .unwrap_or_default())
}

/// Expand a `dir/pattern` glob (single `*` wildcard in the filename
/// component) relative to `project_root`, appending matches to `out`.
/// Dependency-free — covers the `scripts/*-e2e.sh` shape without pulling
/// in a glob crate.
pub(crate) fn expand_glob(project_root: &Path, pattern: &str, out: &mut Vec<PathBuf>) {
    let (dir_part, file_pat) = match pattern.rsplit_once('/') {
        Some((d, f)) => (d, f),
        None => (".", pattern),
    };
    let dir = project_root.join(dir_part);
    match file_pat.split_once('*') {
        None => {
            // No wildcard — a literal path.
            let p = dir.join(file_pat);
            if p.is_file() {
                out.push(p);
            }
        }
        Some((prefix, suffix)) => {
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(_) => return,
            };
            for entry in entries.filter_map(std::result::Result::ok) {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.len() >= prefix.len() + suffix.len()
                    && name.starts_with(prefix)
                    && name.ends_with(suffix)
                    && entry.path().is_file()
                {
                    out.push(entry.path());
                }
            }
        }
    }
}

/// Run each configured test script (via `bash`, cwd = project root) as
/// the project's runtime gate. Aggregates: fails if any script exits
/// non-zero, naming the failures and dumping a tail of each one's output
/// so a CI log shows what broke without a re-run.
pub(crate) fn run_test_scripts(
    project_root: &Path,
    globs: &[String],
    verbose: bool,
) -> std::result::Result<(), String> {
    let mut scripts = Vec::new();
    let mut unmatched = Vec::new();
    for g in globs {
        let before = scripts.len();
        expand_glob(project_root, g, &mut scripts);
        if scripts.len() == before {
            unmatched.push(g.as_str());
        }
    }
    if !unmatched.is_empty() {
        // Every configured glob must resolve — a pattern that matches
        // nothing means a moved/renamed script would silently drop out of
        // the gate.
        return Err(format!(
            "[ci.test] scripts matched no files: {}",
            unmatched.join(", ")
        ));
    }
    scripts.sort();
    scripts.dedup();
    vacuity(
        "project-e2e",
        scripts.len(),
        globs.len(),
        "`[ci.test] scripts` glob(s) are declared",
        "every glob expanded to nothing — the scripts were moved, renamed, or are not in \
         this checkout",
    )?;
    let mut failed = Vec::new();
    for script in &scripts {
        let name = script
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("?")
            .to_string();
        if verbose {
            eprintln!("[ci] project-e2e: {name}");
        }
        match Command::new("bash")
            .arg(script)
            .current_dir(project_root)
            .output()
        {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                failed.push(name.clone());
                // Dump a tail so the failure is diagnosable from the CI log.
                let mut combined = String::from_utf8_lossy(&o.stdout).into_owned();
                combined.push_str(&String::from_utf8_lossy(&o.stderr));
                let tail: Vec<&str> = combined.lines().rev().take(20).collect();
                eprintln!("== project-e2e FAIL: {name} ==");
                for line in tail.into_iter().rev() {
                    eprintln!("  {line}");
                }
            }
            Err(e) => failed.push(format!("{name} ({e})")),
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} of {} e2e scripts failed: {}",
            failed.len(),
            scripts.len(),
            failed.join(", ")
        ))
    }
}

/// Build (and therefore link) each RP board's kernel image, then hold its
/// static RAM against the ceiling its silicon declares.
///
/// The build goes through `tools/firmware.sh` on purpose: per-board feature
/// and triple resolution lives there, and a gate that reimplemented it would
/// be gating a build nobody ships. Boards come from the target registry, so
/// a new RP board is covered by adding its TOML and nothing here.
fn run_kernel_link_budget(project_root: &Path, verbose: bool) -> std::result::Result<(), String> {
    // Every RP board, not one per silicon. A board may carry its own
    // `[build] cargo_features`, and a different feature set is a different
    // image with different statics — so linking one board per die would
    // leave the others unbuilt while looking like coverage. The ceiling is
    // declared per silicon; boards sharing a die are each held to it.
    let mut boards: Vec<crate::target::TargetDescriptor> =
        crate::target::list_targets(project_root)
            .into_iter()
            .filter_map(|name| crate::target::load_target(&name, project_root).ok())
            .filter(|t| t.kind == crate::target::TargetKind::Board && t.id.starts_with("rp"))
            .collect();
    boards.sort_by(|a, b| a.board_id.cmp(&b.board_id));
    if boards.is_empty() {
        return Err("no RP boards in the target registry".into());
    }

    let mut failures = Vec::new();
    for target in &boards {
        let board = target.board_id.as_deref().unwrap_or(&target.id);
        let silicon = &target.id;
        let out = Command::new("tools/firmware.sh")
            .arg(board)
            .current_dir(project_root)
            .output()
            .map_err(|e| format!("firmware.sh {board}: {e}"))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let tail: Vec<&str> = err.lines().rev().take(12).collect();
            failures.push(format!(
                "{board} ({silicon}): kernel image build failed (link, or the \
                 objcopy that follows it)\n    {}",
                tail.into_iter().rev().collect::<Vec<_>>().join("\n    ")
            ));
            continue;
        }

        let Some(max_kb) = target.ram_static_max_kb else {
            failures.push(format!(
                "{silicon}: no [kernel] ram_static_max_kb — every linked silicon \
                 declares its static-RAM ceiling"
            ));
            continue;
        };
        let Some(_build) = target.build.as_ref() else {
            failures.push(format!("{silicon}: no [build] section, so nothing links"));
            continue;
        };
        // The board-scoped copy `firmware.sh` writes, never cargo's per-triple
        // path: two boards over one triple overwrite each other there, so that
        // ELF belongs to whichever built last. Benign for the RP boards today
        // (pico2w and waveshare-lcd4 compile identical features), and a
        // wrong-board measurement the moment they diverge — which is exactly
        // what pi5 and qemu-virt already do on aarch64-unknown-none.
        let elf = project_root.join(format!("target/{board}/firmware.elf"));

        let used = static_ram_bytes(&elf)?;
        let budget = u64::from(max_kb) * 1024;
        if verbose {
            let slack = budget as i64 - used as i64;
            println!("  {board} ({silicon}): {used} of {budget} bytes static RAM, {slack:+} slack");
        }
        if used > budget {
            failures.push(format!(
                "{board} ({silicon}): static RAM {used} B exceeds the declared \
                 ceiling {budget} B ({max_kb} KiB) by {} B. Either the growth is \
                 wanted — raise ram_static_max_kb and say why — or it is the \
                 creep this gate is here to catch.",
                used - budget
            ));
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n  "))
    }
}

/// Static RAM an image occupies: `.data` (copied to RAM at boot) plus
/// `.bss` and `.uninit` (reserved in RAM, absent from flash). Read via
/// `size -A`, the same figure the linker checks its region against.
fn static_ram_bytes(elf: &Path) -> std::result::Result<u64, String> {
    let out = Command::new("arm-none-eabi-size")
        .arg("-A")
        .arg(elf)
        .output()
        .map_err(|e| format!("arm-none-eabi-size: {e} (needed to check the RAM budget)"))?;
    if !out.status.success() {
        return Err(format!("arm-none-eabi-size failed on {}", elf.display()));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut total = 0u64;
    let mut seen = false;
    for line in text.lines() {
        let mut f = line.split_whitespace();
        let (Some(name), Some(size)) = (f.next(), f.next()) else {
            continue;
        };
        if matches!(name, ".data" | ".bss" | ".uninit") {
            total += size.parse::<u64>().map_err(|e| format!("{name}: {e}"))?;
            seen = true;
        }
    }
    if !seen {
        return Err(format!(
            "{}: no .data/.bss/.uninit sections — wrong ELF?",
            elf.display()
        ));
    }
    Ok(total)
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
    let mut considered = 0usize;
    for tr in &report.per_target {
        considered += tr.built.len() + tr.up_to_date.len() + tr.skipped.len() + tr.failed.len();
        if !tr.failed.is_empty() {
            failed.push(format!("{}: {} failed", tr.target, tr.failed.len()));
        }
    }
    if !failed.is_empty() {
        return Err(failed.join("; "));
    }
    vacuity(
        "modules-build (strict)",
        considered,
        module_manifest_count(project_root),
        "module manifest(s) exist under `modules/`",
        "they are in a flat `modules/<name>/` layout the tiers do not cover \
         (standards/fluxor-modules.md §0.1), or `[ci] targets` names no target",
    )
}

/// Every `manifest.toml` under `modules/`, whatever layout it is in.
///
/// Deliberately *not* the tier walk: the point of the count is to
/// notice modules the tier walk cannot see. A repo with 36 modules in a
/// layout the builder does not discover reported `built 0 of 0` in 0 ms
/// and passed — that is the shape of a repo whose modules sit outside
/// the tiers, and it must read as a failure, not as "no modules".
fn module_manifest_count(project_root: &Path) -> usize {
    let root = project_root.join("modules");
    if !root.is_dir() {
        return 0;
    }
    walkdir::WalkDir::new(&root)
        .max_depth(4)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|e| e.file_name() == "manifest.toml")
        .count()
}

/// The vacuity rule, in one place: **a phase that consumed nothing
/// while its inputs exist is a failure, not a pass.**
///
/// Green-and-empty is the hardest failure to notice, because it looks
/// exactly like success and costs less time — `built 0 of 0` in 0 ms, a
/// cargo phase that executed no test, an e2e phase whose globs matched no
/// file. Nothing in the output distinguishes "checked everything and found
/// it good" from "checked nothing", so the distinction has to be asserted
/// here or it is not made at all. A repo that genuinely has no modules, no
/// tests, or no scripts still passes: `inputs == 0` is not a failure,
/// `inputs > 0 && consumed == 0` is.
fn vacuity(
    phase: &str,
    consumed: usize,
    inputs: usize,
    inputs_desc: &str,
    likely_cause: &str,
) -> std::result::Result<(), String> {
    if inputs == 0 || consumed > 0 {
        return Ok(());
    }
    Err(format!(
        "`{phase}` processed nothing while {inputs} {inputs_desc} — a phase that consumes none \
         of its inputs proves nothing, so it fails rather than reads green. Likely cause: \
         {likely_cause}"
    ))
}

/// A cargo test phase that must have executed a test.
///
/// The run itself is the gate; the count that follows is the assertion
/// that the gate had something to hold. `-- --list` is libtest's own
/// enumeration (not a parse of pass/fail prose), and integration-test
/// targets come from `cargo metadata` — so "the tree has tests but this
/// phase ran none" is a structural comparison of two machine surfaces.
/// `cargo test` for a phase, echoing output as it arrives and remembering
/// which cases failed.
///
/// A phase that reports only an exit code sends the reader back to the log
/// to find out what broke, and on a run that took ten minutes that is a
/// second ten minutes. libtest names every failure on stdout, so the names
/// are already there to be kept. Only stdout is piped — cargo's build
/// diagnostics go to stderr, which is inherited and so reaches the terminal
/// untouched and in order.
fn cargo_test_in(dir: &Path, args: &[&str]) -> std::result::Result<(), String> {
    use std::io::{BufRead, BufReader, Write};
    use std::process::Stdio;

    let mut child = Command::new("cargo")
        .current_dir(dir)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("cargo: spawn failed: {e}"))?;
    let mut failed: Vec<String> = Vec::new();
    if let Some(out) = child.stdout.take() {
        for line in BufReader::new(out)
            .lines()
            .map_while(std::result::Result::ok)
        {
            println!("{line}");
            let _ = std::io::stdout().flush();
            // libtest's per-case line: `test some::name ... FAILED`.
            if let Some(name) = line.strip_prefix("test ") {
                if let Some(name) = name.strip_suffix(" ... FAILED") {
                    failed.push(name.trim().to_string());
                }
            }
        }
    }
    let status = child
        .wait()
        .map_err(|e| format!("cargo: wait failed: {e}"))?;
    if status.success() {
        return Ok(());
    }
    let code = status.code().unwrap_or(-1);
    if failed.is_empty() {
        // Non-zero with no named case: the build failed, or the binary died
        // before libtest reported. Say which, rather than implying a test.
        return Err(format!(
            "cargo {} exited {code} without naming a failing case — the test \
             binary failed to build or died before reporting; the compiler \
             output above is the diagnostic",
            args.join(" ")
        ));
    }
    Err(format!(
        "cargo {} exited {code}; {} case(s) failed: {}",
        args.join(" "),
        failed.len(),
        failed.join(", ")
    ))
}

fn cargo_test_phase(dir: &Path, args: &[&str]) -> std::result::Result<(), String> {
    cargo_test_in(dir, args)?;
    let executed = libtest_case_count(dir, args);
    if executed > 0 {
        return Ok(());
    }
    let integration = integration_test_targets(dir);
    if integration.is_empty() {
        return Ok(());
    }
    Err(format!(
        "`cargo {}` executed 0 tests, but this cargo tree declares integration test target(s) \
         ({}) — either the selector does not reach them or their sources are absent from the \
         checkout (a `tests/` tree that is gitignored and shadow-tracked is present only on the \
         machine that wrote it; standards/test-tracking.md §7)",
        args.join(" "),
        integration.join(", ")
    ))
}

/// Test cases the same invocation enumerates, via libtest's `--list`.
fn libtest_case_count(dir: &Path, args: &[&str]) -> usize {
    let mut full: Vec<&str> = args.to_vec();
    full.extend_from_slice(&["--", "--list"]);
    let Ok(out) = Command::new("cargo").current_dir(dir).args(&full).output() else {
        return 0;
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.ends_with(": test") || l.ends_with(": benchmark"))
        .count()
}

/// Names of `tests/**` integration targets in this cargo tree.
fn integration_test_targets(dir: &Path) -> Vec<String> {
    let output = Command::new("cargo")
        .arg("metadata")
        .args(["--format-version", "1", "--no-deps"])
        .current_dir(dir)
        .output();
    let Ok(out) = output else {
        return Vec::new();
    };
    let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&out.stdout) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for pkg in parsed
        .get("packages")
        .and_then(|v| v.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        for target in pkg
            .get("targets")
            .and_then(|v| v.as_array())
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            let is_test = target
                .get("kind")
                .and_then(|v| v.as_array())
                .is_some_and(|k| k.iter().any(|v| v.as_str() == Some("test")));
            if is_test {
                if let Some(n) = target.get("name").and_then(|v| v.as_str()) {
                    names.push(n.to_string());
                }
            }
        }
    }
    names
}

/// Format the summary block printed at end-of-run.
pub fn format_summary(results: &[PhaseResult]) -> String {
    let mut out = String::new();
    out.push_str("\n=================== ci summary ===================\n");
    for r in results {
        out.push_str(&format!(
            "{label:>7}  {name:30}  {ms:>8}\n",
            label = r.status.label(),
            name = r.name,
            ms = dur(r.elapsed_ms),
        ));
        if matches!(r.status, PhaseStatus::Failed | PhaseStatus::Warned) && !r.message.is_empty() {
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

/// Register location, from `[ci] limit_register`, defaulting to the
/// standard path. A project keeping its register elsewhere says so once.
fn limit_register_path(project_root: &Path) -> String {
    read_ci_string(project_root, "limit_register")
        .unwrap_or_else(|| crate::limit_register::DEFAULT_REGISTER.to_string())
}

/// Whether unregistered ceilings fail rather than warn
/// (`[ci] limit_register_coverage = "fail"`). Opt-in: a project promotes the
/// report to a gate once it has worked its list to zero, so the ratchet is
/// deliberate rather than a wall a project meets on upgrade.
fn limit_register_coverage_fails(project_root: &Path) -> bool {
    read_ci_string(project_root, "limit_register_coverage").as_deref() == Some("fail")
}

/// One `[ci]` string key out of `fluxor.toml`. A missing file, an
/// unparseable one, or an absent key all read as unset — the schema phase
/// is what reports a malformed manifest, not every reader of it.
fn read_ci_string(project_root: &Path, key: &str) -> Option<String> {
    let raw = std::fs::read_to_string(project_root.join("fluxor.toml")).ok()?;
    let doc: toml::Value = toml::from_str(&raw).ok()?;
    doc.get("ci")?.get(key)?.as_str().map(str::to_string)
}

/// A few entries plus a count — enough to act on, short enough to read.
fn preview(items: &[String]) -> String {
    const SHOWN: usize = 5;
    if items.len() <= SHOWN {
        return items.join(", ");
    }
    format!(
        "{}, and {} more",
        items[..SHOWN].join(", "),
        items.len() - SHOWN
    )
}

#[cfg(test)]
mod tests {
    use super::{classify_staleness, live_staleness_scope, PhaseStatus};
    use crate::store_sync::StalenessScope;

    fn findings(lines: &[&str]) -> Vec<String> {
        lines.iter().map(|s| (*s).to_string()).collect()
    }

    /// The default reports a dependency's unpublished work without
    /// failing: a pinned build resolving what that dependency published
    /// is correct behaviour, so the finding is news, not a defect.
    #[test]
    fn a_dependency_with_unpublished_work_warns_by_default() {
        let (status, message) = classify_staleness(
            &findings(&["dependency 'fluxor' has unpublished changes"]),
            StalenessScope::Report,
        );
        assert_eq!(status, PhaseStatus::Warned);
        assert!(message.contains("fluxor"), "{message}");
    }

    /// A release gate opts into failing on the same finding.
    #[test]
    fn a_dependency_with_unpublished_work_fails_under_fail_scope() {
        let (status, message) = classify_staleness(
            &findings(&["dependency 'fluxor' has unpublished changes"]),
            StalenessScope::Fail,
        );
        assert_eq!(status, PhaseStatus::Failed);
        assert!(message.contains("fluxor"), "{message}");
    }

    #[test]
    fn nothing_stale_is_ok_under_every_scope() {
        for scope in [StalenessScope::Report, StalenessScope::Fail] {
            let (status, message) = classify_staleness(&[], scope);
            assert_eq!(status, PhaseStatus::Ok, "{scope:?}");
            assert!(message.is_empty(), "{scope:?}");
        }
    }

    /// The `[ci] live_staleness` key: absent or unreadable → the safe
    /// default; an unrecognised value likewise (the schema phase is what
    /// reports the typo, not this reader).
    #[test]
    fn live_staleness_scope_reads_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let write = |body: &str| std::fs::write(dir.path().join("fluxor.toml"), body).unwrap();

        assert_eq!(live_staleness_scope(dir.path()), StalenessScope::Report);

        write("[project]\nname = \"x\"\n");
        assert_eq!(live_staleness_scope(dir.path()), StalenessScope::Report);

        write("[ci]\nlive_staleness = \"fail\"\n");
        assert_eq!(live_staleness_scope(dir.path()), StalenessScope::Fail);

        write("[ci]\nlive_staleness = \"report\"\n");
        assert_eq!(live_staleness_scope(dir.path()), StalenessScope::Report);

        write("[ci]\nlive_staleness = \"everything\"\n");
        assert_eq!(live_staleness_scope(dir.path()), StalenessScope::Report);
    }

    use super::*;

    /// Vacuity, stated once: inputs without consumption is a failure;
    /// no inputs at all is not. The second half is what keeps a repo
    /// with genuinely no modules, tests, or scripts green.
    #[test]
    fn vacuity_fails_only_when_inputs_exist_and_none_were_consumed() {
        assert!(vacuity("p", 0, 0, "things", "cause").is_ok());
        assert!(vacuity("p", 7, 7, "things", "cause").is_ok());
        assert!(vacuity("p", 1, 36, "things", "cause").is_ok());
        let e = vacuity(
            "modules-build (strict)",
            0,
            36,
            "module manifest(s)",
            "flat layout",
        )
        .unwrap_err();
        assert!(
            e.contains("processed nothing while 36 module manifest(s)"),
            "{e}"
        );
        assert!(e.contains("flat layout"), "{e}");
    }

    #[test]
    fn skipset_parses_comma_separated_phases() {
        let s = SkipSet::from_strs(&["cargo,modules".into(), "lint".into()]).unwrap();
        assert!(s.cargo);
        assert!(s.modules);
        assert!(s.lint);
        assert!(!s.hygiene);
        assert!(!s.templates);
    }

    /// The catalog owner edits `stacks/` and `targets/` as ordinary work and
    /// pins nothing, so drift there says nothing on its own. It means something
    /// only where a pinned module could meet a live stack file.
    #[test]
    fn catalog_drift_needs_something_pinned_to_skew_against() {
        let (a, b) = ("sha256:9b84f1bf934f", "sha256:c4eae6fa67d6");

        assert!(
            !catalog_drift_matters(0, a, b),
            "nothing pinned: the live catalog is the only catalog"
        );
        assert!(
            catalog_drift_matters(1, a, b),
            "one pin is enough for a graph to expand past what it pins"
        );
        assert!(
            !catalog_drift_matters(42, a, a),
            "pins that agree with the catalog they were resolved against"
        );
        assert!(
            !catalog_drift_matters(0, a, a),
            "neither pinned nor drifted"
        );
    }

    #[test]
    fn skipset_rejects_unknown_phase() {
        let err = SkipSet::from_strs(&["bogus".into()]).unwrap_err();
        assert!(err.contains("bogus"));
    }

    /// The link gate has its own skip key rather than riding the test
    /// key: `--skip cargo` means "not the tests", and it must not quietly
    /// take the only phase that builds a kernel image with it.
    #[test]
    fn skipping_tests_does_not_skip_the_kernel_link_gate() {
        let s = SkipSet::from_strs(&["cargo".into()]).unwrap();
        assert!(s.cargo);
        assert!(!s.kernel, "--skip cargo must leave kernel-link running");

        let s = SkipSet::from_strs(&["kernel".into()]).unwrap();
        assert!(s.kernel);
        assert!(!s.cargo);
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
