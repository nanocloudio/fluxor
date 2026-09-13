//! `fluxor modules build` — orchestrate the PIC / wasm module build.
//!
//! In-process discovery + compile + pack pipeline.
//!
//! Output layout:
//!
//! ```text
//! <out>/<silicon>/modules/<name>.{o,elf,fmod}      (PIC targets)
//! <out>/<silicon>/modules/<name>.{wasm,fmod}       (wasm target)
//! ```
//!
//! `<out>` defaults to `<project_root>/target/fluxor`. The flat
//! `<project_root>/target/<silicon>/` layout is selected by passing
//! `--out target`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use crate::error::{Error, Result};
use crate::modules::{pack_fmod, pack_fmod_wasm};

/// Per-silicon compile recipe — target triple, extra rustflags, and
/// linker invocation. Will move into `TargetDescriptor` once
/// `targets/silicon/*.toml` grows a `module_rustflags` field.
#[derive(Debug, Clone)]
struct SiliconSpec {
    silicon_id: &'static str,
    /// `rustc --target` triple for module compilation.
    module_target: &'static str,
    /// Extra `rustc` flags appended after the standard `-O -C
    /// relocation-model=pic` flags. Empty for most targets.
    extra_rustflags: &'static [&'static str],
    /// Linker invocation. `None` selects the wasm path (cdylib
    /// crate-type, no separate linker step).
    linker: Option<LinkerSpec>,
}

#[derive(Debug, Clone)]
struct LinkerSpec {
    /// First argv of the linker process, e.g. `"arm-none-eabi-ld"` or
    /// `"rust-lld"`.
    program: &'static str,
    /// Flavor argument prepended (e.g. `-flavor gnu` for `rust-lld`).
    flavor: Option<&'static str>,
}

const SILICON_SPECS: &[SiliconSpec] = &[
    SiliconSpec {
        silicon_id: "rp2040",
        module_target: "thumbv6m-none-eabi",
        extra_rustflags: &[],
        linker: Some(LinkerSpec {
            program: "arm-none-eabi-ld",
            flavor: None,
        }),
    },
    SiliconSpec {
        silicon_id: "rp2350",
        module_target: "thumbv8m.main-none-eabihf",
        extra_rustflags: &[],
        linker: Some(LinkerSpec {
            program: "arm-none-eabi-ld",
            flavor: None,
        }),
    },
    SiliconSpec {
        silicon_id: "bcm2712",
        // Cortex-A76 — AES + SHA2 + NEON enabled so the inline-asm
        // crypto paths in `modules/sdk/aes_gcm.rs` activate. Without
        // these features the AESE/AESMC instructions SIGILL.
        module_target: "aarch64-unknown-none",
        extra_rustflags: &["-C", "target-feature=+aes,+sha2,+neon"],
        linker: Some(LinkerSpec {
            program: "rust-lld",
            flavor: Some("gnu"),
        }),
    },
    SiliconSpec {
        silicon_id: "wasm",
        module_target: "wasm32-unknown-unknown",
        // wasm modules build as cdylib with `-C opt-level=z -C
        // strip=symbols`. Added below in `compile_module_wasm`.
        extra_rustflags: &[],
        linker: None,
    },
];

fn silicon_spec(silicon: &str) -> Option<&'static SiliconSpec> {
    SILICON_SPECS.iter().find(|s| s.silicon_id == silicon)
}

/// Resolve a user-supplied module-build target name to the silicon id
/// used for module artefacts, via the `targets/` registry (the ONLY
/// board→silicon mapping — standards/target_consolidation.md §3).
///
/// Module builds take silicon and host ids only: a board name is a
/// level error (build the board's silicon instead). Hosts redirect via
/// `[target].module_silicon` (linux → bcm2712). Modules are
/// byte-identical across boards that share silicon + module_target.
pub fn resolve_silicon(target: &str, project_root: &Path) -> Result<String> {
    let desc = crate::target::load_target(target, project_root)?;
    if let Some(board) = &desc.board_id {
        return Err(Error::Config(format!(
            "'{board}' is a board id; module builds take silicon ids only \
             (use `--target {}`)",
            desc.module_silicon()
        )));
    }
    Ok(desc.module_silicon().to_string())
}

/// Caller-facing build options.
#[derive(Debug, Clone)]
pub struct BuildOpts {
    pub project_root: PathBuf,
    pub selector: TargetSelector,
    pub out_root: PathBuf,
    pub strict: bool,
    pub verbose: bool,
}

#[derive(Debug, Clone)]
pub enum TargetSelector {
    /// Build for a single target. Resolved via `resolve_silicon`.
    One(String),
    /// Build for every target listed in `fluxor.toml::[ci].targets`.
    All,
}

/// Result of a build run. Aggregates per-target outcomes; one
/// `TargetReport` per selected target.
#[derive(Debug, Default)]
pub struct BuildReport {
    pub per_target: Vec<TargetReport>,
}

impl BuildReport {
    #[allow(
        dead_code,
        reason = "public API exposed for consumers driving the build orchestrator from the lib surface; main.rs reads the per-target reports directly"
    )]
    pub fn ok(&self) -> bool {
        self.per_target.iter().all(|t| t.failed.is_empty())
    }
}

#[derive(Debug)]
pub struct TargetReport {
    pub target: String,
    pub silicon: String,
    pub built: Vec<String>,
    pub up_to_date: Vec<String>,
    pub skipped: Vec<(String, String)>,
    pub failed: Vec<(String, String)>,
}

/// Discovered module candidate.
#[derive(Debug)]
struct Candidate {
    /// Artifact name — the `.fmod`/`.o`/`.elf` filename stem. For a
    /// variant candidate this carries the `-<variant>` suffix (default
    /// variant stays unsuffixed); the suffix exists ONLY here.
    name: String,
    /// Name embedded in the fmod header — always the base module type.
    /// Graphs bind by `fnv1a(type_name)`, so this must never carry a
    /// variant suffix.
    embed_name: String,
    dir: PathBuf,
    entry: PathBuf,
    manifest: PathBuf,
    hardware_targets: Vec<String>,
    /// 1 (Source) / 2 (Transformer) / 3 (Sink) / 4 (EventHandler) /
    /// 5 (Protocol). Pulled from `manifest.toml::type` when present.
    type_id: u8,
    /// Rust edition passed to `rustc --edition`. Defaults to "2021";
    /// 2024 is blocked on the SDK adopting `#[unsafe(no_mangle)]`.
    edition: String,
    /// `[[variant]]` name this candidate builds, if any. Drives the
    /// embedded-manifest port filtering in `pack_fmod`.
    variant: Option<String>,
    /// `--cfg feature="…"` flags for this candidate (the variant's
    /// feature set). Empty for non-variant modules — they get no
    /// feature cfg arguments at all.
    features: Vec<String>,
    /// Accepted values for `--check-cfg=cfg(feature, values(…))`: the
    /// union of every variant's features plus the `host-test` cfg.
    /// Only populated (and only emitted) for variant
    /// candidates.
    check_cfg_features: Vec<String>,
    /// `[build] wasm_opt_level` from the manifest — per-module rustc
    /// `opt-level` for the wasm target. `None` keeps the default.
    wasm_opt_level: Option<String>,
    /// `[build] opt_level` from the manifest — per-module rustc
    /// `opt-level` for a native target. `None` keeps the default.
    opt_level: Option<String>,
    /// `builtin = true`: a declaration of a kernel-resident module.
    /// Inventoried, never built — it has no source of its own.
    builtin: bool,
}

#[derive(serde::Deserialize)]
struct ManifestRaw {
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "field exists in manifest for documentation; consumed by Manifest::from_toml elsewhere"
    )]
    version: Option<String>,
    #[serde(default)]
    hardware_targets: Option<Vec<String>>,
    /// `builtin = true` marks a manifest as a declaration of a
    /// kernel-resident module: the implementation is compiled into
    /// the kernel and the directory carries no entry file
    /// (standards/fluxor-modules.md §0.1). There is nothing to build.
    #[serde(default)]
    builtin: bool,
    #[serde(default, rename = "type")]
    type_str: Option<String>,
    #[serde(default)]
    entry: Option<String>,
    #[serde(default)]
    edition: Option<String>,
    #[serde(default)]
    variant: Option<Vec<VariantRaw>>,
    #[serde(default)]
    build: Option<BuildRaw>,
}

/// Raw `[build]` table as discovery sees it — only the key the build
/// itself consumes. Full validation shares
/// `manifest::validate_wasm_opt_level` with the manifest parse.
#[derive(serde::Deserialize, Default)]
struct BuildRaw {
    #[serde(default)]
    wasm_opt_level: Option<String>,
    #[serde(default)]
    opt_level: Option<String>,
}

/// Raw `[[variant]]` row as discovery sees it. Full validation
/// (omit_ports vs declared ports, name syntax) lives in
/// `Manifest::from_toml_for_target`; discovery checks only what it
/// needs to expand candidates correctly. Unknown keys are rejected
/// here too (matching `TomlVariant`) so a typo'd row fails at
/// discovery instead of after the compile, at pack.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct VariantRaw {
    name: String,
    #[serde(default)]
    features: Vec<String>,
    #[serde(default)]
    default: bool,
    #[serde(default)]
    #[allow(dead_code, reason = "consumed by Manifest::apply_variant at pack time")]
    omit_ports: Vec<String>,
    #[serde(default)]
    #[allow(dead_code, reason = "validated and applied at manifest packing")]
    omit_capabilities: Vec<String>,
}

/// Editions `rustc` accepts today. Kept explicit so a manifest typo
/// fails discovery loudly instead of surfacing as an opaque rustc error.
const SUPPORTED_EDITIONS: &[&str] = &["2015", "2018", "2021", "2024"];

/// Every module the project declares, buildable or not — the
/// inventory `fluxor modules list` reports.
fn discover_all(project_root: &Path) -> Result<Vec<Candidate>> {
    let mut out = Vec::new();
    for dir in crate::manifest::MODULE_TIERS {
        let root = project_root.join(dir);
        if !root.is_dir() {
            continue;
        }
        for entry in walkdir::WalkDir::new(&root)
            .min_depth(2)
            .max_depth(3)
            .into_iter()
            .filter_map(std::result::Result::ok)
        {
            if entry.file_name() != "manifest.toml" {
                continue;
            }
            let manifest = entry.path().to_path_buf();
            let dir = manifest
                .parent()
                .ok_or_else(|| Error::Module(format!("orphan manifest: {}", manifest.display())))?
                .to_path_buf();
            let name = dir
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| Error::Module(format!("unreadable module dir: {}", dir.display())))?
                .to_string();
            let raw_text = std::fs::read_to_string(&manifest).map_err(Error::from)?;
            let raw: ManifestRaw = toml::from_str(&raw_text)
                .map_err(|e| Error::Module(format!("{}: {e}", manifest.display())))?;
            let builtin = raw.builtin;
            let entry_rel = raw.entry.unwrap_or_else(|| "mod.rs".to_string());
            let entry = dir.join(&entry_rel);
            // A `builtin = true` manifest is a declaration of a
            // kernel-resident module (standards/fluxor-modules.md
            // §0.1): the implementation is compiled into the kernel
            // and the directory carries no entry file. Its absence is
            // correct, not the broken-module case below.
            if !builtin && !entry.exists() {
                // A manifest pointing at a missing entry is a broken
                // module, not an absent one — diagnose the skip so the
                // module doesn't silently vanish from the build set.
                eprintln!(
                    "warning: {}: entry `{entry_rel}` not found; module skipped",
                    manifest.display()
                );
                continue;
            }
            let type_id = resolve_type_id(&name, raw.type_str.as_deref());
            let edition = raw.edition.unwrap_or_else(|| "2021".to_string());
            if !SUPPORTED_EDITIONS.contains(&edition.as_str()) {
                return Err(Error::Module(format!(
                    "{}: unsupported edition {edition:?} (expected one of {SUPPORTED_EDITIONS:?})",
                    manifest.display()
                )));
            }
            let hardware_targets = raw.hardware_targets.unwrap_or_default();
            let build = raw.build.unwrap_or_default();
            let wasm_opt_level = build.wasm_opt_level;
            let opt_level = build.opt_level;
            for level in [&wasm_opt_level, &opt_level].into_iter().flatten() {
                crate::manifest::validate_wasm_opt_level(level)
                    .map_err(|e| Error::Module(format!("{}: {e}", manifest.display())))?;
            }
            match raw.variant {
                None => out.push(Candidate {
                    name: name.clone(),
                    embed_name: name,
                    dir: dir.clone(),
                    entry,
                    manifest,
                    hardware_targets,
                    type_id,
                    edition,
                    variant: None,
                    features: Vec::new(),
                    check_cfg_features: Vec::new(),
                    wasm_opt_level: wasm_opt_level.clone(),
                    opt_level: opt_level.clone(),
                    builtin,
                }),
                Some(variants) => {
                    // Expansion-level validation only; the full table
                    // check (omit_ports, name syntax) runs in
                    // `Manifest::from_toml_for_target` at pack time.
                    let defaults = variants.iter().filter(|v| v.default).count();
                    if defaults != 1 {
                        return Err(Error::Module(format!(
                            "{}: [[variant]] table needs exactly one `default = true` \
                             entry (found {defaults})",
                            manifest.display()
                        )));
                    }
                    // `--check-cfg` accepted values: union of every
                    // variant's features + the `host-test` cfg the SDK
                    // dual-build uses.
                    let mut all: Vec<String> = variants
                        .iter()
                        .flat_map(|v| v.features.iter().cloned())
                        .collect();
                    all.push("host-test".to_string());
                    all.sort();
                    all.dedup();
                    for v in &variants {
                        let artifact = if v.default {
                            name.clone()
                        } else {
                            format!("{name}-{}", v.name)
                        };
                        out.push(Candidate {
                            name: artifact,
                            embed_name: name.clone(),
                            dir: dir.clone(),
                            entry: entry.clone(),
                            manifest: manifest.clone(),
                            hardware_targets: hardware_targets.clone(),
                            type_id,
                            edition: edition.clone(),
                            variant: Some(v.name.clone()),
                            features: v.features.clone(),
                            check_cfg_features: all.clone(),
                            wasm_opt_level: wasm_opt_level.clone(),
                            opt_level: opt_level.clone(),
                            builtin,
                        });
                    }
                }
            }
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    // Artifact names must be unique across the whole set: a variant
    // suffix (`<module>-<variant>`) can collide with another module
    // DIRECTORY of that literal name, and both would race for the same
    // `<name>.fmod` in out_dir — whichever built last would win.
    for pair in out.windows(2) {
        if pair[0].name == pair[1].name {
            return Err(Error::Module(format!(
                "artifact name collision: '{}.fmod' is produced by both {} and {} — \
                 rename the variant or the module",
                pair[0].name,
                pair[0].manifest.display(),
                pair[1].manifest.display()
            )));
        }
    }
    Ok(out)
}

/// The buildable subset of the inventory: `builtin = true` manifests
/// are declarations of kernel-resident modules with no source of
/// their own, so the build, fmt, and clippy sweeps never see them.
fn discover(project_root: &Path) -> Result<Vec<Candidate>> {
    Ok(discover_all(project_root)?
        .into_iter()
        .filter(|c| !c.builtin)
        .collect())
}

/// `--cfg feature="…"` + `--check-cfg` arguments for a variant
/// candidate. Empty for non-variant modules — their rustc /
/// clippy-driver invocations carry no feature cfgs at all.
fn cfg_feature_args(cand: &Candidate) -> Vec<String> {
    if cand.features.is_empty() {
        return Vec::new();
    }
    let mut args = Vec::new();
    for f in &cand.features {
        args.push("--cfg".to_string());
        args.push(format!("feature=\"{f}\""));
    }
    let values = cand
        .check_cfg_features
        .iter()
        .map(|f| format!("\"{f}\""))
        .collect::<Vec<_>>()
        .join(", ");
    args.push("--check-cfg".to_string());
    args.push(format!("cfg(feature, values({values}))"));
    args
}

/// Resolve the module-type byte (1–5) used by `pack_fmod`.
///
/// Preference order:
///   1. Manifest `type = "Source"|"Transformer"|…|"Protocol"` —
///      authoritative when present.
///   2. Name table mirroring the Makefile's `mod_type` macro,
///      hardcoded here so the output is byte-identical to the
///      shell loop's. A module declaring `type = "..."` in its
///      manifest needs no row.
///   3. Default `Transformer` (2).
fn resolve_type_id(name: &str, manifest_type: Option<&str>) -> u8 {
    if let Some(t) = manifest_type {
        return match t {
            "Source" => 1,
            "Transformer" => 2,
            "Sink" => 3,
            "EventHandler" => 4,
            "Protocol" => 5,
            _ => 2,
        };
    }
    legacy_type_by_name(name)
}

fn legacy_type_by_name(name: &str) -> u8 {
    match name {
        // Protocol (5) — drivers exposing a wire protocol surface.
        "cyw43" | "enc28j60" | "ch9120" | "sd" | "st7701s" | "gt911" | "pwm_rp" => 5,
        // Sink (3)
        "i2s_pio" => 3,
        // EventHandler (4)
        "button" | "flash_rp" => 4,
        // Source (1)
        "temp_sensor" | "mic_pio" | "synth_source" => 1,
        // Transformer (2) is the default
        _ => 2,
    }
}

fn matches_target(c: &Candidate, target: &str, silicon: &str) -> bool {
    if c.hardware_targets.is_empty() {
        return true;
    }
    c.hardware_targets
        .iter()
        .any(|t| t == target || t == silicon)
}

/// Public entry point. Drives discovery, per-target compile, and pack.
pub fn run(opts: &BuildOpts) -> Result<BuildReport> {
    // Staged consumption state (source trees under `target/fluxor/<name>/`,
    // reached by module `#[path]` includes) is lockfile-recorded but lives in
    // `target/`, so `cargo clean` wipes it; replay the lockfile before
    // building rather than demanding a manual re-sync.
    crate::store_sync::ensure_synced(&opts.project_root)
        .map_err(|e| crate::error::Error::Config(e.to_string()))?;
    // The target matrix only means something when there is something to
    // build, so discovery comes first. A portable-core-only repo has no
    // module tree and declares no `[ci].targets` — the `fluxor.toml` schema
    // gate refuses that key when nothing needs targeting — and an empty
    // build is the honest report for it.
    //
    // What keeps that from hiding a real fault is `ci`'s vacuity rule: a
    // repo whose manifests exist but whose layout the tier walk cannot see
    // reports zero here and fails there, because the count it is checked
    // against is a separate walk of every `manifest.toml` under `modules/`.
    let candidates = discover(&opts.project_root)?;
    if candidates.is_empty() {
        return Ok(BuildReport::default());
    }
    let targets = match &opts.selector {
        TargetSelector::One(t) => vec![t.clone()],
        TargetSelector::All => resolve_all_targets(&opts.project_root)?,
    };
    let mut report = BuildReport::default();
    for target in targets {
        report
            .per_target
            .push(build_one_target(&target, &candidates, opts)?);
    }
    Ok(report)
}

/// Outcome of a module-source lint sweep (fmt or clippy).
#[derive(Debug, Default)]
pub struct ModuleLintReport {
    /// Number of module sources checked.
    pub checked: usize,
    /// `(source, first-diagnostic)` for each source that failed.
    pub failed: Vec<(String, String)>,
}

impl ModuleLintReport {
    pub fn ok(&self) -> bool {
        self.failed.is_empty()
    }

    /// Comma-joined list of the sources that failed, for a phase message.
    pub fn failed_summary(&self) -> String {
        self.failed
            .iter()
            .map(|(s, _)| s.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// `rustfmt --check` every `.rs` source under the project's `modules/`
/// tree. Formatting is target-independent, so each file is checked once.
///
/// This is the fmod-only counterpart to `cargo fmt --check`: a project
/// that is all PIC modules with no host cargo workspace still gets its
/// module sources format-gated in `fluxor ci`. Covers both module entry
/// files and shared `include!`d fragments (which compile only inside a
/// module but are still standalone-formattable item lists).
///
/// Each file is parsed under its owning module's declared edition
/// (`manifest.toml::edition`); files outside any module dir (shared
/// fragments) use the "2021" default the manifest parser applies.
pub fn fmt_check_modules(project_root: &Path, verbose: bool) -> Result<ModuleLintReport> {
    let mut report = ModuleLintReport::default();
    let modules_root = project_root.join("modules");
    if !modules_root.exists() {
        return Ok(report);
    }
    // Best-effort: a malformed manifest is the clippy/build phases'
    // diagnostic to raise, not a reason to abandon the format sweep.
    let candidates = discover(project_root).unwrap_or_default();
    for entry in walkdir::WalkDir::new(&modules_root)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        report.checked += 1;
        let rel = path
            .strip_prefix(project_root)
            .unwrap_or(path)
            .display()
            .to_string();
        if verbose {
            eprintln!("[modules] rustfmt --check {rel}");
        }
        let edition = candidates
            .iter()
            .find(|c| path.starts_with(&c.dir))
            .map_or("2021", |c| c.edition.as_str());
        let out = Command::new("rustfmt")
            .arg("--check")
            .arg("--edition")
            .arg(edition)
            .arg(path)
            .output()
            .map_err(|e| Error::Module(format!("rustfmt: {e} (is rustfmt installed?)")))?;
        if !out.status.success() {
            report.failed.push((rel, "formatting differs".to_string()));
        }
    }
    Ok(report)
}

/// Run `clippy-driver` over every module source using the same target,
/// edition, and PIC flags the strict build uses. This is the fmod-only
/// counterpart to `cargo clippy`: a project with no host crate still gets
/// a real clippy gate on its PIC modules.
///
/// Each module is linted once, against the first configured target it
/// builds for — clippy diagnostics are effectively target-invariant.
/// `clippy::empty_loop` is allowed: the SDK's bare-metal park loops
/// (`loop {}`) are idiomatic in `no_std` and would otherwise fire on
/// every module through the `include!`d runtime.
pub fn clippy_check_modules(project_root: &Path, verbose: bool) -> Result<ModuleLintReport> {
    crate::store_sync::ensure_synced(project_root)
        .map_err(|e| crate::error::Error::Config(e.to_string()))?;
    let targets = resolve_all_targets(project_root)?;
    let candidates = discover(project_root)?;
    let scratch = project_root.join("target/fluxor/clippy");
    std::fs::create_dir_all(&scratch)?;
    let mut report = ModuleLintReport::default();
    for cand in &candidates {
        // Lint against the first configured target this module builds for.
        let Some((target, spec)) = targets.iter().find_map(|t| {
            let silicon = resolve_silicon(t, project_root).ok()?;
            let spec = silicon_spec(&silicon)?;
            // wasm builds as a cdylib and has no PIC lint surface here.
            if spec.linker.is_none() || !matches_target(cand, t, &silicon) {
                None
            } else {
                Some((t.clone(), spec))
            }
        }) else {
            // wasm-only (or no configured target matches): nothing to lint
            // here, but say so rather than dropping the module silently.
            if verbose {
                eprintln!(
                    "[modules] clippy skip {} (no configured PIC target builds it)",
                    cand.name
                );
            }
            continue;
        };
        report.checked += 1;
        if verbose {
            eprintln!("[modules] clippy-driver {} ({target})", cand.name);
        }
        let rmeta = scratch.join(format!("{}.rmeta", cand.name));
        let out = Command::new("clippy-driver")
            .arg("--crate-type=lib")
            .arg("--edition")
            .arg(&cand.edition)
            .arg("--target")
            .arg(spec.module_target)
            .arg("-O")
            .arg("-C")
            .arg("relocation-model=pic")
            .args(spec.extra_rustflags)
            .args(cfg_feature_args(cand))
            .arg("-A")
            .arg("clippy::empty_loop")
            .arg("-D")
            .arg("warnings")
            .arg("--emit=metadata")
            .arg("-o")
            .arg(&rmeta)
            .arg(&cand.entry)
            .output()
            .map_err(|e| {
                Error::Module(format!(
                    "clippy-driver: {e} (install the clippy component: `rustup component add clippy`)"
                ))
            })?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let first = stderr
                .lines()
                .find(|l| l.starts_with("error") || l.starts_with("warning"))
                .unwrap_or("clippy reported errors")
                .to_string();
            report.failed.push((cand.name.clone(), first));
        }
    }
    Ok(report)
}

fn resolve_all_targets(project_root: &Path) -> Result<Vec<String>> {
    let cfg_path = project_root.join("fluxor.toml");
    if !cfg_path.exists() {
        return Err(Error::Module(
            "no `fluxor.toml` — `--all` requires `[ci].targets`".to_string(),
        ));
    }
    let raw = std::fs::read_to_string(&cfg_path)?;
    #[derive(serde::Deserialize)]
    struct Top {
        ci: Option<Ci>,
    }
    #[derive(serde::Deserialize)]
    struct Ci {
        targets: Option<Vec<String>>,
    }
    let parsed: Top = toml::from_str(&raw)?;
    let targets = parsed.ci.and_then(|c| c.targets).unwrap_or_default();
    if targets.is_empty() {
        return Err(Error::Module(
            "fluxor.toml has no `[ci].targets` — `--all` needs at least one target".to_string(),
        ));
    }
    Ok(targets)
}

fn build_one_target(
    target: &str,
    candidates: &[Candidate],
    opts: &BuildOpts,
) -> Result<TargetReport> {
    let silicon = resolve_silicon(target, &opts.project_root)?;
    let spec = silicon_spec(&silicon).ok_or_else(|| {
        Error::Module(format!(
            "unknown silicon `{silicon}` for target `{target}` — recognised: {}",
            SILICON_SPECS
                .iter()
                .map(|s| s.silicon_id)
                .collect::<Vec<_>>()
                .join(", ")
        ))
    })?;
    let out_dir = opts.out_root.join(&silicon).join("modules");
    std::fs::create_dir_all(&out_dir)?;

    let mut report = TargetReport {
        target: target.to_string(),
        silicon: silicon.clone(),
        built: Vec::new(),
        up_to_date: Vec::new(),
        skipped: Vec::new(),
        failed: Vec::new(),
    };

    for cand in candidates {
        if !matches_target(cand, target, &silicon) {
            continue;
        }
        let out_path = out_dir.join(format!("{}.fmod", cand.name));
        if is_up_to_date(cand, &out_path, &opts.project_root) {
            report.up_to_date.push(cand.name.clone());
            continue;
        }
        let build_result = if spec.linker.is_none() {
            compile_module_wasm(cand, spec, &out_dir, opts)
        } else {
            compile_module_pic(cand, spec, &out_dir, opts)
        };
        match build_result {
            Ok(BuildOutcome::Built) => report.built.push(cand.name.clone()),
            Ok(BuildOutcome::Skipped(reason)) => {
                report.skipped.push((cand.name.clone(), reason));
            }
            Err(e) => {
                report.failed.push((cand.name.clone(), e.to_string()));
            }
        }
    }
    Ok(report)
}

enum BuildOutcome {
    Built,
    /// wasm modules that compile but don't export the canonical
    /// `module_init_wasm` + `module_step_wasm` symbols are not viable
    /// wasm payloads; skipped with a reason.
    Skipped(String),
}

fn is_up_to_date(cand: &Candidate, out_path: &Path, project_root: &Path) -> bool {
    let out_mtime = match mtime(out_path) {
        Some(m) => m,
        None => return false,
    };
    let inputs = [
        cand.manifest.clone(),
        project_root.join("modules/sdk/abi.rs"),
        project_root.join("modules/sdk/runtime.rs"),
        project_root.join("modules/sdk/runtime/params.rs"),
        // Linker script. Lives under modules/sdk/ so it ships in the
        // fluxor-abi source artifact for downstream consumers.
        project_root.join("modules/sdk/module.ld"),
    ];
    for input in &inputs {
        if let Some(im) = mtime(input) {
            if im > out_mtime {
                return false;
            }
        }
    }
    // Source tree under the module dir — any .rs newer than the .fmod
    // invalidates the cache.
    for entry in walkdir::WalkDir::new(&cand.dir)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        if entry.path().extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        if let Some(im) = mtime(entry.path()) {
            if im > out_mtime {
                return false;
            }
        }
    }
    // Project-local sources pulled in by `include!` — shared cores that live
    // OUTSIDE the module directory (the common pattern: many modules include one
    // `modules/common/*.rs`). The walk above cannot see them, so without this a
    // shared-core edit leaves every consumer's `.fmod` looking up to date and
    // silently ships stale device code. The SDK's own deep includes are covered
    // by the digest check below; this covers the project's.
    if !includes_are_older(&cand.dir, out_mtime) {
        return false;
    }
    // ABI-surface freshness — the precise invalidation trigger. Mtime cannot
    // catch a digest change that comes from a deep SDK edit (kernel_abi.rs,
    // wire.rs, contracts/*, platform/*, internal/*) or a regenerated digest
    // const: those files are reached via `include!` and aren't in `inputs`
    // (and needn't be individually enumerated). Instead compare the digest
    // the existing `.fmod` embeds against the current surface directly —
    // any change to the surface, from any source, invalidates exactly the
    // modules that predate it. This is what makes `fluxor modules build`
    // sufficient after an ABI change, with no `modules clean` step: a stale
    // artifact rebuilds automatically instead of surviving to be rejected
    // at packaging.
    match crate::modules::ModuleInfo::from_file(out_path) {
        Ok(info) if info.manifest.abi_surface == Some(crate::hash::abi_surface_digest()) => {}
        _ => return false,
    }
    true
}

fn mtime(p: &Path) -> Option<SystemTime> {
    p.metadata().ok()?.modified().ok()
}

/// Whether every file transitively reachable from `dir`'s `.rs` sources via
/// `include!("…")` is older than `out_mtime`.
///
/// Follows the include graph rather than guessing at a directory convention, so
/// it holds for any layout, and tracks a `visited` set so an include cycle or a
/// diamond terminates. Paths that don't resolve are ignored: a missing include
/// is the compiler's error to report, not a reason to rebuild forever.
fn includes_are_older(dir: &Path, out_mtime: SystemTime) -> bool {
    let mut visited = std::collections::HashSet::new();
    let mut queue: Vec<std::path::PathBuf> = walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("rs"))
        .map(|e| e.path().to_path_buf())
        .collect();

    while let Some(path) = queue.pop() {
        let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
        if !visited.insert(canonical) {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(&path) else {
            continue;
        };
        let base = path.parent().unwrap_or(Path::new("."));
        for target in include_paths(&src) {
            let resolved = base.join(&target);
            let Ok(resolved) = resolved.canonicalize() else {
                continue;
            };
            if let Some(im) = mtime(&resolved) {
                if im > out_mtime {
                    return false;
                }
            }
            queue.push(resolved);
        }
    }
    true
}

/// Every file transitively reachable from `dir`'s `.rs` sources via
/// `#[path = "…"]` / `include!`-family references that lives OUTSIDE
/// `dir` — the inputs a module-directory walk cannot see (the truffle
/// pattern: a module whose `mod.rs` is `#[path]`-mounted shared
/// source elsewhere in the tree). Deduped, sorted, and confined to
/// `allowed_roots` (project root + workspace-member roots): a
/// reference escaping every root is not a build input of this
/// checkout. Unresolvable paths are ignored — cfg'd variants and
/// macro-generated paths are the compiler's business, not a hashing
/// failure.
#[allow(
    dead_code,
    reason = "lib-surface API: consumed by store_publish's input-digest walk, which the dual-context bin build does not include"
)]
pub fn transitive_source_refs(dir: &Path, allowed_roots: &[PathBuf]) -> Vec<PathBuf> {
    let roots: Vec<PathBuf> = allowed_roots
        .iter()
        .filter_map(|r| r.canonicalize().ok())
        .collect();
    let dir_canon = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    let mut visited = std::collections::HashSet::new();
    let mut out = std::collections::BTreeSet::new();
    let mut queue: Vec<PathBuf> = walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("rs"))
        .map(|e| e.path().to_path_buf())
        .collect();
    while let Some(path) = queue.pop() {
        let canonical = match path.canonicalize() {
            Ok(c) => c,
            Err(_) => continue,
        };
        if !visited.insert(canonical.clone()) {
            continue;
        }
        if !canonical.starts_with(&dir_canon) {
            if !roots.iter().any(|r| canonical.starts_with(r)) {
                continue;
            }
            out.insert(canonical.clone());
        }
        let Ok(src) = std::fs::read_to_string(&canonical) else {
            continue;
        };
        let base = canonical.parent().unwrap_or(Path::new("."));
        for target in include_paths(&src) {
            let resolved = base.join(&target);
            if resolved.is_file() {
                queue.push(resolved);
            }
        }
    }
    out.into_iter().collect()
}

/// Extract the literal paths from `include!("…")` / `include_str!` /
/// `include_bytes!` invocations and `#[path = "…"]` module attributes
/// in `src`. Both reach source files the directory walk cannot see, so
/// both feed the staleness graph and the input digest identically.
fn include_paths(src: &str) -> Vec<String> {
    let mut out = source_ref_macro_paths(src);
    out.extend(path_attr_paths(src));
    out
}

/// `#[path = "…"]` string literals. Resolution is relative to the
/// containing file, same as the include macros — the compiler's exact
/// nested-inline-module rule is richer, but a miss only means an
/// unresolvable path, which callers ignore by contract.
fn path_attr_paths(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(hit) = src[from..].find("#[path") {
        let after = from + hit + "#[path".len();
        from = after;
        let rest = src[after..].trim_start();
        let Some(rest) = rest.strip_prefix('=') else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix('"') else {
            continue;
        };
        if let Some(end) = rest.find('"') {
            out.push(rest[..end].to_string());
        }
    }
    out
}

fn source_ref_macro_paths(src: &str) -> Vec<String> {
    const MACROS: [&str; 3] = ["include!", "include_str!", "include_bytes!"];
    let mut out = Vec::new();
    for mac in MACROS {
        let mut from = 0;
        while let Some(hit) = src[from..].find(mac) {
            let after = from + hit + mac.len();
            from = after;
            // Skip whitespace and the opening delimiter, then take the string
            // literal. Anything else (a macro-generated path, say) is ignored.
            let rest = src[after..].trim_start();
            let Some(rest) = rest
                .strip_prefix('(')
                .or_else(|| rest.strip_prefix('['))
                .or_else(|| rest.strip_prefix('{'))
            else {
                continue;
            };
            let rest = rest.trim_start();
            let Some(rest) = rest.strip_prefix('"') else {
                continue;
            };
            if let Some(end) = rest.find('"') {
                out.push(rest[..end].to_string());
            }
        }
    }
    out
}

fn compile_module_pic(
    cand: &Candidate,
    spec: &SiliconSpec,
    out_dir: &Path,
    opts: &BuildOpts,
) -> Result<BuildOutcome> {
    let obj_path = out_dir.join(format!("{}.o", cand.name));
    let elf_path = out_dir.join(format!("{}.elf", cand.name));
    let out_path = out_dir.join(format!("{}.fmod", cand.name));

    // 1) Compile to relocatable object.
    let mut rustc = Command::new("rustc");
    rustc
        .arg("--crate-type=lib")
        .arg("--edition")
        .arg(&cand.edition)
        .arg("--target")
        .arg(spec.module_target)
        .arg("-C")
        .arg(format!(
            "opt-level={}",
            // `-O` is opt-level=2. A module that names its own takes it:
            // one that links a whole engine may need the smaller code more
            // than the faster code, and that is its own trade rather than
            // every module's.
            cand.opt_level.as_deref().unwrap_or("2")
        ))
        .arg("-C")
        .arg("relocation-model=pic")
        .args(spec.extra_rustflags)
        .args(cfg_feature_args(cand));
    if opts.strict {
        // `-D warnings` upgrades unfulfilled `#[expect(...)]` and
        // every other warning into a hard error, which is what a
        // strict build means.
        rustc.arg("-D").arg("warnings");
    } else {
        rustc.arg("-W").arg("warnings");
        // Even in lenient mode, unfulfilled lint expectations must
        // fail so `#[expect]` stays honest.
        rustc.arg("-D").arg("unfulfilled_lint_expectations");
    }
    rustc
        .arg("--emit=obj")
        .arg("-o")
        .arg(&obj_path)
        .arg(&cand.entry);
    if opts.verbose {
        eprintln!("[modules] rustc {cand_name}", cand_name = cand.name);
    }
    run_step(rustc, "rustc")?;

    // 2) Link object → PIC ELF.
    let ld_script = pick_linker_script(cand, &opts.project_root);
    let linker = spec.linker.as_ref().expect("PIC path requires linker");
    let mut ld = Command::new(linker.program);
    if let Some(flavor) = linker.flavor {
        ld.arg("-flavor").arg(flavor);
    }
    ld.arg("-T")
        .arg(&ld_script)
        .arg("--gc-sections")
        .arg("--no-undefined")
        .arg("--undefined=module_arena_size")
        .arg("-o")
        .arg(&elf_path)
        .arg(&obj_path);
    if opts.verbose {
        eprintln!("[modules] link  {cand_name}", cand_name = cand.name);
    }
    run_step(ld, "linker")?;

    // 3) Pack ELF → .fmod (in-process, no subshell). Header name is the
    // BASE module type (`embed_name`), never the variant-suffixed
    // filename — graphs bind by fnv1a(type_name).
    pack_fmod(
        &elf_path,
        &out_path,
        &cand.embed_name,
        cand.type_id,
        Some(&cand.manifest),
        Some(spec.silicon_id),
        cand.variant.as_deref(),
    )?;
    Ok(BuildOutcome::Built)
}

fn compile_module_wasm(
    cand: &Candidate,
    spec: &SiliconSpec,
    out_dir: &Path,
    opts: &BuildOpts,
) -> Result<BuildOutcome> {
    let wasm_path = out_dir.join(format!("{}.wasm", cand.name));
    let out_path = out_dir.join(format!("{}.fmod", cand.name));

    let mut rustc = Command::new("rustc");
    rustc
        .arg("--crate-type=cdylib")
        .arg("--edition")
        .arg(&cand.edition)
        .arg("--target")
        .arg(spec.module_target)
        .arg("-C")
        .arg(format!(
            "opt-level={}",
            cand.wasm_opt_level.as_deref().unwrap_or("z")
        ))
        .arg("-C")
        .arg("strip=symbols");
    rustc.args(cfg_feature_args(cand));
    if opts.strict {
        rustc.arg("-D").arg("warnings");
    } else {
        rustc.arg("-W").arg("warnings");
        rustc.arg("-D").arg("unfulfilled_lint_expectations");
    }
    rustc.arg("-o").arg(&wasm_path).arg(&cand.entry);
    if opts.verbose {
        eprintln!("[modules] rustc (wasm) {cand_name}", cand_name = cand.name);
    }
    let outcome = run_step_capture(rustc, "rustc")?;
    if !outcome.success {
        let _ = std::fs::remove_file(&wasm_path);
        let _ = std::fs::remove_file(&out_path);
        let detail = outcome
            .stderr
            .lines()
            .take(3)
            .collect::<Vec<_>>()
            .join(" | ");
        // A module that declares `wasm` in `hardware_targets` must compile for
        // wasm, so a failure there is real breakage (an SDK ABI change, say)
        // and fails the build. A module that does not claim wasm is legitimately
        // not a wasm payload, and skipping it is correct.
        if cand.hardware_targets.iter().any(|t| t == "wasm") {
            return Err(Error::Module(format!(
                "{}: declares `wasm` target but wasm32 compile failed: {detail}",
                cand.name
            )));
        }
        return Ok(BuildOutcome::Skipped(format!(
            "wasm32 compile failed (module does not declare `wasm`): {detail}"
        )));
    }

    // Verify the wasm exports the canonical wasm-payload entry
    // points. Symbol-name grep over the binary is the same heuristic
    // shell tooling uses, so the accepted module set is identical.
    let wasm_bytes = std::fs::read(&wasm_path)?;
    let has_init = needle_in(&wasm_bytes, b"module_init_wasm");
    let has_step = needle_in(&wasm_bytes, b"module_step_wasm");
    if !has_init || !has_step {
        let _ = std::fs::remove_file(&wasm_path);
        let _ = std::fs::remove_file(&out_path);
        return Ok(BuildOutcome::Skipped(
            "compiles for wasm32 but missing module_init_wasm + module_step_wasm exports"
                .to_string(),
        ));
    }

    pack_fmod_wasm(
        &wasm_path,
        &out_path,
        &cand.embed_name,
        cand.type_id,
        Some(&cand.manifest),
        Some(spec.silicon_id),
        cand.variant.as_deref(),
    )?;
    Ok(BuildOutcome::Built)
}

fn pick_linker_script(cand: &Candidate, project_root: &Path) -> PathBuf {
    // 1. Per-module override wins.
    let local = cand.dir.join("module.ld");
    if local.exists() {
        return local;
    }
    // 2. Project-local default at `modules/sdk/module.ld` — shipped in
    //    the `fluxor-abi` source artifact (`sdk/**`). Also accept
    //    `modules/module.ld` as a fallback location.
    for cand_path in [
        project_root.join("modules/sdk/module.ld"),
        project_root.join("modules/module.ld"),
    ] {
        if cand_path.exists() {
            return cand_path;
        }
    }
    // 3. Downstream consumers materialise fluxor's SDK source into
    //    `target/fluxor/fluxor-abi/sdk/` via `fluxor sync`. Pick that
    //    up so PIC builds in a downstream project find the script
    //    without an explicit copy.
    {
        let cand_path = project_root.join("target/fluxor/fluxor-abi/sdk/module.ld");
        if cand_path.exists() {
            return cand_path;
        }
    }
    // Fall back to a conventional path so the error message points at
    // the familiar location.
    project_root.join("modules/module.ld")
}

fn run_step(mut cmd: Command, name: &str) -> Result<()> {
    let status = cmd
        .status()
        .map_err(|e| Error::Module(format!("{name}: {e}")))?;
    if !status.success() {
        return Err(Error::Module(format!(
            "{name} exited {}",
            status.code().unwrap_or(-1)
        )));
    }
    Ok(())
}

struct CaptureOutcome {
    success: bool,
    stderr: String,
}

fn run_step_capture(mut cmd: Command, name: &str) -> Result<CaptureOutcome> {
    let output = cmd
        .output()
        .map_err(|e| Error::Module(format!("{name}: {e}")))?;
    Ok(CaptureOutcome {
        success: output.status.success(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

fn needle_in(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// `fluxor modules clean` — remove every `.fmod` (and adjacent `.o` /
/// `.elf` / `.wasm` intermediates) under the resolved output root.
pub fn clean(opts: &BuildOpts) -> Result<usize> {
    let mut removed = 0usize;
    if !opts.out_root.exists() {
        return Ok(0);
    }
    for entry in walkdir::WalkDir::new(&opts.out_root)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let ext = entry.path().extension().and_then(|s| s.to_str());
        if matches!(ext, Some("fmod" | "o" | "elf" | "wasm"))
            && std::fs::remove_file(entry.path()).is_ok()
        {
            removed += 1;
        }
    }
    Ok(removed)
}

/// `fluxor modules list` — human-readable inventory of every module
/// discovered under the project's `modules/` tree.
///
/// Reports the whole inventory, `builtin = true` declarations
/// included: they are modules a graph can bind, they just carry no
/// source to build.
pub fn list(project_root: &Path) -> Result<Vec<ModuleSummary>> {
    let cands = discover_all(project_root)?;
    Ok(cands
        .into_iter()
        .map(|c| ModuleSummary {
            name: c.name,
            entry: c.entry,
            manifest: c.manifest,
            hardware_targets: c.hardware_targets,
            type_id: c.type_id,
            builtin: c.builtin,
        })
        .collect())
}

#[derive(Debug)]
pub struct ModuleSummary {
    pub name: String,
    pub entry: PathBuf,
    pub manifest: PathBuf,
    pub hardware_targets: Vec<String>,
    pub type_id: u8,
    /// Kernel-resident declaration: no entry file exists at `entry`.
    pub builtin: bool,
}

/// The `target/fluxor/<silicon>/modules` directory whose artefacts a target
/// LOADS, from a descriptor the caller already holds.
///
/// Takes the descriptor rather than a target name because the two differ
/// exactly where it matters: a host target loads the artefacts of the silicon
/// it runs on — `linux` loads `bcm2712`'s — and a directory named after the
/// host has no artefact tree and never will. Every caller that needs .fmod
/// bytes goes through here, so that rule is stated once instead of being
/// rebuilt from `target_desc.id` at each call site, which is how a host
/// target came to resolve to an empty directory and report every module as
/// carrying no parameter schema.
pub fn modules_dir_for(desc: &crate::target::TargetDescriptor) -> PathBuf {
    PathBuf::from("target/fluxor")
        .join(desc.module_silicon())
        .join("modules")
}

/// `fluxor modules resolve` — print the resolved `target/.../modules`
/// directory for a given target, honouring the dual-root resolution
/// from standards/fluxor-modules.md §6.
pub fn resolve(project_root: &Path, out_root: &Path, target: &str) -> PathBuf {
    // A BOARD is a legitimate subject here even though it is not a
    // legitimate build target: its modules live in its silicon's
    // directory, and where they live is the whole question. Going
    // through `resolve_silicon` would take the board's level error and
    // fall back to the board's own name — a directory that is always
    // empty, handed to the callers who use this verb precisely so they
    // need not know the layout.
    //
    // The raw-name fallback stays for a genuinely unknown target: the
    // caller is printing a path, not building, and an unknown name
    // still gets a deterministic answer.
    let silicon = crate::target::load_target(target, project_root)
        .map(|d| d.module_silicon().to_string())
        .unwrap_or_else(|_| target.to_string());
    out_root.join(silicon).join("modules")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_root() -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p
    }

    /// A project with no module tree builds nothing, and that is a report
    /// rather than an error.
    ///
    /// The two halves are one rule seen from both sides. A portable-core-only
    /// repo declares no `[ci].targets` — the `fluxor.toml` schema gate refuses
    /// the key when nothing needs targeting — so resolving the target matrix
    /// before discovering candidates makes such a project unbuildable by
    /// construction. But the requirement itself has to survive: a repo that
    /// *does* have modules and declares no targets is genuinely
    /// misconfigured, and must still be told so.
    #[test]
    fn a_project_with_no_modules_builds_nothing_but_one_with_modules_still_needs_targets() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join("fluxor.toml"),
            "[project]\nname = \"core_only\"\n",
        )
        .unwrap();

        let opts = BuildOpts {
            project_root: root.to_path_buf(),
            selector: TargetSelector::All,
            out_root: root.join("target/fluxor"),
            strict: false,
            verbose: false,
        };
        let report = run(&opts).expect("a project with no module tree is not a build failure");
        assert!(
            report.per_target.is_empty(),
            "nothing was discovered, so there is nothing to report per target"
        );
        assert!(report.ok(), "an empty build is a passing build");

        // Now give it a module. The missing target matrix becomes a real
        // fault again, because there is now something that needs targeting.
        let m = root.join("modules/fixtures/probe");
        std::fs::create_dir_all(&m).unwrap();
        std::fs::write(
            m.join("manifest.toml"),
            "version = \"1.0.0\"\nhardware_targets = [\"linux\"]\n",
        )
        .unwrap();
        std::fs::write(m.join("mod.rs"), "// entry\n").unwrap();

        let err = run(&opts).expect_err("a module with no declared target is misconfigured");
        assert!(
            err.to_string().contains("[ci].targets"),
            "the diagnostic must name the missing key, not the symptom: {err}"
        );
    }

    /// `modules_dir_for` sends a HOST target to the silicon whose artefacts
    /// it loads, not to a directory named after itself.
    ///
    /// The call sites that build a modules path from `target_desc.id` instead
    /// gave `target/fluxor/linux/modules`, which is never created. Every .fmod
    /// lookup under it missed, and a config check reported the modules as
    /// carrying no parameter schema — a staleness-shaped message for a path
    /// fault, which is the hardest kind to trace back.
    #[test]
    fn modules_dir_for_sends_a_host_target_to_its_silicon() {
        let root = repo_root();
        for (target, want) in [
            ("linux", "bcm2712"),
            ("bcm2712", "bcm2712"),
            ("rp2350", "rp2350"),
        ] {
            let desc = crate::target::load_target(target, &root)
                .unwrap_or_else(|e| panic!("{target} target loads: {e}"));
            assert_eq!(
                modules_dir_for(&desc),
                PathBuf::from("target/fluxor").join(want).join("modules"),
                "{target} must load {want}'s modules"
            );
        }
    }

    /// `resolve` answers for a BOARD, which `resolve_silicon` rejects.
    /// The two differ on purpose: you build silicon, but you ask where a
    /// board's modules are, and the answer is its silicon's directory.
    #[test]
    fn resolve_maps_a_board_onto_its_silicon_directory() {
        let root = repo_root();
        let out = root.join("target/fluxor");
        assert_eq!(
            resolve(&root, &out, "pi5"),
            out.join("bcm2712").join("modules"),
            "a board must not resolve to a directory that never holds modules"
        );
        // Silicon and hosts are unchanged.
        assert_eq!(
            resolve(&root, &out, "bcm2712"),
            out.join("bcm2712").join("modules")
        );
        assert_eq!(
            resolve(&root, &out, "rp2350"),
            out.join("rp2350").join("modules")
        );
        // An unknown name still gets a deterministic answer.
        assert_eq!(
            resolve(&root, &out, "not-a-target"),
            out.join("not-a-target").join("modules")
        );
    }

    #[test]
    fn resolve_silicon_uses_registry() {
        let root = repo_root();
        assert_eq!(resolve_silicon("rp2350", &root).unwrap(), "rp2350");
        assert_eq!(resolve_silicon("rp2040", &root).unwrap(), "rp2040");
        assert_eq!(resolve_silicon("wasm", &root).unwrap(), "wasm");
        assert_eq!(resolve_silicon("bcm2712", &root).unwrap(), "bcm2712");
        // Hosts redirect via [target].module_silicon.
        assert_eq!(resolve_silicon("linux", &root).unwrap(), "bcm2712");
        // Boards are a level error in module-build slots.
        let err = resolve_silicon("pi5", &root).unwrap_err().to_string();
        assert!(err.contains("board id"), "{err}");
        assert!(err.contains("bcm2712"), "{err}");
    }

    #[test]
    fn resolve_type_id_honours_manifest() {
        assert_eq!(resolve_type_id("anything", Some("Source")), 1);
        assert_eq!(resolve_type_id("anything", Some("Transformer")), 2);
        assert_eq!(resolve_type_id("anything", Some("Sink")), 3);
        assert_eq!(resolve_type_id("anything", Some("EventHandler")), 4);
        assert_eq!(resolve_type_id("anything", Some("Protocol")), 5);
        assert_eq!(resolve_type_id("anything", Some("Mystery")), 2);
    }

    #[test]
    fn resolve_type_id_falls_back_to_legacy_name_table() {
        // A manifest with no `type = "..."` falls back to the name
        // table the Makefile's mod_type macro hardcodes; the two must
        // agree byte for byte.
        assert_eq!(resolve_type_id("cyw43", None), 5);
        assert_eq!(resolve_type_id("enc28j60", None), 5);
        assert_eq!(resolve_type_id("i2s_pio", None), 3);
        assert_eq!(resolve_type_id("button", None), 4);
        assert_eq!(resolve_type_id("flash_rp", None), 4);
        assert_eq!(resolve_type_id("temp_sensor", None), 1);
        assert_eq!(resolve_type_id("mic_pio", None), 1);
        assert_eq!(resolve_type_id("synth_source", None), 1);
        assert_eq!(resolve_type_id("ip", None), 2);
        assert_eq!(resolve_type_id("http", None), 2);
    }

    /// Discovery walks the one tier list, so a `platform/` module is
    /// found — and a `builtin = true` manifest there is a declaration
    /// with no entry file, so it must be skipped as a non-candidate
    /// rather than diagnosed as a broken module.
    #[test]
    fn discovery_covers_tiers_and_skips_builtin_declarations() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let builtin = root.join("modules/platform/linux/host_thing");
        std::fs::create_dir_all(&builtin).unwrap();
        std::fs::write(
            builtin.join("manifest.toml"),
            "version = \"1.0.0\"\nhardware_targets = [\"linux\"]\nbuiltin = true\n",
        )
        .unwrap();

        let real = root.join("modules/fixtures/probe");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("manifest.toml"), "version = \"1.0.0\"\n").unwrap();
        std::fs::write(real.join("mod.rs"), "// probe\n").unwrap();

        // The inventory sees both tiers…
        let all = discover_all(root).unwrap();
        let mut names: Vec<&str> = all.iter().map(|c| c.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec!["host_thing", "probe"],
            "the tier list must reach platform/ and fixtures/"
        );
        // …and the build set does not include the declaration.
        let buildable = discover(root).unwrap();
        let names: Vec<&str> = buildable.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["probe"],
            "builtin declarations are not build candidates"
        );
    }

    #[test]
    fn silicon_spec_lookup_covers_all_documented_targets() {
        for s in ["rp2040", "rp2350", "bcm2712", "wasm"] {
            assert!(silicon_spec(s).is_some(), "missing spec for {s}");
        }
        assert!(silicon_spec("unknown").is_none());
    }

    #[test]
    fn matches_target_empty_means_all() {
        let c = Candidate {
            name: "x".into(),
            dir: PathBuf::new(),
            entry: PathBuf::new(),
            manifest: PathBuf::new(),
            hardware_targets: vec![],
            type_id: 2,
            edition: "2021".into(),
            embed_name: "x".into(),
            variant: None,
            features: Vec::new(),
            check_cfg_features: Vec::new(),
            wasm_opt_level: None,
            opt_level: None,
            builtin: false,
        };
        assert!(matches_target(&c, "rp2350", "rp2350"));
        assert!(matches_target(&c, "linux", "bcm2712"));
    }

    #[test]
    fn matches_target_by_silicon_id() {
        let c = Candidate {
            name: "x".into(),
            dir: PathBuf::new(),
            entry: PathBuf::new(),
            manifest: PathBuf::new(),
            hardware_targets: vec!["bcm2712".into()],
            type_id: 2,
            edition: "2021".into(),
            embed_name: "x".into(),
            variant: None,
            features: Vec::new(),
            check_cfg_features: Vec::new(),
            wasm_opt_level: None,
            opt_level: None,
            builtin: false,
        };
        // Host target "linux" matches via its module silicon (bcm2712).
        assert!(matches_target(&c, "linux", "bcm2712"));
        assert!(matches_target(&c, "bcm2712", "bcm2712"));
        assert!(!matches_target(&c, "rp2350", "rp2350"));
    }

    #[test]
    fn matches_target_by_raw_target_token() {
        let c = Candidate {
            name: "x".into(),
            dir: PathBuf::new(),
            entry: PathBuf::new(),
            manifest: PathBuf::new(),
            hardware_targets: vec!["linux".into()],
            type_id: 2,
            edition: "2021".into(),
            embed_name: "x".into(),
            variant: None,
            features: Vec::new(),
            check_cfg_features: Vec::new(),
            wasm_opt_level: None,
            opt_level: None,
            builtin: false,
        };
        // Manifest pinned to the raw host token — the target-string
        // match lets it through when the user invokes `--target linux`.
        assert!(matches_target(&c, "linux", "bcm2712"));
        // But the silicon alone doesn't imply the host token.
        assert!(!matches_target(&c, "bcm2712", "bcm2712"));
    }

    #[test]
    fn include_paths_finds_every_include_macro_form() {
        let src = r#"
            include!("../common/agg_core.rs");
            include_str!("banner.txt");
            include_bytes!( "blob.bin" );
            include!(concat!(env!("OUT_DIR"), "/gen.rs"));
        "#;
        let got = include_paths(src);
        assert!(got.contains(&"../common/agg_core.rs".to_string()));
        assert!(got.contains(&"banner.txt".to_string()));
        assert!(
            got.contains(&"blob.bin".to_string()),
            "whitespace before the literal is fine"
        );
        assert_eq!(
            got.len(),
            3,
            "a macro-generated path has no literal to follow"
        );
    }

    #[test]
    fn include_paths_finds_path_attributes() {
        let src = r#"
            #[path = "../../shared/core.rs"]
            mod core;
            #[path="sibling.rs"]
            mod sib;
            #[path
                = "spread.rs"]
            mod spread;
        "#;
        let got = include_paths(src);
        assert!(got.contains(&"../../shared/core.rs".to_string()));
        assert!(got.contains(&"sibling.rs".to_string()));
        assert!(got.contains(&"spread.rs".to_string()));
    }

    #[test]
    fn transitive_source_refs_walks_path_mounts_within_roots() {
        let scratch = tempfile::tempdir().unwrap();
        let pr = scratch.path().join("proj");
        let mod_dir = pr.join("modules/app/demo");
        std::fs::create_dir_all(&mod_dir).unwrap();
        std::fs::create_dir_all(pr.join("shared")).unwrap();
        // module → shared/core.rs (#[path]) → shared/deep.rs (include!),
        // plus a reference escaping the project root that must be dropped.
        std::fs::write(
            mod_dir.join("mod.rs"),
            "#[path = \"../../../shared/core.rs\"]\nmod core;\n",
        )
        .unwrap();
        std::fs::write(
            pr.join("shared/core.rs"),
            "include!(\"deep.rs\");\n#[path = \"../../outside.rs\"]\nmod out;\n",
        )
        .unwrap();
        std::fs::write(pr.join("shared/deep.rs"), "pub fn d() {}\n").unwrap();
        std::fs::write(scratch.path().join("outside.rs"), "pub fn o() {}\n").unwrap();

        let refs = transitive_source_refs(&mod_dir, std::slice::from_ref(&pr));
        let names: Vec<String> = refs
            .iter()
            .filter_map(|p| p.file_name().map(|s| s.to_string_lossy().to_string()))
            .collect();
        assert!(names.contains(&"core.rs".to_string()), "{names:?}");
        assert!(
            names.contains(&"deep.rs".to_string()),
            "recursion through a #[path] mount must follow include!: {names:?}"
        );
        assert!(
            !names.contains(&"outside.rs".to_string()),
            "references escaping every allowed root are not inputs: {names:?}"
        );
    }

    #[test]
    fn a_shared_core_edit_invalidates_a_module_that_includes_it() {
        // A core OUTSIDE the module directory, reached only via `include!`,
        // must still invalidate the module that includes it — otherwise
        // editing the core silently ships a stale .fmod.
        let tmp = std::env::temp_dir().join(format!("fluxbuild-{}", std::process::id()));
        let moddir = tmp.join("app/thing");
        let common = tmp.join("common");
        std::fs::create_dir_all(&moddir).unwrap();
        std::fs::create_dir_all(&common).unwrap();
        let core = common.join("core.rs");
        std::fs::write(&core, "// core").unwrap();
        std::fs::write(moddir.join("mod.rs"), "include!(\"../../common/core.rs\");").unwrap();

        // An output newer than everything: fresh.
        let future = SystemTime::now() + std::time::Duration::from_secs(3600);
        assert!(includes_are_older(&moddir, future));

        // An output older than the core: stale, via the include edge alone.
        let past = SystemTime::now() - std::time::Duration::from_secs(3600);
        assert!(!includes_are_older(&moddir, past));

        std::fs::remove_dir_all(&tmp).ok();
    }
}
