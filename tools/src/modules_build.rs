//! `fluxor modules build` — orchestrate the PIC / wasm module build.
//!
//! In-process discovery + compile + pack pipeline; replaces the
//! ~50-line Makefile shell loop earlier projects carried.
//!
//! Output layout:
//!
//! ```text
//! <out>/<silicon>/modules/<name>.{o,elf,fmod}      (PIC targets)
//! <out>/<silicon>/modules/<name>.{wasm,fmod}       (wasm target)
//! ```
//!
//! `<out>` defaults to `<project_root>/target/fluxor`. The legacy
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

/// Resolve a user-supplied target name (rp2350a/rp2350b → rp2350,
/// cm5 → bcm2712, etc.) to the silicon id used for module artefacts.
/// Modules are byte-identical across boards that share silicon + module_target.
pub fn target_to_silicon(target: &str) -> &str {
    match target {
        "rp2350a" | "rp2350b" => "rp2350",
        "cm5" => "bcm2712",
        other => other,
    }
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
    /// Build for a single target. Resolved via `target_to_silicon`.
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
    name: String,
    dir: PathBuf,
    entry: PathBuf,
    manifest: PathBuf,
    hardware_targets: Vec<String>,
    /// 1 (Source) / 2 (Transformer) / 3 (Sink) / 4 (EventHandler) /
    /// 5 (Protocol). Pulled from `manifest.toml::type` when present.
    type_id: u8,
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
    #[serde(default, rename = "type")]
    type_str: Option<String>,
    #[serde(default)]
    entry: Option<String>,
}

const MODULE_DIRS: &[&str] = &["modules/drivers", "modules/foundation", "modules/app"];

fn discover(project_root: &Path) -> Result<Vec<Candidate>> {
    let mut out = Vec::new();
    for dir in MODULE_DIRS {
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
            let entry_rel = raw.entry.unwrap_or_else(|| "mod.rs".to_string());
            let entry = dir.join(&entry_rel);
            if !entry.exists() {
                // A manifest pointing at a missing entry — skip with a
                // diagnostic. The `make modules` glob would have hit
                // the same gap.
                continue;
            }
            let type_id = resolve_type_id(&name, raw.type_str.as_deref());
            out.push(Candidate {
                name,
                dir: dir.clone(),
                entry,
                manifest,
                hardware_targets: raw.hardware_targets.unwrap_or_default(),
                type_id,
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Resolve the module-type byte (1–5) used by `pack_fmod`.
///
/// Preference order:
///   1. Manifest `type = "Source"|"Transformer"|…|"Protocol"` —
///      authoritative when present.
///   2. Legacy name table from the Makefile's `mod_type` macro,
///      hardcoded here for byte-identical output with the shell
///      loop. Migrate to manifest `type = "..."` to drop the row.
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
    let targets = match &opts.selector {
        TargetSelector::One(t) => vec![t.clone()],
        TargetSelector::All => resolve_all_targets(&opts.project_root)?,
    };
    let candidates = discover(&opts.project_root)?;
    let mut report = BuildReport::default();
    for target in targets {
        report
            .per_target
            .push(build_one_target(&target, &candidates, opts)?);
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
    let silicon = target_to_silicon(target).to_string();
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

    if silicon == "rp2350" {
        // Symlink rp2350a + rp2350b → rp2350 so consumers that key by
        // silicon variant find modules at the unified directory.
        for variant in &["rp2350a", "rp2350b"] {
            let link_path = opts.out_root.join(variant);
            if !link_path.exists() {
                let _ = symlink_relative(&silicon, &link_path);
            }
        }
    }

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
        project_root.join("modules/sdk/params.rs"),
        project_root.join("modules/module.ld"),
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
    true
}

fn mtime(p: &Path) -> Option<SystemTime> {
    p.metadata().ok()?.modified().ok()
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
        .arg("--target")
        .arg(spec.module_target)
        .arg("-O")
        .arg("-C")
        .arg("relocation-model=pic")
        .args(spec.extra_rustflags);
    if opts.strict {
        // `-D warnings` upgrades unfulfilled `#[expect(...)]` and
        // every other warning into a hard error, matching the
        // standard's §4 strict mode.
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

    // 3) Pack ELF → .fmod (in-process, no subshell).
    pack_fmod(
        &elf_path,
        &out_path,
        &cand.name,
        cand.type_id,
        Some(&cand.manifest),
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
        .arg("--target")
        .arg(spec.module_target)
        .arg("-C")
        .arg("opt-level=z")
        .arg("-C")
        .arg("strip=symbols");
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
        // wasm compile failures are a `skip` rather than a hard fail
        // for modules that aren't expected to be wasm payloads. Drop
        // the `.fmod` and continue so the rest of the build proceeds.
        let _ = std::fs::remove_file(&wasm_path);
        let _ = std::fs::remove_file(&out_path);
        return Ok(BuildOutcome::Skipped(format!(
            "wasm32 compile failed: {}",
            outcome
                .stderr
                .lines()
                .take(3)
                .collect::<Vec<_>>()
                .join(" | ")
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
        &cand.name,
        cand.type_id,
        Some(&cand.manifest),
    )?;
    Ok(BuildOutcome::Built)
}

fn pick_linker_script(cand: &Candidate, project_root: &Path) -> PathBuf {
    let local = cand.dir.join("module.ld");
    if local.exists() {
        local
    } else {
        project_root.join("modules/module.ld")
    }
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

fn symlink_relative(target: &str, link: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(not(unix))]
    {
        let _ = (target, link);
        Ok(())
    }
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
pub fn list(project_root: &Path) -> Result<Vec<ModuleSummary>> {
    let cands = discover(project_root)?;
    Ok(cands
        .into_iter()
        .map(|c| ModuleSummary {
            name: c.name,
            entry: c.entry,
            manifest: c.manifest,
            hardware_targets: c.hardware_targets,
            type_id: c.type_id,
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
}

/// `fluxor modules resolve` — print the resolved `target/.../modules`
/// directory for a given target, honouring the dual-root resolution
/// from standards/fluxor-modules.md §6.
pub fn resolve(out_root: &Path, target: &str) -> PathBuf {
    out_root.join(target_to_silicon(target)).join("modules")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_to_silicon_maps_known_aliases() {
        assert_eq!(target_to_silicon("rp2350a"), "rp2350");
        assert_eq!(target_to_silicon("rp2350b"), "rp2350");
        assert_eq!(target_to_silicon("cm5"), "bcm2712");
        assert_eq!(target_to_silicon("rp2040"), "rp2040");
        assert_eq!(target_to_silicon("wasm"), "wasm");
        assert_eq!(target_to_silicon("bcm2712"), "bcm2712");
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
        // Manifests today don't carry `type = "..."`; the Makefile's
        // mod_type macro hardcodes these. Keeping byte-identical
        // outputs prevents an .fmod regression on the swap.
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
        };
        assert!(matches_target(&c, "rp2350", "rp2350"));
        assert!(matches_target(&c, "cm5", "bcm2712"));
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
        };
        // Board target "cm5" matches via its silicon mapping to bcm2712.
        assert!(matches_target(&c, "cm5", "bcm2712"));
        assert!(matches_target(&c, "bcm2712", "bcm2712"));
        assert!(!matches_target(&c, "rp2350", "rp2350"));
    }

    #[test]
    fn matches_target_by_explicit_board_name() {
        let c = Candidate {
            name: "x".into(),
            dir: PathBuf::new(),
            entry: PathBuf::new(),
            manifest: PathBuf::new(),
            hardware_targets: vec!["cm5".into()],
            type_id: 2,
        };
        // Manifest pinned to the board name (cm5) — silicon-keyed
        // match should still let it through when the user invokes
        // with `--target cm5`.
        assert!(matches_target(&c, "cm5", "bcm2712"));
        // But a different board sharing the same silicon shouldn't.
        assert!(!matches_target(&c, "bcm2712", "bcm2712"));
    }
}
