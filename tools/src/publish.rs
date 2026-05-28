//! `fluxor publish` — registry-publication CLI.
//!
//! Each verb packages a project artefact and writes it into the local
//! registry at `~/.fluxor/registry/`.
//!
//! Versioning rules:
//! - **Canonical publish** (no `--local`): refuses to overwrite an
//!   existing `(name, version)` and refuses to publish if the
//!   resolved version is the dev default (`0.0.0-dev`).
//! - **Local publish** (`--local`): appends `-local.<content-hash>`
//!   to every artefact name so re-publishing after edits produces a
//!   new file rather than overwriting. Consumers pick the newest
//!   hash automatically.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cargo_index;
use crate::error::{Error, Result};
use crate::hash::file_sha256_short;
use crate::project::{self, ProjectIdentity, DEV_VERSION};
use crate::project_meta;
use crate::registry;
use crate::workspace;

// ── Common helpers ────────────────────────────────────────────────────

fn resolve_project_root(opt: Option<&Path>) -> PathBuf {
    opt.map(PathBuf::from).unwrap_or_else(project::root)
}

/// Refresh the project-meta file at the registry. Called from every
/// canonical-publish path so the meta tracks the latest published
/// state of the project's `[project]` + `[dependencies]` tables.
fn refresh_project_meta(project_root: &Path) -> Result<()> {
    let registry_root = registry::registry_root()?;
    let meta = project_meta::from_project_root(project_root)?;
    let _ = project_meta::write_meta(&registry_root, &meta)?;
    Ok(())
}

/// One-line stderr advisory when publish runs from inside a live
/// workspace member. The artifact still publishes normally — the
/// advisory just informs the developer that workspace-aware
/// consumers will continue using the live source path until they
/// leave the workspace.
fn announce_workspace_mode_if_active(project_root: &Path) {
    let Ok(Some(ws)) = workspace::load_workspace() else {
        return;
    };
    let Some(msg) = workspace::advisory(&ws, project_root) else {
        return;
    };
    eprintln!("note: {msg}");
    eprintln!(
        "      published artefact still lands in the registry, but workspace-aware consumers"
    );
    eprintln!("      will resolve to the live source path until they leave the workspace.");
}

fn require_project_identity(project_root: &Path) -> Result<ProjectIdentity> {
    let identity = project::project_identity(project_root)
        .map_err(Error::Config)?
        .ok_or_else(|| {
            Error::Config(format!(
                "no [project] table in {}/fluxor.toml — publish requires `[project].name`",
                project_root.display()
            ))
        })?;
    Ok(identity)
}

fn reject_dev_version_for_canonical(identity: &ProjectIdentity, local: bool) -> Result<()> {
    if !local && identity.version == DEV_VERSION {
        return Err(Error::Config(format!(
            "canonical publish refuses `[project].version = \"{DEV_VERSION}\"` — \
             set a real version in fluxor.toml, or pass --local."
        )));
    }
    Ok(())
}

fn content_hash(path: &Path) -> Result<String> {
    file_sha256_short(path)
}

/// Build the destination filename: `<stem>.<ext>` or
/// `<stem>-local.<hash>.<ext>`.
fn target_filename(stem: &str, ext: &str, hash: Option<&str>) -> String {
    match hash {
        Some(h) => format!("{stem}-local.{h}.{ext}"),
        None => format!("{stem}.{ext}"),
    }
}

/// Copy `src` into the registry's `cargo/` shelf. Returns the
/// destination path. Refuses to overwrite a canonical artefact.
fn install_crate_artefact(
    src: &Path,
    crate_name: &str,
    version: &str,
    local: bool,
) -> Result<PathBuf> {
    let root = registry::registry_root()?;
    registry::ensure_layout(&root)?;
    let cargo_dir = root.join("cargo");

    let stem = format!("{crate_name}-{version}");
    let hash = if local {
        Some(content_hash(src)?)
    } else {
        None
    };
    let filename = target_filename(&stem, "crate", hash.as_deref());
    let dest = cargo_dir.join(&filename);

    if !local && dest.exists() {
        return Err(Error::Config(format!(
            "canonical {} already exists; bump [package].version or pass --local",
            dest.display()
        )));
    }

    fs::copy(src, &dest)?;
    Ok(dest)
}

fn run_cargo_package(project_root: &Path, package: &str) -> Result<PathBuf> {
    let status = Command::new("cargo")
        .arg("package")
        .arg("--no-verify")
        .arg("--allow-dirty")
        .arg("--package")
        .arg(package)
        .arg("--target-dir")
        .arg(project_root.join("target"))
        .current_dir(project_root)
        .status()
        .map_err(|e| Error::Config(format!("failed to spawn cargo package: {e}")))?;
    if !status.success() {
        return Err(Error::Config(format!(
            "cargo package -p {package} exited with status {status}"
        )));
    }

    // Read the package's actual version from its Cargo.toml — the
    // emitted artefact is `<name>-<version>.crate` and that's what we
    // copy into the registry.
    let manifest = read_crate_manifest(project_root, package)?;
    let crate_path = project_root
        .join("target")
        .join("package")
        .join(format!("{}-{}.crate", package, manifest.version));
    if !crate_path.exists() {
        return Err(Error::Config(format!(
            "expected packaged artefact at {} but it is missing",
            crate_path.display()
        )));
    }
    Ok(crate_path)
}

struct CrateManifest {
    version: String,
}

fn read_crate_manifest(project_root: &Path, package: &str) -> Result<CrateManifest> {
    // Parse the workspace root's Cargo.toml to enumerate members,
    // then walk each member's Cargo.toml looking for the requested
    // package name. Avoids a fragile substring match and tolerates
    // any layout the workspace declares.
    #[derive(serde::Deserialize)]
    struct WorkspaceManifest {
        workspace: Option<WorkspaceSection>,
    }
    #[derive(serde::Deserialize)]
    struct WorkspaceSection {
        #[serde(default)]
        members: Vec<String>,
    }
    #[derive(serde::Deserialize)]
    struct PackageManifest {
        package: PackageSection,
    }
    #[derive(serde::Deserialize)]
    struct PackageSection {
        name: String,
        version: String,
    }

    let root_manifest_path = project_root.join("Cargo.toml");
    let root_text = fs::read_to_string(&root_manifest_path)
        .map_err(|e| Error::Config(format!("read {}: {e}", root_manifest_path.display())))?;
    let root_manifest: WorkspaceManifest = toml::from_str(&root_text)
        .map_err(|e| Error::Config(format!("parse {}: {e}", root_manifest_path.display())))?;
    let members = root_manifest
        .workspace
        .map(|w| w.members)
        .unwrap_or_default();

    for member in &members {
        let manifest_path = project_root.join(member).join("Cargo.toml");
        if !manifest_path.exists() {
            continue;
        }
        let text = fs::read_to_string(&manifest_path)
            .map_err(|e| Error::Config(format!("read {}: {e}", manifest_path.display())))?;
        let pkg: PackageManifest = match toml::from_str(&text) {
            Ok(p) => p,
            Err(_) => continue, // member may be a virtual workspace
        };
        if pkg.package.name == package {
            return Ok(CrateManifest {
                version: pkg.package.version,
            });
        }
    }

    Err(Error::Config(format!(
        "could not locate Cargo.toml for package {package} \
         (searched workspace members from {})",
        root_manifest_path.display()
    )))
}

// ── Verb implementations ──────────────────────────────────────────────

pub fn cmd_publish_abi(local: bool, project_root: Option<&Path>) -> Result<()> {
    publish_workspace_crate("fluxor-abi", local, project_root)
}

pub fn cmd_publish_sdk(local: bool, project_root: Option<&Path>) -> Result<()> {
    publish_workspace_crate("fluxor-sdk", local, project_root)
}

pub fn cmd_publish_common(local: bool, project_root: Option<&Path>) -> Result<()> {
    let pr = resolve_project_root(project_root);
    let identity = require_project_identity(&pr)?;
    publish_workspace_crate(&format!("{}-common", identity.name), local, project_root)
}

fn publish_workspace_crate(package: &str, local: bool, project_root: Option<&Path>) -> Result<()> {
    let pr = resolve_project_root(project_root);
    let identity = require_project_identity(&pr)?;
    reject_dev_version_for_canonical(&identity, local)?;
    announce_workspace_mode_if_active(&pr);

    let manifest = read_crate_manifest(&pr, package)?;

    // Single source of truth: `[package].version` in every workspace
    // member crate must match `[project].version` in fluxor.toml.
    // The transitive resolver looks up project-meta at
    // `projects/<dep>/<resolved-crate-version>.toml` (lockfile.rs);
    // project-meta is written at `<dep>/<[project].version>.toml`
    // (project_meta.rs). Keeping the two numbers identical is what
    // makes transitive resolution find the meta file. Canonical
    // publish refuses to publish a mismatched crate; `--local`
    // accepts (locals are content-hashed and aren't indexed).
    if !local && manifest.version != identity.version {
        return Err(Error::Config(format!(
            "version mismatch: crate `{}` is at {} but [project].version is {} — \
             keep [package].version aligned with [project].version (single source of truth) \
             or pass --local for a content-hashed snapshot",
            package, manifest.version, identity.version,
        )));
    }

    println!(
        "packaging {} v{} from {}",
        package,
        manifest.version,
        pr.display()
    );
    let crate_path = run_cargo_package(&pr, package)?;

    let dest = install_crate_artefact(&crate_path, package, &manifest.version, local)?;
    println!("published {} → {}", package, dest.display());

    // Canonical publish updates the cargo git-index so downstream
    // projects can resolve the crate by name. Local publishes are
    // throwaway content-hashed artefacts and never enter the index.
    if !local {
        let manifest_path = locate_member_manifest(&pr, package)?;
        let deps = cargo_index::extract_deps(&manifest_path)?;
        let cksum = cargo_index::sha256_hex(&dest)?;
        let entry = cargo_index::IndexEntry {
            name: package,
            vers: &manifest.version,
            deps,
            cksum,
            features: serde_json::Map::new(),
            yanked: false,
        };
        let registry_root = registry::registry_root()?;
        let idx_path = cargo_index::append_entry(&registry_root, &entry)?;
        println!(
            "indexed {} {} → {}",
            package,
            manifest.version,
            idx_path.display()
        );
        refresh_project_meta(&pr)?;
    }

    Ok(())
}

/// Locate the workspace member's source Cargo.toml for the given
/// package. Reused by `publish_workspace_crate` to feed dep
/// extraction into the cargo-index writer.
fn locate_member_manifest(project_root: &Path, package: &str) -> Result<PathBuf> {
    #[derive(serde::Deserialize)]
    struct WorkspaceManifest {
        workspace: Option<WorkspaceSection>,
    }
    #[derive(serde::Deserialize)]
    struct WorkspaceSection {
        #[serde(default)]
        members: Vec<String>,
    }
    #[derive(serde::Deserialize)]
    struct PackageManifest {
        package: PackageSection,
    }
    #[derive(serde::Deserialize)]
    struct PackageSection {
        name: String,
    }

    let root_text = fs::read_to_string(project_root.join("Cargo.toml"))?;
    let root: WorkspaceManifest =
        toml::from_str(&root_text).map_err(|e| Error::Config(format!("parse Cargo.toml: {e}")))?;
    let members = root.workspace.map(|w| w.members).unwrap_or_default();
    for m in &members {
        let path = project_root.join(m).join("Cargo.toml");
        if !path.exists() {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap_or_default();
        let parsed: PackageManifest = match toml::from_str(&text) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if parsed.package.name == package {
            return Ok(path);
        }
    }
    Err(Error::Config(format!(
        "could not locate workspace-member manifest for {package}"
    )))
}

/// Read `version = "..."` from a module's `manifest.toml`. Each fmod
/// is versioned independently from the project — bumping `moduleA1`
/// shouldn't require republishing `moduleA2`.
fn read_module_version(project_root: &Path, module_name: &str) -> Option<String> {
    let tiers = ["foundation", "app", "drivers"];
    for tier in tiers {
        let manifest = project_root
            .join("modules")
            .join(tier)
            .join(module_name)
            .join("manifest.toml");
        if !manifest.exists() {
            continue;
        }
        let text = fs::read_to_string(&manifest).ok()?;
        #[derive(serde::Deserialize)]
        struct ModuleManifest {
            version: Option<String>,
        }
        let parsed: ModuleManifest = toml::from_str(&text).ok()?;
        return parsed.version;
    }
    None
}

pub fn cmd_publish_fmod(
    target: Option<&str>,
    module: Option<&str>,
    local: bool,
    project_root: Option<&Path>,
) -> Result<()> {
    let pr = resolve_project_root(project_root);
    let identity = require_project_identity(&pr)?;
    // Note: identity.version is *not* what gates canonical fmod
    // publish — each fmod uses its own manifest version. The
    // project-version guard here exists so a `publish --local` run
    // catches the missing `[project].name` early; we re-evaluate
    // each fmod's version individually below.
    reject_dev_version_for_canonical(&identity, true)?;
    announce_workspace_mode_if_active(&pr);

    let root = registry::registry_root()?;
    registry::ensure_layout(&root)?;

    // Source layout: fmods land under either
    // `target/fluxor/<target>/modules/<name>.fmod` or
    // `target/<target>/modules/<name>.fmod` depending on how the build
    // was invoked. Search both.
    let target_root_under_fluxor = pr.join("target").join("fluxor");
    let target_root_bare = pr.join("target");
    let candidate_roots = [&target_root_under_fluxor, &target_root_bare];

    let targets_to_walk: Vec<String> = match target {
        Some(t) => vec![t.to_string()],
        None => list_built_targets(&candidate_roots)?,
    };

    if targets_to_walk.is_empty() {
        return Err(Error::Config(
            "no built fmods under target/fluxor/* or target/* — run `make modules-all` first"
                .to_string(),
        ));
    }

    let mut published: Vec<PathBuf> = Vec::new();
    let mut skipped_idempotent = 0usize;
    let mut errors: Vec<String> = Vec::new();
    for target_name in &targets_to_walk {
        for root_dir in &candidate_roots {
            let modules_dir = root_dir.join(target_name).join("modules");
            if !modules_dir.exists() {
                continue;
            }
            for entry in fs::read_dir(&modules_dir)? {
                let entry = entry?;
                let filename = entry.file_name().to_string_lossy().into_owned();
                let Some(stem) = filename.strip_suffix(".fmod") else {
                    continue;
                };
                if let Some(m) = module {
                    if stem != m {
                        continue;
                    }
                }
                let src = entry.path();
                let module_version = match read_module_version(&pr, stem) {
                    Some(v) => v,
                    None => {
                        errors.push(format!(
                            "skip {stem}: no version in modules/*/{stem}/manifest.toml"
                        ));
                        continue;
                    }
                };
                if !local && module_version == project::DEV_VERSION {
                    errors.push(format!(
                        "skip {stem}: canonical publish refuses module version `{}`",
                        project::DEV_VERSION
                    ));
                    continue;
                }
                let dest_dir = root
                    .join("fmod")
                    .join(&identity.name)
                    .join(target_name)
                    .join(stem);
                fs::create_dir_all(&dest_dir)?;
                let hash = if local {
                    Some(content_hash(&src)?)
                } else {
                    None
                };
                let dest_filename = target_filename(&module_version, "fmod", hash.as_deref());
                let dest = dest_dir.join(&dest_filename);
                if !local && dest.exists() {
                    // Same-version + same-content: idempotent
                    // skip. Different content at the same version
                    // is a hard error — the registry promise is
                    // that `(name, version)` identifies one
                    // immutable artefact. fmod versions are
                    // independent of `[project].version`, so an
                    // ABI/SDK/runtime-only publish-cycle commonly
                    // re-encounters every already-published fmod
                    // unchanged. Don't fail that case.
                    let existing_hash = content_hash(&dest)?;
                    let new_hash = content_hash(&src)?;
                    if existing_hash == new_hash {
                        skipped_idempotent += 1;
                        continue;
                    }
                    errors.push(format!(
                        "{} already exists with different content — bump module version in modules/{}/<tier>/{}/manifest.toml",
                        dest.display(),
                        target_name,
                        stem,
                    ));
                    continue;
                }
                fs::copy(&src, &dest)?;
                published.push(dest);
            }
        }
    }

    let real_failure = !errors.is_empty();
    for line in &errors {
        eprintln!("warning: {line}");
    }
    if published.is_empty() && skipped_idempotent == 0 {
        // Truly nothing happened — neither published nor skipped.
        // Likely an empty target set or all source files missing.
        return Err(Error::Config(
            "no fmods were published or matched (empty target set?)".into(),
        ));
    }
    if real_failure {
        return Err(Error::Config(format!(
            "{} fmod(s) failed to publish — see warnings above",
            errors.len()
        )));
    }
    if !published.is_empty() {
        println!("published {} fmod(s):", published.len());
        for p in &published {
            println!("  {}", p.display());
        }
    }
    if skipped_idempotent > 0 {
        println!("skipped {skipped_idempotent} fmod(s) already at the same content (idempotent).");
    }
    if !local {
        refresh_project_meta(&pr)?;
    }
    Ok(())
}

fn list_built_targets(roots: &[&PathBuf]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for root in roots {
        if !root.exists() {
            continue;
        }
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let modules = entry.path().join("modules");
            if !modules.exists() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if !out.contains(&name) {
                out.push(name);
            }
        }
    }
    Ok(out)
}

/// Detect the host target triple — used by `publish runtime`'s
/// `--host-target` default. We read it from rustc's print output
/// since cargo doesn't surface it via env at runtime.
fn detect_host_target() -> Result<String> {
    let out = std::process::Command::new("rustc")
        .args(["-Vv"])
        .output()
        .map_err(|e| Error::Config(format!("spawn rustc -Vv: {e}")))?;
    if !out.status.success() {
        return Err(Error::Config(format!(
            "rustc -Vv failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("host: ") {
            return Ok(rest.trim().to_string());
        }
    }
    Err(Error::Config("rustc -Vv output had no `host:` line".into()))
}

pub fn cmd_publish_runtime(
    binary: &str,
    host_target: Option<&str>,
    local: bool,
    project_root: Option<&Path>,
) -> Result<()> {
    let pr = resolve_project_root(project_root);
    let identity = require_project_identity(&pr)?;
    reject_dev_version_for_canonical(&identity, local)?;
    announce_workspace_mode_if_active(&pr);

    let host_target = match host_target {
        Some(s) => s.to_string(),
        None => detect_host_target()?,
    };

    let src = pr
        .join("target")
        .join(&host_target)
        .join("release")
        .join(binary);
    if !src.exists() {
        return Err(Error::Config(format!(
            "runtime binary not found at {} — build it first \
             (e.g. `cargo build -p <pkg> --target {} --release --bin {}`)",
            src.display(),
            host_target,
            binary,
        )));
    }

    let root = registry::registry_root()?;
    registry::ensure_layout(&root)?;
    let bin_root = root.join("bin");
    fs::create_dir_all(&bin_root)?;
    let dest_dir = bin_root
        .join(&identity.name)
        .join(&host_target)
        .join(binary);
    fs::create_dir_all(&dest_dir)?;

    let hash = if local {
        Some(content_hash(&src)?)
    } else {
        None
    };
    let dest_filename = match &hash {
        Some(h) => format!("{}-local.{}", identity.version, h),
        None => identity.version.clone(),
    };
    let dest = dest_dir.join(&dest_filename);

    if !local && dest.exists() {
        return Err(Error::Config(format!(
            "canonical {} already exists; bump [project].version or pass --local",
            dest.display()
        )));
    }

    fs::copy(&src, &dest)?;
    // Preserve executable bit (cargo emits chmod 755 binaries; fs::copy
    // preserves mode on Linux, but be explicit for safety).
    let mut perms = fs::metadata(&dest)?.permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o755);
    fs::set_permissions(&dest, perms)?;

    println!(
        "published runtime {} ({}/{}) → {}",
        binary,
        identity.name,
        host_target,
        dest.display(),
    );
    if !local {
        refresh_project_meta(&pr)?;
    }
    Ok(())
}

/// Publish every applicable tier in one sweep. `local=false`
/// performs canonical publishing (refuses dev versions, refuses to
/// overwrite, writes cargo-index entries and project-meta files);
/// `local=true` writes content-hashed `-local.<sha>` snapshots that
/// never enter the cargo index. The bare `fluxor publish` (no
/// subcommand) routes here, honouring the top-level `--local` flag.
///
/// Each tier is attempted best-effort: a fluxor checkout may lack
/// `common` (only fluxor itself owns `abi`/`sdk`), a downstream
/// checkout may lack `abi`/`sdk`. The aggregate is fault-tolerant
/// across that asymmetry; it only fails when *no* tier produced an
/// artefact AND every tier reported a real error.
pub fn cmd_publish_all(local: bool, project_root: Option<&Path>) -> Result<()> {
    let pr = resolve_project_root(project_root);
    let _identity = require_project_identity(&pr)?;

    type PublishFn = fn(bool, Option<&Path>) -> Result<()>;
    let attempts: &[(&str, PublishFn)] = &[
        ("abi", cmd_publish_abi),
        ("sdk", cmd_publish_sdk),
        ("common", cmd_publish_common),
    ];

    let mut any_succeeded = false;
    let mut soft_failures: Vec<String> = Vec::new();
    for (label, f) in attempts {
        match f(local, Some(&pr)) {
            Ok(()) => any_succeeded = true,
            Err(e) => soft_failures.push(format!("{label}: {e}")),
        }
    }

    // fmods — always attempted; per-module idempotency means a
    // canonical-mode re-publish without version bumps doesn't count
    // as failure.
    match cmd_publish_fmod(None, None, local, Some(&pr)) {
        Ok(()) => any_succeeded = true,
        Err(e) => soft_failures.push(format!("fmod: {e}")),
    }

    // Runtime binaries — best-effort. Each project declares its
    // host-runtime binaries via `fluxor.toml::[publish.runtime]`
    // (future) or via convention. Today the only host-runtime
    // binary fluxor itself publishes is `fluxor-linux`; downstream
    // projects don't generally have one. Attempt fluxor-linux when
    // the binary exists at the conventional location; otherwise
    // silently skip.
    if let Ok(host_target) = detect_host_target() {
        let conventional = pr
            .join("target")
            .join(&host_target)
            .join("release")
            .join("fluxor-linux");
        if conventional.exists() {
            match cmd_publish_runtime("fluxor-linux", Some(&host_target), local, Some(&pr)) {
                Ok(()) => any_succeeded = true,
                Err(e) => soft_failures.push(format!("runtime fluxor-linux: {e}")),
            }
        }
    }

    for s in &soft_failures {
        eprintln!("note: {s}");
    }
    if !any_succeeded {
        let kind = if local { "publish --local" } else { "publish" };
        return Err(Error::Config(format!(
            "{kind}: nothing was published; see notes above"
        )));
    }
    Ok(())
}
